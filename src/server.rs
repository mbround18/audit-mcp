use std::{collections::HashSet, sync::Arc, time::Duration};

use futures_util::future::join_all;
use rmcp::{
    Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{
    explain::FindingExplainer,
    fixes::FixEngine,
    models::{
        FindingExplanation, ListScannersResponse, NormalizedFinding, RunScanResponse, RunStatus,
        ScanSummary, ScannerRunResult, Severity, SuggestFixesResponse, ToolSelectionPlan,
    },
    runner::{DockerScannerRunner, ScanOptions},
    scanners::ScannerRegistry,
    selection::ToolSelector,
};

/// Default number of scanner containers allowed to run at once. Each container
/// may claim up to 4 GB, so an unbounded fan-out can take the host down.
const DEFAULT_MAX_PARALLEL: usize = 4;
/// Upper bound on findings returned in a single response, to keep MCP payloads
/// (and the caller's context window) manageable.
const DEFAULT_MAX_FINDINGS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunScanRequest {
    /// Absolute path to the directory (or file) to scan.
    pub target: String,
    /// How scanners are selected. Defaults to `single`.
    pub mode: Option<RunScanMode>,
    /// Scanner name — required when `mode=single`.
    pub scanner: Option<String>,
    /// Scanner names — required when `mode=many`.
    pub scanners: Option<Vec<String>>,
    /// Drop findings below this severity (`info`, `low`, `medium`, `high`, `critical`).
    pub min_severity: Option<String>,
    /// Cap the number of findings returned across all scanners.
    pub max_findings: Option<usize>,
    /// Attach raw scanner stdout/stderr even when parsing succeeded.
    pub include_raw_logs: Option<bool>,
    /// Wall-clock ceiling per scanner, overriding each scanner's default.
    pub timeout_secs: Option<u64>,
    /// How many scanner containers may run concurrently.
    pub max_parallel: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunScanMode {
    Single,
    Many,
    All,
}

impl RunScanMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Many => "many",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExplainFindingRequest {
    pub scanner: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuggestFixesRequest {
    pub findings: Vec<NormalizedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditStatusResponse {
    /// Whether a Docker daemon is reachable right now. Scans require one.
    pub docker_available: bool,
    pub scanner_count: usize,
    /// Scanners whose output is normalized into structured findings.
    pub normalized_scanner_count: usize,
    pub default_max_parallel: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuditMcpServer {
    tool_router: ToolRouter<Self>,
    registry: Arc<ScannerRegistry>,
    runner: Arc<DockerScannerRunner>,
    explainer: Arc<FindingExplainer>,
    fixer: Arc<FixEngine>,
    selector: Arc<ToolSelector>,
}

impl AuditMcpServer {
    /// Construction never touches Docker, so the MCP server starts (and can
    /// answer catalog/explain calls) on a host with no daemon running.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            tool_router: Self::tool_router(),
            registry: Arc::new(ScannerRegistry::new()?),
            runner: Arc::new(DockerScannerRunner::new()),
            explainer: Arc::new(FindingExplainer::new()),
            fixer: Arc::new(FixEngine::new()),
            selector: Arc::new(ToolSelector::new()),
        })
    }
}

#[tool_handler(
    router = self.tool_router,
    name = "audit-mcp",
    version = "0.2.0",
    instructions = "Runs dockerized audit scanners and returns normalized findings with remediation context. Call audit_status first if scans fail; run_scan with mode=all auto-detects the project's languages from the target directory's contents."
)]
impl ServerHandler for AuditMcpServer {}

#[tool_router(router = tool_router)]
impl AuditMcpServer {
    #[tool(
        name = "list_scanners",
        description = "List supported scanners, their categories, whether their output is normalized, and any credentials they require."
    )]
    pub async fn list_scanners(&self) -> Json<ListScannersResponse> {
        Json(ListScannersResponse {
            scanners: self.registry.list_summaries(),
        })
    }

    #[tool(
        name = "audit_status",
        description = "Report whether Docker is reachable and how much of the scanner catalog produces normalized findings."
    )]
    pub async fn audit_status(&self) -> Json<AuditStatusResponse> {
        let docker_available = self.runner.is_available().await;
        let summaries = self.registry.list_summaries();
        let normalized_scanner_count = summaries.iter().filter(|entry| entry.normalized).count();

        let mut notes = Vec::new();
        if !docker_available {
            notes.push(
                "No Docker daemon is reachable; run_scan will fail until one is available. list_scanners and explain_finding still work."
                    .to_string(),
            );
        }
        notes.push(format!(
            "{normalized_scanner_count} of {} scanners emit structured findings; the rest return raw logs with status 'unparsed'.",
            summaries.len()
        ));

        Json(AuditStatusResponse {
            docker_available,
            scanner_count: summaries.len(),
            normalized_scanner_count,
            default_max_parallel: DEFAULT_MAX_PARALLEL,
            notes,
        })
    }

    #[tool(
        name = "run_scan",
        description = "Run dockerized scanners against a path and return normalized findings with a severity rollup."
    )]
    pub async fn run_scan(
        &self,
        Parameters(request): Parameters<RunScanRequest>,
    ) -> Result<Json<RunScanResponse>, String> {
        let selection = self.selector.plan(&request.target, &self.registry);
        let (mode, scanners_to_run) =
            resolve_scanners_for_request(&self.registry, &selection, &request)?;

        // One preflight beats N identical per-scanner failures.
        if !self.runner.is_available().await {
            return Err(
                "no Docker daemon is reachable, so no scanner can run. Start Docker and retry; call audit_status to re-check."
                    .to_string(),
            );
        }

        let options = ScanOptions {
            timeout: request.timeout_secs.map(Duration::from_secs),
            include_raw_logs: request.include_raw_logs.unwrap_or(false),
        };
        let permits = Arc::new(Semaphore::new(
            request
                .max_parallel
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_MAX_PARALLEL),
        ));

        let runs = join_all(scanners_to_run.iter().map(|scanner_name| {
            let runner = self.runner.clone();
            let permits = permits.clone();
            let scanner = self
                .registry
                .get(scanner_name)
                .expect("scanner is validated before execution")
                .clone();
            let target = request.target.clone();
            let options = options.clone();
            async move {
                // Bound concurrency: every scanner is a container with its own
                // memory ceiling, so `mode=all` must not fan out without limit.
                let _permit = match permits.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        return ScannerRunResult::failed(
                            &scanner.name,
                            "scan scheduler shut down before this scanner could start",
                        );
                    }
                };
                runner.run_scan(&scanner, &target, &options).await
            }
        }))
        .await;

        let (runs, summary) = shape_results(runs, &request);

        Ok(Json(RunScanResponse {
            mode: mode.as_str().to_string(),
            target: request.target,
            selection,
            summary,
            runs,
        }))
    }

    #[tool(
        name = "explain_finding",
        description = "Explain a finding and provide remediation guidance."
    )]
    pub async fn explain_finding(
        &self,
        Parameters(request): Parameters<ExplainFindingRequest>,
    ) -> Json<FindingExplanation> {
        Json(self.explainer.explain(&request.scanner, &request.id))
    }

    #[tool(
        name = "suggest_fixes",
        description = "Suggest minimal diffs or steps from normalized findings."
    )]
    pub async fn suggest_fixes(
        &self,
        Parameters(request): Parameters<SuggestFixesRequest>,
    ) -> Json<SuggestFixesResponse> {
        Json(self.fixer.suggest(&request.findings))
    }
}

/// Deduplicate, filter, sort, and cap findings, and roll the run statuses up
/// into a summary. Everything that shapes the response payload lives here so
/// it can be tested without Docker.
fn shape_results(
    mut runs: Vec<ScannerRunResult>,
    request: &RunScanRequest,
) -> (Vec<ScannerRunResult>, ScanSummary) {
    let min_severity = request
        .min_severity
        .as_deref()
        .map(Severity::parse)
        .unwrap_or(Severity::Unknown);
    let max_findings = request.max_findings.unwrap_or(DEFAULT_MAX_FINDINGS);

    let mut summary = ScanSummary {
        // Counts the scanners actually dispatched, which differs from the
        // auto-selection plan in `single`/`many` mode.
        scanners_selected: runs.len(),
        ..Default::default()
    };

    let mut duplicates = 0_usize;
    let mut filtered = 0_usize;

    for run in &mut runs {
        // A scanner can report the same rule at the same location twice when
        // the same file is reached through more than one path.
        let mut seen = HashSet::new();
        run.findings.retain(|finding| {
            if !seen.insert(finding.fingerprint.clone()) {
                duplicates += 1;
                return false;
            }
            true
        });

        run.findings.retain(|finding| {
            let keep = Severity::parse(&finding.severity) >= min_severity;
            if !keep {
                filtered += 1;
            }
            keep
        });

        // Highest severity first so a truncated list keeps what matters.
        run.findings.sort_by(|left, right| {
            Severity::parse(&right.severity)
                .cmp(&Severity::parse(&left.severity))
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });

        summary.total_findings += run.findings.len();
        for finding in &run.findings {
            *summary
                .by_severity
                .entry(finding.severity.clone())
                .or_insert(0) += 1;
        }

        match run.status {
            RunStatus::Findings => summary.scanners_with_findings += 1,
            RunStatus::Clean => summary.scanners_clean += 1,
            RunStatus::ToolError => summary.scanners_failed += 1,
            RunStatus::Timeout => summary.scanners_timed_out += 1,
            RunStatus::Skipped => summary.scanners_skipped += 1,
            RunStatus::Unparsed => {}
        }

        // A severity filter can empty out a run that genuinely had findings.
        if run.status == RunStatus::Findings && run.findings.is_empty() {
            run.status = RunStatus::Clean;
            summary.scanners_with_findings -= 1;
            summary.scanners_clean += 1;
        }
    }

    // Cap across all runs, spending the budget on the most severe findings
    // first rather than on whichever scanner happens to be listed first.
    let mut budget = max_findings;
    let mut order = runs
        .iter()
        .enumerate()
        .flat_map(|(index, run)| {
            run.findings
                .iter()
                .enumerate()
                .map(move |(position, finding)| {
                    (Severity::parse(&finding.severity), index, position)
                })
        })
        .collect::<Vec<_>>();
    order.sort_by_key(|entry| std::cmp::Reverse(entry.0));

    let mut keep: Vec<HashSet<usize>> = vec![HashSet::new(); runs.len()];
    for (_, run_index, position) in order {
        if budget == 0 {
            break;
        }
        keep[run_index].insert(position);
        budget -= 1;
    }

    let mut dropped = 0_usize;
    for (index, run) in runs.iter_mut().enumerate() {
        let mut position = 0;
        run.findings.retain(|_| {
            let retained = keep[index].contains(&position);
            position += 1;
            if !retained {
                dropped += 1;
            }
            retained
        });
        summary.findings_returned += run.findings.len();
    }

    if duplicates > 0 {
        summary
            .notes
            .push(format!("{duplicates} duplicate finding(s) collapsed."));
    }
    if filtered > 0 {
        summary.notes.push(format!(
            "{filtered} finding(s) below severity '{}' were filtered out.",
            min_severity.as_str()
        ));
    }
    if dropped > 0 {
        summary.notes.push(format!(
            "{dropped} finding(s) omitted to stay within max_findings={max_findings}; raise max_findings or add min_severity to see more."
        ));
    }
    if summary.scanners_failed > 0 || summary.scanners_timed_out > 0 {
        summary.notes.push(format!(
            "{} scanner(s) failed and {} timed out; their `error` and `execution.logs` fields carry the diagnostics.",
            summary.scanners_failed, summary.scanners_timed_out
        ));
    }

    (runs, summary)
}

fn resolve_scanners_for_request(
    registry: &ScannerRegistry,
    selection: &ToolSelectionPlan,
    request: &RunScanRequest,
) -> Result<(RunScanMode, Vec<String>), String> {
    let mode = request.mode.unwrap_or(RunScanMode::Single);

    let mut scanners = match mode {
        RunScanMode::Single => vec![
            request
                .scanner
                .clone()
                .ok_or_else(|| "run_scan mode=single requires 'scanner'".to_string())?,
        ],
        RunScanMode::Many => request
            .scanners
            .clone()
            .ok_or_else(|| "run_scan mode=many requires 'scanners[]'".to_string())?,
        RunScanMode::All => selection.selected_scanners.clone(),
    };

    if scanners.is_empty() {
        return Err(match mode {
            RunScanMode::All => format!(
                "run_scan mode=all found no eligible scanners for target '{}'",
                request.target
            ),
            RunScanMode::Many => "run_scan mode=many requires at least one scanner".to_string(),
            RunScanMode::Single => "run_scan mode=single requires exactly one scanner".to_string(),
        });
    }

    scanners.sort();
    scanners.dedup();

    let unknown = scanners
        .iter()
        .filter(|scanner| registry.get(scanner).is_none())
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!(
            "unsupported scanner(s): {}. Call list_scanners for the catalog.",
            unknown.join(", ")
        ));
    }

    Ok((mode, scanners))
}

/// Convenience for tests and callers building a request programmatically.
impl RunScanRequest {
    pub fn new(target: impl Into<String>, mode: RunScanMode) -> Self {
        Self {
            target: target.into(),
            mode: Some(mode),
            scanner: None,
            scanners: None,
            min_severity: None,
            max_findings: None,
            include_raw_logs: None,
            timeout_secs: None,
            max_parallel: None,
        }
    }

    pub fn with_scanner(mut self, scanner: impl Into<String>) -> Self {
        self.scanner = Some(scanner.into());
        self
    }

    pub fn with_scanners(mut self, scanners: Vec<String>) -> Self {
        self.scanners = Some(scanners);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{RunScanMode, RunScanRequest, resolve_scanners_for_request, shape_results};
    use crate::models::{
        FindingLocation, NormalizedFinding, RunStatus, ScannerRunResult, ToolSelectionPlan,
    };
    use crate::{scanners::ScannerRegistry, selection::ToolSelector};
    use serde_json::json;

    fn finding(scanner: &str, id: &str, severity: &str) -> NormalizedFinding {
        NormalizedFinding {
            id: id.to_string(),
            scanner: scanner.to_string(),
            category: "Test".to_string(),
            severity: severity.to_string(),
            title: id.to_string(),
            description: String::new(),
            location: FindingLocation {
                path: Some("a.rs".to_string()),
                line: Some(1),
                column: None,
            },
            fingerprint: format!("{scanner}:{id}"),
            remediation: String::new(),
            references: vec![],
            raw: json!({}),
        }
    }

    fn run(scanner: &str, findings: Vec<NormalizedFinding>) -> ScannerRunResult {
        ScannerRunResult {
            scanner: scanner.to_string(),
            status: if findings.is_empty() {
                RunStatus::Clean
            } else {
                RunStatus::Findings
            },
            execution: None,
            findings,
            error: None,
        }
    }

    fn empty_plan() -> ToolSelectionPlan {
        ToolSelectionPlan {
            phase: "test".to_string(),
            selected_scanners: vec![],
            rationale: String::new(),
            detected_languages: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn resolves_single_mode() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let selector = ToolSelector::new();
        let selection = selector.plan("src/main.rs", &registry);

        let request =
            RunScanRequest::new("src/main.rs", RunScanMode::Single).with_scanner("cargo-clippy");

        let (mode, scanners) =
            resolve_scanners_for_request(&registry, &selection, &request).expect("should resolve");
        assert_eq!(mode, RunScanMode::Single);
        assert_eq!(scanners, vec!["cargo-clippy".to_string()]);
    }

    #[test]
    fn resolves_many_mode_with_dedup() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let selector = ToolSelector::new();
        let selection = selector.plan("src/main.rs", &registry);

        let request = RunScanRequest::new("src/main.rs", RunScanMode::Many).with_scanners(vec![
            "cargo-fmt".to_string(),
            "cargo-clippy".to_string(),
            "cargo-fmt".to_string(),
        ]);

        let (mode, scanners) =
            resolve_scanners_for_request(&registry, &selection, &request).expect("should resolve");
        assert_eq!(mode, RunScanMode::Many);
        assert_eq!(
            scanners,
            vec!["cargo-clippy".to_string(), "cargo-fmt".to_string()]
        );
    }

    #[test]
    fn reports_every_unknown_scanner_at_once() {
        let registry = ScannerRegistry::new().expect("registry");
        let selection = empty_plan();
        let request = RunScanRequest::new("/tmp", RunScanMode::Many)
            .with_scanners(vec!["nope".to_string(), "also-nope".to_string()]);

        let error = resolve_scanners_for_request(&registry, &selection, &request)
            .expect_err("unknown scanners must be rejected");
        assert!(error.contains("also-nope") && error.contains("nope"));
    }

    #[test]
    fn resolves_all_mode_from_selection() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let selector = ToolSelector::new();
        // The repository root is a real Rust project, so detection is content-based.
        let selection = selector.plan(env!("CARGO_MANIFEST_DIR"), &registry);

        let request = RunScanRequest::new(env!("CARGO_MANIFEST_DIR"), RunScanMode::All);

        let (mode, scanners) =
            resolve_scanners_for_request(&registry, &selection, &request).expect("should resolve");
        assert_eq!(mode, RunScanMode::All);
        assert!(scanners.contains(&"cargo-clippy".to_string()));
        assert!(scanners.contains(&"semgrep".to_string()));
    }

    #[test]
    fn summary_counts_statuses_and_severities() {
        let runs = vec![
            run(
                "a",
                vec![finding("a", "A1", "critical"), finding("a", "A2", "low")],
            ),
            run("b", vec![]),
            ScannerRunResult::failed("c", "boom"),
            ScannerRunResult::skipped("d", "no token"),
        ];
        let request = RunScanRequest::new("/tmp", RunScanMode::Many);
        let (runs, summary) = shape_results(runs, &request);

        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.findings_returned, 2);
        assert_eq!(summary.by_severity.get("critical"), Some(&1));
        assert_eq!(summary.by_severity.get("low"), Some(&1));
        assert_eq!(summary.scanners_with_findings, 1);
        assert_eq!(summary.scanners_clean, 1);
        assert_eq!(summary.scanners_failed, 1);
        assert_eq!(summary.scanners_skipped, 1);
        // Most severe first.
        assert_eq!(runs[0].findings[0].severity, "critical");
    }

    #[test]
    fn min_severity_filters_and_reclassifies_empty_runs() {
        let runs = vec![run("a", vec![finding("a", "A1", "low")])];
        let mut request = RunScanRequest::new("/tmp", RunScanMode::Many);
        request.min_severity = Some("high".to_string());

        let (runs, summary) = shape_results(runs, &request);
        assert!(runs[0].findings.is_empty());
        // The run no longer has findings, so it must not be reported as if it did.
        assert_eq!(runs[0].status, RunStatus::Clean);
        assert_eq!(summary.scanners_with_findings, 0);
        assert_eq!(summary.scanners_clean, 1);
        assert!(
            summary
                .notes
                .iter()
                .any(|note| note.contains("filtered out"))
        );
    }

    #[test]
    fn max_findings_keeps_the_most_severe_across_scanners() {
        let runs = vec![
            run(
                "a",
                vec![finding("a", "A1", "low"), finding("a", "A2", "info")],
            ),
            run("b", vec![finding("b", "B1", "critical")]),
        ];
        let mut request = RunScanRequest::new("/tmp", RunScanMode::Many);
        request.max_findings = Some(1);

        let (runs, summary) = shape_results(runs, &request);
        assert_eq!(summary.findings_returned, 1);
        assert_eq!(summary.total_findings, 3);
        // The single retained finding must be the critical one from scanner b.
        let kept = runs
            .iter()
            .flat_map(|run| run.findings.iter())
            .collect::<Vec<_>>();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].severity, "critical");
        assert!(summary.notes.iter().any(|note| note.contains("omitted")));
    }

    #[test]
    fn duplicate_fingerprints_are_collapsed() {
        let runs = vec![run(
            "a",
            vec![finding("a", "A1", "high"), finding("a", "A1", "high")],
        )];
        let request = RunScanRequest::new("/tmp", RunScanMode::Many);
        let (runs, summary) = shape_results(runs, &request);

        assert_eq!(runs[0].findings.len(), 1);
        assert!(summary.notes.iter().any(|note| note.contains("duplicate")));
    }
}
