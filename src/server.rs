use std::sync::Arc;

use futures_util::future::join_all;
use rmcp::{
    Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    explain::FindingExplainer,
    fixes::FixEngine,
    models::{
        FindingExplanation, ListScannersResponse, NormalizedFinding, RunScanResponse,
        ScannerRunResult, SuggestFixesResponse,
    },
    runner::DockerScannerRunner,
    scanners::ScannerRegistry,
    selection::ToolSelector,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunScanRequest {
    pub mode: Option<RunScanMode>,
    pub scanner: Option<String>,
    pub scanners: Option<Vec<String>>,
    pub target: String,
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
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            tool_router: Self::tool_router(),
            registry: Arc::new(ScannerRegistry::new()?),
            runner: Arc::new(DockerScannerRunner::new()?),
            explainer: Arc::new(FindingExplainer::new()),
            fixer: Arc::new(FixEngine::new()),
            selector: Arc::new(ToolSelector::new()),
        })
    }
}

#[tool_handler(
    router = self.tool_router,
    name = "audit-mcp",
    version = "0.1.0",
    instructions = "Runs dockerized audit scanners and returns normalized findings with remediation context."
)]
impl ServerHandler for AuditMcpServer {}

#[tool_router(router = tool_router)]
impl AuditMcpServer {
    #[tool(
        name = "list_scanners",
        description = "List supported scanners and their categories."
    )]
    pub async fn list_scanners(&self) -> Json<ListScannersResponse> {
        Json(ListScannersResponse {
            scanners: self.registry.list_summaries(),
        })
    }

    #[tool(
        name = "run_scan",
        description = "Run a dockerized scanner and return normalized findings."
    )]
    pub async fn run_scan(
        &self,
        Parameters(request): Parameters<RunScanRequest>,
    ) -> Result<Json<RunScanResponse>, String> {
        let selection = self.selector.plan(&request.target, &self.registry);
        let (mode, scanners_to_run) =
            resolve_scanners_for_request(&self.registry, &selection, &request)?;

        let runs = join_all(scanners_to_run.iter().map(|scanner_name| {
            let runner = self.runner.clone();
            let scanner = self
                .registry
                .get(scanner_name)
                .expect("scanner should be validated before execution")
                .clone();
            let target = request.target.clone();
            async move {
                match runner.run_scan(&scanner, &target).await {
                    Ok((execution, findings)) => ScannerRunResult {
                        scanner: scanner.name,
                        execution: Some(execution),
                        findings,
                        error: None,
                    },
                    Err(error) => ScannerRunResult {
                        scanner: scanner.name,
                        execution: None,
                        findings: vec![],
                        error: Some(error),
                    },
                }
            }
        }))
        .await;

        Ok(Json(RunScanResponse {
            mode: mode.as_str().to_string(),
            target: request.target,
            selection,
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

fn resolve_scanners_for_request(
    registry: &ScannerRegistry,
    selection: &crate::models::ToolSelectionPlan,
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
            RunScanMode::All => {
                format!(
                    "run_scan mode=all found no eligible scanners for target '{}'",
                    request.target
                )
            }
            RunScanMode::Many => "run_scan mode=many requires at least one scanner".to_string(),
            RunScanMode::Single => "run_scan mode=single requires exactly one scanner".to_string(),
        });
    }

    scanners.sort();
    scanners.dedup();

    for scanner in &scanners {
        if registry.get(scanner).is_none() {
            return Err(format!("scanner '{}' is not supported", scanner));
        }
    }

    Ok((mode, scanners))
}

#[cfg(test)]
mod tests {
    use super::{RunScanMode, RunScanRequest, resolve_scanners_for_request};
    use crate::{scanners::ScannerRegistry, selection::ToolSelector};

    #[test]
    fn resolves_single_mode() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let selector = ToolSelector::new();
        let selection = selector.plan("src/main.rs", &registry);

        let request = RunScanRequest {
            mode: Some(RunScanMode::Single),
            scanner: Some("cargo-clippy".to_string()),
            scanners: None,
            target: "src/main.rs".to_string(),
        };

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

        let request = RunScanRequest {
            mode: Some(RunScanMode::Many),
            scanner: None,
            scanners: Some(vec![
                "cargo-fmt".to_string(),
                "cargo-clippy".to_string(),
                "cargo-fmt".to_string(),
            ]),
            target: "src/main.rs".to_string(),
        };

        let (mode, scanners) =
            resolve_scanners_for_request(&registry, &selection, &request).expect("should resolve");
        assert_eq!(mode, RunScanMode::Many);
        assert_eq!(
            scanners,
            vec!["cargo-clippy".to_string(), "cargo-fmt".to_string()]
        );
    }

    #[test]
    fn resolves_all_mode_from_selection() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let selector = ToolSelector::new();
        let selection = selector.plan("app/main.py", &registry);

        let request = RunScanRequest {
            mode: Some(RunScanMode::All),
            scanner: None,
            scanners: None,
            target: "app/main.py".to_string(),
        };

        let (mode, scanners) =
            resolve_scanners_for_request(&registry, &selection, &request).expect("should resolve");
        assert_eq!(mode, RunScanMode::All);
        assert!(scanners.contains(&"bandit".to_string()));
        assert!(scanners.contains(&"ruff".to_string()));
    }
}
