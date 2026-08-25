//! End-to-end tests that exercise the real MCP tool surface against real,
//! ephemeral Docker containers. These are network- and Docker-dependent, so
//! they are `#[ignore]`d by default — run them explicitly with:
//!
//!   cargo test --test e2e_scan -- --ignored
//!
//! Each test checks Docker reachability first and skips (rather than fails)
//! when no daemon is available, so the suite degrades gracefully in
//! environments without a Docker socket.
//!
//! Unlike the previous revision, these assert on *normalized findings* —
//! rule IDs, severities, and file locations — not on substrings of raw logs.

use audit_mcp::models::{NormalizedFinding, OutputFormat, RunStatus, ScannerDefinition};
use audit_mcp::runner::{ScanOptions, ScanRunner};
use audit_mcp::server::{AuditMcpServer, ExplainFindingRequest, RunScanMode, RunScanRequest};
use bollard::Docker;
use rmcp::handler::server::wrapper::Parameters;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Returns `true` when a Docker daemon is reachable, so tests can skip
/// cleanly instead of failing in environments without Docker.
async fn docker_available() -> bool {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => docker.ping().await.is_ok(),
        Err(_) => false,
    }
}

macro_rules! require_docker {
    () => {
        if !docker_available().await {
            eprintln!("skipping: no reachable Docker daemon");
            return;
        }
    };
}

/// Run one scanner and assert it completed without a tool-level failure.
async fn scan_one(scanner: &str, target: &str) -> Vec<NormalizedFinding> {
    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan_for(
            RunScanRequest::new(target, RunScanMode::Single).with_scanner(scanner),
            None,
        )
        .await
        .expect("run_scan should succeed");

    assert_eq!(response.0.runs.len(), 1);
    let run = &response.0.runs[0];
    assert_eq!(run.scanner, scanner);
    assert!(
        !matches!(run.status, RunStatus::ToolError | RunStatus::Timeout),
        "scanner '{scanner}' failed with status {:?}: {:?}\nlogs: {:?}",
        run.status,
        run.error,
        run.execution.as_ref().and_then(|e| e.logs.as_deref()),
    );
    assert!(
        run.execution.is_some(),
        "expected execution metadata for '{scanner}'"
    );
    run.findings.clone()
}

fn assert_has_rule(findings: &[NormalizedFinding], rule: &str) {
    assert!(
        findings.iter().any(|finding| finding.id.contains(rule)),
        "expected rule '{rule}' among {:?}",
        findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore]
async fn shellcheck_normalizes_unquoted_variable_finding() {
    require_docker!();
    let findings = scan_one("shellcheck", &fixture("shellcheck")).await;

    assert_has_rule(&findings, "SC2086");
    let finding = findings
        .iter()
        .find(|finding| finding.id == "SC2086")
        .expect("SC2086");
    assert_eq!(finding.location.path.as_deref(), Some("deploy.sh"));
    assert!(finding.location.line.is_some());
    assert!(finding.title.to_lowercase().contains("double quote"));
    assert!(finding.references.iter().any(|url| url.contains("SC2086")));
}

#[tokio::test]
#[ignore]
async fn bandit_normalizes_shell_true_subprocess_finding() {
    require_docker!();
    let findings = scan_one("bandit", &fixture("bandit")).await;

    assert!(
        findings
            .iter()
            .any(|finding| finding.id.starts_with("B6") || finding.id.starts_with("B4")),
        "expected a subprocess/shell finding among {:?}",
        findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>()
    );
    let finding = &findings[0];
    assert_eq!(finding.location.path.as_deref(), Some("app.py"));
    assert!(matches!(
        finding.severity.as_str(),
        "critical" | "high" | "medium" | "low"
    ));
}

#[tokio::test]
#[ignore]
async fn hadolint_normalizes_unpinned_base_image_finding() {
    require_docker!();
    let findings = scan_one("hadolint", &fixture("hadolint")).await;

    assert_has_rule(&findings, "DL3006");
    let finding = findings
        .iter()
        .find(|finding| finding.id == "DL3006")
        .expect("DL3006");
    assert!(finding.location.line.is_some());
}

#[tokio::test]
#[ignore]
async fn semgrep_returns_sarif_normalized_findings() {
    require_docker!();
    // semgrep's default ruleset on the python fixture; we assert the shape of
    // the SARIF pipeline rather than a specific rule, which can change.
    let findings = scan_one("semgrep", &fixture("bandit")).await;
    for finding in &findings {
        assert!(!finding.id.is_empty());
        assert!(!finding.fingerprint.is_empty());
        assert!(
            !finding
                .location
                .path
                .as_deref()
                .unwrap_or_default()
                .starts_with("/workspace"),
            "container mount path leaked into a finding location"
        );
    }
}

#[tokio::test]
#[ignore]
async fn gitleaks_runs_clean_on_a_repository_without_secrets() {
    require_docker!();
    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan_for(
            RunScanRequest::new(fixture("knip"), RunScanMode::Single).with_scanner("gitleaks"),
            None,
        )
        .await
        .expect("run_scan should succeed");

    let run = &response.0.runs[0];
    // The point of this test: a scanner with nothing to report must come back
    // as `clean`, never as an "unparsed" placeholder or a silent success.
    assert_eq!(
        run.status,
        RunStatus::Clean,
        "expected clean, got {:?}: {:?}",
        run.status,
        run.error
    );
    assert!(run.findings.is_empty());
}

#[tokio::test]
#[ignore]
async fn many_mode_runs_scanners_in_parallel_with_a_summary() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan_for(
            RunScanRequest::new(fixture("multi"), RunScanMode::Many)
                .with_scanners(vec!["shellcheck".to_string(), "hadolint".to_string()]),
            None,
        )
        .await
        .expect("run_scan should succeed");

    assert_eq!(response.0.runs.len(), 2);
    let names: Vec<&str> = response.0.runs.iter().map(|r| r.scanner.as_str()).collect();
    assert!(names.contains(&"shellcheck"));
    assert!(names.contains(&"hadolint"));

    for run in &response.0.runs {
        assert!(
            !matches!(run.status, RunStatus::ToolError | RunStatus::Timeout),
            "scanner '{}' failed: {:?}",
            run.scanner,
            run.error
        );
    }

    let summary = &response.0.summary;
    assert_eq!(summary.scanners_selected, 2);
    assert_eq!(
        summary.findings_returned,
        response
            .0
            .runs
            .iter()
            .map(|run| run.findings.len())
            .sum::<usize>()
    );
    assert!(
        summary.total_findings > 0,
        "both fixtures contain known violations"
    );
}

#[tokio::test]
#[ignore]
async fn all_mode_detects_languages_from_directory_contents() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let mut request = RunScanRequest::new(fixture("multi"), RunScanMode::All);
    // Keep the container fan-out (and the runtime) small for a test.
    request.max_parallel = Some(2);
    request.scanners = None;

    let response = server
        .run_scan_for(request, None)
        .await
        .expect("run_scan should succeed");

    // The fixture holds a Dockerfile and a shell script.
    let detected = &response.0.selection.detected_languages;
    assert!(detected.contains(&"iac".to_string()), "{detected:?}");
    assert!(detected.contains(&"shell".to_string()), "{detected:?}");
    assert!(
        response
            .0
            .selection
            .selected_scanners
            .contains(&"hadolint".to_string())
    );
}

#[tokio::test]
#[ignore]
async fn scan_reports_missing_target_without_crashing() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan_for(
            RunScanRequest::new(fixture("does-not-exist"), RunScanMode::Single)
                .with_scanner("shellcheck"),
            None,
        )
        .await
        .expect("tool call itself should succeed even though the scan fails");

    let run = &response.0.runs[0];
    assert_eq!(run.status, RunStatus::ToolError);
    assert!(run.execution.is_none());
    assert!(run.findings.is_empty());
    let error = run.error.as_ref().expect("expected a target error");
    assert!(
        error.contains("does not exist"),
        "unexpected error message: {error}"
    );
}

#[tokio::test]
#[ignore]
async fn timeout_is_enforced_and_reported_as_a_timeout() {
    require_docker!();

    // A synthetic scanner that deliberately outlives its budget, so the test
    // measures the timeout path itself rather than a real tool's runtime.
    let scanner = ScannerDefinition {
        name: "sleeper".to_string(),
        description: "test-only scanner that never finishes".to_string(),
        image: "alpine:3".to_string(),
        categories: vec!["Test".to_string()],
        command_template: vec!["sh".to_string(), "-c".to_string(), "sleep 120".to_string()],
        install_script: None,
        success_exit_codes: vec![0],
        output_format: OutputFormat::Text,
        timeout_secs: Some(2),
    };

    let runner = ScanRunner::docker();
    let started = std::time::Instant::now();
    let result = runner
        .run_scan(&scanner, &fixture("multi"), &ScanOptions::default())
        .await;

    assert_eq!(
        result.status,
        RunStatus::Timeout,
        "expected a timeout, got {:?}: {:?}",
        result.status,
        result.error
    );
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("budget")
    );
    // The container must actually be killed, not merely abandoned.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "timeout did not cut the run short"
    );
    let execution = result
        .execution
        .expect("timed-out runs still report execution");
    assert_eq!(execution.status, "timeout");
    assert!(execution.exit_code.is_none());
}

#[tokio::test]
#[ignore]
async fn scans_a_repository_that_was_never_checked_out() {
    require_docker!();
    use std::net::ToSocketAddrs;
    if ("github.com", 443).to_socket_addrs().is_err() {
        eprintln!("skipping: github.com is not resolvable");
        return;
    }

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan_for(
            // A URL, not a path. Nothing is checked out locally.
            RunScanRequest::new(
                "https://github.com/octocat/Hello-World",
                RunScanMode::Single,
            )
            .with_scanner("gitleaks"),
            None,
        )
        .await
        .expect("run_scan should succeed");

    let workspace = &response.0.workspace;
    assert_eq!(workspace.origin, "git_https");
    // Which credential was used depends on the host — a machine with a
    // logged-in `gh` borrows its token. What matters is that the source is
    // reported by name, and that a name is all it ever is.
    let source = workspace
        .credential_source
        .as_deref()
        .expect("a cloned scan reports which credential it used");
    assert!(
        ["anonymous", "gh_cli", "token", "github_app"].contains(&source),
        "unexpected credential source: {source}"
    );
    let resolved = workspace
        .resolved_ref
        .as_deref()
        .expect("a cloned scan reports the commit it scanned");
    assert_eq!(resolved.len(), 40, "a full commit sha");

    let run = &response.0.runs[0];
    assert!(
        !matches!(run.status, RunStatus::ToolError | RunStatus::Timeout),
        "scan of a cloned repository failed: {:?}",
        run.error
    );

    // No temporary directory prefix may reach a finding location.
    for finding in &run.findings {
        let path = finding.location.path.as_deref().unwrap_or_default();
        assert!(
            !path.contains("audit-workspace-") && !path.starts_with("/tmp"),
            "a clone path leaked into a finding location: {path}"
        );
    }
}

/// These don't touch Docker at all, so they run unconditionally and act as a
/// fast smoke test of the non-container tool surface.
#[tokio::test]
async fn catalog_and_explain_work_without_docker() {
    let server = AuditMcpServer::new().expect("server should initialize");

    let catalog = server.list_scanners().await;
    assert!(
        catalog.0.scanners.len() >= 90,
        "expected the full scanner catalog, got {}",
        catalog.0.scanners.len()
    );
    assert!(
        catalog
            .0
            .scanners
            .iter()
            .any(|scanner| scanner.name == "shellcheck" && scanner.normalized)
    );

    let explanation = server
        .explain_finding(Parameters(ExplainFindingRequest {
            scanner: "bandit".to_string(),
            id: "B101".to_string(),
        }))
        .await;
    assert_eq!(explanation.0.title, "Use of assert detected");
}

/// `audit_status` must answer regardless of whether Docker is running — the
/// server no longer refuses to start without a daemon.
#[tokio::test]
async fn status_reports_catalog_and_docker_reachability() {
    let server = AuditMcpServer::new().expect("server should initialize");
    let status = server.audit_status().await;

    assert!(status.0.scanner_count >= 90);
    assert!(status.0.normalized_scanner_count > 0);
    assert!(status.0.normalized_scanner_count < status.0.scanner_count);
    assert_eq!(status.0.docker_available, docker_available().await);
    assert_eq!(status.0.executor.backend, "docker");
    assert!(!status.0.notes.is_empty());

    // Credential sources are reported by name only, never by value.
    let serialized = serde_json::to_string(&status.0).expect("status serializes");
    assert!(!serialized.contains("ghp_"));
    assert!(status.0.workspace.remote_scanning_enabled);
}
