//! End-to-end tests that exercise the real MCP tool surface against real,
//! ephemeral Docker containers. These are network- and Docker-dependent, so
//! they are `#[ignore]`d by default — run them explicitly with:
//!
//!   cargo test --test e2e_scan -- --ignored
//!
//! Each test checks Docker reachability first and skips (rather than fails)
//! when no daemon is available, so the suite degrades gracefully in
//! environments without a Docker socket.

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

#[tokio::test]
#[ignore]
async fn shellcheck_flags_unquoted_variable() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan(Parameters(RunScanRequest {
            mode: Some(RunScanMode::Single),
            scanner: Some("shellcheck".to_string()),
            scanners: None,
            target: fixture("shellcheck"),
        }))
        .await
        .expect("run_scan should succeed");

    assert_eq!(response.0.runs.len(), 1);
    let run = &response.0.runs[0];
    assert_eq!(run.scanner, "shellcheck");
    assert!(run.error.is_none(), "unexpected error: {:?}", run.error);
    assert!(run.execution.is_some());
    assert_eq!(run.execution.as_ref().unwrap().status, "completed");

    // shellcheck has no dedicated output parser yet, so the fallback finding
    // carries the raw JSON report — assert the known violation surfaced.
    assert!(!run.findings.is_empty());
    let raw = run.findings[0].raw.to_string();
    assert!(
        raw.contains("2086") && raw.contains("Double quote"),
        "expected shellcheck code 2086 (unquoted variable) in raw output: {raw}"
    );
}

#[tokio::test]
#[ignore]
async fn hadolint_flags_unpinned_base_image() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan(Parameters(RunScanRequest {
            mode: Some(RunScanMode::Single),
            scanner: Some("hadolint".to_string()),
            scanners: None,
            target: fixture("hadolint"),
        }))
        .await
        .expect("run_scan should succeed");

    let run = &response.0.runs[0];
    assert!(run.error.is_none(), "unexpected error: {:?}", run.error);
    assert!(!run.findings.is_empty());
    let raw = run.findings[0].raw.to_string();
    assert!(
        raw.contains("DL3006"),
        "expected DL3006 (unpinned FROM tag) in raw output: {raw}"
    );
}

#[tokio::test]
#[ignore]
async fn many_mode_runs_scanners_in_parallel() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan(Parameters(RunScanRequest {
            mode: Some(RunScanMode::Many),
            scanner: None,
            scanners: Some(vec!["shellcheck".to_string(), "hadolint".to_string()]),
            target: fixture("multi"),
        }))
        .await
        .expect("run_scan should succeed");

    assert_eq!(response.0.runs.len(), 2);
    let names: Vec<&str> = response.0.runs.iter().map(|r| r.scanner.as_str()).collect();
    assert!(names.contains(&"shellcheck"));
    assert!(names.contains(&"hadolint"));
    for run in &response.0.runs {
        assert!(
            run.error.is_none(),
            "scanner '{}' unexpectedly failed: {:?}",
            run.scanner,
            run.error
        );
    }
}

#[tokio::test]
#[ignore]
async fn run_scan_reports_missing_target_without_crashing() {
    require_docker!();

    let server = AuditMcpServer::new().expect("server should initialize");
    let response = server
        .run_scan(Parameters(RunScanRequest {
            mode: Some(RunScanMode::Single),
            scanner: Some("shellcheck".to_string()),
            scanners: None,
            target: fixture("does-not-exist"),
        }))
        .await
        .expect("tool call itself should succeed even though the scan fails");

    let run = &response.0.runs[0];
    assert!(run.execution.is_none());
    assert!(run.findings.is_empty());
    let error = run.error.as_ref().expect("expected a target error");
    assert!(
        error.contains("does not exist"),
        "unexpected error message: {error}"
    );
}

/// These don't touch Docker at all, so they run unconditionally (no
/// `#[ignore]`) and act as a fast smoke test of the non-container tool
/// surface (`list_scanners`, `explain_finding`, `suggest_fixes`).
#[tokio::test]
async fn list_scanners_and_explain_finding_work_without_docker() {
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
            .any(|scanner| scanner.name == "shellcheck")
    );

    let explanation = server
        .explain_finding(Parameters(ExplainFindingRequest {
            scanner: "bandit".to_string(),
            id: "B101".to_string(),
        }))
        .await;
    assert_eq!(explanation.0.title, "Use of assert detected");
}
