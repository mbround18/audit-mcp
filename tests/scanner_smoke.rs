//! Smoke tests that every scanner declaring structured output can actually
//! *run* — the failure mode this catches is a command template that no image
//! can execute (a swallowed ENTRYPOINT, a renamed flag, a tool that was never
//! installed in the base image).
//!
//! These pull real images and are `#[ignore]`d by default:
//!
//!   cargo test --test scanner_smoke -- --ignored --nocapture
//!
//! They are split by cost so the fast tier can be run routinely:
//!   * `smoke_fast_tier`   — python/node/iac/security/shell/c-cpp images
//!   * `smoke_slow_tier`   — rust/go/java/dotnet, which compile before scanning
//!
//! A scanner "passes" when it does not come back as `tool_error`. Finding
//! nothing is a pass; being unable to run is not.

use audit_mcp::models::RunStatus;
use audit_mcp::runner::{DockerScannerRunner, ScanOptions};
use audit_mcp::scanners::ScannerRegistry;
use bollard::Docker;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

async fn docker_available() -> bool {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => docker.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// Pick a fixture whose contents suit the scanner under test.
fn fixture_for(scanner: &str) -> String {
    match scanner {
        "bandit" | "ruff" | "pip-audit" => fixture("python"),
        "eslint" => fixture("eslint"),
        "npm-audit" | "osv-scanner" | "grype" => fixture("knip"),
        "shellcheck" => fixture("shellcheck"),
        "hadolint" => fixture("hadolint"),
        "kube-linter" | "kubesec" => fixture("k8s"),
        "checkov" | "tfsec" | "terrascan" | "trivy-config" => fixture("detect/terraform"),
        "staticcheck" | "gosec" | "govulncheck" | "golangci-lint" => fixture("go"),
        // The repository itself is the most realistic Rust target available.
        scanner if scanner.starts_with("cargo-") => env!("CARGO_MANIFEST_DIR").to_string(),
        _ => fixture("multi"),
    }
}

/// Run one scanner and return a one-line verdict, or `None` when it ran fine.
async fn check(runner: &DockerScannerRunner, scanner: &str) -> Option<String> {
    let registry = ScannerRegistry::new().expect("registry");
    let definition = registry.get(scanner).expect("scanner in catalog").clone();

    let options = ScanOptions {
        // Keep a stuck scanner from stalling the whole sweep.
        timeout: Some(std::time::Duration::from_secs(420)),
        include_raw_logs: true,
    };
    let result = runner
        .run_scan(&definition, &fixture_for(scanner), &options)
        .await;

    let findings = result.findings.len();
    println!(
        "  {:<22} {:<10} findings={}",
        scanner,
        result.status.as_str(),
        findings
    );
    if !matches!(result.status, RunStatus::Clean | RunStatus::Findings) {
        // Print the tail of the container output so a failure is diagnosable
        // from the test log alone.
        if let Some(logs) = result.execution.as_ref().and_then(|e| e.logs.as_deref()) {
            let tail: String = logs
                .chars()
                .rev()
                .take(600)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            println!("      logs(tail): {}", tail.replace('\n', " | "));
        }
    }

    match result.status {
        RunStatus::ToolError | RunStatus::Timeout => Some(format!(
            "{scanner}: {} — {}",
            result.status.as_str(),
            result
                .error
                .unwrap_or_default()
                .chars()
                .take(400)
                .collect::<String>()
        )),
        // A structured scanner that came back unparsed emitted output its
        // declared parser could not read, which is a real regression.
        RunStatus::Unparsed => Some(format!(
            "{scanner}: declared structured output but nothing parsed"
        )),
        _ => None,
    }
}

async fn run_tier(scanners: &[&str]) {
    if !docker_available().await {
        eprintln!("skipping: no reachable Docker daemon");
        return;
    }

    let runner = DockerScannerRunner::new();
    let mut failures = Vec::new();
    for scanner in scanners {
        if let Some(failure) = check(&runner, scanner).await {
            failures.push(failure);
        }
    }

    assert!(
        failures.is_empty(),
        "{} scanner(s) could not run:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Scanners whose images are small and which do not compile the project.
#[tokio::test]
#[ignore]
async fn smoke_fast_tier() {
    run_tier(&[
        // python
        "bandit",
        "ruff",
        "pip-audit",
        // node
        "eslint",
        "npm-audit",
        // shell
        "shellcheck",
        // iac
        "hadolint",
        "checkov",
        "tfsec",
        "trivy-config",
        "kube-linter",
        "terrascan",
        // cross-language security
        "semgrep",
        "gitleaks",
        "grype",
        "osv-scanner",
        // c/c++
        "flawfinder",
    ])
    .await;
}

/// Scanners that download a toolchain or compile before they can report.
/// Slow (tens of minutes on a cold cache) but the same contract applies.
#[tokio::test]
#[ignore]
async fn smoke_slow_tier() {
    run_tier(&[
        "staticcheck",
        "gosec",
        "govulncheck",
        "cargo-clippy",
        "cargo-audit",
    ])
    .await;
}
