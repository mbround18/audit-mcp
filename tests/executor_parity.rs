//! The Kubernetes backend must produce the same findings as the Docker one.
//!
//! This is the check that catches the cluster path being subtly different —
//! the failure that would otherwise surface months later as "the cluster
//! reports fewer findings than my laptop".
//!
//! `#[ignore]`d and self-skipping. Needs Docker, a reachable cluster with a
//! usable namespace, `git`, and network.

#![cfg(feature = "kubernetes")]

use std::time::Duration;

use audit_mcp::config::KubernetesConfig;
use audit_mcp::executor::kubernetes::KubernetesExecutor;
use audit_mcp::models::{NormalizedFinding, RunStatus, ScannerRunResult};
use audit_mcp::runner::{ScanOptions, ScanRunner};
use audit_mcp::scanners::ScannerRegistry;
use audit_mcp::workspace::{self, Workspace};
use bollard::Docker;
use std::sync::Arc;

/// The namespace this suite is allowed to create workloads in.
const NAMESPACE: &str = "auditor-development";

/// A small public repository containing a shell script, so shellcheck has
/// something to say about it on both backends.
const REPO: &str = "https://github.com/koalaman/shellcheck";

async fn docker_available() -> bool {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => docker.ping().await.is_ok(),
        Err(_) => false,
    }
}

fn kubernetes_config() -> KubernetesConfig {
    KubernetesConfig {
        namespace: Some(NAMESPACE.to_string()),
        ..Default::default()
    }
}

async fn cluster_available() -> bool {
    use audit_mcp::executor::Executor;
    KubernetesExecutor::new(kubernetes_config())
        .is_available()
        .await
}

macro_rules! require_cluster {
    () => {
        if !cluster_available().await {
            eprintln!("skipping: no reachable Kubernetes cluster or namespace '{NAMESPACE}'");
            return;
        }
    };
}

/// Identity of a finding, ignoring anything that legitimately differs between
/// two runs (run ids, durations, image digests).
fn fingerprints(
    findings: &[NormalizedFinding],
) -> Vec<(String, String, Option<String>, Option<u32>)> {
    let mut identities: Vec<_> = findings
        .iter()
        .map(|finding| {
            (
                finding.id.clone(),
                finding.severity.clone(),
                finding.location.path.clone(),
                finding.location.line,
            )
        })
        .collect();
    identities.sort();
    identities
}

async fn scan_with(runner: ScanRunner, scanner: &str, workspace: &Workspace) -> ScannerRunResult {
    let registry = ScannerRegistry::new().expect("registry");
    let definition = registry.get(scanner).expect("scanner in catalog").clone();
    runner
        .run_scan(
            &definition,
            &workspace.scan_path(),
            &ScanOptions {
                timeout: Some(Duration::from_secs(300)),
                include_raw_logs: true,
                source: workspace.source(),
                ..Default::default()
            },
        )
        .await
}

#[tokio::test]
#[ignore]
async fn both_backends_produce_equivalent_findings() {
    require_cluster!();
    if !docker_available().await {
        eprintln!("skipping: no reachable Docker daemon");
        return;
    }

    let workspace = Arc::new(
        workspace::provision(
            REPO,
            &audit_mcp::config::WorkspaceConfig::default(),
            &audit_mcp::redact::Redactor::new(),
        )
        .await
        .expect("clones"),
    );

    let docker = scan_with(ScanRunner::docker(), "shellcheck", &workspace).await;
    let kubernetes = scan_with(
        ScanRunner::with_executor(Arc::new(KubernetesExecutor::new(kubernetes_config()))),
        "shellcheck",
        &workspace,
    )
    .await;

    assert!(
        !matches!(docker.status, RunStatus::ToolError | RunStatus::Timeout),
        "docker backend failed: {:?}",
        docker.error
    );
    assert!(
        !matches!(kubernetes.status, RunStatus::ToolError | RunStatus::Timeout),
        "kubernetes backend failed: {:?} / logs {:?}",
        kubernetes.error,
        kubernetes
            .execution
            .as_ref()
            .and_then(|e| e.logs.as_deref()),
    );

    assert_eq!(
        docker.status, kubernetes.status,
        "the two backends disagree about the outcome"
    );
    assert_eq!(
        fingerprints(&docker.findings),
        fingerprints(&kubernetes.findings),
        "the two backends disagree about the findings"
    );

    // Each reports which backend produced it, and neither leaks a container or
    // clone path into a finding location.
    assert_eq!(
        docker.execution.as_ref().expect("execution").backend,
        "docker"
    );
    assert_eq!(
        kubernetes.execution.as_ref().expect("execution").backend,
        "kubernetes"
    );
    for finding in &kubernetes.findings {
        let path = finding.location.path.as_deref().unwrap_or_default();
        assert!(!path.starts_with("/workspace"), "mount path leaked: {path}");
    }
}

#[tokio::test]
#[ignore]
async fn a_local_path_is_refused_rather_than_scanned_empty() {
    require_cluster!();

    let workspace = Workspace::local(env!("CARGO_MANIFEST_DIR"));
    let result = scan_with(
        ScanRunner::with_executor(Arc::new(KubernetesExecutor::new(kubernetes_config()))),
        "shellcheck",
        &workspace,
    )
    .await;

    // The cluster cannot see this host, and an empty emptyDir reported as
    // "clean" would be the worst possible answer.
    assert_eq!(result.status, RunStatus::ToolError);
    let error = result.error.expect("an explanation");
    assert!(
        error.contains("cannot see this host's filesystem"),
        "{error}"
    );
}

#[tokio::test]
#[ignore]
async fn an_unreachable_cluster_yields_one_preflight_error() {
    // Not one identical failure per selected scanner (FR-016).
    use audit_mcp::executor::Executor;

    let executor = KubernetesExecutor::new(KubernetesConfig {
        namespace: Some("audit-mcp-namespace-that-does-not-exist".to_string()),
        ..Default::default()
    });
    if !cluster_available().await {
        eprintln!("skipping: no reachable Kubernetes cluster");
        return;
    }

    // The namespace check is what makes this meaningful: the API server is
    // reachable, but the place we would create Jobs is not usable.
    assert!(
        !executor.is_available().await,
        "a missing namespace must count as unavailable"
    );
}

#[tokio::test]
#[ignore]
async fn the_backend_cleans_up_after_itself() {
    require_cluster!();

    let workspace = Arc::new(
        workspace::provision(
            REPO,
            &audit_mcp::config::WorkspaceConfig::default(),
            &audit_mcp::redact::Redactor::new(),
        )
        .await
        .expect("clones"),
    );

    let before = count_jobs().await;
    let _ = scan_with(
        ScanRunner::with_executor(Arc::new(KubernetesExecutor::new(kubernetes_config()))),
        "shellcheck",
        &workspace,
    )
    .await;

    // Deletion is background-propagated, so give the controller a moment.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        count_jobs().await,
        before,
        "the Job must be deleted when the scan ends"
    );
}

async fn count_jobs() -> usize {
    let Ok(output) = std::process::Command::new("kubectl")
        .args(["get", "jobs", "-n", NAMESPACE, "--no-headers"])
        .output()
    else {
        return 0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}
