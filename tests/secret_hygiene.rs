//! No credential material may appear in any response field (FR-027, SC-004).
//!
//! Reviewing for this by eye does not work: scanner output is arbitrary text
//! from third-party tools, and a leak arrives through whichever path nobody
//! thought of. So the test seeds a recognisable sentinel into every credential
//! source, runs a real scan, serializes the *entire* response, and asserts the
//! sentinel appears nowhere at all.
//!
//! `#[ignore]`d and self-skipping; needs Docker, `git`, and network.

use audit_mcp::config::{CredentialConfig, WorkspaceConfig};
use audit_mcp::models::ScannerRunResult;
use audit_mcp::redact::Redactor;
use audit_mcp::runner::{ScanOptions, ScanRunner};
use audit_mcp::scanners::ScannerRegistry;
use audit_mcp::workspace;
use bollard::Docker;

/// Distinctive enough that finding it anywhere is unambiguous.
const SENTINEL: &str = "ghp_AUDITMCPSENTINEL0000000000000000000";
const SSH_SENTINEL: &str = "-----BEGIN OPENSSH PRIVATE KEY-----SENTINELKEYMATERIAL";
const PUBLIC_REPO: &str = "https://github.com/octocat/Hello-World";

async fn docker_available() -> bool {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => docker.ping().await.is_ok(),
        Err(_) => false,
    }
}

fn network_available() -> bool {
    use std::net::ToSocketAddrs;
    ("github.com", 443).to_socket_addrs().is_ok()
}

fn seeded_config() -> WorkspaceConfig {
    WorkspaceConfig {
        credentials: CredentialConfig {
            // Not the GitHub App source: minting its token would need a real
            // key. The token path exercises the same delivery mechanism.
            github_app: None,
            token: Some(SENTINEL.to_string()),
            ssh_private_key: Some(SSH_SENTINEL.to_string()),
            ssh_known_hosts: Some("github.com ssh-ed25519 AAAASENTINEL".to_string()),
            // The seeded token is the credential under test; borrowing a real
            // one from `gh` would mean testing the wrong thing.
            use_gh_cli: false,
        },
        ..Default::default()
    }
}

/// Assert a serialized value contains no trace of any seeded secret.
fn assert_no_secrets(label: &str, serialized: &str) {
    for (name, secret) in [("token", SENTINEL), ("ssh key", SSH_SENTINEL)] {
        assert!(
            !serialized.contains(secret),
            "{label} leaked the {name}. This is the failure SC-004 exists to catch."
        );
    }
    // A prefix long enough to be recognisable is also a leak, which is what a
    // truncation that cut mid-secret would produce.
    assert!(
        !serialized.contains("ghp_AUDITMCPSENTINEL"),
        "{label} leaked a recognisable prefix of the token"
    );
}

#[tokio::test]
#[ignore]
async fn a_scan_of_a_cloned_repository_leaks_no_credential() {
    if !docker_available().await {
        eprintln!("skipping: no reachable Docker daemon");
        return;
    }
    if !network_available() {
        eprintln!("skipping: github.com is not resolvable");
        return;
    }

    let redactor = Redactor::new();
    let workspace = workspace::provision(PUBLIC_REPO, &seeded_config(), &redactor)
        .await
        .expect("clone succeeds; a public repository ignores the token");

    // The credential was registered, so anything echoing it gets redacted.
    assert!(
        !redactor.is_empty(),
        "provisioning must register the credential it used"
    );

    let registry = ScannerRegistry::new().expect("registry");
    let scanner = registry.get("shellcheck").expect("shellcheck").clone();
    let runner = ScanRunner::docker();

    let result: ScannerRunResult = runner
        .run_scan(
            &scanner,
            &workspace.scan_path(),
            &ScanOptions {
                // The worst case for leakage: every byte of scanner output is
                // attached to the response.
                include_raw_logs: true,
                redactor: redactor.clone(),
                ..Default::default()
            },
        )
        .await;

    let serialized = serde_json::to_string(&result).expect("result serializes");
    assert_no_secrets("the scanner run result", &serialized);

    let workspace_json =
        serde_json::to_string(workspace.info()).expect("workspace info serializes");
    assert_no_secrets("the workspace info", &workspace_json);
    // The reported source is a clean URL, not one with a credential spliced in.
    assert!(!workspace.info().source.contains('@'));
}

#[tokio::test]
#[ignore]
async fn scanner_output_echoing_a_credential_is_redacted() {
    // The realistic leak: a tool prints its environment, or a URL, into stdout.
    if !docker_available().await {
        eprintln!("skipping: no reachable Docker daemon");
        return;
    }

    let redactor = Redactor::new();
    redactor.register(SENTINEL);

    let registry = ScannerRegistry::new().expect("registry");
    let mut scanner = registry.get("shellcheck").expect("shellcheck").clone();
    // Make the scanner deliberately echo the secret, standing in for a tool
    // that prints an environment variable or a remote URL.
    scanner.command_template = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("echo 'leaking {SENTINEL} now'"),
    ];
    scanner.success_exit_codes = vec![0];

    let result = ScanRunner::docker()
        .run_scan(
            &scanner,
            env!("CARGO_MANIFEST_DIR"),
            &ScanOptions {
                include_raw_logs: true,
                redactor,
                ..Default::default()
            },
        )
        .await;

    let serialized = serde_json::to_string(&result).expect("serializes");
    assert_no_secrets("the raw log excerpt", &serialized);
    assert!(
        serialized.contains("REDACTED"),
        "the secret should have been replaced, not merely absent: {serialized}"
    );
}

#[tokio::test]
#[ignore]
async fn a_failed_clone_reports_without_leaking() {
    if !network_available() {
        eprintln!("skipping: github.com is not resolvable");
        return;
    }

    let error = workspace::provision(
        "https://github.com/octocat/this-repository-does-not-exist-audit-mcp",
        &seeded_config(),
        &Redactor::new(),
    )
    .await
    .expect_err("cannot be cloned");

    // Error paths are where credentials most often escape, because they carry
    // whatever the underlying tool said.
    assert_no_secrets("the clone error", &error);
}
