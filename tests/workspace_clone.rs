//! Cloning a repository and scanning it, against a real remote.
//!
//! `#[ignore]`d and self-skipping: these need `git` and network access, so the
//! default `cargo test` run stays hermetic (SC-009).
//!
//! The cleanup assertions matter more than the happy path. A workspace that
//! survives a *successful* scan is a bug someone notices; one that survives a
//! *failed* scan is a slow disk leak nobody notices until the host fills up.

use audit_mcp::config::WorkspaceConfig;
use audit_mcp::redact::Redactor;
use audit_mcp::workspace::{self, WORKSPACE_PREFIX};

/// A tiny, stable public repository. Small enough that cloning it in a test is
/// not rude.
const PUBLIC_REPO: &str = "https://github.com/octocat/Hello-World";

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn network_available() -> bool {
    use std::net::ToSocketAddrs;
    ("github.com", 443).to_socket_addrs().is_ok()
}

macro_rules! require_clone_environment {
    () => {
        if !git_available() {
            eprintln!("skipping: git is not installed");
            return;
        }
        if !network_available() {
            eprintln!("skipping: github.com is not resolvable");
            return;
        }
    };
}

fn count_workspaces() -> usize {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(WORKSPACE_PREFIX)
        })
        .count()
}

#[tokio::test]
#[ignore]
async fn clones_a_public_repository_with_no_credentials() {
    require_clone_environment!();

    let before = count_workspaces();
    let redactor = Redactor::new();
    let root;

    {
        let workspace = workspace::provision(PUBLIC_REPO, &WorkspaceConfig::default(), &redactor)
            .await
            .expect("a public repository clones anonymously");

        root = workspace.root().to_path_buf();
        assert!(workspace.is_owned(), "a clone is ours to delete");
        assert!(root.join(".git").exists(), "the clone is a git repository");

        let info = workspace.info();
        assert_eq!(info.origin, "git_https");
        // Zero configuration: no credential was needed or used.
        assert_eq!(info.credential_source.as_deref(), Some("anonymous"));
        // The result is tied to an exact revision.
        let resolved = info.resolved_ref.as_deref().expect("a resolved commit");
        assert_eq!(resolved.len(), 40, "a full commit sha: {resolved}");
        assert!(resolved.chars().all(|ch| ch.is_ascii_hexdigit()));
        // The reported source never carries credentials.
        assert!(!info.source.contains('@'));
    }

    assert!(!root.exists(), "the workspace is removed when released");
    assert_eq!(
        count_workspaces(),
        before,
        "no workspace directory is left behind"
    );
}

#[tokio::test]
#[ignore]
async fn a_failed_clone_leaves_nothing_behind() {
    // The failure path is the one that leaks.
    require_clone_environment!();

    let before = count_workspaces();
    let error = workspace::provision(
        "https://github.com/octocat/this-repository-does-not-exist-audit-mcp",
        &WorkspaceConfig::default(),
        &Redactor::new(),
    )
    .await
    .expect_err("a nonexistent repository cannot be cloned");

    // It must not confirm whether the repository exists.
    assert!(
        !error.contains("not found") && !error.contains("does not exist"),
        "the error discloses existence: {error}"
    );
    assert!(
        error.contains("GITHUB_TOKEN") || error.contains("credentials"),
        "the error should name what to configure: {error}"
    );
    assert_eq!(
        count_workspaces(),
        before,
        "a failed clone must not leave a directory behind"
    );
}

#[tokio::test]
#[ignore]
async fn a_requested_reference_is_what_gets_checked_out() {
    require_clone_environment!();

    let workspace = workspace::provision(
        &format!("{PUBLIC_REPO}#test"),
        &WorkspaceConfig::default(),
        &Redactor::new(),
    )
    .await
    .expect("the 'test' branch exists in this repository");

    let head = std::process::Command::new("git")
        .current_dir(workspace.root())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse runs");
    let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
    assert_eq!(
        workspace.info().resolved_ref.as_deref(),
        Some(head.as_str()),
        "the reported commit is the one checked out"
    );
}

#[tokio::test]
#[ignore]
async fn the_clone_timeout_is_enforced() {
    require_clone_environment!();

    let config = WorkspaceConfig {
        // Far too short for any real clone to finish.
        clone_timeout: std::time::Duration::from_millis(1),
        ..Default::default()
    };
    let before = count_workspaces();

    let error = workspace::provision(PUBLIC_REPO, &config, &Redactor::new())
        .await
        .expect_err("the clone cannot finish in a millisecond");
    assert!(
        error.contains("budget") || error.contains("AUDIT_CLONE_TIMEOUT_SECS"),
        "unexpected error: {error}"
    );
    assert_eq!(
        count_workspaces(),
        before,
        "a timed-out clone must not leave a directory behind"
    );
}

#[tokio::test]
#[ignore]
async fn a_shallow_clone_is_the_default() {
    require_clone_environment!();

    let workspace =
        workspace::provision(PUBLIC_REPO, &WorkspaceConfig::default(), &Redactor::new())
            .await
            .expect("clones");

    let output = std::process::Command::new("git")
        .current_dir(workspace.root())
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .expect("git rev-list runs");
    let commits: usize = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(usize::MAX);
    assert_eq!(commits, 1, "depth 1 by default, so history stays bounded");
}
