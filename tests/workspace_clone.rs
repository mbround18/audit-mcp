//! Cloning a repository and scanning it, against a real remote.
//!
//! `#[ignore]`d and self-skipping: these need `git` and network access, so the
//! default `cargo test` run stays hermetic (SC-009).
//!
//! The cleanup assertions matter more than the happy path. A workspace that
//! survives a *successful* scan is a bug someone notices; one that survives a
//! *failed* scan is a slow disk leak nobody notices until the host fills up.

use audit_mcp::config::{CredentialConfig, WorkspaceConfig};
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

/// A configuration with genuinely no credentials.
///
/// The default now borrows a logged-in `gh` CLI's token, so a test about
/// anonymous access has to say so explicitly rather than assume the machine it
/// runs on has nothing configured.
fn without_credentials() -> WorkspaceConfig {
    WorkspaceConfig {
        credentials: CredentialConfig {
            use_gh_cli: false,
            ..Default::default()
        },
        ..Default::default()
    }
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
        let workspace = workspace::provision(PUBLIC_REPO, &without_credentials(), &redactor)
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
        &without_credentials(),
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

/// The `gh` CLI fallback, verified against a repository that actually requires
/// authentication.
///
/// Skips unless `gh` is logged in. The point is not that a token exists but
/// that it reaches `git` and authenticates a clone that anonymous access
/// cannot do.
#[tokio::test]
#[ignore]
async fn a_logged_in_gh_cli_authenticates_a_private_clone() {
    require_clone_environment!();
    if audit_mcp::config::gh_cli_token().is_none() {
        eprintln!("skipping: the gh CLI is not logged in");
        return;
    }

    // Ask gh for a private repository this account can read. Without one there
    // is nothing to prove, so skip rather than assert something weaker.
    let listing = std::process::Command::new("gh")
        .args([
            "repo",
            "list",
            "--visibility",
            "private",
            "--limit",
            "1",
            "--json",
            "nameWithOwner",
            "--jq",
            ".[0].nameWithOwner",
        ])
        .output()
        .expect("gh repo list runs");
    let repo = String::from_utf8_lossy(&listing.stdout).trim().to_string();
    if repo.is_empty() {
        eprintln!("skipping: this account has no private repository to test with");
        return;
    }

    // Anonymous access must fail, or the test proves nothing.
    let anonymous = WorkspaceConfig {
        credentials: audit_mcp::config::CredentialConfig {
            use_gh_cli: false,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        workspace::provision(&repo, &anonymous, &Redactor::new())
            .await
            .is_err(),
        "'{repo}' is readable anonymously, so it cannot demonstrate authentication"
    );

    let workspace = workspace::provision(&repo, &WorkspaceConfig::default(), &Redactor::new())
        .await
        .unwrap_or_else(|err| panic!("the gh token should authenticate '{repo}': {err}"));

    assert_eq!(
        workspace.info().credential_source.as_deref(),
        Some("gh_cli")
    );
    assert!(workspace.root().join(".git").exists());
    // The borrowed token must not appear in the reported source.
    assert!(!workspace.info().source.contains("gho_"));
}
