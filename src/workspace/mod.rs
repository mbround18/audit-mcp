//! Workspace provisioning: what a scan actually runs against.
//!
//! Either a caller-supplied local path, used as-is and never modified, or a
//! repository cloned to a temporary directory that this process owns and must
//! delete — on success, on failure, and on timeout.
//!
//! A scan provisions **one** workspace and shares it read-only across every
//! scanner it runs. Release is by ownership: the last `Arc` to drop takes the
//! directory with it, so a straggler or a timed-out scanner cannot have the
//! tree deleted out from under it.

pub mod clone;
pub mod credentials;
pub mod target;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use crate::config::WorkspaceConfig;
use crate::models::WorkspaceInfo;
use crate::redact::Redactor;
use crate::workspace::credentials::{Credential, candidate_sources};
use crate::workspace::target::{TargetExpression, resolve_and_check};

/// Prefix for every directory this process creates for a clone. Also what
/// orphan reaping looks for, so the two can never drift apart.
pub const WORKSPACE_PREFIX: &str = "audit-workspace-";

/// A directory a scan runs against.
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
    info: WorkspaceInfo,
    /// Present only for a provisioned clone. Dropping it removes the tree.
    staging: Option<TempDir>,
    /// Secrets registered for this scan, cleared when the workspace goes.
    redactor: Redactor,
}

impl Workspace {
    /// Wrap a caller-supplied local path. Never deleted, never modified.
    pub fn local(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            info: WorkspaceInfo {
                origin: "local_path".to_string(),
                source: path.display().to_string(),
                resolved_ref: None,
                credential_source: None,
            },
            root: path,
            staging: None,
            redactor: Redactor::new(),
        }
    }

    /// The path scanners are pointed at.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path as a string, for the runner's target resolution.
    pub fn scan_path(&self) -> String {
        self.root.display().to_string()
    }

    pub fn info(&self) -> &WorkspaceInfo {
        &self.info
    }

    pub fn is_owned(&self) -> bool {
        self.staging.is_some()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        // The `TempDir` removes the tree. Clearing the redactor here keeps a
        // credential from outliving the scan that needed it.
        if self.staging.is_some() {
            self.redactor.clear();
        }
    }
}

/// Resolve a target into something scannable.
///
/// A local path is used as-is. A repository is validated, cloned, and made
/// safe to expose to a scanner.
pub async fn provision(
    target: &str,
    config: &WorkspaceConfig,
    redactor: &Redactor,
) -> Result<Workspace, String> {
    match target::parse(target)? {
        TargetExpression::LocalPath(path) => Ok(Workspace::local(path)),
        TargetExpression::Remote(remote) => {
            if !config.allow_remote_targets {
                return Err(
                    "remote targets are disabled (AUDIT_ALLOW_REMOTE_TARGETS=false); pass a local path"
                        .to_string(),
                );
            }

            // Checked before any connection: once the server fetches URLs on a
            // caller's behalf it can be pointed at things the caller cannot
            // reach themselves.
            let port = match remote.scheme {
                target::RemoteScheme::Https => 443,
                target::RemoteScheme::Ssh => 22,
            };
            resolve_and_check(&remote.host, port, config.allow_private_addresses)?;

            let credential = credentials::resolve(&config.credentials, &remote).await?;
            if let Some(secret) = credential.secret_value() {
                redactor.register(secret);
            }

            let staging = tempfile::Builder::new()
                .prefix(WORKSPACE_PREFIX)
                .tempdir()
                .map_err(|err| format!("failed to create a workspace directory: {err}"))?;
            // The clone goes in a subdirectory so credential material can live
            // beside it without ever being inside the mounted tree.
            let root = staging.path().join("repo");
            std::fs::create_dir(&root)
                .map_err(|err| format!("failed to create the clone directory: {err}"))?;

            let outcome = clone::clone_into(&root, &remote, &credential, config)
                .await
                .map_err(|err| describe_clone_failure(err, &remote, &credential))?;

            let escapes = contain_symlinks(&root)?;

            Ok(Workspace {
                info: WorkspaceInfo {
                    origin: remote.scheme.as_str().to_string(),
                    source: remote.url.clone(),
                    resolved_ref: Some(outcome.resolved_ref),
                    credential_source: Some(credential.source().as_str().to_string()),
                },
                root,
                staging: Some(staging),
                redactor: redactor.clone(),
            })
            .inspect(|_| {
                if escapes > 0 {
                    // Not fatal: the links are gone. Worth saying so, because a
                    // repository containing them is unusual.
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"symlinks_removed\",\"count\":{escapes}}}"
                    );
                }
            })
        }
    }
}

/// Turn a clone failure into something actionable without disclosing whether
/// the repository exists.
///
/// "Not found" and "no permission" are the same answer from an unauthenticated
/// probe, and telling them apart is how a private repository's existence leaks.
fn describe_clone_failure(
    error: String,
    remote: &target::RemoteTarget,
    credential: &Credential,
) -> String {
    let looks_like_auth = error.contains("Authentication")
        || error.contains("not found")
        || error.contains("Permission denied")
        || error.contains("could not read Username")
        || error.contains("403")
        || error.contains("404");

    if looks_like_auth && matches!(credential, Credential::Anonymous) {
        return format!(
            "could not access '{}' without credentials. If it is private, configure one of: {}.",
            remote.path,
            candidate_sources(remote).join(", ")
        );
    }
    if looks_like_auth {
        return format!(
            "could not access '{}' with the configured '{}' credential. Check that it grants read access.",
            remote.path,
            credential.source().as_str()
        );
    }
    error
}

/// Remove symlinks whose target escapes the workspace.
///
/// A scanner is handed a read-only tree; a link pointing at `/etc` or at the
/// host's home directory would let it read outside what the caller asked to be
/// scanned. Returns how many were removed.
fn contain_symlinks(root: &Path) -> Result<usize, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize the workspace: {err}"))?;

    let mut removed = 0_usize;
    let mut stack = vec![canonical_root.clone()];

    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };

            if kind.is_symlink() {
                let escapes = match path.canonicalize() {
                    // A link that resolves outside the tree, or to nothing at
                    // all, has no business being handed to a scanner.
                    Ok(resolved) => !resolved.starts_with(&canonical_root),
                    Err(_) => true,
                };
                if escapes {
                    let _ = std::fs::remove_file(&path);
                    removed += 1;
                }
                continue;
            }

            if kind.is_dir() {
                stack.push(path);
            }
        }
    }

    Ok(removed)
}

/// Remove workspaces left behind by an unclean shutdown.
///
/// `TempDir` cleans up on drop, but a process that is killed never drops
/// anything. Without this, a crash loop fills the disk.
pub fn reap_orphans(older_than: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut reaped = 0_usize;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(WORKSPACE_PREFIX) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let age = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default();
        if age >= older_than && std::fs::remove_dir_all(entry.path()).is_ok() {
            reaped += 1;
        }
    }

    reaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_local_workspace_is_never_owned_or_deleted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().to_path_buf();

        {
            let workspace = Workspace::local(&path);
            assert!(!workspace.is_owned());
            assert_eq!(workspace.info().origin, "local_path");
            assert!(workspace.info().resolved_ref.is_none());
            assert!(workspace.info().credential_source.is_none());
        }

        assert!(path.exists(), "a caller's own directory must survive");
    }

    #[test]
    fn a_provisioned_workspace_is_removed_when_the_last_holder_drops() {
        // Release is by ownership, which is what makes FR-005a's "not while a
        // straggler still holds it" true by construction rather than by care.
        let staging = tempfile::Builder::new()
            .prefix(WORKSPACE_PREFIX)
            .tempdir()
            .expect("temp dir");
        let root = staging.path().join("repo");
        std::fs::create_dir(&root).expect("create");
        let observed = root.clone();

        let workspace = Arc::new(Workspace {
            info: WorkspaceInfo {
                origin: "git_https".to_string(),
                source: "https://example.test/o/r.git".to_string(),
                resolved_ref: Some("abc123".to_string()),
                credential_source: Some("anonymous".to_string()),
            },
            root,
            staging: Some(staging),
            redactor: Redactor::new(),
        });

        let straggler = Arc::clone(&workspace);
        drop(workspace);
        assert!(observed.exists(), "still held by a second scanner");

        drop(straggler);
        assert!(!observed.exists(), "released when the last holder is gone");
    }

    #[test]
    fn dropping_a_provisioned_workspace_clears_its_secrets() {
        let redactor = Redactor::new();
        redactor.register("ghp_supersecrettoken");

        let staging = tempfile::Builder::new()
            .prefix(WORKSPACE_PREFIX)
            .tempdir()
            .expect("temp dir");
        let root = staging.path().join("repo");
        std::fs::create_dir(&root).expect("create");

        {
            let _workspace = Workspace {
                info: WorkspaceInfo {
                    origin: "git_https".to_string(),
                    source: "https://example.test/o/r.git".to_string(),
                    resolved_ref: None,
                    credential_source: Some("token".to_string()),
                },
                root,
                staging: Some(staging),
                redactor: redactor.clone(),
            };
            assert!(!redactor.is_empty());
        }

        assert!(
            redactor.is_empty(),
            "a credential must not outlive its scan"
        );
    }

    #[test]
    fn symlinks_escaping_the_workspace_are_removed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path().join("repo");
        std::fs::create_dir(&root).expect("create");
        std::fs::write(root.join("inside.txt"), "fine").expect("write");
        std::fs::create_dir(root.join("nested")).expect("create");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            // Points outside the tree — a scanner must not follow this.
            symlink("/etc/passwd", root.join("escape")).expect("symlink");
            // Points inside — legitimate, and must survive.
            symlink(root.join("inside.txt"), root.join("nested/ok")).expect("symlink");
            // Dangling — resolves to nothing, so it is removed too.
            symlink(root.join("missing"), root.join("dangling")).expect("symlink");
        }

        let removed = contain_symlinks(&root).expect("containment runs");

        #[cfg(unix)]
        {
            assert_eq!(removed, 2, "the escaping and dangling links");
            assert!(!root.join("escape").exists());
            assert!(root.join("nested/ok").exists(), "an internal link is fine");
            assert!(root.join("inside.txt").exists());
        }
        #[cfg(not(unix))]
        let _ = removed;
    }

    #[test]
    fn orphan_reaping_only_touches_our_own_stale_directories() {
        let orphan = tempfile::Builder::new()
            .prefix(WORKSPACE_PREFIX)
            .tempdir()
            .expect("temp dir");
        let orphan_path = orphan.path().to_path_buf();
        // Leak the handle so the directory survives as a genuine orphan.
        let _ = orphan.keep();

        let unrelated = tempfile::Builder::new()
            .prefix("something-else-")
            .tempdir()
            .expect("temp dir");

        // Nothing is old enough yet.
        reap_orphans(Duration::from_secs(3600));
        assert!(orphan_path.exists(), "a fresh workspace is left alone");

        // With no age requirement, ours goes and the stranger's stays.
        reap_orphans(Duration::ZERO);
        assert!(!orphan_path.exists());
        assert!(
            unrelated.path().exists(),
            "reaping must not touch directories we did not create"
        );
    }

    #[tokio::test]
    async fn provisioning_a_local_path_needs_no_network_or_credentials() {
        let workspace = provision(
            env!("CARGO_MANIFEST_DIR"),
            &WorkspaceConfig::default(),
            &Redactor::new(),
        )
        .await
        .expect("a local path always provisions");
        assert!(!workspace.is_owned());
        assert_eq!(workspace.info().origin, "local_path");
    }

    #[tokio::test]
    async fn remote_targets_can_be_disabled_entirely() {
        let config = WorkspaceConfig {
            allow_remote_targets: false,
            ..Default::default()
        };
        let error = provision("owner/repo", &config, &Redactor::new())
            .await
            .expect_err("must refuse");
        assert!(error.contains("AUDIT_ALLOW_REMOTE_TARGETS"));
    }

    #[tokio::test]
    async fn a_private_address_target_is_refused_before_any_connection() {
        let error = provision(
            "https://localhost/owner/repo",
            &WorkspaceConfig::default(),
            &Redactor::new(),
        )
        .await
        .expect_err("must refuse");
        assert!(error.contains("private or loopback"));
    }

    #[test]
    fn an_anonymous_failure_names_what_to_configure_without_confirming_existence() {
        let remote = target::RemoteTarget {
            scheme: target::RemoteScheme::Https,
            host: "github.com".to_string(),
            path: "owner/secret".to_string(),
            url: "https://github.com/owner/secret.git".to_string(),
            reference: None,
        };
        let message = describe_clone_failure(
            "fatal: repository not found".to_string(),
            &remote,
            &Credential::Anonymous,
        );
        assert!(message.contains("GITHUB_TOKEN"));
        // Must not say whether it exists — only that we could not reach it.
        assert!(!message.contains("not found"));
        assert!(!message.contains("does not exist"));
    }
}
