//! Cloning a repository into a directory we own.
//!
//! Shells out to `git` rather than using a library, because the Kubernetes
//! path must use a binary anyway — its initContainer runs `git clone`, not our
//! process — and one set of semantics for shallow clones, refs, and SSH beats
//! two subtly different ones.
//!
//! Nothing here ever puts a secret in an argv. A process listing is world
//! readable; the environment of a process is not.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::config::WorkspaceConfig;
use crate::workspace::credentials::Credential;
use crate::workspace::target::RemoteTarget;

/// How often the working tree is measured against its size budget.
///
/// Sampling makes the budget a ceiling that can overshoot by one interval. A
/// byte-exact limit would mean intercepting every write, which is not worth it
/// for a guard against runaway clones.
const SIZE_SAMPLE_INTERVAL: Duration = Duration::from_millis(750);

/// Upper bound on entries visited while measuring, so measuring a huge tree
/// cannot itself become the performance problem.
const SIZE_WALK_MAX_ENTRIES: usize = 200_000;

pub struct CloneOutcome {
    /// The commit actually checked out, so a result can be tied to a revision.
    pub resolved_ref: String,
}

/// Clone `target` into `destination`, which must already exist and be empty.
pub async fn clone_into(
    destination: &Path,
    target: &RemoteTarget,
    credential: &Credential,
    config: &WorkspaceConfig,
) -> Result<CloneOutcome, String> {
    // An SSH key must live in a file for `ssh` to read, and that file must not
    // be world readable. It is removed with the workspace.
    let ssh_key_file = match credential {
        Credential::SshKey {
            secret,
            known_hosts,
        } => Some(write_ssh_material(destination, secret.expose(), known_hosts.as_deref()).await?),
        _ => None,
    };

    let reference = target.reference.as_deref();
    let is_commit = reference.is_some_and(looks_like_commit);

    if is_commit {
        clone_at_commit(
            destination,
            target,
            credential,
            config,
            ssh_key_file.as_ref(),
        )
        .await?;
    } else {
        clone_at_branch(
            destination,
            target,
            credential,
            config,
            ssh_key_file.as_ref(),
        )
        .await?;
    }

    let resolved_ref = resolve_head(destination, credential, ssh_key_file.as_ref()).await?;
    Ok(CloneOutcome { resolved_ref })
}

async fn clone_at_branch(
    destination: &Path,
    target: &RemoteTarget,
    credential: &Credential,
    config: &WorkspaceConfig,
    ssh_key_file: Option<&SshMaterial>,
) -> Result<(), String> {
    let mut args = vec!["clone".to_string(), "--quiet".to_string()];
    if config.clone_depth > 0 {
        // Depth is the git-native size lever that actually works here: it
        // bounds history, the usual reason a repository is enormous, without
        // leaving the working tree incomplete.
        args.push(format!("--depth={}", config.clone_depth));
        args.push("--no-tags".to_string());
    }
    if let Some(reference) = &target.reference {
        args.push("--branch".to_string());
        args.push(reference.clone());
    }
    args.push(target.url.clone());
    args.push(".".to_string());

    run_git(destination, &args, credential, ssh_key_file, config).await
}

/// A commit SHA cannot be given to `git clone --branch`, so fetch it directly.
async fn clone_at_commit(
    destination: &Path,
    target: &RemoteTarget,
    credential: &Credential,
    config: &WorkspaceConfig,
    ssh_key_file: Option<&SshMaterial>,
) -> Result<(), String> {
    let commit = target
        .reference
        .clone()
        .expect("caller checked there is a reference");

    run_git(
        destination,
        &["init".to_string(), "--quiet".to_string()],
        credential,
        ssh_key_file,
        config,
    )
    .await?;
    run_git(
        destination,
        &[
            "remote".to_string(),
            "add".to_string(),
            "origin".to_string(),
            target.url.clone(),
        ],
        credential,
        ssh_key_file,
        config,
    )
    .await?;
    run_git(
        destination,
        &[
            "fetch".to_string(),
            "--quiet".to_string(),
            format!("--depth={}", config.clone_depth.max(1)),
            "origin".to_string(),
            commit.clone(),
        ],
        credential,
        ssh_key_file,
        config,
    )
    .await?;
    run_git(
        destination,
        &[
            "checkout".to_string(),
            "--quiet".to_string(),
            "FETCH_HEAD".to_string(),
        ],
        credential,
        ssh_key_file,
        config,
    )
    .await
}

async fn resolve_head(
    destination: &Path,
    credential: &Credential,
    ssh_key_file: Option<&SshMaterial>,
) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(destination)
        .args(["rev-parse", "HEAD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(credential_env(credential, ssh_key_file))
        .output()
        .await
        .map_err(|err| format!("failed to read the cloned commit: {err}"))?;

    if !output.status.success() {
        return Err("cloned repository has no resolvable HEAD".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run one `git` invocation under the clone timeout and size budget.
async fn run_git(
    destination: &Path,
    args: &[String],
    credential: &Credential,
    ssh_key_file: Option<&SshMaterial>,
    config: &WorkspaceConfig,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .current_dir(destination)
        // Never prompt: an interactive credential prompt in a server would
        // hang the scan until the timeout.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .envs(credential_env(credential, ssh_key_file))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // The credential helper is visible in the process listing; the token it
    // reads is not, because it comes from the environment.
    if matches!(credential, Credential::HttpToken { .. }) {
        command.arg("-c");
        command.arg(
            "credential.helper=!f() { echo username=$AUDIT_GIT_USERNAME; echo password=$AUDIT_GIT_PASSWORD; }; f",
        );
    }
    command.args(args);

    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to run git: {err}. Is git installed?"))?;

    let budget = config.clone_max_bytes;
    let root = destination.to_path_buf();
    let mut ticker = tokio::time::interval(SIZE_SAMPLE_INTERVAL);
    ticker.tick().await; // the first tick completes immediately

    let deadline = tokio::time::Instant::now() + config.clone_timeout;

    loop {
        tokio::select! {
            status = child.wait() => {
                let status = status.map_err(|err| format!("git did not complete: {err}"))?;
                if status.success() {
                    return Ok(());
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let _ = pipe.read_to_string(&mut stderr).await;
                }
                return Err(format!(
                    "git {} failed: {}",
                    args.first().map(String::as_str).unwrap_or("clone"),
                    stderr.trim()
                ));
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = child.kill().await;
                return Err(format!(
                    "clone exceeded its {}s budget (AUDIT_CLONE_TIMEOUT_SECS)",
                    config.clone_timeout.as_secs()
                ));
            }
            _ = ticker.tick() => {
                let probe = root.clone();
                let over = tokio::task::spawn_blocking(move || exceeds_size(&probe, budget))
                    .await
                    .unwrap_or(false);
                if over {
                    let _ = child.kill().await;
                    return Err(format!(
                        "clone exceeded its {budget}-byte budget (AUDIT_CLONE_MAX_BYTES)"
                    ));
                }
            }
        }
    }
}

/// Environment carrying credential material. Never argv.
fn credential_env(
    credential: &Credential,
    ssh_key_file: Option<&SshMaterial>,
) -> Vec<(String, String)> {
    let mut env = Vec::new();
    match credential {
        Credential::HttpToken {
            username, secret, ..
        } => {
            env.push(("AUDIT_GIT_USERNAME".to_string(), username.clone()));
            env.push((
                "AUDIT_GIT_PASSWORD".to_string(),
                secret.expose().to_string(),
            ));
        }
        Credential::SshKey { .. } => {
            if let Some(material) = ssh_key_file {
                env.push(("GIT_SSH_COMMAND".to_string(), material.ssh_command()));
            }
        }
        Credential::Anonymous => {}
    }
    env
}

/// An SSH private key, and optionally known hosts, written to private files.
///
/// Only paths, never key material — the key lives on disk with mode 0600.
#[derive(Debug)]
pub struct SshMaterial {
    key_path: PathBuf,
    known_hosts_path: PathBuf,
}

impl SshMaterial {
    fn ssh_command(&self) -> String {
        format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}",
            self.key_path.display(),
            self.known_hosts_path.display()
        )
    }
}

async fn write_ssh_material(
    destination: &Path,
    key: &str,
    known_hosts: Option<&str>,
) -> Result<SshMaterial, String> {
    // Host key checking is not silently disabled. Without known hosts we
    // cannot tell the real server from an impostor, and quietly accepting any
    // key would make the clone feel fine while being unauthenticated.
    let Some(known_hosts) = known_hosts else {
        return Err(
            "SSH_PRIVATE_KEY is set but SSH_KNOWN_HOSTS is not. Host key verification cannot be skipped; supply the host keys for the git server."
                .to_string(),
        );
    };

    // Beside the workspace, not inside it: the scanner container must never see
    // the key, and the workspace is what gets mounted.
    let directory = destination
        .parent()
        .ok_or_else(|| "workspace has no parent directory".to_string())?;
    let key_path = directory.join("ssh-key");
    let known_hosts_path = directory.join("ssh-known-hosts");

    let mut contents = key.to_string();
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    tokio::fs::write(&key_path, contents)
        .await
        .map_err(|err| format!("failed to stage the SSH key: {err}"))?;
    tokio::fs::write(&known_hosts_path, known_hosts)
        .await
        .map_err(|err| format!("failed to stage known hosts: {err}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // ssh refuses to use a key others can read, and it is right to.
        tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|err| format!("failed to restrict SSH key permissions: {err}"))?;
    }

    Ok(SshMaterial {
        key_path,
        known_hosts_path,
    })
}

fn looks_like_commit(reference: &str) -> bool {
    reference.len() >= 7
        && reference.len() <= 40
        && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// Whether the tree under `root` is larger than `cap`, stopping as soon as the
/// answer is known.
fn exceeds_size(root: &Path, cap: u64) -> bool {
    if cap == 0 {
        return false;
    }

    let mut total: u64 = 0;
    let mut visited = 0_usize;
    let mut stack = vec![root.to_path_buf()];

    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > SIZE_WALK_MAX_ENTRIES {
                return false;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(metadata.len());
                if total > cap {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::credentials::{CredentialSource, Secret};

    #[test]
    fn commit_references_are_recognized() {
        assert!(looks_like_commit("a1b2c3d"));
        assert!(looks_like_commit(
            "5f2e8c1a9b3d4e6f7a8b9c0d1e2f3a4b5c6d7e8f"
        ));
        assert!(!looks_like_commit("main"));
        assert!(!looks_like_commit("v1.2.3"));
        // Too short to be unambiguous.
        assert!(!looks_like_commit("abc"));
        // A branch that happens to be hex-ish but too long.
        assert!(!looks_like_commit(&"a".repeat(41)));
    }

    #[test]
    fn credential_material_travels_in_the_environment_only() {
        let credential = Credential::HttpToken {
            source: CredentialSource::Token,
            username: "x-access-token".to_string(),
            secret: Secret::new("ghp_supersecret"),
        };
        let env = credential_env(&credential, None);
        assert!(
            env.iter()
                .any(|(key, value)| key == "AUDIT_GIT_PASSWORD" && value == "ghp_supersecret")
        );
        // And the helper that reads it names no secret of its own.
        assert!(!format!("{env:?}").contains("credential.helper"));
    }

    #[test]
    fn anonymous_clones_carry_no_credential_environment() {
        assert!(credential_env(&Credential::Anonymous, None).is_empty());
    }

    #[tokio::test]
    async fn ssh_without_known_hosts_is_refused_rather_than_disabled() {
        let directory = tempfile::tempdir().expect("temp dir");
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create");

        let error = write_ssh_material(&workspace, "KEY", None)
            .await
            .expect_err("must refuse");
        assert!(error.contains("SSH_KNOWN_HOSTS"));
        assert!(error.contains("cannot be skipped"));
    }

    #[tokio::test]
    async fn ssh_material_is_written_outside_the_mounted_tree() {
        let directory = tempfile::tempdir().expect("temp dir");
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create");

        let material = write_ssh_material(&workspace, "KEY", Some("github.com ssh-ed25519 AAA"))
            .await
            .expect("writes material");

        // The scanner container mounts the workspace; the key must not be in it.
        assert!(!material.key_path.starts_with(&workspace));
        assert!(material.ssh_command().contains("StrictHostKeyChecking=yes"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&material.key_path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "ssh refuses a world-readable key");
        }
    }

    #[test]
    fn size_measurement_stops_as_soon_as_the_budget_is_passed() {
        let directory = tempfile::tempdir().expect("temp dir");
        std::fs::write(directory.path().join("a"), vec![0_u8; 4096]).expect("write");
        std::fs::write(directory.path().join("b"), vec![0_u8; 4096]).expect("write");

        assert!(exceeds_size(directory.path(), 4000));
        assert!(!exceeds_size(directory.path(), 1_000_000));
        // A zero budget means unbounded, not "immediately over".
        assert!(!exceeds_size(directory.path(), 0));
    }

    #[test]
    fn size_measurement_descends_into_subdirectories() {
        let directory = tempfile::tempdir().expect("temp dir");
        let nested = directory.path().join("nested/deeper");
        std::fs::create_dir_all(&nested).expect("create");
        std::fs::write(nested.join("big"), vec![0_u8; 8192]).expect("write");

        assert!(exceeds_size(directory.path(), 4096));
    }
}
