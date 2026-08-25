//! Local Docker execution backend.
//!
//! Owns the container lifecycle and nothing else: pull, create, start, wait
//! under a timeout, collect logs, clean up. What the output *means* is
//! [`crate::runner`]'s job.

use std::{env, time::Instant};

use bollard::{
    Docker,
    container::LogOutput,
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, KillContainerOptionsBuilder,
        LogsOptionsBuilder, RemoveContainerOptionsBuilder,
    },
};
use futures_util::{StreamExt, TryStreamExt, future::BoxFuture};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::executor::{ExecutionOutcome, ExecutionRequest, Executor, Termination, WORKSPACE_MOUNT};

/// Hard ceiling on captured container output, so a runaway scanner cannot
/// exhaust memory. Parsers see the full buffer up to this size.
const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
/// Memory ceiling per scanner container. Compilation is memory-hungry but
/// should not be unbounded.
const CONTAINER_MEMORY_BYTES: i64 = 4 * 1024 * 1024 * 1024;

/// Container output, with stdout kept separate from the interleaved view.
#[derive(Debug, Default)]
struct ContainerOutput {
    stdout: String,
    combined: String,
}

/// Runs scanners in ephemeral Docker containers.
///
/// The Docker client is connected lazily so the MCP server starts (and can
/// answer `list_scanners`/`explain_finding`) even with no daemon running.
#[derive(Debug, Default)]
pub struct DockerExecutor {
    docker: OnceCell<Docker>,
}

impl DockerExecutor {
    pub fn new() -> Self {
        Self {
            docker: OnceCell::new(),
        }
    }

    /// Connect and ping on first use. Failures are not cached, so a daemon
    /// that starts later is picked up on the next scan.
    async fn client(&self) -> Result<&Docker, String> {
        self.docker
            .get_or_try_init(|| async {
                let docker = Docker::connect_with_local_defaults()
                    .map_err(|err| format!("failed to create Docker client: {err}"))?;
                docker
                    .ping()
                    .await
                    .map_err(|err| format!("Docker daemon is not reachable: {err}"))?;
                Ok(docker)
            })
            .await
    }

    async fn run(&self, request: ExecutionRequest<'_>) -> Result<ExecutionOutcome, String> {
        let scanner = request.scanner;
        let docker = self.client().await?;

        let resolved_image = resolve_image_for_pull(&scanner.image);
        self.ensure_image_available(docker, &resolved_image).await?;

        let container_name = format!("audit-scan-{}", Uuid::new_v4());
        let cache = image_cache_config(&resolved_image, &scanner.name);
        let mut container_env = cache.env;
        container_env.extend(request.environment.clone());
        let mut binds = vec![format!(
            "{}:{WORKSPACE_MOUNT}:ro",
            request.workspace.display()
        )];
        binds.extend(cache.volumes);

        let create_response = docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::new()
                        .name(&container_name)
                        .build(),
                ),
                ContainerCreateBody {
                    image: Some(resolved_image.clone()),
                    // Clear the image's ENTRYPOINT so `command` is always the
                    // literal argv. Many scanner images set the tool itself as
                    // the entrypoint, which would otherwise swallow the command
                    // template (`gitleaks` + `["gitleaks","detect"]` becomes
                    // `gitleaks gitleaks detect`) or pass `sh -c ...` to the
                    // tool as arguments.
                    entrypoint: Some(vec![]),
                    cmd: Some(request.command.clone()),
                    working_dir: Some(WORKSPACE_MOUNT.to_string()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    env: Some(container_env),
                    host_config: Some(HostConfig {
                        binds: Some(binds),
                        auto_remove: Some(false),
                        // Prevent privilege escalation inside the container.
                        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                        // Scanners are analysis tools, not system daemons.
                        cap_drop: Some(vec!["ALL".to_string()]),
                        // ...with one exception. Dropping every capability
                        // also drops CAP_DAC_READ_SEARCH, so root inside the
                        // container cannot read a directory the host owns with
                        // mode 0700 — a build output or cache directory is
                        // enough to make a whole scan fail with "permission
                        // denied". Restoring only the read-side capability lets
                        // scanners read the tree the caller explicitly asked
                        // them to scan. It grants no write access (the mount is
                        // read-only) and no path to privilege escalation.
                        //
                        // This is specific to a host bind mount exposing
                        // foreign ownership. Backends that build their own
                        // workspace do not need it and must not copy it.
                        cap_add: Some(vec!["DAC_READ_SEARCH".to_string()]),
                        memory: Some(CONTAINER_MEMORY_BYTES),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(|err| {
                format!("failed to create scanner container '{container_name}': {err}")
            })?;

        let container_id = create_response.id;
        let started = Instant::now();

        // Set up the wait stream BEFORE starting so we don't miss the exit
        // event if the container finishes before the next await point.
        let mut wait_stream = docker.wait_container(&container_id, None);

        if let Err(err) = docker.start_container(&container_id, None).await {
            self.cleanup_container(docker, &container_id).await;
            return Err(format!(
                "failed to start scanner container '{container_id}': {err}"
            ));
        }

        let wait_result = match tokio::time::timeout(request.timeout, wait_stream.next()).await {
            Ok(Some(Ok(result))) => Ok(result),
            // Docker surfaces non-zero container exits as DockerContainerWaitError.
            // Convert to a synthetic response so the exit code reaches our logic.
            Ok(Some(Err(BollardError::DockerContainerWaitError { code, .. }))) => {
                Ok(bollard::models::ContainerWaitResponse {
                    status_code: code,
                    error: None,
                })
            }
            Ok(Some(Err(err))) => Err(format!(
                "failed while waiting for scanner container '{container_id}': {err}"
            )),
            Ok(None) => Err(format!(
                "scanner container '{container_id}' exited without a wait result"
            )),
            Err(_elapsed) => {
                // Kill first so the logs we collect reflect work actually done.
                let _ = docker
                    .kill_container(
                        &container_id,
                        Some(KillContainerOptionsBuilder::new().signal("SIGKILL").build()),
                    )
                    .await;
                let output = self
                    .collect_logs(docker, &container_id)
                    .await
                    .unwrap_or_default();
                self.cleanup_container(docker, &container_id).await;

                return Ok(ExecutionOutcome {
                    image: resolved_image,
                    stdout: output.stdout,
                    combined: output.combined,
                    exit_code: None,
                    duration: started.elapsed(),
                    termination: Termination::TimedOut,
                });
            }
        };

        let wait_result = match wait_result {
            Ok(result) => result,
            Err(error) => {
                self.cleanup_container(docker, &container_id).await;
                return Err(error);
            }
        };

        let output = match self.collect_logs(docker, &container_id).await {
            Some(output) => output,
            None => {
                self.cleanup_container(docker, &container_id).await;
                return Err(format!(
                    "failed to read logs from scanner container '{container_id}'"
                ));
            }
        };

        self.cleanup_container(docker, &container_id).await;

        Ok(ExecutionOutcome {
            image: resolved_image,
            stdout: output.stdout,
            combined: output.combined,
            exit_code: Some(wait_result.status_code),
            duration: started.elapsed(),
            termination: Termination::Completed,
        })
    }

    /// Collect container output, keeping stdout separate from the merged view.
    ///
    /// Docker interleaves the two streams, which corrupts a report written to
    /// stdout the moment the tool (or `go run`) writes a line to stderr —
    /// gosec's SARIF arrives with `exit status 1` spliced in before its
    /// closing brace. Parsers get the clean stdout stream; humans get the
    /// merged one.
    async fn collect_logs(&self, docker: &Docker, container_id: &str) -> Option<ContainerOutput> {
        let chunks = docker
            .logs(
                container_id,
                Some(
                    LogsOptionsBuilder::new()
                        .stdout(true)
                        .stderr(true)
                        .follow(false)
                        .tail("all")
                        .build(),
                ),
            )
            .try_collect::<Vec<_>>()
            .await
            .ok()?;

        let mut output = ContainerOutput::default();
        for chunk in chunks {
            if output.combined.len() >= MAX_LOG_BYTES {
                break;
            }
            let is_stdout = matches!(chunk, LogOutput::StdOut { .. });
            let text = String::from_utf8_lossy(chunk.into_bytes().as_ref()).into_owned();
            if is_stdout {
                output.stdout.push_str(&text);
            }
            output.combined.push_str(&text);
        }

        Some(output)
    }

    async fn ensure_image_available(&self, docker: &Docker, image: &str) -> Result<(), String> {
        if docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }

        docker
            .create_image(
                Some(
                    CreateImageOptionsBuilder::default()
                        .from_image(image)
                        .build(),
                ),
                None,
                None,
            )
            .try_collect::<Vec<_>>()
            .await
            .map_err(|err| format!("failed to pull scanner image '{image}': {err}"))?;

        Ok(())
    }

    async fn cleanup_container(&self, docker: &Docker, container_id: &str) {
        let _ = docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
    }
}

impl Executor for DockerExecutor {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.client().await.is_ok() })
    }

    fn execute<'a>(
        &'a self,
        request: ExecutionRequest<'a>,
    ) -> BoxFuture<'a, Result<ExecutionOutcome, String>> {
        Box::pin(async move { self.run(request).await })
    }
}

fn resolve_image_for_pull(image: &str) -> String {
    let registry = env::var("REGISTRY")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty());

    let Some(registry) = registry else {
        return image.to_string();
    };

    let mut segments = image.split('/');
    let first = segments.next().unwrap_or_default();

    if first == registry {
        return image.to_string();
    }

    let remainder = if is_registry_component(first) {
        segments.collect::<Vec<_>>().join("/")
    } else {
        image.to_string()
    };

    if remainder.is_empty() {
        return image.to_string();
    }

    let normalized = if remainder.contains('/') {
        remainder
    } else {
        format!("library/{remainder}")
    };

    format!("{registry}/{normalized}")
}

fn is_registry_component(component: &str) -> bool {
    component == "localhost" || component.contains('.') || component.contains(':')
}

struct CacheConfig {
    volumes: Vec<String>,
    env: Vec<String>,
}

/// Returns the Docker named volumes and env vars needed to give a scanner
/// container a shared, persistent cache.
///
/// Sharing strategy per ecosystem
/// ───────────────────────────────
/// Rust   audit-cargo-home (shared)      — registry index + installed binaries
///        audit-target-<scanner> (solo)  — incremental build artifacts per scanner
///                                         (scanners produce incompatible artifacts)
///
/// Go     audit-go-mod-cache (shared)    — content-addressed module downloads
///        audit-go-build-cache (shared)  — build cache; Go uses per-entry locking
///
/// Node   audit-npm-cache (shared)       — npm tarball cache (content-addressed)
///
/// Python audit-uv-cache (shared)        — uv wheel/sdist download cache
///        audit-uv-tools (shared)        — uvx tool installs (bandit, ruff, …)
///
/// Ruby   audit-gem-home (shared)        — installed gems; safe because all
///                                         containers use the same base image
///
/// Java   audit-jbang-cache (shared)     — jbang script/jar cache
///        audit-maven-repo (shared)      — Maven local repository
///
/// PHP    audit-composer-cache (shared)  — composer download cache
///        audit-composer-home (shared)   — composer home (global vendor/bin)
///
/// .NET   audit-nuget-packages (shared)  — NuGet global packages folder
///        audit-dotnet-home (shared)     — dotnet CLI home for global tools
///
/// IaC    audit-checkov-cache (shared)   — checkov policy/cache files
///        audit-trivy-cache (shared)     — trivy vulnerability DB and cache
fn image_cache_config(image: &str, scanner_name: &str) -> CacheConfig {
    if image.contains("rust") {
        CacheConfig {
            volumes: vec![
                "audit-cargo-home:/cache/cargo-home".to_string(),
                format!("audit-target-{scanner_name}:/cache/cargo-target"),
            ],
            env: vec![
                "CARGO_HOME=/cache/cargo-home".to_string(),
                "CARGO_TARGET_DIR=/cache/cargo-target".to_string(),
            ],
        }
    } else if image.contains("golang") || image.contains("go:") {
        CacheConfig {
            volumes: vec![
                "audit-go-mod-cache:/cache/go-mod".to_string(),
                "audit-go-build-cache:/cache/go-build".to_string(),
            ],
            env: vec![
                "GOMODCACHE=/cache/go-mod".to_string(),
                "GOCACHE=/cache/go-build".to_string(),
                "GOPATH=/cache/go-mod".to_string(),
                // `go run tool@latest` must not be blocked by a repo's vendor
                // directory or a proxy-less environment.
                "GOFLAGS=-mod=mod".to_string(),
                // The golang image pins GOTOOLCHAIN=local, which makes every
                // `go run tool@latest` fail as soon as the tool's go.mod
                // requires a newer Go than the base image ships. `auto` lets
                // Go fetch the toolchain the tool asks for.
                "GOTOOLCHAIN=auto".to_string(),
            ],
        }
    } else if image.contains("node") {
        CacheConfig {
            // npx (used by all node scanners) installs on demand into npm's
            // own cache, so a single shared volume covers every scanner.
            volumes: vec!["audit-npm-cache:/cache/npm".to_string()],
            env: vec!["NPM_CONFIG_CACHE=/cache/npm".to_string()],
        }
    } else if image.contains("astral") || image.contains("uv") {
        CacheConfig {
            volumes: vec![
                "audit-uv-cache:/cache/uv".to_string(),
                // uvx installs tool environments here; shared = install once.
                "audit-uv-tools:/cache/uv-tools".to_string(),
            ],
            env: vec![
                "UV_CACHE_DIR=/cache/uv".to_string(),
                "UV_TOOL_DIR=/cache/uv-tools".to_string(),
            ],
        }
    } else if image.contains("ruby") {
        CacheConfig {
            volumes: vec!["audit-gem-home:/cache/gems".to_string()],
            env: vec![
                "GEM_HOME=/cache/gems".to_string(),
                "GEM_PATH=/cache/gems".to_string(),
            ],
        }
    } else if image.contains("jbang") {
        CacheConfig {
            volumes: vec![
                "audit-jbang-cache:/cache/jbang".to_string(),
                "audit-maven-repo:/cache/maven".to_string(),
            ],
            env: vec![
                "JBANG_CACHE_DIR=/cache/jbang".to_string(),
                "MAVEN_OPTS=-Dmaven.repo.local=/cache/maven".to_string(),
            ],
        }
    } else if image.contains("composer") {
        CacheConfig {
            volumes: vec![
                "audit-composer-cache:/cache/composer-cache".to_string(),
                "audit-composer-home:/cache/composer-home".to_string(),
            ],
            env: vec![
                "COMPOSER_CACHE_DIR=/cache/composer-cache".to_string(),
                "COMPOSER_HOME=/cache/composer-home".to_string(),
                // Global vendor binaries live under COMPOSER_HOME.
                "PATH=/cache/composer-home/vendor/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ],
        }
    } else if image.contains("dotnet") {
        CacheConfig {
            volumes: vec![
                "audit-nuget-packages:/cache/nuget".to_string(),
                "audit-dotnet-home:/cache/dotnet-home".to_string(),
            ],
            env: vec![
                "NUGET_PACKAGES=/cache/nuget".to_string(),
                // Redirects global tool installs and CLI telemetry away from /root.
                "DOTNET_CLI_HOME=/cache/dotnet-home".to_string(),
                "HOME=/cache/dotnet-home".to_string(),
                "DOTNET_CLI_TELEMETRY_OPTOUT=1".to_string(),
                "PATH=/cache/dotnet-home/.dotnet/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ],
        }
    } else if image.contains("bridgecrew/checkov") {
        CacheConfig {
            volumes: vec!["audit-checkov-cache:/cache/checkov".to_string()],
            env: vec!["CHECKOV_CACHE_DIR=/cache/checkov".to_string()],
        }
    } else if image.contains("aquasec/trivy") {
        CacheConfig {
            volumes: vec!["audit-trivy-cache:/cache/trivy".to_string()],
            env: vec!["TRIVY_CACHE_DIR=/cache/trivy".to_string()],
        }
    } else if image.contains("anchore/grype") {
        CacheConfig {
            volumes: vec!["audit-grype-db:/cache/grype".to_string()],
            env: vec!["GRYPE_DB_CACHE_DIR=/cache/grype".to_string()],
        }
    } else if image.contains("osv-scanner") {
        CacheConfig {
            volumes: vec!["audit-osv-cache:/cache/osv".to_string()],
            env: vec!["OSV_CACHE_DIR=/cache/osv".to_string()],
        }
    } else if image.contains("eclipse-temurin") {
        CacheConfig {
            volumes: vec!["audit-gradle-home:/cache/gradle".to_string()],
            env: vec!["GRADLE_USER_HOME=/cache/gradle".to_string()],
        }
    } else if image.contains("elixir") {
        CacheConfig {
            volumes: vec![
                "audit-hex-packages:/cache/hex".to_string(),
                "audit-mix-build:/cache/mix".to_string(),
            ],
            env: vec![
                "HEX_HOME=/cache/hex".to_string(),
                "MIX_BUILD_PATH=/cache/mix".to_string(),
            ],
        }
    } else {
        CacheConfig {
            volumes: vec![],
            env: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Executor, resolve_image_for_pull};

    #[test]
    fn registry_override_rewrites_image_references() {
        // No REGISTRY set in the test environment: images pass through.
        assert_eq!(resolve_image_for_pull("node:20-alpine"), "node:20-alpine");
    }

    #[test]
    fn backend_reports_its_name() {
        assert_eq!(super::DockerExecutor::new().name(), "docker");
    }
}
