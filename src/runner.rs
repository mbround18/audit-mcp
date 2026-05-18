use std::{env, path::PathBuf};

use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, LogsOptionsBuilder,
        RemoveContainerOptionsBuilder,
    },
};
use futures_util::{StreamExt, TryStreamExt};
use serde_json::json;
use uuid::Uuid;

use crate::models::{FindingLocation, NormalizedFinding, ScanExecution, ScannerDefinition};

#[derive(Debug, Clone)]
pub struct DockerScannerRunner {
    docker: Docker,
}

impl DockerScannerRunner {
    pub fn new() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        Ok(Self { docker })
    }

    pub async fn run_scan(
        &self,
        scanner: &ScannerDefinition,
        target: &str,
    ) -> Result<(ScanExecution, Vec<NormalizedFinding>), String> {
        if scanner.image.trim().is_empty() {
            return Err(format!(
                "scanner '{}' is missing a container image; all scanners must run in containers",
                scanner.name
            ));
        }

        self.docker
            .ping()
            .await
            .map_err(|err| format!("docker ping failed: {err}"))?;

        // Resolve and validate the target before touching Docker.
        let host_target = resolve_target(target)?;

        let resolved_image = resolve_image_for_pull(&scanner.image);
        self.ensure_image_available(&resolved_image).await?;

        let run_id = format!("run-{}", Uuid::new_v4());
        let container_name = format!("audit-scan-{}", Uuid::new_v4());
        let raw_command = scanner
            .command_template
            .iter()
            // container_target is always "." — the mount root IS the target.
            .map(|entry| entry.replace("{target}", "."))
            .collect::<Vec<_>>();
        if raw_command.is_empty() {
            return Err(format!(
                "scanner '{}' is missing an executable command template; all scanners must be container-runnable",
                scanner.name
            ));
        }
        // Wrap in sh -c when an install script is present so tools are available at run time.
        let command = match &scanner.install_script {
            Some(setup) => {
                let main_cmd = raw_command.join(" ");
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("{setup} && {main_cmd}"),
                ]
            }
            None => raw_command,
        };

        let cache = image_cache_config(&resolved_image, &scanner.name);
        let mut binds = vec![format!("{}:/workspace:ro", host_target.display())];
        binds.extend(cache.volumes);

        let create_response = self
            .docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::new()
                        .name(&container_name)
                        .build(),
                ),
                ContainerCreateBody {
                    image: Some(resolved_image.clone()),
                    cmd: Some(command.clone()),
                    working_dir: Some("/workspace".to_string()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    env: Some(cache.env),
                    host_config: Some(HostConfig {
                        binds: Some(binds),
                        auto_remove: Some(false),
                        // Prevent privilege escalation inside the container.
                        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                        // Drop all Linux capabilities; scanners are analysis tools, not system daemons.
                        cap_drop: Some(vec!["ALL".to_string()]),
                        // 4 GB ceiling — compilation is memory-hungry but shouldn't be unbounded.
                        memory: Some(4 * 1024 * 1024 * 1024),
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
        // Set up the wait stream BEFORE starting so we don't miss the exit event
        // if the container finishes before the next await point.
        let mut wait_stream = self.docker.wait_container(&container_id, None);

        if let Err(err) = self.docker.start_container(&container_id, None).await {
            self.cleanup_container(&container_id).await;
            return Err(format!(
                "failed to start scanner container '{container_id}': {err}"
            ));
        }

        let wait_result = match wait_stream.next().await {
            Some(Ok(result)) => result,
            // Docker surfaces non-zero container exits as DockerContainerWaitError.
            // Convert to a synthetic response so the exit code reaches our logging path.
            Some(Err(BollardError::DockerContainerWaitError { code, .. })) => {
                bollard::models::ContainerWaitResponse {
                    status_code: code,
                    error: None,
                }
            }
            Some(Err(err)) => {
                self.cleanup_container(&container_id).await;
                return Err(format!(
                    "failed while waiting for scanner container '{container_id}': {err}"
                ));
            }
            None => {
                self.cleanup_container(&container_id).await;
                return Err(format!(
                    "scanner container '{container_id}' exited without wait result"
                ));
            }
        };

        let logs = match self
            .docker
            .logs(
                &container_id,
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
        {
            Ok(logs) => logs,
            Err(err) => {
                self.cleanup_container(&container_id).await;
                return Err(format!(
                    "failed to read logs from scanner container '{container_id}': {err}"
                ));
            }
        };

        self.cleanup_container(&container_id).await;

        let combined_logs = logs
            .into_iter()
            .map(|output| String::from_utf8_lossy(output.into_bytes().as_ref()).into_owned())
            .collect::<Vec<_>>()
            .join("");
        let trimmed_logs = trim_for_payload(&combined_logs, 24_000);
        if wait_result.status_code != 0 {
            return Err(format!(
                "scanner '{}' failed with exit code {}. logs: {}",
                scanner.name, wait_result.status_code, trimmed_logs
            ));
        }

        let execution = ScanExecution {
            run_id: run_id.clone(),
            image: resolved_image.clone(),
            command: command.clone(),
            status: "completed".to_string(),
            notes: format!(
                "Scanner completed in container '{}' with exit code {}.",
                container_id, wait_result.status_code
            ),
        };

        let finding = NormalizedFinding {
            id: format!("{}:run:{target}:{}", scanner.name, run_id),
            scanner: scanner.name.clone(),
            category: scanner
                .categories
                .first()
                .cloned()
                .unwrap_or_else(|| "general".to_string()),
            severity: "info".to_string(),
            title: "Scanner completed".to_string(),
            description: "Scanner command completed successfully in an isolated container. Output is attached in raw payload until parser-level normalization is added.".to_string(),
            location: FindingLocation {
                path: Some(target.to_string()),
                line: None,
                column: None,
            },
            fingerprint: run_id,
            remediation: "Add scanner-specific output parsers to convert command output into first-class normalized findings.".to_string(),
            references: vec![
                "https://docs.rs/bollard/latest/bollard/".to_string(),
                "https://modelcontextprotocol.io/specification/".to_string(),
            ],
            raw: json!({
                "scaffold": false,
                "image": resolved_image,
                "isolation": "docker",
                "registry_override": env::var("REGISTRY").ok(),
                "container_id": container_id,
                "host_target": host_target.display().to_string(),
                "stdout_stderr": trimmed_logs
            }),
        };

        Ok((execution, vec![finding]))
    }

    async fn ensure_image_available(&self, image: &str) -> Result<(), String> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }

        self.docker
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

    async fn cleanup_container(&self, container_id: &str) {
        let _ = self
            .docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
    }
}

/// Resolve `target` to a canonicalized absolute directory path on the host.
/// Relative paths are resolved against the process CWD.
fn resolve_target(target: &str) -> Result<PathBuf, String> {
    let raw = if PathBuf::from(target).is_absolute() {
        PathBuf::from(target)
    } else {
        env::current_dir()
            .map_err(|e| format!("failed to read CWD: {e}"))?
            .join(target)
    };

    if !raw.exists() {
        return Err(format!("target path does not exist: '{}'", raw.display()));
    }
    if !raw.is_dir() {
        return Err(format!(
            "target must be a directory, got file: '{}'",
            raw.display()
        ));
    }

    // Canonicalize resolves symlinks so the Docker bind-mount path is unambiguous.
    raw.canonicalize()
        .map_err(|e| format!("failed to canonicalize '{}': {e}", raw.display()))
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
///        audit-pnpm-store (shared)      — pnpm content store used by pnpx
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
            ],
        }
    } else if image.contains("node") {
        CacheConfig {
            volumes: vec![
                "audit-npm-cache:/cache/npm".to_string(),
                "audit-pnpm-store:/cache/pnpm".to_string(),
            ],
            env: vec![
                "NPM_CONFIG_CACHE=/cache/npm".to_string(),
                // pnpx (pnpm dlx) uses PNPM_HOME as its content-addressed store.
                "PNPM_HOME=/cache/pnpm".to_string(),
            ],
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
            ],
        }
    } else {
        CacheConfig {
            volumes: vec![],
            env: vec![],
        }
    }
}

fn trim_for_payload(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect()
}
