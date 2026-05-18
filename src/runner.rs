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
use serde_json::{Value, json};
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
        let mut container_env = cache.env;
        let auth_env = build_scanner_auth_env(&scanner.name)?;
        container_env.extend(auth_env);
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
                    env: Some(container_env),
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
        let mut findings = parse_scanner_output(scanner, target, &run_id, &trimmed_logs);
        if findings.is_empty() {
            findings.push(NormalizedFinding {
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
            });
        }

        Ok((execution, findings))
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

fn trim_for_payload(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect()
}

#[derive(Debug)]
struct ScannerAuthEnvConfig {
    allowlist: &'static [&'static str],
    required: &'static [&'static str],
}

fn scanner_auth_env_config(scanner_name: &str) -> ScannerAuthEnvConfig {
    match scanner_name {
        "snyk" | "snyk-java" | "dotnet-snyk" => ScannerAuthEnvConfig {
            allowlist: &["SNYK_TOKEN", "SNYK_API", "SNYK_CFG_ORG"],
            required: &["SNYK_TOKEN"],
        },
        "dotnet-sonarscanner" => ScannerAuthEnvConfig {
            allowlist: &[
                "SONAR_TOKEN",
                "SONAR_HOST_URL",
                "SONAR_PROJECT_KEY",
                "SONAR_ORGANIZATION",
            ],
            required: &["SONAR_TOKEN", "SONAR_HOST_URL"],
        },
        "dependency-check" => ScannerAuthEnvConfig {
            allowlist: &["NVD_API_KEY"],
            required: &[],
        },
        "checkov" => ScannerAuthEnvConfig {
            allowlist: &["BC_API_KEY"],
            required: &[],
        },
        _ => ScannerAuthEnvConfig {
            allowlist: &[],
            required: &[],
        },
    }
}

fn build_scanner_auth_env(scanner_name: &str) -> Result<Vec<String>, String> {
    let config = scanner_auth_env_config(scanner_name);
    let (env, missing) = collect_allowlisted_env(&config, |key| env::var(key).ok());
    if missing.is_empty() {
        return Ok(env);
    }

    Err(format!(
        "scanner '{}' requires environment variable(s): {}. Set these variables before running this scanner.",
        scanner_name,
        missing.join(", ")
    ))
}

fn collect_allowlisted_env<F>(
    config: &ScannerAuthEnvConfig,
    mut resolver: F,
) -> (Vec<String>, Vec<String>)
where
    F: FnMut(&str) -> Option<String>,
{
    let mut env_pairs = Vec::new();
    for key in config.allowlist {
        if let Some(value) = resolver(key) {
            env_pairs.push(format!("{key}={value}"));
        }
    }

    let missing = config
        .required
        .iter()
        .filter(|key| resolver(key).is_none())
        .map(|key| (*key).to_string())
        .collect::<Vec<_>>();

    (env_pairs, missing)
}

fn parse_scanner_output(
    scanner: &ScannerDefinition,
    target: &str,
    run_id: &str,
    logs: &str,
) -> Vec<NormalizedFinding> {
    match scanner.name.as_str() {
        "checkov" => parse_checkov_output(scanner, target, run_id, logs),
        "trivy-config" => parse_trivy_config_output(scanner, target, run_id, logs),
        _ => Vec::new(),
    }
}

fn parse_checkov_output(
    scanner: &ScannerDefinition,
    target: &str,
    run_id: &str,
    logs: &str,
) -> Vec<NormalizedFinding> {
    let json = match extract_json_payload(logs) {
        Some(value) => value,
        None => return Vec::new(),
    };

    let failed_checks = json
        .get("results")
        .and_then(|value| value.get("failed_checks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    failed_checks
        .into_iter()
        .map(|check| {
            let check_id = check
                .get("check_id")
                .and_then(Value::as_str)
                .unwrap_or("CHECKOV_UNKNOWN");
            let title = check
                .get("check_name")
                .and_then(Value::as_str)
                .unwrap_or("Checkov policy violation")
                .to_string();
            let path = check
                .get("file_path")
                .and_then(Value::as_str)
                .map(normalize_workspace_path)
                .or_else(|| Some(target.to_string()));
            let line = check
                .get("file_line_range")
                .and_then(Value::as_array)
                .and_then(|range| range.first())
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
            let severity = check
                .get("severity")
                .and_then(Value::as_str)
                .map(normalize_severity)
                .unwrap_or_else(|| "medium".to_string());
            let description = check
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    check
                        .get("check_result")
                        .and_then(|result| result.get("result"))
                        .and_then(Value::as_str)
                        .unwrap_or("Policy check failed.")
                        .to_string()
                });
            let remediation = check
                .get("guideline")
                .and_then(Value::as_str)
                .unwrap_or("Review the policy failure and update the infrastructure resource to satisfy the control.")
                .to_string();
            let mut references = Vec::new();
            if let Some(url) = check.get("guideline").and_then(Value::as_str) {
                references.push(url.to_string());
            }

            NormalizedFinding {
                id: format!("checkov:{check_id}:{run_id}"),
                scanner: scanner.name.clone(),
                category: scanner
                    .categories
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Security (IaC)".to_string()),
                severity,
                title,
                description,
                location: FindingLocation {
                    path,
                    line,
                    column: None,
                },
                fingerprint: format!("checkov:{check_id}:{run_id}"),
                remediation,
                references,
                raw: check,
            }
        })
        .collect()
}

fn parse_trivy_config_output(
    scanner: &ScannerDefinition,
    target: &str,
    run_id: &str,
    logs: &str,
) -> Vec<NormalizedFinding> {
    let json = match extract_json_payload(logs) {
        Some(value) => value,
        None => return Vec::new(),
    };

    let results = json
        .get("Results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();

    for result in results {
        let target_path = result
            .get("Target")
            .and_then(Value::as_str)
            .map(normalize_workspace_path)
            .unwrap_or_else(|| target.to_string());

        let misconfigurations = result
            .get("Misconfigurations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for issue in misconfigurations {
            let status = issue
                .get("Status")
                .and_then(Value::as_str)
                .unwrap_or("FAIL");
            if status.eq_ignore_ascii_case("pass") {
                continue;
            }

            let issue_id = issue
                .get("ID")
                .and_then(Value::as_str)
                .or_else(|| issue.get("AVDID").and_then(Value::as_str))
                .unwrap_or("TRIVY_CONFIG_UNKNOWN");
            let title = issue
                .get("Title")
                .and_then(Value::as_str)
                .unwrap_or("Trivy configuration finding")
                .to_string();
            let description = issue
                .get("Description")
                .and_then(Value::as_str)
                .or_else(|| issue.get("Message").and_then(Value::as_str))
                .unwrap_or("Configuration issue detected by Trivy.")
                .to_string();
            let remediation = issue
                .get("Resolution")
                .and_then(Value::as_str)
                .unwrap_or("Update the configuration to satisfy the failed policy.")
                .to_string();
            let severity = issue
                .get("Severity")
                .and_then(Value::as_str)
                .map(normalize_severity)
                .unwrap_or_else(|| "medium".to_string());
            let line = issue
                .get("CauseMetadata")
                .and_then(|metadata| metadata.get("StartLine"))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());

            let mut references = Vec::new();
            if let Some(url) = issue.get("PrimaryURL").and_then(Value::as_str) {
                references.push(url.to_string());
            }
            if let Some(additional_refs) = issue.get("References").and_then(Value::as_array) {
                references.extend(
                    additional_refs
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string),
                );
            }

            findings.push(NormalizedFinding {
                id: format!("trivy-config:{issue_id}:{run_id}"),
                scanner: scanner.name.clone(),
                category: scanner
                    .categories
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Security (IaC)".to_string()),
                severity,
                title,
                description,
                location: FindingLocation {
                    path: Some(target_path.clone()),
                    line,
                    column: None,
                },
                fingerprint: format!("trivy-config:{issue_id}:{run_id}"),
                remediation,
                references,
                raw: issue,
            });
        }
    }

    findings
}

fn extract_json_payload(logs: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(logs) {
        return Some(value);
    }

    let mut starts = logs
        .char_indices()
        .filter_map(|(index, ch)| match ch {
            '{' | '[' => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    starts.reverse();

    for start in starts {
        let Some(end) = find_json_end(logs, start) else {
            continue;
        };

        if let Ok(value) = serde_json::from_str::<Value>(&logs[start..=end]) {
            return Some(value);
        }
    }

    None
}

fn find_json_end(input: &str, start: usize) -> Option<usize> {
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in input.char_indices().skip_while(|(idx, _)| *idx < start) {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }

            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }

    None
}

fn normalize_workspace_path(path: &str) -> String {
    path.trim_start_matches("/workspace/")
        .trim_start_matches("./")
        .to_string()
}

fn normalize_severity(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "critical" => "critical".to_string(),
        "high" => "high".to_string(),
        "medium" => "medium".to_string(),
        "low" => "low".to_string(),
        "info" | "informational" => "info".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_scanner_auth_env, collect_allowlisted_env, extract_json_payload,
        normalize_workspace_path, parse_checkov_output, parse_trivy_config_output,
        scanner_auth_env_config,
    };
    use crate::models::ScannerDefinition;

    fn scanner(name: &str, category: &str) -> ScannerDefinition {
        ScannerDefinition {
            name: name.to_string(),
            description: "test".to_string(),
            image: "test-image".to_string(),
            categories: vec![category.to_string()],
            command_template: vec![],
            install_script: None,
        }
    }

    #[test]
    fn parses_checkov_failed_checks() {
        let logs = r#"{"results":{"failed_checks":[{"check_id":"CKV_AWS_20","check_name":"S3 Bucket Public Read","description":"Bucket allows public read","file_path":"/workspace/terraform/main.tf","file_line_range":[7,13],"severity":"HIGH","guideline":"https://docs.bridgecrew.io/docs/s3_1-enable-s3-bucket-encryption"}]}}"#;
        let findings = parse_checkov_output(
            &scanner("checkov", "Security (IaC)"),
            "infrastructure",
            "run-1",
            logs,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(
            findings[0].location.path.as_deref(),
            Some("terraform/main.tf")
        );
        assert_eq!(findings[0].location.line, Some(7));
    }

    #[test]
    fn parses_trivy_config_misconfigurations() {
        let logs = r#"{"Results":[{"Target":"/workspace/k8s/deploy.yaml","Misconfigurations":[{"ID":"KSV001","AVDID":"AVD-KSV-001","Title":"Container should not run as root","Description":"Root containers increase attack surface.","Resolution":"Set securityContext.runAsNonRoot=true","Severity":"CRITICAL","Status":"FAIL","PrimaryURL":"https://avd.aquasec.com/misconfig/ksv001","CauseMetadata":{"StartLine":12}}]}]}"#;
        let findings = parse_trivy_config_output(
            &scanner("trivy-config", "Security (IaC)"),
            "infrastructure",
            "run-2",
            logs,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(
            findings[0].location.path.as_deref(),
            Some("k8s/deploy.yaml")
        );
        assert_eq!(findings[0].location.line, Some(12));
    }

    #[test]
    fn extracts_json_payload_from_prefixed_logs() {
        let logs = "INFO scanner started\n{\"Results\": []}\n";
        let payload = extract_json_payload(logs);
        assert!(payload.is_some());
    }

    #[test]
    fn normalizes_workspace_paths() {
        assert_eq!(normalize_workspace_path("/workspace/a/b.tf"), "a/b.tf");
        assert_eq!(
            normalize_workspace_path("./k8s/deploy.yaml"),
            "k8s/deploy.yaml"
        );
    }

    #[test]
    fn auth_config_requires_snyk_token() {
        let config = scanner_auth_env_config("snyk");
        assert!(config.allowlist.contains(&"SNYK_TOKEN"));
        assert_eq!(config.required, &["SNYK_TOKEN"]);
    }

    #[test]
    fn collect_allowlisted_env_reports_missing_required() {
        let config = scanner_auth_env_config("dotnet-sonarscanner");
        let vars = [("SONAR_TOKEN".to_string(), "test-token".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();

        let (env, missing) = collect_allowlisted_env(&config, |key| vars.get(key).cloned());
        assert_eq!(env, vec!["SONAR_TOKEN=test-token".to_string()]);
        assert_eq!(missing, vec!["SONAR_HOST_URL".to_string()]);
    }

    #[test]
    fn non_auth_scanner_requires_no_env() {
        let env = build_scanner_auth_env("ruff").expect("ruff should not require auth env");
        assert!(env.is_empty());
    }
}
