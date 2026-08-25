use std::{env, path::PathBuf, time::Duration, time::Instant};

use bollard::container::LogOutput;
use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, KillContainerOptionsBuilder,
        LogsOptionsBuilder, RemoveContainerOptionsBuilder,
    },
};
use futures_util::{StreamExt, TryStreamExt};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::models::{RunStatus, ScanExecution, ScannerDefinition, ScannerRunResult};
use crate::parsers::{self, ParseContext};
use crate::scanners::DEFAULT_TIMEOUT_SECS;

/// Hard ceiling on captured container output, so a runaway scanner cannot
/// exhaust memory. Parsers see the full buffer up to this size.
const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
/// How much of the log stream is echoed back to the MCP client.
const LOG_EXCERPT_CHARS: usize = 24_000;
/// Memory ceiling per scanner container. Compilation is memory-hungry but
/// should not be unbounded.
const CONTAINER_MEMORY_BYTES: i64 = 4 * 1024 * 1024 * 1024;

/// Container output, with stdout kept separate from the interleaved view.
#[derive(Debug, Default)]
struct ContainerOutput {
    stdout: String,
    combined: String,
}

/// Per-run knobs supplied by the caller.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Wall-clock ceiling; overrides the scanner's own default when set.
    pub timeout: Option<Duration>,
    /// Echo raw stdout/stderr back even on success.
    pub include_raw_logs: bool,
}

/// Runs scanners in ephemeral Docker containers.
///
/// The Docker client is connected lazily so the MCP server starts (and can
/// answer `list_scanners`/`explain_finding`) even with no daemon running.
#[derive(Debug, Default)]
pub struct DockerScannerRunner {
    docker: OnceCell<Docker>,
}

impl DockerScannerRunner {
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

    /// True when a Docker daemon is reachable right now.
    pub async fn is_available(&self) -> bool {
        self.client().await.is_ok()
    }

    pub async fn run_scan(
        &self,
        scanner: &ScannerDefinition,
        target: &str,
        options: &ScanOptions,
    ) -> ScannerRunResult {
        match self.execute(scanner, target, options).await {
            Ok(result) => result,
            Err(error) => ScannerRunResult::failed(&scanner.name, error),
        }
    }

    async fn execute(
        &self,
        scanner: &ScannerDefinition,
        target: &str,
        options: &ScanOptions,
    ) -> Result<ScannerRunResult, String> {
        if scanner.image.trim().is_empty() {
            return Err(format!(
                "scanner '{}' is missing a container image; all scanners must run in containers",
                scanner.name
            ));
        }
        if scanner.command_template.is_empty() {
            return Err(format!(
                "scanner '{}' is missing an executable command template",
                scanner.name
            ));
        }

        // Credentials are checked before anything expensive happens, and a
        // missing token is a skip rather than a failure so `mode=all` stays quiet.
        let auth_env = match build_scanner_auth_env(&scanner.name) {
            Ok(env) => env,
            Err(missing) => return Ok(ScannerRunResult::skipped(&scanner.name, missing)),
        };

        let docker = self.client().await?;
        let mount = resolve_target(target)?;

        let resolved_image = resolve_image_for_pull(&scanner.image);
        self.ensure_image_available(docker, &resolved_image).await?;

        let run_id = format!("run-{}", Uuid::new_v4());
        let container_name = format!("audit-scan-{}", Uuid::new_v4());
        let raw_command = scanner
            .command_template
            .iter()
            .map(|entry| entry.replace("{target}", &mount.container_target))
            .collect::<Vec<_>>();

        // Wrap in `sh -c` when an install script is present so the tool exists
        // by the time the main command runs.
        let command = match &scanner.install_script {
            Some(setup) => {
                let main_cmd = shell_script_for(&raw_command);
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
        container_env.extend(auth_env);
        let mut binds = vec![format!("{}:/workspace:ro", mount.host_dir.display())];
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

        let timeout = options
            .timeout
            .or_else(|| scanner.timeout_secs.map(Duration::from_secs))
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let wait_result = match tokio::time::timeout(timeout, wait_stream.next()).await {
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
                let logs = self
                    .collect_logs(docker, &container_id)
                    .await
                    .map(|output| output.combined);
                self.cleanup_container(docker, &container_id).await;

                return Ok(ScannerRunResult {
                    scanner: scanner.name.clone(),
                    status: RunStatus::Timeout,
                    execution: Some(ScanExecution {
                        run_id,
                        image: resolved_image,
                        command,
                        status: "timeout".to_string(),
                        exit_code: None,
                        duration_ms: started.elapsed().as_millis() as u64,
                        notes: format!(
                            "Killed after exceeding the {}s budget for this scanner.",
                            timeout.as_secs()
                        ),
                        logs: logs.map(|logs| trim_for_payload(&logs, LOG_EXCERPT_CHARS)),
                    }),
                    findings: vec![],
                    error: Some(format!(
                        "scanner '{}' exceeded its {}s time budget and was killed",
                        scanner.name,
                        timeout.as_secs()
                    )),
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

        let exit_code = wait_result.status_code;
        let duration_ms = started.elapsed().as_millis() as u64;
        let excerpt = trim_for_payload(&output.combined, LOG_EXCERPT_CHARS);

        // Parse the FULL buffer — truncating first would shred any real
        // JSON/SARIF report. Try the clean stdout stream first; fall back to
        // the merged stream for tools that report on stderr.
        let ctx = ParseContext::new(scanner, target);
        let parsed =
            parsers::parse(&ctx, &output.stdout).or_else(|| parsers::parse(&ctx, &output.combined));
        let recognized_output = parsed.is_some();
        let findings = parsed.unwrap_or_default();

        let exit_ok = scanner.success_exit_codes.contains(&exit_code);
        // A tool that produced parseable findings clearly ran, whatever it
        // decided to exit with. This keeps unusual exit codes from turning a
        // useful scan into a reported failure.
        let ran_successfully = exit_ok || !findings.is_empty();

        let status = if !ran_successfully {
            RunStatus::ToolError
        } else if !findings.is_empty() {
            RunStatus::Findings
        } else if recognized_output {
            RunStatus::Clean
        } else {
            // Either no parser exists for this scanner, or it did not emit the
            // report it was asked for — a tool that silently failed must never
            // be reported as clean.
            RunStatus::Unparsed
        };

        let error = (!ran_successfully).then(|| {
            format!(
                "scanner '{}' exited with code {} (expected one of {:?}); logs: {}",
                scanner.name, exit_code, scanner.success_exit_codes, excerpt
            )
        });

        let notes = match status {
            RunStatus::ToolError => {
                format!("Scanner exited with unexpected code {exit_code} after {duration_ms}ms.")
            }
            RunStatus::Unparsed => format!(
                "Scanner completed with exit code {exit_code} but produced no output this parser recognized, so raw logs are attached. Either '{}' has no parser, or it did not emit the expected report.",
                scanner.name
            ),
            _ => format!("Scanner completed in {duration_ms}ms with exit code {exit_code}."),
        };

        // Logs are attached when explicitly requested, when we could not
        // normalize the output, or when the run failed — i.e. whenever they
        // are the only diagnostic the caller has.
        let attach_logs = options.include_raw_logs
            || matches!(status, RunStatus::ToolError | RunStatus::Unparsed);

        Ok(ScannerRunResult {
            scanner: scanner.name.clone(),
            status,
            execution: Some(ScanExecution {
                run_id,
                image: resolved_image,
                command,
                status: status.as_str().to_string(),
                exit_code: Some(exit_code),
                duration_ms,
                notes,
                logs: attach_logs.then_some(excerpt),
            }),
            findings,
            error,
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

/// Render a command template as a single shell script line, for splicing after
/// an install script.
///
/// Most templates are already `["sh", "-c", "<script>"]`; naively joining those
/// with spaces produces `sh -c cargo clippy --all-targets`, where the shell
/// takes only `cargo` as the script and silently runs the wrong thing. Unwrap
/// that form and reuse the script verbatim; quote anything else.
fn shell_script_for(command: &[String]) -> String {
    if let [shell, flag, script] = command
        && (shell == "sh" || shell == "bash")
        && flag == "-c"
    {
        return script.clone();
    }

    command
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Single-quote an argument for POSIX sh.
fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "._-/:=@+,".contains(ch))
    {
        return argument.to_string();
    }
    format!("'{}'", argument.replace('\'', r"'\''"))
}

/// A validated scan target: the host directory to bind-mount, plus the path
/// the scanner should be pointed at inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub host_dir: PathBuf,
    pub container_target: String,
}

/// Resolve `target` to a canonicalized host directory. A file target mounts
/// its parent directory and scopes the scanner to that one file.
pub fn resolve_target(target: &str) -> Result<ResolvedTarget, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("target path must not be empty".to_string());
    }

    let raw = if PathBuf::from(trimmed).is_absolute() {
        PathBuf::from(trimmed)
    } else {
        env::current_dir()
            .map_err(|err| format!("failed to read CWD: {err}"))?
            .join(trimmed)
    };

    if !raw.exists() {
        return Err(format!("target path does not exist: '{}'", raw.display()));
    }

    // Canonicalize resolves symlinks so the bind-mount path is unambiguous.
    let canonical = raw
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize '{}': {err}", raw.display()))?;

    if canonical.is_dir() {
        return Ok(ResolvedTarget {
            host_dir: canonical,
            container_target: ".".to_string(),
        });
    }

    let parent = canonical
        .parent()
        .ok_or_else(|| {
            format!(
                "target file '{}' has no parent directory",
                canonical.display()
            )
        })?
        .to_path_buf();
    let file_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("target file '{}' has a non-UTF-8 name", canonical.display()))?;

    Ok(ResolvedTarget {
        host_dir: parent,
        container_target: format!("./{file_name}"),
    })
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

fn trim_for_payload(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let head = text.chars().take(max_chars).collect::<String>();
    format!("{head}\n… output truncated at {max_chars} characters …")
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

/// Environment variables a scanner cannot run without, for `list_scanners`.
pub fn required_env_for(scanner_name: &str) -> &'static [&'static str] {
    scanner_auth_env_config(scanner_name).required
}

fn build_scanner_auth_env(scanner_name: &str) -> Result<Vec<String>, String> {
    let config = scanner_auth_env_config(scanner_name);
    let (env, missing) = collect_allowlisted_env(&config, |key| env::var(key).ok());
    if missing.is_empty() {
        return Ok(env);
    }

    Err(format!(
        "scanner '{}' requires environment variable(s): {}. Set these on the host before running this scanner.",
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

#[cfg(test)]
mod tests {
    use super::{
        ScanOptions, build_scanner_auth_env, collect_allowlisted_env, required_env_for,
        resolve_image_for_pull, resolve_target, scanner_auth_env_config, shell_quote,
        shell_script_for, trim_for_payload,
    };

    fn words(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    #[test]
    fn install_scripts_reuse_an_sh_c_body_instead_of_nesting_it() {
        // Joining naively yields `sh -c cargo clippy --all-targets`, where the
        // inner shell runs only `cargo` and drops every argument.
        let command = words(&[
            "sh",
            "-c",
            "cargo clippy --all-targets --message-format json",
        ]);
        assert_eq!(
            shell_script_for(&command),
            "cargo clippy --all-targets --message-format json"
        );
    }

    #[test]
    fn install_scripts_quote_plain_argv_commands() {
        let command = words(&["clang-tidy", "src/a b.c", "--"]);
        assert_eq!(shell_script_for(&command), "clang-tidy 'src/a b.c' --");
    }

    #[test]
    fn shell_quoting_escapes_embedded_quotes() {
        assert_eq!(shell_quote("plain-value"), "plain-value");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn resolves_directory_targets_to_the_mount_root() {
        let target = resolve_target(env!("CARGO_MANIFEST_DIR")).expect("manifest dir resolves");
        assert_eq!(target.container_target, ".");
        assert!(target.host_dir.is_dir());
    }

    #[test]
    fn resolves_file_targets_by_mounting_the_parent() {
        let path = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        let target = resolve_target(&path).expect("file resolves");
        assert_eq!(target.container_target, "./Cargo.toml");
        assert_eq!(
            target.host_dir,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .expect("canonical")
        );
    }

    #[test]
    fn rejects_missing_and_empty_targets() {
        let error = resolve_target("/definitely/not/here").expect_err("should fail");
        assert!(error.contains("does not exist"));
        assert!(resolve_target("   ").is_err());
    }

    #[test]
    fn registry_override_rewrites_image_references() {
        // No REGISTRY set in the test environment: images pass through.
        assert_eq!(resolve_image_for_pull("node:20-alpine"), "node:20-alpine");
    }

    #[test]
    fn trimming_marks_truncated_output() {
        let trimmed = trim_for_payload(&"x".repeat(100), 10);
        assert!(trimmed.starts_with(&"x".repeat(10)));
        assert!(trimmed.contains("truncated"));
        assert_eq!(trim_for_payload("short", 10), "short");
    }

    #[test]
    fn auth_config_requires_snyk_token() {
        let config = scanner_auth_env_config("snyk");
        assert!(config.allowlist.contains(&"SNYK_TOKEN"));
        assert_eq!(config.required, &["SNYK_TOKEN"]);
        assert_eq!(required_env_for("snyk"), &["SNYK_TOKEN"]);
        assert!(required_env_for("ruff").is_empty());
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

    #[test]
    fn default_scan_options_are_conservative() {
        let options = ScanOptions::default();
        assert!(options.timeout.is_none());
        assert!(!options.include_raw_logs);
    }
}
