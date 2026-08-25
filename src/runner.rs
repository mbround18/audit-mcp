//! Scan orchestration: turning one execution into one normalized result.
//!
//! This module owns everything that decides what a scan *means* — which
//! environment a scanner may see, how long it may run, how its output is
//! parsed, and which [`RunStatus`] its exit code earns. It owns none of the
//! machinery for actually running a container; that is an
//! [`Executor`](crate::executor::Executor).
//!
//! The split matters: if each backend decided its own statuses, "clean" would
//! come to mean something subtly different in each one, which is precisely the
//! failure this project exists to prevent.

use std::{env, path::PathBuf, sync::Arc, time::Duration};

use uuid::Uuid;

use crate::executor::{ExecutionRequest, Executor, Termination, docker::DockerExecutor};
use crate::models::{RunStatus, ScanExecution, ScannerDefinition, ScannerRunResult};
use crate::parsers::{self, ParseContext};
use crate::redact::Redactor;
use crate::scanners::DEFAULT_TIMEOUT_SECS;

/// How much of the log stream is echoed back to the MCP client.
const LOG_EXCERPT_CHARS: usize = 24_000;

/// Per-run knobs supplied by the caller.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Wall-clock ceiling; overrides the scanner's own default when set.
    pub timeout: Option<Duration>,
    /// Echo raw stdout/stderr back even on success.
    pub include_raw_logs: bool,
    /// Secrets to strip from anything that becomes a response field. Scoped to
    /// one scan, so clearing it cannot unregister another scan's credential.
    pub redactor: Redactor,
}

/// Runs scanners through an execution backend and normalizes what comes back.
#[derive(Debug, Clone)]
pub struct ScanRunner {
    executor: Arc<dyn Executor>,
}

impl ScanRunner {
    /// The default backend: local Docker containers.
    pub fn docker() -> Self {
        Self {
            executor: Arc::new(DockerExecutor::new()),
        }
    }

    pub fn with_executor(executor: Arc<dyn Executor>) -> Self {
        Self { executor }
    }

    /// Which backend is in use, for reporting.
    pub fn backend(&self) -> &'static str {
        self.executor.name()
    }

    /// Whether the backend's infrastructure is reachable right now.
    pub async fn is_available(&self) -> bool {
        self.executor.is_available().await
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
        let environment = match build_scanner_auth_env(&scanner.name) {
            Ok(env) => env,
            Err(missing) => return Ok(ScannerRunResult::skipped(&scanner.name, missing)),
        };

        let mount = resolve_target(target)?;
        let command = build_command(scanner, &mount.container_target);
        let timeout = options
            .timeout
            .or_else(|| scanner.timeout_secs.map(Duration::from_secs))
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let run_id = format!("run-{}", Uuid::new_v4());
        let outcome = self
            .executor
            .execute(ExecutionRequest {
                scanner,
                workspace: mount.host_dir,
                command: command.clone(),
                environment,
                timeout,
            })
            .await?;

        let duration_ms = outcome.duration.as_millis() as u64;
        // Redaction happens before truncation, always — truncating first can
        // cut a secret in half, and half a credential is still a leak.
        let excerpt = options
            .redactor
            .redact_and_trim(&outcome.combined, LOG_EXCERPT_CHARS);
        // The command is a response field too. A scanner whose invocation
        // interpolates a credential would otherwise publish it in every
        // result, which is how this was found: a test made a scanner echo its
        // token and the token came back in `execution.command`.
        let command: Vec<String> = command
            .iter()
            .map(|argument| options.redactor.redact(argument))
            .collect();

        // An execution the environment killed or never completed is reported
        // with the backend's own words, never as a clean scan.
        match &outcome.termination {
            Termination::TimedOut => {
                return Ok(ScannerRunResult {
                    scanner: scanner.name.clone(),
                    status: RunStatus::Timeout,
                    execution: Some(ScanExecution {
                        run_id,
                        backend: self.backend().to_string(),
                        image: outcome.image,
                        command,
                        status: "timeout".to_string(),
                        exit_code: None,
                        duration_ms,
                        notes: format!(
                            "Killed after exceeding the {}s budget for this scanner.",
                            timeout.as_secs()
                        ),
                        logs: Some(excerpt),
                    }),
                    findings: vec![],
                    error: Some(format!(
                        "scanner '{}' exceeded its {}s time budget and was killed",
                        scanner.name,
                        timeout.as_secs()
                    )),
                });
            }
            Termination::Infrastructure(reason) => {
                return Ok(ScannerRunResult {
                    scanner: scanner.name.clone(),
                    status: RunStatus::ToolError,
                    execution: Some(ScanExecution {
                        run_id,
                        backend: self.backend().to_string(),
                        image: outcome.image,
                        command,
                        status: "tool_error".to_string(),
                        exit_code: outcome.exit_code,
                        duration_ms,
                        notes: format!("Execution environment failed the run: {reason}"),
                        logs: Some(excerpt),
                    }),
                    findings: vec![],
                    error: Some(format!(
                        "scanner '{}' could not run: {reason}",
                        scanner.name
                    )),
                });
            }
            Termination::Completed => {}
        }

        let exit_code = outcome.exit_code.unwrap_or_default();

        // Parse the FULL buffer — truncating first would shred any real
        // JSON/SARIF report. Try the clean stdout stream first; fall back to
        // the merged stream for tools that report on stderr.
        let ctx = ParseContext::new(scanner, target);
        let parsed = parsers::parse(&ctx, &outcome.stdout)
            .or_else(|| parsers::parse(&ctx, &outcome.combined));
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
                backend: self.backend().to_string(),
                image: outcome.image,
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
}

/// Resolve `{target}` and splice in any install script, producing the argv the
/// backend will run verbatim.
fn build_command(scanner: &ScannerDefinition, container_target: &str) -> Vec<String> {
    let raw_command = scanner
        .command_template
        .iter()
        .map(|entry| entry.replace("{target}", container_target))
        .collect::<Vec<_>>();

    // Wrap in `sh -c` when an install script is present so the tool exists
    // by the time the main command runs.
    match &scanner.install_script {
        Some(setup) => {
            let main_cmd = shell_script_for(&raw_command);
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("{setup} && {main_cmd}"),
            ]
        }
        None => raw_command,
    }
}

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
mod status_rules {
    //! The status matrix, driven through a stub backend so it can be verified
    //! with no Docker, no cluster, and no network. Before the executor was
    //! extracted these rules could only be exercised by running a real
    //! container, which is why they went wrong quietly for so long.

    use std::sync::Arc;

    use super::{ScanOptions, ScanRunner};
    use crate::executor::stub::StubExecutor;
    use crate::models::{OutputFormat, RunStatus, ScannerDefinition};

    fn scanner(name: &str, format: OutputFormat, success: &[i64]) -> ScannerDefinition {
        ScannerDefinition {
            name: name.to_string(),
            description: "test".to_string(),
            image: "stub-image".to_string(),
            categories: vec!["Test".to_string()],
            command_template: vec!["run".to_string()],
            install_script: None,
            success_exit_codes: success.to_vec(),
            output_format: format,
            timeout_secs: Some(60),
        }
    }

    async fn run_with(
        executor: StubExecutor,
        definition: &ScannerDefinition,
    ) -> crate::models::ScannerRunResult {
        let runner = ScanRunner::with_executor(Arc::new(executor));
        // The repository root is a real directory, so target resolution succeeds
        // without touching any backend.
        runner
            .run_scan(
                definition,
                env!("CARGO_MANIFEST_DIR"),
                &ScanOptions::default(),
            )
            .await
    }

    const SHELLCHECK_JSON: &str = r#"[{"file":"./a.sh","line":3,"column":6,"level":"warning","code":2086,"message":"Double quote"}]"#;

    #[tokio::test]
    async fn parsed_findings_are_reported_as_findings() {
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::completed(SHELLCHECK_JSON, 1), &definition).await;
        assert_eq!(result.status, RunStatus::Findings);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].id, "SC2086");
    }

    #[tokio::test]
    async fn a_recognized_empty_report_is_clean() {
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::completed("[]", 0), &definition).await;
        assert_eq!(result.status, RunStatus::Clean);
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn unrecognized_output_is_unparsed_not_clean() {
        // The distinction that stops a silently broken scanner reporting a
        // clean bill of health.
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::completed("command not found", 0), &definition).await;
        assert_eq!(result.status, RunStatus::Unparsed);
        assert!(result.execution.unwrap().logs.is_some());
    }

    #[tokio::test]
    async fn an_unexpected_exit_code_is_a_tool_error() {
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::completed("boom", 127), &definition).await;
        assert_eq!(result.status, RunStatus::ToolError);
        assert!(result.error.unwrap().contains("127"));
    }

    #[tokio::test]
    async fn findings_are_trusted_over_an_unexpected_exit_code() {
        // xargs reports 123 whenever the tool it spawned exited non-zero. A
        // scan that produced real findings ran, whatever it exited with.
        let definition = scanner("shellcheck", OutputFormat::Json, &[0]);
        let result = run_with(StubExecutor::completed(SHELLCHECK_JSON, 123), &definition).await;
        assert_eq!(result.status, RunStatus::Findings);
    }

    #[tokio::test]
    async fn a_text_scanner_is_always_unparsed() {
        let definition = scanner("radon", OutputFormat::Text, &[0]);
        let result = run_with(StubExecutor::completed("cc score 4", 0), &definition).await;
        assert_eq!(result.status, RunStatus::Unparsed);
    }

    #[tokio::test]
    async fn a_timeout_reports_timeout_and_keeps_partial_logs() {
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::timed_out(), &definition).await;
        assert_eq!(result.status, RunStatus::Timeout);
        let execution = result
            .execution
            .expect("timed-out runs still report execution");
        assert_eq!(execution.status, "timeout");
        assert!(execution.exit_code.is_none());
        assert!(execution.logs.unwrap().contains("partial output"));
    }

    #[tokio::test]
    async fn an_infrastructure_failure_is_a_tool_error_carrying_the_reason() {
        // An evicted pod or an OOM kill must never look like a clean scan.
        let definition = scanner("shellcheck", OutputFormat::Json, &[0, 1]);
        let result = run_with(StubExecutor::infrastructure("pod evicted"), &definition).await;
        assert_eq!(result.status, RunStatus::ToolError);
        assert!(result.error.unwrap().contains("pod evicted"));
    }

    #[tokio::test]
    async fn a_missing_credential_skips_rather_than_fails() {
        let definition = scanner("snyk", OutputFormat::Sarif, &[0, 1]);
        let result = run_with(StubExecutor::completed("", 0), &definition).await;
        assert_eq!(result.status, RunStatus::Skipped);
        assert!(result.error.unwrap().contains("SNYK_TOKEN"));
    }

    #[tokio::test]
    async fn the_backend_name_is_reported() {
        let runner = ScanRunner::with_executor(Arc::new(StubExecutor::completed("", 0)));
        assert_eq!(runner.backend(), "stub");
        assert!(runner.is_available().await);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ScanOptions, build_scanner_auth_env, collect_allowlisted_env, required_env_for,
        resolve_target, scanner_auth_env_config, shell_quote, shell_script_for,
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
