//! Pluggable scanner execution.
//!
//! An executor runs one scanner against one prepared workspace and returns its
//! raw output, exit code, and duration — deliberately **no status and no
//! findings**. Status determination and normalization live in
//! [`crate::runner`], so two backends cannot drift apart in what they call a
//! clean scan.
//!
//! Every backend enforces the same isolation guarantees: a read-only
//! workspace, no privilege escalation, dropped capabilities, an explicit
//! memory ceiling, and a wall-clock timeout. A backend that cannot is not a
//! backend.

pub mod docker;

use std::{fmt::Debug, path::PathBuf, time::Duration};

use futures_util::future::BoxFuture;

use crate::models::ScannerDefinition;

/// Where the workspace is mounted inside every execution environment.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// Everything a backend needs to run one scanner once.
#[derive(Debug, Clone)]
pub struct ExecutionRequest<'a> {
    pub scanner: &'a ScannerDefinition,
    /// Directory to expose read-only at [`WORKSPACE_MOUNT`].
    pub workspace: PathBuf,
    /// Fully resolved argv, with `{target}` already substituted and any
    /// install script already spliced in.
    pub command: Vec<String>,
    /// Allowlisted `KEY=VALUE` pairs for this scanner, and nothing else.
    pub environment: Vec<String>,
    /// Wall-clock ceiling. Exceeding it must kill the execution, not abandon it.
    pub timeout: Duration,
}

/// How an execution ended, from the backend's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Termination {
    /// The command ran to completion, whatever it exited with.
    Completed,
    /// Killed for exceeding its wall-clock budget.
    TimedOut,
    /// The environment failed the execution — an eviction, an OOM kill, an
    /// image that would not pull. Carries the backend's own words so the
    /// resulting `tool_error` is diagnosable.
    Infrastructure(String),
}

/// The raw result of one execution. Note what is absent: no status, no
/// findings, no judgement about whether the scan was clean.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    /// The image actually used, after any registry rewriting.
    pub image: String,
    /// Captured stdout, kept separate from stderr.
    ///
    /// This is not a nicety. Docker interleaves the two streams, and a stderr
    /// line spliced into stdout corrupted gosec's SARIF mid-document — the
    /// report parsed as nothing and the scan reported clean.
    pub stdout: String,
    /// Both streams as a human would see them, for diagnostics.
    pub combined: String,
    /// `None` when the execution was killed before it could exit.
    pub exit_code: Option<i64>,
    pub duration: Duration,
    pub termination: Termination,
}

/// A backend that can run a scanner.
///
/// Deliberately expressed with boxed futures rather than `async fn`: the
/// runner holds an `Arc<dyn Executor>` so the backend can be chosen at
/// startup, and `async fn` in a trait is not yet dyn-compatible. Using
/// `BoxFuture` keeps that working without pulling in another dependency.
pub trait Executor: Send + Sync + Debug {
    /// Stable identifier reported in `execution.backend`.
    fn name(&self) -> &'static str;

    /// Whether this backend's infrastructure is reachable right now.
    ///
    /// Called once as a preflight so an unreachable backend yields one clear
    /// error rather than one identical failure per selected scanner.
    fn is_available(&self) -> BoxFuture<'_, bool>;

    fn execute<'a>(
        &'a self,
        request: ExecutionRequest<'a>,
    ) -> BoxFuture<'a, Result<ExecutionOutcome, String>>;
}

/// A backend that needs no infrastructure, so the runner's status rules can be
/// exercised hermetically. Test-only, but shared across modules.
#[cfg(test)]
pub mod stub {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct StubExecutor {
        pub stdout: String,
        pub combined: String,
        pub exit_code: Option<i64>,
        pub termination: Termination,
    }

    impl StubExecutor {
        /// A completed run with the given stdout and exit code.
        pub fn completed(stdout: &str, exit_code: i64) -> Self {
            Self {
                stdout: stdout.to_string(),
                combined: stdout.to_string(),
                exit_code: Some(exit_code),
                termination: Termination::Completed,
            }
        }

        pub fn timed_out() -> Self {
            Self {
                stdout: String::new(),
                combined: "partial output".to_string(),
                exit_code: None,
                termination: Termination::TimedOut,
            }
        }

        pub fn infrastructure(reason: &str) -> Self {
            Self {
                stdout: String::new(),
                combined: String::new(),
                exit_code: None,
                termination: Termination::Infrastructure(reason.to_string()),
            }
        }
    }

    impl Executor for StubExecutor {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn is_available(&self) -> BoxFuture<'_, bool> {
            Box::pin(async { true })
        }

        fn execute<'a>(
            &'a self,
            _request: ExecutionRequest<'a>,
        ) -> BoxFuture<'a, Result<ExecutionOutcome, String>> {
            Box::pin(async move {
                Ok(ExecutionOutcome {
                    image: "stub-image".to_string(),
                    stdout: self.stdout.clone(),
                    combined: self.combined.clone(),
                    exit_code: self.exit_code,
                    duration: Duration::from_millis(1),
                    termination: self.termination.clone(),
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::stub::StubExecutor;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn executor_is_object_safe() {
        // The runner stores `Arc<dyn Executor>`, so this must keep compiling.
        let executor: Arc<dyn Executor> = Arc::new(StubExecutor::completed("", 0));
        assert_eq!(executor.name(), "stub");
    }

    #[tokio::test]
    async fn stub_executor_reports_availability_without_infrastructure() {
        assert!(StubExecutor::completed("", 0).is_available().await);
    }
}
