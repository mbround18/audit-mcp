use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How a scanner's stdout should be interpreted by the normalization layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// SARIF 2.1.0 — parsed by the generic SARIF parser.
    Sarif,
    /// Tool-specific JSON — parsed by a named parser in `crate::parsers`.
    Json,
    /// Human-readable output with no parser; surfaced as raw logs only.
    #[default]
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannerDefinition {
    pub name: String,
    pub description: String,
    pub image: String,
    pub categories: Vec<String>,
    pub command_template: Vec<String>,
    /// Shell commands to run inside the container before the main command.
    #[serde(default)]
    pub install_script: Option<String>,
    /// Exit codes that mean "the tool ran correctly". Most linters exit
    /// non-zero when they have findings, which is not a failure.
    #[serde(default = "default_success_exit_codes")]
    pub success_exit_codes: Vec<i64>,
    /// Shape of the tool's stdout, used to pick a parser.
    #[serde(default)]
    pub output_format: OutputFormat,
    /// Per-scanner wall-clock ceiling. Falls back to the request/global default.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_success_exit_codes() -> Vec<i64> {
    vec![0]
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannerSummary {
    pub name: String,
    pub description: String,
    pub image: String,
    pub categories: Vec<String>,
    /// True when this scanner has a real output parser (not raw-log fallback).
    pub normalized: bool,
    /// Environment variables that must be set on the host for this scanner.
    pub required_env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListScannersResponse {
    pub scanners: Vec<ScannerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingLocation {
    pub path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NormalizedFinding {
    pub id: String,
    pub scanner: String,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub location: FindingLocation,
    pub fingerprint: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub raw: Value,
}

/// Ordered severity ladder used for filtering and summary rollups.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" | "fatal" | "blocker" => Self::Critical,
            "high" | "error" | "severe" => Self::High,
            "medium" | "moderate" | "warning" | "warn" => Self::Medium,
            "low" | "minor" | "style" => Self::Low,
            "info" | "informational" | "note" | "none" => Self::Info,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
            Self::Unknown => "unknown",
        }
    }
}

/// Outcome of a single scanner run. Distinguishes "found nothing" from
/// "could not run", which the previous `|| true` shape could not express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Scanner ran and reported no findings.
    Clean,
    /// Scanner ran and reported at least one finding.
    Findings,
    /// Scanner ran but produced output no parser could normalize.
    Unparsed,
    /// Scanner could not run (bad image, crash, unexpected exit code).
    ToolError,
    /// Scanner exceeded its wall-clock budget and was killed.
    Timeout,
    /// Scanner was intentionally not run (missing credentials, no Docker).
    Skipped,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Findings => "findings",
            Self::Unparsed => "unparsed",
            Self::ToolError => "tool_error",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanExecution {
    pub run_id: String,
    pub image: String,
    pub command: Vec<String>,
    pub status: String,
    pub exit_code: Option<i64>,
    pub duration_ms: u64,
    pub notes: String,
    /// Raw stdout/stderr, only populated when explicitly requested or when
    /// the run failed (where the logs are the diagnostic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolSelectionPlan {
    pub phase: String,
    pub selected_scanners: Vec<String>,
    pub rationale: String,
    /// Languages inferred from the target's contents.
    #[serde(default)]
    pub detected_languages: Vec<String>,
    /// Files that drove detection, for auditability.
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub findings_returned: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub scanners_selected: usize,
    pub scanners_with_findings: usize,
    pub scanners_clean: usize,
    pub scanners_failed: usize,
    pub scanners_skipped: usize,
    pub scanners_timed_out: usize,
    /// Non-fatal notes worth surfacing to the caller (truncation, filtering).
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunScanResponse {
    pub mode: String,
    pub target: String,
    pub selection: ToolSelectionPlan,
    pub summary: ScanSummary,
    pub runs: Vec<ScannerRunResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannerRunResult {
    pub scanner: String,
    pub status: RunStatus,
    pub execution: Option<ScanExecution>,
    pub findings: Vec<NormalizedFinding>,
    pub error: Option<String>,
}

impl ScannerRunResult {
    pub fn skipped(scanner: &str, reason: impl Into<String>) -> Self {
        Self {
            scanner: scanner.to_string(),
            status: RunStatus::Skipped,
            execution: None,
            findings: vec![],
            error: Some(reason.into()),
        }
    }

    pub fn failed(scanner: &str, reason: impl Into<String>) -> Self {
        Self {
            scanner: scanner.to_string(),
            status: RunStatus::ToolError,
            execution: None,
            findings: vec![],
            error: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingExplanation {
    pub scanner: String,
    pub id: String,
    pub title: String,
    pub explanation: String,
    pub remediation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FixSuggestion {
    pub kind: String,
    pub target: String,
    pub content: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuggestFixesResponse {
    pub suggestions: Vec<FixSuggestion>,
}

/// Which execution backend is active and whether it can be reached.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecutorStatus {
    /// `docker` or `kubernetes`.
    pub backend: String,
    pub available: bool,
    /// Why it is unavailable, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LanguageToolProfile {
    pub language: String,
    pub preferred_scanners: Vec<String>,
    pub categories: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn severity_ladder_orders_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
        assert!(Severity::Info > Severity::Unknown);
    }

    #[test]
    fn severity_parses_tool_synonyms() {
        assert_eq!(Severity::parse("ERROR"), Severity::High);
        assert_eq!(Severity::parse("warning"), Severity::Medium);
        assert_eq!(Severity::parse("MODERATE"), Severity::Medium);
        assert_eq!(Severity::parse("note"), Severity::Info);
        assert_eq!(Severity::parse("nonsense"), Severity::Unknown);
    }
}
