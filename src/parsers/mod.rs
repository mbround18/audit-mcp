//! Normalization layer: converts scanner stdout into [`NormalizedFinding`]s.
//!
//! Two strategies, in order of preference:
//!
//! 1. **SARIF** ([`sarif`]) — one parser covers every tool that can emit
//!    SARIF 2.1.0 natively (semgrep, gitleaks, hadolint, gosec, ruff, …).
//! 2. **Tool-native JSON** ([`tools`]) — for scanners with no SARIF support.
//!
//! Anything else falls through to raw logs, which the runner reports as
//! [`RunStatus::Unparsed`](crate::models::RunStatus::Unparsed) rather than
//! pretending the scan was clean.

pub mod json;
pub mod sarif;
pub mod tools;

use crate::models::{
    FindingLocation, NormalizedFinding, OutputFormat, ScannerDefinition, Severity,
};

/// Everything a parser needs beyond the raw output itself.
pub struct ParseContext<'a> {
    pub scanner: &'a ScannerDefinition,
    pub target: &'a str,
}

impl<'a> ParseContext<'a> {
    pub fn new(scanner: &'a ScannerDefinition, target: &'a str) -> Self {
        Self { scanner, target }
    }

    fn category(&self) -> String {
        self.scanner
            .categories
            .first()
            .cloned()
            .unwrap_or_else(|| "general".to_string())
    }

    /// Build a finding with a stable, run-independent fingerprint so callers
    /// can diff results across runs and deduplicate across scanners.
    #[allow(clippy::too_many_arguments)]
    pub fn finding(
        &self,
        rule_id: &str,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        path: Option<String>,
        line: Option<u32>,
        column: Option<u32>,
        remediation: impl Into<String>,
        references: Vec<String>,
        raw: serde_json::Value,
    ) -> NormalizedFinding {
        let path = path.map(|value| normalize_workspace_path(&value));
        let fingerprint = format!(
            "{}:{}:{}:{}",
            self.scanner.name,
            rule_id,
            path.as_deref().unwrap_or("-"),
            line.map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        );

        NormalizedFinding {
            // `id` is the tool's own rule identifier so `explain_finding`
            // can be called with it directly.
            id: rule_id.to_string(),
            scanner: self.scanner.name.clone(),
            category: self.category(),
            severity: severity.as_str().to_string(),
            title: title.into(),
            description: description.into(),
            location: FindingLocation { path, line, column },
            fingerprint,
            remediation: remediation.into(),
            references,
            raw,
        }
    }
}

/// Returns true when this scanner has a real parser (used by `list_scanners`
/// so callers know which scanners yield structured findings).
pub fn has_parser(scanner: &ScannerDefinition) -> bool {
    match scanner.output_format {
        OutputFormat::Sarif => true,
        OutputFormat::Json => tools::supports(&scanner.name),
        OutputFormat::Text => false,
    }
}

/// Parse a scanner's output into normalized findings.
///
/// `None` means the output was not recognized — no parser exists for this
/// scanner, or the tool did not emit the report it was asked for. That is
/// deliberately distinct from `Some(vec![])`, which means the tool ran and
/// genuinely found nothing. Collapsing the two is how a broken scanner ends
/// up reported as a clean one.
pub fn parse(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    match ctx.scanner.output_format {
        OutputFormat::Sarif => sarif::parse(ctx, logs),
        OutputFormat::Json => tools::parse(ctx, logs),
        OutputFormat::Text => None,
    }
}

/// Strip the container mount prefix so paths are relative to the scanned repo.
pub fn normalize_workspace_path(path: &str) -> String {
    let trimmed = path
        .trim()
        .trim_start_matches("file://")
        .trim_start_matches("/workspace/")
        .trim_start_matches("workspace/")
        .trim_start_matches("./");
    if trimmed == "/workspace" || trimmed.is_empty() {
        return ".".to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::normalize_workspace_path;

    #[test]
    fn normalizes_container_paths() {
        assert_eq!(normalize_workspace_path("/workspace/a/b.tf"), "a/b.tf");
        assert_eq!(
            normalize_workspace_path("./k8s/deploy.yaml"),
            "k8s/deploy.yaml"
        );
        assert_eq!(normalize_workspace_path("file:///workspace/x.py"), "x.py");
        assert_eq!(normalize_workspace_path("/workspace"), ".");
    }
}
