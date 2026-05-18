use crate::models::{FixSuggestion, NormalizedFinding, SuggestFixesResponse};

#[derive(Debug, Clone)]
pub struct FixEngine;

impl FixEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn suggest(&self, findings: &[NormalizedFinding]) -> SuggestFixesResponse {
        let suggestions = findings
            .iter()
            .map(|finding| FixSuggestion {
                kind: "steps".to_string(),
                target: finding
                    .location
                    .path
                    .clone()
                    .unwrap_or_else(|| "repository".to_string()),
                content: format!(
                    "Address '{}' by applying scanner guidance: {}",
                    finding.title, finding.remediation
                ),
                rationale: format!(
                    "Generated from {} finding {} ({})",
                    finding.scanner, finding.id, finding.severity
                ),
            })
            .collect();

        SuggestFixesResponse { suggestions }
    }
}
