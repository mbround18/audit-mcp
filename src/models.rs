use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannerSummary {
    pub name: String,
    pub description: String,
    pub image: String,
    pub categories: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanExecution {
    pub run_id: String,
    pub image: String,
    pub command: Vec<String>,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolSelectionPlan {
    pub phase: String,
    pub selected_scanners: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunScanResponse {
    pub mode: String,
    pub target: String,
    pub selection: ToolSelectionPlan,
    pub runs: Vec<ScannerRunResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannerRunResult {
    pub scanner: String,
    pub execution: Option<ScanExecution>,
    pub findings: Vec<NormalizedFinding>,
    pub error: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LanguageToolProfile {
    pub language: String,
    pub preferred_scanners: Vec<String>,
    pub categories: Vec<String>,
}
