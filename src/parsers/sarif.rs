//! Generic SARIF 2.1.0 parser.
//!
//! This is the highest-leverage parser in the project: every scanner that can
//! emit SARIF natively (semgrep, gitleaks, hadolint, gosec, golangci-lint,
//! ruff, tfsec, terrascan, bearer, detekt, ktlint, …) is normalized here,
//! with real rule IDs, severities, locations, and help URIs.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::models::{NormalizedFinding, Severity};
use crate::parsers::{ParseContext, json::extract_payload};

/// Returns `None` when the output is not a SARIF document, so the caller can
/// distinguish "the tool reported nothing" from "the tool produced no report".
pub fn parse(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let runs = document.get("runs")?.as_array()?;

    let mut findings = Vec::new();
    for run in runs {
        let rules = index_rules(run);
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };

        for result in results {
            if is_suppressed(result) {
                continue;
            }
            findings.push(convert_result(ctx, result, &rules));
        }
    }

    Some(findings)
}

/// Build a rule-id → rule-metadata index from the SARIF tool driver, including
/// any extensions, so results can be enriched with descriptions and help URIs.
fn index_rules(run: &Value) -> HashMap<String, Value> {
    let mut index = HashMap::new();
    let tool = run.get("tool");

    let drivers = tool.and_then(|tool| tool.get("driver")).into_iter().chain(
        tool.and_then(|tool| tool.get("extensions"))
            .and_then(Value::as_array)
            .map(|extensions| extensions.iter())
            .into_iter()
            .flatten(),
    );

    for driver in drivers {
        let Some(rules) = driver.get("rules").and_then(Value::as_array) else {
            continue;
        };
        for rule in rules {
            if let Some(id) = rule.get("id").and_then(Value::as_str) {
                index.insert(id.to_string(), rule.clone());
            }
        }
    }

    index
}

/// SARIF lets a tool ship results it has already decided to suppress
/// (baselines, inline ignores). Those are not actionable findings.
fn is_suppressed(result: &Value) -> bool {
    result
        .get("suppressions")
        .and_then(Value::as_array)
        .is_some_and(|suppressions| {
            suppressions.iter().any(|suppression| {
                suppression
                    .get("status")
                    .and_then(Value::as_str)
                    .map(|status| !status.eq_ignore_ascii_case("rejected"))
                    .unwrap_or(true)
            })
        })
}

fn convert_result(
    ctx: &ParseContext<'_>,
    result: &Value,
    rules: &HashMap<String, Value>,
) -> NormalizedFinding {
    let rule_id = result
        .get("ruleId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .unwrap_or("SARIF_RESULT")
        .to_string();
    let rule = rules.get(&rule_id);

    let message = text_of(result.get("message"))
        .or_else(|| rule.and_then(|rule| text_of(rule.get("shortDescription"))))
        .unwrap_or_else(|| "Finding reported without a message.".to_string());

    let title = rule
        .and_then(|rule| text_of(rule.get("shortDescription")))
        .or_else(|| {
            rule.and_then(|rule| rule.get("name").and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_else(|| first_line(&message));

    let description = rule
        .and_then(|rule| text_of(rule.get("fullDescription")))
        .filter(|full| full != &title)
        .map(|full| format!("{message}\n\n{full}"))
        .unwrap_or_else(|| message.clone());

    let severity = severity_for(result, rule);
    let (path, line, column) = location_of(result);

    // `text_of` already falls back from `text` to `markdown`.
    let remediation = rule
        .and_then(|rule| text_of(rule.get("help")))
        .unwrap_or_else(|| {
            format!("Review rule '{rule_id}' in the scanner's documentation and update the flagged code.")
        });

    let mut references = Vec::new();
    if let Some(uri) = rule.and_then(|rule| rule.get("helpUri").and_then(Value::as_str)) {
        references.push(uri.to_string());
    }

    ctx.finding(
        &rule_id,
        severity,
        title,
        description,
        path,
        line,
        column,
        remediation,
        references,
        json!({ "result": result, "rule": rule }),
    )
}

/// Extract text from a SARIF multiformat message string (`{text, markdown}`).
fn text_of(value: Option<&Value>) -> Option<String> {
    let value = value?;
    value
        .get("text")
        .and_then(Value::as_str)
        .or_else(|| value.get("markdown").and_then(Value::as_str))
        .or_else(|| value.as_str())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or(text).trim().to_string()
}

/// SARIF severity resolution, most specific source first:
/// 1. `security-severity` CVSS score on the result or its rule
/// 2. the result's `level`
/// 3. the rule's `defaultConfiguration.level`
fn severity_for(result: &Value, rule: Option<&Value>) -> Severity {
    let security_severity = properties_of(result)
        .and_then(|props| numeric(props.get("security-severity")))
        .or_else(|| {
            rule.and_then(properties_of)
                .and_then(|props| numeric(props.get("security-severity")))
        });

    if let Some(score) = security_severity {
        return match score {
            score if score >= 9.0 => Severity::Critical,
            score if score >= 7.0 => Severity::High,
            score if score >= 4.0 => Severity::Medium,
            score if score > 0.0 => Severity::Low,
            _ => Severity::Info,
        };
    }

    // Some tools (terrascan, several SARIF converters) put a plain severity
    // word in properties instead of using `level`.
    if let Some(word) = properties_of(result)
        .and_then(|props| props.get("severity"))
        .and_then(Value::as_str)
        .or_else(|| {
            rule.and_then(properties_of)
                .and_then(|props| props.get("severity"))
                .and_then(Value::as_str)
        })
    {
        let parsed = Severity::parse(word);
        if parsed != Severity::Unknown {
            return parsed;
        }
    }

    let level = result
        .get("level")
        .and_then(Value::as_str)
        .or_else(|| {
            rule.and_then(|rule| {
                rule.get("defaultConfiguration")
                    .and_then(|config| config.get("level"))
                    .and_then(Value::as_str)
            })
        })
        // SARIF's default level when the field is absent.
        .unwrap_or("warning");

    Severity::parse(level)
}

fn properties_of(value: &Value) -> Option<&Value> {
    value.get("properties")
}

fn numeric(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<f64>().ok()))
}

/// Pull the first physical location from a result, preferring an explicit
/// region start line.
fn location_of(result: &Value) -> (Option<String>, Option<u32>, Option<u32>) {
    let Some(location) = result
        .get("locations")
        .and_then(Value::as_array)
        .and_then(|locations| locations.first())
    else {
        return (None, None, None);
    };

    let physical = location.get("physicalLocation");
    let path = physical
        .and_then(|physical| physical.get("artifactLocation"))
        .and_then(|artifact| artifact.get("uri"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let region = physical.and_then(|physical| physical.get("region"));
    let line = region
        .and_then(|region| region.get("startLine"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let column = region
        .and_then(|region| region.get("startColumn"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    (path, line, column)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::models::{OutputFormat, ScannerDefinition};
    use crate::parsers::ParseContext;

    fn scanner() -> ScannerDefinition {
        ScannerDefinition {
            name: "semgrep".to_string(),
            description: "test".to_string(),
            image: "test".to_string(),
            categories: vec!["Security (SAST)".to_string()],
            command_template: vec!["semgrep".to_string()],
            install_script: None,
            success_exit_codes: vec![0],
            output_format: OutputFormat::Sarif,
            timeout_secs: None,
        }
    }

    const SAMPLE: &str = r#"
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "semgrep",
              "rules": [
                {
                  "id": "python.lang.security.audit.exec-detected",
                  "name": "exec-detected",
                  "shortDescription": {"text": "Detected exec() usage"},
                  "fullDescription": {"text": "exec() executes arbitrary code."},
                  "help": {"text": "Avoid exec(); use explicit dispatch."},
                  "helpUri": "https://semgrep.dev/r/exec-detected",
                  "properties": {"security-severity": "8.5"}
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "python.lang.security.audit.exec-detected",
              "level": "warning",
              "message": {"text": "Detected exec() on user input"},
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {"uri": "app/handler.py"},
                    "region": {"startLine": 42, "startColumn": 9}
                  }
                }
              ]
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_sarif_results_with_rule_metadata() {
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        let findings = parse(&ctx, SAMPLE).expect("SARIF should parse");

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, "python.lang.security.audit.exec-detected");
        // security-severity 8.5 outranks the result's "warning" level.
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.title, "Detected exec() usage");
        assert_eq!(finding.location.path.as_deref(), Some("app/handler.py"));
        assert_eq!(finding.location.line, Some(42));
        assert_eq!(finding.location.column, Some(9));
        assert_eq!(finding.remediation, "Avoid exec(); use explicit dispatch.");
        assert_eq!(
            finding.references,
            vec!["https://semgrep.dev/r/exec-detected"]
        );
        assert_eq!(
            finding.fingerprint,
            "semgrep:python.lang.security.audit.exec-detected:app/handler.py:42"
        );
    }

    #[test]
    fn falls_back_to_result_level_without_security_severity() {
        let logs = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[
            {"ruleId":"R1","level":"error","message":{"text":"boom"}},
            {"ruleId":"R2","level":"note","message":{"text":"fyi"}},
            {"ruleId":"R3","message":{"text":"no level"}}
        ]}]}"#;
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        let findings = parse(&ctx, logs).expect("SARIF should parse");

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[1].severity, "info");
        // SARIF defaults an absent level to "warning".
        assert_eq!(findings[2].severity, "medium");
        assert!(findings[2].location.path.is_none());
    }

    #[test]
    fn reads_plain_severity_words_from_rule_properties() {
        // terrascan reports severity as a word under rule properties.
        let logs = r#"{"runs":[{"tool":{"driver":{"name":"terrascan","rules":[
            {"id":"AC_AWS_0214","shortDescription":{"text":"S3 versioning"},"properties":{"severity":"HIGH"}}
        ]}},"results":[{"ruleId":"AC_AWS_0214","level":"note","message":{"text":"versioning disabled"}}]}]}"#;
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        let findings = parse(&ctx, logs).expect("SARIF should parse");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn drops_suppressed_results() {
        let logs = r#"{"runs":[{"tool":{"driver":{"name":"t"}},"results":[
            {"ruleId":"R1","message":{"text":"kept"}},
            {"ruleId":"R2","message":{"text":"ignored"},"suppressions":[{"kind":"inSource","status":"accepted"}]}
        ]}]}"#;
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        let findings = parse(&ctx, logs).expect("SARIF should parse");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "R1");
    }

    #[test]
    fn returns_nothing_for_non_sarif_output() {
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        // `None`, not an empty vector: nothing here was a SARIF report, and
        // the caller must not read that as a clean scan.
        assert!(parse(&ctx, "plain text output").is_none());
        assert!(parse(&ctx, r#"{"not":"sarif"}"#).is_none());
    }

    #[test]
    fn handles_empty_sarif_run_as_clean() {
        let definition = scanner();
        let ctx = ParseContext::new(&definition, "repo");
        let findings = parse(
            &ctx,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":[]}]}"#,
        )
        .expect("an empty SARIF run is still a valid report");
        assert!(findings.is_empty());
    }
}
