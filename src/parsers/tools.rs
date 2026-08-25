//! Tool-native JSON parsers for scanners that cannot emit SARIF.
//!
//! Each parser is deliberately defensive: tools change their schemas between
//! releases, so every field access is optional and a shape we do not
//! recognize yields zero findings rather than a panic. The runner reports
//! that as `unparsed`, so a schema drift is visible instead of silent.

use serde_json::{Value, json};

use crate::models::{NormalizedFinding, Severity};
use crate::parsers::{
    ParseContext,
    json::{extract_ndjson, extract_payload, str_field, u32_field},
};

/// Scanner names with a native JSON parser in this module.
const SUPPORTED: &[&str] = &[
    "bandit",
    "cargo-audit",
    "cargo-clippy",
    "checkov",
    "credo",
    "dotnet-format",
    "eslint",
    "grype",
    "kube-linter",
    "npm-audit",
    "osv-scanner",
    "phpcs",
    "phpstan",
    "roslyn-analyzers",
    "pip-audit",
    "rubocop",
    "shellcheck",
    "standardrb",
    "staticcheck",
    "trivy-config",
];

pub fn supports(scanner: &str) -> bool {
    SUPPORTED.contains(&scanner)
}

/// Returns `None` when the output does not match the shape this parser
/// expects — the caller reports that as `unparsed` rather than as a clean
/// scan, so a tool that failed to produce a report is never mistaken for a
/// tool that found nothing.
pub fn parse(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    match ctx.scanner.name.as_str() {
        "bandit" => bandit(ctx, logs),
        "cargo-audit" => cargo_audit(ctx, logs),
        "cargo-clippy" => cargo_clippy(ctx, logs),
        "checkov" => checkov(ctx, logs),
        "credo" => credo(ctx, logs),
        // Both emit the standard MSBuild diagnostic line format.
        "dotnet-format" | "roslyn-analyzers" => msbuild(ctx, logs),
        "eslint" => eslint(ctx, logs),
        "grype" => grype(ctx, logs),
        "kube-linter" => kube_linter(ctx, logs),
        "npm-audit" => npm_audit(ctx, logs),
        "osv-scanner" => osv_scanner(ctx, logs),
        "phpcs" => phpcs(ctx, logs),
        "phpstan" => phpstan(ctx, logs),
        "pip-audit" => pip_audit(ctx, logs),
        // standard is a rubocop wrapper and emits the same report shape.
        "rubocop" | "standardrb" => rubocop(ctx, logs),
        "shellcheck" => shellcheck(ctx, logs),
        "staticcheck" => staticcheck(ctx, logs),
        "trivy-config" => trivy(ctx, logs),
        _ => None,
    }
}

/// Fetch an array field, treating a missing field as "unrecognized output".
fn require_array<'a>(value: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    value.get(key)?.as_array()
}

fn array_at<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

// ---------------------------------------------------------------- python ---

fn bandit(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let issues = require_array(&document, "results")?;

    let findings = issues
        .iter()
        .map(|issue| {
            let test_id = str_field(issue, &["test_id"]).unwrap_or("BANDIT");
            let title = str_field(issue, &["test_name"]).unwrap_or("Bandit finding");
            let message = str_field(issue, &["issue_text"]).unwrap_or("Security issue detected.");
            let confidence = str_field(issue, &["issue_confidence"]).unwrap_or("unknown");
            let mut references = Vec::new();
            if let Some(url) = str_field(issue, &["more_info"]) {
                references.push(url.to_string());
            }

            ctx.finding(
                test_id,
                Severity::parse(str_field(issue, &["issue_severity"]).unwrap_or("medium")),
                title,
                format!("{message} (confidence: {confidence})"),
                str_field(issue, &["filename"]).map(str::to_string),
                u32_field(issue, &["line_number"]),
                u32_field(issue, &["col_offset"]),
                format!("Review Bandit rule {test_id} and replace the flagged construct with a safe equivalent."),
                references,
                issue.clone(),
            )
        })
        .collect();
    Some(findings)
}

fn pip_audit(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    // pip-audit emits either a bare array or `{"dependencies": [...]}`.
    let dependencies = match document.as_array() {
        Some(items) => items.as_slice(),
        None => require_array(&document, "dependencies")?.as_slice(),
    };

    let mut findings = Vec::new();
    for dependency in dependencies {
        let name = str_field(dependency, &["name"]).unwrap_or("unknown");
        let version = str_field(dependency, &["version"]).unwrap_or("unknown");

        for vulnerability in array_at(dependency, "vulns") {
            let id = str_field(vulnerability, &["id"]).unwrap_or("PIP_AUDIT");
            let fixes = array_at(vulnerability, "fix_versions")
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let remediation = if fixes.is_empty() {
                format!(
                    "No fixed version is published yet for {name} {version}; consider replacing or pinning the dependency."
                )
            } else {
                format!("Upgrade {name} from {version} to one of: {fixes}.")
            };

            findings.push(
                ctx.finding(
                    id,
                    Severity::High,
                    format!("{id} affects {name} {version}"),
                    str_field(vulnerability, &["description"])
                        .unwrap_or("Known vulnerability in a Python dependency.")
                        .to_string(),
                    Some(format!("{name}=={version}")),
                    None,
                    None,
                    remediation,
                    vec![format!("https://osv.dev/vulnerability/{id}")],
                    vulnerability.clone(),
                ),
            );
        }
    }

    Some(findings)
}

// ------------------------------------------------------------------ node ---

fn eslint(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let files = document.as_array()?;

    let mut findings = Vec::new();
    for file in files {
        let path = str_field(file, &["filePath"]).map(str::to_string);

        for message in array_at(file, "messages") {
            let rule_id = str_field(message, &["ruleId"]).unwrap_or("eslint");
            // ESLint encodes severity numerically: 1 = warn, 2 = error.
            let severity = match message.get("severity").and_then(Value::as_u64) {
                Some(2) => Severity::High,
                Some(1) => Severity::Medium,
                _ => Severity::Info,
            };
            let text = str_field(message, &["message"]).unwrap_or("ESLint rule violation.");

            findings.push(ctx.finding(
                rule_id,
                severity,
                text.to_string(),
                text.to_string(),
                path.clone(),
                u32_field(message, &["line"]),
                u32_field(message, &["column"]),
                format!("Fix or explicitly disable ESLint rule '{rule_id}' at this location."),
                vec![format!("https://eslint.org/docs/latest/rules/{rule_id}")],
                message.clone(),
            ));
        }
    }

    Some(findings)
}

fn npm_audit(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let vulnerabilities = document.get("vulnerabilities")?.as_object()?;

    let mut findings = Vec::new();
    for (package, entry) in vulnerabilities {
        let severity = Severity::parse(str_field(entry, &["severity"]).unwrap_or("unknown"));
        let range = str_field(entry, &["range"]).unwrap_or("unknown range");

        // `via` mixes advisory objects with plain strings naming the
        // dependency path that pulled the vulnerability in.
        let advisories = array_at(entry, "via")
            .iter()
            .filter(|via| via.is_object())
            .collect::<Vec<_>>();

        let fix_available = entry
            .get("fixAvailable")
            .map(|fix| !matches!(fix, Value::Bool(false)))
            .unwrap_or(false);
        let remediation = if fix_available {
            format!("Run `npm audit fix` or upgrade '{package}' beyond {range}.")
        } else {
            format!(
                "No automatic fix is available for '{package}' ({range}); evaluate replacing the dependency."
            )
        };

        if advisories.is_empty() {
            findings.push(ctx.finding(
                package,
                severity,
                format!("Vulnerable dependency '{package}'"),
                format!("npm audit flagged '{package}' ({range}) as vulnerable via a transitive dependency."),
                Some("package-lock.json".to_string()),
                None,
                None,
                remediation.clone(),
                vec![],
                entry.clone(),
            ));
            continue;
        }

        for advisory in advisories {
            let title = str_field(advisory, &["title"]).unwrap_or("Known vulnerability");
            let id = str_field(advisory, &["url"])
                .and_then(|url| url.rsplit('/').next())
                .unwrap_or(package.as_str());
            let mut references = Vec::new();
            if let Some(url) = str_field(advisory, &["url"]) {
                references.push(url.to_string());
            }

            findings.push(ctx.finding(
                id,
                Severity::parse(str_field(advisory, &["severity"]).unwrap_or(severity.as_str())),
                format!("{title} in '{package}'"),
                format!("{title} affects '{package}' {range}."),
                Some("package-lock.json".to_string()),
                None,
                None,
                remediation.clone(),
                references,
                advisory.clone(),
            ));
        }
    }

    Some(findings)
}

// ------------------------------------------------------------------ rust ---

fn cargo_clippy(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    // `--message-format json` always emits records (compiler-artifact,
    // build-finished) even on a clean build, so an empty record set means
    // cargo never got as far as producing a report.
    let records = extract_ndjson(logs);
    if records.is_empty() {
        return None;
    }

    let findings = records
        .into_iter()
        .filter(|record| str_field(record, &["reason"]) == Some("compiler-message"))
        .filter_map(|record| {
            let message = record.get("message")?.clone();
            let level = str_field(&message, &["level"]).unwrap_or("warning");
            // Cargo also streams summary records with no real diagnostic.
            if matches!(level, "failure-note" | "note" | "help") {
                return None;
            }

            let code = message
                .get("code")
                .and_then(|code| code.get("code"))
                .and_then(Value::as_str)
                .unwrap_or("clippy")
                .to_string();
            let text = str_field(&message, &["message"])
                .unwrap_or("Clippy diagnostic")
                .to_string();

            // The primary span is the one the diagnostic points at; other
            // spans are supporting context.
            let span = array_at(&message, "spans")
                .iter()
                .find(|span| span.get("is_primary").and_then(Value::as_bool) == Some(true))
                .or_else(|| array_at(&message, "spans").first())
                .cloned();

            let suggestion = array_at(&message, "children")
                .iter()
                .filter_map(|child| str_field(child, &["message"]).map(str::to_string))
                .collect::<Vec<_>>()
                .join("; ");

            Some(
                ctx.finding(
                    &code,
                    Severity::parse(level),
                    text.clone(),
                    str_field(&message, &["rendered"])
                        .unwrap_or(&text)
                        .to_string(),
                    span.as_ref()
                        .and_then(|span| str_field(span, &["file_name"]).map(str::to_string)),
                    span.as_ref()
                        .and_then(|span| u32_field(span, &["line_start"])),
                    span.as_ref()
                        .and_then(|span| u32_field(span, &["column_start"])),
                    if suggestion.is_empty() {
                        format!(
                            "Resolve lint '{code}' or allow it explicitly with a documented reason."
                        )
                    } else {
                        suggestion
                    },
                    vec![format!(
                        "https://rust-lang.github.io/rust-clippy/master/index.html#{}",
                        code.trim_start_matches("clippy::")
                    )],
                    message,
                ),
            )
        })
        .collect();
    Some(findings)
}

fn cargo_audit(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    let list = require_array(document.get("vulnerabilities")?, "list")?;

    let findings = list
        .iter()
        .map(|entry| {
            let advisory = entry.get("advisory").cloned().unwrap_or(Value::Null);
            let id = str_field(&advisory, &["id"]).unwrap_or("RUSTSEC").to_string();
            let package = entry
                .get("package")
                .and_then(|package| str_field(package, &["name"]))
                .unwrap_or("unknown");
            let version = entry
                .get("package")
                .and_then(|package| str_field(package, &["version"]))
                .unwrap_or("unknown");
            let patched = entry
                .get("versions")
                .map(|versions| array_at(versions, "patched"))
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");

            let mut references = Vec::new();
            if let Some(url) = str_field(&advisory, &["url"]) {
                references.push(url.to_string());
            }
            references.push(format!("https://rustsec.org/advisories/{id}"));

            ctx.finding(
                &id,
                Severity::High,
                str_field(&advisory, &["title"])
                    .unwrap_or("RustSec advisory")
                    .to_string(),
                str_field(&advisory, &["description"])
                    .unwrap_or("A dependency is affected by a published advisory.")
                    .to_string(),
                Some("Cargo.lock".to_string()),
                None,
                None,
                if patched.is_empty() {
                    format!("No patched release for {package} {version}; consider replacing the dependency.")
                } else {
                    format!("Upgrade {package} from {version} to a patched version ({patched}).")
                },
                references,
                entry.clone(),
            )
        })
        .collect();
    Some(findings)
}

// -------------------------------------------------------------------- go ---

fn staticcheck(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    // Unlike cargo, staticcheck prints nothing at all when it has no
    // diagnostics, so an empty record set is a clean run rather than a
    // missing report.
    let findings = extract_ndjson(logs)
        .into_iter()
        .filter_map(|record| {
            let code = str_field(&record, &["code"])?.to_string();
            let location = record.get("location").cloned().unwrap_or(Value::Null);
            let message = str_field(&record, &["message"])
                .unwrap_or("Staticcheck diagnostic")
                .to_string();

            Some(ctx.finding(
                &code,
                Severity::parse(str_field(&record, &["severity"]).unwrap_or("warning")),
                message.clone(),
                message,
                str_field(&location, &["file"]).map(str::to_string),
                u32_field(&location, &["line"]),
                u32_field(&location, &["column"]),
                format!("Address staticcheck {code} or document an explicit ignore directive."),
                vec![format!("https://staticcheck.dev/docs/checks#{code}")],
                record,
            ))
        })
        .collect();
    Some(findings)
}

// ------------------------------------------------------------------ ruby ---

fn rubocop(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    let files = require_array(&document, "files")?;

    let mut findings = Vec::new();
    for file in files {
        let path = str_field(file, &["path"]).map(str::to_string);

        for offense in array_at(file, "offenses") {
            let cop = str_field(offense, &["cop_name"]).unwrap_or("rubocop");
            let location = offense.get("location").cloned().unwrap_or(Value::Null);
            let message = str_field(offense, &["message"]).unwrap_or("RuboCop offense");

            findings.push(ctx.finding(
                cop,
                Severity::parse(str_field(offense, &["severity"]).unwrap_or("warning")),
                message.to_string(),
                message.to_string(),
                path.clone(),
                u32_field(&location, &["start_line", "line"]),
                u32_field(&location, &["start_column", "column"]),
                format!("Fix the {cop} offense or record a deliberate exclusion in .rubocop.yml."),
                vec![],
                offense.clone(),
            ));
        }
    }

    Some(findings)
}

// ------------------------------------------------------------------- php ---

fn phpstan(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let files = document.get("files")?.as_object()?;

    let mut findings = Vec::new();
    for (path, entry) in files {
        for message in array_at(entry, "messages") {
            let identifier = str_field(message, &["identifier"]).unwrap_or("phpstan");
            let text = str_field(message, &["message"]).unwrap_or("PHPStan error");

            findings.push(ctx.finding(
                identifier,
                Severity::High,
                text.to_string(),
                text.to_string(),
                Some(path.clone()),
                u32_field(message, &["line"]),
                None,
                "Resolve the type or logic error PHPStan reported at this line.".to_string(),
                vec![],
                message.clone(),
            ));
        }
    }

    Some(findings)
}

fn phpcs(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let files = document.get("files")?.as_object()?;

    let mut findings = Vec::new();
    for (path, entry) in files {
        for message in array_at(entry, "messages") {
            // phpcs names the sniff in `source`; `type` is ERROR or WARNING.
            let sniff = str_field(message, &["source"]).unwrap_or("phpcs");
            let text = str_field(message, &["message"]).unwrap_or("Coding standard violation");

            findings.push(ctx.finding(
                sniff,
                Severity::parse(str_field(message, &["type"]).unwrap_or("warning")),
                text.to_string(),
                text.to_string(),
                Some(path.clone()),
                u32_field(message, &["line"]),
                u32_field(message, &["column"]),
                if message.get("fixable").and_then(Value::as_bool) == Some(true) {
                    format!("Fixable automatically by phpcbf, or adjust the {sniff} sniff.")
                } else {
                    format!("Update the code to satisfy the {sniff} sniff.")
                },
                vec![],
                message.clone(),
            ));
        }
    }

    Some(findings)
}

// ----------------------------------------------------------------- shell ---

fn shellcheck(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let comments = document.as_array()?;

    let findings = comments
        .iter()
        .map(|comment| {
            let code = comment
                .get("code")
                .and_then(Value::as_u64)
                .map(|code| format!("SC{code}"))
                .unwrap_or_else(|| "shellcheck".to_string());
            let message = str_field(comment, &["message"]).unwrap_or("ShellCheck diagnostic");

            ctx.finding(
                &code,
                Severity::parse(str_field(comment, &["level"]).unwrap_or("warning")),
                message.to_string(),
                message.to_string(),
                str_field(comment, &["file"]).map(str::to_string),
                u32_field(comment, &["line"]),
                u32_field(comment, &["column"]),
                format!("See https://www.shellcheck.net/wiki/{code} for the recommended rewrite."),
                vec![format!("https://www.shellcheck.net/wiki/{code}")],
                comment.clone(),
            )
        })
        .collect();
    Some(findings)
}

// ---------------------------------------------------------------- elixir ---

fn credo(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;
    let issues = require_array(&document, "issues")?;

    let findings = issues
        .iter()
        .map(|issue| {
            // credo names the check by its Elixir module path.
            let check = str_field(issue, &["check"]).unwrap_or("Credo.Check");
            let message = str_field(issue, &["message"]).unwrap_or("Credo issue");
            let category = str_field(issue, &["category"]).unwrap_or("readability");
            // credo priority runs high (positive) to low (negative).
            let severity = match issue.get("priority").and_then(Value::as_i64) {
                Some(priority) if priority >= 10 => Severity::High,
                Some(priority) if priority >= 1 => Severity::Medium,
                Some(priority) if priority >= 0 => Severity::Low,
                _ => Severity::Info,
            };

            ctx.finding(
                check,
                if category == "warning" {
                    Severity::High
                } else {
                    severity
                },
                message.to_string(),
                format!("{message} (category: {category})"),
                str_field(issue, &["filename"]).map(str::to_string),
                u32_field(issue, &["line_no"]),
                u32_field(issue, &["column"]),
                format!("Resolve the {check} issue or configure an exception in .credo.exs."),
                vec![],
                issue.clone(),
            )
        })
        .collect();
    Some(findings)
}

// ----------------------------------------------------------------- dotnet ---

/// Parse MSBuild diagnostic lines, the shared output format of `dotnet build`
/// and `dotnet format`:
///
/// ```text
/// /tmp/src/Program.cs(12,17): warning CS0219: The variable is unused [/tmp/src/App.csproj]
/// ```
fn msbuild(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let mut findings = Vec::new();
    let mut saw_msbuild_output = false;

    for line in logs.lines() {
        let line = line.trim();
        // Cheap gate before the more expensive splitting below.
        if !line.contains("): ") {
            if line.contains("Build succeeded")
                || line.contains("Format complete")
                || line.contains("Error(s)")
            {
                saw_msbuild_output = true;
            }
            continue;
        }

        let Some((location, rest)) = line.split_once("): ") else {
            continue;
        };
        let Some((path, position)) = location.rsplit_once('(') else {
            continue;
        };
        // `severity CODE: message [project]`
        let Some((level_and_code, message)) = rest.split_once(": ") else {
            continue;
        };
        let mut level_parts = level_and_code.split_whitespace();
        let Some(level) = level_parts.next() else {
            continue;
        };
        if !matches!(level, "error" | "warning" | "info") {
            continue;
        }
        let code = level_parts.next().unwrap_or("MSBUILD");

        let (line_number, column) = match position.split_once(',') {
            Some((line_text, column_text)) => (
                line_text.trim().parse::<u32>().ok(),
                column_text.trim().parse::<u32>().ok(),
            ),
            None => (position.trim().parse::<u32>().ok(), None),
        };

        // Strip the trailing `[project.csproj]` marker from the message.
        let message = message
            .rsplit_once(" [")
            .map(|(text, _)| text)
            .unwrap_or(message)
            .trim();

        saw_msbuild_output = true;
        findings.push(ctx.finding(
            code,
            Severity::parse(level),
            message.to_string(),
            message.to_string(),
            Some(path.to_string()),
            line_number,
            column,
            format!("Resolve {code}, or suppress it deliberately in .editorconfig."),
            vec![],
            json!({ "line": line, "code": code, "level": level }),
        ));
    }

    // Without any recognizable MSBuild output the tool did not get far enough
    // to report; that is not a clean build.
    saw_msbuild_output.then_some(findings)
}

// -------------------------------------------------------------- security ---

fn grype(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    let matches = require_array(&document, "matches")?;

    let findings = matches
        .iter()
        .map(|entry| {
            let vulnerability = entry.get("vulnerability").cloned().unwrap_or(Value::Null);
            let artifact = entry.get("artifact").cloned().unwrap_or(Value::Null);
            let id = str_field(&vulnerability, &["id"]).unwrap_or("GRYPE").to_string();
            let package = str_field(&artifact, &["name"]).unwrap_or("unknown");
            let version = str_field(&artifact, &["version"]).unwrap_or("unknown");

            let fixed_in = vulnerability
                .get("fix")
                .map(|fix| array_at(fix, "versions"))
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");

            let path = artifact
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|locations| locations.first())
                .and_then(|location| str_field(location, &["path"]))
                .map(str::to_string);

            let mut references = array_at(&vulnerability, "urls")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if let Some(source) = str_field(&vulnerability, &["dataSource"]) {
                references.insert(0, source.to_string());
            }

            ctx.finding(
                &id,
                Severity::parse(str_field(&vulnerability, &["severity"]).unwrap_or("unknown")),
                format!("{id} in {package} {version}"),
                str_field(&vulnerability, &["description"])
                    .unwrap_or("Known vulnerability in a resolved dependency.")
                    .to_string(),
                path,
                None,
                None,
                if fixed_in.is_empty() {
                    format!("No fixed version is known for {package} {version}; assess exposure and consider alternatives.")
                } else {
                    format!("Upgrade {package} from {version} to {fixed_in}.")
                },
                references,
                entry.clone(),
            )
        })
        .collect();
    Some(findings)
}

fn osv_scanner(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    // osv-scanner writes no JSON at all when the target has no dependency
    // manifests. That is a clean result, not a missing report.
    if logs.contains("No package sources found") {
        return Some(Vec::new());
    }

    let document = extract_payload(logs)?;

    let results = require_array(&document, "results")?;

    let mut findings = Vec::new();
    for result in results {
        let source = result
            .get("source")
            .and_then(|source| str_field(source, &["path"]))
            .map(str::to_string);

        for package_entry in array_at(result, "packages") {
            let package = package_entry.get("package").cloned().unwrap_or(Value::Null);
            let name = str_field(&package, &["name"]).unwrap_or("unknown");
            let version = str_field(&package, &["version"]).unwrap_or("unknown");

            // `groups` carries the aggregated CVSS score OSV computed for a
            // set of aliased advisory IDs.
            let severity_for = |id: &str| {
                array_at(package_entry, "groups")
                    .iter()
                    .find(|group| {
                        array_at(group, "ids")
                            .iter()
                            .any(|value| value.as_str() == Some(id))
                    })
                    .and_then(|group| str_field(group, &["max_severity"]))
                    .and_then(|score| score.parse::<f64>().ok())
                    .map(|score| match score {
                        score if score >= 9.0 => Severity::Critical,
                        score if score >= 7.0 => Severity::High,
                        score if score >= 4.0 => Severity::Medium,
                        score if score > 0.0 => Severity::Low,
                        _ => Severity::Info,
                    })
                    .unwrap_or(Severity::High)
            };

            for vulnerability in array_at(package_entry, "vulnerabilities") {
                let id = str_field(vulnerability, &["id"])
                    .unwrap_or("OSV")
                    .to_string();
                let references = array_at(vulnerability, "references")
                    .iter()
                    .filter_map(|reference| str_field(reference, &["url"]))
                    .map(str::to_string)
                    .collect::<Vec<_>>();

                findings.push(ctx.finding(
                    &id,
                    severity_for(&id),
                    format!(
                        "{id}: {}",
                        str_field(vulnerability, &["summary"]).unwrap_or("Known vulnerability")
                    ),
                    str_field(vulnerability, &["details"])
                        .or_else(|| str_field(vulnerability, &["summary"]))
                        .unwrap_or("A dependency is affected by a published advisory.")
                        .to_string(),
                    source.clone(),
                    None,
                    None,
                    format!("Upgrade {name} (currently {version}) to a release outside the affected range for {id}."),
                    references,
                    vulnerability.clone(),
                ));
            }
        }
    }

    Some(findings)
}

// ------------------------------------------------------------------- iac ---

fn checkov(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    // Checkov emits one object per framework, or an array when several
    // frameworks ran against the same target.
    let reports = document
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![document.clone()]);
    if !reports.iter().any(|report| report.get("results").is_some()) {
        return None;
    }

    let mut findings = Vec::new();
    for report in reports {
        let failed = report
            .get("results")
            .map(|results| array_at(results, "failed_checks"))
            .unwrap_or_default()
            .to_vec();

        for check in failed {
            let check_id = str_field(&check, &["check_id"]).unwrap_or("CHECKOV_UNKNOWN");
            let guideline = str_field(&check, &["guideline"]);
            let line = check
                .get("file_line_range")
                .and_then(Value::as_array)
                .and_then(|range| range.first())
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());

            let description = str_field(&check, &["description"])
                .map(str::to_string)
                .unwrap_or_else(|| {
                    str_field(
                        check.get("check_result").unwrap_or(&Value::Null),
                        &["result"],
                    )
                    .unwrap_or("Policy check failed.")
                    .to_string()
                });

            findings.push(
                ctx.finding(
                    check_id,
                    Severity::parse(str_field(&check, &["severity"]).unwrap_or("medium")),
                    str_field(&check, &["check_name"])
                        .unwrap_or("Checkov policy violation")
                        .to_string(),
                    description,
                    str_field(&check, &["file_path"])
                        .map(str::to_string)
                        .or_else(|| Some(ctx.target.to_string())),
                    line,
                    None,
                    guideline.map(str::to_string).unwrap_or_else(|| {
                        "Update the resource definition to satisfy the failed control.".to_string()
                    }),
                    guideline.into_iter().map(str::to_string).collect(),
                    check.clone(),
                ),
            );
        }
    }

    Some(findings)
}

/// Handles Trivy's `Results[]` shape for both misconfigurations and
/// vulnerabilities, so the same parser serves config and filesystem scans.
fn trivy(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    // A Trivy report with nothing to say still carries a `Results` key.
    let results = require_array(&document, "Results")?;

    let mut findings = Vec::new();
    for result in results {
        let target_path = str_field(result, &["Target"])
            .map(str::to_string)
            .unwrap_or_else(|| ctx.target.to_string());

        for issue in array_at(result, "Misconfigurations") {
            if str_field(issue, &["Status"])
                .is_some_and(|status| status.eq_ignore_ascii_case("PASS"))
            {
                continue;
            }

            let id = str_field(issue, &["ID"])
                .or_else(|| str_field(issue, &["AVDID"]))
                .unwrap_or("TRIVY_CONFIG_UNKNOWN");
            let line = issue
                .get("CauseMetadata")
                .and_then(|metadata| metadata.get("StartLine"))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());

            let mut references = Vec::new();
            if let Some(url) = str_field(issue, &["PrimaryURL"]) {
                references.push(url.to_string());
            }
            references.extend(
                array_at(issue, "References")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );

            findings.push(
                ctx.finding(
                    id,
                    Severity::parse(str_field(issue, &["Severity"]).unwrap_or("medium")),
                    str_field(issue, &["Title"])
                        .unwrap_or("Trivy configuration finding")
                        .to_string(),
                    str_field(issue, &["Description"])
                        .or_else(|| str_field(issue, &["Message"]))
                        .unwrap_or("Configuration issue detected by Trivy.")
                        .to_string(),
                    Some(target_path.clone()),
                    line,
                    None,
                    str_field(issue, &["Resolution"])
                        .unwrap_or("Update the configuration to satisfy the failed policy.")
                        .to_string(),
                    references,
                    issue.clone(),
                ),
            );
        }

        for issue in array_at(result, "Vulnerabilities") {
            let id = str_field(issue, &["VulnerabilityID"]).unwrap_or("TRIVY_VULN");
            let package = str_field(issue, &["PkgName"]).unwrap_or("unknown");
            let installed = str_field(issue, &["InstalledVersion"]).unwrap_or("unknown");
            let fixed = str_field(issue, &["FixedVersion"]);

            let mut references = Vec::new();
            if let Some(url) = str_field(issue, &["PrimaryURL"]) {
                references.push(url.to_string());
            }

            findings.push(
                ctx.finding(
                    id,
                    Severity::parse(str_field(issue, &["Severity"]).unwrap_or("unknown")),
                    format!("{id} in {package} {installed}"),
                    str_field(issue, &["Description"])
                        .or_else(|| str_field(issue, &["Title"]))
                        .unwrap_or("Known vulnerability in a dependency.")
                        .to_string(),
                    Some(target_path.clone()),
                    None,
                    None,
                    match fixed {
                        Some(version) => {
                            format!("Upgrade {package} from {installed} to {version}.")
                        }
                        None => format!("No fixed version is published for {package} {installed}."),
                    },
                    references,
                    issue.clone(),
                ),
            );
        }
    }

    Some(findings)
}

fn kube_linter(ctx: &ParseContext<'_>, logs: &str) -> Option<Vec<NormalizedFinding>> {
    let document = extract_payload(logs)?;

    // kube-linter emits `"Reports": null` when it has nothing to report, so
    // the key's presence — not its contents — is what marks a real report.
    document.get("Reports")?;
    let findings = array_at(&document, "Reports")
        .iter()
        .map(|report| {
            let check = str_field(report, &["Check"]).unwrap_or("kube-linter");
            let message = report
                .get("Diagnostic")
                .and_then(|diagnostic| str_field(diagnostic, &["Message"]))
                .unwrap_or("Kubernetes workload policy violation");

            let object = report.get("Object").cloned().unwrap_or(Value::Null);
            let path = object
                .get("Metadata")
                .and_then(|metadata| str_field(metadata, &["FilePath"]))
                .map(str::to_string);
            let name = object
                .get("K8sObject")
                .and_then(|k8s| str_field(k8s, &["Name"]))
                .unwrap_or("unknown object");

            ctx.finding(
                check,
                Severity::Medium,
                format!("{check} on {name}"),
                message.to_string(),
                path,
                None,
                None,
                str_field(report, &["Remediation"])
                    .unwrap_or("Update the workload manifest to satisfy the failed check.")
                    .to_string(),
                vec![format!(
                    "https://docs.kubelinter.io/#/generated/checks?id={check}"
                )],
                json!({ "report": report }),
            )
        })
        .collect();
    Some(findings)
}

#[cfg(test)]
mod tests {
    use super::{parse, supports};
    use crate::models::{OutputFormat, ScannerDefinition};
    use crate::parsers::ParseContext;

    fn scanner(name: &str) -> ScannerDefinition {
        ScannerDefinition {
            name: name.to_string(),
            description: "test".to_string(),
            image: "test".to_string(),
            categories: vec!["Test".to_string()],
            command_template: vec!["run".to_string()],
            install_script: None,
            success_exit_codes: vec![0],
            output_format: OutputFormat::Json,
            timeout_secs: None,
        }
    }

    fn run(name: &str, logs: &str) -> Vec<crate::models::NormalizedFinding> {
        let definition = scanner(name);
        let ctx = ParseContext::new(&definition, "repo");
        parse(&ctx, logs).expect("output should be recognized by the parser")
    }

    #[test]
    fn every_supported_scanner_has_a_dispatch_arm() {
        // Guards against adding a name to SUPPORTED without wiring the parser.
        for name in super::SUPPORTED {
            assert!(supports(name));
            let definition = scanner(name);
            let ctx = ParseContext::new(&definition, "repo");
            // Empty output is not a clean scan for tools that always emit a
            // report. `staticcheck` is the documented exception: it prints
            // nothing when it has nothing to say.
            if *name != "staticcheck" {
                assert!(
                    parse(&ctx, "").is_none(),
                    "{name} treated empty output as a parsed report"
                );
            }
        }
    }

    #[test]
    fn parses_bandit_results() {
        let logs = r#"{"results":[{"test_id":"B602","test_name":"subprocess_popen_with_shell_equals_true","issue_text":"subprocess call with shell=True identified","issue_severity":"HIGH","issue_confidence":"HIGH","filename":"/workspace/app.py","line_number":7,"col_offset":4,"more_info":"https://bandit.readthedocs.io/b602"}]}"#;
        let findings = run("bandit", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "B602");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].location.path.as_deref(), Some("app.py"));
        assert_eq!(findings[0].location.line, Some(7));
    }

    #[test]
    fn parses_shellcheck_comments() {
        let logs = r#"[{"file":"./deploy.sh","line":3,"column":6,"level":"warning","code":2086,"message":"Double quote to prevent globbing and word splitting."}]"#;
        let findings = run("shellcheck", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SC2086");
        assert_eq!(findings[0].severity, "medium");
        assert_eq!(findings[0].location.path.as_deref(), Some("deploy.sh"));
    }

    #[test]
    fn parses_eslint_numeric_severities() {
        let logs = r#"[{"filePath":"/workspace/src/a.js","messages":[
            {"ruleId":"no-unused-vars","severity":2,"message":"'x' is defined but never used.","line":1,"column":7},
            {"ruleId":"eqeqeq","severity":1,"message":"Expected '===' ","line":4,"column":9}
        ]}]"#;
        let findings = run("eslint", logs);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[1].severity, "medium");
        assert_eq!(findings[0].location.path.as_deref(), Some("src/a.js"));
    }

    #[test]
    fn parses_npm_audit_advisories_and_transitive_entries() {
        let logs = r#"{"vulnerabilities":{
            "lodash":{"name":"lodash","severity":"high","range":"<4.17.21","fixAvailable":true,
                      "via":[{"title":"Prototype Pollution","url":"https://github.com/advisories/GHSA-1234","severity":"high"}]},
            "transitive":{"name":"transitive","severity":"low","range":"*","fixAvailable":false,"via":["lodash"]}
        }}"#;
        let mut findings = run("npm-audit", logs);
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "GHSA-1234" && f.severity == "high")
        );
        let transitive = findings
            .iter()
            .find(|f| f.id == "transitive")
            .expect("entry");
        assert!(transitive.remediation.contains("No automatic fix"));
    }

    #[test]
    fn parses_clippy_ndjson_and_skips_non_diagnostics() {
        let logs = concat!(
            r#"{"reason":"compiler-artifact","target":{}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::unwrap_used"},"level":"warning","message":"used unwrap()","rendered":"warning: used unwrap()","spans":[{"file_name":"src/main.rs","line_start":10,"column_start":5,"is_primary":true}],"children":[{"level":"help","message":"use expect()"}]}}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        let findings = run("cargo-clippy", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "clippy::unwrap_used");
        assert_eq!(findings[0].location.line, Some(10));
        assert_eq!(findings[0].remediation, "use expect()");
        assert!(findings[0].references[0].ends_with("#unwrap_used"));
    }

    #[test]
    fn parses_grype_matches() {
        let logs = r#"{"matches":[{"vulnerability":{"id":"CVE-2021-1234","severity":"Critical","description":"bad","dataSource":"https://nvd.nist.gov/CVE-2021-1234","fix":{"versions":["1.2.3"]},"urls":["https://example.test"]},"artifact":{"name":"pkg","version":"1.0.0","locations":[{"path":"/workspace/go.sum"}]}}]}"#;
        let findings = run("grype", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[0].location.path.as_deref(), Some("go.sum"));
        assert!(findings[0].remediation.contains("1.2.3"));
    }

    #[test]
    fn parses_osv_groups_for_severity() {
        let logs = r#"{"results":[{"source":{"path":"/workspace/go.mod"},"packages":[{
            "package":{"name":"golang.org/x/net","version":"0.1.0"},
            "vulnerabilities":[{"id":"GHSA-aaaa","summary":"HTTP/2 issue","details":"details here","references":[{"url":"https://example.test"}]}],
            "groups":[{"ids":["GHSA-aaaa"],"max_severity":"9.8"}]
        }]}]}"#;
        let findings = run("osv-scanner", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[0].location.path.as_deref(), Some("go.mod"));
    }

    #[test]
    fn osv_reports_a_target_with_no_manifests_as_clean() {
        let definition = scanner("osv-scanner");
        let ctx = ParseContext::new(&definition, "repo");
        let parsed = parse(
            &ctx,
            "Scanning dir .\nNo package sources found, --help for usage information.",
        )
        .expect("no manifests is a clean result, not a missing report");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parses_checkov_failed_checks_in_array_form() {
        let logs = r#"[{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_20","check_name":"S3 Bucket Public Read","description":"Bucket allows public read","file_path":"/workspace/terraform/main.tf","file_line_range":[7,13],"severity":"HIGH","guideline":"https://docs.example/s3"}]}}]"#;
        let findings = run("checkov", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "CKV_AWS_20");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(
            findings[0].location.path.as_deref(),
            Some("terraform/main.tf")
        );
        assert_eq!(findings[0].location.line, Some(7));
    }

    #[test]
    fn parses_trivy_misconfigurations_and_vulnerabilities() {
        let logs = r#"{"Results":[
            {"Target":"/workspace/k8s/deploy.yaml","Misconfigurations":[
                {"ID":"KSV001","Title":"Container should not run as root","Description":"Root containers increase attack surface.","Resolution":"Set runAsNonRoot","Severity":"CRITICAL","Status":"FAIL","PrimaryURL":"https://avd.example/ksv001","CauseMetadata":{"StartLine":12}},
                {"ID":"KSV002","Title":"passing","Severity":"LOW","Status":"PASS"}
            ]},
            {"Target":"/workspace/go.sum","Vulnerabilities":[
                {"VulnerabilityID":"CVE-2020-1","PkgName":"pkg","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH","Title":"t"}
            ]}
        ]}"#;
        let findings = run("trivy-config", logs);
        assert_eq!(findings.len(), 2, "PASS status must be filtered out");
        assert_eq!(findings[0].id, "KSV001");
        assert_eq!(findings[0].location.line, Some(12));
        assert_eq!(findings[1].id, "CVE-2020-1");
        assert!(findings[1].remediation.contains("1.1"));
    }

    #[test]
    fn parses_rubocop_offenses() {
        let logs = r#"{"files":[{"path":"app/models/user.rb","offenses":[{"severity":"convention","message":"Line too long","cop_name":"Layout/LineLength","location":{"start_line":12,"start_column":81}}]}]}"#;
        let findings = run("rubocop", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "Layout/LineLength");
        assert_eq!(findings[0].location.line, Some(12));
    }

    #[test]
    fn staticcheck_silence_is_a_clean_run() {
        // staticcheck prints nothing when it finds nothing.
        let definition = scanner("staticcheck");
        let ctx = ParseContext::new(&definition, "repo");
        let parsed = parse(&ctx, "").expect("silence is a valid staticcheck result");
        assert!(parsed.is_empty());
    }

    #[test]
    fn clippy_silence_means_cargo_never_reported() {
        // cargo always emits records, so silence is a failure, not a clean run.
        let definition = scanner("cargo-clippy");
        let ctx = ParseContext::new(&definition, "repo");
        assert!(parse(&ctx, "error: could not compile").is_none());
    }

    #[test]
    fn parses_staticcheck_ndjson() {
        let logs = r#"{"code":"SA4006","severity":"error","location":{"file":"/workspace/main.go","line":9,"column":2},"message":"this value of x is never used"}"#;
        let findings = run("staticcheck", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SA4006");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].location.path.as_deref(), Some("main.go"));
    }

    #[test]
    fn parses_kube_linter_reports() {
        let logs = r#"{"Reports":[{"Check":"unset-cpu-requirements","Remediation":"Set CPU requests","Diagnostic":{"Message":"container has no cpu request"},"Object":{"Metadata":{"FilePath":"k8s/deploy.yaml"},"K8sObject":{"Name":"api"}}}]}"#;
        let findings = run("kube-linter", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "unset-cpu-requirements");
        assert!(findings[0].title.contains("api"));
    }

    #[test]
    fn parses_pip_audit_and_cargo_audit_advisories() {
        let pip = r#"{"dependencies":[{"name":"flask","version":"1.0","vulns":[{"id":"PYSEC-2021-1","description":"bad","fix_versions":["1.1"]}]}]}"#;
        let findings = run("pip-audit", pip);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].remediation.contains("1.1"));

        let cargo = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2021-0001","title":"t","description":"d","url":"https://example.test"},"package":{"name":"foo","version":"0.1.0"},"versions":{"patched":[">=0.1.2"]}}]}}"#;
        let findings = run("cargo-audit", cargo);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "RUSTSEC-2021-0001");
        assert!(findings[0].remediation.contains(">=0.1.2"));
    }

    #[test]
    fn parses_credo_issues() {
        let logs = r#"{"issues":[{"category":"readability","check":"Credo.Check.Readability.ModuleDoc","column":11,"filename":"lib/app.ex","line_no":4,"message":"Modules should have a @moduledoc tag.","priority":1,"scope":"AuditFixture.App"}]}"#;
        let findings = run("credo", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "Credo.Check.Readability.ModuleDoc");
        assert_eq!(findings[0].severity, "medium");
        assert_eq!(findings[0].location.path.as_deref(), Some("lib/app.ex"));
        assert_eq!(findings[0].location.line, Some(4));
    }

    #[test]
    fn parses_msbuild_diagnostic_lines() {
        let logs = concat!(
            "  Determining projects to restore...\n",
            "/tmp/src/Program.cs(12,17): warning CS0219: The variable 'unused' is assigned but its value is never used [/tmp/src/App.csproj]\n",
            "/tmp/src/Program.cs(15,9): error WHITESPACE: Fix whitespace formatting. Delete 4 characters. [/tmp/src/App.csproj]\n",
            "Build succeeded.\n",
        );
        let findings = run("roslyn-analyzers", logs);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "CS0219");
        assert_eq!(findings[0].severity, "medium");
        // The container-local copy prefix is mapped back to a repo path.
        assert_eq!(findings[0].location.path.as_deref(), Some("Program.cs"));
        assert_eq!(findings[0].location.line, Some(12));
        assert_eq!(findings[0].location.column, Some(17));
        // The trailing [project] marker is not part of the message.
        assert!(!findings[0].title.contains("csproj"));
        assert_eq!(findings[1].id, "WHITESPACE");
        assert_eq!(findings[1].severity, "high");
    }

    #[test]
    fn msbuild_output_that_never_ran_is_unrecognized() {
        let definition = scanner("roslyn-analyzers");
        let ctx = ParseContext::new(&definition, "repo");
        assert!(parse(&ctx, "MSBUILD : error MSB1001: Unknown switch.").is_none());
    }

    #[test]
    fn parses_phpcs_sniff_violations() {
        let logs = r#"{"totals":{"errors":1},"files":{"\/workspace\/src\/App.php":{"messages":[{"message":"Header blocks must be separated by a single blank line","source":"PSR12.Files.FileHeader.SpacingAfterTagBlock","severity":5,"fixable":true,"type":"ERROR","line":1,"column":1}]}}}"#;
        let findings = run("phpcs", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].id,
            "PSR12.Files.FileHeader.SpacingAfterTagBlock"
        );
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].location.path.as_deref(), Some("src/App.php"));
        assert!(findings[0].remediation.contains("phpcbf"));
    }

    #[test]
    fn parses_phpstan_messages() {
        let logs = r#"{"files":{"src/A.php":{"errors":1,"messages":[{"message":"Undefined variable","line":4,"identifier":"variable.undefined"}]}}}"#;
        let findings = run("phpstan", logs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "variable.undefined");
        assert_eq!(findings[0].location.line, Some(4));
    }

    #[test]
    fn unknown_scanner_is_unrecognized_rather_than_clean() {
        let definition = scanner("not-a-real-scanner");
        let ctx = ParseContext::new(&definition, "repo");
        assert!(parse(&ctx, r#"{"results":[]}"#).is_none());
        assert!(!supports("not-a-real-scanner"));
    }

    #[test]
    fn a_valid_report_with_no_findings_parses_as_empty_not_unrecognized() {
        // The distinction the runner relies on to tell `clean` from `unparsed`.
        let definition = scanner("bandit");
        let ctx = ParseContext::new(&definition, "repo");
        let parsed = parse(&ctx, r#"{"results":[],"errors":[]}"#).expect("valid empty report");
        assert!(parsed.is_empty());

        // Output that is not a bandit report at all is unrecognized.
        assert!(parse(&ctx, r#"{"something":"else"}"#).is_none());
    }
}
