//! JSON extraction helpers.
//!
//! Scanner containers routinely interleave progress logs, warnings, and
//! banners with their machine-readable report, so we cannot simply
//! `serde_json::from_str` the whole log stream.

use serde_json::Value;

/// Pull the largest parseable JSON document out of a noisy log stream.
///
/// Tries the whole buffer first, then scans for `{`/`[` starts and takes the
/// first one that yields a valid document. Starts are tried outermost-first so
/// a wrapping object wins over one of its nested members.
pub fn extract_payload(logs: &str) -> Option<Value> {
    let trimmed = logs.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Some(value);
    }

    let starts = logs
        .char_indices()
        .filter_map(|(index, ch)| match ch {
            '{' | '[' => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();

    for start in starts {
        let Some(end) = find_end(logs, start) else {
            continue;
        };

        if let Ok(value) = serde_json::from_str::<Value>(&logs[start..=end]) {
            // Ignore trivially small documents (e.g. `{}` inside a log line)
            // when there may be a richer report later in the stream.
            if is_meaningful(&value) {
                return Some(value);
            }
        }
    }

    None
}

fn is_meaningful(value: &Value) -> bool {
    match value {
        Value::Object(map) => !map.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => false,
    }
}

/// Parse newline-delimited JSON, skipping any line that is not a JSON value.
/// Used by tools that stream one record per line (cargo, staticcheck).
pub fn extract_ndjson(logs: &str) -> Vec<Value> {
    logs.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

fn find_end(input: &str, start: usize) -> Option<usize> {
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

/// Read a string field, trying several key spellings (tools disagree on case).
pub fn str_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|found| !found.is_empty())
}

/// Read an unsigned integer field as a `u32`, tolerating string encodings.
pub fn u32_field(value: &Value, keys: &[&str]) -> Option<u32> {
    keys.iter().find_map(|key| {
        let field = value.get(*key)?;
        field
            .as_u64()
            .or_else(|| field.as_str().and_then(|text| text.parse::<u64>().ok()))
            .and_then(|number| u32::try_from(number).ok())
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_ndjson, extract_payload, str_field, u32_field};
    use serde_json::json;

    #[test]
    fn extracts_payload_from_prefixed_logs() {
        let logs = "INFO scanner started\n{\"Results\": []}\n";
        assert!(extract_payload(logs).is_some());
    }

    #[test]
    fn extracts_payload_when_wrapped_in_banner_noise() {
        let logs = "banner {} \n[{\"a\":1}]\ntrailing text";
        let payload = extract_payload(logs).expect("payload");
        assert!(payload.is_array());
    }

    #[test]
    fn skips_empty_objects_in_favor_of_real_reports() {
        let logs = "{}\n{\"vulnerabilities\":{\"x\":1}}";
        let payload = extract_payload(logs).expect("payload");
        assert!(payload.get("vulnerabilities").is_some());
    }

    #[test]
    fn returns_none_without_json() {
        assert!(extract_payload("no structured output here").is_none());
    }

    #[test]
    fn parses_ndjson_lines_ignoring_noise() {
        let logs = "warning: something\n{\"a\":1}\nnot json\n{\"a\":2}\n";
        assert_eq!(extract_ndjson(logs).len(), 2);
    }

    #[test]
    fn reads_fields_with_alternate_spellings() {
        let value = json!({"Message": "hi", "line": "42"});
        assert_eq!(str_field(&value, &["message", "Message"]), Some("hi"));
        assert_eq!(u32_field(&value, &["line", "Line"]), Some(42));
        assert_eq!(str_field(&value, &["absent"]), None);
    }
}
