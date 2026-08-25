//! Structured logging.
//!
//! Server logs go to **stderr**, always. On the stdio transport stdout carries
//! the JSON-RPC stream, and a stray log line there corrupts the protocol —
//! the client sees a parse error rather than a log message.
//!
//! Records are emitted as single-line JSON so an operator's existing pipeline
//! can collect them. Nothing is persisted here: audit records are log lines,
//! not a database, and retention belongs to whoever runs the deployment.

use std::io::Write;

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Parse a configured level, defaulting to `info` for anything unrecognized
    /// rather than failing — a typo in a log level should not stop a server.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" | "trace" => Self::Debug,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }
}

/// Emits structured records to stderr at or above a minimum level.
#[derive(Debug, Clone)]
pub struct Logger {
    minimum: Level,
    /// When false, records are rendered as plain text instead of JSON.
    json: bool,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            minimum: Level::Info,
            json: true,
        }
    }
}

impl Logger {
    pub fn new(minimum: Level, json: bool) -> Self {
        Self { minimum, json }
    }

    pub fn from_config(config: &crate::config::ObservabilityConfig) -> Self {
        Self::new(
            Level::parse(&config.log_level),
            config.log_format.eq_ignore_ascii_case("json"),
        )
    }

    pub fn enabled(&self, level: Level) -> bool {
        level >= self.minimum
    }

    /// Render one record. Returns `None` when the level is filtered out, which
    /// is what makes this testable without capturing stderr.
    pub fn render(&self, level: Level, event: &str, fields: Value) -> Option<String> {
        if !self.enabled(level) {
            return None;
        }

        if !self.json {
            return Some(format!("{} {event} {fields}", level.as_str()));
        }

        let mut record = Map::new();
        record.insert("level".to_string(), json!(level.as_str()));
        record.insert("event".to_string(), json!(event));
        if let Value::Object(extra) = fields {
            for (key, value) in extra {
                // `level` and `event` are ours; a caller cannot overwrite them
                // and disguise one record as another.
                if key != "level" && key != "event" {
                    record.insert(key, value);
                }
            }
        }
        Some(Value::Object(record).to_string())
    }

    /// Write a record to stderr. Never stdout — see the module docs.
    pub fn log(&self, level: Level, event: &str, fields: Value) {
        if let Some(line) = self.render(level, event, fields) {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{line}");
        }
    }

    pub fn info(&self, event: &str, fields: Value) {
        self.log(Level::Info, event, fields);
    }

    pub fn warn(&self, event: &str, fields: Value) {
        self.log(Level::Warn, event, fields);
    }

    pub fn error(&self, event: &str, fields: Value) {
        self.log(Level::Error, event, fields);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_render_as_single_line_json() {
        let logger = Logger::new(Level::Info, true);
        let line = logger
            .render(Level::Info, "scan_started", json!({"scanner": "ruff"}))
            .expect("info is enabled");
        assert!(!line.contains('\n'), "a record must be one line");
        let parsed: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["level"], "info");
        assert_eq!(parsed["event"], "scan_started");
        assert_eq!(parsed["scanner"], "ruff");
    }

    #[test]
    fn levels_below_the_minimum_are_dropped() {
        let logger = Logger::new(Level::Warn, true);
        assert!(logger.render(Level::Info, "noise", json!({})).is_none());
        assert!(logger.render(Level::Error, "real", json!({})).is_some());
    }

    #[test]
    fn callers_cannot_overwrite_the_reserved_fields() {
        let logger = Logger::new(Level::Info, true);
        let line = logger
            .render(
                Level::Info,
                "real_event",
                json!({"event": "spoofed", "level": "error"}),
            )
            .expect("enabled");
        let parsed: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["event"], "real_event");
        assert_eq!(parsed["level"], "info");
    }

    #[test]
    fn an_unknown_level_defaults_to_info_rather_than_failing() {
        assert_eq!(Level::parse("chatty"), Level::Info);
        assert_eq!(Level::parse("DEBUG"), Level::Debug);
        assert_eq!(Level::parse("warning"), Level::Warn);
    }

    #[test]
    fn text_format_is_available_for_humans() {
        let logger = Logger::new(Level::Info, false);
        let line = logger
            .render(Level::Warn, "docker_unreachable", json!({}))
            .expect("enabled");
        assert!(line.starts_with("warn docker_unreachable"));
    }
}
