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

/// The audit trail for one scan, emitted as a structured log line.
///
/// Never stored: this is a log record, not a findings database. Collection and
/// retention belong to whoever runs the deployment.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    /// Who asked, or `local` on stdio where the caller is the operator.
    pub caller: String,
    pub target: String,
    pub resolved_ref: Option<String>,
    pub scanners: Vec<String>,
    pub outcome: String,
    pub findings: usize,
    pub duration_ms: u64,
}

impl ScanRecord {
    /// Render the record. Redaction is applied even though nothing here should
    /// ever contain a secret — a target can be a URL a caller supplied, and
    /// "should never" is not a control.
    pub fn emit(&self, logger: &Logger, redactor: &crate::redact::Redactor) {
        logger.info(
            "scan",
            json!({
                "caller": self.caller,
                "target": redactor.redact(&self.target),
                "resolved_ref": self.resolved_ref,
                "scanners": self.scanners,
                "outcome": self.outcome,
                "findings": self.findings,
                "duration_ms": self.duration_ms,
            }),
        );
    }
}

/// Values that may appear as a metric label.
///
/// The metrics endpoint is deliberately less protected than the MCP endpoint,
/// so anything reaching a label is effectively public. Repository names, target
/// URLs, caller subjects, and file paths are barred — they would both publish
/// private information and explode cardinality, since each distinct value
/// creates a new time series that is never reclaimed.
pub fn is_safe_label_value(value: &str) -> bool {
    // Bounded vocabularies only: statuses, modes, scanner names, backends.
    // Anything caller-supplied fails at least one of these.
    !value.is_empty()
        && value.len() <= 64
        && !value.contains('/')
        && !value.contains(':')
        && !value.contains('.')
        && !value.contains('@')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

#[cfg(feature = "http")]
pub use metrics::Metrics;

#[cfg(feature = "http")]
mod metrics {
    use super::is_safe_label_value;
    use prometheus::{
        Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
        TextEncoder,
    };

    /// Prometheus metrics for one server.
    #[derive(Debug, Clone)]
    pub struct Metrics {
        registry: Registry,
        scans: IntCounterVec,
        scan_duration: HistogramVec,
        scanner_duration: HistogramVec,
        backend_available: IntGaugeVec,
        in_flight: IntGauge,
        rejections: IntCounterVec,
    }

    impl Default for Metrics {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Metrics {
        pub fn new() -> Self {
            let registry = Registry::new();

            let scans = IntCounterVec::new(
                Opts::new("audit_scans_total", "Scans by terminal status."),
                &["status"],
            )
            .expect("valid metric");
            let scan_duration = HistogramVec::new(
                HistogramOpts::new("audit_scan_duration_seconds", "Wall-clock time per scan."),
                &["mode"],
            )
            .expect("valid metric");
            let scanner_duration = HistogramVec::new(
                HistogramOpts::new(
                    "audit_scanner_duration_seconds",
                    "Wall-clock time per scanner run.",
                ),
                &["scanner", "status"],
            )
            .expect("valid metric");
            let backend_available = IntGaugeVec::new(
                Opts::new(
                    "audit_backend_available",
                    "1 when the execution backend was last seen reachable.",
                ),
                &["backend"],
            )
            .expect("valid metric");
            let in_flight = IntGauge::new("audit_scans_in_flight", "Scans currently executing.")
                .expect("valid metric");
            let rejections = IntCounterVec::new(
                Opts::new(
                    "audit_caller_rejections_total",
                    "Requests refused, by reason.",
                ),
                &["reason"],
            )
            .expect("valid metric");

            for collector in [
                Box::new(scans.clone()) as Box<dyn prometheus::core::Collector>,
                Box::new(scan_duration.clone()),
                Box::new(scanner_duration.clone()),
                Box::new(backend_available.clone()),
                Box::new(in_flight.clone()),
                Box::new(rejections.clone()),
            ] {
                registry.register(collector).expect("unique metric");
            }

            Self {
                registry,
                scans,
                scan_duration,
                scanner_duration,
                backend_available,
                in_flight,
                rejections,
            }
        }

        /// Reject any label value that is not from a bounded vocabulary.
        ///
        /// Silently substituting is better than publishing: a caller-supplied
        /// value here would be both a leak and an unbounded time series.
        fn label(value: &str) -> &str {
            if is_safe_label_value(value) {
                value
            } else {
                "other"
            }
        }

        pub fn scan_started(&self) {
            self.in_flight.inc();
        }

        pub fn scan_finished(&self, mode: &str, outcome: &str, duration_secs: f64) {
            self.in_flight.dec();
            self.scans.with_label_values(&[Self::label(outcome)]).inc();
            self.scan_duration
                .with_label_values(&[Self::label(mode)])
                .observe(duration_secs);
        }

        pub fn scanner_finished(&self, scanner: &str, status: &str, duration_secs: f64) {
            self.scanner_duration
                .with_label_values(&[Self::label(scanner), Self::label(status)])
                .observe(duration_secs);
        }

        pub fn backend_reachability(&self, backend: &str, available: bool) {
            self.backend_available
                .with_label_values(&[Self::label(backend)])
                .set(i64::from(available));
        }

        pub fn rejected(&self, reason: &str) {
            self.rejections
                .with_label_values(&[Self::label(reason)])
                .inc();
        }

        /// Render the exposition format.
        pub fn render(&self) -> String {
            let mut buffer = Vec::new();
            let encoder = TextEncoder::new();
            let _ = encoder.encode(&self.registry.gather(), &mut buffer);
            String::from_utf8(buffer).unwrap_or_default()
        }
    }
}

/// Without the HTTP transport there is nothing to scrape, so every call is a
/// no-op and the type costs nothing.
#[cfg(not(feature = "http"))]
#[derive(Debug, Clone, Default)]
pub struct Metrics;

#[cfg(not(feature = "http"))]
impl Metrics {
    pub fn new() -> Self {
        Self
    }
    pub fn scan_started(&self) {}
    pub fn scan_finished(&self, _mode: &str, _outcome: &str, _duration_secs: f64) {}
    pub fn scanner_finished(&self, _scanner: &str, _status: &str, _duration_secs: f64) {}
    pub fn backend_reachability(&self, _backend: &str, _available: bool) {}
    pub fn rejected(&self, _reason: &str) {}
    pub fn render(&self) -> String {
        String::new()
    }
}
