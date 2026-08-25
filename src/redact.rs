//! Secret redaction at the response boundary.
//!
//! Scanner output is arbitrary text from third-party tools, any of which may
//! echo an environment variable or a remote URL. Discipline alone cannot keep
//! credentials out of a response, so every captured string passes through here
//! before it can be serialized.
//!
//! This is defence in depth, not a licence. The primary control remains never
//! putting a credential somewhere it can be read — no secrets in remote URLs,
//! no secrets in Kubernetes object specs. Anyone tempted to route a credential
//! somewhere new "because redaction will catch it" is misreading this module.

use std::sync::{Arc, RwLock};

/// What replaces a secret in redacted output.
pub const PLACEHOLDER: &str = "[REDACTED]";

/// Secrets shorter than this are ignored.
///
/// A one- or two-character "secret" would match constantly and turn every
/// response into placeholders, which destroys the diagnostic value of logs
/// without protecting anything worth protecting.
const MIN_SECRET_LEN: usize = 6;

/// A set of secret values to strip from anything leaving the process.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Arc<RwLock<Vec<String>>>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a secret. Short and empty values are ignored deliberately.
    pub fn register(&self, secret: impl AsRef<str>) {
        let secret = secret.as_ref();
        if secret.chars().count() < MIN_SECRET_LEN {
            return;
        }
        let Ok(mut secrets) = self.secrets.write() else {
            return;
        };
        if !secrets.iter().any(|known| known == secret) {
            secrets.push(secret.to_string());
            // Longest first, so a secret that contains another is replaced
            // whole rather than being partly rewritten by its own substring.
            secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        }
    }

    /// Forget every registered secret. Called when a workspace is released.
    pub fn clear(&self) {
        if let Ok(mut secrets) = self.secrets.write() {
            secrets.clear();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets
            .read()
            .map(|secrets| secrets.is_empty())
            .unwrap_or(true)
    }

    /// Replace every registered secret in `text`.
    pub fn redact(&self, text: &str) -> String {
        let Ok(secrets) = self.secrets.read() else {
            // A poisoned lock must not become a leak: without the secret list
            // we cannot redact, so we refuse to emit the text at all.
            return PLACEHOLDER.to_string();
        };
        if secrets.is_empty() {
            return text.to_string();
        }

        let mut out = text.to_string();
        for secret in secrets.iter() {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), PLACEHOLDER);
            }
        }
        out
    }

    /// Redact, then truncate — in that order, always.
    ///
    /// Truncating first can cut a secret in half, and half a credential in a
    /// response is still a leak of half a credential. Redacting first means
    /// the placeholder is what gets cut.
    pub fn redact_and_trim(&self, text: &str, max_chars: usize) -> String {
        let redacted = self.redact(text);
        if redacted.chars().count() <= max_chars {
            return redacted;
        }
        let head: String = redacted.chars().take(max_chars).collect();
        format!("{head}\n… output truncated at {max_chars} characters …")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_registry_is_a_no_op() {
        let redactor = Redactor::new();
        assert!(redactor.is_empty());
        assert_eq!(redactor.redact("nothing to hide"), "nothing to hide");
    }

    #[test]
    fn registered_secrets_are_replaced() {
        let redactor = Redactor::new();
        redactor.register("ghp_supersecrettoken");
        let out = redactor.redact("cloning with ghp_supersecrettoken now");
        assert!(!out.contains("ghp_supersecrettoken"));
        assert!(out.contains(PLACEHOLDER));
    }

    #[test]
    fn overlapping_secrets_are_replaced_longest_first() {
        // If the shorter secret were applied first it would rewrite part of the
        // longer one, leaving the remainder visible.
        let redactor = Redactor::new();
        redactor.register("secret-value");
        redactor.register("secret-value-extended");
        let out = redactor.redact("token=secret-value-extended end");
        assert!(!out.contains("secret-value"));
        assert!(!out.contains("extended"));
    }

    #[test]
    fn redaction_happens_before_truncation() {
        // The failure this ordering prevents: truncating mid-secret leaves half
        // a credential in the response.
        let redactor = Redactor::new();
        redactor.register("ghp_supersecrettoken");
        let text = format!("{}ghp_supersecrettoken", "x".repeat(20));
        let out = redactor.redact_and_trim(&text, 25);
        assert!(!out.contains("ghp_"));
        assert!(out.contains("truncated"));
    }

    #[test]
    fn short_values_are_ignored() {
        // Registering "a" would redact every response into uselessness.
        let redactor = Redactor::new();
        redactor.register("abc");
        redactor.register("");
        assert!(redactor.is_empty());
        assert_eq!(redactor.redact("abc def"), "abc def");
    }

    #[test]
    fn clearing_forgets_every_secret() {
        let redactor = Redactor::new();
        redactor.register("ghp_supersecrettoken");
        redactor.clear();
        assert!(redactor.is_empty());
        assert_eq!(
            redactor.redact("ghp_supersecrettoken"),
            "ghp_supersecrettoken"
        );
    }

    #[test]
    fn a_clone_shares_the_same_registry() {
        // The runner and the server hold separate handles to one registry.
        let redactor = Redactor::new();
        let handle = redactor.clone();
        handle.register("ghp_supersecrettoken");
        assert!(!redactor.is_empty());
        assert!(!redactor.redact("ghp_supersecrettoken").contains("ghp_"));
    }

    #[test]
    fn trimming_without_secrets_still_bounds_output() {
        let redactor = Redactor::new();
        let out = redactor.redact_and_trim(&"y".repeat(100), 10);
        assert!(out.starts_with(&"y".repeat(10)));
        assert!(out.contains("truncated"));
        assert_eq!(redactor.redact_and_trim("short", 10), "short");
    }
}
