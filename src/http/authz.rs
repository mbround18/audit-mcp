//! Authorization: not who is calling, but what they may scan.
//!
//! Authentication proves an identity. It does not entitle that identity to
//! everything this server can reach. The server may hold a GitHub App
//! installation credential with broad read access; without the check in this
//! module, anyone who could log in could point it at any repository that
//! installation reaches and receive the contents back as findings. That is a
//! textbook confused deputy, and it is what FR-031 exists to prevent.
//!
//! The rule: a caller supplies their *own* GitHub credential, we confirm with
//! it that they can read the repository, and only then does a clone proceed —
//! using their credential, so the authorization is inherent rather than
//! merely checked.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::http::auth::CallerIdentity;
use crate::workspace::target::{RemoteScheme, RemoteTarget};

/// A caller's own forge credential, presented per request.
///
/// Delivered as an HTTP header rather than a tool argument: a token in a tool
/// argument would flow through the model's context, where it would be logged,
/// summarized, and quite possibly repeated back.
#[derive(Clone, PartialEq, Eq)]
pub struct CallerToken(String);

impl CallerToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CallerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CallerToken([redacted])")
    }
}

/// The outcome of asking whether one caller may read one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Copy)]
struct CachedDecision {
    decision: Decision,
    expires_at: Instant,
}

/// Per-caller repository access checks, with a bounded cache.
#[derive(Debug)]
pub struct Authorizer {
    ttl: Duration,
    cache: RwLock<HashMap<(String, String), CachedDecision>>,
    http: reqwest::Client,
    /// Overridable so tests can exercise the logic without reaching GitHub.
    api_base: String,
}

impl Authorizer {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            cache: RwLock::new(HashMap::new()),
            http: reqwest::Client::new(),
            api_base: "https://api.github.com".to_string(),
        }
    }

    #[cfg(test)]
    pub fn with_api_base(ttl: Duration, api_base: String) -> Self {
        Self {
            api_base,
            ..Self::new(ttl)
        }
    }

    fn key(caller: &CallerIdentity, target: &RemoteTarget) -> (String, String) {
        // Keyed by caller *and* repository: a decision for one caller must
        // never apply to another.
        (
            format!("{}|{}", caller.issuer, caller.subject),
            format!("{}/{}", target.host, target.path),
        )
    }

    fn cached(&self, key: &(String, String)) -> Option<Decision> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(key)?;
        (entry.expires_at > Instant::now()).then_some(entry.decision)
    }

    fn remember(&self, key: (String, String), decision: Decision) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key,
                CachedDecision {
                    decision,
                    // Bounded, so revoked access stops working promptly rather
                    // than at the next restart.
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }
    }

    /// May this caller read this repository?
    ///
    /// Returns an error message suitable for the caller — one that does not
    /// disclose whether the repository exists, because "no such repository"
    /// and "you may not see it" are the same answer to someone probing.
    pub async fn authorize(
        &self,
        caller: &CallerIdentity,
        target: &RemoteTarget,
        token: Option<&CallerToken>,
    ) -> Result<(), String> {
        if target.scheme == RemoteScheme::Ssh {
            return Err(
                "the hosted transport authorizes GitHub repositories over https only; an ssh:// target cannot be checked against your identity"
                    .to_string(),
            );
        }
        if !target.host.eq_ignore_ascii_case("github.com") {
            return Err(format!(
                "cannot verify your access to '{}': the hosted transport only authorizes github.com targets",
                target.host
            ));
        }

        let Some(token) = token else {
            return Err(
                "this scan needs your own GitHub credential so the server can confirm you may read the repository. Supply a GitHub App installation token or a PAT in the X-Audit-Github-Token header."
                    .to_string(),
            );
        };

        let key = Self::key(caller, target);
        if let Some(decision) = self.cached(&key) {
            return match decision {
                Decision::Allowed => Ok(()),
                Decision::Denied => Err(refusal(&target.path)),
            };
        }

        let decision = self.probe(&target.path, token).await?;
        self.remember(key, decision);

        match decision {
            Decision::Allowed => Ok(()),
            Decision::Denied => Err(refusal(&target.path)),
        }
    }

    /// Ask GitHub whether this credential can see the repository.
    async fn probe(&self, path: &str, token: &CallerToken) -> Result<Decision, String> {
        let url = format!("{}/repos/{path}", self.api_base);
        let response = self
            .http
            .get(&url)
            .bearer_auth(token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "audit-mcp")
            .send()
            .await
            .map_err(|err| format!("could not verify your repository access: {err}"))?;

        match response.status().as_u16() {
            200 => Ok(Decision::Allowed),
            // GitHub answers 404 for a repository you may not see, which is
            // exactly the behaviour we mirror back to the caller.
            401 | 403 | 404 => Ok(Decision::Denied),
            other => Err(format!(
                "could not verify your repository access: GitHub answered HTTP {other}"
            )),
        }
    }
}

/// One message for "does not exist" and "you may not see it".
fn refusal(path: &str) -> String {
    format!(
        "your credential does not grant read access to '{path}'. If it exists and you can see it, check the token's scopes or installation."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(subject: &str) -> CallerIdentity {
        CallerIdentity {
            subject: subject.to_string(),
            issuer: "https://idp.example.test".to_string(),
            scopes: vec![],
        }
    }

    fn github(path: &str) -> RemoteTarget {
        RemoteTarget {
            scheme: RemoteScheme::Https,
            host: "github.com".to_string(),
            path: path.to_string(),
            url: format!("https://github.com/{path}.git"),
            reference: None,
        }
    }

    #[test]
    fn a_caller_token_does_not_print_itself() {
        let token = CallerToken::new("ghp_supersecret");
        assert!(!format!("{token:?}").contains("supersecret"));
    }

    #[tokio::test]
    async fn a_scan_without_a_caller_credential_is_refused() {
        // The server's own credential must not stand in for the caller's.
        let error = Authorizer::new(Duration::from_secs(60))
            .authorize(&caller("user-1"), &github("owner/repo"), None)
            .await
            .expect_err("must refuse");
        assert!(error.contains("X-Audit-Github-Token"));
    }

    #[tokio::test]
    async fn non_github_targets_are_refused_rather_than_assumed_authorized() {
        let mut target = github("owner/repo");
        target.host = "gitlab.example.com".to_string();

        let error = Authorizer::new(Duration::from_secs(60))
            .authorize(&caller("user-1"), &target, Some(&CallerToken::new("t")))
            .await
            .expect_err("must refuse");
        assert!(error.contains("only authorizes github.com"));
    }

    #[tokio::test]
    async fn ssh_targets_are_refused() {
        let mut target = github("owner/repo");
        target.scheme = RemoteScheme::Ssh;

        let error = Authorizer::new(Duration::from_secs(60))
            .authorize(&caller("user-1"), &target, Some(&CallerToken::new("t")))
            .await
            .expect_err("must refuse");
        assert!(error.contains("https only"));
    }

    #[test]
    fn a_decision_is_keyed_by_caller_and_repository() {
        // The property that stops one person's access being reused for another.
        let one = Authorizer::key(&caller("user-1"), &github("owner/repo"));
        let two = Authorizer::key(&caller("user-2"), &github("owner/repo"));
        let three = Authorizer::key(&caller("user-1"), &github("owner/other"));

        assert_ne!(one, two, "different callers must not share a decision");
        assert_ne!(one, three, "different repositories must not share one");
    }

    #[test]
    fn a_cached_decision_expires() {
        let authorizer = Authorizer::new(Duration::from_millis(40));
        let key = Authorizer::key(&caller("user-1"), &github("owner/repo"));

        authorizer.remember(key.clone(), Decision::Allowed);
        assert_eq!(authorizer.cached(&key), Some(Decision::Allowed));

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            authorizer.cached(&key),
            None,
            "revoked access must stop working within the TTL"
        );
    }

    #[test]
    fn a_denial_is_cached_too() {
        // Otherwise every refused attempt costs a round trip, which makes
        // probing cheap for the prober and expensive for us.
        let authorizer = Authorizer::new(Duration::from_secs(60));
        let key = Authorizer::key(&caller("user-1"), &github("owner/repo"));
        authorizer.remember(key.clone(), Decision::Denied);
        assert_eq!(authorizer.cached(&key), Some(Decision::Denied));
    }

    #[test]
    fn a_refusal_does_not_disclose_existence() {
        let message = refusal("owner/secret");
        assert!(!message.contains("does not exist"));
        assert!(!message.contains("not found"));
        // It says what to check without confirming anything.
        assert!(message.contains("scopes") || message.contains("installation"));
    }
}
