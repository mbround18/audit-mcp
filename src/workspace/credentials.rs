//! Choosing and minting a credential for one clone.
//!
//! Two rules govern this module. A credential's *name* is reported and its
//! *value* never is — the types below make printing a secret impossible rather
//! than merely discouraged. And a secret never travels in a URL or an argv,
//! where it would land in `.git/config`, in a process listing, and in any
//! object built from it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{CredentialConfig, GitHubAppConfig};
use crate::workspace::target::{RemoteScheme, RemoteTarget};

/// A secret that cannot be printed by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the value. Deliberately awkward to call, and easy to grep for.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// A derived Debug would print the secret the first time anyone logged a struct
// containing one. That is not a hypothetical: it is the most common way
// credentials reach logs.
impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

/// Which configured source a credential came from. Safe to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    GitHubApp,
    Token,
    SshKey,
    Anonymous,
}

impl CredentialSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHubApp => "github_app",
            Self::Token => "token",
            Self::SshKey => "ssh_key",
            Self::Anonymous => "anonymous",
        }
    }
}

/// A credential ready to be handed to `git`.
#[derive(Debug, Clone)]
pub enum Credential {
    /// An HTTP credential, supplied to git through the environment.
    HttpToken {
        source: CredentialSource,
        username: String,
        secret: Secret,
    },
    /// An SSH key, written to a private file for the duration of one clone.
    SshKey {
        secret: Secret,
        known_hosts: Option<String>,
    },
    Anonymous,
}

impl Credential {
    pub fn source(&self) -> CredentialSource {
        match self {
            Self::HttpToken { source, .. } => *source,
            Self::SshKey { .. } => CredentialSource::SshKey,
            Self::Anonymous => CredentialSource::Anonymous,
        }
    }

    /// The secret value, for registering with the redactor. Never for display.
    pub fn secret_value(&self) -> Option<&str> {
        match self {
            Self::HttpToken { secret, .. } => Some(secret.expose()),
            Self::SshKey { secret, .. } => Some(secret.expose()),
            Self::Anonymous => None,
        }
    }
}

/// Which source *would* be used for a target, without minting anything.
///
/// Precedence: GitHub App, then token, then SSH key, then anonymous — with the
/// transport narrowing the field, since an SSH key cannot authenticate an
/// HTTPS clone and a token cannot authenticate an SSH one.
pub fn select_source(config: &CredentialConfig, target: &RemoteTarget) -> CredentialSource {
    match target.scheme {
        RemoteScheme::Ssh => {
            if config.ssh_private_key.is_some() {
                CredentialSource::SshKey
            } else {
                CredentialSource::Anonymous
            }
        }
        RemoteScheme::Https => {
            // A GitHub App installation only speaks for GitHub.
            if config.github_app.is_some() && target.host.eq_ignore_ascii_case("github.com") {
                CredentialSource::GitHubApp
            } else if config.token.is_some() {
                CredentialSource::Token
            } else {
                CredentialSource::Anonymous
            }
        }
    }
}

/// Names of the sources that could authenticate this target, for an error
/// message that tells the caller what to configure — without revealing whether
/// the repository exists.
pub fn candidate_sources(target: &RemoteTarget) -> &'static [&'static str] {
    match target.scheme {
        RemoteScheme::Ssh => &["SSH_PRIVATE_KEY"],
        RemoteScheme::Https => &[
            "GITHUB_APP_ID/GITHUB_APP_PRIVATE_KEY/GITHUB_APP_INSTALLATION_ID",
            "GITHUB_TOKEN",
        ],
    }
}

/// Resolve the credential to use, minting a short-lived token where needed.
pub async fn resolve(
    config: &CredentialConfig,
    target: &RemoteTarget,
) -> Result<Credential, String> {
    match select_source(config, target) {
        CredentialSource::GitHubApp => {
            let app = config
                .github_app
                .as_ref()
                .expect("selection implies configuration");
            let token = mint_installation_token(app).await?;
            Ok(Credential::HttpToken {
                source: CredentialSource::GitHubApp,
                // GitHub's documented username for an installation token.
                username: "x-access-token".to_string(),
                secret: Secret::new(token),
            })
        }
        CredentialSource::Token => Ok(Credential::HttpToken {
            source: CredentialSource::Token,
            username: "x-access-token".to_string(),
            secret: Secret::new(
                config
                    .token
                    .clone()
                    .expect("selection implies configuration"),
            ),
        }),
        CredentialSource::SshKey => Ok(Credential::SshKey {
            secret: Secret::new(
                config
                    .ssh_private_key
                    .clone()
                    .expect("selection implies configuration"),
            ),
            known_hosts: config.ssh_known_hosts.clone(),
        }),
        CredentialSource::Anonymous => Ok(Credential::Anonymous),
    }
}

#[derive(Debug, Serialize)]
struct AppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

/// Exchange an app private key for an installation access token.
///
/// The token is fetched immediately before the clone and never refreshed into
/// a running scan. Installation tokens last an hour and a scan can outrun one;
/// since the workspace is cloned once up front and scanners only read it, that
/// is safe — but it constrains any future design that re-fetches mid-scan.
async fn mint_installation_token(app: &GitHubAppConfig) -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("system clock is before the epoch: {err}"))?
        .as_secs();

    let claims = AppClaims {
        // Backdated by a minute to tolerate mild clock skew, which GitHub
        // rejects outright.
        iat: now.saturating_sub(60),
        // GitHub refuses app JWTs valid for more than ten minutes.
        exp: now + 540,
        iss: app.app_id.clone(),
    };

    let key = jsonwebtoken::EncodingKey::from_rsa_pem(app.private_key.as_bytes())
        .map_err(|err| format!("GITHUB_APP_PRIVATE_KEY is not a valid RSA PEM key: {err}"))?;
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|err| format!("failed to sign the GitHub App assertion: {err}"))?;

    let url = format!(
        "https://api.github.com/app/installations/{}/access_tokens",
        app.installation_id
    );
    let response = reqwest::Client::new()
        .post(&url)
        .bearer_auth(assertion)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "audit-mcp")
        .send()
        .await
        .map_err(|err| format!("GitHub App token exchange failed: {err}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        // The body can echo request detail; report the status only.
        return Err(format!(
            "GitHub App token exchange was refused with HTTP {status}. Check the app id, installation id, and private key."
        ));
    }

    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("token")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| "GitHub App token exchange returned no token".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::target::{RemoteScheme, RemoteTarget};

    fn https(host: &str) -> RemoteTarget {
        RemoteTarget {
            scheme: RemoteScheme::Https,
            host: host.to_string(),
            path: "owner/repo".to_string(),
            url: format!("https://{host}/owner/repo.git"),
            reference: None,
        }
    }

    fn ssh() -> RemoteTarget {
        RemoteTarget {
            scheme: RemoteScheme::Ssh,
            host: "github.com".to_string(),
            path: "owner/repo".to_string(),
            url: "ssh://git@github.com/owner/repo.git".to_string(),
            reference: None,
        }
    }

    fn config(app: bool, token: bool, ssh_key: bool) -> CredentialConfig {
        CredentialConfig {
            github_app: app.then(|| GitHubAppConfig {
                app_id: "1".to_string(),
                private_key: "key".to_string(),
                installation_id: "2".to_string(),
            }),
            token: token.then(|| "ghp_token".to_string()),
            ssh_private_key: ssh_key.then(|| "-----BEGIN KEY-----".to_string()),
            ssh_known_hosts: None,
        }
    }

    #[test]
    fn a_secret_never_renders_its_value() {
        // The single most important property in this module.
        let secret = Secret::new("ghp_supersecret");
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(format!("{secret}"), "[redacted]");
        assert!(!format!("{secret:?}").contains("supersecret"));

        // And it survives being nested in another struct's derived Debug.
        let credential = Credential::HttpToken {
            source: CredentialSource::Token,
            username: "x-access-token".to_string(),
            secret,
        };
        assert!(!format!("{credential:?}").contains("supersecret"));
    }

    #[test]
    fn precedence_is_app_then_token_then_anonymous_for_https() {
        assert_eq!(
            select_source(&config(true, true, true), &https("github.com")),
            CredentialSource::GitHubApp
        );
        assert_eq!(
            select_source(&config(false, true, true), &https("github.com")),
            CredentialSource::Token
        );
        assert_eq!(
            select_source(&config(false, false, true), &https("github.com")),
            CredentialSource::Anonymous
        );
    }

    #[test]
    fn a_github_app_does_not_speak_for_other_hosts() {
        // An installation token is scoped to GitHub; sending it elsewhere would
        // hand a GitHub credential to an unrelated server.
        assert_eq!(
            select_source(&config(true, true, false), &https("gitlab.example.com")),
            CredentialSource::Token
        );
        assert_eq!(
            select_source(&config(true, false, false), &https("gitlab.example.com")),
            CredentialSource::Anonymous
        );
    }

    #[test]
    fn ssh_targets_only_consider_ssh_keys() {
        // A token cannot authenticate an SSH clone, so having one is irrelevant.
        assert_eq!(
            select_source(&config(true, true, false), &ssh()),
            CredentialSource::Anonymous
        );
        assert_eq!(
            select_source(&config(false, false, true), &ssh()),
            CredentialSource::SshKey
        );
    }

    #[tokio::test]
    async fn anonymous_resolution_needs_no_network() {
        let credential = resolve(&config(false, false, false), &https("github.com"))
            .await
            .expect("anonymous always resolves");
        assert_eq!(credential.source(), CredentialSource::Anonymous);
        assert!(credential.secret_value().is_none());
    }

    #[tokio::test]
    async fn a_configured_token_is_used_verbatim() {
        let credential = resolve(&config(false, true, false), &https("github.com"))
            .await
            .expect("token resolves without network");
        assert_eq!(credential.source(), CredentialSource::Token);
        assert_eq!(credential.secret_value(), Some("ghp_token"));
    }

    #[test]
    fn candidate_sources_name_what_to_configure() {
        assert_eq!(candidate_sources(&ssh()), &["SSH_PRIVATE_KEY"]);
        assert!(
            candidate_sources(&https("github.com"))
                .iter()
                .any(|name| name.contains("GITHUB_TOKEN"))
        );
    }
}
