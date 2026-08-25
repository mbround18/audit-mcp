//! OAuth 2.1 Resource Server: who is calling, and may they call at all.
//!
//! `rmcp` ships the *client* half of MCP authorization — it consumes a
//! `WWW-Authenticate` challenge and drives a token exchange. Validating a
//! presented token is ours to build, and it is the part that has to be right.
//!
//! The defect this module exists to prevent is audience confusion: accepting a
//! token that the same identity provider minted for a *different* service.
//! Without that check, anything sharing your IdP can drive this server.

use std::collections::HashSet;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::authz::CallerIdentity;
use crate::config::OAuthConfig;

/// Signature algorithms we will accept.
///
/// An allowlist, not a denylist: `alg: none` and the HMAC family must never be
/// reachable, because an attacker choosing the algorithm is an attacker
/// choosing whether verification means anything.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// How long a fetched JWKS is trusted before being refetched.
const JWKS_TTL: Duration = Duration::from_secs(300);

/// Why a request was refused.
///
/// The variants exist so the server can choose a status code; the *caller* is
/// told only that authentication failed, never which check failed, because
/// that difference is a probing oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No credential presented. Answered with a challenge.
    Missing,
    /// Presented but not acceptable.
    Invalid(String),
    /// Valid, but lacking the required scope.
    Forbidden(String),
}

impl AuthError {
    pub fn status(&self) -> u16 {
        match self {
            Self::Missing | Self::Invalid(_) => 401,
            Self::Forbidden(_) => 403,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Option<Vec<String>>,
}

#[derive(Debug, Default)]
struct CachedJwks {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

/// Validates bearer tokens against an identity provider's published keys.
#[derive(Debug)]
pub struct ResourceServer {
    config: OAuthConfig,
    /// This server's identity. A token whose audience is not this value is
    /// refused however well-formed it is.
    resource: String,
    jwks: RwLock<CachedJwks>,
    http: reqwest::Client,
}

impl ResourceServer {
    pub fn new(config: OAuthConfig, resource: String) -> Self {
        Self {
            config,
            resource,
            jwks: RwLock::new(CachedJwks::default()),
            http: reqwest::Client::new(),
        }
    }

    /// The `WWW-Authenticate` value sent with an unauthenticated request.
    ///
    /// It names where to find this resource's metadata, which is how a
    /// compliant MCP client bootstraps without being told out of band.
    pub fn challenge(&self, metadata_url: &str) -> String {
        format!("Bearer resource_metadata=\"{metadata_url}\"")
    }

    /// Where the provider publishes its signing keys.
    fn jwks_url(&self) -> String {
        self.config.jwks_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/jwks.json",
                self.config.issuer.trim_end_matches('/')
            )
        })
    }

    async fn keys(&self) -> Result<JwkSet, AuthError> {
        if let Ok(cache) = self.jwks.read()
            && let (Some(keys), Some(fetched)) = (&cache.keys, cache.fetched_at)
            && fetched.elapsed() < JWKS_TTL
        {
            return Ok(keys.clone());
        }

        let url = self.jwks_url();
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Invalid(format!("could not fetch JWKS: {err}")))?;
        let keys: JwkSet = response
            .json()
            .await
            .map_err(|err| AuthError::Invalid(format!("JWKS is not valid JSON: {err}")))?;

        if let Ok(mut cache) = self.jwks.write() {
            cache.keys = Some(keys.clone());
            cache.fetched_at = Some(Instant::now());
        }
        Ok(keys)
    }

    /// Validate a bearer token and produce the identity it proves.
    pub async fn authenticate(&self, header: Option<&str>) -> Result<CallerIdentity, AuthError> {
        let token = bearer_token(header).ok_or(AuthError::Missing)?;
        let keys = self.keys().await?;
        self.verify(&token, &keys)
    }

    /// The pure half, so every rule can be tested without a network.
    pub fn verify(&self, token: &str, keys: &JwkSet) -> Result<CallerIdentity, AuthError> {
        let header = decode_header(token)
            .map_err(|err| AuthError::Invalid(format!("unreadable token header: {err}")))?;

        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(AuthError::Invalid(format!(
                "algorithm {:?} is not accepted",
                header.alg
            )));
        }

        let key = match &header.kid {
            Some(kid) => keys.find(kid),
            // A single-key set needs no kid; more than one and we cannot guess.
            None => (keys.keys.len() == 1).then(|| &keys.keys[0]),
        }
        .ok_or_else(|| AuthError::Invalid("no signing key matches this token".to_string()))?;

        let decoding = DecodingKey::from_jwk(key)
            .map_err(|err| AuthError::Invalid(format!("unusable signing key: {err}")))?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        // The check this module exists for. A token minted by the same issuer
        // for another service must not work here.
        validation.set_audience(&[self.resource.as_str()]);
        validation.required_spec_claims =
            HashSet::from(["exp".to_string(), "iss".to_string(), "aud".to_string()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<Claims>(token, &decoding, &validation)
            .map_err(|err| AuthError::Invalid(format!("token rejected: {err}")))?;

        let scopes = collect_scopes(&data.claims);
        if let Some(required) = &self.config.required_scope
            && !scopes.iter().any(|scope| scope == required)
        {
            return Err(AuthError::Forbidden(format!(
                "token lacks the required scope '{required}'"
            )));
        }

        Ok(CallerIdentity {
            subject: data.claims.sub,
            issuer: data.claims.iss,
            scopes,
        })
    }
}

fn collect_scopes(claims: &Claims) -> Vec<String> {
    // Providers disagree: a space-delimited `scope` string or an `scp` array.
    if let Some(scope) = &claims.scope {
        return scope.split_whitespace().map(str::to_string).collect();
    }
    claims.scp.clone().unwrap_or_default()
}

/// Extract a bearer token, case-insensitively on the scheme.
fn bearer_token(header: Option<&str>) -> Option<String> {
    let header = header?.trim();
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
pub(crate) mod testing {
    //! A self-signed issuer, so every validation rule can be exercised without
    //! an identity provider.

    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    /// A 2048-bit RSA key generated once for tests. Not a secret: it signs
    /// nothing outside this test suite.
    pub const TEST_KEY_PEM: &str = include_str!("testdata/test-key.pem");
    pub const TEST_JWKS: &str = include_str!("testdata/test-jwks.json");

    pub fn jwks() -> JwkSet {
        serde_json::from_str(TEST_JWKS).expect("test JWKS parses")
    }

    pub fn sign(claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("test key parses");
        jsonwebtoken::encode(&header, &claims, &key).expect("signs")
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    /// A token that should pass every check.
    pub fn valid_token(issuer: &str, audience: &str) -> String {
        sign(json!({
            "sub": "user-1",
            "iss": issuer,
            "aud": audience,
            "exp": now() + 300,
            "nbf": now() - 10,
            "scope": "audit:scan",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://idp.example.test";
    const RESOURCE: &str = "https://audit.example.test/mcp";

    fn server(required_scope: Option<&str>) -> ResourceServer {
        ResourceServer::new(
            OAuthConfig {
                issuer: ISSUER.to_string(),
                jwks_url: None,
                required_scope: required_scope.map(str::to_string),
                authz_cache_ttl: Duration::from_secs(300),
            },
            RESOURCE.to_string(),
        )
    }

    #[test]
    fn a_valid_token_yields_an_identity() {
        let identity = server(None)
            .verify(&valid_token(ISSUER, RESOURCE), &jwks())
            .expect("a well-formed token for this resource is accepted");
        assert_eq!(identity.subject, "user-1");
        assert_eq!(identity.issuer, ISSUER);
        assert_eq!(identity.scopes, vec!["audit:scan"]);
    }

    #[test]
    fn a_token_for_another_resource_is_refused() {
        // SC-006, and the single most likely defect in a hand-rolled resource
        // server: the same issuer, a valid signature, the wrong audience.
        let token = valid_token(ISSUER, "https://some-other-service.example.test");
        let error = server(None)
            .verify(&token, &jwks())
            .expect_err("a token minted for another service must not work here");
        assert_eq!(error.status(), 401);
    }

    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let token = valid_token("https://attacker.example.test", RESOURCE);
        assert!(server(None).verify(&token, &jwks()).is_err());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let token = sign(json!({
            "sub": "user-1",
            "iss": ISSUER,
            "aud": RESOURCE,
            // Well past the default 60s leeway.
            "exp": now() - 3600,
        }));
        assert!(server(None).verify(&token, &jwks()).is_err());
    }

    #[test]
    fn a_not_yet_valid_token_is_refused() {
        let token = sign(json!({
            "sub": "user-1",
            "iss": ISSUER,
            "aud": RESOURCE,
            "exp": now() + 3600,
            "nbf": now() + 3600,
        }));
        assert!(server(None).verify(&token, &jwks()).is_err());
    }

    #[test]
    fn alg_none_is_refused() {
        // The classic: an attacker choosing the algorithm chooses whether
        // verification means anything.
        let unsigned = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTEifQ.";
        let error = server(None)
            .verify(unsigned, &jwks())
            .expect_err("alg:none must never be accepted");
        assert_eq!(error.status(), 401);
    }

    #[test]
    fn a_malformed_token_is_refused() {
        assert!(server(None).verify("not-a-token", &jwks()).is_err());
        assert!(server(None).verify("", &jwks()).is_err());
    }

    #[test]
    fn an_unknown_signing_key_is_refused() {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("some-other-key".to_string());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
        let token = jsonwebtoken::encode(
            &header,
            &json!({"sub": "u", "iss": ISSUER, "aud": RESOURCE, "exp": now() + 300}),
            &key,
        )
        .expect("signs");

        assert!(server(None).verify(&token, &jwks()).is_err());
    }

    #[test]
    fn a_missing_required_scope_is_forbidden_not_unauthorized() {
        // The caller is who they say they are; they simply may not do this.
        let token = sign(json!({
            "sub": "user-1",
            "iss": ISSUER,
            "aud": RESOURCE,
            "exp": now() + 300,
            "scope": "something:else",
        }));
        let error = server(Some("audit:scan"))
            .verify(&token, &jwks())
            .expect_err("must be refused");
        assert_eq!(error.status(), 403);
    }

    #[test]
    fn the_scp_array_form_is_understood() {
        // Entra issues an array where others issue a delimited string.
        let token = sign(json!({
            "sub": "user-1",
            "iss": ISSUER,
            "aud": RESOURCE,
            "exp": now() + 300,
            "scp": ["audit:scan", "other"],
        }));
        let identity = server(Some("audit:scan"))
            .verify(&token, &jwks())
            .expect("accepted");
        assert_eq!(identity.scopes.len(), 2);
    }

    #[test]
    fn bearer_tokens_are_extracted_case_insensitively() {
        assert_eq!(bearer_token(Some("Bearer abc")).as_deref(), Some("abc"));
        assert_eq!(bearer_token(Some("bearer abc")).as_deref(), Some("abc"));
        assert_eq!(bearer_token(Some("BEARER  abc ")).as_deref(), Some("abc"));
        assert!(bearer_token(Some("Basic abc")).is_none());
        assert!(bearer_token(Some("Bearer")).is_none());
        assert!(bearer_token(Some("Bearer ")).is_none());
        assert!(bearer_token(None).is_none());
    }

    #[test]
    fn the_challenge_names_where_to_find_metadata() {
        let challenge = server(None)
            .challenge("https://audit.example.test/.well-known/oauth-protected-resource");
        assert!(challenge.starts_with("Bearer "));
        assert!(challenge.contains("resource_metadata="));
        assert!(challenge.contains(".well-known/oauth-protected-resource"));
    }

    #[test]
    fn the_jwks_url_is_derived_from_the_issuer_when_not_given() {
        assert_eq!(
            server(None).jwks_url(),
            "https://idp.example.test/.well-known/jwks.json"
        );

        let explicit = ResourceServer::new(
            OAuthConfig {
                issuer: ISSUER.to_string(),
                jwks_url: Some("https://idp.example.test/keys".to_string()),
                required_scope: None,
                authz_cache_ttl: Duration::from_secs(300),
            },
            RESOURCE.to_string(),
        );
        assert_eq!(explicit.jwks_url(), "https://idp.example.test/keys");
    }
}
