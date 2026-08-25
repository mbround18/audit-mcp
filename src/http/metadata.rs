//! RFC 9728 protected resource metadata.
//!
//! Served unauthenticated at `/.well-known/oauth-protected-resource`. This is
//! how a compliant MCP client discovers where to authenticate without being
//! told out of band — `rmcp`'s client-side auth module reads exactly this.

use serde::Serialize;

use crate::config::TransportConfig;

/// The document an unauthenticated client fetches to learn where to get a token.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// This server's identity. Tokens are validated against it as an audience.
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn from_config(config: &TransportConfig) -> Option<Self> {
        let resource = config.resource_url.clone()?;
        let oauth = config.oauth.as_ref()?;
        Some(Self {
            resource,
            authorization_servers: vec![oauth.issuer.clone()],
            scopes_supported: oauth
                .required_scope
                .clone()
                .map(|scope| vec![scope])
                .unwrap_or_default(),
            // Header only. A token in a query string lands in access logs and
            // proxy logs, which is a leak with no upside.
            bearer_methods_supported: vec!["header".to_string()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OAuthConfig, TransportKind};
    use std::time::Duration;

    fn transport(resource: Option<&str>, oauth: bool) -> TransportConfig {
        TransportConfig {
            kind: TransportKind::Http,
            bind: "127.0.0.1:8080".to_string(),
            resource_url: resource.map(str::to_string),
            oauth: oauth.then(|| OAuthConfig {
                issuer: "https://idp.example.test".to_string(),
                jwks_url: None,
                required_scope: Some("audit:scan".to_string()),
                authz_cache_ttl: Duration::from_secs(300),
            }),
            max_scans_per_caller: 2,
        }
    }

    #[test]
    fn the_document_names_the_resource_and_its_issuer() {
        let metadata = ProtectedResourceMetadata::from_config(&transport(
            Some("https://audit.example.test/mcp"),
            true,
        ))
        .expect("a complete configuration yields metadata");

        assert_eq!(metadata.resource, "https://audit.example.test/mcp");
        assert_eq!(metadata.authorization_servers, ["https://idp.example.test"]);
        assert_eq!(metadata.scopes_supported, ["audit:scan"]);
        assert_eq!(metadata.bearer_methods_supported, ["header"]);
    }

    #[test]
    fn tokens_are_never_advertised_in_a_query_string() {
        // They would land in access logs and proxy logs.
        let metadata = ProtectedResourceMetadata::from_config(&transport(
            Some("https://audit.example.test/mcp"),
            true,
        ))
        .expect("metadata");
        assert!(
            !metadata
                .bearer_methods_supported
                .iter()
                .any(|method| method == "query")
        );
    }

    #[test]
    fn an_incomplete_configuration_yields_no_document() {
        assert!(ProtectedResourceMetadata::from_config(&transport(None, true)).is_none());
        assert!(
            ProtectedResourceMetadata::from_config(&transport(
                Some("https://audit.example.test/mcp"),
                false
            ))
            .is_none()
        );
    }

    #[test]
    fn the_document_serializes_with_the_spec_field_names() {
        let metadata = ProtectedResourceMetadata::from_config(&transport(
            Some("https://audit.example.test/mcp"),
            true,
        ))
        .expect("metadata");
        let json = serde_json::to_string(&metadata).expect("serializes");
        assert!(json.contains("\"authorization_servers\""));
        assert!(json.contains("\"bearer_methods_supported\""));
    }
}
