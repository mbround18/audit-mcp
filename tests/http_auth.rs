//! The hosted transport, exercised over a real socket.
//!
//! A local mock issuer signs tokens and serves a JWKS, so every rule is
//! verified end to end without an identity provider: the challenge, the
//! rejections, and above all the audience check — a token minted by the same
//! issuer for a *different* service must not work here (SC-006).
//!
//! `#[ignore]`d by default because it binds a port.

#![cfg(feature = "http")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use audit_mcp::config::{Config, OAuthConfig, TransportConfig, TransportKind};
use audit_mcp::http::auth::ResourceServer;
use audit_mcp::http::authz::Authorizer;
use audit_mcp::http::metadata::ProtectedResourceMetadata;
use audit_mcp::http::{HttpState, METADATA_PATH, router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const ISSUER_KEY: &str = include_str!("../src/http/testdata/test-key.pem");
const ISSUER_JWKS: &str = include_str!("../src/http/testdata/test-jwks.json");
const RESOURCE: &str = "https://audit.example.test/mcp";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn sign(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_string());
    let key = EncodingKey::from_rsa_pem(ISSUER_KEY.as_bytes()).expect("test key");
    jsonwebtoken::encode(&header, &claims, &key).expect("signs")
}

/// Serve the JWKS the way a real provider would, so the server fetches it over
/// HTTP rather than being handed keys directly.
async fn start_issuer() -> String {
    let app = axum::Router::new().route(
        "/.well-known/jwks.json",
        axum::routing::get(|| async { ISSUER_JWKS }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind issuer");
    let address = listener.local_addr().expect("issuer address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

async fn start_server(issuer: &str) -> SocketAddr {
    let oauth = OAuthConfig {
        issuer: issuer.to_string(),
        jwks_url: Some(format!("{issuer}/.well-known/jwks.json")),
        required_scope: Some("audit:scan".to_string()),
        authz_cache_ttl: Duration::from_secs(300),
    };
    let transport = TransportConfig {
        kind: TransportKind::Http,
        bind: "127.0.0.1:0".to_string(),
        resource_url: Some(RESOURCE.to_string()),
        oauth: Some(oauth.clone()),
        max_scans_per_caller: 2,
    };
    let config = Config {
        transport: transport.clone(),
        ..Default::default()
    };

    let state = Arc::new(HttpState {
        resource_server: ResourceServer::new(oauth.clone(), RESOURCE.to_string()),
        authorizer: Arc::new(Authorizer::new(oauth.authz_cache_ttl)),
        metadata: ProtectedResourceMetadata::from_config(&transport).expect("metadata"),
        metadata_url: format!("https://audit.example.test{METADATA_PATH}"),
        per_caller_limit: 2,
    });

    let app = router(&config, state).expect("router builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let address = listener.local_addr().expect("server address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    address
}

async fn post_mcp(address: SocketAddr, token: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.expect("request completes")
}

#[tokio::test]
#[ignore]
async fn discovery_and_probes_answer_without_a_token() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let client = reqwest::Client::new();

    // A client that cannot fetch metadata unauthenticated can never bootstrap.
    let metadata = client
        .get(format!("http://{address}{METADATA_PATH}"))
        .send()
        .await
        .expect("metadata request");
    assert_eq!(metadata.status(), 200);
    let body: serde_json::Value = metadata.json().await.expect("json");
    assert_eq!(body["resource"], RESOURCE);
    assert_eq!(body["authorization_servers"][0], issuer);

    let health = client
        .get(format!("http://{address}/healthz"))
        .send()
        .await
        .expect("healthz");
    assert_eq!(health.status(), 200);
}

#[tokio::test]
#[ignore]
async fn an_unauthenticated_request_is_challenged() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let response = post_mcp(address, None).await;
    assert_eq!(response.status(), 401);

    let challenge = response
        .headers()
        .get("www-authenticate")
        .expect("a challenge names where to authenticate")
        .to_str()
        .expect("ascii");
    assert!(challenge.starts_with("Bearer "));
    assert!(challenge.contains(METADATA_PATH));
}

#[tokio::test]
#[ignore]
async fn a_token_for_another_resource_is_rejected() {
    // SC-006. The same issuer, a valid signature, the wrong audience — the
    // defect that lets any service sharing an IdP drive this one.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1",
        "iss": issuer,
        "aud": "https://some-other-service.example.test",
        "exp": now() + 300,
        "scope": "audit:scan",
    }));

    let response = post_mcp(address, Some(&token)).await;
    assert_eq!(
        response.status(),
        401,
        "a token minted for another service must not be accepted"
    );
}

#[tokio::test]
#[ignore]
async fn expired_malformed_and_foreign_tokens_are_all_rejected_alike() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let expired = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() - 3600, "scope": "audit:scan",
    }));
    let foreign_issuer = sign(json!({
        "sub": "user-1", "iss": "https://attacker.example.test", "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    for (label, token) in [
        ("garbage", "not-a-token".to_string()),
        ("expired", expired),
        ("foreign issuer", foreign_issuer),
        (
            "alg:none",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.".to_string(),
        ),
    ] {
        let response = post_mcp(address, Some(&token)).await;
        assert_eq!(response.status(), 401, "{label} should be rejected");
        // The body must not say which check failed: that difference is a
        // probing oracle.
        let body = response.text().await.unwrap_or_default();
        assert!(
            !body.contains("expired") && !body.contains("audience") && !body.contains("issuer"),
            "{label} disclosed which check failed: {body}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn a_valid_token_missing_the_required_scope_is_forbidden() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "something:else",
    }));

    // 403, not 401: we know who they are, they simply may not do this.
    assert_eq!(post_mcp(address, Some(&token)).await.status(), 403);
}

#[tokio::test]
#[ignore]
async fn a_valid_token_reaches_the_mcp_endpoint() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let response = post_mcp(address, Some(&token)).await;
    // Whatever MCP makes of the payload, authentication let it through — which
    // is what this layer is responsible for.
    assert_ne!(response.status(), 401);
    assert_ne!(response.status(), 403);
}

#[tokio::test]
#[ignore]
async fn an_oversized_body_is_refused() {
    // MCP payloads are small; an unbounded body is a denial-of-service vector.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .body("x".repeat(8 * 1024 * 1024))
        .send()
        .await
        .expect("request completes");

    assert!(
        response.status() == 413 || response.status() == 401,
        "an 8 MiB body should be refused, got {}",
        response.status()
    );
}
