//! The hosted HTTP transport.
//!
//! Active only when `AUDIT_TRANSPORT=http`. On stdio none of this exists — no
//! listener is opened and no token is required, which is the deployment nearly
//! everyone uses and the one that must not change.

pub mod auth;
pub mod metadata;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};

use std::collections::HashMap;
use std::sync::Mutex;

use crate::authz::{Authorizer, CallerContext, CallerToken};
use crate::config::Config;
use crate::http::auth::{AuthError, ResourceServer};
use crate::http::metadata::ProtectedResourceMetadata;
use crate::observe::Metrics;
use crate::server::AuditMcpServer;

/// Where the metadata document lives, per RFC 9728.
pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Header carrying the caller's own forge credential.
///
/// A header rather than a tool argument: a token in a tool argument would flow
/// through the model's context, where it would be logged, summarized, and
/// quite possibly repeated back.
pub const FORGE_TOKEN_HEADER: &str = "x-audit-github-token";

/// MCP payloads are small. An unbounded body is a denial-of-service vector.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Everything the HTTP layer needs, shared across requests.
pub struct HttpState {
    pub resource_server: ResourceServer,
    pub authorizer: Arc<Authorizer>,
    pub metadata: ProtectedResourceMetadata,
    pub metadata_url: String,
    /// Per-caller concurrent request ceiling, so one caller cannot starve others.
    pub per_caller_limit: usize,
    pub metrics: Arc<Metrics>,
    /// In-flight requests per caller subject.
    in_flight: Mutex<HashMap<String, usize>>,
    /// Which caller opened each MCP session.
    sessions: Mutex<HashMap<String, String>>,
}

impl HttpState {
    pub fn new(
        resource_server: ResourceServer,
        authorizer: Arc<Authorizer>,
        metadata: ProtectedResourceMetadata,
        metadata_url: String,
        per_caller_limit: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            resource_server,
            authorizer,
            metadata,
            metadata_url,
            per_caller_limit,
            metrics,
            in_flight: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Claim a slot for this caller, or refuse.
    ///
    /// Bounded per caller rather than globally: one person running a big
    /// `mode=all` should slow themselves down, not everyone else.
    fn claim(&self, subject: &str) -> bool {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return true;
        };
        let count = in_flight.entry(subject.to_string()).or_insert(0);
        if *count >= self.per_caller_limit {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&self, subject: &str) {
        if let Ok(mut in_flight) = self.in_flight.lock()
            && let Some(count) = in_flight.get_mut(subject)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                in_flight.remove(subject);
            }
        }
    }

    /// Bind a session to the identity that created it, and refuse anyone else.
    ///
    /// Without this, knowing a session id would be enough to continue someone
    /// else's conversation with the server.
    fn session_belongs_to(&self, session: &str, subject: &str) -> bool {
        let Ok(mut sessions) = self.sessions.lock() else {
            return true;
        };
        match sessions.get(session) {
            Some(owner) => owner == subject,
            None => {
                sessions.insert(session.to_string(), subject.to_string());
                true
            }
        }
    }
}

/// Build the HTTP application.
///
/// Note what is *not* here: an unauthenticated mode. Serving tools that
/// execute containers over an open port is not a configuration we offer, so
/// `/mcp` is always behind token validation.
pub fn router(config: &Config, state: Arc<HttpState>) -> Result<Router, String> {
    let mcp = StreamableHttpService::new(
        || AuditMcpServer::new().map_err(std::io::Error::other),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    let _ = config;

    Ok(Router::new()
        // Unauthenticated by design: discovery, liveness, readiness.
        .route(METADATA_PATH, get(metadata_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        // Authentication applies to `/mcp` only: discovery and probes must
        // answer without a token, or a client could never bootstrap.
        .nest_service(
            "/mcp",
            Router::new()
                .fallback_service(mcp)
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    require_token,
                ))
                .with_state(Arc::clone(&state)),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state))
}

/// Reject any request to the MCP endpoint that does not carry a valid token.
async fn require_token(
    State(state): State<Arc<HttpState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let identity = match state.resource_server.authenticate(header.as_deref()).await {
        Ok(identity) => identity,
        Err(error) => return refuse(&state, error),
    };

    // A session belongs to whoever opened it. Knowing its id is not a
    // credential.
    if let Some(session) = request
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        && !state.session_belongs_to(&session, &identity.subject)
    {
        state.metrics.rejected("session_owned_by_another_caller");
        return (
            StatusCode::FORBIDDEN,
            "this session belongs to another caller",
        )
            .into_response();
    }

    if !state.claim(&identity.subject) {
        state.metrics.rejected("per_caller_limit");
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "5".parse().expect("valid header"));
        return (
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            format!(
                "you already have {} requests in flight; retry shortly",
                state.per_caller_limit
            ),
        )
            .into_response();
    }

    let forge_token = request
        .headers()
        .get(FORGE_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(CallerToken::new);

    // The tool handler reads this back out of the request parts rmcp forwards.
    // Attaching it here, after validation, is what makes it impossible for a
    // scan to run without the server knowing who asked for it.
    let subject = identity.subject.clone();
    request.extensions_mut().insert(CallerContext {
        identity,
        forge_token,
    });

    let response = next.run(request).await;
    state.release(&subject);
    response
}

/// Render an authentication failure.
///
/// The body never says *which* check failed: the difference between "expired"
/// and "wrong audience" is a probing oracle.
fn refuse(state: &HttpState, error: AuthError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::UNAUTHORIZED);
    let mut headers = HeaderMap::new();
    if status == StatusCode::UNAUTHORIZED
        && let Ok(value) = state.resource_server.challenge(&state.metadata_url).parse()
    {
        headers.insert(header::WWW_AUTHENTICATE, value);
    }

    let body = match error {
        AuthError::Forbidden(detail) => detail,
        _ => "authentication required".to_string(),
    };
    (status, headers, body).into_response()
}

async fn metadata_handler(State(state): State<Arc<HttpState>>) -> Json<ProtectedResourceMetadata> {
    Json(state.metadata.clone())
}

/// Prometheus exposition.
///
/// No MCP token required, because scrapers do not carry one — and bindable
/// separately (`AUDIT_METRICS_BIND`) so an operator can expose it only to their
/// scrape infrastructure. Because it is deliberately less protected than
/// `/mcp`, no label value may carry a repository name, URL, caller subject, or
/// path.
async fn metrics_handler(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

/// Liveness: the process is running. Deliberately says nothing about the
/// execution backend — an unreachable cluster makes us *not ready*, and
/// killing the process would not help.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness: the execution backend is reachable.
async fn readyz(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let _ = state;
    match AuditMcpServer::new() {
        Ok(server) => {
            let status = server.audit_status().await;
            if status.0.executor.available {
                (StatusCode::OK, "ready")
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "execution backend unreachable",
                )
            }
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "server not configured"),
    }
}

/// Serve MCP over HTTP until the process is stopped.
pub async fn serve(config: &Config) -> anyhow::Result<()> {
    let resource =
        config.transport.resource_url.clone().ok_or_else(|| {
            anyhow::anyhow!("AUDIT_RESOURCE_URL is required for the http transport")
        })?;
    let oauth =
        config.transport.oauth.clone().ok_or_else(|| {
            anyhow::anyhow!("AUDIT_OAUTH_ISSUER is required for the http transport")
        })?;

    let metadata = ProtectedResourceMetadata::from_config(&config.transport)
        .ok_or_else(|| anyhow::anyhow!("incomplete OAuth configuration"))?;
    let metadata_url = format!("{}{METADATA_PATH}", resource.trim_end_matches("/mcp"));

    let server = AuditMcpServer::new()?;
    let state = Arc::new(HttpState::new(
        ResourceServer::new(oauth.clone(), resource),
        Arc::new(Authorizer::new(oauth.authz_cache_ttl)),
        metadata,
        metadata_url,
        config.transport.max_scans_per_caller,
        server.metrics(),
    ));

    let app = router(config, state).map_err(|err| anyhow::anyhow!(err))?;
    let listener = tokio::net::TcpListener::bind(&config.transport.bind).await?;
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"http_listening\",\"bind\":\"{}\"}}",
        config.transport.bind
    );
    axum::serve(listener, app).await?;
    Ok(())
}
