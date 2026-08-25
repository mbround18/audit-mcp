use anyhow::Context;
use audit_mcp::config::{Config, TransportKind};
use audit_mcp::server::AuditMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configuration is validated before anything starts. An unreachable
    // dependency is a runtime condition to report; an incoherent configuration
    // is refused at the door, because it would only produce confusing failures
    // later.
    let config =
        Config::from_env().map_err(|err| anyhow::anyhow!("invalid configuration: {err}"))?;

    match config.transport.kind {
        // The default, and the deployment nearly everyone uses: no listener,
        // no authentication, nothing on the network.
        TransportKind::Stdio => serve_stdio().await,
        #[cfg(feature = "http")]
        TransportKind::Http => audit_mcp::http::serve(&config).await,
        #[cfg(not(feature = "http"))]
        TransportKind::Http => Err(anyhow::anyhow!(
            "AUDIT_TRANSPORT=http requires a build with --features http"
        )),
    }
}

async fn serve_stdio() -> anyhow::Result<()> {
    let service = AuditMcpServer::new().context("failed to initialize audit MCP server")?;
    let _quit_reason = service
        .serve(stdio())
        .await
        .context("failed to start audit MCP transport")?
        .waiting()
        .await
        .context("audit MCP server exited unexpectedly")?;
    Ok(())
}
