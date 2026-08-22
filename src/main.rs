use anyhow::Context;
use audit_mcp::server::AuditMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
