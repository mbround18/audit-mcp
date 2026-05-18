mod explain;
mod fixes;
mod models;
mod runner;
mod scanners;
mod selection;
mod server;

use anyhow::Context;
use rmcp::{ServiceExt, transport::stdio};
use server::AuditMcpServer;

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
