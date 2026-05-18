# Copilot Instructions for `audit-mcp`

## Build, test, and lint commands

- Build/type-check: `cargo check`
- Run the MCP server (stdio transport): `cargo run`
- Run all tests: `cargo test`
- Run a single test by name: `cargo test <test_name>`
- Lint: `cargo clippy --all-targets --all-features`
- Format check: `cargo fmt --all -- --check`

## High-level architecture

- `src/main.rs` is only the process bootstrap: it creates `AuditMcpServer`, serves it over RMCP stdio transport, and waits for shutdown.
- `src/server.rs` is the MCP boundary. It defines tool request types and exposes tools via RMCP macros:
  - `list_scanners`
  - `run_scan`
  - `explain_finding`
  - `suggest_fixes`
- `src/models.rs` contains the shared contract types used across all tools (scanner definitions, normalized findings, execution metadata, fix suggestions, and selection plan). Keep cross-module payload shape changes centralized here.
- Runtime responsibilities are intentionally split:
  - `src/scanners.rs`: static scanner catalog and lookup/list APIs
  - `src/runner.rs`: docker-facing scanner execution (Bollard) and finding production
  - `src/selection.rs`: observability-phase scanner selection logic from target context/language profiles
  - `src/explain.rs`: finding explanation knowledge base
  - `src/fixes.rs`: remediation suggestion generation

## Key conventions in this repository

- Use RMCP macro routing patterns from `src/server.rs` (`#[tool_router]` + `#[tool_handler]`) and keep tool methods on `AuditMcpServer`.
- Return structured tool output with `rmcp::Json<T>` instead of plain text when the tool response has a schema.
- Keep tool input DTOs in `src/server.rs`, but keep reusable domain/result models in `src/models.rs`.
- `run_scan` must validate scanner support via `ScannerRegistry` before invoking `DockerScannerRunner`.
- Scanner command templates use `{target}` placeholder replacement in `DockerScannerRunner`; preserve this contract for new scanners.
- Keep scanner list output deterministic by sorting scanner summaries (see `ScannerRegistry::list_summaries`).
- Current scan execution is scaffold-first: Docker connectivity is verified, and normalized placeholder findings are returned until scanner-specific parser/execution paths are implemented. Extend behavior without breaking the normalized finding schema.
