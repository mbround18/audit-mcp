# Architecture

## Overview

`audit-mcp` is a single Rust binary that speaks the [Model Context Protocol](https://modelcontextprotocol.io/) over stdio. It exposes five tools to any MCP-compatible client and executes all scanner work inside ephemeral Docker containers.

`src/lib.rs` re-exports every module as the `audit_mcp` library crate; `src/main.rs` is a thin binary entry point on top of it. The library target exists so `tests/e2e_scan.rs` can drive `AuditMcpServer`'s real tool methods directly instead of talking to a spawned process over stdio.

```mermaid
flowchart TD
    SRC["src/"] --> MAIN["main.rs<br/>bootstrap: creates AuditMcpServer, serves over stdio"]
    SRC --> SERVER["server.rs<br/>MCP boundary: tool definitions, request routing"]
    SRC --> MODELS["models.rs<br/>shared data contract (findings, scanner definitions, etc.)"]
    SRC --> SCANNERS["scanners.rs<br/>static scanner catalog and registry"]
    SRC --> RUNNER["runner.rs<br/>normalization, status rules, exit-code policy"]
    SRC --> EXECUTOR["executor/<br/>pluggable backends: docker, kubernetes"]
    SRC --> WORKSPACE["workspace/<br/>target parsing, credentials, cloning, cleanup"]
    SRC --> PARSERS["parsers/<br/>SARIF + tool-native JSON normalization"]
    SRC --> CONFIG["config.rs<br/>configuration + startup validation"]
    SRC --> REDACT["redact.rs<br/>secret redaction at the response boundary"]
    SRC --> SELECTION["selection.rs<br/>language-based scanner auto-selection"]
    SRC --> EXPLAIN["explain.rs<br/>finding explanation knowledge base"]
    SRC --> FIXES["fixes.rs<br/>remediation suggestion generation"]
```

## Module responsibilities

### `main.rs`

Process entry point only. Creates an `AuditMcpServer`, wraps it in the RMCP stdio transport, and blocks until the client disconnects.

### `server.rs`

The MCP surface. Defines tool request/response DTOs and wires them to handler methods via the `#[tool_router]` and `#[tool_handler]` RMCP macros. Nothing in this file touches Docker or filesystem.

Tools:

- `list_scanners` — delegates to `ScannerRegistry::list_summaries`; reports which scanners are normalized and which need credentials
- `audit_status` — reports Docker reachability and catalog normalization coverage; answers even with no daemon running
- `run_scan` — validates the request, resolves the scanner set, preflights Docker once, then fans out under a concurrency semaphore
- `explain_finding` — delegates to `FindingExplainer`
- `suggest_fixes` — delegates to `FixEngine`

`shape_results` (also in this file) owns everything that shapes the response: per-scanner fingerprint dedup, `min_severity` filtering, severity-descending sort, a global `max_findings` cap that spends its budget on the most severe findings first, and the `ScanSummary` rollup. It takes plain data and is fully unit-tested without Docker.

### `models.rs`

The shared data contract. All cross-module payload types live here:

- `ScannerDefinition` — name, image, command template, optional install script, `success_exit_codes`, `output_format`, `timeout_secs`
- `RunStatus` — `clean` / `findings` / `unparsed` / `tool_error` / `timeout` / `skipped`; the distinction between "found nothing" and "could not run"
- `Severity` — ordered ladder (`unknown` < `info` < `low` < `medium` < `high` < `critical`) with parsing for the synonyms different tools use
- `ScanSummary` — severity rollup and per-status scanner counts
- `NormalizedFinding` — scanner-agnostic finding shape with severity, location, fingerprint, and raw output
- `ScanExecution` — execution metadata attached to a completed scan
- `ToolSelectionPlan` — which scanners were chosen and why
- `RunScanResponse` — full response envelope

Changes to the finding shape should be made here first.

### `scanners.rs`

A static in-memory catalog of all supported scanners. `ScannerRegistry` is built at startup from hardcoded `ScannerDefinition` entries and validates that every entry has a non-empty image and command template before the server begins accepting requests.

Entries are written with a fluent `Builder` so each states only what differs from the defaults (exit codes `[0]`, text output, the default timeout): `python("ruff", …).sarif().exits(&[0, 1]).build()`.

`validate_container_guards` runs at startup and rejects a catalog that has an empty image, an empty command template, no success exit codes, or a `Json` output format with no matching parser in `parsers::tools` — so a structured format can never silently degrade to raw logs.

### `runner.rs`

The Docker layer. `DockerScannerRunner` owns a `bollard::Docker` client and is responsible for:

1. Connecting to the daemon **lazily** (`tokio::sync::OnceCell`), so the MCP server starts with no Docker present and picks up a daemon that appears later; failures are not cached
2. Skipping (not failing) a scanner whose required credentials are absent
3. Resolving the target — a directory is mounted as-is, a **file** target mounts its parent and scopes the command to that one file
4. Pulling the scanner image if absent
5. Creating, starting, and waiting for the container under a wall-clock timeout
6. Reading logs and handing the **full** buffer to `parsers`
7. Cleaning up the container regardless of outcome

**Exit-code policy.** Each scanner declares `success_exit_codes`. An exit outside that set is a `tool_error` carrying the logs — unless the tool nonetheless produced parseable findings, in which case the run is trusted. That keeps an unusual exit code from discarding a useful scan while still surfacing genuine crashes.

**Timeouts.** The wait is wrapped in `tokio::time::timeout`. On expiry the container is `SIGKILL`ed, its logs are collected (so partial work is still visible), and the run is reported as `timeout` — never as a hang.

**Entrypoint.** Every container is created with `entrypoint: []`. Most scanner images set the tool itself as the ENTRYPOINT, which would otherwise swallow the command template — `gitleaks` plus `["gitleaks","detect"]` becomes `gitleaks gitleaks detect`, and `["sh","-c",…]` is passed to the tool as arguments. Clearing it means a command template always means exactly what it says, on every image.

**Security constraints applied to every container:**

| Constraint      | Value                    | Reason                         |
| --------------- | ------------------------ | ------------------------------ |
| Workspace mount | `:ro`                    | Scanner cannot modify source   |
| `SecurityOpt`   | `no-new-privileges:true` | Blocks setuid/sudo escalation  |
| `CapDrop`       | `ALL`                    | Removes all Linux capabilities |
| `CapAdd`        | `DAC_READ_SEARCH`        | Read-only exception, see below |
| `Memory`        | 4 GB                     | Bounds compiler memory usage   |
| Concurrency     | 4 containers (default)   | 4 GB each; unbounded fan-out OOMs the host |

Dropping every capability has two consequences worth knowing about, because both look like unrelated scanner bugs:

- Root in the container cannot **write** to apt's `_apt`-owned cache directories. The `APT` install prefix in `scanners.rs` relocates apt's archive and list directories under `/tmp` rather than relaxing the sandbox.
- Root in the container cannot **read** a host directory with mode `0700` — a build output or cache directory is enough to fail a whole scan with "permission denied", which is how `govulncheck` died on a real repository containing a `dist/` directory. `DAC_READ_SEARCH` is added back for exactly this: it bypasses read permission checks and nothing else. It grants no write access (the mount is read-only) and no path to privilege escalation, and it only lets a scanner read the tree the caller explicitly pointed it at.

**Cache volumes** are named Docker volumes mounted at `/cache/*` inside the container. Environment variables (`CARGO_HOME`, `UV_CACHE_DIR`, `GEM_HOME`, etc.) redirect each ecosystem's tooling to those paths. This means package downloads and compiled artifacts persist across runs without any host filesystem exposure.

Per-scanner target volumes (`audit-target-<scanner>`) prevent concurrent scanners from writing conflicting build artifacts into a shared directory.

**Bollard quirk:** Docker's wait API surfaces non-zero container exits as `Err(DockerContainerWaitError { code, .. })` rather than `Ok(WaitContainerResponse { status_code })`. The runner intercepts this variant and converts it to a synthetic response so the exit code is handled uniformly.

### `selection.rs`

`ToolSelector` maps a target to a set of scanner names via per-language profiles. Used only when `mode=all` is requested. The selected set is intersected with the live registry so deleted or renamed scanners never appear in results.

Detection reads the target's **contents**, not its path string:

- **Directory** — `detect_languages` walks it breadth-first, bounded to depth 4 and 20 000 entries, skipping dependency and build directories (`node_modules`, `target`, `vendor`, `.venv`, …). Every manifest (`Cargo.toml`, `go.mod`, `package.json`, …) and source extension it finds contributes a language, so a polyglot repository selects every relevant profile at once. The files that drove the decision are returned as `evidence`.
- **File** — classified by its own name.
- **Neither** (a path not present on this host) — falls back to the legacy `infer_language` path-string heuristic, and says so in the plan's `rationale`.

The `security` profile is cross-language and is always unioned in. `lighthouse` and `bundlephobia` are deliberately excluded from auto-selection: they take a URL or package name, not a repository path.

### `executor/`

The seam that makes remote execution possible without forking the pipeline. An
`Executor` runs one scanner against one prepared workspace and returns raw
output, an exit code, and a duration — **no status and no findings**. That
omission is the design: if each backend decided its own statuses, "clean" would
come to mean something subtly different in each one.

- `executor/docker.rs` — local containers. Restores `DAC_READ_SEARCH` because a
  host bind mount can expose directories with foreign ownership.
- `executor/kubernetes.rs` — one `batch/v1` Job per scanner, behind the
  `kubernetes` feature. Drops all capabilities and adds none: an `emptyDir`
  written by our own initContainer has ownership we control, so the Docker
  path's exception does not apply here.

Two things the Kubernetes backend has to work around, both discovered by
running it rather than by reading docs:

- **Pod logs are merged.** `pods/log` returns one buffer, the same condition
  that corrupted gosec's SARIF locally. Where a command runs through a shell,
  stderr is redirected to a file and replayed after a marker so parsers still
  see clean stdout. A distroless image has no shell to wrap with, so its
  streams stay merged.
- **Listing is not an availability check.** The API server answers happily for
  a namespace that does not exist. Availability is a dry-run Job create, which
  asks the question that matters — may we create a Job *here*? — and validates
  namespace and RBAC without creating anything.

### `workspace/`

What a scan actually runs against: a caller's local path, used as-is and never
modified, or a repository cloned to a directory this process owns and must
delete.

- `workspace/target.rs` — parses local paths, HTTPS and SSH URLs, and
  `owner/repo`. Parsing is side-effect free, so it is exhaustively testable;
  address *classification* is separated from resolution for the same reason. An
  existing local path always wins, which is what guarantees no current caller's
  target changes meaning.
- `workspace/credentials.rs` — GitHub App, token, SSH key, anonymous. `Secret`
  cannot be printed: a derived `Debug` would leak it the first time anyone
  logged a struct containing one.
- `workspace/clone.rs` — invokes `git`. No secret ever reaches an argv, because
  a process listing is world readable and an environment is not; git gets a
  credential helper whose *shape* is in the command line and whose token comes
  from the environment.
- `workspace/mod.rs` — provisioning, symlink containment, orphan reaping.

Release is by ownership: every scanner holds an `Arc` to the one workspace its
scan provisioned, and the last to drop takes the directory with it. A straggler
cannot have the tree deleted underneath it, and that is true by construction
rather than by care.

### `redact.rs`

Redaction runs **before** truncation, always. Truncating first can cut a secret
in half, and half a credential is still half a credential. It covers logs *and*
the reported command — a sentinel test found `execution.command` publishing a
token that nobody had thought to redact.

### `parsers/`

The normalization layer, in preference order:

- `parsers/sarif.rs` — a generic SARIF 2.1.0 parser. This is the highest-leverage code in the project: one implementation normalizes every scanner that can emit SARIF (semgrep, gitleaks, hadolint, gosec, golangci-lint, ruff, tfsec, terrascan, bearer, psalm, flawfinder, detekt, ktlint, …), with real rule IDs, help URIs, and severities. Severity resolves from `security-severity` (CVSS), then a plain `properties.severity` word, then the SARIF `level`. Suppressed results are dropped.
- `parsers/tools.rs` — tool-native JSON for scanners with no SARIF support (bandit, shellcheck, grype, osv-scanner, cargo-clippy, cargo-audit, npm-audit, eslint, rubocop, staticcheck, pip-audit, kube-linter, phpstan, checkov, trivy).
- `parsers/json.rs` — extraction helpers. Scanner containers interleave banners and progress logs with their report, so `extract_payload` finds the largest parseable JSON document in a noisy stream and `extract_ndjson` handles line-delimited output.

Findings get a **stable fingerprint** (`scanner:rule:path:line`) that contains no run ID, so results can be diffed across runs, and `id` is the tool's own rule identifier so it can be passed straight to `explain_finding`.

### `http/` and `authz.rs`

The hosted transport, behind the `http` feature. `rmcp`'s `StreamableHttpService`
is a `tower::Service`, so authentication wraps it as a layer rather than
forking the handler.

- `http/auth.rs` — the Resource Server half of MCP authorization, which `rmcp`
  does not provide: JWKS fetch and cache, algorithm allowlist, and validation
  of issuer, expiry, and **audience**.
- `http/metadata.rs` — the RFC 9728 document a client fetches to discover where
  to authenticate.
- `http/mod.rs` — the axum app: routes, per-caller concurrency, session
  ownership, body limits, `/healthz`, `/readyz`, `/metrics`.
- `authz.rs` — per-caller repository access. Deliberately *not* under `http/`:
  the scan path must be able to ask whether it has a caller whatever transport
  is in use, and on stdio the answer is no.

**How a caller reaches the tool handler.** The middleware validates a token and
attaches a `CallerContext` to the request extensions. `rmcp` forwards the whole
`http::request::Parts` into the tool context, so `server.rs` reads it back out.
On stdio there are no parts and no caller — correct, because the caller is the
operator and there is nobody to authorize.

**Why authorization is not just a check.** A caller supplies their own forge
credential; it is verified against the repository, and then used for the clone.
Every server-held credential is stripped from the caller-scoped configuration,
so there is no path by which a scan authorized for one caller falls back to the
server's broader access. What a caller can scan is what they could already
read.

### `observe.rs`

Structured logs to **stderr**, always — on stdio, stdout carries the JSON-RPC
stream and a stray log line corrupts the protocol. Scan records are log lines,
not rows: nothing is persisted and retention belongs to the operator.

Metrics are a no-op type without the `http` feature, so `server.rs` calls them
unconditionally without knowing whether anything is listening. Label values come
from bounded vocabularies and anything else becomes `other`: the metrics
endpoint is deliberately less protected than `/mcp`, so a repository name in a
label would be both a disclosure and an unbounded time series.

### `explain.rs` / `fixes.rs`

Knowledge-base modules that return contextual explanations and fix suggestions given a scanner name and finding. Currently scaffolded — extend by adding scanner-specific entries.

## Data flow

```mermaid
flowchart TD
    A["run_scan request"] --> A0["ToolSelector::plan()<br/>detect languages from directory contents"]
    A0 --> B["resolve_scanners_for_request()<br/>validates scanner names against ScannerRegistry"]
    B --> B1["Docker preflight<br/>one clear error, not N identical ones"]
    B1 --> C["join_all() + Semaphore<br/>bounded parallel fanout"]
    C --> D["DockerScannerRunner::run_scan()"]
    D --> D1["resolve_target()<br/>canonicalize; file targets mount their parent"]
    D1 --> D2["ensure_image_available()<br/>pull if needed"]
    D2 --> D3["image_cache_config()<br/>volumes + env vars"]
    D3 --> D4["create_container()<br/>apply security opts"]
    D4 --> D5["start_container() and wait_container()"]
    D5 --> D6["logs()<br/>collect stdout+stderr"]
    D6 --> D7["cleanup_container()<br/>always runs"]
    D7 --> D8["NormalizedFinding"]
    D8 --> E["RunScanResponse"]
```

## Adding a new scanner

1. Add an entry in `scanners.rs` using the appropriate language builder.
2. Prefer a command that emits **SARIF** (`.sarif()`) — it needs no new parser. Otherwise emit tool-native JSON, add a parser to `parsers/tools.rs`, list the name in `SUPPORTED`, and mark the entry `.json()`. If neither is possible, leave it as text; runs will report `unparsed` with raw logs attached.
3. Declare `.exits(&[…])` with every exit code that means "ran correctly". Most linters exit 1 simply because they found something. Never wrap the command in `|| true` — that is the bug this design exists to prevent, and a unit test rejects it.
4. Never use an in-place write flag (`-w`, `-i`, `--write`, `--fix`): the workspace is mounted read-only. Use the tool's check/dry-run mode. A unit test rejects these too.
5. If the tool is not pre-installed in the base image, set `.install(…)`. For Debian/Ubuntu images use the `APT` prefix constant.
6. Add the scanner name to the relevant `LanguageToolProfile` in `selection.rs` so `mode=all` can discover it.
7. Verify `cargo test` passes, then run the scanner for real: `cargo test --test scanner_smoke -- --ignored --nocapture`. A command template that no image can execute is invisible to the unit tests.

## Adding a new language

1. Add a language builder function in `scanners.rs` (e.g. `swift_scanner`).
2. Add entries for all scanners in that ecosystem.
3. Add a `LanguageToolProfile` in `selection.rs`.
4. Extend `image_cache_config` in `runner.rs` to cover the new image pattern and redirect its cache directories to named volumes.
5. Add the ecosystem's manifest names to `MANIFESTS` and its file extensions to `EXTENSIONS` in `selection.rs` (and, for the not-on-disk fallback path, `infer_language`).

## Testing

Three layers:

- **Unit tests** — `#[cfg(test)]` modules inline in `models.rs`, `parsers/*`, `runner.rs`, `scanners.rs`, `selection.rs`, and `server.rs`. No Docker required; part of the default `cargo test` run. The parser tests pin real tool output shapes, and the registry tests enforce the catalog invariants above.
- **End-to-end tests** — `tests/e2e_scan.rs`. Runs real scanner containers via `DockerScannerRunner` through the full `AuditMcpServer` tool surface (`run_scan`, `list_scanners`, `explain_finding`) against fixtures in `tests/fixtures/`. Each Docker-dependent test is `#[ignore]`d and self-skips (with a message) if no daemon is reachable, so `cargo test` alone stays fast and hermetic. Run explicitly with `cargo test --test e2e_scan -- --ignored` whenever a change touches `runner.rs`, a scanner's `command_template`, or `image_cache_config`.

- **Clone tests** — `tests/workspace_clone.rs`, against a real remote. The
  cleanup assertions matter more than the happy path: a workspace surviving a
  *successful* scan is a bug someone notices, one surviving a *failed* scan is
  a slow disk leak nobody notices.
- **Secret hygiene** — `tests/secret_hygiene.rs`. Seeds a sentinel into every
  credential source, runs a real scan, serializes the whole response, and
  asserts the sentinel appears nowhere. Reviewing for this by eye does not
  work.
- **Backend parity** — `tests/executor_parity.rs`. The same scanner and
  repository through both backends must yield the same rule IDs, severities,
  and locations.
- **HTTP auth** — `tests/http_auth.rs`, against a real socket with a local mock
  issuer that signs tokens and serves a JWKS. Note the trap it now guards
  against: MCP requires an `initialize` handshake, and without it every call
  fails with "expect initialize request" — which reads like a refusal, so two
  authorization tests once passed while proving nothing. The helper asserts the
  handshake took.
- **Scanner smoke tests** — `tests/scanner_smoke.rs`. Runs every scanner that declares structured output against a matching fixture and asserts it does not come back as `tool_error`, `timeout`, or `unparsed`. Split by cost into `smoke_fast_tier`, `smoke_slow_tier` (Go/Rust, which compile first), `smoke_jvm_tier`, `smoke_scripting_tier` (Ruby/PHP), `smoke_dotnet_tier`, and `smoke_elixir_tier`. This is the only layer that catches a command template no image can execute — a swallowed ENTRYPOINT, a renamed flag, a tool missing from the base image, a `-quiet` that suppresses the whole report. Run it after any change to a `command_template`, an image, or an install script.

  Set `AUDIT_MCP_CORPUS` to a directory of real example projects to smoke the scanners against realistic code instead of the minimal in-repo fixtures:

  ```bash
  AUDIT_MCP_CORPUS=../paws/examples cargo test --test scanner_smoke -- --ignored --nocapture
  ```

  A name absent from the corpus falls back to the in-repo fixture, so the suite still runs anywhere. Real projects are worth the extra pass: the corpus run is what exposed both the `0700` directory failure and gosec's `-quiet` behaviour, neither of which the minimal fixtures could reproduce.

When adding a new e2e case, assert on **normalized findings** — rule ID, severity, file, line — not on substrings of raw logs. Log-grepping assertions pass even when normalization is broken, which is precisely the failure this suite exists to catch.
