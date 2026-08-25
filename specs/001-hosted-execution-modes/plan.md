# Implementation Plan: Remote repositories, Kubernetes execution, and a hosted authenticated transport

**Branch**: `001-hosted-execution-modes` | **Date**: 2026-08-25 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-hosted-execution-modes/spec.md`

## Summary

Three capabilities, each off by default, each shippable on its own:

1. **Workspace provisioning** — `target` may be a git URL; the server clones it
   to a temporary directory, scans, and cleans up. Credentials from GitHub App,
   SSH key, token, or none.
2. **Pluggable execution** — extract an `Executor` trait from today's
   `DockerScannerRunner`, then add a Kubernetes backend that runs each scanner
   as a Job.
3. **Hosted transport** — serve MCP over streamable HTTP alongside stdio, with
   the server acting as an OAuth 2.1 Resource Server.

The technical spine is a single refactor done first: today `run_scan` resolves
the target, runs the container, parses output, and decides status all in one
function. Splitting *workspace provisioning* and *container lifecycle* out of
that function — leaving normalization, status, and shaping shared — is what
makes all three features additive rather than three parallel forks of the same
logic.

## Technical Context

**Language/Version**: Rust 2024 edition, stable toolchain (currently 1.98)

**Primary Dependencies**: existing — `rmcp` 1.7 (`transport-streamable-http-server`
feature to be added), `bollard`, `tokio`, `serde`. New — `kube` + `k8s-openapi`
(Kubernetes backend), `axum` (HTTP surface around rmcp's tower service),
`jsonwebtoken` (JWT validation and GitHub App JWT signing), `reqwest` (JWKS,
introspection, GitHub App token exchange), `tempfile` (workspace lifetimes).
Runtime — the `git` binary.

**Storage**: None persistent. Temporary clone directories with an explicit
cleanup obligation; an append-only audit log of scan records.

**Testing**: `cargo test` (hermetic, no Docker/network — must stay that way);
`tests/e2e_scan.rs` and `tests/scanner_smoke.rs` (`#[ignore]`d, self-skipping)
extended with a cluster tier that self-skips without a reachable cluster.

**Target Platform**: Linux, both as a local developer process and as a
container running inside Kubernetes.

**Project Type**: Single Rust binary plus library crate. No new crates.

**Performance Goals**: Clone overhead should not dominate: a shallow clone of a
typical repository well under the fastest scanner's runtime. Kubernetes Job
startup adds latency versus a local container; acceptable, since the alternative
is not running at all.

**Constraints**: Every existing constitutional constraint applies unchanged to
every new mode — read-only workspace, dropped capabilities, no privilege
escalation, memory ceiling, wall-clock timeout, bounded concurrency, bounded
output. A credential must never reach a response field.

**Scale/Scope**: A team-sized deployment — tens of callers, not thousands.
Isolation requirements are scoped to colleagues, per the spec's assumptions.

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1 design.*

| Principle | Gate | Assessment |
|-----------|------|------------|
| **I. A scan result must never lie** | New failure modes must map onto existing statuses, never onto `clean` | **PASS by design.** Clone failure, pod eviction, OOM kill, and image pull failure each map to `tool_error` or `timeout` with the cause attached (FR-018). The executor trait deliberately returns raw output and exit code, *not* a status, so status rules stay in one place and cannot diverge per backend (R9). |
| **II. Verify against real containers** | New execution paths need real-infrastructure tests | **PASS.** A cluster tier is added to `scanner_smoke.rs`, self-skipping without a cluster. SC-003 requires the same fixture through both backends to produce equivalent findings — the strongest available check that the Kubernetes path is not subtly different. |
| **III. Isolation is the product** | New modes must not weaken the sandbox | **PASS, with attention.** The Kubernetes path keeps read-only workspace, dropped capabilities, no-privilege-escalation, memory limit, and timeout (FR-013). Note the workspace arrives via `emptyDir` from an initContainer — no host path, no Docker socket, which is *stronger* than the local default. Credentials mount from a Secret, never from a Job spec env var (R7). |
| **IV. Bounded by default** | Every new input needs a bound | **PASS.** Clone size, depth, and duration are bounded (FR-006); per-caller concurrency is bounded (FR-025); the existing per-scan concurrency and findings caps apply unchanged. |
| **V. Degrade, don't disappear** | Missing infrastructure must not prevent startup | **PASS.** The Kubernetes client connects lazily exactly as the Docker client does; an unreachable backend yields one preflight error (FR-016) and the status tool reports which backend is active and whether it is reachable (FR-017). |
| **VI. Normalize once, at the edge** | Findings must be backend-independent | **PASS.** Container-path stripping already exists and gains the clone-root case (FR-007). SC-008 states the requirement directly: a third backend must require no change to normalization, status, or shaping. |

**Additional constraints check**: The default `cargo test` run must stay
hermetic (SC-009) — every new test that needs a cluster, a network, or a
credential is `#[ignore]`d and self-skips. New tool downloads, if any, are
pinned.

**Gate result: PASS.** No violations to justify; Complexity Tracking is
therefore empty.

**Post-Phase-1 re-evaluation**: PASS. The design added one deliberate,
narrowly-scoped exception, recorded below rather than waved through.

### Recorded design exception

**Secret redaction is a defence in depth, not a licence.** FR-027 introduces a
redaction pass over captured output. That is *not* permission to be relaxed
about where credentials flow: the primary control remains never putting a
credential somewhere it can be read (no credentials in remote URLs, no
credentials in Job specs). Redaction exists because scanner output is arbitrary
third-party text and cannot be reasoned about. Anyone tempted to pass a secret
somewhere new "because redaction will catch it" is misreading this.

## Project Structure

### Documentation (this feature)

```text
specs/001-hosted-execution-modes/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── mcp-tools.md            # Tool schema changes
│   ├── configuration.md        # Environment/config surface
│   └── http-transport.md       # HTTP endpoints and auth challenge
└── tasks.md             # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src/
├── lib.rs
├── main.rs                  # gains transport selection (stdio default)
├── models.rs                # + WorkspaceOrigin, CallerIdentity, ScanRecord
├── scanners.rs              # unchanged
├── selection.rs             # unchanged
├── explain.rs               # unchanged
├── fixes.rs                 # unchanged
├── parsers/                 # unchanged except clone-root path stripping
│   ├── mod.rs
│   ├── json.rs
│   ├── sarif.rs
│   └── tools.rs
├── server.rs                # orchestration; gains workspace + identity wiring
├── workspace/               # NEW — P1
│   ├── mod.rs               # Workspace, provisioning, cleanup, reaping
│   ├── target.rs            # target expression parsing + SSRF validation
│   ├── clone.rs             # git invocation, refs, bounds
│   └── credentials.rs       # GitHub App / SSH / token / anonymous
├── executor/                # NEW — P2 (Docker moves here unchanged in behaviour)
│   ├── mod.rs               # Executor trait, ExecutionRequest/Outcome
│   ├── docker.rs            # today's runner.rs container lifecycle
│   └── kubernetes.rs        # Job lifecycle
├── runner.rs                # retains normalization, status, timeout policy
├── redact.rs                # NEW — secret redaction at the response boundary
└── http/                    # NEW — P3
    ├── mod.rs               # axum app wrapping rmcp's tower service
    ├── auth.rs              # resource server: challenge, JWKS, introspection
    └── metadata.rs          # protected resource metadata document

tests/
├── e2e_scan.rs              # existing
├── scanner_smoke.rs         # existing + cluster tier
├── workspace_clone.rs       # NEW — clone paths, self-skipping
├── executor_parity.rs       # NEW — SC-003 same findings across backends
├── secret_hygiene.rs        # NEW — SC-004 sentinel leak test
└── http_auth.rs             # NEW — SC-006 audience rejection
```

**Structure Decision**: Single crate, existing layout, three new modules that
map one-to-one onto the three user stories, plus `redact.rs` as a cross-cutting
boundary. `runner.rs` deliberately *keeps* normalization, status determination,
and timeout policy while shedding container lifecycle to `executor/` — that
split is the whole reason the three features stay additive. Nothing in
`scanners.rs`, `selection.rs`, or `parsers/` changes behaviourally, which is
the strongest signal the seam is drawn in the right place.

## Phased delivery

| Phase | Story | Delivers | Gate to proceed |
|-------|-------|----------|-----------------|
| A | — | `Executor` trait extracted; Docker backend behind it; no behaviour change | Full existing suite green, including both smoke tiers |
| B | US1 (P1) | Clone from URL, all four credential sources, cleanup, redaction | SC-002, SC-004, SC-005 |
| C | US2 (P2) | Kubernetes Job backend | SC-003 parity, SC-007 |
| D | US3 (P3) | HTTP transport + resource server | SC-001 unchanged default, SC-006 |

Phase A ships no user-visible change and must be provably behaviour-preserving —
that is precisely why it goes first and alone.

## Complexity Tracking

No constitutional violations. Table intentionally empty.
