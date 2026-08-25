---

description: "Task list for 001-hosted-execution-modes"
---

# Tasks: Remote repositories, Kubernetes execution, and a hosted authenticated transport

**Input**: Design documents from `/specs/001-hosted-execution-modes/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included, and not optional here. The spec names specific tests as
success criteria (SC-003 backend parity, SC-004 secret leakage, SC-006 audience
rejection, SC-009 hermetic default suite, SC-012 metric label leakage), and
constitution principle II requires that any change to execution be verified
against real infrastructure.

**Organization**: Grouped by user story. Each story is independently
implementable, testable, and shippable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1, US2, US3 — maps to the user stories in spec.md
- Every task names the exact file it touches

## Path Conventions

Single Rust crate: `src/` and `tests/` at the repository root, per plan.md.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Make the new dependencies available without changing what a
default build produces.

- [ ] T001 Add `kubernetes` and `http` Cargo features (both off by default) to `Cargo.toml`, so the stdio+Docker default build gains no new dependencies — this is the first line of defence for SC-001
- [ ] T002 Add feature-gated dependencies to `Cargo.toml`: `kube`/`k8s-openapi` under `kubernetes`; `axum`, `jsonwebtoken`, and a Prometheus exporter under `http`; `reqwest` and `tempfile` for the always-on clone path; enable `rmcp`'s `transport-streamable-http-server` under `http`
- [ ] T003 [P] Create module skeletons with doc comments and no logic: `src/workspace/mod.rs`, `src/executor/mod.rs`, `src/config.rs`, `src/redact.rs`, `src/observe.rs`; register them in `src/lib.rs`
- [ ] T004 [P] Add the new test binaries as empty, self-skipping stubs so CI wiring lands before the code: `tests/workspace_clone.rs`, `tests/executor_parity.rs`, `tests/secret_hygiene.rs`, `tests/http_auth.rs`
- [ ] T005 [P] Extend `.github/` CI to run `cargo build --all-features` and `cargo clippy --all-features -- -D warnings`, so a feature-gated module cannot rot unnoticed
- [ ] T006 Verify `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` all pass with default features unchanged

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The refactor that makes all three stories additive rather than
three forks of the same logic — plan.md Phase A. This phase ships **no
user-visible change**, and that is the point.

**⚠️ CRITICAL**: No user story work begins until T020 is green.

### Executor extraction (behaviour-preserving)

- [ ] T007 Define `Executor`, `ExecutionRequest`, `ExecutionOutcome`, and `Termination` (Completed / TimedOut / Infrastructure) in `src/executor/mod.rs` per data-model.md; the outcome carries stdout, combined output, exit code, and duration — deliberately **no status and no findings**
- [ ] T008 Move the container lifecycle out of `src/runner.rs` into `src/executor/docker.rs`: image pull, container create with entrypoint clearing and security options, start, wait, log collection with stdout kept separate, kill-on-timeout, and cleanup
- [ ] T009 Rewrite `src/runner.rs` to call an `Executor` and retain everything else it owns today — parsing, `RunStatus` determination, the exit-code policy, the "parsed findings mean it ran" rule, and log attachment
- [ ] T010 Wire the executor choice through `src/server.rs` so `run_scan` holds an `Arc<dyn Executor>` instead of a `DockerScannerRunner`
- [ ] T011 [P] Add a unit test in `src/executor/mod.rs` asserting the trait is object-safe and that a stub executor drives `runner.rs`'s status rules with no Docker present

### Configuration and startup validation

- [ ] T012 [P] Implement configuration loading in `src/config.rs` for every variable in contracts/configuration.md, with documented defaults
- [ ] T013 [P] Implement startup validation in `src/config.rs`: reject `AUDIT_TRANSPORT=http` without `AUDIT_RESOURCE_URL` or `AUDIT_OAUTH_ISSUER`, reject a partial `GITHUB_APP_*` set, reject an unknown `AUDIT_EXECUTOR`. An incoherent configuration must fail at the door, unlike an unreachable dependency
- [ ] T014 [P] Unit-test the configuration matrix in `src/config.rs`, including that an empty environment yields today's defaults exactly

### Cross-cutting infrastructure

- [ ] T015 [P] Implement the redaction boundary in `src/redact.rs`: a registry of known secret values and a pass applied to any captured text before it can become a response field. Register no secrets yet — seeding is US1's job
- [ ] T016 [P] Unit-test `src/redact.rs` for overlapping secrets, secrets spanning a truncation boundary, and the empty-registry no-op case
- [ ] T017 [P] Implement structured levelled logging in `src/observe.rs`, writing to **stderr** on the stdio transport — stdout carries the JSON-RPC stream and must not be shared (FR-036)
- [ ] T018 Extend `AuditStatusResponse` in `src/models.rs` and `src/server.rs` with the active backend and its reachability (FR-017), keeping the existing fields untouched

### Regression gate

- [ ] T019 Run the full existing verification: `cargo test`, then `cargo test --test e2e_scan -- --ignored`, then all six tiers of `cargo test --test scanner_smoke -- --ignored`
- [ ] T020 Confirm behaviour preservation against the pre-refactor baseline: all 33 structured scanners still produce the same statuses and finding counts, and no field of `RunScanResponse` in `src/models.rs` changed shape

**Checkpoint**: Foundation ready. US1, US2, and US3 can now proceed independently.

---

## Phase 3: User Story 1 - Scan a repository I have not checked out (Priority: P1) 🎯 MVP

**Goal**: `target` accepts a git URL or `owner/repo`; the server clones it,
scans it exactly as a local directory, and removes it afterwards.

**Independent Test**: Point `run_scan` at a public repository URL with no
credentials configured, confirm findings carry repository-relative paths, then
confirm the temporary directory is gone.

### Tests for User Story 1 ⚠️

> Write these first and confirm they fail.

- [ ] T021 [P] [US1] Unit-test target expression parsing in `src/workspace/target.rs`: local paths, HTTPS URLs, SSH URLs, `owner/repo`, inline `#ref`, and the rule that an existing local path always wins. Parsing is side-effect free, so this is exhaustive and hermetic
- [ ] T022 [P] [US1] Unit-test SSRF rejection in `src/workspace/target.rs` for private, loopback, and link-local resolutions, plus the `AUDIT_ALLOW_PRIVATE_ADDRESSES` opt-out
- [ ] T023 [P] [US1] Unit-test credential precedence and reporting in `src/workspace/credentials.rs`: the documented order, and that a `Debug`/`Display` render of any credential never contains the secret
- [ ] T024 [P] [US1] Integration test in `tests/workspace_clone.rs` (`#[ignore]`, self-skipping without network/`git`): clone a public repository, assert repository-relative finding paths, assert `resolved_ref` is a SHA, assert the temporary directory is removed
- [ ] T025 [P] [US1] Add a failure-path case to `tests/workspace_clone.rs`: a scan that errors must still remove its workspace (SC-005) — the failure path is the one that leaks
- [ ] T026 [P] [US1] Write `tests/secret_hygiene.rs` (`#[ignore]`): seed a sentinel into every credential source, run a scan, serialize the whole response, assert the sentinel appears nowhere in logs, execution metadata, findings, or errors (SC-004)

### Implementation for User Story 1

- [ ] T027 [P] [US1] Implement target expression parsing in `src/workspace/target.rs` per data-model.md, including ref extraction and the local-path-wins disambiguation
- [ ] T028 [US1] Implement address validation in `src/workspace/target.rs`: resolve the host, reject private/loopback/link-local unless opted in, and bind the resolved address for the connection so DNS rebinding cannot slip past the check (FR-008)
- [ ] T029 [P] [US1] Implement the `CredentialSource` enum in `src/workspace/credentials.rs` for GitHub App, token, SSH key, and anonymous, with a `name()` for reporting and secrets that cannot be printed
- [ ] T030 [US1] Implement GitHub App authentication in `src/workspace/credentials.rs`: sign an RS256 JWT with ≤10 minute expiry, exchange it for an installation token, and fetch it immediately before the clone rather than caching it across a scan (R6)
- [ ] T031 [US1] Implement cloning in `src/workspace/clone.rs` by invoking `git`: shallow by default, ref resolution, and credential delivery that never embeds a secret in a URL or a git remote (FR-028)
- [ ] T032 [US1] Enforce clone bounds in `src/workspace/clone.rs` — size, depth, and duration — reporting a `tool_error` that names the exceeded budget (FR-006)
- [ ] T033 [US1] Implement `Workspace` provisioning and release in `src/workspace/mod.rs`: one workspace per scan shared read-only by all scanners, refcounted release so a straggler or timed-out scanner cannot lose the tree underneath it (FR-005a)
- [ ] T034 [US1] Implement cleanup and orphan reaping in `src/workspace/mod.rs`: remove on success, failure, and timeout, and reap workspaces left behind by an unclean shutdown (FR-005)
- [ ] T035 [US1] Implement symlink containment in `src/workspace/mod.rs` so a link inside a clone cannot expose paths outside it to a scanner (FR-009)
- [ ] T036 [US1] Extend path normalization in `src/parsers/mod.rs` to strip the clone root, so no temporary directory prefix can reach a finding location (FR-007)
- [ ] T037 [US1] Seed `src/redact.rs` with every resolved credential value at workspace provisioning time, and clear it on release
- [ ] T038 [US1] Wire workspace provisioning into `run_scan` in `src/server.rs`: resolve the target once per scan, share it across scanners, release it in every exit path
- [ ] T039 [US1] Add `ref` and `subdir` arguments to `RunScanRequest` in `src/server.rs` per contracts/mcp-tools.md, both optional
- [ ] T040 [US1] Add the `workspace` block (origin, normalized source, resolved ref, credential source name) to `RunScanResponse` in `src/models.rs`
- [ ] T041 [US1] Extend `audit_status` in `src/server.rs` with `git` availability and configured credential source names, so a missing `git` is visible before a scan fails late (R5)
- [ ] T042 [US1] Return an actionable error from `src/workspace/mod.rs` for a private repository with no matching credential, naming the workable credential sources without disclosing whether the repository exists

**Checkpoint**: US1 is fully functional. Remote scanning works on the existing
stdio + Docker deployment with no other change.

---

## Phase 4: User Story 2 - Run scanners in a cluster instead of on a Docker socket (Priority: P2)

**Goal**: Each scanner runs as a Kubernetes Job, with the same isolation
guarantees and identical normalized findings.

**Independent Test**: With a kubeconfig pointing at a local cluster and
`AUDIT_EXECUTOR=kubernetes`, run a scanner from the existing e2e suite and
assert an identical normalized finding.

### Tests for User Story 2 ⚠️

- [ ] T043 [P] [US2] Write `tests/executor_parity.rs` (`#[ignore]`, self-skipping without a cluster): run the same scanner and fixture through both backends and assert equivalent normalized findings — same rule IDs, severities, and repository-relative paths (SC-003)
- [ ] T044 [P] [US2] Add a cluster tier to `tests/scanner_smoke.rs` that runs the structured scanners through the Kubernetes backend and applies the same "did not come back as tool_error, timeout, or unparsed" contract
- [ ] T045 [P] [US2] Add a preflight test in `tests/executor_parity.rs` asserting that with no reachable cluster a scan returns exactly one error, not one per selected scanner (FR-016)

### Implementation for User Story 2

- [ ] T046 [US2] Confirm the `kube` API surface assumed in research.md R4 (`Api::<Job>::namespaced`, completion watching, log retrieval) before building on it — research.md flags this as unverified
- [ ] T047 [US2] Implement lazy cluster connection in `src/executor/kubernetes.rs` using in-cluster ServiceAccount with kubeconfig fallback, not caching failures, mirroring the Docker client's behaviour (constitution V)
- [ ] T048 [US2] Build the Job spec in `src/executor/kubernetes.rs`: one `batch/v1` Job per scanner run, with `backoffLimit` and `ttlSecondsAfterFinished` as a cleanup backstop
- [ ] T049 [US2] Add the git-clone initContainer and `emptyDir` in `src/executor/kubernetes.rs`, mounted **read-only** by the scanner container — no host path, no Docker socket (FR-012)
- [ ] T050 [US2] Apply the isolation guarantees in `src/executor/kubernetes.rs`: read-only mount, no privilege escalation, dropped capabilities with only `DAC_READ_SEARCH` restored, memory limit, and wall-clock timeout (FR-013)
- [ ] T051 [US2] Apply operator settings in `src/executor/kubernetes.rs` verbatim: namespace, service account, resource requests/limits, node selector, tolerations, image pull secrets (FR-014)
- [ ] T052 [US2] Implement log collection in `src/executor/kubernetes.rs` — and **check whether pod logs interleave stdout and stderr** the way Docker's do. Interleaving corrupted gosec's SARIF in the Docker path; if the cluster merges them, affected scanners need their stderr redirected in the command instead (research.md open question)
- [ ] T053 [US2] Implement timeout handling in `src/executor/kubernetes.rs`: delete the Job, collect partial logs first so work done is still visible, and return `Termination::TimedOut`
- [ ] T054 [US2] Map infrastructure failures in `src/executor/kubernetes.rs` — eviction, OOM kill, unschedulable, image pull failure — to `Termination::Infrastructure(reason)` carrying the cluster's own words, so they surface as `tool_error` and never as `clean` (FR-018)
- [ ] T055 [US2] Implement Job deletion on every exit path plus reaping of Jobs orphaned by a controller restart, in `src/executor/kubernetes.rs` (FR-015)
- [ ] T056 [US2] Deliver credentials to the clone initContainer from a Kubernetes Secret in `src/executor/kubernetes.rs`, never as Job spec environment variables — a Job spec is readable by anyone with `get jobs` in the namespace (FR-029, R7)
- [ ] T057 [US2] Report the backend in `ScanExecution` in `src/models.rs` and select it from configuration in `src/server.rs`
- [ ] T058 [US2] Accept a cold scanner cache in the cluster for this release, documenting the limitation in `docs/CACHE.md` and recording the persistent-cache question as follow-up in `specs/001-hosted-execution-modes/research.md` — correctness before cache optimisation (R9)

**Checkpoint**: US1 and US2 both work independently. `audit-mcp` can now run in
a cluster with no Docker socket.

---

## Phase 5: User Story 3 - Several people share one authenticated deployment (Priority: P3)

**Goal**: MCP over streamable HTTP, with the server as an OAuth 2.1 Resource
Server, per-caller authorization, and metrics.

**Independent Test**: An unauthenticated request is refused with a challenge
naming the authorization server; a request bearing a valid token for this
resource succeeds.

**⚠️ Blocked on an open question**: how a caller-scoped forge credential reaches
the authorization check under a JWT-only IdP (research.md R10). Resolve before
starting T070.

### Tests for User Story 3 ⚠️

- [ ] T059 [P] [US3] Write `tests/http_auth.rs` (`#[ignore]`): unauthenticated request returns 401 with a `WWW-Authenticate` challenge naming the resource metadata URL
- [ ] T060 [P] [US3] Add rejection cases to `tests/http_auth.rs`: malformed token, expired token, wrong issuer, and `alg: none` — each a 401 with no indication of which check failed
- [ ] T061 [P] [US3] Add the audience test to `tests/http_auth.rs`: a valid token minted by the same issuer for a **different** resource must be rejected (SC-006). This is the defect a hand-rolled resource server most often ships
- [ ] T062 [P] [US3] Add an authorization test to `tests/http_auth.rs` asserting that a caller who cannot read a private repository cannot cause the server to scan it, even when a server-held credential would have granted access (SC-010)
- [ ] T063 [P] [US3] Add a metrics leakage test to `tests/secret_hygiene.rs` asserting no label value scraped after a scan contains a repository name, target URL, caller subject, or file path (SC-012)
- [ ] T064 [P] [US3] Add an isolation test to `tests/http_auth.rs`: two identities scanning concurrently, neither response containing the other's target, findings, or workspace (FR-024)

### Implementation for User Story 3

- [ ] T065 [US3] Build the axum application in `src/http/mod.rs`, mounting `rmcp`'s `StreamableHttpService` as a tower service at `/mcp` (verified available in research.md R1)
- [ ] T066 [P] [US3] Serve the RFC 9728 protected resource metadata document at `/.well-known/oauth-protected-resource` from `src/http/metadata.rs`, unauthenticated
- [ ] T067 [US3] Implement the authentication layer in `src/http/auth.rs`: `WWW-Authenticate` challenge on unauthenticated requests, JWKS fetch with a bounded cache and key rotation handling, and an algorithm allowlist that rejects `alg: none`
- [ ] T068 [US3] Implement full token validation in `src/http/auth.rs` — `iss`, `exp`, `nbf`, signature — and **audience against `AUDIT_RESOURCE_URL`**, which is not optional and not a formality (FR-022)
- [ ] T069 [US3] Implement scope checking in `src/http/auth.rs`, returning 403 rather than 401 when a valid token lacks the required scope
- [ ] T070 [US3] Implement per-caller repository authorization in `src/http/authz.rs`: confirm the calling identity can itself read the target before any server-held credential touches it (FR-031, FR-032)
- [ ] T071 [US3] Implement the authorization decision cache in `src/http/authz.rs`, keyed by caller and repository with a bounded lifetime so revoked access stops working promptly (FR-034)
- [ ] T072 [US3] Refuse unauthorized targets in `src/http/authz.rs` without disclosing whether the repository exists (FR-033)
- [ ] T073 [P] [US3] Implement per-caller concurrency limits in `src/http/mod.rs`, returning 429 with `Retry-After` and leaving other callers unaffected (FR-025)
- [ ] T074 [P] [US3] Bind a session to the identity that created it in `src/http/mod.rs`, and let an in-flight scan finish when its token expires while requiring a valid token for any new request
- [ ] T075 [P] [US3] Emit the Scan Record as a structured log line from `src/observe.rs` — caller, target, resolved ref, scanners, outcome, timing — including authorization refusals (FR-026, FR-035). Nothing is persisted
- [ ] T076 [US3] Implement Prometheus metrics in `src/observe.rs`: scans by terminal status, scan and per-scanner durations, backend reachability, in-flight executions and queue depth, per-caller rejections (FR-037)
- [ ] T077 [US3] Enforce the metric label allowlist in `src/observe.rs` so repository names, target URLs, caller subjects, and paths can never become label values (FR-038)
- [ ] T078 [P] [US3] Serve `/metrics` from `src/http/mod.rs` with no MCP token required and a separate bind address, so an operator can expose it only to scrape infrastructure (FR-039)
- [ ] T079 [P] [US3] Add `/healthz` and `/readyz` to `src/http/mod.rs`, distinguishing alive from ready — an unreachable backend is not a reason to be killed
- [ ] T080 [US3] Add transport selection to `src/main.rs`, defaulting to stdio with no listener and no authentication (FR-019, SC-001)
- [ ] T081 [P] [US3] Add request body size limits and origin validation in `src/http/mod.rs` to bound denial-of-service and prevent DNS rebinding against a loopback-bound server
- [ ] T082 [P] [US3] Extend `audit_status` in `src/server.rs` with the transport kind and authentication mode per contracts/mcp-tools.md

**Checkpoint**: All three stories work independently.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T083 [P] Update `README.md`: the three optional modes, the new `run_scan` arguments and response fields, and an explicit statement that the default is unchanged
- [ ] T084 [P] Update `docs/ARCHITECTURE.md` with the executor seam, the workspace layer, the HTTP surface, and why status determination deliberately stays out of the executor
- [ ] T085 [P] Update `docs/SECURITY.md` with the threat model this feature introduces: SSRF, confused-deputy authorization, credential leakage, metrics exposure, and multi-tenant isolation
- [ ] T086 [P] Add `docs/DEPLOYMENT.md` with example Kubernetes manifests — RBAC for Job management, a Secret for credentials, and a scrape-only path to `/metrics`
- [ ] T087 [P] Ship a container image containing `git`, and document that the clone path depends on it (R5)
- [ ] T088 Run every scenario in `specs/001-hosted-execution-modes/quickstart.md`, Scenario 0 first and last
- [ ] T089 Confirm SC-001 by diffing a default-configuration `list_scanners` and `run_scan` response against the pre-feature baseline
- [ ] T090 [P] Run `cargo clippy --all-features -- -D warnings` and `cargo fmt --check`
- [ ] T091 Review whether any constitution principle needs amending, and record the reasoning in `.specify/memory/constitution.md` if so — the constitution requires an explicit amendment rather than a quiet exception
- [ ] T092 Close or re-record the remaining open questions in `specs/001-hosted-execution-modes/research.md`: pod log interleaving (T052) and persistent scanner caching in-cluster (T058)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies
- **Foundational (Phase 2)**: depends on Setup — **blocks every user story**
- **US1 (Phase 3)**: depends on Foundational only
- **US2 (Phase 4)**: depends on Foundational; uses US1's workspace layer for the clone initContainer, so US1 first is the shorter path, though the backend itself can be built against a local path
- **US3 (Phase 5)**: depends on Foundational; only genuinely useful once US2 exists, because hosting without a cluster executor means exposing a Docker socket
- **Polish (Phase 6)**: depends on whichever stories shipped

### Within Each Story

- Tests first, failing, before implementation
- `target.rs` → `credentials.rs` → `clone.rs` → `workspace/mod.rs` → server wiring
- Executor internals before server wiring
- Authentication before authorization; authorization before it can gate a scan

### Parallel Opportunities

- Setup: T003, T004, T005 together
- Foundational: T012–T017 are independent files and can run alongside the executor extraction (T007–T011); T018 needs T007
- US1: all six test tasks (T021–T026) in parallel; T027 and T029 in parallel; T036 and T041 independent of the clone chain
- US2: all three test tasks (T043–T045) in parallel; T046 gates the rest
- US3: all six test tasks (T059–T064) in parallel; T066, T073, T074, T078, T079, T081 are independent of the auth chain
- Polish: T083–T087 and T090 in parallel
- Across stories: once Phase 2 is green, US1, US2, and US3 can be staffed in parallel

---

## Implementation Strategy

### MVP

**Phase 1 + Phase 2 + Phase 3 (US1)** — remote repository scanning on the
existing stdio + Docker deployment. That is a complete, useful increment: it
needs no cluster, no login, and no new transport, and it delivers the capability
that prompted this feature.

### Incremental delivery

1. **Phases 1–2** — refactor only. No user-visible change; the entire value is
   that Phase 2's regression gate (T019, T020) proves it.
2. **Phase 3** — remote repositories. Ship it.
3. **Phase 4** — Kubernetes execution. Ship it.
4. **Phase 5** — hosted transport. Ship it last, on two proven layers, because
   it carries the largest new attack surface.

### A note on sequencing

Phase 2 deliberately produces nothing a user can see. Resist folding it into
Phase 3: if the executor extraction and the clone feature land together, a
regression in the default Docker path and a bug in the new clone path become
indistinguishable, and the default path is the one nearly every user is on.

Scenario 0 of quickstart.md — "the default did not change" — is a gate on every
phase, not just the first.
