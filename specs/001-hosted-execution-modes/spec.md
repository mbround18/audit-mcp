# Feature Specification: Remote repositories, Kubernetes execution, and a hosted authenticated transport

**Feature Branch**: `001-hosted-execution-modes`

**Created**: 2026-08-25

**Status**: Draft

**Input**: User description: "can we have it run in 2 modes? local default but optionally if you have a GITHUB_APP_* or SSH_PRIVATE_KEY settings it can clone the repo into a tempdir and run the scanners against it and optionally if were running in a k8s environment and have the capabilities spin up pods instead of containers is that all possible? and optionally add a oauth provider to log in?"

## Summary

Today `audit-mcp` does exactly one thing: it is a stdio MCP server that runs
scanners in local Docker containers against a local directory. That is the
right default and it stays the default. This feature makes three further
deployments possible without changing that default:

1. **Remote repositories.** `target` may be a git URL or `owner/repo`. The
   server clones it to a temporary directory, scans it, and deletes it.
   Credentials come from whichever of GitHub App, SSH key, or token is
   configured; with none configured, public repositories still work.
2. **Kubernetes execution.** Where a Docker socket is unavailable or
   undesirable — notably when `audit-mcp` itself runs in a cluster — each
   scanner runs as a Kubernetes Job instead of a local container.
3. **A hosted, authenticated transport.** Alongside stdio, the server can
   serve MCP over streamable HTTP, acting as an OAuth 2.1 Resource Server so
   that several people, on several machines, can use one deployment.

Each is independently useful and independently shippable. Together they turn a
single-user developer tool into a service, without taking anything away from
the single-user developer tool.

## Clarifications

### Session 2026-08-25

- Q: OAuth in MCP is specified for HTTP transports; over stdio there is nobody
  to log in. What is actually wanted? → A: A hosted HTTP mode with MCP's OAuth
  2.1 resource-server flow, delegating to an external identity provider. The
  hosted mode is what makes multi-user remote scanning and cluster execution
  coherent as one deployment.
- Q: How should the Kubernetes executor run scanners? → A: One Job per scanner
  run, using the in-cluster ServiceAccount when present and falling back to
  kubeconfig. Jobs carry retry and TTL semantics and survive a controller
  restart; the workspace arrives through a git-clone initContainer into an
  `emptyDir`.
- Q: How should a caller ask for a remote repository scan? → A: `target`
  accepts a URL. One `run_scan` tool, no duplicated parameters, and `mode=all`
  keeps working unchanged.
- Q: Which credential sources should the clone path support? → A: All four —
  `GITHUB_APP_*` installation tokens, `SSH_PRIVATE_KEY`, a plain
  `GITHUB_TOKEN`/PAT, and anonymous public clone as the zero-configuration
  default.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan a repository I have not checked out (Priority: P1)

A developer asks their assistant to audit a repository that is not on their
disk — a dependency they are evaluating, a service another team owns, a pull
request branch. They give it a URL rather than a path. The server clones it,
scans it exactly as it would a local directory, and cleans up after itself.

**Why this priority**: It is the smallest of the three changes, it is useful on
day one to the existing single-user stdio deployment, and it requires no new
transport, no cluster, and no login. It also builds the workspace-provisioning
seam that Kubernetes execution later reuses.

**Independent Test**: Point `run_scan` at a public repository URL with no
credentials configured and confirm findings come back with repository-relative
paths, then confirm the temporary directory no longer exists.

**Acceptance Scenarios**:

1. **Given** no credentials are configured, **When** `run_scan` is called with
   a public HTTPS git URL, **Then** the repository is cloned, scanned, and the
   findings carry repository-relative paths with no temporary directory prefix.
2. **Given** `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, and
   `GITHUB_APP_INSTALLATION_ID` are set, **When** `run_scan` targets a private
   repository in that installation, **Then** the clone succeeds using a
   short-lived installation token.
3. **Given** `SSH_PRIVATE_KEY` is set, **When** `run_scan` targets an
   `ssh://` or `git@host:owner/repo` URL, **Then** the clone succeeds using
   that key and the key never appears in any response field.
4. **Given** a target with a `#ref` suffix or an explicit ref, **When** the
   scan runs, **Then** that branch, tag, or commit is what gets scanned, and
   the resolved commit SHA appears in the response.
5. **Given** a private repository and no matching credential, **When**
   `run_scan` is called, **Then** the response explains which credential
   source would be needed, and does not leak whether the repository exists.
6. **Given** a scan has finished, failed, or timed out, **When** the response
   is returned, **Then** the temporary clone has been removed.

---

### User Story 2 - Run scanners in a cluster instead of on a Docker socket (Priority: P2)

An operator runs `audit-mcp` inside Kubernetes. There is no Docker socket to
mount, and mounting one would hand every scanner root on the node. Instead each
scanner runs as a Job in a namespace the operator controls, with the cluster's
own quotas, node selection, and image pull secrets applied.

**Why this priority**: It is what makes any hosted deployment defensible.
Without it, hosting `audit-mcp` means exposing a Docker socket to untrusted
scanner images. It is independently testable against a local `kind` cluster and
delivers value even while the transport is still stdio.

**Independent Test**: With a kubeconfig pointing at a local single-node
cluster and `AUDIT_EXECUTOR=kubernetes`, run the same scanner that the Docker
executor runs in the existing e2e suite and assert an identical normalized
finding.

**Acceptance Scenarios**:

1. **Given** `AUDIT_EXECUTOR=kubernetes` and a reachable cluster, **When** a
   scan runs, **Then** a Job is created in the configured namespace, its logs
   are collected, its findings are normalized identically to the Docker path,
   and the Job is deleted.
2. **Given** the same scanner and fixture, **When** run through the Docker
   executor and the Kubernetes executor, **Then** the normalized findings are
   equivalent — same rule IDs, severities, and repository-relative paths.
3. **Given** a scanner exceeds its wall-clock budget, **When** the timeout
   fires, **Then** the Job is deleted, partial logs are collected, and the run
   is reported as `timeout` exactly as in the Docker path.
4. **Given** no cluster is reachable, **When** a scan is attempted, **Then**
   one clear preflight error is returned naming the executor and the reason,
   not one failure per selected scanner.
5. **Given** a Job's pod is evicted or its node disappears, **When** the
   controller observes this, **Then** the run is reported as `tool_error` with
   the eviction reason, never as `clean`.
6. **Given** the operator has set resource limits, a node selector, tolerations,
   or image pull secrets, **When** a Job is created, **Then** those settings
   are applied to it.

---

### User Story 3 - Several people share one authenticated deployment (Priority: P3)

A team runs one `audit-mcp` and connects to it from several machines. Each
person authenticates through the organisation's existing identity provider.
The server knows who is calling, applies per-caller limits, and audit-logs
scans against an identity.

**Why this priority**: It carries the largest new attack surface and is the
only piece that is useless on its own — a hosted server with no cluster
executor still needs a Docker socket. It should land last, on top of two
proven layers.

**Independent Test**: Start the server with the HTTP transport enabled and
confirm that an unauthenticated request is refused with a challenge naming the
authorization server, and that a request bearing a valid token for this
resource succeeds.

**Acceptance Scenarios**:

1. **Given** the HTTP transport is enabled, **When** an unauthenticated
   request arrives, **Then** it is rejected with a challenge identifying the
   authorization server and this server's resource identifier.
2. **Given** a valid access token issued for this resource, **When** a request
   arrives, **Then** it is served and the caller's identity is attached to the
   scan record.
3. **Given** a token that is expired, malformed, or issued for a *different*
   resource, **When** a request arrives, **Then** it is rejected — a token
   minted for another service must never be accepted here.
4. **Given** two callers scanning concurrently, **When** both scans run,
   **Then** neither can observe the other's target, findings, workspace, or
   credentials.
5. **Given** the stdio transport is in use, **When** the server starts,
   **Then** no HTTP listener is opened and no authentication is required —
   the existing single-user experience is unchanged.
6. **Given** a caller exceeds their configured concurrent-scan allowance,
   **When** they start another scan, **Then** it is refused or queued with a
   clear message, and other callers are unaffected.

---

### Edge Cases

**Cloning**

- A repository larger than the configured size or depth budget — the clone
  must stop and report rather than filling the disk.
- A repository whose history is huge but whose tree is small: shallow clone by
  default; full history only when a scanner demonstrably needs it (`gitleaks`
  history scanning is the one real case).
- Submodules, LFS pointers, and symlinks pointing outside the worktree. A
  symlink escape must not let a scanner read outside the clone.
- A URL that resolves to a private network address or a non-git service —
  server-side request forgery is a live risk once the server fetches arbitrary
  URLs on a caller's behalf.
- A credential that expires mid-scan, or an installation token that expires
  between clone and scan.
- Two concurrent scans of the same repository at different refs.
- Disk exhaustion from concurrent clones; cleanup after a crash rather than a
  clean shutdown.

**Kubernetes**

- The namespace's quota rejects the Job, or the image pull is denied.
- The cluster's default `runAsNonRoot` or a restricted Pod Security Standard
  conflicts with a scanner image that expects root.
- Logs truncated or rotated by the cluster before collection.
- The controller restarts mid-scan, leaving orphaned Jobs to reap.
- A network policy blocks a scanner's tool download, producing a confusing
  install failure rather than an obvious network error.

**Hosted transport**

- Token audience confusion: a token for another resource presented here.
- A caller whose identity is valid but who has no authorization to scan the
  requested target.
- Session resumption and long-lived scans that outlive an access token.
- Credential material appearing in a response: a clone URL with an embedded
  token, a scanner echoing an environment variable, a log line containing a
  key.

## Requirements *(mandatory)*

### Functional Requirements — Workspace provisioning

- **FR-001**: `run_scan` MUST accept, as `target`, a local path (today's
  behaviour, unchanged), an HTTPS or SSH git URL, or an `owner/repo`
  shorthand.
- **FR-002**: The system MUST resolve a requested ref (branch, tag, or commit)
  and MUST report the resolved commit SHA in the response, so a result can be
  tied to an exact revision.
- **FR-003**: The system MUST select a credential from the configured sources
  in a documented precedence order, and MUST report which source was used —
  never the credential itself.
- **FR-004**: With no credentials configured, the system MUST still clone
  public repositories.
- **FR-005**: The system MUST remove a cloned workspace after the scan
  completes, fails, or times out, and MUST reap orphaned workspaces left by an
  unclean shutdown.
- **FR-006**: The system MUST bound clone size, depth, and duration, and MUST
  report a `tool_error` naming the exceeded budget rather than exhausting the
  host.
- **FR-007**: Findings from a cloned workspace MUST carry repository-relative
  paths. No temporary directory or container mount prefix may appear in a
  finding location.
- **FR-008**: The system MUST refuse to clone a target that resolves to a
  private or link-local network address unless explicitly permitted by
  configuration.
- **FR-009**: The system MUST prevent a symlink inside a clone from exposing
  files outside the cloned workspace to a scanner.

### Functional Requirements — Execution backends

- **FR-010**: Scanner execution MUST be pluggable behind a single interface,
  with the local Docker backend as the default and Kubernetes as an
  alternative. The normalization, status, timeout, and summary logic MUST be
  shared by all backends rather than duplicated.
- **FR-011**: The Kubernetes backend MUST run each scanner as a Job in a
  configured namespace, authenticating with the in-cluster ServiceAccount when
  present and falling back to a kubeconfig.
- **FR-012**: The Kubernetes backend MUST deliver the workspace to the Job via
  a git-clone initContainer writing into an `emptyDir`, so no host path is
  mounted and no Docker socket is required.
- **FR-013**: The Kubernetes backend MUST apply the same isolation guarantees
  as the Docker backend: a read-only workspace, no privilege escalation,
  dropped capabilities, an explicit memory limit, and a wall-clock timeout.
- **FR-014**: The Kubernetes backend MUST honour operator-supplied resource
  requests and limits, node selectors, tolerations, service account name, and
  image pull secrets.
- **FR-015**: The Kubernetes backend MUST delete its Jobs when a scan ends,
  including on timeout and failure, and MUST reap Jobs orphaned by a
  controller restart.
- **FR-016**: A backend that cannot reach its infrastructure MUST report one
  clear preflight error, not one failure per selected scanner.
- **FR-017**: The status tool MUST report which backend is active and whether
  it is currently reachable.
- **FR-018**: A pod that is evicted, OOM-killed, or fails to schedule MUST be
  reported as `tool_error` or `timeout` with the cluster's reason attached —
  never as `clean`.

### Functional Requirements — Hosted transport and identity

- **FR-019**: The server MUST continue to support stdio as its default
  transport, with no listener opened and no authentication required.
- **FR-020**: The server MUST optionally serve MCP over streamable HTTP,
  enabled by explicit configuration.
- **FR-021**: When the HTTP transport is enabled, the server MUST act as an
  OAuth 2.1 Resource Server: it MUST advertise its authorization server and
  resource identifier, reject unauthenticated requests with a challenge, and
  validate every presented token.
- **FR-022**: The server MUST reject a token that is expired, malformed, or
  whose audience is not this server. Accepting a token minted for another
  resource is a defect, not a convenience.
- **FR-023**: The server MUST NOT implement its own user database or password
  storage. Identity is delegated to an external provider.
- **FR-024**: The server MUST isolate concurrent callers: no caller may
  observe another's target, workspace, findings, or credentials.
- **FR-025**: The server MUST apply per-caller limits on concurrent scans, and
  MUST refuse or queue past that limit with a clear message rather than
  degrading service for everyone.
- **FR-026**: The server MUST record an audit entry per scan containing the
  caller identity, target, resolved ref, scanners run, and outcome.

### Functional Requirements — Secret hygiene (cross-cutting)

- **FR-027**: Credential material MUST NOT appear in any response field,
  including raw logs, execution metadata, findings, and error messages. Known
  secret values MUST be redacted from captured output before it leaves the
  process.
- **FR-028**: A credential MUST NOT be embedded in a URL that could be written
  to a log, a git remote, or a Kubernetes object.
- **FR-029**: Credentials MUST reach an execution backend by the narrowest
  available mechanism, and MUST NOT be readable by scanner containers that
  were not granted them.
- **FR-030**: Tokens minted for a clone MUST be short-lived, and MUST be
  discarded with the workspace.

### Key Entities

- **Workspace**: A directory a scan runs against, either a caller-supplied
  local path or a provisioned clone. Knows its origin, its resolved commit,
  its cleanup obligation, and its size budget.
- **Workspace Source**: How a workspace comes into being — local path, git
  clone over HTTPS, git clone over SSH. Resolves a target expression to
  something scannable.
- **Credential Source**: A configured way to authenticate a clone — GitHub
  App installation, SSH key, token, or anonymous. Produces a short-lived
  credential and a name for reporting; never surfaces the secret.
- **Executor**: A backend that runs one scanner against one workspace and
  returns its output, exit code, and duration. Local Docker or Kubernetes Job.
- **Execution Environment**: The operator-controlled settings an executor
  applies — namespace, resource limits, scheduling constraints, pull secrets,
  concurrency ceiling.
- **Caller Identity**: Who is making a request on the hosted transport, from a
  validated token. Carries the subject, the limits that apply, and what goes
  into the audit record.
- **Scan Record**: The audit trail for one scan — caller, target, resolved
  ref, scanners, outcome, timing.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An existing stdio user who upgrades and changes no configuration
  observes identical behaviour: same tools, same default backend, no listener,
  no authentication, no new required environment variable.
- **SC-002**: A caller can scan a public repository they have never checked
  out, in a single tool call, with zero configuration.
- **SC-003**: For every scanner in the verified set, a scan of the same fixture
  produces equivalent normalized findings under the Docker and Kubernetes
  backends — same rule IDs, same severities, same repository-relative paths.
- **SC-004**: No response field, in any mode, contains credential material.
  This is verified by a test that seeds a recognisable secret into every
  configured credential source and asserts it appears nowhere in a serialized
  response.
- **SC-005**: 100% of provisioned workspaces are removed after the scan ends,
  including on failure, timeout, and process restart.
- **SC-006**: A request bearing a token issued for a different resource is
  rejected, demonstrated by a test.
- **SC-007**: With no reachable backend, the server still starts and answers
  the catalog, status, and explanation tools, and a scan attempt returns one
  actionable error.
- **SC-008**: Adding a third execution backend requires no change to
  normalization, status determination, or response shaping.
- **SC-009**: The default `cargo test` run remains hermetic — no Docker, no
  cluster, no network — and every new dependency-requiring test self-skips
  with a message when its dependency is unreachable.

## Assumptions

- The three capabilities are independent and shippable in priority order. Each
  is off by default and enabled by explicit configuration.
- Local-path scanning over stdio with the Docker backend remains the default
  and the most-used path. No change may regress it.
- Identity is delegated to an existing external provider. This feature will not
  store passwords or issue its own long-lived credentials.
- Operators running the Kubernetes backend own the namespace, its quotas, and
  its network policy. The server configures its Jobs but does not create
  namespaces, RBAC, or policy on their behalf.
- The existing scanner catalog, parsers, statuses, and summary shaping are
  reused unchanged by every new mode. A finding must not be distinguishable by
  the backend that produced it.
- Git is available to the clone path, whether as a library or a binary in the
  clone container.
- A single deployment serves a team, not the public internet. Multi-tenancy
  means colleagues, and the isolation requirements are scoped to that.

## Out of Scope

- Any web UI. This remains an MCP server.
- Storing scan history, trend analysis, or a findings database. `Scan Record`
  is an audit log entry, not a reporting product.
- Writing fixes back to a repository, opening pull requests, or pushing
  commits. The workspace stays read-only, in every mode.
- Autoscaling, sharding, or multi-cluster scheduling.
- Acting as an OAuth *authorization* server, or any credential storage of our
  own.
- Scanning anything other than a git repository or a local directory.
