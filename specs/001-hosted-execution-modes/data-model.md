# Phase 1 Data Model: Hosted execution modes

Entities are described by what they mean and what must be true of them, not by
their eventual Rust field layout. Where an existing type changes, the change is
called out.

## Workspace

A directory a scan runs against.

| Attribute | Meaning |
|-----------|---------|
| `root` | Absolute path the scanners see |
| `origin` | How it came to exist (see **Workspace Origin**) |
| `resolved_ref` | Commit SHA actually scanned; `None` for a local path |
| `owned` | Whether this process must delete it |

**Rules**

- An owned workspace is deleted when the scan ends — success, failure, or
  timeout (FR-005). Deletion is the responsibility of whoever created it, and
  must not depend on the happy path being taken.
- A workspace not owned by us (a caller's local directory) is never deleted or
  modified.
- `resolved_ref` is reported in the response so a result can be tied to an
  exact revision (FR-002).
- A workspace root is canonicalized before use, and a symlink inside it must
  not resolve to a path outside it (FR-009).

**Lifecycle**

```
requested → provisioning → ready → in-use → released
                  │                            │
                  └──── failed ────────────────┘
                        (still released)
```

The `failed → released` edge is the one that matters: a clone that dies halfway
still leaves bytes on disk.

## Workspace Origin

Discriminates how a workspace was obtained, and carries what reporting needs.

| Variant | Carries |
|---------|---------|
| `LocalPath` | The caller-supplied path |
| `GitHttps` | Normalized URL, requested ref, credential source name |
| `GitSsh` | Normalized URL, requested ref, credential source name |

**Rules**

- The credential *source name* is reported; the credential is not (FR-003).
- A normalized URL never contains embedded credentials (FR-028).

## Target Expression

The parsed form of the `target` argument, produced before any I/O.

| Form | Example |
|------|---------|
| Local path | `/home/me/project`, `./src` |
| HTTPS git URL | `https://github.com/owner/repo` |
| SSH git URL | `git@github.com:owner/repo.git`, `ssh://git@host/owner/repo` |
| Shorthand | `owner/repo` |

**Rules**

- Parsing is total and side-effect free: it never touches the network or the
  filesystem, so it is exhaustively unit-testable.
- An optional ref may be attached (`…#branch`, `…#v1.2.3`, `…#<sha>`).
- Ambiguity resolves toward the existing behaviour: anything that names an
  existing local path is a local path. This guarantees no current caller's
  target changes meaning.
- A remote form is rejected before any connection if its host resolves to a
  private, loopback, or link-local address, unless explicitly permitted
  (FR-008).

## Credential Source

A configured way to authenticate a clone.

| Variant | Configuration | Produces |
|---------|---------------|----------|
| `GitHubApp` | app id, private key, installation id | Short-lived installation token |
| `SshKey` | private key material | Key available to `git` for one clone |
| `Token` | token value | HTTP credential |
| `Anonymous` | — | Nothing |

**Rules**

- Precedence is fixed and documented: request-scoped → GitHub App → token →
  SSH key → anonymous (FR-003).
- Every variant exposes a stable `name` for reporting and a secret that is
  never serialized. The type must make "print this" impossible rather than
  merely discouraged — a `Debug` implementation that prints a secret is a
  defect.
- Minted tokens are short-lived and discarded with the workspace (FR-030).
- No credential is embedded in a URL, a git remote, or a Kubernetes object
  (FR-028, FR-029).

## Executor

Runs one scanner against one prepared workspace.

**Contract**

```
run(request) -> outcome
```

| `ExecutionRequest` | |
|--------------------|---|
| `scanner` | The scanner definition (image, command, timeout, exit codes) |
| `workspace` | Where the code is |
| `environment` | Allowlisted variables for this scanner |
| `timeout` | Wall-clock ceiling |

| `ExecutionOutcome` | |
|--------------------|---|
| `stdout` | Captured stdout, kept separate |
| `combined` | Captured stdout+stderr, for humans |
| `exit_code` | `None` if killed |
| `duration` | Wall-clock elapsed |
| `termination` | Completed, TimedOut, or Infrastructure(reason) |

**Rules**

- The executor returns **no status and no findings**. Status determination and
  normalization stay in the shared layer, so two backends cannot drift
  (constitution I, R9).
- `stdout` stays separate from `combined` in every backend. This is not an
  implementation detail: merging them corrupted gosec's SARIF in the Docker
  path, and the Kubernetes path must be checked for the same behaviour rather
  than assumed safe.
- `Infrastructure(reason)` carries the backend's own words — an eviction
  message, an image pull failure — so the resulting `tool_error` is
  diagnosable.
- Every backend enforces the same isolation guarantees; a backend that cannot
  is not a backend.

## Execution Environment

Operator-controlled settings a backend applies. Mostly meaningful for
Kubernetes.

| Attribute | Meaning |
|-----------|---------|
| `namespace` | Where Jobs are created |
| `service_account` | Identity Jobs run as |
| `resource_limits` | CPU and memory requests/limits |
| `scheduling` | Node selector, tolerations |
| `image_pull_secrets` | For private scanner images |
| `max_concurrent` | Ceiling on simultaneous executions |

**Rules**

- Operator-supplied values are applied verbatim (FR-014); we do not second-guess
  a cluster's own policy.
- We configure our Jobs. We do not create namespaces, RBAC, or network policy.

## Caller Identity

Who is making a request on the hosted transport.

| Attribute | Meaning |
|-----------|---------|
| `subject` | Stable identifier from the validated token |
| `issuer` | Which authorization server minted it |
| `limits` | Concurrency and any per-caller restriction |

**Rules**

- Present only on the HTTP transport. On stdio there is no identity and none is
  required (FR-019).
- Constructed only from a token that passed full validation, **including
  audience** (FR-022). A token minted for another resource yields no identity.
- Two callers' scans share no workspace, no findings, and no credentials
  (FR-024).

## Scan Record

The audit trail for one scan.

| Attribute | Meaning |
|-----------|---------|
| `caller` | Identity, or `local` on stdio |
| `target` | The requested target expression |
| `resolved_ref` | Commit actually scanned, if remote |
| `scanners` | Which ran |
| `outcome` | Per-scanner statuses and the severity rollup |
| `timing` | Start and duration |

**Rules**

- Written for every scan on the hosted transport (FR-026).
- Contains no credential material and no finding bodies — it is an audit
  record, not a findings database (spec: Out of Scope).

## Changes to existing types

| Type | Change | Compatibility |
|------|--------|---------------|
| `RunScanResponse` | Gains `workspace` (origin + resolved ref) | Additive |
| `ScanExecution` | Gains `backend` naming the executor used | Additive |
| `AuditStatusResponse` | Gains active backend, its reachability, `git` availability, and configured credential source names | Additive |
| `ScannerDefinition` | Unchanged | — |
| `NormalizedFinding` | Unchanged | — |
| `RunStatus` | Unchanged — new failures map to existing variants | — |

That `RunStatus` and `NormalizedFinding` need no change is the design working
as intended: a finding must not be distinguishable by the backend that produced
it, and no new failure mode deserves a new way to say "this did not work".
