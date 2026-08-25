# Phase 0 Research: Hosted execution modes

All findings below were checked against the crate sources vendored in this
machine's cargo registry, not from memory. Where something was not verified, it
says so.

## R1. Does `rmcp` support a server-side HTTP transport?

**Decision**: Yes — enable the `transport-streamable-http-server` feature and
mount `StreamableHttpService` in a `tower`/`axum` stack. Stay on `rmcp 1.7`.

**Verified**: `rmcp-1.7.0` exposes a `transport-streamable-http-server` feature
and `StreamableHttpService<S, M>`, which implements
`tower_service::Service<Request<RequestBody>>`
(`src/transport/streamable_http_server/tower.rs:520`). That is exactly the seam
needed to wrap MCP in ordinary HTTP middleware.

**Rationale**: The existing stdio path is untouched; the HTTP transport becomes
one more way to serve the same `AuditMcpServer`. Because it is a tower service,
authentication is a layer around it rather than a fork of the handler code.

**Alternatives considered**: The older SSE server transport — superseded by
streamable HTTP in the MCP spec. Writing a bespoke HTTP layer — pointless when
the crate already yields a tower service.

**Upgrade note**: `rmcp` 2.x and 3.x exist (3.1.4 is in the local registry). Their
auth story is identical to 1.7's (see R2), so there is no reason to take a major
upgrade *for this feature*. Upgrading `rmcp` is worthwhile but orthogonal, and
mixing it into this change would make a transport bug and a migration bug
indistinguishable.

## R2. Does `rmcp` provide server-side OAuth validation?

**Decision**: No. We implement the Resource Server role ourselves as a tower
layer.

**Verified**: `src/transport/auth.rs` in both 1.7.0 and 3.1.4 is entirely
*client*-side: it parses `WWW-Authenticate`, discovers an authorization server
from resource metadata, and drives the `oauth2` crate to obtain a token
(`discover_oauth_server_via_resource_metadata`, `select_scopes`). There is no
token *validation* path and no protected-resource metadata endpoint.

**What we must build**:

1. A protected resource metadata document (RFC 9728) advertising the
   authorization server(s) and this server's resource identifier.
2. A `WWW-Authenticate` challenge on unauthenticated requests pointing at that
   metadata.
3. Token validation on every request, including **audience** validation.

**Rationale**: This is a small, well-specified amount of work, and it is the
part that must be correct. The confused-deputy risk — accepting a token minted
for a different resource — is the single most likely security defect in this
feature, which is why FR-022 and SC-006 call it out explicitly rather than
folding it into "validate the token".

## R3. How should tokens be validated?

**Decision**: Support both, JWT-first. Validate JWTs locally against the
provider's JWKS with cached keys; fall back to RFC 7662 token introspection
when the provider issues opaque tokens.

**Rationale**: Most providers (Entra, Auth0, Okta, Keycloak) issue JWTs, and
local validation costs no network round trip per request. GitHub issues opaque
tokens, and GitHub is the most likely provider here given the rest of the
feature — so introspection cannot be skipped.

**Alternatives considered**: JWT-only, which would exclude GitHub as an IdP.
Introspection-only, which adds a provider round trip to every MCP call and
makes the provider a hard availability dependency.

**Care required**: Cache JWKS with a bounded TTL and handle key rotation;
validate `iss`, `aud`, `exp`, and `nbf`; reject `alg: none` and any algorithm
not on an allowlist.

## R4. Kubernetes client and workload shape

**Decision**: `kube` + `k8s-openapi`, creating one `batch/v1` Job per scanner
run. Authenticate with the in-cluster ServiceAccount when present, falling back
to kubeconfig — `kube::Client::try_default()` already implements exactly that
precedence.

**Not verified locally**: `kube` is not currently a dependency and is not in the
local registry. Its API surface here is from prior knowledge; the plan assumes
`Api::<Job>::namespaced`, a watcher for completion, and `logs` for output
retrieval. First implementation task should confirm.

**Rationale for Job over bare Pod**: `backoffLimit` and
`ttlSecondsAfterFinished` give us bounded retries and automatic cleanup even if
our controller dies mid-scan — which matters because FR-015 requires reaping
orphans. A bare Pod would need us to reimplement both.

**Workspace delivery**: a git-clone initContainer writes into an `emptyDir` that
the scanner container mounts **read-only**. This keeps FR-013's isolation
guarantee identical to the Docker path and requires no host mount, no PVC, and
no Docker socket.

**Alternatives considered**: A shared PVC across scanners in one scan — avoids
re-cloning per scanner, but introduces a ReadWriteMany storage requirement that
many clusters cannot satisfy, plus cross-scanner interference. Revisit only if
clone cost measurably dominates.

## R5. Cloning: library or the `git` binary?

**Decision**: Shell out to `git` in the local case, and use a standard
git-capable image for the Kubernetes initContainer.

**Rationale**: The Kubernetes path *must* use a binary anyway — the
initContainer runs `git clone`, not our process. Using the same mechanism in
both paths means one set of semantics for shallow clones, refs, submodules, and
LFS, rather than two subtly different ones. `git` also handles SSH host key and
credential-helper behaviour that we would otherwise reimplement.

**Alternatives considered**: `gix` (pure Rust, no subprocess, but partial
support for LFS and some transport edge cases) and `git2`/libgit2 (mature, but
adds a C dependency and still needs separate SSH handling). Neither removes the
need for a binary in the cluster path.

**Consequence**: `git` becomes a runtime dependency of the clone feature. It is
absent from a scratch container, so the shipped image must include it, and the
status tool should report its availability rather than failing a scan late.

## R6. GitHub App authentication

**Decision**: Sign a short-lived JWT with the app private key (RS256, ≤10 minute
expiry), exchange it for an installation access token, cache that token until
shortly before its expiry, and use it as an HTTP basic password for the clone.

**Care required**: Installation tokens last one hour. A long scan can outlive
one, so the token must be fetched immediately before the clone and never
refreshed into a running scanner. Since the workspace is cloned once up front
and scanners only read it, this is naturally safe — but it constrains any future
design that re-fetches mid-scan.

**Credential precedence** (FR-003): explicit request-scoped credential, then
GitHub App, then `GITHUB_TOKEN`/PAT, then SSH key, then anonymous. Report the
name of the source used, never the value.

## R7. Keeping secrets out of responses

**Decision**: A redaction pass over every captured log and error string before
it can be serialized, seeded from the set of secret values the process knows.

**Rationale**: FR-027 cannot be satisfied by discipline alone. Scanner output is
arbitrary text from third-party tools; any of them may echo an environment
variable or a remote URL. The only reliable enforcement point is the boundary
where captured output becomes a response field.

**Care required**: Never embed a credential in a remote URL (FR-028) — it would
otherwise reach `.git/config`, a Kubernetes object, and a log line at once. Use
a credential helper or an HTTP header instead. In Kubernetes, mount credentials
from a Secret rather than passing them as environment variables in a Job spec,
because a Job spec is readable by anyone with `get jobs` in the namespace.

**Test strategy for SC-004**: seed a recognisable sentinel value into every
credential source, run a scan, serialize the whole response, and assert the
sentinel appears nowhere. This catches leaks through paths nobody anticipated,
which is the entire point.

## R8. SSRF and target validation

**Decision**: Parse and validate the target before any network call — allowed
schemes only, resolve the host, and reject private, loopback, and link-local
addresses unless an operator explicitly opts in.

**Rationale**: The moment the server fetches a URL on a caller's behalf, it can
be used to reach things the caller cannot. This matters much more in the hosted
mode (P3), where the caller is not the operator — but the check belongs with the
clone code (P1) so it exists before it is needed.

**Care required**: Resolve-then-check is subject to DNS rebinding. Bind the
resolved address for the actual connection, or re-check after resolution.

## R9. Shape of the executor abstraction

**Decision**: A trait with one method — run one scanner against one prepared
workspace, return raw output, exit code, and duration. Everything else stays
where it is.

**Rationale**: The current runner conflates four things: workspace resolution,
container lifecycle, output parsing, and status determination. Only the
container lifecycle differs between Docker and Kubernetes. If the seam is drawn
there, normalization, status rules, timeout semantics, and summary shaping are
shared by construction — which is what SC-003 (identical findings across
backends) and SC-008 (a third backend changes no shared logic) actually require.

**Alternatives considered**: A trait returning finished `ScannerRunResult`s.
Rejected: it would let each backend invent its own status rules, and the whole
point of the constitution's first principle is that those rules live in exactly
one place.

**Note on caching**: the Docker backend's named cache volumes have no direct
Kubernetes equivalent. The first implementation should accept a cold cache in
the cluster (correctness first) and treat persistent caching as a follow-up.

## Open questions for implementation

- Does `kube`'s log API return the same interleaving behaviour as Docker's?
  The Docker path had to separate stdout from stderr because interleaving
  corrupted gosec's SARIF. The Kubernetes equivalent must be checked, not
  assumed — if pod logs are already merged, some scanners will need their
  stderr redirected in the command instead.
- Which identity provider is the first target? It determines whether the
  introspection path (R3) is needed on day one or can follow.
- Should a `mode=all` scan of a cloned repository run one clone shared by all
  scanners (cheaper) or one per scanner (simpler isolation)? Shared is assumed;
  confirm it does not break scanners that write to the workspace root.
