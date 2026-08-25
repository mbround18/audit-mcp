# Contract: HTTP transport and OAuth resource server

Active only when `AUDIT_TRANSPORT=http`. On stdio none of this exists — no
listener is opened and no token is required (FR-019).

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/mcp` | Required | MCP streamable HTTP endpoint |
| `GET` | `/mcp` | Required | Server-initiated stream (SSE) |
| `DELETE` | `/mcp` | Required | Terminate session |
| `GET` | `/.well-known/oauth-protected-resource` | None | RFC 9728 metadata |
| `GET` | `/healthz` | None | Liveness — no scanner or cluster state |
| `GET` | `/readyz` | None | Readiness — backend reachable |
| `GET` | `/metrics` | None (bindable separately) | Prometheus exposition |

`/healthz` and `/readyz` are deliberately distinct: an unreachable Docker
daemon or cluster makes the server *not ready* but still *alive*, and killing
it would not help (constitution V).

## Protected resource metadata

`GET /.well-known/oauth-protected-resource` returns, unauthenticated:

```jsonc
{
  "resource": "https://audit.example.com/mcp",   // AUDIT_RESOURCE_URL
  "authorization_servers": ["https://idp.example.com"],
  "scopes_supported": ["audit:scan"],
  "bearer_methods_supported": ["header"]
}
```

## Unauthenticated request

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://audit.example.com/.well-known/oauth-protected-resource"
```

This is what lets a compliant MCP client discover where to authenticate without
being told out of band. `rmcp`'s client-side auth module consumes exactly this
header, so a standard client bootstraps itself.

## Token validation

Every authenticated request, in order. Any failure is `401`, with no detail
about *which* check failed.

1. `Authorization: Bearer <token>` present and well-formed.
2. **JWT** — signature verified against cached JWKS; algorithm on an allowlist
   (`alg: none` rejected); `iss` matches the configured issuer; `exp` and `nbf`
   valid. JWTs are the only supported token form in the first release; opaque
   tokens and RFC 7662 introspection are deferred.
3. **Audience** — `aud` contains `AUDIT_RESOURCE_URL`.
4. **Scope** — contains `AUDIT_OAUTH_REQUIRED_SCOPE` when configured.

Step 3 is not optional and not a formality. A token minted for a *different*
resource, by the same issuer, must be rejected — otherwise any service sharing
the identity provider can be used to drive this one. Rejecting it is SC-006,
and it gets a dedicated test.

| Condition | Status |
|-----------|--------|
| No token | `401` + challenge |
| Invalid signature, expired, wrong issuer | `401` |
| Wrong audience | `401` |
| Valid token, missing required scope | `403` |
| Valid, but per-caller concurrency exceeded | `429` + `Retry-After` |
| Valid, but caller cannot read the requested repository | `403`, with no indication of whether it exists |

## Authorization

Authentication answers *who*; it does not answer *what they may scan*. Before a
server-held clone credential touches a remote target, the caller's own identity
must be shown to grant read access to it (FR-031–FR-035). A refusal is recorded
in the scan record like any other outcome.

## Metrics endpoint

`GET /metrics` returns Prometheus exposition covering scans by terminal status,
scan and per-scanner durations, backend reachability, in-flight executions and
queue depth, and per-caller rejections.

It requires no MCP token and is bindable separately from the MCP endpoint, so
an operator can expose it only to their scrape infrastructure. Because it is
deliberately less protected, label values must never carry a repository name,
target URL, caller subject, or file path (FR-038) — those would both explode
cardinality and publish private repository names.

## Session and identity

- A session is bound to the caller identity that created it. A different
  identity may not resume it.
- A scan already running when its token expires is allowed to finish; a *new*
  request needs a valid token. Killing a five-minute scan because a token
  aged out would be user-hostile and would not improve security.
- Every scan writes a Scan Record carrying the caller subject (FR-026).

## Transport-level expectations

- TLS is expected to be terminated in front of this server (ingress, mesh, or
  reverse proxy). The server does not implement TLS itself, and binds to
  loopback by default so that shipping it publicly without a proxy takes a
  deliberate act.
- Request bodies are size-limited; MCP payloads are small and an unbounded body
  is a denial-of-service vector.
- Origin is validated to prevent DNS-rebinding against a locally-bound server.
