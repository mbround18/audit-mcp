# Contract: Configuration surface

Every variable below is **optional**. With none of them set, `audit-mcp`
behaves exactly as it does today: stdio transport, Docker backend, local paths
only, no authentication (SC-001).

## Execution backend

| Variable | Values | Default | Effect |
|----------|--------|---------|--------|
| `AUDIT_EXECUTOR` | `docker`, `kubernetes` | `docker` | Which backend runs scanners |
| `AUDIT_MAX_PARALLEL` | integer | `4` | Concurrent executions (already effective via `run_scan`) |

### Kubernetes backend

Used only when `AUDIT_EXECUTOR=kubernetes`. Cluster credentials come from the
in-cluster ServiceAccount when present, otherwise the ambient kubeconfig — no
variable selects between them.

| Variable | Default | Effect |
|----------|---------|--------|
| `AUDIT_K8S_NAMESPACE` | current namespace, else `default` | Where Jobs are created |
| `AUDIT_K8S_SERVICE_ACCOUNT` | namespace default | Identity Jobs run as |
| `AUDIT_K8S_CPU_REQUEST` / `AUDIT_K8S_CPU_LIMIT` | unset | Applied to scanner containers |
| `AUDIT_K8S_MEMORY_REQUEST` / `AUDIT_K8S_MEMORY_LIMIT` | `4Gi` limit | Matches the Docker backend's ceiling |
| `AUDIT_K8S_NODE_SELECTOR` | unset | `key=value,key=value` |
| `AUDIT_K8S_TOLERATIONS` | unset | Applied verbatim |
| `AUDIT_K8S_IMAGE_PULL_SECRETS` | unset | Comma-separated secret names |
| `AUDIT_K8S_JOB_TTL_SECONDS` | `300` | `ttlSecondsAfterFinished`, a backstop for cleanup |

## Remote repositories

| Variable | Default | Effect |
|----------|---------|--------|
| `AUDIT_ALLOW_REMOTE_TARGETS` | `true` when any credential source is configured, else `true` for public HTTPS | Master switch for cloning |
| `AUDIT_CLONE_MAX_BYTES` | `2GiB` | Clone size budget |
| `AUDIT_CLONE_DEPTH` | `1` | Shallow by default |
| `AUDIT_CLONE_TIMEOUT_SECS` | `300` | Clone wall-clock budget |
| `AUDIT_ALLOW_PRIVATE_ADDRESSES` | `false` | Permit targets resolving to private/loopback/link-local addresses. Only for self-hosted git on an internal network; it disables an SSRF control (FR-008). |

### Credential sources

Precedence: GitHub App → token → SSH key → anonymous.

| Variable | Source |
|----------|--------|
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_INSTALLATION_ID` | GitHub App installation token. All three required; a partial set is a startup error, not a silent fallback. |
| `GITHUB_TOKEN` | Token / PAT over HTTPS |
| `SSH_PRIVATE_KEY` | Key for git-over-SSH |
| `SSH_KNOWN_HOSTS` | Host key verification material. Absent, host key checking is **not** silently disabled; the clone fails with an explanation. |

A partial GitHub App configuration failing loudly is deliberate: silently
falling through to anonymous would turn a misconfiguration into a confusing
"repository not found".

## Transport

| Variable | Default | Effect |
|----------|---------|--------|
| `AUDIT_TRANSPORT` | `stdio` | `stdio` or `http` |
| `AUDIT_HTTP_BIND` | `127.0.0.1:8080` | Listen address. Loopback by default — binding publicly must be a deliberate act. |
| `AUDIT_RESOURCE_URL` | — | This server's canonical resource identifier. **Required** when `AUDIT_TRANSPORT=http`; token audience is validated against it. |

### Authentication

Required when `AUDIT_TRANSPORT=http`. There is no unauthenticated HTTP mode:
serving MCP tools that execute containers over an open port is not a
configuration we offer.

| Variable | Effect |
|----------|--------|
| `AUDIT_OAUTH_ISSUER` | Authorization server issuer URL; metadata is discovered from it |
| `AUDIT_OAUTH_JWKS_URL` | Override JWKS location (default: discovered) |
| `AUDIT_OAUTH_REQUIRED_SCOPE` | Scope a token must carry |
| `AUDIT_MAX_SCANS_PER_CALLER` | Per-caller concurrent scan ceiling (default `2`) |
| `AUDIT_AUTHZ_CACHE_TTL_SECS` | How long a per-caller repository access decision may be cached (default `300`) |

Only JWT-issuing OIDC providers are supported in the first release. There is no
introspection configuration because opaque tokens are out of scope (FR-021a).

## Observability

| Variable | Default | Effect |
|----------|---------|--------|
| `AUDIT_METRICS_BIND` | same listener as MCP | Bind the Prometheus endpoint separately so it can be exposed only to scrape infrastructure |
| `AUDIT_LOG_FORMAT` | `json` | Structured log format |
| `AUDIT_LOG_LEVEL` | `info` | Server log verbosity |

On the stdio transport, server logs go to stderr. Writing them to stdout would
corrupt the JSON-RPC protocol stream (FR-036).

## Startup validation

The server validates configuration at startup and **fails to start** on an
incoherent combination, rather than failing later on a request:

- `AUDIT_TRANSPORT=http` without `AUDIT_RESOURCE_URL` or `AUDIT_OAUTH_ISSUER`
- A partial `GITHUB_APP_*` set
- `AUDIT_EXECUTOR` naming an unknown backend

This is the one place where "degrade, don't disappear" (constitution V) does
not apply, and the distinction is worth stating: an *unreachable dependency* is
a runtime condition to report, but an *incoherent configuration* is an operator
error that will only produce confusing failures later. Refuse it at the door.
