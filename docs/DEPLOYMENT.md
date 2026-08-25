# Deploying audit-mcp

Two shapes, and the difference matters more than it looks.

**Local** — one binary on a developer's machine, speaking MCP over stdio, running
scanners in local Docker. No listener, no authentication, no manifests. This is
the default and needs nothing on this page.

**Hosted** — a deployment several people share. Everything below is about that,
and it exists mainly to say one thing clearly: **do not mount a Docker socket
into it.** That would hand every scanner image — 95 pieces of third-party
tooling — root on the node. The Kubernetes backend exists precisely so you do
not have to.

## What the pieces are

| Piece | Why |
| ----- | --- |
| Deployment | The server itself. Needs no privileges beyond its own namespace |
| ServiceAccount + Role + RoleBinding | Lets it create the Jobs that scanners run in |
| Secret | Clone credentials, if you scan private repositories |
| Service | Reaching `/mcp`; optionally a second port for `/metrics` |

Scanners are **not** pods you deploy. The server creates a Job per scanner run
and deletes it afterwards.

## Namespace and identity

Give it a namespace of its own. Everything it creates lands there, and the
blast radius of a misbehaving scanner image is that namespace.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: audit
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: audit-mcp
  namespace: audit
```

## RBAC

Narrow on purpose. The server creates and reaps Jobs and reads their pods'
logs; it has no business doing anything else, and this Role is the difference
between "a scanner misbehaved" and "a scanner misbehaved with cluster access".

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: audit-mcp
  namespace: audit
rules:
  # Jobs are how scanners run, and reaping them is how they stop accumulating.
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "delete"]
  # Pods and their logs: the logs *are* the scanner output.
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  # Clone credentials are staged as a short-lived Secret per scan, never in the
  # Job spec — a Job spec is readable by anyone with `get jobs` here.
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: audit-mcp
  namespace: audit
subjects:
  - kind: ServiceAccount
    name: audit-mcp
    namespace: audit
roleRef:
  kind: Role
  name: audit-mcp
  apiGroup: rbac.authorization.k8s.io
```

Note there is no ClusterRole. If you need to scan into other namespaces, add a
RoleBinding there rather than widening this to cluster scope.

**This Role has been verified against a live cluster**, not just derived from
reading the code: a ServiceAccount bound to exactly these rules, with a token
minted for it and nothing else in its kubeconfig, ran a five-scanner scan to
completion. The same identity is correctly refused `create pods`, `get nodes`,
`list secrets`, and `create deployments`.

Two things are easy to over-grant and are deliberately absent:

- **No `watch`.** Completion is polled with `get`, so `watch` buys nothing.
- **No `get`/`list` on secrets.** The server creates and deletes the clone
  credential Secret; it never needs to read one back, including its own.

## Credentials

Only if you scan private repositories. On the hosted transport each caller
supplies their own credential per request, so this is for the stdio-style
deployment where the server holds one.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: audit-mcp-credentials
  namespace: audit
type: Opaque
stringData:
  # One of these, not all. See docs/SECURITY.md for the precedence order.
  GITHUB_TOKEN: "ghp_..."
  # GITHUB_APP_ID: "123456"
  # GITHUB_APP_INSTALLATION_ID: "654321"
  # GITHUB_APP_PRIVATE_KEY: |
  #   -----BEGIN RSA PRIVATE KEY-----
  #   ...
```

## The Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audit-mcp
  namespace: audit
spec:
  replicas: 1
  selector:
    matchLabels: { app: audit-mcp }
  template:
    metadata:
      labels: { app: audit-mcp }
    spec:
      serviceAccountName: audit-mcp
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: audit-mcp
          image: ghcr.io/mbround18/audit-mcp:latest
          env:
            - name: AUDIT_EXECUTOR
              value: kubernetes
            - name: AUDIT_K8S_NAMESPACE
              value: audit
            - name: AUDIT_TRANSPORT
              value: http
            - name: AUDIT_HTTP_BIND
              value: 0.0.0.0:8080
            - name: AUDIT_RESOURCE_URL
              value: https://audit.example.com/mcp
            - name: AUDIT_OAUTH_ISSUER
              value: https://idp.example.com
            - name: AUDIT_OAUTH_REQUIRED_SCOPE
              value: audit:scan
            # Metrics on their own port, so the Service can expose /mcp
            # publicly and leave this one to the scrape network.
            - name: AUDIT_METRICS_BIND
              value: 0.0.0.0:9090
          envFrom:
            - secretRef:
                name: audit-mcp-credentials
                optional: true
          ports:
            - { name: mcp, containerPort: 8080 }
            - { name: metrics, containerPort: 9090 }
          # Liveness and readiness are deliberately different questions. An
          # unreachable cluster makes the server *not ready*; restarting it
          # would not help, so it must not fail liveness.
          livenessProbe:
            httpGet: { path: /healthz, port: mcp }
          readinessProbe:
            httpGet: { path: /readyz, port: mcp }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false  # clones are written to a temp dir
            capabilities: { drop: ["ALL"] }
          resources:
            requests: { cpu: 100m, memory: 256Mi }
            limits: { memory: 1Gi }
      # There is no Docker socket here, and there must not be.
```

Note the image needs `git` — the clone path shells out to it, and the shipped
image includes it for exactly that reason. A slimmer image without `git` fails
every repository target at the last moment rather than at startup.

## Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: audit-mcp
  namespace: audit
spec:
  selector: { app: audit-mcp }
  ports:
    - { name: mcp, port: 443, targetPort: mcp }
```

Terminate TLS at your ingress; the server does not implement it. Expose only
the `mcp` port here. `/metrics` should be reachable from your scrape
infrastructure and nothing else — a separate Service with an internal-only
annotation, or a ServiceMonitor pointing at port 9090 directly.

## Sizing the scanner Jobs

The server's own resource requests are small; the *scanners* are what consume
the cluster. Each Job gets a 4 GiB memory limit by default, matching the local
Docker backend.

```yaml
- { name: AUDIT_K8S_MEMORY_LIMIT, value: "4Gi" }
- { name: AUDIT_K8S_CPU_LIMIT,    value: "2" }
- { name: AUDIT_K8S_NODE_SELECTOR, value: "workload=build" }
- { name: AUDIT_MAX_PARALLEL,     value: "4" }
```

`AUDIT_MAX_PARALLEL` bounds concurrent Jobs per scan. A `mode=all` scan of a
polyglot repository can select seventeen scanners; without a cap that is
seventeen Jobs at once. Set a ResourceQuota on the namespace as a backstop —
the server respects the cluster's answer, and a rejected Job surfaces as a
`tool_error` naming the reason rather than as a mysterious hang.

## Verifying it

```bash
# Reachable, and the backend is up
curl -s https://audit.example.com/readyz

# Discovery answers without a token, or no client can bootstrap
curl -s https://audit.example.com/.well-known/oauth-protected-resource | jq

# An unauthenticated call is challenged, not served
curl -i -X POST https://audit.example.com/mcp
```

During a scan, Jobs appear and then go:

```bash
kubectl -n audit get jobs -w
```

After it, the namespace should be empty. Jobs are deleted on every path, with
`ttlSecondsAfterFinished` as a backstop for a controller that dies mid-scan. If
Jobs are accumulating, that is a bug worth reporting.

## Scans start cold

Each Job repeats whatever install its scanner does at run time; there is no
persistent cache in the cluster yet, so budget for that on the Rust and Go
tiers in particular. Findings are unaffected — the two backends are verified to
produce identical results — but a cluster scan is slower than the same scan
locally with a warm cache. Tracked as
[#6](https://github.com/mbround18/audit-mcp/issues/6).

## Two things that will bite you

**A local path cannot be scanned by a cluster.** The cluster cannot see the
machine the request came from. The backend refuses a local path and says so
rather than scanning an empty directory and calling it clean. Pass a repository
target.

**A missing namespace looks healthy until the first scan.** The Kubernetes API
answers a list request happily for a namespace that does not exist, so
availability is checked with a dry-run Job create instead — it validates the
namespace and your RBAC without creating anything. `audit_status` reports the
result.
