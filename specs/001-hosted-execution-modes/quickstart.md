# Quickstart: validating hosted execution modes

Runnable scenarios that prove each phase works. Every scenario states what
proves it, so a green run means something specific.

Details live elsewhere and are not repeated here: argument and response shapes
in [contracts/mcp-tools.md](./contracts/mcp-tools.md), variables in
[contracts/configuration.md](./contracts/configuration.md), endpoints and token
rules in [contracts/http-transport.md](./contracts/http-transport.md).

## Prerequisites

| Scenario | Needs |
|----------|-------|
| 0 — regression | Docker |
| 1 — public clone | Docker, network, `git` |
| 2 — private clone | The above, plus one credential source |
| 3 — Kubernetes | A cluster (`kind` is sufficient) |
| 4 — hosted transport | A JWT-issuing OIDC provider, or a local mock issuer |

```bash
cargo build
cargo test                                   # hermetic: no Docker, no network
```

---

## Scenario 0 — The default did not change (SC-001)

Run **first and last**. The whole feature is only acceptable if this stays
true.

```bash
cargo test --test e2e_scan     -- --ignored
cargo test --test scanner_smoke -- --ignored
```

**Proves**: with no new configuration, the server is stdio, the backend is
Docker, no listener is opened, no credential is required, and all 33 verified
scanners still normalize identically.

---

## Scenario 1 — Scan a public repository with zero configuration (SC-002)

```bash
AUDIT_TRANSPORT=stdio cargo run
# run_scan { "target": "https://github.com/koalaman/shellcheck", "mode": "single", "scanner": "shellcheck" }
```

**Expected**

- Findings with paths relative to the repository root — no `/tmp/…`, no
  `/workspace/…`.
- `workspace.resolved_ref` is a commit SHA.
- `workspace.credential_source` is null.

**Then prove cleanup (SC-005)**:

```bash
ls /tmp | grep audit-workspace   # must return nothing
```

Repeat with a deliberately invalid scanner name so the scan fails, and confirm
the directory is gone anyway. The failure path is the one that leaks.

---

## Scenario 2 — Private repository and secret hygiene (SC-004)

Configure one credential source, then:

```bash
# run_scan { "target": "owner/private-repo", "ref": "main", "mode": "single", "scanner": "gitleaks" }
```

**Expected**

- Clone succeeds; `workspace.credential_source` names the source
  (`github_app`), never the value.
- With the credential removed, the error names which sources would work and
  does not disclose whether the repository exists.

**The automated version is the one that counts**:

```bash
cargo test --test secret_hygiene -- --ignored
```

It seeds a sentinel value into every credential source, runs a scan, serializes
the entire response, and asserts the sentinel appears nowhere — logs, execution
metadata, findings, errors. Reviewing by eye does not find leaks through paths
nobody thought of; this does.

---

## Scenario 3 — Kubernetes parity (SC-003, SC-007)

```bash
kind create cluster --name audit-mcp
kubectl create namespace audit

AUDIT_EXECUTOR=kubernetes AUDIT_K8S_NAMESPACE=audit cargo run
# run_scan { "target": "…", "mode": "single", "scanner": "shellcheck" }
```

**Expected**

- A Job appears in `audit`, runs, and is deleted:
  ```bash
  kubectl -n audit get jobs -w
  ```
- `execution.backend` is `kubernetes`.
- Findings are **identical** to the Docker run of the same fixture.

**The automated version**:

```bash
cargo test --test executor_parity -- --ignored
```

Runs the same scanner and fixture through both backends and asserts equivalent
normalized findings. This is the check that catches the Kubernetes path being
subtly different — the failure mode that would otherwise surface as "the
cluster reports fewer findings" months later.

**Then prove graceful degradation (SC-007)**:

```bash
kind delete cluster --name audit-mcp
AUDIT_EXECUTOR=kubernetes cargo run
```

`list_scanners`, `explain_finding`, and `audit_status` must still answer;
`audit_status` must report the backend unreachable with a reason; and a scan
attempt must return **one** error, not one per selected scanner.

---

## Scenario 4 — Hosted transport (SC-006)

```bash
AUDIT_TRANSPORT=http \
AUDIT_RESOURCE_URL=https://audit.example.com/mcp \
AUDIT_OAUTH_ISSUER=https://idp.example.com \
cargo run
```

**Discovery and challenge**

```bash
curl -s localhost:8080/.well-known/oauth-protected-resource   # 200, no auth
curl -i -X POST localhost:8080/mcp                            # 401 + WWW-Authenticate
```

**Rejection cases** — each must be `401`:

```bash
curl -i -X POST localhost:8080/mcp -H "Authorization: Bearer garbage"
curl -i -X POST localhost:8080/mcp -H "Authorization: Bearer $EXPIRED_TOKEN"
curl -i -X POST localhost:8080/mcp -H "Authorization: Bearer $TOKEN_FOR_ANOTHER_RESOURCE"
```

The third is the important one, and it is the case a hand-rolled resource
server most often gets wrong:

```bash
cargo test --test http_auth -- --ignored
```

**Authorization (SC-010)** — the check that stops the server laundering its own
credentials. With a server-held GitHub App credential that *can* reach a private
repository, authenticate as a caller who cannot read it and target it:

```bash
# expect: refused, with no indication of whether the repository exists
```

The server credential must never touch the repository. Confirm the refusal is
recorded in the audit log (FR-035).

**Metrics (SC-011, SC-012)**

```bash
curl -s localhost:8080/metrics | grep audit_
curl -s localhost:8080/metrics | grep -i 'my-private-repo'   # must return nothing
```

The first shows scans by status and backend reachability without reading a log
line. The second proves no repository name, target URL, caller subject, or file
path leaked into a label value — the endpoint is deliberately less protected
than `/mcp`, so anything in a label is effectively public.

**Isolation**: with two identities scanning concurrently, neither response
contains the other's target, findings, or workspace.

---

## Phase gates

| Phase | Ships when |
|-------|-----------|
| A — executor extracted | Scenario 0 green, no behaviour change |
| B — remote repositories | Scenarios 0, 1, 2 green |
| C — Kubernetes | Scenarios 0, 3 green |
| D — hosted transport | Scenarios 0, 4 green, including authorization and metrics |

Scenario 0 appears in every row deliberately. The default path is the one
almost everyone uses, and it is the one a refactor is most likely to break
quietly.
