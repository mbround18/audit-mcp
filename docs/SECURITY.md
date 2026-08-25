# Security Policy

## Supported versions

| Version         | Supported   |
| --------------- | ----------- |
| `main` branch   | Yes         |
| Tagged releases | Latest only |

Only the current `main` branch receives security fixes. If you are running an older release, please update before reporting.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by emailing **michael.bruno1337@gmail.com** with the subject line `[audit-mcp] Security Report`. Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (in a private gist if needed)
- Affected versions or commits
- Any suggested mitigations if you have them

You will receive an acknowledgment within **48 hours** and a status update within **7 days**.

If the report is confirmed, a fix will be prepared and released as soon as practical. Credit will be given in the release notes unless you prefer to remain anonymous.

## Security design

### Container isolation

Every scanner runs in an ephemeral container with the following constraints enforced unconditionally by every execution backend. A backend that cannot enforce them is not a backend.

| Constraint          | Details                                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Workspace mount     | Target directory mounted read-only (`:ro`) — scanners cannot write to source                                                       |
| `no-new-privileges` | Applied via `SecurityOpt` — blocks `setuid`, `sudo`, and capability escalation inside the container                                |
| `CapDrop: ALL`      | All Linux capabilities are dropped — containers cannot bind privileged ports, manipulate network interfaces, or access raw sockets |
| Memory limit        | 4 GB ceiling — prevents a runaway compiler from consuming host memory                                                              |
| Ephemeral           | Containers are removed immediately after the scan completes or fails                                                               |
| Wall-clock timeout  | Every execution is killed at its budget, so a hung scanner cannot hold a scan open indefinitely                                     |
| Bounded concurrency | A capped number of containers run at once — `mode=all` cannot fan out 17 containers at 4 GB each                                    |

One capability is added back on the **Docker** backend only: `CAP_DAC_READ_SEARCH`. Dropping every capability also drops it, and root inside the container then cannot read a host directory with mode `0700` — a build output or cache directory is enough to fail an entire scan with "permission denied". It bypasses read permission checks and nothing else: no write access (the mount is read-only) and no path to escalation, and it only lets a scanner read the tree the caller explicitly pointed it at.

The **Kubernetes** backend adds nothing back, deliberately. Its workspace is an `emptyDir` written by our own initContainer, so ownership is already ours and the grant would buy nothing.

### Target validation

`run_scan` resolves and validates the target before any image is pulled:

- Canonicalizes the path, resolving symlinks
- Rejects non-existent paths with an error
- A file target mounts its parent directory and scopes the scanner to that file
- Mounts only the canonical target, never the server's working directory

An **existing local path always wins** over any remote interpretation, so no target that works today can change meaning.

### Remote repositories

Once the server fetches URLs on a caller's behalf, it can be pointed at things the caller cannot reach — internal services, cloud metadata endpoints, localhost. Several controls apply:

| Threat | Control |
| ------ | ------- |
| **SSRF** | The host is resolved and every address checked before any connection. Private, loopback, link-local, carrier-grade NAT, and IPv4-mapped equivalents are refused. `169.254.169.254` is in the test suite by name. `AUDIT_ALLOW_PRIVATE_ADDRESSES=true` opts out, for self-hosted git only |
| **DNS rebinding** | The connection binds a *checked* address rather than re-resolving, closing the window between check and connect |
| **Plaintext transport** | `http://` targets are refused outright |
| **Credentials in URLs** | A URL carrying embedded credentials is refused rather than carried — they would land in `.git/config`, in a log line, and in any object built from that URL |
| **Symlink escape** | Symlinks resolving outside the clone are removed before a scanner sees the tree |
| **Disk exhaustion** | Clone size, depth, and duration are bounded; workspaces are removed on success, failure, and timeout, and orphans from a killed process are reaped at startup |
| **Existence disclosure** | A failed clone never distinguishes "does not exist" from "you may not see it" |

### Credential handling

- **Never in an argv.** A process listing is world readable; a process environment is not. `git` receives a credential helper whose *shape* is in the command line and whose token comes from the environment.
- **Never in a Kubernetes Job spec.** A Job spec is readable by anyone with `get jobs` in the namespace, so clone credentials are delivered through a Secret that is deleted with the Job.
- **Never printed.** The `Secret` type has a hand-written `Debug` that renders `[redacted]`; a derived one would leak the value the first time anyone logged a struct containing it.
- **Never in a response.** A redaction pass runs over captured output *before* truncation — truncating first can cut a secret in half, and half a credential is still a leak. It covers logs and the reported command, the latter because a sentinel test found `execution.command` publishing a token nobody had thought to redact.
- **Short-lived.** GitHub App tokens are minted immediately before the clone and discarded with the workspace.
- **Host key checking is never silently disabled.** SSH cloning requires `SSH_KNOWN_HOSTS`; without it the clone fails with an explanation, because quietly accepting any host key makes a clone feel fine while being unauthenticated.

A test seeds a recognisable sentinel into every credential source, runs a real scan, serializes the entire response, and asserts the sentinel appears nowhere.

### Hosted transport

Only when `AUDIT_TRANSPORT=http`. On stdio none of this exists — no listener, no authentication, nobody to log in.

| Threat | Control |
| ------ | ------- |
| **Unauthenticated access** | There is no unauthenticated HTTP mode. Serving tools that execute containers over an open port is not a configuration offered |
| **Audience confusion** | A token minted by the same issuer for a *different* service is rejected. Without this, anything sharing your identity provider can drive this server. It has a dedicated test |
| **Algorithm confusion** | Signature algorithms are an allowlist. `alg: none` and the HMAC family are unreachable — an attacker choosing the algorithm is an attacker choosing whether verification means anything |
| **Confused deputy** | Authentication proves who you are; it does not entitle you to what the server can reach. A repository scan requires the caller's *own* forge credential, is checked against the repository before anything is cloned, and clones with that same credential. Every server-held source is stripped from the caller-scoped configuration, so there is no fallback to the server's broader access |
| **Probing oracle** | Rejections do not say which check failed, and authorization refusals do not reveal whether a repository exists |
| **Session theft** | A session is bound to the identity that opened it. Knowing a session id is not a credential |
| **Noisy-neighbour** | Per-caller concurrency limits, answered with `429` and `Retry-After`, so one caller cannot starve others |
| **Denial of service** | Request bodies are size-limited; MCP payloads are small |
| **Token in model context** | The caller's forge credential travels in an HTTP header, never a tool argument — an argument would flow through the model's context, where it would be logged, summarized, and possibly repeated back |

TLS is expected to be terminated in front of this server. It binds to loopback by default, so exposing it publicly takes a deliberate act.

### Metrics endpoint

`/metrics` requires no MCP token, because scrapers do not carry one, and is bindable separately so it can be exposed only to scrape infrastructure. Because it is deliberately less protected than `/mcp`, no label value may carry a repository name, target URL, caller subject, or file path — that would both publish private information and create an unbounded number of time series. Label values are drawn from bounded vocabularies and anything else is replaced with `other`. A test scrapes the endpoint after a scan and asserts the target and caller do not appear.

### Cache volumes

Named Docker volumes (`audit-cargo-home`, `audit-uv-tools`, etc.) are used to cache package downloads across runs. These volumes are:

- Never mounted into the workspace path — they live at `/cache/*`, separate from `/workspace`
- Writable by the scanner process, but that is intentional (the cache is scanner-owned data, not user source)
- Isolated per-scanner for build artifact volumes to prevent cross-scanner artifact collisions

### Network access

Containers use the default Docker bridge network. Network access is required for scanners that download advisory databases or install tools at runtime (e.g. `cargo-audit`, `govulncheck`). There is currently no per-scanner network policy — all containers can reach the internet.

If you operate in an air-gapped environment, pre-warm the cache volumes using a connected machine and transfer the Docker volumes, or set a `REGISTRY` environment variable to point the server at an internal mirror.

### Docker socket access

The Docker backend connects to the daemon via the local socket. Any process with access to that socket has effective root on the host, so restrict who can run `audit-mcp` the same way you restrict Docker socket access.

**Do not mount a Docker socket into a hosted deployment.** It would hand every scanner image root on the node. That is what the Kubernetes backend exists for: it needs only a namespace, and scanners run as Jobs with no socket anywhere. See [DEPLOYMENT.md](DEPLOYMENT.md).

### Supply chain

Scanner images are pulled from their official upstream registries (Docker Hub, `ghcr.io`, `mcr.microsoft.com`). The `REGISTRY` environment variable can redirect all pulls to an internal registry, which is recommended for production deployments.

## Out of scope

The following are not considered security vulnerabilities in this project:

- Findings produced by scanners (those are the scanner's responsibility)
- Lack of network isolation within the Docker bridge network
- Scanners that fail, time out, or produce noisy output
- Issues that require an attacker to already have access to the host Docker socket
- Reaching a private address when `AUDIT_ALLOW_PRIVATE_ADDRESSES=true` is set — that flag exists to disable the control, and its documentation says so
- Cross-scanner interference through a shared cache volume within a single trusted deployment
