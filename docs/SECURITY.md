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

Every scanner runs in an ephemeral Docker container with the following constraints enforced unconditionally by `runner.rs`:

| Constraint          | Details                                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Workspace mount     | Target directory mounted read-only (`:ro`) — scanners cannot write to source                                                       |
| `no-new-privileges` | Applied via `SecurityOpt` — blocks `setuid`, `sudo`, and capability escalation inside the container                                |
| `CapDrop: ALL`      | All Linux capabilities are dropped — containers cannot bind privileged ports, manipulate network interfaces, or access raw sockets |
| Memory limit        | 4 GB ceiling — prevents a runaway compiler from consuming host memory                                                              |
| Ephemeral           | Containers are removed immediately after the scan completes or fails                                                               |

### Target path validation

`run_scan` canonicalizes the target path before any Docker call:

- Resolves symlinks to their real path
- Rejects non-existent paths with an error before any image is pulled
- Rejects non-directory targets — only directory trees can be scanned
- Mounts only the canonical target, not the server's working directory

### Cache volumes

Named Docker volumes (`audit-cargo-home`, `audit-uv-tools`, etc.) are used to cache package downloads across runs. These volumes are:

- Never mounted into the workspace path — they live at `/cache/*`, separate from `/workspace`
- Writable by the scanner process, but that is intentional (the cache is scanner-owned data, not user source)
- Isolated per-scanner for build artifact volumes to prevent cross-scanner artifact collisions

### Network access

Containers use the default Docker bridge network. Network access is required for scanners that download advisory databases or install tools at runtime (e.g. `cargo-audit`, `govulncheck`). There is currently no per-scanner network policy — all containers can reach the internet.

If you operate in an air-gapped environment, pre-warm the cache volumes using a connected machine and transfer the Docker volumes, or set a `REGISTRY` environment variable to point the server at an internal mirror.

### Docker socket access

`audit-mcp` connects to the Docker daemon via the local socket (`/var/run/docker.sock` or equivalent). Any process with access to this socket has effective root on the host. Restrict who can run `audit-mcp` the same way you restrict Docker socket access.

### Supply chain

Scanner images are pulled from their official upstream registries (Docker Hub, `ghcr.io`, `mcr.microsoft.com`). The `REGISTRY` environment variable can redirect all pulls to an internal registry, which is recommended for production deployments.

## Out of scope

The following are not considered security vulnerabilities in this project:

- Findings produced by scanners (those are the scanner's responsibility)
- Lack of network isolation within the Docker bridge network
- Scanners that fail, time out, or produce noisy output
- Issues that require an attacker to already have access to the host Docker socket
