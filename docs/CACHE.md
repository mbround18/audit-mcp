# Cache Volumes

`audit-mcp` uses named Docker volumes to share package downloads and compiled artifacts across scanner runs. This document explains what each volume contains, why it is safe to share, and how to manage the volumes.

## Why volumes instead of host directories

Named Docker volumes:

- Are managed entirely by Docker — no host path permissions to configure
- Persist across container restarts and MCP server restarts
- Are isolated from the host filesystem (no accidental exposure of `/home`, etc.)
- Can be inspected, backed up, and deleted with standard `docker volume` commands

## Volume map

### Rust (`rust:latest`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-cargo-home` | `/cache/cargo-home` | `CARGO_HOME` | Registry index, downloaded `.crate` files, installed tool binaries (`cargo-audit`, `cargo-machete`, …) |
| `audit-target-<scanner>` | `/cache/cargo-target` | `CARGO_TARGET_DIR` | Incremental build artifacts for that scanner only |

**Why per-scanner target volumes?** Rust build artifacts are tied to a specific set of compiler flags and features. `cargo-clippy` produces debug check artifacts; `cargo-bloat` produces release artifacts. Sharing a single target directory across scanners causes rebuilds and potential corruption. Each scanner gets its own volume and caches cleanly.

**Why shared `CARGO_HOME`?** The registry index and `.crate` downloads are content-addressed and protected by per-file locks. Concurrent containers reading the same `CARGO_HOME` is safe. The big win is installed binaries — `cargo install cargo-audit --locked` compiles from source and takes ~2 minutes the first time. With a shared volume it is a no-op on every subsequent run.

### Go (`golang:1.24-bookworm`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-go-mod-cache` | `/cache/go-mod` | `GOMODCACHE`, `GOPATH` | Downloaded module zip files |
| `audit-go-build-cache` | `/cache/go-build` | `GOCACHE` | Compiled build cache entries |

Both are content-addressed and safe to share across concurrent containers.

### Python (`ghcr.io/astral-sh/uv:latest`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-uv-cache` | `/cache/uv` | `UV_CACHE_DIR` | Downloaded wheels and sdists |
| `audit-uv-tools` | `/cache/uv-tools` | `UV_TOOL_DIR` | `uvx` tool virtual environments (`bandit`, `ruff`, `mypy`, …) |

`uvx` installs an isolated virtual environment per tool. With a shared `UV_TOOL_DIR`, each tool is only installed once across all Python scanner runs.

### Node (`node:20-alpine`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-npm-cache` | `/cache/npm` | `NPM_CONFIG_CACHE` | npm tarball cache (content-addressed) |
| `audit-pnpm-store` | `/cache/pnpm` | `PNPM_HOME` | pnpm content-addressed store used by `pnpx` |

### Ruby (`ruby:3.3-slim`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-gem-home` | `/cache/gems` | `GEM_HOME`, `GEM_PATH` | Installed gems and native extensions |

Sharing `GEM_HOME` across Ruby scanners is safe because all containers use the same base image, so compiled native extensions are binary-compatible.

### Java (`ghcr.io/jbangdev/jbang-action:latest`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-jbang-cache` | `/cache/jbang` | `JBANG_CACHE_DIR` | jbang script and JAR cache, JDK downloads |
| `audit-maven-repo` | `/cache/maven` | `MAVEN_OPTS` (`-Dmaven.repo.local`) | Maven local repository |

### PHP (`composer:2`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-composer-cache` | `/cache/composer-cache` | `COMPOSER_CACHE_DIR` | Downloaded package archives |
| `audit-composer-home` | `/cache/composer-home` | `COMPOSER_HOME` | Global vendor directory and config |

### .NET (`mcr.microsoft.com/dotnet/sdk:8.0`)

| Volume | Mount | Env var | Contents |
|---|---|---|---|
| `audit-nuget-packages` | `/cache/nuget` | `NUGET_PACKAGES` | NuGet global packages |
| `audit-dotnet-home` | `/cache/dotnet-home` | `DOTNET_CLI_HOME`, `HOME` | dotnet CLI home, global tool installs |

## Listing volumes

```bash
docker volume ls | grep audit-
```

After running a few Rust scans you will see something like:

```
local     audit-cargo-home
local     audit-target-cargo-audit
local     audit-target-cargo-clippy
local     audit-target-cargo-fmt
local     audit-target-cargo-machete
```

## Inspecting a volume

```bash
docker run --rm \
  -v audit-cargo-home:/cache \
  busybox \
  ls /cache
```

## Clearing a volume

To force a full re-download for a specific ecosystem:

```bash
# clear just the Rust registry cache
docker volume rm audit-cargo-home

# clear a specific scanner's build cache
docker volume rm audit-target-cargo-clippy
```

Docker will re-create volumes automatically on the next scan.

## Clearing all audit volumes

```bash
docker volume ls --format '{{.Name}}' | grep '^audit-' | xargs docker volume rm
```

## Air-gapped environments

Volumes can be exported and imported using `docker run` with `tar`:

```bash
# export
docker run --rm \
  -v audit-cargo-home:/data \
  -v $(pwd):/out \
  busybox \
  tar czf /out/audit-cargo-home.tar.gz -C /data .

# import on another machine
docker volume create audit-cargo-home
docker run --rm \
  -v audit-cargo-home:/data \
  -v $(pwd):/out \
  busybox \
  tar xzf /out/audit-cargo-home.tar.gz -C /data
```
