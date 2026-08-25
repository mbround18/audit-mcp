# audit-mcp — built for the Kubernetes backend, where scanners run as Jobs and
# this image needs no Docker socket of its own.
#
# `git` is not optional: the clone path shells out to it, and a scratch image
# would fail every repository target at the last moment instead of at startup.

FROM rust:1-bookworm AS build
WORKDIR /src

# Cache dependencies separately from source, so a code change does not refetch
# the whole registry.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --features kubernetes,http 2>/dev/null || true
RUN rm -rf src

COPY . .
RUN cargo build --release --features kubernetes,http

FROM debian:bookworm-slim

# Distro packages are deliberately unpinned. The constitution's pinning rule
# targets tooling fetched from a release URL, where a 404 silently yields an
# HTML page instead of a binary. apt packages are integrity-checked against a
# signed repository, and pinning them here means the image stops building the
# next time a security update lands — trading a real supply-chain check for a
# broken build.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Scanners are isolated by the execution backend; this process still has no
# reason to be root. Numeric, so a Kubernetes `runAsNonRoot` check can resolve
# it without the image's /etc/passwd.
RUN useradd --create-home --uid 10001 audit
USER 10001
WORKDIR /home/audit

COPY --from=build /src/target/release/audit-mcp /usr/local/bin/audit-mcp

# stdio by default, exactly like a local build. Set AUDIT_TRANSPORT=http to
# serve over the network instead.
ENTRYPOINT ["/usr/local/bin/audit-mcp"]
