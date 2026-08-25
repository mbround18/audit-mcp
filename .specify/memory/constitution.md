# audit-mcp Constitution

The rules below are not aspirational. Each one was written after a bug that
shipped because the rule did not exist, and each is enforced by a test.

## Core Principles

### I. A scan result must never lie (NON-NEGOTIABLE)

"Found nothing" and "could not run" are different outcomes and must never be
collapsed. Every run reports one of `clean`, `findings`, `unparsed`,
`tool_error`, `timeout`, or `skipped`.

- No scanner command may be wrapped in `|| true`. It makes a crash
  indistinguishable from a clean bill of health. Declare `success_exit_codes`
  instead.
- A parser returns `None` when it does not recognize its input, never an empty
  vector. `Some(vec![])` means "the tool ran and found nothing"; `None` means
  "no report was produced". Collapsing these is how a broken scanner gets
  reported as clean — it has happened, to four scanners at once.
- A tool that prints nothing when clean (`staticcheck`) must have that
  encoded in its own parser, not assumed globally. Prefer removing the flag
  that causes the silence (`gosec -quiet`) where one exists.
- When a scan is degraded, say so in the response. Never silently truncate,
  filter, or drop results without a note in the summary.

### II. Verify against real containers (NON-NEGOTIABLE)

A unit test cannot tell you that a command template is unrunnable. Every bug
of that class in this project's history — swallowed ENTRYPOINTs, jbang catalog
aliases that never existed, base images missing the tool they invoke, `xargs`
exit 123, a `-quiet` flag that suppressed an entire report — was invisible
until a real container ran.

- Any change to a `command_template`, an image, or an install script requires
  running `cargo test --test scanner_smoke -- --ignored`.
- Prefer running against a real project corpus (`AUDIT_MCP_CORPUS`) as well as
  the minimal fixtures. Real repositories expose failures that clean fixtures
  cannot: a `0700` build directory, an unusual lockfile, a missing config.
- Assert on normalized findings — rule ID, severity, file, line — never on
  substrings of raw logs. A log-grep assertion passes even when normalization
  is completely broken.

### III. Isolation is the product

Scanners are untrusted third-party code executing against a user's source. The
container boundary is the feature, not an implementation detail.

- Read-only workspace mount. No scanner may use an in-place write flag; use
  the tool's check or dry-run mode. Where a toolchain genuinely cannot work
  read-only, copy to a container-local path — never relax the mount.
- `no-new-privileges`, all capabilities dropped, an explicit memory ceiling,
  and a wall-clock timeout on every execution.
- Any relaxation of the sandbox must be the narrowest possible, and must
  document what it grants and why in the code at the point of the exception.
- Credentials are passed by per-scanner allowlist. A scanner never receives an
  environment variable it was not explicitly granted.

### IV. Bounded by default

The caller is usually a language model with a finite context window, driving a
host with finite memory. Unbounded output and unbounded fan-out are bugs.

- Cap concurrent executions; each one may claim gigabytes.
- Cap findings returned, and spend that budget on the most severe first.
- Every walk of a filesystem is bounded in both depth and entry count.
- Raw logs are attached only when they are the diagnostic — on failure, on
  unparsed output, or on explicit request.

### V. Degrade, don't disappear

The server starts and stays useful when its dependencies are missing.

- Never fail construction because an external dependency is absent. Connect
  lazily, report reachability through a status tool, and pick the dependency
  up if it appears later.
- A missing credential skips one scanner with a reason; it does not fail a
  scan.
- Prefer one clear preflight error over N identical per-item failures.

### VI. Normalize once, at the edge

Findings are the product; raw logs are a fallback.

- Prefer a command that emits SARIF: one parser serves every tool that speaks
  it. Reach for a tool-specific parser only when SARIF is unavailable.
- A finding's `id` is the tool's own rule identifier, and its fingerprint is
  stable across runs — no run IDs, no timestamps — so results can be diffed
  and deduplicated.
- Container paths never leak into a finding location.
- A declared structured output format with no matching parser is a startup
  error, not a silent downgrade to raw logs.

## Additional Constraints

- Rust 2024 edition. `cargo clippy -- -D warnings` and `cargo fmt --check`
  must both pass.
- The default `cargo test` run must remain fast, hermetic, and require neither
  Docker nor network. Everything that needs either is `#[ignore]`d and
  self-skips with a message when its dependency is unreachable.
- Catalog invariants are enforced at registry construction and in unit tests,
  so a malformed scanner entry cannot reach a user.
- Pin the version of any tool downloaded by an install script. An unpinned URL
  that 404s downloads an HTML error page that then masquerades as a broken
  binary.

## Governance

This constitution supersedes convention and personal preference. A change that
violates a principle must either be redesigned or amend the principle
explicitly in the same change, with the reasoning recorded.

Amendments require: the principle amended, the failure or requirement that
motivated it, and the test that will enforce the new rule.

**Version**: 1.0.0 | **Ratified**: 2026-08-25 | **Last Amended**: 2026-08-25
