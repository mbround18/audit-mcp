# Contributing

Thanks for wanting to help. This document is how to build it, how to test it,
and — most importantly — how to add a scanner without shipping one that
silently does nothing.

## The one rule worth reading first

**A scan result must never lie.** "Found nothing" and "could not run" are
different outcomes and must never be collapsed. Almost every convention below
exists because that rule was broken once and shipped.

The full set lives in
[`.specify/memory/constitution.md`](../.specify/memory/constitution.md). Each
principle names the failure that motivated it.

## Prerequisites

| Tool | For |
| ---- | --- |
| Rust 1.88+ | Building. `rustup update stable`, plus `rustup component add clippy rustfmt` |
| Docker | The default execution backend and every real-infrastructure test |
| `git` | Cloning remote repositories |
| [paws](https://github.com/mbround18/paws) | Reproducing CI locally |
| `kubectl` + a cluster | Only for the Kubernetes backend tests |

## Getting started

```bash
git clone https://github.com/mbround18/audit-mcp
cd audit-mcp
cargo build
cargo test          # fast, hermetic: no Docker, no network
```

### Reproducing CI locally with paws

CI runs on [paws](https://github.com/mbround18/paws), so the same pipeline runs
on your machine — no "works on my laptop, fails in Actions" gap:

```bash
# Install paws and dagger, once
curl -fsSL https://raw.githubusercontent.com/mbround18/paws/main/scripts/install.sh | sh
paws init

# Exactly what CI runs: fmt, clippy, build, test
paws ci --toolchain rust

# With a coverage summary
paws ci --toolchain rust --coverage
```

`paws mcp setup` registers paws itself as an MCP server for this repo, which is
handy if you drive development through an assistant.

## Everyday commands

```bash
cargo check                          # type-check
cargo test                           # hermetic suite (must stay that way)
cargo clippy --all-targets -- -D warnings
cargo fmt

# Feature-gated code is invisible to the default build, so check it too
cargo build --all-features
cargo clippy --all-features --all-targets -- -D warnings

cargo run                            # run the server (reads MCP messages on stdin)
```

## The test tiers

The default `cargo test` run is **hermetic** — no Docker, no cluster, no
network — and must stay that way. Everything that needs infrastructure is
`#[ignore]`d and self-skips with a message when its dependency is unreachable.

| Suite | Needs | Run |
| ----- | ----- | --- |
| unit | nothing | `cargo test` |
| `e2e_scan` | Docker | `cargo test --test e2e_scan -- --ignored` |
| `scanner_smoke` | Docker, network | `cargo test --test scanner_smoke -- --ignored --nocapture` |
| `workspace_clone` | git, network | `cargo test --test workspace_clone -- --ignored` |
| `secret_hygiene` | Docker, git, network | `cargo test --test secret_hygiene -- --ignored` |
| `executor_parity` | a cluster | `cargo test --features kubernetes --test executor_parity -- --ignored` |
| `http_auth` | a free port | `cargo test --features http --test http_auth -- --ignored` |

`scanner_smoke` is split into six tiers by cost — `smoke_fast_tier`,
`smoke_slow_tier`, `smoke_jvm_tier`, `smoke_scripting_tier`,
`smoke_dotnet_tier`, `smoke_elixir_tier` — so you can run just the one your
change affects.

**Point it at real projects.** Set `AUDIT_MCP_CORPUS` to a directory of example
repositories and the smoke tests use those instead of the minimal in-repo
fixtures:

```bash
AUDIT_MCP_CORPUS=../paws/examples cargo test --test scanner_smoke -- --ignored --nocapture
```

Worth the extra pass. Real repositories expose failures clean fixtures cannot —
a `0700` build directory, an unusual lockfile, a missing config. Two genuine
bugs were found exactly that way.

## Adding a scanner

1. **Add an entry** in `src/scanners.rs` using the language builder:

   ```rust
   python("ruff", "Fast Python linting.", "Linting & Formatting",
          &["sh", "-c", "uvx ruff check {target} --output-format sarif"])
       .sarif()
       .exits(&[0, 1])
       .build(),
   ```

2. **Prefer SARIF** (`.sarif()`) — one parser already handles every tool that
   speaks it, so you write no parsing code. Otherwise emit tool-native JSON,
   add a parser to `src/parsers/tools.rs`, list the name in `SUPPORTED`, and
   mark the entry `.json()`. If neither is possible, leave it as text: runs
   report `unparsed` with raw logs attached, which is honest.

3. **Declare `.exits(&[…])`** with every code that means "ran correctly". Most
   linters exit `1` simply because they found something. **Never wrap a command
   in `|| true`** — it makes a crash indistinguishable from a clean run. A unit
   test rejects it.

4. **Never use an in-place write flag** (`-w`, `-i`, `--write`, `--fix`). The
   workspace is read-only, so those can only fail. Use the tool's check or
   dry-run mode. A unit test rejects these too.

5. **Fanning out over `find … | xargs`?** Accept exit `123` as well — `xargs`
   reports 123 whenever a command it spawned exited non-zero. A unit test
   enforces this.

6. **Pin anything an install script downloads.** An unpinned URL that 404s
   fetches an HTML error page that then masquerades as a broken binary. That
   has happened here.

7. **Add the name** to the right `LanguageToolProfile` in `src/selection.rs` so
   `mode=all` can find it.

8. **Run it for real:**

   ```bash
   cargo test                                               # catalog invariants
   cargo test --test scanner_smoke -- --ignored --nocapture # does it actually run?
   ```

   Step 8 is not optional. Every scanner bug in this project's history — a
   swallowed ENTRYPOINT, a base image missing the tool it invoked, jbang
   aliases that never existed, a `-quiet` flag that suppressed an entire report
   — was invisible until a real container ran.

## Adding a language

1. A language builder in `src/scanners.rs` (base image + category tag).
2. Entries for that ecosystem's scanners.
3. A `LanguageToolProfile` in `src/selection.rs`, plus its manifest names in
   `MANIFESTS` and file extensions in `EXTENSIONS`.
4. A cache configuration in `src/executor/docker.rs` so its package manager
   writes to a named volume instead of re-downloading on every run.
5. A fixture under `tests/fixtures/` containing a deliberate violation, and an
   entry in the matching smoke tier.

## Adding an execution backend

Implement `Executor` in `src/executor/`. Return raw output, an exit code, and a
duration — **not** a status and **not** findings. Status determination and
normalization live in `src/runner.rs` so two backends cannot drift on what
"clean" means. If a backend seems to need its own status rules, that is a sign
the seam is in the wrong place, not a reason to add them locally.

Every backend enforces the same guarantees: read-only workspace, no privilege
escalation, dropped capabilities, memory ceiling, wall-clock timeout. Any
relaxation must be the narrowest possible and argued at the point of the
exception — see the `DAC_READ_SEARCH` comment in `executor/docker.rs`, and its
deliberate absence in `executor/kubernetes.rs`.

## Style

- `cargo fmt` and `cargo clippy -- -D warnings` both clean.
- Comments explain *why*, especially where code looks odd. Most odd-looking
  code here is odd because a specific tool behaved badly.
- Tests assert on **normalized findings** — rule ID, severity, file, line —
  never on substrings of raw logs. A log-grep assertion passes even when
  normalization is completely broken, which is the failure the suite exists to
  catch.

## Working on the spec

Feature work is spec-driven with [Spec Kit](https://github.com/github/spec-kit).
Specs live in `specs/`, the constitution in `.specify/memory/`. The flow is
`/speckit-specify` → `/speckit-clarify` → `/speckit-plan` → `/speckit-tasks` →
`/speckit-analyze` → `/speckit-implement`. You do not need any of it for a bug
fix or a new scanner.

## Submitting

1. Branch from `main`.
2. Make the change, with tests.
3. `paws ci --toolchain rust` green (or the cargo commands above).
4. Run the real-infrastructure suite your change touches.
5. Open a PR describing what changed and, if behaviour changed, what proves it.

Commits in this repository are signed.
