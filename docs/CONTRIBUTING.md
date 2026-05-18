# Contributing

Thank you for your interest in contributing to `audit-mcp`. This document covers how to get set up, what the conventions are, and how to submit changes.

## Prerequisites

- Rust 1.88 or newer (`rustup update stable`)
- Docker with a running daemon
- `cargo clippy` and `cargo fmt` available (installed via `rustup component add clippy rustfmt`)

## Getting started

```bash
git clone https://github.com/mbround18/audit-mcp
cd audit-mcp
cargo build
cargo test
```

## Development workflow

```bash
# type-check without full compile
cargo check

# run the full test suite
cargo test

# lint — must pass with no warnings
cargo clippy -- -D warnings

# format check — must pass before submitting
cargo fmt -- --check

# auto-format
cargo fmt

# run the server locally (reads MCP messages from stdin)
cargo run
```

The CI pipeline runs `cargo clippy -- -D warnings`, `cargo fmt -- --check`, and `cargo test`. All three must pass on every pull request.

## Project structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full walkthrough. The short version:

| File | What to change there |
|---|---|
| `src/scanners.rs` | Add, remove, or update scanner definitions |
| `src/selection.rs` | Change which scanners are selected for a language, or add language inference rules |
| `src/runner.rs` | Change container lifecycle, security constraints, or cache volume layout |
| `src/models.rs` | Change the shared data contract (findings, execution metadata, etc.) |
| `src/server.rs` | Add or change MCP-exposed tools |
| `src/explain.rs` | Add finding explanations for a scanner |
| `src/fixes.rs` | Add fix suggestions for a scanner |

## Adding a scanner

1. Open `src/scanners.rs` and add a `ScannerDefinition` using the appropriate language builder. Use `rust_scanner_with_install` if the tool must be installed at runtime; otherwise use the base builder.
2. Set `install_script` to the shell command that installs the tool if it is not pre-installed in the base image (e.g. `"cargo install cargo-foo --locked"`).
3. Add the scanner name to the matching `LanguageToolProfile` in `src/selection.rs` so `mode=all` discovers it.
4. Run `cargo test` — the registry validates every entry at construction time and will catch missing fields.
5. Manually verify the scanner runs correctly:
   ```bash
   cargo run  # then send a run_scan request via stdin
   ```

When naming scanners, use the tool's canonical CLI name as it appears in its own documentation (e.g. `cargo-audit`, `golangci-lint`, `phpstan`).

## Adding a language

1. Add a builder function in `src/scanners.rs` (follow the pattern of `python_scanner`, `go_scanner`, etc.).
2. Add scanner entries for all tools in that ecosystem.
3. Add a `LanguageToolProfile` to `src/selection.rs`.
4. Extend `image_cache_config` in `src/runner.rs` to cover the new Docker image and set up cache volumes for its package manager.
5. Extend `infer_language` in `src/selection.rs` to recognize file extensions and manifest filenames for the new language.
6. Add tests to `src/selection.rs` (follow the `selects_*_scanners_for_*_target` pattern).

## Pull requests

- Keep PRs focused — one logical change per PR.
- Write a clear description of what changed and why. Reference any related issues.
- All commits should build and pass tests individually (rebase before submitting if needed).
- Do not bump the version in `Cargo.toml` unless asked — releases are managed by the maintainer.
- If your change affects container security constraints or the cache volume layout, call that out explicitly in the PR description.

## Code style

- No comments that describe *what* the code does — the code should be self-explanatory.
- One short comment is acceptable when the *why* is non-obvious (a hidden constraint, a workaround for a specific bug, etc.).
- No `#[allow(clippy::*)]` suppressions without a justification comment.
- Prefer returning `Err(String)` from `runner.rs` functions — the error string becomes the MCP tool error message, so write it for a user, not a developer.

## Reporting bugs

Open an issue on GitHub with:

- What you ran and what you expected
- What actually happened (include full error output)
- Your OS, Docker version, and `audit-mcp` version or commit

For security-related bugs, follow the [Security Policy](SECURITY.md) instead.

## License

By contributing you agree that your changes will be licensed under the [BSD 3-Clause License](../LICENSE).
