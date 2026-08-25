# Scanner Reference

Complete reference for all scanners supported by `audit-mcp`. Every scanner runs in an isolated Docker container with the workspace mounted read-only.

## Normalized output

A scanner is **normalized** when `audit-mcp` parses its output into structured findings (rule ID, severity, file, line, remediation). Everything else returns raw logs with status `unparsed`. `list_scanners` reports this per scanner via the `normalized` field.

Normalized via the generic **SARIF** parser:

`semgrep`, `gitleaks`, `hadolint`, `ruff`, `tfsec`, `terrascan`, `bearer`, `gosec`, `govulncheck`, `golangci-lint`, `snyk`, `snyk-java`, `dotnet-snyk`, `jb-inspectcode`, `spotbugs`, `pmd`, `checkstyle`, `dependency-check`, `psalm`, `flawfinder`, `detekt`, `ktlint`

Normalized via a **tool-native JSON** parser:

`bandit`, `pip-audit`, `eslint`, `npm-audit`, `shellcheck`, `cargo-clippy`, `cargo-audit`, `staticcheck`, `rubocop`, `standardrb`, `phpstan`, `phpcs`, `credo`, `dotnet-format`, `roslyn-analyzers`, `grype`, `osv-scanner`, `checkov`, `trivy-config`, `kube-linter`

Everything else runs and returns raw logs. Adding a parser is the most valuable contribution you can make — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Silent-when-clean tools

Some tools print nothing at all when they find nothing, which is
indistinguishable from a crash. Where a flag exists, the catalog avoids it —
`gosec` runs without `-quiet`, which otherwise suppresses its whole report on a
clean run. Where no flag exists (`staticcheck`), the parser encodes that
silence means "clean" for that specific tool.

## Exit codes

Each scanner declares the exit codes that mean "ran correctly". Most linters exit `1` simply because they found something, which is not a failure. An exit code outside the declared set is reported as `tool_error` with the logs attached — unless the scanner nonetheless produced parseable findings, in which case the results are trusted.

No scanner wraps its command in `|| true`: that would make a crash indistinguishable from a clean run, which is the failure mode this design exists to prevent.

Scanners that fan a tool out over `find … | xargs` must also accept exit **123**: `xargs` reports 123 whenever a command it spawned exited non-zero, so a linter's "I found something" exit reaches us as 123. A unit test enforces this for every xargs-based entry.

## Read-only workspace

The workspace is mounted read-only, so every formatter runs in **check mode** (`--check`, `--dry-run`, `-l`) and reports what would change rather than rewriting files. A scanner using an in-place write flag is rejected by a unit test.

## Timeouts

Every scanner has a wall-clock budget: 600 s by default, 900 s for Go and JVM scanners that compile a tool first, 1800 s for Rust scanners that build the project, 3600 s for `cargo-mutants`. Exceeding it kills the container and reports status `timeout`. Override per request with `timeout_secs`.

## Auth environment variables

Scanners only receive an allowlisted set of host environment variables. Required values:

| Scanner(s)                         | Required env vars               | Optional allowlisted env vars             |
| ---------------------------------- | ------------------------------- | ----------------------------------------- |
| `snyk`, `snyk-java`, `dotnet-snyk` | `SNYK_TOKEN`                    | `SNYK_API`, `SNYK_CFG_ORG`                |
| `dotnet-sonarscanner`              | `SONAR_TOKEN`, `SONAR_HOST_URL` | `SONAR_PROJECT_KEY`, `SONAR_ORGANIZATION` |

Optional auth values passed when present:

| Scanner            | Optional env vars |
| ------------------ | ----------------- |
| `dependency-check` | `NVD_API_KEY`     |
| `checkov`          | `BC_API_KEY`      |

## Rust

Base image: `rust:latest`

| Scanner           | Category           | Description                                                   |
| ----------------- | ------------------ | ------------------------------------------------------------- |
| `cargo-audit`     | Security (SCA)     | Audits `Cargo.lock` against the RustSec advisory database     |
| `cargo-clippy`    | Linting            | Runs Clippy over all targets; diagnostics are normalized from cargo's JSON |
| `cargo-deny`      | Security & License | Validates dependency graph, license policy, and denied crates |
| `cargo-fmt`       | Formatting         | Checks formatting with `--check`; never rewrites files        |
| `cargo-machete`   | Optimization       | Detects unused dependencies in `Cargo.toml`                   |
| `cargo-bloat`     | Performance        | Reports binary size contribution per crate and symbol         |
| `cargo-tarpaulin` | Test Coverage      | Line coverage via instrumentation                             |
| `cargo-llvm-cov`  | Test Coverage      | Source-based coverage via LLVM                                |
| `cargo-outdated`  | Dependencies       | Lists dependencies with newer available versions              |
| `cargo-mutants`   | Testing            | Mutation testing to evaluate test suite strength              |
| `cargo-geiger`    | Security (Unsafe)  | Detects usage of unsafe Rust code in a crate and dependencies |
| `cargo-udeps`     | Optimization       | Finds unused crate dependencies (requires nightly toolchain)  |

Cache volumes: `audit-cargo-home` (shared registry + binaries), `audit-target-<scanner>` (per-scanner build artifacts).

## Go

Base image: `golang:1.25-bookworm`

`GOTOOLCHAIN=auto` is set so `go run tool@latest` can fetch a newer toolchain when a tool's `go.mod` requires one. Without it every Go scanner fails as soon as its tool outruns the base image.

| Scanner         | Category          | Description                                                             |
| --------------- | ----------------- | ----------------------------------------------------------------------- |
| `govulncheck`   | Security (SCA)    | Official Go vulnerability scanner against the Go vulnerability database |
| `gosec`         | Security (SAST)   | Inspects Go source for common security flaws                            |
| `golangci-lint` | Linting           | Aggregates many Go linters in a single run                              |
| `staticcheck`   | Code Quality      | Advanced static analysis and bug detection                              |
| `goimports`     | Formatting        | Formats code and normalizes import grouping                             |
| `gocyclo`       | Complexity        | Cyclomatic complexity per function                                      |
| `nilaway`       | Code Reliability  | Nil safety and panic prevention analysis                                |
| `ineffassign`   | Optimization      | Finds ineffectual assignments                                           |
| `go-carpet`     | Test Coverage     | Terminal-style coverage visualization                                   |
| `revive`        | Linting & Quality | Fast, configurable, extensible linter for Go                            |
| `errcheck`      | Code Reliability  | Checks for unchecked errors in Go programs                              |

Cache volumes: `audit-go-mod-cache` (module downloads), `audit-go-build-cache` (build cache).

## Python

Base image: `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`

| Scanner     | Category        | Description                                               |
| ----------- | --------------- | --------------------------------------------------------- |
| `bandit`    | Security (SAST) | Finds common security flaws in Python code                |
| `safety`    | Security (SCA)  | Checks dependencies against known vulnerability databases |
| `pip-audit` | Security (SCA)  | Audits Python environments for vulnerable packages        |
| `ruff`      | Linting         | Fast Python linter covering hundreds of rules             |
| `flake8`    | Code Quality    | PEP 8 style and programming error checks                  |
| `mypy`      | Type Checking   | Static type checking for type-annotated Python            |
| `black`     | Formatting      | Deterministic Python code formatter                       |
| `isort`     | Formatting      | Sorts and groups Python imports                           |
| `vulture`   | Optimization    | Finds unused code                                         |
| `radon`     | Complexity      | Cyclomatic complexity metrics                             |

Cache volumes: `audit-uv-cache` (wheel/sdist downloads), `audit-uv-tools` (uvx tool environments).

## Node

Base image: `node:20-alpine`

| Scanner           | Category       | Description                                       |
| ----------------- | -------------- | ------------------------------------------------- |
| `knip`            | Optimization   | Finds unused files, exports, and dependencies     |
| `snyk`            | Security       | Scans npm dependencies for known vulnerabilities  |
| `retire`          | Security       | Identifies vulnerable JavaScript libraries        |
| `auditjs`         | Security       | Audits package manifests against OSS Index        |
| `eslint`          | Code Quality   | Configurable JavaScript/TypeScript linter         |
| `prettier`        | Formatting     | Opinionated formatter for JS, TS, CSS, and more   |
| `depcheck`        | Dependencies   | Finds unused or missing npm dependencies          |
| `license-checker` | Compliance     | Scans dependency licenses for policy violations   |
| `lighthouse`      | Performance    | Web app performance, SEO, and accessibility audit |
| `bundlephobia`    | Optimization   | Reports bundle size impact of npm packages        |
| `oxlint`          | Linting        | Extremely fast JS/TS linter written in Rust       |
| `npm-audit`       | Security (SCA) | Audits npm dependencies for known vulnerabilities |

Cache volumes: `audit-npm-cache` (npm tarball cache used by `npx --yes`).

## Cross-language Security

These scanners run on **every** target regardless of inferred language (`mode=all` always includes them).

| Scanner       | Image                               | Category           | Description                                                    |
| ------------- | ----------------------------------- | ------------------ | -------------------------------------------------------------- |
| `semgrep`     | `returntocorp/semgrep:latest`       | Security (SAST)    | Multi-language static analysis for security and correctness    |
| `gitleaks`    | `zricethezav/gitleaks:latest`       | Security (Secrets) | Detects hardcoded secrets and credentials in source code       |
| `osv-scanner` | `ghcr.io/google/osv-scanner:latest` | Security (SCA)     | Google's ecosystem-agnostic dependency vulnerability scanner   |
| `grype`       | `anchore/grype:latest`              | Security (SCA)     | Vulnerability scanner for repositories and filesystems         |
| `bearer`      | `bearer/bearer:latest`              | Security (SAST)    | Multi-language SAST focused on security risks and data privacy |

Cache volumes: `audit-grype-db` (Grype vulnerability DB), `audit-osv-cache` (OSV cache).

## IaC / Kubernetes

Base images: `bridgecrew/checkov:latest`, `aquasec/tfsec:latest`, `stackrox/kube-linter:latest`, `aquasec/trivy:latest`, `hadolint/hadolint:latest-alpine`, `kubesec/kubesec:v2`, `openpolicyagent/conftest:latest`, `tenable/terrascan:latest`

| Scanner        | Category              | Description                                                        |
| -------------- | --------------------- | ------------------------------------------------------------------ |
| `checkov`      | Security (IaC)        | Terraform and Kubernetes policy/security checks                    |
| `tfsec`        | Security (IaC)        | Terraform-focused security misconfiguration detection              |
| `kube-linter`  | Security (Kubernetes) | Kubernetes manifest and workload policy checks                     |
| `trivy-config` | Security (IaC)        | IaC and Kubernetes configuration scanning with Trivy               |
| `hadolint`     | Security (Containers) | Dockerfile linting for security and best-practice violations       |
| `kubesec`      | Security (Kubernetes) | Security risk analysis and scoring for Kubernetes YAML resources   |
| `conftest`     | Security (Policy)     | Tests configuration files using Open Policy Agent Rego policies    |
| `terrascan`    | Security (IaC)        | Static analysis for Terraform, Kubernetes, ARM, and CloudFormation |

Cache volumes: `audit-checkov-cache` (checkov cache), `audit-trivy-cache` (trivy DB/cache).

## Shell

Base image: `koalaman/shellcheck-alpine:stable`

| Scanner      | Category        | Description                                                |
| ------------ | --------------- | ---------------------------------------------------------- |
| `shellcheck` | Security (SAST) | Static analysis and best-practice linter for shell scripts |

## Kotlin

Base image: `eclipse-temurin:21-alpine`

| Scanner  | Category             | Description                                                    |
| -------- | -------------------- | -------------------------------------------------------------- |
| `detekt` | Code Quality         | Static analysis for Kotlin with code smell and security checks |
| `ktlint` | Linting & Formatting | Kotlin linter and formatter following the official style guide |

Cache volumes: `audit-gradle-home` (Gradle user home / caches).

## Elixir

Base image: `elixir:1.18-slim`

Two things the base image cannot do unaided, both handled by the install script: `elixir:*-slim` ships no CA certificates, so every hex fetch fails with `:no_cacerts_found`; and `mix archive.install` does not resolve dependencies, so credo must be given `bunt`, `jason`, and `file_system` explicitly or it crashes on its first line of output.

`sobelow` targets Phoenix applications and warns that it cannot find a router on a plain Elixir project.

| Scanner   | Category        | Description                                                          |
| --------- | --------------- | -------------------------------------------------------------------- |
| `credo`   | Code Quality    | Static code analysis for Elixir with consistency and quality checks  |
| `sobelow` | Security (SAST) | Security-focused static analysis for Phoenix and Elixir applications |

Cache volumes: `audit-hex-packages` (Hex package cache), `audit-mix-build` (Mix build artifacts).

## SQL

Base image: `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`

| Scanner    | Category             | Description                                         |
| ---------- | -------------------- | --------------------------------------------------- |
| `sqlfluff` | Linting & Formatting | SQL linter and formatter with multi-dialect support |

## Java

Base image: `eclipse-temurin:21` (plus `ghcr.io/jbangdev/jbang-action:latest` for `dependency-check`)

| Scanner              | Category       | Description                                                        |
| -------------------- | -------------- | ------------------------------------------------------------------ |
| `spotbugs`           | Code Quality   | Bytecode analysis for logic defects — needs compiled classes       |
| `pmd`                | Code Analysis  | Detects suboptimal patterns and complex structures (SARIF)         |
| `checkstyle`         | Formatting     | Validates code style against Google Java Style (SARIF)             |
| `snyk-java`          | Security (SCA) | Scans Maven/Gradle dependencies for vulnerabilities (SARIF)        |
| `google-java-format` | Formatting     | Checks Java sources against Google Java Style; never rewrites files |
| `dependency-check`   | Security (SCA) | OWASP dependency CVE scanner — set `NVD_API_KEY` to avoid throttling |

Java tools are downloaded from their own **pinned** releases at container start, the same pattern used for detekt and ktlint. Pinning matters: these are fetched by exact asset name, and an unpinned URL that 404s downloads an HTML error page that then masquerades as a broken jar.

`spotbugs` reads bytecode rather than source, so it only reports on a project that has already been compiled; on a source-only checkout it finds no classes and returns `unparsed`.

Cache volumes: `audit-gradle-home`; `audit-jbang-cache` and `audit-maven-repo` for `dependency-check`.

> **Removed in 0.2.0.** `palantir-java-format`, `error-prone`, and `jdk-flight-recorder` were dropped. All three were invoked through jbang catalog aliases that do not exist, and none could function as a repository scanner: `error-prone` is a compiler plugin and `jdk-flight-recorder` records a running program rather than analysing code. `google-java-format` covers Java formatting.

## Ruby

Base image: `ruby:3.3`

Deliberately **not** the `-slim` variant: it ships no compiler or `make`, so every gem with a native extension (`prism`, `racc` — pulled in by rubocop and brakeman) fails to build and every Ruby scanner dies during install.

`brakeman` requires a Rails application layout and errors on a plain Ruby project.

| Scanner          | Category        | Description                                     |
| ---------------- | --------------- | ----------------------------------------------- |
| `brakeman`       | Security (SAST) | Static security analysis for Ruby on Rails      |
| `bundler-audit`  | Security (SCA)  | Checks `Gemfile.lock` against known advisories  |
| `rubocop`        | Linting         | Ruby style and lint enforcement                 |
| `standardrb`     | Linting         | Zero-config Ruby style checks                   |
| `pronto`         | Code Quality    | Lint checks on git-changed files                |
| `debride`        | Optimization    | Finds potentially dead Ruby methods             |
| `flay`           | Optimization    | Detects structural code duplication             |
| `flog`           | Complexity      | Complexity and maintainability scoring          |
| `license_finder` | Compliance      | Audits Ruby dependencies for license compliance |

Cache volumes: `audit-gem-home` (installed gems shared across all Ruby scanners).

## PHP

Base image: `composer:2`

The image ships no analyzers, so each PHP scanner installs its own tool into the shared composer home volume first.

| Scanner    | Category        | Description                                       |
| ---------- | --------------- | ------------------------------------------------- |
| `phpstan`  | Code Quality    | Advanced static analysis for PHP                  |
| `psalm`    | Code Quality    | Type-aware static analysis                        |
| `phpcs`    | Formatting      | Coding standard checks                            |
| `rector`   | Code Upgrades   | Automated PHP refactoring and upgrades            |
| `enlightn` | Security (SAST) | Laravel-focused security and performance analysis |

Cache volumes: `audit-composer-cache` (download cache), `audit-composer-home` (global vendor/bin).

## .NET

Base image: `mcr.microsoft.com/dotnet/sdk:8.0`

.NET scanners copy the workspace to a container-local path before running. The SDK insists on writing `obj/` next to the project before it can even load a workspace, which the read-only mount forbids. The copy keeps the host source untouched while giving the toolchain the writable tree it requires; finding paths are mapped back to repository-relative form.

`dotnet-format` and `roslyn-analyzers` both emit standard MSBuild diagnostic lines, which are normalized by a shared parser.

| Scanner               | Category       | Description                                  |
| --------------------- | -------------- | -------------------------------------------- |
| `dotnet-format`       | Formatting     | Enforces .NET formatting conventions         |
| `roslyn-analyzers`    | Code Quality   | Compiler analyzer checks via `dotnet build`  |
| `dotnet-sonarscanner` | Code Quality   | SonarScanner quality and security analysis   |
| `dotnet-snyk`         | Security (SCA) | Scans NuGet dependencies for vulnerabilities |
| `jb-inspectcode`      | Code Quality   | JetBrains InspectCode analysis               |

Cache volumes: `audit-nuget-packages` (NuGet global packages), `audit-dotnet-home` (CLI home and global tools).

## C / C++

Base image: `ubuntu:24.04`

| Scanner        | Category        | Description                                    |
| -------------- | --------------- | ---------------------------------------------- |
| `clang-tidy`   | Linting         | Static linting for security and quality issues |
| `cppcheck`     | Static Analysis | Static analysis for defects and correctness    |
| `clang-format` | Formatting      | Canonical C/C++ formatting                     |
| `flawfinder`   | Security (SAST) | SAST checks against known CWE/CVE patterns     |

No cache volumes — tools are system-installed in the image and have no persistent user-level cache.
