# Scanner Reference

Complete reference for all scanners supported by `audit-mcp`. Every scanner runs in an isolated Docker container with the workspace mounted read-only.

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
| `cargo-clippy`    | Linting            | Runs Clippy with `-D warnings` — fails on any lint            |
| `cargo-deny`      | Security & License | Validates dependency graph, license policy, and denied crates |
| `cargo-fmt`       | Formatting         | Checks formatting with `--check` — fails on any diff          |
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

Base image: `golang:1.24-bookworm`

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

Base image: `ghcr.io/astral-sh/uv:latest`

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

Cache volumes: `audit-npm-cache` (npm tarball cache), `audit-pnpm-store` (pnpm content store used by `pnpx`).

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

| Scanner   | Category        | Description                                                          |
| --------- | --------------- | -------------------------------------------------------------------- |
| `credo`   | Code Quality    | Static code analysis for Elixir with consistency and quality checks  |
| `sobelow` | Security (SAST) | Security-focused static analysis for Phoenix and Elixir applications |

Cache volumes: `audit-hex-packages` (Hex package cache), `audit-mix-build` (Mix build artifacts).

## SQL

Base image: `ghcr.io/astral-sh/uv:latest`

| Scanner    | Category             | Description                                         |
| ---------- | -------------------- | --------------------------------------------------- |
| `sqlfluff` | Linting & Formatting | SQL linter and formatter with multi-dialect support |

## Java

Base image: `ghcr.io/jbangdev/jbang-action:latest`

| Scanner                | Category           | Description                                         |
| ---------------------- | ------------------ | --------------------------------------------------- |
| `spotbugs`             | Code Quality       | Bytecode analysis for logic defects                 |
| `pmd`                  | Code Analysis      | Detects suboptimal patterns and complex structures  |
| `checkstyle`           | Formatting         | Validates code style against Google Java Style      |
| `snyk-java`            | Security (SCA)     | Scans Maven/Gradle dependencies for vulnerabilities |
| `google-java-format`   | Formatting         | Formats Java sources to Google Java Style           |
| `palantir-java-format` | Formatting         | Alternative deterministic Java formatter            |
| `dependency-check`     | Security (SCA)     | OWASP dependency CVE scanner                        |
| `error-prone`          | Compilation Safety | Compiler plugin checks for common Java mistakes     |
| `jdk-flight-recorder`  | Performance        | JFR-based runtime behavior capture                  |

Cache volumes: `audit-jbang-cache` (jbang downloads), `audit-maven-repo` (Maven local repository).

## Ruby

Base image: `ruby:3.3-slim`

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
