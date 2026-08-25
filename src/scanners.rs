use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::models::{OutputFormat, ScannerDefinition, ScannerSummary};
use crate::parsers;
use crate::runner::required_env_for;

/// Default wall-clock ceiling for a scanner container.
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;
/// Scanners that compile the project (Rust, coverage, mutation testing) need
/// considerably longer, especially on a cold cache.
const BUILD_TIMEOUT_SECS: u64 = 1_800;
/// `go run tool@latest` compiles the tool before running it.
const GO_TIMEOUT_SECS: u64 = 900;

/// Fluent builder so each catalog entry states only what differs from the
/// defaults (exit codes `[0]`, text output, default timeout).
struct Builder(ScannerDefinition);

impl Builder {
    fn new(
        name: &str,
        description: &str,
        category: &str,
        language: &str,
        image: &str,
        command_template: &[&str],
    ) -> Self {
        Self(ScannerDefinition {
            name: name.to_string(),
            description: description.to_string(),
            image: image.to_string(),
            categories: vec![category.to_string(), language.to_string()],
            command_template: command_template
                .iter()
                .map(|arg| (*arg).to_string())
                .collect(),
            install_script: None,
            success_exit_codes: vec![0],
            output_format: OutputFormat::Text,
            timeout_secs: None,
        })
    }

    /// Output is SARIF 2.1.0 and handled by the generic SARIF parser.
    fn sarif(mut self) -> Self {
        self.0.output_format = OutputFormat::Sarif;
        self
    }

    /// Output is tool-native JSON with a dedicated parser in `parsers::tools`.
    fn json(mut self) -> Self {
        self.0.output_format = OutputFormat::Json;
        self
    }

    /// Exit codes that mean "ran correctly" — most linters exit non-zero
    /// simply because they found something.
    fn exits(mut self, codes: &[i64]) -> Self {
        self.0.success_exit_codes = codes.to_vec();
        self
    }

    fn install(mut self, script: &str) -> Self {
        self.0.install_script = Some(script.to_string());
        self
    }

    fn timeout(mut self, seconds: u64) -> Self {
        self.0.timeout_secs = Some(seconds);
        self
    }

    fn build(self) -> ScannerDefinition {
        self.0
    }
}

const UV_IMAGE: &str = "ghcr.io/astral-sh/uv:python3.12-bookworm-slim";
const NODE_IMAGE: &str = "node:20-alpine";
const RUST_IMAGE: &str = "rust:latest";
const GO_IMAGE: &str = "golang:1.25-bookworm";
const JAVA_IMAGE: &str = "ghcr.io/jbangdev/jbang-action:latest";
const RUBY_IMAGE: &str = "ruby:3.3-slim";
const PHP_IMAGE: &str = "composer:2";
const DOTNET_IMAGE: &str = "mcr.microsoft.com/dotnet/sdk:8.0";
const CPP_IMAGE: &str = "ubuntu:24.04";
const KOTLIN_IMAGE: &str = "eclipse-temurin:21-alpine";
const ELIXIR_IMAGE: &str = "elixir:1.18-slim";

fn python(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "python", UV_IMAGE, command)
}

fn node(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "node", NODE_IMAGE, command)
}

fn rust(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "rust", RUST_IMAGE, command)
        .timeout(BUILD_TIMEOUT_SECS)
}

fn go(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "go", GO_IMAGE, command).timeout(GO_TIMEOUT_SECS)
}

fn java(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "java", JAVA_IMAGE, command).timeout(GO_TIMEOUT_SECS)
}

fn ruby(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "ruby", RUBY_IMAGE, command)
}

fn php(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "php", PHP_IMAGE, command)
}

fn dotnet(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "dotnet", DOTNET_IMAGE, command)
        .timeout(GO_TIMEOUT_SECS)
}

fn cpp(name: &str, description: &str, category: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "c-cpp", CPP_IMAGE, command)
}

fn iac(name: &str, description: &str, category: &str, image: &str, command: &[&str]) -> Builder {
    Builder::new(name, description, category, "iac", image, command)
}

fn security(
    name: &str,
    description: &str,
    category: &str,
    image: &str,
    command: &[&str],
) -> Builder {
    Builder::new(name, description, category, "security", image, command)
}

/// Prefix for apt-based installs inside a scanner container.
///
/// Containers run with all Linux capabilities dropped, so root has no
/// CAP_DAC_OVERRIDE and cannot write into apt's `_apt`-owned cache
/// directories. Relocating the archive and list directories under /tmp (which
/// we create, and therefore own) makes apt work under the same lockdown that
/// protects every other scanner, rather than relaxing the sandbox for C/C++.
const APT: &str = concat!(
    "mkdir -p /tmp/apt/archives/partial /tmp/apt/lists/partial && ",
    "APTOPTS='-o APT::Sandbox::User=root -o Dir::Cache::archives=/tmp/apt/archives -o Dir::State::lists=/tmp/apt/lists' && ",
    "apt-get $APTOPTS update -qq >/dev/null && ",
    "DEBIAN_FRONTEND=noninteractive apt-get $APTOPTS install -y -qq --no-install-recommends"
);

#[derive(Debug, Clone)]
pub struct ScannerRegistry {
    scanners: HashMap<String, ScannerDefinition>,
}

impl ScannerRegistry {
    pub fn new() -> Result<Self> {
        let entries = vec![
            // ------------------------------------------------------ python ---
            python(
                "bandit",
                "Finds common security flaws and vulnerabilities in Python code.",
                "Security (SAST)",
                &["sh", "-c", "uvx bandit -r {target} -f json -q"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            python(
                "safety",
                "Checks installed Python dependencies for known vulnerabilities.",
                "Security (SCA)",
                &["sh", "-c", "uvx safety check"],
            )
            .exits(&[0, 1, 64, 255])
            .build(),
            python(
                "ruff",
                "Fast linting and formatting checks for Python projects.",
                "Linting & Formatting",
                &[
                    "sh",
                    "-c",
                    "uvx ruff check {target} --output-format sarif --no-cache",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            python(
                "black",
                "Checks Python formatting against the Black style (read-only).",
                "Code Formatting",
                &["sh", "-c", "uvx black --check --diff {target}"],
            )
            .exits(&[0, 1])
            .build(),
            python(
                "mypy",
                "Static type checking for Python type hints.",
                "Type Checking",
                &[
                    "sh",
                    "-c",
                    "uvx mypy {target} --no-error-summary --ignore-missing-imports",
                ],
            )
            .exits(&[0, 1])
            .build(),
            python(
                "pip-audit",
                "Audits Python environments for dependency vulnerabilities.",
                "Security (SCA)",
                &[
                    "sh",
                    "-c",
                    "uvx pip-audit -f json --progress-spinner off",
                ],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            python(
                "vulture",
                "Finds unused code in Python projects.",
                "Code Optimization",
                &["sh", "-c", "uvx vulture {target}"],
            )
            .exits(&[0, 1, 3])
            .build(),
            python(
                "flake8",
                "Checks style and programming errors against PEP 8.",
                "Code Quality",
                &["sh", "-c", "uvx flake8 {target}"],
            )
            .exits(&[0, 1])
            .build(),
            python(
                "isort",
                "Checks Python import ordering without rewriting files.",
                "Code Formatting",
                &["sh", "-c", "uvx isort --check-only --diff {target}"],
            )
            .exits(&[0, 1])
            .build(),
            python(
                "radon",
                "Computes cyclomatic complexity metrics.",
                "Performance / Complexity",
                &["sh", "-c", "uvx radon cc {target} -a"],
            )
            .build(),
            Builder::new(
                "sqlfluff",
                "SQL linter with support for multiple SQL dialects.",
                "Linting & Formatting",
                "sql",
                UV_IMAGE,
                &[
                    "sh",
                    "-c",
                    "uvx sqlfluff lint {target} --dialect ansi --format json",
                ],
            )
            .exits(&[0, 1, 65])
            .build(),
            // -------------------------------------------------------- node ---
            node(
                "knip",
                "Finds unused files, dependencies, and exports in Node projects.",
                "Code Optimization",
                &["sh", "-c", "npx --yes knip --reporter json"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "snyk",
                "Scans open-source dependencies for vulnerabilities.",
                "Security",
                &["sh", "-c", "npx --yes snyk test --sarif"],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            node(
                "retire",
                "Finds vulnerable JavaScript libraries in the project.",
                "Security",
                &["sh", "-c", "npx --yes retire --outputformat json"],
            )
            .exits(&[0, 13])
            .build(),
            node(
                "auditjs",
                "Audits package manifests against OSS Index.",
                "Security",
                &["sh", "-c", "npx --yes auditjs ossi --json"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "prettier",
                "Checks JS/TS formatting without rewriting files.",
                "Code Formatting",
                &["sh", "-c", "npx --yes prettier --check {target}"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "eslint",
                "Checks JavaScript/TypeScript code quality rules. Requires an eslint config in the target; exits 2 (reported as tool_error) without one.",
                "Code Quality",
                &["sh", "-c", "npx --yes eslint {target} -f json"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            node(
                "depcheck",
                "Finds unused or missing npm dependencies.",
                "Dependency Mgmt",
                &["sh", "-c", "npx --yes depcheck --json"],
            )
            .exits(&[0, 255])
            .build(),
            node(
                "license-checker",
                "Scans dependency license types for compliance.",
                "Compliance",
                &["sh", "-c", "npx --yes license-checker --json"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "lighthouse",
                "Audits a running web app's performance and SEO. Requires a URL, not a repository path.",
                "Performance",
                &["sh", "-c", "npx --yes lighthouse {target} --quiet --chrome-flags=--headless"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "bundlephobia",
                "Checks bundle size impact of npm packages.",
                "Optimization",
                &["sh", "-c", "npx --yes bundlephobia-cli {target}"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "oxlint",
                "Extremely fast JavaScript/TypeScript linter written in Rust.",
                "Linting",
                &["sh", "-c", "npx --yes oxlint {target} --format json"],
            )
            .exits(&[0, 1])
            .build(),
            node(
                "npm-audit",
                "Audits npm dependencies for known security vulnerabilities.",
                "Security (SCA)",
                &["sh", "-c", "npm audit --json"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            // ---------------------------------------------------- security ---
            security(
                "semgrep",
                "Multi-language static analysis for security and code correctness.",
                "Security (SAST)",
                "returntocorp/semgrep:latest",
                &[
                    "sh",
                    "-c",
                    "semgrep scan --sarif --no-rewrite-rule-ids --config p/default --metrics off --quiet .",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            security(
                "gitleaks",
                "Detects hardcoded secrets, credentials, and tokens in source code.",
                "Security (Secrets)",
                "zricethezav/gitleaks:latest",
                &[
                    "sh",
                    "-c",
                    // gitleaks only writes its report to --report-path, and a
                    // /dev/stdout path comes back empty, so stage it in the
                    // container and cat it.
                    "gitleaks detect --source . --no-git --no-banner --exit-code 0 --report-format sarif --report-path /tmp/gitleaks.sarif >/dev/null 2>&1; cat /tmp/gitleaks.sarif",
                ],
            )
            .sarif()
            .build(),
            security(
                "osv-scanner",
                "Ecosystem-agnostic dependency vulnerability scanner by Google.",
                "Security (SCA)",
                "ghcr.io/google/osv-scanner:latest",
                // The binary lives at the image root and is not on PATH.
                &["/osv-scanner", "--format", "json", "-r", "."],
            )
            .json()
            // 128 = "no package sources found", which is a legitimate outcome
            // for a repository with no dependency manifests.
            .exits(&[0, 1, 128])
            .build(),
            security(
                "grype",
                "Vulnerability scanner for repositories, filesystems, and SBOMs.",
                "Security (SCA)",
                "anchore/grype:latest",
                // Distroless image: no shell available.
                &["/grype", "dir:.", "-o", "json", "-q"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            security(
                "bearer",
                "Multi-language SAST scanner focused on security risks and data privacy.",
                "Security (SAST)",
                "bearer/bearer:latest",
                &["sh", "-c", "bearer scan . --format sarif --quiet"],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            // --------------------------------------------------------- iac ---
            iac(
                "checkov",
                "Scans Terraform and Kubernetes configurations for policy violations.",
                "Security (IaC)",
                "bridgecrew/checkov:latest",
                &[
                    "checkov",
                    "-d",
                    "{target}",
                    "-o",
                    "json",
                    "--compact",
                    "--quiet",
                    "--soft-fail",
                ],
            )
            .json()
            .build(),
            iac(
                "tfsec",
                "Finds security misconfigurations in Terraform code.",
                "Security (IaC)",
                "aquasec/tfsec:latest",
                &["sh", "-c", "tfsec {target} --format sarif --no-colour"],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            iac(
                "kube-linter",
                "Detects Kubernetes workload misconfigurations and policy issues.",
                "Security (Kubernetes)",
                "stackrox/kube-linter:latest",
                // Distroless image: no shell, and the binary lives at the root.
                &["/kube-linter", "lint", "{target}", "--format", "json"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            iac(
                "trivy-config",
                "Scans infrastructure and Kubernetes manifests for misconfigurations.",
                "Security (IaC)",
                "aquasec/trivy:latest",
                &[
                    "trivy",
                    "config",
                    "{target}",
                    "--format",
                    "json",
                    "--quiet",
                ],
            )
            .json()
            .build(),
            iac(
                "hadolint",
                "Lints Dockerfiles for security and best-practice issues.",
                "Security (Containers)",
                "hadolint/hadolint:latest-alpine",
                &[
                    "sh",
                    "-c",
                    "find . -type f \\( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \\) -print0 | xargs -0 -r hadolint -f sarif",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            iac(
                "kubesec",
                "Security risk analysis and scoring for Kubernetes resources.",
                "Security (Kubernetes)",
                "kubesec/kubesec:v2",
                &[
                    "sh",
                    "-c",
                    "find . \\( -name '*.yaml' -o -name '*.yml' \\) -print0 | xargs -0 -r kubesec scan",
                ],
            )
            .exits(&[0, 2])
            .build(),
            iac(
                "conftest",
                "Tests configuration files using Open Policy Agent Rego policies.",
                "Security (Policy)",
                "openpolicyagent/conftest:latest",
                &["sh", "-c", "conftest test . --all-namespaces -o json"],
            )
            .exits(&[0, 1, 2])
            .build(),
            iac(
                "terrascan",
                "Static code analyser for Terraform, Kubernetes, ARM, and CloudFormation.",
                "Security (IaC)",
                "tenable/terrascan:latest",
                &["sh", "-c", "terrascan scan -d . -o sarif"],
            )
            .sarif()
            // 3 = violations found, 4/5 = violations plus scan errors.
            .exits(&[0, 3, 4, 5])
            .build(),
            // ------------------------------------------------------- shell ---
            Builder::new(
                "shellcheck",
                "Static analysis and best-practice linter for shell scripts.",
                "Security (SAST)",
                "shell",
                "koalaman/shellcheck-alpine:stable",
                &[
                    "sh",
                    "-c",
                    "find . \\( -name '*.sh' -o -name '*.bash' -o -name '*.zsh' \\) -print0 | xargs -0 -r shellcheck -f json",
                ],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            // -------------------------------------------------------- rust ---
            rust(
                "cargo-audit",
                "Audits Cargo.lock dependencies against RustSec advisories.",
                "Security (SCA)",
                &["sh", "-c", "cargo audit --json"],
            )
            .install("cargo install cargo-audit --locked")
            .json()
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-deny",
                "Validates dependency graph, licenses, and denied crates.",
                "Security & License",
                &["sh", "-c", "cargo deny check"],
            )
            .install("cargo install cargo-deny --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-mutants",
                "Runs mutation testing to evaluate test suite strength.",
                "Testing Security",
                &["sh", "-c", "cargo mutants --no-times"],
            )
            .install("cargo install cargo-mutants --locked")
            .exits(&[0, 1, 2, 3, 4])
            .timeout(3_600)
            .build(),
            rust(
                "cargo-clippy",
                "Runs Clippy lint checks for idiomatic Rust quality.",
                "Linting & Code Quality",
                &[
                    "sh",
                    "-c",
                    "cargo clippy --all-targets --message-format json",
                ],
            )
            .install("rustup component add clippy")
            .json()
            .build(),
            rust(
                "cargo-fmt",
                "Checks Rust formatting without rewriting files.",
                "Code Formatting",
                &["sh", "-c", "cargo fmt --all -- --check"],
            )
            .install("rustup component add rustfmt")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-machete",
                "Finds unused dependencies in Cargo.toml manifests.",
                "Code Optimization",
                &["sh", "-c", "cargo machete"],
            )
            .install("cargo install cargo-machete --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-bloat",
                "Analyzes binary size contribution by crate and symbol.",
                "Performance / Optimization",
                &["sh", "-c", "cargo bloat --release"],
            )
            .install("cargo install cargo-bloat --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-tarpaulin",
                "Computes Rust line coverage with tarpaulin.",
                "Test Coverage",
                &["sh", "-c", "cargo tarpaulin --skip-clean"],
            )
            .install("cargo install cargo-tarpaulin --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-llvm-cov",
                "Computes source-based test coverage via LLVM.",
                "Test Coverage",
                &["sh", "-c", "cargo llvm-cov --summary-only"],
            )
            .install("rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-outdated",
                "Reports dependencies that have newer versions available.",
                "Dependency Mgmt",
                &["sh", "-c", "cargo outdated --root-deps-only"],
            )
            .install("cargo install cargo-outdated --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-geiger",
                "Detects usage of unsafe Rust code in a crate and all dependencies.",
                "Security (Unsafe)",
                &["sh", "-c", "cargo geiger --output-format Json"],
            )
            .install("cargo install cargo-geiger --locked")
            .exits(&[0, 1])
            .build(),
            rust(
                "cargo-udeps",
                "Finds unused crate dependencies with Rust nightly.",
                "Code Optimization",
                &["sh", "-c", "cargo +nightly udeps"],
            )
            .install(
                "rustup toolchain install nightly --profile minimal && cargo install cargo-udeps --locked",
            )
            .exits(&[0, 1])
            .build(),
            // ---------------------------------------------------------- go ---
            go(
                "govulncheck",
                "Official Go vulnerability scanner for known advisories.",
                "Security (SCA)",
                &[
                    "sh",
                    "-c",
                    "go run golang.org/x/vuln/cmd/govulncheck@latest -format sarif ./...",
                ],
            )
            .sarif()
            .exits(&[0, 3])
            .build(),
            go(
                "gosec",
                "Inspects Go source code for security flaws.",
                "Security (SAST)",
                &[
                    "sh",
                    "-c",
                    "go run github.com/securego/gosec/v2/cmd/gosec@latest -fmt sarif -out /dev/stdout -quiet ./...",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            go(
                "golangci-lint",
                "Aggregates many Go linters in one run.",
                "Linting & Quality",
                &[
                    "sh",
                    "-c",
                    "go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --out-format sarif",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            go(
                "staticcheck",
                "Advanced static analysis and bug detection for Go.",
                "Code Quality",
                &[
                    "sh",
                    "-c",
                    "go run honnef.co/go/tools/cmd/staticcheck@latest -f json ./...",
                ],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            go(
                "goimports",
                "Reports Go files whose imports are not correctly formatted.",
                "Code Formatting",
                &[
                    "sh",
                    "-c",
                    "go run golang.org/x/tools/cmd/goimports@latest -l {target}",
                ],
            )
            .exits(&[0, 1])
            .build(),
            go(
                "gocyclo",
                "Calculates cyclomatic complexity of Go functions.",
                "Complexity",
                &[
                    "sh",
                    "-c",
                    "go run github.com/fzipp/gocyclo/cmd/gocyclo@latest -over 15 {target}",
                ],
            )
            .exits(&[0, 1])
            .build(),
            go(
                "nilaway",
                "Static analysis for nil safety and panic prevention.",
                "Code Reliability",
                &[
                    "sh",
                    "-c",
                    "go run go.uber.org/nilaway/cmd/nilaway@latest ./...",
                ],
            )
            .exits(&[0, 1, 3])
            .build(),
            go(
                "ineffassign",
                "Finds ineffectual assignments in Go code.",
                "Optimization",
                &[
                    "sh",
                    "-c",
                    "go run github.com/gordonklaus/ineffassign@latest ./...",
                ],
            )
            .exits(&[0, 1])
            .build(),
            go(
                "go-carpet",
                "Terminal-style coverage visualization utility for Go.",
                "Test Coverage",
                &["sh", "-c", "go run github.com/msoap/go-carpet@latest"],
            )
            .exits(&[0, 1])
            .build(),
            go(
                "revive",
                "Fast, configurable, extensible linter for Go.",
                "Linting & Quality",
                &[
                    "sh",
                    "-c",
                    "go run github.com/mgechev/revive@latest ./...",
                ],
            )
            .exits(&[0, 1])
            .build(),
            go(
                "errcheck",
                "Checks for unchecked errors in Go programs.",
                "Code Reliability",
                &[
                    "sh",
                    "-c",
                    "go run github.com/kisielk/errcheck@latest ./...",
                ],
            )
            .exits(&[0, 1])
            .build(),
            // -------------------------------------------------------- java ---
            java(
                "spotbugs",
                "Bytecode analysis for deep Java logic defects.",
                "Code Quality",
                &["sh", "-c", "jbang spotbugs@spotbugs {target}"],
            )
            .exits(&[0, 1])
            .build(),
            java(
                "pmd",
                "Detects suboptimal Java code and complex structures.",
                "Code Analysis",
                &[
                    "sh",
                    "-c",
                    "jbang pmd@pmd check -d {target} -R rulesets/java/quickstart.xml -f sarif",
                ],
            )
            .sarif()
            .exits(&[0, 4])
            .build(),
            java(
                "checkstyle",
                "Validates Java code style conventions.",
                "Code Formatting",
                &[
                    "sh",
                    "-c",
                    "jbang checkstyle@checkstyle -c /google_checks.xml -f sarif {target}",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            java(
                "snyk-java",
                "Scans Java dependencies for known vulnerabilities.",
                "Security (SCA)",
                &["sh", "-c", "jbang snyk@snyk test --sarif"],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            java(
                "google-java-format",
                "Checks Java sources against Google Java Style (read-only).",
                "Code Formatting",
                &[
                    "sh",
                    "-c",
                    "jbang google-java-format@google --dry-run --set-exit-if-changed {target}",
                ],
            )
            .exits(&[0, 1])
            .build(),
            java(
                "palantir-java-format",
                "Alternative deterministic Java formatter optimized for diffs.",
                "Code Formatting",
                &[
                    "sh",
                    "-c",
                    "jbang palantir-java-format@palantir --dry-run --set-exit-if-changed {target}",
                ],
            )
            .exits(&[0, 1])
            .build(),
            java(
                "dependency-check",
                "OWASP dependency CVE scanner for Java builds.",
                "Security (SCA)",
                &[
                    "sh",
                    "-c",
                    "jbang org.owasp:dependency-check-cli:RELEASE --project audit --scan {target} --format SARIF --out /dev/stdout",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .timeout(BUILD_TIMEOUT_SECS)
            .build(),
            java(
                "error-prone",
                "Compiler plugin checks for common Java mistakes.",
                "Compilation Safety",
                &[
                    "sh",
                    "-c",
                    "jbang --javac-option=-Xplugin:ErrorProne {target}",
                ],
            )
            .exits(&[0, 1])
            .build(),
            java(
                "jdk-flight-recorder",
                "JFR-based runtime performance and behavior capture.",
                "Perf / Analysis",
                &["sh", "-c", "jbang --jfr {target}"],
            )
            .exits(&[0, 1])
            .build(),
            // -------------------------------------------------------- ruby ---
            ruby(
                "brakeman",
                "Static security analysis for Ruby on Rails applications.",
                "Security (SAST)",
                &["sh", "-c", "gem exec brakeman -f json --no-progress"],
            )
            .exits(&[0, 3])
            .build(),
            ruby(
                "bundler-audit",
                "Checks Gemfile.lock dependencies against known advisories.",
                "Security (SCA)",
                &["sh", "-c", "gem exec bundler-audit check --update"],
            )
            .exits(&[0, 1])
            .build(),
            ruby(
                "rubocop",
                "Ruby linting and style enforcement.",
                "Linting & Formatting",
                &["sh", "-c", "gem exec rubocop --format json --no-color"],
            )
            .json()
            .exits(&[0, 1])
            .build(),
            ruby(
                "pronto",
                "Runs quick lint and quality checks on git changes.",
                "Code Quality",
                &["sh", "-c", "gem exec pronto run"],
            )
            .exits(&[0, 1, 30])
            .build(),
            ruby(
                "debride",
                "Finds potentially dead and uncalled Ruby methods.",
                "Code Optimization",
                &["sh", "-c", "gem exec debride {target}"],
            )
            .exits(&[0, 1])
            .build(),
            ruby(
                "flay",
                "Detects structural code duplication in Ruby.",
                "Optimization",
                &["sh", "-c", "gem exec flay {target}"],
            )
            .exits(&[0, 1, 3])
            .build(),
            ruby(
                "flog",
                "Reports complexity and maintainability pain points.",
                "Complexity",
                &["sh", "-c", "gem exec flog {target}"],
            )
            .exits(&[0, 1])
            .build(),
            ruby(
                "standardrb",
                "Zero-config Ruby style and lint checks.",
                "Linting / Formatting",
                &["sh", "-c", "gem exec standard"],
            )
            .exits(&[0, 1])
            .build(),
            ruby(
                "license_finder",
                "Audits Ruby dependencies for license compliance.",
                "Compliance",
                &["sh", "-c", "gem exec license_finder"],
            )
            .exits(&[0, 1])
            .build(),
            // --------------------------------------------------------- php ---
            php(
                "phpstan",
                "Advanced static analysis for PHP bug detection.",
                "Code Quality",
                &[
                    "sh",
                    "-c",
                    "composer global exec -- phpstan analyse {target} --level=5 --error-format=json --no-progress",
                ],
            )
            // The base image ships no analyzers, so each PHP scanner installs
            // its own tool into the shared composer home volume.
            .install("composer global require --no-interaction --quiet phpstan/phpstan")
            .json()
            .exits(&[0, 1])
            .build(),
            php(
                "psalm",
                "Type-aware static analysis for PHP codebases.",
                "Code Quality",
                &[
                    "sh",
                    "-c",
                    "composer global exec -- psalm --no-cache --output-format=sarif {target}",
                ],
            )
            .install("composer global require --no-interaction --quiet vimeo/psalm")
            .sarif()
            .exits(&[0, 1, 2])
            .build(),
            php(
                "phpcs",
                "Coding-standard checks for PHP source files.",
                "Formatting",
                &[
                    "sh",
                    "-c",
                    "composer global exec -- phpcs --report=json {target}",
                ],
            )
            .install("composer global require --no-interaction --quiet squizlabs/php_codesniffer")
            .exits(&[0, 1, 2])
            .build(),
            php(
                "rector",
                "Reports available automated PHP upgrades (dry run).",
                "Code Upgrades",
                &[
                    "sh",
                    "-c",
                    "composer global exec -- rector process {target} --dry-run --no-progress-bar",
                ],
            )
            .install("composer global require --no-interaction --quiet rector/rector")
            .exits(&[0, 1, 2])
            .build(),
            php(
                "enlightn",
                "Laravel-focused security and performance analyzer.",
                "Security (SAST)",
                &["sh", "-c", "php artisan enlightn"],
            )
            .exits(&[0, 1])
            .build(),
            // ------------------------------------------------------ dotnet ---
            dotnet(
                "dotnet-format",
                "Verifies .NET formatting without rewriting files.",
                "Formatting",
                &["sh", "-c", "dotnet format --verify-no-changes --verbosity diagnostic"],
            )
            .exits(&[0, 2])
            .build(),
            dotnet(
                "roslyn-analyzers",
                "Compiler analyzer checks via standard .NET build.",
                "Code Quality",
                &["sh", "-c", "dotnet build --nologo -warnaserror-"],
            )
            .exits(&[0, 1])
            .build(),
            dotnet(
                "dotnet-sonarscanner",
                "Runs SonarScanner for .NET quality/security analysis.",
                "Code Quality",
                &[
                    "sh",
                    "-c",
                    "dotnet tool install --global dotnet-sonarscanner && dotnet sonarscanner begin /k:\"$SONAR_PROJECT_KEY\" && dotnet build --nologo && dotnet sonarscanner end",
                ],
            )
            .exits(&[0, 1])
            .timeout(BUILD_TIMEOUT_SECS)
            .build(),
            dotnet(
                "dotnet-snyk",
                "Scans NuGet dependencies for known vulnerabilities.",
                "Security (SCA)",
                &[
                    "sh",
                    "-c",
                    "dotnet tool install --global snyk && snyk test --sarif",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            dotnet(
                "jb-inspectcode",
                "Runs JetBrains InspectCode analysis in CI.",
                "Code Quality",
                &[
                    "sh",
                    "-c",
                    "dotnet tool install --global JetBrains.ReSharper.GlobalTools && jb inspectcode . --format=Sarif --output=/dev/stdout",
                ],
            )
            .sarif()
            .exits(&[0, 1])
            .timeout(BUILD_TIMEOUT_SECS)
            .build(),
            // ------------------------------------------------------- c/c++ ---
            cpp(
                "clang-tidy",
                "Static linting for C/C++ security and quality issues.",
                "Linting & Security",
                &[
                    "sh",
                    "-c",
                    "find {target} \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \\) -print0 | xargs -0 -r clang-tidy --",
                ],
            )
            // ubuntu:24.04 ships none of these tools by default.
            .install(&format!("{APT} clang-tidy"))
            .exits(&[0, 1])
            .build(),
            cpp(
                "cppcheck",
                "Static analysis for C/C++ defects and correctness.",
                "Static Analysis",
                &[
                    "sh",
                    "-c",
                    "cppcheck --enable=warning,style,performance,portability --template=gcc --quiet {target}",
                ],
            )
            .install(&format!("{APT} cppcheck"))
            .exits(&[0, 1])
            .build(),
            cpp(
                "clang-format",
                "Checks C/C++ formatting without rewriting files.",
                "Formatting",
                &[
                    "sh",
                    "-c",
                    "find {target} \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \\) -print0 | xargs -0 -r clang-format --dry-run --Werror",
                ],
            )
            .install(&format!("{APT} clang-format"))
            .exits(&[0, 1])
            .build(),
            cpp(
                "flawfinder",
                "C/C++ SAST checks against known CWE/CVE patterns.",
                "Security (SAST)",
                &["sh", "-c", "flawfinder --sarif --quiet {target}"],
            )
            .install(&format!("{APT} flawfinder"))
            .sarif()
            .exits(&[0, 1])
            .build(),
            // ------------------------------------------------------ kotlin ---
            Builder::new(
                "detekt",
                "Static analysis for Kotlin with code smell and security checks.",
                "Code Quality",
                "kotlin",
                KOTLIN_IMAGE,
                &[
                    "sh",
                    "-c",
                    "java -jar /opt/detekt/detekt-cli-*/lib/detekt-cli-*.jar --input . --report sarif:/dev/stdout",
                ],
            )
            // Pinned: the "latest release" asset name is not stable, and an
            // unpinned 404 previously produced an HTML file masquerading as a jar.
            .install(
                "apk add --no-cache curl unzip >/dev/null && mkdir -p /opt/detekt && curl -sSLf https://github.com/detekt/detekt/releases/download/v1.23.7/detekt-cli-1.23.7.zip -o /tmp/detekt.zip && unzip -q /tmp/detekt.zip -d /opt/detekt",
            )
            .sarif()
            .exits(&[0, 2, 3])
            .build(),
            Builder::new(
                "ktlint",
                "Kotlin linter following the official Kotlin style guide.",
                "Linting & Formatting",
                "kotlin",
                KOTLIN_IMAGE,
                &["sh", "-c", "ktlint --reporter=sarif '**/*.kt' '**/*.kts'"],
            )
            .install(
                "apk add --no-cache curl bash >/dev/null && curl -sSLf https://github.com/pinterest/ktlint/releases/latest/download/ktlint -o /usr/local/bin/ktlint && chmod +x /usr/local/bin/ktlint",
            )
            .sarif()
            .exits(&[0, 1])
            .build(),
            // ------------------------------------------------------ elixir ---
            Builder::new(
                "credo",
                "Static code analysis for Elixir with consistency and quality checks.",
                "Code Quality",
                "elixir",
                ELIXIR_IMAGE,
                &["sh", "-c", "mix credo --strict --format json"],
            )
            .install("mix local.hex --force && mix archive.install hex credo --force")
            .exits(&[0, 1, 2, 4, 8, 16])
            .build(),
            Builder::new(
                "sobelow",
                "Security-focused static analysis for Phoenix and Elixir applications.",
                "Security (SAST)",
                "elixir",
                ELIXIR_IMAGE,
                &["sh", "-c", "mix sobelow --format json"],
            )
            .install("mix local.hex --force && mix archive.install hex sobelow --force")
            .exits(&[0, 1])
            .build(),
        ];

        let mut scanners: HashMap<String, ScannerDefinition> = HashMap::new();
        for scanner in entries {
            if let Some(existing) = scanners.insert(scanner.name.clone(), scanner) {
                bail!("duplicate scanner definition for '{}'", existing.name);
            }
        }

        let registry = Self { scanners };
        registry.validate_container_guards()?;
        Ok(registry)
    }

    pub fn get(&self, scanner: &str) -> Option<&ScannerDefinition> {
        self.scanners.get(scanner)
    }

    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    pub fn list_summaries(&self) -> Vec<ScannerSummary> {
        let mut summaries = self
            .scanners
            .values()
            .map(|scanner| ScannerSummary {
                name: scanner.name.clone(),
                description: scanner.description.clone(),
                image: scanner.image.clone(),
                categories: scanner.categories.clone(),
                normalized: parsers::has_parser(scanner),
                required_env: required_env_for(&scanner.name)
                    .iter()
                    .map(|key| (*key).to_string())
                    .collect(),
            })
            .collect::<Vec<_>>();

        summaries.sort_by(|left, right| left.name.cmp(&right.name));
        summaries
    }

    fn validate_container_guards(&self) -> Result<()> {
        for scanner in self.scanners.values() {
            if scanner.image.trim().is_empty() {
                bail!(
                    "scanner '{}' violates isolation policy: missing container image",
                    scanner.name
                );
            }

            if scanner.command_template.is_empty() {
                bail!(
                    "scanner '{}' violates isolation policy: empty command template",
                    scanner.name
                );
            }

            if scanner.success_exit_codes.is_empty() {
                bail!(
                    "scanner '{}' has no success exit codes; every run would be reported as a failure",
                    scanner.name
                );
            }

            // A structured output format with no parser silently degrades to
            // raw logs, so catch the mismatch at startup instead.
            if scanner.output_format == OutputFormat::Json
                && !parsers::tools::supports(&scanner.name)
            {
                bail!(
                    "scanner '{}' declares JSON output but has no parser in parsers::tools",
                    scanner.name
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ScannerRegistry;
    use crate::models::OutputFormat;
    use crate::parsers;

    #[test]
    fn registry_initializes_and_validates() {
        let registry = ScannerRegistry::new().expect("registry should initialize");
        assert!(registry.len() >= 90, "got {} scanners", registry.len());
    }

    #[test]
    fn no_scanner_swallows_its_exit_code() {
        // `|| true` made a crashed scanner indistinguishable from a clean one.
        let registry = ScannerRegistry::new().expect("registry");
        for scanner in registry.scanners.values() {
            let command = scanner.command_template.join(" ");
            assert!(
                !command.contains("|| true"),
                "scanner '{}' still swallows its exit code",
                scanner.name
            );
        }
    }

    #[test]
    fn no_scanner_writes_to_the_read_only_workspace() {
        // The workspace is mounted read-only, so an in-place formatter can
        // only ever fail.
        let registry = ScannerRegistry::new().expect("registry");
        let write_flags = [" -w ", " -i ", "--write", "--fix"];
        for scanner in registry.scanners.values() {
            let command = format!(" {} ", scanner.command_template.join(" "));
            for flag in write_flags {
                assert!(
                    !command.contains(flag),
                    "scanner '{}' uses in-place write flag '{}'",
                    scanner.name,
                    flag.trim()
                );
            }
        }
    }

    #[test]
    fn structured_formats_have_parsers() {
        let registry = ScannerRegistry::new().expect("registry");
        for scanner in registry.scanners.values() {
            if scanner.output_format != OutputFormat::Text {
                assert!(
                    parsers::has_parser(scanner),
                    "scanner '{}' claims structured output without a parser",
                    scanner.name
                );
            }
        }
    }

    #[test]
    fn summaries_report_normalization_and_required_env() {
        let registry = ScannerRegistry::new().expect("registry");
        let summaries = registry.list_summaries();

        let semgrep = summaries
            .iter()
            .find(|summary| summary.name == "semgrep")
            .expect("semgrep");
        assert!(semgrep.normalized);
        assert!(semgrep.required_env.is_empty());

        let snyk = summaries
            .iter()
            .find(|summary| summary.name == "snyk")
            .expect("snyk");
        assert_eq!(snyk.required_env, vec!["SNYK_TOKEN".to_string()]);

        let radon = summaries
            .iter()
            .find(|summary| summary.name == "radon")
            .expect("radon");
        assert!(!radon.normalized, "radon has no parser yet");
    }

    #[test]
    fn parsed_scanners_request_machine_readable_output() {
        let registry = ScannerRegistry::new().expect("registry");
        for name in ["semgrep", "bandit", "shellcheck", "grype", "cargo-clippy"] {
            let scanner = registry.get(name).expect(name);
            assert_ne!(
                scanner.output_format,
                OutputFormat::Text,
                "scanner '{name}' should emit structured output"
            );
        }
    }
}
