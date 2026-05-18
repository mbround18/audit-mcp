use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::models::{ScannerDefinition, ScannerSummary};

#[derive(Debug, Clone)]
pub struct ScannerRegistry {
    scanners: HashMap<String, ScannerDefinition>,
}

impl ScannerRegistry {
    pub fn new() -> Result<Self> {
        let entries = vec![
            python_scanner(
                "bandit",
                "Finds common security flaws and vulnerabilities in Python code.",
                "Security (SAST)",
                &["uvx", "bandit", "-r", "{target}"],
            ),
            python_scanner(
                "safety",
                "Checks installed Python dependencies for known vulnerabilities.",
                "Security (SCA)",
                &["uvx", "safety", "check"],
            ),
            python_scanner(
                "ruff",
                "Fast linting and formatting checks for Python projects.",
                "Linting & Formatting",
                &["uvx", "ruff", "check", "{target}"],
            ),
            python_scanner(
                "black",
                "Deterministic Python code formatter.",
                "Code Formatting",
                &["uvx", "black", "{target}"],
            ),
            python_scanner(
                "mypy",
                "Static type checking for Python type hints.",
                "Type Checking",
                &["uvx", "mypy", "{target}"],
            ),
            python_scanner(
                "pip-audit",
                "Audits Python environments for dependency vulnerabilities.",
                "Security (SCA)",
                &["uvx", "pip-audit"],
            ),
            python_scanner(
                "vulture",
                "Finds unused code in Python projects.",
                "Code Optimization",
                &["uvx", "vulture", "{target}"],
            ),
            python_scanner(
                "flake8",
                "Checks style and programming errors against PEP 8.",
                "Code Quality",
                &["uvx", "flake8", "{target}"],
            ),
            python_scanner(
                "isort",
                "Sorts and groups Python imports automatically.",
                "Code Formatting",
                &["uvx", "isort", "{target}"],
            ),
            python_scanner(
                "radon",
                "Computes cyclomatic complexity metrics.",
                "Performance / Complexity",
                &["uvx", "radon", "cc", "{target}", "-a"],
            ),
            node_scanner(
                "knip",
                "Finds unused files, dependencies, and exports in Node projects.",
                "Code Optimization",
                &["pnpx", "knip"],
            ),
            node_scanner(
                "snyk",
                "Scans open-source dependencies for vulnerabilities.",
                "Security",
                &["pnpx", "snyk", "test"],
            ),
            node_scanner(
                "retire",
                "Finds vulnerable JavaScript libraries in the project.",
                "Security",
                &["pnpx", "retire"],
            ),
            node_scanner(
                "auditjs",
                "Audits package manifests against OSS Index.",
                "Security",
                &["pnpx", "auditjs", "ossi"],
            ),
            node_scanner(
                "prettier",
                "Formats JS/TS and related files with consistent style.",
                "Code Formatting",
                &["pnpx", "prettier", "--write", "{target}"],
            ),
            node_scanner(
                "eslint",
                "Checks JavaScript/TypeScript code quality rules.",
                "Code Quality",
                &["pnpx", "eslint", "{target}"],
            ),
            node_scanner(
                "depcheck",
                "Finds unused or missing npm dependencies.",
                "Dependency Mgmt",
                &["pnpx", "depcheck"],
            ),
            node_scanner(
                "license-checker",
                "Scans dependency license types for compliance.",
                "Compliance",
                &["pnpx", "license-checker"],
            ),
            node_scanner(
                "lighthouse",
                "Audits web app performance, SEO, and UX signals.",
                "Performance",
                &["pnpx", "lighthouse", "{target}"],
            ),
            node_scanner(
                "bundlephobia",
                "Checks bundle size impact of npm packages.",
                "Optimization",
                &["pnpx", "bundlephobia", "{target}"],
            ),
            rust_scanner_with_install(
                "cargo-audit",
                "Audits Cargo.lock dependencies against RustSec advisories.",
                "Security (SCA)",
                &["cargo", "audit"],
                Some("cargo install cargo-audit --locked"),
            ),
            rust_scanner_with_install(
                "cargo-deny",
                "Validates dependency graph, licenses, and denied crates.",
                "Security & License",
                &["cargo", "deny", "check"],
                Some("cargo install cargo-deny --locked"),
            ),
            rust_scanner_with_install(
                "cargo-mutants",
                "Runs mutation testing to evaluate test suite strength.",
                "Testing Security",
                &["cargo", "mutants"],
                Some("cargo install cargo-mutants --locked"),
            ),
            rust_scanner_with_install(
                "cargo-clippy",
                "Runs Clippy lint checks for idiomatic Rust quality.",
                "Linting & Code Quality",
                &["cargo", "clippy", "--", "-D", "warnings"],
                Some("rustup component add clippy"),
            ),
            rust_scanner_with_install(
                "cargo-fmt",
                "Checks and enforces Rust formatting standards.",
                "Code Formatting",
                &["cargo", "fmt", "--", "--check"],
                Some("rustup component add rustfmt"),
            ),
            rust_scanner_with_install(
                "cargo-machete",
                "Finds unused dependencies in Cargo.toml manifests.",
                "Code Optimization",
                &["cargo", "machete"],
                Some("cargo install cargo-machete --locked"),
            ),
            rust_scanner_with_install(
                "cargo-bloat",
                "Analyzes binary size contribution by crate and symbol.",
                "Performance / Optimization",
                &["cargo", "bloat"],
                Some("cargo install cargo-bloat --locked"),
            ),
            rust_scanner_with_install(
                "cargo-tarpaulin",
                "Computes Rust line coverage with tarpaulin.",
                "Test Coverage",
                &["cargo", "tarpaulin"],
                Some("cargo install cargo-tarpaulin --locked"),
            ),
            rust_scanner_with_install(
                "cargo-llvm-cov",
                "Computes source-based test coverage via LLVM.",
                "Test Coverage",
                &["cargo", "llvm-cov"],
                Some("cargo install cargo-llvm-cov --locked"),
            ),
            rust_scanner_with_install(
                "cargo-outdated",
                "Reports dependencies that have newer versions available.",
                "Dependency Mgmt",
                &["cargo", "outdated"],
                Some("cargo install cargo-outdated --locked"),
            ),
            go_scanner(
                "govulncheck",
                "Official Go vulnerability scanner for known advisories.",
                "Security (SCA)",
                &[
                    "go",
                    "run",
                    "golang.org/x/vuln/cmd/govulncheck@latest",
                    "./...",
                ],
            ),
            go_scanner(
                "gosec",
                "Inspects Go source code for security flaws.",
                "Security (SAST)",
                &[
                    "go",
                    "run",
                    "github.com/securego/gosec/v2/cmd/gosec@latest",
                    "./...",
                ],
            ),
            go_scanner(
                "golangci-lint",
                "Aggregates many Go linters in one run.",
                "Linting & Quality",
                &[
                    "go",
                    "run",
                    "github.com/golangci/golangci-lint/cmd/golangci-lint@latest",
                    "run",
                ],
            ),
            go_scanner(
                "staticcheck",
                "Advanced static analysis and bug detection for Go.",
                "Code Quality",
                &[
                    "go",
                    "run",
                    "honnef.co/go/tools/cmd/staticcheck@latest",
                    "./...",
                ],
            ),
            go_scanner(
                "goimports",
                "Formats code and normalizes imports for Go projects.",
                "Code Formatting",
                &[
                    "go",
                    "run",
                    "golang.org/x/tools/cmd/goimports@latest",
                    "-w",
                    "{target}",
                ],
            ),
            go_scanner(
                "gocyclo",
                "Calculates cyclomatic complexity of Go functions.",
                "Complexity",
                &[
                    "go",
                    "run",
                    "github.com/fzipp/gocyclo/cmd/gocyclo@latest",
                    "{target}",
                ],
            ),
            go_scanner(
                "nilaway",
                "Static analysis for nil safety and panic prevention.",
                "Code Reliability",
                &[
                    "go",
                    "run",
                    "go.uber.org/nilaway/cmd/nilaway@latest",
                    "./...",
                ],
            ),
            go_scanner(
                "ineffassign",
                "Finds ineffectual assignments in Go code.",
                "Optimization",
                &[
                    "go",
                    "run",
                    "github.com/gordonklaus/ineffassign@latest",
                    "./...",
                ],
            ),
            go_scanner(
                "go-carpet",
                "Terminal-style coverage visualization utility for Go.",
                "Test Coverage",
                &["go", "run", "github.com/msoap/go-carpet@latest"],
            ),
            java_scanner(
                "spotbugs",
                "Bytecode analysis for deep Java logic defects.",
                "Code Quality",
                &["jbang", "spotbugs@spotbugs", "{target}"],
            ),
            java_scanner(
                "pmd",
                "Detects suboptimal Java code and complex structures.",
                "Code Analysis",
                &[
                    "jbang",
                    "pmd@pmd",
                    "check",
                    "-d",
                    "{target}",
                    "-R",
                    "rulesets/java/quickstart.xml",
                ],
            ),
            java_scanner(
                "checkstyle",
                "Validates Java code style conventions.",
                "Code Formatting",
                &[
                    "jbang",
                    "checkstyle@checkstyle",
                    "-c",
                    "/google_checks.xml",
                    "{target}",
                ],
            ),
            java_scanner(
                "snyk-java",
                "Scans Java dependencies for known vulnerabilities.",
                "Security (SCA)",
                &["jbang", "snyk@snyk", "test"],
            ),
            java_scanner(
                "google-java-format",
                "Formats Java sources to Google Java Style.",
                "Code Formatting",
                &["jbang", "google-java-format@google", "-i", "{target}"],
            ),
            java_scanner(
                "palantir-java-format",
                "Alternative deterministic Java formatter optimized for diffs.",
                "Code Formatting",
                &["jbang", "palantir-java-format@palantir", "-i", "{target}"],
            ),
            java_scanner(
                "dependency-check",
                "OWASP dependency CVE scanner for Java builds.",
                "Security (SCA)",
                &[
                    "jbang",
                    "org.owasp:dependency-check-cli:RELEASE",
                    "--project",
                    "audit-mcp",
                    "--scan",
                    "{target}",
                ],
            ),
            java_scanner(
                "error-prone",
                "Compiler plugin checks for common Java mistakes.",
                "Compilation Safety",
                &["jbang", "--javac-option=-Xplugin:ErrorProne", "{target}"],
            ),
            java_scanner(
                "jdk-flight-recorder",
                "JFR-based runtime performance and behavior capture.",
                "Perf / Analysis",
                &["jbang", "--jfr", "{target}"],
            ),
            ruby_scanner(
                "brakeman",
                "Static security analysis for Ruby on Rails applications.",
                "Security (SAST)",
                &["gem", "exec", "brakeman"],
            ),
            ruby_scanner(
                "bundler-audit",
                "Checks Gemfile.lock dependencies against known advisories.",
                "Security (SCA)",
                &["gem", "exec", "bundler-audit", "check", "--update"],
            ),
            ruby_scanner(
                "rubocop",
                "Ruby linting and style enforcement.",
                "Linting & Formatting",
                &["gem", "exec", "rubocop"],
            ),
            ruby_scanner(
                "pronto",
                "Runs quick lint and quality checks on git changes.",
                "Code Quality",
                &["gem", "exec", "pronto", "run"],
            ),
            ruby_scanner(
                "debride",
                "Finds potentially dead and uncalled Ruby methods.",
                "Code Optimization",
                &["gem", "exec", "debride", "{target}"],
            ),
            ruby_scanner(
                "flay",
                "Detects structural code duplication in Ruby.",
                "Optimization",
                &["gem", "exec", "flay", "{target}"],
            ),
            ruby_scanner(
                "flog",
                "Reports complexity and maintainability pain points.",
                "Complexity",
                &["gem", "exec", "flog", "{target}"],
            ),
            ruby_scanner(
                "standardrb",
                "Zero-config Ruby style and lint checks.",
                "Linting / Formatting",
                &["gem", "exec", "standardrb"],
            ),
            ruby_scanner(
                "license_finder",
                "Audits Ruby dependencies for license compliance.",
                "Compliance",
                &["gem", "exec", "license_finder"],
            ),
            php_scanner(
                "phpstan",
                "Advanced static analysis for PHP bug detection.",
                "Code Quality",
                &[
                    "composer", "global", "exec", "phpstan", "analyse", "{target}",
                ],
            ),
            php_scanner(
                "psalm",
                "Type-aware static analysis for PHP codebases.",
                "Code Quality",
                &["composer", "global", "exec", "psalm"],
            ),
            php_scanner(
                "phpcs",
                "Coding-standard checks for PHP source files.",
                "Formatting",
                &["composer", "global", "exec", "phpcs", "{target}"],
            ),
            php_scanner(
                "rector",
                "Automated PHP upgrades and refactoring passes.",
                "Code Upgrades",
                &["composer", "global", "exec", "rector", "process"],
            ),
            php_scanner(
                "enlightn",
                "Laravel-focused security and performance analyzer.",
                "Security (SAST)",
                &["composer", "global", "exec", "enlightn"],
            ),
            dotnet_scanner(
                "dotnet-format",
                "Enforces .NET formatting and style conventions.",
                "Formatting",
                &["dotnet", "format"],
            ),
            dotnet_scanner(
                "roslyn-analyzers",
                "Compiler analyzer checks via standard .NET build.",
                "Code Quality",
                &["dotnet", "build"],
            ),
            dotnet_scanner(
                "dotnet-sonarscanner",
                "Runs SonarScanner for .NET quality/security analysis.",
                "Code Quality",
                &["dotnet", "tool", "run", "dotnet-sonarscanner"],
            ),
            dotnet_scanner(
                "dotnet-snyk",
                "Scans NuGet dependencies for known vulnerabilities.",
                "Security (SCA)",
                &["dotnet", "tool", "run", "snyk"],
            ),
            dotnet_scanner(
                "jb-inspectcode",
                "Runs JetBrains InspectCode analysis in CI.",
                "Code Quality",
                &["dotnet", "tool", "run", "jb", "inspectcode"],
            ),
            cpp_scanner(
                "clang-tidy",
                "Static linting for C/C++ security and quality issues.",
                "Linting & Security",
                &["clang-tidy", "{target}", "--"],
            ),
            cpp_scanner(
                "cppcheck",
                "Static analysis for C/C++ defects and correctness.",
                "Static Analysis",
                &["cppcheck", "{target}"],
            ),
            cpp_scanner(
                "clang-format",
                "Canonical formatting for C/C++ source files.",
                "Formatting",
                &["clang-format", "-i", "{target}"],
            ),
            cpp_scanner(
                "flawfinder",
                "C/C++ SAST checks against known CWE/CVE patterns.",
                "Security (SAST)",
                &["pipx", "run", "flawfinder", "{target}"],
            ),
        ];

        let scanners = entries
            .into_iter()
            .map(|scanner| (scanner.name.clone(), scanner))
            .collect();

        let registry = Self { scanners };
        registry.validate_container_guards()?;
        Ok(registry)
    }

    pub fn get(&self, scanner: &str) -> Option<&ScannerDefinition> {
        self.scanners.get(scanner)
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
        }
        Ok(())
    }
}

fn python_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "ghcr.io/astral-sh/uv:latest".to_string(),
        categories: vec![category.to_string(), "python".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn node_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "node:20-alpine".to_string(),
        categories: vec![category.to_string(), "node".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn rust_scanner_with_install(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
    install_script: Option<&str>,
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "rust:latest".to_string(),
        categories: vec![category.to_string(), "rust".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: install_script.map(str::to_string),
    }
}

fn go_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "golang:1.24-bookworm".to_string(),
        categories: vec![category.to_string(), "go".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn java_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "ghcr.io/jbangdev/jbang-action:latest".to_string(),
        categories: vec![category.to_string(), "java".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn ruby_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "ruby:3.3-slim".to_string(),
        categories: vec![category.to_string(), "ruby".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn php_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "composer:2".to_string(),
        categories: vec![category.to_string(), "php".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn dotnet_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "mcr.microsoft.com/dotnet/sdk:8.0".to_string(),
        categories: vec![category.to_string(), "dotnet".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}

fn cpp_scanner(
    name: &str,
    description: &str,
    category: &str,
    command_template: &[&str],
) -> ScannerDefinition {
    ScannerDefinition {
        name: name.to_string(),
        description: description.to_string(),
        image: "ubuntu:24.04".to_string(),
        categories: vec![category.to_string(), "c-cpp".to_string()],
        command_template: command_template
            .iter()
            .map(|arg| (*arg).to_string())
            .collect(),
        install_script: None,
    }
}
