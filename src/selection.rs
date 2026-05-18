use crate::{
    models::{LanguageToolProfile, ToolSelectionPlan},
    scanners::ScannerRegistry,
};

#[derive(Debug, Clone)]
pub struct ToolSelector {
    language_profiles: Vec<LanguageToolProfile>,
}

impl ToolSelector {
    pub fn new() -> Self {
        Self {
            language_profiles: vec![
                LanguageToolProfile {
                    language: "python".to_string(),
                    preferred_scanners: vec![
                        "bandit".to_string(),
                        "safety".to_string(),
                        "ruff".to_string(),
                        "black".to_string(),
                        "mypy".to_string(),
                        "pip-audit".to_string(),
                        "vulture".to_string(),
                        "flake8".to_string(),
                        "isort".to_string(),
                        "radon".to_string(),
                    ],
                    categories: vec![
                        "Security (SAST)".to_string(),
                        "Security (SCA)".to_string(),
                        "Linting & Formatting".to_string(),
                        "Type Checking".to_string(),
                        "Code Optimization".to_string(),
                        "Code Quality".to_string(),
                        "Performance / Complexity".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "node".to_string(),
                    preferred_scanners: vec![
                        "knip".to_string(),
                        "snyk".to_string(),
                        "retire".to_string(),
                        "auditjs".to_string(),
                        "prettier".to_string(),
                        "eslint".to_string(),
                        "depcheck".to_string(),
                        "license-checker".to_string(),
                        "lighthouse".to_string(),
                        "bundlephobia".to_string(),
                        "oxlint".to_string(),
                        "npm-audit".to_string(),
                    ],
                    categories: vec![
                        "Security".to_string(),
                        "Code Optimization".to_string(),
                        "Code Formatting".to_string(),
                        "Code Quality".to_string(),
                        "Dependency Mgmt".to_string(),
                        "Compliance".to_string(),
                        "Performance".to_string(),
                        "Optimization".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "rust".to_string(),
                    preferred_scanners: vec![
                        "cargo-audit".to_string(),
                        "cargo-deny".to_string(),
                        "cargo-mutants".to_string(),
                        "cargo-clippy".to_string(),
                        "cargo-fmt".to_string(),
                        "cargo-machete".to_string(),
                        "cargo-bloat".to_string(),
                        "cargo-tarpaulin".to_string(),
                        "cargo-llvm-cov".to_string(),
                        "cargo-outdated".to_string(),
                        "cargo-geiger".to_string(),
                        "cargo-udeps".to_string(),
                    ],
                    categories: vec![
                        "Security (SCA)".to_string(),
                        "Security & License".to_string(),
                        "Testing Security".to_string(),
                        "Linting & Code Quality".to_string(),
                        "Code Formatting".to_string(),
                        "Code Optimization".to_string(),
                        "Performance / Optimization".to_string(),
                        "Test Coverage".to_string(),
                        "Dependency Mgmt".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "go".to_string(),
                    preferred_scanners: vec![
                        "govulncheck".to_string(),
                        "gosec".to_string(),
                        "golangci-lint".to_string(),
                        "staticcheck".to_string(),
                        "goimports".to_string(),
                        "gocyclo".to_string(),
                        "nilaway".to_string(),
                        "ineffassign".to_string(),
                        "go-carpet".to_string(),
                        "revive".to_string(),
                        "errcheck".to_string(),
                    ],
                    categories: vec![
                        "Security (SCA)".to_string(),
                        "Security (SAST)".to_string(),
                        "Linting & Quality".to_string(),
                        "Code Quality".to_string(),
                        "Code Formatting".to_string(),
                        "Complexity".to_string(),
                        "Code Reliability".to_string(),
                        "Optimization".to_string(),
                        "Test Coverage".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "java".to_string(),
                    preferred_scanners: vec![
                        "spotbugs".to_string(),
                        "pmd".to_string(),
                        "checkstyle".to_string(),
                        "snyk-java".to_string(),
                        "google-java-format".to_string(),
                        "palantir-java-format".to_string(),
                        "dependency-check".to_string(),
                        "error-prone".to_string(),
                        "jdk-flight-recorder".to_string(),
                    ],
                    categories: vec![
                        "Code Quality".to_string(),
                        "Code Analysis".to_string(),
                        "Code Formatting".to_string(),
                        "Security (SCA)".to_string(),
                        "Compilation Safety".to_string(),
                        "Perf / Analysis".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "ruby".to_string(),
                    preferred_scanners: vec![
                        "brakeman".to_string(),
                        "bundler-audit".to_string(),
                        "rubocop".to_string(),
                        "pronto".to_string(),
                        "debride".to_string(),
                        "flay".to_string(),
                        "flog".to_string(),
                        "standardrb".to_string(),
                        "license_finder".to_string(),
                    ],
                    categories: vec![
                        "Security (SAST)".to_string(),
                        "Security (SCA)".to_string(),
                        "Linting & Formatting".to_string(),
                        "Code Quality".to_string(),
                        "Code Optimization".to_string(),
                        "Optimization".to_string(),
                        "Complexity".to_string(),
                        "Linting / Formatting".to_string(),
                        "Compliance".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "php".to_string(),
                    preferred_scanners: vec![
                        "phpstan".to_string(),
                        "psalm".to_string(),
                        "phpcs".to_string(),
                        "rector".to_string(),
                        "enlightn".to_string(),
                    ],
                    categories: vec![
                        "Code Quality".to_string(),
                        "Formatting".to_string(),
                        "Code Upgrades".to_string(),
                        "Security (SAST)".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "dotnet".to_string(),
                    preferred_scanners: vec![
                        "dotnet-format".to_string(),
                        "roslyn-analyzers".to_string(),
                        "dotnet-sonarscanner".to_string(),
                        "dotnet-snyk".to_string(),
                        "jb-inspectcode".to_string(),
                    ],
                    categories: vec![
                        "Formatting".to_string(),
                        "Code Quality".to_string(),
                        "Security (SCA)".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "c-cpp".to_string(),
                    preferred_scanners: vec![
                        "clang-tidy".to_string(),
                        "cppcheck".to_string(),
                        "clang-format".to_string(),
                        "flawfinder".to_string(),
                    ],
                    categories: vec![
                        "Linting & Security".to_string(),
                        "Static Analysis".to_string(),
                        "Formatting".to_string(),
                        "Security (SAST)".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "iac".to_string(),
                    preferred_scanners: vec![
                        "checkov".to_string(),
                        "tfsec".to_string(),
                        "kube-linter".to_string(),
                        "trivy-config".to_string(),
                        "hadolint".to_string(),
                        "kubesec".to_string(),
                        "conftest".to_string(),
                        "terrascan".to_string(),
                    ],
                    categories: vec![
                        "Security (IaC)".to_string(),
                        "Security (Kubernetes)".to_string(),
                        "Security (Containers)".to_string(),
                        "Security (Policy)".to_string(),
                    ],
                },
                // The "security" profile is always included regardless of inferred language.
                // Scanners here are cross-language and add value to every repository.
                LanguageToolProfile {
                    language: "security".to_string(),
                    preferred_scanners: vec![
                        "semgrep".to_string(),
                        "gitleaks".to_string(),
                        "osv-scanner".to_string(),
                        "grype".to_string(),
                        "bearer".to_string(),
                    ],
                    categories: vec![
                        "Security (SAST)".to_string(),
                        "Security (Secrets)".to_string(),
                        "Security (SCA)".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "shell".to_string(),
                    preferred_scanners: vec!["shellcheck".to_string()],
                    categories: vec!["Security (SAST)".to_string()],
                },
                LanguageToolProfile {
                    language: "kotlin".to_string(),
                    preferred_scanners: vec!["detekt".to_string(), "ktlint".to_string()],
                    categories: vec![
                        "Code Quality".to_string(),
                        "Linting & Formatting".to_string(),
                    ],
                },
                LanguageToolProfile {
                    language: "elixir".to_string(),
                    preferred_scanners: vec!["credo".to_string(), "sobelow".to_string()],
                    categories: vec!["Code Quality".to_string(), "Security (SAST)".to_string()],
                },
                LanguageToolProfile {
                    language: "sql".to_string(),
                    preferred_scanners: vec!["sqlfluff".to_string()],
                    categories: vec!["Linting & Formatting".to_string()],
                },
            ],
        }
    }

    pub fn plan(&self, target: &str, registry: &ScannerRegistry) -> ToolSelectionPlan {
        let mut selected_scanners = Vec::new();
        let target_language = Self::infer_language(target);

        for profile in &self.language_profiles {
            let is_cross_language = profile.language == "security";
            let matches_target = target_language.as_deref() == Some(profile.language.as_str());
            if is_cross_language || matches_target {
                selected_scanners.extend(profile.preferred_scanners.clone());
            }
        }

        selected_scanners.retain(|name| registry.get(name).is_some());
        selected_scanners.sort();
        selected_scanners.dedup();

        ToolSelectionPlan {
            phase: "observability".to_string(),
            selected_scanners,
            rationale: "Initial selection uses lightweight repository context (target shape and baseline security coverage) and is designed to be replaced by language/tool inventory inputs.".to_string(),
        }
    }

    fn infer_language(target: &str) -> Option<String> {
        if target.ends_with(".py") || target.contains("python") {
            return Some("python".to_string());
        }
        if target.ends_with(".js")
            || target.ends_with(".jsx")
            || target.ends_with(".ts")
            || target.ends_with(".tsx")
            || target.ends_with("package.json")
            || target.contains("node")
        {
            return Some("node".to_string());
        }
        if target.ends_with(".rs") || target.ends_with("Cargo.toml") || target.contains("rust") {
            return Some("rust".to_string());
        }
        if target.ends_with(".go")
            || target.ends_with("go.mod")
            || target.ends_with("go.sum")
            || target.contains("golang")
            || target.contains("/go/")
        {
            return Some("go".to_string());
        }
        if target.ends_with(".java")
            || target.ends_with("pom.xml")
            || target.ends_with("build.gradle")
            || target.ends_with("build.gradle.kts")
            || target.ends_with("settings.gradle")
            || target.ends_with("settings.gradle.kts")
            || target.contains("maven")
            || target.contains("gradle")
            || target.contains("java")
        {
            return Some("java".to_string());
        }
        if target.ends_with(".rb")
            || target.ends_with("Gemfile")
            || target.ends_with("Gemfile.lock")
            || target.ends_with(".gemspec")
            || target.contains("ruby")
            || target.contains("rails")
        {
            return Some("ruby".to_string());
        }
        if target.ends_with(".php")
            || target.ends_with("composer.json")
            || target.ends_with("composer.lock")
            || target.contains("laravel")
            || target.contains("php")
        {
            return Some("php".to_string());
        }
        if target.ends_with(".cs")
            || target.ends_with(".csproj")
            || target.ends_with(".sln")
            || target.ends_with(".fsproj")
            || target.contains("dotnet")
            || target.contains("nuget")
        {
            return Some("dotnet".to_string());
        }
        if target.ends_with(".c")
            || target.ends_with(".cc")
            || target.ends_with(".cpp")
            || target.ends_with(".cxx")
            || target.ends_with(".h")
            || target.ends_with(".hh")
            || target.ends_with(".hpp")
            || target.ends_with(".hxx")
            || target.ends_with("CMakeLists.txt")
            || target.contains("clang")
            || target.contains("cpp")
        {
            return Some("c-cpp".to_string());
        }
        if target.ends_with(".tf")
            || target.ends_with(".tfvars")
            || target.ends_with("Dockerfile")
            || target.contains("dockerfile")
            || target.contains("terraform")
            || target.contains("kubernetes")
            || target.contains("k8s")
            || target.contains("helm")
            || target.contains("kustomize")
            || target.contains("infra")
            || target.contains("infrastructure")
        {
            return Some("iac".to_string());
        }
        if target.ends_with(".sh")
            || target.ends_with(".bash")
            || target.ends_with(".zsh")
            || target.contains("scripts")
            || target.contains("bin/")
        {
            return Some("shell".to_string());
        }
        if target.ends_with(".kt")
            || target.ends_with(".kts")
            || target.ends_with("build.gradle.kts")
            || target.ends_with("settings.gradle.kts")
            || target.contains("kotlin")
        {
            return Some("kotlin".to_string());
        }
        if target.ends_with(".ex")
            || target.ends_with(".exs")
            || target.ends_with("mix.exs")
            || target.contains("elixir")
            || target.contains("phoenix")
        {
            return Some("elixir".to_string());
        }
        if target.ends_with(".sql") || target.ends_with(".ddl") || target.contains("/migrations/") {
            return Some("sql".to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ToolSelector;
    use crate::scanners::ScannerRegistry;

    #[test]
    fn selects_python_scanners_for_python_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("services/api/app.py", &registry);
        for name in &[
            "bandit",
            "safety",
            "ruff",
            "black",
            "mypy",
            "pip-audit",
            "vulture",
            "flake8",
            "isort",
            "radon",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in python plan"
            );
        }
    }

    #[test]
    fn selects_node_scanners_for_node_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("web/package.json", &registry);
        for name in &[
            "knip",
            "snyk",
            "retire",
            "auditjs",
            "prettier",
            "eslint",
            "depcheck",
            "license-checker",
            "lighthouse",
            "bundlephobia",
            "oxlint",
            "npm-audit",
            "semgrep",
            "gitleaks",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in node plan"
            );
        }
    }

    #[test]
    fn selects_rust_scanners_for_rust_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("crates/core/Cargo.toml", &registry);
        for name in &[
            "cargo-audit",
            "cargo-deny",
            "cargo-mutants",
            "cargo-clippy",
            "cargo-fmt",
            "cargo-machete",
            "cargo-bloat",
            "cargo-tarpaulin",
            "cargo-llvm-cov",
            "cargo-outdated",
            "cargo-geiger",
            "cargo-udeps",
            "semgrep",
            "gitleaks",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in rust plan"
            );
        }
    }

    #[test]
    fn selects_go_scanners_for_go_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("cmd/server/main.go", &registry);
        for name in &[
            "govulncheck",
            "gosec",
            "golangci-lint",
            "staticcheck",
            "goimports",
            "gocyclo",
            "nilaway",
            "ineffassign",
            "go-carpet",
            "revive",
            "errcheck",
            "semgrep",
            "gitleaks",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in go plan"
            );
        }
    }

    #[test]
    fn selects_java_scanners_for_java_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("services/payments/pom.xml", &registry);
        for name in &[
            "spotbugs",
            "pmd",
            "checkstyle",
            "snyk-java",
            "google-java-format",
            "palantir-java-format",
            "dependency-check",
            "error-prone",
            "jdk-flight-recorder",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in java plan"
            );
        }
    }

    #[test]
    fn selects_ruby_scanners_for_ruby_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("apps/store/Gemfile", &registry);
        for name in &[
            "brakeman",
            "bundler-audit",
            "rubocop",
            "pronto",
            "debride",
            "flay",
            "flog",
            "standardrb",
            "license_finder",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in ruby plan"
            );
        }
    }

    #[test]
    fn selects_php_scanners_for_php_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("backend/composer.json", &registry);
        for name in &["phpstan", "psalm", "phpcs", "rector", "enlightn"] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in php plan"
            );
        }
    }

    #[test]
    fn selects_dotnet_scanners_for_dotnet_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("src/App/App.csproj", &registry);
        for name in &[
            "dotnet-format",
            "roslyn-analyzers",
            "dotnet-sonarscanner",
            "dotnet-snyk",
            "jb-inspectcode",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in dotnet plan"
            );
        }
    }

    #[test]
    fn selects_cpp_scanners_for_cpp_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("native/CMakeLists.txt", &registry);
        for name in &["clang-tidy", "cppcheck", "clang-format", "flawfinder"] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected '{name}' in cpp plan"
            );
        }
    }

    #[test]
    fn returns_only_security_scanners_for_unknown_target() {
        // Cross-language security scanners are always included; non-IaC/language
        // targets still get the always-on security layer.
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("docs/architecture.txt", &registry);
        assert!(plan.selected_scanners.contains(&"semgrep".to_string()));
        assert!(plan.selected_scanners.contains(&"gitleaks".to_string()));
        assert!(plan.selected_scanners.contains(&"osv-scanner".to_string()));
        assert!(plan.selected_scanners.contains(&"grype".to_string()));
    }

    #[test]
    fn selects_iac_scanners_for_iac_target() {
        // IaC target should get IaC scanners unioned with the always-on security layer.
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("infrastructure/main.tf", &registry);
        for name in &[
            "checkov",
            "tfsec",
            "kube-linter",
            "trivy-config",
            "hadolint",
            "kubesec",
            "conftest",
            "terrascan",
            "semgrep",
            "gitleaks",
        ] {
            assert!(
                plan.selected_scanners.contains(&(*name).to_string()),
                "expected scanner '{name}' in IaC plan"
            );
        }
    }

    #[test]
    fn selects_shell_scanners_for_shell_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("scripts/deploy.sh", &registry);
        assert!(plan.selected_scanners.contains(&"shellcheck".to_string()));
        assert!(plan.selected_scanners.contains(&"semgrep".to_string()));
    }

    #[test]
    fn selects_kotlin_scanners_for_kotlin_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("app/src/Main.kt", &registry);
        assert!(plan.selected_scanners.contains(&"detekt".to_string()));
        assert!(plan.selected_scanners.contains(&"ktlint".to_string()));
    }

    #[test]
    fn selects_elixir_scanners_for_elixir_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("lib/app/mix.exs", &registry);
        assert!(plan.selected_scanners.contains(&"credo".to_string()));
        assert!(plan.selected_scanners.contains(&"sobelow".to_string()));
    }

    #[test]
    fn selects_sql_scanners_for_sql_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("db/migrations/001_create_users.sql", &registry);
        assert!(plan.selected_scanners.contains(&"sqlfluff".to_string()));
    }

    #[test]
    fn security_scanners_always_included_with_python_target() {
        let selector = ToolSelector::new();
        let registry = ScannerRegistry::new().expect("registry should initialize");
        let plan = selector.plan("services/api/app.py", &registry);
        // Language-specific scanners present
        assert!(plan.selected_scanners.contains(&"bandit".to_string()));
        // Always-on security layer also present
        assert!(plan.selected_scanners.contains(&"semgrep".to_string()));
        assert!(plan.selected_scanners.contains(&"gitleaks".to_string()));
    }
}
