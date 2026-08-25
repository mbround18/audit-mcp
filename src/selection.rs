use std::{
    collections::{BTreeSet, VecDeque},
    path::Path,
};

use crate::{
    models::{LanguageToolProfile, ToolSelectionPlan},
    scanners::ScannerRegistry,
};

/// Depth of the bounded directory walk used for language detection.
const MAX_DEPTH: usize = 4;
/// Upper bound on entries inspected, so a huge monorepo cannot stall a scan.
const MAX_ENTRIES: usize = 20_000;

/// Directories that never carry useful detection signal and are expensive to
/// walk (dependency trees, build output, VCS metadata).
const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    ".gradle",
    ".idea",
    "obj",
    ".terraform",
    "coverage",
    "_build",
    "deps",
    ".bundle",
    "Pods",
];

/// Filenames that identify an ecosystem on sight.
const MANIFESTS: &[(&str, &str)] = &[
    ("Cargo.toml", "rust"),
    ("go.mod", "go"),
    ("go.sum", "go"),
    ("package.json", "node"),
    ("pnpm-lock.yaml", "node"),
    ("tsconfig.json", "node"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("setup.py", "python"),
    ("setup.cfg", "python"),
    ("Pipfile", "python"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("settings.gradle", "java"),
    ("Gemfile", "ruby"),
    ("Gemfile.lock", "ruby"),
    ("composer.json", "php"),
    ("composer.lock", "php"),
    ("CMakeLists.txt", "c-cpp"),
    ("Dockerfile", "iac"),
    ("docker-compose.yml", "iac"),
    ("docker-compose.yaml", "iac"),
    ("Chart.yaml", "iac"),
    ("kustomization.yaml", "iac"),
    ("mix.exs", "elixir"),
    ("build.gradle.kts", "kotlin"),
    ("settings.gradle.kts", "kotlin"),
];

/// File extensions that identify an ecosystem.
const EXTENSIONS: &[(&str, &str)] = &[
    ("rs", "rust"),
    ("go", "go"),
    ("py", "python"),
    ("js", "node"),
    ("jsx", "node"),
    ("ts", "node"),
    ("tsx", "node"),
    ("mjs", "node"),
    ("cjs", "node"),
    ("java", "java"),
    ("rb", "ruby"),
    ("gemspec", "ruby"),
    ("php", "php"),
    ("cs", "dotnet"),
    ("csproj", "dotnet"),
    ("fsproj", "dotnet"),
    ("sln", "dotnet"),
    ("c", "c-cpp"),
    ("cc", "c-cpp"),
    ("cpp", "c-cpp"),
    ("cxx", "c-cpp"),
    ("h", "c-cpp"),
    ("hh", "c-cpp"),
    ("hpp", "c-cpp"),
    ("hxx", "c-cpp"),
    ("tf", "iac"),
    ("tfvars", "iac"),
    ("sh", "shell"),
    ("bash", "shell"),
    ("zsh", "shell"),
    ("kt", "kotlin"),
    ("kts", "kotlin"),
    ("ex", "elixir"),
    ("exs", "elixir"),
    ("sql", "sql"),
    ("ddl", "sql"),
];

/// What a target directory was found to contain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectDetection {
    pub languages: BTreeSet<String>,
    /// Files that produced the detection, for auditability.
    pub evidence: Vec<String>,
}

/// Classify a single file name into a language, manifest names first.
fn classify(file_name: &str) -> Option<&'static str> {
    if let Some((_, language)) = MANIFESTS
        .iter()
        .find(|(manifest, _)| manifest.eq_ignore_ascii_case(file_name))
    {
        return Some(language);
    }

    // Dockerfile.dev, prod.Dockerfile, and friends.
    if file_name.starts_with("Dockerfile.") || file_name.ends_with(".Dockerfile") {
        return Some("iac");
    }

    let extension = file_name.rsplit_once('.').map(|(_, ext)| ext)?;
    EXTENSIONS
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(extension))
        .map(|(_, language)| *language)
}

/// Walk `dir` breadth-first, bounded in depth and entry count, and report
/// every ecosystem found. Unreadable directories are skipped rather than
/// failing the scan — partial detection beats no detection.
pub fn detect_languages(dir: &Path) -> ProjectDetection {
    let mut detection = ProjectDetection::default();
    let mut queue = VecDeque::from([(dir.to_path_buf(), 0_usize)]);
    let mut inspected = 0_usize;

    while let Some((current, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };

        for entry in entries.flatten() {
            if inspected >= MAX_ENTRIES {
                return detection;
            }
            inspected += 1;

            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);

            if is_dir {
                if depth < MAX_DEPTH && !IGNORED_DIRS.contains(&name.as_str()) {
                    queue.push_back((entry.path(), depth + 1));
                }
                continue;
            }

            if let Some(language) = classify(&name)
                && detection.languages.insert(language.to_string())
            {
                detection.evidence.push(name);
            }
        }
    }

    detection
}

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
                        // lighthouse/bundlephobia take a URL or package name,
                        // not a repository path, so they are catalog-only and
                        // never auto-selected.
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
}

impl Default for ToolSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolSelector {
    /// Build a scanner selection for `target`.
    ///
    /// Detection reads the target's *contents* when it exists on disk — a
    /// directory is walked for manifests and source extensions, a file is
    /// classified by its own name. Only when the path cannot be inspected do
    /// we fall back to the old string heuristic, so callers passing a
    /// hypothetical path still get a sensible answer.
    pub fn plan(&self, target: &str, registry: &ScannerRegistry) -> ToolSelectionPlan {
        let path = Path::new(target);
        let (languages, evidence, rationale) = if path.is_dir() {
            let detection = detect_languages(path);
            let rationale = if detection.languages.is_empty() {
                format!(
                    "No ecosystem markers found under '{target}'; running the always-on cross-language security layer only."
                )
            } else {
                format!(
                    "Detected {} from files in '{target}'; unioned each ecosystem's profile with the always-on security layer.",
                    detection
                        .languages
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            (
                detection.languages.into_iter().collect::<Vec<_>>(),
                detection.evidence,
                rationale,
            )
        } else if path.is_file() {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let language = classify(&name).map(str::to_string);
            let rationale = match &language {
                Some(language) => {
                    format!(
                        "Target is a single {language} file; selected that ecosystem's profile plus the security layer."
                    )
                }
                None => format!(
                    "Target file '{name}' matches no known ecosystem; running the security layer only."
                ),
            };
            (
                language.into_iter().collect::<Vec<_>>(),
                vec![name],
                rationale,
            )
        } else {
            let language = Self::infer_language(target);
            let rationale = format!(
                "Target '{target}' is not present on this host; fell back to inferring the ecosystem from the path string."
            );
            (language.into_iter().collect::<Vec<_>>(), vec![], rationale)
        };

        let mut selected_scanners = Vec::new();
        for profile in &self.language_profiles {
            // The security profile is cross-language and always applies.
            let is_cross_language = profile.language == "security";
            if is_cross_language || languages.contains(&profile.language) {
                selected_scanners.extend(profile.preferred_scanners.clone());
            }
        }

        selected_scanners.retain(|name| registry.get(name).is_some());
        selected_scanners.sort();
        selected_scanners.dedup();

        ToolSelectionPlan {
            phase: "observability".to_string(),
            selected_scanners,
            rationale,
            detected_languages: languages,
            evidence,
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
    use super::{ToolSelector, detect_languages};
    use crate::scanners::ScannerRegistry;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/detect")
            .join(name)
    }

    #[test]
    fn detects_every_ecosystem_present_in_a_polyglot_repo() {
        let detection = detect_languages(&fixture("polyglot"));
        let languages = detection.languages.iter().cloned().collect::<Vec<_>>();

        assert!(languages.contains(&"python".to_string()), "{languages:?}");
        assert!(languages.contains(&"node".to_string()), "{languages:?}");
        assert!(languages.contains(&"iac".to_string()), "{languages:?}");
        assert!(languages.contains(&"shell".to_string()), "{languages:?}");
        // A vendored .go file inside node_modules must not be counted.
        assert!(!languages.contains(&"go".to_string()), "{languages:?}");
        assert!(!detection.evidence.is_empty());
    }

    #[test]
    fn detects_nothing_in_a_directory_without_markers() {
        let detection = detect_languages(&fixture("empty"));
        assert!(detection.languages.is_empty());
    }

    #[test]
    fn stops_walking_past_the_depth_bound() {
        // deep.rs sits five directories down, past MAX_DEPTH.
        let detection = detect_languages(&fixture("deep"));
        assert!(detection.languages.is_empty(), "{detection:?}");
    }

    #[test]
    fn plan_uses_directory_contents_not_the_path_string() {
        let registry = ScannerRegistry::new().expect("registry");
        let selector = ToolSelector::new();
        let plan = selector.plan(fixture("terraform").to_str().expect("utf-8"), &registry);

        assert_eq!(plan.detected_languages, vec!["iac".to_string()]);
        assert!(plan.evidence.contains(&"main.tf".to_string()));
        assert!(plan.selected_scanners.contains(&"checkov".to_string()));
        assert!(plan.selected_scanners.contains(&"semgrep".to_string()));
    }

    #[test]
    fn plan_over_a_polyglot_directory_unions_every_profile() {
        let registry = ScannerRegistry::new().expect("registry");
        let selector = ToolSelector::new();
        let plan = selector.plan(fixture("polyglot").to_str().expect("utf-8"), &registry);

        // Python, Node, IaC and shell scanners must all be selected together.
        for name in ["bandit", "eslint", "checkov", "shellcheck", "gitleaks"] {
            assert!(
                plan.selected_scanners.contains(&name.to_string()),
                "expected '{name}' in polyglot plan: {:?}",
                plan.selected_scanners
            );
        }
        // No Rust or Go scanners: neither ecosystem is present.
        assert!(!plan.selected_scanners.contains(&"cargo-clippy".to_string()));
        assert!(!plan.selected_scanners.contains(&"gosec".to_string()));
    }

    #[test]
    fn plan_classifies_a_single_file_target() {
        let registry = ScannerRegistry::new().expect("registry");
        let selector = ToolSelector::new();
        let path = fixture("polyglot/services/api/app.py");
        let plan = selector.plan(path.to_str().expect("utf-8"), &registry);

        assert_eq!(plan.detected_languages, vec!["python".to_string()]);
        assert!(plan.selected_scanners.contains(&"bandit".to_string()));
        assert!(!plan.selected_scanners.contains(&"eslint".to_string()));
    }

    #[test]
    fn plan_falls_back_to_path_inference_for_paths_that_do_not_exist() {
        let registry = ScannerRegistry::new().expect("registry");
        let selector = ToolSelector::new();
        let plan = selector.plan("/nonexistent/project/main.go", &registry);

        assert_eq!(plan.detected_languages, vec!["go".to_string()]);
        assert!(plan.rationale.contains("not present on this host"));
        assert!(plan.selected_scanners.contains(&"gosec".to_string()));
    }

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

        // These take a URL or package name rather than a repository path, so
        // they must never be auto-selected.
        for name in &["lighthouse", "bundlephobia"] {
            assert!(
                !plan.selected_scanners.contains(&(*name).to_string()),
                "'{name}' must not be auto-selected"
            );
            assert!(
                registry.get(name).is_some(),
                "'{name}' should still be in the catalog for explicit use"
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
