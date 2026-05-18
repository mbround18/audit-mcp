use std::collections::HashMap;

use crate::models::FindingExplanation;

#[derive(Debug, Clone)]
pub struct FindingExplainer {
    entries: HashMap<(String, String), FindingExplanation>,
}

impl FindingExplainer {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            ("bandit".to_string(), "B101".to_string()),
            FindingExplanation {
                scanner: "bandit".to_string(),
                id: "B101".to_string(),
                title: "Use of assert detected".to_string(),
                explanation: "Bandit flags assert because Python can remove assertions with optimization flags, which can bypass security-relevant checks in production.".to_string(),
                remediation: "Use explicit conditional checks that raise concrete exceptions instead of assert for runtime validation.".to_string(),
                references: vec![
                    "https://bandit.readthedocs.io/".to_string(),
                    "https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement".to_string(),
                ],
            },
        );
        entries.insert(
            ("eslint".to_string(), "no-unused-vars".to_string()),
            FindingExplanation {
                scanner: "eslint".to_string(),
                id: "no-unused-vars".to_string(),
                title: "Unused variables detected".to_string(),
                explanation: "Unused variables often indicate dead code paths, refactor leftovers, or mistaken assumptions about side effects.".to_string(),
                remediation: "Remove unused bindings or rename intentionally unused values with the project convention (for example `_ignored`).".to_string(),
                references: vec![
                    "https://eslint.org/docs/latest/rules/no-unused-vars".to_string(),
                ],
            },
        );
        entries.insert(
            ("cargo-clippy".to_string(), "clippy::unwrap_used".to_string()),
            FindingExplanation {
                scanner: "cargo-clippy".to_string(),
                id: "clippy::unwrap_used".to_string(),
                title: "Use of unwrap() in production path".to_string(),
                explanation: "Unwrap can panic and crash process execution in unexpected runtime conditions, which is risky in service and tooling paths.".to_string(),
                remediation: "Replace unwrap() with explicit error handling (`?`, `map_err`, or contextual errors) to preserve control flow and diagnostics.".to_string(),
                references: vec![
                    "https://rust-lang.github.io/rust-clippy/master/index.html#unwrap_used"
                        .to_string(),
                ],
            },
        );
        entries.insert(
            ("staticcheck".to_string(), "SA4006".to_string()),
            FindingExplanation {
                scanner: "staticcheck".to_string(),
                id: "SA4006".to_string(),
                title: "Value assigned but never used".to_string(),
                explanation: "Staticcheck SA4006 flags assignments whose values are overwritten before being observed, which often indicates dead logic or a mistaken implementation path.".to_string(),
                remediation: "Remove the ineffective assignment or use the computed value before reassignment.".to_string(),
                references: vec!["https://staticcheck.dev/docs/checks#SA4006".to_string()],
            },
        );
        entries.insert(
            ("spotbugs".to_string(), "NP_NULL_ON_SOME_PATH".to_string()),
            FindingExplanation {
                scanner: "spotbugs".to_string(),
                id: "NP_NULL_ON_SOME_PATH".to_string(),
                title: "Possible null dereference on execution path".to_string(),
                explanation: "SpotBugs detected a path where a nullable reference may be dereferenced without a preceding guard.".to_string(),
                remediation: "Add explicit null checks or enforce non-null contracts before dereferencing the value.".to_string(),
                references: vec!["https://spotbugs.readthedocs.io/".to_string()],
            },
        );
        entries.insert(
            ("brakeman".to_string(), "SQL Injection".to_string()),
            FindingExplanation {
                scanner: "brakeman".to_string(),
                id: "SQL Injection".to_string(),
                title: "Potential SQL injection sink".to_string(),
                explanation: "Brakeman detected user-controlled input flowing into a SQL query construction path without sufficient parameterization or sanitization.".to_string(),
                remediation: "Use parameterized query APIs (for example ActiveRecord placeholders) and avoid string interpolation in SQL statements.".to_string(),
                references: vec!["https://brakemanscanner.org/docs/warning_types/sql_injection/".to_string()],
            },
        );
        entries.insert(
            ("phpstan".to_string(), "undefined.variable".to_string()),
            FindingExplanation {
                scanner: "phpstan".to_string(),
                id: "undefined.variable".to_string(),
                title: "Potential undefined variable usage".to_string(),
                explanation: "PHPStan detected a path where a variable may be read before initialization, which can produce runtime notices or broken behavior.".to_string(),
                remediation: "Initialize the variable along all control-flow paths before first use, or guard access with explicit checks.".to_string(),
                references: vec!["https://phpstan.org/user-guide/discovering-symbols".to_string()],
            },
        );
        entries.insert(
            ("dotnet-format".to_string(), "formatting.violation".to_string()),
            FindingExplanation {
                scanner: "dotnet-format".to_string(),
                id: "formatting.violation".to_string(),
                title: "Formatting/style mismatch".to_string(),
                explanation: "Code style differs from configured .NET formatting conventions, which can obscure meaningful diffs and review signal.".to_string(),
                remediation: "Run dotnet format and commit only semantic changes plus normalized formatting updates.".to_string(),
                references: vec!["https://learn.microsoft.com/dotnet/core/tools/dotnet-format".to_string()],
            },
        );
        entries.insert(
            ("clang-tidy".to_string(), "bugprone-use-after-move".to_string()),
            FindingExplanation {
                scanner: "clang-tidy".to_string(),
                id: "bugprone-use-after-move".to_string(),
                title: "Use-after-move risk".to_string(),
                explanation: "clang-tidy detected use of an object after it has been moved from, which can lead to undefined or surprising behavior.".to_string(),
                remediation: "Avoid using moved-from objects, or reinitialize them before further access.".to_string(),
                references: vec!["https://clang.llvm.org/extra/clang-tidy/checks/bugprone/use-after-move.html".to_string()],
            },
        );
        Self { entries }
    }

    pub fn explain(&self, scanner: &str, id: &str) -> FindingExplanation {
        self.entries
            .get(&(scanner.to_string(), id.to_string()))
            .cloned()
            .unwrap_or_else(|| FindingExplanation {
                scanner: scanner.to_string(),
                id: id.to_string(),
                title: "Finding explanation not yet cataloged".to_string(),
                explanation: "This scanner finding is recognized, but detailed metadata has not been added to the local knowledge base yet.".to_string(),
                remediation: "Use scanner-native documentation for immediate guidance, then add this finding ID to the explanation registry.".to_string(),
                references: vec![],
            })
    }
}
