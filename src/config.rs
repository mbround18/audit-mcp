//! Runtime configuration and startup validation.
//!
//! Every setting is optional. With none set, `audit-mcp` behaves exactly as it
//! always has: stdio transport, Docker executor, local paths only, no
//! authentication.
//!
//! This module is the one place where "degrade, don't disappear" does *not*
//! apply. An unreachable dependency is a runtime condition to report; an
//! incoherent configuration is an operator error that would only surface later
//! as a confusing failure, so it is refused at startup.

use std::{collections::HashMap, env, fmt, time::Duration};

/// Which backend runs scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutorKind {
    #[default]
    Docker,
    Kubernetes,
}

impl ExecutorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Kubernetes => "kubernetes",
        }
    }
}

/// How MCP is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportKind {
    #[default]
    Stdio,
    Http,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
        }
    }
}

/// A configuration that cannot work, reported before anything starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub variable: &'static str,
    pub detail: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.variable, self.detail)
    }
}

impl std::error::Error for ConfigError {}

fn error(variable: &'static str, detail: impl Into<String>) -> ConfigError {
    ConfigError {
        variable,
        detail: detail.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesConfig {
    pub namespace: Option<String>,
    pub service_account: Option<String>,
    pub cpu_request: Option<String>,
    pub cpu_limit: Option<String>,
    pub memory_request: Option<String>,
    pub memory_limit: String,
    pub node_selector: Vec<(String, String)>,
    pub tolerations: Option<String>,
    pub image_pull_secrets: Vec<String>,
    pub job_ttl_seconds: u32,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            namespace: None,
            service_account: None,
            cpu_request: None,
            cpu_limit: None,
            memory_request: None,
            // Matches the Docker backend's ceiling.
            memory_limit: "4Gi".to_string(),
            node_selector: Vec::new(),
            tolerations: None,
            image_pull_secrets: Vec::new(),
            job_ttl_seconds: 300,
        }
    }
}

/// Credentials available for cloning, in precedence order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialConfig {
    pub github_app: Option<GitHubAppConfig>,
    pub token: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_known_hosts: Option<String>,
}

impl CredentialConfig {
    /// Names of the configured sources, for reporting. Never the values.
    pub fn source_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.github_app.is_some() {
            names.push("github_app");
        }
        if self.token.is_some() {
            names.push("token");
        }
        if self.ssh_private_key.is_some() {
            names.push("ssh_key");
        }
        names
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAppConfig {
    pub app_id: String,
    pub private_key: String,
    pub installation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfig {
    pub allow_remote_targets: bool,
    pub clone_max_bytes: u64,
    pub clone_depth: u32,
    pub clone_timeout: Duration,
    /// Permit targets resolving to private, loopback, or link-local addresses.
    /// Disables an SSRF control, so it is off unless explicitly requested.
    pub allow_private_addresses: bool,
    pub credentials: CredentialConfig,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            allow_remote_targets: true,
            clone_max_bytes: 2 * 1024 * 1024 * 1024,
            clone_depth: 1,
            clone_timeout: Duration::from_secs(300),
            allow_private_addresses: false,
            credentials: CredentialConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OAuthConfig {
    pub issuer: String,
    pub jwks_url: Option<String>,
    pub required_scope: Option<String>,
    pub authz_cache_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub kind: TransportKind,
    pub bind: String,
    pub resource_url: Option<String>,
    pub oauth: Option<OAuthConfig>,
    pub max_scans_per_caller: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            kind: TransportKind::Stdio,
            // Loopback by default: binding publicly must be a deliberate act.
            bind: "127.0.0.1:8080".to_string(),
            resource_url: None,
            oauth: None,
            max_scans_per_caller: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub metrics_bind: Option<String>,
    pub log_format: String,
    pub log_level: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_bind: None,
            log_format: "json".to_string(),
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub executor: ExecutorKind,
    pub max_parallel: usize,
    pub kubernetes: KubernetesConfig,
    pub workspace: WorkspaceConfig,
    pub transport: TransportConfig,
    pub observability: ObservabilityConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            executor: ExecutorKind::Docker,
            max_parallel: 4,
            kubernetes: KubernetesConfig::default(),
            workspace: WorkspaceConfig::default(),
            transport: TransportConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

impl Config {
    /// Read configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_resolver(|key| env::var(key).ok())
    }

    /// Read configuration from an arbitrary source.
    ///
    /// Tests use this rather than mutating the process environment, which is
    /// global state and races across parallel test threads.
    pub fn from_resolver<F>(mut resolve: F) -> Result<Self, ConfigError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let get = &mut resolve;
        let mut config = Config::default();

        if let Some(value) = get("AUDIT_EXECUTOR") {
            config.executor = match value.trim().to_ascii_lowercase().as_str() {
                "docker" => ExecutorKind::Docker,
                "kubernetes" | "k8s" => ExecutorKind::Kubernetes,
                other => {
                    return Err(error(
                        "AUDIT_EXECUTOR",
                        format!("unknown backend '{other}'; expected 'docker' or 'kubernetes'"),
                    ));
                }
            };
        }
        if config.executor == ExecutorKind::Kubernetes && !cfg!(feature = "kubernetes") {
            return Err(error(
                "AUDIT_EXECUTOR",
                "'kubernetes' requires a build with --features kubernetes; this binary was built without it",
            ));
        }

        if let Some(value) = get("AUDIT_MAX_PARALLEL") {
            config.max_parallel = parse_number("AUDIT_MAX_PARALLEL", &value)?;
            if config.max_parallel == 0 {
                return Err(error("AUDIT_MAX_PARALLEL", "must be at least 1"));
            }
        }

        config.kubernetes = kubernetes_from(get)?;
        config.workspace = workspace_from(get)?;
        config.transport = transport_from(get)?;
        config.observability = observability_from(get);

        Ok(config)
    }
}

fn kubernetes_from<F>(get: &mut F) -> Result<KubernetesConfig, ConfigError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut kubernetes = KubernetesConfig {
        namespace: get("AUDIT_K8S_NAMESPACE"),
        service_account: get("AUDIT_K8S_SERVICE_ACCOUNT"),
        cpu_request: get("AUDIT_K8S_CPU_REQUEST"),
        cpu_limit: get("AUDIT_K8S_CPU_LIMIT"),
        memory_request: get("AUDIT_K8S_MEMORY_REQUEST"),
        ..Default::default()
    };
    if let Some(value) = get("AUDIT_K8S_MEMORY_LIMIT") {
        kubernetes.memory_limit = value;
    }
    if let Some(value) = get("AUDIT_K8S_NODE_SELECTOR") {
        kubernetes.node_selector = parse_key_values("AUDIT_K8S_NODE_SELECTOR", &value)?;
    }
    kubernetes.tolerations = get("AUDIT_K8S_TOLERATIONS");
    if let Some(value) = get("AUDIT_K8S_IMAGE_PULL_SECRETS") {
        kubernetes.image_pull_secrets = split_list(&value);
    }
    if let Some(value) = get("AUDIT_K8S_JOB_TTL_SECONDS") {
        kubernetes.job_ttl_seconds = parse_number("AUDIT_K8S_JOB_TTL_SECONDS", &value)?;
    }
    Ok(kubernetes)
}

fn workspace_from<F>(get: &mut F) -> Result<WorkspaceConfig, ConfigError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut workspace = WorkspaceConfig::default();
    if let Some(value) = get("AUDIT_ALLOW_REMOTE_TARGETS") {
        workspace.allow_remote_targets = parse_bool("AUDIT_ALLOW_REMOTE_TARGETS", &value)?;
    }
    if let Some(value) = get("AUDIT_CLONE_MAX_BYTES") {
        workspace.clone_max_bytes = parse_number("AUDIT_CLONE_MAX_BYTES", &value)?;
    }
    if let Some(value) = get("AUDIT_CLONE_DEPTH") {
        workspace.clone_depth = parse_number("AUDIT_CLONE_DEPTH", &value)?;
    }
    if let Some(value) = get("AUDIT_CLONE_TIMEOUT_SECS") {
        workspace.clone_timeout =
            Duration::from_secs(parse_number("AUDIT_CLONE_TIMEOUT_SECS", &value)?);
    }
    if let Some(value) = get("AUDIT_ALLOW_PRIVATE_ADDRESSES") {
        workspace.allow_private_addresses = parse_bool("AUDIT_ALLOW_PRIVATE_ADDRESSES", &value)?;
    }

    // A partial GitHub App configuration fails loudly. Silently falling through
    // to anonymous would turn a typo into a confusing "repository not found".
    let app_id = get("GITHUB_APP_ID");
    let private_key = get("GITHUB_APP_PRIVATE_KEY");
    let installation_id = get("GITHUB_APP_INSTALLATION_ID");
    workspace.credentials.github_app = match (app_id, private_key, installation_id) {
        (Some(app_id), Some(private_key), Some(installation_id)) => Some(GitHubAppConfig {
            app_id,
            private_key,
            installation_id,
        }),
        (None, None, None) => None,
        (app_id, private_key, installation_id) => {
            let mut missing = Vec::new();
            if app_id.is_none() {
                missing.push("GITHUB_APP_ID");
            }
            if private_key.is_none() {
                missing.push("GITHUB_APP_PRIVATE_KEY");
            }
            if installation_id.is_none() {
                missing.push("GITHUB_APP_INSTALLATION_ID");
            }
            return Err(error(
                "GITHUB_APP_*",
                format!(
                    "incomplete GitHub App configuration; missing {}. Set all three or none.",
                    missing.join(", ")
                ),
            ));
        }
    };

    workspace.credentials.token = get("GITHUB_TOKEN");
    workspace.credentials.ssh_private_key = get("SSH_PRIVATE_KEY");
    workspace.credentials.ssh_known_hosts = get("SSH_KNOWN_HOSTS");

    Ok(workspace)
}

fn transport_from<F>(get: &mut F) -> Result<TransportConfig, ConfigError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut transport = TransportConfig::default();
    if let Some(value) = get("AUDIT_TRANSPORT") {
        transport.kind = match value.trim().to_ascii_lowercase().as_str() {
            "stdio" => TransportKind::Stdio,
            "http" => TransportKind::Http,
            other => {
                return Err(error(
                    "AUDIT_TRANSPORT",
                    format!("unknown transport '{other}'; expected 'stdio' or 'http'"),
                ));
            }
        };
    }
    if let Some(value) = get("AUDIT_HTTP_BIND") {
        transport.bind = value;
    }
    transport.resource_url = get("AUDIT_RESOURCE_URL");
    if let Some(value) = get("AUDIT_MAX_SCANS_PER_CALLER") {
        transport.max_scans_per_caller = parse_number("AUDIT_MAX_SCANS_PER_CALLER", &value)?;
    }

    let issuer = get("AUDIT_OAUTH_ISSUER");
    if let Some(issuer) = issuer {
        let ttl = match get("AUDIT_AUTHZ_CACHE_TTL_SECS") {
            Some(value) => Duration::from_secs(parse_number("AUDIT_AUTHZ_CACHE_TTL_SECS", &value)?),
            None => Duration::from_secs(300),
        };
        transport.oauth = Some(OAuthConfig {
            issuer,
            jwks_url: get("AUDIT_OAUTH_JWKS_URL"),
            required_scope: get("AUDIT_OAUTH_REQUIRED_SCOPE"),
            authz_cache_ttl: ttl,
        });
    }

    if transport.kind == TransportKind::Http {
        if !cfg!(feature = "http") {
            return Err(error(
                "AUDIT_TRANSPORT",
                "'http' requires a build with --features http; this binary was built without it",
            ));
        }
        // There is no unauthenticated HTTP mode: serving tools that execute
        // containers over an open port is not a configuration we offer.
        if transport.resource_url.is_none() {
            return Err(error(
                "AUDIT_RESOURCE_URL",
                "required when AUDIT_TRANSPORT=http; token audience is validated against it",
            ));
        }
        if transport.oauth.is_none() {
            return Err(error(
                "AUDIT_OAUTH_ISSUER",
                "required when AUDIT_TRANSPORT=http; there is no unauthenticated HTTP mode",
            ));
        }
    }

    Ok(transport)
}

fn observability_from<F>(get: &mut F) -> ObservabilityConfig
where
    F: FnMut(&str) -> Option<String>,
{
    let mut observability = ObservabilityConfig {
        metrics_bind: get("AUDIT_METRICS_BIND"),
        ..Default::default()
    };
    if let Some(value) = get("AUDIT_LOG_FORMAT") {
        observability.log_format = value;
    }
    if let Some(value) = get("AUDIT_LOG_LEVEL") {
        observability.log_level = value;
    }
    observability
}

fn parse_number<T: std::str::FromStr>(
    variable: &'static str,
    value: &str,
) -> Result<T, ConfigError> {
    value
        .trim()
        .parse::<T>()
        .map_err(|_| error(variable, format!("'{value}' is not a valid number")))
}

fn parse_bool(variable: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(error(variable, format!("'{other}' is not a boolean"))),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_key_values(
    variable: &'static str,
    value: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    split_list(value)
        .into_iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(key, val)| (key.trim().to_string(), val.trim().to_string()))
                .ok_or_else(|| error(variable, format!("'{pair}' is not in key=value form")))
        })
        .collect()
}

/// Convenience for tests and callers building an environment programmatically.
pub fn resolver_from(pairs: &[(&str, &str)]) -> impl FnMut(&str) -> Option<String> + use<> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    move |key: &str| map.get(key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_resolver(resolver_from(pairs))
    }

    #[test]
    fn an_empty_environment_yields_todays_behaviour() {
        // The single most important test in this module: an existing user who
        // upgrades and changes nothing must see no change at all (SC-001).
        let config = config_from(&[]).expect("empty environment is valid");
        assert_eq!(config, Config::default());
        assert_eq!(config.executor, ExecutorKind::Docker);
        assert_eq!(config.transport.kind, TransportKind::Stdio);
        assert_eq!(config.max_parallel, 4);
        assert!(config.transport.oauth.is_none());
        assert!(config.workspace.credentials.source_names().is_empty());
        assert!(!config.workspace.allow_private_addresses);
    }

    #[test]
    fn an_unknown_backend_is_refused_at_startup() {
        let error = config_from(&[("AUDIT_EXECUTOR", "nomad")]).expect_err("should refuse");
        assert_eq!(error.variable, "AUDIT_EXECUTOR");
        assert!(error.detail.contains("nomad"));
    }

    #[test]
    fn selecting_a_backend_without_its_feature_names_the_feature() {
        let result = config_from(&[("AUDIT_EXECUTOR", "kubernetes")]);
        if cfg!(feature = "kubernetes") {
            assert_eq!(
                result.expect("valid with the feature").executor,
                ExecutorKind::Kubernetes
            );
        } else {
            // The message must say what to do, not just "unknown backend".
            let error = result.expect_err("should refuse without the feature");
            assert!(error.detail.contains("--features kubernetes"));
        }
    }

    #[test]
    fn a_partial_github_app_configuration_fails_loudly() {
        // Falling through to anonymous would turn a typo into a confusing
        // "repository not found".
        let error = config_from(&[("GITHUB_APP_ID", "123")]).expect_err("should refuse");
        assert_eq!(error.variable, "GITHUB_APP_*");
        assert!(error.detail.contains("GITHUB_APP_PRIVATE_KEY"));
        assert!(error.detail.contains("GITHUB_APP_INSTALLATION_ID"));
    }

    #[test]
    fn a_complete_github_app_configuration_is_accepted() {
        let config = config_from(&[
            ("GITHUB_APP_ID", "123"),
            ("GITHUB_APP_PRIVATE_KEY", "-----BEGIN-----"),
            ("GITHUB_APP_INSTALLATION_ID", "456"),
        ])
        .expect("complete configuration is valid");
        assert_eq!(
            config.workspace.credentials.source_names(),
            vec!["github_app"]
        );
    }

    #[test]
    fn credential_sources_report_names_not_values() {
        let config = config_from(&[("GITHUB_TOKEN", "ghp_secret"), ("SSH_PRIVATE_KEY", "key")])
            .expect("valid");
        let names = config.workspace.credentials.source_names();
        assert_eq!(names, vec!["token", "ssh_key"]);
        assert!(!format!("{names:?}").contains("ghp_secret"));
    }

    #[test]
    fn http_transport_requires_a_resource_url_and_an_issuer() {
        if !cfg!(feature = "http") {
            let error = config_from(&[("AUDIT_TRANSPORT", "http")]).expect_err("should refuse");
            assert!(error.detail.contains("--features http"));
            return;
        }

        let error = config_from(&[("AUDIT_TRANSPORT", "http")]).expect_err("should refuse");
        assert_eq!(error.variable, "AUDIT_RESOURCE_URL");

        let error = config_from(&[
            ("AUDIT_TRANSPORT", "http"),
            ("AUDIT_RESOURCE_URL", "https://audit.example/mcp"),
        ])
        .expect_err("should refuse without an issuer");
        assert_eq!(error.variable, "AUDIT_OAUTH_ISSUER");

        let config = config_from(&[
            ("AUDIT_TRANSPORT", "http"),
            ("AUDIT_RESOURCE_URL", "https://audit.example/mcp"),
            ("AUDIT_OAUTH_ISSUER", "https://idp.example"),
        ])
        .expect("complete http configuration is valid");
        assert_eq!(config.transport.kind, TransportKind::Http);
        assert_eq!(
            config.transport.oauth.unwrap().authz_cache_ttl,
            Duration::from_secs(300)
        );
    }

    #[test]
    fn stdio_never_requires_authentication() {
        // OAuth settings are simply ignored on stdio; there is nobody to log in.
        let config = config_from(&[("AUDIT_TRANSPORT", "stdio")]).expect("valid");
        assert_eq!(config.transport.kind, TransportKind::Stdio);
        assert_eq!(config.transport.bind, "127.0.0.1:8080");
    }

    #[test]
    fn kubernetes_settings_parse_into_structured_values() {
        let config = config_from(&[
            ("AUDIT_K8S_NAMESPACE", "auditor-development"),
            (
                "AUDIT_K8S_NODE_SELECTOR",
                "kubernetes.io/os=linux,tier=build",
            ),
            ("AUDIT_K8S_IMAGE_PULL_SECRETS", "regcred, other"),
            ("AUDIT_K8S_JOB_TTL_SECONDS", "60"),
        ])
        .expect("valid");
        assert_eq!(
            config.kubernetes.namespace.as_deref(),
            Some("auditor-development")
        );
        assert_eq!(
            config.kubernetes.node_selector,
            vec![
                ("kubernetes.io/os".to_string(), "linux".to_string()),
                ("tier".to_string(), "build".to_string())
            ]
        );
        assert_eq!(
            config.kubernetes.image_pull_secrets,
            vec!["regcred", "other"]
        );
        assert_eq!(config.kubernetes.job_ttl_seconds, 60);
    }

    #[test]
    fn malformed_values_are_refused_with_the_variable_named() {
        let error =
            config_from(&[("AUDIT_K8S_NODE_SELECTOR", "not-a-pair")]).expect_err("should refuse");
        assert_eq!(error.variable, "AUDIT_K8S_NODE_SELECTOR");

        let error = config_from(&[("AUDIT_MAX_PARALLEL", "lots")]).expect_err("should refuse");
        assert_eq!(error.variable, "AUDIT_MAX_PARALLEL");

        let error = config_from(&[("AUDIT_MAX_PARALLEL", "0")]).expect_err("should refuse");
        assert!(error.detail.contains("at least 1"));

        let error =
            config_from(&[("AUDIT_ALLOW_PRIVATE_ADDRESSES", "maybe")]).expect_err("should refuse");
        assert_eq!(error.variable, "AUDIT_ALLOW_PRIVATE_ADDRESSES");
    }

    #[test]
    fn workspace_bounds_have_documented_defaults() {
        let config = config_from(&[]).expect("valid");
        assert_eq!(config.workspace.clone_depth, 1);
        assert_eq!(config.workspace.clone_timeout, Duration::from_secs(300));
        assert_eq!(config.workspace.clone_max_bytes, 2 * 1024 * 1024 * 1024);
        assert!(config.workspace.allow_remote_targets);
    }
}
