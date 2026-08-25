//! Kubernetes execution backend.
//!
//! Runs each scanner as a `batch/v1` Job. Where the Docker backend needs a
//! socket that would hand every scanner image root on the node, this needs
//! only the namespace an operator gives it.
//!
//! The workspace arrives through a git-clone initContainer writing into an
//! `emptyDir` that the scanner container mounts read-only — no host path, no
//! PVC, no socket. That is a *stronger* isolation posture than the local
//! default, not a weaker one.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, EmptyDirVolumeSource, EnvVar, EnvVarSource, LocalObjectReference,
    PodSpec, PodTemplateSpec, ResourceRequirements, Secret, SecretKeySelector, SecurityContext,
    Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, ListParams, LogParams, PostParams};
use std::collections::BTreeMap as SecretData;
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::config::KubernetesConfig;
use crate::executor::{
    ExecutionOutcome, ExecutionRequest, Executor, Termination, WORKSPACE_MOUNT, WorkspaceSource,
};

/// Delete a Job and let the controller clean up its pods behind us.
fn background_delete() -> DeleteParams {
    DeleteParams {
        propagation_policy: Some(kube::api::PropagationPolicy::Background),
        ..Default::default()
    }
}

/// Marks the boundary between stdout and stderr in a merged pod log.
///
/// Kubernetes does not separate the two streams — `pods/log` returns one
/// merged buffer. That is the exact condition that corrupted gosec's SARIF in
/// the Docker path, where a stderr line landed mid-document. Where the command
/// runs through a shell we redirect stderr to a file and replay it after this
/// marker, so the parser still sees clean stdout.
const STREAM_MARKER: &str = "<<<AUDIT-MCP-STDERR>>>";

/// Every Job this backend creates carries this label, so orphans can be found
/// and reaped without touching anything else in the namespace.
const MANAGED_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_VALUE: &str = "audit-mcp";

/// Pinned. An unpinned tag that drifts or 404s is the same failure class as an
/// unpinned tool download delivering an HTML error page.
const GIT_IMAGE: &str = "alpine/git:v2.47.2";

const WORKSPACE_VOLUME: &str = "workspace";

pub struct KubernetesExecutor {
    config: KubernetesConfig,
    client: OnceCell<kube::Client>,
}

// `kube::Client` has no Debug, and the `Executor` trait needs one. Printing the
// namespace is all that is useful anyway; a client's internals are not.
impl std::fmt::Debug for KubernetesExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KubernetesExecutor")
            .field("namespace", &self.namespace())
            .finish()
    }
}

impl KubernetesExecutor {
    pub fn new(config: KubernetesConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }

    /// Connect lazily, exactly as the Docker backend does, so the server
    /// starts with no cluster and picks one up if it appears. Failures are not
    /// cached.
    async fn client(&self) -> Result<&kube::Client, String> {
        self.client
            .get_or_try_init(|| async {
                // `try_default` already prefers the in-cluster ServiceAccount
                // and falls back to a kubeconfig, which is the precedence we
                // want; no variable selects between them.
                kube::Client::try_default()
                    .await
                    .map_err(|err| format!("Kubernetes cluster is not reachable: {err}"))
            })
            .await
    }

    fn namespace(&self) -> String {
        self.config
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    async fn run(&self, request: ExecutionRequest<'_>) -> Result<ExecutionOutcome, String> {
        // A directory on this host is not reachable from a cluster. Saying so
        // plainly beats scanning an empty tree and reporting it clean.
        if let WorkspaceSource::Repository {
            url, credential, ..
        } = &request.source
            && url.starts_with("ssh://")
            && credential.is_none()
        {
            return Err(
                "the kubernetes backend cannot clone over SSH yet: the key and host key material would need their own delivery. Use an https:// target with GITHUB_TOKEN or a GitHub App, or AUDIT_EXECUTOR=docker."
                    .to_string(),
            );
        }

        if request.source == WorkspaceSource::LocalPath {
            return Err(
                "the kubernetes backend cannot scan a local path: a cluster cannot see this host's filesystem. Pass a repository target (a git URL or owner/repo) instead, or use AUDIT_EXECUTOR=docker."
                    .to_string(),
            );
        }

        let client = self.client().await?;
        let namespace = self.namespace();
        let jobs: Api<Job> = Api::namespaced(client.clone(), &namespace);
        let pods: Api<k8s_openapi::api::core::v1::Pod> =
            Api::namespaced(client.clone(), &namespace);

        let name = format!("audit-scan-{}", Uuid::new_v4());
        let image = request.scanner.image.clone();
        let started = Instant::now();

        // A credential is delivered through a Secret, never through the Job
        // spec: a Job spec is readable by anyone with `get jobs` in the
        // namespace, and a token in one would be readable by all of them.
        let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        let secret_name = self.create_clone_secret(&secrets, &name, &request).await?;

        let job = self.build_job(&name, &request, secret_name.as_deref());

        let created = jobs
            .create(&PostParams::default(), &job)
            .await
            .map_err(|err| format!("failed to create Job '{name}' in '{namespace}': {err}"));
        if let Err(error) = created {
            if let Some(secret_name) = &secret_name {
                let _ = secrets.delete(secret_name, &background_delete()).await;
            }
            return Err(error);
        }

        let outcome = self
            .await_completion(&jobs, &pods, &name, &request, started, &image)
            .await;

        // Delete on every path. `ttlSecondsAfterFinished` is only a backstop
        // for the case where this process dies before getting here.
        let _ = jobs.delete(&name, &background_delete()).await;
        if let Some(secret_name) = &secret_name {
            // The credential must not outlive the scan that needed it.
            let _ = secrets.delete(secret_name, &background_delete()).await;
        }

        outcome
    }

    /// Stage a clone credential as a Secret, returning its name.
    async fn create_clone_secret(
        &self,
        secrets: &Api<Secret>,
        job_name: &str,
        request: &ExecutionRequest<'_>,
    ) -> Result<Option<String>, String> {
        let WorkspaceSource::Repository { credential, .. } = &request.source else {
            return Ok(None);
        };
        let Some(credential) = credential else {
            return Ok(None);
        };

        let name = format!("{job_name}-clone");
        let mut data = SecretData::new();
        data.insert("username".to_string(), credential.username.clone());
        data.insert("password".to_string(), credential.secret.clone());

        let mut labels = BTreeMap::new();
        labels.insert(MANAGED_LABEL.to_string(), MANAGED_VALUE.to_string());

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels: Some(labels),
                ..Default::default()
            },
            string_data: Some(data),
            type_: Some("Opaque".to_string()),
            ..Default::default()
        };

        secrets
            .create(&PostParams::default(), &secret)
            .await
            .map_err(|err| format!("failed to stage the clone credential: {err}"))?;
        Ok(Some(name))
    }

    async fn await_completion(
        &self,
        jobs: &Api<Job>,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        name: &str,
        request: &ExecutionRequest<'_>,
        started: Instant,
        image: &str,
    ) -> Result<ExecutionOutcome, String> {
        let deadline = tokio::time::Instant::now() + request.timeout;
        let mut poll = tokio::time::interval(Duration::from_millis(750));

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let logs = self.collect_logs(pods, name).await.unwrap_or_default();
                    let (stdout, combined) = split_streams(&logs);
                    return Ok(ExecutionOutcome {
                        image: image.to_string(),
                        stdout,
                        combined,
                        exit_code: None,
                        duration: started.elapsed(),
                        termination: Termination::TimedOut,
                    });
                }
                _ = poll.tick() => {
                    let Ok(Some(job)) = jobs.get_opt(name).await else {
                        continue;
                    };
                    let status = job.status.clone().unwrap_or_default();

                    let finished = status.succeeded.unwrap_or(0) > 0
                        || status.failed.unwrap_or(0) > 0;
                    if !finished {
                        // A pod that cannot be scheduled or cannot pull its
                        // image will never finish, and waiting for the timeout
                        // would report that as a timeout rather than as what it
                        // is.
                        if let Some(reason) = self.blocking_condition(pods, name).await {
                            let logs = self.collect_logs(pods, name).await.unwrap_or_default();
                            let (stdout, combined) = split_streams(&logs);
                            return Ok(ExecutionOutcome {
                                image: image.to_string(),
                                stdout,
                                combined,
                                exit_code: None,
                                duration: started.elapsed(),
                                termination: Termination::Infrastructure(reason),
                            });
                        }
                        continue;
                    }

                    let logs = self.collect_logs(pods, name).await.unwrap_or_default();
                    let (stdout, combined) = split_streams(&logs);
                    let exit_code = self.exit_code(pods, name).await;

                    // A pod the cluster killed did not "exit non-zero"; it was
                    // taken away, and saying so is the difference between a
                    // diagnosable failure and a mystery.
                    if let Some(reason) = self.termination_reason(pods, name).await {
                        return Ok(ExecutionOutcome {
                            image: image.to_string(),
                            stdout,
                            combined,
                            exit_code,
                            duration: started.elapsed(),
                            termination: Termination::Infrastructure(reason),
                        });
                    }

                    return Ok(ExecutionOutcome {
                        image: image.to_string(),
                        stdout,
                        combined,
                        exit_code,
                        duration: started.elapsed(),
                        termination: Termination::Completed,
                    });
                }
            }
        }
    }

    /// The pod belonging to a Job, if it exists yet.
    async fn pod_name(
        &self,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        job_name: &str,
    ) -> Option<String> {
        let params = ListParams::default().labels(&format!("job-name={job_name}"));
        pods.list(&params)
            .await
            .ok()?
            .items
            .into_iter()
            .next()
            .and_then(|pod| pod.metadata.name)
    }

    async fn collect_logs(
        &self,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        job_name: &str,
    ) -> Option<String> {
        let pod = self.pod_name(pods, job_name).await?;
        let params = LogParams {
            container: Some("scanner".to_string()),
            ..Default::default()
        };
        pods.logs(&pod, &params).await.ok()
    }

    /// A reason the pod will never run, rather than a reason it failed.
    async fn blocking_condition(
        &self,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        job_name: &str,
    ) -> Option<String> {
        let name = self.pod_name(pods, job_name).await?;
        let pod = pods.get_opt(&name).await.ok()??;
        let status = pod.status?;

        for container in status
            .init_container_statuses
            .into_iter()
            .flatten()
            .chain(status.container_statuses.into_iter().flatten())
        {
            let waiting = container.state.and_then(|state| state.waiting)?;
            let reason = waiting.reason.unwrap_or_default();
            if matches!(
                reason.as_str(),
                "ImagePullBackOff" | "ErrImagePull" | "InvalidImageName" | "CreateContainerError"
            ) {
                return Some(format!(
                    "{reason}: {}",
                    waiting.message.unwrap_or_else(|| "no detail".to_string())
                ));
            }
        }
        None
    }

    /// Why the cluster ended this pod, when it was the cluster's doing.
    async fn termination_reason(
        &self,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        job_name: &str,
    ) -> Option<String> {
        let name = self.pod_name(pods, job_name).await?;
        let pod = pods.get_opt(&name).await.ok()??;
        let status = pod.status?;

        if status.phase.as_deref() == Some("Failed")
            && let Some(reason) = status.reason.as_deref()
            && matches!(
                reason,
                "Evicted" | "NodeAffinity" | "Shutdown" | "UnexpectedAdmissionError"
            )
        {
            return Some(format!(
                "pod {reason}: {}",
                status.message.unwrap_or_else(|| "no detail".to_string())
            ));
        }

        for container in status.container_statuses.into_iter().flatten() {
            let terminated = container.state.and_then(|state| state.terminated)?;
            if terminated.reason.as_deref() == Some("OOMKilled") {
                return Some("container OOMKilled: it exceeded its memory limit".to_string());
            }
        }
        None
    }

    async fn exit_code(
        &self,
        pods: &Api<k8s_openapi::api::core::v1::Pod>,
        job_name: &str,
    ) -> Option<i64> {
        let name = self.pod_name(pods, job_name).await?;
        let pod = pods.get_opt(&name).await.ok()??;
        pod.status?
            .container_statuses?
            .into_iter()
            .find(|status| status.name == "scanner")?
            .state?
            .terminated
            .map(|terminated| i64::from(terminated.exit_code))
    }

    fn build_job(
        &self,
        name: &str,
        request: &ExecutionRequest<'_>,
        clone_secret: Option<&str>,
    ) -> Job {
        let mut labels = BTreeMap::new();
        labels.insert(MANAGED_LABEL.to_string(), MANAGED_VALUE.to_string());

        let command = wrap_for_stream_split(&request.command);
        let environment: Vec<EnvVar> = request
            .environment
            .iter()
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| EnvVar {
                name: key.to_string(),
                value: Some(value.to_string()),
                ..Default::default()
            })
            .collect();

        let mount = VolumeMount {
            name: WORKSPACE_VOLUME.to_string(),
            mount_path: WORKSPACE_MOUNT.to_string(),
            // The same guarantee as the Docker bind mount: a scanner may read
            // the tree and may not change it.
            read_only: Some(true),
            ..Default::default()
        };

        let scanner = Container {
            name: "scanner".to_string(),
            image: Some(request.scanner.image.clone()),
            command: Some(command),
            working_dir: Some(WORKSPACE_MOUNT.to_string()),
            env: (!environment.is_empty()).then_some(environment),
            volume_mounts: Some(vec![mount.clone()]),
            security_context: Some(self.security_context()),
            resources: Some(self.resources()),
            ..Default::default()
        };

        // The workspace is staged by an initContainer rather than mounted from
        // the host, so nothing outside the cluster is exposed.
        let clone_env = clone_secret.map(|secret_name| {
            ["username", "password"]
                .into_iter()
                .map(|key| EnvVar {
                    name: format!("AUDIT_GIT_{}", key.to_uppercase()),
                    value_from: Some(EnvVarSource {
                        secret_key_ref: Some(SecretKeySelector {
                            name: secret_name.to_string(),
                            key: key.to_string(),
                            optional: Some(false),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect::<Vec<_>>()
        });

        let clone = Container {
            name: "clone".to_string(),
            image: Some(GIT_IMAGE.to_string()),
            command: Some(clone_command(&request.source, clone_secret.is_some())),
            env: clone_env,
            volume_mounts: Some(vec![VolumeMount {
                name: WORKSPACE_VOLUME.to_string(),
                mount_path: WORKSPACE_MOUNT.to_string(),
                read_only: Some(false),
                ..Default::default()
            }]),
            security_context: Some(self.security_context()),
            ..Default::default()
        };

        let pod_spec = PodSpec {
            init_containers: Some(vec![clone]),
            containers: vec![scanner],
            restart_policy: Some("Never".to_string()),
            service_account_name: self.config.service_account.clone(),
            node_selector: (!self.config.node_selector.is_empty()).then(|| {
                self.config
                    .node_selector
                    .iter()
                    .cloned()
                    .collect::<BTreeMap<_, _>>()
            }),
            image_pull_secrets: (!self.config.image_pull_secrets.is_empty()).then(|| {
                self.config
                    .image_pull_secrets
                    .iter()
                    .map(|name| LocalObjectReference { name: name.clone() })
                    .collect()
            }),
            volumes: Some(vec![Volume {
                name: WORKSPACE_VOLUME.to_string(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            }]),
            ..Default::default()
        };

        Job {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(JobSpec {
                // One attempt. A scanner is not idempotent in cost, and a
                // silent retry would double the work and confuse the timing.
                backoff_limit: Some(0),
                // A backstop for cleanup if this process dies before deleting.
                ttl_seconds_after_finished: Some(self.config.job_ttl_seconds as i32),
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(pod_spec),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn security_context(&self) -> SecurityContext {
        SecurityContext {
            allow_privilege_escalation: Some(false),
            privileged: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                // Deliberately no `add`. The Docker backend restores
                // DAC_READ_SEARCH to read host directories a bind mount exposes
                // with foreign ownership; an emptyDir written by our own
                // initContainer has ownership we control, so the grant would
                // buy nothing and the narrowest relaxation is none.
                add: None,
            }),
            ..Default::default()
        }
    }

    fn resources(&self) -> ResourceRequirements {
        let mut limits = BTreeMap::new();
        limits.insert(
            "memory".to_string(),
            Quantity(self.config.memory_limit.clone()),
        );
        if let Some(cpu) = &self.config.cpu_limit {
            limits.insert("cpu".to_string(), Quantity(cpu.clone()));
        }

        let mut requests = BTreeMap::new();
        if let Some(memory) = &self.config.memory_request {
            requests.insert("memory".to_string(), Quantity(memory.clone()));
        }
        if let Some(cpu) = &self.config.cpu_request {
            requests.insert("cpu".to_string(), Quantity(cpu.clone()));
        }

        ResourceRequirements {
            limits: Some(limits),
            requests: (!requests.is_empty()).then_some(requests),
            ..Default::default()
        }
    }

    /// Remove Jobs this backend created that no longer have an owner —
    /// whatever `ttlSecondsAfterFinished` has not already collected after a
    /// controller restart.
    pub async fn reap_orphans(&self) -> usize {
        let Ok(client) = self.client().await else {
            return 0;
        };
        let jobs: Api<Job> = Api::namespaced(client.clone(), &self.namespace());
        let params = ListParams::default().labels(&format!("{MANAGED_LABEL}={MANAGED_VALUE}"));
        let Ok(list) = jobs.list(&params).await else {
            return 0;
        };

        let mut reaped = 0;
        for job in list.items {
            let Some(name) = job.metadata.name else {
                continue;
            };
            let status = job.status.unwrap_or_default();
            if (status.succeeded.unwrap_or(0) > 0 || status.failed.unwrap_or(0) > 0)
                && jobs.delete(&name, &background_delete()).await.is_ok()
            {
                reaped += 1;
            }
        }
        reaped
    }
}

/// The initContainer script that stages the workspace.
///
/// Shallow by default, and the URL is passed as an argument rather than
/// interpolated into the script, so a repository name can never be read as
/// shell syntax.
fn clone_command(source: &WorkspaceSource, authenticated: bool) -> Vec<String> {
    match source {
        WorkspaceSource::Repository { url, reference, .. } => {
            // The credential helper's shape is in the command; the token it
            // reads comes from the environment, which is not world readable
            // the way a process listing is.
            let helper = if authenticated {
                "-c 'credential.helper=!f() { echo username=$AUDIT_GIT_USERNAME; echo password=$AUDIT_GIT_PASSWORD; }; f' "
            } else {
                ""
            };
            let mut script = format!(
                "set -e; export GIT_TERMINAL_PROMPT=0; git {helper}clone --quiet --depth 1 --no-tags \"$1\" \"$0\""
            );
            if reference.is_some() {
                script = format!(
                    "set -e; export GIT_TERMINAL_PROMPT=0; git {helper}clone --quiet --depth 1 --no-tags --branch \"$2\" \"$1\" \"$0\""
                );
            }
            let mut command = vec![
                "sh".to_string(),
                "-c".to_string(),
                script,
                WORKSPACE_MOUNT.to_string(),
                url.clone(),
            ];
            if let Some(reference) = reference {
                command.push(reference.clone());
            }
            command
        }
        // Unreachable in practice: `run` refuses a local path before building
        // a Job, and this keeps that refusal from being silently bypassed.
        WorkspaceSource::LocalPath => vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo 'no workspace source' >&2; exit 1".to_string(),
        ],
    }
}

/// Wrap a shell command so stderr is replayed after a marker.
///
/// Kubernetes merges the two streams into one log, which is exactly what
/// corrupted gosec's SARIF in the Docker path. Where the command already runs
/// through a shell we can separate them again cheaply. A direct-argv command
/// on a distroless image has no shell to wrap with, so it is left alone and
/// its streams stay merged.
fn wrap_for_stream_split(command: &[String]) -> Vec<String> {
    let [shell, flag, script] = command else {
        return command.to_vec();
    };
    if (shell != "sh" && shell != "bash") || flag != "-c" {
        return command.to_vec();
    }

    vec![
        shell.clone(),
        flag.clone(),
        format!(
            "{{ {script} ; }} 2>/tmp/audit-stderr; code=$?; echo '{STREAM_MARKER}'; cat /tmp/audit-stderr 2>/dev/null; exit $code"
        ),
    ]
}

/// Split a merged log back into (stdout, combined) using the marker.
fn split_streams(logs: &str) -> (String, String) {
    match logs.split_once(STREAM_MARKER) {
        Some((stdout, stderr)) => {
            let combined = format!("{stdout}{stderr}");
            (stdout.to_string(), combined)
        }
        // No marker: the command was not wrappable, so the streams really are
        // merged and the parser gets what there is.
        None => (logs.to_string(), logs.to_string()),
    }
}

impl Executor for KubernetesExecutor {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(client) = self.client().await else {
                return false;
            };

            // Listing is not a usable check: the API server answers happily for
            // a namespace that does not exist, so a typo'd namespace would look
            // healthy right up until the first scan. A dry-run create asks the
            // question that actually matters — may we create a Job *here*? —
            // and validates the namespace and RBAC without creating anything.
            let jobs: Api<Job> = Api::namespaced(client.clone(), &self.namespace());
            let probe = Job {
                metadata: ObjectMeta {
                    name: Some("audit-mcp-preflight".to_string()),
                    ..Default::default()
                },
                spec: Some(JobSpec {
                    template: PodTemplateSpec {
                        spec: Some(PodSpec {
                            containers: vec![Container {
                                name: "probe".to_string(),
                                image: Some("busybox:1.37".to_string()),
                                ..Default::default()
                            }],
                            restart_policy: Some("Never".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            };
            let params = PostParams {
                dry_run: true,
                ..Default::default()
            };
            jobs.create(&params, &probe).await.is_ok()
        })
    }

    fn execute<'a>(
        &'a self,
        request: ExecutionRequest<'a>,
    ) -> BoxFuture<'a, Result<ExecutionOutcome, String>> {
        Box::pin(async move { self.run(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{OutputFormat, ScannerDefinition};
    use std::path::PathBuf;

    fn scanner() -> ScannerDefinition {
        ScannerDefinition {
            name: "shellcheck".to_string(),
            description: "test".to_string(),
            image: "koalaman/shellcheck-alpine:stable".to_string(),
            categories: vec!["Test".to_string()],
            command_template: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            install_script: None,
            success_exit_codes: vec![0],
            output_format: OutputFormat::Json,
            timeout_secs: Some(60),
        }
    }

    fn request<'a>(
        definition: &'a ScannerDefinition,
        command: Vec<String>,
    ) -> ExecutionRequest<'a> {
        ExecutionRequest {
            scanner: definition,
            workspace: PathBuf::from("/tmp/workspace"),
            source: WorkspaceSource::Repository {
                url: "https://github.com/octocat/Hello-World.git".to_string(),
                reference: None,
                credential: None,
            },
            command,
            environment: vec!["FOO=bar".to_string()],
            timeout: Duration::from_secs(60),
        }
    }

    #[test]
    fn the_job_keeps_every_isolation_guarantee() {
        let executor = KubernetesExecutor::new(KubernetesConfig::default());
        let definition = scanner();
        let job = executor.build_job(
            "audit-scan-test",
            &request(&definition, vec!["sh".into(), "-c".into(), "true".into()]),
            None,
        );

        let spec = job.spec.expect("spec");
        let pod = spec.template.spec.expect("pod spec");
        let container = &pod.containers[0];
        let security = container
            .security_context
            .as_ref()
            .expect("security context");

        assert_eq!(security.allow_privilege_escalation, Some(false));
        assert_eq!(security.privileged, Some(false));
        let capabilities = security.capabilities.as_ref().expect("capabilities");
        assert_eq!(capabilities.drop.as_deref(), Some(&["ALL".to_string()][..]));
        // The Docker path's DAC_READ_SEARCH must not be inherited here: the
        // reason for it does not exist in a cluster-built workspace.
        assert!(capabilities.add.is_none());

        let mount = &container.volume_mounts.as_ref().expect("mounts")[0];
        assert_eq!(mount.read_only, Some(true), "the workspace is read-only");

        // One attempt, and a TTL backstop for a controller that dies mid-scan.
        assert_eq!(spec.backoff_limit, Some(0));
        assert_eq!(spec.ttl_seconds_after_finished, Some(300));
        assert_eq!(pod.restart_policy.as_deref(), Some("Never"));

        // No host path anywhere: the workspace is an emptyDir the cluster owns.
        let volume = &pod.volumes.as_ref().expect("volumes")[0];
        assert!(volume.empty_dir.is_some());
        assert!(volume.host_path.is_none());
    }

    #[test]
    fn operator_settings_are_applied_verbatim() {
        let config = KubernetesConfig {
            namespace: Some("auditor-development".to_string()),
            service_account: Some("scanner".to_string()),
            memory_limit: "2Gi".to_string(),
            cpu_limit: Some("500m".to_string()),
            memory_request: Some("256Mi".to_string()),
            node_selector: vec![("kubernetes.io/os".to_string(), "linux".to_string())],
            image_pull_secrets: vec!["regcred".to_string()],
            job_ttl_seconds: 60,
            ..Default::default()
        };
        let executor = KubernetesExecutor::new(config);
        let definition = scanner();
        let job = executor.build_job(
            "audit-scan-test",
            &request(&definition, vec!["sh".into(), "-c".into(), "true".into()]),
            None,
        );

        let spec = job.spec.expect("spec");
        let pod = spec.template.spec.expect("pod spec");
        assert_eq!(pod.service_account_name.as_deref(), Some("scanner"));
        assert_eq!(
            pod.node_selector.expect("selector").get("kubernetes.io/os"),
            Some(&"linux".to_string())
        );
        assert_eq!(pod.image_pull_secrets.expect("secrets")[0].name, "regcred");
        assert_eq!(spec.ttl_seconds_after_finished, Some(60));

        let resources = pod.containers[0].resources.as_ref().expect("resources");
        assert_eq!(
            resources.limits.as_ref().expect("limits").get("memory"),
            Some(&Quantity("2Gi".to_string()))
        );
        assert_eq!(
            resources.requests.as_ref().expect("requests").get("memory"),
            Some(&Quantity("256Mi".to_string()))
        );
    }

    #[test]
    fn jobs_are_labelled_so_orphans_can_be_found() {
        let executor = KubernetesExecutor::new(KubernetesConfig::default());
        let definition = scanner();
        let job = executor.build_job(
            "audit-scan-test",
            &request(&definition, vec!["sh".into(), "-c".into(), "true".into()]),
            None,
        );
        assert_eq!(
            job.metadata.labels.expect("labels").get(MANAGED_LABEL),
            Some(&MANAGED_VALUE.to_string())
        );
    }

    #[test]
    fn a_shell_command_is_wrapped_so_streams_can_be_split_again() {
        // Kubernetes merges stdout and stderr; this is how we get them back.
        let wrapped = wrap_for_stream_split(&[
            "sh".to_string(),
            "-c".to_string(),
            "gosec -fmt sarif ./...".to_string(),
        ]);
        assert_eq!(wrapped.len(), 3);
        assert!(wrapped[2].contains("gosec -fmt sarif ./..."));
        assert!(wrapped[2].contains("2>/tmp/audit-stderr"));
        assert!(wrapped[2].contains(STREAM_MARKER));
        // The scanner's own exit code must survive the wrapper.
        assert!(wrapped[2].contains("exit $code"));
    }

    #[test]
    fn a_distroless_command_is_left_alone() {
        // No shell in the image, so there is nothing to wrap with.
        let command = vec!["/grype".to_string(), "dir:.".to_string()];
        assert_eq!(wrap_for_stream_split(&command), command);
    }

    #[test]
    fn streams_are_split_back_apart_at_the_marker() {
        let logs = format!("{{\"runs\":[]}}\n{STREAM_MARKER}\nexit status 1\n");
        let (stdout, combined) = split_streams(&logs);
        // The SARIF is intact — this is the corruption the marker prevents.
        assert_eq!(stdout.trim(), "{\"runs\":[]}");
        assert!(combined.contains("exit status 1"));
        assert!(!stdout.contains("exit status 1"));
    }

    #[test]
    fn an_unmarked_log_is_treated_as_genuinely_merged() {
        let (stdout, combined) = split_streams("plain output");
        assert_eq!(stdout, "plain output");
        assert_eq!(combined, "plain output");
    }

    #[test]
    fn the_clone_container_passes_the_url_as_an_argument() {
        // Interpolating it into the script would let a repository name be read
        // as shell syntax.
        let command = clone_command(
            &WorkspaceSource::Repository {
                url: "https://github.com/owner/repo.git".to_string(),
                reference: None,
                credential: None,
            },
            false,
        );
        assert_eq!(command[0], "sh");
        assert!(command[2].contains("git clone"));
        assert!(
            !command[2].contains("github.com"),
            "the URL must not be inside the script"
        );
        assert_eq!(command[3], WORKSPACE_MOUNT);
        assert_eq!(command[4], "https://github.com/owner/repo.git");
    }

    #[test]
    fn a_requested_reference_reaches_the_clone_container() {
        let command = clone_command(
            &WorkspaceSource::Repository {
                url: "https://github.com/owner/repo.git".to_string(),
                reference: Some("v1.2.3".to_string()),
                credential: None,
            },
            false,
        );
        assert!(command[2].contains("--branch"));
        assert_eq!(command[5], "v1.2.3");
    }

    #[tokio::test]
    async fn a_local_path_is_refused_with_an_explanation() {
        // The alternative is scanning an empty emptyDir and calling it clean.
        let executor = KubernetesExecutor::new(KubernetesConfig::default());
        let definition = scanner();
        let mut req = request(&definition, vec!["sh".into(), "-c".into(), "true".into()]);
        req.source = WorkspaceSource::LocalPath;

        let error = executor.run(req).await.expect_err("must refuse");
        assert!(error.contains("cannot see this host's filesystem"));
        assert!(error.contains("AUDIT_EXECUTOR=docker"));
    }

    #[test]
    fn a_credential_never_appears_in_the_job_spec() {
        // A Job spec is readable by anyone with `get jobs` in the namespace.
        let executor = KubernetesExecutor::new(KubernetesConfig::default());
        let definition = scanner();
        let mut req = request(&definition, vec!["sh".into(), "-c".into(), "true".into()]);
        req.source = WorkspaceSource::Repository {
            url: "https://github.com/owner/private.git".to_string(),
            reference: None,
            credential: Some(crate::executor::CloneCredential {
                username: "x-access-token".to_string(),
                secret: "ghp_supersecrettoken".to_string(),
            }),
        };

        let job = executor.build_job("audit-scan-test", &req, Some("audit-scan-test-clone"));
        let rendered = serde_json::to_string(&job).expect("job serializes");
        assert!(
            !rendered.contains("ghp_supersecrettoken"),
            "the token must reach the pod through a Secret, not the Job spec"
        );
        // It is referenced, not inlined.
        assert!(rendered.contains("audit-scan-test-clone"));
        assert!(rendered.contains("secretKeyRef"));
    }

    #[test]
    fn a_clone_credential_does_not_print_itself() {
        let credential = crate::executor::CloneCredential {
            username: "x-access-token".to_string(),
            secret: "ghp_supersecrettoken".to_string(),
        };
        assert!(!format!("{credential:?}").contains("supersecrettoken"));
    }

    #[tokio::test]
    async fn ssh_targets_are_refused_rather_than_cloned_anonymously() {
        // Silently falling back to an anonymous clone would report a private
        // repository as clean.
        let executor = KubernetesExecutor::new(KubernetesConfig::default());
        let definition = scanner();
        let mut req = request(&definition, vec!["sh".into(), "-c".into(), "true".into()]);
        req.source = WorkspaceSource::Repository {
            url: "ssh://git@github.com/owner/repo.git".to_string(),
            reference: None,
            credential: None,
        };

        let error = executor.run(req).await.expect_err("must refuse");
        assert!(error.contains("cannot clone over SSH"));
    }

    #[test]
    fn the_backend_reports_its_name_and_namespace() {
        let executor = KubernetesExecutor::new(KubernetesConfig {
            namespace: Some("auditor-development".to_string()),
            ..Default::default()
        });
        assert_eq!(executor.name(), "kubernetes");
        assert_eq!(executor.namespace(), "auditor-development");
        // With no namespace configured we do not invent one.
        assert_eq!(
            KubernetesExecutor::new(KubernetesConfig::default()).namespace(),
            "default"
        );
    }
}
