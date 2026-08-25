//! Execution target boundary between lifecycle use cases and transports.
//!
//! Use cases must not know whether Docker/systemd operations run on the
//! control machine or on a remote host (goal plan 03 §1). [`ExecutionTarget`]
//! is that seam, kept at exactly five methods; selectors are resolved before
//! anything enters a target, and transports surface failures through one
//! result model while preserving diagnostics.
//!
//! Only two implementations exist by design: [`LocalTarget`] and the
//! OpenSSH-based [`SshTarget`] (task C05), which pipes the frozen wire types
//! from [`wire`] through system OpenSSH into the fixed `remote exec` helper
//! ([`remote_exec`], task C04). No HTTP/Kubernetes/agent targets exist.

pub(crate) mod bootstrap_authority;
pub mod deployment_state;
pub(crate) mod install_exec;
pub mod journal;
pub(crate) mod remote_exec;
pub mod ssh;
pub mod wire;

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

pub use bootstrap_authority::{
    BOOTSTRAP_CLOSED, CONTEXT_FILE_NAME, FRESH_BOOTSTRAP_ALLOWLIST, FRESH_BOOTSTRAP_SCHEMA,
    FreshBootstrapContext, TOKEN_FILE_NAME,
};
pub use deployment_state::{
    ActiveHostOperationRef, ArtifactRefs, BootstrapParams, CONFIG_REVISION_MISMATCH, ConfigState,
    DEPLOYMENT_EXISTS, DEPLOYMENT_STATE_SCHEMA, DEPLOYMENT_UNKNOWN, DeploymentState, Failure,
    HealthRecord, INSTALL_FAILED, MAX_RESOURCES, RESOURCE_DELETE_FORBIDDEN, RESOURCE_UNKNOWN,
    Resource, ResourceOwnership, ResourceScope, RuntimeSurface, StateMutationPayload,
    TargetStateStore,
};
pub use install_exec::{
    ARTIFACT_UNVERIFIED, CONFIG_INVALID, CONFIG_PATH_OCCUPIED, EMBEDDED_IDENTITY_MISMATCH,
    HEALTH_PROBE_FAILED, InstallOrder, OfficialArtifactRef, PlannedSecret, RUNTIME_START_FAILED,
    SECRET_PROVISION_FAILED, SECRET_PURPOSES,
};
pub use journal::{JournalStatus, TargetJournal};
pub use ssh::SshTarget;
pub use wire::{
    HELLO_PRODUCT, HOST_ERR_OPERATION_CONFLICT, HOST_ERR_OPERATION_INVALID,
    HOST_ERR_REMOTE_HELPER_MISMATCH, HOST_OPERATION_KINDS, HOST_PROTOCOL_SCHEMA,
    HostCompletionBody, HostOperation, HostOperationBody, HostOutcome, HostResult,
    InstanceInspection, LOCAL_BUILD_COMMIT, MAX_HOST_OPERATION_BYTES, MAX_HOST_RESULT_BYTES,
    MessageRejection, RejectionCode, RemoteHello, canonical_operation_hash, encode_host_operation,
    encode_host_result, local_hello, parse_host_operation, parse_host_result, verify_remote_hello,
};

/// Stable code for capabilities whose owning wave has not landed yet.
///
/// This is a delivery boundary, not a compatibility shim: the contract is
/// frozen ahead of its executors so transports can answer identically over
/// stdio. After the F01 wave only the app-level ControlOperation execution
/// path (E01/E03) still answers with it.
pub const TARGET_CAPABILITY_UNAVAILABLE: &str = "TARGET_CAPABILITY_UNAVAILABLE";

/// The formalized target state root (task F01): one private directory holding
/// every deployment's [`DeploymentState`] document beside its C07 operation
/// journal. Target administrators may relocate it with
/// `NAZOAUTHCTL_TARGET_STATE_ROOT`; the layout beneath the root is owned by
/// [`TargetStateStore`] and [`TargetJournal`] alone.
pub fn target_state_root() -> anyhow::Result<PathBuf> {
    if let Some(root) = std::env::var_os("NAZOAUTHCTL_TARGET_STATE_ROOT") {
        return Ok(PathBuf::from(root));
    }
    #[cfg(windows)]
    {
        use anyhow::Context as _;
        let program_data = std::env::var_os("ProgramData")
            .context("ProgramData is not set; cannot locate the target state root")?;
        Ok(std::path::PathBuf::from(program_data)
            .join("nazoauthctl")
            .join("target-state"))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from("/var/lib/nazoauthctl/target-state"))
    }
}

/// Read-only facts about an execution host (goal plan 03 §6 fields that have
/// producers today). The remote handshake wave (C08) extends this type with
/// build identity and supported runtimes when their consumers exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOverview {
    pub product: String,
    /// Highest HostOperation/HostResult wire schema this target answers.
    pub protocol_schema: u32,
    pub version: String,
    pub os: String,
    pub arch: String,
}

/// Minimal health snapshot projected from the target-side DeploymentState
/// (`read_health` reports the authoritative `local_health` record).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub deployment_id: String,
    pub healthy: bool,
    pub summary: String,
    pub observed_at: DateTime<Utc>,
}

/// An app-level NazoAuth operation, signed by the instance's Controller Key
/// and carried opaquely by any transport (goal plan 03 §3.3, rule R4).
/// The compact JWS form keeps private-key bytes on the control machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlOperationRequest {
    pub deployment_id: String,
    pub compact_jws: String,
}

/// Receipt of an accepted/rejected app-level operation. Shape stays minimal
/// until E01 freezes the ControlOperation wire it mirrors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlOperationReceipt {
    pub operation_id: String,
    pub accepted: bool,
}

/// The complete surface a transport exposes to lifecycle use cases.
///
/// Exactly the five methods of goal plan 03 §1 — no more, no fewer. Every
/// method takes resolved identifiers (never user selectors) and every
/// failure keeps its diagnostic context for the unified error reporter.
pub trait ExecutionTarget {
    /// Read-only host facts used by `host add`/`check` style flows.
    fn inspect_host(&self) -> anyhow::Result<HostOverview>;

    /// Read-only inspection of one registered instance on this target.
    fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection>;

    /// Execute one host-level operation and return the uniform result model
    /// (goal plan 03 §2: local runs natively, remote via the frozen stdio
    /// contract; both answer with the same [`HostResult`]).
    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult>;

    /// Execute an already-signed app-level ControlOperation against one
    /// instance. Never signs; never touches Controller Key material.
    fn execute_control_operation(
        &self,
        request: &ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt>;

    /// Read the current health view of one instance.
    fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot>;
}

/// The control machine itself.
///
/// Executes through the existing process/filesystem adapters with the OS's
/// own privileges (goal plan 03 §2): no session keys, no JSON loopback — a local
/// caller hands typed values straight to native dispatch, exactly what the
/// remote executor does after parsing the same operation from stdin.
///
/// Since F01, instance inspection and health reads consult the real target
/// [`DeploymentState`] document on this machine through
/// [`TargetStateStore`]; there are no placeholder answers left on those
/// paths. Production resolves the state root via [`target_state_root`];
/// tests inject a private temp root with [`LocalTarget::with_state_root`].
#[derive(Clone)]
pub struct LocalTarget {
    state_root: PathBuf,
    /// Target-side install execution seam (G01): production wires
    /// [`install_exec::HostInstallExecutor`], tests inject scripted doubles so
    /// container engines are never spawned on development machines.
    executor: Arc<dyn install_exec::InstallExecutor>,
}

impl LocalTarget {
    /// Production constructor using the formalized default state root.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            state_root: target_state_root()?,
            executor: Arc::new(install_exec::HostInstallExecutor),
        })
    }

    /// Test seam: read/write DeploymentState under this explicit root.
    pub fn with_state_root(root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: root.into(),
            executor: Arc::new(install_exec::HostInstallExecutor),
        }
    }

    /// Test seam: substitute the install executor.
    #[allow(dead_code)] // test seam: consumed by the clean-install use-case tests
    pub(crate) fn with_install_executor(
        mut self,
        executor: Arc<dyn install_exec::InstallExecutor>,
    ) -> Self {
        self.executor = executor;
        self
    }

    fn unavailable(method: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "{TARGET_CAPABILITY_UNAVAILABLE}: {method} executes once the ControlOperation \
             execution wave (E01/E03) lands"
        )
    }

    /// Execute with the target-side journal contract (task C07): a replay of
    /// an accepted id returns the stored result, the same id with a different
    /// payload conflicts, and fresh operations are journaled pending before
    /// dispatch and finalized after. State mutations (F01) run under this
    /// contract like every other operation.
    pub fn execute_journaled(
        &self,
        operation: &HostOperation,
        journal: &TargetJournal,
    ) -> anyhow::Result<HostResult> {
        if let Err(rejection) = operation.validate() {
            return Ok(HostResult::failed(
                &operation.operation_id,
                HOST_ERR_OPERATION_INVALID,
                format!("{}: {}", rejection.code.as_str(), rejection.detail),
            ));
        }
        let store = TargetStateStore::open(journal.root())?;
        let executor = self.executor.clone();
        journal.run_journaled(operation, |operation| {
            dispatch_host_operation(operation, &store, &executor)
        })
    }
}

impl Default for LocalTarget {
    fn default() -> Self {
        Self::new().expect("default target state root must resolve")
    }
}

impl std::fmt::Debug for LocalTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalTarget")
            .field("state_root", &self.state_root)
            .finish_non_exhaustive()
    }
}

/// Shared dispatch for validated host operations. [`LocalTarget`] answers
/// natively with it and the remote exec helper answers through the identical
/// function after parsing stdin, so both transports cannot drift apart.
pub(crate) fn dispatch_host_operation(
    operation: &HostOperation,
    store: &TargetStateStore,
    executor: &Arc<dyn install_exec::InstallExecutor>,
) -> HostResult {
    debug_assert!(
        operation.validate().is_ok(),
        "dispatch requires a validated operation"
    );
    match &operation.operation {
        HostOperationBody::Ping { nonce } => HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::Ping {
                nonce: nonce.clone(),
            },
        ),
        HostOperationBody::Hello {} => HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::Hello {
                hello: local_hello(local_supported_runtimes()),
            },
        ),
        HostOperationBody::StateInspect {} => answer_inspect(operation, store)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::StateMutate { mutation } => match mutation {
            StateMutationPayload::Bootstrap {
                issuer,
                runtime,
                artifact,
                config_reference,
                config_schema,
                resources,
                install,
            } => {
                let deployment_id = operation.deployment_id.clone().unwrap_or_default();
                match install {
                    // G01 clean install: execute the full order first; only a
                    // fully healthy target commits `local_healthy` state. The
                    // artifact refs recorded in state come from the verified
                    // facts the executor returns — never from the request.
                    Some(order) => {
                        let scope_dir = match store.scope_dir(&deployment_id) {
                            Ok(dir) => dir,
                            Err(failure) => return state_failure(operation, &failure),
                        };
                        ensure_scope_dir(&scope_dir);
                        let job = install_exec::InstallJob {
                            operation_id: &operation.operation_id,
                            deployment_id: &deployment_id,
                            issuer,
                            runtime_kind: &runtime.kind,
                            runtime_object: &runtime.object,
                            config_reference,
                            scope_dir: &scope_dir,
                            order,
                        };
                        // The executor rolls back its own partial work on any
                        // failure: nothing is registered, no state is created.
                        let facts = match executor.execute_install(&job) {
                            Ok(facts) => facts,
                            Err(failure) => return state_failure(operation, &failure),
                        };
                        let params = BootstrapParams {
                            issuer: issuer.clone(),
                            runtime: runtime.clone(),
                            artifact: ArtifactRefs {
                                current: Some(facts.artifact_reference.clone()),
                                previous: None,
                            },
                            config_reference: config_reference.clone(),
                            config_schema: config_schema.clone(),
                            resources: resources.clone(),
                        };
                        match commit_clean_install(store, &deployment_id, params, operation) {
                            Ok(inspection) => HostResult::completed(
                                &operation.operation_id,
                                HostCompletionBody::InstallApplied { inspection },
                            ),
                            Err(failure) => state_failure(operation, &failure),
                        }
                    }
                    None => {
                        let params = BootstrapParams {
                            issuer: issuer.clone(),
                            runtime: runtime.clone(),
                            artifact: artifact.clone(),
                            config_reference: config_reference.clone(),
                            config_schema: config_schema.clone(),
                            resources: resources.clone(),
                        };
                        match store.bootstrap(&deployment_id, params, &operation.operation_id) {
                            Ok(state) => HostResult::completed(
                                &operation.operation_id,
                                HostCompletionBody::StateMutateApplied {
                                    revision: state.config.revision,
                                },
                            ),
                            Err(failure) => state_failure(operation, &failure),
                        }
                    }
                }
            }
            StateMutationPayload::ApplyConfig { reference, schema } => {
                // CAS is mandatory at the wire level; validate() already
                // rejected absent expectations, so treat None defensively.
                let Some(expected_revision) = operation.expected_revision else {
                    return state_failure(
                        operation,
                        &Failure::new(
                            HOST_ERR_OPERATION_INVALID,
                            "apply-config requires expected_revision",
                        ),
                    );
                };
                let deployment_id = operation.deployment_id.clone().unwrap_or_default();
                match store.apply_config(
                    &deployment_id,
                    expected_revision,
                    reference.clone(),
                    schema.clone(),
                    &operation.operation_id,
                ) {
                    Ok(config) => HostResult::completed(
                        &operation.operation_id,
                        HostCompletionBody::StateMutateApplied {
                            revision: config.revision,
                        },
                    ),
                    Err(failure) => state_failure(operation, &failure),
                }
            }
        },
    }
}

/// Commit the post-install DeploymentState: fresh document plus the healthy
/// local-health fact, both under the install operation's idempotency. An
/// interrupted commit replays safely because both writes key off the same
/// operation id.
fn commit_clean_install(
    store: &TargetStateStore,
    deployment_id: &str,
    params: BootstrapParams,
    operation: &HostOperation,
) -> Result<InstanceInspection, Failure> {
    store.bootstrap(deployment_id, params, &operation.operation_id)?;
    store.record_local_health(
        deployment_id,
        true,
        "local readiness probe passed after clean install".to_owned(),
        &operation.operation_id,
    )?;
    Ok(inspection_from_state(store.load_existing(deployment_id)?))
}

fn inspection_from_state(state: DeploymentState) -> InstanceInspection {
    InstanceInspection {
        deployment_id: state.deployment_id,
        issuer: state.issuer,
        observed_at: Utc::now(),
        revision: state.config.revision,
        runtime: state.runtime,
        artifact: state.artifact,
        config_reference: state.config.reference,
        config_schema: state.config.schema,
        resources: state.resources,
        healthy: state.local_health.healthy,
        health_summary: state.local_health.summary,
        active_host_operation: state
            .active_host_operation
            .map(|active| active.operation_id),
    }
}

fn ensure_scope_dir(scope_dir: &std::path::Path) {
    let _ = crate::filesystem::ensure_directory_chain(scope_dir);
}

fn state_failure(operation: &HostOperation, failure: &Failure) -> HostResult {
    HostResult::failed(
        &operation.operation_id,
        failure.code,
        failure.detail.clone(),
    )
}

fn answer_inspect(
    operation: &HostOperation,
    store: &TargetStateStore,
) -> Result<HostResult, Failure> {
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::StateInspect {
            inspection: inspection_from_state(state),
        },
    ))
}

/// Project a live inspection into the health view (`read_health`).
fn health_from_inspection(inspection: &InstanceInspection) -> HealthSnapshot {
    HealthSnapshot {
        deployment_id: inspection.deployment_id.clone(),
        healthy: inspection.healthy,
        summary: inspection.health_summary.clone(),
        observed_at: inspection.observed_at,
    }
}

/// Runtimes this installation could drive, detected without spawning engines:
/// engine binaries present on PATH plus the systemd host backend on Linux.
fn local_supported_runtimes() -> Vec<String> {
    let mut runtimes = Vec::new();
    for engine in ["podman", "docker"] {
        if crate::process::command_exists(engine) {
            runtimes.push(engine.to_owned());
        }
    }
    if cfg!(target_os = "linux") {
        runtimes.push("host".to_owned());
    }
    runtimes
}

impl ExecutionTarget for LocalTarget {
    fn inspect_host(&self) -> anyhow::Result<HostOverview> {
        Ok(HostOverview {
            product: "nazoauthctl".to_owned(),
            protocol_schema: HOST_PROTOCOL_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
        // Live read of the real state file through the same store and the
        // same validation the remote helper answers with — no cache, no
        // Registry shortcut (F01 boundary: the Registry cannot mutate or
        // impersonate target state).
        let store = TargetStateStore::open(&self.state_root)?;
        let operation = HostOperation::state_inspect(Uuid::now_v7().to_string(), deployment_id);
        match dispatch_host_operation(&operation, &store, &self.executor).outcome {
            HostOutcome::Completed {
                body: HostCompletionBody::StateInspect { inspection },
            } => Ok(inspection),
            HostOutcome::Completed { .. } => unreachable!("inspect answers with an inspection"),
            HostOutcome::Failed { code, detail } => Err(anyhow::anyhow!("{code}: {detail}")),
        }
    }

    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        // Mirror the remote executor's admission order (parse → validate →
        // dispatch) so local and remote targets accept the same inputs.
        // [`HostOperation::validate`] owns every semantic rule, including
        // per-kind payload constraints; [`dispatch_host_operation`] stays
        // mechanical and shared with the remote helper.
        if let Err(rejection) = operation.validate() {
            return Ok(HostResult::failed(
                &operation.operation_id,
                HOST_ERR_OPERATION_INVALID,
                format!("{}: {}", rejection.code.as_str(), rejection.detail),
            ));
        }
        // State mutations run under the C07 journal contract on this machine
        // exactly as the remote exec helper journals them on a target host —
        // the install use case cannot tell the transports apart.
        if matches!(operation.operation, HostOperationBody::StateMutate { .. }) {
            let journal = TargetJournal::open(&self.state_root)?;
            return self.execute_journaled(operation, &journal);
        }
        let store = TargetStateStore::open(&self.state_root)?;
        Ok(dispatch_host_operation(operation, &store, &self.executor))
    }

    fn execute_control_operation(
        &self,
        _request: &ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt> {
        Err(Self::unavailable("execute_control_operation"))
    }

    fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
        Ok(health_from_inspection(
            &self.inspect_instance(deployment_id)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::PrivateTempDir;

    fn temp_target() -> anyhow::Result<(PrivateTempDir, LocalTarget, TargetJournal)> {
        let temp = PrivateTempDir::new("nazauthctl-local-state-test")?;
        let root = temp.path().join("state");
        let target = LocalTarget::with_state_root(&root);
        let journal = TargetJournal::open(&root)?;
        Ok((temp, target, journal))
    }

    fn sample_bootstrap(deployment_id: &str) -> HostOperation {
        HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            deployment_id,
            None,
            StateMutationPayload::Bootstrap {
                issuer: "https://auth.example.com".to_owned(),
                runtime: RuntimeSurface::new("podman", "nazoauth-main").expect("runtime"),
                artifact: ArtifactRefs {
                    current: Some("sha256:abcdef0123456789".to_owned()),
                    previous: None,
                },
                config_reference: "/etc/nazauth/config.toml".to_owned(),
                config_schema: "nazauth-config-v1".to_owned(),
                resources: vec![
                    Resource::new(
                        "app-container",
                        "container",
                        "nazoauth-main",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )
                    .expect("managed resource"),
                    Resource::new(
                        "shared-db",
                        "postgres",
                        "pg-main.example.internal:5432",
                        ResourceOwnership::External,
                        ResourceScope::Shared,
                    )
                    .expect("external resource"),
                    Resource::new(
                        "backup-volume",
                        "volume",
                        "/srv/backups/deploy-alpha",
                        ResourceOwnership::External,
                        ResourceScope::Deployment,
                    )
                    .expect("external dedicated resource"),
                ],
                install: None,
            },
        )
    }

    #[test]
    fn local_ping_smoke_executes_without_json_loopback() -> anyhow::Result<()> {
        let (_temp, target, _journal) = temp_target()?;
        let operation = HostOperation::ping(Uuid::now_v7().to_string(), "smoke-probe");
        let result = target.execute_host_operation(&operation)?;
        assert_eq!(result.operation_id, operation.operation_id);
        assert_eq!(
            result.outcome,
            HostOutcome::Completed {
                body: HostCompletionBody::Ping {
                    nonce: "smoke-probe".to_owned(),
                },
            }
        );
        // The identical bytes must survive the full stdio round trip so a
        // remote executor can answer the same message (C04 readiness).
        let encoded = encode_host_result(&result)?;
        assert_eq!(parse_host_result(&encoded)?, result);
        Ok(())
    }

    #[test]
    fn local_target_reports_host_facts() -> anyhow::Result<()> {
        let overview = temp_target()?.1.inspect_host()?;
        assert_eq!(overview.product, "nazoauthctl");
        assert_eq!(overview.protocol_schema, HOST_PROTOCOL_SCHEMA);
        assert!(!overview.version.is_empty());
        assert!(!overview.os.is_empty());
        assert!(!overview.arch.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_operations_fail_through_the_shared_model() -> anyhow::Result<()> {
        let (_temp, target, _journal) = temp_target()?;
        let mut operation = HostOperation::ping(Uuid::now_v7().to_string(), "probe");
        operation.expected_revision = Some(4);
        let result = target.execute_host_operation(&operation)?;
        let HostOutcome::Failed { code, detail } = result.outcome else {
            panic!("expected failed outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_INVALID);
        assert!(detail.contains("expected_revision"), "{detail}");

        let mut operation = HostOperation::ping(Uuid::now_v7().to_string(), "probe");
        // A well-formed UUID that is not v7 must be rejected.
        operation.operation_id = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        let result = target.execute_host_operation(&operation)?;
        let HostOutcome::Failed { code, detail } = result.outcome else {
            panic!("expected failed outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_INVALID);
        assert!(detail.contains("UUIDv7"), "{detail}");
        Ok(())
    }

    #[test]
    fn local_hello_reports_the_helper_identity() -> anyhow::Result<()> {
        let (_temp, target, _journal) = temp_target()?;
        let hello = HostOperation::hello(Uuid::now_v7().to_string());
        let result = target.execute_host_operation(&hello)?;
        let HostOutcome::Completed {
            body: HostCompletionBody::Hello { hello },
        } = result.outcome
        else {
            panic!("expected a hello completion");
        };
        verify_remote_hello(&hello).expect("local helper answers its own handshake");
        Ok(())
    }

    #[test]
    fn journaled_execution_replays_and_conflicts_through_local_target() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-local-journaled")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let target = LocalTarget::with_state_root(temp.path().join("state"));

        let operation = HostOperation::ping(Uuid::now_v7().to_string(), "journaled");
        let first = target.execute_journaled(&operation, &journal)?;
        let second = target.execute_journaled(&operation, &journal)?;
        assert_eq!(first, second, "replay returns the stored result");

        let mut conflict = operation.clone();
        conflict.operation = HostOperationBody::Ping {
            nonce: "different".to_owned(),
        };
        let result = target.execute_journaled(&conflict, &journal)?;
        let HostOutcome::Failed { code, .. } = result.outcome else {
            panic!("expected the conflict outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_CONFLICT);
        Ok(())
    }

    // ---------- F01/F02/F04 local real-file behavior ----------

    #[test]
    fn local_inspection_reads_the_real_state_file_on_this_machine() -> anyhow::Result<()> {
        let (_temp, target, journal) = temp_target()?;

        let unknown = target.inspect_instance("deploy-alpha").err().unwrap();
        assert!(
            unknown.to_string().contains(DEPLOYMENT_UNKNOWN),
            "{unknown}"
        );

        let bootstrapped = target.execute_journaled(&sample_bootstrap("deploy-alpha"), &journal)?;
        let HostOutcome::Completed {
            body: HostCompletionBody::StateMutateApplied { revision },
        } = bootstrapped.outcome
        else {
            panic!("expected a bootstrap completion: {bootstrapped:?}");
        };
        assert_eq!(revision, 1);

        // The state document really exists beside its journal.
        let state_path = journal
            .root()
            .join("deployments")
            .join("deploy-alpha")
            .join("state.json");
        let raw = std::fs::read_to_string(&state_path)?;
        let persisted: DeploymentState = serde_json::from_str(&raw)?;
        assert_eq!(persisted.deployment_id, "deploy-alpha");
        assert_eq!(persisted.resources.len(), 3);

        let inspection = target.inspect_instance("deploy-alpha")?;
        assert_eq!(inspection.deployment_id, "deploy-alpha");
        assert_eq!(inspection.issuer, "https://auth.example.com");
        assert_eq!(inspection.revision, 1);
        assert_eq!(inspection.runtime.kind, "podman");
        assert_eq!(
            inspection.artifact.current.as_deref(),
            Some("sha256:abcdef0123456789")
        );
        assert_eq!(inspection.resources.len(), 3);
        assert!(!inspection.healthy);

        let health = target.read_health("deploy-alpha")?;
        assert_eq!(health.deployment_id, "deploy-alpha");
        assert!(!health.healthy);
        // Each method performs its own live read, so timestamps are
        // independent; they must still be fresh.
        let age = (chrono::Utc::now() - health.observed_at).num_milliseconds();
        assert!((0..60_000).contains(&age), "stale health read: {age}ms");
        Ok(())
    }

    #[test]
    fn config_cas_advances_only_against_the_expected_revision() -> anyhow::Result<()> {
        let (_temp, target, journal) = temp_target()?;
        target.execute_journaled(&sample_bootstrap("deploy-alpha"), &journal)?;

        let apply = |expected: Option<u64>| {
            let operation = HostOperation::state_mutate(
                Uuid::now_v7().to_string(),
                "deploy-alpha",
                expected,
                StateMutationPayload::ApplyConfig {
                    reference: "/etc/nazauth/config-v2.toml".to_owned(),
                    schema: "nazauth-config-v2".to_owned(),
                },
            );
            target.execute_journaled(&operation, &journal).unwrap()
        };

        // Stale expectation: never last-write-wins.
        let stale = apply(Some(99));
        let HostOutcome::Failed { code, detail } = stale.outcome else {
            panic!("expected the CAS failure");
        };
        assert_eq!(code, CONFIG_REVISION_MISMATCH, "{detail}");

        // Correct expectation advances exactly one revision.
        let applied = apply(Some(1));
        let HostOutcome::Completed {
            body: HostCompletionBody::StateMutateApplied { revision },
        } = applied.outcome
        else {
            panic!("expected the applied outcome: {applied:?}");
        };
        assert_eq!(revision, 2);

        // The same expectation again is now stale too.
        let stale = apply(Some(1));
        let HostOutcome::Failed { code, .. } = stale.outcome else {
            panic!("expected the second CAS failure");
        };
        assert_eq!(code, CONFIG_REVISION_MISMATCH);

        let inspection = target.inspect_instance("deploy-alpha")?;
        assert_eq!(inspection.revision, 2);
        assert_eq!(inspection.config_reference, "/etc/nazauth/config-v2.toml");
        assert_eq!(inspection.config_schema, "nazauth-config-v2");
        Ok(())
    }

    #[test]
    fn bootstrap_over_existing_state_fails_and_replays_interrupted_runs() -> anyhow::Result<()> {
        let (_temp, target, journal) = temp_target()?;
        let first = target.execute_journaled(&sample_bootstrap("deploy-alpha"), &journal)?;
        assert!(matches!(first.outcome, HostOutcome::Completed { .. }));

        // A different bootstrap over existing state fails closed.
        let clash = target.execute_journaled(&sample_bootstrap("deploy-alpha"), &journal)?;
        let HostOutcome::Failed { code, .. } = clash.outcome else {
            panic!("expected DEPLOYMENT_EXISTS");
        };
        assert_eq!(code, DEPLOYMENT_EXISTS);

        // The exact interrupted operation replays without advancing.
        let mut replay_operation = sample_bootstrap("deploy-alpha");
        replay_operation.operation_id = {
            // Reuse the id recorded in the stored state.
            let raw = std::fs::read_to_string(
                journal
                    .root()
                    .join("deployments")
                    .join("deploy-alpha")
                    .join("state.json"),
            )?;
            let state: DeploymentState = serde_json::from_str(&raw)?;
            state
                .active_host_operation
                .expect("bootstrap op")
                .operation_id
        };
        let replayed = target.execute_journaled(&replay_operation, &journal)?;
        let HostOutcome::Completed {
            body: HostCompletionBody::StateMutateApplied { revision },
        } = replayed.outcome
        else {
            panic!("expected the replayed bootstrap to succeed: {replayed:?}");
        };
        assert_eq!(revision, 1, "replay must not advance the revision");
        Ok(())
    }

    #[test]
    fn ownership_delete_guard_is_enforced_against_concrete_facts() -> anyhow::Result<()> {
        let (_temp, target, journal) = temp_target()?;
        target.execute_journaled(&sample_bootstrap("deploy-alpha"), &journal)?;
        let store = TargetStateStore::open(journal.root())?;
        let state = store.load_existing("deploy-alpha")?;

        // managed + deployment: the only deletable classification.
        let managed = state.exact_managed_deployment_resource("app-container")?;
        assert_eq!(managed.locator, "nazoauth-main");

        for (resource_id, expected_code) in [
            ("shared-db", RESOURCE_DELETE_FORBIDDEN),
            ("backup-volume", RESOURCE_DELETE_FORBIDDEN),
            ("ghost-resource", RESOURCE_UNKNOWN),
        ] {
            let failure = state
                .exact_managed_deployment_resource(resource_id)
                .expect_err(resource_id);
            assert_eq!(failure.code, expected_code, "{}: {failure:?}", resource_id);
        }
        Ok(())
    }

    #[test]
    fn corrupt_or_foreign_state_fails_closed_with_reset_guidance() -> anyhow::Result<()> {
        use crate::registry::STATE_RESET_REQUIRED;

        let temp = PrivateTempDir::new("nazauthctl-local-state-test")?;
        let root = temp.path().join("state");
        let target = LocalTarget::with_state_root(&root);
        let store = TargetStateStore::open(&root)?;
        let dir = root.join("deployments").join("deploy-beta");
        std::fs::create_dir_all(&dir)?;

        // Store level: the full remediation guidance names the file.
        crate::filesystem::atomic_write(&dir.join("state.json"), b"{ not json", 0o600)?;
        let failure = store.load_existing("deploy-beta").expect_err("corrupt");
        let rendered = format!("{failure:?}");
        assert!(rendered.contains(STATE_RESET_REQUIRED), "{rendered}");
        assert!(rendered.contains("back the file up"), "{rendered}");
        assert!(rendered.contains("state.json"), "{rendered}");

        // Wire level: diagnostics are bounded, but the stable codes survive
        // sanitization so automation can classify the failure.
        let error = target.inspect_instance("deploy-beta").err().unwrap();
        let rendered = format!("{error:#}");
        assert!(rendered.contains(DEPLOYMENT_UNKNOWN), "{rendered}");
        assert!(rendered.contains(STATE_RESET_REQUIRED), "{rendered}");

        // A foreign-schema document (future or hand-edited) is equally
        // rejected instead of being interpreted leniently.
        crate::filesystem::atomic_write(
            &dir.join("state.json"),
            br#"{"schema":99,"deployment_id":"deploy-beta"}"#,
            0o600,
        )?;
        let failure = store
            .load_existing("deploy-beta")
            .expect_err("foreign schema");
        assert!(failure.detail.contains(STATE_RESET_REQUIRED), "{failure:?}");
        Ok(())
    }

    #[test]
    fn only_the_control_operation_boundary_still_reports_unavailable() -> anyhow::Result<()> {
        let (_temp, target, _journal) = temp_target()?;
        let error = target
            .execute_control_operation(&ControlOperationRequest {
                deployment_id: "deploy-alpha".to_owned(),
                compact_jws: "jws".to_owned(),
            })
            .err()
            .unwrap();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(TARGET_CAPABILITY_UNAVAILABLE),
            "{rendered}"
        );
        Ok(())
    }
}
