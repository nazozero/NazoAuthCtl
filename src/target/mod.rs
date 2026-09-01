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

pub(crate) mod admin_exec;
pub(crate) mod backup;
pub(crate) mod backup_exec;
pub(crate) mod control_exec;
pub mod deployment_state;
pub(crate) mod install_exec;
pub mod journal;
pub(crate) mod remote_exec;
pub mod ssh;
pub(crate) mod uninstall_exec;
pub(crate) mod update_exec;
pub mod wire;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use nazo_operator_protocol::{ControlResult, validate_control_result};
use uuid::Uuid;

use crate::error_codes::CONFIG_REVISION_MISMATCH;
use crate::runtime_backend;

use self::wire::{local_hello_for_target, sanitize};

pub use crate::model::{DatabaseRestore, ReleaseRollbackPolicy};
pub use backup::{BackupProjection, RestoreTestReceipt, SnapshotManifest, SnapshotProjection};
pub use backup_exec::{BACKUP_EXECUTION_FAILED, RESTORE_TEST_FAILED};
pub use control_exec::{
    CONTROL_EXECUTION_UNAVAILABLE, CONTROL_OUTCOME_UNKNOWN, CONTROL_TARGET_DRIFT,
};
pub use deployment_state::{
    ActiveHostOperationRef, AppliedMigration, ArtifactRefs, BootstrapParams, ConfigState,
    DEPLOYMENT_EXISTS, DEPLOYMENT_STATE_SCHEMA, DEPLOYMENT_UNKNOWN, DeploymentState, Failure,
    HealthRecord, INSTALL_FAILED, OBJECT_IDENTITY_MISMATCH, ROLLBACK_RECOVERY_REQUIRED,
    ROLLBACK_UNAVAILABLE, ReleaseVersion, Resource, ResourceOwnership, ResourceScope,
    RuntimeSurface, StateMutationPayload, TargetStateStore, UpdateBackupPrecondition,
};
pub use install_exec::{
    ARTIFACT_UNVERIFIED, CONFIG_INVALID, CONFIG_PATH_OCCUPIED, HEALTH_PROBE_FAILED,
    INSTALL_OUTCOME_UNKNOWN, InstallOrder, OfficialArtifactRef, PlannedSecret,
    RUNTIME_START_FAILED, SECRET_PROVISION_FAILED, SECRET_PURPOSES, StagedConfig,
    TARGET_IDENTITY_MISMATCH,
};
pub use journal::{JournalStatus, OperationLogEntry, OperationOutcomeSummary, TargetJournal};
pub use ssh::SshTarget;
pub use update_exec::{ACTIVATION_FAILED, ROLLBACK_ARTIFACT_MISSING};
pub use wire::SecretMaterial;
pub use wire::{
    AdminProvisionReceipt, HELLO_PRODUCT, HOST_ERR_OPERATION_INVALID, HOST_OPERATION_KINDS,
    HOST_PROTOCOL_SCHEMA, HostCompletionBody, HostOperation, HostOperationBody, HostOutcome,
    HostResult, InstanceInspection, MAX_CONTROL_CHANGE_SET_BYTES, MAX_HOST_OPERATION_BYTES,
    MAX_HOST_RESULT_BYTES, MessageRejection, RejectionCode, RemoteHello, RuntimeInstanceIdentity,
    canonical_operation_hash, encode_host_operation, encode_host_result, local_hello,
    parse_host_operation, parse_host_result, verify_remote_hello,
};

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
/// release version and supported runtimes when their consumers exist.
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
pub struct ControlOperationRequest {
    pub operation_id: String,
    pub deployment_id: String,
    pub compact_jws: String,
    /// Raw material consumed only by tenant-resource Apply. Other operations
    /// must leave it absent.
    pub change_set: Option<SecretMaterial>,
}

/// Receipt of one delivered ControlOperation. `accepted` is true exactly when
/// the target surfaced the operator's durable [`ControlResult`] — the
/// operation was journal-accepted server-side. `accepted = false` represents
/// only a definitive refusal before acceptance; transport failures and unknown
/// outcomes surface as `Err` and must be resumed with the same request.
#[derive(Clone, Debug)]
pub struct ControlOperationReceipt {
    pub operation_id: String,
    pub accepted: bool,
    /// The durable application result when the target produced one.
    pub result: Option<ControlResult>,
    /// Stable target rejection code for the only pre-acceptance path.
    pub rejection_code: Option<String>,
}

/// Admit a target answer only after validating the complete ControlResult
/// structure and its operation-id echo. The caller that prepared the signed
/// operation owns the final request-hash equality check because the transport
/// deliberately carries the compact JWS opaquely and has no second hash fact.
fn accepted_control_operation_receipt(
    request_operation_id: String,
    result: ControlResult,
) -> anyhow::Result<ControlOperationReceipt> {
    validate_control_result(&result).map_err(|error| {
        anyhow::anyhow!(
            "{HOST_ERR_OPERATION_INVALID}: target returned an invalid ControlResult: {error}"
        )
    })?;
    if result.operation_id != request_operation_id {
        anyhow::bail!(
            "{HOST_ERR_OPERATION_INVALID}: the target answered operation '{}' while '{}' was presented",
            result.operation_id,
            request_operation_id
        );
    }
    Ok(ControlOperationReceipt {
        operation_id: request_operation_id,
        accepted: true,
        result: Some(result),
        rejection_code: None,
    })
}

fn control_operation_receipt(
    request_operation_id: String,
    outcome: HostOutcome,
) -> anyhow::Result<ControlOperationReceipt> {
    match outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::ControlOperationExecuted { result },
        } => accepted_control_operation_receipt(request_operation_id, result),
        HostOutcome::Completed { .. } => anyhow::bail!(
            "{HOST_ERR_OPERATION_INVALID}: the target answered an unexpected completion instead of a ControlOperation result"
        ),
        HostOutcome::Failed { code, .. }
            if matches!(
                code.as_str(),
                crate::error_codes::INPUT_INVALID
                    | crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED
                    | crate::error_codes::TARGET_IDENTITY_MISMATCH
                    | crate::error_codes::CONFIG_REVISION_MISMATCH
                    | crate::error_codes::OPERATION_ID_CONFLICT
            ) =>
        {
            Ok(ControlOperationReceipt {
                operation_id: request_operation_id,
                accepted: false,
                result: None,
                rejection_code: Some(code),
            })
        }
        HostOutcome::Failed { code, detail } => anyhow::bail!("{code}: {detail}"),
    }
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
        request: ControlOperationRequest,
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
///
/// The G wave replaces every executor placeholder: installs run through the
/// install seam, delivered ControlOperations through the one-shot NazoAuth
/// operator, and update/rollback/uninstall orders through their lifecycle
/// seams. Each seam is individually injectable so development machines never
/// spawn engines.
#[derive(Clone)]
pub struct LocalTarget {
    state_root: PathBuf,
    /// Target-side install execution seam (G01): production wires
    /// [`install_exec::HostInstallExecutor`], tests inject scripted doubles so
    /// container engines are never spawned on development machines.
    executor: Arc<dyn install_exec::InstallExecutor>,
    /// Delivered-ControlOperation seam (G-wave decision 1).
    control: Arc<dyn control_exec::ControlOperationExecutor>,
    /// Target-side administrator provisioning seam.
    admin: Arc<dyn admin_exec::AdminProvisionExecutor>,
    /// Update/rollback order seam (G03/G04).
    lifecycle: Arc<dyn update_exec::LifecycleExecutor>,
    /// Uninstall deletion seam (G06).
    deletion: Arc<dyn uninstall_exec::DeletionExecutor>,
}

impl LocalTarget {
    /// Production constructor using the formalized default state root.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            state_root: target_state_root()?,
            executor: Arc::new(install_exec::HostInstallExecutor),
            control: Arc::new(control_exec::HostControlOperator),
            admin: Arc::new(admin_exec::HostAdminProvisioner),
            lifecycle: Arc::new(update_exec::HostLifecycleExecutor),
            deletion: Arc::new(uninstall_exec::HostDeletionExecutor),
        })
    }

    /// Test seam: read/write DeploymentState under this explicit root.
    pub fn with_state_root(root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: root.into(),
            executor: Arc::new(install_exec::HostInstallExecutor),
            control: Arc::new(control_exec::HostControlOperator),
            admin: Arc::new(admin_exec::HostAdminProvisioner),
            lifecycle: Arc::new(update_exec::HostLifecycleExecutor),
            deletion: Arc::new(uninstall_exec::HostDeletionExecutor),
        }
    }

    /// Test seam: substitute the install executor.
    #[cfg(test)]
    pub(crate) fn with_install_executor(
        mut self,
        executor: Arc<dyn install_exec::InstallExecutor>,
    ) -> Self {
        self.executor = executor;
        self
    }

    /// Test seam: substitute the ControlOperation operator.
    #[cfg(test)]
    pub(crate) fn with_control_executor(
        mut self,
        control: Arc<dyn control_exec::ControlOperationExecutor>,
    ) -> Self {
        self.control = control;
        self
    }

    /// Test seam: substitute administrator provisioning without spawning a
    /// runtime one-shot process.
    #[cfg(test)]
    pub(crate) fn with_admin_provision_executor(
        mut self,
        admin: Arc<dyn admin_exec::AdminProvisionExecutor>,
    ) -> Self {
        self.admin = admin;
        self
    }

    /// Test seam: substitute the update/rollback executor.
    #[cfg(test)]
    pub(crate) fn with_lifecycle_executor(
        mut self,
        lifecycle: Arc<dyn update_exec::LifecycleExecutor>,
    ) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Test seam: substitute the uninstall deletion executor.
    #[cfg(test)]
    pub(crate) fn with_deletion_executor(
        mut self,
        deletion: Arc<dyn uninstall_exec::DeletionExecutor>,
    ) -> Self {
        self.deletion = deletion;
        self
    }

    fn executors(&self) -> Executors<'_> {
        Executors {
            install: &self.executor,
            control: &self.control,
            admin: &self.admin,
            lifecycle: &self.lifecycle,
            deletion: &self.deletion,
        }
    }

    /// Execute a previously validated operation with the target-side journal
    /// contract (task C07): a replay of an accepted id returns the stored
    /// result, the same id with a different payload conflicts, and fresh
    /// side-effecting operations are journaled pending before dispatch and
    /// finalized after. Pure reads dispatch directly because replay is
    /// already harmless and retaining their results would only create journal
    /// noise.
    ///
    /// Validation belongs to the public `ExecutionTarget`/remote wire
    /// boundaries. Keeping that precondition here avoids re-running the full
    /// wire validator after a caller has already admitted the operation.
    pub(crate) fn execute_journaled_validated(
        &self,
        operation: &HostOperation,
        journal: &TargetJournal,
    ) -> anyhow::Result<HostResult> {
        let store = TargetStateStore::open(journal.root())?;
        let executors = self.executors();
        if !operation.operation.requires_journal() {
            return Ok(dispatch_validated_host_operation(
                operation, &store, &executors,
            ));
        }
        journal.run_journaled(operation, |operation| {
            if matches!(
                &operation.operation,
                HostOperationBody::StateMutate {
                    mutation: StateMutationPayload::Uninstall { .. }
                }
            ) {
                let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
                let completed = match store.converge_uninstall_completion(
                    deployment_id,
                    operation.expected_revision.unwrap_or_default(),
                    &operation.operation_id,
                ) {
                    Ok(completed) => completed,
                    Err(failure) => return state_failure(operation, &failure),
                };
                if completed {
                    return HostResult::completed(
                        &operation.operation_id,
                        HostCompletionBody::StateMutateApplied {
                            revision: operation.expected_revision.unwrap_or_default(),
                            control_result: None,
                        },
                    );
                }
            }
            dispatch_validated_host_operation(operation, &store, &executors)
        })
    }
}

/// The bundle of target-side executors handed to shared dispatch.
pub(crate) struct Executors<'a> {
    pub(crate) install: &'a Arc<dyn install_exec::InstallExecutor>,
    pub(crate) control: &'a Arc<dyn control_exec::ControlOperationExecutor>,
    pub(crate) admin: &'a Arc<dyn admin_exec::AdminProvisionExecutor>,
    pub(crate) lifecycle: &'a Arc<dyn update_exec::LifecycleExecutor>,
    pub(crate) deletion: &'a Arc<dyn uninstall_exec::DeletionExecutor>,
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
fn dispatch_validated_host_operation(
    operation: &HostOperation,
    store: &TargetStateStore,
    executors: &Executors<'_>,
) -> HostResult {
    match &operation.operation {
        HostOperationBody::Ping { nonce } => HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::Ping {
                nonce: nonce.clone(),
            },
        ),
        HostOperationBody::Hello {} => answer_hello(operation, store)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::StateInspect {} => answer_inspect(operation, store)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::StateList {} => answer_state_list(operation, store)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::AdminCreate { email, password } => answer_admin_create(
            operation,
            store,
            email,
            password.as_bytes(),
            executors.admin,
        )
        .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::RuntimeLogs { limit } => answer_runtime_logs(operation, store, *limit)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::JournalRead { limit } => answer_journal_read(operation, store, *limit)
            .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::BackupSnapshot {} => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            let answered = (|| -> Result<HostResult, Failure> {
                let state = store.load_existing(deployment_id)?;
                let scope_dir = store.scope_dir(deployment_id)?;
                let manifest = backup_exec::snapshot(&scope_dir, &state, &operation.operation_id)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupSnapshotCreated { manifest },
                ))
            })();
            answered.unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupRestoreTest {} => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            let answered = (|| -> Result<HostResult, Failure> {
                let state = store.load_existing(deployment_id)?;
                let scope_dir = store.scope_dir(deployment_id)?;
                let receipt = backup_exec::restore_test(&scope_dir, &state)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupRestoreTested { receipt },
                ))
            })();
            answered.unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupRecover {
            expected_manifest_sha256,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let expected_revision = operation.expected_revision.ok_or_else(|| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "backup recover requires expected_revision",
                    )
                })?;
                let state = store.load_existing(deployment_id)?;
                let backend = runtime_backend::backend(state.runtime.kind);
                let runtime_was_running = backend
                    .inspect_optional(&state.runtime.object)
                    .map_err(|error| {
                        Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string()))
                    })?
                    .is_some_and(|runtime| runtime.running);
                backend
                    .quiesce_for_recovery(&state.runtime.object)
                    .map_err(|error| {
                        Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string()))
                    })?;
                let scope_dir = store.scope_dir(deployment_id)?;
                let facts = match backup_exec::recover(
                    &scope_dir,
                    &state,
                    expected_manifest_sha256,
                    &operation.operation_id,
                ) {
                    Ok(facts) => facts,
                    Err(mut failure) => {
                        let safe_to_restart = runtime_was_running
                            && backup_exec::recovery_path_switch_started(
                                &scope_dir,
                                &operation.operation_id,
                            )
                            .is_ok_and(|started| !started);
                        if safe_to_restart {
                            match backend.start(&state.runtime.object) {
                                Ok(()) => failure.detail.push_str(
                                    "; original runtime restarted after safe recovery abort",
                                ),
                                Err(error) => failure.detail.push_str(&format!(
                                    "; original runtime restart failed: {}",
                                    sanitize(error.to_string())
                                )),
                            }
                        }
                        return Err(failure);
                    }
                };
                let committed = store.apply_recovery(
                    deployment_id,
                    expected_revision,
                    &facts,
                    &operation.operation_id,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupRecovered {
                        snapshot_id: facts.snapshot_id,
                        manifest_sha256: facts.manifest_sha256,
                        revision: committed.config.revision,
                    },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupRecoveryCandidateStage {
            recovery_operation_id,
            state_epoch,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let expected_revision = operation.expected_revision.ok_or_else(|| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "recovery candidate stage requires expected_revision",
                    )
                })?;
                let state = store.load_existing(deployment_id)?;
                if state.config.revision != expected_revision {
                    return Err(Failure::new(
                        CONFIG_REVISION_MISMATCH,
                        "recovery candidate stage no longer matches the restored deployment revision",
                    ));
                }
                let scope_dir = store.scope_dir(deployment_id)?;
                let endpoint = backup_exec::stage_recovery_candidate(
                    &scope_dir,
                    &state,
                    recovery_operation_id,
                    state_epoch,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupRecoveryCandidateStaged { endpoint },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupRecoveryCandidateCleanup { endpoint } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let state = store.load_existing(deployment_id)?;
                backup_exec::cleanup_recovery_candidate(&state, endpoint)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupRecoveryCandidateCleaned {},
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupRecoveryActivate {
            recovery_operation_id,
            state_epoch,
            not_before,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let expected_revision = operation.expected_revision.ok_or_else(|| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "recovery activation requires expected_revision",
                    )
                })?;
                let state = store.load_existing(deployment_id)?;
                if state.config.revision != expected_revision {
                    return Err(Failure::new(
                        CONFIG_REVISION_MISMATCH,
                        "recovery activation no longer matches the restored deployment revision",
                    ));
                }
                let scope_dir = store.scope_dir(deployment_id)?;
                backup_exec::activate_recovered_runtime(
                    &scope_dir,
                    &state,
                    recovery_operation_id,
                    state_epoch,
                    *not_before,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupRecoveryActivated {},
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupExportPrepare {} => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let state = store.load_existing(deployment_id)?;
                let scope_dir = store.scope_dir(deployment_id)?;
                let plan =
                    backup_exec::prepare_export(&scope_dir, &state, &operation.operation_id)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupTransferPrepared { plan },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupImportPrepare {} => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let scope_dir = store.scope_dir(deployment_id)?;
                let plan = backup_exec::prepare_import(
                    &scope_dir,
                    deployment_id,
                    &operation.operation_id,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupTransferPrepared { plan },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupTransferRead {
            transfer_operation_id,
            file_name,
            offset,
            maximum_bytes,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let scope_dir = store.scope_dir(deployment_id)?;
                let chunk = backup_exec::read_transfer_chunk(
                    &scope_dir,
                    transfer_operation_id,
                    file_name,
                    *offset,
                    *maximum_bytes,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupTransferChunk { chunk },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupTransferWrite {
            transfer_operation_id,
            file_name,
            offset,
            total_bytes,
            file_sha256,
            bytes,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let scope_dir = store.scope_dir(deployment_id)?;
                backup_exec::write_transfer_chunk(
                    &scope_dir,
                    transfer_operation_id,
                    file_name,
                    *offset,
                    *total_bytes,
                    file_sha256,
                    bytes,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupTransferWritten {},
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupImportFinalize {
            transfer_operation_id,
            expected_manifest_sha256,
            source_host_id,
            destination_host_id,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let local_target_id = target_identity(store.root())?.to_string();
                if destination_host_id != &local_target_id || source_host_id == destination_host_id {
                    return Err(Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "backup import receipt identities do not bind distinct source and destination targets",
                    ));
                }
                let scope_dir = store.scope_dir(deployment_id)?;
                let receipt = backup_exec::finalize_import(
                    &scope_dir,
                    deployment_id,
                    transfer_operation_id,
                    expected_manifest_sha256,
                    source_host_id,
                    destination_host_id,
                )?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupImportFinalized { receipt },
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupOffHostRecord { receipt } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let local_target_id = target_identity(store.root())?.to_string();
                if receipt.source_host_id != local_target_id
                    || receipt.destination_host_id == local_target_id
                {
                    return Err(Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "off-host receipt identities do not bind this source and a distinct destination",
                    ));
                }
                let scope_dir = store.scope_dir(deployment_id)?;
                backup_exec::record_off_host_copy(&scope_dir, receipt)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupOffHostRecorded {},
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::BackupTransferCleanup {
            transfer_operation_id,
        } => {
            let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
            (|| -> Result<HostResult, Failure> {
                let scope_dir = store.scope_dir(deployment_id)?;
                backup_exec::cleanup_transfer(&scope_dir, transfer_operation_id)?;
                Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::BackupTransferCleaned {},
                ))
            })()
            .unwrap_or_else(|failure| state_failure(operation, &failure))
        }
        HostOperationBody::ControlOperation {
            compact_jws,
            change_set,
            ..
        } => answer_control_operation(
            operation,
            store,
            compact_jws,
            change_set.as_ref().map(|material| material.as_bytes()),
            executors.control,
        )
        .unwrap_or_else(|failure| state_failure(operation, &failure)),
        HostOperationBody::StateMutate { mutation } => match mutation {
            StateMutationPayload::Bootstrap {
                issuer,
                runtime,
                artifact: _,
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
                        if let Err(failure) = ensure_scope_dir(&scope_dir) {
                            return state_failure(operation, &failure);
                        }
                        let job = install_exec::InstallJob {
                            deployment_id: &deployment_id,
                            issuer,
                            runtime,
                            config_reference,
                            scope_dir: &scope_dir,
                            order,
                        };
                        // The executor owns its performed-step receipt through
                        // the single authoritative state commit. A failure in
                        // either phase therefore rolls the same install back.
                        match executors.install.execute_install(&job, &mut |facts| {
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
                                current_release: facts.release.clone(),
                                current_rollback_policy: facts.rollback_policy.clone(),
                            };
                            commit_clean_install(store, &deployment_id, params, operation)
                        }) {
                            Ok(inspection) => HostResult::completed(
                                &operation.operation_id,
                                HostCompletionBody::InstallApplied { inspection },
                            ),
                            Err(failure) => state_failure(operation, &failure),
                        }
                    }
                    None => state_failure(
                        operation,
                        &Failure::new(
                            install_exec::ARTIFACT_UNVERIFIED,
                            "adoption cannot prove the running release rollback policy; use clean-install from a verified Release",
                        ),
                    ),
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
                            control_result: None,
                        },
                    ),
                    Err(failure) => state_failure(operation, &failure),
                }
            }
            StateMutationPayload::Update { .. } => {
                answer_update(operation, store, mutation, executors.lifecycle)
                    .unwrap_or_else(|failure| state_failure(operation, &failure))
            }
            StateMutationPayload::Rollback {} => {
                answer_rollback(operation, store, executors.lifecycle)
                    .unwrap_or_else(|failure| state_failure(operation, &failure))
            }
            StateMutationPayload::Uninstall {} => {
                answer_uninstall(operation, store, executors.deletion)
                    .unwrap_or_else(|failure| state_failure(operation, &failure))
            }
        },
    }
}

const TARGET_IDENTITY_FILE: &str = "target-id";
const TARGET_IDENTITY_LOCK: &str = "target-id.lock";
const MAX_TARGET_IDENTITY_BYTES: u64 = 64;

/// Read the target's one immutable identity, creating it exactly once while
/// holding a private file lock.  This belongs beside TargetJournal because it
/// names the target itself, not an inventory alias or one deployment.
fn target_identity(root: &Path) -> Result<Uuid, Failure> {
    crate::filesystem::ensure_private_directory(root, "target state root").map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!("target identity root: {error}"),
        )
    })?;
    let _lock =
        crate::file_lock::FileLock::acquire(&root.join(TARGET_IDENTITY_LOCK)).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                format!("target identity lock: {error}"),
            )
        })?;
    let path = root.join(TARGET_IDENTITY_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = crate::filesystem::read_secure_regular_file(
                &path,
                "target identity",
                true,
                MAX_TARGET_IDENTITY_BYTES,
            )
            .map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("target identity: {error}"),
                )
            })?;
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| {
                    Failure::new(HOST_ERR_OPERATION_INVALID, "target identity is not UTF-8")
                })?
                .trim();
            let id = Uuid::parse_str(value).map_err(|_| {
                Failure::new(HOST_ERR_OPERATION_INVALID, "target identity is not a UUID")
            })?;
            if id.get_version_num() != 7 {
                return Err(Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    "target identity is not UUIDv7",
                ));
            }
            Ok(id)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let id = Uuid::now_v7();
            crate::filesystem::atomic_write(&path, id.to_string().as_bytes(), 0o600).map_err(
                |error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to create target identity: {error}"),
                    )
                },
            )?;
            Ok(id)
        }
        Err(error) => Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!("failed to inspect target identity: {error}"),
        )),
    }
}

fn answer_hello(
    operation: &HostOperation,
    store: &TargetStateStore,
) -> Result<HostResult, Failure> {
    let target_id = target_identity(store.root())?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::Hello {
            hello: local_hello_for_target(local_supported_runtimes(), target_id),
        },
    ))
}

fn answer_runtime_logs(
    operation: &HostOperation,
    store: &TargetStateStore,
    limit: usize,
) -> Result<HostResult, Failure> {
    let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
    let state = store.load_existing(deployment_id)?;
    let kind = state.runtime.kind;
    let backend = runtime_backend::backend(kind);
    let lines = backend
        .read_logs(&state.runtime.object, limit)
        .map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                wire::sanitize(error.to_string()),
            )
        })?
        .into_iter()
        .map(|line| redact_log_line(&line))
        .collect();
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::RuntimeLogs { lines },
    ))
}

fn answer_journal_read(
    operation: &HostOperation,
    store: &TargetStateStore,
    limit: usize,
) -> Result<HostResult, Failure> {
    let deployment_id = operation.deployment_id.as_deref().unwrap_or_default();
    store.load_existing(deployment_id)?;
    let mut entries = TargetJournal::open(store.root())
        .map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                wire::sanitize(error.to_string()),
            )
        })?
        .operation_log(deployment_id)
        .map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                wire::sanitize(error.to_string()),
            )
        })?;
    if entries.len() > limit {
        entries = entries.split_off(entries.len() - limit);
    }
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::JournalRead { entries },
    ))
}

fn redact_log_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "authorization",
        "password",
        "secret",
        "token",
        "cookie",
        "database_url",
        "valkey_url",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "[redacted sensitive log line]".to_owned()
    } else {
        wire::sanitize(line.to_owned())
    }
}

/// Execute one G03 update order: the lifecycle executor performs the full
/// staged sequence (verify → snapshot → stage config → activate → health →
/// commit) inside this journaled operation and rolls its own partial work
/// back on failure.
fn answer_update(
    operation: &HostOperation,
    store: &TargetStateStore,
    mutation: &StateMutationPayload,
    lifecycle: &Arc<dyn update_exec::LifecycleExecutor>,
) -> Result<HostResult, Failure> {
    let StateMutationPayload::Update {
        artifact,
        backup_precondition,
        config,
        migration_jws,
        migration_request_hash,
    } = mutation
    else {
        unreachable!("answer_update is called only for update mutations")
    };
    let Some(expected_revision) = operation.expected_revision else {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "update requires expected_revision",
        ));
    };
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    let scope_dir = store.scope_dir(&deployment_id)?;
    // TargetJournal holds this deployment's exclusive operation lock across
    // dispatch. Validate the exact current backup projection before entering
    // the lifecycle executor, which is the first artifact/migration/config
    // side-effect boundary.
    update_exec::validate_backup_precondition(&scope_dir, &state, backup_precondition, Utc::now())?;
    ensure_scope_dir(&scope_dir)?;
    let Some(current_artifact) = state.artifact.current.clone() else {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "the deployment records no current artifact reference; adopt or install it first",
        ));
    };
    // P1-11: the recorded release version version is the signed
    // anti-downgrade floor for this update.
    let current_version = state
        .current_release
        .as_ref()
        .map(|identity| identity.version.clone());
    let data_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-data" && resource.kind == "directory")
        .map(|resource| resource.locator.clone())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "deployment state has no app-data directory resource",
            )
        })?;
    let runtime_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-binary" && resource.kind == "directory")
        .map(|resource| resource.locator.clone());
    let secrets_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-secrets" && resource.kind == "directory")
        .map(|resource| resource.locator.clone())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "deployment state has no app-secrets directory resource",
            )
        })?;
    let job = update_exec::UpdateJob {
        operation_id: &operation.operation_id,
        deployment_id: &deployment_id,
        issuer: &state.issuer,
        runtime_kind: state.runtime.kind,
        runtime_object: &state.runtime.object,
        config_reference: &state.config.reference.clone(),
        port: state.runtime.loopback_port,
        data_root: &data_root,
        secrets_root: &secrets_root,
        runtime_root: runtime_root.as_deref(),
        config_schema: &state.config.schema.clone(),
        current_artifact: &current_artifact,
        current_version: current_version.as_deref(),
        expected_revision,
        artifact,
        config: config.as_ref(),
        migration_jws: migration_jws.as_deref(),
        migration_request_hash: migration_request_hash.as_deref(),
        scope_dir: &scope_dir,
        store,
    };
    match lifecycle.execute_update(&job)? {
        update_exec::UpdateExecution::Noop { revision } => Ok(HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::StateMutateNoop { revision },
        )),
        update_exec::UpdateExecution::Activated(facts) => Ok(HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::StateMutateApplied {
                revision: facts.revision,
                control_result: facts.migration_result,
            },
        )),
        update_exec::UpdateExecution::MigrationFailed(result) => Ok(HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::StateMutateMigrationFailed { result },
        )),
        update_exec::UpdateExecution::RecoveryRequired { result, detail } => {
            Ok(HostResult::completed(
                &operation.operation_id,
                HostCompletionBody::StateMutateRecoveryRequired {
                    result,
                    detail: wire::sanitize(detail),
                },
            ))
        }
    }
}

/// Execute one explicit G04 rollback order.
fn answer_rollback(
    operation: &HostOperation,
    store: &TargetStateStore,
    lifecycle: &Arc<dyn update_exec::LifecycleExecutor>,
) -> Result<HostResult, Failure> {
    let Some(expected_revision) = operation.expected_revision else {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "rollback requires expected_revision",
        ));
    };
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    if state.applied_migration.is_some()
        || !state
            .current_rollback_policy
            .artifact_rollback_allowed_after_migration()
    {
        return Err(Failure::new(
            deployment_state::ROLLBACK_RECOVERY_REQUIRED,
            "the verified Release migration policy forbids artifact/config rollback; keep the writer stopped and run verified backup recover",
        ));
    }
    let scope_dir = store.scope_dir(&deployment_id)?;
    ensure_scope_dir(&scope_dir)?;
    let Some(current_artifact) = state.artifact.current.clone() else {
        return Err(Failure::new(
            ROLLBACK_UNAVAILABLE,
            "the deployment records no current artifact reference",
        ));
    };
    let runtime_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-binary" && resource.kind == "directory")
        .map(|resource| resource.locator.clone());
    let job = update_exec::RollbackJob {
        operation_id: &operation.operation_id,
        deployment_id: &deployment_id,
        issuer: &state.issuer,
        runtime_kind: state.runtime.kind,
        runtime_object: &state.runtime.object,
        config_reference: &state.config.reference.clone(),
        port: state.runtime.loopback_port,
        runtime_root: runtime_root.as_deref(),
        config_schema: &state.config.schema.clone(),
        current_artifact: &current_artifact,
        previous_artifact: state.artifact.previous.as_deref(),
        current_rollback_policy: &state.current_rollback_policy,
        expected_revision,
        scope_dir: &scope_dir,
        store,
    };
    let facts = lifecycle.execute_rollback(&job)?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::StateMutateApplied {
            revision: facts.revision,
            control_result: None,
        },
    ))
}

/// Execute one G06 uninstall order: zero-delete enforcement runs against the
/// live state here (managed+deployment only), then the deletion executor
/// removes the planned objects physically with identity re-confirmation.
fn answer_uninstall(
    operation: &HostOperation,
    store: &TargetStateStore,
    deletion: &Arc<dyn uninstall_exec::DeletionExecutor>,
) -> Result<HostResult, Failure> {
    let Some(expected_revision) = operation.expected_revision else {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "uninstall requires expected_revision",
        ));
    };
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    let job = uninstall_exec::DeletionJob {
        operation_id: &operation.operation_id,
        deployment_id: &deployment_id,
        runtime_kind: state.runtime.kind,
        runtime_object: &state.runtime.object,
        config_reference: &state.config.reference.clone(),
        declared: &state.resources,
        expected_revision,
        store,
    };
    deletion.execute_deletion(&job)?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::StateMutateApplied {
            revision: state.config.revision,
            control_result: None,
        },
    ))
}

/// Deliver one signed ControlOperation to the local one-shot NazoAuth
/// operator through the injected seam (G-wave decision 1). The target never
/// parses or verifies the envelope; it refuses only when the live facts do
/// not match the deployment binding.
fn answer_control_operation(
    operation: &HostOperation,
    store: &TargetStateStore,
    compact_jws: &str,
    change_set: Option<&[u8]>,
    control: &Arc<dyn control_exec::ControlOperationExecutor>,
) -> Result<HostResult, Failure> {
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    let result = execute_bound_control_operation(
        &operation.operation_id,
        &deployment_id,
        &state,
        store,
        compact_jws,
        change_set,
        control,
    )?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::ControlOperationExecuted { result },
    ))
}

/// Create an administrator through the target deployment's fixed local
/// provisioner. The live DeploymentState supplies every runtime/config/path
/// fact; the HostOperation contributes the non-secret email and redacted
/// password material.
fn answer_admin_create(
    operation: &HostOperation,
    store: &TargetStateStore,
    email: &str,
    password: &[u8],
    admin: &Arc<dyn admin_exec::AdminProvisionExecutor>,
) -> Result<HostResult, Failure> {
    let deployment_id = operation.deployment_id.clone().unwrap_or_default();
    let state = store.load_existing(&deployment_id)?;
    let current_artifact = state.artifact.current.clone().ok_or_else(|| {
        Failure::new(
            CONTROL_TARGET_DRIFT,
            "the deployment records no current artifact reference",
        )
    })?;
    let data_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-data" && resource.kind == "directory")
        .map(|resource| resource.locator.clone())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "deployment state has no app-data directory resource",
            )
        })?;
    let scope_dir = store.scope_dir(&deployment_id)?;
    let job = admin_exec::AdminProvisionJob {
        operation_id: &operation.operation_id,
        deployment_id: &deployment_id,
        artifact_reference: &current_artifact,
        runtime_kind: state.runtime.kind,
        runtime_object: &state.runtime.object,
        config_reference: &state.config.reference,
        data_root: &data_root,
        scope_dir: &scope_dir,
        email,
        password,
    };
    let receipt = admin.execute(&job)?;
    admin_exec::validate_admin_provision_receipt(
        &receipt,
        &operation.operation_id,
        &deployment_id,
    )?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::AdminCreated { receipt },
    ))
}

/// One target-side implementation of the signed ControlOperation runtime
/// contract.  Direct delivery and Update's nested MigrateApply both call this
/// function so they cannot drift on runtime identity, mount, or stdout rules.
fn execute_bound_control_operation(
    operation_id: &str,
    deployment_id: &str,
    state: &DeploymentState,
    store: &TargetStateStore,
    compact_jws: &str,
    change_set: Option<&[u8]>,
    control: &Arc<dyn control_exec::ControlOperationExecutor>,
) -> Result<ControlResult, Failure> {
    let Some(current_artifact) = state.artifact.current.clone() else {
        return Err(Failure::new(
            CONTROL_TARGET_DRIFT,
            "the deployment records no current artifact reference",
        ));
    };
    let data_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-data" && resource.kind == "directory")
        .map(|resource| resource.locator.clone())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "deployment state has no app-data directory resource",
            )
        })?;
    let secrets_root = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == "app-secrets" && resource.kind == "directory")
        .map(|resource| resource.locator.clone())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "deployment state has no app-secrets directory resource",
            )
        })?;
    let scope_dir = store.scope_dir(deployment_id)?;
    let job = control_exec::ControlJob {
        operation_id,
        deployment_id,
        artifact_reference: &current_artifact,
        runtime_kind: state.runtime.kind,
        runtime_object: &state.runtime.object,
        config_reference: &state.config.reference,
        data_root: &data_root,
        secrets_root: &secrets_root,
        scope_dir: &scope_dir,
        compact_jws,
        change_set,
    };
    control.execute(&job)
}

/// Commit the complete post-install DeploymentState in one atomic write. The
/// executor keeps its rollback receipt until this returns successfully.
fn commit_clean_install(
    store: &TargetStateStore,
    deployment_id: &str,
    params: BootstrapParams,
    operation: &HostOperation,
) -> Result<InstanceInspection, Failure> {
    let state = store.bootstrap_healthy(deployment_id, params, &operation.operation_id)?;
    inspection_from_state(store, state)
}

const DEFAULT_INSTANCE_IDENTITY_DIRECTORY: &str = "instance";
const INSTANCE_IDENTITY_PUBLIC_FILE: &str = "identity.pub";
const INSTANCE_DEPLOYMENT_STATEMENT_FILE: &str = "deployment-statement.jws";
const RUNTIME_INSTANCE_IDENTITY_RESOURCE: &str = "runtime-instance-identity";
const MAX_INSTANCE_PUBLIC_KEY_BYTES: u64 = 256;

fn current_instance_identity(
    state: &DeploymentState,
) -> Result<Option<RuntimeInstanceIdentity>, Failure> {
    let explicit_identity = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == RUNTIME_INSTANCE_IDENTITY_RESOURCE);
    let identity_directory = if let Some(resource) = explicit_identity {
        if resource.kind != "directory"
            || resource.ownership != ResourceOwnership::Managed
            || resource.scope != ResourceScope::Deployment
        {
            return Err(Failure::new(
                CONTROL_TARGET_DRIFT,
                "the runtime instance identity resource is not a managed deployment directory",
            ));
        }
        PathBuf::from(&resource.locator)
    } else {
        let Some(data) = state
            .resources
            .iter()
            .find(|resource| resource.resource_id == "app-data")
        else {
            return Ok(None);
        };
        if data.kind != "directory"
            || data.ownership != ResourceOwnership::Managed
            || data.scope != ResourceScope::Deployment
        {
            return Err(Failure::new(
                CONTROL_TARGET_DRIFT,
                "the app-data resource is not a managed deployment directory",
            ));
        }
        PathBuf::from(&data.locator).join(DEFAULT_INSTANCE_IDENTITY_DIRECTORY)
    };
    let public_key_path = identity_directory.join(INSTANCE_IDENTITY_PUBLIC_FILE);
    let statement_path = identity_directory.join(INSTANCE_DEPLOYMENT_STATEMENT_FILE);
    let public_key_exists = secure_path_exists(&public_key_path)?;
    let statement_exists = secure_path_exists(&statement_path)?;
    if !public_key_exists && !statement_exists && explicit_identity.is_none() {
        return Ok(None);
    }
    if !public_key_exists || !statement_exists {
        return Err(Failure::new(
            CONTROL_TARGET_DRIFT,
            "the runtime instance identity is incomplete on the target",
        ));
    }

    let encoded_public_key = read_runtime_owned_file(
        &public_key_path,
        "runtime instance public key",
        false,
        MAX_INSTANCE_PUBLIC_KEY_BYTES,
        state,
    )
    .and_then(|bytes| {
        std::str::from_utf8(bytes.trim_ascii())
            .map(str::to_owned)
            .map_err(anyhow::Error::from)
    })
    .map_err(|error| {
        Failure::new(
            CONTROL_TARGET_DRIFT,
            wire::sanitize(format!("invalid runtime instance public key: {error}")),
        )
    })?;
    let public_key = nazo_operator_protocol::decode_instance_public_key(&encoded_public_key)
        .map_err(|error| {
            Failure::new(
                CONTROL_TARGET_DRIFT,
                wire::sanitize(format!("invalid runtime instance public key: {error}")),
            )
        })?;
    let instance_key_id = nazo_operator_protocol::instance_key_id(&public_key);
    let deployment_statement = read_runtime_owned_file(
        &statement_path,
        "runtime deployment statement",
        false,
        nazo_operator_protocol::MAX_COMPACT_JWS_BYTES as u64,
        state,
    )
    .and_then(|bytes| {
        std::str::from_utf8(bytes.trim_ascii())
            .map(str::to_owned)
            .map_err(anyhow::Error::from)
    })
    .and_then(|compact| {
        nazo_operator_protocol::verify_deployment_statement(&compact, &instance_key_id, &public_key)
            .map_err(anyhow::Error::from)
    })
    .map_err(|error| {
        Failure::new(
            CONTROL_TARGET_DRIFT,
            wire::sanitize(format!("invalid runtime deployment statement: {error}")),
        )
    })?;
    if deployment_statement.deployment_id != state.deployment_id
        || deployment_statement.issuer != state.issuer
    {
        return Err(Failure::new(
            CONTROL_TARGET_DRIFT,
            "the runtime instance identity does not match DeploymentState",
        ));
    }
    Ok(Some(RuntimeInstanceIdentity {
        runtime_instance_id: deployment_statement.runtime_instance_id,
        instance_key_id,
        instance_public_key_base64: nazo_operator_protocol::encode_instance_public_key(&public_key),
    }))
}

fn secure_path_exists(path: &std::path::Path) -> Result<bool, Failure> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Failure::new(
            CONTROL_TARGET_DRIFT,
            wire::sanitize(format!("failed to inspect runtime identity: {error}")),
        )),
    }
}

pub(super) fn read_runtime_owned_file(
    path: &std::path::Path,
    label: &str,
    private: bool,
    max_bytes: u64,
    state: &DeploymentState,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        let runtime_uid = match state.runtime.kind {
            runtime_backend::RuntimeBackendKind::Host => {
                runtime_backend::systemd_service_user_uid(&state.deployment_id)?
            }
            runtime_backend::RuntimeBackendKind::Podman
            | runtime_backend::RuntimeBackendKind::Docker => {
                runtime_backend::NON_ROOT_ONE_SHOT_USER
                    .split_once(':')
                    .and_then(|(uid, _)| uid.parse::<u32>().ok())
                    .ok_or_else(|| anyhow::anyhow!("runtime UID policy is invalid"))?
            }
        };
        crate::filesystem::read_secure_regular_file_for_uid(
            path,
            label,
            private,
            max_bytes,
            runtime_uid,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = state;
        crate::filesystem::read_secure_regular_file(path, label, private, max_bytes)
    }
}

fn inspection_from_state(
    store: &TargetStateStore,
    state: DeploymentState,
) -> Result<InstanceInspection, Failure> {
    let scope_dir = store.scope_dir(&state.deployment_id)?;
    let backup = backup::backup_projection(&scope_dir, &state).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            wire::sanitize(format!("invalid backup evidence: {error}")),
        )
    })?;
    Ok(InstanceInspection {
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
        backup,
        active_host_operation: state
            .active_host_operation
            .map(|active| active.operation_id),
        // The discovery sweep never reads the marker: it is a per-deployment
        // fact that only the dedicated inspect kind surfaces.
        config_revision_marker: None,
        current_release: state.current_release,
        current_instance_identity: None,
    })
}

fn ensure_scope_dir(scope_dir: &std::path::Path) -> Result<(), Failure> {
    crate::filesystem::ensure_directory_chain(scope_dir).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!("failed to prepare target state directory: {error}"),
        )
    })
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
    let scope_dir = store.scope_dir(&deployment_id)?;
    let backup = backup::backup_projection(&scope_dir, &state).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            wire::sanitize(format!("invalid backup evidence: {error}")),
        )
    })?;
    let current_instance_identity = current_instance_identity(&state)?;
    let config_revision_marker = Some(&scope_dir).and_then(|scope| {
        std::fs::read(scope.join("config-revision"))
            .ok()
            .map(|bytes| String::from_utf8_lossy(bytes.trim_ascii()).into_owned())
            .filter(|value| !value.is_empty())
    });
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::StateInspect {
            inspection: InstanceInspection {
                deployment_id: state.deployment_id.clone(),
                issuer: state.issuer.clone(),
                observed_at: Utc::now(),
                revision: state.config.revision,
                runtime: state.runtime.clone(),
                artifact: state.artifact.clone(),
                config_reference: state.config.reference.clone(),
                config_schema: state.config.schema.clone(),
                resources: state.resources.clone(),
                healthy: state.local_health.healthy,
                health_summary: state.local_health.summary.clone(),
                backup,
                active_host_operation: state
                    .active_host_operation
                    .as_ref()
                    .map(|active| active.operation_id.clone()),
                config_revision_marker,
                current_release: state.current_release.clone(),
                current_instance_identity,
            },
        },
    ))
}

/// Answer one G05 discovery sweep: every DeploymentState on this target,
/// projected through the same inspection shape as state-inspect and sorted by
/// deployment id. Strictly read-only — no journal line and no state write.
fn answer_state_list(
    operation: &HostOperation,
    store: &TargetStateStore,
) -> Result<HostResult, Failure> {
    let states = store.list_deployments()?;
    let deployments = states
        .into_iter()
        .map(|state| inspection_from_state(store, state))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HostResult::completed(
        &operation.operation_id,
        HostCompletionBody::StateListed { deployments },
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

/// Runtimes this installation can drive end-to-end, detected without spawning
/// engines. Read-only discovery support is not advertised as lifecycle
/// capability.
fn local_supported_runtimes() -> Vec<String> {
    let mut runtimes = Vec::new();
    for engine in ["podman", "docker"] {
        if crate::process::command_exists(engine) {
            runtimes.push(engine.to_owned());
        }
    }
    if cfg!(target_os = "linux")
        && crate::runtime_backend::backend(crate::runtime_backend::RuntimeBackendKind::Host)
            .available()
    {
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
        let operation = HostOperation::state_inspect(Uuid::now_v7().to_string(), deployment_id);
        match self.execute_host_operation(&operation)?.outcome {
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
        // per-kind payload constraints; [`dispatch_validated_host_operation`] stays
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
        if matches!(
            operation.operation,
            HostOperationBody::StateMutate { .. }
                | HostOperationBody::BackupRecover { .. }
                | HostOperationBody::BackupRecoveryCandidateStage { .. }
                | HostOperationBody::BackupRecoveryCandidateCleanup { .. }
                | HostOperationBody::BackupRecoveryActivate { .. }
                | HostOperationBody::BackupSnapshot {}
                | HostOperationBody::BackupRestoreTest {}
                | HostOperationBody::BackupExportPrepare {}
                | HostOperationBody::BackupImportPrepare {}
                | HostOperationBody::BackupTransferRead { .. }
                | HostOperationBody::BackupTransferWrite { .. }
                | HostOperationBody::BackupImportFinalize { .. }
                | HostOperationBody::BackupOffHostRecord { .. }
                | HostOperationBody::BackupTransferCleanup { .. }
                | HostOperationBody::ControlOperation { .. }
                | HostOperationBody::AdminCreate { .. }
        ) {
            let journal = TargetJournal::open(&self.state_root)?;
            return self.execute_journaled_validated(operation, &journal);
        }
        let store = TargetStateStore::open(&self.state_root)?;
        let executors = self.executors();
        Ok(dispatch_validated_host_operation(
            operation, &store, &executors,
        ))
    }

    fn execute_control_operation(
        &self,
        request: ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt> {
        // The delivered envelope rides the SAME frozen stdio/journal path as
        // every other kind (decision 1): validated, journaled, dispatched to
        // the local one-shot NazoAuth operator.  The JWS is public; the
        // optional Apply material remains an opaque, zeroizing carrier.
        let request_operation_id = request.operation_id.clone();
        let operation = HostOperation::control_operation(
            request.operation_id,
            request.deployment_id,
            request.compact_jws,
            request.change_set,
        );
        let result = self.execute_host_operation(&operation)?;
        control_operation_receipt(request_operation_id, result.outcome)
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
                runtime: RuntimeSurface::new("podman", "nazoauth-main", 8000).expect("runtime"),
                artifact: Some(ArtifactRefs {
                    current: Some("sha256:abcdef0123456789".to_owned()),
                    previous: None,
                }),
                config_reference: "/etc/nazauth/config.toml".to_owned(),
                config_schema: "nazauth-config-v1".to_owned(),
                resources: vec![
                    Resource::new(
                        "app-data",
                        "directory",
                        "/var/lib/nazoauth/deploy-alpha",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )
                    .expect("managed data resource"),
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

    fn seed_sample_deployment(journal: &TargetJournal, deployment_id: &str) -> anyhow::Result<()> {
        TargetStateStore::open(journal.root())?.bootstrap(
            deployment_id,
            BootstrapParams {
                issuer: "https://auth.example.com".to_owned(),
                runtime: RuntimeSurface::new("podman", "nazoauth-main", 8000)?,
                artifact: ArtifactRefs {
                    current: Some("sha256:abcdef0123456789".to_owned()),
                    previous: None,
                },
                config_reference: "/etc/nazauth/config.toml".to_owned(),
                config_schema: "nazauth-config-v1".to_owned(),
                resources: vec![
                    Resource::new(
                        "app-data",
                        "directory",
                        "/var/lib/nazoauth/deploy-alpha",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )?,
                    Resource::new(
                        "app-secrets",
                        "directory",
                        "/var/lib/nazoauth/deploy-alpha-secrets",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )?,
                    Resource::new(
                        "shared-db",
                        "postgres",
                        "pg-main.example.internal:5432",
                        ResourceOwnership::External,
                        ResourceScope::Shared,
                    )?,
                    Resource::new(
                        "backup-volume",
                        "volume",
                        "/srv/backups/deploy-alpha",
                        ResourceOwnership::External,
                        ResourceScope::Deployment,
                    )?,
                ],
                current_release: None,
                current_rollback_policy: crate::model::test_release_rollback_policy(),
            },
            &Uuid::now_v7().to_string(),
        )?;
        Ok(())
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
    fn hello_persists_one_target_owned_identity() -> anyhow::Result<()> {
        let (temp, target, _) = temp_target()?;
        let first =
            target.execute_host_operation(&HostOperation::hello(Uuid::now_v7().to_string()))?;
        let second =
            target.execute_host_operation(&HostOperation::hello(Uuid::now_v7().to_string()))?;
        let target_id = |result: HostResult| match result.outcome {
            HostOutcome::Completed {
                body: HostCompletionBody::Hello { hello },
            } => hello.target_id,
            other => panic!("expected hello, got {other:?}"),
        };
        let first = target_id(first);
        assert_eq!(first, target_id(second));
        assert!(Uuid::parse_str(&first)?.get_version_num() == 7);
        let stored = std::fs::read_to_string(temp.path().join("state").join(TARGET_IDENTITY_FILE))?;
        assert_eq!(stored, first);
        Ok(())
    }

    #[test]
    fn backup_import_refuses_a_receipt_for_a_different_destination_target() -> anyhow::Result<()> {
        let (_temp, target, _) = temp_target()?;
        let operation = HostOperation::backup_import_finalize(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Uuid::now_v7().to_string(),
            "a".repeat(64),
            Uuid::now_v7().to_string(),
            Uuid::now_v7().to_string(),
        );
        let result = target.execute_host_operation(&operation)?;
        assert!(matches!(
            result.outcome,
            HostOutcome::Failed { ref code, .. } if code == HOST_ERR_OPERATION_INVALID
        ));
        Ok(())
    }

    #[test]
    fn read_only_execution_does_not_use_the_local_journal() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-local-journaled")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let target = LocalTarget::with_state_root(temp.path().join("state"));

        let operation = HostOperation::ping(Uuid::now_v7().to_string(), "journaled");
        let first = target.execute_journaled_validated(&operation, &journal)?;
        let second = target.execute_journaled_validated(&operation, &journal)?;
        assert_eq!(first, second, "a repeated read returns the same answer");

        let mut changed: HostOperation = serde_json::from_slice(
            &serde_json::to_vec(&operation).expect("serialize public test operation"),
        )
        .expect("deserialize public test operation");
        changed.operation = HostOperationBody::Ping {
            nonce: "different".to_owned(),
        };
        let result = target.execute_journaled_validated(&changed, &journal)?;
        assert_eq!(
            result.outcome,
            HostOutcome::Completed {
                body: HostCompletionBody::Ping {
                    nonce: "different".to_owned(),
                },
            }
        );
        assert!(
            !journal
                .root()
                .join("deployments/host/operations.jsonl")
                .exists()
        );
        Ok(())
    }

    #[derive(Default)]
    struct CrashAfterUninstallStateRemoval {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl uninstall_exec::DeletionExecutor for CrashAfterUninstallStateRemoval {
        fn execute_deletion(&self, job: &uninstall_exec::DeletionJob<'_>) -> Result<(), Failure> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            job.store.remove_deployment(
                job.deployment_id,
                job.expected_revision,
                job.operation_id,
            )?;
            panic!("simulated process loss after state removal")
        }
    }

    #[test]
    fn interrupted_uninstall_finishes_when_state_was_already_removed() -> anyhow::Result<()> {
        let (_temp, _base_target, journal) = temp_target()?;
        let bootstrap_state = || -> anyhow::Result<()> {
            TargetStateStore::open(journal.root())?.bootstrap(
                "deploy-alpha",
                BootstrapParams {
                    issuer: "https://auth.example.com".to_owned(),
                    runtime: RuntimeSurface::new("podman", "nazoauth-main", 8000)?,
                    artifact: ArtifactRefs {
                        current: Some(format!("sha256:{}", "a".repeat(64))),
                        previous: None,
                    },
                    config_reference: "/etc/nazoauth/config.toml".to_owned(),
                    config_schema: "nazoauth-config-v1".to_owned(),
                    resources: vec![Resource::new(
                        "app-data",
                        "directory",
                        "/var/lib/nazoauth/deploy-alpha",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )?],
                    current_release: Some(ReleaseVersion::new("v1")?),
                    current_rollback_policy: crate::model::test_release_rollback_policy(),
                },
                &Uuid::now_v7().to_string(),
            )?;
            Ok(())
        };
        bootstrap_state()?;

        let crash = Arc::new(CrashAfterUninstallStateRemoval::default());
        let target =
            LocalTarget::with_state_root(journal.root()).with_deletion_executor(crash.clone());
        let state_path = journal.root().join("deployments/deploy-alpha/state.json");
        let pre_uninstall_state = std::fs::read(&state_path)
            .map_err(|error| anyhow::anyhow!("read pre-uninstall state: {error}"))?;
        let operation = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(1),
            StateMutationPayload::Uninstall {},
        );
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = target.execute_journaled_validated(&operation, &journal);
        }));
        assert!(crashed.is_err());

        // Recreate the exact pre-delete bytes to model a crash after the
        // completion fence was committed but before state.json removal.
        crate::filesystem::atomic_write(&state_path, &pre_uninstall_state, 0o600)
            .map_err(|error| anyhow::anyhow!("restore crash-window state: {error}"))?;
        let replay = target
            .execute_journaled_validated(&operation, &journal)
            .map_err(|error| anyhow::anyhow!("resume crash-window uninstall: {error}"))?;
        assert!(matches!(replay.outcome, HostOutcome::Completed { .. }));
        assert!(!state_path.exists());
        assert_eq!(
            crash.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the completed destructive phase must not execute again"
        );

        let fresh_unknown = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(1),
            StateMutationPayload::Uninstall {},
        );
        let rejected = target.execute_journaled_validated(&fresh_unknown, &journal)?;
        assert!(matches!(
            rejected.outcome,
            HostOutcome::Failed { ref code, .. } if code == DEPLOYMENT_UNKNOWN
        ));

        // The completion fence outlives bounded journal history. Reusing the
        // deployment id for a new generation must not let an ancient retry
        // delete that new generation after its old terminal line ages out.
        bootstrap_state()
            .map_err(|error| anyhow::anyhow!("bootstrap replacement generation: {error}"))?;
        crate::filesystem::remove_file_durable(
            &journal
                .root()
                .join("deployments/deploy-alpha/operations.jsonl"),
        )
        .map_err(|error| anyhow::anyhow!("remove bounded journal history: {error}"))?;
        let ancient_replay = target
            .execute_journaled_validated(&operation, &journal)
            .map_err(|error| anyhow::anyhow!("replay ancient uninstall: {error}"))?;
        assert!(matches!(
            ancient_replay.outcome,
            HostOutcome::Completed { .. }
        ));
        let replacement = TargetStateStore::open(journal.root())?
            .load_existing("deploy-alpha")
            .map_err(|error| anyhow::anyhow!("replacement generation disappeared: {error:?}"))?;
        assert_eq!(replacement.deployment_id, "deploy-alpha");
        assert_eq!(
            crash.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "an ancient uninstall must not reach the new deployment generation"
        );
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

        seed_sample_deployment(&journal, "deploy-alpha")?;

        // The state document really exists beside its journal.
        let state_path = journal
            .root()
            .join("deployments")
            .join("deploy-alpha")
            .join("state.json");
        let raw = std::fs::read_to_string(&state_path)?;
        let persisted: DeploymentState = serde_json::from_str(&raw)?;
        assert_eq!(persisted.deployment_id, "deploy-alpha");
        assert_eq!(persisted.resources.len(), 4);

        let inspection = target.inspect_instance("deploy-alpha")?;
        assert_eq!(inspection.deployment_id, "deploy-alpha");
        assert_eq!(inspection.issuer, "https://auth.example.com");
        assert_eq!(inspection.revision, 1);
        assert_eq!(
            inspection.runtime.kind,
            crate::runtime_backend::RuntimeBackendKind::Podman
        );
        assert_eq!(
            inspection.artifact.current.as_deref(),
            Some("sha256:abcdef0123456789")
        );
        assert_eq!(inspection.resources.len(), 4);
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
        seed_sample_deployment(&journal, "deploy-alpha")?;

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
            target
                .execute_journaled_validated(&operation, &journal)
                .unwrap()
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
            body: HostCompletionBody::StateMutateApplied { revision, .. },
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
    fn artifact_only_adoption_fails_without_a_verified_release_policy() -> anyhow::Result<()> {
        let (_temp, target, journal) = temp_target()?;
        let first =
            target.execute_journaled_validated(&sample_bootstrap("deploy-alpha"), &journal)?;
        let HostOutcome::Failed { code, detail } = first.outcome else {
            panic!("artifact-only adoption unexpectedly succeeded");
        };
        assert_eq!(code, ARTIFACT_UNVERIFIED, "{detail}");
        assert!(detail.contains("rollback policy"), "{detail}");
        Ok(())
    }

    #[test]
    fn corrupt_or_foreign_state_fails_closed_with_reset_guidance() -> anyhow::Result<()> {
        use crate::error_codes::STATE_RESET_REQUIRED;

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
        assert_eq!(failure.code, STATE_RESET_REQUIRED);
        Ok(())
    }

    /// Scripted ControlOperation operator: echoes the presented operation id
    /// and answers with the scripted durable result.
    struct ScriptedControl {
        outcome: nazo_operator_protocol::ControlOutcome,
        calls: std::sync::atomic::AtomicUsize,
        change_set_size: std::sync::atomic::AtomicUsize,
    }

    impl control_exec::ControlOperationExecutor for ScriptedControl {
        fn execute(
            &self,
            job: &control_exec::ControlJob<'_>,
        ) -> Result<nazo_operator_protocol::ControlResult, Failure> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.change_set_size.store(
                job.change_set.map_or(0, <[u8]>::len),
                std::sync::atomic::Ordering::Relaxed,
            );
            Ok(nazo_operator_protocol::ControlResult {
                schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
                operation_id: job.operation_id.to_owned(),
                request_hash: "0".repeat(64),
                outcome: self.outcome,
                error: None,
                accepted_at: 0,
                completed_at: Some(1),
                result: None,
            })
        }
    }

    struct ScriptedAdmin {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl admin_exec::AdminProvisionExecutor for ScriptedAdmin {
        fn execute(
            &self,
            job: &admin_exec::AdminProvisionJob<'_>,
        ) -> Result<AdminProvisionReceipt, Failure> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(job.deployment_id, "deploy-alpha");
            assert_eq!(job.email, "admin@example.com");
            assert!(job.password.ends_with(b"-secret"));
            Ok(AdminProvisionReceipt {
                schema: 1,
                operation_id: job.operation_id.to_owned(),
                deployment_id: job.deployment_id.to_owned(),
                user_id: "019d0000-0000-7000-8000-000000000002"
                    .parse()
                    .expect("valid test user id"),
                email: "admin@example.com".to_owned(),
            })
        }
    }

    #[test]
    fn admin_create_is_instance_bound_journaled_and_replayable() -> anyhow::Result<()> {
        let (_temp, base_target, journal) = temp_target()?;
        seed_sample_deployment(&journal, "deploy-alpha")?;
        let scripted = Arc::new(ScriptedAdmin {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let target = base_target.with_admin_provision_executor(scripted.clone());
        let operation_id = Uuid::now_v7().to_string();
        let operation = HostOperation::admin_create(
            operation_id.clone(),
            "deploy-alpha",
            "admin@example.com",
            SecretMaterial::try_new(b"first-secret".to_vec())?,
        );

        let first = target.execute_host_operation(&operation)?;
        assert!(matches!(
            &first.outcome,
            HostOutcome::Completed {
                body: HostCompletionBody::AdminCreated { .. }
            }
        ));
        let second = target.execute_host_operation(&operation)?;
        assert_eq!(
            first, second,
            "same operation id replays the stored receipt"
        );
        assert_eq!(
            scripted.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "journal replay must not provision twice"
        );

        let retry = HostOperation::admin_create(
            operation_id,
            "deploy-alpha",
            "admin@example.com",
            SecretMaterial::try_new(b"second-secret".to_vec())?,
        );
        assert_eq!(
            crate::target::canonical_operation_hash(&operation)?,
            crate::target::canonical_operation_hash(&retry)?,
            "password changes must preserve the admin-create journal hash"
        );
        assert_eq!(
            target.execute_host_operation(&retry)?,
            first,
            "same email retry replays the existing journal result"
        );
        assert_eq!(
            scripted.calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a password-only retry must not provision twice"
        );

        let journal_text = std::fs::read_to_string(
            journal
                .root()
                .join("deployments/deploy-alpha/operations.jsonl"),
        )?;
        assert!(journal_text.contains("admin-create"), "{journal_text}");
        assert!(
            !journal_text.contains("first-secret") && !journal_text.contains("second-secret"),
            "credential bytes must not be persisted in the journal"
        );
        Ok(())
    }

    const CONTROL_JWS_OP_ID: &str = "018f0000-0000-7000-8000-00000000c001";

    fn valid_control_result() -> nazo_operator_protocol::ControlResult {
        nazo_operator_protocol::ControlResult {
            schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
            operation_id: CONTROL_JWS_OP_ID.to_owned(),
            request_hash: "0".repeat(64),
            outcome: nazo_operator_protocol::ControlOutcome::Succeeded,
            error: None,
            accepted_at: 0,
            completed_at: Some(1),
            result: None,
        }
    }

    #[test]
    fn accepted_receipts_reject_unvalidated_control_results() {
        let request = ControlOperationRequest {
            operation_id: CONTROL_JWS_OP_ID.to_owned(),
            deployment_id: "deploy-alpha".to_owned(),
            compact_jws: sample_control_jws(),
            change_set: None,
        };

        let mut invalid_schema = valid_control_result();
        invalid_schema.schema += 1;
        let error =
            accepted_control_operation_receipt(request.operation_id.clone(), invalid_schema)
                .expect_err("foreign result schema must be rejected");
        assert!(
            format!("{error:#}").contains("invalid ControlResult"),
            "{error:#}"
        );

        let mut invalid_request_hash = valid_control_result();
        invalid_request_hash.request_hash = "not-a-digest".to_owned();
        let error =
            accepted_control_operation_receipt(request.operation_id.clone(), invalid_request_hash)
                .expect_err("malformed request hashes must be rejected");
        assert!(
            format!("{error:#}").contains("invalid ControlResult"),
            "{error:#}"
        );

        let mut inconsistent_outcome = valid_control_result();
        inconsistent_outcome.outcome = nazo_operator_protocol::ControlOutcome::Failed;
        let error =
            accepted_control_operation_receipt(request.operation_id.clone(), inconsistent_outcome)
                .expect_err("failed result without an error code must be rejected");
        assert!(
            format!("{error:#}").contains("failed results require an error code"),
            "{error:#}"
        );

        let resource = nazo_operator_protocol::TenantResourceIdentity {
            kind: nazo_operator_protocol::TenantResourceKind::User,
            resource_id: "user-1".to_owned(),
            digest: "a".repeat(64),
        };
        let mut incomplete_mapping = valid_control_result();
        incomplete_mapping.result = Some(
            nazo_operator_protocol::ControlResultData::TenantResourceApply {
                revision: 1,
                resource_manifest_sha256:
                    nazo_operator_protocol::canonical_tenant_resource_manifest_sha256(
                        std::slice::from_ref(&resource),
                    )
                    .expect("test resource is valid"),
                resources: vec![resource],
                resource_mappings: Vec::new(),
            },
        );
        let error =
            accepted_control_operation_receipt(request.operation_id.clone(), incomplete_mapping)
                .expect_err("apply results must map every public resource");
        assert!(
            format!("{error:#}").contains("mappings must cover public resources exactly"),
            "{error:#}"
        );
    }

    #[test]
    fn inspection_reads_only_the_state_owned_runtime_identity_and_verifies_its_binding()
    -> anyhow::Result<()> {
        let temp = PrivateTempDir::new("nazoauthctl-runtime-identity-test")?;
        let data_root = temp.path().join("app-data");
        let identity_dir = data_root.join(DEFAULT_INSTANCE_IDENTITY_DIRECTORY);
        crate::filesystem::ensure_private_directory(&data_root, "test app data")?;
        crate::filesystem::ensure_private_directory(&identity_dir, "test runtime identity")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let public_key = key.verifying_key();
        let key_id = nazo_operator_protocol::instance_key_id(&public_key);
        let statement = nazo_operator_protocol::DeploymentStatement {
            schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
            product: nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT.to_owned(),
            deployment_id: "deploy-alpha".to_owned(),
            runtime_instance_id: "runtime-alpha".to_owned(),
            issuer: "https://auth.example.com".to_owned(),
            release: "1.0.0".to_owned(),
            control_protocol_versions: vec![nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA],
            operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
            instance_key_id: key_id.clone(),
            issued_at: 1,
        };
        crate::filesystem::atomic_write(
            &identity_dir.join(INSTANCE_IDENTITY_PUBLIC_FILE),
            nazo_operator_protocol::encode_instance_public_key(&public_key).as_bytes(),
            0o600,
        )?;
        crate::filesystem::atomic_write(
            &identity_dir.join(INSTANCE_DEPLOYMENT_STATEMENT_FILE),
            nazo_operator_protocol::sign_deployment_statement(&statement, &key_id, &key)?
                .as_bytes(),
            0o600,
        )?;

        let store = TargetStateStore::open(temp.path().join("state"))?;
        store.bootstrap(
            "deploy-alpha",
            BootstrapParams {
                issuer: "https://auth.example.com".to_owned(),
                runtime: RuntimeSurface::new("podman", "nazoauth-main", 8000)?,
                artifact: ArtifactRefs {
                    current: Some(format!("sha256:{}", "a".repeat(64))),
                    previous: None,
                },
                config_reference: temp
                    .path()
                    .join("config.json")
                    .to_string_lossy()
                    .into_owned(),
                config_schema: "nazoauth-config-v1".to_owned(),
                resources: vec![Resource::new(
                    "app-data",
                    "directory",
                    data_root.to_string_lossy(),
                    ResourceOwnership::Managed,
                    ResourceScope::Deployment,
                )?],
                current_release: Some(ReleaseVersion::new("1.0.0")?),
                current_rollback_policy: crate::model::test_release_rollback_policy(),
            },
            "bootstrap-op",
        )?;
        let mut state = store.load_existing("deploy-alpha")?;
        let identity = current_instance_identity(&state)?.expect("runtime identity");
        assert_eq!(identity.runtime_instance_id, "runtime-alpha");
        assert_eq!(identity.instance_key_id, key_id);
        assert_eq!(
            identity.instance_public_key_base64,
            nazo_operator_protocol::encode_instance_public_key(&public_key)
        );

        state.current_release = Some(ReleaseVersion::new("2.0.0")?);
        let after_update =
            current_instance_identity(&state)?.expect("runtime identity after update");
        assert_eq!(after_update, identity);

        let explicit_dir = temp.path().join("explicit-identity");
        crate::filesystem::ensure_private_directory(&explicit_dir, "explicit runtime identity")?;
        let explicit_key = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
        let explicit_key_id =
            nazo_operator_protocol::instance_key_id(&explicit_key.verifying_key());
        let mut explicit_statement = statement;
        explicit_statement.runtime_instance_id = "runtime-explicit".to_owned();
        explicit_statement.instance_key_id = explicit_key_id.clone();
        crate::filesystem::atomic_write(
            &explicit_dir.join(INSTANCE_IDENTITY_PUBLIC_FILE),
            nazo_operator_protocol::encode_instance_public_key(&explicit_key.verifying_key())
                .as_bytes(),
            0o600,
        )?;
        crate::filesystem::atomic_write(
            &explicit_dir.join(INSTANCE_DEPLOYMENT_STATEMENT_FILE),
            nazo_operator_protocol::sign_deployment_statement(
                &explicit_statement,
                &explicit_key_id,
                &explicit_key,
            )?
            .as_bytes(),
            0o600,
        )?;
        state.resources.push(Resource::new(
            RUNTIME_INSTANCE_IDENTITY_RESOURCE,
            "directory",
            explicit_dir.to_string_lossy(),
            ResourceOwnership::Managed,
            ResourceScope::Deployment,
        )?);
        let explicit = current_instance_identity(&state)?.expect("explicit runtime identity");
        assert_eq!(explicit.runtime_instance_id, "runtime-explicit");
        assert_eq!(explicit.instance_key_id, explicit_key_id);

        crate::filesystem::atomic_write(
            &explicit_dir.join(INSTANCE_IDENTITY_PUBLIC_FILE),
            nazo_operator_protocol::encode_instance_public_key(&public_key).as_bytes(),
            0o600,
        )?;
        assert!(
            current_instance_identity(&state).is_err(),
            "a public key that cannot verify the deployment statement must fail closed"
        );

        let explicit_public_path = explicit_dir.join(INSTANCE_IDENTITY_PUBLIC_FILE);
        crate::filesystem::atomic_write(
            &explicit_public_path,
            &vec![b'A'; MAX_INSTANCE_PUBLIC_KEY_BYTES as usize + 1],
            0o600,
        )?;
        assert!(
            current_instance_identity(&state).is_err(),
            "oversized runtime identity files must fail closed"
        );

        crate::filesystem::atomic_write(
            &explicit_public_path,
            nazo_operator_protocol::encode_instance_public_key(&explicit_key.verifying_key())
                .as_bytes(),
            0o600,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                &explicit_public_path,
                std::fs::Permissions::from_mode(0o666),
            )?;
            assert!(
                current_instance_identity(&state).is_err(),
                "group/world writable runtime identity files must fail closed"
            );
            std::fs::set_permissions(
                &explicit_public_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
            std::fs::remove_file(&explicit_public_path)?;
            std::os::unix::fs::symlink(
                identity_dir.join(INSTANCE_IDENTITY_PUBLIC_FILE),
                &explicit_public_path,
            )?;
            assert!(
                current_instance_identity(&state).is_err(),
                "symlinked runtime identity files must fail closed"
            );
        }
        Ok(())
    }

    /// A syntactically valid three-segment JWS whose payload carries
    /// `operation_id` = [`CONTROL_JWS_OP_ID`]. Signature verification is the
    /// server's job; the transport only needs a decodable identity to echo.
    fn sample_control_jws() -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = serde_json::json!({ "operation_id": CONTROL_JWS_OP_ID });
        format!(
            "eyJhbGciOiJFZERTQSJ9.{}.c2ln",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        )
    }

    #[test]
    fn control_operations_reach_the_local_operator_and_map_to_receipts() -> anyhow::Result<()> {
        let (_temp, plain_target, journal) = temp_target()?;
        seed_sample_deployment(&journal, "deploy-alpha")?;
        let scripted = Arc::new(ScriptedControl {
            outcome: nazo_operator_protocol::ControlOutcome::Succeeded,
            calls: std::sync::atomic::AtomicUsize::new(0),
            change_set_size: std::sync::atomic::AtomicUsize::new(0),
        });
        let target = plain_target.with_control_executor(scripted.clone());

        let receipt = target.execute_control_operation(ControlOperationRequest {
            operation_id: CONTROL_JWS_OP_ID.to_owned(),
            deployment_id: "deploy-alpha".to_owned(),
            compact_jws: sample_control_jws(),
            change_set: Some(SecretMaterial::try_new(b"bound material".to_vec())?),
        })?;
        assert_eq!(receipt.operation_id, CONTROL_JWS_OP_ID);
        assert!(receipt.accepted);
        assert_eq!(
            receipt.result.expect("durable result").outcome,
            nazo_operator_protocol::ControlOutcome::Succeeded
        );
        assert_eq!(scripted.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            scripted
                .change_set_size
                .load(std::sync::atomic::Ordering::Relaxed),
            b"bound material".len()
        );

        // The delivery was journaled under its own HostOperation id.
        let raw = std::fs::read_to_string(
            journal
                .root()
                .join("deployments")
                .join("deploy-alpha")
                .join("operations.jsonl"),
        )?;
        assert!(raw.contains("control-operation"), "{raw}");
        Ok(())
    }
}
