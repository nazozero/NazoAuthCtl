//! Target-side execution of the update and rollback lifecycle orders (goal
//! plan 07, tasks G03/G04).
//!
//! An `Update` mutation makes the target perform the complete crash-safe
//! update inside its one journaled operation: verify and pull the digest-
//! pinned official artifact (download-on-target through the same H01/H02
//! pipeline as install), snapshot the current configuration, write the staged
//! config when present, redeploy the runtime object onto the new artifact,
//! probe local health, and only then commit `previous=current` state. Every
//! step is resumable by re-execution because the C07 journal replays
//! interrupted operations; on any failure the executor restores the exact
//! pre-update runtime object and config bytes before returning the stable
//! failure — artifact/config REFERENCES roll back locally, while database or
//! other external mutations are never faked as reversible (the release
//! operation contract boundary is reported by the control side).
//!
//! A `Rollback` mutation is an explicit action over saved facts only: it
//! verifies the previous artifact still exists in the local engine image
//! store (offline cached rollback), swaps the runtime back, restores the
//! config snapshot only when it is explicitly saved, integrity-checked, AND
//! still belongs to the deployment's current config generation, probes local
//! health, and atomically swaps `current`/`previous`. No application mutation
//! is ever created here.
//!
//! The executor is an injected seam ([`LifecycleExecutor`]): production uses
//! [`HostLifecycleExecutor`], tests substitute scripted doubles.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::deployment_state::{Failure, OBJECT_IDENTITY_MISMATCH, TargetStateStore};
use super::install_exec::{
    CONTAINER_CONFIG_FILE, CONTAINER_DATA_DIR, CONTAINER_SECRETS_DIR, MIGRATION_RUNTIME_ROLE_ENV,
    OfficialArtifactRef, SERVER_CONFIG_FILE_ENV, StagedConfig, cache_systemd_artifact,
    probe_local_health,
};
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};
use crate::{
    controller_identity::validate_control_result_binding,
    filesystem,
    release::{ReleaseRequest, VerifiedRelease},
    runtime_backend::{self, RuntimeBackendKind},
};

/// Stable failure code: activation or the local readiness gate failed after
/// the update had already touched the runtime/config; the executor rolled its
/// own work back before reporting.
pub const ACTIVATION_FAILED: &str = "ACTIVATION_FAILED";
/// Stable failure code: the running object does not serve the artifact it was
/// expected to serve at this point of the order.
pub const TARGET_IDENTITY_MISMATCH: &str = "TARGET_IDENTITY_MISMATCH";
/// Stable failure code: the previous artifact is not present in the local
/// engine image store, so an offline rollback cannot proceed.
pub const ROLLBACK_ARTIFACT_MISSING: &str = "ROLLBACK_ARTIFACT_MISSING";
/// Stable refusal code when the controller-required backup evidence changed
/// between inspection and execution or aged out before the target lock gate.
pub const BACKUP_UPDATE_PRECONDITION_FAILED: &str = "BACKUP_UPDATE_PRECONDITION_FAILED";
/// Stable refusal code for a legacy deployment that has not imported its
/// file-backed signing keys under a deployment-owned wrapping root.
pub const SIGNING_KEY_MIGRATION_REQUIRED: &str = "SIGNING_KEY_MIGRATION_REQUIRED";

/// Validate the controller-inspected backup facts against the target-owned
/// evidence while the caller holds the deployment's TargetJournal lock. This
/// is deliberately before `LifecycleExecutor::execute_update`, the first
/// artifact, migration, config, and runtime side-effect boundary.
pub(crate) fn validate_backup_precondition(
    scope_dir: &Path,
    state: &super::deployment_state::DeploymentState,
    precondition: &super::deployment_state::UpdateBackupPrecondition,
    now: DateTime<Utc>,
) -> Result<(), Failure> {
    let super::deployment_state::UpdateBackupPrecondition::Require {
        manifest_sha256,
        restore_tested_at,
        max_age_seconds,
    } = precondition
    else {
        return Ok(());
    };
    validate_loaded_backup_projection(
        manifest_sha256,
        *restore_tested_at,
        *max_age_seconds,
        super::backup::backup_projection(scope_dir, state),
        now,
    )
}

fn require_shared_signing_key_root(
    secrets_root: &str,
    config: &str,
    kind: RuntimeBackendKind,
    mounts: &[runtime_backend::NeutralMount],
) -> Result<(), Failure> {
    let refusal = || {
        Failure::new(
            SIGNING_KEY_MIGRATION_REQUIRED,
            "provision the deployment signing-key root, import existing keys, and configure its runtime access before updating; no runtime or database change was made",
        )
    };
    let configured = super::backup_exec::parse_signing_key_encryption_config(config)
        .map_err(|_| refusal())?
        .ok_or_else(refusal)?;
    let configured_files = [
        Some(("signing-key-encryption-key", configured.file.as_str())),
        configured
            .previous_file
            .as_deref()
            .map(|file| ("signing-key-previous-encryption-key", file)),
    ];
    for (name, file) in configured_files.into_iter().flatten() {
        let root = Path::new(secrets_root).join(name);
        let runtime_path = if kind.is_container() {
            Path::new(CONTAINER_SECRETS_DIR).join(name)
        } else {
            root.clone()
        };
        if Path::new(file) != runtime_path {
            return Err(refusal());
        }
        let bytes =
            filesystem::read_secure_secret_file(&root, name, 4096).map_err(|_| refusal())?;
        super::install_exec::validate_signing_key_encryption_key(&bytes).map_err(|_| refusal())?;
        if kind.is_container()
            && !mounts
                .iter()
                .any(|mount| mount.source == root && mount.destination == runtime_path)
        {
            return Err(refusal());
        }
    }
    Ok(())
}

fn validate_loaded_backup_projection(
    expected_manifest_sha256: &str,
    expected_restore_tested_at: DateTime<Utc>,
    max_age_seconds: u64,
    projection: anyhow::Result<super::backup::BackupProjection>,
    now: DateTime<Utc>,
) -> Result<(), Failure> {
    let projection = projection.map_err(|error| {
        Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            format!(
                "current backup evidence is invalid: {}",
                sanitize(error.to_string())
            ),
        )
    })?;
    let current = projection.snapshot.as_ref();
    let current = current.ok_or_else(|| {
        Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            "the required snapshot manifest no longer exists",
        )
    })?;
    if current.manifest_sha256 != expected_manifest_sha256 {
        return Err(Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            "the snapshot manifest changed after controller inspection",
        ));
    }
    let restored_at = current.restore_tested_at.ok_or_else(|| {
        Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            "the required restore-test receipt no longer exists",
        )
    })?;
    if restored_at != expected_restore_tested_at {
        return Err(Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            "the restore-test receipt changed after controller inspection",
        ));
    }
    let age = now.signed_duration_since(restored_at).num_seconds();
    if age < 0 {
        return Err(Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            "the restore-test receipt timestamp is in the future",
        ));
    }
    if age as u64 > max_age_seconds {
        return Err(Failure::new(
            BACKUP_UPDATE_PRECONDITION_FAILED,
            format!(
                "the restore-test receipt is {age} seconds old, exceeding the required {max_age_seconds} seconds"
            ),
        ));
    }
    Ok(())
}

/// Everything one update needs besides the order itself.
pub(crate) struct UpdateJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub issuer: &'a str,
    /// Runtime class token from the live DeploymentState surface.
    pub runtime_kind: RuntimeBackendKind,
    pub runtime_object: &'a str,
    /// Absolute config path recorded in the DeploymentState.
    pub config_reference: &'a str,
    /// The published loopback port for local health probes.
    pub port: u16,
    pub data_root: &'a str,
    /// Deployment-owned directory containing the stable runtime and lifecycle
    /// database URL files. The runtime role is derived from that authority at
    /// execution time instead of being copied into DeploymentState.
    pub secrets_root: &'a str,
    /// Managed systemd binary root. Container deployments do not have one.
    pub runtime_root: Option<&'a str>,
    /// The deployment's current config schema token (pre-update).
    pub config_schema: &'a str,
    /// The deployment's recorded current artifact reference (`sha256:<hex>`).
    pub current_artifact: &'a str,
    /// P1-11 anti-downgrade floor: the version embedded in the current
    /// release version, when the target recorded one.
    pub current_version: Option<&'a str>,
    pub expected_revision: u64,
    pub artifact: &'a OfficialArtifactRef,
    pub config: Option<&'a StagedConfig>,
    pub migration_jws: Option<&'a str>,
    pub migration_request_hash: Option<&'a str>,
    /// `<state root>/deployments/<deployment id>/` — where the rollback
    /// snapshot lives beside the journal.
    pub scope_dir: &'a Path,
    pub store: &'a TargetStateStore,
}

/// Everything one explicit rollback needs besides the confirmation itself.
pub(crate) struct RollbackJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub issuer: &'a str,
    pub runtime_kind: RuntimeBackendKind,
    pub runtime_object: &'a str,
    pub config_reference: &'a str,
    /// The published loopback port for local health probes.
    pub port: u16,
    /// Managed systemd binary root. Container deployments do not have one.
    pub runtime_root: Option<&'a str>,
    pub config_schema: &'a str,
    pub current_artifact: &'a str,
    pub previous_artifact: Option<&'a str>,
    pub current_rollback_policy: &'a crate::model::ReleaseRollbackPolicy,
    pub expected_revision: u64,
    pub scope_dir: &'a Path,
    pub store: &'a TargetStateStore,
}

/// What a completed lifecycle order reports back to dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleFacts {
    pub revision: u64,
    /// The verified manifest's release version, committed alongside the new
    /// current reference for update ordering and rollback history.
    pub release: Option<super::deployment_state::ReleaseVersion>,
    pub migration_result: Option<nazo_operator_protocol::ControlResult>,
}

/// The one host-journaled Update order either activates after a successful
/// MigrateApply, or reports that exact durable migration failure after rolling
/// back all provisional host changes.  It never turns a business failure into
/// an untyped host error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UpdateExecution {
    /// The selected artifact was independently verified on the target and is
    /// already current; with no staged config there is no mutation to run.
    Noop {
        revision: u64,
    },
    Activated(LifecycleFacts),
    MigrationFailed(nazo_operator_protocol::ControlResult),
    RecoveryRequired {
        result: nazo_operator_protocol::ControlResult,
        detail: String,
    },
}

/// The injectable seam executing update/rollback orders on the target.
///
/// Contract: resumable by re-execution; on any failure the implementation has
/// already restored the pre-order runtime/config before returning `Err`.
pub(crate) trait LifecycleExecutor: Send + Sync {
    fn execute_update(&self, job: &UpdateJob<'_>) -> Result<UpdateExecution, Failure>;
    fn execute_rollback(&self, job: &RollbackJob<'_>) -> Result<LifecycleFacts, Failure>;
}

/// Steps an update has durably performed, driving precise rollback.
#[derive(Default)]
pub(crate) struct PerformedSteps {
    pub(crate) snapshotted_config: bool,
    pub(crate) wrote_config: bool,
    pub(crate) replaced_runtime: bool,
    pub(crate) config_before_rollback: Option<Vec<u8>>,
    pub(crate) migration_applied: bool,
    pub(crate) migration_outcome_unknown: bool,
    pub(crate) migration_result: Option<nazo_operator_protocol::ControlResult>,
    pub(crate) verified_rollback_policy: Option<crate::model::ReleaseRollbackPolicy>,
    pub(crate) runtime_before_update: Option<runtime_backend::RuntimeReplacement>,
    pub(crate) runtime_before_update_was_running: bool,
}

/// Production executor backed by the real adapters.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostLifecycleExecutor;

impl LifecycleExecutor for HostLifecycleExecutor {
    fn execute_update(&self, job: &UpdateJob<'_>) -> Result<UpdateExecution, Failure> {
        let mut performed = PerformedSteps::default();
        match self.run_update(job, &mut performed) {
            Ok(UpdateExecution::Noop { revision }) => Ok(UpdateExecution::Noop { revision }),
            Ok(UpdateExecution::Activated(facts)) => Ok(UpdateExecution::Activated(facts)),
            Ok(UpdateExecution::RecoveryRequired { result, detail }) => {
                Ok(UpdateExecution::RecoveryRequired { result, detail })
            }
            Ok(UpdateExecution::MigrationFailed(result)) => {
                match rollback_update(job, &performed) {
                    Ok(()) => Ok(UpdateExecution::MigrationFailed(result)),
                    Err(cleanup) => Err(Failure::new(
                        ACTIVATION_FAILED,
                        format!(
                            "durable migration failure; rollback was incomplete: {}",
                            cleanup.detail
                        ),
                    )),
                }
            }
            Err(failure)
                if performed.migration_applied
                    && performed
                        .verified_rollback_policy
                        .as_ref()
                        .is_some_and(|policy| {
                            !policy.artifact_rollback_allowed_after_migration()
                        }) =>
            {
                let failure = stop_writer_for_recovery(job, failure);
                match performed.migration_result {
                    Some(result) => Ok(UpdateExecution::RecoveryRequired {
                        result,
                        detail: failure.detail,
                    }),
                    None => Err(failure),
                }
            }
            Err(failure) if performed.migration_outcome_unknown => {
                Err(stop_writer_for_unknown_migration(job, failure))
            }
            Err(failure) => match rollback_update(job, &performed) {
                Ok(()) => {
                    if performed.migration_applied {
                        job.store
                            .clear_applied_migration(job.deployment_id, job.operation_id)?;
                    }
                    Err(failure)
                }
                Err(cleanup) => Err(Failure::new(
                    failure.code,
                    format!(
                        "{}; rollback was incomplete: {}",
                        failure.detail, cleanup.detail
                    ),
                )),
            },
        }
    }

    fn execute_rollback(&self, job: &RollbackJob<'_>) -> Result<LifecycleFacts, Failure> {
        let mut performed = PerformedSteps::default();
        match self.run_rollback(job, &mut performed) {
            Ok(facts) => Ok(facts),
            Err(failure) => match restore_current_after_failed_rollback(job, &performed) {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(Failure::new(
                    failure.code,
                    format!(
                        "{}; rollback recovery was incomplete: {}",
                        failure.detail, cleanup.detail
                    ),
                )),
            },
        }
    }
}

impl HostLifecycleExecutor {
    fn run_update(
        &self,
        job: &UpdateJob<'_>,
        performed: &mut PerformedSteps,
    ) -> Result<UpdateExecution, Failure> {
        let kind = job.runtime_kind;
        let backend = runtime_backend::backend(kind);
        privilege_gate(kind)?;

        // 0. The live object's deployment ownership is the authority.
        // Container artifact drift can be reconciled from its immutable live
        // reference; a systemd executable cannot serve as its own rollback
        // source, so host drift is rejected before any mutation.
        let observation = live_observation(backend.as_ref(), job.runtime_object)?;
        require_observation_owned(&observation, kind, job.deployment_id)?;
        let live_digest = observation_digest(&observation).ok_or_else(|| {
            Failure::new(
                OBJECT_IDENTITY_MISMATCH,
                "the owned runtime object does not report a digest-bound artifact",
            )
        })?;
        let recorded_current_was_live =
            require_host_artifact_continuity(kind, &live_digest, job.current_artifact)?;

        // 1. Verify + pull the selected official artifact (download-on-target;
        // re-running verify/pull is idempotent for interrupted resumes).
        // An explicit version is operator-authoritative. The recorded release
        // only acts as the downgrade floor when selecting latest implicitly.
        let verified = verify_pinned_artifact_facts(
            job.artifact,
            kind,
            version_floor_for_update(job.artifact, job.current_version),
            job.runtime_root,
        )?;
        performed.verified_rollback_policy = Some(verified.rollback_policy.clone());
        let new_digest = verified.digest.clone();

        // Verification is the target's authority. Once it proves that the
        // selected digest is already current and no config was staged, the
        // update is complete: do not snapshot, dispatch migration, rotate the
        // rollback generation, or advance the config revision.
        if update_is_noop(
            &live_digest,
            job.current_artifact,
            &new_digest,
            job.config.is_some(),
        ) {
            return Ok(UpdateExecution::Noop {
                revision: job.expected_revision,
            });
        }
        let config_bytes = match job.config {
            Some(config) => zeroize::Zeroizing::new(config.content.as_bytes().to_vec()),
            None => filesystem::read_secure_regular_file(
                Path::new(job.config_reference),
                "deployment configuration",
                false,
                super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
            )
            .map_err(|error| {
                Failure::new(
                    super::install_exec::CONFIG_INVALID,
                    sanitize(error.to_string()),
                )
            })?,
        };
        let config_text = std::str::from_utf8(&config_bytes).map_err(|_| {
            Failure::new(
                super::install_exec::CONFIG_INVALID,
                "deployment configuration must be UTF-8",
            )
        })?;
        require_shared_signing_key_root(job.secrets_root, config_text, kind, &observation.mounts)?;
        // Build and validate the executable replacement before any migration
        // can mutate external state. Activation consumes this exact plan.
        let replacement = runtime_replacement_required(
            Some(live_digest.as_str()),
            &new_digest,
            job.config.is_some(),
        )
        .then(|| {
            let mut replacement = replacement_from_observation(
                &observation,
                job.runtime_object,
                &verified.runtime_artifact,
            )?;
            replacement.local_artifact_id = verified.local_artifact_id.clone();
            Ok::<_, Failure>(replacement)
        })
        .transpose()?;

        if replacement.is_some() && kind.is_container() {
            performed.runtime_before_update = Some(exact_replacement_from_observation(
                &observation,
                job.runtime_object,
            )?);
            performed.runtime_before_update_was_running = observation.running;
        }

        // 2. Snapshot the current config so a failed activation restores the
        // exact bytes (and a later explicit rollback can reuse the snapshot).
        if Path::new(job.config_reference).exists() {
            snapshot_config(
                job.scope_dir,
                job.operation_id,
                job.config_reference,
                job.config_schema,
                job.config.map(|staged| staged.schema.as_str()),
            )
            .map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })?;
            performed.snapshotted_config = true;
        }

        // 3. Stage the new config when present (atomic replace, digest-gated).
        if let Some(staged) = job.config {
            let content_bytes = staged.content.as_bytes();
            if sha256_hex(content_bytes) != staged.sha256 {
                return Err(Failure::new(
                    super::install_exec::CONFIG_INVALID,
                    "staged config content does not match its declared digest",
                ));
            }
            filesystem::atomic_write(Path::new(job.config_reference), content_bytes, 0o600)
                .map_err(|error| {
                    Failure::new(
                        super::install_exec::CONFIG_INVALID,
                        sanitize(error.to_string()),
                    )
                })?;
            grant_runtime_config_read(Path::new(job.config_reference))?;
            performed.wrote_config = true;
        }

        // 3.5. Application migration: run one-shot task using the VERIFIED target artifact.
        let mut migration_result = None;
        if let Some(migration_jws) = job.migration_jws {
            let request_hash = job.migration_request_hash.ok_or_else(|| {
                Failure::new(
                    super::wire::HOST_ERR_OPERATION_INVALID,
                    "update migration JWS has no request-hash binding",
                )
            })?;
            let host = kind == RuntimeBackendKind::Host;
            let service_user =
                host.then(|| runtime_backend::systemd_service_user(job.deployment_id));
            let mut environment = BTreeMap::new();
            let mut read_only_paths = Vec::new();
            let mut read_write_paths = Vec::new();
            let transient_credentials = BTreeMap::new();
            let mounts = observation
                .mounts
                .iter()
                .filter(|mount| {
                    matches!(
                        mount.destination.to_str(),
                        Some(CONTAINER_CONFIG_FILE)
                            | Some(CONTAINER_DATA_DIR)
                            | Some(super::install_exec::CONTAINER_OPERATOR_CONFIG_REVISION_FILE)
                    ) || mount
                        .destination
                        .parent()
                        .is_some_and(|parent| parent == Path::new(CONTAINER_SECRETS_DIR))
                        && mount.destination.file_name().is_some_and(|name| {
                            name == "signing-key-previous-encryption-key"
                                || super::install_exec::SECRET_PURPOSES
                                    .iter()
                                    .any(|purpose| name == *purpose)
                        })
                })
                .cloned()
                .collect();
            let runtime_role = runtime_database_role(job.secrets_root)?;
            let lifecycle_url = lifecycle_database_url(job.secrets_root)?;
            environment.insert(MIGRATION_RUNTIME_ROLE_ENV.to_owned(), runtime_role);
            environment.insert("DATABASE_URL".to_owned(), lifecycle_url);
            if host {
                environment.insert(
                    super::install_exec::SERVER_CONFIG_FILE_ENV.to_owned(),
                    job.config_reference.to_owned(),
                );
                environment.insert(
                    "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
                    job.scope_dir
                        .join("config-revision")
                        .to_string_lossy()
                        .into_owned(),
                );
                environment.insert(
                    "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
                    Path::new(job.data_root)
                        .join("operator-state")
                        .to_string_lossy()
                        .into_owned(),
                );
                read_only_paths.push(PathBuf::from(job.config_reference));
                read_write_paths.push(PathBuf::from(job.data_root));
            } else {
                environment.insert(
                    SERVER_CONFIG_FILE_ENV.to_owned(),
                    CONTAINER_CONFIG_FILE.to_owned(),
                );
                environment.insert(
                    "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
                    super::install_exec::CONTAINER_OPERATOR_CONFIG_REVISION_FILE.to_owned(),
                );
                environment.insert(
                    "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
                    format!("{CONTAINER_DATA_DIR}/operator-state"),
                );
            }
            let task = runtime_backend::OneShotTask {
                artifact: verified.runtime_artifact.clone(),
                command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
                network: if host {
                    Some("host".to_owned())
                } else {
                    observation.networks.first().cloned()
                },
                mounts,
                environment,
                working_directory: kind
                    .is_container()
                    .then(|| std::path::PathBuf::from("/app")),
                service_user: if host {
                    service_user
                } else {
                    Some(crate::runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned())
                },
                transient_credentials,
                read_only_paths,
                read_write_paths,
                inaccessible_paths: Vec::new(),
                private_mounts: false,
                stdin: format!("{}\n", migration_jws).into_bytes(),
            };
            performed.migration_outcome_unknown = true;
            let stdout = backend.run_one_shot(&task).map_err(|error| {
                Failure::new("CONTROL_OUTCOME_UNKNOWN", sanitize(error.to_string()))
            })?;
            let control_result =
                super::control_exec::decode_operator_answer(&stdout, job.operation_id)?;
            validate_migration_result(job.operation_id, request_hash, &control_result)?;
            match control_result.outcome {
                nazo_operator_protocol::ControlOutcome::Succeeded => {
                    performed.migration_result = Some(control_result.clone());
                    performed.migration_applied = true;
                    performed.migration_outcome_unknown = false;
                    job.store.record_migration_applied(
                        job.deployment_id,
                        job.expected_revision,
                        job.operation_id,
                        &format!("sha256:{new_digest}"),
                        &verified.rollback_policy,
                    )?;
                    migration_result = Some(control_result);
                }
                nazo_operator_protocol::ControlOutcome::Failed => {
                    performed.migration_outcome_unknown = false;
                    return Ok(UpdateExecution::MigrationFailed(control_result));
                }
                nazo_operator_protocol::ControlOutcome::InProgress => {
                    return Err(Failure::new(
                        "CONTROL_OUTCOME_UNKNOWN",
                        "the application migration is still in progress; resume the same operation",
                    ));
                }
            }
        }

        // 4. Redeploy the runtime object onto the new artifact. Resume-safe:
        // an object already serving the verified digest is left untouched.
        if let Some(replacement) = replacement {
            if observation.running {
                backend.stop(job.runtime_object).map_err(|error| {
                    Failure::new(ACTIVATION_FAILED, sanitize(error.to_string()))
                })?;
            }
            // From this point the old runtime is stopped, or replacement of
            // an already-stopped object is about to begin. Any failure must
            // restore the exact observed object.
            performed.replaced_runtime = true;
            backend
                .replace(&replacement)
                .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
            backend
                .start(job.runtime_object)
                .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
        }

        // 5. Embedded identity check: the running object must now report the
        // verified digest and be running.
        let activated = live_observation(backend.as_ref(), job.runtime_object)?;
        if !activated.running
            || observation_digest(&activated).as_deref() != Some(new_digest.as_str())
        {
            return Err(Failure::new(
                TARGET_IDENTITY_MISMATCH,
                "the started runtime does not serve the verified artifact",
            ));
        }

        // 6. Local readiness gate (G08 boundary: loopback only).
        probe_local_health(job.port, job.issuer)?;

        // 7. Commit: previous <- old current, current <- new (+ its release
        // version), optional config CAS advance — replay-safe under this
        // operation id.
        let state = job.store.apply_update_healthy_from_live(
            job.deployment_id,
            job.expected_revision,
            super::deployment_state::UpdateCommit {
                artifact: format!("sha256:{new_digest}"),
                release: verified.release.clone(),
                rollback_policy: verified.rollback_policy.clone(),
                config: staged_config_change(job.config_reference, job.config),
                operation_id: job.operation_id.to_owned(),
            },
            recorded_current_was_live,
        )?;
        Ok(UpdateExecution::Activated(LifecycleFacts {
            revision: state.config.revision,
            release: verified.release,
            migration_result,
        }))
    }

    fn run_rollback(
        &self,
        job: &RollbackJob<'_>,
        performed: &mut PerformedSteps,
    ) -> Result<LifecycleFacts, Failure> {
        let kind = job.runtime_kind;
        let backend = runtime_backend::backend(kind);
        privilege_gate(kind)?;

        if !job
            .current_rollback_policy
            .artifact_rollback_allowed_after_migration()
        {
            return Err(Failure::new(
                super::deployment_state::ROLLBACK_RECOVERY_REQUIRED,
                "the verified Release migration policy forbids artifact/config rollback; keep the writer stopped and run verified backup recover",
            ));
        }

        let previous = job.previous_artifact.ok_or_else(|| {
            Failure::new(
                super::deployment_state::ROLLBACK_UNAVAILABLE,
                "no previous verified artifact reference is saved; rollback never guesses",
            )
        })?;

        // 0. Live identity hook on the CURRENT object before anything moves.
        let observation = live_observation(backend.as_ref(), job.runtime_object)?;
        require_observation_serves(&observation, job.current_artifact)?;

        // 1. Offline handle verification: the previous artifact must exist in
        // the local engine image store right now (no network fetch — a
        // rollback depends only on already-verified local bytes).
        let previous_digest = previous.trim_start_matches("sha256:").to_owned();
        let previous_runtime_artifact = match kind {
            RuntimeBackendKind::Host => {
                let runtime_root = job.runtime_root.ok_or_else(|| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "systemd deployment state has no app-binary directory resource",
                    )
                })?;
                let path = Path::new(runtime_root)
                    .join("artifacts")
                    .join(&previous_digest)
                    .join("nazoauth");
                if filesystem::sha256(&path).ok().as_deref() != Some(previous_digest.as_str()) {
                    return Err(Failure::new(
                        ROLLBACK_ARTIFACT_MISSING,
                        format!(
                            "previous host binary {previous} is not present in the verified \
                             target cache"
                        ),
                    ));
                }
                runtime_backend::ArtifactReference::HostBinary {
                    path,
                    sha256: previous_digest.clone(),
                }
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                let image_repo = observation_image_reference(&observation).ok_or_else(|| {
                    Failure::new(
                        OBJECT_IDENTITY_MISMATCH,
                        "the running runtime object does not report a digest-bound OCI artifact",
                    )
                })?;
                let previous_image = format!("{image_repo}@{previous}");
                if !image_exists_locally(kind, &previous_image)? {
                    return Err(Failure::new(
                        ROLLBACK_ARTIFACT_MISSING,
                        format!(
                            "previous artifact {previous} is not present in the local image \
                             store; pull it explicitly before rolling back"
                        ),
                    ));
                }
                runtime_backend::ArtifactReference::Oci {
                    image_reference: image_repo,
                    digest: previous.to_owned(),
                }
            }
        };

        // 2. Config snapshot decision BEFORE touching the runtime: restore
        // only when explicitly saved, integrity-intact, and still belonging to
        // the deployment's current config generation.
        let restored_config =
            read_restorable_snapshot(job.scope_dir, job.config_schema).map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })?;

        // 3. Swap the runtime object back onto the previous artifact.
        let replacement = replacement_from_observation(
            &observation,
            job.runtime_object,
            &previous_runtime_artifact,
        )?;
        backend
            .replace(&replacement)
            .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
        backend
            .start(job.runtime_object)
            .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
        performed.replaced_runtime = true;

        // 4. Identity + local health gates.
        let activated = live_observation(backend.as_ref(), job.runtime_object)?;
        if !activated.running
            || observation_digest(&activated).as_deref() != Some(previous_digest.as_str())
        {
            return Err(Failure::new(
                TARGET_IDENTITY_MISMATCH,
                "the rolled-back runtime does not serve the previous verified artifact",
            ));
        }
        probe_local_health(job.port, job.issuer)?;

        // 5. Restore the snapshot bytes when the decision said so.
        if let Some((bytes, _)) = &restored_config {
            performed.config_before_rollback = Some(
                filesystem::read_secure_regular_file(
                    Path::new(job.config_reference),
                    "current configuration",
                    false,
                    super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
                )
                .map_err(|error| {
                    Failure::new(
                        super::install_exec::CONFIG_INVALID,
                        sanitize(error.to_string()),
                    )
                })?
                .to_vec(),
            );
            filesystem::atomic_write(Path::new(job.config_reference), bytes, 0o600).map_err(
                |error| {
                    Failure::new(
                        super::install_exec::CONFIG_INVALID,
                        sanitize(error.to_string()),
                    )
                },
            )?;
            grant_runtime_config_read(Path::new(job.config_reference))?;
            performed.wrote_config = true;
        }

        // 6. Commit the reference swap (current <-> previous) under CAS; a
        // restored snapshot advances the config CAS under its own schema.
        let config_change = restored_config
            .as_ref()
            .map(|(_, schema)| (job.config_reference.to_owned(), schema.clone()));
        let state = job.store.apply_rollback_healthy(
            job.deployment_id,
            job.expected_revision,
            config_change,
            job.operation_id,
        )?;
        Ok(LifecycleFacts {
            revision: state.config.revision,
            release: None,
            migration_result: None,
        })
    }
}

pub(crate) fn runtime_database_role(secrets_root: impl AsRef<Path>) -> Result<String, Failure> {
    let path = secrets_root.as_ref().join("database-runtime-url");
    let bytes =
        filesystem::read_secure_regular_file(&path, "runtime database URL", false, 16 * 1024)
            .map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })?;
    let value = std::str::from_utf8(&bytes).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "runtime database URL is not UTF-8",
        )
    })?;
    let url = url::Url::parse(value.trim()).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            sanitize(format!("runtime database URL is invalid: {error}")),
        )
    })?;
    let role = url.username();
    if role.is_empty()
        || role.len() > 63
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "runtime database URL has an invalid PostgreSQL role",
        ));
    }
    Ok(role.to_owned())
}

pub(crate) fn lifecycle_database_url(secrets_root: &str) -> Result<String, Failure> {
    let path = Path::new(secrets_root).join("database-lifecycle-url");
    let bytes =
        filesystem::read_secure_regular_file(&path, "lifecycle database URL", false, 16 * 1024)
            .map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })?;
    let value = std::str::from_utf8(&bytes).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "lifecycle database URL is not UTF-8",
        )
    })?;
    let value = value.trim();
    let url = url::Url::parse(value).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            sanitize(format!("lifecycle database URL is invalid: {error}")),
        )
    })?;
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.username().is_empty() {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "lifecycle database URL is not a PostgreSQL credential URL",
        ));
    }
    Ok(value.to_owned())
}

/// Target-side pre-activation gate for the nested MigrateApply.  This is only
/// an adapter to the controller's one result-binding authority; it adds no
/// second operation/result contract.
fn validate_migration_result(
    operation_id: &str,
    request_hash: &str,
    result: &nazo_operator_protocol::ControlResult,
) -> Result<(), Failure> {
    validate_control_result_binding(
        operation_id,
        request_hash,
        &nazo_operator_protocol::ControlOperationPayload::MigrateApply,
        result,
    )
    .map_err(|error| {
        Failure::new(
            super::control_exec::CONTROL_OUTCOME_UNKNOWN,
            sanitize(error.to_string()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use nazo_operator_protocol::{ControlOutcome, ControlResult, ControlResultData};

    const OPERATION_ID: &str = "01900000-0000-7000-8000-000000000001";

    #[test]
    fn migration_runtime_role_comes_from_the_existing_runtime_database_url() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("migration-runtime-role")?;
        let path = temp.path().join("database-runtime-url");
        crate::filesystem::atomic_write(
            &path,
            b"postgresql://nazo_runtime:secret@db.internal/oauth\n",
            0o600,
        )?;

        assert_eq!(
            runtime_database_role(temp.path().to_str().unwrap()).map_err(anyhow::Error::from)?,
            "nazo_runtime"
        );
        Ok(())
    }

    #[test]
    fn migration_runtime_role_rejects_an_encoded_identifier() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("migration-runtime-role-invalid")?;
        let path = temp.path().join("database-runtime-url");
        crate::filesystem::atomic_write(
            &path,
            b"postgresql://nazo%22runtime:secret@db.internal/oauth",
            0o600,
        )?;

        assert!(runtime_database_role(temp.path().to_str().unwrap()).is_err());
        Ok(())
    }

    #[test]
    fn migration_lifecycle_url_is_loaded_as_a_direct_postgresql_value() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("migration-lifecycle-url")?;
        let path = temp.path().join("database-lifecycle-url");
        crate::filesystem::atomic_write(
            &path,
            b"postgresql://nazo_lifecycle:secret@db.internal/oauth\n",
            0o600,
        )?;

        assert_eq!(
            lifecycle_database_url(temp.path().to_str().unwrap()).map_err(anyhow::Error::from)?,
            "postgresql://nazo_lifecycle:secret@db.internal/oauth"
        );
        Ok(())
    }

    #[test]
    fn update_requires_an_existing_shared_signing_root_before_mutation() -> anyhow::Result<()> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let temp = crate::filesystem::PrivateTempDir::new("update-signing-root")?;
        let directory = temp.path().to_str().unwrap();
        let path = temp.path().join("signing-key-encryption-key");
        let config = serde_json::json!({
            "SIGNING_KEY_ENCRYPTION_KEY_FILE": path,
            "SIGNING_KEY_ENCRYPTION_KEY_ID": "test",
        })
        .to_string();
        let refusal =
            require_shared_signing_key_root(directory, &config, RuntimeBackendKind::Host, &[])
                .expect_err("old deployment requires explicit key migration");
        assert_eq!(refusal.code, SIGNING_KEY_MIGRATION_REQUIRED);
        assert!(!path.exists());
        filesystem::atomic_write(&path, URL_SAFE_NO_PAD.encode([42_u8; 32]).as_bytes(), 0o600)?;
        require_shared_signing_key_root(directory, &config, RuntimeBackendKind::Host, &[])?;
        let previous_path = temp.path().join("signing-key-previous-encryption-key");
        let mut rolling: serde_json::Value = serde_json::from_str(&config)?;
        rolling["SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_FILE"] = serde_json::json!(previous_path);
        rolling["SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID"] = serde_json::json!("previous");
        assert!(
            require_shared_signing_key_root(
                directory,
                &rolling.to_string(),
                RuntimeBackendKind::Host,
                &[]
            )
            .is_err()
        );
        filesystem::atomic_write(
            &previous_path,
            URL_SAFE_NO_PAD.encode([43_u8; 32]).as_bytes(),
            0o600,
        )?;
        require_shared_signing_key_root(
            directory,
            &rolling.to_string(),
            RuntimeBackendKind::Host,
            &[],
        )?;
        assert!(
            require_shared_signing_key_root(directory, "{}", RuntimeBackendKind::Host, &[])
                .is_err()
        );
        let container_config = serde_json::json!({
            "SIGNING_KEY_ENCRYPTION_KEY_FILE": format!("{CONTAINER_SECRETS_DIR}/signing-key-encryption-key"),
            "SIGNING_KEY_ENCRYPTION_KEY_ID": "test",
        }).to_string();
        assert!(
            require_shared_signing_key_root(
                directory,
                &container_config,
                RuntimeBackendKind::Docker,
                &[]
            )
            .is_err()
        );
        filesystem::atomic_write(&path, b"invalid", 0o600)?;
        assert!(
            require_shared_signing_key_root(directory, &config, RuntimeBackendKind::Host, &[])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn migration_lifecycle_url_rejects_non_postgresql_inputs() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("migration-lifecycle-url-invalid")?;
        let path = temp.path().join("database-lifecycle-url");
        crate::filesystem::atomic_write(&path, b"https://db.internal/oauth", 0o600)?;

        let error = lifecycle_database_url(temp.path().to_str().unwrap())
            .expect_err("non-PostgreSQL lifecycle URL must fail closed");
        assert_eq!(error.code, HOST_ERR_OPERATION_INVALID);
        Ok(())
    }

    fn terminal_result() -> ControlResult {
        ControlResult {
            schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
            operation_id: OPERATION_ID.to_owned(),
            request_hash: "a".repeat(64),
            outcome: ControlOutcome::Succeeded,
            error: None,
            accepted_at: 1,
            completed_at: Some(2),
            result: None,
        }
    }

    fn projection(
        manifest_sha256: &str,
        restore_tested_at: Option<DateTime<Utc>>,
    ) -> super::super::backup::BackupProjection {
        super::super::backup::BackupProjection {
            local_rollback_ready: false,
            snapshot: Some(super::super::backup::SnapshotProjection {
                snapshot_id: "01900000-0000-7000-8000-000000000002".to_owned(),
                created_at: Utc::now(),
                manifest_sha256: manifest_sha256.to_owned(),
                restore_tested_at,
                off_host_verified_at: None,
            }),
        }
    }

    #[test]
    fn backup_precondition_rejects_every_same_revision_evidence_drift() {
        let now = Utc::now();
        let restored_at = now - TimeDelta::seconds(60);
        let expected_hash = "a".repeat(64);

        let replaced = validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            300,
            Ok(projection(&"b".repeat(64), Some(restored_at))),
            now,
        )
        .expect_err("a replacement manifest must fail at the target");
        assert_eq!(replaced.code, BACKUP_UPDATE_PRECONDITION_FAILED);

        let cleared = validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            300,
            Ok(projection(&expected_hash, None)),
            now,
        )
        .expect_err("a cleared receipt must fail at the target");
        assert_eq!(cleared.code, BACKUP_UPDATE_PRECONDITION_FAILED);

        let changed_receipt = validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            300,
            Ok(projection(
                &expected_hash,
                Some(restored_at + TimeDelta::seconds(1)),
            )),
            now,
        )
        .expect_err("a replacement receipt must fail at the target");
        assert_eq!(changed_receipt.code, BACKUP_UPDATE_PRECONDITION_FAILED);

        let crossed_receipt = validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            300,
            Err(anyhow::anyhow!(
                "restore-test receipt does not bind the current manifest hash"
            )),
            now,
        )
        .expect_err("a receipt carrying another manifest hash must fail closed");
        assert_eq!(crossed_receipt.code, BACKUP_UPDATE_PRECONDITION_FAILED);
    }

    #[test]
    fn backup_precondition_enforces_freshness_and_accepts_exact_current_facts() {
        let now = Utc::now();
        let restored_at = now - TimeDelta::seconds(60);
        let expected_hash = "a".repeat(64);

        validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            60,
            Ok(projection(&expected_hash, Some(restored_at))),
            now,
        )
        .expect("the exact receipt at the inclusive age boundary is valid");

        let expired = validate_loaded_backup_projection(
            &expected_hash,
            restored_at,
            59,
            Ok(projection(&expected_hash, Some(restored_at))),
            now,
        )
        .expect_err("an expired receipt must fail before update execution");
        assert_eq!(expired.code, BACKUP_UPDATE_PRECONDITION_FAILED);
    }

    #[test]
    fn preactivation_guard_rejects_wrong_request_hash_and_typed_result() {
        let mut wrong_hash = terminal_result();
        wrong_hash.request_hash = "b".repeat(64);
        let error = validate_migration_result(OPERATION_ID, &"a".repeat(64), &wrong_hash)
            .expect_err("wrong hash must not reach activation");
        assert_eq!(
            error.code,
            super::super::control_exec::CONTROL_OUTCOME_UNKNOWN
        );
        assert!(error.detail.contains("request hash"));

        let mut wrong_typed = terminal_result();
        wrong_typed.result = Some(ControlResultData::RecoveryInvalidation {
            state_epoch: "01900000-0000-7000-8000-000000000002".to_owned(),
            not_before: 3,
            revoked_refresh_tokens: 0,
        });
        let error = validate_migration_result(OPERATION_ID, &"a".repeat(64), &wrong_typed)
            .expect_err("wrong typed result must not reach activation");
        assert_eq!(
            error.code,
            super::super::control_exec::CONTROL_OUTCOME_UNKNOWN
        );
        assert!(error.detail.contains("operation contract"));
    }

    #[test]
    fn replacement_never_reuses_another_artifacts_local_image_id() {
        let current = runtime_backend::ArtifactReference::Oci {
            image_reference: "registry.example/nazoauth".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        };
        let next = runtime_backend::ArtifactReference::Oci {
            image_reference: "registry.example/nazoauth".to_owned(),
            digest: format!("sha256:{}", "b".repeat(64)),
        };
        let mount = |destination: &str| runtime_backend::NeutralMount {
            source: PathBuf::from(format!("/srv/nazoauth{}", destination)),
            destination: PathBuf::from(destination),
            read_only: true,
            selinux_relabel: false,
            ownership: runtime_backend::Responsibility::Managed,
            scope: runtime_backend::RuntimeResourceScope::Deployment,
        };
        let observation = runtime_backend::RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: "nazoauth".to_owned(),
            display_name: "nazoauth".to_owned(),
            running: true,
            server_command_verified: true,
            artifact: current.clone(),
            local_artifact_id: Some(format!("sha256:{}", "c".repeat(64))),
            ports: vec!["127.0.0.1:29892->8000/tcp".to_owned()],
            networks: Vec::new(),
            mounts: vec![
                mount("/run/secrets/database-runtime-url"),
                mount("/run/secrets/valkey-url"),
                mount("/run/secrets/mfa-key"),
            ],
            safe_environment: BTreeMap::from([
                (
                    "DATABASE_URL_FILE".to_owned(),
                    "/run/secrets/database-runtime-url".to_owned(),
                ),
                (
                    "VALKEY_URL_FILE".to_owned(),
                    "/run/secrets/valkey-url".to_owned(),
                ),
                ("DATA_DIR".to_owned(), "/var/lib/nazoauth".to_owned()),
            ]),
            labels: BTreeMap::new(),
            evidence: Vec::new(),
            missing: Vec::new(),
        };

        let unchanged = replacement_from_observation(&observation, "nazoauth", &current)
            .expect("same artifact replacement");
        assert_eq!(unchanged.local_artifact_id, observation.local_artifact_id);
        assert_eq!(unchanged.ports, ["127.0.0.1:29892:8000/tcp"]);
        assert_eq!(unchanged.mounts.len(), 1);
        assert_eq!(
            unchanged.mounts[0].destination,
            PathBuf::from("/run/secrets/mfa-key")
        );
        assert_eq!(
            unchanged.environment,
            BTreeMap::from([("DATA_DIR".to_owned(), "/var/lib/nazoauth".to_owned())])
        );

        let changed = replacement_from_observation(&observation, "nazoauth", &next)
            .expect("changed artifact replacement");
        assert_eq!(changed.local_artifact_id, None);
    }

    #[test]
    fn staged_config_replaces_runtime_even_when_artifact_is_unchanged() {
        let digest = "a".repeat(64);
        assert!(!runtime_replacement_required(Some(&digest), &digest, false));
        assert!(runtime_replacement_required(Some(&digest), &digest, true));
        assert!(runtime_replacement_required(
            Some(&"b".repeat(64)),
            &digest,
            false
        ));
    }

    #[test]
    fn noop_uses_live_digest_and_reconciles_stale_recorded_state() {
        let selected = "a".repeat(64);
        let other = "b".repeat(64);

        assert!(update_is_noop(
            &selected,
            &format!("sha256:{selected}"),
            &selected,
            false
        ));
        assert!(!update_is_noop(
            &other,
            &format!("sha256:{selected}"),
            &selected,
            false
        ));
        assert!(!update_is_noop(
            &selected,
            &format!("sha256:{other}"),
            &selected,
            false
        ));
    }

    #[test]
    fn explicit_version_does_not_inherit_the_recorded_version_floor() {
        let explicit = OfficialArtifactRef {
            repository: "nazozero/NazoAuth".to_owned(),
            version: Some("v0.2.8".to_owned()),
        };
        let latest = OfficialArtifactRef {
            repository: "nazozero/NazoAuth".to_owned(),
            version: None,
        };

        assert_eq!(version_floor_for_update(&explicit, Some("v0.2.9")), None);
        assert_eq!(
            version_floor_for_update(&latest, Some("v0.2.9")),
            Some("v0.2.9")
        );
    }

    fn owned_observation(kind: RuntimeBackendKind) -> runtime_backend::RuntimeObservation {
        runtime_backend::RuntimeObservation {
            backend: kind,
            object_reference: "nazoauth".to_owned(),
            display_name: "nazoauth".to_owned(),
            running: true,
            server_command_verified: true,
            artifact: runtime_backend::ArtifactReference::Oci {
                image_reference: "registry.example/nazoauth".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            local_artifact_id: None,
            ports: vec!["127.0.0.1:29892->8000/tcp".to_owned()],
            networks: Vec::new(),
            mounts: Vec::new(),
            safe_environment: BTreeMap::from([("DEPLOYMENT_ID".to_owned(), "deploy-a".to_owned())]),
            labels: BTreeMap::from([(
                "io.nazoauth.deployment-id".to_owned(),
                "deploy-a".to_owned(),
            )]),
            evidence: Vec::new(),
            missing: Vec::new(),
        }
    }

    #[test]
    fn live_update_authority_is_deployment_ownership_not_recorded_digest() {
        let container = owned_observation(RuntimeBackendKind::Podman);
        require_observation_owned(&container, RuntimeBackendKind::Podman, "deploy-a")
            .expect("matching label and environment own the container");

        let mut missing_label = container.clone();
        missing_label.labels.clear();
        assert_eq!(
            require_observation_owned(&missing_label, RuntimeBackendKind::Podman, "deploy-a")
                .expect_err("container ownership requires its label")
                .code,
            OBJECT_IDENTITY_MISMATCH
        );

        let mut wrong_environment = container.clone();
        wrong_environment
            .safe_environment
            .insert("DEPLOYMENT_ID".to_owned(), "deploy-b".to_owned());
        assert_eq!(
            require_observation_owned(&wrong_environment, RuntimeBackendKind::Podman, "deploy-a")
                .expect_err("container ownership requires its environment")
                .code,
            OBJECT_IDENTITY_MISMATCH
        );

        let mut host = owned_observation(RuntimeBackendKind::Host);
        host.labels.clear();
        host.artifact = runtime_backend::ArtifactReference::HostBinary {
            path: PathBuf::from("/usr/local/lib/nazoauth"),
            sha256: "a".repeat(64),
        };
        require_observation_owned(&host, RuntimeBackendKind::Host, "deploy-a")
            .expect("systemd ownership comes from the deployment environment");
    }

    #[test]
    fn only_container_updates_may_converge_a_live_artifact_drift() -> Result<(), Failure> {
        let live = "b".repeat(64);
        let recorded = format!("sha256:{}", "a".repeat(64));

        assert!(!require_host_artifact_continuity(
            RuntimeBackendKind::Podman,
            &live,
            &recorded
        )?);
        let host_error =
            require_host_artifact_continuity(RuntimeBackendKind::Host, &live, &recorded)
                .expect_err("a live systemd binary is not a rollback artifact");
        assert_eq!(host_error.code, OBJECT_IDENTITY_MISMATCH);
        assert!(require_host_artifact_continuity(
            RuntimeBackendKind::Host,
            &live,
            &format!("sha256:{live}")
        )?);
        Ok(())
    }

    #[test]
    fn failed_activation_snapshot_retains_the_exact_live_surface() {
        let mut observation = owned_observation(RuntimeBackendKind::Podman);
        observation.safe_environment.insert(
            "DATABASE_URL_FILE".to_owned(),
            "/run/secrets/database-runtime-url".to_owned(),
        );
        observation.mounts.push(runtime_backend::NeutralMount {
            source: PathBuf::from("/srv/nazoauth/database-runtime-url"),
            destination: PathBuf::from("/run/secrets/database-runtime-url"),
            read_only: true,
            selinux_relabel: false,
            ownership: runtime_backend::Responsibility::Managed,
            scope: runtime_backend::RuntimeResourceScope::Deployment,
        });

        let replacement = exact_replacement_from_observation(&observation, "nazoauth")
            .expect("live surface can be captured");
        assert_eq!(replacement.artifact, observation.artifact);
        assert_eq!(replacement.local_artifact_id, observation.local_artifact_id);
        assert_eq!(replacement.mounts, observation.mounts);
        assert_eq!(replacement.environment, observation.safe_environment);
        assert_eq!(replacement.labels, observation.labels);
    }

    #[test]
    fn replacement_rejects_a_non_neutral_port_binding() {
        let artifact = runtime_backend::ArtifactReference::Oci {
            image_reference: "registry.example/nazoauth".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        };
        let observation = runtime_backend::RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: "nazoauth".to_owned(),
            display_name: "nazoauth".to_owned(),
            running: true,
            server_command_verified: true,
            artifact: artifact.clone(),
            local_artifact_id: None,
            ports: vec!["127.0.0.1:29892:8000/tcp".to_owned()],
            networks: Vec::new(),
            mounts: Vec::new(),
            safe_environment: BTreeMap::new(),
            labels: BTreeMap::new(),
            evidence: Vec::new(),
            missing: Vec::new(),
        };

        let error = replacement_from_observation(&observation, "nazoauth", &artifact)
            .expect_err("replacement must not pass through an ambiguous port binding");
        assert_eq!(error.code, OBJECT_IDENTITY_MISMATCH);
    }
}

fn privilege_gate(runtime_kind: RuntimeBackendKind) -> Result<(), Failure> {
    if runtime_kind.is_container() {
        crate::instance_lifecycle::privilege::ensure_engine_access(
            runtime_kind.as_str(),
            &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
        )
        .map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))
    } else {
        crate::instance_lifecycle::privilege::ensure_systemd_access()
            .map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))
    }
}

fn live_observation(
    backend: &dyn runtime_backend::RuntimeBackend,
    object: &str,
) -> Result<runtime_backend::RuntimeObservation, Failure> {
    backend
        .inspect(object)
        .map_err(|error| Failure::new(OBJECT_IDENTITY_MISMATCH, sanitize(error.to_string())))
}

/// The digest half of an Oci observation reference (`sha256:` stripped).
pub(crate) fn observation_digest(
    observation: &runtime_backend::RuntimeObservation,
) -> Option<String> {
    match &observation.artifact {
        runtime_backend::ArtifactReference::Oci { digest, .. } => {
            Some(digest.trim_start_matches("sha256:").to_owned())
        }
        runtime_backend::ArtifactReference::HostBinary { sha256, .. } => Some(sha256.clone()),
        runtime_backend::ArtifactReference::Unknown => None,
    }
}

fn runtime_replacement_required(
    current_digest: Option<&str>,
    selected_digest: &str,
    has_staged_config: bool,
) -> bool {
    has_staged_config || current_digest != Some(selected_digest)
}

fn update_is_noop(
    live_digest: &str,
    recorded_current: &str,
    selected_digest: &str,
    has_staged_config: bool,
) -> bool {
    !has_staged_config
        && live_digest == selected_digest
        && live_digest == recorded_current.trim_start_matches("sha256:")
}

fn require_host_artifact_continuity(
    kind: RuntimeBackendKind,
    live_digest: &str,
    recorded_current: &str,
) -> Result<bool, Failure> {
    let matches = live_digest == recorded_current.trim_start_matches("sha256:");
    if kind == RuntimeBackendKind::Host && !matches {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "the systemd runtime artifact differs from deployment state; refusing an update because the live executable is not a recoverable rollback source",
        ));
    }
    Ok(matches)
}

fn version_floor_for_update<'a>(
    artifact: &OfficialArtifactRef,
    current_version: Option<&'a str>,
) -> Option<&'a str> {
    artifact
        .version
        .is_none()
        .then_some(current_version)
        .flatten()
}

fn observation_image_reference(
    observation: &runtime_backend::RuntimeObservation,
) -> Option<String> {
    match &observation.artifact {
        runtime_backend::ArtifactReference::Oci {
            image_reference, ..
        } => Some(image_reference.clone()),
        _ => None,
    }
}

fn require_observation_serves(
    observation: &runtime_backend::RuntimeObservation,
    expected: &str,
) -> Result<(), Failure> {
    let digest = observation_digest(observation).ok_or_else(|| {
        Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "the running runtime object does not report a digest-bound artifact",
        )
    })?;
    if digest != expected.trim_start_matches("sha256:") {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            format!(
                "runtime object serves {} while the deployment state records {}",
                sanitize(digest),
                sanitize(expected.to_owned())
            ),
        ));
    }
    Ok(())
}

fn require_observation_owned(
    observation: &runtime_backend::RuntimeObservation,
    kind: RuntimeBackendKind,
    deployment_id: &str,
) -> Result<(), Failure> {
    if !observation.server_command_verified {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "the runtime object is not a verified NazoAuth server",
        ));
    }
    if observation
        .safe_environment
        .get("DEPLOYMENT_ID")
        .map(String::as_str)
        != Some(deployment_id)
    {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "the runtime object deployment environment does not match this deployment",
        ));
    }
    if kind.is_container()
        && observation
            .labels
            .get("io.nazoauth.deployment-id")
            .map(String::as_str)
            != Some(deployment_id)
    {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "the runtime object ownership label does not match this deployment",
        ));
    }
    Ok(())
}

pub(crate) fn verify_pinned_artifact_facts(
    artifact: &OfficialArtifactRef,
    kind: RuntimeBackendKind,
    version_floor: Option<&str>,
    runtime_root: Option<&str>,
) -> Result<VerifiedArtifactFacts, Failure> {
    #[cfg(feature = "pre-release-validation")]
    if let Some(candidate) = crate::pre_release::resolve(artifact).map_err(|error| {
        Failure::new(
            super::install_exec::ARTIFACT_UNVERIFIED,
            sanitize(format!("{error:#}")),
        )
    })? {
        candidate.enforce_floor(version_floor).map_err(|error| {
            Failure::new(
                super::install_exec::ARTIFACT_UNVERIFIED,
                sanitize(error.to_string()),
            )
        })?;
        let backend = runtime_backend::backend(kind);
        let (digest, runtime_artifact, local_artifact_id) = match kind {
            RuntimeBackendKind::Host => {
                let runtime_root = runtime_root.ok_or_else(|| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        "systemd deployment state has no app-binary directory resource",
                    )
                })?;
                let (host_binary_path, host_binary_sha256) =
                    candidate.host_binary_artifact().ok_or_else(|| {
                        Failure::new(
                            super::install_exec::ARTIFACT_UNVERIFIED,
                            "pre-release candidate has no host binary artifact",
                        )
                    })?;
                let source = Path::new(host_binary_path);
                let observed_digest = filesystem::sha256(source).map_err(|error| {
                    Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        sanitize(error.to_string()),
                    )
                })?;
                if observed_digest != host_binary_sha256 {
                    return Err(Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        "local pre-release host binary does not match its content digest",
                    ));
                }
                let cached =
                    cache_systemd_artifact(source, Path::new(runtime_root), &observed_digest)
                        .map_err(|error| {
                            Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
                        })?;
                (
                    observed_digest.clone(),
                    runtime_backend::ArtifactReference::HostBinary {
                        path: cached,
                        sha256: observed_digest,
                    },
                    None,
                )
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                let (oci_image, oci_pull_digest, oci_runtime_digest) =
                    candidate.oci_artifact().ok_or_else(|| {
                        Failure::new(
                            super::install_exec::ARTIFACT_UNVERIFIED,
                            "pre-release candidate has no OCI artifact",
                        )
                    })?;
                let image = format!("{oci_image}@{oci_pull_digest}");
                backend.pull_image(&image).map_err(|error| {
                    Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        sanitize(error.to_string()),
                    )
                })?;
                (
                    oci_runtime_digest.trim_start_matches("sha256:").to_owned(),
                    runtime_backend::ArtifactReference::Oci {
                        image_reference: oci_image.to_owned(),
                        digest: oci_runtime_digest.to_owned(),
                    },
                    None,
                )
            }
        };
        let release = candidate.release_version().map_err(|error| {
            Failure::new(
                super::install_exec::ARTIFACT_UNVERIFIED,
                sanitize(error.to_string()),
            )
        })?;
        return Ok(VerifiedArtifactFacts {
            digest,
            runtime_artifact,
            local_artifact_id,
            release: Some(release),
            rollback_policy: candidate.rollback,
        });
    }
    let release = VerifiedRelease::verify(ReleaseRequest {
        repository: &artifact.repository,
        requested_version: artifact.version.as_deref(),
        trusted_version_floor: version_floor,
    })
    .map_err(|error| {
        Failure::new(
            super::install_exec::ARTIFACT_UNVERIFIED,
            sanitize(error.to_string()),
        )
    })?;
    let (digest, runtime_artifact, local_artifact_id) = match kind {
        RuntimeBackendKind::Host => {
            let runtime_root = runtime_root.ok_or_else(|| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    "systemd deployment state has no app-binary directory resource",
                )
            })?;
            let source = release
                .artifact("binary", &artifact.repository)
                .map_err(|error| {
                    Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        sanitize(error.to_string()),
                    )
                })?;
            let digest = filesystem::sha256(&source).map_err(|error| {
                Failure::new(
                    super::install_exec::ARTIFACT_UNVERIFIED,
                    sanitize(error.to_string()),
                )
            })?;
            let cached = cache_systemd_artifact(&source, Path::new(runtime_root), &digest)
                .map_err(|error| {
                    Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
                })?;
            (
                digest.clone(),
                runtime_backend::ArtifactReference::HostBinary {
                    path: cached,
                    sha256: digest,
                },
                None,
            )
        }
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
            let digest = release
                .manifest
                .runtime_oci_digest_for(crate::model::container_oci_platform())
                .map_err(|error| {
                    Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        sanitize(error.to_string()),
                    )
                })?;
            let image = format!(
                "{}@{digest}",
                release.manifest.oci.repository.trim_end_matches('/')
            );
            runtime_backend::backend(kind)
                .pull_image(&image)
                .map_err(|error| {
                    Failure::new(
                        super::install_exec::ARTIFACT_UNVERIFIED,
                        sanitize(error.to_string()),
                    )
                })?;
            let digest = digest.trim_start_matches("sha256:").to_owned();
            // Run the container from the digest-bound reference, never a bare
            // local image ID: a multi-arch index pull stores platform digest
            // entries whose order must not decide the identity assertion.
            (
                digest.clone(),
                runtime_backend::ArtifactReference::Oci {
                    image_reference: release.manifest.oci.repository.clone(),
                    digest: format!("sha256:{digest}"),
                },
                None,
            )
        }
    };
    Ok(VerifiedArtifactFacts {
        digest,
        runtime_artifact,
        local_artifact_id,
        rollback_policy: release.rollback_policy(),
        release: Some(
            super::deployment_state::ReleaseVersion::new(&release.manifest.version).map_err(
                |error| Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string())),
            )?,
        ),
    })
}

/// The verified facts an update needs from its selected artifact: its sole
/// content identity plus the release version used for ordering and rollback.
pub(crate) struct VerifiedArtifactFacts {
    pub(crate) digest: String,
    pub(crate) runtime_artifact: runtime_backend::ArtifactReference,
    pub(crate) local_artifact_id: Option<String>,
    pub(crate) release: Option<super::deployment_state::ReleaseVersion>,
    pub(crate) rollback_policy: crate::model::ReleaseRollbackPolicy,
}

/// Rebuild the runtime replacement from the LIVE observation, changing only
/// the artifact. This preserves whatever mounts/networks/ports/environment
/// the deployment actually runs with instead of reconstructing from a plan.
pub(crate) fn replacement_from_observation(
    observation: &runtime_backend::RuntimeObservation,
    object: &str,
    artifact: &runtime_backend::ArtifactReference,
) -> Result<runtime_backend::RuntimeReplacement, Failure> {
    let (command, container_policy) = match artifact {
        runtime_backend::ArtifactReference::Oci { .. } => (
            vec!["nazoauth".to_owned(), "server".to_owned()],
            Some(runtime_backend::ContainerRuntimePolicy::managed_default()),
        ),
        runtime_backend::ArtifactReference::HostBinary { .. } => {
            let executable = match &observation.artifact {
                runtime_backend::ArtifactReference::HostBinary { path, .. } => path,
                _ => {
                    return Err(Failure::new(
                        OBJECT_IDENTITY_MISMATCH,
                        "systemd replacement requires a live host-binary observation",
                    ));
                }
            };
            (
                vec![
                    executable.to_string_lossy().into_owned(),
                    "server".to_owned(),
                ],
                None,
            )
        }
        runtime_backend::ArtifactReference::Unknown => {
            return Err(Failure::new(
                super::install_exec::ARTIFACT_UNVERIFIED,
                "runtime replacement requires a verified artifact reference",
            ));
        }
    };
    let ports = observation
        .ports
        .iter()
        .map(|binding| {
            let (host, container) = binding.split_once("->").ok_or_else(|| {
                Failure::new(
                    OBJECT_IDENTITY_MISMATCH,
                    format!("runtime observation has an invalid port binding '{binding}'"),
                )
            })?;
            if host.is_empty() || container.is_empty() || container.contains("->") {
                return Err(Failure::new(
                    OBJECT_IDENTITY_MISMATCH,
                    format!("runtime observation has an invalid port binding '{binding}'"),
                ));
            }
            Ok(format!("{host}:{container}"))
        })
        .collect::<Result<Vec<_>, Failure>>()?;

    let legacy_url_mounts = [
        Path::new(super::install_exec::CONTAINER_SECRETS_DIR).join("database-runtime-url"),
        Path::new(super::install_exec::CONTAINER_SECRETS_DIR).join("valkey-url"),
    ];
    let mounts = observation
        .mounts
        .iter()
        .filter(|mount| !legacy_url_mounts.contains(&mount.destination))
        .cloned()
        .collect();
    let environment = observation
        .safe_environment
        .iter()
        .filter(|(name, _)| {
            name.as_str() != "DATABASE_URL_FILE" && name.as_str() != "VALKEY_URL_FILE"
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    Ok(runtime_backend::RuntimeReplacement {
        object_reference: object.to_owned(),
        artifact: artifact.clone(),
        local_artifact_id: if observation.artifact == *artifact {
            observation.local_artifact_id.clone()
        } else {
            None
        },
        command,
        mounts,
        environment,
        networks: observation.networks.clone(),
        ip_address: None,
        ports,
        labels: observation.labels.clone(),
        container_policy,
    })
}

/// Capture the live runtime surface used to undo a failed activation. Unlike
/// a forward replacement this retains every observed mount and safe
/// environment value because failure recovery must restore the object that
/// was actually running, not reconstruct it from stale deployment state.
fn exact_replacement_from_observation(
    observation: &runtime_backend::RuntimeObservation,
    object: &str,
) -> Result<runtime_backend::RuntimeReplacement, Failure> {
    if observation.backend == RuntimeBackendKind::Host {
        return Err(Failure::new(
            OBJECT_IDENTITY_MISMATCH,
            "a live systemd executable path is not a recoverable artifact source",
        ));
    }
    let mut replacement = replacement_from_observation(observation, object, &observation.artifact)?;
    replacement.mounts = observation.mounts.clone();
    replacement.environment = observation.safe_environment.clone();
    Ok(replacement)
}

fn image_exists_locally(kind: RuntimeBackendKind, image: &str) -> Result<bool, Failure> {
    use crate::process::Process;
    let engine = match kind {
        RuntimeBackendKind::Podman => "podman",
        RuntimeBackendKind::Docker => "docker",
        RuntimeBackendKind::Host => {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "systemd deployments cannot verify image handles",
            ));
        }
    };
    let process = Process::new(engine);
    let process = match kind {
        RuntimeBackendKind::Podman => process.args(["image", "exists", image]),
        _ => process.args(["image", "inspect", image]),
    };
    Ok(process.succeeds())
}

// ------------------------------------------------------------------ snapshots

const SNAPSHOT_META_SCHEMA: u32 = 2;
pub(super) const SNAPSHOT_BYTES_FILE: &str = "rollback-config.bin";
pub(super) const SNAPSHOT_META_FILE: &str = "rollback-config.json";

/// Snapshot metadata binding the saved bytes to the two config generations it
/// separates: the schema it replaced (`config_schema`) and the schema that
/// replaced it (`replaced_by_schema`). A rollback restores the snapshot only
/// while the deployment's live config still runs `replaced_by_schema`, which
/// is exactly the condition under which the snapshot is the explicitly-saved,
/// schema-compatible previous generation (goal plan 07 §5 item 2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigSnapshotMeta {
    pub schema: u32,
    pub operation_id: String,
    pub content_sha256: String,
    /// The schema of the config that was running BEFORE the update.
    pub config_schema: String,
    /// The schema the update declared for its own staged config, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by_schema: Option<String>,
}

fn snapshot_config(
    scope_dir: &Path,
    operation_id: &str,
    config_reference: &str,
    current_schema: &str,
    replacing_schema: Option<&str>,
) -> anyhow::Result<()> {
    let meta_path = scope_dir.join(SNAPSHOT_META_FILE);
    let bytes_path = scope_dir.join(SNAPSHOT_BYTES_FILE);
    if meta_path.exists() || bytes_path.exists() {
        let meta_bytes = filesystem::read_secure_regular_file(
            &meta_path,
            "config snapshot metadata",
            false,
            16 * 1024,
        )?;
        let meta: ConfigSnapshotMeta = serde_json::from_slice(&meta_bytes)?;
        if meta.schema != SNAPSHOT_META_SCHEMA {
            anyhow::bail!("obsolete config snapshot requires explicit cleanup before update");
        }
        if meta.operation_id == operation_id {
            let saved = filesystem::read_secure_regular_file(
                &bytes_path,
                "config snapshot bytes",
                false,
                super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
            )?;
            if sha256_hex(&saved) != meta.content_sha256
                || meta.config_schema != current_schema
                || meta.replaced_by_schema.as_deref() != replacing_schema
            {
                anyhow::bail!("resumed update config snapshot does not match its operation");
            }
            return Ok(());
        }
    }
    let bytes = filesystem::read_secure_regular_file(
        Path::new(config_reference),
        "deployment configuration",
        false,
        super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
    )?;
    filesystem::atomic_write(&bytes_path, &bytes, 0o600)?;
    let meta = ConfigSnapshotMeta {
        schema: SNAPSHOT_META_SCHEMA,
        operation_id: operation_id.to_owned(),
        content_sha256: sha256_hex(&bytes),
        config_schema: current_schema.to_owned(),
        replaced_by_schema: replacing_schema.map(str::to_owned),
    };
    filesystem::atomic_write(&meta_path, &serde_json::to_vec_pretty(&meta)?, 0o600)
}

/// Decide whether the saved snapshot may be restored: explicitly present,
/// byte-integrity intact, and the live config generation still equals the
/// generation the update installed (otherwise the snapshot is stale and the
/// rollback touches references only).
fn read_restorable_snapshot(
    scope_dir: &Path,
    live_schema: &str,
) -> anyhow::Result<Option<(Vec<u8>, String)>> {
    let meta_path = scope_dir.join(SNAPSHOT_META_FILE);
    let bytes_path = scope_dir.join(SNAPSHOT_BYTES_FILE);
    if !meta_path.exists() || !bytes_path.exists() {
        return Ok(None);
    }
    let meta_bytes = filesystem::read_secure_regular_file(
        &meta_path,
        "config snapshot metadata",
        false,
        16 * 1024,
    )?;
    let meta: ConfigSnapshotMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|error| anyhow::anyhow!("config snapshot metadata is invalid: {error}"))?;
    if meta.schema != SNAPSHOT_META_SCHEMA {
        anyhow::bail!(
            "unsupported config snapshot schema {} (expected {SNAPSHOT_META_SCHEMA})",
            meta.schema
        );
    }
    let Some(replaced_by) = meta.replaced_by_schema.as_deref() else {
        return Ok(None);
    };
    if replaced_by != live_schema {
        return Ok(None);
    }
    let bytes = filesystem::read_secure_regular_file(
        &bytes_path,
        "config snapshot bytes",
        false,
        super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
    )?;
    if sha256_hex(&bytes) != meta.content_sha256 {
        anyhow::bail!("config snapshot bytes no longer match their recorded digest");
    }
    Ok(Some((bytes.to_vec(), meta.config_schema)))
}

fn staged_config_change(
    config_reference: &str,
    staged: Option<&StagedConfig>,
) -> Option<(String, String)> {
    staged.map(|staged| (config_reference.to_owned(), staged.schema.clone()))
}

fn stop_writer_for_recovery(job: &UpdateJob<'_>, failure: Failure) -> Failure {
    let stop_status = match runtime_backend::backend(job.runtime_kind).stop(job.runtime_object) {
        Ok(()) => "writer is stopped".to_owned(),
        Err(error) => format!(
            "writer stop failed ({}); do not start the old release",
            sanitize(error.to_string())
        ),
    };
    Failure::new(
        super::deployment_state::ROLLBACK_RECOVERY_REQUIRED,
        format!(
            "{}; the verified Release forbids rollback after its applied migration; {stop_status}; recovery must use `nazoauthctl recover` from a verified backup",
            failure.detail
        ),
    )
}

fn stop_writer_for_unknown_migration(job: &UpdateJob<'_>, failure: Failure) -> Failure {
    let stop_status = match runtime_backend::backend(job.runtime_kind).stop(job.runtime_object) {
        Ok(()) => "writer is stopped".to_owned(),
        Err(error) => format!(
            "writer stop failed ({}); do not start it until the operation is resolved",
            sanitize(error.to_string())
        ),
    };
    Failure::new(
        "CONTROL_OUTCOME_UNKNOWN",
        format!(
            "{}; migration may have been applied, so {stop_status} until the same operation is resumed",
            failure.detail
        ),
    )
}

fn rollback_update(job: &UpdateJob<'_>, performed: &PerformedSteps) -> Result<(), Failure> {
    let mut errors = Vec::new();
    if performed.wrote_config {
        let restore = if performed.snapshotted_config {
            restore_snapshot_bytes(job.scope_dir, job.config_reference)
        } else {
            filesystem::remove_file_durable(Path::new(job.config_reference)).map_err(|error| {
                Failure::new(
                    super::install_exec::CONFIG_INVALID,
                    sanitize(format!(
                        "removing newly staged configuration failed: {error}"
                    )),
                )
            })
        };
        if let Err(error) = restore {
            errors.push(error.detail);
        }
    }
    if performed.replaced_runtime {
        if job.runtime_kind == RuntimeBackendKind::Host {
            if let Err(error) = redeploy_digest(
                job.runtime_kind,
                job.runtime_object,
                job.current_artifact,
                job.runtime_root,
            ) {
                errors.push(format!(
                    "restoring the verified pre-update host artifact failed: {}",
                    error.detail
                ));
            }
        } else {
            match &performed.runtime_before_update {
                Some(replacement) => {
                    let backend = runtime_backend::backend(job.runtime_kind);
                    if let Err(error) = backend.replace(replacement) {
                        errors.push(format!(
                            "restoring the pre-update runtime failed: {}",
                            sanitize(error.to_string())
                        ));
                    } else if performed.runtime_before_update_was_running {
                        if let Err(error) = backend.start(job.runtime_object) {
                            errors.push(format!(
                                "starting the restored pre-update runtime failed: {}",
                                sanitize(error.to_string())
                            ));
                        }
                    } else if let Err(error) = backend.stop(job.runtime_object) {
                        errors.push(format!(
                            "restoring the stopped pre-update runtime state failed: {}",
                            sanitize(error.to_string())
                        ));
                    }
                }
                None => errors.push(
                    "the exact pre-update runtime was not retained before replacement".to_owned(),
                ),
            }
        }
    }
    rollback_result(errors)
}

fn restore_current_after_failed_rollback(
    job: &RollbackJob<'_>,
    performed: &PerformedSteps,
) -> Result<(), Failure> {
    let mut errors = Vec::new();
    if performed.wrote_config {
        match performed.config_before_rollback.as_deref() {
            Some(bytes) => {
                if let Err(error) =
                    filesystem::atomic_write(Path::new(job.config_reference), bytes, 0o600)
                {
                    errors.push(format!(
                        "restoring the pre-rollback configuration failed: {error}"
                    ));
                } else if let Err(error) =
                    grant_runtime_config_read(Path::new(job.config_reference))
                {
                    errors.push(error.detail);
                }
            }
            None => errors.push(
                "pre-rollback configuration bytes were not retained before replacement".to_owned(),
            ),
        }
    }
    if performed.replaced_runtime
        && let Err(error) = redeploy_digest(
            job.runtime_kind,
            job.runtime_object,
            job.current_artifact,
            job.runtime_root,
        )
    {
        errors.push(format!(
            "restoring the current runtime failed: {}",
            error.detail
        ));
    }
    rollback_result(errors)
}

fn restore_snapshot_bytes(scope_dir: &Path, config_reference: &str) -> Result<(), Failure> {
    let bytes_path = scope_dir.join(SNAPSHOT_BYTES_FILE);
    let bytes = filesystem::read_secure_regular_file(
        &bytes_path,
        "config snapshot bytes",
        false,
        super::install_exec::MAX_CONFIG_CONTENT_BYTES as u64,
    )
    .map_err(|error| {
        Failure::new(
            super::install_exec::CONFIG_INVALID,
            sanitize(format!("reading the config snapshot failed: {error}")),
        )
    })?;
    filesystem::atomic_write(Path::new(config_reference), &bytes, 0o600).map_err(|error| {
        Failure::new(
            super::install_exec::CONFIG_INVALID,
            sanitize(format!("restoring the config snapshot failed: {error}")),
        )
    })?;
    grant_runtime_config_read(Path::new(config_reference))
}

fn grant_runtime_config_read(path: &Path) -> Result<(), Failure> {
    let preserve_owner = super::install_exec::path_is_owned_by_non_root(path).map_err(|error| {
        Failure::new(
            super::install_exec::CONFIG_INVALID,
            sanitize(format!(
                "inspecting staged configuration ownership failed: {error}"
            )),
        )
    })?;
    super::install_exec::set_runtime_identity(path, false, preserve_owner)
}

fn rollback_result(errors: Vec<String>) -> Result<(), Failure> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Failure::new(ACTIVATION_FAILED, sanitize(errors.join("; "))))
    }
}

fn redeploy_digest(
    runtime_kind: RuntimeBackendKind,
    runtime_object: &str,
    digest_ref: &str,
    runtime_root: Option<&str>,
) -> Result<(), Failure> {
    let kind = runtime_kind;
    let backend = runtime_backend::backend(kind);
    let observation = live_observation(backend.as_ref(), runtime_object)?;
    let digest = digest_ref.trim_start_matches("sha256:").to_owned();
    let artifact = match kind {
        RuntimeBackendKind::Host => {
            let runtime_root = runtime_root.ok_or_else(|| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    "systemd deployment state has no app-binary directory resource",
                )
            })?;
            runtime_backend::ArtifactReference::HostBinary {
                path: Path::new(runtime_root)
                    .join("artifacts")
                    .join(&digest)
                    .join("nazoauth"),
                sha256: digest,
            }
        }
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
            let image_reference = observation_image_reference(&observation).ok_or_else(|| {
                Failure::new(
                    OBJECT_IDENTITY_MISMATCH,
                    "the runtime object does not report an OCI repository",
                )
            })?;
            runtime_backend::ArtifactReference::Oci {
                image_reference,
                digest: format!("sha256:{digest}"),
            }
        }
    };
    let replacement = replacement_from_observation(&observation, runtime_object, &artifact)?;
    backend
        .replace(&replacement)
        .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
    backend
        .start(runtime_object)
        .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
