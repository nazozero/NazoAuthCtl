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
    OfficialArtifactRef, StagedConfig, cache_systemd_artifact, probe_local_health,
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
    /// Runtime class token from the live DeploymentState surface.
    pub runtime_kind: RuntimeBackendKind,
    pub runtime_object: &'a str,
    /// Absolute config path recorded in the DeploymentState.
    pub config_reference: &'a str,
    /// The published loopback port for local health probes.
    pub port: u16,
    pub data_root: &'a str,
    /// Managed systemd binary root. Container deployments do not have one.
    pub runtime_root: Option<&'a str>,
    /// The deployment's current config schema token (pre-update).
    pub config_schema: &'a str,
    /// The deployment's recorded current artifact reference (`sha256:<hex>`).
    pub current_artifact: &'a str,
    /// P1-11 anti-downgrade floor: the version embedded in the current
    /// build identity, when the target recorded one.
    pub current_version: Option<&'a str>,
    pub expected_revision: u64,
    pub artifact: &'a OfficialArtifactRef,
    pub rollback_policy: &'a crate::model::ReleaseRollbackPolicy,
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
    /// The verified artifact's embedded build identity, committed alongside
    /// the new current reference (G03 envelope binding source).
    pub build_identity: Option<super::deployment_state::BuildIdentity>,
    pub migration_result: Option<nazo_operator_protocol::ControlResult>,
}

/// The one host-journaled Update order either activates after a successful
/// MigrateApply, or reports that exact durable migration failure after rolling
/// back all provisional host changes.  It never turns a business failure into
/// an untyped host error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UpdateExecution {
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
}

/// Production executor backed by the real adapters.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostLifecycleExecutor;

impl LifecycleExecutor for HostLifecycleExecutor {
    fn execute_update(&self, job: &UpdateJob<'_>) -> Result<UpdateExecution, Failure> {
        let mut performed = PerformedSteps::default();
        match self.run_update(job, &mut performed) {
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
                    && !job
                        .rollback_policy
                        .artifact_rollback_allowed_after_migration() =>
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

        // 0. Live identity hook: the running object must serve exactly the
        // artifact the DeploymentState records, or nothing proceeds.
        let observation = live_observation(backend.as_ref(), job.runtime_object)?;
        require_observation_serves(&observation, job.current_artifact)?;

        // 1. Verify + pull the pinned official artifact (download-on-target;
        // re-running verify/pull is idempotent for interrupted resumes).
        // P1-11: the recorded current version is the signed anti-downgrade
        // floor — a verified-but-older Release is rejected before download.
        let verified = verify_pinned_artifact_facts(
            job.artifact,
            kind,
            job.current_version,
            job.runtime_root,
        )?;
        if verified.rollback_policy != *job.rollback_policy {
            return Err(Failure::new(
                super::install_exec::ARTIFACT_UNVERIFIED,
                "update rollback policy does not match the verified target Release",
            ));
        }
        let new_digest = verified.digest.clone();
        // Build and validate the executable replacement before any migration
        // can mutate external state. Activation consumes this exact plan.
        let replacement = (observation_digest(&observation).as_deref()
            != Some(new_digest.as_str()))
        .then(|| {
            replacement_from_observation(
                &observation,
                job.runtime_object,
                &verified.runtime_artifact,
            )
        })
        .transpose()?;

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
            let service_user = host.then(|| systemd_service_user(job.deployment_id));
            let mut environment = BTreeMap::new();
            let mut read_only_paths = Vec::new();
            let mut read_write_paths = Vec::new();
            super::inject_operator_oci_artifact_fence(&mut environment, &verified.runtime_artifact);
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
            }
            let task = runtime_backend::OneShotTask {
                artifact: verified.runtime_artifact.clone(),
                command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
                network: observation.networks.first().cloned(),
                mounts: observation.mounts.clone(),
                environment,
                working_directory: kind
                    .is_container()
                    .then(|| std::path::PathBuf::from("/app")),
                service_user: if host {
                    service_user
                } else {
                    Some(crate::runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned())
                },
                transient_credentials: BTreeMap::new(),
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
                        job.rollback_policy,
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
            backend
                .replace(&replacement)
                .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
            backend
                .start(job.runtime_object)
                .map_err(|error| Failure::new(ACTIVATION_FAILED, sanitize(error.to_string())))?;
            performed.replaced_runtime = true;
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
        probe_local_health(job.port)?;

        // 7. Commit: previous <- old current, current <- new (+ its build
        // identity), optional config CAS advance — replay-safe under this
        // operation id.
        let state = job.store.apply_update(
            job.deployment_id,
            job.expected_revision,
            super::deployment_state::UpdateCommit {
                artifact: format!("sha256:{new_digest}"),
                build_identity: verified.build_identity.clone(),
                rollback_policy: job.rollback_policy.clone(),
                config: staged_config_change(job.config_reference, job.config),
                operation_id: job.operation_id.to_owned(),
            },
        )?;
        job.store.record_local_health(
            job.deployment_id,
            true,
            "local readiness probe passed after update".to_owned(),
            job.operation_id,
        )?;
        Ok(UpdateExecution::Activated(LifecycleFacts {
            revision: state.config.revision,
            build_identity: verified.build_identity,
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
        probe_local_health(job.port)?;

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
            performed.wrote_config = true;
        }

        // 6. Commit the reference swap (current <-> previous) under CAS; a
        // restored snapshot advances the config CAS under its own schema.
        let config_change = restored_config
            .as_ref()
            .map(|(_, schema)| (job.config_reference.to_owned(), schema.clone()));
        let state = job.store.apply_rollback(
            job.deployment_id,
            job.expected_revision,
            config_change,
            job.operation_id,
        )?;
        job.store.record_local_health(
            job.deployment_id,
            true,
            "local readiness probe passed after rollback".to_owned(),
            job.operation_id,
        )?;
        Ok(LifecycleFacts {
            revision: state.config.revision,
            build_identity: None,
            migration_result: None,
        })
    }
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
}

pub(super) fn systemd_service_user(deployment_id: &str) -> String {
    format!(
        "nazoauth-{}",
        deployment_id
            .trim_start_matches("deploy-")
            .chars()
            .take(12)
            .collect::<String>()
    )
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
fn observation_digest(observation: &runtime_backend::RuntimeObservation) -> Option<String> {
    match &observation.artifact {
        runtime_backend::ArtifactReference::Oci { digest, .. } => {
            Some(digest.trim_start_matches("sha256:").to_owned())
        }
        runtime_backend::ArtifactReference::HostBinary { sha256, .. } => Some(sha256.clone()),
        runtime_backend::ArtifactReference::Unknown => None,
    }
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

fn verify_pinned_artifact_facts(
    artifact: &OfficialArtifactRef,
    kind: RuntimeBackendKind,
    version_floor: Option<&str>,
    runtime_root: Option<&str>,
) -> Result<VerifiedArtifactFacts, Failure> {
    let release = VerifiedRelease::verify(ReleaseRequest {
        repository: &artifact.repository,
        requested_version: artifact.version.as_deref(),
        container_backend: kind.is_container().then_some(kind),
        trusted_version_floor: version_floor,
    })
    .map_err(|error| {
        Failure::new(
            super::install_exec::ARTIFACT_UNVERIFIED,
            sanitize(error.to_string()),
        )
    })?;
    let (digest, pin_subject, runtime_artifact) = match kind {
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
                digest.clone(),
                runtime_backend::ArtifactReference::HostBinary {
                    path: cached,
                    sha256: digest,
                },
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
            (
                digest.clone(),
                release
                    .manifest
                    .image_oci_digest()
                    .trim_start_matches("sha256:")
                    .to_owned(),
                runtime_backend::ArtifactReference::Oci {
                    image_reference: release.manifest.oci.repository.clone(),
                    digest: format!("sha256:{digest}"),
                },
            )
        }
    };
    if let Some(expected) = &artifact.expected_subject_sha256
        && *expected != pin_subject
    {
        return Err(Failure::new(
            super::install_exec::ARTIFACT_UNVERIFIED,
            "verified subject digest differs from the requested pin",
        ));
    }
    Ok(VerifiedArtifactFacts {
        digest,
        runtime_artifact,
        rollback_policy: release.rollback_policy(),
        build_identity: Some(
            super::deployment_state::BuildIdentity::new(
                super::deployment_state::BUILD_IDENTITY_PRODUCT,
                &release.manifest.version,
                &release.manifest.backend_commit,
            )
            .map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })?,
        ),
    })
}

/// The verified facts an update needs from its pinned artifact: the OCI
/// subject digest and the embedded build identity.
struct VerifiedArtifactFacts {
    digest: String,
    runtime_artifact: runtime_backend::ArtifactReference,
    build_identity: Option<super::deployment_state::BuildIdentity>,
    rollback_policy: crate::model::ReleaseRollbackPolicy,
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
    Ok(runtime_backend::RuntimeReplacement {
        object_reference: object.to_owned(),
        artifact: artifact.clone(),
        local_artifact_id: observation.local_artifact_id.clone(),
        command,
        mounts: observation.mounts.clone(),
        environment: observation.safe_environment.clone(),
        networks: observation.networks.clone(),
        ip_address: None,
        ports: observation.ports.clone(),
        labels: observation.labels.clone(),
        container_policy,
    })
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
    if (performed.replaced_runtime || performed.wrote_config)
        && let Err(error) = redeploy_digest(
            job.runtime_kind,
            job.runtime_object,
            job.current_artifact,
            job.runtime_root,
        )
    {
        errors.push(format!(
            "restoring the pre-update runtime failed: {}",
            error.detail
        ));
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
    })
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
