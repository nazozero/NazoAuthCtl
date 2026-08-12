use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nazo_operator_protocol::{
    Actor, ActorKind, CanonicalConfigManifest, ConfigBinding, ControllerTrustTransition,
    EmbeddedIdentity, FinalReceipt, ManagementAuditEvent, RuntimeReceipt, RuntimeTargetClaim,
    SecretBinding, TaskEnvelope, TaskOperation, TaskOutcome, TaskResult, TransitionAuthorization,
    canonical_config_sha256, compact_sha256, protected_header, sign_final_receipt,
    sign_management_event, sign_task, sign_trust_transition, verify_final_receipt,
    verify_management_event, verify_runtime_receipt, verify_task_signature,
    verify_trust_transition,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    deployment::{
        DeploymentRecord, DeploymentStore, RuntimeBackendKind, SafeReference, TrustState,
    },
    filesystem::{atomic_write, sha256},
    model::UpdateConfig,
    runtime::Runtime,
};

mod audit;
mod identity;
#[cfg(test)]
use audit::{
    append_audit, audit_head, execute_test_task, load_or_issue_task, operation_name,
    target_expectation, validate_retirement_probe_audit_evidence, validate_runtime_receipt,
};
pub(crate) use audit::{
    append_management_event, append_management_event_idempotent, audit_entries, execute,
    execute_with_io, expected_release_target, load_management_event, show_audit, verify_audit,
    verify_audit_chain,
};
use audit::{
    canonical_manifest, encode_retirement_probe_audit_evidence, verify_target_expectation,
};
use identity::{
    encode_hex, is_real_directory_or_missing, is_regular_non_symlink, path_present,
    read_signing_key, read_single_line, read_verifying_key, safe_identity_component,
    trusted_break_glass_key, trusted_controller_key,
};
#[cfg(test)]
use identity::{
    ensure_only_expected_generation, ensure_static_identity_files, generation_paths,
    identity_layout, new_active_identity, read_active_identity, read_key,
    refuse_ambiguous_legacy_adoption, remove_allowlisted_generation_directory,
    remove_uncommitted_generation, validate_generation, verify_retired_controller_probe_with,
    write_active_identity, write_generation,
};
pub(crate) use identity::{
    identity_recovery_required, initialize_identity_generation,
    recover_controller_without_controller_key, recover_pending_rotation, rehearse_controller_loss,
    report_controller_availability, rotate_controller, trusted_audit_key,
    verify_retired_controller_probe,
};

#[derive(Clone, Debug)]
pub(crate) struct ExpectedReleaseTarget {
    pub(crate) embedded: EmbeddedIdentity,
    pub(crate) image_digest: String,
    pub(crate) binary_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct OperationResult {
    pub(crate) request_id: String,
    pub(crate) result: TaskResult,
    pub(crate) final_receipt: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditHead {
    sequence: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RotationIntent {
    schema: u32,
    #[serde(default)]
    next_generation: String,
    previous_key_id: String,
    next_key_id: String,
    previous_audit_key_id: String,
    next_audit_key_id: String,
    previous_break_glass_key_id: String,
    next_break_glass_key_id: String,
    transition_file: String,
    compact_transition: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(clippy::enum_variant_names)]
pub(crate) enum IdentityRotationPhase {
    GenerationCommitted,
    DeclarationCommitted,
    ActiveCommitted,
    AuditCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityRotationJournal {
    pub(crate) schema: u32,
    pub(crate) request_id: String,
    pub(crate) deployment_id: String,
    pub(crate) break_glass: bool,
    pub(crate) reason: String,
    pub(crate) from_revision: u64,
    pub(crate) previous_record: DeploymentRecord,
    pub(crate) next_record: DeploymentRecord,
    pub(crate) previous: ActiveIdentity,
    pub(crate) previous_controller_public_sha256: String,
    pub(crate) next: ActiveIdentity,
    pub(crate) transition_file: String,
    pub(crate) compact_transition: String,
    pub(crate) retirement_probe: Option<String>,
    pub(crate) phase: IdentityRotationPhase,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyAdoptionIntent {
    schema: u32,
    generation: String,
    controller_key_id: String,
    audit_key_id: String,
    break_glass_key_id: String,
}

/// A generation is immutable before it becomes active.  The one small active
/// record is the only commit point that selects controller, audit and recovery
/// material together; it deliberately contains no secret bytes or paths.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveIdentity {
    schema: u32,
    pub(crate) generation: String,
    pub(crate) controller_key_id: String,
    pub(crate) audit_key_id: String,
    pub(crate) break_glass_key_id: String,
}

#[derive(Clone, Debug)]
struct IdentityLayout {
    operator_directory: PathBuf,
    active_file: PathBuf,
    generations: PathBuf,
    recovery_generations: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct RotationResult {
    pub(crate) previous_controller_key_id: String,
    pub(crate) previous_controller_public_sha256: String,
    retirement_probe: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetirementProbeExecution {
    /// Verified by nazoauthctl and the runtime adapter; the application does
    /// not and cannot attest its containing OCI image digest by itself.
    controller_verified_target: RuntimeTargetClaim,
    application_reported_embedded_identity: EmbeddedIdentity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum RetirementProbeAuditEvidence {
    RuntimeAuthorizationRejected {
        schema: u32,
        previous_controller_key_id: String,
        active_controller_key_id: String,
        probe_sha256: String,
        controller_verified_target: RuntimeTargetClaim,
        application_reported_embedded_identity: EmbeddedIdentity,
    },
    NotIssued {
        schema: u32,
        previous_controller_key_id: String,
        previous_controller_public_sha256: String,
        reason: String,
    },
}

/// The recovery path must remain usable when the active controller private key
/// is genuinely unavailable.  A rehearsal carries a copy only in memory,
/// then makes every subsequent controller signing read fail closed.
enum ControllerSigningAccess {
    Available,
    ForbiddenForRehearsal(Box<SigningKey>),
    Unavailable,
}

impl ControllerSigningAccess {
    fn controller_for_retirement_probe(&self, path: &Path) -> anyhow::Result<Option<SigningKey>> {
        match self {
            Self::Available => Ok(Some(read_signing_key(path)?)),
            Self::ForbiddenForRehearsal(key) => Ok(Some(key.as_ref().clone())),
            Self::Unavailable => Ok(None),
        }
    }

    fn controller_for_normal_rotation(&self, path: &Path) -> anyhow::Result<SigningKey> {
        match self {
            Self::Available => read_signing_key(path),
            Self::ForbiddenForRehearsal(_) | Self::Unavailable => {
                bail!("controller signing access is forbidden for this recovery operation")
            }
        }
    }
}

pub(crate) fn rotate_registered_controller(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    identity::rotate_registered_controller_with_access(
        store,
        record,
        config_path,
        config,
        break_glass,
        reason,
        ControllerSigningAccess::Available,
    )
}

pub(crate) fn rehearse_registered_controller_loss(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    config_path: &Path,
    config: &UpdateConfig,
) -> anyhow::Result<RotationResult> {
    let probe_key = read_signing_key(&config.operator.controller_private_key)?;
    identity::rotate_registered_controller_with_access(
        store,
        record,
        config_path,
        config,
        true,
        "simulated-unavailable",
        ControllerSigningAccess::ForbiddenForRehearsal(Box::new(probe_key)),
    )
}

pub(crate) fn recover_registered_controller_without_controller_key(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    config_path: &Path,
    config: &UpdateConfig,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    identity::rotate_registered_controller_with_access(
        store,
        record,
        config_path,
        config,
        true,
        reason,
        ControllerSigningAccess::Unavailable,
    )
}

pub(crate) fn recover_registered_rotation_locked(
    store: &DeploymentStore,
    config_path: &Path,
    expected_record: &DeploymentRecord,
) -> anyhow::Result<bool> {
    identity::recover_registered_rotation_locked(store, config_path, expected_record)
}

#[cfg(test)]
#[path = "../tests/unit/operator.rs"]
mod tests;
