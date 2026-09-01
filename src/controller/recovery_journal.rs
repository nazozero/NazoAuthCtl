//! One narrow controller-side pointer for the disaster-recovery choreography.
//!
//! TargetJournal remains authoritative for HostOperations and OperationJournal
//! remains authoritative for the signed ControlOperation.  This file records
//! only which authority must be re-read next after a controller crash.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::{file_lock::FileLock, filesystem};

const SCHEMA: u32 = 1;
const FILE_NAME: &str = "recovery-plan.json";
const LOCK_NAME: &str = "recovery-plan.lock";
const MAX_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecoveryPhase {
    Restoring,
    Invalidating,
    WaitingForDeadline,
    CleanupPending,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidatePointer {
    pub object_reference: String,
    pub object_id: String,
    pub loopback_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPlan {
    pub schema: u32,
    pub deployment_id: String,
    pub phase: RecoveryPhase,
    pub source_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_revision: Option<u64>,
    pub manifest_sha256: String,
    pub state_epoch: String,
    pub recover_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_stage_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<CandidatePointer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_control_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_operation_id: Option<String>,
}

pub(crate) struct RecoveryJournal {
    path: PathBuf,
    _lock: FileLock,
}

impl RecoveryJournal {
    pub(crate) fn open(instance_dir: &Path) -> anyhow::Result<Self> {
        filesystem::ensure_private_directory(instance_dir, "controller recovery directory")?;
        Ok(Self {
            path: instance_dir.join(FILE_NAME),
            _lock: FileLock::acquire(&instance_dir.join(LOCK_NAME))?,
        })
    }

    pub(crate) fn load(&self) -> anyhow::Result<Option<RecoveryPlan>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = filesystem::read_secure_regular_file(
            &self.path,
            "controller recovery journal",
            true,
            MAX_BYTES,
        )?;
        let plan: RecoveryPlan = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a valid recovery plan", self.path.display()))?;
        validate(&plan)?;
        Ok(Some(plan))
    }

    pub(crate) fn store(&self, plan: &RecoveryPlan) -> anyhow::Result<()> {
        validate(plan)?;
        let bytes = serde_json::to_vec_pretty(plan)?;
        filesystem::atomic_write(&self.path, &bytes, 0o600)
    }

    pub(crate) fn clear(&self) -> anyhow::Result<()> {
        if self.path.exists() {
            filesystem::remove_file_durable(&self.path)?;
        }
        Ok(())
    }
}

fn validate(plan: &RecoveryPlan) -> anyhow::Result<()> {
    if plan.schema != SCHEMA || plan.deployment_id.is_empty() || plan.manifest_sha256.len() != 64 {
        bail!("controller recovery journal has an invalid identity binding");
    }
    for id in [
        Some(plan.recover_operation_id.as_str()),
        plan.candidate_stage_operation_id.as_deref(),
        plan.invalidation_operation_id.as_deref(),
        plan.candidate_control_operation_id.as_deref(),
        plan.activate_operation_id.as_deref(),
        plan.cleanup_operation_id.as_deref(),
        Some(plan.state_epoch.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if !uuid::Uuid::parse_str(id).is_ok_and(|value| value.get_version_num() == 7) {
            bail!("controller recovery journal has a non-UUIDv7 operation binding");
        }
    }
    if plan
        .invalidation_request_hash
        .as_deref()
        .is_some_and(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        bail!("controller recovery journal has an invalid request hash");
    }
    if let Some(candidate) = &plan.candidate
        && (candidate.object_reference.is_empty()
            || candidate.object_id.is_empty()
            || candidate.loopback_port == 0)
    {
        bail!("controller recovery journal has an invalid candidate pointer");
    }
    match plan.phase {
        RecoveryPhase::Restoring => {}
        RecoveryPhase::Invalidating
        | RecoveryPhase::WaitingForDeadline
        | RecoveryPhase::CleanupPending => {
            if plan.restored_revision.is_none()
                || plan.candidate_stage_operation_id.is_none()
                || plan.candidate.is_none()
            {
                bail!("controller recovery journal phase lacks restored candidate bindings");
            }
        }
    }
    if matches!(
        plan.phase,
        RecoveryPhase::WaitingForDeadline | RecoveryPhase::CleanupPending
    ) && (plan.invalidation_operation_id.is_none()
        || plan.invalidation_request_hash.is_none()
        || plan.not_before.is_none())
    {
        bail!("controller recovery journal phase lacks invalidation bindings");
    }
    Ok(())
}

pub(crate) fn new_plan(
    deployment_id: String,
    source_revision: u64,
    manifest_sha256: String,
) -> RecoveryPlan {
    RecoveryPlan {
        schema: SCHEMA,
        deployment_id,
        phase: RecoveryPhase::Restoring,
        source_revision,
        restored_revision: None,
        manifest_sha256,
        state_epoch: uuid::Uuid::now_v7().to_string(),
        recover_operation_id: uuid::Uuid::now_v7().to_string(),
        candidate_stage_operation_id: None,
        candidate: None,
        invalidation_operation_id: None,
        invalidation_request_hash: None,
        candidate_control_operation_id: None,
        not_before: None,
        activate_operation_id: None,
        cleanup_operation_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged_plan() -> RecoveryPlan {
        let mut plan = new_plan("deployment-a".to_owned(), 4, "a".repeat(64));
        plan.restored_revision = Some(5);
        plan.candidate_stage_operation_id = Some(uuid::Uuid::now_v7().to_string());
        plan.candidate = Some(CandidatePointer {
            object_reference: "oci://candidate@sha256:abc".to_owned(),
            object_id: "immutable-candidate-id".to_owned(),
            loopback_port: 48123,
        });
        plan.phase = RecoveryPhase::Invalidating;
        plan
    }

    #[test]
    fn ceremony_checkpoint_continues_under_the_original_journal_lock() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("recovery-journal")?;
        let journal = RecoveryJournal::open(temp.path())?;
        let mut plan = staged_plan();
        plan.invalidation_operation_id = Some(uuid::Uuid::now_v7().to_string());
        plan.invalidation_request_hash = Some("b".repeat(64));
        journal.store(&plan)?;

        // This is the exact durable checkpoint written after the old key's
        // admission rejection but before the Recovery Secret ceremony.  The
        // same open journal stays usable afterwards: the orchestration does
        // not recursively open (and deadlock on) a second journal lock.
        plan.invalidation_operation_id = None;
        plan.invalidation_request_hash = None;
        journal.store(&plan)?;
        let resumed = journal.load()?.expect("stored plan");
        assert_eq!(resumed.phase, RecoveryPhase::Invalidating);
        assert!(resumed.invalidation_operation_id.is_none());
        assert!(resumed.invalidation_request_hash.is_none());
        assert_eq!(resumed.candidate, plan.candidate);
        Ok(())
    }
}
