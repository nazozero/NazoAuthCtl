//! Durable controller pointer for one off-host backup transfer.
//!
//! Target journals remain authoritative for every remote operation. This
//! record binds the two target identities, the immutable source plan, and the
//! next operation that the controller must replay after a crash.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::{
    file_lock::FileLock,
    filesystem,
    target::{backup::OffHostCopyReceipt, backup_exec::BackupTransferPlan},
};

const SCHEMA: u32 = 1;
const FILE_NAME: &str = "backup-transfer.json";
const LOCK_NAME: &str = "backup-transfer.lock";
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TransferPhase {
    SourcePrepare,
    DestinationPrepare,
    Copying,
    Finalize,
    RecordSourceReceipt,
    CleanupSource,
    CleanupDestination,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CopyCursor {
    pub file_index: usize,
    pub offset: u64,
    pub read_operation_id: String,
    pub write_operation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferRecord {
    pub schema: u32,
    pub deployment_id: String,
    pub source_host_id: String,
    pub destination_host_id: String,
    pub destination_alias: String,
    pub transfer_operation_id: String,
    pub phase: TransferPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_plan: Option<BackupTransferPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<CopyCursor>,
    pub finalize_operation_id: String,
    pub source_receipt_operation_id: String,
    pub source_cleanup_operation_id: String,
    pub destination_cleanup_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<OffHostCopyReceipt>,
}

impl TransferRecord {
    pub(crate) fn new(
        deployment_id: String,
        source_host_id: String,
        destination_host_id: String,
        destination_alias: String,
    ) -> Self {
        Self {
            schema: SCHEMA,
            deployment_id,
            source_host_id,
            destination_host_id,
            destination_alias,
            transfer_operation_id: new_operation_id(),
            phase: TransferPhase::SourcePrepare,
            source_plan: None,
            cursor: None,
            finalize_operation_id: new_operation_id(),
            source_receipt_operation_id: new_operation_id(),
            source_cleanup_operation_id: new_operation_id(),
            destination_cleanup_operation_id: new_operation_id(),
            receipt: None,
        }
    }

    pub(crate) fn reset_cursor(&mut self, file_index: usize, offset: u64) {
        self.cursor = Some(CopyCursor {
            file_index,
            offset,
            read_operation_id: new_operation_id(),
            write_operation_id: new_operation_id(),
        });
    }
}

pub(crate) struct TransferJournal {
    path: PathBuf,
    _lock: FileLock,
}

impl TransferJournal {
    pub(crate) fn open(instance_dir: &Path) -> anyhow::Result<Self> {
        filesystem::ensure_private_directory(instance_dir, "controller instance directory")?;
        Ok(Self {
            path: instance_dir.join(FILE_NAME),
            _lock: FileLock::acquire(&instance_dir.join(LOCK_NAME))?,
        })
    }

    pub(crate) fn load(&self) -> anyhow::Result<Option<TransferRecord>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = filesystem::read_secure_regular_file(
            &self.path,
            "controller backup transfer journal",
            true,
            MAX_BYTES,
        )?;
        let record: TransferRecord = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "{} is not a valid backup transfer record; preserve it and repair or remove it only after verifying both target staging areas",
                self.path.display()
            )
        })?;
        validate(&record)?;
        Ok(Some(record))
    }

    pub(crate) fn store(&self, record: &TransferRecord) -> anyhow::Result<()> {
        validate(record)?;
        let bytes = serde_json::to_vec_pretty(record)?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!("controller backup transfer record exceeds its bounded size");
        }
        filesystem::atomic_write(&self.path, &bytes, 0o600)
    }

    pub(crate) fn clear(&self) -> anyhow::Result<()> {
        if self.path.exists() {
            filesystem::remove_file_durable(&self.path)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn exists(&self) -> bool {
        self.path.exists()
    }
}

fn new_operation_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn valid_uuid_v7(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate(record: &TransferRecord) -> anyhow::Result<()> {
    if record.schema != SCHEMA {
        bail!("controller backup transfer journal has an unsupported schema");
    }
    crate::registry::validate_identifier(
        &record.deployment_id,
        128,
        "backup transfer deployment id",
    )?;
    crate::registry::validate_identifier(
        &record.source_host_id,
        128,
        "backup transfer source host id",
    )?;
    crate::registry::validate_identifier(
        &record.destination_host_id,
        128,
        "backup transfer destination host id",
    )?;
    crate::registry::validate_identifier(
        &record.destination_alias,
        128,
        "backup destination host alias",
    )?;
    if record.source_host_id == record.destination_host_id {
        bail!("controller backup transfer journal binds the same source and destination host");
    }
    for id in [
        record.transfer_operation_id.as_str(),
        record.finalize_operation_id.as_str(),
        record.source_receipt_operation_id.as_str(),
        record.source_cleanup_operation_id.as_str(),
        record.destination_cleanup_operation_id.as_str(),
    ] {
        if !valid_uuid_v7(id) {
            bail!("controller backup transfer journal has a non-UUIDv7 operation binding");
        }
    }
    if let Some(plan) = &record.source_plan
        && (plan.operation_id != record.transfer_operation_id
            || plan.deployment_id != record.deployment_id
            || !valid_sha256(&plan.manifest_sha256)
            || plan.files.is_empty())
    {
        bail!("controller backup transfer journal has an invalid immutable source plan");
    }
    if let Some(cursor) = &record.cursor {
        if !valid_uuid_v7(&cursor.read_operation_id) || !valid_uuid_v7(&cursor.write_operation_id) {
            bail!("controller backup transfer journal has an invalid copy cursor");
        }
        let plan = record
            .source_plan
            .as_ref()
            .context("controller backup transfer cursor has no source plan")?;
        if cursor.file_index >= plan.files.len()
            || cursor.offset >= plan.files[cursor.file_index].size
        {
            bail!("controller backup transfer journal has an out-of-range copy cursor");
        }
    }
    match record.phase {
        TransferPhase::SourcePrepare => {
            if record.source_plan.is_some() || record.cursor.is_some() || record.receipt.is_some() {
                bail!("controller backup transfer source-prepare phase has later-phase state");
            }
        }
        TransferPhase::DestinationPrepare => {
            if record.source_plan.is_none() || record.cursor.is_some() || record.receipt.is_some() {
                bail!("controller backup transfer destination-prepare phase is incomplete");
            }
        }
        TransferPhase::Copying => {
            if record.source_plan.is_none() || record.cursor.is_none() || record.receipt.is_some() {
                bail!("controller backup transfer copying phase is incomplete");
            }
        }
        TransferPhase::Finalize => {
            if record.source_plan.is_none() || record.cursor.is_some() || record.receipt.is_some() {
                bail!("controller backup transfer finalize phase is inconsistent");
            }
        }
        TransferPhase::RecordSourceReceipt
        | TransferPhase::CleanupSource
        | TransferPhase::CleanupDestination => {
            if record.source_plan.is_none() || record.cursor.is_some() || record.receipt.is_none() {
                bail!("controller backup transfer terminal phase lacks its receipt");
            }
        }
    }
    Ok(())
}
