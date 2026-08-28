use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::{file_lock::FileLock, filesystem};

const JOURNAL_SCHEMA: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedInstallPlan {
    schema: u32,
    pub(super) request_hash: String,
    pub(super) host_id: String,
    pub(super) deployment_id: String,
    pub(super) operation_id: String,
    pub(super) state_epoch: String,
    pub(super) runtime_kind: String,
    pub(super) target_os: String,
}

impl PreparedInstallPlan {
    pub(super) fn new(
        request_hash: String,
        host_id: String,
        deployment_id: String,
        operation_id: String,
        state_epoch: String,
        runtime_kind: String,
        target_os: String,
    ) -> Self {
        Self {
            schema: JOURNAL_SCHEMA,
            request_hash,
            host_id,
            deployment_id,
            operation_id,
            state_epoch,
            runtime_kind,
            target_os,
        }
    }

    fn validate(&self, expected_request_hash: &str) -> anyhow::Result<()> {
        if self.schema != JOURNAL_SCHEMA {
            bail!("prepared install journal has an unsupported schema");
        }
        if self.request_hash != expected_request_hash {
            bail!("prepared install journal request hash does not match its file identity");
        }
        if self.host_id.is_empty()
            || self.deployment_id.is_empty()
            || self.operation_id.is_empty()
            || self.state_epoch.is_empty()
            || self.runtime_kind.is_empty()
            || self.target_os.is_empty()
        {
            bail!("prepared install journal is incomplete");
        }
        let operation_id = uuid::Uuid::parse_str(&self.operation_id)
            .context("prepared install operation id is not a UUID")?;
        if operation_id.get_version_num() != 7 {
            bail!("prepared install operation id is not UUIDv7");
        }
        let deployment_suffix = self
            .deployment_id
            .strip_prefix("deploy-")
            .context("prepared install deployment id is invalid")?;
        if deployment_suffix.len() != 32
            || !deployment_suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("prepared install deployment id is invalid");
        }
        let epoch = uuid::Uuid::parse_str(&self.state_epoch)
            .context("prepared install state epoch is not a UUID")?;
        if epoch.get_version_num() != 7 {
            bail!("prepared install state epoch is not UUIDv7");
        }
        Ok(())
    }
}

/// One exclusive lease for one exact clean-install request. The journal is a
/// control-side resume pointer only; the target operation journal and
/// DeploymentState remain authoritative for execution and committed state.
pub(super) struct PreparedInstallLease {
    path: PathBuf,
    _lock: FileLock,
}

impl PreparedInstallLease {
    pub(super) fn acquire(registry_root: &Path, request_hash: &str) -> anyhow::Result<Self> {
        if request_hash.len() != 64
            || !request_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("prepared install request hash is invalid");
        }
        let directory = registry_root.join("prepared-installs");
        filesystem::ensure_private_directory(&directory, "prepared install journal directory")?;
        // One stable lock avoids leaving one lock inode per completed install
        // and makes load/create/clear atomic across all clean-install plans.
        let lock = FileLock::acquire(&directory.join("install.lock"))?;
        Ok(Self {
            path: directory.join(format!("{request_hash}.json")),
            _lock: lock,
        })
    }

    pub(super) fn load(&self, request_hash: &str) -> anyhow::Result<Option<PreparedInstallPlan>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = filesystem::read_secure_regular_file(
            &self.path,
            "prepared install journal",
            true,
            MAX_JOURNAL_BYTES,
        )?;
        let plan: PreparedInstallPlan = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow!(
                "{}: prepared install journal is invalid JSON ({}): {error}",
                crate::error_codes::STATE_RESET_REQUIRED,
                self.path.display()
            )
        })?;
        plan.validate(request_hash).map_err(|error| {
            anyhow!(
                "{}: prepared install journal does not conform ({}): {error}",
                crate::error_codes::STATE_RESET_REQUIRED,
                self.path.display()
            )
        })?;
        Ok(Some(plan))
    }

    pub(super) fn persist(&self, plan: &PreparedInstallPlan) -> anyhow::Result<()> {
        plan.validate(&plan.request_hash)?;
        let bytes = serde_json::to_vec_pretty(plan)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            bail!("prepared install journal exceeds its size limit");
        }
        filesystem::atomic_write(&self.path, &bytes, 0o600)
            .context("failed to persist prepared install journal")
    }

    pub(super) fn clear(self) -> anyhow::Result<()> {
        if self.path.exists() {
            filesystem::remove_file_durable(&self.path)
                .context("failed to clear completed prepared install journal")?;
        }
        Ok(())
    }
}
