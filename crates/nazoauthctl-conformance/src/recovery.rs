use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

const RECOVERY_JOURNAL_SCHEMA: u32 = 1;
const MAX_RECOVERY_JOURNAL_BYTES: usize = 128 * 1024;
const MAX_PENDING_RUNS: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceRecoveryBinding {
    pub deployment_id: String,
    pub target_issuer: String,
    pub deployment_revision: String,
    pub request_jti: String,
    pub matrix_sha256: String,
    pub bundle_sha256: String,
    pub prepared_at: i64,
    pub requested_expires_at: i64,
    pub proxy: Option<ConformanceProxyRecovery>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceProxyRecovery {
    pub bundle_path: PathBuf,
    pub reload_executable: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryJournal {
    schema: u32,
    binding: ConformanceRecoveryBinding,
    lease_id: Option<String>,
    lease_expires_at: Option<i64>,
    lease_cleanup_complete: bool,
    proxy_cleanup_complete: bool,
}

pub struct ConformanceRecoveryStore {
    root: PathBuf,
    deployment_id: String,
}

pub struct ConformanceRecoveryGuard {
    store: ConformanceRecoveryStore,
    journal: RecoveryJournal,
    journal_path: PathBuf,
    lock_path: PathBuf,
    lock: Option<File>,
}

impl ConformanceRecoveryStore {
    pub fn open(root: &Path, deployment_id: &str) -> anyhow::Result<Self> {
        validate_component(deployment_id, "deployment ID")?;
        let root = crate::secure_file::ensure_directory(root, true)
            .map_err(|error| anyhow::anyhow!("invalid recovery directory: {error:?}"))?;
        Ok(Self {
            root,
            deployment_id: deployment_id.to_owned(),
        })
    }

    pub fn begin(
        &self,
        binding: ConformanceRecoveryBinding,
    ) -> anyhow::Result<ConformanceRecoveryGuard> {
        validate_binding(&binding, &self.deployment_id)?;
        let (journal_path, lock_path) = self.paths(&binding.request_jti);
        let lock = crate::secure_file::open_lock_file(&lock_path, true)
            .map_err(|error| anyhow::anyhow!("failed to open recovery lock: {error:?}"))?;
        lock.try_lock_exclusive()
            .context("another controller owns this conformance recovery transaction")?;
        match crate::secure_file::read_bounded(&journal_path, 1, true) {
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Ok(_) | Err(crate::secure_file::SecureFileError::Oversize) => {
                bail!("conformance recovery transaction already exists")
            }
            Err(error) => bail!("failed to inspect conformance recovery journal: {error:?}"),
        }
        let journal = RecoveryJournal {
            schema: RECOVERY_JOURNAL_SCHEMA,
            proxy_cleanup_complete: binding.proxy.is_none(),
            binding,
            lease_id: None,
            lease_expires_at: None,
            lease_cleanup_complete: false,
        };
        write_journal(&journal_path, &journal)?;
        Ok(ConformanceRecoveryGuard {
            store: self.clone(),
            journal,
            journal_path,
            lock_path,
            lock: Some(lock),
        })
    }

    pub fn claim_pending(&self) -> anyhow::Result<Vec<ConformanceRecoveryGuard>> {
        let mut entries = fs::read_dir(&self.root)
            .with_context(|| format!("failed to list {}", self.root.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        let journal_names = entries
            .into_iter()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                (name.starts_with("run-") && name.ends_with(".json")).then_some(name)
            })
            .collect::<Vec<_>>();
        if journal_names.len() > MAX_PENDING_RUNS {
            bail!("conformance recovery journal count exceeds policy");
        }
        let mut pending = Vec::new();
        for name in journal_names {
            let request_jti = name
                .strip_prefix("run-")
                .and_then(|name| name.strip_suffix(".json"))
                .context("invalid conformance recovery journal name")?;
            validate_component(request_jti, "request JTI")?;
            let (journal_path, lock_path) = self.paths(request_jti);
            let lock = crate::secure_file::open_lock_file(&lock_path, true)
                .map_err(|error| anyhow::anyhow!("failed to open recovery lock: {error:?}"))?;
            match lock.try_lock_exclusive() {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error).context("failed to claim recovery lock"),
            }
            let bytes = crate::secure_file::read_bounded(
                &journal_path,
                MAX_RECOVERY_JOURNAL_BYTES,
                true,
            )
            .map_err(|error| anyhow::anyhow!("failed to read recovery journal: {error:?}"))?;
            let journal: RecoveryJournal =
                serde_json::from_slice(&bytes).context("recovery journal is invalid")?;
            validate_journal(&journal, &self.deployment_id, request_jti)?;
            pending.push(ConformanceRecoveryGuard {
                store: self.clone(),
                journal,
                journal_path,
                lock_path,
                lock: Some(lock),
            });
        }
        Ok(pending)
    }

    fn paths(&self, request_jti: &str) -> (PathBuf, PathBuf) {
        (
            self.root.join(format!("run-{request_jti}.json")),
            self.root.join(format!("run-{request_jti}.lock")),
        )
    }
}

impl Clone for ConformanceRecoveryStore {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            deployment_id: self.deployment_id.clone(),
        }
    }
}

impl ConformanceRecoveryGuard {
    pub fn binding(&self) -> &ConformanceRecoveryBinding {
        &self.journal.binding
    }

    pub fn lease_id(&self) -> Option<&str> {
        self.journal.lease_id.as_deref()
    }

    pub fn lease_cleanup_complete(&self) -> bool {
        self.journal.lease_cleanup_complete
    }

    pub fn proxy_cleanup_complete(&self) -> bool {
        self.journal.proxy_cleanup_complete
    }

    pub fn record_lease(&mut self, lease_id: &str, expires_at: i64) -> anyhow::Result<()> {
        validate_component(lease_id, "lease ID")?;
        if expires_at <= self.journal.binding.prepared_at
            || expires_at > self.journal.binding.requested_expires_at
        {
            bail!("lease expiry is outside the recovery binding");
        }
        if self
            .journal
            .lease_id
            .as_deref()
            .is_some_and(|existing| existing != lease_id)
        {
            bail!("recovery journal is already bound to a different lease");
        }
        self.journal.lease_id = Some(lease_id.to_owned());
        self.journal.lease_expires_at = Some(expires_at);
        self.persist()
    }

    pub fn mark_lease_cleanup_complete(&mut self) -> anyhow::Result<()> {
        self.journal.lease_cleanup_complete = true;
        self.persist()
    }

    pub fn mark_proxy_cleanup_complete(&mut self) -> anyhow::Result<()> {
        self.journal.proxy_cleanup_complete = true;
        self.persist()
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        if !self.journal.lease_cleanup_complete || !self.journal.proxy_cleanup_complete {
            bail!("conformance recovery obligations are incomplete");
        }
        crate::secure_file::remove_file(&self.journal_path, true)
            .map_err(|error| anyhow::anyhow!("failed to remove recovery journal: {error:?}"))?;
        if let Some(lock) = self.lock.take() {
            fs2::FileExt::unlock(&lock).context("failed to unlock recovery transaction")?;
            drop(lock);
        }
        crate::secure_file::remove_file(&self.lock_path, true)
            .map_err(|error| anyhow::anyhow!("failed to remove recovery lock: {error:?}"))?;
        Ok(())
    }

    fn persist(&self) -> anyhow::Result<()> {
        validate_journal(
            &self.journal,
            &self.store.deployment_id,
            &self.journal.binding.request_jti,
        )?;
        write_journal(&self.journal_path, &self.journal)
    }
}

fn write_journal(path: &Path, journal: &RecoveryJournal) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() > MAX_RECOVERY_JOURNAL_BYTES {
        bail!("conformance recovery journal exceeds policy");
    }
    crate::secure_file::write_atomic(path, &bytes, true)
        .map_err(|error| anyhow::anyhow!("failed to persist recovery journal: {error:?}"))
}

fn validate_journal(
    journal: &RecoveryJournal,
    deployment_id: &str,
    request_jti: &str,
) -> anyhow::Result<()> {
    if journal.schema != RECOVERY_JOURNAL_SCHEMA
        || journal.binding.request_jti != request_jti
        || journal.lease_id.is_some() != journal.lease_expires_at.is_some()
        || (journal.lease_cleanup_complete && journal.lease_id.is_none())
    {
        bail!("conformance recovery journal state is invalid");
    }
    validate_binding(&journal.binding, deployment_id)
}

fn validate_binding(
    binding: &ConformanceRecoveryBinding,
    deployment_id: &str,
) -> anyhow::Result<()> {
    validate_component(&binding.deployment_id, "deployment ID")?;
    validate_component(&binding.request_jti, "request JTI")?;
    if binding.deployment_id != deployment_id
        || !lower_hex(&binding.deployment_revision, 40)
        || !lower_hex(&binding.matrix_sha256, 64)
        || !lower_hex(&binding.bundle_sha256, 64)
        || binding.prepared_at <= 0
        || binding.requested_expires_at <= binding.prepared_at
    {
        bail!("conformance recovery binding is invalid");
    }
    let target = url::Url::parse(&binding.target_issuer)
        .context("conformance recovery target issuer is invalid")?;
    if target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
    {
        bail!("conformance recovery target issuer is invalid");
    }
    if let Some(proxy) = &binding.proxy
        && (!proxy.bundle_path.is_absolute() || !proxy.reload_executable.is_absolute())
    {
        bail!("conformance proxy recovery paths must be absolute");
    }
    Ok(())
}

fn validate_component(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ConformanceRecoveryBinding {
        ConformanceRecoveryBinding {
            deployment_id: "deployment-a".to_owned(),
            target_issuer: "https://issuer.example".to_owned(),
            deployment_revision: "a".repeat(40),
            request_jti: "request-0123456789abcdef0123456789abcdef".to_owned(),
            matrix_sha256: "b".repeat(64),
            bundle_sha256: "c".repeat(64),
            prepared_at: 1_700_000_000,
            requested_expires_at: 1_700_014_700,
            proxy: None,
        }
    }

    #[test]
    fn recovery_binding_rejects_path_components_and_cross_deployment_state() {
        let mut invalid = binding();
        invalid.request_jti = "../escape".to_owned();
        assert!(validate_binding(&invalid, "deployment-a").is_err());
        assert!(validate_binding(&binding(), "deployment-b").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn active_run_lock_is_skipped_and_crashed_journal_is_claimed_then_removed() {
        let root = std::env::temp_dir().join(format!("nazoauth-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let guard = store.begin(binding()).expect("begin");
        assert!(store.claim_pending().expect("active scan").is_empty());
        drop(guard);

        let mut claimed = store.claim_pending().expect("crash scan");
        assert_eq!(claimed.len(), 1);
        let mut guard = claimed.pop().expect("claimed journal");
        guard
            .record_lease("019ff000-8190-7393-8c33-ab4339c3d85e", 1_700_014_400)
            .expect("lease receipt");
        guard.mark_lease_cleanup_complete().expect("lease cleanup");
        assert!(guard.proxy_cleanup_complete());
        guard.finish().expect("complete journal");
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
