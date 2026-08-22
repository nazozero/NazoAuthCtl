use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use nazo_operator_protocol::{
    MAX_COMPACT_JWS_BYTES, MAX_TENANT_RESOURCE_IDENTITIES, TenantResourceIdentity,
    TenantResourceOperation, TenantResourceReceipt, compact_sha256, validate_file_identifier_value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const LEGACY_RECOVERY_JOURNAL_SCHEMA: u32 = 1;
/// The ordinary default journal remains schema 2 byte-for-byte compatible.
const TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA: u32 = 2;
/// Schema 3 is emitted only after an explicit certification-retention policy
/// is durably bound. Older binaries reject it rather than deleting plans.
const RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA: u32 = 3;
const TENANT_RESOURCE_RECOVERY_KIND: &str = "tenant-resource";
const MAX_RECOVERY_JOURNAL_BYTES: usize = 128 * 1024;
const MAX_PENDING_RUNS: usize = 64;
const MAX_PERSISTED_REVISION: u64 = i64::MAX as u64;
const MAX_TENANT_RESOURCE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUITE_RECOVERY_PLANS: usize = 128;
const MAX_SUITE_RECOVERY_MODULES: usize = 16 * 1024;
const SUITE_RETENTION_MANIFEST_SCHEMA: u32 = 1;
const MAX_SUITE_RETENTION_MANIFEST_BYTES: usize = 64 * 1024;

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

/// The immutable identities that ordinary tenant-resource cleanup is allowed
/// to touch.  This intentionally reuses the wire-protocol identity type: ctl
/// must not invent a second kind/id/digest vocabulary at the recovery layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceRecoveryBinding {
    pub deployment_id: String,
    pub tenant_id: String,
    pub request_jti: String,
    pub capability_jws: String,
    pub capability_sha256: String,
    pub task_jws: String,
    pub task_sha256: String,
    pub change_set_id: String,
    pub change_set_sha256: String,
    /// SHA-256 of the complete canonical execute HTTP body.  The recovery
    /// layer stores and rechecks this claim; the caller owns canonical body
    /// construction and must compare its freshly prepared bytes before send.
    pub request_sha256: String,
    pub operation: TenantResourceOperation,
    pub expected_revision: u64,
    pub manifest_path: Option<PathBuf>,
    /// Optional proxy material that the Apply caller may have installed.  The
    /// recovery layer only records whether the caller restored it; it never
    /// executes the legacy proxy command itself.
    #[serde(default)]
    pub proxy: Option<ConformanceProxyRecovery>,
    pub resource_identities: Vec<TenantResourceIdentity>,
}

/// A compact, verified identity of the signed apply receipt.  The signed JWS
/// itself is deliberately not retained in the recovery journal; its digest
/// and the fields needed to re-bind it to the intent are sufficient evidence
/// for recovery without copying any private material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceReceiptIdentity {
    pub receipt_sha256: String,
    pub jti: String,
    pub deployment_id: String,
    pub tenant_id: String,
    pub request_sha256: String,
    pub change_set_id: String,
    pub change_set_sha256: String,
    pub operation: TenantResourceOperation,
    pub expected_revision: u64,
    pub revision: u64,
    pub resources: Vec<TenantResourceIdentity>,
}

impl TenantResourceReceiptIdentity {
    /// Build the journal identity only after the caller has verified the
    /// signed protocol receipt.  No compact JWS bytes are copied into the
    /// journal.
    pub fn from_verified_receipt(
        receipt: &TenantResourceReceipt,
        receipt_sha256: &str,
    ) -> anyhow::Result<Self> {
        if !lower_hex(receipt_sha256, 64) {
            bail!("tenant resource receipt digest is invalid");
        }
        Ok(Self {
            receipt_sha256: receipt_sha256.to_owned(),
            jti: receipt.jti.clone(),
            deployment_id: receipt.deployment_id.clone(),
            tenant_id: receipt.tenant_id.clone(),
            request_sha256: receipt.request_sha256.clone(),
            change_set_id: receipt.change_set_id.clone(),
            change_set_sha256: receipt.change_set_sha256.clone(),
            operation: receipt.operation,
            expected_revision: receipt.expected_revision,
            revision: receipt.revision,
            resources: receipt.resources.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TenantResourceRevokeOutcome {
    Revoked,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceRevokeRecord {
    pub identity: TenantResourceIdentity,
    pub outcome: Option<TenantResourceRevokeOutcome>,
}

/// Opaque external Suite resources that must be removed after a controller
/// crash. The Suite credential is deliberately not journaled: a recovery run
/// obtains it again from the authenticated controller invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRecoveryState {
    pub origin: String,
    pub plan_ids: Vec<String>,
    pub module_ids: Vec<String>,
    /// Intent IDs are written before a Suite create request is sent and are
    /// atomically replaced by the returned opaque resource ID.  A surviving
    /// intent means the request outcome is unknown and must block cleanup
    /// completion until an operator can reconcile it with the Suite.
    #[serde(default)]
    pub pending_create_intents: Vec<String>,
    pub cleanup_complete: bool,
}

/// Non-secret ownership evidence for an explicitly retained Suite plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionPlan {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub plan_name: String,
    pub plan_alias_sha256: String,
}

/// Root-owned certification-review evidence. It deliberately contains no
/// module logs, Suite credentials, client config, or tenant secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionManifest {
    pub schema: u32,
    pub suite_origin: String,
    pub artifact_digest: String,
    pub matrix_sha256: String,
    pub deployment_id: String,
    pub tenant_id: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_screenshot_manifest: Option<SuiteRetentionScreenshotManifest>,
    pub plans: Vec<SuiteRetentionPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionScreenshotManifest {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotManifestDocument {
    schema: u32,
    run_jti: String,
    artifact_digest: String,
    matrix_sha256: String,
    suite_origin: String,
    modules: Vec<ReviewScreenshotManifestModule>,
    screenshots: Vec<ReviewScreenshotManifestImage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotManifestModule {
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: std::collections::BTreeMap<String, String>,
    required: usize,
    captured_required: usize,
    missing_optional: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotManifestImage {
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: std::collections::BTreeMap<String, String>,
    marker: crate::ReviewScreenshotMarker,
    obligation_index: usize,
    path: PathBuf,
    sha256: String,
    size: usize,
    receipt_sha256: String,
    trigger_origin: String,
    trigger_path: String,
    trigger_url_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotAudit {
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: std::collections::BTreeMap<String, String>,
    marker: crate::ReviewScreenshotMarker,
    obligation_index: usize,
    path: PathBuf,
    sha256: String,
    size: usize,
    trigger_origin: String,
    trigger_path: String,
    trigger_url_sha256: String,
}

impl SuiteRetentionManifest {
    pub fn plan_alias_sha256(matrix_plan_id: &str) -> String {
        sha256_hex(matrix_plan_id.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SuiteRetentionRecord {
    manifest: SuiteRetentionManifest,
    manifest_sha256: String,
    manifest_path: PathBuf,
}

/// The non-secret, root-owned manifest that now owns retained Suite plans.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionManifestReceipt {
    pub path: PathBuf,
    pub sha256: String,
}

/// Suite plan ownership remains active until all non-Suite cleanup succeeds.
/// `RetentionPrepared` is intentionally recoverable as ordinary deletion;
/// only `Retained` transfers plan ownership to the verified manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "kebab-case", deny_unknown_fields)]
enum SuiteRetentionDisposition {
    Active { requested: bool },
    RetentionPrepared { record: SuiteRetentionRecord },
    Retained { record: SuiteRetentionRecord },
    Cleaned,
}

impl Default for SuiteRetentionDisposition {
    fn default() -> Self {
        Self::Active { requested: false }
    }
}

impl SuiteRetentionDisposition {
    fn is_default(value: &Self) -> bool {
        matches!(value, Self::Active { requested: false })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecoveryJournal {
    schema: u32,
    binding: ConformanceRecoveryBinding,
    lease_id: Option<String>,
    lease_expires_at: Option<i64>,
    lease_cleanup_complete: bool,
    proxy_cleanup_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantResourceRecoveryJournal {
    schema: u32,
    kind: String,
    binding: TenantResourceRecoveryBinding,
    receipt: Option<TenantResourceReceiptIdentity>,
    enumeration: Option<Vec<TenantResourceIdentity>>,
    revocations: Vec<TenantResourceRevokeRecord>,
    #[serde(default)]
    cleanup_complete: bool,
    #[serde(default)]
    manifest_removal_intent: bool,
    #[serde(default)]
    manifest_cleanup_complete: bool,
    /// A deterministic provider rejection before any receipt proves that the
    /// remote transaction did not commit.  Persist this intent before
    /// deleting the private manifest so a crash cannot strand an unreadable
    /// journal or cause the rejected request to be replayed forever.
    #[serde(default)]
    abort_uncommitted_intent: bool,
    /// A proxy may be installed by the Apply caller before the process dies.
    /// This marker is deliberately separate from ordinary resource cleanup:
    /// both must be complete before the journal can be removed.
    #[serde(default)]
    proxy_cleanup_complete: bool,
    /// Absent in older schema-2 journals, which could not have recorded a
    /// Suite allocation and are therefore already settled at this boundary.
    #[serde(default)]
    suite: Option<SuiteRecoveryState>,
    #[serde(default, skip_serializing_if = "SuiteRetentionDisposition::is_default")]
    suite_retention: SuiteRetentionDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecoveryJournal {
    Legacy(Box<LegacyRecoveryJournal>),
    TenantResource(Box<TenantResourceRecoveryJournal>),
}

impl Serialize for RecoveryJournal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Legacy(journal) => journal.serialize(serializer),
            Self::TenantResource(journal) => journal.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RecoveryJournal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let schema = value
            .get("schema")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| serde::de::Error::custom("recovery journal has no schema"))?;
        const LEGACY_SCHEMA: u64 = LEGACY_RECOVERY_JOURNAL_SCHEMA as u64;
        const TENANT_RESOURCE_SCHEMA: u64 = TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA as u64;
        const RETAINING_TENANT_RESOURCE_SCHEMA: u64 =
            RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA as u64;
        match schema {
            LEGACY_SCHEMA => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::Legacy)
                .map_err(serde::de::Error::custom),
            TENANT_RESOURCE_SCHEMA | RETAINING_TENANT_RESOURCE_SCHEMA => {
                serde_json::from_value(value)
                    .map(Box::new)
                    .map(Self::TenantResource)
                    .map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::custom(
                "unsupported recovery journal schema",
            )),
        }
    }
}

impl RecoveryJournal {
    fn request_jti(&self) -> &str {
        match self {
            Self::Legacy(journal) => &journal.binding.request_jti,
            Self::TenantResource(journal) => &journal.binding.request_jti,
        }
    }
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
    // This is deliberately a test-only durability seam.  Production always
    // persists through the same atomic journal writer.
    #[cfg(test)]
    fail_next_persist: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
        let request_jti = binding.request_jti.clone();
        self.begin_journal(
            &request_jti,
            RecoveryJournal::Legacy(Box::new(LegacyRecoveryJournal {
                schema: LEGACY_RECOVERY_JOURNAL_SCHEMA,
                proxy_cleanup_complete: binding.proxy.is_none(),
                binding,
                lease_id: None,
                lease_expires_at: None,
                lease_cleanup_complete: false,
            })),
        )
    }

    /// Persist ordinary tenant-resource intent before the caller performs any
    /// remote apply.  This method performs no network operation and only
    /// returns a lock-held guard after the durable journal write succeeds.
    pub fn begin_tenant_resource(
        &self,
        binding: TenantResourceRecoveryBinding,
    ) -> anyhow::Result<ConformanceRecoveryGuard> {
        validate_tenant_resource_binding(&binding, &self.deployment_id)?;
        if !validate_tenant_resource_manifest_file(&binding)? {
            bail!("tenant-resource apply manifest is missing");
        }
        let request_jti = binding.request_jti.clone();
        let proxy_cleanup_complete = binding.proxy.is_none();
        self.begin_journal(
            &request_jti,
            RecoveryJournal::TenantResource(Box::new(TenantResourceRecoveryJournal {
                schema: TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
                kind: TENANT_RESOURCE_RECOVERY_KIND.to_owned(),
                binding,
                receipt: None,
                enumeration: None,
                revocations: Vec::new(),
                cleanup_complete: false,
                manifest_removal_intent: false,
                manifest_cleanup_complete: false,
                abort_uncommitted_intent: false,
                proxy_cleanup_complete,
                suite: None,
                suite_retention: SuiteRetentionDisposition::default(),
            })),
        )
    }

    fn begin_journal(
        &self,
        request_jti: &str,
        journal: RecoveryJournal,
    ) -> anyhow::Result<ConformanceRecoveryGuard> {
        let (journal_path, lock_path) = self.paths(request_jti);
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
        write_journal(&journal_path, &journal)?;
        Ok(ConformanceRecoveryGuard {
            store: self.clone(),
            journal,
            journal_path,
            lock_path,
            lock: Some(lock),
            #[cfg(test)]
            fail_next_persist: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
            let mut journal: RecoveryJournal =
                serde_json::from_slice(&bytes).context("recovery journal is invalid")?;
            // Schema-2 journals written before proxy recovery was added had
            // no proxy binding or cleanup marker.  They are safe to recover
            // as already restored because there is no proxy side effect to
            // undo; persist the normalized marker before exposing the guard.
            let mut normalized_proxy_cleanup = false;
            if let RecoveryJournal::TenantResource(tenant_journal) = &mut journal
                && tenant_journal.binding.proxy.is_none()
                && !tenant_journal.proxy_cleanup_complete
            {
                tenant_journal.proxy_cleanup_complete = true;
                normalized_proxy_cleanup = true;
            }
            validate_journal(&journal, &self.deployment_id, request_jti)?;
            // Completed Suite cleanup has no future external action to take.
            // Older journals retained the already-cleaned opaque IDs, which
            // wastes the bounded recovery budget and can prevent later
            // tenant-resource cleanup records from being persisted. Validate
            // their legacy contents above, then atomically discard them.
            let mut normalized_suite_cleanup = false;
            if let RecoveryJournal::TenantResource(tenant_journal) = &mut journal
                && let Some(suite) = &mut tenant_journal.suite
                && suite.cleanup_complete
                && suite.pending_create_intents.is_empty()
                && (!suite.plan_ids.is_empty() || !suite.module_ids.is_empty())
            {
                suite.plan_ids.clear();
                suite.module_ids.clear();
                if tenant_journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
                    && matches!(
                        &tenant_journal.suite_retention,
                        SuiteRetentionDisposition::Active { .. }
                    )
                {
                    tenant_journal.suite_retention = SuiteRetentionDisposition::Cleaned;
                }
                normalized_suite_cleanup = true;
            }
            let mut recovered_retention_manifest = false;
            if let RecoveryJournal::TenantResource(tenant_journal) = &journal
                && let SuiteRetentionDisposition::Retained { record } =
                    &tenant_journal.suite_retention
            {
                let final_path = record.manifest_path.clone();
                let name = final_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .context("retained Suite manifest path is invalid")?;
                let pending_path = final_path.with_file_name(format!(".{name}.pending"));
                match crate::secure_file::read_bounded(
                    &final_path,
                    MAX_SUITE_RETENTION_MANIFEST_BYTES,
                    true,
                ) {
                    Ok(bytes) if sha256_hex(&bytes) == record.manifest_sha256 => {}
                    Ok(_) => bail!("retained Suite manifest conflicts with recovery journal"),
                    Err(crate::secure_file::SecureFileError::NotFound) => {
                        let pending = crate::secure_file::read_bounded(
                            &pending_path,
                            MAX_SUITE_RETENTION_MANIFEST_BYTES,
                            true,
                        )
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "retained Suite pending manifest is not secure: {error:?}"
                            )
                        })?;
                        if sha256_hex(&pending) != record.manifest_sha256 {
                            bail!(
                                "retained Suite pending manifest conflicts with recovery journal"
                            );
                        }
                        crate::secure_file::promote_private_file(&pending_path, &final_path)
                            .map_err(|error| {
                                anyhow::anyhow!(
                                    "failed to recover retained Suite manifest: {error:?}"
                                )
                            })?;
                        recovered_retention_manifest = true;
                    }
                    Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
                }
            }
            let mut recovered_manifest_removal = false;
            if let RecoveryJournal::TenantResource(tenant_journal) = &mut journal
                && tenant_journal.binding.manifest_path.is_some()
            {
                let present = validate_tenant_resource_manifest_file(&tenant_journal.binding)?;
                if tenant_journal.manifest_cleanup_complete {
                    if present {
                        bail!("tenant-resource manifest remains after cleanup marker");
                    }
                } else if !present {
                    if !tenant_journal.manifest_removal_intent {
                        bail!("tenant-resource apply manifest disappeared before cleanup");
                    }
                    tenant_journal.manifest_cleanup_complete = true;
                    recovered_manifest_removal = true;
                }
            }
            if recovered_manifest_removal
                || normalized_proxy_cleanup
                || normalized_suite_cleanup
                || recovered_retention_manifest
            {
                validate_journal(&journal, &self.deployment_id, request_jti)?;
                write_journal(&journal_path, &journal)?;
            }
            pending.push(ConformanceRecoveryGuard {
                store: self.clone(),
                journal,
                journal_path,
                lock_path,
                lock: Some(lock),
                #[cfg(test)]
                fail_next_persist: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
    #[cfg(test)]
    fn fail_next_persist_for_test(&self) {
        self.fail_next_persist
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn binding(&self) -> &ConformanceRecoveryBinding {
        match &self.journal {
            RecoveryJournal::Legacy(journal) => &journal.binding,
            RecoveryJournal::TenantResource(_) => {
                panic!("legacy conformance binding requested for tenant-resource journal")
            }
        }
    }

    pub fn tenant_resource_binding(&self) -> Option<&TenantResourceRecoveryBinding> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => Some(&journal.binding),
        }
    }

    pub fn tenant_resource_receipt(&self) -> Option<&TenantResourceReceiptIdentity> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => journal.receipt.as_ref(),
        }
    }

    pub fn tenant_resource_enumeration(&self) -> Option<&[TenantResourceIdentity]> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => journal.enumeration.as_deref(),
        }
    }

    pub fn tenant_resource_revocations(&self) -> Option<&[TenantResourceRevokeRecord]> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => Some(&journal.revocations),
        }
    }

    pub fn lease_id(&self) -> Option<&str> {
        match &self.journal {
            RecoveryJournal::Legacy(journal) => journal.lease_id.as_deref(),
            RecoveryJournal::TenantResource(_) => None,
        }
    }

    pub fn lease_cleanup_complete(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(journal) => journal.lease_cleanup_complete,
            RecoveryJournal::TenantResource(_) => false,
        }
    }

    pub fn proxy_cleanup_complete(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(journal) => journal.proxy_cleanup_complete,
            RecoveryJournal::TenantResource(journal) => journal.proxy_cleanup_complete,
        }
    }

    pub fn record_lease(&mut self, lease_id: &str, expires_at: i64) -> anyhow::Result<()> {
        validate_component(lease_id, "lease ID")?;
        let (prepared_at, requested_expires_at) = self
            .legacy_journal()
            .map(|journal| {
                (
                    journal.binding.prepared_at,
                    journal.binding.requested_expires_at,
                )
            })
            .context("lease cleanup is not valid for a tenant-resource journal")?;
        if expires_at <= prepared_at || expires_at > requested_expires_at {
            bail!("lease expiry is outside the recovery binding");
        }
        if self
            .legacy_journal()
            .and_then(|journal| journal.lease_id.as_deref())
            .is_some_and(|existing| existing != lease_id)
        {
            bail!("recovery journal is already bound to a different lease");
        }
        let journal = self
            .legacy_journal_mut()
            .context("lease cleanup is not valid for a tenant-resource journal")?;
        journal.lease_id = Some(lease_id.to_owned());
        journal.lease_expires_at = Some(expires_at);
        self.persist()
    }

    pub fn mark_lease_cleanup_complete(&mut self) -> anyhow::Result<()> {
        let journal = self
            .legacy_journal_mut()
            .context("lease cleanup is not valid for a tenant-resource journal")?;
        journal.lease_cleanup_complete = true;
        self.persist()
    }

    pub fn mark_proxy_cleanup_complete(&mut self) -> anyhow::Result<()> {
        match &mut self.journal {
            RecoveryJournal::Legacy(journal) => journal.proxy_cleanup_complete = true,
            RecoveryJournal::TenantResource(journal) => journal.proxy_cleanup_complete = true,
        }
        self.persist()
    }

    /// Persist a remote Suite plan immediately after it is allocated.  This
    /// is intentionally outside NazoAuth: it records only the canonical
    /// external origin and opaque Suite identifier needed for cancellation.
    pub fn record_suite_plan(
        &mut self,
        origin: &str,
        intent_id: &str,
        plan_id: &str,
    ) -> anyhow::Result<()> {
        let origin = crate::Origin::parse_suite(origin)
            .map_err(|_| anyhow::anyhow!("Suite recovery origin is invalid"))?;
        validate_component(plan_id, "Suite plan ID")?;
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite recovery is not valid for a legacy journal")?;
        let suite = journal.suite.get_or_insert_with(|| SuiteRecoveryState {
            origin: origin.as_str().to_owned(),
            plan_ids: Vec::new(),
            module_ids: Vec::new(),
            pending_create_intents: Vec::new(),
            cleanup_complete: false,
        });
        if suite.origin != origin.as_str() {
            bail!("Suite recovery origin conflicts with the journal");
        }
        if suite.cleanup_complete {
            bail!("Suite recovery is already marked complete");
        }
        Self::resolve_suite_create_intent(suite, intent_id)?;
        if !suite.plan_ids.iter().any(|existing| existing == plan_id) {
            if suite.plan_ids.len() >= MAX_SUITE_RECOVERY_PLANS {
                bail!("Suite recovery plan count exceeds policy");
            }
            suite.plan_ids.push(plan_id.to_owned());
        }
        self.persist()
    }

    /// Persist an unknown-outcome marker before sending a Suite create
    /// request. The Suite API does not yet expose a caller supplied
    /// idempotency key or an authenticated run-scoped enumeration endpoint,
    /// so recovery must retain this marker if the process dies before the
    /// returned opaque resource ID is journaled.
    pub fn begin_suite_create(&mut self, origin: &str, intent_id: &str) -> anyhow::Result<()> {
        self.begin_suite_create_with_retention(origin, intent_id, false)
    }

    /// Bind the requested retention policy before any remote Suite create
    /// request. Once persisted, retries cannot silently change it.
    pub fn begin_suite_create_with_retention(
        &mut self,
        origin: &str,
        intent_id: &str,
        retain_suite_plans_for_certification: bool,
    ) -> anyhow::Result<()> {
        let origin = crate::Origin::parse_suite(origin)
            .map_err(|_| anyhow::anyhow!("Suite recovery origin is invalid"))?;
        validate_component(intent_id, "Suite create intent ID")?;
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite recovery is not valid for a legacy journal")?;
        match &journal.suite_retention {
            SuiteRetentionDisposition::Active { requested }
                if *requested != retain_suite_plans_for_certification
                    && journal.suite.is_some() =>
            {
                bail!("Suite retention policy conflicts with the recovery journal");
            }
            SuiteRetentionDisposition::Active { .. } => {
                journal.suite_retention = SuiteRetentionDisposition::Active {
                    requested: retain_suite_plans_for_certification,
                };
                if retain_suite_plans_for_certification {
                    journal.schema = RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA;
                }
            }
            SuiteRetentionDisposition::RetentionPrepared { .. }
            | SuiteRetentionDisposition::Retained { .. }
            | SuiteRetentionDisposition::Cleaned => {
                bail!("Suite resources are already settled for this recovery journal");
            }
        }
        let suite = journal.suite.get_or_insert_with(|| SuiteRecoveryState {
            origin: origin.as_str().to_owned(),
            plan_ids: Vec::new(),
            module_ids: Vec::new(),
            pending_create_intents: Vec::new(),
            cleanup_complete: false,
        });
        if suite.origin != origin.as_str() {
            bail!("Suite recovery origin conflicts with the journal");
        }
        if suite.cleanup_complete {
            bail!("Suite recovery is already marked complete");
        }
        if suite
            .pending_create_intents
            .iter()
            .any(|existing| existing == intent_id)
        {
            bail!("Suite create intent is already pending");
        }
        if suite.pending_create_intents.len()
            >= MAX_SUITE_RECOVERY_PLANS + MAX_SUITE_RECOVERY_MODULES
        {
            bail!("Suite create intent count exceeds policy");
        }
        suite.pending_create_intents.push(intent_id.to_owned());
        self.persist()
    }

    fn resolve_suite_create_intent(
        suite: &mut SuiteRecoveryState,
        intent_id: &str,
    ) -> anyhow::Result<()> {
        validate_component(intent_id, "Suite create intent ID")?;
        let Some(index) = suite
            .pending_create_intents
            .iter()
            .position(|existing| existing == intent_id)
        else {
            bail!("Suite create intent is not pending");
        };
        suite.pending_create_intents.remove(index);
        Ok(())
    }

    /// Persist a Suite module immediately after it is allocated.  A module
    /// cannot be recorded before its containing plan, preventing a recovery
    /// journal with unactionable external state.
    pub fn record_suite_module(&mut self, intent_id: &str, module_id: &str) -> anyhow::Result<()> {
        validate_component(module_id, "Suite module ID")?;
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite recovery is not valid for a legacy journal")?;
        let suite = journal
            .suite
            .as_mut()
            .context("Suite module has no persisted Suite plan")?;
        if suite.cleanup_complete {
            bail!("Suite recovery is already marked complete");
        }
        Self::resolve_suite_create_intent(suite, intent_id)?;
        if !suite
            .module_ids
            .iter()
            .any(|existing| existing == module_id)
        {
            if suite.module_ids.len() >= MAX_SUITE_RECOVERY_MODULES {
                bail!("Suite recovery module count exceeds policy");
            }
            suite.module_ids.push(module_id.to_owned());
        }
        self.persist()
    }

    pub fn suite_recovery(&self) -> Option<&SuiteRecoveryState> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => journal.suite.as_ref(),
        }
    }

    pub fn suite_cleanup_complete(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(_) => true,
            RecoveryJournal::TenantResource(journal) => {
                matches!(
                    &journal.suite_retention,
                    SuiteRetentionDisposition::Retained { .. } | SuiteRetentionDisposition::Cleaned
                ) || journal.suite.as_ref().is_none_or(|suite| {
                    suite.cleanup_complete && suite.pending_create_intents.is_empty()
                })
            }
        }
    }

    /// Mark external cleanup complete only after every persisted module has
    /// been cancelled and every persisted plan has reached a terminal delete
    /// outcome.  Repeated calls are safe.
    pub fn mark_suite_cleanup_complete(&mut self) -> anyhow::Result<()> {
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite recovery is not valid for a legacy journal")?;
        if !matches!(
            &journal.suite_retention,
            SuiteRetentionDisposition::Active { .. }
                | SuiteRetentionDisposition::RetentionPrepared { .. }
        ) {
            bail!("retained Suite resources cannot be marked as cleanup complete");
        }
        {
            let suite = journal
                .suite
                .as_mut()
                .context("Suite cleanup has no persisted allocation")?;
            if !suite.pending_create_intents.is_empty() {
                bail!("Suite cleanup cannot complete with unresolved Suite create intent");
            }
            suite.cleanup_complete = true;
            suite.plan_ids.clear();
            suite.module_ids.clear();
        }
        if journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA {
            journal.suite_retention = SuiteRetentionDisposition::Cleaned;
        }
        self.persist()
    }

    /// Durably record exact retained plan ownership before publishing its
    /// root-owned manifest. A later crash can recreate the manifest without
    /// deleting the plans.
    pub fn prepare_suite_plan_retention(
        &mut self,
        manifest: SuiteRetentionManifest,
        manifest_path: PathBuf,
    ) -> anyhow::Result<()> {
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite retention is not valid for a legacy journal")?;
        if !matches!(
            &journal.suite_retention,
            SuiteRetentionDisposition::Active { requested: true }
        ) {
            bail!("Suite retention was not requested before allocation");
        }
        let suite = journal
            .suite
            .as_mut()
            .context("Suite retention has no persisted allocation")?;
        if suite.cleanup_complete || !suite.pending_create_intents.is_empty() {
            bail!("Suite retention requires a settled allocation");
        }
        validate_suite_retention_manifest(&manifest, &journal.binding, Some(suite))?;
        let bytes = canonical_suite_retention_manifest(&manifest)?;
        let record = SuiteRetentionRecord {
            manifest,
            manifest_sha256: sha256_hex(&bytes),
            manifest_path,
        };
        // Retention eligibility is evaluated only after every allocated
        // module has reached a terminal state. Prepared fallback cleanup
        // therefore needs exact plan IDs, not the potentially 16k module ID
        // inventory: plan deletion removes the terminal modules with it.
        suite.module_ids.clear();
        journal.suite_retention = SuiteRetentionDisposition::RetentionPrepared { record };
        self.persist()
    }

    /// Write a non-final pending manifest only after all non-Suite cleanup
    /// obligations have completed. The journal remains `Prepared`, so a
    /// crash here still defaults to deletion of the Suite allocation.
    pub fn stage_suite_retention_manifest(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::RetentionPrepared { record } => record,
                _ => bail!("Suite retention has not been prepared"),
            },
            RecoveryJournal::Legacy(_) => {
                bail!("Suite retention is not valid for a legacy journal")
            }
        };
        let bytes = canonical_suite_retention_manifest(&record.manifest)?;
        if sha256_hex(&bytes) != record.manifest_sha256 {
            bail!("Suite retention manifest digest conflicts with the journal");
        }
        if let Some(screenshot) = &record.manifest.review_screenshot_manifest {
            validate_review_screenshot_manifest_binding(
                screenshot,
                &record.manifest,
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
            )?;
        }
        let path = self.suite_retention_pending_path()?;
        match crate::secure_file::read_bounded(&path, MAX_SUITE_RETENTION_MANIFEST_BYTES, true) {
            Ok(existing) if sha256_hex(&existing) == record.manifest_sha256 => return Ok(path),
            Ok(_) => bail!("retained Suite manifest conflicts with the recovery journal"),
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
        }
        crate::secure_file::write_atomic(&path, &bytes, true).map_err(|error| {
            anyhow::anyhow!("failed to stage retained Suite manifest: {error:?}")
        })?;
        Ok(path)
    }

    /// Transfer ownership only after a complete pending manifest has been
    /// fsynced. This is the sole transition that compacts module IDs.
    pub fn commit_suite_plan_retention(&mut self) -> anyhow::Result<()> {
        if let RecoveryJournal::TenantResource(journal) = &self.journal
            && (!tenant_resource_obligations_complete(journal) || !journal.proxy_cleanup_complete)
        {
            bail!("Suite retention cannot commit before ordinary and proxy cleanup complete");
        }
        let pending = self.suite_retention_pending_path()?;
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::RetentionPrepared { record } => record.clone(),
                _ => bail!("Suite retention has not been prepared"),
            },
            RecoveryJournal::Legacy(_) => {
                bail!("Suite retention is not valid for a legacy journal")
            }
        };
        if let Some(screenshot) = &record.manifest.review_screenshot_manifest {
            validate_review_screenshot_manifest_binding(
                screenshot,
                &record.manifest,
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
            )?;
        }
        let bytes =
            crate::secure_file::read_bounded(&pending, MAX_SUITE_RETENTION_MANIFEST_BYTES, true)
                .map_err(|error| {
                    anyhow::anyhow!("retained Suite pending manifest is not secure: {error:?}")
                })?;
        if sha256_hex(&bytes) != record.manifest_sha256 {
            bail!("retained Suite pending manifest conflicts with the journal");
        }
        let mut next = self.journal.clone();
        let journal = match &mut next {
            RecoveryJournal::TenantResource(journal) => journal,
            RecoveryJournal::Legacy(_) => unreachable!("tenant-resource journal was just verified"),
        };
        {
            let suite = journal
                .suite
                .as_mut()
                .context("Suite retention has no persisted allocation")?;
            suite.plan_ids.clear();
            suite.module_ids.clear();
        }
        journal.suite_retention = SuiteRetentionDisposition::Retained { record };
        // Do not expose an in-memory Retained state until its compacted
        // ownership journal is durable. A failed write must remain Prepared
        // so the caller can still perform exact fallback deletion.
        self.persist_snapshot(&next)?;
        self.journal = next;
        Ok(())
    }

    /// Finalize a journal-authorized pending manifest. A missing or altered
    /// final/pending file fails closed and never triggers Suite deletion.
    pub fn publish_committed_suite_retention_manifest(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::Retained { record } => record,
                _ => bail!("Suite retention has not been committed"),
            },
            RecoveryJournal::Legacy(_) => {
                bail!("Suite retention is not valid for a legacy journal")
            }
        };
        let final_path = record.manifest_path.clone();
        if let Some(screenshot) = &record.manifest.review_screenshot_manifest {
            validate_review_screenshot_manifest_binding(
                screenshot,
                &record.manifest,
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
            )?;
        }
        match crate::secure_file::read_bounded(
            &final_path,
            MAX_SUITE_RETENTION_MANIFEST_BYTES,
            true,
        ) {
            Ok(existing) if sha256_hex(&existing) == record.manifest_sha256 => {
                return Ok(final_path);
            }
            Ok(_) => bail!("retained Suite manifest conflicts with the recovery journal"),
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
        }
        let pending = self.suite_retention_pending_path()?;
        crate::secure_file::promote_private_file(&pending, &final_path).map_err(|error| {
            anyhow::anyhow!("failed to publish retained Suite manifest: {error:?}")
        })?;
        Ok(final_path)
    }

    pub fn suite_retention_manifest(&self) -> Option<&SuiteRetentionManifest> {
        match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::RetentionPrepared { record }
                | SuiteRetentionDisposition::Retained { record } => Some(&record.manifest),
                SuiteRetentionDisposition::Active { .. } | SuiteRetentionDisposition::Cleaned => {
                    None
                }
            },
        }
    }

    /// Returns a receipt only after exact Suite plan ownership has transferred.
    pub fn suite_retention_manifest_receipt(
        &self,
    ) -> anyhow::Result<Option<SuiteRetentionManifestReceipt>> {
        match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::Retained { record } => {
                    validate_suite_retention_manifest_path(
                        record,
                        self.tenant_resource_binding()
                            .context("Suite retention has no ordinary binding")?,
                    )?;
                    let bytes = crate::secure_file::read_bounded(
                        &record.manifest_path,
                        MAX_SUITE_RETENTION_MANIFEST_BYTES,
                        true,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("retained Suite manifest is not secure: {error:?}")
                    })?;
                    if sha256_hex(&bytes) != record.manifest_sha256 {
                        bail!("retained Suite manifest conflicts with the recovery journal");
                    }
                    Ok(Some(SuiteRetentionManifestReceipt {
                        path: record.manifest_path.clone(),
                        sha256: record.manifest_sha256.clone(),
                    }))
                }
                SuiteRetentionDisposition::Active { .. }
                | SuiteRetentionDisposition::RetentionPrepared { .. }
                | SuiteRetentionDisposition::Cleaned => Ok(None),
            },
            RecoveryJournal::Legacy(_) => Ok(None),
        }
    }

    pub fn suite_retention_committed(&self) -> bool {
        matches!(
            &self.journal,
            RecoveryJournal::TenantResource(journal)
                if matches!(&journal.suite_retention, SuiteRetentionDisposition::Retained { .. })
        )
    }

    /// A prepared-but-uncommitted retention is ordinary cleanup state. Remove
    /// only its non-final staging file before deleting the journal-owned plans.
    pub fn discard_prepared_suite_retention_staging(&self) -> anyhow::Result<()> {
        let prepared = matches!(
            &self.journal,
            RecoveryJournal::TenantResource(journal)
                if matches!(
                    &journal.suite_retention,
                    SuiteRetentionDisposition::RetentionPrepared { .. }
                )
        );
        if !prepared {
            return Ok(());
        }
        let pending = self.suite_retention_pending_path()?;
        match crate::secure_file::remove_file(&pending, true) {
            Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => Ok(()),
            Err(error) => bail!("failed to discard staged Suite retention manifest: {error:?}"),
        }
    }

    fn suite_retention_pending_path(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::RetentionPrepared { record }
                | SuiteRetentionDisposition::Retained { record } => record,
                _ => bail!("Suite retention has no manifest path"),
            },
            RecoveryJournal::Legacy(_) => {
                bail!("Suite retention is not valid for a legacy journal")
            }
        };
        let name = record
            .manifest_path
            .file_name()
            .and_then(|value| value.to_str())
            .context("Suite retention manifest path is invalid")?;
        Ok(record
            .manifest_path
            .with_file_name(format!(".{name}.pending")))
    }

    /// Persist the verified signed apply receipt identity.  This is the only
    /// method that advances the journal beyond intent; it never performs the
    /// remote apply itself.
    pub fn record_tenant_resource_receipt(
        &mut self,
        receipt: TenantResourceReceiptIdentity,
    ) -> anyhow::Result<()> {
        let journal = self
            .tenant_resource_journal_mut()
            .context("tenant-resource receipt is not valid for a legacy journal")?;
        validate_tenant_resource_receipt_identity(&journal.binding, &receipt)?;
        if let Some(existing) = &journal.receipt {
            if existing != &receipt {
                bail!("tenant-resource receipt identity conflicts with the journal");
            }
            return Ok(());
        }
        journal.receipt = Some(receipt);
        journal.cleanup_complete = tenant_resource_obligations_complete(journal);
        self.persist()
    }

    /// Record the authenticated enumerate result that will drive cleanup.  A
    /// repeated identical result is idempotent; a resource reappearing after
    /// an absence outcome fails closed.
    pub fn record_tenant_resource_enumeration(
        &mut self,
        identities: Vec<TenantResourceIdentity>,
    ) -> anyhow::Result<()> {
        let journal = self
            .tenant_resource_journal_mut()
            .context("tenant-resource enumeration is not valid for a legacy journal")?;
        if journal.receipt.is_none() {
            bail!("tenant-resource enumeration requires a persisted apply receipt");
        }
        validate_tenant_resource_identities(&identities, false)?;
        if !identity_set_is_subset(&identities, &journal.binding.resource_identities) {
            bail!("tenant-resource enumeration contains an unbound resource");
        }
        if let Some(existing) = &journal.enumeration
            && !identity_sets_equal(existing, &identities)
        {
            for identity in &identities {
                let record = journal
                    .revocations
                    .iter()
                    .find(|record| same_resource_key(&record.identity, identity))
                    .context("tenant-resource enumeration is missing a bound resource")?;
                if record.identity.digest != identity.digest {
                    bail!("tenant-resource enumeration digest fence does not match");
                }
                if record.outcome == Some(TenantResourceRevokeOutcome::AlreadyAbsent) {
                    bail!("tenant-resource resource reappeared after absence was recorded");
                }
            }
        }
        if journal.revocations.is_empty() {
            journal.revocations = journal
                .binding
                .resource_identities
                .iter()
                .cloned()
                .map(|identity| TenantResourceRevokeRecord {
                    identity,
                    outcome: None,
                })
                .collect();
        }
        for record in &mut journal.revocations {
            if !identities
                .iter()
                .any(|identity| identity == &record.identity)
                && record.outcome.is_none()
            {
                // An authenticated full enumerate response proves this bound
                // identity is already absent; persist that terminal outcome
                // so a retry remains idempotent.
                record.outcome = Some(TenantResourceRevokeOutcome::AlreadyAbsent);
            }
        }
        journal.enumeration = Some(identities);
        journal.cleanup_complete = tenant_resource_obligations_complete(journal);
        self.persist()
    }

    /// Record one digest-fenced revoke result.  Callers perform the actual
    /// authenticated network operation; this method only records a verified
    /// outcome and is safe to retry with the same result.
    pub fn record_tenant_resource_revoke(
        &mut self,
        identity: &TenantResourceIdentity,
        outcome: TenantResourceRevokeOutcome,
    ) -> anyhow::Result<()> {
        let journal = self
            .tenant_resource_journal_mut()
            .context("tenant-resource revoke is not valid for a legacy journal")?;
        let listed = if let Some(enumeration) = &journal.enumeration {
            enumeration.iter().any(|candidate| candidate == identity)
        } else {
            bail!("tenant-resource revoke requires a persisted enumeration");
        };
        if !listed {
            bail!("tenant-resource revoke identity is not in the current enumeration");
        }
        let record = journal
            .revocations
            .iter_mut()
            .find(|record| same_resource_key(&record.identity, identity))
            .context("tenant-resource revoke identity is not in the enumeration")?;
        if record.identity.digest != identity.digest {
            bail!("tenant-resource revoke digest fence does not match");
        }
        if let Some(existing) = record.outcome {
            if existing != outcome {
                bail!("tenant-resource revoke outcome conflicts with the journal");
            }
            return Ok(());
        }
        record.outcome = Some(outcome);
        journal.cleanup_complete = tenant_resource_obligations_complete(journal);
        self.persist()
    }

    pub fn tenant_resource_cleanup_complete(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(_) => false,
            RecoveryJournal::TenantResource(journal) => {
                tenant_resource_obligations_complete(journal)
            }
        }
    }

    fn legacy_journal(&self) -> Option<&LegacyRecoveryJournal> {
        match &self.journal {
            RecoveryJournal::Legacy(journal) => Some(journal),
            RecoveryJournal::TenantResource(_) => None,
        }
    }

    fn legacy_journal_mut(&mut self) -> Option<&mut LegacyRecoveryJournal> {
        match &mut self.journal {
            RecoveryJournal::Legacy(journal) => Some(journal),
            RecoveryJournal::TenantResource(_) => None,
        }
    }

    fn tenant_resource_journal_mut(&mut self) -> Option<&mut TenantResourceRecoveryJournal> {
        match &mut self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => Some(journal),
        }
    }

    pub fn ordinary_cleanup_complete(&self) -> bool {
        self.tenant_resource_cleanup_complete()
    }

    pub fn tenant_resource_manifest_removal_intent(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(_) => false,
            RecoveryJournal::TenantResource(journal) => journal.manifest_removal_intent,
        }
    }

    pub fn tenant_resource_manifest_cleanup_complete(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(_) => false,
            RecoveryJournal::TenantResource(journal) => journal.manifest_cleanup_complete,
        }
    }

    pub fn tenant_resource_abort_uncommitted_intent(&self) -> bool {
        match &self.journal {
            RecoveryJournal::Legacy(_) => false,
            RecoveryJournal::TenantResource(journal) => journal.abort_uncommitted_intent,
        }
    }

    /// Discard an Apply intent only after the authenticated provider has
    /// returned a deterministic pre-commit rejection.  Callers must first
    /// prove that no proxy side effect remains.  Any receipt, enumeration, or
    /// revoke record makes this operation unavailable; such a journal must go
    /// through ordinary cleanup instead.
    pub fn abort_uncommitted_tenant_resource(mut self) -> anyhow::Result<()> {
        let manifest_path = {
            let journal = self
                .tenant_resource_journal_mut()
                .context("uncommitted abort is not valid for a legacy journal")?;
            if journal.binding.operation != TenantResourceOperation::Apply
                || journal.receipt.is_some()
                || journal.enumeration.is_some()
                || !journal.revocations.is_empty()
                || journal.cleanup_complete
                || !journal.proxy_cleanup_complete
            {
                bail!("tenant-resource journal may have committed side effects");
            }
            let manifest_path = journal
                .binding
                .manifest_path
                .clone()
                .context("tenant-resource Apply journal has no private manifest")?;
            journal.abort_uncommitted_intent = true;
            journal.manifest_removal_intent = true;
            manifest_path
        };
        self.persist()?;

        let needs_manifest_removal = match &self.journal {
            RecoveryJournal::TenantResource(journal) => !journal.manifest_cleanup_complete,
            RecoveryJournal::Legacy(_) => false,
        };
        if needs_manifest_removal {
            match crate::secure_file::remove_file(&manifest_path, true) {
                Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => {}
                Err(error) => {
                    bail!("failed to remove rejected tenant-resource manifest: {error:?}");
                }
            }
            if let RecoveryJournal::TenantResource(journal) = &mut self.journal {
                journal.manifest_cleanup_complete = true;
            }
            self.persist()?;
        } else if validate_tenant_resource_manifest_file(match &self.journal {
            RecoveryJournal::TenantResource(journal) => &journal.binding,
            RecoveryJournal::Legacy(_) => unreachable!(),
        })? {
            bail!("rejected tenant-resource manifest remains after cleanup marker");
        }
        self.remove_journal_and_lock()
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        if self.suite_retention_committed() {
            self.publish_committed_suite_retention_manifest()?;
        }
        match &self.journal {
            RecoveryJournal::Legacy(journal) => {
                if !journal.lease_cleanup_complete || !journal.proxy_cleanup_complete {
                    bail!("conformance recovery obligations are incomplete");
                }
            }
            RecoveryJournal::TenantResource(journal) => {
                if !tenant_resource_obligations_complete(journal)
                    || !journal.proxy_cleanup_complete
                    || !suite_resources_settled(journal)
                {
                    bail!("conformance recovery obligations are incomplete");
                }
            }
        }

        let ordinary_manifest_path = match &self.journal {
            RecoveryJournal::Legacy(_) => None,
            RecoveryJournal::TenantResource(journal) => journal.binding.manifest_path.clone(),
        };
        if let Some(manifest_path) = ordinary_manifest_path {
            let needs_intent = match &self.journal {
                RecoveryJournal::TenantResource(journal) => !journal.manifest_removal_intent,
                RecoveryJournal::Legacy(_) => false,
            };
            if needs_intent {
                if let RecoveryJournal::TenantResource(journal) = &mut self.journal {
                    journal.cleanup_complete = true;
                    journal.manifest_removal_intent = true;
                }
                // The cleanup marker and removal intent are durable before
                // touching the private manifest.
                self.persist()?;
            }

            let needs_manifest_removal = match &self.journal {
                RecoveryJournal::TenantResource(journal) => !journal.manifest_cleanup_complete,
                RecoveryJournal::Legacy(_) => false,
            };
            if needs_manifest_removal {
                match crate::secure_file::remove_file(&manifest_path, true) {
                    Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => {}
                    Err(error) => {
                        bail!("failed to remove tenant-resource manifest: {error:?}");
                    }
                }
                if let RecoveryJournal::TenantResource(journal) = &mut self.journal {
                    journal.manifest_cleanup_complete = true;
                }
                // If the process dies after unlink and before this write,
                // claim_pending treats the missing file plus persisted intent
                // as the completed removal and retries this marker write.
                self.persist()?;
            } else if validate_tenant_resource_manifest_file(match &self.journal {
                RecoveryJournal::TenantResource(journal) => &journal.binding,
                RecoveryJournal::Legacy(_) => unreachable!(),
            })? {
                bail!("tenant-resource manifest remains after cleanup marker");
            }
        }
        self.remove_journal_and_lock()
    }

    fn remove_journal_and_lock(mut self) -> anyhow::Result<()> {
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
        self.persist_snapshot(&self.journal)
    }

    fn persist_snapshot(&self, journal: &RecoveryJournal) -> anyhow::Result<()> {
        #[cfg(test)]
        if self
            .fail_next_persist
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            bail!("injected recovery journal persistence failure");
        }
        validate_journal(journal, &self.store.deployment_id, journal.request_jti())?;
        if let RecoveryJournal::TenantResource(journal) = journal
            && journal.binding.manifest_path.is_some()
        {
            let present = validate_tenant_resource_manifest_file(&journal.binding)?;
            if journal.manifest_cleanup_complete && present {
                bail!("tenant-resource manifest remains after cleanup marker");
            }
            if !present && !journal.manifest_removal_intent {
                bail!("tenant-resource apply manifest disappeared before cleanup");
            }
        }
        write_journal(&self.journal_path, journal)
    }
}

fn suite_resources_settled(journal: &TenantResourceRecoveryJournal) -> bool {
    matches!(
        &journal.suite_retention,
        SuiteRetentionDisposition::Retained { .. } | SuiteRetentionDisposition::Cleaned
    ) || journal
        .suite
        .as_ref()
        .is_none_or(|suite| suite.cleanup_complete)
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
    if journal.request_jti() != request_jti {
        bail!("conformance recovery journal request JTI does not match its path");
    }
    match journal {
        RecoveryJournal::Legacy(journal) => {
            if journal.schema != LEGACY_RECOVERY_JOURNAL_SCHEMA
                || journal.lease_id.is_some() != journal.lease_expires_at.is_some()
                || (journal.lease_cleanup_complete && journal.lease_id.is_none())
            {
                bail!("legacy conformance recovery journal state is invalid");
            }
            validate_binding(&journal.binding, deployment_id)
        }
        RecoveryJournal::TenantResource(journal) => {
            if !matches!(
                journal.schema,
                TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
                    | RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
            ) || journal.kind != TENANT_RESOURCE_RECOVERY_KIND
            {
                bail!("tenant-resource recovery journal discriminator is invalid");
            }
            validate_tenant_resource_journal(journal, deployment_id)
        }
    }
}

fn validate_tenant_resource_journal(
    journal: &TenantResourceRecoveryJournal,
    deployment_id: &str,
) -> anyhow::Result<()> {
    validate_tenant_resource_binding(&journal.binding, deployment_id)?;
    if journal.schema == TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
        && !SuiteRetentionDisposition::is_default(&journal.suite_retention)
    {
        bail!("schema-2 recovery journal cannot retain Suite plans");
    }
    if journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
        && SuiteRetentionDisposition::is_default(&journal.suite_retention)
    {
        bail!("schema-3 recovery journal has no explicit retention policy");
    }
    if journal.cleanup_complete && !tenant_resource_obligations_complete(journal) {
        bail!("tenant-resource cleanup marker is ahead of its obligations");
    }
    if journal.abort_uncommitted_intent
        && (journal.binding.operation != TenantResourceOperation::Apply
            || journal.receipt.is_some()
            || journal.enumeration.is_some()
            || !journal.revocations.is_empty()
            || journal.cleanup_complete
            || !journal.proxy_cleanup_complete
            || journal.binding.manifest_path.is_none())
    {
        bail!("tenant-resource uncommitted abort state is invalid");
    }
    if journal.manifest_removal_intent
        && ((!journal.cleanup_complete && !journal.abort_uncommitted_intent)
            || journal.binding.manifest_path.is_none())
    {
        bail!("tenant-resource manifest removal intent is invalid");
    }
    if journal.manifest_cleanup_complete && !journal.manifest_removal_intent {
        bail!("tenant-resource manifest cleanup marker has no intent");
    }
    if journal.binding.proxy.is_none() && !journal.proxy_cleanup_complete {
        bail!("tenant-resource proxy cleanup marker is incomplete without a proxy binding");
    }
    let suite_inventory_transferred = matches!(
        &journal.suite_retention,
        SuiteRetentionDisposition::Retained { .. }
    );
    if let Some(suite) = &journal.suite {
        let origin = crate::Origin::parse_suite(&suite.origin)
            .map_err(|_| anyhow::anyhow!("Suite recovery origin is invalid"))?;
        if origin.as_str() != suite.origin
            || (!suite.cleanup_complete
                && !suite_inventory_transferred
                && suite.plan_ids.is_empty()
                && suite.pending_create_intents.is_empty())
            || suite.plan_ids.len() > MAX_SUITE_RECOVERY_PLANS
            || suite.module_ids.len() > MAX_SUITE_RECOVERY_MODULES
            || suite.pending_create_intents.len()
                > MAX_SUITE_RECOVERY_PLANS + MAX_SUITE_RECOVERY_MODULES
            || (suite.cleanup_complete && !suite.pending_create_intents.is_empty())
        {
            bail!("Suite recovery state is outside policy");
        }
        let mut plan_ids = std::collections::BTreeSet::new();
        for plan_id in &suite.plan_ids {
            validate_component(plan_id, "Suite plan ID")?;
            if !plan_ids.insert(plan_id) {
                bail!("Suite recovery plan identifiers must be unique");
            }
        }
        let mut module_ids = std::collections::BTreeSet::new();
        for module_id in &suite.module_ids {
            validate_component(module_id, "Suite module ID")?;
            if !module_ids.insert(module_id) {
                bail!("Suite recovery module identifiers must be unique");
            }
        }
        let mut intent_ids = std::collections::BTreeSet::new();
        for intent_id in &suite.pending_create_intents {
            validate_component(intent_id, "Suite create intent ID")?;
            if !intent_ids.insert(intent_id) {
                bail!("Suite create intent identifiers must be unique");
            }
        }
    }
    match &journal.suite_retention {
        SuiteRetentionDisposition::Active { .. } => {}
        SuiteRetentionDisposition::Cleaned => {
            let suite = journal
                .suite
                .as_ref()
                .context("Suite cleanup disposition has no Suite state")?;
            if !suite.cleanup_complete
                || !suite.pending_create_intents.is_empty()
                || !suite.plan_ids.is_empty()
                || !suite.module_ids.is_empty()
            {
                bail!("Suite cleaned disposition is outside policy");
            }
        }
        SuiteRetentionDisposition::RetentionPrepared { record } => {
            let suite = journal
                .suite
                .as_ref()
                .context("prepared Suite retention has no Suite state")?;
            if suite.cleanup_complete || !suite.pending_create_intents.is_empty() {
                bail!("prepared Suite retention has unsettled allocation state");
            }
            validate_suite_retention_record(record, &journal.binding, suite)?;
        }
        SuiteRetentionDisposition::Retained { record } => {
            let suite = journal
                .suite
                .as_ref()
                .context("retained Suite disposition has no Suite state")?;
            if suite.cleanup_complete
                || !suite.pending_create_intents.is_empty()
                || !suite.plan_ids.is_empty()
                || !suite.module_ids.is_empty()
            {
                bail!("retained Suite disposition must transfer all allocation IDs");
            }
            validate_suite_retention_record_without_inventory(record, &journal.binding)?;
        }
    }
    if let Some(receipt) = &journal.receipt {
        validate_tenant_resource_receipt_identity(&journal.binding, receipt)?;
    }
    if journal.enumeration.is_none() && !journal.revocations.is_empty() {
        bail!("tenant-resource revocations require a persisted enumeration");
    }
    if let Some(enumeration) = &journal.enumeration {
        validate_tenant_resource_identities(enumeration, false)?;
        if !identity_set_is_subset(enumeration, &journal.binding.resource_identities) {
            bail!("tenant-resource enumeration contains an unbound resource");
        }
        if journal.revocations.len() != journal.binding.resource_identities.len() {
            bail!("tenant-resource revoke records do not cover the binding");
        }
        let revoke_identities = journal
            .revocations
            .iter()
            .map(|record| record.identity.clone())
            .collect::<Vec<_>>();
        validate_tenant_resource_identities(&revoke_identities, true)?;
        if !identity_sets_equal(&revoke_identities, &journal.binding.resource_identities) {
            bail!("tenant-resource revoke records do not match the binding");
        }
        if enumeration.iter().any(|identity| {
            journal.revocations.iter().any(|record| {
                record.identity == *identity
                    && record.outcome == Some(TenantResourceRevokeOutcome::AlreadyAbsent)
            })
        }) {
            bail!("tenant-resource journal marks an enumerated resource absent");
        }
        for record in &journal.revocations {
            validate_tenant_resource_identity(&record.identity)?;
        }
    }
    Ok(())
}

fn canonical_suite_retention_manifest(
    manifest: &SuiteRetentionManifest,
) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(manifest).context("failed to serialize Suite retention manifest")
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn validate_suite_retention_record(
    record: &SuiteRetentionRecord,
    binding: &TenantResourceRecoveryBinding,
    suite: &SuiteRecoveryState,
) -> anyhow::Result<()> {
    validate_suite_retention_manifest(&record.manifest, binding, Some(suite))?;
    if sha256_hex(&canonical_suite_retention_manifest(&record.manifest)?) != record.manifest_sha256
    {
        bail!("Suite retention manifest digest is invalid");
    }
    validate_suite_retention_manifest_path(record, binding)?;
    Ok(())
}

fn validate_suite_retention_record_without_inventory(
    record: &SuiteRetentionRecord,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    validate_suite_retention_manifest(&record.manifest, binding, None)?;
    if sha256_hex(&canonical_suite_retention_manifest(&record.manifest)?) != record.manifest_sha256
    {
        bail!("Suite retention manifest digest is invalid");
    }
    validate_suite_retention_manifest_path(record, binding)?;
    Ok(())
}

fn validate_suite_retention_manifest(
    manifest: &SuiteRetentionManifest,
    binding: &TenantResourceRecoveryBinding,
    suite: Option<&SuiteRecoveryState>,
) -> anyhow::Result<()> {
    if manifest.schema != SUITE_RETENTION_MANIFEST_SCHEMA
        || crate::Origin::parse_suite(&manifest.suite_origin)
            .map_err(|_| anyhow::anyhow!("retained Suite origin is invalid"))?
            .as_str()
            != "https://www.certification.openid.net"
        || manifest.deployment_id != binding.deployment_id
        || manifest.tenant_id != binding.tenant_id
        || manifest.run_id != binding.request_jti
        || !lower_hex(&manifest.artifact_digest, 64)
        || !lower_hex(&manifest.matrix_sha256, 64)
        || manifest.plans.is_empty()
        || manifest.plans.len() > MAX_SUITE_RECOVERY_PLANS
    {
        bail!("Suite retention manifest is outside policy");
    }
    if let Some(screenshot) = &manifest.review_screenshot_manifest {
        validate_review_screenshot_manifest_binding(screenshot, manifest, binding)?;
    }
    let mut matrix_ids = std::collections::BTreeSet::new();
    let mut suite_ids = std::collections::BTreeSet::new();
    for plan in &manifest.plans {
        validate_component(&plan.matrix_plan_id, "retained Matrix plan ID")?;
        validate_component(&plan.suite_plan_id, "retained Suite plan ID")?;
        if plan.plan_name.is_empty()
            || plan.plan_name.len() > 256
            || plan.plan_name.bytes().any(|byte| byte.is_ascii_control())
            || !lower_hex(&plan.plan_alias_sha256, 64)
            || SuiteRetentionManifest::plan_alias_sha256(&plan.matrix_plan_id)
                != plan.plan_alias_sha256
            || !matrix_ids.insert(&plan.matrix_plan_id)
            || !suite_ids.insert(&plan.suite_plan_id)
        {
            bail!("Suite retention plan ownership is invalid");
        }
    }
    if let Some(suite) = suite {
        let suite_ids = suite
            .plan_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let manifest_ids = manifest
            .plans
            .iter()
            .map(|plan| &plan.suite_plan_id)
            .collect::<std::collections::BTreeSet<_>>();
        if suite_ids != manifest_ids {
            bail!("Suite retention manifest does not cover the journal plan IDs");
        }
        if suite.origin != manifest.suite_origin {
            bail!("Suite retention origin conflicts with the recovery journal");
        }
    }
    Ok(())
}

fn validate_review_screenshot_manifest_binding(
    screenshot: &SuiteRetentionScreenshotManifest,
    retention: &SuiteRetentionManifest,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let expected_name = format!("{}.json", binding.request_jti);
    if !screenshot.path.is_absolute()
        || screenshot.path.file_name().and_then(|name| name.to_str())
            != Some(expected_name.as_str())
        || screenshot
            .path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            != Some("review-screenshot-manifests")
        || !lower_hex(&screenshot.sha256, 64)
    {
        bail!("review screenshot manifest binding is outside policy");
    }
    let bytes = crate::secure_file::read_bounded(
        &screenshot.path,
        crate::evidence::MAX_REVIEW_SCREENSHOT_MANIFEST_BYTES,
        true,
    )
    .map_err(|error| anyhow::anyhow!("review screenshot manifest is not secure: {error:?}"))?;
    if sha256_hex(&bytes) != screenshot.sha256 {
        bail!("review screenshot manifest digest is invalid");
    }
    let document: ReviewScreenshotManifestDocument =
        serde_json::from_slice(&bytes).context("review screenshot manifest is not valid JSON")?;
    if document.schema != 3
        || document.run_jti != binding.request_jti
        || document.artifact_digest != retention.artifact_digest
        || document.matrix_sha256 != retention.matrix_sha256
        || document.suite_origin != retention.suite_origin
    {
        bail!("review screenshot manifest identity conflicts with retention");
    }
    let plans = retention
        .plans
        .iter()
        .map(|plan| (&plan.matrix_plan_id, &plan.suite_plan_id))
        .collect::<std::collections::BTreeSet<_>>();
    let mut modules = std::collections::BTreeSet::new();
    for module in &document.modules {
        if !plans.contains(&(&module.matrix_plan_id, &module.suite_plan_id))
            || module.module_id.is_empty()
            || module.test_name.is_empty()
            || module.required != module.captured_required
            || !modules.insert((
                &module.matrix_plan_id,
                &module.suite_plan_id,
                &module.module_id,
                &module.test_name,
                &module.variant,
            ))
        {
            bail!("review screenshot manifest module graph is invalid");
        }
    }
    let mut images = std::collections::BTreeSet::new();
    let mut expected_files = std::collections::BTreeSet::new();
    let evidence_root = screenshot
        .path
        .parent()
        .and_then(Path::parent)
        .context("review screenshot manifest has no evidence root")?;
    for image in &document.screenshots {
        let mut path_components = image.path.components();
        let valid_path = path_components
            .next()
            .is_some_and(|part| part.as_os_str() == std::ffi::OsStr::new("review-screenshots"))
            && path_components
                .next()
                .is_some_and(|part| part.as_os_str() == std::ffi::OsStr::new(&binding.request_jti))
            && matches!(
                path_components.next(),
                Some(std::path::Component::Normal(_))
            )
            && path_components.next().is_none();
        let target = format!("/test/a/{}/verification-evidence", image.module_id);
        if !plans.contains(&(&image.matrix_plan_id, &image.suite_plan_id))
            || !modules
                .iter()
                .any(|(matrix_plan_id, suite_plan_id, module_id, _, _)| {
                    *matrix_plan_id == &image.matrix_plan_id
                        && *suite_plan_id == &image.suite_plan_id
                        && *module_id == &image.module_id
                })
            || !valid_path
            || image.size == 0
            || !lower_hex(&image.sha256, 64)
            || !lower_hex(&image.receipt_sha256, 64)
            || image.trigger_origin != "https://www.certification.openid.net"
            || image.trigger_path != target
            || !lower_hex(&image.trigger_url_sha256, 64)
            || sha256_hex(format!("{}{}", image.trigger_origin, image.trigger_path).as_bytes())
                != image.trigger_url_sha256
            || !images.insert(&image.path)
        {
            bail!("review screenshot manifest screenshot graph is invalid");
        }
        let image_path = evidence_root.join(&image.path);
        expected_files.insert(image.path.clone());
        expected_files.insert(image.path.with_extension("png.receipt.json"));
        let image_bytes = crate::secure_file::read_bounded(&image_path, 500 * 1024, true)
            .map_err(|error| anyhow::anyhow!("review screenshot is not secure: {error:?}"))?;
        if image_bytes.len() != image.size
            || sha256_hex(&image_bytes) != image.sha256
            || crate::browser::validate_png_screenshot(&image_bytes).is_err()
        {
            bail!("review screenshot bytes conflict with the manifest");
        }
        let receipt_path = image_path.with_extension("png.receipt.json");
        let receipt =
            crate::secure_file::read_bounded(&receipt_path, 16 * 1024, true).map_err(|error| {
                anyhow::anyhow!("review screenshot receipt is not secure: {error:?}")
            })?;
        let audit: ReviewScreenshotAudit = serde_json::from_slice(&receipt)
            .context("review screenshot receipt is invalid JSON")?;
        if sha256_hex(&receipt) != image.receipt_sha256
            || audit.suite_plan_id != image.suite_plan_id
            || audit.module_id != image.module_id
            || audit.test_name != image.test_name
            || audit.variant != image.variant
            || audit.marker != image.marker
            || audit.obligation_index != image.obligation_index
            || audit.path != image.path
            || audit.sha256 != image.sha256
            || audit.size != image.size
            || audit.trigger_origin != image.trigger_origin
            || audit.trigger_path != image.trigger_path
            || audit.trigger_url_sha256 != image.trigger_url_sha256
        {
            bail!("review screenshot receipt conflicts with the manifest");
        }
    }
    if expected_files.len() > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN * 2 {
        bail!("review screenshot manifest exceeds the run file budget");
    }
    let run_directory = evidence_root
        .join("review-screenshots")
        .join(&binding.request_jti);
    match crate::secure_file::validate_directory(&run_directory, true) {
        Ok(_) => {}
        Err(crate::secure_file::SecureFileError::NotFound) if expected_files.is_empty() => {
            return Ok(());
        }
        Err(error) => {
            return Err(anyhow::anyhow!(
                "review screenshot run directory is not secure: {error:?}"
            ));
        }
    }
    let mut found_files = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&run_directory)
        .context("failed to enumerate review screenshot run directory")?
    {
        let entry = entry.context("failed to enumerate review screenshot entry")?;
        let file_type = entry
            .file_type()
            .context("failed to inspect review screenshot entry")?;
        if !file_type.is_file() || file_type.is_symlink() {
            bail!("review screenshot run directory contains a non-file entry");
        }
        let name = entry.file_name();
        let relative = PathBuf::from("review-screenshots")
            .join(&binding.request_jti)
            .join(name);
        if !expected_files.contains(&relative) || !found_files.insert(relative) {
            bail!("review screenshot run directory contains an unexpected entry");
        }
        if found_files.len() > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN * 2 {
            bail!("review screenshot run directory exceeds the file budget");
        }
    }
    if found_files != expected_files {
        bail!("review screenshot run directory is missing a declared entry");
    }
    Ok(())
}

fn validate_suite_retention_manifest_path(
    record: &SuiteRetentionRecord,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let expected_name = format!("retained-suite-{}.json", binding.request_jti);
    if record_path_is_invalid(&record.manifest_path, &expected_name) {
        bail!("Suite retention manifest path is outside policy");
    }
    Ok(())
}

fn record_path_is_invalid(path: &Path, expected_name: &str) -> bool {
    !retention_manifest_parent_is_root_owned(path)
        || !path.is_absolute()
        || path.file_name().and_then(|value| value.to_str()) != Some(expected_name)
        || crate::secure_file::normalize_absolute(path).is_err()
        || path.parent().is_none()
        || crate::secure_file::validate_directory(path.parent().unwrap_or(Path::new(".")), true)
            .is_err()
}

fn retention_manifest_parent_is_root_owned(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        path.parent()
            .and_then(|parent| std::fs::metadata(parent).ok())
            .is_some_and(|metadata| metadata.uid() == 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn tenant_resource_obligations_complete(journal: &TenantResourceRecoveryJournal) -> bool {
    journal.receipt.is_some()
        && journal.enumeration.is_some()
        && journal.revocations.len() == journal.binding.resource_identities.len()
        && journal
            .revocations
            .iter()
            .all(|record| record.outcome.is_some())
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

fn validate_tenant_resource_binding(
    binding: &TenantResourceRecoveryBinding,
    deployment_id: &str,
) -> anyhow::Result<()> {
    validate_component(&binding.deployment_id, "deployment ID")?;
    validate_component(&binding.request_jti, "request JTI")?;
    validate_component(&binding.change_set_id, "change-set ID")?;
    validate_compact_jws(&binding.capability_jws, "capability JWS")?;
    validate_compact_jws(&binding.task_jws, "tenant-resource task JWS")?;
    let tenant_id = uuid::Uuid::parse_str(&binding.tenant_id)
        .map_err(|_| anyhow::anyhow!("tenant-resource tenant ID is invalid"))?;
    if binding.deployment_id != deployment_id
        || tenant_id.to_string() != binding.tenant_id
        || compact_sha256(&binding.capability_jws) != binding.capability_sha256
        || compact_sha256(&binding.task_jws) != binding.task_sha256
        || !lower_hex(&binding.capability_sha256, 64)
        || !lower_hex(&binding.task_sha256, 64)
        || !lower_hex(&binding.change_set_sha256, 64)
        || !lower_hex(&binding.request_sha256, 64)
        || binding.expected_revision >= MAX_PERSISTED_REVISION
        || (matches!(binding.operation, TenantResourceOperation::Apply)
            && binding.manifest_path.is_none())
        || (!matches!(binding.operation, TenantResourceOperation::Apply)
            && binding.manifest_path.is_some())
        || binding
            .manifest_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        || binding.proxy.as_ref().is_some_and(|proxy| {
            !proxy.bundle_path.is_absolute() || !proxy.reload_executable.is_absolute()
        })
    {
        bail!("tenant-resource recovery binding is invalid");
    }
    validate_tenant_resource_identities(
        &binding.resource_identities,
        !matches!(binding.operation, TenantResourceOperation::Enumerate),
    )
}

fn validate_compact_jws(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_COMPACT_JWS_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.split('.').count() != 3
        || value.split('.').any(str::is_empty)
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_tenant_resource_manifest_file(
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<bool> {
    let Some(path) = &binding.manifest_path else {
        return Ok(false);
    };
    if !path.is_absolute() {
        bail!("tenant-resource manifest path must be absolute");
    }
    let bytes =
        match crate::secure_file::read_bounded(path, MAX_TENANT_RESOURCE_MANIFEST_BYTES, true) {
            Ok(bytes) => bytes,
            Err(crate::secure_file::SecureFileError::NotFound) => return Ok(false),
            Err(error) => {
                bail!("tenant-resource manifest is not secure: {error:?}");
            }
        };
    let digest = Sha256::digest(&bytes);
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != binding.change_set_sha256 {
        bail!("tenant-resource manifest digest does not match the change-set");
    }
    Ok(true)
}

fn validate_tenant_resource_receipt_identity(
    binding: &TenantResourceRecoveryBinding,
    receipt: &TenantResourceReceiptIdentity,
) -> anyhow::Result<()> {
    if !lower_hex(&receipt.receipt_sha256, 64)
        || receipt.jti != binding.request_jti
        || receipt.deployment_id != binding.deployment_id
        || receipt.tenant_id != binding.tenant_id
        || receipt.request_sha256 != binding.request_sha256
        || receipt.change_set_id != binding.change_set_id
        || receipt.change_set_sha256 != binding.change_set_sha256
        || receipt.operation != TenantResourceOperation::Apply
        || receipt.expected_revision != binding.expected_revision
        || receipt
            .expected_revision
            .checked_add(1)
            .is_none_or(|revision| receipt.revision != revision)
        || !identity_sets_equal(&receipt.resources, &binding.resource_identities)
    {
        bail!("tenant-resource receipt identity is not bound to the journal");
    }
    validate_tenant_resource_identities(&receipt.resources, true)
}

fn validate_tenant_resource_identities(
    identities: &[TenantResourceIdentity],
    require_nonempty: bool,
) -> anyhow::Result<()> {
    if identities.len() > MAX_TENANT_RESOURCE_IDENTITIES
        || (require_nonempty && identities.is_empty())
    {
        bail!("tenant-resource identities are out of bounds");
    }
    for identity in identities {
        validate_tenant_resource_identity(identity)?;
    }
    for (index, left) in identities.iter().enumerate() {
        if identities
            .iter()
            .skip(index + 1)
            .any(|right| same_resource_key(left, right))
        {
            bail!("tenant-resource identities must be unique");
        }
    }
    Ok(())
}

fn validate_tenant_resource_identity(identity: &TenantResourceIdentity) -> anyhow::Result<()> {
    validate_file_identifier_value(&identity.resource_id)
        .map_err(|error| anyhow::anyhow!("invalid tenant-resource ID: {error}"))?;
    if !lower_hex(&identity.digest, 64) {
        bail!("tenant-resource identity digest is invalid");
    }
    Ok(())
}

fn same_resource_key(left: &TenantResourceIdentity, right: &TenantResourceIdentity) -> bool {
    left.kind == right.kind && left.resource_id == right.resource_id
}

fn identity_sets_equal(left: &[TenantResourceIdentity], right: &[TenantResourceIdentity]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().all(|identity| {
        right.iter().any(|candidate| {
            candidate.kind == identity.kind
                && candidate.resource_id == identity.resource_id
                && candidate.digest == identity.digest
        })
    })
}

fn identity_set_is_subset(
    subset: &[TenantResourceIdentity],
    superset: &[TenantResourceIdentity],
) -> bool {
    subset.iter().all(|identity| {
        superset.iter().any(|candidate| {
            candidate.kind == identity.kind
                && candidate.resource_id == identity.resource_id
                && candidate.digest == identity.digest
        })
    })
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
    #[cfg(unix)]
    use base64::{Engine as _, engine::general_purpose::STANDARD};

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

    #[cfg(unix)]
    fn tenant_resource_identity(digest: char) -> TenantResourceIdentity {
        TenantResourceIdentity {
            kind: nazo_operator_protocol::TenantResourceKind::OauthClient,
            resource_id: "client-1".to_owned(),
            digest: digest.to_string().repeat(64),
        }
    }

    #[cfg(unix)]
    fn tenant_resource_binding(root: &Path) -> TenantResourceRecoveryBinding {
        let manifest = br#"{"resources":["client-1"]}"#;
        let manifest_path = root.join("tenant-resource-manifest.json");
        crate::secure_file::write_atomic(&manifest_path, manifest, true)
            .expect("write tenant manifest");
        let manifest_digest = Sha256::digest(manifest)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let capability_jws = "capability.header.payload".to_owned();
        let task_jws = "task.header.payload".to_owned();
        TenantResourceRecoveryBinding {
            deployment_id: "deployment-a".to_owned(),
            tenant_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            request_jti: "tenant-request-0123456789abcdef0123456789abcdef".to_owned(),
            capability_sha256: compact_sha256(&capability_jws),
            capability_jws,
            task_jws: task_jws.clone(),
            task_sha256: compact_sha256(&task_jws),
            change_set_id: "change-set-1".to_owned(),
            change_set_sha256: manifest_digest,
            request_sha256: "e".repeat(64),
            operation: TenantResourceOperation::Apply,
            expected_revision: 7,
            manifest_path: Some(manifest_path),
            proxy: None,
            resource_identities: vec![tenant_resource_identity('c')],
        }
    }

    #[cfg(unix)]
    fn tenant_resource_binding_with_proxy(root: &Path) -> TenantResourceRecoveryBinding {
        let mut binding = tenant_resource_binding(root);
        binding.proxy = Some(ConformanceProxyRecovery {
            bundle_path: root.join("proxy-bundle.pem"),
            reload_executable: root.join("reload-proxy"),
        });
        binding
    }

    #[cfg(unix)]
    fn tenant_resource_receipt(
        binding: &TenantResourceRecoveryBinding,
    ) -> TenantResourceReceiptIdentity {
        TenantResourceReceiptIdentity {
            receipt_sha256: "f".repeat(64),
            jti: binding.request_jti.clone(),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            request_sha256: binding.request_sha256.clone(),
            change_set_id: binding.change_set_id.clone(),
            change_set_sha256: binding.change_set_sha256.clone(),
            operation: TenantResourceOperation::Apply,
            expected_revision: binding.expected_revision,
            revision: binding.expected_revision + 1,
            resources: binding.resource_identities.clone(),
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
    fn tenant_resource_intent_is_durable_and_has_no_legacy_lease_fields() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        assert_ne!(binding.task_sha256, binding.request_sha256);
        let guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let journal = std::fs::read_to_string(&journal_path).expect("read intent journal");
        assert!(journal.contains("\"schema\": 2"));
        assert!(journal.contains("\"kind\": \"tenant-resource\""));
        assert!(journal.contains(&binding.tenant_id));
        assert!(journal.contains(&binding.capability_jws));
        assert!(journal.contains(&binding.task_jws));
        assert!(journal.contains("manifest_path"));
        assert!(journal.contains("proxy_cleanup_complete"));
        assert!(!journal.contains("lease_id"));
        assert!(store.claim_pending().expect("active scan").is_empty());
        drop(guard);

        let mut pending = store.claim_pending().expect("crash scan");
        assert_eq!(pending.len(), 1);
        let guard = pending.pop().expect("claimed tenant journal");
        assert_eq!(guard.tenant_resource_binding(), Some(&binding));
        assert!(!guard.tenant_resource_cleanup_complete());
        drop(guard);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_journal_rejects_legacy_fields_in_schema_two() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        drop(guard);
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let mut journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).expect("read tenant journal"))
                .expect("decode tenant journal");
        journal["lease_id"] = serde_json::Value::String("legacy-must-not-parse".to_owned());
        std::fs::write(
            &journal_path,
            serde_json::to_vec_pretty(&journal).expect("encode tampered journal"),
        )
        .expect("write tampered journal");
        assert!(store.claim_pending().is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn suite_allocations_are_durable_origin_bound_and_block_finish_until_cleaned() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .begin_suite_create("https://suite.example", "intent-plan-1")
            .expect("persist plan create intent");
        assert_eq!(
            guard
                .suite_recovery()
                .expect("pending Suite recovery")
                .pending_create_intents,
            vec!["intent-plan-1"]
        );
        assert!(guard.mark_suite_cleanup_complete().is_err());
        guard
            .record_suite_plan("https://suite.example", "intent-plan-1", "plan-1")
            .expect("persist plan allocation");
        guard
            .begin_suite_create("https://suite.example", "intent-module-1")
            .expect("persist module create intent");
        assert!(guard.mark_suite_cleanup_complete().is_err());
        assert_eq!(
            guard.suite_recovery(),
            Some(&SuiteRecoveryState {
                origin: "https://suite.example".to_owned(),
                plan_ids: vec!["plan-1".to_owned()],
                module_ids: Vec::new(),
                pending_create_intents: vec!["intent-module-1".to_owned()],
                cleanup_complete: false,
            })
        );
        guard
            .record_suite_module("intent-module-1", "module-1")
            .expect("persist module allocation");
        assert_eq!(
            guard.suite_recovery(),
            Some(&SuiteRecoveryState {
                origin: "https://suite.example".to_owned(),
                plan_ids: vec!["plan-1".to_owned()],
                module_ids: vec!["module-1".to_owned()],
                pending_create_intents: Vec::new(),
                cleanup_complete: false,
            })
        );
        assert!(
            guard
                .record_suite_plan("https://other.example", "intent-other", "plan-2")
                .is_err()
        );

        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .mark_suite_cleanup_complete()
            .expect("Suite cleanup settled");
        assert_eq!(
            guard.suite_recovery(),
            Some(&SuiteRecoveryState {
                origin: "https://suite.example".to_owned(),
                plan_ids: Vec::new(),
                module_ids: Vec::new(),
                pending_create_intents: Vec::new(),
                cleanup_complete: true,
            })
        );
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("enumerate already absent");
        guard.mark_proxy_cleanup_complete().expect("proxy settled");
        guard.finish().expect("finish after Suite cleanup");
        assert!(store.claim_pending().expect("journal removed").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn completed_suite_cleanup_compacts_ids_before_tenant_cleanup_records() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .begin_suite_create("https://suite.example", "intent-plan-1")
            .expect("persist plan intent");
        guard
            .record_suite_plan("https://suite.example", "intent-plan-1", "plan-1")
            .expect("persist plan allocation");
        match &mut guard.journal {
            RecoveryJournal::TenantResource(journal) => {
                let suite = journal.suite.as_mut().expect("Suite state");
                suite.module_ids = (0..1408)
                    .map(|index| format!("module-{index:04}"))
                    .collect();
            }
            RecoveryJournal::Legacy(_) => panic!("expected tenant-resource journal"),
        }
        guard.persist().expect("persist populated Suite state");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .mark_suite_cleanup_complete()
            .expect("compact completed Suite state");
        let suite = guard.suite_recovery().expect("completed Suite state");
        assert!(suite.plan_ids.is_empty());
        assert!(suite.module_ids.is_empty());
        guard
            .record_tenant_resource_enumeration(binding.resource_identities.clone())
            .expect("enumerate after Suite compaction");
        guard
            .record_tenant_resource_revoke(
                &binding.resource_identities[0],
                TenantResourceRevokeOutcome::Revoked,
            )
            .expect("revoke after Suite compaction");
        assert!(
            std::fs::metadata(root.join(format!("run-{}.json", binding.request_jti)))
                .expect("journal metadata")
                .len()
                < MAX_RECOVERY_JOURNAL_BYTES as u64
        );
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn claim_pending_normalizes_legacy_completed_suite_ids_after_validation() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .begin_suite_create("https://suite.example", "intent-plan-1")
            .expect("persist plan intent");
        guard
            .record_suite_plan("https://suite.example", "intent-plan-1", "plan-1")
            .expect("persist plan allocation");
        match &mut guard.journal {
            RecoveryJournal::TenantResource(journal) => {
                journal
                    .suite
                    .as_mut()
                    .expect("Suite state")
                    .cleanup_complete = true;
            }
            RecoveryJournal::Legacy(_) => panic!("expected tenant-resource journal"),
        }
        guard
            .persist()
            .expect("persist legacy completed Suite state");
        drop(guard);

        let mut pending = store
            .claim_pending()
            .expect("claim legacy completed journal");
        let guard = pending.pop().expect("claimed legacy completed journal");
        assert_eq!(
            guard.suite_recovery(),
            Some(&SuiteRecoveryState {
                origin: "https://suite.example".to_owned(),
                plan_ids: Vec::new(),
                module_ids: Vec::new(),
                pending_create_intents: Vec::new(),
                cleanup_complete: true,
            })
        );
        drop(guard);
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).expect("read normalized journal"))
                .expect("decode normalized journal");
        assert_eq!(document["suite"]["plan_ids"], serde_json::json!([]));
        assert_eq!(document["suite"]["module_ids"], serde_json::json!([]));
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn schema_two_suite_journal_without_create_intents_remains_readable() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .begin_suite_create("https://suite.example", "intent-plan-1")
            .expect("persist plan intent");
        guard
            .record_suite_plan("https://suite.example", "intent-plan-1", "plan-1")
            .expect("persist plan allocation");
        drop(guard);

        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let mut journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).expect("read journal"))
                .expect("decode journal");
        journal["suite"]
            .as_object_mut()
            .expect("suite recovery object")
            .remove("pending_create_intents");
        std::fs::write(
            &journal_path,
            serde_json::to_vec_pretty(&journal).expect("encode schema-two journal"),
        )
        .expect("write schema-two journal");

        let mut pending = store.claim_pending().expect("read compatible journal");
        let guard = pending.pop().expect("recovered guard");
        assert!(
            guard
                .suite_recovery()
                .expect("suite recovery")
                .pending_create_intents
                .is_empty()
        );
        drop(guard);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn default_suite_cleanup_remains_a_schema_two_journal_without_retention_fields() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .begin_suite_create("https://suite.example", "intent-plan-1")
            .expect("persist plan intent");
        guard
            .record_suite_plan("https://suite.example", "intent-plan-1", "plan-1")
            .expect("persist plan allocation");
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let before_cleanup =
            std::fs::read_to_string(&journal_path).expect("read schema-two journal");
        assert!(before_cleanup.contains("\"schema\": 2"));
        assert!(!before_cleanup.contains("suite_retention"));

        guard
            .mark_suite_cleanup_complete()
            .expect("settle default Suite cleanup");
        let after_cleanup =
            std::fs::read_to_string(&journal_path).expect("read normalized journal");
        assert!(after_cleanup.contains("\"schema\": 2"));
        assert!(!after_cleanup.contains("suite_retention"));
        drop(guard);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_binding_rejects_jws_digest_and_manifest_path_drift() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let binding = tenant_resource_binding(&root);
        validate_tenant_resource_binding(&binding, "deployment-a").expect("valid binding");

        let mut bad_jws = binding.clone();
        bad_jws.task_jws = "task.changed.payload".to_owned();
        assert!(validate_tenant_resource_binding(&bad_jws, "deployment-a").is_err());

        let mut bad_path = binding;
        bad_path.manifest_path = Some(PathBuf::from("relative/manifest.json"));
        assert!(validate_tenant_resource_binding(&bad_path, "deployment-a").is_err());

        let mut bad_proxy = tenant_resource_binding(&root);
        bad_proxy.proxy = Some(ConformanceProxyRecovery {
            bundle_path: PathBuf::from("relative/proxy.pem"),
            reload_executable: root.join("reload-proxy"),
        });
        assert!(validate_tenant_resource_binding(&bad_proxy, "deployment-a").is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_receipt_cleanup_is_digest_fenced_and_idempotent() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        let receipt = tenant_resource_receipt(&binding);
        guard
            .record_tenant_resource_receipt(receipt.clone())
            .expect("persist verified receipt identity");
        guard
            .record_tenant_resource_receipt(receipt)
            .expect("receipt retry is idempotent");

        let identities = binding.resource_identities.clone();
        guard
            .record_tenant_resource_enumeration(identities.clone())
            .expect("persist enumerate result");
        guard
            .record_tenant_resource_enumeration(identities)
            .expect("enumerate retry is idempotent");

        let mut stale = tenant_resource_identity('a');
        stale.resource_id = "client-1".to_owned();
        assert!(
            guard
                .record_tenant_resource_revoke(&stale, TenantResourceRevokeOutcome::Revoked)
                .is_err()
        );
        let identity = binding.resource_identities[0].clone();
        guard
            .record_tenant_resource_revoke(&identity, TenantResourceRevokeOutcome::Revoked)
            .expect("digest-fenced revoke result");
        guard
            .record_tenant_resource_revoke(&identity, TenantResourceRevokeOutcome::Revoked)
            .expect("revoke retry is idempotent");
        assert!(guard.tenant_resource_cleanup_complete());
        drop(guard);

        let mut pending = store.claim_pending().expect("crash scan");
        let guard = pending.pop().expect("claimed completed tenant journal");
        assert!(guard.tenant_resource_cleanup_complete());
        guard.finish().expect("remove completed journal");
        assert!(
            !binding
                .manifest_path
                .as_ref()
                .expect("manifest path")
                .exists()
        );
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_proxy_restore_is_required_before_finish() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding_with_proxy(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("persist receipt");
        guard
            .record_tenant_resource_enumeration(binding.resource_identities.clone())
            .expect("persist enumeration");
        guard
            .record_tenant_resource_revoke(
                &binding.resource_identities[0],
                TenantResourceRevokeOutcome::Revoked,
            )
            .expect("persist revoke");
        assert!(guard.tenant_resource_cleanup_complete());
        assert!(!guard.proxy_cleanup_complete());
        drop(guard);

        let mut pending = store.claim_pending().expect("claim pending proxy restore");
        let guard = pending.pop().expect("claimed proxy journal");
        assert!(!guard.proxy_cleanup_complete());
        assert!(guard.finish().is_err());
        assert!(
            binding
                .manifest_path
                .as_ref()
                .expect("manifest path")
                .exists()
        );

        let mut pending = store.claim_pending().expect("claim retry proxy journal");
        let mut guard = pending.pop().expect("claimed retry journal");
        guard
            .mark_proxy_cleanup_complete()
            .expect("persist proxy restore");
        assert!(guard.proxy_cleanup_complete());
        guard.finish().expect("finish after proxy restore");
        assert!(
            !binding
                .manifest_path
                .as_ref()
                .expect("manifest path")
                .exists()
        );
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_proxy_pending_survives_crash_and_can_be_restored() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding_with_proxy(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("persist receipt before crash");
        drop(guard);

        // Simulate a crash after Apply (and possible proxy installation) but
        // before either proxy restore or ordinary-resource cleanup.
        let mut pending = store.claim_pending().expect("claim crashed journal");
        let mut guard = pending.pop().expect("claimed crashed journal");
        assert!(guard.tenant_resource_receipt().is_some());
        assert!(!guard.proxy_cleanup_complete());
        guard
            .mark_proxy_cleanup_complete()
            .expect("persist recovered proxy restore");
        assert!(guard.proxy_cleanup_complete());
        assert!(!guard.tenant_resource_cleanup_complete());
        drop(guard);

        let mut pending = store.claim_pending().expect("claim cleanup journal");
        let mut guard = pending.pop().expect("claimed cleanup journal");
        guard
            .record_tenant_resource_enumeration(binding.resource_identities.clone())
            .expect("persist recovered enumeration");
        guard
            .record_tenant_resource_revoke(
                &binding.resource_identities[0],
                TenantResourceRevokeOutcome::Revoked,
            )
            .expect("persist recovered revoke");
        assert!(guard.tenant_resource_cleanup_complete());
        guard.finish().expect("finish recovered proxy journal");
        assert!(
            !binding
                .manifest_path
                .as_ref()
                .expect("manifest path")
                .exists()
        );
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_deterministic_rejection_aborts_only_uncommitted_intent() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let manifest_path = binding.manifest_path.clone().expect("manifest path");
        let guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist rejected intent");
        guard
            .abort_uncommitted_tenant_resource()
            .expect("abort rejected intent");
        assert!(!manifest_path.exists());
        assert!(store.claim_pending().expect("final scan").is_empty());

        let mut committed = store
            .begin_tenant_resource(tenant_resource_binding(&root))
            .expect("persist committed intent");
        let committed_binding = committed
            .tenant_resource_binding()
            .expect("tenant binding")
            .clone();
        committed
            .record_tenant_resource_receipt(tenant_resource_receipt(&committed_binding))
            .expect("persist receipt");
        assert!(committed.abort_uncommitted_tenant_resource().is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_abort_recovers_after_manifest_unlink_crash() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let manifest_path = binding.manifest_path.clone().expect("manifest path");
        let mut guard = store
            .begin_tenant_resource(binding)
            .expect("persist rejected intent");
        if let RecoveryJournal::TenantResource(journal) = &mut guard.journal {
            journal.abort_uncommitted_intent = true;
            journal.manifest_removal_intent = true;
        }
        guard.persist().expect("persist abort intent");
        crate::secure_file::remove_file(&manifest_path, true).expect("simulate unlink");
        drop(guard);

        let mut pending = store.claim_pending().expect("recover aborted journal");
        let guard = pending.pop().expect("claimed aborted journal");
        assert!(guard.tenant_resource_abort_uncommitted_intent());
        assert!(guard.tenant_resource_manifest_cleanup_complete());
        guard
            .abort_uncommitted_tenant_resource()
            .expect("finish aborted journal");
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_manifest_tamper_blocks_receipt_persistence() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        std::fs::write(
            binding.manifest_path.as_ref().expect("manifest path"),
            b"tampered",
        )
        .expect("tamper manifest");
        assert!(
            guard
                .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
                .is_err()
        );
        drop(guard);
        assert!(store.claim_pending().is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_deleted_manifest_before_marker_is_recovered() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let manifest_path = binding.manifest_path.clone().expect("manifest path");
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("persist receipt");
        guard
            .record_tenant_resource_enumeration(binding.resource_identities.clone())
            .expect("persist enumeration");
        guard
            .record_tenant_resource_revoke(
                &binding.resource_identities[0],
                TenantResourceRevokeOutcome::Revoked,
            )
            .expect("persist revoke");
        if let RecoveryJournal::TenantResource(journal) = &mut guard.journal {
            journal.cleanup_complete = true;
            journal.manifest_removal_intent = true;
        }
        guard.persist().expect("persist removal intent");
        drop(guard);
        crate::secure_file::remove_file(&manifest_path, true).expect("simulate unlink");

        let mut pending = store.claim_pending().expect("recover deleted manifest");
        let guard = pending.pop().expect("claimed journal");
        match &guard.journal {
            RecoveryJournal::TenantResource(journal) => {
                assert!(journal.manifest_cleanup_complete);
            }
            RecoveryJournal::Legacy(_) => panic!("expected tenant-resource journal"),
        }
        guard.finish().expect("finish after recovered marker");
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_manifest_delete_failure_keeps_intent_for_retry() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let manifest_path = binding.manifest_path.clone().expect("manifest path");
        let manifest = br#"{"resources":["client-1"]}"#;
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("persist receipt");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("persist enumeration");
        if let RecoveryJournal::TenantResource(journal) = &mut guard.journal {
            journal.cleanup_complete = true;
            journal.manifest_removal_intent = true;
        }
        guard.persist().expect("persist removal intent");
        crate::secure_file::remove_file(&manifest_path, true).expect("remove manifest");
        std::fs::create_dir(&manifest_path).expect("replace with invalid directory");
        assert!(guard.finish().is_err());
        std::fs::remove_dir(&manifest_path).expect("remove invalid directory");
        crate::secure_file::write_atomic(&manifest_path, manifest, true).expect("restore manifest");

        let mut pending = store.claim_pending().expect("claim retry journal");
        let guard = pending.pop().expect("claimed retry journal");
        guard.finish().expect("retry manifest deletion");
        assert!(!manifest_path.exists());
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn tenant_resource_cleanup_accepts_an_already_absent_idempotent_retry() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-tenant-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("persist tenant intent");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("persist verified receipt identity");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("persist authenticated empty enumerate result");
        assert!(guard.tenant_resource_cleanup_complete());
        assert_eq!(
            guard
                .tenant_resource_revocations()
                .expect("tenant revocations")
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![Some(TenantResourceRevokeOutcome::AlreadyAbsent)]
        );
        guard.finish().expect("remove completed journal");
        assert!(store.claim_pending().expect("final scan").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn active_run_lock_is_skipped_and_crashed_journal_is_claimed_then_removed() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-recovery-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let guard = store.begin(binding()).expect("begin");
        let journal_path = root.join(format!(
            "run-{}.json",
            "request-0123456789abcdef0123456789abcdef"
        ));
        let legacy_journal = std::fs::read_to_string(&journal_path).expect("read legacy journal");
        assert!(legacy_journal.contains("\"schema\": 1"));
        assert!(!legacy_journal.contains("tenant-resource"));
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

    #[cfg(unix)]
    #[test]
    fn retained_suite_manifest_transfers_plan_ownership_only_after_pending_write() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-retention-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("intent");
        guard
            .begin_suite_create_with_retention(
                "https://www.certification.openid.net",
                "suite-intent-1",
                true,
            )
            .expect("Suite intent");
        guard
            .record_suite_plan(
                "https://www.certification.openid.net",
                "suite-intent-1",
                "suite-plan-1",
            )
            .expect("Suite plan");
        guard
            .begin_suite_create_with_retention(
                "https://www.certification.openid.net",
                "suite-intent-module-1",
                true,
            )
            .expect("Suite module intent");
        guard
            .record_suite_module("suite-intent-module-1", "suite-module-1")
            .expect("Suite module");
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        let retention_journal =
            std::fs::read_to_string(&journal_path).expect("read schema-three journal");
        assert!(retention_journal.contains("\"schema\": 3"));
        assert!(retention_journal.contains("suite_retention"));
        let manifest = SuiteRetentionManifest {
            schema: SUITE_RETENTION_MANIFEST_SCHEMA,
            suite_origin: "https://www.certification.openid.net".to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            run_id: binding.request_jti.clone(),
            review_screenshot_manifest: None,
            plans: vec![SuiteRetentionPlan {
                matrix_plan_id: "matrix-plan-1".to_owned(),
                suite_plan_id: "suite-plan-1".to_owned(),
                plan_name: "Certification plan".to_owned(),
                plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256("matrix-plan-1"),
            }],
        };
        let final_path = evidence.join(format!("retained-suite-{}.json", binding.request_jti));
        guard
            .prepare_suite_plan_retention(manifest, final_path.clone())
            .expect("prepare retention");
        assert_eq!(
            guard.suite_recovery().expect("suite").plan_ids,
            vec!["suite-plan-1".to_owned()]
        );
        assert!(guard.suite_recovery().expect("suite").module_ids.is_empty());
        guard
            .stage_suite_retention_manifest()
            .expect("stage manifest");
        assert!(!final_path.exists());
        assert!(guard.commit_suite_plan_retention().is_err());
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("enumeration");
        // A disk failure must not expose a compacted in-memory Retained
        // state: exact plan ownership remains available for recovery.
        guard.fail_next_persist_for_test();
        assert!(guard.commit_suite_plan_retention().is_err());
        assert!(!guard.suite_retention_committed());
        assert_eq!(
            guard.suite_recovery().expect("prepared suite").plan_ids,
            vec!["suite-plan-1".to_owned()]
        );
        guard
            .commit_suite_plan_retention()
            .expect("transfer ownership");
        assert!(guard.suite_recovery().expect("suite").plan_ids.is_empty());
        guard
            .publish_committed_suite_retention_manifest()
            .expect("publish manifest");
        let receipt = guard
            .suite_retention_manifest_receipt()
            .expect("retention receipt")
            .expect("committed receipt");
        assert_eq!(receipt.path, final_path);
        let manifest_bytes =
            crate::secure_file::read_bounded(&final_path, MAX_SUITE_RETENTION_MANIFEST_BYTES, true)
                .expect("read manifest");
        assert!(!String::from_utf8_lossy(&manifest_bytes).contains("capability.header.payload"));
        drop(guard);
        let mut recovered = store.claim_pending().expect("retained recovery");
        assert_eq!(recovered.len(), 1);
        assert!(
            recovered
                .pop()
                .expect("retained guard")
                .suite_retention_manifest_receipt()
                .expect("recovered receipt")
                .is_some()
        );
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn typed_screenshot_manifest_binds_real_png_receipt_and_exact_directory() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-screenshot-{}", uuid::Uuid::now_v7()));
        crate::secure_file::ensure_directory(&root, true).expect("test root");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let relative = PathBuf::from("review-screenshots")
            .join(&binding.request_jti)
            .join("matrix-plan-1--suite-module-1--000.png");
        let image_path = evidence.join(&relative);
        crate::secure_file::ensure_directory(image_path.parent().expect("image parent"), true)
            .expect("image directory");
        let png = STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .expect("one pixel png");
        crate::secure_file::write_atomic(&image_path, &png, true).expect("write png");
        let trigger_origin = "https://www.certification.openid.net";
        let trigger_path = "/test/a/suite-module-1/verification-evidence";
        let image_sha = sha256_hex(&png);
        let trigger_sha = sha256_hex(format!("{trigger_origin}{trigger_path}").as_bytes());
        let audit = serde_json::to_vec(&serde_json::json!({
            "suite_plan_id": "suite-plan-1",
            "module_id": "suite-module-1",
            "test_name": "browser-test",
            "variant": {"mode":"review"},
            "marker": "required",
            "obligation_index": 0,
            "path": relative.clone(),
            "sha256": image_sha.clone(),
            "size": png.len(),
            "trigger_origin": trigger_origin,
            "trigger_path": trigger_path,
            "trigger_url_sha256": trigger_sha.clone(),
        }))
        .expect("audit");
        let receipt_path = image_path.with_extension("png.receipt.json");
        crate::secure_file::write_atomic(&receipt_path, &audit, true).expect("write receipt");
        let screenshot_path = evidence
            .join("review-screenshot-manifests")
            .join(format!("{}.json", binding.request_jti));
        crate::secure_file::ensure_directory(
            screenshot_path.parent().expect("manifest parent"),
            true,
        )
        .expect("manifest directory");
        let document = serde_json::to_vec(&serde_json::json!({
            "schema": 3,
            "run_jti": binding.request_jti.clone(),
            "artifact_digest": "a".repeat(64),
            "matrix_sha256": "b".repeat(64),
            "suite_origin": trigger_origin,
            "modules": [{
                "matrix_plan_id": "matrix-plan-1", "suite_plan_id": "suite-plan-1",
                "module_id": "suite-module-1", "test_name": "browser-test",
                "variant": {"mode":"review"}, "required": 1,
                "captured_required": 1, "missing_optional": 0
            }],
            "screenshots": [{
                "matrix_plan_id": "matrix-plan-1", "suite_plan_id": "suite-plan-1",
                "module_id": "suite-module-1", "test_name": "browser-test",
                "variant": {"mode":"review"}, "marker": "required", "obligation_index": 0,
                "path": relative.clone(), "sha256": image_sha.clone(), "size": png.len(),
                "receipt_sha256": sha256_hex(&audit), "trigger_origin": trigger_origin,
                "trigger_path": trigger_path, "trigger_url_sha256": trigger_sha.clone()
            }]
        }))
        .expect("typed manifest");
        crate::secure_file::write_atomic(&screenshot_path, &document, true)
            .expect("write manifest");
        let retention = SuiteRetentionManifest {
            schema: SUITE_RETENTION_MANIFEST_SCHEMA,
            suite_origin: trigger_origin.to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            run_id: binding.request_jti.clone(),
            review_screenshot_manifest: None,
            plans: vec![SuiteRetentionPlan {
                matrix_plan_id: "matrix-plan-1".to_owned(),
                suite_plan_id: "suite-plan-1".to_owned(),
                plan_name: "Certification plan".to_owned(),
                plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256("matrix-plan-1"),
            }],
        };
        let bound = SuiteRetentionScreenshotManifest {
            path: screenshot_path,
            sha256: sha256_hex(&document),
        };
        validate_review_screenshot_manifest_binding(&bound, &retention, &binding)
            .expect("complete typed chain");
        let extra = image_path.parent().expect("image parent").join("extra.png");
        crate::secure_file::write_atomic(&extra, &png, true).expect("extra image");
        assert!(validate_review_screenshot_manifest_binding(&bound, &retention, &binding).is_err());
        std::fs::remove_file(&extra).expect("remove extra");
        std::fs::remove_file(&receipt_path).expect("remove receipt");
        assert!(validate_review_screenshot_manifest_binding(&bound, &retention, &binding).is_err());
        crate::secure_file::write_atomic(&receipt_path, &audit, true).expect("restore receipt");
        crate::secure_file::write_atomic(&image_path, b"not-a-png", true).expect("tamper png");
        assert!(validate_review_screenshot_manifest_binding(&bound, &retention, &binding).is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn retained_suite_screenshot_manifest_tamper_blocks_commit_and_finish() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-retention-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("intent");
        guard
            .begin_suite_create_with_retention(
                "https://www.certification.openid.net",
                "suite-intent-1",
                true,
            )
            .expect("Suite intent");
        guard
            .record_suite_plan(
                "https://www.certification.openid.net",
                "suite-intent-1",
                "suite-plan-1",
            )
            .expect("Suite plan");

        let screenshot_directory = evidence.join("review-screenshot-manifests");
        crate::secure_file::ensure_directory(&screenshot_directory, true)
            .expect("screenshot manifest directory");
        let screenshot_path = screenshot_directory.join(format!("{}.json", binding.request_jti));
        let original = serde_json::to_vec(&serde_json::json!({
            "schema": 3,
            "run_jti": binding.request_jti,
            "artifact_digest": "a".repeat(64),
            "matrix_sha256": "b".repeat(64),
            "suite_origin": "https://www.certification.openid.net",
            "modules": [{
                "matrix_plan_id": "matrix-plan-1",
                "suite_plan_id": "suite-plan-1",
                "module_id": "suite-module-1",
                "test_name": "test",
                "variant": {},
                "required": 0,
                "captured_required": 0,
                "missing_optional": 0
            }],
            "screenshots": []
        }))
        .expect("serialize screenshot manifest");
        crate::secure_file::write_atomic(&screenshot_path, &original, true)
            .expect("write screenshot manifest");
        let manifest = SuiteRetentionManifest {
            schema: SUITE_RETENTION_MANIFEST_SCHEMA,
            suite_origin: "https://www.certification.openid.net".to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            run_id: binding.request_jti.clone(),
            review_screenshot_manifest: Some(SuiteRetentionScreenshotManifest {
                path: screenshot_path.clone(),
                sha256: sha256_hex(&original),
            }),
            plans: vec![SuiteRetentionPlan {
                matrix_plan_id: "matrix-plan-1".to_owned(),
                suite_plan_id: "suite-plan-1".to_owned(),
                plan_name: "Certification plan".to_owned(),
                plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256("matrix-plan-1"),
            }],
        };
        let final_path = evidence.join(format!("retained-suite-{}.json", binding.request_jti));
        guard
            .prepare_suite_plan_retention(manifest, final_path)
            .expect("prepare retention");
        guard
            .stage_suite_retention_manifest()
            .expect("stage retention manifest");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("enumeration");
        crate::secure_file::write_atomic(&screenshot_path, b"tampered", true)
            .expect("tamper screenshot manifest");
        assert!(guard.commit_suite_plan_retention().is_err());

        crate::secure_file::write_atomic(&screenshot_path, &original, true)
            .expect("restore screenshot manifest");
        guard
            .commit_suite_plan_retention()
            .expect("commit retention");
        guard
            .publish_committed_suite_retention_manifest()
            .expect("publish retention manifest");
        crate::secure_file::write_atomic(&screenshot_path, b"tampered", true)
            .expect("tamper retained screenshot manifest");
        assert!(guard.finish().is_err());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_retention_compacts_1198_terminal_modules_below_shared_manifest_cap() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-retention-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("intent");
        guard
            .begin_suite_create_with_retention(
                "https://www.certification.openid.net",
                "suite-intent-1",
                true,
            )
            .expect("Suite intent");
        guard
            .record_suite_plan(
                "https://www.certification.openid.net",
                "suite-intent-1",
                "suite-plan-0",
            )
            .expect("Suite plan");
        let suite = guard
            .tenant_resource_journal_mut()
            .expect("tenant journal")
            .suite
            .as_mut()
            .expect("Suite recovery");
        suite.plan_ids = (0..44).map(|index| format!("suite-plan-{index}")).collect();
        suite.module_ids = (0..1198)
            .map(|index| format!("suite-module-{index}"))
            .collect();
        let plans = (0..44)
            .map(|index| {
                let matrix_plan_id = format!("matrix-plan-{index}");
                SuiteRetentionPlan {
                    plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256(&matrix_plan_id),
                    matrix_plan_id,
                    suite_plan_id: format!("suite-plan-{index}"),
                    plan_name: format!("Certification plan {index}"),
                }
            })
            .collect();
        let manifest = SuiteRetentionManifest {
            schema: SUITE_RETENTION_MANIFEST_SCHEMA,
            suite_origin: "https://www.certification.openid.net".to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            run_id: binding.request_jti.clone(),
            review_screenshot_manifest: None,
            plans,
        };
        let final_path = evidence.join(format!("retained-suite-{}.json", binding.request_jti));
        guard
            .prepare_suite_plan_retention(manifest, final_path)
            .expect("prepare retention");
        let suite = guard.suite_recovery().expect("prepared Suite recovery");
        assert_eq!(suite.plan_ids.len(), 44);
        assert!(suite.module_ids.is_empty());
        let journal_path = root.join(format!("run-{}.json", binding.request_jti));
        assert!(
            std::fs::metadata(&journal_path)
                .expect("prepared journal metadata")
                .len()
                < MAX_RECOVERY_JOURNAL_BYTES as u64
        );
        assert!(
            std::fs::metadata(&journal_path)
                .expect("prepared journal metadata")
                .len()
                < crate::evidence::MAX_REVIEW_SCREENSHOT_MANIFEST_BYTES as u64
        );
        drop(guard);
        let mut pending = store.claim_pending().expect("claim prepared journal");
        let claimed = pending.pop().expect("prepared guard");
        let suite = claimed.suite_recovery().expect("prepared Suite recovery");
        assert_eq!(suite.plan_ids.len(), 44);
        assert!(suite.module_ids.is_empty());
        drop(claimed);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
