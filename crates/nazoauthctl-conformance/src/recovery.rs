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
/// Schema 3 is the first retention journal format. It stays readable for
/// previously completed/Retained runs but is never emitted by new capture
/// runs.
const RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA: u32 = 3;
/// Schema 4 adds a durable provider-evidence state machine. New retention
/// runs persist an Intent before creating any provider evidence directory.
const RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA: u32 = 4;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_evidence: Option<SuiteRetentionProviderEvidence>,
    pub plans: Vec<SuiteRetentionPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionScreenshotManifest {
    pub path: PathBuf,
    pub sha256: String,
}

/// A provider evidence bundle is staged before plan ownership is transferred.
/// The retention journal binds its root-private directory and immutable
/// manifest digest so a crash cannot later report an unrelated bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionProviderEvidence {
    pub directory: PathBuf,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum SuiteRetentionProviderState {
    None,
    Intent {
        pending_directory: PathBuf,
        final_directory: PathBuf,
    },
    Staged {
        pending_directory: PathBuf,
        final_directory: PathBuf,
        manifest_sha256: String,
    },
    Final {
        evidence: SuiteRetentionProviderEvidence,
    },
    CleanupIntent {
        pending_directory: PathBuf,
        manifest_sha256: Option<String>,
    },
}

impl Default for SuiteRetentionProviderState {
    fn default() -> Self {
        Self::None
    }
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
    #[serde(
        default,
        skip_serializing_if = "suite_retention_provider_state_is_none"
    )]
    provider_state: SuiteRetentionProviderState,
}

fn suite_retention_provider_state_is_none(value: &SuiteRetentionProviderState) -> bool {
    matches!(value, SuiteRetentionProviderState::None)
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
        const RETAINING_PROVIDER_EVIDENCE_SCHEMA: u64 =
            RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA as u64;
        match schema {
            LEGACY_SCHEMA => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::Legacy)
                .map_err(serde::de::Error::custom),
            TENANT_RESOURCE_SCHEMA
            | RETAINING_TENANT_RESOURCE_SCHEMA
            | RETAINING_PROVIDER_EVIDENCE_SCHEMA => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::TenantResource)
                .map_err(serde::de::Error::custom),
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
                if matches!(
                    tenant_journal.schema,
                    RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
                        | RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA
                ) && matches!(
                    &tenant_journal.suite_retention,
                    SuiteRetentionDisposition::Active { .. }
                ) {
                    tenant_journal.suite_retention = SuiteRetentionDisposition::Cleaned;
                }
                normalized_suite_cleanup = true;
            }
            // A Retained provider bundle may still be in its private pending
            // namespace. Do not publish the Suite manifest from claim_pending:
            // `finish` owns the ordered provider promotion -> manifest restage
            // -> final publish transition and can retry it without deleting
            // the retained plans.
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
            if recovered_manifest_removal || normalized_proxy_cleanup || normalized_suite_cleanup {
                validate_journal(&journal, &self.deployment_id, request_jti)?;
                write_journal(&journal_path, &journal)?;
            }
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
                    journal.schema = RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA;
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
        if matches!(
            journal.schema,
            RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
                | RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA
        ) {
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
        validate_suite_retention_manifest(&manifest, &journal.binding, Some(suite), false)?;
        let bytes = canonical_suite_retention_manifest(&manifest)?;
        let provider_state =
            if journal.schema == RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA {
                let evidence_root = manifest_path
                    .parent()
                    .context("Suite retention manifest has no evidence parent")?;
                let evidence_root = crate::secure_file::validate_directory(evidence_root, true)
                    .map_err(|error| {
                        anyhow::anyhow!("provider evidence root is not secure: {error:?}")
                    })?;
                SuiteRetentionProviderState::Intent {
                    pending_directory: evidence_root
                        .join(".pending-provider")
                        .join(&journal.binding.request_jti),
                    final_directory: evidence_root
                        .join("provider-evidence")
                        .join(&journal.binding.request_jti),
                }
            } else {
                SuiteRetentionProviderState::None
            };
        let record = SuiteRetentionRecord {
            manifest,
            manifest_sha256: sha256_hex(&bytes),
            manifest_path,
            provider_state,
        };
        // Retention eligibility is evaluated only after every allocated
        // module has reached a terminal state. Prepared fallback cleanup
        // therefore needs exact plan IDs, not the potentially 16k module ID
        // inventory: plan deletion removes the terminal modules with it.
        suite.module_ids.clear();
        journal.suite_retention = SuiteRetentionDisposition::RetentionPrepared { record };
        self.persist()
    }

    /// Bind a fully fsynced provider evidence bundle while Suite plans remain
    /// journal-owned. The later Retained transition therefore cannot expose a
    /// receipt whose report was not part of the exact recovery record.
    pub fn bind_prepared_suite_provider_evidence(
        &mut self,
        provider_evidence: SuiteRetentionProviderEvidence,
    ) -> anyhow::Result<()> {
        let binding = self
            .tenant_resource_binding()
            .context("Suite retention has no ordinary binding")?
            .clone();
        let suite = self
            .suite_recovery()
            .context("Suite retention has no persisted allocation")?
            .clone();
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite retention is not valid for a legacy journal")?;
        let SuiteRetentionDisposition::RetentionPrepared { record } = &mut journal.suite_retention
        else {
            bail!("Suite retention has not been prepared");
        };
        let (pending_directory, final_directory) = match &record.provider_state {
            SuiteRetentionProviderState::Intent {
                pending_directory,
                final_directory,
            } => (pending_directory.clone(), final_directory.clone()),
            _ => bail!("Suite retention provider evidence was not prepared"),
        };
        if provider_evidence.directory != pending_directory {
            bail!("staged provider evidence path conflicts with the recovery intent");
        }
        validate_suite_retention_provider_evidence(
            &provider_evidence,
            &binding,
            &record.manifest,
            false,
            None,
        )?;
        record.provider_state = SuiteRetentionProviderState::Staged {
            pending_directory,
            final_directory,
            manifest_sha256: provider_evidence.manifest_sha256,
        };
        self.persist()
    }

    /// Write a non-final pending manifest only after all non-Suite cleanup
    /// obligations have completed. The journal remains `Prepared`, so a
    /// crash here still defaults to deletion of the Suite allocation.
    pub fn stage_suite_retention_manifest(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::RetentionPrepared { record }
                | SuiteRetentionDisposition::Retained { record } => record,
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
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
            )?;
        }
        let path = self.suite_retention_pending_path()?;
        match crate::secure_file::read_bounded(&path, MAX_SUITE_RETENTION_MANIFEST_BYTES, true) {
            Ok(existing) if sha256_hex(&existing) == record.manifest_sha256 => return Ok(path),
            // This pending file is journal-owned and has not been published.
            // A Retained provider promotion updates its bound path/digest, so
            // replace only this private staging file before final publish.
            Ok(_) => {}
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
        }
        crate::secure_file::write_atomic(&path, &bytes, true).map_err(|error| {
            anyhow::anyhow!("failed to stage retained Suite manifest: {error:?}")
        })?;
        Ok(path)
    }

    /// Promote the journal-bound provider evidence only after Suite ownership
    /// has moved to Retained. The directory name is deterministic from the
    /// run binding; no caller-controlled path is accepted here.
    pub fn publish_retained_provider_evidence(
        &mut self,
    ) -> anyhow::Result<SuiteRetentionProviderEvidence> {
        let (
            pending,
            final_directory,
            manifest_sha256,
            already_published,
            schema_four,
            binding,
            manifest_path,
        ) = {
            let journal = self
                .tenant_resource_journal()
                .context("Suite retention is not valid for a legacy journal")?;
            let SuiteRetentionDisposition::Retained { record } = &journal.suite_retention else {
                bail!("Suite retention has not been committed");
            };
            if let SuiteRetentionProviderState::Final { evidence } = &record.provider_state {
                validate_suite_retention_provider_evidence(
                    evidence,
                    &journal.binding,
                    &record.manifest,
                    journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
                    Some(&record.manifest_path),
                )?;
                return Ok(evidence.clone());
            }
            let legacy_schema = journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA;
            let (provider, final_directory, already_published) = match &record.provider_state {
                SuiteRetentionProviderState::Staged {
                    pending_directory,
                    final_directory,
                    manifest_sha256,
                } => (
                    SuiteRetentionProviderEvidence {
                        directory: pending_directory.clone(),
                        manifest_sha256: manifest_sha256.clone(),
                    },
                    final_directory.clone(),
                    false,
                ),
                _ if legacy_schema => {
                    let provider = record
                        .manifest
                        .provider_evidence
                        .clone()
                        .context("legacy retained Suite journal has no provider evidence")?;
                    (provider.clone(), provider.directory.clone(), true)
                }
                _ => bail!("retained Suite journal has no staged provider evidence"),
            };
            if !legacy_schema {
                let namespace = provider
                    .directory
                    .parent()
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str());
                if provider
                    .directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(record.manifest.run_id.as_str())
                    || !matches!(
                        namespace,
                        Some(".pending-provider") | Some("provider-evidence")
                    )
                {
                    bail!("provider evidence pending path is outside policy");
                }
            }
            (
                provider.directory.clone(),
                final_directory,
                provider.manifest_sha256.clone(),
                already_published,
                journal.schema == RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA,
                journal.binding.clone(),
                record.manifest_path.clone(),
            )
        };
        if !already_published {
            let final_parent = final_directory
                .parent()
                .context("provider evidence final path is invalid")?;
            crate::secure_file::ensure_directory(final_parent, true).map_err(|error| {
                anyhow::anyhow!("provider evidence final directory is not secure: {error:?}")
            })?;
            match crate::secure_file::validate_directory(&pending, true) {
                Ok(_) => crate::secure_file::promote_private_directory(&pending, &final_directory)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish provider evidence: {error:?}")
                    })?,
                Err(crate::secure_file::SecureFileError::NotFound) => {
                    let adopted = SuiteRetentionProviderEvidence {
                        directory: final_directory.clone(),
                        manifest_sha256: manifest_sha256.clone(),
                    };
                    let manifest = self
                        .suite_retention_manifest()
                        .context("retained Suite journal has no manifest")?;
                    validate_suite_retention_provider_evidence(
                        &adopted, &binding, manifest, false, None,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("provider evidence promotion cannot be adopted: {error:#}")
                    })?;
                }
                Err(error) => {
                    bail!("provider evidence pending directory is not secure: {error:?}")
                }
            }
        }
        let published = SuiteRetentionProviderEvidence {
            directory: final_directory,
            manifest_sha256,
        };
        let manifest = self
            .suite_retention_manifest()
            .context("retained Suite journal has no manifest")?;
        validate_suite_retention_provider_evidence(
            &published,
            &binding,
            manifest,
            !schema_four,
            Some(&manifest_path),
        )?;
        let journal = self
            .tenant_resource_journal_mut()
            .context("Suite retention is not valid for a legacy journal")?;
        let SuiteRetentionDisposition::Retained { record } = &mut journal.suite_retention else {
            bail!("Suite retention has not been committed");
        };
        record.manifest.provider_evidence = Some(published.clone());
        if schema_four {
            record.provider_state = SuiteRetentionProviderState::Final {
                evidence: published.clone(),
            };
        }
        record.manifest_sha256 = sha256_hex(&canonical_suite_retention_manifest(&record.manifest)?);
        self.persist()?;
        Ok(published)
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
                SuiteRetentionDisposition::RetentionPrepared { record }
                    if journal.schema == RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA
                        && !matches!(
                            &record.provider_state,
                            SuiteRetentionProviderState::Staged { .. }
                        ) =>
                {
                    bail!("schema-4 retained Suite journals require staged provider evidence")
                }
                SuiteRetentionDisposition::RetentionPrepared { record } => record.clone(),
                _ => bail!("Suite retention has not been prepared"),
            },
            RecoveryJournal::Legacy(_) => {
                bail!("Suite retention is not valid for a legacy journal")
            }
        };
        let bytes =
            crate::secure_file::read_bounded(&pending, MAX_SUITE_RETENTION_MANIFEST_BYTES, true)
                .map_err(|error| {
                    anyhow::anyhow!("retained Suite pending manifest is not secure: {error:?}")
                })?;
        if sha256_hex(&bytes) != record.manifest_sha256 {
            bail!("retained Suite pending manifest conflicts with the journal");
        }
        let journal = self
            .tenant_resource_journal_mut()
            .expect("tenant-resource journal was just verified");
        {
            let suite = journal
                .suite
                .as_mut()
                .context("Suite retention has no persisted allocation")?;
            suite.plan_ids.clear();
            suite.module_ids.clear();
        }
        journal.suite_retention = SuiteRetentionDisposition::Retained { record };
        self.persist()
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
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
            )?;
        }
        if let Some(provider) = &record.manifest.provider_evidence {
            validate_suite_retention_provider_evidence(
                provider,
                self.tenant_resource_binding()
                    .context("Suite retention has no ordinary binding")?,
                &record.manifest,
                match &self.journal {
                    RecoveryJournal::TenantResource(journal) => {
                        journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
                    }
                    RecoveryJournal::Legacy(_) => false,
                },
                Some(&record.manifest_path),
            )?;
        } else {
            bail!("retained Suite journal has no provider evidence");
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

    pub fn suite_retention_committed(&self) -> bool {
        matches!(
            &self.journal,
            RecoveryJournal::TenantResource(journal)
                if matches!(&journal.suite_retention, SuiteRetentionDisposition::Retained { .. })
        )
    }

    /// A prepared-but-uncommitted retention is ordinary cleanup state. Remove
    /// only its non-final staging file before deleting the journal-owned plans.
    pub fn discard_prepared_suite_retention_staging(&mut self) -> anyhow::Result<()> {
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
        let provider_cleanup = {
            let journal = self
                .tenant_resource_journal_mut()
                .context("Suite retention is not valid for a legacy journal")?;
            let SuiteRetentionDisposition::RetentionPrepared { record } =
                &mut journal.suite_retention
            else {
                bail!("Suite retention is no longer prepared");
            };
            let provider_cleanup = match &record.provider_state {
                SuiteRetentionProviderState::Intent {
                    pending_directory, ..
                } => (pending_directory.clone(), None),
                SuiteRetentionProviderState::Staged {
                    pending_directory,
                    manifest_sha256,
                    ..
                } => (pending_directory.clone(), Some(manifest_sha256.clone())),
                SuiteRetentionProviderState::CleanupIntent {
                    pending_directory,
                    manifest_sha256,
                } => (pending_directory.clone(), manifest_sha256.clone()),
                SuiteRetentionProviderState::None | SuiteRetentionProviderState::Final { .. } => {
                    bail!("prepared Suite journal has invalid provider cleanup state")
                }
            };
            record.provider_state = SuiteRetentionProviderState::CleanupIntent {
                pending_directory: provider_cleanup.0.clone(),
                manifest_sha256: provider_cleanup.1.clone(),
            };
            provider_cleanup
        };
        // Persist intent before removing either Suite or provider staging so a
        // crash resumes the same bounded cleanup rather than retaining plans.
        self.persist()?;
        let pending = self.suite_retention_pending_path()?;
        match crate::secure_file::remove_file(&pending, true) {
            Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("failed to discard staged Suite retention manifest: {error:?}"),
        }
        match crate::secure_file::validate_directory(&provider_cleanup.0, true) {
            Ok(_) => {
                if let Some(manifest_sha256) = provider_cleanup.1 {
                    crate::evidence::discard_staged_private_provider_evidence_bundle(
                        &provider_cleanup.0,
                        &manifest_sha256,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("failed to discard staged provider evidence: {error:?}")
                    })?;
                } else {
                    crate::evidence::discard_incomplete_staged_private_provider_evidence_bundle(
                        &provider_cleanup.0,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("failed to discard incomplete provider evidence: {error:?}")
                    })?;
                }
            }
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("provider evidence staging directory is not secure: {error:?}"),
        }
        Ok(())
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

    fn tenant_resource_journal(&self) -> Option<&TenantResourceRecoveryJournal> {
        match &self.journal {
            RecoveryJournal::TenantResource(journal) => Some(journal),
            RecoveryJournal::Legacy(_) => None,
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
            self.publish_retained_provider_evidence()?;
            // A crash between the provider directory promotion and final Suite
            // manifest publication leaves a Retained journal. Recreate its
            // private pending manifest from the authoritative journal before
            // the final no-replace promotion.
            if !self.suite_retention_manifest_is_published()? {
                self.stage_suite_retention_manifest()?;
                self.publish_committed_suite_retention_manifest()?;
            }
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

    fn suite_retention_manifest_is_published(&self) -> anyhow::Result<bool> {
        let record = match &self.journal {
            RecoveryJournal::TenantResource(journal) => match &journal.suite_retention {
                SuiteRetentionDisposition::Retained { record } => record,
                _ => return Ok(false),
            },
            RecoveryJournal::Legacy(_) => return Ok(false),
        };
        match crate::secure_file::read_bounded(
            &record.manifest_path,
            MAX_SUITE_RETENTION_MANIFEST_BYTES,
            true,
        ) {
            Ok(bytes) => {
                if sha256_hex(&bytes) != record.manifest_sha256 {
                    bail!("retained Suite manifest conflicts with the recovery journal");
                }
                Ok(true)
            }
            Err(crate::secure_file::SecureFileError::NotFound) => Ok(false),
            Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
        }
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
        validate_journal(
            &self.journal,
            &self.store.deployment_id,
            self.journal.request_jti(),
        )?;
        if let RecoveryJournal::TenantResource(journal) = &self.journal
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
        write_journal(&self.journal_path, &self.journal)
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
                    | RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA
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
    if matches!(
        journal.schema,
        RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
            | RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA
    ) && SuiteRetentionDisposition::is_default(&journal.suite_retention)
    {
        bail!("retaining recovery journal has no explicit retention policy");
    }
    if journal.schema == RETAINING_PROVIDER_EVIDENCE_RECOVERY_JOURNAL_SCHEMA {
        match &journal.suite_retention {
            SuiteRetentionDisposition::RetentionPrepared { record }
                if !matches!(
                    &record.provider_state,
                    SuiteRetentionProviderState::Intent { .. }
                        | SuiteRetentionProviderState::Staged { .. }
                        | SuiteRetentionProviderState::CleanupIntent { .. }
                ) =>
            {
                bail!("schema-4 prepared retention has no provider staging state")
            }
            SuiteRetentionDisposition::Retained { record }
                if !matches!(
                    &record.provider_state,
                    SuiteRetentionProviderState::Staged { .. }
                        | SuiteRetentionProviderState::Final { .. }
                ) =>
            {
                bail!("schema-4 retained Suite plans have no staged provider evidence")
            }
            _ => {}
        }
        if let SuiteRetentionDisposition::RetentionPrepared { record }
        | SuiteRetentionDisposition::Retained { record } = &journal.suite_retention
        {
            validate_suite_retention_provider_state(record, &journal.binding)?;
        }
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
            validate_suite_retention_record(
                record,
                &journal.binding,
                suite,
                journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
            )?;
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
            validate_suite_retention_record_without_inventory(
                record,
                &journal.binding,
                journal.schema == RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
            )?;
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

fn validate_suite_retention_provider_state(
    record: &SuiteRetentionRecord,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let evidence_root = record
        .manifest_path
        .parent()
        .context("schema-4 Suite retention manifest has no evidence root")?;
    let pending = evidence_root
        .join(".pending-provider")
        .join(&binding.request_jti);
    let final_directory = evidence_root
        .join("provider-evidence")
        .join(&binding.request_jti);
    match &record.provider_state {
        SuiteRetentionProviderState::Intent {
            pending_directory,
            final_directory: declared_final,
        } if pending_directory == &pending && declared_final == &final_directory => Ok(()),
        SuiteRetentionProviderState::Staged {
            pending_directory,
            final_directory: declared_final,
            manifest_sha256,
        } if pending_directory == &pending
            && declared_final == &final_directory
            && lower_hex(manifest_sha256, 64) =>
        {
            Ok(())
        }
        SuiteRetentionProviderState::Final { evidence }
            if evidence.directory == final_directory
                && lower_hex(&evidence.manifest_sha256, 64) =>
        {
            Ok(())
        }
        SuiteRetentionProviderState::CleanupIntent {
            pending_directory,
            manifest_sha256,
        } if pending_directory == &pending
            && manifest_sha256
                .as_deref()
                .is_none_or(|digest| lower_hex(digest, 64)) =>
        {
            Ok(())
        }
        _ => bail!("schema-4 provider evidence state conflicts with its recovery binding"),
    }
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
    legacy_read_only: bool,
) -> anyhow::Result<()> {
    validate_suite_retention_manifest(&record.manifest, binding, Some(suite), legacy_read_only)?;
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
    legacy_read_only: bool,
) -> anyhow::Result<()> {
    validate_suite_retention_manifest(&record.manifest, binding, None, legacy_read_only)?;
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
    legacy_read_only: bool,
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
        validate_review_screenshot_manifest_binding(screenshot, binding)?;
    }
    if let Some(provider_evidence) = &manifest.provider_evidence
        && !legacy_read_only
    {
        validate_suite_retention_provider_evidence(
            provider_evidence,
            binding,
            manifest,
            false,
            None,
        )?;
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
    let bytes = crate::secure_file::read_bounded(&screenshot.path, 1024 * 1024, true)
        .map_err(|error| anyhow::anyhow!("review screenshot manifest is not secure: {error:?}"))?;
    if sha256_hex(&bytes) != screenshot.sha256 {
        bail!("review screenshot manifest digest is invalid");
    }
    Ok(())
}

fn validate_suite_retention_provider_evidence(
    provider_evidence: &SuiteRetentionProviderEvidence,
    binding: &TenantResourceRecoveryBinding,
    manifest: &SuiteRetentionManifest,
    legacy_provider_layout: bool,
    legacy_manifest_path: Option<&Path>,
) -> anyhow::Result<()> {
    if !provider_evidence.directory.is_absolute()
        || !lower_hex(&provider_evidence.manifest_sha256, 64)
    {
        bail!("provider evidence binding is outside policy");
    }
    let namespace = provider_evidence
        .directory
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str());
    let canonical_layout = matches!(
        namespace,
        Some(".pending-provider") | Some("provider-evidence")
    ) && provider_evidence
        .directory
        .file_name()
        .and_then(|name| name.to_str())
        == Some(binding.request_jti.as_str());
    let legacy_layout = legacy_manifest_path
        .and_then(Path::parent)
        .is_some_and(|root| provider_evidence.directory.parent() == Some(root))
        && provider_evidence
            .directory
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("run-"))
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok());
    if !canonical_layout && !(legacy_provider_layout && legacy_layout) {
        bail!("provider evidence path is outside the retained run policy");
    }
    let verified = crate::evidence::verify_private_provider_evidence_bundle(
        &provider_evidence.directory,
        &provider_evidence.manifest_sha256,
    )
    .map_err(|error| anyhow::anyhow!("provider evidence bundle is invalid: {error:?}"))?;
    if verified.identity.run_jti != binding.request_jti
        || (!legacy_provider_layout && verified.receipt.evidence_jti != binding.request_jti)
    {
        bail!("provider evidence JTI conflicts with the retained run binding");
    }
    if verified.identity.deployment.deployment_id != manifest.deployment_id
        || verified.report.suite_origin != manifest.suite_origin
        || verified.report.matrix_digest != manifest.matrix_sha256
    {
        bail!("provider evidence deployment, Suite, or matrix identity conflicts with retention");
    }
    let crate::evidence::EvidenceSourceIdentity::SignedOidfArtifact {
        suite_origin,
        artifact_digest,
        artifact,
    } = &verified.identity.source
    else {
        bail!("retained provider evidence must be sourced from a signed OIDF artifact");
    };
    if artifact_digest != &manifest.artifact_digest
        || suite_origin != &manifest.suite_origin
        || artifact.suite.origin != manifest.suite_origin
        || artifact.matrix_sha256 != manifest.matrix_sha256
    {
        bail!("provider evidence artifact conflicts with retained Suite identity");
    }
    let provider = verified
        .identity
        .provider
        .as_ref()
        .context("provider evidence has no provider capability identity")?;
    if provider.deployment_id != manifest.deployment_id
        || provider
            .capabilities
            .iter()
            .any(|capability| capability.tenant_id != manifest.tenant_id)
    {
        bail!("provider evidence capability tenant conflicts with retention");
    }
    let expected_plans = manifest
        .plans
        .iter()
        .map(|plan| (&plan.matrix_plan_id, &plan.suite_plan_id))
        .collect::<std::collections::BTreeSet<_>>();
    let observed_plans = verified
        .report
        .modules
        .iter()
        .map(|module| {
            if !module.terminal || module.module_id.is_none() {
                bail!("provider evidence contains a nonterminal or unowned module");
            }
            Ok((&module.matrix_plan_id, &module.suite_plan_id))
        })
        .collect::<anyhow::Result<std::collections::BTreeSet<_>>>()?;
    if observed_plans != expected_plans {
        bail!("provider evidence module ownership does not exactly match retained plans");
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
            std::fs::read_to_string(&journal_path).expect("read schema-four journal");
        assert!(retention_journal.contains("\"schema\": 4"));
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
            provider_evidence: None,
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
        let retained = guard
            .suite_retention_manifest()
            .expect("retention manifest")
            .clone();
        let (report, identity) =
            crate::evidence::test_support::retained_provider_fixture(&binding, &retained);
        let staged = crate::evidence::stage_private_provider_evidence_bundle(
            &report,
            &evidence,
            &identity,
            &binding.request_jti,
        )
        .expect("stage provider evidence");
        let expected_pending = evidence
            .join(".pending-provider")
            .join(&binding.request_jti);
        assert_eq!(staged.directory, expected_pending);
        let staged_binding = SuiteRetentionProviderEvidence {
            directory: staged.directory.clone(),
            manifest_sha256: staged.manifest_sha256.clone(),
        };
        let mut wrong_tenant = retained.clone();
        wrong_tenant.tenant_id = "00000000-0000-4000-8000-000000000002".to_owned();
        assert!(
            validate_suite_retention_provider_evidence(
                &staged_binding,
                &binding,
                &wrong_tenant,
                false,
                None,
            )
            .is_err()
        );
        let mut wrong_artifact = retained.clone();
        wrong_artifact.artifact_digest = "c".repeat(64);
        assert!(
            validate_suite_retention_provider_evidence(
                &staged_binding,
                &binding,
                &wrong_artifact,
                false,
                None,
            )
            .is_err()
        );
        let mut wrong_plan = retained.clone();
        wrong_plan.plans[0].matrix_plan_id = "matrix-plan-2".to_owned();
        wrong_plan.plans[0].plan_alias_sha256 =
            SuiteRetentionManifest::plan_alias_sha256("matrix-plan-2");
        assert!(
            validate_suite_retention_provider_evidence(
                &staged_binding,
                &binding,
                &wrong_plan,
                false,
                None,
            )
            .is_err()
        );
        guard
            .stage_suite_retention_manifest()
            .expect("stage manifest");
        assert!(!final_path.exists());
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("enumeration");
        let error = guard
            .commit_suite_plan_retention()
            .expect_err("schema-four commit requires staged provider evidence");
        assert!(
            error
                .to_string()
                .contains("require staged provider evidence")
        );
        guard
            .bind_prepared_suite_provider_evidence(SuiteRetentionProviderEvidence {
                directory: staged_binding.directory.clone(),
                manifest_sha256: staged_binding.manifest_sha256.clone(),
            })
            .expect("bind provider evidence");
        guard
            .commit_suite_plan_retention()
            .expect("transfer ownership");
        assert!(guard.suite_recovery().expect("suite").plan_ids.is_empty());
        let published_provider = guard
            .publish_retained_provider_evidence()
            .expect("publish provider evidence");
        assert_eq!(
            published_provider.directory,
            evidence
                .join("provider-evidence")
                .join(&binding.request_jti)
        );
        assert!(!expected_pending.exists());
        assert!(published_provider.directory.exists());
        // Simulate a crash after the no-replace directory promotion and
        // before the Retained journal records Final. Recovery must adopt the
        // exact final directory; it must not attempt another rename or delete
        // the transferred Suite plan.
        {
            let journal = guard.tenant_resource_journal_mut().expect("tenant journal");
            let SuiteRetentionDisposition::Retained { record } = &mut journal.suite_retention
            else {
                panic!("retained record");
            };
            record.manifest.provider_evidence = None;
            record.provider_state = SuiteRetentionProviderState::Staged {
                pending_directory: expected_pending.clone(),
                final_directory: published_provider.directory.clone(),
                manifest_sha256: published_provider.manifest_sha256.clone(),
            };
            record.manifest_sha256 = sha256_hex(
                &canonical_suite_retention_manifest(&record.manifest)
                    .expect("canonical crash-recovery manifest"),
            );
        }
        guard.persist().expect("persist pre-final crash fixture");
        assert_eq!(
            guard
                .publish_retained_provider_evidence()
                .expect("adopt promoted provider publication"),
            published_provider
        );
        guard
            .stage_suite_retention_manifest()
            .expect("restage provider-bound manifest");
        guard
            .publish_committed_suite_retention_manifest()
            .expect("publish manifest");
        let manifest_bytes =
            crate::secure_file::read_bounded(&final_path, MAX_SUITE_RETENTION_MANIFEST_BYTES, true)
                .expect("read manifest");
        assert!(!String::from_utf8_lossy(&manifest_bytes).contains("capability.header.payload"));
        guard.finish().expect("complete retained journal");
        assert!(store.claim_pending().expect("retained recovery").is_empty());
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_retention_compacts_terminal_module_inventory_below_the_journal_cap() {
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
        suite.module_ids = (0..1408)
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
            provider_evidence: None,
            plans,
        };
        let final_path = evidence.join(format!("retained-suite-{}.json", binding.request_jti));
        guard
            .prepare_suite_plan_retention(manifest, final_path)
            .expect("prepare retention");
        let SuiteRetentionDisposition::RetentionPrepared { record } = &guard
            .tenant_resource_journal()
            .expect("tenant journal")
            .suite_retention
        else {
            panic!("prepared retention record");
        };
        assert_eq!(
            record.provider_state,
            SuiteRetentionProviderState::Intent {
                pending_directory: evidence
                    .join(".pending-provider")
                    .join(&binding.request_jti),
                final_directory: evidence
                    .join("provider-evidence")
                    .join(&binding.request_jti),
            }
        );
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
        drop(guard);
        let mut pending = store.claim_pending().expect("claim prepared journal");
        let claimed = pending.pop().expect("prepared guard");
        let suite = claimed.suite_recovery().expect("prepared Suite recovery");
        assert_eq!(suite.plan_ids.len(), 44);
        assert!(suite.module_ids.is_empty());
        drop(claimed);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn legacy_schema_three_retained_journal_without_provider_bundle_is_read_only() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-retention-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("tenant intent");
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
        let manifest = SuiteRetentionManifest {
            schema: SUITE_RETENTION_MANIFEST_SCHEMA,
            suite_origin: "https://www.certification.openid.net".to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            run_id: binding.request_jti.clone(),
            review_screenshot_manifest: None,
            provider_evidence: None,
            plans: vec![SuiteRetentionPlan {
                matrix_plan_id: "matrix-plan-1".to_owned(),
                suite_plan_id: "suite-plan-1".to_owned(),
                plan_name: "Certification plan".to_owned(),
                plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256("matrix-plan-1"),
            }],
        };
        guard
            .prepare_suite_plan_retention(
                manifest,
                evidence.join(format!("retained-suite-{}.json", binding.request_jti)),
            )
            .expect("prepare retention");
        let retained = guard
            .suite_retention_manifest()
            .expect("retention manifest")
            .clone();
        let (report, identity) =
            crate::evidence::test_support::retained_provider_fixture(&binding, &retained);
        let provider =
            crate::evidence::write_private_provider_evidence_bundle(&report, &evidence, &identity)
                .expect("legacy provider evidence");
        {
            let journal = guard.tenant_resource_journal_mut().expect("tenant journal");
            journal.schema = RETAINING_TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA;
            let SuiteRetentionDisposition::RetentionPrepared { record } =
                &mut journal.suite_retention
            else {
                panic!("prepared retention record");
            };
            record.provider_state = SuiteRetentionProviderState::None;
            record.manifest.provider_evidence = Some(SuiteRetentionProviderEvidence {
                directory: provider.directory.clone(),
                manifest_sha256: provider.manifest_sha256.clone(),
            });
            record.manifest_sha256 = sha256_hex(
                &canonical_suite_retention_manifest(&record.manifest)
                    .expect("canonical schema-three manifest"),
            );
        }
        guard.persist().expect("persist schema-three fixture");
        guard
            .stage_suite_retention_manifest()
            .expect("stage legacy manifest");
        guard
            .record_tenant_resource_receipt(tenant_resource_receipt(&binding))
            .expect("receipt");
        guard
            .record_tenant_resource_enumeration(Vec::new())
            .expect("enumeration");
        guard
            .commit_suite_plan_retention()
            .expect("legacy ownership transfer");
        guard
            .finish()
            .expect("finish compatible schema-three journal");
        assert!(
            store
                .claim_pending()
                .expect("finished schema-three journal")
                .is_empty()
        );
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_retention_persists_provider_cleanup_intent_before_plan_fallback() {
        let temp_root = std::env::temp_dir().canonicalize().expect("resolve temp");
        let root = temp_root.join(format!("nazoauth-retention-{}", uuid::Uuid::now_v7()));
        let store = ConformanceRecoveryStore::open(&root, "deployment-a").expect("store");
        let evidence = root.join("evidence");
        crate::secure_file::ensure_directory(&evidence, true).expect("evidence root");
        let binding = tenant_resource_binding(&root);
        let mut guard = store
            .begin_tenant_resource(binding.clone())
            .expect("tenant intent");
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
            .prepare_suite_plan_retention(
                SuiteRetentionManifest {
                    schema: SUITE_RETENTION_MANIFEST_SCHEMA,
                    suite_origin: "https://www.certification.openid.net".to_owned(),
                    artifact_digest: "a".repeat(64),
                    matrix_sha256: "b".repeat(64),
                    deployment_id: binding.deployment_id.clone(),
                    tenant_id: binding.tenant_id.clone(),
                    run_id: binding.request_jti.clone(),
                    review_screenshot_manifest: None,
                    provider_evidence: None,
                    plans: vec![SuiteRetentionPlan {
                        matrix_plan_id: "matrix-plan-1".to_owned(),
                        suite_plan_id: "suite-plan-1".to_owned(),
                        plan_name: "Certification plan".to_owned(),
                        plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256(
                            "matrix-plan-1",
                        ),
                    }],
                },
                evidence.join(format!("retained-suite-{}.json", binding.request_jti)),
            )
            .expect("prepare retention");
        guard
            .stage_suite_retention_manifest()
            .expect("stage Suite manifest");
        let partial_provider = evidence
            .join(".pending-provider")
            .join(&binding.request_jti);
        crate::secure_file::write_new_or_exact(
            &partial_provider.join("module-0000.json"),
            br#"{}"#,
            true,
        )
        .expect("write bounded interrupted provider file");
        guard
            .discard_prepared_suite_retention_staging()
            .expect("persist cleanup intent and discard staging");
        assert!(!partial_provider.exists());
        let SuiteRetentionDisposition::RetentionPrepared { record } = &guard
            .tenant_resource_journal()
            .expect("tenant journal")
            .suite_retention
        else {
            panic!("prepared retention record");
        };
        assert!(matches!(
            &record.provider_state,
            SuiteRetentionProviderState::CleanupIntent {
                pending_directory,
                manifest_sha256: None,
            } if pending_directory == &evidence
                .join(".pending-provider")
                .join(&binding.request_jti)
        ));
        assert_eq!(
            guard.suite_recovery().expect("Suite recovery").plan_ids,
            vec!["suite-plan-1".to_owned()]
        );
        drop(guard);
        let pending = store.claim_pending().expect("claim cleanup-intent journal");
        assert_eq!(pending.len(), 1);
        drop(pending);
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
