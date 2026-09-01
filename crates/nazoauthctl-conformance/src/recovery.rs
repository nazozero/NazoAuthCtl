use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::oidf_protocol as nazo_operator_protocol;
use crate::oidf_protocol::{
    ControlOutcome, ControlResult, ControlResultData, MAX_TENANT_RESOURCE_IDENTITIES,
    TenantResourceIdentity, TenantResourceKind, validate_file_identifier_value,
};
use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA: u32 = 3;
const TENANT_RESOURCE_RECOVERY_KIND: &str = "tenant-resource";
const MAX_RECOVERY_JOURNAL_BYTES: usize = 128 * 1024;
const MAX_PENDING_RUNS: usize = 64;
const MAX_TENANT_RESOURCE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUITE_RECOVERY_PLANS: usize = 128;
const MAX_SUITE_RECOVERY_MODULES: usize = 16 * 1024;
const SUITE_RETENTION_MANIFEST_SCHEMA: u32 = 2;
const MAX_SUITE_RETENTION_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceProxyRecovery {
    pub bundle_path: PathBuf,
    pub reload_executable: PathBuf,
}

/// The immutable ordinary-run state that survives a process crash. The
/// operation records are current ControlOperation identities; there is no
/// retired transport state at this layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceRecoveryBinding {
    pub deployment_id: String,
    pub tenant_id: String,
    pub realm_id: String,
    pub organization_id: String,
    pub run_id: String,
    pub tenant_create_expected_revision: u64,
    pub manifest_path: Option<PathBuf>,
    /// SHA-256 of the private Apply material. The ControlOperation request
    /// binds its public identity set; this digest makes resume reject a local
    /// material-file substitution before it reaches the core session.
    pub material_sha256: Option<String>,
    /// Optional proxy material that the Apply caller may have installed.  The
    /// recovery layer only records whether the caller restored it; it never
    /// executes the proxy command itself.
    pub proxy: Option<ConformanceProxyRecovery>,
    /// Runtime-discovery trust anchor for a possible NazoAuthWeb VP evidence receipt.
    pub vp_evidence_trust_anchor: Option<OpenId4VpEvidenceTrustAnchor>,
    pub resource_identities: Vec<TenantResourceIdentity>,
}

/// The durable record of one signed control operation. The complete typed
/// result is retained so recovery never reconstructs public IDs or guesses a
/// remote mutation outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceControlOperation {
    pub operation_id: String,
    pub request_hash: String,
    pub controller_kid: String,
    pub result: ControlResult,
}

/// The last durable ordinary control boundary. Together with the typed
/// operation records it makes a crash window explicit without duplicating the
/// core session's own in-flight operation journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantResourceRecoveryPhase {
    Intent,
    BaselineEnumerated,
    Applied,
    CleanupEnumerated,
    CleanupRevoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenId4VpEvidenceTrustAnchor {
    pub target_issuer: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub instance_public_key_base64: String,
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
    pub review_screenshot_manifest: Option<SuiteRetentionScreenshotManifest>,
    /// Explicit non-terminal Suite modules retained at the OIDF deferred
    /// verification-evidence boundary. They are not terminal/pass results.
    pub deferred_review_pending: Vec<SuiteRetentionDeferredReview>,
    pub plans: Vec<SuiteRetentionPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRetentionDeferredReview {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: String,
    pub test_name: String,
    pub variant: std::collections::BTreeMap<String, String>,
    pub placeholder_path: String,
    pub marker: crate::ReviewScreenshotMarker,
    pub obligation_index: usize,
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
    target_issuer: Option<String>,
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
    source: crate::BrowserReviewScreenshotSource,
    verification_receipt: Option<crate::OpenId4VpVerificationReceiptProvenance>,
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
    source: crate::BrowserReviewScreenshotSource,
    verification_receipt: Option<crate::OpenId4VpVerificationReceiptProvenance>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantResourceRecoveryJournal {
    schema: u32,
    kind: String,
    binding: TenantResourceRecoveryBinding,
    phase: TenantResourceRecoveryPhase,
    tenant_created: bool,
    tenant_key_generated: bool,
    tenant_reload_expected_revision: Option<u64>,
    tenant_reloaded: bool,
    tenant_disable_expected_revision: Option<u64>,
    tenant_disabled: bool,
    tenant_finalize_expected_revision: Option<u64>,
    tenant_cleanup_complete: bool,
    #[serde(default)]
    tenant_absence_revision: Option<u64>,
    baseline_enumerate: Option<TenantResourceControlOperation>,
    apply: Option<TenantResourceControlOperation>,
    cleanup_enumerate: Option<TenantResourceControlOperation>,
    cleanup_revoke: Option<TenantResourceControlOperation>,
    /// A server-side business failure is a durable terminal answer, not an
    /// unknown transport outcome.  It must survive before the ctl operation
    /// journal is cleared, so a later run cannot silently continue past it.
    terminal_failure: Option<TenantResourceControlOperation>,
    cleanup_complete: bool,
    manifest_removal_intent: bool,
    manifest_cleanup_complete: bool,
    /// A proxy may be installed by the Apply caller before the process dies.
    /// This marker is deliberately separate from ordinary resource cleanup:
    /// both must be complete before the journal can be removed.
    proxy_cleanup_complete: bool,
    /// Suite allocation state, if Suite work has started.
    suite: Option<SuiteRecoveryState>,
    suite_retention: SuiteRetentionDisposition,
}

pub struct ConformanceRecoveryStore {
    root: PathBuf,
    deployment_id: String,
}

pub struct ConformanceRecoveryGuard {
    store: ConformanceRecoveryStore,
    journal: TenantResourceRecoveryJournal,
    journal_path: PathBuf,
    lock_path: PathBuf,
    lock: Option<File>,
    retention_commit_resolution: SuiteRetentionCommitResolution,
}

/// The only safe cleanup decision after attempting the durable ownership
/// transfer. `Ambiguous` is intentionally distinct from `Prepared`: callers
/// must leave Suite resources and the journal untouched until a later claim
/// can validate the on-disk transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuiteRetentionCommitResolution {
    NotAttempted,
    Prepared,
    Retained,
    Ambiguous,
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

    /// Persist ordinary-run intent before the caller performs any remote
    /// control operation. This method performs no network operation and only
    /// returns a lock-held guard after the durable journal write succeeds.
    pub fn begin_ordinary_run(
        &self,
        binding: TenantResourceRecoveryBinding,
    ) -> anyhow::Result<ConformanceRecoveryGuard> {
        validate_ordinary_binding(&binding, &self.deployment_id)?;
        if binding.manifest_path.is_some() && !validate_tenant_resource_manifest_file(&binding)? {
            bail!("ordinary Apply material is missing");
        }
        let run_id = binding.run_id.clone();
        let proxy_cleanup_complete = binding.proxy.is_none();
        self.begin_journal(
            &run_id,
            TenantResourceRecoveryJournal {
                schema: TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
                kind: TENANT_RESOURCE_RECOVERY_KIND.to_owned(),
                binding,
                phase: TenantResourceRecoveryPhase::Intent,
                tenant_created: false,
                tenant_key_generated: false,
                tenant_reload_expected_revision: None,
                tenant_reloaded: false,
                tenant_disable_expected_revision: None,
                tenant_disabled: false,
                tenant_finalize_expected_revision: None,
                tenant_cleanup_complete: false,
                tenant_absence_revision: None,
                baseline_enumerate: None,
                apply: None,
                cleanup_enumerate: None,
                cleanup_revoke: None,
                terminal_failure: None,
                cleanup_complete: false,
                manifest_removal_intent: false,
                manifest_cleanup_complete: false,
                proxy_cleanup_complete,
                suite: None,
                suite_retention: SuiteRetentionDisposition::default(),
            },
        )
    }

    /// Remove private Apply material through the same owner-only, no-follow
    /// primitive used by recovery.  Callers may use this only for a material
    /// file they just created and must treat every non-NotFound failure as a
    /// failure to contain a secret.
    pub fn remove_private_material(path: &Path) -> anyhow::Result<()> {
        match crate::secure_file::remove_file(path, true) {
            Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => Ok(()),
            Err(error) => bail!("failed to remove private Apply material: {error:?}"),
        }
    }

    fn begin_journal(
        &self,
        run_id: &str,
        journal: TenantResourceRecoveryJournal,
    ) -> anyhow::Result<ConformanceRecoveryGuard> {
        let (journal_path, lock_path) = self.paths(run_id);
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
            retention_commit_resolution: SuiteRetentionCommitResolution::NotAttempted,
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
            let run_id = name
                .strip_prefix("run-")
                .and_then(|name| name.strip_suffix(".json"))
                .context("invalid conformance recovery journal name")?;
            validate_component(run_id, "run ID")?;
            let (journal_path, lock_path) = self.paths(run_id);
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
            let mut journal: TenantResourceRecoveryJournal =
                serde_json::from_slice(&bytes).context("recovery journal is invalid")?;
            validate_journal(&journal, &self.deployment_id, run_id)?;
            let mut recovered_retention_manifest = false;
            if let SuiteRetentionDisposition::Retained { record } = &journal.suite_retention {
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
            if journal.binding.manifest_path.is_some() {
                let present = validate_tenant_resource_manifest_file(&journal.binding)?;
                if journal.manifest_cleanup_complete {
                    if present {
                        bail!("tenant-resource manifest remains after cleanup marker");
                    }
                } else if !present {
                    if !journal.manifest_removal_intent {
                        bail!("tenant-resource apply manifest disappeared before cleanup");
                    }
                    journal.manifest_cleanup_complete = true;
                    recovered_manifest_removal = true;
                }
            }
            if recovered_manifest_removal || recovered_retention_manifest {
                validate_journal(&journal, &self.deployment_id, run_id)?;
                write_journal(&journal_path, &journal)?;
            }
            let retention_commit_resolution = if matches!(
                &journal.suite_retention,
                SuiteRetentionDisposition::Retained { .. }
            ) {
                SuiteRetentionCommitResolution::Retained
            } else {
                SuiteRetentionCommitResolution::Prepared
            };
            pending.push(ConformanceRecoveryGuard {
                store: self.clone(),
                journal,
                journal_path,
                lock_path,
                lock: Some(lock),
                retention_commit_resolution,
            });
        }
        Ok(pending)
    }

    fn paths(&self, run_id: &str) -> (PathBuf, PathBuf) {
        (
            self.root.join(format!("run-{run_id}.json")),
            self.root.join(format!("run-{run_id}.lock")),
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
    pub fn suite_retention_commit_resolution(&self) -> SuiteRetentionCommitResolution {
        self.retention_commit_resolution
    }

    pub fn ordinary_binding(&self) -> &TenantResourceRecoveryBinding {
        &self.journal.binding
    }

    pub fn ordinary_phase(&self) -> TenantResourceRecoveryPhase {
        self.journal.phase
    }

    pub fn tenant_created(&self) -> bool {
        self.journal.tenant_created
    }

    pub fn mark_tenant_created(&mut self) -> anyhow::Result<()> {
        self.journal.tenant_created = true;
        self.persist()
    }

    pub fn tenant_key_generated(&self) -> bool {
        self.journal.tenant_key_generated
    }

    pub fn mark_tenant_key_generated(&mut self) -> anyhow::Result<()> {
        if !self.journal.tenant_created {
            bail!("tenant key generation requires a persisted tenant create result");
        }
        self.journal.tenant_key_generated = true;
        self.persist()
    }

    pub fn tenant_reload_expected_revision(&self) -> Option<u64> {
        self.journal.tenant_reload_expected_revision
    }

    pub fn prepare_tenant_reload(&mut self, revision: u64) -> anyhow::Result<()> {
        if !self.journal.tenant_key_generated {
            bail!("tenant reload requires persisted key generation");
        }
        match self.journal.tenant_reload_expected_revision {
            Some(existing) if existing != revision => bail!("tenant reload revision conflicts"),
            _ => self.journal.tenant_reload_expected_revision = Some(revision),
        }
        self.persist()
    }

    pub fn tenant_reloaded(&self) -> bool {
        self.journal.tenant_reloaded
    }

    pub fn mark_tenant_reloaded(&mut self) -> anyhow::Result<()> {
        if self.journal.tenant_reload_expected_revision.is_none() {
            bail!("tenant reload has no persisted revision");
        }
        self.journal.tenant_reloaded = true;
        self.persist()
    }

    pub fn tenant_disable_expected_revision(&self) -> Option<u64> {
        self.journal.tenant_disable_expected_revision
    }

    pub fn prepare_tenant_disable(&mut self, revision: u64) -> anyhow::Result<()> {
        match self.journal.tenant_disable_expected_revision {
            Some(existing) if existing != revision => bail!("tenant disable revision conflicts"),
            _ => self.journal.tenant_disable_expected_revision = Some(revision),
        }
        self.persist()
    }

    pub fn tenant_disabled(&self) -> bool {
        self.journal.tenant_disabled
    }

    pub fn mark_tenant_disabled(&mut self) -> anyhow::Result<()> {
        if self.journal.tenant_disable_expected_revision.is_none() {
            bail!("tenant disable has no persisted revision");
        }
        self.journal.tenant_disabled = true;
        self.persist()
    }

    pub fn tenant_finalize_expected_revision(&self) -> Option<u64> {
        self.journal.tenant_finalize_expected_revision
    }

    pub fn prepare_tenant_finalize(&mut self, revision: u64) -> anyhow::Result<()> {
        if !self.journal.tenant_disabled {
            bail!("tenant finalize requires a persisted disable result");
        }
        match self.journal.tenant_finalize_expected_revision {
            Some(existing) if existing != revision => bail!("tenant finalize revision conflicts"),
            _ => self.journal.tenant_finalize_expected_revision = Some(revision),
        }
        self.persist()
    }

    pub fn tenant_cleanup_complete(&self) -> bool {
        self.journal.tenant_cleanup_complete
    }

    pub fn tenant_absent(&self) -> bool {
        self.journal.tenant_absence_revision.is_some()
    }

    pub fn mark_tenant_absent(&mut self, directory_revision: u64) -> anyhow::Result<()> {
        self.journal.tenant_absence_revision = Some(directory_revision);
        self.journal.terminal_failure = None;
        self.journal.tenant_disable_expected_revision = None;
        self.journal.tenant_disabled = false;
        self.journal.tenant_finalize_expected_revision = None;
        self.journal.tenant_cleanup_complete = true;
        self.journal.cleanup_complete = true;
        self.persist()
    }

    pub fn mark_tenant_cleanup_complete(&mut self) -> anyhow::Result<()> {
        if !self.journal.tenant_disabled || self.journal.tenant_finalize_expected_revision.is_none()
        {
            bail!("temporary tenant cleanup requires persisted disable and finalize intent");
        }
        self.journal.tenant_cleanup_complete = true;
        self.persist()
    }

    pub fn apply_operation(&self) -> Option<&TenantResourceControlOperation> {
        self.journal.apply.as_ref()
    }

    pub fn baseline_enumerate_operation(&self) -> Option<&TenantResourceControlOperation> {
        self.journal.baseline_enumerate.as_ref()
    }

    pub fn cleanup_enumerate_operation(&self) -> Option<&TenantResourceControlOperation> {
        self.journal.cleanup_enumerate.as_ref()
    }

    pub fn cleanup_revoke_operation(&self) -> Option<&TenantResourceControlOperation> {
        self.journal.cleanup_revoke.as_ref()
    }

    pub fn terminal_failure(&self) -> Option<&TenantResourceControlOperation> {
        self.journal.terminal_failure.as_ref()
    }

    /// The recovery binding is the sole authority for reopening private Apply
    /// material.  It performs the bounded, owner-only read and rechecks the
    /// digest that was durably bound before a prior process could die.
    pub fn read_private_material(&self) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        let path = self
            .journal
            .binding
            .manifest_path
            .as_ref()
            .context("ordinary recovery has no private Apply material path")?;
        let expected = self
            .journal
            .binding
            .material_sha256
            .as_deref()
            .context("ordinary recovery has no private Apply material digest")?;
        let bytes =
            crate::secure_file::read_bounded(path, MAX_TENANT_RESOURCE_MANIFEST_BYTES, true)
                .map_err(|error| anyhow::anyhow!("ordinary material is not secure: {error:?}"))?;
        if sha256_hex(&bytes) != expected {
            bail!("ordinary material digest conflicts with recovery binding");
        }
        Ok(zeroize::Zeroizing::new(bytes))
    }

    pub fn proxy_cleanup_complete(&self) -> bool {
        self.journal.proxy_cleanup_complete
    }

    pub fn mark_proxy_cleanup_complete(&mut self) -> anyhow::Result<()> {
        self.journal.proxy_cleanup_complete = true;
        self.persist()
    }

    /// Persist the only safe terminal interpretation of a ControlOperation
    /// before its controller-side single-slot journal is cleared.  Successful
    /// answers are accepted only when the phase-specific typed result is
    /// valid; a durable Failed answer is retained verbatim and blocks this
    /// recovery transaction from advancing.  InProgress is deliberately not
    /// terminal and leaves the controller journal in place for replay.
    pub fn record_terminal_completion(
        &mut self,
        phase: TenantResourceRecoveryPhase,
        operation: TenantResourceControlOperation,
    ) -> anyhow::Result<()> {
        validate_control_identity(&operation)?;
        match operation.result.outcome {
            ControlOutcome::Succeeded => {
                if operation.result.error.is_some() || operation.result.result.is_none() {
                    bail!("successful control operation result is invalid");
                }
                match phase {
                    TenantResourceRecoveryPhase::BaselineEnumerated => {
                        validate_enumerate_operation(&self.journal.binding, &operation)?;
                        record_operation(
                            &mut self.journal.baseline_enumerate,
                            operation,
                            "baseline enumerate",
                        )?;
                    }
                    TenantResourceRecoveryPhase::Applied => {
                        validate_apply_operation(&self.journal.binding, &operation)?;
                        record_operation(&mut self.journal.apply, operation, "Apply")?;
                    }
                    TenantResourceRecoveryPhase::CleanupEnumerated => {
                        if self.journal.apply.is_none() {
                            bail!("cleanup enumerate requires a persisted Apply result");
                        }
                        validate_enumerate_operation(&self.journal.binding, &operation)?;
                        record_operation(
                            &mut self.journal.cleanup_enumerate,
                            operation,
                            "cleanup enumerate",
                        )?;
                    }
                    TenantResourceRecoveryPhase::CleanupRevoked => {
                        let enumerate = self
                            .journal
                            .cleanup_enumerate
                            .as_ref()
                            .context("cleanup Revoke requires a persisted enumeration")?;
                        validate_revoke_operation(&self.journal.binding, enumerate, &operation)?;
                        record_operation(
                            &mut self.journal.cleanup_revoke,
                            operation,
                            "cleanup Revoke",
                        )?;
                    }
                    TenantResourceRecoveryPhase::Intent => {
                        bail!("Intent is not a ControlOperation completion phase")
                    }
                }
                self.journal.phase = phase;
                self.journal.cleanup_complete = tenant_resource_obligations_complete(&self.journal);
            }
            ControlOutcome::Failed => {
                if operation.result.error.is_none() || operation.result.result.is_some() {
                    bail!("failed control operation result is invalid");
                }
                record_operation(
                    &mut self.journal.terminal_failure,
                    operation,
                    "terminal control failure",
                )?;
            }
            ControlOutcome::InProgress => {
                bail!("in-progress control operation cannot clear the controller journal")
            }
        }
        self.persist()
    }

    /// Persist the typed Apply result before the session is allowed to clear
    /// its own operation journal. A repeat must be byte-identical.
    pub fn record_apply_result(
        &mut self,
        operation: TenantResourceControlOperation,
    ) -> anyhow::Result<()> {
        validate_apply_operation(&self.journal.binding, &operation)?;
        record_operation(&mut self.journal.apply, operation, "Apply")?;
        self.journal.phase = TenantResourceRecoveryPhase::Applied;
        self.journal.cleanup_complete = tenant_resource_obligations_complete(&self.journal);
        self.persist()
    }

    pub fn record_baseline_enumerate_result(
        &mut self,
        operation: TenantResourceControlOperation,
    ) -> anyhow::Result<()> {
        validate_enumerate_operation(&self.journal.binding, &operation)?;
        record_operation(
            &mut self.journal.baseline_enumerate,
            operation,
            "baseline enumerate",
        )?;
        self.journal.phase = TenantResourceRecoveryPhase::BaselineEnumerated;
        self.persist()
    }

    /// Persist the full typed cleanup enumeration before deriving a Revoke
    /// payload. This prevents a crash from changing the selected resource set.
    pub fn record_cleanup_enumerate_result(
        &mut self,
        operation: TenantResourceControlOperation,
    ) -> anyhow::Result<()> {
        if self.journal.apply.is_none() {
            bail!("cleanup enumerate requires a persisted Apply result");
        }
        validate_enumerate_operation(&self.journal.binding, &operation)?;
        record_operation(
            &mut self.journal.cleanup_enumerate,
            operation,
            "cleanup enumerate",
        )?;
        self.journal.phase = TenantResourceRecoveryPhase::CleanupEnumerated;
        self.journal.cleanup_complete = tenant_resource_obligations_complete(&self.journal);
        self.persist()
    }

    /// Persist the typed Revoke result. The result must cover exactly the
    /// run-scoped resources still present in the persisted cleanup snapshot.
    pub fn record_cleanup_revoke_result(
        &mut self,
        operation: TenantResourceControlOperation,
    ) -> anyhow::Result<()> {
        let enumerate = self
            .journal
            .cleanup_enumerate
            .as_ref()
            .context("cleanup Revoke requires a persisted enumeration")?;
        validate_revoke_operation(&self.journal.binding, enumerate, &operation)?;
        record_operation(
            &mut self.journal.cleanup_revoke,
            operation,
            "cleanup Revoke",
        )?;
        self.journal.phase = TenantResourceRecoveryPhase::CleanupRevoked;
        self.journal.cleanup_complete = tenant_resource_obligations_complete(&self.journal);
        self.persist()
    }

    pub fn ordinary_cleanup_complete(&self) -> bool {
        tenant_resource_obligations_complete(&self.journal)
    }

    pub fn ordinary_manifest_removal_intent(&self) -> bool {
        self.journal.manifest_removal_intent
    }

    pub fn ordinary_manifest_cleanup_complete(&self) -> bool {
        self.journal.manifest_cleanup_complete
    }
    pub fn record_suite_plan(
        &mut self,
        origin: &str,
        intent_id: &str,
        plan_id: &str,
    ) -> anyhow::Result<()> {
        let origin = crate::Origin::parse_suite(origin)
            .map_err(|_| anyhow::anyhow!("Suite recovery origin is invalid"))?;
        validate_component(plan_id, "Suite plan ID")?;
        let suite = self
            .journal
            .suite
            .get_or_insert_with(|| SuiteRecoveryState {
                origin: origin.as_str().to_owned(),
                plan_ids: Vec::new(),
                module_ids: Vec::new(),
                pending_create_intents: Vec::new(),
                cleanup_complete: false,
            });
        if suite.origin != origin.as_str() || suite.cleanup_complete {
            bail!("Suite recovery state conflicts with plan allocation");
        }
        Self::resolve_suite_create_intent(suite, intent_id)?;
        if !suite.plan_ids.iter().any(|existing| existing == plan_id) {
            suite.plan_ids.push(plan_id.to_owned());
        }
        self.persist()
    }

    pub fn begin_suite_create_with_retention(
        &mut self,
        origin: &str,
        intent_id: &str,
        retain: bool,
    ) -> anyhow::Result<()> {
        let origin = crate::Origin::parse_suite(origin)
            .map_err(|_| anyhow::anyhow!("Suite recovery origin is invalid"))?;
        validate_component(intent_id, "Suite create intent ID")?;
        match &self.journal.suite_retention {
            SuiteRetentionDisposition::Active { requested }
                if self.journal.suite.is_none() || *requested == retain => {}
            SuiteRetentionDisposition::Active { .. } => {
                bail!("Suite retention policy conflicts with recovery journal")
            }
            _ => bail!("Suite resources are already settled for this recovery journal"),
        }
        self.journal.suite_retention = SuiteRetentionDisposition::Active { requested: retain };
        let suite = self
            .journal
            .suite
            .get_or_insert_with(|| SuiteRecoveryState {
                origin: origin.as_str().to_owned(),
                plan_ids: Vec::new(),
                module_ids: Vec::new(),
                pending_create_intents: Vec::new(),
                cleanup_complete: false,
            });
        if suite.origin != origin.as_str()
            || suite.cleanup_complete
            || suite
                .pending_create_intents
                .iter()
                .any(|existing| existing == intent_id)
        {
            bail!("Suite create intent conflicts with recovery journal");
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

    pub fn record_suite_module(&mut self, intent_id: &str, module_id: &str) -> anyhow::Result<()> {
        validate_component(module_id, "Suite module ID")?;
        let suite = self
            .journal
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
            suite.module_ids.push(module_id.to_owned());
        }
        self.persist()
    }

    pub fn suite_recovery(&self) -> Option<&SuiteRecoveryState> {
        self.journal.suite.as_ref()
    }
    pub fn suite_cleanup_complete(&self) -> bool {
        suite_resources_settled(&self.journal)
    }

    pub fn mark_suite_cleanup_complete(&mut self) -> anyhow::Result<()> {
        if !matches!(
            self.journal.suite_retention,
            SuiteRetentionDisposition::Active { .. }
                | SuiteRetentionDisposition::RetentionPrepared { .. }
        ) {
            bail!("retained Suite resources cannot be marked as cleanup complete");
        }
        let suite = self
            .journal
            .suite
            .as_mut()
            .context("Suite cleanup has no persisted allocation")?;
        if !suite.pending_create_intents.is_empty() {
            bail!("Suite cleanup cannot complete with unresolved Suite create intent");
        }
        suite.cleanup_complete = true;
        suite.plan_ids.clear();
        suite.module_ids.clear();
        self.journal.suite_retention = SuiteRetentionDisposition::Cleaned;
        self.persist()
    }

    pub fn prepare_suite_plan_retention(
        &mut self,
        manifest: SuiteRetentionManifest,
        manifest_path: PathBuf,
    ) -> anyhow::Result<()> {
        if !matches!(
            self.journal.suite_retention,
            SuiteRetentionDisposition::Active { requested: true }
        ) {
            bail!("Suite retention was not requested before allocation");
        }
        let suite = self
            .journal
            .suite
            .as_mut()
            .context("Suite retention has no persisted allocation")?;
        if suite.cleanup_complete || !suite.pending_create_intents.is_empty() {
            bail!("Suite retention requires a settled allocation");
        }
        validate_suite_retention_manifest(&manifest, &self.journal.binding, Some(suite))?;
        let bytes = canonical_suite_retention_manifest(&manifest)?;
        self.journal.suite_retention = SuiteRetentionDisposition::RetentionPrepared {
            record: SuiteRetentionRecord {
                manifest,
                manifest_sha256: sha256_hex(&bytes),
                manifest_path,
            },
        };
        suite.module_ids.clear();
        self.persist()
    }

    pub fn stage_suite_retention_manifest(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal.suite_retention {
            SuiteRetentionDisposition::RetentionPrepared { record } => record,
            _ => bail!("Suite retention has not been prepared"),
        };
        let bytes = canonical_suite_retention_manifest(&record.manifest)?;
        if sha256_hex(&bytes) != record.manifest_sha256 {
            bail!("Suite retention manifest digest conflicts with journal");
        }
        let pending = self.suite_retention_pending_path()?;
        match crate::secure_file::read_bounded(&pending, MAX_SUITE_RETENTION_MANIFEST_BYTES, true) {
            Ok(existing) if sha256_hex(&existing) == record.manifest_sha256 => return Ok(pending),
            Ok(_) => bail!("retained Suite manifest conflicts with recovery journal"),
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Err(error) => bail!("retained Suite manifest is not secure: {error:?}"),
        }
        crate::secure_file::write_atomic(&pending, &bytes, true).map_err(|error| {
            anyhow::anyhow!("failed to stage retained Suite manifest: {error:?}")
        })?;
        Ok(pending)
    }

    pub fn commit_suite_plan_retention(&mut self) -> anyhow::Result<()> {
        if !tenant_resource_obligations_complete(&self.journal)
            || !self.journal.tenant_cleanup_complete
            || !self.journal.proxy_cleanup_complete
        {
            bail!("Suite retention cannot commit before ordinary and proxy cleanup complete");
        }
        let pending = self.suite_retention_pending_path()?;
        let record = match &self.journal.suite_retention {
            SuiteRetentionDisposition::RetentionPrepared { record } => record.clone(),
            _ => bail!("Suite retention has not been prepared"),
        };
        let bytes =
            crate::secure_file::read_bounded(&pending, MAX_SUITE_RETENTION_MANIFEST_BYTES, true)
                .map_err(|error| {
                    anyhow::anyhow!("retained Suite pending manifest is not secure: {error:?}")
                })?;
        if sha256_hex(&bytes) != record.manifest_sha256 {
            bail!("retained Suite pending manifest conflicts with recovery journal");
        }
        let suite = self
            .journal
            .suite
            .as_mut()
            .context("Suite retention has no persisted allocation")?;
        suite.plan_ids.clear();
        suite.module_ids.clear();
        self.journal.suite_retention = SuiteRetentionDisposition::Retained { record };
        self.persist()?;
        self.retention_commit_resolution = SuiteRetentionCommitResolution::Retained;
        Ok(())
    }

    pub fn publish_committed_suite_retention_manifest(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal.suite_retention {
            SuiteRetentionDisposition::Retained { record } => record,
            _ => bail!("Suite retention has not been committed"),
        };
        let final_path = record.manifest_path.clone();
        match crate::secure_file::read_bounded(
            &final_path,
            MAX_SUITE_RETENTION_MANIFEST_BYTES,
            true,
        ) {
            Ok(existing) if sha256_hex(&existing) == record.manifest_sha256 => {
                return Ok(final_path);
            }
            Ok(_) => bail!("retained Suite manifest conflicts with recovery journal"),
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
        match &self.journal.suite_retention {
            SuiteRetentionDisposition::RetentionPrepared { record }
            | SuiteRetentionDisposition::Retained { record } => Some(&record.manifest),
            _ => None,
        }
    }
    pub fn suite_retention_manifest_receipt(
        &self,
    ) -> anyhow::Result<Option<SuiteRetentionManifestReceipt>> {
        match &self.journal.suite_retention {
            SuiteRetentionDisposition::Retained { record } => {
                let bytes = crate::secure_file::read_bounded(
                    &record.manifest_path,
                    MAX_SUITE_RETENTION_MANIFEST_BYTES,
                    true,
                )
                .map_err(|error| {
                    anyhow::anyhow!("retained Suite manifest is not secure: {error:?}")
                })?;
                if sha256_hex(&bytes) != record.manifest_sha256 {
                    bail!("retained Suite manifest conflicts with recovery journal");
                }
                Ok(Some(SuiteRetentionManifestReceipt {
                    path: record.manifest_path.clone(),
                    sha256: record.manifest_sha256.clone(),
                }))
            }
            _ => Ok(None),
        }
    }
    pub fn suite_retention_committed(&self) -> bool {
        matches!(
            self.journal.suite_retention,
            SuiteRetentionDisposition::Retained { .. }
        )
    }
    pub fn discard_prepared_suite_retention_staging(&self) -> anyhow::Result<()> {
        if !matches!(
            self.journal.suite_retention,
            SuiteRetentionDisposition::RetentionPrepared { .. }
        ) {
            return Ok(());
        }
        let pending = self.suite_retention_pending_path()?;
        match crate::secure_file::remove_file(&pending, true) {
            Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => Ok(()),
            Err(error) => bail!("failed to discard staged Suite retention manifest: {error:?}"),
        }
    }
    fn suite_retention_pending_path(&self) -> anyhow::Result<PathBuf> {
        let record = match &self.journal.suite_retention {
            SuiteRetentionDisposition::RetentionPrepared { record }
            | SuiteRetentionDisposition::Retained { record } => record,
            _ => bail!("Suite retention has no manifest path"),
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
    pub fn finish(mut self) -> anyhow::Result<()> {
        if self.suite_retention_committed() {
            self.publish_committed_suite_retention_manifest()?;
        }
        if !tenant_resource_obligations_complete(&self.journal)
            || !self.journal.proxy_cleanup_complete
            || !suite_resources_settled(&self.journal)
        {
            bail!("conformance recovery obligations are incomplete");
        }

        let ordinary_manifest_path = self.journal.binding.manifest_path.clone();
        if let Some(manifest_path) = ordinary_manifest_path {
            let needs_intent = !self.journal.manifest_removal_intent;
            if needs_intent {
                self.journal.cleanup_complete = true;
                self.journal.manifest_removal_intent = true;
                // The cleanup marker and removal intent are durable before
                // touching the private manifest.
                self.persist()?;
            }

            let needs_manifest_removal = !self.journal.manifest_cleanup_complete;
            if needs_manifest_removal {
                match crate::secure_file::remove_file(&manifest_path, true) {
                    Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => {}
                    Err(error) => {
                        bail!("failed to remove tenant-resource manifest: {error:?}");
                    }
                }
                self.journal.manifest_cleanup_complete = true;
                // If the process dies after unlink and before this write,
                // claim_pending treats the missing file plus persisted intent
                // as the completed removal and retries this marker write.
                self.persist()?;
            } else if validate_tenant_resource_manifest_file(&self.journal.binding)? {
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

    fn persist_snapshot(&self, journal: &TenantResourceRecoveryJournal) -> anyhow::Result<()> {
        validate_journal(journal, &self.store.deployment_id, &journal.binding.run_id)?;
        if journal.binding.manifest_path.is_some() {
            let present = validate_tenant_resource_manifest_file(&journal.binding)?;
            if journal.manifest_cleanup_complete && present {
                bail!("tenant-resource manifest remains after cleanup marker");
            }
            if !present && !journal.manifest_removal_intent {
                bail!("tenant-resource apply manifest disappeared before cleanup");
            }
        }
        write_journal(&self.journal_path, journal)?;
        Ok(())
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

fn write_journal(path: &Path, journal: &TenantResourceRecoveryJournal) -> anyhow::Result<()> {
    let bytes = canonical_journal_bytes(journal)?;
    crate::secure_file::write_atomic(path, &bytes, true)
        .map_err(|error| anyhow::anyhow!("failed to persist recovery journal: {error:?}"))
}

fn canonical_journal_bytes(journal: &TenantResourceRecoveryJournal) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() > MAX_RECOVERY_JOURNAL_BYTES {
        bail!("conformance recovery journal exceeds policy");
    }
    Ok(bytes)
}

fn validate_journal(
    journal: &TenantResourceRecoveryJournal,
    deployment_id: &str,
    run_id: &str,
) -> anyhow::Result<()> {
    if journal.binding.run_id != run_id {
        bail!("conformance recovery journal run ID does not match its path");
    }
    if journal.schema != TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA
        || journal.kind != TENANT_RESOURCE_RECOVERY_KIND
    {
        bail!("tenant-resource recovery journal discriminator is invalid");
    }
    validate_tenant_resource_journal(journal, deployment_id)
}

fn validate_tenant_resource_journal(
    journal: &TenantResourceRecoveryJournal,
    deployment_id: &str,
) -> anyhow::Result<()> {
    validate_ordinary_binding(&journal.binding, deployment_id)?;
    let expected_phase = if journal.cleanup_revoke.is_some() {
        TenantResourceRecoveryPhase::CleanupRevoked
    } else if journal.cleanup_enumerate.is_some() {
        TenantResourceRecoveryPhase::CleanupEnumerated
    } else if journal.apply.is_some() {
        TenantResourceRecoveryPhase::Applied
    } else if journal.baseline_enumerate.is_some() {
        TenantResourceRecoveryPhase::BaselineEnumerated
    } else {
        TenantResourceRecoveryPhase::Intent
    };
    if journal.phase != expected_phase {
        bail!("tenant-resource recovery phase does not match durable operations");
    }
    if let Some(failure) = &journal.terminal_failure {
        validate_control_identity(failure)?;
        if failure.result.outcome != ControlOutcome::Failed
            || failure.result.error.is_none()
            || failure.result.result.is_some()
        {
            bail!("terminal control failure is invalid");
        }
        if journal.cleanup_complete
            || journal.manifest_removal_intent
            || journal.manifest_cleanup_complete
        {
            bail!("terminal control failure cannot have completed recovery cleanup");
        }
    }
    if journal.cleanup_complete && !tenant_resource_obligations_complete(journal) {
        bail!("tenant-resource cleanup marker is ahead of its obligations");
    }
    if journal.tenant_cleanup_complete
        && !journal.tenant_created
        && journal.tenant_absence_revision.is_none()
    {
        bail!("temporary tenant cleanup is ahead of tenant creation");
    }
    if journal.tenant_absence_revision.is_some()
        && (!journal.tenant_cleanup_complete
            || !journal.cleanup_complete
            || journal.tenant_disable_expected_revision.is_some()
            || journal.tenant_disabled
            || journal.tenant_finalize_expected_revision.is_some())
    {
        bail!("temporary tenant absence state is inconsistent");
    }
    if journal.tenant_absence_revision.is_none()
        && (journal.tenant_key_generated && !journal.tenant_created
            || journal.tenant_reload_expected_revision.is_some() && !journal.tenant_key_generated
            || journal.tenant_reloaded && journal.tenant_reload_expected_revision.is_none()
            || journal.tenant_disable_expected_revision.is_some() && !journal.tenant_created
            || journal.tenant_disabled && journal.tenant_disable_expected_revision.is_none()
            || journal.tenant_finalize_expected_revision.is_some() && !journal.tenant_disabled
            || journal.tenant_cleanup_complete
                && journal.tenant_finalize_expected_revision.is_none())
    {
        bail!("temporary tenant lifecycle state is inconsistent");
    }
    if journal.manifest_removal_intent
        && (!journal.cleanup_complete || journal.binding.manifest_path.is_none())
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
    if let Some(baseline) = &journal.baseline_enumerate {
        validate_enumerate_operation(&journal.binding, baseline)?;
    }
    if let Some(apply) = &journal.apply {
        if journal.baseline_enumerate.is_none() {
            bail!("ordinary Apply precedes baseline enumeration");
        }
        validate_apply_operation(&journal.binding, apply)?;
    }
    if let Some(enumerate) = &journal.cleanup_enumerate {
        if journal.apply.is_none() {
            bail!("ordinary cleanup enumeration precedes Apply");
        }
        validate_enumerate_operation(&journal.binding, enumerate)?;
    }
    if let Some(revoke) = &journal.cleanup_revoke {
        let enumerate = journal
            .cleanup_enumerate
            .as_ref()
            .context("ordinary Revoke precedes cleanup enumeration")?;
        validate_revoke_operation(&journal.binding, enumerate, revoke)?;
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
        || manifest.run_id != binding.run_id
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
    if !manifest.deferred_review_pending.is_empty() {
        let screenshot = manifest
            .review_screenshot_manifest
            .as_ref()
            .context("deferred review retention has no screenshot manifest")?;
        validate_deferred_review_screenshot_binding(screenshot, manifest, binding)?;
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
    let mut deferred_modules = std::collections::BTreeSet::new();
    for pending in &manifest.deferred_review_pending {
        let canonical_variant = serde_json::to_string(&pending.variant)
            .expect("BTreeMap<String, String> always serializes to JSON");
        validate_component(&pending.matrix_plan_id, "deferred review Matrix plan ID")?;
        validate_component(&pending.suite_plan_id, "deferred review Suite plan ID")?;
        validate_component(&pending.module_id, "deferred review Suite module ID")?;
        if pending.test_name.is_empty()
            || pending.test_name.len() > 256
            || pending
                .test_name
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || pending.marker != crate::ReviewScreenshotMarker::Required
            || pending.obligation_index != 0
            || pending.placeholder_path
                != format!("/test/a/{}/verification-evidence", pending.module_id)
            || !matrix_ids.contains(&pending.matrix_plan_id)
            || !suite_ids.contains(&pending.suite_plan_id)
            || !deferred_modules.insert((
                pending.matrix_plan_id.clone(),
                pending.suite_plan_id.clone(),
                pending.module_id.clone(),
                pending.test_name.clone(),
                canonical_variant,
            ))
        {
            bail!("deferred review retention identity is invalid");
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

fn validate_deferred_review_screenshot_binding(
    screenshot: &SuiteRetentionScreenshotManifest,
    retention: &SuiteRetentionManifest,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let bytes = crate::secure_file::read_bounded(
        &screenshot.path,
        crate::evidence::MAX_REVIEW_SCREENSHOT_MANIFEST_BYTES,
        true,
    )
    .map_err(|error| anyhow::anyhow!("review screenshot manifest is not secure: {error:?}"))?;
    let document: ReviewScreenshotManifestDocument =
        serde_json::from_slice(&bytes).context("review screenshot manifest is not valid JSON")?;
    for pending in &retention.deferred_review_pending {
        let module_matches = document.modules.iter().any(|module| {
            module.matrix_plan_id == pending.matrix_plan_id
                && module.suite_plan_id == pending.suite_plan_id
                && module.module_id == pending.module_id
                && module.test_name == pending.test_name
                && module.variant == pending.variant
                && module.required == 1
                && module.captured_required == 1
                && module.missing_optional == 0
        });
        let screenshot_matches = document.screenshots.iter().any(|image| {
            image.matrix_plan_id == pending.matrix_plan_id
                && image.suite_plan_id == pending.suite_plan_id
                && image.module_id == pending.module_id
                && image.test_name == pending.test_name
                && image.variant == pending.variant
                && image.marker == pending.marker
                && image.obligation_index == pending.obligation_index
                && image.source
                    == crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver
                && image.trigger_path == "/ui/verification-result"
        });
        if !module_matches || !screenshot_matches {
            bail!("deferred review screenshot manifest does not bind the retained module");
        }
    }
    if document.run_jti != binding.run_id {
        bail!("deferred review screenshot manifest has the wrong run identity");
    }
    Ok(())
}

fn validate_review_screenshot_manifest_binding(
    screenshot: &SuiteRetentionScreenshotManifest,
    retention: &SuiteRetentionManifest,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let expected_name = format!("{}.json", binding.run_id);
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
    if document.schema != crate::evidence::REVIEW_SCREENSHOT_MANIFEST_SCHEMA
        || document.run_jti != binding.run_id
        || document.artifact_digest != retention.artifact_digest
        || document.matrix_sha256 != retention.matrix_sha256
        || document.suite_origin != retention.suite_origin
    {
        bail!("review screenshot manifest identity conflicts with retention");
    }
    let target_issuer = document.target_issuer.as_deref();
    let vp_trust_anchor = binding.vp_evidence_trust_anchor.as_ref();
    if target_issuer.is_none() {
        bail!("review screenshot manifest has no target issuer");
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
    let mut obligations = std::collections::BTreeSet::new();
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
                .is_some_and(|part| part.as_os_str() == std::ffi::OsStr::new(&binding.run_id))
            && matches!(
                path_components.next(),
                Some(std::path::Component::Normal(_))
            )
            && path_components.next().is_none();
        let source_valid = match image.source {
            crate::BrowserReviewScreenshotSource::SuiteVerificationEvidence => {
                image.verification_receipt.is_none()
                    && image.trigger_origin == "https://www.certification.openid.net"
                    && image.trigger_path
                        == format!("/test/a/{}/verification-evidence", image.module_id)
                    && sha256_hex(
                        format!("{}{}", image.trigger_origin, image.trigger_path).as_bytes(),
                    ) == image.trigger_url_sha256
            }
            crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver => {
                url::Url::parse(&format!("{}{}", image.trigger_origin, image.trigger_path))
                    .is_ok_and(|url| {
                        url.scheme() == "https"
                            && url.host_str().is_some()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.query().is_none()
                            && url.fragment().is_none()
                    })
                    && target_issuer
                        .zip(vp_trust_anchor)
                        .is_some_and(|(target_issuer, anchor)| {
                            target_issuer == anchor.target_issuer
                                && image.verification_receipt.as_ref().is_some_and(|receipt| {
                                    verify_vp_receipt_provenance(
                                        receipt, anchor, binding, retention, image,
                                    )
                                })
                        })
                    && image.trigger_path == "/ui/verification-result"
                    && sha256_hex(
                        format!("{}{}", image.trigger_origin, image.trigger_path).as_bytes(),
                    ) == image.trigger_url_sha256
            }
        };
        if !plans.contains(&(&image.matrix_plan_id, &image.suite_plan_id))
            || !modules.contains(&(
                &image.matrix_plan_id,
                &image.suite_plan_id,
                &image.module_id,
                &image.test_name,
                &image.variant,
            ))
            || !valid_path
            || image.size == 0
            || !lower_hex(&image.sha256, 64)
            || !lower_hex(&image.receipt_sha256, 64)
            || !lower_hex(&image.trigger_url_sha256, 64)
            || !source_valid
            || !images.insert(&image.path)
        {
            bail!("review screenshot manifest screenshot graph is invalid");
        }
        let module = document
            .modules
            .iter()
            .find(|module| {
                module.matrix_plan_id == image.matrix_plan_id
                    && module.suite_plan_id == image.suite_plan_id
                    && module.module_id == image.module_id
                    && module.test_name == image.test_name
                    && module.variant == image.variant
            })
            .context("review screenshot has no exact module tuple")?;
        let total_attempts = document
            .screenshots
            .iter()
            .filter(|candidate| {
                candidate.matrix_plan_id == module.matrix_plan_id
                    && candidate.suite_plan_id == module.suite_plan_id
                    && candidate.module_id == module.module_id
                    && candidate.test_name == module.test_name
                    && candidate.variant == module.variant
            })
            .count()
            .checked_add(module.missing_optional)
            .context("review screenshot attempt count overflows")?;
        if image.obligation_index >= total_attempts
            || !obligations.insert((
                &image.matrix_plan_id,
                &image.suite_plan_id,
                &image.module_id,
                &image.test_name,
                &image.variant,
                image.obligation_index,
            ))
        {
            bail!("review screenshot manifest obligation graph is invalid");
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
            || audit.source != image.source
            || audit.verification_receipt != image.verification_receipt
        {
            bail!("review screenshot receipt conflicts with the manifest");
        }
    }
    for module in &document.modules {
        let required_captured = document
            .screenshots
            .iter()
            .filter(|image| {
                image.matrix_plan_id == module.matrix_plan_id
                    && image.suite_plan_id == module.suite_plan_id
                    && image.module_id == module.module_id
                    && image.test_name == module.test_name
                    && image.variant == module.variant
                    && matches!(image.marker, crate::ReviewScreenshotMarker::Required)
            })
            .count();
        let optional_captured = document
            .screenshots
            .iter()
            .filter(|image| {
                image.matrix_plan_id == module.matrix_plan_id
                    && image.suite_plan_id == module.suite_plan_id
                    && image.module_id == module.module_id
                    && image.test_name == module.test_name
                    && image.variant == module.variant
                    && matches!(image.marker, crate::ReviewScreenshotMarker::Optional)
            })
            .count();
        let total_attempts = required_captured
            .checked_add(optional_captured)
            .and_then(|attempts| attempts.checked_add(module.missing_optional))
            .context("review screenshot optional attempt count overflows")?;
        if required_captured != module.required
            || module.captured_required != module.required
            || total_attempts > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_MODULE
        {
            bail!("review screenshot manifest optional obligation count is invalid");
        }
    }
    if expected_files.len() > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN * 2 {
        bail!("review screenshot manifest exceeds the run file budget");
    }
    let run_directory = evidence_root
        .join("review-screenshots")
        .join(&binding.run_id);
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
            .join(&binding.run_id)
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

fn verify_vp_receipt_provenance(
    receipt: &crate::OpenId4VpVerificationReceiptProvenance,
    anchor: &OpenId4VpEvidenceTrustAnchor,
    binding: &TenantResourceRecoveryBinding,
    retention: &SuiteRetentionManifest,
    image: &ReviewScreenshotManifestImage,
) -> bool {
    use time::format_description::well_known::Rfc3339;

    if receipt.issuer != anchor.target_issuer
        || receipt.deployment_id != anchor.deployment_id
        || receipt.tenant_id != binding.tenant_id
        || receipt.runtime_instance_id != anchor.runtime_instance_id
        || receipt.instance_key_id != anchor.instance_key_id
        || receipt.instance_public_key_base64 != anchor.instance_public_key_base64
        || image.trigger_origin != anchor.target_issuer
        || receipt.receipt_api_url
            != format!("{}/openid4vp/verification-receipts", anchor.target_issuer)
        || sha256_hex(receipt.receipt_jws.as_bytes()) != receipt.receipt_sha256
        || !lower_hex(&receipt.receipt_sha256, 64)
        || !lower_hex(&receipt.capability_sha256, 64)
        || uuid::Uuid::parse_str(&receipt.issuance_request_jti).is_err()
        || !lower_hex(&receipt.presentation_binding_sha256, 64)
        || !lower_hex(&receipt.intent_sha256, 64)
    {
        return false;
    }
    let Ok(key) =
        nazo_operator_protocol::decode_instance_public_key(&anchor.instance_public_key_base64)
    else {
        return false;
    };
    if nazo_operator_protocol::instance_key_id(&key) != receipt.instance_key_id {
        return false;
    }
    let Ok(variant_bytes) = serde_json::to_vec(&image.variant) else {
        return false;
    };
    let context = nazo_operator_protocol::Openid4vpEvidenceContext {
        run_jti: binding.run_id.clone(),
        artifact_sha256: retention.artifact_digest.clone(),
        matrix_sha256: retention.matrix_sha256.clone(),
        suite_plan_id: image.suite_plan_id.clone(),
        suite_module_id: image.module_id.clone(),
        test_name: image.test_name.clone(),
        variant_sha256: sha256_hex(&variant_bytes),
    };
    let Ok(context_sha256) =
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
    else {
        return false;
    };
    let Ok(completed_at) = time::OffsetDateTime::parse(&receipt.completed_at, &Rfc3339) else {
        return false;
    };
    if completed_at.format(&Rfc3339).ok().as_deref() != Some(receipt.completed_at.as_str()) {
        return false;
    }
    let Ok(expires_at) = time::OffsetDateTime::parse(&receipt.expires_at, &Rfc3339) else {
        return false;
    };
    if expires_at.format(&Rfc3339).ok().as_deref() != Some(receipt.expires_at.as_str())
        || expires_at <= completed_at
    {
        return false;
    }
    // This is historical verification: the presentation completes before the
    // runtime can issue its receipt, so `completed_at` may precede the signed
    // `iat`. Verify at the last whole second inside the signed validity window,
    // then separately bind the verified issuance time to presentation order.
    let Some(verification_time) = expires_at.unix_timestamp().checked_sub(1) else {
        return false;
    };
    let receipt_id = receipt.receipt_id.to_string();
    let transaction_id = receipt.transaction_id.to_string();
    let expected = nazo_operator_protocol::Openid4vpVerificationReceiptExpectations {
        issuer: &anchor.target_issuer,
        audience: &receipt.receipt_api_url,
        deployment_id: &receipt.deployment_id,
        runtime_instance_id: &receipt.runtime_instance_id,
        instance_key_id: &receipt.instance_key_id,
        tenant_id: &receipt.tenant_id,
        transaction_id: &transaction_id,
        receipt_id: &receipt_id,
        issuance_request_jti: &receipt.issuance_request_jti,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &receipt.presentation_binding_sha256,
        intent_sha256: &receipt.intent_sha256,
        capability_sha256: &receipt.capability_sha256,
    };
    let Ok(verified) = nazo_operator_protocol::verify_openid4vp_verification_receipt(
        &receipt.receipt_jws,
        &expected,
        &key,
        verification_time,
    ) else {
        return false;
    };
    verified.completed_at == receipt.completed_at
        && verified.iat >= completed_at.unix_timestamp()
        && verified.iat < verified.exp
        && verified.iss == receipt.issuer
        && verified.deployment_id == receipt.deployment_id
        && verified.tenant_id == receipt.tenant_id
        && verified.runtime_instance_id == receipt.runtime_instance_id
        && verified.instance_key_id == receipt.instance_key_id
        && verified.transaction_id == transaction_id
        && verified.issuance_request_jti == receipt.issuance_request_jti
        && verified.intent_sha256 == receipt.intent_sha256
        && verified.exp == expires_at.unix_timestamp()
        && exact_vp_trust_policy_binding(binding, &verified.presentation_binding.trust_policy)
}

/// Bind the signed VP trust-policy projection to the one policy resource this
/// ordinary run was authorized to create. A hash alone cannot distinguish a
/// different valid policy resource, so both the kind and the exact identity
/// must agree with the durable tenant-resource journal.
pub(crate) fn exact_vp_trust_policy_binding(
    binding: &TenantResourceRecoveryBinding,
    policy: &nazo_operator_protocol::Openid4vpTrustPolicyBinding,
) -> bool {
    let (Some(binding_id), Some(resource_id), Some(resource_digest)) = (
        policy.binding_id.as_deref(),
        policy.resource_id.as_deref(),
        policy.resource_digest.as_deref(),
    ) else {
        return false;
    };
    if !uuid::Uuid::parse_str(binding_id).is_ok_and(|parsed| parsed.to_string() == binding_id) {
        return false;
    }
    let mut matching = binding
        .resource_identities
        .iter()
        .filter(|identity| identity.kind == TenantResourceKind::Openid4vcTrustPolicy);
    let Some(identity) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && identity.resource_id == resource_id
        && identity.digest == resource_digest
}

fn validate_suite_retention_manifest_path(
    record: &SuiteRetentionRecord,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    let expected_name = format!("retained-suite-{}.json", binding.run_id);
    if record_path_is_invalid(&record.manifest_path, &expected_name) {
        bail!("Suite retention manifest path is outside policy");
    }
    Ok(())
}

fn record_path_is_invalid(path: &Path, expected_name: &str) -> bool {
    !retention_manifest_parent_has_allowed_owner(path)
        || !path.is_absolute()
        || path.file_name().and_then(|value| value.to_str()) != Some(expected_name)
        || crate::secure_file::normalize_absolute(path).is_err()
        || path.parent().is_none()
        || crate::secure_file::validate_directory(path.parent().unwrap_or(Path::new(".")), true)
            .is_err()
}

fn retention_manifest_parent_has_allowed_owner(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        path.parent()
            .and_then(|parent| std::fs::metadata(parent).ok())
            .is_some_and(|metadata| retention_manifest_owner_is_allowed(metadata.uid()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(all(unix, not(test)))]
fn retention_manifest_owner_is_allowed(uid: u32) -> bool {
    uid == 0
}

#[cfg(all(unix, test))]
fn retention_manifest_owner_is_allowed(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn tenant_resource_obligations_complete(journal: &TenantResourceRecoveryJournal) -> bool {
    if journal.terminal_failure.is_some() {
        return false;
    }
    if journal.tenant_absence_revision.is_some() {
        return true;
    }
    let Some(enumerate) = &journal.cleanup_enumerate else {
        return false;
    };
    if journal.apply.is_none() {
        return false;
    }
    let Some(ControlResultData::TenantResourceEnumerate { resources, .. }) =
        &enumerate.result.result
    else {
        return false;
    };
    let present = resources
        .iter()
        .filter(|candidate| {
            journal
                .binding
                .resource_identities
                .iter()
                .any(|bound| bound == *candidate)
        })
        .count();
    if present == 0 {
        return true;
    }
    journal.cleanup_revoke.is_some()
}

fn record_operation(
    slot: &mut Option<TenantResourceControlOperation>,
    operation: TenantResourceControlOperation,
    label: &str,
) -> anyhow::Result<()> {
    if let Some(existing) = slot {
        if existing != &operation {
            bail!("{label} control operation conflicts with recovery journal");
        }
        return Ok(());
    }
    *slot = Some(operation);
    Ok(())
}

fn validate_control_identity(operation: &TenantResourceControlOperation) -> anyhow::Result<()> {
    let operation_id = uuid::Uuid::parse_str(&operation.operation_id)
        .map_err(|_| anyhow::anyhow!("control operation ID is invalid"))?;
    if operation_id.to_string() != operation.operation_id
        || !lower_hex(&operation.request_hash, 64)
        || operation.controller_kid.len() != 43
        || !operation
            .controller_kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || operation.result.operation_id != operation.operation_id
        || operation.result.request_hash != operation.request_hash
    {
        bail!("control operation result is invalid");
    }
    Ok(())
}

fn validate_control_operation(operation: &TenantResourceControlOperation) -> anyhow::Result<()> {
    validate_control_identity(operation)?;
    if operation.result.outcome != ControlOutcome::Succeeded
        || operation.result.error.is_some()
        || operation.result.result.is_none()
    {
        bail!("control operation result is invalid");
    }
    Ok(())
}

fn validate_apply_operation(
    binding: &TenantResourceRecoveryBinding,
    operation: &TenantResourceControlOperation,
) -> anyhow::Result<()> {
    validate_control_operation(operation)?;
    let Some(ControlResultData::TenantResourceApply {
        resources,
        resource_mappings,
        resource_manifest_sha256,
        ..
    }) = &operation.result.result
    else {
        bail!("ordinary Apply has no typed Apply result");
    };
    if !identity_sets_equal(resources, &binding.resource_identities)
        || !lower_hex(resource_manifest_sha256, 64)
        || !valid_apply_mappings(resource_mappings, resources)
    {
        bail!("ordinary Apply result does not match run resources");
    }
    Ok(())
}

fn validate_enumerate_operation(
    binding: &TenantResourceRecoveryBinding,
    operation: &TenantResourceControlOperation,
) -> anyhow::Result<()> {
    validate_control_operation(operation)?;
    let Some(ControlResultData::TenantResourceEnumerate {
        resources,
        resource_manifest_sha256,
        ..
    }) = &operation.result.result
    else {
        bail!("ordinary cleanup has no typed Enumerate result");
    };
    validate_tenant_resource_identities(resources, false)?;
    if !lower_hex(resource_manifest_sha256, 64) {
        bail!("ordinary Enumerate result manifest digest is invalid");
    }
    for resource in resources {
        if binding.resource_identities.iter().any(|bound| {
            bound.kind == resource.kind
                && bound.resource_id == resource.resource_id
                && bound.digest != resource.digest
        }) {
            bail!("ordinary cleanup resource reappeared with a different digest");
        }
    }
    Ok(())
}

fn validate_revoke_operation(
    binding: &TenantResourceRecoveryBinding,
    enumerate: &TenantResourceControlOperation,
    operation: &TenantResourceControlOperation,
) -> anyhow::Result<()> {
    validate_control_operation(operation)?;
    let Some(ControlResultData::TenantResourceEnumerate {
        revision,
        resources,
        ..
    }) = &enumerate.result.result
    else {
        bail!("ordinary cleanup enumeration is invalid");
    };
    let Some(ControlResultData::TenantResourceRevoke {
        revision: revoke_revision,
        resources: revoked,
        resource_manifest_sha256,
    }) = &operation.result.result
    else {
        bail!("ordinary cleanup has no typed Revoke result");
    };
    let expected = resources
        .iter()
        .filter(|candidate| {
            binding
                .resource_identities
                .iter()
                .any(|bound| bound == *candidate)
        })
        .cloned()
        .collect::<Vec<_>>();
    if expected.is_empty()
        || !identity_sets_equal(revoked, &expected)
        || *revoke_revision
            != revision
                .checked_add(1)
                .context("cleanup revision overflow")?
        || !lower_hex(resource_manifest_sha256, 64)
    {
        bail!("ordinary Revoke result does not match persisted cleanup enumeration");
    }
    Ok(())
}

fn valid_apply_mappings(
    mappings: &[nazo_operator_protocol::TenantResourceMapping],
    resources: &[TenantResourceIdentity],
) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    mappings.iter().all(|mapping| {
        validate_file_identifier_value(&mapping.resource_id).is_ok()
            && !mapping.public_id.is_empty()
            && mapping.public_id.len() <= 512
            && !mapping.public_id.chars().any(char::is_control)
            && resources.iter().any(|resource| {
                resource.kind == mapping.kind && resource.resource_id == mapping.resource_id
            })
            && seen.insert((mapping.kind, mapping.resource_id.as_str()))
    })
}

fn validate_ordinary_binding(
    binding: &TenantResourceRecoveryBinding,
    deployment_id: &str,
) -> anyhow::Result<()> {
    validate_component(&binding.deployment_id, "deployment ID")?;
    validate_component(&binding.run_id, "run ID")?;
    let tenant_id = uuid::Uuid::parse_str(&binding.tenant_id)
        .map_err(|_| anyhow::anyhow!("tenant-resource tenant ID is invalid"))?;
    let realm_id = uuid::Uuid::parse_str(&binding.realm_id)
        .map_err(|_| anyhow::anyhow!("tenant-resource realm ID is invalid"))?;
    let organization_id = uuid::Uuid::parse_str(&binding.organization_id)
        .map_err(|_| anyhow::anyhow!("tenant-resource organization ID is invalid"))?;
    if binding.deployment_id != deployment_id
        || tenant_id.to_string() != binding.tenant_id
        || realm_id.to_string() != binding.realm_id
        || organization_id.to_string() != binding.organization_id
        || tenant_id == realm_id
        || tenant_id == organization_id
        || realm_id == organization_id
        || binding.manifest_path.is_some() != binding.material_sha256.is_some()
        || binding
            .manifest_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        || binding
            .material_sha256
            .as_deref()
            .is_some_and(|digest| !lower_hex(digest, 64))
        || binding.proxy.as_ref().is_some_and(|proxy| {
            !proxy.bundle_path.is_absolute() || !proxy.reload_executable.is_absolute()
        })
    {
        bail!("ordinary recovery binding is invalid");
    }
    validate_tenant_resource_identities(&binding.resource_identities, true)?;
    if let Some(anchor) = &binding.vp_evidence_trust_anchor {
        validate_vp_evidence_trust_anchor(anchor, binding)?;
    }
    Ok(())
}

fn validate_vp_evidence_trust_anchor(
    anchor: &OpenId4VpEvidenceTrustAnchor,
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<()> {
    validate_component(&anchor.deployment_id, "VP evidence deployment ID")?;
    validate_component(
        &anchor.runtime_instance_id,
        "VP evidence runtime instance ID",
    )?;
    validate_component(&anchor.instance_key_id, "VP evidence instance key ID")?;
    let issuer =
        url::Url::parse(&anchor.target_issuer).context("VP evidence target issuer is invalid")?;
    if anchor.deployment_id != binding.deployment_id
        || issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || !matches!(issuer.path(), "" | "/")
        || anchor.target_issuer != issuer.as_str().trim_end_matches('/')
    {
        bail!("VP evidence trust anchor conflicts with the recovery binding");
    }
    let key =
        nazo_operator_protocol::decode_instance_public_key(&anchor.instance_public_key_base64)
            .context("VP evidence instance public key is invalid")?;
    if nazo_operator_protocol::instance_key_id(&key) != anchor.instance_key_id {
        bail!("VP evidence instance key ID conflicts with its public key");
    }
    Ok(())
}

fn validate_tenant_resource_manifest_file(
    binding: &TenantResourceRecoveryBinding,
) -> anyhow::Result<bool> {
    let (Some(path), Some(expected_digest)) = (&binding.manifest_path, &binding.material_sha256)
    else {
        return Ok(false);
    };
    if !path.is_absolute() {
        bail!("ordinary material path must be absolute");
    }
    let bytes =
        match crate::secure_file::read_bounded(path, MAX_TENANT_RESOURCE_MANIFEST_BYTES, true) {
            Ok(bytes) => bytes,
            Err(crate::secure_file::SecureFileError::NotFound) => return Ok(false),
            Err(error) => bail!("ordinary material is not secure: {error:?}"),
        };
    if sha256_hex(&bytes) != *expected_digest {
        bail!("ordinary material digest conflicts with recovery binding");
    }
    Ok(true)
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
    left.len() == right.len()
        && left
            .iter()
            .all(|identity| right.iter().any(|candidate| candidate == identity))
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
    use ::nazo_operator_protocol::{ControlOutcome, TenantResourceMapping};

    fn identity() -> TenantResourceIdentity {
        TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client-1".to_owned(),
            digest: "a".repeat(64),
        }
    }

    fn binding() -> TenantResourceRecoveryBinding {
        TenantResourceRecoveryBinding {
            deployment_id: "deployment-1".to_owned(),
            tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
            realm_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            organization_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            run_id: "run-1".to_owned(),
            tenant_create_expected_revision: 0,
            manifest_path: None,
            material_sha256: None,
            proxy: None,
            vp_evidence_trust_anchor: None,
            resource_identities: vec![identity()],
        }
    }

    fn operation(result: ControlResultData) -> TenantResourceControlOperation {
        let operation_id = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        TenantResourceControlOperation {
            operation_id: operation_id.clone(),
            request_hash: "b".repeat(64),
            controller_kid: "c".repeat(43),
            result: ControlResult {
                schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
                operation_id,
                request_hash: "b".repeat(64),
                outcome: ControlOutcome::Succeeded,
                error: None,
                accepted_at: 1,
                completed_at: Some(2),
                result: Some(result),
            },
        }
    }

    #[test]
    fn typed_apply_enumerate_and_revoke_are_cross_checked_without_public_id_guessing() {
        let binding = binding();
        let apply = operation(ControlResultData::TenantResourceApply {
            revision: 2,
            resources: vec![identity()],
            resource_mappings: vec![TenantResourceMapping {
                kind: TenantResourceKind::OauthClient,
                resource_id: "client-1".to_owned(),
                public_id: "public-client-1".to_owned(),
            }],
            resource_manifest_sha256: "d".repeat(64),
        });
        validate_apply_operation(&binding, &apply).expect("typed Apply");
        let enumerate = operation(ControlResultData::TenantResourceEnumerate {
            revision: 2,
            resources: vec![identity()],
            resource_manifest_sha256: "d".repeat(64),
        });
        validate_enumerate_operation(&binding, &enumerate).expect("typed enumerate");
        let revoke = operation(ControlResultData::TenantResourceRevoke {
            revision: 3,
            resources: vec![identity()],
            resource_manifest_sha256: "e".repeat(64),
        });
        validate_revoke_operation(&binding, &enumerate, &revoke).expect("typed revoke");
    }

    #[test]
    fn authoritative_tenant_absence_settles_rewound_run_resources() {
        let journal = TenantResourceRecoveryJournal {
            schema: TENANT_RESOURCE_RECOVERY_JOURNAL_SCHEMA,
            kind: TENANT_RESOURCE_RECOVERY_KIND.to_owned(),
            binding: binding(),
            phase: TenantResourceRecoveryPhase::Intent,
            tenant_created: true,
            tenant_key_generated: true,
            tenant_reload_expected_revision: Some(48),
            tenant_reloaded: true,
            tenant_disable_expected_revision: None,
            tenant_disabled: false,
            tenant_finalize_expected_revision: None,
            tenant_cleanup_complete: true,
            tenant_absence_revision: Some(49),
            baseline_enumerate: None,
            apply: None,
            cleanup_enumerate: None,
            cleanup_revoke: None,
            terminal_failure: None,
            cleanup_complete: true,
            manifest_removal_intent: false,
            manifest_cleanup_complete: false,
            proxy_cleanup_complete: true,
            suite: None,
            suite_retention: SuiteRetentionDisposition::default(),
        };

        validate_tenant_resource_journal(&journal, "deployment-1")
            .expect("authoritative absence did not settle the rewound tenant");
        assert!(tenant_resource_obligations_complete(&journal));
    }
}
