#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

use nazo_operator_protocol::{PROTOCOL_VERSION, TenantResourceOperation, TenantResourceOutcome};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
#[cfg(unix)]
use zeroize::Zeroizing;

use crate::{ConformanceReport, VerifiedOidfArtifact};

#[cfg(unix)]
const EVIDENCE_BUNDLE_SCHEMA: u32 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRuntimeIdentity {
    OciImage { digest: String },
    HostBinary { sha256: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeploymentIdentity {
    pub deployment_id: String,
    pub target_issuer: String,
    pub release: String,
    pub revision: String,
    pub build_id: String,
    pub runtime: EvidenceRuntimeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSourceIdentity {
    LegacyOperatorMatrix {
        source_release: String,
        matrix_sha256: String,
        suite_origin: String,
    },
    SignedOidfArtifact {
        suite_origin: String,
        artifact: Box<VerifiedOidfArtifact>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleIdentity {
    pub run_jti: String,
    pub deployment: EvidenceDeploymentIdentity,
    pub source: EvidenceSourceIdentity,
    /// Optional for legacy Suite-only evidence.  Ordinary provider evidence
    /// must use [`write_private_provider_evidence_bundle`], which requires
    /// this binding and validates every receipt before any file is written.
    #[serde(default)]
    pub provider: Option<EvidenceProviderIdentity>,
    pub outer_cleanup_complete: bool,
}

/// Ordinary tenant-resource capability provenance captured in a conformance
/// evidence bundle.  The compact JWS itself is intentionally not persisted;
/// its digest and signed identity are enough to bind the evidence without
/// copying capability payload or secret material into the evidence directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProviderIdentity {
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub runtime: EvidenceRuntimeIdentity,
    pub release: String,
    pub runtime_revision: String,
    pub protocol: u32,
    pub build_id: String,
    /// Capabilities are ordered by the provider state they observed.  A
    /// successful Apply/Revoke advances the state, so later operations must
    /// use a newly discovered capability at the resulting revision.
    pub capabilities: Vec<EvidenceProviderCapability>,
    pub cleanup_complete: bool,
}

/// One freshness-verified capability generation and only the receipts issued
/// under that generation.  Deployment/runtime identity is retained once at
/// [`EvidenceProviderIdentity`] and every receipt repeats the tenant and
/// capability digest/JTI binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProviderCapability {
    pub capability_compact_sha256: String,
    pub capability_jti: String,
    pub tenant_id: String,
    pub revision: u64,
    pub resource_manifest_sha256: String,
    pub receipts: Vec<EvidenceProviderReceipt>,
}

/// Receipt binding retained for each ordinary provider operation.  It keeps
/// identity, CAS revision, manifest/change-set, and audit-chain fields while
/// excluding signed payloads and resource configuration values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProviderReceipt {
    pub action: TenantResourceOperation,
    pub compact_sha256: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub tenant_id: String,
    pub capability_jti: String,
    pub capability_compact_sha256: String,
    pub expected_revision: u64,
    pub revision: u64,
    pub change_set_id: String,
    pub change_set_sha256: String,
    pub baseline_manifest_sha256: String,
    pub resource_manifest_sha256: String,
    pub outcome: TenantResourceOutcome,
    pub audit_sequence: u64,
    pub audit_previous_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleReceipt {
    pub schema: u32,
    pub evidence_jti: String,
    pub directory: PathBuf,
    pub manifest_sha256: String,
    pub module_count: u32,
}

/// Digest-bound local capture manifest that can be embedded in the Suite
/// retention journal without carrying any image bytes, URLs, secrets, or
/// Suite credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewScreenshotManifestReceipt {
    pub path: PathBuf,
    pub sha256: String,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest<'a> {
    schema: u32,
    evidence_jti: &'a str,
    identity: &'a EvidenceBundleIdentity,
    public_report_file: &'static str,
    public_report_sha256: String,
    modules: Vec<EvidenceModuleManifest>,
    screenshots: Vec<EvidenceScreenshotManifest>,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceScreenshotManifest {
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    path: PathBuf,
    sha256: String,
    size: usize,
    receipt_sha256: String,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotAudit {
    suite_plan_id: String,
    module_id: String,
    path: PathBuf,
    sha256: String,
    size: usize,
    trigger_origin: String,
    trigger_path: String,
    trigger_url_sha256: String,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceModuleManifest {
    index: u32,
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: Option<String>,
    test_name: String,
    file: String,
    sha256: String,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateModuleEvidence<'a> {
    schema: u32,
    evidence_jti: &'a str,
    index: u32,
    matrix_plan_id: &'a str,
    suite_plan_id: &'a str,
    module_id: &'a Option<String>,
    test_name: &'a str,
    info: &'a serde_json::Value,
    log: &'a serde_json::Value,
}

pub fn write_private_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_identity(report, identity)?;
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(EvidenceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let root =
            crate::secure_file::ensure_directory(root, true).map_err(map_secure_file_error)?;
        let evidence_jti = uuid::Uuid::now_v7().to_string();
        let directory =
            crate::secure_file::ensure_directory(&root.join(format!("run-{evidence_jti}")), true)
                .map_err(map_secure_file_error)?;
        match crate::secure_file::read_bounded(&directory.join("manifest.json"), 1, true) {
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Ok(_) | Err(crate::secure_file::SecureFileError::Oversize) => {
                return Err(EvidenceError::Conflict);
            }
            Err(error) => return Err(map_secure_file_error(error)),
        }

        let public_report = report
            .to_json_bytes()
            .map_err(|_| EvidenceError::Encoding)?;
        crate::secure_file::write_atomic(&directory.join("report.json"), &public_report, true)
            .map_err(map_secure_file_error)?;

        let mut modules = Vec::with_capacity(report.modules.len());
        let mut screenshots = Vec::new();
        let mut screenshot_paths = BTreeSet::new();
        let mut total_screenshot_bytes = 0usize;
        for (index, module) in report.modules.iter().enumerate() {
            validate_review_screenshot_obligations(module)?;
            let index = u32::try_from(index).map_err(|_| EvidenceError::Encoding)?;
            let file = format!("module-{index:04}.json");
            let bytes = Zeroizing::new(
                serde_json::to_vec(&PrivateModuleEvidence {
                    schema: EVIDENCE_BUNDLE_SCHEMA,
                    evidence_jti: &evidence_jti,
                    index,
                    matrix_plan_id: &module.matrix_plan_id,
                    suite_plan_id: &module.suite_plan_id,
                    module_id: &module.module_id,
                    test_name: &module.test_name,
                    info: &module.raw_info,
                    log: &module.raw_log,
                })
                .map_err(|_| EvidenceError::Encoding)?,
            );
            crate::secure_file::write_atomic(&directory.join(&file), bytes.as_slice(), true)
                .map_err(map_secure_file_error)?;
            modules.push(EvidenceModuleManifest {
                index,
                matrix_plan_id: module.matrix_plan_id.clone(),
                suite_plan_id: module.suite_plan_id.clone(),
                module_id: module.module_id.clone(),
                test_name: module.test_name.clone(),
                file,
                sha256: sha256(bytes.as_slice()),
            });
            for screenshot in &module.review_screenshots {
                let module_id = module.module_id.as_deref().ok_or(EvidenceError::Identity)?;
                if !screenshot_paths.insert(screenshot.path.clone()) {
                    return Err(EvidenceError::Identity);
                }
                validate_review_screenshot_path(&screenshot.path)?;
                let source = root.join(&screenshot.path);
                let screenshot_bytes = crate::secure_file::read_bounded(&source, 500 * 1024, true)
                    .map_err(map_secure_file_error)?;
                if screenshots.len() >= crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN
                    || screenshot_bytes.len() > 32 * 1024 * 1024 - total_screenshot_bytes
                {
                    return Err(EvidenceError::Identity);
                }
                crate::browser::validate_png_screenshot(&screenshot_bytes)
                    .map_err(|_| EvidenceError::Identity)?;
                if screenshot_bytes.len() != screenshot.size
                    || sha256(&screenshot_bytes) != screenshot.sha256
                {
                    return Err(EvidenceError::Identity);
                }
                let receipt_source = source.with_extension("png.receipt.json");
                let receipt = crate::secure_file::read_bounded(&receipt_source, 16 * 1024, true)
                    .map_err(map_secure_file_error)?;
                let audit: ReviewScreenshotAudit =
                    serde_json::from_slice(&receipt).map_err(|_| EvidenceError::Identity)?;
                if audit.suite_plan_id != module.suite_plan_id
                    || audit.module_id != module_id
                    || audit.path != screenshot.path
                    || audit.sha256 != screenshot.sha256
                    || audit.size != screenshot.size
                    || audit.trigger_origin != report.suite_origin
                    || !crate::browser::review_screenshot_path_binds_module(
                        &url::Url::parse(&format!(
                            "{}{}",
                            audit.trigger_origin, audit.trigger_path
                        ))
                        .map_err(|_| EvidenceError::Identity)?,
                        module_id,
                    )
                    || !lower_hex(&audit.trigger_url_sha256, 64)
                {
                    return Err(EvidenceError::Identity);
                }
                let destination = directory.join(&screenshot.path);
                crate::secure_file::write_atomic(&destination, &screenshot_bytes, true)
                    .map_err(map_secure_file_error)?;
                crate::secure_file::write_atomic(
                    &destination.with_extension("png.receipt.json"),
                    &receipt,
                    true,
                )
                .map_err(map_secure_file_error)?;
                screenshots.push(EvidenceScreenshotManifest {
                    matrix_plan_id: module.matrix_plan_id.clone(),
                    suite_plan_id: module.suite_plan_id.clone(),
                    module_id: module_id.to_owned(),
                    path: screenshot.path.clone(),
                    sha256: screenshot.sha256.clone(),
                    size: screenshot.size,
                    receipt_sha256: sha256(&receipt),
                });
                total_screenshot_bytes = total_screenshot_bytes.saturating_add(screenshot.size);
            }
        }

        let module_count = u32::try_from(modules.len()).map_err(|_| EvidenceError::Encoding)?;
        let manifest = serde_json::to_vec_pretty(&EvidenceManifest {
            schema: EVIDENCE_BUNDLE_SCHEMA,
            evidence_jti: &evidence_jti,
            identity,
            public_report_file: "report.json",
            public_report_sha256: sha256(&public_report),
            modules,
            screenshots,
        })
        .map_err(|_| EvidenceError::Encoding)?;
        crate::secure_file::write_atomic(&directory.join("manifest.json"), &manifest, true)
            .map_err(map_secure_file_error)?;
        Ok(EvidenceBundleReceipt {
            schema: EVIDENCE_BUNDLE_SCHEMA,
            evidence_jti,
            directory,
            manifest_sha256: sha256(&manifest),
            module_count,
        })
    }
}

#[cfg(unix)]
fn validate_review_screenshot_path(path: &Path) -> Result<(), EvidenceError> {
    let mut components = path.components();
    let Some(Component::Normal(directory)) = components.next() else {
        return Err(EvidenceError::UnsafePath);
    };
    let Some(Component::Normal(file)) = components.next() else {
        return Err(EvidenceError::UnsafePath);
    };
    if components.next().is_some()
        || directory != "review-screenshots"
        || !file.to_string_lossy().ends_with(".png")
        || file.len() > 240
        || !file
            .as_encoded_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
    {
        return Err(EvidenceError::UnsafePath);
    }
    Ok(())
}

/// Writes evidence for an ordinary tenant-resource provider run.  Legacy
/// Suite-only callers continue to use [`write_private_evidence_bundle`], but
/// this entry point refuses to commit a bundle without the signed capability
/// binding and receipt evidence.
pub fn write_private_provider_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_ordinary_provider_identity(report, identity)?;
    write_private_evidence_bundle(report, root, identity)
}

/// Commits the screenshot-to-current-module binding before Suite plan
/// ownership can be retained. It intentionally references the root-private
/// image files in place; the full provider evidence bundle later copies and
/// rebinds the same verified files into its own committed directory.
pub fn write_review_screenshot_manifest(
    report: &ConformanceReport,
    root: &Path,
    run_jti: &str,
    artifact_digest: &str,
) -> Result<ReviewScreenshotManifestReceipt, EvidenceError> {
    #[cfg(not(unix))]
    {
        let _ = (report, root, run_jti, artifact_digest);
        Err(EvidenceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        if crate::artifact::validate_identifier(run_jti, 128).is_err() {
            return Err(EvidenceError::Identity);
        }
        let root =
            crate::secure_file::validate_directory(root, true).map_err(map_secure_file_error)?;
        if !lower_hex(artifact_digest, 64) {
            return Err(EvidenceError::Identity);
        }
        let mut modules = Vec::with_capacity(report.modules.len());
        let mut screenshots = Vec::new();
        let mut paths = BTreeSet::new();
        let mut total_screenshot_bytes = 0usize;
        for module in &report.modules {
            validate_review_screenshot_obligations(module)?;
            modules.push(ReviewScreenshotModuleManifest {
                matrix_plan_id: module.matrix_plan_id.clone(),
                suite_plan_id: module.suite_plan_id.clone(),
                module_id: module.module_id.clone().ok_or(EvidenceError::Identity)?,
                test_name: module.test_name.clone(),
                variant: module.variant.clone(),
                required: module.review_screenshots_required,
                captured_required: module.review_screenshots_required_captured,
                missing_optional: module.review_screenshots_missing,
            });
            for screenshot in &module.review_screenshots {
                let module_id = module.module_id.as_deref().ok_or(EvidenceError::Identity)?;
                if !paths.insert(screenshot.path.clone()) {
                    return Err(EvidenceError::Identity);
                }
                validate_review_screenshot_path(&screenshot.path)?;
                let source = root.join(&screenshot.path);
                let image = crate::secure_file::read_bounded(&source, 500 * 1024, true)
                    .map_err(map_secure_file_error)?;
                if screenshots.len() >= crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN
                    || image.len() > 32 * 1024 * 1024 - total_screenshot_bytes
                {
                    return Err(EvidenceError::Identity);
                }
                crate::browser::validate_png_screenshot(&image)
                    .map_err(|_| EvidenceError::Identity)?;
                if image.len() != screenshot.size || sha256(&image) != screenshot.sha256 {
                    return Err(EvidenceError::Identity);
                }
                let receipt = crate::secure_file::read_bounded(
                    &source.with_extension("png.receipt.json"),
                    16 * 1024,
                    true,
                )
                .map_err(map_secure_file_error)?;
                let audit: ReviewScreenshotAudit =
                    serde_json::from_slice(&receipt).map_err(|_| EvidenceError::Identity)?;
                if audit.suite_plan_id != module.suite_plan_id
                    || audit.module_id != module_id
                    || audit.path != screenshot.path
                    || audit.sha256 != screenshot.sha256
                    || audit.size != screenshot.size
                    || audit.trigger_origin != report.suite_origin
                    || !crate::browser::review_screenshot_path_binds_module(
                        &url::Url::parse(&format!(
                            "{}{}",
                            audit.trigger_origin, audit.trigger_path
                        ))
                        .map_err(|_| EvidenceError::Identity)?,
                        module_id,
                    )
                    || !lower_hex(&audit.trigger_url_sha256, 64)
                {
                    return Err(EvidenceError::Identity);
                }
                screenshots.push(EvidenceScreenshotManifest {
                    matrix_plan_id: module.matrix_plan_id.clone(),
                    suite_plan_id: module.suite_plan_id.clone(),
                    module_id: module_id.to_owned(),
                    path: screenshot.path.clone(),
                    sha256: screenshot.sha256.clone(),
                    size: screenshot.size,
                    receipt_sha256: sha256(&receipt),
                });
                total_screenshot_bytes = total_screenshot_bytes.saturating_add(image.len());
            }
        }
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 2,
            "run_jti": run_jti,
            "artifact_digest": artifact_digest,
            "matrix_sha256": report.matrix_digest,
            "suite_origin": report.suite_origin,
            "modules": modules,
            "screenshots": screenshots,
        }))
        .map_err(|_| EvidenceError::Encoding)?;
        let path = root
            .join("review-screenshot-manifests")
            .join(format!("{run_jti}.json"));
        write_private_new_or_exact(&path, &bytes)?;
        Ok(ReviewScreenshotManifestReceipt {
            path,
            sha256: sha256(&bytes),
        })
    }
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewScreenshotModuleManifest {
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: std::collections::BTreeMap<String, String>,
    required: usize,
    captured_required: usize,
    missing_optional: usize,
}

#[cfg(unix)]
fn write_private_new_or_exact(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    match crate::secure_file::read_bounded(path, bytes.len(), true) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) | Err(crate::secure_file::SecureFileError::Oversize) => Err(EvidenceError::Conflict),
        Err(crate::secure_file::SecureFileError::NotFound) => {
            crate::secure_file::write_atomic(path, bytes, true).map_err(map_secure_file_error)
        }
        Err(error) => Err(map_secure_file_error(error)),
    }
}

#[cfg(unix)]
fn validate_review_screenshot_obligations(
    module: &crate::report::ModuleReport,
) -> Result<(), EvidenceError> {
    if module.review_screenshots_required != module.review_screenshots_required_captured
        || module.review_screenshots_required_captured > module.review_screenshots.len()
        || module
            .review_screenshots
            .len()
            .saturating_add(module.review_screenshots_missing)
            > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_MODULE
    {
        return Err(EvidenceError::Identity);
    }
    Ok(())
}

/// Validates ordinary provider evidence without touching the filesystem.  A
/// cleanup failure is retained as evidence (`cleanup_complete=false`) and is
/// therefore deliberately not rejected here; the caller decides whether that
/// run is successful.
pub fn validate_ordinary_provider_identity(
    report: &ConformanceReport,
    identity: &EvidenceBundleIdentity,
) -> Result<(), EvidenceError> {
    validate_identity(report, identity)?;
    if identity.provider.is_none() {
        return Err(EvidenceError::Identity);
    }
    Ok(())
}

/// Retention evidence must target an existing root-owned safe directory before
/// Suite allocation begins; unlike ordinary evidence this preflight never
/// creates an operator-selected path.
pub fn validate_private_evidence_directory(root: &Path) -> Result<(), EvidenceError> {
    let root = crate::secure_file::validate_directory(root, true).map_err(map_secure_file_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(root).map_err(|_| EvidenceError::Io)?;
        if metadata.uid() != 0 {
            return Err(EvidenceError::UnsafePath);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(EvidenceError::UnsupportedPlatform)
    }
}

fn validate_identity(
    report: &ConformanceReport,
    identity: &EvidenceBundleIdentity,
) -> Result<(), EvidenceError> {
    if crate::artifact::validate_identifier(&identity.run_jti, 128).is_err()
        || crate::artifact::validate_identifier(&identity.deployment.deployment_id, 128).is_err()
        || !bounded(&identity.deployment.release, 128)
        || !lower_hex(&identity.deployment.revision, 40)
        || !bounded(&identity.deployment.build_id, 256)
        || identity.deployment.target_issuer.ends_with('/')
    {
        return Err(EvidenceError::Identity);
    }
    url::Url::parse(&identity.deployment.target_issuer)
        .ok()
        .filter(|url| url.scheme() == "https" && url.host_str().is_some())
        .ok_or(EvidenceError::Identity)?;
    if !valid_runtime_identity(&identity.deployment.runtime) {
        return Err(EvidenceError::Identity);
    }
    let (matrix_sha256, suite_origin) = match &identity.source {
        EvidenceSourceIdentity::LegacyOperatorMatrix {
            source_release,
            matrix_sha256,
            suite_origin,
        } => {
            if !bounded(source_release, 128) || !lower_hex(matrix_sha256, 64) {
                return Err(EvidenceError::Identity);
            }
            (matrix_sha256, suite_origin)
        }
        EvidenceSourceIdentity::SignedOidfArtifact {
            suite_origin,
            artifact,
        } => {
            if !lower_hex(&artifact.matrix_sha256, 64)
                || !lower_hex(&artifact.driver_manifest_sha256, 64)
                || !lower_hex(&artifact.driver_sha256, 64)
            {
                return Err(EvidenceError::Identity);
            }
            (&artifact.matrix_sha256, suite_origin)
        }
    };
    if report.matrix_digest != *matrix_sha256 || report.suite_origin != *suite_origin {
        return Err(EvidenceError::Identity);
    }
    if let Some(provider) = identity.provider.as_ref() {
        validate_provider_identity(identity, provider)?;
    }
    Ok(())
}

fn validate_provider_identity(
    identity: &EvidenceBundleIdentity,
    provider: &EvidenceProviderIdentity,
) -> Result<(), EvidenceError> {
    if provider.deployment_id != identity.deployment.deployment_id
        || provider.release != identity.deployment.release
        || provider.runtime_revision != identity.deployment.revision
        || provider.build_id != identity.deployment.build_id
        || provider.runtime != identity.deployment.runtime
        || crate::artifact::validate_identifier(&provider.runtime_instance_id, 128).is_err()
        || !valid_runtime_identity(&provider.runtime)
        || !bounded(&provider.release, 128)
        || !bounded(&provider.runtime_revision, 128)
        || provider.protocol != PROTOCOL_VERSION
        || !bounded(&provider.build_id, 256)
        || provider.capabilities.is_empty()
        || identity.outer_cleanup_complete != provider.cleanup_complete
    {
        return Err(EvidenceError::Identity);
    }

    let mut capability_jtis = std::collections::BTreeSet::new();
    let mut capability_digests = std::collections::BTreeSet::new();
    let mut receipt_jtis = std::collections::BTreeSet::new();
    let mut last_audit_sequence = 0;
    let mut previous_revision = None;
    let mut previous_manifest = None;
    let mut tenant_id = None;
    let mut saw_apply = false;
    let mut saw_enumerate = false;
    let mut saw_revoke = false;
    let mut apply_capability_index = None;
    let mut apply_baseline_manifest = None;
    let mut cleanup_enumerate_capability_index = None;
    let mut cleanup_enumerate_manifest = None;
    let mut revoke_capability_index = None;
    let mut revoke_final_manifest = None;
    let mut final_capability_has_enumerate = false;

    for (capability_index, capability) in provider.capabilities.iter().enumerate() {
        if !lower_hex(&capability.capability_compact_sha256, 64)
            || crate::artifact::validate_identifier(&capability.capability_jti, 128).is_err()
            || !Uuid::parse_str(&capability.tenant_id)
                .ok()
                .is_some_and(|tenant| tenant.hyphenated().to_string() == capability.tenant_id)
            || !lower_hex(&capability.resource_manifest_sha256, 64)
            || capability.receipts.is_empty()
            || !capability_jtis.insert(capability.capability_jti.as_str())
            || !capability_digests.insert(capability.capability_compact_sha256.as_str())
        {
            return Err(EvidenceError::Identity);
        }

        if let Some(previous_tenant) = &tenant_id {
            if previous_tenant != &capability.tenant_id {
                return Err(EvidenceError::Identity);
            }
        } else {
            tenant_id = Some(capability.tenant_id.clone());
        }
        if previous_revision != Some(capability.revision) && previous_revision.is_some() {
            return Err(EvidenceError::Identity);
        }
        if previous_manifest.as_deref() != Some(capability.resource_manifest_sha256.as_str())
            && previous_manifest.is_some()
        {
            return Err(EvidenceError::Identity);
        }

        let mut state_revision = capability.revision;
        let mut state_manifest = capability.resource_manifest_sha256.clone();
        let mut mutation_seen = false;
        let mut capability_has_enumerate = false;
        for receipt in &capability.receipts {
            if mutation_seen
                || !lower_hex(&receipt.compact_sha256, 64)
                || crate::artifact::validate_identifier(&receipt.jti, 128).is_err()
                || !lower_hex(&receipt.request_sha256, 64)
                || receipt.deployment_id != provider.deployment_id
                || receipt.tenant_id != capability.tenant_id
                || receipt.capability_jti != capability.capability_jti
                || receipt.capability_compact_sha256 != capability.capability_compact_sha256
                || receipt.expected_revision != capability.revision
                || receipt.baseline_manifest_sha256 != state_manifest
                || !crate::artifact::validate_identifier(&receipt.change_set_id, 128).is_ok()
                || !lower_hex(&receipt.change_set_sha256, 64)
                || !lower_hex(&receipt.resource_manifest_sha256, 64)
                || receipt.audit_sequence == 0
                || receipt.audit_sequence <= last_audit_sequence
                || !lower_hex(&receipt.audit_previous_sha256, 64)
                || !receipt_jtis.insert(receipt.jti.as_str())
            {
                return Err(EvidenceError::Identity);
            }
            last_audit_sequence = receipt.audit_sequence;
            if matches!(
                receipt.action,
                TenantResourceOperation::Apply | TenantResourceOperation::Revoke
            ) && !capability_has_enumerate
            {
                return Err(EvidenceError::Identity);
            }
            if receipt.action == TenantResourceOperation::Revoke && !saw_apply {
                return Err(EvidenceError::Identity);
            }
            match &receipt.outcome {
                TenantResourceOutcome::Failed { code } => {
                    if !bounded(code, 128) || receipt.revision != receipt.expected_revision {
                        return Err(EvidenceError::Identity);
                    }
                }
                TenantResourceOutcome::Succeeded => match receipt.action {
                    TenantResourceOperation::Enumerate => {
                        if receipt.revision != receipt.expected_revision
                            || receipt.resource_manifest_sha256 != state_manifest
                        {
                            return Err(EvidenceError::Identity);
                        }
                        saw_enumerate = true;
                        capability_has_enumerate = true;
                        if apply_capability_index.is_some_and(|index| capability_index > index) {
                            cleanup_enumerate_capability_index.get_or_insert(capability_index);
                            cleanup_enumerate_manifest
                                .get_or_insert_with(|| receipt.resource_manifest_sha256.clone());
                        }
                    }
                    TenantResourceOperation::Apply | TenantResourceOperation::Revoke => {
                        if receipt.revision
                            != receipt
                                .expected_revision
                                .checked_add(1)
                                .ok_or(EvidenceError::Identity)?
                        {
                            return Err(EvidenceError::Identity);
                        }
                        mutation_seen = true;
                        state_revision = receipt.revision;
                        state_manifest = receipt.resource_manifest_sha256.clone();
                        if receipt.action == TenantResourceOperation::Apply {
                            if !capability_has_enumerate || saw_apply {
                                return Err(EvidenceError::Identity);
                            }
                            saw_apply = true;
                            apply_capability_index.get_or_insert(capability_index);
                            apply_baseline_manifest =
                                Some(capability.resource_manifest_sha256.clone());
                        } else {
                            if !capability_has_enumerate
                                || saw_revoke
                                || !saw_apply
                                || cleanup_enumerate_capability_index
                                    .is_none_or(|index| capability_index < index)
                            {
                                return Err(EvidenceError::Identity);
                            }
                            saw_revoke = true;
                            revoke_capability_index.get_or_insert(capability_index);
                            revoke_final_manifest = Some(receipt.resource_manifest_sha256.clone());
                        }
                    }
                },
            }
        }
        previous_revision = Some(state_revision);
        previous_manifest = Some(state_manifest);
        final_capability_has_enumerate = capability_has_enumerate;
    }

    if !saw_apply || !saw_enumerate {
        return Err(EvidenceError::Identity);
    }
    let Some(apply_baseline_manifest) = apply_baseline_manifest else {
        return Err(EvidenceError::Identity);
    };
    if provider.cleanup_complete {
        let Some(cleanup_enumerate_manifest) = cleanup_enumerate_manifest else {
            return Err(EvidenceError::Identity);
        };
        if !final_capability_has_enumerate {
            return Err(EvidenceError::Identity);
        }
        if cleanup_enumerate_manifest != apply_baseline_manifest {
            if !saw_revoke
                || revoke_capability_index <= apply_capability_index
                || revoke_capability_index != Some(provider.capabilities.len() - 1)
                || revoke_final_manifest.as_deref() != Some(apply_baseline_manifest.as_str())
            {
                return Err(EvidenceError::Identity);
            }
        } else if saw_revoke
            && revoke_final_manifest.as_deref() != Some(apply_baseline_manifest.as_str())
        {
            return Err(EvidenceError::Identity);
        }
    } else if saw_revoke
        && revoke_final_manifest.as_deref() != Some(apply_baseline_manifest.as_str())
    {
        return Err(EvidenceError::Identity);
    }
    Ok(())
}

fn valid_runtime_identity(runtime: &EvidenceRuntimeIdentity) -> bool {
    match runtime {
        EvidenceRuntimeIdentity::OciImage { digest } => digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| lower_hex(digest, 64)),
        EvidenceRuntimeIdentity::HostBinary { sha256 } => lower_hex(sha256, 64),
    }
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn map_secure_file_error(error: crate::secure_file::SecureFileError) -> EvidenceError {
    match error {
        crate::secure_file::SecureFileError::UnsupportedPlatform => {
            EvidenceError::UnsupportedPlatform
        }
        crate::secure_file::SecureFileError::UnsafePath => EvidenceError::UnsafePath,
        crate::secure_file::SecureFileError::NotFound
        | crate::secure_file::SecureFileError::Oversize
        | crate::secure_file::SecureFileError::Io => EvidenceError::Io,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EvidenceError {
    UnsupportedPlatform,
    UnsafePath,
    Identity,
    Conflict,
    Encoding,
    Io,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "private evidence persistence is unavailable on this platform"
            }
            Self::UnsafePath => "private evidence path is not owner-only",
            Self::Identity => "private evidence identity is incomplete or inconsistent",
            Self::Conflict => "private evidence run directory is already committed",
            Self::Encoding => "private evidence could not be encoded",
            Self::Io => "private evidence persistence failed",
        })
    }
}

impl std::error::Error for EvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::OrchestrationIntegrity;
    use crate::{CleanupReport, ConformanceReport, ModuleOutcome, ModuleReport, ProgressSnapshot};

    fn report() -> ConformanceReport {
        ConformanceReport {
            schema: 3,
            matrix_digest: "c".repeat(64),
            suite_origin: "https://suite.example".to_owned(),
            auth_probe: None,
            errors: Vec::new(),
            local_success: true,
            suite_pass: true,
            acceptance_pass: true,
            human_review_required: false,
            human_review_modules: Vec::new(),
            skipped_modules: Vec::new(),
            expected_skipped_modules: Vec::new(),
            unexpected_skipped_modules: Vec::new(),
            unknown_declared_skip_modules: Vec::new(),
            matrix_expectations_satisfied: true,
            failed_modules: Vec::new(),
            incomplete_modules: Vec::new(),
            orchestration_integrity: OrchestrationIntegrity {
                defined_modules: 1,
                created_instances: 1,
                terminal_modules: 1,
                all_modules_instantiated: true,
                all_modules_terminal: true,
                cleanup_complete: true,
                retention_requested: false,
                retention_eligible: false,
                suite_resources_settled: true,
            },
            progress: ProgressSnapshot {
                completed: 1,
                total: 1,
                groups: Vec::new(),
                passed_groups: 1,
                review_groups: 0,
                skipped_groups: 0,
                failed_groups: 0,
                running_groups: 0,
                remaining_groups: 0,
                passed: 1,
                reviewed: 0,
                skipped: 0,
                failed: 0,
                running: 0,
                remaining: 0,
                current_profile: None,
                current_variant: None,
                current_test: None,
            },
            plans: Vec::new(),
            modules: vec![ModuleReport {
                matrix_plan_id: "plan-a".to_owned(),
                suite_plan_id: "suite-plan-a".to_owned(),
                module_id: Some("module-a".to_owned()),
                test_name: "test-a".to_owned(),
                variant: Default::default(),
                terminal: true,
                official_status: Some("FINISHED".to_owned()),
                official_result: Some("PASSED".to_owned()),
                expected_result: None,
                outcome: ModuleOutcome::Passed,
                human_review_required: false,
                blocking_log_results: Vec::new(),
                advisory_log_results: Vec::new(),
                review_screenshots: Vec::new(),
                review_screenshots_required: 0,
                review_screenshots_required_captured: 0,
                review_screenshots_missing: 0,
                info: serde_json::json!({"status":"FINISHED","result":"PASSED"}),
                log: serde_json::json!({"entries":1,"present":true}),
                raw_info: serde_json::json!({"status":"FINISHED","secret":"private"}),
                raw_log: serde_json::json!([{"message":"raw-private"}]),
            }],
            cleanup: CleanupReport::default(),
        }
    }

    fn identity() -> EvidenceBundleIdentity {
        EvidenceBundleIdentity {
            run_jti: "request-0123456789abcdef0123456789abcdef".to_owned(),
            deployment: EvidenceDeploymentIdentity {
                deployment_id: "deployment-a".to_owned(),
                target_issuer: "https://issuer.example".to_owned(),
                release: "v1.2.3".to_owned(),
                revision: "a".repeat(40),
                build_id: "build-a".to_owned(),
                runtime: EvidenceRuntimeIdentity::HostBinary {
                    sha256: "b".repeat(64),
                },
            },
            source: EvidenceSourceIdentity::LegacyOperatorMatrix {
                source_release: "v5.2.2".to_owned(),
                matrix_sha256: "c".repeat(64),
                suite_origin: "https://suite.example".to_owned(),
            },
            provider: None,
            outer_cleanup_complete: true,
        }
    }

    #[test]
    fn public_report_includes_stable_skip_expectation_summary() {
        let encoded = report().to_json_bytes().expect("report JSON");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("report value");

        assert_eq!(value["expected_skipped_modules"], serde_json::json!([]));
        assert_eq!(value["unexpected_skipped_modules"], serde_json::json!([]));
        assert_eq!(
            value["unknown_declared_skip_modules"],
            serde_json::json!([])
        );
        assert_eq!(
            value["matrix_expectations_satisfied"],
            serde_json::json!(true)
        );
        assert_eq!(value["acceptance_pass"], serde_json::json!(true));
    }

    struct ReceiptSpec<'a> {
        action: TenantResourceOperation,
        capability_jti: &'a str,
        capability_compact_sha256: &'a str,
        expected_revision: u64,
        revision: u64,
        baseline_manifest_sha256: &'a str,
        resource_manifest_sha256: &'a str,
        jti: &'a str,
        compact_sha256: &'a str,
        audit_sequence: u64,
    }

    fn receipt(spec: ReceiptSpec<'_>) -> EvidenceProviderReceipt {
        let ReceiptSpec {
            action,
            capability_jti,
            capability_compact_sha256,
            expected_revision,
            revision,
            baseline_manifest_sha256,
            resource_manifest_sha256,
            jti,
            compact_sha256,
            audit_sequence,
        } = spec;
        EvidenceProviderReceipt {
            action,
            compact_sha256: compact_sha256.to_owned(),
            jti: jti.to_owned(),
            request_sha256: "b".repeat(64),
            deployment_id: "deployment-a".to_owned(),
            tenant_id: Uuid::nil().to_string(),
            capability_jti: capability_jti.to_owned(),
            capability_compact_sha256: capability_compact_sha256.to_owned(),
            expected_revision,
            revision,
            change_set_id: format!("change-set-{audit_sequence}"),
            change_set_sha256: "c".repeat(64),
            baseline_manifest_sha256: baseline_manifest_sha256.to_owned(),
            resource_manifest_sha256: resource_manifest_sha256.to_owned(),
            outcome: TenantResourceOutcome::Succeeded,
            audit_sequence,
            audit_previous_sha256: "0".repeat(64),
        }
    }

    fn provider() -> EvidenceProviderIdentity {
        let tenant_id = Uuid::nil().to_string();
        EvidenceProviderIdentity {
            deployment_id: "deployment-a".to_owned(),
            runtime_instance_id: "runtime-a".to_owned(),
            runtime: EvidenceRuntimeIdentity::HostBinary {
                sha256: "b".repeat(64),
            },
            release: "v1.2.3".to_owned(),
            runtime_revision: "a".repeat(40),
            protocol: 1,
            build_id: "build-a".to_owned(),
            capabilities: vec![
                EvidenceProviderCapability {
                    capability_compact_sha256: "d".repeat(64),
                    capability_jti: "capability-0123456789abcdef".to_owned(),
                    tenant_id: tenant_id.clone(),
                    revision: 7,
                    resource_manifest_sha256: "e".repeat(64),
                    receipts: vec![
                        receipt(ReceiptSpec {
                            action: TenantResourceOperation::Enumerate,
                            capability_jti: "capability-0123456789abcdef",
                            capability_compact_sha256: &"d".repeat(64),
                            expected_revision: 7,
                            revision: 7,
                            baseline_manifest_sha256: &"e".repeat(64),
                            resource_manifest_sha256: &"e".repeat(64),
                            jti: "receipt-0123456789abcdef",
                            compact_sha256: &"a".repeat(64),
                            audit_sequence: 1,
                        }),
                        receipt(ReceiptSpec {
                            action: TenantResourceOperation::Apply,
                            capability_jti: "capability-0123456789abcdef",
                            capability_compact_sha256: &"d".repeat(64),
                            expected_revision: 7,
                            revision: 8,
                            baseline_manifest_sha256: &"e".repeat(64),
                            resource_manifest_sha256: &"f".repeat(64),
                            jti: "receipt-1123456789abcdef",
                            compact_sha256: &"b".repeat(64),
                            audit_sequence: 2,
                        }),
                    ],
                },
                EvidenceProviderCapability {
                    capability_compact_sha256: "9".repeat(64),
                    capability_jti: "capability-1123456789abcdef".to_owned(),
                    tenant_id,
                    revision: 8,
                    resource_manifest_sha256: "f".repeat(64),
                    receipts: vec![
                        receipt(ReceiptSpec {
                            action: TenantResourceOperation::Enumerate,
                            capability_jti: "capability-1123456789abcdef",
                            capability_compact_sha256: &"9".repeat(64),
                            expected_revision: 8,
                            revision: 8,
                            baseline_manifest_sha256: &"f".repeat(64),
                            resource_manifest_sha256: &"f".repeat(64),
                            jti: "receipt-2123456789abcdef",
                            compact_sha256: &"c".repeat(64),
                            audit_sequence: 3,
                        }),
                        receipt(ReceiptSpec {
                            action: TenantResourceOperation::Revoke,
                            capability_jti: "capability-1123456789abcdef",
                            capability_compact_sha256: &"9".repeat(64),
                            expected_revision: 8,
                            revision: 9,
                            baseline_manifest_sha256: &"f".repeat(64),
                            resource_manifest_sha256: &"e".repeat(64),
                            jti: "receipt-3123456789abcdef",
                            compact_sha256: &"e".repeat(64),
                            audit_sequence: 4,
                        }),
                    ],
                },
            ],
            cleanup_complete: true,
        }
    }

    #[test]
    fn identity_must_match_report_before_any_filesystem_access() {
        let mut identity = identity();
        if let EvidenceSourceIdentity::LegacyOperatorMatrix { matrix_sha256, .. } =
            &mut identity.source
        {
            *matrix_sha256 = "d".repeat(64);
        }
        assert_eq!(
            write_private_evidence_bundle(&report(), Path::new("relative"), &identity),
            Err(EvidenceError::Identity)
        );
    }

    #[test]
    fn ordinary_provider_evidence_requires_capability_binding() {
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &identity()),
            Err(EvidenceError::Identity)
        );
    }

    #[test]
    fn ordinary_provider_evidence_accepts_same_capability_cleanup_sequence() {
        let mut identity = identity();
        identity.provider = Some(provider());
        validate_ordinary_provider_identity(&report(), &identity)
            .expect("cleanup capability may enumerate before its exact revoke");
    }

    #[test]
    fn ordinary_provider_evidence_accepts_cleanup_failure_as_recorded_state() {
        let mut identity = identity();
        let mut provider = provider();
        provider.cleanup_complete = false;
        let cleanup = provider
            .capabilities
            .last_mut()
            .expect("cleanup capability")
            .receipts
            .last_mut()
            .expect("cleanup receipt");
        cleanup.outcome = TenantResourceOutcome::Failed {
            code: "cleanup-failed".to_owned(),
        };
        cleanup.revision = cleanup.expected_revision;
        cleanup.resource_manifest_sha256 = cleanup.baseline_manifest_sha256.clone();
        identity.outer_cleanup_complete = false;
        identity.provider = Some(provider);
        validate_ordinary_provider_identity(&report(), &identity)
            .expect("cleanup failure is evidence, not a write blocker");
    }

    #[test]
    fn ordinary_provider_evidence_rejects_cross_capability_receipts_and_state_gaps() {
        let mut first_identity = identity();
        let mut first_provider = provider();
        first_provider.capabilities[1].receipts[0].capability_jti =
            first_provider.capabilities[0].capability_jti.clone();
        first_identity.provider = Some(first_provider);
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &first_identity),
            Err(EvidenceError::Identity)
        );

        let mut second_identity = identity();
        let mut second_provider = provider();
        second_provider.capabilities[1].revision = 7;
        second_identity.provider = Some(second_provider);
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &second_identity),
            Err(EvidenceError::Identity)
        );

        let mut third_identity = identity();
        let mut third_provider = provider();
        third_provider.capabilities[1].capability_jti =
            third_provider.capabilities[0].capability_jti.clone();
        third_identity.provider = Some(third_provider);
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &third_identity),
            Err(EvidenceError::Identity)
        );
    }

    #[test]
    fn ordinary_provider_evidence_accepts_already_absent_cleanup_without_revoke() {
        let mut identity = identity();
        let mut provider = provider();
        let apply = &mut provider.capabilities[0].receipts[1];
        apply.resource_manifest_sha256 = "e".repeat(64);
        let cleanup = &mut provider.capabilities[1];
        cleanup.resource_manifest_sha256 = "e".repeat(64);
        cleanup.receipts.truncate(1);
        cleanup.receipts[0].baseline_manifest_sha256 = "e".repeat(64);
        cleanup.receipts[0].resource_manifest_sha256 = "e".repeat(64);
        identity.provider = Some(provider);
        validate_ordinary_provider_identity(&report(), &identity)
            .expect("cleanup enumerate proves run resources were already absent");
    }

    #[test]
    fn ordinary_provider_evidence_requires_revoke_when_cleanup_enumerate_still_has_run_state() {
        let mut first_identity = identity();
        let mut first_provider = provider();
        first_provider.capabilities[1].receipts.truncate(1);
        first_identity.provider = Some(first_provider);
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &first_identity),
            Err(EvidenceError::Identity)
        );

        let mut second_identity = identity();
        let mut second_provider = provider();
        second_provider.capabilities[1].receipts[1].resource_manifest_sha256 = "h".repeat(64);
        second_identity.provider = Some(second_provider);
        assert_eq!(
            validate_ordinary_provider_identity(&report(), &second_identity),
            Err(EvidenceError::Identity)
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn private_evidence_refuses_platforms_without_owner_only_file_proof() {
        assert_eq!(
            write_private_evidence_bundle(&report(), Path::new("relative"), &identity()),
            Err(EvidenceError::UnsupportedPlatform)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unique_run_bundle_commits_manifest_last_and_binds_raw_files() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-evidence-{}", uuid::Uuid::now_v7()));
        let receipt =
            write_private_evidence_bundle(&report(), &root, &identity()).expect("evidence bundle");
        assert_eq!(receipt.module_count, 1);
        let manifest = std::fs::read(receipt.directory.join("manifest.json")).expect("manifest");
        assert_eq!(sha256(&manifest), receipt.manifest_sha256);
        let module = std::fs::read_to_string(receipt.directory.join("module-0000.json"))
            .expect("private module");
        assert!(module.contains("raw-private"));
        assert!(module.contains(&receipt.evidence_jti));
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_provider_bundle_persists_capability_receipt_bindings() {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve system temporary directory");
        let root = temp_root.join(format!("nazoauth-provider-evidence-{}", Uuid::now_v7()));
        let mut identity = identity();
        identity.provider = Some(provider());
        let receipt = write_private_provider_evidence_bundle(&report(), &root, &identity)
            .expect("ordinary provider evidence bundle");
        let manifest =
            std::fs::read_to_string(receipt.directory.join("manifest.json")).expect("manifest");
        let manifest: serde_json::Value = serde_json::from_str(&manifest).expect("JSON manifest");
        let provider = &manifest["identity"]["provider"];
        assert_eq!(
            provider["capabilities"][0]["capability_jti"],
            "capability-0123456789abcdef"
        );
        assert_eq!(provider["deployment_id"], "deployment-a");
        assert_eq!(
            provider["capabilities"][0]["tenant_id"],
            Uuid::nil().to_string()
        );
        assert_eq!(provider["cleanup_complete"], true);
        assert_eq!(
            provider["capabilities"][0]["receipts"][0]["action"],
            "enumerate"
        );
        assert_eq!(
            provider["capabilities"][0]["receipts"][0]["compact_sha256"],
            "a".repeat(64)
        );
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
