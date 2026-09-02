#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};

use crate::oidf_protocol as nazo_operator_protocol;
use crate::oidf_protocol::{ControlResultData, TenantResourceIdentity};
use uuid::Uuid;
#[cfg(unix)]
use zeroize::Zeroizing;

use crate::{ConformanceReport, VerifiedOidfArtifact};

#[cfg(unix)]
const EVIDENCE_BUNDLE_SCHEMA: u32 = 4;
/// Shared writer/retention-reader ceiling for the public screenshot manifest.
pub(crate) const MAX_REVIEW_SCREENSHOT_MANIFEST_BYTES: usize = 1024 * 1024;
/// Schema 6 retains the runtime-signed OpenID4VP receipt provenance needed to
/// re-verify a NazoAuthWeb result after process restart.
pub(crate) const REVIEW_SCREENSHOT_MANIFEST_SCHEMA: u32 = 6;

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
    pub runtime: EvidenceRuntimeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSourceIdentity {
    pub suite_origin: String,
    pub artifact: Box<VerifiedOidfArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleIdentity {
    pub run_jti: String,
    pub deployment: EvidenceDeploymentIdentity,
    pub source: EvidenceSourceIdentity,
    /// Controller-signed control operations which created and removed the
    /// run-scoped resources. Every typed result is validated before any file
    /// is written.
    pub control: EvidenceControlIdentity,
    pub outer_cleanup_complete: bool,
}

/// Controller-operation provenance captured in an ordinary conformance
/// evidence bundle. The compact JWS itself is intentionally not persisted;
/// its signed identity and typed result bind the evidence without copying
/// private material into the evidence directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceControlIdentity {
    pub deployment_id: String,
    pub tenant_id: String,
    /// Ordered current control operations: baseline enumerate, Apply,
    /// cleanup enumerate, then an optional Revoke when resources remained.
    pub operations: Vec<EvidenceControlOperation>,
    pub cleanup_complete: bool,
}

/// One controller-signed operation and the closed result returned by the
/// server-side operation journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceControlOperation {
    pub operation_id: String,
    pub request_sha256: String,
    pub controller_kid: String,
    pub result: ControlResultData,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_receipt: Option<crate::OpenId4VpVerificationReceiptProvenance>,
}

#[cfg(unix)]
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
    #[serde(default)]
    verification_receipt: Option<crate::OpenId4VpVerificationReceiptProvenance>,
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

fn write_private_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_identity(report, identity)?;
    validate_review_screenshot_run_limit(report)?;
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
            let mut obligations = BTreeSet::new();
            let total_attempts = module
                .review_screenshots
                .len()
                .checked_add(module.review_screenshots_missing)
                .ok_or(EvidenceError::Identity)?;
            let mut required_captured = 0usize;
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
                let trigger_url =
                    url::Url::parse(&format!("{}{}", audit.trigger_origin, audit.trigger_path))
                        .map_err(|_| EvidenceError::Identity)?;
                if audit.suite_plan_id != module.suite_plan_id
                    || audit.module_id != module_id
                    || audit.test_name != module.test_name
                    || audit.variant != module.variant
                    || audit.obligation_index >= total_attempts
                    || !obligations.insert(audit.obligation_index)
                    || audit.path != screenshot.path
                    || audit.sha256 != screenshot.sha256
                    || audit.size != screenshot.size
                    || !valid_review_screenshot_trigger(
                        &audit,
                        &trigger_url,
                        &report.suite_origin,
                        &identity.deployment.target_issuer,
                        module_id,
                    )
                {
                    return Err(EvidenceError::Identity);
                }
                if matches!(audit.marker, crate::ReviewScreenshotMarker::Required) {
                    required_captured = required_captured
                        .checked_add(1)
                        .ok_or(EvidenceError::Identity)?;
                }
                let destination = directory.join(&screenshot.path);
                write_private_screenshot_pair(&destination, &screenshot_bytes, &receipt)?;
                screenshots.push(EvidenceScreenshotManifest {
                    matrix_plan_id: module.matrix_plan_id.clone(),
                    suite_plan_id: module.suite_plan_id.clone(),
                    module_id: module_id.to_owned(),
                    test_name: audit.test_name.clone(),
                    variant: audit.variant.clone(),
                    marker: audit.marker,
                    obligation_index: audit.obligation_index,
                    path: screenshot.path.clone(),
                    sha256: screenshot.sha256.clone(),
                    size: screenshot.size,
                    receipt_sha256: sha256(&receipt),
                    trigger_origin: audit.trigger_origin,
                    trigger_path: audit.trigger_path,
                    trigger_url_sha256: audit.trigger_url_sha256,
                    source: audit.source,
                    verification_receipt: audit.verification_receipt,
                });
                total_screenshot_bytes = total_screenshot_bytes.saturating_add(screenshot.size);
            }
            if required_captured != module.review_screenshots_required {
                return Err(EvidenceError::Identity);
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
    let Some(Component::Normal(run_jti)) = components.next() else {
        return Err(EvidenceError::UnsafePath);
    };
    let Some(Component::Normal(file)) = components.next() else {
        return Err(EvidenceError::UnsafePath);
    };
    if components.next().is_some()
        || directory != "review-screenshots"
        || run_jti.is_empty()
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

/// Writes evidence for a controller-operation backed ordinary run.
pub fn write_private_control_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
    recovery_binding: &crate::recovery::TenantResourceRecoveryBinding,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_ordinary_control_identity(report, identity)?;
    validate_control_vp_receipts(report, root, identity, recovery_binding)?;
    write_private_evidence_bundle(report, root, identity)
}

/// Re-check live-WebDriver VP receipts with the journal-owned discovery
/// anchor before the final evidence bundle copies any screenshot bytes.
#[cfg(unix)]
fn validate_control_vp_receipts(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
    recovery_binding: &crate::recovery::TenantResourceRecoveryBinding,
) -> Result<(), EvidenceError> {
    for module in &report.modules {
        for screenshot in &module.review_screenshots {
            let receipt_bytes = crate::secure_file::read_bounded(
                &root
                    .join(&screenshot.path)
                    .with_extension("png.receipt.json"),
                16 * 1024,
                true,
            )
            .map_err(map_secure_file_error)?;
            let audit: ReviewScreenshotAudit =
                serde_json::from_slice(&receipt_bytes).map_err(|_| EvidenceError::Identity)?;
            if audit.source
                != crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver
            {
                continue;
            }
            let artifact_digest = vp_artifact_digest(identity)?;
            let anchor = recovery_binding
                .vp_evidence_trust_anchor
                .as_ref()
                .ok_or(EvidenceError::Identity)?;
            let receipt = audit
                .verification_receipt
                .as_ref()
                .ok_or(EvidenceError::Identity)?;
            let context = ControlVpReceiptContext {
                artifact_digest,
                matrix_sha256: &report.matrix_digest,
                suite_plan_id: &module.suite_plan_id,
                suite_module_id: module.module_id.as_deref().ok_or(EvidenceError::Identity)?,
                test_name: &module.test_name,
                variant: &module.variant,
                trigger_origin: &audit.trigger_origin,
            };
            if !verify_control_vp_receipt(receipt, anchor, recovery_binding, &context) {
                return Err(EvidenceError::Identity);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn vp_artifact_digest(identity: &EvidenceBundleIdentity) -> Result<&str, EvidenceError> {
    Ok(identity.source.artifact.driver_manifest_sha256.as_str())
}

#[cfg(not(unix))]
fn validate_control_vp_receipts(
    _report: &ConformanceReport,
    _root: &Path,
    _identity: &EvidenceBundleIdentity,
    _recovery_binding: &crate::recovery::TenantResourceRecoveryBinding,
) -> Result<(), EvidenceError> {
    Err(EvidenceError::UnsupportedPlatform)
}

#[cfg(unix)]
struct ControlVpReceiptContext<'a> {
    artifact_digest: &'a str,
    matrix_sha256: &'a str,
    suite_plan_id: &'a str,
    suite_module_id: &'a str,
    test_name: &'a str,
    variant: &'a std::collections::BTreeMap<String, String>,
    trigger_origin: &'a str,
}

#[cfg(unix)]
fn verify_control_vp_receipt(
    receipt: &crate::OpenId4VpVerificationReceiptProvenance,
    anchor: &crate::recovery::OpenId4VpEvidenceTrustAnchor,
    binding: &crate::recovery::TenantResourceRecoveryBinding,
    context: &ControlVpReceiptContext<'_>,
) -> bool {
    use time::format_description::well_known::Rfc3339;

    if receipt.issuer != anchor.target_issuer
        || receipt.deployment_id != anchor.deployment_id
        || receipt.tenant_id != binding.tenant_id
        || receipt.runtime_instance_id != anchor.runtime_instance_id
        || receipt.instance_key_id != anchor.instance_key_id
        || receipt.instance_public_key_base64 != anchor.instance_public_key_base64
        || context.trigger_origin != anchor.target_issuer
        || receipt.receipt_api_url
            != format!("{}/openid4vp/verification-receipts", anchor.target_issuer)
        || sha256(receipt.receipt_jws.as_bytes()) != receipt.receipt_sha256
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
    let Ok(variant_bytes) = serde_json::to_vec(context.variant) else {
        return false;
    };
    let context = nazo_operator_protocol::Openid4vpEvidenceContext {
        run_jti: binding.run_id.clone(),
        artifact_sha256: context.artifact_digest.to_owned(),
        matrix_sha256: context.matrix_sha256.to_owned(),
        suite_plan_id: context.suite_plan_id.to_owned(),
        suite_module_id: context.suite_module_id.to_owned(),
        test_name: context.test_name.to_owned(),
        variant_sha256: sha256(&variant_bytes),
    };
    let Ok(context_sha256) =
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
    else {
        return false;
    };
    let Ok(completed_at) = time::OffsetDateTime::parse(&receipt.completed_at, &Rfc3339) else {
        return false;
    };
    let Ok(expires_at) = time::OffsetDateTime::parse(&receipt.expires_at, &Rfc3339) else {
        return false;
    };
    if completed_at.format(&Rfc3339).ok().as_deref() != Some(receipt.completed_at.as_str())
        || expires_at.format(&Rfc3339).ok().as_deref() != Some(receipt.expires_at.as_str())
        || expires_at <= completed_at
    {
        return false;
    }
    let receipt_id = receipt.receipt_id.to_string();
    let transaction_id = receipt.transaction_id.to_string();
    let expected = nazo_operator_protocol::Openid4vpVerificationReceiptExpectations {
        issuer: &anchor.target_issuer,
        audience: &receipt.receipt_api_url,
        deployment_id: &anchor.deployment_id,
        runtime_instance_id: &anchor.runtime_instance_id,
        instance_key_id: &anchor.instance_key_id,
        tenant_id: &binding.tenant_id,
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
        completed_at.unix_timestamp(),
    ) else {
        return false;
    };
    verified.completed_at == receipt.completed_at
        && verified.iss == receipt.issuer
        && verified.deployment_id == receipt.deployment_id
        && verified.tenant_id == receipt.tenant_id
        && verified.runtime_instance_id == receipt.runtime_instance_id
        && verified.instance_key_id == receipt.instance_key_id
        && verified.transaction_id == transaction_id
        && verified.issuance_request_jti == receipt.issuance_request_jti
        && verified.intent_sha256 == receipt.intent_sha256
        && verified.exp == expires_at.unix_timestamp()
        && crate::recovery::exact_vp_trust_policy_binding(
            binding,
            &verified.presentation_binding.trust_policy,
        )
}

/// Commits the screenshot-to-current-module binding before Suite plan
/// ownership can be retained. It intentionally references the root-private
/// image files in place; the full evidence bundle later copies and
/// rebinds the same verified files into its own committed directory.
pub fn write_review_screenshot_manifest(
    report: &ConformanceReport,
    root: &Path,
    run_jti: &str,
    artifact_digest: &str,
    target_issuer: &str,
) -> Result<ReviewScreenshotManifestReceipt, EvidenceError> {
    #[cfg(not(unix))]
    {
        let _ = (report, root, run_jti, artifact_digest, target_issuer);
        Err(EvidenceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let suite_origin = crate::Origin::parse_suite(&report.suite_origin)
            .map_err(|_| EvidenceError::Identity)?;
        if suite_origin.as_str() != report.suite_origin {
            return Err(EvidenceError::Identity);
        }
        validate_review_screenshot_run_limit(report)?;
        if crate::artifact::validate_identifier(run_jti, 128).is_err() {
            return Err(EvidenceError::Identity);
        }
        let root =
            crate::secure_file::validate_directory(root, true).map_err(map_secure_file_error)?;
        if !lower_hex(artifact_digest, 64) {
            return Err(EvidenceError::Identity);
        }
        let target_issuer = url::Url::parse(target_issuer).map_err(|_| EvidenceError::Identity)?;
        if target_issuer.scheme() != "https"
            || target_issuer.host_str().is_none()
            || !target_issuer.username().is_empty()
            || target_issuer.password().is_some()
            || target_issuer.query().is_some()
            || target_issuer.fragment().is_some()
            || !matches!(target_issuer.path(), "" | "/")
        {
            return Err(EvidenceError::Identity);
        }
        let target_issuer = target_issuer.as_str().trim_end_matches('/').to_owned();
        let mut modules = Vec::with_capacity(report.modules.len());
        let mut screenshots = Vec::new();
        let mut paths = BTreeSet::new();
        let mut total_screenshot_bytes = 0usize;
        for module in &report.modules {
            validate_review_screenshot_obligations(module)?;
            let mut obligations = BTreeSet::new();
            let total_attempts = module
                .review_screenshots
                .len()
                .checked_add(module.review_screenshots_missing)
                .ok_or(EvidenceError::Identity)?;
            let mut required_captured = 0usize;
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
                let trigger_url =
                    url::Url::parse(&format!("{}{}", audit.trigger_origin, audit.trigger_path))
                        .map_err(|_| EvidenceError::Identity)?;
                if audit.suite_plan_id != module.suite_plan_id
                    || audit.module_id != module_id
                    || audit.test_name != module.test_name
                    || audit.variant != module.variant
                    || audit.obligation_index >= total_attempts
                    || !obligations.insert(audit.obligation_index)
                    || audit.path != screenshot.path
                    || audit.sha256 != screenshot.sha256
                    || audit.size != screenshot.size
                    || !valid_review_screenshot_trigger(
                        &audit,
                        &trigger_url,
                        &report.suite_origin,
                        &target_issuer,
                        module_id,
                    )
                {
                    return Err(EvidenceError::Identity);
                }
                if matches!(audit.marker, crate::ReviewScreenshotMarker::Required) {
                    required_captured = required_captured
                        .checked_add(1)
                        .ok_or(EvidenceError::Identity)?;
                }
                screenshots.push(EvidenceScreenshotManifest {
                    matrix_plan_id: module.matrix_plan_id.clone(),
                    suite_plan_id: module.suite_plan_id.clone(),
                    module_id: module_id.to_owned(),
                    test_name: audit.test_name.clone(),
                    variant: audit.variant.clone(),
                    marker: audit.marker,
                    obligation_index: audit.obligation_index,
                    path: screenshot.path.clone(),
                    sha256: screenshot.sha256.clone(),
                    size: screenshot.size,
                    receipt_sha256: sha256(&receipt),
                    trigger_origin: audit.trigger_origin,
                    trigger_path: audit.trigger_path,
                    trigger_url_sha256: audit.trigger_url_sha256,
                    source: audit.source,
                    verification_receipt: audit.verification_receipt,
                });
                total_screenshot_bytes = total_screenshot_bytes.saturating_add(image.len());
            }
            if required_captured != module.review_screenshots_required {
                return Err(EvidenceError::Identity);
            }
        }
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": REVIEW_SCREENSHOT_MANIFEST_SCHEMA,
            "run_jti": run_jti,
            "artifact_digest": artifact_digest,
            "matrix_sha256": report.matrix_digest,
            "suite_origin": report.suite_origin,
            "target_issuer": target_issuer,
            "modules": modules,
            "screenshots": screenshots,
        }))
        .map_err(|_| EvidenceError::Encoding)?;
        if bytes.len() > MAX_REVIEW_SCREENSHOT_MANIFEST_BYTES {
            return Err(EvidenceError::Encoding);
        }
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
    crate::secure_file::write_new_or_exact(path, bytes, true).map_err(map_secure_file_error)
}

#[cfg(unix)]
fn write_private_screenshot_pair(
    image_path: &Path,
    image: &[u8],
    audit: &[u8],
) -> Result<(), EvidenceError> {
    let outcome = crate::secure_file::write_new_or_exact_with_outcome(image_path, image, true)
        .map_err(map_secure_file_error)?;
    let audit_path = image_path.with_extension("png.receipt.json");
    if let Err(error) = crate::secure_file::write_new_or_exact(&audit_path, audit, true) {
        if matches!(outcome, crate::secure_file::NewOrExactOutcome::Created) {
            let _ = crate::secure_file::remove_private_file_if_exact(image_path, image);
        }
        return Err(map_secure_file_error(error));
    }
    Ok(())
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

#[cfg(unix)]
fn valid_review_screenshot_trigger(
    audit: &ReviewScreenshotAudit,
    trigger_url: &url::Url,
    suite_origin: &str,
    target_issuer: &str,
    module_id: &str,
) -> bool {
    if !lower_hex(&audit.trigger_url_sha256, 64) {
        return false;
    }
    match audit.source {
        crate::BrowserReviewScreenshotSource::SuiteVerificationEvidence => {
            audit.verification_receipt.is_none()
                && audit.trigger_origin == suite_origin
                && crate::browser::review_screenshot_path_binds_module(trigger_url, module_id)
                && sha256(trigger_url.as_str().as_bytes()) == audit.trigger_url_sha256
        }
        crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver => {
            audit.verification_receipt.as_ref().is_some_and(|receipt| {
                valid_vp_verification_receipt_provenance(receipt, target_issuer)
            }) && audit.trigger_origin == target_issuer
                && trigger_url.scheme() == "https"
                && trigger_url.host_str().is_some()
                && trigger_url.path() == "/ui/verification-result"
                && trigger_url.query().is_none()
                && trigger_url.fragment().is_none()
                && trigger_url.username().is_empty()
                && trigger_url.password().is_none()
                && sha256(format!("{}{}", audit.trigger_origin, audit.trigger_path).as_bytes())
                    == audit.trigger_url_sha256
        }
        crate::BrowserReviewScreenshotSource::NazoVpCompletionLiveWebdriver => {
            audit.verification_receipt.is_none()
                && audit.trigger_origin == target_issuer
                && trigger_url.scheme() == "https"
                && trigger_url.host_str().is_some()
                && trigger_url
                    .path()
                    .strip_prefix("/openid4vp/complete/")
                    .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
                && trigger_url.query().is_none()
                && trigger_url.fragment().is_none()
                && trigger_url.username().is_empty()
                && trigger_url.password().is_none()
                && sha256(format!("{}{}", audit.trigger_origin, audit.trigger_path).as_bytes())
                    == audit.trigger_url_sha256
        }
    }
}

#[cfg(unix)]
fn valid_vp_verification_receipt_provenance(
    receipt: &crate::OpenId4VpVerificationReceiptProvenance,
    target_issuer: &str,
) -> bool {
    receipt.issuer == target_issuer
        && receipt.receipt_api_url == format!("{target_issuer}/openid4vp/verification-receipts")
        && !receipt.receipt_jws.is_empty()
        && receipt.receipt_jws.len() <= 16 * 1024
        && lower_hex(&receipt.receipt_sha256, 64)
        && lower_hex(&receipt.capability_sha256, 64)
        && !receipt.deployment_id.is_empty()
        && uuid::Uuid::parse_str(&receipt.tenant_id)
            .is_ok_and(|tenant_id| tenant_id.to_string() == receipt.tenant_id)
        && !receipt.runtime_instance_id.is_empty()
        && !receipt.instance_key_id.is_empty()
        && uuid::Uuid::parse_str(&receipt.issuance_request_jti).is_ok()
        && lower_hex(&receipt.presentation_binding_sha256, 64)
        && lower_hex(&receipt.intent_sha256, 64)
        && nazo_operator_protocol::decode_instance_public_key(&receipt.instance_public_key_base64)
            .is_ok_and(|key| {
                nazo_operator_protocol::instance_key_id(&key) == receipt.instance_key_id
            })
        && !receipt.completed_at.is_empty()
        && !receipt.expires_at.is_empty()
}

fn validate_review_screenshot_run_limit(report: &ConformanceReport) -> Result<(), EvidenceError> {
    let attempts = report.modules.iter().try_fold(0usize, |total, module| {
        total
            .checked_add(module.review_screenshots.len())
            .and_then(|total| total.checked_add(module.review_screenshots_missing))
            .ok_or(EvidenceError::Identity)
    })?;
    if attempts > crate::browser::MAX_REVIEW_SCREENSHOTS_PER_RUN {
        return Err(EvidenceError::Identity);
    }
    Ok(())
}

/// Validates ordinary control-operation evidence without touching the filesystem. A
/// cleanup failure is retained as evidence (`cleanup_complete=false`) and is
/// therefore deliberately not rejected here; the caller decides whether that
/// run is successful.
pub fn validate_ordinary_control_identity(
    report: &ConformanceReport,
    identity: &EvidenceBundleIdentity,
) -> Result<(), EvidenceError> {
    validate_identity(report, identity)
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
        if !private_evidence_owner_is_allowed(metadata.uid()) {
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

#[cfg(all(unix, not(test)))]
fn private_evidence_owner_is_allowed(uid: u32) -> bool {
    uid == 0
}

#[cfg(all(unix, test))]
fn private_evidence_owner_is_allowed(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn validate_identity(
    report: &ConformanceReport,
    identity: &EvidenceBundleIdentity,
) -> Result<(), EvidenceError> {
    if crate::artifact::validate_identifier(&identity.run_jti, 128).is_err()
        || crate::artifact::validate_identifier(&identity.deployment.deployment_id, 128).is_err()
        || !bounded(&identity.deployment.release, 128)
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
    let artifact = &identity.source.artifact;
    if !lower_hex(&artifact.matrix_sha256, 64)
        || !lower_hex(&artifact.driver_manifest_sha256, 64)
        || !lower_hex(&artifact.driver_sha256, 64)
    {
        return Err(EvidenceError::Identity);
    }
    let matrix_sha256 = &artifact.matrix_sha256;
    let suite_origin = &identity.source.suite_origin;
    if report.matrix_digest != *matrix_sha256 || report.suite_origin != *suite_origin {
        return Err(EvidenceError::Identity);
    }
    validate_control_identity(identity, &identity.control)?;
    Ok(())
}

fn validate_control_identity(
    identity: &EvidenceBundleIdentity,
    control: &EvidenceControlIdentity,
) -> Result<(), EvidenceError> {
    if control.deployment_id != identity.deployment.deployment_id
        || !Uuid::parse_str(&control.tenant_id)
            .ok()
            .is_some_and(|tenant| tenant.hyphenated().to_string() == control.tenant_id)
        || control.operations.len() < 3
        || control.operations.len() > 4
        || identity.outer_cleanup_complete != control.cleanup_complete
    {
        return Err(EvidenceError::Identity);
    }

    let mut operation_ids = std::collections::BTreeSet::new();
    let baseline = control.operations.first().ok_or(EvidenceError::Identity)?;
    let apply = control.operations.get(1).ok_or(EvidenceError::Identity)?;
    let cleanup_enumerate = control.operations.get(2).ok_or(EvidenceError::Identity)?;
    if !valid_control_operation(baseline)
        || !valid_control_operation(apply)
        || !valid_control_operation(cleanup_enumerate)
        || !operation_ids.insert(baseline.operation_id.as_str())
        || !operation_ids.insert(apply.operation_id.as_str())
        || !operation_ids.insert(cleanup_enumerate.operation_id.as_str())
    {
        return Err(EvidenceError::Identity);
    }
    let ControlResultData::TenantResourceEnumerate {
        revision: baseline_revision,
        resource_manifest_sha256: baseline_manifest,
        ..
    } = &baseline.result
    else {
        return Err(EvidenceError::Identity);
    };
    let ControlResultData::TenantResourceApply {
        revision: applied_revision,
        resources: applied_resources,
        resource_mappings,
        resource_manifest_sha256: applied_manifest,
    } = &apply.result
    else {
        return Err(EvidenceError::Identity);
    };
    let ControlResultData::TenantResourceEnumerate {
        revision: cleanup_revision,
        resources: cleanup_resources,
        resource_manifest_sha256: cleanup_manifest,
    } = &cleanup_enumerate.result
    else {
        return Err(EvidenceError::Identity);
    };
    if *applied_revision
        != baseline_revision
            .checked_add(1)
            .ok_or(EvidenceError::Identity)?
        || *cleanup_revision != *applied_revision
        || !lower_hex(baseline_manifest, 64)
        || !lower_hex(applied_manifest, 64)
        || !lower_hex(cleanup_manifest, 64)
        || !valid_resource_set(applied_resources)
        || !valid_apply_mappings(resource_mappings, applied_resources)
    {
        return Err(EvidenceError::Identity);
    }

    match control.operations.get(3) {
        None if control.cleanup_complete => {
            if cleanup_resources
                .iter()
                .any(|candidate| applied_resources.iter().any(|applied| applied == candidate))
                || cleanup_manifest != applied_manifest
            {
                return Err(EvidenceError::Identity);
            }
        }
        None => {}
        Some(revoke) => {
            if !valid_control_operation(revoke)
                || !operation_ids.insert(revoke.operation_id.as_str())
            {
                return Err(EvidenceError::Identity);
            }
            let ControlResultData::TenantResourceRevoke {
                revision,
                resources,
                resource_manifest_sha256,
            } = &revoke.result
            else {
                return Err(EvidenceError::Identity);
            };
            if *revision
                != cleanup_revision
                    .checked_add(1)
                    .ok_or(EvidenceError::Identity)?
                || resources != cleanup_resources
                || resource_manifest_sha256 != baseline_manifest
                || !valid_resource_set(resources)
            {
                return Err(EvidenceError::Identity);
            }
        }
    }
    Ok(())
}

fn valid_control_operation(operation: &EvidenceControlOperation) -> bool {
    Uuid::parse_str(&operation.operation_id).is_ok()
        && lower_hex(&operation.request_sha256, 64)
        && operation.controller_kid.len() == 43
        && operation
            .controller_kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_resource_set(resources: &[TenantResourceIdentity]) -> bool {
    !resources.is_empty()
        && resources.len() <= nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
        && resources.iter().all(|resource| {
            crate::artifact::validate_identifier(&resource.resource_id, 256).is_ok()
                && lower_hex(&resource.digest, 64)
        })
}

fn valid_apply_mappings(
    mappings: &[nazo_operator_protocol::TenantResourceMapping],
    resources: &[TenantResourceIdentity],
) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    mappings.iter().all(|mapping| {
        crate::artifact::validate_identifier(&mapping.resource_id, 256).is_ok()
            && !mapping.public_id.is_empty()
            && mapping.public_id.len() <= 512
            && !mapping.public_id.chars().any(char::is_control)
            && resources.iter().any(|resource| {
                resource.kind == mapping.kind && resource.resource_id == mapping.resource_id
            })
            && seen.insert((mapping.kind, mapping.resource_id.as_str()))
    })
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn completion_evidence_is_bound_to_the_dynamic_tenant_issuer() {
        let tenant_issuer = "https://01a06016-43e0-7cf1-9633-b9c6124823cb.oidf.nazoauth.com";
        let trigger_path = "/openid4vp/complete/01a06016-71d4-7181-b275-be8f5ade62a0";
        let trigger_url =
            url::Url::parse(&format!("{tenant_issuer}{trigger_path}")).expect("completion URL");
        let audit = ReviewScreenshotAudit {
            suite_plan_id: "suite-plan".to_owned(),
            module_id: "suite-module".to_owned(),
            test_name: "oid4vp-1final-verifier-happy-flow".to_owned(),
            variant: std::collections::BTreeMap::new(),
            marker: crate::ReviewScreenshotMarker::Required,
            obligation_index: 0,
            path: PathBuf::from("review-screenshots/run/module.png"),
            sha256: "a".repeat(64),
            size: 1,
            trigger_origin: tenant_issuer.to_owned(),
            trigger_path: trigger_path.to_owned(),
            trigger_url_sha256: sha256(trigger_url.as_str().as_bytes()),
            source: crate::BrowserReviewScreenshotSource::NazoVpCompletionLiveWebdriver,
            verification_receipt: None,
        };

        assert!(valid_review_screenshot_trigger(
            &audit,
            &trigger_url,
            "https://auth.nazo.run:18544",
            tenant_issuer,
            "suite-module",
        ));
        assert!(!valid_review_screenshot_trigger(
            &audit,
            &trigger_url,
            "https://auth.nazo.run:18544",
            "https://auth.nazo.run",
            "suite-module",
        ));
    }
}
