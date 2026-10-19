#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};

use nazo_operator_protocol::{ControlResultData, TenantResourceIdentity};
use uuid::Uuid;
#[cfg(unix)]
use zeroize::Zeroizing;

use crate::{ConformanceReport, OidfTestSource};

#[cfg(unix)]
const EVIDENCE_BUNDLE_SCHEMA: u32 = 5;
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
    pub test_source: Box<OidfTestSource>,
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

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest<'a> {
    schema: u32,
    evidence_jti: &'a str,
    identity: &'a EvidenceBundleIdentity,
    public_report_file: &'static str,
    public_report_sha256: String,
    modules: Vec<EvidenceModuleManifest<'a>>,
    screenshots: Vec<EvidenceScreenshotManifest<'a>>,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceScreenshotManifest<'a> {
    matrix_plan_id: &'a str,
    suite_plan_id: &'a str,
    module_id: &'a str,
    test_name: String,
    variant: std::collections::BTreeMap<String, String>,
    marker: crate::ReviewScreenshotMarker,
    obligation_index: usize,
    path: &'a Path,
    sha256: &'a str,
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
struct EvidenceModuleManifest<'a> {
    index: u32,
    matrix_plan_id: &'a str,
    suite_plan_id: &'a str,
    module_id: Option<&'a str>,
    test_name: &'a str,
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

/// Writes evidence for a controller-operation backed ordinary run.
pub fn write_private_control_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
    recovery_binding: &crate::recovery::TenantResourceRecoveryBinding,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_identity(report, identity)?;
    validate_review_screenshot_run_limit(&report.modules)?;
    #[cfg(not(unix))]
    {
        let _ = (root, recovery_binding);
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
        for (index, module) in report.modules.iter().enumerate() {
            validate_review_screenshot_obligations(module)?;
            let mut obligations = BTreeSet::new();
            let total_attempts =
                module.review_screenshots.len() + module.review_screenshots_missing;
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
                matrix_plan_id: &module.matrix_plan_id,
                suite_plan_id: &module.suite_plan_id,
                module_id: module.module_id.as_deref(),
                test_name: &module.test_name,
                file,
                sha256: sha256(bytes.as_slice()),
            });
            for screenshot in &module.review_screenshots {
                let module_id = module.module_id.as_deref().ok_or(EvidenceError::Identity)?;
                if !screenshot_paths.insert(&screenshot.path) {
                    return Err(EvidenceError::Identity);
                }
                validate_review_screenshot_path(&screenshot.path)?;
                let source = root.join(&screenshot.path);
                let screenshot_bytes = crate::secure_file::read_bounded(&source, 500 * 1024, true)
                    .map_err(map_secure_file_error)?;
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
                if audit.source
                    == crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver
                {
                    let anchor = recovery_binding
                        .vp_evidence_trust_anchor
                        .as_ref()
                        .ok_or(EvidenceError::Identity)?;
                    let receipt = audit
                        .verification_receipt
                        .as_ref()
                        .ok_or(EvidenceError::Identity)?;
                    let context = crate::recovery::VpReceiptContext {
                        artifact_digest: &identity.source.test_source.content_sha256,
                        matrix_sha256: &report.matrix_digest,
                        suite_plan_id: &module.suite_plan_id,
                        suite_module_id: module_id,
                        test_name: &module.test_name,
                        variant: &module.variant,
                        trigger_origin: &audit.trigger_origin,
                    };
                    if !crate::recovery::verify_vp_receipt_provenance(
                        receipt,
                        anchor,
                        recovery_binding,
                        &context,
                    ) {
                        return Err(EvidenceError::Identity);
                    }
                }
                if matches!(audit.marker, crate::ReviewScreenshotMarker::Required) {
                    required_captured += 1;
                }
                let destination = directory.join(&screenshot.path);
                write_private_screenshot_pair(&destination, &screenshot_bytes, &receipt)?;
                screenshots.push(EvidenceScreenshotManifest {
                    matrix_plan_id: &module.matrix_plan_id,
                    suite_plan_id: &module.suite_plan_id,
                    module_id,
                    test_name: audit.test_name,
                    variant: audit.variant,
                    marker: audit.marker,
                    obligation_index: audit.obligation_index,
                    path: &screenshot.path,
                    sha256: &screenshot.sha256,
                    size: screenshot.size,
                    receipt_sha256: sha256(&receipt),
                    trigger_origin: audit.trigger_origin,
                    trigger_path: audit.trigger_path,
                    trigger_url_sha256: audit.trigger_url_sha256,
                    source: audit.source,
                    verification_receipt: audit.verification_receipt,
                });
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
        || module.review_screenshots.len() + module.review_screenshots_missing
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
            audit.trigger_origin == target_issuer
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

fn validate_review_screenshot_run_limit(
    modules: &[crate::report::ModuleReport],
) -> Result<(), EvidenceError> {
    // At most 64 captures, each read with a 500 KiB ceiling, also bound image
    // payloads below 32 MiB before either writer starts processing evidence.
    let attempts = modules.iter().try_fold(0usize, |total, module| {
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

/// Retention evidence must target an existing controller-owned safe directory before
/// Suite allocation begins; unlike ordinary evidence this preflight never
/// creates an operator-selected path.
pub fn validate_private_evidence_directory(root: &Path) -> Result<(), EvidenceError> {
    #[cfg(unix)]
    {
        crate::secure_file::validate_directory(root, true)
            .map(|_| ())
            .map_err(map_secure_file_error)
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
    if crate::plan::validate_identifier(&identity.run_jti, 128).is_err()
        || crate::plan::validate_identifier(&identity.deployment.deployment_id, 128).is_err()
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
    let artifact = &identity.source.test_source;
    if !lower_hex(&artifact.matrix_sha256, 64)
        || !lower_hex(&artifact.content_sha256, 64)
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
            crate::plan::validate_identifier(&resource.resource_id, 256).is_ok()
                && lower_hex(&resource.digest, 64)
        })
}

fn valid_apply_mappings(
    mappings: &[nazo_operator_protocol::TenantResourceMapping],
    resources: &[TenantResourceIdentity],
) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    mappings.iter().all(|mapping| {
        crate::plan::validate_identifier(&mapping.resource_id, 256).is_ok()
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
    hex::encode(Sha256::digest(bytes))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn evidence_bundle_copies_bound_receipt_and_rejects_substitution_or_bad_signature() {
        use crate::report::{
            CleanupReport, ModuleReport, ModuleReportContext, OrchestrationIntegrity,
            ReviewScreenshotReport,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use serde_json::{Value, json};

        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nazo-evidence-{}", Uuid::now_v7()));
        crate::secure_file::ensure_directory(&root, true).unwrap();
        let image = STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=").unwrap();
        let path = PathBuf::from("review-screenshots/run/module.png");
        let image_path = root.join(&path);
        crate::secure_file::write_atomic(&image_path, &image, true).unwrap();
        let mut module = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "matrix-plan".into(),
                suite_plan_id: "suite-plan".into(),
                module_id: Some("module".into()),
                test_name: "test".into(),
                variant: Default::default(),
                terminal: true,
                expected_result: None,
            },
            json!({"status":"FINISHED", "result":"PASSED"}),
            json!([]),
        );
        module.review_screenshots.push(ReviewScreenshotReport {
            path: path.clone(),
            sha256: sha256(&image),
            size: image.len(),
        });
        module.review_screenshots_required = 1;
        module.review_screenshots_required_captured = 1;
        let report = ConformanceReport {
            schema: 1,
            matrix_digest: "a".repeat(64),
            suite_origin: "https://suite.example".into(),
            auth_probe: None,
            fail_fast: false,
            local_success: true,
            suite_pass: true,
            acceptance_pass: true,
            review_pending: false,
            human_review_required: false,
            matrix_expectations_satisfied: true,
            excluded_plans: vec![],
            errors: vec![],
            human_review_modules: vec![],
            warning_modules: vec![],
            deferred_review_modules: vec![],
            skipped_modules: vec![],
            expected_skipped_modules: vec![],
            unexpected_skipped_modules: vec![],
            unknown_declared_skip_modules: vec![],
            retained_suite_plan_ids: vec![],
            failed_modules: vec![],
            incomplete_modules: vec![],
            orchestration_integrity: OrchestrationIntegrity {
                defined_modules: 1,
                created_instances: 1,
                terminal_modules: 1,
                all_modules_instantiated: true,
                all_modules_terminal: true,
                all_modules_settled: true,
                deferred_review_modules: 0,
                cleanup_complete: true,
                retention_requested: false,
                retention_eligible: false,
                retention_candidate_settled: false,
                retention_committed: false,
                suite_resources_settled: true,
            },
            progress: Default::default(),
            plans: vec![],
            modules: vec![module],
            cleanup: CleanupReport::default(),
        };
        let tenant_id = Uuid::now_v7().to_string();
        let resource = TenantResourceIdentity {
            kind: nazo_operator_protocol::TenantResourceKind::User,
            resource_id: "user".into(),
            digest: "a".repeat(64),
        };
        let operations = [
            ControlResultData::TenantResourceEnumerate {
                revision: 0,
                resources: vec![],
                resource_manifest_sha256: "a".repeat(64),
            },
            ControlResultData::TenantResourceApply {
                revision: 1,
                resources: vec![resource],
                resource_mappings: vec![],
                resource_manifest_sha256: "b".repeat(64),
            },
            ControlResultData::TenantResourceEnumerate {
                revision: 1,
                resources: vec![],
                resource_manifest_sha256: "b".repeat(64),
            },
        ]
        .into_iter()
        .map(|result| EvidenceControlOperation {
            operation_id: Uuid::now_v7().to_string(),
            request_sha256: "c".repeat(64),
            controller_kid: "k".repeat(43),
            result,
        })
        .collect();
        let identity = EvidenceBundleIdentity {
            run_jti: Uuid::now_v7().to_string(), outer_cleanup_complete: true,
            deployment: EvidenceDeploymentIdentity {
                deployment_id: "deployment".into(), target_issuer: "https://issuer.example".into(), release: "test".into(),
                runtime: EvidenceRuntimeIdentity::HostBinary { sha256: "d".repeat(64) },
            },
            source: EvidenceSourceIdentity {
                suite_origin: report.suite_origin.clone(),
                test_source: Box::new(serde_json::from_value(json!({
                    "controller_version":"test", "revision":"revision", "content_sha256":"b".repeat(64),
                    "suite_reference":{"release":"test","revision":"revision","image_digest":"sha256:test"},
                    "driver_sha256":"c".repeat(64), "matrix_sha256":report.matrix_digest
                })).unwrap()),
            },
            control: EvidenceControlIdentity { deployment_id: "deployment".into(), tenant_id: tenant_id.clone(), operations, cleanup_complete: true },
        };
        let mut binding: crate::recovery::TenantResourceRecoveryBinding = serde_json::from_value(json!({
            "deployment_id":"deployment", "tenant_id":tenant_id, "tenant_domain":"issuer.example",
            "realm_id":"realm", "organization_id":"organization", "run_id":identity.run_jti,
            "tenant_create_expected_revision":0,"manifest_path":null,"material_sha256":null,
            "proxy":null,"vp_evidence_trust_anchor":null,"resource_identities":[]
        })).unwrap();
        let trigger = "https://suite.example/test/a/module/verification-evidence";
        let mut audit = json!({
            "suite_plan_id":"suite-plan", "module_id":"module", "test_name":"test", "variant":{},
            "marker":"Required", "obligation_index":0, "path":path, "sha256":sha256(&image), "size":image.len(),
            "trigger_origin":"https://suite.example", "trigger_path":"/test/a/module/verification-evidence",
            "trigger_url_sha256":sha256(trigger.as_bytes()), "source":"SuiteVerificationEvidence"
        });
        audit["marker"] = serde_json::to_value(crate::ReviewScreenshotMarker::Required).unwrap();
        audit["source"] =
            serde_json::to_value(crate::BrowserReviewScreenshotSource::SuiteVerificationEvidence)
                .unwrap();
        let receipt_path = image_path.with_extension("png.receipt.json");
        let receipt_bytes = serde_json::to_vec(&audit).unwrap();
        crate::secure_file::write_atomic(&receipt_path, &receipt_bytes, true).unwrap();
        let receipt =
            write_private_control_evidence_bundle(&report, &root, &identity, &binding).unwrap();
        assert_eq!(std::fs::read(receipt.directory.join(&path)).unwrap(), image);
        assert_eq!(
            std::fs::read(
                receipt
                    .directory
                    .join(&path)
                    .with_extension("png.receipt.json")
            )
            .unwrap(),
            receipt_bytes
        );
        let manifest_bytes = std::fs::read(receipt.directory.join("manifest.json")).unwrap();
        assert_eq!(receipt.manifest_sha256, sha256(&manifest_bytes));
        let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(
            manifest["screenshots"][0]["receipt_sha256"],
            sha256(&receipt_bytes)
        );
        assert_eq!(manifest["modules"][0]["module_id"], "module");

        audit["module_id"] = json!("substituted-module");
        crate::secure_file::write_atomic(&receipt_path, &serde_json::to_vec(&audit).unwrap(), true)
            .unwrap();
        assert_eq!(
            write_private_control_evidence_bundle(&report, &root, &identity, &binding),
            Err(EvidenceError::Identity)
        );
        audit["module_id"] = json!("module");
        let mut seed = [0_u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut seed).unwrap();
        let signing = nazo_crypto::ed25519::SigningKey::from_bytes(&seed);
        let key = signing.verifying_key();
        let key_id = nazo_operator_protocol::instance_key_id(&key);
        let public_key = nazo_operator_protocol::encode_instance_public_key(&key);
        binding.vp_evidence_trust_anchor = Some(crate::recovery::OpenId4VpEvidenceTrustAnchor {
            target_issuer: "https://issuer.example".into(),
            deployment_id: "deployment".into(),
            runtime_instance_id: "instance".into(),
            instance_key_id: key_id.clone(),
            instance_public_key_base64: public_key.clone(),
        });
        audit["source"] = serde_json::to_value(
            crate::BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver,
        )
        .unwrap();
        audit["trigger_origin"] = json!("https://issuer.example");
        audit["trigger_path"] = json!("/ui/verification-result");
        audit["trigger_url_sha256"] =
            json!(sha256(b"https://issuer.example/ui/verification-result"));
        audit["verification_receipt"] = json!({
            "issuer":"https://issuer.example", "receipt_api_url":"https://issuer.example/openid4vp/verification-receipts",
            "receipt_id":Uuid::now_v7(), "transaction_id":Uuid::now_v7(), "tenant_id":tenant_id,
            "issuance_request_jti":Uuid::now_v7(), "presentation_binding_sha256":"a".repeat(64), "intent_sha256":"b".repeat(64),
            "receipt_jws":"invalid", "receipt_sha256":sha256(b"invalid"), "capability_sha256":"c".repeat(64),
            "deployment_id":"deployment", "runtime_instance_id":"instance", "instance_key_id":key_id,
            "instance_public_key_base64":public_key,"completed_at":"2026-10-16T00:00:00Z","expires_at":"2026-10-16T00:10:00Z"
        });
        let parsed: ReviewScreenshotAudit = serde_json::from_value(audit.clone()).unwrap();
        assert!(valid_review_screenshot_trigger(
            &parsed,
            &url::Url::parse("https://issuer.example/ui/verification-result").unwrap(),
            &report.suite_origin,
            &identity.deployment.target_issuer,
            "module"
        ));
        crate::secure_file::write_atomic(&receipt_path, &serde_json::to_vec(&audit).unwrap(), true)
            .unwrap();
        assert_eq!(
            write_private_control_evidence_bundle(&report, &root, &identity, &binding),
            Err(EvidenceError::Identity)
        );
        // A runtime signs the receipt after presentation completion. Both the
        // evidence writer and recovery reader use this historical verifier.
        use crate::oidf_protocol::Openid4vpVerificationReceipt;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        binding.resource_identities.push(TenantResourceIdentity {
            kind: nazo_operator_protocol::TenantResourceKind::Openid4vcTrustPolicy,
            resource_id: "policy".into(),
            digest: "d".repeat(64),
        });
        let provenance = &audit["verification_receipt"];
        let completed =
            chrono::DateTime::parse_from_rfc3339(provenance["completed_at"].as_str().unwrap())
                .unwrap();
        let expires =
            chrono::DateTime::parse_from_rfc3339(provenance["expires_at"].as_str().unwrap())
                .unwrap();
        let signed: Openid4vpVerificationReceipt = serde_json::from_value(json!({
            "schema":1,"iss":provenance["issuer"],"aud":provenance["receipt_api_url"],
            "jti":provenance["receipt_id"],"iat":completed.timestamp()+5,"exp":expires.timestamp(),
            "deployment_id":provenance["deployment_id"],"runtime_instance_id":provenance["runtime_instance_id"],
            "instance_key_id":provenance["instance_key_id"],"tenant_id":provenance["tenant_id"],
            "transaction_id":provenance["transaction_id"],"issuance_request_jti":provenance["issuance_request_jti"],
            "status":"verified","completed_at":provenance["completed_at"],
            "intent_sha256":provenance["intent_sha256"],"capability_sha256":provenance["capability_sha256"],
            "evidence_context":{
                "run_jti":binding.run_id,"artifact_sha256":identity.source.test_source.content_sha256,
                "matrix_sha256":report.matrix_digest,"suite_plan_id":"suite-plan","suite_module_id":"module",
                "test_name":"test","variant_sha256":sha256(b"{}")
            },
            "presentation_binding":{
                "presentation_request_sha256":"d".repeat(64),
                "trust_policy":{"binding_id":Uuid::now_v7(),"resource_id":"policy","resource_digest":"d".repeat(64)}
            }
        })).unwrap();
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA", "kid": key_id,
                "typ": "nazoauth-openid4vp-verification-receipt+jwt",
            }))
            .unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        let input = format!("{protected}.{payload}");
        let signature = signing.sign(input.as_bytes());
        let compact = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        audit["verification_receipt"]["receipt_sha256"] = json!(sha256(compact.as_bytes()));
        audit["verification_receipt"]["receipt_jws"] = json!(compact);
        audit["verification_receipt"]["presentation_binding_sha256"] = json!(sha256(
            &serde_json::to_vec(&signed.presentation_binding).unwrap()
        ));
        let valid_bytes = serde_json::to_vec(&audit).unwrap();
        crate::secure_file::write_atomic(&receipt_path, &valid_bytes, true).unwrap();
        let valid = write_private_control_evidence_bundle(&report, &root, &identity, &binding)
            .expect("receipt issued after completion must be accepted");
        assert_eq!(
            std::fs::read(
                valid
                    .directory
                    .join(&path)
                    .with_extension("png.receipt.json")
            )
            .unwrap(),
            valid_bytes
        );
        audit["verification_receipt"]["tenant_id"] = json!(Uuid::now_v7());
        crate::secure_file::write_atomic(&receipt_path, &serde_json::to_vec(&audit).unwrap(), true)
            .unwrap();
        assert_eq!(
            write_private_control_evidence_bundle(&report, &root, &identity, &binding),
            Err(EvidenceError::Identity)
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.path().join("manifest.json").exists())
                .count(),
            2
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn screenshot_limits_reject_excess_and_overflow_before_writing() {
        let mut module = crate::report::ModuleReport::from_info(
            crate::report::ModuleReportContext {
                matrix_plan_id: "matrix-plan".to_owned(),
                suite_plan_id: "suite-plan".to_owned(),
                module_id: Some("module".to_owned()),
                test_name: "test".to_owned(),
                variant: Default::default(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status": "FINISHED", "result": "PASSED"}),
            serde_json::json!([]),
        );
        module.review_screenshots_missing = 2;
        assert!(validate_review_screenshot_obligations(&module).is_ok());
        let mut modules = vec![module.clone(); 32];
        assert!(validate_review_screenshot_run_limit(&modules).is_ok());
        modules.push(module.clone());
        assert!(validate_review_screenshot_run_limit(&modules).is_err());
        module.review_screenshots_missing = 3;
        assert!(validate_review_screenshot_obligations(&module).is_err());
        modules[1].review_screenshots_missing = usize::MAX;
        assert!(validate_review_screenshot_run_limit(&modules).is_err());
    }

    #[test]
    fn completion_evidence_is_bound_to_the_dynamic_tenant_issuer() {
        let tenant_issuer = "https://01a06016-43e0-7cf1-9633-b9c6124823cb.oidf.example.com";
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
