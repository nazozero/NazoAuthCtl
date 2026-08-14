use std::{collections::BTreeSet, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::artifact_driver::OidfDriverProgram;

pub const OIDF_TRUST_POLICY_SCHEMA_VERSION: u32 = 1;
pub const OIDF_ARTIFACT_SCHEMA_VERSION: u32 = 3;
pub const OIDF_DRIVER_ENGINE_PROTOCOL: u32 = 2;
pub const OIDF_MATRIX_SCHEMA_VERSION: u32 = 2;
pub const MAX_SIGNED_DRIVER_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACT_MATRIX_BYTES: usize = 8 * 1024 * 1024;

const DRIVER_JWS_TYPE: &str = "nazoauth-oidf-driver-manifest+jws";
const MAX_ARTIFACT_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTrustPolicy {
    pub schema: u32,
    pub source: String,
    pub signer_identity: String,
    pub key_id: String,
    pub public_key_sec1: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverManifest {
    pub schema: u32,
    pub artifact_id: String,
    pub revision: String,
    pub source: String,
    pub signer_identity: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub suite: OidfSuiteIdentity,
    pub engine_protocol: u32,
    pub required_capabilities: Vec<String>,
    pub driver: OidfDriverIdentity,
    pub matrix: OidfMatrixIdentity,
    pub resource_bounds: OidfResourceBounds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfSuiteIdentity {
    pub release: String,
    pub revision: String,
    pub image_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfMatrixIdentity {
    pub schema: u32,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverIdentity {
    pub schema: u32,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfResourceBounds {
    pub max_plans: u32,
    pub max_modules: u32,
    pub max_clients: u32,
    pub max_wall_clock_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfArtifactMatrix {
    pub schema: u32,
    pub name: String,
    pub groups: Vec<OidfArtifactMatrixGroup>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfArtifactMatrixGroup {
    pub id: String,
    pub profile: String,
    pub variant: OidfArtifactMatrixVariant,
    pub plans: Vec<OidfArtifactMatrixPlan>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfArtifactMatrixVariant {
    pub id: String,
    #[serde(default)]
    pub values: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfArtifactMatrixPlan {
    pub id: String,
    pub plan: String,
    pub driver_handler: String,
    pub resource_budget: OidfPlanResourceBudget,
    pub config_template: Value,
    #[serde(default)]
    pub variant: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub expected_results: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfPlanResourceBudget {
    pub modules: u32,
    pub clients: u32,
    pub wall_clock_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedOidfArtifact {
    pub artifact_id: String,
    pub revision: String,
    pub source: String,
    pub signer_identity: String,
    pub signer_key_id: String,
    pub driver_manifest_sha256: String,
    pub driver_manifest_size: u64,
    pub suite: OidfSuiteIdentity,
    pub engine_protocol: u32,
    pub required_capabilities: Vec<String>,
    pub driver_schema: u32,
    pub driver_sha256: String,
    pub driver_size: u64,
    pub driver_handlers: u32,
    pub matrix_sha256: String,
    pub matrix_size: u64,
    pub matrix_groups: u32,
    pub matrix_plans: u32,
    pub matrix_modules: u32,
    pub matrix_clients: u32,
    pub matrix_wall_clock_seconds: u64,
    pub not_before: i64,
    pub expires_at: i64,
    pub resource_bounds: OidfResourceBounds,
}

#[derive(Clone, Debug)]
pub struct VerifiedOidfDriverManifest {
    manifest: OidfDriverManifest,
    signer_key_id: String,
    compact_sha256: String,
    compact_size: u64,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ArtifactError {
    #[error("artifact input path is not a stable regular file")]
    UnsafePath,
    #[error("artifact input could not be read")]
    Io,
    #[error("artifact input exceeds its size limit")]
    Oversize,
    #[error("artifact trust policy is malformed")]
    TrustPolicy,
    #[error("signed driver manifest is malformed")]
    MalformedManifest,
    #[error("signed driver manifest protected header is invalid")]
    ProtectedHeader,
    #[error("signed driver manifest signature is invalid")]
    Signature,
    #[error("signed driver manifest violates policy: {0}")]
    ManifestPolicy(&'static str),
    #[error("artifact matrix is malformed")]
    MalformedMatrix,
    #[error("artifact driver is malformed")]
    MalformedDriver,
    #[error("artifact driver violates policy: {0}")]
    DriverPolicy(&'static str),
    #[error("artifact matrix violates policy: {0}")]
    MatrixPolicy(&'static str),
    #[error("artifact requires unsupported capability {0}")]
    UnsupportedCapability(String),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl ArtifactTrustPolicy {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(ArtifactError::TrustPolicy);
        }
        let policy: Self = serde_json::from_slice(bytes).map_err(|_| ArtifactError::TrustPolicy)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_path(path: &Path) -> Result<Self, ArtifactError> {
        let bytes = crate::secure_file::read_bounded(path, 64 * 1024, true)
            .map_err(map_secure_file_error)?;
        Self::from_bytes(&bytes)
    }

    fn verifying_key(&self) -> Result<VerifyingKey, ArtifactError> {
        let bytes = decode_base64url(&self.public_key_sec1, ArtifactError::TrustPolicy)?;
        let key = VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| ArtifactError::TrustPolicy)?;
        if self.key_id != key_id(&key) {
            return Err(ArtifactError::TrustPolicy);
        }
        Ok(key)
    }

    fn validate(&self) -> Result<Url, ArtifactError> {
        self.verifying_key()?;
        let source = self.validated_source()?;
        if self.schema != OIDF_TRUST_POLICY_SCHEMA_VERSION
            || !valid_signer_identity(&self.signer_identity)
        {
            return Err(ArtifactError::TrustPolicy);
        }
        Ok(source)
    }

    fn validated_source(&self) -> Result<Url, ArtifactError> {
        let source =
            validated_https_url(&self.source, true).map_err(|_| ArtifactError::TrustPolicy)?;
        if source.as_str() != self.source {
            return Err(ArtifactError::TrustPolicy);
        }
        Ok(source)
    }

    pub(crate) fn accepts_url(&self, value: &str) -> bool {
        let Ok(source) = self.validate() else {
            return false;
        };
        validated_https_url(value, false)
            .is_ok_and(|candidate| url_is_below_source(&candidate, &source))
    }
}

pub fn verify_oidf_artifact(
    compact_manifest: &str,
    driver_bytes: &[u8],
    matrix_bytes: &[u8],
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<VerifiedOidfArtifact, ArtifactError> {
    let driver = verify_oidf_driver_manifest(compact_manifest, trust, available_capabilities, now)?;
    verify_oidf_matrix(driver, driver_bytes, matrix_bytes)
}

pub fn verify_oidf_driver_manifest(
    compact_manifest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<VerifiedOidfDriverManifest, ArtifactError> {
    trust.validate()?;
    if compact_manifest.is_empty() || compact_manifest.len() > MAX_SIGNED_DRIVER_BYTES {
        return Err(ArtifactError::Oversize);
    }
    if compact_manifest.chars().any(char::is_whitespace) {
        return Err(ArtifactError::MalformedManifest);
    }
    let mut segments = compact_manifest.split('.');
    let protected = segments.next().ok_or(ArtifactError::MalformedManifest)?;
    let payload = segments.next().ok_or(ArtifactError::MalformedManifest)?;
    let signature = segments.next().ok_or(ArtifactError::MalformedManifest)?;
    if segments.next().is_some()
        || protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
    {
        return Err(ArtifactError::MalformedManifest);
    }

    let protected_bytes = decode_base64url(protected, ArtifactError::ProtectedHeader)?;
    let header: ProtectedHeader =
        serde_json::from_slice(&protected_bytes).map_err(|_| ArtifactError::ProtectedHeader)?;
    if header.alg != "ES256" || header.typ != DRIVER_JWS_TYPE || header.kid != trust.key_id {
        return Err(ArtifactError::ProtectedHeader);
    }
    let signature_bytes = decode_base64url(signature, ArtifactError::Signature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ArtifactError::Signature)?;
    trust
        .verifying_key()?
        .verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .map_err(|_| ArtifactError::Signature)?;

    let payload_bytes = decode_base64url(payload, ArtifactError::MalformedManifest)?;
    if payload_bytes.is_empty() || payload_bytes.len() > MAX_SIGNED_DRIVER_BYTES {
        return Err(ArtifactError::Oversize);
    }
    let manifest: OidfDriverManifest =
        serde_json::from_slice(&payload_bytes).map_err(|_| ArtifactError::MalformedManifest)?;
    validate_manifest(&manifest, trust, available_capabilities, now)?;
    Ok(VerifiedOidfDriverManifest {
        manifest,
        signer_key_id: trust.key_id.clone(),
        compact_sha256: digest(compact_manifest.as_bytes()),
        compact_size: u64::try_from(compact_manifest.len())
            .map_err(|_| ArtifactError::ManifestPolicy("driver manifest size exceeds u64"))?,
    })
}

pub fn verify_oidf_matrix(
    driver: VerifiedOidfDriverManifest,
    driver_bytes: &[u8],
    matrix_bytes: &[u8],
) -> Result<VerifiedOidfArtifact, ArtifactError> {
    let driver_program = driver.verify_driver_payload(driver_bytes)?;
    verify_oidf_matrix_with_driver(driver, driver_program, matrix_bytes)
}

pub(crate) fn verify_oidf_matrix_with_driver(
    driver: VerifiedOidfDriverManifest,
    driver_program: OidfDriverProgram,
    matrix_bytes: &[u8],
) -> Result<VerifiedOidfArtifact, ArtifactError> {
    let (matrix, matrix_budget) = validate_matrix(matrix_bytes, &driver.manifest, &driver_program)?;
    let matrix_plans = matrix
        .groups
        .iter()
        .map(|group| group.plans.len())
        .sum::<usize>();
    let manifest = driver.manifest;
    Ok(VerifiedOidfArtifact {
        artifact_id: manifest.artifact_id,
        revision: manifest.revision,
        source: manifest.source,
        signer_identity: manifest.signer_identity,
        signer_key_id: driver.signer_key_id,
        driver_manifest_sha256: driver.compact_sha256,
        driver_manifest_size: driver.compact_size,
        suite: manifest.suite,
        engine_protocol: manifest.engine_protocol,
        required_capabilities: manifest.required_capabilities,
        driver_schema: manifest.driver.schema,
        driver_sha256: manifest.driver.sha256,
        driver_size: manifest.driver.size,
        driver_handlers: u32::try_from(driver_program.handlers.len())
            .map_err(|_| ArtifactError::DriverPolicy("driver handler count exceeds u32"))?,
        matrix_sha256: manifest.matrix.sha256,
        matrix_size: manifest.matrix.size,
        matrix_groups: u32::try_from(matrix.groups.len())
            .map_err(|_| ArtifactError::MatrixPolicy("matrix group count exceeds u32"))?,
        matrix_plans: u32::try_from(matrix_plans)
            .map_err(|_| ArtifactError::MatrixPolicy("matrix plan count exceeds u32"))?,
        matrix_modules: matrix_budget.modules,
        matrix_clients: matrix_budget.clients,
        matrix_wall_clock_seconds: matrix_budget.wall_clock_seconds,
        not_before: manifest.not_before,
        expires_at: manifest.expires_at,
        resource_bounds: manifest.resource_bounds,
    })
}

impl VerifiedOidfDriverManifest {
    pub(crate) fn verify_driver_payload(
        &self,
        driver_bytes: &[u8],
    ) -> Result<OidfDriverProgram, ArtifactError> {
        crate::artifact_driver::validate_oidf_driver(
            driver_bytes,
            self.manifest.driver.schema,
            self.manifest.driver.size,
            &self.manifest.driver.sha256,
            self.manifest.engine_protocol,
        )
    }

    pub fn driver_url(&self) -> &str {
        &self.manifest.driver.url
    }

    pub fn driver_size(&self) -> u64 {
        self.manifest.driver.size
    }

    pub fn matrix_url(&self) -> &str {
        &self.manifest.matrix.url
    }

    pub fn matrix_size(&self) -> u64 {
        self.manifest.matrix.size
    }

    pub fn compact_sha256(&self) -> &str {
        &self.compact_sha256
    }
}

pub fn read_compact_manifest(path: &Path) -> Result<String, ArtifactError> {
    let bytes = crate::secure_file::read_bounded(path, MAX_SIGNED_DRIVER_BYTES, false)
        .map_err(map_secure_file_error)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ArtifactError::MalformedManifest)?;
    let compact = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    Ok(compact.to_owned())
}

pub fn read_artifact_matrix(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    crate::secure_file::read_bounded(path, MAX_ARTIFACT_MATRIX_BYTES, false)
        .map_err(map_secure_file_error)
}

pub fn read_artifact_driver(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    crate::secure_file::read_bounded(path, crate::MAX_ARTIFACT_DRIVER_BYTES, false)
        .map_err(map_secure_file_error)
}

fn validate_manifest(
    manifest: &OidfDriverManifest,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<(), ArtifactError> {
    if manifest.schema != OIDF_ARTIFACT_SCHEMA_VERSION {
        return Err(ArtifactError::ManifestPolicy("unsupported artifact schema"));
    }
    validate_identifier(&manifest.artifact_id, 128).map_err(ArtifactError::ManifestPolicy)?;
    validate_lower_hex(&manifest.revision, 40).map_err(ArtifactError::ManifestPolicy)?;
    if manifest.source != trust.source || manifest.signer_identity != trust.signer_identity {
        return Err(ArtifactError::ManifestPolicy(
            "artifact source or signer is not trusted",
        ));
    }
    let source = trust.validated_source()?;
    let driver_url =
        validated_https_url(&manifest.driver.url, false).map_err(ArtifactError::ManifestPolicy)?;
    if !url_is_below_source(&driver_url, &source) {
        return Err(ArtifactError::ManifestPolicy(
            "driver URL is outside the trusted source",
        ));
    }
    let matrix_url =
        validated_https_url(&manifest.matrix.url, false).map_err(ArtifactError::ManifestPolicy)?;
    if !url_is_below_source(&matrix_url, &source) {
        return Err(ArtifactError::ManifestPolicy(
            "matrix URL is outside the trusted source",
        ));
    }
    if manifest.issued_at <= 0
        || manifest.not_before < manifest.issued_at
        || manifest.expires_at <= manifest.not_before
        || manifest.expires_at - manifest.issued_at > MAX_ARTIFACT_LIFETIME_SECONDS
        || now < manifest.not_before
        || now >= manifest.expires_at
    {
        return Err(ArtifactError::ManifestPolicy(
            "artifact is outside its validity window",
        ));
    }
    if !valid_bounded_text(&manifest.suite.release, 128)
        || validate_lower_hex(&manifest.suite.revision, 40).is_err()
        || !valid_sha256_digest(&manifest.suite.image_digest)
    {
        return Err(ArtifactError::ManifestPolicy("Suite identity is invalid"));
    }
    if manifest.engine_protocol != OIDF_DRIVER_ENGINE_PROTOCOL {
        return Err(ArtifactError::ManifestPolicy(
            "driver engine protocol is unsupported",
        ));
    }
    validate_capabilities(&manifest.required_capabilities)
        .map_err(ArtifactError::ManifestPolicy)?;
    for capability in &manifest.required_capabilities {
        if !available_capabilities.contains(capability) {
            return Err(ArtifactError::UnsupportedCapability(capability.clone()));
        }
    }
    if manifest.driver.schema != crate::OIDF_DRIVER_SCHEMA_VERSION
        || manifest.driver.size == 0
        || manifest.driver.size > crate::MAX_ARTIFACT_DRIVER_BYTES as u64
        || validate_lower_hex(&manifest.driver.sha256, 64).is_err()
    {
        return Err(ArtifactError::ManifestPolicy("driver identity is invalid"));
    }
    if manifest.matrix.schema != OIDF_MATRIX_SCHEMA_VERSION
        || manifest.matrix.size == 0
        || manifest.matrix.size > MAX_ARTIFACT_MATRIX_BYTES as u64
        || validate_lower_hex(&manifest.matrix.sha256, 64).is_err()
    {
        return Err(ArtifactError::ManifestPolicy("matrix identity is invalid"));
    }
    let bounds = &manifest.resource_bounds;
    if !(1..=512).contains(&bounds.max_plans)
        || !(1..=8192).contains(&bounds.max_modules)
        || !(1..=256).contains(&bounds.max_clients)
        || !(60..=86_400).contains(&bounds.max_wall_clock_seconds)
    {
        return Err(ArtifactError::ManifestPolicy(
            "resource bounds are outside controller policy",
        ));
    }
    if manifest.expires_at - manifest.not_before
        <= i64::try_from(bounds.max_wall_clock_seconds)
            .map_err(|_| ArtifactError::ManifestPolicy("wall-clock bound exceeds i64"))?
    {
        return Err(ArtifactError::ManifestPolicy(
            "artifact validity cannot contain its signed wall-clock bound",
        ));
    }
    Ok(())
}

fn validate_matrix(
    bytes: &[u8],
    manifest: &OidfDriverManifest,
    driver: &crate::OidfDriverProgram,
) -> Result<(OidfArtifactMatrix, OidfPlanResourceBudget), ArtifactError> {
    if bytes.is_empty()
        || bytes.len() > MAX_ARTIFACT_MATRIX_BYTES
        || bytes.len() as u64 != manifest.matrix.size
        || digest(bytes) != manifest.matrix.sha256
    {
        return Err(ArtifactError::MatrixPolicy(
            "matrix bytes do not match the signed identity",
        ));
    }
    let matrix: OidfArtifactMatrix =
        serde_json::from_slice(bytes).map_err(|_| ArtifactError::MalformedMatrix)?;
    if matrix.schema != OIDF_MATRIX_SCHEMA_VERSION
        || matrix.schema != manifest.matrix.schema
        || !valid_bounded_text(&matrix.name, 128)
        || matrix.groups.is_empty()
        || matrix.groups.len() > 64
    {
        return Err(ArtifactError::MatrixPolicy(
            "matrix header is outside policy",
        ));
    }
    let mut group_ids = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    let driver_handlers = driver
        .handlers
        .iter()
        .map(|handler| handler.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut used_driver_handlers = BTreeSet::new();
    let mut plan_count = 0usize;
    let mut matrix_budget = OidfPlanResourceBudget {
        modules: 0,
        clients: 0,
        wall_clock_seconds: 0,
    };
    for group in &matrix.groups {
        validate_identifier(&group.id, 128).map_err(ArtifactError::MatrixPolicy)?;
        validate_identifier(&group.profile, 128).map_err(ArtifactError::MatrixPolicy)?;
        validate_identifier(&group.variant.id, 128).map_err(ArtifactError::MatrixPolicy)?;
        validate_variant(&group.variant.values).map_err(ArtifactError::MatrixPolicy)?;
        if !group_ids.insert(group.id.as_str()) || group.plans.is_empty() {
            return Err(ArtifactError::MatrixPolicy(
                "matrix groups must be unique and non-empty",
            ));
        }
        for plan in &group.plans {
            plan_count = plan_count.saturating_add(1);
            validate_identifier(&plan.id, 128).map_err(ArtifactError::MatrixPolicy)?;
            validate_identifier(&plan.plan, 256).map_err(ArtifactError::MatrixPolicy)?;
            validate_identifier(&plan.driver_handler, 128).map_err(ArtifactError::MatrixPolicy)?;
            if !driver_handlers.contains(plan.driver_handler.as_str()) {
                return Err(ArtifactError::MatrixPolicy(
                    "matrix plan references an unknown driver handler",
                ));
            }
            used_driver_handlers.insert(plan.driver_handler.as_str());
            validate_plan_resource_budget(&plan.resource_budget, &manifest.resource_bounds)
                .map_err(ArtifactError::MatrixPolicy)?;
            matrix_budget.modules = matrix_budget
                .modules
                .checked_add(plan.resource_budget.modules)
                .ok_or(ArtifactError::MatrixPolicy(
                    "matrix module budget overflows",
                ))?;
            matrix_budget.clients = matrix_budget
                .clients
                .checked_add(plan.resource_budget.clients)
                .ok_or(ArtifactError::MatrixPolicy(
                    "matrix client budget overflows",
                ))?;
            matrix_budget.wall_clock_seconds = matrix_budget
                .wall_clock_seconds
                .checked_add(plan.resource_budget.wall_clock_seconds)
                .ok_or(ArtifactError::MatrixPolicy(
                    "matrix wall-clock budget overflows",
                ))?;
            validate_variant(&plan.variant).map_err(ArtifactError::MatrixPolicy)?;
            validate_capabilities(&plan.required_capabilities)
                .map_err(ArtifactError::MatrixPolicy)?;
            for capability in &plan.required_capabilities {
                if !manifest.required_capabilities.contains(capability) {
                    return Err(ArtifactError::MatrixPolicy(
                        "plan capability is not declared by the signed driver",
                    ));
                }
            }
            if !plan_ids.insert(plan.id.as_str()) || !plan.config_template.is_object() {
                return Err(ArtifactError::MatrixPolicy(
                    "matrix plans must be unique and contain object templates",
                ));
            }
            if plan.expected_results.len() > plan.resource_budget.modules as usize
                || plan.expected_results.len() > 64
                || plan.expected_results.iter().any(|(module, result)| {
                    validate_identifier(module, 256).is_err() || result != "SKIPPED"
                })
            {
                return Err(ArtifactError::MatrixPolicy(
                    "expected SKIPPED exceptions exceed the plan budget or are invalid",
                ));
            }
            let mut nodes = 0usize;
            validate_template(&plan.config_template, 0, &mut nodes)
                .map_err(ArtifactError::MatrixPolicy)?;
        }
    }
    if plan_count == 0 || plan_count > manifest.resource_bounds.max_plans as usize {
        return Err(ArtifactError::MatrixPolicy(
            "matrix plan count exceeds the signed resource bound",
        ));
    }
    if matrix_budget.modules > manifest.resource_bounds.max_modules
        || matrix_budget.clients > manifest.resource_bounds.max_clients
        || matrix_budget.wall_clock_seconds > manifest.resource_bounds.max_wall_clock_seconds
    {
        return Err(ArtifactError::MatrixPolicy(
            "matrix resource budget exceeds the signed artifact bounds",
        ));
    }
    if used_driver_handlers != driver_handlers {
        return Err(ArtifactError::MatrixPolicy(
            "driver contains handlers unused by the signed Matrix",
        ));
    }
    Ok((matrix, matrix_budget))
}

fn validate_plan_resource_budget(
    budget: &OidfPlanResourceBudget,
    bounds: &OidfResourceBounds,
) -> Result<(), &'static str> {
    if budget.modules == 0
        || budget.modules > bounds.max_modules
        || budget.clients > bounds.max_clients
        || budget.wall_clock_seconds == 0
        || budget.wall_clock_seconds > bounds.max_wall_clock_seconds
    {
        return Err("plan resource budget is outside the signed artifact bounds");
    }
    Ok(())
}

fn validate_template(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), &'static str> {
    *nodes = nodes.saturating_add(1);
    if depth > 16 || *nodes > 4096 {
        return Err("matrix template structure is too large");
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if !valid_bounded_text(key, 256) {
                    return Err("matrix template contains an invalid key");
                }
                match sensitive_field(key) {
                    Some(SensitiveField::PlaceholderOnly) if !matches!(child, Value::String(text) if valid_placeholder(text)) =>
                    {
                        return Err("matrix template embeds sensitive material");
                    }
                    Some(SensitiveField::JwkContainer) if matches!(child, Value::String(text) if !valid_placeholder(text)) =>
                    {
                        return Err("matrix template embeds serialized sensitive material");
                    }
                    _ => {}
                }
                validate_template(child, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                validate_template(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) => {
            if text.len() > 16 * 1024
                || ((text.contains("{{") || text.contains("}}")) && !valid_placeholder(text))
                || contains_private_key_pem(text)
            {
                return Err("matrix template contains an invalid string");
            }
            if matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['))
                && let Ok(serialized) = serde_json::from_str::<Value>(text)
            {
                validate_template(&serialized, depth + 1, nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn valid_placeholder(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("{{")
        .and_then(|value| value.strip_suffix("}}"))
    else {
        return false;
    };
    if inner.is_empty() || inner.len() > 256 {
        return false;
    }
    let mut segments = inner.split('.');
    if !matches!(
        segments.next(),
        Some("target" | "suite" | "resource" | "run")
    ) {
        return false;
    }
    let mut path_segments = 0usize;
    for segment in segments {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-'))
        {
            return false;
        }
        path_segments += 1;
    }
    path_segments > 0
}

#[derive(Clone, Copy)]
enum SensitiveField {
    PlaceholderOnly,
    JwkContainer,
}

fn sensitive_field(key: &str) -> Option<SensitiveField> {
    let normalized = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    match normalized.as_str() {
        "password" | "passwordhash" | "passwd" | "token" | "accesstoken" | "refreshtoken"
        | "idtoken" | "clientsecret" | "clientassertion" | "secret" | "apikey" | "privatekey"
        | "privatejwk" | "privatejwks" | "signingkey" | "d" | "p" | "q" | "dp" | "dq" | "qi"
        | "oth" | "k" => Some(SensitiveField::PlaceholderOnly),
        "authorization" | "authorizationheader" | "credential" | "credentials" => {
            Some(SensitiveField::PlaceholderOnly)
        }
        "jwk" | "jwks" => Some(SensitiveField::JwkContainer),
        _ => None,
    }
}

fn contains_private_key_pem(value: &str) -> bool {
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn validate_capabilities(values: &[String]) -> Result<(), &'static str> {
    if values.len() > 128 {
        return Err("capability set exceeds policy");
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(value, 128)?;
        if !value.contains('.') || !unique.insert(value) {
            return Err("capabilities must be namespaced and unique");
        }
    }
    Ok(())
}

fn validate_variant(
    values: &std::collections::BTreeMap<String, String>,
) -> Result<(), &'static str> {
    if values.len() > 64 {
        return Err("matrix variant exceeds policy");
    }
    for (key, value) in values {
        validate_identifier(key, 128)?;
        if sensitive_field(key).is_some() {
            if !valid_placeholder(value) {
                return Err("matrix variant embeds sensitive material");
            }
        } else {
            validate_identifier(value, 256)?;
        }
    }
    Ok(())
}

fn validated_https_url(value: &str, directory: bool) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "artifact URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().contains(['\\', '%'])
        || (directory && !url.path().ends_with('/'))
    {
        return Err("artifact URL violates HTTPS source policy");
    }
    Ok(url)
}

fn url_is_below_source(candidate: &Url, source: &Url) -> bool {
    candidate.scheme() == source.scheme()
        && candidate.host_str() == source.host_str()
        && candidate.port_or_known_default() == source.port_or_known_default()
        && candidate.path().starts_with(source.path())
        && candidate.path().len() > source.path().len()
}

pub(crate) fn validate_identifier(value: &str, maximum: usize) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
    {
        return Err("identifier is invalid");
    }
    Ok(())
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character == '\0')
}

fn valid_signer_identity(value: &str) -> bool {
    valid_bounded_text(value, 2048)
        && !value.chars().any(char::is_whitespace)
        && validated_https_url(value, false).is_ok_and(|identity| identity.as_str() == value)
}

fn validate_lower_hex(value: &str, length: usize) -> Result<(), &'static str> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err("digest or revision is invalid")
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| validate_lower_hex(digest, 64).is_ok())
}

fn decode_base64url<T>(value: &str, error: T) -> Result<Vec<u8>, T> {
    if value.contains('=') {
        return Err(error);
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| error)
}

fn key_id(key: &VerifyingKey) -> String {
    let encoded = key.to_encoded_point(true);
    format!("oidf-es256-{}", &digest(encoded.as_bytes())[..32])
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn map_secure_file_error(error: crate::secure_file::SecureFileError) -> ArtifactError {
    match error {
        crate::secure_file::SecureFileError::UnsafePath => ArtifactError::UnsafePath,
        crate::secure_file::SecureFileError::Oversize => ArtifactError::Oversize,
        crate::secure_file::SecureFileError::NotFound
        | crate::secure_file::SecureFileError::UnsupportedPlatform
        | crate::secure_file::SecureFileError::Io => ArtifactError::Io,
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    use crate::{OidfDriverAutomation, OidfDriverHandler, OidfDriverLane, OidfDriverProgram};

    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7; 32]).expect("signing key")
    }

    fn trust() -> ArtifactTrustPolicy {
        let key = signing_key();
        let public = key.verifying_key().to_encoded_point(true);
        ArtifactTrustPolicy {
            schema: OIDF_TRUST_POLICY_SCHEMA_VERSION,
            source: "https://artifacts.example/oidf/".to_owned(),
            signer_identity:
                "https://github.com/example/oidf-driver/.github/workflows/release.yml@refs/tags/v1.2.3"
                    .to_owned(),
            key_id: key_id(key.verifying_key()),
            public_key_sec1: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        }
    }

    fn matrix() -> Vec<u8> {
        serde_json::to_vec(&OidfArtifactMatrix {
            schema: OIDF_MATRIX_SCHEMA_VERSION,
            name: "official-fixed-matrix".to_owned(),
            groups: vec![OidfArtifactMatrixGroup {
                id: "oidc-core".to_owned(),
                profile: "oidc".to_owned(),
                variant: OidfArtifactMatrixVariant {
                    id: "default".to_owned(),
                    values: Default::default(),
                },
                plans: vec![OidfArtifactMatrixPlan {
                    id: "oidc-core-p001".to_owned(),
                    plan: "oidcc-basic-certification-test-plan".to_owned(),
                    driver_handler: "default".to_owned(),
                    resource_budget: OidfPlanResourceBudget {
                        modules: 32,
                        clients: 2,
                        wall_clock_seconds: 600,
                    },
                    config_template: serde_json::json!({
                        "alias": "{{run.alias}}",
                        "server": {"discoveryUrl": "{{target.discovery_url}}"},
                        "client_secret": "{{resource.client.secret}}"
                    }),
                    variant: Default::default(),
                    required_capabilities: vec!["nazoauth.client.create".to_owned()],
                    expected_results: std::collections::BTreeMap::from([(
                        "oidcc-intentional-skip".to_owned(),
                        "SKIPPED".to_owned(),
                    )]),
                }],
            }],
        })
        .expect("matrix")
    }

    fn driver() -> Vec<u8> {
        serde_json::to_vec(&OidfDriverProgram {
            schema: crate::OIDF_DRIVER_SCHEMA_VERSION,
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            handlers: vec![OidfDriverHandler {
                id: "default".to_owned(),
                automation: OidfDriverAutomation::None,
                lane: OidfDriverLane::Parallel,
            }],
        })
        .expect("driver")
    }

    fn verify_oidf_artifact(
        compact_manifest: &str,
        matrix_bytes: &[u8],
        trust: &ArtifactTrustPolicy,
        available_capabilities: &BTreeSet<String>,
        now: i64,
    ) -> Result<VerifiedOidfArtifact, ArtifactError> {
        super::verify_oidf_artifact(
            compact_manifest,
            &driver(),
            matrix_bytes,
            trust,
            available_capabilities,
            now,
        )
    }

    fn manifest(matrix: &[u8]) -> OidfDriverManifest {
        let driver = driver();
        OidfDriverManifest {
            schema: OIDF_ARTIFACT_SCHEMA_VERSION,
            artifact_id: "official-oidf-driver".to_owned(),
            revision: "a".repeat(40),
            source: trust().source,
            signer_identity: trust().signer_identity,
            issued_at: NOW - 60,
            not_before: NOW - 30,
            expires_at: NOW + 3600,
            suite: OidfSuiteIdentity {
                release: "v5.2.2".to_owned(),
                revision: "b".repeat(40),
                image_digest: format!("sha256:{}", "c".repeat(64)),
            },
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            required_capabilities: vec!["nazoauth.client.create".to_owned()],
            driver: OidfDriverIdentity {
                schema: crate::OIDF_DRIVER_SCHEMA_VERSION,
                url: "https://artifacts.example/oidf/v1.2.3/driver.json".to_owned(),
                sha256: digest(&driver),
                size: driver.len() as u64,
            },
            matrix: OidfMatrixIdentity {
                schema: OIDF_MATRIX_SCHEMA_VERSION,
                url: "https://artifacts.example/oidf/v1.2.3/matrix.json".to_owned(),
                sha256: digest(matrix),
                size: matrix.len() as u64,
            },
            resource_bounds: OidfResourceBounds {
                max_plans: 32,
                max_modules: 512,
                max_clients: 64,
                max_wall_clock_seconds: 3600,
            },
        }
    }

    fn sign(manifest: &OidfDriverManifest) -> String {
        let key = signing_key();
        let header = ProtectedHeader {
            alg: "ES256".to_owned(),
            kid: key_id(key.verifying_key()),
            typ: DRIVER_JWS_TYPE.to_owned(),
        };
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(manifest).expect("manifest"));
        let signing_input = format!("{protected}.{payload}");
        let signature: Signature = key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn capabilities() -> BTreeSet<String> {
        BTreeSet::from(["nazoauth.client.create".to_owned()])
    }

    #[test]
    fn verifies_signature_source_identity_matrix_and_capabilities_together() {
        let matrix = matrix();
        let compact = sign(&manifest(&matrix));
        let verified = verify_oidf_artifact(&compact, &matrix, &trust(), &capabilities(), NOW)
            .expect("verified artifact");
        assert_eq!(verified.matrix_sha256, digest(&matrix));
        assert_eq!(verified.driver_manifest_sha256, digest(compact.as_bytes()));
        assert_eq!(verified.matrix_groups, 1);
        assert_eq!(verified.matrix_plans, 1);
        assert_eq!(verified.matrix_modules, 32);
        assert_eq!(verified.matrix_clients, 2);
        assert_eq!(verified.matrix_wall_clock_seconds, 600);
        assert_eq!(verified.driver_schema, crate::OIDF_DRIVER_SCHEMA_VERSION);
        assert_eq!(verified.driver_sha256, digest(&driver()));
        assert_eq!(verified.driver_handlers, 1);
        assert_eq!(verified.suite.release, "v5.2.2");
    }

    #[test]
    fn matrix_must_reference_every_signed_declarative_driver_handler() {
        let matrix = matrix();
        let mut unknown: OidfArtifactMatrix = serde_json::from_slice(&matrix).expect("matrix");
        unknown.groups[0].plans[0].driver_handler = "missing".to_owned();
        let unknown = serde_json::to_vec(&unknown).expect("matrix");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&unknown)),
                &unknown,
                &trust(),
                &capabilities(),
                NOW,
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));

        let driver = serde_json::to_vec(&OidfDriverProgram {
            schema: crate::OIDF_DRIVER_SCHEMA_VERSION,
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            handlers: vec![
                OidfDriverHandler {
                    id: "default".to_owned(),
                    automation: OidfDriverAutomation::None,
                    lane: OidfDriverLane::Parallel,
                },
                OidfDriverHandler {
                    id: "unused".to_owned(),
                    automation: OidfDriverAutomation::None,
                    lane: OidfDriverLane::Parallel,
                },
            ],
        })
        .expect("driver");
        let mut signed = manifest(&matrix);
        signed.driver.sha256 = digest(&driver);
        signed.driver.size = driver.len() as u64;
        assert!(matches!(
            super::verify_oidf_artifact(
                &sign(&signed),
                &driver,
                &matrix,
                &trust(),
                &capabilities(),
                NOW,
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));
    }

    #[test]
    fn rejects_tampering_expiry_unknown_capability_and_cross_source_url() {
        let matrix = matrix();
        let compact = sign(&manifest(&matrix));
        let mut signature_tampered = compact.clone().into_bytes();
        let last = signature_tampered.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let signature_tampered = String::from_utf8(signature_tampered).expect("compact JWS");
        assert_eq!(
            verify_oidf_artifact(&signature_tampered, &matrix, &trust(), &capabilities(), NOW),
            Err(ArtifactError::Signature)
        );
        let mut tampered = matrix.clone();
        tampered.push(b' ');
        assert!(matches!(
            verify_oidf_artifact(&compact, &tampered, &trust(), &capabilities(), NOW),
            Err(ArtifactError::MatrixPolicy(_))
        ));
        assert!(matches!(
            verify_oidf_artifact(&compact, &matrix, &trust(), &capabilities(), NOW + 7200),
            Err(ArtifactError::ManifestPolicy(_))
        ));
        assert!(matches!(
            verify_oidf_artifact(&compact, &matrix, &trust(), &BTreeSet::new(), NOW),
            Err(ArtifactError::UnsupportedCapability(_))
        ));

        let mut outside = manifest(&matrix);
        outside.matrix.url = "https://attacker.example/matrix.json".to_owned();
        assert!(matches!(
            verify_oidf_artifact(&sign(&outside), &matrix, &trust(), &capabilities(), NOW),
            Err(ArtifactError::ManifestPolicy(_))
        ));
    }

    #[test]
    fn rejects_unknown_fields_sensitive_literals_review_and_plan_bound_overflow() {
        let matrix = matrix();
        let mut value: Value = serde_json::from_slice(&matrix).expect("matrix JSON");
        value["unknown"] = Value::Bool(true);
        let unknown = serde_json::to_vec(&value).expect("unknown matrix");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&unknown)),
                &unknown,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::MalformedMatrix)
        ));

        let mut literal: OidfArtifactMatrix = serde_json::from_slice(&matrix).expect("matrix");
        literal.groups[0].plans[0].config_template["client_secret"] =
            Value::String("plaintext".to_owned());
        let literal = serde_json::to_vec(&literal).expect("literal");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&literal)),
                &literal,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));

        let mut review: OidfArtifactMatrix = serde_json::from_slice(&matrix).expect("matrix");
        review.groups[0].plans[0]
            .expected_results
            .insert("module".to_owned(), "REVIEW".to_owned());
        let review = serde_json::to_vec(&review).expect("review");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&review)),
                &review,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));

        let mut bounded = manifest(&matrix);
        bounded.resource_bounds.max_plans = 0;
        assert!(matches!(
            verify_oidf_artifact(&sign(&bounded), &matrix, &trust(), &capabilities(), NOW),
            Err(ArtifactError::ManifestPolicy(_))
        ));

        let mut resource_overflow: OidfArtifactMatrix =
            serde_json::from_slice(&matrix).expect("matrix");
        resource_overflow.groups[0].plans[0].resource_budget.modules = 513;
        let resource_overflow = serde_json::to_vec(&resource_overflow).expect("resource overflow");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&resource_overflow)),
                &resource_overflow,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));

        let mut exception_overflow: OidfArtifactMatrix =
            serde_json::from_slice(&matrix).expect("matrix");
        exception_overflow.groups[0].plans[0]
            .resource_budget
            .modules = 1;
        exception_overflow.groups[0].plans[0]
            .expected_results
            .insert("oidcc-second-skip".to_owned(), "SKIPPED".to_owned());
        let exception_overflow =
            serde_json::to_vec(&exception_overflow).expect("exception overflow");
        assert!(matches!(
            verify_oidf_artifact(
                &sign(&manifest(&exception_overflow)),
                &exception_overflow,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::MatrixPolicy(_))
        ));
    }

    #[test]
    fn trust_key_id_is_derived_from_the_public_key() {
        let mut policy = trust();
        policy.key_id = "oidf-es256-wrong".to_owned();
        let bytes = serde_json::to_vec(&policy).expect("policy");
        assert_eq!(
            ArtifactTrustPolicy::from_bytes(&bytes),
            Err(ArtifactError::TrustPolicy)
        );
    }

    #[test]
    fn public_verifier_revalidates_trust_policy_and_uses_exclusive_expiry() {
        let matrix = matrix();
        let compact = sign(&manifest(&matrix));
        let mut invalid_trust = trust();
        invalid_trust.schema = OIDF_TRUST_POLICY_SCHEMA_VERSION + 1;
        assert_eq!(
            verify_oidf_artifact(&compact, &matrix, &invalid_trust, &capabilities(), NOW),
            Err(ArtifactError::TrustPolicy)
        );

        let mut expired = manifest(&matrix);
        expired.expires_at = NOW;
        expired.resource_bounds.max_wall_clock_seconds = 10;
        assert!(matches!(
            verify_oidf_driver_manifest(&sign(&expired), &trust(), &capabilities(), NOW),
            Err(ArtifactError::ManifestPolicy(_))
        ));

        let mut no_completion_margin = manifest(&matrix);
        no_completion_margin.resource_bounds.max_wall_clock_seconds =
            u64::try_from(no_completion_margin.expires_at - no_completion_margin.not_before)
                .unwrap();
        assert!(matches!(
            verify_oidf_driver_manifest(
                &sign(&no_completion_margin),
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactError::ManifestPolicy(_))
        ));
    }

    #[test]
    fn sensitive_schema_rejects_normalized_variant_serialized_and_pem_bypasses() {
        assert!(!valid_placeholder("{{resource.}}"));
        assert!(!valid_placeholder("{{resource..secret}}"));
        let rejects = |artifact_matrix: OidfArtifactMatrix| {
            let bytes = serde_json::to_vec(&artifact_matrix).expect("matrix");
            let result = verify_oidf_artifact(
                &sign(&manifest(&bytes)),
                &bytes,
                &trust(),
                &capabilities(),
                NOW,
            );
            assert!(matches!(result, Err(ArtifactError::MatrixPolicy(_))));
        };

        let baseline = || serde_json::from_slice::<OidfArtifactMatrix>(&matrix()).expect("matrix");
        let mut camel_case = baseline();
        camel_case.groups[0].plans[0].config_template["clientSecret"] =
            Value::String("literal".to_owned());
        rejects(camel_case);

        let mut variant = baseline();
        variant.groups[0].plans[0]
            .variant
            .insert("privateKey".to_owned(), "literal".to_owned());
        rejects(variant);

        let mut group_variant = baseline();
        group_variant.groups[0]
            .variant
            .values
            .insert("secret".to_owned(), "literal".to_owned());
        rejects(group_variant);

        let mut authorization = baseline();
        authorization.groups[0].plans[0].config_template["authorization"] =
            serde_json::json!({"value": "Bearer literal"});
        rejects(authorization);

        let mut serialized = baseline();
        serialized.groups[0].plans[0].config_template["opaque"] =
            Value::String(r#"{"jwk":{"kty":"EC","d":"literal"}}"#.to_owned());
        rejects(serialized);

        let mut pem = baseline();
        pem.groups[0].plans[0].config_template["opaque"] =
            Value::String("-----BEGIN PRIVATE KEY-----\nliteral".to_owned());
        rejects(pem);

        let mut placeholder_variant = baseline();
        placeholder_variant.groups[0].plans[0].variant.insert(
            "clientSecret".to_owned(),
            "{{resource.client.secret}}".to_owned(),
        );
        let bytes = serde_json::to_vec(&placeholder_variant).expect("matrix");
        assert!(
            verify_oidf_artifact(
                &sign(&manifest(&bytes)),
                &bytes,
                &trust(),
                &capabilities(),
                NOW,
            )
            .is_ok()
        );

        let mut public_jwk = baseline();
        public_jwk.groups[0].plans[0].config_template["jwk"] = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y"
        });
        let bytes = serde_json::to_vec(&public_jwk).expect("matrix");
        assert!(
            verify_oidf_artifact(
                &sign(&manifest(&bytes)),
                &bytes,
                &trust(),
                &capabilities(),
                NOW,
            )
            .is_ok()
        );
    }
}
