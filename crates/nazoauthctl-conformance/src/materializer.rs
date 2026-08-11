//! Two-phase Rust-native materialization for NazoAuth's conformance matrix.
//!
//! `prepare` allocates the complete ephemeral credential set and emits only
//! the values required by the NazoAuth onboarding endpoint.  The operator
//! applies that bundle and returns an `OnboardingOutput` containing lease and
//! logical-to-actual client mappings.  `finalize` then substitutes private
//! material from the in-memory preparation into the Suite configuration.  A
//! bundle or mapping from another run cannot be accepted because all three
//! identities (lease, matrix, and bundle) are checked before finalization.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(all(test, unix))]
use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
use crate::origin::Origin;

pub const SECURE_BUNDLE_SCHEMA_VERSION: u32 = 2;

mod crypto;
mod descriptor;
mod template;

#[cfg(test)]
use crypto::MTLS_CLIENT_SAN_DNS;
use crypto::{
    digest_hex, generate_client_crypto, random_hex, random_secret, registration_requires_mtls,
    validate_materialized_mtls_registration,
};
pub use descriptor::{
    CryptoPolicy, DESCRIPTOR_SCHEMA_VERSION, DescriptorGroup, DescriptorPlan, DescriptorSource,
    DescriptorVariant, MAX_DESCRIPTOR_BYTES, MatrixDescriptor, RoleRequirement,
};
use descriptor::{
    collect_client_policies, collect_registrations, descriptor_requires_reference, is_placeholder,
    parse_placeholder, validate_binding_reference, validate_descriptor, validate_digest,
};
use template::{materialize_registration_template, materialize_value, validate_target_issuer};

/// Lease/apply result.  It intentionally contains no password, client secret,
/// private JWK, or private certificate key.  The values are retained only in
/// `PreparedMaterialization` and are substituted during `finalize`.
#[derive(Clone)]
pub struct OnboardingOutput {
    lease_id: String,
    request_jti: String,
    matrix_sha256: String,
    applicant_id: String,
    openid4vc_request_object_trust_anchor_pem: String,
    clients: BTreeMap<String, String>,
}

impl OnboardingOutput {
    pub fn new(
        lease_id: impl Into<String>,
        request_jti: impl Into<String>,
        matrix_sha256: impl Into<String>,
        applicant_id: impl Into<String>,
        openid4vc_request_object_trust_anchor_pem: impl Into<String>,
        clients: BTreeMap<String, String>,
    ) -> Result<Self, MaterializerError> {
        let lease_id = lease_id.into();
        let request_jti = request_jti.into();
        let matrix_sha256 = matrix_sha256.into();
        let applicant_id = applicant_id.into();
        let openid4vc_request_object_trust_anchor_pem =
            openid4vc_request_object_trust_anchor_pem.into();
        validate_lease_id(&lease_id)?;
        validate_request_jti(&request_jti)?;
        validate_digest(&matrix_sha256, "matrix_sha256")?;
        validate_lease_id(&applicant_id)
            .map_err(|_| MaterializerError::InvalidField("applicant_id"))?;
        validate_public_certificate_bundle(&openid4vc_request_object_trust_anchor_pem)?;
        for (logical, actual) in &clients {
            validate_public_id(logical, "logical client id", 256)?;
            validate_public_id(actual, "actual client id", 512)?;
        }
        let actual_ids = clients.values().collect::<BTreeSet<_>>();
        if actual_ids.len() != clients.len() {
            return Err(MaterializerError::DuplicateClientMapping);
        }
        Ok(Self {
            lease_id,
            request_jti,
            matrix_sha256,
            applicant_id,
            openid4vc_request_object_trust_anchor_pem,
            clients,
        })
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn matrix_sha256(&self) -> &str {
        &self.matrix_sha256
    }

    /// Compatibility accessor; this is the raw MatrixDescribe SHA-256, not a
    /// second derived identity.
    pub fn matrix_digest(&self) -> &str {
        self.matrix_sha256()
    }

    pub fn request_jti(&self) -> &str {
        &self.request_jti
    }

    pub fn clients(&self) -> &BTreeMap<String, String> {
        &self.clients
    }
}

impl std::fmt::Debug for OnboardingOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OnboardingOutput")
            .field("lease_id", &self.lease_id)
            .field("request_jti", &self.request_jti)
            .field("matrix_sha256", &self.matrix_sha256)
            .field("applicant_id", &self.applicant_id)
            .field(
                "openid4vc_request_object_trust_anchor_pem",
                &"<public-certificate>",
            )
            .field("clients", &self.clients)
            .finish()
    }
}

/// Preparation state is deliberately neither serializable nor printable.
/// Its `Zeroize`/`ZeroizeOnDrop` implementation clears every private field;
/// descriptor/public metadata is retained only for the duration of finalize.
pub struct PreparedMaterialization {
    descriptor: MatrixDescriptor,
    target_issuer: String,
    suite_base_url: String,
    request_jti: String,
    matrix_sha256: String,
    bundle_digest: String,
    applicant_email: Zeroizing<String>,
    applicant_password: Zeroizing<String>,
    dynamic_registration_initial_access_token: Option<Zeroizing<String>>,
    ciba_automated_decision_token: Option<Zeroizing<String>>,
    clients: BTreeMap<String, PreparedClient>,
}

impl Zeroize for PreparedMaterialization {
    fn zeroize(&mut self) {
        self.applicant_password.zeroize();
        self.applicant_email.zeroize();
        self.dynamic_registration_initial_access_token.zeroize();
        self.ciba_automated_decision_token.zeroize();
        for client in self.clients.values_mut() {
            client.zeroize();
        }
    }
}

impl ZeroizeOnDrop for PreparedMaterialization {}

impl Drop for PreparedMaterialization {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PreparedMaterialization {
    pub fn request_jti(&self) -> &str {
        &self.request_jti
    }

    pub fn matrix_sha256(&self) -> &str {
        &self.matrix_sha256
    }

    pub fn matrix_digest(&self) -> &str {
        self.matrix_sha256()
    }

    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    pub fn expected_clients(&self) -> BTreeSet<String> {
        self.clients.keys().cloned().collect()
    }

    pub fn applicant_email(&self) -> &str {
        &self.applicant_email
    }

    pub fn suite_base_url(&self) -> &str {
        &self.suite_base_url
    }
}

struct PreparedClient {
    logical_client_id: String,
    client_secret: Zeroizing<String>,
    rsa_private_jwks: Zeroizing<String>,
    rsa_public_jwks: Zeroizing<String>,
    ec_private_jwks: Zeroizing<String>,
    ec_public_jwks: Zeroizing<String>,
    mtls_ca_certificate: Zeroizing<String>,
    mtls_client_certificate: Zeroizing<String>,
    mtls_client_key: Zeroizing<String>,
    mtls_client_certificate_sha256: String,
    request: Value,
}

impl Zeroize for PreparedClient {
    fn zeroize(&mut self) {
        self.client_secret.zeroize();
        self.rsa_private_jwks.zeroize();
        self.rsa_public_jwks.zeroize();
        self.ec_private_jwks.zeroize();
        self.ec_public_jwks.zeroize();
        self.mtls_ca_certificate.zeroize();
        self.mtls_client_certificate.zeroize();
        self.mtls_client_key.zeroize();
    }
}

/// Private bytes are zeroized and can only be written using the owner-only
/// atomic writer.  The bundle record below intentionally excludes private JWK
/// values and the mTLS private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Zeroizing<Vec<u8>>);

impl SecureBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn write_private(&self, path: &Path) -> Result<(), MaterializerError> {
        crate::secure_file::write_atomic(path, self.as_bytes(), true).map_err(|error| match error {
            crate::secure_file::SecureFileError::UnsupportedPlatform => {
                MaterializerError::UnsupportedPlatform
            }
            _ => MaterializerError::SecureIo,
        })
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecureBytes([redacted])")
    }
}

pub struct SecureOnboardingBundle {
    bytes: SecureBytes,
    digest: String,
    matrix_sha256: String,
    request_jti: String,
}

impl SecureOnboardingBundle {
    pub fn bytes(&self) -> &SecureBytes {
        &self.bytes
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn matrix_sha256(&self) -> &str {
        &self.matrix_sha256
    }

    pub fn request_jti(&self) -> &str {
        &self.request_jti
    }

    pub fn write_private(&self, path: &Path) -> Result<(), MaterializerError> {
        self.bytes.write_private(path)
    }
}

impl std::fmt::Debug for SecureOnboardingBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureOnboardingBundle")
            .field("digest", &self.digest)
            .field("matrix_sha256", &self.matrix_sha256)
            .field("request_jti", &self.request_jti)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MaterializerError {
    #[error("matrix descriptor exceeds its size limit")]
    Oversize,
    #[error("matrix descriptor is malformed")]
    Malformed,
    #[error("matrix descriptor schema is unsupported: {0}")]
    UnsupportedSchema(u32),
    #[error("matrix descriptor field {0} is invalid")]
    InvalidField(&'static str),
    #[error("matrix descriptor contains duplicate id: {0}")]
    DuplicateId(String),
    #[error("matrix descriptor contains duplicate role: {0}")]
    DuplicateRole(String),
    #[error("matrix descriptor contains a static sensitive value")]
    EmbeddedSecret,
    #[error("matrix template contains an invalid placeholder")]
    InvalidPlaceholder,
    #[error("matrix template references an unknown secret: {0}")]
    UnknownSecretReference(String),
    #[error("matrix template references another plan or group: {0}")]
    CrossPlanReference(String),
    #[error("matrix template contains a cyclic secret reference")]
    SecretCycle,
    #[error("matrix template references an unknown logical client: {0}")]
    UnknownClientReference(String),
    #[error("matrix template contains an ambiguous logical client reference")]
    AmbiguousClientReference,
    #[error("descriptor requests a weak or unsupported cryptographic policy")]
    WeakAlgorithm,
    #[error("target issuer is not an HTTPS or loopback HTTP URL")]
    UnsafeIssuer,
    #[error("cryptographic material generation failed")]
    Crypto,
    #[error("secure bundle encoding failed")]
    Encoding,
    #[error("secure bundle persistence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("secure bundle persistence failed")]
    SecureIo,
    #[error("onboarding output is missing a required logical client")]
    MissingClientMapping,
    #[error("onboarding output contains an unexpected logical client")]
    ExtraClientMapping,
    #[error("onboarding output contains duplicate actual clients")]
    DuplicateClientMapping,
    #[error("onboarding request identity does not match preparation")]
    RequestMismatch,
    #[error("onboarding matrix identity does not match preparation")]
    MatrixDigestMismatch,
}

pub struct DescriptorMaterializer;

/// Deployment-owned profile tokens required by official dynamic-registration
/// and CIBA plans. They are supplied by the controller's secure-file boundary;
/// the materializer never invents a second authority value.
pub struct DeploymentConformanceSecrets {
    dynamic_registration_initial_access_token: Zeroizing<String>,
    ciba_automated_decision_token: Zeroizing<String>,
}

impl DeploymentConformanceSecrets {
    pub fn new(
        dynamic_registration_initial_access_token: Zeroizing<String>,
        ciba_automated_decision_token: Zeroizing<String>,
    ) -> Result<Self, MaterializerError> {
        for value in [
            dynamic_registration_initial_access_token.as_str(),
            ciba_automated_decision_token.as_str(),
        ] {
            if value.len() < 32
                || value.len() > 4096
                || value
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err(MaterializerError::InvalidField(
                    "deployment_conformance_secret",
                ));
            }
        }
        Ok(Self {
            dynamic_registration_initial_access_token,
            ciba_automated_decision_token,
        })
    }
}

impl DescriptorMaterializer {
    pub fn from_bytes(bytes: &[u8]) -> Result<MatrixDescriptor, MaterializerError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(MaterializerError::Oversize);
        }
        let mut descriptor: MatrixDescriptor =
            serde_json::from_slice(bytes).map_err(|_| MaterializerError::Malformed)?;
        validate_descriptor(&descriptor)?;
        descriptor.raw_sha256 = Some(digest_hex(bytes));
        Ok(descriptor)
    }

    /// Generate all ephemeral material and an onboarding-only bundle.  No
    /// actual client ids or lease are known at this point.
    pub fn prepare(
        descriptor: MatrixDescriptor,
        target_issuer: &str,
        suite_origin: &Origin,
        request_jti: &str,
        deployment_secrets: DeploymentConformanceSecrets,
    ) -> Result<(PreparedMaterialization, SecureOnboardingBundle), MaterializerError> {
        validate_descriptor(&descriptor)?;
        validate_target_issuer(target_issuer)?;
        validate_request_jti(request_jti)?;
        let matrix_sha256 = descriptor
            .raw_sha256
            .clone()
            .ok_or(MaterializerError::InvalidField("matrix_sha256"))?;
        let policies = collect_client_policies(&descriptor)?;
        let registrations = collect_registrations(&descriptor)?;
        let applicant_password = Zeroizing::new(random_secret(32));
        let applicant_email = Zeroizing::new(format!("oidf-{}@example.invalid", random_hex(16)));
        let mut clients = BTreeMap::new();
        for (logical_client_id, policy) in policies {
            let registration = registrations
                .get(&logical_client_id)
                .ok_or(MaterializerError::InvalidField("registration_template"))?;
            clients.insert(
                logical_client_id.clone(),
                PreparedClient::new(
                    logical_client_id,
                    &policy,
                    registration,
                    target_issuer,
                    suite_origin.as_str(),
                    request_jti,
                )?,
            );
        }
        let needs_dynamic_token = descriptor_requires_reference(
            &descriptor,
            "deployment.dynamic_registration_initial_access_token",
        );
        let needs_ciba_token =
            descriptor_requires_reference(&descriptor, "deployment.ciba_automated_decision_token")
                || descriptor_requires_reference(&descriptor, "target.ciba_automated_decision_url");
        let dynamic_registration_initial_access_token = needs_dynamic_token
            .then_some(deployment_secrets.dynamic_registration_initial_access_token);
        let ciba_automated_decision_token =
            needs_ciba_token.then_some(deployment_secrets.ciba_automated_decision_token);
        let bundle_record = SecureBundleRecord {
            schema: SECURE_BUNDLE_SCHEMA_VERSION,
            request_jti: request_jti.to_owned(),
            matrix_sha256: matrix_sha256.clone(),
            profile: "nazoauth-full".to_owned(),
            target_issuer: target_issuer.to_owned(),
            suite_base_url: suite_origin.as_str().to_owned(),
            applicant: SecureApplicantBundle {
                email: applicant_email.clone(),
                password: applicant_password.clone(),
            },
            dynamic_registration_initial_access_token: dynamic_registration_initial_access_token
                .clone(),
            ciba_automated_decision_token: ciba_automated_decision_token.clone(),
            clients: clients
                .values()
                .map(PreparedClient::server_record)
                .collect(),
        };
        let bytes = serde_json::to_vec(&bundle_record).map_err(|_| MaterializerError::Encoding)?;
        let bundle_digest = digest_hex(&bytes);
        let bundle = SecureOnboardingBundle {
            bytes: SecureBytes(Zeroizing::new(bytes)),
            digest: bundle_digest.clone(),
            matrix_sha256: matrix_sha256.clone(),
            request_jti: request_jti.to_owned(),
        };
        let prepared = PreparedMaterialization {
            descriptor,
            target_issuer: target_issuer.to_owned(),
            suite_base_url: suite_origin.as_str().to_owned(),
            request_jti: request_jti.to_owned(),
            matrix_sha256,
            bundle_digest,
            applicant_email,
            applicant_password,
            dynamic_registration_initial_access_token,
            ciba_automated_decision_token,
            clients,
        };
        Ok((prepared, bundle))
    }

    /// Verify the lease/apply result and only then construct the Suite matrix
    /// with actual client ids and private in-memory material.
    pub fn finalize(
        prepared: PreparedMaterialization,
        onboarding: OnboardingOutput,
    ) -> Result<MaterializedMatrix, MaterializerError> {
        validate_lease_id(&onboarding.lease_id)?;
        if onboarding.request_jti != prepared.request_jti {
            return Err(MaterializerError::RequestMismatch);
        }
        if onboarding.matrix_sha256 != prepared.matrix_sha256 {
            return Err(MaterializerError::MatrixDigestMismatch);
        }
        let expected = prepared.clients.keys().collect::<BTreeSet<_>>();
        let actual = onboarding.clients.keys().collect::<BTreeSet<_>>();
        if actual.len() < expected.len() && !expected.is_subset(&actual) {
            return Err(MaterializerError::MissingClientMapping);
        }
        if !expected.is_subset(&actual) {
            return Err(MaterializerError::MissingClientMapping);
        }
        if !actual.is_subset(&expected) {
            return Err(MaterializerError::ExtraClientMapping);
        }

        let mut groups = Vec::with_capacity(prepared.descriptor.groups.len());
        for group in &prepared.descriptor.groups {
            let mut plans = Vec::with_capacity(group.plans.len());
            for plan in &group.plans {
                let config = materialize_value(
                    &plan.config_template,
                    &plan.secret_bindings,
                    &prepared,
                    &onboarding,
                    &mut BTreeSet::new(),
                )?;
                plans.push(MatrixPlan {
                    id: plan.id.clone(),
                    plan: plan.plan.clone(),
                    config,
                    variant: plan.variant.clone(),
                });
            }
            groups.push(MatrixGroup {
                id: group.id.clone(),
                profile: group.profile.clone(),
                variant: MatrixVariant {
                    id: group.variant.id.clone(),
                    values: group.variant.values.clone(),
                },
                plans,
            });
        }
        let matrix = MatrixDocument {
            schema: crate::matrix::MATRIX_SCHEMA_VERSION,
            name: format!("nazoauth-{}", prepared.descriptor.source.release),
            groups,
        };
        Ok(MaterializedMatrix {
            matrix: Some(SelectedMatrix::from_materialized(
                matrix,
                prepared.matrix_sha256.clone(),
            )),
            matrix_sha256: prepared.matrix_sha256.clone(),
            bundle_digest: prepared.bundle_digest.clone(),
            lease_id: onboarding.lease_id.clone(),
        })
    }
}

pub struct MaterializedMatrix {
    matrix: Option<SelectedMatrix>,
    matrix_sha256: String,
    bundle_digest: String,
    lease_id: String,
}

impl Drop for MaterializedMatrix {
    fn drop(&mut self) {
        if let Some(matrix) = &mut self.matrix {
            matrix.zeroize_config();
        }
    }
}

impl MaterializedMatrix {
    pub fn matrix(&self) -> &SelectedMatrix {
        self.matrix
            .as_ref()
            .expect("materialized matrix has not been transferred")
    }

    /// Transfer the secret-bearing Suite configuration into the runner
    /// without cloning it. The empty shell remains safely droppable.
    pub fn take_matrix(&mut self) -> SelectedMatrix {
        self.matrix
            .take()
            .expect("materialized matrix may be transferred only once")
    }

    pub fn matrix_sha256(&self) -> &str {
        &self.matrix_sha256
    }

    pub fn matrix_digest(&self) -> &str {
        self.matrix_sha256()
    }

    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }
}

impl std::fmt::Debug for MaterializedMatrix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaterializedMatrix")
            .field("matrix_sha256", &self.matrix_sha256)
            .field("bundle_digest", &self.bundle_digest)
            .field("lease_id", &self.lease_id)
            .finish()
    }
}

impl PreparedClient {
    fn new(
        logical_client_id: String,
        policy: &CryptoPolicy,
        registration_template: &Value,
        target_issuer: &str,
        suite_origin: &str,
        request_jti: &str,
    ) -> Result<Self, MaterializerError> {
        let generated = generate_client_crypto(policy)?;
        let request = materialize_registration_template(
            registration_template,
            &logical_client_id,
            target_issuer,
            suite_origin,
            &generated.rsa_public_jwks,
            &generated.ec_public_jwks,
            &generated.mtls_ca_certificate,
            &generated.mtls_client_certificate,
            &generated.mtls_client_certificate_sha256,
            request_jti,
        )?;
        validate_materialized_mtls_registration(
            &request,
            &generated.mtls_client_certificate_sha256,
        )?;
        let auth_method = request
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .ok_or(MaterializerError::InvalidField(
                "registration_template.token_endpoint_auth_method",
            ))?;
        let client_secret = if matches!(auth_method, "client_secret_basic" | "client_secret_post") {
            generated.client_secret
        } else {
            Zeroizing::new(String::new())
        };
        Ok(Self {
            logical_client_id,
            client_secret,
            rsa_private_jwks: generated.rsa_private_jwks,
            rsa_public_jwks: generated.rsa_public_jwks,
            ec_private_jwks: generated.ec_private_jwks,
            ec_public_jwks: generated.ec_public_jwks,
            mtls_ca_certificate: generated.mtls_ca_certificate,
            mtls_client_certificate: generated.mtls_client_certificate,
            mtls_client_key: generated.mtls_client_key,
            mtls_client_certificate_sha256: generated.mtls_client_certificate_sha256,
            request,
        })
    }

    fn server_record(&self) -> SecureClientRecord {
        SecureClientRecord {
            client_secret: if self.client_secret.is_empty() {
                None
            } else {
                Some(self.client_secret.clone())
            },
            request: self.request.clone(),
            mtls_trust_anchor_pem: if registration_requires_mtls(&self.request) {
                Some(self.mtls_ca_certificate.clone())
            } else {
                None
            },
            logical_client_id: self.logical_client_id.clone(),
        }
    }
}

#[derive(Serialize)]
struct SecureBundleRecord {
    schema: u32,
    request_jti: String,
    matrix_sha256: String,
    profile: String,
    target_issuer: String,
    suite_base_url: String,
    applicant: SecureApplicantBundle,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_registration_initial_access_token: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciba_automated_decision_token: Option<Zeroizing<String>>,
    clients: Vec<SecureClientRecord>,
}

#[derive(Serialize)]
struct SecureClientRecord {
    logical_client_id: String,
    request: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtls_trust_anchor_pem: Option<Zeroizing<String>>,
}

#[derive(Serialize)]
struct SecureApplicantBundle {
    email: Zeroizing<String>,
    password: Zeroizing<String>,
}

fn validate_public_certificate_bundle(value: &str) -> Result<(), MaterializerError> {
    if value.is_empty()
        || value.len() > 256 * 1024
        || value.contains('\0')
        || value.contains("PRIVATE KEY")
        || !value.contains("-----BEGIN CERTIFICATE-----")
        || !value.contains("-----END CERTIFICATE-----")
    {
        return Err(MaterializerError::InvalidField(
            "openid4vc_request_object_trust_anchor_pem",
        ));
    }
    Ok(())
}

fn validate_public_id(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), MaterializerError> {
    if value.trim().is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

fn validate_lease_id(value: &str) -> Result<(), MaterializerError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| MaterializerError::InvalidField("lease_id"))
}

fn validate_request_jti(value: &str) -> Result<(), MaterializerError> {
    let suffix = value
        .strip_prefix("request-")
        .ok_or(MaterializerError::InvalidField("request_jti"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(MaterializerError::InvalidField("request_jti"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_optional_mtls_selectors_do_not_create_a_trust_anchor() {
        let baseline = serde_json::json!({
            "token_endpoint_auth_method": "client_secret_basic",
            "require_mtls_bound_tokens": false,
            "tls_client_auth_subject_dn": null,
            "tls_client_auth_cert_sha256": null,
            "tls_client_auth_san_dns": [],
            "tls_client_auth_san_uri": [],
            "tls_client_auth_san_ip": [],
            "tls_client_auth_san_email": []
        });
        assert!(!registration_requires_mtls(&baseline));

        let mut mtls = baseline.clone();
        mtls["token_endpoint_auth_method"] = serde_json::json!("tls_client_auth");
        assert!(registration_requires_mtls(&mtls));

        let mut san_bound = baseline;
        san_bound["tls_client_auth_san_uri"] = serde_json::json!(["spiffe://client"]);
        assert!(registration_requires_mtls(&san_bound));
    }

    #[test]
    fn tls_client_auth_must_bind_the_generated_certificate_identity() {
        let digest = "a".repeat(64);
        let valid = serde_json::json!({
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_auth_subject_dn": null,
            "tls_client_auth_cert_sha256": digest,
            "tls_client_auth_san_dns": [MTLS_CLIENT_SAN_DNS],
            "tls_client_auth_san_uri": [],
            "tls_client_auth_san_ip": [],
            "tls_client_auth_san_email": []
        });
        assert!(validate_materialized_mtls_registration(&valid, &"a".repeat(64)).is_ok());

        let mut wrong_san = valid.clone();
        wrong_san["tls_client_auth_san_dns"] = serde_json::json!(["other-client"]);
        assert!(validate_materialized_mtls_registration(&wrong_san, &"a".repeat(64)).is_err());

        let mut wrong_digest = valid;
        wrong_digest["tls_client_auth_cert_sha256"] = serde_json::json!("b".repeat(64));
        assert!(validate_materialized_mtls_registration(&wrong_digest, &"a".repeat(64)).is_err());
    }

    fn descriptor() -> MatrixDescriptor {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema":1,
            "source":{"release":"test","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "groups":[{"id":"oidc","profile":"oidc","variant":{"id":"default"},
                "required_roles":[{"role":"applicant","logical_client_id":"web","registration_template":{
                    "client_name":"test-client","client_type":"confidential","redirect_uris":["{{target.suite}}"],
                    "post_logout_redirect_uris":[],"scopes":["openid"],"allowed_audiences":["resource://default"],
                    "grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_basic",
                    "jwks":"{{client.web.ec.public_jwks}}"
                }}],
                "plans":[{"id":"basic","plan":"oidcc-basic-certification-test-plan",
                    "config_template":{"issuer":"{{target.issuer}}","client_id":"{{client.web.id}}",
                        "client_secret":"{{client.web.client_secret}}","jwks":"{{client.web.ec.private_jwks}}",
                        "password":"{{generated.applicant_password}}"},
                    "required_roles":[]}]
            }]
        })).expect("descriptor");
        DescriptorMaterializer::from_bytes(&bytes).expect("descriptor")
    }

    fn suite() -> Origin {
        Origin::parse_suite("https://suite.example").expect("suite")
    }

    fn deployment_secrets() -> DeploymentConformanceSecrets {
        DeploymentConformanceSecrets::new(
            Zeroizing::new("d".repeat(32)),
            Zeroizing::new("c".repeat(32)),
        )
        .expect("deployment secrets")
    }

    #[test]
    fn secure_bundle_uses_deployment_profile_tokens_without_generating_another_authority() {
        let mut descriptor = descriptor();
        let config = &mut descriptor.groups[0].plans[0].config_template;
        config["initial_access_token"] =
            serde_json::json!("{{deployment.dynamic_registration_initial_access_token}}");
        config["automated_ciba_token"] =
            serde_json::json!("{{deployment.ciba_automated_decision_token}}");
        let dynamic = "dynamic-deployment-token-0123456789";
        let ciba = "ciba-deployment-token-01234567890123";
        let (_, bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            DeploymentConformanceSecrets::new(
                Zeroizing::new(dynamic.to_owned()),
                Zeroizing::new(ciba.to_owned()),
            )
            .expect("deployment secrets"),
        )
        .expect("prepare");
        let value: Value = serde_json::from_slice(bundle.bytes().as_bytes()).expect("bundle");
        assert_eq!(value["dynamic_registration_initial_access_token"], dynamic);
        assert_eq!(value["ciba_automated_decision_token"], ciba);
    }

    fn request_jti() -> &'static str {
        "request-0123456789abcdef0123456789abcdef"
    }

    fn test_trust_anchor() -> &'static str {
        "-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----\n"
    }

    fn onboarding_output(
        lease_id: &str,
        request_jti: &str,
        matrix_sha256: &str,
        clients: BTreeMap<String, String>,
    ) -> Result<OnboardingOutput, MaterializerError> {
        OnboardingOutput::new(
            lease_id,
            request_jti,
            matrix_sha256,
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f41",
            test_trust_anchor(),
            clients,
        )
    }

    #[test]
    fn two_phase_bundle_excludes_private_factors_and_matrix_reuses_secret() {
        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            deployment_secrets(),
        )
        .expect("prepare");
        let bundle_text =
            String::from_utf8(bundle.bytes().as_bytes().to_vec()).expect("bundle utf8");
        assert!(bundle_text.contains("client_secret"));
        assert!(bundle_text.contains("\"applicant\""));
        assert!(bundle_text.contains("\"password\""));
        assert!(!bundle_text.contains("\"d\""));
        assert!(!bundle_text.contains("private_jwk"));
        assert!(!bundle_text.contains("client_key"));
        let actual = BTreeMap::from([("web".to_owned(), "actual-client".to_owned())]);
        let output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            actual,
        )
        .expect("output");
        let matrix = DescriptorMaterializer::finalize(prepared, output).expect("finalize");
        let config = &matrix.matrix().document.groups[0].plans[0].config;
        assert_eq!(
            config.get("client_id").and_then(Value::as_str),
            Some("actual-client")
        );
        assert!(
            config
                .get("client_secret")
                .and_then(Value::as_str)
                .is_some()
        );
        let private_key = config
            .get("jwks")
            .and_then(|value| value.get("keys"))
            .and_then(Value::as_array)
            .and_then(|keys| keys.first())
            .expect("Suite client.jwks must be a JWKS containing a private key");
        assert!(private_key.get("d").and_then(Value::as_str).is_some());
        assert!(private_key.get("kid").and_then(Value::as_str).is_some());
        assert_eq!(matrix.matrix_sha256().len(), 64);
    }

    #[test]
    fn missing_extra_and_cross_run_mappings_are_rejected() {
        let (prepared, _bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            deployment_secrets(),
        )
        .expect("prepare");
        let missing = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            BTreeMap::new(),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, missing).unwrap_err(),
            MaterializerError::MissingClientMapping
        );

        let (prepared, _bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            deployment_secrets(),
        )
        .expect("prepare");
        let extra = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            BTreeMap::from([
                ("web".to_owned(), "actual".to_owned()),
                ("extra".to_owned(), "other".to_owned()),
            ]),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, extra).unwrap_err(),
            MaterializerError::ExtraClientMapping
        );

        let (prepared, _) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            deployment_secrets(),
        )
        .expect("prepare");
        let wrong_matrix = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            BTreeMap::from([("web".to_owned(), "actual".to_owned())]),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, wrong_matrix).unwrap_err(),
            MaterializerError::MatrixDigestMismatch
        );

        let (prepared, _) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            deployment_secrets(),
        )
        .expect("prepare");
        let invalid_lease = onboarding_output(
            "not-a-uuid",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            BTreeMap::from([("web".to_owned(), "actual".to_owned())]),
        );
        assert_eq!(
            invalid_lease.unwrap_err(),
            MaterializerError::InvalidField("lease_id")
        );
    }

    #[test]
    fn secure_bundle_writer_is_owner_only() {
        #[cfg(unix)]
        {
            let root = std::env::temp_dir()
                .join(format!("nazoauthctl-materializer-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            crate::secure_file::ensure_directory(&root, true).expect("private root");
            let (_, bundle) = DescriptorMaterializer::prepare(
                descriptor(),
                "https://issuer.example",
                &suite(),
                request_jti(),
                deployment_secrets(),
            )
            .expect("prepare");
            let path = root.join("bundle.json");
            bundle.write_private(&path).expect("write");
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
            let _ = fs::remove_dir_all(root);
        }
    }
}
