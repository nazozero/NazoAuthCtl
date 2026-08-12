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

pub const SECURE_BUNDLE_SCHEMA_VERSION: u32 = 3;

mod crypto;
mod descriptor;
mod template;

#[cfg(test)]
use crypto::MTLS_CLIENT_SAN_DNS;
use crypto::{
    GeneratedAttestationMaterial, digest_hex, generate_attestation_material,
    generate_client_crypto, random_hex, random_secret, random_tx_code, registration_requires_mtls,
    validate_materialized_mtls_registration,
};
pub use descriptor::{
    CryptoPolicy, DESCRIPTOR_SCHEMA_VERSION, DescriptorGroup, DescriptorPlan, DescriptorSource,
    DescriptorVariant, MAX_DESCRIPTOR_BYTES, MatrixDescriptor, RoleRequirement,
};
use descriptor::{
    collect_client_policies, collect_registrations, descriptor_requires_reference, is_placeholder,
    parse_placeholder, validate_binding_reference, validate_descriptor, validate_digest,
    validate_single_mdoc_trust_anchor,
};
use template::{
    materialize_registration_template, materialize_value, materialize_vci_config,
    materialize_vp_config, validate_target_issuer,
};

/// Lease/apply result.  It intentionally contains no password, client secret,
/// private JWK, or private certificate key.  The values are retained only in
/// `PreparedMaterialization` and are substituted during `finalize`.
#[derive(Clone)]
pub struct OnboardingOutput {
    lease_id: String,
    request_jti: String,
    matrix_sha256: String,
    bundle_sha256: String,
    applicant_id: String,
    openid4vc_request_object_trust_anchor_pem: String,
    clients: BTreeMap<String, String>,
}

impl OnboardingOutput {
    pub fn new(
        lease_id: impl Into<String>,
        request_jti: impl Into<String>,
        matrix_sha256: impl Into<String>,
        bundle_sha256: impl Into<String>,
        applicant_id: impl Into<String>,
        openid4vc_request_object_trust_anchor_pem: impl Into<String>,
        clients: BTreeMap<String, String>,
    ) -> Result<Self, MaterializerError> {
        let lease_id = lease_id.into();
        let request_jti = request_jti.into();
        let matrix_sha256 = matrix_sha256.into();
        let bundle_sha256 = bundle_sha256.into();
        let applicant_id = applicant_id.into();
        let openid4vc_request_object_trust_anchor_pem =
            openid4vc_request_object_trust_anchor_pem.into();
        validate_lease_id(&lease_id)?;
        validate_request_jti(&request_jti)?;
        validate_digest(&matrix_sha256, "matrix_sha256")?;
        validate_digest(&bundle_sha256, "bundle_sha256")?;
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
            bundle_sha256,
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

    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    /// Compatibility accessor; this is the raw MatrixDescribe SHA-256, not a
    /// second derived identity.
    pub fn matrix_digest(&self) -> &str {
        self.matrix_sha256()
    }

    pub fn request_jti(&self) -> &str {
        &self.request_jti
    }

    pub fn applicant_id(&self) -> &str {
        &self.applicant_id
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
            .field("bundle_sha256", &self.bundle_sha256)
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
    credential_trust_anchor_pem: String,
    applicant_email: Zeroizing<String>,
    applicant_password: Zeroizing<String>,
    tx_code: Option<Zeroizing<String>>,
    attestation: Option<GeneratedAttestationMaterial>,
    dynamic_registration_initial_access_token: Option<Zeroizing<String>>,
    ciba_automated_decision_token: Option<Zeroizing<String>>,
    clients: BTreeMap<String, PreparedClient>,
}

impl Zeroize for PreparedMaterialization {
    fn zeroize(&mut self) {
        self.applicant_password.zeroize();
        self.applicant_email.zeroize();
        self.tx_code.zeroize();
        self.attestation.zeroize();
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

    /// Return a zeroizing run-scoped pre-authorized-code clone for the issuer
    /// driver. It is neither serializable nor printable; callers must not
    /// persist or log it.
    pub fn tx_code(&self) -> Option<Zeroizing<String>> {
        self.tx_code
            .as_ref()
            .map(|value| Zeroizing::new(value.to_string()))
    }

    pub fn expected_clients(&self) -> BTreeSet<String> {
        self.clients.keys().cloned().collect()
    }

    pub fn applicant_email(&self) -> &str {
        &self.applicant_email
    }

    /// Return a zeroizing clone for the lease-owned hosted authorization
    /// session. The password remains neither serializable nor printable and
    /// is only copied across this explicit in-memory boundary.
    pub fn applicant_password(&self) -> Zeroizing<String> {
        Zeroizing::new(self.applicant_password.to_string())
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
    #[error("onboarding bundle identity does not match preparation")]
    BundleDigestMismatch,
}

pub struct DescriptorMaterializer;

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
        credential_trust_anchor_pem: &str,
    ) -> Result<(PreparedMaterialization, SecureOnboardingBundle), MaterializerError> {
        validate_descriptor(&descriptor)?;
        validate_target_issuer(target_issuer)?;
        validate_request_jti(request_jti)?;
        // The server's run-scoped deployment anchor and the Suite's mdoc root
        // are distinct trust domains.  Bind both to this raw Matrix and fail
        // closed if an operator accidentally supplies the same certificate
        // twice; the bundle must contain exactly these two roots in order.
        let credential_trust_anchor_pem = combine_openid4vc_credential_trust_anchors(
            credential_trust_anchor_pem,
            &descriptor.openid4vc_suite_mdoc_trust_anchor_pem,
        )?;
        let matrix_sha256 = descriptor
            .raw_sha256
            .clone()
            .ok_or(MaterializerError::InvalidField("matrix_sha256"))?;
        let policies = collect_client_policies(&descriptor)?;
        let registrations = collect_registrations(&descriptor)?;
        let applicant_password = Zeroizing::new(random_secret(32));
        let applicant_email = Zeroizing::new(format!("oidf-{}@example.invalid", random_hex(16)));
        let tx_code = descriptor_requires_pre_authorized_vci(&descriptor)
            .then(|| Zeroizing::new(random_tx_code()));
        // The official VCI runner may select proof type `attestation` for any
        // VCI plan whose issuer metadata advertises it.  Keep one run-scoped
        // attestation identity for all VCI plans; HAIP adds the client
        // attestation envelope, but it is not the owner of the proof key.
        // The schema-3 onboarding contract requires one lease-scoped public
        // trust object even when a selected subset does not include a VCI
        // plan.  The corresponding private keys remain in `PreparedMaterialization`
        // and are only consumed if a finalized VCI/HAIP plan needs them.
        let attestation = Some(generate_attestation_material()?);
        let attestation_ref = attestation.as_ref().ok_or(MaterializerError::Crypto)?;
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
        // These values are lease-scoped capabilities, not deployment profile
        // configuration.  Generate them only when the signed descriptor
        // actually references the capability.  This keeps unrelated runs from
        // receiving a token and prevents a second run from reusing a DB-unique
        // deployment token.
        let needs_dynamic_token = descriptor_requires_reference(
            &descriptor,
            "generated.dynamic_registration_initial_access_token",
        );
        let needs_ciba_token =
            descriptor_requires_reference(&descriptor, "generated.ciba_automated_decision_token")
                || descriptor_requires_reference(&descriptor, "target.ciba_automated_decision_url");
        let dynamic_registration_initial_access_token =
            needs_dynamic_token.then(|| Zeroizing::new(random_secret(32)));
        let ciba_automated_decision_token =
            needs_ciba_token.then(|| Zeroizing::new(random_secret(32)));
        let bundle_record = SecureBundleRecord {
            schema: SECURE_BUNDLE_SCHEMA_VERSION,
            request_jti: request_jti.to_owned(),
            matrix_sha256: matrix_sha256.clone(),
            profile: "nazoauth-full".to_owned(),
            target_issuer: target_issuer.to_owned(),
            suite_base_url: suite_origin.as_str().to_owned(),
            openid4vc_conformance_trust: SecureOpenid4vcConformanceTrust {
                schema: 1,
                client_attestation_issuer: format!(
                    "{}/",
                    suite_origin.as_str().trim_end_matches('/')
                ),
                client_attestation_jwks: serde_json::from_str(
                    attestation_ref.attester_public_jwks.as_str(),
                )
                .map_err(|_| MaterializerError::Encoding)?,
                key_attestation_jwks: serde_json::from_str(
                    attestation_ref.key_attestation_public_jwks.as_str(),
                )
                .map_err(|_| MaterializerError::Encoding)?,
                credential_trust_anchor_pem: credential_trust_anchor_pem.clone(),
            },
            openid4vc_credential_datasets: descriptor.openid4vc_credential_datasets.clone(),
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
            credential_trust_anchor_pem,
            applicant_email,
            applicant_password,
            tx_code,
            attestation,
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
        if onboarding.bundle_sha256 != prepared.bundle_digest {
            return Err(MaterializerError::BundleDigestMismatch);
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
                let config = materialize_vci_config(
                    &plan.plan,
                    &plan.variant,
                    config,
                    &prepared.target_issuer,
                    &prepared.suite_base_url,
                    prepared.tx_code.as_ref().map(|value| value.as_str()),
                    prepared.attestation.as_ref(),
                    &prepared.credential_trust_anchor_pem,
                )?;
                let config = materialize_vp_config(
                    &plan.plan,
                    &plan.variant,
                    config,
                    &onboarding.openid4vc_request_object_trust_anchor_pem,
                )?;
                plans.push(MatrixPlan {
                    id: plan.id.clone(),
                    plan: plan.plan.clone(),
                    config,
                    variant: plan.variant.clone(),
                    expected_results: plan.expected_results.clone(),
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
    openid4vc_conformance_trust: SecureOpenid4vcConformanceTrust,
    openid4vc_credential_datasets: BTreeMap<String, Value>,
    applicant: SecureApplicantBundle,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_registration_initial_access_token: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciba_automated_decision_token: Option<Zeroizing<String>>,
    clients: Vec<SecureClientRecord>,
}

#[derive(Serialize)]
struct SecureOpenid4vcConformanceTrust {
    schema: u32,
    client_attestation_issuer: String,
    client_attestation_jwks: Value,
    key_attestation_jwks: Value,
    credential_trust_anchor_pem: String,
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

fn combine_openid4vc_credential_trust_anchors(
    deployment_anchor_pem: &str,
    suite_anchor_pem: &str,
) -> Result<String, MaterializerError> {
    let deployment_der =
        validate_single_mdoc_trust_anchor(deployment_anchor_pem, "credential_trust_anchor_pem")?;
    let suite_der = validate_single_mdoc_trust_anchor(
        suite_anchor_pem,
        "openid4vc_suite_mdoc_trust_anchor_pem",
    )?;
    if deployment_der == suite_der {
        return Err(MaterializerError::InvalidField(
            "credential_trust_anchor_pem",
        ));
    }

    let mut combined = String::with_capacity(deployment_anchor_pem.len() + suite_anchor_pem.len());
    combined.push_str(deployment_anchor_pem.trim_end());
    combined.push('\n');
    combined.push_str(suite_anchor_pem.trim_end());
    combined.push('\n');
    Ok(combined)
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

fn descriptor_requires_pre_authorized_vci(descriptor: &MatrixDescriptor) -> bool {
    descriptor.groups.iter().any(|group| {
        group.plans.iter().any(|plan| {
            plan.plan.starts_with("oid4vci-")
                && plan.variant.get("vci_grant_type").map(String::as_str)
                    == Some("pre_authorization_code")
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

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

    #[test]
    fn every_run_generates_fresh_secret_key_and_certificate_material() {
        let first = generate_client_crypto(&CryptoPolicy::default()).expect("first material");
        let second = generate_client_crypto(&CryptoPolicy::default()).expect("second material");

        assert_ne!(first.client_secret.as_str(), second.client_secret.as_str());
        assert_ne!(
            first.rsa_private_jwks.as_str(),
            second.rsa_private_jwks.as_str()
        );
        assert_ne!(
            first.ec_private_jwks.as_str(),
            second.ec_private_jwks.as_str()
        );
        assert_ne!(
            first.mtls_ca_certificate.as_str(),
            second.mtls_ca_certificate.as_str()
        );
        assert_ne!(
            first.mtls_client_certificate_sha256,
            second.mtls_client_certificate_sha256
        );
        assert_ne!(
            first.mtls_client_key.as_str(),
            second.mtls_client_key.as_str()
        );
    }

    fn descriptor_json() -> Value {
        serde_json::json!({
            "schema":1,
            "source":{"release":"test","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "openid4vc_suite_mdoc_trust_anchor_pem": test_suite_mdoc_trust_anchor(),
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
                    "expected_results":{"oidcc-expected-skip":"SKIPPED"},
                    "required_roles":[]}]
            }]
        })
    }

    fn descriptor() -> MatrixDescriptor {
        let bytes = serde_json::to_vec(&descriptor_json()).expect("descriptor");
        DescriptorMaterializer::from_bytes(&bytes).expect("descriptor")
    }

    fn descriptor_with_openid4vc_plan(
        plan_name: &str,
        variant: BTreeMap<String, String>,
        config: Value,
    ) -> MatrixDescriptor {
        let mut descriptor = descriptor();
        let configuration_id = config
            .get("vci")
            .and_then(Value::as_object)
            .and_then(|vci| vci.get("credential_configuration_id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| variant.get("credential_configuration_id").cloned());
        let dataset = config
            .get("nazo")
            .and_then(Value::as_object)
            .and_then(|nazo| nazo.get("credential_dataset"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"given_name":"Conformance"}));
        {
            let plan = &mut descriptor.groups[0].plans[0];
            plan.plan = plan_name.to_owned();
            plan.variant = variant;
            plan.config_template = config;
        }
        if let Some(configuration_id) = configuration_id {
            descriptor
                .openid4vc_credential_datasets
                .insert(configuration_id, dataset);
        }
        descriptor
    }

    fn descriptor_with_openid4vp_plan(request_method: &str, config: Value) -> MatrixDescriptor {
        let mut descriptor = descriptor();
        let plan = &mut descriptor.groups[0].plans[0];
        plan.plan = "oid4vp-1final-verifier-test-plan".to_owned();
        plan.variant = BTreeMap::from([
            ("vp_profile".to_owned(), "plain_vp".to_owned()),
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
            ("request_method".to_owned(), request_method.to_owned()),
        ]);
        plan.config_template = config;
        descriptor
    }

    fn suite() -> Origin {
        Origin::parse_suite("https://suite.example").expect("suite")
    }

    #[test]
    fn secure_bundle_generates_run_scoped_profile_tokens_only_when_referenced() {
        let mut descriptor = descriptor();
        let config = &mut descriptor.groups[0].plans[0].config_template;
        config["initial_access_token"] =
            serde_json::json!("{{generated.dynamic_registration_initial_access_token}}");
        config["automated_ciba_token"] =
            serde_json::json!("{{generated.ciba_automated_decision_token}}");
        let (first_prepared, first_bundle) = DescriptorMaterializer::prepare(
            descriptor.clone(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("first prepare");
        let (second_prepared, second_bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            "request-fedcba9876543210fedcba9876543210",
            test_trust_anchor(),
        )
        .expect("second prepare");
        let first: Value = serde_json::from_slice(first_bundle.bytes().as_bytes()).expect("bundle");
        let second: Value =
            serde_json::from_slice(second_bundle.bytes().as_bytes()).expect("bundle");
        let first_dynamic = first["dynamic_registration_initial_access_token"]
            .as_str()
            .expect("dynamic token");
        let second_dynamic = second["dynamic_registration_initial_access_token"]
            .as_str()
            .expect("dynamic token");
        let first_ciba = first["ciba_automated_decision_token"]
            .as_str()
            .expect("CIBA token");
        let second_ciba = second["ciba_automated_decision_token"]
            .as_str()
            .expect("CIBA token");
        assert!(first_dynamic.len() >= 32);
        assert!(first_ciba.len() >= 32);
        assert_ne!(first_dynamic, second_dynamic);
        assert_ne!(first_ciba, second_ciba);
        assert_ne!(first_bundle.digest(), second_bundle.digest());

        let first_output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            first_prepared.request_jti(),
            first_prepared.matrix_sha256(),
            first_prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "first-client".to_owned())]),
        )
        .expect("first output");
        let second_output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f42",
            second_prepared.request_jti(),
            second_prepared.matrix_sha256(),
            second_prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "second-client".to_owned())]),
        )
        .expect("second output");
        let first_matrix =
            DescriptorMaterializer::finalize(first_prepared, first_output).expect("first finalize");
        let second_matrix = DescriptorMaterializer::finalize(second_prepared, second_output)
            .expect("second finalize");
        assert_eq!(
            first_matrix.matrix().document.groups[0].plans[0].config["initial_access_token"],
            first_dynamic
        );
        assert_eq!(
            first_matrix.matrix().document.groups[0].plans[0].config["automated_ciba_token"],
            first_ciba
        );
        assert_ne!(
            first_matrix.matrix().document.groups[0].plans[0].config["initial_access_token"],
            second_matrix.matrix().document.groups[0].plans[0].config["initial_access_token"]
        );
    }

    #[test]
    fn secure_bundle_omits_profile_tokens_without_references() {
        let (_, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let value: Value = serde_json::from_slice(bundle.bytes().as_bytes()).expect("bundle");
        assert!(
            value
                .get("dynamic_registration_initial_access_token")
                .is_none()
        );
        assert!(value.get("ciba_automated_decision_token").is_none());
    }

    fn request_jti() -> &'static str {
        "request-0123456789abcdef0123456789abcdef"
    }

    fn generated_test_anchor(
        common_name: &str,
        is_ca: IsCa,
        days_before: i64,
        days_after: i64,
    ) -> String {
        let now = time::OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.to_owned());
        params.not_before = now - time::Duration::days(days_before);
        params.not_after = now + time::Duration::days(days_after);
        params.is_ca = is_ca;
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key_pair = KeyPair::generate().expect("key pair");
        params
            .self_signed(&key_pair)
            .expect("certificate")
            .pem()
            .replace("\r\n", "\n")
    }

    fn test_trust_anchor() -> &'static str {
        static ANCHOR: OnceLock<String> = OnceLock::new();
        ANCHOR
            .get_or_init(|| {
                generated_test_anchor(
                    "nazoauthctl-deployment",
                    IsCa::Ca(BasicConstraints::Constrained(1)),
                    1,
                    30,
                )
            })
            .as_str()
    }

    fn test_suite_mdoc_trust_anchor() -> &'static str {
        static ANCHOR: OnceLock<String> = OnceLock::new();
        ANCHOR
            .get_or_init(|| {
                generated_test_anchor(
                    "oidf-suite-mdoc",
                    IsCa::Ca(BasicConstraints::Constrained(1)),
                    1,
                    30,
                )
            })
            .as_str()
    }

    fn combined_test_trust_anchor() -> String {
        format!(
            "{}\n{}\n",
            test_trust_anchor().trim_end(),
            test_suite_mdoc_trust_anchor().trim_end()
        )
    }

    #[test]
    fn suite_mdoc_anchor_is_required_and_cryptographically_validated() {
        let mut missing = descriptor_json();
        missing
            .as_object_mut()
            .expect("descriptor object")
            .remove("openid4vc_suite_mdoc_trust_anchor_pem");
        assert!(
            DescriptorMaterializer::from_bytes(
                &serde_json::to_vec(&missing).expect("missing descriptor")
            )
            .is_err()
        );

        let mut malformed = descriptor_json();
        malformed["openid4vc_suite_mdoc_trust_anchor_pem"] =
            serde_json::json!("-----BEGIN CERTIFICATE-----\nVEVST1I=\n-----END CERTIFICATE-----\n");
        assert!(
            DescriptorMaterializer::from_bytes(
                &serde_json::to_vec(&malformed).expect("malformed descriptor")
            )
            .is_err()
        );

        let mut expired = descriptor_json();
        expired["openid4vc_suite_mdoc_trust_anchor_pem"] =
            serde_json::json!(generated_test_anchor(
                "expired-suite-mdoc",
                IsCa::Ca(BasicConstraints::Constrained(1)),
                2,
                -1
            ));
        assert!(
            DescriptorMaterializer::from_bytes(
                &serde_json::to_vec(&expired).expect("expired descriptor")
            )
            .is_err()
        );

        let mut leaf = descriptor_json();
        leaf["openid4vc_suite_mdoc_trust_anchor_pem"] =
            serde_json::json!(generated_test_anchor("leaf-suite-mdoc", IsCa::NoCa, 1, 30));
        assert!(
            DescriptorMaterializer::from_bytes(
                &serde_json::to_vec(&leaf).expect("leaf descriptor")
            )
            .is_err()
        );
    }

    #[test]
    fn deployment_and_suite_mdoc_roots_must_be_distinct_and_complete() {
        let descriptor = descriptor();
        let duplicate = DescriptorMaterializer::prepare(
            descriptor.clone(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_suite_mdoc_trust_anchor(),
        )
        .err()
        .expect("duplicate roots must fail closed");
        assert!(matches!(
            duplicate,
            MaterializerError::InvalidField("credential_trust_anchor_pem")
        ));

        let missing = DescriptorMaterializer::prepare(
            descriptor.clone(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            "",
        )
        .err()
        .expect("missing deployment root must fail closed");
        assert!(matches!(
            missing,
            MaterializerError::InvalidField("credential_trust_anchor_pem")
        ));

        let expired = generated_test_anchor(
            "expired-deployment-mdoc",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            2,
            -1,
        );
        let expired = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            &expired,
        )
        .err()
        .expect("expired deployment root must fail closed");
        assert!(matches!(
            expired,
            MaterializerError::InvalidField("credential_trust_anchor_pem")
        ));
    }

    fn onboarding_output(
        lease_id: &str,
        request_jti: &str,
        matrix_sha256: &str,
        bundle_sha256: &str,
        clients: BTreeMap<String, String>,
    ) -> Result<OnboardingOutput, MaterializerError> {
        OnboardingOutput::new(
            lease_id,
            request_jti,
            matrix_sha256,
            bundle_sha256,
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
            test_trust_anchor(),
        )
        .expect("prepare");
        let bundle_text =
            String::from_utf8(bundle.bytes().as_bytes().to_vec()).expect("bundle utf8");
        let bundle_value: Value = serde_json::from_str(&bundle_text).expect("bundle json");
        let public_kid = bundle_value["clients"][0]["request"]["jwks"]["keys"][0]["kid"]
            .as_str()
            .expect("public JWK kid")
            .to_owned();
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
            prepared.bundle_digest(),
            actual,
        )
        .expect("output");
        assert_eq!(
            output.applicant_id(),
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f41"
        );
        let matrix = DescriptorMaterializer::finalize(prepared, output).expect("finalize");
        assert_eq!(
            matrix.matrix().document.groups[0].plans[0]
                .expected_results
                .get("oidcc-expected-skip")
                .map(String::as_str),
            Some("SKIPPED")
        );
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
        assert_eq!(
            private_key.get("kid").and_then(Value::as_str),
            Some(public_kid.as_str())
        );
        assert_eq!(matrix.matrix_sha256().len(), 64);
    }

    #[test]
    fn review_cannot_be_preapproved_by_the_signed_matrix() {
        let mut descriptor = descriptor();
        descriptor.groups[0].plans[0]
            .expected_results
            .insert("oidcc-review".to_owned(), "REVIEW".to_owned());
        assert_eq!(
            validate_descriptor(&descriptor),
            Err(MaterializerError::InvalidField(
                "plan.expected_results.result"
            ))
        );
    }

    #[test]
    fn vci_materialization_binds_issuer_and_declared_variant() {
        let first_attestation = generate_attestation_material().expect("first attestation");
        let second_attestation = generate_attestation_material().expect("second attestation");
        assert_ne!(
            first_attestation.key_attestation_private_jwks.as_str(),
            second_attestation.key_attestation_private_jwks.as_str(),
            "VCI proof keys must be generated afresh for each run"
        );
        let config = serde_json::json!({
            "alias": "nazo-vci-run",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "browser": [{
                "match": "https://issuer.example/authorize*",
                "tasks": [
                    {
                        "task": "Complete login page",
                        "match": "https://issuer.example/ui/auth*",
                        "commands": [
                            ["text", "id", "nazo-login-email", "applicant@example.test"],
                            ["text", "id", "nazo-login-password", "password"],
                            ["click", "id", "nazo-login-submit"]
                        ]
                    },
                    {
                        "task": "Complete consent page",
                        "match": "https://issuer.example/ui/consent*",
                        "commands": [
                            ["wait-element-visible", "id", "nazo-consent-approve", 30],
                            ["click", "id", "nazo-consent-approve"]
                        ]
                    }
                ]
            }],
            "nazo": {
                "openid4vc_role": "issuer",
                "client_auth_type": "private_key_jwt",
                "credential_dataset": {"name": "fixture"}
            }
        });
        let variant = BTreeMap::from([
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
            ("client_auth_type".to_owned(), "private_key_jwt".to_owned()),
        ]);
        let materialized = materialize_vci_config(
            "oid4vci-1_0-issuer-test-plan",
            &variant,
            config.clone(),
            "https://issuer.example",
            "https://suite.example",
            None,
            Some(&first_attestation),
            test_trust_anchor(),
        )
        .expect("VCI config");
        assert_eq!(
            materialized["vci"]["credential_issuer_url"],
            "https://issuer.example"
        );
        assert_eq!(
            materialized["vci"]["credential_configuration_id"],
            "eu.example.pid"
        );
        assert_eq!(materialized["nazo"]["credential_format"], "sd_jwt_vc");
        assert_eq!(materialized["nazo"]["openid4vc_role"], "issuer");
        assert_eq!(
            materialized["credential"]["trust_anchor_pem"],
            test_trust_anchor()
        );
        assert_eq!(
            materialized["credential"]["status_list_trust_anchor_pem"],
            test_trust_anchor()
        );
        assert!(
            materialized["vci"]["key_attestation_jwks"]["keys"][0]["d"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        let reject = &materialized["override"]["fapi2-security-profile-final-user-rejects-authentication"]
            ["browser"];
        let reject_text = serde_json::to_string(reject).expect("reject override");
        assert!(!reject_text.contains("nazo-consent-approve"));
        assert_eq!(reject_text.matches("nazo-consent-deny").count(), 2);
        let par = &materialized["override"]["fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"]
            ["browser"];
        assert_eq!(par[0]["match-limit"], 1);
        let first_text = serde_json::to_string(&par[0]).expect("first authorization");
        assert!(!first_text.contains("\"text\""));
        assert!(!first_text.contains("\"click\""));
        assert!(par[1].get("match-limit").is_none());
        let second_text = serde_json::to_string(&par[1]).expect("second authorization");
        assert!(second_text.contains("nazo-login-email"));
        assert!(second_text.contains("nazo-login-submit"));

        let rematerialized = materialize_vci_config(
            "oid4vci-1_0-issuer-test-plan",
            &variant,
            materialized.clone(),
            "https://issuer.example",
            "https://suite.example",
            None,
            Some(&first_attestation),
            test_trust_anchor(),
        )
        .expect("identical Suite overrides are idempotent");
        assert_eq!(rematerialized["override"], materialized["override"]);

        let mut conflicting_override = config.clone();
        conflicting_override["override"] = serde_json::json!({
            "fapi2-security-profile-final-user-rejects-authentication": {"browser": []}
        });
        assert_eq!(
            materialize_vci_config(
                "oid4vci-1_0-issuer-test-plan",
                &variant,
                conflicting_override,
                "https://issuer.example",
                "https://suite.example",
                None,
                Some(&first_attestation),
                test_trust_anchor(),
            )
            .expect_err("conflicting Suite browser override must fail"),
            MaterializerError::InvalidField("override.browser")
        );

        let mut conflicting_url = config.clone();
        conflicting_url["vci"]["credential_issuer_url"] =
            serde_json::json!("https://other.example");
        assert_eq!(
            materialize_vci_config(
                "oid4vci-1_0-issuer-test-plan",
                &variant,
                conflicting_url,
                "https://issuer.example",
                "https://suite.example",
                None,
                Some(&first_attestation),
                test_trust_anchor(),
            )
            .expect_err("conflicting issuer must fail"),
            MaterializerError::InvalidField("vci.credential_issuer_url")
        );

        let mut conflicting_format = config;
        conflicting_format["nazo"]["credential_format"] = serde_json::json!("mdoc");
        assert_eq!(
            materialize_vci_config(
                "oid4vci-1_0-issuer-test-plan",
                &variant,
                conflicting_format,
                "https://issuer.example",
                "https://suite.example",
                None,
                Some(&first_attestation),
                test_trust_anchor(),
            )
            .expect_err("conflicting format must fail"),
            MaterializerError::InvalidField("nazo.credential_format")
        );

        let conflicting_anchor = serde_json::json!({
            "alias": "nazo-vci-run",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "credential": {"trust_anchor_pem": "different"}
        });
        assert_eq!(
            materialize_vci_config(
                "oid4vci-1_0-issuer-test-plan",
                &variant,
                conflicting_anchor,
                "https://issuer.example",
                "https://suite.example",
                None,
                Some(&first_attestation),
                test_trust_anchor(),
            )
            .expect_err("a second credential trust source must fail"),
            MaterializerError::InvalidField("credential.trust_anchor")
        );
    }

    #[test]
    fn vci_dataset_authority_is_copied_into_the_onboarding_bundle() {
        let config = serde_json::json!({
            "alias": "nazo-vci-dataset",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {
                "openid4vc_role": "issuer",
                "credential_format": "sd_jwt_vc",
                "credential_dataset": {"given_name": "Fixture", "age": 42}
            }
        });
        let descriptor = descriptor_with_openid4vc_plan(
            "oid4vci-1_0-issuer-test-plan",
            BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]),
            config,
        );
        let expected = descriptor
            .openid4vc_credential_datasets
            .get("eu.example.pid")
            .cloned()
            .expect("dataset authority");
        let (_, bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let value: Value = serde_json::from_slice(bundle.bytes().as_bytes()).expect("bundle");
        assert_eq!(
            value["openid4vc_credential_datasets"]["eu.example.pid"],
            expected
        );
    }

    #[test]
    fn vci_dataset_authority_rejects_missing_extra_and_conflicting_entries() {
        let config = serde_json::json!({
            "alias": "nazo-vci-dataset",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {
                "openid4vc_role": "issuer",
                "credential_format": "sd_jwt_vc",
                "credential_dataset": {"given_name": "Fixture"}
            }
        });
        let make_descriptor = || {
            descriptor_with_openid4vc_plan(
                "oid4vci-1_0-issuer-test-plan",
                BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]),
                config.clone(),
            )
        };
        let mut missing = make_descriptor();
        missing.openid4vc_credential_datasets.clear();
        assert_eq!(
            DescriptorMaterializer::prepare(
                missing,
                "https://issuer.example",
                &suite(),
                request_jti(),
                test_trust_anchor()
            )
            .err()
            .expect("missing dataset must fail"),
            MaterializerError::InvalidField("openid4vc_credential_datasets")
        );

        let mut extra = make_descriptor();
        extra.openid4vc_credential_datasets.insert(
            "unused.configuration".to_owned(),
            serde_json::json!({"given_name":"Unused"}),
        );
        assert_eq!(
            DescriptorMaterializer::prepare(
                extra,
                "https://issuer.example",
                &suite(),
                request_jti(),
                test_trust_anchor()
            )
            .err()
            .expect("extra dataset must fail"),
            MaterializerError::InvalidField("openid4vc_credential_datasets")
        );

        let mut conflicting = make_descriptor();
        conflicting.openid4vc_credential_datasets.insert(
            "eu.example.pid".to_owned(),
            serde_json::json!({"given_name":"Different"}),
        );
        assert_eq!(
            DescriptorMaterializer::prepare(
                conflicting,
                "https://issuer.example",
                &suite(),
                request_jti(),
                test_trust_anchor()
            )
            .err()
            .expect("conflicting dataset must fail"),
            MaterializerError::InvalidField("nazo.credential_dataset")
        );
    }

    #[test]
    fn vci_dataset_authority_rejects_private_or_empty_claims() {
        let config = serde_json::json!({
            "alias": "nazo-vci-dataset",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {"openid4vc_role": "issuer", "credential_format": "sd_jwt_vc"}
        });
        let mut private = descriptor_with_openid4vc_plan(
            "oid4vci-1_0-issuer-test-plan",
            BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]),
            config.clone(),
        );
        private.openid4vc_credential_datasets.insert(
            "eu.example.pid".to_owned(),
            serde_json::json!({"private_key": "not-a-public-claim"}),
        );
        assert_eq!(
            DescriptorMaterializer::prepare(
                private,
                "https://issuer.example",
                &suite(),
                request_jti(),
                test_trust_anchor()
            )
            .err()
            .expect("private dataset must fail"),
            MaterializerError::EmbeddedSecret
        );

        let mut empty = descriptor_with_openid4vc_plan(
            "oid4vci-1_0-issuer-test-plan",
            BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]),
            config,
        );
        empty
            .openid4vc_credential_datasets
            .insert("eu.example.pid".to_owned(), serde_json::json!({}));
        assert_eq!(
            DescriptorMaterializer::prepare(
                empty,
                "https://issuer.example",
                &suite(),
                request_jti(),
                test_trust_anchor()
            )
            .err()
            .expect("empty dataset must fail"),
            MaterializerError::InvalidField("openid4vc_credential_datasets")
        );
    }

    #[test]
    fn pre_authorized_vci_gets_a_fresh_six_digit_tx_code_in_private_matrix_only() {
        let variant = BTreeMap::from([
            ("fapi_profile".to_owned(), "vci".to_owned()),
            ("client_auth_type".to_owned(), "private_key_jwt".to_owned()),
            (
                "vci_grant_type".to_owned(),
                "pre_authorization_code".to_owned(),
            ),
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
            (
                "vci_authorization_code_flow_variant".to_owned(),
                "issuer_initiated".to_owned(),
            ),
        ]);
        let config = serde_json::json!({
            "alias": "nazo-vci-preauth",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {
                "openid4vc_role": "issuer",
                "client_auth_type": "private_key_jwt",
                "credential_format": "sd_jwt_vc"
            }
        });
        let descriptor =
            descriptor_with_openid4vc_plan("oid4vci-1_0-issuer-test-plan", variant, config);
        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("preauth prepare");
        let tx_code = prepared.tx_code().expect("run-scoped tx code");
        assert_eq!(tx_code.len(), 6);
        assert!(tx_code.bytes().all(|byte| byte.is_ascii_digit()));
        let bundle_value: Value =
            serde_json::from_slice(bundle.bytes().as_bytes()).expect("bundle");
        assert!(bundle_value["applicant"].is_object());
        assert!(bundle_value.get("static_tx_code").is_none());
        assert!(bundle_value.get("tx_code").is_none());
        assert!(!bundle_value.to_string().contains(tx_code.as_str()));

        let output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "actual-client".to_owned())]),
        )
        .expect("output");
        let matrix = DescriptorMaterializer::finalize(prepared, output).expect("finalize");
        assert_eq!(
            matrix.matrix().document.groups[0].plans[0].config["vci"]["static_tx_code"],
            tx_code.as_str()
        );
    }

    #[test]
    fn two_pre_authorized_runs_do_not_reuse_tx_code_or_bundle_digest() {
        let variant = BTreeMap::from([
            (
                "vci_grant_type".to_owned(),
                "pre_authorization_code".to_owned(),
            ),
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
        ]);
        let config = serde_json::json!({
            "alias": "nazo-vci-preauth",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {"openid4vc_role": "issuer", "credential_format": "sd_jwt_vc"}
        });
        let descriptor =
            descriptor_with_openid4vc_plan("oid4vci-1_0-issuer-test-plan", variant, config);
        let (first, first_bundle) = DescriptorMaterializer::prepare(
            descriptor.clone(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("first prepare");
        let (second, second_bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            "request-fedcba9876543210fedcba9876543210",
            test_trust_anchor(),
        )
        .expect("second prepare");
        assert_ne!(first_bundle.digest(), second_bundle.digest());
        assert!(first.tx_code().is_some_and(|value| value.len() == 6));
        assert!(second.tx_code().is_some_and(|value| value.len() == 6));
    }

    #[test]
    fn non_pre_authorized_vci_rejects_descriptor_static_tx_code() {
        let variant = BTreeMap::from([
            ("vci_grant_type".to_owned(), "authorization_code".to_owned()),
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
        ]);
        let config = serde_json::json!({
            "alias": "nazo-vci-authcode",
            "vci": {
                "credential_configuration_id": "eu.example.pid",
                "static_tx_code": "123456"
            },
            "nazo": {"openid4vc_role": "issuer", "credential_format": "sd_jwt_vc"}
        });
        let descriptor = descriptor_with_openid4vc_plan(
            "oid4vci-1_0-issuer-test-plan",
            variant.clone(),
            config.clone(),
        );
        let error = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .err()
        .expect("static tx code must fail");
        assert_eq!(error, MaterializerError::InvalidField("vci.static_tx_code"));

        let mut static_key = config;
        static_key["vci"]
            .as_object_mut()
            .expect("vci object")
            .remove("static_tx_code");
        static_key["vci"]["key_attestation_jwks"] = serde_json::json!({"keys": []});
        let descriptor =
            descriptor_with_openid4vc_plan("oid4vci-1_0-issuer-test-plan", variant, static_key);
        let error = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .err()
        .expect("descriptor-supplied proof key must fail");
        assert_eq!(
            error,
            MaterializerError::InvalidField("vci.key_attestation_jwks")
        );
    }

    #[test]
    fn vci_haip_materializes_run_attestation_only_in_suite_config() {
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let config = serde_json::json!({
            "alias": "nazo-vci-haip",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {
                "openid4vc_role": "issuer",
                "client_auth_type": "client_attestation",
                "credential_format": "sd_jwt_vc"
            }
        });
        let descriptor =
            descriptor_with_openid4vc_plan("oid4vci-1_0-issuer-haip-test-plan", variant, config);
        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("HAIP prepare");
        let bundle_text = String::from_utf8(bundle.bytes().as_bytes().to_vec()).expect("bundle");
        let bundle_value: Value = serde_json::from_str(&bundle_text).expect("bundle json");
        let trust = &bundle_value["openid4vc_conformance_trust"];
        assert_eq!(trust["schema"], 1);
        assert_eq!(trust["client_attestation_issuer"], "https://suite.example/");
        assert_eq!(
            trust["credential_trust_anchor_pem"],
            combined_test_trust_anchor()
        );
        assert_eq!(
            trust["credential_trust_anchor_pem"]
                .as_str()
                .expect("combined trust anchor")
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            2
        );
        assert!(
            trust["client_attestation_jwks"]["keys"][0]["kid"]
                .as_str()
                .is_some()
        );
        assert!(
            trust["key_attestation_jwks"]["keys"][0]["kid"]
                .as_str()
                .is_some()
        );
        assert!(!bundle_text.contains("\"d\""));
        assert!(!bundle_text.contains("PRIVATE KEY"));
        let output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "actual-client".to_owned())]),
        )
        .expect("output");
        let matrix = DescriptorMaterializer::finalize(prepared, output).expect("finalize");
        let config = &matrix.matrix().document.groups[0].plans[0].config;
        assert_eq!(config["nazo"]["client_auth_type"], "client_attestation");
        assert!(
            config["client_attestation"]["trust_anchor"]
                .as_str()
                .is_some_and(|value| value.contains("BEGIN CERTIFICATE"))
        );
        assert!(
            config["client_attestation"]["attester_jwks"]["keys"][0]["d"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            config["vci"]["key_attestation_jwks"]["keys"][0]["d"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(
            trust["client_attestation_jwks"]["keys"][0]["kid"],
            config["client_attestation"]["attester_jwks"]["keys"][0]["kid"]
        );
        assert_eq!(
            trust["key_attestation_jwks"]["keys"][0]["kid"],
            config["vci"]["key_attestation_jwks"]["keys"][0]["kid"]
        );
        assert_eq!(
            config["client_attestation"]["issuer"],
            "https://suite.example/"
        );
    }

    #[test]
    fn vci_conformance_trust_keys_are_fresh_public_and_anchor_bound() {
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let config = serde_json::json!({
            "alias": "nazo-vci-trust",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {
                "openid4vc_role": "issuer",
                "client_auth_type": "private_key_jwt",
                "credential_format": "sd_jwt_vc"
            }
        });
        let descriptor =
            descriptor_with_openid4vc_plan("oid4vci-1_0-issuer-test-plan", variant, config);
        let (first_prepared, first_bundle) = DescriptorMaterializer::prepare(
            descriptor.clone(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("first prepare");
        let (second_prepared, second_bundle) = DescriptorMaterializer::prepare(
            descriptor,
            "https://issuer.example",
            &suite(),
            "request-fedcba9876543210fedcba9876543210",
            test_trust_anchor(),
        )
        .expect("second prepare");
        let first_value: Value =
            serde_json::from_slice(first_bundle.bytes().as_bytes()).expect("first bundle");
        let second_value: Value =
            serde_json::from_slice(second_bundle.bytes().as_bytes()).expect("second bundle");
        let first_trust = &first_value["openid4vc_conformance_trust"];
        let second_trust = &second_value["openid4vc_conformance_trust"];
        assert_eq!(
            first_trust["credential_trust_anchor_pem"],
            combined_test_trust_anchor()
        );
        assert_ne!(
            first_trust["client_attestation_jwks"],
            second_trust["client_attestation_jwks"]
        );
        assert_ne!(
            first_trust["key_attestation_jwks"],
            second_trust["key_attestation_jwks"]
        );
        let first_bundle_text = first_bundle.bytes().as_bytes();
        let second_bundle_text = second_bundle.bytes().as_bytes();
        assert!(
            !first_bundle_text
                .windows(3)
                .any(|window| window == b"\"d\"")
        );
        assert!(
            !second_bundle_text
                .windows(3)
                .any(|window| window == b"\"d\"")
        );
        assert!(!String::from_utf8_lossy(first_bundle_text).contains("PRIVATE KEY"));
        assert!(!String::from_utf8_lossy(second_bundle_text).contains("PRIVATE KEY"));

        let first_output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            first_prepared.request_jti(),
            first_prepared.matrix_sha256(),
            first_prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "first-client".to_owned())]),
        )
        .expect("first output");
        let first_matrix =
            DescriptorMaterializer::finalize(first_prepared, first_output).expect("first finalize");
        let first_config = &first_matrix.matrix().document.groups[0].plans[0].config;
        assert_eq!(
            first_trust["key_attestation_jwks"]["keys"][0]["kid"],
            first_config["vci"]["key_attestation_jwks"]["keys"][0]["kid"]
        );

        let second_output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f42",
            second_prepared.request_jti(),
            second_prepared.matrix_sha256(),
            second_prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "second-client".to_owned())]),
        )
        .expect("second output");
        let second_matrix = DescriptorMaterializer::finalize(second_prepared, second_output)
            .expect("second finalize");
        let second_config = &second_matrix.matrix().document.groups[0].plans[0].config;
        assert_eq!(
            second_trust["key_attestation_jwks"]["keys"][0]["kid"],
            second_config["vci"]["key_attestation_jwks"]["keys"][0]["kid"]
        );
    }

    #[test]
    fn signed_vp_binds_onboarding_trust_anchor_and_url_query_rejects_it() {
        let signed = descriptor_with_openid4vp_plan(
            "request_uri_signed",
            serde_json::json!({
                "alias": "nazo-vp-signed",
                "client": {"client_id": "{{target.host}}"}
            }),
        );
        let (prepared, _bundle) = DescriptorMaterializer::prepare(
            signed,
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("signed VP prepare");
        let output = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            prepared.bundle_digest(),
            BTreeMap::from([("web".to_owned(), "actual-client".to_owned())]),
        )
        .expect("output");
        let matrix = DescriptorMaterializer::finalize(prepared, output).expect("signed finalize");
        assert_eq!(
            matrix.matrix().document.groups[0].plans[0].config["client"]["request_object_trust_anchor_pem"],
            test_trust_anchor()
        );

        let query_variant = BTreeMap::from([("request_method".to_owned(), "url_query".to_owned())]);
        let query_config = serde_json::json!({
            "alias": "nazo-vp-query",
            "client": {
                "request_object_trust_anchor_pem": test_trust_anchor()
            }
        });
        assert_eq!(
            materialize_vp_config(
                "oid4vp-1final-verifier-test-plan",
                &query_variant,
                query_config,
                test_trust_anchor(),
            )
            .unwrap_err(),
            MaterializerError::InvalidField("client.request_object_trust_anchor_pem")
        );
    }

    #[test]
    fn vp_haip_without_transport_variant_still_binds_request_trust_anchor() {
        let config = serde_json::json!({
            "alias": "nazo-vp-haip",
            "client": {"client_id": "issuer.example"}
        });
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let materialized = materialize_vp_config(
            "oid4vp-1final-verifier-haip-test-plan",
            &variant,
            config,
            test_trust_anchor(),
        )
        .expect("VP HAIP config");
        assert_eq!(
            materialized["client"]["request_object_trust_anchor_pem"],
            test_trust_anchor()
        );
    }

    #[test]
    fn missing_extra_and_cross_run_mappings_are_rejected() {
        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let missing = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            bundle.digest(),
            BTreeMap::new(),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, missing).unwrap_err(),
            MaterializerError::MissingClientMapping
        );

        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let extra = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            bundle.digest(),
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

        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let wrong_matrix = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            bundle.digest(),
            BTreeMap::from([("web".to_owned(), "actual".to_owned())]),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, wrong_matrix).unwrap_err(),
            MaterializerError::MatrixDigestMismatch
        );

        let (prepared, _bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let wrong_bundle = onboarding_output(
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f40",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            BTreeMap::from([("web".to_owned(), "actual".to_owned())]),
        )
        .expect("output");
        assert_eq!(
            DescriptorMaterializer::finalize(prepared, wrong_bundle).unwrap_err(),
            MaterializerError::BundleDigestMismatch
        );

        let (prepared, bundle) = DescriptorMaterializer::prepare(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
            test_trust_anchor(),
        )
        .expect("prepare");
        let invalid_lease = onboarding_output(
            "not-a-uuid",
            prepared.request_jti(),
            prepared.matrix_sha256(),
            bundle.digest(),
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
                test_trust_anchor(),
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
