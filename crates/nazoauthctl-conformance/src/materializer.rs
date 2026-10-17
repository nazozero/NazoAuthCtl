//! Tenant-resource materialization for NazoAuth's conformance matrix.
//!
//! Preparation creates run-scoped private material and a deployment-bound
//! resource manifest. Finalization accepts only the typed result of the
//! controller-signed Apply operation for that exact manifest before
//! substituting returned resource identifiers into the Suite configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{
    ControlOutcome, ControlResult, ControlResultData, Openid4vcTrustPolicy, TenantResourceIdentity,
    TenantResourceKind, TenantResourceMapping, validate_openid4vc_trust_policy,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::matrix::{
    MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix, zeroize_json_value,
};
use crate::origin::Origin;

/// Version of the short-lived, controller-private NazoAuth resource
/// manifest emitted by this materializer.  It intentionally mirrors the
/// server's ordinary tenant-resource apply envelope rather than the Suite
/// matrix or artifact schemas.
pub const TENANT_RESOURCE_MANIFEST_SCHEMA_VERSION: u32 = 1;

const MAX_TENANT_RESOURCE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_TENANT_RESOURCE_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_TENANT_RESOURCE_PAYLOAD_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_TENANT_RESOURCE_ID_BYTES: usize = 128;
const MAX_TENANT_RESOURCE_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_TENANT_RESOURCE_CONFIGURATION_ID_BYTES: usize = 255;

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
pub(crate) use descriptor::artifact_placeholder_is_valid;
pub use descriptor::{
    CryptoPolicy, DESCRIPTOR_SCHEMA_VERSION, DescriptorGroup, DescriptorPlan, DescriptorSource,
    DescriptorVariant, MAX_DESCRIPTOR_BYTES, MatrixDescriptor, RoleRequirement,
};
use descriptor::{
    descriptor_requires_reference, extract_single_mdoc_trust_anchor_from_bundle, parse_placeholder,
    referenced_openid4vc_credential_dataset_ids, validate_descriptor, validate_digest,
    validate_single_mdoc_trust_anchor,
};
use template::{
    materialize_registration_template, materialize_value, materialize_vci_config,
    materialize_vp_config, validate_target_issuer,
};

struct MaterializationBindings {
    applicant_id: String,
    openid4vc_credential_trust_anchor_pem: String,
    openid4vc_request_object_trust_anchor_pem: String,
    clients: BTreeMap<String, String>,
}

/// Preparation state is deliberately neither serializable nor printable.
/// Private fields own their zeroizing buffers; each client clears its private
/// request JSON on drop. Public metadata is retained until finalize completes.
pub struct PreparedMaterialization {
    descriptor: MatrixDescriptor,
    target_issuer: String,
    suite_base_url: String,
    request_jti: String,
    matrix_sha256: String,
    applicant_email: Zeroizing<String>,
    applicant_password: Zeroizing<String>,
    tx_code: Option<Zeroizing<String>>,
    attestation: Option<GeneratedAttestationMaterial>,
    dynamic_registration_initial_access_token: Option<Zeroizing<String>>,
    clients: BTreeMap<String, PreparedClient>,
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

    /// Return a zeroizing run-scoped pre-authorized-code clone for the issuer
    /// driver. It is neither serializable nor printable; callers must not
    /// persist or log it.
    pub fn tx_code(&self) -> Option<Zeroizing<String>> {
        self.tx_code
            .as_ref()
            .map(|value| Zeroizing::new(value.to_string()))
    }

    #[cfg(test)]
    fn expected_clients(&self) -> BTreeSet<String> {
        self.clients.keys().cloned().collect()
    }

    pub fn applicant_email(&self) -> &str {
        &self.applicant_email
    }

    /// Return a zeroizing clone for the run-scoped hosted authorization
    /// session. The password remains neither serializable nor printable and
    /// is only copied across this explicit in-memory boundary.
    pub fn applicant_password(&self) -> Zeroizing<String> {
        Zeroizing::new(self.applicant_password.to_string())
    }

    pub fn suite_base_url(&self) -> &str {
        &self.suite_base_url
    }

    /// Materialize the ordinary NazoAuth resource apply manifest for this
    /// prepared run.  The returned bytes are controller-private: they carry
    /// the temporary applicant password and, for secret-auth clients, the
    /// generated supplied secret.  Client/wallet private keys and Suite
    /// tokens are deliberately absent; they remain in the existing
    /// controller/private paths used by the Suite runner.
    ///
    /// Resource identifiers are independent of Suite plan/module/origin
    /// names.  mTLS and dataset payloads refer only to the corresponding
    /// ordinary resource identifiers, so the server can enforce dependency
    /// ownership without receiving Suite metadata.  `run_namespace` is the
    /// canonical request JTI: explicitly binding it here makes exact recovery
    /// deterministic while ensuring a later run can never reuse an earlier
    /// run's cleanup selectors.
    pub fn tenant_resource_manifest(
        &self,
        run_namespace: &str,
    ) -> Result<TenantResourceManifest, MaterializerError> {
        if run_namespace != self.request_jti {
            return Err(MaterializerError::RequestMismatch);
        }
        let run_suffix = run_namespace_suffix(run_namespace);
        let user_resource_id = run_scoped_resource_id("user", "applicant", &run_suffix);
        let trust_policy_resource_id = self
            .attestation
            .as_ref()
            .map(|_| run_scoped_resource_id("openid4vc-trust-policy", "provider", &run_suffix));
        let username = self
            .applicant_email
            .split_once('@')
            .map(|(local, _)| local)
            .ok_or(MaterializerError::InvalidField("generated.applicant_email"))?;
        let applicant_profile_origin = self.target_issuer.trim_end_matches('/');

        let mut resources = Vec::with_capacity(
            2 + 2 * self.clients.len() + self.descriptor.openid4vc_credential_datasets.len(),
        );
        let mut payload_total = 0usize;

        push_manifest_resource(
            &mut resources,
            &mut payload_total,
            TenantResourceKind::User,
            user_resource_id.clone(),
            serde_json::json!({
                "username": username,
                "email": self.applicant_email.as_str(),
                "password": self.applicant_password.as_str(),
                "email_verified": true,
                "profile": {
                    "display_name": "OIDF Conformance User",
                    "given_name": "OIDF",
                    "family_name": "Conformance",
                    "middle_name": "Test",
                    "nickname": "oidf-user",
                    "profile_url": format!("{applicant_profile_origin}/oidf/profile"),
                    "avatar_url": format!("{applicant_profile_origin}/oidf/avatar.png"),
                    "website_url": format!("{applicant_profile_origin}/"),
                    "gender": "unspecified",
                    "birthdate": "1980-01-01",
                    "zoneinfo": "UTC",
                    "locale": "en-US",
                    "address_formatted": "123 Conformance Way, Test City, CA 94105, US",
                    "address_street_address": "123 Conformance Way",
                    "address_locality": "Test City",
                    "address_region": "CA",
                    "address_postal_code": "94105",
                    "address_country": "US",
                    "phone_number": "+12025550100",
                    "phone_number_verified": true,
                },
            }),
        )?;

        for (logical_client_id, client) in &self.clients {
            let client_resource_id =
                run_scoped_resource_id("oauth-client", logical_client_id, &run_suffix);
            let supplied_secret =
                (!client.client_secret.is_empty()).then_some(client.client_secret.as_str());
            push_manifest_resource(
                &mut resources,
                &mut payload_total,
                TenantResourceKind::OauthClient,
                client_resource_id.clone(),
                serde_json::json!({
                    "request": client.request,
                    "supplied_secret": supplied_secret,
                    "trust_policy_resource_id": trust_policy_resource_id,
                }),
            )?;

            if registration_requires_mtls(&client.request) {
                validate_manifest_certificate_pem(
                    client.mtls_ca_certificate.as_str(),
                    "generated.mtls.ca_cert",
                )?;
                push_manifest_resource(
                    &mut resources,
                    &mut payload_total,
                    TenantResourceKind::MtlsTrustAnchor,
                    run_scoped_resource_id("mtls-trust-anchor", logical_client_id, &run_suffix),
                    serde_json::json!({
                        "client_resource_id": client_resource_id,
                        "certificate_pem": client.mtls_ca_certificate.as_str(),
                    }),
                )?;
            }
        }

        for (configuration_id, claims) in &self.descriptor.openid4vc_credential_datasets {
            validate_bounded_text(
                configuration_id,
                MAX_TENANT_RESOURCE_CONFIGURATION_ID_BYTES,
                "openid4vc_credential_datasets",
            )?;
            push_manifest_resource(
                &mut resources,
                &mut payload_total,
                TenantResourceKind::Openid4vcDataset,
                run_scoped_resource_id("openid4vc-dataset", configuration_id, &run_suffix),
                serde_json::json!({
                    "user_resource_id": user_resource_id,
                    "configuration_id": configuration_id,
                    "claims": materialize_openid4vc_dataset_claims(configuration_id, claims),
                }),
            )?;
        }

        if let (Some(attestation), Some(trust_policy_resource_id)) =
            (&self.attestation, trust_policy_resource_id)
        {
            let public_material = Openid4vcTrustPolicy {
                schema: 1,
                client_attestation_issuer: format!(
                    "{}/",
                    self.suite_base_url.trim_end_matches('/')
                ),
                client_attestation_jwks: attestation.attester_public_jwks.clone(),
                key_attestation_jwks: attestation.key_attestation_public_jwks.clone(),
                wallet_authorization_origins: vec![self.suite_base_url.clone()],
                credential_trust_anchor_pem: combine_openid4vc_credential_trust_anchors(
                    attestation.trust_anchor_pem.as_str(),
                    &self.descriptor.openid4vc_suite_mdoc_trust_anchor_pem,
                )?,
            };
            validate_openid4vc_trust_policy(&public_material).map_err(|_| {
                MaterializerError::InvalidField("tenant_resource_manifest.openid4vc_trust_policy")
            })?;
            let trust_payload =
                serde_json::to_value(public_material).map_err(|_| MaterializerError::Encoding)?;
            push_manifest_resource(
                &mut resources,
                &mut payload_total,
                TenantResourceKind::Openid4vcTrustPolicy,
                trust_policy_resource_id,
                trust_payload,
            )?;
        }

        TenantResourceManifest::from_resources(resources)
    }
}

fn materialize_openid4vc_dataset_claims(configuration_id: &str, claims: &Value) -> Value {
    let mut claims = claims.clone();
    if configuration_id != "org.iso.18013.5.1.mDL" {
        return claims;
    }
    let Some(elements) = claims
        .get_mut("org.iso.18013.5.1")
        .and_then(Value::as_object_mut)
    else {
        return claims;
    };
    for name in ["portrait", "signature_usual_mark"] {
        if let Some(Value::String(value)) = elements.get_mut(name) {
            *value = URL_SAFE_NO_PAD.encode(value.as_bytes());
        }
    }
    claims
}

struct PreparedClient {
    client_secret: Zeroizing<String>,
    rsa_private_jwks: Zeroizing<String>,
    rsa_public_jwks: String,
    ec_private_jwks: Zeroizing<String>,
    ec_public_jwks: String,
    mtls_ca_certificate: String,
    mtls_client_certificate: String,
    mtls_client_key: Zeroizing<String>,
    mtls_client_certificate_sha256: String,
    request: Value,
}

impl Drop for PreparedClient {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.request);
    }
}

/// Private bytes are zeroized and can only be written using the owner-only
/// atomic writer.  The bundle record below intentionally excludes private JWK
/// values and the mTLS private key.
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

/// One resource entry in a controller-private NazoAuth apply manifest.
///
/// `payload_base64url` is intentionally kept in a zeroizing wrapper: user
/// passwords and secret-auth client secrets are valid for this short-lived
/// management request, while client/wallet private keys and Suite tokens are
/// never materialized here.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceManifestResource {
    pub kind: TenantResourceKind,
    pub resource_id: String,
    pub payload_base64url: Zeroizing<String>,
    #[serde(skip)]
    digest: String,
}

impl std::fmt::Debug for TenantResourceManifestResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantResourceManifestResource")
            .field("kind", &self.kind)
            .field("resource_id", &self.resource_id)
            .field("payload_base64url", &"<redacted>")
            .field("digest", &self.digest)
            .finish()
    }
}

impl TenantResourceManifestResource {
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// NazoAuth TenantResourceManifest v1.
///
/// The serialized form is exactly the server's `ApplyManifest` wire shape:
/// `{ "schema": 1, "resources": [...] }`.  Raw bytes and resource identity
/// digests are retained separately so callers can bind the exact bytes to a
/// controller operation without introducing a second canonicalization rule.
pub struct TenantResourceManifest {
    pub schema: u32,
    pub resources: Vec<TenantResourceManifestResource>,
    bytes: SecureBytes,
    raw_sha256: String,
    identities: Vec<TenantResourceIdentity>,
    resource_manifest_sha256: String,
}

impl Serialize for TenantResourceManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Document<'a> {
            schema: u32,
            resources: &'a [TenantResourceManifestResource],
        }
        Document {
            schema: self.schema,
            resources: &self.resources,
        }
        .serialize(serializer)
    }
}

impl std::fmt::Debug for TenantResourceManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantResourceManifest")
            .field("schema", &self.schema)
            .field("resources", &self.resources)
            .field("raw_sha256", &self.raw_sha256)
            .field("resource_manifest_sha256", &self.resource_manifest_sha256)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl TenantResourceManifest {
    fn from_resources(
        mut resources: Vec<TenantResourceManifestResource>,
    ) -> Result<Self, MaterializerError> {
        resources.sort_by(|left, right| {
            (left.kind, &left.resource_id).cmp(&(right.kind, &right.resource_id))
        });
        let identities = resources
            .iter()
            .map(|resource| TenantResourceIdentity {
                kind: resource.kind,
                resource_id: resource.resource_id.clone(),
                digest: resource.digest.clone(),
            })
            .collect::<Vec<_>>();
        #[derive(Serialize)]
        struct Document<'a> {
            schema: u32,
            resources: &'a [TenantResourceManifestResource],
        }
        let document = Document {
            schema: TENANT_RESOURCE_MANIFEST_SCHEMA_VERSION,
            resources: &resources,
        };
        let bytes = serde_json::to_vec(&document).map_err(|_| MaterializerError::Encoding)?;
        if bytes.len() > MAX_TENANT_RESOURCE_MANIFEST_BYTES {
            return Err(MaterializerError::Oversize);
        }
        let resource_manifest_sha256 =
            nazo_operator_protocol::canonical_tenant_resource_manifest_sha256(&identities)
                .map_err(|_| {
                    MaterializerError::InvalidField("tenant_resource_manifest.resources")
                })?;
        let raw_sha256 = digest_hex(&bytes);
        Ok(Self {
            schema: TENANT_RESOURCE_MANIFEST_SCHEMA_VERSION,
            resources,
            bytes: SecureBytes(Zeroizing::new(bytes)),
            raw_sha256,
            identities,
            resource_manifest_sha256,
        })
    }

    pub fn bytes(&self) -> &SecureBytes {
        &self.bytes
    }

    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }

    /// Return the canonical digest of the identities touched by this private
    /// Apply manifest.  Incremental callers separately merge these identities
    /// with the enumerated baseline to compute the final active manifest.
    pub fn resource_manifest_sha256(&self) -> &str {
        &self.resource_manifest_sha256
    }

    pub fn resource_identities(&self) -> &[TenantResourceIdentity] {
        &self.identities
    }

    pub fn write_private(&self, path: &Path) -> Result<(), MaterializerError> {
        self.bytes.write_private(path)
    }
}

/// Typed result of one ordinary controller-signed tenant-resource Apply.
///
/// All fields are private so no unbound or wrong-operation result can reach
/// ordinary finalization. The operation identity is supplied by the
/// controller session that signed the operation; the result must echo its id
/// and request hash.
#[derive(Clone, Debug)]
pub struct TenantResourceApplyOutput {
    operation_id: String,
    request_hash: String,
    controller_kid: String,
    revision: u64,
    resource_manifest_sha256: String,
    resource_mappings: Vec<TenantResourceMapping>,
    delta_resources: Vec<TenantResourceIdentity>,
    final_active_resources: Vec<TenantResourceIdentity>,
}

impl TenantResourceApplyOutput {
    pub fn from_control_result(
        result: &ControlResult,
        expected_operation_id: &str,
        expected_request_hash: &str,
        controller_kid: &str,
        manifest: &TenantResourceManifest,
        final_active_resources: Vec<TenantResourceIdentity>,
    ) -> Result<Self, MaterializerError> {
        validate_public_id(expected_operation_id, "control operation ID", 256)?;
        validate_digest(expected_request_hash, "control operation request hash")?;
        validate_public_id(controller_kid, "controller key ID", 256)?;
        if result.operation_id != expected_operation_id
            || result.request_hash != expected_request_hash
            || result.outcome != ControlOutcome::Succeeded
        {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "apply binding",
            ));
        }
        let Some(ControlResultData::TenantResourceApply {
            revision,
            resources,
            resource_mappings,
            resource_manifest_sha256,
        }) = &result.result
        else {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "typed apply result",
            ));
        };

        let delta = collect_identity_map(manifest.resource_identities())?;
        let result_delta = collect_identity_map(resources)?;
        if result_delta != delta {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "delta resources",
            ));
        }
        let final_active = collect_identity_map(&final_active_resources)?;
        if delta
            .iter()
            .any(|(key, digest)| final_active.get(key) != Some(digest))
        {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "final active resources",
            ));
        }
        let final_manifest_sha256 =
            nazo_operator_protocol::canonical_tenant_resource_manifest_sha256(
                &final_active_resources,
            )
            .map_err(|_| {
                MaterializerError::TenantResourceResultMismatch("final active resources")
            })?;
        if *resource_manifest_sha256 != final_manifest_sha256 {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "final manifest digest",
            ));
        }

        validate_apply_mappings(resource_mappings, &delta)?;

        Ok(Self {
            operation_id: expected_operation_id.to_owned(),
            request_hash: expected_request_hash.to_owned(),
            controller_kid: controller_kid.to_owned(),
            revision: *revision,
            resource_manifest_sha256: resource_manifest_sha256.clone(),
            resource_mappings: resource_mappings.clone(),
            delta_resources: manifest.resource_identities().to_vec(),
            final_active_resources,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    pub fn controller_kid(&self) -> &str {
        &self.controller_kid
    }

    pub fn resource_manifest_sha256(&self) -> &str {
        &self.resource_manifest_sha256
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn resource_mappings(&self) -> &[TenantResourceMapping] {
        &self.resource_mappings
    }

    pub fn delta_resources(&self) -> &[TenantResourceIdentity] {
        &self.delta_resources
    }

    pub fn final_active_resources(&self) -> &[TenantResourceIdentity] {
        &self.final_active_resources
    }
}

fn collect_identity_map(
    resources: &[TenantResourceIdentity],
) -> Result<BTreeMap<(TenantResourceKind, &str), &str>, MaterializerError> {
    let mut seen_resource_ids = BTreeSet::new();
    let mut identities = BTreeMap::new();
    for resource in resources {
        validate_resource_id(&resource.resource_id)?;
        validate_digest(&resource.digest, "tenant_resource_identity.digest")?;
        if !seen_resource_ids.insert(resource.resource_id.as_str()) {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "duplicate resource identity",
            ));
        }
        identities.insert(
            (resource.kind, resource.resource_id.as_str()),
            resource.digest.as_str(),
        );
    }
    Ok(identities)
}

fn validate_apply_mappings(
    mappings: &[TenantResourceMapping],
    delta: &BTreeMap<(TenantResourceKind, &str), &str>,
) -> Result<(), MaterializerError> {
    let expected = delta
        .keys()
        .filter(|(kind, _)| {
            matches!(
                kind,
                TenantResourceKind::User | TenantResourceKind::OauthClient
            )
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut public_client_ids = BTreeSet::new();
    for mapping in mappings {
        validate_resource_id(&mapping.resource_id)?;
        if !actual.insert((mapping.kind, mapping.resource_id.as_str())) {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "duplicate mapping",
            ));
        }
        match mapping.kind {
            TenantResourceKind::User => {
                let id = Uuid::parse_str(&mapping.public_id).map_err(|_| {
                    MaterializerError::TenantResourceResultMismatch("applicant mapping")
                })?;
                if id.to_string() != mapping.public_id {
                    return Err(MaterializerError::TenantResourceResultMismatch(
                        "applicant mapping",
                    ));
                }
            }
            TenantResourceKind::OauthClient => {
                validate_public_id(&mapping.public_id, "OAuth client mapping", 512)?;
                if !public_client_ids.insert(mapping.public_id.as_str()) {
                    return Err(MaterializerError::DuplicateClientMapping);
                }
            }
            TenantResourceKind::MtlsTrustAnchor
            | TenantResourceKind::Openid4vcDataset
            | TenantResourceKind::Openid4vcTrustPolicy => {
                return Err(MaterializerError::TenantResourceResultMismatch(
                    "mapping kind",
                ));
            }
        }
    }
    if actual != expected {
        return Err(MaterializerError::TenantResourceResultMismatch(
            "mapping coverage",
        ));
    }
    Ok(())
}

fn push_manifest_resource(
    resources: &mut Vec<TenantResourceManifestResource>,
    payload_total: &mut usize,
    kind: TenantResourceKind,
    resource_id: String,
    mut payload: Value,
) -> Result<(), MaterializerError> {
    validate_resource_id(&resource_id)?;
    reject_manifest_private_or_suite_value(&payload)?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| MaterializerError::Encoding)?;
    if payload_bytes.len() > MAX_TENANT_RESOURCE_PAYLOAD_BYTES {
        return Err(MaterializerError::Oversize);
    }
    *payload_total += payload_bytes.len();
    if *payload_total > MAX_TENANT_RESOURCE_PAYLOAD_TOTAL_BYTES {
        return Err(MaterializerError::Oversize);
    }
    let digest = digest_hex(&payload_bytes);
    let payload_base64url = Zeroizing::new(URL_SAFE_NO_PAD.encode(&payload_bytes));
    zeroize_json_value(&mut payload);
    let mut payload_bytes = payload_bytes;
    payload_bytes.zeroize();
    resources.push(TenantResourceManifestResource {
        kind,
        resource_id,
        payload_base64url,
        digest,
    });
    Ok(())
}

fn run_namespace_suffix(run_namespace: &str) -> String {
    digest_hex(run_namespace.as_bytes())[..32].to_owned()
}

// Prefixes are fixed call-site constants; values come from the validated descriptor,
// and run_suffix is produced by run_namespace_suffix.
fn run_scoped_resource_id(prefix: &str, value: &str, run_suffix: &str) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || ".:+-".contains(character) {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let needs_hash_suffix = normalized != value;
    let normalized = normalized.trim_matches('-');
    let available_base_bytes = MAX_TENANT_RESOURCE_ID_BYTES - "-run-".len() - run_suffix.len();
    let base_length = prefix.len() + 1 + normalized.len() + if needs_hash_suffix { 17 } else { 0 };
    if base_length > available_base_bytes {
        format!(
            "{prefix}-{}-run-{run_suffix}",
            &digest_hex(value.as_bytes())[..32]
        )
    } else if needs_hash_suffix {
        format!(
            "{prefix}-{normalized}-{}-run-{run_suffix}",
            &digest_hex(value.as_bytes())[..16]
        )
    } else {
        format!("{prefix}-{normalized}-run-{run_suffix}")
    }
}

fn validate_resource_id(value: &str) -> Result<(), MaterializerError> {
    if value.is_empty()
        || value.len() > MAX_TENANT_RESOURCE_ID_BYTES
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:+-".contains(character))
    {
        return Err(MaterializerError::InvalidField(
            "tenant_resource_manifest.resource_id",
        ));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), MaterializerError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

fn validate_manifest_certificate_pem(
    value: &str,
    field: &'static str,
) -> Result<(), MaterializerError> {
    if value.is_empty()
        || value.len() > MAX_TENANT_RESOURCE_CERTIFICATE_BYTES
        || !value.is_ascii()
        || value.contains('\0')
        || value.contains("PRIVATE KEY")
        || value.matches("-----BEGIN CERTIFICATE-----").count() != 1
        || value.matches("-----END CERTIFICATE-----").count() != 1
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n'))
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

fn reject_manifest_private_or_suite_value(value: &Value) -> Result<(), MaterializerError> {
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(reject_manifest_private_or_suite_value),
        Value::Object(values) => {
            for (key, child) in values {
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "private_key"
                        | "private_key_pem"
                        | "private_jwk"
                        | "private_jwks"
                        | "client_key"
                        | "mtls_client_key"
                        | "d"
                        | "p"
                        | "q"
                        | "dp"
                        | "dq"
                        | "qi"
                        | "oth"
                        | "k"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "tx_code"
                        | "conformance_lease_id"
                        | "conformance_task_jti"
                        | "plan"
                        | "module"
                        | "suite"
                        | "origin"
                ) {
                    return Err(
                        if matches!(
                            lower.as_str(),
                            "conformance_lease_id" | "conformance_task_jti"
                        ) {
                            MaterializerError::InvalidField(
                                "tenant_resource_manifest.forbidden_field",
                            )
                        } else if matches!(lower.as_str(), "plan" | "module" | "suite" | "origin") {
                            MaterializerError::InvalidField(
                                "tenant_resource_manifest.suite_metadata",
                            )
                        } else {
                            MaterializerError::EmbeddedSecret
                        },
                    );
                }
                reject_manifest_private_or_suite_value(child)?;
            }
            Ok(())
        }
        Value::String(text) if text.contains("PRIVATE KEY") => {
            Err(MaterializerError::EmbeddedSecret)
        }
        _ => Ok(()),
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
    #[error("onboarding output contains duplicate actual clients")]
    DuplicateClientMapping,
    #[error("onboarding request identity does not match preparation")]
    RequestMismatch,
    #[error("onboarding matrix identity does not match preparation")]
    MatrixDigestMismatch,
    #[error("onboarding bundle identity does not match preparation")]
    BundleDigestMismatch,
    #[error("tenant resource control result does not match {0}")]
    TenantResourceResultMismatch(&'static str),
}

/// Cohesive provenance, target, run, and trust binding for materializing one
/// signed artifact Matrix.
#[derive(Clone, Copy)]
pub struct ArtifactMaterializationBinding<'a> {
    pub artifact_source_release: &'a str,
    pub artifact_source_digest: &'a str,
    pub raw_matrix_sha256: &'a str,
    pub target_issuer: &'a str,
    pub suite_origin: &'a Origin,
    pub request_jti: &'a str,
    /// Run-tenant RFC 7591 initial access token derived from the deployment
    /// root. Ordinary runs may expose it to a signed plan, but never persist it
    /// in the recovery journal.
    pub dynamic_registration_initial_access_token: Option<&'a str>,
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

    /// Prepare directly from the signed artifact Matrix.  The artifact is the
    /// sole authority for executable plans and public OpenID4VC inputs; this
    /// conversion only adapts its shared descriptor fields before invoking the
    /// existing descriptor validator and preparation pipeline.  The caller's
    /// raw Matrix digest is retained verbatim and is never replaced by a
    /// digest of a re-serialized descriptor.
    /// Prepare the tenant-resource path from the signed artifact Matrix.
    pub fn prepare_tenant_resources_from_artifact_matrix(
        matrix: &crate::artifact::OidfArtifactMatrix,
        binding: ArtifactMaterializationBinding<'_>,
    ) -> Result<PreparedMaterialization, MaterializerError> {
        let descriptor = Self::descriptor_from_artifact_matrix(
            matrix,
            binding.artifact_source_release,
            binding.artifact_source_digest,
            binding.raw_matrix_sha256,
        )?;
        // VP certificate profiles use signed matrix facts independently of the
        // subset of datasets provisioned into the credential issuer.
        let mdoc_issuing_country = matrix
            .openid4vc_credential_datasets
            .get("org.iso.18013.5.1.mDL")
            .and_then(|dataset| dataset.get("org.iso.18013.5.1"))
            .and_then(|namespace| namespace.get("issuing_country"))
            .and_then(Value::as_str);
        if matrix
            .groups
            .iter()
            .flat_map(|group| &group.plans)
            .any(|plan| {
                plan.variant.get("credential_format").map(String::as_str) == Some("iso_mdl")
            })
            && mdoc_issuing_country.is_none()
        {
            return Err(MaterializerError::InvalidField("mdoc issuing country"));
        }
        Self::prepare_materialization(
            descriptor,
            binding.target_issuer,
            binding.suite_origin,
            binding.request_jti,
            binding.dynamic_registration_initial_access_token,
            mdoc_issuing_country,
        )
    }

    fn descriptor_from_artifact_matrix(
        matrix: &crate::artifact::OidfArtifactMatrix,
        artifact_source_release: &str,
        artifact_source_digest: &str,
        raw_matrix_sha256: &str,
    ) -> Result<MatrixDescriptor, MaterializerError> {
        validate_digest(raw_matrix_sha256, "matrix_sha256")?;
        let mut descriptor = MatrixDescriptor {
            schema: DESCRIPTOR_SCHEMA_VERSION,
            source: DescriptorSource {
                release: artifact_source_release.to_owned(),
                digest: artifact_source_digest.to_owned(),
            },
            openid4vc_credential_datasets: BTreeMap::new(),
            openid4vc_suite_mdoc_trust_anchor_pem: matrix
                .openid4vc_suite_mdoc_trust_anchor_pem
                .clone(),
            groups: matrix
                .groups
                .iter()
                .map(|group| DescriptorGroup {
                    id: group.id.clone(),
                    profile: group.profile.clone(),
                    variant: DescriptorVariant {
                        id: group.variant.id.clone(),
                        values: group.variant.values.clone(),
                    },
                    required_roles: group.required_roles.clone(),
                    plans: group
                        .plans
                        .iter()
                        .map(|plan| DescriptorPlan {
                            id: plan.id.clone(),
                            plan: plan.plan.clone(),
                            config_template: plan.config_template.clone(),
                            variant: plan.variant.clone(),
                            expected_results: plan.expected_results.clone(),
                            required_roles: plan.required_roles.clone(),
                            secret_bindings: plan.secret_bindings.clone(),
                            crypto: plan.crypto.clone(),
                        })
                        .collect(),
                })
                .collect(),
            raw_sha256: Some(raw_matrix_sha256.to_owned()),
        };
        let referenced_datasets = referenced_openid4vc_credential_dataset_ids(&descriptor.groups)?;
        descriptor.openid4vc_credential_datasets = matrix
            .openid4vc_credential_datasets
            .iter()
            .filter(|(configuration_id, _)| referenced_datasets.contains(configuration_id.as_str()))
            .map(|(configuration_id, claims)| (configuration_id.clone(), claims.clone()))
            .collect();
        Ok(descriptor)
    }

    fn prepare_materialization(
        mut descriptor: MatrixDescriptor,
        target_issuer: &str,
        suite_origin: &Origin,
        request_jti: &str,
        dynamic_registration_initial_access_token: Option<&str>,
        mdoc_issuing_country: Option<&str>,
    ) -> Result<PreparedMaterialization, MaterializerError> {
        validate_target_issuer(target_issuer)?;
        validate_request_jti(request_jti)?;
        let matrix_sha256 = descriptor
            .raw_sha256
            .take()
            .ok_or(MaterializerError::InvalidField("matrix_sha256"))?;
        let registrations = validate_descriptor(&descriptor)?;
        let applicant_password = Zeroizing::new(random_secret(32));
        let applicant_email = Zeroizing::new(format!("oidf-{}@example.invalid", random_hex(16)));
        let tx_code = descriptor_requires_pre_authorized_vci(&descriptor)
            .then(|| Zeroizing::new(random_tx_code()));
        // Only VC plans consume the run's attestation keys and trust policy.
        let needs_attestation = descriptor.groups.iter().any(|group| {
            group
                .plans
                .iter()
                .any(|plan| plan.plan.starts_with("oid4vci-") || plan.plan.starts_with("oid4vp-"))
        });
        let issuing_country = descriptor
            .openid4vc_credential_datasets
            .get("org.iso.18013.5.1.mDL")
            .and_then(|dataset| dataset.get("org.iso.18013.5.1"))
            .and_then(|namespace| namespace.get("issuing_country"))
            .and_then(Value::as_str)
            .or(mdoc_issuing_country);
        if descriptor
            .openid4vc_credential_datasets
            .contains_key("org.iso.18013.5.1.mDL")
            && issuing_country.is_none()
        {
            return Err(MaterializerError::InvalidField(
                "openid4vc_credential_datasets.org.iso.18013.5.1.mDL.issuing_country",
            ));
        }
        let attestation = needs_attestation
            .then(|| generate_attestation_material(suite_origin.as_str(), issuing_country))
            .transpose()?;
        let mut clients = BTreeMap::new();
        for (logical_client_id, registration) in registrations {
            clients.insert(
                logical_client_id.to_owned(),
                PreparedClient::new(
                    logical_client_id,
                    &descriptor,
                    registration.policy,
                    registration.template,
                    target_issuer,
                    suite_origin.as_str(),
                    request_jti,
                )?,
            );
        }
        // These values are run-scoped credentials, not deployment profile
        // configuration.  Generate them only when the signed descriptor
        // actually references the credential. This keeps unrelated runs from
        // receiving a token and prevents a second run from reusing a DB-unique
        // deployment token.
        let needs_dynamic_token = descriptor_requires_reference(
            &descriptor,
            "generated.dynamic_registration_initial_access_token",
        );
        if needs_dynamic_token && dynamic_registration_initial_access_token.is_none() {
            return Err(MaterializerError::InvalidField(
                "dynamic_registration_initial_access_token",
            ));
        }
        let dynamic_registration_initial_access_token = if needs_dynamic_token {
            dynamic_registration_initial_access_token.map(|token| Zeroizing::new(token.to_owned()))
        } else {
            None
        };
        let prepared = PreparedMaterialization {
            descriptor,
            target_issuer: target_issuer.to_owned(),
            suite_base_url: suite_origin.as_str().to_owned(),
            request_jti: request_jti.to_owned(),
            matrix_sha256,
            applicant_email,
            applicant_password,
            tx_code,
            attestation,
            dynamic_registration_initial_access_token,
            clients,
        };
        Ok(prepared)
    }

    /// Finalize a Suite matrix from an ordinary tenant-resource Apply.
    pub fn finalize_tenant_resources(
        mut prepared: PreparedMaterialization,
        apply_output: TenantResourceApplyOutput,
        tenant_signing_certificate_chain_pem: impl Into<String>,
    ) -> Result<TenantResourceMaterializedMatrix, MaterializerError> {
        let tenant_signing_certificate_chain_pem = tenant_signing_certificate_chain_pem.into();
        let tenant_trust_anchor_pem = if prepared.attestation.is_some() {
            let tenant_trust_anchor_pem = extract_single_mdoc_trust_anchor_from_bundle(
                &tenant_signing_certificate_chain_pem,
                "openid4vc_request_object_trust_anchor_pem",
            )?;
            let deployment_der = validate_single_mdoc_trust_anchor(
                &tenant_trust_anchor_pem,
                "credential_trust_anchor_pem",
            )?;
            let suite_der = validate_single_mdoc_trust_anchor(
                &prepared.descriptor.openid4vc_suite_mdoc_trust_anchor_pem,
                "openid4vc_suite_mdoc_trust_anchor_pem",
            )?;
            if deployment_der == suite_der {
                return Err(MaterializerError::InvalidField(
                    "credential_trust_anchor_pem",
                ));
            }
            tenant_trust_anchor_pem
        } else {
            String::new()
        };

        let expected_manifest = prepared.tenant_resource_manifest(prepared.request_jti())?;
        if expected_manifest.resource_identities() != apply_output.delta_resources() {
            return Err(MaterializerError::TenantResourceResultMismatch(
                "prepared manifest",
            ));
        }

        let run_suffix = run_namespace_suffix(prepared.request_jti());
        let applicant_resource_id = run_scoped_resource_id("user", "applicant", &run_suffix);
        let trust_policy_resource_id =
            run_scoped_resource_id("openid4vc-trust-policy", "provider", &run_suffix);
        let trust_policy_identity = apply_output
            .delta_resources()
            .iter()
            .find(|resource| {
                resource.kind == TenantResourceKind::Openid4vcTrustPolicy
                    && resource.resource_id == trust_policy_resource_id
            })
            .cloned();

        let mappings = apply_output
            .resource_mappings()
            .iter()
            .map(|mapping| {
                (
                    (mapping.kind, mapping.resource_id.as_str()),
                    mapping.public_id.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let applicant_id = mappings
            .get(&(TenantResourceKind::User, applicant_resource_id.as_str()))
            .ok_or(MaterializerError::MissingClientMapping)?
            .to_string();
        let applicant_uuid = Uuid::parse_str(&applicant_id)
            .map_err(|_| MaterializerError::TenantResourceResultMismatch("applicant mapping"))?;
        let mut clients = BTreeMap::new();
        for logical_client_id in prepared.clients.keys() {
            let resource_id =
                run_scoped_resource_id("oauth-client", logical_client_id, &run_suffix);
            let public_id = mappings
                .get(&(TenantResourceKind::OauthClient, resource_id.as_str()))
                .ok_or(MaterializerError::MissingClientMapping)?;
            clients.insert(logical_client_id.clone(), (*public_id).to_owned());
        }

        let bindings = MaterializationBindings {
            applicant_id,
            openid4vc_credential_trust_anchor_pem: tenant_trust_anchor_pem.clone(),
            openid4vc_request_object_trust_anchor_pem: tenant_trust_anchor_pem,
            clients,
        };
        let matrix = materialize_matrix_document(&mut prepared, &bindings)?;
        Ok(TenantResourceMaterializedMatrix {
            matrix: Some(SelectedMatrix::from_materialized(
                matrix,
                prepared.matrix_sha256.clone(),
            )),
            matrix_sha256: prepared.matrix_sha256.clone(),
            operation_id: apply_output.operation_id,
            request_hash: apply_output.request_hash,
            controller_kid: apply_output.controller_kid,
            applied_revision: apply_output.revision,
            resource_manifest_sha256: apply_output.resource_manifest_sha256,
            applicant_id: applicant_uuid,
            clients: bindings.clients,
            trust_policy_identity,
        })
    }
}

fn materialize_matrix_document(
    prepared: &mut PreparedMaterialization,
    bindings: &MaterializationBindings,
) -> Result<MatrixDocument, MaterializerError> {
    let mut groups = Vec::with_capacity(prepared.descriptor.groups.len());
    for group in std::mem::take(&mut prepared.descriptor.groups) {
        let mut plans = Vec::with_capacity(group.plans.len());
        for plan in group.plans {
            let config = materialize_value(
                plan.config_template,
                &plan.secret_bindings,
                prepared,
                bindings,
            )?;
            let config = materialize_vci_config(
                &plan.plan,
                &plan.variant,
                config,
                &prepared.target_issuer,
                &prepared.suite_base_url,
                prepared.tx_code.as_ref().map(|value| value.as_str()),
                prepared.attestation.as_ref(),
                &bindings.openid4vc_credential_trust_anchor_pem,
            )?;
            let config = materialize_vp_config(
                &plan.plan,
                &plan.variant,
                config,
                &prepared.suite_base_url,
                &bindings.openid4vc_request_object_trust_anchor_pem,
                prepared.attestation.as_ref(),
            )?;
            plans.push(MatrixPlan {
                id: plan.id,
                plan: plan.plan,
                config,
                variant: plan.variant,
                expected_results: plan.expected_results,
            });
        }
        groups.push(MatrixGroup {
            id: group.id,
            profile: group.profile,
            variant: MatrixVariant {
                id: group.variant.id,
                values: group.variant.values,
            },
            plans,
        });
    }
    Ok(MatrixDocument {
        schema: crate::matrix::MATRIX_SCHEMA_VERSION,
        name: format!("nazoauth-{}", prepared.descriptor.source.release),
        groups,
    })
}

/// Secret-bearing matrix finalized through the typed controller result.
pub struct TenantResourceMaterializedMatrix {
    matrix: Option<SelectedMatrix>,
    matrix_sha256: String,
    operation_id: String,
    request_hash: String,
    controller_kid: String,
    applied_revision: u64,
    resource_manifest_sha256: String,
    applicant_id: Uuid,
    clients: BTreeMap<String, String>,
    trust_policy_identity: Option<TenantResourceIdentity>,
}

impl TenantResourceMaterializedMatrix {
    pub fn matrix(&self) -> &SelectedMatrix {
        self.matrix
            .as_ref()
            .expect("materialized matrix has not been transferred")
    }

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

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    pub fn controller_kid(&self) -> &str {
        &self.controller_kid
    }

    pub fn applied_revision(&self) -> u64 {
        self.applied_revision
    }

    pub fn resource_manifest_sha256(&self) -> &str {
        &self.resource_manifest_sha256
    }

    pub fn applicant_id(&self) -> &Uuid {
        &self.applicant_id
    }

    pub fn clients(&self) -> &BTreeMap<String, String> {
        &self.clients
    }

    pub fn trust_policy_identity(&self) -> Option<&TenantResourceIdentity> {
        self.trust_policy_identity.as_ref()
    }
}

impl std::fmt::Debug for TenantResourceMaterializedMatrix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantResourceMaterializedMatrix")
            .field("matrix_sha256", &self.matrix_sha256)
            .field("operation_id", &self.operation_id)
            .field("request_hash", &self.request_hash)
            .field("controller_kid", &self.controller_kid)
            .field("applied_revision", &self.applied_revision)
            .field("resource_manifest_sha256", &self.resource_manifest_sha256)
            .field("applicant_id", &self.applicant_id)
            .field("clients", &self.clients)
            .field("trust_policy_identity", &self.trust_policy_identity)
            .finish()
    }
}

impl PreparedClient {
    fn new(
        logical_client_id: &str,
        descriptor: &MatrixDescriptor,
        policy: &CryptoPolicy,
        registration_template: &Value,
        target_issuer: &str,
        suite_origin: &str,
        request_jti: &str,
    ) -> Result<Self, MaterializerError> {
        let needs = |fields: &[&str]| {
            fields.iter().any(|field| {
                [
                    format!("client.{logical_client_id}.{field}"),
                    format!("generated.{field}"),
                ]
                .iter()
                .any(|reference| {
                    descriptor_requires_reference(descriptor, reference)
                        || descriptor::value_contains_reference(registration_template, reference)
                }) || descriptor::value_contains_reference(
                    registration_template,
                    &format!("client.{field}"),
                )
            })
        };
        let generated = generate_client_crypto(
            policy,
            needs(&["rsa.public_jwks", "rsa.private_jwks"]),
            needs(&["ec.public_jwks", "ec.private_jwks"]),
            registration_requires_mtls(registration_template)
                || needs(&[
                    "mtls.ca_cert",
                    "mtls.client_cert",
                    "mtls.client_key",
                    "mtls.cert_sha256",
                ]),
        )?;
        let mut request = materialize_registration_template(
            registration_template,
            logical_client_id,
            target_issuer,
            suite_origin,
            &generated.rsa_public_jwks,
            &generated.ec_public_jwks,
            &generated.mtls_ca_certificate,
            &generated.mtls_client_certificate,
            &generated.mtls_client_certificate_sha256,
            request_jti,
        )?;
        canonicalize_registration_string_sets(&mut request)?;
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
}

fn canonicalize_registration_string_sets(request: &mut Value) -> Result<(), MaterializerError> {
    let object = request
        .as_object_mut()
        .ok_or(MaterializerError::InvalidField("registration_template"))?;
    for field in [
        "scopes",
        "allowed_audiences",
        "grant_types",
        "post_logout_redirect_uris",
    ] {
        let Some(value) = object.get_mut(field) else {
            continue;
        };
        let values = value
            .as_array_mut()
            .ok_or(MaterializerError::InvalidField("registration_template"))?;
        if values.iter().any(|value| !value.is_string()) {
            return Err(MaterializerError::InvalidField("registration_template"));
        }
        let mut unique = BTreeSet::new();
        values.retain(|value| {
            value
                .as_str()
                .is_some_and(|value| unique.insert(value.to_owned()))
        });
    }
    Ok(())
}

fn combine_openid4vc_credential_trust_anchors(
    run_anchor_pem: &str,
    suite_anchor_pem: &str,
) -> Result<String, MaterializerError> {
    let run_der = validate_single_mdoc_trust_anchor(run_anchor_pem, "credential_trust_anchor_pem")?;
    let suite_der = validate_single_mdoc_trust_anchor(
        suite_anchor_pem,
        "openid4vc_suite_mdoc_trust_anchor_pem",
    )?;
    if run_der == suite_der {
        return Err(MaterializerError::InvalidField(
            "credential_trust_anchor_pem",
        ));
    }

    let mut combined = String::with_capacity(run_anchor_pem.len() + suite_anchor_pem.len());
    combined.push_str(run_anchor_pem.trim_end());
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

    use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
    use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use x509_parser::{extensions::ParsedExtension, parse_x509_certificate, pem::parse_x509_pem};

    use super::*;
    use crate::materializer::crypto::generate_mtls;

    #[test]
    fn scoped_resource_ids_preserve_existing_bytes_at_length_and_normalization_boundaries() {
        let suffix = "0123456789abcdef0123456789abcdef";
        let boundary = "a".repeat(78);
        let cases = [
            ("client".to_owned(), "oauth-client-client".to_owned()),
            (
                "client bad".to_owned(),
                "oauth-client-client-bad-0f5b0b0575d09479".to_owned(),
            ),
            (boundary.clone(), format!("oauth-client-{boundary}")),
            (
                "a".repeat(79),
                "oauth-client-daa76b4d16679957833226a884450609".to_owned(),
            ),
            (
                format!("{} bad", "a".repeat(100)),
                "oauth-client-c62229478d6097202dee780bff7fc745".to_owned(),
            ),
            ("客".repeat(70), "oauth-client--9ba568dccb565324".to_owned()),
        ];
        for (value, expected_base) in cases {
            assert_eq!(
                run_scoped_resource_id("oauth-client", &value, suffix),
                format!("{expected_base}-run-{suffix}")
            );
        }
    }

    #[test]
    fn mdoc_dataset_binary_elements_are_materialized_as_base64url() {
        let claims = serde_json::json!({
            "org.iso.18013.5.1": {
                "portrait": "portrait-bytes",
                "family_name": "Specimen"
            }
        });
        let materialized = materialize_openid4vc_dataset_claims("org.iso.18013.5.1.mDL", &claims);
        assert_eq!(
            materialized["org.iso.18013.5.1"]["portrait"],
            URL_SAFE_NO_PAD.encode(b"portrait-bytes")
        );
        assert_eq!(materialized["org.iso.18013.5.1"]["family_name"], "Specimen");
        assert_eq!(
            materialize_openid4vc_dataset_claims("other", &claims),
            claims
        );
    }

    #[test]
    fn manifest_canonicalization_rejects_duplicate_resource_identities() {
        let resources = (0..2)
            .map(|_| TenantResourceManifestResource {
                kind: TenantResourceKind::User,
                resource_id: "same-user".to_owned(),
                payload_base64url: Zeroizing::new("e30".to_owned()),
                digest: "a".repeat(64),
            })
            .collect();
        assert!(matches!(
            TenantResourceManifest::from_resources(resources),
            Err(MaterializerError::InvalidField(
                "tenant_resource_manifest.resources"
            ))
        ));
    }

    #[test]
    fn manifest_payload_limits_accept_exact_total_and_reject_the_next_resource() {
        let mut resources = Vec::new();
        let mut total = 0;
        // A JSON string adds two quote bytes to the ASCII payload.
        for index in 0..MAX_TENANT_RESOURCE_PAYLOAD_TOTAL_BYTES / MAX_TENANT_RESOURCE_PAYLOAD_BYTES
        {
            push_manifest_resource(
                &mut resources,
                &mut total,
                TenantResourceKind::User,
                format!("user-{index}"),
                Value::String("a".repeat(MAX_TENANT_RESOURCE_PAYLOAD_BYTES - 2)),
            )
            .unwrap();
        }
        assert_eq!(total, MAX_TENANT_RESOURCE_PAYLOAD_TOTAL_BYTES);
        let count = resources.len();
        assert!(matches!(
            push_manifest_resource(
                &mut resources,
                &mut total,
                TenantResourceKind::User,
                "next-user".to_owned(),
                Value::Null
            ),
            Err(MaterializerError::Oversize)
        ));
        assert_eq!(resources.len(), count);
        let mut fresh_total = 0;
        assert!(matches!(
            push_manifest_resource(
                &mut resources,
                &mut fresh_total,
                TenantResourceKind::User,
                "oversized-user".to_owned(),
                Value::String("a".repeat(MAX_TENANT_RESOURCE_PAYLOAD_BYTES - 1))
            ),
            Err(MaterializerError::Oversize)
        ));
        assert_eq!(fresh_total, 0);
    }

    #[test]
    fn registration_template_rejects_forbidden_control_fields() {
        for field in ["conformance_lease_id", "conformance_task_jti"] {
            let request = Value::Object([(field.to_owned(), Value::Null)].into_iter().collect());
            let mut resources = Vec::new();
            let mut total = 0;
            assert_eq!(
                push_manifest_resource(
                    &mut resources,
                    &mut total,
                    TenantResourceKind::OauthClient,
                    "client".to_owned(),
                    serde_json::json!({"request": request}),
                ),
                Err(MaterializerError::InvalidField(
                    "tenant_resource_manifest.forbidden_field"
                ))
            );
        }
    }

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
        let first = generate_client_crypto(&CryptoPolicy::default(), true, true, true)
            .expect("first material");
        let second = generate_client_crypto(&CryptoPolicy::default(), true, true, true)
            .expect("second material");

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

    #[test]
    fn generated_mtls_leaf_builds_a_strict_chain_to_its_unique_ca() {
        let (first_ca_pem, first_leaf_pem, _, _) = generate_mtls().expect("first mTLS material");
        let (second_ca_pem, _, _, _) = generate_mtls().expect("second mTLS material");
        let (_, first_ca_pem) = parse_x509_pem(first_ca_pem.as_bytes()).expect("first CA PEM");
        let (_, second_ca_pem) = parse_x509_pem(second_ca_pem.as_bytes()).expect("second CA PEM");
        let (_, first_leaf_pem) =
            parse_x509_pem(first_leaf_pem.as_bytes()).expect("first leaf PEM");
        let (_, first_ca) = parse_x509_certificate(&first_ca_pem.contents).expect("first CA");
        let (_, second_ca) = parse_x509_certificate(&second_ca_pem.contents).expect("second CA");
        let (_, first_leaf) = parse_x509_certificate(&first_leaf_pem.contents).expect("first leaf");

        assert_ne!(first_leaf.subject(), first_leaf.issuer());
        assert_eq!(first_leaf.issuer(), first_ca.subject());
        assert_ne!(first_ca.subject(), second_ca.subject());
        first_leaf
            .verify_signature(Some(first_ca.public_key()))
            .expect("leaf signature must verify with the generated CA");
    }

    #[test]
    fn unreferenced_client_crypto_is_not_generated() {
        let prepared = prepare_for_test(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .unwrap();
        assert!(prepared.attestation.is_none());
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .unwrap();
        assert!(
            !manifest
                .resource_identities()
                .iter()
                .any(|identity| identity.kind == TenantResourceKind::Openid4vcTrustPolicy)
        );
        assert!(prepared.clients.values().all(
            |client| client.mtls_ca_certificate.is_empty() && client.mtls_client_key.is_empty()
        ));
    }

    fn tenant_resource_descriptor() -> MatrixDescriptor {
        let mut descriptor = descriptor();
        let registration = descriptor.groups[0].required_roles[0]
            .registration_template
            .as_mut()
            .expect("registration template")
            .as_object_mut()
            .expect("registration object");
        registration.insert(
            "token_endpoint_auth_method".to_owned(),
            serde_json::json!("tls_client_auth"),
        );
        registration.insert(
            "tls_client_auth_cert_sha256".to_owned(),
            serde_json::json!("{{client.web.mtls.cert_sha256}}"),
        );
        registration.insert(
            "tls_client_auth_san_dns".to_owned(),
            serde_json::json!([MTLS_CLIENT_SAN_DNS]),
        );
        let plan = &mut descriptor.groups[0].plans[0];
        plan.plan = "oid4vci-1_0-issuer-test-plan".to_owned();
        plan.variant = BTreeMap::from([
            (
                "credential_configuration_id".to_owned(),
                "eu.example.pid".to_owned(),
            ),
            ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
        ]);
        plan.config_template = serde_json::json!({
            "alias": "nazo-vci-manifest",
            "vci": {"credential_configuration_id": "eu.example.pid"},
            "nazo": {"openid4vc_role": "issuer", "credential_format": "sd_jwt_vc"}
        });
        descriptor.openid4vc_credential_datasets.insert(
            "eu.example.pid".to_owned(),
            serde_json::json!({"given_name": "Conformance", "family_name": "User"}),
        );
        descriptor
    }

    fn tenant_resource_apply_result(manifest: &TenantResourceManifest) -> ControlResult {
        let resource_mappings = manifest
            .resource_identities()
            .iter()
            .filter_map(|resource| match resource.kind {
                TenantResourceKind::User => Some(TenantResourceMapping {
                    kind: resource.kind,
                    resource_id: resource.resource_id.clone(),
                    public_id: "01890f8e-7c18-7b70-9d1e-9bb8c44a2f41".to_owned(),
                }),
                TenantResourceKind::OauthClient => Some(TenantResourceMapping {
                    kind: resource.kind,
                    resource_id: resource.resource_id.clone(),
                    public_id: "actual-client".to_owned(),
                }),
                TenantResourceKind::MtlsTrustAnchor
                | TenantResourceKind::Openid4vcDataset
                | TenantResourceKind::Openid4vcTrustPolicy => None,
            })
            .collect();
        ControlResult {
            schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
            operation_id: "01890f8e-7c18-7b70-9d1e-9bb8c44a2f50".to_owned(),
            request_hash: "e".repeat(64),
            outcome: ControlOutcome::Succeeded,
            error: None,
            accepted_at: 1_700_000_000,
            completed_at: Some(1_700_000_001),
            result: Some(ControlResultData::TenantResourceApply {
                revision: 8,
                resources: manifest.resource_identities().to_vec(),
                resource_mappings,
                resource_manifest_sha256: manifest.resource_manifest_sha256().to_owned(),
            }),
        }
    }

    fn tenant_resource_apply_output(
        result: ControlResult,
        manifest: &TenantResourceManifest,
    ) -> Result<TenantResourceApplyOutput, MaterializerError> {
        TenantResourceApplyOutput::from_control_result(
            &result,
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f50",
            &"e".repeat(64),
            &"a".repeat(43),
            manifest,
            manifest.resource_identities().to_vec(),
        )
    }

    #[test]
    fn tenant_resource_manifest_is_deterministic_and_dependency_fenced() {
        let descriptor = tenant_resource_descriptor();
        let prepared = prepare_for_test(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let first = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("first manifest");
        let second = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("second manifest");
        assert_eq!(first.raw_sha256(), second.raw_sha256());
        assert_eq!(first.bytes().as_bytes(), second.bytes().as_bytes());
        assert_eq!(
            first.raw_sha256(),
            digest_hex(first.bytes().as_bytes()).as_str()
        );
        assert_eq!(
            first.resource_manifest_sha256(),
            nazo_operator_protocol::canonical_tenant_resource_manifest_sha256(
                first.resource_identities()
            )
            .expect("identity manifest digest")
        );

        let document: Value =
            serde_json::from_slice(first.bytes().as_bytes()).expect("manifest JSON");
        assert_eq!(document["schema"], TENANT_RESOURCE_MANIFEST_SCHEMA_VERSION);
        let resources = document["resources"]
            .as_array()
            .expect("manifest resources");
        assert_eq!(resources.len(), 5);
        let mut identities = BTreeSet::new();
        let mut oauth_id = None;
        let mut user_id = None;
        let mut mtls_client_ref = None;
        let mut dataset_user_ref = None;
        let mut oauth_trust_ref = None;
        let mut trust_policy_id = None;
        for resource in resources {
            let kind = resource["kind"].as_str().expect("resource kind");
            let resource_id = resource["resource_id"].as_str().expect("resource id");
            assert!(identities.insert((kind.to_owned(), resource_id.to_owned())));
            let encoded = resource["payload_base64url"]
                .as_str()
                .expect("resource payload");
            let payload = URL_SAFE_NO_PAD.decode(encoded).expect("payload b64");
            let payload: Value = serde_json::from_slice(&payload).expect("payload JSON");
            let payload_text = payload.to_string();
            assert!(!payload_text.contains("PRIVATE KEY"));
            assert!(!payload_text.contains("\"d\""));
            match kind {
                "oauth-client" => {
                    oauth_id = Some(resource_id.to_owned());
                    oauth_trust_ref = payload["trust_policy_resource_id"]
                        .as_str()
                        .map(str::to_owned);
                }
                "user" => user_id = Some(resource_id.to_owned()),
                "mtls-trust-anchor" => {
                    mtls_client_ref = payload["client_resource_id"].as_str().map(str::to_owned)
                }
                "openid4vc-dataset" => {
                    dataset_user_ref = payload["user_resource_id"].as_str().map(str::to_owned)
                }
                "openid4vc-trust-policy" => {
                    trust_policy_id = Some(resource_id.to_owned());
                    assert_eq!(payload["schema"], 1);
                    assert_eq!(
                        payload["wallet_authorization_origins"],
                        serde_json::json!(["https://suite.example"])
                    );
                    assert_eq!(
                        payload["credential_trust_anchor_pem"]
                            .as_str()
                            .expect("credential anchors")
                            .matches("-----BEGIN CERTIFICATE-----")
                            .count(),
                        2
                    );
                    let policy: Openid4vcTrustPolicy =
                        serde_json::from_value(payload.clone()).expect("trust policy payload");
                    validate_openid4vc_trust_policy(&policy)
                        .expect("ordinary trust policy must satisfy the shared wire contract");
                    let attestation = prepared.attestation.as_ref().expect("attestation");
                    for (jwks, private) in [
                        (
                            &policy.client_attestation_jwks,
                            &attestation.attester_private_jwks,
                        ),
                        (
                            &policy.key_attestation_jwks,
                            &attestation.key_attestation_private_jwks,
                        ),
                    ] {
                        let private: Value = serde_json::from_str(private).expect("private JWKS");
                        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
                        for name in ["alg", "crv", "kid", "kty", "x", "y"] {
                            assert_eq!(jwks["keys"][0][name], private["keys"][0][name]);
                        }
                        assert!(private["keys"][0]["d"].is_string());
                        assert_eq!(private["keys"][0]["use"], "sig");
                        assert!(private["keys"][0]["x5c"][0].is_string());
                        assert_eq!(
                            jwks.as_object()
                                .expect("JWKS object")
                                .keys()
                                .collect::<Vec<_>>(),
                            vec!["keys"]
                        );
                        for key in jwks["keys"].as_array().expect("JWKS keys") {
                            let key = key.as_object().expect("public JWK");
                            for forbidden in
                                ["use", "x5c", "d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                            {
                                assert!(!key.contains_key(forbidden));
                            }
                        }
                    }
                }
                other => panic!("unexpected resource kind {other}"),
            }
        }
        assert_eq!(mtls_client_ref.as_deref(), oauth_id.as_deref());
        assert_eq!(dataset_user_ref.as_deref(), user_id.as_deref());
        assert_eq!(oauth_trust_ref, trust_policy_id);
    }

    #[test]
    fn ordinary_applicant_manifest_includes_complete_nonsecret_oidc_profile() {
        let prepared = prepare_for_test(
            tenant_resource_descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let document: Value =
            serde_json::from_slice(manifest.bytes().as_bytes()).expect("manifest JSON");
        let user = document["resources"]
            .as_array()
            .expect("resources")
            .iter()
            .find(|resource| resource["kind"].as_str() == Some("user"))
            .expect("user resource");
        let payload = URL_SAFE_NO_PAD
            .decode(user["payload_base64url"].as_str().expect("user payload"))
            .expect("payload encoding");
        let payload: Value = serde_json::from_slice(&payload).expect("payload JSON");

        assert_eq!(
            payload["profile"],
            serde_json::json!({
                "display_name": "OIDF Conformance User",
                "given_name": "OIDF",
                "family_name": "Conformance",
                "middle_name": "Test",
                "nickname": "oidf-user",
                "profile_url": "https://issuer.example/oidf/profile",
                "avatar_url": "https://issuer.example/oidf/avatar.png",
                "website_url": "https://issuer.example/",
                "gender": "unspecified",
                "birthdate": "1980-01-01",
                "zoneinfo": "UTC",
                "locale": "en-US",
                "address_formatted": "123 Conformance Way, Test City, CA 94105, US",
                "address_street_address": "123 Conformance Way",
                "address_locality": "Test City",
                "address_region": "CA",
                "address_postal_code": "94105",
                "address_country": "US",
                "phone_number": "+12025550100",
                "phone_number_verified": true,
            })
        );
        let profile = payload["profile"].as_object().expect("profile object");
        assert!(!profile.contains_key("username"));
        assert!(!profile.contains_key("email"));
        assert!(!profile.contains_key("password"));
    }

    #[test]
    fn registration_set_metadata_is_stably_deduplicated() {
        let mut request = serde_json::json!({
            "scopes": ["openid", "profile", "openid"],
            "allowed_audiences": ["https://issuer.example/resource", "resource://default", "https://issuer.example/resource"],
            "grant_types": ["authorization_code", "refresh_token", "authorization_code"],
            "post_logout_redirect_uris": ["https://suite.example/logout", "https://suite.example/logout"],
        });
        canonicalize_registration_string_sets(&mut request).expect("canonical registration sets");
        assert_eq!(request["scopes"], serde_json::json!(["openid", "profile"]));
        assert_eq!(
            request["allowed_audiences"],
            serde_json::json!(["https://issuer.example/resource", "resource://default"])
        );
        assert_eq!(
            request["grant_types"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            request["post_logout_redirect_uris"],
            serde_json::json!(["https://suite.example/logout"])
        );

        request["scopes"] = serde_json::json!(["openid", 1]);
        assert!(canonicalize_registration_string_sets(&mut request).is_err());
    }

    #[test]
    fn tenant_resource_ids_are_deterministic_and_disjoint_across_runs() {
        let first_namespace = request_jti();
        let second_namespace = "request-fedcba9876543210fedcba9876543210";
        let first_prepared = prepare_for_test(
            tenant_resource_descriptor(),
            "https://issuer.example",
            &suite(),
            first_namespace,
        )
        .expect("first preparation");
        let second_prepared = prepare_for_test(
            tenant_resource_descriptor(),
            "https://issuer.example",
            &suite(),
            second_namespace,
        )
        .expect("second preparation");

        let first = first_prepared
            .tenant_resource_manifest(first_namespace)
            .expect("first manifest");
        let rebuilt = first_prepared
            .tenant_resource_manifest(first_namespace)
            .expect("rebuilt first manifest");
        assert_eq!(first.bytes().as_bytes(), rebuilt.bytes().as_bytes());
        assert!(matches!(
            first_prepared.tenant_resource_manifest(second_namespace),
            Err(MaterializerError::RequestMismatch)
        ));
        assert!(matches!(
            first_prepared.tenant_resource_manifest("invalid"),
            Err(MaterializerError::RequestMismatch)
        ));
        let second = second_prepared
            .tenant_resource_manifest(second_namespace)
            .expect("second manifest");

        let resource_ids = |manifest: &TenantResourceManifest| {
            let document: Value =
                serde_json::from_slice(manifest.bytes().as_bytes()).expect("manifest JSON");
            document["resources"]
                .as_array()
                .expect("manifest resources")
                .iter()
                .map(|resource| {
                    (
                        resource["kind"].as_str().expect("resource kind").to_owned(),
                        resource["resource_id"]
                            .as_str()
                            .expect("resource id")
                            .to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let first_ids = resource_ids(&first);
        let second_ids = resource_ids(&second);
        assert_eq!(
            first_ids
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "mtls-trust-anchor",
                "oauth-client",
                "openid4vc-dataset",
                "openid4vc-trust-policy",
                "user",
            ])
        );
        assert_eq!(
            first_ids.keys().collect::<Vec<_>>(),
            second_ids.keys().collect::<Vec<_>>()
        );

        let first_suffix = format!("-run-{}", run_namespace_suffix(first_namespace));
        let second_suffix = format!("-run-{}", run_namespace_suffix(second_namespace));
        for resource_id in first_ids.values() {
            assert!(resource_id.ends_with(&first_suffix));
            assert!(resource_id.len() <= MAX_TENANT_RESOURCE_ID_BYTES);
            assert!(!resource_id.contains("oid4vci-1_0-issuer-test-plan"));
            assert!(!resource_id.contains("suite.example"));
            assert!(
                resource_id.chars().all(
                    |character| character.is_ascii_alphanumeric() || ".:+-".contains(character)
                )
            );
        }
        for resource_id in second_ids.values() {
            assert!(resource_id.ends_with(&second_suffix));
            assert!(resource_id.len() <= MAX_TENANT_RESOURCE_ID_BYTES);
            assert!(
                resource_id.chars().all(
                    |character| character.is_ascii_alphanumeric() || ".:+-".contains(character)
                )
            );
        }
        let first_set = first_ids.values().collect::<BTreeSet<_>>();
        let second_set = second_ids.values().collect::<BTreeSet<_>>();
        assert!(first_set.is_disjoint(&second_set));
    }

    #[test]
    fn ordinary_finalize_uses_typed_apply_mappings_without_lease_identity() {
        let mut descriptor = descriptor();
        let plan = &mut descriptor.groups[0].plans[0];
        plan.secret_bindings = BTreeMap::from([
            ("outer".into(), "{{secret.inner}}".into()),
            ("inner".into(), "{{client.web.id}}".into()),
        ]);
        plan.config_template["client_id"] = serde_json::json!("{{outer}}");
        plan.config_template["nested"] = serde_json::json!([
            {"client": "{{secret.outer}}", "literal": "保留原值"}, 17, null
        ]);
        let prepared = prepare_for_test(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let result = tenant_resource_apply_result(&manifest);
        let output = tenant_resource_apply_output(result, &manifest).expect("apply output");
        let finalized = DescriptorMaterializer::finalize_tenant_resources(
            prepared,
            output,
            test_trust_anchor(),
        )
        .expect("ordinary finalize");

        assert_eq!(
            finalized.applicant_id().to_string(),
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f41"
        );
        assert_eq!(
            finalized.clients(),
            &BTreeMap::from([("web".to_owned(), "actual-client".to_owned())])
        );
        assert!(finalized.trust_policy_identity().is_none());
        assert_eq!(
            finalized.matrix().document.groups[0].plans[0].config["client_id"],
            "actual-client"
        );
        assert_eq!(
            finalized.matrix().document.groups[0].plans[0].config["nested"],
            serde_json::json!([{"client": "actual-client", "literal": "保留原值"}, 17, null])
        );
        assert_eq!(
            finalized.operation_id(),
            "01890f8e-7c18-7b70-9d1e-9bb8c44a2f50"
        );
    }

    #[test]
    fn preparation_rejects_invalid_alias_graphs_before_materialization() {
        for (bindings, expected) in [
            (
                BTreeMap::from([
                    ("outer".into(), "{{secret.inner}}".into()),
                    ("inner".into(), "{{outer}}".into()),
                ]),
                MaterializerError::SecretCycle,
            ),
            (
                BTreeMap::from([("outer".into(), "{{secret.missing}}".into())]),
                MaterializerError::UnknownSecretReference("secret.missing".into()),
            ),
            (
                BTreeMap::from([("outer".into(), "{{plan.other}}".into())]),
                MaterializerError::CrossPlanReference("plan.other".into()),
            ),
            (
                BTreeMap::from([("outer".into(), "{{client.missing.id}}".into())]),
                MaterializerError::UnknownClientReference("missing".into()),
            ),
        ] {
            let mut descriptor = descriptor();
            let plan = &mut descriptor.groups[0].plans[0];
            plan.secret_bindings = bindings;
            plan.config_template["client_id"] = serde_json::json!("{{outer}}");
            let error = prepare_for_test(
                descriptor,
                "https://issuer.example",
                &suite(),
                request_jti(),
            )
            .err()
            .expect("invalid descriptor must fail during preparation");
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn tenant_resource_apply_output_rejects_tampered_result_binding() {
        let prepared = prepare_for_test(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let mut result = tenant_resource_apply_result(&manifest);
        result.request_hash = "a".repeat(64);
        assert!(matches!(
            tenant_resource_apply_output(result, &manifest),
            Err(MaterializerError::TenantResourceResultMismatch(
                "apply binding"
            ))
        ));
    }

    #[test]
    fn tenant_resource_apply_output_rejects_missing_mapping() {
        let prepared = prepare_for_test(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let mut result = tenant_resource_apply_result(&manifest);
        let Some(ControlResultData::TenantResourceApply {
            resource_mappings, ..
        }) = result.result.as_mut()
        else {
            panic!("apply result");
        };
        resource_mappings.pop();
        assert!(tenant_resource_apply_output(result, &manifest).is_err());
    }

    #[test]
    fn tenant_resource_apply_output_rejects_duplicate_mapping() {
        let prepared = prepare_for_test(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let mut result = tenant_resource_apply_result(&manifest);
        let Some(ControlResultData::TenantResourceApply {
            resource_mappings, ..
        }) = result.result.as_mut()
        else {
            panic!("apply result");
        };
        let duplicate = resource_mappings[0].clone();
        resource_mappings.push(duplicate);
        assert!(matches!(
            tenant_resource_apply_output(result, &manifest),
            Err(MaterializerError::TenantResourceResultMismatch(
                "duplicate mapping"
            ))
        ));
    }

    #[test]
    fn tenant_resource_apply_output_rejects_wrong_mapping_kind() {
        let prepared = prepare_for_test(
            descriptor(),
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .expect("prepare");
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let mut result = tenant_resource_apply_result(&manifest);
        let Some(ControlResultData::TenantResourceApply {
            resource_mappings, ..
        }) = result.result.as_mut()
        else {
            panic!("apply result");
        };
        resource_mappings[0].kind = TenantResourceKind::MtlsTrustAnchor;
        assert!(matches!(
            tenant_resource_apply_output(result, &manifest),
            Err(MaterializerError::TenantResourceResultMismatch(
                "mapping kind"
            ))
        ));
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

    #[test]
    fn artifact_matrix_bridge_validates_descriptor_and_preserves_raw_digest() {
        let descriptor = descriptor();
        let mut matrix = crate::artifact::OidfArtifactMatrix {
            schema: crate::OIDF_MATRIX_SCHEMA_VERSION,
            name: "official-fixed-matrix".to_owned(),
            openid4vc_credential_datasets: descriptor.openid4vc_credential_datasets.clone(),
            openid4vc_suite_mdoc_trust_anchor_pem: descriptor
                .openid4vc_suite_mdoc_trust_anchor_pem
                .clone(),
            groups: descriptor
                .groups
                .iter()
                .map(|group| crate::OidfArtifactMatrixGroup {
                    id: group.id.clone(),
                    profile: group.profile.clone(),
                    variant: crate::OidfArtifactMatrixVariant {
                        id: group.variant.id.clone(),
                        values: group.variant.values.clone(),
                    },
                    required_roles: group.required_roles.clone(),
                    plans: group
                        .plans
                        .iter()
                        .map(|plan| crate::OidfArtifactMatrixPlan {
                            id: plan.id.clone(),
                            plan: plan.plan.clone(),
                            driver_handler: "default".to_owned(),
                            resource_budget: crate::OidfPlanResourceBudget {
                                modules: 1,
                                clients: 1,
                                wall_clock_seconds: 1,
                            },
                            config_template: plan.config_template.clone(),
                            variant: plan.variant.clone(),
                            required_capabilities: Vec::new(),
                            expected_results: plan.expected_results.clone(),
                            required_roles: plan.required_roles.clone(),
                            secret_bindings: plan.secret_bindings.clone(),
                            crypto: plan.crypto.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        matrix.openid4vc_credential_datasets.insert(
            "eu.example.unselected".to_owned(),
            serde_json::json!({"given_name":"Unselected"}),
        );
        let raw_digest = "f".repeat(64);
        let artifact_source_digest = "a".repeat(64);
        let suite_origin = suite();
        let binding = ArtifactMaterializationBinding {
            artifact_source_release: "test",
            artifact_source_digest: &artifact_source_digest,
            raw_matrix_sha256: &raw_digest,
            target_issuer: "https://issuer.example",
            suite_origin: &suite_origin,
            request_jti: request_jti(),
            dynamic_registration_initial_access_token: None,
        };
        let prepared =
            DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(&matrix, binding)
                .expect("artifact matrix preparation");
        assert_eq!(prepared.matrix_sha256(), raw_digest);
        assert!(prepared.descriptor.openid4vc_credential_datasets.is_empty());

        prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("tenant resource manifest");
    }

    #[test]
    fn ordinary_artifact_preparation_uses_only_the_deployment_dcr_token() {
        let descriptor = descriptor();
        let mut matrix = crate::artifact::OidfArtifactMatrix {
            schema: crate::OIDF_MATRIX_SCHEMA_VERSION,
            name: "official-fixed-matrix".to_owned(),
            openid4vc_credential_datasets: descriptor.openid4vc_credential_datasets.clone(),
            openid4vc_suite_mdoc_trust_anchor_pem: descriptor
                .openid4vc_suite_mdoc_trust_anchor_pem
                .clone(),
            groups: descriptor
                .groups
                .iter()
                .map(|group| crate::OidfArtifactMatrixGroup {
                    id: group.id.clone(),
                    profile: group.profile.clone(),
                    variant: crate::OidfArtifactMatrixVariant {
                        id: group.variant.id.clone(),
                        values: group.variant.values.clone(),
                    },
                    required_roles: group.required_roles.clone(),
                    plans: group
                        .plans
                        .iter()
                        .map(|plan| crate::OidfArtifactMatrixPlan {
                            id: plan.id.clone(),
                            plan: plan.plan.clone(),
                            driver_handler: "default".to_owned(),
                            resource_budget: crate::OidfPlanResourceBudget {
                                modules: 1,
                                clients: 1,
                                wall_clock_seconds: 1,
                            },
                            config_template: plan.config_template.clone(),
                            variant: plan.variant.clone(),
                            required_capabilities: Vec::new(),
                            expected_results: plan.expected_results.clone(),
                            required_roles: plan.required_roles.clone(),
                            secret_bindings: plan.secret_bindings.clone(),
                            crypto: plan.crypto.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        matrix.groups[0].plans[0].config_template["initial_access_token"] =
            serde_json::json!("{{generated.dynamic_registration_initial_access_token}}");
        let artifact_source_digest = "a".repeat(64);
        let raw_matrix_sha256 = "f".repeat(64);
        let suite_origin = suite();
        let result = DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(
            &matrix,
            ArtifactMaterializationBinding {
                artifact_source_release: "test",
                artifact_source_digest: &artifact_source_digest,
                raw_matrix_sha256: &raw_matrix_sha256,
                target_issuer: "https://issuer.example",
                suite_origin: &suite_origin,
                request_jti: request_jti(),
                dynamic_registration_initial_access_token: None,
            },
        );
        assert!(matches!(
            result,
            Err(MaterializerError::InvalidField(
                "dynamic_registration_initial_access_token"
            ))
        ));

        let prepared = DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(
            &matrix,
            ArtifactMaterializationBinding {
                artifact_source_release: "test",
                artifact_source_digest: &artifact_source_digest,
                raw_matrix_sha256: &raw_matrix_sha256,
                target_issuer: "https://issuer.example",
                suite_origin: &suite_origin,
                request_jti: request_jti(),
                dynamic_registration_initial_access_token: Some("deployment-dcr-token"),
            },
        )
        .expect("ordinary DCR preparation");
        assert_eq!(
            prepared
                .dynamic_registration_initial_access_token
                .as_ref()
                .map(|token| token.as_str()),
            Some("deployment-dcr-token")
        );
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

    fn suite() -> Origin {
        Origin::parse_suite("https://suite.example").expect("suite")
    }

    fn prepare_for_test(
        descriptor: MatrixDescriptor,
        target_issuer: &str,
        suite_origin: &Origin,
        request_jti: &str,
    ) -> Result<PreparedMaterialization, MaterializerError> {
        DescriptorMaterializer::prepare_materialization(
            descriptor,
            target_issuer,
            suite_origin,
            request_jti,
            None,
            None,
        )
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

    fn generated_test_certificate_bundle() -> (String, String) {
        let now = time::OffsetDateTime::now_utc();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "nazoauthctl-deployment");
        ca_params.not_before = now - time::Duration::days(1);
        ca_params.not_after = now + time::Duration::days(30);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("CA key"))
            .expect("CA certificate");

        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "tenant signing leaf");
        leaf_params.not_before = now - time::Duration::days(1);
        leaf_params.not_after = now + time::Duration::days(2);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf = leaf_params
            .signed_by(&KeyPair::generate().expect("leaf key"), &ca)
            .expect("leaf certificate")
            .pem()
            .replace("\r\n", "\n");
        let root = ca.pem().replace("\r\n", "\n");
        (format!("{leaf}{root}"), root)
    }

    fn assert_vp_credential_signer(config: &Value, suite_origin: &str) {
        let credential = config["credential"]
            .as_object()
            .expect("credential configuration");
        let signing_jwk = credential["signing_jwk"]
            .as_object()
            .expect("credential signing JWK");
        for (field, expected) in [
            ("kty", "EC"),
            ("crv", "P-256"),
            ("alg", "ES256"),
            ("use", "sig"),
        ] {
            assert_eq!(signing_jwk[field], expected);
        }
        assert!(
            signing_jwk["d"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        let leaf_der = STANDARD
            .decode(signing_jwk["x5c"][0].as_str().expect("credential leaf x5c"))
            .expect("credential leaf base64");
        let (remaining, leaf) = parse_x509_certificate(&leaf_der).expect("credential leaf");
        assert!(remaining.is_empty());
        let eku = leaf
            .extended_key_usage()
            .expect("credential EKU")
            .expect("credential EKU present");
        assert!(eku.critical, "document signer EKU must be critical");
        assert!(
            eku.value
                .other
                .iter()
                .any(|oid| oid.to_id_string() == "1.0.18013.5.1.2")
        );
        assert!(
            leaf.subject()
                .iter_country()
                .next()
                .and_then(|value| value.as_str().ok())
                .is_some_and(|value| value == "UT")
        );
        for oid in ["2.5.29.14", "2.5.29.18", "2.5.29.31", "2.5.29.35"] {
            assert!(
                leaf.extensions()
                    .iter()
                    .any(|extension| extension.oid.to_id_string() == oid),
                "document signer extension {oid}"
            );
        }
        assert!(leaf.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::IssuerAlternativeName(names)
                    if names.general_names.iter().any(|name| {
                        matches!(name, x509_parser::extensions::GeneralName::URI(value) if *value == suite_origin)
                    })
            )
        }));
        assert!(leaf.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::SubjectAlternativeName(names)
                    if names.general_names.iter().any(|name| {
                        matches!(name, x509_parser::extensions::GeneralName::URI(value) if *value == suite_origin)
                    }) && names.general_names.iter().any(|name| {
                        matches!(name, x509_parser::extensions::GeneralName::DNSName(value) if *value == "suite.example")
                    })
            )
        }));
        assert!(leaf.extensions().iter().any(|extension| matches!(
            extension.parsed_extension(),
            ParsedExtension::CRLDistributionPoints(_)
        )));

        let run_anchor = credential["trust_anchor_pem"]
            .as_str()
            .expect("run credential trust anchor");
        assert_eq!(credential["status_list_trust_anchor_pem"], run_anchor);
        let (_, root_pem) =
            x509_parser::pem::parse_x509_pem(run_anchor.as_bytes()).expect("run root PEM");
        let (_, root) = parse_x509_certificate(&root_pem.contents).expect("run root certificate");
        assert_eq!(root.subject(), root.issuer());
        assert!(
            root.subject()
                .iter_country()
                .next()
                .and_then(|value| value.as_str().ok())
                .is_some_and(|value| value == "UT")
        );
        let constraints = root
            .basic_constraints()
            .expect("IACA basic constraints")
            .expect("IACA basic constraints present");
        assert!(constraints.critical);
        assert!(constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, Some(0));
        for oid in ["2.5.29.14", "2.5.29.18", "2.5.29.31"] {
            assert!(
                root.extensions()
                    .iter()
                    .any(|extension| extension.oid.to_id_string() == oid),
                "IACA extension {oid}"
            );
        }
        let root_ski = root
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0),
                _ => None,
            })
            .expect("IACA subject key identifier");
        let leaf_ski = leaf
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0),
                _ => None,
            })
            .expect("document signer subject key identifier");
        let leaf_aki = leaf
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                    identifier.key_identifier.as_ref().map(|value| value.0)
                }
                _ => None,
            })
            .expect("document signer authority key identifier");
        assert_eq!(
            root_ski,
            digest(
                &SHA1_FOR_LEGACY_USE_ONLY,
                root.public_key().subject_public_key.data.as_ref(),
            )
            .as_ref()
        );
        assert_eq!(
            leaf_ski,
            digest(
                &SHA1_FOR_LEGACY_USE_ONLY,
                leaf.public_key().subject_public_key.data.as_ref(),
            )
            .as_ref()
        );
        assert_eq!(leaf_aki, root_ski);
        leaf.verify_signature(Some(root.public_key()))
            .expect("credential leaf must chain to the run root");
    }

    fn assert_sd_jwt_vp_credential_signer(
        attestation: &GeneratedAttestationMaterial,
        suite_origin: &str,
    ) {
        let signing_jwk: Value = serde_json::from_str(&attestation.credential_signing_private_jwk)
            .expect("credential signing JWK");
        let leaf_der = STANDARD
            .decode(signing_jwk["x5c"][0].as_str().expect("credential leaf x5c"))
            .expect("credential leaf base64");
        let (remaining, leaf) = parse_x509_certificate(&leaf_der).expect("credential leaf");
        assert!(remaining.is_empty());
        assert!(leaf.extended_key_usage().expect("credential EKU").is_none());
        assert!(leaf.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::SubjectAlternativeName(names)
                    if names.general_names.iter().any(|name| {
                        matches!(name, x509_parser::extensions::GeneralName::URI(value) if *value == suite_origin)
                    }) && names.general_names.iter().any(|name| {
                        matches!(name, x509_parser::extensions::GeneralName::DNSName(value) if *value == "suite.example")
                    })
            )
        }));

        let (_, root_pem) =
            x509_parser::pem::parse_x509_pem(attestation.trust_anchor_pem.as_bytes())
                .expect("run root PEM");
        let (_, root) = parse_x509_certificate(&root_pem.contents).expect("run root certificate");
        leaf.verify_signature(Some(root.public_key()))
            .expect("credential leaf must chain to the run root");
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
        let descriptor = tenant_resource_descriptor();
        let prepare = || {
            let prepared = prepare_for_test(
                descriptor.clone(),
                "https://issuer.example",
                &suite(),
                request_jti(),
            )
            .expect("prepare");
            let manifest = prepared
                .tenant_resource_manifest(prepared.request_jti())
                .expect("manifest");
            let result = tenant_resource_apply_result(&manifest);
            let output = tenant_resource_apply_output(result, &manifest).expect("apply output");
            (prepared, output)
        };

        let (prepared, output) = prepare();
        let duplicate = DescriptorMaterializer::finalize_tenant_resources(
            prepared,
            output,
            test_suite_mdoc_trust_anchor(),
        )
        .expect_err("duplicate roots must fail closed");
        assert!(matches!(
            duplicate,
            MaterializerError::InvalidField("credential_trust_anchor_pem")
        ));

        let (prepared, output) = prepare();
        let missing = DescriptorMaterializer::finalize_tenant_resources(prepared, output, "")
            .expect_err("missing deployment root must fail closed");
        assert!(matches!(
            missing,
            MaterializerError::InvalidField("openid4vc_request_object_trust_anchor_pem")
        ));

        let expired = generated_test_anchor(
            "expired-deployment-mdoc",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            2,
            -1,
        );
        let (prepared, output) = prepare();
        let expired = DescriptorMaterializer::finalize_tenant_resources(prepared, output, expired)
            .expect_err("expired deployment root must fail closed");
        assert!(matches!(
            expired,
            MaterializerError::InvalidField("credential_trust_anchor_pem")
        ));

        let (bundle, root) = generated_test_certificate_bundle();
        assert_eq!(
            extract_single_mdoc_trust_anchor_from_bundle(
                &bundle,
                "openid4vc_request_object_trust_anchor_pem"
            )
            .expect("deployment root from signing chain"),
            root
        );
        let (prepared, output) = prepare();
        DescriptorMaterializer::finalize_tenant_resources(prepared, output, bundle)
            .expect("leaf plus root certificate chain must materialize");
    }

    #[test]
    fn shared_clients_borrow_one_registration_and_reject_conflicts() {
        let mut descriptor = descriptor();
        let mut second = descriptor.groups[0].plans[0].clone();
        second.id = "second-plan".to_owned();
        descriptor.groups[0].plans.push(second);
        let clients = validate_descriptor(&descriptor).expect("shared client");
        assert_eq!(clients.len(), 1);
        let client = &clients["web"];
        assert!(std::ptr::eq(
            client.policy,
            &descriptor.groups[0].plans[0].crypto
        ));
        assert!(std::ptr::eq(
            client.template,
            descriptor.groups[0].required_roles[0]
                .registration_template
                .as_ref()
                .unwrap(),
        ));

        descriptor.groups[0].plans[1].crypto.rsa_bits = 4096;
        assert!(matches!(
            validate_descriptor(&descriptor),
            Err(MaterializerError::InvalidField("client crypto policy"))
        ));
        descriptor.groups[0].plans[1].crypto.rsa_bits = 2048;
        let mut second_group = descriptor.groups[0].clone();
        second_group.id = "second-group".to_owned();
        for plan in &mut second_group.plans {
            plan.id = format!("other-{}", plan.id);
        }
        second_group.required_roles[0]
            .registration_template
            .as_mut()
            .unwrap()["client_name"] = serde_json::json!("conflicting client");
        descriptor.groups.push(second_group);
        assert!(matches!(
            validate_descriptor(&descriptor),
            Err(MaterializerError::InvalidField("registration_template"))
        ));
    }

    #[test]
    fn review_cannot_be_preapproved_by_the_signed_matrix() {
        let mut descriptor = descriptor();
        descriptor.groups[0].plans[0]
            .expected_results
            .insert("oidcc-review".to_owned(), "REVIEW".to_owned());
        assert_eq!(
            validate_descriptor(&descriptor).map(|_| ()),
            Err(MaterializerError::InvalidField(
                "plan.expected_results.result"
            ))
        );
    }

    #[test]
    fn vci_materialization_binds_issuer_and_declared_variant() {
        let first_attestation = generate_attestation_material("https://suite.example", Some("UT"))
            .expect("first attestation");
        let second_attestation = generate_attestation_material("https://suite.example", Some("UT"))
            .expect("second attestation");
        assert_ne!(
            first_attestation.key_attestation_private_jwks.as_str(),
            second_attestation.key_attestation_private_jwks.as_str(),
            "VCI proof keys must be generated afresh for each run"
        );
        assert_ne!(
            first_attestation.credential_signing_private_jwk.as_str(),
            second_attestation.credential_signing_private_jwk.as_str(),
            "VP credential signing keys must be generated afresh for each run"
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
            prepare_for_test(missing, "https://issuer.example", &suite(), request_jti(),)
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
            prepare_for_test(extra, "https://issuer.example", &suite(), request_jti(),)
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
            prepare_for_test(
                conflicting,
                "https://issuer.example",
                &suite(),
                request_jti(),
            )
            .err()
            .expect("conflicting dataset must fail"),
            MaterializerError::InvalidField("nazo.credential_dataset")
        );
    }

    #[test]
    fn shared_vci_dataset_keeps_its_node_limit() {
        let mut descriptor = descriptor_with_openid4vc_plan(
            "oid4vci-1_0-issuer-test-plan",
            BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]),
            serde_json::json!({
                "alias": "nazo-vci-dataset",
                "vci": {"credential_configuration_id": "eu.example.pid"},
                "nazo": {"openid4vc_role": "issuer", "credential_format": "sd_jwt_vc"}
            }),
        );
        let mut second = descriptor.groups[0].plans[0].clone();
        second.id = "second-vci-plan".to_owned();
        descriptor.groups[0].plans.push(second);
        for (children, valid) in [(510, true), (511, false)] {
            descriptor.openid4vc_credential_datasets.insert(
                "eu.example.pid".to_owned(),
                serde_json::json!({"claims": vec![Value::Null; children]}),
            );
            let result = validate_descriptor(&descriptor).map(|_| ());
            if valid {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err(), MaterializerError::Oversize);
            }
        }
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
            prepare_for_test(private, "https://issuer.example", &suite(), request_jti(),)
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
            prepare_for_test(empty, "https://issuer.example", &suite(), request_jti(),)
                .err()
                .expect("empty dataset must fail"),
            MaterializerError::InvalidField("openid4vc_credential_datasets")
        );
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
        let error = prepare_for_test(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
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
        let error = prepare_for_test(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
        )
        .err()
        .expect("descriptor-supplied proof key must fail");
        assert_eq!(
            error,
            MaterializerError::InvalidField("vci.key_attestation_jwks")
        );
    }

    #[test]
    fn vp_haip_without_transport_variant_still_binds_request_trust_anchor() {
        let config = serde_json::json!({
            "alias": "nazo-vp-haip",
            "client": {"client_id": "issuer.example"}
        });
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let attestation = generate_attestation_material("https://suite.example", Some("UT"))
            .expect("attestation");
        let materialized = materialize_vp_config(
            "oid4vp-1final-verifier-haip-test-plan",
            &variant,
            config,
            "https://suite.example",
            test_trust_anchor(),
            Some(&attestation),
        )
        .expect("VP HAIP config");
        assert_eq!(
            materialized["client"]["request_object_trust_anchor_pem"],
            test_trust_anchor()
        );
        assert_vp_credential_signer(&materialized, "https://suite.example");
        assert_eq!(
            materialize_vp_config(
                "oid4vp-1final-verifier-haip-test-plan",
                &variant,
                materialized.clone(),
                "https://suite.example",
                test_trust_anchor(),
                Some(&attestation),
            )
            .expect("idempotent VP materialization"),
            materialized
        );

        let conflicting_browser = serde_json::json!({
            "alias": "nazo-vp-haip",
            "client": {"client_id": "issuer.example"},
            "browser": []
        });
        assert_eq!(
            materialize_vp_config(
                "oid4vp-1final-verifier-haip-test-plan",
                &variant,
                conflicting_browser,
                "https://suite.example",
                test_trust_anchor(),
                Some(&attestation),
            )
            .unwrap_err(),
            MaterializerError::InvalidField("browser")
        );

        let conflicting = serde_json::json!({
            "alias": "nazo-vp-haip",
            "client": {"client_id": "issuer.example"},
            "credential": {"signing_jwk": {"kty": "RSA"}}
        });
        assert_eq!(
            materialize_vp_config(
                "oid4vp-1final-verifier-haip-test-plan",
                &variant,
                conflicting,
                "https://suite.example",
                test_trust_anchor(),
                Some(&attestation),
            )
            .unwrap_err(),
            MaterializerError::InvalidField("credential.signing_jwk")
        );
    }

    #[test]
    fn sd_jwt_vp_credential_signer_is_bound_to_the_suite_issuer() {
        let attestation = generate_attestation_material("https://suite.example", None)
            .expect("SD-JWT attestation");
        assert_sd_jwt_vp_credential_signer(&attestation, "https://suite.example");
    }

    fn ciba_descriptor() -> MatrixDescriptor {
        let mut descriptor = descriptor();
        let registration = descriptor.groups[0].required_roles[0]
            .registration_template
            .as_mut()
            .expect("registration template")
            .as_object_mut()
            .expect("registration object");
        registration.insert(
            "grant_types".to_owned(),
            serde_json::json!(["urn:openid:params:grant-type:ciba"]),
        );
        descriptor.groups[0].plans[0].config_template = serde_json::json!({
            "client_id": "{{client.web.id}}"
        });
        descriptor
    }

    fn ordinary_ciba_prepared(descriptor: MatrixDescriptor) -> PreparedMaterialization {
        DescriptorMaterializer::prepare_materialization(
            descriptor,
            "https://issuer.example",
            &suite(),
            request_jti(),
            None,
            None,
        )
        .expect("ordinary CIBA preparation")
    }

    #[test]
    fn ordinary_ciba_keeps_multiple_signed_client_roles_without_server_bindings() {
        let mut descriptor = ciba_descriptor();
        let mut second_group = descriptor.groups[0].clone();
        second_group.id = "ciba-second".to_owned();
        second_group.required_roles[0].role = "client2".to_owned();
        second_group.required_roles[0].logical_client_id = Some("web2".to_owned());
        let registration = second_group.required_roles[0]
            .registration_template
            .as_mut()
            .expect("registration")
            .as_object_mut()
            .expect("registration object");
        registration.insert(
            "jwks".to_owned(),
            serde_json::json!("{{generated.ec.public_jwks}}"),
        );
        second_group.plans[0].id = "basic-second".to_owned();
        descriptor.groups.push(second_group);

        let prepared = ordinary_ciba_prepared(descriptor);
        let manifest = prepared
            .tenant_resource_manifest(prepared.request_jti())
            .expect("manifest");
        let document: Value = serde_json::from_slice(manifest.bytes().as_bytes()).expect("JSON");
        assert_eq!(
            document["resources"]
                .as_array()
                .expect("resources")
                .iter()
                .filter(|resource| resource["kind"].as_str() == Some("oauth-client"))
                .count(),
            2
        );
        assert!(
            document["resources"]
                .as_array()
                .expect("resources")
                .iter()
                .all(|resource| resource["kind"].as_str() != Some("ciba-decision-binding"))
        );
    }

    #[test]
    fn ordinary_ciba_accepts_multiple_signed_roles_without_a_callback() {
        let mut ambiguous = ciba_descriptor();
        let mut second_role = ambiguous.groups[0].required_roles[0].clone();
        second_role.role = "client2".to_owned();
        second_role.logical_client_id = Some("web2".to_owned());
        second_role
            .registration_template
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("registration")
            .insert(
                "jwks".to_owned(),
                serde_json::json!("{{generated.ec.public_jwks}}"),
            );
        ambiguous.groups[0].plans[0]
            .required_roles
            .push(second_role);
        let prepared = DescriptorMaterializer::prepare_materialization(
            ambiguous,
            "https://issuer.example",
            &suite(),
            request_jti(),
            None,
            None,
        )
        .expect("multiple signed CIBA clients must retain their ordinary roles");
        assert_eq!(prepared.expected_clients().len(), 2);
    }
    #[test]
    fn security_cloud_vp_only_matrix_keeps_mdoc_certificate_profile_without_issuer_datasets() {
        let mut matrix: crate::artifact::OidfArtifactMatrix =
            serde_json::from_str(include_str!("../resources/oidf/matrix.json")).unwrap();
        matrix.groups.retain(|group| group.id == "openid4vc-vp");
        for group in &mut matrix.groups {
            group.plans.retain(|plan| {
                plan.variant.get("credential_format").map(String::as_str) == Some("iso_mdl")
            });
        }
        assert!(matrix.groups.iter().any(|group| !group.plans.is_empty()));
        let prepared = DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(
            &matrix,
            ArtifactMaterializationBinding {
                artifact_source_release: "test",
                artifact_source_digest: &"a".repeat(64),
                raw_matrix_sha256: &"b".repeat(64),
                target_issuer: "https://issuer.example",
                suite_origin: &suite(),
                request_jti: request_jti(),
                dynamic_registration_initial_access_token: None,
            },
        )
        .unwrap();
        assert!(prepared.descriptor.openid4vc_credential_datasets.is_empty());
        let material = prepared.attestation.as_ref().unwrap();
        let jwk: Value = serde_json::from_str(&material.credential_signing_private_jwk).unwrap();
        let der = STANDARD.decode(jwk["x5c"][0].as_str().unwrap()).unwrap();
        let (_, certificate) = parse_x509_certificate(&der).unwrap();
        assert!(certificate.subject().iter_country().next().is_some());
        let eku = certificate.extended_key_usage().unwrap().unwrap();
        assert!(eku.critical);
        assert!(
            eku.value
                .other
                .iter()
                .any(|oid| oid.to_id_string() == "1.0.18013.5.1.2")
        );
    }
}
