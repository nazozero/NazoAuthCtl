//! Target-side OpenID4VP verifier orchestration.
//!
//! This module owns the narrow management API used to initiate a verifier
//! transaction. Browser protocol and Suite result handling remain in their
//! respective owners.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    BrowserTargetOrigin,
    validation::{MAX_STEP_TIMEOUT, redacted_origin},
};
use crate::origin::Origin;
use crate::transport::{HttpMethod, HttpRequest, HttpTransport, Transport, TransportError};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ALIAS_BYTES: usize = 256;
const MAX_TEST_NAME_BYTES: usize = 512;
const MAX_VARIANT_VALUE_BYTES: usize = 256;
const MAX_EVIDENCE_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CREATE_ATTEMPTS: usize = 4;
const VP_VERIFICATION_RESULT_PATH: &str = "/ui/verification-result";
const VP_VERIFICATION_RECEIPT_PATH: &str = "/openid4vp/verification-receipts";
const SPECIAL_POST_TEST: &str = "oid4vp-1final-verifier-request-uri-method-post";
const IMMEDIATE_REJECTION_TESTS: [&str; 8] = [
    "oid4vp-1final-verifier-invalid-session-transcript",
    "oid4vp-1final-verifier-invalid-kb-jwt-signature",
    "oid4vp-1final-verifier-invalid-credential-signature",
    "oid4vp-1final-verifier-invalid-sd-hash",
    "oid4vp-1final-verifier-invalid-kb-jwt-nonce",
    "oid4vp-1final-verifier-invalid-kb-jwt-aud",
    "oid4vp-1final-verifier-kb-jwt-iat-in-past",
    "oid4vp-1final-verifier-kb-jwt-iat-in-future",
];

/// The deployment-owned trust-policy binding that must accompany every
/// target-side verifier start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBinding {
    resource_id: String,
    digest: String,
}

impl ConformanceBinding {
    /// Construct a deployment trust-policy binding. Only the
    /// immutable logical resource id and exact applied payload digest cross
    /// the verifier-create boundary.
    pub fn openid4vc_trust_policy(
        resource_id: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, OpenId4VpError> {
        let resource_id = resource_id.into();
        let digest = digest.into();
        if resource_id.is_empty()
            || resource_id.len() > 128
            || !resource_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(OpenId4VpError::InvalidBinding);
        }
        Ok(Self {
            resource_id,
            digest,
        })
    }
}

/// The trusted create request identifies the policy resource and immutable
/// revision, while NazoAuth allocates the database binding UUID.  The latter
/// is therefore not caller-known, but must still be present and canonical in
/// the signed attachment projection.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedTrustPolicyBinding {
    resource_id: String,
    digest: String,
}

impl ExpectedTrustPolicyBinding {
    fn from_conformance_binding(binding: &ConformanceBinding) -> Self {
        Self {
            resource_id: binding.resource_id.clone(),
            digest: binding.digest.clone(),
        }
    }

    fn matches(&self, actual: &nazo_operator_protocol::Openid4vpTrustPolicyBinding) -> bool {
        actual.binding_id.as_deref().is_some_and(|binding_id| {
            Uuid::parse_str(binding_id).is_ok_and(|parsed| parsed.to_string() == binding_id)
        }) && actual.resource_id.as_deref() == Some(self.resource_id.as_str())
            && actual.resource_digest.as_deref() == Some(self.digest.as_str())
    }
}

/// Immutable facts NazoAuth signs into an OpenID4VP verification receipt.
///
/// This is intentionally constructed only after the Suite allocated the new
/// plan/module IDs.  It contains no bearer capability, presentation payload,
/// or user credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenId4VpEvidenceContext {
    pub run_jti: String,
    pub artifact_sha256: String,
    pub matrix_sha256: String,
    pub suite_plan_id: String,
    pub suite_module_id: String,
    pub test_name: String,
    pub variant_sha256: String,
}

/// Run-scoped facts shared by every worker lane. Per-module Suite IDs and
/// canonical variants are added only at the actual verifier-create boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenId4VpEvidenceRunContext {
    run_jti: String,
    artifact_sha256: String,
    matrix_sha256: String,
}

impl OpenId4VpEvidenceRunContext {
    pub fn new(
        run_jti: impl Into<String>,
        artifact_sha256: impl Into<String>,
        matrix_sha256: impl Into<String>,
    ) -> Result<Self, OpenId4VpError> {
        let context = Self {
            run_jti: run_jti.into(),
            artifact_sha256: artifact_sha256.into(),
            matrix_sha256: matrix_sha256.into(),
        };
        if !valid_identifier(&context.run_jti, 128)
            || !valid_lower_hex(&context.artifact_sha256)
            || !valid_lower_hex(&context.matrix_sha256)
        {
            return Err(OpenId4VpError::InvalidEvidenceContext);
        }
        Ok(context)
    }

    pub fn for_module(
        &self,
        suite_plan_id: &str,
        suite_module_id: &str,
        test_name: &str,
        variant: &BTreeMap<String, String>,
    ) -> Result<OpenId4VpEvidenceContext, OpenId4VpError> {
        OpenId4VpEvidenceContext::new(
            self.run_jti.clone(),
            self.artifact_sha256.clone(),
            self.matrix_sha256.clone(),
            suite_plan_id,
            suite_module_id,
            test_name,
            variant,
        )
    }
}

impl OpenId4VpEvidenceContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_jti: impl Into<String>,
        artifact_sha256: impl Into<String>,
        matrix_sha256: impl Into<String>,
        suite_plan_id: impl Into<String>,
        suite_module_id: impl Into<String>,
        test_name: impl Into<String>,
        variant: &BTreeMap<String, String>,
    ) -> Result<Self, OpenId4VpError> {
        let context = Self {
            run_jti: run_jti.into(),
            artifact_sha256: artifact_sha256.into(),
            matrix_sha256: matrix_sha256.into(),
            suite_plan_id: suite_plan_id.into(),
            suite_module_id: suite_module_id.into(),
            test_name: test_name.into(),
            variant_sha256: canonical_variant_sha256(variant)?,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), OpenId4VpError> {
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(
            &protocol_evidence_context(self),
        )
        .map(|_| ())
        .map_err(|_| OpenId4VpError::InvalidEvidenceContext)
    }
}

fn canonical_variant_sha256(variant: &BTreeMap<String, String>) -> Result<String, OpenId4VpError> {
    let bytes = serde_json::to_vec(variant).map_err(|_| OpenId4VpError::InvalidEvidenceContext)?;
    Ok(sha256_hex(&bytes))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Inputs required to start one OpenID4VP verifier presentation. Matrix
/// values stay opaque until this boundary; the verifier client accepts only
/// formats and request methods used by the official plans.
#[derive(Clone, Debug)]
pub struct OpenId4VpStartRequest {
    pub alias: String,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
    pub haip: bool,
    pub binding: ConformanceBinding,
}

impl OpenId4VpStartRequest {
    pub fn new(
        alias: impl Into<String>,
        test_name: impl Into<String>,
        variant: BTreeMap<String, String>,
        haip: bool,
        binding: ConformanceBinding,
    ) -> Result<Self, OpenId4VpError> {
        let request = Self {
            alias: alias.into(),
            test_name: test_name.into(),
            variant,
            haip,
            binding,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), OpenId4VpError> {
        if self.alias.is_empty()
            || self.alias.len() > MAX_ALIAS_BYTES
            || self.alias.chars().any(|character| {
                character.is_control()
                    || !character.is_ascii()
                    || !matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.')
            })
            || self.alias == "."
            || self.alias == ".."
        {
            return Err(OpenId4VpError::InvalidInput);
        }
        if self.test_name.is_empty()
            || self.test_name.len() > MAX_TEST_NAME_BYTES
            || self.test_name.chars().any(char::is_control)
        {
            return Err(OpenId4VpError::InvalidInput);
        }
        if self.variant.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > MAX_VARIANT_VALUE_BYTES
                || value.len() > MAX_VARIANT_VALUE_BYTES
                || key.chars().any(char::is_control)
                || value.chars().any(char::is_control)
        }) {
            return Err(OpenId4VpError::InvalidInput);
        }
        Ok(())
    }
}

/// The target response reduced to the two URLs required by the browser state
/// machine. No Suite result is interpreted or rewritten.
pub struct OpenId4VpPresentation {
    pub authorization_url: Url,
    pub completion_url: Url,
    pub transaction_id: Uuid,
    /// Non-secret caller idempotency key for the target-side presentation
    /// create. It is generated once before the first request, then reused by
    /// the narrow response-loss retry loop.
    create_request_jti: String,
    expected_trust_policy: ExpectedTrustPolicyBinding,
    evidence_context: Option<OpenId4VpEvidenceContext>,
    evidence_attachment: Option<OpenId4VpEvidenceAttachment>,
    /// A non-secret idempotency key generated once after the target accepted
    /// the exact evidence context. Receipt issuance retries reuse it, so a
    /// lost response cannot rotate the browser capability for this module.
    issuance_request_jti: Option<String>,
    immediate_rejection_allowed: bool,
}

/// The protocol-level result of delivering the wallet response. A named
/// negative test may be rejected by the verifier before a completed
/// presentation exists; that expected outcome must never be treated as a
/// completed transaction with verification evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenId4VpCompletionOutcome {
    Completed,
    ExpectedImmediateRejection,
}

/// Non-secret attachment facts verified under the live runtime key before the
/// presentation can be completed. The signed compact intent is persisted only
/// through its digest in the later receipt provenance; the receipt itself
/// repeats and signs the exact binding.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenId4VpEvidenceAttachment {
    presentation_binding_sha256: String,
    intent_sha256: String,
}

impl fmt::Debug for OpenId4VpPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpPresentation")
            .field(
                "authorization_origin",
                &redacted_origin(&self.authorization_url),
            )
            .field("completion_origin", &redacted_origin(&self.completion_url))
            .field("transaction_id", &self.transaction_id)
            .field("create_request_jti", &self.create_request_jti)
            .field("expected_trust_policy", &self.expected_trust_policy)
            .field("evidence_attachment", &self.evidence_attachment)
            .field("issuance_request_jti", &self.issuance_request_jti)
            .field(
                "immediate_rejection_allowed",
                &self.immediate_rejection_allowed,
            )
            .finish()
    }
}

#[cfg(all(test, unix))]
impl OpenId4VpPresentation {
    /// Test-only presentation fixture for orchestration tests. Production
    /// construction remains exclusively in the verified management client.
    pub(crate) fn test_presentation() -> Self {
        let binding = ConformanceBinding::openid4vc_trust_policy(
            "openid4vc-trust-policy:test",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("test binding");
        Self {
            authorization_url: Url::parse("https://issuer.example/authorize?request=opaque")
                .expect("test authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/00000000-0000-0000-0000-000000000000",
            )
            .expect("test completion URL"),
            transaction_id: Uuid::nil(),
            create_request_jti: Uuid::nil().to_string(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(&binding),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: false,
        }
    }
}

/// Narrow orchestration hook for an OpenID4VP verifier. Browser protocol
/// remains in `BrowserAutomation`; this trait only starts a presentation.
pub trait OpenId4VpVerifier: Send {
    fn start(
        &mut self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError>;

    /// Deliver the presentation request to the Suite wallet and require the
    /// one redirect that proves the target transaction completed. This is an
    /// HTTP protocol step, not an interactive browser session.
    fn complete(
        &mut self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError>;

    /// Fetch a completed, runtime-signed evidence receipt for a presentation
    /// that explicitly requested one.
    fn verification_evidence(
        &mut self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpVerificationEvidence, OpenId4VpError>;

    /// Attach a receipt context after the target has returned the concrete
    /// authorization URL and the same browser lane has selected its actual
    /// signed entry. A context is never guessed at create time.
    fn attach_evidence_context(
        &mut self,
        presentation: &mut OpenId4VpPresentation,
        context: OpenId4VpEvidenceContext,
    ) -> Result<(), OpenId4VpError>;
}

/// The runtime identity pinned by the ordinary tenant-resource capability.
/// It is deliberately separate from the management bearer token: an API
/// response is useful only when its receipt verifies under this live key.
#[derive(Clone)]
pub struct OpenId4VpEvidenceVerifier {
    deployment_id: String,
    tenant_id: String,
    runtime_instance_id: String,
    instance_key_id: String,
    instance_public_key: VerifyingKey,
    instance_public_key_base64: String,
}

impl OpenId4VpEvidenceVerifier {
    pub fn new(
        deployment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        runtime_instance_id: impl Into<String>,
        instance_key_id: impl Into<String>,
        instance_public_key: VerifyingKey,
    ) -> Result<Self, OpenId4VpError> {
        let verifier = Self {
            deployment_id: deployment_id.into(),
            tenant_id: tenant_id.into(),
            runtime_instance_id: runtime_instance_id.into(),
            instance_key_id: instance_key_id.into(),
            instance_public_key_base64: nazo_operator_protocol::encode_instance_public_key(
                &instance_public_key,
            ),
            instance_public_key,
        };
        let canonical_tenant_id = Uuid::parse_str(&verifier.tenant_id)
            .map_err(|_| OpenId4VpError::InvalidEvidenceContext)?;
        if !valid_identifier(&verifier.deployment_id, 128)
            || canonical_tenant_id.to_string() != verifier.tenant_id
            || !valid_identifier(&verifier.runtime_instance_id, 128)
            || !valid_identifier(&verifier.instance_key_id, 128)
            || verifier.instance_key_id
                != nazo_operator_protocol::instance_key_id(&verifier.instance_public_key)
        {
            return Err(OpenId4VpError::InvalidEvidenceContext);
        }
        Ok(verifier)
    }

    /// Convert the live discovery binding into the non-secret anchor held by
    /// the ordinary recovery journal. A later screenshot receipt is verified
    /// against this journal-owned key, never a key carried by that receipt.
    pub fn recovery_trust_anchor(
        &self,
        target_issuer: impl Into<String>,
    ) -> Result<crate::OpenId4VpEvidenceTrustAnchor, OpenId4VpError> {
        let target_issuer = target_issuer.into();
        let issuer =
            Url::parse(&target_issuer).map_err(|_| OpenId4VpError::InvalidEvidenceContext)?;
        let anchor = crate::OpenId4VpEvidenceTrustAnchor {
            target_issuer: issuer.as_str().trim_end_matches('/').to_owned(),
            deployment_id: self.deployment_id.clone(),
            runtime_instance_id: self.runtime_instance_id.clone(),
            instance_key_id: self.instance_key_id.clone(),
            instance_public_key_base64: self.instance_public_key_base64.clone(),
        };
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !matches!(issuer.path(), "" | "/")
        {
            return Err(OpenId4VpError::InvalidEvidenceContext);
        }
        Ok(anchor)
    }
}

/// Non-secret evidence required to re-verify that a durable screenshot came
/// from the selected NazoAuth runtime. The bearer capability and fragment UI
/// URL are intentionally absent.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenId4VpVerificationReceiptProvenance {
    pub issuer: String,
    pub receipt_api_url: String,
    pub receipt_id: Uuid,
    pub transaction_id: Uuid,
    pub tenant_id: String,
    pub issuance_request_jti: String,
    pub presentation_binding_sha256: String,
    pub intent_sha256: String,
    pub receipt_jws: String,
    pub receipt_sha256: String,
    pub capability_sha256: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub instance_public_key_base64: String,
    pub completed_at: String,
    pub expires_at: String,
}

impl fmt::Debug for OpenId4VpVerificationReceiptProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpVerificationReceiptProvenance")
            .field("issuer", &self.issuer)
            .field("receipt_api_url", &self.receipt_api_url)
            .field("receipt_id", &self.receipt_id)
            .field("transaction_id", &self.transaction_id)
            .field("tenant_id", &self.tenant_id)
            .field("issuance_request_jti", &self.issuance_request_jti)
            .field(
                "presentation_binding_sha256",
                &self.presentation_binding_sha256,
            )
            .field("intent_sha256", &self.intent_sha256)
            .field("receipt_jws", &"<redacted>")
            .field("receipt_sha256", &self.receipt_sha256)
            .field("capability_sha256", &self.capability_sha256)
            .field("deployment_id", &self.deployment_id)
            .field("runtime_instance_id", &self.runtime_instance_id)
            .field("instance_key_id", &self.instance_key_id)
            .field(
                "instance_public_key_base64",
                &self.instance_public_key_base64,
            )
            .field("completed_at", &self.completed_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Verified, non-secret projection used to bind a browser screenshot to the
/// just-created Suite module. The capability-bearing UI URL is held only for
/// the immediate same-lane navigation and must never enter reports/evidence.
pub struct OpenId4VpVerificationEvidence {
    pub receipt: OpenId4VpVerificationReceiptProvenance,
    pub context: OpenId4VpEvidenceContext,
    pub(crate) ui_url_diagnostic: OpenId4VpEvidenceUrlDiagnostic,
    ui_url: Zeroizing<String>,
}

impl fmt::Debug for OpenId4VpVerificationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpVerificationEvidence")
            .field("receipt", &self.receipt)
            .field("context", &self.context)
            .field("ui_url", &"<redacted>")
            .finish()
    }
}

impl OpenId4VpVerificationEvidence {
    pub(crate) fn ui_url(&self) -> Result<Url, OpenId4VpError> {
        Url::parse(self.ui_url.as_str()).map_err(|_| OpenId4VpError::MalformedEvidenceResponse)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn test_verified(
        context: OpenId4VpEvidenceContext,
        receipt_sha256: &str,
        ui_url: &str,
    ) -> Self {
        Self {
            receipt: OpenId4VpVerificationReceiptProvenance {
                issuer: "https://issuer.example".to_owned(),
                receipt_api_url: "https://issuer.example/openid4vp/verification-receipts"
                    .to_owned(),
                receipt_id: Uuid::nil(),
                transaction_id: Uuid::nil(),
                tenant_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                issuance_request_jti: Uuid::nil().to_string(),
                presentation_binding_sha256: "b".repeat(64),
                intent_sha256: "c".repeat(64),
                receipt_jws: "test-receipt-jws".to_owned(),
                receipt_sha256: receipt_sha256.to_owned(),
                capability_sha256: "a".repeat(64),
                deployment_id: "deployment-a".to_owned(),
                runtime_instance_id: "runtime-a".to_owned(),
                instance_key_id: "test-key".to_owned(),
                instance_public_key_base64: "test-key".to_owned(),
                completed_at: "2026-01-01T00:00:00Z".to_owned(),
                expires_at: "2026-01-01T00:05:00Z".to_owned(),
            },
            context,
            ui_url_diagnostic: issuance_url_diagnostic("verification_ui_url", ui_url),
            ui_url: Zeroizing::new(ui_url.to_owned()),
        }
    }
}

/// Rust-native client for NazoAuth's verifier-start endpoint.
pub struct OpenId4VpVerifierClient {
    target_origin: BrowserTargetOrigin,
    suite_origin: Origin,
    management_token: Zeroizing<String>,
    binding: ConformanceBinding,
    transport: Arc<dyn Transport>,
    max_response_bytes: usize,
    evidence_verifier: Option<OpenId4VpEvidenceVerifier>,
}

impl fmt::Debug for OpenId4VpVerifierClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpVerifierClient")
            .field("target_origin", &self.target_origin)
            .field("suite_origin", &self.suite_origin)
            .field("management_token", &"<redacted>")
            .field("binding", &self.binding)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("evidence_verifier", &self.evidence_verifier.is_some())
            .finish()
    }
}

impl OpenId4VpVerifierClient {
    pub fn new(
        target_origin: BrowserTargetOrigin,
        suite_origin: Origin,
        management_token: Zeroizing<String>,
        timeout: Duration,
        binding: ConformanceBinding,
    ) -> Result<Self, OpenId4VpError> {
        if management_token.trim().is_empty()
            || management_token.len() > MAX_VARIANT_VALUE_BYTES * 64
            || management_token
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || timeout.is_zero()
            || timeout > MAX_STEP_TIMEOUT
        {
            return Err(OpenId4VpError::InvalidInput);
        }
        let transport = HttpTransport::new(timeout).map_err(OpenId4VpError::Transport)?;
        Ok(Self {
            target_origin,
            suite_origin,
            management_token,
            binding,
            transport: Arc::new(transport),
            max_response_bytes: MAX_RESPONSE_BYTES,
            evidence_verifier: None,
        })
    }

    /// Enable the post-completion receipt boundary with the runtime identity
    /// observed through the ordinary control plane.
    pub fn with_evidence_verifier(mut self, verifier: OpenId4VpEvidenceVerifier) -> Self {
        self.evidence_verifier = Some(verifier);
        self
    }

    #[cfg(test)]
    fn with_transport(
        target_origin: BrowserTargetOrigin,
        suite_origin: Origin,
        management_token: Zeroizing<String>,
        transport: Arc<dyn Transport>,
        binding: ConformanceBinding,
    ) -> Result<Self, OpenId4VpError> {
        let mut client = Self::new(
            target_origin,
            suite_origin,
            management_token,
            Duration::from_secs(30),
            binding,
        )?;
        client.transport = transport;
        Ok(client)
    }

    fn start_presentation(
        &self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError> {
        request.validate()?;
        if self.binding != request.binding {
            return Err(OpenId4VpError::BindingMismatch);
        }
        let format_name = request
            .variant
            .get("credential_format")
            .map(String::as_str)
            .unwrap_or("sd_jwt_vc");
        let (dcql_format, credential_meta) = match format_name {
            "sd_jwt_vc" => (
                "dc+sd-jwt",
                serde_json::json!({"vct_values": ["urn:eudi:pid:1"]}),
            ),
            "iso_mdl" | "mso_mdoc" => (
                "mso_mdoc",
                serde_json::json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
            ),
            _ => return Err(OpenId4VpError::UnsupportedCredentialFormat),
        };

        let request_method = match request
            .variant
            .get("request_method")
            .map(String::as_str)
            .unwrap_or("request_uri_signed")
        {
            "url_query" => "url_query",
            "request_uri_signed" if request.test_name == SPECIAL_POST_TEST => {
                "request_uri_signed_post"
            }
            "request_uri_signed" => "request_uri_signed_get",
            _ => return Err(OpenId4VpError::UnsupportedRequestMethod),
        };
        let response_mode = request
            .variant
            .get("response_mode")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                if request.haip {
                    "direct_post.jwt".to_owned()
                } else {
                    "direct_post".to_owned()
                }
            });
        let client_id_prefix = request
            .variant
            .get("client_id_prefix")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| "x509_hash".to_owned());
        if response_mode.len() > MAX_VARIANT_VALUE_BYTES
            || client_id_prefix.len() > MAX_VARIANT_VALUE_BYTES
            || response_mode.chars().any(char::is_control)
            || client_id_prefix.chars().any(char::is_control)
        {
            return Err(OpenId4VpError::InvalidInput);
        }

        let wallet_authorization_endpoint = self
            .suite_origin
            .url(&format!("/test/a/{}/authorize", request.alias))
            .map_err(|_| OpenId4VpError::InvalidInput)?;
        let mut endpoint = self.target_origin.as_url().clone();
        endpoint.set_path("/openid4vp/presentations");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let create_request_jti = Uuid::new_v4().to_string();
        nazo_operator_protocol::validate_openid4vp_create_request_jti(&create_request_jti)
            .map_err(|_| OpenId4VpError::InvalidInput)?;
        let dcql_query = serde_json::json!({
            "credentials": [{
                "id": "credential",
                "format": dcql_format,
                "meta": credential_meta,
                "require_cryptographic_holder_binding": true,
            }]
        });
        let trust_policy_resource_id = Some(self.binding.resource_id.clone());
        let trust_policy_digest = Some(self.binding.digest.clone());
        let normalized = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
            wallet_authorization_endpoint: wallet_authorization_endpoint.as_str().to_owned(),
            dcql_query: dcql_query.clone(),
            haip: request.haip,
            client_id_prefix: client_id_prefix.clone(),
            request_method: request_method.to_owned(),
            response_mode: response_mode.clone(),
            transaction_data: None,
            openid4vc_trust_policy_resource_id: trust_policy_resource_id.clone(),
            openid4vc_trust_policy_digest: trust_policy_digest.clone(),
        };
        let (_, create_request_sha256) =
            nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
                .map_err(|_| OpenId4VpError::InvalidInput)?;
        let mut body = serde_json::json!({
            "wallet_authorization_endpoint": wallet_authorization_endpoint.as_str(),
            "dcql_query": dcql_query,
            "haip": request.haip,
            "client_id_prefix": client_id_prefix,
            "request_method": request_method,
            "response_mode": response_mode,
        });
        let body_object = body.as_object_mut().ok_or(OpenId4VpError::InvalidInput)?;
        let idempotency =
            serde_json::to_value(nazo_operator_protocol::Openid4vpCreateIdempotencyRequest {
                create_request_jti: create_request_jti.clone(),
            })
            .map_err(|_| OpenId4VpError::InvalidInput)?;
        let idempotency = idempotency
            .as_object()
            .ok_or(OpenId4VpError::InvalidInput)?;
        body_object.extend(idempotency.clone());
        body_object.insert(
            "openid4vc_trust_policy_resource_id".to_owned(),
            Value::String(self.binding.resource_id.clone()),
        );
        body_object.insert(
            "openid4vc_trust_policy_digest".to_owned(),
            Value::String(self.binding.digest.clone()),
        );
        let body = serde_json::to_vec(&body).map_err(|_| OpenId4VpError::InvalidInput)?;
        let mut attempts = 0usize;
        let response = loop {
            attempts = attempts.saturating_add(1);
            let request = HttpRequest {
                method: HttpMethod::Post,
                url: endpoint.clone(),
                headers: vec![
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                    (
                        "Authorization".to_owned(),
                        format!("Bearer {}", self.management_token.as_str()),
                    ),
                ],
                body: Some(body.clone()),
            };
            match self.transport.send(request, self.max_response_bytes) {
                Ok(response) => break response,
                Err(TransportError::Network(_)) if attempts < MAX_CREATE_ATTEMPTS => continue,
                Err(error) => return Err(OpenId4VpError::Transport(error)),
            }
        };
        if !(200..300).contains(&response.status) {
            return Err(OpenId4VpError::UnexpectedStatus);
        }
        let response: CreatePresentationResponse = serde_json::from_slice(&response.body)
            .map_err(|_| OpenId4VpError::MalformedResponse)?;
        if response.expires_in == 0
            || response.idempotency.create_request_jti != create_request_jti
            || !valid_lower_hex(&response.idempotency.create_request_sha256)
            || response.idempotency.create_request_sha256 != create_request_sha256
        {
            return Err(OpenId4VpError::MalformedResponse);
        }
        let authorization_url = Url::parse(&response.authorization_url)
            .map_err(|_| OpenId4VpError::MalformedResponse)?;
        if !self.allows_browser_url(&authorization_url)
            || !authorization_url.username().is_empty()
            || authorization_url.password().is_some()
            || authorization_url.fragment().is_some()
        {
            return Err(OpenId4VpError::CrossOriginNavigation);
        }
        let transaction_id = response.transaction_id;
        let mut completion_url = self.target_origin.as_url().clone();
        completion_url.set_path(&format!("/openid4vp/complete/{transaction_id}"));
        completion_url.set_query(None);
        completion_url.set_fragment(None);
        Ok(OpenId4VpPresentation {
            authorization_url,
            completion_url,
            transaction_id,
            create_request_jti,
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &self.binding,
            ),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: IMMEDIATE_REJECTION_TESTS
                .contains(&request.test_name.as_str()),
        })
    }

    fn allows_browser_url(&self, url: &Url) -> bool {
        (self.target_origin.allows(url) || self.suite_origin.same_origin_url(url))
            && matches!(url.scheme(), "https" | "http")
    }

    fn complete_presentation(
        &self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError> {
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Get,
                    url: presentation.authorization_url.clone(),
                    headers: vec![(
                        "Accept".to_owned(),
                        "text/html,application/xhtml+xml".to_owned(),
                    )],
                    body: None,
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VpError::Transport)?;
        // For an OID4VP negative test, the target's response_uri may reject the
        // invalid presentation with 4xx. The Suite then returns a 2xx result
        // page from its authorization endpoint instead of redirecting to the
        // target completion page. Only the named negative tests may terminate
        // on that Suite 2xx; positive and deferred-verification flows remain
        // bound to the exact completion redirect.
        if (200..300).contains(&response.status) && presentation.immediate_rejection_allowed {
            return Ok(OpenId4VpCompletionOutcome::ExpectedImmediateRejection);
        }
        if !matches!(response.status, 302 | 303) {
            return Err(OpenId4VpError::UnexpectedAuthorizationRedirect);
        }
        let location = response
            .header("Location")
            .ok_or(OpenId4VpError::UnexpectedAuthorizationRedirect)?;
        let redirected = presentation
            .authorization_url
            .join(location)
            .map_err(|_| OpenId4VpError::UnexpectedAuthorizationRedirect)?;
        if redirected != presentation.completion_url {
            return Err(OpenId4VpError::UnexpectedAuthorizationRedirect);
        }

        let completed = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Get,
                    url: presentation.completion_url.clone(),
                    headers: vec![(
                        "Accept".to_owned(),
                        "text/html,application/xhtml+xml".to_owned(),
                    )],
                    body: None,
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VpError::Transport)?;
        if !(200..300).contains(&completed.status) {
            return Err(OpenId4VpError::CompletionFailed);
        }
        Ok(OpenId4VpCompletionOutcome::Completed)
    }

    fn verification_evidence(
        &self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpVerificationEvidence, OpenId4VpError> {
        let expected_context = presentation
            .evidence_context
            .as_ref()
            .ok_or(OpenId4VpError::EvidenceUnavailable)?;
        let issuance_request_jti = presentation
            .issuance_request_jti
            .as_deref()
            .ok_or(OpenId4VpError::EvidenceUnavailable)?;
        if Uuid::parse_str(issuance_request_jti).is_err() {
            return Err(OpenId4VpError::EvidenceBindingMismatch);
        }
        let attachment = presentation
            .evidence_attachment
            .as_ref()
            .ok_or(OpenId4VpError::EvidenceUnavailable)?;
        let verifier = self
            .evidence_verifier
            .as_ref()
            .ok_or(OpenId4VpError::EvidenceUnavailable)?;
        let mut endpoint = self.target_origin.as_url().clone();
        endpoint.set_path(&format!(
            "/openid4vp/verification/{}/receipt-capability",
            presentation.transaction_id
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Post,
                    url: endpoint,
                    headers: vec![
                        ("Accept".to_owned(), "application/json".to_owned()),
                        (
                            "Authorization".to_owned(),
                            format!("Bearer {}", self.management_token.as_str()),
                        ),
                    ],
                    body: Some(
                        serde_json::to_vec(
                            &nazo_operator_protocol::Openid4vpIssueVerificationReceiptRequest {
                                schema: 1,
                                issuance_request_jti: issuance_request_jti.to_owned(),
                            },
                        )
                        .map_err(|_| OpenId4VpError::InvalidEvidenceContext)?,
                    ),
                },
                MAX_EVIDENCE_RESPONSE_BYTES,
            )
            .map_err(OpenId4VpError::Transport)?;
        if response.status == 404 {
            return Err(OpenId4VpError::EvidenceUnavailable);
        }
        if response.status == 503 {
            return Err(OpenId4VpError::EvidenceTemporarilyUnavailable);
        }
        if !(200..300).contains(&response.status) {
            return Err(OpenId4VpError::UnexpectedEvidenceStatus);
        }
        let response: VerificationEvidenceResponse = serde_json::from_slice(&response.body)
            .map_err(|_| OpenId4VpError::MalformedEvidenceResponse)?;
        let evidence = verify_evidence_response(
            response,
            presentation.transaction_id,
            expected_context,
            issuance_request_jti,
            attachment,
            verifier,
            self.target_origin.as_url(),
        )?;
        Ok(evidence)
    }

    fn attach_evidence_context(
        &self,
        presentation: &mut OpenId4VpPresentation,
        context: OpenId4VpEvidenceContext,
    ) -> Result<(), OpenId4VpError> {
        context.validate()?;
        let verifier = self
            .evidence_verifier
            .as_ref()
            .ok_or(OpenId4VpError::EvidenceUnavailable)?;
        let protocol_context = protocol_evidence_context(&context);
        let expected_sha256 =
            nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&protocol_context)
                .map_err(|_| OpenId4VpError::InvalidEvidenceContext)?;
        let mut endpoint = self.target_origin.as_url().clone();
        endpoint.set_path(&format!(
            "/openid4vp/verification/{}/evidence-context",
            presentation.transaction_id
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let body = serde_json::to_vec(&nazo_operator_protocol::Openid4vpAttachEvidenceRequest {
            schema: 1,
            evidence_context: protocol_context.clone(),
        })
        .map_err(|_| OpenId4VpError::InvalidEvidenceContext)?;
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Post,
                    url: endpoint,
                    headers: vec![
                        ("Accept".to_owned(), "application/json".to_owned()),
                        ("Content-Type".to_owned(), "application/json".to_owned()),
                        (
                            "Authorization".to_owned(),
                            format!("Bearer {}", self.management_token.as_str()),
                        ),
                    ],
                    body: Some(body),
                },
                MAX_EVIDENCE_RESPONSE_BYTES,
            )
            .map_err(OpenId4VpError::Transport)?;
        if response.status == 404 {
            return Err(OpenId4VpError::EvidenceUnavailable);
        }
        if response.status == 503 {
            return Err(OpenId4VpError::EvidenceTemporarilyUnavailable);
        }
        if !(200..300).contains(&response.status) {
            return Err(OpenId4VpError::UnexpectedEvidenceStatus);
        }
        let response: nazo_operator_protocol::Openid4vpAttachEvidenceResponse =
            serde_json::from_slice(&response.body)
                .map_err(|_| OpenId4VpError::MalformedEvidenceResponse)?;
        let transaction_id = presentation.transaction_id.to_string();
        let presentation_binding_sha256 =
            nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                &response.presentation_binding,
            )
            .map_err(|_| attach_binding_mismatch("presentation_binding"))?;
        if response.schema != 1 {
            return Err(attach_binding_mismatch("schema"));
        }
        if response.transaction_id != transaction_id {
            return Err(attach_binding_mismatch("transaction_id"));
        }
        if response.status != nazo_operator_protocol::Openid4vpEvidenceAttachmentStatus::Attached {
            return Err(attach_binding_mismatch("status"));
        }
        if response.evidence_context_sha256 != expected_sha256 {
            return Err(attach_binding_mismatch("context_sha256"));
        }
        if response.presentation_binding_sha256 != presentation_binding_sha256 {
            return Err(attach_binding_mismatch("presentation_binding"));
        }
        if !presentation
            .expected_trust_policy
            .matches(&response.presentation_binding.trust_policy)
        {
            return Err(attach_binding_mismatch("trust_policy"));
        }
        if nazo_operator_protocol::compact_sha256(&response.intent_jws) != response.intent_sha256 {
            return Err(attach_binding_mismatch("intent_sha256"));
        }
        let target_issuer = self.target_origin.as_url().as_str().trim_end_matches('/');
        let intent_audience = format!("{target_issuer}/openid4vp/verification-intents");
        let expected = nazo_operator_protocol::Openid4vpVerificationIntentExpectations {
            issuer: target_issuer,
            audience: &intent_audience,
            deployment_id: &verifier.deployment_id,
            runtime_instance_id: &verifier.runtime_instance_id,
            instance_key_id: &verifier.instance_key_id,
            tenant_id: &verifier.tenant_id,
            transaction_id: &transaction_id,
            evidence_context_sha256: &expected_sha256,
            presentation_binding_sha256: &presentation_binding_sha256,
        };
        let intent = nazo_operator_protocol::verify_openid4vp_verification_intent(
            &response.intent_jws,
            &expected,
            &verifier.instance_public_key,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| attach_binding_mismatch("intent_jws"))?;
        if intent.evidence_context != protocol_context
            || intent.presentation_binding != response.presentation_binding
        {
            return Err(attach_binding_mismatch("intent_jws_claims"));
        }
        presentation.evidence_context = Some(context);
        presentation.evidence_attachment = Some(OpenId4VpEvidenceAttachment {
            presentation_binding_sha256,
            intent_sha256: response.intent_sha256,
        });
        presentation.issuance_request_jti = Some(Uuid::new_v4().to_string());
        Ok(())
    }
}

impl OpenId4VpVerifier for OpenId4VpVerifierClient {
    fn start(
        &mut self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError> {
        self.start_presentation(request)
    }

    fn complete(
        &mut self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError> {
        self.complete_presentation(presentation)
    }

    fn verification_evidence(
        &mut self,
        presentation: &OpenId4VpPresentation,
    ) -> Result<OpenId4VpVerificationEvidence, OpenId4VpError> {
        OpenId4VpVerifierClient::verification_evidence(self, presentation)
    }

    fn attach_evidence_context(
        &mut self,
        presentation: &mut OpenId4VpPresentation,
        context: OpenId4VpEvidenceContext,
    ) -> Result<(), OpenId4VpError> {
        OpenId4VpVerifierClient::attach_evidence_context(self, presentation, context)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePresentationResponse {
    #[serde(flatten)]
    idempotency: nazo_operator_protocol::Openid4vpCreateIdempotencyBinding,
    authorization_url: String,
    transaction_id: Uuid,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationEvidenceResponse {
    schema: u32,
    issuer: String,
    deployment_id: String,
    runtime_instance_id: String,
    instance_key_id: String,
    tenant_id: String,
    transaction_id: Uuid,
    receipt_id: Uuid,
    issuance_request_jti: String,
    status: nazo_operator_protocol::Openid4vpVerificationStatus,
    evidence_context: OpenId4VpEvidenceContext,
    presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    intent_sha256: String,
    completed_at: String,
    expires_at: String,
    receipt_jws: String,
    receipt_sha256: String,
    receipt_api_url: String,
    verification_ui_url: String,
    verification_ttl_seconds: u64,
}

fn verify_evidence_response(
    response: VerificationEvidenceResponse,
    expected_transaction_id: Uuid,
    expected_context: &OpenId4VpEvidenceContext,
    issuance_request_jti: &str,
    attachment: &OpenId4VpEvidenceAttachment,
    verifier: &OpenId4VpEvidenceVerifier,
    target_origin: &Url,
) -> Result<OpenId4VpVerificationEvidence, OpenId4VpError> {
    let receipt_sha256 = sha256_hex(response.receipt_jws.as_bytes());
    let presentation_binding_sha256 =
        nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
            &response.presentation_binding,
        )
        .map_err(|_| issuance_binding_mismatch("presentation_binding"))?;
    if response.schema != 1 {
        return Err(issuance_binding_mismatch("schema"));
    }
    if response.status != nazo_operator_protocol::Openid4vpVerificationStatus::Verified {
        return Err(issuance_binding_mismatch("status"));
    }
    if response.transaction_id != expected_transaction_id {
        return Err(issuance_binding_mismatch("transaction_id"));
    }
    if response.tenant_id != verifier.tenant_id {
        return Err(issuance_binding_mismatch("tenant_id"));
    }
    if response.issuance_request_jti != issuance_request_jti {
        return Err(issuance_binding_mismatch("issuance_request_jti"));
    }
    if response.evidence_context != *expected_context {
        return Err(issuance_binding_mismatch("context_sha256"));
    }
    if presentation_binding_sha256 != attachment.presentation_binding_sha256 {
        return Err(issuance_binding_mismatch("presentation_binding"));
    }
    if response.intent_sha256 != attachment.intent_sha256 {
        return Err(issuance_binding_mismatch("intent_sha256"));
    }
    if !valid_lower_hex(&response.receipt_sha256) || response.receipt_sha256 != receipt_sha256 {
        return Err(issuance_binding_mismatch("receipt_sha256"));
    }
    if !same_target_origin(&response.issuer, target_origin) {
        return Err(issuance_binding_mismatch("issuer"));
    }
    if response.deployment_id != verifier.deployment_id {
        return Err(issuance_binding_mismatch("deployment_id"));
    }
    if response.runtime_instance_id != verifier.runtime_instance_id {
        return Err(issuance_binding_mismatch("runtime_instance_id"));
    }
    if response.instance_key_id != verifier.instance_key_id {
        return Err(issuance_binding_mismatch("instance_key_id"));
    }
    let expected_receipt_api_url = target_origin
        .join(VP_VERIFICATION_RECEIPT_PATH)
        .map_err(|_| issuance_binding_mismatch("receipt_api_url"))?;
    if response.receipt_api_url != expected_receipt_api_url.as_str() {
        return Err(issuance_binding_mismatch("receipt_api_url"));
    }
    let ui_url_diagnostic =
        issuance_url_diagnostic("verification_ui_url", &response.verification_ui_url);
    let capability = Zeroizing::new(
        validate_evidence_urls(
            &response.verification_ui_url,
            &response.receipt_api_url,
            target_origin,
        )
        .map_err(|_| OpenId4VpError::EvidenceUrlDiagnostic(Box::new(ui_url_diagnostic.clone())))?,
    );
    let capability_sha256 =
        nazo_operator_protocol::openid4vp_verification_capability_sha256(&capability)
            .map_err(|_| issuance_binding_mismatch("capability_sha256"))?;
    let protocol_context = protocol_evidence_context(&response.evidence_context);
    let evidence_context_sha256 =
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&protocol_context)
            .map_err(|_| issuance_binding_mismatch("context_sha256"))?;
    let receipt_id = response.receipt_id.to_string();
    let transaction_id = response.transaction_id.to_string();
    let expected = nazo_operator_protocol::Openid4vpVerificationReceiptExpectations {
        issuer: &response.issuer,
        audience: &response.receipt_api_url,
        deployment_id: &verifier.deployment_id,
        runtime_instance_id: &verifier.runtime_instance_id,
        instance_key_id: &verifier.instance_key_id,
        tenant_id: &verifier.tenant_id,
        transaction_id: &transaction_id,
        receipt_id: &receipt_id,
        issuance_request_jti,
        evidence_context_sha256: &evidence_context_sha256,
        presentation_binding_sha256: &attachment.presentation_binding_sha256,
        intent_sha256: &attachment.intent_sha256,
        capability_sha256: &capability_sha256,
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let receipt = nazo_operator_protocol::verify_openid4vp_verification_receipt(
        &response.receipt_jws,
        &expected,
        &verifier.instance_public_key,
        now,
    )
    .map_err(|_| issuance_binding_mismatch("receipt_jws"))?;
    if receipt.schema != response.schema
        || receipt.completed_at != response.completed_at
        || receipt.tenant_id != response.tenant_id
        || receipt.issuance_request_jti != response.issuance_request_jti
        || receipt.presentation_binding != response.presentation_binding
        || receipt.intent_sha256 != response.intent_sha256
    {
        return Err(issuance_binding_mismatch("receipt_jws_claims"));
    }
    validate_evidence_window(
        &response.completed_at,
        &response.expires_at,
        receipt.iat,
        receipt.exp,
        response.verification_ttl_seconds,
    )
    .map_err(|_| issuance_binding_mismatch("receipt_window"))?;
    Ok(OpenId4VpVerificationEvidence {
        receipt: OpenId4VpVerificationReceiptProvenance {
            issuer: response.issuer,
            receipt_api_url: response.receipt_api_url,
            receipt_id: response.receipt_id,
            transaction_id: response.transaction_id,
            tenant_id: response.tenant_id,
            issuance_request_jti: issuance_request_jti.to_owned(),
            presentation_binding_sha256: attachment.presentation_binding_sha256.clone(),
            intent_sha256: attachment.intent_sha256.clone(),
            receipt_jws: response.receipt_jws,
            receipt_sha256: response.receipt_sha256,
            capability_sha256,
            deployment_id: verifier.deployment_id.clone(),
            runtime_instance_id: verifier.runtime_instance_id.clone(),
            instance_key_id: verifier.instance_key_id.clone(),
            instance_public_key_base64: verifier.instance_public_key_base64.clone(),
            completed_at: response.completed_at,
            expires_at: response.expires_at,
        },
        context: response.evidence_context,
        ui_url_diagnostic,
        ui_url: Zeroizing::new(response.verification_ui_url),
    })
}

fn protocol_evidence_context(
    context: &OpenId4VpEvidenceContext,
) -> nazo_operator_protocol::Openid4vpEvidenceContext {
    nazo_operator_protocol::Openid4vpEvidenceContext {
        run_jti: context.run_jti.clone(),
        artifact_sha256: context.artifact_sha256.clone(),
        matrix_sha256: context.matrix_sha256.clone(),
        suite_plan_id: context.suite_plan_id.clone(),
        suite_module_id: context.suite_module_id.clone(),
        test_name: context.test_name.clone(),
        variant_sha256: context.variant_sha256.clone(),
    }
}

fn same_target_origin(value: &str, target: &Url) -> bool {
    Url::parse(value).is_ok_and(|candidate| {
        candidate.scheme() == target.scheme()
            && candidate.host_str() == target.host_str()
            && candidate.port_or_known_default() == target.port_or_known_default()
            && candidate.username().is_empty()
            && candidate.password().is_none()
            && candidate.query().is_none()
            && candidate.fragment().is_none()
            && matches!(candidate.path(), "" | "/")
    })
}

fn validate_evidence_urls(
    ui_url: &str,
    receipt_api_url: &str,
    target: &Url,
) -> Result<String, OpenId4VpError> {
    let ui_url = Url::parse(ui_url).map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?;
    let api_url =
        Url::parse(receipt_api_url).map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?;
    let valid_origin = |url: &Url| {
        url.scheme() == target.scheme()
            && url.host_str() == target.host_str()
            && url.port_or_known_default() == target.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
    };
    if !valid_origin(&ui_url)
        || ui_url.path() != VP_VERIFICATION_RESULT_PATH
        || ui_url.query().is_some()
        || !valid_origin(&api_url)
        || api_url.path() != VP_VERIFICATION_RECEIPT_PATH
        || api_url.query().is_some()
        || api_url.fragment().is_some()
    {
        return Err(OpenId4VpError::EvidenceBindingMismatch);
    }
    let fragment = ui_url
        .fragment()
        .ok_or(OpenId4VpError::EvidenceBindingMismatch)?;
    let Some(capability) = fragment.strip_prefix("receipt=") else {
        return Err(OpenId4VpError::EvidenceBindingMismatch);
    };
    if capability.len() != 43
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || capability.contains('&')
        || capability.contains('=')
    {
        return Err(OpenId4VpError::EvidenceBindingMismatch);
    }
    Ok(capability.to_owned())
}

fn validate_evidence_window(
    completed_at: &str,
    expires_at: &str,
    issued_at: i64,
    expires_at_epoch: i64,
    verification_ttl_seconds: u64,
) -> Result<(), OpenId4VpError> {
    use time::format_description::well_known::Rfc3339;
    let parse_canonical = |value: &str| {
        let parsed = time::OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?;
        if parsed
            .format(&Rfc3339)
            .map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?
            != value
        {
            return Err(OpenId4VpError::EvidenceBindingMismatch);
        }
        Ok(parsed)
    };
    let completed_at = parse_canonical(completed_at)?;
    let expires_at = parse_canonical(expires_at)?;
    let issued_at = time::OffsetDateTime::from_unix_timestamp(issued_at)
        .map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?;
    let expires_at_jwt = time::OffsetDateTime::from_unix_timestamp(expires_at_epoch)
        .map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?;
    let now = time::OffsetDateTime::now_utc();
    if !(1..=600).contains(&verification_ttl_seconds)
        || expires_at <= completed_at
        || completed_at > issued_at
        || expires_at_jwt != expires_at
        || expires_at_jwt <= issued_at
        || expires_at_epoch - issued_at.unix_timestamp()
            != i64::try_from(verification_ttl_seconds)
                .map_err(|_| OpenId4VpError::EvidenceBindingMismatch)?
        || expires_at_jwt <= now
        || issued_at > now + time::Duration::minutes(5)
        || completed_at > now + time::Duration::minutes(5)
    {
        return Err(OpenId4VpError::EvidenceBindingMismatch);
    }
    Ok(())
}

/// Safe-only evidence-binding discriminator retained with a failed run.  The
/// actual values (including compact JWSes, URLs, and management tokens) never
/// cross this boundary.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct OpenId4VpEvidenceBindingDiagnostic {
    pub stage: &'static str,
    pub field: &'static str,
}

impl std::fmt::Display for OpenId4VpEvidenceBindingDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "stage={} field={}", self.stage, self.field)
    }
}

/// Safe parse-boundary metadata for a capability-bearing verification UI URL.
/// The raw URL and its fragment never cross this diagnostic boundary.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenId4VpEvidenceUrlDiagnostic {
    pub stage: &'static str,
    pub field: &'static str,
    pub authority_has_at: bool,
    pub canonical_origin: Option<String>,
    pub canonical_path: Option<String>,
    pub fragment_len: Option<usize>,
    pub fragment_sha256: Option<String>,
    pub capability_sha256: Option<String>,
}

impl std::fmt::Display for OpenId4VpEvidenceUrlDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "stage={} field={} authority_has_at={} canonical_origin={} canonical_path={} fragment_len={} fragment_sha256={} capability_sha256={}",
            self.stage,
            self.field,
            self.authority_has_at,
            self.canonical_origin.as_deref().unwrap_or("none"),
            self.canonical_path.as_deref().unwrap_or("none"),
            self.fragment_len
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("none"),
            self.fragment_sha256.as_deref().unwrap_or("none"),
            self.capability_sha256.as_deref().unwrap_or("none"),
        )
    }
}

fn raw_url_authority_has_at(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
}

fn issuance_url_diagnostic(field: &'static str, value: &str) -> OpenId4VpEvidenceUrlDiagnostic {
    let parsed = Url::parse(value).ok();
    let fragment = parsed.as_ref().and_then(|url| url.fragment());
    let capability_sha256 = fragment
        .and_then(|fragment| fragment.strip_prefix("receipt="))
        .and_then(|capability| {
            nazo_operator_protocol::openid4vp_verification_capability_sha256(capability).ok()
        });
    OpenId4VpEvidenceUrlDiagnostic {
        stage: "issuance",
        field,
        authority_has_at: raw_url_authority_has_at(value),
        canonical_origin: parsed
            .as_ref()
            .map(|url| url.origin().ascii_serialization()),
        canonical_path: parsed.as_ref().map(|url| url.path().to_owned()),
        fragment_len: fragment.map(str::len),
        fragment_sha256: fragment.map(|fragment| sha256_hex(fragment.as_bytes())),
        capability_sha256,
    }
}

fn attach_binding_mismatch(field: &'static str) -> OpenId4VpError {
    OpenId4VpError::EvidenceBindingDiagnostic(OpenId4VpEvidenceBindingDiagnostic {
        stage: "attach",
        field,
    })
}

fn issuance_binding_mismatch(field: &'static str) -> OpenId4VpError {
    OpenId4VpError::EvidenceBindingDiagnostic(OpenId4VpEvidenceBindingDiagnostic {
        stage: "issuance",
        field,
    })
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum OpenId4VpError {
    #[error("OpenID4VP verifier input is invalid")]
    InvalidInput,
    #[error("OpenID4VP conformance binding is invalid")]
    InvalidBinding,
    #[error("OpenID4VP conformance binding does not match the verifier client")]
    BindingMismatch,
    #[error("OpenID4VP credential format is unsupported")]
    UnsupportedCredentialFormat,
    #[error("OpenID4VP request method is unsupported")]
    UnsupportedRequestMethod,
    #[error("OpenID4VP verifier transport failed")]
    Transport(TransportError),
    #[error("OpenID4VP verifier returned an unexpected status")]
    UnexpectedStatus,
    #[error("OpenID4VP verifier response is malformed")]
    MalformedResponse,
    #[error("OpenID4VP authorization URL crossed the browser allowlist")]
    CrossOriginNavigation,
    #[error("OpenID4VP wallet returned an unexpected authorization redirect")]
    UnexpectedAuthorizationRedirect,
    #[error("OpenID4VP verifier completion endpoint failed")]
    CompletionFailed,
    #[error("OpenID4VP verification evidence context is invalid")]
    InvalidEvidenceContext,
    #[error("OpenID4VP verification evidence is unavailable")]
    EvidenceUnavailable,
    #[error("OpenID4VP verification evidence is temporarily unavailable")]
    EvidenceTemporarilyUnavailable,
    #[error("OpenID4VP verification evidence returned an unexpected status")]
    UnexpectedEvidenceStatus,
    #[error("OpenID4VP verification evidence response is malformed")]
    MalformedEvidenceResponse,
    #[error("OpenID4VP verification evidence receipt is malformed")]
    MalformedEvidenceReceipt,
    #[error("OpenID4VP verification evidence does not match this run")]
    EvidenceBindingMismatch,
    #[error("OpenID4VP verification evidence does not match this run [{0}]")]
    EvidenceBindingDiagnostic(OpenId4VpEvidenceBindingDiagnostic),
    #[error("OpenID4VP verification evidence URL is invalid [{0}]")]
    EvidenceUrlDiagnostic(Box<OpenId4VpEvidenceUrlDiagnostic>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{HttpResponse, TransportError, TransportFailureStage};
    use std::collections::VecDeque;

    #[test]
    fn evidence_window_starts_when_the_receipt_is_issued() {
        use time::format_description::well_known::Rfc3339;

        let issued_at = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("whole-second issuance time");
        let completed_at = issued_at - time::Duration::seconds(1);
        let expires_at = issued_at + time::Duration::seconds(600);

        assert!(
            validate_evidence_window(
                &completed_at.format(&Rfc3339).expect("completion time"),
                &expires_at.format(&Rfc3339).expect("expiry time"),
                issued_at.unix_timestamp(),
                expires_at.unix_timestamp(),
                600,
            )
            .is_ok(),
            "a receipt issued after verification owns its own bounded lifetime"
        );
    }

    #[test]
    fn evidence_window_rejects_completion_after_receipt_issuance() {
        use time::format_description::well_known::Rfc3339;

        let issued_at = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("whole-second issuance time");
        let completed_at = issued_at + time::Duration::seconds(1);
        let expires_at = issued_at + time::Duration::seconds(600);

        assert!(
            validate_evidence_window(
                &completed_at.format(&Rfc3339).expect("completion time"),
                &expires_at.format(&Rfc3339).expect("expiry time"),
                issued_at.unix_timestamp(),
                expires_at.unix_timestamp(),
                600,
            )
            .is_err()
        );
    }

    struct VerifierTransport {
        request: std::sync::Mutex<Option<HttpRequest>>,
        response: std::sync::Mutex<Option<HttpResponse>>,
    }

    impl Transport for VerifierTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let mut response = self
                .response
                .lock()
                .expect("response lock")
                .take()
                .ok_or(TransportError::Network(TransportFailureStage::SendRequest))?;
            bind_test_create_response(&request, &mut response);
            *self.request.lock().expect("request lock") = Some(request);
            Ok(response)
        }
    }

    struct CompletionTransport {
        requests: std::sync::Mutex<Vec<HttpRequest>>,
        responses: std::sync::Mutex<VecDeque<HttpResponse>>,
    }

    impl Transport for CompletionTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let mut response = self
                .responses
                .lock()
                .expect("response lock")
                .pop_front()
                .ok_or(TransportError::Network(TransportFailureStage::SendRequest))?;
            bind_test_create_response(&request, &mut response);
            self.requests.lock().expect("request lock").push(request);
            Ok(response)
        }
    }

    fn bind_test_create_response(request: &HttpRequest, response: &mut HttpResponse) {
        if request.url().path() != "/openid4vp/presentations"
            || !(200..300).contains(&response.status)
        {
            return;
        }
        let request_body: Value =
            serde_json::from_slice(request.body().expect("create body")).expect("create body JSON");
        let response_body: Value = serde_json::from_slice(&response.body).expect("create JSON");
        let mut response_body = response_body.as_object().expect("create object").clone();
        if response_body.contains_key("create_request_jti")
            || response_body.contains_key("create_request_sha256")
        {
            return;
        }
        let normalized = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
            wallet_authorization_endpoint: request_body["wallet_authorization_endpoint"]
                .as_str()
                .expect("wallet endpoint")
                .to_owned(),
            dcql_query: request_body["dcql_query"].clone(),
            haip: request_body["haip"].as_bool().expect("haip"),
            client_id_prefix: request_body["client_id_prefix"]
                .as_str()
                .expect("client id prefix")
                .to_owned(),
            request_method: request_body["request_method"]
                .as_str()
                .expect("request method")
                .to_owned(),
            response_mode: request_body["response_mode"]
                .as_str()
                .expect("response mode")
                .to_owned(),
            transaction_data: request_body
                .get("transaction_data")
                .filter(|value| !value.is_null())
                .map(|value| serde_json::from_value(value.clone()).expect("transaction data")),
            openid4vc_trust_policy_resource_id: request_body
                .get("openid4vc_trust_policy_resource_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            openid4vc_trust_policy_digest: request_body
                .get("openid4vc_trust_policy_digest")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        let (_, create_request_sha256) =
            nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
                .expect("canonical create request");
        response_body.insert(
            "create_request_jti".to_owned(),
            request_body["create_request_jti"].clone(),
        );
        response_body.insert(
            "create_request_sha256".to_owned(),
            Value::String(create_request_sha256),
        );
        response.body = serde_json::to_vec(&response_body).expect("bound create JSON");
    }

    fn binding() -> ConformanceBinding {
        trust_policy_binding()
    }

    fn trust_policy_binding() -> ConformanceBinding {
        ConformanceBinding::openid4vc_trust_policy(
            "openid4vc-trust-policy:provider:0123456789abcdef",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("trust policy binding")
    }

    #[test]
    fn signed_attachment_trust_projection_must_match_the_local_create_binding() {
        let expected =
            ExpectedTrustPolicyBinding::from_conformance_binding(&trust_policy_binding());
        let exact = nazo_operator_protocol::Openid4vpTrustPolicyBinding {
            binding_id: Some("550e8400-e29b-41d4-a716-446655440007".to_owned()),
            resource_id: Some("openid4vc-trust-policy:provider:0123456789abcdef".to_owned()),
            resource_digest: Some("a".repeat(64)),
        };
        assert!(expected.matches(&exact));

        let none = nazo_operator_protocol::Openid4vpTrustPolicyBinding {
            binding_id: None,
            resource_id: None,
            resource_digest: None,
        };
        assert!(!expected.matches(&none));
        let mut wrong_resource = exact.clone();
        wrong_resource.resource_id = Some("openid4vc-trust-policy:provider:other".to_owned());
        assert!(!expected.matches(&wrong_resource));
        let mut wrong_digest = exact.clone();
        wrong_digest.resource_digest = Some("b".repeat(64));
        assert!(!expected.matches(&wrong_digest));
        let mut missing_binding_id = exact;
        missing_binding_id.binding_id = None;
        assert!(!expected.matches(&missing_binding_id));

        assert!(
            !expected.matches(&nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: None,
                resource_id: None,
                resource_digest: None,
            })
        );
    }

    #[test]
    fn evidence_binding_diagnostics_identify_only_safe_stage_and_field() {
        let attach = attach_binding_mismatch("trust_policy");
        assert_eq!(
            attach,
            OpenId4VpError::EvidenceBindingDiagnostic(OpenId4VpEvidenceBindingDiagnostic {
                stage: "attach",
                field: "trust_policy",
            })
        );
        let issuance = issuance_binding_mismatch("receipt_jws_claims");
        assert!(issuance.to_string().contains("stage=issuance"));
        assert!(issuance.to_string().contains("field=receipt_jws_claims"));
        assert!(!issuance.to_string().contains("eyJ"));
    }

    #[test]
    fn issuance_url_diagnostic_redacts_fragment_but_retains_parse_boundary_metadata() {
        let capability = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        assert_eq!(capability.len(), 43);
        let diagnostic = issuance_url_diagnostic(
            "verification_ui_url",
            &format!(
                "https://unexpected@issuer.example/ui/verification-result#receipt={capability}"
            ),
        );
        assert_eq!(diagnostic.stage, "issuance");
        assert_eq!(diagnostic.field, "verification_ui_url");
        assert!(diagnostic.authority_has_at);
        assert_eq!(
            diagnostic.canonical_origin.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(
            diagnostic.canonical_path.as_deref(),
            Some(VP_VERIFICATION_RESULT_PATH)
        );
        assert_eq!(
            diagnostic.fragment_len,
            Some("receipt=".len() + capability.len())
        );
        let expected_capability_sha256 =
            nazo_operator_protocol::openid4vp_verification_capability_sha256(capability)
                .expect("capability hash");
        assert_eq!(
            diagnostic.capability_sha256.as_deref(),
            Some(expected_capability_sha256.as_str())
        );
        let rendered = diagnostic.to_string();
        assert!(!rendered.contains(capability));
        assert!(!rendered.contains("unexpected@"));
    }

    struct RetryingCreateTransport {
        request_bodies: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl Transport for RetryingCreateTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let body = request.body().expect("create body").to_vec();
            let mut request_bodies = self.request_bodies.lock().expect("request lock");
            request_bodies.push(body);
            if request_bodies.len() == 1 {
                return Err(TransportError::Network(TransportFailureStage::ReadBody));
            }
            let mut response = HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "expires_in": 300,
                }))
                .expect("response"),
            };
            bind_test_create_response(&request, &mut response);
            Ok(response)
        }
    }

    #[test]
    fn create_response_loss_retries_once_with_the_same_typed_idempotency_binding() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(RetryingCreateTransport {
            request_bodies: std::sync::Mutex::new(Vec::new()),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let request = OpenId4VpStartRequest::new("vp", "happy", BTreeMap::new(), false, binding())
            .expect("request");

        let presentation = client.start(&request).expect("response-loss retry");
        let request_bodies = transport.request_bodies.lock().expect("request lock");
        assert_eq!(request_bodies.len(), 2);
        let first: Value = serde_json::from_slice(&request_bodies[0]).expect("first body JSON");
        let second: Value = serde_json::from_slice(&request_bodies[1]).expect("second body JSON");
        assert_eq!(request_bodies[0], request_bodies[1]);
        assert_eq!(first["create_request_jti"], second["create_request_jti"]);
        assert_eq!(
            first["create_request_jti"],
            Value::String(presentation.create_request_jti)
        );
        assert!(
            nazo_operator_protocol::validate_openid4vp_create_request_jti(
                first["create_request_jti"].as_str().expect("create JTI")
            )
            .is_ok()
        );
    }

    #[test]
    fn create_rejects_response_with_a_nonmatching_idempotency_binding() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "create_request_jti": "550e8400-e29b-41d4-a716-446655440000",
                    "create_request_sha256": "a".repeat(64),
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "expires_in": 300,
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            binding(),
        )
        .expect("client");
        let request = OpenId4VpStartRequest::new("vp", "happy", BTreeMap::new(), false, binding())
            .expect("request");
        assert_eq!(
            client.start(&request).expect_err("mismatched echo"),
            OpenId4VpError::MalformedResponse
        );
    }

    #[test]
    fn ordinary_start_sends_only_the_exact_trust_policy_binding() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "expires_in": 300
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            trust_policy_binding(),
        )
        .expect("client");
        let request = OpenId4VpStartRequest::new(
            "vp",
            "happy",
            BTreeMap::new(),
            false,
            trust_policy_binding(),
        )
        .expect("request");

        client.start(&request).expect("start");

        let captured = transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("request");
        let body: Value = serde_json::from_slice(captured.body().expect("body")).expect("body");
        assert_eq!(
            body["openid4vc_trust_policy_resource_id"],
            "openid4vc-trust-policy:provider:0123456789abcdef"
        );
        assert_eq!(
            body["openid4vc_trust_policy_digest"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(body.get("conformance_lease_id").is_none());
        assert!(body.get("conformance_task_jti").is_none());
    }

    #[test]
    fn create_never_sends_evidence_context_before_actual_browser_entry_selection() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "expires_in": 300
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            trust_policy_binding(),
        )
        .expect("client");
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let request = OpenId4VpStartRequest::new(
            "vp",
            "happy",
            variant.clone(),
            false,
            trust_policy_binding(),
        )
        .expect("request");
        let presentation = client.start(&request).expect("start");
        let body: Value = serde_json::from_slice(
            transport
                .request
                .lock()
                .expect("request lock")
                .as_ref()
                .expect("request")
                .body()
                .expect("body"),
        )
        .expect("body json");
        assert!(body.get("evidence_context").is_none());
        assert!(!format!("{presentation:?}").contains("receipt="));
    }

    #[test]
    fn attaches_exact_opaque_suite_identifier_context_after_start_returns_the_transaction() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transaction_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("transaction ID");
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let context = OpenId4VpEvidenceRunContext::new(
            "request-0123456789abcdef0123456789abcdef",
            "a".repeat(64),
            "b".repeat(64),
        )
        .expect("run context")
        .for_module("suite-plan-01", "module-item-001", "happy", &variant)
        .expect("module context");
        let expected_context_sha256 =
            nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(
                &protocol_evidence_context(&context),
            )
            .expect("context digest");
        let signing = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let verifying = signing.verifying_key();
        let key_id = nazo_operator_protocol::instance_key_id(&verifying);
        let runtime_verifier = OpenId4VpEvidenceVerifier::new(
            "deployment-a",
            "00000000-0000-4000-8000-000000000001",
            "runtime-a",
            key_id.clone(),
            verifying,
        )
        .expect("runtime verifier");
        let presentation_binding = nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256: "d".repeat(64),
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: Some("550e8400-e29b-41d4-a716-446655440007".to_owned()),
                resource_id: Some("openid4vc-trust-policy:provider:0123456789abcdef".to_owned()),
                resource_digest: Some("a".repeat(64)),
            },
        };
        let presentation_binding_sha256 =
            nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                &presentation_binding,
            )
            .expect("presentation binding digest");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let intent = nazo_operator_protocol::Openid4vpVerificationIntent {
            schema: 1,
            iss: "https://issuer.example".to_owned(),
            aud: "https://issuer.example/openid4vp/verification-intents".to_owned(),
            jti: transaction_id.to_string(),
            iat: now,
            exp: now + 300,
            deployment_id: "deployment-a".to_owned(),
            runtime_instance_id: "runtime-a".to_owned(),
            instance_key_id: key_id.clone(),
            tenant_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            transaction_id: transaction_id.to_string(),
            evidence_context: protocol_evidence_context(&context),
            presentation_binding: presentation_binding.clone(),
        };
        let intent_jws =
            nazo_operator_protocol::sign_openid4vp_verification_intent(&intent, &key_id, &signing)
                .expect("signed intent");
        let intent_sha256 = nazo_operator_protocol::compact_sha256(&intent_jws);
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([
                HttpResponse {
                    status: 201,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                        "transaction_id": transaction_id,
                        "expires_in": 300,
                    }))
                    .expect("start response"),
                },
                HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "schema": 1,
                        "transaction_id": transaction_id,
                        "status": "attached",
                        "evidence_context_sha256": expected_context_sha256,
                        "presentation_binding": presentation_binding,
                        "presentation_binding_sha256": presentation_binding_sha256,
                        "intent_jws": intent_jws,
                        "intent_sha256": intent_sha256,
                    }))
                    .expect("attach response"),
                },
            ])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            trust_policy_binding(),
        )
        .expect("client")
        .with_evidence_verifier(runtime_verifier);
        let request =
            OpenId4VpStartRequest::new("vp", "happy", variant, false, trust_policy_binding())
                .expect("request");
        let mut presentation = client.start(&request).expect("start");
        client
            .attach_evidence_context(&mut presentation, context.clone())
            .expect("attach");
        let requests = transport.requests.lock().expect("request lock");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.path(), "/openid4vp/presentations");
        assert_eq!(
            requests[1].url.path(),
            "/openid4vp/verification/550e8400-e29b-41d4-a716-446655440000/evidence-context"
        );
        assert_eq!(requests[1].method, HttpMethod::Post);
        let attach: Value =
            serde_json::from_slice(requests[1].body().expect("attach body")).expect("attach JSON");
        assert_eq!(attach["schema"], 1);
        assert_eq!(attach["evidence_context"]["suite_plan_id"], "suite-plan-01");
        assert_eq!(
            attach["evidence_context"]["suite_module_id"],
            "module-item-001"
        );
        assert!(attach.get("capability").is_none());
        assert_eq!(presentation.evidence_context, Some(context));
        assert!(
            presentation
                .issuance_request_jti
                .as_deref()
                .is_some_and(|value| Uuid::parse_str(value).is_ok())
        );
    }

    #[test]
    fn evidence_context_uses_the_protocol_opaque_suite_identifier_contract() {
        let variant = BTreeMap::new();
        let context = OpenId4VpEvidenceContext::new(
            "request-0123456789abcdef0123456789abcdef",
            "a".repeat(64),
            "b".repeat(64),
            "suite-plan-01",
            "module-item-001",
            "happy",
            &variant,
        )
        .expect("official opaque IDs");
        assert_eq!(context.suite_plan_id.len(), 13);
        assert_eq!(context.suite_module_id.len(), 15);

        assert_eq!(
            OpenId4VpEvidenceContext::new(
                "request-0123456789abcdef0123456789abcdef",
                "a".repeat(64),
                "b".repeat(64),
                "suite/plan",
                "module-item-001",
                "happy",
                &variant,
            ),
            Err(OpenId4VpError::InvalidEvidenceContext)
        );
        assert_eq!(
            OpenId4VpEvidenceContext::new(
                "request-0123456789abcdef0123456789abcdef",
                "a".repeat(64),
                "b".repeat(64),
                "s".repeat(129),
                "module-item-001",
                "happy",
                &variant,
            ),
            Err(OpenId4VpError::InvalidEvidenceContext)
        );
    }

    #[test]
    fn evidence_create_response_rejects_a_premature_capability() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "verification_ui_url": "https://issuer.example/ui/verification-result#receipt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            trust_policy_binding(),
        )
        .expect("client");
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let request =
            OpenId4VpStartRequest::new("vp", "happy", variant, false, trust_policy_binding())
                .expect("request");
        match client.start(&request) {
            Err(error) => assert_eq!(error, OpenId4VpError::MalformedResponse),
            Ok(_) => panic!("premature capability was accepted"),
        }
    }

    #[test]
    fn evidence_capability_is_issued_only_after_completion_through_the_bounded_post_endpoint() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            })),
        });
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let verifying = signing.verifying_key();
        let key_id = nazo_operator_protocol::instance_key_id(&verifying);
        let verifier = OpenId4VpEvidenceVerifier::new(
            "deployment-a",
            "00000000-0000-4000-8000-000000000001",
            "runtime-a",
            key_id,
            verifying,
        )
        .expect("runtime verifier");
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            trust_policy_binding(),
        )
        .expect("client")
        .with_evidence_verifier(verifier);
        let variant = BTreeMap::new();
        let evidence_context = OpenId4VpEvidenceRunContext::new(
            "request-0123456789abcdef0123456789abcdef",
            "a".repeat(64),
            "b".repeat(64),
        )
        .expect("run")
        .for_module(
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
            "happy",
            &variant,
        )
        .expect("context");
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse("https://suite.example/test/a/vp/authorize?x=1")
                .expect("authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
            )
            .expect("completion URL"),
            transaction_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("transaction ID"),
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: Some(evidence_context),
            evidence_attachment: Some(OpenId4VpEvidenceAttachment {
                presentation_binding_sha256: "d".repeat(64),
                intent_sha256: "e".repeat(64),
            }),
            issuance_request_jti: Some("550e8400-e29b-41d4-a716-446655440004".to_owned()),
            immediate_rejection_allowed: false,
        };
        assert_eq!(
            OpenId4VpVerifier::verification_evidence(&mut client, &presentation)
                .expect_err("pending issuance"),
            OpenId4VpError::EvidenceUnavailable
        );
        let request = transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("issuance request");
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(
            request.url.path(),
            "/openid4vp/verification/550e8400-e29b-41d4-a716-446655440000/receipt-capability"
        );
        let body: Value = serde_json::from_slice(request.body().expect("issuance body"))
            .expect("issuance body JSON");
        assert_eq!(body["schema"], 1);
        assert_eq!(
            body["issuance_request_jti"],
            "550e8400-e29b-41d4-a716-446655440004"
        );
    }

    #[test]
    fn issued_evidence_receipt_binds_the_same_new_suite_module_without_retaining_capability() {
        use time::format_description::well_known::Rfc3339;

        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let verifying = signing.verifying_key();
        let key_id = nazo_operator_protocol::instance_key_id(&verifying);
        let runtime_verifier = OpenId4VpEvidenceVerifier::new(
            "deployment-a",
            "00000000-0000-4000-8000-000000000001",
            "runtime-a",
            key_id.clone(),
            verifying,
        )
        .expect("runtime verifier");
        let variant = BTreeMap::from([("credential_format".to_owned(), "sd_jwt_vc".to_owned())]);
        let context = OpenId4VpEvidenceRunContext::new(
            "request-0123456789abcdef0123456789abcdef",
            "a".repeat(64),
            "b".repeat(64),
        )
        .expect("run")
        .for_module(
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
            "happy",
            &variant,
        )
        .expect("context");
        let transaction_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("transaction ID");
        let receipt_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440003").expect("receipt ID");
        let capability = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        let capability_sha256 =
            nazo_operator_protocol::openid4vp_verification_capability_sha256(capability)
                .expect("capability hash");
        let issuance_request_jti = "550e8400-e29b-41d4-a716-446655440004";
        let presentation_binding = nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256: "d".repeat(64),
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: None,
                resource_id: None,
                resource_digest: None,
            },
        };
        let presentation_binding_sha256 =
            nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                &presentation_binding,
            )
            .expect("presentation binding digest");
        let intent_sha256 = "e".repeat(64);
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("whole seconds");
        let expires = now + time::Duration::seconds(300);
        let completed_at = now.format(&Rfc3339).expect("completed timestamp");
        let expires_at = expires.format(&Rfc3339).expect("expiry timestamp");
        let receipt = nazo_operator_protocol::Openid4vpVerificationReceipt {
            schema: 1,
            iss: "https://issuer.example".to_owned(),
            aud: "https://issuer.example/openid4vp/verification-receipts".to_owned(),
            jti: receipt_id.to_string(),
            iat: now.unix_timestamp(),
            exp: expires.unix_timestamp(),
            deployment_id: "deployment-a".to_owned(),
            runtime_instance_id: "runtime-a".to_owned(),
            instance_key_id: key_id.clone(),
            tenant_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            transaction_id: transaction_id.to_string(),
            issuance_request_jti: issuance_request_jti.to_owned(),
            status: nazo_operator_protocol::Openid4vpVerificationStatus::Verified,
            evidence_context: protocol_evidence_context(&context),
            presentation_binding: presentation_binding.clone(),
            intent_sha256: intent_sha256.clone(),
            completed_at: completed_at.clone(),
            capability_sha256: capability_sha256.clone(),
        };
        let receipt_jws = nazo_operator_protocol::sign_openid4vp_verification_receipt(
            &receipt, &key_id, &signing,
        )
        .expect("signed receipt");
        let receipt_sha256 = sha256_hex(receipt_jws.as_bytes());
        let response = serde_json::json!({
            "schema": 1,
            "issuer": "https://issuer.example",
            "deployment_id": "deployment-a",
            "runtime_instance_id": "runtime-a",
            "instance_key_id": key_id,
            "tenant_id": "00000000-0000-4000-8000-000000000001",
            "transaction_id": transaction_id,
            "receipt_id": receipt_id,
            "issuance_request_jti": issuance_request_jti,
            "status": "verified",
            "evidence_context": context,
            "presentation_binding": presentation_binding,
            "intent_sha256": intent_sha256,
            "completed_at": completed_at,
            "expires_at": expires_at,
            "receipt_jws": receipt_jws,
            "receipt_sha256": receipt_sha256,
            "receipt_api_url": "https://issuer.example/openid4vp/verification-receipts",
            "verification_ui_url": format!(
                "https://issuer.example/ui/verification-result#receipt={capability}"
            ),
            "verification_ttl_seconds": 300,
        });
        let attachment = OpenId4VpEvidenceAttachment {
            presentation_binding_sha256: presentation_binding_sha256.clone(),
            intent_sha256: intent_sha256.clone(),
        };
        let parse = |value: Value| {
            serde_json::from_value::<VerificationEvidenceResponse>(value)
                .expect("typed evidence response")
        };
        assert!(
            verify_evidence_response(
                parse(response.clone()),
                transaction_id,
                &context,
                issuance_request_jti,
                &attachment,
                &runtime_verifier,
                target.as_url(),
            )
            .is_ok()
        );

        let mut bad_signature = response.clone();
        bad_signature["receipt_jws"] = Value::String("bad.compact.jws".to_owned());
        bad_signature["receipt_sha256"] = Value::String(sha256_hex(b"bad.compact.jws"));
        assert!(
            verify_evidence_response(
                parse(bad_signature),
                transaction_id,
                &context,
                issuance_request_jti,
                &attachment,
                &runtime_verifier,
                target.as_url(),
            )
            .is_err()
        );

        let other_signing = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let other_key_id = nazo_operator_protocol::instance_key_id(&other_signing.verifying_key());
        let mut wrong_kid_receipt = receipt.clone();
        wrong_kid_receipt.instance_key_id = other_key_id.clone();
        let wrong_kid_jws = nazo_operator_protocol::sign_openid4vp_verification_receipt(
            &wrong_kid_receipt,
            &other_key_id,
            &other_signing,
        )
        .expect("wrong-kid signed receipt");
        let mut wrong_kid = response.clone();
        wrong_kid["receipt_jws"] = Value::String(wrong_kid_jws.clone());
        wrong_kid["receipt_sha256"] = Value::String(sha256_hex(wrong_kid_jws.as_bytes()));
        assert!(
            verify_evidence_response(
                parse(wrong_kid),
                transaction_id,
                &context,
                issuance_request_jti,
                &attachment,
                &runtime_verifier,
                target.as_url(),
            )
            .is_err()
        );

        let wrong_key_verifier = OpenId4VpEvidenceVerifier::new(
            "deployment-a",
            "00000000-0000-4000-8000-000000000001",
            "runtime-a",
            other_key_id,
            other_signing.verifying_key(),
        )
        .expect("wrong runtime key verifier");
        assert!(
            verify_evidence_response(
                parse(response.clone()),
                transaction_id,
                &context,
                issuance_request_jti,
                &attachment,
                &wrong_key_verifier,
                target.as_url(),
            )
            .is_err()
        );

        let mut projection_mismatch = response.clone();
        projection_mismatch["tenant_id"] =
            Value::String("00000000-0000-4000-8000-000000000099".to_owned());
        assert_eq!(
            verify_evidence_response(
                parse(projection_mismatch),
                transaction_id,
                &context,
                issuance_request_jti,
                &attachment,
                &runtime_verifier,
                target.as_url(),
            )
            .expect_err("tenant projection mismatch"),
            issuance_binding_mismatch("tenant_id")
        );
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&response).expect("response"),
            })),
        });
        let client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            trust_policy_binding(),
        )
        .expect("client")
        .with_evidence_verifier(runtime_verifier);
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse("https://suite.example/test/a/vp/authorize?x=1")
                .expect("authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
            )
            .expect("completion URL"),
            transaction_id,
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: Some(context),
            evidence_attachment: Some(attachment),
            issuance_request_jti: Some(issuance_request_jti.to_owned()),
            immediate_rejection_allowed: false,
        };
        let evidence = client
            .verification_evidence(&presentation)
            .expect("verified evidence");
        assert_eq!(evidence.receipt.receipt_id, receipt_id);
        assert_eq!(evidence.receipt.capability_sha256, capability_sha256);
        assert_eq!(
            evidence.context.suite_module_id,
            "550e8400-e29b-41d4-a716-446655440002"
        );
        let debug = format!("{evidence:?}");
        assert!(debug.contains("ui_url: \"<redacted>\""));
        assert!(debug.contains("receipt_id"));
        assert!(!debug.contains(capability));
    }

    #[test]
    fn maps_mdoc_and_rejects_cross_origin_authorization() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://evil.example/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                    "expires_in": 300
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            binding(),
        )
        .expect("client");
        let mut variant = BTreeMap::new();
        variant.insert("credential_format".to_owned(), "iso_mdl".to_owned());
        let request =
            OpenId4VpStartRequest::new("vp", "happy", variant, true, binding()).expect("request");
        assert_eq!(
            client.start(&request).expect_err("cross origin"),
            OpenId4VpError::CrossOriginNavigation
        );
    }

    #[test]
    fn rejects_malformed_or_partial_binding() {
        assert_eq!(
            ConformanceBinding::openid4vc_trust_policy(
                "openid4vc trust policy",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect_err("invalid resource id"),
            OpenId4VpError::InvalidBinding
        );
        assert_eq!(
            ConformanceBinding::openid4vc_trust_policy(
                "openid4vc-trust-policy:provider",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .expect_err("uppercase digest"),
            OpenId4VpError::InvalidBinding
        );
    }

    #[test]
    fn rejects_binding_mismatch_before_transport() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(None),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let other_binding = ConformanceBinding::openid4vc_trust_policy(
            "openid4vc-trust-policy:provider:fedcba9876543210",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("other binding");
        let request =
            OpenId4VpStartRequest::new("vp", "happy", BTreeMap::new(), false, other_binding)
                .expect("request");
        assert_eq!(
            client.start(&request).expect_err("mismatch"),
            OpenId4VpError::BindingMismatch
        );
        assert!(transport.request.lock().expect("request lock").is_none());
    }

    #[test]
    fn completes_with_one_exact_redirect_without_browser_automation() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let completion_url = Url::parse(
            "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("completion URL");
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([
                HttpResponse {
                    status: 302,
                    headers: vec![("Location".to_owned(), completion_url.to_string())],
                    body: Vec::new(),
                },
                HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"complete".to_vec(),
                },
            ])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse(
                "https://suite.example/test/a/vp/authorize?request_uri=urn%3Aexample",
            )
            .expect("authorization URL"),
            completion_url: completion_url.clone(),
            transaction_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("transaction ID"),
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: false,
        };

        assert_eq!(
            client.complete(&presentation).expect("completion"),
            OpenId4VpCompletionOutcome::Completed
        );

        let requests = transport.requests.lock().expect("request lock");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method(), HttpMethod::Get);
        assert_eq!(requests[0].url(), &presentation.authorization_url);
        assert_eq!(requests[1].url(), &completion_url);
        assert_eq!(
            requests[0].header("Accept"),
            Some("text/html,application/xhtml+xml")
        );
    }

    #[test]
    fn negative_test_accepts_suite_2xx_after_target_immediate_rejection() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([
                HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                        "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                        "expires_in": 300
                    }))
                    .expect("start response"),
                },
                HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            ])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let request = OpenId4VpStartRequest::new(
            "vp",
            "oid4vp-1final-verifier-invalid-session-transcript",
            BTreeMap::new(),
            false,
            binding(),
        )
        .expect("request");
        let presentation = client.start(&request).expect("presentation");

        assert_eq!(
            client
                .complete(&presentation)
                .expect("immediate rejection is an expected negative outcome"),
            OpenId4VpCompletionOutcome::ExpectedImmediateRejection
        );
        assert_eq!(transport.requests.lock().expect("request lock").len(), 2);
    }

    #[test]
    fn positive_test_rejects_suite_2xx_without_completion_redirect() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
            }])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            binding(),
        )
        .expect("client");
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse("https://suite.example/test/a/vp/authorize?x=1")
                .expect("authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
            )
            .expect("completion URL"),
            transaction_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("transaction ID"),
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: false,
        };

        assert_eq!(
            client.complete(&presentation).expect_err("positive 4xx"),
            OpenId4VpError::UnexpectedAuthorizationRedirect
        );
    }

    #[test]
    fn negative_test_rejects_suite_4xx_transport_failure() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([HttpResponse {
                status: 400,
                headers: Vec::new(),
                body: Vec::new(),
            }])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport,
            binding(),
        )
        .expect("client");
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse("https://suite.example/test/a/vp/authorize?x=1")
                .expect("authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
            )
            .expect("completion URL"),
            transaction_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("transaction ID"),
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: true,
        };

        assert_eq!(
            client.complete(&presentation).expect_err("Suite 4xx"),
            OpenId4VpError::UnexpectedAuthorizationRedirect
        );
    }

    #[test]
    fn rejects_redirect_not_bound_to_the_created_transaction() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(CompletionTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from([HttpResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://issuer.example/openid4vp/complete/00000000-0000-0000-0000-000000000000"
                        .to_owned(),
                )],
                body: Vec::new(),
            }])),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let presentation = OpenId4VpPresentation {
            authorization_url: Url::parse("https://suite.example/test/a/vp/authorize?x=1")
                .expect("authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000",
            )
            .expect("completion URL"),
            transaction_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
                .expect("transaction ID"),
            create_request_jti: "550e8400-e29b-41d4-a716-446655440006".to_owned(),
            expected_trust_policy: ExpectedTrustPolicyBinding::from_conformance_binding(
                &trust_policy_binding(),
            ),
            evidence_context: None,
            evidence_attachment: None,
            issuance_request_jti: None,
            immediate_rejection_allowed: false,
        };

        assert_eq!(
            client
                .complete(&presentation)
                .expect_err("redirect mismatch"),
            OpenId4VpError::UnexpectedAuthorizationRedirect
        );
        assert_eq!(transport.requests.lock().expect("request lock").len(), 1);
    }
}
