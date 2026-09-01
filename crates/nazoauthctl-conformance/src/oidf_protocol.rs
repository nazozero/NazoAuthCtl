use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

pub use nazo_operator_protocol::*;

const RECEIPT_JWS_TYPE: &str = "nazoauth-openid4vp-verification-receipt+jwt";
const INTENT_JWS_TYPE: &str = "nazoauth-openid4vp-verification-intent+jwt";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpEvidenceContext {
    pub run_jti: String,
    pub artifact_sha256: String,
    pub matrix_sha256: String,
    pub suite_plan_id: String,
    pub suite_module_id: String,
    pub test_name: String,
    pub variant_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpAttachEvidenceRequest {
    pub schema: u32,
    pub evidence_context: Openid4vpEvidenceContext,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Openid4vpEvidenceAttachmentStatus {
    Attached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpAttachEvidenceResponse {
    pub schema: u32,
    pub transaction_id: String,
    pub status: Openid4vpEvidenceAttachmentStatus,
    pub evidence_context_sha256: String,
    pub presentation_binding: Openid4vpPresentationBinding,
    pub presentation_binding_sha256: String,
    pub intent_jws: String,
    pub intent_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpTrustPolicyBinding {
    pub binding_id: Option<String>,
    pub resource_id: Option<String>,
    pub resource_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpPresentationBinding {
    pub presentation_request_sha256: String,
    pub trust_policy: Openid4vpTrustPolicyBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpIssueVerificationReceiptRequest {
    pub schema: u32,
    pub issuance_request_jti: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Openid4vpVerificationStatus {
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpVerificationReceipt {
    pub schema: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub tenant_id: String,
    pub transaction_id: String,
    pub issuance_request_jti: String,
    pub status: Openid4vpVerificationStatus,
    pub evidence_context: Openid4vpEvidenceContext,
    pub presentation_binding: Openid4vpPresentationBinding,
    pub intent_sha256: String,
    pub completed_at: String,
    pub capability_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpVerificationIntent {
    pub schema: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub tenant_id: String,
    pub transaction_id: String,
    pub evidence_context: Openid4vpEvidenceContext,
    pub presentation_binding: Openid4vpPresentationBinding,
}

pub struct Openid4vpVerificationReceiptExpectations<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub deployment_id: &'a str,
    pub runtime_instance_id: &'a str,
    pub instance_key_id: &'a str,
    pub tenant_id: &'a str,
    pub transaction_id: &'a str,
    pub receipt_id: &'a str,
    pub issuance_request_jti: &'a str,
    pub evidence_context_sha256: &'a str,
    pub presentation_binding_sha256: &'a str,
    pub intent_sha256: &'a str,
    pub capability_sha256: &'a str,
}

pub struct Openid4vpVerificationIntentExpectations<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub deployment_id: &'a str,
    pub runtime_instance_id: &'a str,
    pub instance_key_id: &'a str,
    pub tenant_id: &'a str,
    pub transaction_id: &'a str,
    pub evidence_context_sha256: &'a str,
    pub presentation_binding_sha256: &'a str,
}

pub fn canonical_openid4vp_evidence_context_sha256(
    context: &Openid4vpEvidenceContext,
) -> Result<String, ProtocolError> {
    validate_evidence_context(context)?;
    let bytes = serde_json::to_vec(context).map_err(|_| ProtocolError::Json)?;
    Ok(hex_sha256(&bytes))
}

pub fn canonical_openid4vp_presentation_binding_sha256(
    binding: &Openid4vpPresentationBinding,
) -> Result<String, ProtocolError> {
    validate_presentation_binding(binding)?;
    let bytes = serde_json::to_vec(binding).map_err(|_| ProtocolError::Json)?;
    Ok(hex_sha256(&bytes))
}

pub fn openid4vp_verification_capability_sha256(capability: &str) -> Result<String, ProtocolError> {
    if capability.len() != 43
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VP verification capability",
        ));
    }
    let mut binding = b"nazoauth-openid4vp-verification-capability-v1\0".to_vec();
    binding.extend_from_slice(capability.as_bytes());
    Ok(hex_sha256(&binding))
}

pub fn verify_openid4vp_verification_receipt(
    compact: &str,
    expected: &Openid4vpVerificationReceiptExpectations<'_>,
    key: &VerifyingKey,
    now: i64,
) -> Result<Openid4vpVerificationReceipt, ProtocolError> {
    let receipt: Openid4vpVerificationReceipt =
        verify_compact(compact, expected.instance_key_id, RECEIPT_JWS_TYPE, key)?;
    validate_receipt(&receipt)?;
    let context_sha256 = canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context)?;
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding)?;
    if receipt.iss != expected.issuer
        || receipt.aud != expected.audience
        || receipt.deployment_id != expected.deployment_id
        || receipt.runtime_instance_id != expected.runtime_instance_id
        || receipt.instance_key_id != expected.instance_key_id
        || receipt.tenant_id != expected.tenant_id
        || receipt.transaction_id != expected.transaction_id
        || receipt.jti != expected.receipt_id
        || receipt.issuance_request_jti != expected.issuance_request_jti
        || context_sha256 != expected.evidence_context_sha256
        || presentation_binding_sha256 != expected.presentation_binding_sha256
        || receipt.intent_sha256 != expected.intent_sha256
        || receipt.capability_sha256 != expected.capability_sha256
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt binding does not match expectations",
        ));
    }
    if now < receipt.iat || now >= receipt.exp {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt is outside its validity window",
        ));
    }
    Ok(receipt)
}

pub fn verify_openid4vp_verification_intent(
    compact: &str,
    expected: &Openid4vpVerificationIntentExpectations<'_>,
    key: &VerifyingKey,
    now: i64,
) -> Result<Openid4vpVerificationIntent, ProtocolError> {
    let intent: Openid4vpVerificationIntent =
        verify_compact(compact, expected.instance_key_id, INTENT_JWS_TYPE, key)?;
    validate_intent(&intent)?;
    let context_sha256 = canonical_openid4vp_evidence_context_sha256(&intent.evidence_context)?;
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&intent.presentation_binding)?;
    if intent.iss != expected.issuer
        || intent.aud != expected.audience
        || intent.deployment_id != expected.deployment_id
        || intent.runtime_instance_id != expected.runtime_instance_id
        || intent.instance_key_id != expected.instance_key_id
        || intent.tenant_id != expected.tenant_id
        || intent.transaction_id != expected.transaction_id
        || intent.jti != expected.transaction_id
        || context_sha256 != expected.evidence_context_sha256
        || presentation_binding_sha256 != expected.presentation_binding_sha256
        || now < intent.iat
        || now >= intent.exp
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent binding does not match expectations",
        ));
    }
    Ok(intent)
}

#[cfg(test)]
pub fn sign_openid4vp_verification_receipt(
    receipt: &Openid4vpVerificationReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_receipt(receipt)?;
    if receipt.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt key id does not match signer",
        ));
    }
    sign_compact(receipt, key_id, RECEIPT_JWS_TYPE, key)
}

#[cfg(test)]
pub fn sign_openid4vp_verification_intent(
    intent: &Openid4vpVerificationIntent,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_intent(intent)?;
    if intent.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent key id does not match signer",
        ));
    }
    sign_compact(intent, key_id, INTENT_JWS_TYPE, key)
}

#[cfg(test)]
fn sign_compact<T: Serialize>(
    claims: &T,
    key_id: &str,
    expected_type: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_file_identifier(key_id)?;
    #[derive(Serialize)]
    struct Header<'a> {
        alg: &'static str,
        kid: &'a str,
        typ: &'a str,
    }
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&Header {
            alg: "EdDSA",
            kid: key_id,
            typ: expected_type,
        })
        .map_err(|_| ProtocolError::Json)?,
    );
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| ProtocolError::Json)?);
    let signing_input = format!("{protected}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    let compact = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    if compact.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(compact)
}

fn verify_compact<T: DeserializeOwned>(
    compact: &str,
    expected_key_id: &str,
    expected_type: &str,
    key: &VerifyingKey,
) -> Result<T, ProtocolError> {
    validate_file_identifier(expected_key_id).map_err(|_| ProtocolError::Header)?;
    if compact.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut segments = compact.split('.');
    let protected = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let payload = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let signature = segments.next().ok_or(ProtocolError::SegmentCount)?;
    if segments.next().is_some()
        || protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
    {
        return Err(ProtocolError::SegmentCount);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        alg: String,
        kid: String,
        typ: String,
    }
    let header: Header = decode_json(protected).map_err(|_| ProtocolError::Header)?;
    if header.alg != "EdDSA" || header.kid != expected_key_id || header.typ != expected_type {
        return Err(ProtocolError::Header);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProtocolError::Base64)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ProtocolError::Signature)?;
    key.verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .map_err(|_| ProtocolError::Signature)?;
    decode_json(payload)
}

fn decode_json<T: DeserializeOwned>(encoded: &str) -> Result<T, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::Base64)?;
    serde_json::from_slice(&bytes).map_err(|_| ProtocolError::Json)
}

fn validate_receipt(receipt: &Openid4vpVerificationReceipt) -> Result<(), ProtocolError> {
    if receipt.schema != 1 {
        return Err(ProtocolError::Policy(
            "unsupported OpenID4VP verification receipt schema",
        ));
    }
    validate_issuer(&receipt.iss)?;
    validate_issuer(&receipt.aud)?;
    validate_file_identifier(&receipt.deployment_id)?;
    validate_file_identifier(&receipt.runtime_instance_id)?;
    validate_file_identifier(&receipt.instance_key_id)?;
    validate_uuid(&receipt.tenant_id)?;
    validate_uuid(&receipt.jti)?;
    validate_uuid(&receipt.transaction_id)?;
    validate_uuid(&receipt.issuance_request_jti)?;
    validate_evidence_context(&receipt.evidence_context)?;
    validate_presentation_binding(&receipt.presentation_binding)?;
    validate_lower_hex(&receipt.intent_sha256, 64)?;
    validate_lower_hex(&receipt.capability_sha256, 64)?;
    let completed_at = chrono::DateTime::parse_from_rfc3339(&receipt.completed_at)
        .map_err(|_| ProtocolError::Policy("invalid OpenID4VP receipt completion time"))?;
    let lifetime = receipt.exp.checked_sub(receipt.iat);
    if completed_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != receipt.completed_at
        || receipt.iat < 0
        || lifetime.is_none_or(|value| value <= 0 || value > 600)
        || completed_at.timestamp() > receipt.iat
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt expiry is invalid",
        ));
    }
    Ok(())
}

fn validate_intent(intent: &Openid4vpVerificationIntent) -> Result<(), ProtocolError> {
    if intent.schema != 1 {
        return Err(ProtocolError::Policy(
            "unsupported OpenID4VP verification intent schema",
        ));
    }
    validate_issuer(&intent.iss)?;
    validate_issuer(&intent.aud)?;
    validate_file_identifier(&intent.deployment_id)?;
    validate_file_identifier(&intent.runtime_instance_id)?;
    validate_file_identifier(&intent.instance_key_id)?;
    validate_uuid(&intent.tenant_id)?;
    validate_uuid(&intent.transaction_id)?;
    validate_uuid(&intent.jti)?;
    validate_evidence_context(&intent.evidence_context)?;
    validate_presentation_binding(&intent.presentation_binding)?;
    let lifetime = intent.exp.checked_sub(intent.iat);
    if intent.jti != intent.transaction_id
        || intent.iat < 0
        || lifetime.is_none_or(|value| value <= 0 || value > 600)
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent window is invalid",
        ));
    }
    Ok(())
}

fn validate_evidence_context(context: &Openid4vpEvidenceContext) -> Result<(), ProtocolError> {
    validate_file_identifier(&context.run_jti)?;
    validate_lower_hex(&context.artifact_sha256, 64)?;
    validate_lower_hex(&context.matrix_sha256, 64)?;
    validate_file_identifier(&context.suite_plan_id)?;
    validate_file_identifier(&context.suite_module_id)?;
    validate_identifier(&context.test_name)?;
    validate_lower_hex(&context.variant_sha256, 64)
}

fn validate_presentation_binding(
    binding: &Openid4vpPresentationBinding,
) -> Result<(), ProtocolError> {
    validate_lower_hex(&binding.presentation_request_sha256, 64)?;
    match (
        binding.trust_policy.binding_id.as_deref(),
        binding.trust_policy.resource_id.as_deref(),
        binding.trust_policy.resource_digest.as_deref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(binding_id), Some(resource_id), Some(resource_digest)) => {
            validate_uuid(binding_id)?;
            validate_file_identifier(resource_id)?;
            validate_lower_hex(resource_digest, 64)
        }
        _ => Err(ProtocolError::Policy(
            "OpenID4VP trust policy binding must be all present or all absent",
        )),
    }
}

fn validate_issuer(value: &str) -> Result<(), ProtocolError> {
    let host_and_path = value.strip_prefix("https://");
    if value.is_empty()
        || value.len() > 2048
        || host_and_path.is_none_or(str::is_empty)
        || host_and_path.is_some_and(|suffix| {
            suffix
                .as_bytes()
                .first()
                .is_some_and(|byte| matches!(*byte, b'/' | b'?' | b'#'))
        })
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        || value.contains('?')
        || value.contains('#')
    {
        return Err(ProtocolError::Policy("invalid OpenID4VC issuer"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
    {
        return Err(ProtocolError::Policy("invalid identifier"));
    }
    Ok(())
}

fn validate_file_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
    {
        return Err(ProtocolError::Policy("invalid file identifier"));
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(ProtocolError::Policy("invalid UUID"));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() != length
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(ProtocolError::Policy("invalid digest"));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
