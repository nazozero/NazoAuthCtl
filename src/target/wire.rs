//! HostOperation / HostResult wire contract for target transports.
//!
//! This module freezes the stdio message contract consumed by the future
//! `nazauthctl remote exec` helper (goal plan 03 §3.2 / task C04): the
//! control side serializes one bounded [`HostOperation`] to stdin, and the
//! target answers with exactly one bounded [`HostResult`] on stdout. A remote
//! executor can answer every message from this module alone — user input
//! never crosses a shell, no secret material has a field to live in, and
//! unknown content is rejected instead of interpreted.
//!
//! Contract rules (goal plan 03 / task C03):
//!
//! - closed `kind`/`status` discriminators; unknown values are rejected;
//! - `deny_unknown_fields` everywhere, explicit `schema` discriminator;
//! - hard size caps on both directions;
//! - stable failure codes in [`HostOutcome::Failed`];
//! - `operation_id` is a UUIDv7 so target journals (task C07) sort by time
//!   and can deduplicate retries via [`canonical_operation_hash`];
//! - diagnostics quote only bounded, sanitized tokens — raw payload bytes
//!   are never echoed back.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Wire schema discriminator for HostOperation and HostResult messages.
pub const HOST_PROTOCOL_SCHEMA: u32 = 1;

/// Maximum serialized HostOperation accepted from stdin or a local caller.
pub const MAX_HOST_OPERATION_BYTES: usize = 64 * 1024;

/// Maximum serialized HostResult accepted from stdout before parsing fails.
pub const MAX_HOST_RESULT_BYTES: usize = 1024 * 1024;

/// Closed registry of operation kinds. Kept literally beside the
/// [`HostOperationBody`] variants on purpose; the wire-level parse classifies
/// unknown kinds here before typed deserialization, and the
/// `every_registered_kind_round_trips` test pins this list to the enum.
pub const HOST_OPERATION_KINDS: &[&str] = &["ping"];

/// Stable failure code: the operation is well-formed but not valid for its
/// kind (e.g. a host-level ping carrying an instance binding).
pub const HOST_ERR_OPERATION_INVALID: &str = "OPERATION_INVALID";

/// Stable failure code: the target does not implement the requested kind.
pub const HOST_ERR_UNSUPPORTED_OPERATION: &str = "UNSUPPORTED_OPERATION";

/// Stable failure code: expected-revision CAS mismatch against the target
/// DeploymentState. Consumed by the deployment waves (F04).
pub const HOST_ERR_REVISION_MISMATCH: &str = "REVISION_MISMATCH";

/// Stable rejection codes used when a transport cannot even parse a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionCode {
    OperationOversize,
    OperationMalformed,
    OperationSchemaUnsupported,
    OperationKindUnknown,
    ResultOversize,
    ResultMalformed,
    ResultSchemaUnsupported,
}

impl RejectionCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperationOversize => "HOST_OPERATION_OVERSIZE",
            Self::OperationMalformed => "HOST_OPERATION_MALFORMED",
            Self::OperationSchemaUnsupported => "HOST_OPERATION_SCHEMA_UNSUPPORTED",
            Self::OperationKindUnknown => "HOST_OPERATION_KIND_UNKNOWN",
            Self::ResultOversize => "HOST_RESULT_OVERSIZE",
            Self::ResultMalformed => "HOST_RESULT_MALFORMED",
            Self::ResultSchemaUnsupported => "HOST_RESULT_SCHEMA_UNSUPPORTED",
        }
    }
}

/// A rejected wire message. `detail` never contains raw input bytes; it may
/// quote bounded, sanitized discriminators such as the offending kind token,
/// and secret *values* can therefore never leak through rejections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRejection {
    pub code: RejectionCode,
    pub detail: String,
}

impl MessageRejection {
    fn new(code: RejectionCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for MessageRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for MessageRejection {}

/// One host-level operation addressed to an execution target.
///
/// SSH already authenticates and protects the channel (goal plan 01, P2), so
/// this message deliberately carries no controller signature material. It
/// holds only what idempotency, addressing, and the typed payload require.
///
/// The payload rides in an explicit `operation` object (not `serde(flatten)`:
/// flatten silently disables `deny_unknown_fields` and does not compose with
/// internally tagged enums), so both nesting levels reject unknown fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOperation {
    pub schema: u32,
    /// Retry identity. Same id + same canonical hash ⇒ replay of the same
    /// operation at the target journal; same id + different hash ⇒ conflict.
    pub operation_id: String,
    /// Instance binding. Present only for instance-scoped operations; the
    /// selector has been resolved before entering any ExecutionTarget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    /// Expected target DeploymentState revision for optimistic concurrency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    /// Typed payload with the closed `kind` discriminator.
    pub operation: HostOperationBody,
}

/// Typed operation payloads, discriminated by the closed `kind` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostOperationBody {
    /// Minimal liveness/helper probe. Echoes `nonce`; carries no state.
    Ping { nonce: String },
}

impl HostOperationBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
        }
    }
}

impl HostOperation {
    pub fn ping(operation_id: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            deployment_id: None,
            expected_revision: None,
            operation: HostOperationBody::Ping {
                nonce: nonce.into(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), MessageRejection> {
        if self.schema != HOST_PROTOCOL_SCHEMA {
            return Err(MessageRejection::new(
                RejectionCode::OperationSchemaUnsupported,
                format!("unsupported schema {}", self.schema),
            ));
        }
        if !is_uuid_v7(&self.operation_id) {
            return Err(MessageRejection::new(
                RejectionCode::OperationMalformed,
                "operation_id must be a UUIDv7",
            ));
        }
        if let Some(deployment) = self.deployment_id.as_deref()
            && !valid_token(deployment, 128)
        {
            return Err(MessageRejection::new(
                RejectionCode::OperationMalformed,
                "deployment_id is not a valid identifier",
            ));
        }
        match &self.operation {
            HostOperationBody::Ping { nonce } => {
                if !valid_token(nonce, 128) {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "ping nonce must be 1-128 visible ASCII characters",
                    ));
                }
                // Ping is a host-level probe: instance bindings do not apply.
                if self.deployment_id.is_some() || self.expected_revision.is_some() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "ping must not carry deployment_id or expected_revision",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The single answer a target returns for one HostOperation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostResult {
    pub schema: u32,
    pub operation_id: String,
    /// Typed outcome with the closed `status` discriminator.
    pub outcome: HostOutcome,
}

impl HostResult {
    pub fn completed(operation_id: impl Into<String>, body: HostCompletionBody) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            outcome: HostOutcome::Completed { body },
        }
    }

    /// Build a failed result. `detail` must be target-generated diagnostic
    /// text (static strings or validated identifiers); transports never echo
    /// raw input into this field, and [`sanitize`] bounds whatever is passed.
    pub fn failed(operation_id: impl Into<String>, code: &str, detail: impl Into<String>) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            outcome: HostOutcome::Failed {
                code: code.to_owned(),
                detail: sanitize(detail.into()),
            },
        }
    }

    pub fn validate(&self) -> Result<(), MessageRejection> {
        if self.schema != HOST_PROTOCOL_SCHEMA {
            return Err(MessageRejection::new(
                RejectionCode::ResultSchemaUnsupported,
                format!("unsupported schema {}", self.schema),
            ));
        }
        if !is_uuid_v7(&self.operation_id) {
            return Err(MessageRejection::new(
                RejectionCode::ResultMalformed,
                "operation_id must be a UUIDv7",
            ));
        }
        Ok(())
    }
}

/// Outcome half of a [`HostResult`], discriminated by the closed `status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostOutcome {
    Completed { body: HostCompletionBody },
    Failed { code: String, detail: String },
}

/// Typed completion payloads mirroring [`HostOperationBody`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostCompletionBody {
    Ping { nonce: String },
}

/// Serialize a HostOperation for a target's stdin, enforcing the size cap.
pub fn encode_host_operation(operation: &HostOperation) -> anyhow::Result<Vec<u8>> {
    encode_bounded(
        operation,
        MAX_HOST_OPERATION_BYTES,
        RejectionCode::OperationOversize,
    )
}

/// Parse the exact bytes a control side wrote to a remote-exec stdin.
pub fn parse_host_operation(raw: &[u8]) -> Result<HostOperation, MessageRejection> {
    if raw.len() > MAX_HOST_OPERATION_BYTES {
        return Err(MessageRejection::new(
            RejectionCode::OperationOversize,
            format!("exceeds the {}-byte limit", MAX_HOST_OPERATION_BYTES),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|error| malformed(RejectionCode::OperationMalformed, &error))?;
    let Some(kind) = value
        .get("operation")
        .and_then(|operation| operation.get("kind"))
        .and_then(serde_json::Value::as_str)
    else {
        return Err(MessageRejection::new(
            RejectionCode::OperationMalformed,
            "missing string 'kind' discriminator",
        ));
    };
    if !HOST_OPERATION_KINDS.contains(&kind) {
        return Err(MessageRejection::new(
            RejectionCode::OperationKindUnknown,
            format!("unsupported operation kind '{}'", sanitize(kind)),
        ));
    }
    let operation: HostOperation = serde_json::from_value(value)
        .map_err(|error| malformed(RejectionCode::OperationMalformed, &error))?;
    operation.validate()?;
    Ok(operation)
}

/// Serialize a HostResult for the control side's stdout reader.
pub fn encode_host_result(result: &HostResult) -> anyhow::Result<Vec<u8>> {
    encode_bounded(result, MAX_HOST_RESULT_BYTES, RejectionCode::ResultOversize)
}

/// Parse the single JSON document a remote exec wrote to stdout.
pub fn parse_host_result(raw: &[u8]) -> Result<HostResult, MessageRejection> {
    if raw.len() > MAX_HOST_RESULT_BYTES {
        return Err(MessageRejection::new(
            RejectionCode::ResultOversize,
            format!("exceeds the {}-byte limit", MAX_HOST_RESULT_BYTES),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|error| malformed(RejectionCode::ResultMalformed, &error))?;
    match value
        .get("outcome")
        .and_then(|outcome| outcome.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        Some("completed" | "failed") => {}
        _ => {
            return Err(MessageRejection::new(
                RejectionCode::ResultMalformed,
                "missing string 'status' discriminator",
            ));
        }
    }
    let result: HostResult = serde_json::from_value(value)
        .map_err(|error| malformed(RejectionCode::ResultMalformed, &error))?;
    result.validate()?;
    Ok(result)
}

fn encode_bounded<T: Serialize>(
    value: &T,
    limit: usize,
    oversize: RejectionCode,
) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > limit {
        return Err(anyhow::Error::from(MessageRejection::new(
            oversize,
            format!("serialized message exceeds the {}-byte limit", limit),
        )));
    }
    Ok(bytes)
}

fn malformed(code: RejectionCode, error: &serde_json::Error) -> MessageRejection {
    MessageRejection::new(code, sanitize(error.to_string()))
}

fn canonical_bytes(value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    // serde_json maps use sorted keys by default (no `preserve_order`
    // feature), so `to_value` yields a canonical key order independent of
    // construction order. That byte form is the journal hash input.
    let json = serde_json::to_value(value)?;
    serde_json::to_vec(&json).map_err(std::convert::Into::into)
}

/// Canonical SHA-256 over the full operation. The target-side journal (C07)
/// uses `operation_id + hash` to distinguish replays from conflicts.
pub fn canonical_operation_hash(operation: &HostOperation) -> anyhow::Result<String> {
    Ok(hex_sha256(&canonical_bytes(operation)?))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn is_uuid_v7(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.get_version_num() == 7)
}

fn valid_token(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= max_chars
        && value.chars().all(|character| character.is_ascii_graphic())
}

/// Bound a diagnostic token: printable ASCII only, hard length cap.
fn sanitize(value: impl Into<String>) -> String {
    let value: String = value.into();
    let characters: Vec<char> = value.chars().collect();
    let truncated = characters.len() > 200;
    let mut bounded: String = characters
        .into_iter()
        .take(200)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect();
    if truncated {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping_operation(nonce: &str) -> HostOperation {
        HostOperation::ping(Uuid::now_v7().to_string(), nonce)
    }

    #[test]
    fn every_registered_kind_round_trips() -> anyhow::Result<()> {
        assert_eq!(HOST_OPERATION_KINDS, &["ping"]);
        let operation = ping_operation("probe");
        let encoded = encode_host_operation(&operation)?;
        let parsed = parse_host_operation(&encoded)?;
        assert_eq!(parsed, operation);
        assert_eq!(parsed.operation.kind(), "ping");
        Ok(())
    }

    #[test]
    fn result_round_trips_through_the_codec() -> anyhow::Result<()> {
        let completed = HostResult::completed(
            Uuid::now_v7().to_string(),
            HostCompletionBody::Ping {
                nonce: "nonce-1".to_owned(),
            },
        );
        let parsed = parse_host_result(&encode_host_result(&completed)?)?;
        assert_eq!(parsed, completed);

        let failed = HostResult::failed(
            Uuid::now_v7().to_string(),
            HOST_ERR_OPERATION_INVALID,
            "static diagnostic text",
        );
        let parsed = parse_host_result(&encode_host_result(&failed)?)?;
        assert_eq!(parsed, failed);
        let HostOutcome::Failed { code, .. } = parsed.outcome else {
            panic!("failed outcome expected");
        };
        assert_eq!(code, HOST_ERR_OPERATION_INVALID);
        Ok(())
    }

    #[test]
    fn oversize_operation_and_result_are_rejected() -> anyhow::Result<()> {
        let oversized = vec![b'a'; MAX_HOST_OPERATION_BYTES + 1];
        let rejection = parse_host_operation(&oversized).expect_err("oversize");
        assert_eq!(rejection.code, RejectionCode::OperationOversize);

        let result = HostResult::completed(
            Uuid::now_v7().to_string(),
            HostCompletionBody::Ping {
                nonce: "x".repeat(MAX_HOST_RESULT_BYTES + 1),
            },
        );
        let error = encode_host_result(&result).expect_err("oversize");
        let rejection = error.downcast::<MessageRejection>()?;
        assert_eq!(rejection.code, RejectionCode::ResultOversize);
        Ok(())
    }

    #[test]
    fn unknown_kind_is_rejected_with_stable_code_and_without_echoing_input() -> anyhow::Result<()> {
        let poison = "POISON-SECRET-VALUE";
        let raw = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{}","operation":{{"kind":"teleport","payload":"{poison}"}}}}"#,
            Uuid::now_v7()
        );
        let rejection = parse_host_operation(raw.as_bytes()).expect_err("unknown kind");
        assert_eq!(rejection.code, RejectionCode::OperationKindUnknown);
        assert!(rejection.detail.contains("teleport"), "{rejection}");
        assert!(!rejection.detail.contains(poison), "{rejection}");
        Ok(())
    }

    #[test]
    fn schema_mismatch_malformed_json_and_missing_kind_are_classified() {
        let id = Uuid::now_v7();
        let wrong_schema = format!(
            r#"{{"schema":99,"operation_id":"{id}","operation":{{"kind":"ping","nonce":"n"}}}}"#
        );
        let rejection = parse_host_operation(wrong_schema.as_bytes()).err().unwrap();
        assert_eq!(rejection.code, RejectionCode::OperationSchemaUnsupported);

        let rejection = parse_host_operation(b"{not json").err().unwrap();
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);

        let missing = format!(r#"{{"schema":1,"operation_id":"{id}"}}"#);
        let rejection = parse_host_operation(missing.as_bytes()).err().unwrap();
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
    }

    #[test]
    fn non_v7_operation_ids_are_rejected() -> anyhow::Result<()> {
        // Well-formed UUIDv4 string; only the version differs from the rule.
        let v4 = "550e8400-e29b-41d4-a716-446655440000";
        let raw = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{v4}","operation":{{"kind":"ping","nonce":"n"}}}}"#
        );
        let rejection = parse_host_operation(raw.as_bytes()).expect_err("v4 id");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
        assert!(rejection.detail.contains("UUIDv7"));
        Ok(())
    }

    #[test]
    fn unknown_fields_are_denied_on_both_messages() {
        let id = Uuid::now_v7();
        let op = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{id}","extra":1,"operation":{{"kind":"ping","nonce":"n"}}}}"#
        );
        let rejection = parse_host_operation(op.as_bytes()).expect_err("extra field");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);

        // Unknown fields inside the payload object are equally rejected.
        let op_inner = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{id}","operation":{{"kind":"ping","nonce":"n","extra":1}}}}"#
        );
        let rejection = parse_host_operation(op_inner.as_bytes()).expect_err("inner extra");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);

        let result = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{id}","extra":1,"outcome":{{"status":"failed","code":"X","detail":"d"}}}}"#
        );
        let rejection = parse_host_result(result.as_bytes()).expect_err("extra field");
        assert_eq!(rejection.code, RejectionCode::ResultMalformed);
    }

    #[test]
    fn result_schema_mismatch_is_reported_separately() {
        let raw = format!(
            r#"{{"schema":9,"operation_id":"{}","outcome":{{"status":"completed","body":{{"result":"ping","nonce":"n"}}}}}}"#,
            Uuid::now_v7()
        );
        let rejection = parse_host_result(raw.as_bytes()).expect_err("schema");
        assert_eq!(rejection.code, RejectionCode::ResultSchemaUnsupported);
    }

    #[test]
    fn canonical_hash_is_deterministic_across_key_order() -> anyhow::Result<()> {
        let operation = ping_operation("same-nonce");
        let direct = canonical_operation_hash(&operation)?;
        let reparsed = parse_host_operation(&encode_host_operation(&operation)?)?;
        assert_eq!(canonical_operation_hash(&reparsed)?, direct);

        let mut reordered = serde_json::to_value(&operation)?;
        let object = reordered.as_object_mut().unwrap();
        let rotated: Vec<(String, serde_json::Value)> = object
            .iter()
            .rev()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        *object = rotated.into_iter().collect();
        let reordered_hash = hex_sha256(&canonical_bytes(&reordered)?);
        assert_eq!(reordered_hash, direct, "hash must ignore key order");

        let other = ping_operation("other-nonce");
        assert_ne!(canonical_operation_hash(&other)?, direct);
        Ok(())
    }

    #[test]
    fn failure_details_are_bounded_and_sanitized() {
        let result = HostResult::failed(
            Uuid::now_v7().to_string(),
            HOST_ERR_UNSUPPORTED_OPERATION,
            format!("line1\nline2\x07{}", "x".repeat(500)),
        );
        let HostOutcome::Failed { detail, .. } = result.outcome else {
            panic!("failed outcome expected");
        };
        assert!(detail.chars().count() <= 201, "{detail}");
        assert!(!detail.contains('\n'), "{detail}");
        assert!(!detail.contains('\x07'), "{detail}");
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn ping_rejects_deployment_bindings_at_validation() {
        let mut operation = ping_operation("probe");
        operation.deployment_id = Some("deploy-alpha".to_owned());
        let rejection = operation.validate().expect_err("binding rejected");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
        assert!(rejection.detail.contains("deployment_id"));

        let mut operation = ping_operation("probe");
        operation.expected_revision = Some(3);
        assert!(operation.validate().is_err());

        let mut operation = ping_operation("");
        operation.operation = HostOperationBody::Ping {
            nonce: String::new(),
        };
        assert!(operation.validate().is_err(), "empty nonce");
    }
}
