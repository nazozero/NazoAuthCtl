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

use chrono::{DateTime, Utc};
use nazo_operator_protocol::ControlResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::bootstrap_authority::FreshBootstrapMaterialView;
use super::deployment_state::{ArtifactRefs, RuntimeSurface, StateMutationPayload};

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
///
/// The F01 wave added the two DeploymentState kinds (`state-inspect`,
/// `state-mutate`). The G wave extends the `state-mutate` mutation set and
/// adds exactly one transport kind: `control-operation`, which carries an
/// already-signed compact-JWS ControlOperation opaquely to the target's
/// one-shot NazoAuth operator (goal plan 03 §3.3; no secret material, no
/// signing on the target).
pub const HOST_OPERATION_KINDS: &[&str] = &[
    "hello",
    "ping",
    "state-inspect",
    "state-mutate",
    "control-operation",
];

/// Product identity reported by a remote helper and required by the C08
/// handshake. Anything else is a different program and must never be mutated.
pub const HELLO_PRODUCT: &str = "nazoauthctl";

/// Build commit embedded by release builds through the
/// `NAZOAUTHCTL_BUILD_COMMIT` environment variable at compile time. Empty on
/// both sides means two dev builds of the same source tree; mixed presence or
/// any differing value fails the handshake closed (goal plan 03 §6).
pub const LOCAL_BUILD_COMMIT: &str = match option_env!("NAZOAUTHCTL_BUILD_COMMIT") {
    Some(commit) => commit,
    None => "",
};

/// Stable failure code: the operation is well-formed but not valid for its
/// kind (e.g. a host-level ping carrying an instance binding).
pub const HOST_ERR_OPERATION_INVALID: &str = "OPERATION_INVALID";

/// Stable failure code: the target does not implement the requested kind.
pub const HOST_ERR_UNSUPPORTED_OPERATION: &str = "UNSUPPORTED_OPERATION";

/// Stable failure code: the same `operation_id` was already accepted with a
/// different canonical request hash (goal plan 01 rule 13). The retry must
/// mint a new operation; the journal never overwrites the original intent.
pub const HOST_ERR_OPERATION_CONFLICT: &str = "OPERATION_CONFLICT";

/// Stable failure code: the remote helper's product, wire schema, or build
/// identity does not match this binary (task C08). No fallback exists; the
/// only remedy is upgrading the helper on the target host.
pub const HOST_ERR_REMOTE_HELPER_MISMATCH: &str = "REMOTE_HELPER_MISMATCH";

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
    /// Crate-visible constructor: sibling target modules (install order
    /// admission) build typed rejections through the same bounded shape.
    pub(crate) fn new(code: RejectionCode, detail: impl Into<String>) -> Self {
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
//
// `large_enum_variant` is intentional for the same reason as HostOutcome:
// StateMutate carries the typed Bootstrap payload (which includes the G01
// install order) and these are short-lived wire values.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostOperationBody {
    /// Minimal liveness/helper probe. Echoes `nonce`; carries no state.
    Ping { nonce: String },
    /// Helper identity announcement (task C08). Answered with
    /// [`HostCompletionBody::Hello`]; carries no state and no binding.
    Hello {},
    /// Read one deployment's target-side DeploymentState (task F01).
    /// Requires the instance binding; read-only, so `expected_revision`
    /// never applies.
    StateInspect {},
    /// Apply one closed-set mutation to the target DeploymentState (tasks
    /// F01/F04, extended by G03/G04/G06 with the lifecycle variants).
    /// Bootstrap creates fresh state; every other mutation is CAS-guarded by
    /// the mandatory `expected_revision`.
    StateMutate { mutation: StateMutationPayload },
    /// Deliver one signed ControlOperation to the target's local one-shot
    /// NazoAuth operator (goal plan 05 §6, decision: JWS on stdin, single-line
    /// ControlResult on stdout). The envelope is opaque here: the target never
    /// parses or verifies it — admission and execution stay server-side. The
    /// expected deployment id must equal the operation binding so a ctl bug
    /// can never aim instance A's envelope at instance B.
    ControlOperation {
        compact_jws: String,
        expected_deployment_id: String,
    },
}

impl HostOperationBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
            Self::Hello {} => "hello",
            Self::StateInspect {} => "state-inspect",
            Self::StateMutate { .. } => "state-mutate",
            Self::ControlOperation { .. } => "control-operation",
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

    /// Helper handshake probe (task C08). Host-level by definition.
    pub fn hello(operation_id: impl Into<String>) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            deployment_id: None,
            expected_revision: None,
            operation: HostOperationBody::Hello {},
        }
    }

    /// Read one deployment's target-side DeploymentState (task F01).
    pub fn state_inspect(
        operation_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            deployment_id: Some(deployment_id.into()),
            expected_revision: None,
            operation: HostOperationBody::StateInspect {},
        }
    }

    /// Apply one state mutation (task F01/F04). `expected_revision` is
    /// mandatory for every mutation except bootstrap, where it must be
    /// absent; [`HostOperation::validate`] enforces the pairing.
    pub fn state_mutate(
        operation_id: impl Into<String>,
        deployment_id: impl Into<String>,
        expected_revision: Option<u64>,
        mutation: StateMutationPayload,
    ) -> Self {
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            deployment_id: Some(deployment_id.into()),
            expected_revision,
            operation: HostOperationBody::StateMutate { mutation },
        }
    }

    /// Deliver one signed ControlOperation to the target's local operator.
    /// The JWS travels opaquely; the binding pair is validated here so a
    /// mismatched envelope is refused before any transport activity.
    pub fn control_operation(
        operation_id: impl Into<String>,
        deployment_id: impl Into<String>,
        compact_jws: impl Into<String>,
    ) -> Self {
        let deployment_id = deployment_id.into();
        Self {
            schema: HOST_PROTOCOL_SCHEMA,
            operation_id: operation_id.into(),
            deployment_id: Some(deployment_id.clone()),
            expected_revision: None,
            operation: HostOperationBody::ControlOperation {
                compact_jws: compact_jws.into(),
                expected_deployment_id: deployment_id,
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
        let bound = |value: &Option<String>| {
            value
                .as_deref()
                .map(|deployment| valid_token(deployment, 128))
                .unwrap_or(false)
        };
        if self.deployment_id.is_some() && !bound(&self.deployment_id) {
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
            HostOperationBody::Hello {} => {
                // Hello identifies the helper itself; instance bindings and
                // revision expectations are meaningless against it.
                if self.deployment_id.is_some() || self.expected_revision.is_some() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "hello must not carry deployment_id or expected_revision",
                    ));
                }
            }
            HostOperationBody::StateInspect {} => {
                // Inspection addresses exactly one registered deployment and
                // never mutates, so a revision expectation is meaningless.
                if self.deployment_id.is_none() || self.expected_revision.is_some() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "state-inspect requires deployment_id and must not carry \
                         expected_revision",
                    ));
                }
            }
            HostOperationBody::StateMutate { mutation } => {
                if self.deployment_id.is_none() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "state-mutate requires deployment_id",
                    ));
                }
                match mutation {
                    StateMutationPayload::Bootstrap { install, .. } => {
                        // There is no prior revision to expect on creation.
                        if self.expected_revision.is_some() {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "bootstrap must not carry expected_revision",
                            ));
                        }
                        // A carried install order must itself be well-formed;
                        // admission rejects broken orders before any target
                        // side effect.
                        if let Some(order) = install
                            && let Err(rejection) = order.validate()
                        {
                            return Err(rejection);
                        }
                    }
                    StateMutationPayload::ApplyConfig { .. } => {
                        // CAS is the whole point of config application (F04):
                        // without an expectation the mutation is rejected
                        // instead of silently last-write-winning.
                        if self.expected_revision.is_none() {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "apply-config requires expected_revision",
                            ));
                        }
                    }
                    StateMutationPayload::Update { artifact, config } => {
                        // Every lifecycle mutation replays against the live
                        // revision; without the expectation a resumed update
                        // could re-apply over drifted state.
                        if self.expected_revision.is_none() {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "update requires expected_revision",
                            ));
                        }
                        if artifact.repository.is_empty() || artifact.repository.len() > 128 {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "update artifact repository must be 1-128 characters",
                            ));
                        }
                        if let Some(pin) = &artifact.expected_subject_sha256
                            && !valid_lower_hex_sha256(pin)
                        {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "update expected_subject_sha256 must be 64 lowercase \
                                 hexadecimal characters",
                            ));
                        }
                        if let Some(config) = config
                            && let Err(rejection) = config.validate()
                        {
                            return Err(rejection);
                        }
                    }
                    StateMutationPayload::Rollback {} => {
                        if self.expected_revision.is_none() {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "rollback requires expected_revision",
                            ));
                        }
                    }
                    StateMutationPayload::Uninstall { resources } => {
                        if self.expected_revision.is_none() {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "uninstall requires expected_revision",
                            ));
                        }
                        if resources.len() > super::deployment_state::MAX_RESOURCES {
                            return Err(MessageRejection::new(
                                RejectionCode::OperationMalformed,
                                "uninstall plans more deletions than any deployment declares",
                            ));
                        }
                        for resource in resources {
                            resource.validate()?;
                        }
                    }
                }
            }
            HostOperationBody::ControlOperation {
                compact_jws,
                expected_deployment_id,
            } => {
                // Instance binding required; revision expectations are
                // meaningless for a pass-through delivery.
                if self.deployment_id.is_none() || self.expected_revision.is_some() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "control-operation requires deployment_id and must not carry \
                         expected_revision",
                    ));
                }
                if compact_jws.is_empty()
                    || compact_jws.len() > MAX_CONTROL_JWS_BYTES
                    || !compact_jws.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "control-operation compact_jws must be a bounded base64url JWS",
                    ));
                }
                if compact_jws.split('.').count() != 3 {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "control-operation compact_jws must have exactly three segments",
                    ));
                }
                if expected_deployment_id != self.deployment_id.as_deref().unwrap_or_default() {
                    return Err(MessageRejection::new(
                        RejectionCode::OperationMalformed,
                        "control-operation expected_deployment_id must equal the operation \
                         binding",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Upper bound for the opaque compact JWS inside one control-operation kind.
/// The frozen protocol allows 64 KiB envelopes and the HostOperation total
/// cap equals it, so the payload keeps that bound minus framing headroom.
const MAX_CONTROL_JWS_BYTES: usize = 60 * 1024;

fn valid_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
//
// `large_enum_variant` is intentional: the completed body carries the typed
// inspection payload (F01), and HostResult is a short-lived per-operation
// value where an extra indirection would buy nothing but churn at every
// match site.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostOutcome {
    Completed { body: HostCompletionBody },
    Failed { code: String, detail: String },
}

/// Typed completion payloads mirroring [`HostOperationBody`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "completion", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostCompletionBody {
    Ping {
        nonce: String,
    },
    Hello {
        hello: RemoteHello,
    },
    /// Full live view of one deployment's target-side state (F01).
    StateInspect {
        inspection: InstanceInspection,
    },
    /// The revision a successful mutation produced (F04).
    StateMutateApplied {
        revision: u64,
    },
    /// A clean install committed `local_healthy` state on the target (G01).
    /// Carries the full live inspection so the control side can register the
    /// InstanceRecord without a second round trip.
    InstallApplied {
        inspection: InstanceInspection,
    },
    /// The target's local one-shot NazoAuth operator answered a delivered
    /// ControlOperation with its durable [`ControlResult`] (goal plan 05 §6).
    /// Only journal-backed results complete this way; refusals before
    /// acceptance are Failed outcomes.
    ControlOperationExecuted {
        result: ControlResult,
    },
}

/// Live inspection of one registered instance read from the target-side
/// DeploymentState (task F01). This is the payload both transports answer
/// with and the exact type [`crate::target::ExecutionTarget::inspect_instance`]
/// returns, so local and remote reads cannot drift apart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceInspection {
    pub deployment_id: String,
    pub issuer: String,
    pub observed_at: DateTime<Utc>,
    /// Current config revision (the single CAS fact, F04).
    pub revision: u64,
    pub runtime: RuntimeSurface,
    pub artifact: ArtifactRefs,
    pub config_reference: String,
    pub config_schema: String,
    /// Concrete resources with ownership + scope facts (F02).
    pub resources: Vec<super::deployment_state::Resource>,
    pub healthy: bool,
    pub health_summary: String,
    /// Operation id that produced the current revision, if any (journal index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_host_operation: Option<String>,
    /// Read-only fresh-install bootstrap capability, surfaced ONLY while the
    /// capability is open and the live state still matches its install
    /// journal binding (goal plan 07 G-A decision). Absent in every other
    /// state — closure, consumption, and drift are indistinguishable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_material: Option<FreshBootstrapMaterialView>,
    /// Embedded build identity facts of `artifact.current`, when the target's
    /// verification recorded them (G03 ControlOperation envelope source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_build_identity: Option<super::deployment_state::BuildIdentity>,
}

/// Identity a target helper announces about itself (goal plan 03 §6).
///
/// The control side compares `product`, `remote_exec_schema`, `version`, and
/// `commit` against its own constants before any host-level mutation
/// ([`verify_remote_hello`]). `os`, `arch`, and `supported_runtimes` are
/// informational inventory facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteHello {
    pub product: String,
    /// Highest HostOperation/HostResult wire schema the helper answers.
    pub remote_exec_schema: u32,
    pub version: String,
    pub commit: String,
    pub os: String,
    pub arch: String,
    pub supported_runtimes: Vec<String>,
}

/// The hello payload this binary answers with. Runtime detection stays with
/// the caller; the identity fields are compile-time facts.
pub fn local_hello(supported_runtimes: Vec<String>) -> RemoteHello {
    RemoteHello {
        product: HELLO_PRODUCT.to_owned(),
        remote_exec_schema: HOST_PROTOCOL_SCHEMA,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        commit: LOCAL_BUILD_COMMIT.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        supported_runtimes,
    }
}

/// Task C08 handshake check: the announced helper identity must equal this
/// binary's constants exactly. Any difference is a mismatch — there is no
/// compatibility range and no fallback.
pub fn verify_remote_hello(hello: &RemoteHello) -> Result<(), String> {
    if !valid_token(&hello.product, 64) {
        return Err("hello product is not a valid token".to_owned());
    }
    if !valid_token(&hello.version, 64) {
        return Err("hello version is not a valid token".to_owned());
    }
    if !(hello.commit.is_empty() || valid_token(&hello.commit, 128)) {
        return Err("hello commit is not a valid token".to_owned());
    }
    for fact in [&hello.os, &hello.arch] {
        if !valid_token(fact, 32) {
            return Err("hello platform facts contain invalid tokens".to_owned());
        }
    }
    if hello.supported_runtimes.len() > 16
        || hello
            .supported_runtimes
            .iter()
            .any(|runtime| !valid_token(runtime, 32))
    {
        return Err("hello supported_runtimes is not a bounded token list".to_owned());
    }
    if hello.product != HELLO_PRODUCT {
        return Err(format!(
            "target answered as product '{}' instead of '{HELLO_PRODUCT}'",
            sanitize(hello.product.clone())
        ));
    }
    if hello.remote_exec_schema != HOST_PROTOCOL_SCHEMA {
        return Err(format!(
            "remote exec schema {} does not match controller schema {HOST_PROTOCOL_SCHEMA}",
            hello.remote_exec_schema
        ));
    }
    let expected_version = env!("CARGO_PKG_VERSION");
    if hello.version != expected_version {
        return Err(format!(
            "helper version '{}' does not match controller version '{expected_version}'",
            sanitize(hello.version.clone())
        ));
    }
    if hello.commit != LOCAL_BUILD_COMMIT {
        return Err(format!(
            "helper build commit '{}' does not match controller commit '{}'",
            sanitize(hello.commit.clone()),
            LOCAL_BUILD_COMMIT
        ));
    }
    Ok(())
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
pub(super) fn sanitize(value: impl Into<String>) -> String {
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
        assert_eq!(
            HOST_OPERATION_KINDS,
            &[
                "hello",
                "ping",
                "state-inspect",
                "state-mutate",
                "control-operation"
            ]
        );
        let operation = ping_operation("probe");
        let encoded = encode_host_operation(&operation)?;
        let parsed = parse_host_operation(&encoded)?;
        assert_eq!(parsed, operation);
        assert_eq!(parsed.operation.kind(), "ping");

        let hello = HostOperation::hello(Uuid::now_v7().to_string());
        let encoded = encode_host_operation(&hello)?;
        assert!(
            String::from_utf8(encoded.clone())?.contains(r#""kind":"hello""#),
            "canonical encoding carries the tagged empty payload"
        );
        assert_eq!(parse_host_operation(&encoded)?, hello);

        // F01 kinds round-trip with their typed payloads intact.
        let inspect = HostOperation::state_inspect(Uuid::now_v7().to_string(), "deploy-alpha");
        let parsed = parse_host_operation(&encode_host_operation(&inspect)?)?;
        assert_eq!(parsed, inspect);
        assert_eq!(parsed.operation.kind(), "state-inspect");

        let bootstrap = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            None,
            StateMutationPayload::Bootstrap {
                issuer: "https://auth.example.com".to_owned(),
                runtime: super::super::deployment_state::RuntimeSurface::new(
                    "podman",
                    "nazoauth-main",
                )?,
                artifact: Default::default(),
                config_reference: "/etc/nazauth/config.toml".to_owned(),
                config_schema: "nazauth-config-v1".to_owned(),
                resources: vec![super::super::deployment_state::Resource::new(
                    "db",
                    "postgres",
                    "pg-main.example.internal:5432",
                    super::super::deployment_state::ResourceOwnership::External,
                    super::super::deployment_state::ResourceScope::Shared,
                )?],
                install: None,
            },
        );
        let parsed = parse_host_operation(&encode_host_operation(&bootstrap)?)?;
        assert_eq!(parsed, bootstrap);
        assert_eq!(parsed.operation.kind(), "state-mutate");

        // The G01 clean-install order rides inside the Bootstrap mutation and
        // round-trips with its typed payload intact.
        let order = super::super::install_exec::InstallOrder {
            artifact: super::super::install_exec::OfficialArtifactRef {
                repository: "nazozero/NazoAuth".to_owned(),
                version: Some("v0.2.0".to_owned()),
                expected_subject_sha256: Some("a".repeat(64)),
            },
            config_content: "{\"issuer\":\"https://auth.example.com\"}".to_owned(),
            config_sha256: "b".repeat(64),
            data_root: "/var/lib/nazoauth".to_owned(),
            secrets: vec![super::super::install_exec::PlannedSecret {
                purpose: "database-url".to_owned(),
                path: "/var/lib/nazoauth/secrets/database-url".to_owned(),
            }],
            fresh_bootstrap: true,
            port: 8000,
        };
        let mut install = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            None,
            StateMutationPayload::Bootstrap {
                issuer: "https://auth.example.com".to_owned(),
                runtime: super::super::deployment_state::RuntimeSurface::new(
                    "podman",
                    "nazoauth-main",
                )?,
                artifact: Default::default(),
                config_reference: "/etc/nazauth/deployments/deploy-alpha/config.json".to_owned(),
                config_schema: "nazauth-seed-v1".to_owned(),
                resources: Vec::new(),
                install: Some(order.clone()),
            },
        );
        let parsed = parse_host_operation(&encode_host_operation(&install)?)?;
        assert_eq!(parsed, install);
        assert!(
            String::from_utf8(encode_host_operation(&install)?)?
                .contains(r#""kind":"state-mutate""#)
        );

        // A broken order fails at admission, before any target side effect.
        let mut broken_order = order;
        broken_order.config_sha256 = "not-a-digest".to_owned();
        if let HostOperationBody::StateMutate {
            mutation: StateMutationPayload::Bootstrap { install, .. },
        } = &mut install.operation
        {
            *install = Some(broken_order);
        }
        let rejection = install.validate().expect_err("broken order");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
        assert!(rejection.detail.contains("config_sha256"), "{rejection}");

        let apply = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(3),
            StateMutationPayload::ApplyConfig {
                reference: "/etc/nazauth/config.toml".to_owned(),
                schema: "nazauth-config-v1".to_owned(),
            },
        );
        assert_eq!(
            parse_host_operation(&encode_host_operation(&apply)?)?,
            apply
        );

        // G-wave lifecycle mutations round-trip with their payloads intact.
        let update = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(4),
            StateMutationPayload::Update {
                artifact: super::super::install_exec::OfficialArtifactRef {
                    repository: "nazozero/NazoAuth".to_owned(),
                    version: Some("v0.3.0".to_owned()),
                    expected_subject_sha256: Some("c".repeat(64)),
                },
                config: Some(super::super::install_exec::StagedConfig {
                    content: "{\"issuer\":\"https://auth.example.com\"}".to_owned(),
                    sha256: "d".repeat(64),
                    schema: "nazauth-config-v2".to_owned(),
                }),
            },
        );
        assert_eq!(
            parse_host_operation(&encode_host_operation(&update)?)?,
            update
        );

        let rollback = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(5),
            StateMutationPayload::Rollback {},
        );
        assert_eq!(
            parse_host_operation(&encode_host_operation(&rollback)?)?,
            rollback
        );

        let uninstall = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(5),
            StateMutationPayload::Uninstall {
                resources: vec![super::super::install_exec::PlannedResourceDeletion {
                    resource_id: "app-runtime".to_owned(),
                    locator: "nazoauth-main".to_owned(),
                }],
            },
        );
        assert_eq!(
            parse_host_operation(&encode_host_operation(&uninstall)?)?,
            uninstall
        );

        // The control-operation kind carries the opaque JWS plus the binding
        // cross-check and round-trips byte-stable.
        let control = HostOperation::control_operation(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            "eyJhbGciOiJFZERTQSJ9.eyJvcGVyYXRpb25faWQiOiJ4In0.sig",
        );
        let parsed = parse_host_operation(&encode_host_operation(&control)?)?;
        assert_eq!(parsed, control);
        assert_eq!(parsed.operation.kind(), "control-operation");
        Ok(())
    }

    #[test]
    fn control_operation_kind_enforces_binding_and_jws_shape() -> anyhow::Result<()> {
        let jws = format!("{}.{}.{}", "a".repeat(40), "b".repeat(40), "c".repeat(64));

        // Binding mismatch is refused before any transport activity.
        let mut crossed =
            HostOperation::control_operation(Uuid::now_v7().to_string(), "deploy-a", &jws);
        if let HostOperationBody::ControlOperation {
            expected_deployment_id,
            ..
        } = &mut crossed.operation
        {
            *expected_deployment_id = "deploy-b".to_owned();
        }
        let rejection = crossed.validate().expect_err("crossed binding");
        assert!(rejection.detail.contains("must equal"), "{rejection}");

        // A revision expectation is meaningless on a pass-through delivery.
        let mut revisioned =
            HostOperation::control_operation(Uuid::now_v7().to_string(), "deploy-a", &jws);
        revisioned.expected_revision = Some(2);
        assert!(revisioned.validate().is_err());

        // Non-JWS shapes fail closed.
        for broken in [
            "",
            "one-segment",
            "a.b.c d",
            &"x".repeat(MAX_CONTROL_JWS_BYTES + 1),
        ] {
            let operation =
                HostOperation::control_operation(Uuid::now_v7().to_string(), "deploy-a", broken);
            let rejection = operation.validate().expect_err(broken);
            assert_eq!(
                rejection.code,
                RejectionCode::OperationMalformed,
                "{rejection}"
            );
        }
        Ok(())
    }

    #[test]
    fn lifecycle_mutations_demand_their_revision_expectations() -> anyhow::Result<()> {
        let cas_free_update = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-a",
            None,
            StateMutationPayload::Update {
                artifact: super::super::install_exec::OfficialArtifactRef {
                    repository: "nazozero/NazoAuth".to_owned(),
                    version: None,
                    expected_subject_sha256: None,
                },
                config: None,
            },
        );
        let rejection = cas_free_update.validate().expect_err("update without CAS");
        assert!(
            rejection.detail.contains("expected_revision"),
            "{rejection}"
        );

        let bad_pin = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-a",
            Some(1),
            StateMutationPayload::Update {
                artifact: super::super::install_exec::OfficialArtifactRef {
                    repository: "nazozero/NazoAuth".to_owned(),
                    version: None,
                    expected_subject_sha256: Some("NOT-A-DIGEST".to_owned()),
                },
                config: None,
            },
        );
        assert!(bad_pin.validate().is_err());

        let cas_free_rollback = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-a",
            None,
            StateMutationPayload::Rollback {},
        );
        assert!(cas_free_rollback.validate().is_err());

        let cas_free_uninstall = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-a",
            None,
            StateMutationPayload::Uninstall { resources: vec![] },
        );
        let rejection = cas_free_uninstall
            .validate()
            .expect_err("uninstall without CAS");
        assert!(
            rejection.detail.contains("expected_revision"),
            "{rejection}"
        );
        Ok(())
    }

    #[test]
    fn state_kinds_enforce_binding_and_revision_pairing() -> anyhow::Result<()> {
        // Inspect demands its instance binding and never a revision.
        let mut missing = HostOperation::ping(Uuid::now_v7().to_string(), "x");
        missing.operation = HostOperationBody::StateInspect {};
        missing.deployment_id = None;
        let rejection = missing.validate().expect_err("inspect without binding");
        assert!(
            rejection.detail.contains("requires deployment_id"),
            "{rejection}"
        );

        let mut revisioned = HostOperation::state_inspect(Uuid::now_v7().to_string(), "deploy-a");
        revisioned.expected_revision = Some(2);
        let rejection = revisioned.validate().expect_err("inspect with revision");
        assert!(
            rejection
                .detail
                .contains("must not carry expected_revision"),
            "{rejection}"
        );

        // Apply-config without an expectation would be last-write-wins.
        let mut cas_free = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-a",
            None,
            StateMutationPayload::ApplyConfig {
                reference: "/cfg".to_owned(),
                schema: "v1".to_owned(),
            },
        );
        let rejection = cas_free.validate().expect_err("apply without CAS");
        assert!(
            rejection.detail.contains("expected_revision"),
            "{rejection}"
        );

        // Bootstrap over a claimed prior revision is rejected too.
        cas_free.expected_revision = Some(9);
        cas_free.operation = HostOperationBody::StateMutate {
            mutation: StateMutationPayload::Bootstrap {
                issuer: "https://auth.example.com".to_owned(),
                runtime: super::super::deployment_state::RuntimeSurface::new("host", "unit")?,
                artifact: Default::default(),
                config_reference: "/cfg".to_owned(),
                config_schema: "v1".to_owned(),
                resources: Vec::new(),
                install: None,
            },
        };
        let rejection = cas_free.validate().expect_err("bootstrap with revision");
        assert!(rejection.detail.contains("bootstrap"), "{rejection}");

        // Mutations always demand their binding.
        let mut unbound = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "",
            Some(1),
            StateMutationPayload::ApplyConfig {
                reference: "/cfg".to_owned(),
                schema: "v1".to_owned(),
            },
        );
        unbound.deployment_id = None;
        let rejection = unbound.validate().expect_err("mutate without binding");
        assert!(
            rejection.detail.contains("requires deployment_id"),
            "{rejection}"
        );
        Ok(())
    }

    #[test]
    fn unknown_mutation_tag_is_rejected_without_echoing_payloads() -> anyhow::Result<()> {
        let raw = format!(
            r#"{{"schema":{HOST_PROTOCOL_SCHEMA},"operation_id":"{}","deployment_id":"deploy-a","operation":{{"kind":"state-mutate","mutation":{{"mutation":"teleport","poison":"secret-value"}}}}}}"#,
            Uuid::now_v7()
        );
        let rejection = parse_host_operation(raw.as_bytes()).expect_err("unknown mutation tag");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
        assert!(!rejection.detail.contains("secret-value"), "{rejection}");
        Ok(())
    }

    #[test]
    fn hello_rejects_deployment_bindings_at_validation() {
        let mut hello = HostOperation::hello(Uuid::now_v7().to_string());
        hello.deployment_id = Some("deploy-alpha".to_owned());
        let rejection = hello.validate().expect_err("binding rejected");
        assert_eq!(rejection.code, RejectionCode::OperationMalformed);
        assert!(rejection.detail.contains("deployment_id"));

        let mut hello = HostOperation::hello(Uuid::now_v7().to_string());
        hello.expected_revision = Some(2);
        assert!(hello.validate().is_err());
    }

    #[test]
    fn local_hello_verifies_against_itself_and_detects_drift() -> anyhow::Result<()> {
        let hello = local_hello(vec!["podman".to_owned()]);
        verify_remote_hello(&hello).expect("a helper answers its own handshake");
        assert_eq!(hello.remote_exec_schema, HOST_PROTOCOL_SCHEMA);

        let mut drift = hello.clone();
        drift.version = "9.9.9".to_owned();
        let reason = verify_remote_hello(&drift).expect_err("version drift");
        assert!(reason.contains("version"), "{reason}");

        let mut drift = hello.clone();
        drift.product = "other-helper".to_owned();
        assert!(verify_remote_hello(&drift).is_err());

        let mut drift = hello;
        drift.commit = "deadbeef".to_owned();
        let reason = verify_remote_hello(&drift).expect_err("commit drift");
        assert!(reason.contains("commit"), "{reason}");
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

        let hello = HostResult::completed(
            Uuid::now_v7().to_string(),
            HostCompletionBody::Hello {
                hello: local_hello(vec!["docker".to_owned()]),
            },
        );
        assert_eq!(parse_host_result(&encode_host_result(&hello)?)?, hello);

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
            r#"{{"schema":9,"operation_id":"{}","outcome":{{"status":"completed","body":{{"completion":"ping","nonce":"n"}}}}}}"#,
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
