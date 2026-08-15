//! Machine client for NazoAuth tenant-resource management.
//!
//! This module owns the controller-side HTTP boundary only.  Wire shape,
//! compact-JWS verification, digest calculation, and task/receipt binding are
//! delegated to `nazo-operator-protocol`; no protocol rules are reimplemented
//! here.

use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nazo_operator_protocol::{
    Actor, ActorKind, DiscoveryRequest, EmbeddedIdentity, ProtocolError, TenantResourceCapability,
    TenantResourceIdentity, TenantResourceOperation, TenantResourceReceipt, TenantResourceSelector,
    TenantResourceTask, TenantResourceTaskPayload, canonical_tenant_resource_manifest_sha256,
    compact_sha256, instance_key_id, sign_tenant_resource_task, validate_discovery_request,
    validate_tenant_resource_capability, validate_tenant_resource_capability_request_binding,
    validate_tenant_resource_receipt_binding,
    validate_tenant_resource_receipt_capability_binding_at,
    validate_tenant_resource_receipt_capability_binding_with_digest,
    validate_tenant_resource_receipt_request_binding,
    validate_tenant_resource_task_capability_binding_at,
    validate_tenant_resource_task_capability_binding_with_digest,
    validate_tenant_resource_task_deployment_binding, verify_tenant_resource_capability_signature,
    verify_tenant_resource_receipt_signature, verify_tenant_resource_receipt_window,
    verify_tenant_resource_task_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The execute endpoint and the provider use the same bounded JSON body.
pub const MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const TASK_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityRequest {
    schema: u32,
    nonce: String,
    tenant_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityResponse {
    capability_jws: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecuteEnvelope<'a> {
    capability_jws: &'a str,
    task_jws: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_base64url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredExecuteEnvelope {
    capability_jws: String,
    task_jws: String,
    #[serde(default)]
    manifest_base64url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecuteResponse {
    receipt_jws: String,
}

/// A transport response with the HTTP status kept separate from the body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Synchronous HTTP injection boundary.  Production uses curl through the
/// existing runtime process wrapper; tests can provide an in-memory transport
/// without bypassing any client verification.
pub trait TenantResourceHttpTransport: Send + Sync {
    fn post_json(
        &self,
        endpoint: &Url,
        body: &[u8],
    ) -> Result<TenantResourceHttpResponse, TenantResourceClientError>;
}

/// Production transport.  `--fail` is intentionally not used: stable 4xx/5xx
/// statuses are part of the management contract and must reach the mapper.
#[derive(Clone, Debug)]
pub struct CurlTenantResourceTransport {
    timeout: Duration,
}

impl Default for CurlTenantResourceTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

impl CurlTenantResourceTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl TenantResourceHttpTransport for CurlTenantResourceTransport {
    fn post_json(
        &self,
        endpoint: &Url,
        body: &[u8],
    ) -> Result<TenantResourceHttpResponse, TenantResourceClientError> {
        use nazoauthctl_runtime::process::Process;

        let timeout_secs = self.timeout.as_secs().max(1).to_string();
        let output = Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--connect-timeout",
                "10",
                "--max-time",
                timeout_secs.as_str(),
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--header",
                "Accept: application/json",
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
                endpoint.as_str(),
            ])
            .timeout(self.timeout)
            .stdin_stdout(body)
            .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;

        let (body, status) = output.rsplit_once('\n').ok_or_else(|| {
            TenantResourceClientError::Transport("curl returned no HTTP status".into())
        })?;
        let status = status.trim().parse::<u16>().map_err(|_| {
            TenantResourceClientError::Transport("curl returned an invalid HTTP status".into())
        })?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantResourceClientError::TooLarge);
        }
        Ok(TenantResourceHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }
}

/// Client trust and deployment configuration.  `controller_signing_key` is
/// the operator key authorized by the runtime's pinned controller public key.
#[derive(Clone)]
pub struct TenantResourceClientConfig {
    pub base_url: Url,
    pub deployment_id: String,
    pub tenant_id: String,
    pub runtime_instance_id: String,
    pub runtime_key_id: String,
    pub runtime_public_key: VerifyingKey,
    pub controller_key_id: String,
    /// Optional for replay-only recovery.  New task preparation requires it;
    /// receipt verification only needs the pinned public key.
    pub controller_public_key: VerifyingKey,
    pub controller_signing_key: Option<SigningKey>,
    pub actor_id: String,
    pub embedded: EmbeddedIdentity,
}

impl TenantResourceClientConfig {
    fn validate(&self) -> Result<(), TenantResourceClientError> {
        if self.base_url.scheme() != "https"
            || self.base_url.host_str().is_none()
            || !self.base_url.username().is_empty()
            || self.base_url.password().is_some()
            || self.base_url.query().is_some()
            || self.base_url.fragment().is_some()
            || (!self.base_url.path().is_empty() && self.base_url.path() != "/")
        {
            return Err(TenantResourceClientError::InvalidRequest(
                "base URL must be an HTTPS origin without credentials or query".into(),
            ));
        }
        validate_file_identifier(&self.deployment_id)?;
        validate_file_identifier(&self.runtime_instance_id)?;
        validate_file_identifier(&self.runtime_key_id)?;
        validate_file_identifier(&self.controller_key_id)?;
        validate_identifier(&self.actor_id)?;
        if !is_canonical_uuid(&self.tenant_id) {
            return Err(TenantResourceClientError::InvalidRequest(
                "tenant_id must be a canonical UUID".into(),
            ));
        }
        if self.runtime_key_id != instance_key_id(&self.runtime_public_key) {
            return Err(TenantResourceClientError::InvalidRequest(
                "runtime key id does not match runtime public key".into(),
            ));
        }
        if self.controller_key_id != instance_key_id(&self.controller_public_key) {
            return Err(TenantResourceClientError::InvalidRequest(
                "controller key id does not match controller public key".into(),
            ));
        }
        if self
            .controller_signing_key
            .as_ref()
            .is_some_and(|key| key.verifying_key() != self.controller_public_key)
        {
            return Err(TenantResourceClientError::InvalidRequest(
                "controller signing key does not match controller public key".into(),
            ));
        }
        if self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION {
            return Err(TenantResourceClientError::InvalidRequest(
                "embedded protocol version is unsupported".into(),
            ));
        }
        Ok(())
    }
}

/// A capability plus the exact compact JWS bytes that authorized it.
#[derive(Clone, Debug)]
pub struct TenantResourceCapabilitySession {
    pub compact_jws: String,
    pub capability: TenantResourceCapability,
}

impl TenantResourceCapabilitySession {
    /// Digest of the exact compact capability evidence.  Consumers should use
    /// this accessor instead of reimplementing the protocol hash.
    pub fn compact_sha256(&self) -> String {
        compact_sha256(&self.compact_jws)
    }
}

/// A fully signed request frozen before transport.  The exact body and
/// operation JTI are retained so a caller can persist this redacted request
/// and retry it after a controller crash without issuing a second mutation.
/// `Debug` deliberately omits all compact JWS and manifest bytes.
pub struct PreparedTenantResourceRequest {
    capability_jws: String,
    task_jws: String,
    task: TenantResourceTask,
    raw_manifest: Option<Zeroizing<Vec<u8>>>,
    body: Zeroizing<Vec<u8>>,
}

struct TenantResourceTaskDraft<'a> {
    change_set_id: &'a str,
    change_set_sha256: String,
    operation: TenantResourceOperation,
    payload: TenantResourceTaskPayload,
    resource_manifest_sha256: String,
    raw_manifest: Option<&'a [u8]>,
    now: i64,
}

/// Redacted, dependency-neutral recovery metadata.  A conformance/recovery
/// layer can persist these values without importing its own wire types; the
/// private manifest bytes remain outside this binding.
#[derive(Clone)]
pub struct TenantResourceRecoveryBinding {
    capability_jws: String,
    task_jws: String,
    task: TenantResourceTask,
    capability_sha256: String,
    task_sha256: String,
    request_sha256: String,
    operation: TenantResourceOperation,
    jti: String,
    change_set_id: String,
    change_set_sha256: String,
}

impl TenantResourceRecoveryBinding {
    pub fn capability_jws(&self) -> &str {
        &self.capability_jws
    }

    pub fn task_jws(&self) -> &str {
        &self.task_jws
    }

    pub fn task(&self) -> &TenantResourceTask {
        &self.task
    }

    pub fn capability_sha256(&self) -> &str {
        &self.capability_sha256
    }

    pub fn task_sha256(&self) -> &str {
        &self.task_sha256
    }

    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    pub fn operation(&self) -> TenantResourceOperation {
        self.operation
    }

    pub fn jti(&self) -> &str {
        &self.jti
    }

    pub fn change_set_id(&self) -> &str {
        &self.change_set_id
    }

    pub fn change_set_sha256(&self) -> &str {
        &self.change_set_sha256
    }
}

impl fmt::Debug for TenantResourceRecoveryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantResourceRecoveryBinding")
            .field("operation", &self.operation)
            .field("jti", &self.jti)
            .field("change_set_id", &self.change_set_id)
            .field("request_sha256", &self.request_sha256)
            .finish()
    }
}

impl PreparedTenantResourceRequest {
    /// Restore a previously persisted request without regenerating its JTI or
    /// changing the exact execute body.  The envelope is checked against every
    /// supplied component before the request can be sent.
    pub fn restore(
        capability_jws: String,
        task_jws: String,
        task: TenantResourceTask,
        raw_manifest: Option<Vec<u8>>,
        body: Vec<u8>,
    ) -> Result<Self, TenantResourceClientError> {
        if body.len() > MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES {
            return Err(TenantResourceClientError::TooLarge);
        }
        let envelope: StoredExecuteEnvelope = serde_json::from_slice(&body).map_err(|_| {
            TenantResourceClientError::InvalidRequest("persisted execute body is malformed".into())
        })?;
        if envelope.capability_jws != capability_jws || envelope.task_jws != task_jws {
            return Err(TenantResourceClientError::InvalidRequest(
                "persisted execute body does not match signed request".into(),
            ));
        }
        let expected_manifest = raw_manifest
            .as_ref()
            .map(|manifest| URL_SAFE_NO_PAD.encode(manifest));
        if envelope.manifest_base64url != expected_manifest {
            return Err(TenantResourceClientError::InvalidRequest(
                "persisted execute body does not match raw manifest".into(),
            ));
        }
        let apply_requires_manifest = matches!(task.operation, TenantResourceOperation::Apply);
        if apply_requires_manifest != raw_manifest.is_some() {
            return Err(TenantResourceClientError::InvalidRequest(
                "persisted execute body manifest does not match operation".into(),
            ));
        }
        Ok(Self {
            capability_jws,
            task_jws,
            task,
            raw_manifest: raw_manifest.map(Zeroizing::new),
            body: Zeroizing::new(body),
        })
    }

    pub fn capability_jws(&self) -> &str {
        &self.capability_jws
    }

    pub fn task_jws(&self) -> &str {
        &self.task_jws
    }

    pub fn task(&self) -> &TenantResourceTask {
        &self.task
    }

    /// Exact JSON bytes sent to `/management/tenant-resources/execute`.
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    pub fn raw_manifest(&self) -> Option<&[u8]> {
        self.raw_manifest.as_ref().map(|bytes| bytes.as_slice())
    }

    pub fn capability_sha256(&self) -> String {
        compact_sha256(&self.capability_jws)
    }

    pub fn task_sha256(&self) -> String {
        compact_sha256(&self.task_jws)
    }

    pub fn request_sha256(&self) -> String {
        hex_sha256(self.body())
    }

    pub fn recovery_binding(&self) -> TenantResourceRecoveryBinding {
        TenantResourceRecoveryBinding {
            capability_jws: self.capability_jws.clone(),
            task_jws: self.task_jws.clone(),
            task: self.task.clone(),
            capability_sha256: self.capability_sha256(),
            task_sha256: self.task_sha256(),
            request_sha256: self.request_sha256(),
            operation: self.task.operation,
            jti: self.task.jti.clone(),
            change_set_id: self.task.change_set_id.clone(),
            change_set_sha256: self.task.change_set_sha256.clone(),
        }
    }
}

impl fmt::Debug for PreparedTenantResourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTenantResourceRequest")
            .field("jti", &self.task.jti)
            .field("operation", &self.task.operation)
            .field("expected_revision", &self.task.expected_revision)
            .field("has_raw_manifest", &self.raw_manifest.is_some())
            .finish()
    }
}

/// A receipt plus its exact runtime-signed compact JWS bytes.  The compact
/// evidence is intentionally private; callers receive borrowed read-only
/// accessors and a redacted `Debug` representation.
#[derive(Clone)]
pub struct TenantResourceReceiptResult {
    compact_jws: String,
    receipt: TenantResourceReceipt,
}

pub struct TenantResourceReceiptEvidence<'a> {
    compact_jws: &'a str,
    receipt: &'a TenantResourceReceipt,
    compact_sha256: String,
}

impl TenantResourceReceiptEvidence<'_> {
    pub fn compact_jws(&self) -> &str {
        self.compact_jws
    }

    pub fn receipt(&self) -> &TenantResourceReceipt {
        self.receipt
    }

    pub fn compact_sha256(&self) -> &str {
        &self.compact_sha256
    }

    pub fn receipt_sha256(&self) -> &str {
        self.compact_sha256()
    }
}

impl fmt::Debug for TenantResourceReceiptEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantResourceReceiptEvidence")
            .field("jti", &self.receipt.jti)
            .field("operation", &self.receipt.operation)
            .field("compact_sha256", &self.compact_sha256)
            .finish()
    }
}

impl TenantResourceReceiptResult {
    pub fn receipt(&self) -> &TenantResourceReceipt {
        &self.receipt
    }

    pub fn compact_jws(&self) -> &str {
        &self.compact_jws
    }

    pub fn compact_sha256(&self) -> String {
        compact_sha256(&self.compact_jws)
    }

    pub fn receipt_sha256(&self) -> String {
        self.compact_sha256()
    }

    pub fn evidence(&self) -> TenantResourceReceiptEvidence<'_> {
        TenantResourceReceiptEvidence {
            compact_jws: &self.compact_jws,
            receipt: &self.receipt,
            compact_sha256: self.compact_sha256(),
        }
    }
}

impl fmt::Debug for TenantResourceReceiptResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantResourceReceiptResult")
            .field("jti", &self.receipt.jti)
            .field("operation", &self.receipt.operation)
            .field("compact_sha256", &self.compact_sha256())
            .finish()
    }
}

/// Stable categories exposed by the HTTP contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantResourceHttpStatus {
    BadRequest,
    Unauthorized,
    Forbidden,
    Conflict,
    TooLarge,
    Unavailable,
}

impl TenantResourceHttpStatus {
    pub const fn code(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Conflict => 409,
            Self::TooLarge => 413,
            Self::Unavailable => 503,
        }
    }
}

/// Errors deliberately avoid exposing response bodies or curl diagnostics.
#[derive(Debug)]
pub enum TenantResourceClientError {
    InvalidRequest(String),
    Unauthorized(String),
    Forbidden(String),
    Conflict(String),
    TooLarge,
    Unavailable(String),
    Transport(String),
    Protocol(String),
    UnexpectedStatus(u16),
    TaskFailed(String),
}

impl TenantResourceClientError {
    pub const fn status(&self) -> Option<TenantResourceHttpStatus> {
        match self {
            Self::InvalidRequest(_) => Some(TenantResourceHttpStatus::BadRequest),
            Self::Unauthorized(_) => Some(TenantResourceHttpStatus::Unauthorized),
            Self::Forbidden(_) => Some(TenantResourceHttpStatus::Forbidden),
            Self::Conflict(_) => Some(TenantResourceHttpStatus::Conflict),
            Self::TooLarge => Some(TenantResourceHttpStatus::TooLarge),
            Self::Unavailable(_) | Self::Transport(_) => {
                Some(TenantResourceHttpStatus::Unavailable)
            }
            Self::Protocol(_) | Self::UnexpectedStatus(_) | Self::TaskFailed(_) => None,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self.status() {
            Some(status) => Some(status.code()),
            None => None,
        }
    }
}

impl fmt::Display for TenantResourceClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::Unauthorized(message)
            | Self::Forbidden(message)
            | Self::Conflict(message)
            | Self::Unavailable(message)
            | Self::Transport(message)
            | Self::Protocol(message)
            | Self::TaskFailed(message) => formatter.write_str(message),
            Self::TooLarge => formatter.write_str("tenant resource request is too large"),
            Self::UnexpectedStatus(status) => write!(formatter, "unexpected HTTP status {status}"),
        }
    }
}

impl std::error::Error for TenantResourceClientError {}

/// A synchronous client over an injectable transport.
pub struct TenantResourceClient<T> {
    config: TenantResourceClientConfig,
    transport: T,
}

impl TenantResourceClient<CurlTenantResourceTransport> {
    pub fn with_curl(
        config: TenantResourceClientConfig,
    ) -> Result<Self, TenantResourceClientError> {
        Self::new(config, CurlTenantResourceTransport::default())
    }
}

impl<T: TenantResourceHttpTransport> TenantResourceClient<T> {
    pub fn new(
        config: TenantResourceClientConfig,
        transport: T,
    ) -> Result<Self, TenantResourceClientError> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    pub fn config(&self) -> &TenantResourceClientConfig {
        &self.config
    }

    pub fn discover_capability(
        &self,
    ) -> Result<TenantResourceCapabilitySession, TenantResourceClientError> {
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        self.discover_capability_with_nonce_at(&nonce, Utc::now().timestamp())
    }

    pub fn discover_capability_with_nonce(
        &self,
        nonce: &str,
    ) -> Result<TenantResourceCapabilitySession, TenantResourceClientError> {
        self.discover_capability_with_nonce_at(nonce, Utc::now().timestamp())
    }

    pub fn discover_capability_with_nonce_at(
        &self,
        nonce: &str,
        now: i64,
    ) -> Result<TenantResourceCapabilitySession, TenantResourceClientError> {
        validate_discovery_request(&DiscoveryRequest {
            schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
            nonce: nonce.to_owned(),
        })
        .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))?;
        let request = CapabilityRequest {
            schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
            nonce: nonce.to_owned(),
            tenant_id: self.config.tenant_id.clone(),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|error| TenantResourceClientError::Protocol(error.to_string()))?;
        let response = self.post("management/tenant-resources/capability", &body)?;
        let response: CapabilityResponse =
            serde_json::from_slice(&response.body).map_err(|_| {
                TenantResourceClientError::InvalidRequest("invalid capability response".into())
            })?;
        let capability = verify_tenant_resource_capability_signature(
            &response.capability_jws,
            &self.config.runtime_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_signature_error)?;
        validate_tenant_resource_capability(&capability, now)
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        validate_tenant_resource_capability_request_binding(
            &capability,
            &self.config.deployment_id,
            &self.config.tenant_id,
            &capability.jti,
            nonce,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        if capability.runtime_instance_id != self.config.runtime_instance_id
            || capability.issuer != format!("runtime:{}", self.config.deployment_id)
            || capability.instance_key_id != self.config.runtime_key_id
            || capability.embedded != self.config.embedded
        {
            return Err(TenantResourceClientError::Forbidden(
                "capability runtime identity binding mismatch".into(),
            ));
        }
        Ok(TenantResourceCapabilitySession {
            compact_jws: response.capability_jws,
            capability,
        })
    }

    pub fn apply(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        raw_manifest: &[u8],
        delta_resources: Vec<TenantResourceIdentity>,
        final_active_resources: Vec<TenantResourceIdentity>,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let now = Utc::now().timestamp();
        let prepared = self.prepare_apply(
            capability,
            change_set_id,
            raw_manifest,
            delta_resources,
            final_active_resources,
            now,
        )?;
        self.execute_prepared_live(&prepared)
    }

    pub fn prepare_apply(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        raw_manifest: &[u8],
        delta_resources: Vec<TenantResourceIdentity>,
        final_active_resources: Vec<TenantResourceIdentity>,
        now: i64,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        if raw_manifest.is_empty() {
            return Err(TenantResourceClientError::InvalidRequest(
                "apply manifest is empty".into(),
            ));
        }
        if raw_manifest.len() > MAX_MANIFEST_BYTES {
            return Err(TenantResourceClientError::TooLarge);
        }
        ensure_delta_is_in_final_set(&delta_resources, &final_active_resources)?;
        let resource_manifest_sha256 = canonical_manifest(&final_active_resources)?;
        self.prepare_task(
            capability,
            TenantResourceTaskDraft {
                change_set_id,
                change_set_sha256: hex_sha256(raw_manifest),
                operation: TenantResourceOperation::Apply,
                payload: TenantResourceTaskPayload::Apply {
                    resources: delta_resources,
                },
                resource_manifest_sha256,
                raw_manifest: Some(raw_manifest),
                now,
            },
        )
    }

    pub fn apply_at(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        raw_manifest: &[u8],
        delta_resources: Vec<TenantResourceIdentity>,
        final_active_resources: Vec<TenantResourceIdentity>,
        now: i64,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let prepared = self.prepare_apply(
            capability,
            change_set_id,
            raw_manifest,
            delta_resources,
            final_active_resources,
            now,
        )?;
        self.execute_prepared(&prepared, now)
    }

    pub fn enumerate(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        selectors: Vec<TenantResourceSelector>,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let now = Utc::now().timestamp();
        let prepared =
            self.prepare_enumerate(capability, change_set_id, change_set_sha256, selectors, now)?;
        self.execute_prepared_live(&prepared)
    }

    pub fn prepare_enumerate(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        selectors: Vec<TenantResourceSelector>,
        now: i64,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        validate_digest(change_set_sha256)?;
        self.prepare_task(
            capability,
            TenantResourceTaskDraft {
                change_set_id,
                change_set_sha256: change_set_sha256.to_owned(),
                operation: TenantResourceOperation::Enumerate,
                payload: TenantResourceTaskPayload::Enumerate { selectors },
                resource_manifest_sha256: capability.capability.resource_manifest_sha256.clone(),
                raw_manifest: None,
                now,
            },
        )
    }

    pub fn enumerate_at(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        selectors: Vec<TenantResourceSelector>,
        now: i64,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let prepared =
            self.prepare_enumerate(capability, change_set_id, change_set_sha256, selectors, now)?;
        self.execute_prepared(&prepared, now)
    }

    pub fn revoke(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        resources: Vec<TenantResourceIdentity>,
        final_manifest_sha256: &str,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let now = Utc::now().timestamp();
        let prepared = self.prepare_revoke(
            capability,
            change_set_id,
            change_set_sha256,
            resources,
            final_manifest_sha256,
            now,
        )?;
        self.execute_prepared_live(&prepared)
    }

    pub fn prepare_revoke(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        resources: Vec<TenantResourceIdentity>,
        final_manifest_sha256: &str,
        now: i64,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        validate_digest(change_set_sha256)?;
        validate_digest(final_manifest_sha256)?;
        self.prepare_task(
            capability,
            TenantResourceTaskDraft {
                change_set_id,
                change_set_sha256: change_set_sha256.to_owned(),
                operation: TenantResourceOperation::Revoke,
                payload: TenantResourceTaskPayload::Revoke { resources },
                resource_manifest_sha256: final_manifest_sha256.to_owned(),
                raw_manifest: None,
                now,
            },
        )
    }

    pub fn revoke_at(
        &self,
        capability: &TenantResourceCapabilitySession,
        change_set_id: &str,
        change_set_sha256: &str,
        resources: Vec<TenantResourceIdentity>,
        final_manifest_sha256: &str,
        now: i64,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let prepared = self.prepare_revoke(
            capability,
            change_set_id,
            change_set_sha256,
            resources,
            final_manifest_sha256,
            now,
        )?;
        self.execute_prepared(&prepared, now)
    }

    fn build_task(
        &self,
        session: &TenantResourceCapabilitySession,
        draft: &TenantResourceTaskDraft<'_>,
    ) -> Result<TenantResourceTask, TenantResourceClientError> {
        validate_file_identifier(draft.change_set_id)?;
        validate_digest(&draft.change_set_sha256)?;
        validate_digest(&draft.resource_manifest_sha256)?;
        let verified_capability = verify_tenant_resource_capability_signature(
            &session.compact_jws,
            &self.config.runtime_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_signature_error)?;
        if verified_capability != session.capability {
            return Err(TenantResourceClientError::Forbidden(
                "capability compact JWS does not match decoded capability".into(),
            ));
        }
        let task = TenantResourceTask {
            ver: nazo_operator_protocol::PROTOCOL_VERSION,
            iss: format!("controller:{}", self.config.deployment_id),
            aud: format!("runtime:{}", self.config.deployment_id),
            jti: format!("tenant-resource-{}", Uuid::now_v7()),
            iat: draft.now,
            nbf: draft.now,
            exp: draft
                .now
                .checked_add(TASK_LIFETIME_SECONDS)
                .ok_or_else(|| {
                    TenantResourceClientError::InvalidRequest("task clock overflow".into())
                })?,
            deployment_id: self.config.deployment_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            capability_jti: session.capability.jti.clone(),
            capability_sha256: session.compact_sha256(),
            actor: Actor {
                kind: ActorKind::Automation,
                id: self.config.actor_id.clone(),
            },
            expected_revision: session.capability.revision,
            change_set_id: draft.change_set_id.to_owned(),
            change_set_sha256: draft.change_set_sha256.clone(),
            operation: draft.operation,
            payload: draft.payload.clone(),
            baseline_manifest_sha256: session.capability.resource_manifest_sha256.clone(),
            resource_manifest_sha256: draft.resource_manifest_sha256.clone(),
        };
        validate_tenant_resource_task_deployment_binding(
            &task,
            &self.config.deployment_id,
            &self.config.tenant_id,
        )
        .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))?;
        validate_tenant_resource_task_capability_binding_at(
            &task,
            &session.capability,
            &task.capability_sha256,
            draft.now,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        Ok(task)
    }

    fn prepare_task(
        &self,
        session: &TenantResourceCapabilitySession,
        draft: TenantResourceTaskDraft<'_>,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        let task = self.build_task(session, &draft)?;
        let task_jws = sign_tenant_resource_task(
            &task,
            &self.config.controller_key_id,
            self.config.controller_signing_key.as_ref().ok_or_else(|| {
                TenantResourceClientError::Unavailable(
                    "controller signing key is unavailable for new tasks".into(),
                )
            })?,
        )
        .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))?;
        let body = build_execute_body(&session.compact_jws, &task_jws, draft.raw_manifest)?;
        Ok(PreparedTenantResourceRequest {
            capability_jws: session.compact_jws.clone(),
            task_jws,
            task,
            raw_manifest: draft.raw_manifest.map(|raw| Zeroizing::new(raw.to_vec())),
            body: Zeroizing::new(body),
        })
    }

    /// Rebuild a prepared request from controller-owned recovery metadata and
    /// caller-supplied private manifest bytes.  All signed and digest-bound
    /// identities are checked before the exact envelope is returned.
    pub fn restore_from_recovery(
        &self,
        binding: &TenantResourceRecoveryBinding,
        manifest_bytes: Option<&[u8]>,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        let capability = verify_tenant_resource_capability_signature(
            binding.capability_jws(),
            &self.config.runtime_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_signature_error)?;
        let task = verify_tenant_resource_task_signature(
            binding.task_jws(),
            &self.config.controller_key_id,
            &self.config.controller_public_key,
        )
        .map_err(map_task_signature_error)?;
        if task != *binding.task() {
            return Err(TenantResourceClientError::InvalidRequest(
                "recovery task JWS does not match decoded task".into(),
            ));
        }
        if task.actor.kind != ActorKind::Automation {
            return Err(TenantResourceClientError::Forbidden(
                "tenant resource tasks require an automation actor".into(),
            ));
        }
        if task.operation != binding.operation()
            || task.jti != binding.jti()
            || task.change_set_id != binding.change_set_id()
            || task.change_set_sha256 != binding.change_set_sha256()
        {
            return Err(TenantResourceClientError::InvalidRequest(
                "recovery task identity binding mismatch".into(),
            ));
        }
        validate_tenant_resource_task_deployment_binding(
            &task,
            &self.config.deployment_id,
            &self.config.tenant_id,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        let capability_sha256 = compact_sha256(binding.capability_jws());
        if capability_sha256 != binding.capability_sha256() {
            return Err(TenantResourceClientError::InvalidRequest(
                "recovery capability digest mismatch".into(),
            ));
        }
        let task_sha256 = compact_sha256(binding.task_jws());
        if task_sha256 != binding.task_sha256() {
            return Err(TenantResourceClientError::InvalidRequest(
                "recovery task digest mismatch".into(),
            ));
        }
        validate_tenant_resource_task_capability_binding_with_digest(
            &task,
            &capability,
            &capability_sha256,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        if matches!(task.operation, TenantResourceOperation::Apply) {
            let manifest = manifest_bytes.ok_or_else(|| {
                TenantResourceClientError::InvalidRequest(
                    "apply recovery requires private manifest bytes".into(),
                )
            })?;
            if manifest.is_empty() {
                return Err(TenantResourceClientError::InvalidRequest(
                    "apply recovery manifest is empty".into(),
                ));
            }
            if manifest.len() > MAX_MANIFEST_BYTES {
                return Err(TenantResourceClientError::TooLarge);
            }
            if hex_sha256(manifest) != task.change_set_sha256 {
                return Err(TenantResourceClientError::Forbidden(
                    "recovery manifest digest does not match change set".into(),
                ));
            }
        } else if manifest_bytes.is_some() {
            return Err(TenantResourceClientError::InvalidRequest(
                "non-apply recovery must not carry a manifest".into(),
            ));
        }
        let body =
            build_execute_body(binding.capability_jws(), binding.task_jws(), manifest_bytes)?;
        if hex_sha256(&body) != binding.request_sha256() {
            return Err(TenantResourceClientError::InvalidRequest(
                "recovery request digest mismatch".into(),
            ));
        }
        Ok(PreparedTenantResourceRequest {
            capability_jws: binding.capability_jws().to_owned(),
            task_jws: binding.task_jws().to_owned(),
            task,
            raw_manifest: manifest_bytes.map(|manifest| Zeroizing::new(manifest.to_vec())),
            body: Zeroizing::new(body),
        })
    }

    /// Restore directly from the redacted fields persisted by a recovery
    /// journal.  The caller does not need to decode or verify the task, and
    /// no controller private key is required: the configured pinned public
    /// key performs the verification before the exact binding is rebuilt.
    /// The resulting body still passes through `restore_from_recovery`, so
    /// every digest, JTI, operation, and change-set field is compared before
    /// any transport call.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_from_persisted(
        &self,
        capability_jws: &str,
        task_jws: &str,
        capability_sha256: &str,
        task_sha256: &str,
        request_sha256: &str,
        operation: TenantResourceOperation,
        jti: &str,
        change_set_id: &str,
        change_set_sha256: &str,
        manifest_bytes: Option<&[u8]>,
    ) -> Result<PreparedTenantResourceRequest, TenantResourceClientError> {
        let task = verify_tenant_resource_task_signature(
            task_jws,
            &self.config.controller_key_id,
            &self.config.controller_public_key,
        )
        .map_err(map_task_signature_error)?;
        let binding = TenantResourceRecoveryBinding {
            capability_jws: capability_jws.to_owned(),
            task_jws: task_jws.to_owned(),
            task,
            capability_sha256: capability_sha256.to_owned(),
            task_sha256: task_sha256.to_owned(),
            request_sha256: request_sha256.to_owned(),
            operation,
            jti: jti.to_owned(),
            change_set_id: change_set_id.to_owned(),
            change_set_sha256: change_set_sha256.to_owned(),
        };
        self.restore_from_recovery(&binding, manifest_bytes)
    }

    /// Execute a previously prepared request.  If its validity window has
    /// elapsed, only a runtime-signed receipt for the exact historical request
    /// is accepted; a fresh mutation is never synthesized client-side.
    pub fn execute_prepared(
        &self,
        prepared: &PreparedTenantResourceRequest,
        now: i64,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        self.execute_prepared_inner(prepared, now, false)
    }

    /// Execute against the live runtime clock. Task/capability admission is
    /// checked immediately before dispatch, while receipt freshness is
    /// checked after the HTTP response arrives so a legitimate next-second
    /// completion cannot be rejected with the pre-dispatch timestamp.
    pub fn execute_prepared_live(
        &self,
        prepared: &PreparedTenantResourceRequest,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        self.execute_prepared_inner(prepared, Utc::now().timestamp(), true)
    }

    fn execute_prepared_inner(
        &self,
        prepared: &PreparedTenantResourceRequest,
        now: i64,
        live_receipt_clock: bool,
    ) -> Result<TenantResourceReceiptResult, TenantResourceClientError> {
        let capability = verify_tenant_resource_capability_signature(
            &prepared.capability_jws,
            &self.config.runtime_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_signature_error)?;
        let task = verify_tenant_resource_task_signature(
            &prepared.task_jws,
            &self.config.controller_key_id,
            &self.config.controller_public_key,
        )
        .map_err(map_task_signature_error)?;
        if task != prepared.task {
            return Err(TenantResourceClientError::InvalidRequest(
                "prepared task JWS does not match decoded task".into(),
            ));
        }
        if task.actor.kind != ActorKind::Automation {
            return Err(TenantResourceClientError::Forbidden(
                "tenant resource tasks require an automation actor".into(),
            ));
        }
        validate_tenant_resource_task_deployment_binding(
            &task,
            &self.config.deployment_id,
            &self.config.tenant_id,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        let capability_digest = compact_sha256(&prepared.capability_jws);
        validate_tenant_resource_task_capability_binding_with_digest(
            &task,
            &capability,
            &capability_digest,
        )
        .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        let expired = now < capability.issued_at
            || now > capability.expires_at
            || now < task.nbf
            || now > task.exp;
        if !expired {
            validate_tenant_resource_task_capability_binding_at(
                &task,
                &capability,
                &capability_digest,
                now,
            )
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        }

        let response = self.post(
            "management/tenant-resources/execute",
            prepared.body.as_slice(),
        )?;
        let response: ExecuteResponse = serde_json::from_slice(&response.body).map_err(|_| {
            TenantResourceClientError::Unavailable("invalid receipt response".into())
        })?;
        let receipt = verify_tenant_resource_receipt_signature(
            &response.receipt_jws,
            &self.config.runtime_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_signature_error)?;
        if !expired {
            let receipt_now = if live_receipt_clock {
                Utc::now().timestamp()
            } else {
                now
            };
            verify_tenant_resource_receipt_window(&receipt, receipt_now)
                .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        }
        validate_tenant_resource_receipt_binding(&task, &receipt)
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        if expired {
            validate_tenant_resource_receipt_capability_binding_with_digest(
                &receipt,
                &capability,
                &capability_digest,
            )
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
            if receipt.started_at > task.exp || receipt.completed_at > task.exp {
                return Err(TenantResourceClientError::Forbidden(
                    "expired request returned a non-historical receipt".into(),
                ));
            }
        } else {
            validate_tenant_resource_receipt_capability_binding_at(
                &receipt,
                &capability,
                &capability_digest,
                now,
            )
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        }
        validate_tenant_resource_receipt_request_binding(&receipt, &hex_sha256(prepared.body()))
            .map_err(|error| TenantResourceClientError::Forbidden(error.to_string()))?;
        if let nazo_operator_protocol::TenantResourceOutcome::Failed { code } = &receipt.outcome {
            return Err(TenantResourceClientError::TaskFailed(code.clone()));
        }
        Ok(TenantResourceReceiptResult {
            compact_jws: response.receipt_jws,
            receipt,
        })
    }

    fn post(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<TenantResourceHttpResponse, TenantResourceClientError> {
        let endpoint = self
            .config
            .base_url
            .join(path)
            .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))?;
        let response = self.transport.post_json(&endpoint, body)?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(TenantResourceClientError::TooLarge);
        }
        if response.status != 200 {
            return Err(match response.status {
                400 => {
                    TenantResourceClientError::InvalidRequest("server rejected the request".into())
                }
                401 => TenantResourceClientError::Unauthorized(
                    "server rejected signed evidence".into(),
                ),
                403 => TenantResourceClientError::Forbidden("server denied the request".into()),
                409 => TenantResourceClientError::Conflict("resource revision conflict".into()),
                413 => TenantResourceClientError::TooLarge,
                500..=599 => TenantResourceClientError::Unavailable(
                    "tenant resource provider unavailable".into(),
                ),
                status => TenantResourceClientError::UnexpectedStatus(status),
            });
        }
        Ok(response)
    }
}

fn map_signature_error(error: ProtocolError) -> TenantResourceClientError {
    match error {
        ProtocolError::TooLarge => TenantResourceClientError::TooLarge,
        ProtocolError::SegmentCount | ProtocolError::Base64 | ProtocolError::Json => {
            TenantResourceClientError::InvalidRequest("malformed signed response".into())
        }
        ProtocolError::Header | ProtocolError::Signature => {
            TenantResourceClientError::Unauthorized("signed response verification failed".into())
        }
        ProtocolError::Policy(message) => TenantResourceClientError::InvalidRequest(message.into()),
    }
}

fn map_task_signature_error(error: ProtocolError) -> TenantResourceClientError {
    match error {
        ProtocolError::TooLarge => TenantResourceClientError::TooLarge,
        ProtocolError::SegmentCount | ProtocolError::Base64 | ProtocolError::Json => {
            TenantResourceClientError::InvalidRequest("malformed signed task".into())
        }
        ProtocolError::Header | ProtocolError::Signature => {
            TenantResourceClientError::Unauthorized("task signature verification failed".into())
        }
        ProtocolError::Policy(message) => TenantResourceClientError::InvalidRequest(message.into()),
    }
}

fn canonical_manifest(
    resources: &[TenantResourceIdentity],
) -> Result<String, TenantResourceClientError> {
    tenant_resource_manifest_sha256(resources)
}

/// Compute the protocol-defined digest of a complete active tenant-resource
/// identity set.  Callers such as cleanup/revoke wiring use this helper so
/// the canonical encoding remains owned by `nazo-operator-protocol`.
pub fn tenant_resource_manifest_sha256(
    resources: &[TenantResourceIdentity],
) -> Result<String, TenantResourceClientError> {
    canonical_tenant_resource_manifest_sha256(resources)
        .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))
}

fn build_execute_body(
    capability_jws: &str,
    task_jws: &str,
    raw_manifest: Option<&[u8]>,
) -> Result<Vec<u8>, TenantResourceClientError> {
    let envelope = ExecuteEnvelope {
        capability_jws,
        task_jws,
        manifest_base64url: raw_manifest.map(|raw| URL_SAFE_NO_PAD.encode(raw)),
    };
    let body = serde_json::to_vec(&envelope)
        .map_err(|error| TenantResourceClientError::Protocol(error.to_string()))?;
    if body.len() > MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES {
        return Err(TenantResourceClientError::TooLarge);
    }
    Ok(body)
}

fn ensure_delta_is_in_final_set(
    delta: &[TenantResourceIdentity],
    final_active: &[TenantResourceIdentity],
) -> Result<(), TenantResourceClientError> {
    for requested in delta {
        if !final_active.iter().any(|active| active == requested) {
            return Err(TenantResourceClientError::InvalidRequest(
                "apply final active set must contain every delta identity".into(),
            ));
        }
    }
    Ok(())
}

fn validate_file_identifier(value: &str) -> Result<(), TenantResourceClientError> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|error| TenantResourceClientError::InvalidRequest(error.to_string()))
}

fn validate_identifier(value: &str) -> Result<(), TenantResourceClientError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
    {
        return Err(TenantResourceClientError::InvalidRequest(
            "invalid actor identifier".into(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), TenantResourceClientError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TenantResourceClientError::InvalidRequest(
            "digest must be lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

fn is_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .map(|uuid| uuid.to_string() == value)
        .unwrap_or(false)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
