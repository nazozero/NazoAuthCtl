//! Admin API client for the NazoAuth Controller Registry (goal plan 04,
//! tasks D04–D08; server contract frozen at NazoAuth commit `81870b2f`).
//!
//! The client talks HTTPS to the instance issuer origin and consumes exactly
//! the four admin endpoints the server publishes under
//! `/admin/controller-registry`:
//!
//! ```text
//! GET  /controller-registry/slots?deployment_id=…
//!                                        public read-only slot snapshot
//! POST /approvals                        single-use approval token issuance
//!                                        (the server enforces fresh admin MFA)
//! POST /slots                            bind/add commit
//! POST /slots/rotate                     rotate commit
//! POST /slots/revoke                     revoke commit
//! ```
//!
//! Transport choice: a hyper-rustls client with the platform verifier and
//! `https_only` enforced. TLS verification can neither be disabled nor
//! redirected: the issuer origin is pinned at construction, non-HTTPS origins
//! are rejected before any request is built, and no redirect following exists.
//! This mirrors the ACME transport already in the dependency tree, so no new
//! crates are introduced beyond declaring `http-body-util`, which hyper-util
//! already compiles transitively. The legacy curl-subprocess pattern from
//! `src/controller/bootstrap.rs` was rejected because it belongs to the
//! root-owned deployment lifecycle context and would drag that state machine
//! into identity flows while adding process-spawn and PATH dependence on the
//! control machine.
//!
//! Approval tokens and operator-provided admin access material are secrets:
//! they are never logged, never rendered by [`std::fmt::Debug`], and never
//! echoed. Error rendering carries only status codes plus the server's public
//! error/description fields.

use std::fmt;
use std::time::Duration;

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt as _;
use serde::{Deserialize, Serialize};
use url::Url;

/// Upper bound for any single admin API response body (~64 KiB; slot lists
/// are bounded by the three-slot invariant).
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Total request timeout, matching the controller's existing HTTP budget.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// transport seam
// ---------------------------------------------------------------------------

/// One outbound admin API request. Headers carry exact values; nothing here is
/// logged or rendered.
#[derive(Clone)]
pub struct AdminHttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for AdminHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

/// One inbound admin API response.
#[derive(Clone, Debug)]
pub struct AdminHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Pluggable HTTP seam. Production wires [`HttpsAdminTransport`]; tests feed
/// canned responses including every error shape the server can emit.
pub trait AdminApiTransport: Send + Sync {
    fn send(&self, request: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse>;
}

// ---------------------------------------------------------------------------
// production transport (hyper-rustls, platform verifier, https-only)
// ---------------------------------------------------------------------------

type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

/// Production transport: platform-rooted TLS, HTTPS-only, no redirects, hard
/// request timeout, response-size cap.
pub struct HttpsAdminTransport {
    runtime: tokio::runtime::Runtime,
    client: HttpClient,
}

impl fmt::Debug for HttpsAdminTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsAdminTransport")
    }
}

impl HttpsAdminTransport {
    pub fn new() -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start the admin API runtime")?;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .context("failed to load platform trust for the admin API client")?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client: HttpClient =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        Ok(Self { runtime, client })
    }
}

impl AdminApiTransport for HttpsAdminTransport {
    fn send(&self, request: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse> {
        let mut builder = http::Request::builder()
            .method(request.method)
            .uri(request.url.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        let outgoing = builder
            .body(http_body_util::Full::new(bytes::Bytes::from(
                request.body.unwrap_or_default(),
            )))
            .context("failed to build the admin API request")?;

        let response = self
            .runtime
            .block_on(async {
                match tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(outgoing)).await {
                    Ok(result) => result.map_err(anyhow::Error::from),
                    Err(_) => Err(anyhow::anyhow!(
                        "admin API request timed out after {}s",
                        REQUEST_TIMEOUT.as_secs()
                    )),
                }
            })
            .context("admin API request failed")?;
        let status = response.status().as_u16();
        let (_, body) = response.into_parts();

        let bytes = self
            .runtime
            .block_on(async {
                let mut body = body;
                let mut bytes = Vec::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(anyhow::Error::from)?;
                    if let Ok(data) = frame.into_data() {
                        append_response_frame(&mut bytes, &data)?;
                    }
                }
                Ok::<_, anyhow::Error>(bytes)
            })
            .context("failed to read the admin API response body")?;
        Ok(AdminHttpResponse {
            status,
            body: bytes,
        })
    }
}

/// The cap is enforced as each frame arrives so a malicious peer cannot make
/// ctl collect an oversized response before it notices the limit.
fn append_response_frame(output: &mut Vec<u8>, frame: &[u8]) -> anyhow::Result<()> {
    if frame.len() > MAX_RESPONSE_BYTES.saturating_sub(output.len()) {
        bail!(
            "admin API response exceeds the {} byte limit",
            MAX_RESPONSE_BYTES
        );
    }
    output.extend_from_slice(frame);
    Ok(())
}

// ---------------------------------------------------------------------------
// operator-supplied access material
// ---------------------------------------------------------------------------

/// Operator-provided admin session material attached to every admin API call.
///
/// The NazoAuth admin surface authenticates with its existing cookie session
/// plus the matching CSRF header; ctl never sees administrator passwords or
/// MFA secrets. Automation provisions both values out of band (for example via
/// `--admin-access-file`); interactive runs may omit them and receive the
/// server's own rejection instead.
#[derive(Clone, Default)]
pub struct AdminAccess {
    /// Raw `Cookie` header value carrying the admin session cookie.
    session_cookie: Option<String>,
    /// Raw CSRF token sent as `x-csrf-token`.
    csrf_token: Option<String>,
}

impl AdminAccess {
    pub fn new(session_cookie: Option<String>, csrf_token: Option<String>) -> Self {
        Self {
            session_cookie: session_cookie.filter(|value| !value.trim().is_empty()),
            csrf_token: csrf_token.filter(|value| !value.trim().is_empty()),
        }
    }

    pub fn session_cookie(&self) -> Option<&str> {
        self.session_cookie.as_deref()
    }

    pub fn csrf_token(&self) -> Option<&str> {
        self.csrf_token.as_deref()
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::with_capacity(2);
        if let Some(cookie) = &self.session_cookie {
            headers.push(("Cookie", cookie.clone()));
        }
        if let Some(csrf) = &self.csrf_token {
            headers.push(("x-csrf-token", csrf.clone()));
        }
        headers
    }
}

impl fmt::Debug for AdminAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminAccess")
            .field("session_cookie", &self.session_cookie.is_some())
            .field("csrf_token", &self.csrf_token.is_some())
            .finish()
    }
}

/// Strict schema of the optional `--admin-access-file` document.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAccessFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_cookie: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
}

// ---------------------------------------------------------------------------
// wire types (exact server shapes)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotStatus {
    Active,
    Revoked,
}

impl SlotStatus {
    pub(super) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            other => bail!("unknown controller slot status '{other}'"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// Server-computed expiry warning class (D02).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiryWarningKind {
    Expiring7d,
    Urgent24h,
}

impl ExpiryWarningKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "expiring_7d" => Ok(Self::Expiring7d),
            "urgent_24h" => Ok(Self::Urgent24h),
            other => bail!("unknown controller expiry warning '{other}'"),
        }
    }
}

/// One authoritative controller slot as reported by the server. Public
/// material only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSlotView {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub slot_index: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: SlotStatus,
    pub warning: Option<ExpiryWarningKind>,
}

/// Authoritative answer to "which controllers exist for this deployment".
#[derive(Clone, Debug)]
pub struct SlotsSnapshot {
    pub deployment_id: String,
    pub total: u32,
    pub max_active_slots: u32,
    pub items: Vec<ControllerSlotView>,
}

impl SlotsSnapshot {
    pub fn active_slots(&self) -> Vec<&ControllerSlotView> {
        self.items
            .iter()
            .filter(|slot| slot.status == SlotStatus::Active)
            .collect()
    }
}

/// Non-secret slot summary carried by `controller_slot_limit` rejections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotSummary {
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub slot_index: u32,
    pub expires_at: DateTime<Utc>,
}

/// A freshly issued single-use approval. `approval_token` is a secret and is
/// redacted from [`Debug`].
#[derive(Clone)]
pub struct IssuedApproval {
    pub approval_token: String,
    pub action: String,
    pub action_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
}

impl fmt::Debug for IssuedApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApproval")
            .field("approval_token", &"<redacted>")
            .field("action", &self.action)
            .field("action_sha256", &self.action_sha256)
            .field("expires_at", &self.expires_at)
            .field("single_use", &self.single_use)
            .finish()
    }
}

// --- strict response parsing -------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotViewWire {
    deployment_id: String,
    controller_id: String,
    label: String,
    kid: String,
    slot_index: u32,
    issued_at: String,
    expires_at: String,
    status: String,
    warning: Option<String>,
}

impl SlotViewWire {
    fn into_view(self) -> anyhow::Result<ControllerSlotView> {
        Ok(ControllerSlotView {
            deployment_id: self.deployment_id,
            controller_id: self.controller_id,
            label: self.label,
            kid: self.kid,
            slot_index: self.slot_index,
            issued_at: parse_timestamp(&self.issued_at, "issued_at")?,
            expires_at: parse_timestamp(&self.expires_at, "expires_at")?,
            status: SlotStatus::parse(&self.status)?,
            warning: self
                .warning
                .map(|warning| ExpiryWarningKind::parse(&warning))
                .transpose()?,
        })
    }
}

fn parse_timestamp(value: &str, field: &'static str) -> anyhow::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .with_context(|| format!("controller slot {field} is not RFC 3339"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotsSnapshotWire {
    deployment_id: String,
    total: u32,
    max_active_slots: u32,
    items: Vec<SlotViewWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuedApprovalWire {
    approval_token: String,
    action: String,
    action_sha256: String,
    expires_at: String,
    single_use: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotEnvelopeWire {
    slot: SlotViewWire,
}

/// Tolerant error-body shape: OAuth-style error plus the optional slot-limit
/// summary list. Unknown members are ignored only here, because error bodies
/// are diagnostics rather than contract facts.
#[derive(Deserialize, Default)]
struct ErrorBodyWire {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    active_slots: Option<Vec<SlotSummaryWire>>,
}

#[derive(Deserialize)]
struct SlotSummaryWire {
    controller_id: String,
    label: String,
    kid: String,
    slot_index: u32,
    expires_at: String,
}

// ---------------------------------------------------------------------------
// typed requests (mirror the server's strict bodies verbatim)
// ---------------------------------------------------------------------------

/// Payload for a bind/add/rotate/revoke approval issuance.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequestBody {
    pub action: &'static str,
    pub deployment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// P0-3 atomic first binding: carried ONLY by `bind`; the canonical
    /// server-side digest covers it, so the approval and the commit stay
    /// bound to the same recovery material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_kid: Option<String>,
}

/// Body of `POST /slots` (bind/add commit).
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlotCommitBody {
    pub approval_token: String,
    pub action: &'static str,
    pub deployment_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
    /// P0-3: present on `bind`, absent otherwise; must match the approved
    /// payload byte-for-byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_kid: Option<String>,
}

/// Body of `POST /slots/rotate`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateCommitBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
}

/// Body of `POST /slots/revoke`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCommitBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub controller_id: String,
}

// ---------------------------------------------------------------------------
// error taxonomy
// ---------------------------------------------------------------------------

/// Failure of one admin API call. Transport-level faults keep their cause;
/// server decisions are typed so flows can react without string matching on
/// localized descriptions.
#[derive(Debug)]
pub enum AdminApiError {
    /// 409 `controller_slot_limit`: three unrevoked slots already exist.
    SlotLimit(Vec<SlotSummary>),
    /// Any other structured server rejection (status + error code).
    Rejected {
        status: u16,
        error: String,
        description: String,
    },
    /// 2xx but the body violates the frozen response schema (contract drift).
    MalformedResponse(anyhow::Error),
    /// The request never produced an authoritative outcome.
    Transport(anyhow::Error),
}

impl fmt::Display for AdminApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotLimit(summaries) => {
                write!(
                    formatter,
                    "{}: the deployment already has three unrevoked controller slots; revoke one first. Active slots:",
                    crate::error_codes::CONTROLLER_SLOT_LIMIT
                )?;
                for summary in summaries {
                    write!(
                        formatter,
                        "\n  - controller {} label '{}' kid {} slot {} expires {}",
                        summary.controller_id,
                        summary.label,
                        short_kid(&summary.kid),
                        summary.slot_index,
                        summary.expires_at.to_rfc3339()
                    )?;
                }
                Ok(())
            }
            Self::Rejected {
                status,
                error,
                description,
            } => {
                if matches!(status, 401 | 403) {
                    write!(
                        formatter,
                        "{}: the admin API rejected the request (HTTP {status}, error {error}): \
                         {description}",
                        crate::error_codes::ADMIN_ACCESS_REQUIRED
                    )
                } else {
                    write!(
                        formatter,
                        "admin API rejected the request (HTTP {status}, error {error}): {description}"
                    )
                }
            }
            Self::MalformedResponse(error) => write!(
                formatter,
                "admin API response violated the frozen contract: {error:#}"
            ),
            Self::Transport(error) => write!(formatter, "admin API transport failed: {error:#}"),
        }
    }
}

impl std::error::Error for AdminApiError {}

/// Short public fingerprint used in human-facing output (first 12 chars).
pub fn short_kid(kid: &str) -> &str {
    &kid[..kid.len().min(12)]
}

// ---------------------------------------------------------------------------
// client trait + HTTPS implementation
// ---------------------------------------------------------------------------

/// Synchronous seam consumed by the D04–D08 lifecycle flows. Sync on purpose:
/// every ctl command path is synchronous today, so the async boundary stays
/// confined inside [`HttpsAdminTransport`].
pub trait ControllerRegistryApi {
    fn list_slots(&self, deployment_id: &str) -> Result<SlotsSnapshot, AdminApiError>;
    fn issue_approval(&self, body: &ApprovalRequestBody) -> Result<IssuedApproval, AdminApiError>;
    fn commit_slot(&self, body: &SlotCommitBody) -> Result<ControllerSlotView, AdminApiError>;
    fn rotate_slot(&self, body: &RotateCommitBody) -> Result<ControllerSlotView, AdminApiError>;
    fn revoke_slot(&self, body: &RevokeCommitBody) -> Result<ControllerSlotView, AdminApiError>;
    /// Read-only Recovery Root view (D12 admin surface).
    fn recovery_root_view(&self, deployment_id: &str) -> Result<RecoveryRootView, AdminApiError>;
    /// Issue a fresh-2FA approval for one exact root-rotation digest.
    fn issue_recovery_root_approval(
        &self,
        body: &RecoveryRootApprovalBody,
    ) -> Result<IssuedApproval, AdminApiError>;
    /// Commit an approved replacement; consumption and replacement are
    /// atomic server-side.
    fn rotate_recovery_root(
        &self,
        body: &RecoveryRootRotateBody,
    ) -> Result<RecoveryRootView, AdminApiError>;
    /// Request one break-glass challenge after proving possession of the
    /// current Recovery Root in the request body.
    fn issue_recovery_challenge(
        &self,
        body: &RecoveryChallengeBody,
    ) -> Result<IssuedRecoveryChallenge, AdminApiError>;
    /// Submit the signed answer; on success the server revokes every slot,
    /// installs exactly one recovered slot, and bumps the root generation.
    fn submit_recovery_answer(
        &self,
        body: &RecoveryAnswerBody,
    ) -> Result<RecoveryCommitView, AdminApiError>;
}

/// Production [`ControllerRegistryApi`] over one pinned issuer origin.
pub struct HttpControllerRegistryApi {
    issuer: Url,
    access: AdminAccess,
    transport: Box<dyn AdminApiTransport>,
}

impl fmt::Debug for HttpControllerRegistryApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpControllerRegistryApi")
            .field("issuer", &self.issuer.as_str())
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl HttpControllerRegistryApi {
    /// Pin the instance issuer origin. HTTPS is mandatory: the admin surface
    /// carries session credentials and must never cross plaintext origins.
    pub fn new(issuer: &str, access: AdminAccess) -> anyhow::Result<Self> {
        Self::with_transport(issuer, access, Box::new(HttpsAdminTransport::new()?))
    }

    /// Injectable constructor (tests supply canned transports).
    pub fn with_transport(
        issuer: &str,
        access: AdminAccess,
        transport: Box<dyn AdminApiTransport>,
    ) -> anyhow::Result<Self> {
        let parsed =
            Url::parse(issuer).with_context(|| format!("issuer '{issuer}' is not a URL"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            bail!("the admin API requires a bare HTTPS issuer origin");
        }
        Ok(Self {
            issuer: parsed,
            access,
            transport,
        })
    }

    fn endpoint_url(&self, path: &str, query: Option<(&str, &str)>) -> String {
        let mut url = format!("{}{}", self.issuer.as_str().trim_end_matches('/'), path);
        if let Some((name, value)) = query {
            url.push('?');
            url.push_str(name);
            url.push('=');
            url.push_str(urlencoding::encode(value).as_ref());
        }
        url
    }

    fn send_json(
        &self,
        method: &'static str,
        path: &str,
        query: Option<(&str, &str)>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, AdminApiError> {
        // A Recovery Secret is its own authority and must never share an
        // administrator session. This is structural: even the
        // normal `controller recover` command cannot send Cookie/CSRF there.
        let mut headers = if matches!(
            path,
            "/controller-recovery/challenges"
                | "/controller-recovery/recover"
                | "/controller-registry/slots"
        ) {
            Vec::new()
        } else {
            self.access.headers()
        };
        if body.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let request = AdminHttpRequest {
            method,
            url: self.endpoint_url(path, query),
            headers,
            body,
        };
        let response = self
            .transport
            .send(request)
            .map_err(AdminApiError::Transport)?;
        decode_response(response)
    }
}

/// Shared response decoding: 2xx returns the body, everything else maps onto
/// the typed taxonomy. Malformed success bodies fail closed.
fn decode_response(response: AdminHttpResponse) -> Result<Vec<u8>, AdminApiError> {
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    let parsed: ErrorBodyWire = serde_json::from_slice(&response.body).unwrap_or_default();
    if response.status == 409 && parsed.error.as_deref() == Some("controller_slot_limit") {
        let mut summaries = Vec::new();
        for wire in parsed.active_slots.unwrap_or_default() {
            let expires_at = parse_timestamp(&wire.expires_at, "expires_at")
                .map_err(AdminApiError::MalformedResponse)?;
            summaries.push(SlotSummary {
                controller_id: wire.controller_id,
                label: wire.label,
                kid: wire.kid,
                slot_index: wire.slot_index,
                expires_at,
            });
        }
        return Err(AdminApiError::SlotLimit(summaries));
    }
    Err(AdminApiError::Rejected {
        status: response.status,
        error: parsed.error.unwrap_or_else(|| "unknown_error".to_owned()),
        description: parsed
            .error_description
            .unwrap_or_else(|| "the server returned no description".to_owned()),
    })
}

fn serialize_body<T: Serialize>(body: &T) -> Result<Vec<u8>, AdminApiError> {
    serde_json::to_vec(body).map_err(|error| AdminApiError::Transport(anyhow::Error::new(error)))
}

impl ControllerRegistryApi for HttpControllerRegistryApi {
    fn list_slots(&self, deployment_id: &str) -> Result<SlotsSnapshot, AdminApiError> {
        let raw = self.send_json(
            "GET",
            "/controller-registry/slots",
            Some(("deployment_id", deployment_id)),
            None,
        )?;
        let wire: SlotsSnapshotWire = serde_json::from_slice(&raw)
            .map_err(|error| AdminApiError::MalformedResponse(anyhow::Error::new(error)))?;
        let items = wire
            .items
            .into_iter()
            .map(SlotViewWire::into_view)
            .collect::<Result<Vec<_>, _>>()
            .map_err(AdminApiError::MalformedResponse)?;
        Ok(SlotsSnapshot {
            deployment_id: wire.deployment_id,
            total: wire.total,
            max_active_slots: wire.max_active_slots,
            items,
        })
    }

    fn issue_approval(&self, body: &ApprovalRequestBody) -> Result<IssuedApproval, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/approvals",
            None,
            Some(serialize_body(body)?),
        )?;
        let wire: IssuedApprovalWire = serde_json::from_slice(&raw)
            .map_err(|error| AdminApiError::MalformedResponse(anyhow::Error::new(error)))?;
        Ok(IssuedApproval {
            approval_token: wire.approval_token,
            action: wire.action,
            action_sha256: wire.action_sha256,
            expires_at: parse_timestamp(&wire.expires_at, "expires_at")
                .map_err(AdminApiError::MalformedResponse)?,
            single_use: wire.single_use,
        })
    }

    fn commit_slot(&self, body: &SlotCommitBody) -> Result<ControllerSlotView, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/slots",
            None,
            Some(serialize_body(body)?),
        )?;
        decode_slot_envelope(raw)
    }

    fn rotate_slot(&self, body: &RotateCommitBody) -> Result<ControllerSlotView, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/slots/rotate",
            None,
            Some(serialize_body(body)?),
        )?;
        decode_slot_envelope(raw)
    }

    fn revoke_slot(&self, body: &RevokeCommitBody) -> Result<ControllerSlotView, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/slots/revoke",
            None,
            Some(serialize_body(body)?),
        )?;
        decode_slot_envelope(raw)
    }

    fn recovery_root_view(&self, deployment_id: &str) -> Result<RecoveryRootView, AdminApiError> {
        let raw = self.send_json(
            "GET",
            "/admin/controller-registry/recovery-root",
            Some(("deployment_id", deployment_id)),
            None,
        )?;
        decode_recovery_root_view(raw)
    }

    fn issue_recovery_root_approval(
        &self,
        body: &RecoveryRootApprovalBody,
    ) -> Result<IssuedApproval, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/recovery-root/approvals",
            None,
            Some(serialize_body(body)?),
        )?;
        let wire: IssuedApprovalWire = serde_json::from_slice(&raw).map_err(malformed_response)?;
        Ok(IssuedApproval {
            approval_token: wire.approval_token,
            action: wire.action,
            action_sha256: wire.action_sha256,
            expires_at: parse_timestamp(&wire.expires_at, "expires_at")
                .map_err(AdminApiError::MalformedResponse)?,
            single_use: wire.single_use,
        })
    }

    fn rotate_recovery_root(
        &self,
        body: &RecoveryRootRotateBody,
    ) -> Result<RecoveryRootView, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/admin/controller-registry/recovery-root/rotate",
            None,
            Some(serialize_body(body)?),
        )?;
        let value: serde_json::Value = serde_json::from_slice(&raw).map_err(malformed_response)?;
        // The commit response wraps the root object without the `present`
        // discriminant (it is implicitly present); normalize before decoding.
        let mut inner = value
            .get("recovery_root")
            .cloned()
            .and_then(|inner| inner.as_object().cloned())
            .ok_or_else(|| malformed_response(anyhow::anyhow!("missing 'recovery_root'")))?;
        if inner.contains_key("present") {
            return Err(malformed_response(anyhow::anyhow!(
                "recovery_root must not carry 'present'"
            )));
        }
        inner.insert("present".to_owned(), serde_json::Value::Bool(true));
        decode_recovery_root_view(
            serde_json::to_vec(&serde_json::Value::Object(inner)).map_err(malformed_response)?,
        )
    }

    fn issue_recovery_challenge(
        &self,
        body: &RecoveryChallengeBody,
    ) -> Result<IssuedRecoveryChallenge, AdminApiError> {
        use base64::Engine as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ChallengeWire {
            challenge_id: String,
            deployment_id: String,
            nonce: String,
            expires_at: String,
            algorithm: serde_json::Value,
            single_use: bool,
        }
        // Break-glass route never carries browser-session credentials.
        let raw = self.send_json(
            "POST",
            "/controller-recovery/challenges",
            None,
            Some(serialize_body(body)?),
        )?;
        let wire: ChallengeWire = serde_json::from_slice(&raw).map_err(malformed_response)?;
        if wire.deployment_id != body.deployment_id {
            return Err(malformed_response(anyhow::anyhow!(
                "server challenge echoed a different deployment id"
            )));
        }
        if wire.algorithm != serde_json::json!({"type": "Ed25519"}) {
            return Err(malformed_response(anyhow::anyhow!(
                "server challenge selected an unsupported signature algorithm"
            )));
        }
        if !wire.single_use {
            return Err(malformed_response(anyhow::anyhow!(
                "server issued a non-single-use challenge"
            )));
        }
        let nonce_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(wire.nonce.as_bytes())
            .map_err(malformed_response)?;
        let nonce: [u8; 32] = nonce_bytes
            .try_into()
            .map_err(|_| malformed_response(anyhow::anyhow!("challenge nonce is not 32 bytes")))?;
        Ok(IssuedRecoveryChallenge {
            challenge_id: wire.challenge_id,
            nonce,
            expires_at: parse_timestamp(&wire.expires_at, "expires_at")
                .map_err(AdminApiError::MalformedResponse)?,
        })
    }

    fn submit_recovery_answer(
        &self,
        body: &RecoveryAnswerBody,
    ) -> Result<RecoveryCommitView, AdminApiError> {
        let raw = self.send_json(
            "POST",
            "/controller-recovery/recover",
            None,
            Some(serialize_body(body)?),
        )?;
        decode_recovery_commit(raw)
    }
}

fn decode_slot_envelope(raw: Vec<u8>) -> Result<ControllerSlotView, AdminApiError> {
    let wire: SlotEnvelopeWire = serde_json::from_slice(&raw)
        .map_err(|error| AdminApiError::MalformedResponse(anyhow::Error::new(error)))?;
    wire.slot
        .into_view()
        .map_err(AdminApiError::MalformedResponse)
}

// ---------------------------------------------------------------------------
// recovery-root + break-glass recovery contract (goal plan 04A, D10–D12;
// server shapes frozen at NazoAuth commit `9e4499dd`)
// ---------------------------------------------------------------------------

/// Body of `POST /admin/controller-registry/recovery-root/approvals`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRootApprovalBody {
    pub deployment_id: String,
    /// Unpadded base64url of the 32-byte replacement Recovery Public Key.
    pub recovery_public_key: String,
    pub kid: String,
}

/// Body of `POST /admin/controller-registry/recovery-root/rotate`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRootRotateBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub recovery_public_key: String,
    pub kid: String,
}

/// Body of `POST /controller-recovery/challenges`.  The `recovery_*` fields
/// name the REPLACEMENT root installed on success; the answer itself is
/// signed by the OLD secret's key against the CURRENT root.
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallengeBody {
    pub deployment_id: String,
    pub label: String,
    pub controller_public_key: String,
    pub kid: String,
    pub recovery_public_key: String,
    pub recovery_kid: String,
    pub allocation_nonce: String,
    pub allocation_signature: String,
}

/// Body of `POST /controller-recovery/recover`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAnswerBody {
    pub deployment_id: String,
    pub challenge_id: String,
    pub nonce: String,
    pub signature: String,
}

/// Read-only admin view of one deployment's Recovery Root. Public key bytes
/// are never part of this view by server design.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRootView {
    pub deployment_id: String,
    pub present: bool,
    pub recovery_kid: Option<String>,
    pub kdf: Option<String>,
    pub generation: Option<u64>,
}

/// One issued break-glass challenge.
#[derive(Clone, Debug)]
pub struct IssuedRecoveryChallenge {
    pub challenge_id: String,
    pub nonce: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

/// Authoritative result of one accepted recovery commit.
#[derive(Clone, Debug)]
pub struct RecoveryCommitView {
    pub slot: ControllerSlotView,
    pub recovery_generation: u64,
}

fn malformed_response(error: impl Into<anyhow::Error>) -> AdminApiError {
    AdminApiError::MalformedResponse(error.into())
}

fn decode_recovery_root_view(raw: Vec<u8>) -> Result<RecoveryRootView, AdminApiError> {
    let mut object =
        match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&raw) {
            Ok(object) => object,
            Err(error) => return Err(malformed_response(error)),
        };
    let present = object
        .get("present")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_response(anyhow::anyhow!("missing boolean 'present'")))?;
    // Strip the discriminant so each branch can stay deny_unknown_fields.
    object.remove("present");
    let value = serde_json::Value::Object(object);
    if !present {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AbsentWire {
            deployment_id: String,
        }
        let wire: AbsentWire = serde_json::from_value(value).map_err(malformed_response)?;
        return Ok(RecoveryRootView {
            deployment_id: wire.deployment_id,
            present: false,
            recovery_kid: None,
            kdf: None,
            generation: None,
        });
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PresentWire {
        deployment_id: String,
        recovery_kid: String,
        kdf: String,
        generation: u64,
    }
    let wire: PresentWire = serde_json::from_value(value).map_err(malformed_response)?;
    Ok(RecoveryRootView {
        deployment_id: wire.deployment_id,
        present: true,
        recovery_kid: Some(wire.recovery_kid),
        kdf: Some(wire.kdf),
        generation: Some(wire.generation),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryCommitWire {
    slot: SlotViewWire,
    recovery_generation: u64,
    /// Public confirmation that the previous generation stopped verifying at
    /// commit time; asserted so contract drift cannot silently weaken it.
    #[serde(default)]
    old_recovery_secret_invalid: Option<bool>,
}

fn decode_recovery_commit(raw: Vec<u8>) -> Result<RecoveryCommitView, AdminApiError> {
    let wire: RecoveryCommitWire = serde_json::from_slice(&raw).map_err(malformed_response)?;
    if wire.old_recovery_secret_invalid != Some(true) {
        return Err(malformed_response(anyhow::anyhow!(
            "recovery commit did not confirm previous-generation invalidation"
        )));
    }
    Ok(RecoveryCommitView {
        slot: wire
            .slot
            .into_view()
            .map_err(AdminApiError::MalformedResponse)?,
        recovery_generation: wire.recovery_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const SLOT_JSON: &str = r#"{"deployment_id":"deploy-alpha","controller_id":"01900000-0000-7000-8000-000000000001","label":"ops","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0","slot_index":0,"issued_at":"2026-08-24T00:00:00Z","expires_at":"2026-09-23T00:00:00Z","status":"active","warning":null}"#;

    /// Canned transport recording every request it saw; shareable so tests keep
    /// a handle after the client takes ownership.
    #[derive(Clone, Default)]
    struct CannedTransport {
        inner: Arc<CannedInner>,
    }

    #[derive(Default)]
    struct CannedInner {
        responses: Mutex<Vec<anyhow::Result<AdminHttpResponse>>>,
        seen: Mutex<Vec<AdminHttpRequest>>,
    }

    impl CannedTransport {
        fn push(&self, status: u16, body: &str) -> &Self {
            self.inner
                .responses
                .lock()
                .unwrap()
                .push(Ok(AdminHttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                }));
            self
        }

        fn requests(&self) -> Vec<AdminHttpRequest> {
            self.inner.seen.lock().unwrap().clone()
        }
    }

    impl AdminApiTransport for CannedTransport {
        fn send(&self, request: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse> {
            self.inner.seen.lock().unwrap().push(request);
            self.inner
                .responses
                .lock()
                .unwrap()
                .pop()
                .expect("no canned response left")
        }
    }

    fn https_client(transport: CannedTransport) -> HttpControllerRegistryApi {
        HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::default(),
            Box::new(transport),
        )
        .expect("valid issuer")
    }

    #[test]
    fn rejects_non_https_and_decorated_issuers() {
        for bad in [
            "http://auth.example.com",
            "https://user:pw@example.com/",
            "https://example.com/admin",
            "not a url",
        ] {
            assert!(
                HttpControllerRegistryApi::with_transport(
                    bad,
                    AdminAccess::default(),
                    Box::new(CannedTransport::default())
                )
                .is_err(),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn slots_list_parses_into_typed_snapshot_and_sends_encoded_query() {
        let transport = CannedTransport::default();
        let list_body = format!(
            r#"{{"deployment_id":"deploy-alpha","total":1,"max_active_slots":3,"items":[{SLOT_JSON}]}}"#
        );
        transport.push(200, &list_body);
        let client = HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::new(
                Some("must-not-be-sent=1".to_owned()),
                Some("csrf-no".to_owned()),
            ),
            Box::new(transport.clone()),
        )
        .unwrap();
        let snapshot = client.list_slots("deploy alpha?x").expect("snapshot");
        assert_eq!(snapshot.deployment_id, "deploy-alpha");
        assert_eq!(snapshot.max_active_slots, 3);
        assert_eq!(snapshot.active_slots().len(), 1);
        let slot = snapshot.items[0].clone();
        assert_eq!(slot.status, SlotStatus::Active);
        assert_eq!(slot.warning, None);
        assert_eq!(slot.expires_at.to_rfc3339(), "2026-09-23T00:00:00+00:00");

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://auth.example.com/controller-registry/slots?deployment_id=deploy%20alpha%3Fx"
        );
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].body.is_none());
        assert!(
            requests[0].headers.is_empty(),
            "the public read-only query must not carry admin credentials"
        );
    }

    #[test]
    fn warning_classes_parse_strictly() {
        let make_list = |warning: &str| {
            format!(
                r#"{{"deployment_id":"d","total":1,"max_active_slots":3,"items":[{SLOT_JSON}]}}"#
            )
            .replace("\"warning\":null", &format!("\"warning\":\"{warning}\""))
        };
        let transport = CannedTransport::default();
        transport.push(200, &make_list("expiring_7d"));
        let client = https_client(transport.clone());
        assert_eq!(
            client.list_slots("d").unwrap().items[0].warning,
            Some(ExpiryWarningKind::Expiring7d)
        );

        transport.push(200, &make_list("urgent_24h"));
        assert_eq!(
            client.list_slots("d").unwrap().items[0].warning,
            Some(ExpiryWarningKind::Urgent24h)
        );

        // An unknown server-side class must fail closed instead of being
        // dropped silently.
        transport.push(200, &make_list("some_new_class"));
        assert!(matches!(
            client.list_slots("d"),
            Err(AdminApiError::MalformedResponse(_))
        ));
    }

    #[test]
    fn slot_commit_sends_exact_contract_body_and_attaches_access_headers() {
        let transport = CannedTransport::default();
        transport.push(200, &format!("{{\"slot\":{SLOT_JSON}}}"));
        let client = HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::new(Some("session=abc".to_owned()), Some("csrf-1".to_owned())),
            Box::new(transport.clone()),
        )
        .unwrap();
        let view = client
            .commit_slot(&SlotCommitBody {
                approval_token: "tok".to_owned(),
                action: "bind",
                deployment_id: "deploy-alpha".to_owned(),
                label: "ops".to_owned(),
                public_key: "pk".to_owned(),
                kid: "k".to_owned(),
                recovery_public_key: Some("rpk".to_owned()),
                recovery_kid: Some("rkid".to_owned()),
            })
            .expect("committed");
        assert_eq!(view.controller_id, "01900000-0000-7000-8000-000000000001");

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.url,
            "https://auth.example.com/admin/controller-registry/slots"
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| *name == "Cookie" && value == "session=abc")
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| *name == "x-csrf-token" && value == "csrf-1")
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| *name == "Content-Type" && value == "application/json")
        );
        let body_text = std::str::from_utf8(request.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body_text,
            r#"{"approval_token":"tok","action":"bind","deployment_id":"deploy-alpha","label":"ops","public_key":"pk","kid":"k","recovery_public_key":"rpk","recovery_kid":"rkid"}"#
        );
    }

    #[test]
    fn recovery_ceremony_never_attaches_admin_access_headers() -> anyhow::Result<()> {
        let transport = CannedTransport::default();
        transport.push(200, "{}");
        let client = HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::new(
                Some("session=must-not-leak".to_owned()),
                Some("csrf-no".to_owned()),
            ),
            Box::new(transport.clone()),
        )?;
        client.send_json(
            "POST",
            "/controller-recovery/challenges",
            None,
            Some(b"{}".to_vec()),
        )?;
        let request = transport.requests().pop().expect("one request");
        assert_eq!(
            request.headers,
            vec![("Content-Type", "application/json".to_owned())]
        );
        Ok(())
    }

    #[test]
    fn response_cap_is_enforced_before_oversized_frame_is_appended() {
        let mut collected = vec![0; MAX_RESPONSE_BYTES - 1];
        assert!(append_response_frame(&mut collected, &[1]).is_ok());
        assert_eq!(collected.len(), MAX_RESPONSE_BYTES);
        assert!(append_response_frame(&mut collected, &[2]).is_err());
        assert_eq!(collected.len(), MAX_RESPONSE_BYTES);
    }

    #[test]
    fn rotate_revoke_and_approvals_hit_exact_paths() {
        let transport = CannedTransport::default();
        transport.push(200, &format!("{{\"slot\":{SLOT_JSON}}}"));
        transport.push(200, &format!("{{\"slot\":{SLOT_JSON}}}"));
        let client = https_client(transport.clone());

        let rotated = client
            .rotate_slot(&RotateCommitBody {
                approval_token: "t".to_owned(),
                deployment_id: "deploy-alpha".to_owned(),
                controller_id: "c1".to_owned(),
                label: "l".to_owned(),
                public_key: "pk".to_owned(),
                kid: "k".to_owned(),
            })
            .expect("rotated");
        assert_eq!(rotated.kid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0");

        let revoked = client
            .revoke_slot(&RevokeCommitBody {
                approval_token: "t".to_owned(),
                deployment_id: "deploy-alpha".to_owned(),
                controller_id: "c1".to_owned(),
            })
            .expect("revoked");
        assert_eq!(revoked.status, SlotStatus::Active);

        let paths: Vec<(String, String)> = transport
            .requests()
            .into_iter()
            .map(|request| (request.method.to_owned(), request.url))
            .collect();
        assert_eq!(
            paths,
            vec![
                (
                    "POST".to_owned(),
                    "https://auth.example.com/admin/controller-registry/slots/rotate".to_owned()
                ),
                (
                    "POST".to_owned(),
                    "https://auth.example.com/admin/controller-registry/slots/revoke".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn approvals_endpoint_parses_single_use_token_shape() {
        let transport = CannedTransport::default();
        transport.push(
            200,
            r#"{"approval_token":"one-time-secret","action":"bind","action_sha256":"c0ffee","expires_at":"2026-08-24T00:10:00Z","single_use":true}"#,
        );
        let client = https_client(transport.clone());
        let issued = client
            .issue_approval(&ApprovalRequestBody {
                action: "bind",
                deployment_id: "deploy-alpha".to_owned(),
                controller_id: None,
                label: Some("ops".to_owned()),
                public_key: Some("pk".to_owned()),
                kid: Some("kid".to_owned()),
                recovery_public_key: None,
                recovery_kid: None,
            })
            .expect("approval");
        assert_eq!(issued.action, "bind");
        assert!(issued.single_use);
        assert!(!format!("{issued:?}").contains("one-time-secret"));

        let requests = transport.requests();
        let body_text = std::str::from_utf8(requests[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body_text,
            r#"{"action":"bind","deployment_id":"deploy-alpha","label":"ops","public_key":"pk","kid":"kid"}"#
        );
    }

    #[test]
    fn slot_limit_conflict_maps_to_typed_error_with_summaries() {
        let transport = CannedTransport::default();
        transport.push(
            409,
            r#"{"error":"controller_slot_limit","error_description":"full","active_slots":[{"controller_id":"c1","label":"a","kid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1","slot_index":0,"expires_at":"2026-09-01T00:00:00Z"}]}"#,
        );
        let client = https_client(transport);
        let error = client.list_slots("deploy-alpha").expect_err("slot limit");
        match &error {
            AdminApiError::SlotLimit(summaries) => {
                assert_eq!(summaries.len(), 1);
                assert_eq!(summaries[0].controller_id, "c1");
            }
            other => panic!("expected SlotLimit, got {other:?}"),
        }
        let rendered = error.to_string();
        assert!(rendered.contains("CONTROLLER_SLOT_LIMIT"), "{rendered}");
        assert!(rendered.contains("revoke one first"), "{rendered}");
        assert!(rendered.contains("bbbbbbbbbbbb"), "{rendered}");
    }

    #[test]
    fn rejection_shapes_surface_status_code_and_description() {
        let cases: [(u16, &str, &str); 4] = [
            (
                400,
                r#"{"error":"invalid_request","error_description":"审批令牌已过期；请在十分钟窗口内完成提交."}"#,
                "invalid_request",
            ),
            (
                409,
                r#"{"error":"invalid_request","error_description":"审批令牌已被使用；身份变更需要重新批准."}"#,
                "invalid_request",
            ),
            (
                400,
                r#"{"error":"invalid_request","error_description":"审批令牌与本次提交的动作内容不一致."}"#,
                "invalid_request",
            ),
            (
                503,
                r#"{"error":"server_error","error_description":"审批状态查询失败."}"#,
                "server_error",
            ),
        ];
        for (status, body, expected_error) in cases {
            let transport = CannedTransport::default();
            transport.push(status, body);
            let client = https_client(transport);
            let error = client.list_slots("deploy-alpha").expect_err("rejection");
            match &error {
                AdminApiError::Rejected {
                    status: got,
                    error: code,
                    description,
                } => {
                    assert_eq!(*got, status);
                    assert_eq!(code, expected_error);
                    assert!(!description.is_empty());
                }
                other => panic!("expected Rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_success_bodies_fail_closed() {
        let transport = CannedTransport::default();
        transport.push(200, r#"{"slot":{"unexpected":true}}"#);
        let client = https_client(transport);
        let error = client.list_slots("deploy-alpha").expect_err("malformed");
        assert!(
            matches!(error, AdminApiError::MalformedResponse(_)),
            "{error:?}"
        );
    }

    #[test]
    fn unknown_status_spelling_fails_closed() {
        let transport = CannedTransport::default();
        let drifted = SLOT_JSON.replace("\"status\":\"active\"", "\"status\":\"zombie\"");
        transport.push(
            200,
            &format!(
                r#"{{"total":0,"deployment_id":"d","max_active_slots":3,"items":[{drifted}]}}"#
            ),
        );
        let client = https_client(transport);
        assert!(matches!(
            client.list_slots("d"),
            Err(AdminApiError::MalformedResponse(_))
        ));
    }

    #[test]
    fn transport_failures_keep_unknown_outcome() {
        struct FailingTransport;
        impl AdminApiTransport for FailingTransport {
            fn send(&self, _: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse> {
                bail!("connection reset")
            }
        }
        let client = HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::default(),
            Box::new(FailingTransport),
        )
        .unwrap();
        let error = client.list_slots("deploy-alpha").expect_err("failure");
        assert!(matches!(error, AdminApiError::Transport(_)), "{error:?}");
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let approval = IssuedApproval {
            approval_token: "super-secret-token".to_owned(),
            action: "bind".to_owned(),
            action_sha256: "ab".repeat(32),
            expires_at: Utc::now(),
            single_use: true,
        };
        let rendered = format!("{approval:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");

        let access = AdminAccess::new(
            Some("session-cookie-value".to_owned()),
            Some("csrf-value".to_owned()),
        );
        let rendered = format!("{access:?}");
        assert!(!rendered.contains("session-cookie-value"), "{rendered}");
        assert!(!rendered.contains("csrf-value"), "{rendered}");

        let request = AdminHttpRequest {
            method: "POST",
            url: "https://auth.example.com/x".to_owned(),
            headers: vec![("Cookie", "secret-cookie-value".to_owned())],
            body: Some(b"secret-body-value".to_vec()),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-cookie-value"), "{rendered}");
        assert!(!rendered.contains("secret-body-value"), "{rendered}");

        let api = HttpControllerRegistryApi::with_transport(
            "https://auth.example.com",
            AdminAccess::new(Some("another-session".to_owned()), None),
            Box::new(CannedTransport::default()),
        )
        .unwrap();
        let rendered = format!("{api:?}");
        assert!(!rendered.contains("another-session"), "{rendered}");
    }

    #[test]
    fn short_kid_bounds_public_fingerprint() {
        assert_eq!(short_kid("abcdefghij12rest"), "abcdefghij12");
        assert_eq!(short_kid("short"), "short");
    }
}
