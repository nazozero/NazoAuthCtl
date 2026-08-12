//! Target-side OpenID4VCI issuer orchestration.
//!
//! The official Suite remains the authority for the test flow and result.  This
//! module only performs the two pieces of target-side work that a waiting VCI
//! module cannot perform by itself: create a credential offer and drive the
//! materialized browser task.  All identities, configuration ids and
//! transaction codes are explicit inputs; this module never invents them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{BrowserTargetOrigin, validation::MAX_STEP_TIMEOUT};
use crate::credentials::BearerToken;
use crate::matrix::zeroize_json_value;
use crate::origin::Origin;
use crate::transport::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransport, Transport, TransportError,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_MODULE_ID_BYTES: usize = 256;
const MAX_COOKIES: usize = 64;
const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const MULTIPLE_CLIENTS_MODULE: &str = "oid4vci-1_0-issuer-happy-flow-multiple-clients";
const INITIAL_ANONYMOUS_MODULE: &str =
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds";
const REPEATED_AUTHORIZATION_MODULE: &str =
    "fapi2-security-profile-final-par-attempt-reuse-request_uri";
const USER_REJECT_MODULES: [&str; 2] = [
    "fapi2-security-profile-final-user-rejects-authentication",
    "fapi2-security-profile-id2-user-rejects-authentication",
];

/// A deliberately small, origin-local cookie jar.  The shared transport does
/// not own cookies (and must not be changed globally for a single VCI module),
/// so the hosted flow carries only the target response cookies between its
/// requests.  Attributes are never reflected into a request header.
#[derive(Default)]
struct CookieJar {
    cookies: Vec<StoredCookie>,
}

struct StoredCookie {
    name: String,
    value: Zeroizing<String>,
}

impl CookieJar {
    fn capture(&mut self, response: &HttpResponse) -> Result<(), OpenId4VciError> {
        for (header, value) in response
            .headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case("set-cookie"))
        {
            let _ = header;
            let pair = value
                .split(';')
                .next()
                .ok_or(OpenId4VciError::InvalidCookie)?;
            let (name, value) = pair.split_once('=').ok_or(OpenId4VciError::InvalidCookie)?;
            validate_cookie_name(name)?;
            validate_cookie_value(value)?;
            if value.is_empty() {
                self.cookies.retain(|cookie| cookie.name != name);
                continue;
            }
            if let Some(cookie) = self.cookies.iter_mut().find(|cookie| cookie.name == name) {
                cookie.value = Zeroizing::new(value.to_owned());
            } else {
                if self.cookies.len() >= MAX_COOKIES {
                    return Err(OpenId4VciError::InvalidCookie);
                }
                self.cookies.push(StoredCookie {
                    name: name.to_owned(),
                    value: Zeroizing::new(value.to_owned()),
                });
            }
        }
        Ok(())
    }

    fn header_value(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value.as_str()))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

struct HostedSession {
    cookies: CookieJar,
    csrf_token: Zeroizing<String>,
}

impl Default for HostedSession {
    fn default() -> Self {
        Self {
            cookies: CookieJar::default(),
            csrf_token: Zeroizing::new(String::new()),
        }
    }
}

fn validate_cookie_name(value: &str) -> Result<(), OpenId4VciError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
    {
        return Err(OpenId4VciError::InvalidCookie);
    }
    Ok(())
}

fn validate_cookie_value(value: &str) -> Result<(), OpenId4VciError> {
    if value.len() > MAX_FIELD_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b','))
    {
        return Err(OpenId4VciError::InvalidCookie);
    }
    Ok(())
}

/// Errors intentionally contain no URLs, request bodies or credential values.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum OpenId4VciError {
    #[error("OpenID4VCI input is invalid")]
    InvalidInput,
    #[error("OpenID4VCI target origin is invalid")]
    InvalidTargetOrigin,
    #[error("OpenID4VCI Suite callback is invalid")]
    InvalidSuiteCallback,
    #[error("OpenID4VCI runner data is unavailable")]
    MissingRunnerData,
    #[error("OpenID4VCI runner is waiting for browser data")]
    Pending,
    #[error("OpenID4VCI credential offer endpoint is unavailable")]
    MissingOfferEndpoint,
    #[error("OpenID4VCI credential configuration is unavailable")]
    MissingCredentialConfiguration,
    #[error("OpenID4VCI pre-authorized transaction code is unavailable")]
    MissingTransactionCode,
    #[error("OpenID4VCI transaction code does not match the materialized issuer configuration")]
    TransactionCodeMismatch,
    #[error("OpenID4VCI credential offer response is invalid")]
    InvalidOfferResponse,
    #[error("OpenID4VCI browser task configuration is unavailable")]
    MissingBrowserTasks,
    #[error("OpenID4VCI browser authorization URL is invalid or ambiguous")]
    InvalidAuthorizationUrl,
    #[error("OpenID4VCI hosted authorization response is invalid")]
    InvalidHostedResponse,
    #[error("OpenID4VCI hosted login requires MFA")]
    MfaRequired,
    #[error("OpenID4VCI hosted login did not return a CSRF token")]
    MissingCsrfToken,
    #[error("OpenID4VCI hosted response cookie is invalid")]
    InvalidCookie,
    #[error("OpenID4VCI HTTP transport failed")]
    Transport(#[source] TransportError),
    #[error("OpenID4VCI HTTP response status was not accepted")]
    HttpStatus(u16),
}

/// A waiting VCI module as observed from the Suite runner and the signed
/// Matrix materialization.  `runner` is the Suite's opaque JSON; only the
/// documented `exposed` and `browser` fields are read here.
#[derive(Clone)]
pub struct OpenId4VciModule {
    pub module_id: String,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
    pub plan_config: Value,
    pub runner: Value,
}

impl Drop for OpenId4VciModule {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.plan_config);
        zeroize_json_value(&mut self.runner);
    }
}

impl fmt::Debug for OpenId4VciModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VciModule")
            .field("module_id", &self.module_id)
            .field("test_name", &self.test_name)
            .field("variant", &self.variant)
            .field("plan_config", &"<redacted>")
            .field("runner", &"<redacted>")
            .finish()
    }
}

impl OpenId4VciModule {
    pub fn new(
        module_id: impl Into<String>,
        test_name: impl Into<String>,
        variant: BTreeMap<String, String>,
        plan_config: Value,
        runner: Value,
    ) -> Result<Self, OpenId4VciError> {
        let module = Self {
            module_id: module_id.into(),
            test_name: test_name.into(),
            variant,
            plan_config,
            runner,
        };
        if module.module_id.is_empty()
            || module.module_id.len() > MAX_MODULE_ID_BYTES
            || module.module_id.chars().any(|c| {
                c.is_control() || !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.')
            })
            || module.module_id == "."
            || module.module_id == ".."
            || module.test_name.is_empty()
            || module.test_name.len() > MAX_FIELD_BYTES
            || module.test_name.chars().any(char::is_control)
            || module.variant.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > MAX_FIELD_BYTES
                    || value.len() > MAX_FIELD_BYTES
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
            || !module.plan_config.is_object()
            || !module.runner.is_object()
        {
            return Err(OpenId4VciError::InvalidInput);
        }
        Ok(module)
    }
}

/// Narrow hook consumed by the conformance orchestrator.  It is deliberately
/// separate from `BrowserAutomation`: VCI hosted authorization follows the
/// Suite's bounded HTTP state machine and owns its short-lived cookie session.
pub trait OpenId4VciIssuerDriver: Send {
    fn drive(&mut self, module: &OpenId4VciModule) -> Result<(), OpenId4VciError>;
}

/// Rust-native client for the target's issuer-management offer endpoint and
/// the Suite's browser-visit bookkeeping endpoint.
pub struct OpenId4VciIssuerConfig {
    target_origin: BrowserTargetOrigin,
    suite_origin: Origin,
    subject_id: Uuid,
    expected_static_tx_code: Option<Zeroizing<String>>,
    hosted_email: Zeroizing<String>,
    hosted_password: Zeroizing<String>,
    timeout: Duration,
}

impl OpenId4VciIssuerConfig {
    pub fn new(
        target_origin: BrowserTargetOrigin,
        suite_origin: Origin,
        subject_id: Uuid,
        expected_static_tx_code: Option<Zeroizing<String>>,
        hosted_email: Zeroizing<String>,
        hosted_password: Zeroizing<String>,
        timeout: Duration,
    ) -> Result<Self, OpenId4VciError> {
        if subject_id.is_nil() || timeout.is_zero() || timeout > MAX_STEP_TIMEOUT {
            return Err(OpenId4VciError::InvalidInput);
        }
        if let Some(tx_code) = &expected_static_tx_code {
            validate_secret(tx_code)?;
        }
        validate_secret(&hosted_email)?;
        validate_hosted_password(&hosted_password)?;
        Ok(Self {
            target_origin,
            suite_origin,
            subject_id,
            expected_static_tx_code,
            hosted_email,
            hosted_password,
            timeout,
        })
    }
}

pub struct OpenId4VciIssuerClient {
    target_origin: BrowserTargetOrigin,
    suite_origin: Origin,
    issuer_management_token: Zeroizing<String>,
    suite_token: BearerToken,
    subject_id: Uuid,
    expected_static_tx_code: Option<Zeroizing<String>>,
    hosted_email: Zeroizing<String>,
    hosted_password: Zeroizing<String>,
    transport: Arc<dyn Transport>,
    max_response_bytes: usize,
    triggered: HashSet<String>,
    completed_browser_urls: HashMap<String, HashSet<String>>,
    anonymous_browser_urls: HashSet<String>,
}

impl fmt::Debug for OpenId4VciIssuerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VciIssuerClient")
            .field("target_origin", &self.target_origin)
            .field("suite_origin", &self.suite_origin)
            .field("issuer_management_token", &"<redacted>")
            .field("suite_token", &self.suite_token)
            .field("subject_id", &self.subject_id)
            .field(
                "expected_static_tx_code",
                &self.expected_static_tx_code.as_ref().map(|_| "<redacted>"),
            )
            .field("hosted_email", &"<redacted>")
            .field("hosted_password", &"<redacted>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl OpenId4VciIssuerClient {
    /// Construct with a dedicated HTTP transport.  `subject_id` is mandatory:
    /// the caller must pass the explicitly provisioned conformance subject.
    pub fn new(
        config: OpenId4VciIssuerConfig,
        issuer_management_token: Zeroizing<String>,
        suite_token: BearerToken,
    ) -> Result<Self, OpenId4VciError> {
        let transport = HttpTransport::new(config.timeout).map_err(OpenId4VciError::Transport)?;
        Self::with_transport(
            config,
            issuer_management_token,
            suite_token,
            Arc::new(transport),
        )
    }

    /// Construct with the transport already owned by the caller.  This keeps
    /// timeout/redirect and TLS policy in the existing conformance transport.
    pub fn with_transport(
        config: OpenId4VciIssuerConfig,
        issuer_management_token: Zeroizing<String>,
        suite_token: BearerToken,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, OpenId4VciError> {
        validate_secret(&issuer_management_token)?;
        if suite_token.is_empty() {
            return Err(OpenId4VciError::InvalidInput);
        }
        Ok(Self {
            target_origin: config.target_origin,
            suite_origin: config.suite_origin,
            issuer_management_token,
            suite_token,
            subject_id: config.subject_id,
            expected_static_tx_code: config.expected_static_tx_code,
            hosted_email: config.hosted_email,
            hosted_password: config.hosted_password,
            transport,
            max_response_bytes: MAX_RESPONSE_BYTES,
            triggered: HashSet::new(),
            completed_browser_urls: HashMap::new(),
            anonymous_browser_urls: HashSet::new(),
        })
    }

    fn send(
        &self,
        method: HttpMethod,
        url: Url,
        mut headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        cookies: Option<&CookieJar>,
    ) -> Result<HttpResponse, OpenId4VciError> {
        if let Some(cookies) = cookies
            && let Some(value) = cookies.header_value()
        {
            headers.push(("Cookie".to_owned(), value));
        }
        let response = self
            .transport
            .send(
                HttpRequest {
                    method,
                    url,
                    headers,
                    body,
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VciError::Transport)?;
        let header_bytes = response
            .headers
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .ok_or(())
            });
        if header_bytes.map_or(true, |total| total > self.max_response_bytes)
            || response.body.len() > self.max_response_bytes
        {
            return Err(OpenId4VciError::Transport(TransportError::Oversize));
        }
        Ok(response)
    }

    fn send_session(
        &self,
        session: &mut HostedSession,
        method: HttpMethod,
        url: Url,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, OpenId4VciError> {
        let response = self.send(method, url, headers, body, Some(&session.cookies))?;
        session.cookies.capture(&response)?;
        Ok(response)
    }

    fn target_url(&self, path: &str) -> Result<Url, OpenId4VciError> {
        if !path.starts_with('/') || path.contains("//") || path.contains("..") {
            return Err(OpenId4VciError::InvalidInput);
        }
        let mut url = self.target_origin.as_url().clone();
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        if !self.target_origin.allows(&url) {
            return Err(OpenId4VciError::InvalidTargetOrigin);
        }
        Ok(url)
    }

    fn validate_target_url(&self, url: &Url) -> Result<(), OpenId4VciError> {
        if !self.target_origin.allows(url)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(OpenId4VciError::InvalidAuthorizationUrl);
        }
        Ok(())
    }

    fn response_json(
        &self,
        response: &HttpResponse,
    ) -> Result<serde_json::Map<String, Value>, OpenId4VciError> {
        if !response
            .header("Content-Type")
            .is_some_and(|value| value.to_ascii_lowercase().contains("application/json"))
        {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|_| OpenId4VciError::InvalidHostedResponse)?;
        value
            .as_object()
            .cloned()
            .ok_or(OpenId4VciError::InvalidHostedResponse)
    }

    fn location(&self, request_url: &Url, response: &HttpResponse) -> Result<Url, OpenId4VciError> {
        if !matches!(response.status, 302 | 303) {
            return Err(OpenId4VciError::HttpStatus(response.status));
        }
        let value = response
            .header("Location")
            .ok_or(OpenId4VciError::InvalidHostedResponse)?;
        if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control)
        {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        request_url
            .join(value)
            .map_err(|_| OpenId4VciError::InvalidHostedResponse)
    }

    fn login_session(&self) -> Result<HostedSession, OpenId4VciError> {
        let mut session = HostedSession::default();
        let body = serde_json::to_vec(&serde_json::json!({
            "email": self.hosted_email.as_str(),
            "password": self.hosted_password.as_str(),
        }))
        .map_err(|_| OpenId4VciError::InvalidInput)?;
        let response = self.send_session(
            &mut session,
            HttpMethod::Post,
            self.target_url("/auth/login")?,
            vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
            Some(body),
        )?;
        if response.status != 200 {
            return Err(OpenId4VciError::HttpStatus(response.status));
        }
        let body = self.response_json(&response)?;
        if body.get("mfa_required").and_then(Value::as_bool) == Some(true) {
            return Err(OpenId4VciError::MfaRequired);
        }
        let csrf = body
            .get("csrf_token")
            .and_then(Value::as_str)
            .ok_or(OpenId4VciError::MissingCsrfToken)?;
        validate_secret(csrf)?;
        session.csrf_token = Zeroizing::new(csrf.to_owned());
        Ok(session)
    }

    fn target_endpoint(&self) -> Result<Url, OpenId4VciError> {
        let mut endpoint = self.target_origin.as_url().clone();
        endpoint.set_path("/openid4vci/offers");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        if !self.target_origin.allows(&endpoint) {
            return Err(OpenId4VciError::InvalidTargetOrigin);
        }
        Ok(endpoint)
    }

    fn create_offer(
        &self,
        configuration_id: &str,
        grant_type: &str,
        tx_code: Option<&str>,
    ) -> Result<Offer, OpenId4VciError> {
        validate_field(configuration_id)?;
        if grant_type != "authorization_code" && grant_type != PRE_AUTHORIZED_CODE_GRANT {
            return Err(OpenId4VciError::InvalidInput);
        }
        if grant_type == PRE_AUTHORIZED_CODE_GRANT && tx_code.is_none() {
            return Err(OpenId4VciError::MissingTransactionCode);
        }
        let mut body = serde_json::Map::new();
        body.insert(
            "subject_id".to_owned(),
            Value::String(self.subject_id.to_string()),
        );
        body.insert(
            "credential_configuration_ids".to_owned(),
            Value::Array(vec![Value::String(configuration_id.to_owned())]),
        );
        body.insert(
            "grant_types".to_owned(),
            Value::Array(vec![Value::String(grant_type.to_owned())]),
        );
        body.insert("expires_in".to_owned(), Value::from(300));
        if let Some(tx_code) = tx_code {
            body.insert("tx_code".to_owned(), Value::String(tx_code.to_owned()));
        }
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Post,
                    url: self.target_endpoint()?,
                    headers: vec![
                        ("Accept".to_owned(), "application/json".to_owned()),
                        ("Content-Type".to_owned(), "application/json".to_owned()),
                        (
                            "Authorization".to_owned(),
                            format!("Bearer {}", self.issuer_management_token.as_str()),
                        ),
                    ],
                    body: Some(
                        serde_json::to_vec(&Value::Object(body))
                            .map_err(|_| OpenId4VciError::InvalidInput)?,
                    ),
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VciError::Transport)?;
        if response.status != 200 && response.status != 201 {
            return Err(OpenId4VciError::HttpStatus(response.status));
        }
        parse_offer(&response.body)
    }

    fn deliver_offer(
        &self,
        endpoint: &Url,
        offer: &Offer,
        delivery: OfferDelivery,
    ) -> Result<(), OpenId4VciError> {
        let mut callback = endpoint.clone();
        match delivery {
            OfferDelivery::Value => {
                let value = offer
                    .credential_offer
                    .as_ref()
                    .ok_or(OpenId4VciError::InvalidOfferResponse)?;
                let serialized = serde_json::to_string(value)
                    .map_err(|_| OpenId4VciError::InvalidOfferResponse)?;
                if serialized.len() > MAX_FIELD_BYTES {
                    return Err(OpenId4VciError::InvalidOfferResponse);
                }
                callback
                    .query_pairs_mut()
                    .append_pair("credential_offer", &serialized);
            }
            OfferDelivery::Uri => {
                let value = offer
                    .credential_offer_uri
                    .as_deref()
                    .ok_or(OpenId4VciError::InvalidOfferResponse)?;
                validate_field(value)?;
                let offer_uri =
                    Url::parse(value).map_err(|_| OpenId4VciError::InvalidOfferResponse)?;
                if !self.target_origin.allows(&offer_uri)
                    || !offer_uri.username().is_empty()
                    || offer_uri.password().is_some()
                    || offer_uri.fragment().is_some()
                {
                    return Err(OpenId4VciError::InvalidOfferResponse);
                }
                callback
                    .query_pairs_mut()
                    .append_pair("credential_offer_uri", value);
            }
        }
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Get,
                    url: callback,
                    headers: vec![(
                        "Accept".to_owned(),
                        "text/html,application/xhtml+xml".to_owned(),
                    )],
                    body: None,
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VciError::Transport)?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(OpenId4VciError::HttpStatus(response.status))
        }
    }

    fn suite_visit(&self, module_id: &str, authorization_url: &Url) -> Result<(), OpenId4VciError> {
        let path = format!("/api/runner/browser/{module_id}/visit");
        if path.len() > MAX_FIELD_BYTES {
            return Err(OpenId4VciError::InvalidInput);
        }
        let mut endpoint = self
            .suite_origin
            .url(&path)
            .map_err(|_| OpenId4VciError::InvalidInput)?;
        endpoint
            .query_pairs_mut()
            .append_pair("url", authorization_url.as_str());
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
                            format!("Bearer {}", self.suite_token.as_str()),
                        ),
                    ],
                    body: None,
                },
                self.max_response_bytes,
            )
            .map_err(OpenId4VciError::Transport)?;
        if response.status == 204 {
            Ok(())
        } else {
            Err(OpenId4VciError::HttpStatus(response.status))
        }
    }

    fn drive_offer(&mut self, module: &OpenId4VciModule) -> Result<(), OpenId4VciError> {
        if self.triggered.contains(&module.module_id) {
            return Ok(());
        }
        let exposed = module
            .runner
            .get("exposed")
            .and_then(Value::as_object)
            .ok_or(OpenId4VciError::Pending)?;
        let endpoint = exposed
            .get("credential_offer_endpoint")
            .and_then(Value::as_str)
            .ok_or(OpenId4VciError::Pending)?;
        let endpoint = self.validate_suite_callback(endpoint)?;
        let vci = module
            .plan_config
            .get("vci")
            .and_then(Value::as_object)
            .ok_or(OpenId4VciError::MissingCredentialConfiguration)?;
        let configuration_id = vci
            .get("credential_configuration_id")
            .and_then(Value::as_str)
            .ok_or(OpenId4VciError::MissingCredentialConfiguration)?;
        let grant = module
            .variant
            .get("vci_grant_type")
            .map(String::as_str)
            .ok_or(OpenId4VciError::InvalidInput)?;
        let (grant_type, tx_code) = match grant {
            "authorization_code" => {
                if vci.get("static_tx_code").is_some() {
                    return Err(OpenId4VciError::TransactionCodeMismatch);
                }
                ("authorization_code", None)
            }
            "pre_authorization_code" => {
                let tx_code = vci
                    .get("static_tx_code")
                    .and_then(Value::as_str)
                    .ok_or(OpenId4VciError::MissingTransactionCode)?;
                validate_field(tx_code)?;
                if self
                    .expected_static_tx_code
                    .as_ref()
                    .is_some_and(|expected| expected.as_str() != tx_code)
                {
                    return Err(OpenId4VciError::TransactionCodeMismatch);
                }
                (PRE_AUTHORIZED_CODE_GRANT, Some(tx_code))
            }
            _ => return Err(OpenId4VciError::InvalidInput),
        };
        let offer_count =
            if grant == "pre_authorization_code" && module.test_name == MULTIPLE_CLIENTS_MODULE {
                2
            } else {
                1
            };
        let delivery = offer_delivery(&module.plan_config)?;
        for _ in 0..offer_count {
            let offer = self.create_offer(configuration_id, grant_type, tx_code)?;
            self.deliver_offer(&endpoint, &offer, delivery)?;
        }
        self.triggered.insert(module.module_id.clone());
        Ok(())
    }

    fn drive_browser(&mut self, module: &OpenId4VciModule) -> Result<(), OpenId4VciError> {
        let browser = module
            .runner
            .get("browser")
            .and_then(Value::as_object)
            .ok_or(OpenId4VciError::Pending)?;
        let urls = browser
            .get("urls")
            .and_then(Value::as_array)
            .ok_or(OpenId4VciError::Pending)?;
        let mut candidates = Vec::new();
        let mut invalid_authorization_url = false;
        for value in urls {
            let value = value
                .as_str()
                .or_else(|| value.get("url").and_then(Value::as_str));
            let Some(value) = value else { continue };
            if value.len() > MAX_FIELD_BYTES * 8 {
                invalid_authorization_url = true;
                continue;
            }
            let Ok(url) = Url::parse(value) else { continue };
            if url.path() == "/authorize"
                && (!self.target_origin.allows(&url)
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some())
            {
                invalid_authorization_url = true;
                continue;
            }
            if url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path() == "/authorize"
                && url.query().is_some_and(|query| !query.is_empty())
                && self.target_origin.allows(&url)
            {
                candidates.push(url);
            }
        }
        candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        candidates.dedup_by(|left, right| left == right);
        let completed = self
            .completed_browser_urls
            .get(&module.module_id)
            .cloned()
            .unwrap_or_default();
        let pending = if module.test_name == REPEATED_AUTHORIZATION_MODULE {
            candidates.clone()
        } else {
            candidates
                .iter()
                .filter(|url| !completed.contains(url.as_str()))
                .cloned()
                .collect::<Vec<_>>()
        };
        if pending.is_empty() {
            if invalid_authorization_url {
                return Err(OpenId4VciError::InvalidAuthorizationUrl);
            }
            return Err(OpenId4VciError::Pending);
        }
        if pending.len() != 1 {
            return Err(OpenId4VciError::InvalidAuthorizationUrl);
        }
        let authorization_url = pending.into_iter().next().expect("one pending URL");
        let visited = browser_visited(browser, authorization_url.as_str());
        let anonymous_key = format!("{}\0{}", module.module_id, authorization_url);
        if module.test_name == INITIAL_ANONYMOUS_MODULE
            && !visited
            && !self.anonymous_browser_urls.contains(&anonymous_key)
        {
            let response = self.send(
                HttpMethod::Get,
                authorization_url.clone(),
                vec![(
                    "Accept".to_owned(),
                    "text/html,application/xhtml+xml".to_owned(),
                )],
                None,
                None,
            )?;
            let location = self.location(&authorization_url, &response)?;
            self.initial_anonymous_location(&location)?;
            self.suite_visit(&module.module_id, &authorization_url)?;
            self.anonymous_browser_urls.insert(anonymous_key);
            return Ok(());
        }

        self.suite_visit(&module.module_id, &authorization_url)?;
        let mut session = self.login_session()?;
        let response = self.send_session(
            &mut session,
            HttpMethod::Get,
            authorization_url.clone(),
            vec![(
                "Accept".to_owned(),
                "text/html,application/xhtml+xml".to_owned(),
            )],
            None,
        )?;
        let location = self.location(&authorization_url, &response)?;
        let callback = if self.suite_origin.same_origin_url(&location) {
            self.validate_suite_callback_url(&location)?;
            location
        } else {
            let request_id = self.consent_request_id(&location)?;
            let mut consent_url = self.target_url("/authorize/consent")?;
            consent_url
                .query_pairs_mut()
                .append_pair("request_id", &request_id);
            let csrf_header = session.csrf_token.as_str().to_owned();
            let consent = self.send_session(
                &mut session,
                HttpMethod::Get,
                consent_url,
                vec![
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("X-CSRF-Token".to_owned(), csrf_header),
                ],
                None,
            )?;
            if consent.status != 200 {
                return Err(OpenId4VciError::HttpStatus(consent.status));
            }
            let consent_json = self.response_json(&consent)?;
            let csrf = consent_json
                .get("csrf_token")
                .and_then(Value::as_str)
                .ok_or(OpenId4VciError::MissingCsrfToken)?;
            validate_secret(csrf)?;
            session.csrf_token = Zeroizing::new(csrf.to_owned());
            let decision = if USER_REJECT_MODULES.contains(&module.test_name.as_str()) {
                "deny"
            } else {
                "approve"
            };
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("request_id", &request_id)
                .append_pair("decision", decision)
                .append_pair("csrf_token", session.csrf_token.as_str());
            let decision_url = self.target_url("/authorize/decision")?;
            let csrf_header = session.csrf_token.as_str().to_owned();
            let decision_response = self.send_session(
                &mut session,
                HttpMethod::Post,
                decision_url.clone(),
                vec![
                    (
                        "Accept".to_owned(),
                        "text/html,application/xhtml+xml".to_owned(),
                    ),
                    (
                        "Content-Type".to_owned(),
                        "application/x-www-form-urlencoded".to_owned(),
                    ),
                    (
                        "Origin".to_owned(),
                        self.target_origin.as_url().origin().ascii_serialization(),
                    ),
                    ("X-CSRF-Token".to_owned(), csrf_header),
                ],
                Some(form.finish().into_bytes()),
            )?;
            let callback = self.location(&decision_url, &decision_response)?;
            self.validate_suite_callback_url(&callback)?;
            callback
        };
        self.complete_suite_callback(&callback)?;
        self.completed_browser_urls
            .entry(module.module_id.clone())
            .or_default()
            .insert(authorization_url.to_string());
        Ok(())
    }

    fn initial_anonymous_location(&self, location: &Url) -> Result<(), OpenId4VciError> {
        self.validate_target_url(location)?;
        if location.path() != "/ui/auth"
            || location.fragment().is_some()
            || location.query_pairs().count() != 1
            || location
                .query_pairs()
                .next()
                .is_none_or(|(key, value)| key != "next" || value.is_empty())
        {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        Ok(())
    }

    fn consent_request_id(&self, location: &Url) -> Result<String, OpenId4VciError> {
        self.validate_target_url(location)?;
        if location.path() != "/ui/consent" || location.fragment().is_some() {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        let pairs = location.query_pairs().collect::<Vec<_>>();
        if pairs.len() != 1 || pairs[0].0 != "request_id" || pairs[0].1.is_empty() {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        let request_id = pairs[0].1.to_string();
        validate_field(&request_id)?;
        Ok(request_id)
    }

    fn validate_suite_callback_url(&self, url: &Url) -> Result<(), OpenId4VciError> {
        if !self.suite_origin.same_origin_url(url)
            || !url.path().starts_with("/test/")
            || url.path().contains("..")
            || url.path().contains("//")
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(OpenId4VciError::InvalidSuiteCallback);
        }
        Ok(())
    }

    fn complete_suite_callback(&self, callback: &Url) -> Result<(), OpenId4VciError> {
        self.validate_suite_callback_url(callback)?;
        let response = self.send(
            HttpMethod::Get,
            callback.clone(),
            vec![(
                "Accept".to_owned(),
                "text/html,application/xhtml+xml".to_owned(),
            )],
            None,
            None,
        )?;
        if response.status != 200
            || !response
                .header("Content-Type")
                .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
        {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        let pattern = Regex::new(r#"xhr\.open\('POST',\s*("(?:\\.|[^"\\])*")\s*,\s*true\);"#)
            .map_err(|_| OpenId4VciError::InvalidHostedResponse)?;
        let mut matches = pattern.captures_iter(
            std::str::from_utf8(&response.body)
                .map_err(|_| OpenId4VciError::InvalidHostedResponse)?,
        );
        let capture = matches
            .next()
            .and_then(|capture| capture.get(1))
            .ok_or(OpenId4VciError::InvalidHostedResponse)?;
        if matches.next().is_some() {
            return Err(OpenId4VciError::InvalidHostedResponse);
        }
        let submit_url = serde_json::from_str::<String>(capture.as_str())
            .map_err(|_| OpenId4VciError::InvalidHostedResponse)?;
        let submit_url =
            Url::parse(&submit_url).map_err(|_| OpenId4VciError::InvalidHostedResponse)?;
        if !self.suite_origin.same_origin_url(&submit_url)
            || !submit_url.path().starts_with("/test/")
            || !submit_url.path().contains("/implicit/")
            || submit_url.query().is_some()
            || submit_url.fragment().is_some()
            || !submit_url.username().is_empty()
            || submit_url.password().is_some()
        {
            return Err(OpenId4VciError::InvalidSuiteCallback);
        }
        let response = self.send(
            HttpMethod::Post,
            submit_url,
            vec![
                ("Accept".to_owned(), "*/*".to_owned()),
                ("Content-Type".to_owned(), "text/plain".to_owned()),
                ("Origin".to_owned(), self.suite_origin.as_str().to_owned()),
            ],
            Some(Vec::new()),
            None,
        )?;
        if response.status == 204 {
            Ok(())
        } else {
            Err(OpenId4VciError::HttpStatus(response.status))
        }
    }

    fn validate_suite_callback(&self, value: &str) -> Result<Url, OpenId4VciError> {
        let url = Url::parse(value).map_err(|_| OpenId4VciError::InvalidSuiteCallback)?;
        self.validate_suite_callback_url(&url)?;
        Ok(url)
    }
}

impl OpenId4VciIssuerDriver for OpenId4VciIssuerClient {
    fn drive(&mut self, module: &OpenId4VciModule) -> Result<(), OpenId4VciError> {
        let flow = module
            .variant
            .get("vci_authorization_code_flow_variant")
            .map(String::as_str)
            .ok_or(OpenId4VciError::InvalidInput)?;
        match flow {
            "issuer_initiated" => {
                self.drive_offer(module)?;
                if module
                    .variant
                    .get("vci_grant_type")
                    .is_some_and(|grant| grant == "authorization_code")
                {
                    self.drive_browser(module)?;
                }
            }
            "wallet_initiated" => self.drive_browser(module)?,
            _ => return Err(OpenId4VciError::InvalidInput),
        }
        Ok(())
    }
}

struct Offer {
    credential_offer: Option<Value>,
    credential_offer_uri: Option<String>,
}

impl Drop for Offer {
    fn drop(&mut self) {
        if let Some(value) = &mut self.credential_offer {
            zeroize_json_value(value);
        }
    }
}

#[derive(Clone, Copy)]
enum OfferDelivery {
    Value,
    Uri,
}

fn parse_offer(body: &[u8]) -> Result<Offer, OpenId4VciError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| OpenId4VciError::InvalidOfferResponse)?;
    let object = value
        .as_object()
        .ok_or(OpenId4VciError::InvalidOfferResponse)?;
    let credential_offer = object.get("credential_offer").cloned();
    if credential_offer
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(OpenId4VciError::InvalidOfferResponse);
    }
    let credential_offer_uri = object
        .get("credential_offer_uri")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if credential_offer.is_none() && credential_offer_uri.is_none() {
        return Err(OpenId4VciError::InvalidOfferResponse);
    }
    Ok(Offer {
        credential_offer,
        credential_offer_uri,
    })
}

fn offer_delivery(config: &Value) -> Result<OfferDelivery, OpenId4VciError> {
    let value = config
        .get("vci")
        .and_then(Value::as_object)
        .and_then(|object| object.get("offer_delivery"))
        .and_then(Value::as_str)
        .unwrap_or("uri");
    match value {
        "uri" => Ok(OfferDelivery::Uri),
        "value" => Ok(OfferDelivery::Value),
        _ => Err(OpenId4VciError::InvalidInput),
    }
}

fn validate_secret(value: &str) -> Result<(), OpenId4VciError> {
    if value.trim().is_empty()
        || value.len() > MAX_FIELD_BYTES * 16
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(OpenId4VciError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_hosted_password(value: &str) -> Result<(), OpenId4VciError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES * 16 || value.chars().any(char::is_control)
    {
        Err(OpenId4VciError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_field(value: &str) -> Result<(), OpenId4VciError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        Err(OpenId4VciError::InvalidInput)
    } else {
        Ok(())
    }
}

fn browser_visited(browser: &serde_json::Map<String, Value>, authorization_url: &str) -> bool {
    browser
        .get("visited")
        .and_then(Value::as_array)
        .is_some_and(|visited| {
            visited.iter().any(|value| {
                value.as_str() == Some(authorization_url)
                    || value
                        .get("url")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value == authorization_url)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserTargetOrigin;
    use crate::transport::{HttpResponse, Transport};
    use std::sync::Mutex;

    struct FixtureTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<Vec<HttpResponse>>,
    }

    impl Transport for FixtureTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            self.requests.lock().expect("requests").push(request);
            self.responses
                .lock()
                .expect("responses")
                .pop()
                .ok_or(TransportError::Network)
        }
    }

    fn module(flow: &str, grant: &str) -> OpenId4VciModule {
        module_named("test", flow, grant)
    }

    fn module_named(name: &str, flow: &str, grant: &str) -> OpenId4VciModule {
        OpenId4VciModule::new(
            "module-1",
            name,
            BTreeMap::from([
                (
                    "vci_authorization_code_flow_variant".to_owned(),
                    flow.to_owned(),
                ),
                ("vci_grant_type".to_owned(), grant.to_owned()),
            ]),
            serde_json::json!({
                "vci": {
                    "credential_configuration_id": "UniversityDegree_JWT",
                    "static_tx_code": "012345"
                },
                "browser": [{"match":"/authorize", "tasks": []}]
            }),
            serde_json::json!({
                "exposed": {"credential_offer_endpoint":"https://suite.example/test/a/offer"},
                "browser": {"urls":["https://target.example/authorize?request=1"], "visited":[]}
            }),
        )
        .expect("module")
    }

    fn issuer_config(tx_code: Option<&str>) -> OpenId4VciIssuerConfig {
        OpenId4VciIssuerConfig::new(
            BrowserTargetOrigin::parse("https://target.example").expect("target"),
            Origin::parse("https://suite.example").expect("suite"),
            Uuid::from_u128(1),
            tx_code.map(|value| Zeroizing::new(value.to_owned())),
            Zeroizing::new("applicant@example.test".to_owned()),
            Zeroizing::new("applicant-password".to_owned()),
            Duration::from_secs(30),
        )
        .expect("issuer config")
    }

    fn hosted_responses() -> Vec<HttpResponse> {
        vec![
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
            HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "text/html".to_owned())],
                body: br#"<script>xhr.open('POST', "https://suite.example/test/flow/implicit/submit", true);</script>"#.to_vec(),
            },
            HttpResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://suite.example/test/flow/callback?state=ok".to_owned(),
                )],
                body: vec![],
            },
            HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: br#"{"csrf_token":"consent-csrf"}"#.to_vec(),
            },
            HttpResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://target.example/ui/consent?request_id=req-1".to_owned(),
                )],
                body: vec![],
            },
            HttpResponse {
                status: 200,
                headers: vec![
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                    ("Set-Cookie".to_owned(), "session=s1; Path=/; HttpOnly".to_owned()),
                ],
                body: br#"{"csrf_token":"login-csrf"}"#.to_vec(),
            },
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
        ]
    }

    fn client_with_responses(
        responses: Vec<HttpResponse>,
    ) -> (Arc<FixtureTransport>, OpenId4VciIssuerClient) {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses),
        });
        let client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        (transport, client)
    }

    #[test]
    fn offer_body_contains_explicit_subject_and_tx_code() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![
                HttpResponse {
                    status: 204,
                    headers: vec![],
                    body: vec![],
                },
                HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: br#"{"credential_offer_uri":"https://target.example/offer/1"}"#.to_vec(),
                },
            ]),
        });
        let client = OpenId4VciIssuerClient::with_transport(
            issuer_config(Some("012345")),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        let mut client = client;
        client
            .drive(&module("issuer_initiated", "pre_authorization_code"))
            .expect("drive");
        let requests = transport.requests.lock().expect("requests");
        let body = requests[0].body().expect("body");
        let body: Value = serde_json::from_slice(body).expect("json");
        assert_eq!(body["subject_id"], Uuid::from_u128(1).to_string());
        assert_eq!(body["tx_code"], "012345");
        assert_eq!(
            requests[0].header("Authorization"),
            Some("Bearer issuer-secret")
        );
        assert!(!format!("{client:?}").contains("issuer-secret"));
        assert!(!format!("{client:?}").contains("suite-secret"));
    }

    #[test]
    fn cross_origin_offer_callback_is_rejected_before_transport() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        });
        let client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        let module = OpenId4VciModule::new(
            "module-1",
            "test",
            BTreeMap::from([("vci_authorization_code_flow_variant".to_owned(), "issuer_initiated".to_owned())]),
            serde_json::json!({"vci":{"credential_configuration_id":"id"}}),
            serde_json::json!({"exposed":{"credential_offer_endpoint":"https://evil.example/test/a"}}),
        )
        .expect("module");
        let mut client = client;
        assert_eq!(
            client.drive(&module),
            Err(OpenId4VciError::InvalidSuiteCallback)
        );
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn tx_code_mismatch_is_rejected_without_network() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        });
        let mut client = OpenId4VciIssuerClient::with_transport(
            issuer_config(Some("other")),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        assert_eq!(
            client.drive(&module("issuer_initiated", "pre_authorization_code")),
            Err(OpenId4VciError::TransactionCodeMismatch)
        );
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn wallet_initiated_flow_does_not_create_an_offer() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(hosted_responses()),
        });
        let mut client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        client
            .drive(&module("wallet_initiated", "authorization_code"))
            .expect("drive");
        assert_eq!(transport.requests.lock().expect("requests").len(), 7);
    }

    #[test]
    fn hosted_user_reject_posts_deny_and_completes_callback() {
        let (transport, mut client) = client_with_responses(hosted_responses());
        client
            .drive(&module_named(
                "fapi2-security-profile-final-user-rejects-authentication",
                "wallet_initiated",
                "authorization_code",
            ))
            .expect("drive");
        let requests = transport.requests.lock().expect("requests");
        let decision = requests
            .iter()
            .find(|request| request.url().path() == "/authorize/decision")
            .expect("decision request");
        let body = std::str::from_utf8(decision.body().expect("decision body")).expect("form");
        assert!(body.contains("decision=deny"));
        assert!(body.contains("csrf_token=consent-csrf"));
        assert_eq!(decision.header("Origin"), Some("https://target.example"));
        assert_eq!(decision.header("X-CSRF-Token"), Some("consent-csrf"));
        assert_eq!(decision.header("Cookie"), Some("session=s1"));
    }

    #[test]
    fn initial_anonymous_visit_has_no_cookie_and_waits_for_next_round() {
        let responses = vec![
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
            HttpResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://target.example/ui/auth?next=https%3A%2F%2Ftarget.example%2Fauthorize%3Frequest%3D1".to_owned(),
                )],
                body: vec![],
            },
        ];
        let (transport, mut client) = client_with_responses(responses);
        client
            .drive(&module_named(
                INITIAL_ANONYMOUS_MODULE,
                "wallet_initiated",
                "authorization_code",
            ))
            .expect("anonymous visit");
        let requests = transport.requests.lock().expect("requests");
        let authorize = requests
            .iter()
            .find(|request| request.url().path() == "/authorize")
            .expect("authorize request");
        assert_eq!(authorize.header("Cookie"), None);
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn hosted_cross_origin_redirect_is_rejected_without_follow_up() {
        let responses = vec![
            HttpResponse {
                status: 302,
                headers: vec![(
                    "Location".to_owned(),
                    "https://evil.example/ui/consent?request_id=req-1".to_owned(),
                )],
                body: vec![],
            },
            HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: br#"{"csrf_token":"login-csrf"}"#.to_vec(),
            },
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
        ];
        let (transport, mut client) = client_with_responses(responses);
        let result = client.drive(&module("wallet_initiated", "authorization_code"));
        assert_eq!(result, Err(OpenId4VciError::InvalidAuthorizationUrl));
        assert_eq!(transport.requests.lock().expect("requests").len(), 3);
    }

    #[test]
    fn hosted_login_mfa_is_rejected_without_interactive_fallback() {
        let responses = vec![
            HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: br#"{"mfa_required":true,"csrf_token":"ignored"}"#.to_vec(),
            },
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
        ];
        let (transport, mut client) = client_with_responses(responses);
        assert_eq!(
            client.drive(&module("wallet_initiated", "authorization_code")),
            Err(OpenId4VciError::MfaRequired)
        );
        assert_eq!(transport.requests.lock().expect("requests").len(), 2);
    }

    #[test]
    fn hosted_login_requires_csrf_token() {
        let responses = vec![
            HttpResponse {
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: br#"{}"#.to_vec(),
            },
            HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            },
        ];
        let (_, mut client) = client_with_responses(responses);
        assert_eq!(
            client.drive(&module("wallet_initiated", "authorization_code")),
            Err(OpenId4VciError::MissingCsrfToken)
        );
    }

    #[test]
    fn hosted_callback_response_is_bounded() {
        let mut responses = hosted_responses();
        responses[1].body = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let (_, mut client) = client_with_responses(responses);
        assert_eq!(
            client.drive(&module("wallet_initiated", "authorization_code")),
            Err(OpenId4VciError::Transport(TransportError::Oversize))
        );
    }

    #[test]
    fn empty_runner_browser_urls_are_pending_not_complete() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        });
        let mut client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            transport.clone(),
        )
        .expect("client");
        let mut pending = module("wallet_initiated", "authorization_code");
        pending.runner["browser"]["urls"] = serde_json::json!([]);
        assert_eq!(client.drive(&pending), Err(OpenId4VciError::Pending));
        assert!(transport.requests.lock().expect("requests").is_empty());
    }
}
