//! Target-side OpenID4VCI issuer orchestration.
//!
//! The official Suite remains the authority for the test flow and result.  This
//! module only performs the two pieces of target-side work that a waiting VCI
//! module cannot perform by itself: create a credential offer and drive the
//! materialized browser task.  All identities, configuration ids and
//! transaction codes are explicit inputs; this module never invents them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
use super::BrowserEntry;
use super::{
    BrowserAutomation, BrowserError, BrowserTargetOrigin, parse_browser_entries_owned,
    validation::MAX_STEP_TIMEOUT,
};
use crate::credentials::BearerToken;
use crate::origin::Origin;
use crate::transport::{HttpMethod, HttpRequest, HttpTransport, Transport, TransportError};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_MODULE_ID_BYTES: usize = 256;
const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const MULTIPLE_CLIENTS_MODULE: &str = "oid4vci-1_0-issuer-happy-flow-multiple-clients";
const INITIAL_ANONYMOUS_MODULE: &str =
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds";
const REPEATED_AUTHORIZATION_MODULE: &str =
    "fapi2-security-profile-final-par-attempt-reuse-request_uri";

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
    #[error("OpenID4VCI browser automation failed")]
    Browser(#[source] BrowserError),
    #[error("OpenID4VCI HTTP transport failed")]
    Transport(#[source] TransportError),
    #[error("OpenID4VCI HTTP response status was not accepted")]
    HttpStatus(u16),
    #[error("OpenID4VCI browser lock failed")]
    BrowserLock,
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
/// separate from `BrowserAutomation`: offer creation is HTTP, while browser
/// protocol and cookie/session lifecycle remain owned by the browser driver.
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
    timeout: Duration,
}

impl OpenId4VciIssuerConfig {
    pub fn new(
        target_origin: BrowserTargetOrigin,
        suite_origin: Origin,
        subject_id: Uuid,
        expected_static_tx_code: Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Result<Self, OpenId4VciError> {
        if subject_id.is_nil() || timeout.is_zero() || timeout > MAX_STEP_TIMEOUT {
            return Err(OpenId4VciError::InvalidInput);
        }
        if let Some(tx_code) = &expected_static_tx_code {
            validate_secret(tx_code)?;
        }
        Ok(Self {
            target_origin,
            suite_origin,
            subject_id,
            expected_static_tx_code,
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
    browser: Arc<Mutex<dyn BrowserAutomation>>,
    transport: Arc<dyn Transport>,
    max_response_bytes: usize,
    triggered: HashSet<String>,
    completed_browser_urls: HashMap<String, HashSet<String>>,
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
        browser: Arc<Mutex<dyn BrowserAutomation>>,
    ) -> Result<Self, OpenId4VciError> {
        let transport = HttpTransport::new(config.timeout).map_err(OpenId4VciError::Transport)?;
        Self::with_transport(
            config,
            issuer_management_token,
            suite_token,
            browser,
            Arc::new(transport),
        )
    }

    /// Construct with the transport already owned by the caller.  This keeps
    /// timeout/redirect and TLS policy in the existing conformance transport.
    pub fn with_transport(
        config: OpenId4VciIssuerConfig,
        issuer_management_token: Zeroizing<String>,
        suite_token: BearerToken,
        browser: Arc<Mutex<dyn BrowserAutomation>>,
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
            browser,
            transport,
            max_response_bytes: MAX_RESPONSE_BYTES,
            triggered: HashSet::new(),
            completed_browser_urls: HashMap::new(),
        })
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
            .ok_or(OpenId4VciError::MissingRunnerData)?;
        let endpoint = exposed
            .get("credential_offer_endpoint")
            .and_then(Value::as_str)
            .ok_or(OpenId4VciError::MissingOfferEndpoint)?;
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
            .ok_or(OpenId4VciError::MissingRunnerData)?;
        let urls = browser
            .get("urls")
            .and_then(Value::as_array)
            .ok_or(OpenId4VciError::MissingRunnerData)?;
        let mut candidates = Vec::new();
        for value in urls {
            let Some(value) = value.as_str() else {
                continue;
            };
            let Ok(url) = Url::parse(value) else { continue };
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
            return Ok(());
        }
        if pending.len() != 1 {
            return Err(OpenId4VciError::InvalidAuthorizationUrl);
        }
        let authorization_url = pending.into_iter().next().expect("one pending URL");
        let initial_anonymous = module.test_name == INITIAL_ANONYMOUS_MODULE
            && browser
                .get("visited")
                .and_then(Value::as_array)
                .is_none_or(|visited| {
                    !visited
                        .iter()
                        .any(|value| value.as_str() == Some(authorization_url.as_str()))
                });
        if initial_anonymous {
            let mut browser = self
                .browser
                .lock()
                .map_err(|_| OpenId4VciError::BrowserLock)?;
            browser
                .navigate(&authorization_url)
                .map_err(OpenId4VciError::Browser)?;
            drop(browser);
            self.suite_visit(&module.module_id, &authorization_url)?;
        } else {
            self.suite_visit(&module.module_id, &authorization_url)?;
            let browser_config = module
                .plan_config
                .get("browser")
                .cloned()
                .ok_or(OpenId4VciError::MissingBrowserTasks)?;
            let entries =
                parse_browser_entries_owned(browser_config).map_err(OpenId4VciError::Browser)?;
            if entries.is_empty() {
                return Err(OpenId4VciError::MissingBrowserTasks);
            }
            let mut browser = self
                .browser
                .lock()
                .map_err(|_| OpenId4VciError::BrowserLock)?;
            browser
                .execute(&authorization_url, &entries)
                .map_err(OpenId4VciError::Browser)?;
        }
        self.completed_browser_urls
            .entry(module.module_id.clone())
            .or_default()
            .insert(authorization_url.to_string());
        Ok(())
    }

    fn validate_suite_callback(&self, value: &str) -> Result<Url, OpenId4VciError> {
        let url = Url::parse(value).map_err(|_| OpenId4VciError::InvalidSuiteCallback)?;
        if !self.suite_origin.same_origin_url(&url)
            || !url.path().starts_with("/test/")
            || url.path().contains("..")
            || url.path().contains("//")
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(OpenId4VciError::InvalidSuiteCallback);
        }
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

fn validate_field(value: &str) -> Result<(), OpenId4VciError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        Err(OpenId4VciError::InvalidInput)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::{BrowserRunReport, BrowserTargetOrigin};
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

    struct FixtureBrowser {
        navigated: Vec<Url>,
        executed: usize,
    }

    impl BrowserAutomation for FixtureBrowser {
        fn execute(
            &mut self,
            authorization_url: &Url,
            _entries: &[BrowserEntry],
        ) -> Result<BrowserRunReport, BrowserError> {
            self.navigated.push(authorization_url.clone());
            self.executed += 1;
            Ok(BrowserRunReport {
                steps: 1,
                tasks: 1,
                entry_index: 0,
                final_origin: authorization_url.origin().ascii_serialization(),
            })
        }

        fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
            self.navigated.push(url.clone());
            Ok(())
        }
    }

    fn module(flow: &str, grant: &str) -> OpenId4VciModule {
        OpenId4VciModule::new(
            "module-1",
            "test",
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
            Duration::from_secs(30),
        )
        .expect("issuer config")
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
        let browser = Arc::new(Mutex::new(FixtureBrowser {
            navigated: Vec::new(),
            executed: 0,
        }));
        let client = OpenId4VciIssuerClient::with_transport(
            issuer_config(Some("012345")),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            browser,
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
        let browser = Arc::new(Mutex::new(FixtureBrowser {
            navigated: Vec::new(),
            executed: 0,
        }));
        let client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            browser,
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
        let browser = Arc::new(Mutex::new(FixtureBrowser {
            navigated: Vec::new(),
            executed: 0,
        }));
        let mut client = OpenId4VciIssuerClient::with_transport(
            issuer_config(Some("other")),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            browser,
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
            responses: Mutex::new(vec![HttpResponse {
                status: 204,
                headers: vec![],
                body: vec![],
            }]),
        });
        let browser = Arc::new(Mutex::new(FixtureBrowser {
            navigated: Vec::new(),
            executed: 0,
        }));
        let mut client = OpenId4VciIssuerClient::with_transport(
            issuer_config(None),
            Zeroizing::new("issuer-secret".to_owned()),
            BearerToken::new("suite-secret").expect("token"),
            browser.clone(),
            transport.clone(),
        )
        .expect("client");
        client
            .drive(&module("wallet_initiated", "authorization_code"))
            .expect("drive");
        assert_eq!(transport.requests.lock().expect("requests").len(), 1);
        assert_eq!(browser.lock().expect("browser").executed, 1);
    }
}
