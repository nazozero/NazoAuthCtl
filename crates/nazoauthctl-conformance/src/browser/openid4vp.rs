//! Target-side OpenID4VP verifier orchestration.
//!
//! This module owns the narrow management API used to initiate a verifier
//! transaction. Browser protocol and Suite result handling remain in their
//! respective owners.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
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

/// The deployment capability binding that must accompany every target-side
/// verifier start.  Keeping the two values in one validated type makes a
/// partial binding unrepresentable at the HTTP boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBinding {
    lease_id: Uuid,
    task_jti: String,
}

impl ConformanceBinding {
    pub fn new(
        lease_id: impl AsRef<str>,
        task_jti: impl Into<String>,
    ) -> Result<Self, OpenId4VpError> {
        let lease_id =
            Uuid::parse_str(lease_id.as_ref()).map_err(|_| OpenId4VpError::InvalidBinding)?;
        let task_jti = task_jti.into();
        let suffix = task_jti
            .strip_prefix("request-")
            .ok_or(OpenId4VpError::InvalidBinding)?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(OpenId4VpError::InvalidBinding);
        }
        Ok(Self { lease_id, task_jti })
    }

    pub fn lease_id(&self) -> Uuid {
        self.lease_id
    }

    pub fn task_jti(&self) -> &str {
        &self.task_jti
    }
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
    immediate_rejection_allowed: bool,
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
            .field(
                "immediate_rejection_allowed",
                &self.immediate_rejection_allowed,
            )
            .finish()
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
    fn complete(&mut self, presentation: &OpenId4VpPresentation) -> Result<(), OpenId4VpError>;
}

/// Rust-native client for NazoAuth's verifier-start endpoint.
pub struct OpenId4VpVerifierClient {
    target_origin: BrowserTargetOrigin,
    suite_origin: Origin,
    management_token: Zeroizing<String>,
    binding: ConformanceBinding,
    transport: Arc<dyn Transport>,
    max_response_bytes: usize,
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
        })
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
        let body = serde_json::json!({
            "wallet_authorization_endpoint": wallet_authorization_endpoint.as_str(),
            "dcql_query": {
                "credentials": [{
                    "id": "credential",
                    "format": dcql_format,
                    "meta": credential_meta,
                    "require_cryptographic_holder_binding": true,
                }]
            },
            "haip": request.haip,
            "client_id_prefix": client_id_prefix,
            "request_method": request_method,
            "response_mode": response_mode,
            "conformance_lease_id": self.binding.lease_id().to_string(),
            "conformance_task_jti": self.binding.task_jti(),
        });
        let body = serde_json::to_vec(&body).map_err(|_| OpenId4VpError::InvalidInput)?;
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
                self.max_response_bytes,
            )
            .map_err(OpenId4VpError::Transport)?;
        if !(200..300).contains(&response.status) {
            return Err(OpenId4VpError::UnexpectedStatus);
        }
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|_| OpenId4VpError::MalformedResponse)?;
        let authorization_url = value
            .get("authorization_url")
            .and_then(Value::as_str)
            .ok_or(OpenId4VpError::MalformedResponse)
            .and_then(|value| Url::parse(value).map_err(|_| OpenId4VpError::MalformedResponse))?;
        if !self.allows_browser_url(&authorization_url)
            || !authorization_url.username().is_empty()
            || authorization_url.password().is_some()
            || authorization_url.fragment().is_some()
        {
            return Err(OpenId4VpError::CrossOriginNavigation);
        }
        let transaction_id = value
            .get("transaction_id")
            .and_then(Value::as_str)
            .ok_or(OpenId4VpError::MalformedResponse)
            .and_then(|value| {
                Uuid::parse_str(value).map_err(|_| OpenId4VpError::MalformedResponse)
            })?;
        let mut completion_url = self.target_origin.as_url().clone();
        completion_url.set_path(&format!("/openid4vp/complete/{transaction_id}"));
        completion_url.set_query(None);
        completion_url.set_fragment(None);
        Ok(OpenId4VpPresentation {
            authorization_url,
            completion_url,
            transaction_id,
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
    ) -> Result<(), OpenId4VpError> {
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
            return Ok(());
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

    fn complete(&mut self, presentation: &OpenId4VpPresentation) -> Result<(), OpenId4VpError> {
        self.complete_presentation(presentation)
    }
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{HttpResponse, TransportError};
    use std::collections::VecDeque;

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
            *self.request.lock().expect("request lock") = Some(request);
            self.response
                .lock()
                .expect("response lock")
                .take()
                .ok_or(TransportError::Network)
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
            self.requests.lock().expect("request lock").push(request);
            self.responses
                .lock()
                .expect("response lock")
                .pop_front()
                .ok_or(TransportError::Network)
        }
    }

    fn binding() -> ConformanceBinding {
        ConformanceBinding::new(
            "019ff000-8190-7393-8c33-ab4339c3d85e",
            "request-0123456789abcdef0123456789abcdef",
        )
        .expect("binding")
    }

    #[test]
    fn maps_sd_jwt_and_post_method_without_leaking_token() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let transport = Arc::new(VerifierTransport {
            request: std::sync::Mutex::new(None),
            response: std::sync::Mutex::new(Some(HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: serde_json::to_vec(&serde_json::json!({
                    "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000"
                }))
                .expect("response"),
            })),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            target,
            suite,
            Zeroizing::new("management-secret".to_owned()),
            transport.clone(),
            binding(),
        )
        .expect("client");
        let mut variant = BTreeMap::new();
        variant.insert("credential_format".to_owned(), "sd_jwt_vc".to_owned());
        variant.insert("request_method".to_owned(), "request_uri_signed".to_owned());
        let request =
            OpenId4VpStartRequest::new("vp", SPECIAL_POST_TEST, variant, false, binding())
                .expect("request");
        let presentation = client.start(&request).expect("presentation");
        assert_eq!(
            presentation.completion_url.as_str(),
            "https://issuer.example/openid4vp/complete/550e8400-e29b-41d4-a716-446655440000"
        );
        let captured = transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("request");
        assert_eq!(captured.url().path(), "/openid4vp/presentations");
        assert_eq!(
            captured.header("Authorization"),
            Some("Bearer management-secret")
        );
        let body: Value = serde_json::from_slice(captured.body().expect("body")).expect("body");
        assert_eq!(body["request_method"], "request_uri_signed_post");
        assert_eq!(body["dcql_query"]["credentials"][0]["format"], "dc+sd-jwt");
        assert_eq!(
            body["dcql_query"]["credentials"][0]["meta"]["vct_values"][0],
            "urn:eudi:pid:1"
        );
        assert_eq!(
            body["conformance_lease_id"],
            "019ff000-8190-7393-8c33-ab4339c3d85e"
        );
        assert_eq!(
            body["conformance_task_jti"],
            "request-0123456789abcdef0123456789abcdef"
        );
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
                    "transaction_id": "550e8400-e29b-41d4-a716-446655440000"
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
            ConformanceBinding::new("not-a-uuid", "request-0123456789abcdef0123456789abcdef")
                .expect_err("invalid lease"),
            OpenId4VpError::InvalidBinding
        );
        assert_eq!(
            ConformanceBinding::new(
                "019ff000-8190-7393-8c33-ab4339c3d85e",
                "request-0123456789abcdef0123456789ABCDEf",
            )
            .expect_err("uppercase task jti"),
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
        let other_binding = ConformanceBinding::new(
            "019ff000-8190-7393-8c33-ab4339c3d85f",
            "request-fedcba9876543210fedcba9876543210",
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
            immediate_rejection_allowed: false,
        };

        client.complete(&presentation).expect("completion");

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
                        "transaction_id": "550e8400-e29b-41d4-a716-446655440000"
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

        client
            .complete(&presentation)
            .expect("immediate rejection is an expected negative outcome");
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
