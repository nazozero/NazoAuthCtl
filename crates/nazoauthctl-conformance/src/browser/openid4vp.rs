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

/// Inputs required to start one OpenID4VP verifier presentation. Matrix
/// values stay opaque until this boundary; the verifier client accepts only
/// formats and request methods used by the official plans.
#[derive(Clone, Debug)]
pub struct OpenId4VpStartRequest {
    pub alias: String,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
    pub haip: bool,
}

impl OpenId4VpStartRequest {
    pub fn new(
        alias: impl Into<String>,
        test_name: impl Into<String>,
        variant: BTreeMap<String, String>,
        haip: bool,
    ) -> Result<Self, OpenId4VpError> {
        let request = Self {
            alias: alias.into(),
            test_name: test_name.into(),
            variant,
            haip,
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
}

/// Rust-native client for NazoAuth's verifier-start endpoint.
pub struct OpenId4VpVerifierClient {
    target_origin: BrowserTargetOrigin,
    suite_origin: Origin,
    management_token: Zeroizing<String>,
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
    ) -> Result<Self, OpenId4VpError> {
        let mut client = Self::new(
            target_origin,
            suite_origin,
            management_token,
            Duration::from_secs(30),
        )?;
        client.transport = transport;
        Ok(client)
    }

    fn start_presentation(
        &self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError> {
        request.validate()?;
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
        })
    }

    fn allows_browser_url(&self, url: &Url) -> bool {
        (self.target_origin.allows(url) || self.suite_origin.same_origin_url(url))
            && matches!(url.scheme(), "https" | "http")
    }
}

impl OpenId4VpVerifier for OpenId4VpVerifierClient {
    fn start(
        &mut self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError> {
        self.start_presentation(request)
    }
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum OpenId4VpError {
    #[error("OpenID4VP verifier input is invalid")]
    InvalidInput,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{HttpResponse, TransportError};

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
        )
        .expect("client");
        let mut variant = BTreeMap::new();
        variant.insert("credential_format".to_owned(), "sd_jwt_vc".to_owned());
        variant.insert("request_method".to_owned(), "request_uri_signed".to_owned());
        let request =
            OpenId4VpStartRequest::new("vp", SPECIAL_POST_TEST, variant, false).expect("request");
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
        )
        .expect("client");
        let mut variant = BTreeMap::new();
        variant.insert("credential_format".to_owned(), "iso_mdl".to_owned());
        let request = OpenId4VpStartRequest::new("vp", "happy", variant, true).expect("request");
        assert_eq!(
            client.start(&request).expect_err("cross origin"),
            OpenId4VpError::CrossOriginNavigation
        );
    }
}
