//! Target-side OpenID4VP verifier orchestration.
//!
//! This module owns the narrow management API used to initiate a verifier
//! transaction. Browser protocol and Suite result handling remain in their
//! respective owners.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
#[cfg(test)]
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
const MAX_CREATE_ATTEMPTS: usize = 4;
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

/// The protocol-level result of delivering the wallet response. A named
/// negative test may be rejected by the verifier before a completed
/// presentation exists; that expected outcome must never be treated as a
/// completed transaction with verification evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenId4VpCompletionOutcome {
    Completed,
    ExpectedImmediateRejection,
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

#[cfg(all(test, unix))]
impl OpenId4VpPresentation {
    /// Test-only presentation fixture for orchestration tests. Production
    /// construction remains exclusively in the verified management client.
    pub(crate) fn test_presentation() -> Self {
        Self {
            authorization_url: Url::parse("https://issuer.example/authorize?request=opaque")
                .expect("test authorization URL"),
            completion_url: Url::parse(
                "https://issuer.example/openid4vp/complete/00000000-0000-0000-0000-000000000000",
            )
            .expect("test completion URL"),
            transaction_id: Uuid::nil(),
            immediate_rejection_allowed: false,
        }
    }
}

/// Narrow orchestration hook for an OpenID4VP verifier. Browser protocol
/// executes in the Suite; this trait drives the verifier protocol exchange.
pub trait OpenId4VpVerifier: Send {
    fn start(
        &mut self,
        request: &OpenId4VpStartRequest,
    ) -> Result<OpenId4VpPresentation, OpenId4VpError>;

    /// Deliver the presentation request to the Suite wallet, then verify the
    /// completion endpoint bound to the target transaction. The Suite may
    /// redirect or display a result page; neither alone proves completion.
    fn complete(
        &mut self,
        presentation: &OpenId4VpPresentation,
        delivery_url: &Url,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError>;
}

/// Historical evidence required to re-verify that a retained screenshot came
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
        let wallet_authorization_endpoint = self
            .suite_origin
            .url(&format!("/test/a/{}/authorize", request.alias))
            .map_err(|_| OpenId4VpError::InvalidInput)?;
        let mut endpoint = self.target_origin.as_url().clone();
        endpoint.set_path("/openid4vp/presentations");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let idempotency = nazo_operator_protocol::Openid4vpCreateIdempotencyRequest {
            create_request_jti: Uuid::new_v4().to_string(),
        };
        let dcql_query = serde_json::json!({
            "credentials": [{
                "id": "credential",
                "format": dcql_format,
                "meta": credential_meta,
                "require_cryptographic_holder_binding": true,
            }]
        });
        let normalized = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
            wallet_authorization_endpoint: wallet_authorization_endpoint.into(),
            dcql_query,
            haip: request.haip,
            client_id_prefix,
            request_method: request_method.to_owned(),
            response_mode,
            transaction_data: None,
            openid4vc_trust_policy_resource_id: Some(self.binding.resource_id.clone()),
            openid4vc_trust_policy_digest: Some(self.binding.digest.clone()),
        };
        let (_, create_request_sha256) =
            nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
                .map_err(|_| OpenId4VpError::InvalidInput)?;
        #[derive(Serialize)]
        struct CreateRequest<'a> {
            #[serde(flatten)]
            normalized: &'a nazo_operator_protocol::Openid4vpNormalizedCreateRequest,
            #[serde(flatten)]
            idempotency: &'a nazo_operator_protocol::Openid4vpCreateIdempotencyRequest,
        }
        let body: bytes::Bytes = serde_json::to_vec(&CreateRequest {
            normalized: &normalized,
            idempotency: &idempotency,
        })
        .map_err(|_| OpenId4VpError::InvalidInput)?
        .into();
        let mut attempts = 0usize;
        let response = loop {
            attempts += 1;
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
            || response.idempotency.create_request_jti != idempotency.create_request_jti
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
        delivery_url: &Url,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError> {
        if !self.suite_origin.same_origin_url(delivery_url)
            || !delivery_url.username().is_empty()
            || delivery_url.password().is_some()
            || delivery_url.fragment().is_some()
        {
            return Err(OpenId4VpError::InvalidInput);
        }
        let response = self
            .transport
            .send(
                HttpRequest {
                    method: HttpMethod::Get,
                    url: delivery_url.clone(),
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
        // on that Suite 2xx; positive and deferred-verification flows still require
        // the target transaction completion endpoint to succeed.
        if (200..300).contains(&response.status) && presentation.immediate_rejection_allowed {
            return Ok(OpenId4VpCompletionOutcome::ExpectedImmediateRejection);
        }
        if matches!(response.status, 302 | 303) {
            let location = response
                .header("Location")
                .ok_or(OpenId4VpError::UnexpectedAuthorizationRedirect)?;
            let redirected = delivery_url
                .join(location)
                .map_err(|_| OpenId4VpError::UnexpectedAuthorizationRedirect)?;
            if redirected != presentation.completion_url {
                return Err(OpenId4VpError::UnexpectedAuthorizationRedirect);
            }
        } else if response.status != 200 {
            return Err(OpenId4VpError::UnexpectedAuthorizationRedirect);
        }
        // The Suite can display its result page instead of issuing a redirect.
        // Its 200 is not completion evidence: visit only the completion URL
        // bound by start(), whose endpoint succeeds only for a verified result.

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
        delivery_url: &Url,
    ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError> {
        self.complete_presentation(presentation, delivery_url)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{HttpResponse, TransportError, TransportFailureStage};
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

    struct RetryingCreateTransport {
        request_bodies: std::sync::Mutex<Vec<bytes::Bytes>>,
    }

    impl Transport for RetryingCreateTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let body = request.body.as_ref().expect("create body").clone();
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

        client.start(&request).expect("response-loss retry");
        let request_bodies = transport.request_bodies.lock().expect("request lock");
        assert_eq!(request_bodies.len(), 2);
        let first: Value = serde_json::from_slice(&request_bodies[0]).expect("first body JSON");
        let second: Value = serde_json::from_slice(&request_bodies[1]).expect("second body JSON");
        assert_eq!(request_bodies[0], request_bodies[1]);
        assert_eq!(request_bodies[0].as_ptr(), request_bodies[1].as_ptr());
        assert_eq!(first["create_request_jti"], second["create_request_jti"]);
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
    #[ignore = "set NAZO_SERVER_TEST_BINARY to the NazoAuth host library unit-test executable"]
    fn start_accepts_server_typed_dcql_digest() {
        struct ServerDigestTransport {
            binary: std::path::PathBuf,
            directory: std::path::PathBuf,
        }
        impl Transport for ServerDigestTransport {
            fn send(&self, request: HttpRequest, _: usize) -> Result<HttpResponse, TransportError> {
                let input = self.directory.join("request.json");
                let output = self.directory.join("sha256.txt");
                let raw = request.body().expect("actual controller start body");
                let body: Value = serde_json::from_slice(raw).unwrap();
                assert!(
                    body["dcql_query"]["credentials"][0]
                        .get("multiple")
                        .is_none()
                );
                std::fs::write(&input, raw).unwrap();
                let status = std::process::Command::new(&self.binary)
                    .args([
                        "canonicalize_controller_start_wire",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("NAZO_VP_WIRE_INPUT", &input)
                    .env("NAZO_VP_HASH_OUTPUT", &output)
                    .status()
                    .expect("run server's real typed DCQL canonicalization");
                assert!(status.success());
                let hash = std::fs::read_to_string(output).unwrap();
                Ok(HttpResponse {
                    status: 201,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "authorization_url": "https://suite.example/test/a/vp/authorize?x=1",
                        "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
                        "expires_in": 300,
                        "create_request_jti": body["create_request_jti"],
                        "create_request_sha256": hash,
                    }))
                    .unwrap(),
                })
            }
        }
        let directory = std::env::temp_dir().join(format!("nazo-vp-contract-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let transport = Arc::new(ServerDigestTransport {
            binary: std::env::var_os("NAZO_SERVER_TEST_BINARY")
                .expect("server test binary")
                .into(),
            directory: directory.clone(),
        });
        let mut client = OpenId4VpVerifierClient::with_transport(
            BrowserTargetOrigin::parse("https://issuer.example").unwrap(),
            Origin::parse("https://suite.example").unwrap(),
            Zeroizing::new("management-secret".to_owned()),
            transport,
            binding(),
        )
        .unwrap();
        let request =
            OpenId4VpStartRequest::new("vp", "happy", BTreeMap::new(), false, binding()).unwrap();
        client
            .start(&request)
            .expect("controller must accept the digest computed from the server's typed request");
        std::fs::remove_file(directory.join("request.json")).unwrap();
        std::fs::remove_file(directory.join("sha256.txt")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn ordinary_create_omits_legacy_evidence_fields() {
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
    fn create_rejects_legacy_capability_response() {
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
    fn completes_redirect_or_result_page_only_after_target_transaction_success() {
        for (suite_status, target_status) in [(302, 200), (303, 200), (200, 200), (200, 400)] {
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
                        status: suite_status,
                        headers: if suite_status == 200 {
                            Vec::new()
                        } else {
                            vec![("Location".to_owned(), completion_url.to_string())]
                        },
                        body: Vec::new(),
                    },
                    HttpResponse {
                        status: target_status,
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

            let delivery_url = Url::parse(
                "https://suite.example/test/a/module/authorize?request_uri=urn%3Aexample",
            )
            .expect("delivery URL");
            let completed = client.complete(&presentation, &delivery_url);
            if target_status == 200 {
                assert_eq!(
                    completed.expect("completion"),
                    OpenId4VpCompletionOutcome::Completed
                );
            } else {
                assert_eq!(
                    completed.expect_err("unverified transaction"),
                    OpenId4VpError::CompletionFailed
                );
            }

            let requests = transport.requests.lock().expect("request lock");
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0].method(), HttpMethod::Get);
            assert_eq!(requests[0].url(), &delivery_url);
            assert_eq!(requests[1].url(), &completion_url);
            assert_eq!(
                requests[0].header("Accept"),
                Some("text/html,application/xhtml+xml")
            );
        }
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
                .complete(&presentation, &presentation.authorization_url)
                .expect("immediate rejection is an expected negative outcome"),
            OpenId4VpCompletionOutcome::ExpectedImmediateRejection
        );
        assert_eq!(transport.requests.lock().expect("request lock").len(), 2);
    }

    #[test]
    fn positive_test_rejects_suite_2xx_without_target_completion() {
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

        assert!(matches!(
            client
                .complete(&presentation, &presentation.authorization_url)
                .expect_err("Suite 200 alone cannot prove target completion"),
            OpenId4VpError::Transport(_)
        ));
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
            client
                .complete(&presentation, &presentation.authorization_url)
                .expect_err("Suite 4xx"),
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
                .complete(&presentation, &presentation.authorization_url)
                .expect_err("redirect mismatch"),
            OpenId4VpError::UnexpectedAuthorizationRedirect
        );
        assert_eq!(transport.requests.lock().expect("request lock").len(), 1);
    }
}
