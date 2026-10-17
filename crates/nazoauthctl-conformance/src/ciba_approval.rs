//! Normal CIBA user-approval client used by the external conformance driver.
//!
//! This module deliberately uses only public, production NazoAuth endpoints:
//! password login, CIBA verification, and CIBA user decision.  It contains no
//! Suite identifiers, test-client shortcuts, or privileged decision route.

use crate::{HttpMethod, HttpRequest, HttpResponse, Transport, TransportError};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const BACKCHANNEL_RESPONSE_SOURCE: &str = "CallBackchannelAuthenticationEndpoint";
const AUTOMATED_APPROVAL_SOURCE: &str = "CallAutomatedCibaApprovalEndpoint";

pub struct CibaUserApprovalClient {
    issuer: Url,
    email: Zeroizing<String>,
    password: Zeroizing<String>,
    transport: Arc<dyn Transport>,
    allowed_clients: HashSet<String>,
}

impl std::fmt::Debug for CibaUserApprovalClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CibaUserApprovalClient")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl CibaUserApprovalClient {
    pub fn new(
        issuer: Url,
        email: Zeroizing<String>,
        password: Zeroizing<String>,
        transport: Arc<dyn Transport>,
        allowed_clients: HashSet<String>,
    ) -> Result<Self, CibaUserApprovalError> {
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.path() != "/"
        {
            return Err(CibaUserApprovalError::InvalidIssuer);
        }
        if email.trim().is_empty() || password.is_empty() {
            return Err(CibaUserApprovalError::InvalidCredentials);
        }
        Ok(Self {
            issuer,
            email,
            password,
            transport,
            allowed_clients,
        })
    }

    /// Authenticate the temporary applicant and submit a normal user decision.
    /// A fresh session is used per decision so a crash cannot leave a reusable
    /// browser-equivalent session in the controller process.
    pub fn decide(&self, auth_req_id: &str, approve: bool) -> Result<(), CibaUserApprovalError> {
        if auth_req_id.trim().is_empty() || auth_req_id.len() > 2048 {
            return Err(CibaUserApprovalError::InvalidAuthRequestId);
        }
        #[derive(Serialize)]
        struct LoginRequest<'a> {
            email: &'a str,
            password: &'a str,
        }
        #[derive(Serialize)]
        struct DecisionRequest<'a> {
            decision: &'a str,
            csrf_token: &'a str,
        }
        let login = self.send_json(
            HttpMethod::Post,
            "auth/login",
            &[],
            LoginRequest {
                email: self.email.as_str(),
                password: self.password.as_str(),
            },
        )?;
        if login.status != 200 {
            return Err(CibaUserApprovalError::LoginRejected(login.status));
        }
        let login_value: Value = login
            .body
            .json()
            .map_err(|_| CibaUserApprovalError::MalformedLoginResponse)?;
        if login_value
            .get("mfa_required")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            return Err(CibaUserApprovalError::MfaRequired);
        }
        let csrf = login_value
            .get("csrf_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(CibaUserApprovalError::MalformedLoginResponse)?;
        let cookies = cookie_header(&login, csrf)?;
        let encoded_id =
            url::form_urlencoded::byte_serialize(auth_req_id.as_bytes()).collect::<String>();
        let path = format!("auth/ciba/{encoded_id}");
        let verification = self.send(
            HttpMethod::Get,
            &path,
            vec![("Cookie".to_owned(), cookies.clone())],
            None,
        )?;
        if verification.status != 200 {
            return Err(CibaUserApprovalError::VerificationRejected(
                verification.status,
            ));
        }
        let verification_value: Value = verification
            .body
            .json()
            .map_err(|_| CibaUserApprovalError::MalformedVerificationResponse)?;
        if verification_value
            .get("auth_req_id")
            .and_then(Value::as_str)
            != Some(auth_req_id)
            || !verification_value
                .pointer("/request/client_id")
                .and_then(Value::as_str)
                .is_some_and(|client_id| self.allowed_clients.contains(client_id))
        {
            return Err(CibaUserApprovalError::VerificationRejected(403));
        }
        let response = self.send_json(
            HttpMethod::Post,
            &path,
            &[("Cookie", cookies.as_str())],
            DecisionRequest {
                decision: if approve { "approve" } else { "deny" },
                csrf_token: csrf,
            },
        )?;
        if response.status != 200 {
            return Err(CibaUserApprovalError::DecisionRejected(response.status));
        }
        Ok(())
    }

    fn send_json(
        &self,
        method: HttpMethod,
        path: &str,
        headers: &[(&str, &str)],
        body: impl Serialize,
    ) -> Result<HttpResponse, CibaUserApprovalError> {
        let mut values = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        values.extend(
            headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        let body = serde_json::to_vec(&body).map_err(|_| CibaUserApprovalError::RequestEncoding)?;
        self.send(method, path, values, Some(body))
    }

    fn send(
        &self,
        method: HttpMethod,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, CibaUserApprovalError> {
        let url = self
            .issuer
            .join(path)
            .map_err(|_| CibaUserApprovalError::InvalidIssuer)?;
        self.transport
            .send(
                HttpRequest {
                    method,
                    url,
                    headers,
                    body: body.map(Into::into),
                },
                MAX_RESPONSE_BYTES,
            )
            .map_err(CibaUserApprovalError::Transport)
    }
}

/// Returns only the CIBA request identifiers for which the Suite has reached
/// its ordinary automated-approval step. A backchannel response alone is not
/// approval authority because expiry and ignore tests intentionally omit that
/// step.
pub fn ciba_approval_requests(raw_log: &Value) -> Result<Vec<String>, CibaUserApprovalError> {
    let entries = raw_log
        .as_array()
        .ok_or(CibaUserApprovalError::MalformedSuiteLog)?;
    let mut seen = HashSet::new();
    let mut auth_req_ids = Vec::new();
    let mut pending_auth_req_id: Option<String> = None;
    for entry in entries {
        let source = entry.get("src").and_then(Value::as_str);
        if source == Some(AUTOMATED_APPROVAL_SOURCE) {
            let auth_req_id = pending_auth_req_id
                .take()
                .ok_or(CibaUserApprovalError::MalformedSuiteLog)?;
            if seen.insert(auth_req_id.clone()) {
                auth_req_ids.push(auth_req_id);
            }
            continue;
        }
        if source != Some(BACKCHANNEL_RESPONSE_SOURCE) {
            continue;
        }
        let decoded;
        let response = match entry.get("backchannel_authentication_endpoint_response") {
            Some(Value::String(response)) => {
                decoded = serde_json::from_str::<Value>(response)
                    .map_err(|_| CibaUserApprovalError::MalformedSuiteLog)?;
                &decoded
            }
            Some(response @ Value::Object(_)) => response,
            Some(_) => return Err(CibaUserApprovalError::MalformedSuiteLog),
            None => entry,
        };
        let Some(auth_req_id) = response.get("auth_req_id").and_then(Value::as_str) else {
            continue;
        };
        if auth_req_id.is_empty()
            || auth_req_id.len() > 2048
            || auth_req_id.chars().any(char::is_control)
        {
            return Err(CibaUserApprovalError::MalformedSuiteLog);
        }
        pending_auth_req_id = Some(auth_req_id.to_owned());
    }
    Ok(auth_req_ids)
}

fn cookie_header(
    response: &HttpResponse,
    csrf_token: &str,
) -> Result<String, CibaUserApprovalError> {
    let mut cookies = String::new();
    let mut count = 0;
    let mut has_csrf = false;
    for (_, value) in response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
    {
        let pair = value
            .split_once(';')
            .map_or(value.as_str(), |(pair, _)| pair);
        let Some((_, value)) = pair.split_once('=') else {
            continue;
        };
        if count > 0 {
            cookies.push_str("; ");
        }
        cookies.push_str(pair);
        count += 1;
        has_csrf |= value == csrf_token;
    }
    if count < 2 || !has_csrf {
        return Err(CibaUserApprovalError::MissingSessionCookies);
    }
    Ok(cookies)
}

#[derive(Debug, Error)]
pub enum CibaUserApprovalError {
    #[error("CIBA issuer must be an HTTPS origin")]
    InvalidIssuer,
    #[error("CIBA user credentials are invalid")]
    InvalidCredentials,
    #[error("CIBA auth_req_id is invalid")]
    InvalidAuthRequestId,
    #[error("CIBA login request encoding failed")]
    RequestEncoding,
    #[error("CIBA login was rejected with HTTP {0}")]
    LoginRejected(u16),
    #[error("CIBA login response is malformed")]
    MalformedLoginResponse,
    #[error("CIBA login requires MFA")]
    MfaRequired,
    #[error("CIBA login did not issue both session and CSRF cookies")]
    MissingSessionCookies,
    #[error("CIBA verification was rejected with HTTP {0}")]
    VerificationRejected(u16),
    #[error("CIBA verification response is malformed")]
    MalformedVerificationResponse,
    #[error("CIBA decision was rejected with HTTP {0}")]
    DecisionRejected(u16),
    #[error("CIBA user approval transport failed: {0}")]
    Transport(TransportError),
    #[error("OIDF Suite CIBA log is malformed")]
    MalformedSuiteLog,
}

/// A non-sensitive CIBA approval phase used by orchestration diagnostics.
///
/// Diagnostics deliberately discard HTTP statuses, response contents, issuer
/// URLs, request identifiers, and credentials before reporting this phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaApprovalFailureStage {
    Client,
    Login,
    Csrf,
    Verify,
    Decision,
    Transport(TransportError),
}

impl std::fmt::Display for CibaApprovalFailureStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => formatter.write_str("client"),
            Self::Login => formatter.write_str("login"),
            Self::Csrf => formatter.write_str("csrf"),
            Self::Verify => formatter.write_str("verify"),
            Self::Decision => formatter.write_str("decision"),
            Self::Transport(TransportError::InvalidConfiguration) => {
                formatter.write_str("transport-configuration")
            }
            Self::Transport(TransportError::Network(stage)) => {
                write!(formatter, "transport-{stage}")
            }
            Self::Transport(TransportError::Oversize) => formatter.write_str("transport-oversize"),
        }
    }
}

impl CibaUserApprovalError {
    pub fn approval_failure_stage(&self) -> CibaApprovalFailureStage {
        match self {
            Self::InvalidIssuer
            | Self::InvalidCredentials
            | Self::InvalidAuthRequestId
            | Self::RequestEncoding
            | Self::MalformedSuiteLog => CibaApprovalFailureStage::Client,
            Self::LoginRejected(_) | Self::MalformedLoginResponse | Self::MfaRequired => {
                CibaApprovalFailureStage::Login
            }
            Self::MissingSessionCookies => CibaApprovalFailureStage::Csrf,
            Self::VerificationRejected(_) | Self::MalformedVerificationResponse => {
                CibaApprovalFailureStage::Verify
            }
            Self::DecisionRejected(_) => CibaApprovalFailureStage::Decision,
            Self::Transport(error) => CibaApprovalFailureStage::Transport(*error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportFailureStage;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, request: HttpRequest, _: usize) -> Result<HttpResponse, TransportError> {
            self.requests.lock().expect("requests").push(request);
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .ok_or(TransportError::Network(TransportFailureStage::SendRequest))
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: serde_json::to_vec(&body).expect("JSON response").into(),
        }
    }

    fn client(fake: Arc<FakeTransport>) -> CibaUserApprovalClient {
        CibaUserApprovalClient::new(
            Url::parse("https://auth.example/").expect("issuer"),
            Zeroizing::new("applicant@example.invalid".to_owned()),
            Zeroizing::new("correct horse battery staple".to_owned()),
            fake,
            HashSet::from(["client-1".to_owned()]),
        )
        .expect("client")
    }

    #[test]
    fn security_cloud_ciba_foreign_client_never_reaches_decision() {
        let fake = Arc::new(FakeTransport::new(vec![
            response(
                200,
                &[
                    ("Set-Cookie", "session=opaque; Path=/; HttpOnly"),
                    ("Set-Cookie", "csrf=csrf-value; Path=/"),
                ],
                json!({"csrf_token":"csrf-value","mfa_required":false}),
            ),
            response(
                200,
                &[],
                json!({"auth_req_id":"request-1","request":{"client_id":"foreign-client"}}),
            ),
        ]));
        assert!(matches!(
            client(fake.clone()).decide("request-1", true),
            Err(CibaUserApprovalError::VerificationRejected(403))
        ));
        assert_eq!(fake.requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn standard_user_session_approves_ciba_request() {
        let fake = Arc::new(FakeTransport::new(vec![
            response(
                200,
                &[
                    ("Set-Cookie", "session=opaque; Path=/; HttpOnly"),
                    ("Set-Cookie", "csrf=csrf-value; Path=/"),
                ],
                json!({"csrf_token":"csrf-value","mfa_required":false}),
            ),
            response(
                200,
                &[],
                json!({"auth_req_id":"request-1","csrf_token":"csrf-value","request":{"client_id":"client-1"}}),
            ),
            response(200, &[], json!({"success":true})),
        ]));
        client(Arc::clone(&fake))
            .decide("request-1", true)
            .expect("normal user decision succeeds");
        let requests = fake.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].url.path(), "/auth/login");
        assert_eq!(requests[1].url.path(), "/auth/ciba/request-1");
        assert_eq!(requests[2].url.path(), "/auth/ciba/request-1");
        assert_eq!(
            requests[2].header("Cookie"),
            Some("session=opaque; csrf=csrf-value")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(requests[2].body().expect("decision body"))
                .expect("decision JSON"),
            json!({"decision":"approve","csrf_token":"csrf-value"})
        );
    }

    #[test]
    fn standard_user_session_rejects_when_the_suite_requests_denial() {
        let fake = Arc::new(FakeTransport::new(vec![
            response(
                200,
                &[
                    ("Set-Cookie", "session=opaque; Path=/; HttpOnly"),
                    ("Set-Cookie", "csrf=csrf-value; Path=/"),
                ],
                json!({"csrf_token":"csrf-value","mfa_required":false}),
            ),
            response(
                200,
                &[],
                json!({"auth_req_id":"request-1","request":{"client_id":"client-1"}}),
            ),
            response(200, &[], json!({"success":true})),
        ]));
        client(Arc::clone(&fake))
            .decide("request-1", false)
            .expect("normal user denial succeeds");
        let requests = fake.requests.lock().expect("requests");
        assert_eq!(
            serde_json::from_slice::<Value>(requests[2].body().expect("decision body"))
                .expect("decision JSON"),
            json!({"decision":"deny","csrf_token":"csrf-value"})
        );
    }

    #[test]
    fn mismatched_or_absent_verification_never_posts_a_decision() {
        let fake = Arc::new(FakeTransport::new(vec![
            response(
                200,
                &[
                    ("Set-Cookie", "session=opaque; Path=/; HttpOnly"),
                    ("Set-Cookie", "csrf=csrf-value; Path=/"),
                ],
                json!({"csrf_token":"csrf-value","mfa_required":false}),
            ),
            response(
                200,
                &[],
                json!({"auth_req_id":"different-request","csrf_token":"csrf-value","request":null}),
            ),
        ]));
        assert!(matches!(
            client(Arc::clone(&fake)).decide("request-1", true),
            Err(CibaUserApprovalError::VerificationRejected(403))
        ));
        assert_eq!(fake.requests.lock().expect("requests").len(), 2);
    }

    #[test]
    fn issuer_must_be_a_clean_https_origin() {
        let fake = Arc::new(FakeTransport::new(Vec::new()));
        assert!(matches!(
            CibaUserApprovalClient::new(
                Url::parse("http://auth.example/path?x=1").expect("URL"),
                Zeroizing::new("applicant@example.invalid".to_owned()),
                Zeroizing::new("password".to_owned()),
                fake.clone(),
                HashSet::from(["client-1".to_owned()]),
            ),
            Err(CibaUserApprovalError::InvalidIssuer)
        ));
        assert!(matches!(
            CibaUserApprovalClient::new(
                Url::parse("https://auth.example/not-an-origin").expect("URL"),
                Zeroizing::new("applicant@example.invalid".to_owned()),
                Zeroizing::new("password".to_owned()),
                fake,
                HashSet::from(["client-1".to_owned()]),
            ),
            Err(CibaUserApprovalError::InvalidIssuer)
        ));
    }

    #[test]
    fn suite_log_exposes_only_explicit_automated_approval_requests_in_order() {
        let log = json!([
            {
                "src": "UnrelatedCondition",
                "auth_req_id": "ignored"
            },
            {
                "src": "CallBackchannelAuthenticationEndpoint",
                "backchannel_authentication_endpoint_response":
                    "{\"auth_req_id\":\"request-1\",\"expires_in\":120}"
            },
            {
                "src": "CallBackchannelAuthenticationEndpoint",
                "auth_req_id": "request-1",
                "result": "SUCCESS"
            },
            {
                "src": "CallAutomatedCibaApprovalEndpoint",
                "msg": "automation requested"
            },
            {
                "src": "CallBackchannelAuthenticationEndpoint",
                "auth_req_id": "request-2",
                "result": "SUCCESS"
            },
            {
                "src": "CallAutomatedCibaApprovalEndpoint",
                "msg": "automation requested"
            }
        ]);
        assert_eq!(
            ciba_approval_requests(&log).expect("valid Suite log"),
            ["request-1", "request-2"]
        );
    }

    #[test]
    fn approval_marker_uses_the_most_recent_backchannel_request() {
        let log = json!([
            {
                "src": "CallBackchannelAuthenticationEndpoint",
                "auth_req_id": "stale-request",
                "result": "SUCCESS"
            },
            {
                "src": "CallBackchannelAuthenticationEndpoint",
                "auth_req_id": "current-request",
                "result": "SUCCESS"
            },
            {
                "src": "CallAutomatedCibaApprovalEndpoint",
                "msg": "automation requested"
            }
        ]);
        assert_eq!(
            ciba_approval_requests(&log).expect("valid Suite log"),
            ["current-request"]
        );
    }

    #[test]
    fn backchannel_response_without_automation_marker_is_not_approved() {
        let log = json!([{
            "src": "CallBackchannelAuthenticationEndpoint",
            "auth_req_id": "must-not-be-approved",
            "result": "SUCCESS"
        }]);
        assert!(
            ciba_approval_requests(&log)
                .expect("valid Suite log")
                .is_empty()
        );
    }

    #[test]
    fn malformed_matching_suite_response_fails_closed() {
        let log = json!([{
            "src": "CallBackchannelAuthenticationEndpoint",
            "backchannel_authentication_endpoint_response": "not-json"
        }]);
        assert!(matches!(
            ciba_approval_requests(&log),
            Err(CibaUserApprovalError::MalformedSuiteLog)
        ));
    }

    #[test]
    fn approval_marker_without_a_backchannel_request_fails_closed() {
        let log = json!([{"src": "CallAutomatedCibaApprovalEndpoint"}]);
        assert!(matches!(
            ciba_approval_requests(&log),
            Err(CibaUserApprovalError::MalformedSuiteLog)
        ));
    }

    #[test]
    fn approval_failure_stages_are_static_and_cover_each_protocol_phase() {
        let cases = [
            (
                CibaUserApprovalError::LoginRejected(503),
                CibaApprovalFailureStage::Login,
            ),
            (
                CibaUserApprovalError::MissingSessionCookies,
                CibaApprovalFailureStage::Csrf,
            ),
            (
                CibaUserApprovalError::VerificationRejected(403),
                CibaApprovalFailureStage::Verify,
            ),
            (
                CibaUserApprovalError::DecisionRejected(418),
                CibaApprovalFailureStage::Decision,
            ),
            (
                CibaUserApprovalError::Transport(TransportError::Network(
                    TransportFailureStage::SendTimeout,
                )),
                CibaApprovalFailureStage::Transport(TransportError::Network(
                    TransportFailureStage::SendTimeout,
                )),
            ),
        ];
        for (error, stage) in cases {
            assert_eq!(error.approval_failure_stage(), stage);
            let rendered = stage.to_string();
            for sensitive_or_dynamic in [
                "503",
                "403",
                "418",
                "private-auth-request",
                "csrf-value",
                "correct horse battery staple",
                "approval_token",
                "auth_req_id",
            ] {
                assert!(!rendered.contains(sensitive_or_dynamic));
            }
        }
        assert_eq!(
            CibaApprovalFailureStage::Transport(TransportError::Network(
                TransportFailureStage::SendTimeout
            ))
            .to_string(),
            "transport-send-timeout"
        );
    }
}
