//! Normal CIBA user-approval client used by the external conformance driver.
//!
//! This module deliberately uses only public, production NazoAuth endpoints:
//! password login, CIBA verification, and CIBA user decision.  It contains no
//! Suite identifiers, test-client shortcuts, or privileged decision route.

use crate::{HttpMethod, HttpRequest, HttpResponse, Transport, TransportError};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CALLBACK_REQUEST_BYTES: usize = 8 * 1024;
const CALLBACK_IDLE_WAIT: Duration = Duration::from_millis(20);

pub struct CibaUserApprovalClient {
    issuer: Url,
    email: Zeroizing<String>,
    password: Zeroizing<String>,
    transport: Arc<dyn Transport>,
}

impl std::fmt::Debug for CibaUserApprovalClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CibaUserApprovalClient")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl Drop for CibaUserApprovalClient {
    fn drop(&mut self) {
        self.email.zeroize();
        self.password.zeroize();
    }
}

impl CibaUserApprovalClient {
    pub fn new(
        issuer: Url,
        email: Zeroizing<String>,
        password: Zeroizing<String>,
        transport: Arc<dyn Transport>,
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
        })
    }

    /// Authenticate the temporary applicant and submit a normal user decision.
    /// A fresh session is used per callback so a crash cannot leave a reusable
    /// browser-equivalent session in the controller process.
    pub fn decide(&self, auth_req_id: &str, approve: bool) -> Result<(), CibaUserApprovalError> {
        if auth_req_id.trim().is_empty() || auth_req_id.len() > 2048 {
            return Err(CibaUserApprovalError::InvalidAuthRequestId);
        }
        let login = self.send_json(
            HttpMethod::Post,
            "auth/login",
            &[],
            json!({"email": self.email.as_str(), "password": self.password.as_str()}),
        )?;
        if login.status != 200 {
            return Err(CibaUserApprovalError::LoginRejected(login.status));
        }
        let login_value: Value = serde_json::from_slice(&login.body)
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
        let verification = self.send(
            HttpMethod::Get,
            &format!("auth/ciba/{encoded_id}"),
            vec![("Cookie".to_owned(), cookies.clone())],
            None,
        )?;
        if verification.status != 200 {
            return Err(CibaUserApprovalError::VerificationRejected(
                verification.status,
            ));
        }
        let verification_value: Value = serde_json::from_slice(&verification.body)
            .map_err(|_| CibaUserApprovalError::MalformedVerificationResponse)?;
        if verification_value
            .get("auth_req_id")
            .and_then(Value::as_str)
            != Some(auth_req_id)
            || verification_value.get("request").is_none_or(Value::is_null)
        {
            return Err(CibaUserApprovalError::VerificationRejected(403));
        }
        let response = self.send_json(
            HttpMethod::Post,
            &format!("auth/ciba/{encoded_id}"),
            &[("Cookie", cookies.as_str())],
            json!({"decision": if approve { "approve" } else { "deny" }, "csrf_token": csrf}),
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
        body: Value,
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
                    body,
                },
                MAX_RESPONSE_BYTES,
            )
            .map_err(CibaUserApprovalError::Transport)
    }
}

fn cookie_header(
    response: &HttpResponse,
    csrf_token: &str,
) -> Result<String, CibaUserApprovalError> {
    let values = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, value)| value.split(';').next())
        .filter(|pair| pair.contains('='))
        .collect::<Vec<_>>();
    if values.len() < 2
        || !values.iter().any(|pair| {
            pair.split_once('=')
                .is_some_and(|(_, value)| value == csrf_token)
        })
    {
        return Err(CibaUserApprovalError::MissingSessionCookies);
    }
    Ok(values.join("; "))
}

/// Loopback callback bridge used by an external driver to request a normal
/// CIBA user decision. The configured public HTTPS origin is terminated and
/// forwarded by the deployment edge; this listener deliberately accepts only
/// loopback traffic and never becomes an NazoAuth route.
pub struct CibaUserApprovalBridge {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    health: Arc<Mutex<Option<String>>>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for CibaUserApprovalBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CibaUserApprovalBridge")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl CibaUserApprovalBridge {
    pub fn start(
        bind_addr: SocketAddr,
        callback_path: &str,
        approval_token: Zeroizing<String>,
        approver: Arc<CibaUserApprovalClient>,
    ) -> Result<Self, CibaUserApprovalError> {
        if !matches!(bind_addr.ip(), IpAddr::V4(address) if address.is_loopback())
            && !matches!(bind_addr.ip(), IpAddr::V6(address) if address.is_loopback())
        {
            return Err(CibaUserApprovalError::CallbackMustBindLoopback);
        }
        let callback_path = validate_callback_path(callback_path)?;
        if approval_token.len() < 32
            || approval_token.len() > 512
            || approval_token.chars().any(char::is_control)
        {
            return Err(CibaUserApprovalError::InvalidCallbackToken);
        }
        let listener = TcpListener::bind(bind_addr).map_err(CibaUserApprovalError::CallbackBind)?;
        listener
            .set_nonblocking(true)
            .map_err(CibaUserApprovalError::CallbackBind)?;
        let local_addr = listener
            .local_addr()
            .map_err(CibaUserApprovalError::CallbackBind)?;
        let stop = Arc::new(AtomicBool::new(false));
        let health = Arc::new(Mutex::new(None));
        let worker_stop = Arc::clone(&stop);
        let worker_health = Arc::clone(&health);
        let worker = thread::Builder::new()
            .name("nazoauthctl-ciba-approval".to_owned())
            .spawn(move || {
                run_callback_loop(
                    listener,
                    worker_stop,
                    worker_health,
                    callback_path,
                    approval_token,
                    approver,
                )
            })
            .map_err(CibaUserApprovalError::CallbackSpawn)?;
        Ok(Self {
            local_addr,
            stop,
            health,
            worker: Some(worker),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn ensure_healthy(&self) -> Result<(), CibaUserApprovalError> {
        self.health
            .lock()
            .map_err(|_| CibaUserApprovalError::CallbackUnhealthy)?
            .as_ref()
            .map_or(Ok(()), |_| Err(CibaUserApprovalError::CallbackUnhealthy))
    }
}

impl Drop for CibaUserApprovalBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn validate_callback_path(path: &str) -> Result<String, CibaUserApprovalError> {
    if !path.starts_with('/')
        || path == "/"
        || path.len() > 1024
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
    {
        return Err(CibaUserApprovalError::InvalidCallbackPath);
    }
    Ok(path.to_owned())
}

fn run_callback_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    health: Arc<Mutex<Option<String>>>,
    callback_path: String,
    approval_token: Zeroizing<String>,
    approver: Arc<CibaUserApprovalClient>,
) {
    let accepted = Mutex::new(HashSet::new());
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    let _ = write_callback_response(stream, 404);
                    continue;
                }
                if let Err(_error) = handle_callback(
                    stream,
                    &callback_path,
                    approval_token.as_bytes(),
                    &approver,
                    &accepted,
                ) {
                    // A malformed or disconnected external request is not a
                    // process failure and must not let an untrusted peer stop
                    // approvals for the remaining signed run.
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(CALLBACK_IDLE_WAIT);
            }
            Err(error) => {
                *health.lock().expect("callback health lock") = Some(error.to_string());
                return;
            }
        }
    }
}

fn handle_callback(
    mut stream: TcpStream,
    callback_path: &str,
    approval_token: &[u8],
    approver: &CibaUserApprovalClient,
    accepted: &Mutex<HashSet<String>>,
) -> Result<(), CibaUserApprovalError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(CibaUserApprovalError::CallbackRead)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(CibaUserApprovalError::CallbackWrite)?;
    let request = read_callback_request(&mut stream)?;
    let Some((auth_req_id, approve)) =
        parse_callback_request(&request, callback_path, approval_token)
    else {
        write_callback_response(stream, 404)?;
        return Ok(());
    };
    {
        let accepted = accepted
            .lock()
            .map_err(|_| CibaUserApprovalError::CallbackUnhealthy)?;
        if accepted.contains(&auth_req_id) {
            write_callback_response(stream, 404)?;
            return Ok(());
        }
    }
    match approver.decide(&auth_req_id, approve) {
        Ok(()) => {
            accepted
                .lock()
                .map_err(|_| CibaUserApprovalError::CallbackUnhealthy)?
                .insert(auth_req_id);
            write_callback_response(stream, 204)?;
        }
        Err(_) => write_callback_response(stream, 404)?,
    }
    Ok(())
}

fn read_callback_request(stream: &mut TcpStream) -> Result<String, CibaUserApprovalError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(CibaUserApprovalError::CallbackRead)?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > MAX_CALLBACK_REQUEST_BYTES {
            return Err(CibaUserApprovalError::CallbackRequestTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    std::str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|_| CibaUserApprovalError::MalformedCallbackRequest)
}

fn parse_callback_request(
    request: &str,
    callback_path: &str,
    approval_token: &[u8],
) -> Option<(String, bool)> {
    let (line, _) = request.split_once("\r\n")?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "GET" {
        return None;
    }
    let target = fields.next()?;
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return None;
    }
    if fields.next().is_some() {
        return None;
    }
    let url = Url::parse(&format!("http://localhost{target}")).ok()?;
    if url.path() != callback_path {
        return None;
    }
    let mut token = None;
    let mut auth_req_id = None;
    let mut action = None;
    for (name, value) in url.query_pairs() {
        let value = value.into_owned();
        match name.as_ref() {
            "approval_token" => {
                if token.replace(value).is_some() {
                    return None;
                }
            }
            "auth_req_id" => {
                if auth_req_id.replace(value).is_some() {
                    return None;
                }
            }
            "action" => {
                if action.replace(value).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let token = token?;
    if token.len() != approval_token.len()
        || token.as_bytes().ct_eq(approval_token).unwrap_u8() != 1
    {
        return None;
    }
    let auth_req_id = auth_req_id?;
    if auth_req_id.is_empty()
        || auth_req_id.len() > 2048
        || auth_req_id.chars().any(char::is_control)
    {
        return None;
    }
    let approve = match action.as_deref() {
        Some("allow") | Some("approve") => true,
        Some("deny") => false,
        _ => return None,
    };
    Some((auth_req_id, approve))
}

fn write_callback_response(
    mut stream: TcpStream,
    status: u16,
) -> Result<(), CibaUserApprovalError> {
    let reason = match status {
        204 => "No Content",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(CibaUserApprovalError::CallbackWrite)
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
    #[error("CIBA callback must bind a loopback address")]
    CallbackMustBindLoopback,
    #[error("CIBA callback path is invalid")]
    InvalidCallbackPath,
    #[error("CIBA callback token is invalid")]
    InvalidCallbackToken,
    #[error("CIBA callback listener could not bind: {0}")]
    CallbackBind(std::io::Error),
    #[error("CIBA callback listener could not start: {0}")]
    CallbackSpawn(std::io::Error),
    #[error("CIBA callback listener is unhealthy")]
    CallbackUnhealthy,
    #[error("CIBA callback request is malformed")]
    MalformedCallbackRequest,
    #[error("CIBA callback request exceeds the size limit")]
    CallbackRequestTooLarge,
    #[error("CIBA callback request could not be read: {0}")]
    CallbackRead(std::io::Error),
    #[error("CIBA callback response could not be written: {0}")]
    CallbackWrite(std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
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
                .ok_or(TransportError::Network)
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: serde_json::to_vec(&body).expect("JSON response"),
        }
    }

    fn client(fake: Arc<FakeTransport>) -> CibaUserApprovalClient {
        CibaUserApprovalClient::new(
            Url::parse("https://auth.example/").expect("issuer"),
            Zeroizing::new("applicant@example.invalid".to_owned()),
            Zeroizing::new("correct horse battery staple".to_owned()),
            fake,
        )
        .expect("client")
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
            ),
            Err(CibaUserApprovalError::InvalidIssuer)
        ));
        assert!(matches!(
            CibaUserApprovalClient::new(
                Url::parse("https://auth.example/not-an-origin").expect("URL"),
                Zeroizing::new("applicant@example.invalid".to_owned()),
                Zeroizing::new("password".to_owned()),
                fake,
            ),
            Err(CibaUserApprovalError::InvalidIssuer)
        ));
    }

    #[test]
    fn callback_parser_is_single_use_shape_and_token_fenced() {
        let token = b"0123456789abcdef0123456789abcdef";
        let request = concat!(
            "GET /ciba/approve?approval_token=0123456789abcdef0123456789abcdef",
            "&auth_req_id=request-1&action=allow HTTP/1.1\r\nHost: callback.example\r\n\r\n"
        );
        assert_eq!(
            parse_callback_request(request, "/ciba/approve", token),
            Some(("request-1".to_owned(), true))
        );
        assert!(parse_callback_request(
            "GET /ciba/approve?approval_token=wrong&auth_req_id=request-1&action=allow HTTP/1.1\r\n\r\n",
            "/ciba/approve",
            token,
        )
        .is_none());
        assert!(parse_callback_request(
            "GET /ciba/approve?approval_token=0123456789abcdef0123456789abcdef&auth_req_id=request-1&action=allow&extra=1 HTTP/1.1\r\n\r\n",
            "/ciba/approve",
            token,
        )
        .is_none());
    }
}
