use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

use crate::credentials::BearerToken;
use crate::matrix::zeroize_json_value;
use crate::origin::{Origin, OriginError};
#[cfg(test)]
use crate::transport::HttpResponse;
use crate::transport::{HttpMethod, HttpRequest, Transport, TransportError};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS: usize = 3;
const MAX_SUITE_LONG_POLL_MS: u128 = 30_000;
const MAX_SUITE_LONG_POLL_HEADROOM_MS: u128 = 5_000;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub max_log_response_bytes: usize,
    pub max_redirects: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_log_response_bytes: DEFAULT_MAX_LOG_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }
}

#[derive(Clone)]
pub struct SuiteClient {
    origin: Origin,
    token: Option<BearerToken>,
    transport: Arc<dyn Transport>,
    config: ClientConfig,
}

impl SuiteClient {
    pub fn new(
        origin: Origin,
        token: BearerToken,
        config: ClientConfig,
    ) -> Result<Self, SuiteClientError> {
        let transport = crate::transport::HttpTransport::new(config.timeout)?;
        Self::with_transport(origin, Some(token), Arc::new(transport), config)
    }

    pub fn with_transport(
        origin: Origin,
        token: Option<BearerToken>,
        transport: Arc<dyn Transport>,
        config: ClientConfig,
    ) -> Result<Self, SuiteClientError> {
        if config.max_response_bytes == 0
            || config.max_log_response_bytes == 0
            || config.max_redirects > DEFAULT_MAX_REDIRECTS
            || config.timeout.is_zero()
        {
            return Err(SuiteClientError::InvalidConfiguration);
        }
        Ok(Self {
            origin,
            token,
            transport,
            config,
        })
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn probe_auth(&self) -> Result<AuthProbe, SuiteClientError> {
        let unauthenticated = self.request_json(
            HttpMethod::Get,
            "/api/plan",
            &[("start", "0"), ("length", "1")],
            None,
            false,
            self.config.max_response_bytes,
        )?;
        if unauthenticated.status != 401 {
            return Err(SuiteClientError::AuthBoundary);
        }
        let authenticated = self.request_json(
            HttpMethod::Get,
            "/api/plan",
            &[("start", "0"), ("length", "1")],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        if authenticated.status != 200 || !authenticated.body.is_object() {
            return Err(SuiteClientError::AuthBoundary);
        }
        Ok(AuthProbe {
            unauthenticated_status: unauthenticated.status,
            authenticated_status: authenticated.status,
        })
    }

    pub fn create_plan(
        &self,
        plan_name: &str,
        variant: &BTreeMap<String, String>,
        config: &Value,
    ) -> Result<PlanCreated, SuiteClientError> {
        if plan_name.trim().is_empty() || !config.is_object() {
            return Err(SuiteClientError::InvalidInput);
        }
        let variant_json =
            serde_json::to_string(variant).map_err(|_| SuiteClientError::InvalidInput)?;
        let response = self.request_json(
            HttpMethod::Post,
            "/api/plan",
            &[("planName", plan_name), ("variant", variant_json.as_str())],
            Some(config),
            true,
            self.config.max_response_bytes,
        )?;
        if response.status != 201 {
            return Err(SuiteClientError::HttpStatus(response.status));
        }
        parse_plan_created(response.body)
    }

    pub fn create_module(
        &self,
        plan_id: &str,
        module: &ModuleDefinition,
    ) -> Result<ModuleInstance, SuiteClientError> {
        if plan_id.is_empty() || module.test_name.is_empty() {
            return Err(SuiteClientError::InvalidInput);
        }
        let variant_json = (!module.variant.is_empty())
            .then(|| serde_json::to_string(&module.variant))
            .transpose()
            .map_err(|_| SuiteClientError::InvalidInput)?;
        let mut query = vec![("test", module.test_name.as_str()), ("plan", plan_id)];
        if let Some(variant) = variant_json.as_deref() {
            query.push(("variant", variant));
        }
        let response = self.request_json(
            HttpMethod::Post,
            "/api/runner",
            &query,
            None,
            true,
            self.config.max_response_bytes,
        )?;
        if response.status != 201 {
            return Err(SuiteClientError::HttpStatus(response.status));
        }
        let object = response
            .body
            .as_object()
            .ok_or(SuiteClientError::MalformedResponse)?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SuiteClientError::MalformedResponse)?;
        Ok(ModuleInstance {
            id: id.to_owned(),
            raw: response.body,
        })
    }

    pub fn start_module(&self, module_id: &str) -> Result<Value, SuiteClientError> {
        if module_id.is_empty() {
            return Err(SuiteClientError::InvalidInput);
        }
        let response = self.request_json(
            HttpMethod::Post,
            &format!("/api/runner/{module_id}"),
            &[],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        if response.status != 200 {
            return Err(SuiteClientError::HttpStatus(response.status));
        }
        Ok(response.body)
    }

    pub fn wait_for_state(
        &self,
        module_id: &str,
        states: &[&str],
        timeout: Duration,
    ) -> Result<Value, SuiteClientError> {
        if module_id.is_empty() || states.is_empty() || timeout.is_zero() {
            return Err(SuiteClientError::InvalidInput);
        }
        let deadline = Instant::now() + timeout;
        let state_string = states.join(",");
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SuiteClientError::Timeout);
            }
            let call_ms = wait_state_call_timeout_ms(remaining, self.config.timeout).to_string();
            let response = self.request_json(
                HttpMethod::Get,
                &format!("/api/runner/{module_id}/wait-state"),
                &[
                    ("states", state_string.as_str()),
                    ("timeoutMs", call_ms.as_str()),
                ],
                None,
                true,
                self.config.max_response_bytes,
            )?;
            if response.status == 404 {
                return Err(SuiteClientError::HttpStatus(404));
            }
            if response.status != 200 {
                return Err(SuiteClientError::HttpStatus(response.status));
            }
            if response.body.get("timeout").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            if response.body.get("state").and_then(Value::as_str).is_none() {
                return Err(SuiteClientError::MalformedResponse);
            }
            return Ok(response.body);
        }
    }

    pub fn module_info(&self, module_id: &str) -> Result<Value, SuiteClientError> {
        let response = self.request_json(
            HttpMethod::Get,
            &format!("/api/info/{module_id}"),
            &[],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        if response.status != 200 || !response.body.is_object() {
            return Err(if response.status == 200 {
                SuiteClientError::MalformedResponse
            } else {
                SuiteClientError::HttpStatus(response.status)
            });
        }
        Ok(response.body)
    }

    /// Fetch the Suite runner document for a WAITING module.  The runner
    /// document is distinct from `/api/info/{id}` and carries the authoritative
    /// `exposed` and `browser` fields consumed by the native OpenID4VC drivers.
    pub fn runner_info(&self, module_id: &str) -> Result<Value, SuiteClientError> {
        if module_id.is_empty()
            || module_id.len() > 256
            || module_id == "."
            || module_id == ".."
            || module_id.chars().any(|character| {
                character.is_control()
                    || !matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.')
            })
        {
            return Err(SuiteClientError::InvalidInput);
        }
        let response = self.request_json(
            HttpMethod::Get,
            &format!("/api/runner/{module_id}"),
            &[],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        if response.status != 200 || !response.body.is_object() {
            return Err(if response.status == 200 {
                SuiteClientError::MalformedResponse
            } else {
                SuiteClientError::HttpStatus(response.status)
            });
        }
        Ok(response.body)
    }

    pub fn module_log(&self, module_id: &str) -> Result<Value, SuiteClientError> {
        let response = self.request_json(
            HttpMethod::Get,
            &format!("/api/log/{module_id}"),
            &[],
            None,
            true,
            self.config.max_log_response_bytes,
        )?;
        if response.status != 200 || !response.body.is_array() {
            return Err(if response.status == 200 {
                SuiteClientError::MalformedResponse
            } else {
                SuiteClientError::HttpStatus(response.status)
            });
        }
        Ok(response.body)
    }

    pub fn cancel_module(&self, module_id: &str) -> Result<CancelOutcome, SuiteClientError> {
        let response = self.request_json(
            HttpMethod::Delete,
            &format!("/api/runner/{module_id}"),
            &[],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        match response.status {
            200 => Ok(CancelOutcome::Cancelled),
            404 => Ok(CancelOutcome::AlreadyGone),
            500 if is_finalisation_race(&response.body) => Ok(CancelOutcome::AlreadyFinalised),
            status => Err(SuiteClientError::HttpStatus(status)),
        }
    }

    pub fn delete_plan(&self, plan_id: &str) -> Result<DeleteOutcome, SuiteClientError> {
        let response = self.request_json(
            HttpMethod::Delete,
            &format!("/api/plan/{plan_id}"),
            &[],
            None,
            true,
            self.config.max_response_bytes,
        )?;
        match response.status {
            200 | 204 => Ok(DeleteOutcome::Deleted),
            404 => Ok(DeleteOutcome::AlreadyGone),
            405 => Ok(DeleteOutcome::Immutable),
            status => Err(SuiteClientError::HttpStatus(status)),
        }
    }

    fn request_json(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        authenticated: bool,
        max_response_bytes: usize,
    ) -> Result<RawResponse, SuiteClientError> {
        let mut url = self.origin.url(path)?;
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        if !same_origin(&self.origin, &url) {
            return Err(SuiteClientError::CrossOriginRedirect);
        }
        let body_bytes = body
            .map(|value| serde_json::to_vec(value).map_err(|_| SuiteClientError::InvalidInput))
            .transpose()?;
        let mut headers = vec![("Accept".to_owned(), "application/json".to_owned())];
        if body_bytes.is_some() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        if authenticated {
            let token = self.token.as_ref().ok_or(SuiteClientError::MissingToken)?;
            headers.push((
                "Authorization".to_owned(),
                format!("Bearer {}", token.as_str()),
            ));
        }
        let mut redirects = 0;
        loop {
            let request = HttpRequest {
                method,
                url: url.clone(),
                headers: headers.clone(),
                body: body_bytes.clone(),
            };
            let response = self.transport.send(request, max_response_bytes)?;
            if response.body.len() > max_response_bytes {
                return Err(SuiteClientError::Transport(TransportError::Oversize));
            }
            if (300..400).contains(&response.status) {
                let location = response
                    .header("location")
                    .ok_or(SuiteClientError::Redirect)?;
                if redirects >= self.config.max_redirects {
                    return Err(SuiteClientError::Redirect);
                }
                let redirected = url.join(location).map_err(|_| SuiteClientError::Redirect)?;
                if !same_origin(&self.origin, &redirected) {
                    return Err(SuiteClientError::CrossOriginRedirect);
                }
                url = redirected;
                redirects += 1;
                continue;
            }
            let body = if response.body.is_empty() {
                Value::Null
            } else if (200..300).contains(&response.status) {
                serde_json::from_slice(&response.body)
                    .map_err(|_| SuiteClientError::MalformedResponse)?
            } else {
                // Error pages are not part of the machine-readable contract;
                // preserve only the status and never echo their body.
                serde_json::from_slice(&response.body).unwrap_or(Value::Null)
            };
            return Ok(RawResponse {
                status: response.status,
                body,
            });
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthProbe {
    pub unauthenticated_status: u16,
    pub authenticated_status: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ModuleDefinition {
    #[serde(rename = "testModule")]
    pub test_name: String,
    /// The Suite definition is normalized to a sorted map at the response
    /// boundary. This gives module creation, local automation, and reports
    /// one exact identity even when Suite JSON object key order differs.
    #[serde(
        default,
        deserialize_with = "deserialize_module_variant",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub variant: BTreeMap<String, String>,
    #[serde(skip)]
    pub raw: Value,
}

impl Drop for ModuleDefinition {
    fn drop(&mut self) {
        for (mut key, mut value) in std::mem::take(&mut self.variant) {
            key.zeroize();
            value.zeroize();
        }
        zeroize_json_value(&mut self.raw);
    }
}

fn deserialize_module_variant<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<BTreeMap<String, String>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PlanCreated {
    pub id: String,
    pub name: String,
    pub modules: Vec<ModuleDefinition>,
    #[serde(skip)]
    pub raw: Value,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ModuleInstance {
    pub id: String,
    #[serde(skip)]
    pub raw: Value,
}

impl Drop for ModuleInstance {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.raw);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CancelOutcome {
    Cancelled,
    AlreadyGone,
    AlreadyFinalised,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeleteOutcome {
    Deleted,
    AlreadyGone,
    Immutable,
}

#[derive(Clone)]
struct RawResponse {
    status: u16,
    body: Value,
}

#[derive(Debug, Error)]
pub enum SuiteClientError {
    #[error("origin validation failed")]
    Origin(#[from] OriginError),
    #[error("HTTP transport failed")]
    Transport(#[from] TransportError),
    #[error("HTTP response status {0}")]
    HttpStatus(u16),
    #[error("Suite authentication boundary failed")]
    AuthBoundary,
    #[error("Suite bearer token is required")]
    MissingToken,
    #[error("Suite response is malformed JSON")]
    MalformedResponse,
    #[error("Suite redirected the request")]
    Redirect,
    #[error("Suite redirected across origins")]
    CrossOriginRedirect,
    #[error("Suite request timed out")]
    Timeout,
    #[error("invalid Suite request input")]
    InvalidInput,
    #[error("invalid Suite client configuration")]
    InvalidConfiguration,
}

fn parse_plan_created(body: Value) -> Result<PlanCreated, SuiteClientError> {
    let object = body
        .as_object()
        .ok_or(SuiteClientError::MalformedResponse)?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(SuiteClientError::MalformedResponse)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or(SuiteClientError::MalformedResponse)?;
    let modules = object
        .get("modules")
        .and_then(Value::as_array)
        .ok_or(SuiteClientError::MalformedResponse)?;
    let mut parsed = Vec::with_capacity(modules.len());
    for raw in modules {
        let module = raw.as_object().ok_or(SuiteClientError::MalformedResponse)?;
        let test_name = module
            .get("testModule")
            .and_then(Value::as_str)
            .ok_or(SuiteClientError::MalformedResponse)?;
        let variant = match module.get("variant") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(entries)) => entries
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_owned()))
                        .ok_or(SuiteClientError::MalformedResponse)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
            Some(_) => return Err(SuiteClientError::MalformedResponse),
        };
        parsed.push(ModuleDefinition {
            test_name: test_name.to_owned(),
            variant,
            raw: raw.clone(),
        });
    }
    Ok(PlanCreated {
        id: id.to_owned(),
        name: name.to_owned(),
        modules: parsed,
        raw: body,
    })
}

fn is_finalisation_race(value: &Value) -> bool {
    let text = serde_json::to_string(value).unwrap_or_default();
    text.contains("runInBackground called after runFinalisationTaskInBackground()")
}

fn same_origin(expected: &Origin, actual: &Url) -> bool {
    let Some(host) = actual.host_str() else {
        return false;
    };
    if actual.scheme() != "https" || !actual.username().is_empty() || actual.password().is_some() {
        return false;
    }
    let mut authority = host.to_owned();
    if host.contains(':') {
        authority = format!("[{host}]");
    }
    if let Some(port) = actual.port()
        && port != 443
    {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    expected.as_str() == format!("https://{authority}")
}

fn wait_state_call_timeout_ms(remaining: Duration, transport_timeout: Duration) -> u128 {
    let transport_ms = transport_timeout.as_millis().max(1);
    // The Suite's wait-state timeout is a server-side long poll. It must finish
    // before the HTTP client's own deadline; using the same 30-second value for
    // both creates a deterministic race whenever a module legitimately runs
    // for at least one poll interval.
    let headroom_ms = (transport_ms / 6).clamp(1, MAX_SUITE_LONG_POLL_HEADROOM_MS);
    let server_budget_ms = transport_ms.saturating_sub(headroom_ms).max(1);
    remaining
        .as_millis()
        .clamp(1, server_budget_ms.min(MAX_SUITE_LONG_POLL_MS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportError;
    use std::sync::{Arc, Mutex};

    struct Noop;
    impl Transport for Noop {
        fn send(&self, _request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            Ok(HttpResponse {
                status: 201,
                headers: vec![],
                body: b"{}".to_vec(),
            })
        }
    }

    #[test]
    fn wait_state_long_poll_finishes_before_the_transport_deadline() {
        assert_eq!(
            wait_state_call_timeout_ms(Duration::from_secs(60), Duration::from_secs(30)),
            25_000
        );
        assert_eq!(
            wait_state_call_timeout_ms(Duration::from_secs(3), Duration::from_secs(30)),
            3_000
        );
        assert_eq!(
            wait_state_call_timeout_ms(Duration::from_secs(60), Duration::from_secs(1)),
            834
        );
    }

    #[test]
    fn malformed_plan_response_is_rejected_without_body_echo() {
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("secret-token").expect("token")),
            Arc::new(Noop),
            ClientConfig::default(),
        )
        .expect("client");
        let error = match client.create_plan("plan", &BTreeMap::new(), &serde_json::json!({})) {
            Ok(_) => panic!("malformed plan response was accepted"),
            Err(error) => error,
        };
        assert!(!error.to_string().contains("suite.example"));
    }

    struct Capture {
        request: Mutex<Option<HttpRequest>>,
        response: HttpResponse,
    }

    impl Transport for Capture {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            *self.request.lock().expect("lock") = Some(request);
            Ok(HttpResponse {
                status: self.response.status,
                headers: self.response.headers.clone(),
                body: self.response.body.clone(),
            })
        }
    }

    #[test]
    fn bearer_is_header_only_and_oversize_is_rejected() {
        let capture = Arc::new(Capture {
            request: Mutex::new(None),
            response: HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![b'{'; 32],
            },
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("secret-token").expect("token")),
            capture.clone(),
            ClientConfig {
                max_response_bytes: 8,
                ..ClientConfig::default()
            },
        )
        .expect("client");
        let error = client.probe_auth().unwrap_err();
        assert!(matches!(
            error,
            SuiteClientError::Transport(TransportError::Oversize)
        ));
    }

    struct AuthCapture {
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl Transport for AuthCapture {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let mut requests = self.requests.lock().expect("lock");
            let authenticated = !requests.is_empty();
            requests.push(request);
            Ok(HttpResponse {
                status: if authenticated { 200 } else { 401 },
                headers: vec![],
                body: b"{}".to_vec(),
            })
        }
    }

    #[test]
    fn bearer_never_enters_url_or_error() {
        let capture = Arc::new(AuthCapture {
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("secret-token").expect("token")),
            capture.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        client.probe_auth().expect("auth probe");
        let requests = capture.requests.lock().expect("lock");
        let authenticated = requests.get(1).expect("authenticated request");
        assert_eq!(
            authenticated.header("authorization"),
            Some("Bearer secret-token")
        );
        assert!(!authenticated.url().as_str().contains("secret-token"));
    }

    #[test]
    fn plan_definition_variant_is_a_canonical_string_map_or_rejected() {
        let created = parse_plan_created(serde_json::json!({
            "id": "plan",
            "name": "plan",
            "modules": [
                {"testModule": "missing"},
                {"testModule": "null", "variant": null},
                {"testModule": "ordered", "variant": {"b": "two", "a": "one"}}
            ]
        }))
        .expect("valid definition");
        assert!(created.modules[0].variant.is_empty());
        assert!(created.modules[1].variant.is_empty());
        assert_eq!(
            created.modules[2].variant,
            BTreeMap::from([
                ("a".to_owned(), "one".to_owned()),
                ("b".to_owned(), "two".to_owned())
            ])
        );

        for variant in [
            serde_json::json!(["not", "an object"]),
            serde_json::json!({"key": 1}),
            serde_json::json!(true),
        ] {
            assert!(matches!(
                parse_plan_created(serde_json::json!({
                    "id": "plan",
                    "name": "plan",
                    "modules": [{"testModule": "invalid", "variant": variant}]
                })),
                Err(SuiteClientError::MalformedResponse)
            ));
        }
    }
}
