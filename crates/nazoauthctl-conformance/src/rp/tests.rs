use super::*;

    #[test]
    fn plan_roles_are_exhaustive_and_do_not_relabel_op_plans() {
        assert_eq!(profile_modules(RpProfile::Basic).len(), 14);
        assert_eq!(profile_modules(RpProfile::Configuration).len(), 6);
        assert_eq!(profile_modules(RpProfile::Backchannel).len(), 8);
        assert_eq!(profile_modules(RpProfile::Backchannel)[0], LOGOUT_VALID);
        assert!(negative_module(UNSIGNED));
        assert!(!negative_module("oidcc-client-test"));
    }

    #[test]
    fn logout_form_extracts_only_expected_protocol_fields() {
        let html = r#"<body><form method="post" action="https://suite.example/test/a/alias/end_session_endpoint">
<input type="hidden" name="id_token_hint" value="header.payload.signature">
<input type="hidden" name="post_logout_redirect_uri" value="https://rp.example/ui/login"></form></body>"#;
        let (endpoint, hint, redirect) = parse_logout_form(html).unwrap();
        assert_eq!(endpoint.host_str(), Some("suite.example"));
        assert_eq!(hint, "header.payload.signature");
        assert_eq!(redirect, "https://rp.example/ui/login");
    }

    #[test]
    fn target_configuration_requires_separate_providers_and_same_origin_return() {
        let settings: RpSettings = serde_json::from_value(json!({
            "schema": 1, "client_id": "rp-client", "client_secret": "rp-secret",
            "basic": {"alias":"rp-basic", "provider_id":"rp-basic"},
            "configuration": {"alias":"rp-config", "provider_id":"rp-config"},
            "configuration_keys_provider_id": "rp-config-keys",
            "backchannel": {"alias":"rp-logout", "provider_id":"rp-logout"},
            "post_logout_redirect_uri": "https://rp.example/ui/login",
            "session_cookie_name":"nazo_session", "csrf_cookie_name":"nazo_csrf",
            "account":{"email":"rp@example.com", "password":"fixture-password"}
        }))
        .unwrap();
        assert!(
            settings
                .validate(&Origin::parse("https://rp.example").unwrap())
                .is_ok()
        );
        assert!(
            settings
                .validate(&Origin::parse("https://other.example").unwrap())
                .is_err()
        );
    }

use std::{collections::VecDeque, sync::Mutex};
use crate::TransportError;

const ACCOUNT: &str = "019c8ca2-30a6-7000-8000-00000000e202";

fn settings() -> RpSettings {
    serde_json::from_value(json!({
        "schema": 1, "client_id": "rp-client", "client_secret": "fixture-client-secret",
        "basic": {"alias":"rp-basic", "provider_id":"rp-basic"},
        "configuration": {"alias":"rp-config", "provider_id":"rp-config"},
        "configuration_keys_provider_id": "rp-config-keys",
        "backchannel": {"alias":"rp-logout", "provider_id":"rp-logout"},
        "post_logout_redirect_uri": "https://rp.example/live",
        "session_cookie_name":"nazo_session", "csrf_cookie_name":"nazo_csrf",
        "account":{"email":"rp@example.com", "password":"fixture-password"}
    })).unwrap()
}

struct Step {
    method: HttpMethod,
    url: String,
    response: HttpResponse,
}

struct Scripted(Mutex<VecDeque<Step>>);

impl Transport for Scripted {
    fn send(&self, request: HttpRequest, limit: usize) -> Result<HttpResponse, TransportError> {
        assert_eq!(limit, MAX_RP_HTTP_BYTES);
        let step = self.0.lock().unwrap().pop_front().expect("unexpected extra HTTP request");
        assert_eq!(request.method(), step.method);
        assert_eq!(request.url().as_str(), step.url);
        if request.url().path() == "/auth/login" {
            assert_eq!(request.header("content-type"), Some("application/json"));
            let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
            assert_eq!(body["email"], "rp@example.com");
            assert_eq!(body["password"], "fixture-password");
        }
        if request.url().path().starts_with("/auth/me/federation/links/") {
            assert!(request.header("cookie").unwrap().contains("nazo_session=session"));
            assert_eq!(request.body().unwrap(), b"csrf_token=csrf");
        }
        if request.url().path() == "/auth/logout" {
            assert_eq!(request.header("x-csrf-token"), Some("csrf"));
        }
        Ok(step.response)
    }
}

impl Scripted {
    fn new(steps: Vec<Step>) -> Self { Self(Mutex::new(steps.into())) }
    fn finished(&self) { assert!(self.0.lock().unwrap().is_empty()); }
}

fn step(method: HttpMethod, url: &str, status: u16, body: Value, headers: &[(&str, &str)]) -> Step {
    Step {
        method, url: url.to_owned(),
        response: HttpResponse {
            status,
            headers: headers.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect(),
            body: serde_json::to_vec(&body).unwrap().into(),
        },
    }
}

fn login_step(url: &str) -> Step {
    step(HttpMethod::Get, url, 200, json!({"csrf_token":"csrf", "expires_in":600, "mfa_required":false}), &[
        ("set-cookie", "nazo_session=session; Path=/; Secure; HttpOnly"),
        ("set-cookie", "nazo_csrf=csrf; Path=/; Secure"),
    ])
}

fn me(id: &str) -> Step {
    step(HttpMethod::Get, "https://rp.example/auth/me", 200, json!({"id":id,"mfa_required":false}), &[])
}

fn logout_steps() -> Vec<Step> {
    vec![
        step(HttpMethod::Post, "https://rp.example/auth/logout", 200, json!({"success":true}), &[
            ("set-cookie", "nazo_session=; Max-Age=0; Path=/"),
            ("set-cookie", "nazo_csrf=; Max-Age=0; Path=/"),
        ]),
        step(HttpMethod::Get, "https://rp.example/auth/me", 401, json!({"error":"login_required"}), &[]),
    ]
}

fn flow(provider: &str, callback: Step) -> Vec<Step> {
    vec![
        step(HttpMethod::Get, &format!("https://rp.example/auth/federation/{provider}/start"), 302, json!({}), &[
            ("location", "https://suite.example/authorize"),
        ]),
        step(HttpMethod::Get, "https://suite.example/authorize", 302, json!({}), &[
            ("location", &callback.url),
        ]),
        callback,
    ]
}

fn module(name: &str) -> ModuleDefinition {
    ModuleDefinition { test_name: name.to_owned(), variant: BTreeMap::new() }
}

#[test]
fn account_binding_uses_only_authenticated_production_endpoints() {
    let settings = settings();
    let mut login = login_step("https://rp.example/auth/login");
    login.method = HttpMethod::Post;
    let mut steps = vec![
        login, me(ACCOUNT),
        step(HttpMethod::Post, "https://rp.example/auth/me/federation/links/rp-basic/start", 302, json!({}), &[
            ("location", "https://suite.example/authorize"),
        ]),
        step(HttpMethod::Get, "https://suite.example/authorize", 302, json!({}), &[
            ("location", "https://rp.example/auth/federation/rp-basic/callback?code=opaque"),
        ]),
        step(HttpMethod::Get, "https://rp.example/auth/federation/rp-basic/callback?code=opaque", 200,
            json!({"linked":true,"provider_id":"rp-basic"}), &[]),
        me(ACCOUNT),
        step(HttpMethod::Get, "https://rp.example/auth/me/federation/links", 200, json!({"items":[{
            "id":"019c8ca2-30a6-7000-8000-00000000e203", "provider_id":"rp-basic",
        }]}), &[]),
    ];
    steps.extend(logout_steps());
    let http = Scripted::new(steps);
    assert_eq!(bind_account(&http, &Origin::parse("https://rp.example").unwrap(),
        &Origin::parse("https://suite.example").unwrap(), &settings, &settings.basic,
        &module("oidcc-client-test"), ACCOUNT).unwrap(), 200);
    http.finished();
}

#[test]
fn rotation_performs_both_logins_and_revokes_the_last_session() {
    let settings = settings();
    let callback = "https://rp.example/auth/federation/rp-config/callback?code=opaque";
    let mut steps = Vec::new();
    for _ in 0..2 {
        steps.extend(flow("rp-config", login_step(callback)));
        steps.push(me(ACCOUNT));
        steps.extend(logout_steps());
    }
    let http = Scripted::new(steps);
    assert_eq!(drive_module(&http, &Origin::parse("https://rp.example").unwrap(),
        &Origin::parse("https://suite.example").unwrap(), &settings, RpProfile::Configuration,
        &settings.configuration, &module("oidcc-client-test-signing-key-rotation"), ACCOUNT).unwrap(), 200);
    http.finished();
}

#[test]
fn positive_module_rejects_http_200_without_a_local_session() {
    let settings = settings();
    let http = Scripted::new(flow("rp-basic", step(HttpMethod::Get,
        "https://rp.example/auth/federation/rp-basic/callback?code=opaque", 200,
        json!({"csrf_token":"csrf","expires_in":600,"mfa_required":false}), &[])));
    assert!(drive_module(&http, &Origin::parse("https://rp.example").unwrap(),
        &Origin::parse("https://suite.example").unwrap(), &settings, RpProfile::Basic,
        &settings.basic, &module("oidcc-client-test"), ACCOUNT).is_err());
    http.finished();
}

#[test]
fn invalid_upstream_requires_a_rejected_callback_and_anonymous_local_profile() {
    let settings = settings();
    let mut steps = flow("rp-basic", step(HttpMethod::Get,
        "https://rp.example/auth/federation/rp-basic/callback?code=opaque", 401,
        json!({"error":"access_denied"}), &[]));
    steps.push(step(HttpMethod::Get, "https://rp.example/auth/me", 401, json!({"error":"login_required"}), &[]));
    let http = Scripted::new(steps);
    assert_eq!(drive_module(&http, &Origin::parse("https://rp.example").unwrap(),
        &Origin::parse("https://suite.example").unwrap(), &settings, RpProfile::Basic,
        &settings.basic, &module("oidcc-client-test-invalid-aud"), ACCOUNT).unwrap(), 401);
    http.finished();
}

#[test]
fn login_as_a_different_account_fails_and_still_logs_out() {
    let settings = settings();
    let mut steps = flow("rp-basic", login_step("https://rp.example/auth/federation/rp-basic/callback?code=opaque"));
    steps.push(me("019c8ca2-30a6-7000-8000-00000000e204"));
    steps.extend(logout_steps());
    let http = Scripted::new(steps);
    assert!(drive_module(&http, &Origin::parse("https://rp.example").unwrap(),
        &Origin::parse("https://suite.example").unwrap(), &settings, RpProfile::Basic,
        &settings.basic, &module("oidcc-client-test"), ACCOUNT).is_err());
    http.finished();
}

#[test]
fn logout_form_decodes_the_servers_escaped_url_attributes() {
    let html = r#"<form method="post" action="https://suite.example/end?a=1&amp;b=2">
<input type="hidden" name="id_token_hint" value="header.payload.signature">
<input type="hidden" name="post_logout_redirect_uri" value="https://rp.example/live?a=1&amp;b=2"></form>"#;
    let (action, _, return_uri) = parse_logout_form(html).unwrap();
    assert_eq!(action.as_str(), "https://suite.example/end?a=1&b=2");
    assert_eq!(return_uri, "https://rp.example/live?a=1&b=2");
}

#[test]
fn setup_http_failure_revokes_the_authenticated_session_before_returning() {
    let settings = settings();
    let target = Origin::parse("https://rp.example").unwrap();
    let suite_origin = Origin::parse("https://suite.example").unwrap();
    let mut login = login_step("https://rp.example/auth/login");
    login.method = HttpMethod::Post;
    let mut steps = vec![
        step(HttpMethod::Get, "https://rp.example/auth/federation/providers", 200,
            json!({"providers":settings.provider_ids().iter().map(|id| json!({"provider_id":id})).collect::<Vec<_>>()}), &[]),
        step(HttpMethod::Get, "https://suite.example/api/server", 200, json!({"version":"5.3.4"}), &[]),
        login, me(ACCOUNT),
        step(HttpMethod::Get, "https://rp.example/auth/me/federation/links", 503,
            json!({"error":"server_error"}), &[]),
    ];
    steps.extend(logout_steps());
    let http = std::sync::Arc::new(Scripted::new(steps));
    let suite = SuiteClient::with_transport(suite_origin, None, http.clone(), ClientConfig::default()).unwrap();
    assert!(run_with_transport(&suite, http.as_ref(), target, &settings,
        Path::new("unused-before-baseline"), Duration::from_secs(1), true, &RunControl::default()).is_err());
    http.finished();
}
