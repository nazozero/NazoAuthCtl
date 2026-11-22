//! Black-box OIDC RP conformance. The target is an already running NazoAuth
//! release, never an in-process facade or a database-backed test bridge.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use anyhow::{Context as _, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    ClientConfig, DeleteOutcome, HttpRequest, HttpResponse, HttpTransport, Origin, SuiteClient,
    Transport, client::ModuleDefinition, matrix::zeroize_json_value,
};
use nazoauthctl_runtime::secure_file;

const MAX_RP_HTTP_BYTES: usize = 1024 * 1024;
const MAX_RP_CONFIG_BYTES: usize = 8192;
const MAX_REDIRECT_HOPS: usize = 10;
const LOGOUT_VALID: &str = "oidcc-client-test-rp-backchannel-rpinitlogout";
const UNSIGNED: &str = "oidcc-client-test-idtoken-sig-none";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpSettings {
    schema: u32,
    client_id: String,
    client_secret: String,
    basic: RpProvider,
    configuration: RpProvider,
    configuration_keys_provider_id: String,
    backchannel: RpProvider,
    post_logout_redirect_uri: String,
    session_cookie_name: String,
    csrf_cookie_name: String,
}

impl Drop for RpSettings {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpProvider {
    alias: String,
    provider_id: String,
}

impl RpSettings {
    pub fn load(path: &Path, target: &Origin) -> anyhow::Result<Self> {
        let mut bytes =
            secure_file::read_bounded(path, MAX_RP_CONFIG_BYTES, true).map_err(|error| {
                anyhow::anyhow!("RP configuration must be a private regular file: {error:?}")
            })?;
        let parsed = serde_json::from_slice::<Self>(&bytes);
        bytes.zeroize();
        let settings = parsed.context("RP configuration is malformed")?;
        settings.validate(target)?;
        Ok(settings)
    }

    fn validate(&self, target: &Origin) -> anyhow::Result<()> {
        let providers = [&self.basic, &self.configuration, &self.backchannel];
        let configured = [
            self.basic.provider_id.as_str(),
            self.configuration.provider_id.as_str(),
            self.configuration_keys_provider_id.as_str(),
            self.backchannel.provider_id.as_str(),
        ];
        if self.schema != 1
            || self.client_id.is_empty()
            || self.client_secret.is_empty()
            || self.client_id.len() > 256
            || self.client_secret.len() > 512
            || self.session_cookie_name.is_empty()
            || self.csrf_cookie_name.is_empty()
            || configured.iter().any(|id| !valid_path_segment(id))
            || configured.into_iter().collect::<BTreeSet<_>>().len() != 4
            || providers
                .iter()
                .any(|provider| !valid_path_segment(&provider.alias))
            || providers
                .iter()
                .map(|provider| provider.alias.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != 3
        {
            bail!("RP configuration contains invalid or conflicting provider bindings");
        }
        let post = Url::parse(&self.post_logout_redirect_uri)?;
        if post.scheme() != "https"
            || post.origin().ascii_serialization() != target.as_str()
            || post.fragment().is_some()
        {
            bail!("RP post-logout return must be an existing HTTPS URL on the target origin");
        }
        Ok(())
    }
}

fn valid_path_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpProfile {
    Basic,
    Configuration,
    Backchannel,
}

impl RpProfile {
    fn name(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Configuration => "configuration",
            Self::Backchannel => "backchannel",
        }
    }

    fn plan(self) -> &'static str {
        match self {
            Self::Basic => "oidcc-client-basic-certification-test-plan",
            Self::Configuration => "oidcc-client-config-certification-test-plan",
            Self::Backchannel => "oidcc-client-back-channel-logout-rp-basic",
        }
    }
}

#[derive(Serialize)]
pub struct RpModuleReport {
    pub name: String,
    pub suite_module_id: String,
    pub suite_status: String,
    pub suite_result: Option<String>,
    pub observed_http_status: Option<u16>,
    pub application_pass: bool,
    pub application_error: Option<String>,
    pub raw_suite_log: Option<String>,
}

#[derive(Serialize)]
pub struct RpPlanReport {
    pub profile: &'static str,
    pub suite_plan_id: String,
    pub modules: Vec<RpModuleReport>,
    pub cleanup: &'static str,
}

#[derive(Serialize)]
pub struct RpReport {
    pub schema: u32,
    pub suite_origin: String,
    pub target_origin: String,
    pub plans: Vec<RpPlanReport>,
    pub success: bool,
    pub suite_pass: bool,
    pub blocked_preconditions: usize,
}

pub fn run(
    suite: &SuiteClient,
    target: Origin,
    settings: &RpSettings,
    evidence_dir: &Path,
    poll_timeout: Duration,
    delete_suite_plans: bool,
) -> anyhow::Result<RpReport> {
    let transport = HttpTransport::new(ClientConfig::default().timeout)?;
    // Use an existing public production endpoint to establish which RP
    // providers are enabled; no introspection of server internals.
    let providers = transport
        .send(
            HttpRequest::get(target.url("/auth/federation/providers")?),
            MAX_RP_HTTP_BYTES,
        )?
        .body
        .json::<Value>()?;
    let visible = providers["providers"]
        .as_array()
        .context("production RP provider list is unavailable")?;
    for id in [
        &settings.basic.provider_id,
        &settings.configuration.provider_id,
        &settings.configuration_keys_provider_id,
        &settings.backchannel.provider_id,
    ] {
        if !visible
            .iter()
            .any(|provider| provider["provider_id"] == *id)
        {
            bail!("required production RP provider is not enabled");
        }
    }
    let mut report = RpReport {
        schema: 1,
        suite_origin: suite.origin().to_string(),
        target_origin: target.to_string(),
        plans: Vec::new(),
        success: true,
        suite_pass: true,
        blocked_preconditions: 0,
    };
    for profile in [
        RpProfile::Basic,
        RpProfile::Configuration,
        RpProfile::Backchannel,
    ] {
        let provider = match profile {
            RpProfile::Basic => &settings.basic,
            RpProfile::Configuration => &settings.configuration,
            RpProfile::Backchannel => &settings.backchannel,
        };
        let mut config = plan_config(profile, settings, &target, provider);
        let variant = plan_variant(profile);
        let created = suite.create_plan(profile.plan(), &variant, &config);
        zeroize_json_value(&mut config);
        let plan = created?;
        let mut output = RpPlanReport {
            profile: profile.name(),
            suite_plan_id: plan.id.clone(),
            modules: Vec::new(),
            cleanup: "retained",
        };
        let plan_is_known = profile_modules(profile).len() == plan.modules.len()
            && plan
                .modules
                .iter()
                .all(|module| profile_modules(profile).contains(&module.test_name.as_str()));
        if !plan_is_known {
            report.success = false;
            report.suite_pass = false;
            output.cleanup = "retained-unknown-plan";
            report.plans.push(output);
            bail!(
                "OIDF Suite RP module set differs from the reviewed plan; plan retained for inspection"
            );
        }
        for (index, module) in plan.modules.iter().enumerate() {
            let instance = suite.create_module(&plan.id, module)?;
            let mut observed_http_status = None;
            let mut application_error = None;
            let mut application_pass = false;
            let mut ready = suite.wait_for_state(
                &instance.id,
                &["CONFIGURED", "WAITING", "FINISHED", "INTERRUPTED"],
                poll_timeout,
            )?;
            if ready["state"] == "CONFIGURED" {
                suite.start_module(&instance.id)?;
                ready = suite.wait_for_state(
                    &instance.id,
                    &["WAITING", "FINISHED", "INTERRUPTED"],
                    poll_timeout,
                )?;
            }
            if ready["state"] == "WAITING" {
                match drive_module(
                    &transport,
                    &target,
                    suite.origin(),
                    settings,
                    profile,
                    provider,
                    module,
                ) {
                    Ok(status) => {
                        observed_http_status = Some(status);
                        application_pass = true;
                    }
                    Err(error) => {
                        // No internal DB fallback or weakened session assertion.
                        application_error = Some(error.to_string());
                    }
                }
            } else {
                application_error =
                    Some("Suite module did not reach the browser-ready state".into());
            }
            if application_pass {
                let _ =
                    suite.wait_for_state(&instance.id, &["FINISHED", "INTERRUPTED"], poll_timeout);
            }
            let final_state = suite.module_info(&instance.id)?;
            let suite_status = final_state["status"]
                .as_str()
                .unwrap_or("INCOMPLETE")
                .to_owned();
            let suite_result = final_state["result"].as_str().map(str::to_owned);
            let expected = if module.test_name == UNSIGNED {
                "SKIPPED"
            } else {
                "PASSED"
            };
            let accepted = suite_status == "FINISHED"
                && suite_result.as_deref() == Some(expected)
                && application_pass;
            report.success &= accepted;
            report.suite_pass &=
                suite_status == "FINISHED" && suite_result.as_deref() == Some("PASSED");
            if !application_pass && observed_http_status == Some(401) {
                report.blocked_preconditions += 1;
            }
            let log = suite.module_log(&instance.id)?;
            let relative = format!("rp-{}-{:02}.json", profile.name(), index + 1);
            let bytes = serde_json::to_vec(&log)?;
            secure_file::write_atomic(&evidence_dir.join(&relative), &bytes, true).map_err(
                |error| anyhow::anyhow!("failed to save private RP Suite log: {error:?}"),
            )?;
            output.modules.push(RpModuleReport {
                name: module.test_name.clone(),
                suite_module_id: std::mem::take(&mut instance.id),
                suite_status,
                suite_result,
                observed_http_status,
                application_pass,
                application_error,
                raw_suite_log: Some(relative),
            });
        }
        if delete_suite_plans {
            output.cleanup = match suite.delete_plan(&plan.id)? {
                DeleteOutcome::Deleted | DeleteOutcome::AlreadyGone => "deleted",
                DeleteOutcome::Immutable => "immutable-retained",
            };
            if output.cleanup != "deleted" {
                report.success = false;
            }
        }
        report.plans.push(output);
    }
    secure_file::write_atomic(
        &evidence_dir.join("rp-report.json"),
        &serde_json::to_vec_pretty(&report)?,
        true,
    )
    .map_err(|error| anyhow::anyhow!("failed to save private RP report: {error:?}"))?;
    Ok(report)
}

fn plan_variant(profile: RpProfile) -> BTreeMap<String, String> {
    let mut variants = BTreeMap::from([
        ("client_registration".into(), "static_client".into()),
        ("request_type".into(), "plain_http_request".into()),
    ]);
    if profile != RpProfile::Basic {
        variants.insert("client_auth_type".into(), "client_secret_basic".into());
        variants.insert("response_mode".into(), "default".into());
    }
    variants
}

fn plan_config(
    profile: RpProfile,
    settings: &RpSettings,
    target: &Origin,
    provider: &RpProvider,
) -> Value {
    let callback = format!(
        "{}/auth/federation/{}/callback",
        target, provider.provider_id
    );
    let mut client = json!({
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "redirect_uri": callback,
        "id_token_signed_response_alg": "RS256",
    });
    if profile == RpProfile::Backchannel {
        client["backchannel_logout_uri"] = json!(format!(
            "{}/auth/federation/{}/backchannel-logout",
            target, provider.provider_id
        ));
        client["backchannel_logout_session_required"] = json!(true);
        client["post_logout_redirect_uri"] = json!(settings.post_logout_redirect_uri);
    }
    let mut config = json!({
        "alias": provider.alias,
        "description": format!("NazoAuthCtl black-box RP {}", profile.name()),
        "waitTimeoutSeconds": 5,
        "client": client,
    });
    if profile == RpProfile::Configuration {
        config["override"] = json!({
            "oidcc-client-test-discovery-jwks-uri-keys": {
                "client": {
                    "client_id": settings.client_id,
                    "client_secret": settings.client_secret,
                    "redirect_uri": format!("{}/auth/federation/{}/callback", target, settings.configuration_keys_provider_id),
                    "id_token_signed_response_alg": "RS256",
                }
            }
        });
    }
    config
}

fn profile_modules(profile: RpProfile) -> &'static [&'static str] {
    match profile {
        RpProfile::Basic => &[
            "oidcc-client-test",
            "oidcc-client-test-kid-absent-single-jwks",
            "oidcc-client-test-idtoken-sig-rs256",
            "oidcc-client-test-scope-userinfo-claims",
            "oidcc-client-test-client-secret-basic",
            "oidcc-client-test-invalid-iss",
            "oidcc-client-test-missing-sub",
            "oidcc-client-test-invalid-aud",
            "oidcc-client-test-missing-iat",
            "oidcc-client-test-invalid-sig-rs256",
            "oidcc-client-test-userinfo-invalid-sub",
            "oidcc-client-test-nonce-invalid",
            "oidcc-client-test-kid-absent-multiple-jwks",
            UNSIGNED,
        ],
        RpProfile::Configuration => &[
            "oidcc-client-test-discovery-openid-config",
            "oidcc-client-test-discovery-issuer-mismatch",
            "oidcc-client-test-signing-key-rotation",
            "oidcc-client-test-signing-key-rotation-just-before-signing",
            "oidcc-client-test-discovery-jwks-uri-keys",
            UNSIGNED,
        ],
        RpProfile::Backchannel => &[
            LOGOUT_VALID,
            "oidcc-client-test-rp-backchannel-rpinitlogout-alg-none",
            "oidcc-client-test-rp-backchannel-rpinitlogout-no-event",
            "oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss",
        ],
    }
}

fn negative_module(module: &str) -> bool {
    matches!(
        module,
        "oidcc-client-test-invalid-iss"
            | "oidcc-client-test-missing-sub"
            | "oidcc-client-test-invalid-aud"
            | "oidcc-client-test-missing-iat"
            | "oidcc-client-test-invalid-sig-rs256"
            | "oidcc-client-test-userinfo-invalid-sub"
            | "oidcc-client-test-nonce-invalid"
            | "oidcc-client-test-kid-absent-multiple-jwks"
            | UNSIGNED
    )
}

struct Browser<'a> {
    http: &'a HttpTransport,
    target: &'a Origin,
    suite: &'a Origin,
    cookies: BTreeMap<String, BTreeMap<String, Zeroizing<String>>>,
}

impl Browser<'_> {
    fn request(&mut self, url: Url, form: Option<String>) -> anyhow::Result<HttpResponse> {
        let origin = url.origin().ascii_serialization();
        if url.scheme() != "https"
            || (origin != self.target.as_str() && origin != self.suite.as_str())
        {
            bail!("RP test redirect escaped the two explicitly configured HTTPS origins");
        }
        let mut request = match form {
            Some(body) => HttpRequest::post_form(url, body),
            None => HttpRequest::get(url),
        };
        if let Some(jar) = self.cookies.get(&origin) {
            let value = jar
                .iter()
                .map(|(name, value)| format!("{name}={}", value.as_str()))
                .collect::<Vec<_>>()
                .join("; ");
            if !value.is_empty() {
                request = request.with_header("cookie", value);
            }
        }
        let response = self.http.send(request, MAX_RP_HTTP_BYTES)?;
        let jar = self.cookies.entry(origin).or_default();
        for cookie in response
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        {
            let pair = cookie.1.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                if valid_path_segment(name) {
                    if value.is_empty() {
                        jar.remove(name);
                    } else {
                        jar.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
                    }
                }
            }
        }
        Ok(response)
    }

    fn get(&mut self, url: Url) -> anyhow::Result<HttpResponse> {
        self.request(url, None)
    }

    fn post(&mut self, url: Url, form: String) -> anyhow::Result<HttpResponse> {
        self.request(url, Some(form))
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .get(self.target.as_str())?
            .get(name)
            .map(|value| value.as_str())
    }

    fn follow(&mut self, mut url: Url) -> anyhow::Result<(Url, HttpResponse)> {
        for _ in 0..MAX_REDIRECT_HOPS {
            let response = self.get(url.clone())?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok((url, response));
            }
            let location = response
                .header("location")
                .context("RP redirect missing Location")?;
            url = url.join(location)?;
        }
        bail!("RP flow exceeded the redirect budget")
    }
}

fn drive_module(
    http: &HttpTransport,
    target: &Origin,
    suite: &Origin,
    settings: &RpSettings,
    profile: RpProfile,
    provider: &RpProvider,
    module: &ModuleDefinition,
) -> anyhow::Result<u16> {
    let provider_id = if module.test_name == "oidcc-client-test-discovery-jwks-uri-keys" {
        settings.configuration_keys_provider_id.as_str()
    } else {
        &provider.provider_id
    };
    let start_url = target.url(&format!("/auth/federation/{provider_id}/start"))?;
    let callback = target.url(&format!("/auth/federation/{provider_id}/callback"))?;
    let mut browser = Browser {
        http,
        target,
        suite,
        cookies: BTreeMap::new(),
    };
    if module.test_name == "oidcc-client-test-discovery-openid-config"
        || module.test_name == "oidcc-client-test-discovery-issuer-mismatch"
    {
        let response = browser.get(start_url)?;
        if module.test_name == "oidcc-client-test-discovery-issuer-mismatch" {
            if response.status != 503 || response.header("location").is_some() {
                bail!("issuer mismatch did not reject discovery before authorization");
            }
        } else {
            let redirect = response
                .header("location")
                .context("discovery did not redirect")?;
            let url = Url::parse(redirect)?;
            if response.status != 302
                || url.origin().ascii_serialization() != suite.as_str()
                || !url.path().ends_with("/authorize")
            {
                bail!("valid discovery did not reach the Suite authorization endpoint");
            }
        }
        return Ok(response.status);
    }
    let (final_url, response) = browser.follow(start_url)?;
    let body = response
        .body
        .json::<Value>()
        .context("RP callback was not JSON")?;
    if final_url.origin().ascii_serialization() != target.as_str()
        || final_url.path() != callback.path()
    {
        bail!("RP flow did not finish at the configured callback");
    }
    if negative_module(&module.test_name) {
        if response.status != 401
            || body["error"] != "access_denied"
            || browser.cookie(&settings.session_cookie_name).is_some()
        {
            bail!("invalid upstream identity was accepted or returned an unexpected status");
        }
        return Ok(response.status);
    }
    let csrf = body["csrf_token"]
        .as_str()
        .context("RP callback has no CSRF token")?;
    if response.status != 200
        || body["mfa_required"] != false
        || body["expires_in"].as_i64().is_none_or(|value| value <= 0)
        || browser.cookie(&settings.session_cookie_name).is_none()
        || browser.cookie(&settings.csrf_cookie_name) != Some(csrf)
    {
        bail!("valid upstream identity did not establish an authenticated local session");
    }
    if profile == RpProfile::Backchannel {
        drive_logout(
            &mut browser,
            target,
            suite,
            settings,
            provider,
            &module.test_name,
            csrf,
        )?;
    }
    Ok(response.status)
}

fn drive_logout(
    browser: &mut Browser<'_>,
    target: &Origin,
    suite: &Origin,
    settings: &RpSettings,
    provider: &RpProvider,
    module: &str,
    csrf: &str,
) -> anyhow::Result<()> {
    let status_url = target.url("/auth/me")?;
    let endpoint = target.url(&format!("/auth/federation/{}/logout", provider.provider_id))?;
    if browser.get(status_url.clone())?.status != 200 {
        bail!("RP session was not authenticated before logout");
    }
    if browser.post(endpoint.clone(), String::new())?.status != 400 {
        bail!("RP-initiated logout accepted a missing CSRF token");
    }
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", csrf)
        .finish();
    let intent = browser.post(endpoint, body)?;
    if intent.status != 200 || intent.header("cache-control") != Some("no-store") {
        bail!("RP did not return a non-cacheable upstream logout form");
    }
    let html_body = intent.body.contiguous();
    let html = std::str::from_utf8(html_body.as_ref())?;
    let (action, hint, return_uri) = parse_logout_form(html)?;
    if action.origin().ascii_serialization() != suite.as_str()
        || return_uri != settings.post_logout_redirect_uri
    {
        bail!("RP logout form did not target the registered Suite OP and callback");
    }
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", &hint)
        .append_pair("post_logout_redirect_uri", &return_uri)
        .finish();
    let op_response = browser.post(action.clone(), form)?;
    let redirect = op_response
        .header("location")
        .context("Suite logout did not redirect")?;
    let url = action.join(redirect)?;
    if url.as_str() != return_uri {
        bail!("Suite logout did not return to the registered RP URI");
    }
    let _ = browser.get(url)?;
    let expected = if module == LOGOUT_VALID { 401 } else { 200 };
    if browser.get(status_url)?.status != expected {
        bail!("RP session state did not match the verified Logout Token outcome");
    }
    Ok(())
}

fn parse_logout_form(html: &str) -> anyhow::Result<(Url, String, String)> {
    let action = Regex::new(r#"<form method="post" action="([^"]+)""#)?
        .captures(html)
        .and_then(|c| c.get(1))
        .context("upstream logout form is missing")?;
    let hidden = Regex::new(r#"<input type="hidden" name="([^"]+)" value="([^"]*)""#)?;
    let mut values = BTreeMap::new();
    for pair in hidden.captures_iter(html) {
        values.insert(pair[1].to_owned(), pair[2].to_owned());
    }
    let hint = values.remove("id_token_hint").context("no ID Token hint")?;
    let return_uri = values
        .remove("post_logout_redirect_uri")
        .context("no return URI")?;
    if hint.is_empty() {
        bail!("empty upstream logout ID Token hint");
    }
    Ok((Url::parse(action.as_str())?, hint, return_uri))
}

#[cfg(test)]
mod tests {
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
            "session_cookie_name":"nazo_session", "csrf_cookie_name":"nazo_csrf"
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
}
