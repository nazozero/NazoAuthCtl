//! Black-box OIDC RP conformance. The target is an already running NazoAuth
//! release, never an in-process facade or a database-backed test bridge.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use regex::Regex;

mod recovery;
use recovery::Recovery;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    ClientConfig, HttpMethod, HttpRequest, HttpResponse, HttpTransport, Origin, RunControl, SuiteClient, SuiteClientError,
    Transport, client::ModuleDefinition, matrix::zeroize_json_value, recover_suite_resources,
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
    account: RpAccount,
}

impl Drop for RpSettings {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.account.password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpAccount {
    email: String,
    password: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Link {
    id: String,
    provider_id: String,
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
            || self.account.email.is_empty()
            || self.account.email.len() > 254
            || self.account.password.is_empty()
            || self.account.password.len() > 1024
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
        if !target.same_origin_url(&post)
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
    pub setup: Vec<RpModuleReport>,
    pub modules: Vec<RpModuleReport>,
    pub cleanup: &'static str,
}

#[derive(Serialize)]
pub struct RpReport {
    pub schema: u32,
    pub suite_origin: String,
    pub target_origin: String,
    pub suite_runtime: Value,
    pub errors: Vec<String>,
    pub cleanup_complete: bool,
    pub plans: Vec<RpPlanReport>,
    pub success: bool,
    pub suite_pass: bool,
    pub failed_application_assertions: usize,
}

/// Run the official RP plans against public production endpoints. The caller
/// holds the deployment orchestration lock for the full run and recovery.
pub fn run(
    suite: &SuiteClient,
    target: Origin,
    settings: &RpSettings,
    evidence_dir: &Path,
    poll_timeout: Duration,
    delete_suite_plans: bool,
    control: &RunControl,
) -> anyhow::Result<RpReport> {
    let transport = HttpTransport::new(ClientConfig::default().timeout)?;
    run_with_transport(
        suite, &transport, target, settings, evidence_dir, poll_timeout, delete_suite_plans, control,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with_transport(
    suite: &SuiteClient,
    transport: &dyn Transport,
    target: Origin,
    settings: &RpSettings,
    evidence_dir: &Path,
    poll_timeout: Duration,
    delete_suite_plans: bool,
    control: &RunControl,
) -> anyhow::Result<RpReport> {
    if control.is_interrupted() { bail!("RP run interrupted"); }
    settings.validate(&target)?;
    let response = transport.send(
        HttpRequest::get(target.url("/auth/federation/providers")?), MAX_RP_HTTP_BYTES,
    )?;
    if response.status != 200 {
        bail!("production RP provider list is unavailable");
    }
    let providers = response.body.json::<Value>()?;
    let visible = providers["providers"].as_array()
        .context("production RP provider list is unavailable")?;
    let provider_ids = settings.provider_ids();
    for id in &provider_ids {
        if !visible.iter().any(|provider| provider["provider_id"] == *id) {
            bail!("required production RP provider is not enabled");
        }
    }
    let suite_runtime = suite.server_info()?;
    let mut account = Browser::new(transport, &target, suite.origin());
    let prepared = (|| -> anyhow::Result<_> {
        let account_id = account.login(settings)?;
        let baseline_links = account.links()?;
        let recovery = Recovery::create(
            evidence_dir, suite.origin(), &target, account_id.clone(), baseline_links, provider_ids,
        )?;
        let report = RpReport {
            schema: 1,
            suite_origin: suite.origin().to_string(),
            target_origin: target.to_string(),
            suite_runtime,
            plans: Vec::new(),
            errors: Vec::new(),
            success: false,
            suite_pass: false,
            failed_application_assertions: 0,
            cleanup_complete: false,
        };
        save_report(evidence_dir, &report)?;
        Ok((account_id, recovery, report))
    })();
    let (account_id, mut recovery, mut report) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Err(logout) = account.logout(settings) {
                bail!("RP setup failed: {error}; account logout also failed: {logout}");
            }
            return Err(error);
        }
    };
    let result = execute_plans(
        suite, transport, &target, settings, evidence_dir, poll_timeout,
        &account_id, control, &mut recovery, &mut report,
    );
    if let Err(error) = result {
        report.errors.push(error.to_string());
    }
    // Account cleanup remains possible if the Suite fails. Only new links in
    // the dedicated account's recorded provider scope belong to this run.
    let links_cleanup = clean_links(&mut account, &recovery, settings);
    let logout = account.logout(settings);
    let suite_cleanup = settle_suite(suite, &mut recovery, delete_suite_plans, poll_timeout);
    report.cleanup_complete = links_cleanup.is_ok() && logout.is_ok() && suite_cleanup.is_ok();
    for (name, result) in [("account", links_cleanup), ("logout", logout), ("Suite", suite_cleanup)] {
        if let Err(error) = result { report.errors.push(format!("RP {name} cleanup: {error}")); }
    }
    report.failed_application_assertions = report.plans.iter()
        .flat_map(|plan| &plan.modules).filter(|module| !module.application_pass).count();
    let modules = report.plans.iter().flat_map(|plan| &plan.modules).collect::<Vec<_>>();
    report.suite_pass = modules.len() == 28 && modules.iter().all(|module| {
        module.suite_status == "FINISHED" && module.suite_result.as_deref() == Some("PASSED")
    });
    report.success = report.errors.is_empty() && modules.len() == 28
        && modules.iter().all(|module| module.accepted());
    if report.cleanup_complete {
        // The ownership receipt survives both process exit and retained Suite
        // records. Failed assertion evidence is retained without claiming PASS.
        match recovery.settle(!delete_suite_plans) {
            Ok(()) => {
                for plan in &mut report.plans {
                    plan.cleanup = if delete_suite_plans { "deleted" } else { "retained" };
                }
            }
            Err(error) => {
                report.cleanup_complete = false;
                report.success = false;
                report.errors.push(format!("RP ownership receipt: {error}"));
            }
        }
    }
    save_report(evidence_dir, &report)?;
    Ok(report)
}

impl RpSettings {
    fn provider_ids(&self) -> Vec<String> {
        [
            &self.basic.provider_id, &self.configuration.provider_id,
            &self.configuration_keys_provider_id, &self.backchannel.provider_id,
        ].into_iter().cloned().collect()
    }
}

impl RpModuleReport {
    fn accepted(&self) -> bool {
        let expected = if self.name == UNSIGNED { "SKIPPED" } else { "PASSED" };
        self.suite_status == "FINISHED"
            && self.suite_result.as_deref() == Some(expected)
            && self.application_pass
    }
}

fn save_report(dir: &Path, report: &RpReport) -> anyhow::Result<()> {
    secure_file::write_atomic(&dir.join("rp-report.json"), &serde_json::to_vec_pretty(report)?, true)
        .map_err(|error| anyhow::anyhow!("failed to save private RP report: {error:?}"))
}

#[allow(clippy::too_many_arguments)]
fn execute_plans(
    suite: &SuiteClient,
    transport: &dyn Transport,
    target: &Origin,
    settings: &RpSettings,
    evidence_dir: &Path,
    poll_timeout: Duration,
    account_id: &str,
    control: &RunControl,
    recovery: &mut Recovery,
    report: &mut RpReport,
) -> anyhow::Result<()> {
    for profile in [RpProfile::Basic, RpProfile::Configuration, RpProfile::Backchannel] {
        if control.is_interrupted() { bail!("RP run interrupted"); }
        let provider = match profile {
            RpProfile::Basic => &settings.basic,
            RpProfile::Configuration => &settings.configuration,
            RpProfile::Backchannel => &settings.backchannel,
        };
        let mut config = plan_config(profile, settings, target, provider);
        let intent = format!("plan-{}", profile.name());
        recovery.before_create(&intent)?;
        let created = suite.create_plan(profile.plan(), &plan_variant(profile), &config);
        zeroize_json_value(&mut config);
        let plan = created?;
        recovery.plan_created(&intent, &plan.id)?;
        report.plans.push(RpPlanReport {
            profile: profile.name(), suite_plan_id: plan.id.clone(),
            setup: Vec::new(), modules: Vec::new(), cleanup: "pending",
        });
        save_report(evidence_dir, report)?;
        let observed = plan.modules.iter().map(|module| module.test_name.as_str())
            .collect::<BTreeSet<_>>();
        let expected = profile_modules(profile).iter().copied().collect::<BTreeSet<_>>();
        if observed.len() != plan.modules.len() || observed != expected {
            bail!("OIDF Suite RP module set differs from the reviewed plan");
        }
        // Setup is an ordinary authenticated account binding performed through
        // an original Suite positive case. It is recorded separately, never
        // counted among the 28 fresh-browser conformance module executions.
        let setup_names: &[&str] = match profile {
            RpProfile::Basic => &["oidcc-client-test"],
            RpProfile::Configuration => &[
                "oidcc-client-test-signing-key-rotation-just-before-signing",
                "oidcc-client-test-discovery-jwks-uri-keys",
            ],
            RpProfile::Backchannel => &[LOGOUT_VALID],
        };
        for (index, name) in setup_names.iter().enumerate() {
            let module = plan.modules.iter().find(|module| &module.test_name == name)
                .context("RP setup module is absent")?;
            let result = execute_module(
                suite, transport, target, settings, profile, provider, module, &plan.id,
                &format!("{}-setup-{index}", profile.name()), evidence_dir, poll_timeout,
                account_id, control, recovery, true,
            )?;
            let success = result.application_pass;
            report.plans.last_mut().unwrap().setup.push(result);
            save_report(evidence_dir, report)?;
            if !success {
                bail!("normal production account binding did not establish the RP precondition");
            }
        }
        for (index, module) in plan.modules.iter().enumerate() {
            if control.is_interrupted() { bail!("RP run interrupted"); }
            let result = execute_module(
                suite, transport, target, settings, profile, provider, module, &plan.id,
                &format!("{}-{:02}", profile.name(), index + 1), evidence_dir, poll_timeout,
                account_id, control, recovery, false,
            )?;
            let accepted = result.accepted();
            report.plans.last_mut().unwrap().modules.push(result);
            save_report(evidence_dir, report)?;
            if !accepted && control.is_fail_fast() { bail!("RP fail-fast stopped after the failed module"); }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_module(
    suite: &SuiteClient,
    transport: &dyn Transport,
    target: &Origin,
    settings: &RpSettings,
    profile: RpProfile,
    provider: &RpProvider,
    module: &ModuleDefinition,
    plan_id: &str,
    evidence_name: &str,
    evidence_dir: &Path,
    poll_timeout: Duration,
    account_id: &str,
    control: &RunControl,
    recovery: &mut Recovery,
    setup: bool,
) -> anyhow::Result<RpModuleReport> {
    recovery.before_create(evidence_name)?;
    let instance = suite.create_module(plan_id, module)?;
    recovery.module_created(evidence_name, &instance.id)?;
    let module_record = evidence_dir.join(format!("rp-{evidence_name}-result.json"));
    secure_file::write_atomic(&module_record, &serde_json::to_vec(&json!({
        "name": module.test_name, "suite_module_id": instance.id, "suite_status": "CREATED",
    }))?, true).map_err(|error| anyhow::anyhow!("failed to save RP module identity: {error:?}"))?;
    let execution = (|| -> anyhow::Result<u16> {
        let mut ready = wait_for_state(suite, control,
            &instance.id, &["CONFIGURED", "WAITING", "FINISHED", "INTERRUPTED"], poll_timeout,
        )?;
        if ready["state"] == "CONFIGURED" {
            suite.start_module(&instance.id)?;
            ready = wait_for_state(suite, control,
                &instance.id, &["WAITING", "FINISHED", "INTERRUPTED"], poll_timeout,
            )?;
        }
        if ready["state"] != "WAITING" {
            bail!("Suite module did not reach the browser-ready state");
        }
        if setup {
            bind_account(transport, target, suite.origin(), settings, provider, module, account_id)
        } else {
            let status = drive_module(
                transport, target, suite.origin(), settings, profile, provider, module, account_id,
            )?;
            wait_for_state(suite, control, &instance.id, &["FINISHED", "INTERRUPTED"], poll_timeout)?;
            Ok(status)
        }
    })();
    let (observed_http_status, application_error) = match execution {
        Ok(status) => (Some(status), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let observed = suite.module_info(&instance.id)?;
    let suite_status = observed["status"].as_str().unwrap_or("INCOMPLETE").to_owned();
    let suite_result = observed["result"].as_str().map(str::to_owned);
    let log = suite.module_log(&instance.id)?;
    let relative = format!("rp-{evidence_name}.json");
    secure_file::write_atomic(&evidence_dir.join(&relative), &serde_json::to_vec(&log)?, true)
        .map_err(|error| anyhow::anyhow!("failed to save private RP Suite log: {error:?}"))?;
    let result = RpModuleReport {
        name: module.test_name.clone(), suite_module_id: instance.id.clone(),
        suite_status, suite_result, observed_http_status,
        application_pass: application_error.is_none(), application_error,
        raw_suite_log: Some(relative),
    };
    secure_file::write_atomic(&module_record, &serde_json::to_vec_pretty(&result)?, true)
        .map_err(|error| anyhow::anyhow!("failed to save RP module outcome: {error:?}"))?;
    // Preserve the observed outcome before cancellation. Wait for cancellation
    // to complete before another module can own the same configured alias.
    stop_module(suite, &instance.id, &result.suite_status, poll_timeout)?;
    Ok(result)
}

fn wait_for_state(
    suite: &SuiteClient, control: &RunControl, id: &str, states: &[&str], timeout: Duration,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if control.is_interrupted() { bail!("RP run interrupted"); }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { bail!("RP Suite wait timed out"); }
        match suite.wait_for_state(id, states, remaining.min(Duration::from_secs(5))) {
            Ok(state) => return Ok(state),
            Err(SuiteClientError::Timeout) => {},
            Err(error) => return Err(error.into()),
        }
    }
}

fn stop_module(suite: &SuiteClient, id: &str, status: &str, timeout: Duration) -> anyhow::Result<()> {
    if !matches!(status, "FINISHED" | "INTERRUPTED") {
        suite.cancel_module(id)?;
        suite.wait_for_state(id, &["FINISHED", "INTERRUPTED"], timeout)?;
    }
    Ok(())
}

fn settle_suite(
    suite: &SuiteClient, recovery: &mut Recovery, delete: bool, timeout: Duration,
) -> anyhow::Result<()> {
    if delete {
        recover_suite_resources(suite, recovery.state()).map_err(anyhow::Error::msg)?;
    } else {
        if !recovery.state().pending_create_intents.is_empty() {
            bail!("Suite allocation outcome is unknown; recovery journal remains active");
        }
        for id in &recovery.state().module_ids {
            let info = suite.module_info(id)?;
            let status = info["status"].as_str().context("Suite module has no status")?;
            stop_module(suite, id, status, timeout)?;
        }
    }
    Ok(())
}

/// Recover only resources recorded by an earlier RP run. An ordinary OP-only
/// invocation cannot silently skip RP obligations requiring account credentials.
pub fn recover_runs(
    suite: &SuiteClient,
    target: &Origin,
    settings: Option<&RpSettings>,
    evidence_root: &Path,
) -> anyhow::Result<()> {
    let pending = Recovery::pending(evidence_root)?;
    if pending.is_empty() { return Ok(()); }
    let settings = settings.context("pending RP cleanup requires its private --rp-config file")?;
    let transport = HttpTransport::new(ClientConfig::default().timeout)?;
    for mut recovery in pending {
        if recovery.target_origin() != target.as_str() {
            bail!("RP recovery target does not match the authenticated fixture");
        }
        let mut browser = Browser::new(&transport, target, suite.origin());
        let recovered = (|| -> anyhow::Result<()> {
            clean_links(&mut browser, &recovery, settings)?;
            recover_suite_resources(suite, recovery.state()).map_err(anyhow::Error::msg)
        })();
        let logout = browser.logout(settings);
        recovered.and(logout).with_context(|| format!(
            "RP recovery remains pending in {}", recovery.evidence_dir().display(),
        ))?;
        recovery.settle(false)?;
    }
    Ok(())
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
    http: &'a dyn Transport,
    target: &'a Origin,
    suite: &'a Origin,
    cookies: BTreeMap<String, BTreeMap<String, Zeroizing<String>>>,
}

impl<'a> Browser<'a> {
    fn new(http: &'a dyn Transport, target: &'a Origin, suite: &'a Origin) -> Self {
        Self { http, target, suite, cookies: BTreeMap::new() }
    }

    fn request(&mut self, mut request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let origin = request.url.origin().ascii_serialization();
        if !self.target.same_origin_url(&request.url) && !self.suite.same_origin_url(&request.url) {
            bail!("RP test redirect escaped the two explicitly configured HTTPS origins");
        }
        if let Some(jar) = self.cookies.get(&origin) {
            let value = jar.iter().map(|(name, value)| format!("{name}={}", value.as_str()))
                .collect::<Vec<_>>().join("; ");
            if !value.is_empty() { request = request.with_header("cookie", value); }
        }
        let response = self.http.send(request, MAX_RP_HTTP_BYTES)?;
        let jar = self.cookies.entry(origin).or_default();
        for (_, cookie) in response.headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie")) {
            let pair = cookie.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') && valid_path_segment(name) {
                let expired = cookie.split(';').skip(1).any(|attribute| {
                    attribute.trim().eq_ignore_ascii_case("max-age=0")
                });
                if value.is_empty() || expired {
                    jar.remove(name);
                } else {
                    jar.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
                }
            }
        }
        Ok(response)
    }

    fn get(&mut self, url: Url) -> anyhow::Result<HttpResponse> {
        self.request(HttpRequest::get(url))
    }

    fn post(&mut self, url: Url, form: String) -> anyhow::Result<HttpResponse> {
        self.request(HttpRequest::post_form(url, form))
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(self.target.as_str())?.get(name).map(|value| value.as_str())
    }

    fn follow(&mut self, mut url: Url) -> anyhow::Result<(Url, HttpResponse)> {
        for _ in 0..MAX_REDIRECT_HOPS {
            let response = self.get(url.clone())?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok((url, response));
            }
            url = url.join(response.header("location").context("RP redirect missing Location")?)?;
        }
        bail!("RP flow exceeded the redirect budget")
    }

    fn login(&mut self, settings: &RpSettings) -> anyhow::Result<String> {
        #[derive(Serialize)]
        struct Login<'b> { email: &'b str, password: &'b str }
        let body = serde_json::to_vec(&Login {
            email: &settings.account.email, password: &settings.account.password,
        })?;
        let response = self.request(HttpRequest {
            method: HttpMethod::Post, url: self.target.url("/auth/login")?,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(body.into()),
        })?;
        self.assert_login(&response, settings)?;
        self.account_id()
    }

    fn assert_login(&self, response: &HttpResponse, settings: &RpSettings) -> anyhow::Result<()> {
        let body = response.body.json::<Value>().context("local login response was not JSON")?;
        let csrf = body["csrf_token"].as_str().filter(|value| !value.is_empty())
            .context("local login has no CSRF token")?;
        if response.status != 200 || body["mfa_required"] != false
            || body["expires_in"].as_i64().is_none_or(|value| value <= 0)
            || self.cookie(&settings.session_cookie_name).is_none()
            || self.cookie(&settings.csrf_cookie_name) != Some(csrf)
        {
            bail!("valid identity did not establish an authenticated local session");
        }
        Ok(())
    }

    fn account_id(&mut self) -> anyhow::Result<String> {
        let response = self.get(self.target.url("/auth/me")?)?;
        if response.status != 200 { bail!("local session is not authenticated"); }
        let body = response.body.json::<Value>()?;
        if body["mfa_required"] != false { bail!("RP fixture account requires MFA"); }
        let id = body["id"].as_str().context("local profile has no account ID")?;
        uuid::Uuid::parse_str(id).context("local profile account ID is malformed")?;
        Ok(id.to_owned())
    }

    fn links(&mut self) -> anyhow::Result<Vec<Link>> {
        let response = self.get(self.target.url("/auth/me/federation/links")?)?;
        if response.status != 200 { bail!("local account link list is unavailable"); }
        #[derive(Deserialize)]
        struct Links { items: Vec<Link> }
        let links = response.body.json::<Links>()?.items;
        for link in &links {
            uuid::Uuid::parse_str(&link.id).context("public account link ID is malformed")?;
        }
        Ok(links)
    }

    fn logout(&mut self, settings: &RpSettings) -> anyhow::Result<()> {
        if self.cookie(&settings.session_cookie_name).is_none() { return Ok(()); }
        let csrf = self.cookie(&settings.csrf_cookie_name).context("local logout has no CSRF cookie")?.to_owned();
        let response = self.request(HttpRequest::post_form(self.target.url("/auth/logout")?, String::new())
            .with_header("x-csrf-token", csrf))?;
        if response.status != 200 || response.body.json::<Value>()?["success"] != true {
            bail!("local test session could not be revoked");
        }
        if self.get(self.target.url("/auth/me")?)?.status != 401 {
            bail!("local test session remained authenticated after logout");
        }
        Ok(())
    }
}

fn provider_id<'a>(settings: &'a RpSettings, provider: &'a RpProvider, module: &str) -> &'a str {
    if module == "oidcc-client-test-discovery-jwks-uri-keys" {
        &settings.configuration_keys_provider_id
    } else { &provider.provider_id }
}

fn bind_account(
    http: &dyn Transport, target: &Origin, suite: &Origin, settings: &RpSettings,
    provider: &RpProvider, module: &ModuleDefinition, account_id: &str,
) -> anyhow::Result<u16> {
    let provider = provider_id(settings, provider, &module.test_name);
    let mut browser = Browser::new(http, target, suite);
    let result = (|| -> anyhow::Result<u16> {
        if browser.login(settings)? != account_id { bail!("RP setup authenticated a different local account"); }
        let csrf = browser.cookie(&settings.csrf_cookie_name).context("account binding has no CSRF cookie")?;
        let form = url::form_urlencoded::Serializer::new(String::new()).append_pair("csrf_token", csrf).finish();
        let response = browser.post(target.url(&format!("/auth/me/federation/links/{provider}/start"))?, form)?;
        if response.status != 302 { bail!("normal production account linking could not start"); }
        let location = Url::parse(response.header("location").context("account linking did not redirect")?)?;
        let (url, response) = browser.follow(location)?;
        let body = response.body.json::<Value>()?;
        if !target.same_origin_url(&url) || url.path() != format!("/auth/federation/{provider}/callback")
            || response.status != 200 || body["linked"] != true || body["provider_id"] != provider
            || browser.account_id()? != account_id
            || !browser.links()?.iter().any(|link| link.provider_id == provider)
        {
            bail!("normal production account linking did not preserve the authenticated account");
        }
        Ok(response.status)
    })();
    let logout = browser.logout(settings);
    result.and_then(|status| logout.map(|()| status))
}

fn clean_links(browser: &mut Browser<'_>, recovery: &Recovery, settings: &RpSettings) -> anyhow::Result<()> {
    if browser.login(settings)? != recovery.account_id() {
        bail!("RP cleanup authenticated a different local account");
    }
    for link in browser.links()? {
        if !recovery.provider_ids().contains(&link.provider_id)
            || recovery.baseline_links().iter().any(|before| before.id == link.id) { continue; }
        let csrf = browser.cookie(&settings.csrf_cookie_name).context("unlink has no CSRF cookie")?.to_owned();
        let response = browser.request(HttpRequest {
            method: HttpMethod::Delete,
            url: browser.target.url(&format!("/auth/me/federation/links/{}", link.id))?,
            headers: vec![("x-csrf-token".into(), csrf)], body: None,
        })?;
        if response.status != 204 { bail!("normal production account unlink failed"); }
    }
    if browser.links()?.iter().any(|link| {
        recovery.provider_ids().contains(&link.provider_id)
            && !recovery.baseline_links().iter().any(|before| before.id == link.id)
    }) { bail!("RP setup links remain after unlink"); }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drive_module(
    http: &dyn Transport, target: &Origin, suite: &Origin, settings: &RpSettings,
    profile: RpProfile, provider: &RpProvider, module: &ModuleDefinition, account_id: &str,
) -> anyhow::Result<u16> {
    let provider_id = provider_id(settings, provider, &module.test_name);
    let start_url = target.url(&format!("/auth/federation/{provider_id}/start"))?;
    let callback = target.url(&format!("/auth/federation/{provider_id}/callback"))?;
    let mut browser = Browser::new(http, target, suite);
    let result = (|| -> anyhow::Result<u16> {
        if module.test_name == "oidcc-client-test-discovery-openid-config"
            || module.test_name == "oidcc-client-test-discovery-issuer-mismatch" {
            let response = browser.get(start_url.clone())?;
            if module.test_name == "oidcc-client-test-discovery-issuer-mismatch" {
                if response.status != 503 || response.header("location").is_some() {
                    bail!("issuer mismatch did not reject discovery before authorization");
                }
            } else {
                let url = Url::parse(response.header("location").context("discovery did not redirect")?)?;
                if response.status != 302 || !suite.same_origin_url(&url) || !url.path().ends_with("/authorize") {
                    bail!("valid discovery did not reach the Suite authorization endpoint");
                }
            }
            return Ok(response.status);
        }
        let attempts = if module.test_name == "oidcc-client-test-signing-key-rotation" { 2 } else { 1 };
        let mut observed_status = 0;
        for attempt in 0..attempts {
            let (url, response) = browser.follow(start_url.clone())?;
            if !target.same_origin_url(&url) || url.path() != callback.path() {
                bail!("RP flow did not finish at the configured callback");
            }
            observed_status = response.status;
            if negative_module(&module.test_name) {
                if response.status != 401 || response.body.json::<Value>()?["error"] != "access_denied"
                    || browser.cookie(&settings.session_cookie_name).is_some()
                    || browser.cookie(&settings.csrf_cookie_name).is_some()
                    || browser.get(target.url("/auth/me")?)?.status != 401 {
                    bail!("invalid upstream identity was accepted or returned an unexpected status");
                }
            } else {
                browser.assert_login(&response, settings)?;
                if browser.account_id()? != account_id {
                    bail!("upstream identity authenticated a different local account");
                }
                if attempt + 1 < attempts { browser.logout(settings)?; }
            }
        }
        if profile == RpProfile::Backchannel {
            let csrf = browser.cookie(&settings.csrf_cookie_name).context("logout has no CSRF token")?.to_owned();
            drive_logout(&mut browser, target, suite, settings, provider, &module.test_name, &csrf)?;
        }
        Ok(observed_status)
    })();
    let logout = browser.logout(settings);
    result.and_then(|status| logout.map(|()| status))
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
    if !matches!(op_response.status, 302 | 303) {
        bail!("Suite logout did not return an HTTP redirect");
    }
    let redirect = op_response
        .header("location")
        .context("Suite logout did not redirect")?;
    let url = action.join(redirect)?;
    if url.as_str() != return_uri {
        bail!("Suite logout did not return to the registered RP URI");
    }
    if browser.get(url)?.status != 200 {
        bail!("registered post-logout URI was not reachable");
    }
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
        values.insert(pair[1].to_owned(), decode_html_attribute(&pair[2]));
    }
    let hint = values.remove("id_token_hint").context("no ID Token hint")?;
    let return_uri = values
        .remove("post_logout_redirect_uri")
        .context("no return URI")?;
    if hint.is_empty() {
        bail!("empty upstream logout ID Token hint");
    }
    Ok((Url::parse(&decode_html_attribute(action.as_str()))?, hint, return_uri))
}

fn decode_html_attribute(value: &str) -> String {
    value.replace("&quot;", "\"").replace("&#39;", "'")
        .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

#[cfg(test)]
mod tests;
