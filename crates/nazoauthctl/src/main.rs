use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, bail};
use nazoauthctl_conformance::{
    BearerToken, BrowserAutomation, BrowserExecutor, BrowserPolicy, BrowserTargetOrigin,
    ClientConfig, ConformanceBinding, ConformanceRunConfig, ConformanceRunner, CredentialStore,
    DescriptorMaterializer, ManagedWebDriver, MatrixSelection, OnboardingOutput,
    OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver, OpenId4VpVerifier,
    OpenId4VpVerifierClient, Origin, RunControl, StableRenderer, SuiteClient, TtyRenderer,
    WebDriverClient, WebDriverEndpoint,
};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_LEASE_TTL_SECONDS: u64 = 14_400;
const MAX_STDIN_TOKEN_BYTES: u64 = 16 * 1024;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let invocation = match parse_run_invocation(&args) {
        Ok(Some(invocation)) => invocation,
        Ok(None) => {
            nazoauthctl_core::main_entry();
            return;
        }
        Err(error) => exit_with_error(&error),
    };

    match execute(invocation) {
        Ok(code) => std::process::exit(code),
        Err(error) => exit_with_error(&error),
    }
}

fn exit_with_error(error: &anyhow::Error) -> ! {
    let message = format!("{error:#}");
    let output = serde_json::json!({
        "schema": 1,
        "success": false,
        "error": message,
    });
    let _ = serde_json::to_writer_pretty(io::stdout().lock(), &output);
    let _ = writeln!(io::stdout());
    let _ = writeln!(
        io::stderr(),
        "nazoauthctl conformance run failed: {error:#}"
    );
    std::process::exit(1)
}

struct RunInvocation {
    config: PathBuf,
    deployment: Option<String>,
    suite: Option<String>,
    token: Option<Zeroizing<String>>,
    token_file: Option<PathBuf>,
    token_stdin: bool,
    token_fd: Option<u32>,
    webdriver: Option<String>,
    evidence_directory: Option<PathBuf>,
    groups: Vec<String>,
    plans: Vec<String>,
    poll_timeout: Duration,
    lease_ttl_seconds: u64,
}

fn parse_run_invocation(args: &[OsString]) -> anyhow::Result<Option<RunInvocation>> {
    let mut values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("conformance arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut config = env::var_os("NAZOAUTH_UPDATE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let mut deployment = None;
    while values
        .first()
        .is_some_and(|value| matches!(value.as_str(), "--config" | "--deployment"))
    {
        if values.len() < 2 {
            bail!("{} requires a value", values[0]);
        }
        let value = values.remove(1);
        match values.remove(0).as_str() {
            "--config" => config = PathBuf::from(value),
            "--deployment" => {
                if deployment.replace(value).is_some() {
                    bail!("--deployment may be specified only once");
                }
            }
            _ => unreachable!(),
        }
    }
    if values.first().map(String::as_str) != Some("conformance")
        || values.get(1).map(String::as_str) != Some("run")
    {
        return Ok(None);
    }
    values.drain(..2);
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_run_help();
        std::process::exit(0);
    }

    let mut suite = None;
    let mut token = None;
    let mut token_file = None;
    let mut token_stdin = false;
    let mut token_fd = None;
    let mut webdriver = None;
    let mut evidence_directory = None;
    let mut groups = Vec::new();
    let mut plans = Vec::new();
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut lease_ttl_seconds = DEFAULT_LEASE_TTL_SECONDS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--suite" | "--token" | "--token-file" | "--token-fd" | "--webdriver"
            | "--evidence-dir" | "--group" | "--plan" | "--poll-timeout" | "--lease-ttl" => {
                let value = values
                    .get(index + 1)
                    .with_context(|| format!("{option} requires a value"))?
                    .clone();
                match option {
                    "--suite" => set_once(&mut suite, value, option)?,
                    "--token" => set_once(&mut token, Zeroizing::new(value), option)?,
                    "--token-file" => set_once(&mut token_file, PathBuf::from(value), option)?,
                    "--token-fd" => {
                        let value = value
                            .parse::<u32>()
                            .context("--token-fd must be an integer")?;
                        set_once(&mut token_fd, value, option)?;
                    }
                    "--webdriver" => set_once(&mut webdriver, value, option)?,
                    "--evidence-dir" => {
                        set_once(&mut evidence_directory, PathBuf::from(value), option)?;
                    }
                    "--group" => groups.push(value),
                    "--plan" => plans.push(value),
                    "--poll-timeout" => {
                        poll_timeout = Duration::from_secs(
                            value
                                .parse::<u64>()
                                .context("--poll-timeout must be an integer")?,
                        );
                    }
                    "--lease-ttl" => {
                        lease_ttl_seconds = value
                            .parse::<u64>()
                            .context("--lease-ttl must be an integer")?;
                    }
                    _ => unreachable!(),
                }
                index += 2;
            }
            "--token-stdin" => {
                if token_stdin {
                    bail!("--token-stdin may be specified only once");
                }
                token_stdin = true;
                index += 1;
            }
            _ => bail!("unknown conformance run option: {option}"),
        }
    }
    let token_sources = usize::from(token.is_some())
        + usize::from(token_file.is_some())
        + usize::from(token_stdin)
        + usize::from(token_fd.is_some());
    if token_sources > 1 {
        bail!("--token, --token-file, --token-stdin, and --token-fd are mutually exclusive");
    }
    if poll_timeout.is_zero() || !(300..=86_400).contains(&lease_ttl_seconds) {
        bail!("poll timeout must be positive and lease TTL must be between 300 and 86400 seconds");
    }
    Ok(Some(RunInvocation {
        config,
        deployment,
        suite,
        token,
        token_file,
        token_stdin,
        token_fd,
        webdriver,
        evidence_directory,
        groups,
        plans,
        poll_timeout,
        lease_ttl_seconds,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        bail!("{option} may be specified only once");
    }
    Ok(())
}

fn execute(mut invocation: RunInvocation) -> anyhow::Result<i32> {
    let suite_origin = Origin::from_suite_arg(invocation.suite.as_deref())
        .context("invalid OpenID Foundation Conformance Suite origin")?;

    // Deployment validation and the capability lock precede Suite access.
    let session = nazoauthctl_core::ConformanceSession::open(
        &invocation.config,
        invocation.deployment.as_deref(),
    )
    .context("deployment is not ready for conformance orchestration")?;

    let (token, prompted) = resolve_token(&mut invocation, &suite_origin)?;
    let client = SuiteClient::new(suite_origin.clone(), token.clone(), ClientConfig::default())
        .context("failed to initialize the Suite client")?;
    client
        .probe_auth()
        .context("Suite API token authentication failed")?;
    if prompted {
        offer_credential_persistence(&suite_origin, &token)?;
    }

    let matrix = session
        .describe_matrix()
        .context("failed to load the deployment Matrix")?;
    let descriptor = DescriptorMaterializer::from_bytes(&matrix.bytes)
        .context("deployment Matrix cannot be materialized")?;
    let request_jti = format!("request-{}", hex(rand::random::<[u8; 16]>()));
    let openid4vc_request_object_trust_anchor_pem = session
        .openid4vc_request_object_trust_anchor_pem()
        .context("failed to load the deployment OpenID4VC public trust anchor")?;
    let (prepared, bundle) = DescriptorMaterializer::prepare(
        descriptor,
        session.target_issuer(),
        &suite_origin,
        &request_jti,
        &openid4vc_request_object_trust_anchor_pem,
    )
    .context("failed to prepare ephemeral conformance material")?;
    if prepared.matrix_sha256() != matrix.sha256 {
        bail!("deployment Matrix digest does not match the signed operator result");
    }
    let client_count = u32::try_from(prepared.expected_clients().len())
        .context("Matrix contains too many conformance clients")?;
    let onboarding = session
        .apply_onboarding(
            &request_jti,
            &matrix.sha256,
            bundle.bytes().as_bytes(),
            client_count,
            invocation.lease_ttl_seconds,
        )
        .context("failed to atomically provision the conformance lease")?;
    let lease_id = onboarding.lease_id.clone();
    let applicant_id = uuid::Uuid::parse_str(&onboarding.applicant_id)
        .context("operator onboarding returned an invalid applicant identifier")?;
    let static_tx_code = prepared.tx_code();

    let run_result = (|| -> anyhow::Result<RunOutput> {
        let onboarding_output = OnboardingOutput::new(
            onboarding.lease_id.clone(),
            onboarding.request_jti.clone(),
            onboarding.matrix_sha256.clone(),
            onboarding.bundle_sha256.clone(),
            onboarding.applicant_id.clone(),
            openid4vc_request_object_trust_anchor_pem.clone(),
            onboarding.client_mappings.clone(),
        )?;
        let binding =
            ConformanceBinding::new(&onboarding.lease_id, onboarding.request_jti.clone())?;
        let mut materialized = DescriptorMaterializer::finalize(prepared, onboarding_output)
            .context("operator onboarding result does not match the prepared Matrix")?;
        let browser = build_browser(
            invocation.webdriver.as_deref(),
            session.target_issuer(),
            &suite_origin,
        )?;
        let issuer: Arc<Mutex<dyn OpenId4VciIssuerDriver>> =
            Arc::new(Mutex::new(OpenId4VciIssuerClient::new(
                OpenId4VciIssuerConfig::new(
                    BrowserTargetOrigin::parse(session.target_issuer())?,
                    suite_origin.clone(),
                    applicant_id,
                    static_tx_code,
                    Duration::from_secs(30),
                )?,
                session
                    .openid4vci_management_token()
                    .context("failed to load the deployment OpenID4VCI management token")?,
                token.clone(),
                browser.clone(),
            )?));
        let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> =
            Arc::new(Mutex::new(OpenId4VpVerifierClient::new(
                BrowserTargetOrigin::parse(session.target_issuer())?,
                suite_origin.clone(),
                session
                    .openid4vp_management_token()
                    .context("failed to load the deployment OpenID4VP management token")?,
                Duration::from_secs(30),
                binding.clone(),
            )?));
        let control = RunControl::default();
        let interrupt = control.clone();
        ctrlc::set_handler(move || interrupt.interrupt())
            .context("failed to install the conformance interrupt handler")?;
        let selected_matrix = materialized
            .take_matrix()
            .select(&MatrixSelection {
                groups: invocation.groups.clone(),
                profiles: Vec::new(),
                plans: invocation.plans.clone(),
            })
            .context("requested conformance Matrix selection is invalid")?;
        let selected_groups = u32::try_from(selected_matrix.document.groups.len())
            .context("selected Matrix contains too many groups")?;
        let selected_plans = u32::try_from(selected_matrix.document.plan_count())
            .context("selected Matrix contains too many plans")?;
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: selected_matrix,
            target_origin: Some(BrowserTargetOrigin::parse(session.target_issuer())?),
            binding,
            poll_timeout: invocation.poll_timeout,
            control,
            browser: Some(browser),
            verifier: Some(verifier),
            issuer: Some(issuer),
        })?;
        let summary = if io::stderr().is_terminal() {
            let mut renderer = TtyRenderer::new(io::stderr().lock());
            runner.run(&mut renderer)
        } else {
            let mut renderer = StableRenderer::new(io::stderr().lock());
            runner.run(&mut renderer)
        };
        if let Some(directory) = &invocation.evidence_directory {
            summary
                .report
                .write_private_evidence(directory)
                .context("failed to persist private Suite evidence")?;
        }
        Ok(RunOutput {
            report: summary.report,
            deployment: DeploymentReport {
                matrix_sha256: matrix.sha256.clone(),
                matrix_source_release: matrix.source_release.clone(),
                matrix_groups: matrix.group_count,
                matrix_plans: matrix.plan_count,
                selected_groups,
                selected_plans,
                lease_id: onboarding.lease_id.clone(),
                applicant_id: onboarding.applicant_id.clone(),
                client_count,
                expires_at: onboarding.expires_at,
                idempotent_replay: onboarding.idempotent_replay,
                cleanup_complete: false,
            },
        })
    })();

    let lease_cleanup = session.cleanup_lease(&lease_id);
    let mut output = run_result?;
    output.deployment.cleanup_complete = lease_cleanup.is_ok();
    if let Err(error) = lease_cleanup {
        bail!("Suite completed but deployment lease cleanup failed: {error:#}");
    }
    let success = output.report.local_success
        && output.report.suite_pass
        && output.deployment.cleanup_complete;
    let final_output = FinalOutput {
        schema: 1,
        success,
        run: output,
    };
    serde_json::to_writer_pretty(io::stdout().lock(), &final_output)
        .context("failed to write the structured conformance report")?;
    writeln!(io::stdout()).context("failed to finish the structured conformance report")?;
    Ok(if success { 0 } else { 1 })
}

fn build_browser(
    endpoint: Option<&str>,
    target_issuer: &str,
    suite_origin: &Origin,
) -> anyhow::Result<Arc<Mutex<dyn BrowserAutomation>>> {
    let target = BrowserTargetOrigin::parse(target_issuer)?;
    let policy = BrowserPolicy::new(target, suite_origin.clone())?;
    if let Some(endpoint) = endpoint {
        let endpoint = WebDriverEndpoint::parse(endpoint)?;
        let mut driver = WebDriverClient::connect(endpoint, Duration::from_secs(30))?;
        driver.start_chrome()?;
        Ok(Arc::new(Mutex::new(BrowserExecutor::new(driver, policy))))
    } else {
        let driver = ManagedWebDriver::start_default(Duration::from_secs(30))?;
        Ok(Arc::new(Mutex::new(BrowserExecutor::new(driver, policy))))
    }
}

fn resolve_token(
    invocation: &mut RunInvocation,
    origin: &Origin,
) -> anyhow::Result<(BearerToken, bool)> {
    if let Some(mut value) = invocation.token.take() {
        eprintln!("warning: --token is visible in argv and may be retained by shell history");
        let token = BearerToken::new(value.as_str().to_owned())?;
        value.zeroize();
        return Ok((token, false));
    }
    if let Some(path) = &invocation.token_file {
        return Ok((BearerToken::read_file(path)?, false));
    }
    if invocation.token_stdin {
        let mut bytes = Zeroizing::new(Vec::new());
        io::stdin()
            .take(MAX_STDIN_TOKEN_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to read the Suite token from stdin")?;
        if bytes.len() as u64 > MAX_STDIN_TOKEN_BYTES {
            bail!("Suite token from stdin exceeds the size limit");
        }
        let value = std::str::from_utf8(&bytes).context("Suite token from stdin is not UTF-8")?;
        return Ok((BearerToken::new(value.to_owned())?, false));
    }
    if let Some(fd) = invocation.token_fd {
        return Ok((CredentialStore::read_descriptor(fd)?, false));
    }

    let store = CredentialStore::new(credential_root()?)?;
    if let Some(token) = store.load(origin)? {
        return Ok((token, false));
    }
    if !io::stdin().is_terminal() {
        bail!("no Suite API token is available; use a token option in non-TTY environments");
    }
    let value = rpassword::prompt_password("OpenID Foundation Conformance Suite API Token:")?;
    Ok((BearerToken::new(value)?, true))
}

fn offer_credential_persistence(origin: &Origin, token: &BearerToken) -> anyhow::Result<()> {
    if !io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("Save this token securely for {}? [y/N] ", origin.as_str());
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let save = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    answer.zeroize();
    if save {
        CredentialStore::new(credential_root()?)?.save(origin, token)?;
        eprintln!("Token saved for this Suite origin.");
    }
    Ok(())
}

fn credential_root() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let root = env::var_os("APPDATA")
        .map(PathBuf::from)
        .context("APPDATA is not set")?;
    #[cfg(not(windows))]
    let root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .context("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(root.join("nazoauthctl").join("conformance-credentials"))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Serialize)]
struct FinalOutput {
    schema: u32,
    success: bool,
    run: RunOutput,
}

#[derive(Serialize)]
struct RunOutput {
    deployment: DeploymentReport,
    report: nazoauthctl_conformance::ConformanceReport,
}

#[derive(Serialize)]
struct DeploymentReport {
    matrix_sha256: String,
    matrix_source_release: String,
    matrix_groups: u32,
    matrix_plans: u32,
    selected_groups: u32,
    selected_plans: u32,
    lease_id: String,
    applicant_id: String,
    client_count: u32,
    expires_at: i64,
    idempotent_replay: bool,
    cleanup_complete: bool,
}

fn print_run_help() {
    println!(
        "Usage:\n  nazoauthctl [--deployment ID_OR_ALIAS] [--config PATH] conformance run [options]\n\nOptions:\n  --suite URL             OpenID Foundation Suite origin (default: official Suite)\n  --token TOKEN           API token; visible in argv/shell history\n  --token-file PATH       Read token from a private regular file\n  --token-stdin           Read token from stdin\n  --token-fd FD           Read token from an inherited private descriptor\n  --webdriver URL         Use an existing W3C WebDriver endpoint\n  --evidence-dir PATH     Persist private raw Suite evidence securely\n  --group ID              Run one Matrix group; repeat to select more\n  --plan ID               Run one Matrix plan; repeat to select more\n  --poll-timeout SECONDS  Per-module Suite wait bound (default: 1800)\n  --lease-ttl SECONDS     Deployment lease lifetime (default: 14400)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn unrelated_command_is_owned_by_core() {
        assert!(
            parse_run_invocation(&args(&["nazoauthctl", "status"]))
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn run_parses_global_and_automation_options() {
        let parsed = parse_run_invocation(&args(&[
            "nazoauthctl",
            "--deployment",
            "prod",
            "--config",
            "/x/update.json",
            "conformance",
            "run",
            "--suite",
            "https://suite.example",
            "--token-fd",
            "7",
            "--group",
            "oidc",
            "--plan",
            "oidc-core-p001",
        ]))
        .expect("parse")
        .expect("run");
        assert_eq!(parsed.deployment.as_deref(), Some("prod"));
        assert_eq!(parsed.config, PathBuf::from("/x/update.json"));
        assert_eq!(parsed.token_fd, Some(7));
        assert_eq!(parsed.groups, ["oidc"]);
        assert_eq!(parsed.plans, ["oidc-core-p001"]);
    }

    #[test]
    fn token_sources_are_mutually_exclusive() {
        let result = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--token",
            "secret",
            "--token-stdin",
        ]));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("must reject"),
        };
        assert!(error.to_string().contains("mutually exclusive"));
    }
}
