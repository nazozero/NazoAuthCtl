use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use nazoauthctl_conformance::{
    ArtifactTrustPolicy, BearerToken, BrowserAutomation, BrowserExecutor, BrowserPolicy,
    BrowserTargetOrigin, ClientConfig, ConformanceAutomation, ConformanceBinding,
    ConformanceRunConfig, ConformanceRunner, CredentialStore, DescriptorMaterializer,
    EvidenceBundleIdentity, EvidenceBundleReceipt, EvidenceDeploymentIdentity,
    EvidenceRuntimeIdentity, EvidenceSourceIdentity, MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS,
    ManagedWebDriver, MatrixSelection, OidfPlanSelection, OnboardingOutput, OpenId4VciIssuerClient,
    OpenId4VciIssuerConfig, OpenId4VciIssuerDriver, OpenId4VpVerifier, OpenId4VpVerifierClient,
    Origin, ProxyTrustGuard, RunControl, StableRenderer, SuiteClient, TtyRenderer, WebDriverClient,
    WebDriverEndpoint, open_cached_oidf_artifact, open_cached_oidf_driver_plan,
    read_artifact_driver, read_artifact_matrix, read_compact_manifest, resolve_oidf_artifact,
    verify_oidf_artifact, write_private_evidence_bundle,
};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_LEASE_TTL_SECONDS: u64 = 14_400;
const DEFAULT_JOBS: usize = 4;
const MAX_STDIN_TOKEN_BYTES: u64 = 16 * 1024;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let plan = match parse_artifact_plan_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error),
    };
    if let Some(invocation) = plan {
        match execute_artifact_plan(invocation) {
            Ok(()) => return,
            Err(error) => exit_with_error(&error),
        }
    }
    let cached = match parse_artifact_open_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error),
    };
    if let Some(invocation) = cached {
        match execute_artifact_open(invocation) {
            Ok(()) => return,
            Err(error) => exit_with_error(&error),
        }
    }
    let resolution = match parse_artifact_resolve_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error),
    };
    if let Some(invocation) = resolution {
        match execute_artifact_resolve(invocation) {
            Ok(()) => return,
            Err(error) => exit_with_error(&error),
        }
    }
    let artifact = match parse_artifact_verify_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error),
    };
    if let Some(invocation) = artifact {
        match execute_artifact_verify(invocation) {
            Ok(()) => return,
            Err(error) => exit_with_error(&error),
        }
    }
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

struct ArtifactPlanInvocation {
    trust_policy: PathBuf,
    cache_directory: PathBuf,
    manifest_digest: String,
    capabilities: std::collections::BTreeSet<String>,
    selection: OidfPlanSelection,
}

fn parse_artifact_plan_invocation(
    args: &[OsString],
) -> anyhow::Result<Option<ArtifactPlanInvocation>> {
    let mut values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("artifact plan arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if values.first().map(String::as_str) != Some("conformance")
        || values.get(1).map(String::as_str) != Some("artifact")
        || values.get(2).map(String::as_str) != Some("plan")
    {
        return Ok(None);
    }
    values.drain(..3);
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_artifact_plan_help();
        std::process::exit(0);
    }
    let mut trust_policy = None;
    let mut cache_directory = None;
    let mut manifest_digest = None;
    let mut capabilities = std::collections::BTreeSet::new();
    let mut groups = Vec::new();
    let mut plans = Vec::new();
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        if !matches!(
            option,
            "--trust-policy" | "--cache-dir" | "--digest" | "--capability" | "--group" | "--plan"
        ) {
            bail!("unknown conformance artifact plan option: {option}");
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--trust-policy" => set_once(&mut trust_policy, PathBuf::from(value), option)?,
            "--cache-dir" => set_once(&mut cache_directory, PathBuf::from(value), option)?,
            "--digest" => set_once(&mut manifest_digest, value, option)?,
            "--capability" => push_unique(&mut capabilities, value, option)?,
            "--group" => push_unique_vec(&mut groups, value, option)?,
            "--plan" => push_unique_vec(&mut plans, value, option)?,
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(Some(ArtifactPlanInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        manifest_digest: manifest_digest.context("--digest is required")?,
        capabilities,
        selection: OidfPlanSelection { groups, plans },
    }))
}

fn execute_artifact_plan(invocation: ArtifactPlanInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy)
        .context("OIDF artifact trust policy is invalid")?;
    let plan = open_cached_oidf_driver_plan(
        &invocation.cache_directory,
        &invocation.manifest_digest,
        &trust,
        &invocation.capabilities,
        invocation.selection,
        current_unix_time()?,
    )
    .context("cached OIDF driver plan compilation failed")?;
    serde_json::to_writer_pretty(io::stdout().lock(), &plan)
        .context("failed to write OIDF driver inspection plan")?;
    writeln!(io::stdout()).context("failed to finish OIDF driver inspection plan")
}

fn print_artifact_plan_help() {
    println!(
        "Usage:\n  nazoauthctl conformance artifact plan --trust-policy PATH --cache-dir PATH --digest SHA256 [--capability NAME ...] [--group ID ...] [--plan ID ...]\n\nThis is a read-only, offline inspection plan. It revalidates one exact cached artifact and compiles exact signed Matrix selections. Caller-supplied capability names are not attested negotiation. The output is explicitly not deployment-bound or executable and creates no run journal or resources."
    );
}

struct ArtifactOpenInvocation {
    trust_policy: PathBuf,
    cache_directory: PathBuf,
    manifest_digest: String,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_open_invocation(
    args: &[OsString],
) -> anyhow::Result<Option<ArtifactOpenInvocation>> {
    let mut values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("artifact cache arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if values.first().map(String::as_str) != Some("conformance")
        || values.get(1).map(String::as_str) != Some("artifact")
        || values.get(2).map(String::as_str) != Some("open")
    {
        return Ok(None);
    }
    values.drain(..3);
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_artifact_open_help();
        std::process::exit(0);
    }
    let mut trust_policy = None;
    let mut cache_directory = None;
    let mut manifest_digest = None;
    let mut capabilities = std::collections::BTreeSet::new();
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        if !matches!(
            option,
            "--trust-policy" | "--cache-dir" | "--digest" | "--capability"
        ) {
            bail!("unknown conformance artifact open option: {option}");
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--trust-policy" => {
                set_once(&mut trust_policy, PathBuf::from(value), option)?;
            }
            "--cache-dir" => {
                set_once(&mut cache_directory, PathBuf::from(value), option)?;
            }
            "--digest" => set_once(&mut manifest_digest, value, option)?,
            "--capability" => {
                if !capabilities.insert(value) {
                    bail!("--capability values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(Some(ArtifactOpenInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        manifest_digest: manifest_digest.context("--digest is required")?,
        capabilities,
    }))
}

fn execute_artifact_open(invocation: ArtifactOpenInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy)
        .context("OIDF artifact trust policy is invalid")?;
    let cached = open_cached_oidf_artifact(
        &invocation.cache_directory,
        &invocation.manifest_digest,
        &trust,
        &invocation.capabilities,
        current_unix_time()?,
    )
    .context("cached OIDF artifact verification failed")?;
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &serde_json::json!({
            "schema": 1,
            "opened": true,
            "cache": cached,
        }),
    )
    .context("failed to write cached artifact identity")?;
    writeln!(io::stdout()).context("failed to finish cached artifact identity")
}

fn print_artifact_open_help() {
    println!(
        "Usage:\n  nazoauthctl conformance artifact open --trust-policy PATH --cache-dir PATH --digest SHA256 [--capability NAME ...]\n\nThe command performs no network request or mutation. It opens only the exact immutable digest entry and revalidates its commit record, source, ES256 signature, current validity window, Suite identity, declarative driver and Matrix digests/sizes/schemas, resource bounds, engine protocol, and every caller-supplied capability requirement."
    );
}

struct ArtifactResolveInvocation {
    trust_policy: PathBuf,
    manifest_url: String,
    cache_directory: PathBuf,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_resolve_invocation(
    args: &[OsString],
) -> anyhow::Result<Option<ArtifactResolveInvocation>> {
    let mut values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("artifact resolution arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if values.first().map(String::as_str) != Some("conformance")
        || values.get(1).map(String::as_str) != Some("artifact")
        || values.get(2).map(String::as_str) != Some("resolve")
    {
        return Ok(None);
    }
    values.drain(..3);
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_artifact_resolve_help();
        std::process::exit(0);
    }
    let mut trust_policy = None;
    let mut manifest_url = None;
    let mut cache_directory = None;
    let mut capabilities = std::collections::BTreeSet::new();
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        if !matches!(
            option,
            "--trust-policy" | "--manifest-url" | "--cache-dir" | "--capability"
        ) {
            bail!("unknown conformance artifact resolve option: {option}");
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--trust-policy" => {
                set_once(&mut trust_policy, PathBuf::from(value), option)?;
            }
            "--manifest-url" => set_once(&mut manifest_url, value, option)?,
            "--cache-dir" => {
                set_once(&mut cache_directory, PathBuf::from(value), option)?;
            }
            "--capability" => {
                if !capabilities.insert(value) {
                    bail!("--capability values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(Some(ArtifactResolveInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        manifest_url: manifest_url.context("--manifest-url is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        capabilities,
    }))
}

fn execute_artifact_resolve(invocation: ArtifactResolveInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy)
        .context("OIDF artifact trust policy is invalid")?;
    let resolution = resolve_oidf_artifact(
        &invocation.manifest_url,
        &trust,
        &invocation.capabilities,
        &invocation.cache_directory,
        current_unix_time()?,
    )
    .context("OIDF artifact discovery failed")?;
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &serde_json::json!({
            "schema": 1,
            "resolved": true,
            "resolution": resolution,
        }),
    )
    .context("failed to write resolved artifact identity")?;
    writeln!(io::stdout()).context("failed to finish resolved artifact identity")
}

fn print_artifact_resolve_help() {
    println!(
        "Usage:\n  nazoauthctl conformance artifact resolve --trust-policy PATH --manifest-url HTTPS_URL --cache-dir PATH [--capability NAME ...]\n\nThe command fetches a bounded manifest without redirects, verifies it before following the signed declarative driver and Matrix URLs, verifies both exact payloads, and commits an immutable owner-only cache entry with a final verified record marker. It performs no NazoAuth or Suite mutation."
    );
}

struct ArtifactVerifyInvocation {
    trust_policy: PathBuf,
    manifest: PathBuf,
    driver: PathBuf,
    matrix: PathBuf,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_verify_invocation(
    args: &[OsString],
) -> anyhow::Result<Option<ArtifactVerifyInvocation>> {
    let mut values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("artifact verification arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if values.first().map(String::as_str) != Some("conformance")
        || values.get(1).map(String::as_str) != Some("artifact")
        || values.get(2).map(String::as_str) != Some("verify")
    {
        return Ok(None);
    }
    values.drain(..3);
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_artifact_verify_help();
        std::process::exit(0);
    }
    let mut trust_policy = None;
    let mut manifest = None;
    let mut driver = None;
    let mut matrix = None;
    let mut capabilities = std::collections::BTreeSet::new();
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        if !matches!(
            option,
            "--trust-policy" | "--manifest" | "--driver" | "--matrix" | "--capability"
        ) {
            bail!("unknown conformance artifact verify option: {option}");
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--trust-policy" => {
                set_once(&mut trust_policy, PathBuf::from(value), option)?;
            }
            "--manifest" => set_once(&mut manifest, PathBuf::from(value), option)?,
            "--driver" => set_once(&mut driver, PathBuf::from(value), option)?,
            "--matrix" => set_once(&mut matrix, PathBuf::from(value), option)?,
            "--capability" => {
                if !capabilities.insert(value) {
                    bail!("--capability values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(Some(ArtifactVerifyInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        manifest: manifest.context("--manifest is required")?,
        driver: driver.context("--driver is required")?,
        matrix: matrix.context("--matrix is required")?,
        capabilities,
    }))
}

fn execute_artifact_verify(invocation: ArtifactVerifyInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy)
        .context("OIDF artifact trust policy is invalid")?;
    let manifest = read_compact_manifest(&invocation.manifest)
        .context("signed OIDF driver manifest is invalid")?;
    let driver =
        read_artifact_driver(&invocation.driver).context("OIDF driver payload is invalid")?;
    let matrix =
        read_artifact_matrix(&invocation.matrix).context("OIDF artifact matrix is invalid")?;
    let artifact = verify_oidf_artifact(
        &manifest,
        &driver,
        &matrix,
        &trust,
        &invocation.capabilities,
        current_unix_time()?,
    )
    .context("OIDF artifact verification failed")?;
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &serde_json::json!({
            "schema": 1,
            "verified": true,
            "artifact": artifact,
        }),
    )
    .context("failed to write verified artifact identity")?;
    writeln!(io::stdout()).context("failed to finish verified artifact identity")
}

fn current_unix_time() -> anyhow::Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(now).context("system clock exceeds the supported range")
}

fn print_artifact_verify_help() {
    println!(
        "Usage:\n  nazoauthctl conformance artifact verify --trust-policy PATH --manifest PATH --driver PATH --matrix PATH [--capability NAME ...]\n\nThe command performs no NazoAuth or Suite mutation. It emits a verified identity only after the local trust policy, ES256 signature, source, validity window, Suite identity, declarative driver digest/size/schema, matrix digest/size/schema, resource bounds, and all required capabilities have been accepted."
    );
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
    let _ = writeln!(io::stderr(), "nazoauthctl failed: {error:#}");
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
    webdriver: Vec<String>,
    evidence_directory: Option<PathBuf>,
    proxy_trust_bundle: Option<PathBuf>,
    proxy_reload_executable: Option<PathBuf>,
    groups: Vec<String>,
    plans: Vec<String>,
    poll_timeout: Duration,
    lease_ttl_seconds: u64,
    jobs: usize,
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
    let mut webdriver = Vec::new();
    let mut evidence_directory = None;
    let mut proxy_trust_bundle = None;
    let mut proxy_reload_executable = None;
    let mut groups = Vec::new();
    let mut plans = Vec::new();
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut lease_ttl_seconds = DEFAULT_LEASE_TTL_SECONDS;
    let mut jobs = DEFAULT_JOBS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--suite"
            | "--token"
            | "--token-file"
            | "--token-fd"
            | "--webdriver"
            | "--evidence-dir"
            | "--proxy-trust-bundle"
            | "--proxy-reload-executable"
            | "--group"
            | "--plan"
            | "--poll-timeout"
            | "--lease-ttl"
            | "--jobs" => {
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
                    "--webdriver" => webdriver.push(value),
                    "--evidence-dir" => {
                        set_once(&mut evidence_directory, PathBuf::from(value), option)?;
                    }
                    "--proxy-trust-bundle" => {
                        set_once(&mut proxy_trust_bundle, PathBuf::from(value), option)?;
                    }
                    "--proxy-reload-executable" => {
                        set_once(&mut proxy_reload_executable, PathBuf::from(value), option)?;
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
                    "--jobs" => {
                        jobs = value
                            .parse::<usize>()
                            .context("--jobs must be an integer")?;
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
    if proxy_trust_bundle.is_some() != proxy_reload_executable.is_some() {
        bail!("--proxy-trust-bundle and --proxy-reload-executable must be specified together");
    }
    let distinct_webdrivers = webdriver.iter().collect::<std::collections::BTreeSet<_>>();
    if poll_timeout.is_zero()
        || poll_timeout > Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS)
        || !(300..=86_400).contains(&lease_ttl_seconds)
        || !(1..=MAX_PARALLEL_JOBS).contains(&jobs)
        || (!webdriver.is_empty()
            && (webdriver.len() != jobs || distinct_webdrivers.len() != webdriver.len()))
    {
        bail!(
            "poll timeout must be between 1 and {MAX_POLL_TIMEOUT_SECONDS} seconds, lease TTL must be between 300 and 86400 seconds, jobs must be between 1 and {MAX_PARALLEL_JOBS}, and explicit WebDriver endpoints must be distinct and repeated exactly once per job"
        );
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
        proxy_trust_bundle,
        proxy_reload_executable,
        groups,
        plans,
        poll_timeout,
        lease_ttl_seconds,
        jobs,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        bail!("{option} may be specified only once");
    }
    Ok(())
}

fn push_unique(
    values: &mut std::collections::BTreeSet<String>,
    value: String,
    option: &str,
) -> anyhow::Result<()> {
    if !values.insert(value) {
        bail!("{option} values must be unique");
    }
    Ok(())
}

fn push_unique_vec(values: &mut Vec<String>, value: String, option: &str) -> anyhow::Result<()> {
    if values.contains(&value) {
        bail!("{option} values must be unique");
    }
    values.push(value);
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
    let deployment_evidence = session.deployment_evidence();

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
    let hosted_email = Zeroizing::new(prepared.applicant_email().to_owned());
    let hosted_password = prepared.applicant_password();
    let mut proxy_trust = match (
        invocation.proxy_trust_bundle.as_deref(),
        invocation.proxy_reload_executable.as_deref(),
    ) {
        (Some(bundle_path), Some(reload_executable)) => {
            match ProxyTrustGuard::install(
                bundle_path,
                reload_executable,
                prepared.mtls_trust_anchor_pem().as_bytes(),
            ) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    return match session.cleanup_lease(&lease_id) {
                        Ok(()) => Err(error).context(
                            "failed to install the run-scoped proxy trust bundle; onboarding lease rolled back",
                        ),
                        Err(cleanup) => bail!(
                            "failed to install the run-scoped proxy trust bundle and onboarding lease rollback also failed: proxy={error:#}; cleanup={cleanup:#}"
                        ),
                    };
                }
            }
        }
        (None, None) => None,
        _ => unreachable!(),
    };

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
        let target_origin = BrowserTargetOrigin::parse(session.target_issuer())?;
        let openid4vci_management_token = session
            .openid4vci_management_token()
            .context("failed to load the deployment OpenID4VCI management token")?;
        let openid4vp_management_token = session
            .openid4vp_management_token()
            .context("failed to load the deployment OpenID4VP management token")?;
        let mut automation = Vec::with_capacity(invocation.jobs);
        for worker_index in 0..invocation.jobs {
            let browser = build_browser(
                invocation.webdriver.get(worker_index).map(String::as_str),
                session.target_issuer(),
                &suite_origin,
            )?;
            let issuer: Arc<Mutex<dyn OpenId4VciIssuerDriver>> =
                Arc::new(Mutex::new(OpenId4VciIssuerClient::new(
                    OpenId4VciIssuerConfig::new(
                        target_origin.clone(),
                        suite_origin.clone(),
                        applicant_id,
                        static_tx_code.clone(),
                        hosted_email.clone(),
                        hosted_password.clone(),
                        Duration::from_secs(30),
                    )?,
                    openid4vci_management_token.clone(),
                    token.clone(),
                )?));
            let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> =
                Arc::new(Mutex::new(OpenId4VpVerifierClient::new(
                    target_origin.clone(),
                    suite_origin.clone(),
                    openid4vp_management_token.clone(),
                    Duration::from_secs(30),
                    binding.clone(),
                )?));
            automation.push(ConformanceAutomation {
                browser: Some(browser),
                verifier: Some(verifier),
                issuer: Some(issuer),
            });
        }
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
            target_origin: Some(target_origin),
            binding,
            poll_timeout: invocation.poll_timeout,
            control,
            jobs: invocation.jobs,
            automation,
        })?;
        let summary = if io::stderr().is_terminal() {
            let mut renderer = TtyRenderer::new(io::stderr().lock());
            runner.run(&mut renderer)
        } else {
            let mut renderer = StableRenderer::new(io::stderr().lock());
            runner.run(&mut renderer)
        };
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
            evidence: None,
        })
    })();

    let lease_cleanup = session.cleanup_lease(&lease_id);
    let proxy_cleanup = proxy_trust
        .as_mut()
        .map(ProxyTrustGuard::restore)
        .transpose();
    let mut errors = Vec::new();
    let mut output = match run_result {
        Ok(output) => Some(output),
        Err(error) => {
            errors.push(format!("run={error:#}"));
            None
        }
    };
    let lease_cleanup_complete = lease_cleanup.is_ok();
    let proxy_cleanup_complete = proxy_cleanup.is_ok();
    if let Err(error) = lease_cleanup {
        errors.push(format!("lease-cleanup={error:#}"));
    }
    if let Err(error) = proxy_cleanup {
        errors.push(format!("proxy-cleanup={error:#}"));
    }
    if let Some(output) = &mut output {
        output.deployment.cleanup_complete = lease_cleanup_complete && proxy_cleanup_complete;
        if let Some(directory) = &invocation.evidence_directory {
            let runtime = match &deployment_evidence.runtime {
                nazoauthctl_core::ConformanceRuntimeEvidence::OciImage { digest } => {
                    EvidenceRuntimeIdentity::OciImage {
                        digest: digest.clone(),
                    }
                }
                nazoauthctl_core::ConformanceRuntimeEvidence::HostBinary { sha256 } => {
                    EvidenceRuntimeIdentity::HostBinary {
                        sha256: sha256.clone(),
                    }
                }
            };
            let identity = EvidenceBundleIdentity {
                run_jti: request_jti.clone(),
                deployment: EvidenceDeploymentIdentity {
                    deployment_id: deployment_evidence.deployment_id.clone(),
                    target_issuer: deployment_evidence.target_issuer.clone(),
                    release: deployment_evidence.release.clone(),
                    revision: deployment_evidence.revision.clone(),
                    build_id: deployment_evidence.build_id.clone(),
                    runtime,
                },
                source: EvidenceSourceIdentity::LegacyOperatorMatrix {
                    source_release: matrix.source_release.clone(),
                    matrix_sha256: matrix.sha256.clone(),
                    suite_origin: suite_origin.to_string(),
                },
                outer_cleanup_complete: output.deployment.cleanup_complete,
            };
            match write_private_evidence_bundle(&output.report, directory, &identity) {
                Ok(receipt) => output.evidence = Some(receipt),
                Err(error) => errors.push(format!("evidence={error}")),
            }
        }
    }
    let (final_output, exit_code) = finalize_run_output(output, errors);
    serde_json::to_writer_pretty(io::stdout().lock(), &final_output)
        .context("failed to write the structured conformance report")?;
    writeln!(io::stdout()).context("failed to finish the structured conformance report")?;
    Ok(exit_code)
}

fn finalize_run_output(output: Option<RunOutput>, errors: Vec<String>) -> (FinalOutput, i32) {
    let success = errors.is_empty()
        && output.as_ref().is_some_and(|output| {
            output.report.local_success
                && output.report.suite_pass
                && output.deployment.cleanup_complete
        });
    (
        FinalOutput {
            schema: 2,
            success,
            errors,
            run: output,
        },
        if success { 0 } else { 1 },
    )
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
    errors: Vec<String>,
    run: Option<RunOutput>,
}

#[derive(Serialize)]
struct RunOutput {
    deployment: DeploymentReport,
    report: nazoauthctl_conformance::ConformanceReport,
    evidence: Option<EvidenceBundleReceipt>,
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
        "Usage:\n  nazoauthctl [--deployment ID_OR_ALIAS] [--config PATH] conformance run [options]\n\nOptions:\n  --suite URL                    OpenID Foundation Suite origin (default: official Suite)\n  --token TOKEN                  API token; visible in argv/shell history\n  --token-file PATH              Read token from a private regular file\n  --token-stdin                  Read token from stdin\n  --token-fd FD                  Read token from an inherited private descriptor\n  --webdriver URL                Dedicated W3C endpoint; repeat exactly once per job\n  --evidence-dir PATH            Commit a unique digest-bound private evidence bundle\n  --proxy-trust-bundle PATH      Atomically install this run's public client CAs\n  --proxy-reload-executable PATH Root-owned executable that validates/reloads the proxy\n  --group ID                     Run one Matrix group; repeat to select more\n  --plan ID                      Run one Matrix plan; repeat to select more\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)\n  --lease-ttl SECONDS            Deployment lease lifetime (default: 14400)"
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
    fn artifact_open_requires_exact_cache_identity_and_unique_capabilities() {
        let digest = "a".repeat(64);
        let parsed = parse_artifact_open_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "artifact",
            "open",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--digest",
            &digest,
            "--capability",
            "nazoauth.client.create",
        ]))
        .expect("parse")
        .expect("artifact cache open");
        assert_eq!(parsed.manifest_digest, digest);
        assert_eq!(
            parsed.cache_directory,
            PathBuf::from("/var/lib/nazoauthctl/oidf-cache")
        );
        assert!(parsed.capabilities.contains("nazoauth.client.create"));
        assert!(
            parse_run_invocation(&args(&["nazoauthctl", "conformance", "artifact", "open",]))
                .expect("run parser")
                .is_none()
        );

        assert!(
            parse_artifact_open_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "open",
                "--trust-policy",
                "/trust.json",
                "--cache-dir",
                "/cache",
            ]))
            .is_err()
        );
        assert!(
            parse_artifact_open_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "open",
                "--trust-policy",
                "/trust.json",
                "--cache-dir",
                "/cache",
                "--digest",
                &digest,
                "--capability",
                "nazoauth.client.create",
                "--capability",
                "nazoauth.client.create",
            ]))
            .is_err()
        );
    }

    #[test]
    fn artifact_plan_is_a_separate_read_only_selection_command() {
        let digest = "a".repeat(64);
        let parsed = parse_artifact_plan_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "artifact",
            "plan",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--digest",
            &digest,
            "--capability",
            "nazoauth.client.create",
            "--group",
            "oidc",
            "--plan",
            "p001",
        ]))
        .expect("parse")
        .expect("artifact plan");
        assert_eq!(parsed.manifest_digest, digest);
        assert_eq!(parsed.selection.groups, ["oidc"]);
        assert_eq!(parsed.selection.plans, ["p001"]);
        assert!(parsed.capabilities.contains("nazoauth.client.create"));
        assert!(
            parse_run_invocation(&args(&["nazoauthctl", "conformance", "artifact", "plan"]))
                .expect("run parser")
                .is_none()
        );
    }

    #[test]
    fn artifact_plan_requires_closed_unique_inputs() {
        let digest = "a".repeat(64);
        assert!(
            parse_artifact_plan_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "plan",
                "--trust-policy",
                "/trust.json",
                "--cache-dir",
                "/cache",
            ]))
            .is_err()
        );
        for option in ["--capability", "--group", "--plan"] {
            assert!(
                parse_artifact_plan_invocation(&args(&[
                    "nazoauthctl",
                    "conformance",
                    "artifact",
                    "plan",
                    "--trust-policy",
                    "/trust.json",
                    "--cache-dir",
                    "/cache",
                    "--digest",
                    &digest,
                    option,
                    "duplicate",
                    option,
                    "duplicate",
                ]))
                .is_err(),
                "duplicate {option} must fail"
            );
        }
    }

    #[test]
    fn artifact_verify_is_a_separate_non_deployment_command() {
        let parsed = parse_artifact_verify_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "artifact",
            "verify",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--manifest",
            "/tmp/manifest.jws",
            "--driver",
            "/tmp/driver.json",
            "--matrix",
            "/tmp/matrix.json",
            "--capability",
            "nazoauth.client.create",
        ]))
        .expect("parse")
        .expect("artifact verification");
        assert_eq!(
            parsed.trust_policy,
            PathBuf::from("/etc/nazoauthctl/oidf-trust.json")
        );
        assert!(parsed.capabilities.contains("nazoauth.client.create"));
        assert_eq!(parsed.driver, PathBuf::from("/tmp/driver.json"));
        assert!(
            parse_run_invocation(&args(
                &["nazoauthctl", "conformance", "artifact", "verify",]
            ))
            .expect("run parser")
            .is_none()
        );
    }

    #[test]
    fn artifact_verify_requires_closed_unique_inputs() {
        assert!(
            parse_artifact_verify_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "verify",
                "--trust-policy",
                "/trust.json",
            ]))
            .is_err()
        );
        assert!(
            parse_artifact_verify_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "verify",
                "--trust-policy",
                "/trust.json",
                "--manifest",
                "/manifest.jws",
                "--driver",
                "/driver.json",
                "--matrix",
                "/matrix.json",
                "--capability",
                "nazoauth.client.create",
                "--capability",
                "nazoauth.client.create",
            ]))
            .is_err()
        );
    }

    #[test]
    fn artifact_resolve_requires_trust_channel_cache_and_unique_capabilities() {
        let parsed = parse_artifact_resolve_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "artifact",
            "resolve",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--manifest-url",
            "https://artifacts.example/oidf/stable/driver.jws",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--capability",
            "nazoauth.client.create",
        ]))
        .expect("parse")
        .expect("artifact resolution");
        assert_eq!(
            parsed.manifest_url,
            "https://artifacts.example/oidf/stable/driver.jws"
        );
        assert_eq!(
            parsed.cache_directory,
            PathBuf::from("/var/lib/nazoauthctl/oidf-cache")
        );
        assert!(parsed.capabilities.contains("nazoauth.client.create"));

        assert!(
            parse_artifact_resolve_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "resolve",
                "--trust-policy",
                "/trust.json",
                "--manifest-url",
                "https://artifacts.example/driver.jws",
            ]))
            .is_err()
        );
        assert!(
            parse_artifact_resolve_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "artifact",
                "resolve",
                "--trust-policy",
                "/trust.json",
                "--manifest-url",
                "https://artifacts.example/driver.jws",
                "--cache-dir",
                "/cache",
                "--capability",
                "nazoauth.client.create",
                "--capability",
                "nazoauth.client.create",
            ]))
            .is_err()
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
            "--jobs",
            "3",
        ]))
        .expect("parse")
        .expect("run");
        assert_eq!(parsed.deployment.as_deref(), Some("prod"));
        assert_eq!(parsed.config, PathBuf::from("/x/update.json"));
        assert_eq!(parsed.token_fd, Some(7));
        assert_eq!(parsed.groups, ["oidc"]);
        assert_eq!(parsed.plans, ["oidc-core-p001"]);
        assert_eq!(parsed.jobs, 3);
    }

    #[test]
    fn run_rejects_jobs_outside_the_validated_bound() {
        for jobs in ["0", "5"] {
            let error = match parse_run_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "run",
                "--jobs",
                jobs,
            ])) {
                Err(error) => error,
                Ok(_) => panic!("jobs outside 1-4 must fail"),
            };
            assert!(error.to_string().contains("jobs must be between 1 and 4"));
        }
    }

    #[test]
    fn run_rejects_poll_timeout_above_the_validated_bound() {
        let error = match parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--poll-timeout",
            "86401",
        ])) {
            Err(error) => error,
            Ok(_) => panic!("poll timeout above the bound must fail"),
        };
        assert!(
            error
                .to_string()
                .contains("poll timeout must be between 1 and 86400 seconds")
        );
    }

    #[test]
    fn proxy_trust_bundle_and_reload_executable_are_atomic_pair() {
        let missing_reload = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--proxy-trust-bundle",
            "/run/proxy/client-cas.pem",
        ]));
        assert!(missing_reload.is_err());

        let parsed = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--proxy-trust-bundle",
            "/run/proxy/client-cas.pem",
            "--proxy-reload-executable",
            "/usr/local/sbin/reload-nazoauth-proxy",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed.proxy_trust_bundle,
            Some(PathBuf::from("/run/proxy/client-cas.pem"))
        );
        assert_eq!(
            parsed.proxy_reload_executable,
            Some(PathBuf::from("/usr/local/sbin/reload-nazoauth-proxy"))
        );
    }

    #[test]
    fn explicit_webdrivers_are_distinct_and_one_per_job() {
        let one = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--jobs",
            "2",
            "--webdriver",
            "http://127.0.0.1:24444/wd/hub",
        ]));
        assert!(one.is_err());

        let duplicate = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--jobs",
            "2",
            "--webdriver",
            "http://127.0.0.1:24444/wd/hub",
            "--webdriver",
            "http://127.0.0.1:24444/wd/hub",
        ]));
        assert!(duplicate.is_err());

        let distinct = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--jobs",
            "2",
            "--webdriver",
            "http://127.0.0.1:24444/wd/hub",
            "--webdriver",
            "http://127.0.0.1:24445/wd/hub",
        ]))
        .expect("parse")
        .expect("run");
        assert_eq!(distinct.webdriver.len(), 2);
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

    #[test]
    fn cleanup_failure_preserves_completed_structured_run_as_failed() {
        let report = serde_json::from_value(serde_json::json!({
            "schema": 3,
            "matrix_digest": "a".repeat(64),
            "suite_origin": "https://suite.example",
            "auth_probe": null,
            "errors": [],
            "local_success": true,
            "suite_pass": true,
            "human_review_required": false,
            "human_review_modules": [],
            "skipped_modules": [],
            "failed_modules": [],
            "incomplete_modules": [],
            "orchestration_integrity": {
                "defined_modules": 1,
                "created_instances": 1,
                "terminal_modules": 1,
                "all_modules_instantiated": true,
                "all_modules_terminal": true,
                "cleanup_complete": true
            },
            "progress": {
                "completed": 1,
                "total": 1,
                "groups": [],
                "passed_groups": 1,
                "review_groups": 0,
                "skipped_groups": 0,
                "failed_groups": 0,
                "running_groups": 0,
                "remaining_groups": 0,
                "passed": 1,
                "reviewed": 0,
                "skipped": 0,
                "failed": 0,
                "running": 0,
                "remaining": 0,
                "current_profile": null,
                "current_variant": null,
                "current_test": null
            },
            "plans": [],
            "modules": [],
            "cleanup": {
                "cancelled": [],
                "deleted_plans": [],
                "immutable_plans": [],
                "failures": []
            }
        }))
        .expect("report");
        let output = RunOutput {
            deployment: DeploymentReport {
                matrix_sha256: "a".repeat(64),
                matrix_source_release: "v1".to_owned(),
                matrix_groups: 1,
                matrix_plans: 1,
                selected_groups: 1,
                selected_plans: 1,
                lease_id: "lease-a".to_owned(),
                applicant_id: uuid::Uuid::nil().to_string(),
                client_count: 1,
                expires_at: 1,
                idempotent_replay: false,
                cleanup_complete: false,
            },
            report,
            evidence: None,
        };
        let (final_output, exit_code) =
            finalize_run_output(Some(output), vec!["lease-cleanup=failed".to_owned()]);

        assert_eq!(exit_code, 1);
        assert!(!final_output.success);
        assert_eq!(final_output.errors, ["lease-cleanup=failed"]);
        assert!(final_output.run.is_some());
        assert!(
            !final_output
                .run
                .expect("preserved run")
                .deployment
                .cleanup_complete
        );
    }
}
