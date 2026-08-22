use std::env;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use nazoauthctl_conformance::{
    ArtifactTrustPolicy, MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS, OidfPlanSelection,
    open_cached_oidf_artifact, open_cached_oidf_driver_plan, read_artifact_driver,
    read_artifact_matrix, read_compact_manifest, resolve_oidf_artifact, verify_oidf_artifact,
};
use zeroize::Zeroizing;

mod ordinary_run;

const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_JOBS: usize = 4;

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

    match ordinary_run::execute(invocation) {
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

pub(crate) struct RunInvocation {
    pub(crate) config: PathBuf,
    pub(crate) deployment: Option<String>,
    pub(crate) trust_policy: PathBuf,
    pub(crate) artifact_cache: PathBuf,
    pub(crate) artifact_digest: String,
    pub(crate) tenant_id: String,
    pub(crate) suite: Option<String>,
    pub(crate) token: Option<Zeroizing<String>>,
    pub(crate) token_file: Option<PathBuf>,
    pub(crate) token_stdin: bool,
    pub(crate) token_fd: Option<u32>,
    pub(crate) webdriver: Vec<String>,
    pub(crate) evidence_directory: Option<PathBuf>,
    pub(crate) capture_review_screenshots: bool,
    pub(crate) retain_suite_plans_for_certification: bool,
    pub(crate) proxy_trust_bundle: Option<PathBuf>,
    pub(crate) proxy_reload_executable: Option<PathBuf>,
    pub(crate) ciba_user_approval_callback_url: Option<String>,
    pub(crate) ciba_user_approval_listen: Option<std::net::SocketAddr>,
    pub(crate) groups: Vec<String>,
    pub(crate) plans: Vec<String>,
    pub(crate) poll_timeout: Duration,
    pub(crate) jobs: usize,
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

    let mut trust_policy = None;
    let mut artifact_cache = None;
    let mut artifact_digest = None;
    let mut tenant_id = None;
    let mut suite = None;
    let mut token = None;
    let mut token_file = None;
    let mut token_stdin = false;
    let mut token_fd = None;
    let mut webdriver = Vec::new();
    let mut evidence_directory = None;
    let mut capture_review_screenshots = false;
    let mut retain_suite_plans_for_certification = false;
    let mut proxy_trust_bundle = None;
    let mut proxy_reload_executable = None;
    let mut ciba_user_approval_callback_url = None;
    let mut ciba_user_approval_listen = None;
    let mut groups = Vec::new();
    let mut plans = Vec::new();
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut jobs = DEFAULT_JOBS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--trust-policy"
            | "--artifact-cache"
            | "--artifact-digest"
            | "--tenant-id"
            | "--suite"
            | "--token"
            | "--token-file"
            | "--token-fd"
            | "--webdriver"
            | "--evidence-dir"
            | "--proxy-trust-bundle"
            | "--proxy-reload-executable"
            | "--ciba-user-approval-callback-url"
            | "--ciba-user-approval-listen"
            | "--group"
            | "--plan"
            | "--poll-timeout"
            | "--jobs" => {
                let value = values
                    .get(index + 1)
                    .with_context(|| format!("{option} requires a value"))?
                    .clone();
                match option {
                    "--trust-policy" => {
                        set_once(&mut trust_policy, PathBuf::from(value), option)?;
                    }
                    "--artifact-cache" => {
                        set_once(&mut artifact_cache, PathBuf::from(value), option)?;
                    }
                    "--artifact-digest" => set_once(&mut artifact_digest, value, option)?,
                    "--tenant-id" => set_once(&mut tenant_id, value, option)?,
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
                    "--ciba-user-approval-callback-url" => {
                        set_once(&mut ciba_user_approval_callback_url, value, option)?;
                    }
                    "--ciba-user-approval-listen" => {
                        let address = value.parse::<std::net::SocketAddr>().context(
                            "--ciba-user-approval-listen must be an IP address and port",
                        )?;
                        set_once(&mut ciba_user_approval_listen, address, option)?;
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
            "--retain-suite-plans-for-certification" => {
                if retain_suite_plans_for_certification {
                    bail!("--retain-suite-plans-for-certification may be specified only once");
                }
                retain_suite_plans_for_certification = true;
                index += 1;
            }
            "--capture-review-screenshots" => {
                if capture_review_screenshots {
                    bail!("--capture-review-screenshots may be specified only once");
                }
                capture_review_screenshots = true;
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
    if ciba_user_approval_callback_url.is_some() != ciba_user_approval_listen.is_some() {
        bail!(
            "--ciba-user-approval-callback-url and --ciba-user-approval-listen must be specified together"
        );
    }
    if capture_review_screenshots && evidence_directory.is_none() {
        bail!("--capture-review-screenshots requires --evidence-dir");
    }
    let trust_policy = trust_policy.context("--trust-policy is required")?;
    let artifact_cache = artifact_cache.context("--artifact-cache is required")?;
    let artifact_digest = artifact_digest.context("--artifact-digest is required")?;
    if artifact_digest.len() != 64
        || !artifact_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("--artifact-digest must be 64 lowercase hexadecimal characters");
    }
    let tenant_id = tenant_id.context("--tenant-id is required")?;
    let parsed_tenant =
        uuid::Uuid::parse_str(&tenant_id).context("--tenant-id must be a canonical UUID")?;
    if parsed_tenant.hyphenated().to_string() != tenant_id {
        bail!("--tenant-id must be a canonical UUID");
    }
    let distinct_webdrivers = webdriver.iter().collect::<std::collections::BTreeSet<_>>();
    if poll_timeout.is_zero()
        || poll_timeout > Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS)
        || !(1..=MAX_PARALLEL_JOBS).contains(&jobs)
        || (!webdriver.is_empty()
            && (webdriver.len() != jobs || distinct_webdrivers.len() != webdriver.len()))
    {
        bail!(
            "poll timeout must be between 1 and {MAX_POLL_TIMEOUT_SECONDS} seconds, jobs must be between 1 and {MAX_PARALLEL_JOBS}, and explicit WebDriver endpoints must be distinct and repeated exactly once per job"
        );
    }
    Ok(Some(RunInvocation {
        config,
        deployment,
        trust_policy,
        artifact_cache,
        artifact_digest,
        tenant_id,
        suite,
        token,
        token_file,
        token_stdin,
        token_fd,
        webdriver,
        evidence_directory,
        capture_review_screenshots,
        retain_suite_plans_for_certification,
        proxy_trust_bundle,
        proxy_reload_executable,
        ciba_user_approval_callback_url,
        ciba_user_approval_listen,
        groups,
        plans,
        poll_timeout,
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

fn print_run_help() {
    println!(
        "Usage:\n  nazoauthctl [--deployment ID_OR_ALIAS] [--config PATH] conformance run --trust-policy PATH --artifact-cache PATH --artifact-digest SHA256 --tenant-id UUID [options]\n\nRequired:\n  --trust-policy PATH            Signed-artifact trust policy\n  --artifact-cache PATH          Private immutable artifact cache root\n  --artifact-digest SHA256       Exact cached compact-manifest digest (64 lowercase hex)\n  --tenant-id UUID               Canonical target tenant UUID\n\nOptions:\n  --suite URL                    OpenID Foundation Suite origin (default: official Suite)\n  --token TOKEN                  API token; visible in argv/shell history\n  --token-file PATH              Read token from a private regular file\n  --token-stdin                  Read token from stdin\n  --token-fd FD                  Read token from an inherited private descriptor\n  --webdriver URL                Dedicated W3C endpoint; repeat exactly once per job\n  --evidence-dir PATH            Commit a unique provider-bound private evidence bundle\n  --capture-review-screenshots   Capture signed review placeholders locally into --evidence-dir\n  --retain-suite-plans-for-certification\n                               Retain terminal plans only at the official Suite for manual review\n  --proxy-trust-bundle PATH      Atomically install this run's public client CAs\n  --proxy-reload-executable PATH Root-owned executable that validates/reloads the proxy\n  --group ID                     Run one signed Matrix group; repeat to select more\n  --plan ID                      Run one signed Matrix plan; repeat to select more\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)"
    );
    println!(
        "  --ciba-user-approval-callback-url URL  Public HTTPS callback forwarded only to the local Ctl listener\n  --ciba-user-approval-listen ADDR       Loopback IP:port for that callback"
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
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
            "--evidence-dir",
            "/x/evidence",
            "--capture-review-screenshots",
            "--retain-suite-plans-for-certification",
        ]))
        .expect("parse")
        .expect("run");
        assert_eq!(parsed.deployment.as_deref(), Some("prod"));
        assert_eq!(parsed.config, PathBuf::from("/x/update.json"));
        assert_eq!(parsed.trust_policy, PathBuf::from("/x/trust.json"));
        assert_eq!(parsed.artifact_cache, PathBuf::from("/x/cache"));
        assert_eq!(parsed.artifact_digest, "a".repeat(64));
        assert_eq!(parsed.tenant_id, uuid::Uuid::nil().to_string());
        assert_eq!(parsed.token_fd, Some(7));
        assert_eq!(parsed.groups, ["oidc"]);
        assert!(parsed.retain_suite_plans_for_certification);
        assert!(parsed.capture_review_screenshots);
        assert_eq!(parsed.plans, ["oidc-core-p001"]);
        assert_eq!(parsed.jobs, 3);
    }

    #[test]
    fn review_screenshot_capture_requires_an_explicit_evidence_directory() {
        let error = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
            "--capture-review-screenshots",
        ]))
        .err()
        .expect("capture needs evidence root");
        assert!(error.to_string().contains("requires --evidence-dir"));
    }

    #[test]
    fn run_rejects_jobs_outside_the_validated_bound() {
        for jobs in ["0", "5"] {
            let error = match parse_run_invocation(&args(&[
                "nazoauthctl",
                "conformance",
                "run",
                "--trust-policy",
                "/x/trust.json",
                "--artifact-cache",
                "/x/cache",
                "--artifact-digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--tenant-id",
                "00000000-0000-0000-0000-000000000000",
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
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
    fn run_requires_exact_ordinary_identity_and_rejects_lease_options() {
        let missing = parse_run_invocation(&args(&["nazoauthctl", "conformance", "run"]));
        let missing = match missing {
            Err(error) => error,
            Ok(_) => panic!("ordinary identity is required"),
        };
        assert!(missing.to_string().contains("--trust-policy is required"));

        let lease = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
            "--lease-ttl",
            "14400",
        ]));
        let lease = match lease {
            Err(error) => error,
            Ok(_) => panic!("lease options must be rejected"),
        };
        assert!(
            lease
                .to_string()
                .contains("unknown conformance run option: --lease-ttl")
        );

        let uppercase_digest = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
        ]));
        let uppercase_digest = match uppercase_digest {
            Err(error) => error,
            Ok(_) => panic!("uppercase artifact digest must fail"),
        };
        assert!(
            uppercase_digest
                .to_string()
                .contains("64 lowercase hexadecimal characters")
        );

        let noncanonical_tenant = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000000000000000000000000000",
        ]));
        let noncanonical_tenant = match noncanonical_tenant {
            Err(error) => error,
            Ok(_) => panic!("noncanonical tenant UUID must fail"),
        };
        assert!(noncanonical_tenant.to_string().contains("canonical UUID"));
    }

    #[test]
    fn proxy_trust_bundle_and_reload_executable_are_atomic_pair() {
        let missing_reload = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
            "--proxy-trust-bundle",
            "/run/proxy/client-cas.pem",
        ]));
        assert!(missing_reload.is_err());

        let parsed = parse_run_invocation(&args(&[
            "nazoauthctl",
            "conformance",
            "run",
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
            "--trust-policy",
            "/x/trust.json",
            "--artifact-cache",
            "/x/cache",
            "--artifact-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
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
}
