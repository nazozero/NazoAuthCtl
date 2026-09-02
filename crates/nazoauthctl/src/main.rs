use std::env;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use nazoauthctl_conformance::{
    ArtifactTrustPolicy, MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS, OidfPlanSelection,
    bundled_oidf_selection_choices, open_cached_oidf_artifact, open_cached_oidf_driver_plan,
    read_artifact_driver, read_artifact_matrix, read_compact_manifest,
    resolve_bundled_oidf_selection, resolve_oidf_artifact, verify_oidf_artifact,
};

mod ordinary_run;

const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_JOBS: usize = 4;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error),
    };
    let result = match invocation {
        Invocation::Core => {
            nazoauthctl_core::main_entry();
            return;
        }
        Invocation::ArtifactPlan(invocation) => execute_artifact_plan(invocation),
        Invocation::ArtifactOpen(invocation) => execute_artifact_open(invocation),
        Invocation::ArtifactResolve(invocation) => execute_artifact_resolve(invocation),
        Invocation::ArtifactVerify(invocation) => execute_artifact_verify(invocation),
        Invocation::Run(invocation) => ordinary_run::execute(*invocation).map(|code| {
            std::process::exit(code);
        }),
    };
    if let Err(error) = result {
        exit_with_error(&error);
    }
}

enum Invocation {
    Core,
    ArtifactPlan(ArtifactPlanInvocation),
    ArtifactOpen(ArtifactOpenInvocation),
    ArtifactResolve(ArtifactResolveInvocation),
    ArtifactVerify(ArtifactVerifyInvocation),
    Run(Box<RunInvocation>),
}

fn parse_invocation(args: &[OsString]) -> anyhow::Result<Invocation> {
    let values = args
        .iter()
        .skip(1)
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .context("command-line arguments must be valid UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let globals = nazoauthctl_core::parse_global_options(&values)?;
    let command = &values[globals.consumed..];
    let Some((family, command)) = command.split_first() else {
        return Ok(Invocation::Core);
    };
    if family != "oidf" {
        return Ok(Invocation::Core);
    }

    match command {
        [artifact, operation, options @ ..] if artifact == "artifact" => match operation.as_str() {
            "plan" => parse_artifact_plan_options(options).map(Invocation::ArtifactPlan),
            "open" => parse_artifact_open_options(options).map(Invocation::ArtifactOpen),
            "resolve" => parse_artifact_resolve_options(options).map(Invocation::ArtifactResolve),
            "verify" => parse_artifact_verify_options(options).map(Invocation::ArtifactVerify),
            other => bail!("unknown oidf artifact command: {other}"),
        },
        [command, options @ ..] if command == "run" => parse_run_options(options, globals.instance)
            .map(Box::new)
            .map(Invocation::Run),
        [command, ..] => bail!("unknown oidf command: {command}"),
        [] => bail!("an oidf command is required"),
    }
}

struct ArtifactPlanInvocation {
    trust_policy: PathBuf,
    cache_directory: PathBuf,
    manifest_digest: String,
    capabilities: std::collections::BTreeSet<String>,
    selection: OidfPlanSelection,
}

fn parse_artifact_plan_options(values: &[String]) -> anyhow::Result<ArtifactPlanInvocation> {
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
            "--trust-policy" | "--cache-dir" | "--digest" | "--require" | "--group" | "--plan"
        ) {
            bail!("unknown oidf artifact plan option: {option}");
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--trust-policy" => set_once(&mut trust_policy, PathBuf::from(value), option)?,
            "--cache-dir" => set_once(&mut cache_directory, PathBuf::from(value), option)?,
            "--digest" => set_once(&mut manifest_digest, value, option)?,
            "--require" => push_unique(&mut capabilities, value, option)?,
            "--group" => push_unique_vec(&mut groups, value, option)?,
            "--plan" => push_unique_vec(&mut plans, value, option)?,
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactPlanInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        manifest_digest: manifest_digest.context("--digest is required")?,
        capabilities,
        selection: OidfPlanSelection { groups, plans },
    })
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
        "Usage:\n  nazoauthctl oidf artifact plan --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...] [--group ID ...] [--plan ID ...]\n\nThis is a read-only, offline inspection plan. It revalidates one exact cached artifact and compiles exact signed Matrix selections. Caller-supplied capability names are not attested negotiation. The output is explicitly not deployment-bound or executable and creates no run journal or resources."
    );
}

struct ArtifactOpenInvocation {
    trust_policy: PathBuf,
    cache_directory: PathBuf,
    manifest_digest: String,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_open_options(values: &[String]) -> anyhow::Result<ArtifactOpenInvocation> {
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
            "--trust-policy" | "--cache-dir" | "--digest" | "--require"
        ) {
            bail!("unknown oidf artifact open option: {option}");
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
            "--require" => {
                if !capabilities.insert(value) {
                    bail!("--require values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactOpenInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        manifest_digest: manifest_digest.context("--digest is required")?,
        capabilities,
    })
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
        "Usage:\n  nazoauthctl oidf artifact open --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...]\n\nThe command performs no network request or mutation. It opens only the exact immutable digest entry and revalidates its commit record, source, ES256 signature, current validity window, Suite identity, declarative driver and Matrix digests/sizes/schemas, resource bounds, engine protocol, and every caller-supplied capability requirement."
    );
}

struct ArtifactResolveInvocation {
    trust_policy: PathBuf,
    manifest_url: String,
    cache_directory: PathBuf,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_resolve_options(values: &[String]) -> anyhow::Result<ArtifactResolveInvocation> {
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
            "--trust-policy" | "--manifest-url" | "--cache-dir" | "--require"
        ) {
            bail!("unknown oidf artifact resolve option: {option}");
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
            "--require" => {
                if !capabilities.insert(value) {
                    bail!("--require values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactResolveInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        manifest_url: manifest_url.context("--manifest-url is required")?,
        cache_directory: cache_directory.context("--cache-dir is required")?,
        capabilities,
    })
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
        "Usage:\n  nazoauthctl oidf artifact resolve --trust-policy PATH --manifest-url HTTPS_URL --cache-dir PATH [--require NAME ...]\n\nThe command fetches a bounded manifest without redirects, verifies it before following the signed declarative driver and Matrix URLs, verifies both exact payloads, and commits an immutable owner-only cache entry with a final verified record marker. It performs no NazoAuth or Suite mutation."
    );
}

struct ArtifactVerifyInvocation {
    trust_policy: PathBuf,
    manifest: PathBuf,
    driver: PathBuf,
    matrix: PathBuf,
    capabilities: std::collections::BTreeSet<String>,
}

fn parse_artifact_verify_options(values: &[String]) -> anyhow::Result<ArtifactVerifyInvocation> {
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
            "--trust-policy" | "--manifest" | "--driver" | "--matrix" | "--require"
        ) {
            bail!("unknown oidf artifact verify option: {option}");
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
            "--require" => {
                if !capabilities.insert(value) {
                    bail!("--require values must be unique");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactVerifyInvocation {
        trust_policy: trust_policy.context("--trust-policy is required")?,
        manifest: manifest.context("--manifest is required")?,
        driver: driver.context("--driver is required")?,
        matrix: matrix.context("--matrix is required")?,
        capabilities,
    })
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
        "Usage:\n  nazoauthctl oidf artifact verify --trust-policy PATH --manifest PATH --driver PATH --matrix PATH [--require NAME ...]\n\nThe command performs no NazoAuth or Suite mutation. It emits a verified identity only after the local trust policy, ES256 signature, source, validity window, Suite identity, declarative driver digest/size/schema, matrix digest/size/schema, resource bounds, and all required capabilities have been accepted."
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
    pub(crate) instance: Option<String>,
    pub(crate) tenant_id: String,
    pub(crate) token_stdin: bool,
    pub(crate) capture_review_screenshots: bool,
    pub(crate) upload_review_screenshots: bool,
    pub(crate) retain_suite_plans_for_certification: bool,
    pub(crate) groups: Vec<String>,
    pub(crate) plans: Vec<String>,
    pub(crate) poll_timeout: Duration,
    pub(crate) jobs: usize,
}

fn parse_run_options(values: &[String], instance: Option<String>) -> anyhow::Result<RunInvocation> {
    if values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        print_run_help();
        std::process::exit(0);
    }

    let mut token_stdin = false;
    let mut capture_review_screenshots = false;
    let mut upload_review_screenshots = false;
    let mut retain_suite_plans_for_certification = false;
    let mut selector = None;
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut jobs = DEFAULT_JOBS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--poll-timeout" | "--jobs" => {
                let value = values
                    .get(index + 1)
                    .with_context(|| format!("{option} requires a value"))?
                    .clone();
                match option {
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
            "--upload-review-screenshots" => {
                if upload_review_screenshots {
                    bail!("--upload-review-screenshots may be specified only once");
                }
                upload_review_screenshots = true;
                index += 1;
            }
            value if value.starts_with('-') => bail!("unknown oidf run option: {value}"),
            value => {
                set_once(&mut selector, value.to_owned(), "OIDF selector")?;
                index += 1;
            }
        }
    }
    if upload_review_screenshots && !capture_review_screenshots {
        bail!("--upload-review-screenshots requires --capture-review-screenshots");
    }
    let selection = resolve_bundled_oidf_selection(selector.as_deref()).map_err(|error| {
        if error == nazoauthctl_conformance::OidfPlanError::UnknownSelection {
            let choices = bundled_oidf_selection_choices()
                .map(|choices| choices.join(", "))
                .unwrap_or_else(|_| {
                    "oidc, ciba, fapi, openid4vci, openid4vp, openid4vc".to_owned()
                });
            anyhow::anyhow!(
                "unknown OIDF selector `{}`; valid choices: {choices}",
                selector.as_deref().unwrap_or_default()
            )
        } else {
            anyhow::anyhow!("bundled OIDF Matrix is invalid: {error}")
        }
    })?;
    let tenant_id = uuid::Uuid::now_v7().to_string();
    if poll_timeout.is_zero()
        || poll_timeout > Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS)
        || !(1..=MAX_PARALLEL_JOBS).contains(&jobs)
    {
        bail!(
            "poll timeout must be between 1 and {MAX_POLL_TIMEOUT_SECONDS} seconds and jobs must be between 1 and {MAX_PARALLEL_JOBS}"
        );
    }
    Ok(RunInvocation {
        instance,
        tenant_id,
        token_stdin,
        capture_review_screenshots,
        upload_review_screenshots,
        retain_suite_plans_for_certification,
        groups: selection.groups,
        plans: selection.plans,
        poll_timeout,
        jobs,
    })
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
        "Usage:\n  nazoauthctl [--instance SELECTOR] oidf run [GROUP_OR_PLAN] [options]\n\nWithout a selector, the complete bundled OIDF Matrix runs against the official OpenID Foundation Conformance Suite. Aliases: oidc, ciba, fapi, openid4vci, openid4vp, openid4vc. Exact bundled group and plan IDs are also accepted.\n\nEach run creates a fresh temporary tenant at <uuid>.oidf.nazoauth.com, generates fresh test material, starts its browser workers, and writes evidence below the instance recovery directory.\n\nOptions:\n  --token-stdin                  Read the official Suite API token from stdin instead of the secure credential store\n  --capture-review-screenshots   Capture review evidence into the automatic evidence directory\n  --upload-review-screenshots    Upload each captured PNG to its exact Suite placeholder and wait for REVIEW\n  --retain-suite-plans-for-certification\n                               Retain terminal plans, or an audited deferred OIDF review boundary, at the official Suite\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn routed_run(args: &[OsString]) -> anyhow::Result<Option<RunInvocation>> {
        match parse_invocation(args)? {
            Invocation::Run(invocation) => Ok(Some(*invocation)),
            _ => Ok(None),
        }
    }

    fn routed_artifact_open(args: &[OsString]) -> anyhow::Result<Option<ArtifactOpenInvocation>> {
        match parse_invocation(args)? {
            Invocation::ArtifactOpen(invocation) => Ok(Some(invocation)),
            _ => Ok(None),
        }
    }

    fn routed_artifact_plan(args: &[OsString]) -> anyhow::Result<Option<ArtifactPlanInvocation>> {
        match parse_invocation(args)? {
            Invocation::ArtifactPlan(invocation) => Ok(Some(invocation)),
            _ => Ok(None),
        }
    }

    fn routed_artifact_resolve(
        args: &[OsString],
    ) -> anyhow::Result<Option<ArtifactResolveInvocation>> {
        match parse_invocation(args)? {
            Invocation::ArtifactResolve(invocation) => Ok(Some(invocation)),
            _ => Ok(None),
        }
    }

    fn routed_artifact_verify(
        args: &[OsString],
    ) -> anyhow::Result<Option<ArtifactVerifyInvocation>> {
        match parse_invocation(args)? {
            Invocation::ArtifactVerify(invocation) => Ok(Some(invocation)),
            _ => Ok(None),
        }
    }

    #[test]
    fn unrelated_command_is_owned_by_core() {
        assert!(
            routed_run(&args(&["nazoauthctl", "status"]))
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn artifact_open_requires_exact_cache_identity_and_unique_capabilities() {
        let digest = "a".repeat(64);
        let parsed = routed_artifact_open(&args(&[
            "nazoauthctl",
            "oidf",
            "artifact",
            "open",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--digest",
            &digest,
            "--require",
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
            routed_artifact_open(&args(&[
                "nazoauthctl",
                "oidf",
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
            routed_artifact_open(&args(&[
                "nazoauthctl",
                "oidf",
                "artifact",
                "open",
                "--trust-policy",
                "/trust.json",
                "--cache-dir",
                "/cache",
                "--digest",
                &digest,
                "--require",
                "nazoauth.client.create",
                "--require",
                "nazoauth.client.create",
            ]))
            .is_err()
        );
    }

    #[test]
    fn artifact_plan_is_a_separate_read_only_selection_command() {
        let digest = "a".repeat(64);
        let parsed = routed_artifact_plan(&args(&[
            "nazoauthctl",
            "oidf",
            "artifact",
            "plan",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--digest",
            &digest,
            "--require",
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
    }

    #[test]
    fn artifact_plan_requires_closed_unique_inputs() {
        let digest = "a".repeat(64);
        assert!(
            routed_artifact_plan(&args(&[
                "nazoauthctl",
                "oidf",
                "artifact",
                "plan",
                "--trust-policy",
                "/trust.json",
                "--cache-dir",
                "/cache",
            ]))
            .is_err()
        );
        for option in ["--require", "--group", "--plan"] {
            assert!(
                routed_artifact_plan(&args(&[
                    "nazoauthctl",
                    "oidf",
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
        let parsed = routed_artifact_verify(&args(&[
            "nazoauthctl",
            "oidf",
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
            "--require",
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
    }

    #[test]
    fn artifact_verify_requires_closed_unique_inputs() {
        assert!(
            routed_artifact_verify(&args(&[
                "nazoauthctl",
                "oidf",
                "artifact",
                "verify",
                "--trust-policy",
                "/trust.json",
            ]))
            .is_err()
        );
        assert!(
            routed_artifact_verify(&args(&[
                "nazoauthctl",
                "oidf",
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
                "--require",
                "nazoauth.client.create",
                "--require",
                "nazoauth.client.create",
            ]))
            .is_err()
        );
    }

    #[test]
    fn artifact_resolve_requires_trust_channel_cache_and_unique_capabilities() {
        let parsed = routed_artifact_resolve(&args(&[
            "nazoauthctl",
            "oidf",
            "artifact",
            "resolve",
            "--trust-policy",
            "/etc/nazoauthctl/oidf-trust.json",
            "--manifest-url",
            "https://artifacts.example/oidf/stable/driver.jws",
            "--cache-dir",
            "/var/lib/nazoauthctl/oidf-cache",
            "--require",
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
            routed_artifact_resolve(&args(&[
                "nazoauthctl",
                "oidf",
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
            routed_artifact_resolve(&args(&[
                "nazoauthctl",
                "oidf",
                "artifact",
                "resolve",
                "--trust-policy",
                "/trust.json",
                "--manifest-url",
                "https://artifacts.example/driver.jws",
                "--cache-dir",
                "/cache",
                "--require",
                "nazoauth.client.create",
                "--require",
                "nazoauth.client.create",
            ]))
            .is_err()
        );
    }

    #[test]
    fn run_without_options_selects_the_complete_bundled_matrix() {
        let parsed = routed_run(&args(&["nazoauthctl", "oidf", "run"]))
            .expect("parse")
            .expect("run");
        assert!(parsed.groups.is_empty());
        assert!(parsed.plans.is_empty());
        assert!(uuid::Uuid::parse_str(&parsed.tenant_id).is_ok());
        assert_eq!(parsed.jobs, DEFAULT_JOBS);
    }

    #[test]
    fn run_accepts_alias_and_exact_plan_selectors() {
        let ciba = routed_run(&args(&["nazoauthctl", "oidf", "run", "ciba"]))
            .expect("parse")
            .expect("run");
        assert_eq!(ciba.groups, ["fapi-ciba"]);
        assert!(ciba.plans.is_empty());

        let plan = routed_run(&args(&["nazoauthctl", "oidf", "run", "oidc-core-p001"]))
            .expect("parse")
            .expect("run");
        assert!(plan.groups.is_empty());
        assert_eq!(plan.plans, ["oidc-core-p001"]);
    }

    #[test]
    fn run_rejects_unknown_or_multiple_selectors_without_full_fallback() {
        let unknown = routed_run(&args(&["nazoauthctl", "oidf", "run", "missing"]))
            .err()
            .expect("unknown selector must fail");
        let message = unknown.to_string();
        assert!(message.contains("unknown OIDF selector `missing`"));
        assert!(message.contains("ciba"));
        assert!(message.contains("oidc-core-p001"));

        let multiple = routed_run(&args(&["nazoauthctl", "oidf", "run", "oidc", "ciba"]))
            .err()
            .expect("only one selector is accepted");
        assert!(
            multiple
                .to_string()
                .contains("OIDF selector may be specified only once")
        );
    }

    #[test]
    fn removed_internal_run_inputs_are_rejected() {
        for option in [
            "--trust-policy",
            "--artifact-cache",
            "--artifact-digest",
            "--suite",
            "--token",
            "--token-file",
            "--token-fd",
            "--webdriver",
            "--evidence-dir",
            "--proxy-trust-bundle",
            "--proxy-reload-executable",
            "--ciba-user-approval-callback-url",
            "--ciba-user-approval-listen",
            "--group",
            "--plan",
        ] {
            let error = routed_run(&args(&["nazoauthctl", "oidf", "run", option, "value"]))
                .err()
                .expect("removed internal option must fail");
            assert!(error.to_string().contains("unknown oidf run option"));
        }
    }

    #[test]
    fn review_screenshot_capture_uses_the_automatic_evidence_directory() {
        let parsed = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--capture-review-screenshots",
        ]))
        .expect("parse")
        .expect("run");
        assert!(parsed.capture_review_screenshots);
    }

    #[test]
    fn review_screenshot_upload_requires_capture() {
        let error = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--upload-review-screenshots",
        ]))
        .err()
        .expect("upload needs capture");
        assert!(
            error
                .to_string()
                .contains("requires --capture-review-screenshots")
        );
    }

    #[test]
    fn run_rejects_jobs_outside_the_validated_bound() {
        for jobs in ["0", "5"] {
            let error = match routed_run(&args(&["nazoauthctl", "oidf", "run", "--jobs", jobs])) {
                Err(error) => error,
                Ok(_) => panic!("jobs outside 1-4 must fail"),
            };
            assert!(error.to_string().contains("jobs must be between 1 and 4"));
        }
    }

    #[test]
    fn run_rejects_poll_timeout_above_the_validated_bound() {
        let error = match routed_run(&args(&[
            "nazoauthctl",
            "oidf",
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
    fn run_rejects_lease_options() {
        let lease = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
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
                .contains("unknown oidf run option: --lease-ttl")
        );

        let caller_supplied_tenant = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
        ]));
        let caller_supplied_tenant = match caller_supplied_tenant {
            Err(error) => error,
            Ok(_) => panic!("caller-supplied tenant identity must fail"),
        };
        assert!(
            caller_supplied_tenant
                .to_string()
                .contains("unknown oidf run option: --tenant-id")
        );
    }

    #[test]
    fn token_stdin_remains_available_for_noninteractive_runs() {
        let parsed = routed_run(&args(&["nazoauthctl", "oidf", "run", "--token-stdin"]))
            .expect("parse")
            .expect("run");
        assert!(parsed.token_stdin);
    }
}
