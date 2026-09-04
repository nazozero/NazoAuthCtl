use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use cliclack::{intro, log, note, outro};
use nazoauthctl_conformance::{
    ArtifactTrustPolicy, BearerToken, MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS,
    OidfPlanSelection, OutputLanguage, bundled_oidf_selection_choices, open_cached_oidf_artifact,
    open_cached_oidf_driver_plan, read_artifact_driver, read_artifact_matrix,
    read_compact_manifest, resolve_bundled_oidf_selection, resolve_oidf_artifact,
    verify_oidf_artifact,
};

mod ordinary_run;

const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_JOBS: usize = 4;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let json_requested = args.iter().any(|value| value == "--json");
    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error, json_requested),
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
        Invocation::Configure {
            instance,
            tenant_domain,
            suite_origin,
        } => execute_configure(instance, tenant_domain, suite_origin),
        Invocation::Run(invocation) => ordinary_run::execute(*invocation).map(|code| {
            std::process::exit(code);
        }),
    };
    if let Err(error) = result {
        exit_with_error(&error, json_requested);
    }
}

fn execute_configure(
    instance: Option<String>,
    tenant_domain: String,
    suite_origin: String,
) -> anyhow::Result<()> {
    let (alias, tenant_domain, suite_origin) =
        nazoauthctl_core::configure_oidf(instance.as_deref(), &tenant_domain, &suite_origin)?;
    let language = output_language();
    if io::stdout().is_terminal() && io::stderr().is_terminal() {
        let title = match language {
            OutputLanguage::Chinese => "OIDF 配置已保存",
            OutputLanguage::English => "OIDF configuration saved",
        };
        let (instance_label, domain_label) = match language {
            OutputLanguage::Chinese => ("实例", "租户域名"),
            OutputLanguage::English => ("Instance", "Tenant domain"),
        };
        intro("NazoAuth OIDF")?;
        note(
            title,
            format!(
                "{instance_label}: {alias}\n{domain_label}: {tenant_domain}\nOIDF Suite: {suite_origin}"
            ),
        )?;
        outro(title)?;
    } else {
        println!(
            "OIDF configuration for instance '{alias}': tenant domain {tenant_domain}; Suite {suite_origin}"
        );
    }
    Ok(())
}

enum Invocation {
    Core,
    ArtifactPlan(ArtifactPlanInvocation),
    ArtifactOpen(ArtifactOpenInvocation),
    ArtifactResolve(ArtifactResolveInvocation),
    ArtifactVerify(ArtifactVerifyInvocation),
    Configure {
        instance: Option<String>,
        tenant_domain: String,
        suite_origin: String,
    },
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
        [command, options @ ..] if command == "configure" => {
            parse_configure_options(options, globals.instance)
        }
        [command, options @ ..] if command == "run" => parse_run_options(options, globals.instance)
            .map(Box::new)
            .map(Invocation::Run),
        [command, ..] => bail!("unknown oidf command: {command}"),
        [] => bail!("an oidf command is required"),
    }
}

fn parse_configure_options(
    values: &[String],
    instance: Option<String>,
) -> anyhow::Result<Invocation> {
    let mut tenant_domain = None;
    let mut suite_origin = None;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--tenant-domain" => set_once(&mut tenant_domain, value, option)?,
            "--suite" => set_once(&mut suite_origin, value, option)?,
            _ => bail!("unknown oidf configure option: {option}"),
        }
        index += 2;
    }
    Ok(Invocation::Configure {
        instance,
        tenant_domain: tenant_domain.context("oidf configure requires --tenant-domain DOMAIN")?,
        suite_origin: suite_origin.context("oidf configure requires --suite HTTPS_ORIGIN")?,
    })
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

fn exit_with_error(error: &anyhow::Error, json: bool) -> ! {
    let message = format!("{error:#}");
    if json {
        let output = serde_json::json!({
            "schema": 1,
            "success": false,
            "error": message,
        });
        let _ = serde_json::to_writer_pretty(io::stdout().lock(), &output);
        let _ = writeln!(io::stdout());
    } else {
        let language = output_language();
        let title = match language {
            OutputLanguage::Chinese => "命令执行失败",
            OutputLanguage::English => "Command failed",
        };
        if io::stderr().is_terminal() {
            let _ = log::error(format!("{title}\n\n{message}"));
        } else {
            let _ = writeln!(io::stderr(), "{title}\n\n{message}");
        }
    }
    std::process::exit(1)
}

pub(crate) struct RunInvocation {
    pub(crate) instance: Option<String>,
    pub(crate) tenant_id: String,
    pub(crate) token: Option<BearerToken>,
    pub(crate) token_stdin: bool,
    pub(crate) json: bool,
    pub(crate) delete_suite_plans: bool,
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

    let mut token = None;
    let mut token_stdin = false;
    let mut json = false;
    let mut delete_suite_plans = false;
    let mut selector = None;
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut jobs = DEFAULT_JOBS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--poll-timeout" | "--jobs" | "--token" => {
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
                    "--token" => {
                        set_once(
                            &mut token,
                            BearerToken::new(value).context("--token is invalid")?,
                            "--token",
                        )?;
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
            "--json" => {
                if json {
                    bail!("--json may be specified only once");
                }
                json = true;
                index += 1;
            }
            "--delete-suite-plans" => {
                if delete_suite_plans {
                    bail!("--delete-suite-plans may be specified only once");
                }
                delete_suite_plans = true;
                index += 1;
            }
            value if value.starts_with('-') => bail!("unknown oidf run option: {value}"),
            value => {
                set_once(&mut selector, value.to_owned(), "OIDF selector")?;
                index += 1;
            }
        }
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
    if token.is_some() && token_stdin {
        bail!("--token and --token-stdin cannot be used together");
    }
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
        token,
        token_stdin,
        json,
        delete_suite_plans,
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

fn output_language() -> OutputLanguage {
    OutputLanguage::from_locale(
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
            .as_deref(),
    )
}

fn run_help(language: OutputLanguage) -> &'static str {
    match language {
        OutputLanguage::Chinese => {
            "用法：\n  nazoauthctl [--instance 实例] oidf configure --tenant-domain 域名 --suite HTTPS地址\n  nazoauthctl [--instance 实例] oidf run [分组或计划] [选项]\n\nconfigure 只需设置一次临时租户所用的通配域名后缀和 OIDF Suite 地址。未指定分组或计划时运行完整矩阵。可用别名：oidc、ciba、fapi、openid4vci、openid4vp、openid4vc；也可使用内置分组或计划的完整 ID。\n\n每次运行都会创建新的临时租户、生成新的测试资料，并仅在所选计划需要时启动浏览器任务。Suite 测试记录默认保留。\n\n选项：\n  --token TOKEN                  本次运行直接使用 Token，不保存\n  --token-stdin                  从标准输入读取 Token，不保存\n  --json                         输出完整 JSON 报告；默认仅输出简洁摘要\n  --delete-suite-plans           运行结束后删除本次创建的 Suite 测试记录\n  --jobs N                       并行计划数，1-4（默认：4）\n  --poll-timeout 秒数            单个模块等待 Suite 的最长时间（默认：1800）"
        }
        OutputLanguage::English => {
            "Usage:\n  nazoauthctl [--instance SELECTOR] oidf configure --tenant-domain DOMAIN --suite HTTPS_ORIGIN\n  nazoauthctl [--instance SELECTOR] oidf run [GROUP_OR_PLAN] [options]\n\nConfigure stores the wildcard tenant-domain suffix and OIDF Suite origin once. Without a selector, the complete bundled Matrix runs. Aliases: oidc, ciba, fapi, openid4vci, openid4vp, openid4vc. Exact bundled group and plan IDs are also accepted.\n\nEach run creates a fresh temporary tenant and test material, and starts browser workers only when the selected plan needs them. Suite test records are retained by default.\n\nOptions:\n  --token TOKEN                  Use a token for this run only; do not save it\n  --token-stdin                  Read a token from stdin; do not save it\n  --json                         Print the full JSON report; the default is a concise summary\n  --delete-suite-plans           Delete Suite test records created by the run when it finishes\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)"
        }
    }
}

fn print_run_help() {
    let language = output_language();
    let help = run_help(language);
    if io::stdout().is_terminal() && io::stderr().is_terminal() {
        let title = match language {
            OutputLanguage::Chinese => "NazoAuth OIDF 使用说明",
            OutputLanguage::English => "NazoAuth OIDF guide",
        };
        let _ = intro("NazoAuth OIDF");
        let _ = note(title, help);
        let _ = outro(match language {
            OutputLanguage::Chinese => "准备就绪",
            OutputLanguage::English => "Ready",
        });
    } else {
        println!("{help}");
    }
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

    fn routed_configure(
        args: &[OsString],
    ) -> anyhow::Result<Option<(Option<String>, String, String)>> {
        match parse_invocation(args)? {
            Invocation::Configure {
                instance,
                tenant_domain,
                suite_origin,
            } => Ok(Some((instance, tenant_domain, suite_origin))),
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
        assert!(!parsed.delete_suite_plans);
    }

    #[test]
    fn suite_plans_are_deleted_only_when_explicitly_requested() {
        let parsed = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--delete-suite-plans",
        ]))
        .expect("parse")
        .expect("run");
        assert!(parsed.delete_suite_plans);

        let removed_option = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--retain-suite-plans-for-certification",
        ]))
        .err()
        .expect("removed retention option must fail");
        assert!(
            removed_option
                .to_string()
                .contains("unknown oidf run option")
        );
    }

    #[test]
    fn configure_binds_one_domain_to_the_selected_instance() {
        let parsed = routed_configure(&args(&[
            "nazoauthctl",
            "--instance",
            "production",
            "oidf",
            "configure",
            "--tenant-domain",
            "oidf.example.com",
            "--suite",
            "https://suite.example",
        ]))
        .expect("parse")
        .expect("configure");
        assert_eq!(parsed.0.as_deref(), Some("production"));
        assert_eq!(parsed.1, "oidf.example.com");
        assert_eq!(parsed.2, "https://suite.example");
        assert!(routed_configure(&args(&["nazoauthctl", "oidf", "configure"])).is_err());
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
            "--token-file",
            "--token-fd",
            "--webdriver",
            "--evidence-dir",
            "--proxy-trust-bundle",
            "--proxy-reload-executable",
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
    fn review_screenshot_flags_are_not_part_of_the_user_interface() {
        for option in [
            "--capture-review-screenshots",
            "--upload-review-screenshots",
        ] {
            let error = routed_run(&args(&["nazoauthctl", "oidf", "run", option]))
                .err()
                .expect("legacy review option must be rejected");
            assert!(error.to_string().contains("unknown oidf run option"));
        }
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

    #[test]
    fn direct_token_is_transient_and_redacted() {
        let parsed = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--token",
            "temporary-secret",
        ]))
        .expect("parse")
        .expect("run");

        assert!(parsed.token.is_some());
        assert_eq!(
            format!("{:?}", parsed.token.as_ref().expect("token")),
            "BearerToken(REDACTED)"
        );
        assert!(!parsed.token_stdin);
    }

    #[test]
    fn direct_token_and_stdin_are_mutually_exclusive() {
        let error = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "--token",
            "temporary-secret",
            "--token-stdin",
        ]))
        .err()
        .expect("ambiguous token source must fail");

        assert!(
            error
                .to_string()
                .contains("--token and --token-stdin cannot be used together")
        );
    }

    #[test]
    fn json_output_is_explicit() {
        let default = routed_run(&args(&["nazoauthctl", "oidf", "run"]))
            .expect("parse")
            .expect("run");
        let json = routed_run(&args(&["nazoauthctl", "oidf", "run", "--json"]))
            .expect("parse")
            .expect("run");

        assert!(!default.json);
        assert!(json.json);
    }

    #[test]
    fn run_help_is_localized() {
        assert!(run_help(OutputLanguage::Chinese).contains("用法："));
        assert!(run_help(OutputLanguage::Chinese).contains("本次运行直接使用 Token，不保存"));
        assert!(run_help(OutputLanguage::English).contains("Usage:"));
    }
}
