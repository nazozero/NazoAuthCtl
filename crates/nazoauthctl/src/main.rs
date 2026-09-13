use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cliclack::{intro, log, note, outro};
use nazoauthctl_conformance::{
    ArtifactTrustPolicy, BearerToken, MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS,
    OidfPlanSelection, OutputLanguage, bundled_oidf_selection_choices, open_cached_oidf_artifact,
    open_cached_oidf_driver_plan, read_artifact_driver, read_artifact_matrix,
    read_compact_manifest, resolve_bundled_oidf_plan_id, resolve_bundled_oidf_selection,
    resolve_oidf_artifact, verify_oidf_artifact,
};

macro_rules! localized_message {
    ($en:literal, $zh:literal $(, $($args:tt)*)?) => {
        if nazoauthctl_core::presentation_text("en", "zh") == "zh" {
            format!($zh $(, $($args)*)?)
        } else { format!($en $(, $($args)*)?) }
    };
}
macro_rules! localized_bail {
    ($($args:tt)*) => { anyhow::bail!("{}", localized_message!($($args)*)) };
}

mod ordinary_run;

const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_JOBS: usize = 4;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let json_requested = args.iter().any(|value| value == "--json");
    nazoauthctl_core::configure_presentation(json_requested);
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
    nazoauthctl_core::print_presentation_value(&serde_json::json!({
        "schema": 1, "configured": true, "instance": alias,
        "tenant_domain": tenant_domain, "suite_origin": suite_origin,
    }));
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
                .context(nazoauthctl_core::presentation_text(
                    "command-line arguments must be valid UTF-8",
                    "命令行参数必须为有效的 UTF-8 文本",
                ))
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

    if command
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
        && command.first().is_none_or(|arg| arg != "artifact")
    {
        print_run_help();
        std::process::exit(0);
    }
    match command {
        [artifact, operation, options @ ..] if artifact == "artifact" => match operation.as_str() {
            "plan" => parse_artifact_plan_options(options).map(Invocation::ArtifactPlan),
            "open" => parse_artifact_open_options(options).map(Invocation::ArtifactOpen),
            "resolve" => parse_artifact_resolve_options(options).map(Invocation::ArtifactResolve),
            "verify" => parse_artifact_verify_options(options).map(Invocation::ArtifactVerify),
            other => localized_bail!(
                "unknown oidf artifact command: {other}",
                "未知的 OIDF 制品命令：{other}"
            ),
        },
        [command, options @ ..] if command == "configure" => {
            parse_configure_options(options, globals.instance)
        }
        [command, options @ ..] if command == "run" => parse_run_options(options, globals.instance)
            .map(|mut run| {
                run.json |= globals.json;
                Box::new(run)
            })
            .map(Invocation::Run),
        [command, ..] => localized_bail!(
            "unknown oidf command: {command}",
            "未知的 OIDF 命令：{command}"
        ),
        [] => localized_bail!(
            "an oidf command is required",
            "请指定 OIDF 子命令；使用 oidf --help 查看帮助"
        ),
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
            .with_context(|| {
                localized_message!("{option} requires a value", "{option} 需要一个值")
            })?
            .clone();
        match option {
            "--tenant-domain" => set_once(&mut tenant_domain, value, option)?,
            "--suite" => set_once(&mut suite_origin, value, option)?,
            _ => localized_bail!(
                "unknown oidf configure option: {option}",
                "OIDF 配置不支持选项 {option}"
            ),
        }
        index += 2;
    }
    Ok(Invocation::Configure {
        instance,
        tenant_domain: tenant_domain.context(nazoauthctl_core::presentation_text(
            "oidf configure requires --tenant-domain DOMAIN",
            "OIDF 配置需要 --tenant-domain DOMAIN",
        ))?,
        suite_origin: suite_origin.context(nazoauthctl_core::presentation_text(
            "oidf configure requires --suite HTTPS_ORIGIN",
            "OIDF 配置需要 --suite HTTPS_ORIGIN",
        ))?,
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
            localized_bail!(
                "unknown oidf artifact plan option: {option}",
                "OIDF 制品 plan 不支持选项 {option}"
            );
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                localized_message!("{option} requires a value", "{option} 需要一个值")
            })?
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
        trust_policy: trust_policy.context(nazoauthctl_core::presentation_text(
            "--trust-policy is required",
            "必须提供 --trust-policy",
        ))?,
        cache_directory: cache_directory.context(nazoauthctl_core::presentation_text(
            "--cache-dir is required",
            "必须提供 --cache-dir",
        ))?,
        manifest_digest: manifest_digest.context(nazoauthctl_core::presentation_text(
            "--digest is required",
            "必须提供 --digest",
        ))?,
        capabilities,
        selection: OidfPlanSelection {
            groups,
            plans,
            excluded_plans: Vec::new(),
        },
    })
}

fn execute_artifact_plan(invocation: ArtifactPlanInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy).context(
        nazoauthctl_core::presentation_text(
            "OIDF artifact trust policy is invalid",
            "OIDF 制品信任配置无效",
        ),
    )?;
    let plan = open_cached_oidf_driver_plan(
        &invocation.cache_directory,
        &invocation.manifest_digest,
        &trust,
        &invocation.capabilities,
        invocation.selection,
        current_unix_time()?,
    )
    .context(nazoauthctl_core::presentation_text(
        "cached OIDF driver plan compilation failed",
        "无法生成缓存 OIDF 驱动的检查计划",
    ))?;
    nazoauthctl_core::print_presentation_value(&serde_json::to_value(&plan)?);
    Ok(())
}

fn print_artifact_plan_help() {
    println!(
        "{}",
        nazoauthctl_core::presentation_text(
            "Usage:\n  nazoauthctl oidf artifact plan --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...] [--group ID ...] [--plan ID ...]\n\nThis is a read-only, offline inspection plan. It revalidates one exact cached artifact and compiles exact signed Matrix selections. Caller-supplied capability names are not attested negotiation. The output is explicitly not deployment-bound or executable and creates no run journal or resources.",
            "用法：\n  nazoauthctl oidf artifact plan --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...] [--group ID ...] [--plan ID ...]\n\n离线检查指定的缓存制品，并根据所选分组或计划生成检查计划。此命令不执行测试、不创建资源，也不修改部署。默认显示可读摘要；在 oidf 前添加 --json 可查看完整结构。"
        )
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
            localized_bail!(
                "unknown oidf artifact open option: {option}",
                "OIDF 制品 open 不支持选项 {option}"
            );
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                localized_message!("{option} requires a value", "{option} 需要一个值")
            })?
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
                    localized_bail!("--require values must be unique", "--require 的值不能重复");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactOpenInvocation {
        trust_policy: trust_policy.context(nazoauthctl_core::presentation_text(
            "--trust-policy is required",
            "必须提供 --trust-policy",
        ))?,
        cache_directory: cache_directory.context(nazoauthctl_core::presentation_text(
            "--cache-dir is required",
            "必须提供 --cache-dir",
        ))?,
        manifest_digest: manifest_digest.context(nazoauthctl_core::presentation_text(
            "--digest is required",
            "必须提供 --digest",
        ))?,
        capabilities,
    })
}

fn execute_artifact_open(invocation: ArtifactOpenInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy).context(
        nazoauthctl_core::presentation_text(
            "OIDF artifact trust policy is invalid",
            "OIDF 制品信任配置无效",
        ),
    )?;
    let cached = open_cached_oidf_artifact(
        &invocation.cache_directory,
        &invocation.manifest_digest,
        &trust,
        &invocation.capabilities,
        current_unix_time()?,
    )
    .context(nazoauthctl_core::presentation_text(
        "cached OIDF artifact verification failed",
        "缓存 OIDF 制品验证失败",
    ))?;
    nazoauthctl_core::print_presentation_value(&serde_json::json!({
        "schema": 1,
        "opened": true,
        "cache": cached,
    }));
    Ok(())
}

fn print_artifact_open_help() {
    println!(
        "{}",
        nazoauthctl_core::presentation_text(
            "Usage:\n  nazoauthctl oidf artifact open --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...]\n\nThe command performs no network request or mutation. It opens only the exact immutable digest entry and revalidates its commit record, source, ES256 signature, current validity window, Suite identity, declarative driver and Matrix digests/sizes/schemas, resource bounds, engine protocol, and every caller-supplied capability requirement.",
            "用法：\n  nazoauthctl oidf artifact open --trust-policy PATH --cache-dir PATH --digest SHA256 [--require NAME ...]\n\n离线打开并重新验证指定缓存，包括签名、有效期、测试服务身份及驱动和矩阵内容。此命令不访问网络、不修改部署。默认显示可读摘要；在 oidf 前添加 --json 可查看完整结构。"
        )
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
            localized_bail!(
                "unknown oidf artifact resolve option: {option}",
                "OIDF 制品 resolve 不支持选项 {option}"
            );
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                localized_message!("{option} requires a value", "{option} 需要一个值")
            })?
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
                    localized_bail!("--require values must be unique", "--require 的值不能重复");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactResolveInvocation {
        trust_policy: trust_policy.context(nazoauthctl_core::presentation_text(
            "--trust-policy is required",
            "必须提供 --trust-policy",
        ))?,
        manifest_url: manifest_url.context(nazoauthctl_core::presentation_text(
            "--manifest-url is required",
            "必须提供 --manifest-url",
        ))?,
        cache_directory: cache_directory.context(nazoauthctl_core::presentation_text(
            "--cache-dir is required",
            "必须提供 --cache-dir",
        ))?,
        capabilities,
    })
}

fn execute_artifact_resolve(invocation: ArtifactResolveInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy).context(
        nazoauthctl_core::presentation_text(
            "OIDF artifact trust policy is invalid",
            "OIDF 制品信任配置无效",
        ),
    )?;
    let resolution = resolve_oidf_artifact(
        &invocation.manifest_url,
        &trust,
        &invocation.capabilities,
        &invocation.cache_directory,
        current_unix_time()?,
    )
    .context(nazoauthctl_core::presentation_text(
        "OIDF artifact discovery failed",
        "OIDF 制品下载或解析失败",
    ))?;
    nazoauthctl_core::print_presentation_value(&serde_json::json!({
        "schema": 1,
        "resolved": true,
        "resolution": resolution,
    }));
    Ok(())
}

fn print_artifact_resolve_help() {
    println!(
        "{}",
        nazoauthctl_core::presentation_text(
            "Usage:\n  nazoauthctl oidf artifact resolve --trust-policy PATH --manifest-url HTTPS_URL --cache-dir PATH [--require NAME ...]\n\nThe command fetches a bounded manifest without redirects, verifies it before following the signed declarative driver and Matrix URLs, verifies both exact payloads, and commits an immutable owner-only cache entry with a final verified record marker. It performs no NazoAuth or Suite mutation.",
            "用法：\n  nazoauthctl oidf artifact resolve --trust-policy PATH --manifest-url HTTPS_URL --cache-dir PATH [--require NAME ...]\n\n下载并验证发布清单、驱动和矩阵，然后保存到本地缓存。此命令不修改 NazoAuth 或测试服务。默认显示可读摘要；在 oidf 前添加 --json 可查看完整结构。"
        )
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
            localized_bail!(
                "unknown oidf artifact verify option: {option}",
                "OIDF 制品 verify 不支持选项 {option}"
            );
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                localized_message!("{option} requires a value", "{option} 需要一个值")
            })?
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
                    localized_bail!("--require values must be unique", "--require 的值不能重复");
                }
            }
            _ => unreachable!(),
        }
        index += 2;
    }
    Ok(ArtifactVerifyInvocation {
        trust_policy: trust_policy.context(nazoauthctl_core::presentation_text(
            "--trust-policy is required",
            "必须提供 --trust-policy",
        ))?,
        manifest: manifest.context(nazoauthctl_core::presentation_text(
            "--manifest is required",
            "必须提供 --manifest",
        ))?,
        driver: driver.context(nazoauthctl_core::presentation_text(
            "--driver is required",
            "必须提供 --driver",
        ))?,
        matrix: matrix.context(nazoauthctl_core::presentation_text(
            "--matrix is required",
            "必须提供 --matrix",
        ))?,
        capabilities,
    })
}

fn execute_artifact_verify(invocation: ArtifactVerifyInvocation) -> anyhow::Result<()> {
    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy).context(
        nazoauthctl_core::presentation_text(
            "OIDF artifact trust policy is invalid",
            "OIDF 制品信任配置无效",
        ),
    )?;
    let manifest = read_compact_manifest(&invocation.manifest).context(
        nazoauthctl_core::presentation_text(
            "signed OIDF driver manifest is invalid",
            "OIDF 驱动发布清单无效",
        ),
    )?;
    let driver = read_artifact_driver(&invocation.driver).context(
        nazoauthctl_core::presentation_text("OIDF driver payload is invalid", "OIDF 驱动内容无效"),
    )?;
    let matrix = read_artifact_matrix(&invocation.matrix).context(
        nazoauthctl_core::presentation_text("OIDF artifact matrix is invalid", "OIDF 测试矩阵无效"),
    )?;
    let artifact = verify_oidf_artifact(
        &manifest,
        &driver,
        &matrix,
        &trust,
        &invocation.capabilities,
        current_unix_time()?,
    )
    .context(nazoauthctl_core::presentation_text(
        "OIDF artifact verification failed",
        "OIDF 制品验证失败",
    ))?;
    nazoauthctl_core::print_presentation_value(&serde_json::json!({
        "schema": 1,
        "verified": true,
        "artifact": artifact,
    }));
    Ok(())
}

fn current_unix_time() -> anyhow::Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context(nazoauthctl_core::presentation_text(
            "system clock is before the Unix epoch",
            "系统时间早于 Unix 时间起点，请校准时钟",
        ))?
        .as_secs();
    i64::try_from(now).context(nazoauthctl_core::presentation_text(
        "system clock exceeds the supported range",
        "系统时间超出支持范围",
    ))
}

fn print_artifact_verify_help() {
    println!(
        "{}",
        nazoauthctl_core::presentation_text(
            "Usage:\n  nazoauthctl oidf artifact verify --trust-policy PATH --manifest PATH --driver PATH --matrix PATH [--require NAME ...]\n\nThe command performs no NazoAuth or Suite mutation. It emits a verified identity only after the local trust policy, ES256 signature, source, validity window, Suite identity, declarative driver digest/size/schema, matrix digest/size/schema, resource bounds, and all required capabilities have been accepted.",
            "用法：\n  nazoauthctl oidf artifact verify --trust-policy PATH --manifest PATH --driver PATH --matrix PATH [--require NAME ...]\n\n验证本地发布清单、驱动、矩阵及所需能力，成功后显示验证结果。此命令不修改 NazoAuth 或测试服务。默认显示可读摘要；在 oidf 前添加 --json 可查看完整结构。"
        )
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
    pub(crate) excluded_plans: Vec<String>,
    pub(crate) poll_timeout: Duration,
    pub(crate) jobs: usize,
    pub(crate) fail_fast: bool,
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
    let mut excluded_plans = Vec::new();
    let mut fail_fast = false;
    let mut poll_timeout = Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECONDS);
    let mut jobs = DEFAULT_JOBS;
    let mut index = 0usize;
    while index < values.len() {
        let option = values[index].as_str();
        match option {
            "--poll-timeout" | "--jobs" | "--token" => {
                let value = values
                    .get(index + 1)
                    .with_context(|| {
                        localized_message!("{option} requires a value", "{option} 需要一个值")
                    })?
                    .clone();
                match option {
                    "--poll-timeout" => {
                        poll_timeout = Duration::from_secs(value.parse::<u64>().context(
                            nazoauthctl_core::presentation_text(
                                "--poll-timeout must be an integer",
                                "--poll-timeout 必须为整数",
                            ),
                        )?);
                    }
                    "--jobs" => {
                        jobs =
                            value
                                .parse::<usize>()
                                .context(nazoauthctl_core::presentation_text(
                                    "--jobs must be an integer",
                                    "--jobs 必须为整数",
                                ))?;
                    }
                    "--token" => {
                        set_once(
                            &mut token,
                            BearerToken::new(value).context(
                                nazoauthctl_core::presentation_text(
                                    "--token is invalid",
                                    "--token 的内容无效",
                                ),
                            )?,
                            "--token",
                        )?;
                    }
                    _ => unreachable!(),
                }
                index += 2;
            }
            "--token-stdin" => {
                if token_stdin {
                    localized_bail!(
                        "--token-stdin may be specified only once",
                        "--token-stdin 只能指定一次"
                    );
                }
                token_stdin = true;
                index += 1;
            }
            "--json" => {
                if json {
                    localized_bail!("--json may be specified only once", "--json 只能指定一次");
                }
                json = true;
                index += 1;
            }
            "--delete-suite-plans" => {
                if delete_suite_plans {
                    localized_bail!(
                        "--delete-suite-plans may be specified only once",
                        "--delete-suite-plans 只能指定一次"
                    );
                }
                delete_suite_plans = true;
                index += 1;
            }
            "--fail-fast" => {
                if fail_fast {
                    localized_bail!(
                        "--fail-fast may be specified only once",
                        "--fail-fast 只能指定一次"
                    );
                }
                fail_fast = true;
                index += 1;
            }
            "--exclude-plan" => {
                let value = values
                    .get(index + 1)
                    .with_context(|| {
                        localized_message!("{option} requires a value", "{option} 需要一个值")
                    })?
                    .clone();
                push_unique_vec(&mut excluded_plans, value, option)?;
                index += 2;
            }
            value if value.starts_with('-') => localized_bail!(
                "unknown oidf run option: {value}",
                "OIDF 测试不支持选项 {value}"
            ),
            value => {
                set_once(&mut selector, value.to_owned(), "OIDF selector")?;
                index += 1;
            }
        }
    }
    let mut selection = resolve_bundled_oidf_selection(selector.as_deref()).map_err(|error| {
        if error == nazoauthctl_conformance::OidfPlanError::UnknownSelection {
            let choices = bundled_oidf_selection_choices()
                .map(|choices| choices.join(", "))
                .unwrap_or_else(|_| {
                    "oidc, ciba, fapi, openid4vci, openid4vp, openid4vc".to_owned()
                });
            anyhow::anyhow!(
                "{}",
                localized_message!(
                    "unknown OIDF selector `{}`; valid choices: {choices}",
                    "未知的 OIDF 选择项“{}”；可选项：{choices}",
                    selector.as_deref().unwrap_or_default()
                )
            )
        } else {
            anyhow::anyhow!(
                "{}",
                localized_message!(
                    "bundled OIDF Matrix is invalid: {error}",
                    "内置 OIDF 矩阵无效：{error}"
                )
            )
        }
    })?;
    selection.excluded_plans = excluded_plans
        .iter()
        .map(|reference| {
            resolve_bundled_oidf_plan_id(reference).map_err(|_| {
                anyhow::anyhow!(
                    "{}",
                    localized_message!(
                        "unknown or ambiguous excluded OIDF plan `{reference}`",
                        "排除的 OIDF 计划“{reference}”不存在或不唯一"
                    )
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let tenant_id = uuid::Uuid::now_v7().to_string();
    if token.is_some() && token_stdin {
        localized_bail!(
            "--token and --token-stdin cannot be used together",
            "--token 和 --token-stdin 不能同时使用"
        );
    }
    if poll_timeout.is_zero()
        || poll_timeout > Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS)
        || !(1..=MAX_PARALLEL_JOBS).contains(&jobs)
    {
        localized_bail!(
            "poll timeout must be between 1 and {MAX_POLL_TIMEOUT_SECONDS} seconds and jobs must be between 1 and {MAX_PARALLEL_JOBS}",
            "轮询超时必须为 1 到 {MAX_POLL_TIMEOUT_SECONDS} 秒，并行任务数必须为 1 到 {MAX_PARALLEL_JOBS}"
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
        excluded_plans: selection.excluded_plans,
        poll_timeout,
        jobs,
        fail_fast,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        localized_bail!(
            "{option} may be specified only once",
            "{option} 只能指定一次"
        );
    }
    Ok(())
}

fn push_unique(
    values: &mut std::collections::BTreeSet<String>,
    value: String,
    option: &str,
) -> anyhow::Result<()> {
    if !values.insert(value) {
        localized_bail!("{option} values must be unique", "{option} 的值不能重复");
    }
    Ok(())
}

fn push_unique_vec(values: &mut Vec<String>, value: String, option: &str) -> anyhow::Result<()> {
    if values.contains(&value) {
        localized_bail!("{option} values must be unique", "{option} 的值不能重复");
    }
    values.push(value);
    Ok(())
}

fn output_language() -> OutputLanguage {
    if nazoauthctl_core::chinese_output() {
        OutputLanguage::Chinese
    } else {
        OutputLanguage::English
    }
}

fn run_help(language: OutputLanguage) -> &'static str {
    match language {
        OutputLanguage::Chinese => {
            "用法：\n  nazoauthctl [--instance 实例] oidf configure --tenant-domain 域名 --suite HTTPS地址\n  nazoauthctl [--instance 实例] oidf run [分组或计划] [选项]\n\nconfigure 只需设置一次临时租户所用的通配域名后缀和 OIDF Suite 地址。未指定分组或计划时运行完整矩阵。可用别名：oidc、ciba、fapi、openid4vci、openid4vp、openid4vc；也可使用内置分组或计划的完整 ID。\n\n每次运行都会创建新的临时租户、生成新的测试资料，并仅在所选计划需要时启动浏览器任务。Suite 测试记录默认保留。\n\n选项：\n  --token TOKEN                  本次运行直接使用 Token，不保存\n  --token-stdin                  从标准输入读取 Token，不保存\n  --json                         输出完整 JSON 报告；默认仅输出简洁摘要\n  --delete-suite-plans           运行结束后删除本次创建的 Suite 测试记录\n  --exclude-plan ID              明确排除计划，接受完整 ID 或 p040 形式，可重复指定\n  --fail-fast                    首个错误后停止后续测试（默认继续收集）\n  --jobs N                       并行计划数，1-4（默认：4）\n  --poll-timeout 秒数            单个模块等待 Suite 的最长时间（默认：1800）"
        }
        OutputLanguage::English => {
            "Usage:\n  nazoauthctl [--instance SELECTOR] oidf configure --tenant-domain DOMAIN --suite HTTPS_ORIGIN\n  nazoauthctl [--instance SELECTOR] oidf run [GROUP_OR_PLAN] [options]\n\nConfigure stores the wildcard tenant-domain suffix and OIDF Suite origin once. Without a selector, the complete bundled Matrix runs. Aliases: oidc, ciba, fapi, openid4vci, openid4vp, openid4vc. Exact bundled group and plan IDs are also accepted.\n\nEach run creates a fresh temporary tenant and test material, and starts browser workers only when the selected plan needs them. Suite test records are retained by default.\n\nOptions:\n  --token TOKEN                  Use a token for this run only; do not save it\n  --token-stdin                  Read a token from stdin; do not save it\n  --json                         Print the full JSON report; the default is a concise summary\n  --delete-suite-plans           Delete Suite test records created by the run when it finishes\n  --exclude-plan ID              Explicitly exclude a full plan ID or p040 suffix; repeatable\n  --fail-fast                    Stop after the first error (default: continue collecting)\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)"
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
    fn run_excludes_unique_plan_suffix_and_enables_fail_fast_only_explicitly() {
        let parsed = routed_run(&args(&[
            "nazoauthctl",
            "oidf",
            "run",
            "openid4vc",
            "--exclude-plan",
            "p040",
            "--fail-fast",
        ]))
        .expect("parse")
        .expect("run");
        assert_eq!(parsed.excluded_plans, ["openid4vc-vp-p040"]);
        assert!(parsed.fail_fast);

        let default = routed_run(&args(&["nazoauthctl", "oidf", "run"]))
            .expect("parse")
            .expect("run");
        assert!(default.excluded_plans.is_empty());
        assert!(!default.fail_fast);
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
