use std::env;
use std::io::{self, IsTerminal as _, Write as _};
use std::time::Duration;

use anyhow::Context as _;
use cliclack::{intro, log, note, outro};
use nazoauthctl_conformance::{
    MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT_SECONDS, OutputLanguage, bundled_oidf_selection_choices,
    resolve_bundled_oidf_plan_id, resolve_bundled_oidf_selection,
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
    let args = match args
        .into_iter()
        .map(|value| {
            value.into_string().map_err(|_| {
                anyhow::anyhow!(nazoauthctl_core::presentation_text(
                    "command-line arguments must be valid UTF-8",
                    "命令行参数必须为有效的 UTF-8 文本",
                ))
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(args) => args,
        Err(error) => exit_with_error(&error, json_requested),
    };
    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error, json_requested),
    };
    let result = match invocation {
        Invocation::Core(globals) => {
            nazoauthctl_core::main_entry(args, globals);
            return;
        }
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
    Core(nazoauthctl_core::GlobalOptions),
    Configure {
        instance: Option<String>,
        tenant_domain: String,
        suite_origin: String,
    },
    Run(Box<RunInvocation>),
}

fn parse_invocation(args: &[String]) -> anyhow::Result<Invocation> {
    let values = args.get(1..).unwrap_or_default();
    let globals = nazoauthctl_core::parse_global_options(values)?;
    let command = &values[globals.consumed..];
    let Some((family, command)) = command.split_first() else {
        return Ok(Invocation::Core(globals));
    };
    if family != "oidf" {
        return Ok(Invocation::Core(globals));
    }

    if command
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_run_help();
        std::process::exit(0);
    }
    match command {
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
            "--poll-timeout" | "--jobs" => {
                let value = values.get(index + 1).with_context(|| {
                    localized_message!("{option} requires a value", "{option} 需要一个值")
                })?;
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
                let value = values.get(index + 1).with_context(|| {
                    localized_message!("{option} requires a value", "{option} 需要一个值")
                })?;
                push_unique_vec(&mut excluded_plans, value, option)?;
                index += 2;
            }
            value if value.starts_with('-') => localized_bail!(
                "unknown oidf run option: {value}",
                "OIDF 测试不支持选项 {value}"
            ),
            value => {
                set_once(&mut selector, value, "OIDF selector")?;
                index += 1;
            }
        }
    }
    let mut selection = resolve_bundled_oidf_selection(selector).map_err(|error| {
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
                    selector.unwrap_or_default()
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

fn push_unique_vec<T: PartialEq>(
    values: &mut Vec<T>,
    value: T,
    option: &str,
) -> anyhow::Result<()> {
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
            "用法：\n  nazoauthctl [--instance 实例] oidf configure --tenant-domain 域名 --suite HTTPS地址\n  nazoauthctl [--instance 实例] oidf run [分组或计划] [选项]\n\nconfigure 只需设置一次临时租户所用的通配域名后缀和 OIDF Suite 地址。未指定分组或计划时运行完整矩阵。可用别名：oidc、ciba、fapi、openid4vci、openid4vp、openid4vc；也可使用内置分组或计划的完整 ID。\n\n每次运行都会创建新的临时租户、生成新的测试资料，并仅在所选计划需要时启动浏览器任务。Suite 测试记录默认保留。\n\n选项：\n  --token-stdin                  从标准输入读取 Token，不保存\n  --json                         输出完整 JSON 报告；默认仅输出简洁摘要\n  --delete-suite-plans           运行结束后删除本次创建的 Suite 测试记录\n  --exclude-plan ID              明确排除计划，接受完整 ID 或 p040 形式，可重复指定\n  --fail-fast                    首个错误后停止后续测试（默认继续收集）\n  --jobs N                       并行计划数，1-4（默认：4）\n  --poll-timeout 秒数            单个模块等待 Suite 的最长时间（默认：1800）"
        }
        OutputLanguage::English => {
            "Usage:\n  nazoauthctl [--instance SELECTOR] oidf configure --tenant-domain DOMAIN --suite HTTPS_ORIGIN\n  nazoauthctl [--instance SELECTOR] oidf run [GROUP_OR_PLAN] [options]\n\nConfigure stores the wildcard tenant-domain suffix and OIDF Suite origin once. Without a selector, the complete bundled Matrix runs. Aliases: oidc, ciba, fapi, openid4vci, openid4vp, openid4vc. Exact bundled group and plan IDs are also accepted.\n\nEach run creates a fresh temporary tenant and test material, and starts browser workers only when the selected plan needs them. Suite test records are retained by default.\n\nOptions:\n  --token-stdin                  Read a token from stdin; do not save it\n  --json                         Print the full JSON report; the default is a concise summary\n  --delete-suite-plans           Delete Suite test records created by the run when it finishes\n  --exclude-plan ID              Explicitly exclude a full plan ID or p040 suffix; repeatable\n  --fail-fast                    Stop after the first error (default: continue collecting)\n  --jobs N                       Parallel plan workers, 1-4 (default: 4)\n  --poll-timeout SECONDS         Per-module Suite wait bound (default: 1800)"
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

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn routed_run(args: &[String]) -> anyhow::Result<Option<RunInvocation>> {
        match parse_invocation(args)? {
            Invocation::Run(invocation) => Ok(Some(*invocation)),
            _ => Ok(None),
        }
    }

    fn routed_configure(
        args: &[String],
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

    #[test]
    fn unrelated_command_is_owned_by_core() {
        assert!(
            routed_run(&args(&["nazoauthctl", "status"]))
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn core_route_keeps_the_parsed_global_prefix() {
        let invocation = parse_invocation(&args(&[
            "nazoauthctl",
            "--json",
            "--instance",
            "production",
            "status",
        ]))
        .expect("parse");
        let Invocation::Core(globals) = invocation else {
            panic!("core route")
        };
        assert_eq!(globals.instance.as_deref(), Some("production"));
        assert!(globals.json);
        assert_eq!(globals.consumed, 3);
    }

    #[test]
    fn external_artifact_commands_are_not_supported() {
        for command in ["plan", "open", "resolve", "verify"] {
            assert!(
                parse_invocation(&args(&["nazoauthctl", "oidf", "artifact", command])).is_err()
            );
        }
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
    fn security_cloud_rejects_argv_token_without_echoing_secret() {
        for suffix in [vec![], vec!["--token-stdin"]] {
            let mut values = vec!["nazoauthctl", "oidf", "run", "--token", "temporary-secret"];
            values.extend(suffix);
            let error = routed_run(&args(&values))
                .err()
                .expect("argv token must fail");
            assert!(!error.to_string().contains("temporary-secret"));
            assert!(error.to_string().contains("--token"));
        }
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
        assert!(run_help(OutputLanguage::Chinese).contains("从标准输入读取 Token，不保存"));
        assert!(run_help(OutputLanguage::English).contains("Usage:"));
    }
}
