//! Exercise the shipped entrypoint with isolated state and independent locale environments.
use std::process::{Command, Output, Stdio};

struct Sandbox(nazoauthctl_runtime::filesystem::PrivateTempDir);
impl Sandbox {
    fn new() -> Self {
        Self(nazoauthctl_runtime::filesystem::PrivateTempDir::new("ctl-presentation").unwrap())
    }
    fn run(&self, args: &[&str], locale: &str) -> Output {
        self.command(args, locale).output().unwrap()
    }
    fn command(&self, args: &[&str], locale: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nazoauthctl"));
        command
            .args(args)
            .env("LC_ALL", locale)
            .env("LC_MESSAGES", "")
            .env("LANG", "en_US.UTF-8")
            .env("APPDATA", self.0.path())
            .env("XDG_CONFIG_HOME", self.0.path())
            .env(
                "NAZOAUTHCTL_TARGET_STATE_ROOT",
                self.0.path().join("target"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}
fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn all_command_families_have_bilingual_help_without_state_or_network() {
    let sandbox = Sandbox::new();
    for command in [
        vec![],
        vec!["host"],
        vec!["instance"],
        vec!["controller"],
        vec!["install"],
        vec!["update"],
        vec!["rollback"],
        vec!["uninstall"],
        vec!["verify"],
        vec!["status"],
        vec!["doctor"],
        vec!["logs"],
        vec!["operation"],
        vec!["backup"],
        vec!["recover"],
        vec!["policy"],
        vec!["bind"],
        vec!["discover"],
        vec!["admin"],
        vec!["self"],
        vec!["tls", "certificate"],
        vec!["tls", "acme"],
        vec!["oidf"],
        vec!["oidf", "configure"],
        vec!["oidf", "run"],
        vec!["oidf", "artifact", "plan"],
        vec!["oidf", "artifact", "open"],
        vec!["oidf", "artifact", "resolve"],
        vec!["oidf", "artifact", "verify"],
    ] {
        let mut args = command.clone();
        args.push("--help");
        let zh = sandbox.run(&args, "zh_CN.UTF-8");
        let en = sandbox.run(&args, "en_US.UTF-8");
        assert!(zh.status.success(), "{args:?}: {}", stderr(&zh));
        assert!(en.status.success(), "{args:?}: {}", stderr(&en));
        assert!(stdout(&zh).contains("用法："), "{args:?}: {}", stdout(&zh));
        assert!(stdout(&en).contains("Usage:"), "{args:?}: {}", stdout(&en));
        assert!(
            !stdout(&zh).contains("\u{1b}["),
            "piped output must have no terminal controls"
        );
    }
}

#[test]
fn locale_precedence_and_empty_variable_fallback_apply_to_the_binary() {
    let sandbox = Sandbox::new();
    let mut command = sandbox.command(&["--help"], "en_US.UTF-8");
    command.env("LANG", "zh_CN.UTF-8");
    assert!(stdout(&command.output().unwrap()).contains("Usage:"));
    let mut command = sandbox.command(&["--help"], "");
    command.env("LC_MESSAGES", "zh_TW.UTF-8");
    assert!(stdout(&command.output().unwrap()).contains("用法："));
    let mut command = sandbox.command(&["--help"], "");
    command.env("LANG", "zh_CN.UTF-8");
    assert!(stdout(&command.output().unwrap()).contains("用法："));
}

#[test]
fn human_errors_and_empty_lists_are_localized_and_do_not_prompt_on_pipes() {
    let sandbox = Sandbox::new();
    for args in [
        &["unknown"][..],
        &["update", "--unknown"],
        &["oidf", "run", "--unknown"],
        &["--instance"],
    ] {
        let output = sandbox.run(args, "zh_CN.UTF-8");
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("未知")
                || stderr(&output).contains("不支持")
                || stderr(&output).contains("需要"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    let output = sandbox.run(&["status", "--all"], "zh_CN.UTF-8");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("尚未注册实例"));
    let output = sandbox.run(&["instance", "list"], "zh_CN.UTF-8");
    assert!(stdout(&output).contains("实例") && stdout(&output).contains("暂无记录"));
}

#[test]
fn json_documents_are_locale_independent_for_success_and_failure() {
    let sandbox = Sandbox::new();
    for args in [
        &["--json", "status", "--all"][..],
        &["--json", "self", "verify-state"],
        &["--json", "unknown"],
    ] {
        let en = sandbox.run(args, "en_US.UTF-8");
        let zh = sandbox.run(args, "zh_CN.UTF-8");
        let document = |output: &Output| -> serde_json::Value {
            serde_json::from_slice(if output.stdout.is_empty() {
                &output.stderr
            } else {
                &output.stdout
            })
            .unwrap()
        };
        assert_eq!(document(&en), document(&zh), "{args:?}");
    }
}

#[test]
fn instance_names_are_not_translated_as_status_tokens() {
    let sandbox = Sandbox::new();
    nazoauthctl_runtime::filesystem::ensure_private_directory(
        &sandbox.0.path().join("nazoauthctl"),
        "fixture configuration",
    )
    .unwrap();
    let store = nazoauthctl_core::registry::RegistryStore::open(
        sandbox.0.path().join("nazoauthctl/registry"),
    )
    .unwrap();
    let host = store
        .add_host(nazoauthctl_core::registry::HostRecord::new_local(
            uuid::Uuid::now_v7(),
        ))
        .unwrap();
    let record = nazoauthctl_core::registry::InstanceRecord::new(
        "deploy-presentation",
        "healthy",
        host.host_id,
        "https://example.com",
    );
    let record_path = store.root().join("instances/deploy-presentation.json");
    std::fs::create_dir_all(record_path.parent().unwrap()).unwrap();
    nazoauthctl_runtime::filesystem::atomic_write(
        &record_path,
        &serde_json::to_vec(&record.unwrap()).unwrap(),
        0o600,
    )
    .unwrap();
    store
        .set_instance_observation(
            "deploy-presentation",
            nazoauthctl_core::registry::ObservationCache::now(
                true,
                "rev=8 artifact=sha256:internal-digest",
            ),
        )
        .unwrap();
    let output = sandbox.run(&["instance", "show", "healthy"], "zh_CN.UTF-8");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("healthy"), "{}", stdout(&output));
    assert!(!stdout(&output).trim_start().starts_with('{'));
    assert!(!stdout(&output).contains("internal-digest"));
    let machine = sandbox.run(&["--json", "instance", "show", "healthy"], "zh_CN.UTF-8");
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert!(
        value["observation"]["summary"]
            .as_str()
            .unwrap()
            .contains("internal-digest")
    );
}
