mod admin_credentials;
mod clean_install;
mod cli;
mod conformance;
pub mod controller_identity;
mod discover_adopt;
mod error_codes;
mod file_lock;
mod fleet;
mod instance_lifecycle;
mod model;
#[cfg(feature = "pre-release-validation")]
mod pre_release;
pub mod registry;
mod release;
mod runtime_backend;
pub mod target;
mod tls;
mod ui;

pub(crate) use nazoauthctl_runtime::filesystem;
pub(crate) use nazoauthctl_runtime::process;

pub use cli::language::chinese_output;
pub use cli::{GlobalOptions, parse_global_options};
pub use conformance::{
    ConformanceControlCompletion, ConformanceControlOutcome, ConformanceDeploymentEvidence,
    ConformanceRuntimeEvidence, ConformanceSession, ControlOperationIdentity,
    OpenId4VpEvidenceVerifierInputs, configure_oidf,
};
pub use ui::{
    configure as configure_presentation, print_value as print_presentation_value,
    text as presentation_text,
};

pub fn main_entry() {
    use std::io::IsTerminal as _;

    let args = match std::env::args_os()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command-line arguments must be valid UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(error) => {
            print_entry_error("Argument parsing failed", error);
            std::process::exit(2);
        }
    };
    if let Some(topic) = cli::help_topic(&args) {
        print_help(topic);
        return;
    }
    let cli = match cli::Cli::parse(args) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_help(cli::HelpTopic::TopLevel);
            return;
        }
        Err(error) => {
            print_entry_error("Invalid command", &format!("{error:#}"));
            std::process::exit(2);
        }
    };
    let action = command_action(&cli.command).to_owned();
    let json_mode = cli.json;
    ui::configure(json_mode);
    let envelope_context = cli::envelope::EnvelopeContext {
        host: None,
        instance: cli.instance.clone(),
    };
    if let Err(error) = controller::run(cli) {
        // A partial fleet failure already printed its complete report with
        // per-item results; a second envelope would duplicate it.
        if error
            .downcast_ref::<crate::fleet::fleet_read::PartialFleetFailure>()
            .is_none()
        {
            let envelope =
                cli::envelope::render_failure(&action, &envelope_context, &error, json_mode);
            if !json_mode && std::io::stderr().is_terminal() {
                let title = cli::language::text("Command failed", "命令执行失败");
                let _ = cliclack::log::error(format!("{title}\n\n{envelope}"));
            } else {
                eprintln!("{envelope}");
            }
        } else {
            eprintln!("nazoauthctl: {error:#}");
        }
        std::process::exit(1);
    }
}

fn print_entry_error(title: &str, detail: &str) {
    use std::io::IsTerminal as _;

    if ui::json_mode() {
        eprintln!(
            "{}",
            serde_json::json!({"schema": 1, "success": false, "code": "INPUT_INVALID", "detail": detail})
        );
        return;
    }
    let title = if chinese_output() {
        match title {
            "Invalid command" => "命令无效",
            "Argument parsing failed" => "参数解析失败",
            _ => title,
        }
    } else {
        title
    };

    if std::io::stderr().is_terminal() {
        let _ = cliclack::log::error(format!("{title}\n\n{detail}"));
    } else {
        eprintln!("nazoauthctl: {title}: {detail}");
    }
}

/// The top-level token naming the failed action in the error envelope.
fn command_action(command: &cli::Command) -> &'static str {
    match command {
        cli::Command::Host(_) => "host",
        cli::Command::Instance(_) => "instance",
        cli::Command::Controller(_) => "controller",
        cli::Command::Bind(_) => "bind",
        cli::Command::Install(_) => "install",
        cli::Command::Discover { .. } => "discover",
        cli::Command::Status { .. } => "status",
        cli::Command::Logs { .. } => "logs",
        cli::Command::Doctor { .. } => "doctor",
        cli::Command::Verify { .. } => "verify",
        cli::Command::Update(_) => "update",
        cli::Command::Rollback { .. } => "rollback",
        cli::Command::Operation { .. } => "operation",
        cli::Command::Backup(_) => "backup",
        cli::Command::Policy(_) => "policy",
        cli::Command::Recover(_) => "recover",
        cli::Command::Uninstall { .. } => "uninstall",
        cli::Command::Admin(_) => "admin",
        cli::Command::Tls(_) => "tls",
        cli::Command::RemoteExec => "remote exec",
        cli::Command::SelfCheck(_) => "self check",
        cli::Command::SelfUpdate { .. } => "self update",
        cli::Command::SelfRollback => "self rollback",
        cli::Command::SelfVerifyState => "self verify-state",
    }
}

fn print_help(topic: cli::HelpTopic) {
    use std::io::IsTerminal as _;

    let help = if chinese_output() {
        cli::language::chinese_help(topic)
    } else {
        help_text(topic).to_owned()
    };
    if std::io::stdout().is_terminal() && std::io::stderr().is_terminal() {
        let _ = cliclack::note("NazoAuthCtl", help);
    } else {
        println!("{help}");
    }
}

fn help_text(topic: cli::HelpTopic) -> &'static str {
    match topic {
        cli::HelpTopic::Read => "Usage:\n  nazoauthctl status [SELECTOR] [--all]\n  nazoauthctl doctor [SELECTOR] [--all]\n  nazoauthctl logs [SELECTOR] [--limit 1-500]\n  nazoauthctl operation [SELECTOR] [--limit 1-1000]\n\nStatus shows a compact table. Doctor adds diagnostics. Logs retain the service's original text; operation shows pending and completed work. Use the global --json option for structured details.",
        cli::HelpTopic::Backup => "Usage:\n  nazoauthctl [--instance SELECTOR] backup [show]\n  nazoauthctl [--instance SELECTOR] backup snapshot\n  nazoauthctl [--instance SELECTOR] backup restore-test\n  nazoauthctl [--instance SELECTOR] backup copy --to-host HOST\n\nSnapshot creates a backup. Restore-test checks it by restoring into an isolated database. Copy transfers the verified snapshot to a different registered host.",
        cli::HelpTopic::Recover => "Usage:\n  nazoauthctl recover [SELECTOR] [--to VERSION] [--recovery-secret-file PATH]\n\nRestore data and keys from a recorded snapshot, then start the selected official release. Omitting --to selects the latest release. Interrupted recovery resumes its recorded operation. An offline recovery secret is needed only when the restored registry rejects the current controller.",
        cli::HelpTopic::Policy => "Usage:\n  nazoauthctl [--instance SELECTOR] policy backup-before-update off\n  nazoauthctl [--instance SELECTOR] policy backup-before-update warn\n  nazoauthctl [--instance SELECTOR] policy backup-before-update require --max-age-seconds N\n\nChoose whether updates ignore, warn about, or require a recent backup. The age limit is in seconds.",
        cli::HelpTopic::Bind => "Usage:\n  nazoauthctl bind [SELECTOR] --label NAME [--credentials-file PATH]\n             [--approval-token TOKEN] [--output-secret-file PATH]\n\nAuthenticate an administrator, complete MFA and bind this controller. Save the displayed recovery secret offline, or use an owner-only output file. Credential files and approval tokens are alternative authentication inputs.",
        cli::HelpTopic::Discover => "Usage:\n  nazoauthctl discover [--host HOST]\n\nInspect deployments on the selected host. Discovery does not register or change them. Use instance register to register a discovered deployment.",
        cli::HelpTopic::Remote => "Usage:\n  nazoauthctl remote exec\n\nInternal SSH transport endpoint. Reads and writes the machine protocol on standard input/output; it has no interactive interface.",
        cli::HelpTopic::TopLevel => {
            "nazoauthctl — operate NazoAuth across local and SSH hosts

Each NazoAuth installation is an INSTANCE that lives on a HOST. You register
hosts once, install or adopt instances, and bind one 30-day Controller Key
per instance. Read-only commands work per instance or, with --all, over the
whole fleet.

Usage:
  nazoauthctl [--instance SELECTOR] [--json] <command> [options]

Start here:
  nazoauthctl host add server-a --ssh prod-a --privilege sudo
  nazoauthctl install --help
  nazoauthctl admin create --instance production
  # bind authenticates that administrator and completes MFA before enrollment.
  nazoauthctl bind --instance production --label operations
  nazoauthctl status
  nazoauthctl update
  nazoauthctl instance list
  nazoauthctl status --all

Commands:
  host        Register and inspect hosts (add/list/show/check/forget)
  instance    Register and manage instances (list/show/register/rename/forget/relocate)
  controller  Per-instance Controller Key lifecycle (list/add/rotate/revoke/recover)
  install     Fresh install of one instance onto one host
  discover    Read-only sweep of every NazoAuth deployment on one target
  bind        Initial Controller Key enrollment for one instance
  status      Instance state summary (--all for the whole fleet)
  logs        Bounded, redacted application log tail (--limit 1-500)
  doctor      Health and security diagnostics (--all supported)
  verify      Independent public DNS/TLS/OIDC verification report
  update      Crash-safe update to a verified official artifact
  rollback    Return to the previous verified artifact reference
  operation   Read-only operation log from the two journals
  policy      Set backup-before-update to off, warn, or require(max age)
  backup      Create, inspect, and actually restore-test target snapshots
  recover     Restore a recorded snapshot after token invalidation is durable
  oidf        Official OIDF/OID4 conformance artifacts and runs
  uninstall   Delete exactly this instance's managed resources

Selectors:
  One registered instance is selected automatically; several instances demand
  exactly one of the global or per-command --instance flags.

Recovery:
  nazoauthctl recover [SELECTOR] [--to VERSION] [--recovery-secret-file PATH]
  The snapshot supplies data and keys. The selected current Release supplies
  the migrated runtime; omitting --to resolves the latest official Release.

Maintenance:
  self check|update|rollback   Update nazoauthctl itself (signed releases)
  admin create                 Create an administrator through the deployment root
  tls certificate|acme ...     Deployment-owned TLS material via the
                               external file-provider contract
  remote exec                  Internal stdio executor used over OpenSSH

Run `nazoauthctl <command> --help` for exact options."
        }
        cli::HelpTopic::Host => {
            "Usage:
  nazoauthctl host add <alias> --ssh PROFILE [--privilege direct|sudo]
  nazoauthctl host list [--refresh]
  nazoauthctl host show <alias>
  nazoauthctl host check <alias>
  nazoauthctl host forget <alias> [--cascade]

`host add` verifies the target helper live before anything is stored.
`host check` re-probes and reports drift against the cached observation.
`host forget` removes ONLY local registry records; it never contacts the
target, never uninstalls anything, and never revokes controller slots."
        }
        cli::HelpTopic::Instance => {
            "Usage:
  nazoauthctl instance list [--refresh]
  nazoauthctl instance show [SELECTOR]
  nazoauthctl instance register --host HOST --deployment-id ID [--alias NAME]
  nazoauthctl instance rename [OLD] NEW
  nazoauthctl instance forget [SELECTOR]
  nazoauthctl instance relocate [SELECTOR] --to-host HOST

`instance register` adopts a deployment discovered on the named host; the
binding comes from the target's own state over a verified handshake.
`instance forget` deletes ONLY the local registry entry and key selector
reference. It does not remote-uninstall, does not revoke the Controller Slot,
and does not touch target state. Deleting resources is `uninstall`; revoking
a slot is `controller revoke`."
        }
        cli::HelpTopic::Controller => {
            "Usage:
  nazoauthctl [--instance SEL] controller list
  nazoauthctl [--instance SEL] controller add --label NAME
  nazoauthctl [--instance SEL] controller rotate [--label NAME]
  nazoauthctl [--instance SEL] controller revoke <controller-id>
  nazoauthctl [--instance SEL] controller recover [--label NAME]
  nazoauthctl [--instance SEL] controller recover --rotate-secret

Every identity change needs a single-use approval backed by fresh administrator
MFA. Without an explicit approval token, ctl authenticates the administrator,
completes MFA, and requests approval for its exact in-memory proposal. An
owner-only `--credentials-file` avoids retyping the email and password.
Keys expire 30 days after enrollment. `controller revoke <id>` revokes exactly one
NazoAuth Controller Slot; it never forgets the local instance record and
never deletes artifacts or other resources. `controller recover`
re-establishes the Controller Key from the offline Recovery Secret (or, with
--rotate-secret, issues a replacement secret under fresh approval)."
        }
        cli::HelpTopic::Install => {
            "Usage:
  nazoauthctl install [--host HOST] [--name ALIAS] --public-url URL
                     --database-host HOST --database-port PORT
                     --database-name NAME
                     --database-runtime-user USER
                     --database-runtime-password-file PATH
                     --database-lifecycle-user USER
                     --database-lifecycle-password-file PATH
                     --valkey-host HOST --valkey-port PORT
                     --valkey-password-file PATH
                     [--to VERSION]
                     [--runtime podman|docker|host] [--install-root PATH]
                     [--direct-tls-config FILE --tls-material-root TARGET_DIR]

One verified handshake, one typed install order, one committed DeploymentState
(local=healthy, control unbound, public unknown). The PostgreSQL and Valkey
runtime/lifecycle PostgreSQL roles and Valkey credentials are operator-provided external facts — ctl never
invents a credential the external system does not know; password files are
read once and never logged. No backups, no public checks, no recovery media.
Next steps after install:
  nazoauthctl admin create --instance ALIAS
  nazoauthctl bind --instance ALIAS --label NAME --output-secret-file PATH
  nazoauthctl verify --instance ALIAS"
        }
        cli::HelpTopic::Update => {
            "Usage:
  nazoauthctl [--instance SEL] update [--to VERSION]
             [--config-file PATH --config-schema TOKEN]
  nazoauthctl [--instance SEL] rollback
  nazoauthctl [--instance SEL] uninstall [--yes]
  nazoauthctl [--instance SEL] verify

Update drives ONE pre-signed migration plus ONE journaled stage/activate/
health/commit HostOperation; retries resume the same operation id. Rollback
restores only saved artifact/config references; data restore stays a separate
command. Without --yes, `uninstall` shows the deletion plan and asks for confirmation
in an interactive terminal. Non-interactive runs only show the plan.
External and shared resources are kept."
        }
        cli::HelpTopic::SelfUpdate => {
            "Usage:
  nazoauthctl self check [--to VERSION]
  nazoauthctl self update [--to VERSION]
  nazoauthctl self rollback
  nazoauthctl self verify-state

Controller updates consume only signed NazoAuthCtl Release binaries and
provenance. Candidate state checks run before replacement; failed installation
verification restores the previous controller. verify-state checks local state
and backup metadata offline without changing deployments."
        }
        cli::HelpTopic::Tls => {
            "Usage:
  nazoauthctl tls certificate check --provider-config PATH --tenant T --hostname H
                                    [--warning-window-seconds S]
  nazoauthctl tls certificate plan|apply --provider-config PATH --tenant T --hostname H
                                     (--certificate F --private-key F | --from-acme-current)
                                     [--proxy-config COMPLETE_NATIVE_CONFIG]
  nazoauthctl tls certificate recover --tenant T --hostname H
  nazoauthctl tls certificate show   --tenant T --hostname H
  nazoauthctl tls acme plan|issue|recover|show --acme-config PATH --provider-config PATH --tenant T --hostname H
                         [--agree-terms]

Installs deployment-owned public TLS material through the external file-provider
contract: offline chain/SAN/key validation, an atomic generation switch, a
provider validate/reload pair, independent public verification, and a committed
receipt bound to the declaration revision. `recover` restores the exact previous
or committed generation; nothing else deletes provider material."
        }
        cli::HelpTopic::Admin => {
            "Usage:\n  nazoauthctl admin create [--instance SELECTOR] [--credentials-stdin]\n\nCreates an administrator through the target deployment's fixed local\nprovisioner. Credentials are supplied interactively or as strict JSON on\nstdin; they never enter argv, logs, or persistent ctl state. Each invocation\nis journaled as one target operation; rerun the command after a known failure."
        }
    }
}

pub(crate) mod controller;

#[cfg(test)]
#[path = "../tests/unit/entrypoint.rs"]
mod tests;
