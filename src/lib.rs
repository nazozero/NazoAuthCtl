mod clean_install;
mod cli;
mod conformance;
pub mod controller_identity;
mod deployment;
mod discover_adopt;
mod error_codes;
mod fleet;
mod install;
mod instance_lifecycle;
mod model;
pub mod registry;
mod release;
mod runtime;
mod runtime_backend;
mod runtime_identity;
pub mod target;
pub mod tenant_resources;
mod tls;

pub(crate) use nazoauthctl_runtime::filesystem;
pub(crate) use nazoauthctl_runtime::process;

pub use conformance::{
    ConformanceDeploymentEvidence, ConformanceRuntimeEvidence, ConformanceSession,
};

#[cfg(all(test, unix))]
#[path = "../tests/unit/support.rs"]
mod test_support;

pub fn main_entry() {
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
            eprintln!("nazoauthctl: argument parsing failed: {error}");
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
            eprintln!("nazoauthctl: {error:#}");
            std::process::exit(2);
        }
    };
    let action = command_action(&cli.command).to_owned();
    let json_mode = cli.json;
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
            eprintln!("{envelope}");
        } else {
            eprintln!("nazoauthctl: {error:#}");
        }
        std::process::exit(1);
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
        cli::Command::Policy => "policy",
        cli::Command::Backup(_) => "backup",
        cli::Command::Recover { .. } => "recover",
        cli::Command::Uninstall { .. } => "uninstall",
        cli::Command::BootstrapAdmin(_) => "bootstrap-admin",
        cli::Command::Tls(_) => "tls",
        cli::Command::RemoteExec => "remote exec",
        cli::Command::SelfCheck(_) => "self check",
        cli::Command::SelfUpdate { .. } => "self update",
        cli::Command::SelfRollback { .. } => "self rollback",
    }
}

fn print_help(topic: cli::HelpTopic) {
    println!("{}", help_text(topic));
}

fn help_text(topic: cli::HelpTopic) -> &'static str {
    match topic {
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
  nazoauthctl install --host server-a --name production --public-url https://auth.example.com
  nazoauthctl bind --instance production
  nazoauthctl status
  nazoauthctl update --yes
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
  logs        Application log view (lands with K-phase acceptance)
  doctor      Health and security diagnostics (--all supported)
  verify      Independent public DNS/TLS/OIDC verification report
  update      Crash-safe update to a verified official artifact
  rollback    Return to the previous verified artifact reference
  operation   Read-only operation log from the two journals
  policy      Explicit policy entries (lands with K-phase acceptance)
  backup      Backup maturity facts; explicit snapshots land with K phase
  recover     Data restore beyond rollback (lands with K-phase acceptance)
  oidf        Official OIDF/OID4 conformance artifacts and runs
  uninstall   Delete exactly this instance's managed resources

Selectors:
  One registered instance is selected automatically; several instances demand
  exactly one of the global or per-command --instance flags.

Maintenance:
  self check|update|rollback   Update nazoauthctl itself (signed releases)
  bootstrap-admin              Claim the fresh-install initial administrator
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
  nazoauthctl [--instance SEL] controller revoke <controller-id> --yes
  nazoauthctl [--instance SEL] controller recover [--label NAME]
  nazoauthctl [--instance SEL] controller recover --rotate-secret

Every identity change needs a single-use approval token created with fresh
2FA at the instance admin console; interactive runs read it hidden. Keys
expire 30 days after enrollment. `controller revoke <id>` revokes exactly one
NazoAuth Controller Slot; it never forgets the local instance record and
never deletes artifacts or other resources. `controller recover`
re-establishes the Controller Key from the offline Recovery Secret (or, with
--rotate-secret, issues a replacement secret under fresh approval)."
        }
        cli::HelpTopic::Install => {
            "Usage:
  nazoauthctl install [--host HOST] [--name ALIAS] --public-url URL
                     --database-host HOST --database-port PORT
                     --database-name NAME --database-user USER
                     --database-password-file PATH
                     --valkey-host HOST --valkey-port PORT
                     --valkey-password-file PATH
                     [--to VERSION] [--artifact-sha256 SHA256]
                     [--runtime podman|docker|host] [--install-root PATH]

One verified handshake, one typed install order, one committed DeploymentState
(local=healthy, control unbound, public unknown). The PostgreSQL and Valkey
endpoints AND their passwords are operator-provided external facts — ctl never
invents a credential the external system does not know; password files are
read once and never logged. No backups, no public checks, no recovery media.
Next steps after install:
  nazoauthctl bootstrap-admin --instance ALIAS
  nazoauthctl bind --instance ALIAS --label NAME --output-secret-file PATH
  nazoauthctl verify --instance ALIAS"
        }
        cli::HelpTopic::Update => {
            "Usage:
  nazoauthctl [--instance SEL] update --yes [--to VERSION] [--artifact-sha256 SHA256]
             [--config-file PATH --config-schema TOKEN]
  nazoauthctl [--instance SEL] rollback --yes
  nazoauthctl [--instance SEL] uninstall [--yes]
  nazoauthctl [--instance SEL] verify

Update drives ONE pre-signed migration plus ONE journaled stage/activate/
health/commit HostOperation; retries resume the same operation id. Rollback
restores only saved artifact/config references; data restore stays a separate
command. Without --yes, `uninstall` prints the exact deletion plan and
changes nothing; external/shared resources always have zero-delete protection."
        }
        cli::HelpTopic::SelfUpdate => {
            "Usage:
  nazoauthctl self check [--to VERSION]
  nazoauthctl self update [--to VERSION] --yes
  nazoauthctl self rollback --yes

Controller updates consume only signed NazoAuthCtl Release binaries and
provenance. They never select keys or state from a NazoAuth deployment."
        }
        cli::HelpTopic::Tls => {
            "Usage:
  nazoauthctl tls certificate check --provider-config PATH --tenant T --hostname H
                                    [--warning-window-seconds S]
  nazoauthctl tls certificate plan   --provider-config PATH --tenant T --hostname H
                                     (--certificate F --private-key F | --from-acme-current)
  nazoauthctl tls certificate apply  ...same inputs... [--yes]
  nazoauthctl tls certificate recover --tenant T --hostname H --yes
  nazoauthctl tls certificate show   --tenant T --hostname H
  nazoauthctl tls acme plan|issue|recover|show ... (issue requires --agree-terms [--yes])

Installs deployment-owned public TLS material through the external file-provider
contract: offline chain/SAN/key validation, an atomic generation switch, a
provider validate/reload pair, independent public verification, and a committed
receipt bound to the declaration revision. `recover` restores the exact previous
or committed generation; nothing else deletes provider material."
        }
        cli::HelpTopic::BootstrapAdmin => {
            "Usage:
  nazoauthctl bootstrap-admin [--instance SELECTOR] [--credentials-stdin]

Creates the first administrator through the fresh-install authority while it
is still open. Interactive mode prompts for email and password without echo;
non-interactive mode accepts strict JSON on stdin. The one-time capability is
closed permanently on first success."
        }
    }
}

pub(crate) mod controller;

#[cfg(test)]
#[path = "../tests/unit/entrypoint.rs"]
mod tests;
