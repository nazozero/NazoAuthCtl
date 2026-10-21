//! Token parser for the final command façade (goal plan 09 §1, I01).
//!
//! Command families own their option state and boundary checks in sibling modules.  This module
//! consumes the already parsed global prefix and routes tokens to the family parser.

mod common;
mod controller;
mod fleet;
mod surface;
mod tls;

use anyhow::Context as _;

use super::types::{Cli, Command, InstanceSelector};
use common::{no_arguments, parse_version_option};
use controller::parse_controller;
use fleet::{parse_host, parse_instance};
use surface::{
    parse_admin, parse_backup, parse_bind, parse_install_args, parse_policy,
    parse_read_view_selector, parse_recover, parse_update_args,
};
use tls::parse_tls;

impl Cli {
    pub(crate) fn parse(
        args: Vec<String>,
        globals: super::GlobalOptions,
    ) -> anyhow::Result<Option<Self>> {
        let mut values = args.into_iter();
        let _program = values.next();
        if values.as_slice().is_empty() {
            return Ok(None);
        }
        let command = values
            .nth(globals.consumed)
            .context("a command is required")?;
        let command = match command.as_str() {
            // ---- primary 18-command surface --------------------------------
            "host" => Command::Host(parse_host(values)?),
            "instance" => Command::Instance(parse_instance(values)?),
            "controller" => Command::Controller(parse_controller(values)?),
            "install" => Command::Install(parse_install_args(values)?),
            "discover" => {
                let mut parsed = fleet::parse_options(values, &["--host"], &[], "discover")?;
                no_arguments(&parsed.positionals, "discover")?;
                Command::Discover {
                    host: parsed.values.remove("--host"),
                }
            }
            "bind" => Command::Bind(parse_bind(values)?),
            "version" | "V" | "--version" | "-V" => {
                let (selector, all) = parse_read_view_selector(values, "version")?;
                Command::Version { selector, all }
            }
            "status" => {
                let (selector, all) = parse_read_view_selector(values, "status")?;
                Command::Status { selector, all }
            }
            "logs" => {
                let (selector, limit) = parse_limited_selector(values, "logs", 200, 500)?;
                Command::Logs { selector, limit }
            }
            "doctor" => {
                let (selector, all) = parse_read_view_selector(values, "doctor")?;
                Command::Doctor { selector, all }
            }
            "verify" => {
                let (selector, all) = parse_read_view_selector(values, "verify")?;
                if all {
                    crate::ui::fail!(
                        "verify does not accept --all",
                        "verify 不支持 --all，请指定实例"
                    );
                }
                Command::Verify { selector }
            }
            "update" => Command::Update(parse_update_args(values)?),
            "rollback" => {
                let (selector, all) = parse_read_view_selector(values, "rollback")?;
                if all {
                    crate::ui::fail!(
                        "rollback does not accept --all",
                        "rollback 不支持 --all，请指定实例"
                    );
                }
                Command::Rollback { selector }
            }
            "operation" => {
                let (parts, limit) = parse_limited_selector(values, "operation", 20, 1000)?;
                Command::Operation {
                    selector: parts,
                    limit,
                }
            }
            "backup" => Command::Backup(parse_backup(values)?),
            "policy" => Command::Policy(parse_policy(values)?),
            "recover" => Command::Recover(parse_recover(values)?),
            "uninstall" => {
                let (selector, yes) =
                    surface::parse_confirm_scoped(values, &["--yes"], "uninstall")?;
                Command::Uninstall { selector, yes }
            }
            // ---- final-model maintenance surface ---------------------------
            "admin" => Command::Admin(parse_admin(values)?),
            "tls" => Command::Tls(parse_tls(values)?),
            "remote" if values.as_slice() == ["transfer-stream"] => Command::RemoteTransferStream,
            "remote"
                if values
                    .as_slice()
                    .first()
                    .is_some_and(|value| value == "exec") =>
            {
                values.next();
                no_arguments(values.as_slice(), "remote exec")?;
                Command::RemoteExec
            }
            "self"
                if values
                    .as_slice()
                    .first()
                    .is_some_and(|value| value == "check") =>
            {
                values.next();
                Command::SelfCheck(parse_version_option(values)?)
            }
            "self"
                if values
                    .as_slice()
                    .first()
                    .is_some_and(|value| value == "verify-state") =>
            {
                values.next();
                no_arguments(values.as_slice(), "self verify-state")?;
                Command::SelfVerifyState
            }
            "self"
                if values
                    .as_slice()
                    .first()
                    .is_some_and(|value| value == "update") =>
            {
                values.next();
                Command::SelfUpdate {
                    version: parse_version_option(values)?,
                }
            }
            "self"
                if values
                    .as_slice()
                    .first()
                    .is_some_and(|value| value == "rollback") =>
            {
                values.next();
                no_arguments(values.as_slice(), "self rollback")?;
                Command::SelfRollback
            }
            other => crate::ui::fail!(
                "unknown command {other}; run `nazoauthctl --help` to see the current surface",
                "未知命令：{other}。运行 nazoauthctl --help 查看可用命令"
            ),
        };
        Ok(Some(Self {
            instance: globals.instance,
            json: globals.json,
            command,
        }))
    }
}

fn parse_limited_selector(
    values: impl IntoIterator<Item = String>,
    command: &str,
    default: usize,
    maximum: usize,
) -> anyhow::Result<(InstanceSelector, usize)> {
    let parsed = fleet::selector_parts(values, &["--limit"], &[], command)?;
    let limit = match parsed.values.get("--limit") {
        Some(raw) => raw.parse::<usize>().with_context(|| {
            crate::ui::message!(
                "{command} --limit must be an integer",
                "{command} 的 --limit 必须是整数"
            )
        })?,
        None => default,
    };
    if !(1..=maximum).contains(&limit) {
        crate::ui::fail!(
            "{command} --limit must be between 1 and {maximum}",
            "{command} 的 --limit 必须在 1 到 {maximum} 之间"
        );
    }
    Ok((
        InstanceSelector {
            positional: parsed.positional,
            named: parsed.named,
        },
        limit,
    ))
}

#[cfg(test)]
fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Option<Cli>> {
    let args: Vec<_> = args.into_iter().collect();
    let globals = super::parse_global_options(args.get(1..).unwrap_or_default())?;
    Cli::parse(args, globals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::types::{AdminCommand, Command};

    #[test]
    fn limited_commands_accept_the_shared_named_selector() {
        for command in ["logs", "operation"] {
            let (selector, limit) = parse_limited_selector(
                ["--instance", "production", "--limit", "7"].map(str::to_owned),
                command,
                20,
                1000,
            )
            .unwrap();
            assert_eq!(selector.named.as_deref(), Some("production"));
            assert!(selector.positional.is_none());
            assert_eq!(limit, 7);
        }
    }

    #[test]
    fn verify_rejects_all_instead_of_ignoring_it() {
        let error = parse(["nazoauthctl", "verify", "--all"].map(str::to_owned))
            .expect_err("verify --all must not be silently narrowed");
        assert!(error.to_string().contains("does not accept --all"));
    }

    #[test]
    fn admin_create_accepts_only_the_fixed_credentials_input_shape() {
        let parsed = parse(
            [
                "nazoauthctl",
                "admin",
                "create",
                "--instance",
                "production",
                "--credentials-stdin",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("admin create parses")
        .expect("command");
        assert!(matches!(
            parsed.command,
            Command::Admin(AdminCommand::Create(args))
                if args.selector.named.as_deref() == Some("production")
                    && args.credentials_stdin
        ));
        assert!(
            parse(
                ["nazoauthctl", "admin", "delete"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_mutation_commands_do_not_require_a_second_confirmation_flag() {
        for command in [
            vec!["nazoauthctl", "update"],
            vec!["nazoauthctl", "rollback"],
            vec!["nazoauthctl", "recover"],
            vec!["nazoauthctl", "self", "update"],
            vec!["nazoauthctl", "self", "rollback"],
            vec!["nazoauthctl", "controller", "revoke", "controller-a"],
        ] {
            assert!(
                parse(command.into_iter().map(str::to_owned)).is_ok(),
                "the command itself is the operator intent"
            );
        }

        for command in [
            vec!["nazoauthctl", "update", "--yes"],
            vec!["nazoauthctl", "rollback", "--yes"],
            vec!["nazoauthctl", "recover", "--yes"],
            vec!["nazoauthctl", "self", "update", "--yes"],
            vec!["nazoauthctl", "self", "rollback", "--yes"],
            vec!["nazoauthctl", "tls", "certificate", "apply", "--yes"],
            vec!["nazoauthctl", "tls", "certificate", "recover", "--yes"],
            vec!["nazoauthctl", "tls", "acme", "issue", "--yes"],
            vec!["nazoauthctl", "tls", "acme", "recover", "--yes"],
            vec![
                "nazoauthctl",
                "controller",
                "revoke",
                "controller-a",
                "--yes",
            ],
        ] {
            assert!(
                parse(command.into_iter().map(str::to_owned)).is_err(),
                "the removed compatibility flag must not remain accepted"
            );
        }

        assert!(
            parse(
                ["nazoauthctl", "uninstall", "--yes"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_ok(),
            "permanent deployment deletion keeps the explicit confirmation boundary"
        );
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    #[test]
    fn version_aliases_accept_instance_and_json_without_changing_other_commands() {
        for alias in ["version", "V", "--version", "-V"] {
            let cli = parse(
                ["nazoauthctl", "--json", "--instance", "production", alias].map(str::to_owned),
            )
            .unwrap()
            .unwrap();
            assert!(cli.json);
            assert_eq!(cli.instance.as_deref(), Some("production"));
            assert!(matches!(cli.command, Command::Version { all: false, .. }));
        }
        assert!(parse(["nazoauthctl", "version", "--to", "v9.0.0"].map(str::to_owned)).is_err());
    }
}
