//! Token parser for the final command façade (goal plan 09 §1, I01).
//!
//! Command families own their option state and boundary checks in sibling modules.  This module
//! only consumes global options and routes the remaining tokens to the family parser.

mod common;
mod controller;
mod fleet;
mod surface;
mod tls;

use anyhow::{Context as _, bail};

use super::types::{Cli, Command, InstanceSelector};
use common::{no_arguments, parse_version_option};
use controller::parse_controller;
use fleet::{parse_host, parse_instance};
use surface::{
    parse_backup, parse_bind, parse_bootstrap_admin_args, parse_install_args, parse_policy,
    parse_read_view_selector, parse_recover, parse_update_args,
};
use tls::parse_tls;

impl Cli {
    pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Option<Self>> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut values = args.collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(None);
        }
        let globals = super::parse_global_options(&values)?;
        values.drain(..globals.consumed);
        if values
            .iter()
            .any(|value| matches!(value.as_str(), "-h" | "--help"))
        {
            return Ok(None);
        }
        let command = values.first().cloned().context("a command is required")?;
        values.remove(0);
        let command = match command.as_str() {
            // ---- primary 18-command surface --------------------------------
            "host" => Command::Host(parse_host(values)?),
            "instance" => Command::Instance(parse_instance(values)?),
            "controller" => Command::Controller(parse_controller(values)?),
            "install" => Command::Install(parse_install_args(values)?),
            "discover" => {
                let parsed = fleet::parse_options(values.to_vec(), &["--host"], &[], "discover")?;
                no_arguments(&parsed.positionals, "discover")?;
                Command::Discover {
                    host: parsed.values.get("--host").cloned(),
                }
            }
            "bind" => Command::Bind(parse_bind(values)?),
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
                    bail!("verify does not accept --all");
                }
                Command::Verify { selector }
            }
            "update" => Command::Update(parse_update_args(values)?),
            "rollback" => {
                let (selector, all) = parse_read_view_selector(values, "rollback")?;
                if all {
                    bail!("rollback does not accept --all");
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
            "bootstrap-admin" => Command::BootstrapAdmin(parse_bootstrap_admin_args(values)?),
            "tls" => Command::Tls(parse_tls(values)?),
            "remote" if values.first().is_some_and(|value| value == "exec") => {
                values.remove(0);
                no_arguments(&values, "remote exec")?;
                Command::RemoteExec
            }
            "self" if values.first().is_some_and(|value| value == "check") => {
                values.remove(0);
                Command::SelfCheck(parse_version_option(values)?)
            }
            "self" if values.first().is_some_and(|value| value == "update") => {
                values.remove(0);
                Command::SelfUpdate {
                    version: parse_version_option(values)?,
                }
            }
            "self" if values.first().is_some_and(|value| value == "rollback") => {
                values.remove(0);
                no_arguments(&values, "self rollback")?;
                Command::SelfRollback
            }
            other => bail!(
                "unknown command {other}; run `nazoauthctl --help` to see the current surface"
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
    values: Vec<String>,
    command: &str,
    default: usize,
    maximum: usize,
) -> anyhow::Result<(InstanceSelector, usize)> {
    let parsed = fleet::parse_options(values, &["--limit"], &[], command)?;
    let selector = surface::selector_from_parsed(&parsed)?;
    let limit = match parsed.values.get("--limit") {
        Some(raw) => raw
            .parse::<usize>()
            .with_context(|| format!("{command} --limit must be an integer"))?,
        None => default,
    };
    if !(1..=maximum).contains(&limit) {
        bail!("{command} --limit must be between 1 and {maximum}");
    }
    Ok((selector, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_all_instead_of_ignoring_it() {
        let error = Cli::parse(["nazoauthctl", "verify", "--all"].map(str::to_owned))
            .expect_err("verify --all must not be silently narrowed");
        assert!(error.to_string().contains("does not accept --all"));
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
                Cli::parse(command.into_iter().map(str::to_owned)).is_ok(),
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
                Cli::parse(command.into_iter().map(str::to_owned)).is_err(),
                "the removed compatibility flag must not remain accepted"
            );
        }

        assert!(
            Cli::parse(
                ["nazoauthctl", "uninstall", "--yes"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_ok(),
            "permanent deployment deletion keeps the explicit confirmation boundary"
        );
    }
}
