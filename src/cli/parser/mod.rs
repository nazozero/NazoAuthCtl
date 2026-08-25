//! Token parser for the final 18-command façade (goal plan 09 §1, I01).
//!
//! Command families own their option state and boundary checks in sibling modules.  This module
//! only consumes global options and routes the remaining tokens to the family parser. The frozen
//! pre-goal parsers (`admin`, `tls`) stay compiled for the frozen legacy runner until the second
//! J-phase pass deletes them; argv cannot reach them.

#[allow(dead_code)]
mod admin;
mod common;
mod controller;
mod fleet;
mod surface;
#[allow(dead_code)]
mod tls;

use std::{env, path::PathBuf};

use anyhow::{Context, bail};

use super::types::{self, Cli, Command};
use common::{no_arguments, parse_version_option, parse_yes, take_yes};
use controller::parse_controller;
use fleet::{parse_host, parse_instance};
use surface::{
    parse_backup, parse_bind, parse_bootstrap_admin_args, parse_install_args,
    parse_read_view_selector, parse_update_args,
};

impl Cli {
    pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Option<Self>> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut values = args.collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(None);
        }
        let globals = super::parse_global_options(&values)?;
        let config = env::var_os("NAZOAUTH_UPDATE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(types::DEFAULT_CONFIG));
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
            "logs" => Command::Logs {
                selector: parse_read_view_selector(values, "logs")?.0,
            },
            "doctor" => {
                let (selector, all) = parse_read_view_selector(values, "doctor")?;
                Command::Doctor { selector, all }
            }
            "verify" => Command::Verify {
                selector: parse_read_view_selector(values, "verify")?.0,
            },
            "update" => Command::Update(parse_update_args(values)?),
            "rollback" => {
                let (selector, yes) =
                    surface::parse_confirm_scoped(values, &["--yes"], "rollback")?;
                Command::Rollback { selector, yes }
            }
            "operation" => {
                let parsed = fleet::parse_options(values.to_vec(), &["--limit"], &[], "operation")?;
                let parts = surface::selector_from_parsed(&parsed)?;
                let limit = match parsed.values.get("--limit") {
                    Some(raw) => {
                        let value = raw.parse::<usize>().context("--limit must be an integer")?;
                        if value == 0 || value > 1000 {
                            bail!("--limit must be between 1 and 1000");
                        }
                        value
                    }
                    None => 20,
                };
                Command::Operation {
                    selector: parts,
                    limit,
                }
            }
            "policy" => {
                no_arguments(&values, "policy")?;
                Command::Policy
            }
            "backup" => Command::Backup(parse_backup(values)?),
            "recover" => Command::Recover {
                selector: parse_read_view_selector(values, "recover")?.0,
            },
            "uninstall" => {
                let (selector, yes) =
                    surface::parse_confirm_scoped(values, &["--yes"], "uninstall")?;
                Command::Uninstall { selector, yes }
            }
            // ---- final-model maintenance surface ---------------------------
            "bootstrap-admin" => Command::BootstrapAdmin(parse_bootstrap_admin_args(values)?),
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
                let (values, yes) = take_yes(values)?;
                Command::SelfUpdate {
                    version: parse_version_option(values)?,
                    yes,
                }
            }
            "self" if values.first().is_some_and(|value| value == "rollback") => {
                values.remove(0);
                Command::SelfRollback {
                    yes: parse_yes(values, "self rollback")?,
                }
            }
            other => bail!(
                "unknown command {other}; run `nazoauthctl --help` to see the current surface"
            ),
        };
        Ok(Some(Self {
            config,
            deployment: None,
            instance: globals.instance,
            json: globals.json,
            command,
        }))
    }
}
