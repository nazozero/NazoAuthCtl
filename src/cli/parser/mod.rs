//! Token parser for the command-line façade.
//!
//! Command families own their option state and boundary checks in sibling modules.  This module
//! only consumes global options and routes the remaining tokens to the family parser, preserving
//! the existing `Cli::parse` contract and diagnostics.

mod admin;
mod adoption;
mod common;
mod fleet;
mod install;
mod keys;
mod tls;
mod transaction;
mod update;

use std::{env, path::PathBuf};

use anyhow::{Context, bail};

use super::types::*;
use admin::parse_bootstrap_admin;
use adoption::{parse_adoption, parse_permission_options, parse_relinquish_options};
use common::{no_arguments, parse_candidate_target, parse_version_option, parse_yes, take_yes};
use fleet::{parse_host, parse_instance};
use install::parse_install;
use keys::parse_keys;
use tls::parse_tls;
use transaction::{parse_transaction_evidence, parse_transaction_resume};
use update::parse_update_options;

impl Cli {
    pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Option<Self>> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut values = args.collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(None);
        }
        let globals = super::parse_global_options(&values)?;
        let mut config = env::var_os("NAZOAUTH_UPDATE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
        if let Some(global_config) = globals.config {
            config = global_config;
        }
        let deployment = globals.deployment;
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
            "discover" => {
                no_arguments(&values, "discover")?;
                Command::Discover
            }
            "adopt" => Command::Adopt(parse_adoption(values)?),
            "deployments" if values == ["list"] => Command::DeploymentsList,
            "transaction" if values == ["show"] => Command::TransactionShow,
            "transaction" if values.first().is_some_and(|value| value == "evidence") => {
                values.remove(0);
                let (file, yes) = parse_transaction_evidence(values)?;
                Command::TransactionEvidence { file, yes }
            }
            "transaction" if values.first().is_some_and(|value| value == "resume") => {
                values.remove(0);
                let (yes, accept_migration_barrier) = parse_transaction_resume(values)?;
                Command::TransactionResume {
                    yes,
                    accept_migration_barrier,
                }
            }
            "permissions" if values.first().is_some_and(|value| value == "set") => {
                values.remove(0);
                Command::PermissionsSet(parse_permission_options(values)?)
            }
            "relinquish" => Command::Relinquish(parse_relinquish_options(values)?),
            "reconcile" => {
                no_arguments(&values, "reconcile")?;
                Command::Reconcile
            }
            "install" => Command::Install(Box::new(parse_install(values)?)),
            "bootstrap-admin" => Command::BootstrapAdmin(parse_bootstrap_admin(values)?),
            "status" => {
                no_arguments(&values, "status")?;
                Command::Status
            }
            "doctor" => {
                no_arguments(&values, "doctor")?;
                Command::Doctor
            }
            "check" => Command::Check(parse_version_option(values)?),
            "update" => Command::Update(parse_update_options(values)?),
            "development" if values.first().is_some_and(|value| value == "activate") => {
                values.remove(0);
                let mut artifact = None;
                let mut yes = false;
                let mut index = 0;
                while index < values.len() {
                    match values[index].as_str() {
                        "--artifact" => {
                            let value = values.get(index + 1).context(
                                "--artifact requires a local image reference or binary path",
                            )?;
                            if value.is_empty() || value.len() > 4096 || value.contains('\0') {
                                bail!("development artifact reference is invalid");
                            }
                            if artifact.replace(value.clone()).is_some() {
                                bail!("--artifact may be specified only once");
                            }
                            index += 2;
                        }
                        "--yes" => {
                            if yes {
                                bail!("development activate --yes may be specified only once");
                            }
                            yes = true;
                            index += 1;
                        }
                        other => bail!("unknown development activate option {other}"),
                    }
                }
                Command::DevelopmentActivate(DevelopmentActivateOptions {
                    artifact: artifact
                        .context("development activate requires --artifact IMAGE_OR_BINARY")?,
                    yes,
                })
            }
            "rollback" => Command::Rollback {
                yes: parse_yes(values, "rollback")?,
            },
            "recover" => Command::Recover {
                yes: parse_yes(values, "recover")?,
            },
            "recover-update" => Command::RecoverUpdate {
                yes: parse_yes(values, "recover-update")?,
            },
            "recover-identity" => Command::RecoverIdentity {
                yes: parse_yes(values, "recover-identity")?,
            },
            "migrate" => {
                let (values, yes) = take_yes(values)?;
                Command::Migrate {
                    yes,
                    candidate: parse_candidate_target(values)?,
                }
            }
            "keys" => Command::Keys(parse_keys(values)?),
            "host" => Command::Host(parse_host(values)?),
            "instance" => Command::Instance(parse_instance(values)?),
            "tls" => Command::Tls(parse_tls(values)?),
            "audit" if values == ["verify"] => Command::AuditVerify,
            "audit" if values.first().is_some_and(|value| value == "show") => {
                values.remove(0);
                let request_id = if values.is_empty() {
                    None
                } else if values.len() == 2 && values[0] == "--request-id" {
                    let value = values[1].clone();
                    if value.is_empty()
                        || value.len() > 128
                        || !value.chars().all(|character| {
                            character.is_ascii_alphanumeric() || "._-".contains(character)
                        })
                    {
                        bail!("audit request ID is unsafe");
                    }
                    Some(value)
                } else {
                    bail!("audit show accepts only --request-id ID");
                };
                Command::AuditShow { request_id }
            }
            "identity" if values.first().is_some_and(|value| value == "rotate") => {
                values.remove(0);
                Command::IdentityRotate {
                    yes: parse_yes(values, "identity rotate")?,
                }
            }
            "break-glass"
                if values
                    .first()
                    .is_some_and(|value| value == "controller-availability") =>
            {
                values.remove(0);
                no_arguments(&values, "break-glass controller-availability")?;
                Command::BreakGlassControllerAvailability
            }
            "break-glass"
                if values
                    .first()
                    .is_some_and(|value| value == "rehearse-controller-loss") =>
            {
                values.remove(0);
                Command::BreakGlassRehearseControllerLoss {
                    yes: parse_yes(values, "break-glass controller-loss rehearsal")?,
                }
            }
            "break-glass"
                if values
                    .first()
                    .is_some_and(|value| value == "recover-controller") =>
            {
                values.remove(0);
                let mut yes = false;
                let mut reason = None;
                let mut index = 0;
                while index < values.len() {
                    match values[index].as_str() {
                        "--yes" => {
                            if yes {
                                bail!(
                                    "break-glass recover-controller --yes may be specified only once"
                                );
                            }
                            yes = true;
                            index += 1;
                        }
                        "--reason" => {
                            if reason.is_some() {
                                bail!("--reason may be specified only once");
                            }
                            reason = Some(
                                values
                                    .get(index + 1)
                                    .context("--reason requires lost or stolen")?
                                    .clone(),
                            );
                            index += 2;
                        }
                        other => bail!("unknown break-glass option {other}"),
                    }
                }
                let reason =
                    reason.context("break-glass recovery requires --reason lost|stolen")?;
                if !matches!(reason.as_str(), "lost" | "stolen") {
                    bail!("--reason must be lost or stolen");
                }
                Command::BreakGlassRecover { yes, reason }
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
            "remote" if values.first().is_some_and(|value| value == "exec") => {
                values.remove(0);
                no_arguments(&values, "remote exec")?;
                Command::RemoteExec
            }
            other => bail!("unknown command {other}"),
        };
        Ok(Some(Self {
            config,
            deployment,
            command,
        }))
    }
}
