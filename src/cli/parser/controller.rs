//! Token parser for the `controller` command family (goal plan 04, tasks
//! D04–D09).
//!
//! Grammar mirrors the fleet families: fixed subcommands, closed option sets,
//! and the shared positional/`--instance` selector merge. Approval tokens are
//! accepted as `--approval-token` for automation; interactive runs prompt on
//! the terminal with echo disabled instead.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use anyhow::{Context as _, bail};

use super::super::types::{ControllerCommand, InstanceSelector};
use super::fleet::{checked_name, parse_options};

pub(super) fn parse_controller(values: Vec<String>) -> anyhow::Result<ControllerCommand> {
    let (subcommand, rest) = values
        .split_first()
        .with_context(|| "expected controller bind|add|rotate|revoke|slots")?;
    match subcommand.as_str() {
        "bind" => parse_slot_change(rest, "bind"),
        "add" => parse_slot_change(rest, "add"),
        "rotate" => parse_rotate(rest),
        "revoke" => parse_revoke(rest),
        "slots" => parse_slots(rest),
        other => bail!("unknown controller subcommand '{other}'"),
    }
}

/// Options shared by every subcommand plus whatever the caller declared.
struct Common {
    selector: InstanceSelector,
    approval_token: Option<String>,
    admin_access_file: Option<PathBuf>,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

fn parse_common(
    values: Vec<String>,
    extra_value_flags: &[&str],
    extra_bool_flags: &[&str],
    command: &str,
) -> anyhow::Result<Common> {
    let mut value_flags = extra_value_flags.to_vec();
    value_flags.extend(["--instance", "--approval-token", "--admin-access-file"]);
    let parsed = parse_options(values, &value_flags, extra_bool_flags, command)?;
    if parsed.positionals.len() > 1 {
        bail!("{command} accepts at most one selector argument");
    }
    let named = match parsed.values.get("--instance") {
        Some(instance) => {
            checked_name("--instance", instance)?;
            Some(instance.clone())
        }
        None => None,
    };
    let approval_token = match parsed.values.get("--approval-token") {
        Some(token) => {
            if token.trim().is_empty() || token.chars().any(char::is_control) || token.len() > 512 {
                bail!("--approval-token must be a single-line bounded token");
            }
            // The raw value is kept; trimming happens again at use time so an
            // accidental trailing newline in scripted input stays harmless.
            Some(token.clone())
        }
        None => None,
    };
    let admin_access_file = match parsed.values.get("--admin-access-file") {
        Some(path) => {
            if path.is_empty() {
                bail!("--admin-access-file requires a file path");
            }
            Some(PathBuf::from(path))
        }
        None => None,
    };
    Ok(Common {
        selector: InstanceSelector {
            positional: parsed.positionals.into_iter().next(),
            named,
        },
        approval_token,
        admin_access_file,
        values: parsed.values,
        flags: parsed.flags,
    })
}

fn require_label(
    values: &BTreeMap<String, String>,
    optional: bool,
) -> anyhow::Result<Option<String>> {
    match values.get("--label") {
        Some(label) => {
            checked_name("--label", label)?;
            Ok(Some(label.clone()))
        }
        None if optional => Ok(None),
        None => bail!("--label NAME is required so administrators can recognize this key"),
    }
}

fn parse_slot_change(values: &[String], action: &'static str) -> anyhow::Result<ControllerCommand> {
    let command = format!("controller {action}");
    let common = parse_common(values.to_vec(), &["--label"], &[], &command)?;
    let label = require_label(&common.values, false)?.expect("required above");
    let selector = common.selector;
    let approval_token = common.approval_token;
    let admin_access_file = common.admin_access_file;
    Ok(match action {
        "bind" => ControllerCommand::Bind {
            selector,
            label,
            approval_token,
            admin_access_file,
        },
        _ => ControllerCommand::Add {
            selector,
            label,
            approval_token,
            admin_access_file,
        },
    })
}

fn parse_rotate(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &["--label"], &[], "controller rotate")?;
    let label = require_label(&common.values, true)?;
    let selector = common.selector;
    let approval_token = common.approval_token;
    let admin_access_file = common.admin_access_file;
    Ok(ControllerCommand::Rotate {
        selector,
        label,
        approval_token,
        admin_access_file,
    })
}

fn parse_revoke(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(
        values.to_vec(),
        &["--controller-id"],
        &["--yes"],
        "controller revoke",
    )?;
    let controller_id = common
        .values
        .get("--controller-id")
        .with_context(
            || "controller revoke requires --controller-id ID (the exact id, never a label)",
        )?
        .clone();
    checked_name("--controller-id", &controller_id)?;
    if !common.flags.contains("--yes") {
        bail!("controller revoke is destructive and requires --yes");
    }
    let selector = common.selector;
    let approval_token = common.approval_token;
    let admin_access_file = common.admin_access_file;
    Ok(ControllerCommand::Revoke {
        selector,
        controller_id,
        yes: true,
        approval_token,
        admin_access_file,
    })
}

fn parse_slots(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &[], &[], "controller slots")?;
    if common.approval_token.is_some() {
        bail!("controller slots does not accept --approval-token");
    }
    let selector = common.selector;
    let admin_access_file = common.admin_access_file;
    Ok(ControllerCommand::Slots {
        selector,
        admin_access_file,
    })
}
