//! Token parser for the `controller` command family (goal plan 09 §1).
//!
//! Grammar mirrors the fleet families: fixed subcommands, closed option sets,
//! and the shared positional/`--instance` selector merge. Approval tokens are
//! accepted as `--approval-token` for automation; interactive runs prompt on
//! the terminal with echo disabled instead. `revoke` takes the exact
//! controller id as its single positional argument.

use std::path::PathBuf;

use anyhow::{Context as _, bail};

use super::super::types::{ControllerCommand, InstanceSelector};
use super::fleet::{checked_name, parse_options, selector_parts};

pub(super) fn parse_controller(values: Vec<String>) -> anyhow::Result<ControllerCommand> {
    let (subcommand, rest) = values
        .split_first()
        .with_context(|| "expected controller list|add|rotate|revoke|recover")?;
    match subcommand.as_str() {
        "list" => parse_list(rest),
        "add" => parse_add(rest),
        "rotate" => parse_rotate(rest),
        "revoke" => parse_revoke(rest),
        "recover" => parse_recover(rest),
        other => bail!("unknown controller subcommand '{other}'"),
    }
}

/// Options shared by every subcommand plus whatever the caller declared.
struct Common {
    selector: InstanceSelector,
    approval_token: Option<String>,
    admin_access_file: Option<PathBuf>,
    values: std::collections::BTreeMap<String, String>,
    flags: std::collections::BTreeSet<String>,
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
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--admin-access-file requires a file path"),
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
    values: &std::collections::BTreeMap<String, String>,
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

fn parse_list(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &[], &[], "controller list")?;
    if common.approval_token.is_some() {
        bail!("controller list does not accept --approval-token");
    }
    Ok(ControllerCommand::List {
        selector: common.selector,
        admin_access_file: common.admin_access_file,
    })
}

fn parse_add(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &["--label"], &[], "controller add")?;
    let label = require_label(&common.values, false)?.expect("required above");
    Ok(ControllerCommand::Add {
        selector: common.selector,
        label,
        approval_token: common.approval_token,
        admin_access_file: common.admin_access_file,
    })
}

fn parse_rotate(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &["--label"], &[], "controller rotate")?;
    let label = require_label(&common.values, true)?;
    Ok(ControllerCommand::Rotate {
        selector: common.selector,
        label,
        approval_token: common.approval_token,
        admin_access_file: common.admin_access_file,
    })
}

fn parse_revoke(values: &[String]) -> anyhow::Result<ControllerCommand> {
    // Grammar per goal plan 09 §1: controller revoke <controller-id>.
    let parts = selector_parts(
        values,
        &["--approval-token", "--admin-access-file"],
        &["--yes"],
        "controller revoke",
    )?;
    let controller_id = parts
        .positional
        .clone()
        .with_context(|| "controller revoke requires the exact <controller-id>")?;
    checked_name("--controller-id", &controller_id)?;
    if !parts.flags.contains("--yes") {
        bail!("controller revoke is destructive and requires --yes");
    }
    Ok(ControllerCommand::Revoke {
        selector: InstanceSelector {
            positional: None,
            named: parts.named,
        },
        controller_id,
        yes: true,
        approval_token: parts.values.get("--approval-token").cloned(),
        admin_access_file: parts.values.get("--admin-access-file").map(PathBuf::from),
    })
}

fn parse_recover(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(
        values.to_vec(),
        &["--label", "--secret-file", "--output-secret-file"],
        &["--rotate-secret"],
        "controller recover",
    )?;
    let rotate_secret = common.flags.contains("--rotate-secret");
    let secret_file = match common.values.get("--secret-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--secret-file requires a file path"),
        None => None,
    };
    let output_secret_file = match common.values.get("--output-secret-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--output-secret-file requires a file path"),
        None => None,
    };
    if rotate_secret && secret_file.is_some() {
        bail!(
            "--secret-file belongs to the recovery flow and cannot be combined with --rotate-secret"
        );
    }
    if let (Some(input), Some(output)) = (&secret_file, &output_secret_file)
        && input == output
    {
        bail!(
            "--output-secret-file must differ from --secret-file; the commit invalidates the \
             old secret and the new one must never overwrite it"
        );
    }
    if common.approval_token.is_some() {
        bail!(
            "--approval-token is not accepted on controller recover; break-glass recovery authenticates with the recovery secret, and --rotate-secret issues approval directly through the admin API"
        );
    }
    let label = require_label(&common.values, rotate_secret)?;
    Ok(ControllerCommand::Recover {
        selector: common.selector,
        label: label.unwrap_or_else(|| "recovered-controller".to_owned()),
        secret_file,
        rotate_secret,
        admin_access_file: common.admin_access_file,
        output_secret_file,
    })
}
