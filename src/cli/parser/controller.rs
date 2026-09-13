//! Token parser for the `controller` command family (goal plan 09 §1).
//!
//! Grammar mirrors the fleet families: fixed subcommands, closed option sets,
//! and the shared positional/`--instance` selector merge. Approval tokens are
//! accepted as `--approval-token` for automation; interactive runs prompt on
//! the terminal with echo disabled instead. `revoke` takes the exact
//! controller id as its single positional argument.

use std::path::PathBuf;

use anyhow::Context as _;

use super::super::types::{ControllerCommand, InstanceSelector};
use super::fleet::{checked_name, parse_options, selector_parts};

pub(super) fn parse_controller(values: Vec<String>) -> anyhow::Result<ControllerCommand> {
    let (subcommand, rest) = values.split_first().with_context(|| {
        crate::ui::text(
            "expected controller list|add|rotate|revoke|recover",
            "请指定 controller list、add、rotate、revoke 或 recover",
        )
    })?;
    match subcommand.as_str() {
        "list" => parse_list(rest),
        "add" => parse_add(rest),
        "rotate" => parse_rotate(rest),
        "revoke" => parse_revoke(rest),
        "recover" => parse_recover(rest),
        other => crate::ui::fail!(
            "unknown controller subcommand '{other}'",
            "未知的 controller 子命令：{other}"
        ),
    }
}

/// Options shared by every subcommand plus whatever the caller declared.
struct Common {
    selector: InstanceSelector,
    approval_token: Option<String>,
    credentials_file: Option<PathBuf>,
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
    value_flags.extend(["--instance", "--approval-token", "--credentials-file"]);
    let parsed = parse_options(values, &value_flags, extra_bool_flags, command)?;
    if parsed.positionals.len() > 1 {
        crate::ui::fail!(
            "{command} accepts at most one selector argument",
            "{command} 最多接受一个实例选择参数"
        );
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
                crate::ui::fail!(
                    "--approval-token must be a single-line bounded token",
                    "--approval-token 必须是长度符合限制的单行令牌"
                );
            }
            // The raw value is kept; trimming happens again at use time so an
            // accidental trailing newline in scripted input stays harmless.
            Some(token.clone())
        }
        None => None,
    };
    let credentials_file = match parsed.values.get("--credentials-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => crate::ui::fail!(
            "--credentials-file requires a file path",
            "--credentials-file 需要文件路径"
        ),
        None => None,
    };
    if approval_token.is_some() && credentials_file.is_some() {
        crate::ui::fail!(
            "--approval-token and --credentials-file are alternative approval sources",
            "--approval-token 和 --credentials-file 只能选择一种"
        );
    }
    Ok(Common {
        selector: InstanceSelector {
            positional: parsed.positionals.into_iter().next(),
            named,
        },
        approval_token,
        credentials_file,
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
        None => crate::ui::fail!(
            "--label NAME is required so administrators can recognize this key",
            "必须提供 --label NAME，便于管理员识别此密钥"
        ),
    }
}

fn parse_list(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let parts = selector_parts(values, &[], &[], "controller list")?;
    Ok(ControllerCommand::List {
        selector: InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
    })
}

fn parse_add(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &["--label"], &[], "controller add")?;
    let label = require_label(&common.values, false)?.expect("required above");
    Ok(ControllerCommand::Add {
        selector: common.selector,
        label,
        approval_token: common.approval_token,
        credentials_file: common.credentials_file,
    })
}

fn parse_rotate(values: &[String]) -> anyhow::Result<ControllerCommand> {
    let common = parse_common(values.to_vec(), &["--label"], &[], "controller rotate")?;
    let label = require_label(&common.values, true)?;
    Ok(ControllerCommand::Rotate {
        selector: common.selector,
        label,
        approval_token: common.approval_token,
        credentials_file: common.credentials_file,
    })
}

fn parse_revoke(values: &[String]) -> anyhow::Result<ControllerCommand> {
    // Grammar per goal plan 09 §1: controller revoke <controller-id>.
    let parts = selector_parts(
        values,
        &["--approval-token", "--credentials-file"],
        &[],
        "controller revoke",
    )?;
    let controller_id = parts.positional.clone().with_context(|| {
        crate::ui::text(
            "controller revoke requires the exact <controller-id>",
            "controller revoke 需要准确的 <controller-id>",
        )
    })?;
    checked_name("--controller-id", &controller_id)?;
    Ok(ControllerCommand::Revoke {
        selector: InstanceSelector {
            positional: None,
            named: parts.named,
        },
        controller_id,
        approval_token: parts.values.get("--approval-token").cloned(),
        credentials_file: parts.values.get("--credentials-file").map(PathBuf::from),
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
        Some(_) => crate::ui::fail!(
            "--secret-file requires a file path",
            "--secret-file 需要文件路径"
        ),
        None => None,
    };
    let output_secret_file = match common.values.get("--output-secret-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => crate::ui::fail!(
            "--output-secret-file requires a file path",
            "--output-secret-file 需要文件路径"
        ),
        None => None,
    };
    if rotate_secret && secret_file.is_some() {
        crate::ui::fail!(
            "--secret-file belongs to the recovery flow and cannot be combined with --rotate-secret",
            "--secret-file 用于恢复，不能与 --rotate-secret 同时使用"
        );
    }
    if let (Some(input), Some(output)) = (&secret_file, &output_secret_file)
        && input == output
    {
        crate::ui::fail!(
            "--output-secret-file must differ from --secret-file; the commit invalidates the \
             old secret and the new one must never overwrite it",
            "新旧密钥文件必须使用不同路径：--output-secret-file 不能与 --secret-file 相同"
        );
    }
    if common.approval_token.is_some() {
        crate::ui::fail!(
            "--approval-token is not accepted on controller recover; break-glass recovery authenticates with the recovery secret, and --rotate-secret issues approval directly through the admin API",
            "controller recover 使用恢复密钥认证，不接受 --approval-token；--rotate-secret 会直接向管理员接口申请批准"
        );
    }
    if !rotate_secret && common.credentials_file.is_some() {
        crate::ui::fail!(
            "--credentials-file is used only with controller recover --rotate-secret",
            "--credentials-file 仅用于 controller recover --rotate-secret"
        );
    }
    let label = require_label(&common.values, rotate_secret)?;
    Ok(ControllerCommand::Recover {
        selector: common.selector,
        label: label.unwrap_or_else(|| "recovered-controller".to_owned()),
        secret_file,
        rotate_secret,
        credentials_file: common.credentials_file,
        output_secret_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_accepts_only_an_instance_selector() {
        assert!(parse_list(&["production".to_owned()]).is_ok());
        assert!(
            parse_list(&[
                "--instance".to_owned(),
                "production".to_owned(),
                "--credentials-file".to_owned(),
                "access.json".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_list(&[
                "--instance".to_owned(),
                "production".to_owned(),
                "--approval-token".to_owned(),
                "token".to_owned(),
            ])
            .is_err()
        );
    }
}
