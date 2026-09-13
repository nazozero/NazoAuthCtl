//! Token parsers for the `host` and `instance` command families (goal plan 02).
//!
//! The grammars are intentionally narrow: fixed subcommands, closed option
//! sets, and at most a couple of positional arguments. Registration accepts no
//! hand-typed deployment identity at all — the deployment binding of
//! `instance register` comes from the target's own DeploymentState over a
//! verified handshake (G05).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context as _;

use super::super::types::{HostCommand, InstanceCommand, InstanceSelector};
use crate::registry::HostPrivilege;

pub(super) fn parse_host(values: Vec<String>) -> anyhow::Result<HostCommand> {
    let (subcommand, rest) = split_subcommand(&values, "host add|list|show|check|forget")?;
    match subcommand {
        "add" => parse_host_add(rest),
        "list" => {
            let parsed = parse_options(rest.to_vec(), &[], &["--refresh"], "host list")?;
            require_no_positionals(&parsed.positionals, "host list")?;
            Ok(HostCommand::List {
                refresh: parsed.flags.contains("--refresh"),
            })
        }
        "show" => Ok(HostCommand::Show {
            alias: exactly_one(rest.to_vec(), "host show <alias>")?,
        }),
        "check" => Ok(HostCommand::Check {
            alias: exactly_one(rest.to_vec(), "host check <alias>")?,
        }),
        "forget" => {
            let parsed = parse_options(rest.to_vec(), &[], &["--cascade"], "host forget")?;
            Ok(HostCommand::Forget {
                alias: exactly_one(parsed.positionals, "host forget <alias>")?,
                cascade: parsed.flags.contains("--cascade"),
            })
        }
        other => crate::ui::fail!(
            "unknown host subcommand '{other}'",
            "未知的 host 子命令：{other}"
        ),
    }
}

fn parse_host_add(values: &[String]) -> anyhow::Result<HostCommand> {
    let parsed = parse_options(
        values.to_owned(),
        &["--ssh", "--privilege"],
        &[],
        "host add",
    )?;
    let alias = exactly_one(parsed.positionals, "host add <alias> --ssh PROFILE")?;
    checked_name("alias", &alias)?;
    let ssh_profile = parsed.values.get("--ssh").context(crate::ui::text(
        "host add requires --ssh PROFILE",
        "host add 需要 --ssh PROFILE",
    ))?;
    checked_name("--ssh", ssh_profile)?;
    let privilege = match parsed.values.get("--privilege").map(String::as_str) {
        None => HostPrivilege::Direct,
        Some("direct") => HostPrivilege::Direct,
        Some("sudo") => HostPrivilege::Sudo,
        Some(other) => crate::ui::fail!(
            "--privilege must be direct or sudo, not '{other}'",
            "--privilege 必须为 direct 或 sudo，当前值为“{other}”"
        ),
    };
    Ok(HostCommand::Add {
        alias,
        ssh_profile: ssh_profile.clone(),
        privilege,
    })
}

pub(super) fn parse_instance(values: Vec<String>) -> anyhow::Result<InstanceCommand> {
    let (subcommand, rest) = split_subcommand(
        &values,
        "instance list|show|register|rename|forget|relocate",
    )?;
    match subcommand {
        "list" => {
            let parsed = parse_options(rest.to_vec(), &[], &["--refresh"], "instance list")?;
            require_no_positionals(&parsed.positionals, "instance list")?;
            Ok(InstanceCommand::List {
                refresh: parsed.flags.contains("--refresh"),
            })
        }
        "show" => {
            let parts = selector_parts(rest, &[], &[], "instance show")?;
            Ok(InstanceCommand::Show(InstanceSelector {
                positional: parts.positional,
                named: parts.named,
            }))
        }
        "register" => {
            // Controlled takeover (G05): the deployment binding comes from the
            // target's own DeploymentState over a verified handshake.
            let parsed = parse_options(
                rest.to_vec(),
                &["--host", "--deployment-id", "--alias"],
                &[],
                "instance register",
            )?;
            require_no_positionals(&parsed.positionals, "instance register")?;
            for flag in ["--host", "--deployment-id"] {
                parsed.values.get(flag).with_context(|| {
                    crate::ui::message!(
                        "instance register requires {flag}",
                        "instance register 需要 {flag}"
                    )
                })?;
            }
            checked_name("--host", &parsed.values["--host"])?;
            checked_name("--deployment-id", &parsed.values["--deployment-id"])?;
            let alias = match parsed.values.get("--alias") {
                Some(alias) => {
                    checked_name("--alias", alias)?;
                    Some(alias.clone())
                }
                None => None,
            };
            Ok(InstanceCommand::Register {
                host: parsed.values["--host"].clone(),
                deployment_id: parsed.values["--deployment-id"].clone(),
                alias,
            })
        }
        "rename" => {
            // Grammar: `[OLD] NEW`, or `--instance OLD NEW`.
            let parsed = parse_options(rest.to_vec(), &["--instance"], &[], "instance rename")?;
            let named = match parsed.values.get("--instance") {
                Some(instance) => {
                    checked_name("--instance", instance)?;
                    Some(instance.clone())
                }
                None => None,
            };
            let (source, new_alias) = match parsed.positionals.as_slice() {
                [new_alias] => (
                    InstanceSelector {
                        positional: None,
                        named,
                    },
                    new_alias.clone(),
                ),
                [old, new_alias] => {
                    if named.is_some() {
                        crate::ui::fail!(
                            "instance rename takes either --instance OLD or the positional OLD, not both",
                            "旧实例名称只能通过 --instance OLD 或位置参数 OLD 指定一次"
                        );
                    }
                    checked_name("old selector", old)?;
                    (
                        InstanceSelector {
                            positional: Some(old.clone()),
                            named: None,
                        },
                        new_alias.clone(),
                    )
                }
                [] => crate::ui::fail!(
                    "instance rename requires the new alias",
                    "instance rename 需要新名称"
                ),
                _ => crate::ui::fail!(
                    "instance rename takes at most OLD and NEW",
                    "instance rename 最多接受 OLD 和 NEW 两个参数"
                ),
            };
            checked_name("new alias", &new_alias)?;
            Ok(InstanceCommand::Rename { source, new_alias })
        }
        "forget" => {
            let parts = selector_parts(rest, &[], &[], "instance forget")?;
            Ok(InstanceCommand::Forget(InstanceSelector {
                positional: parts.positional,
                named: parts.named,
            }))
        }
        "relocate" => {
            let parts = selector_parts(rest, &["--to-host"], &[], "instance relocate")?;
            let to_host = parts
                .values
                .get("--to-host")
                .context(crate::ui::text(
                    "instance relocate requires --to-host HOST_ALIAS",
                    "instance relocate 需要 --to-host HOST_ALIAS",
                ))?
                .clone();
            checked_name("--to-host", &to_host)?;
            Ok(InstanceCommand::Relocate {
                selector: InstanceSelector {
                    positional: parts.positional,
                    named: parts.named,
                },
                to_host,
            })
        }
        other => crate::ui::fail!(
            "unknown instance subcommand '{other}'",
            "未知的 instance 子命令：{other}"
        ),
    }
}

/// Merge the positional selector argument with the explicit `--instance`
/// channel. Extra named flags ride along in `values`.
pub(super) fn selector_parts(
    values: &[String],
    extra_value_flags: &[&str],
    bool_flags: &[&str],
    command: &str,
) -> anyhow::Result<SelectorParts> {
    let mut value_flags = extra_value_flags.to_vec();
    value_flags.push("--instance");
    let parsed = parse_options(values.to_vec(), &value_flags, bool_flags, command)?;
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
    Ok(SelectorParts {
        positional: parsed.positionals.into_iter().next(),
        named,
        values: parsed.values,
        flags: parsed.flags,
    })
}

pub(super) struct SelectorParts {
    pub(super) positional: Option<String>,
    pub(super) named: Option<String>,
    pub(super) values: BTreeMap<String, String>,
    pub(super) flags: BTreeSet<String>,
}

fn split_subcommand<'a>(
    values: &'a [String],
    usage: &str,
) -> anyhow::Result<(&'a str, &'a [String])> {
    let (subcommand, rest) = values
        .split_first()
        .with_context(|| format!("expected {usage}"))?;
    Ok((subcommand.as_str(), rest))
}

pub(super) struct ParsedOptions {
    pub(super) positionals: Vec<String>,
    pub(super) values: BTreeMap<String, String>,
    pub(super) flags: BTreeSet<String>,
}

pub(super) fn parse_options(
    values: Vec<String>,
    value_flags: &[&str],
    bool_flags: &[&str],
    command: &str,
) -> anyhow::Result<ParsedOptions> {
    let mut parsed = ParsedOptions {
        positionals: Vec::new(),
        values: BTreeMap::new(),
        flags: BTreeSet::new(),
    };
    let mut iter = values.into_iter();
    while let Some(token) = iter.next() {
        if value_flags.contains(&token.as_str()) {
            let value = iter.next().with_context(|| {
                crate::ui::message!("{token} requires a value", "{token} 需要一个值")
            })?;
            if parsed.values.insert(token.clone(), value).is_some() {
                crate::ui::fail!("{token} may be specified only once", "{token} 只能指定一次");
            }
        } else if bool_flags.contains(&token.as_str()) {
            if !parsed.flags.insert(token.clone()) {
                crate::ui::fail!("{token} may be specified only once", "{token} 只能指定一次");
            }
        } else if token.starts_with('-') && token.len() > 1 {
            crate::ui::fail!(
                "unknown {command} option {token}",
                "{command} 不支持选项 {token}"
            );
        } else {
            parsed.positionals.push(token);
        }
    }
    Ok(parsed)
}

fn exactly_one(values: Vec<String>, usage: &str) -> anyhow::Result<String> {
    let mut iter = values.into_iter();
    let first = iter
        .next()
        .with_context(|| format!("{usage} is required"))?;
    if let Some(extra) = iter.next() {
        crate::ui::fail!(
            "{usage} accepts exactly one argument, found an extra '{extra}'",
            "{usage} 仅接受一个参数，多余参数为“{extra}”"
        );
    }
    Ok(first)
}

fn require_no_positionals(positionals: &[String], command: &str) -> anyhow::Result<()> {
    if let Some(unexpected) = positionals.first() {
        crate::ui::fail!(
            "{command} does not accept the argument '{unexpected}'",
            "{command} 不接受参数“{unexpected}”"
        );
    }
    Ok(())
}

pub(super) fn checked_name(flag: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        crate::ui::fail!(
            "{flag} must be a non-empty bounded name without control characters",
            "{flag} 名称不能为空、超长或包含控制字符"
        );
    }
    Ok(())
}
