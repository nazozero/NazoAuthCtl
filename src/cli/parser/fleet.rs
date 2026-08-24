//! Token parsers for the `host` and `instance` command families (goal plan 02).
//!
//! The grammars are intentionally narrow: fixed subcommands, closed option
//! sets, and at most a couple of positional arguments. Registration accepts no
//! hand-typed deployment identity at all — the only deployment-bearing input
//! is the evidence file path consumed by `instance register`.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use anyhow::{Context as _, bail};

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
        other => bail!("unknown host subcommand '{other}'"),
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
    let ssh_profile = parsed
        .values
        .get("--ssh")
        .context("host add requires --ssh PROFILE")?;
    checked_name("--ssh", ssh_profile)?;
    let privilege = match parsed.values.get("--privilege").map(String::as_str) {
        None => HostPrivilege::Direct,
        Some("direct") => HostPrivilege::Direct,
        Some("sudo") => HostPrivilege::Sudo,
        Some(other) => bail!("--privilege must be direct or sudo, not '{other}'"),
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
        "instance list|show|observe|register|rename|forget|relocate",
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
        "observe" => {
            let parsed = parse_options(
                rest.to_vec(),
                &["--host", "--deployment-id", "--issuer", "--output"],
                &[],
                "instance observe",
            )?;
            require_no_positionals(&parsed.positionals, "instance observe")?;
            for flag in ["--host", "--deployment-id", "--issuer", "--output"] {
                parsed
                    .values
                    .get(flag)
                    .with_context(|| format!("instance observe requires {flag}"))?;
            }
            checked_name("--host", &parsed.values["--host"])?;
            checked_name("--deployment-id", &parsed.values["--deployment-id"])?;
            Ok(InstanceCommand::Observe {
                host: parsed.values["--host"].clone(),
                deployment_id: parsed.values["--deployment-id"].clone(),
                issuer: parsed.values["--issuer"].clone(),
                output: PathBuf::from(&parsed.values["--output"]),
            })
        }
        "register" => {
            let parsed = parse_options(
                rest.to_vec(),
                &["--from-discovery", "--alias"],
                &[],
                "instance register",
            )?;
            require_no_positionals(&parsed.positionals, "instance register")?;
            let from_discovery = parsed
                .values
                .get("--from-discovery")
                .context(
                    "instance register requires --from-discovery PATH: deployment identities \
                     are accepted only from a live-observed evidence artifact produced by \
                     `instance observe`; hand-typed values are never trusted",
                )?
                .clone();
            let alias = match parsed.values.get("--alias") {
                Some(alias) => {
                    checked_name("--alias", alias)?;
                    Some(alias.clone())
                }
                None => None,
            };
            Ok(InstanceCommand::Register {
                from_discovery: PathBuf::from(from_discovery),
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
                        bail!(
                            "instance rename takes either --instance OLD or the positional OLD, not both"
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
                [] => bail!("instance rename requires the new alias"),
                _ => bail!("instance rename takes at most OLD and NEW"),
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
                .context("instance relocate requires --to-host HOST_ALIAS")?
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
        other => bail!("unknown instance subcommand '{other}'"),
    }
}

/// Merge the positional selector argument with the explicit `--instance`
/// channel. Extra named flags ride along in `values`.
fn selector_parts(
    values: &[String],
    extra_value_flags: &[&str],
    bool_flags: &[&str],
    command: &str,
) -> anyhow::Result<SelectorParts> {
    let mut value_flags = extra_value_flags.to_vec();
    value_flags.push("--instance");
    let parsed = parse_options(values.to_vec(), &value_flags, bool_flags, command)?;
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
    Ok(SelectorParts {
        positional: parsed.positionals.into_iter().next(),
        named,
        values: parsed.values,
    })
}

struct SelectorParts {
    positional: Option<String>,
    named: Option<String>,
    values: BTreeMap<String, String>,
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

struct ParsedOptions {
    positionals: Vec<String>,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

fn parse_options(
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
            let value = iter
                .next()
                .with_context(|| format!("{token} requires a value"))?;
            if parsed.values.insert(token.clone(), value).is_some() {
                bail!("{token} may be specified only once");
            }
        } else if bool_flags.contains(&token.as_str()) {
            if !parsed.flags.insert(token.clone()) {
                bail!("{token} may be specified only once");
            }
        } else if token.starts_with('-') && token.len() > 1 {
            bail!("unknown {command} option {token}");
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
        bail!("{usage} accepts exactly one argument, found an extra '{extra}'");
    }
    Ok(first)
}

fn require_no_positionals(positionals: &[String], command: &str) -> anyhow::Result<()> {
    if let Some(unexpected) = positionals.first() {
        bail!("{command} does not accept the argument '{unexpected}'");
    }
    Ok(())
}

fn checked_name(flag: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        bail!("{flag} must be a non-empty bounded name without control characters");
    }
    Ok(())
}
