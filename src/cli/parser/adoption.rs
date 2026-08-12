use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, bail};

use crate::adoption::AdoptionOptions;
use crate::deployment::{
    Capability, CapabilityGrant, CapabilityGrants, ResourceScope, Responsibility,
};

use super::super::types::{PermissionOptions, RelinquishOptions};
use super::common::take_yes;

pub(super) fn parse_adoption(values: Vec<String>) -> anyhow::Result<AdoptionOptions> {
    let mut target = None;
    let mut alias = None;
    let mut capabilities = CapabilityGrants::observed();
    let mut seen_capabilities = BTreeSet::new();
    let mut recovery_evidence = None;
    let mut lifecycle_contract = None;
    let mut plan = false;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--plan" => {
                if plan {
                    bail!("--plan may be specified only once");
                }
                plan = true;
                index += 1;
            }
            "--yes" => {
                if yes {
                    bail!("--yes may be specified only once");
                }
                yes = true;
                index += 1;
            }
            flag @ ("--target"
            | "--alias"
            | "--capability"
            | "--recovery-evidence"
            | "--lifecycle") => {
                let value = values
                    .get(index + 1)
                    .with_context(|| format!("{flag} requires a value"))?
                    .clone();
                match flag {
                    "--target" => {
                        if target.replace(value).is_some() {
                            bail!("--target may be specified only once");
                        }
                    }
                    "--alias" => {
                        nazo_operator_protocol::validate_file_identifier_value(&value)
                            .context("deployment alias is invalid")?;
                        if alias.replace(value).is_some() {
                            bail!("--alias may be specified only once");
                        }
                    }
                    "--capability" => {
                        let capability = apply_capability(&mut capabilities, &value)?;
                        if !seen_capabilities.insert(capability) {
                            bail!("--capability may be specified only once per capability");
                        }
                    }
                    "--recovery-evidence" => {
                        if recovery_evidence.replace(PathBuf::from(value)).is_some() {
                            bail!("--recovery-evidence may be specified only once");
                        }
                    }
                    "--lifecycle" => {
                        if lifecycle_contract.replace(PathBuf::from(value)).is_some() {
                            bail!("--lifecycle may be specified only once");
                        }
                    }
                    _ => unreachable!(),
                }
                index += 2;
            }
            other => bail!("unknown adopt option {other}"),
        }
    }
    if plan == yes {
        bail!("adopt requires exactly one of --plan or --yes");
    }
    Ok(AdoptionOptions {
        target: target.context("adopt requires --target BACKEND:OBJECT")?,
        alias,
        capabilities,
        recovery_evidence,
        lifecycle_contract,
        plan,
        yes,
    })
}

fn apply_capability(
    capabilities: &mut CapabilityGrants,
    value: &str,
) -> anyhow::Result<Capability> {
    let (capability, parsed) = parse_capability(value)?;
    *capabilities.grant_mut(capability) = parsed;
    Ok(capability)
}

fn parse_capability(value: &str) -> anyhow::Result<(Capability, CapabilityGrant)> {
    let (name, grant) = value
        .split_once('=')
        .context("--capability must be NAME=external|delegated|managed[:deployment|shared]")?;
    let (responsibility, scope) = grant
        .split_once(':')
        .map_or((grant, "deployment"), |(responsibility, scope)| {
            (responsibility, scope)
        });
    let capability = match name {
        "runtime" => Capability::Runtime,
        "artifact" => Capability::Artifact,
        "server_config" => Capability::ServerConfig,
        "database" => Capability::Database,
        "valkey" => Capability::Valkey,
        "operator_tasks" => Capability::OperatorTasks,
        "backups" => Capability::Backups,
        "proxy_tls" => Capability::ProxyTls,
        _ => bail!("unknown deployment capability {name}"),
    };
    let responsibility = match responsibility {
        "external" => Responsibility::External,
        "delegated" => Responsibility::Delegated,
        "managed" => Responsibility::Managed,
        _ => bail!("invalid capability responsibility"),
    };
    let scope = match scope {
        "deployment" => ResourceScope::Deployment,
        "shared" => ResourceScope::Shared,
        _ => bail!("invalid capability resource scope"),
    };
    Ok((
        capability,
        CapabilityGrant {
            responsibility,
            scope,
        },
    ))
}

pub(super) fn parse_permission_options(values: Vec<String>) -> anyhow::Result<PermissionOptions> {
    let (mut values, yes) = take_yes(values)?;
    let mut changes = Vec::new();
    while !values.is_empty() {
        if values.first().is_none_or(|value| value != "--capability") || values.len() < 2 {
            bail!("permissions set accepts repeated --capability NAME=GRANT and --yes");
        }
        let value = values.remove(1);
        values.remove(0);
        let change = parse_capability(&value)?;
        if changes
            .iter()
            .any(|(capability, _)| *capability == change.0)
        {
            bail!("a capability may be changed only once per transaction");
        }
        changes.push(change);
    }
    if changes.is_empty() {
        bail!("permissions set requires at least one --capability");
    }
    Ok(PermissionOptions { changes, yes })
}

pub(super) fn parse_relinquish_options(values: Vec<String>) -> anyhow::Result<RelinquishOptions> {
    let (mut values, yes) = take_yes(values)?;
    let mut capabilities = Vec::new();
    while !values.is_empty() {
        if values.first().is_none_or(|value| value != "--capability") || values.len() < 2 {
            bail!("relinquish accepts repeated --capability NAME and --yes");
        }
        let value = values.remove(1);
        values.remove(0);
        let (capability, _) = parse_capability(&format!("{value}=external"))?;
        if capabilities.contains(&capability) {
            bail!("a capability may be relinquished only once per transaction");
        }
        capabilities.push(capability);
    }
    if capabilities.is_empty() {
        bail!("relinquish requires at least one --capability");
    }
    Ok(RelinquishOptions { capabilities, yes })
}
