use std::path::PathBuf;

use anyhow::{Context, bail};

use super::super::types::{TlsCertificateInput, TlsCommand};

pub(super) fn parse_tls(mut values: Vec<String>) -> anyhow::Result<TlsCommand> {
    if values.first().map(String::as_str) != Some("certificate") {
        bail!("tls requires the certificate command family");
    }
    values.remove(0);
    let operation = values
        .first()
        .cloned()
        .context("tls certificate requires plan, apply, recover, or show")?;
    values.remove(0);
    match operation.as_str() {
        "plan" => {
            let (input, yes) = parse_material_input(values, false)?;
            debug_assert!(!yes);
            Ok(TlsCommand::Plan(input))
        }
        "apply" => {
            let (input, yes) = parse_material_input(values, true)?;
            Ok(TlsCommand::Apply { input, yes })
        }
        "recover" => {
            let (tenant, hostname, yes) = parse_binding(values, true)?;
            Ok(TlsCommand::Recover {
                tenant,
                hostname,
                yes,
            })
        }
        "show" => {
            let (tenant, hostname, yes) = parse_binding(values, false)?;
            debug_assert!(!yes);
            Ok(TlsCommand::Show { tenant, hostname })
        }
        other => bail!("unknown tls certificate operation {other}"),
    }
}

fn parse_material_input(
    values: Vec<String>,
    allow_yes: bool,
) -> anyhow::Result<(TlsCertificateInput, bool)> {
    let mut provider_config = None;
    let mut tenant = None;
    let mut hostname = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        if option == "--yes" {
            if !allow_yes {
                bail!("tls certificate plan does not accept --yes");
            }
            if yes {
                bail!("--yes may be specified only once");
            }
            yes = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--provider-config" => set_once(
                &mut provider_config,
                PathBuf::from(value),
                "--provider-config",
            )?,
            "--tenant" => set_once(&mut tenant, value, "--tenant")?,
            "--hostname" => set_once(&mut hostname, value, "--hostname")?,
            "--certificate" => set_once(&mut certificate, PathBuf::from(value), "--certificate")?,
            "--private-key" => set_once(&mut private_key, PathBuf::from(value), "--private-key")?,
            other => bail!("unknown tls certificate option {other}"),
        }
        index += 2;
    }
    Ok((
        TlsCertificateInput {
            provider_config: provider_config.context("--provider-config is required")?,
            tenant: tenant.context("--tenant is required")?,
            hostname: hostname.context("--hostname is required")?,
            certificate: certificate.context("--certificate is required")?,
            private_key: private_key.context("--private-key is required")?,
        },
        yes,
    ))
}

fn parse_binding(values: Vec<String>, allow_yes: bool) -> anyhow::Result<(String, String, bool)> {
    let mut tenant = None;
    let mut hostname = None;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--yes" if allow_yes => {
                if yes {
                    bail!("--yes may be specified only once");
                }
                yes = true;
                index += 1;
            }
            option @ ("--tenant" | "--hostname") => {
                let value = values
                    .get(index + 1)
                    .with_context(|| format!("{option} requires a value"))?
                    .clone();
                match option {
                    "--tenant" => set_once(&mut tenant, value, option)?,
                    "--hostname" => set_once(&mut hostname, value, option)?,
                    _ => unreachable!(),
                }
                index += 2;
            }
            other => bail!("unknown tls certificate option {other}"),
        }
    }
    Ok((
        tenant.context("--tenant is required")?,
        hostname.context("--hostname is required")?,
        yes,
    ))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        bail!("{option} may be specified only once");
    }
    Ok(())
}
