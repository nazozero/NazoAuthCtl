use std::path::PathBuf;

use anyhow::{Context, bail};

use super::super::types::{
    AcmeCertificateInput, AcmeCommand, TlsCertificateInput, TlsCertificateSource, TlsCommand,
};

pub(super) fn parse_tls(mut values: Vec<String>) -> anyhow::Result<TlsCommand> {
    let family = values
        .first()
        .cloned()
        .context("tls requires the certificate or acme command family")?;
    values.remove(0);
    match family.as_str() {
        "certificate" => parse_certificate(values),
        "acme" => parse_acme(values).map(TlsCommand::Acme),
        other => bail!("unknown tls command family {other}"),
    }
}

fn parse_certificate(mut values: Vec<String>) -> anyhow::Result<TlsCommand> {
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
            let (tenant, hostname, yes) = parse_binding(values, true, "tls certificate")?;
            Ok(TlsCommand::Recover {
                tenant,
                hostname,
                yes,
            })
        }
        "show" => {
            let (tenant, hostname, yes) = parse_binding(values, false, "tls certificate")?;
            debug_assert!(!yes);
            Ok(TlsCommand::Show { tenant, hostname })
        }
        other => bail!("unknown tls certificate operation {other}"),
    }
}

fn parse_acme(mut values: Vec<String>) -> anyhow::Result<AcmeCommand> {
    let operation = values
        .first()
        .cloned()
        .context("tls acme requires plan, issue, recover, or show")?;
    values.remove(0);
    match operation.as_str() {
        "plan" => {
            let (input, agree_terms, yes) = parse_acme_input(values, false)?;
            debug_assert!(!agree_terms && !yes);
            Ok(AcmeCommand::Plan(input))
        }
        "issue" => {
            let (input, agree_terms, yes) = parse_acme_input(values, true)?;
            Ok(AcmeCommand::Issue {
                input,
                agree_terms,
                yes,
            })
        }
        "recover" => {
            let (tenant, hostname, yes) = parse_binding(values, true, "tls acme")?;
            Ok(AcmeCommand::Recover {
                tenant,
                hostname,
                yes,
            })
        }
        "show" => {
            let (tenant, hostname, yes) = parse_binding(values, false, "tls acme")?;
            debug_assert!(!yes);
            Ok(AcmeCommand::Show { tenant, hostname })
        }
        other => bail!("unknown tls acme operation {other}"),
    }
}

fn parse_acme_input(
    values: Vec<String>,
    allow_mutation_flags: bool,
) -> anyhow::Result<(AcmeCertificateInput, bool, bool)> {
    let mut acme_config = None;
    let mut provider_config = None;
    let mut tenant = None;
    let mut hostname = None;
    let mut agree_terms = false;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        if matches!(option, "--agree-terms" | "--yes") {
            if !allow_mutation_flags {
                bail!("tls acme plan does not accept {option}");
            }
            let flag = if option == "--agree-terms" {
                &mut agree_terms
            } else {
                &mut yes
            };
            if *flag {
                bail!("{option} may be specified only once");
            }
            *flag = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--acme-config" => set_once(&mut acme_config, PathBuf::from(value), "--acme-config")?,
            "--provider-config" => set_once(
                &mut provider_config,
                PathBuf::from(value),
                "--provider-config",
            )?,
            "--tenant" => set_once(&mut tenant, value, "--tenant")?,
            "--hostname" => set_once(&mut hostname, value, "--hostname")?,
            other => bail!("unknown tls acme option {other}"),
        }
        index += 2;
    }
    Ok((
        AcmeCertificateInput {
            acme_config: acme_config.context("--acme-config is required")?,
            provider_config: provider_config.context("--provider-config is required")?,
            tenant: tenant.context("--tenant is required")?,
            hostname: hostname.context("--hostname is required")?,
        },
        agree_terms,
        yes,
    ))
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
    let mut from_acme_current = false;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        if matches!(option, "--yes" | "--from-acme-current") {
            let flag = if option == "--yes" {
                if !allow_yes {
                    bail!("tls certificate plan does not accept --yes");
                }
                &mut yes
            } else {
                &mut from_acme_current
            };
            if *flag {
                bail!("{option} may be specified only once");
            }
            *flag = true;
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
    let source = match (certificate, private_key, from_acme_current) {
        (Some(certificate), Some(private_key), false) => TlsCertificateSource::ExternalFiles {
            certificate,
            private_key,
        },
        (None, None, true) => TlsCertificateSource::CurrentAcmeReceipt,
        (Some(_), Some(_), true) => {
            bail!("--from-acme-current cannot be combined with --certificate/--private-key")
        }
        (None, None, false) => {
            bail!("either --from-acme-current or --certificate with --private-key is required")
        }
        _ => bail!("--certificate and --private-key must be supplied together"),
    };
    Ok((
        TlsCertificateInput {
            provider_config: provider_config.context("--provider-config is required")?,
            tenant: tenant.context("--tenant is required")?,
            hostname: hostname.context("--hostname is required")?,
            source,
        },
        yes,
    ))
}

fn parse_binding(
    values: Vec<String>,
    allow_yes: bool,
    command: &str,
) -> anyhow::Result<(String, String, bool)> {
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
            other => bail!("unknown {command} option {other}"),
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
