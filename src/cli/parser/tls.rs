use std::path::PathBuf;

use anyhow::Context;

use super::super::types::{
    AcmeCertificateInput, AcmeCommand, TlsCertificateCheckInput, TlsCertificateInput,
    TlsCertificateSource, TlsCommand,
};

pub(super) fn parse_tls(mut values: Vec<String>) -> anyhow::Result<TlsCommand> {
    let family = values.first().cloned().context(crate::ui::text(
        "tls requires the certificate or acme command family",
        "tls 需要 certificate 或 acme 子命令",
    ))?;
    values.remove(0);
    match family.as_str() {
        "certificate" => parse_certificate(values),
        "acme" => parse_acme(values).map(TlsCommand::Acme),
        other => crate::ui::fail!(
            "unknown tls command family {other}",
            "未知的 tls 子命令：{other}"
        ),
    }
}

fn parse_certificate(mut values: Vec<String>) -> anyhow::Result<TlsCommand> {
    let operation = values.first().cloned().context(crate::ui::text(
        "tls certificate requires check, plan, apply, recover, or show",
        "tls certificate 需要 check、plan、apply、recover 或 show",
    ))?;
    values.remove(0);
    match operation.as_str() {
        "check" => parse_check_input(values).map(TlsCommand::Check),
        "plan" => parse_material_input(values).map(TlsCommand::Plan),
        "apply" => parse_material_input(values).map(TlsCommand::Apply),
        "recover" => {
            let (tenant, hostname) = parse_binding(values, "tls certificate")?;
            Ok(TlsCommand::Recover { tenant, hostname })
        }
        "show" => {
            let (tenant, hostname) = parse_binding(values, "tls certificate")?;
            Ok(TlsCommand::Show { tenant, hostname })
        }
        other => crate::ui::fail!(
            "unknown tls certificate operation {other}",
            "未知的证书操作：{other}"
        ),
    }
}

fn parse_check_input(values: Vec<String>) -> anyhow::Result<TlsCertificateCheckInput> {
    let mut provider_config = None;
    let mut tenant = None;
    let mut hostname = None;
    let mut warning_window_seconds = None;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        let value = values
            .get(index + 1)
            .with_context(|| {
                crate::ui::message!("{option} requires a value", "{option} 需要一个值")
            })?
            .clone();
        match option {
            "--provider-config" => set_once(
                &mut provider_config,
                PathBuf::from(value),
                "--provider-config",
            )?,
            "--tenant" => set_once(&mut tenant, value, "--tenant")?,
            "--hostname" => set_once(&mut hostname, value, "--hostname")?,
            "--warning-window-seconds" => set_once(
                &mut warning_window_seconds,
                value.parse::<u64>().context(crate::ui::text(
                    "--warning-window-seconds must be an integer",
                    "--warning-window-seconds 必须为整数",
                ))?,
                "--warning-window-seconds",
            )?,
            other => crate::ui::fail!(
                "unknown tls certificate check option {other}",
                "证书检查不支持选项 {other}"
            ),
        }
        index += 2;
    }
    Ok(TlsCertificateCheckInput {
        provider_config: provider_config.context(crate::ui::text(
            "--provider-config is required",
            "必须提供 --provider-config",
        ))?,
        tenant: tenant.context(crate::ui::text("--tenant is required", "必须提供 --tenant"))?,
        hostname: hostname.context(crate::ui::text(
            "--hostname is required",
            "必须提供 --hostname",
        ))?,
        warning_window_seconds,
    })
}

fn parse_acme(mut values: Vec<String>) -> anyhow::Result<AcmeCommand> {
    let operation = values.first().cloned().context(crate::ui::text(
        "tls acme requires plan, issue, recover, or show",
        "tls acme 需要 plan、issue、recover 或 show",
    ))?;
    values.remove(0);
    match operation.as_str() {
        "plan" => {
            let (input, agree_terms) = parse_acme_input(values, false)?;
            debug_assert!(!agree_terms);
            Ok(AcmeCommand::Plan(input))
        }
        "issue" => {
            let (input, agree_terms) = parse_acme_input(values, true)?;
            Ok(AcmeCommand::Issue { input, agree_terms })
        }
        "recover" => {
            let (tenant, hostname) = parse_binding(values, "tls acme")?;
            Ok(AcmeCommand::Recover { tenant, hostname })
        }
        "show" => {
            let (tenant, hostname) = parse_binding(values, "tls acme")?;
            Ok(AcmeCommand::Show { tenant, hostname })
        }
        other => crate::ui::fail!(
            "unknown tls acme operation {other}",
            "未知的 ACME 操作：{other}"
        ),
    }
}

fn parse_acme_input(
    values: Vec<String>,
    allow_mutation_flags: bool,
) -> anyhow::Result<(AcmeCertificateInput, bool)> {
    let mut acme_config = None;
    let mut provider_config = None;
    let mut tenant = None;
    let mut hostname = None;
    let mut agree_terms = false;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        if option == "--agree-terms" {
            if !allow_mutation_flags {
                crate::ui::fail!(
                    "tls acme plan does not accept {option}",
                    "tls acme plan 不接受 {option}"
                );
            }
            if agree_terms {
                crate::ui::fail!(
                    "{option} may be specified only once",
                    "{option} 只能指定一次"
                );
            }
            agree_terms = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                crate::ui::message!("{option} requires a value", "{option} 需要一个值")
            })?
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
            other => crate::ui::fail!("unknown tls acme option {other}", "ACME 不支持选项 {other}"),
        }
        index += 2;
    }
    Ok((
        AcmeCertificateInput {
            acme_config: acme_config.context(crate::ui::text(
                "--acme-config is required",
                "必须提供 --acme-config",
            ))?,
            provider_config: provider_config.context(crate::ui::text(
                "--provider-config is required",
                "必须提供 --provider-config",
            ))?,
            tenant: tenant.context(crate::ui::text("--tenant is required", "必须提供 --tenant"))?,
            hostname: hostname.context(crate::ui::text(
                "--hostname is required",
                "必须提供 --hostname",
            ))?,
        },
        agree_terms,
    ))
}

fn parse_material_input(values: Vec<String>) -> anyhow::Result<TlsCertificateInput> {
    let mut provider_config = None;
    let mut proxy_config = None;
    let mut tenant = None;
    let mut hostname = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut from_acme_current = false;
    let mut index = 0;
    while index < values.len() {
        let option = values[index].as_str();
        if option == "--from-acme-current" {
            if from_acme_current {
                crate::ui::fail!(
                    "{option} may be specified only once",
                    "{option} 只能指定一次"
                );
            }
            from_acme_current = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| {
                crate::ui::message!("{option} requires a value", "{option} 需要一个值")
            })?
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
            "--proxy-config" => {
                set_once(&mut proxy_config, PathBuf::from(value), "--proxy-config")?
            }
            other => crate::ui::fail!(
                "unknown tls certificate option {other}",
                "证书操作不支持选项 {other}"
            ),
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
            crate::ui::fail!(
                "--from-acme-current cannot be combined with --certificate/--private-key",
                "--from-acme-current 不能与 --certificate 或 --private-key 同时使用"
            )
        }
        (None, None, false) => {
            crate::ui::fail!(
                "either --from-acme-current or --certificate with --private-key is required",
                "请选择 --from-acme-current，或同时提供 --certificate 和 --private-key"
            )
        }
        _ => crate::ui::fail!(
            "--certificate and --private-key must be supplied together",
            "--certificate 和 --private-key 必须一起提供"
        ),
    };
    Ok(TlsCertificateInput {
        provider_config: provider_config.context(crate::ui::text(
            "--provider-config is required",
            "必须提供 --provider-config",
        ))?,
        proxy_config,
        tenant: tenant.context(crate::ui::text("--tenant is required", "必须提供 --tenant"))?,
        hostname: hostname.context(crate::ui::text(
            "--hostname is required",
            "必须提供 --hostname",
        ))?,
        source,
    })
}

fn parse_binding(values: Vec<String>, command: &str) -> anyhow::Result<(String, String)> {
    let mut tenant = None;
    let mut hostname = None;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            option @ ("--tenant" | "--hostname") => {
                let value = values
                    .get(index + 1)
                    .with_context(|| {
                        crate::ui::message!("{option} requires a value", "{option} 需要一个值")
                    })?
                    .clone();
                match option {
                    "--tenant" => set_once(&mut tenant, value, option)?,
                    "--hostname" => set_once(&mut hostname, value, option)?,
                    _ => unreachable!(),
                }
                index += 2;
            }
            other => crate::ui::fail!(
                "unknown {command} option {other}",
                "{command} 不支持选项 {other}"
            ),
        }
    }
    Ok((
        tenant.context(crate::ui::text("--tenant is required", "必须提供 --tenant"))?,
        hostname.context(crate::ui::text(
            "--hostname is required",
            "必须提供 --hostname",
        ))?,
    ))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> anyhow::Result<()> {
    if slot.replace(value).is_some() {
        crate::ui::fail!(
            "{option} may be specified only once",
            "{option} 只能指定一次"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_configuration_composes_with_acme_and_rejects_duplicate_flags() -> anyhow::Result<()> {
        let mut values = [
            "--provider-config",
            "/etc/provider.json",
            "--tenant",
            "a",
            "--hostname",
            "auth.example",
            "--from-acme-current",
            "--proxy-config",
            "/etc/proxy.conf",
        ]
        .map(str::to_owned)
        .to_vec();
        let parsed = parse_material_input(values.clone())?;
        assert_eq!(parsed.proxy_config, Some(PathBuf::from("/etc/proxy.conf")));
        assert_eq!(parsed.source, TlsCertificateSource::CurrentAcmeReceipt);
        values.extend(["--proxy-config".to_owned(), "/etc/other.conf".to_owned()]);
        assert!(parse_material_input(values).is_err());
        Ok(())
    }
}
