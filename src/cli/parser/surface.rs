//! Token parsers for the instance-scoped surface commands of the final
//! 18-command model (goal plan 09 §1/§2, I01/I02): bind, install, the
//! read-only views, update, backup, and bootstrap-admin.
//!
//! Every parser here shares two rules:
//!
//! * at most one explicit selector channel per invocation (positional,
//!   per-command `--instance`, or the global `--instance` folded in later by
//!   [`InstanceSelector::merge_global`]);
//! * closed option sets — an unknown flag is a hard error, never ignored.

use std::path::PathBuf;

use anyhow::{Context as _, bail};

use super::super::types::{
    BackupArgs, BindOptions, BootstrapAdminArgs, InstallArgs, InstanceSelector, UpdateArgs,
};
use super::common::validate_version;
use super::fleet::{checked_name, parse_options, selector_parts};

/// Selector plus bool flags for read-only views (`status`, `doctor`, ...).
pub(super) fn parse_read_view_selector(
    values: Vec<String>,
    command: &str,
) -> anyhow::Result<(InstanceSelector, bool)> {
    let parts = selector_parts(&values, &[], &["--all"], command)?;
    Ok((
        InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        parts.flags.contains("--all"),
    ))
}

/// Selector plus confirmation flags for mutating commands
/// (`rollback`, `uninstall`).
pub(super) fn parse_confirm_scoped(
    values: Vec<String>,
    bool_flags: &[&str],
    command: &str,
) -> anyhow::Result<(InstanceSelector, bool)> {
    let parts = selector_parts(&values, &[], bool_flags, command)?;
    Ok((
        InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        parts.flags.contains("--yes"),
    ))
}

pub(super) fn selector_from_parsed(
    parsed: &super::fleet::ParsedOptions,
) -> anyhow::Result<InstanceSelector> {
    Ok(InstanceSelector {
        positional: parsed.positionals.first().cloned(),
        named: parsed.values.get("--instance").cloned(),
    })
}

/// `nazoauthctl bind [--instance SELECTOR] --label NAME [--approval-token T]
/// [--admin-access-file PATH] [--output-secret-file PATH]`
pub(super) fn parse_bind(values: Vec<String>) -> anyhow::Result<BindOptions> {
    let parsed = parse_options(
        values,
        &[
            "--instance",
            "--label",
            "--approval-token",
            "--admin-access-file",
            "--output-secret-file",
        ],
        &[],
        "bind",
    )?;
    if parsed.positionals.len() > 1 {
        bail!("bind accepts at most one selector argument");
    }
    let named = match parsed.values.get("--instance") {
        Some(instance) => {
            checked_name("--instance", instance)?;
            Some(instance.clone())
        }
        None => None,
    };
    let label = match parsed.values.get("--label") {
        Some(label) => {
            checked_name("--label", label)?;
            label.clone()
        }
        None => bail!("--label NAME is required so administrators can recognize this key"),
    };
    let approval_token = match parsed.values.get("--approval-token") {
        Some(token) => {
            if token.trim().is_empty() || token.chars().any(char::is_control) || token.len() > 512 {
                bail!("--approval-token must be a single-line bounded token");
            }
            Some(token.clone())
        }
        None => None,
    };
    let admin_access_file = match parsed.values.get("--admin-access-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--admin-access-file requires a file path"),
        None => None,
    };
    let output_secret_file = match parsed.values.get("--output-secret-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--output-secret-file requires a file path"),
        None => None,
    };
    Ok(BindOptions {
        selector: InstanceSelector {
            positional: parsed.positionals.into_iter().next(),
            named,
        },
        label,
        approval_token,
        admin_access_file,
        output_secret_file,
    })
}

/// `nazoauthctl install [--host HOST] [--name ALIAS] --public-url URL
/// [--to VERSION] [--artifact-sha256 SHA256] [--runtime CLASS] [--install-root PATH]`
///
/// This is the G01 clean install; the retired per-deployment installer is gone.
pub(super) fn parse_install_args(values: Vec<String>) -> anyhow::Result<InstallArgs> {
    let parsed = parse_options(
        values,
        &[
            "--host",
            "--name",
            "--public-url",
            "--to",
            "--artifact-sha256",
            "--runtime",
            "--install-root",
            "--database-host",
            "--database-port",
            "--database-name",
            "--database-user",
            "--database-password-file",
            "--valkey-host",
            "--valkey-port",
            "--valkey-password-file",
        ],
        &[],
        "install",
    )?;
    if let Some(unexpected) = parsed.positionals.first() {
        bail!("install does not accept the argument '{unexpected}'");
    }
    let public_url = parsed
        .values
        .get("--public-url")
        .context("install requires --public-url URL (the public issuer origin)")?
        .clone();
    if let Some(host) = parsed.values.get("--host") {
        checked_name("--host", host)?;
    }
    if let Some(name) = parsed.values.get("--name") {
        checked_name("--name", name)?;
    }
    let version = match parsed.values.get("--to") {
        Some(version) => {
            validate_version(version)?;
            Some(version.clone())
        }
        None => None,
    };
    let artifact_sha256 = match parsed.values.get("--artifact-sha256") {
        Some(digest) => {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("--artifact-sha256 must be 64 lowercase hexadecimal characters");
            }
            Some(digest.clone())
        }
        None => None,
    };
    let runtime = match parsed.values.get("--runtime") {
        Some(class) => {
            if !matches!(class.as_str(), "podman" | "docker" | "host") {
                bail!("--runtime must be podman, docker, or host");
            }
            Some(class.clone())
        }
        None => None,
    };
    let install_root = parsed.values.get("--install-root").map(PathBuf::from);
    let database_host = parsed
        .values
        .get("--database-host")
        .context("install requires --database-host HOST (external PostgreSQL endpoint)")?
        .clone();
    let database_port = match parsed.values.get("--database-port") {
        Some(port) => port
            .parse::<u16>()
            .context("--database-port must be 1-65535")?,
        None => bail!("install requires --database-port PORT"),
    };
    let database_name = parsed
        .values
        .get("--database-name")
        .context("install requires --database-name DATABASE")?
        .clone();
    let database_user = parsed
        .values
        .get("--database-user")
        .context("install requires --database-user ROLE")?
        .clone();
    let valkey_host = parsed
        .values
        .get("--valkey-host")
        .context("install requires --valkey-host HOST (external Valkey endpoint)")?
        .clone();
    let valkey_port = match parsed.values.get("--valkey-port") {
        Some(port) => port
            .parse::<u16>()
            .context("--valkey-port must be 1-65535")?,
        None => bail!("install requires --valkey-port PORT"),
    };
    let database_password_file = match parsed.values.get("--database-password-file") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => bail!("--database-password-file requires a file path"),
        None => bail!(
            "install requires --database-password-file PATH (the EXISTING PostgreSQL role \
             password; ctl never invents credentials the external system does not know)"
        ),
    };
    let valkey_password_file = match parsed.values.get("--valkey-password-file") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => bail!("--valkey-password-file requires a file path"),
        None => bail!(
            "install requires --valkey-password-file PATH (the EXISTING Valkey password; ctl \
             never invents credentials the external system does not know)"
        ),
    };
    Ok(InstallArgs {
        host: parsed.values.get("--host").cloned(),
        name: parsed.values.get("--name").cloned(),
        public_url,
        version,
        artifact_sha256,
        runtime,
        install_root,
        database_host,
        database_port,
        database_name,
        database_user,
        database_password_file,
        valkey_host,
        valkey_port,
        valkey_password_file,
    })
}

/// `nazoauthctl update [--instance SELECTOR] [--to VERSION]
/// [--artifact-sha256 SHA256] [--config-file PATH --config-schema TOKEN] --yes`
pub(super) fn parse_update_args(values: Vec<String>) -> anyhow::Result<UpdateArgs> {
    let parsed = parse_options(
        values,
        &[
            "--instance",
            "--to",
            "--artifact-sha256",
            "--config-file",
            "--config-schema",
        ],
        &["--yes"],
        "update",
    )?;
    if parsed.positionals.len() > 1 {
        bail!("update accepts at most one selector argument");
    }
    let named = match parsed.values.get("--instance") {
        Some(instance) => {
            checked_name("--instance", instance)?;
            Some(instance.clone())
        }
        None => None,
    };
    let version = match parsed.values.get("--to") {
        Some(version) => {
            validate_version(version)?;
            Some(version.clone())
        }
        None => None,
    };
    let artifact_sha256 = match parsed.values.get("--artifact-sha256") {
        Some(digest) => {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("--artifact-sha256 must be 64 lowercase hexadecimal characters");
            }
            Some(digest.clone())
        }
        None => None,
    };
    let config_file = parsed.values.get("--config-file").map(PathBuf::from);
    let config_schema = parsed.values.get("--config-schema").cloned();
    match (&config_file, &config_schema) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => bail!(
            "staging a configuration requires --config-file PATH together with \
             --config-schema TOKEN"
        ),
    }
    Ok(UpdateArgs {
        selector: InstanceSelector {
            positional: parsed.positionals.into_iter().next(),
            named,
        },
        version,
        artifact_sha256,
        config_file,
        config_schema,
        yes: parsed.flags.contains("--yes"),
    })
}

/// `nazoauthctl backup [show] [--instance SELECTOR]` or
/// `nazoauthctl backup snapshot [--instance SELECTOR]`.
pub(super) fn parse_backup(values: Vec<String>) -> anyhow::Result<BackupArgs> {
    let (subcommand, rest) = match values.split_first() {
        Some((first, rest)) if first == "show" || first == "snapshot" => (first.as_str(), rest),
        _ => ("show", values.as_slice()),
    };
    let parts = selector_parts(rest, &[], &[], "backup")?;
    if parts.positional.is_some() {
        bail!("backup does not accept a positional selector; use --instance");
    }
    Ok(BackupArgs {
        selector: InstanceSelector {
            positional: None,
            named: parts.named,
        },
        snapshot: subcommand == "snapshot",
    })
}

/// `nazoauthctl bootstrap-admin [--instance SELECTOR] [--credentials-stdin]`
pub(super) fn parse_bootstrap_admin_args(
    values: Vec<String>,
) -> anyhow::Result<BootstrapAdminArgs> {
    let parts = selector_parts(&values, &[], &["--credentials-stdin"], "bootstrap-admin")?;
    Ok(BootstrapAdminArgs {
        selector: InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        credentials_stdin: parts.flags.contains("--credentials-stdin"),
    })
}
