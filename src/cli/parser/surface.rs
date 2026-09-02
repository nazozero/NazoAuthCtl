//! Token parsers for the instance-scoped surface commands of the final
//! 18-command model (goal plan 09 §1/§2, I01/I02): bind, install, the
//! read-only views, update, and backup.
//!
//! Every parser here shares two rules:
//!
//! * at most one explicit selector channel per invocation (positional,
//!   per-command `--instance`, or the global `--instance` folded in later by
//!   [`InstanceSelector::merge_global`]);
//! * closed option sets — an unknown flag is a hard error, never ignored.

use std::path::PathBuf;

use anyhow::{Context as _, bail};

use crate::runtime_backend::RuntimeBackendKind;

use super::super::types::{
    AdminCommand, AdminCreateArgs, BackupArgs, BackupCommand, BindOptions, InstallArgs,
    InstanceSelector, PolicyArgs, RecoverArgs, UpdateArgs,
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
/// [--credentials-file PATH] [--output-secret-file PATH]`
pub(super) fn parse_bind(values: Vec<String>) -> anyhow::Result<BindOptions> {
    let parsed = parse_options(
        values,
        &[
            "--instance",
            "--label",
            "--approval-token",
            "--credentials-file",
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
    let credentials_file = match parsed.values.get("--credentials-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => bail!("--credentials-file requires a file path"),
        None => None,
    };
    if approval_token.is_some() && credentials_file.is_some() {
        bail!("--approval-token and --credentials-file are alternative approval sources");
    }
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
        credentials_file,
        output_secret_file,
    })
}

/// `nazoauthctl install [--host HOST] [--name ALIAS] --public-url URL
/// [--to VERSION] [--runtime CLASS] [--install-root PATH]`
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
            "--runtime",
            "--install-root",
            "--database-host",
            "--database-port",
            "--database-name",
            "--database-runtime-user",
            "--database-runtime-password-file",
            "--database-lifecycle-user",
            "--database-lifecycle-password-file",
            "--valkey-host",
            "--valkey-port",
            "--valkey-password-file",
            "--import-data-root",
            "--import-mfa-key-file",
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
    let runtime = parsed
        .values
        .get("--runtime")
        .map(|class| class.parse::<RuntimeBackendKind>())
        .transpose()
        .context("--runtime must be podman, docker, or host")?;
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
    let database_runtime_user = parsed
        .values
        .get("--database-runtime-user")
        .context("install requires --database-runtime-user ROLE")?
        .clone();
    let database_lifecycle_user = parsed
        .values
        .get("--database-lifecycle-user")
        .context("install requires --database-lifecycle-user ROLE")?
        .clone();
    if database_runtime_user == database_lifecycle_user {
        bail!("runtime and lifecycle PostgreSQL roles must be distinct");
    }
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
    let database_runtime_password_file = match parsed.values.get("--database-runtime-password-file")
    {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => bail!("--database-runtime-password-file requires a file path"),
        None => bail!(
            "install requires --database-runtime-password-file PATH (the EXISTING PostgreSQL runtime role \
             password; ctl never invents credentials the external system does not know)"
        ),
    };
    let database_lifecycle_password_file = match parsed
        .values
        .get("--database-lifecycle-password-file")
    {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => bail!("--database-lifecycle-password-file requires a file path"),
        None => bail!(
            "install requires --database-lifecycle-password-file PATH (the EXISTING PostgreSQL lifecycle role password)"
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
    let target_path = |flag: &str| -> anyhow::Result<Option<PathBuf>> {
        let Some(value) = parsed.values.get(flag) else {
            return Ok(None);
        };
        let windows_absolute = value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\');
        if value.is_empty()
            || value.len() > 512
            || (!value.starts_with('/') && !windows_absolute)
            || value
                .split(['/', '\\'])
                .any(|part| matches!(part, "." | ".."))
            || value.chars().any(char::is_control)
        {
            bail!("{flag} must be a bounded absolute target-side path without traversal");
        }
        Ok(Some(PathBuf::from(value)))
    };
    let import_data_root = target_path("--import-data-root")?;
    let import_mfa_key_file = target_path("--import-mfa-key-file")?;
    if import_data_root.is_some() != import_mfa_key_file.is_some() {
        bail!(
            "--import-data-root and --import-mfa-key-file must be supplied together for one current-format import"
        );
    }
    Ok(InstallArgs {
        host: parsed.values.get("--host").cloned(),
        name: parsed.values.get("--name").cloned(),
        public_url,
        version,
        runtime,
        install_root,
        database_host,
        database_port,
        database_name,
        database_runtime_user,
        database_runtime_password_file,
        database_lifecycle_user,
        database_lifecycle_password_file,
        valkey_host,
        valkey_port,
        valkey_password_file,
        import_data_root,
        import_mfa_key_file,
    })
}

/// `nazoauthctl update [--instance SELECTOR] [--to VERSION]
/// [--config-file PATH --config-schema TOKEN]`
pub(super) fn parse_update_args(values: Vec<String>) -> anyhow::Result<UpdateArgs> {
    let parsed = parse_options(
        values,
        &["--instance", "--to", "--config-file", "--config-schema"],
        &[],
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
        config_file,
        config_schema,
    })
}

/// `nazoauthctl backup show|snapshot|restore-test|copy [--instance SELECTOR]`.
pub(super) fn parse_backup(values: Vec<String>) -> anyhow::Result<BackupArgs> {
    let (command, rest) = match values.split_first() {
        None => (BackupCommand::Show, values.as_slice()),
        Some((first, rest)) => match first.as_str() {
            "show" => (BackupCommand::Show, rest),
            "snapshot" => (BackupCommand::Snapshot, rest),
            "restore-test" => (BackupCommand::RestoreTest, rest),
            "copy" => {
                let parts = selector_parts(rest, &["--to-host"], &[], "backup copy")?;
                if parts.positional.is_some() {
                    bail!("backup copy does not accept a positional selector; use --instance");
                }
                let to_host = parts
                    .values
                    .get("--to-host")
                    .cloned()
                    .context("backup copy requires --to-host HOST")?;
                return Ok(BackupArgs {
                    selector: InstanceSelector {
                        positional: None,
                        named: parts.named,
                    },
                    command: BackupCommand::Copy { to_host },
                });
            }
            _ => bail!("backup requires show, snapshot, restore-test, or copy"),
        },
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
        command,
    })
}

/// `nazoauthctl policy backup-before-update off|warn|require --max-age-seconds N`.
pub(super) fn parse_policy(values: Vec<String>) -> anyhow::Result<PolicyArgs> {
    let Some((subject, rest)) = values.split_first() else {
        bail!("policy requires backup-before-update");
    };
    if subject != "backup-before-update" {
        bail!("policy only supports backup-before-update");
    }
    let Some((mode, rest)) = rest.split_first() else {
        bail!("backup-before-update requires off, warn, or require");
    };
    let parts = selector_parts(
        rest,
        &["--max-age-seconds"],
        &[],
        "policy backup-before-update",
    )?;
    let policy = match mode.as_str() {
        "off" => {
            if parts.values.contains_key("--max-age-seconds") {
                bail!("off does not accept --max-age-seconds");
            }
            crate::registry::BackupBeforeUpdatePolicy::Off
        }
        "warn" => {
            if parts.values.contains_key("--max-age-seconds") {
                bail!("warn does not accept --max-age-seconds");
            }
            crate::registry::BackupBeforeUpdatePolicy::Warn
        }
        "require" => {
            let value = parts
                .values
                .get("--max-age-seconds")
                .context("require needs --max-age-seconds")?;
            let max_age_seconds = value
                .parse::<u64>()
                .context("--max-age-seconds must be an integer")?;
            crate::registry::BackupBeforeUpdatePolicy::Require { max_age_seconds }
        }
        _ => bail!("backup-before-update requires off, warn, or require"),
    };
    policy.validate()?;
    Ok(PolicyArgs {
        selector: InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        mode: policy,
    })
}

pub(super) fn parse_recover(values: Vec<String>) -> anyhow::Result<RecoverArgs> {
    let parts = selector_parts(&values, &["--to", "--recovery-secret-file"], &[], "recover")?;
    let version = parts.values.get("--to").cloned();
    if let Some(version) = &version {
        validate_version(version)?;
    }
    let recovery_secret_file = parts
        .values
        .get("--recovery-secret-file")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    Ok(RecoverArgs {
        selector: InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        version,
        recovery_secret_file,
    })
}

/// `nazoauthctl admin create [--instance SELECTOR] [--credentials-stdin]`
pub(super) fn parse_admin(values: Vec<String>) -> anyhow::Result<AdminCommand> {
    let (subcommand, rest) = values
        .split_first()
        .with_context(|| "expected admin create")?;
    if *subcommand != "create" {
        bail!("unknown admin subcommand '{subcommand}'");
    }
    let parts = selector_parts(rest, &[], &["--credentials-stdin"], "admin create")?;
    Ok(AdminCommand::Create(AdminCreateArgs {
        selector: InstanceSelector {
            positional: parts.positional,
            named: parts.named,
        },
        credentials_stdin: parts.flags.contains("--credentials-stdin"),
    }))
}

#[cfg(test)]
mod install_tests {
    use super::*;

    fn current_args() -> Vec<String> {
        [
            "--public-url",
            "https://auth.example.com",
            "--database-host",
            "db.internal",
            "--database-port",
            "5432",
            "--database-name",
            "nazoauth",
            "--database-runtime-user",
            "nazo_runtime",
            "--database-runtime-password-file",
            "runtime-password",
            "--database-lifecycle-user",
            "nazo_lifecycle",
            "--database-lifecycle-password-file",
            "lifecycle-password",
            "--valkey-host",
            "valkey.internal",
            "--valkey-port",
            "6379",
            "--valkey-password-file",
            "valkey-password",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn install_accepts_exactly_two_distinct_database_roles() -> anyhow::Result<()> {
        let parsed = parse_install_args(current_args())?;
        assert_eq!(parsed.database_runtime_user, "nazo_runtime");
        assert_eq!(parsed.database_lifecycle_user, "nazo_lifecycle");

        let mut same = current_args();
        let index = same
            .iter()
            .position(|value| value == "nazo_lifecycle")
            .expect("lifecycle role");
        same[index] = "nazo_runtime".to_owned();
        assert!(parse_install_args(same).is_err());

        let mut legacy = current_args();
        legacy.extend(["--database-user".to_owned(), "legacy".to_owned()]);
        assert!(parse_install_args(legacy).is_err());
        Ok(())
    }

    #[test]
    fn current_data_import_paths_are_an_exact_pair() -> anyhow::Result<()> {
        let mut paired = current_args();
        paired.extend([
            "--import-data-root".to_owned(),
            "/srv/current-data".to_owned(),
            "--import-mfa-key-file".to_owned(),
            "/run/current-mfa".to_owned(),
        ]);
        let parsed = parse_install_args(paired)?;
        assert!(parsed.import_data_root.is_some());
        assert!(parsed.import_mfa_key_file.is_some());

        let mut incomplete = current_args();
        incomplete.extend([
            "--import-data-root".to_owned(),
            "/srv/current-data".to_owned(),
        ]);
        assert!(parse_install_args(incomplete).is_err());
        let mut relative = current_args();
        relative.extend([
            "--import-data-root".to_owned(),
            "relative/data".to_owned(),
            "--import-mfa-key-file".to_owned(),
            "/run/current-mfa".to_owned(),
        ]);
        assert!(parse_install_args(relative).is_err());
        Ok(())
    }

    #[test]
    fn artifact_digest_pin_is_not_a_supported_install_or_update_input() {
        let digest = "a".repeat(64);

        let mut install = current_args();
        install.extend(["--artifact-sha256".to_owned(), digest.clone()]);
        assert!(parse_install_args(install).is_err());

        assert!(parse_update_args(vec!["--artifact-sha256".to_owned(), digest,]).is_err());
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn backup_copy_rejects_a_positional_selector() {
        let error = parse_backup(
            ["copy", "unexpected", "--to-host", "other"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .expect_err("a positional selector must not be ignored");
        assert!(error.to_string().contains("does not accept a positional"));
    }

    #[test]
    fn recover_binds_an_exact_target_release() -> anyhow::Result<()> {
        let parsed = parse_recover(vec![
            "production".to_owned(),
            "--to".to_owned(),
            "v0.2.9-candidate.ae1d409".to_owned(),
        ])?;
        assert_eq!(parsed.selector.positional.as_deref(), Some("production"));
        assert_eq!(parsed.version.as_deref(), Some("v0.2.9-candidate.ae1d409"));
        Ok(())
    }
}
