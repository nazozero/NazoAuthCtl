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

use anyhow::Context as _;

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
        crate::ui::fail!(
            "bind accepts at most one selector argument",
            "bind 最多接受一个实例选择参数"
        );
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
        None => crate::ui::fail!(
            "--label NAME is required so administrators can recognize this key",
            "必须提供 --label NAME，便于管理员识别此密钥"
        ),
    };
    let approval_token = match parsed.values.get("--approval-token") {
        Some(token) => {
            if token.trim().is_empty() || token.chars().any(char::is_control) || token.len() > 512 {
                crate::ui::fail!(
                    "--approval-token must be a single-line bounded token",
                    "--approval-token 必须是长度符合限制的单行令牌"
                );
            }
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
    let output_secret_file = match parsed.values.get("--output-secret-file") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Some(_) => crate::ui::fail!(
            "--output-secret-file requires a file path",
            "--output-secret-file 需要文件路径"
        ),
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
            "--direct-tls-config",
            "--tls-material-root",
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
        ],
        &[],
        "install",
    )?;
    if let Some(unexpected) = parsed.positionals.first() {
        crate::ui::fail!(
            "install does not accept the argument '{unexpected}'",
            "install 不接受参数“{unexpected}”"
        );
    }
    let public_url = parsed
        .values
        .get("--public-url")
        .context(crate::ui::text(
            "install requires --public-url URL (the public issuer origin)",
            "安装需要 --public-url URL（公开服务地址）",
        ))?
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
        .context(crate::ui::text(
            "--runtime must be podman, docker, or host",
            "--runtime 必须为 podman、docker 或 host",
        ))?;
    let install_root = parsed.values.get("--install-root").map(PathBuf::from);
    let database_host = parsed
        .values
        .get("--database-host")
        .context(crate::ui::text(
            "install requires --database-host HOST (external PostgreSQL endpoint)",
            "安装需要 --database-host HOST（已有 PostgreSQL 地址）",
        ))?
        .clone();
    let database_port = match parsed.values.get("--database-port") {
        Some(port) => port.parse::<u16>().context(crate::ui::text(
            "--database-port must be 1-65535",
            "--database-port 必须在 1 到 65535 之间",
        ))?,
        None => crate::ui::fail!(
            "install requires --database-port PORT",
            "安装需要 --database-port PORT"
        ),
    };
    let database_name = parsed
        .values
        .get("--database-name")
        .context(crate::ui::text(
            "install requires --database-name DATABASE",
            "安装需要 --database-name DATABASE",
        ))?
        .clone();
    let database_runtime_user = parsed
        .values
        .get("--database-runtime-user")
        .context(crate::ui::text(
            "install requires --database-runtime-user ROLE",
            "安装需要 --database-runtime-user ROLE",
        ))?
        .clone();
    let database_lifecycle_user = parsed
        .values
        .get("--database-lifecycle-user")
        .context(crate::ui::text(
            "install requires --database-lifecycle-user ROLE",
            "安装需要 --database-lifecycle-user ROLE",
        ))?
        .clone();
    if database_runtime_user == database_lifecycle_user {
        crate::ui::fail!(
            "runtime and lifecycle PostgreSQL roles must be distinct",
            "PostgreSQL 的运行角色与迁移角色必须不同"
        );
    }
    let valkey_host = parsed
        .values
        .get("--valkey-host")
        .context(crate::ui::text(
            "install requires --valkey-host HOST (external Valkey endpoint)",
            "安装需要 --valkey-host HOST（已有 Valkey 地址）",
        ))?
        .clone();
    let valkey_port = match parsed.values.get("--valkey-port") {
        Some(port) => port.parse::<u16>().context(crate::ui::text(
            "--valkey-port must be 1-65535",
            "--valkey-port 必须在 1 到 65535 之间",
        ))?,
        None => crate::ui::fail!(
            "install requires --valkey-port PORT",
            "安装需要 --valkey-port PORT"
        ),
    };
    let database_runtime_password_file = match parsed.values.get("--database-runtime-password-file")
    {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => crate::ui::fail!(
            "--database-runtime-password-file requires a file path",
            "--database-runtime-password-file 需要文件路径"
        ),
        None => crate::ui::fail!(
            "install requires --database-runtime-password-file PATH (the EXISTING PostgreSQL runtime role \
             password; ctl never invents credentials the external system does not know)",
            "安装需要 --database-runtime-password-file PATH，文件中应为已有 PostgreSQL 运行角色的密码"
        ),
    };
    let database_lifecycle_password_file = match parsed
        .values
        .get("--database-lifecycle-password-file")
    {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => crate::ui::fail!(
            "--database-lifecycle-password-file requires a file path",
            "--database-lifecycle-password-file 需要文件路径"
        ),
        None => crate::ui::fail!(
            "install requires --database-lifecycle-password-file PATH (the EXISTING PostgreSQL lifecycle role password)",
            "安装需要 --database-lifecycle-password-file PATH，文件中应为已有 PostgreSQL 迁移角色的密码"
        ),
    };
    let valkey_password_file = match parsed.values.get("--valkey-password-file") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        Some(_) => crate::ui::fail!(
            "--valkey-password-file requires a file path",
            "--valkey-password-file 需要文件路径"
        ),
        None => crate::ui::fail!(
            "install requires --valkey-password-file PATH (the EXISTING Valkey password; ctl \
             never invents credentials the external system does not know)",
            "安装需要 --valkey-password-file PATH，文件中应为已有 Valkey 的密码"
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
            crate::ui::fail!(
                "{flag} must be a bounded absolute target-side path without traversal",
                "{flag} 必须为目标主机上的绝对路径，不能包含路径跳转或超长内容"
            );
        }
        Ok(Some(PathBuf::from(value)))
    };
    let direct_tls_config = parsed.values.get("--direct-tls-config").map(PathBuf::from);
    let tls_material_root = target_path("--tls-material-root")?;
    if direct_tls_config.is_some() != tls_material_root.is_some() {
        crate::ui::fail!(
            "--direct-tls-config and --tls-material-root must be supplied together",
            "--direct-tls-config 和 --tls-material-root 必须一起提供"
        );
    }
    Ok(InstallArgs {
        host: parsed.values.get("--host").cloned(),
        name: parsed.values.get("--name").cloned(),
        public_url,
        version,
        runtime,
        install_root,
        direct_tls_config,
        tls_material_root,
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
        crate::ui::fail!(
            "update accepts at most one selector argument",
            "update 最多接受一个实例选择参数"
        );
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
        _ => crate::ui::fail!(
            "staging a configuration requires --config-file PATH together with \
             --config-schema TOKEN",
            "更新配置时，必须同时提供 --config-file PATH 和 --config-schema TOKEN"
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
                    crate::ui::fail!(
                        "backup copy does not accept a positional selector; use --instance",
                        "backup copy 请使用 --instance 选择实例，不接受位置参数"
                    );
                }
                let to_host = parts
                    .values
                    .get("--to-host")
                    .cloned()
                    .context(crate::ui::text(
                        "backup copy requires --to-host HOST",
                        "backup copy 需要 --to-host HOST",
                    ))?;
                return Ok(BackupArgs {
                    selector: InstanceSelector {
                        positional: None,
                        named: parts.named,
                    },
                    command: BackupCommand::Copy { to_host },
                });
            }
            _ => crate::ui::fail!(
                "backup requires show, snapshot, restore-test, or copy",
                "backup 需要 show、snapshot、restore-test 或 copy 子命令"
            ),
        },
    };
    let parts = selector_parts(rest, &[], &[], "backup")?;
    if parts.positional.is_some() {
        crate::ui::fail!(
            "backup does not accept a positional selector; use --instance",
            "backup 请使用 --instance 选择实例，不接受位置参数"
        );
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
        crate::ui::fail!(
            "policy requires backup-before-update",
            "policy 需要 backup-before-update 子命令"
        );
    };
    if subject != "backup-before-update" {
        crate::ui::fail!(
            "policy only supports backup-before-update",
            "policy 仅支持 backup-before-update"
        );
    }
    let Some((mode, rest)) = rest.split_first() else {
        crate::ui::fail!(
            "backup-before-update requires off, warn, or require",
            "备份策略必须为 off、warn 或 require"
        );
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
                crate::ui::fail!(
                    "off does not accept --max-age-seconds",
                    "off 策略不接受 --max-age-seconds"
                );
            }
            crate::registry::BackupBeforeUpdatePolicy::Off
        }
        "warn" => {
            if parts.values.contains_key("--max-age-seconds") {
                crate::ui::fail!(
                    "warn does not accept --max-age-seconds",
                    "warn 策略不接受 --max-age-seconds"
                );
            }
            crate::registry::BackupBeforeUpdatePolicy::Warn
        }
        "require" => {
            let value = parts
                .values
                .get("--max-age-seconds")
                .context(crate::ui::text(
                    "require needs --max-age-seconds",
                    "require 策略需要 --max-age-seconds",
                ))?;
            let max_age_seconds = value.parse::<u64>().context(crate::ui::text(
                "--max-age-seconds must be an integer",
                "--max-age-seconds 必须为整数",
            ))?;
            crate::registry::BackupBeforeUpdatePolicy::Require { max_age_seconds }
        }
        _ => crate::ui::fail!(
            "backup-before-update requires off, warn, or require",
            "备份策略必须为 off、warn 或 require"
        ),
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
        crate::ui::fail!(
            "unknown admin subcommand '{subcommand}'",
            "未知的 admin 子命令：{subcommand}"
        );
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
    fn direct_tls_install_requires_both_config_and_explicit_target_material_root()
    -> anyhow::Result<()> {
        let mut args = current_args();
        args.extend(["--direct-tls-config".to_owned(), "tls.yaml".to_owned()]);
        assert!(parse_install_args(args.clone()).is_err());
        args.extend(["--tls-material-root".to_owned(), "/etc/nazo-tls".to_owned()]);
        let parsed = parse_install_args(args)?;
        assert_eq!(parsed.direct_tls_config, Some("tls.yaml".into()));
        assert_eq!(parsed.tls_material_root, Some("/etc/nazo-tls".into()));
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
