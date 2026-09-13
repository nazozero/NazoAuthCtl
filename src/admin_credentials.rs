//! Administrator credentials shared by target-local provisioning and HTTPS
//! administrator authentication.
//!
//! Passwords are accepted only from a hidden terminal prompt, bounded stdin,
//! or an owner-only file. They never enter argv, environment variables, logs,
//! or persistent ctl state.

use std::io::{IsTerminal as _, Read as _};
use std::path::Path;

use anyhow::{Context as _, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error_codes::INPUT_INVALID;

const MAX_CREDENTIALS_BYTES: u64 = 8 * 1024;

pub(crate) struct AdminCredentials {
    pub(crate) email: String,
    pub(crate) password: Zeroizing<String>,
}

pub(crate) enum AdminCredentialsInput<'a> {
    Interactive,
    Stdin,
    File(&'a Path),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdminCredentials {
    email: String,
    password: String,
}

pub(crate) fn read_admin_credentials(
    input: AdminCredentialsInput<'_>,
    command: &str,
) -> anyhow::Result<AdminCredentials> {
    let credentials = match input {
        AdminCredentialsInput::Interactive => read_interactive(command)?,
        AdminCredentialsInput::Stdin => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_CREDENTIALS_BYTES + 1)
                .read_to_end(&mut bytes)
                .context("failed to read administrator credentials from stdin")?;
            if bytes.len() as u64 > MAX_CREDENTIALS_BYTES {
                bail!("{INPUT_INVALID}: administrator credentials input is too large");
            }
            parse_credentials(&bytes, "stdin credentials")?
        }
        AdminCredentialsInput::File(path) => {
            let bytes = crate::filesystem::read_secure_regular_file(
                path,
                "administrator credentials file",
                true,
                MAX_CREDENTIALS_BYTES,
            )?;
            parse_credentials(&bytes, &path.display().to_string())?
        }
    };
    validate_admin_credentials(&credentials)?;
    Ok(credentials)
}

fn parse_credentials(bytes: &[u8], source: &str) -> anyhow::Result<AdminCredentials> {
    let raw: RawAdminCredentials = serde_json::from_slice(bytes)
        .with_context(|| format!("{source} must be strict JSON with email and password"))?;
    Ok(AdminCredentials {
        email: raw.email,
        password: Zeroizing::new(raw.password),
    })
}

fn read_interactive(command: &str) -> anyhow::Result<AdminCredentials> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        crate::ui::fail!(
            "{command} needs an interactive terminal or an explicit credentials input; passwords are never accepted on argv",
            "{command} 需要交互终端，或通过凭据文件／标准输入提供凭据；不接受命令行密码"
        );
    }
    let email: String = cliclack::input(crate::ui::text("Administrator email", "管理员邮箱"))
        .required(false)
        .validate(|value: &String| validate_admin_email(value).map_err(|error| error.to_string()))
        .interact()
        .context(crate::ui::text(
            "failed to read administrator email",
            "无法读取管理员邮箱",
        ))?;
    let password = cliclack::password(crate::ui::text("Administrator password", "管理员密码"))
        .allow_empty()
        .validate(|value: &String| {
            validate_admin_password(value).map_err(|error| error.to_string())
        })
        .interact()
        .context(crate::ui::text(
            "failed to read administrator password",
            "无法读取管理员密码",
        ))?;
    Ok(AdminCredentials {
        email: email.trim().to_owned(),
        password: Zeroizing::new(password),
    })
}

pub(crate) fn validate_admin_credentials(credentials: &AdminCredentials) -> anyhow::Result<()> {
    validate_admin_email(&credentials.email)?;
    validate_admin_password(&credentials.password)
}

fn validate_admin_email(email: &str) -> anyhow::Result<()> {
    let email = email.trim();
    if !(5..=254).contains(&email.len())
        || !email.contains('@')
        || email.contains(['\n', '\r', '\0', ' '])
    {
        crate::ui::fail!(
            "{INPUT_INVALID}: administrator email is invalid",
            "{INPUT_INVALID}：管理员邮箱格式不正确"
        );
    }
    Ok(())
}

fn validate_admin_password(password: &str) -> anyhow::Result<()> {
    if !(12..=1024).contains(&password.len()) {
        crate::ui::fail!(
            "{INPUT_INVALID}: administrator password must contain between 12 and 1024 UTF-8 bytes",
            "{INPUT_INVALID}：管理员密码的 UTF-8 长度须为 12 到 1024 字节"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_is_parsed_into_zeroizing_credentials() {
        let parsed = parse_credentials(
            br#"{"email":"admin@example.com","password":"long-enough-password"}"#,
            "test",
        )
        .expect("credentials");
        assert_eq!(parsed.email, "admin@example.com");
        assert_eq!(parsed.password.as_str(), "long-enough-password");
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        assert!(
            parse_credentials(
                br#"{"email":"admin@example.com","password":"long-enough-password","session":"no"}"#,
                "test",
            )
            .is_err()
        );
    }
}
