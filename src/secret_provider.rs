use std::path::Path;

use anyhow::{Context, bail};
use url::Url;

use crate::filesystem::{PrivateTempDir, atomic_write, read_secure_secret_file};

const MAX_SECRET_PROVIDER_BYTES: u64 = 16 * 1024;

pub(crate) struct PostgresProvider {
    work: PrivateTempDir,
}

impl PostgresProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = Url::parse(raw.as_str()).context("PostgreSQL secret provider URL is invalid")?;
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            bail!("PostgreSQL secret provider has an unsupported scheme");
        }
        let host = url.host_str().context("PostgreSQL URL has no host")?;
        reject_credential_controls(host, "PostgreSQL host")?;
        let user = decode(url.username(), "PostgreSQL user")?;
        let password = decode(
            url.password().context("PostgreSQL URL has no password")?,
            "PostgreSQL password",
        )?;
        let database = decode(url.path().trim_start_matches('/'), "PostgreSQL database")?;
        if user.is_empty() || password.is_empty() || database.is_empty() || database.contains('/') {
            bail!("PostgreSQL URL must contain one database, user, and password");
        }
        let port = url.port().unwrap_or(5432).to_string();
        let work = PrivateTempDir::new("nazoauth-pg-provider")?;
        let mut service = format!(
            "[nazoauth]\nhost={}\nport={}\ndbname={}\nuser={}\n",
            service_value(host, "PostgreSQL host")?,
            service_value(&port, "PostgreSQL port")?,
            service_value(database.as_str(), "PostgreSQL database")?,
            service_value(user.as_str(), "PostgreSQL user")?
        );
        for (key, value) in url.query_pairs() {
            if key == "password"
                || key.is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                bail!("PostgreSQL URL contains an unsafe service option");
            }
            service.push_str(&format!(
                "{}={}\n",
                key,
                service_value(&value, "PostgreSQL service option")?
            ));
        }
        let service_path = work.path().join("pg_service.conf");
        let pass_path = work.path().join("pgpass");
        // Percent decoding happens before values reach pg_service.conf/pgpass.
        // Reject encoded CR/LF as well as raw control bytes so a credential
        // cannot become a second line or an injected service option.
        reject_credential_controls(password.as_str(), "PostgreSQL password")?;
        atomic_write(&service_path, service.as_bytes(), 0o400)?;
        let pass = zeroize::Zeroizing::new(format!(
            "{}:{}:{}:{}:{}\n",
            pgpass_escape(host),
            pgpass_escape(&port),
            pgpass_escape(database.as_str()),
            pgpass_escape(user.as_str()),
            pgpass_escape(password.as_str())
        ));
        atomic_write(&pass_path, pass.as_bytes(), 0o400)?;
        Ok(Self { work })
    }

    pub(crate) fn service_file(&self) -> std::path::PathBuf {
        self.work.path().join("pg_service.conf")
    }

    pub(crate) fn password_file(&self) -> std::path::PathBuf {
        self.work.path().join("pgpass")
    }
}

pub(crate) struct ValkeyProvider {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) database: u32,
    pub(crate) tls: bool,
    password: zeroize::Zeroizing<String>,
}

impl ValkeyProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = Url::parse(raw.as_str()).context("Valkey secret provider URL is invalid")?;
        if !matches!(url.scheme(), "redis" | "rediss") || url.query().is_some() {
            bail!("Valkey secret provider has an unsupported URL");
        }
        let username = (!url.username().is_empty())
            .then(|| decode(url.username(), "Valkey user"))
            .transpose()?
            .map(|value| value.to_string());
        let password = decode(
            url.password().context("Valkey URL has no password")?,
            "Valkey password",
        )?;
        let database = url
            .path()
            .trim_start_matches('/')
            .parse::<u32>()
            .context("Valkey database is invalid")?;
        let host = url.host_str().context("Valkey URL has no host")?;
        reject_credential_controls(host, "Valkey host")?;
        Ok(Self {
            host: host.to_owned(),
            port: url.port().unwrap_or(6379),
            username,
            database,
            tls: url.scheme() == "rediss",
            password,
        })
    }

    pub(crate) fn password_stdin(&self) -> Vec<u8> {
        format!("{}\n", self.password.as_str()).into_bytes()
    }
}

fn read_single_line(path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let bytes = read_secure_secret_file(path, "secret provider", MAX_SECRET_PROVIDER_BYTES)?;
    let value = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("secret provider is not valid UTF-8: {}", path.display()))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("secret provider input must be one non-empty line");
    }
    Ok(zeroize::Zeroizing::new(value))
}

fn decode(value: &str, label: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let decoded = urlencoding::decode(value)
        .with_context(|| format!("{label} has invalid percent encoding"))?
        .into_owned();
    reject_credential_controls(&decoded, label)?;
    Ok(zeroize::Zeroizing::new(decoded))
}

fn reject_credential_controls(value: &str, label: &str) -> anyhow::Result<()> {
    if value.contains(['\0', '\r', '\n']) {
        bail!("{label} cannot be represented safely (NUL, CR, or LF)");
    }
    Ok(())
}

fn service_value<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    if value.contains(['\0', '\r', '\n'])
        || value.chars().next_back().is_some_and(char::is_whitespace)
    {
        bail!("{label} cannot be represented safely in a PostgreSQL service file");
    }
    Ok(value)
}

fn pgpass_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace(':', "\\:")
}

#[cfg(test)]
#[path = "../tests/unit/secret_provider.rs"]
mod tests;
