use std::{fmt::Write as _, ops::Deref, path::Path};

use anyhow::{Context, bail};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::filesystem::{PrivateTempDir, atomic_write, read_secure_secret_file};

const MAX_SECRET_PROVIDER_BYTES: u64 = 16 * 1024;

pub(crate) struct PostgresProvider {
    work: PrivateTempDir,
}

impl PostgresProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        // The source is Zeroizing and the URL wrapper scrubs its credential
        // components before the parser allocation is released.
        let url = SensitiveUrl(
            Url::parse(raw.as_str()).context("PostgreSQL secret provider URL is invalid")?,
        );
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
        let mut pass = zeroize::Zeroizing::new(String::new());
        write!(
            &mut *pass,
            "{}:{}:{}:{}:{}\n",
            pgpass_escape(host).as_str(),
            pgpass_escape(&port).as_str(),
            pgpass_escape(database.as_str()).as_str(),
            pgpass_escape(user.as_str()).as_str(),
            pgpass_escape(password.as_str()).as_str()
        )?;
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
    pub(crate) username: Option<zeroize::Zeroizing<String>>,
    pub(crate) database: u32,
    pub(crate) tls: bool,
    password: zeroize::Zeroizing<String>,
}

impl ValkeyProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = SensitiveUrl(
            Url::parse(raw.as_str()).context("Valkey secret provider URL is invalid")?,
        );
        if !matches!(url.scheme(), "redis" | "rediss") || url.query().is_some() {
            bail!("Valkey secret provider has an unsupported URL");
        }
        let username = (!url.username().is_empty())
            .then(|| decode(url.username(), "Valkey user"))
            .transpose()?
            .map(|value| value);
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

    pub(crate) fn password_stdin(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(format!("{}\n", self.password.as_str()).into_bytes())
    }
}

pub(crate) struct ExternalDependencyBackupBinding {
    pub(crate) database_endpoint_sha256: String,
    pub(crate) valkey_endpoint_sha256: String,
}

pub(crate) fn bind_external_dependency_credentials(
    database_url: &str,
    migration_database_url: &str,
    database_backup_url: &str,
    valkey_url: &str,
    valkey_backup_url: &str,
) -> anyhow::Result<ExternalDependencyBackupBinding> {
    let database = postgres_binding(database_url, "PostgreSQL runtime")?;
    let migration = postgres_binding(migration_database_url, "PostgreSQL migration")?;
    let backup = postgres_binding(database_backup_url, "PostgreSQL backup")?;
    if database.endpoint != migration.endpoint || database.endpoint != backup.endpoint {
        bail!(
            "external PostgreSQL runtime, migration, and backup URLs must target one canonical endpoint"
        );
    }
    if database.username == migration.username
        || database.username == backup.username
        || migration.username == backup.username
    {
        bail!("external PostgreSQL runtime, migration, and backup usernames must be distinct");
    }
    let valkey = valkey_binding(valkey_url, "Valkey runtime")?;
    let valkey_backup = valkey_binding(valkey_backup_url, "Valkey backup")?;
    if valkey.endpoint != valkey_backup.endpoint {
        bail!("external Valkey runtime and backup URLs must target one canonical endpoint");
    }
    if valkey.username == valkey_backup.username {
        bail!("external Valkey runtime and backup usernames must be distinct");
    }
    Ok(ExternalDependencyBackupBinding {
        database_endpoint_sha256: endpoint_sha256(&database.endpoint),
        valkey_endpoint_sha256: endpoint_sha256(&valkey.endpoint),
    })
}

pub(crate) fn bind_external_dependency_url_files(
    database_url: &Path,
    migration_database_url: &Path,
    database_backup_url: &Path,
    valkey_url: &Path,
    valkey_backup_url: &Path,
) -> anyhow::Result<ExternalDependencyBackupBinding> {
    let database = read_single_line(database_url)?;
    let migration = read_single_line(migration_database_url)?;
    let database_backup = read_single_line(database_backup_url)?;
    let valkey = read_single_line(valkey_url)?;
    let valkey_backup = read_single_line(valkey_backup_url)?;
    bind_external_dependency_credentials(
        database.as_str(),
        migration.as_str(),
        database_backup.as_str(),
        valkey.as_str(),
        valkey_backup.as_str(),
    )
}

struct ProviderBinding {
    endpoint: String,
    username: zeroize::Zeroizing<String>,
}

/// `url::Url` owns user-info while parsing. Keep it inside a wrapper that
/// removes credential-bearing components even on an error path before the URL
/// allocation is dropped.
struct SensitiveUrl(Url);

impl Deref for SensitiveUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveUrl {
    fn drop(&mut self) {
        let _ = self.0.set_password(None);
        let _ = self.0.set_username("");
        self.0.set_path("");
        self.0.set_query(None);
        self.0.set_fragment(None);
    }
}

fn postgres_binding(value: &str, label: &str) -> anyhow::Result<ProviderBinding> {
    let url = SensitiveUrl(Url::parse(value).with_context(|| format!("{label} URL is invalid"))?);
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        bail!("{label} URL must use a PostgreSQL endpoint");
    }
    for (key, value) in url.query_pairs() {
        // `sslmode` is transport policy, rather than endpoint or principal
        // identity.  Preserve the existing supported TLS form without making
        // equivalent TLS policy spellings change the durable endpoint hash.
        if key != "sslmode"
            || !matches!(
                value.as_ref(),
                "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
            )
        {
            bail!("{label} URL has an unsupported PostgreSQL query option");
        }
    }
    let host = url.host_str().context("PostgreSQL URL has no host")?;
    let username = decode(url.username(), "PostgreSQL user")?;
    let password = decode(
        url.password().context("PostgreSQL URL has no password")?,
        "PostgreSQL password",
    )?;
    let database = decode(url.path().trim_start_matches('/'), "PostgreSQL database")?;
    if username.is_empty()
        || password.is_empty()
        || database.is_empty()
        || database.contains('/')
        || host.contains(['\0', '\r', '\n'])
    {
        bail!("{label} URL has an invalid canonical PostgreSQL endpoint");
    }
    Ok(ProviderBinding {
        endpoint: format!(
            "postgresql://{}:{}/{}",
            host.to_ascii_lowercase(),
            url.port().unwrap_or(5432),
            database.as_str()
        ),
        username,
    })
}

fn valkey_binding(value: &str, label: &str) -> anyhow::Result<ProviderBinding> {
    let url = SensitiveUrl(Url::parse(value).with_context(|| format!("{label} URL is invalid"))?);
    if !matches!(url.scheme(), "redis" | "rediss") || url.query().is_some() {
        bail!("{label} URL must use a canonical Valkey endpoint without query options");
    }
    let host = url.host_str().context("Valkey URL has no host")?;
    let username = decode(url.username(), "Valkey user")?;
    let password = decode(
        url.password().context("Valkey URL has no password")?,
        "Valkey password",
    )?;
    let database = decode(url.path().trim_start_matches('/'), "Valkey database")?;
    if username.is_empty()
        || password.is_empty()
        || database.is_empty()
        || database.contains('/')
        || database.parse::<u32>().is_err()
        || host.contains(['\0', '\r', '\n'])
    {
        bail!("{label} URL has an invalid canonical Valkey endpoint");
    }
    Ok(ProviderBinding {
        endpoint: format!(
            "{}://{}:{}/{}",
            url.scheme(),
            host.to_ascii_lowercase(),
            url.port().unwrap_or(6379),
            database.as_str()
        ),
        username,
    })
}

fn endpoint_sha256(endpoint: &str) -> String {
    Sha256::digest(endpoint.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_single_line(path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let bytes = read_secure_secret_file(path, "secret provider", MAX_SECRET_PROVIDER_BYTES)?;
    let value = std::str::from_utf8(&bytes)
        .with_context(|| format!("secret provider is not valid UTF-8: {}", path.display()))?;
    let value = zeroize::Zeroizing::new(value.to_owned());
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("secret provider input must be one non-empty line");
    }
    Ok(value)
}

fn decode(value: &str, label: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let decoded = zeroize::Zeroizing::new(
        urlencoding::decode(value)
            .with_context(|| format!("{label} has invalid percent encoding"))?
            .into_owned(),
    );
    reject_credential_controls(&decoded, label)?;
    Ok(decoded)
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

fn pgpass_escape(value: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(value.replace('\\', "\\\\").replace(':', "\\:"))
}

#[cfg(test)]
#[path = "../tests/unit/secret_provider.rs"]
mod tests;
