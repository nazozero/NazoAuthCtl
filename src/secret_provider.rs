use std::{fmt::Write as _, path::Path};

use anyhow::{Context, bail};
use sha2::{Digest as _, Sha256};

use crate::filesystem::{PrivateTempDir, atomic_write, read_secure_secret_file};

const MAX_SECRET_PROVIDER_BYTES: u64 = 16 * 1024;

pub(crate) struct PostgresProvider {
    work: PrivateTempDir,
}

impl PostgresProvider {
    pub(crate) fn from_url_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_single_line(path)?;
        let url = parse_dependency_url(raw.as_str(), "PostgreSQL secret provider")?;
        if !matches!(url.scheme.as_str(), "postgres" | "postgresql") {
            bail!("PostgreSQL secret provider has an unsupported scheme");
        }
        let host = &url.host;
        let user = &url.username;
        let password = &url.password;
        let database = &url.database;
        let port = url.port.unwrap_or(5432).to_string();
        let work = PrivateTempDir::new("nazoauth-pg-provider")?;
        let mut service = format!(
            "[nazoauth]\nhost={}\nport={}\ndbname={}\nuser={}\n",
            service_value(host, "PostgreSQL host")?,
            service_value(&port, "PostgreSQL port")?,
            service_value(database.as_str(), "PostgreSQL database")?,
            service_value(user.as_str(), "PostgreSQL user")?
        );
        for (key, value) in &url.query {
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
                service_value(value, "PostgreSQL service option")?
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
        let url = parse_dependency_url(raw.as_str(), "Valkey secret provider")?;
        if !matches!(url.scheme.as_str(), "redis" | "rediss") || !url.query.is_empty() {
            bail!("Valkey secret provider has an unsupported URL");
        }
        let username = (!url.username.is_empty()).then(|| url.username);
        let password = url.password;
        let database = url
            .database
            .as_str()
            .parse::<u32>()
            .context("Valkey database is invalid")?;
        Ok(Self {
            host: url.host,
            port: url.port.unwrap_or(6379),
            username,
            database,
            tls: url.scheme == "rediss",
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
        database_endpoint_sha256: endpoint_sha256(&format!(
            "{};tls-policy={}",
            backup.endpoint, backup.tls_policy
        )),
        valkey_endpoint_sha256: endpoint_sha256(&format!(
            "{};tls-policy={}",
            valkey_backup.endpoint, valkey_backup.tls_policy
        )),
    })
}

/// Verify the two credentials consumed by backup without exposing runtime or
/// migration credentials to the backup process.
pub(crate) fn bind_external_backup_credentials(
    database_backup_url: &str,
    valkey_backup_url: &str,
) -> anyhow::Result<ExternalDependencyBackupBinding> {
    let database = postgres_binding(database_backup_url, "PostgreSQL backup")?;
    let valkey = valkey_binding(valkey_backup_url, "Valkey backup")?;
    Ok(ExternalDependencyBackupBinding {
        database_endpoint_sha256: endpoint_sha256(&format!(
            "{};tls-policy={}",
            database.endpoint, database.tls_policy
        )),
        valkey_endpoint_sha256: endpoint_sha256(&format!(
            "{};tls-policy={}",
            valkey.endpoint, valkey.tls_policy
        )),
    })
}

pub(crate) fn bind_external_backup_url_files(
    database_backup_url: &Path,
    valkey_backup_url: &Path,
) -> anyhow::Result<ExternalDependencyBackupBinding> {
    let database = read_single_line(database_backup_url)?;
    let valkey = read_single_line(valkey_backup_url)?;
    bind_external_backup_credentials(database.as_str(), valkey.as_str())
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
    tls_policy: String,
}

pub(crate) struct DependencyUrl {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
    pub(crate) username: zeroize::Zeroizing<String>,
    pub(crate) password: zeroize::Zeroizing<String>,
    pub(crate) database: zeroize::Zeroizing<String>,
    pub(crate) query: Vec<(String, zeroize::Zeroizing<String>)>,
}

/// Parses only the strict dependency URL grammar.  It never hands a complete
/// credential URL to a general URL type with ordinary Drop semantics.
pub(crate) fn parse_dependency_url(value: &str, label: &str) -> anyhow::Result<DependencyUrl> {
    let (scheme, remainder) = value
        .split_once("://")
        .with_context(|| format!("{label} URL is invalid"))?;
    if scheme.is_empty()
        || scheme
            .chars()
            .any(|character| !character.is_ascii_alphabetic())
    {
        bail!("{label} URL has an invalid scheme");
    }
    let (remainder, query) = match remainder.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (remainder, None),
    };
    if remainder.contains('#') || query.is_some_and(|query| query.contains('#')) {
        bail!("{label} URL must not contain a fragment");
    }
    let (authority, raw_database) = remainder
        .split_once('/')
        .with_context(|| format!("{label} URL must contain one database path component"))?;
    if raw_database.is_empty() || raw_database.contains('/') || authority.is_empty() {
        bail!("{label} URL must contain one database path component");
    }
    let (userinfo, host_port) = authority
        .rsplit_once('@')
        .with_context(|| format!("{label} URL must contain a username and password"))?;
    if userinfo.contains('@') || host_port.is_empty() {
        bail!("{label} URL userinfo is missing or has ambiguous separators");
    }
    let (raw_username, raw_password) = userinfo
        .split_once(':')
        .with_context(|| format!("{label} URL must contain a username and password"))?;
    if raw_username.is_empty()
        || raw_password.is_empty()
        || raw_username.contains([':', '@'])
        || raw_password.contains([':', '@'])
    {
        bail!("{label} URL userinfo is missing or has ambiguous separators");
    }
    let (host, port) = parse_host_port(host_port, label)?;
    let username = decode(raw_username, &format!("{label} username"))?;
    let password = decode(raw_password, &format!("{label} password"))?;
    let database = decode(raw_database, &format!("{label} database"))?;
    if database.contains(['/', '\\']) {
        bail!("{label} URL database path must contain exactly one component");
    }
    let mut parsed_query = Vec::new();
    if let Some(query) = query {
        if query.is_empty() {
            bail!("{label} URL query is empty");
        }
        for pair in query.split('&') {
            let (raw_key, raw_value) = pair
                .split_once('=')
                .with_context(|| format!("{label} URL query is invalid"))?;
            let key = decode(raw_key, &format!("{label} query key"))?;
            if key.is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                || key.eq_ignore_ascii_case("password")
            {
                bail!("{label} URL query contains an unsafe option");
            }
            parsed_query.push((
                key.as_str().to_owned(),
                decode(raw_value, &format!("{label} query value"))?,
            ));
        }
    }
    Ok(DependencyUrl {
        scheme: scheme.to_ascii_lowercase(),
        host,
        port,
        username,
        password,
        database,
        query: parsed_query,
    })
}

fn parse_host_port(value: &str, label: &str) -> anyhow::Result<(String, Option<u16>)> {
    let (host, raw_port) = if let Some(remainder) = value.strip_prefix('[') {
        let (host, after) = remainder
            .split_once(']')
            .with_context(|| format!("{label} URL host is invalid"))?;
        let port = after.strip_prefix(':').map(str::to_owned);
        if !after.is_empty() && port.is_none() {
            bail!("{label} URL host is invalid");
        }
        (format!("[{host}]"), port)
    } else {
        match value.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host.to_owned(), Some(port.to_owned())),
            Some(_) => bail!("{label} URL host is invalid"),
            None => (value.to_owned(), None),
        }
    };
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("{label} URL host contains unsafe characters");
    }
    let port = raw_port
        .map(|port| {
            if port.is_empty() {
                bail!("{label} URL port is invalid");
            }
            port.parse::<u16>()
                .with_context(|| format!("{label} URL port is invalid"))
        })
        .transpose()?;
    Ok((host, port))
}

fn postgres_binding(value: &str, label: &str) -> anyhow::Result<ProviderBinding> {
    let url = parse_dependency_url(value, label)?;
    if !matches!(url.scheme.as_str(), "postgres" | "postgresql") {
        bail!("{label} URL must use a PostgreSQL endpoint");
    }
    let mut tls_policy = None;
    for (key, value) in &url.query {
        // `sslmode` is transport policy, rather than endpoint or principal
        // identity.  Preserve the existing supported TLS form without making
        // equivalent TLS policy spellings change the durable endpoint hash.
        if key != "sslmode"
            || !matches!(
                value.as_ref(),
                "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
            )
            || tls_policy.replace(value.as_str().to_owned()).is_some()
        {
            bail!("{label} URL has an unsupported PostgreSQL query option");
        }
    }
    Ok(ProviderBinding {
        endpoint: format!(
            "postgresql://{}:{}/{}",
            url.host.to_ascii_lowercase(),
            url.port.unwrap_or(5432),
            url.database.as_str()
        ),
        username: url.username,
        tls_policy: tls_policy.unwrap_or_else(|| "default".to_owned()),
    })
}

fn valkey_binding(value: &str, label: &str) -> anyhow::Result<ProviderBinding> {
    let url = parse_dependency_url(value, label)?;
    if !matches!(url.scheme.as_str(), "redis" | "rediss") || !url.query.is_empty() {
        bail!("{label} URL must use a canonical Valkey endpoint without query options");
    }
    if url.database.parse::<u32>().is_err() {
        bail!("{label} URL has an invalid canonical Valkey endpoint");
    }
    let tls_policy = url.scheme.clone();
    Ok(ProviderBinding {
        endpoint: format!(
            "{}://{}:{}/{}",
            tls_policy.as_str(),
            url.host.to_ascii_lowercase(),
            url.port.unwrap_or(6379),
            url.database.as_str()
        ),
        username: url.username,
        tls_policy,
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
