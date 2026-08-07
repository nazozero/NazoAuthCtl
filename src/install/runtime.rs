use super::*;

pub(super) fn configure_managed_database_roles(config: &UpdateConfig) -> anyhow::Result<()> {
    let password_path = config
        .dependencies
        .database_url_file
        .parent()
        .context("managed PostgreSQL secret directory is unavailable")?
        .join("dependencies")
        .join("postgres-runtime-password");
    let password = fs::read_to_string(password_path)?;
    if password.is_empty()
        || !password
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("managed PostgreSQL runtime password is invalid");
    }
    let sql = format!(
        "DO $$ BEGIN\n\
         IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nazoauth_runtime') THEN\n\
           CREATE ROLE nazoauth_runtime LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         ELSE\n\
           ALTER ROLE nazoauth_runtime PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         END IF;\n\
         END $$;\n\
         REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
         REVOKE TEMPORARY ON DATABASE oauth FROM PUBLIC;\n"
    );
    crate::runtime::Runtime::new(config).execute_managed_postgres(sql.as_bytes())
}

pub(crate) fn grant_runtime_database(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.dependencies.mode != "managed" {
        return Ok(());
    }
    crate::runtime::Runtime::new(config)
        .execute_managed_postgres(MANAGED_RUNTIME_DATABASE_GRANT_SQL)
}

pub(super) const MANAGED_RUNTIME_DATABASE_GRANT_SQL: &[u8] = b"GRANT CONNECT ON DATABASE oauth TO nazoauth_runtime;\n\
    GRANT USAGE ON SCHEMA public TO nazoauth_runtime;\n\
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nazoauth_runtime;\n\
    REVOKE ALL ON TABLE\n\
        public.security_audit_chain_state,\n\
        public.security_audit_events,\n\
        public.security_audit_event_outbox\n\
    FROM nazoauth_runtime;\n\
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO nazoauth_runtime;\n\
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nazoauth_runtime;\n\
    REVOKE ALL ON FUNCTION\n\
        public.nazo_reject_security_audit_event_mutation(),\n\
        public.nazo_claim_security_audit_events(BIGINT, INTEGER),\n\
        public.nazo_ack_security_audit_event(UUID, INTEGER),\n\
        public.nazo_reschedule_security_audit_event(UUID, INTEGER, TIMESTAMPTZ, TEXT),\n\
        public.nazo_security_audit_anchor_health()\n\
    FROM nazoauth_runtime;\n\
    GRANT EXECUTE ON FUNCTION\n\
        public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN),\n\
        public.nazo_security_audit_chain_head_for_update(),\n\
        public.nazo_append_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA),\n\
        public.nazo_security_audit_anchor_freshness()\n\
    TO nazoauth_runtime;\n\
    ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public\n\
        REVOKE ALL ON TABLES FROM nazoauth_runtime;\n\
    ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public\n\
        REVOKE ALL ON SEQUENCES FROM nazoauth_runtime;\n\
    ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public\n\
        REVOKE ALL ON FUNCTIONS FROM nazoauth_runtime;\n";

pub(crate) fn verify_runtime_no_ddl(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.dependencies.mode != "managed" {
        eprintln!(
            "doctor: external PostgreSQL privileges are operator-owned and were not modified"
        );
        return Ok(());
    }
    let postgres = PostgresProvider::from_url_file(&config.dependencies.database_url_file)?;
    runtime_backend::backend(
        config
            .container_backend()
            .context("managed PostgreSQL requires a container backend")?,
    )
    .verify_runtime_database_privileges(&RuntimeDatabasePrivilegeProbe {
        network: config.runtime.network.clone(),
        service_file: postgres.service_file().to_owned(),
        password_file: postgres.password_file().to_owned(),
        image: config.postgres.validation_image.clone(),
    })
}

pub(super) fn validate_public_url(value: &str) -> anyhow::Result<()> {
    let url = Url::parse(value).context("--public-url must be an absolute HTTP(S) origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "" && url.path() != "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("--public-url must be an absolute HTTP(S) origin");
    }
    Ok(())
}

pub(super) fn validate_install_path(path: &Path, label: &str) -> anyhow::Result<()> {
    let value = path
        .to_str()
        .with_context(|| format!("{label} must be valid UTF-8"))?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        bail!("{label} contains characters that cannot be represented safely in runtime config");
    }
    Ok(())
}

pub(super) fn validate_dependency_url(
    value: &str,
    schemes: &[&str],
    name: &str,
) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("{name} URL is invalid"))?;
    if !schemes.contains(&parsed.scheme()) || parsed.host_str().is_none() {
        bail!("{name} URL has an unsupported scheme or no host");
    }
    Ok(())
}

pub(super) fn create_directory(path: &Path, mode: u32) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!(
            "managed directory must not be a symlink: {}",
            path.display()
        );
    }
    set_mode(path, mode)
}

pub(super) fn require_supported_install_platform() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if !install_platform_supported(std::env::consts::OS, std::env::consts::ARCH) {
        bail!("install lifecycle supports only Linux x86_64 and aarch64");
    }
    Ok(())
}

pub(super) fn install_platform_supported(os: &str, arch: &str) -> bool {
    matches!((os, arch), ("linux", "x86_64" | "aarch64"))
}

pub(super) fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        bail!("install and update require root on a Unix host");
    }
    #[cfg(unix)]
    {
        if Process::new("id").arg("-u").stdout()?.trim() != "0" {
            bail!("install and update require root");
        }
        Ok(())
    }
}

pub(super) fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}
