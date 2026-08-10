use super::*;

pub(super) fn configure_managed_database_roles(config: &UpdateConfig) -> anyhow::Result<()> {
    let password_path = config
        .dependencies
        .database_url_file
        .parent()
        .context("managed PostgreSQL secret directory is unavailable")?
        .join("dependencies")
        .join("postgres-runtime-password");
    let password_bytes = crate::filesystem::read_secure_secret_file(
        &password_path,
        "managed PostgreSQL runtime password",
        4096,
    )?;
    let password = std::str::from_utf8(&password_bytes)
        .context("managed PostgreSQL runtime password is not UTF-8")?;
    if password.is_empty()
        || !password
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("managed PostgreSQL runtime password is invalid");
    }
    let sql = zeroize::Zeroizing::new(format!(
        "DO $$ BEGIN\n\
         IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nazoauth_runtime') THEN\n\
           CREATE ROLE nazoauth_runtime LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         ELSE\n\
           ALTER ROLE nazoauth_runtime PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         END IF;\n\
         END $$;\n\
         REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
        REVOKE TEMPORARY ON DATABASE oauth FROM PUBLIC;\n"
    ).into_bytes());
    crate::runtime::Runtime::new(config).execute_managed_postgres(&sql)
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

pub(super) const MANAGED_RUNTIME_DATABASE_GRANT_SQL: &[u8] = br#"
GRANT CONNECT ON DATABASE oauth TO nazoauth_runtime;
GRANT USAGE ON SCHEMA public TO nazoauth_runtime;

-- The runtime role is intentionally driven by an explicit migration-owned
-- allowlist. A new public table must be added here before an install can
-- grant privileges; silently falling back to ALL TABLES would turn a schema
-- migration into an authorization escalation.
DO $$
DECLARE
    full_dml_tables CONSTANT text[] := ARRAY[
        'users', 'oauth_clients', 'oauth_tokens', 'user_client_grants',
        'access_token_revocations', 'client_access_requests',
        'user_passkey_credentials', 'user_totp_credentials',
        'user_mfa_backup_codes', 'user_mfa_remembered_devices',
        'tenants', 'realms', 'organizations', 'external_identity_links',
        'scim_tokens',
        'backchannel_logout_deliveries', 'runtime_module_desired_states',
        'runtime_module_instance_states',
        'openid4vci_credential_configurations', 'openid4vci_offers',
        'openid4vci_access_grants', 'openid4vci_nonces',
        'openid4vci_deferred_transactions', 'openid4vci_notifications',
        'openid4vp_transactions', 'openid4vci_credential_datasets',
        'openid4vci_pre_authorized_code_consumptions',
        'oauth_client_mtls_trust_anchor_requests',
        'runtime_module_default_policy', 'initial_admin_bootstrap',
        'conformance_leases', 'openid4vci_issuance_responses',
        'oauth_token_issuances', 'conformance_lease_applicants'
    ];
    append_tables CONSTANT text[] := ARRAY[
        'scim_audit_events', 'scim_security_events',
        'scim_security_event_receipts', 'identity_security_events',
        'runtime_module_state_events',
        'openid4vci_credential_dataset_events',
        'oauth_client_mtls_trust_anchor_events'
    ];
    cleanup_tables CONSTANT text[] := ARRAY[
        'scim_audit_events', 'scim_security_events',
        'oauth_client_mtls_trust_anchor_events',
        'oauth_client_mtls_trust_anchor_requests',
        'backchannel_logout_deliveries', 'oauth_token_issuances',
        'oauth_tokens', 'user_client_grants', 'access_token_revocations',
        'client_access_requests', 'oauth_clients',
        'openid4vci_credential_dataset_events',
        'openid4vci_credential_datasets', 'identity_security_events',
        'users'
    ];
    denied_tables CONSTANT text[] := ARRAY[
        'security_audit_chain_state', 'security_audit_events',
        'security_audit_event_outbox'
    ];
    known_tables text[];
    unknown_tables text[];
    missing_tables text[];
    table_name text;
    sequence_record record;
BEGIN
    known_tables := full_dml_tables || append_tables || denied_tables
        || ARRAY['__diesel_schema_migrations'];

    SELECT array_agg(candidate.relname ORDER BY candidate.relname)
    INTO unknown_tables
    FROM pg_class AS candidate
    JOIN pg_namespace AS namespace ON namespace.oid = candidate.relnamespace
    WHERE namespace.nspname = 'public'
      AND candidate.relkind IN ('r', 'p')
      AND NOT (candidate.relname = ANY(known_tables));
    IF unknown_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'runtime table privilege allowlist is incomplete: %',
            array_to_string(unknown_tables, ', ');
    END IF;

    SELECT array_agg(expected.name ORDER BY expected.name)
    INTO missing_tables
    FROM unnest(full_dml_tables || append_tables || denied_tables) AS expected(name)
    WHERE to_regclass(format('public.%I', expected.name)) IS NULL;
    IF missing_tables IS NOT NULL THEN
        RAISE EXCEPTION
            'runtime table privilege allowlist names missing tables: %',
            array_to_string(missing_tables, ', ');
    END IF;

    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nazoauth_runtime;
    FOREACH table_name IN ARRAY full_dml_tables LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO nazoauth_runtime',
            table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY append_tables LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT ON TABLE public.%I TO nazoauth_runtime',
            table_name
        );
    END LOOP;
    FOREACH table_name IN ARRAY cleanup_tables LOOP
        EXECUTE format(
            'GRANT DELETE ON TABLE public.%I TO nazoauth_runtime',
            table_name
        );
    END LOOP;

    -- The security audit ledger is written only by SECURITY DEFINER
    -- functions. Never grant direct table mutation.
    REVOKE ALL ON TABLE
        public.security_audit_chain_state,
        public.security_audit_events,
        public.security_audit_event_outbox
    FROM nazoauth_runtime;

    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM nazoauth_runtime;
    IF EXISTS (
        SELECT 1
        FROM pg_class AS sequence_rel
        JOIN pg_namespace AS namespace ON namespace.oid = sequence_rel.relnamespace
        WHERE namespace.nspname = 'public'
          AND sequence_rel.relkind = 'S'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend AS dependency
              JOIN pg_class AS owner_table ON owner_table.oid = dependency.refobjid
              JOIN pg_namespace AS owner_namespace
                ON owner_namespace.oid = owner_table.relnamespace
              WHERE dependency.classid = 'pg_class'::regclass
                AND dependency.objid = sequence_rel.oid
                AND dependency.refclassid = 'pg_class'::regclass
                AND dependency.deptype IN ('a', 'i')
                AND owner_namespace.nspname = 'public'
                AND owner_table.relname = ANY(full_dml_tables || append_tables || denied_tables)
          )
    ) THEN
        RAISE EXCEPTION 'runtime sequence privilege allowlist is incomplete';
    END IF;
    FOR sequence_record IN
        SELECT sequence_namespace.nspname AS sequence_schema,
               sequence_rel.relname AS sequence_name
        FROM pg_class AS sequence_rel
        JOIN pg_namespace AS sequence_namespace
          ON sequence_namespace.oid = sequence_rel.relnamespace
        JOIN pg_depend AS dependency
          ON dependency.classid = 'pg_class'::regclass
         AND dependency.objid = sequence_rel.oid
         AND dependency.refclassid = 'pg_class'::regclass
         AND dependency.deptype IN ('a', 'i')
        JOIN pg_class AS owner_table ON owner_table.oid = dependency.refobjid
        JOIN pg_namespace AS owner_namespace
          ON owner_namespace.oid = owner_table.relnamespace
        WHERE sequence_namespace.nspname = 'public'
          AND sequence_rel.relkind = 'S'
          AND owner_namespace.nspname = 'public'
          AND owner_table.relname = ANY(full_dml_tables || append_tables)
    LOOP
        EXECUTE format(
            'GRANT USAGE, SELECT, UPDATE ON SEQUENCE %I.%I TO nazoauth_runtime',
            sequence_record.sequence_schema,
            sequence_record.sequence_name
        );
    END LOOP;

    -- No blanket function EXECUTE. Trigger-only functions run as their
    -- table owner; these are the functions called directly by the runtime.
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM nazoauth_runtime;
    GRANT EXECUTE ON FUNCTION
        public.nazo_oauth_cleanup_expired_security_state(),
        public.nazo_oauth_conformance_lease_is_active(UUID, UUID),
        public.nazo_oauth_cleanup_expired_conformance_leases(),
        public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN),
        public.nazo_security_audit_chain_head_for_update(),
        public.nazo_append_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA),
        public.nazo_security_audit_anchor_freshness()
    TO nazoauth_runtime;
END
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public
    REVOKE ALL ON TABLES FROM nazoauth_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM nazoauth_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public
    REVOKE ALL ON FUNCTIONS FROM nazoauth_runtime;
"#;

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

pub(crate) fn normalize_public_url_for_profile(
    value: &str,
    _profile: &str,
) -> anyhow::Result<String> {
    validate_public_url(value)?;
    let url = Url::parse(value).context("--public-url must be an absolute HTTP(S) origin")?;
    if url.scheme() == "http"
        && !url.host().is_some_and(|host| match host {
            url::Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
        })
    {
        bail!("--public-url must use HTTPS outside localhost or loopback HTTP");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

pub(crate) fn normalize_single_host_cidr(value: &str) -> anyhow::Result<String> {
    if value != value.trim() {
        bail!("trusted proxy CIDR must not contain surrounding whitespace");
    }
    let (address, prefix) = value
        .split_once('/')
        .context("trusted proxy CIDR must be a single-host CIDR")?;
    let address: std::net::IpAddr = address
        .parse()
        .context("trusted proxy CIDR must contain a valid IP address")?;
    let prefix: u8 = prefix
        .parse()
        .context("trusted proxy CIDR must contain a valid prefix length")?;
    let required = if address.is_ipv4() { 32 } else { 128 };
    if prefix != required {
        bail!("trusted proxy CIDR must be exactly one IPv4 /32 or IPv6 /128 host");
    }
    Ok(format!("{address}/{prefix}"))
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

    let raw_username = parsed.username();
    let raw_password = parsed
        .password()
        .with_context(|| format!("{name} URL must contain a username and password"))?;
    if raw_username.is_empty()
        || raw_password.is_empty()
        || raw_username.contains([':', '@'])
        || raw_password.contains([':', '@'])
    {
        bail!("{name} URL userinfo is missing or has ambiguous separators");
    }
    let username = decode_dependency_component(raw_username, &format!("{name} username"))?;
    let password = decode_dependency_component(raw_password, &format!("{name} password"))?;
    if username.chars().any(char::is_whitespace) || password.chars().any(char::is_control) {
        bail!("{name} URL userinfo contains unsafe characters");
    }
    let host = parsed
        .host_str()
        .context("dependency URL host is unavailable")?;
    if host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("{name} URL host contains unsafe characters");
    }

    if parsed.fragment().is_some() {
        bail!("{name} URL must not contain a fragment");
    }
    let raw_database = parsed
        .path()
        .strip_prefix('/')
        .filter(|path| !path.is_empty())
        .with_context(|| format!("{name} URL must contain one database path component"))?;
    let database = decode_dependency_component(raw_database, &format!("{name} database"))?;
    if database.is_empty() || database.contains('/') || database.contains('\\') {
        bail!("{name} URL database path must contain exactly one component");
    }
    if parsed.scheme() == "postgres" || parsed.scheme() == "postgresql" {
        let mut query_keys = std::collections::BTreeSet::new();
        if let Some(query) = parsed.query() {
            if query.is_empty() {
                bail!("{name} URL query is empty");
            }
            for (key, value) in parsed.query_pairs() {
                if key.is_empty()
                    || !key
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                    || key.eq_ignore_ascii_case("password")
                    || !query_keys.insert(key.to_string())
                {
                    bail!("{name} URL query contains an unsafe or duplicate option");
                }
                let _ = decode_dependency_component(&value, &format!("{name} query value"))?;
            }
        }
        if database.len() > 63
            || !database
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
            || !database.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
            })
        {
            bail!("{name} URL database path is not one valid PostgreSQL name");
        }
    } else if (parsed.scheme() == "redis" || parsed.scheme() == "rediss")
        && (parsed.query().is_some()
            || !database.bytes().all(|byte| byte.is_ascii_digit())
            || (database.len() > 1 && database.starts_with('0'))
            || database.parse::<u32>().is_err())
    {
        bail!("{name} URL database path must be an unambiguous numeric index");
    }
    Ok(())
}

fn decode_dependency_component(value: &str, label: &str) -> anyhow::Result<String> {
    let decoded = urlencoding::decode(value)
        .with_context(|| format!("{label} has invalid percent encoding"))?
        .into_owned();
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        bail!("{label} contains unsafe control characters");
    }
    Ok(decoded)
}

pub(super) fn create_directory(path: &Path, mode: u32) -> anyhow::Result<()> {
    crate::filesystem::ensure_directory_chain(path)
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
