use super::*;

pub(super) fn normalize_external_dependencies(options: &mut InstallOptions) -> anyhow::Result<()> {
    if !options.external_dependencies && (options.secrets_stdin || options.secret_fd.is_some()) {
        bail!("secure dependency secret input requires --external-dependencies");
    }
    if options.secrets_stdin && options.secret_fd.is_some() {
        bail!("choose exactly one of --secrets-stdin or --secret-fd");
    }
    if options.external_dependencies {
        if options.secrets_stdin {
            read_external_dependency_secrets(options, std::io::stdin().lock())?;
        } else if options.secret_fd.is_some() {
            #[cfg(unix)]
            {
                let fd = options.secret_fd.context("secret FD is unavailable")?;
                let file = fs::File::open(format!("/proc/self/fd/{fd}"))?;
                read_external_dependency_secrets(options, file)?;
            }
            #[cfg(not(unix))]
            bail!("--secret-fd requires Linux");
        } else {
            options.database_url = Some(rpassword::prompt_password("PostgreSQL runtime URL: ")?);
            options.migration_database_url =
                Some(rpassword::prompt_password("PostgreSQL migration URL: ")?);
            options.valkey_url = Some(rpassword::prompt_password("Valkey URL: ")?);
        }
    }
    if (options.database_url.is_some()
        || options.migration_database_url.is_some()
        || options.valkey_url.is_some())
        && (options.database_url.is_none()
            || options.migration_database_url.is_none()
            || options.valkey_url.is_none())
    {
        bail!(
            "external dependencies require runtime PostgreSQL, migration PostgreSQL, and Valkey URLs"
        );
    }
    if let Some(database) = &options.database_url {
        validate_dependency_url(database, &["postgres", "postgresql"], "PostgreSQL")?;
        validate_dependency_url(
            options
                .migration_database_url
                .as_deref()
                .unwrap_or_default(),
            &["postgres", "postgresql"],
            "PostgreSQL migration",
        )?;
        validate_dependency_url(
            options.valkey_url.as_deref().unwrap_or_default(),
            &["redis", "rediss"],
            "Valkey",
        )?;
    }
    Ok(())
}

pub(super) fn normalize_profile_secrets(options: &mut InstallOptions) -> anyhow::Result<()> {
    if options.profile != "standards-full"
        && (options.profile_secrets_stdin || options.profile_secret_fd.is_some())
    {
        bail!("secure profile secret input requires --profile standards-full");
    }
    if options.profile_secrets_stdin && options.profile_secret_fd.is_some() {
        bail!("choose exactly one of --profile-secrets-stdin or --profile-secret-fd");
    }
    if options.secrets_stdin && options.profile_secrets_stdin {
        bail!(
            "--secrets-stdin and --profile-secrets-stdin both consume stdin; use separate FDs instead"
        );
    }
    if options.secret_fd.is_some() && options.secret_fd == options.profile_secret_fd {
        bail!("--secret-fd and --profile-secret-fd must use different FDs");
    }
    if options.profile_secrets_stdin {
        read_profile_secrets(options, std::io::stdin().lock())?;
    } else if options.profile_secret_fd.is_some() {
        #[cfg(unix)]
        {
            let fd = options
                .profile_secret_fd
                .context("profile secret FD is unavailable")?;
            let file = fs::File::open(format!("/proc/self/fd/{fd}"))?;
            read_profile_secrets(options, file)?;
        }
        #[cfg(not(unix))]
        bail!("--profile-secret-fd requires Linux");
    }
    Ok(())
}

#[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ExternalDependencySecrets {
    database_url: String,
    migration_database_url: String,
    valkey_url: String,
}

pub(super) fn read_external_dependency_secrets(
    options: &mut InstallOptions,
    mut source: impl std::io::Read,
) -> anyhow::Result<()> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("dependency secret input exceeds 64 KiB");
    }
    let secrets: ExternalDependencySecrets =
        serde_json::from_slice(&bytes).context("dependency secret input must be strict JSON")?;
    // InstallOptions owns the working copies for the duration of the
    // transaction; the deserialization buffer and temporary input object are
    // independently wiped on drop.
    options.database_url = Some(secrets.database_url.clone());
    options.migration_database_url = Some(secrets.migration_database_url.clone());
    options.valkey_url = Some(secrets.valkey_url.clone());
    Ok(())
}

pub(super) fn read_profile_secrets(
    options: &mut InstallOptions,
    mut source: impl std::io::Read,
) -> anyhow::Result<()> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take(MAX_PROFILE_SECRET_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROFILE_SECRET_INPUT_BYTES {
        bail!("profile secret input exceeds 32 KiB");
    }
    let input: StandardsProfileSecrets =
        serde_json::from_slice(&bytes).context("profile secret input must be strict JSON")?;
    for (name, value) in [
        (
            "dynamic_registration_initial_access_token",
            &input.dynamic_registration_initial_access_token,
        ),
        (
            "ciba_automated_decision_token",
            &input.ciba_automated_decision_token,
        ),
        (
            "openid4vci_management_token",
            &input.openid4vci_management_token,
        ),
        (
            "openid4vp_management_token",
            &input.openid4vp_management_token,
        ),
    ] {
        validate_profile_secret_value(name, value)?;
    }
    options.profile_secrets = Some(input);
    Ok(())
}

pub(super) fn validate_profile_secret_value(name: &str, value: &str) -> anyhow::Result<()> {
    let length = value.len();
    if !(MIN_PROFILE_SECRET_VALUE_BYTES..=MAX_PROFILE_SECRET_VALUE_BYTES).contains(&length)
        || value.contains(['\n', '\r', '\0'])
    {
        bail!(
            "{name} must be between {MIN_PROFILE_SECRET_VALUE_BYTES} and {MAX_PROFILE_SECRET_VALUE_BYTES} bytes and contain no CR, LF, or NUL"
        );
    }
    Ok(())
}

pub(super) fn select_runtime(
    options: &InstallOptions,
) -> anyhow::Result<(RuntimeBackendKind, Option<RuntimeBackendKind>)> {
    let runtime = match options.runtime.as_str() {
        "auto" if runtime_backend::backend(RuntimeBackendKind::Podman).available() => {
            RuntimeBackendKind::Podman
        }
        "auto" if runtime_backend::backend(RuntimeBackendKind::Docker).available() => {
            RuntimeBackendKind::Docker
        }
        "auto" => bail!("auto runtime requires Podman or Docker"),
        "podman" => RuntimeBackendKind::Podman,
        "docker" => RuntimeBackendKind::Docker,
        "host" | "systemd" => RuntimeBackendKind::Systemd,
        value => bail!("unsupported runtime backend {value}"),
    };
    if runtime != RuntimeBackendKind::Systemd {
        if !runtime_backend::backend(runtime).available() {
            bail!("selected container runtime is unavailable");
        }
        return Ok((runtime, Some(runtime)));
    }
    if !runtime_backend::backend(RuntimeBackendKind::Systemd).available() {
        bail!("host runtime requires an available systemd 247 or newer backend");
    }
    if options.database_url.is_some() {
        return Ok((runtime, None));
    }
    bail!(
        "host runtime requires explicit external PostgreSQL and Valkey URLs; managed container dependencies are not network-reachable from the systemd service"
    )
}

pub(super) fn write_external_urls(
    secrets: &Path,
    options: &InstallOptions,
) -> anyhow::Result<String> {
    atomic_write(
        &secrets.join("database-migration-url"),
        options
            .migration_database_url
            .as_deref()
            .context("missing PostgreSQL migration URL")?
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("database-url"),
        options
            .database_url
            .as_deref()
            .context("missing PostgreSQL URL")?
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("valkey-url"),
        options
            .valkey_url
            .as_deref()
            .context("missing Valkey URL")?
            .as_bytes(),
        0o440,
    )?;
    Ok("external".to_owned())
}

pub(super) fn write_managed_secrets(
    secrets: &Path,
    postgres_container: &str,
    valkey_container: &str,
) -> anyhow::Result<String> {
    let dependencies = secrets.join("dependencies");
    create_directory(&dependencies, 0o700)?;
    let postgres = generate_secret(&dependencies.join("postgres-password"))?;
    let runtime_postgres = generate_secret(&dependencies.join("postgres-runtime-password"))?;
    let valkey = generate_secret(&dependencies.join("valkey-password"))?;
    // Dependency containers use fixed internal UIDs unrelated to host groups.
    // The dependency-only parent remains root-owned 0700, and these bind mounts
    // are read-only in their containers, so runtime users cannot traverse to them.
    set_mode(&dependencies.join("postgres-password"), 0o444)?;
    set_mode(&dependencies.join("valkey-password"), 0o444)?;
    atomic_write(
        &secrets.join("database-url"),
        format!(
            "postgresql://nazoauth_runtime:{}@{postgres_container}:5432/oauth",
            runtime_postgres.as_str()
        )
        .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("database-migration-url"),
        format!(
            "postgresql://nazoauth_migrator:{}@{postgres_container}:5432/oauth",
            postgres.as_str()
        )
        .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("valkey-url"),
        format!(
            "redis://nazoauth_runtime:{}@{valkey_container}:6379/0",
            valkey.as_str()
        )
        .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &dependencies.join("valkey.acl"),
        format!(
            concat!(
                "user default off\n",
                "user nazoauth_runtime on >{} ~* ",
                "+get +mget +getdel +set +setnx +del +exists ",
                "+expire +expireat +expiretime +pexpireat +pexpiretime +ttl ",
                "+incr +zadd +zrangebyscore +zrem +time +eval ",
                "+ping +hello +select +client|setname +client|setinfo\n"
            ),
            valkey.as_str()
        )
        .as_bytes(),
        0o444,
    )?;
    Ok("managed".to_owned())
}

pub(super) fn mfa_totp_key_path(config_dir: &Path) -> PathBuf {
    config_dir.join("secrets").join(MFA_TOTP_KEY_FILE_NAME)
}

pub(super) fn mfa_totp_config_path(runtime: RuntimeBackendKind, config_dir: &Path) -> String {
    if runtime == RuntimeBackendKind::Systemd {
        mfa_totp_key_path(config_dir).display().to_string()
    } else {
        MFA_TOTP_CONTAINER_KEY_PATH.to_owned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MfaTotpSourceState {
    ManagedCreated,
    ManagedExisting,
    External,
}

pub(crate) fn ensure_mfa_totp_configuration(
    config_dir: &Path,
    runtime: RuntimeBackendKind,
) -> anyhow::Result<()> {
    ensure_mfa_totp_configuration_state(config_dir, runtime).map(|_| ())
}

fn ensure_mfa_totp_configuration_state(
    config_dir: &Path,
    runtime: RuntimeBackendKind,
) -> anyhow::Result<MfaTotpSourceState> {
    let target = config_dir.join(".env.yaml");
    let Some(existing) = read_existing_server_config(&target)? else {
        ensure_mfa_totp_key(&mfa_totp_key_path(config_dir))?;
        return Ok(MfaTotpSourceState::ManagedCreated);
    };
    let inline_key = config_key_present(&existing, "MFA_TOTP_ENCRYPTION_KEY")?;
    let file_key = config_key_present(&existing, "MFA_TOTP_ENCRYPTION_KEY_FILE")?;
    let key_id = config_key_present(&existing, "MFA_TOTP_ENCRYPTION_KEY_ID")?;
    let mut additions = Vec::new();
    let mut managed_created = false;
    if !inline_key && !file_key {
        ensure_mfa_totp_key(&mfa_totp_key_path(config_dir))?;
        managed_created = true;
        additions.push(format!(
            "MFA_TOTP_ENCRYPTION_KEY_FILE: \"{}\"\n",
            mfa_totp_config_path(runtime, config_dir)
        ));
    }
    if !key_id {
        additions.push(format!(
            "MFA_TOTP_ENCRYPTION_KEY_ID: \"{MFA_TOTP_KEY_ID}\"\n"
        ));
    }
    if additions.is_empty() {
        return if managed_mfa_totp_source(config_dir, runtime)? {
            Ok(MfaTotpSourceState::ManagedExisting)
        } else {
            Ok(MfaTotpSourceState::External)
        };
    }
    let mut updated = existing;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    for addition in additions {
        updated.push_str(&addition);
    }
    atomic_write(&target, updated.as_bytes(), 0o640)?;
    if managed_mfa_totp_source(config_dir, runtime)? {
        Ok(if managed_created {
            MfaTotpSourceState::ManagedCreated
        } else {
            MfaTotpSourceState::ManagedExisting
        })
    } else {
        Ok(MfaTotpSourceState::External)
    }
}

pub(crate) fn ensure_mfa_totp_runtime(
    config_dir: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<bool> {
    let runtime = config.runtime.backend;
    let source = ensure_mfa_totp_configuration_state(config_dir, runtime)?;
    if source == MfaTotpSourceState::External {
        return Ok(false);
    }

    let key_path = mfa_totp_key_path(config_dir);
    if source == MfaTotpSourceState::ManagedExisting && !key_path.exists() {
        bail!(
            "managed MFA TOTP encryption key is missing; restore {} from backup",
            key_path.display()
        );
    }
    ensure_mfa_totp_key(&key_path)?;
    let mut changed = false;
    let secrets_dir = config_dir.join("secrets");
    if !config.runtime.snapshot_paths.contains(&secrets_dir) {
        config.runtime.snapshot_paths.push(secrets_dir);
        changed = true;
    }
    if runtime != RuntimeBackendKind::Systemd {
        let target = PathBuf::from(MFA_TOTP_CONTAINER_KEY_PATH);
        if let Some(existing) = config
            .runtime
            .mounts
            .iter_mut()
            .find(|mount| mount.target == target)
        {
            if existing.source != key_path {
                bail!(
                    "managed MFA TOTP mount conflicts with {}",
                    existing.source.display()
                );
            }
            if !existing.read_only {
                existing.read_only = true;
                changed = true;
            }
            if !existing.selinux_relabel {
                existing.selinux_relabel = true;
                changed = true;
            }
        } else {
            config.runtime.mounts.push(mount(
                key_path.clone(),
                MFA_TOTP_CONTAINER_KEY_PATH,
                true,
                true,
            ));
            changed = true;
        }
    }
    protect_mfa_totp_runtime_file(config, &key_path)?;
    Ok(changed)
}

pub(super) fn managed_mfa_totp_source(
    config_dir: &Path,
    runtime: RuntimeBackendKind,
) -> anyhow::Result<bool> {
    let Some(existing) = read_existing_server_config(&config_dir.join(".env.yaml"))? else {
        return Ok(false);
    };
    if config_key_value(&existing, "MFA_TOTP_ENCRYPTION_KEY")?.is_some() {
        return Ok(false);
    }
    let Some(configured) = config_key_value(&existing, "MFA_TOTP_ENCRYPTION_KEY_FILE")? else {
        return Ok(false);
    };
    if runtime != RuntimeBackendKind::Systemd {
        return Ok(configured == MFA_TOTP_CONTAINER_KEY_PATH);
    }
    let configured = Path::new(&configured);
    let configured = if configured.is_absolute() {
        configured.to_owned()
    } else {
        config_dir.join(configured)
    };
    Ok(configured == mfa_totp_key_path(config_dir))
}

pub(super) fn protect_mfa_totp_runtime_file(
    config: &UpdateConfig,
    key_path: &Path,
) -> anyhow::Result<()> {
    if cfg!(test) || test_mode() {
        return Ok(());
    }
    let parent = key_path
        .parent()
        .context("MFA TOTP key has no parent directory")?;
    let (owner, parent_mode) = if config.runtime.backend == RuntimeBackendKind::Systemd {
        let service_user = config.runtime.service_user.trim();
        if service_user.is_empty() {
            bail!("host runtime has no MFA TOTP service user");
        }
        (format!("root:{service_user}"), 0o750)
    } else {
        ("root:root".to_owned(), 0o700)
    };
    Process::new("chown").arg(&owner).arg(parent).run_quiet()?;
    set_mode(parent, parent_mode)?;
    let key_owner = if config.runtime.backend == RuntimeBackendKind::Systemd {
        owner
    } else {
        "root:10001".to_owned()
    };
    Process::new("chown")
        .arg(key_owner)
        .arg(key_path)
        .run_quiet()?;
    set_mode(key_path, 0o440)
}

pub(super) fn ensure_mfa_totp_key(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "MFA TOTP encryption key must be a regular file: {}",
                    path.display()
                );
            }
            let bytes = read_secure_secret_file(path, "MFA TOTP encryption key", 4 * 1024)?;
            let value = std::str::from_utf8(&bytes)
                .context("MFA TOTP encryption key is not valid UTF-8")?;
            validate_mfa_totp_key(value)?;
            set_mode(path, 0o440)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let value = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            atomic_write(path, value.as_bytes(), 0o440)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect MFA TOTP encryption key {}",
                path.display()
            )
        }),
    }
}

pub(super) fn validate_mfa_totp_key(value: &str) -> anyhow::Result<()> {
    let value = value.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("MFA TOTP encryption key is not valid base64url")?;
    if decoded.len() != 32 {
        bail!("MFA TOTP encryption key must decode to exactly 32 bytes");
    }
    Ok(())
}

pub(super) fn read_existing_server_config(
    target: &Path,
) -> anyhow::Result<Option<zeroize::Zeroizing<String>>> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!(
            "existing server configuration is invalid: {}",
            target.display()
        );
    }
    let bytes = read_secure_secret_file(target, "existing server configuration", 1024 * 1024)?;
    let value = String::from_utf8(bytes.to_vec()).with_context(|| {
        format!(
            "existing server configuration is not valid UTF-8: {}",
            target.display()
        )
    })?;
    Ok(Some(zeroize::Zeroizing::new(value)))
}

pub(super) fn config_key_present(content: &str, key: &str) -> anyhow::Result<bool> {
    Ok(config_key_value(content, key)?.is_some())
}

pub(super) fn config_key_value(content: &str, key: &str) -> anyhow::Result<Option<String>> {
    let mut value = None;
    for line in content.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, raw_value)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        if value.is_some() {
            bail!("server configuration contains duplicate {key}");
        }
        let parsed = raw_value.split('#').next().unwrap_or_default().trim();
        let parsed = parsed
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                parsed
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(parsed)
            .trim();
        if parsed.is_empty() {
            bail!("{key} must not be empty in existing server configuration");
        }
        value = Some(parsed.to_owned());
    }
    Ok(value)
}

pub(super) fn write_server_config(
    config_dir: &Path,
    options: &InstallOptions,
    deployment_id: &str,
    runtime: RuntimeBackendKind,
    data_root: &Path,
    trusted_proxy_cidr: Option<&str>,
    profile_config: Option<&str>,
) -> anyhow::Result<()> {
    let standards_full = options.profile == "standards-full";
    if standards_full != profile_config.is_some() {
        bail!("server profile selection does not match the validated install profile");
    }
    if standards_full {
        normalize_single_host_cidr(
            trusted_proxy_cidr.context("standards-full requires an explicit trusted proxy CIDR")?,
        )?;
    } else if trusted_proxy_cidr.is_some() {
        bail!("server profile and trusted proxy settings are inconsistent");
    }
    let target = config_dir.join(".env.yaml");
    if let Some(existing) = read_existing_server_config(&target)? {
        validate_existing_server_config(&existing, options, trusted_proxy_cidr)?;
        return Ok(());
    }
    ensure_mfa_totp_key(&mfa_totp_key_path(config_dir))?;
    let (bind, data_dir, ui_dir, dependency_files) = if runtime == RuntimeBackendKind::Systemd {
        (
            format!("127.0.0.1:{}", options.port),
            data_root.join("app").display().to_string(),
            data_root.join("ui-releases").display().to_string(),
            format!(
                "DATABASE_URL_FILE: \"{}\"\nVALKEY_URL_FILE: \"{}\"\n",
                config_dir.join("secrets/database-url").display(),
                config_dir.join("secrets/valkey-url").display()
            ),
        )
    } else {
        (
            "0.0.0.0:8000".to_owned(),
            "/var/lib/nazo_oauth".to_owned(),
            "/var/lib/nazo_oauth/ui-releases".to_owned(),
            String::new(),
        )
    };
    let profile_secret_root = if runtime == RuntimeBackendKind::Systemd {
        config_dir.join("secrets").display().to_string()
    } else {
        "/run/nazoauth-secrets".to_owned()
    };
    let profile_app_root = if runtime == RuntimeBackendKind::Systemd {
        data_root.join("app").display().to_string()
    } else {
        "/var/lib/nazo_oauth".to_owned()
    };
    let content = format!(
        "# Generated by nazoauthctl install. Explicit operator overrides are preserved.\n\
         BIND: \"{bind}\"\n\
         PUBLIC_BASE_URL: \"{public_url}\"\n\
         DEPLOYMENT_ID: \"{deployment_id}\"\n\
         MFA_TOTP_ENCRYPTION_KEY_FILE: \"{mfa_key_file}\"\n\
         MFA_TOTP_ENCRYPTION_KEY_ID: \"{mfa_key_id}\"\n\
         DATABASE_MAX_CONNECTIONS: 32\n\
         DATA_DIR: \"{data_dir}\"\n\
         UI_CACHE_DIR: \"{ui_dir}\"\n\
         RUST_LOG: \"info\"\n\
         {dependency_files}{profile}",
        public_url = options.public_url.trim_end_matches('/'),
        mfa_key_file = mfa_totp_config_path(runtime, config_dir),
        mfa_key_id = MFA_TOTP_KEY_ID,
        profile = profile_config
            .unwrap_or_default()
            .replace(
                "${TRUSTED_PROXY_CIDR}",
                trusted_proxy_cidr.unwrap_or_default(),
            )
            .replace("${PROFILE_SECRET_ROOT}", &profile_secret_root,)
            .replace("${PROFILE_APP_ROOT}", &profile_app_root),
    );
    atomic_write(&target, content.as_bytes(), 0o640)
}

pub(super) fn validate_existing_server_config(
    content: &str,
    options: &InstallOptions,
    trusted_proxy_cidr: Option<&str>,
) -> anyhow::Result<()> {
    let expected_public_url =
        normalize_public_url_for_profile(&options.public_url, &options.profile)?;
    let configured_public_url = config_key_value(content, "PUBLIC_BASE_URL")?
        .context("existing server configuration has no PUBLIC_BASE_URL")?;
    let normalized_public_url =
        normalize_public_url_for_profile(&configured_public_url, &options.profile)?;
    if configured_public_url != normalized_public_url
        || normalized_public_url != expected_public_url
    {
        bail!("existing PUBLIC_BASE_URL does not match the requested issuer origin");
    }

    if let Some(configured_issuer) = config_key_value(content, "ISSUER")? {
        let normalized_issuer =
            normalize_public_url_for_profile(&configured_issuer, &options.profile)?;
        if configured_issuer != normalized_issuer || normalized_issuer != expected_public_url {
            bail!("existing ISSUER does not match the requested issuer origin");
        }
    }

    if options.profile == "standards-full" {
        let configured_mtls_endpoint = config_key_value(content, "MTLS_ENDPOINT_BASE_URL")?
            .context(
                "standards-full existing server configuration has no MTLS_ENDPOINT_BASE_URL",
            )?;
        let normalized_mtls_endpoint =
            normalize_public_url_for_profile(&configured_mtls_endpoint, &options.profile)?;
        if configured_mtls_endpoint != normalized_mtls_endpoint
            || normalized_mtls_endpoint != expected_public_url
        {
            bail!("existing MTLS_ENDPOINT_BASE_URL does not match the requested issuer origin");
        }

        let configured_source = config_key_value(content, "MTLS_CERTIFICATE_SOURCE")?.context(
            "standards-full existing server configuration has no MTLS_CERTIFICATE_SOURCE",
        )?;
        if configured_source != "rfc9440" {
            bail!("standards-full requires MTLS_CERTIFICATE_SOURCE=rfc9440");
        }

        let configured_cidr = config_key_value(content, "TRUSTED_PROXY_CIDRS")?
            .context("standards-full existing server configuration has no TRUSTED_PROXY_CIDRS")?;
        let configured_cidr = normalize_single_host_cidr(&configured_cidr)?;
        let expected_cidr = trusted_proxy_cidr
            .context("standards-full requires an explicit trusted proxy CIDR")
            .and_then(normalize_single_host_cidr)?;
        if configured_cidr != expected_cidr {
            bail!("existing TRUSTED_PROXY_CIDRS does not match the requested proxy boundary");
        }

        for key in ["ENABLE_OPENID4VCI_ISSUER", "ENABLE_OPENID4VP_VERIFIER"] {
            if config_key_value(content, key)?.as_deref() != Some("true") {
                bail!("standards-full existing server configuration must enable {key}");
            }
        }
    } else {
        if trusted_proxy_cidr.is_some() {
            bail!("server profile and trusted proxy settings are inconsistent");
        }
        for key in [
            "MTLS_ENDPOINT_BASE_URL",
            "MTLS_CERTIFICATE_SOURCE",
            "TRUSTED_PROXY_CIDRS",
            "ENABLE_OPENID4VCI_ISSUER",
            "ENABLE_OPENID4VP_VERIFIER",
        ] {
            if config_key_value(content, key)?.is_some() {
                bail!("baseline existing server configuration contains standards-full key {key}");
            }
        }
    }
    Ok(())
}
