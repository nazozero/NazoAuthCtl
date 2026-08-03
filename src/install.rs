use std::{
    collections::BTreeMap,
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use url::Url;

use crate::{
    cli::{InstallOptions, StandardsProfileSecrets},
    deployment::RuntimeBackendKind,
    filesystem::{atomic_write, generate_secret, set_mode},
    model::{
        Dependencies, Mount, Operator, Postgres, Runtime, Ui, UpdateConfig, Valkey, safe_absolute,
    },
    operator,
    process::Process,
    runtime_backend::{
        self, HostServiceInstall, ManagedDependencies, ManagedNetwork,
        RuntimeDatabasePrivilegeProbe,
    },
    secret_provider::PostgresProvider,
};

pub(crate) const POSTGRES_IMAGE: &str = "docker.io/library/postgres:18@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a";
pub(crate) const VALKEY_IMAGE: &str = "docker.io/valkey/valkey:8-alpine@sha256:a038175878d66b9d274fbf8be73c0305e93798b83917647f167e18cef3c71eec";
const STANDARDS_PROFILE_SECRET_NAMES: &[&str] = &[
    "dynamic-registration-token",
    "ciba-decision-token",
    "openid4vc-data-encryption-key",
    "openid4vci-management-token",
    "openid4vp-management-token",
];
const MAX_PROFILE_SECRET_INPUT_BYTES: u64 = 32 * 1024;
const MIN_PROFILE_SECRET_VALUE_BYTES: usize = 32;
const MAX_PROFILE_SECRET_VALUE_BYTES: usize = 4096;

pub(crate) struct PreparedInstall {
    pub(crate) config: UpdateConfig,
    pub(crate) config_path: PathBuf,
}

pub(crate) fn prepare(
    config_path: &Path,
    mut options: InstallOptions,
) -> anyhow::Result<PreparedInstall> {
    require_supported_install_platform()?;
    require_root()?;
    safe_absolute(config_path)?;
    safe_absolute(&options.data_root)?;
    safe_absolute(&options.control_root)?;
    safe_absolute(&options.recovery_root)?;
    validate_install_path(config_path, "configuration path")?;
    validate_install_path(&options.data_root, "data root")?;
    validate_install_path(&options.control_root, "controller root")?;
    validate_install_path(&options.recovery_root, "recovery root")?;
    for (left, right, label) in [
        (
            &options.data_root,
            &options.control_root,
            "application and controller roots",
        ),
        (
            &options.data_root,
            &options.recovery_root,
            "application and recovery roots",
        ),
        (
            &options.control_root,
            &options.recovery_root,
            "controller and recovery roots",
        ),
    ] {
        if left.starts_with(right) || right.starts_with(left) {
            bail!("{label} must be distinct non-nested failure domains");
        }
    }
    validate_public_url(&options.public_url)?;
    normalize_external_dependencies(&mut options)?;
    normalize_profile_secrets(&mut options)?;
    let (runtime_backend, dependency_backend) = select_runtime(&options)?;
    let config_dir = config_path
        .parent()
        .context("update config path has no parent")?;
    let secrets_dir = config_dir.join("secrets");
    let app_root = options.data_root.join("app");
    create_directory(config_dir, 0o755)?;
    create_directory(&options.data_root, 0o755)?;
    create_directory(&options.control_root, 0o700)?;
    create_directory(&options.recovery_root, 0o700)?;
    let operator_dir = config_dir.join("operator");
    create_directory(&operator_dir, 0o700)?;
    operator::initialize_identity_generation(&operator_dir, &options.recovery_root)?;
    let bootstrap_operator =
        operator_config(config_dir, &options.control_root, &options.recovery_root)?;
    let name_suffix = object_name_suffix(&bootstrap_operator.deployment_id);
    let network_name = format!("nazoauth-{name_suffix}-network");
    if runtime_backend == RuntimeBackendKind::Systemd && options.network_subnet.is_some() {
        bail!("container network options are unavailable with the selected host runtime");
    }
    let network_gateway = if runtime_backend != RuntimeBackendKind::Systemd {
        Some(
            runtime_backend::backend(runtime_backend).ensure_managed_network(&ManagedNetwork {
                name: network_name.clone(),
                subnet: options.network_subnet.clone(),
                deployment_id: bootstrap_operator.deployment_id.clone(),
                control_authority: bootstrap_operator.controller_key_id.clone(),
            })?,
        )
    } else {
        None
    };
    let trusted_proxy_cidr = if options.profile == "standards-full" {
        if runtime_backend == RuntimeBackendKind::Systemd {
            Some("127.0.0.1/32".to_owned())
        } else {
            Some(host_cidr(
                network_gateway.context("container network gateway was not established")?,
            ))
        }
    } else {
        None
    };
    create_directory(&secrets_dir, 0o700)?;
    create_directory(&options.data_root.join("ui-releases"), 0o755)?;
    for path in [
        options.control_root.join("backups"),
        options.control_root.join("deployments"),
        options.control_root.join("audit"),
        options.control_root.join("operator-state"),
    ] {
        create_directory(&path, 0o700)?;
    }
    for path in [
        app_root.join("keys"),
        app_root.join("avatars"),
        app_root.join("secrets"),
        app_root.join("bootstrap"),
        app_root.join("instance"),
    ] {
        create_directory(&path, 0o700)?;
    }
    let profile = write_install_profile(config_dir, &options)?;

    let dependency_mode = if options.database_url.is_some() {
        write_external_urls(&secrets_dir, &options)?
    } else {
        write_managed_secrets(
            &secrets_dir,
            &format!("nazoauth-{name_suffix}-postgres"),
            &format!("nazoauth-{name_suffix}-valkey"),
        )?
    };
    write_server_config(
        config_dir,
        &options,
        runtime_backend,
        &options.data_root,
        trusted_proxy_cidr.as_deref(),
        profile.as_deref(),
    )?;
    let config = build_config(
        config_path,
        &options,
        runtime_backend,
        dependency_backend,
        &dependency_mode,
    )?;
    configure_runtime_permissions(&config)?;
    atomic_write(config_path, &(serde_json::to_vec_pretty(&config)?), 0o600)?;
    Ok(PreparedInstall {
        config,
        config_path: config_path.to_owned(),
    })
}

fn configure_runtime_permissions(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        return Ok(());
    }
    let app_root = config
        .runtime
        .snapshot_paths
        .first()
        .and_then(|path| path.parent())
        .context("application data root is unavailable")?;
    Process::new("chown")
        .args(["-R", "10001:10001"])
        .arg(app_root)
        .run_quiet()?;
    let ui_cache = config
        .runtime
        .mounts
        .iter()
        .find(|mount| mount.target == Path::new("/var/lib/nazo_oauth/ui-releases"))
        .context("UI cache mount is unavailable")?;
    Process::new("chown")
        .args(["-R", "10001:10001"])
        .arg(&ui_cache.source)
        .run_quiet()?;
    let config_file = config
        .runtime
        .mounts
        .iter()
        .find(|mount| mount.target == Path::new("/app/.env.yaml"))
        .context("server configuration mount is unavailable")?
        .source
        .clone();
    let mut readable = vec![
        config_file,
        config.dependencies.database_url_file.clone(),
        config.dependencies.migration_database_url_file.clone(),
        config.dependencies.valkey_url_file.clone(),
        config.operator.receipt_private_key.clone(),
    ];
    for name in STANDARDS_PROFILE_SECRET_NAMES {
        readable.push(
            config
                .dependencies
                .database_url_file
                .parent()
                .context("secret directory is unavailable")?
                .join(name),
        );
    }
    readable.retain(|path| path.exists());
    for path in readable {
        Process::new("chown")
            .arg("root:10001")
            .arg(&path)
            .run_quiet()?;
        set_mode(&path, 0o440)?;
    }
    Ok(())
}

pub(crate) fn start_managed_dependencies(config: &UpdateConfig) -> anyhow::Result<()> {
    if config.dependencies.mode != "managed" {
        return Ok(());
    }
    let backend = config
        .container_backend()
        .context("managed dependencies require Podman or Docker")?;
    let postgres_volume = format!("{}-data", config.postgres.container_name);
    let secrets = config
        .dependencies
        .database_url_file
        .parent()
        .context("dependency secret path has no parent")?
        .join("dependencies");
    runtime_backend::backend(backend).ensure_managed_dependencies(&ManagedDependencies {
        network: ManagedNetwork {
            name: config.runtime.network.clone(),
            subnet: None,
            deployment_id: config.operator.deployment_id.clone(),
            control_authority: config.operator.controller_key_id.clone(),
        },
        runtime_instance_id: config.runtime.runtime_instance_id.clone(),
        postgres_object: config.postgres.container_name.clone(),
        postgres_volume,
        postgres_image: config.postgres.image.clone(),
        postgres_database: config.postgres.database.clone(),
        postgres_user: config.postgres.user.clone(),
        postgres_password_file: secrets.join("postgres-password"),
        valkey_object: config.valkey.container_name.clone(),
        valkey_volume: config.valkey.data_volume.clone(),
        valkey_image: config.valkey.image.clone(),
        valkey_password_file: secrets.join("valkey-password"),
        valkey_acl_file: secrets.join("valkey.acl"),
    })?;
    configure_managed_database_roles(config)
        .context("failed to configure managed PostgreSQL roles after final readiness")
}

pub(crate) fn install_systemd(config: &UpdateConfig) -> anyhow::Result<()> {
    if config.runtime.backend != RuntimeBackendKind::Systemd {
        return Ok(());
    }
    let app_root = config
        .runtime
        .snapshot_paths
        .first()
        .and_then(|path| path.parent())
        .context("host runtime has no application data root")?;
    let data_root = app_root
        .parent()
        .context("host runtime has no deployment data root")?;
    let operator_dir = config
        .operator
        .controller_public_key
        .parent()
        .context("host runtime has no operator directory")?;
    runtime_backend::backend(RuntimeBackendKind::Systemd).install_host_service(
        &HostServiceInstall {
            service_name: config.runtime.service_name.clone(),
            service_user: config.runtime.service_user.clone(),
            working_directory: config.runtime.working_directory.clone(),
            binary: config.runtime.binary_path.clone(),
            app_root: app_root.to_owned(),
            ui_releases: data_root.join("ui-releases"),
            operator_state: config.operator.state_directory.clone(),
            operator_directory: operator_dir.to_owned(),
            recovery_directory: config
                .operator
                .break_glass_private_key
                .parent()
                .context("host runtime has no recovery directory")?
                .to_owned(),
            migration_url: config.dependencies.migration_database_url_file.clone(),
            receipt_private_key: config.operator.receipt_private_key.clone(),
            runtime_readable_secret_names: ["database-url", "valkey-url"]
                .into_iter()
                .chain(STANDARDS_PROFILE_SECRET_NAMES.iter().copied())
                .map(ToOwned::to_owned)
                .collect(),
        },
    )
}

fn normalize_external_dependencies(options: &mut InstallOptions) -> anyhow::Result<()> {
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

fn normalize_profile_secrets(options: &mut InstallOptions) -> anyhow::Result<()> {
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalDependencySecrets {
    database_url: String,
    migration_database_url: String,
    valkey_url: String,
}

fn read_external_dependency_secrets(
    options: &mut InstallOptions,
    mut source: impl std::io::Read,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("dependency secret input exceeds 64 KiB");
    }
    let secrets: ExternalDependencySecrets =
        serde_json::from_slice(&bytes).context("dependency secret input must be strict JSON")?;
    options.database_url = Some(secrets.database_url);
    options.migration_database_url = Some(secrets.migration_database_url);
    options.valkey_url = Some(secrets.valkey_url);
    Ok(())
}

fn read_profile_secrets(
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

fn validate_profile_secret_value(name: &str, value: &str) -> anyhow::Result<()> {
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

fn select_runtime(
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
    let dependency_backend = if runtime_backend::backend(RuntimeBackendKind::Podman).available() {
        RuntimeBackendKind::Podman
    } else if runtime_backend::backend(RuntimeBackendKind::Docker).available() {
        RuntimeBackendKind::Docker
    } else {
        bail!("host runtime requires Podman or Docker for managed dependencies");
    };
    Ok((runtime, Some(dependency_backend)))
}

fn write_external_urls(secrets: &Path, options: &InstallOptions) -> anyhow::Result<String> {
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

fn write_managed_secrets(
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
        format!("postgresql://nazoauth_runtime:{runtime_postgres}@{postgres_container}:5432/oauth")
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("database-migration-url"),
        format!("postgresql://nazoauth_migrator:{postgres}@{postgres_container}:5432/oauth")
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("valkey-url"),
        format!("redis://default:{valkey}@{valkey_container}:6379/0").as_bytes(),
        0o440,
    )?;
    atomic_write(
        &dependencies.join("valkey.acl"),
        format!("user default on >{valkey} ~* &* +@all\n").as_bytes(),
        0o444,
    )?;
    Ok("managed".to_owned())
}

fn write_server_config(
    config_dir: &Path,
    options: &InstallOptions,
    runtime: RuntimeBackendKind,
    data_root: &Path,
    trusted_proxy_cidr: Option<&str>,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let target = config_dir.join(".env.yaml");
    if target.exists() {
        if !target.is_file() || target.is_symlink() || fs::metadata(&target)?.len() == 0 {
            bail!(
                "existing server configuration is invalid: {}",
                target.display()
            );
        }
        return Ok(());
    }
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
         DATABASE_MAX_CONNECTIONS: 32\n\
         DATA_DIR: \"{data_dir}\"\n\
         UI_CACHE_DIR: \"{ui_dir}\"\n\
         RUST_LOG: \"info\"\n\
         {dependency_files}{profile}",
        public_url = options.public_url,
        profile = profile
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardsFullProfileMaterial {
    #[serde(default)]
    client_attestation_issuer: Option<String>,
    #[serde(default)]
    client_attestation_jwks: Option<serde_json::Value>,
    #[serde(default)]
    key_attestation_jwks: Option<serde_json::Value>,
    credential_configurations: serde_json::Value,
    wallet_authorization_origins: Vec<String>,
    ciba_notification_private_origins: Vec<String>,
    backchannel_logout_private_origins: Vec<String>,
}

fn write_install_profile(
    config_dir: &Path,
    options: &InstallOptions,
) -> anyhow::Result<Option<String>> {
    if options.profile == "baseline" {
        return Ok(None);
    }
    let source = options
        .profile_material
        .as_deref()
        .context("standards-full profile material is unavailable")?;
    safe_absolute(source)?;
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect profile material {}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 * 1024 {
        bail!("profile material must be a regular file no larger than 256 KiB");
    }
    let material: StandardsFullProfileMaterial = serde_json::from_slice(&fs::read(source)?)
        .context("standards-full profile material must be strict JSON")?;
    match (
        &material.client_attestation_issuer,
        &material.client_attestation_jwks,
    ) {
        (Some(issuer), Some(jwks)) => {
            validate_https_origin(issuer, "client attestation issuer")?;
            validate_public_jwks(jwks, "client attestation JWKS")?;
        }
        (None, None) => {}
        _ => bail!("client attestation issuer and JWKS must be supplied together"),
    }
    if let Some(jwks) = &material.key_attestation_jwks {
        validate_public_jwks(jwks, "key attestation JWKS")?;
    }
    let credential_configurations = material
        .credential_configurations
        .as_object()
        .filter(|value| !value.is_empty())
        .context("credential configurations must be a non-empty object")?;
    if credential_configurations
        .keys()
        .any(|key| key.trim().is_empty())
    {
        bail!("credential configuration identifiers must not be empty");
    }
    for (name, origins) in [
        (
            "wallet authorization",
            &material.wallet_authorization_origins,
        ),
        (
            "CIBA notification",
            &material.ciba_notification_private_origins,
        ),
        (
            "back-channel logout",
            &material.backchannel_logout_private_origins,
        ),
    ] {
        if origins.is_empty() {
            bail!("{name} origins must not be empty");
        }
        for origin in origins {
            validate_https_origin(origin, &format!("{name} origin"))?;
        }
    }
    let secrets = config_dir.join("secrets");
    let provided = options.profile_secrets.as_ref();
    write_or_verify_profile_secret(
        &secrets.join("dynamic-registration-token"),
        "dynamic_registration_initial_access_token",
        provided.map(|secrets| secrets.dynamic_registration_initial_access_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("ciba-decision-token"),
        "ciba_automated_decision_token",
        provided.map(|secrets| secrets.ciba_automated_decision_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("openid4vci-management-token"),
        "openid4vci_management_token",
        provided.map(|secrets| secrets.openid4vci_management_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("openid4vp-management-token"),
        "openid4vp_management_token",
        provided.map(|secrets| secrets.openid4vp_management_token.as_str()),
    )?;
    let encryption_key_path = secrets.join("openid4vc-data-encryption-key");
    if !encryption_key_path.exists() {
        let value = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        atomic_write(&encryption_key_path, value.as_bytes(), 0o440)?;
    }
    let encryption_key = fs::read_to_string(&encryption_key_path)?;
    if encryption_key.contains(['\n', '\r'])
        || URL_SAFE_NO_PAD
            .decode(&encryption_key)
            .ok()
            .is_none_or(|decoded| decoded.len() != 32)
    {
        bail!("persisted OpenID4VC data encryption key is invalid");
    }

    let scalar = |value: &str| serde_json::to_string(value).expect("serialize YAML scalar");
    let mut lines = vec![
        "ENABLE_REQUEST_OBJECT: true".to_owned(),
        "ENABLE_PAR_REQUEST_OBJECT: true".to_owned(),
        "ENABLE_AUTHORIZATION_DETAILS: true".to_owned(),
        "ENABLE_DEVICE_AUTHORIZATION_GRANT: true".to_owned(),
        "ENABLE_DYNAMIC_CLIENT_REGISTRATION: true".to_owned(),
        "ENABLE_CIBA: true".to_owned(),
        "ENABLE_FRONTCHANNEL_LOGOUT: true".to_owned(),
        "ENABLE_SESSION_MANAGEMENT: true".to_owned(),
        "ENABLE_NATIVE_SSO: true".to_owned(),
        "ENABLE_OPENID4VCI_ISSUER: true".to_owned(),
        "ENABLE_OPENID4VP_VERIFIER: true".to_owned(),
        format!(
            "MTLS_ENDPOINT_BASE_URL: {}",
            scalar(options.public_url.trim_end_matches('/'))
        ),
        "TRUSTED_PROXY_CIDRS: \"${TRUSTED_PROXY_CIDR}\"".to_owned(),
        "MTLS_CERTIFICATE_SOURCE: \"legacy-verified-headers\"".to_owned(),
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/dynamic-registration-token\"".to_owned(),
        "CIBA_AUTOMATED_DECISION_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/ciba-decision-token\"".to_owned(),
        "OPENID4VC_DATA_ENCRYPTION_KEY_FILE: \"${PROFILE_SECRET_ROOT}/openid4vc-data-encryption-key\"".to_owned(),
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vci-management-token\"".to_owned(),
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vp-management-token\"".to_owned(),
        "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
        "OPENID4VC_TRUST_ANCHORS_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
    ];
    if let (Some(issuer), Some(jwks)) = (
        &material.client_attestation_issuer,
        &material.client_attestation_jwks,
    ) {
        lines.push(format!(
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER: {}",
            scalar(issuer)
        ));
        lines.push(format!(
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(jwks)?)
        ));
    }
    if let Some(jwks) = &material.key_attestation_jwks {
        lines.push(format!(
            "OPENID4VC_KEY_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(jwks)?)
        ));
    }
    lines.extend([
        format!(
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON: {}",
            scalar(&serde_json::to_string(&material.credential_configurations)?)
        ),
        format!(
            "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS: {}",
            scalar(&material.wallet_authorization_origins.join(","))
        ),
        format!(
            "CIBA_NOTIFICATION_PRIVATE_ORIGINS: {}",
            scalar(&material.ciba_notification_private_origins.join(","))
        ),
        format!(
            "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS: {}",
            scalar(&material.backchannel_logout_private_origins.join(","))
        ),
    ]);
    Ok(Some(format!("{}\n", lines.join("\n"))))
}

fn write_or_verify_profile_secret(
    path: &Path,
    name: &str,
    provided: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(value) = provided {
        validate_profile_secret_value(name, value)?;
        if path.exists() {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to inspect persisted profile secret {name}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("persisted profile secret {name} is not a regular file");
            }
            let persisted = zeroize::Zeroizing::new(
                fs::read_to_string(path)
                    .with_context(|| format!("failed to read persisted profile secret {name}"))?,
            );
            validate_profile_secret_value(name, &persisted)?;
            if persisted.as_str() != value {
                bail!(
                    "provided profile secret {name} does not match the persisted installation state"
                );
            }
        } else {
            atomic_write(path, value.as_bytes(), 0o440)?;
        }
        return Ok(());
    }

    let generated_or_persisted = zeroize::Zeroizing::new(generate_secret(path)?);
    validate_profile_secret_value(name, &generated_or_persisted)
}

fn validate_https_origin(value: &str, label: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("invalid {label}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("{label} must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}

fn validate_public_jwks(value: &serde_json::Value, label: &str) -> anyhow::Result<()> {
    let keys = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .with_context(|| format!("{label} must contain a non-empty keys array"))?;
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if keys.iter().any(|key| {
        key.as_object().is_none_or(|object| {
            PRIVATE_MEMBERS
                .iter()
                .any(|name| object.contains_key(*name))
        })
    }) {
        bail!("{label} must contain public asymmetric keys only");
    }
    Ok(())
}

fn host_cidr(address: std::net::IpAddr) -> String {
    match address {
        std::net::IpAddr::V4(address) => format!("{address}/32"),
        std::net::IpAddr::V6(address) => format!("{address}/128"),
    }
}

fn build_config(
    config_path: &Path,
    options: &InstallOptions,
    runtime_backend: RuntimeBackendKind,
    dependency_backend: Option<RuntimeBackendKind>,
    dependency_mode: &str,
) -> anyhow::Result<UpdateConfig> {
    let config_dir = config_path.parent().context("config has no parent")?;
    let secrets = config_dir.join("secrets");
    let app = options.data_root.join("app");
    let updater = env::var_os("NAZOAUTH_UPDATER_INSTALL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/sbin/nazoauthctl"));
    let binary = env::var_os("NAZOAUTH_BINARY_INSTALL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/nazoauth"));
    let releases = env::var_os("NAZOAUTH_BINARY_RELEASES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/nazoauth/releases"));
    let container = runtime_backend != RuntimeBackendKind::Systemd;
    let mut mounts = if container {
        vec![
            mount(config_dir.join(".env.yaml"), "/app/.env.yaml", "ro,Z"),
            mount(app.join("keys"), "/var/lib/nazo_oauth/keys", "rw,Z"),
            mount(app.join("avatars"), "/var/lib/nazo_oauth/avatars", "rw,Z"),
            mount(app.join("secrets"), "/var/lib/nazo_oauth/secrets", "rw,Z"),
            mount(app.join("instance"), "/var/lib/nazo_oauth/instance", "rw,Z"),
            mount(
                app.join("bootstrap"),
                "/var/lib/nazo_oauth/bootstrap",
                "rw,Z",
            ),
            mount(
                options.data_root.join("ui-releases"),
                "/var/lib/nazo_oauth/ui-releases",
                "rw,Z",
            ),
            mount(
                secrets.join("database-url"),
                "/run/nazoauth-secrets/database-url",
                "ro,Z",
            ),
            mount(
                secrets.join("valkey-url"),
                "/run/nazoauth-secrets/valkey-url",
                "ro,Z",
            ),
        ]
    } else {
        Vec::new()
    };
    if container && options.profile == "standards-full" {
        mounts.extend(STANDARDS_PROFILE_SECRET_NAMES.iter().map(|name| {
            mount(
                secrets.join(name),
                &format!("/run/nazoauth-secrets/{name}"),
                "ro,Z",
            )
        }));
    }
    let environment = if container {
        BTreeMap::from([
            (
                "DATABASE_URL_FILE".to_owned(),
                "/run/nazoauth-secrets/database-url".to_owned(),
            ),
            (
                "VALKEY_URL_FILE".to_owned(),
                "/run/nazoauth-secrets/valkey-url".to_owned(),
            ),
        ])
    } else {
        BTreeMap::new()
    };
    let publish_address = if container {
        format!("127.0.0.1:{}:8000", options.port)
    } else {
        String::new()
    };
    let operator = operator_config(config_dir, &options.control_root, &options.recovery_root)?;
    let name_suffix = object_name_suffix(&operator.deployment_id);
    let (service_name, service_user, binary_path, binary_releases, working_directory) = if container
    {
        (
            String::new(),
            String::new(),
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        )
    } else {
        (
            format!("nazoauth-{name_suffix}.service"),
            format!("nazoauth-{name_suffix}"),
            binary,
            releases,
            config_dir.to_owned(),
        )
    };
    let valkey_password_file = if dependency_mode == "managed" {
        PathBuf::from("/run/nazoauth-secrets/valkey-password")
    } else {
        PathBuf::new()
    };
    let config = UpdateConfig {
        schema: 2,
        trust: crate::deployment::TrustState::Adopted,
        capabilities: crate::deployment::CapabilityGrants::controller_installed(),
        install_profile: options.profile.clone(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: updater,
        backup_root: options.control_root.join("backups"),
        deployment_root: options.control_root.join("deployments"),
        operator,
        dependencies: Dependencies {
            mode: dependency_mode.to_owned(),
            database_url_file: secrets.join("database-url"),
            migration_database_url_file: secrets.join("database-migration-url"),
            valkey_url_file: secrets.join("valkey-url"),
        },
        runtime: Runtime {
            backend: runtime_backend,
            dependency_backend,
            backend_command_override: None,
            container_name: format!("nazoauth-{name_suffix}-server"),
            runtime_instance_id: uuid::Uuid::now_v7().to_string(),
            network: format!("nazoauth-{name_suffix}-network"),
            ip_address: options.runtime_ip.clone().unwrap_or_default(),
            publish_address,
            health_url: format!("http://127.0.0.1:{}/ready", options.port),
            readiness_attempts: 60,
            readiness_interval_seconds: 1,
            public_discovery_url: format!(
                "{}/.well-known/openid-configuration",
                options.public_url.trim_end_matches('/')
            ),
            expected_issuer: options.public_url.trim_end_matches('/').to_owned(),
            mounts,
            snapshot_paths: vec![
                app.join("keys"),
                app.join("secrets"),
                app.join("bootstrap"),
                app.join("instance"),
            ],
            environment,
            service_name,
            service_user,
            binary_path,
            binary_releases,
            working_directory,
        },
        postgres: Postgres {
            container_name: format!("nazoauth-{name_suffix}-postgres"),
            database: "oauth".to_owned(),
            user: "nazoauth_migrator".to_owned(),
            image: POSTGRES_IMAGE.to_owned(),
            validation_image: POSTGRES_IMAGE.to_owned(),
        },
        valkey: Valkey {
            container_name: format!("nazoauth-{name_suffix}-valkey"),
            data_volume: format!("nazoauth-{name_suffix}-valkey-data"),
            image: VALKEY_IMAGE.to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: valkey_password_file,
        },
        ui: Ui {
            releases_root: options.data_root.join("ui-releases"),
        },
    };
    config.validate()?;
    Ok(config)
}

fn operator_config(
    config_dir: &Path,
    control_root: &Path,
    recovery_root: &Path,
) -> anyhow::Result<Operator> {
    let directory = config_dir.join("operator");
    let deployment_id = fs::read_to_string(directory.join("deployment-id"))?;
    let active = operator::read_active_identity(&directory.join("active-generation.json"))?;
    let receipt_key_id = fs::read_to_string(directory.join("receipt.kid"))?;
    let generation = directory.join("generations").join(&active.generation);
    let recovery_generation = recovery_root.join("generations").join(&active.generation);
    Ok(Operator {
        deployment_id,
        controller_key_id: active.controller_key_id,
        controller_private_key: generation.join("controller.key"),
        controller_public_key: generation.join("controller.pub"),
        receipt_key_id,
        receipt_private_key: directory.join("receipt.key"),
        receipt_public_key: directory.join("receipt.pub"),
        audit_key_id: active.audit_key_id,
        audit_private_key: generation.join("audit.key"),
        audit_public_key: generation.join("audit.pub"),
        break_glass_key_id: active.break_glass_key_id,
        break_glass_private_key: recovery_generation.join("break-glass.key"),
        break_glass_public_key: generation.join("break-glass.pub"),
        active_identity_file: directory.join("active-generation.json"),
        identity_generations_directory: directory.join("generations"),
        recovery_generations_directory: recovery_root.join("generations"),
        secret_revision_file: directory.join("secret-revision"),
        state_directory: control_root.join("operator-state"),
        audit_directory: control_root.join("audit"),
        trust_state_file: directory.join("release-trust.json"),
    })
}

fn object_name_suffix(deployment_id: &str) -> String {
    deployment_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(16)
        .collect()
}

fn mount(source: PathBuf, target: &str, mode: &str) -> Mount {
    Mount {
        source,
        target: PathBuf::from(target),
        read_only: mode.starts_with("ro"),
        selinux_relabel: mode.split(',').any(|value| matches!(value, "z" | "Z")),
    }
}

fn configure_managed_database_roles(config: &UpdateConfig) -> anyhow::Result<()> {
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
    let sql = b"GRANT CONNECT ON DATABASE oauth TO nazoauth_runtime;\n\
        GRANT USAGE ON SCHEMA public TO nazoauth_runtime;\n\
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nazoauth_runtime;\n\
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO nazoauth_runtime;\n\
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO nazoauth_runtime;\n";
    crate::runtime::Runtime::new(config).execute_managed_postgres(sql)
}

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

fn validate_public_url(value: &str) -> anyhow::Result<()> {
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

fn validate_install_path(path: &Path, label: &str) -> anyhow::Result<()> {
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

fn validate_dependency_url(value: &str, schemes: &[&str], name: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("{name} URL is invalid"))?;
    if !schemes.contains(&parsed.scheme()) || parsed.host_str().is_none() {
        bail!("{name} URL has an unsupported scheme or no host");
    }
    Ok(())
}

fn create_directory(path: &Path, mode: u32) -> anyhow::Result<()> {
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

fn require_supported_install_platform() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if !install_platform_supported(std::env::consts::OS, std::env::consts::ARCH) {
        bail!("install lifecycle supports only Linux x86_64 and aarch64");
    }
    Ok(())
}

fn install_platform_supported(os: &str, arch: &str) -> bool {
    matches!((os, arch), ("linux", "x86_64" | "aarch64"))
}

fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if Process::new("id").arg("-u").stdout()?.trim() != "0" {
        bail!("install and update require root");
    }
    Ok(())
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

#[cfg(test)]
#[path = "../tests/unit/install.rs"]
mod tests;
