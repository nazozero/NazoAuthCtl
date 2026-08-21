use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
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

mod config;
mod profile;
mod runtime;
mod secrets;
use config::*;
use profile::*;
use runtime::*;
pub(crate) use runtime::{
    grant_runtime_database, normalize_public_url_for_profile, normalize_single_host_cidr,
    verify_runtime_no_ddl,
};
use secrets::*;
pub(crate) use secrets::{
    ensure_mfa_totp_configuration, ensure_mfa_totp_runtime,
    ensure_tenant_resource_controller_identity, ensure_tenant_resource_controller_runtime,
    read_tenant_resource_controller_signing_key, reconcile_managed_secrets,
    tenant_resource_controller_key_id_path, tenant_resource_controller_private_key_path,
    tenant_resource_controller_public_key_path, verify_live_external_dependencies,
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
const MFA_TOTP_KEY_FILE_NAME: &str = "mfa-totp-encryption-key";
const MFA_TOTP_KEY_ID: &str = "nazoauth-mfa-totp-v1";
const MFA_TOTP_CONTAINER_KEY_PATH: &str = "/run/nazoauth-secrets/mfa-totp-encryption-key";
const TENANT_RESOURCE_CONTROLLER_CONTAINER_KEY_PATH: &str = "/run/nazoauth-control/controller.pub";

pub(crate) struct PreparedInstall {
    pub(crate) config: UpdateConfig,
    pub(crate) config_path: PathBuf,
    pub(crate) local_oci_candidate: Option<crate::cli::LocalOciCandidateInstall>,
}

/// Durable sibling intent for the otherwise unjournaled interval between
/// preparing a fresh configuration and the first candidate runtime check.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalOciCandidatePrepareIntent {
    schema: u32,
    candidate: crate::cli::LocalOciCandidateInstall,
    config: UpdateConfig,
    config_sha256: String,
}

pub(crate) fn local_oci_candidate_prepare_intent_path(config_path: &Path) -> PathBuf {
    let name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("nazoauthctl.json");
    config_path.with_file_name(format!(".{name}.local-oci-candidate-intent.json"))
}

fn candidate_intent_config_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn load_local_oci_candidate_prepare_intent(
    config_path: &Path,
) -> anyhow::Result<Option<LocalOciCandidatePrepareIntent>> {
    let path = local_oci_candidate_prepare_intent_path(config_path);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!(
            "local OCI candidate prepare intent must be a regular non-symlink file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect local OCI candidate prepare intent {}",
                    path.display()
                )
            });
        }
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "local OCI candidate prepare intent",
        true,
        1024 * 1024,
    )?;
    Ok(Some(serde_json::from_slice(&bytes).context(
        "local OCI candidate prepare intent is invalid",
    )?))
}

pub(crate) fn restore_local_oci_candidate_prepare_intent(
    config_path: &Path,
    candidate: &crate::cli::LocalOciCandidateInstall,
) -> anyhow::Result<()> {
    let intent = load_local_oci_candidate_prepare_intent(config_path)?
        .context("local OCI candidate config is absent and no durable prepare intent exists")?;
    validate_local_oci_candidate_prepare_intent(&intent, candidate)?;
    let bytes = serde_json::to_vec_pretty(&intent.config)?;
    if candidate_intent_config_digest(&bytes) != intent.config_sha256 {
        bail!("local OCI candidate prepare intent config digest is inconsistent");
    }
    atomic_write(config_path, &bytes, 0o600)
}

pub(crate) fn validate_existing_local_oci_candidate_prepare_intent(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &crate::cli::LocalOciCandidateInstall,
) -> anyhow::Result<()> {
    let intent = load_local_oci_candidate_prepare_intent(config_path)?
        .context("local OCI candidate install has no durable fresh-prepare intent")?;
    validate_local_oci_candidate_prepare_intent(&intent, candidate)?;
    let bytes = serde_json::to_vec_pretty(config)?;
    if candidate_intent_config_digest(&bytes) != intent.config_sha256 {
        bail!("existing controller config differs from its local OCI candidate prepare intent");
    }
    Ok(())
}

fn validate_local_oci_candidate_prepare_intent(
    intent: &LocalOciCandidatePrepareIntent,
    candidate: &crate::cli::LocalOciCandidateInstall,
) -> anyhow::Result<()> {
    if intent.schema != 1 || intent.candidate != *candidate {
        bail!("local OCI candidate prepare intent does not match the exact requested candidate");
    }
    Ok(())
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
    options.public_url = normalize_public_url_for_profile(&options.public_url, &options.profile)?;
    if options.profile == "standards-full" {
        let cidr = options
            .trusted_proxy_cidr
            .as_deref()
            .context("standards-full requires an explicit trusted proxy CIDR")?;
        options.trusted_proxy_cidr = Some(normalize_single_host_cidr(cidr)?);
    } else if options.trusted_proxy_cidr.is_some() {
        bail!("--trusted-proxy-cidr is accepted only with --profile standards-full");
    }
    validate_standards_full_trusted_proxy_contract(
        &options.public_url,
        &options.profile,
        options.trusted_proxy_cidr.as_deref(),
    )?;
    if options.local_oci_candidate.is_some() && options.external_dependencies {
        bail!("a local OCI candidate install is managed-only and rejects external dependencies");
    }
    normalize_external_dependencies(&mut options)?;
    normalize_profile_secrets(&mut options)?;
    // Validate the exact NazoAuth standards-full schema before this fresh
    // install creates controller state, config, or managed dependencies.
    let profile_material = load_and_validate_install_profile(&options)?;
    let (runtime_backend, dependency_backend) = select_runtime(&options)?;
    if options.local_oci_candidate.is_some() {
        if runtime_backend == RuntimeBackendKind::Systemd {
            bail!("a local OCI candidate install requires a Podman or Docker runtime");
        }
        if options.profile != "standards-full" {
            bail!("a local OCI candidate install requires --profile standards-full");
        }
    }
    let config_dir = config_path
        .parent()
        .context("update config path has no parent")?;
    let secrets_dir = config_dir.join("secrets");
    let app_root = options.data_root.join("app");
    crate::deployment::validate_independent_recovery_device(
        &options.recovery_root,
        &[
            ("application root", &options.data_root),
            ("controller root", &options.control_root),
        ],
        "installation recovery root",
    )?;
    create_directory(config_dir, 0o755)?;
    create_directory(&options.data_root, 0o755)?;
    // Keep the controller root owner-only until the Systemd backend has
    // created and validated the non-root service account.  The backend then
    // grants only the traverse/group boundary needed for operator-state.
    create_directory(&options.control_root, 0o700)?;
    create_directory(&options.recovery_root, 0o700)?;
    let operator_dir = config_dir.join("operator");
    create_directory(&operator_dir, 0o700)?;
    operator::initialize_identity_generation(&operator_dir, &options.recovery_root)?;
    ensure_tenant_resource_controller_identity(config_dir)?;
    let bootstrap_operator =
        operator_config(config_dir, &options.control_root, &options.recovery_root)?;
    let name_suffix = object_name_suffix(&bootstrap_operator.deployment_id);
    let network_name = format!("nazoauth-{name_suffix}-network");
    if runtime_backend == RuntimeBackendKind::Systemd && options.network_subnet.is_some() {
        bail!("container network options are unavailable with the selected host runtime");
    }
    if runtime_backend != RuntimeBackendKind::Systemd {
        runtime_backend::backend(runtime_backend).ensure_managed_network(&ManagedNetwork {
            name: network_name.clone(),
            subnet: options.network_subnet.clone(),
            deployment_id: bootstrap_operator.deployment_id.clone(),
            control_authority: bootstrap_operator.controller_key_id.clone(),
        })?;
    }
    create_directory(&secrets_dir, 0o700)?;
    create_directory(&options.data_root.join("ui-releases"), 0o755)?;
    create_directory(&options.recovery_root.join("backups"), 0o700)?;
    for path in [
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
    ensure_mfa_totp_configuration(config_dir, runtime_backend)?;
    let profile =
        write_prevalidated_install_profile(config_dir, &options, profile_material.as_ref())?;

    let dependency_mode = if options.database_url.is_some() {
        write_external_urls(&secrets_dir, &options)?
    } else {
        write_managed_secrets(
            &secrets_dir,
            &format!("nazoauth-{name_suffix}-postgres"),
            &format!("nazoauth-{name_suffix}-valkey"),
        )?
    };
    write_server_config(ServerConfigWriteRequest {
        config_dir,
        options: &options,
        deployment_id: &bootstrap_operator.deployment_id,
        controller_public_key: &tenant_resource_controller_public_key_path(config_dir),
        runtime: runtime_backend,
        data_root: &options.data_root,
        trusted_proxy_cidr: options.trusted_proxy_cidr.as_deref(),
        profile_config: profile.as_deref(),
    })?;
    let config = build_config(
        config_path,
        &options,
        runtime_backend,
        dependency_backend,
        &dependency_mode,
    )?;
    configure_runtime_permissions(&config)?;
    let config_bytes = serde_json::to_vec_pretty(&config)?;
    if let Some(candidate) = options.local_oci_candidate.as_ref() {
        let intent = LocalOciCandidatePrepareIntent {
            schema: 1,
            candidate: candidate.clone(),
            config: config.clone(),
            config_sha256: candidate_intent_config_digest(&config_bytes),
        };
        // Write and fsync the candidate provenance before publishing the
        // config.  If the next rename or first image inspection fails, retry
        // can restore exactly this prepared deployment rather than creating a
        // second controller identity.
        atomic_write(
            &local_oci_candidate_prepare_intent_path(config_path),
            &serde_json::to_vec_pretty(&intent)?,
            0o600,
        )?;
    }
    atomic_write(config_path, &config_bytes, 0o600)?;
    Ok(PreparedInstall {
        config,
        config_path: config_path.to_owned(),
        local_oci_candidate: options.local_oci_candidate.clone(),
    })
}

pub(crate) fn validate_standards_full_trusted_proxy_contract(
    public_url: &str,
    profile: &str,
    trusted_proxy_cidr: Option<&str>,
) -> anyhow::Result<()> {
    if profile != "standards-full" {
        return Ok(());
    }
    if !public_url.starts_with("https://") {
        bail!("standards-full trusted-proxy install requires an HTTPS --public-url");
    }
    let cidr = trusted_proxy_cidr
        .context("standards-full trusted-proxy install requires --trusted-proxy-cidr")?;
    normalize_single_host_cidr(cidr)?;
    Ok(())
}

fn configure_runtime_permissions(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        // The service account does not exist until install_systemd invokes the
        // backend.  Account-specific ownership and the control-root traverse
        // boundary are applied there, after the UID has been proven non-root.
        return Ok(());
    }
    configure_container_operator_state_permissions(
        OsStr::new("chown"),
        &config.operator.state_directory,
    )?;
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
    let mfa_key = config_file
        .parent()
        .context("server configuration directory is unavailable")?
        .join("secrets")
        .join(MFA_TOTP_KEY_FILE_NAME);
    let tenant_resource_controller_public_key = tenant_resource_controller_public_key_path(
        config_file
            .parent()
            .context("server configuration directory is unavailable")?,
    );
    let mut readable = vec![
        config_file,
        config.dependencies.database_url_file.clone(),
        // This is mounted only into the isolated migration task.  It shares
        // the fixed non-root operator group, while the long-lived runtime has
        // no mount for this path.
        config.dependencies.migration_database_url_file.clone(),
        config.dependencies.valkey_url_file.clone(),
        mfa_key,
        config.operator.receipt_private_key.clone(),
        tenant_resource_controller_public_key,
        config.operator.secret_revision_file.clone(),
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

fn configure_container_operator_state_permissions(
    chown_command: &OsStr,
    state_directory: &Path,
) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(state_directory).with_context(|| {
        format!(
            "failed to inspect operator state directory {}",
            state_directory.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("operator state path must be a real directory");
    }
    Process::new(chown_command)
        .arg("10001:10001")
        .arg(state_directory)
        .run_quiet()?;
    set_mode(state_directory, 0o700)
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
            subnet: config.runtime.network_subnet.clone(),
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
        valkey_user: runtime_backend::MANAGED_VALKEY_RUNTIME_USER.to_owned(),
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
            deployment_id: config.operator.deployment_id.clone(),
            runtime_instance_id: config.runtime.runtime_instance_id.clone(),
            control_authority: config.operator.controller_key_id.clone(),
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
            restricted_secret_paths: if config.dependencies.mode == "external" {
                [
                    config.dependencies.database_backup_url_file.clone(),
                    config.dependencies.valkey_backup_url_file.clone(),
                ]
                .into_iter()
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
            } else {
                Vec::new()
            },
            receipt_private_key: config.operator.receipt_private_key.clone(),
            runtime_readable_secret_names: ["database-url", "valkey-url", MFA_TOTP_KEY_FILE_NAME]
                .into_iter()
                .chain(STANDARDS_PROFILE_SECRET_NAMES.iter().copied())
                .map(ToOwned::to_owned)
                .collect(),
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/install.rs"]
mod tests;
