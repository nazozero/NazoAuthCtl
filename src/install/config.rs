use super::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveIdentityManifest {
    schema: u32,
    generation: String,
    controller_key_id: String,
    audit_key_id: String,
    break_glass_key_id: String,
}

pub(super) fn build_config(
    config_path: &Path,
    options: &InstallOptions,
    runtime_backend: RuntimeBackendKind,
    dependency_backend: Option<RuntimeBackendKind>,
    dependency_mode: &str,
) -> anyhow::Result<UpdateConfig> {
    let config_dir = config_path.parent().context("config has no parent")?;
    let secrets = config_dir.join("secrets");
    let app = options.data_root.join("app");
    let binary = env::var_os("NAZOAUTH_BINARY_INSTALL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/nazoauth"));
    let releases = env::var_os("NAZOAUTH_BINARY_RELEASES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/nazoauth/releases"));
    let container = runtime_backend != RuntimeBackendKind::Systemd;
    let mut mounts = if container {
        vec![
            mount(config_dir.join(".env.yaml"), "/app/.env.yaml", true, true),
            mount(app.join("keys"), "/var/lib/nazo_oauth/keys", false, true),
            mount(
                app.join("avatars"),
                "/var/lib/nazo_oauth/avatars",
                false,
                true,
            ),
            mount(
                app.join("secrets"),
                "/var/lib/nazo_oauth/secrets",
                false,
                true,
            ),
            mount(
                app.join("instance"),
                "/var/lib/nazo_oauth/instance",
                false,
                true,
            ),
            mount(
                app.join("bootstrap"),
                "/var/lib/nazo_oauth/bootstrap",
                false,
                true,
            ),
            mount(
                options.data_root.join("ui-releases"),
                "/var/lib/nazo_oauth/ui-releases",
                false,
                true,
            ),
            mount(
                secrets.join("database-url"),
                "/run/nazoauth-secrets/database-url",
                true,
                true,
            ),
            mount(
                secrets.join("valkey-url"),
                "/run/nazoauth-secrets/valkey-url",
                true,
                true,
            ),
        ]
    } else {
        Vec::new()
    };
    let mfa_key = secrets.join(MFA_TOTP_KEY_FILE_NAME);
    let managed_mfa = managed_mfa_totp_source(config_dir, runtime_backend)?;
    if container && managed_mfa && mfa_key.exists() {
        mounts.push(mount(
            mfa_key.clone(),
            MFA_TOTP_CONTAINER_KEY_PATH,
            true,
            true,
        ));
    }
    if container && options.profile == "standards-full" {
        mounts.extend(STANDARDS_PROFILE_SECRET_NAMES.iter().map(|name| {
            mount(
                secrets.join(name),
                &format!("/run/nazoauth-secrets/{name}"),
                true,
                true,
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
            snapshot_paths: {
                let mut paths = vec![
                    app.join("keys"),
                    app.join("secrets"),
                    app.join("bootstrap"),
                    app.join("instance"),
                ];
                if managed_mfa {
                    paths.push(secrets);
                }
                paths
            },
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

pub(super) fn operator_config(
    config_dir: &Path,
    control_root: &Path,
    recovery_root: &Path,
) -> anyhow::Result<Operator> {
    let directory = config_dir.join("operator");
    let deployment_id =
        read_operator_identity_line(&directory.join("deployment-id"), "deployment identity")?;
    let active_bytes = crate::filesystem::read_secure_regular_file(
        &directory.join("active-generation.json"),
        "active operator identity",
        true,
        16 * 1024,
    )?;
    let active: ActiveIdentityManifest =
        serde_json::from_slice(&active_bytes).context("active operator identity is invalid")?;
    validate_active_identity_manifest(&active)?;
    let receipt_key_id =
        read_operator_identity_line(&directory.join("receipt.kid"), "receipt key identity")?;
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

fn read_operator_identity_line(path: &Path, label: &str) -> anyhow::Result<String> {
    // These identifiers are public metadata, but still need descriptor-bound
    // reads so a symlink or path replacement cannot redirect configuration.
    let bytes = crate::filesystem::read_secure_regular_file(path, label, false, 256)?;
    let value = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("{label} is invalid");
    }
    Ok(value.to_owned())
}

fn validate_active_identity_manifest(active: &ActiveIdentityManifest) -> anyhow::Result<()> {
    if active.schema != 1
        || !valid_identity_component(&active.generation)
        || !valid_identity_component(&active.controller_key_id)
        || !valid_identity_component(&active.audit_key_id)
        || !valid_identity_component(&active.break_glass_key_id)
    {
        bail!("active operator identity is invalid");
    }
    Ok(())
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

pub(super) fn object_name_suffix(deployment_id: &str) -> String {
    let digest = Sha256::digest(deployment_id.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    format!("{:016x}", u64::from_be_bytes(prefix))
}

pub(super) fn mount(
    source: PathBuf,
    target: &str,
    read_only: bool,
    selinux_relabel: bool,
) -> Mount {
    Mount {
        source,
        target: PathBuf::from(target),
        read_only,
        selinux_relabel,
    }
}
