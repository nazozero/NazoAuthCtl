use super::*;

fn valid_config() -> UpdateConfig {
    let root = std::env::temp_dir().join("nazoauthctl-model-test");
    UpdateConfig {
        schema: 2,
        trust: crate::deployment::TrustState::Adopted,
        capabilities: crate::deployment::CapabilityGrants::controller_installed(),
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        backup_root: root.join("backups"),
        deployment_root: root.join("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: root.join("operator/controller.key"),
            controller_public_key: root.join("operator/controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: root.join("operator/receipt.key"),
            receipt_public_key: root.join("operator/receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: root.join("operator/audit.key"),
            audit_public_key: root.join("operator/audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: root.join("recovery/break-glass.key"),
            break_glass_public_key: root.join("operator/break-glass.pub"),
            active_identity_file: root.join("operator/active-generation.json"),
            identity_generations_directory: root.join("operator/generations"),
            recovery_generations_directory: root.join("recovery/generations"),
            secret_revision_file: root.join("operator/secret-revision"),
            state_directory: root.join("state"),
            audit_directory: root.join("audit"),
            trust_state_file: root.join("operator/release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: Runtime {
            backend: crate::deployment::RuntimeBackendKind::Systemd,
            dependency_backend: Some(crate::deployment::RuntimeBackendKind::Podman),
            backend_command_override: None,
            container_name: "nazoauth".to_owned(),
            runtime_instance_id: "runtime-test".to_owned(),
            network: "nazoauth-net".to_owned(),
            network_subnet: None,
            ip_address: String::new(),
            publish_address: "127.0.0.1:8000".to_owned(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: vec![Mount {
                source: root.join("config/.env.yaml"),
                target: root.join("mounted/.env.yaml"),
                read_only: true,
                selinux_relabel: false,
            }],
            snapshot_paths: vec![root.join("keys")],
            environment: BTreeMap::from([(
                "DATABASE_URL_FILE".to_owned(),
                root.join("secrets/database-url").display().to_string(),
            )]),
            service_name: "nazoauth".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: root.join("bin/nazoauth"),
            binary_releases: root.join("releases"),
            working_directory: root.join("config"),
        },
        postgres: Postgres {
            container_name: "nazoauth-postgres".to_owned(),
            database: "nazoauth".to_owned(),
            user: "nazoauth".to_owned(),
            image: "postgres:test".to_owned(),
            validation_image: "postgres:test".to_owned(),
        },
        valkey: Valkey {
            container_name: "nazoauth-valkey".to_owned(),
            data_volume: "nazoauth-valkey-data".to_owned(),
            image: "valkey:test".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: root.join("secrets/valkey-password"),
        },
        ui: Ui {
            releases_root: root.join("ui-releases"),
        },
    }
}

fn valid_manifest() -> ReleaseManifest {
    let target = release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let artifact = |name: String| Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name,
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 5,
        version: "v0.2.0".to_owned(),
        target: target.clone(),
        backend_commit: "b".repeat(40),
        release_identity: "release-identity".to_owned(),
        embedded: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.2.0".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        operator_protocol: Some(OperatorProtocolCompatibility {
            version: nazo_operator_protocol::PROTOCOL_VERSION,
            minimum_ctl_version: "0.1.19".to_owned(),
            maximum_ctl_version_exclusive: "0.2.0".to_owned(),
        }),
        artifacts: BTreeMap::from([(
            "binary".to_owned(),
            artifact(format!("nazoauth-{target}{suffix}")),
        )]),
        frontend: FrontendRelease {
            repository: "nazozero/NazoAuthWeb".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: "c".repeat(40),
            release_identity: "https://github.com/nazozero/NazoAuthWeb/.github/workflows/release.yml@refs/tags/v0.2.0".to_owned(),
            artifact: Artifact {
                repository: "nazozero/NazoAuthWeb".to_owned(),
                name: "nazoauth-web.tar.gz".to_owned(),
                sha256: "d".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "e".repeat(64)),
            platform_manifests: BTreeMap::from([
                ("linux/amd64".to_owned(), format!("sha256:{}", "1".repeat(64))),
                ("linux/arm64".to_owned(), format!("sha256:{}", "2".repeat(64))),
            ]),
        },
        rollback: Rollback {
            artifact: true,
            schema_compatible: true,
            database_restore: DatabaseRestore::Backup,
            irreversible_migration: false,
            minimum_supported_version: "0.1.2".to_owned(),
            migration_floor: "1".to_owned(),
            rationale: "compatible".to_owned(),
        },
    }
}

#[test]
fn semantic_versions_require_an_immutable_tag() {
    assert!(semantic_tag("v1.2.3"));
    assert!(semantic_tag("v1.2.3-rc.1"));
    assert!(!semantic_tag("latest"));
    assert!(!semantic_tag("v1.2"));
    assert!(!semantic_tag("1.2.3"));
}

#[test]
fn environment_keys_are_strict() {
    assert!(valid_environment_key("DATABASE_URL_FILE"));
    assert!(!valid_environment_key("database_url"));
    assert!(!valid_environment_key("BAD-VALUE"));
}

#[test]
fn runtime_environment_requires_normalized_file_locators() {
    let mut inline_secret = valid_config();
    inline_secret.runtime.environment.insert(
        "DATABASE_URL".to_owned(),
        "/run/secrets/database-url".to_owned(),
    );
    assert!(
        inline_secret.validate().is_err(),
        "runtime environment must not carry inline secret values"
    );

    let mut relative_locator = valid_config();
    relative_locator
        .runtime
        .environment
        .insert("DATABASE_URL_FILE".to_owned(), "../database-url".to_owned());
    assert!(
        relative_locator.validate().is_err(),
        "secret locators must be normalized absolute paths"
    );

    let mut valid_locator = valid_config();
    let valid_path = std::path::PathBuf::from(
        valid_locator
            .runtime
            .environment
            .get("DATABASE_URL_FILE")
            .expect("baseline fixture should contain a file locator"),
    );
    valid_locator.runtime.environment.insert(
        "VALKEY_URL_FILE".to_owned(),
        valid_path
            .parent()
            .expect("baseline locator should have a parent")
            .join("valkey-url")
            .display()
            .to_string(),
    );
    valid_locator
        .validate()
        .expect("normalized *_FILE locators should remain valid");

    let mut exact_identity = valid_config();
    exact_identity.runtime.environment.extend([
        (
            "DEPLOYMENT_ID".to_owned(),
            exact_identity.operator.deployment_id.clone(),
        ),
        (
            "RUNTIME_INSTANCE_ID".to_owned(),
            exact_identity.runtime.runtime_instance_id.clone(),
        ),
    ]);
    exact_identity
        .validate()
        .expect("exact persisted runtime identity bindings should remain valid");

    let mut drifted_identity = exact_identity;
    drifted_identity.runtime.environment.insert(
        "RUNTIME_INSTANCE_ID".to_owned(),
        "runtime-substitution".to_owned(),
    );
    assert!(
        drifted_identity.validate().is_err(),
        "runtime identity environment must not drift from persisted authority"
    );
}

#[test]
fn update_config_accepts_only_closed_safe_runtime_boundaries() {
    let config = valid_config();
    config.validate().unwrap();
    assert_eq!(
        config.container_backend(),
        Some(crate::deployment::RuntimeBackendKind::Podman)
    );
    UpdateConfig::parse(&serde_json::to_vec(&config).unwrap()).unwrap();

    let mut invalid = config.clone();
    invalid.schema = 1;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.install_profile = "custom".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.repository = "unsafe".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.dependencies.mode = "shared".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.backend = crate::deployment::RuntimeBackendKind::Podman;
    invalid.runtime.container_name = "bad/name".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.operator.controller_key_id = "bad key".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.service_name.clear();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.service_user = "unsafe/user".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.readiness_attempts = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.environment = BTreeMap::from([(
        "DATABASE_URL".to_owned(),
        config.backup_root.display().to_string(),
    )]);
    assert!(invalid.validate().is_err());
    assert!(UpdateConfig::parse(b"not-json").is_err());
}

#[test]
fn public_runtime_urls_are_same_origin_and_never_remote_plaintext() {
    let mut config = valid_config();
    config.validate().unwrap();

    for issuer in [
        "http://auth.example",
        "http://10.0.0.8:8000",
        "https://user@auth.example",
        "https://auth.example/issuer",
        "https://auth.example?tenant=one",
    ] {
        let mut invalid = config.clone();
        invalid.runtime.expected_issuer = issuer.to_owned();
        assert!(invalid.validate().is_err(), "accepted issuer {issuer}");
    }

    for discovery in [
        "http://auth.example/.well-known/openid-configuration",
        "https://other.example/.well-known/openid-configuration",
        "https://auth.example/.well-known/openid-configuration?tenant=one",
        "https://auth.example/redirect",
    ] {
        let mut invalid = config.clone();
        invalid.runtime.public_discovery_url = discovery.to_owned();
        assert!(
            invalid.validate().is_err(),
            "accepted public Discovery URL {discovery}"
        );
    }

    for health in [
        "ftp://127.0.0.1:8000/ready",
        "http://127.0.0.1:8000/ready?probe=secret",
        "http://user:password@127.0.0.1:8000/ready",
        "https://other.example/ready",
        "http://10.0.0.8:8000/ready",
    ] {
        let mut invalid = config.clone();
        invalid.runtime.health_url = health.to_owned();
        assert!(invalid.validate().is_err(), "accepted health URL {health}");
    }

    config.runtime.health_url = "https://auth.example/ready".to_owned();
    config.validate().unwrap();

    config.runtime.expected_issuer = "http://127.0.0.1:8000".to_owned();
    config.runtime.health_url = "http://127.0.0.1:8000/ready".to_owned();
    config.runtime.public_discovery_url =
        "http://127.0.0.1:8000/.well-known/openid-configuration".to_owned();
    config.validate().unwrap();
}

#[test]
fn external_and_container_dependency_modes_resolve_explicitly() {
    let mut config = valid_config();
    config.runtime.backend = crate::deployment::RuntimeBackendKind::Docker;
    config.schema = 3;
    config.runtime.service_name.clear();
    config.runtime.service_user.clear();
    config.dependencies.mode = "external".to_owned();
    let root = std::env::temp_dir().join("nazoauthctl-external-model-test");
    config.dependencies.database_url_file = root.join("database-url");
    config.dependencies.migration_database_url_file = root.join("migration-database-url");
    config.dependencies.database_backup_url_file = root.join("database-backup-url");
    config.dependencies.valkey_url_file = root.join("valkey-url");
    config.dependencies.valkey_backup_url_file = root.join("valkey-backup-url");
    config.dependencies.external_valkey_backup_scope = "dedicated-instance".to_owned();
    config.dependencies.database_runtime_endpoint_sha256 = "a".repeat(64);
    config.dependencies.migration_database_endpoint_sha256 = "b".repeat(64);
    config.dependencies.database_backup_endpoint_sha256 = "a".repeat(64);
    config.dependencies.valkey_backup_endpoint_sha256 = "b".repeat(64);
    config.validate().unwrap();
    assert_eq!(
        config.container_backend(),
        Some(crate::deployment::RuntimeBackendKind::Docker)
    );

    config.dependencies.database_url_file = "relative".into();
    assert!(config.validate().is_err());
    assert!(safe_absolute(std::path::Path::new("relative")).is_err());
    assert!(safe_absolute(std::path::Path::new(&std::path::MAIN_SEPARATOR.to_string())).is_err());
    assert!(safe_absolute(std::path::Path::new("/var/lib/../nazoauthctl")).is_err());
}

#[test]
fn schema_two_keeps_managed_configs_readable_but_rejects_legacy_external_credentials() {
    let managed = valid_config();
    let mut managed_json = serde_json::to_value(&managed).unwrap();
    let dependencies = managed_json
        .get_mut("dependencies")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap();
    dependencies.remove("database_backup_url_file");
    dependencies.remove("valkey_backup_url_file");
    dependencies.remove("external_valkey_backup_scope");
    dependencies.remove("database_runtime_endpoint_sha256");
    dependencies.remove("migration_database_endpoint_sha256");
    dependencies.remove("database_backup_endpoint_sha256");
    dependencies.remove("valkey_backup_endpoint_sha256");
    let managed_legacy: UpdateConfig = serde_json::from_value(managed_json.clone()).unwrap();
    managed_legacy.validate().unwrap();

    managed_json["dependencies"]["mode"] = serde_json::Value::String("external".to_owned());
    let external_legacy: UpdateConfig = serde_json::from_value(managed_json).unwrap();
    let error = external_legacy.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("external dependencies require update config schema 3")
    );

    let mut external = valid_config();
    external.schema = 3;
    external.runtime.backend = crate::deployment::RuntimeBackendKind::Docker;
    external.runtime.service_name.clear();
    external.runtime.service_user.clear();
    external.dependencies.mode = "external".to_owned();
    let root = std::env::temp_dir().join("nazoauthctl-legacy-external-schema-three");
    external.dependencies.database_url_file = root.join("database-url");
    external.dependencies.migration_database_url_file = root.join("migration-database-url");
    external.dependencies.database_backup_url_file = root.join("database-backup-url");
    external.dependencies.valkey_url_file = root.join("valkey-url");
    external.dependencies.valkey_backup_url_file = root.join("valkey-backup-url");
    external.dependencies.external_valkey_backup_scope = "dedicated-instance".to_owned();
    external.dependencies.database_runtime_endpoint_sha256 = "a".repeat(64);
    external.dependencies.migration_database_endpoint_sha256 = "b".repeat(64);
    external.dependencies.database_backup_endpoint_sha256 = "c".repeat(64);
    external.dependencies.valkey_backup_endpoint_sha256 = "d".repeat(64);
    let mut legacy_external = serde_json::to_value(&external).unwrap();
    let dependencies = legacy_external["dependencies"].as_object_mut().unwrap();
    dependencies.remove("database_runtime_endpoint_sha256");
    dependencies.remove("migration_database_endpoint_sha256");
    dependencies.remove("database_backup_endpoint_sha256");
    dependencies.remove("valkey_backup_endpoint_sha256");
    let legacy_external: UpdateConfig = serde_json::from_value(legacy_external).unwrap();
    assert!(
        legacy_external
            .validate()
            .unwrap_err()
            .to_string()
            .contains("external PostgreSQL runtime endpoint identity")
    );
}

#[test]
fn systemd_runtime_paths_reject_unit_injection_boundaries() {
    for (field, value) in [
        ("binary_path", "/opt/nazoauth%releases/nazoauth"),
        (
            "binary_releases",
            "/opt/nazoauth/releases\r\nEnvironment=BAD=1",
        ),
        ("working_directory", "/opt/nazoauth\\quoted"),
        ("working_directory", "/opt/nazo auth"),
        ("binary_path", "/opt/nazoauth\0server"),
    ] {
        let mut config = valid_config();
        match field {
            "binary_path" => config.runtime.binary_path = value.into(),
            "binary_releases" => config.runtime.binary_releases = value.into(),
            "working_directory" => config.runtime.working_directory = value.into(),
            _ => unreachable!(),
        }
        assert!(config.validate().is_err(), "{field}={value:?}");
    }
}

#[test]
fn release_manifest_binds_every_binary_frontend_and_oci_identity() {
    let manifest = valid_manifest();
    manifest.validate("v0.2.0", "release-identity").unwrap();
    assert_eq!(
        manifest.image_oci_digest(),
        format!("sha256:{}", "e".repeat(64))
    );
    assert_eq!(manifest.frontend_commit(), "c".repeat(40));

    if cfg!(target_os = "linux") {
        assert!(
            manifest
                .image_ref()
                .unwrap()
                .starts_with("ghcr.io/nazozero/nazoauth@sha256:")
        );
        assert!(manifest.runtime_oci_digest().is_ok());
    } else {
        assert!(manifest.image_ref().is_err());
        assert!(manifest.runtime_oci_digest().is_err());
    }

    let mut invalid = manifest.clone();
    invalid.rollback.irreversible_migration = true;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.rollback.artifact = false;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.insert(
        "updater".to_owned(),
        Artifact {
            repository: "nazozero/NazoAuth".to_owned(),
            name: "nazoauthctl-unexpected".to_owned(),
            sha256: "a".repeat(64),
            size: 1,
        },
    );
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().name = "nazoauth-wrong-target".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().size = 0;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.frontend.artifact.name = "index.html".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.oci.platform_manifests.remove("linux/arm64");
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
}

#[test]
fn platform_mapping_is_total_over_every_published_release_target() {
    assert_eq!(executable_suffix("x86_64-pc-windows-msvc"), ".exe");
    assert_eq!(executable_suffix("x86_64-unknown-linux-gnu"), "");
    assert_eq!(
        runtime_oci_platform("linux", "x86_64").unwrap(),
        "linux/amd64"
    );
    assert_eq!(
        runtime_oci_platform("linux", "aarch64").unwrap(),
        "linux/arm64"
    );
    assert!(runtime_oci_platform("windows", "x86_64").is_err());

    for (arch, os, env, expected) in [
        ("x86_64", "linux", "musl", Some("x86_64-unknown-linux-musl")),
        (
            "aarch64",
            "linux",
            "musl",
            Some("aarch64-unknown-linux-musl"),
        ),
        ("x86_64", "linux", "gnu", Some("x86_64-unknown-linux-gnu")),
        ("aarch64", "linux", "gnu", Some("aarch64-unknown-linux-gnu")),
        ("x86_64", "windows", "msvc", Some("x86_64-pc-windows-msvc")),
        (
            "aarch64",
            "windows",
            "msvc",
            Some("aarch64-pc-windows-msvc"),
        ),
        ("x86_64", "macos", "", Some("x86_64-apple-darwin")),
        ("aarch64", "macos", "", Some("aarch64-apple-darwin")),
        ("wasm32", "unknown", "", None),
    ] {
        assert_eq!(release_target_for(arch, os, env), expected);
    }
}
