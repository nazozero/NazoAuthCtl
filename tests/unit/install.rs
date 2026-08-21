use std::fs;

use super::*;
use crate::filesystem::PrivateTempDir;
#[cfg(unix)]
use crate::test_support::write_shell_executable;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

fn set_server_config_fixture_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
    #[cfg(not(unix))]
    let _ = path;
}

fn install_options(data_root: PathBuf) -> InstallOptions {
    let control_root = data_root.with_file_name("control");
    let recovery_root = data_root.with_file_name("recovery");
    InstallOptions {
        runtime: "podman".to_owned(),
        public_url: "https://auth.example".to_owned(),
        profile: "baseline".to_owned(),
        profile_material: None,
        trusted_proxy_cidr: None,
        data_root,
        control_root,
        recovery_root,
        port: 8000,
        network_subnet: None,
        runtime_ip: None,
        database_url: None,
        migration_database_url: None,
        database_backup_url: None,
        valkey_url: None,
        valkey_backup_url: None,
        external_valkey_backup_scope: None,
        database_runtime_endpoint_sha256: None,
        migration_database_endpoint_sha256: None,
        database_backup_endpoint_sha256: None,
        valkey_backup_endpoint_sha256: None,
        external_dependencies: false,
        secrets_stdin: false,
        secret_fd: None,
        profile_secrets_stdin: false,
        profile_secret_fd: None,
        profile_secrets: None,
        version: Some("v0.2.0".to_owned()),
        local_oci_candidate: None,
    }
}

fn bind_external_dependency_fixture(options: &mut InstallOptions) {
    let binding = crate::secret_provider::bind_external_dependency_credentials(
        "postgresql://runtime:runtime-secret@db.example/oauth?sslmode=require",
        "postgresql://migrator:migration-secret@db.example/oauth",
        "postgresql://backup:backup-secret@db.example/oauth?sslmode=require",
        "rediss://runtime:runtime-secret@cache.example/0",
        "rediss://backup:backup-secret@cache.example/0",
    )
    .unwrap();
    options.external_valkey_backup_scope = Some("dedicated-instance".to_owned());
    options.database_runtime_endpoint_sha256 = Some(binding.database_runtime_endpoint_sha256);
    options.migration_database_endpoint_sha256 = Some(binding.migration_database_endpoint_sha256);
    options.database_backup_endpoint_sha256 = Some(binding.database_endpoint_sha256);
    options.valkey_backup_endpoint_sha256 = Some(binding.valkey_endpoint_sha256);
}

#[cfg(unix)]
#[test]
fn container_operator_state_is_private_and_owned_by_the_runtime_identity() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("operator-state-ownership").unwrap();
    let state = work.path().join("operator-state");
    let command = work.path().join("fake-chown");
    let arguments = work.path().join("arguments");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    write_shell_executable(
        &command,
        &format!("printf '%s\\n' \"$*\" > '{}'", arguments.display()),
    );

    configure_container_operator_state_permissions(command.as_os_str(), &state).unwrap();

    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::read_to_string(arguments).unwrap().trim(),
        format!("10001:10001 {}", state.display())
    );

    let symlink = work.path().join("operator-state-link");
    std::os::unix::fs::symlink(&state, &symlink).unwrap();
    assert!(configure_container_operator_state_permissions(command.as_os_str(), &symlink).is_err());
}

#[test]
fn public_origin_rejects_embedded_credentials() {
    for value in [
        "https://operator@auth.example",
        "https://operator:secret@auth.example",
    ] {
        let error = validate_public_url(value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--public-url must be an absolute HTTP(S) origin"),
            "unexpected error for {value}: {error:#}"
        );
    }
}

#[test]
fn managed_dependency_credentials_are_outside_runtime_secret_directory() {
    let work = PrivateTempDir::new("managed-secret-boundaries").unwrap();
    let secrets = work.path().join("secrets");
    fs::create_dir(&secrets).unwrap();

    assert_eq!(
        write_managed_secrets(&secrets, "example-postgres", "example-valkey").unwrap(),
        "managed"
    );

    let dependencies = secrets.join("dependencies");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&dependencies).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for name in [
        "postgres-password",
        "postgres-runtime-password",
        "valkey-password",
        "valkey-backup-password",
        "valkey.acl",
    ] {
        assert!(dependencies.join(name).is_file());
        assert!(!secrets.join(name).exists());
    }
    for name in ["database-url", "database-migration-url", "valkey-url"] {
        assert!(secrets.join(name).is_file());
    }

    let runtime_url = fs::read_to_string(secrets.join("database-url")).unwrap();
    let migration_url = fs::read_to_string(secrets.join("database-migration-url")).unwrap();
    assert!(runtime_url.contains("nazoauth_runtime"));
    assert!(migration_url.contains("nazoauth_migrator"));
    assert!(runtime_url.contains("example-postgres"));
    assert!(
        fs::read_to_string(secrets.join("valkey-url"))
            .unwrap()
            .contains("example-valkey")
    );
    assert_ne!(runtime_url, migration_url);
    let valkey_acl = fs::read_to_string(dependencies.join("valkey.acl")).unwrap();
    let mut valkey_acl_lines = valkey_acl.lines();
    assert_eq!(valkey_acl_lines.next(), Some("user default off"));
    let runtime_acl = valkey_acl_lines.next().unwrap();
    assert!(runtime_acl.starts_with("user nazoauth_runtime on"));
    assert!(
        runtime_acl
            .split_whitespace()
            .any(|token| token == "+dbsize")
    );
    for forbidden in [
        "+flushall",
        "+flushdb",
        "+config",
        "+acl",
        "@all",
        "allcommands",
    ] {
        assert!(
            !runtime_acl
                .split_whitespace()
                .any(|token| token == forbidden)
        );
    }
    let backup_acl = valkey_acl_lines.next().unwrap();
    assert!(backup_acl.starts_with("user nazoauth_backup on"));
    assert!(backup_acl.ends_with("~* +ping +lastsave +bgsave"));
    assert_eq!(valkey_acl_lines.next(), None);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(dependencies.join("valkey.acl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );

    fs::remove_file(dependencies.join("valkey-backup-password")).unwrap();
    crate::filesystem::atomic_write(
        &dependencies.join("valkey.acl"),
        b"user default off\nuser nazoauth_runtime on >legacy ~* +get\n",
        0o444,
    )
    .unwrap();
    write_managed_secrets(&secrets, "example-postgres", "example-valkey").unwrap();
    assert!(dependencies.join("valkey-backup-password").is_file());
    let reconciled_acl = fs::read_to_string(dependencies.join("valkey.acl")).unwrap();
    assert!(reconciled_acl.contains("user nazoauth_backup on"));
    assert!(!reconciled_acl.contains(">legacy"));
}

#[test]
fn systemd_version_parser_is_closed() {
    assert_eq!(
        crate::runtime_backend::parse_systemd_version("systemd 252 (252.39-1)\n+PAM").unwrap(),
        252
    );
    assert!(crate::runtime_backend::parse_systemd_version("252\n").is_err());
    assert!(crate::runtime_backend::parse_systemd_version("systemd unknown\n").is_err());
}

#[test]
fn managed_object_locators_hash_the_complete_deployment_identity() {
    let first = object_name_suffix("019a-identical-prefix-deployment-a");
    let second = object_name_suffix("019a-identical-prefix-deployment-b");
    assert_eq!(first.len(), 16);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first, second);
}

#[test]
fn generated_install_paths_are_safe_for_yaml_systemd_and_container_mounts() {
    validate_install_path(Path::new("/var/lib/nazoauth-0.2/app_data"), "data root").unwrap();
    for path in [
        "/var/lib/nazo auth",
        "/var/lib/nazoauth\nINJECTED: true",
        "/var/lib/nazoauth:other",
        "/var/lib/nazoauth\"",
    ] {
        assert!(validate_install_path(Path::new(path), "data root").is_err());
    }
}

#[test]
fn host_service_unit_exposes_only_runtime_state() {
    let unit = crate::runtime_backend::render_host_service_unit(
        &crate::runtime_backend::HostServiceInstall {
            service_name: "nazoauth.service".to_owned(),
            deployment_id: "deployment-test".to_owned(),
            runtime_instance_id: "runtime-test".to_owned(),
            control_authority: "authority-test".to_owned(),
            service_user: "nazoauth".to_owned(),
            working_directory: PathBuf::from("/etc/nazoauth"),
            binary: PathBuf::from("/usr/local/bin/nazoauth"),
            app_root: PathBuf::from("/var/lib/nazoauth/app"),
            ui_releases: PathBuf::from("/var/lib/nazoauth/ui-releases"),
            operator_state: PathBuf::from("/var/lib/nazoauth/app/operator-state"),
            operator_directory: PathBuf::from("/etc/nazoauth/operator"),
            recovery_directory: PathBuf::from("/var/lib/nazoauth/recovery"),
            migration_url: PathBuf::from("/etc/nazoauth/secrets/database-migration-url"),
            restricted_secret_paths: vec![
                PathBuf::from("/etc/nazoauth/secrets/database-backup-url"),
                PathBuf::from("/etc/nazoauth/secrets/valkey-backup-url"),
            ],
            receipt_private_key: PathBuf::from("/etc/nazoauth/operator/receipt.key"),
            runtime_readable_secret_names: Vec::new(),
        },
    )
    .unwrap()
    .replace('\\', "/");

    assert!(unit.contains("User=nazoauth\nGroup=nazoauth"));
    assert!(unit.contains("Environment=DATA_DIR=/var/lib/nazoauth/app"));
    assert!(unit.contains("Environment=INSTANCE_IDENTITY_DIR=/var/lib/nazoauth/app/instance"));
    assert!(unit.contains(
        "ReadWritePaths=/var/lib/nazoauth/app/keys /var/lib/nazoauth/app/avatars /var/lib/nazoauth/app/secrets /var/lib/nazoauth/app/bootstrap /var/lib/nazoauth/app/instance /var/lib/nazoauth/ui-releases"
    ));
    assert!(!unit.contains("ReadOnlyPaths=/var/lib/nazoauth/ui-releases"));
    assert!(unit.contains(
        "InaccessiblePaths=/var/lib/nazoauth/app/operator-state /etc/nazoauth/operator /var/lib/nazoauth/recovery /etc/nazoauth/secrets/database-migration-url /etc/nazoauth/secrets/database-backup-url /etc/nazoauth/secrets/valkey-backup-url"
    ));
    assert!(!unit.contains("ReadWritePaths=/etc/nazoauth/secrets"));
    assert!(!unit.contains("ReadWritePaths=/var/lib/nazoauth/app\n"));
}

#[test]
fn oidf_profile_material_generates_only_file_references_for_secrets() {
    let work = PrivateTempDir::new("oidf-install-profile").unwrap();
    let config = work.path().join("config");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
    let material = work.path().join("profile.json");
    fs::write(
        &material,
        serde_json::to_vec(&serde_json::json!({
            "client_attestation_issuer": "https://attester.example/",
            "client_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "key_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "credential_configurations": {"example":{"format":"dc+sd-jwt","scope":"example"}},
            "wallet_authorization_origins": ["https://suite.example"],
            "ciba_notification_private_origins": ["https://suite.example"],
            "backchannel_logout_private_origins": ["https://suite.example"]
        }))
        .unwrap(),
    )
    .unwrap();
    let options = InstallOptions {
        runtime: "podman".to_owned(),
        public_url: "https://auth.example".to_owned(),
        profile: "standards-full".to_owned(),
        profile_material: Some(material),
        trusted_proxy_cidr: Some("192.0.2.10/32".to_owned()),
        data_root: work.path().join("data"),
        control_root: work.path().join("control"),
        recovery_root: work.path().join("recovery"),
        port: 8000,
        network_subnet: None,
        runtime_ip: None,
        database_url: None,
        migration_database_url: None,
        database_backup_url: None,
        valkey_url: None,
        valkey_backup_url: None,
        external_valkey_backup_scope: None,
        database_runtime_endpoint_sha256: None,
        migration_database_endpoint_sha256: None,
        database_backup_endpoint_sha256: None,
        valkey_backup_endpoint_sha256: None,
        external_dependencies: false,
        secrets_stdin: false,
        secret_fd: None,
        profile_secrets_stdin: false,
        profile_secret_fd: None,
        profile_secrets: None,
        version: Some("v1.2.3".to_owned()),
        local_oci_candidate: None,
    };

    let rendered = write_install_profile(&config, &options).unwrap().unwrap();

    for name in STANDARDS_PROFILE_SECRET_NAMES {
        let value = fs::read_to_string(config.join("secrets").join(name)).unwrap();
        if *name != "openid4vc-data-encryption-key" {
            assert!(value.len() >= MIN_PROFILE_SECRET_VALUE_BYTES);
        }
        assert!(!rendered.contains(&value));
        if *name != "ciba-decision-token" {
            assert!(rendered.contains(&format!("${{PROFILE_SECRET_ROOT}}/{name}")));
        }
    }
    assert!(rendered.contains("ENABLE_OPENID4VCI_ISSUER: true"));
    assert!(rendered.contains("ENABLE_OPENID4VP_VERIFIER: true"));
    assert!(rendered.contains("TRUSTED_PROXY_CIDRS: \"${TRUSTED_PROXY_CIDR}\""));
    assert!(rendered.contains("MTLS_CERTIFICATE_SOURCE: \"rfc9440\""));
    assert!(!rendered.contains("legacy-verified-headers"));
    assert!(rendered.contains("OPENID4VC_REVOCATION_POLICY: \"required\""));
    assert!(rendered.contains(
        "OPENID4VC_REVOCATION_SNAPSHOT_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-revocation-snapshot.json\""
    ));
    assert_eq!(
        rendered.matches("openid4vc-certificate-bundle.pem").count(),
        2
    );
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn oidf_profile_secret_override_is_strict_private_and_resumable() {
    let work = PrivateTempDir::new("oidf-install-profile-secret-override").unwrap();
    let config = work.path().join("config");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
    let material = work.path().join("profile.json");
    fs::write(
        &material,
        serde_json::to_vec(&serde_json::json!({
            "client_attestation_issuer": "https://attester.example/",
            "client_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "key_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "credential_configurations": {"example":{"format":"dc+sd-jwt","scope":"example"}},
            "wallet_authorization_origins": ["https://suite.example"],
            "ciba_notification_private_origins": ["https://suite.example"],
            "backchannel_logout_private_origins": ["https://suite.example"]
        }))
        .unwrap(),
    )
    .unwrap();
    let canary = "x".repeat(32);
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    options.profile_material = Some(material);
    options.profile_secrets = Some(StandardsProfileSecrets {
        dynamic_registration_initial_access_token: format!("dynamic-{canary}"),
        ciba_automated_decision_token: format!("ciba-{canary}"),
        openid4vci_management_token: format!("issuer-{canary}"),
        openid4vp_management_token: format!("verifier-{canary}"),
    });

    let rendered = write_install_profile(&config, &options).unwrap().unwrap();
    assert!(!rendered.contains(&canary));
    assert_eq!(
        fs::read_to_string(config.join("secrets/dynamic-registration-token")).unwrap(),
        format!("dynamic-{canary}")
    );
    assert_eq!(
        fs::read_to_string(config.join("secrets/openid4vp-management-token")).unwrap(),
        format!("verifier-{canary}")
    );
    assert!(write_install_profile(&config, &options).is_ok());

    let mut mismatched = install_options(work.path().join("data"));
    mismatched.profile = "standards-full".to_owned();
    mismatched.profile_material = options.profile_material.clone();
    mismatched.profile_secrets = Some(StandardsProfileSecrets {
        dynamic_registration_initial_access_token: "other-secret-value-that-is-at-least-32"
            .to_owned(),
        ciba_automated_decision_token: format!("ciba-{canary}"),
        openid4vci_management_token: format!("issuer-{canary}"),
        openid4vp_management_token: format!("verifier-{canary}"),
    });
    let error = write_install_profile(&config, &mismatched).unwrap_err();
    assert!(!format!("{error:#}").contains(&canary));
}

#[cfg(unix)]
#[test]
fn persisted_profile_secret_descriptor_rejects_symlink_unsafe_mode_and_oversize_inputs() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("profile-secret-descriptor-boundaries").unwrap();
    let path = work.path().join("profile-secret");
    let value = "x".repeat(32);
    fs::write(&path, &value).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        load_profile_secret(&path, "test profile secret", 32)
            .unwrap()
            .as_str(),
        value
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(load_profile_secret(&path, "test profile secret", 32).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, vec![b'x'; 33]).unwrap();
    assert!(load_profile_secret(&path, "test profile secret", 32).is_err());

    let decoy = work.path().join("profile-secret-decoy");
    fs::write(&decoy, &value).unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o400)).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&decoy, &path).unwrap();
    assert!(load_profile_secret(&path, "test profile secret", 32).is_err());
}

#[cfg(unix)]
#[test]
fn operator_identity_descriptor_rejects_symlink_private_mode_and_oversize_inputs() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("operator-identity-descriptor-boundaries").unwrap();
    let config_dir = work.path().join("config");
    let operator_dir = config_dir.join("operator");
    fs::create_dir_all(&operator_dir).unwrap();
    let deployment_id = operator_dir.join("deployment-id");
    fs::write(&deployment_id, b"deployment-test").unwrap();
    fs::set_permissions(&deployment_id, fs::Permissions::from_mode(0o644)).unwrap();
    let active = operator_dir.join("active-generation.json");
    fs::write(
        &active,
        serde_json::json!({
            "schema": 1,
            "generation": "generation-test",
            "controller_key_id": "controller-test",
            "audit_key_id": "audit-test",
            "break_glass_key_id": "break-glass-test"
        })
        .to_string(),
    )
    .unwrap();
    fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
    let receipt_kid = operator_dir.join("receipt.kid");
    fs::write(&receipt_kid, b"receipt-test").unwrap();
    fs::set_permissions(&receipt_kid, fs::Permissions::from_mode(0o444)).unwrap();

    let operator = operator_config(
        &config_dir,
        &work.path().join("control"),
        &work.path().join("recovery"),
    )
    .unwrap();
    assert_eq!(operator.deployment_id, "deployment-test");
    assert_eq!(operator.receipt_key_id, "receipt-test");

    fs::set_permissions(&active, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        operator_config(
            &config_dir,
            &work.path().join("control"),
            &work.path().join("recovery"),
        )
        .is_err()
    );
    fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();

    let decoy = operator_dir.join("deployment-decoy");
    fs::write(&decoy, b"deployment-test").unwrap();
    fs::remove_file(&deployment_id).unwrap();
    symlink(&decoy, &deployment_id).unwrap();
    assert!(
        operator_config(
            &config_dir,
            &work.path().join("control"),
            &work.path().join("recovery"),
        )
        .is_err()
    );
    fs::remove_file(&deployment_id).unwrap();
    fs::write(&deployment_id, b"deployment-test").unwrap();
    fs::set_permissions(&deployment_id, fs::Permissions::from_mode(0o644)).unwrap();

    fs::write(&active, vec![b'x'; 16 * 1024 + 1]).unwrap();
    fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        operator_config(
            &config_dir,
            &work.path().join("control"),
            &work.path().join("recovery"),
        )
        .is_err()
    );
}

#[test]
fn profile_secret_input_is_closed_bounded_and_never_echoed() {
    let work = PrivateTempDir::new("profile-secret-input").unwrap();
    let canary = "profile-secret-canary-that-is-long-enough";
    let valid = serde_json::json!({
        "dynamic_registration_initial_access_token": canary,
        "ciba_automated_decision_token": canary,
        "openid4vci_management_token": canary,
        "openid4vp_management_token": canary,
    });
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    read_profile_secrets(
        &mut options,
        std::io::Cursor::new(serde_json::to_vec(&valid).unwrap()),
    )
    .unwrap();
    assert_eq!(
        options
            .profile_secrets
            .as_ref()
            .unwrap()
            .openid4vci_management_token,
        canary
    );

    for invalid in [
        br#"{"dynamic_registration_initial_access_token":"profile-secret-canary-that-is-long-enough","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough","unexpected":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
        br#"{"dynamic_registration_initial_access_token":"short","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
        br#"{"dynamic_registration_initial_access_token":"profile-secret-canary-that-is-long-enough\n","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
    ] {
        let mut options = install_options(work.path().join("invalid-data"));
        let error = read_profile_secrets(&mut options, std::io::Cursor::new(invalid)).unwrap_err();
        assert!(!format!("{error:#}").contains("profile-secret-canary"));
        assert!(options.profile_secrets.is_none());
    }

    let mut oversized = install_options(work.path().join("oversized-data"));
    let error = read_profile_secrets(
        &mut oversized,
        std::io::Cursor::new(vec![b' '; 32 * 1024 + 1]),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "profile secret input exceeds 32 KiB");
}

#[test]
fn profile_secret_channels_fail_closed_without_consuming_ambiguous_stdin() {
    let work = PrivateTempDir::new("profile-secret-channels").unwrap();
    let mut stdin_conflict = install_options(work.path().join("stdin-conflict"));
    stdin_conflict.profile = "standards-full".to_owned();
    stdin_conflict.secrets_stdin = true;
    stdin_conflict.profile_secrets_stdin = true;
    assert_eq!(
        normalize_profile_secrets(&mut stdin_conflict)
            .unwrap_err()
            .to_string(),
        "--secrets-stdin and --profile-secrets-stdin both consume stdin; use separate FDs instead"
    );

    let mut fd_conflict = install_options(work.path().join("fd-conflict"));
    fd_conflict.profile = "standards-full".to_owned();
    fd_conflict.secret_fd = Some(7);
    fd_conflict.profile_secret_fd = Some(7);
    assert_eq!(
        normalize_profile_secrets(&mut fd_conflict)
            .unwrap_err()
            .to_string(),
        "--secret-fd and --profile-secret-fd must use different FDs"
    );

    let mut baseline = install_options(work.path().join("baseline"));
    baseline.profile_secrets_stdin = true;
    assert_eq!(
        normalize_profile_secrets(&mut baseline)
            .unwrap_err()
            .to_string(),
        "secure profile secret input requires --profile standards-full"
    );

    let mut duplicate_profile_channel = install_options(work.path().to_owned());
    duplicate_profile_channel.profile = "standards-full".to_owned();
    duplicate_profile_channel.profile_secrets_stdin = true;
    duplicate_profile_channel.profile_secret_fd = Some(8);
    assert_eq!(
        normalize_profile_secrets(&mut duplicate_profile_channel)
            .unwrap_err()
            .to_string(),
        "choose exactly one of --profile-secrets-stdin or --profile-secret-fd"
    );
}

#[test]
fn oidf_profile_rejects_legacy_external_openid4vc_trust_anchors() {
    let work = PrivateTempDir::new("oidf-install-profile-legacy-anchor").unwrap();
    let config = work.path().join("config");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
    let material = work.path().join("profile.json");
    fs::write(
        &material,
        serde_json::to_vec(&serde_json::json!({
            "client_attestation_issuer": "https://attester.example/",
            "client_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "key_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "credential_configurations": {"example":{"format":"dc+sd-jwt","scope":"example"}},
            "wallet_authorization_origins": ["https://suite.example"],
            "ciba_notification_private_origins": ["https://suite.example"],
            "backchannel_logout_private_origins": ["https://suite.example"],
            "trust_anchors_pem": "-----BEGIN CERTIFICATE-----\\nlegacy\\n-----END CERTIFICATE-----\\n"
        }))
        .unwrap(),
    )
    .unwrap();
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    options.profile_material = Some(material);

    let error = write_install_profile(&config, &options).unwrap_err();
    assert!(error.to_string().contains("strict JSON"));
}

#[test]
fn oidf_profile_rejects_private_jwk_material() {
    assert!(
        validate_public_jwks(
            &serde_json::json!({"keys":[{"kty":"EC","d":"private"}]}),
            "test JWKS"
        )
        .is_err()
    );
}

#[test]
fn oidf_profile_origins_are_strict_https_origins() {
    for accepted in ["https://suite.example", "https://suite.example:8443/"] {
        validate_https_origin(accepted, "suite origin").unwrap();
    }
    for rejected in [
        "http://suite.example",
        "https://user@suite.example",
        "https://suite.example/path",
        "https://suite.example?query=1",
        "https://suite.example/#fragment",
    ] {
        assert!(
            validate_https_origin(rejected, "suite origin").is_err(),
            "accepted invalid origin {rejected}"
        );
    }
}

#[test]
fn trusted_proxy_requires_a_single_host_cidr() {
    assert_eq!(
        normalize_single_host_cidr("10.89.0.1/32").unwrap(),
        "10.89.0.1/32"
    );
    assert_eq!(
        normalize_single_host_cidr("fd00::1/128").unwrap(),
        "fd00::1/128"
    );
    for value in ["10.89.0.0/24", "0.0.0.0/0", "fd00::/64", "not-a-cidr"] {
        assert!(
            normalize_single_host_cidr(value).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn standards_full_public_origin_rejects_non_loopback_http() {
    assert!(normalize_public_url_for_profile("https://auth.example", "standards-full").is_ok());
    for value in ["http://auth.example", "http://10.0.0.7:8000"] {
        assert!(
            normalize_public_url_for_profile(value, "standards-full").is_err(),
            "accepted insecure standards-full URL {value}"
        );
    }
    assert!(normalize_public_url_for_profile("http://auth.example", "baseline").is_err());
    for value in ["http://localhost:8000/", "http://127.0.0.1:8000/"] {
        assert_eq!(
            normalize_public_url_for_profile(value, "standards-full").unwrap(),
            value.trim_end_matches('/')
        );
    }
}

#[test]
fn external_dependency_secret_input_is_bounded_closed_and_value_opaque() {
    let work = PrivateTempDir::new("external-secret-input").unwrap();
    let valid = br#"{
        "database_url":"postgresql://runtime:runtime-secret@db.example/oauth",
        "migration_database_url":"postgresql://migrator:migration-secret@db.example/oauth",
        "database_backup_url":"postgresql://backup:backup-secret@db.example/oauth",
        "valkey_url":"rediss://default:valkey-secret@cache.example/0",
        "valkey_backup_url":"rediss://backup:backup-secret@cache.example/0",
        "valkey_backup_scope":"dedicated-instance"
    }"#;
    let mut options = install_options(work.path().join("data"));
    read_external_dependency_secrets(&mut options, std::io::Cursor::new(valid)).unwrap();
    assert_eq!(
        options.database_url.as_deref(),
        Some("postgresql://runtime:runtime-secret@db.example/oauth")
    );
    assert_eq!(
        options.migration_database_url.as_deref(),
        Some("postgresql://migrator:migration-secret@db.example/oauth")
    );
    assert_eq!(
        options.database_backup_url.as_deref(),
        Some("postgresql://backup:backup-secret@db.example/oauth")
    );
    assert_eq!(
        options.valkey_url.as_deref(),
        Some("rediss://default:valkey-secret@cache.example/0")
    );
    assert_eq!(
        options.valkey_backup_url.as_deref(),
        Some("rediss://backup:backup-secret@cache.example/0")
    );
    assert_eq!(
        options.external_valkey_backup_scope.as_deref(),
        Some("dedicated-instance")
    );
    assert!(
        options
            .database_backup_endpoint_sha256
            .as_deref()
            .is_some_and(|value| value.len() == 64)
    );
    assert!(
        options
            .valkey_backup_endpoint_sha256
            .as_deref()
            .is_some_and(|value| value.len() == 64)
    );

    let required = [
        "database_url",
        "migration_database_url",
        "database_backup_url",
        "valkey_url",
        "valkey_backup_url",
        "valkey_backup_scope",
    ];
    for omitted in required {
        let mut input: serde_json::Value = serde_json::from_slice(valid).unwrap();
        input.as_object_mut().unwrap().remove(omitted);
        let mut options = install_options(work.path().join("invalid-data"));
        let error = read_external_dependency_secrets(
            &mut options,
            std::io::Cursor::new(serde_json::to_vec(&input).unwrap()),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("dependency secret input must be strict JSON"));
        assert!(options.database_url.is_none());
        assert!(options.migration_database_url.is_none());
        assert!(options.valkey_url.is_none());
    }
    for invalid in [
        br#"{"database_url":"postgresql://db.example/oauth","migration_database_url":"postgresql://db.example/oauth","database_backup_url":"postgresql://db.example/oauth","valkey_url":"redis://cache.example/0","valkey_backup_url":"redis://cache.example/0","valkey_backup_scope":"dedicated-instance","unexpected":"secret-canary"}"#.as_slice(),
        br#"{"database_url":"postgresql://db.example/oauth","migration_database_url":"postgresql://db.example/oauth","database_backup_url":"postgresql://db.example/oauth","valkey_url":"redis://cache.example/0","valkey_backup_url":"redis://cache.example/0","valkey_backup_scope":"dedicated-instance"} trailing"#.as_slice(),
    ] {
        let mut options = install_options(work.path().join("invalid-data"));
        let error = read_external_dependency_secrets(&mut options, std::io::Cursor::new(invalid))
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("dependency secret input must be strict JSON"));
        assert!(!message.contains("secret-canary"));
    }

    let mut options = install_options(work.path().join("oversized-data"));
    let error = read_external_dependency_secrets(
        &mut options,
        std::io::Cursor::new(vec![b' '; 64 * 1024 + 1]),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "dependency secret input exceeds 64 KiB");
}

#[test]
fn dependency_secret_channels_and_url_set_fail_closed() {
    let work = PrivateTempDir::new("external-secret-boundaries").unwrap();

    let mut without_external = install_options(work.path().join("without-external"));
    without_external.secrets_stdin = true;
    assert_eq!(
        normalize_external_dependencies(&mut without_external)
            .unwrap_err()
            .to_string(),
        "secure dependency secret input requires --external-dependencies"
    );

    let mut conflicting = install_options(work.path().join("conflicting"));
    conflicting.external_dependencies = true;
    conflicting.secrets_stdin = true;
    conflicting.secret_fd = Some(3);
    assert_eq!(
        normalize_external_dependencies(&mut conflicting)
            .unwrap_err()
            .to_string(),
        "choose exactly one of --secrets-stdin or --secret-fd"
    );

    let mut partial = install_options(work.path().join("partial"));
    partial.database_url = Some("postgresql://runtime@db.example/oauth".to_owned());
    assert!(
        normalize_external_dependencies(&mut partial)
            .unwrap_err()
            .to_string()
            .contains("require distinct runtime, migration, backup PostgreSQL/Valkey URLs")
    );

    let mut invalid_scheme = install_options(work.path().join("invalid-scheme"));
    invalid_scheme.database_url = Some("https://db.example/oauth".to_owned());
    invalid_scheme.migration_database_url =
        Some("postgresql://migrator@db.example/oauth".to_owned());
    invalid_scheme.database_backup_url = Some("postgresql://backup@db.example/oauth".to_owned());
    invalid_scheme.valkey_url = Some("redis://cache.example/0".to_owned());
    invalid_scheme.valkey_backup_url = Some("redis://backup@cache.example/0".to_owned());
    invalid_scheme.external_valkey_backup_scope = Some("dedicated-instance".to_owned());
    let error = normalize_external_dependencies(&mut invalid_scheme).unwrap_err();
    assert!(!error.to_string().is_empty());
    assert!(!format!("{error:#}").contains("https://db.example/oauth"));

    let mut copied_runtime = install_options(work.path().join("copied-runtime"));
    copied_runtime.database_url = Some("postgresql://runtime:one@db.example/oauth".to_owned());
    copied_runtime.migration_database_url =
        Some("postgresql://migrator:two@db.example/oauth".to_owned());
    copied_runtime.database_backup_url =
        Some("postgresql://runtime:one@db.example/oauth".to_owned());
    copied_runtime.valkey_url = Some("rediss://runtime:three@cache.example/0".to_owned());
    copied_runtime.valkey_backup_url = Some("rediss://backup:four@cache.example/0".to_owned());
    copied_runtime.external_valkey_backup_scope = Some("dedicated-instance".to_owned());
    assert_eq!(
        normalize_external_dependencies(&mut copied_runtime)
            .unwrap_err()
            .to_string(),
        "external dependency credential URLs must be distinct"
    );
}

#[test]
fn dependency_urls_bind_credentials_database_and_query_safely() {
    assert!(
        validate_dependency_url(
            "postgresql://alice:p%40ss@db.example/oauth?sslmode=require",
            &["postgres", "postgresql"],
            "PostgreSQL",
        )
        .is_ok()
    );
    assert!(
        validate_dependency_url(
            "rediss://default:cache-secret@cache.example/0",
            &["redis", "rediss"],
            "Valkey",
        )
        .is_ok()
    );

    for (value, schemes, name) in [
        (
            "postgresql://alice@db.example/oauth",
            &["postgres", "postgresql"][..],
            "PostgreSQL",
        ),
        (
            "postgresql://alice:p%0Ass@db.example/oauth",
            &["postgres", "postgresql"][..],
            "PostgreSQL",
        ),
        (
            "postgresql://alice:p%40ss@db.example/a/b",
            &["postgres", "postgresql"][..],
            "PostgreSQL",
        ),
        (
            "postgresql://alice:p%40ss@db.example/oauth#fragment",
            &["postgres", "postgresql"][..],
            "PostgreSQL",
        ),
        (
            "postgresql://alice:p%40ss@db.example/oauth?password=leak",
            &["postgres", "postgresql"][..],
            "PostgreSQL",
        ),
        (
            "rediss://default:cache-secret@cache.example/01",
            &["redis", "rediss"][..],
            "Valkey",
        ),
        (
            "rediss://default:cache-secret@cache.example/0?tls=true",
            &["redis", "rediss"][..],
            "Valkey",
        ),
        (
            "redis://default:cache-secret@cache.example/cache",
            &["redis", "rediss"][..],
            "Valkey",
        ),
    ] {
        assert!(
            validate_dependency_url(value, schemes, name).is_err(),
            "accepted unsafe dependency URL {value}"
        );
    }
}

#[test]
fn external_urls_are_persisted_only_as_private_secret_files() {
    let work = PrivateTempDir::new("external-url-files").unwrap();
    let secrets = work.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    let mut options = install_options(work.path().join("data"));
    options.database_url = Some("postgresql://runtime:one@db.example/oauth".to_owned());
    options.migration_database_url = Some("postgresql://migrator:two@db.example/oauth".to_owned());
    options.database_backup_url = Some("postgresql://backup:three@db.example/oauth".to_owned());
    options.valkey_url = Some("rediss://default:three@cache.example/0".to_owned());
    options.valkey_backup_url = Some("rediss://backup:four@cache.example/0".to_owned());
    options.external_valkey_backup_scope = Some("dedicated-instance".to_owned());

    assert_eq!(write_external_urls(&secrets, &options).unwrap(), "external");
    assert_eq!(
        fs::read_to_string(secrets.join("database-url")).unwrap(),
        options.database_url.as_deref().unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("database-migration-url")).unwrap(),
        options.migration_database_url.as_deref().unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("database-backup-url")).unwrap(),
        options.database_backup_url.as_deref().unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("valkey-url")).unwrap(),
        options.valkey_url.as_deref().unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("valkey-backup-url")).unwrap(),
        options.valkey_backup_url.as_deref().unwrap()
    );
    #[cfg(unix)]
    for name in ["database-url", "valkey-url"] {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(secrets.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o440
        );
    }
    #[cfg(unix)]
    for name in [
        "database-migration-url",
        "database-backup-url",
        "valkey-backup-url",
    ] {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(secrets.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }
}

#[test]
fn fresh_server_config_persists_bootstrap_deployment_identity_without_rewriting_existing() {
    let work = PrivateTempDir::new("server-config-deployment-identity").unwrap();
    let config_dir = work.path().join("config");
    fs::create_dir(&config_dir).unwrap();
    let options = install_options(work.path().join("data"));
    let controller_public_key = work.path().join("operator/controller.pub");

    write_server_config(ServerConfigWriteRequest {
        config_dir: &config_dir,
        options: &options,
        deployment_id: "deployment-bootstrap",
        controller_public_key: &controller_public_key,
        runtime: RuntimeBackendKind::Podman,
        data_root: &options.data_root,
        trusted_proxy_cidr: None,
        profile_config: None,
    })
    .unwrap();
    let target = config_dir.join(".env.yaml");
    let rendered = fs::read_to_string(&target).unwrap();
    assert!(rendered.contains("DEPLOYMENT_ID: \"deployment-bootstrap\"\n"));
    assert!(rendered.contains(&format!(
        "TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE: \"{}\"\n",
        TENANT_RESOURCE_CONTROLLER_CONTAINER_KEY_PATH
    )));
    assert!(rendered.contains(
        "MFA_TOTP_ENCRYPTION_KEY_FILE: \"/run/nazoauth-secrets/mfa-totp-encryption-key\"\n"
    ));
    assert!(rendered.contains("MFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n"));

    let host_config_dir = work.path().join("host-config");
    fs::create_dir(&host_config_dir).unwrap();
    let host_data_root = work.path().join("host-data");
    write_server_config(ServerConfigWriteRequest {
        config_dir: &host_config_dir,
        options: &options,
        deployment_id: "deployment-bootstrap",
        controller_public_key: &controller_public_key,
        runtime: RuntimeBackendKind::Systemd,
        data_root: &host_data_root,
        trusted_proxy_cidr: None,
        profile_config: None,
    })
    .unwrap();
    let host_rendered = fs::read_to_string(host_config_dir.join(".env.yaml")).unwrap();
    assert!(host_rendered.contains(&format!(
        "MFA_TOTP_ENCRYPTION_KEY_FILE: \"{}\"\n",
        mfa_totp_key_path(&host_config_dir).display()
    )));
    assert!(host_rendered.contains(&format!(
        "TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE: \"{}\"\n",
        controller_public_key.display()
    )));
    assert!(managed_mfa_totp_source(&host_config_dir, RuntimeBackendKind::Systemd).unwrap());

    fs::write(
        &target,
        "PUBLIC_BASE_URL: \"https://auth.example\"\nDEPLOYMENT_ID: existing\n",
    )
    .unwrap();
    set_server_config_fixture_permissions(&target);
    write_server_config(ServerConfigWriteRequest {
        config_dir: &config_dir,
        options: &options,
        deployment_id: "deployment-replacement",
        controller_public_key: &controller_public_key,
        runtime: RuntimeBackendKind::Podman,
        data_root: &options.data_root,
        trusted_proxy_cidr: None,
        profile_config: None,
    })
    .unwrap();
    assert_eq!(
        fs::read_to_string(target).unwrap(),
        format!(
            "PUBLIC_BASE_URL: \"https://auth.example\"\nDEPLOYMENT_ID: existing\nTENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE: \"{}\"\n",
            TENANT_RESOURCE_CONTROLLER_CONTAINER_KEY_PATH
        )
    );
}

#[test]
fn tenant_resource_controller_identity_is_stable_and_idempotent() {
    let work = PrivateTempDir::new("tenant-resource-controller-identity").unwrap();
    let config_dir = work.path().join("config");
    fs::create_dir_all(config_dir.join("operator/generations/active")).unwrap();
    ensure_tenant_resource_controller_identity(&config_dir).unwrap();
    let private = tenant_resource_controller_private_key_path(&config_dir);
    let public = tenant_resource_controller_public_key_path(&config_dir);
    let key_id = tenant_resource_controller_key_id_path(&config_dir);
    let before = (
        fs::read(&private).unwrap(),
        fs::read(&public).unwrap(),
        fs::read(&key_id).unwrap(),
    );

    // Normal operator generation rotation writes below generations/ and must
    // not affect the dedicated management identity.
    fs::write(
        config_dir.join("operator/generations/active/controller.pub"),
        b"rotated-operator-controller",
    )
    .unwrap();
    ensure_tenant_resource_controller_identity(&config_dir).unwrap();
    assert_eq!(fs::read(private).unwrap(), before.0);
    assert_eq!(fs::read(public).unwrap(), before.1);
    assert_eq!(fs::read(key_id).unwrap(), before.2);

    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(tenant_resource_controller_private_key_path(&config_dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(tenant_resource_controller_public_key_path(&config_dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
    }
}

#[cfg(unix)]
#[test]
fn tenant_resource_controller_upgrade_replaces_only_the_legacy_managed_binding() {
    let work = PrivateTempDir::new("tenant-resource-controller-upgrade").unwrap();
    let config_dir = work.path().join("config");
    let mut options = install_options(work.path().join("data"));
    bind_external_dependency_fixture(&mut options);
    operator::initialize_identity_generation(&config_dir.join("operator"), &options.recovery_root)
        .unwrap();
    ensure_tenant_resource_controller_identity(&config_dir).unwrap();
    fs::create_dir(config_dir.join("secrets")).unwrap();
    let config_path = config_dir.join("update.json");
    let mut config = build_config(
        &config_path,
        &options,
        RuntimeBackendKind::Podman,
        Some(RuntimeBackendKind::Podman),
        "external",
    )
    .unwrap();
    assert_eq!(
        config.runtime.environment.get("DEPLOYMENT_ID"),
        Some(&config.operator.deployment_id)
    );
    assert_eq!(
        config.runtime.environment.get("RUNTIME_INSTANCE_ID"),
        Some(&config.runtime.runtime_instance_id)
    );
    let target = PathBuf::from(TENANT_RESOURCE_CONTROLLER_CONTAINER_KEY_PATH);
    let binding = config
        .runtime
        .mounts
        .iter_mut()
        .find(|mount| mount.target == target)
        .unwrap();
    binding.source = config.operator.controller_public_key.clone();
    fs::write(
        config_dir.join(".env.yaml"),
        format!(
            "PUBLIC_BASE_URL: \"https://auth.example\"\nTENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE: \"{}\"\n",
            TENANT_RESOURCE_CONTROLLER_CONTAINER_KEY_PATH
        ),
    )
    .unwrap();
    set_server_config_fixture_permissions(&config_dir.join(".env.yaml"));

    assert!(ensure_tenant_resource_controller_runtime(&config_dir, &mut config).unwrap());
    let binding = config
        .runtime
        .mounts
        .iter()
        .find(|mount| mount.target == target)
        .unwrap();
    assert_eq!(
        binding.source,
        tenant_resource_controller_public_key_path(&config_dir)
    );
    assert!(binding.read_only && binding.selinux_relabel);
    assert!(!ensure_tenant_resource_controller_runtime(&config_dir, &mut config).unwrap());
}

#[test]
fn existing_standards_full_server_config_must_match_the_explicit_proxy_boundary() {
    let work = PrivateTempDir::new("standards-full-existing-config-validation").unwrap();
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    options.trusted_proxy_cidr = Some("192.0.2.10/32".to_owned());
    let valid = "PUBLIC_BASE_URL: \"https://auth.example\"\n\
                 ENABLE_AUTHORIZATION_DETAILS: true\n\
                 ENABLE_NATIVE_SSO: true\n\
                 MTLS_ENDPOINT_BASE_URL: \"https://auth.example\"\n\
                 MTLS_CERTIFICATE_SOURCE: \"rfc9440\"\n\
                 TRUSTED_PROXY_CIDRS: \"192.0.2.10/32\"\n\
                 ENABLE_OPENID4VCI_ISSUER: true\n\
                 ENABLE_OPENID4VP_VERIFIER: true\n\
                 OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON: \"{\\\"example\\\":{\\\"format\\\":\\\"dc+sd-jwt\\\"}}\"\n";
    let expected_profile = "ENABLE_AUTHORIZATION_DETAILS: true\n\
                            ENABLE_NATIVE_SSO: true\n\
                            ENABLE_OPENID4VCI_ISSUER: true\n\
                            ENABLE_OPENID4VP_VERIFIER: true\n\
                            MTLS_ENDPOINT_BASE_URL: \"https://auth.example\"\n\
                            TRUSTED_PROXY_CIDRS: \"192.0.2.10/32\"\n\
                            MTLS_CERTIFICATE_SOURCE: \"rfc9440\"\n\
                            OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON: \"{\\\"example\\\":{\\\"format\\\":\\\"dc+sd-jwt\\\"}}\"\n";
    validate_existing_server_config(
        valid,
        &options,
        options.trusted_proxy_cidr.as_deref(),
        Some(expected_profile),
    )
    .unwrap();

    for invalid in [
        valid.replace("rfc9440", "legacy-verified-headers"),
        valid.replace("192.0.2.10/32", "0.0.0.0/0"),
        valid.replace("https://auth.example", "https://other.example"),
        valid.replace(
            "ENABLE_OPENID4VP_VERIFIER: true",
            "ENABLE_OPENID4VP_VERIFIER: false",
        ),
        valid.replace("dc+sd-jwt", "jwt_vc_json"),
    ] {
        assert!(
            validate_existing_server_config(
                &invalid,
                &options,
                options.trusted_proxy_cidr.as_deref(),
                Some(expected_profile),
            )
            .is_err(),
            "accepted invalid standards-full server configuration: {invalid}"
        );
    }
}

#[test]
fn mfa_totp_key_is_32_byte_base64url_and_idempotent() {
    let work = PrivateTempDir::new("mfa-totp-key").unwrap();
    let key_path = mfa_totp_key_path(&work.path().join("config"));

    ensure_mfa_totp_key(&key_path).unwrap();
    let first = fs::read_to_string(&key_path).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(first.trim()).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o440
        );
    }
    ensure_mfa_totp_key(&key_path).unwrap();
    assert_eq!(fs::read_to_string(key_path).unwrap(), first);
}

#[test]
fn mfa_totp_upgrade_fills_missing_config_without_replacing_existing_key_sources() {
    let work = PrivateTempDir::new("mfa-totp-upgrade").unwrap();
    let config_dir = work.path().join("config");
    fs::create_dir(&config_dir).unwrap();
    let target = config_dir.join(".env.yaml");
    fs::write(&target, "PUBLIC_BASE_URL: \"https://auth.example\"\n").unwrap();
    set_server_config_fixture_permissions(&target);

    ensure_mfa_totp_configuration(&config_dir, RuntimeBackendKind::Podman).unwrap();
    let first = fs::read_to_string(&target).unwrap();
    assert!(first.contains(
        "MFA_TOTP_ENCRYPTION_KEY_FILE: \"/run/nazoauth-secrets/mfa-totp-encryption-key\"\n"
    ));
    assert!(first.contains("MFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n"));
    let key_path = mfa_totp_key_path(&config_dir);
    let key = fs::read_to_string(&key_path).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(key.trim()).unwrap().len(), 32);

    ensure_mfa_totp_configuration(&config_dir, RuntimeBackendKind::Podman).unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), first);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), key);

    let inline_dir = work.path().join("inline-config");
    fs::create_dir(&inline_dir).unwrap();
    fs::write(
        inline_dir.join(".env.yaml"),
        "MFA_TOTP_ENCRYPTION_KEY: \"existing-inline-key\"\n",
    )
    .unwrap();
    set_server_config_fixture_permissions(&inline_dir.join(".env.yaml"));
    ensure_mfa_totp_configuration(&inline_dir, RuntimeBackendKind::Podman).unwrap();
    let inline = fs::read_to_string(inline_dir.join(".env.yaml")).unwrap();
    assert!(inline.contains("MFA_TOTP_ENCRYPTION_KEY: \"existing-inline-key\"\n"));
    assert!(inline.contains("MFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n"));
    assert!(!mfa_totp_key_path(&inline_dir).exists());
    assert!(!managed_mfa_totp_source(&inline_dir, RuntimeBackendKind::Podman).unwrap());

    let file_dir = work.path().join("file-config");
    fs::create_dir(&file_dir).unwrap();
    let existing_file = file_dir.join("existing-mfa.key");
    fs::write(&existing_file, "external-file-key").unwrap();
    fs::write(
        file_dir.join(".env.yaml"),
        format!(
            "MFA_TOTP_ENCRYPTION_KEY_FILE: \"{}\"\n",
            existing_file.display()
        ),
    )
    .unwrap();
    set_server_config_fixture_permissions(&file_dir.join(".env.yaml"));
    ensure_mfa_totp_configuration(&file_dir, RuntimeBackendKind::Podman).unwrap();
    let file_config = fs::read_to_string(file_dir.join(".env.yaml")).unwrap();
    assert!(file_config.contains(&format!(
        "MFA_TOTP_ENCRYPTION_KEY_FILE: \"{}\"\n",
        existing_file.display()
    )));
    assert!(file_config.contains("MFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n"));
    assert_eq!(
        fs::read_to_string(existing_file).unwrap(),
        "external-file-key"
    );
    assert!(!mfa_totp_key_path(&file_dir).exists());
    assert!(!managed_mfa_totp_source(&file_dir, RuntimeBackendKind::Podman).unwrap());
}

#[cfg(unix)]
#[test]
fn generated_container_config_exposes_secret_files_but_not_secret_values() {
    let work = PrivateTempDir::new("container-config-boundary").unwrap();
    let config_dir = work.path().join("config");
    let mut options = install_options(work.path().join("data"));
    operator::initialize_identity_generation(&config_dir.join("operator"), &options.recovery_root)
        .unwrap();
    let secret_dir = config_dir.join("secrets");
    fs::create_dir(&secret_dir).unwrap();
    set_mode(&secret_dir, 0o750).unwrap();
    let mfa_key = mfa_totp_key_path(&config_dir);
    ensure_mfa_totp_key(&mfa_key).unwrap();
    fs::write(
        config_dir.join(".env.yaml"),
        "MFA_TOTP_ENCRYPTION_KEY_FILE: \"/run/nazoauth-secrets/mfa-totp-encryption-key\"\nMFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n",
    )
    .unwrap();
    set_server_config_fixture_permissions(&config_dir.join(".env.yaml"));
    options.profile = "standards-full".to_owned();
    bind_external_dependency_fixture(&mut options);
    let config_path = config_dir.join("update.json");
    let config = build_config(
        &config_path,
        &options,
        RuntimeBackendKind::Podman,
        Some(RuntimeBackendKind::Podman),
        "external",
    )
    .unwrap();
    let rendered = serde_json::to_string(&config).unwrap();

    assert_eq!(config.runtime.publish_address, "127.0.0.1:8000:8000");
    assert_eq!(
        config.runtime.environment.get("DATABASE_URL_FILE"),
        Some(&"/run/nazoauth-secrets/database-url".to_owned())
    );
    assert_eq!(
        config.runtime.environment.get("VALKEY_URL_FILE"),
        Some(&"/run/nazoauth-secrets/valkey-url".to_owned())
    );
    assert!(config.runtime.mounts.iter().any(|mount| {
        mount.target == Path::new("/run/nazoauth-secrets/database-url")
            && mount.read_only
            && mount.selinux_relabel
    }));
    assert!(!config.runtime.mounts.iter().any(|mount| {
        mount.target == Path::new("/run/nazoauth-secrets/database-migration-url")
    }));
    for name in ["database-backup-url", "valkey-backup-url"] {
        assert!(
            !config.runtime.mounts.iter().any(|mount| {
                mount.target == Path::new(&format!("/run/nazoauth-secrets/{name}"))
            })
        );
    }
    for name in STANDARDS_PROFILE_SECRET_NAMES {
        let expected = PathBuf::from(format!("/run/nazoauth-secrets/{name}"));
        assert!(
            config.runtime.mounts.iter().any(|mount| {
                mount.target == expected && mount.read_only && mount.selinux_relabel
            })
        );
    }
    let instance = options.data_root.join("app/instance");
    assert!(config.runtime.mounts.iter().any(|mount| {
        mount.source == instance
            && mount.target == Path::new("/var/lib/nazo_oauth/instance")
            && !mount.read_only
            && mount.selinux_relabel
    }));
    assert!(config.runtime.snapshot_paths.contains(&instance));
    assert!(config.runtime.mounts.iter().any(|mount| {
        mount.source == mfa_key
            && mount.target == Path::new(MFA_TOTP_CONTAINER_KEY_PATH)
            && mount.read_only
            && mount.selinux_relabel
    }));
    assert!(
        config
            .runtime
            .snapshot_paths
            .contains(&options.data_root.join("app/secrets"))
    );
    assert!(config.runtime.snapshot_paths.contains(&secret_dir));
    assert_eq!(mfa_key.parent(), Some(secret_dir.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o022,
            0
        );
    }

    let mut stale = config.clone();
    stale
        .runtime
        .mounts
        .retain(|mount| mount.target != Path::new(MFA_TOTP_CONTAINER_KEY_PATH));
    stale
        .runtime
        .snapshot_paths
        .retain(|path| path != &secret_dir);
    assert!(ensure_mfa_totp_runtime(&config_dir, &mut stale).unwrap());
    assert!(stale.runtime.mounts.iter().any(|mount| {
        mount.source == mfa_key
            && mount.target == Path::new(MFA_TOTP_CONTAINER_KEY_PATH)
            && mount.read_only
            && mount.selinux_relabel
    }));
    assert!(stale.runtime.snapshot_paths.contains(&secret_dir));
    assert!(!ensure_mfa_totp_runtime(&config_dir, &mut stale).unwrap());

    let mut conflict = stale.clone();
    conflict
        .runtime
        .mounts
        .iter_mut()
        .find(|mount| mount.target == Path::new(MFA_TOTP_CONTAINER_KEY_PATH))
        .unwrap()
        .source = options.data_root.join("app/secrets/old-mfa.key");
    assert!(
        ensure_mfa_totp_runtime(&config_dir, &mut conflict)
            .unwrap_err()
            .to_string()
            .contains("managed MFA TOTP mount conflicts")
    );

    fs::remove_file(&mfa_key).unwrap();
    assert!(
        ensure_mfa_totp_runtime(&config_dir, &mut stale)
            .unwrap_err()
            .to_string()
            .contains("restore")
    );
    assert!(
        !config
            .runtime
            .snapshot_paths
            .contains(&options.recovery_root)
    );
    assert!(!rendered.contains("postgresql://"));
    assert!(!rendered.contains("redis://"));

    let host_config = build_config(
        &config_path,
        &options,
        RuntimeBackendKind::Systemd,
        Some(RuntimeBackendKind::Podman),
        "external",
    )
    .unwrap();
    assert_eq!(host_config.runtime.backend, RuntimeBackendKind::Systemd);
    assert_eq!(
        host_config.runtime.dependency_backend,
        Some(RuntimeBackendKind::Podman)
    );
}

#[test]
fn managed_runtime_database_grants_keep_the_audit_ledger_api_least_privileged() {
    let sql = std::str::from_utf8(MANAGED_RUNTIME_DATABASE_GRANT_SQL)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(sql.contains("full_dml_tables CONSTANT text[]"));
    assert!(sql.contains("optional_full_dml_tables CONSTANT text[]"));
    assert!(sql.contains("append_tables CONSTANT text[]"));
    assert!(sql.contains("runtime table privilege allowlist is incomplete"));
    for table in [
        "scim_tokens",
        "oauth_client_mtls_trust_anchor_requests",
        "openid4vci_credential_dataset_events",
        "tenant_resource_states",
        "tenant_resource_bindings",
        "tenant_resource_operations",
        "openid4vc_trust_policies",
        "openid4vc_trust_policy_clients",
        "ciba_decision_bindings",
        "security_audit_event_outbox",
    ] {
        assert!(
            sql.contains(table),
            "missing runtime table allowlist entry: {table}"
        );
    }
    let full_dml_tables = sql
        .split("full_dml_tables CONSTANT text[]")
        .nth(1)
        .and_then(|section| {
            section
                .split("optional_full_dml_tables CONSTANT text[]")
                .next()
        })
        .expect("full DML table section");
    let optional_full_dml_tables = sql
        .split("optional_full_dml_tables CONSTANT text[]")
        .nth(1)
        .and_then(|section| section.split("append_tables CONSTANT text[]").next())
        .expect("optional full DML table section");
    assert!(!full_dml_tables.contains("ciba_decision_bindings"));
    assert!(optional_full_dml_tables.contains("ciba_decision_bindings"));
    assert!(
        sql.contains("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO nazoauth_runtime")
    );
    assert!(sql.contains("GRANT SELECT, INSERT ON TABLE public.%I TO nazoauth_runtime"));
    assert!(sql.contains("GRANT DELETE ON TABLE public.%I TO nazoauth_runtime"));
    assert!(!sql.contains("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"));
    assert!(!sql.contains("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES"));
    assert!(!sql.contains("GRANT EXECUTE ON ALL FUNCTIONS"));
    assert!(sql.contains(
        "REVOKE ALL ON TABLE public.security_audit_chain_state, public.security_audit_events, public.security_audit_event_outbox FROM nazoauth_runtime;"
    ));
    assert!(sql.contains("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM nazoauth_runtime;"));
    assert!(sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM nazoauth_runtime;"));
    assert!(sql.contains("nazo_oauth_cleanup_expired_security_state()"));
    assert!(!sql.contains("nazo_oauth_conformance_lease_is_active(UUID, UUID)"));
    assert!(!sql.contains("nazo_oauth_cleanup_expired_conformance_leases()"));
    for function in [
        "public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN)",
        "public.nazo_security_audit_chain_head_for_update()",
        "public.nazo_append_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA)",
        "public.nazo_security_audit_anchor_freshness()",
    ] {
        assert!(
            sql.contains(function),
            "missing explicit audit function grant: {function}"
        );
    }
    assert!(!sql.contains("nazo_security_audit_anchor_health()"));

    for revoke in [
        "ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public REVOKE ALL ON TABLES FROM nazoauth_runtime;",
        "ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public REVOKE ALL ON SEQUENCES FROM nazoauth_runtime;",
        "ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM nazoauth_runtime;",
    ] {
        assert!(
            sql.contains(revoke),
            "missing default-privilege revoke: {revoke}"
        );
    }
    assert!(
        !sql.contains("ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT")
    );

    assert!(
        sql.find("full_dml_tables CONSTANT").unwrap() < sql.find("REVOKE ALL ON TABLE").unwrap()
    );
}

#[cfg(unix)]
#[test]
fn managed_directory_rejects_symlink_targets() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("install-directory-symlink").unwrap();
    let real = work.path().join("real");
    let linked = work.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();

    let error = create_directory(&linked, 0o700).unwrap_err();
    assert!(error.to_string().contains("symlink"));
}

#[test]
fn lifecycle_install_platform_boundary_is_linux_x86_64_and_arm64_only() {
    assert!(install_platform_supported("linux", "x86_64"));
    assert!(install_platform_supported("linux", "aarch64"));
    for (os, arch) in [
        ("linux", "arm"),
        ("linux", "s390x"),
        ("windows", "x86_64"),
        ("windows", "aarch64"),
        ("macos", "x86_64"),
        ("macos", "aarch64"),
    ] {
        assert!(!install_platform_supported(os, arch));
    }
}
