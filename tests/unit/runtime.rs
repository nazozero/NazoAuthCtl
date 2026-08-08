use std::{collections::BTreeMap, path::PathBuf};

#[cfg(unix)]
use std::fs;

#[cfg(unix)]
use crate::test_support::write_shell_executable;

use super::*;
use crate::{
    filesystem::PrivateTempDir,
    model::{Dependencies, Operator, Postgres, Runtime as RuntimeConfig, Ui, Valkey},
};

#[cfg(unix)]
use crate::runtime_backend::{
    ManagedDependencyBackup, ManagedDependencyIdentity, ManagedPostgresCommand,
    ManagedValkeyRestore, RuntimeBackend,
};

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let config_dir = work.path().join("config");
    let operator_dir = config_dir.join("operator");
    let app = work.path().join("app");
    let secrets = config_dir.join("secrets");
    UpdateConfig {
        schema: 2,
        trust: crate::deployment::TrustState::Adopted,
        capabilities: crate::deployment::CapabilityGrants::controller_installed(),
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        backup_root: work.path().join("backups"),
        deployment_root: work.path().join("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: operator_dir.join("controller.key"),
            controller_public_key: operator_dir.join("controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: operator_dir.join("receipt.key"),
            receipt_public_key: operator_dir.join("receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: operator_dir.join("audit.key"),
            audit_public_key: operator_dir.join("audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: work.path().join("recovery/break-glass.key"),
            break_glass_public_key: operator_dir.join("break-glass.pub"),
            active_identity_file: operator_dir.join("active-generation.json"),
            identity_generations_directory: operator_dir.join("generations"),
            recovery_generations_directory: work.path().join("recovery/generations"),
            secret_revision_file: operator_dir.join("secret-revision"),
            state_directory: app.join("operator-state"),
            audit_directory: work.path().join("audit"),
            trust_state_file: operator_dir.join("release-trust.json"),
        },
        dependencies: Dependencies {
            mode: "external".to_owned(),
            database_url_file: secrets.join("database-url"),
            migration_database_url_file: secrets.join("database-migration-url"),
            valkey_url_file: secrets.join("valkey-url"),
        },
        runtime: RuntimeConfig {
            backend: RuntimeBackendKind::Podman,
            dependency_backend: Some(RuntimeBackendKind::Podman),
            backend_command_override: None,
            container_name: "nazo-oauth-server".to_owned(),
            runtime_instance_id: "runtime-test".to_owned(),
            network: "nazo_oauth_net".to_owned(),
            ip_address: "10.89.0.20".to_owned(),
            publish_address: "127.0.0.1:8000:8000".to_owned(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 60,
            readiness_interval_seconds: 1,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: vec![
                Mount {
                    source: config_dir.join(".env.yaml"),
                    target: PathBuf::from("/app/.env.yaml"),
                    read_only: true,
                    selinux_relabel: true,
                },
                Mount {
                    source: app.join("keys"),
                    target: PathBuf::from("/var/lib/nazo_oauth/keys"),
                    read_only: false,
                    selinux_relabel: true,
                },
                Mount {
                    source: secrets.join("database-url"),
                    target: PathBuf::from("/run/nazoauth-secrets/database-url"),
                    read_only: true,
                    selinux_relabel: true,
                },
                Mount {
                    source: secrets.join("valkey-url"),
                    target: PathBuf::from("/run/nazoauth-secrets/valkey-url"),
                    read_only: true,
                    selinux_relabel: true,
                },
            ],
            snapshot_paths: vec![app.join("keys"), app.join("secrets"), app.join("bootstrap")],
            environment: BTreeMap::from([
                (
                    "DATABASE_URL_FILE".to_owned(),
                    "/run/nazoauth-secrets/database-url".to_owned(),
                ),
                (
                    "VALKEY_URL_FILE".to_owned(),
                    "/run/nazoauth-secrets/valkey-url".to_owned(),
                ),
            ]),
            service_name: String::new(),
            service_user: String::new(),
            binary_path: PathBuf::new(),
            binary_releases: PathBuf::new(),
            working_directory: PathBuf::new(),
        },
        postgres: Postgres {
            container_name: "nazo-oauth-postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "nazoauth_migrator".to_owned(),
            image: "postgres-image".to_owned(),
            validation_image: "postgres-image".to_owned(),
        },
        valkey: Valkey {
            container_name: "nazo-oauth-valkey".to_owned(),
            data_volume: "nazo-oauth-valkey-data".to_owned(),
            image: "valkey-image".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: PathBuf::new(),
        },
        ui: Ui {
            releases_root: work.path().join("ui-releases"),
        },
    }
}

#[test]
fn managed_dependency_identity_binds_runtime_and_immutable_configuration() {
    let identity = crate::runtime_backend::managed_dependency_identity(
        "deployment-a",
        "controller-a",
        "runtime-a",
        "nazoauth-network",
        "nazoauth-postgres",
        "nazoauth-postgres-data",
        "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "nazoauth",
        "nazoauth_runtime",
        "nazoauth-valkey",
        "nazoauth-valkey-data",
        "valkey@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let mut runtime_changed = identity.clone();
    runtime_changed.runtime_instance_id = "runtime-b".to_owned();
    let mut image_changed = identity.clone();
    image_changed.postgres_config_digest = crate::runtime_backend::managed_config_digest(
        "postgres",
        &[(
            "image",
            "postgres@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )],
    );
    assert_ne!(identity, runtime_changed);
    assert_ne!(identity, image_changed);
    assert!(identity.network_config_digest.starts_with("sha256:"));
    assert!(identity.postgres_config_digest.starts_with("sha256:"));
}

#[cfg(unix)]
fn managed_dependency_fixture() -> (ManagedDependencyIdentity, String, String) {
    let postgres_image = format!("postgres@sha256:{}", "a".repeat(64));
    let valkey_image = format!("valkey@sha256:{}", "b".repeat(64));
    let identity = crate::runtime_backend::managed_dependency_identity(
        "deployment-test",
        "controller-test",
        "runtime-test",
        "nazoauth-network",
        "nazoauth-postgres",
        "nazoauth-postgres-data",
        &postgres_image,
        "oauth",
        "nazoauth_runtime",
        "nazoauth-valkey",
        "nazoauth-valkey-data",
        &valkey_image,
    );
    (identity, postgres_image, valkey_image)
}

#[cfg(unix)]
fn managed_identity_engine(
    work: &PrivateTempDir,
    identity: &ManagedDependencyIdentity,
    postgres_image: &str,
    valkey_image: &str,
    drift: &str,
) -> (PathBuf, PathBuf) {
    let engine = work.path().join("managed-identity-engine");
    let marker = work.path().join("managed-side-effect.marker");
    let wrong_digest = format!("sha256:{}", "d".repeat(64));
    let wrong_image = format!("postgres@sha256:{}", "e".repeat(64));
    let network_digest = if drift == "network" {
        &wrong_digest
    } else {
        &identity.network_config_digest
    };
    let postgres_digest = if drift == "config-digest" {
        &wrong_digest
    } else {
        &identity.postgres_config_digest
    };
    let valkey_digest = if drift == "config-digest" {
        &wrong_digest
    } else {
        &identity.valkey_config_digest
    };
    let postgres_volume_digest = if drift == "volume" {
        &wrong_digest
    } else {
        &identity.postgres_volume_config_digest
    };
    let valkey_volume_digest = if drift == "volume" {
        &wrong_digest
    } else {
        &identity.valkey_volume_config_digest
    };
    let runtime_instance_id = if drift == "runtime-instance" {
        "runtime-foreign"
    } else {
        identity.runtime_instance_id.as_str()
    };
    let postgres_role = if drift == "container" {
        "foreign-container"
    } else {
        "postgres"
    };
    let valkey_role = if drift == "container" {
        "foreign-container"
    } else {
        "valkey"
    };
    let postgres_reported_image = if drift == "image" {
        wrong_image.as_str()
    } else {
        postgres_image
    };
    let valkey_reported_image = if drift == "image" {
        wrong_image.as_str()
    } else {
        valkey_image
    };
    write_shell_executable(
        &engine,
        &format!(
            r#"case "$*" in
  *'io.nazoauth.deployment-id'*) printf '%s\n' 'deployment-test' ;;
  *'io.nazoauth.control-authority'*) printf '%s\n' 'controller-test' ;;
  *'io.nazoauth.runtime-instance-id'*) printf '%s\n' '{runtime_instance_id}' ;;
  *'io.nazoauth.managed-resource'*)
    case "$*" in
      *'network inspect'*) printf '%s\n' 'network' ;;
      *'postgres-data'*) printf '%s\n' 'postgres-volume' ;;
      *'valkey-data'*) printf '%s\n' 'valkey-volume' ;;
      *'postgres'*) printf '%s\n' '{postgres_role}' ;;
      *'valkey'*) printf '%s\n' '{valkey_role}' ;;
      *) exit 1 ;;
    esac ;;
  *'io.nazoauth.config-digest'*)
    case "$*" in
      *'network inspect'*) printf '%s\n' '{network_digest}' ;;
      *'volume inspect'*)
        case "$*" in
          *'postgres-data'*) printf '%s\n' '{postgres_volume_digest}' ;;
          *'valkey-data'*) printf '%s\n' '{valkey_volume_digest}' ;;
          *) exit 1 ;;
        esac
        ;;
      *'postgres'*) printf '%s\n' '{postgres_digest}' ;;
      *'valkey'*) printf '%s\n' '{valkey_digest}' ;;
      *) exit 1 ;;
    esac ;;
  *'Config.Image'*|*'ImageName'*|*'RepoDigests'*)
    case "$*" in
      *'postgres'*) printf '%s\n' '{postgres_reported_image}' ;;
      *'valkey'*) printf '%s\n' '{valkey_reported_image}' ;;
      *) exit 1 ;;
    esac ;;
  *)
    case "${{1-}}" in
      exec|run|stop|start|cp) printf '%s\n' "$*" >> '{marker}' ;;
    esac ;;
esac"#,
            marker = marker.display(),
            runtime_instance_id = runtime_instance_id,
            postgres_role = postgres_role,
            valkey_role = valkey_role,
            network_digest = network_digest,
            postgres_volume_digest = postgres_volume_digest,
            valkey_volume_digest = valkey_volume_digest,
            postgres_digest = postgres_digest,
            valkey_digest = valkey_digest,
            postgres_reported_image = postgres_reported_image,
            valkey_reported_image = valkey_reported_image,
        ),
    );
    (engine, marker)
}

#[cfg(unix)]
#[test]
fn managed_postgres_execute_rejects_container_identity_drift_before_exec() {
    for drift in ["container", "config-digest", "runtime-instance", "image"] {
        let work = PrivateTempDir::new("runtime-managed-execute").unwrap();
        let (identity, postgres_image, _) = managed_dependency_fixture();
        let (engine, marker) = managed_identity_engine(
            &work,
            &identity,
            &postgres_image,
            "valkey@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            drift,
        );
        let command = ManagedPostgresCommand {
            object_reference: "nazoauth-postgres".to_owned(),
            network: "nazoauth-network".to_owned(),
            database: "oauth".to_owned(),
            user: "nazoauth_runtime".to_owned(),
            stdin: b"select 1".to_vec(),
            image: postgres_image,
            identity,
        };
        let error =
            crate::runtime_backend::backend_with_command(RuntimeBackendKind::Podman, engine)
                .execute_managed_postgres(&command)
                .unwrap_err();
        let expected = if drift == "image" {
            "immutable image"
        } else {
            "immutable managed-resource identity"
        };
        assert!(
            error.to_string().contains(expected),
            "{drift} drift returned an unexpected error: {error:#}"
        );
        assert!(
            !marker.exists(),
            "{drift} drift reached the PostgreSQL exec side effect"
        );
    }
}

#[cfg(unix)]
#[test]
fn managed_valkey_restore_rejects_network_and_volume_drift_before_stop() {
    for drift in ["network", "volume"] {
        let work = PrivateTempDir::new("runtime-managed-valkey-restore").unwrap();
        let (identity, _, valkey_image) = managed_dependency_fixture();
        let (engine, marker) = managed_identity_engine(
            &work,
            &identity,
            "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &valkey_image,
            drift,
        );
        let restore = ManagedValkeyRestore {
            network: "nazoauth-network".to_owned(),
            object_reference: "nazoauth-valkey".to_owned(),
            data_volume: "nazoauth-valkey-data".to_owned(),
            backup_directory: work.path().join("backup"),
            image: valkey_image,
            identity,
        };
        let error =
            crate::runtime_backend::backend_with_command(RuntimeBackendKind::Podman, engine)
                .restore_managed_valkey(&restore)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("immutable managed-resource identity"),
            "{drift} drift returned an unexpected error: {error:#}"
        );
        assert!(
            !marker.exists(),
            "{drift} drift reached the Valkey stop/restore side effect"
        );
    }
}

#[cfg(unix)]
#[test]
fn managed_backup_rejects_config_digest_drift_before_dump() {
    let work = PrivateTempDir::new("runtime-managed-backup").unwrap();
    let (identity, postgres_image, valkey_image) = managed_dependency_fixture();
    let (engine, marker) = managed_identity_engine(
        &work,
        &identity,
        &postgres_image,
        &valkey_image,
        "config-digest",
    );
    let backup = ManagedDependencyBackup {
        destination: work.path().join("backup"),
        network: "nazoauth-network".to_owned(),
        postgres_object: "nazoauth-postgres".to_owned(),
        postgres_volume: "nazoauth-postgres-data".to_owned(),
        postgres_image: postgres_image.clone(),
        postgres_user: "nazoauth_runtime".to_owned(),
        postgres_database: "oauth".to_owned(),
        postgres_validation_image: postgres_image,
        valkey_object: "nazoauth-valkey".to_owned(),
        valkey_volume: "nazoauth-valkey-data".to_owned(),
        valkey_image,
        valkey_rdb_path: "/data/dump.rdb".to_owned(),
        valkey_password_file: None,
        identity,
    };
    let error = crate::runtime_backend::backend_with_command(RuntimeBackendKind::Podman, engine)
        .backup_managed_dependencies(&backup)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("immutable managed-resource identity"),
        "config digest drift returned an unexpected error: {error:#}"
    );
    assert!(
        !marker.exists(),
        "config digest drift reached the backup dump"
    );
}

#[test]
fn privileged_container_task_mounts_are_operation_scoped_and_file_only() {
    let work = PrivateTempDir::new("runtime-task-mounts").unwrap();
    let config = config(&work);
    let runtime = Runtime::new(&config);
    let artifact = ArtifactReference::Oci {
        image_reference: "fixture.invalid/nazoauth".to_owned(),
        digest: format!("sha256:{}", "a".repeat(64)),
    };
    let migration = runtime
        .one_shot_task(artifact.clone(), &TaskOperation::MigrateApply, None)
        .unwrap();

    assert_eq!(
        migration.environment.get("DATABASE_URL_FILE"),
        Some(&"/run/nazoauth-secrets/database-url".to_owned())
    );
    assert!(migration.mounts.iter().any(|mount| {
        mount.source == config.dependencies.migration_database_url_file
            && mount.destination == Path::new("/run/nazoauth-secrets/database-url")
    }));
    assert!(
        !migration
            .mounts
            .iter()
            .any(|mount| mount.destination == Path::new("/var/lib/nazo_oauth/keys"))
    );

    let conformance = runtime
        .one_shot_task(
            artifact.clone(),
            &TaskOperation::ConformanceLeaseCleanup,
            None,
        )
        .unwrap();
    assert!(conformance.mounts.iter().any(|mount| {
        mount.source == config.dependencies.database_url_file
            && mount.destination == Path::new("/run/nazoauth-secrets/database-url")
    }));
    assert!(
        !conformance
            .mounts
            .iter()
            .any(|mount| mount.source == config.dependencies.migration_database_url_file)
    );
    assert!(
        !conformance
            .mounts
            .iter()
            .any(|mount| mount.destination == Path::new("/var/lib/nazo_oauth/keys"))
    );

    let public_jwk = work.path().join("public.jwk");
    let keys = runtime
        .one_shot_task(artifact, &TaskOperation::KeysValidate, Some(&public_jwk))
        .unwrap();

    assert!(
        keys.mounts
            .iter()
            .any(|mount| mount.destination == Path::new("/var/lib/nazo_oauth/keys"))
    );
    assert!(
        keys.mounts
            .iter()
            .any(|mount| mount.destination == Path::new("/run/nazoauth-operator/public.jwk"))
    );
    assert!(!keys.environment.contains_key("DATABASE_URL"));
}

#[cfg(unix)]
#[test]
fn privileged_container_task_attaches_the_signed_envelope_stdin() {
    let work = PrivateTempDir::new("runtime-task-stdin").unwrap();
    let engine = work.path().join("fake-engine");
    let argv = work.path().join("argv.txt");
    let stdin = work.path().join("stdin.txt");
    write_shell_executable(
        &engine,
        &format!(
            "cat > '{}'\nprintf '%s\\n' \"$@\" > '{}'",
            stdin.display(),
            argv.display()
        ),
    );
    let task = OneShotTask {
        artifact: ArtifactReference::Oci {
            image_reference: "fixture.invalid/nazoauth".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        },
        command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
        network: None,
        mounts: Vec::new(),
        environment: BTreeMap::new(),
        working_directory: None,
        service_user: None,
        transient_credentials: BTreeMap::new(),
        read_only_paths: Vec::new(),
        read_write_paths: Vec::new(),
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin: b"signed-envelope".to_vec(),
    };
    runtime_backend::backend_with_command(RuntimeBackendKind::Podman, engine)
        .run_one_shot(&task)
        .unwrap();
    let command = fs::read_to_string(argv).unwrap();

    assert!(command.contains("--interactive"));
    assert_eq!(fs::read(stdin).unwrap(), b"signed-envelope");
}

#[test]
fn privileged_task_fails_closed_without_required_config_mount() {
    let work = PrivateTempDir::new("runtime-missing-mount").unwrap();
    let mut config = config(&work);
    config
        .runtime
        .mounts
        .retain(|mount| mount.target != Path::new("/app/.env.yaml"));

    let error = Runtime::new(&config)
        .one_shot_task(
            ArtifactReference::Oci {
                image_reference: "fixture.invalid/nazoauth".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            &TaskOperation::KeysList,
            None,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime mount /app/.env.yaml is unavailable")
    );
}

#[cfg(unix)]
#[test]
fn retirement_probe_accepts_only_the_closed_runtime_authorization_marker() {
    let work = PrivateTempDir::new("runtime-retirement-probe").unwrap();
    let target = RuntimeTargetClaim::HostBinary {
        path: work.path().join("nazoauth").display().to_string(),
        sha256: "a".repeat(64),
    };
    let rejected = work.path().join("authorization-rejected");
    write_shell_executable(
        &rejected,
        "cat >/dev/null; echo nazoauth-operator-rejection=authorization >&2; exit 1",
    );
    let prepared = PreparedAppTask {
        backend: RuntimeBackendKind::Podman,
        command_override: Some(rejected.into_os_string()),
        task: OneShotTask {
            artifact: ArtifactReference::Oci {
                image_reference: "fixture.invalid/nazoauth".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
            network: None,
            mounts: Vec::new(),
            environment: BTreeMap::new(),
            working_directory: None,
            service_user: None,
            transient_credentials: BTreeMap::new(),
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            inaccessible_paths: Vec::new(),
            private_mounts: false,
            stdin: Vec::new(),
        },
        target: target.clone(),
    };
    prepared
        .expect_authorization_rejection("signed-envelope")
        .unwrap();

    for (name, body) in [
        ("successful", "cat >/dev/null; exit 0"),
        (
            "unrelated-failure",
            "cat >/dev/null; echo unrelated >&2; exit 1",
        ),
    ] {
        let executable = work.path().join(name);
        write_shell_executable(&executable, body);
        let prepared = PreparedAppTask {
            backend: RuntimeBackendKind::Podman,
            command_override: Some(executable.into_os_string()),
            task: OneShotTask {
                artifact: ArtifactReference::Oci {
                    image_reference: "fixture.invalid/nazoauth".to_owned(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                },
                command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
                network: None,
                mounts: Vec::new(),
                environment: BTreeMap::new(),
                working_directory: None,
                service_user: None,
                transient_credentials: BTreeMap::new(),
                read_only_paths: Vec::new(),
                read_write_paths: Vec::new(),
                inaccessible_paths: Vec::new(),
                private_mounts: false,
                stdin: Vec::new(),
            },
            target: target.clone(),
        };
        assert!(
            prepared
                .expect_authorization_rejection("signed-envelope")
                .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn application_container_command_uses_hardening_and_secret_file_references() {
    let work = PrivateTempDir::new("runtime-start-command").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-container-engine");
    let argv = work.path().join("argv.txt");
    let digest = format!("sha256:{}", "a".repeat(64));
    let image = format!("ghcr.io/nazozero/nazoauth@{digest}");
    write_shell_executable(
        &engine,
        &format!(
            "case \"$*\" in\n  *'container inspect'*) printf '%s\\n' 'no such object' >&2; exit 1 ;;\n  *'image inspect'*) printf '%s\\n' '[\"{image}\"]' ;;\n  *) printf '%s\\n' \"$@\" > '{}' ;;\nesac",
            argv.display()
        ),
    );
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(engine.clone());
    let raw_secret = "secret-canary-that-must-not-enter-argv";
    fs::create_dir_all(config.dependencies.database_url_file.parent().unwrap()).unwrap();
    fs::write(&config.dependencies.database_url_file, raw_secret).unwrap();

    Runtime::new(&config).start_container(&image).unwrap();
    let arguments = fs::read_to_string(argv).unwrap();

    for expected in [
        "run",
        "-d",
        "--restart",
        "unless-stopped",
        "--cap-drop",
        "ALL",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "512",
        "--memory",
        "1073741824",
        "--cpus",
        "2.000",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--network",
        "nazo_oauth_net",
        "--ip",
        "10.89.0.20",
        "127.0.0.1:8000:8000",
        "DATABASE_URL_FILE=/run/nazoauth-secrets/database-url",
        "VALKEY_URL_FILE=/run/nazoauth-secrets/valkey-url",
        image.as_str(),
        "nazoauth",
        "server",
    ] {
        assert!(arguments.lines().any(|argument| argument == expected));
    }
    assert!(!arguments.contains(raw_secret));
    assert!(!arguments.contains("DATABASE_URL="));
    assert!(!arguments.contains("VALKEY_URL="));
}

#[cfg(unix)]
#[test]
fn pull_image_executes_the_selected_engine_without_secret_arguments() {
    let work = PrivateTempDir::new("runtime-pull-image").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let argv = work.path().join("argv.txt");
    write_shell_executable(
        &engine,
        &format!("printf '%s\\n' \"$@\" > '{}'", argv.display()),
    );
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(engine.clone());
    let image = "ghcr.io/nazozero/nazoauth@sha256:aaaaaaaa";

    Runtime::new(&config).pull_image(image).unwrap();

    assert_eq!(
        fs::read_to_string(argv).unwrap(),
        format!("pull\n{image}\n")
    );
}

#[cfg(unix)]
#[test]
fn image_digest_accepts_an_exact_repo_digest() {
    let work = PrivateTempDir::new("runtime-repo-digest").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let digest = format!("sha256:{}", "a".repeat(64));
    write_shell_executable(
        &engine,
        &format!("printf '%s\\n' '[\"ghcr.io/nazozero/nazoauth@{digest}\"]'"),
    );
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(engine);
    let image = format!("ghcr.io/nazozero/nazoauth@{digest}");

    assert_eq!(Runtime::new(&config).image_digest(&image).unwrap(), digest);
}

#[cfg(unix)]
#[test]
fn image_digest_rejects_unpinned_invalid_and_unretained_references() {
    let work = PrivateTempDir::new("runtime-rejected-digests").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    write_shell_executable(&engine, "printf '%s\\n' '[]'");
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(engine.clone());
    let runtime = Runtime::new(&config);

    for (image, expected) in [
        (
            "ghcr.io/nazozero/nazoauth:v0.2.0".to_owned(),
            "managed OCI image reference is not pinned by digest",
        ),
        (
            format!("ghcr.io/nazozero/nazoauth@sha256:{}", "a".repeat(63)),
            "managed OCI image reference has an invalid digest",
        ),
        (
            format!("ghcr.io/nazozero/nazoauth@sha256:{}g", "a".repeat(63)),
            "managed OCI image reference has an invalid digest",
        ),
    ] {
        assert_eq!(
            runtime.image_digest(&image).unwrap_err().to_string(),
            expected
        );
    }

    let valid_but_missing = format!("ghcr.io/nazozero/nazoauth@sha256:{}", "b".repeat(64));
    assert_eq!(
        runtime
            .image_digest(&valid_but_missing)
            .unwrap_err()
            .to_string(),
        "container engine did not retain the signed OCI digest"
    );

    write_shell_executable(&engine, "printf '%s\\n' 'not-json'");
    assert_eq!(
        runtime
            .image_digest(&valid_but_missing)
            .unwrap_err()
            .to_string(),
        "container engine did not retain the signed OCI digest"
    );
}

#[cfg(unix)]
#[test]
fn podman_image_digest_uses_the_engine_digest_fallback() {
    const CHILD: &str = "NAZOAUTHCTL_TEST_PODMAN_DIGEST_FALLBACK";
    let digest = format!("sha256:{}", "c".repeat(64));
    if std::env::var_os(CHILD).is_some() {
        let work = PrivateTempDir::new("runtime-podman-digest-child").unwrap();
        let mut config = config(&work);
        config.runtime.backend = RuntimeBackendKind::Podman;
        let image = format!("ghcr.io/nazozero/nazoauth@{digest}");
        assert_eq!(Runtime::new(&config).image_digest(&image).unwrap(), digest);
        return;
    }

    let work = PrivateTempDir::new("runtime-podman-digest").unwrap();
    let bin = work.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let engine = bin.join("podman");
    write_shell_executable(
        &engine,
        &format!(
            "case \"$5\" in\n  *RepoDigests*) printf '%s\\n' '[]' ;;\n  *) printf '%s\\n' '{digest}' ;;\nesac"
        ),
    );
    let mut paths = vec![bin];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::podman_image_digest_uses_the_engine_digest_fallback",
            "--nocapture",
        ])
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("NAZOAUTHCTL_TESTING", "1")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn podman_image_digest_rejects_a_mismatched_fallback_digest() {
    const CHILD: &str = "NAZOAUTHCTL_TEST_PODMAN_DIGEST_MISMATCH";
    let image = format!("ghcr.io/nazozero/nazoauth@sha256:{}", "e".repeat(64));
    if std::env::var_os(CHILD).is_some() {
        let work = PrivateTempDir::new("runtime-podman-mismatch-child").unwrap();
        let mut config = config(&work);
        config.runtime.backend = RuntimeBackendKind::Podman;
        assert_eq!(
            Runtime::new(&config)
                .image_digest(&image)
                .unwrap_err()
                .to_string(),
            "container engine retained a different OCI digest"
        );
        return;
    }

    let work = PrivateTempDir::new("runtime-podman-mismatch").unwrap();
    let bin = work.path().join("bin");
    fs::create_dir(&bin).unwrap();
    write_shell_executable(
        &bin.join("podman"),
        &format!(
            "case \"$5\" in\n  *RepoDigests*) printf '%s\\n' '[]' ;;\n  *) printf '%s\\n' 'sha256:{}' ;;\nesac",
            "d".repeat(64)
        ),
    );
    let mut paths = vec![bin];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::podman_image_digest_rejects_a_mismatched_fallback_digest",
            "--nocapture",
        ])
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("NAZOAUTHCTL_TESTING", "1")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn embedded_identity_json() -> String {
    serde_json::to_string(&nazo_operator_protocol::EmbeddedIdentity {
        release: "v0.2.0".to_owned(),
        revision: "f".repeat(40),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "build:test".to_owned(),
    })
    .unwrap()
}

#[cfg(unix)]
#[test]
fn embedded_identity_executes_host_binary_directly() {
    let work = PrivateTempDir::new("runtime-host-identity").unwrap();
    let mut config = config(&work);
    config.runtime.backend = RuntimeBackendKind::Systemd;
    let binary = work.path().join("nazoauth");
    let argv = work.path().join("argv.txt");
    write_shell_executable(
        &binary,
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' '{}'",
            argv.display(),
            embedded_identity_json()
        ),
    );

    let identity = Runtime::new(&config)
        .embedded_identity(&binary.to_string_lossy())
        .unwrap();

    assert_eq!(identity.release, "v0.2.0");
    assert_eq!(fs::read_to_string(argv).unwrap(), "build-identity\n");
}

#[cfg(unix)]
#[test]
fn embedded_identity_container_is_networkless_and_hardened() {
    let work = PrivateTempDir::new("runtime-container-identity").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let argv = work.path().join("argv.txt");
    let digest = format!("sha256:{}", "f".repeat(64));
    let image = format!("ghcr.io/nazozero/nazoauth@{digest}");
    write_shell_executable(
        &engine,
        &format!(
            "case \"$*\" in\n  *'image inspect'*) printf '%s\\n' '[\"{image}\"]' ;;\n  *) printf '%s\\n' \"$@\" > '{}'; printf '%s\\n' '{}' ;;\nesac",
            argv.display(),
            embedded_identity_json()
        ),
    );
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(engine);
    let identity = Runtime::new(&config).embedded_identity(&image).unwrap();
    let arguments = fs::read_to_string(argv).unwrap();

    assert_eq!(identity.release, "v0.2.0");
    for expected in [
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "no-new-privileges",
        "--read-only",
        image.as_str(),
        "nazoauth",
        "build-identity",
    ] {
        assert!(arguments.lines().any(|argument| argument == expected));
    }
}

#[cfg(unix)]
#[test]
fn embedded_identity_rejects_invalid_application_output() {
    let work = PrivateTempDir::new("runtime-invalid-identity").unwrap();
    let mut config = config(&work);
    config.runtime.backend = RuntimeBackendKind::Systemd;
    let binary = work.path().join("nazoauth");
    write_shell_executable(&binary, "printf '%s\\n' 'not-json'");

    let error = Runtime::new(&config)
        .embedded_identity(&binary.to_string_lossy())
        .unwrap_err();
    assert!(format!("{error:#}").contains("runtime embedded build identity is invalid"));
}
