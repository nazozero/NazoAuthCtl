//! Shared command construction and parsing for OCI container backends.
//!
//! Docker and Podman intentionally keep their runtime-specific discovery and
//! lifecycle details in their respective façades.  The command policy,
//! ownership checks, one-shot setup, and digest parsing are the same security
//! rules for both engines, so they live here to keep the two backends from
//! drifting.

use std::{ffi::OsStr, time::Duration};

use crate::process::Process;
use anyhow::{Context as _, bail};

use super::{
    ContainerRestartPolicy, ContainerRuntimePolicy, ManagedValkeyRestore, NeutralMount,
    OneShotTask, managed_config_digest,
};

mod managed_dependencies;
mod policy;

pub use managed_dependencies::oci_backup_digests;
pub(crate) use managed_dependencies::{
    TemporaryPostgresCredentials, backup_managed_dependencies, load_dependency_restore_journal,
    persist_dependency_restore_journal, postgres_database_from_service_file,
    temporary_postgres_credentials, validate_sql_identifier, verify_oci_backup_artifacts,
};
pub(crate) use policy::{
    append_container_policy, append_managed_labels, assert_container_image, assert_managed_labels,
    command_stdout, container_is_running, ensure_container, ensure_volume, inspect_document,
    inspect_document_optional, inspect_managed_container_id, is_engine_unavailable_error,
    network_config_digest, network_gateway, prepare_managed_volume_ownership,
    quiesce_managed_one_shot, reconcile_bound_file, remove_managed_container_by_id,
    remove_managed_container_by_name, require_digest_pinned_image,
};
#[cfg(all(test, unix))]
use policy::{assert_managed_container_policy, observed_cap_drop_all};

/// Numeric uid/gid used for OCI one-shot work.  A name supplied by an image
/// is not an authorization boundary: the caller must provide the explicit
/// uid:gid contract and the engine must accept it.
pub(crate) const NON_ROOT_ONE_SHOT_USER: &str = "10001:10001";
pub(crate) const VALKEY_RESTORE_CHECK_RESOURCE_KIND: &str = "valkey-restore-check";

pub(crate) fn valkey_restore_check_config_digest(
    restore: &ManagedValkeyRestore,
    volume: &str,
    container: &str,
) -> String {
    managed_config_digest(
        VALKEY_RESTORE_CHECK_RESOURCE_KIND,
        &[
            ("image", restore.image.as_str()),
            ("volume", volume),
            ("container", container),
            ("network", "none"),
            ("port", "6379"),
            ("server-mode", "protected-mode=off;save=;appendonly=no"),
        ],
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use crate::runtime_backend::{ManagedDependencyBackup, managed_dependency_identity};
    use crate::{
        filesystem::PrivateTempDir, process::Process, runtime_backend::ManagedNetwork,
        test_support::write_shell_executable,
    };

    #[test]
    fn container_lookup_cannot_resolve_a_volume_with_the_container_name_as_prefix() {
        let work = PrivateTempDir::new("runtime-container-inspect-type").unwrap();
        let engine = work.path().join("fake-podman");
        let generic_marker = work.path().join("generic-inspect-was-used");
        let create_argv = work.path().join("create-argv");
        write_shell_executable(
            &engine,
            &format!(
                "if [ \"$*\" = 'container inspect managed-postgres --format {{{{json .}}}}' ]; then printf '%s\\n' 'no such object' >&2; exit 1; fi\nif [ \"$*\" = 'inspect managed-postgres' ]; then : > '{}'; exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\n",
                generic_marker.display(),
                create_argv.display(),
            ),
        );
        let network = ManagedNetwork {
            name: "managed-network".to_owned(),
            subnet: None,
            deployment_id: "deployment-test".to_owned(),
            control_authority: "controller-test".to_owned(),
        };
        super::ensure_container(
            engine.as_os_str(),
            "managed-postgres",
            &network,
            "runtime-test",
            "postgres",
            &format!("sha256:{}", "c".repeat(64)),
            "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Process::new(engine.as_os_str()).args(["run", "--name", "managed-postgres"]),
            "Podman",
            &super::ContainerRuntimePolicy::managed_default(),
            &[],
            &[],
        )
        .unwrap();
        assert!(!generic_marker.exists());
        assert_eq!(
            fs::read_to_string(create_argv).unwrap(),
            "run\n--name\nmanaged-postgres\n"
        );
    }

    #[test]
    fn image_identity_uses_valid_engine_templates() {
        let work = PrivateTempDir::new("runtime-image-inspect-template").unwrap();
        let engine = work.path().join("fake-podman");
        let expected = "docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        write_shell_executable(
            &engine,
            "if [ \"$*\" = 'container inspect managed-postgres --format {{json .}}' ]; then\n  printf '%s\\n' '{\"Config\":{\"Image\":\"docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'\n  exit 0\nfi\nexit 1",
        );
        super::assert_container_image(
            engine.as_os_str(),
            &["container", "inspect", "managed-postgres"],
            expected,
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn managed_identity_accepts_podman_lowercase_label_surface() {
        let work = PrivateTempDir::new("runtime-podman-label-surface").unwrap();
        let engine = work.path().join("fake-podman");
        write_shell_executable(
            &engine,
            "printf '%s\n' '{\"labels\":{\"io.nazoauth.deployment-id\":\"deployment-test\",\"io.nazoauth.control-authority\":\"controller-test\",\"io.nazoauth.managed-resource\":\"network\",\"io.nazoauth.config-digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'",
        );
        super::assert_managed_labels(
            engine.as_os_str(),
            &["network", "inspect", "managed-network"],
            "deployment-test",
            "controller-test",
            None,
            "network",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn managed_dependency_policy_runs_services_as_the_image_non_root_identity() {
        let work = PrivateTempDir::new("runtime-managed-service-user").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );
        super::append_container_policy(
            Process::new(engine.as_os_str()).arg("run"),
            &super::ContainerRuntimePolicy::managed_postgres(),
        )
        .run_quiet()
        .unwrap();
        let arguments = fs::read_to_string(arguments).unwrap();
        assert!(arguments.contains("--user\n999:999\n"));
        assert!(arguments.contains("--cap-drop=ALL\n"));
        assert!(arguments.contains("--read-only\n"));
    }

    #[test]
    fn build_identity_policy_is_closed_before_the_image_positional() {
        let work = PrivateTempDir::new("runtime-build-identity-order").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );
        let image = "example.invalid/nazoauth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        super::build_identity_process(engine.as_os_str())
            .args(["--network", "none"])
            .arg(image)
            .arg("nazoauth")
            .arg("build-identity")
            .run_quiet()
            .unwrap();

        let arguments = fs::read_to_string(arguments).unwrap();
        let arguments = arguments.lines().collect::<Vec<_>>();
        let policy = arguments
            .iter()
            .position(|argument| *argument == "--cap-drop=ALL")
            .unwrap();
        let image = arguments
            .iter()
            .position(|argument| *argument == image)
            .unwrap();
        assert!(policy < image);
        assert!(!arguments.contains(&"ALL"));
    }

    #[test]
    fn managed_volume_copy_has_only_offline_filesystem_capabilities() {
        let work = PrivateTempDir::new("runtime-managed-volume-copy").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );

        super::build_managed_volume_copy_process(engine.as_os_str())
            .arg("example.invalid/valkey@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .args(["sh", "-c", "cp -a /source/. /destination/"])
            .run_quiet()
            .unwrap();

        let arguments = fs::read_to_string(arguments).unwrap();
        assert!(arguments.contains("--user\n0:0\n"));
        assert!(arguments.contains("--network\nnone\n"));
        assert!(arguments.contains("--read-only\n"));
        assert!(arguments.contains("--cap-drop\nALL\n"));
        assert!(arguments.contains("--cap-add\nCHOWN\n"));
        assert!(arguments.contains("--cap-add\nDAC_OVERRIDE\n"));
        assert!(arguments.contains("--cap-add\nFOWNER\n"));
        assert!(arguments.contains("--security-opt\nno-new-privileges\n"));
        assert!(!arguments.contains("NET_ADMIN"));
        assert!(!arguments.contains("SYS_ADMIN"));
    }

    #[test]
    fn podman_expanded_cap_drop_all_is_recognized_without_accepting_partial_sets() {
        let complete = [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ]
        .into_iter()
        .map(serde_json::Value::from)
        .collect::<Vec<_>>();
        assert!(super::observed_cap_drop_all(&complete));
        assert!(!super::observed_cap_drop_all(&complete[..10]));
    }

    #[test]
    fn managed_valkey_backup_reads_auth_from_stdin_without_a_secret_environment_variable() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("managed-valkey-backup-auth").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let engine = work.path().join("fake-podman");
        let argv = work.path().join("argv");
        let lastsave_seen = work.path().join("lastsave-seen");
        let password_file = work.path().join("valkey-password");
        fs::create_dir(work.path().join("backup")).unwrap();
        chown(work.path().join("backup"), Some(0), Some(10001)).unwrap();
        fs::set_permissions(
            work.path().join("backup"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::write(&password_file, "secret-canary").unwrap();
        fs::set_permissions(&password_file, fs::Permissions::from_mode(0o400)).unwrap();
        write_shell_executable(
            &engine,
            &format!(
                "case \"$*\" in *--interactive*) IFS= read -r _ || true ;; esac\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  *LASTSAVE*) if [ -e '{}' ]; then printf '101\\n'; else : > '{}'; printf '100\\n'; fi ;;\n  *) if [ \"$1\" = cp ]; then : > \"$3\"; fi; exit 0 ;;\nesac",
                argv.display(),
                lastsave_seen.display(),
                lastsave_seen.display(),
            ),
        );
        let postgres_image = format!("postgres@sha256:{}", "a".repeat(64));
        let valkey_image = format!("valkey@sha256:{}", "b".repeat(64));
        let backup = ManagedDependencyBackup {
            destination: work.path().join("backup"),
            network: "managed-network".to_owned(),
            postgres_object: "managed-postgres".to_owned(),
            postgres_volume: "managed-postgres-data".to_owned(),
            postgres_image: postgres_image.clone(),
            postgres_user: "nazoauth_runtime".to_owned(),
            postgres_database: "oauth".to_owned(),
            postgres_validation_image: postgres_image.clone(),
            valkey_object: "managed-valkey".to_owned(),
            valkey_volume: "managed-valkey-data".to_owned(),
            valkey_image: valkey_image.clone(),
            valkey_rdb_path: "/data/dump.rdb".to_owned(),
            valkey_password_file: Some(password_file),
            valkey_user: Some(super::super::MANAGED_VALKEY_BACKUP_USER.to_owned()),
            identity: managed_dependency_identity(
                "deployment-test",
                "controller-test",
                "runtime-test",
                "managed-network",
                None,
                "managed-postgres",
                "managed-postgres-data",
                &postgres_image,
                "oauth",
                "nazoauth_runtime",
                "managed-valkey",
                "managed-valkey-data",
                &valkey_image,
            ),
        };
        super::backup_managed_dependencies(engine.as_os_str(), &backup, true).unwrap();
        let arguments = fs::read_to_string(argv).unwrap();
        assert!(arguments.contains("valkey-cli --user nazoauth_backup --askpass"));
        assert!(!arguments.contains("VALKEYCLI_AUTH"));
        assert!(!arguments.contains("REDISCLI_AUTH"));
        assert!(!arguments.contains("secret-canary"));
    }

    #[test]
    fn managed_restore_journal_rejects_backend_drift() {
        let work = PrivateTempDir::new("managed-restore-journal-drift").unwrap();
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("SHA256SUMS"), b"placeholder\n").unwrap();
        let image = format!("postgres@sha256:{}", "a".repeat(64));
        let identity = managed_dependency_identity(
            "deployment-test",
            "controller-test",
            "runtime-test",
            "managed-network",
            None,
            "managed-postgres",
            "managed-postgres-data",
            &image,
            "oauth",
            "nazoauth_runtime",
            "managed-valkey",
            "managed-valkey-data",
            &format!("valkey@sha256:{}", "b".repeat(64)),
        );
        let (path, journal) =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap();
        super::persist_dependency_restore_journal(&path, &journal).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Podman", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
        let mut tampered = journal.clone();
        tampered.deployment_id = "other-deployment".to_owned();
        super::persist_dependency_restore_journal(&path, &tampered).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
    }

    #[test]
    fn managed_container_surface_rejects_extra_mounts_and_environment() {
        let policy = super::ContainerRuntimePolicy::managed_default();
        let tmpfs = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216"
        });
        for (extra_mount, extra_env, expected_error) in [
            (true, false, "undeclared mount"),
            (false, true, "undeclared environment"),
        ] {
            let work = PrivateTempDir::new("managed-container-surface").unwrap();
            let engine = work.path().join("fake-engine");
            let mut mounts = vec![serde_json::json!({
                "Destination": "/data",
                "RW": true,
                "Source": "managed-data"
            })];
            if extra_mount {
                mounts.push(serde_json::json!({
                    "Destination": "/unexpected",
                    "RW": true,
                    "Source": "unexpected"
                }));
            }
            let mut environment = vec!["POSTGRES_DB=oauth", "PATH=/usr/local/bin"];
            if extra_env {
                environment.push("UNDECLARED=value");
            }
            let document = serde_json::json!({
                "HostConfig": {
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "ReadonlyRootfs": true,
                    "SecurityOpt": ["no-new-privileges"],
                    "CapDrop": ["ALL"],
                    "PidsLimit": 512,
                    "Memory": 1073741824_i64,
                    "NanoCpus": 2000000000_i64,
                    "Tmpfs": tmpfs.clone(),
                },
                "NetworkSettings": {"Networks": {"managed-network": {}}},
                "Mounts": mounts,
                "Config": {"Env": environment},
            });
            write_shell_executable(&engine, &format!("printf '%s\\n' '{}'", document));
            let error = super::assert_managed_container_policy(
                engine.as_os_str(),
                &["container", "inspect", "managed"],
                "Docker",
                &policy,
                "managed-network",
                &[("/data", false, Some("managed-data"))],
                &[("POSTGRES_DB", "oauth")],
                &std::collections::BTreeMap::from([(
                    "PATH".to_owned(),
                    "/usr/local/bin".to_owned(),
                )]),
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn oci_backup_completion_and_artifact_digests_are_bound() {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("oci-backup-completion-bound").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        chown(&backup, Some(0), Some(10001)).unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o750)).unwrap();
        let payload = backup.join("payload");
        fs::write(&payload, b"payload").unwrap();
        let digest = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let payload_digest = digest(b"payload");
        fs::write(
            backup.join("SHA256SUMS"),
            format!("{payload_digest}  payload\n"),
        )
        .unwrap();
        let manifest_bytes = fs::read(backup.join("SHA256SUMS")).unwrap();
        let manifest_digest = digest(&manifest_bytes);
        fs::write(
            backup.join("BACKUP-COMPLETE"),
            format!("marker=BACKUP-COMPLETE\nversion=1\nmanifest-sha256={manifest_digest}\n"),
        )
        .unwrap();
        for name in ["payload", "SHA256SUMS", "BACKUP-COMPLETE"] {
            let path = backup.join(name);
            chown(&path, Some(0), Some(10001)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        }
        let marker_digest = digest(&fs::read(backup.join("BACKUP-COMPLETE")).unwrap());
        super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest).unwrap();
        fs::write(&payload, b"tampered").unwrap();
        let error = super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest)
            .unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }
}

pub(crate) fn append_mounts(mut command: Process, mounts: &[NeutralMount]) -> Process {
    for mount in mounts {
        let access = if mount.read_only { "ro" } else { "rw" };
        let relabel = if mount.selinux_relabel { ",Z" } else { "" };
        command = command.arg("--volume").arg(format!(
            "{}:{}:{access}{relabel}",
            mount.source.display(),
            mount.destination.display()
        ));
    }
    command
}

pub(crate) fn one_shot_process(
    command: &OsStr,
    task: &OneShotTask,
    backend_name: &str,
) -> anyhow::Result<Process> {
    let super::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &task.artifact
    else {
        bail!("{backend_name} one-shot task requires a digest-bound OCI artifact");
    };
    let image = normalize_local_image_id(image_reference, false).unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let user = task
        .service_user
        .as_deref()
        .context("OCI one-shot task requires an explicit non-root UID:GID")?;
    validate_non_root_user(user, backend_name)?;
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    let mut process = append_container_policy(
        Process::new(command)
            .timeout(Duration::from_secs(300))
            .args(["run", "--rm", "--interactive"]),
        &policy,
    );
    if let Some(identity) = &task.managed_identity {
        process = process.arg("--name").arg(&identity.name);
        for (key, value) in &identity.labels {
            process = process.arg("--label").arg(format!("{key}={value}"));
        }
    }
    let process = process
        .arg("--user")
        .arg(user)
        .arg("--network")
        .arg(task.network.as_deref().unwrap_or("none"));
    if let Some(directory) = &task.working_directory {
        process = process.arg("--workdir").arg(directory);
    }
    for (name, value) in &task.environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    Ok(append_mounts(process, &task.mounts)
        .arg(image)
        .args(&task.command))
}

/// Start a hardened one-shot container command before any caller-controlled
/// engine options or image reference are appended.
///
/// Taking the engine binary rather than a partially assembled `Process`
/// makes it impossible to append policy flags after the image positional.
pub(crate) fn build_identity_process(command: &OsStr) -> Process {
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    append_container_policy(Process::new(command).args(["run", "--rm"]), &policy)
        .arg("--user")
        .arg(NON_ROOT_ONE_SHOT_USER)
}

/// Build the narrowly privileged process used to copy an already-validated
/// managed data volume.  Dependency images write their data as image-specific
/// UIDs (for example Valkey uses 999:1000), so the fixed non-root identity used
/// by ordinary one-shot probes cannot read a mode-0600 source or preserve its
/// ownership.  The copy remains offline, read-only at the container root, and
/// receives only the filesystem capabilities required by `cp -a`.
pub(crate) fn build_managed_volume_copy_process(command: &OsStr) -> Process {
    Process::new(command).args([
        "run",
        "--rm",
        "--user",
        "0:0",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "FOWNER",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "134217728",
        "--cpus",
        "1.000",
    ])
}

fn validate_non_root_user(user: &str, backend_name: &str) -> anyhow::Result<()> {
    let Some((uid, gid)) = user.split_once(':') else {
        bail!("{backend_name} one-shot user must be an explicit UID:GID");
    };
    if uid.is_empty()
        || gid.is_empty()
        || !uid.chars().all(|value| value.is_ascii_digit())
        || !gid.chars().all(|value| value.is_ascii_digit())
        || uid.parse::<u32>().ok().is_none_or(|value| value == 0)
        || gid.parse::<u32>().ok().is_none_or(|value| value == 0)
    {
        bail!("{backend_name} one-shot user must be a non-root UID:GID");
    }
    Ok(())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

pub(crate) fn requested_digest_matches(image_reference: &str, digest: &str) -> bool {
    let Some((_, requested)) = image_reference.rsplit_once('@') else {
        return true;
    };
    requested.eq_ignore_ascii_case(digest)
}

/// Normalize an engine's local image identity.  Docker emits `sha256:...`;
/// Podman may emit the same digest without the algorithm prefix.
pub fn normalize_local_image_id(value: &str, allow_bare_digest: bool) -> Option<String> {
    if allow_bare_digest {
        let digest = value.strip_prefix("sha256:").unwrap_or(value);
        return (digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        .then(|| format!("sha256:{}", digest.to_ascii_lowercase()));
    }
    let normalized = value.to_ascii_lowercase();
    valid_digest(&normalized).then_some(normalized)
}

#[cfg(test)]
mod policy_tests {
    use super::{
        ContainerRestartPolicy, ContainerRuntimePolicy, NON_ROOT_ONE_SHOT_USER,
        requested_digest_matches, validate_non_root_user,
    };

    #[test]
    fn requested_digest_cannot_be_replaced_by_another_repo_digest() {
        let image = "registry.example/nazoauth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(requested_digest_matches(
            image,
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!requested_digest_matches(
            image,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(requested_digest_matches(
            "registry.example/nazoauth:stable",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[test]
    fn one_shot_user_contract_rejects_root_and_names() {
        assert!(validate_non_root_user(NON_ROOT_ONE_SHOT_USER, "Docker").is_ok());
        assert!(validate_non_root_user("0:0", "Docker").is_err());
        assert!(validate_non_root_user("nobody", "Docker").is_err());
        assert!(validate_non_root_user("65532", "Docker").is_err());
    }

    #[test]
    fn managed_policy_has_explicit_resource_and_restart_bounds() {
        let policy = ContainerRuntimePolicy::managed_default();
        assert_eq!(policy.restart, ContainerRestartPolicy::UnlessStopped);
        assert!(policy.read_only_root);
        assert!(policy.no_new_privileges);
        assert!(policy.drop_all_capabilities);
        assert_eq!(policy.pids_limit, Some(512));
        assert_eq!(policy.memory_limit_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(policy.cpu_limit_millis, Some(2_000));
        assert_eq!(policy.tmpfs.len(), 2);
        assert_eq!(
            policy.tmpfs[1].destination,
            std::path::Path::new("/run/postgresql")
        );
    }

    #[test]
    fn application_policy_requires_the_controller_owned_uid_and_gid() {
        assert_eq!(
            ContainerRuntimePolicy::managed_app()
                .service_user
                .as_deref(),
            Some("10001:10001")
        );
    }
}
