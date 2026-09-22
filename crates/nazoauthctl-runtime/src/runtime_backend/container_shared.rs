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

use super::{ContainerRestartPolicy, ContainerRuntimePolicy, NeutralMount, OneShotTask};

mod policy;
mod recovery;

#[cfg(all(test, unix))]
use policy::observed_cap_drop_all;
pub(crate) use policy::{
    append_container_policy, assert_container_image, assert_managed_container_policy,
    command_stdout, inspect_document, inspect_document_optional, inspect_image_environment,
    is_engine_unavailable_error,
};
pub(crate) use recovery::{cleanup_recovery_candidate, stage_recovery_candidate};

/// Numeric uid/gid used for OCI one-shot work.  A name supplied by an image
/// is not an authorization boundary: the caller must provide the explicit
/// uid:gid contract and the engine must accept it.
pub const NON_ROOT_ONE_SHOT_USER: &str = "10001:10001";

pub(crate) fn append_cosign_sandbox(process: Process) -> Process {
    process
        .args(["--user", NON_ROOT_ONE_SHOT_USER])
        .arg("--cap-drop=ALL")
        .args(["--read-only", "--security-opt=no-new-privileges"])
        .args(["--pids-limit", "64", "--memory", "256m", "--cpus", "1"])
        .args(["--env", "HOME=/tmp/cosign-home", "--tmpfs"])
        .arg("/tmp/cosign-home:rw,noexec,nosuid,nodev,size=16m")
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use crate::runtime_backend::{ArtifactReference, OneShotTask};
    use crate::{filesystem::PrivateTempDir, test_support::write_shell_executable};

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
            &super::inspect_document(
                engine.as_os_str(),
                &["container", "inspect", "managed-postgres"],
                "test",
            )
            .unwrap(),
            expected,
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn one_shot_host_gateway_mapping_precedes_the_image() {
        let work = PrivateTempDir::new("runtime-one-shot-host-gateway").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );
        let image = format!("sha256:{}", "a".repeat(64));
        let digest = image.clone();
        let task = OneShotTask {
            artifact: ArtifactReference::Oci {
                image_reference: image.clone(),
                digest,
            },
            command: vec!["nazoauth".to_owned(), "migrate".to_owned()],
            network: Some("bridge".to_owned()),
            mounts: Vec::new(),
            environment: std::collections::BTreeMap::new(),
            working_directory: None,
            service_user: Some(super::NON_ROOT_ONE_SHOT_USER.to_owned()),
            transient_credentials: std::collections::BTreeMap::new(),
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            inaccessible_paths: Vec::new(),
            private_mounts: false,
            stdin: Vec::new(),
        };

        super::one_shot_process(
            engine.as_os_str(),
            &task,
            "Docker",
            false,
            Some("host.docker.internal:host-gateway"),
        )
        .unwrap()
        .run_quiet()
        .unwrap();

        let arguments = fs::read_to_string(arguments).unwrap();
        let arguments = arguments.lines().collect::<Vec<_>>();
        let mapping = arguments
            .iter()
            .position(|argument| *argument == "host.docker.internal:host-gateway")
            .unwrap();
        let image = arguments
            .iter()
            .position(|argument| *argument == image)
            .unwrap_or_else(|| panic!("one-shot image is absent from {arguments:?}"));
        assert!(mapping < image);
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
                &super::inspect_document(
                    engine.as_os_str(),
                    &["container", "inspect", "managed"],
                    "test",
                )
                .unwrap(),
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
    fn podman_tmpfs_inspect_normalizes_only_its_non_security_metadata() {
        fn assert_tmpfs_policy(tmpfs: serde_json::Value, backend: &str) -> anyhow::Result<()> {
            let work = PrivateTempDir::new("managed-container-tmpfs-inspect").unwrap();
            let engine = work.path().join("fake-engine");
            let document = serde_json::json!({
                "HostConfig": {
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "ReadonlyRootfs": true,
                    "SecurityOpt": ["no-new-privileges"],
                    "CapDrop": ["ALL"],
                    "PidsLimit": 512,
                    "Memory": 1073741824_i64,
                    "NanoCpus": 2000000000_i64,
                    "Tmpfs": tmpfs,
                },
                "NetworkSettings": {"Networks": {"managed-network": {}}},
                "Mounts": [{
                    "Destination": "/data",
                    "RW": true,
                    "Source": "managed-data"
                }],
                "Config": {"Env": ["POSTGRES_DB=oauth", "PATH=/usr/local/bin"]},
            });
            write_shell_executable(&engine, &format!("printf '%s\\n' '{}'", document));
            super::assert_managed_container_policy(
                &super::inspect_document(
                    engine.as_os_str(),
                    &["container", "inspect", "managed"],
                    "test",
                )
                .unwrap(),
                backend,
                &super::ContainerRuntimePolicy::managed_default(),
                "managed-network",
                &[("/data", false, Some("managed-data"))],
                &[("POSTGRES_DB", "oauth")],
                &std::collections::BTreeMap::from([(
                    "PATH".to_owned(),
                    "/usr/local/bin".to_owned(),
                )]),
            )
        }

        let podman_tmpfs = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864,rprivate,tmpcopyup",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216,rprivate,tmpcopyup",
        });
        assert_tmpfs_policy(podman_tmpfs.clone(), "Podman").unwrap();
        assert!(assert_tmpfs_policy(podman_tmpfs, "Docker").is_err());

        let unknown_token = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864,rprivate,tmpcopyup,unknown",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216,rprivate,tmpcopyup",
        });
        assert!(assert_tmpfs_policy(unknown_token, "Podman").is_err());

        let relaxed_permissions = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,size=67108864,rprivate,tmpcopyup",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216,rprivate,tmpcopyup",
        });
        assert!(assert_tmpfs_policy(relaxed_permissions, "Podman").is_err());

        let duplicate_option = serde_json::json!({
            "/tmp": "rw,rw,noexec,nosuid,nodev,size=67108864,rprivate,tmpcopyup",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216,rprivate,tmpcopyup",
        });
        assert!(assert_tmpfs_policy(duplicate_option, "Podman").is_err());
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
    rootless_user_namespace: bool,
    host_gateway_mapping: Option<&str>,
) -> anyhow::Result<Process> {
    let super::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &task.artifact
    else {
        bail!("{backend_name} one-shot task requires a digest-bound OCI artifact");
    };
    let image = runnable_oci_image(image_reference, digest, None);
    let user = task
        .service_user
        .as_deref()
        .context("OCI one-shot task requires an explicit non-root UID:GID")?;
    validate_non_root_user(user, backend_name)?;
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    let process = Process::new(command)
        .timeout(Duration::from_secs(300))
        .args(["run", "--rm", "--interactive"]);
    let process = if rootless_user_namespace {
        process.arg("--userns=keep-id:uid=10001,gid=10001")
    } else {
        process
    };
    let network = match task.network.as_deref() {
        Some("bridge" | "pasta") if rootless_user_namespace => "pasta:--map-gw",
        Some(network) => network,
        None => "none",
    };
    let mut process = append_container_policy(process, &policy)
        .arg("--user")
        .arg(user)
        .arg("--network")
        .arg(network);
    if let Some(mapping) = host_gateway_mapping {
        process = process.args(["--add-host", mapping]);
    }
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

pub(crate) fn runnable_oci_image(
    image_reference: &str,
    digest: &str,
    local_artifact_id: Option<&str>,
) -> String {
    local_artifact_id
        .map(ToOwned::to_owned)
        .or_else(|| normalize_local_image_id(image_reference, true))
        .unwrap_or_else(|| {
            format!(
                "{}@{}",
                image_reference.split('@').next().unwrap_or(image_reference),
                digest
            )
        })
}

#[cfg(test)]
mod policy_tests {
    use super::{
        ContainerRestartPolicy, ContainerRuntimePolicy, NON_ROOT_ONE_SHOT_USER,
        requested_digest_matches, runnable_oci_image, validate_non_root_user,
    };

    #[test]
    fn runnable_oci_image_preserves_local_ids_and_pins_named_references() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(runnable_oci_image(&digest, &digest, None), digest);
        assert_eq!(
            runnable_oci_image("registry.example/nazoauth:candidate", &digest, None),
            format!("registry.example/nazoauth:candidate@{digest}")
        );
        assert_eq!(
            runnable_oci_image(
                "registry.example/nazoauth:candidate",
                &digest,
                Some("sha256:local")
            ),
            "sha256:local"
        );
    }

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
