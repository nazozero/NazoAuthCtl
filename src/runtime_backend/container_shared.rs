//! Shared command construction and parsing for OCI container backends.
//!
//! Docker and Podman intentionally keep their runtime-specific discovery and
//! lifecycle details in their respective façades.  The command policy,
//! ownership checks, one-shot setup, and digest parsing are the same security
//! rules for both engines, so they live here to keep the two backends from
//! drifting.

use std::{ffi::OsStr, thread, time::Duration};

use anyhow::{Context as _, bail};

use crate::process::Process;

use super::{
    ContainerRestartPolicy, ContainerRuntimePolicy, ManagedDependencyBackup, ManagedNetwork,
    NeutralMount, OneShotTask, managed_network_config_digest,
};

const DEPLOYMENT_LABEL: &str = "io.nazoauth.deployment-id";
const AUTHORITY_LABEL: &str = "io.nazoauth.control-authority";
const RUNTIME_INSTANCE_LABEL: &str = "io.nazoauth.runtime-instance-id";
const RESOURCE_KIND_LABEL: &str = "io.nazoauth.managed-resource";
const CONFIG_DIGEST_LABEL: &str = "io.nazoauth.config-digest";

pub(crate) fn network_config_digest(network: &ManagedNetwork) -> String {
    managed_network_config_digest(
        &network.deployment_id,
        &network.control_authority,
        &network.name,
    )
}

/// Build the common hardening flags used by managed containers.
pub(crate) fn append_container_policy(
    mut command: Process,
    policy: &ContainerRuntimePolicy,
) -> Process {
    command = match policy.restart {
        ContainerRestartPolicy::No => command,
        ContainerRestartPolicy::OnFailure => command.args(["--restart", "on-failure"]),
        ContainerRestartPolicy::Always => command.args(["--restart", "always"]),
        ContainerRestartPolicy::UnlessStopped => command.args(["--restart", "unless-stopped"]),
    };
    if policy.drop_all_capabilities {
        command = command.args(["--cap-drop", "ALL"]);
    }
    if policy.no_new_privileges {
        command = command.args(["--security-opt", "no-new-privileges"]);
    }
    if policy.read_only_root {
        command = command.arg("--read-only");
    }
    if let Some(value) = policy.pids_limit {
        command = command.arg("--pids-limit").arg(value.to_string());
    }
    if let Some(value) = policy.memory_limit_bytes {
        command = command.arg("--memory").arg(value.to_string());
    }
    if let Some(value) = policy.cpu_limit_millis {
        command = command
            .arg("--cpus")
            .arg(format!("{}.{:03}", value / 1000, value % 1000));
    }
    for tmpfs in &policy.tmpfs {
        let mut options = vec![if tmpfs.read_only { "ro" } else { "rw" }];
        if tmpfs.no_exec {
            options.push("noexec");
        }
        if tmpfs.no_suid {
            options.push("nosuid");
        }
        if tmpfs.no_device {
            options.push("nodev");
        }
        command = command.arg("--tmpfs").arg(format!(
            "{}:{},size={}",
            tmpfs.destination.display(),
            options.join(","),
            tmpfs.size_bytes
        ));
    }
    command
}

/// Back up the managed PostgreSQL and Valkey data and validate the archive.
///
/// Podman needs an SELinux relabel on the validation bind mount; Docker uses
/// its explicit `--mount` spelling.  Keeping that one dialect switch here
/// avoids duplicating the backup/BGSAVE state machine in both backends.
pub(crate) fn backup_managed_dependencies(
    command: &OsStr,
    backup: &ManagedDependencyBackup,
    selinux_relabel: bool,
) -> anyhow::Result<()> {
    let postgres = backup.destination.join("postgresql.dump");
    Process::new(command)
        .args(["exec", backup.postgres_object.as_str(), "pg_dump"])
        .args([
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "-U",
            backup.postgres_user.as_str(),
            backup.postgres_database.as_str(),
        ])
        .stdout_file(&postgres)?;

    let validation = if selinux_relabel {
        Process::new(command)
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/backup:ro,Z", backup.destination.display()))
    } else {
        Process::new(command)
            .args(["run", "--rm", "--mount"])
            .arg(format!(
                "type=bind,src={},dst=/backup,readonly",
                backup.destination.display()
            ))
    };
    validation
        .arg(&backup.postgres_validation_image)
        .args(["pg_restore", "--list", "/backup/postgresql.dump"])
        .run_quiet()?;

    let output = |arguments: &[&str]| -> anyhow::Result<String> {
        if let Some(password_file) = &backup.valkey_password_file {
            return Process::new(command)
                .args(["exec", backup.valkey_object.as_str(), "sh", "-eu", "-c"])
                .arg("VALKEYCLI_AUTH=$(cat \"$1\"); export VALKEYCLI_AUTH; shift; exec valkey-cli \"$@\"")
                .arg("_")
                .arg(password_file)
                .args(arguments)
                .stdout();
        }
        Process::new(command)
            .args(["exec", backup.valkey_object.as_str(), "valkey-cli"])
            .args(arguments)
            .stdout()
    };
    let previous = output(&["LASTSAVE"])?
        .trim()
        .parse::<u64>()
        .context("Valkey LASTSAVE is not numeric")?;
    output(&["BGSAVE"])?;
    let mut completed = false;
    for _ in 0..60 {
        if output(&["LASTSAVE"])?
            .trim()
            .parse::<u64>()
            .context("Valkey LASTSAVE is not numeric")?
            > previous
        {
            completed = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !completed {
        bail!("Valkey BGSAVE did not complete");
    }
    Process::new(command)
        .args(["cp"])
        .arg(format!(
            "{}:{}",
            backup.valkey_object, backup.valkey_rdb_path
        ))
        .arg(backup.destination.join("valkey-dump.rdb"))
        .run_quiet()
}

/// Require the complete managed-resource identity before an operation can
/// inspect or mutate an engine object.  A deployment/authority pair is only a
/// coarse namespace; runtime id, resource role and configuration digest close
/// the cross-instance and stale-configuration gaps.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_managed_labels(
    command: &OsStr,
    arguments: &[&str],
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let mut expected_labels = vec![
        (DEPLOYMENT_LABEL, deployment_id),
        (AUTHORITY_LABEL, control_authority),
        (RESOURCE_KIND_LABEL, resource_kind),
        (CONFIG_DIGEST_LABEL, config_digest),
    ];
    if let Some(runtime_instance_id) = runtime_instance_id {
        expected_labels.push((RUNTIME_INSTANCE_LABEL, runtime_instance_id));
    }
    for (label, expected) in expected_labels {
        let mut matched = false;
        for format in [
            format!("{{{{index .Config.Labels \"{label}\"}}}}"),
            format!("{{{{index .Labels \"{label}\"}}}}"),
        ] {
            if Process::new(command)
                .args(arguments)
                .arg("--format")
                .arg(format)
                .stdout()
                .is_ok_and(|value| value.trim() == expected)
            {
                matched = true;
                break;
            }
        }
        if !matched {
            bail!(
                "refusing to manage a {backend_name} object without the expected immutable managed-resource identity"
            );
        }
    }
    Ok(())
}

/// Compare the engine-reported image reference before touching a managed
/// container.  The image reference is expected to be digest-pinned by the
/// install/recovery policy; accepting a tag or an unavailable inspect field
/// would turn the labels back into the only trust boundary.
pub(crate) fn assert_container_image(
    command: &OsStr,
    arguments: &[&str],
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    require_digest_pinned_image(expected_image, backend_name)?;
    let expected_digest = expected_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| format!("sha256:{digest}"))
        .filter(|digest| valid_digest(digest))
        .context("managed dependency image has an invalid digest")?;
    for format in [
        "{{{{.Config.Image}}}}",
        "{{{{.ImageName}}}}",
        "{{{{.Config.ImageName}}}}",
        "{{{{index .RepoDigests 0}}}}",
    ] {
        let actual = Process::new(command)
            .args(arguments)
            .arg("--format")
            .arg(format)
            .stdout()
            .ok()
            .map(|value| value.trim().to_owned());
        if actual.as_deref().is_some_and(|value| {
            value == expected_image
                || value == expected_digest
                || value.ends_with(&format!("@{expected_digest}"))
        }) {
            return Ok(());
        }
    }
    bail!("refusing to manage a {backend_name} container whose immutable image does not match")
}

pub(crate) fn require_digest_pinned_image(
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let Some((_, digest)) = expected_image.rsplit_once('@') else {
        bail!("{backend_name} managed dependency image is not digest-pinned");
    };
    if valid_digest(digest) {
        return Ok(());
    }
    bail!("{backend_name} managed dependency image is not digest-pinned")
}

pub(crate) fn append_managed_labels(
    mut command: Process,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
) -> Process {
    command = command
        .arg("--label")
        .arg(format!("{DEPLOYMENT_LABEL}={deployment_id}"))
        .arg("--label")
        .arg(format!("{AUTHORITY_LABEL}={control_authority}"))
        .arg("--label")
        .arg(format!("{RESOURCE_KIND_LABEL}={resource_kind}"))
        .arg("--label")
        .arg(format!("{CONFIG_DIGEST_LABEL}={config_digest}"));
    if let Some(runtime_instance_id) = runtime_instance_id {
        command = command
            .arg("--label")
            .arg(format!("{RUNTIME_INSTANCE_LABEL}={runtime_instance_id}"));
    }
    command
}

pub(crate) fn network_gateway(document: &serde_json::Value) -> Option<std::net::IpAddr> {
    match document {
        serde_json::Value::Object(object) => object.iter().find_map(|(key, value)| {
            if key.eq_ignore_ascii_case("gateway") {
                value.as_str().and_then(|value| value.parse().ok())
            } else {
                network_gateway(value)
            }
        }),
        serde_json::Value::Array(values) => values.iter().find_map(network_gateway),
        _ => None,
    }
}

pub(crate) fn ensure_volume(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    if Process::new(command)
        .args(["volume", "inspect", name])
        .succeeds()
    {
        return assert_managed_labels(
            command,
            &["volume", "inspect", name],
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        );
    }
    append_managed_labels(
        Process::new(command).args(["volume", "create"]),
        &network.deployment_id,
        &network.control_authority,
        Some(runtime_instance_id),
        resource_kind,
        config_digest,
    )
    .arg(name)
    .run_quiet()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_container(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    expected_image: &str,
    create: Process,
    backend_name: &str,
) -> anyhow::Result<()> {
    if Process::new(command).args(["inspect", name]).succeeds() {
        assert_managed_labels(
            command,
            &["inspect", name],
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        )?;
        assert_container_image(command, &["inspect", name], expected_image, backend_name)?;
        return Process::new(command).args(["start", name]).run_quiet();
    }
    create.run_quiet()
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
    let image = format!(
        "{}@{}",
        image_reference.split('@').next().unwrap_or(image_reference),
        digest
    );
    let mut process = Process::new(command)
        .timeout(Duration::from_secs(300))
        .args([
            "run",
            "--rm",
            "--interactive",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            task.network.as_deref().unwrap_or("none"),
        ]);
    if let Some(directory) = &task.working_directory {
        process = process.arg("--workdir").arg(directory);
    }
    if let Some(user) = &task.service_user {
        process = process.arg("--user").arg(user);
    }
    for (name, value) in &task.environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    Ok(append_mounts(process, &task.mounts)
        .arg(image)
        .args(&task.command))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

/// Normalize an engine's local image identity.  Docker emits `sha256:...`;
/// Podman may emit the same digest without the algorithm prefix.
pub(crate) fn normalize_local_image_id(value: &str, allow_bare_digest: bool) -> Option<String> {
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
