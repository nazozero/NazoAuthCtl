//! Podman inspection and immutable image identity discovery.

use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind},
    process::Process,
};

use super::super::container_shared;
use super::super::{RuntimeObservation, labels, safe_environment, server_command_verified};

pub(super) fn discover(command: &OsStr) -> anyhow::Result<Vec<RuntimeObservation>> {
    let ids = Process::new(command)
        .args(["container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"])
        .stdout()?;
    ids.lines()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| inspect(command, id))
        .filter_map(|result| match result {
            Ok(observation) if observation.server_command_verified => Some(Ok(observation)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub(super) fn inspect(
    command: &OsStr,
    object_reference: &str,
) -> anyhow::Result<RuntimeObservation> {
    let output = Process::new(command)
        .args(["container", "inspect", object_reference])
        .stdout()?;
    let values: Vec<serde_json::Value> =
        serde_json::from_str(&output).context("Podman inspect returned invalid JSON")?;
    let value = values
        .first()
        .context("Podman inspect returned no object")?;
    let config = value
        .get("Config")
        .context("Podman inspect omitted Config")?;
    let command_values = config
        .get("Command")
        .or_else(|| config.get("Cmd"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut complete_command = config
        .get("Entrypoint")
        .and_then(serde_json::Value::as_str)
        .map(|value| vec![value.to_owned()])
        .unwrap_or_default();
    complete_command.extend(command_values);
    let server_command_verified = server_command_verified(&complete_command);
    let image_reference = value
        .get("ImageName")
        .or_else(|| config.get("Image"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let local_artifact_id = value
        .get("Image")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| container_shared::normalize_local_image_id(value, true));
    let (artifact, artifact_missing) = match resolve_image_digest(command, &image_reference) {
        Ok(digest) => (
            ArtifactReference::Oci {
                image_reference,
                digest,
            },
            None,
        ),
        Err(_) => (
            ArtifactReference::Unknown,
            Some("trusted OCI digest could not be resolved".to_owned()),
        ),
    };
    let ports = value
        .pointer("/NetworkSettings/Ports")
        .and_then(serde_json::Value::as_object)
        .map(|ports| {
            ports
                .iter()
                .flat_map(|(container_port, bindings)| {
                    bindings
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(move |binding| {
                            let host_ip = binding.get("HostIp")?.as_str()?;
                            let host_port = binding.get("HostPort")?.as_str()?;
                            Some(format!("{host_ip}:{host_port}->{container_port}"))
                        })
                })
                .collect()
        })
        .unwrap_or_default();
    let networks = value
        .pointer("/NetworkSettings/Networks")
        .and_then(serde_json::Value::as_object)
        .map(|networks| networks.keys().cloned().collect())
        .unwrap_or_default();
    let mounts = value
        .get("Mounts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(podman_mount)
        .collect();
    let safe_environment = safe_environment(
        config
            .get("Env")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    let labels = labels(config.get("Labels"));
    let id = value
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .context("Podman inspect omitted immutable container ID")?
        .to_owned();
    let display_name = value
        .get("Name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&id)
        .trim_start_matches('/')
        .to_owned();
    let running = value
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut missing = Vec::new();
    if let Some(missing_artifact) = artifact_missing {
        missing.push(missing_artifact);
    }
    Ok(RuntimeObservation {
        backend: RuntimeBackendKind::Podman,
        object_reference: display_name.clone(),
        display_name,
        running,
        server_command_verified,
        artifact,
        local_artifact_id,
        ports,
        networks,
        mounts,
        safe_environment,
        labels,
        evidence: vec![
            "runtime command identifies nazoauth server".to_owned(),
            format!("Podman immutable container ID observed: {id}"),
        ],
        missing,
    })
}

fn podman_mount(mount: &serde_json::Value) -> Option<super::super::NeutralMount> {
    let source = mount.get("Source")?.as_str()?;
    let destination = mount.get("Destination")?.as_str()?;
    let options = mount
        .get("Options")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    let read_only = mount
        .get("RW")
        .and_then(serde_json::Value::as_bool)
        .map_or_else(|| options.contains(&"ro"), |read_write| !read_write);
    Some(super::super::NeutralMount {
        source: PathBuf::from(source),
        destination: PathBuf::from(destination),
        read_only,
        selinux_relabel: options.iter().any(|value| matches!(*value, "z" | "Z")),
        ownership: Responsibility::External,
        scope: ResourceScope::Deployment,
    })
}

pub(super) fn inspect_optional(
    command: &OsStr,
    object_reference: &str,
) -> anyhow::Result<Option<RuntimeObservation>> {
    let output = Process::new(command)
        .args(["container", "inspect", object_reference])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("no such object")
            || stderr.contains("no such container")
            || stderr.contains("no container with name or id")
        {
            return Ok(None);
        }
        bail!("Podman container inspection failed: {}", stderr.trim());
    }
    Ok(Some(inspect(command, object_reference)?))
}

pub(super) fn resolve_image_digest(
    command: &OsStr,
    image_reference: &str,
) -> anyhow::Result<String> {
    let repo_digests = Process::new(command)
        .args([
            "image",
            "inspect",
            image_reference,
            "--format",
            "{{json .RepoDigests}}",
        ])
        .stdout()?;
    if let Ok(values) = serde_json::from_str::<Vec<String>>(repo_digests.trim()) {
        let expected = image_reference.rsplit_once('@').map(|(_, digest)| digest);
        if let Some(digest) = values
            .iter()
            .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
            .find(|digest| Some(*digest) == expected && container_shared::valid_digest(digest))
        {
            return Ok(digest.to_ascii_lowercase());
        }
        if let Some(digest) = values
            .iter()
            .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
            .find(|digest| container_shared::valid_digest(digest))
        {
            return Ok(digest.to_ascii_lowercase());
        }
    }
    let digest = Process::new(command)
        .args([
            "image",
            "inspect",
            image_reference,
            "--format",
            "{{.Digest}}",
        ])
        .stdout()?;
    let digest = digest.trim();
    if !container_shared::valid_digest(digest) {
        bail!("container engine did not retain the signed OCI digest");
    }
    Ok(digest.to_ascii_lowercase())
}

pub(super) fn resolve_local_image_id(
    command: &OsStr,
    image_reference: &str,
) -> anyhow::Result<String> {
    let output = Process::new(command)
        .args(["image", "inspect", image_reference, "--format", "{{.Id}}"])
        .stdout()?;
    container_shared::normalize_local_image_id(output.trim(), true)
        .context("Podman image has no immutable local content identity")
}

pub(super) fn read_build_identity(
    command: &OsStr,
    artifact: &ArtifactReference,
    local_artifact_id: Option<&str>,
) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>> {
    let ArtifactReference::Oci {
        image_reference,
        digest,
    } = artifact
    else {
        bail!("Podman build identity requires a digest-bound OCI artifact");
    };
    let image = local_artifact_id.map(ToOwned::to_owned).unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let output = Process::new(command)
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
        ])
        .arg(image)
        .args(["nazoauth", "build-identity"])
        .stdout()?;
    Ok(Some(serde_json::from_str(output.trim()).context(
        "Podman image returned an invalid build identity",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podman_mount_uses_the_inspect_rw_field_for_read_only_state() {
        let mount = serde_json::json!({
            "Source": "/etc/nazoauth/secret",
            "Destination": "/run/nazoauth/secret",
            "Options": ["rbind"],
            "RW": false,
        });
        let observed = podman_mount(&mount).unwrap();
        assert!(observed.read_only);
        assert!(!observed.selinux_relabel);
        assert_eq!(observed.ownership, Responsibility::External);
    }
}
