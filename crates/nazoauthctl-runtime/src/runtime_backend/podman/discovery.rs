//! Podman inspection and immutable image identity discovery.

use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Context as _, bail};

use crate::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind};

use super::super::container_shared;
use super::super::{RuntimeObservation, labels, safe_environment, server_command_verified};

pub(super) fn discover(command: &OsStr) -> anyhow::Result<Vec<RuntimeObservation>> {
    let ids = container_shared::command_stdout(
        command,
        &["container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"],
        "Podman",
    )?;
    let mut observations = Vec::new();
    for id in ids.lines().map(str::trim).filter(|id| !id.is_empty()) {
        match inspect(command, id) {
            Ok(observation) if observation.server_command_verified => {
                observations.push(observation)
            }
            Ok(_) => {}
            Err(error) if container_shared::is_engine_unavailable_error(&error) => {
                return Err(error);
            }
            Err(error) if error.to_string().contains("managed object is absent") => {
                // The object may have been removed between `ls` and inspect.
            }
            Err(error) => return Err(error),
        }
    }
    Ok(observations)
}

pub(super) fn inspect(
    command: &OsStr,
    object_reference: &str,
) -> anyhow::Result<RuntimeObservation> {
    let value = container_shared::inspect_document(
        command,
        &["container", "inspect", object_reference],
        "Podman",
    )?;
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
    let (artifact, artifact_missing) =
        match resolve_image_digest(command, &image_reference, local_artifact_id.as_deref()) {
            Ok(digest) => (
                ArtifactReference::Oci {
                    image_reference,
                    digest,
                },
                None,
            ),
            Err(error) if container_shared::is_engine_unavailable_error(&error) => {
                return Err(error);
            }
            Err(_) => (
                ArtifactReference::Unknown,
                Some("trusted OCI digest could not be resolved".to_owned()),
            ),
        };
    let ports = parse_ports(&value)?;
    let networks = value
        .pointer("/NetworkSettings/Networks")
        .and_then(serde_json::Value::as_object)
        .map(|networks| networks.keys().cloned().collect())
        .unwrap_or_default();
    let mounts = parse_mounts(&value)?;
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

fn parse_ports(value: &serde_json::Value) -> anyhow::Result<Vec<String>> {
    let Some(raw_ports) = value.pointer("/NetworkSettings/Ports") else {
        return Ok(Vec::new());
    };
    if raw_ports.is_null() {
        return Ok(Vec::new());
    }
    let ports = raw_ports
        .as_object()
        .context("Podman inspect returned an invalid port map")?;
    let mut observed = Vec::new();
    for (container_port, bindings) in ports {
        let Some((port, protocol)) = container_port.rsplit_once('/') else {
            bail!("Podman inspect returned a malformed container port");
        };
        if port.parse::<u16>().is_err()
            || !matches!(
                protocol.to_ascii_lowercase().as_str(),
                "tcp" | "udp" | "sctp"
            )
        {
            bail!("Podman inspect returned a malformed container port");
        }
        if bindings.is_null() {
            continue;
        }
        let bindings = bindings
            .as_array()
            .context("Podman inspect returned invalid port bindings")?;
        for binding in bindings {
            let binding = binding
                .as_object()
                .context("Podman inspect returned a non-object port binding")?;
            let host_ip = binding
                .get("HostIp")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Podman inspect returned a port binding without a host address")?;
            let host_port = binding
                .get("HostPort")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Podman inspect returned a port binding without a host port")?;
            if host_port.parse::<u16>().is_err() {
                bail!("Podman inspect returned a non-numeric host port");
            }
            observed.push(format!("{host_ip}:{host_port}->{container_port}"));
        }
    }
    Ok(observed)
}

fn parse_mounts(value: &serde_json::Value) -> anyhow::Result<Vec<super::super::NeutralMount>> {
    let Some(raw_mounts) = value.get("Mounts") else {
        return Ok(Vec::new());
    };
    if raw_mounts.is_null() {
        return Ok(Vec::new());
    }
    let mounts = raw_mounts
        .as_array()
        .context("Podman inspect returned an invalid mount list")?;
    mounts.iter().map(podman_mount).collect()
}

fn podman_mount(mount: &serde_json::Value) -> anyhow::Result<super::super::NeutralMount> {
    let source = mount
        .get("Source")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("Podman inspect returned a mount without a source")?;
    let destination = mount
        .get("Destination")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("Podman inspect returned a mount without a destination")?;
    let options = match mount.get("Options") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(value) => value
            .as_array()
            .context("Podman inspect returned invalid mount options")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .context("Podman inspect returned an invalid mount option")
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    };
    let read_only = match mount.get("RW") {
        None | Some(serde_json::Value::Null) if options.is_empty() => {
            bail!("Podman inspect returned a mount without read/write metadata")
        }
        None | Some(serde_json::Value::Null) => options.contains(&"ro"),
        Some(value) => !value
            .as_bool()
            .context("Podman inspect returned an invalid mount read/write flag")?,
    };
    Ok(super::super::NeutralMount {
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
    if container_shared::inspect_document_optional(
        command,
        &["container", "inspect", object_reference],
        "Podman",
    )?
    .is_none()
    {
        return Ok(None);
    }
    Ok(Some(inspect(command, object_reference)?))
}

/// Resolve the trusted repository digest for an image reference.
///
/// `local_image_id` is the container's recorded immutable local image ID.
/// Podman quirk: a container started from an index (manifest-list) digest
/// reference can be stored under the platform manifest digest, after which
/// the index reference stops resolving for `image inspect`. The local image
/// ID always resolves, and its `RepoDigests` list carries every digest the
/// engine retained — including the requested one — so it is a pure lookup
/// fallback, never a trust downgrade: the requested-digest match below is
/// unchanged.
pub(super) fn resolve_image_digest(
    command: &OsStr,
    image_reference: &str,
    local_image_id: Option<&str>,
) -> anyhow::Result<String> {
    let repo_digests = image_inspect_output(
        command,
        image_reference,
        local_image_id,
        "{{json .RepoDigests}}",
    )?;
    let expected = image_reference
        .rsplit_once('@')
        .map(|(_, digest)| digest.to_ascii_lowercase());
    if let Ok(values) = serde_json::from_str::<Vec<String>>(repo_digests.trim()) {
        if let Some(digest) = values
            .iter()
            .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
            .find(|digest| {
                container_shared::valid_digest(digest)
                    && container_shared::requested_digest_matches(image_reference, digest)
            })
        {
            return Ok(digest.to_ascii_lowercase());
        }
        if expected.is_none()
            && let Some(digest) = values
                .iter()
                .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
                .find(|digest| container_shared::valid_digest(digest))
        {
            return Ok(digest.to_ascii_lowercase());
        }
    }
    let digest = image_inspect_output(command, image_reference, local_image_id, "{{.Digest}}")?;
    let digest = digest.trim();
    if !container_shared::valid_digest(digest)
        || !container_shared::requested_digest_matches(image_reference, digest)
    {
        bail!("container engine did not retain the signed OCI digest");
    }
    Ok(digest.to_ascii_lowercase())
}

/// Run one `image inspect --format` query against the image reference,
/// falling back to the container's recorded local image ID when Podman no
/// longer resolves the original reference (index-digest storage quirk).
fn image_inspect_output(
    command: &OsStr,
    image_reference: &str,
    local_image_id: Option<&str>,
    format: &str,
) -> anyhow::Result<String> {
    match container_shared::command_stdout(
        command,
        &["image", "inspect", image_reference, "--format", format],
        "Podman",
    ) {
        Ok(output) => Ok(output),
        Err(reference_error) => match local_image_id {
            Some(id) => container_shared::command_stdout(
                command,
                &["image", "inspect", id, "--format", format],
                "Podman",
            )
            .map_err(|_| reference_error),
            None => Err(reference_error),
        },
    }
}

pub(super) fn resolve_local_image_id(
    command: &OsStr,
    image_reference: &str,
) -> anyhow::Result<String> {
    let output = container_shared::command_stdout(
        command,
        &["image", "inspect", image_reference, "--format", "{{.Id}}"],
        "Podman",
    )?;
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
    let output = container_shared::build_identity_process(command)
        .args(["--network", "none"])
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

    #[test]
    fn podman_discovery_rejects_malformed_mount_and_port_entries() {
        let mount = serde_json::json!({"Source": "/host"});
        assert!(podman_mount(&mount).is_err());
        let value = serde_json::json!({
            "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "127.0.0.1"}]}}
        });
        assert!(parse_ports(&value).is_err());
    }
}
