//! Docker inspection and immutable image identity discovery.

use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Context as _, bail};

use crate::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind};

use super::super::container_shared;
use super::super::{RuntimeObservation, labels, safe_environment, server_command_verified};

pub(super) fn discover(command: &OsStr) -> anyhow::Result<Vec<RuntimeObservation>> {
    let ids = container_shared::command_stdout(
        command,
        &["container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"],
        "Docker",
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
        "Docker",
    )?;
    let config = value
        .get("Config")
        .context("Docker inspect omitted Config")?;
    let mut command_values = value
        .get("Path")
        .and_then(serde_json::Value::as_str)
        .map(|value| vec![value.to_owned()])
        .unwrap_or_default();
    command_values.extend(
        value
            .get("Args")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    );
    let server_command_verified = server_command_verified(&command_values);
    let image_reference = config
        .get("Image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let local_artifact_id = value
        .get("Image")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| container_shared::normalize_local_image_id(value, false));
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
        .context("Docker inspect omitted immutable container ID")?
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
        backend: RuntimeBackendKind::Docker,
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
            format!("Docker immutable container ID observed: {id}"),
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
        .context("Docker inspect returned an invalid port map")?;
    let mut observed = Vec::new();
    for (container_port, bindings) in ports {
        let Some((port, protocol)) = container_port.rsplit_once('/') else {
            bail!("Docker inspect returned a malformed container port");
        };
        if port.parse::<u16>().is_err()
            || !matches!(
                protocol.to_ascii_lowercase().as_str(),
                "tcp" | "udp" | "sctp"
            )
        {
            bail!("Docker inspect returned a malformed container port");
        }
        if bindings.is_null() {
            continue;
        }
        let bindings = bindings
            .as_array()
            .context("Docker inspect returned invalid port bindings")?;
        for binding in bindings {
            let binding = binding
                .as_object()
                .context("Docker inspect returned a non-object port binding")?;
            let host_ip = binding
                .get("HostIp")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Docker inspect returned a port binding without a host address")?;
            let host_port = binding
                .get("HostPort")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Docker inspect returned a port binding without a host port")?;
            if host_port.parse::<u16>().is_err() {
                bail!("Docker inspect returned a non-numeric host port");
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
        .context("Docker inspect returned an invalid mount list")?;
    mounts
        .iter()
        .map(|mount| {
            let source = mount
                .get("Source")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Docker inspect returned a mount without a source")?;
            let destination = mount
                .get("Destination")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Docker inspect returned a mount without a destination")?;
            let mode = match mount.get("Mode") {
                None | Some(serde_json::Value::Null) => "",
                Some(value) => value
                    .as_str()
                    .context("Docker inspect returned an invalid mount mode")?,
            };
            let read_only = match mount.get("RW") {
                None | Some(serde_json::Value::Null) if mode.is_empty() => {
                    bail!("Docker inspect returned a mount without read/write metadata")
                }
                None | Some(serde_json::Value::Null) => mode.split(',').any(|value| value == "ro"),
                Some(value) => !value
                    .as_bool()
                    .context("Docker inspect returned an invalid mount read/write flag")?,
            };
            Ok(super::super::NeutralMount {
                source: PathBuf::from(source),
                destination: PathBuf::from(destination),
                read_only,
                selinux_relabel: mode.split(',').any(|value| matches!(value, "z" | "Z")),
                ownership: Responsibility::External,
                scope: ResourceScope::Deployment,
            })
        })
        .collect()
}

pub(super) fn inspect_optional(
    command: &OsStr,
    object_reference: &str,
) -> anyhow::Result<Option<RuntimeObservation>> {
    if container_shared::inspect_document_optional(
        command,
        &["container", "inspect", object_reference],
        "Docker",
    )?
    .is_none()
    {
        return Ok(None);
    }
    Ok(Some(inspect(command, object_reference)?))
}

/// Whether any locally cached image carries exactly the repository digest
/// embedded in `image_reference`. Errors are reported as `false`: a failed
/// existence check must never authorize proceeding without the registry.
pub(super) fn local_image_matches_digest(command: &OsStr, image_reference: &str) -> bool {
    let Some(requested) = image_reference
        .rsplit_once('@')
        .map(|(_, digest)| digest.trim().to_ascii_lowercase())
        .filter(|digest| container_shared::valid_digest(digest))
    else {
        return false;
    };
    let Ok(output) = container_shared::command_stdout(
        command,
        &["images", "--format", "{{json .RepoDigests}}"],
        "Docker",
    ) else {
        return false;
    };
    output.lines().any(|line| {
        serde_json::from_str::<Vec<String>>(line.trim())
            .ok()
            .is_some_and(|digests| {
                digests.iter().any(|entry| {
                    entry
                        .rsplit_once('@')
                        .is_some_and(|(_, digest)| digest.trim().to_ascii_lowercase() == requested)
                })
            })
    })
}

/// Resolve the trusted repository digest for an image reference.
///
/// `local_image_id` is the container's recorded immutable local image ID and
/// serves as a pure lookup fallback when the engine no longer resolves the
/// original reference (e.g. index-digest storage quirks). The trust model is
/// unchanged: the digest only validates through the requested-digest match.
pub(super) fn resolve_image_digest(
    command: &OsStr,
    image_reference: &str,
    local_image_id: Option<&str>,
) -> anyhow::Result<String> {
    let output = image_inspect_output(
        command,
        image_reference,
        local_image_id,
        "{{json .RepoDigests}}",
    )?;
    let digests: Vec<String> = serde_json::from_str(output.trim())
        .context("Docker image inspect returned invalid RepoDigests")?;
    let requested = image_reference
        .rsplit_once('@')
        .map(|(_, digest)| digest.to_ascii_lowercase());
    let digest = digests
        .iter()
        .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
        .find(|digest| {
            container_shared::valid_digest(digest)
                && container_shared::requested_digest_matches(image_reference, digest)
        })
        .with_context(|| {
            requested.map_or_else(
                || "Docker image has no immutable repository digest".to_owned(),
                |requested| format!("Docker image does not retain requested digest {requested}"),
            )
        })?;
    Ok(digest.to_ascii_lowercase())
}

/// Run one `image inspect --format` query against the image reference,
/// falling back to the container's recorded local image ID when the engine
/// no longer resolves that reference.
fn image_inspect_output(
    command: &OsStr,
    image_reference: &str,
    local_image_id: Option<&str>,
    format: &str,
) -> anyhow::Result<String> {
    match container_shared::command_stdout(
        command,
        &["image", "inspect", image_reference, "--format", format],
        "Docker",
    ) {
        Ok(output) => Ok(output),
        Err(reference_error) => match local_image_id {
            Some(id) => container_shared::command_stdout(
                command,
                &["image", "inspect", id, "--format", format],
                "Docker",
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
        "Docker",
    )?;
    container_shared::normalize_local_image_id(output.trim(), false)
        .context("Docker image has no immutable local content identity")
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
        bail!("Docker build identity requires a digest-bound OCI artifact");
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
        "Docker image returned an invalid build identity",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_discovery_rejects_malformed_mount_and_port_entries() {
        let value = serde_json::json!({
            "Mounts": [{"Source": "/host"}],
            "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "127.0.0.1"}]}}
        });
        assert!(parse_mounts(&value).is_err());
        assert!(parse_ports(&value).is_err());
    }
}
