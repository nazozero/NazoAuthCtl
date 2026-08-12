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
            Err(_) => {
                // A malformed or concurrently removed object is isolated to
                // that object; it must not hide healthy server candidates.
            }
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
    let (artifact, artifact_missing) = match resolve_image_digest(command, &image_reference) {
        Ok(digest) => (
            ArtifactReference::Oci {
                image_reference,
                digest,
            },
            None,
        ),
        Err(error) if container_shared::is_engine_unavailable_error(&error) => return Err(error),
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
        .filter_map(|mount| {
            let source = mount.get("Source")?.as_str()?;
            let destination = mount.get("Destination")?.as_str()?;
            let mode = mount
                .get("Mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            Some(super::super::NeutralMount {
                source: PathBuf::from(source),
                destination: PathBuf::from(destination),
                read_only: !mount
                    .get("RW")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                selinux_relabel: mode.split(',').any(|value| matches!(value, "z" | "Z")),
                ownership: Responsibility::External,
                scope: ResourceScope::Deployment,
            })
        })
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

pub(super) fn resolve_image_digest(
    command: &OsStr,
    image_reference: &str,
) -> anyhow::Result<String> {
    let output = container_shared::command_stdout(
        command,
        &[
            "image",
            "inspect",
            image_reference,
            "--format",
            "{{json .RepoDigests}}",
        ],
        "Docker",
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
