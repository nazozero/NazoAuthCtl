use std::path::PathBuf;

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind},
    process::Process,
};

use super::{
    NeutralMount, OneShotTask, RuntimeBackend, RuntimeObservation, RuntimeReplacement, labels,
    safe_environment, server_command_verified,
};

pub(crate) struct PodmanBackend;

impl RuntimeBackend for PodmanBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Podman
    }

    fn available(&self) -> bool {
        Process::new("podman")
            .args(["info", "--format", "json"])
            .succeeds()
    }

    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>> {
        let ids = Process::new("podman")
            .args(["container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"])
            .stdout()?;
        ids.lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(|id| self.inspect(id))
            .filter_map(|result| match result {
                Ok(observation) if observation.server_command_verified => Some(Ok(observation)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn inspect(&self, object_reference: &str) -> anyhow::Result<RuntimeObservation> {
        let output = Process::new("podman")
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
        let command = config
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
        complete_command.extend(command);
        let server_command_verified = server_command_verified(&complete_command);
        let image_reference = value
            .get("ImageName")
            .or_else(|| config.get("Image"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let (artifact, artifact_missing) = match self.resolve_image_digest(&image_reference) {
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
                            .filter_map(|binding| {
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
                let options = mount
                    .get("Options")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>();
                Some(NeutralMount {
                    source: PathBuf::from(source),
                    destination: PathBuf::from(destination),
                    read_only: options.contains(&"ro"),
                    selinux_relabel: options.iter().any(|value| matches!(*value, "z" | "Z")),
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
            .context("Podman inspect omitted immutable container ID")?
            .to_owned();
        let display_name = value
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&id)
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
            backend: self.kind(),
            object_reference: id,
            display_name,
            running,
            server_command_verified,
            artifact,
            ports,
            networks,
            mounts,
            safe_environment,
            labels,
            evidence: vec!["runtime command identifies nazoauth server".to_owned()],
            missing,
        })
    }

    fn start(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("podman")
            .args(["start", object_reference])
            .run_quiet()
    }

    fn stop(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("podman")
            .args(["stop", object_reference])
            .run_quiet()
    }

    fn restart(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("podman")
            .args(["restart", object_reference])
            .run_quiet()
    }

    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()> {
        let ArtifactReference::Oci {
            image_reference,
            digest,
        } = &replacement.artifact
        else {
            bail!("Podman replacement requires a digest-bound OCI artifact");
        };
        let image = format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        );
        let mut command = Process::new("podman")
            .args(["run", "-d", "--name"])
            .arg(&replacement.object_reference);
        for (name, value) in &replacement.labels {
            command = command.arg("--label").arg(format!("{name}={value}"));
        }
        for env_file in &replacement.environment_files {
            command = command.arg("--env-file").arg(env_file);
        }
        command = append_mounts(command, &replacement.mounts);
        command.arg(image).args(&replacement.command).run_quiet()
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        let ArtifactReference::Oci {
            image_reference,
            digest,
        } = &task.artifact
        else {
            bail!("Podman one-shot task requires a digest-bound OCI artifact");
        };
        let image = format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        );
        let command = Process::new("podman").args([
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            if task.network_enabled {
                "bridge"
            } else {
                "none"
            },
        ]);
        append_mounts(command, &task.mounts)
            .arg(image)
            .args(&task.command)
            .stdout()
    }

    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String> {
        let digest = Process::new("podman")
            .args([
                "image",
                "inspect",
                image_reference,
                "--format",
                "{{.Digest}}",
            ])
            .stdout()?;
        let digest = digest.trim();
        if !valid_digest(digest) {
            bail!("Podman image has no immutable sha256 digest");
        }
        Ok(digest.to_ascii_lowercase())
    }

    fn read_build_identity(
        &self,
        _observation: &RuntimeObservation,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>> {
        Ok(None)
    }
}

fn append_mounts(mut command: Process, mounts: &[NeutralMount]) -> Process {
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

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}
