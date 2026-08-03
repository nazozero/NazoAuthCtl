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

pub(crate) struct DockerBackend;

impl RuntimeBackend for DockerBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Docker
    }

    fn available(&self) -> bool {
        Process::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .succeeds()
    }

    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>> {
        let ids = Process::new("docker")
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
        let output = Process::new("docker")
            .args(["container", "inspect", object_reference])
            .stdout()?;
        let values: Vec<serde_json::Value> =
            serde_json::from_str(&output).context("Docker inspect returned invalid JSON")?;
        let value = values
            .first()
            .context("Docker inspect returned no object")?;
        let config = value
            .get("Config")
            .context("Docker inspect omitted Config")?;
        let mut command = value
            .get("Path")
            .and_then(serde_json::Value::as_str)
            .map(|value| vec![value.to_owned()])
            .unwrap_or_default();
        command.extend(
            value
                .get("Args")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        );
        let server_command_verified = server_command_verified(&command);
        let image_reference = config
            .get("Image")
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
                Some(NeutralMount {
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
        Process::new("docker")
            .args(["start", object_reference])
            .run_quiet()
    }

    fn stop(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("docker")
            .args(["stop", object_reference])
            .run_quiet()
    }

    fn restart(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("docker")
            .args(["restart", object_reference])
            .run_quiet()
    }

    fn remove(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new("docker")
            .args(["rm", "--force", object_reference])
            .run_quiet()
    }

    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()> {
        let ArtifactReference::Oci {
            image_reference,
            digest,
        } = &replacement.artifact
        else {
            bail!("Docker replacement requires a digest-bound OCI artifact");
        };
        let image = format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        );
        let mut command = Process::new("docker")
            .args(["run", "-d", "--name"])
            .arg(&replacement.object_reference)
            .args([
                "--restart",
                "unless-stopped",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--pids-limit",
                "512",
                "--memory",
                "1g",
                "--cpus",
                "2",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m",
            ]);
        for (name, value) in &replacement.labels {
            command = command.arg("--label").arg(format!("{name}={value}"));
        }
        for (name, value) in &replacement.environment {
            command = command.arg("--env").arg(format!("{name}={value}"));
        }
        for network in &replacement.networks {
            command = command.arg("--network").arg(network);
        }
        if let Some(ip_address) = &replacement.ip_address {
            command = command.arg("--ip").arg(ip_address);
        }
        for port in &replacement.ports {
            command = command.arg("--publish").arg(port);
        }
        for mount in &replacement.mounts {
            let access = if mount.read_only { "ro" } else { "rw" };
            let relabel = if mount.selinux_relabel { ",Z" } else { "" };
            command = command.arg("--volume").arg(format!(
                "{}:{}:{}{}",
                mount.source.display(),
                mount.destination.display(),
                access,
                relabel
            ));
        }
        command.arg(image).args(&replacement.command).run_quiet()
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        docker_one_shot_process(task)?.stdin_stdout(&task.stdin)
    }

    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool> {
        docker_one_shot_process(task)?.stdin_authorization_rejected(&task.stdin)
    }

    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String> {
        let output = Process::new("docker")
            .args([
                "image",
                "inspect",
                image_reference,
                "--format",
                "{{json .RepoDigests}}",
            ])
            .stdout()?;
        let digests: Vec<String> = serde_json::from_str(output.trim())
            .context("Docker image inspect returned invalid RepoDigests")?;
        let digest = digests
            .iter()
            .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
            .find(|digest| valid_digest(digest))
            .context("Docker image has no immutable repository digest")?;
        Ok(digest.to_ascii_lowercase())
    }

    fn read_build_identity(
        &self,
        artifact: &ArtifactReference,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>> {
        let ArtifactReference::Oci {
            image_reference,
            digest,
        } = artifact
        else {
            bail!("Docker build identity requires a digest-bound OCI artifact");
        };
        let image = format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        );
        let output = Process::new("docker")
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
            "Docker image returned an invalid build identity",
        )?))
    }
}

fn docker_one_shot_process(task: &OneShotTask) -> anyhow::Result<Process> {
    let ArtifactReference::Oci {
        image_reference,
        digest,
    } = &task.artifact
    else {
        bail!("Docker one-shot task requires a digest-bound OCI artifact");
    };
    let image = format!(
        "{}@{}",
        image_reference.split('@').next().unwrap_or(image_reference),
        digest
    );
    let mut process = Process::new("docker")
        .timeout(std::time::Duration::from_secs(300))
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
    for mount in &task.mounts {
        let access = if mount.read_only { "ro" } else { "rw" };
        let relabel = if mount.selinux_relabel { ",Z" } else { "" };
        process = process.arg("--volume").arg(format!(
            "{}:{}:{}{}",
            mount.source.display(),
            mount.destination.display(),
            access,
            relabel
        ));
    }
    Ok(process.arg(image).args(&task.command))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}
