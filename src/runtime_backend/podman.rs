use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind},
    process::Process,
};

use super::{
    BlobAttestationVerification, ManagedPostgresCommand, ManagedPostgresRestore,
    ManagedValkeyRestore, NeutralMount, OneShotTask, RuntimeBackend, RuntimeObservation,
    RuntimeReplacement, labels, safe_environment, server_command_verified,
};

pub(crate) struct PodmanBackend {
    command: OsString,
}

impl Default for PodmanBackend {
    fn default() -> Self {
        Self {
            command: OsString::from("podman"),
        }
    }
}

impl PodmanBackend {
    #[cfg(test)]
    pub(crate) fn with_command(command: impl Into<OsString>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

impl RuntimeBackend for PodmanBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Podman
    }

    fn available(&self) -> bool {
        Process::new(&self.command)
            .args(["info", "--format", "json"])
            .succeeds()
    }

    fn verify_blob_attestation(
        &self,
        verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["run", "--rm", "--user", "0:0", "--cap-drop", "ALL"])
            .args(["--read-only", "--security-opt", "no-new-privileges"])
            .args(["--pids-limit", "64", "--tmpfs"])
            .arg("/root/.sigstore:rw,noexec,nosuid,nodev,size=16m")
            .arg("-v")
            .arg(format!("{}:/work:ro,Z", verification.work.display()))
            .arg(&verification.cosign_image)
            .args(["verify-blob-attestation", "--bundle"])
            .arg(format!("/work/{}", verification.bundle))
            .args(["--type", verification.predicate_type.as_str()])
            .args([
                "--certificate-identity",
                verification.certificate_identity.as_str(),
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ])
            .arg(format!("/work/{}", verification.blob))
            .run_quiet()
    }

    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>> {
        let ids = Process::new(&self.command)
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
        let output = Process::new(&self.command)
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
        Process::new(&self.command)
            .args(["start", object_reference])
            .run_quiet()
    }

    fn stop(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["stop", object_reference])
            .run_quiet()
    }

    fn restart(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["restart", object_reference])
            .run_quiet()
    }

    fn remove(&self, object_reference: &str) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["rm", "--force", object_reference])
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
        let mut command = Process::new(&self.command)
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
        command = append_mounts(command, &replacement.mounts);
        command.arg(image).args(&replacement.command).run_quiet()
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        podman_one_shot_process(&self.command, task)?.stdin_stdout(&task.stdin)
    }

    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool> {
        podman_one_shot_process(&self.command, task)?.stdin_authorization_rejected(&task.stdin)
    }

    fn pull_image(&self, image_reference: &str) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["pull", image_reference])
            .run_quiet()
    }

    fn export_image(&self, image_reference: &str, archive: &std::path::Path) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["image", "save", "--output"])
            .arg(archive)
            .arg(image_reference)
            .run_quiet()
    }

    fn import_image(&self, archive: &std::path::Path) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["image", "load", "--input"])
            .arg(archive)
            .run_quiet()
    }

    fn restore_managed_postgres(&self, restore: &ManagedPostgresRestore) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["run", "--rm", "--network"])
            .arg(&restore.network)
            .args([
                "-e",
                "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
                "-e",
                "PGPASSFILE=/run/nazoauth-secrets/pgpass",
                "-v",
            ])
            .arg(format!(
                "{}:/backup:ro,Z",
                restore.backup_directory.display()
            ))
            .arg("-v")
            .arg(format!(
                "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
                restore.service_file.display()
            ))
            .arg("-v")
            .arg(format!(
                "{}:/run/nazoauth-secrets/pgpass:ro,Z",
                restore.password_file.display()
            ))
            .arg(&restore.image)
            .args([
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--dbname=service=nazoauth",
                "/backup/postgresql.dump",
            ])
            .run_quiet()
    }

    fn restore_managed_valkey(&self, restore: &ManagedValkeyRestore) -> anyhow::Result<()> {
        self.stop(&restore.object_reference)?;
        let restored = Process::new(&self.command)
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/data", restore.data_volume))
            .arg("-v")
            .arg(format!(
                "{}:/backup:ro,Z",
                restore.backup_directory.display()
            ))
            .arg(&restore.image)
            .args([
                "sh",
                "-eu",
                "-c",
                "test -s /backup/valkey-dump.rdb; rm -rf -- /data/appendonlydir; install -m 600 /backup/valkey-dump.rdb /data/dump.rdb",
            ])
            .run_quiet();
        let restarted = self.start(&restore.object_reference);
        restored?;
        restarted
    }

    fn execute_managed_postgres(&self, command: &ManagedPostgresCommand) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["exec", "-i"])
            .arg(&command.object_reference)
            .args(["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "-U"])
            .arg(&command.user)
            .arg("-d")
            .arg(&command.database)
            .stdin_stdout(&command.stdin)
            .map(|_| ())
    }

    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String> {
        let repo_digests = Process::new(&self.command)
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
                .find(|digest| Some(*digest) == expected && valid_digest(digest))
            {
                return Ok(digest.to_ascii_lowercase());
            }
            if let Some(digest) = values
                .iter()
                .filter_map(|value| value.rsplit_once('@').map(|(_, digest)| digest))
                .find(|digest| valid_digest(digest))
            {
                return Ok(digest.to_ascii_lowercase());
            }
        }
        let digest = Process::new(&self.command)
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
            bail!("container engine did not retain the signed OCI digest");
        }
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
            bail!("Podman build identity requires a digest-bound OCI artifact");
        };
        let image = format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        );
        let output = Process::new(&self.command)
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
}

fn podman_one_shot_process(
    command: &std::ffi::OsStr,
    task: &OneShotTask,
) -> anyhow::Result<Process> {
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
    let mut process = Process::new(command)
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
    Ok(append_mounts(process, &task.mounts)
        .arg(image)
        .args(&task.command))
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
