use std::{path::PathBuf, thread, time::Duration};

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind},
    process::Process,
};

#[cfg(debug_assertions)]
use super::DebugArtifactTask;
use super::{
    BlobAttestationVerification, ContainerRestartPolicy, ContainerRuntimePolicy,
    HostServiceInstall, ManagedDependencies, ManagedDependencyBackup, ManagedNetwork,
    ManagedPostgresCommand, ManagedPostgresRestore, ManagedValkeyRestore, NeutralMount,
    OneShotTask, RuntimeBackend, RuntimeDatabasePrivilegeProbe, RuntimeObservation,
    RuntimeReplacement, labels, safe_environment, server_command_verified,
};

pub(crate) struct DockerBackend {
    command: std::ffi::OsString,
}

fn append_container_policy(mut command: Process, policy: &ContainerRuntimePolicy) -> Process {
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

fn backup_managed_dependencies(
    command: &std::ffi::OsStr,
    backup: &ManagedDependencyBackup,
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
    Process::new(command)
        .args(["run", "--rm", "--mount"])
        .arg(format!(
            "type=bind,src={},dst=/backup,readonly",
            backup.destination.display()
        ))
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

fn assert_control_labels(
    command: &std::ffi::OsStr,
    arguments: &[&str],
    deployment_id: &str,
    control_authority: &str,
) -> anyhow::Result<()> {
    for (label, expected) in [
        ("io.nazoauth.deployment-id", deployment_id),
        ("io.nazoauth.control-authority", control_authority),
    ] {
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
            bail!("refusing to manage a Docker object outside this deployment authority");
        }
    }
    Ok(())
}

fn network_gateway(document: &serde_json::Value) -> Option<std::net::IpAddr> {
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

fn ensure_volume(
    command: &std::ffi::OsStr,
    name: &str,
    network: &ManagedNetwork,
) -> anyhow::Result<()> {
    if Process::new(command)
        .args(["volume", "inspect", name])
        .succeeds()
    {
        return assert_control_labels(
            command,
            &["volume", "inspect", name],
            &network.deployment_id,
            &network.control_authority,
        );
    }
    Process::new(command)
        .args(["volume", "create", "--label"])
        .arg(format!(
            "io.nazoauth.deployment-id={}",
            network.deployment_id
        ))
        .arg("--label")
        .arg(format!(
            "io.nazoauth.control-authority={}",
            network.control_authority
        ))
        .arg(name)
        .run_quiet()
}

fn ensure_container(
    command: &std::ffi::OsStr,
    name: &str,
    network: &ManagedNetwork,
    create: Process,
) -> anyhow::Result<()> {
    if Process::new(command).args(["inspect", name]).succeeds() {
        assert_control_labels(
            command,
            &["inspect", name],
            &network.deployment_id,
            &network.control_authority,
        )?;
        return Process::new(command).args(["start", name]).run_quiet();
    }
    create.run_quiet()
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self {
            command: "docker".into(),
        }
    }
}

impl DockerBackend {
    #[cfg(test)]
    pub(crate) fn with_command(command: impl Into<std::ffi::OsString>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

impl RuntimeBackend for DockerBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Docker
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
            .arg("--mount")
            .arg(format!(
                "type=bind,src={},dst=/work,readonly",
                verification.work.display()
            ))
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

    fn available(&self) -> bool {
        Process::new(&self.command)
            .args(["info", "--format", "{{.ServerVersion}}"])
            .succeeds()
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
        let local_artifact_id = value
            .get("Image")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_local_image_id);
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

    fn quiesce_for_recovery(&self, object_reference: &str) -> anyhow::Result<()> {
        let output = Process::new(&self.command)
            .args(["inspect", "--type", "container", object_reference])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if stderr.contains("no such object") || stderr.contains("no such container") {
                return Ok(());
            }
            bail!("Docker could not prove the recovery runtime is stopped or absent");
        }
        if self.inspect(object_reference)?.running {
            self.stop(object_reference)?;
        }
        if self.inspect(object_reference)?.running {
            bail!("Docker recovery runtime remained active after stop");
        }
        Ok(())
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
            bail!("Docker replacement requires a digest-bound OCI artifact");
        };
        let image = replacement.local_artifact_id.clone().unwrap_or_else(|| {
            format!(
                "{}@{}",
                image_reference.split('@').next().unwrap_or(image_reference),
                digest
            )
        });
        let policy = replacement
            .container_policy
            .as_ref()
            .context("Docker replacement has no explicit container policy")?;
        let mut command = append_container_policy(
            Process::new(&self.command)
                .args(["run", "-d", "--name"])
                .arg(&replacement.object_reference),
            policy,
        );
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
        docker_one_shot_process(&self.command, task)?.stdin_stdout(&task.stdin)
    }

    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool> {
        docker_one_shot_process(&self.command, task)?.stdin_authorization_rejected(&task.stdin)
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
            .arg(format!("{}:/backup:ro", restore.backup_directory.display()))
            .arg("-v")
            .arg(format!(
                "{}:/run/nazoauth-secrets/pg_service.conf:ro",
                restore.service_file.display()
            ))
            .arg("-v")
            .arg(format!(
                "{}:/run/nazoauth-secrets/pgpass:ro",
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
                "{}:/backup:ro",
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

    fn backup_managed_dependencies(&self, backup: &ManagedDependencyBackup) -> anyhow::Result<()> {
        backup_managed_dependencies(&self.command, backup)
    }

    fn ensure_managed_network(&self, network: &ManagedNetwork) -> anyhow::Result<std::net::IpAddr> {
        if Process::new(&self.command)
            .args(["network", "inspect", network.name.as_str()])
            .succeeds()
        {
            assert_control_labels(
                &self.command,
                &["network", "inspect", network.name.as_str()],
                &network.deployment_id,
                &network.control_authority,
            )?;
        } else {
            let mut create = Process::new(&self.command)
                .args(["network", "create", "--label"])
                .arg(format!(
                    "io.nazoauth.deployment-id={}",
                    network.deployment_id
                ))
                .arg("--label")
                .arg(format!(
                    "io.nazoauth.control-authority={}",
                    network.control_authority
                ));
            if let Some(subnet) = &network.subnet {
                create = create.args(["--subnet", subnet]);
            }
            create.arg(&network.name).run_quiet()?;
        }
        let document: serde_json::Value = serde_json::from_str(
            &Process::new(&self.command)
                .args(["network", "inspect", network.name.as_str()])
                .stdout()?,
        )
        .context("Docker network inspection is not valid JSON")?;
        network_gateway(&document).context("Docker network has no inspectable gateway")
    }

    fn ensure_managed_dependencies(
        &self,
        dependencies: &ManagedDependencies,
    ) -> anyhow::Result<()> {
        self.ensure_managed_network(&dependencies.network)?;
        for volume in [
            dependencies.postgres_volume.as_str(),
            dependencies.valkey_volume.as_str(),
        ] {
            ensure_volume(&self.command, volume, &dependencies.network)?;
        }
        let postgres = Process::new(&self.command)
            .args(["run", "-d", "--name", dependencies.postgres_object.as_str()])
            .arg("--label")
            .arg(format!(
                "io.nazoauth.deployment-id={}",
                dependencies.network.deployment_id
            ))
            .arg("--label")
            .arg(format!(
                "io.nazoauth.control-authority={}",
                dependencies.network.control_authority
            ))
            .arg("--label")
            .arg(format!(
                "io.nazoauth.runtime-instance-id={}-postgres",
                dependencies.runtime_instance_id
            ))
            .args(["--restart", "unless-stopped", "--network"])
            .arg(&dependencies.network.name)
            .arg("--env")
            .arg(format!("POSTGRES_DB={}", dependencies.postgres_database))
            .arg("--env")
            .arg(format!("POSTGRES_USER={}", dependencies.postgres_user))
            .args([
                "--env",
                "POSTGRES_PASSWORD_FILE=/run/nazoauth-secrets/postgres-password",
                "--volume",
            ])
            .arg(format!(
                "{}:/var/lib/postgresql",
                dependencies.postgres_volume
            ))
            .arg("--volume")
            .arg(format!(
                "{}:/run/nazoauth-secrets/postgres-password:ro",
                dependencies.postgres_password_file.display()
            ))
            .arg(&dependencies.postgres_image);
        ensure_container(
            &self.command,
            &dependencies.postgres_object,
            &dependencies.network,
            postgres,
        )?;

        let valkey = Process::new(&self.command)
            .args(["run", "-d", "--name", dependencies.valkey_object.as_str()])
            .arg("--label")
            .arg(format!(
                "io.nazoauth.deployment-id={}",
                dependencies.network.deployment_id
            ))
            .arg("--label")
            .arg(format!(
                "io.nazoauth.control-authority={}",
                dependencies.network.control_authority
            ))
            .arg("--label")
            .arg(format!(
                "io.nazoauth.runtime-instance-id={}-valkey",
                dependencies.runtime_instance_id
            ))
            .args(["--restart", "unless-stopped", "--network"])
            .arg(&dependencies.network.name)
            .arg("--volume")
            .arg(format!("{}:/data", dependencies.valkey_volume))
            .arg("--volume")
            .arg(format!(
                "{}:/run/nazoauth-secrets/valkey-password:ro",
                dependencies.valkey_password_file.display()
            ))
            .arg("--volume")
            .arg(format!(
                "{}:/run/nazoauth-secrets/valkey.acl:ro",
                dependencies.valkey_acl_file.display()
            ))
            .arg(&dependencies.valkey_image)
            .args([
                "valkey-server",
                "--aclfile",
                "/run/nazoauth-secrets/valkey.acl",
                "--appendonly",
                "yes",
                "--dir",
                "/data",
            ]);
        ensure_container(
            &self.command,
            &dependencies.valkey_object,
            &dependencies.network,
            valkey,
        )?;

        for _ in 0..60 {
            let postgres_ready = Process::new(&self.command)
                .args([
                    "exec",
                    dependencies.postgres_object.as_str(),
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                ])
                .arg(&dependencies.postgres_user)
                .arg("-d")
                .arg(&dependencies.postgres_database)
                .succeeds();
            let valkey_ready = Process::new(&self.command)
                .args([
                    "exec",
                    dependencies.valkey_object.as_str(),
                    "sh",
                    "-eu",
                    "-c",
                ])
                .arg("cat /run/nazoauth-secrets/valkey-password | valkey-cli --askpass PING")
                .succeeds();
            if postgres_ready && valkey_ready {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        bail!("managed PostgreSQL or Valkey did not become ready through Docker")
    }

    fn verify_runtime_database_privileges(
        &self,
        probe: &RuntimeDatabasePrivilegeProbe,
    ) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["run", "--rm", "--network"])
            .arg(&probe.network)
            .args([
                "--env",
                "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
                "--env",
                "PGPASSFILE=/run/nazoauth-secrets/pgpass",
                "--mount",
            ])
            .arg(format!(
                "type=bind,src={},dst=/run/nazoauth-secrets/pg_service.conf,readonly",
                probe.service_file.display()
            ))
            .arg("--mount")
            .arg(format!(
                "type=bind,src={},dst=/run/nazoauth-secrets/pgpass,readonly",
                probe.password_file.display()
            ))
            .arg(&probe.image)
            .args(["sh", "-eu", "-c", "if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TABLE nazoauth_runtime_ddl_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has persistent DDL permission' >&2; exit 1; fi; if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TEMPORARY TABLE nazoauth_runtime_temp_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has temporary DDL permission' >&2; exit 1; fi; exit 0"])
            .run_quiet()
    }

    fn install_host_service(&self, _install: &HostServiceInstall) -> anyhow::Result<()> {
        bail!("Docker does not install systemd host services")
    }

    #[cfg(debug_assertions)]
    fn run_debug_artifact_task(&self, task: &DebugArtifactTask) -> anyhow::Result<()> {
        Process::new(&self.command)
            .args(["run", "--rm"])
            .arg(&task.target)
            .arg("nazoauth")
            .args(&task.arguments)
            .run_quiet()
    }

    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String> {
        let output = Process::new(&self.command)
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

    fn resolve_local_image_id(&self, image_reference: &str) -> anyhow::Result<String> {
        let output = Process::new(&self.command)
            .args(["image", "inspect", image_reference, "--format", "{{.Id}}"])
            .stdout()?;
        normalize_local_image_id(output.trim())
            .context("Docker image has no immutable local content identity")
    }

    fn read_build_identity(
        &self,
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
            "Docker image returned an invalid build identity",
        )?))
    }
}

fn docker_one_shot_process(
    command: &std::ffi::OsStr,
    task: &OneShotTask,
) -> anyhow::Result<Process> {
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

fn normalize_local_image_id(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    valid_digest(&normalized).then_some(normalized)
}
