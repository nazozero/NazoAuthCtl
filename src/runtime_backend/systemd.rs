use std::{collections::BTreeMap, path::Path};

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, RuntimeBackendKind},
    filesystem::sha256,
    process::Process,
};

use super::{
    BlobAttestationVerification, ManagedDependencyBackup, ManagedPostgresCommand,
    ManagedPostgresRestore, ManagedValkeyRestore, OneShotTask, RuntimeBackend, RuntimeObservation,
    RuntimeReplacement,
};

pub(crate) struct SystemdBackend;

impl RuntimeBackend for SystemdBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Systemd
    }

    fn available(&self) -> bool {
        Process::new("systemctl")
            .args(["show", "--property=Version", "--value"])
            .succeeds()
    }

    fn verify_blob_attestation(
        &self,
        _verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()> {
        bail!("systemd cannot provide a containerized Cosign fallback")
    }

    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>> {
        let units = Process::new("systemctl")
            .args([
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
            ])
            .stdout()?;
        let mut observations = Vec::new();
        for unit in units
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|unit| unit.ends_with(".service"))
        {
            let observation = self.inspect(unit)?;
            if observation.server_command_verified {
                observations.push(observation);
            }
        }
        observations.extend(discover_unmanaged_processes()?);
        Ok(observations)
    }

    fn inspect(&self, object_reference: &str) -> anyhow::Result<RuntimeObservation> {
        if object_reference.starts_with("process:") {
            return inspect_process(object_reference);
        }
        validate_unit_name(object_reference)?;
        let output = Process::new("systemctl")
            .args([
                "show",
                object_reference,
                "--no-pager",
                "--property=Id,LoadState,ActiveState,FragmentPath,ExecStart,EnvironmentFiles",
            ])
            .stdout()?;
        let properties = parse_properties(&output);
        let exec_start = properties.get("ExecStart").cloned().unwrap_or_default();
        let executable = executable_from_systemd(&exec_start);
        let server_command_verified = command_is_nazoauth_server(&exec_start);
        let artifact = executable
            .as_deref()
            .and_then(|path| host_artifact(Path::new(path)).ok())
            .unwrap_or(ArtifactReference::Unknown);
        let mut missing = vec![
            "published ports are not declared by systemd".to_owned(),
            "network membership is not declared by systemd".to_owned(),
        ];
        if matches!(artifact, ArtifactReference::Unknown) {
            missing.push("host binary digest could not be resolved".to_owned());
        }
        Ok(RuntimeObservation {
            backend: self.kind(),
            object_reference: object_reference.to_owned(),
            display_name: properties
                .get("Id")
                .cloned()
                .unwrap_or_else(|| object_reference.to_owned()),
            running: properties
                .get("ActiveState")
                .is_some_and(|state| state == "active"),
            server_command_verified,
            artifact,
            ports: Vec::new(),
            networks: Vec::new(),
            mounts: Vec::new(),
            safe_environment: BTreeMap::new(),
            labels: BTreeMap::new(),
            evidence: vec!["systemd ExecStart identifies nazoauth server".to_owned()],
            missing,
        })
    }

    fn start(&self, object_reference: &str) -> anyhow::Result<()> {
        validate_mutable_unit(object_reference)?;
        Process::new("systemctl")
            .args(["start", object_reference])
            .run_quiet()
    }

    fn stop(&self, object_reference: &str) -> anyhow::Result<()> {
        validate_mutable_unit(object_reference)?;
        Process::new("systemctl")
            .args(["stop", object_reference])
            .run_quiet()
    }

    fn restart(&self, object_reference: &str) -> anyhow::Result<()> {
        validate_mutable_unit(object_reference)?;
        Process::new("systemctl")
            .args(["restart", object_reference])
            .run_quiet()
    }

    fn remove(&self, _object_reference: &str) -> anyhow::Result<()> {
        bail!("systemd unit removal is not an implicit runtime operation")
    }

    fn replace(&self, _replacement: &RuntimeReplacement) -> anyhow::Result<()> {
        bail!(
            "systemd artifact replacement requires an explicit staged binary transaction and is not inferred from a unit name"
        )
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        systemd_one_shot_process(task)?.stdin_stdout(&task.stdin)
    }

    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool> {
        systemd_one_shot_process(task)?.stdin_authorization_rejected(&task.stdin)
    }

    fn pull_image(&self, _image_reference: &str) -> anyhow::Result<()> {
        bail!("systemd backend does not manage OCI images")
    }

    fn export_image(
        &self,
        _image_reference: &str,
        _archive: &std::path::Path,
    ) -> anyhow::Result<()> {
        bail!("systemd backend does not manage OCI images")
    }

    fn import_image(&self, _archive: &std::path::Path) -> anyhow::Result<()> {
        bail!("systemd backend does not manage OCI images")
    }

    fn restore_managed_postgres(&self, _restore: &ManagedPostgresRestore) -> anyhow::Result<()> {
        bail!("systemd backend does not manage containerized PostgreSQL")
    }

    fn restore_managed_valkey(&self, _restore: &ManagedValkeyRestore) -> anyhow::Result<()> {
        bail!("systemd backend does not manage containerized Valkey")
    }

    fn execute_managed_postgres(&self, _command: &ManagedPostgresCommand) -> anyhow::Result<()> {
        bail!("systemd backend does not manage containerized PostgreSQL")
    }

    fn backup_managed_dependencies(&self, _backup: &ManagedDependencyBackup) -> anyhow::Result<()> {
        bail!("systemd does not manage container dependency backups")
    }

    fn resolve_image_digest(&self, _image_reference: &str) -> anyhow::Result<String> {
        bail!("systemd backend does not manage OCI images")
    }

    fn read_build_identity(
        &self,
        artifact: &ArtifactReference,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>> {
        let ArtifactReference::HostBinary {
            path,
            sha256: expected,
        } = artifact
        else {
            bail!("systemd build identity requires a digest-bound host binary");
        };
        if sha256(path)? != *expected {
            bail!("host binary no longer matches its trusted digest");
        }
        let output = Process::new(path).arg("build-identity").stdout()?;
        Ok(Some(serde_json::from_str(output.trim()).context(
            "host binary returned an invalid build identity",
        )?))
    }
}

fn systemd_one_shot_process(task: &OneShotTask) -> anyhow::Result<Process> {
    let ArtifactReference::HostBinary {
        path,
        sha256: expected,
    } = &task.artifact
    else {
        bail!("systemd one-shot task requires a digest-bound host binary");
    };
    if sha256(path)? != *expected {
        bail!("host one-shot binary does not match the authorized digest");
    }
    let unit = format!("nazoauthctl-task-{}", uuid::Uuid::now_v7());
    let mut process = Process::new("systemd-run")
        .timeout(std::time::Duration::from_secs(300))
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=PrivateDevices=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=",
        ])
        .arg(format!("--unit={unit}"));
    if task.private_mounts {
        process = process.arg("--property=PrivateMounts=yes");
    }
    if task.network.is_none() {
        process = process.arg("--property=RestrictAddressFamilies=AF_UNIX");
    }
    if let Some(directory) = &task.working_directory {
        process = process.arg(format!("--working-directory={}", directory.display()));
    }
    if let Some(user) = &task.service_user {
        process = process
            .arg(format!("--uid={user}"))
            .arg(format!("--gid={user}"));
    }
    for (name, value) in &task.environment {
        process = process.arg(format!("--setenv={name}={value}"));
    }
    for (name, source) in &task.transient_credentials {
        process = process.arg(format!(
            "--property=LoadCredential={name}:{}",
            source.display()
        ));
    }
    for path in &task.read_only_paths {
        process = process.arg(format!("--property=ReadOnlyPaths={}", path.display()));
    }
    for path in &task.read_write_paths {
        process = process.arg(format!("--property=ReadWritePaths={}", path.display()));
    }
    if !task.inaccessible_paths.is_empty() {
        process = process.arg(format!(
            "--property=InaccessiblePaths={}",
            task.inaccessible_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    for mount in &task.mounts {
        let property = if mount.read_only {
            "BindReadOnlyPaths"
        } else {
            "BindPaths"
        };
        process = process.arg(format!(
            "--property={property}={}:{}",
            mount.source.display(),
            mount.destination.display()
        ));
    }
    Ok(process.arg(path).args(&task.command))
}

fn discover_unmanaged_processes() -> anyhow::Result<Vec<RuntimeObservation>> {
    let output = Process::new("ps").args(["-eo", "pid=,args="]).stdout()?;
    Ok(output
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim().split_once(char::is_whitespace)?;
            if !command_is_nazoauth_server(command) {
                return None;
            }
            let executable = command.split_whitespace().next()?;
            let artifact =
                host_artifact(Path::new(executable)).unwrap_or(ArtifactReference::Unknown);
            Some(RuntimeObservation {
                backend: RuntimeBackendKind::Systemd,
                object_reference: format!("process:{pid}"),
                display_name: format!("unmanaged process {pid}"),
                running: true,
                server_command_verified: true,
                artifact,
                ports: Vec::new(),
                networks: Vec::new(),
                mounts: Vec::new(),
                safe_environment: BTreeMap::new(),
                labels: BTreeMap::new(),
                evidence: vec!["process command identifies nazoauth server".to_owned()],
                missing: vec![
                    "process is not controlled by a systemd unit".to_owned(),
                    "published ports and mounts are not safely observable".to_owned(),
                ],
            })
        })
        .collect())
}

fn inspect_process(object_reference: &str) -> anyhow::Result<RuntimeObservation> {
    let expected_pid = object_reference
        .strip_prefix("process:")
        .context("invalid process reference")?;
    let observations = discover_unmanaged_processes()?;
    observations
        .into_iter()
        .find(|observation| observation.object_reference == format!("process:{expected_pid}"))
        .context("discovered process is no longer running")
}

fn parse_properties(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn executable_from_systemd(exec_start: &str) -> Option<String> {
    let value = exec_start.split("path=").nth(1)?;
    let path = value.split(';').next()?.trim();
    (!path.is_empty()).then(|| path.to_owned())
}

fn command_is_nazoauth_server(command: &str) -> bool {
    let words = command.split_whitespace().collect::<Vec<_>>();
    words.windows(2).any(|pair| {
        pair[0].trim_end_matches(';').ends_with("nazoauth")
            && pair[1].trim_end_matches(';') == "server"
    })
}

fn host_artifact(path: &Path) -> anyhow::Result<ArtifactReference> {
    let path = std::fs::canonicalize(path)?;
    Ok(ArtifactReference::HostBinary {
        sha256: sha256(&path)?,
        path,
    })
}

fn validate_unit_name(unit: &str) -> anyhow::Result<()> {
    if !unit.ends_with(".service")
        || unit.len() > 256
        || !unit
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@_.:-\\".contains(character))
    {
        bail!("invalid systemd service reference");
    }
    Ok(())
}

fn validate_mutable_unit(object_reference: &str) -> anyhow::Result<()> {
    if object_reference.starts_with("process:") {
        bail!("unmanaged process cannot be mutated through the systemd backend");
    }
    validate_unit_name(object_reference)
}
