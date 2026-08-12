use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};

use crate::{
    ArtifactReference, RuntimeBackendKind,
    filesystem::{
        atomic_write, copy_atomic_from_file, ensure_directory_chain, open_secure_regular_file,
        read_secure_regular_file, set_mode, sha256, sha256_file, validate_secure_directory,
    },
    process::Process,
};

#[cfg(debug_assertions)]
use super::DebugArtifactTask;
use super::{
    BlobAttestationVerification, HostServiceInstall, ManagedDependencies, ManagedDependencyBackup,
    ManagedNetwork, ManagedPostgresCommand, ManagedPostgresRestore, ManagedValkeyRestore,
    OneShotTask, RuntimeBackend, RuntimeDatabasePrivilegeProbe, RuntimeObservation,
    RuntimeReplacement, safe_environment, safe_systemd_path,
};

pub struct SystemdBackend;

const SYSTEMD_TASKS_MAX: &str = "512";
const SYSTEMD_MEMORY_MAX: &str = "1G";
const SYSTEMD_CPU_QUOTA: &str = "200%";
const SYSTEMD_START_LIMIT_INTERVAL: &str = "60s";
const SYSTEMD_START_LIMIT_BURST: &str = "5";
const OPERATOR_CREDENTIAL_ENVIRONMENT: [(&str, &str); 3] = [
    ("NAZOAUTH_OPERATOR_CONTEXT_FILE", "operator-context"),
    (
        "NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE",
        "operator-controller-public-key",
    ),
    (
        "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE",
        "operator-config-manifest",
    ),
];

impl RuntimeBackend for SystemdBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Systemd
    }

    fn available(&self) -> bool {
        Process::new("systemctl")
            .args(["show", "--property=Version", "--value"])
            .succeeds()
            && Process::new("systemd-run").arg("--version").succeeds()
            && Process::new("systemd")
                .arg("--version")
                .stdout()
                .ok()
                .and_then(|output| parse_systemd_version(&output).ok())
                .is_some_and(|version| version >= 247)
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
            // A host commonly contains stale aliases or generated units that
            // disappear between list-unit-files and show. They are outside the
            // NazoAuth candidate set and must not make the whole read-only scan
            // unavailable.
            if let Ok(observation) = self.inspect(unit)
                && observation.server_command_verified
            {
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
                "--property=Id,LoadState,ActiveState,FragmentPath,ExecStart,Environment,EnvironmentFiles,User,Group,TasksMax,MemoryMax,CPUQuota,StartLimitIntervalUSec,StartLimitBurst,NoNewPrivileges,ProtectSystem,PrivateTmp",
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
        let local_artifact_id = match &artifact {
            ArtifactReference::HostBinary { sha256, .. } => Some(format!("sha256:{sha256}")),
            _ => None,
        };
        let environment = properties
            .get("Environment")
            .into_iter()
            .flat_map(|value| value.split_whitespace())
            .map(|value| serde_json::Value::String(value.trim_matches('"').to_owned()))
            .collect::<Vec<_>>();
        let safe_environment = safe_environment(&environment);
        let mut evidence = vec!["systemd ExecStart identifies nazoauth server".to_owned()];
        for (property, expected) in [
            ("TasksMax", SYSTEMD_TASKS_MAX),
            ("MemoryMax", SYSTEMD_MEMORY_MAX),
            ("CPUQuota", SYSTEMD_CPU_QUOTA),
            ("StartLimitBurst", SYSTEMD_START_LIMIT_BURST),
        ] {
            if properties
                .get(property)
                .is_some_and(|value| systemd_property_matches(property, value, expected))
            {
                evidence.push(format!("systemd {property} policy observed"));
            } else {
                missing.push(format!("systemd {property} policy is missing or drifted"));
            }
        }
        if properties
            .get("StartLimitIntervalUSec")
            .is_some_and(|value| {
                matches!(value.as_str(), "60000000" | "1min" | "60s" | "60000000us")
            })
        {
            evidence.push("systemd StartLimitIntervalSec policy observed".to_owned());
        } else {
            missing.push("systemd StartLimitIntervalSec policy is missing or drifted".to_owned());
        }
        for (property, expected) in [
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("PrivateTmp", "yes"),
        ] {
            if !properties
                .get(property)
                .is_some_and(|value| value.eq_ignore_ascii_case(expected))
            {
                missing.push(format!("systemd {property} hardening is not observable"));
            }
        }
        for variable in ["DEPLOYMENT_ID", "RUNTIME_INSTANCE_ID", "CONTROL_AUTHORITY"] {
            if !safe_environment.contains_key(variable) {
                missing.push(format!("systemd Environment is missing {variable}"));
            }
        }
        if properties
            .get("EnvironmentFiles")
            .is_some_and(|value| !value.is_empty() && value != "-")
        {
            evidence.push("systemd EnvironmentFiles observed".to_owned());
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
            local_artifact_id,
            ports: Vec::new(),
            networks: Vec::new(),
            mounts: Vec::new(),
            safe_environment,
            labels: BTreeMap::new(),
            evidence,
            missing,
        })
    }

    fn inspect_optional(
        &self,
        object_reference: &str,
    ) -> anyhow::Result<Option<RuntimeObservation>> {
        if object_reference.starts_with("process:") {
            return self.inspect(object_reference).map(Some);
        }
        validate_unit_name(object_reference)?;
        let output = Process::new("systemctl")
            .args([
                "show",
                object_reference,
                "--no-pager",
                "--property=LoadState",
                "--value",
            ])
            .output()?;
        if !output.status.success() {
            bail!("systemd could not inspect the recovery unit");
        }
        let load_state = String::from_utf8(output.stdout)
            .context("systemd returned a non-UTF-8 unit load state")?;
        if load_state.trim() == "not-found" {
            return Ok(None);
        }
        self.inspect(object_reference).map(Some)
    }

    fn verify_ownership(
        &self,
        object_reference: &str,
        deployment_id: &str,
        runtime_instance_id: &str,
        control_authority: &str,
    ) -> anyhow::Result<()> {
        validate_mutable_unit(object_reference)?;
        let observation = self.inspect(object_reference)?;
        if !observation.server_command_verified
            || !observation
                .safe_environment
                .get("DEPLOYMENT_ID")
                .is_some_and(|value| value == deployment_id)
            || !observation
                .safe_environment
                .get("RUNTIME_INSTANCE_ID")
                .is_some_and(|value| value == runtime_instance_id)
            || !observation
                .safe_environment
                .get("CONTROL_AUTHORITY")
                .is_some_and(|value| value == control_authority)
        {
            bail!("systemd unit identity does not match the authorized runtime");
        }
        let fragment_path = Process::new("systemctl")
            .args([
                "show",
                object_reference,
                "--property=FragmentPath",
                "--value",
            ])
            .stdout()?
            .trim()
            .to_owned();
        let fragment = read_secure_regular_file(
            Path::new(&fragment_path),
            "managed systemd unit",
            false,
            1024 * 1024,
        )?;
        if !fragment.starts_with(b"# Managed by nazoauthctl\n") {
            bail!("systemd unit is not an authorized nazoauthctl-managed file");
        }
        Ok(())
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

    fn quiesce_for_recovery(&self, object_reference: &str) -> anyhow::Result<()> {
        if object_reference.starts_with("process:") {
            if self.inspect(object_reference).is_ok() {
                bail!("an unmanaged host process cannot be stopped by the recovery controller");
            }
            return Ok(());
        }
        validate_mutable_unit(object_reference)?;
        let output = Process::new("systemctl")
            .args(["show", object_reference, "--property=LoadState", "--value"])
            .output()?;
        if !output.status.success() {
            bail!("systemd could not prove the recovery unit is stopped or absent");
        }
        let load_state = String::from_utf8(output.stdout)
            .context("systemd returned a non-UTF-8 unit load state")?;
        if load_state.trim() == "not-found" {
            return Ok(());
        }
        if self.inspect(object_reference)?.running {
            self.stop(object_reference)?;
        }
        if self.inspect(object_reference)?.running {
            bail!("systemd recovery unit remained active after stop");
        }
        Ok(())
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

    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()> {
        if replacement.container_policy.is_some() {
            bail!("systemd replacement cannot carry a container policy");
        }
        validate_mutable_unit(&replacement.object_reference)?;
        let ArtifactReference::HostBinary {
            path: source,
            sha256: expected,
        } = &replacement.artifact
        else {
            bail!("systemd replacement requires a digest-bound host binary");
        };
        let target = replacement
            .command
            .first()
            .map(PathBuf::from)
            .context("systemd replacement has no executable path")?;
        if !target.is_absolute()
            || target.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || !target
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| matches!(value, "nazoauth" | "nazoauth.exe"))
            || replacement.command.get(1).map(String::as_str) != Some("server")
        {
            bail!("systemd replacement command is not an absolute nazoauth server command");
        }
        let current_target = systemd_unit_executable(&replacement.object_reference)?;
        if current_target != target {
            bail!("systemd replacement target does not match the current unit ExecStart path");
        }
        validate_secure_directory(
            target
                .parent()
                .context("systemd replacement target has no parent")?,
            "systemd replacement target directory",
            false,
        )?;
        let mut source_file =
            open_secure_regular_file(source, "systemd replacement source", false)?;
        if source_file.metadata()?.len() == 0
            || sha256_file(&mut source_file, &source.display().to_string())? != *expected
        {
            bail!("systemd replacement source digest changed before activation");
        }
        self.stop(&replacement.object_reference)?;
        if systemd_unit_executable(&replacement.object_reference)? != target {
            bail!("systemd unit ExecStart changed during replacement");
        }
        copy_atomic_from_file(&mut source_file, &target, 0o755)?;
        let mut target_file =
            open_secure_regular_file(&target, "systemd replacement target", false)?;
        if sha256_file(&mut target_file, &target.display().to_string())? != *expected {
            bail!("systemd replacement target digest changed during activation");
        }
        self.start(&replacement.object_reference)
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

    fn ensure_managed_network(
        &self,
        _network: &ManagedNetwork,
    ) -> anyhow::Result<std::net::IpAddr> {
        bail!("systemd does not manage container networks")
    }

    fn ensure_managed_dependencies(
        &self,
        _dependencies: &ManagedDependencies,
    ) -> anyhow::Result<()> {
        bail!("systemd does not manage container dependencies")
    }

    fn verify_runtime_database_privileges(
        &self,
        _probe: &RuntimeDatabasePrivilegeProbe,
    ) -> anyhow::Result<()> {
        bail!("systemd does not run container database privilege probes")
    }

    fn install_host_service(&self, install: &HostServiceInstall) -> anyhow::Result<()> {
        validate_host_service_install(install)?;
        if !Process::new("id")
            .args(["-u", install.service_user.as_str()])
            .succeeds()
        {
            Process::new("useradd")
                .args(["--system", "--home"])
                .arg(&install.working_directory)
                .args([
                    "--shell",
                    "/usr/sbin/nologin",
                    install.service_user.as_str(),
                ])
                .run_quiet()?;
        }
        require_non_root_service_user(&install.service_user)?;
        configure_operator_state_permissions(install)?;
        let secrets_directory = install.working_directory.join("secrets");
        Process::new("chown")
            .arg(format!("root:{}", install.service_user))
            .arg(&install.working_directory)
            .arg(install.working_directory.join(".env.yaml"))
            .arg(&secrets_directory)
            .run_quiet()?;
        set_mode(&install.working_directory, 0o750)?;
        set_mode(&secrets_directory, 0o750)?;
        set_mode(&install.working_directory.join(".env.yaml"), 0o440)?;
        // The generation directory contains controller/audit private keys and
        // remains root-only.  Operator-task public context, controller key,
        // and config manifest are injected through LoadCredential below; do
        // not widen this directory merely to make those public files visible.
        for entry in fs::read_dir(&secrets_directory)? {
            let path = entry?.path();
            if path.file_name().is_some_and(|name| name == "dependencies") {
                Process::new("chown")
                    .arg("root:root")
                    .arg(&path)
                    .run_quiet()?;
                set_mode(&path, 0o700)?;
                continue;
            }
            let runtime_readable =
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        install
                            .runtime_readable_secret_names
                            .iter()
                            .any(|allowed| allowed == name)
                    });
            Process::new("chown")
                .arg(if runtime_readable {
                    format!("root:{}", install.service_user)
                } else {
                    "root:root".to_owned()
                })
                .arg(&path)
                .run_quiet()?;
            set_mode(&path, if runtime_readable { 0o440 } else { 0o600 })?;
        }
        Process::new("chown")
            .arg("root:root")
            .arg(&install.receipt_private_key)
            .run_quiet()?;
        set_mode(&install.receipt_private_key, 0o600)?;
        for path in [&install.app_root, &install.ui_releases] {
            Process::new("chown")
                .arg("-R")
                .arg(format!("{}:{}", install.service_user, install.service_user))
                .arg(path)
                .run_quiet()?;
        }
        let unit_directory = env::var_os("NAZOAUTH_SYSTEMD_UNIT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
        safe_systemd_path(&unit_directory)?;
        if unit_directory.is_symlink() {
            bail!("systemd unit directory must not be a symlink");
        }
        ensure_directory_chain(&unit_directory)?;
        set_mode(&unit_directory, 0o755)?;
        let unit_path = unit_directory.join(&install.service_name);
        match fs::symlink_metadata(&unit_path) {
            Ok(_) => {
                let existing = read_secure_regular_file(
                    &unit_path,
                    "existing systemd unit",
                    false,
                    1024 * 1024,
                )?;
                if !existing.starts_with(b"# Managed by nazoauthctl\n") {
                    bail!(
                        "refusing to replace an unmanaged systemd unit: {}",
                        unit_path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to inspect systemd unit"),
        }
        let rendered = render_host_service_unit(install)?;
        atomic_write(&unit_path, rendered.as_bytes(), 0o644)?;
        Process::new("systemctl").arg("daemon-reload").run_quiet()?;
        Process::new("systemctl")
            .args(["enable", install.service_name.as_str()])
            .run_quiet()
    }

    #[cfg(debug_assertions)]
    fn run_debug_artifact_task(&self, task: &DebugArtifactTask) -> anyhow::Result<()> {
        Process::new(&task.target).args(&task.arguments).run_quiet()
    }

    fn resolve_image_digest(&self, _image_reference: &str) -> anyhow::Result<String> {
        bail!("systemd backend does not manage OCI images")
    }

    fn resolve_local_image_id(&self, _image_reference: &str) -> anyhow::Result<String> {
        bail!("systemd backend does not manage OCI images")
    }

    fn read_build_identity(
        &self,
        artifact: &ArtifactReference,
        _local_artifact_id: Option<&str>,
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

pub fn render_host_service_unit(install: &HostServiceInstall) -> anyhow::Result<String> {
    validate_host_service_install(install)?;
    Ok(format!(
        "# Managed by nazoauthctl\n\
         [Unit]\n\
         Description=NazoAuth authorization server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec={start_limit_interval}\n\
         StartLimitBurst={start_limit_burst}\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={working}\n\
         ExecStart={binary} server\n\
         Environment=DEPLOYMENT_ID={deployment_id}\n\
         Environment=RUNTIME_INSTANCE_ID={runtime_instance_id}\n\
         Environment=CONTROL_AUTHORITY={control_authority}\n\
         Environment=DATA_DIR={app_root}\n\
         Environment=INSTANCE_IDENTITY_DIR={instance_dir}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         TasksMax={tasks_max}\n\
         MemoryMax={memory_max}\n\
         CPUQuota={cpu_quota}\n\
         NoNewPrivileges=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         LockPersonality=true\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         ReadWritePaths={keys} {avatars} {secrets} {bootstrap} {instance} {ui_releases}\n\
         InaccessiblePaths={operator_state} {operator_dir} {recovery_dir} {migration_url}\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = install.service_user,
        deployment_id = install.deployment_id,
        runtime_instance_id = install.runtime_instance_id,
        control_authority = install.control_authority,
        tasks_max = SYSTEMD_TASKS_MAX,
        memory_max = SYSTEMD_MEMORY_MAX,
        cpu_quota = SYSTEMD_CPU_QUOTA,
        start_limit_interval = SYSTEMD_START_LIMIT_INTERVAL,
        start_limit_burst = SYSTEMD_START_LIMIT_BURST,
        working = install.working_directory.display(),
        binary = install.binary.display(),
        app_root = install.app_root.display(),
        instance_dir = install.app_root.join("instance").display(),
        keys = install.app_root.join("keys").display(),
        avatars = install.app_root.join("avatars").display(),
        secrets = install.app_root.join("secrets").display(),
        bootstrap = install.app_root.join("bootstrap").display(),
        instance = install.app_root.join("instance").display(),
        ui_releases = install.ui_releases.display(),
        operator_state = install.operator_state.display(),
        operator_dir = install.operator_directory.display(),
        recovery_dir = install.recovery_directory.display(),
        migration_url = install.migration_url.display(),
    ))
}

fn validate_host_service_install(install: &HostServiceInstall) -> anyhow::Result<()> {
    validate_unit_name(&install.service_name)?;
    for (name, value) in [
        ("service user", install.service_user.as_str()),
        ("deployment id", install.deployment_id.as_str()),
        ("runtime instance id", install.runtime_instance_id.as_str()),
        ("control authority", install.control_authority.as_str()),
    ] {
        validate_systemd_scalar(name, value)?;
    }
    if matches!(install.service_user.as_str(), "root" | "0") {
        bail!("systemd service user must not be root");
    }
    for (name, path) in [
        ("working directory", &install.working_directory),
        ("binary path", &install.binary),
        ("application root", &install.app_root),
        ("UI releases path", &install.ui_releases),
        ("operator state path", &install.operator_state),
        ("operator directory", &install.operator_directory),
        ("recovery directory", &install.recovery_directory),
        ("migration URL path", &install.migration_url),
        ("receipt private key path", &install.receipt_private_key),
    ] {
        safe_systemd_path(path).with_context(|| format!("{name} is unsafe for a systemd unit"))?;
    }
    for name in &install.runtime_readable_secret_names {
        validate_systemd_scalar("runtime secret name", name)?;
    }
    Ok(())
}

fn validate_non_root_service_uid(output: &str) -> anyhow::Result<u32> {
    let uid = output
        .trim()
        .parse::<u32>()
        .context("systemd service user UID is not numeric")?;
    if uid == 0 {
        bail!("systemd service user must not resolve to UID 0");
    }
    Ok(uid)
}

fn require_non_root_service_user(user: &str) -> anyhow::Result<u32> {
    let output = Process::new("id")
        .args(["-u", user])
        .stdout()
        .with_context(|| format!("failed to resolve UID for systemd service user {user}"))?;
    validate_non_root_service_uid(&output)
}

fn configure_operator_state_permissions(install: &HostServiceInstall) -> anyhow::Result<()> {
    let state_parent = install
        .operator_state
        .parent()
        .context("operator state path has no parent directory")?;
    if install
        .operator_state
        .file_name()
        .and_then(|name| name.to_str())
        != Some("operator-state")
    {
        bail!("operator state path must end in operator-state");
    }
    validate_secure_directory(state_parent, "operator state parent", false)?;
    let state_metadata = fs::symlink_metadata(&install.operator_state).with_context(|| {
        format!(
            "failed to inspect operator state {}",
            install.operator_state.display()
        )
    })?;
    if state_metadata.file_type().is_symlink() || !state_metadata.is_dir() {
        bail!(
            "operator state must be a real directory: {}",
            install.operator_state.display()
        );
    }

    // The control root contains controller-owned siblings (audit and
    // deployment state).  Give the service group traverse-only access to the
    // root and make only the operator-state leaf service-owned.  This avoids
    // widening any private controller directory while allowing systemd-run's
    // service UID to reach its read/write state.
    Process::new("chown")
        .arg(format!("root:{}", install.service_user))
        .arg(state_parent)
        .run_quiet()?;
    set_mode(state_parent, 0o710)?;
    Process::new("chown")
        .arg(format!("{}:{}", install.service_user, install.service_user))
        .arg(&install.operator_state)
        .run_quiet()?;
    set_mode(&install.operator_state, 0o700)
}

fn validate_systemd_scalar(name: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '%' | '\'' | '"' | '\\')
        })
    {
        bail!("{name} contains unsupported systemd input characters");
    }
    Ok(())
}

pub fn parse_systemd_version(output: &str) -> anyhow::Result<u32> {
    let mut fields = output.lines().next().unwrap_or_default().split_whitespace();
    if fields.next() != Some("systemd") {
        bail!("systemd returned an invalid version banner");
    }
    fields
        .next()
        .context("systemd version is unavailable")?
        .parse()
        .context("systemd version is invalid")
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
    let process = Process::new("systemd-run")
        .timeout(std::time::Duration::from_secs(300))
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--property=TasksMax=512",
            "--property=MemoryMax=1G",
            "--property=CPUQuota=200%",
            "--property=StartLimitIntervalSec=60s",
            "--property=StartLimitBurst=5",
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
    let (mut process, credential_environment) = add_operator_credentials(process, task)?;
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
        require_non_root_service_user(user)?;
        process = process
            .arg(format!("--uid={user}"))
            .arg(format!("--gid={user}"));
    }
    for (name, value) in &task.environment {
        if credential_environment.contains(name.as_str()) {
            continue;
        }
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

fn add_operator_credentials(
    mut process: Process,
    task: &OneShotTask,
) -> anyhow::Result<(Process, BTreeSet<String>)> {
    let mut credential_environment = BTreeSet::new();
    for (environment, _) in OPERATOR_CREDENTIAL_ENVIRONMENT {
        let credential = operator_credential_name(environment)
            .expect("operator credential table contains its own environment key");
        let Some(source) = task.environment.get(environment) else {
            continue;
        };
        // A caller that already supplied a credential-directory locator has
        // completed this translation.  This keeps the backend compatible with
        // pre-materialized tasks while ensuring legacy absolute paths are
        // never exposed to the service process.
        if source.starts_with("%d/") {
            let expected = format!("%d/{credential}");
            if source.as_str() != expected || !task.transient_credentials.contains_key(credential) {
                bail!("{environment} has an unbound systemd credential locator");
            }
            continue;
        }
        safe_systemd_path(Path::new(source))
            .with_context(|| format!("{environment} must be a safe absolute credential source"))?;
        if task.transient_credentials.contains_key(credential) {
            bail!("operator credential name is already occupied: {credential}");
        }
        process = process
            .arg(format!("--property=LoadCredential={credential}:{source}"))
            .arg(format!("--setenv={environment}=%d/{credential}"));
        credential_environment.insert(environment.to_owned());
    }
    Ok((process, credential_environment))
}

fn operator_credential_name(environment: &str) -> Option<&'static str> {
    OPERATOR_CREDENTIAL_ENVIRONMENT
        .iter()
        .find(|(candidate, _)| *candidate == environment)
        .map(|(_, credential)| *credential)
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
            let local_artifact_id = match &artifact {
                ArtifactReference::HostBinary { sha256, .. } => Some(format!("sha256:{sha256}")),
                _ => None,
            };
            Some(RuntimeObservation {
                backend: RuntimeBackendKind::Systemd,
                object_reference: format!("process:{pid}"),
                display_name: format!("unmanaged process {pid}"),
                running: true,
                server_command_verified: true,
                artifact,
                local_artifact_id,
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

fn systemd_property_matches(property: &str, value: &str, expected: &str) -> bool {
    match property {
        "MemoryMax" => matches!(value, "1073741824" | "1G" | "1073741824B") && expected == "1G",
        _ => value == expected,
    }
}

fn executable_from_systemd(exec_start: &str) -> Option<String> {
    parse_systemd_exec_start(exec_start)
        .ok()
        .and_then(|argv| argv.into_iter().next())
}

fn systemd_unit_executable(object_reference: &str) -> anyhow::Result<PathBuf> {
    let output = Process::new("systemctl")
        .args([
            "show",
            object_reference,
            "--no-pager",
            "--property=ExecStart",
            "--value",
        ])
        .stdout()?;
    let argv = parse_systemd_exec_start(&output)?;
    if !is_nazoauth_server_argv(&argv) {
        bail!("systemd unit ExecStart is not an authorized nazoauth server command");
    }
    Ok(PathBuf::from(&argv[0]))
}

fn command_is_nazoauth_server(command: &str) -> bool {
    let command = command.strip_suffix('\n').unwrap_or(command);
    if validate_systemd_exec_input(command).is_err() {
        return false;
    }
    let command = command.trim();
    if command.starts_with('{') {
        return parse_systemd_exec_start(command).is_ok_and(|argv| is_nazoauth_server_argv(&argv));
    }
    let words = command
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    words.windows(2).any(is_nazoauth_server_argv)
}

fn is_nazoauth_server_argv(argv: &[String]) -> bool {
    argv.first()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "nazoauth" | "nazoauth.exe"))
        && argv.get(1).map(String::as_str) == Some("server")
}

fn parse_systemd_exec_start(value: &str) -> anyhow::Result<Vec<String>> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    validate_systemd_exec_input(value)?;
    let value = value.trim();
    let body = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .context("systemd ExecStart is not a single structured command")?;
    if body.contains(['{', '}']) {
        bail!("systemd ExecStart contains multiple structured commands");
    }

    let mut path = None;
    let mut argv_fields = Vec::new();
    let mut cursor = 0;
    let bytes = body.as_bytes();
    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b';')
        {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        let key_start = cursor;
        while cursor < bytes.len()
            && bytes[cursor] != b'='
            && !bytes[cursor].is_ascii_whitespace()
            && bytes[cursor] != b';'
        {
            cursor += 1;
        }
        if cursor == key_start || cursor == bytes.len() || bytes[cursor] != b'=' {
            bail!("systemd ExecStart contains a malformed field");
        }
        let key = &body[key_start..cursor];
        cursor += 1;
        let value_start = cursor;
        let mut escaped = false;
        while cursor < bytes.len() {
            match (bytes[cursor], escaped) {
                (b'\\', false) => {
                    escaped = true;
                    cursor += 1;
                }
                (b';', false) => break,
                (_, _) => {
                    escaped = false;
                    cursor += 1;
                }
            }
        }
        if escaped {
            bail!("systemd ExecStart contains a truncated escape");
        }
        let raw = body[value_start..cursor].trim();
        if raw.is_empty() {
            bail!("systemd ExecStart contains an empty field");
        }
        match key {
            "path" => {
                if path.is_some() {
                    bail!("systemd ExecStart contains multiple paths");
                }
                path = Some(decode_systemd_scalar(raw)?);
            }
            "argv[]" => argv_fields.push(raw),
            _ => {}
        }
        if cursor < bytes.len() {
            cursor += 1;
        }
    }

    let path = path.context("systemd ExecStart has no path field")?;
    let mut argv = Vec::new();
    for field in argv_fields {
        argv.extend(split_systemd_argv(field)?);
    }
    if argv.is_empty() {
        bail!("systemd ExecStart has no argv[] field");
    }
    if argv[0] != path {
        bail!("systemd ExecStart path and argv[0] differ");
    }
    Ok(argv)
}

fn decode_systemd_scalar(value: &str) -> anyhow::Result<String> {
    let values = split_systemd_argv(value)?;
    if values.len() != 1 {
        bail!("systemd ExecStart scalar contains multiple words");
    }
    Ok(values.into_iter().next().unwrap())
}

fn split_systemd_argv(value: &str) -> anyhow::Result<Vec<String>> {
    validate_systemd_exec_input(value)?;
    let bytes = value.as_bytes();
    let mut values = Vec::new();
    let mut current = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            if !current.is_empty() {
                values.push(String::from_utf8(std::mem::take(&mut current))?);
            }
            cursor += 1;
            continue;
        }
        if bytes[cursor] != b'\\' {
            if bytes[cursor] < 0x80 {
                current.push(bytes[cursor]);
                cursor += 1;
            } else {
                let character = value[cursor..]
                    .chars()
                    .next()
                    .context("systemd ExecStart contains invalid UTF-8")?;
                let length = character.len_utf8();
                current.extend_from_slice(&bytes[cursor..cursor + length]);
                cursor += length;
            }
            continue;
        }
        cursor += 1;
        if cursor >= bytes.len() {
            bail!("systemd ExecStart contains a truncated escape");
        }
        match bytes[cursor] {
            b'x' if cursor + 2 < bytes.len() => {
                let high = hex_value(bytes[cursor + 1])?;
                let low = hex_value(bytes[cursor + 2])?;
                current.push(high * 16 + low);
                cursor += 3;
            }
            b'n' => {
                current.push(b'\n');
                cursor += 1;
            }
            b'r' => {
                current.push(b'\r');
                cursor += 1;
            }
            b't' => {
                current.push(b'\t');
                cursor += 1;
            }
            b's' => {
                current.push(b' ');
                cursor += 1;
            }
            b'\\' | b'"' | b'\'' => {
                current.push(bytes[cursor]);
                cursor += 1;
            }
            _ => bail!("systemd ExecStart contains an unsupported escape"),
        }
    }
    if !current.is_empty() {
        values.push(String::from_utf8(current)?);
    }
    Ok(values)
}

fn hex_value(value: u8) -> anyhow::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("systemd ExecStart contains an invalid hex escape"),
    }
}

fn validate_systemd_exec_input(value: &str) -> anyhow::Result<()> {
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '%' | '\'' | '"' | '\\'))
    {
        bail!("systemd ExecStart contains unsupported control, specifier, quote, or escape input");
    }
    Ok(())
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
            .all(|character| character.is_ascii_alphanumeric() || "@_.:-".contains(character))
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

#[cfg(test)]
mod tests {
    use super::{
        command_is_nazoauth_server, operator_credential_name, parse_systemd_exec_start,
        systemd_property_matches, validate_non_root_service_uid,
    };

    #[test]
    fn operator_identity_files_use_transient_systemd_credentials() {
        assert_eq!(
            operator_credential_name("NAZOAUTH_OPERATOR_CONTEXT_FILE"),
            Some("operator-context")
        );
        assert_eq!(
            operator_credential_name("NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE"),
            Some("operator-controller-public-key")
        );
        assert_eq!(
            operator_credential_name("NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE"),
            Some("operator-config-manifest")
        );
        assert_eq!(operator_credential_name("DATABASE_URL_FILE"), None);
    }

    #[test]
    fn systemd_service_uid_must_not_be_root() {
        assert_eq!(validate_non_root_service_uid("10001\n").unwrap(), 10001);
        assert!(validate_non_root_service_uid("0\n").is_err());
        assert!(validate_non_root_service_uid("root\n").is_err());
    }

    #[test]
    fn parses_systemd_structured_exec_start_without_shell_splitting() {
        let value = "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server --label=hello-world ; ignore_errors=no ; }";
        assert_eq!(
            parse_systemd_exec_start(value).unwrap(),
            vec!["/opt/nazoauth", "server", "--label=hello-world"]
        );
        assert!(command_is_nazoauth_server(value));
    }

    #[test]
    fn rejects_ambiguous_or_mismatched_systemd_exec_start() {
        for value in [
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server ; } { path=/tmp/nazoauth ; argv[]=/tmp/nazoauth server ; }",
            "{ path=/opt/nazoauth ; argv[]=/tmp/nazoauth server ; }",
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server ; argv[]= ; }",
        ] {
            assert!(parse_systemd_exec_start(value).is_err());
            assert!(!command_is_nazoauth_server(value));
        }

        let unauthorized = "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth shell ; }";
        assert_eq!(
            parse_systemd_exec_start(unauthorized).unwrap(),
            vec!["/opt/nazoauth", "shell"]
        );
        assert!(!command_is_nazoauth_server(unauthorized));
    }

    #[test]
    fn simple_process_command_keeps_exact_server_contract() {
        assert!(command_is_nazoauth_server("/opt/nazoauth server"));
        assert!(!command_is_nazoauth_server("/opt/not-nazoauth server"));
        assert!(!command_is_nazoauth_server("/opt/nazoauth shell"));
    }

    #[test]
    fn rejects_untrusted_systemd_exec_start_boundaries() {
        for value in [
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server% ; }",
            "{ path=/opt/nazoauth ; argv[]=\"/opt/nazoauth server\" ; }",
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth\\ server ; }",
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server\r\n; }",
            "{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server\0 ; }",
            "{ path=/opt/nazo auth ; argv[]=/opt/nazo auth server ; }",
        ] {
            assert!(parse_systemd_exec_start(value).is_err(), "{value:?}");
            assert!(!command_is_nazoauth_server(value), "{value:?}");
        }
        assert!(
            parse_systemd_exec_start("{ path=/opt/nazoauth ; argv[]=/opt/nazoauth server ; }\n")
                .is_ok()
        );
    }

    #[test]
    fn accepts_systemd_show_limit_units_without_treating_missing_values_as_safe() {
        assert!(systemd_property_matches("TasksMax", "512", "512"));
        assert!(systemd_property_matches("MemoryMax", "1073741824", "1G"));
        assert!(systemd_property_matches("CPUQuota", "200%", "200%"));
        assert!(!systemd_property_matches("TasksMax", "infinity", "512"));
    }
}
