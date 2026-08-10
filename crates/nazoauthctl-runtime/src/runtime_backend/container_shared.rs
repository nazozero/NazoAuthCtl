//! Shared command construction and parsing for OCI container backends.
//!
//! Docker and Podman intentionally keep their runtime-specific discovery and
//! lifecycle details in their respective façades.  The command policy,
//! ownership checks, one-shot setup, and digest parsing are the same security
//! rules for both engines, so they live here to keep the two backends from
//! drifting.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::filesystem::set_mode;
use crate::filesystem::{atomic_write, open_secure_regular_file, sha256_file};
use crate::process::Process;
#[cfg(unix)]
use std::fs::File;

use super::{
    ContainerRestartPolicy, ContainerRuntimePolicy, ManagedDependencyBackup, ManagedNetwork,
    NeutralMount, OneShotTask, managed_network_config_digest,
};

/// Numeric uid/gid used for OCI one-shot work.  A name supplied by an image
/// is not an authorization boundary: the caller must provide the explicit
/// uid:gid contract and the engine must accept it.
pub(crate) const NON_ROOT_ONE_SHOT_USER: &str = "10001:10001";

const ENGINE_FIXED_MOUNT_DESTINATIONS: &[&str] =
    &["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"];
const ENGINE_FIXED_ENV_NAMES: &[&str] = &[
    "PATH", "HOSTNAME", "HOME", "TERM", "LANG", "LC_ALL", "PGDATA",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DependencyRestoreJournal {
    pub version: u32,
    pub backend: String,
    pub deployment_id: String,
    pub control_authority: String,
    pub runtime_instance_id: String,
    pub manifest_digest: String,
    pub phase: String,
    pub postgres_database: Option<String>,
    pub postgres_quarantine_database: Option<String>,
    pub valkey_temporary_volume: Option<String>,
    pub valkey_quarantine_volume: Option<String>,
}

pub(crate) fn dependency_restore_journal_path(backup: &Path) -> anyhow::Result<PathBuf> {
    let parent = backup
        .parent()
        .context("managed dependency backup has no journal parent")?;
    let name = backup
        .file_name()
        .and_then(|value| value.to_str())
        .context("managed dependency backup name is not UTF-8")?;
    if name.is_empty() || name.contains(['/', '\\']) {
        bail!("managed dependency backup name is unsafe");
    }
    Ok(parent.join(format!(".nazoauth-managed-restore-{name}.json")))
}

pub(crate) fn backup_manifest_digest(backup: &Path) -> anyhow::Result<String> {
    let path = backup.join("SHA256SUMS");
    let mut file = open_secure_regular_file(&path, "backup checksum manifest", false)?;
    sha256_file(&mut file, &path.display().to_string())
}

pub fn oci_backup_digests(backup: &Path) -> anyhow::Result<(String, String)> {
    let manifest_path = backup.join("SHA256SUMS");
    let marker_path = backup.join("BACKUP-COMPLETE");
    let manifest_digest = secure_file_digest(&manifest_path, "backup checksum manifest")?;
    let completion_marker_digest = secure_file_digest(&marker_path, "backup completion marker")?;
    let marker = crate::filesystem::read_secure_regular_file(
        &marker_path,
        "backup completion marker",
        false,
        4096,
    )?;
    let marker = std::str::from_utf8(&marker).context("backup completion marker is not UTF-8")?;
    let mut marker_name = None;
    let mut marker_version = None;
    let mut marker_manifest = None;
    for line in marker.lines() {
        let (name, value) = line
            .split_once('=')
            .context("backup completion marker entry is invalid")?;
        match name {
            "marker" => marker_name = Some(value),
            "version" => marker_version = Some(value),
            "manifest-sha256" => marker_manifest = Some(value),
            _ => bail!("backup completion marker contains an unknown field"),
        }
    }
    if marker_name != Some("BACKUP-COMPLETE")
        || marker_version != Some("1")
        || marker_manifest != Some(manifest_digest.as_str())
    {
        bail!("backup completion marker is invalid or incomplete");
    }
    Ok((manifest_digest, completion_marker_digest))
}

#[cfg(unix)]
pub(crate) fn verify_oci_backup_artifacts(
    backup: &Path,
    expected_manifest_digest: &str,
    expected_completion_marker_digest: &str,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let directory = fs::symlink_metadata(backup)
        .with_context(|| format!("failed to inspect OCI backup {}", backup.display()))?;
    if directory.file_type().is_symlink()
        || !directory.is_dir()
        || directory.uid() != 0
        || directory.gid() != 10001
        || directory.mode() & 0o7777 != 0o750
    {
        bail!("OCI backup directory ownership or mode is not the installation contract");
    }
    if !lower_hex_digest(expected_manifest_digest)
        || !lower_hex_digest(expected_completion_marker_digest)
    {
        bail!("OCI backup digest contract is invalid");
    }
    let manifest_path = backup.join("SHA256SUMS");
    let marker_path = backup.join("BACKUP-COMPLETE");
    require_oci_backup_file(&manifest_path)?;
    require_oci_backup_file(&marker_path)?;
    let manifest_digest = secure_file_digest(&manifest_path, "backup checksum manifest")?;
    let marker_digest = secure_file_digest(&marker_path, "backup completion marker")?;
    if manifest_digest != expected_manifest_digest
        || marker_digest != expected_completion_marker_digest
    {
        bail!("OCI backup completion evidence does not match the restore request");
    }
    let marker = crate::filesystem::read_secure_regular_file(
        &marker_path,
        "backup completion marker",
        false,
        4096,
    )?;
    let marker = std::str::from_utf8(&marker).context("backup completion marker is not UTF-8")?;
    let mut marker_name = None;
    let mut marker_version = None;
    let mut marker_manifest = None;
    for line in marker.lines() {
        let (name, value) = line
            .split_once('=')
            .context("backup completion marker entry is invalid")?;
        match name {
            "marker" => marker_name = Some(value),
            "version" => marker_version = Some(value),
            "manifest-sha256" => marker_manifest = Some(value),
            _ => bail!("backup completion marker contains an unknown field"),
        }
    }
    if marker_name != Some("BACKUP-COMPLETE")
        || marker_version != Some("1")
        || marker_manifest != Some(expected_manifest_digest)
    {
        bail!("backup completion marker is invalid or incomplete");
    }
    let manifest = crate::filesystem::read_secure_regular_file(
        &manifest_path,
        "backup checksum manifest",
        false,
        1024 * 1024,
    )?;
    let manifest =
        std::str::from_utf8(&manifest).context("backup checksum manifest is not UTF-8")?;
    let mut listed = std::collections::BTreeSet::new();
    for line in manifest.lines() {
        let (digest, name) = line
            .split_once("  ")
            .context("backup checksum entry is invalid")?;
        if !lower_hex_digest(digest)
            || name.is_empty()
            || name.starts_with('.')
            || name.contains(['/', '\\'])
            || name == "SHA256SUMS"
            || name == "BACKUP-COMPLETE"
            || !listed.insert(name.to_owned())
        {
            bail!("backup checksum entry is unsafe");
        }
        let artifact = backup.join(name);
        require_oci_backup_file(&artifact)?;
        if secure_file_digest(&artifact, "backup checksum target")? != digest {
            bail!("backup checksum mismatch: {name}");
        }
    }
    for entry in fs::read_dir(backup).context("failed to enumerate OCI backup")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "SHA256SUMS" && name != "BACKUP-COMPLETE" && !listed.contains(name.as_str()) {
            bail!("OCI backup contains an unlisted artifact");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn verify_oci_backup_artifacts(
    backup: &Path,
    expected_manifest_digest: &str,
    expected_completion_marker_digest: &str,
) -> anyhow::Result<()> {
    let _ = (
        backup,
        expected_manifest_digest,
        expected_completion_marker_digest,
    );
    bail!("OCI backup ownership cannot be proven on this host")
}

#[cfg(unix)]
fn require_oci_backup_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect OCI backup artifact {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 10001
        || metadata.mode() & 0o7777 != 0o440
    {
        bail!("OCI backup artifact ownership or mode is not the installation contract");
    }
    Ok(())
}

fn secure_file_digest(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut file = open_secure_regular_file(path, label, false)?;
    sha256_file(&mut file, &path.display().to_string())
}

#[cfg(unix)]
fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn load_dependency_restore_journal(
    backup: &Path,
    backend: &str,
    identity: &super::ManagedDependencyIdentity,
) -> anyhow::Result<(PathBuf, DependencyRestoreJournal)> {
    let path = dependency_restore_journal_path(backup)?;
    let manifest_digest = backup_manifest_digest(backup)?;
    let journal_exists = match fs::symlink_metadata(&path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("failed to inspect managed restore journal"),
    };
    let journal = if journal_exists {
        let bytes = crate::filesystem::read_secure_regular_file(
            &path,
            "managed dependency restore journal",
            false,
            64 * 1024,
        )?;
        serde_json::from_slice(&bytes).context("managed dependency restore journal is invalid")?
    } else {
        DependencyRestoreJournal {
            version: 1,
            backend: backend.to_owned(),
            deployment_id: identity.deployment_id.clone(),
            control_authority: identity.control_authority.clone(),
            runtime_instance_id: identity.runtime_instance_id.clone(),
            manifest_digest: manifest_digest.clone(),
            phase: "started".to_owned(),
            postgres_database: None,
            postgres_quarantine_database: None,
            valkey_temporary_volume: None,
            valkey_quarantine_volume: None,
        }
    };
    if journal.version != 1
        || journal.backend != backend
        || journal.deployment_id != identity.deployment_id
        || journal.control_authority != identity.control_authority
        || journal.runtime_instance_id != identity.runtime_instance_id
        || journal.manifest_digest != manifest_digest
    {
        bail!("managed dependency restore journal is not bound to this deployment");
    }
    if !matches!(
        journal.phase.as_str(),
        "started"
            | "postgres-prepared"
            | "postgres-old-quarantined"
            | "postgres-swapped"
            | "valkey-prepared"
            | "valkey-old-quarantined"
            | "valkey-swapped"
            | "complete"
    ) {
        bail!("managed dependency restore journal contains an unknown phase");
    }
    Ok((path, journal))
}

pub(crate) fn persist_dependency_restore_journal(
    path: &Path,
    journal: &DependencyRestoreJournal,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(journal).context("failed to encode restore journal")?;
    atomic_write(path, &bytes, 0o600)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .with_context(|| format!("failed to open {} for synchronization", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to synchronize {}", parent.display()))?;
    }
    Ok(())
}

pub(crate) struct TemporaryPostgresCredentials {
    directory: PathBuf,
    service_file: PathBuf,
    password_file: PathBuf,
}

impl TemporaryPostgresCredentials {
    pub(crate) fn service_file(&self) -> &Path {
        &self.service_file
    }

    pub(crate) fn password_file(&self) -> &Path {
        &self.password_file
    }
}

impl Drop for TemporaryPostgresCredentials {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn postgres_database_from_service_file(path: &Path) -> anyhow::Result<String> {
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "PostgreSQL service file",
        false,
        16 * 1024,
    )?;
    let value = std::str::from_utf8(&bytes).context("PostgreSQL service file is not UTF-8")?;
    let database = value
        .lines()
        .find_map(|line| line.strip_prefix("dbname="))
        .context("PostgreSQL service file has no dbname")?;
    validate_sql_identifier(database, "PostgreSQL database")?;
    Ok(database.to_owned())
}

pub(crate) fn temporary_postgres_credentials(
    service_file: &Path,
    password_file: &Path,
    database: &str,
) -> anyhow::Result<TemporaryPostgresCredentials> {
    validate_sql_identifier(database, "temporary PostgreSQL database")?;
    let service_bytes = crate::filesystem::read_secure_regular_file(
        service_file,
        "PostgreSQL service file",
        false,
        16 * 1024,
    )?;
    let password_bytes = crate::filesystem::read_secure_regular_file(
        password_file,
        "PostgreSQL password file",
        false,
        16 * 1024,
    )?;
    let service = rewrite_postgres_service_database(&service_bytes, database)?;
    let password = wildcard_pgpass(&password_bytes)?;
    let directory = std::env::temp_dir().join(format!(
        ".nazoauth-pg-restore-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir(&directory)
        .context("failed to create PostgreSQL restore credential directory")?;
    prepare_non_root_directory(&directory)?;
    let service_path = directory.join("pg_service.conf");
    let password_path = directory.join("pgpass");
    if let Err(error) = (|| -> anyhow::Result<()> {
        atomic_write(&service_path, &service, 0o440)?;
        atomic_write(&password_path, &password, 0o440)?;
        prepare_non_root_readable(&service_path)?;
        prepare_non_root_readable(&password_path)?;
        Ok(())
    })() {
        let _ = fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(TemporaryPostgresCredentials {
        directory,
        service_file: service_path,
        password_file: password_path,
    })
}

#[cfg(unix)]
fn prepare_non_root_readable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::chown;
    chown(path, Some(0), Some(10001)).with_context(|| {
        format!(
            "failed to assign restore credential group for {}",
            path.display()
        )
    })?;
    set_mode(path, 0o440)?;
    File::open(path)
        .with_context(|| format!("failed to reopen restore credential {}", path.display()))?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to synchronize restore credential {}",
                path.display()
            )
        })
}

#[cfg(not(unix))]
fn prepare_non_root_readable(path: &Path) -> anyhow::Result<()> {
    let _ = path;
    bail!("OCI restore credentials require a host group readable by UID:GID 10001:10001")
}

fn prepare_non_root_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        chown(path, Some(0), Some(10001)).with_context(|| {
            format!(
                "failed to assign restore credential directory ownership for {}",
                path.display()
            )
        })?;
        set_mode(path, 0o750)?;
        File::open(path)
            .with_context(|| {
                format!(
                    "failed to reopen restore credential directory {}",
                    path.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to synchronize restore credential directory {}",
                    path.display()
                )
            })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("OCI restore credentials require a host group readable by UID:GID 10001:10001");
    }
}

pub(crate) fn validate_sql_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("{label} is not a safe SQL identifier");
    }
    Ok(())
}

fn rewrite_postgres_service_database(bytes: &[u8], database: &str) -> anyhow::Result<Vec<u8>> {
    let value = std::str::from_utf8(bytes).context("PostgreSQL service file is not UTF-8")?;
    let mut found = false;
    let mut output = String::new();
    for line in value.lines() {
        if let Some(existing) = line.strip_prefix("dbname=") {
            if existing.is_empty() || existing.chars().any(char::is_whitespace) {
                bail!("PostgreSQL service file has an unsafe dbname");
            }
            output.push_str("dbname=");
            output.push_str(database);
            found = true;
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    if !found {
        bail!("PostgreSQL service file has no dbname");
    }
    Ok(output.into_bytes())
}

fn wildcard_pgpass(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let value = std::str::from_utf8(bytes).context("PostgreSQL password file is not UTF-8")?;
    let mut output = String::new();
    for line in value.lines() {
        let mut separators = Vec::new();
        let mut escaped = false;
        for (index, byte) in line.as_bytes().iter().copied().enumerate() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b':' {
                separators.push(index);
            }
        }
        if separators.len() != 4 || line.is_empty() {
            bail!("PostgreSQL password file has an invalid entry");
        }
        output.push_str(&line[..separators[1] + 1]);
        output.push('*');
        output.push_str(&line[separators[2]..]);
        output.push('\n');
    }
    if output.is_empty() {
        bail!("PostgreSQL password file is empty");
    }
    Ok(output.into_bytes())
}

const DEPLOYMENT_LABEL: &str = "io.nazoauth.deployment-id";
const AUTHORITY_LABEL: &str = "io.nazoauth.control-authority";
const RUNTIME_INSTANCE_LABEL: &str = "io.nazoauth.runtime-instance-id";
const RESOURCE_KIND_LABEL: &str = "io.nazoauth.managed-resource";
const CONFIG_DIGEST_LABEL: &str = "io.nazoauth.config-digest";

pub(crate) fn network_config_digest(network: &ManagedNetwork) -> String {
    managed_network_config_digest(
        &network.deployment_id,
        &network.control_authority,
        &network.name,
    )
}

/// Build the common hardening flags used by managed containers.
pub(crate) fn append_container_policy(
    mut command: Process,
    policy: &ContainerRuntimePolicy,
) -> Process {
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

/// Back up the managed PostgreSQL and Valkey data and validate the archive.
///
/// Podman needs an SELinux relabel on the validation bind mount; Docker uses
/// its explicit `--mount` spelling.  Keeping that one dialect switch here
/// avoids duplicating the backup/BGSAVE state machine in both backends.
pub(crate) fn backup_managed_dependencies(
    command: &OsStr,
    backup: &ManagedDependencyBackup,
    selinux_relabel: bool,
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
    prepare_oci_backup_output(&postgres)?;

    let validation = if selinux_relabel {
        append_build_identity_policy(Process::new(command).args(["run", "--rm", "-v"]))
            .arg(format!("{}:/backup:ro,Z", backup.destination.display()))
    } else {
        append_build_identity_policy(Process::new(command).args(["run", "--rm", "--mount"])).arg(
            format!(
                "type=bind,src={},dst=/backup,readonly",
                backup.destination.display()
            ),
        )
    };
    validation
        .arg(&backup.postgres_validation_image)
        .args(["pg_restore", "--list", "/backup/postgresql.dump"])
        .run_quiet()?;

    let output = |arguments: &[&str]| -> anyhow::Result<String> {
        if let Some(password_file) = &backup.valkey_password_file {
            return Process::new(command)
                .args(["exec", backup.valkey_object.as_str(), "sh", "-eu", "-c"])
                .arg("password_file=$1; shift; exec valkey-cli --askpass \"$@\" < \"$password_file\"")
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
        .run_quiet()?;
    prepare_oci_backup_output(&backup.destination.join("valkey-dump.rdb"))
}

fn prepare_oci_backup_output(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, chown};
        let parent = path
            .parent()
            .context("OCI backup artifact has no parent directory")?;
        let directory = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect OCI backup directory {}",
                parent.display()
            )
        })?;
        if directory.uid() != 0 || directory.gid() != 10001 || directory.mode() & 0o7777 != 0o750 {
            bail!("OCI backup directory ownership or mode is not the installation contract");
        }
        chown(path, Some(0), Some(10001)).with_context(|| {
            format!(
                "failed to assign OCI backup artifact ownership for {}",
                path.display()
            )
        })?;
        set_mode(path, 0o440)?;
        File::open(path)
            .with_context(|| format!("failed to reopen OCI backup artifact {}", path.display()))?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to synchronize OCI backup artifact {}",
                    path.display()
                )
            })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("OCI backup ownership cannot be proven on this host");
    }
}

/// Require the complete managed-resource identity before an operation can
/// inspect or mutate an engine object.  A deployment/authority pair is only a
/// coarse namespace; runtime id, resource role and configuration digest close
/// the cross-instance and stale-configuration gaps.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_managed_labels(
    command: &OsStr,
    arguments: &[&str],
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let mut expected_labels = vec![
        (DEPLOYMENT_LABEL, deployment_id),
        (AUTHORITY_LABEL, control_authority),
        (RESOURCE_KIND_LABEL, resource_kind),
        (CONFIG_DIGEST_LABEL, config_digest),
    ];
    if let Some(runtime_instance_id) = runtime_instance_id {
        expected_labels.push((RUNTIME_INSTANCE_LABEL, runtime_instance_id));
    }
    let document = inspect_document(command, arguments, backend_name)?;
    let labels = document
        .get("Config")
        .and_then(|config| config.get("Labels"))
        .or_else(|| document.get("Labels"))
        .and_then(serde_json::Value::as_object);
    for (label, expected) in expected_labels {
        if !labels
            .and_then(|labels| labels.get(label))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == expected)
        {
            bail!(
                "refusing to manage a {backend_name} object without the expected immutable managed-resource identity"
            );
        }
    }
    Ok(())
}

/// Compare the engine-reported image reference before touching a managed
/// container.  The image reference is expected to be digest-pinned by the
/// install/recovery policy; accepting a tag or an unavailable inspect field
/// would turn the labels back into the only trust boundary.
pub(crate) fn assert_container_image(
    command: &OsStr,
    arguments: &[&str],
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    require_digest_pinned_image(expected_image, backend_name)?;
    let expected_digest = expected_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| format!("sha256:{digest}"))
        .filter(|digest| valid_digest(digest))
        .context("managed dependency image has an invalid digest")?;
    let document = inspect_document(command, arguments, backend_name)?;
    let mut actual = Vec::new();
    for value in [
        document.pointer("/Config/Image"),
        document.get("ImageName"),
        document.pointer("/Config/ImageName"),
    ]
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    {
        actual.push(value.to_owned());
    }
    if let Some(values) = document
        .get("RepoDigests")
        .and_then(serde_json::Value::as_array)
    {
        actual.extend(
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    if actual.iter().any(|value| {
        value == expected_image
            || value == &expected_digest
            || value.ends_with(&format!("@{expected_digest}"))
    }) {
        return Ok(());
    }
    bail!("refusing to manage a {backend_name} container whose immutable image does not match")
}

pub(crate) fn require_digest_pinned_image(
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let Some((_, digest)) = expected_image.rsplit_once('@') else {
        bail!("{backend_name} managed dependency image is not digest-pinned");
    };
    if valid_digest(digest) {
        return Ok(());
    }
    bail!("{backend_name} managed dependency image is not digest-pinned")
}

pub(crate) fn append_managed_labels(
    mut command: Process,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
) -> Process {
    command = command
        .arg("--label")
        .arg(format!("{DEPLOYMENT_LABEL}={deployment_id}"))
        .arg("--label")
        .arg(format!("{AUTHORITY_LABEL}={control_authority}"))
        .arg("--label")
        .arg(format!("{RESOURCE_KIND_LABEL}={resource_kind}"))
        .arg("--label")
        .arg(format!("{CONFIG_DIGEST_LABEL}={config_digest}"));
    if let Some(runtime_instance_id) = runtime_instance_id {
        command = command
            .arg("--label")
            .arg(format!("{RUNTIME_INSTANCE_LABEL}={runtime_instance_id}"));
    }
    command
}

pub(crate) fn network_gateway(document: &serde_json::Value) -> Option<std::net::IpAddr> {
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

pub(crate) fn ensure_volume(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let arguments = ["volume", "inspect", name];
    if inspect_document_optional(command, &arguments, backend_name)?.is_some() {
        return assert_managed_labels(
            command,
            &arguments,
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        );
    }
    append_managed_labels(
        Process::new(command).args(["volume", "create"]),
        &network.deployment_id,
        &network.control_authority,
        Some(runtime_instance_id),
        resource_kind,
        config_digest,
    )
    .arg(name)
    .run_quiet()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_container(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    expected_image: &str,
    create: Process,
    backend_name: &str,
    policy: &ContainerRuntimePolicy,
    expected_mounts: &[(&str, bool, Option<&str>)],
    expected_environment: &[(&str, &str)],
) -> anyhow::Result<()> {
    let arguments = ["container", "inspect", name];
    if inspect_document_optional(command, &arguments, backend_name)?.is_some() {
        assert_managed_labels(
            command,
            &arguments,
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        )?;
        assert_container_image(command, &arguments, expected_image, backend_name)?;
        assert_managed_container_policy(
            command,
            &arguments,
            backend_name,
            policy,
            &network.name,
            expected_mounts,
            expected_environment,
        )?;
        return Process::new(command).args(["start", name]).run_quiet();
    }
    create.run_quiet()
}

/// Inspect a single engine object as JSON.  The JSON path is deliberately
/// shared by Docker and Podman so a template failure cannot be mistaken for a
/// missing object.  Engine/daemon failures are surfaced as a distinct,
/// fail-closed error instead of triggering create-on-failure behavior.
pub(crate) fn inspect_document(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<serde_json::Value> {
    inspect_document_optional(command, arguments, backend_name)?
        .context(format!("{backend_name} managed object is absent"))
}

pub(crate) fn inspect_document_optional(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let output = Process::new(command)
        .args(arguments)
        .arg("--format")
        .arg("{{json .}}")
        .output()
        .with_context(|| format!("{backend_name} engine unavailable"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if is_not_found_error(&stderr) {
            return Ok(None);
        }
        if stderr_engine_unavailable(&stderr) {
            bail!("{backend_name} engine unavailable while inspecting a managed object");
        }
        bail!("{backend_name} object inspection failed");
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{backend_name} inspect returned invalid JSON"))?;
    let value = parsed
        .as_array()
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or(parsed);
    Ok(Some(value))
}

pub(crate) fn container_is_running(
    command: &OsStr,
    object: &str,
    backend_name: &str,
) -> anyhow::Result<bool> {
    let arguments = ["container", "inspect", object];
    let document = inspect_document(command, &arguments, backend_name)?;
    document
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .context("container inspect omitted running state")
}

pub(crate) fn command_stdout(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<String> {
    let output = Process::new(command)
        .args(arguments)
        .output()
        .with_context(|| format!("{backend_name} engine unavailable"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr_engine_unavailable(&stderr) {
            bail!("{backend_name} engine unavailable");
        }
        bail!("{backend_name} command failed");
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("{backend_name} command returned non-UTF-8 output"))
}

pub(crate) fn is_engine_unavailable_error(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("engine unavailable")
}

fn is_not_found_error(stderr: &str) -> bool {
    stderr.contains("no such object")
        || stderr.contains("no such container")
        || stderr.contains("no such volume")
        || stderr.contains("no such network")
        || stderr.contains("no volume with name")
        || stderr.contains("no container with name or id")
        || stderr.contains("network not found")
        || stderr.contains("volume not found")
        || stderr.contains("not found")
}

fn stderr_engine_unavailable(stderr: &str) -> bool {
    stderr.contains("cannot connect")
        || stderr.contains("connection refused")
        || stderr.contains("unable to connect")
        || stderr.contains("connection to")
        || stderr.contains("is the docker daemon running")
        || stderr.contains("podman machine")
        || stderr.contains("failed to connect")
        || stderr.contains("cannot communicate")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_managed_container_policy(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
    policy: &ContainerRuntimePolicy,
    expected_network: &str,
    expected_mounts: &[(&str, bool, Option<&str>)],
    expected_environment: &[(&str, &str)],
) -> anyhow::Result<()> {
    let document = inspect_document(command, arguments, backend_name)?;
    let host_config = document
        .get("HostConfig")
        .context("container inspect omitted HostConfig")?;

    let restart = host_config
        .pointer("/RestartPolicy/Name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expected_restart = match policy.restart {
        ContainerRestartPolicy::No => "no",
        ContainerRestartPolicy::OnFailure => "on-failure",
        ContainerRestartPolicy::Always => "always",
        ContainerRestartPolicy::UnlessStopped => "unless-stopped",
    };
    if restart != expected_restart {
        bail!("{backend_name} managed container restart policy drifted");
    }
    if policy.read_only_root
        && !host_config
            .get("ReadonlyRootfs")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        bail!("{backend_name} managed container read-only root policy drifted");
    }
    if policy.no_new_privileges
        && !host_config
            .get("SecurityOpt")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|value| {
                value.eq_ignore_ascii_case("no-new-privileges")
                    || value.to_ascii_lowercase().starts_with("no-new-privileges=")
            })
    {
        bail!("{backend_name} managed container no-new-privileges policy drifted");
    }
    if policy.drop_all_capabilities
        && !host_config
            .get("CapDrop")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|value| value.eq_ignore_ascii_case("ALL"))
    {
        bail!("{backend_name} managed container capability policy drifted");
    }
    if let Some(limit) = policy.pids_limit
        && host_config
            .get("PidsLimit")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u32::try_from(value).ok())
            != Some(limit)
    {
        bail!("{backend_name} managed container pids limit drifted");
    }
    if let Some(limit) = policy.memory_limit_bytes
        && host_config
            .get("Memory")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok())
            != Some(limit)
    {
        bail!("{backend_name} managed container memory limit drifted");
    }
    if let Some(limit) = policy.cpu_limit_millis {
        let expected_nano_cpus = u64::from(limit) * 1_000_000;
        let nano_cpus = host_config
            .get("NanoCpus")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok());
        let quota = host_config
            .get("CpuQuota")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok());
        if nano_cpus != Some(expected_nano_cpus) && quota != Some(u64::from(limit) * 100) {
            bail!("{backend_name} managed container CPU limit drifted");
        }
    }
    for tmpfs in &policy.tmpfs {
        let destination = tmpfs.destination.to_string_lossy();
        let observed = host_config
            .get("Tmpfs")
            .and_then(serde_json::Value::as_object)
            .and_then(|tmpfses| tmpfses.get(destination.as_ref()));
        let options = match observed {
            Some(serde_json::Value::String(value)) => value.to_ascii_lowercase(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
                .to_ascii_lowercase(),
            _ => String::new(),
        };
        let size = format!("size={}", tmpfs.size_bytes);
        if observed.is_none()
            || (tmpfs.read_only && !options.contains("ro"))
            || (!tmpfs.read_only && !options.contains("rw"))
            || (tmpfs.no_exec && !options.contains("noexec"))
            || (tmpfs.no_suid && !options.contains("nosuid"))
            || (tmpfs.no_device && !options.contains("nodev"))
            || !options.contains(&size)
        {
            bail!("{backend_name} managed container tmpfs policy drifted");
        }
    }

    let networks = document
        .pointer("/NetworkSettings/Networks")
        .or_else(|| document.pointer("/NetworkSettings/Networks"))
        .and_then(serde_json::Value::as_object)
        .context("container inspect omitted network membership")?;
    if networks.len() != 1 || !networks.contains_key(expected_network) {
        bail!("{backend_name} managed container network policy drifted");
    }

    let mounts = document
        .get("Mounts")
        .and_then(serde_json::Value::as_array)
        .context("container inspect omitted managed mounts")?;
    let mut expected_destinations = expected_mounts
        .iter()
        .map(|(destination, _, _)| (*destination).to_owned())
        .collect::<std::collections::BTreeSet<String>>();
    expected_destinations.extend(
        policy
            .tmpfs
            .iter()
            .map(|tmpfs| tmpfs.destination.to_string_lossy().into_owned()),
    );
    for mount in mounts {
        let destination = mount
            .get("Destination")
            .and_then(serde_json::Value::as_str)
            .context("container inspect returned a mount without a destination")?;
        if !expected_destinations
            .iter()
            .any(|expected| expected.as_str() == destination)
            && !ENGINE_FIXED_MOUNT_DESTINATIONS.contains(&destination)
        {
            bail!("{backend_name} managed container contains an undeclared mount");
        }
    }
    for (destination, read_only, expected_source) in expected_mounts {
        let Some(mount) = mounts.iter().find(|mount| {
            mount.get("Destination").and_then(serde_json::Value::as_str) == Some(*destination)
        }) else {
            bail!("{backend_name} managed container mount policy drifted");
        };
        let observed_read_only = mount
            .get("RW")
            .and_then(serde_json::Value::as_bool)
            .map_or_else(
                || {
                    mount
                        .get("Mode")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|mode| mode.split(',').any(|value| value == "ro"))
                },
                |read_write| !read_write,
            );
        if observed_read_only != *read_only {
            bail!("{backend_name} managed container mount policy drifted");
        }
        if let Some(expected_source) = *expected_source {
            let observed_source = mount
                .get("Source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !mount_source_matches(observed_source, expected_source) {
                bail!("{backend_name} managed container mount source drifted");
            }
        }
    }

    let env = document
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .context("container inspect omitted environment")?;
    let expected_names = expected_environment
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    for name in env
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|value| value.split_once('=').map(|(name, _)| name))
    {
        if !expected_names.contains(name) && !ENGINE_FIXED_ENV_NAMES.contains(&name) {
            bail!("{backend_name} managed container contains an undeclared environment variable");
        }
    }
    for name in env
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|value| value.split_once('=').map(|(name, _)| name))
    {
        if (name.to_ascii_uppercase().contains("PASSWORD")
            || name.to_ascii_uppercase().contains("SECRET"))
            && !expected_names.contains(name)
        {
            bail!(
                "{backend_name} managed container contains an unauthorized secret environment variable"
            );
        }
    }
    for (name, expected) in expected_environment {
        let prefix = format!("{name}=");
        let observed = env
            .iter()
            .filter_map(serde_json::Value::as_str)
            .find_map(|value| value.strip_prefix(&prefix));
        if observed != Some(*expected) {
            bail!("{backend_name} managed container environment policy drifted");
        }
    }
    Ok(())
}

fn mount_source_matches(observed: &str, expected: &str) -> bool {
    observed == expected
        || (!expected.contains('/')
            && !expected.contains('\\')
            && (observed.ends_with(&format!("/{expected}/_data"))
                || observed.ends_with(&format!("\\{expected}\\_data"))))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use crate::runtime_backend::{ManagedDependencyBackup, managed_dependency_identity};
    use crate::{
        filesystem::PrivateTempDir, process::Process, runtime_backend::ManagedNetwork,
        test_support::write_shell_executable,
    };

    #[test]
    fn container_lookup_cannot_resolve_a_volume_with_the_container_name_as_prefix() {
        let work = PrivateTempDir::new("runtime-container-inspect-type").unwrap();
        let engine = work.path().join("fake-podman");
        let generic_marker = work.path().join("generic-inspect-was-used");
        let create_argv = work.path().join("create-argv");
        write_shell_executable(
            &engine,
            &format!(
                "if [ \"$*\" = 'container inspect managed-postgres --format {{json .}}' ]; then printf '%s\\n' 'no such object' >&2; exit 1; fi\nif [ \"$*\" = 'inspect managed-postgres' ]; then : > '{}'; exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\n",
                generic_marker.display(),
                create_argv.display(),
            ),
        );
        let network = ManagedNetwork {
            name: "managed-network".to_owned(),
            subnet: None,
            deployment_id: "deployment-test".to_owned(),
            control_authority: "controller-test".to_owned(),
        };
        super::ensure_container(
            engine.as_os_str(),
            "managed-postgres",
            &network,
            "runtime-test",
            "postgres",
            &format!("sha256:{}", "c".repeat(64)),
            "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Process::new(engine.as_os_str()).args(["run", "--name", "managed-postgres"]),
            "Podman",
            &super::ContainerRuntimePolicy::managed_default(),
            &[],
            &[],
        )
        .unwrap();
        assert!(!generic_marker.exists());
        assert_eq!(
            fs::read_to_string(create_argv).unwrap(),
            "run\n--name\nmanaged-postgres\n"
        );
    }

    #[test]
    fn image_identity_uses_valid_engine_templates() {
        let work = PrivateTempDir::new("runtime-image-inspect-template").unwrap();
        let engine = work.path().join("fake-podman");
        let expected = "docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        write_shell_executable(
            &engine,
            "if [ \"$*\" = 'container inspect managed-postgres --format {{json .}}' ]; then\n  printf '%s\\n' '{\"Config\":{\"Image\":\"docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'\n  exit 0\nfi\nexit 1",
        );
        super::assert_container_image(
            engine.as_os_str(),
            &["container", "inspect", "managed-postgres"],
            expected,
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn managed_valkey_backup_reads_auth_from_stdin_without_a_secret_environment_variable() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("managed-valkey-backup-auth").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let engine = work.path().join("fake-podman");
        let argv = work.path().join("argv");
        let lastsave_seen = work.path().join("lastsave-seen");
        let password_file = work.path().join("valkey-password");
        fs::create_dir(work.path().join("backup")).unwrap();
        chown(work.path().join("backup"), Some(0), Some(10001)).unwrap();
        fs::set_permissions(
            work.path().join("backup"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::write(&password_file, "secret-canary").unwrap();
        write_shell_executable(
            &engine,
            &format!(
                "printf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  *LASTSAVE*) if [ -e '{}' ]; then printf '101\\n'; else : > '{}'; printf '100\\n'; fi ;;\n  *) if [ \"$1\" = cp ]; then : > \"$3\"; fi; exit 0 ;;\nesac",
                argv.display(),
                lastsave_seen.display(),
                lastsave_seen.display(),
            ),
        );
        let postgres_image = format!("postgres@sha256:{}", "a".repeat(64));
        let valkey_image = format!("valkey@sha256:{}", "b".repeat(64));
        let backup = ManagedDependencyBackup {
            destination: work.path().join("backup"),
            network: "managed-network".to_owned(),
            postgres_object: "managed-postgres".to_owned(),
            postgres_volume: "managed-postgres-data".to_owned(),
            postgres_image: postgres_image.clone(),
            postgres_user: "nazoauth_runtime".to_owned(),
            postgres_database: "oauth".to_owned(),
            postgres_validation_image: postgres_image.clone(),
            valkey_object: "managed-valkey".to_owned(),
            valkey_volume: "managed-valkey-data".to_owned(),
            valkey_image: valkey_image.clone(),
            valkey_rdb_path: "/data/dump.rdb".to_owned(),
            valkey_password_file: Some(password_file),
            identity: managed_dependency_identity(
                "deployment-test",
                "controller-test",
                "runtime-test",
                "managed-network",
                "managed-postgres",
                "managed-postgres-data",
                &postgres_image,
                "oauth",
                "nazoauth_runtime",
                "managed-valkey",
                "managed-valkey-data",
                &valkey_image,
            ),
        };
        super::backup_managed_dependencies(engine.as_os_str(), &backup, true).unwrap();
        let arguments = fs::read_to_string(argv).unwrap();
        assert!(arguments.contains("valkey-cli --askpass"));
        assert!(!arguments.contains("VALKEYCLI_AUTH"));
        assert!(!arguments.contains("REDISCLI_AUTH"));
        assert!(!arguments.contains("secret-canary"));
    }

    #[test]
    fn managed_restore_journal_rejects_backend_drift() {
        let work = PrivateTempDir::new("managed-restore-journal-drift").unwrap();
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("SHA256SUMS"), b"placeholder\n").unwrap();
        let image = format!("postgres@sha256:{}", "a".repeat(64));
        let identity = managed_dependency_identity(
            "deployment-test",
            "controller-test",
            "runtime-test",
            "managed-network",
            "managed-postgres",
            "managed-postgres-data",
            &image,
            "oauth",
            "nazoauth_runtime",
            "managed-valkey",
            "managed-valkey-data",
            &format!("valkey@sha256:{}", "b".repeat(64)),
        );
        let (path, journal) =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap();
        super::persist_dependency_restore_journal(&path, &journal).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Podman", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
        let mut tampered = journal.clone();
        tampered.deployment_id = "other-deployment".to_owned();
        super::persist_dependency_restore_journal(&path, &tampered).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
    }

    #[test]
    fn managed_container_surface_rejects_extra_mounts_and_environment() {
        let policy = super::ContainerRuntimePolicy::managed_default();
        let tmpfs = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216",
            "/var/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216"
        });
        for (extra_mount, extra_env, expected_error) in [
            (true, false, "undeclared mount"),
            (false, true, "undeclared environment"),
        ] {
            let work = PrivateTempDir::new("managed-container-surface").unwrap();
            let engine = work.path().join("fake-engine");
            let mut mounts = vec![serde_json::json!({
                "Destination": "/data",
                "RW": true,
                "Source": "managed-data"
            })];
            if extra_mount {
                mounts.push(serde_json::json!({
                    "Destination": "/unexpected",
                    "RW": true,
                    "Source": "unexpected"
                }));
            }
            let mut environment = vec!["POSTGRES_DB=oauth", "PATH=/usr/local/bin"];
            if extra_env {
                environment.push("UNDECLARED=value");
            }
            let document = serde_json::json!({
                "HostConfig": {
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "ReadonlyRootfs": true,
                    "SecurityOpt": ["no-new-privileges"],
                    "CapDrop": ["ALL"],
                    "PidsLimit": 512,
                    "Memory": 1073741824_i64,
                    "NanoCpus": 2000000000_i64,
                    "Tmpfs": tmpfs.clone(),
                },
                "NetworkSettings": {"Networks": {"managed-network": {}}},
                "Mounts": mounts,
                "Config": {"Env": environment},
            });
            write_shell_executable(&engine, &format!("printf '%s\\n' '{}'", document));
            let error = super::assert_managed_container_policy(
                engine.as_os_str(),
                &["container", "inspect", "managed"],
                "Docker",
                &policy,
                "managed-network",
                &[("/data", false, Some("managed-data"))],
                &[("POSTGRES_DB", "oauth")],
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn oci_backup_completion_and_artifact_digests_are_bound() {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("oci-backup-completion-bound").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        chown(&backup, Some(0), Some(10001)).unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o750)).unwrap();
        let payload = backup.join("payload");
        fs::write(&payload, b"payload").unwrap();
        let digest = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let payload_digest = digest(b"payload");
        fs::write(
            backup.join("SHA256SUMS"),
            format!("{payload_digest}  payload\n"),
        )
        .unwrap();
        let manifest_bytes = fs::read(backup.join("SHA256SUMS")).unwrap();
        let manifest_digest = digest(&manifest_bytes);
        fs::write(
            backup.join("BACKUP-COMPLETE"),
            format!("marker=BACKUP-COMPLETE\nversion=1\nmanifest-sha256={manifest_digest}\n"),
        )
        .unwrap();
        for name in ["payload", "SHA256SUMS", "BACKUP-COMPLETE"] {
            let path = backup.join(name);
            chown(&path, Some(0), Some(10001)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        }
        let marker_digest = digest(&fs::read(backup.join("BACKUP-COMPLETE")).unwrap());
        super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest).unwrap();
        fs::write(&payload, b"tampered").unwrap();
        let error = super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest)
            .unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }
}

pub(crate) fn append_mounts(mut command: Process, mounts: &[NeutralMount]) -> Process {
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

pub(crate) fn one_shot_process(
    command: &OsStr,
    task: &OneShotTask,
    backend_name: &str,
) -> anyhow::Result<Process> {
    let super::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &task.artifact
    else {
        bail!("{backend_name} one-shot task requires a digest-bound OCI artifact");
    };
    let image = normalize_local_image_id(image_reference, false).unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let user = task
        .service_user
        .as_deref()
        .context("OCI one-shot task requires an explicit non-root UID:GID")?;
    validate_non_root_user(user, backend_name)?;
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    let mut process = append_container_policy(
        Process::new(command)
            .timeout(Duration::from_secs(300))
            .args(["run", "--rm", "--interactive"]),
        &policy,
    )
    .arg("--user")
    .arg(user)
    .arg("--network")
    .arg(task.network.as_deref().unwrap_or("none"));
    if let Some(directory) = &task.working_directory {
        process = process.arg("--workdir").arg(directory);
    }
    for (name, value) in &task.environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    Ok(append_mounts(process, &task.mounts)
        .arg(image)
        .args(&task.command))
}

pub(crate) fn append_build_identity_policy(mut command: Process) -> Process {
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    command = append_container_policy(command, &policy);
    command.arg("--user").arg(NON_ROOT_ONE_SHOT_USER)
}

fn validate_non_root_user(user: &str, backend_name: &str) -> anyhow::Result<()> {
    let Some((uid, gid)) = user.split_once(':') else {
        bail!("{backend_name} one-shot user must be an explicit UID:GID");
    };
    if uid.is_empty()
        || gid.is_empty()
        || !uid.chars().all(|value| value.is_ascii_digit())
        || !gid.chars().all(|value| value.is_ascii_digit())
        || uid.parse::<u32>().ok().is_none_or(|value| value == 0)
        || gid.parse::<u32>().ok().is_none_or(|value| value == 0)
    {
        bail!("{backend_name} one-shot user must be a non-root UID:GID");
    }
    Ok(())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

pub(crate) fn requested_digest_matches(image_reference: &str, digest: &str) -> bool {
    let Some((_, requested)) = image_reference.rsplit_once('@') else {
        return true;
    };
    requested.eq_ignore_ascii_case(digest)
}

/// Normalize an engine's local image identity.  Docker emits `sha256:...`;
/// Podman may emit the same digest without the algorithm prefix.
pub fn normalize_local_image_id(value: &str, allow_bare_digest: bool) -> Option<String> {
    if allow_bare_digest {
        let digest = value.strip_prefix("sha256:").unwrap_or(value);
        return (digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        .then(|| format!("sha256:{}", digest.to_ascii_lowercase()));
    }
    let normalized = value.to_ascii_lowercase();
    valid_digest(&normalized).then_some(normalized)
}

#[cfg(test)]
mod policy_tests {
    use super::{
        ContainerRestartPolicy, ContainerRuntimePolicy, NON_ROOT_ONE_SHOT_USER,
        requested_digest_matches, validate_non_root_user,
    };

    #[test]
    fn requested_digest_cannot_be_replaced_by_another_repo_digest() {
        let image = "registry.example/nazoauth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(requested_digest_matches(
            image,
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!requested_digest_matches(
            image,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(requested_digest_matches(
            "registry.example/nazoauth:stable",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[test]
    fn one_shot_user_contract_rejects_root_and_names() {
        assert!(validate_non_root_user(NON_ROOT_ONE_SHOT_USER, "Docker").is_ok());
        assert!(validate_non_root_user("0:0", "Docker").is_err());
        assert!(validate_non_root_user("nobody", "Docker").is_err());
        assert!(validate_non_root_user("65532", "Docker").is_err());
    }

    #[test]
    fn managed_policy_has_explicit_resource_and_restart_bounds() {
        let policy = ContainerRuntimePolicy::managed_default();
        assert_eq!(policy.restart, ContainerRestartPolicy::UnlessStopped);
        assert!(policy.read_only_root);
        assert!(policy.no_new_privileges);
        assert!(policy.drop_all_capabilities);
        assert_eq!(policy.pids_limit, Some(512));
        assert_eq!(policy.memory_limit_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(policy.cpu_limit_millis, Some(2_000));
        assert_eq!(policy.tmpfs.len(), 3);
        assert_eq!(
            policy.tmpfs[1].destination,
            std::path::Path::new("/run/postgresql")
        );
        assert_eq!(
            policy.tmpfs[2].destination,
            std::path::Path::new("/var/run/postgresql")
        );
    }
}
