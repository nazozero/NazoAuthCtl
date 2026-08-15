//! Managed dependency backup, restore, journal, and credential primitives.
//!
//! This module owns the durable provider-state boundary shared by Docker and
//! Podman. Engine-specific command dialects remain in their backend modules.

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
use crate::filesystem::{
    atomic_write, open_secure_regular_file, read_secure_secret_file, sha256_file,
};
use crate::process::Process;
#[cfg(unix)]
use std::fs::File;

use super::super::{ManagedDependencyBackup, ManagedDependencyIdentity};

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
    identity: &ManagedDependencyIdentity,
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
        atomic_write(&password_path, &password, 0o400)?;
        prepare_non_root_readable(&service_path)?;
        prepare_non_root_password_file(&password_path)?;
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

#[cfg(unix)]
fn prepare_non_root_password_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::chown;
    // libpq deliberately ignores a password file with any group or world
    // permissions.  The one-shot container runs as 10001:10001, so make that
    // identity the sole reader instead of relying on the group-readable
    // contract used by the non-secret service file.
    chown(path, Some(10001), Some(10001)).with_context(|| {
        format!(
            "failed to assign PostgreSQL restore password ownership for {}",
            path.display()
        )
    })?;
    set_mode(path, 0o400)?;
    File::open(path)
        .with_context(|| {
            format!(
                "failed to reopen PostgreSQL restore password file {}",
                path.display()
            )
        })?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to synchronize PostgreSQL restore password file {}",
                path.display()
            )
        })
}

#[cfg(not(unix))]
fn prepare_non_root_readable(path: &Path) -> anyhow::Result<()> {
    let _ = path;
    bail!("OCI restore credentials require a host group readable by UID:GID 10001:10001")
}

#[cfg(not(unix))]
fn prepare_non_root_password_file(path: &Path) -> anyhow::Result<()> {
    let _ = path;
    bail!("OCI restore password requires ownership by UID:GID 10001:10001")
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
        super::build_identity_process(command)
            .arg("-v")
            .arg(format!("{}:/backup:ro,Z", backup.destination.display()))
    } else {
        super::build_identity_process(command)
            .arg("--mount")
            .arg(format!(
                "type=bind,src={},dst=/backup,readonly",
                backup.destination.display()
            ))
    };
    validation
        .arg(&backup.postgres_validation_image)
        .args(["pg_restore", "--list", "/backup/postgresql.dump"])
        .run_quiet()?;

    let valkey_password = backup
        .valkey_password_file
        .as_ref()
        .map(|path| read_secure_secret_file(path, "managed Valkey backup password", 4 * 1024))
        .transpose()?;
    if valkey_password.as_deref().is_some_and(|password| {
        password.is_empty()
            || password.contains(&b'\n')
            || password.contains(&b'\r')
            || password.contains(&b'\0')
    }) {
        bail!("managed Valkey backup password is empty or malformed");
    }
    if backup.valkey_password_file.is_some() != backup.valkey_user.is_some() {
        bail!("managed Valkey backup authentication is incomplete");
    }
    if backup.valkey_user.as_deref().is_some_and(|user| {
        user.is_empty()
            || user.len() > 128
            || !user
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    }) {
        bail!("managed Valkey backup user is invalid");
    }
    let output = |arguments: &[&str]| -> anyhow::Result<String> {
        if let (Some(password), Some(user)) = (&valkey_password, &backup.valkey_user) {
            return Process::new(command)
                .args([
                    "exec",
                    "--interactive",
                    backup.valkey_object.as_str(),
                    "valkey-cli",
                    "--user",
                    user,
                    "--askpass",
                ])
                .args(arguments)
                .stdin_stdout(password);
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
