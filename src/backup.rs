use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, File},
    io::Seek as _,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, bail};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tar::{Archive, Builder};

use crate::{
    filesystem::{
        atomic_write, open_secure_regular_file, read_secure_regular_file, read_secure_secret_file,
        set_mode, sha256_file,
    },
    model::UpdateConfig,
    process::{Process, command_exists},
    runtime::Runtime,
    runtime_backend::{
        MANAGED_VALKEY_BACKUP_USER, ManagedDependencyBackup, RuntimeBackendKind, backend,
        managed_dependency_identity,
    },
    secret_provider::{PostgresProvider, ValkeyProvider},
};

const BACKUP_COMPLETION_MARKER: &str = "BACKUP-COMPLETE";
const BACKUP_MARKER_VERSION: &str = "1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRestoreJournal {
    version: u32,
    manifest_digest: String,
    entries: Vec<SnapshotRestoreEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRestoreEntry {
    index: usize,
    target: String,
    staging: String,
    quarantine: Option<String>,
    phase: String,
}

pub(crate) struct Backup {
    path: PathBuf,
}

impl Backup {
    pub(crate) fn open_existing(config: &UpdateConfig, path: &Path) -> anyhow::Result<Self> {
        let root = fs::canonicalize(&config.backup_root)
            .context("failed to resolve configured backup root")?;
        let candidate = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect rollback backup {}", path.display()))?;
        if candidate.file_type().is_symlink() || !candidate.is_dir() {
            bail!("rollback backup must be a real directory");
        }
        let path = fs::canonicalize(path).context("failed to resolve rollback backup")?;
        if path.parent() != Some(root.as_path()) || !path.is_dir() {
            bail!("rollback backup is outside the configured backup root");
        }
        let backup = Self { path };
        backup.verify_completion_marker()?;
        backup.verify_checksums()?;
        backup.verify_identity(config)?;
        Ok(backup)
    }
    pub(crate) fn create(
        config_path: &Path,
        config: &UpdateConfig,
        version: &str,
    ) -> anyhow::Result<Self> {
        crate::filesystem::ensure_directory_chain(&config.backup_root)
            .with_context(|| format!("failed to create {}", config.backup_root.display()))?;
        let staging = allocate_backup_staging(&config.backup_root)?;
        let oci_managed = config.dependencies.mode == "managed"
            && matches!(
                config.container_backend(),
                Some(RuntimeBackendKind::Docker | RuntimeBackendKind::Podman)
            );
        if oci_managed {
            prepare_oci_backup_directory(&staging)?;
        }
        let staged = Self {
            path: staging.clone(),
        };
        let result = (|| -> anyhow::Result<()> {
            if config.dependencies.mode == "external" {
                staged.external_dependencies(config)?;
            } else {
                staged.managed_dependencies(config)?;
            }
            let config_bytes =
                read_secure_regular_file(config_path, "update configuration", false, 256 * 1024)?;
            atomic_write(
                &staged.path.join("update-config.json"),
                &config_bytes,
                0o600,
            )
            .context("failed to back up update configuration")?;
            staged.snapshots(config)?;
            staged.write_checksums()?;
            staged.write_completion_marker()?;
            if oci_managed {
                prepare_oci_backup_artifacts(&staged.path)?;
            }
            sync_directory(&staged.path)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        let final_path = allocate_backup_path(&config.backup_root, version)?;
        fs::rename(&staging, &final_path).with_context(|| {
            format!(
                "failed to atomically commit backup {}",
                final_path.display()
            )
        })?;
        sync_directory(&config.backup_root)?;
        Ok(Self { path: final_path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn restore_snapshots(&self, configured_paths: &[PathBuf]) -> anyhow::Result<()> {
        self.verify_completion_marker()?;
        self.verify_checksums()?;
        for target in configured_paths {
            crate::model::safe_absolute(target)?;
            let parent = target
                .parent()
                .context("snapshot target has no parent directory")?;
            require_real_directory(parent, "snapshot parent")?;
        }
        let journal_path = snapshot_journal_path(&self.path)?;
        let mut journal = load_snapshot_journal(&journal_path, &self.path)?;
        recover_snapshot_journal(&mut journal, configured_paths)?;
        persist_snapshot_journal(&journal_path, &journal)?;
        for (index, target) in configured_paths.iter().enumerate() {
            let target_name = target
                .file_name()
                .context("snapshot target has no file name")?;
            let parent = target
                .parent()
                .context("snapshot target has no parent directory")?;

            let path_file = self.path.join(format!("snapshot-{index}.path"));
            let persisted_bytes =
                read_secure_regular_file(&path_file, "snapshot path manifest", false, 4096)?;
            let persisted = std::str::from_utf8(&persisted_bytes)
                .context("snapshot path manifest is not UTF-8")?;
            let persisted = persisted
                .strip_suffix('\n')
                .context("snapshot path manifest must end with one newline")?;
            if persisted.contains(['\n', '\r']) || Path::new(persisted) != target {
                bail!(
                    "snapshot path manifest does not match the current configured target: {}",
                    target.display()
                );
            }

            let archive_path = self.path.join(format!("snapshot-{index}.tar"));
            let mut archive_file =
                open_secure_regular_file(&archive_path, "snapshot archive", false)?;
            validate_snapshot_archive(&mut archive_file, target_name)?;
            let entry = restore_snapshot_archive_journaled(
                &mut archive_file,
                target,
                parent,
                target_name,
                index,
                &mut journal,
                &journal_path,
            )?;
            journal.entries.retain(|existing| existing.index != index);
            journal.entries.push(entry);
            persist_snapshot_journal(&journal_path, &journal)?;
        }
        Ok(())
    }

    pub(crate) fn restore_databases(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        self.verify_completion_marker()?;
        self.verify_checksums()?;
        self.verify_identity(config)?;
        if config.dependencies.mode != "managed" {
            bail!(
                "automatic external database recovery is unavailable; use the provider's documented PostgreSQL and Valkey recovery procedures"
            );
        }
        let postgres =
            PostgresProvider::from_url_file(&config.dependencies.migration_database_url_file)?;
        Runtime::new(config).restore_managed_dependencies(
            &self.path,
            &postgres.service_file(),
            &postgres.password_file(),
        )
    }

    fn external_dependencies(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        for command in ["pg_dump", "pg_restore", "valkey-cli"] {
            if !command_exists(command) {
                bail!("required command is missing: {command}");
            }
        }
        validate_secret(&config.dependencies.database_url_file)?;
        validate_secret(&config.dependencies.valkey_url_file)?;
        let postgres = self.path.join("postgresql.dump");
        let postgres_provider =
            PostgresProvider::from_url_file(&config.dependencies.database_url_file)?;
        Process::new("pg_dump")
            .env("PGSERVICEFILE", postgres_provider.service_file())
            .env("PGPASSFILE", postgres_provider.password_file())
            .args([
                "--dbname=service=nazoauth",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
            ])
            .stdout_file(&postgres)?;
        Process::new("pg_restore")
            .arg("--list")
            .arg(&postgres)
            .run_quiet()?;
        let valkey = self.path.join("valkey-dump.rdb");
        let valkey_provider = ValkeyProvider::from_url_file(&config.dependencies.valkey_url_file)?;
        let mut command = Process::new("valkey-cli")
            .args(["--no-auth-warning", "--askpass", "-h"])
            .arg(&valkey_provider.host)
            .arg("-p")
            .arg(valkey_provider.port.to_string())
            .arg("-n")
            .arg(valkey_provider.database.to_string());
        if let Some(username) = &valkey_provider.username {
            command = command.arg("--user").arg(username);
        }
        if valkey_provider.tls {
            command = command.arg("--tls");
        }
        command = command.arg("--rdb").arg(&valkey);
        command.stdin_stdout(&valkey_provider.password_stdin())?;
        if fs::metadata(&valkey).map_or(true, |metadata| metadata.len() == 0) {
            bail!("external Valkey RDB export is empty");
        }
        set_mode(&valkey, 0o600)?;
        Ok(())
    }

    fn managed_dependencies(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        let kind = config
            .container_backend()
            .context("managed dependencies require a container backend")?;
        let postgres_volume = format!("{}-data", config.postgres.container_name);
        let identity = managed_dependency_identity(
            &config.operator.deployment_id,
            &config.operator.controller_key_id,
            &config.runtime.runtime_instance_id,
            &config.runtime.network,
            config.runtime.network_subnet.as_deref(),
            &config.postgres.container_name,
            &postgres_volume,
            &config.postgres.image,
            &config.postgres.database,
            &config.postgres.user,
            &config.valkey.container_name,
            &config.valkey.data_volume,
            &config.valkey.image,
        );
        let dependency_secrets = config
            .dependencies
            .valkey_url_file
            .parent()
            .context("managed Valkey URL file has no secret directory")?
            .join("dependencies");
        backend(kind).backup_managed_dependencies(&ManagedDependencyBackup {
            destination: self.path.clone(),
            network: config.runtime.network.clone(),
            postgres_object: config.postgres.container_name.clone(),
            postgres_volume,
            postgres_image: config.postgres.image.clone(),
            postgres_user: config.postgres.user.clone(),
            postgres_database: config.postgres.database.clone(),
            postgres_validation_image: config.postgres.validation_image.clone(),
            valkey_object: config.valkey.container_name.clone(),
            valkey_volume: config.valkey.data_volume.clone(),
            valkey_image: config.valkey.image.clone(),
            valkey_rdb_path: config.valkey.rdb_path.clone(),
            valkey_password_file: Some(dependency_secrets.join("valkey-backup-password")),
            valkey_user: Some(MANAGED_VALKEY_BACKUP_USER.to_owned()),
            identity,
        })?;
        for name in ["postgresql.dump", "valkey-dump.rdb"] {
            set_mode(&self.path.join(name), 0o600)?;
        }
        Ok(())
    }

    /// A backup carries a complete update configuration.  Before any
    /// snapshot/database restore, require that its deployment, controller,
    /// runtime instance and managed dependency configuration all match the
    /// currently selected deployment.  Legacy or hand-edited backups fail
    /// closed because they cannot provide this identity evidence.
    fn verify_identity(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        let archived_config_path = self.path.join("update-config.json");
        let archived_bytes = read_secure_regular_file(
            &archived_config_path,
            "archived update configuration",
            false,
            256 * 1024,
        )?;
        let archived = UpdateConfig::parse(&archived_bytes)
            .context("archived update configuration is invalid")?;
        if archived.dependencies.mode != config.dependencies.mode {
            bail!("backup dependency mode does not match the selected deployment");
        }
        if archived.container_backend() != config.container_backend()
            || archived.postgres.validation_image != config.postgres.validation_image
            || archived.valkey.rdb_path != config.valkey.rdb_path
        {
            bail!(
                "backup immutable dependency configuration does not match the selected deployment"
            );
        }
        let current_identity = dependency_identity_for_config(config);
        let archived_identity = dependency_identity_for_config(&archived);
        if archived_identity != current_identity {
            bail!("backup managed dependency identity does not match the selected deployment");
        }
        Ok(())
    }

    fn snapshots(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        for (index, path) in config.runtime.snapshot_paths.iter().enumerate() {
            if !path.is_dir() || path.is_symlink() {
                bail!("snapshot path is not a real directory: {}", path.display());
            }
            let name = path.file_name().context("snapshot path has no file name")?;
            let archive_path = self.path.join(format!("snapshot-{index}.tar"));
            let file = File::create(&archive_path).context("failed to create snapshot archive")?;
            set_mode(&archive_path, 0o600)?;
            let mut archive = Builder::new(file);
            validate_snapshot_tree(path)?;
            // The tar crate defaults to dereferencing symlinks.  Keep this
            // explicit even though the preflight rejects symlinks, so a race
            // between validation and traversal cannot escape the source tree.
            archive.follow_symlinks(false);
            archive
                .append_dir_all(name, path)
                .with_context(|| format!("failed to snapshot {}", path.display()))?;
            archive
                .finish()
                .context("failed to finish snapshot archive")?;
            let path_manifest = self.path.join(format!("snapshot-{index}.path"));
            atomic_write(
                &path_manifest,
                format!("{}\n", path.display()).as_bytes(),
                0o600,
            )
            .context("failed to write snapshot path")?;
        }
        Ok(())
    }

    fn write_checksums(&self) -> anyhow::Result<()> {
        let mut entries = fs::read_dir(&self.path)
            .context("failed to enumerate backup")?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut content = String::new();
        for entry in entries {
            if entry.file_name() != "SHA256SUMS" && entry.file_type()?.is_file() {
                let digest = secure_file_digest(&entry.path(), "backup checksum source")?;
                writeln!(
                    content,
                    "{}  {}",
                    digest,
                    entry.file_name().to_string_lossy()
                )?;
            }
        }
        atomic_write(&self.path.join("SHA256SUMS"), content.as_bytes(), 0o600)
    }

    fn write_completion_marker(&self) -> anyhow::Result<()> {
        let manifest = self.path.join("SHA256SUMS");
        let digest = secure_file_digest(&manifest, "backup checksum manifest")?;
        let marker = format!(
            "marker={BACKUP_COMPLETION_MARKER}\nversion={BACKUP_MARKER_VERSION}\nmanifest-sha256={digest}\n"
        );
        atomic_write(
            &self.path.join(BACKUP_COMPLETION_MARKER),
            marker.as_bytes(),
            0o600,
        )
    }

    fn verify_completion_marker(&self) -> anyhow::Result<()> {
        let path = self.path.join(BACKUP_COMPLETION_MARKER);
        let bytes = read_secure_regular_file(&path, "backup completion marker", false, 4096)?;
        let value = std::str::from_utf8(&bytes).context("backup completion marker is not UTF-8")?;
        let mut marker = None;
        let mut version = None;
        let mut manifest = None;
        for line in value.lines() {
            let (name, field) = line
                .split_once('=')
                .context("backup completion marker entry is invalid")?;
            match name {
                "marker" => marker = Some(field),
                "version" => version = Some(field),
                "manifest-sha256" => manifest = Some(field),
                _ => bail!("backup completion marker contains an unknown field"),
            }
        }
        if marker != Some(BACKUP_COMPLETION_MARKER)
            || version != Some(BACKUP_MARKER_VERSION)
            || !manifest.is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            bail!("backup completion marker is invalid or incomplete");
        }
        let expected = manifest.expect("validated manifest digest");
        let actual = secure_file_digest(&self.path.join("SHA256SUMS"), "backup checksum manifest")?;
        if actual != expected {
            bail!("backup completion marker does not match its checksum manifest");
        }
        Ok(())
    }

    fn verify_checksums(&self) -> anyhow::Result<()> {
        let manifest_path = self.path.join("SHA256SUMS");
        let manifest_bytes = read_secure_regular_file(
            &manifest_path,
            "backup checksum manifest",
            false,
            1024 * 1024,
        )?;
        let content = std::str::from_utf8(&manifest_bytes)
            .context("backup checksum manifest is not UTF-8")?;
        if content.is_empty() {
            bail!("backup checksum manifest is empty");
        }
        for line in content.lines() {
            let (expected, name) = line
                .split_once("  ")
                .context("backup checksum entry is invalid")?;
            if name.is_empty()
                || name.starts_with('.')
                || name.contains(['/', '\\'])
                || expected.len() != 64
                || !expected
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                bail!("backup checksum entry is unsafe");
            }
            if secure_file_digest(&self.path.join(name), "backup checksum target")? != expected {
                bail!("backup checksum mismatch: {name}");
            }
        }
        Ok(())
    }
}

fn require_real_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("failed to inspect {label} {}", current.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("{label} is not a real directory: {}", current.display());
        }
    }
    Ok(())
}

fn validate_snapshot_tree(root: &Path) -> anyhow::Result<()> {
    require_real_directory(root, "snapshot path")?;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to enumerate snapshot {}", directory.display()))?
        {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to inspect snapshot entry {}", path.display()))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                bail!("snapshot contains a symlink: {}", path.display());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() {
                bail!("snapshot contains a special file: {}", path.display());
            }
        }
    }
    Ok(())
}

fn validate_snapshot_archive(
    archive_file: &mut File,
    root_name: &std::ffi::OsStr,
) -> anyhow::Result<()> {
    let mut archive = Archive::new(&mut *archive_file);
    let root_path = Path::new(root_name);
    let mut seen = BTreeSet::new();
    let mut root_directory = false;
    for entry in archive
        .entries()
        .context("failed to enumerate snapshot archive")?
    {
        let entry = entry.context("failed to read snapshot archive entry")?;
        let path = entry
            .path()
            .context("snapshot archive entry has an invalid path")?
            .into_owned();
        if path.is_absolute()
            || path.as_os_str().is_empty()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("snapshot archive entry path is unsafe: {}", path.display());
        }
        let mut components = path.components();
        if components.next() != Some(Component::Normal(root_name)) {
            bail!(
                "snapshot archive entry escapes the configured target: {}",
                path.display()
            );
        }
        let entry_type = entry.header().entry_type();
        if !entry_type.is_dir() && !entry_type.is_file() {
            bail!(
                "snapshot archive contains an unsupported entry type: {}",
                path.display()
            );
        }
        let mode = entry
            .header()
            .mode()
            .context("snapshot archive entry has an invalid mode")?;
        if mode & 0o7000 != 0 {
            bail!(
                "snapshot archive entry has forbidden special permission bits: {}",
                path.display()
            );
        }
        if !seen.insert(path.clone()) {
            bail!(
                "snapshot archive contains a duplicate entry: {}",
                path.display()
            );
        }
        if path == root_path {
            if !entry_type.is_dir() {
                bail!("snapshot archive root is not a directory");
            }
            root_directory = true;
        }
    }
    if !root_directory {
        bail!("snapshot archive does not contain the configured target directory");
    }
    Ok(())
}

fn snapshot_journal_path(backup: &Path) -> anyhow::Result<PathBuf> {
    let parent = backup
        .parent()
        .context("backup has no parent for snapshot restore journal")?;
    let name = backup
        .file_name()
        .and_then(|value| value.to_str())
        .context("backup name is not valid UTF-8")?;
    Ok(parent.join(format!(".nazoauth-snapshot-restore-{name}.json")))
}

fn load_snapshot_journal(path: &Path, backup: &Path) -> anyhow::Result<SnapshotRestoreJournal> {
    let manifest_digest =
        secure_file_digest(&backup.join("SHA256SUMS"), "backup checksum manifest")?;
    let journal_exists = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("failed to inspect snapshot restore journal"),
    };
    if !journal_exists {
        return Ok(SnapshotRestoreJournal {
            version: 1,
            manifest_digest,
            entries: Vec::new(),
        });
    }
    let bytes = read_secure_regular_file(path, "snapshot restore journal", false, 1024 * 1024)?;
    let journal: SnapshotRestoreJournal =
        serde_json::from_slice(&bytes).context("snapshot restore journal is invalid")?;
    if journal.version != 1 || journal.manifest_digest != manifest_digest {
        bail!("snapshot restore journal is not bound to this backup");
    }
    Ok(journal)
}

fn persist_snapshot_journal(path: &Path, journal: &SnapshotRestoreJournal) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(journal).context("failed to encode snapshot restore journal")?;
    atomic_write(path, &bytes, 0o600)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn recover_snapshot_journal(
    journal: &mut SnapshotRestoreJournal,
    configured_paths: &[PathBuf],
) -> anyhow::Result<()> {
    for entry in &mut journal.entries {
        let target = PathBuf::from(&entry.target);
        let staging = PathBuf::from(&entry.staging);
        let quarantine = entry.quarantine.as_ref().map(PathBuf::from);
        let parent = target
            .parent()
            .context("snapshot journal target has no parent")?;
        if entry.index >= configured_paths.len()
            || Path::new(&entry.target) != configured_paths[entry.index].as_path()
            || !target.is_absolute()
            || staging.parent() != Some(parent)
            || !journal_temp_path(&staging, parent, ".nazoauth-restore-")
            || quarantine
                .as_ref()
                .is_some_and(|path| !journal_temp_path(path, parent, ".nazoauth-previous-"))
        {
            bail!("snapshot restore journal contains an unsafe path");
        }
        match entry.phase.as_str() {
            "staging" => {
                if staging.exists() {
                    fs::remove_dir_all(&staging)?;
                }
                entry.phase = "failed".to_owned();
            }
            "quarantined" => {
                if !target.exists()
                    && let Some(quarantine) = quarantine.as_ref()
                    && quarantine.exists()
                {
                    fs::rename(quarantine, &target)?;
                }
                if staging.exists() {
                    fs::remove_dir_all(&staging)?;
                }
                entry.phase = "failed".to_owned();
            }
            "activated" | "complete" | "failed" => {
                if staging.exists() {
                    fs::remove_dir_all(&staging)?;
                }
                if entry.phase == "activated" {
                    entry.phase = "complete".to_owned();
                }
            }
            _ => bail!("snapshot restore journal contains an unknown phase"),
        }
    }
    Ok(())
}

fn journal_temp_path(path: &Path, parent: &Path, prefix: &str) -> bool {
    path.parent() == Some(parent)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(prefix))
}

fn restore_snapshot_archive_journaled(
    archive_file: &mut File,
    target: &Path,
    parent: &Path,
    target_name: &std::ffi::OsStr,
    index: usize,
    journal: &mut SnapshotRestoreJournal,
    journal_path: &Path,
) -> anyhow::Result<SnapshotRestoreEntry> {
    let staging = allocate_restore_directory(parent)?;
    let mut entry = SnapshotRestoreEntry {
        index,
        target: target.display().to_string(),
        staging: staging.display().to_string(),
        quarantine: None,
        phase: "staging".to_owned(),
    };
    journal.entries.retain(|existing| existing.index != index);
    journal.entries.push(entry.clone());
    persist_snapshot_journal(journal_path, journal)?;

    let result = (|| -> anyhow::Result<()> {
        archive_file
            .rewind()
            .context("failed to rewind validated snapshot archive")?;
        let mut archive = Archive::new(&mut *archive_file);
        // The archive is a controller-created, root-owned artifact whose path,
        // checksum, entry types, and permission bits were validated above.
        // Runtime state relies on numeric ownership (notably UID/GID 10001 for
        // OCI application state and runtime-readable secrets), so discarding
        // this metadata makes a successfully restored runtime unbootable.
        #[cfg(unix)]
        {
            archive.set_preserve_ownerships(true);
            archive.set_preserve_permissions(true);
        }
        #[cfg(not(unix))]
        {
            archive.set_preserve_ownerships(false);
            archive.set_preserve_permissions(false);
        }
        archive.set_overwrite(false);
        archive
            .unpack(&staging)
            .with_context(|| format!("failed to restore {}", target.display()))?;
        let restored = staging.join(target_name);
        let restored_metadata = fs::symlink_metadata(&restored)
            .with_context(|| format!("snapshot archive did not create {}", restored.display()))?;
        if restored_metadata.file_type().is_symlink() || !restored_metadata.is_dir() {
            bail!(
                "restored snapshot root is not a real directory: {}",
                restored.display()
            );
        }
        let target_metadata = fs::symlink_metadata(target).ok();
        if let Some(metadata) = &target_metadata
            && (metadata.file_type().is_symlink() || !metadata.is_dir())
        {
            bail!(
                "snapshot target is not a real directory: {}",
                target.display()
            );
        }
        let quarantine = allocate_quarantine_path(parent)?;
        if target_metadata.is_some() {
            fs::rename(target, &quarantine).with_context(|| {
                format!("failed to quarantine snapshot target {}", target.display())
            })?;
            entry.quarantine = Some(quarantine.display().to_string());
            entry.phase = "quarantined".to_owned();
            journal.entries.retain(|existing| existing.index != index);
            journal.entries.push(entry.clone());
            persist_snapshot_journal(journal_path, journal)?;
        }
        if let Err(error) = fs::rename(&restored, target) {
            if let Some(quarantine) = entry.quarantine.as_ref() {
                let quarantine = Path::new(quarantine);
                if !target.exists() {
                    let _ = fs::rename(quarantine, target);
                }
            }
            return Err(error).with_context(|| {
                format!("failed to activate restored snapshot {}", target.display())
            });
        }
        entry.phase = "activated".to_owned();
        journal.entries.retain(|existing| existing.index != index);
        journal.entries.push(entry.clone());
        persist_snapshot_journal(journal_path, journal)?;
        fs::remove_dir_all(&staging)
            .with_context(|| format!("failed to remove restore staging {}", staging.display()))?;
        entry.phase = "complete".to_owned();
        journal.entries.retain(|existing| existing.index != index);
        journal.entries.push(entry.clone());
        persist_snapshot_journal(journal_path, journal)?;
        Ok(())
    })();
    if result.is_err() && entry.phase == "staging" {
        let _ = fs::remove_dir_all(&staging);
    }
    result.map(|_| entry)
}

fn allocate_restore_directory(parent: &Path) -> anyhow::Result<PathBuf> {
    for _ in 0..32 {
        let path = parent.join(format!(
            ".nazoauth-restore-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                set_mode(&path, 0o700)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create restore staging {}", path.display())
                });
            }
        }
    }
    bail!("failed to allocate restore staging directory")
}

fn allocate_quarantine_path(parent: &Path) -> anyhow::Result<PathBuf> {
    for _ in 0..32 {
        let path = parent.join(format!(
            ".nazoauth-previous-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(path),
            Err(error) => return Err(error).context("failed to inspect snapshot quarantine path"),
        }
    }
    bail!("failed to allocate snapshot quarantine path")
}

fn allocate_backup_staging(root: &Path) -> anyhow::Result<PathBuf> {
    for _ in 0..32 {
        let path = root.join(format!(
            ".nazoauth-backup-staging-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                set_mode(&path, 0o700)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("failed to create backup staging directory"),
        }
    }
    bail!("failed to allocate a unique backup staging directory")
}

fn allocate_backup_path(root: &Path, version: &str) -> anyhow::Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    for _ in 0..32 {
        let suffix = format!("{:08x}", rand::random::<u32>());
        let path = root.join(format!("{stamp}-before-{version}.{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(path),
            Err(error) => return Err(error).context("failed to inspect backup destination path"),
        }
    }
    bail!("failed to allocate a unique backup directory")
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> anyhow::Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open {} for synchronization", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to synchronize {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn prepare_oci_backup_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        chown(path, Some(0), Some(10001)).with_context(|| {
            format!(
                "failed to assign OCI backup directory ownership for {}",
                path.display()
            )
        })?;
        set_mode(path, 0o750)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("OCI backup ownership cannot be proven on this host");
    }
}

fn prepare_oci_backup_artifacts(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        for entry in fs::read_dir(path).context("failed to enumerate OCI backup artifacts")? {
            let entry = entry?;
            let artifact = entry.path();
            let metadata = fs::symlink_metadata(&artifact)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("OCI backup contains an unexpected non-file artifact");
            }
            chown(&artifact, Some(0), Some(10001)).with_context(|| {
                format!(
                    "failed to assign OCI backup artifact ownership for {}",
                    artifact.display()
                )
            })?;
            set_mode(&artifact, 0o440)?;
            File::open(&artifact)
                .with_context(|| {
                    format!(
                        "failed to reopen OCI backup artifact {}",
                        artifact.display()
                    )
                })?
                .sync_all()
                .with_context(|| {
                    format!(
                        "failed to synchronize OCI backup artifact {}",
                        artifact.display()
                    )
                })?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("OCI backup ownership cannot be proven on this host");
    }
}

fn dependency_identity_for_config(
    config: &UpdateConfig,
) -> crate::runtime_backend::ManagedDependencyIdentity {
    let postgres_volume = format!("{}-data", config.postgres.container_name);
    managed_dependency_identity(
        &config.operator.deployment_id,
        &config.operator.controller_key_id,
        &config.runtime.runtime_instance_id,
        &config.runtime.network,
        config.runtime.network_subnet.as_deref(),
        &config.postgres.container_name,
        &postgres_volume,
        &config.postgres.image,
        &config.postgres.database,
        &config.postgres.user,
        &config.valkey.container_name,
        &config.valkey.data_volume,
        &config.valkey.image,
    )
}

fn validate_secret(path: &Path) -> anyhow::Result<()> {
    let bytes = read_secure_secret_file(path, "backup dependency secret", 16 * 1024)?;
    let value = std::str::from_utf8(&bytes)
        .with_context(|| format!("failed to read secret {}", path.display()))?;
    if value.is_empty() || value.contains(['\n', '\r']) {
        bail!("secret file is empty or multiline: {}", path.display());
    }
    Ok(())
}

fn secure_file_digest(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut file = open_secure_regular_file(path, label, false)?;
    sha256_file(&mut file, &path.display().to_string())
}

#[cfg(all(test, unix))]
#[path = "../tests/unit/backup.rs"]
mod tests;
