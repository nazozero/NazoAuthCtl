use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, bail};

use chrono::Utc;
use tar::{Archive, Builder};

use crate::{
    filesystem::{set_mode, sha256},
    model::UpdateConfig,
    process::{Process, command_exists},
    runtime::Runtime,
    runtime_backend::{ManagedDependencyBackup, backend, managed_dependency_identity},
    secret_provider::{PostgresProvider, ValkeyProvider},
};

pub(crate) struct Backup {
    path: PathBuf,
}

impl Backup {
    pub(crate) fn open_existing(config: &UpdateConfig, path: &Path) -> anyhow::Result<Self> {
        let root = fs::canonicalize(&config.backup_root)
            .context("failed to resolve configured backup root")?;
        let path = fs::canonicalize(path).context("failed to resolve rollback backup")?;
        if path.parent() != Some(root.as_path()) || !path.is_dir() || path.is_symlink() {
            bail!("rollback backup is outside the configured backup root");
        }
        let backup = Self { path };
        backup.verify_checksums()?;
        backup.verify_identity(config)?;
        Ok(backup)
    }
    pub(crate) fn create(
        config_path: &Path,
        config: &UpdateConfig,
        version: &str,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(&config.backup_root)
            .with_context(|| format!("failed to create {}", config.backup_root.display()))?;
        let path = allocate_backup_dir(&config.backup_root, version)?;
        let backup = Self { path };
        if config.dependencies.mode == "external" {
            backup.external_dependencies(config)?;
        } else {
            backup.managed_dependencies(config)?;
        }
        fs::copy(config_path, backup.path.join("update-config.json"))
            .context("failed to back up update configuration")?;
        backup.snapshots(config)?;
        backup.write_checksums()?;
        Ok(backup)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn restore_snapshots(&self, configured_paths: &[PathBuf]) -> anyhow::Result<()> {
        for (index, target) in configured_paths.iter().enumerate() {
            crate::model::safe_absolute(target)?;
            let target_name = target
                .file_name()
                .context("snapshot target has no file name")?;
            let parent = target
                .parent()
                .context("snapshot target has no parent directory")?;
            require_real_directory(parent, "snapshot parent")?;

            let path_file = self.path.join(format!("snapshot-{index}.path"));
            require_regular_file(&path_file, "snapshot path manifest")?;
            let persisted = fs::read_to_string(&path_file)
                .with_context(|| format!("failed to read {}", path_file.display()))?;
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
            require_regular_file(&archive_path, "snapshot archive")?;
            validate_snapshot_archive(&archive_path, target_name)?;
            restore_snapshot_archive(&archive_path, target, parent, target_name)?;
        }
        Ok(())
    }

    pub(crate) fn restore_databases(&self, config: &UpdateConfig) -> anyhow::Result<()> {
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
            &config.postgres.container_name,
            &postgres_volume,
            &config.postgres.image,
            &config.postgres.database,
            &config.postgres.user,
            &config.valkey.container_name,
            &config.valkey.data_volume,
            &config.valkey.image,
        );
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
            valkey_password_file: (!config.valkey.password_file.as_os_str().is_empty())
                .then(|| config.valkey.password_file.clone()),
            identity,
        })
    }

    /// A backup carries a complete update configuration.  Before any
    /// snapshot/database restore, require that its deployment, controller,
    /// runtime instance and managed dependency configuration all match the
    /// currently selected deployment.  Legacy or hand-edited backups fail
    /// closed because they cannot provide this identity evidence.
    fn verify_identity(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        let archived_config_path = self.path.join("update-config.json");
        let archived =
            UpdateConfig::parse(&fs::read(&archived_config_path).with_context(|| {
                format!(
                    "failed to read archived update configuration {}",
                    archived_config_path.display()
                )
            })?)
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
            let file = File::create(self.path.join(format!("snapshot-{index}.tar")))
                .context("failed to create snapshot archive")?;
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
            fs::write(
                self.path.join(format!("snapshot-{index}.path")),
                format!("{}\n", path.display()),
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
        let mut file =
            File::create(self.path.join("SHA256SUMS")).context("failed to create checksums")?;
        for entry in entries {
            if entry.file_type()?.is_file() && entry.file_name() != "SHA256SUMS" {
                writeln!(
                    file,
                    "{}  {}",
                    sha256(&entry.path())?,
                    entry.file_name().to_string_lossy()
                )?;
            }
        }
        file.sync_all()
            .context("failed to persist backup checksums")
    }

    fn verify_checksums(&self) -> anyhow::Result<()> {
        let content = fs::read_to_string(self.path.join("SHA256SUMS"))?;
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
            {
                bail!("backup checksum entry is unsafe");
            }
            if sha256(&self.path.join(name))? != expected {
                bail!("backup checksum mismatch: {name}");
            }
        }
        Ok(())
    }
}

fn require_regular_file(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    Ok(())
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
    archive_path: &Path,
    root_name: &std::ffi::OsStr,
) -> anyhow::Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let mut archive = Archive::new(file);
    let root_path = Path::new(root_name);
    let mut seen = BTreeSet::new();
    let mut root_directory = false;
    for entry in archive
        .entries()
        .with_context(|| format!("failed to enumerate {}", archive_path.display()))?
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

fn restore_snapshot_archive(
    archive_path: &Path,
    target: &Path,
    parent: &Path,
    target_name: &std::ffi::OsStr,
) -> anyhow::Result<()> {
    let staging = allocate_restore_directory(parent)?;
    let result = (|| -> anyhow::Result<()> {
        let file = File::open(archive_path)
            .with_context(|| format!("failed to open {}", archive_path.display()))?;
        let mut archive = Archive::new(file);
        // Snapshot archives are untrusted input.  In particular, never apply
        // archived numeric uid/gid or special permission bits to the restore.
        archive.set_preserve_ownerships(false);
        archive.set_preserve_permissions(false);
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
        let mut quarantined = false;
        if target_metadata.is_some() {
            fs::rename(target, &quarantine).with_context(|| {
                format!("failed to quarantine snapshot target {}", target.display())
            })?;
            quarantined = true;
        }
        if let Err(error) = fs::rename(&restored, target) {
            if quarantined {
                let _ = fs::rename(&quarantine, target);
            }
            return Err(error).with_context(|| {
                format!("failed to activate restored snapshot {}", target.display())
            });
        }
        if quarantined {
            fs::remove_dir_all(&quarantine).with_context(|| {
                format!(
                    "failed to remove recovery quarantine {}",
                    quarantine.display()
                )
            })?;
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&staging);
    if result.is_ok() {
        cleanup
            .with_context(|| format!("failed to remove restore staging {}", staging.display()))?;
    }
    result
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
        if !path.exists() {
            return Ok(path);
        }
    }
    bail!("failed to allocate snapshot quarantine path")
}

fn allocate_backup_dir(root: &Path, version: &str) -> anyhow::Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    for _ in 0..32 {
        let suffix = format!("{:08x}", rand::random::<u32>());
        let path = root.join(format!("{stamp}-before-{version}.{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                set_mode(&path, 0o700)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("failed to create backup directory"),
        }
    }
    bail!("failed to allocate a unique backup directory")
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
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read secret {}", path.display()))?;
    if value.is_empty() || value.contains(['\n', '\r']) {
        bail!("secret file is empty or multiline: {}", path.display());
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "../tests/unit/backup.rs"]
mod tests;
