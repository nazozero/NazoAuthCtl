use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
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

    pub(crate) fn restore_snapshots(&self) -> anyhow::Result<()> {
        let mut index = 0;
        loop {
            let path_file = self.path.join(format!("snapshot-{index}.path"));
            if !path_file.exists() {
                break;
            }
            let target = PathBuf::from(
                fs::read_to_string(&path_file)
                    .with_context(|| format!("failed to read {}", path_file.display()))?
                    .trim(),
            );
            let parent = target
                .parent()
                .context("snapshot target has no parent directory")?;
            let quarantine = parent.join(format!(
                ".{}.failed-{}",
                target
                    .file_name()
                    .context("snapshot target has no file name")?
                    .to_string_lossy(),
                std::process::id()
            ));
            if quarantine.exists() {
                bail!(
                    "snapshot recovery quarantine already exists: {}",
                    quarantine.display()
                );
            }
            if target.exists() {
                fs::rename(&target, &quarantine).with_context(|| {
                    format!("failed to quarantine snapshot target {}", target.display())
                })?;
            }
            let archive_path = self.path.join(format!("snapshot-{index}.tar"));
            let restore = (|| -> anyhow::Result<()> {
                let file = File::open(&archive_path)
                    .with_context(|| format!("failed to open {}", archive_path.display()))?;
                let mut archive = Archive::new(file);
                archive.set_preserve_ownerships(true);
                archive
                    .unpack(parent)
                    .with_context(|| format!("failed to restore {}", target.display()))
            })();
            if restore.is_err() && quarantine.exists() {
                if target.exists() {
                    fs::remove_dir_all(&target).ok();
                }
                fs::rename(&quarantine, &target).ok();
            }
            restore?;
            if quarantine.exists() {
                fs::remove_dir_all(&quarantine).with_context(|| {
                    format!(
                        "failed to remove recovery quarantine {}",
                        quarantine.display()
                    )
                })?;
            }
            index += 1;
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
