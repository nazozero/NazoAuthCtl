use crate::secure_file::{read_bounded, write_atomic};
use anyhow::{Context as _, bail};
use std::{
    fs::{self, File},
    path::Path,
    process::Command,
};

const MAX_PROXY_TRUST_BUNDLE_BYTES: usize = 1024 * 1024;

/// Restores a proxy bundle left by an older ordinary-run recovery journal.
/// TODO: Remove with `ConformanceProxyRecovery` when pre-tenant-mTLS journals
/// are no longer supported. New runs never install proxy trust bundles.
pub fn recover_proxy_trust(
    bundle_path: impl AsRef<Path>,
    reload_executable: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let bundle_path = bundle_path.as_ref();
    let reload_executable = reload_executable.as_ref();
    validate_reload_executable(reload_executable)?;
    let file_name = bundle_path
        .file_name()
        .context("proxy trust bundle path has no file name")?
        .to_string_lossy();
    let recovery_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-restore"));
    let lock_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-lock"));
    let _lock = open_provider_lock(&lock_path)?;
    match fs::symlink_metadata(&recovery_path) {
        Ok(_) => {
            let recovery = read_private(&recovery_path, "proxy trust recovery bundle")?;
            write_private(bundle_path, &recovery, "proxy trust recovery")?;
            reload(reload_executable, "recover stale proxy trust transaction")?;
            remove_recovery(&recovery_path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect proxy trust recovery bundle"),
    }
}

fn open_provider_lock(path: &Path) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let owned = rustix::fs::open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .context("failed to open proxy trust provider lock")?;
        let file = File::from(owned);
        file.try_lock()
            .context("another conformance run owns the proxy trust bundle")?;
        let metadata = file.metadata()?;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            bail!("proxy trust provider lock must be root-owned and owner-only");
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("proxy trust mutation is supported only on Unix hosts")
    }
}

fn read_private(path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
    read_bounded(path, MAX_PROXY_TRUST_BUNDLE_BYTES, true)
        .map_err(|error| anyhow::anyhow!("failed to read {label}: {error:?}"))
}

fn write_private(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_PROXY_TRUST_BUNDLE_BYTES {
        bail!("{label} is empty or oversized");
    }
    write_atomic(path, bytes, true)
        .map_err(|error| anyhow::anyhow!("failed to write {label}: {error:?}"))
}

fn remove_recovery(path: &Path) -> anyhow::Result<()> {
    fs::remove_file(path).context("failed to remove proxy trust recovery bundle")?;
    let parent = path
        .parent()
        .context("proxy trust recovery bundle has no parent")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to synchronize proxy trust recovery directory")
}

fn reload(executable: &Path, operation: &str) -> anyhow::Result<()> {
    validate_reload_executable(executable)?;
    let status = Command::new(executable)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .status()
        .with_context(|| format!("failed to {operation}"))?;
    if !status.success() {
        bail!("failed to {operation}: reload executable returned {status}");
    }
    Ok(())
}

fn validate_reload_executable(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        bail!("proxy reload executable must be an absolute path");
    }
    crate::secure_file::validate_directory(
        path.parent()
            .context("proxy reload executable has no parent")?,
        false,
    )
    .map_err(|error| anyhow::anyhow!("unsafe proxy reload executable parent: {error:?}"))?;
    let metadata =
        fs::symlink_metadata(path).context("failed to inspect proxy reload executable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("proxy reload executable must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            bail!("proxy reload executable must be root-owned and not group/world-writable");
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root-owned proxy recovery files and executable"]
    fn legacy_recovery_retains_material_until_reload_succeeds() {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(rustix::process::geteuid().is_root());
        let directory =
            std::env::temp_dir().join(format!("proxy-recovery-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let bundle = directory.join("ca.pem");
        let recovery = directory.join(".ca.pem.nazoauthctl-restore");
        let executable = directory.join("reload");
        write_private(&bundle, b"current bundle", "test bundle").unwrap();
        write_private(&recovery, b"original bundle", "test recovery").unwrap();
        fs::write(&executable, b"#!/bin/sh\nexit 7\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(recover_proxy_trust(&bundle, &executable).is_err());
        assert_eq!(fs::read(&bundle).unwrap(), b"original bundle");
        assert_eq!(fs::read(&recovery).unwrap(), b"original bundle");

        fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        recover_proxy_trust(&bundle, &executable).unwrap();
        assert!(!recovery.exists());
        assert_eq!(fs::read(&bundle).unwrap(), b"original bundle");
        recover_proxy_trust(&bundle, &executable).unwrap();
        assert_eq!(fs::read(&bundle).unwrap(), b"original bundle");
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn security_cloud_reload_rejects_replaceable_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!("reload-parent-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        let executable = path.join("reload");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            validate_reload_executable(&executable)
                .unwrap_err()
                .to_string()
                .contains("parent")
        );
        fs::remove_dir_all(path).unwrap();
    }
}
