use std::{
    fs::{self, File},
    path::Path,
    process::Command,
};

use anyhow::{Context as _, bail};

use crate::secure_file::{read_bounded, write_atomic};

const MAX_PROXY_TRUST_BUNDLE_BYTES: usize = 1024 * 1024;

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
