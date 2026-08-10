use super::*;

pub(crate) fn active_release_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("active-release.json")
}

pub(crate) fn release_cache_dir(config: &UpdateConfig, manifest: &ReleaseManifest) -> PathBuf {
    config
        .deployment_root
        .join("trusted-release-cache")
        .join(&manifest.version)
        .join(&manifest.target)
}

pub(crate) fn cache_trusted_runtime(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    runtime_target: &str,
) -> anyhow::Result<()> {
    let directory = release_cache_dir(config, manifest);
    crate::filesystem::ensure_directory_chain(&directory)?;
    atomic_write(
        &directory.join("server-release-manifest.json"),
        &serde_json::to_vec_pretty(manifest)?,
        0o400,
    )?;
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        let expected = &manifest
            .artifacts
            .get("binary")
            .context("Release manifest has no server binary")?
            .sha256;
        crate::filesystem::copy_atomic_verified(
            Path::new(runtime_target),
            &directory.join("nazoauth"),
            0o500,
            expected,
        )
    } else {
        Runtime::new(config).export_image(runtime_target, &directory.join("server-image.tar"))
    }
}

pub(crate) fn ensure_trusted_runtime_available(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    runtime_target: &str,
) -> anyhow::Result<()> {
    let directory = release_cache_dir(config, manifest);
    let cached_path = directory.join("server-release-manifest.json");
    let cached_bytes = crate::filesystem::read_secure_regular_file(
        &cached_path,
        "trusted recovery manifest",
        true,
        1024 * 1024,
    )
    .context("trusted recovery manifest is unavailable")?;
    let cached: ReleaseManifest =
        serde_json::from_slice(&cached_bytes).context("trusted recovery manifest is invalid")?;
    if &cached != manifest {
        bail!("trusted recovery manifest differs from the persisted rollback state");
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        let expected = &manifest
            .artifacts
            .get("binary")
            .context("Release manifest has no server binary")?
            .sha256;
        if Path::new(runtime_target).is_file()
            && crate::filesystem::sha256(Path::new(runtime_target))
                .is_ok_and(|value| &value == expected)
        {
            return Ok(());
        }
        let cached_binary = directory.join("nazoauth");
        crate::filesystem::ensure_directory_chain(
            Path::new(runtime_target)
                .parent()
                .context("host recovery target has no parent")?,
        )?;
        crate::filesystem::copy_atomic_verified(
            &cached_binary,
            Path::new(runtime_target),
            0o500,
            expected,
        )
    } else {
        let runtime = Runtime::new(config);
        if runtime.image_digest(runtime_target).is_ok() {
            return Ok(());
        }
        runtime.import_image(&directory.join("server-image.tar"), runtime_target)?;
        if runtime.image_digest(runtime_target)? != manifest.runtime_oci_digest()? {
            bail!("imported recovery image differs from the signed Release");
        }
        Ok(())
    }
}

pub(crate) fn write_active_release(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    atomic_write(
        &active_release_path(config),
        &serde_json::to_vec_pretty(manifest)?,
        0o600,
    )
}

pub(crate) fn load_active_release(config: &UpdateConfig) -> anyhow::Result<ReleaseManifest> {
    let path = active_release_path(config);
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "active Release manifest",
        true,
        1024 * 1024,
    )?;
    let manifest: ReleaseManifest = serde_json::from_slice(&bytes)?;
    let identity = format!(
        "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{}",
        config.repository, manifest.version
    );
    manifest.validate(&manifest.version, &identity)?;
    manifest.validate_controller_compatibility()?;
    Ok(manifest)
}

pub(crate) fn load_config_unsettled(path: &Path) -> anyhow::Result<UpdateConfig> {
    if !path.is_file() || path.is_symlink() {
        bail!(
            "update config must be a regular non-symlink file: {}",
            path.display()
        );
    }
    validate_config_permissions(path)?;
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "update configuration",
        false,
        4 * 1024 * 1024,
    )
    .with_context(|| format!("failed to read {}", path.display()))?;
    UpdateConfig::parse(&bytes)
}

pub(crate) fn ensure_no_pending_update(config: &UpdateConfig) -> anyhow::Result<()> {
    if let Some(journal) = load_update_journal(config)? {
        bail!(
            "update transaction {} is pending at phase {:?}; run nazoauthctl recover-update --yes",
            journal.transaction_id,
            journal.phase
        )
    }
    Ok(())
}

pub(crate) fn load_config(path: &Path) -> anyhow::Result<UpdateConfig> {
    let config = load_config_unsettled(path)?;
    if crate::operator::identity_recovery_required(&config)? {
        bail!("identity recovery is pending; run nazoauthctl recover-identity --yes")
    }
    ensure_no_pending_update(&config)?;
    Ok(config)
}

#[cfg(unix)]
pub(crate) fn validate_config_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if cfg!(test) || test_mode() {
        return Ok(());
    }
    let metadata = fs::metadata(path)?;
    if !config_permissions_are_safe(metadata.uid(), metadata.mode()) {
        bail!("update config must be root-owned and not group/world writable");
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn config_permissions_are_safe(owner_uid: u32, mode: u32) -> bool {
    owner_uid == 0 && mode & 0o022 == 0
}

#[cfg(not(unix))]
pub(crate) fn validate_config_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
