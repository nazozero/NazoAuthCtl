use super::*;

pub(crate) fn active_release_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("active-release.json")
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

pub(crate) fn load_config(path: &Path) -> anyhow::Result<UpdateConfig> {
    load_config_unsettled(path)
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
