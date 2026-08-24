use super::*;

pub(crate) fn active_release_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("active-release.json")
}

/// Archival evidence root for a verified Release (F4). Evidence is kept
/// separate from the content-addressed blob sections below it; no trust
/// decision consumes these files.
pub(crate) fn release_cache_dir(config: &UpdateConfig, manifest: &ReleaseManifest) -> PathBuf {
    trusted_release_cache_root(config)
        .join("evidence")
        .join(&manifest.version)
}

pub(crate) fn trusted_release_cache_root(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("trusted-release-cache")
}

fn subject_digest_hex(digest: &str) -> anyhow::Result<String> {
    digest
        .strip_prefix("sha256:")
        .map(str::to_owned)
        .context("signed Release OCI digest is not sha256-prefixed")
}

/// Commit the verified runtime artifact into the content-addressed
/// trusted-release cache (H02). Host binaries are addressed by their signed
/// artifact digest; exported OCI archives carry their own transport digest in
/// the handle record.
pub(crate) fn cache_trusted_runtime(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    runtime_target: &str,
) -> anyhow::Result<()> {
    let root = trusted_release_cache_root(config);
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        let binary = manifest
            .artifacts
            .get("binary")
            .context("Release manifest has no server binary")?;
        crate::release::commit_artifact_handle(
            &root,
            &crate::release::CachedArtifactDescriptor {
                origin: crate::release::ArtifactOrigin::Official,
                kind: crate::release::CachedArtifactKind::HostBinary {
                    artifact_name: binary.name.clone(),
                },
                version: &manifest.version,
                target: &manifest.target,
                subject_sha256: &binary.sha256,
            },
            Path::new(runtime_target),
        )?;
        Ok(())
    } else {
        let subject = subject_digest_hex(manifest.runtime_oci_digest()?)?;
        let work = crate::filesystem::PrivateTempDir::new("nazoauth-release-cache")?;
        let archive = work.path().join("server-image.tar");
        Runtime::new(config).export_image(runtime_target, &archive)?;
        crate::release::commit_artifact_handle(
            &root,
            &crate::release::CachedArtifactDescriptor {
                origin: crate::release::ArtifactOrigin::Official,
                kind: crate::release::CachedArtifactKind::OciArchive {
                    image_reference: runtime_target.to_owned(),
                },
                version: &manifest.version,
                target: &manifest.target,
                subject_sha256: &subject,
            },
            &archive,
        )?;
        Ok(())
    }
}

/// Guarantee that the previously trusted runtime for `manifest` is available
/// at `runtime_target`, restoring it from its committed cache entry when the
/// live object is gone. Restoration opens an official handle only; local
/// development material can never satisfy this gate (no blending).
pub(crate) fn ensure_trusted_runtime_available(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    runtime_target: &str,
) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
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
        let handle = crate::release::open_artifact_handle(
            &trusted_release_cache_root(config),
            crate::release::ArtifactOrigin::Official,
            expected,
        )?;
        handle.require_official()?;
        crate::filesystem::ensure_directory_chain(
            Path::new(runtime_target)
                .parent()
                .context("host recovery target has no parent")?,
        )?;
        crate::filesystem::copy_atomic_verified(
            handle.blob(),
            Path::new(runtime_target),
            0o500,
            expected,
        )
    } else {
        if runtime.image_digest(runtime_target).is_ok() {
            return Ok(());
        }
        let subject = subject_digest_hex(manifest.runtime_oci_digest()?)?;
        let handle = crate::release::open_artifact_handle(
            &trusted_release_cache_root(config),
            crate::release::ArtifactOrigin::Official,
            &subject,
        )?;
        handle.require_official()?;
        runtime.import_image(handle.blob(), runtime_target)?;
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
