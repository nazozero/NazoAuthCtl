use super::*;

/// The standalone OIDF runner does not enter `main_entry`, so it explicitly
/// participates in the same lifecycle lock as update and recovery. Shared mode
/// allows independent read-mostly runs to overlap while excluding mutations.
pub(super) fn acquire_oidf_run_shared_lock() -> anyhow::Result<File> {
    let path = std::env::var_os("NAZOAUTHCTL_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    acquire_oidf_run_shared_lock_at(&path)
}

pub(super) fn acquire_oidf_run_shared_lock_at(path: &Path) -> anyhow::Result<File> {
    let file = open_lock_file(path, false, "lifecycle lock")
        .with_context(|| format!("failed to open lifecycle lock {}", path.display()))?;
    match file.try_lock_shared() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another nazoauthctl lifecycle operation is already running")
        }
        Err(TryLockError::Error(error)) => {
            Err(error).context("failed to acquire shared lifecycle lock")
        }
    }
}

fn local_oci_candidate_install_state_path(config: &UpdateConfig) -> PathBuf {
    config
        .deployment_root
        .join("local-oci-candidate-install.json")
}

fn load_local_oci_candidate_install_state(
    config: &UpdateConfig,
) -> anyhow::Result<Option<LocalOciCandidateInstallState>> {
    let path = local_oci_candidate_install_state_path(config);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("local OCI candidate installation state is not a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("failed to inspect local OCI candidate installation state");
        }
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "local OCI candidate installation state",
        true,
        256 * 1024,
    )?;
    let state: LocalOciCandidateInstallState = serde_json::from_slice(&bytes)
        .context("local OCI candidate installation state is invalid")?;
    if state.schema != 1 || state.local_artifact_id.is_empty() {
        bail!("local OCI candidate installation state has an unsupported schema or identity");
    }
    Ok(Some(state))
}

pub(super) fn local_oci_candidate_install_is_pending(
    config: &UpdateConfig,
) -> anyhow::Result<bool> {
    Ok(load_local_oci_candidate_install_state(config)?.is_some_and(|state| !state.completed))
}

/// A completed candidate install must match the durable state it wrote:
/// release identity, build id, runtime binding, and artifact digest.
pub(super) fn validate_completed_local_oci_candidate_provenance(
    config: &UpdateConfig,
    record: &crate::deployment::DeploymentRecord,
) -> anyhow::Result<()> {
    let state = load_local_oci_candidate_install_state(config)?
        .context("local OCI candidate deployment has no completed installation state")?;
    if !state.completed {
        bail!("local OCI candidate installation is not marked completed");
    }
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate deployment has no runtime binding")?;
    let crate::deployment::ArtifactReference::Oci { digest, .. } = &runtime.artifact else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    if record.active_release.release != state.candidate.target.release
        || record.active_release.revision != state.candidate.target.revision
        || record.active_release.build_id != state.candidate.target.build_id
        || runtime.local_artifact_id.as_deref() != Some(&state.local_artifact_id)
        || digest != &state.candidate.target.oci_digest
    {
        bail!("local OCI candidate deployment does not match its completed durable state");
    }
    Ok(())
}

pub(super) fn local_oci_candidate_install_resource_path(config: &UpdateConfig) -> PathBuf {
    local_oci_candidate_install_state_path(config)
}

pub(super) const LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE: &str = "local_oci_candidate_install";
