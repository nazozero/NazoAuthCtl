use super::*;

pub(super) fn list_deployments() -> anyhow::Result<()> {
    let store = crate::deployment::DeploymentStore::system();
    let registry = store.load_registry()?;
    let deployments = registry
        .deployments
        .keys()
        .map(|deployment_id| store.load(deployment_id))
        .collect::<anyhow::Result<Vec<_>>>()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": 1,
            "deployments": deployments,
        }))?
    );
    Ok(())
}

pub(super) fn registered_status(
    record: &crate::deployment::DeploymentRecord,
    doctor: bool,
) -> anyhow::Result<()> {
    use crate::deployment::{ArtifactReference, Responsibility};
    use crate::runtime_backend::backend;

    let observations = record
        .runtime_instances
        .iter()
        .map(|runtime| {
            let runtime_backend = backend(runtime.backend);
            let described_mounts = runtime_backend
                .describe_mounts(&runtime.object_reference)
                .map(|mounts| mounts.len());
            let observation = runtime_backend.inspect(&runtime.object_reference);
            match observation {
                Ok(observation) => {
                    let artifact_matches = runtime.local_artifact_id.as_ref().map_or_else(
                        || match (&runtime.artifact, &observation.artifact) {
                            (
                                ArtifactReference::Oci {
                                    digest: expected, ..
                                },
                                ArtifactReference::Oci { digest: actual, .. },
                            ) => expected == actual,
                            (
                                ArtifactReference::HostBinary {
                                    sha256: expected, ..
                                },
                                ArtifactReference::HostBinary { sha256: actual, .. },
                            ) => expected == actual,
                            _ => false,
                        },
                        |expected| observation.local_artifact_id.as_ref() == Some(expected),
                    );
                    serde_json::json!({
                        "runtime_instance_id": runtime.runtime_instance_id,
                        "backend": runtime.backend,
                        "object_reference": runtime.object_reference,
                        "present": true,
                        "running": observation.running,
                        "artifact_matches_declaration": artifact_matches,
                        "mounts_verified": described_mounts.is_ok(),
                        "mount_count": described_mounts.unwrap_or_default(),
                    })
                }
                Err(_) => serde_json::json!({
                    "runtime_instance_id": runtime.runtime_instance_id,
                    "backend": runtime.backend,
                    "object_reference": runtime.object_reference,
                    "present": false,
                    "running": false,
                    "artifact_matches_declaration": false,
                    "mounts_verified": false,
                    "mount_count": 0,
                }),
            }
        })
        .collect::<Vec<_>>();
    let managed_runtime_drift = record.capabilities.runtime.responsibility
        == Responsibility::Managed
        && observations.iter().any(|observation| {
            !observation
                .get("present")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || !observation
                    .get("artifact_matches_declaration")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
        });
    let report = serde_json::json!({
        "schema": 1,
        "deployment_id": record.deployment_id,
        "alias": record.alias,
        "issuer": record.issuer,
        "active_release": record.active_release,
        "trust": record.trust,
        "capabilities": record.capabilities,
        "core_recovery_proven": record.core_recovery_is_proven(),
        "machine_loss_requires_off_host_package": true,
        "managed_runtime_drift": managed_runtime_drift,
        "runtime_instances": observations,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    if doctor && managed_runtime_drift {
        bail!("managed runtime drift requires explicit re-verification; no state was overwritten");
    }
    Ok(())
}

#[allow(dead_code)] // J-phase removes the legacy read-only classification with its tests
pub(super) fn command_is_read_only(command: &LegacyCommand) -> bool {
    matches!(
        command,
        LegacyCommand::DeploymentsList | LegacyCommand::Status | LegacyCommand::Doctor
    )
}

#[allow(dead_code)] // J-phase removes the legacy global lock with its tests
pub(super) fn acquire_lock(command: &LegacyCommand) -> anyhow::Result<File> {
    // Installation, update and identity transitions used to mutate one
    // lifecycle state machine and therefore shared one lock even when a test
    // or operator overrides its location.
    let path = std::env::var_os("NAZOAUTHCTL_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    acquire_lock_at(&path, command)
}

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

#[allow(dead_code)] // consumed by tests/unit/controller.rs until J deletes both
pub(super) fn acquire_lock_at(path: &Path, command: &LegacyCommand) -> anyhow::Result<File> {
    let read_only = command_is_read_only(command);
    let file = open_lock_file(path, read_only, "lifecycle lock").with_context(|| {
        if read_only {
            format!(
                "failed to open existing lifecycle lock {} for read-only observation",
                path.display()
            )
        } else {
            format!("failed to open lifecycle lock {}", path.display())
        }
    })?;
    let result = if read_only {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match result {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another nazoauthctl lifecycle operation is already running")
        }
        Err(TryLockError::Error(error)) => Err(error).context("failed to acquire lifecycle lock"),
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
