use super::*;

pub(crate) fn validate_lifecycle_record_binding(
    lifecycle: &LifecycleManifest,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    if lifecycle.deployment_id != record.deployment_id
        || lifecycle.runtimes.len() != record.runtime_instances.len()
    {
        bail!("lifecycle contract no longer matches the deployment declaration");
    }
    for runtime in &lifecycle.runtimes {
        if !record.runtime_instances.iter().any(|declared| {
            declared.runtime_instance_id == runtime.runtime_instance_id
                && declared.backend == runtime.backend
                && declared.object_reference == runtime.object_reference
        }) {
            bail!("lifecycle runtime no longer matches the deployment declaration");
        }
    }
    Ok(())
}

pub(crate) fn lifecycle_path(record: &DeploymentRecord) -> anyhow::Result<&Path> {
    match record.resources.get("lifecycle_contract") {
        Some(SafeReference::File { path }) => Ok(path),
        _ => bail!("deployment has no executable lifecycle contract"),
    }
}

pub(crate) fn controller_step_pending(
    transaction: &crate::coordination::UpdateCoordination,
    step_id: &str,
) -> bool {
    transaction.steps.iter().any(|step| {
        step.id == step_id
            && step.owner == crate::coordination::StepOwner::CtlOwned
            && step.state == crate::coordination::StepState::Pending
    })
}

pub(crate) fn load_cache(
    path: &Path,
    record: &DeploymentRecord,
) -> anyhow::Result<TrustedRuntimeCache> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect trusted runtime cache {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("trusted runtime cache manifest is not a regular file");
    }
    let cache: TrustedRuntimeCache =
        serde_json::from_slice(&fs::read(path)?).context("trusted runtime cache is invalid")?;
    if cache.schema != TRUSTED_RUNTIME_CACHE_SCHEMA
        || cache.deployment_id != record.deployment_id
        || cache.release != record.active_release
        || cache.runtimes.len() != record.runtime_instances.len()
    {
        bail!("trusted runtime cache is bound to a different deployment or Release");
    }
    Ok(cache)
}

pub(crate) fn validate_cached_artifacts(cache: &TrustedRuntimeCache) -> anyhow::Result<()> {
    for artifact in cache.runtimes.values() {
        match artifact {
            CachedRuntimeArtifact::OciArchive {
                digest,
                local_image_id,
                archive,
                archive_sha256,
                ..
            } => {
                validate_oci_digest(digest)?;
                validate_oci_digest(local_image_id)?;
                validate_lower_hex(archive_sha256)?;
                validate_regular_artifact(archive, "trusted OCI recovery archive")?;
                if sha256(archive)? != *archive_sha256 {
                    bail!("trusted OCI recovery archive digest is invalid");
                }
            }
            CachedRuntimeArtifact::HostBinary {
                binary,
                sha256: digest,
            } => {
                validate_lower_hex(digest)?;
                validate_regular_artifact(binary, "trusted host recovery binary")?;
                if sha256(binary)? != *digest {
                    bail!("trusted host recovery binary digest is invalid");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn trusted_runtime_directory(
    store: &DeploymentStore,
    deployment_id: &str,
    release: &str,
) -> anyhow::Result<PathBuf> {
    validate_file_identifier(release, "trusted runtime Release")?;
    Ok(store
        .deployment_state_dir(deployment_id)
        .join("recovery")
        .join("trusted-runtime")
        .join(release))
}

pub(crate) fn recovery_slot_path(store: &DeploymentStore, deployment_id: &str) -> PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("recovery")
        .join("rollback-slot.json")
}

pub(crate) fn persist_recovery_slot(
    store: &DeploymentStore,
    slot: &RecoverySlot,
) -> anyhow::Result<()> {
    atomic_write(
        &recovery_slot_path(store, &slot.deployment_id),
        &serde_json::to_vec_pretty(slot)?,
        0o600,
    )
}

pub(crate) fn load_recovery_slot(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<RecoverySlot> {
    let path = recovery_slot_path(store, &record.deployment_id);
    let metadata = fs::symlink_metadata(&path)
        .context("deployment has no controller-independent recovery slot")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("deployment recovery slot is not a regular file");
    }
    let slot: RecoverySlot =
        serde_json::from_slice(&fs::read(&path)?).context("deployment recovery slot is invalid")?;
    if slot.schema != 1 || slot.deployment_id != record.deployment_id {
        bail!("deployment recovery slot is bound to a different deployment");
    }
    validate_file_identifier(&slot.trusted_release.release, "recovery slot Release")?;
    validate_lower_hex(&slot.recovery_manifest_sha256)?;
    validate_regular_artifact(&slot.recovery_manifest, "deployment recovery manifest")?;
    if sha256(&slot.recovery_manifest)? != slot.recovery_manifest_sha256 {
        bail!("deployment recovery manifest changed after slot commit");
    }
    Ok(slot)
}

pub(crate) fn persist_recovery_transaction(
    path: &Path,
    transaction: &RecoveryTransaction,
) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(transaction)?, 0o600)
}

pub(crate) fn validate_regular_artifact(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("{label} is not a non-empty regular file");
    }
    Ok(())
}

pub(crate) fn update_execution_path(store: &DeploymentStore, deployment_id: &str) -> PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("active-lifecycle-update.json")
}

pub(crate) fn persist_update_execution(
    path: &Path,
    execution: &UpdateExecution,
) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(execution)?, 0o600)
}

pub(crate) fn archive_update_execution(
    store: &DeploymentStore,
    deployment_id: &str,
    transaction_id: &str,
) -> anyhow::Result<()> {
    let active = update_execution_path(store, deployment_id);
    if !active.exists() {
        return Ok(());
    }
    let execution: UpdateExecution = serde_json::from_slice(&fs::read(&active)?)
        .context("lifecycle update execution journal is invalid")?;
    if execution.transaction_id != transaction_id
        || execution.state != UpdateExecutionState::Committed
    {
        bail!("lifecycle update execution cannot be archived before commit");
    }
    let history = active.with_file_name(format!("lifecycle-update-{transaction_id}.json"));
    atomic_write(&history, &serde_json::to_vec_pretty(&execution)?, 0o600)?;
    remove_file_durable(&active)
}

pub(crate) fn validate_oci_digest(value: &str) -> anyhow::Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("OCI recovery artifact has no sha256 digest")?;
    validate_lower_hex(digest)
}

pub(crate) fn validate_container_policy(
    backend: RuntimeBackendKind,
    policy: Option<&ContainerRuntimePolicy>,
) -> anyhow::Result<()> {
    match (backend, policy) {
        (RuntimeBackendKind::Systemd, Some(_)) => {
            bail!("systemd lifecycle runtime cannot declare a container policy")
        }
        (RuntimeBackendKind::Systemd, None) => return Ok(()),
        (RuntimeBackendKind::Docker | RuntimeBackendKind::Podman, None) => {
            bail!("container lifecycle runtime requires an explicit container policy")
        }
        (RuntimeBackendKind::Docker | RuntimeBackendKind::Podman, Some(policy)) => {
            if policy
                .pids_limit
                .is_some_and(|value| value == 0 || value > MAX_PIDS_LIMIT)
            {
                bail!("container lifecycle pids limit is outside the supported boundary");
            }
            if policy
                .memory_limit_bytes
                .is_some_and(|value| value == 0 || value > MAX_MEMORY_LIMIT_BYTES)
            {
                bail!("container lifecycle memory limit is outside the supported boundary");
            }
            if policy
                .cpu_limit_millis
                .is_some_and(|value| value == 0 || value > MAX_CPU_LIMIT_MILLIS)
            {
                bail!("container lifecycle CPU limit is outside the supported boundary");
            }
            if policy.tmpfs.len() > MAX_TMPFS_MOUNTS {
                bail!("container lifecycle declares too many tmpfs mounts");
            }
            let mut destinations = BTreeSet::new();
            for tmpfs in &policy.tmpfs {
                if !runtime_path_is_absolute(backend, &tmpfs.destination) || tmpfs.size_bytes == 0 {
                    bail!("container lifecycle tmpfs declaration is invalid");
                }
                if !destinations.insert(&tmpfs.destination) {
                    bail!("container lifecycle contains a duplicate tmpfs destination");
                }
            }
        }
    }
    Ok(())
}
