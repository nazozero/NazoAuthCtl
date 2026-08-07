use super::*;

pub(crate) fn recover_registered(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    record.require_mutation(&[
        Capability::Runtime,
        Capability::Artifact,
        Capability::Backups,
    ])?;
    if !record.core_recovery_is_proven() {
        bail!("deployment has no proven controller-independent recovery contract");
    }
    let lifecycle_path = lifecycle_path(record)?;
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    let slot = load_recovery_slot(store, record)?;
    let recovery_manifest = slot.recovery_manifest.clone();
    let cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &slot.trusted_release.release)?
            .join("cache.json");
    let trusted_record = DeploymentRecord {
        active_release: slot.trusted_release.clone(),
        ..record.clone()
    };
    let cache = load_cache(&cache_path, &trusted_record)?;
    validate_cached_artifacts(&cache)?;
    let transaction_path = store
        .deployment_state_dir(&record.deployment_id)
        .join("transactions")
        .join("active-recovery.json");
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let cache_sha256 = sha256(&cache_path)?;
    let mut transaction = if transaction_path.exists() {
        let transaction: RecoveryTransaction =
            serde_json::from_slice(&fs::read(&transaction_path)?)
                .context("recovery transaction is invalid")?;
        if transaction.schema != 1
            || transaction.deployment_id != record.deployment_id
            || transaction.release != slot.trusted_release.release
            || transaction.lifecycle_sha256 != lifecycle_sha256
            || transaction.cache_sha256 != cache_sha256
            || transaction.recovery_manifest_sha256 != slot.recovery_manifest_sha256
        {
            bail!("recovery transaction binding changed after preparation");
        }
        transaction
    } else {
        RecoveryTransaction {
            schema: 1,
            transaction_id: uuid::Uuid::now_v7().to_string(),
            deployment_id: record.deployment_id.clone(),
            release: slot.trusted_release.release.clone(),
            lifecycle_sha256,
            cache_sha256,
            recovery_manifest_sha256: slot.recovery_manifest_sha256.clone(),
            state: RecoveryTransactionState::Prepared,
            completed_runtimes: BTreeSet::new(),
            updated_at: Utc::now().timestamp(),
        }
    };
    persist_recovery_transaction(&transaction_path, &transaction)?;
    if transaction.state < RecoveryTransactionState::RuntimesQuiesced {
        for runtime in &lifecycle.runtimes {
            backend(runtime.backend).verify_ownership(
                &runtime.object_reference,
                &record.deployment_id,
                &runtime.runtime_instance_id,
                &record.control_authority,
            )?;
            backend(runtime.backend).quiesce_for_recovery(&runtime.object_reference)?;
        }
        transaction.state = RecoveryTransactionState::RuntimesQuiesced;
        transaction.updated_at = Utc::now().timestamp();
        persist_recovery_transaction(&transaction_path, &transaction)?;
    }
    if transaction.state < RecoveryTransactionState::ProviderRestored {
        let receipt = invoke_recovery_driver(
            lifecycle_path,
            &lifecycle,
            &recovery_manifest,
            &slot.trusted_release.release,
            RecoveryOperation::Restore,
            &record.capabilities,
        )?;
        atomic_write(
            &store
                .deployment_state_dir(&record.deployment_id)
                .join("recovery")
                .join("latest-driver-receipt.json"),
            &serde_json::to_vec_pretty(&receipt)?,
            0o600,
        )?;
        transaction.state = RecoveryTransactionState::ProviderRestored;
        transaction.updated_at = Utc::now().timestamp();
        persist_recovery_transaction(&transaction_path, &transaction)?;
    }
    for runtime in &lifecycle.runtimes {
        if transaction
            .completed_runtimes
            .contains(&runtime.runtime_instance_id)
        {
            continue;
        }
        let artifact = cache
            .runtimes
            .get(&runtime.runtime_instance_id)
            .context("trusted runtime cache omits a lifecycle runtime")?;
        activate_cached_runtime(record, runtime, &slot.trusted_release, artifact)?;
        transaction
            .completed_runtimes
            .insert(runtime.runtime_instance_id.clone());
        transaction.updated_at = Utc::now().timestamp();
        persist_recovery_transaction(&transaction_path, &transaction)?;
    }
    transaction.state = RecoveryTransactionState::RuntimesRestored;
    transaction.updated_at = Utc::now().timestamp();
    persist_recovery_transaction(&transaction_path, &transaction)?;
    let mut recovered = record.clone();
    recovered.active_release = slot.trusted_release.clone();
    for runtime in &mut recovered.runtime_instances {
        let lifecycle_runtime = lifecycle
            .runtimes
            .iter()
            .find(|entry| entry.runtime_instance_id == runtime.runtime_instance_id)
            .context("recovery lifecycle lost a declared runtime")?;
        let cached = cache
            .runtimes
            .get(&runtime.runtime_instance_id)
            .context("recovery cache lost a declared runtime")?;
        runtime.artifact = activated_artifact_reference(lifecycle_runtime, cached)?;
        runtime.local_artifact_id = cached_local_artifact_id(cached);
    }
    if recovered != *record {
        recovered.declaration_revision += 1;
        store.persist_declaration_locked(&recovered)?;
    }
    transaction.state = RecoveryTransactionState::Committed;
    transaction.updated_at = Utc::now().timestamp();
    persist_recovery_transaction(&transaction_path, &transaction)?;
    crate::governance::append_management_audit(
        store,
        &recovered,
        &transaction.transaction_id,
        "lifecycle-recover",
        &recovered.active_release.release,
    )?;
    let history =
        transaction_path.with_file_name(format!("recovery-{}.json", transaction.transaction_id));
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&transaction_path)
}
