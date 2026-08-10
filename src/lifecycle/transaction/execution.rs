use super::*;

pub(crate) fn execute_coordinated_update(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction: &crate::coordination::UpdateCoordination,
) -> anyhow::Result<crate::coordination::UpdateCoordination> {
    use crate::coordination::{CoordinationState, StepOwner, StepState};

    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current_record = store.reload_locked(record)?;
    let record = &current_record;
    let _shared_locks = store.shared_capability_locks(record, &Capability::ALL)?;

    if transaction.deployment_id != record.deployment_id {
        bail!("update transaction is bound to a different deployment");
    }
    if transaction.state == CoordinationState::Committed {
        crate::governance::append_management_audit(
            store,
            record,
            &transaction.transaction_id,
            "lifecycle-update",
            &transaction.target_release.release,
        )?;
        crate::coordination::finalize_committed_locked(store, record, &transaction.transaction_id)?;
        archive_update_execution(store, &record.deployment_id, &transaction.transaction_id)?;
        return Ok(transaction.clone());
    }
    if transaction.state != CoordinationState::ReadyForController {
        bail!("update transaction is not ready for controller execution");
    }
    record.require_mutation(&[Capability::Runtime, Capability::Artifact])?;
    if !record.core_recovery_is_proven() {
        bail!("controller update is forbidden until offline recovery is proven");
    }

    let lifecycle_path = lifecycle_path(record)?;
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    validate_lifecycle_acceptance_record_binding(&lifecycle, record)?;
    let from_cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &record.active_release.release)?
            .join("cache.json");
    let target_cache_path = trusted_runtime_directory(
        store,
        &record.deployment_id,
        &transaction.target_release.release,
    )?
    .join("cache.json");
    let from_cache = load_cache(&from_cache_path, record)?;
    let target_record = DeploymentRecord {
        active_release: transaction.target_release.clone(),
        ..record.clone()
    };
    let target_cache = load_cache(&target_cache_path, &target_record)?;
    validate_cached_artifacts(&from_cache)?;
    validate_cached_artifacts(&target_cache)?;

    let execution_path = update_execution_path(store, &record.deployment_id);
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let from_cache_sha256 = sha256(&from_cache_path)?;
    let target_cache_sha256 = sha256(&target_cache_path)?;
    let mut execution = if execution_path.exists() {
        let execution: UpdateExecution = serde_json::from_slice(&read_secure_regular_file(
            &execution_path,
            "lifecycle update execution journal",
            true,
            MAX_LIFECYCLE_BYTES,
        )?)
        .context("lifecycle update execution journal is invalid")?;
        if execution.schema != 1
            || execution.transaction_id != transaction.transaction_id
            || execution.deployment_id != record.deployment_id
            || execution.from_release != record.active_release
            || execution.target_release != transaction.target_release
            || execution.lifecycle_sha256 != lifecycle_sha256
            || execution.from_cache_sha256 != from_cache_sha256
            || execution.target_cache_sha256 != target_cache_sha256
        {
            bail!("lifecycle update journal binding changed after preparation");
        }
        execution
    } else {
        UpdateExecution {
            schema: 1,
            transaction_id: transaction.transaction_id.clone(),
            deployment_id: record.deployment_id.clone(),
            from_release: record.active_release.clone(),
            target_release: transaction.target_release.clone(),
            lifecycle_sha256,
            from_cache_sha256,
            target_cache_sha256,
            state: UpdateExecutionState::Prepared,
            completed_runtimes: BTreeSet::new(),
            recovery_manifest: None,
            recovery_manifest_sha256: None,
            updated_at: Utc::now().timestamp(),
        }
    };
    persist_update_execution(&execution_path, &execution)?;
    let mut current = crate::coordination::show_locked(store, record)?;

    if controller_step_pending(&current, "recovery-point") {
        record.require_mutation(&[Capability::Backups])?;
        let slot = load_recovery_slot(store, record)?;
        let receipt = invoke_recovery_driver(
            lifecycle_path,
            &lifecycle,
            &slot.recovery_manifest,
            &record.active_release.release,
            RecoveryOperation::Checkpoint,
            &record.capabilities,
        )?;
        let source = receipt
            .checkpoint_manifest
            .as_deref()
            .context("checkpoint receipt did not return a recovery manifest")?;
        let recovery_directory = store
            .deployment_state_dir(&record.deployment_id)
            .join("transactions")
            .join(&transaction.transaction_id)
            .join("recovery");
        crate::adoption::persist_bound_recovery_package(
            source,
            &record.deployment_id,
            &record.active_release.release,
            &recovery_directory,
        )?;
        let persisted = recovery_directory.join("manifest.json");
        execution.recovery_manifest_sha256 = Some(sha256(&persisted)?);
        execution.recovery_manifest = Some(persisted);
        execution.state = UpdateExecutionState::RecoveryPointCreated;
        execution.updated_at = Utc::now().timestamp();
        persist_update_execution(&execution_path, &execution)?;
        current = crate::coordination::complete_controller_step_locked(
            store,
            record,
            &transaction.transaction_id,
            "recovery-point",
            &sha256(&execution_path)?,
        )?;
    }

    if controller_step_pending(&current, "database-migration") {
        bail!(
            "the offline lifecycle contract cannot execute application migrations; enroll operator-task authority or provide this step as external evidence"
        );
    }

    for runtime in &lifecycle.runtimes {
        let step_id = format!("runtime-replace-{}", runtime.runtime_instance_id);
        let step = current
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .with_context(|| {
                format!("update plan omits runtime {}", runtime.runtime_instance_id)
            })?;
        match (step.owner, step.state) {
            (StepOwner::CtlOwned, StepState::Pending) => {
                let cached = target_cache
                    .runtimes
                    .get(&runtime.runtime_instance_id)
                    .context("target cache omits a lifecycle runtime")?;
                activate_cached_runtime(record, runtime, &transaction.target_release, cached)?;
                execution
                    .completed_runtimes
                    .insert(runtime.runtime_instance_id.clone());
                execution.updated_at = Utc::now().timestamp();
                persist_update_execution(&execution_path, &execution)?;
                current = crate::coordination::complete_controller_step_locked(
                    store,
                    record,
                    &transaction.transaction_id,
                    &step_id,
                    &sha256(&execution_path)?,
                )?;
            }
            (StepOwner::UserRequired | StepOwner::ProviderOwned, StepState::EvidenceAccepted)
            | (StepOwner::CtlOwned, StepState::ControllerCompleted) => {
                let cached = target_cache
                    .runtimes
                    .get(&runtime.runtime_instance_id)
                    .context("target cache omits a lifecycle runtime")?;
                verify_active_runtime(runtime, &transaction.target_release, cached)?;
                execution
                    .completed_runtimes
                    .insert(runtime.runtime_instance_id.clone());
            }
            _ => bail!("runtime update step is not ready for execution"),
        }
    }
    execution.state = UpdateExecutionState::RuntimesActivated;
    execution.updated_at = Utc::now().timestamp();
    persist_update_execution(&execution_path, &execution)?;

    if controller_step_pending(&current, "acceptance") {
        let acceptance = (|| -> anyhow::Result<()> {
            for runtime in &lifecycle.runtimes {
                let cached = target_cache
                    .runtimes
                    .get(&runtime.runtime_instance_id)
                    .context("target cache omits a lifecycle runtime")?;
                verify_active_runtime(runtime, &transaction.target_release, cached)?;
                verify_runtime_acceptance(runtime)?;
            }
            Ok(())
        })();
        if let Err(error) = acceptance {
            execution.state = UpdateExecutionState::AcceptanceFailed;
            execution.updated_at = Utc::now().timestamp();
            persist_update_execution(&execution_path, &execution)?;
            return Err(error);
        }
        let old_slot = load_recovery_slot(store, record)?;
        let rollback_manifest = execution
            .recovery_manifest
            .clone()
            .unwrap_or(old_slot.recovery_manifest);
        let rollback_manifest_sha256 = execution
            .recovery_manifest_sha256
            .clone()
            .unwrap_or(old_slot.recovery_manifest_sha256);
        persist_recovery_slot(
            store,
            &RecoverySlot {
                schema: 1,
                deployment_id: record.deployment_id.clone(),
                trusted_release: record.active_release.clone(),
                recovery_manifest: rollback_manifest,
                recovery_manifest_sha256: rollback_manifest_sha256,
            },
        )?;
        let mut updated = record.clone();
        updated.active_release = transaction.target_release.clone();
        for declared in &mut updated.runtime_instances {
            let runtime = lifecycle
                .runtimes
                .iter()
                .find(|runtime| runtime.runtime_instance_id == declared.runtime_instance_id)
                .context("lifecycle lost a declared runtime during update commit")?;
            let cached = target_cache
                .runtimes
                .get(&declared.runtime_instance_id)
                .context("target cache lost a declared runtime during update commit")?;
            declared.artifact = activated_artifact_reference(runtime, cached)?;
            declared.local_artifact_id = cached_local_artifact_id(cached);
        }
        updated.declaration_revision = record
            .declaration_revision
            .checked_add(1)
            .context("deployment declaration revision overflow")?;
        current = crate::coordination::commit_controller_update_locked(
            store,
            record,
            &updated,
            &transaction.transaction_id,
            "acceptance",
            &sha256(&target_cache_path)?,
        )?;
        execution.state = UpdateExecutionState::Committed;
        execution.updated_at = Utc::now().timestamp();
        persist_update_execution(&execution_path, &execution)?;
        crate::governance::append_management_audit(
            store,
            &updated,
            &transaction.transaction_id,
            "lifecycle-update",
            &transaction.target_release.release,
        )?;
        crate::coordination::finalize_committed_locked(
            store,
            &updated,
            &transaction.transaction_id,
        )?;
        archive_update_execution(store, &record.deployment_id, &transaction.transaction_id)?;
    }
    Ok(current)
}

pub(crate) fn rollback_registered(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current_record = store.reload_locked(record)?;
    let record = &current_record;
    let _shared_locks = store.shared_capability_locks(record, &Capability::ALL)?;
    record.require_mutation(&[Capability::Runtime, Capability::Artifact])?;
    if !record.core_recovery_is_proven() {
        bail!("deployment has no proven controller-independent rollback contract");
    }
    let lifecycle_path = lifecycle_path(record)?;
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    validate_lifecycle_acceptance_record_binding(&lifecycle, record)?;
    let slot = load_recovery_slot(store, record)?;
    let trusted_record = DeploymentRecord {
        active_release: slot.trusted_release.clone(),
        ..record.clone()
    };
    let cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &slot.trusted_release.release)?
            .join("cache.json");
    let cache = load_cache(&cache_path, &trusted_record)?;
    validate_cached_artifacts(&cache)?;
    let execution_path = rollback_execution_path(store, &record.deployment_id);
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let cache_sha256 = sha256(&cache_path)?;
    let target_release_sha256 = embedded_identity_digest(&slot.trusted_release)?;
    let mut execution = if execution_path.exists() {
        let execution = load_rollback_execution(&execution_path)?;
        if execution.schema != ROLLBACK_EXECUTION_SCHEMA
            || execution.deployment_id != record.deployment_id
            || execution.target_release != slot.trusted_release
            || execution.lifecycle_sha256 != lifecycle_sha256
            || execution.cache_sha256 != cache_sha256
            || execution.target_release_sha256 != target_release_sha256
        {
            bail!("lifecycle rollback journal binding changed after preparation");
        }
        if execution.state < RollbackExecutionState::DeclarationCommitted
            && execution.source_release != record.active_release
            && execution.target_release != record.active_release
        {
            bail!("lifecycle rollback journal source Release changed after preparation");
        }
        if execution.state >= RollbackExecutionState::DeclarationCommitted
            && record.active_release != execution.target_release
        {
            bail!("lifecycle rollback declaration state is not reflected in the deployment");
        }
        execution
    } else {
        RollbackExecution {
            schema: ROLLBACK_EXECUTION_SCHEMA,
            transaction_id: uuid::Uuid::now_v7().to_string(),
            deployment_id: record.deployment_id.clone(),
            source_release: record.active_release.clone(),
            target_release: slot.trusted_release.clone(),
            lifecycle_sha256,
            cache_sha256,
            target_release_sha256,
            state: RollbackExecutionState::Prepared,
            completed_runtimes: BTreeSet::new(),
            updated_at: Utc::now().timestamp(),
        }
    };
    let lifecycle_runtime_ids = lifecycle
        .runtimes
        .iter()
        .map(|runtime| runtime.runtime_instance_id.as_str())
        .collect::<BTreeSet<_>>();
    if execution
        .completed_runtimes
        .iter()
        .any(|runtime_id| !lifecycle_runtime_ids.contains(runtime_id.as_str()))
    {
        bail!("lifecycle rollback journal contains an unknown runtime");
    }
    if execution.state >= RollbackExecutionState::DeclarationCommitted
        && execution.completed_runtimes.len() != lifecycle.runtimes.len()
    {
        bail!("lifecycle rollback journal committed before every runtime completed");
    }
    persist_rollback_execution(&execution_path, &execution)?;

    if execution.state < RollbackExecutionState::DeclarationCommitted {
        for runtime in &lifecycle.runtimes {
            let cached = cache
                .runtimes
                .get(&runtime.runtime_instance_id)
                .context("rollback cache omits a lifecycle runtime")?;
            if execution
                .completed_runtimes
                .contains(&runtime.runtime_instance_id)
                && verify_active_runtime(runtime, &slot.trusted_release, cached).is_ok()
            {
                continue;
            }
            activate_cached_runtime(record, runtime, &slot.trusted_release, cached)?;
            execution
                .completed_runtimes
                .insert(runtime.runtime_instance_id.clone());
            execution.updated_at = Utc::now().timestamp();
            persist_rollback_execution(&execution_path, &execution)?;
        }
        execution.state = RollbackExecutionState::RuntimesActivated;
        execution.updated_at = Utc::now().timestamp();
        persist_rollback_execution(&execution_path, &execution)?;

        for runtime in &lifecycle.runtimes {
            let cached = cache
                .runtimes
                .get(&runtime.runtime_instance_id)
                .context("rollback cache omits a lifecycle runtime")?;
            verify_active_runtime(runtime, &slot.trusted_release, cached)?;
            verify_runtime_acceptance(runtime)?;
        }

        let mut rolled_back = record.clone();
        rolled_back.active_release = slot.trusted_release.clone();
        for declared in &mut rolled_back.runtime_instances {
            let runtime = lifecycle
                .runtimes
                .iter()
                .find(|runtime| runtime.runtime_instance_id == declared.runtime_instance_id)
                .context("lifecycle lost a declared runtime during rollback")?;
            let cached = cache
                .runtimes
                .get(&declared.runtime_instance_id)
                .context("rollback cache lost a declared runtime")?;
            declared.artifact = activated_artifact_reference(runtime, cached)?;
            declared.local_artifact_id = cached_local_artifact_id(cached);
        }
        if rolled_back != *record {
            rolled_back.declaration_revision = record
                .declaration_revision
                .checked_add(1)
                .context("deployment declaration revision overflow")?;
            store.persist_declaration_cas_locked(record, &rolled_back)?;
        }
        execution.state = RollbackExecutionState::DeclarationCommitted;
        execution.updated_at = Utc::now().timestamp();
        persist_rollback_execution(&execution_path, &execution)?;
    }

    let committed_record = if execution.state >= RollbackExecutionState::DeclarationCommitted {
        store.load(&record.deployment_id)?
    } else {
        record.clone()
    };
    if execution.state < RollbackExecutionState::AuditCommitted {
        crate::governance::append_management_audit(
            store,
            &committed_record,
            &execution.transaction_id,
            "lifecycle-rollback",
            &execution.target_release.release,
        )?;
        execution.state = RollbackExecutionState::AuditCommitted;
        execution.updated_at = Utc::now().timestamp();
        persist_rollback_execution(&execution_path, &execution)?;
    }
    if execution.state < RollbackExecutionState::Committed {
        execution.state = RollbackExecutionState::Committed;
        execution.updated_at = Utc::now().timestamp();
        persist_rollback_execution(&execution_path, &execution)?;
    }
    let history = execution_path.with_file_name(format!(
        "lifecycle-rollback-{}.json",
        execution.transaction_id
    ));
    atomic_write(&history, &serde_json::to_vec_pretty(&execution)?, 0o600)?;
    remove_file_durable(&execution_path)
}
