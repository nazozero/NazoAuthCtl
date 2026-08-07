use super::*;

pub(crate) fn registered_update_plan(
    record: &DeploymentRecord,
    options: &UpdateOptions,
) -> anyhow::Result<()> {
    const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";

    let container_backend = record
        .runtime_instances
        .iter()
        .map(|runtime| runtime.backend)
        .find(|backend| *backend != RuntimeBackendKind::Systemd);
    let release = VerifiedRelease::fetch(
        SERVER_REPOSITORY,
        options.version.as_deref(),
        container_backend,
    )?;
    let plan = build_registered_update_plan(record, &release.manifest)?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

pub(crate) fn registered_update_prepare(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    options: &UpdateOptions,
) -> anyhow::Result<()> {
    const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";

    // Keep the declaration snapshot and all staged transaction material under
    // one deployment/shared-capability lock.  `resolve` happens before this
    // function is called and is therefore only an ID selection step.
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let record = store.reload_locked(record)?;
    let _shared_locks = store.shared_capability_locks(&record, &Capability::ALL)?;

    let container_backend = record
        .runtime_instances
        .iter()
        .map(|runtime| runtime.backend)
        .find(|backend| *backend != RuntimeBackendKind::Systemd);
    let release = VerifiedRelease::fetch(
        SERVER_REPOSITORY,
        options.version.as_deref(),
        container_backend,
    )?;
    let plan = build_registered_update_plan(&record, &release.manifest)?;
    let evidence_root = store
        .deployment_state_dir(&record.deployment_id)
        .join("recovery")
        .join("trusted-releases")
        .join(&release.manifest.version);
    release.persist_verification_evidence(&evidence_root)?;
    if record.resources.contains_key("lifecycle_contract") {
        crate::lifecycle::stage_update_release(store, &record, &release)?;
    }
    let transaction = crate::coordination::prepare_update_locked(store, &record, &plan)?;
    println!("{}", serde_json::to_string_pretty(&transaction)?);
    Ok(())
}

pub(crate) fn build_registered_update_plan(
    record: &DeploymentRecord,
    target: &ReleaseManifest,
) -> anyhow::Result<serde_json::Value> {
    let minimum = format!("v{}", target.rollback.minimum_supported_version);
    let mut blockers = Vec::new();
    if record.trust != crate::deployment::TrustState::Adopted {
        blockers.push("deployment is observed; mutation remains forbidden".to_owned());
    }
    if compare_versions(&record.active_release.release, &minimum)? == std::cmp::Ordering::Less {
        blockers.push(format!(
            "active Release {} is below target minimum supported {}",
            record.active_release.release, minimum
        ));
    }
    if record.recovery.conclusion != RecoveryConclusion::Proven
        && [
            Capability::Runtime,
            Capability::Artifact,
            Capability::Database,
            Capability::Backups,
        ]
        .iter()
        .any(|capability| {
            record
                .capabilities
                .grant(*capability)
                .responsibility
                .permits_mutation()
        })
    {
        blockers.push("controller mutation is forbidden until recovery is proven".to_owned());
    }
    if !record.resources.contains_key("controller_config")
        && !record.resources.contains_key("lifecycle_contract")
        && Capability::ALL.iter().any(|capability| {
            record
                .capabilities
                .grant(*capability)
                .responsibility
                .permits_mutation()
        })
    {
        blockers.push(
            "controller-owned steps require an explicitly approved lifecycle configuration"
                .to_owned(),
        );
    }
    let operator_compatible = record
        .operator_protocol_versions
        .contains(&nazo_operator_protocol::PROTOCOL_VERSION);
    if !operator_compatible
        && record
            .capabilities
            .operator_tasks
            .responsibility
            .permits_mutation()
    {
        blockers.push(format!(
            "application migration requires operator protocol {}; core artifact recovery remains available",
            nazo_operator_protocol::PROTOCOL_VERSION
        ));
    }
    if record.resources.contains_key("lifecycle_contract")
        && record
            .capabilities
            .database
            .responsibility
            .permits_mutation()
    {
        blockers.push(
            "application migration is not authorized by the offline lifecycle contract; provide the database step as external evidence or enroll a separate operator-task authority"
                .to_owned(),
        );
    }

    let owner = |capability: Capability, resource: &str| {
        update_step_owner(record, record.capabilities.grant(capability), resource)
    };
    let mut steps = vec![json!({
        "id": "verify-release",
        "owner": "ctl-owned",
        "capability": "artifact",
        "action": "verify signed Release, attestation, compatibility, and exact OCI or binary identity",
        "evidence_required": true,
    })];
    steps.push(json!({
        "id": "recovery-point",
        "owner": owner(Capability::Backups, "backups"),
        "capability": "backups",
        "action": "create and verify a deployment-bound recovery point before writer shutdown",
        "evidence_required": true,
    }));
    steps.push(json!({
        "id": "database-migration",
        "owner": owner(Capability::Database, "database"),
        "capability": "database",
        "action": if operator_compatible {
            "apply the Release migration under the granted database and operator-task boundaries"
        } else {
            "blocked application task; do not infer migration compatibility"
        },
        "evidence_required": true,
    }));
    for runtime in &record.runtime_instances {
        steps.push(json!({
            "id": format!("runtime-replace-{}", runtime.runtime_instance_id),
            "owner": owner(Capability::Runtime, "runtime"),
            "capability": "runtime",
            "runtime_instance_id": runtime.runtime_instance_id,
            "backend": runtime.backend,
            "object_reference": runtime.object_reference,
            "action": "replace this runtime instance with the digest-bound candidate and retain the previous trusted artifact",
            "evidence_required": true,
        }));
    }
    steps.push(json!({
        "id": "proxy-cutover",
        "owner": owner(Capability::ProxyTls, "proxy_tls"),
        "capability": "proxy_tls",
        "action": "switch or verify the external routing and TLS boundary",
        "evidence_required": true,
    }));
    steps.push(json!({
        "id": "acceptance",
        "owner": "ctl-owned",
        "capability": "artifact",
        "action": "verify issuer, readiness, embedded build identity, and per-replica artifact digest before commit",
        "evidence_required": true,
    }));

    Ok(json!({
        "schema": 1,
        "operation": "update",
        "deployment_id": record.deployment_id,
        "active_release": &record.active_release,
        "target_release": &target.embedded,
        "target_oci_digest": target.image_oci_digest(),
        "capabilities": &record.capabilities,
        "recovery": &record.recovery,
        "operator_protocol_compatible": operator_compatible,
        "core_recovery_requires_operator_task": false,
        "steps": steps,
        "blockers": blockers,
    }))
}

pub(crate) fn update_step_owner(
    record: &DeploymentRecord,
    grant: &CapabilityGrant,
    resource: &str,
) -> &'static str {
    match grant.responsibility {
        Responsibility::Managed | Responsibility::Delegated => "ctl-owned",
        Responsibility::External => {
            if matches!(
                record.resources.get(resource),
                Some(SafeReference::Provider { .. })
            ) {
                "provider-owned"
            } else {
                "user-required"
            }
        }
    }
}

pub(crate) fn print_update_plan(
    config: &UpdateConfig,
    current_version: &str,
    current_revision: &str,
    target: &ReleaseManifest,
) -> anyhow::Result<()> {
    let value = json!({
        "current_version": current_version,
        "current_revision": current_revision,
        "target_version": target.version,
        "target_revision": target.backend_commit,
        "target_oci_digest": target.image_oci_digest(),
        "artifact_rollback": target.rollback.artifact
            && target.rollback.schema_compatible
            && !target.rollback.irreversible_migration,
        "schema_compatible_rollback": target.rollback.schema_compatible,
        "database_recovery": match (config.dependencies.mode.as_str(), target.rollback.database_restore) {
            ("managed", crate::model::DatabaseRestore::Backup) => "verified managed backup restore via nazoauthctl recover --yes",
            ("external", crate::model::DatabaseRestore::Backup) => "external provider backup restore; nazoauthctl will not modify the provider database",
            (_, crate::model::DatabaseRestore::Backup) => "invalid dependency recovery owner",
            (_, crate::model::DatabaseRestore::Pitr) => "external provider PITR procedure required; nazoauthctl does not claim automatic PITR",
            (_, crate::model::DatabaseRestore::None) => "unavailable",
        },
        "database_recovery_owner": if config.dependencies.mode == "managed"
            && target.rollback.database_restore == crate::model::DatabaseRestore::Backup {
            "nazoauthctl"
        } else {
            "external-operator"
        },
        "database_auto_rollback": false,
        "backup_consistency": if config.dependencies.mode == "managed" {
            "single managed application writer is stopped before PostgreSQL and Valkey backup; cross-store recovery may invalidate ephemeral Valkey state"
        } else {
            "this application instance is stopped, but the external operator must quiesce every other writer and provide the declared database recovery procedure"
        },
        "irreversible_migration_barrier": target.rollback.irreversible_migration,
        "migration_floor": target.rollback.migration_floor,
        "minimum_supported_version": target.rollback.minimum_supported_version,
        "backup_will_be_created_at": config.backup_root,
        "rationale": target.rollback.rationale,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) fn recovery_boundary_name(boundary: crate::model::DatabaseRestore) -> &'static str {
    match boundary {
        crate::model::DatabaseRestore::Backup => "database-backup",
        crate::model::DatabaseRestore::Pitr => "database-pitr",
        crate::model::DatabaseRestore::None => "database-unavailable",
    }
}
