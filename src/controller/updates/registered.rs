use super::*;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigBackedUpdateEvidence<'a> {
    schema: u32,
    deployment_id: &'a str,
    transaction_id: &'a str,
    target_release: &'a EmbeddedIdentity,
    active_release_sha256: String,
    rollback_state_sha256: String,
    runtime_observations: &'a [crate::runtime_backend::RuntimeObservation],
    verified_at: i64,
}

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
    if release.manifest.rollback.irreversible_migration && !options.accept_migration_barrier {
        bail!(
            "this Release crosses an irreversible migration barrier; inspect update --plan and repeat with --accept-migration-barrier --yes"
        );
    }
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

pub(crate) fn resume_config_backed_update_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction: &crate::coordination::UpdateCoordination,
    config_path: &Path,
    config: &UpdateConfig,
    accept_migration_barrier: bool,
) -> anyhow::Result<crate::coordination::UpdateCoordination> {
    use crate::coordination::{CoordinationState, StepOwner, StepState};
    use crate::deployment::ArtifactReference;

    if transaction.state != CoordinationState::ReadyForController {
        bail!("update transaction is not ready for controller execution");
    }
    match record.resources.get("controller_config") {
        Some(SafeReference::File { path })
            if fs::canonicalize(path)? == fs::canonicalize(config_path)? => {}
        _ => bail!("registered update is not bound to this controller configuration"),
    }
    if record.resources.contains_key("lifecycle_contract") {
        bail!("config-backed update cannot replace an offline lifecycle update");
    }
    if record.runtime_instances.len() != 1 {
        bail!("config-backed update requires exactly one managed runtime instance");
    }

    update(
        config_path,
        config,
        UpdateOptions {
            version: Some(transaction.target_release.release.clone()),
            plan: false,
            yes: true,
            accept_migration_barrier,
        },
    )?;

    let active = load_active_release(config)?;
    if active.embedded != transaction.target_release {
        bail!("config-backed update did not activate the coordinated Release");
    }
    let runtime = Runtime::new(config);
    if runtime.active_revision()? != transaction.target_release.revision {
        bail!("config-backed update runtime revision differs from the coordinated Release");
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config, &active)?;

    let mut observations = Vec::with_capacity(record.runtime_instances.len());
    for declared in &record.runtime_instances {
        let observation = crate::runtime_backend::backend(declared.backend)
            .inspect(&declared.object_reference)?;
        validate_config_backed_runtime_observation(declared, &observation)?;
        let artifact_matches = match (&observation.artifact, declared.backend) {
            (
                ArtifactReference::Oci {
                    image_reference,
                    digest,
                },
                RuntimeBackendKind::Podman | RuntimeBackendKind::Docker,
            ) => {
                let expected_digest = active.runtime_oci_digest()?;
                digest == expected_digest
                    && image_reference == &format!("{}@{expected_digest}", active.oci.repository)
            }
            (ArtifactReference::HostBinary { sha256, .. }, RuntimeBackendKind::Systemd) => {
                sha256 == &active.artifacts["binary"].sha256
            }
            _ => false,
        };
        if !artifact_matches {
            bail!("updated runtime artifact differs from the signed coordinated Release");
        }
        observations.push(observation);
    }

    let active_release_path = active_release_path(config);
    let rollback_path = rollback_state_path(config);
    let evidence_path = store
        .deployment_state_dir(&record.deployment_id)
        .join("transactions")
        .join(&transaction.transaction_id)
        .join("config-backed-execution.json");
    crate::filesystem::ensure_directory_chain(
        evidence_path
            .parent()
            .context("config-backed update evidence path has no parent")?,
    )?;
    atomic_write(
        &evidence_path,
        &serde_json::to_vec_pretty(&ConfigBackedUpdateEvidence {
            schema: 1,
            deployment_id: &record.deployment_id,
            transaction_id: &transaction.transaction_id,
            target_release: &transaction.target_release,
            active_release_sha256: crate::filesystem::sha256(&active_release_path)?,
            rollback_state_sha256: crate::filesystem::sha256(&rollback_path)?,
            runtime_observations: &observations,
            verified_at: Utc::now().timestamp(),
        })?,
        0o600,
    )?;
    let evidence_sha256 = crate::filesystem::sha256(&evidence_path)?;

    let current_record = store.reload_locked(record)?;
    let current = crate::coordination::show_locked(store, &current_record)?;
    if current.transaction_id != transaction.transaction_id {
        bail!("active update transaction changed during config-backed execution");
    }
    for step in current.steps.clone() {
        if step.owner == StepOwner::CtlOwned
            && step.state == StepState::Pending
            && step.id != "acceptance"
        {
            crate::coordination::complete_controller_step_locked(
                store,
                &current_record,
                &transaction.transaction_id,
                &step.id,
                &evidence_sha256,
            )?;
        }
    }

    let mut updated = current_record.clone();
    updated.active_release = transaction.target_release.clone();
    for declared in &mut updated.runtime_instances {
        let observation = observations
            .iter()
            .find(|candidate| candidate.object_reference == declared.object_reference)
            .context("updated runtime observation disappeared before declaration commit")?;
        declared.artifact = observation.artifact.clone();
        declared.local_artifact_id = observation.local_artifact_id.clone();
    }
    updated.declaration_revision = current_record
        .declaration_revision
        .checked_add(1)
        .context("deployment declaration revision overflow")?;
    let current = crate::coordination::commit_controller_update_locked(
        store,
        &current_record,
        &updated,
        &transaction.transaction_id,
        "acceptance",
        &evidence_sha256,
    )?;
    crate::governance::append_management_audit(
        store,
        &updated,
        &transaction.transaction_id,
        "config-backed-update",
        &transaction.target_release.release,
    )?;
    crate::coordination::finalize_committed_locked(store, &updated, &transaction.transaction_id)?;
    Ok(current)
}

fn validate_config_backed_runtime_observation(
    declared: &crate::deployment::RuntimeInstance,
    observation: &crate::runtime_backend::RuntimeObservation,
) -> anyhow::Result<()> {
    if observation.backend != declared.backend
        || observation.object_reference != declared.object_reference
        || !observation.running
        || !observation.server_command_verified
    {
        bail!("updated runtime failed registered acceptance");
    }

    if matches!(
        declared.backend,
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker
    ) {
        if !observation.missing.is_empty() {
            bail!("updated container runtime has incomplete acceptance evidence");
        }

        let drift =
            crate::runtime_backend::compare_declared_runtime_surface(declared, observation)?;
        if drift.networks {
            bail!("updated container runtime network surface differs from the declaration");
        }
        if drift.mounts {
            bail!("updated container runtime mount surface differs from the declaration");
        }
        if drift.ports {
            bail!("updated container runtime published-port surface differs from the declaration");
        }
    } else if observation
        .missing
        .iter()
        .any(|item| item == "host binary digest could not be resolved")
    {
        bail!("updated systemd runtime binary digest is unavailable");
    }

    Ok(())
}

pub(crate) fn build_registered_update_plan(
    record: &DeploymentRecord,
    target: &ReleaseManifest,
) -> anyhow::Result<serde_json::Value> {
    crate::release::enforce_release_trust_floor(&record.active_release.release, target)?;
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
    let recovery_owner = owner(Capability::Backups, "backups");
    steps.push(json!({
        "id": "recovery-point",
        "owner": recovery_owner,
        "capability": "backups",
        "action": "create and verify a deployment-bound recovery point before writer shutdown",
        "evidence_required": true,
        "evidence_kind": external_evidence_kind(recovery_owner, "recovery-point"),
    }));
    let database_owner = owner(Capability::Database, "database");
    steps.push(json!({
        "id": "database-migration",
        "owner": database_owner,
        "capability": "database",
        "action": if operator_compatible {
            "apply the Release migration under the granted database and operator-task boundaries"
        } else {
            "blocked application task; do not infer migration compatibility"
        },
        "evidence_required": true,
        "evidence_kind": external_evidence_kind(database_owner, "provider-receipt"),
    }));
    for runtime in &record.runtime_instances {
        let runtime_owner = owner(Capability::Runtime, "runtime");
        steps.push(json!({
            "id": format!("runtime-replace-{}", runtime.runtime_instance_id),
            "owner": runtime_owner,
            "capability": "runtime",
            "runtime_instance_id": runtime.runtime_instance_id,
            "backend": runtime.backend,
            "object_reference": runtime.object_reference,
            "action": "replace this runtime instance with the digest-bound candidate and retain the previous trusted artifact",
            "evidence_required": true,
            "evidence_kind": external_evidence_kind(runtime_owner, "provider-receipt"),
        }));
    }
    let proxy_owner = owner(Capability::ProxyTls, "proxy_tls");
    steps.push(json!({
        "id": "proxy-cutover",
        "owner": proxy_owner,
        "capability": "proxy_tls",
        "action": "switch or verify the external routing and TLS boundary",
        "evidence_required": true,
        "evidence_kind": external_evidence_kind(proxy_owner, "routing-change"),
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
        "schema_compatible_rollback": target.rollback.schema_compatible,
        "database_restore": target.rollback.database_restore,
        "irreversible_migration_barrier": target.rollback.irreversible_migration,
        "migration_floor": target.rollback.migration_floor,
        "migration_rationale": target.rollback.rationale,
        "capabilities": &record.capabilities,
        "recovery": &record.recovery,
        "operator_protocol_compatible": operator_compatible,
        "core_recovery_requires_operator_task": false,
        "steps": steps,
        "blockers": blockers,
    }))
}

fn external_evidence_kind(owner: &str, provider_kind: &'static str) -> Option<&'static str> {
    match owner {
        "provider-owned" => Some(provider_kind),
        "user-required" => Some("operator-confirmation"),
        _ => None,
    }
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

#[cfg(test)]
mod config_backed_update_tests {
    use super::*;
    use std::{collections::BTreeMap, path::PathBuf};

    fn declared_runtime() -> crate::deployment::RuntimeInstance {
        crate::deployment::RuntimeInstance {
            runtime_instance_id: "runtime-1".to_owned(),
            backend: RuntimeBackendKind::Podman,
            object_reference: "nazoauth-server".to_owned(),
            artifact: crate::deployment::ArtifactReference::Unknown,
            local_artifact_id: None,
            ports: vec!["127.0.0.1:8000:8000".to_owned()],
            networks: vec!["nazoauth".to_owned()],
            mounts: vec![crate::deployment::MountReference {
                source: PathBuf::from("/srv/nazoauth/data"),
                destination: PathBuf::from("/var/lib/nazo_oauth"),
                read_only: false,
                selinux_relabel: true,
                scope: crate::deployment::ResourceScope::Deployment,
                ownership: Responsibility::Managed,
            }],
            instance_key_id: None,
            deployment_statement: None,
        }
    }

    fn observed_runtime() -> crate::runtime_backend::RuntimeObservation {
        crate::runtime_backend::RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: "nazoauth-server".to_owned(),
            display_name: "nazoauth-server".to_owned(),
            running: true,
            server_command_verified: true,
            artifact: crate::deployment::ArtifactReference::Unknown,
            local_artifact_id: None,
            ports: vec!["127.0.0.1:8000->8000/tcp".to_owned()],
            networks: vec!["nazoauth".to_owned()],
            mounts: vec![crate::runtime_backend::NeutralMount {
                source: PathBuf::from("/srv/nazoauth/data"),
                destination: PathBuf::from("/var/lib/nazo_oauth"),
                read_only: false,
                // Podman applies :Z at creation but does not retain it in the
                // inspect Mounts Options surface.
                selinux_relabel: false,
                scope: crate::deployment::ResourceScope::Deployment,
                // Governance responsibility is not inferable from Podman
                // inspect and is therefore reported as external.
                ownership: Responsibility::External,
            }],
            safe_environment: BTreeMap::new(),
            labels: BTreeMap::new(),
            evidence: vec!["runtime inspected".to_owned()],
            missing: Vec::new(),
        }
    }

    #[test]
    fn config_backed_acceptance_requires_the_declared_runtime_surface() {
        validate_config_backed_runtime_observation(&declared_runtime(), &observed_runtime())
            .unwrap();

        let mut drifted = observed_runtime();
        drifted.networks = vec!["unexpected".to_owned()];
        let error =
            validate_config_backed_runtime_observation(&declared_runtime(), &drifted).unwrap_err();
        assert!(error.to_string().contains("network surface"));

        let mut drifted = observed_runtime();
        drifted.ports = vec!["127.0.0.1:9000->8000/tcp".to_owned()];
        let error =
            validate_config_backed_runtime_observation(&declared_runtime(), &drifted).unwrap_err();
        assert!(error.to_string().contains("published-port surface"));

        let mut drifted = observed_runtime();
        drifted.mounts[0].read_only = true;
        let error =
            validate_config_backed_runtime_observation(&declared_runtime(), &drifted).unwrap_err();
        assert!(error.to_string().contains("mount surface"));
    }

    #[test]
    fn config_backed_acceptance_rejects_incomplete_container_evidence() {
        let mut incomplete = observed_runtime();
        incomplete
            .missing
            .push("trusted OCI digest could not be resolved".to_owned());
        let error = validate_config_backed_runtime_observation(&declared_runtime(), &incomplete)
            .unwrap_err();
        assert!(error.to_string().contains("incomplete acceptance evidence"));
    }
}
