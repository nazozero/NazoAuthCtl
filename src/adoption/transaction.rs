use super::*;

pub(super) fn persist_lifecycle_contract(
    store: &DeploymentStore,
    plan: &AdoptionPlan,
    source: Option<&Path>,
    rehearsal_receipt: Option<&RecoveryDriverReceipt>,
    recovery_evidence: &mut Vec<String>,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(source) = source else {
        if rehearsal_receipt.is_some() {
            bail!("recovery rehearsal has no lifecycle contract");
        }
        return Ok(None);
    };
    let directory = store
        .deployment_state_dir(&plan.deployment_id)
        .join("recovery")
        .join("adoption");
    fs::create_dir_all(&directory)?;
    let target = directory.join("lifecycle.json");
    copy_atomic(source, &target, 0o600)?;
    let lifecycle_digest = sha256(&target)?;
    if lifecycle_digest != LifecycleManifest::digest(source)? {
        bail!("persisted lifecycle contract changed during adoption");
    }
    recovery_evidence.push(format!("lifecycle-sha256:{lifecycle_digest}"));
    if let Some(receipt) = rehearsal_receipt {
        let receipt_path = directory.join("recovery-rehearsal-receipt.json");
        atomic_write(&receipt_path, &serde_json::to_vec_pretty(receipt)?, 0o600)?;
        recovery_evidence.push(format!(
            "recovery-rehearsal-receipt-sha256:{}",
            sha256(&receipt_path)?
        ));
    }
    Ok(Some(target))
}

pub(super) fn execute(
    candidates: &[DiscoveredDeployment],
    plan: &AdoptionPlan,
    options: &AdoptionOptions,
    rehearsal_receipt: Option<&RecoveryDriverReceipt>,
) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&plan.deployment_id)?;
    let transaction_dir = store
        .deployment_state_dir(&plan.deployment_id)
        .join("transactions");
    fs::create_dir_all(&transaction_dir)?;
    let transaction_path = transaction_dir.join("adoption.json");
    let plan_sha256 = hex_sha256(&serde_json::to_vec(plan)?);
    let lifecycle_sha256 = options
        .lifecycle_contract
        .as_deref()
        .map(LifecycleManifest::digest)
        .transpose()?;
    if transaction_path.exists() {
        let transaction: AdoptionTransaction =
            serde_json::from_slice(&fs::read(&transaction_path)?)
                .context("adoption transaction is invalid")?;
        if transaction.schema != 1
            || transaction.plan_sha256 != plan_sha256
            || transaction.lifecycle_sha256 != lifecycle_sha256
        {
            bail!("an existing adoption transaction is bound to a different plan");
        }
        if transaction.state == AdoptionTransactionState::Committed {
            let record = store.load(&plan.deployment_id)?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            return Ok(());
        }
    } else {
        atomic_write(
            &transaction_path,
            &serde_json::to_vec_pretty(&AdoptionTransaction {
                schema: 1,
                state: AdoptionTransactionState::Prepared,
                plan_sha256: plan_sha256.clone(),
                lifecycle_sha256: lifecycle_sha256.clone(),
            })?,
            0o600,
        )?;
    }
    let identities = create_identities(&store, &plan.deployment_id)?;
    let mut recovery_evidence = if let Some(source) = &options.recovery_evidence {
        persist_recovery_evidence(&store, plan, source)?
    } else {
        Vec::new()
    };
    let lifecycle_path = persist_lifecycle_contract(
        &store,
        plan,
        options.lifecycle_contract.as_deref(),
        rehearsal_receipt,
        &mut recovery_evidence,
    )?;
    let observed_state = store
        .deployment_state_dir(&plan.deployment_id)
        .join("observed-state.json");
    atomic_write(
        &observed_state,
        &serde_json::to_vec_pretty(candidates)?,
        0o600,
    )?;
    let mut record = deployment_record(
        candidates,
        plan,
        options.alias.clone(),
        &identities.controller_key_id,
    )?;
    if let Some(path) = lifecycle_path {
        let lifecycle_sha256 = sha256(&path)?;
        record.resources.insert(
            "lifecycle_contract".to_owned(),
            SafeReference::DigestBoundFile {
                path,
                sha256: lifecycle_sha256,
            },
        );
        record.validate()?;
    }
    let primary = candidates
        .iter()
        .find(|candidate| candidate.target == plan.target)
        .context("selected adoption target disappeared from the replica set")?;
    let verified = verified_release(primary, &plan.release)?;
    let release_evidence = store
        .deployment_state_dir(&plan.deployment_id)
        .join("recovery")
        .join("trusted-releases")
        .join(&plan.release);
    verified.persist_verification_evidence(&release_evidence)?;
    if record.trust == TrustState::Adopted && record.resources.contains_key("lifecycle_contract") {
        crate::lifecycle::cache_trusted_runtime(&store, &record)?;
    }
    let manifest = verified.manifest;
    let receipt = AdoptionReceipt {
        schema: CONTROL_DISCOVERY_SCHEMA,
        deployment_id: plan.deployment_id.clone(),
        issuer: plan.issuer.clone(),
        runtime_instances: plan.runtime_instances.clone(),
        verified_release: plan.release.clone(),
        release_manifest_sha256: hex_sha256(&serde_json::to_vec(&manifest)?),
        instance_key_ids: candidates
            .iter()
            .filter_map(|candidate| candidate.instance_key_id.clone())
            .collect(),
        resource_references: receipt_resource_references(candidates),
        capabilities: receipt_capabilities(&plan.capabilities),
        recovery_proven: plan.recovery.conclusion == RecoveryConclusion::Proven,
        recovery_evidence,
        plan_sha256: plan_sha256.clone(),
        adopted_at: Utc::now().timestamp(),
    };
    let compact = sign_adoption_receipt(&receipt, &identities.receipt_key_id, &identities.receipt)?;
    atomic_write(
        &store
            .deployment_state_dir(&plan.deployment_id)
            .join("adoption-receipt.jws"),
        compact.as_bytes(),
        0o600,
    )?;
    initialize_audit(&store, &record, &identities.audit)?;
    store.persist_locked(&record)?;
    atomic_write(
        &transaction_path,
        &serde_json::to_vec_pretty(&AdoptionTransaction {
            schema: 1,
            state: AdoptionTransactionState::Committed,
            plan_sha256,
            lifecycle_sha256,
        })?,
        0o600,
    )?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

pub(crate) fn persist_recovery_evidence(
    store: &DeploymentStore,
    plan: &AdoptionPlan,
    manifest_path: &Path,
) -> anyhow::Result<Vec<String>> {
    let directory = store
        .deployment_state_dir(&plan.deployment_id)
        .join("recovery")
        .join("adoption");
    persist_bound_recovery_package(
        manifest_path,
        &plan.deployment_id,
        &plan.release,
        &directory,
    )
}

pub(crate) fn persist_bound_recovery_package(
    manifest_path: &Path,
    deployment_id: &str,
    release: &str,
    directory: &Path,
) -> anyhow::Result<Vec<String>> {
    let mut manifest = verify_recovery_evidence(manifest_path, deployment_id, release)?;
    fs::create_dir_all(directory)?;
    let evidence = vec![
        persist_recovery_artifact(directory, "data-snapshot", &mut manifest.data_snapshot)?,
        persist_recovery_artifact(
            directory,
            "database-restore",
            &mut manifest.database_restore,
        )?,
        persist_recovery_artifact(
            directory,
            "last-trusted-artifact",
            &mut manifest.last_trusted_artifact,
        )?,
        persist_recovery_artifact(
            directory,
            "verification-material",
            &mut manifest.verification_material,
        )?,
    ];
    atomic_write(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
        0o600,
    )?;
    Ok(evidence)
}

fn persist_recovery_artifact(
    directory: &Path,
    name: &str,
    artifact: &mut RecoveryArtifact,
) -> anyhow::Result<String> {
    let target = directory.join(name);
    copy_atomic(&artifact.path, &target, 0o600)?;
    let actual = sha256(&target)?;
    if actual != artifact.sha256 {
        bail!("persisted recovery artifact changed during adoption");
    }
    artifact.path = target;
    Ok(format!("{name}-sha256:{actual}"))
}

pub(super) fn deployment_record(
    candidates: &[DiscoveredDeployment],
    plan: &AdoptionPlan,
    alias: Option<String>,
    control_authority: &str,
) -> anyhow::Result<DeploymentRecord> {
    let resources = BTreeMap::from([
        (
            "audit_private_key".to_owned(),
            SafeReference::File {
                path: DeploymentStore::system()
                    .deployment_state_dir(&plan.deployment_id)
                    .join("identities")
                    .join("audit.key"),
            },
        ),
        (
            "break_glass_private_key".to_owned(),
            SafeReference::File {
                path: DeploymentStore::system()
                    .break_glass_dir(&plan.deployment_id)
                    .join("break-glass.key"),
            },
        ),
        ("database".to_owned(), SafeReference::NotObserved),
        ("valkey".to_owned(), SafeReference::NotObserved),
        ("proxy_tls".to_owned(), SafeReference::NotObserved),
    ]);
    let runtime_instances = candidates
        .iter()
        .map(|candidate| {
            let runtime_instance_id = candidate
                .runtime_instance_id
                .clone()
                .context("adopted replica has no runtime instance identity")?;
            let mounts = candidate
                .runtime
                .mounts
                .iter()
                .map(|mount| MountReference {
                    source: mount.source.clone(),
                    destination: mount.destination.clone(),
                    read_only: mount.read_only,
                    selinux_relabel: mount.selinux_relabel,
                    scope: mount.scope,
                    ownership: mount.ownership,
                })
                .collect();
            Ok(RuntimeInstance {
                runtime_instance_id,
                backend: candidate.runtime.backend,
                object_reference: candidate.runtime.object_reference.clone(),
                artifact: candidate.runtime.artifact.clone(),
                local_artifact_id: candidate.runtime.local_artifact_id.clone(),
                ports: candidate.runtime.ports.clone(),
                networks: candidate.runtime.networks.clone(),
                mounts,
                instance_key_id: candidate.instance_key_id.clone(),
                deployment_statement: deployment_statement_path(candidate),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let primary = candidates
        .iter()
        .find(|candidate| candidate.target == plan.target)
        .context("selected adoption target is not present")?;
    let record = DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: plan.deployment_id.clone(),
        control_authority: control_authority.to_owned(),
        alias,
        issuer: plan.issuer.clone(),
        active_release: plan.active_release.clone(),
        trust: plan.resulting_trust,
        capabilities: plan.capabilities.clone(),
        runtime_instances,
        resources,
        recovery: plan.recovery.clone(),
        operator_protocol_versions: primary.operator_protocol_versions.iter().copied().collect(),
        control_protocol_versions: primary.control_protocol_versions.iter().copied().collect(),
        declaration_revision: 1,
    };
    record.validate()?;
    Ok(record)
}
