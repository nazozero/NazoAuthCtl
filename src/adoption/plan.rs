use super::*;

pub(super) fn build_plan(
    candidate: &DiscoveredDeployment,
    replicas: &[DiscoveredDeployment],
    options: &AdoptionOptions,
) -> anyhow::Result<AdoptionPlan> {
    options.capabilities.validate()?;
    let deployment_id = candidate
        .deployment_id
        .clone()
        .context("target has no verified NazoAuth deployment identity")?;
    let runtime_instance_id = candidate
        .runtime_instance_id
        .clone()
        .context("target has no verified runtime instance identity")?;
    let issuer = candidate
        .issuer
        .clone()
        .context("target has no signed issuer identity")?;
    let release_name = candidate
        .release
        .clone()
        .context("target has no signed release identity")?;
    if candidate.online_statement.is_none() && candidate.offline_statement.is_none() {
        bail!("target has no verified online or offline deployment statement");
    }
    let verified = verified_release(candidate, &release_name)?;
    let artifact_identity = verify_artifact(candidate, &verified)?;
    if verified.manifest.embedded.release != release_name
        || Some(&verified.manifest.embedded.revision) != candidate.revision.as_ref()
        || Some(&verified.manifest.embedded.build_id) != candidate.build_id.as_ref()
    {
        bail!("signed instance build identity does not match the trusted Release");
    }
    let mut blockers = Vec::new();
    let mut runtime_instances = Vec::new();
    let mut runtime_ids = std::collections::BTreeSet::new();
    for replica in replicas {
        let Some(replica_id) = replica.runtime_instance_id.clone() else {
            blockers.push(format!(
                "replica {} has no verified runtime identity",
                replica.target
            ));
            continue;
        };
        if !runtime_ids.insert(replica_id.clone()) {
            blockers.push(format!(
                "runtime instance identity {replica_id} is duplicated"
            ));
            continue;
        }
        if replica.issuer.as_deref() != Some(issuer.as_str())
            || replica.online_statement.is_none() && replica.offline_statement.is_none()
        {
            blockers.push(format!(
                "replica {} does not prove the selected deployment issuer",
                replica.target
            ));
            continue;
        }
        let artifact = if replica.release.as_deref() == Some(&release_name)
            && replica.revision.as_deref() == Some(verified.manifest.embedded.revision.as_str())
            && replica.build_id.as_deref() == Some(verified.manifest.embedded.build_id.as_str())
        {
            verify_artifact(replica, &verified)?
        } else {
            blockers.push(format!(
                "replica {} runs a different or untrusted Release identity",
                replica.target
            ));
            "unverified-mixed-release".to_owned()
        };
        runtime_instances.push(AdoptedRuntimeIdentity {
            runtime_instance_id: replica_id,
            backend: backend_name(replica.runtime.backend).to_owned(),
            object_reference: replica.runtime.object_reference.clone(),
            artifact_identity: artifact,
        });
    }
    if runtime_instances.is_empty() {
        blockers.push("deployment has no independently verified runtime instances".to_owned());
    }
    let recovery = recovery_assessment(
        candidate,
        &deployment_id,
        &release_name,
        options.recovery_evidence.as_deref(),
    )?;
    if let Some(lifecycle_path) = options.lifecycle_contract.as_deref() {
        let lifecycle = LifecycleManifest::load(lifecycle_path)?;
        if lifecycle.deployment_id != deployment_id {
            bail!("lifecycle contract is bound to a different deployment");
        }
        lifecycle.validate_for_adoption(replicas, &options.capabilities)?;
        if options.recovery_evidence.is_none() {
            blockers.push("lifecycle recovery rehearsal requires --recovery-evidence".to_owned());
        }
    }
    let mutation_requested = Capability::ALL.iter().any(|capability| {
        options
            .capabilities
            .grant(*capability)
            .responsibility
            .permits_mutation()
    });
    if recovery.conclusion != RecoveryConclusion::Proven {
        blockers.push(RECOVERY_UNPROVEN_BLOCKER.to_owned());
    }
    if mutation_requested && recovery.conclusion != RecoveryConclusion::Proven {
        blockers.push(RECOVERY_CAPABILITY_BLOCKER.to_owned());
    }
    if options
        .capabilities
        .database
        .responsibility
        .permits_mutation()
        && candidate.external_database
    {
        blockers.push(
            "external database cannot be adopted without provider-specific evidence".to_owned(),
        );
    }
    if options
        .capabilities
        .valkey
        .responsibility
        .permits_mutation()
        && candidate.external_valkey
    {
        blockers.push(
            "external Valkey cannot be adopted without provider-specific evidence".to_owned(),
        );
    }
    if options
        .capabilities
        .runtime
        .responsibility
        .permits_mutation()
    {
        blockers.push(
            "mutable runtime authority requires exact deployment, runtime-instance, and control-authority ownership evidence"
                .to_owned(),
        );
    }
    if options
        .capabilities
        .operator_tasks
        .responsibility
        .permits_mutation()
    {
        blockers.push(
            "operator-task authority requires a separately verified server-side controller enrollment"
                .to_owned(),
        );
    }
    let resulting_trust = if blockers.is_empty() {
        TrustState::Adopted
    } else {
        TrustState::Observed
    };
    let capabilities = if resulting_trust == TrustState::Observed {
        CapabilityGrants::observed()
    } else {
        options.capabilities.clone()
    };
    let mut steps = vec![
        AdoptionStep {
            owner: StepOwner::Controller,
            action: "verify signed instance identity and nonce/offline binding".to_owned(),
            evidence: candidate.instance_key_id.clone().unwrap_or_default(),
        },
        AdoptionStep {
            owner: StepOwner::Controller,
            action: "verify Release attestation and exact runtime artifact".to_owned(),
            evidence: artifact_identity.clone(),
        },
    ];
    if let Some(path) = &options.recovery_evidence {
        steps.push(AdoptionStep {
            owner: StepOwner::User,
            action: "provide an independently restorable recovery package".to_owned(),
            evidence: format!("manifest-sha256:{}", sha256(path)?),
        });
    } else {
        steps.push(AdoptionStep {
            owner: StepOwner::User,
            action: "provide verifiable recovery evidence before mutation is authorized".to_owned(),
            evidence: "pending".to_owned(),
        });
    }
    steps.push(AdoptionStep {
        owner: StepOwner::Controller,
        action: "create deployment-isolated controller, receipt, audit and break-glass identities"
            .to_owned(),
        evidence: "created only during --yes after all prerequisites pass".to_owned(),
    });
    Ok(AdoptionPlan {
        schema: 1,
        target: candidate.target.clone(),
        deployment_id,
        runtime_instance_id,
        issuer,
        release: release_name,
        active_release: verified.manifest.embedded.clone(),
        artifact_identity,
        runtime_instances,
        resulting_trust,
        requested_capabilities: options.capabilities.clone(),
        capabilities,
        recovery,
        steps,
        blockers,
    })
}

pub(super) fn apply_recovery_rehearsal(
    plan: &mut AdoptionPlan,
    receipt: &RecoveryDriverReceipt,
) -> anyhow::Result<()> {
    if receipt.operation != RecoveryOperation::Rehearse
        || receipt.deployment_id != plan.deployment_id
        || receipt.release != plan.release
    {
        bail!("recovery rehearsal receipt is bound to a different adoption plan");
    }
    let digest = hex_sha256(&serde_json::to_vec(receipt)?);
    plan.recovery.conclusion = RecoveryConclusion::Proven;
    plan.recovery
        .evidence
        .push(format!("recovery-rehearsal-receipt-sha256:{digest}"));
    plan.blockers.retain(|blocker| {
        blocker != RECOVERY_UNPROVEN_BLOCKER && blocker != RECOVERY_CAPABILITY_BLOCKER
    });
    if plan.blockers.is_empty() {
        plan.resulting_trust = TrustState::Adopted;
        plan.capabilities = plan.requested_capabilities.clone();
    }
    Ok(())
}

pub(super) fn verified_release(
    candidate: &DiscoveredDeployment,
    release: &str,
) -> anyhow::Result<VerifiedRelease> {
    let backend = (candidate.runtime.backend != crate::deployment::RuntimeBackendKind::Systemd)
        .then_some(candidate.runtime.backend);
    VerifiedRelease::fetch(SERVER_REPOSITORY, Some(release), backend)
}

pub(super) fn verify_artifact(
    candidate: &DiscoveredDeployment,
    release: &VerifiedRelease,
) -> anyhow::Result<String> {
    match &candidate.runtime.artifact {
        ArtifactReference::Oci { digest, .. } => {
            if digest != release.manifest.image_oci_digest() {
                bail!("discovered OCI digest does not match the trusted Release");
            }
            Ok(digest.clone())
        }
        ArtifactReference::HostBinary {
            path,
            sha256: actual,
        } => {
            let signed = release.artifact("binary", SERVER_REPOSITORY)?;
            let expected = sha256(&signed)?;
            if actual != &expected || sha256(path)? != expected {
                bail!("discovered host binary does not match the trusted Release");
            }
            Ok(format!("sha256:{expected}"))
        }
        ArtifactReference::Unknown => bail!("discovered runtime artifact is not immutable"),
    }
}

pub(super) fn recovery_assessment(
    candidate: &DiscoveredDeployment,
    deployment_id: &str,
    release: &str,
    evidence: Option<&Path>,
) -> anyhow::Result<RecoveryAssessment> {
    let mut proof = candidate.evidence.clone();
    let conclusion = if let Some(path) = evidence {
        let manifest = verify_recovery_evidence(path, deployment_id, release)?;
        proof.push(format!("recovery-manifest-sha256:{}", sha256(path)?));
        for (name, artifact) in recovery_artifacts(&manifest) {
            proof.push(format!("{name}-sha256:{}", artifact.sha256));
        }
        // Integrity and off-host placement are necessary but do not prove that
        // database, data, artifact, and provider recovery steps are executable.
        RecoveryConclusion::RequiresUserEvidence
    } else {
        candidate.recovery_conclusion.clone()
    };
    Ok(RecoveryAssessment {
        conclusion,
        evidence: proof,
        off_host_package_required_for_machine_loss: true,
    })
}

pub(super) fn verify_recovery_evidence(
    path: &Path,
    deployment_id: &str,
    release: &str,
) -> anyhow::Result<RecoveryEvidenceManifest> {
    let metadata = fs::symlink_metadata(path)
        .context("failed to inspect supplied recovery evidence manifest")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        bail!("recovery evidence manifest must be a bounded regular file");
    }
    let manifest: RecoveryEvidenceManifest = serde_json::from_slice(&fs::read(path)?)
        .context("recovery evidence manifest is invalid")?;
    if manifest.schema != 1
        || manifest.deployment_id != deployment_id
        || manifest.release != release
        || !manifest.off_host_package_confirmed
    {
        bail!("recovery evidence is not bound to this deployment, release, and off-host boundary");
    }
    for (_, artifact) in recovery_artifacts(&manifest) {
        let metadata = fs::symlink_metadata(&artifact.path).with_context(|| {
            format!(
                "failed to inspect recovery artifact {}",
                artifact.path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            bail!("recovery artifact must be a non-empty regular file");
        }
        if sha256(&artifact.path)? != artifact.sha256 {
            bail!("recovery artifact digest does not match its manifest");
        }
    }
    Ok(manifest)
}

fn recovery_artifacts(
    manifest: &RecoveryEvidenceManifest,
) -> [(&'static str, &RecoveryArtifact); 4] {
    [
        ("data-snapshot", &manifest.data_snapshot),
        ("database-restore", &manifest.database_restore),
        ("last-trusted-artifact", &manifest.last_trusted_artifact),
        ("verification-material", &manifest.verification_material),
    ]
}

pub(super) fn receipt_resource_references(
    candidates: &[DiscoveredDeployment],
) -> BTreeMap<String, String> {
    let mut references = BTreeMap::new();
    for (runtime_index, candidate) in candidates.iter().enumerate() {
        references.insert(
            format!("runtime-{runtime_index}-object"),
            format!(
                "{}:{}",
                backend_name(candidate.runtime.backend),
                candidate.runtime.object_reference
            ),
        );
        for (mount_index, mount) in candidate.runtime.mounts.iter().enumerate() {
            if !mount.source.to_string_lossy().contains("redacted") {
                references.insert(
                    format!("runtime-{runtime_index}-mount-{mount_index}"),
                    mount.source.display().to_string(),
                );
            }
        }
    }
    references
}

pub(super) fn receipt_capabilities(capabilities: &CapabilityGrants) -> BTreeMap<String, String> {
    Capability::ALL
        .into_iter()
        .map(|capability| {
            let responsibility = match capabilities.grant(capability).responsibility {
                Responsibility::External => "external",
                Responsibility::Delegated => "delegated",
                Responsibility::Managed => "managed",
            };
            (capability.name().to_owned(), responsibility.to_owned())
        })
        .collect()
}

pub(super) fn backend_name(backend: crate::deployment::RuntimeBackendKind) -> &'static str {
    match backend {
        crate::deployment::RuntimeBackendKind::Podman => "podman",
        crate::deployment::RuntimeBackendKind::Docker => "docker",
        crate::deployment::RuntimeBackendKind::Systemd => "systemd",
    }
}

pub(super) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
