use super::*;

use fs2::FileExt as _;
use std::collections::BTreeSet;
use std::io::Write as _;

fn validate_lower_hex(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("SHA-256 digest must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_file_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .with_context(|| format!("{label} is invalid"))
}

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
    if !plan
        .recovery
        .evidence
        .iter()
        .any(|evidence| evidence.starts_with("provider-attestation-verified:"))
    {
        bail!("recovery rehearsal requires an independently verified provider attestation");
    }
    if !plan
        .recovery
        .evidence
        .iter()
        .any(|evidence| evidence == "independent-runtime-readiness-and-discovery-observed")
    {
        bail!("recovery rehearsal requires independent readiness and discovery observations");
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
    // Adoption verifies the exact Release the target reports; the floor pins
    // that same version so a downgrade claim can never verify.
    VerifiedRelease::verify(crate::release::ReleaseRequest {
        repository: SERVER_REPOSITORY,
        requested_version: Some(release),
        container_backend: backend,
        trusted_version_floor: Some(release),
    })
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
    if candidate.oidc_discovery_verified && candidate.readiness_observed {
        proof.push("independent-runtime-readiness-and-discovery-observed".to_owned());
    }
    let conclusion = if let Some(path) = evidence {
        let manifest = verify_recovery_evidence(path, deployment_id, release)?;
        proof.push(format!("recovery-manifest-sha256:{}", sha256(path)?));
        for (name, _, artifact) in recovery_artifacts(&manifest) {
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
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "supplied recovery evidence manifest",
        false,
        MAX_RECOVERY_EVIDENCE_BYTES,
    )?;
    if bytes.is_empty() {
        bail!("recovery evidence manifest must be non-empty");
    }
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).context("recovery evidence manifest is invalid")?;
    if document.get("schema").and_then(serde_json::Value::as_u64)
        != Some(u64::from(RECOVERY_EVIDENCE_SCHEMA))
    {
        bail!("unsupported recovery evidence schema; migrate to schema 2");
    }
    let manifest: RecoveryEvidenceManifest =
        serde_json::from_value(document).context("recovery evidence manifest is invalid")?;
    if manifest.deployment_id != deployment_id || manifest.release != release {
        bail!("recovery evidence is not bound to this deployment and release");
    }
    let mut canonical_paths = BTreeSet::new();
    for (name, role, artifact) in recovery_artifacts(&manifest) {
        if artifact.role != role {
            bail!("recovery artifact {name} has the wrong role");
        }
        validate_recovery_artifact(artifact, role, &mut canonical_paths)?;
    }
    validate_provider_attestation_shape(&manifest)?;
    Ok(manifest)
}

pub(super) fn recovery_artifacts(
    manifest: &RecoveryEvidenceManifest,
) -> [(&'static str, RecoveryArtifactRole, &RecoveryArtifact); 4] {
    [
        (
            "data-snapshot",
            RecoveryArtifactRole::DataSnapshot,
            &manifest.data_snapshot,
        ),
        (
            "database-restore",
            RecoveryArtifactRole::DatabaseRestore,
            &manifest.database_restore,
        ),
        (
            "last-trusted-artifact",
            RecoveryArtifactRole::LastTrustedArtifact,
            &manifest.last_trusted_artifact,
        ),
        (
            "verification-material",
            RecoveryArtifactRole::VerificationMaterial,
            &manifest.verification_material,
        ),
    ]
}

fn validate_recovery_artifact(
    artifact: &RecoveryArtifact,
    expected_role: RecoveryArtifactRole,
    canonical_paths: &mut BTreeSet<String>,
) -> anyhow::Result<()> {
    validate_recovery_path(&artifact.path)?;
    let canonical = fs::canonicalize(&artifact.path).with_context(|| {
        format!(
            "failed to canonicalize recovery artifact {}",
            artifact.path.display()
        )
    })?;
    if !canonical_paths.insert(canonical.display().to_string()) {
        bail!("recovery artifact paths must be distinct canonical files");
    }
    let max_bytes = recovery_artifact_max_bytes(&expected_role);
    if artifact.size == 0 || artifact.size > max_bytes {
        bail!(
            "recovery artifact {} size is outside its role boundary",
            artifact.path.display()
        );
    }
    if artifact.content_type != recovery_artifact_content_type(&expected_role) {
        bail!(
            "recovery artifact {} has an invalid role-specific content type",
            artifact.path.display()
        );
    }
    validate_lower_hex(&artifact.sha256)?;
    let bytes = crate::filesystem::read_secure_regular_file(
        &artifact.path,
        "recovery artifact",
        false,
        max_bytes,
    )?;
    if bytes.len() as u64 != artifact.size {
        bail!("recovery artifact size does not match its descriptor");
    }
    if hex_sha256(&bytes) != artifact.sha256 {
        bail!("recovery artifact digest does not match its descriptor");
    }
    validate_recovery_artifact_content(&expected_role, &bytes)?;
    Ok(())
}

fn validate_recovery_path(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("recovery artifact path must be a normalized absolute non-root path");
    }
    Ok(())
}

fn recovery_artifact_max_bytes(role: &RecoveryArtifactRole) -> u64 {
    match role {
        RecoveryArtifactRole::DataSnapshot | RecoveryArtifactRole::DatabaseRestore => {
            MAX_RECOVERY_ARTIFACT_BYTES
        }
        RecoveryArtifactRole::LastTrustedArtifact => 512 * 1024 * 1024,
        RecoveryArtifactRole::VerificationMaterial => 16 * 1024 * 1024,
    }
}

pub(super) fn recovery_artifact_content_type(role: &RecoveryArtifactRole) -> &'static str {
    match role {
        RecoveryArtifactRole::DataSnapshot => "application/vnd.nazoauth.data-snapshot",
        RecoveryArtifactRole::DatabaseRestore => "application/vnd.nazoauth.database-restore",
        RecoveryArtifactRole::LastTrustedArtifact => "application/vnd.nazoauth.release-artifact",
        RecoveryArtifactRole::VerificationMaterial => {
            "application/vnd.nazoauth.verification-material"
        }
    }
}

fn validate_recovery_artifact_content(
    role: &RecoveryArtifactRole,
    bytes: &[u8],
) -> anyhow::Result<()> {
    match role {
        RecoveryArtifactRole::DataSnapshot | RecoveryArtifactRole::LastTrustedArtifact => Ok(()),
        RecoveryArtifactRole::DatabaseRestore => {
            let text = std::str::from_utf8(bytes)
                .context("database recovery artifact is not valid UTF-8")?;
            if text.trim().is_empty()
                || !["CREATE", "INSERT", "BEGIN", "COPY", "ALTER"]
                    .iter()
                    .any(|marker| text.to_ascii_uppercase().contains(marker))
            {
                bail!("database recovery artifact does not contain a recognized SQL payload");
            }
            Ok(())
        }
        RecoveryArtifactRole::VerificationMaterial => {
            let text =
                std::str::from_utf8(bytes).context("verification material is not valid UTF-8")?;
            let trimmed = text.trim_start();
            if !(trimmed.starts_with('{')
                || trimmed.starts_with('[')
                || trimmed.contains("-----BEGIN"))
            {
                bail!("verification material is neither JSON nor PEM content");
            }
            Ok(())
        }
    }
}

fn validate_provider_attestation_shape(manifest: &RecoveryEvidenceManifest) -> anyhow::Result<()> {
    let attestation = &manifest.provider_attestation;
    if attestation.schema != PROVIDER_ATTESTATION_SCHEMA
        || attestation.deployment_id != manifest.deployment_id
        || attestation.release != manifest.release
    {
        bail!("provider recovery attestation is not bound to the manifest deployment and release");
    }
    validate_file_identifier(&attestation.provider_id, "recovery provider ID")?;
    validate_lower_hex(&attestation.manifest_sha256)?;
    validate_lower_hex(&attestation.lifecycle_sha256)?;
    if attestation.manifest_sha256 != canonical_manifest_digest(manifest)? {
        bail!(
            "provider recovery attestation manifest digest does not match the artifact descriptors"
        );
    }
    validate_provider_time(attestation.issued_at, attestation.expires_at)?;
    if attestation.nonce.len() < 16
        || attestation.nonce.len() > 128
        || !attestation
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        bail!("provider recovery attestation nonce is invalid");
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&attestation.signature)
        .context("provider recovery attestation signature is not base64url")?;
    if signature.len() != 64 {
        bail!("provider recovery attestation signature has an invalid length");
    }
    let mut roles = BTreeSet::new();
    for artifact in &attestation.artifacts {
        if !roles.insert(artifact.role.clone()) {
            bail!("provider recovery attestation contains a duplicate artifact role");
        }
        validate_lower_hex(&artifact.sha256)?;
        if artifact.size == 0 || artifact.size > MAX_RECOVERY_ARTIFACT_BYTES {
            bail!("provider recovery attestation artifact size is invalid");
        }
    }
    let expected = recovery_artifacts(manifest)
        .into_iter()
        .map(|(_, role, artifact)| ProviderArtifactReceipt {
            role,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
            content_type: artifact.content_type.clone(),
        })
        .collect::<Vec<_>>();
    if attestation.artifacts != expected {
        bail!("provider recovery attestation does not cover every role and digest exactly");
    }
    Ok(())
}

pub(super) fn canonical_manifest_digest(
    manifest: &RecoveryEvidenceManifest,
) -> anyhow::Result<String> {
    let artifacts = recovery_artifacts(manifest)
        .into_iter()
        .map(|(_, role, artifact)| ProviderArtifactReceipt {
            role,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
            content_type: artifact.content_type.clone(),
        })
        .collect::<Vec<_>>();
    Ok(hex_sha256(&serde_json::to_vec(&(
        RECOVERY_EVIDENCE_SCHEMA,
        &manifest.deployment_id,
        &manifest.release,
        artifacts,
    ))?))
}

fn validate_provider_time(issued_at: i64, expires_at: i64) -> anyhow::Result<()> {
    let now = Utc::now().timestamp();
    if issued_at <= 0
        || expires_at <= issued_at
        || issued_at > now.saturating_add(MAX_PROVIDER_CLOCK_SKEW_SECONDS)
        || issued_at < now.saturating_sub(MAX_PROVIDER_ATTESTATION_AGE_SECONDS)
        || expires_at > issued_at.saturating_add(MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS)
        || expires_at <= now
    {
        bail!("provider recovery attestation is stale, premature, or exceeds its lifetime");
    }
    Ok(())
}

pub(crate) fn verify_provider_attestation(
    manifest_path: &Path,
    lifecycle: &LifecycleManifest,
    deployment_id: &str,
    release: &str,
    lifecycle_sha256: &str,
    operation: RecoveryOperation,
    consume_nonce: bool,
) -> anyhow::Result<String> {
    let manifest = verify_recovery_evidence(manifest_path, deployment_id, release)?;
    let attestation = &manifest.provider_attestation;
    let provider = lifecycle
        .recovery_providers
        .iter()
        .find(|provider| provider.provider_id == attestation.provider_id)
        .context("lifecycle contract does not trust the provider recovery attestation")?;
    let nonce_ledger = DeploymentStore::system()
        .deployment_state_dir(&attestation.deployment_id)
        .join("recovery")
        .join("provider-nonces");
    verify_provider_attestation_for_provider_with_ledger(
        manifest_path,
        &manifest,
        provider,
        lifecycle_sha256,
        operation,
        consume_nonce,
        Some(&nonce_ledger),
    )
}

fn verify_provider_attestation_for_provider_with_ledger(
    manifest_path: &Path,
    manifest: &RecoveryEvidenceManifest,
    provider: &RecoveryProviderTrust,
    lifecycle_sha256: &str,
    operation: RecoveryOperation,
    consume_nonce: bool,
    nonce_ledger: Option<&Path>,
) -> anyhow::Result<String> {
    validate_provider_attestation_shape(manifest)?;
    let attestation = &manifest.provider_attestation;
    if attestation.lifecycle_sha256 != lifecycle_sha256 {
        bail!("provider recovery attestation is bound to a different lifecycle contract");
    }
    if attestation.operation != operation {
        bail!("provider recovery attestation is bound to a different recovery operation");
    }
    if provider.roles
        != attestation
            .artifacts
            .iter()
            .map(|artifact| artifact.role.clone())
            .collect()
    {
        bail!("provider recovery attestation roles differ from the lifecycle trust pin");
    }
    let SafeReference::DigestBoundFile {
        path,
        sha256: expected,
    } = &provider.verification_key
    else {
        bail!("provider recovery verification key is not digest-bound");
    };
    let key_bytes = crate::filesystem::read_secure_regular_file(
        path,
        "provider recovery verification key",
        false,
        4096,
    )?;
    if hex_sha256(&key_bytes) != *expected {
        bail!("provider recovery verification key changed after lifecycle approval");
    }
    if provider.provider_id != attestation.provider_id {
        bail!("provider recovery attestation names a different trusted provider");
    }
    let decoded = match URL_SAFE_NO_PAD.decode(String::from_utf8_lossy(&key_bytes).trim()) {
        Ok(decoded) => decoded,
        Err(_) => key_bytes.to_vec(),
    };
    let key_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("provider recovery verification key has an invalid length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .context("provider recovery verification key is invalid")?;
    if nazo_operator_protocol::instance_key_id(&verifying_key) != attestation.provider_id {
        bail!("provider recovery attestation provider ID does not match its verification key");
    }
    let signature_bytes = URL_SAFE_NO_PAD.decode(&attestation.signature)?;
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        anyhow::anyhow!("provider recovery attestation signature has invalid length")
    })?;
    let payload = ProviderAttestationPayload {
        schema: attestation.schema,
        provider_id: &attestation.provider_id,
        deployment_id: &attestation.deployment_id,
        release: &attestation.release,
        manifest_sha256: &attestation.manifest_sha256,
        lifecycle_sha256: &attestation.lifecycle_sha256,
        operation,
        artifacts: &attestation.artifacts,
        nonce: &attestation.nonce,
        issued_at: attestation.issued_at,
        expires_at: attestation.expires_at,
    };
    verifying_key
        .verify(
            &serde_json::to_vec(&payload)?,
            &Signature::from_bytes(&signature),
        )
        .context("provider recovery attestation signature is invalid")?;
    if consume_nonce {
        let parent = if let Some(ledger) = nonce_ledger {
            crate::filesystem::ensure_private_directory(ledger, "provider recovery nonce ledger")?;
            ledger.to_path_buf()
        } else {
            manifest_path
                .parent()
                .context("provider recovery manifest has no parent directory")?
                .to_path_buf()
        };
        let nonce_key = format!("{}:{}", attestation.provider_id, attestation.nonce);
        let nonce_path = parent.join(format!(
            "provider-nonce-{}.json",
            hex_sha256(nonce_key.as_bytes())
        ));
        let mut marker = open_lock_file(&nonce_path, false, "provider recovery nonce marker")
            .with_context(|| {
                format!(
                    "failed to open provider recovery nonce marker {}",
                    nonce_path.display()
                )
            })?;
        marker
            .try_lock_exclusive()
            .context("provider recovery attestation nonce is already being consumed")?;
        if marker.metadata()?.len() != 0 {
            let _ = marker.unlock();
            bail!("provider recovery attestation nonce was already consumed");
        }
        marker.write_all(
            format!(
                "{}:{}:{}:{}:{:?}:{}:{}:{}",
                attestation.provider_id,
                attestation.deployment_id,
                attestation.release,
                attestation.lifecycle_sha256,
                attestation.operation,
                attestation.nonce,
                attestation.issued_at,
                attestation.expires_at,
            )
            .as_bytes(),
        )?;
        marker.sync_all()?;
        marker.unlock()?;
    }
    Ok(format!(
        "provider-attestation-verified:{}:{}",
        attestation.provider_id, attestation.nonce
    ))
}

#[cfg(test)]
pub(super) fn verify_provider_attestation_with_provider(
    manifest_path: &Path,
    manifest: &RecoveryEvidenceManifest,
    provider: &RecoveryProviderTrust,
    lifecycle_sha256: &str,
    operation: RecoveryOperation,
    consume_nonce: bool,
) -> anyhow::Result<String> {
    verify_provider_attestation_for_provider_with_ledger(
        manifest_path,
        manifest,
        provider,
        lifecycle_sha256,
        operation,
        consume_nonce,
        None,
    )
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
