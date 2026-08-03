use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    Actor, ActorKind, AdoptedRuntimeIdentity, AdoptionReceipt, CONTROL_DISCOVERY_SCHEMA,
    ManagementAuditEvent, PROTOCOL_VERSION, sign_adoption_receipt, sign_management_event,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    deployment::{
        ArtifactReference, Capability, CapabilityGrants, DEPLOYMENT_SCHEMA, DeploymentRecord,
        DeploymentStore, MountReference, RecoveryAssessment, RecoveryConclusion, Responsibility,
        RuntimeInstance, SafeReference, TrustState,
    },
    discovery::{DiscoveredDeployment, discover, select},
    filesystem::{atomic_write, copy_atomic, sha256},
    release::VerifiedRelease,
};

const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";

#[derive(Clone, Debug)]
pub(crate) struct AdoptionOptions {
    pub(crate) target: String,
    pub(crate) alias: Option<String>,
    pub(crate) capabilities: CapabilityGrants,
    pub(crate) recovery_evidence: Option<PathBuf>,
    pub(crate) plan: bool,
    pub(crate) yes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptionPlan {
    pub(crate) schema: u32,
    pub(crate) target: String,
    pub(crate) deployment_id: String,
    pub(crate) runtime_instance_id: String,
    pub(crate) issuer: String,
    pub(crate) release: String,
    pub(crate) artifact_identity: String,
    pub(crate) resulting_trust: TrustState,
    pub(crate) capabilities: CapabilityGrants,
    pub(crate) recovery: RecoveryAssessment,
    pub(crate) steps: Vec<AdoptionStep>,
    pub(crate) blockers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptionStep {
    pub(crate) owner: StepOwner,
    pub(crate) action: String,
    pub(crate) evidence: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StepOwner {
    Controller,
    User,
    Provider,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEvidenceManifest {
    schema: u32,
    deployment_id: String,
    release: String,
    data_snapshot: RecoveryArtifact,
    database_restore: RecoveryArtifact,
    last_trusted_artifact: RecoveryArtifact,
    verification_material: RecoveryArtifact,
    off_host_package_confirmed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryArtifact {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdoptionTransaction {
    schema: u32,
    state: AdoptionTransactionState,
    plan_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AdoptionTransactionState {
    Prepared,
    Committed,
}

pub(crate) fn run(options: AdoptionOptions) -> anyhow::Result<()> {
    if options.plan == options.yes {
        bail!("adopt requires exactly one of --plan or --yes");
    }
    let report = discover()?;
    let candidate = select(&report, &options.target)?;
    let plan = build_plan(&candidate, &options)?;
    if options.plan {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    if !plan.blockers.is_empty() {
        bail!(
            "adoption plan is blocked and remains observed: {}",
            plan.blockers.join("; ")
        );
    }
    execute(&candidate, &plan, &options)
}

fn build_plan(
    candidate: &DiscoveredDeployment,
    options: &AdoptionOptions,
) -> anyhow::Result<AdoptionPlan> {
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
    let recovery = recovery_assessment(
        candidate,
        &deployment_id,
        &release_name,
        options.recovery_evidence.as_deref(),
    )?;
    let mutation_requested = Capability::ALL.iter().any(|capability| {
        options
            .capabilities
            .grant(*capability)
            .responsibility
            .permits_mutation()
    });
    if mutation_requested && recovery.conclusion != RecoveryConclusion::Proven {
        blockers.push(
            "mutation capabilities require a verified recovery package or provider evidence"
                .to_owned(),
        );
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
    let resulting_trust = if blockers.is_empty() {
        TrustState::Adopted
    } else {
        TrustState::Observed
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
        artifact_identity,
        resulting_trust,
        capabilities: options.capabilities.clone(),
        recovery,
        steps,
        blockers,
    })
}

fn execute(
    candidate: &DiscoveredDeployment,
    plan: &AdoptionPlan,
    options: &AdoptionOptions,
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
    if transaction_path.exists() {
        let transaction: AdoptionTransaction =
            serde_json::from_slice(&fs::read(&transaction_path)?)
                .context("adoption transaction is invalid")?;
        if transaction.schema != 1 || transaction.plan_sha256 != plan_sha256 {
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
            })?,
            0o600,
        )?;
    }
    let identities = create_identities(&store, &plan.deployment_id)?;
    let recovery_evidence = if let Some(source) = &options.recovery_evidence {
        persist_recovery_evidence(&store, plan, source)?
    } else {
        Vec::new()
    };
    let observed_state = store
        .deployment_state_dir(&plan.deployment_id)
        .join("observed-state.json");
    atomic_write(
        &observed_state,
        &serde_json::to_vec_pretty(candidate)?,
        0o600,
    )?;
    let record = deployment_record(candidate, plan, options.alias.clone())?;
    let manifest = verified_release(candidate, &plan.release)?.manifest;
    let receipt = AdoptionReceipt {
        schema: CONTROL_DISCOVERY_SCHEMA,
        deployment_id: plan.deployment_id.clone(),
        issuer: plan.issuer.clone(),
        runtime_instances: vec![AdoptedRuntimeIdentity {
            runtime_instance_id: plan.runtime_instance_id.clone(),
            backend: backend_name(candidate.runtime.backend).to_owned(),
            object_reference: candidate.runtime.object_reference.clone(),
            artifact_identity: plan.artifact_identity.clone(),
        }],
        verified_release: plan.release.clone(),
        release_manifest_sha256: hex_sha256(&serde_json::to_vec(&manifest)?),
        instance_key_ids: candidate.instance_key_id.clone().into_iter().collect(),
        resource_references: receipt_resource_references(candidate),
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
        })?,
        0o600,
    )?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

fn verified_release(
    candidate: &DiscoveredDeployment,
    release: &str,
) -> anyhow::Result<VerifiedRelease> {
    let engine = match candidate.runtime.backend {
        crate::deployment::RuntimeBackendKind::Podman => Some("podman"),
        crate::deployment::RuntimeBackendKind::Docker => Some("docker"),
        crate::deployment::RuntimeBackendKind::Systemd => None,
    };
    VerifiedRelease::fetch(SERVER_REPOSITORY, Some(release), engine)
}

fn verify_artifact(
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

fn recovery_assessment(
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
        RecoveryConclusion::Proven
    } else {
        candidate.recovery_conclusion.clone()
    };
    Ok(RecoveryAssessment {
        conclusion,
        evidence: proof,
        off_host_package_required_for_machine_loss: true,
    })
}

fn verify_recovery_evidence(
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

fn persist_recovery_evidence(
    store: &DeploymentStore,
    plan: &AdoptionPlan,
    manifest_path: &Path,
) -> anyhow::Result<Vec<String>> {
    let manifest = verify_recovery_evidence(manifest_path, &plan.deployment_id, &plan.release)?;
    let directory = store
        .deployment_state_dir(&plan.deployment_id)
        .join("recovery")
        .join("adoption");
    fs::create_dir_all(&directory)?;
    let mut evidence = Vec::new();
    for (name, artifact) in recovery_artifacts(&manifest) {
        let target = directory.join(name);
        copy_atomic(&artifact.path, &target, 0o600)?;
        let actual = sha256(&target)?;
        if actual != artifact.sha256 {
            bail!("persisted recovery artifact changed during adoption");
        }
        evidence.push(format!("{name}-sha256:{actual}"));
    }
    copy_atomic(manifest_path, &directory.join("manifest.json"), 0o600)?;
    Ok(evidence)
}

fn deployment_record(
    candidate: &DiscoveredDeployment,
    plan: &AdoptionPlan,
    alias: Option<String>,
) -> anyhow::Result<DeploymentRecord> {
    let resources = BTreeMap::from([
        ("database".to_owned(), SafeReference::NotObserved),
        ("valkey".to_owned(), SafeReference::NotObserved),
        ("proxy_tls".to_owned(), SafeReference::NotObserved),
    ]);
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
    let record = DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: plan.deployment_id.clone(),
        alias,
        issuer: plan.issuer.clone(),
        trust: plan.resulting_trust,
        capabilities: plan.capabilities.clone(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: plan.runtime_instance_id.clone(),
            backend: candidate.runtime.backend,
            object_reference: candidate.runtime.object_reference.clone(),
            artifact: candidate.runtime.artifact.clone(),
            ports: candidate.runtime.ports.clone(),
            networks: candidate.runtime.networks.clone(),
            mounts,
            instance_key_id: candidate.instance_key_id.clone(),
            deployment_statement: candidate.runtime.mounts.iter().find_map(|mount| {
                let destination = mount.destination.join("instance/deployment-statement.jws");
                destination
                    .is_absolute()
                    .then(|| mount.source.join("instance/deployment-statement.jws"))
            }),
        }],
        resources,
        recovery: plan.recovery.clone(),
        operator_protocol_versions: candidate
            .operator_protocol_versions
            .iter()
            .copied()
            .collect(),
        control_protocol_versions: candidate
            .control_protocol_versions
            .iter()
            .copied()
            .collect(),
        declaration_revision: 1,
    };
    record.validate()?;
    Ok(record)
}

struct Identities {
    receipt_key_id: String,
    receipt: SigningKey,
    audit: SigningKey,
}

fn create_identities(store: &DeploymentStore, deployment_id: &str) -> anyhow::Result<Identities> {
    let active = store.deployment_state_dir(deployment_id).join("identities");
    let break_glass = store.break_glass_dir(deployment_id);
    fs::create_dir_all(&active)?;
    fs::create_dir_all(&break_glass)?;
    let controller = create_identity(&active, "controller")?;
    let receipt = create_identity(&active, "receipt")?;
    let audit = create_identity(&active, "audit")?;
    let _break_glass = create_identity(&break_glass, "break-glass")?;
    if [controller.0.as_str(), receipt.0.as_str(), audit.0.as_str()]
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        bail!("deployment identities are not distinct");
    }
    Ok(Identities {
        receipt_key_id: receipt.0,
        receipt: receipt.1,
        audit: audit.1,
    })
}

fn create_identity(directory: &Path, name: &str) -> anyhow::Result<(String, SigningKey)> {
    let private_path = directory.join(format!("{name}.key"));
    let public_path = directory.join(format!("{name}.pub"));
    if private_path.exists() {
        let private = URL_SAFE_NO_PAD
            .decode(fs::read_to_string(&private_path)?.trim())
            .context("stored identity private key is invalid")?;
        let private: [u8; 32] = private
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored identity private key has an invalid length"))?;
        let signing = SigningKey::from_bytes(&private);
        let public = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        if public_path.exists() {
            if fs::read_to_string(&public_path)?.trim() != public {
                bail!("stored identity public key does not match its private key");
            }
        } else {
            atomic_write(&public_path, public.as_bytes(), 0o640)?;
        }
        let key_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key()).replacen(
            "instance-",
            &format!("{name}-"),
            1,
        );
        return Ok((key_id, signing));
    }
    if public_path.exists() {
        bail!("stored identity has a public key but no private key");
    }
    let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let key_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key()).replacen(
        "instance-",
        &format!("{name}-"),
        1,
    );
    atomic_write(
        &private_path,
        URL_SAFE_NO_PAD.encode(signing.to_bytes()).as_bytes(),
        0o600,
    )?;
    atomic_write(
        &public_path,
        URL_SAFE_NO_PAD
            .encode(signing.verifying_key().to_bytes())
            .as_bytes(),
        0o640,
    )?;
    Ok((key_id, signing))
}

fn initialize_audit(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    key: &SigningKey,
) -> anyhow::Result<()> {
    let key_id = nazo_operator_protocol::instance_key_id(&key.verifying_key()).replacen(
        "instance-",
        "audit-",
        1,
    );
    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: record.deployment_id.clone(),
        sequence: 1,
        previous_sha256: "0".repeat(64),
        request_id: uuid::Uuid::now_v7().to_string(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: "adopt".to_owned(),
        release: record
            .runtime_instances
            .first()
            .map(|_| "verified-release")
            .unwrap_or("unknown")
            .to_owned(),
        recovery_boundary: match record.recovery.conclusion {
            RecoveryConclusion::Proven => "recovery:proven",
            RecoveryConclusion::RequiresUserEvidence => "recovery:user-required",
            RecoveryConclusion::Unproven => "recovery:unproven",
        }
        .to_owned(),
    };
    let compact = sign_management_event(&event, &key_id, key)?;
    atomic_write(
        &store
            .deployment_state_dir(&record.deployment_id)
            .join("audit")
            .join("00000000000000000001.jws"),
        compact.as_bytes(),
        0o600,
    )
}

fn receipt_resource_references(candidate: &DiscoveredDeployment) -> BTreeMap<String, String> {
    let mut references = BTreeMap::new();
    for (index, mount) in candidate.runtime.mounts.iter().enumerate() {
        if !mount.source.to_string_lossy().contains("redacted") {
            references.insert(format!("mount-{index}"), mount.source.display().to_string());
        }
    }
    references
}

fn receipt_capabilities(capabilities: &CapabilityGrants) -> BTreeMap<String, String> {
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

fn backend_name(backend: crate::deployment::RuntimeBackendKind) -> &'static str {
    match backend {
        crate::deployment::RuntimeBackendKind::Podman => "podman",
        crate::deployment::RuntimeBackendKind::Docker => "docker",
        crate::deployment::RuntimeBackendKind::Systemd => "systemd",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
