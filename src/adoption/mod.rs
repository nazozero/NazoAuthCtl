use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
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
    discovery::{DiscoveredDeployment, deployment_statement_path, discover, select},
    filesystem::{
        atomic_write, copy_atomic_verified, open_lock_file, read_secure_regular_file, sha256,
    },
    lifecycle::{
        LifecycleManifest, RecoveryArtifactRole, RecoveryDriverReceipt, RecoveryOperation,
        RecoveryProviderTrust, invoke_recovery_driver,
    },
    release::VerifiedRelease,
};

mod identity;
mod plan;
mod transaction;
use identity::*;
pub(crate) use plan::verify_provider_attestation as verify_provider_attestation_for_lifecycle;
use plan::*;
pub(crate) use transaction::persist_bound_recovery_package;
use transaction::*;

const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";
const RECOVERY_UNPROVEN_BLOCKER: &str =
    "recovery executability is not proven; the deployment can only be recorded as observed";
const RECOVERY_CAPABILITY_BLOCKER: &str =
    "requested mutation capabilities remain external until recovery is proven";
const RECOVERY_EVIDENCE_SCHEMA: u32 = 2;
const PROVIDER_ATTESTATION_SCHEMA: u32 = 1;
const MAX_RECOVERY_EVIDENCE_BYTES: u64 = 64 * 1024;
const MAX_ADOPTION_TRANSACTION_BYTES: u64 = 64 * 1024;
const MAX_RECOVERY_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROVIDER_CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_PROVIDER_ATTESTATION_AGE_SECONDS: i64 = 300;
const MAX_PROVIDER_ATTESTATION_LIFETIME_SECONDS: i64 = 600;

#[derive(Clone, Debug)]
pub(crate) struct AdoptionOptions {
    pub(crate) target: String,
    pub(crate) alias: Option<String>,
    pub(crate) capabilities: CapabilityGrants,
    pub(crate) recovery_evidence: Option<PathBuf>,
    pub(crate) lifecycle_contract: Option<PathBuf>,
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
    pub(crate) active_release: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) artifact_identity: String,
    pub(crate) runtime_instances: Vec<AdoptedRuntimeIdentity>,
    pub(crate) resulting_trust: TrustState,
    pub(crate) requested_capabilities: CapabilityGrants,
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
    provider_attestation: ProviderAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryArtifact {
    role: RecoveryArtifactRole,
    path: PathBuf,
    sha256: String,
    size: u64,
    content_type: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttestation {
    schema: u32,
    provider_id: String,
    deployment_id: String,
    release: String,
    operation: RecoveryOperation,
    manifest_sha256: String,
    lifecycle_sha256: String,
    artifacts: Vec<ProviderArtifactReceipt>,
    nonce: String,
    issued_at: i64,
    expires_at: i64,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderArtifactReceipt {
    role: RecoveryArtifactRole,
    sha256: String,
    size: u64,
    content_type: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttestationPayload<'a> {
    schema: u32,
    provider_id: &'a str,
    deployment_id: &'a str,
    release: &'a str,
    operation: RecoveryOperation,
    manifest_sha256: &'a str,
    lifecycle_sha256: &'a str,
    artifacts: &'a [ProviderArtifactReceipt],
    nonce: &'a str,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdoptionTransaction {
    schema: u32,
    state: AdoptionTransactionState,
    plan_sha256: String,
    #[serde(default)]
    lifecycle_sha256: Option<String>,
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
    DeploymentStore::system().validate_failure_domains()?;
    let report = discover()?;
    let candidate = select(&report, &options.target)?;
    let deployment_id = candidate
        .deployment_id
        .as_deref()
        .context("target has no verified NazoAuth deployment identity")?;
    let replicas = report
        .candidates
        .iter()
        .filter(|entry| entry.deployment_id.as_deref() == Some(deployment_id))
        .cloned()
        .collect::<Vec<_>>();
    let mut plan = build_plan(&candidate, &replicas, &options)?;
    if options.plan {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    let rehearsal_receipt = match (
        options.lifecycle_contract.as_deref(),
        options.recovery_evidence.as_deref(),
    ) {
        (Some(lifecycle_path), Some(recovery_manifest)) => {
            let lifecycle = LifecycleManifest::load(lifecycle_path)?;
            lifecycle.validate_for_adoption(&replicas, &options.capabilities)?;
            let store = DeploymentStore::system();
            let _deployment_lock = store.deployment_lock(&plan.deployment_id)?;
            let evidence = persist_recovery_evidence(&store, &plan, recovery_manifest)?;
            plan.recovery.evidence.extend(evidence);
            let normalized_recovery_manifest = store
                .deployment_state_dir(&plan.deployment_id)
                .join("recovery")
                .join("adoption")
                .join("manifest.json");
            let lifecycle_sha256 = LifecycleManifest::digest(lifecycle_path)?;
            let provider_evidence = verify_provider_attestation(
                &normalized_recovery_manifest,
                &lifecycle,
                &plan.deployment_id,
                &plan.release,
                &lifecycle_sha256,
                RecoveryOperation::Rehearse,
                false,
            )?;
            plan.recovery.evidence.push(provider_evidence);
            let receipt = invoke_recovery_driver(
                lifecycle_path,
                &lifecycle,
                &normalized_recovery_manifest,
                &plan.release,
                RecoveryOperation::Rehearse,
                &options.capabilities,
            )?;
            apply_recovery_rehearsal(&mut plan, &receipt)?;
            Some(receipt)
        }
        _ => None,
    };
    if !plan.blockers.is_empty() {
        eprintln!(
            "nazoauthctl: mutation adoption is blocked; persisting verified observed state only: {}",
            plan.blockers.join("; ")
        );
    }
    execute(&replicas, &plan, &options, rehearsal_receipt.as_ref())
}

#[cfg(test)]
#[path = "../../tests/unit/adoption.rs"]
mod tests;
