use std::{fmt::Write as _, fs, path::Path};

use anyhow::{Context, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    deployment::{DeploymentRecord, DeploymentStore},
    filesystem::{atomic_write, remove_file_durable, sha256},
};

const TRANSACTION_SCHEMA: u32 = 1;
const EVIDENCE_SCHEMA: u32 = 1;
const MAX_EVIDENCE_BYTES: u64 = 32 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoordinationState {
    WaitingForEvidence,
    ReadyForController,
    Blocked,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StepOwner {
    CtlOwned,
    UserRequired,
    ProviderOwned,
}

impl StepOwner {
    fn requires_external_evidence(self) -> bool {
        matches!(self, Self::UserRequired | Self::ProviderOwned)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StepState {
    Pending,
    EvidenceAccepted,
    ControllerCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoordinationStep {
    pub(crate) id: String,
    pub(crate) owner: StepOwner,
    pub(crate) capability: String,
    action: String,
    pub(crate) state: StepState,
    evidence_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateCoordination {
    schema: u32,
    pub(crate) transaction_id: String,
    pub(crate) deployment_id: String,
    operation: String,
    declaration_revision: u64,
    plan_sha256: String,
    pub(crate) target_release: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) state: CoordinationState,
    blockers: Vec<String>,
    pub(crate) steps: Vec<CoordinationStep>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceKind {
    RecoveryPoint,
    ProviderReceipt,
    RoutingChange,
    OperatorConfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceInput {
    schema: u32,
    deployment_id: String,
    transaction_id: String,
    step_id: String,
    kind: EvidenceKind,
    reference_id: String,
    artifact_sha256: String,
    issued_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptedEvidence {
    schema: u32,
    evidence: EvidenceInput,
    source_manifest_sha256: String,
    accepted_at: i64,
    semantic_completion_claimed: bool,
}

#[derive(Deserialize)]
struct PlanStep {
    id: String,
    owner: StepOwner,
    capability: String,
    action: String,
}

pub(crate) fn prepare_update(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    plan: &Value,
) -> anyhow::Result<UpdateCoordination> {
    let _lock = store.deployment_lock(&record.deployment_id)?;
    let plan_deployment = plan
        .get("deployment_id")
        .and_then(Value::as_str)
        .context("update plan has no deployment ID")?;
    if plan_deployment != record.deployment_id {
        bail!("update plan is bound to a different deployment");
    }
    let target_release: nazo_operator_protocol::EmbeddedIdentity = serde_json::from_value(
        plan.get("target_release")
            .cloned()
            .context("update plan has no target Release identity")?,
    )
    .context("update plan target Release identity is invalid")?;
    let plan_sha256 = digest_bytes(&serde_json::to_vec(plan)?);
    let path = transaction_path(store, &record.deployment_id);
    if path.exists() {
        let existing = load_path(&path)?;
        if existing.plan_sha256 != plan_sha256
            || existing.declaration_revision != record.declaration_revision
        {
            bail!(
                "an unfinished update transaction is bound to a different plan or declaration revision"
            );
        }
        return Ok(existing);
    }

    let plan_steps = plan
        .get("steps")
        .and_then(Value::as_array)
        .context("update plan has no steps")?;
    let mut steps = Vec::with_capacity(plan_steps.len());
    for value in plan_steps {
        let step: PlanStep =
            serde_json::from_value(value.clone()).context("update plan step is invalid")?;
        validate_identifier(&step.id, "plan step ID")?;
        if step.capability.is_empty() || step.action.is_empty() {
            bail!("update plan step is incomplete");
        }
        let verified_release = step.id == "verify-release" && step.owner == StepOwner::CtlOwned;
        steps.push(CoordinationStep {
            id: step.id,
            owner: step.owner,
            capability: step.capability,
            action: step.action,
            state: if verified_release {
                StepState::ControllerCompleted
            } else {
                StepState::Pending
            },
            evidence_sha256: verified_release.then(|| plan_sha256.clone()),
        });
    }
    let blockers = plan
        .get("blockers")
        .and_then(Value::as_array)
        .context("update plan has no blockers")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("update plan blocker is not a string")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let now = Utc::now().timestamp();
    let mut transaction = UpdateCoordination {
        schema: TRANSACTION_SCHEMA,
        transaction_id: uuid::Uuid::now_v7().to_string(),
        deployment_id: record.deployment_id.clone(),
        operation: "update".to_owned(),
        declaration_revision: record.declaration_revision,
        plan_sha256,
        target_release,
        state: CoordinationState::WaitingForEvidence,
        blockers,
        steps,
        created_at: now,
        updated_at: now,
    };
    transaction.state = next_state(&transaction);
    persist(store, &transaction)?;
    Ok(transaction)
}

pub(crate) fn show(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<UpdateCoordination> {
    let transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    validate_binding(&transaction, record)?;
    Ok(transaction)
}

pub(crate) fn submit_evidence(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    input_path: &Path,
) -> anyhow::Result<UpdateCoordination> {
    let _lock = store.deployment_lock(&record.deployment_id)?;
    let mut transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    validate_binding(&transaction, record)?;
    if matches!(
        transaction.state,
        CoordinationState::Committed | CoordinationState::Aborted
    ) {
        bail!("the update transaction no longer accepts evidence");
    }
    validate_evidence_file(input_path)?;
    let input_bytes = fs::read(input_path)?;
    let input: EvidenceInput =
        serde_json::from_slice(&input_bytes).context("coordination evidence is invalid")?;
    validate_evidence_input(&input, &transaction)?;
    let step = transaction
        .steps
        .iter_mut()
        .find(|step| step.id == input.step_id)
        .context("coordination evidence step does not exist")?;
    if !step.owner.requires_external_evidence() {
        bail!("controller-owned steps do not accept user-supplied completion evidence");
    }
    let source_manifest_sha256 = digest_bytes(&input_bytes);
    let accepted = AcceptedEvidence {
        schema: EVIDENCE_SCHEMA,
        evidence: input,
        source_manifest_sha256: source_manifest_sha256.clone(),
        accepted_at: Utc::now().timestamp(),
        semantic_completion_claimed: false,
    };
    let evidence_path = evidence_path(store, &transaction.deployment_id, &step.id);
    atomic_write(
        &evidence_path,
        &serde_json::to_vec_pretty(&accepted)?,
        0o600,
    )?;
    step.state = StepState::EvidenceAccepted;
    step.evidence_sha256 = Some(sha256(&evidence_path)?);
    transaction.updated_at = Utc::now().timestamp();
    transaction.state = next_state(&transaction);
    persist(store, &transaction)?;
    Ok(transaction)
}

pub(crate) fn resume(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<UpdateCoordination> {
    let _lock = store.deployment_lock(&record.deployment_id)?;
    let mut transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    validate_binding(&transaction, record)?;
    for step in transaction
        .steps
        .iter()
        .filter(|step| step.owner.requires_external_evidence())
    {
        if step.state != StepState::EvidenceAccepted {
            continue;
        }
        let evidence_path = evidence_path(store, &transaction.deployment_id, &step.id);
        let expected = step
            .evidence_sha256
            .as_deref()
            .context("accepted evidence has no persisted digest")?;
        if sha256(&evidence_path)? != expected {
            bail!("persisted coordination evidence was changed after acceptance");
        }
        let accepted: AcceptedEvidence = serde_json::from_slice(&fs::read(&evidence_path)?)
            .context("persisted coordination evidence is invalid")?;
        validate_evidence_input(&accepted.evidence, &transaction)?;
        if accepted.semantic_completion_claimed {
            bail!("coordination evidence must not claim semantic completion");
        }
    }
    transaction.updated_at = Utc::now().timestamp();
    transaction.state = next_state(&transaction);
    persist(store, &transaction)?;
    Ok(transaction)
}

#[cfg(test)]
pub(crate) fn complete_controller_step(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction_id: &str,
    step_id: &str,
    evidence_sha256: &str,
) -> anyhow::Result<UpdateCoordination> {
    let _lock = store.deployment_lock(&record.deployment_id)?;
    complete_controller_step_locked(store, record, transaction_id, step_id, evidence_sha256)
}

pub(crate) fn complete_controller_step_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction_id: &str,
    step_id: &str,
    evidence_sha256: &str,
) -> anyhow::Result<UpdateCoordination> {
    let mut transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    validate_binding(&transaction, record)?;
    if transaction.transaction_id != transaction_id {
        bail!("controller step is bound to a different update transaction");
    }
    if transaction.state != CoordinationState::ReadyForController {
        bail!("update transaction is not ready for controller execution");
    }
    if evidence_sha256.len() != 64
        || !evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("controller step evidence digest is invalid");
    }
    let step = transaction
        .steps
        .iter_mut()
        .find(|step| step.id == step_id)
        .context("controller update step does not exist")?;
    if step.owner != StepOwner::CtlOwned {
        bail!("external update steps cannot be completed by the controller");
    }
    if step.state == StepState::ControllerCompleted {
        if step.evidence_sha256.as_deref() != Some(evidence_sha256) {
            bail!("controller update step was already completed with different evidence");
        }
        return Ok(transaction);
    }
    if step.state != StepState::Pending {
        bail!("controller update step is not pending execution");
    }
    step.state = StepState::ControllerCompleted;
    step.evidence_sha256 = Some(evidence_sha256.to_owned());
    transaction.updated_at = Utc::now().timestamp();
    transaction.state = next_state(&transaction);
    persist(store, &transaction)?;
    Ok(transaction)
}

#[cfg(test)]
pub(crate) fn commit_controller_update(
    store: &DeploymentStore,
    current: &DeploymentRecord,
    updated: &DeploymentRecord,
    transaction_id: &str,
    step_id: &str,
    evidence_sha256: &str,
) -> anyhow::Result<UpdateCoordination> {
    let _deployment_lock = store.deployment_lock(&current.deployment_id)?;
    commit_controller_update_locked(
        store,
        current,
        updated,
        transaction_id,
        step_id,
        evidence_sha256,
    )
}

pub(crate) fn commit_controller_update_locked(
    store: &DeploymentStore,
    current: &DeploymentRecord,
    updated: &DeploymentRecord,
    transaction_id: &str,
    step_id: &str,
    evidence_sha256: &str,
) -> anyhow::Result<UpdateCoordination> {
    let mut transaction = load_path(&transaction_path(store, &current.deployment_id))?;
    validate_binding(&transaction, current)?;
    if transaction.transaction_id != transaction_id
        || updated.deployment_id != current.deployment_id
        || updated.declaration_revision != current.declaration_revision + 1
    {
        bail!("committed update is not bound to the active deployment transaction");
    }
    let step = transaction
        .steps
        .iter_mut()
        .find(|step| step.id == step_id)
        .context("final controller update step does not exist")?;
    if step.owner != StepOwner::CtlOwned || step.state != StepState::Pending {
        bail!("final controller update step is not pending controller execution");
    }
    if evidence_sha256.len() != 64
        || !evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("final controller evidence digest is invalid");
    }
    step.state = StepState::ControllerCompleted;
    step.evidence_sha256 = Some(evidence_sha256.to_owned());
    transaction.state = next_state(&transaction);
    if transaction.state != CoordinationState::Committed {
        bail!("controller update still has incomplete or blocked steps");
    }
    updated.validate()?;
    store.persist_declaration_locked(updated)?;
    transaction.declaration_revision = updated.declaration_revision;
    transaction.updated_at = Utc::now().timestamp();
    persist(store, &transaction)?;
    Ok(transaction)
}

pub(crate) fn finalize_committed_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction_id: &str,
) -> anyhow::Result<()> {
    let active = transaction_path(store, &record.deployment_id);
    let transaction = load_path(&active)?;
    validate_binding(&transaction, record)?;
    if transaction.transaction_id != transaction_id
        || transaction.state != CoordinationState::Committed
    {
        bail!("only the committed active update transaction can be finalized");
    }
    let history = active.with_file_name(format!("update-{transaction_id}.json"));
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&active)
}

fn next_state(transaction: &UpdateCoordination) -> CoordinationState {
    if transaction.steps.iter().any(|step| {
        step.owner.requires_external_evidence() && step.state != StepState::EvidenceAccepted
    }) {
        CoordinationState::WaitingForEvidence
    } else if !transaction.blockers.is_empty() {
        CoordinationState::Blocked
    } else if transaction.steps.iter().any(|step| {
        step.owner == StepOwner::CtlOwned && step.state != StepState::ControllerCompleted
    }) {
        CoordinationState::ReadyForController
    } else {
        CoordinationState::Committed
    }
}

fn validate_binding(
    transaction: &UpdateCoordination,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    if transaction.schema != TRANSACTION_SCHEMA || transaction.operation != "update" {
        bail!("unsupported coordination transaction");
    }
    if transaction.deployment_id != record.deployment_id {
        bail!("coordination transaction is bound to a different deployment");
    }
    if transaction.declaration_revision != record.declaration_revision {
        bail!("deployment declaration changed after the coordination plan was prepared");
    }
    Ok(())
}

fn validate_evidence_input(
    input: &EvidenceInput,
    transaction: &UpdateCoordination,
) -> anyhow::Result<()> {
    if input.schema != EVIDENCE_SCHEMA {
        bail!("unsupported coordination evidence schema");
    }
    if input.deployment_id != transaction.deployment_id
        || input.transaction_id != transaction.transaction_id
    {
        bail!("coordination evidence is bound to a different deployment or transaction");
    }
    validate_identifier(&input.step_id, "evidence step ID")?;
    validate_identifier(&input.reference_id, "evidence reference ID")?;
    if input.artifact_sha256.len() != 64
        || !input
            .artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("evidence artifact SHA-256 must be 64 lowercase hexadecimal characters");
    }
    if input.issued_at <= 0 {
        bail!("coordination evidence issued_at is invalid");
    }
    Ok(())
}

fn validate_evidence_file(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect evidence {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EVIDENCE_BYTES
    {
        bail!("coordination evidence must be a regular file from 1 through 32768 bytes");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .with_context(|| format!("invalid {label}"))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn transaction_path(store: &DeploymentStore, deployment_id: &str) -> std::path::PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("active-update.json")
}

fn evidence_path(
    store: &DeploymentStore,
    deployment_id: &str,
    step_id: &str,
) -> std::path::PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("evidence")
        .join(format!("{step_id}.json"))
}

fn load_path(path: &Path) -> anyhow::Result<UpdateCoordination> {
    let transaction: UpdateCoordination = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .context("coordination transaction is invalid")?;
    if transaction.schema != TRANSACTION_SCHEMA {
        bail!("unsupported coordination transaction schema");
    }
    Ok(transaction)
}

fn persist(store: &DeploymentStore, transaction: &UpdateCoordination) -> anyhow::Result<()> {
    atomic_write(
        &transaction_path(store, &transaction.deployment_id),
        &serde_json::to_vec_pretty(transaction)?,
        0o600,
    )
}

#[cfg(test)]
#[path = "../tests/unit/coordination.rs"]
mod tests;
