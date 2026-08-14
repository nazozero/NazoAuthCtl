use std::{fmt::Write as _, fs, io::Read as _, path::Path};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    deployment::{Capability, DeploymentRecord, DeploymentStore, SafeReference},
    filesystem::{atomic_write, open_secure_regular_file, remove_file_durable},
};

const TRANSACTION_SCHEMA: u32 = 1;
const EVIDENCE_SCHEMA: u32 = 1;
const MAX_EVIDENCE_BYTES: u64 = 32 * 1024;
const MAX_PROVIDER_KEY_BYTES: u64 = 4 * 1024;
const MAX_EVIDENCE_AGE_SECONDS: i64 = 15 * 60;
const MAX_EVIDENCE_FUTURE_SKEW_SECONDS: i64 = 60;
const MAX_EVIDENCE_LIFETIME_SECONDS: i64 = 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoordinationState {
    WaitingForEvidence,
    ReadyForController,
    Blocked,
    Aborting,
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
    #[serde(default)]
    expected_evidence_kind: Option<EvidenceKind>,
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
    /// Durable commit intent.  The declaration CAS and this journal cannot be
    /// committed atomically, so the target declaration is recorded before the
    /// CAS.  A crash on either side of the CAS can then be replayed safely.
    #[serde(default)]
    committed_declaration: Option<DeploymentRecord>,
    created_at: i64,
    updated_at: i64,
}

impl UpdateCoordination {
    pub(crate) fn declaration_revision(&self) -> u64 {
        self.declaration_revision
    }
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
    action: String,
    capability: String,
    reference_id: String,
    artifact_sha256: String,
    plan_sha256: String,
    target_release: nazo_operator_protocol::EmbeddedIdentity,
    issued_at: i64,
    expires_at: i64,
    nonce: String,
    #[serde(default)]
    signature: Option<String>,
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

#[derive(Serialize)]
struct EvidenceSigningPayload<'a> {
    schema: u32,
    deployment_id: &'a str,
    transaction_id: &'a str,
    step_id: &'a str,
    kind: EvidenceKind,
    action: &'a str,
    capability: &'a str,
    reference_id: &'a str,
    artifact_sha256: &'a str,
    plan_sha256: &'a str,
    target_release: &'a nazo_operator_protocol::EmbeddedIdentity,
    issued_at: i64,
    expires_at: i64,
    nonce: &'a str,
}

#[derive(Deserialize)]
struct PlanStep {
    id: String,
    owner: StepOwner,
    capability: String,
    action: String,
    #[serde(default)]
    evidence_kind: Option<EvidenceKind>,
}

#[cfg(test)]
pub(crate) fn prepare_update(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    plan: &Value,
) -> anyhow::Result<UpdateCoordination> {
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current = current_record_locked(store, record)?;
    let _shared_locks = store.shared_capability_locks(&current, &Capability::ALL)?;
    prepare_update_locked(store, &current, plan)
}

pub(crate) fn prepare_update_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    plan: &Value,
) -> anyhow::Result<UpdateCoordination> {
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
        validate_identifier(&step.capability, "plan step capability")?;
        validate_action(&step.action)?;
        match step.owner {
            StepOwner::CtlOwned if step.evidence_kind.is_some() => {
                bail!("controller-owned update steps must not declare an external evidence kind");
            }
            StepOwner::UserRequired
                if step.evidence_kind != Some(EvidenceKind::OperatorConfirmation) =>
            {
                bail!("user-required update steps must require operator-confirmation evidence");
            }
            StepOwner::ProviderOwned if step.evidence_kind.is_none() => {
                bail!("provider-owned update steps must declare their evidence kind");
            }
            _ => {}
        }
        if steps
            .iter()
            .any(|existing: &CoordinationStep| existing.id == step.id)
        {
            bail!("update plan contains duplicate step IDs");
        }
        let verified_release = step.id == "verify-release" && step.owner == StepOwner::CtlOwned;
        steps.push(CoordinationStep {
            id: step.id,
            owner: step.owner,
            capability: step.capability,
            action: step.action,
            expected_evidence_kind: step.evidence_kind,
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
        committed_declaration: None,
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
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current = current_record_locked(store, record)?;
    show_locked(store, &current)
}

pub(crate) fn active_update_exists(store: &DeploymentStore, record: &DeploymentRecord) -> bool {
    transaction_path(store, &record.deployment_id).exists()
}

pub(crate) fn show_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<UpdateCoordination> {
    let transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    if transaction.state == CoordinationState::Committed {
        return validate_committed_binding(&transaction, record).map(|_| transaction);
    }
    validate_binding(&transaction, record)?;
    Ok(transaction)
}

pub(crate) fn submit_evidence(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    input_path: &Path,
) -> anyhow::Result<UpdateCoordination> {
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current = current_record_locked(store, record)?;
    let _shared_locks = store.shared_capability_locks(&current, &Capability::ALL)?;
    let mut transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    validate_binding(&transaction, &current)?;
    if matches!(
        transaction.state,
        CoordinationState::Aborting | CoordinationState::Committed | CoordinationState::Aborted
    ) {
        bail!("the update transaction no longer accepts evidence");
    }
    let input_bytes = read_bounded_secure_file(
        input_path,
        "coordination evidence",
        false,
        MAX_EVIDENCE_BYTES,
    )?;
    let input: EvidenceInput =
        serde_json::from_slice(&input_bytes).context("coordination evidence is invalid")?;
    let step_index = transaction
        .steps
        .iter()
        .position(|step| step.id == input.step_id)
        .context("coordination evidence step does not exist")?;
    let step = transaction.steps[step_index].clone();
    if !step.owner.requires_external_evidence() {
        bail!("controller-owned steps do not accept user-supplied completion evidence");
    }
    if step.state != StepState::Pending {
        bail!("coordination evidence for this step was already accepted");
    }
    validate_evidence_input(&input, &transaction, &step)?;
    if step.owner == StepOwner::ProviderOwned {
        verify_provider_evidence(&current, &transaction, &step, &input)?;
    }
    reject_replayed_nonce(store, &transaction, &input.nonce)?;
    let source_manifest_sha256 = digest_bytes(&canonical_evidence_bytes(&input)?);
    let accepted = AcceptedEvidence {
        schema: EVIDENCE_SCHEMA,
        evidence: input,
        source_manifest_sha256,
        accepted_at: Utc::now().timestamp(),
        semantic_completion_claimed: false,
    };
    let evidence_path = evidence_path(
        store,
        &transaction.deployment_id,
        &transaction.transaction_id,
        &step.id,
    );
    match fs::symlink_metadata(&evidence_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("coordination evidence must be a regular non-symlink file");
            }
            // The evidence file may have been durably written immediately
            // before the process stopped, while the active transaction still
            // says Pending.  Re-validate that exact accepted payload instead
            // of treating it as a duplicate or overwriting it.
            let persisted_bytes = read_bounded_secure_file(
                &evidence_path,
                "persisted coordination evidence",
                true,
                MAX_EVIDENCE_BYTES,
            )?;
            let persisted =
                validate_persisted_evidence(&current, &transaction, &step, &persisted_bytes)?;
            if persisted.evidence != accepted.evidence {
                bail!(
                    "coordination evidence for this step conflicts with the persisted acceptance"
                );
            }
            let step = &mut transaction.steps[step_index];
            step.state = StepState::EvidenceAccepted;
            step.evidence_sha256 = Some(digest_bytes(&persisted_bytes));
            transaction.updated_at = Utc::now().timestamp();
            transaction.state = next_state(&transaction);
            persist(store, &transaction)?;
            return Ok(transaction);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect existing coordination evidence {}",
                    evidence_path.display()
                )
            });
        }
    }
    let persisted_bytes = serde_json::to_vec_pretty(&accepted)?;
    if persisted_bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        bail!("accepted coordination evidence exceeds the {MAX_EVIDENCE_BYTES}-byte limit");
    }
    atomic_write(&evidence_path, &persisted_bytes, 0o600)?;
    let step = &mut transaction.steps[step_index];
    step.state = StepState::EvidenceAccepted;
    step.evidence_sha256 = Some(digest_bytes(&persisted_bytes));
    transaction.updated_at = Utc::now().timestamp();
    transaction.state = next_state(&transaction);
    persist(store, &transaction)?;
    Ok(transaction)
}

pub(crate) fn resume(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<UpdateCoordination> {
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current = current_record_locked(store, record)?;
    let _shared_locks = store.shared_capability_locks(&current, &Capability::ALL)?;
    let mut transaction = load_path(&transaction_path(store, &record.deployment_id))?;
    if transaction.state == CoordinationState::Committed {
        return reconcile_committed_locked(store, &current, transaction);
    }
    validate_binding(&transaction, &current)?;
    if matches!(
        transaction.state,
        CoordinationState::Aborting | CoordinationState::Aborted
    ) {
        return Ok(transaction);
    }
    let mut repaired_pending_evidence = false;
    for step in transaction
        .steps
        .iter()
        .filter(|step| {
            step.owner.requires_external_evidence()
                && step.state == StepState::Pending
                && evidence_path_present(store, &transaction, &step.id)
        })
        .cloned()
        .collect::<Vec<_>>()
    {
        let evidence_path = accepted_evidence_path(store, &transaction, &step.id)?;
        let persisted_bytes = read_bounded_secure_file(
            &evidence_path,
            "persisted coordination evidence",
            true,
            MAX_EVIDENCE_BYTES,
        )?;
        let _accepted =
            validate_persisted_evidence(&current, &transaction, &step, &persisted_bytes)?;
        let step = transaction
            .steps
            .iter_mut()
            .find(|candidate| candidate.id == step.id)
            .expect("cloned coordination step exists in transaction");
        step.state = StepState::EvidenceAccepted;
        step.evidence_sha256 = Some(digest_bytes(&persisted_bytes));
        repaired_pending_evidence = true;
    }
    for step in transaction
        .steps
        .iter()
        .filter(|step| step.owner.requires_external_evidence())
    {
        if step.state != StepState::EvidenceAccepted {
            continue;
        }
        let evidence_path = accepted_evidence_path(store, &transaction, &step.id)?;
        let expected = step
            .evidence_sha256
            .as_deref()
            .context("accepted evidence has no persisted digest")?;
        let persisted_bytes = read_bounded_secure_file(
            &evidence_path,
            "persisted coordination evidence",
            true,
            MAX_EVIDENCE_BYTES,
        )?;
        let _accepted =
            validate_persisted_evidence(&current, &transaction, step, &persisted_bytes)?;
        if digest_bytes(&persisted_bytes) != expected {
            bail!("persisted coordination evidence was changed after acceptance");
        }
    }
    let recomputed_state = next_state(&transaction);
    if repaired_pending_evidence || transaction.state != recomputed_state {
        transaction.updated_at = Utc::now().timestamp();
        transaction.state = recomputed_state;
        persist(store, &transaction)?;
    }
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
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let current = current_record_locked(store, record)?;
    let _shared_locks = store.shared_capability_locks(&current, &Capability::ALL)?;
    complete_controller_step_locked(store, &current, transaction_id, step_id, evidence_sha256)
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
    let current = current_record_locked(store, current)?;
    let _shared_locks = store.shared_capability_locks(&current, &Capability::ALL)?;
    commit_controller_update_locked(
        store,
        &current,
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
    if transaction.state == CoordinationState::Committed {
        if transaction.transaction_id != transaction_id {
            bail!("committed update is bound to a different deployment transaction");
        }
        return reconcile_committed_locked(store, current, transaction);
    }
    validate_binding(&transaction, current)?;
    let next_revision = current
        .declaration_revision
        .checked_add(1)
        .context("deployment declaration revision overflow")?;
    if transaction.transaction_id != transaction_id
        || updated.deployment_id != current.deployment_id
        || updated.declaration_revision != next_revision
        || updated.active_release != transaction.target_release
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
    transaction.committed_declaration = Some(updated.clone());
    // Persist the commit intent before changing the declaration.  This is the
    // durable hand-off point for the two separate files: replay can either
    // perform the CAS or observe that it already succeeded.
    transaction.updated_at = Utc::now().timestamp();
    persist(store, &transaction)?;
    store.persist_declaration_cas_locked(current, updated)?;
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
    let transaction = if transaction.state == CoordinationState::Committed {
        reconcile_committed_locked(store, record, transaction)?
    } else {
        validate_binding(&transaction, record)?;
        transaction
    };
    if transaction.transaction_id != transaction_id
        || transaction.state != CoordinationState::Committed
    {
        bail!("only the committed active update transaction can be finalized");
    }
    let history = active.with_file_name(format!("update-{transaction_id}.json"));
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&active)
}

/// Archive a controller update that was unwound before its declaration commit.
///
/// The caller must first restore the previous runtime and database through the
/// deployment's recovery boundary.  This function owns only the coordination
/// journal transition; it never mutates the deployment declaration.
pub(crate) fn abort_controller_update_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction_id: &str,
) -> anyhow::Result<UpdateCoordination> {
    let active = transaction_path(store, &record.deployment_id);
    let mut transaction = load_path(&active)?;
    validate_binding(&transaction, record)?;
    if transaction.transaction_id != transaction_id {
        bail!("active update transaction changed before recovery was archived");
    }
    if transaction.state == CoordinationState::Committed {
        bail!("a committed update cannot be archived as aborted");
    }
    transaction.state = CoordinationState::Aborted;
    transaction.updated_at = Utc::now().timestamp();
    persist(store, &transaction)?;

    let history = active.with_file_name(format!("update-{transaction_id}.json"));
    match fs::symlink_metadata(&history) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let archived = load_path(&history)?;
            if archived != transaction {
                bail!("aborted update history conflicts with the active transaction");
            }
            remove_file_durable(&active)?;
            return Ok(transaction);
        }
        Ok(_) => bail!("aborted update history is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect aborted update history {}",
                    history.display()
                )
            });
        }
    }
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&active)?;
    Ok(transaction)
}

/// Persist the unwind decision before touching the legacy runtime/database
/// journal.  A crash after that journal is consumed must resume the abort, not
/// reinterpret its absence as permission to continue the update forward.
pub(crate) fn mark_controller_update_aborting_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction_id: &str,
) -> anyhow::Result<UpdateCoordination> {
    let active = transaction_path(store, &record.deployment_id);
    let mut transaction = load_path(&active)?;
    validate_binding(&transaction, record)?;
    if transaction.transaction_id != transaction_id {
        bail!("active update transaction changed before recovery intent was persisted");
    }
    match transaction.state {
        CoordinationState::Committed => bail!("a committed update cannot enter abort recovery"),
        CoordinationState::Aborting | CoordinationState::Aborted => return Ok(transaction),
        _ => {}
    }
    transaction.state = CoordinationState::Aborting;
    transaction.updated_at = Utc::now().timestamp();
    persist(store, &transaction)?;
    Ok(transaction)
}

/// Replay a committed declaration intent after either side of the declaration
/// CAS/journal persistence boundary.  This function deliberately leaves the
/// active transaction in place: the caller still owns audit/finalization.
fn reconcile_committed_locked(
    store: &DeploymentStore,
    current: &DeploymentRecord,
    mut transaction: UpdateCoordination,
) -> anyhow::Result<UpdateCoordination> {
    validate_committed_binding(&transaction, current)?;
    let Some(target) = transaction.committed_declaration.clone() else {
        // Transactions written by the pre-intent format can only be safely
        // resumed when their declaration revision already matches the active
        // declaration.  There is no durable target from which to reconstruct a
        // missing CAS, so fail closed otherwise.
        return Ok(transaction);
    };
    if current == &target {
        if transaction.declaration_revision != target.declaration_revision {
            transaction.declaration_revision = target.declaration_revision;
            transaction.updated_at = Utc::now().timestamp();
            persist(store, &transaction)?;
        }
        return Ok(transaction);
    }
    if current.declaration_revision != transaction.declaration_revision {
        bail!("committed deployment declaration differs from its durable update target");
    }
    store.persist_declaration_cas_locked(current, &target)?;
    transaction.declaration_revision = target.declaration_revision;
    transaction.updated_at = Utc::now().timestamp();
    persist(store, &transaction)?;
    Ok(transaction)
}

fn validate_committed_binding(
    transaction: &UpdateCoordination,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    if transaction.schema != TRANSACTION_SCHEMA || transaction.operation != "update" {
        bail!("unsupported coordination transaction");
    }
    if transaction.deployment_id != record.deployment_id {
        bail!("coordination transaction is bound to a different deployment");
    }
    validate_identifier(
        &transaction.transaction_id,
        "coordination transaction identifier",
    )?;
    if let Some(target) = &transaction.committed_declaration {
        target.validate()?;
        let target_is_next_revision = target.declaration_revision
            == transaction
                .declaration_revision
                .checked_add(1)
                .context("committed deployment declaration revision overflow")?;
        let target_is_recorded_revision =
            target.declaration_revision == transaction.declaration_revision;
        if target.deployment_id != transaction.deployment_id
            || target.active_release != transaction.target_release
            || (!target_is_next_revision && !target_is_recorded_revision)
        {
            bail!("committed update intent is not bound to the active transaction");
        }
        if record != target
            && (!target_is_next_revision
                || record.declaration_revision != transaction.declaration_revision)
        {
            bail!("deployment declaration changed during committed update recovery");
        }
    } else if transaction.declaration_revision != record.declaration_revision {
        bail!("deployment declaration changed after the coordination commit");
    }
    Ok(())
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
    validate_identifier(
        &transaction.transaction_id,
        "coordination transaction identifier",
    )?;
    if transaction.declaration_revision != record.declaration_revision {
        bail!("deployment declaration changed after the coordination plan was prepared");
    }
    Ok(())
}

fn current_record_locked(
    store: &DeploymentStore,
    expected: &DeploymentRecord,
) -> anyhow::Result<DeploymentRecord> {
    // Unit-level coordination can prepare a transaction before the declaration
    // is registered.  Production paths always have a declaration, in which
    // case reload_locked turns a stale caller snapshot into a fail-closed
    // error.
    if store.declaration_path(&expected.deployment_id).exists() {
        store.reload_locked(expected)
    } else {
        Ok(expected.clone())
    }
}

fn validate_evidence_input(
    input: &EvidenceInput,
    transaction: &UpdateCoordination,
    step: &CoordinationStep,
) -> anyhow::Result<()> {
    validate_evidence_binding(input, transaction, step)?;
    validate_freshness(input.issued_at, input.expires_at)
}

fn validate_evidence_binding(
    input: &EvidenceInput,
    transaction: &UpdateCoordination,
    step: &CoordinationStep,
) -> anyhow::Result<()> {
    if input.schema != EVIDENCE_SCHEMA {
        bail!("unsupported coordination evidence schema");
    }
    if input.deployment_id != transaction.deployment_id
        || input.transaction_id != transaction.transaction_id
    {
        bail!("coordination evidence is bound to a different deployment or transaction");
    }
    if input.step_id != step.id {
        bail!("coordination evidence step does not match the selected step");
    }
    if input.action != step.action {
        bail!("coordination evidence action does not match the coordination step");
    }
    if input.capability != step.capability {
        bail!("coordination evidence capability does not match the coordination step");
    }
    if input.kind != expected_evidence_kind(step)? {
        bail!("coordination evidence kind does not match the step owner and action");
    }
    validate_identifier(&input.step_id, "evidence step ID")?;
    validate_identifier(&input.capability, "evidence capability")?;
    validate_action(&input.action)?;
    validate_identifier(&input.reference_id, "evidence reference ID")?;
    validate_digest(&input.artifact_sha256, "evidence artifact SHA-256")?;
    if input.plan_sha256 != transaction.plan_sha256 {
        bail!("coordination evidence is bound to a different update plan");
    }
    validate_digest(&input.plan_sha256, "evidence plan SHA-256")?;
    if input.target_release != transaction.target_release {
        bail!("coordination evidence is bound to a different target release");
    }
    if input.nonce.is_empty() {
        bail!("coordination evidence nonce is empty");
    }
    validate_identifier(&input.nonce, "evidence nonce")?;
    if input.nonce.len() > 128 {
        bail!("coordination evidence nonce is too long");
    }
    Ok(())
}

fn expected_evidence_kind(step: &CoordinationStep) -> anyhow::Result<EvidenceKind> {
    if step.owner == StepOwner::UserRequired {
        return Ok(EvidenceKind::OperatorConfirmation);
    }
    step.expected_evidence_kind
        .context("provider-owned coordination step predates the signed evidence-kind contract")
}

fn validate_action(action: &str) -> anyhow::Result<()> {
    if action.is_empty() || action.len() > 256 || action.chars().any(char::is_control) {
        bail!("coordination evidence action is invalid");
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_freshness(issued_at: i64, expires_at: i64) -> anyhow::Result<()> {
    let now = Utc::now().timestamp();
    validate_freshness_at_acceptance(issued_at, expires_at, now)
}

fn validate_freshness_at_acceptance(
    issued_at: i64,
    expires_at: i64,
    accepted_at: i64,
) -> anyhow::Result<()> {
    if accepted_at <= 0 {
        bail!("coordination evidence acceptance time is invalid");
    }
    if issued_at <= 0 || expires_at <= issued_at {
        bail!("coordination evidence validity interval is invalid");
    }
    if issued_at > accepted_at.saturating_add(MAX_EVIDENCE_FUTURE_SKEW_SECONDS) {
        bail!("coordination evidence is issued too far in the future");
    }
    if issued_at < accepted_at.saturating_sub(MAX_EVIDENCE_AGE_SECONDS) {
        bail!("coordination evidence is too old");
    }
    if expires_at <= accepted_at {
        bail!("coordination evidence has expired");
    }
    if expires_at > issued_at.saturating_add(MAX_EVIDENCE_LIFETIME_SECONDS) {
        bail!("coordination evidence validity interval is too long");
    }
    Ok(())
}

fn verify_provider_evidence(
    record: &DeploymentRecord,
    transaction: &UpdateCoordination,
    step: &CoordinationStep,
    input: &EvidenceInput,
) -> anyhow::Result<()> {
    let encoded = input
        .signature
        .as_deref()
        .context("provider-owned evidence has no Ed25519 signature")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("provider-owned evidence signature is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes) != encoded {
        bail!("provider-owned evidence signature is not canonical base64url");
    }
    let signature = Signature::from_slice(&signature_bytes)
        .context("provider-owned evidence signature has invalid length")?;
    let verifying_key = load_provider_verifying_key(record, &step.capability)?;
    let payload = canonical_signing_payload(input, transaction)?;
    verifying_key
        .verify(&payload, &signature)
        .context("provider-owned evidence signature verification failed")
}

fn load_provider_verifying_key(
    record: &DeploymentRecord,
    capability: &str,
) -> anyhow::Result<VerifyingKey> {
    let resource_id = format!("provider-evidence:{capability}");
    let Some(SafeReference::DigestBoundFile { path, sha256: pin }) =
        record.resources.get(&resource_id)
    else {
        bail!("provider-owned evidence has no pinned provider verification key");
    };
    validate_digest(pin, "provider evidence verification key pin")?;
    let file = open_secure_regular_file(path, "provider evidence verification key", false)?;
    let mut bytes = Vec::new();
    file.take(MAX_PROVIDER_KEY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("failed to read provider evidence verification key")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROVIDER_KEY_BYTES {
        bail!("provider evidence verification key exceeds its size limit");
    }
    if digest_bytes(&bytes) != pin.as_str() {
        bail!("provider evidence verification key digest does not match its pin");
    }
    let key_bytes = if bytes.len() == 32 {
        bytes
    } else {
        let text = std::str::from_utf8(&bytes)
            .context("provider evidence verification key is not UTF-8")?;
        let decoded = URL_SAFE_NO_PAD
            .decode(text)
            .context("provider evidence verification key is not canonical base64url")?;
        if URL_SAFE_NO_PAD.encode(&decoded) != text {
            bail!("provider evidence verification key is not canonical base64url");
        }
        decoded
    };
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("provider evidence verification key has invalid length"))?;
    VerifyingKey::from_bytes(&key_bytes).context("provider evidence verification key is invalid")
}

fn reject_replayed_nonce(
    store: &DeploymentStore,
    transaction: &UpdateCoordination,
    nonce: &str,
) -> anyhow::Result<()> {
    for step in transaction
        .steps
        .iter()
        .filter(|step| step.owner.requires_external_evidence())
    {
        if step.state != StepState::EvidenceAccepted {
            continue;
        }
        let path = accepted_evidence_path(store, transaction, &step.id)?;
        let bytes = read_bounded_secure_file(
            &path,
            "persisted coordination evidence",
            true,
            MAX_EVIDENCE_BYTES,
        )?;
        let accepted: AcceptedEvidence =
            serde_json::from_slice(&bytes).context("persisted coordination evidence is invalid")?;
        if accepted.evidence.nonce == nonce {
            bail!("coordination evidence nonce was already accepted in this transaction");
        }
    }
    Ok(())
}

fn canonical_signing_payload(
    input: &EvidenceInput,
    transaction: &UpdateCoordination,
) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(&EvidenceSigningPayload {
        schema: input.schema,
        deployment_id: &input.deployment_id,
        transaction_id: &input.transaction_id,
        step_id: &input.step_id,
        kind: input.kind,
        action: &input.action,
        capability: &input.capability,
        reference_id: &input.reference_id,
        artifact_sha256: &input.artifact_sha256,
        plan_sha256: &input.plan_sha256,
        target_release: &input.target_release,
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        nonce: &input.nonce,
    })
    .context("failed to canonicalize coordination evidence payload")
    .and_then(|payload| {
        if input.plan_sha256 != transaction.plan_sha256
            || input.target_release != transaction.target_release
        {
            bail!("coordination evidence signing payload is not bound to this transaction");
        }
        Ok(payload)
    })
}

fn canonical_evidence_bytes(input: &EvidenceInput) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(input).context("failed to canonicalize coordination evidence")
}

fn validate_persisted_evidence(
    current: &DeploymentRecord,
    transaction: &UpdateCoordination,
    step: &CoordinationStep,
    persisted_bytes: &[u8],
) -> anyhow::Result<AcceptedEvidence> {
    let accepted: AcceptedEvidence = serde_json::from_slice(persisted_bytes)
        .context("persisted coordination evidence is invalid")?;
    if accepted.schema != EVIDENCE_SCHEMA {
        bail!("unsupported accepted coordination evidence schema");
    }
    validate_evidence_binding(&accepted.evidence, transaction, step)?;
    validate_freshness_at_acceptance(
        accepted.evidence.issued_at,
        accepted.evidence.expires_at,
        accepted.accepted_at,
    )?;
    if step.owner == StepOwner::ProviderOwned {
        verify_provider_evidence(current, transaction, step, &accepted.evidence)?;
    }
    let source_manifest_sha256 = digest_bytes(&canonical_evidence_bytes(&accepted.evidence)?);
    if accepted.source_manifest_sha256 != source_manifest_sha256 {
        bail!("accepted coordination evidence source digest does not match its payload");
    }
    if accepted.semantic_completion_claimed {
        bail!("coordination evidence must not claim semantic completion");
    }
    Ok(accepted)
}

fn read_bounded_secure_file(
    path: &Path,
    label: &str,
    private: bool,
    max_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    let file = open_secure_regular_file(path, label, private)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        bail!("{label} must be a regular file from 1 through {max_bytes} bytes");
    }
    Ok(bytes)
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
    transaction_id: &str,
    step_id: &str,
) -> std::path::PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("evidence")
        .join(transaction_id)
        .join(format!("{step_id}.json"))
}

fn legacy_evidence_path(
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

fn accepted_evidence_path(
    store: &DeploymentStore,
    transaction: &UpdateCoordination,
    step_id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let current = evidence_path(
        store,
        &transaction.deployment_id,
        &transaction.transaction_id,
        step_id,
    );
    match fs::symlink_metadata(&current) {
        Ok(_) => return Ok(current),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect transaction-scoped coordination evidence {}",
                    current.display()
                )
            });
        }
    }
    let legacy = legacy_evidence_path(store, &transaction.deployment_id, step_id);
    match fs::symlink_metadata(&legacy) {
        Ok(_) => Ok(legacy),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(current),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect legacy coordination evidence {}",
                legacy.display()
            )
        }),
    }
}

fn evidence_path_present(
    store: &DeploymentStore,
    transaction: &UpdateCoordination,
    step_id: &str,
) -> bool {
    let current = evidence_path(
        store,
        &transaction.deployment_id,
        &transaction.transaction_id,
        step_id,
    );
    if fs::symlink_metadata(&current).is_ok() {
        return true;
    }
    fs::symlink_metadata(legacy_evidence_path(
        store,
        &transaction.deployment_id,
        step_id,
    ))
    .is_ok()
}

fn load_path(path: &Path) -> anyhow::Result<UpdateCoordination> {
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "coordination transaction",
        true,
        4 * 1024 * 1024,
    )?;
    let transaction: UpdateCoordination =
        serde_json::from_slice(&bytes).context("coordination transaction is invalid")?;
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
