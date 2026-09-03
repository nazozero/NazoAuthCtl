//! One-authorization-per-operation dispatch glue (goal plan 05 §4/§5/§8 and
//! task E06, ctl half).
//!
//! The flow every top-level application-level mutation follows:
//!
//! ```text
//! prepare_control_operation
//!   ├─ journal hit + same canonical hash  → resume (same operation_id,
//!   │                                       byte-identical JWS)
//!   └─ no hit / changed content           → fresh attempt (new operation_id)
//! → dispatch via the execution target
//! → settle_journal: InProgressAccepted → mark; Terminal → mark, let the
//!   caller durably persist the exact result, then clear; DefinitivelyRejected
//!   → clear so the next attempt after fixing the cause mints a new id;
//!   OutcomeUnknown → keep the entry so a later run resumes instead of
//!   replacing the lost operation.
//! ```
//!
//! Invariant enforced end to end: `same operation_id ⇒ same request_hash ⇒
//! same operation`. A stored id is never reused for different content, and
//! unknown-outcome operations are never replaced by a new one.

use anyhow::{Context as _, bail};
use nazo_operator_protocol::{
    ControlOperationPayload, ControlOutcome, ControlResult, ControlResultData, constant_time_eq,
    validate_control_result,
};

use crate::controller_identity::journal::{JournalState, OperationJournal, OperationJournalEntry};
use crate::controller_identity::operation::{
    ControlOperationInput, SignedControlOperation, build_signed_control_operation_with_id,
};
use crate::registry::{InstanceRecord, RegistryStore};
use crate::target::{
    ControlOperationReceipt, ControlOperationRequest, ExecutionTarget, SecretMaterial,
};

use super::store::ControllerKeyStore;

/// How this prepared operation relates to the journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptKind {
    /// New operation id; the journal entry was written before return.
    Fresh,
    /// Rebuilt from the journal with the stored operation id.
    Resumed,
}

/// A signed operation plus its journal relationship. Dispatch callers send
/// exactly [`PreparedOperation::request`].
#[derive(Clone, Debug)]
pub struct PreparedOperation {
    pub signed: SignedControlOperation,
    pub kind: AttemptKind,
}

impl PreparedOperation {
    pub fn request(
        &self,
        change_set: Option<SecretMaterial>,
    ) -> anyhow::Result<ControlOperationRequest> {
        validate_control_change_set(
            &self.signed.operation.operation,
            change_set.as_ref().map(SecretMaterial::as_bytes),
        )?;
        Ok(ControlOperationRequest {
            operation_id: self.signed.operation_id.clone(),
            deployment_id: self.signed.deployment_id.clone(),
            compact_jws: self.signed.compact_jws.clone(),
            change_set,
        })
    }

    pub fn journal_entry(&self) -> OperationJournalEntry {
        OperationJournalEntry::new(
            self.signed.operation_id.clone(),
            self.signed.request_hash.clone(),
            self.signed.kid.clone(),
        )
    }
}

/// Enforce the single material-consumer rule before journaling or transport.
pub fn validate_control_change_set(
    operation: &ControlOperationPayload,
    change_set: Option<&[u8]>,
) -> anyhow::Result<()> {
    let apply = matches!(
        operation,
        ControlOperationPayload::TenantResourceApply { .. }
    );
    match (apply, change_set) {
        (true, None) => bail!("tenant-resource Apply requires change-set material"),
        (false, Some(_)) => bail!("only tenant-resource Apply accepts change-set material"),
        (true, Some([])) => bail!("change-set material must not be empty"),
        (true, Some(bytes)) if bytes.len() > crate::target::MAX_CONTROL_CHANGE_SET_BYTES => bail!(
            "change-set material exceeds the {}-byte limit",
            crate::target::MAX_CONTROL_CHANGE_SET_BYTES
        ),
        _ => Ok(()),
    }
}

/// What the target told ctl about one dispatch attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchVerdict {
    /// The server definitively refused BEFORE accepting (admission failure).
    /// No side effect can have happened, so a corrected retry may mint a new
    /// id.
    DefinitivelyRejected { code: String },
    /// No answer (crash, disconnect, timeout). The journaled identity must be
    /// kept: only a resumed resend can distinguish "lost response" from "never
    /// arrived".
    OutcomeUnknown,
    /// The server accepted the operation, but it has not completed. The local
    /// journal remains the authorization snapshot for a resumed poll.
    InProgressAccepted,
    /// The server returned the authoritative terminal result, whether
    /// succeeded or failed. The caller must durably persist this exact value;
    /// [`settle_journal`] clears the single-slot journal only after that
    /// persistence callback succeeds.
    Terminal(ControlResult),
}

/// Resolve a selector exactly like the signing helper does.
fn resolve_instance(registry: &RegistryStore, selector: &str) -> anyhow::Result<InstanceRecord> {
    if let Some(record) = registry.instance_by_deployment(selector)? {
        return Ok(record);
    }
    if let Some(record) = registry.instance_by_alias(selector)? {
        return Ok(record);
    }
    bail!("unknown instance selector '{selector}' (no registered deployment id or alias matches)")
}

/// Prepare one control operation for `instance_selector`, resuming the
/// journaled operation when the rebuilt envelope is byte-identical in hash.
///
/// Fresh attempts persist their write-ahead journal entry before returning;
/// resumed attempts leave the existing entry untouched.
pub fn prepare_control_operation(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    journal: &OperationJournal,
    instance_selector: &str,
    input: ControlOperationInput,
) -> anyhow::Result<PreparedOperation> {
    let record = resolve_instance(registry, instance_selector)?;

    let journaled = journal.load()?;
    if let Some(entry) = &journaled {
        // Resume only when the current active key can rebuild EXACTLY the
        // same canonical payload. Any difference (rotated kid, changed
        // revision/payload) means the stored id must never be replayed.
        let rebuilt = build_signed_control_operation_with_id(
            keys,
            &record,
            clone_input(&input),
            Some(&entry.operation_id),
        );
        if let Ok(signed) = rebuilt
            && signed.request_hash == entry.request_hash
            && signed.kid == entry.kid
        {
            return Ok(PreparedOperation {
                signed,
                kind: AttemptKind::Resumed,
            });
        }
        // P1-2: the journal slot is single-occupancy. A changed payload under
        // an existing entry used to mint a fresh id and silently overwrite
        // the old record, destroying the replay anchor for an operation that
        // may still be in flight server-side. Fail closed instead: the
        // operator settles (rerun identical inputs to reach a terminal
        // outcome) or clears the entry explicitly.
        bail!(
            "the operation journal holds '{}' ({:?}) for instance '{}' with DIFFERENT content; \
             refusing to sign a new operation. Re-run the previous command unchanged to settle \
             it, or remove the journal explicitly if that attempt was abandoned",
            entry.operation_id,
            entry.state,
            record.alias
        );
    }

    // Display observations are deliberately absent here. The live server's
    // admission response is the sole controller-validity/expiry decision.
    let signed = build_signed_control_operation_with_id(keys, &record, input, None)?;
    let prepared = PreparedOperation {
        signed,
        kind: AttemptKind::Fresh,
    };
    journal.record_dispatched(&prepared.journal_entry())?;
    Ok(prepared)
}

/// Rebuild the currently journaled operation only when `input` is its exact
/// canonical content. Unlike [`prepare_control_operation`], an empty or
/// different journal never mints a new operation id.
pub fn prepare_pending_control_operation(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    journal: &OperationJournal,
    expected: &OperationJournalEntry,
    instance_selector: &str,
    input: ControlOperationInput,
) -> anyhow::Result<Option<PreparedOperation>> {
    let record = resolve_instance(registry, instance_selector)?;
    let Some(entry) = journal.load()? else {
        return Ok(None);
    };
    if !entry.has_same_identity(expected) {
        bail!(
            "the operation journal changed while operation '{}' was being recovered",
            expected.operation_id
        );
    }
    let signed =
        build_signed_control_operation_with_id(keys, &record, input, Some(&entry.operation_id))?;
    if signed.request_hash != entry.request_hash || signed.kid != entry.kid {
        return Ok(None);
    }
    Ok(Some(PreparedOperation {
        signed,
        kind: AttemptKind::Resumed,
    }))
}

fn clone_input(input: &ControlOperationInput) -> ControlOperationInput {
    ControlOperationInput {
        operation: input.operation.clone(),
        config_revision: input.config_revision.clone(),
    }
}

/// Send one prepared operation through an execution target and classify the
/// outcome for [`settle_journal`].
pub fn dispatch_via_target(
    target: &dyn ExecutionTarget,
    prepared: &PreparedOperation,
    change_set: Option<SecretMaterial>,
) -> anyhow::Result<DispatchVerdict> {
    let receipt: ControlOperationReceipt =
        target.execute_control_operation(prepared.request(change_set)?)?;
    classify_receipt(prepared, receipt)
}

pub fn classify_control_receipt(
    prepared: &PreparedOperation,
    receipt: ControlOperationReceipt,
) -> anyhow::Result<DispatchVerdict> {
    classify_receipt(prepared, receipt)
}

fn classify_receipt(
    prepared: &PreparedOperation,
    receipt: ControlOperationReceipt,
) -> anyhow::Result<DispatchVerdict> {
    if receipt.operation_id != prepared.signed.operation_id {
        bail!(
            "target echoed operation id '{}' for request '{}'; refusing to interpret the result",
            receipt.operation_id,
            prepared.signed.operation_id
        );
    }

    if !receipt.accepted {
        if receipt.result.is_some() {
            bail!("a definitively rejected operation must not carry a ControlResult");
        }
        let code = receipt
            .rejection_code
            .context("a definitively rejected operation must carry a stable rejection code")?;
        return Ok(DispatchVerdict::DefinitivelyRejected { code });
    }

    let result = receipt
        .result
        .context("an accepted operation receipt must carry its durable ControlResult")?;
    validate_result_binding(prepared, &result)?;
    match result.outcome {
        ControlOutcome::InProgress => Ok(DispatchVerdict::InProgressAccepted),
        ControlOutcome::Succeeded | ControlOutcome::Failed => Ok(DispatchVerdict::Terminal(result)),
    }
}

fn validate_result_binding(
    prepared: &PreparedOperation,
    result: &ControlResult,
) -> anyhow::Result<()> {
    validate_control_result_binding(
        &prepared.signed.operation_id,
        &prepared.signed.request_hash,
        &prepared.signed.operation.operation,
        result,
    )
}

/// Validate one target result against the exact operation identity and closed
/// payload contract that produced it. This is the sole binding boundary shared
/// by ordinary dispatch and host-orchestrated operations such as Update.
pub fn validate_control_result_binding(
    expected_operation_id: &str,
    expected_request_hash: &str,
    expected_payload: &ControlOperationPayload,
    result: &ControlResult,
) -> anyhow::Result<()> {
    validate_control_result(result)
        .map_err(|error| anyhow::anyhow!("target returned an invalid ControlResult: {error}"))?;
    if result.operation_id != expected_operation_id {
        bail!(
            "ControlResult operation id '{}' does not match prepared operation '{}'",
            result.operation_id,
            expected_operation_id
        );
    }
    if !constant_time_eq(
        result.request_hash.as_bytes(),
        expected_request_hash.as_bytes(),
    ) {
        bail!(
            "ControlResult request hash does not match prepared operation '{}'",
            expected_operation_id
        );
    }
    validate_result_contract(expected_payload, result)?;
    Ok(())
}

fn validate_result_contract(
    operation: &ControlOperationPayload,
    result: &ControlResult,
) -> anyhow::Result<()> {
    if result.outcome != ControlOutcome::Succeeded {
        return Ok(());
    }

    let data = result.result.as_ref();
    let matches_operation = match operation {
        ControlOperationPayload::MigrateApply
        | ControlOperationPayload::KeysList
        | ControlOperationPayload::KeysValidate
        | ControlOperationPayload::KeysGenerateLocal { .. }
        | ControlOperationPayload::KeysRegisterExternal { .. } => data.is_none(),
        ControlOperationPayload::TenantKeysGenerateLocal { .. } => {
            matches!(data, Some(ControlResultData::TenantKeyGenerated { .. }))
        }
        ControlOperationPayload::TenantResourceApply { .. } => {
            matches!(data, Some(ControlResultData::TenantResourceApply { .. }))
        }
        ControlOperationPayload::TenantResourceEnumerate { .. } => matches!(
            data,
            Some(ControlResultData::TenantResourceEnumerate { .. })
        ),
        ControlOperationPayload::TenantResourceRevoke { .. } => {
            matches!(data, Some(ControlResultData::TenantResourceRevoke { .. }))
        }
        ControlOperationPayload::RecoveryInvalidate { .. } => {
            matches!(data, Some(ControlResultData::RecoveryInvalidation { .. }))
        }
        ControlOperationPayload::TenantDirectoryCreate { .. }
        | ControlOperationPayload::TenantDirectoryUpdate { .. }
        | ControlOperationPayload::TenantDirectoryDisable { .. }
        | ControlOperationPayload::TenantDirectoryReload { .. }
        | ControlOperationPayload::TenantDirectoryFinalize { .. } => matches!(
            data,
            Some(ControlResultData::TenantDirectoryMutation { .. })
        ),
        ControlOperationPayload::TenantDirectoryDescribe => matches!(
            data,
            Some(ControlResultData::TenantDirectoryDescribe { .. })
        ),
    };
    if !matches_operation {
        bail!("ControlResult data does not match the prepared operation contract");
    }
    Ok(())
}

/// Apply the verdict to the journal:
///
/// * DefinitivelyRejected → clear the entry; the next attempt after fixing
///   the cause mints a fresh id.
/// * OutcomeUnknown → keep the write-ahead entry untouched so a later run
///   resumes with the same operation id instead of issuing a new operation.
/// * InProgressAccepted → transition to `accepted` so a later run resumes.
/// * Terminal → transition to `accepted`, invoke `persist_terminal`, and
///   clear only after the callback reports that the exact result is durable.
///
/// A terminal persistence error deliberately leaves the journal accepted. A
/// later identical invocation can replay the same server result instead of
/// losing the only recovery anchor.
pub fn settle_journal(
    journal: &OperationJournal,
    prepared: &PreparedOperation,
    verdict: &DispatchVerdict,
    persist_terminal: impl FnOnce(&ControlResult) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let expected = prepared.journal_entry();
    match verdict {
        DispatchVerdict::DefinitivelyRejected { code }
            if code == crate::error_codes::OPERATION_ID_CONFLICT =>
        {
            Ok(())
        }
        DispatchVerdict::DefinitivelyRejected { .. } => journal.clear_if_matches(&expected),
        DispatchVerdict::OutcomeUnknown => Ok(()),
        DispatchVerdict::InProgressAccepted => journal.mark_accepted_if_matches(&expected),
        DispatchVerdict::Terminal(result) => {
            validate_result_binding(prepared, result)?;
            journal.mark_accepted_if_matches(&expected)?;
            persist_terminal(result).with_context(|| {
                format!(
                    "failed to persist terminal result for operation '{}'",
                    prepared.signed.operation_id
                )
            })?;
            journal.clear_if_matches(&expected)
        }
    }
}

/// True when the journal currently holds an accepted operation that has not
/// been superseded — surfaced by doctor/status style commands.
pub fn has_accepted_pending_result(journal: &OperationJournal) -> anyhow::Result<bool> {
    Ok(journal
        .load()?
        .is_some_and(|entry| entry.state == JournalState::Accepted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_identity::admin_api::SlotsSnapshot;
    use crate::controller_identity::expiry;
    use crate::controller_identity::journal::JournalState;
    use crate::controller_identity::store::{ControllerKeyStore, controller_key_ref_for};
    use crate::filesystem;
    use crate::registry::{InstanceRecord, ObservationCache};
    use crate::target::{
        HealthSnapshot, HostOperation, HostOverview, HostResult, InstanceInspection,
    };
    use nazo_operator_protocol::{
        CONTROL_RESULT_SCHEMA, ControlErrorCode, ControlOperation, ControlOperationPayload,
        TenantResourceIdentity, TenantResourceKind, control_operation_request_hash,
        verify_control_operation_signature,
    };
    use std::cell::RefCell;

    struct Fixture {
        _temp: filesystem::PrivateTempDir,
        registry: RegistryStore,
        keys: ControllerKeyStore,
        deployment: &'static str,
    }

    fn fixture() -> anyhow::Result<Fixture> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-dispatch-test")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        let keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        let host = registry.ensure_local_host()?;
        let mut instance = InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
        )?;
        instance.controller_key_ref = Some(controller_key_ref_for("deploy-alpha")?);
        registry.add_instance(instance)?;
        Ok(Fixture {
            _temp: temp,
            registry,
            keys,
            deployment: "deploy-alpha",
        })
    }

    impl Fixture {
        fn journal(&self) -> anyhow::Result<OperationJournal> {
            OperationJournal::open(self.keys.instance_dir(self.deployment)?)
        }
    }

    fn input(revision: &str) -> ControlOperationInput {
        ControlOperationInput {
            operation: ControlOperationPayload::MigrateApply,
            config_revision: revision.to_owned(),
        }
    }

    fn apply_input(revision: &str) -> ControlOperationInput {
        let mut input = input(revision);
        input.operation = ControlOperationPayload::TenantResourceApply {
            tenant_id: "018f0000-0000-7000-8000-000000000001".to_owned(),
            resources: vec![TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: "suite-user".to_owned(),
                digest: "ab".repeat(32),
            }],
        };
        input
    }

    /// Target double recording executed control requests; optionally answers
    /// acceptance per call.
    #[derive(Default)]
    struct RecordingTarget {
        executed: RefCell<Vec<RecordedControlRequest>>,
        accept_next: RefCell<Vec<bool>>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedControlRequest {
        operation_id: String,
        deployment_id: String,
        compact_jws: String,
        change_set_len: Option<usize>,
    }

    impl RecordingTarget {
        fn push_acceptance(&self, accepted: bool) {
            self.accept_next.borrow_mut().push(accepted);
        }
    }

    impl ExecutionTarget for RecordingTarget {
        fn inspect_host(&self) -> anyhow::Result<HostOverview> {
            anyhow::bail!("unused")
        }

        fn inspect_instance(&self, _: &str) -> anyhow::Result<InstanceInspection> {
            anyhow::bail!("unused")
        }

        fn execute_host_operation(&self, _: &HostOperation) -> anyhow::Result<HostResult> {
            anyhow::bail!("unused")
        }

        fn execute_control_operation(
            &self,
            request: ControlOperationRequest,
        ) -> anyhow::Result<ControlOperationReceipt> {
            let accepted = self
                .accept_next
                .borrow_mut()
                .pop()
                .expect("scripted acceptance missing");
            let operation = decode_control_operation(&request.compact_jws)?;
            self.executed.borrow_mut().push(RecordedControlRequest {
                operation_id: request.operation_id,
                deployment_id: request.deployment_id,
                compact_jws: request.compact_jws,
                change_set_len: request
                    .change_set
                    .as_ref()
                    .map(|value| value.as_bytes().len()),
            });
            Ok(ControlOperationReceipt {
                operation_id: operation.operation_id.clone(),
                accepted,
                result: accepted.then(|| valid_result(&operation, ControlOutcome::InProgress)),
                rejection_code: (!accepted).then(|| "REJECTED".to_owned()),
            })
        }

        fn read_health(&self, _: &str) -> anyhow::Result<HealthSnapshot> {
            anyhow::bail!("unused")
        }
    }

    /// Decode the payload back out of the JWS to echo its operation id like a
    /// real target would.
    fn decode_control_operation(compact_jws: &str) -> anyhow::Result<ControlOperation> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = compact_jws.split('.').nth(1).context("malformed jws")?;
        let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn valid_result(operation: &ControlOperation, outcome: ControlOutcome) -> ControlResult {
        ControlResult {
            schema: CONTROL_RESULT_SCHEMA,
            operation_id: operation.operation_id.clone(),
            request_hash: control_operation_request_hash(operation).expect("valid operation"),
            outcome,
            error: (outcome == ControlOutcome::Failed).then_some(ControlErrorCode::ExecutionFailed),
            accepted_at: 100,
            completed_at: (outcome != ControlOutcome::InProgress).then_some(101),
            result: None,
        }
    }

    #[test]
    fn dynamic_tenant_results_match_their_operation_contracts() {
        let mut result = ControlResult {
            schema: CONTROL_RESULT_SCHEMA,
            operation_id: "01a05c08-1fc8-72d2-a05e-480753f2b01b".to_owned(),
            request_hash: "ab".repeat(32),
            outcome: ControlOutcome::Succeeded,
            error: None,
            accepted_at: 100,
            completed_at: Some(101),
            result: Some(ControlResultData::TenantDirectoryDescribe {
                revision: 1,
                tenants: Vec::new(),
            }),
        };
        assert!(
            validate_result_contract(&ControlOperationPayload::TenantDirectoryDescribe, &result)
                .is_ok()
        );

        result.result = Some(ControlResultData::TenantDirectoryMutation {
            action: "disable".to_owned(),
            tenant_id: "018f0000-0000-7000-8000-000000000001".to_owned(),
            previous_revision: 1,
            revision: 2,
        });
        assert!(
            validate_result_contract(
                &ControlOperationPayload::TenantDirectoryDisable {
                    expected_revision: 1,
                    tenant_id: "018f0000-0000-7000-8000-000000000001".to_owned(),
                },
                &result,
            )
            .is_ok()
        );
        assert!(
            validate_result_contract(&ControlOperationPayload::TenantDirectoryDescribe, &result)
                .is_err()
        );
    }

    fn valid_receipt(
        prepared: &PreparedOperation,
        outcome: ControlOutcome,
    ) -> ControlOperationReceipt {
        ControlOperationReceipt {
            operation_id: prepared.signed.operation_id.clone(),
            accepted: true,
            result: Some(valid_result(&prepared.signed.operation, outcome)),
            rejection_code: None,
        }
    }

    fn attach_expired_observation(fixture: &Fixture) -> anyhow::Result<()> {
        let fact_line = format!(
            "controller-slots n=1 max=3 | c-1:{}:active:{}",
            fixture.keys.load_active("deploy-alpha")?.unwrap().kid(),
            (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()
        );
        fixture
            .registry
            .set_instance_observation("deploy-alpha", ObservationCache::now(true, fact_line))?;
        Ok(())
    }

    #[test]
    fn fresh_attempt_journals_before_dispatch_and_accepts_settle_accepted() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;
        assert!(journal.load()?.is_none());

        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        assert_eq!(prepared.kind, AttemptKind::Fresh);
        let entry = journal.load()?.expect("write-ahead entry");
        assert_eq!(entry.operation_id, prepared.signed.operation_id);
        assert_eq!(entry.state, JournalState::Dispatched);

        let target = RecordingTarget::default();
        target.push_acceptance(true);
        let verdict = dispatch_via_target(&target, &prepared, None)?;
        assert_eq!(verdict, DispatchVerdict::InProgressAccepted);
        settle_journal(&journal, &prepared, &verdict, |_| {
            anyhow::bail!("in-progress verdict must not invoke terminal persistence")
        })?;
        assert_eq!(journal.load()?.expect("kept").state, JournalState::Accepted);
        assert_eq!(target.executed.borrow().len(), 1);
        Ok(())
    }

    #[test]
    fn terminal_result_is_preserved_until_caller_persistence_succeeds() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;
        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;

        for outcome in [ControlOutcome::Succeeded, ControlOutcome::Failed] {
            let verdict = classify_receipt(&prepared, valid_receipt(&prepared, outcome))?;
            assert!(matches!(
                &verdict,
                DispatchVerdict::Terminal(result) if result.outcome == outcome
            ));
        }

        let verdict = classify_receipt(
            &prepared,
            valid_receipt(&prepared, ControlOutcome::Succeeded),
        )?;
        let persistence_error = settle_journal(&journal, &prepared, &verdict, |_| {
            anyhow::bail!("durable result store unavailable")
        })
        .expect_err("callback failure must abort settlement");
        assert!(
            format!("{persistence_error:#}").contains("durable result store unavailable"),
            "{persistence_error:#}"
        );
        assert_eq!(
            journal.load()?.expect("replay anchor retained").state,
            JournalState::Accepted
        );

        let persisted = RefCell::new(None);
        settle_journal(&journal, &prepared, &verdict, |result| {
            persisted.replace(Some(result.clone()));
            Ok(())
        })?;
        assert_eq!(
            persisted.borrow().as_ref(),
            match &verdict {
                DispatchVerdict::Terminal(result) => Some(result),
                _ => None,
            }
        );
        assert!(journal.load()?.is_none(), "terminal journal slot cleared");
        Ok(())
    }

    #[test]
    fn malformed_or_misbinding_receipts_are_rejected() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;
        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;

        let mut receipt = valid_receipt(&prepared, ControlOutcome::Succeeded);
        receipt.operation_id = "01900000-0000-7000-8000-000000000001".to_owned();
        assert!(classify_receipt(&prepared, receipt).is_err());

        let mut receipt = valid_receipt(&prepared, ControlOutcome::Succeeded);
        receipt.result.as_mut().unwrap().operation_id =
            "01900000-0000-7000-8000-000000000002".to_owned();
        assert!(classify_receipt(&prepared, receipt).is_err());

        let mut receipt = valid_receipt(&prepared, ControlOutcome::Succeeded);
        receipt.result.as_mut().unwrap().request_hash = "cd".repeat(32);
        assert!(classify_receipt(&prepared, receipt).is_err());

        let mut receipt = valid_receipt(&prepared, ControlOutcome::Succeeded);
        receipt.result.as_mut().unwrap().error = Some(ControlErrorCode::ExecutionFailed);
        assert!(classify_receipt(&prepared, receipt).is_err());

        let mut receipt = valid_receipt(&prepared, ControlOutcome::Succeeded);
        receipt.result.as_mut().unwrap().result =
            Some(ControlResultData::TenantResourceEnumerate {
                revision: 1,
                resources: vec![],
                resource_manifest_sha256: "ab".repeat(32),
            });
        assert!(classify_receipt(&prepared, receipt).is_err());

        let accepted_without_result = ControlOperationReceipt {
            operation_id: prepared.signed.operation_id.clone(),
            accepted: true,
            result: None,
            rejection_code: None,
        };
        assert!(classify_receipt(&prepared, accepted_without_result).is_err());

        let rejected_with_result = ControlOperationReceipt {
            operation_id: prepared.signed.operation_id.clone(),
            accepted: false,
            result: Some(valid_result(
                &prepared.signed.operation,
                ControlOutcome::Failed,
            )),
            rejection_code: Some("REJECTED".to_owned()),
        };
        assert!(classify_receipt(&prepared, rejected_with_result).is_err());
        Ok(())
    }

    #[test]
    fn only_apply_accepts_one_bounded_change_set() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;
        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            apply_input("rev-1"),
        )?;
        assert!(prepared.request(None).is_err());
        assert!(SecretMaterial::try_new(Vec::new()).is_err());
        assert!(
            validate_control_change_set(&prepared.signed.operation.operation, Some(&[])).is_err()
        );
        let oversized = vec![0; crate::target::MAX_CONTROL_CHANGE_SET_BYTES + 1];
        assert!(
            validate_control_change_set(&prepared.signed.operation.operation, Some(&oversized))
                .is_err()
        );
        assert_eq!(
            prepared
                .request(Some(SecretMaterial::try_new(b"material".to_vec())?))?
                .change_set
                .as_ref()
                .map(SecretMaterial::as_bytes),
            Some(b"material".as_slice())
        );

        journal.clear()?;
        let non_apply = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        assert!(
            non_apply
                .request(Some(SecretMaterial::try_new(b"unused".to_vec())?))
                .is_err()
        );
        assert!(non_apply.request(None).is_ok());
        Ok(())
    }

    #[test]
    fn crash_resume_reuses_the_stored_operation_id_byte_identically() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;

        // Crash happens here; nothing was settled. A new process prepares the
        // SAME logical operation again.
        let second = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        assert_eq!(second.kind, AttemptKind::Resumed);
        assert_eq!(second.signed.operation_id, first.signed.operation_id);
        assert_eq!(second.signed.compact_jws, first.signed.compact_jws);
        assert_eq!(second.signed.request_hash, first.signed.request_hash);

        // Both dispatches carry the identical id: the seam sees two sends of
        // ONE operation, which the server dedupes by id+hash — never two
        // side effects.
        let target = RecordingTarget::default();
        target.push_acceptance(true);
        target.push_acceptance(true);
        let v1 = dispatch_via_target(&target, &first, None)?;
        assert_eq!(v1, DispatchVerdict::InProgressAccepted);
        // A crash before settle is harmless: the resume path still works.
        let v2 = dispatch_via_target(&target, &second, None)?;
        assert_eq!(v2, DispatchVerdict::InProgressAccepted);
        settle_journal(&journal, &second, &v2, |_| {
            anyhow::bail!("in-progress verdict must not invoke terminal persistence")
        })?;

        let sent = target.executed.borrow().clone();
        assert_eq!(sent.len(), 2, "resumed once");
        assert_eq!(sent[0], sent[1], "byte-identical request resent");
        Ok(())
    }

    #[test]
    fn definitive_rejection_clears_the_journal_so_retry_mints_new_id() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        let target = RecordingTarget::default();
        target.push_acceptance(false);
        let verdict = dispatch_via_target(&target, &first, None)?;
        assert_eq!(
            verdict,
            DispatchVerdict::DefinitivelyRejected {
                code: "REJECTED".to_owned()
            }
        );
        settle_journal(&journal, &first, &verdict, |_| {
            anyhow::bail!("rejected verdict must not invoke terminal persistence")
        })?;
        assert!(journal.load()?.is_none(), "rejected entry cleared");

        // After FIXING THE CAUSE (here: config revision bump) the next attempt
        // is genuinely fresh with a new operation id.
        let second = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-2"),
        )?;
        assert_eq!(second.kind, AttemptKind::Fresh);
        assert_ne!(second.signed.operation_id, first.signed.operation_id);
        Ok(())
    }

    #[test]
    fn unknown_outcome_resume_ignores_stale_display_summary() -> anyhow::Result<()> {
        let f = fixture()?;
        let key = f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        // Nothing settles: transport died mid-flight.

        attach_expired_observation(&f)?;

        // A stale display summary has no place in the dispatch decision.
        let resumed = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        assert_eq!(resumed.kind, AttemptKind::Resumed);
        assert_eq!(resumed.signed.operation_id, first.signed.operation_id);
        drop(key);
        Ok(())
    }

    #[test]
    fn stale_expiry_summary_does_not_block_fresh_dispatch_and_server_rejection_wins()
    -> anyhow::Result<()> {
        let f = fixture()?;
        let key = f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        attach_expired_observation(&f)?;
        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-9"),
        )?;
        assert_eq!(prepared.kind, AttemptKind::Fresh);
        assert!(
            journal.load()?.is_some(),
            "fresh attempt is signed and journaled"
        );

        let verdict = classify_receipt(
            &prepared,
            ControlOperationReceipt {
                operation_id: prepared.signed.operation_id.clone(),
                accepted: false,
                result: None,
                rejection_code: Some(crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED.to_owned()),
            },
        )?;
        assert_eq!(
            verdict,
            DispatchVerdict::DefinitivelyRejected {
                code: crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED.to_owned()
            }
        );
        settle_journal(&journal, &prepared, &verdict, |_| {
            anyhow::bail!("definitive server rejection has no terminal result")
        })?;
        assert!(journal.load()?.is_none());
        drop(key);
        Ok(())
    }

    #[test]
    fn changed_content_after_unknown_outcome_mints_a_new_id_but_only_for_a_fixed_cause()
    -> anyhow::Result<()> {
        // P1-2 boundary: the journal slot is single-occupancy. Changed content
        // under an existing entry used to mint a new id and silently overwrite
        // the old record, destroying the replay anchor for an operation that
        // might still be in flight server-side. It now fails closed and the
        // journaled operation id is preserved untouched.
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        let error =
            prepare_control_operation(&f.registry, &f.keys, &journal, "production", input("rev-2"))
                .expect_err("a conflicting payload must not steal the journal slot");
        assert!(
            error
                .to_string()
                .contains("DIFFERENT content; refusing to sign"),
            "{error}"
        );
        assert_eq!(
            journal.load()?.unwrap().operation_id,
            first.signed.operation_id
        );
        Ok(())
    }

    #[test]
    fn resume_only_requires_the_exact_existing_operation() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;
        let absent = OperationJournalEntry::new(
            uuid::Uuid::now_v7().to_string(),
            "ab".repeat(32),
            f.keys
                .get_or_create_active("deploy-alpha")?
                .kid()
                .to_owned(),
        );

        assert!(
            prepare_pending_control_operation(
                &f.registry,
                &f.keys,
                &journal,
                &absent,
                "production",
                input("rev-1"),
            )?
            .is_none()
        );
        assert!(journal.load()?.is_none());

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        let expected = journal.load()?.context("journaled operation")?;
        assert!(
            prepare_pending_control_operation(
                &f.registry,
                &f.keys,
                &journal,
                &expected,
                "production",
                input("rev-2"),
            )?
            .is_none()
        );
        assert_eq!(
            journal.load()?.unwrap().operation_id,
            first.signed.operation_id
        );

        let resumed = prepare_pending_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            &expected,
            "production",
            input("rev-1"),
        )?
        .context("exact pending operation must be recoverable")?;
        assert_eq!(resumed.kind, AttemptKind::Resumed);
        assert_eq!(resumed.signed.operation_id, first.signed.operation_id);
        assert_eq!(resumed.signed.request_hash, first.signed.request_hash);
        assert_eq!(resumed.signed.kid, first.signed.kid);
        assert_eq!(resumed.signed.compact_jws, first.signed.compact_jws);
        Ok(())
    }

    #[test]
    fn signature_verifies_against_the_store_for_resumed_envelopes() -> anyhow::Result<()> {
        let f = fixture()?;
        let store_key = f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        let first = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        let resumed = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-1"),
        )?;
        let decoded = verify_control_operation_signature(
            &resumed.signed.compact_jws,
            store_key.kid(),
            &store_key.verifying_key(),
        )?;
        assert_eq!(decoded.operation_id, first.signed.operation_id);

        // Slots snapshot helpers stay importable for command layers.
        let empty: SlotsSnapshot = SlotsSnapshot {
            deployment_id: "d".to_owned(),
            total: 0,
            max_active_slots: 3,
            items: vec![],
        };
        assert!(!expiry::has_active_slot(&empty));
        Ok(())
    }
}
