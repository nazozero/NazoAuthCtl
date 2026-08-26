//! One-authorization-per-operation dispatch glue (goal plan 05 §4/§5/§8 and
//! task E06, ctl half).
//!
//! The flow every top-level application-level mutation follows:
//!
//! ```text
//! prepare_control_operation
//!   ├─ journal hit + same canonical hash  → resume (same operation_id,
//!   │                                       byte-identical JWS, no expiry
//!   │                                       re-check: accepted state is the
//!   │                                       authorization snapshot, 05 §5)
//!   └─ no hit / changed content           → fresh attempt (new operation_id;
//!                                           D09 expiry pre-screen runs BEFORE
//!                                           signing)
//! → dispatch via the execution target
//! → settle_journal: Accepted → mark; DefinitivelyRejected → clear so the next
//!   attempt after fixing the cause mints a new id; OutcomeUnknown → keep the
//!   entry so a later run resumes instead of replacing the lost operation.
//! ```
//!
//! Invariant enforced end to end: `same operation_id ⇒ same request_hash ⇒
//! same operation`. A stored id is never reused for different content, and
//! unknown-outcome operations are never replaced by a new one.

use anyhow::{Context as _, bail};
use chrono::Utc;

use crate::controller_identity::expiry::{self, CachedSlotFact, ExpiryStatus, rotate_guidance};
use crate::controller_identity::journal::{JournalState, OperationJournal, OperationJournalEntry};
use crate::controller_identity::operation::{
    ControlOperationInput, SignedControlOperation, build_signed_control_operation_with_id,
    deployment_from_key_ref,
};
use crate::registry::{InstanceRecord, RegistryStore};
use crate::target::{ControlOperationReceipt, ControlOperationRequest, ExecutionTarget};

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
    pub fn request(&self) -> ControlOperationRequest {
        ControlOperationRequest {
            deployment_id: self.signed.deployment_id.clone(),
            compact_jws: self.signed.compact_jws.clone(),
        }
    }

    pub fn journal_entry(&self) -> OperationJournalEntry {
        OperationJournalEntry::new(
            self.signed.operation_id.clone(),
            self.signed.request_hash.clone(),
            self.signed.kid.clone(),
        )
    }
}

/// What the target told ctl about one dispatch attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchVerdict {
    /// The server-side journal accepted (or had already accepted) the
    /// operation; its result is authoritative and durable.
    Accepted,
    /// The server definitively refused BEFORE accepting (admission failure).
    /// No side effect can have happened, so a corrected retry may mint a new
    /// id.
    DefinitivelyRejected,
    /// No answer (crash, disconnect, timeout). The journaled identity must be
    /// kept: only a resumed resend can distinguish "lost response" from "never
    /// arrived".
    OutcomeUnknown,
    /// The operation was accepted and executed to a durable FAILED result.
    /// The business side effect did not succeed; lifecycle callers must stop
    /// instead of continuing (P0-5). The record stays terminal for its id:
    /// rerunning the same inputs replays the same durable failure.
    FailedDurably {
        outcome: nazo_operator_protocol::ControlResult,
    },
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

/// D09 pre-screen for FRESH attempts: consult only cached server facts. An
/// expired active identity fails BEFORE signing with rotate guidance; warning
/// windows print to stderr but never block. Absent cache entries cannot gate
/// anything — the server stays the authority at admission time.
fn guard_fresh_operation_expiry(
    record: &InstanceRecord,
    facts: &[CachedSlotFact],
    active_kid: &str,
) -> anyhow::Result<()> {
    let Some(fact) = expiry::cached_fact_for(facts, active_kid) else {
        return Ok(());
    };
    match ExpiryStatus::classify(Utc::now(), fact.expires_at) {
        ExpiryStatus::Expired { seconds_overdue } => {
            bail!(
                "{CONTROLLER_KEY_EXPIRED}: the controller key of instance '{}' expired {} ago \
                 according to the last server observation; {} \
                 (refresh with `controller slots` after rotating — the NazoAuth server makes \
                 the final decision)",
                record.alias,
                expiry::human_duration(seconds_overdue),
                rotate_guidance(&record.alias)
            )
        }
        status @ (ExpiryStatus::Urgent { .. } | ExpiryStatus::Warning { .. }) => {
            eprintln!(
                "nazauthctl: warning: controller key of instance '{}' {}: {}",
                record.alias,
                status.render(),
                rotate_guidance(&record.alias)
            );
            Ok(())
        }
        ExpiryStatus::Ok { .. } => Ok(()),
    }
}

/// Stable error code surfaced when a fresh operation is refused locally.
///
/// Canonical name lives in [`crate::error_codes`]; re-exported here so the
/// historical call sites keep one stable path.
pub use crate::error_codes::CONTROLLER_KEY_EXPIRED;

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
    if record.controller_key_ref.is_some() {
        let ref_deployment =
            deployment_from_key_ref(record.controller_key_ref.as_deref().with_context(|| {
                format!("instance '{}' lost its controller key ref", record.alias)
            })?)?;
        if ref_deployment != record.deployment_id {
            bail!(
                "instance '{}' carries a mismatched controller key ref ('{ref_deployment}' vs \
                 '{}'); refusing to sign",
                record.alias,
                record.deployment_id
            );
        }
    }

    let journaled = journal.load()?;
    if let Some(entry) = &journaled {
        // Resume only when the current active key can rebuild EXACTLY the
        // same canonical payload. Any difference (rotated kid, changed
        // revision/payload) means the stored id must never be replayed.
        let rebuilt = build_signed_control_operation_with_id(
            registry,
            keys,
            &record.deployment_id,
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

    // Fresh attempt: expiry pre-screen BEFORE signing (D09), keyed on the
    // active kid that is about to sign.
    let cached = record
        .last_observation
        .as_ref()
        .and_then(|observation| expiry::parse_cached_slots(&observation.summary))
        .unwrap_or_default();
    let active_kid = keys
        .load_active(&record.deployment_id)?
        .map(|loaded| loaded.kid().to_owned())
        .with_context(|| {
            format!(
                "instance '{}' has no locally stored active controller key",
                record.alias
            )
        })?;
    guard_fresh_operation_expiry(&record, &cached, &active_kid)?;

    let signed =
        build_signed_control_operation_with_id(registry, keys, &record.deployment_id, input, None)?;
    let prepared = PreparedOperation {
        signed,
        kind: AttemptKind::Fresh,
    };
    journal.record_dispatched(&prepared.journal_entry())?;
    Ok(prepared)
}

fn clone_input(input: &ControlOperationInput) -> ControlOperationInput {
    ControlOperationInput {
        operation: input.operation.clone(),
        artifact_target: input.artifact_target.clone(),
        config_revision: input.config_revision.clone(),
    }
}

/// Send one prepared operation through an execution target and classify the
/// outcome for [`settle_journal`].
pub fn dispatch_via_target(
    target: &dyn ExecutionTarget,
    prepared: &PreparedOperation,
) -> anyhow::Result<DispatchVerdict> {
    let receipt: ControlOperationReceipt = target.execute_control_operation(&prepared.request())?;
    if receipt.operation_id != prepared.signed.operation_id {
        bail!(
            "target echoed operation id '{}' for request '{}'; refusing to interpret the result",
            receipt.operation_id,
            prepared.signed.operation_id
        );
    }
    if receipt.accepted {
        // A durable terminal result rides with the receipt when the target
        // produced one. A FAILED business outcome must be visible to callers:
        // acceptance only means the operation was journaled, never that the
        // migration/keys work succeeded (P0-5).
        if let Some(result) = &receipt.result
            && result.outcome == nazo_operator_protocol::ControlOutcome::Failed
        {
            return Ok(DispatchVerdict::FailedDurably {
                outcome: result.clone(),
            });
        }
        Ok(DispatchVerdict::Accepted)
    } else {
        Ok(DispatchVerdict::DefinitivelyRejected)
    }
}

/// Apply the verdict to the journal:
///
/// * Accepted → transition to `accepted` (authorization snapshot lives on).
/// * DefinitivelyRejected → clear the entry; the next attempt after fixing
///   the cause mints a fresh id.
/// * OutcomeUnknown → keep the write-ahead entry untouched so a later run
///   resumes with the same operation id instead of issuing a new operation.
pub fn settle_journal(
    journal: &OperationJournal,
    prepared: &PreparedOperation,
    verdict: &DispatchVerdict,
) -> anyhow::Result<()> {
    match verdict {
        DispatchVerdict::Accepted => journal.mark_accepted(&prepared.signed.operation_id),
        // A durably failed business result is terminal for this id: the
        // record stays accepted so rerunning identical inputs replays the
        // identical durable failure instead of re-executing (P0-5).
        DispatchVerdict::FailedDurably { .. } => {
            journal.mark_accepted(&prepared.signed.operation_id)
        }
        DispatchVerdict::DefinitivelyRejected => journal.clear(),
        DispatchVerdict::OutcomeUnknown => Ok(()),
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
    use crate::controller_identity::journal::JournalState;
    use crate::controller_identity::store::{ControllerKeyStore, controller_key_ref_for};
    use crate::filesystem;
    use crate::registry::{InstanceRecord, ObservationCache};
    use crate::target::{
        HealthSnapshot, HostOperation, HostOverview, HostResult, InstanceInspection,
    };
    use nazo_operator_protocol::{
        ControlBuildIdentity, ControlOperationPayload, ControlTarget,
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
            "ref",
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
            artifact_target: ControlTarget::HostBinary {
                sha256: "ab".repeat(32),
                embedded: ControlBuildIdentity {
                    product: "nazauth".to_owned(),
                    version: "1.0.0".to_owned(),
                    commit: "9f2c1a7".to_owned(),
                },
            },
            config_revision: revision.to_owned(),
        }
    }

    /// Target double recording executed control requests; optionally answers
    /// acceptance per call.
    #[derive(Default)]
    struct RecordingTarget {
        executed: RefCell<Vec<ControlOperationRequest>>,
        accept_next: RefCell<Vec<bool>>,
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
            request: &ControlOperationRequest,
        ) -> anyhow::Result<ControlOperationReceipt> {
            self.executed.borrow_mut().push(request.clone());
            let accepted = self
                .accept_next
                .borrow_mut()
                .pop()
                .expect("scripted acceptance missing");
            Ok(ControlOperationReceipt {
                operation_id: extract_operation_id(&request.compact_jws)?,
                accepted,
                result: None,
            })
        }

        fn read_health(&self, _: &str) -> anyhow::Result<HealthSnapshot> {
            anyhow::bail!("unused")
        }
    }

    /// Decode the payload back out of the JWS to echo its operation id like a
    /// real target would.
    fn extract_operation_id(compact_jws: &str) -> anyhow::Result<String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = compact_jws.split('.').nth(1).context("malformed jws")?;
        let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes())?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok(value["operation_id"]
            .as_str()
            .context("missing operation_id")?
            .to_owned())
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
        let verdict = dispatch_via_target(&target, &prepared)?;
        assert_eq!(verdict, DispatchVerdict::Accepted);
        settle_journal(&journal, &prepared, &verdict)?;
        assert_eq!(journal.load()?.expect("kept").state, JournalState::Accepted);
        assert_eq!(target.executed.borrow().len(), 1);
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
        let v1 = dispatch_via_target(&target, &first)?;
        assert_eq!(v1, DispatchVerdict::Accepted);
        // A crash before settle is harmless: the resume path still works.
        let v2 = dispatch_via_target(&target, &second)?;
        assert_eq!(v2, DispatchVerdict::Accepted);
        settle_journal(&journal, &second, &v2)?;

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
        let verdict = dispatch_via_target(&target, &first)?;
        assert_eq!(verdict, DispatchVerdict::DefinitivelyRejected);
        settle_journal(&journal, &first, &verdict)?;
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
    fn unknown_outcome_keeps_the_entry_and_resume_does_not_recheck_expiry() -> anyhow::Result<()> {
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

        // Resume must NOT be blocked by the now-expired cached view: the
        // authorization snapshot owns the decision (05 §5 / D09).
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
    fn fresh_operations_fail_before_signing_when_cache_says_expired() -> anyhow::Result<()> {
        let f = fixture()?;
        let key = f.keys.get_or_create_active("deploy-alpha")?;
        let journal = f.journal()?;

        attach_expired_observation(&f)?;
        let error =
            prepare_control_operation(&f.registry, &f.keys, &journal, "production", input("rev-9"))
                .expect_err("expired identity");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(CONTROLLER_KEY_EXPIRED), "{rendered}");
        assert!(
            rendered.contains("controller rotate --instance production"),
            "{rendered}"
        );
        // Nothing was journaled or minted for the failed attempt.
        assert!(journal.load()?.is_none());
        drop(key);

        // Clearing the stale observation restores normal preparation.
        f.registry
            .set_instance_observation("deploy-alpha", ObservationCache::now(true, "helper=ok"))?;
        let prepared = prepare_control_operation(
            &f.registry,
            &f.keys,
            &journal,
            "production",
            input("rev-9"),
        )?;
        assert_eq!(prepared.kind, AttemptKind::Fresh);
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
