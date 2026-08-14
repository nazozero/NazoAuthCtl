use super::*;
use crate::{
    deployment::{
        ArtifactReference, CapabilityGrants, DEPLOYMENT_SCHEMA, DeploymentRecord,
        RecoveryAssessment, RecoveryConclusion, ResourceScope, Responsibility, RuntimeBackendKind,
        RuntimeInstance, SafeReference, TrustState,
    },
    filesystem::{PrivateTempDir, sha256},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn store(work: &PrivateTempDir) -> DeploymentStore {
    DeploymentStore {
        config_root: work.path().join("etc"),
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    }
}

fn record(deployment_id: &str) -> DeploymentRecord {
    DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: deployment_id.to_owned(),
        control_authority: format!("controller-{deployment_id}"),
        alias: None,
        issuer: format!("https://{deployment_id}.example"),
        active_release: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.1.19".to_owned(),
            revision: "a".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        trust: TrustState::Adopted,
        capabilities: CapabilityGrants::controller_installed(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: "runtime-a".to_owned(),
            backend: RuntimeBackendKind::Systemd,
            object_reference: "nazoauth-a.service".to_owned(),
            artifact: ArtifactReference::HostBinary {
                path: "/usr/local/bin/nazoauth".into(),
                sha256: "f".repeat(64),
            },
            local_artifact_id: None,
            ports: Vec::new(),
            networks: Vec::new(),
            mounts: Vec::new(),
            instance_key_id: None,
            deployment_statement: None,
        }],
        resources: BTreeMap::new(),
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: vec!["recovery-test".to_owned()],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: BTreeSet::from([nazo_operator_protocol::PROTOCOL_VERSION]),
        control_protocol_versions: BTreeSet::from([1]),
        declaration_revision: 7,
    }
}

fn provider_record(work: &PrivateTempDir, deployment_id: &str) -> (DeploymentRecord, SigningKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let key_path = work.path().join(format!("{deployment_id}-provider.pub"));
    fs::write(&key_path, key.verifying_key().to_bytes()).unwrap();
    let mut record = record(deployment_id);
    record.resources.insert(
        "provider-evidence:backups".to_owned(),
        SafeReference::DigestBoundFile {
            path: key_path.clone(),
            sha256: sha256(&key_path).unwrap(),
        },
    );
    (record, key)
}

fn plan(deployment_id: &str) -> Value {
    json!({
        "deployment_id": deployment_id,
        "target_release": {
            "release": "v0.1.20",
            "revision": "b".repeat(40),
            "protocol": nazo_operator_protocol::PROTOCOL_VERSION,
            "build_id": "build:target"
        },
        "steps": [
            {
                "id": "verify-release",
                "owner": "ctl-owned",
                "capability": "artifact",
                "action": "verify release"
            },
            {
                "id": "external-recovery-point",
                "owner": "provider-owned",
                "capability": "backups",
                "action": "create external recovery point",
                "evidence_kind": "recovery-point"
            },
            {
                "id": "replace-runtime",
                "owner": "ctl-owned",
                "capability": "runtime",
                "action": "replace runtime"
            },
            {
                "id": "acceptance",
                "owner": "ctl-owned",
                "capability": "artifact",
                "action": "accept runtime"
            }
        ],
        "blockers": []
    })
}

fn unsigned_evidence(
    transaction: &UpdateCoordination,
    deployment_id: &str,
    now: i64,
) -> EvidenceInput {
    EvidenceInput {
        schema: EVIDENCE_SCHEMA,
        deployment_id: deployment_id.to_owned(),
        transaction_id: transaction.transaction_id.clone(),
        step_id: "external-recovery-point".to_owned(),
        kind: EvidenceKind::RecoveryPoint,
        action: "create external recovery point".to_owned(),
        capability: "backups".to_owned(),
        reference_id: "snapshot-20260803-001".to_owned(),
        artifact_sha256: "c".repeat(64),
        plan_sha256: transaction.plan_sha256.clone(),
        target_release: transaction.target_release.clone(),
        issued_at: now,
        expires_at: now + 300,
        nonce: format!("nonce-{}", transaction.transaction_id),
        signature: None,
    }
}

fn signed_evidence(
    transaction: &UpdateCoordination,
    deployment_id: &str,
    signing_key: &SigningKey,
) -> EvidenceInput {
    let now = Utc::now().timestamp();
    sign_evidence(
        transaction,
        signing_key,
        unsigned_evidence(transaction, deployment_id, now),
    )
}

fn sign_evidence(
    transaction: &UpdateCoordination,
    signing_key: &SigningKey,
    mut input: EvidenceInput,
) -> EvidenceInput {
    input.signature = Some(
        URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&canonical_signing_payload(&input, transaction).unwrap())
                .to_bytes(),
        ),
    );
    input
}

fn evidence(
    transaction: &UpdateCoordination,
    deployment_id: &str,
    signing_key: &SigningKey,
) -> Value {
    serde_json::to_value(signed_evidence(transaction, deployment_id, signing_key)).unwrap()
}

#[test]
fn external_step_pauses_accepts_bound_evidence_and_resumes_without_claiming_completion() {
    let work = PrivateTempDir::new("nazoauthctl-coordination").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    assert_eq!(prepared.state, CoordinationState::WaitingForEvidence);

    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec_pretty(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    let accepted = submit_evidence(&store, &record, &input).unwrap();
    assert_eq!(accepted.state, CoordinationState::ReadyForController);
    let legacy = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence/external-recovery-point.json");
    fs::write(&legacy, b"{}").unwrap();
    let resumed = resume(&store, &record).unwrap();
    assert_eq!(resumed.state, CoordinationState::ReadyForController);

    let stored = fs::read_to_string(
        store
            .deployment_state_dir("deployment-a")
            .join("transactions/evidence")
            .join(&prepared.transaction_id)
            .join("external-recovery-point.json"),
    )
    .unwrap();
    assert!(stored.contains("\"semantic_completion_claimed\": false"));
    assert!(!stored.contains("password"));
}

#[test]
fn persisted_evidence_is_validated_at_its_durable_acceptance_time() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-persisted-freshness").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let transaction = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let step = transaction
        .steps
        .iter()
        .find(|step| step.id == "external-recovery-point")
        .unwrap();
    let accepted_at = Utc::now().timestamp() - 7_200;
    let input = sign_evidence(
        &transaction,
        &signing_key,
        unsigned_evidence(&transaction, "deployment-a", accepted_at - 10),
    );
    let source_manifest_sha256 = digest_bytes(&canonical_evidence_bytes(&input).unwrap());
    let accepted = AcceptedEvidence {
        schema: EVIDENCE_SCHEMA,
        evidence: input,
        source_manifest_sha256,
        accepted_at,
        semantic_completion_claimed: false,
    };

    validate_persisted_evidence(
        &record,
        &transaction,
        step,
        &serde_json::to_vec(&accepted).unwrap(),
    )
    .unwrap();

    let mut expired_on_acceptance = accepted;
    expired_on_acceptance.accepted_at = expired_on_acceptance.evidence.expires_at;
    assert!(
        validate_persisted_evidence(
            &record,
            &transaction,
            step,
            &serde_json::to_vec(&expired_on_acceptance).unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("expired")
    );
}

#[test]
fn completed_transactions_retain_distinct_external_evidence() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-evidence-history").unwrap();
    let store = store(&work);
    let (current, signing_key) = provider_record(&work, "deployment-a");
    store.persist(&current).unwrap();

    let first = prepare_update(&store, &current, &plan("deployment-a")).unwrap();
    let first_input = work.path().join("first-evidence.json");
    fs::write(
        &first_input,
        serde_json::to_vec(&evidence(&first, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &current, &first_input).unwrap();
    complete_controller_step(
        &store,
        &current,
        &first.transaction_id,
        "replace-runtime",
        &"d".repeat(64),
    )
    .unwrap();
    let mut updated = current.clone();
    updated.active_release = first.target_release.clone();
    updated.declaration_revision += 1;
    commit_controller_update(
        &store,
        &current,
        &updated,
        &first.transaction_id,
        "acceptance",
        &"e".repeat(64),
    )
    .unwrap();
    finalize_committed_locked(&store, &updated, &first.transaction_id).unwrap();

    let second = prepare_update(&store, &updated, &plan("deployment-a")).unwrap();
    assert_ne!(first.transaction_id, second.transaction_id);
    let second_input = work.path().join("second-evidence.json");
    fs::write(
        &second_input,
        serde_json::to_vec(&evidence(&second, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &updated, &second_input).unwrap();

    let evidence_root = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence");
    assert!(
        evidence_root
            .join(&first.transaction_id)
            .join("external-recovery-point.json")
            .is_file()
    );
    assert!(
        evidence_root
            .join(&second.transaction_id)
            .join("external-recovery-point.json")
            .is_file()
    );
}

#[test]
fn aborted_controller_update_is_archived_without_changing_the_declaration() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-abort").unwrap();
    let store = store(&work);
    let current = record("deployment-a");
    store.persist(&current).unwrap();
    let prepared = prepare_update(&store, &current, &plan("deployment-a")).unwrap();

    let aborting =
        mark_controller_update_aborting_locked(&store, &current, &prepared.transaction_id).unwrap();
    assert_eq!(aborting.state, CoordinationState::Aborting);
    assert_eq!(
        resume(&store, &current).unwrap().state,
        CoordinationState::Aborting
    );

    let aborted =
        abort_controller_update_locked(&store, &current, &prepared.transaction_id).unwrap();

    assert_eq!(aborted.state, CoordinationState::Aborted);
    assert_eq!(store.load("deployment-a").unwrap(), current);
    assert!(!active_update_exists(&store, &current));
    let history = store
        .deployment_state_dir("deployment-a")
        .join("transactions")
        .join(format!("update-{}.json", prepared.transaction_id));
    assert!(history.is_file());

    // Simulate a crash after the history write but before durable removal of
    // the active record. The next abort consumes the identical active copy.
    let active = store
        .deployment_state_dir("deployment-a")
        .join("transactions")
        .join("active-update.json");
    let mut archived: UpdateCoordination =
        serde_json::from_slice(&fs::read(&history).unwrap()).unwrap();
    archived.updated_at -= 60;
    let archived_bytes = serde_json::to_vec_pretty(&archived).unwrap();
    atomic_write(&history, &archived_bytes, 0o600).unwrap();
    atomic_write(&active, &archived_bytes, 0o600).unwrap();
    let replayed =
        abort_controller_update_locked(&store, &current, &prepared.transaction_id).unwrap();
    assert_eq!(replayed, archived);
    assert!(!active.exists());
}

#[test]
fn provider_evidence_rejects_forgery_and_wrong_signer() {
    for wrong_signer in [false, true] {
        let work = PrivateTempDir::new("nazoauthctl-coordination-signature").unwrap();
        let store = store(&work);
        let (record, signing_key) = provider_record(&work, "deployment-a");
        let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
        let mut input = signed_evidence(&prepared, "deployment-a", &signing_key);
        if wrong_signer {
            input = sign_evidence(&prepared, &SigningKey::from_bytes(&[8; 32]), input);
        } else {
            input.artifact_sha256 = "d".repeat(64);
        }
        let path = work.path().join("evidence.json");
        fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(submit_evidence(&store, &record, &path).is_err());
    }
}

#[test]
fn provider_evidence_requires_a_pinned_provider_key() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-no-pin").unwrap();
    let store = store(&work);
    let record = record("deployment-a");
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    assert!(submit_evidence(&store, &record, &input).is_err());
}

#[test]
fn provider_evidence_rejects_stale_and_future_validity_windows() {
    for future in [false, true] {
        let work = PrivateTempDir::new("nazoauthctl-coordination-freshness").unwrap();
        let store = store(&work);
        let (record, signing_key) = provider_record(&work, "deployment-a");
        let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
        let now = Utc::now().timestamp();
        let issued_at = if future {
            now + MAX_EVIDENCE_FUTURE_SKEW_SECONDS + 30
        } else {
            now - MAX_EVIDENCE_AGE_SECONDS - 1
        };
        let input = sign_evidence(
            &prepared,
            &signing_key,
            unsigned_evidence(&prepared, "deployment-a", issued_at),
        );
        let path = work.path().join("evidence.json");
        fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(submit_evidence(&store, &record, &path).is_err());
    }
}

#[test]
fn evidence_rejects_wrong_kind_action_capability_and_cross_transaction_binding() {
    for mutation in 0..4 {
        let work = PrivateTempDir::new("nazoauthctl-coordination-binding").unwrap();
        let store = store(&work);
        let (record, signing_key) = provider_record(&work, "deployment-a");
        let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
        let mut input = unsigned_evidence(&prepared, "deployment-a", Utc::now().timestamp());
        match mutation {
            0 => input.kind = EvidenceKind::ProviderReceipt,
            1 => input.action = "replace runtime".to_owned(),
            2 => input.capability = "runtime".to_owned(),
            _ => input.transaction_id = "other-transaction".to_owned(),
        }
        let input = sign_evidence(&prepared, &signing_key, input);
        let path = work.path().join("evidence.json");
        fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(submit_evidence(&store, &record, &path).is_err());
    }
}

#[test]
fn duplicate_provider_evidence_is_rejected_without_overwriting_the_acceptance() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-duplicate").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let path = work.path().join("evidence.json");
    fs::write(
        &path,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &record, &path).unwrap();
    assert!(submit_evidence(&store, &record, &path).is_err());
}

#[test]
fn resume_recomputes_and_rejects_a_tampered_source_digest() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-source-digest").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &record, &input).unwrap();

    let persisted = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence")
        .join(&prepared.transaction_id)
        .join("external-recovery-point.json");
    let mut accepted: AcceptedEvidence =
        serde_json::from_slice(&fs::read(&persisted).unwrap()).unwrap();
    accepted.source_manifest_sha256 = "0".repeat(64);
    let bytes = serde_json::to_vec_pretty(&accepted).unwrap();
    fs::write(&persisted, &bytes).unwrap();

    let active = store
        .deployment_state_dir("deployment-a")
        .join("transactions/active-update.json");
    let mut transaction: UpdateCoordination =
        serde_json::from_slice(&fs::read(&active).unwrap()).unwrap();
    transaction.steps[1].evidence_sha256 = Some(digest_bytes(&bytes));
    fs::write(&active, serde_json::to_vec_pretty(&transaction).unwrap()).unwrap();
    assert!(resume(&store, &record).is_err());
}

#[test]
fn evidence_cannot_cross_deployment_or_survive_persisted_tampering() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-isolation").unwrap();
    let store = store(&work);
    let (record_a, signing_key) = provider_record(&work, "deployment-a");
    let record_b = record("deployment-b");
    let prepared = prepare_update(&store, &record_a, &plan("deployment-a")).unwrap();
    let input = work.path().join("wrong-deployment.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-b", &signing_key)).unwrap(),
    )
    .unwrap();
    assert!(submit_evidence(&store, &record_a, &input).is_err());
    assert!(show(&store, &record_b).is_err());

    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &record_a, &input).unwrap();
    let persisted = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence")
        .join(&prepared.transaction_id)
        .join("external-recovery-point.json");
    fs::write(&persisted, b"{}").unwrap();
    assert!(resume(&store, &record_a).is_err());
}

#[test]
fn accepted_legacy_evidence_remains_resumable() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-legacy-evidence").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &record, &input).unwrap();

    let evidence_root = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence");
    let current = evidence_root
        .join(&prepared.transaction_id)
        .join("external-recovery-point.json");
    let legacy = evidence_root.join("external-recovery-point.json");
    fs::rename(&current, &legacy).unwrap();

    assert_eq!(
        resume(&store, &record).unwrap().state,
        CoordinationState::ReadyForController
    );
    assert!(legacy.is_file());
}

#[test]
fn declaration_drift_and_conflicting_update_plans_fail_closed() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-drift").unwrap();
    let store = store(&work);
    let record = record("deployment-a");
    prepare_update(&store, &record, &plan("deployment-a")).unwrap();

    let mut changed_plan = plan("deployment-a");
    changed_plan["target_release"]["build_id"] = json!("build:different");
    assert!(prepare_update(&store, &record, &changed_plan).is_err());
    let mut drifted = record;
    drifted.declaration_revision += 1;
    assert!(resume(&store, &drifted).is_err());
}

#[test]
fn persisted_declaration_drift_is_rejected_after_the_transaction_was_prepared() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-persisted-drift").unwrap();
    let store = store(&work);
    let current = record("deployment-a");
    store.persist(&current).unwrap();
    prepare_update(&store, &current, &plan("deployment-a")).unwrap();

    let mut changed = current.clone();
    changed.alias = Some("changed-after-plan".to_owned());
    changed.declaration_revision += 1;
    let _lock = store.deployment_lock("deployment-a").unwrap();
    store
        .persist_declaration_cas_locked(&current, &changed)
        .unwrap();
    drop(_lock);

    assert!(resume(&store, &current).is_err());
}

#[test]
fn prepare_update_refuses_a_locked_shared_capability_without_persisting_state() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-shared-lock").unwrap();
    let store = store(&work);
    let mut current = record("deployment-a");
    current.capabilities.database.scope = ResourceScope::Shared;
    current.capabilities.database.responsibility = Responsibility::Delegated;
    store.persist(&current).unwrap();

    let _database_lock = store.shared_resource_lock("database").unwrap();
    assert!(prepare_update(&store, &current, &plan("deployment-a")).is_err());
    assert!(
        !store
            .deployment_state_dir("deployment-a")
            .join("transactions/active-update.json")
            .exists()
    );
}

#[test]
fn controller_steps_commit_the_new_declaration_only_after_final_acceptance() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-commit").unwrap();
    let store = store(&work);
    let (current, signing_key) = provider_record(&work, "deployment-a");
    store.persist(&current).unwrap();
    let prepared = prepare_update(&store, &current, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &current, &input).unwrap();
    let after_runtime = complete_controller_step(
        &store,
        &current,
        &prepared.transaction_id,
        "replace-runtime",
        &"d".repeat(64),
    )
    .unwrap();
    assert_eq!(after_runtime.state, CoordinationState::ReadyForController);

    let mut wrong_target = current.clone();
    wrong_target.active_release = prepared.target_release.clone();
    wrong_target.active_release.build_id = "build:not-the-transaction-target".to_owned();
    wrong_target.declaration_revision += 1;
    assert!(
        commit_controller_update(
            &store,
            &current,
            &wrong_target,
            &prepared.transaction_id,
            "acceptance",
            &"e".repeat(64),
        )
        .is_err()
    );
    assert_eq!(store.load("deployment-a").unwrap(), current);
    assert_eq!(
        show(&store, &current).unwrap().state,
        CoordinationState::ReadyForController
    );

    let mut updated = current.clone();
    updated.active_release = prepared.target_release;
    updated.declaration_revision += 1;
    let committed = commit_controller_update(
        &store,
        &current,
        &updated,
        &prepared.transaction_id,
        "acceptance",
        &"e".repeat(64),
    )
    .unwrap();
    assert_eq!(committed.state, CoordinationState::Committed);
    assert_eq!(store.load("deployment-a").unwrap(), updated);
    finalize_committed_locked(
        &store,
        &store.load("deployment-a").unwrap(),
        &prepared.transaction_id,
    )
    .unwrap();
    assert!(show(&store, &updated).is_err());
    assert!(
        store
            .deployment_state_dir("deployment-a")
            .join(format!(
                "transactions/update-{}.json",
                prepared.transaction_id
            ))
            .is_file()
    );
}

#[test]
fn resume_repairs_evidence_written_before_the_pending_journal_transition() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-evidence-replay").unwrap();
    let store = store(&work);
    let (record, signing_key) = provider_record(&work, "deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    let accepted = submit_evidence(&store, &record, &input).unwrap();
    assert_eq!(accepted.state, CoordinationState::ReadyForController);

    // Simulate a stop after the accepted evidence file was durable but before
    // the active journal's Pending -> EvidenceAccepted write completed.
    let active = store
        .deployment_state_dir("deployment-a")
        .join("transactions/active-update.json");
    let mut interrupted: UpdateCoordination =
        serde_json::from_slice(&fs::read(&active).unwrap()).unwrap();
    let external = interrupted
        .steps
        .iter_mut()
        .find(|step| step.id == "external-recovery-point")
        .unwrap();
    external.state = StepState::Pending;
    external.evidence_sha256 = None;
    interrupted.state = CoordinationState::WaitingForEvidence;
    fs::write(&active, serde_json::to_vec_pretty(&interrupted).unwrap()).unwrap();

    let resumed = resume(&store, &record).unwrap();
    assert_eq!(resumed.state, CoordinationState::ReadyForController);
    let external = resumed
        .steps
        .iter()
        .find(|step| step.id == "external-recovery-point")
        .unwrap();
    assert_eq!(external.state, StepState::EvidenceAccepted);
    assert!(external.evidence_sha256.is_some());
}

#[test]
fn committed_resume_replays_a_cas_that_preceded_the_old_journal_revision() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-commit-replay").unwrap();
    let store = store(&work);
    let (current, signing_key) = provider_record(&work, "deployment-a");
    store.persist(&current).unwrap();
    let prepared = prepare_update(&store, &current, &plan("deployment-a")).unwrap();
    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a", &signing_key)).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &current, &input).unwrap();
    complete_controller_step(
        &store,
        &current,
        &prepared.transaction_id,
        "replace-runtime",
        &"d".repeat(64),
    )
    .unwrap();

    let mut updated = current.clone();
    updated.active_release = prepared.target_release.clone();
    updated.declaration_revision = current.declaration_revision + 1;

    // Simulate the new commit protocol after its durable intent was written,
    // followed by a successful declaration CAS, but before the journal could
    // record the new declaration revision.
    let active = store
        .deployment_state_dir("deployment-a")
        .join("transactions/active-update.json");
    let mut interrupted: UpdateCoordination =
        serde_json::from_slice(&fs::read(&active).unwrap()).unwrap();
    let acceptance = interrupted
        .steps
        .iter_mut()
        .find(|step| step.id == "acceptance")
        .unwrap();
    acceptance.state = StepState::ControllerCompleted;
    acceptance.evidence_sha256 = Some("e".repeat(64));
    interrupted.state = CoordinationState::Committed;
    interrupted.committed_declaration = Some(updated.clone());
    assert_eq!(
        interrupted.declaration_revision + 1,
        updated.declaration_revision
    );
    fs::write(&active, serde_json::to_vec_pretty(&interrupted).unwrap()).unwrap();
    {
        let _lock = store.deployment_lock("deployment-a").unwrap();
        store
            .persist_declaration_cas_locked(&current, &updated)
            .unwrap();
    }

    let resumed = resume(&store, &updated).unwrap();
    assert_eq!(resumed.state, CoordinationState::Committed);
    assert_eq!(resumed.declaration_revision, updated.declaration_revision);
    assert_eq!(store.load("deployment-a").unwrap(), updated);
    finalize_committed_locked(&store, &updated, &prepared.transaction_id).unwrap();
    assert!(!active.exists());
}
