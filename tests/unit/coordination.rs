use super::*;
use crate::{
    deployment::{
        CapabilityGrants, DEPLOYMENT_SCHEMA, DeploymentRecord, RecoveryAssessment,
        RecoveryConclusion, TrustState,
    },
    filesystem::PrivateTempDir,
};
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
        runtime_instances: Vec::new(),
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
                "action": "create external recovery point"
            },
            {
                "id": "replace-runtime",
                "owner": "ctl-owned",
                "capability": "runtime",
                "action": "replace runtime"
            }
        ],
        "blockers": []
    })
}

fn evidence(transaction: &UpdateCoordination, deployment_id: &str) -> Value {
    json!({
        "schema": 1,
        "deployment_id": deployment_id,
        "transaction_id": transaction.transaction_id,
        "step_id": "external-recovery-point",
        "kind": "provider-receipt",
        "reference_id": "snapshot-20260803-001",
        "artifact_sha256": "c".repeat(64),
        "issued_at": 1785783900
    })
}

#[test]
fn external_step_pauses_accepts_bound_evidence_and_resumes_without_claiming_completion() {
    let work = PrivateTempDir::new("nazoauthctl-coordination").unwrap();
    let store = store(&work);
    let record = record("deployment-a");
    let prepared = prepare_update(&store, &record, &plan("deployment-a")).unwrap();
    assert_eq!(prepared.state, CoordinationState::WaitingForEvidence);

    let input = work.path().join("evidence.json");
    fs::write(
        &input,
        serde_json::to_vec_pretty(&evidence(&prepared, "deployment-a")).unwrap(),
    )
    .unwrap();
    let accepted = submit_evidence(&store, &record, &input).unwrap();
    assert_eq!(accepted.state, CoordinationState::ReadyForController);
    let resumed = resume(&store, &record).unwrap();
    assert_eq!(resumed.state, CoordinationState::ReadyForController);

    let stored = fs::read_to_string(
        store
            .deployment_state_dir("deployment-a")
            .join("transactions/evidence/external-recovery-point.json"),
    )
    .unwrap();
    assert!(stored.contains("\"semantic_completion_claimed\": false"));
    assert!(!stored.contains("password"));
}

#[test]
fn evidence_cannot_cross_deployment_or_survive_persisted_tampering() {
    let work = PrivateTempDir::new("nazoauthctl-coordination-isolation").unwrap();
    let store = store(&work);
    let record_a = record("deployment-a");
    let record_b = record("deployment-b");
    let prepared = prepare_update(&store, &record_a, &plan("deployment-a")).unwrap();
    let input = work.path().join("wrong-deployment.json");
    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-b")).unwrap(),
    )
    .unwrap();
    assert!(submit_evidence(&store, &record_a, &input).is_err());
    assert!(show(&store, &record_b).is_err());

    fs::write(
        &input,
        serde_json::to_vec(&evidence(&prepared, "deployment-a")).unwrap(),
    )
    .unwrap();
    submit_evidence(&store, &record_a, &input).unwrap();
    let persisted = store
        .deployment_state_dir("deployment-a")
        .join("transactions/evidence/external-recovery-point.json");
    fs::write(&persisted, b"{}").unwrap();
    assert!(resume(&store, &record_a).is_err());
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
