use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    deployment::{ResourceScope, Responsibility, RuntimeBackendKind},
    filesystem::PrivateTempDir,
    runtime_backend::{NeutralMount, RuntimeObservation},
};

fn candidate(target: &str, runtime_id: &str, data_root: &str) -> DiscoveredDeployment {
    DiscoveredDeployment {
        target: target.to_owned(),
        deployment_id: Some("deployment-test".to_owned()),
        runtime_instance_id: Some(runtime_id.to_owned()),
        issuer: Some("https://issuer.example".to_owned()),
        release: Some("v0.1.19".to_owned()),
        revision: Some("a".repeat(40)),
        build_id: Some("build:test".to_owned()),
        instance_key_id: Some(format!("instance-{runtime_id}")),
        control_protocol_versions: vec![1],
        operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
        runtime: RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: target.to_owned(),
            display_name: target.to_owned(),
            running: false,
            server_command_verified: true,
            artifact: ArtifactReference::Unknown,
            local_artifact_id: None,
            ports: Vec::new(),
            networks: vec!["external-network".to_owned()],
            mounts: vec![NeutralMount {
                source: PathBuf::from(data_root),
                destination: PathBuf::from("/var/lib/nazo_oauth"),
                read_only: false,
                selinux_relabel: false,
                ownership: Responsibility::External,
                scope: ResourceScope::Deployment,
            }],
            safe_environment: BTreeMap::from([(
                "DATA_DIR".to_owned(),
                "/var/lib/nazo_oauth".to_owned(),
            )]),
            labels: BTreeMap::new(),
            evidence: Vec::new(),
            missing: Vec::new(),
        },
        online_statement: None,
        offline_statement: None,
        oidc_discovery_verified: false,
        readiness_observed: false,
        external_database: true,
        external_valkey: true,
        recovery_conclusion: RecoveryConclusion::RequiresUserEvidence,
        evidence: Vec::new(),
        missing: Vec::new(),
        sensitive_mount_sources: BTreeMap::new(),
    }
}

fn plan(candidates: &[DiscoveredDeployment]) -> AdoptionPlan {
    AdoptionPlan {
        schema: 1,
        target: candidates[0].target.clone(),
        deployment_id: "deployment-test".to_owned(),
        runtime_instance_id: "runtime-a".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        release: "v0.1.19".to_owned(),
        active_release: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.1.19".to_owned(),
            revision: "a".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        artifact_identity: "sha256:trusted".to_owned(),
        runtime_instances: candidates
            .iter()
            .map(|candidate| AdoptedRuntimeIdentity {
                runtime_instance_id: candidate.runtime_instance_id.clone().unwrap(),
                backend: "podman".to_owned(),
                object_reference: candidate.runtime.object_reference.clone(),
                artifact_identity: "sha256:trusted".to_owned(),
            })
            .collect(),
        resulting_trust: TrustState::Adopted,
        requested_capabilities: CapabilityGrants::observed(),
        capabilities: CapabilityGrants::observed(),
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::RequiresUserEvidence,
            evidence: Vec::new(),
            off_host_package_required_for_machine_loss: true,
        },
        steps: Vec::new(),
        blockers: Vec::new(),
    }
}

#[test]
fn adoption_record_preserves_every_replica_and_each_offline_identity_path() {
    let candidates = vec![
        candidate("podman:object-a", "runtime-a", "/srv/a"),
        candidate("podman:object-b", "runtime-b", "/srv/b"),
    ];
    let record = deployment_record(
        &candidates,
        &plan(&candidates),
        Some("primary".to_owned()),
        "controller-test",
    )
    .unwrap();

    assert_eq!(record.runtime_instances.len(), 2);
    assert_eq!(
        record
            .runtime_instances
            .iter()
            .map(|runtime| runtime.runtime_instance_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["runtime-a", "runtime-b"])
    );
    assert_eq!(
        record.runtime_instances[0].deployment_statement,
        Some(PathBuf::from("/srv/a/instance/deployment-statement.jws"))
    );
    assert_eq!(
        record.runtime_instances[1].deployment_statement,
        Some(PathBuf::from("/srv/b/instance/deployment-statement.jws"))
    );
}

#[test]
fn recovery_evidence_is_bound_to_deployment_release_off_host_and_content() {
    let work = PrivateTempDir::new("adoption-recovery-evidence").unwrap();
    let artifacts = ["data", "database", "release", "verification"].map(|name| {
        let path = work.path().join(name);
        fs::write(&path, format!("{name}-evidence")).unwrap();
        RecoveryArtifact {
            sha256: sha256(&path).unwrap(),
            path,
        }
    });
    let manifest_path = work.path().join("manifest.json");
    atomic_write(
        &manifest_path,
        &serde_json::to_vec_pretty(&RecoveryEvidenceManifest {
            schema: 1,
            deployment_id: "deployment-test".to_owned(),
            release: "v0.1.19".to_owned(),
            data_snapshot: artifacts[0].clone(),
            database_restore: artifacts[1].clone(),
            last_trusted_artifact: artifacts[2].clone(),
            verification_material: artifacts[3].clone(),
            off_host_package_confirmed: true,
        })
        .unwrap(),
        0o600,
    )
    .unwrap();

    verify_recovery_evidence(&manifest_path, "deployment-test", "v0.1.19").unwrap();
    let assessment = recovery_assessment(
        &candidate("podman:object-a", "runtime-a", "/srv/a"),
        "deployment-test",
        "v0.1.19",
        Some(&manifest_path),
    )
    .unwrap();
    assert_eq!(
        assessment.conclusion,
        RecoveryConclusion::RequiresUserEvidence
    );
    assert!(verify_recovery_evidence(&manifest_path, "another-deployment", "v0.1.19").is_err());
    fs::write(&artifacts[0].path, b"tampered").unwrap();
    assert!(verify_recovery_evidence(&manifest_path, "deployment-test", "v0.1.19").is_err());
}

#[test]
fn adoption_identities_are_distinct_and_break_glass_is_outside_active_state() {
    let work = PrivateTempDir::new("adoption-identities").unwrap();
    let store = DeploymentStore {
        config_root: work.path().join("config"),
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    };
    create_identities(&store, "deployment-test").unwrap();
    let active = store
        .deployment_state_dir("deployment-test")
        .join("identities");
    let public_keys = ["controller.pub", "receipt.pub", "audit.pub"]
        .map(|name| fs::read_to_string(active.join(name)).unwrap());
    let break_glass = fs::read_to_string(
        store
            .break_glass_dir("deployment-test")
            .join("break-glass.pub"),
    )
    .unwrap();
    let distinct = public_keys
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(break_glass.as_str()))
        .collect::<BTreeSet<_>>();
    assert_eq!(distinct.len(), 4);
    assert!(!active.starts_with(store.break_glass_dir("deployment-test")));
}
