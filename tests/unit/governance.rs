use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::deployment::{
    ArtifactReference, CapabilityGrants, DEPLOYMENT_SCHEMA, RecoveryAssessment, RuntimeBackendKind,
    RuntimeInstance, SafeReference,
};
use crate::filesystem::PrivateTempDir;

fn record() -> DeploymentRecord {
    DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: "deployment-test".to_owned(),
        control_authority: "controller-test".to_owned(),
        alias: None,
        issuer: "https://issuer.example".to_owned(),
        active_release: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.1.19".to_owned(),
            revision: "a".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        trust: TrustState::Adopted,
        capabilities: CapabilityGrants::observed(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: "runtime-test".to_owned(),
            backend: RuntimeBackendKind::Systemd,
            object_reference: "nazoauth-test.service".to_owned(),
            artifact: ArtifactReference::Unknown,
            ports: Vec::new(),
            networks: Vec::new(),
            mounts: Vec::new(),
            instance_key_id: None,
            deployment_statement: None,
        }],
        resources: BTreeMap::new(),
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::Unproven,
            evidence: Vec::new(),
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: BTreeSet::from([1]),
        control_protocol_versions: BTreeSet::from([1]),
        declaration_revision: 1,
    }
}

#[test]
fn permission_expansion_requires_recovery_and_shared_management_fails_closed() {
    let mut deployment = record();
    let delegated = CapabilityGrant {
        responsibility: Responsibility::Delegated,
        scope: ResourceScope::Deployment,
    };
    assert!(validate_grant_transition(&deployment, Capability::Artifact, &delegated).is_err());

    deployment.recovery.conclusion = RecoveryConclusion::Proven;
    validate_grant_transition(&deployment, Capability::Artifact, &delegated).unwrap();

    let shared_managed = CapabilityGrant {
        responsibility: Responsibility::Managed,
        scope: ResourceScope::Shared,
    };
    assert!(validate_grant_transition(&deployment, Capability::Database, &shared_managed).is_err());
}

#[test]
fn relinquish_is_a_monotonic_permission_reduction() {
    assert!(
        responsibility_rank(Responsibility::External)
            < responsibility_rank(Responsibility::Delegated)
    );
    assert!(
        responsibility_rank(Responsibility::Delegated)
            < responsibility_rank(Responsibility::Managed)
    );
}

#[test]
fn controller_modules_do_not_encode_runtime_backend_command_syntax() {
    let controller_modules = [
        ("install", include_str!("../../src/install.rs")),
        ("controller", include_str!("../../src/controller.rs")),
        ("operator", include_str!("../../src/operator.rs")),
        ("backup", include_str!("../../src/backup.rs")),
        ("release", include_str!("../../src/release.rs")),
    ];
    let forbidden = [
        "container_engine(",
        "container_command(",
        "Process::new(engine)",
        "systemctl",
        "systemd-run",
        "useradd",
        "--network",
        "ro,Z",
        "rw,Z",
    ];
    for (module, source) in controller_modules {
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{module} must delegate backend command token {token:?} to RuntimeBackend"
            );
        }
    }
}

#[test]
fn integrity_evidence_without_an_executable_controller_config_is_not_core_recovery() {
    let mut deployment = record();
    deployment.trust = TrustState::Adopted;
    deployment.recovery.conclusion = RecoveryConclusion::Proven;
    for capability in [
        Capability::Runtime,
        Capability::Artifact,
        Capability::Backups,
    ] {
        deployment.capabilities.grant_mut(capability).responsibility = Responsibility::Delegated;
    }
    assert!(!deployment.core_recovery_is_proven());

    deployment.resources.insert(
        "controller_config".to_owned(),
        SafeReference::File {
            path: std::path::PathBuf::from("/etc/nazoauthctl/deployment-test.json"),
        },
    );
    assert!(deployment.core_recovery_is_proven());
}

#[test]
fn lifecycle_management_audit_is_chained_and_idempotent() {
    let work = PrivateTempDir::new("nazoauthctl-management-audit").unwrap();
    let store = DeploymentStore {
        config_root: work.path().join("etc"),
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    };
    let mut deployment = record();
    let key = SigningKey::from_bytes(&[7; 32]);
    let key_path = store
        .deployment_state_dir(&deployment.deployment_id)
        .join("identities/audit.key");
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, URL_SAFE_NO_PAD.encode(key.to_bytes())).unwrap();
    deployment.resources.insert(
        "audit_private_key".to_owned(),
        SafeReference::File { path: key_path },
    );

    append_management_audit(
        &store,
        &deployment,
        "request-a",
        "lifecycle-recover",
        "v0.1.19",
    )
    .unwrap();
    append_management_audit(
        &store,
        &deployment,
        "request-a",
        "lifecycle-recover",
        "v0.1.19",
    )
    .unwrap();
    let entries = fs::read_dir(
        store
            .deployment_state_dir(&deployment.deployment_id)
            .join("audit"),
    )
    .unwrap()
    .count();
    assert_eq!(entries, 1);
    assert!(
        append_management_audit(
            &store,
            &deployment,
            "request-a",
            "lifecycle-rollback",
            "v0.1.19",
        )
        .is_err()
    );
}
