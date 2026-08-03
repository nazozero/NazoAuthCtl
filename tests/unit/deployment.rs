use super::*;
use crate::filesystem::PrivateTempDir;

fn store(work: &PrivateTempDir) -> DeploymentStore {
    DeploymentStore {
        config_root: work.path().join("etc"),
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    }
}

fn record(deployment_id: &str, alias: &str) -> DeploymentRecord {
    DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: deployment_id.to_owned(),
        control_authority: format!("controller-{deployment_id}"),
        alias: Some(alias.to_owned()),
        issuer: format!("https://{alias}.example"),
        trust: TrustState::Adopted,
        capabilities: CapabilityGrants::controller_installed(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: format!("runtime-{alias}"),
            backend: RuntimeBackendKind::Podman,
            object_reference: format!("container-{alias}"),
            artifact: ArtifactReference::Oci {
                image_reference: "ghcr.io/nazozero/nazoauth".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            ports: vec![format!("127.0.0.1:8000->8000/tcp")],
            networks: vec![format!("network-{alias}")],
            mounts: Vec::new(),
            instance_key_id: Some(format!("instance-{alias}")),
            deployment_statement: None,
        }],
        resources: BTreeMap::new(),
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: vec!["fixture-sha256".to_owned()],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: BTreeSet::from([1]),
        control_protocol_versions: BTreeSet::from([1]),
        declaration_revision: 1,
    }
}

#[test]
fn registry_requires_explicit_selection_when_multiple_deployments_exist() {
    let work = PrivateTempDir::new("nazoauthctl-registry-selection").unwrap();
    let store = store(&work);
    store.persist(&record("deployment-a", "alpha")).unwrap();
    store.persist(&record("deployment-b", "beta")).unwrap();
    let error = store.resolve(None, true).unwrap_err().to_string();
    assert!(error.contains("requires --deployment"));
    assert_eq!(
        store.resolve(Some("beta"), true).unwrap().deployment_id,
        "deployment-b"
    );
}

#[test]
fn observed_state_cannot_smuggle_mutation_capabilities() {
    let mut observed = record("deployment-a", "alpha");
    observed.trust = TrustState::Observed;
    assert!(observed.validate().is_err());
    observed.capabilities = CapabilityGrants::observed();
    observed.validate().unwrap();
    assert!(observed.require_mutation(&[Capability::Runtime]).is_err());
}

#[test]
fn immutable_security_identity_is_not_an_alias_or_runtime_name() {
    let mut deployment = record("deployment-a", "alpha");
    deployment.alias = Some(deployment.runtime_instances[0].object_reference.clone());
    deployment.validate().unwrap();
    assert_ne!(deployment.deployment_id, deployment.alias.unwrap());

    deployment = record("deployment-a", "alpha");
    deployment.control_authority.clear();
    assert!(deployment.validate().is_err());
}

#[test]
fn deployment_state_and_break_glass_roots_are_separate() {
    let work = PrivateTempDir::new("nazoauthctl-registry-boundaries").unwrap();
    let store = store(&work);
    store.persist(&record("deployment-a", "alpha")).unwrap();
    let state = store.deployment_state_dir("deployment-a");
    assert!(state.join("audit").is_dir());
    assert!(state.join("transactions").is_dir());
    assert!(state.join("recovery").is_dir());
    assert!(!store.break_glass_dir("deployment-a").starts_with(&state));
}

#[test]
fn locks_are_per_deployment_and_per_shared_resource() {
    let work = PrivateTempDir::new("nazoauthctl-registry-locks").unwrap();
    let store = store(&work);
    let _first = store.deployment_lock("deployment-a").unwrap();
    let _second = store.deployment_lock("deployment-b").unwrap();
    assert!(store.deployment_lock("deployment-a").is_err());
    let _shared_a = store.shared_resource_lock("database-a").unwrap();
    let _shared_b = store.shared_resource_lock("database-b").unwrap();
    assert!(store.shared_resource_lock("database-a").is_err());
}

#[test]
fn relinquish_can_reduce_one_capability_without_touching_shared_resources() {
    let mut deployment = record("deployment-a", "alpha");
    deployment.capabilities.database.scope = ResourceScope::Shared;
    deployment.capabilities.database.responsibility = Responsibility::External;
    deployment.validate().unwrap();
    assert!(
        !deployment
            .capabilities
            .database
            .responsibility
            .permits_mutation()
    );
    assert!(
        deployment
            .require_mutation(&[Capability::Runtime, Capability::Artifact])
            .is_ok()
    );
    assert!(
        deployment
            .require_mutation(&[Capability::Database])
            .is_err()
    );
}
