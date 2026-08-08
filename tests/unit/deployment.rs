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
        active_release: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.1.19".to_owned(),
            revision: "a".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
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
            local_artifact_id: None,
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
fn shared_capability_cannot_be_declared_managed() {
    let mut deployment = record("deployment-a", "alpha");
    deployment.capabilities.database.scope = ResourceScope::Shared;
    deployment.capabilities.database.responsibility = Responsibility::Managed;
    assert!(deployment.validate().is_err());
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

    let invalid = DeploymentStore {
        config_root: work.path().join("etc-invalid"),
        state_root: work.path().join("controller"),
        break_glass_root: work.path().join("controller/break-glass"),
    };
    assert!(invalid.validate_failure_domains().is_err());
    store.validate_failure_domains().unwrap();
}

#[cfg(unix)]
#[test]
fn storage_failure_domains_reject_symlinked_roots() {
    let work = PrivateTempDir::new("nazoauthctl-storage-symlink").unwrap();
    let real = work.path().join("real-config");
    std::fs::create_dir(&real).unwrap();
    let linked = work.path().join("linked-config");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let store = DeploymentStore {
        config_root: linked,
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    };
    assert!(store.validate_failure_domains().is_err());
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

#[cfg(unix)]
#[test]
fn deployment_locks_reject_symlink_hardlink_and_writable_entries() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("nazoauthctl-lock-filesystem-boundary").unwrap();
    let store = store(&work);
    store.ensure_storage_roots().unwrap();
    let locks = store.state_root.join("locks");
    std::fs::create_dir_all(&locks).unwrap();

    let symlink_path = locks.join("deployment-deployment-symlink.lock");
    let target = work.path().join("lock-target");
    std::fs::write(&target, []).unwrap();
    symlink(&target, &symlink_path).unwrap();
    assert!(store.deployment_lock("deployment-symlink").is_err());

    let hard_link_path = locks.join("deployment-deployment-hard-link.lock");
    std::fs::hard_link(&target, &hard_link_path).unwrap();
    assert!(store.deployment_lock("deployment-hard-link").is_err());
    std::fs::remove_file(&hard_link_path).unwrap();

    let writable_path = locks.join("deployment-deployment-writable.lock");
    std::fs::write(&writable_path, []).unwrap();
    std::fs::set_permissions(&writable_path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(store.deployment_lock("deployment-writable").is_err());
}

#[test]
fn shared_capability_operations_use_the_same_stable_lock_as_resource_transitions() {
    let work = PrivateTempDir::new("nazoauthctl-shared-capability-locks").unwrap();
    let store = store(&work);
    let mut deployment = record("deployment-a", "alpha");
    deployment.capabilities.database.scope = ResourceScope::Shared;
    deployment.capabilities.database.responsibility = Responsibility::Delegated;
    let _deployment_lock = store.deployment_lock("deployment-a").unwrap();
    let _capability_locks = store
        .shared_capability_locks(&deployment, &[Capability::Database])
        .unwrap();
    assert!(store.shared_resource_lock("database").is_err());
}

#[test]
fn shared_capability_locks_are_sorted_deduplicated_and_exclude_deployment_resources() {
    let work = PrivateTempDir::new("nazoauthctl-shared-capability-lock-order").unwrap();
    let store = store(&work);
    let mut deployment = record("deployment-a", "alpha");
    deployment.capabilities.database.scope = ResourceScope::Shared;
    deployment.capabilities.database.responsibility = Responsibility::Delegated;
    deployment.capabilities.valkey.scope = ResourceScope::Shared;
    deployment.capabilities.valkey.responsibility = Responsibility::Delegated;

    let _locks = store
        .shared_capability_locks(
            &deployment,
            &[
                Capability::Valkey,
                Capability::Runtime,
                Capability::Database,
                Capability::Valkey,
            ],
        )
        .unwrap();
    assert_eq!(
        _locks.len(),
        2,
        "shared capability locks must be deterministic and deduplicated"
    );
    assert!(store.shared_resource_lock("database").is_err());
    assert!(store.shared_resource_lock("valkey").is_err());
    assert!(
        store.shared_resource_lock("runtime").is_ok(),
        "deployment-scoped capabilities must not acquire shared-resource locks"
    );
}

#[test]
fn declaration_persistence_requires_a_single_revision_step_and_exact_cas_snapshot() {
    let work = PrivateTempDir::new("nazoauthctl-declaration-cas").unwrap();
    let store = store(&work);
    let current = record("deployment-a", "alpha");
    store.persist(&current).unwrap();

    let mut updated = current.clone();
    updated.declaration_revision += 1;
    store
        .persist_declaration_cas_locked(&current, &updated)
        .unwrap();

    let mut stale = current;
    stale.alias = Some("stale".to_owned());
    stale.declaration_revision += 1;
    assert!(
        store
            .persist_declaration_cas_locked(&stale, &updated)
            .is_err()
    );
    assert_eq!(store.load("deployment-a").unwrap(), updated);

    let mut skipped = store.load("deployment-a").unwrap();
    skipped.declaration_revision += 2;
    assert!(store.persist_declaration_locked(&skipped).is_err());
    assert_eq!(store.load("deployment-a").unwrap(), updated);
}

#[test]
fn declaration_revision_overflow_fails_closed_without_changing_the_snapshot() {
    let work = PrivateTempDir::new("nazoauthctl-declaration-revision-overflow").unwrap();
    let store = store(&work);
    let mut current = record("deployment-a", "alpha");
    current.declaration_revision = u64::MAX;
    store.persist(&current).unwrap();

    assert!(store.persist_declaration_locked(&current).is_err());
    assert!(
        store
            .persist_declaration_cas_locked(&current, &current)
            .is_err()
    );
    assert_eq!(store.load("deployment-a").unwrap(), current);
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
