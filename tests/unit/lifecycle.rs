use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use super::*;
use crate::{
    deployment::{
        ArtifactReference, CapabilityGrants, RecoveryConclusion, ResourceScope, Responsibility,
        RuntimeBackendKind,
    },
    filesystem::{PrivateTempDir, sha256},
    runtime_backend::{ContainerRestartPolicy, ContainerRuntimePolicy, RuntimeObservation},
};

fn candidate(root: &Path, runtime_id: &str) -> DiscoveredDeployment {
    let mount = NeutralMount {
        source: root.join("application-data"),
        destination: PathBuf::from("/var/lib/nazo_oauth"),
        read_only: false,
        selinux_relabel: false,
        ownership: Responsibility::External,
        scope: ResourceScope::Deployment,
    };
    DiscoveredDeployment {
        target: format!("podman:manual-{runtime_id}"),
        deployment_id: Some("deployment-test".to_owned()),
        runtime_instance_id: Some(runtime_id.to_owned()),
        issuer: Some("https://issuer.example".to_owned()),
        release: Some("v0.1.19".to_owned()),
        revision: Some("a".repeat(40)),
        build_id: Some("build:test".to_owned()),
        instance_key_id: Some(format!("instance-{runtime_id}")),
        control_protocol_versions: vec![1],
        operator_protocol_versions: vec![1],
        runtime: RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: format!("manual-{runtime_id}"),
            display_name: runtime_id.to_owned(),
            running: false,
            server_command_verified: true,
            artifact: ArtifactReference::Unknown,
            local_artifact_id: None,
            ports: vec!["127.0.0.1:19000:8000".to_owned()],
            networks: vec!["manual-network".to_owned()],
            mounts: vec![mount],
            safe_environment: BTreeMap::new(),
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

fn lifecycle(work: &PrivateTempDir) -> LifecycleManifest {
    let driver = work.path().join("recovery-driver");
    fs::write(&driver, b"verified recovery driver").unwrap();
    let credential = work.path().join("database-credential");
    fs::write(&credential, b"not inspected by lifecycle validation").unwrap();
    let candidate = candidate(work.path(), "runtime-a");
    LifecycleManifest {
        schema: LIFECYCLE_SCHEMA,
        deployment_id: "deployment-test".to_owned(),
        runtimes: vec![RuntimeLifecycle {
            runtime_instance_id: "runtime-a".to_owned(),
            backend: RuntimeBackendKind::Podman,
            object_reference: "manual-runtime-a".to_owned(),
            command: vec!["nazoauth".to_owned(), "server".to_owned()],
            mounts: candidate.runtime.mounts,
            environment: BTreeMap::from([
                ("DATA_DIR".to_owned(), "/var/lib/nazo_oauth".to_owned()),
                (
                    "DATABASE_URL_FILE".to_owned(),
                    "/run/credentials/database-url".to_owned(),
                ),
            ]),
            networks: vec!["manual-network".to_owned()],
            ip_address: None,
            ports: vec!["127.0.0.1:19000:8000".to_owned()],
            container_policy: Some(ContainerRuntimePolicy {
                restart: ContainerRestartPolicy::No,
                read_only_root: false,
                no_new_privileges: false,
                drop_all_capabilities: false,
                pids_limit: None,
                memory_limit_bytes: None,
                cpu_limit_millis: None,
                tmpfs: Vec::new(),
            }),
        }],
        recovery_driver: RecoveryDriver {
            program_sha256: sha256(&driver).unwrap(),
            program: driver,
            arguments: vec!["--closed-json".to_owned()],
            rehearsal_workspace: work.path().join("isolated-rehearsal"),
            credentials: BTreeMap::from([(
                "database".to_owned(),
                CredentialReference::File { path: credential },
            )]),
        },
    }
}

#[test]
fn lifecycle_is_bound_to_every_discovered_runtime_without_secret_values() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-test").unwrap();
    let value = lifecycle(&work);
    value
        .validate_for_adoption(
            &[candidate(work.path(), "runtime-a")],
            &CapabilityGrants::observed(),
        )
        .unwrap();

    let encoded = serde_json::to_string(&value).unwrap();
    assert!(!encoded.contains("not inspected by lifecycle validation"));

    let mut mismatched = value.clone();
    mismatched.runtimes[0].object_reference = "another-object".to_owned();
    assert!(
        mismatched
            .validate_for_adoption(
                &[candidate(work.path(), "runtime-a")],
                &CapabilityGrants::observed(),
            )
            .is_err()
    );
}

#[test]
fn lifecycle_rejects_inline_secret_environment_and_rehearsal_mount_overlap() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-invalid-test").unwrap();
    let mut value = lifecycle(&work);
    value.runtimes[0]
        .environment
        .insert("DATABASE_URL".to_owned(), "postgresql://secret".to_owned());
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.recovery_driver.rehearsal_workspace = work.path().join("application-data/rehearsal");
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].mounts[0].source = DeploymentStore::system().state_root;
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].container_policy = None;
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].backend = RuntimeBackendKind::Systemd;
    value.runtimes[0].command[0] = work.path().join("nazoauth").display().to_string();
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0]
        .container_policy
        .as_mut()
        .unwrap()
        .pids_limit = Some(0);
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.schema = 1;
    assert!(value.validate().is_err());
}

#[test]
fn recovery_receipt_must_cover_every_mutable_capability() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-receipt-test").unwrap();
    let value = lifecycle(&work);
    let mut capabilities = CapabilityGrants::observed();
    capabilities.server_config.responsibility = Responsibility::Delegated;
    let request_id = "request-1";
    let lifecycle_sha256 = "a".repeat(64);
    let recovery_sha256 = "b".repeat(64);
    let mut receipt = RecoveryDriverReceipt {
        schema: RECOVERY_DRIVER_SCHEMA,
        request_id: request_id.to_owned(),
        deployment_id: value.deployment_id.clone(),
        release: "v0.1.19".to_owned(),
        operation: RecoveryOperation::Rehearse,
        lifecycle_sha256: lifecycle_sha256.clone(),
        recovery_manifest_sha256: recovery_sha256.clone(),
        status: RecoveryStatus::Succeeded,
        components: BTreeSet::from(["artifact".to_owned(), "verification".to_owned()]),
        checkpoint_manifest: None,
        checkpoint_manifest_sha256: None,
        issued_at: Utc::now().timestamp(),
    };
    assert!(
        validate_receipt(
            &receipt,
            request_id,
            &value,
            "v0.1.19",
            RecoveryOperation::Rehearse,
            &lifecycle_sha256,
            &recovery_sha256,
            &capabilities,
        )
        .is_err()
    );
    receipt.components.insert("data".to_owned());
    validate_receipt(
        &receipt,
        request_id,
        &value,
        "v0.1.19",
        RecoveryOperation::Rehearse,
        &lifecycle_sha256,
        &recovery_sha256,
        &capabilities,
    )
    .unwrap();
}

#[test]
fn checkpoint_receipt_requires_a_digest_bound_regular_recovery_manifest() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-checkpoint-test").unwrap();
    let value = lifecycle(&work);
    let checkpoint = work.path().join("checkpoint.json");
    fs::write(&checkpoint, b"{\"schema\":1}").unwrap();
    let request_id = "request-checkpoint";
    let lifecycle_sha256 = "a".repeat(64);
    let recovery_sha256 = "b".repeat(64);
    let mut receipt = RecoveryDriverReceipt {
        schema: RECOVERY_DRIVER_SCHEMA,
        request_id: request_id.to_owned(),
        deployment_id: value.deployment_id.clone(),
        release: "v0.1.19".to_owned(),
        operation: RecoveryOperation::Checkpoint,
        lifecycle_sha256: lifecycle_sha256.clone(),
        recovery_manifest_sha256: recovery_sha256.clone(),
        status: RecoveryStatus::Succeeded,
        components: BTreeSet::from(["artifact".to_owned(), "verification".to_owned()]),
        checkpoint_manifest: Some(checkpoint.clone()),
        checkpoint_manifest_sha256: Some(sha256(&checkpoint).unwrap()),
        issued_at: Utc::now().timestamp(),
    };
    validate_receipt(
        &receipt,
        request_id,
        &value,
        "v0.1.19",
        RecoveryOperation::Checkpoint,
        &lifecycle_sha256,
        &recovery_sha256,
        &CapabilityGrants::observed(),
    )
    .unwrap();

    receipt.checkpoint_manifest_sha256 = Some("c".repeat(64));
    assert!(
        validate_receipt(
            &receipt,
            request_id,
            &value,
            "v0.1.19",
            RecoveryOperation::Checkpoint,
            &lifecycle_sha256,
            &recovery_sha256,
            &CapabilityGrants::observed(),
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn recovery_driver_process_receipt_is_bound_to_the_closed_request() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-driver-process").unwrap();
    let driver = work.path().join("recovery-driver.py");
    fs::write(
        &driver,
        r#"#!/usr/bin/env python3
import json, sys, time
request = json.load(sys.stdin)
receipt = {
    "schema": request["schema"],
    "request_id": request["request_id"],
    "deployment_id": request["deployment_id"],
    "release": request["release"],
    "operation": request["operation"],
    "lifecycle_sha256": request["lifecycle_sha256"],
    "recovery_manifest_sha256": request["recovery_manifest_sha256"],
    "status": "succeeded",
    "components": ["artifact", "verification"],
    "issued_at": int(time.time())
}
json.dump(receipt, sys.stdout, separators=(",", ":"))
"#,
    )
    .unwrap();
    set_mode(&driver, 0o500).unwrap();
    let credential = work.path().join("database-credential");
    fs::write(&credential, b"not passed as an environment value").unwrap();
    let manifest_path = work.path().join("lifecycle.json");
    let recovery_manifest = work.path().join("recovery.json");
    fs::write(&recovery_manifest, b"{\"schema\":1}").unwrap();
    let mut value = lifecycle(&work);
    value.recovery_driver.program = driver.clone();
    value.recovery_driver.program_sha256 = sha256(&driver).unwrap();
    value.recovery_driver.arguments.clear();
    fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();

    let receipt = invoke_recovery_driver(
        &manifest_path,
        &value,
        &recovery_manifest,
        "v0.1.19",
        RecoveryOperation::Rehearse,
        &CapabilityGrants::observed(),
    )
    .unwrap();
    assert_eq!(receipt.operation, RecoveryOperation::Rehearse);
    assert_eq!(receipt.deployment_id, "deployment-test");
    assert_eq!(receipt.release, "v0.1.19");
}
