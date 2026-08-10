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
use ed25519_dalek::SigningKey;

use crate::filesystem::ensure_private_directory;
#[cfg(unix)]
use crate::filesystem::set_mode;

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
    let provider_key = work.path().join("provider-verification-key");
    fs::write(&provider_key, [7_u8; 32]).unwrap();
    let provider_signing = SigningKey::from_bytes(&[7_u8; 32]);
    let provider_id = nazo_operator_protocol::instance_key_id(&provider_signing.verifying_key());
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
            acceptance: RuntimeAcceptance {
                readiness_url: "https://issuer.example/ready".to_owned(),
                expected_issuer: "https://issuer.example".to_owned(),
                discovery_url: "https://issuer.example/.well-known/openid-configuration".to_owned(),
                ui_url: "https://issuer.example/ui/".to_owned(),
                ui_sha256: "a".repeat(64),
                ui_size: 1,
                attempts: 1,
                interval_seconds: 0,
            },
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
        recovery_providers: vec![RecoveryProviderTrust {
            provider_id,
            roles: BTreeSet::from([
                RecoveryArtifactRole::DataSnapshot,
                RecoveryArtifactRole::DatabaseRestore,
                RecoveryArtifactRole::LastTrustedArtifact,
                RecoveryArtifactRole::VerificationMaterial,
            ]),
            verification_key: SafeReference::DigestBoundFile {
                sha256: sha256(&provider_key).unwrap(),
                path: provider_key,
            },
        }],
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
fn lifecycle_mounts_must_be_an_exact_match_and_support_redacted_sources() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-mount-boundary-test").unwrap();
    let value = lifecycle(&work);
    let mut discovered = candidate(work.path(), "runtime-a");
    let actual_source = discovered.runtime.mounts[0].source.clone();
    discovered.runtime.mounts[0].source = PathBuf::from("<redacted-secret-source>");
    discovered.sensitive_mount_sources.insert(
        discovered.runtime.mounts[0].destination.clone(),
        actual_source,
    );

    value
        .validate_for_adoption(&[discovered.clone()], &CapabilityGrants::observed())
        .unwrap();

    let mut extra = value.clone();
    extra.runtimes[0].mounts.push(NeutralMount {
        source: work.path().join("extra"),
        destination: PathBuf::from("/var/lib/extra"),
        read_only: true,
        selinux_relabel: false,
        ownership: Responsibility::External,
        scope: ResourceScope::Deployment,
    });
    assert!(
        extra
            .validate_for_adoption(&[discovered], &CapabilityGrants::observed())
            .is_err()
    );

    let mut shared = value;
    shared.runtimes[0].mounts[0].scope = ResourceScope::Shared;
    let mut discovered_shared = candidate(work.path(), "runtime-a");
    discovered_shared.runtime.mounts[0].scope = ResourceScope::Shared;
    let mut mutable_capabilities = CapabilityGrants::observed();
    mutable_capabilities.runtime.responsibility = Responsibility::Delegated;
    assert!(
        shared
            .validate_for_adoption(&[discovered_shared], &mutable_capabilities,)
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
    value.schema = 2;
    assert!(value.validate().is_err());
}

#[test]
fn lifecycle_acceptance_contract_has_explicit_same_origin_and_bounded_urls() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-acceptance-url-boundary").unwrap();
    let mut value = lifecycle(&work);

    let loopback = &mut value.runtimes[0].acceptance;
    loopback.expected_issuer = "http://[::1]:19000".to_owned();
    loopback.readiness_url = "http://[::1]:19000/ready".to_owned();
    loopback.discovery_url = "http://[::1]:19000/.well-known/openid-configuration".to_owned();
    loopback.ui_url = "http://[::1]:19000/ui/".to_owned();
    value.validate().unwrap();

    let mut value = lifecycle(&work);

    value.runtimes[0].acceptance.readiness_url = "http://public.example/ready".to_owned();
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.discovery_url =
        "https://other.example/.well-known/openid-configuration".to_owned();
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.discovery_url =
        "https://issuer.example/.well-known/openid-configuration?redirect=1".to_owned();
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.attempts = MAX_ACCEPTANCE_ATTEMPTS + 1;
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.interval_seconds = MAX_ACCEPTANCE_INTERVAL_SECONDS + 1;
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.attempts = MAX_ACCEPTANCE_ATTEMPTS;
    value.runtimes[0].acceptance.interval_seconds = MAX_ACCEPTANCE_INTERVAL_SECONDS;
    assert!(value.validate().is_err());

    let mut value = lifecycle(&work);
    value.runtimes[0].acceptance.ui_size = MAX_ACCEPTANCE_UI_BYTES + 1;
    assert!(value.validate().is_err());
}

#[test]
fn lifecycle_acceptance_issuer_must_match_discovery_evidence() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-acceptance-issuer").unwrap();
    let mut value = lifecycle(&work);
    let mut discovered = candidate(work.path(), "runtime-a");
    discovered.issuer = Some("https://different.example".to_owned());
    assert!(
        value
            .validate_for_adoption(&[discovered], &CapabilityGrants::observed())
            .is_err()
    );

    value.runtimes[0].acceptance.expected_issuer = "https://different.example".to_owned();
    assert!(value.validate().is_err());
}

#[test]
fn rollback_progress_journal_is_durable_and_preserves_partial_replica_progress() {
    let work = PrivateTempDir::new("nazoauth-lifecycle-rollback-journal").unwrap();
    let path = work
        .path()
        .join("transactions/active-lifecycle-rollback.json");
    let identity = nazo_operator_protocol::EmbeddedIdentity {
        release: "v0.1.19".to_owned(),
        revision: "a".repeat(40),
        protocol: 1,
        build_id: "build:test".to_owned(),
    };
    let mut journal = RollbackExecution {
        schema: ROLLBACK_EXECUTION_SCHEMA,
        transaction_id: "rollback-test".to_owned(),
        deployment_id: "deployment-test".to_owned(),
        source_release: identity.clone(),
        target_release: identity.clone(),
        lifecycle_sha256: "a".repeat(64),
        cache_sha256: "b".repeat(64),
        target_release_sha256: embedded_identity_digest(&identity).unwrap(),
        state: RollbackExecutionState::Prepared,
        completed_runtimes: BTreeSet::from(["runtime-a".to_owned()]),
        updated_at: Utc::now().timestamp(),
    };
    persist_rollback_execution(&path, &journal).unwrap();
    let loaded = load_rollback_execution(&path).unwrap();
    assert_eq!(loaded.completed_runtimes, journal.completed_runtimes);

    journal.state = RollbackExecutionState::RuntimesActivated;
    journal.completed_runtimes.insert("runtime-b".to_owned());
    persist_rollback_execution(&path, &journal).unwrap();
    let resumed = load_rollback_execution(&path).unwrap();
    assert_eq!(resumed.state, RollbackExecutionState::RuntimesActivated);
    assert_eq!(resumed.completed_runtimes.len(), 2);
}

#[cfg(any(unix, windows))]
#[test]
fn recovery_driver_and_rehearsal_workspace_use_a_private_filesystem_boundary() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-lifecycle-filesystem-boundary").unwrap();
    let value = lifecycle(&work);

    #[cfg(unix)]
    {
        let driver = value.recovery_driver.program.clone();
        set_mode(&driver, 0o620).unwrap();
        assert!(value.validate().is_err());

        set_mode(&driver, 0o500).unwrap();
        let hard_link = work.path().join("recovery-driver-hard-link");
        std::fs::hard_link(&driver, &hard_link).unwrap();
        assert!(value.validate().is_err());
        std::fs::remove_file(&hard_link).unwrap();
    }

    let workspace = value.recovery_driver.rehearsal_workspace.clone();
    ensure_private_directory(&workspace, "recovery rehearsal workspace").unwrap();

    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(workspace).unwrap().permissions().mode() & 0o777,
        0o700
    );

    #[cfg(windows)]
    {
        assert!(workspace.is_dir());
        assert!(
            !std::fs::symlink_metadata(&workspace)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        crate::filesystem::validate_secure_directory(
            &workspace,
            "recovery rehearsal workspace",
            true,
        )
        .unwrap();
    }
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
fn recovery_driver_rejects_legacy_recovery_manifest_before_execution() {
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

    let error = invoke_recovery_driver(
        &manifest_path,
        &value,
        &recovery_manifest,
        "v0.1.19",
        RecoveryOperation::Rehearse,
        &CapabilityGrants::observed(),
    )
    .expect_err("legacy recovery evidence must fail closed before invoking the driver");
    assert!(
        error
            .to_string()
            .contains("unsupported recovery evidence schema")
    );
}
