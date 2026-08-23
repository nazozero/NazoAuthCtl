use super::*;
use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility},
    runtime_backend::{NeutralMount, RuntimeObservation},
};
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown, symlink};

#[cfg(target_os = "linux")]
use crate::filesystem::PrivateTempDir;
#[cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;

fn candidate(target: &str, deployment_id: &str, runtime_instance_id: &str) -> DiscoveredDeployment {
    DiscoveredDeployment {
        target: target.to_owned(),
        deployment_id: Some(deployment_id.to_owned()),
        runtime_instance_id: Some(runtime_instance_id.to_owned()),
        issuer: Some("https://issuer.example".to_owned()),
        release: Some("v0.1.19".to_owned()),
        revision: Some("a".repeat(40)),
        build_id: Some("build:test".to_owned()),
        instance_key_id: Some(format!("key-{runtime_instance_id}")),
        control_protocol_versions: vec![1],
        operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
        runtime: RuntimeObservation {
            backend: RuntimeBackendKind::Podman,
            object_reference: target.to_owned(),
            display_name: target.to_owned(),
            running: true,
            server_command_verified: true,
            artifact: ArtifactReference::Oci {
                image_reference: "ghcr.io/nazozero/nazoauth".to_owned(),
                digest: format!("sha256:{}", "b".repeat(64)),
            },
            local_artifact_id: Some(format!("sha256:{}", "c".repeat(64))),
            ports: Vec::new(),
            networks: Vec::new(),
            mounts: Vec::new(),
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
        recovery_conclusion: RecoveryConclusion::Unproven,
        evidence: Vec::new(),
        missing: Vec::new(),
        sensitive_mount_sources: std::collections::BTreeMap::new(),
    }
}

#[cfg(target_os = "linux")]
fn runtime_owned_identity_descriptor(work: &PrivateTempDir) -> (PathBuf, SigningKey) {
    let directory = work.path().join("app/instance");
    fs::create_dir_all(&directory).unwrap();
    let signing_key = SigningKey::from_bytes(&[71; 32]);
    let public_key = signing_key.verifying_key();
    let key_id = nazo_operator_protocol::instance_key_id(&public_key);
    let statement = nazo_operator_protocol::DeploymentStatement {
        schema: CONTROL_DISCOVERY_SCHEMA,
        product: nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT.to_owned(),
        deployment_id: "deployment-runtime-owner".to_owned(),
        runtime_instance_id: "runtime-runtime-owner".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        release: "v0.1.41-candidate.459".to_owned(),
        revision: "a".repeat(40),
        build_id: format!("source:{}", "a".repeat(40)),
        control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
        operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
        instance_key_id: key_id.clone(),
        issued_at: 1,
    };
    let statement =
        nazo_operator_protocol::sign_deployment_statement(&statement, &key_id, &signing_key)
            .unwrap();
    let public_key_path = directory.join("identity.pub");
    let statement_path = directory.join("deployment-statement.jws");
    fs::write(
        &public_key_path,
        nazo_operator_protocol::encode_instance_public_key(&public_key),
    )
    .unwrap();
    fs::write(&statement_path, statement).unwrap();
    chown(&directory, Some(10_001), Some(10_001)).unwrap();
    for path in [&public_key_path, &statement_path] {
        chown(path, Some(10_001), Some(10_001)).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    (directory, signing_key)
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_owned_descriptor_requires_the_declared_service_uid_and_secure_filesystem_shape() {
    let work = PrivateTempDir::new("nazoauth-runtime-owned-descriptor").unwrap();
    // Chown is an essential part of this production-shaped fixture. A
    // non-root developer cannot manufacture it, so leave that environment to
    // the existing non-privileged filesystem coverage.
    if fs::metadata(work.path()).unwrap().uid() != 0 {
        return;
    }
    let (directory, signing_key) = runtime_owned_identity_descriptor(&work);

    let identity = load_verified_runtime_identity(&directory, Some(10_001)).unwrap();
    assert_eq!(identity.public_key, signing_key.verifying_key());
    assert_eq!(
        identity.statement.runtime_instance_id,
        "runtime-runtime-owner"
    );
    assert!(load_verified_runtime_identity(&directory, Some(10_002)).is_err());

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(load_verified_runtime_identity(&directory, Some(10_001)).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

    let public_key_path = directory.join("identity.pub");
    fs::set_permissions(&public_key_path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(load_verified_runtime_identity(&directory, Some(10_001)).is_err());
    fs::set_permissions(&public_key_path, fs::Permissions::from_mode(0o644)).unwrap();

    let public_key_link = work.path().join("identity-public-key-link");
    fs::hard_link(&public_key_path, &public_key_link).unwrap();
    assert!(load_verified_runtime_identity(&directory, Some(10_001)).is_err());
    fs::remove_file(&public_key_link).unwrap();

    let statement_path = directory.join("deployment-statement.jws");
    let decoy = work.path().join("decoy-statement");
    fs::write(&decoy, b"not the descriptor").unwrap();
    chown(&decoy, Some(10_001), Some(10_001)).unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o644)).unwrap();
    fs::remove_file(&statement_path).unwrap();
    symlink(&decoy, &statement_path).unwrap();
    assert!(load_verified_runtime_identity(&directory, Some(10_001)).is_err());
}

#[test]
fn multiple_runtime_candidates_are_ambiguous_even_inside_one_deployment() {
    let report = finalize_report(vec![
        candidate("podman:replica-b", "deployment-a", "runtime-b"),
        candidate("podman:replica-a", "deployment-a", "runtime-a"),
    ]);
    assert!(report.read_only);
    assert!(report.ambiguous);
    assert_eq!(report.candidates[0].target, "podman:replica-a");
    assert_eq!(report.candidates[1].target, "podman:replica-b");
    assert_eq!(
        report
            .candidates
            .iter()
            .map(|candidate| candidate.runtime_instance_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["runtime-a", "runtime-b"]
    );
}

#[test]
fn secret_mount_sources_are_redacted_without_changing_neutral_mount_authority() {
    let mut runtime = candidate("docker:manual", "deployment-a", "runtime-a").runtime;
    runtime.mounts = vec![NeutralMount {
        source: PathBuf::from("/private/database-password"),
        destination: PathBuf::from("/run/credentials/database"),
        read_only: true,
        selinux_relabel: false,
        ownership: Responsibility::External,
        scope: ResourceScope::Shared,
    }];
    redact_secret_mount_sources(&mut runtime);
    assert_eq!(
        runtime.mounts[0].source,
        PathBuf::from("<redacted-secret-source>")
    );
    assert_eq!(runtime.mounts[0].ownership, Responsibility::External);
    assert_eq!(runtime.mounts[0].scope, ResourceScope::Shared);
}

#[test]
fn public_discovery_runtime_omits_backend_labels_and_host_mount_sources() {
    let mut discovered = candidate("podman:public", "deployment-a", "runtime-a");
    discovered.runtime.labels.insert(
        "com.example.credentials".to_owned(),
        "database-password=do-not-print".to_owned(),
    );
    discovered.runtime.labels.insert(
        "io.nazoauth.deployment-id".to_owned(),
        "deployment-a".to_owned(),
    );
    discovered.runtime.mounts.push(NeutralMount {
        source: PathBuf::from("/srv/private/database-password"),
        destination: PathBuf::from("/run/credentials/database"),
        read_only: true,
        selinux_relabel: false,
        ownership: Responsibility::External,
        scope: ResourceScope::Shared,
    });

    let output = serde_json::to_value(&discovered).expect("discovery DTO should serialize");
    let runtime = output
        .get("runtime")
        .and_then(serde_json::Value::as_object)
        .expect("public runtime DTO should be an object");
    assert_eq!(
        runtime["labels"]["com.example.credentials"],
        serde_json::Value::Null
    );
    assert_eq!(
        runtime["labels"]["io.nazoauth.deployment-id"],
        "deployment-a"
    );
    let mount = runtime["mounts"]
        .as_array()
        .expect("public mounts should be an array")
        .first()
        .expect("fixture should expose one mount");
    assert_eq!(mount["source"], "<redacted-mount-source>");
    assert!(!output.to_string().contains("do-not-print"));
    assert!(!output.to_string().contains("database-password"));
}

#[test]
fn offline_statement_path_uses_the_declared_data_mount_not_mount_order() {
    let mut discovered = candidate("podman:runtime-a", "deployment-a", "runtime-a");
    discovered
        .runtime
        .safe_environment
        .insert("DATA_DIR".to_owned(), "/var/lib/nazo_oauth".to_owned());
    discovered.runtime.mounts = vec![
        NeutralMount {
            source: PathBuf::from("/etc/nazoauth/.env.yaml"),
            destination: PathBuf::from("/app/.env.yaml"),
            read_only: true,
            selinux_relabel: true,
            ownership: Responsibility::External,
            scope: ResourceScope::Deployment,
        },
        NeutralMount {
            source: PathBuf::from("/srv/nazoauth-a/data"),
            destination: PathBuf::from("/var/lib/nazo_oauth"),
            read_only: false,
            selinux_relabel: true,
            ownership: Responsibility::External,
            scope: ResourceScope::Deployment,
        },
    ];
    assert_eq!(
        deployment_statement_path(&discovered),
        Some(PathBuf::from(
            "/srv/nazoauth-a/data/instance/deployment-statement.jws"
        ))
    );
}

#[test]
fn stopped_systemd_identity_uses_signed_statement_at_declared_host_data_dir() {
    let mut discovered = candidate("systemd:custom.service", "deployment-host", "runtime-host");
    discovered.runtime.backend = RuntimeBackendKind::Systemd;
    discovered.runtime.safe_environment.insert(
        "INSTANCE_IDENTITY_DIR".to_owned(),
        "/srv/custom/identity".to_owned(),
    );
    assert_eq!(
        deployment_statement_path(&discovered),
        Some(PathBuf::from(
            "/srv/custom/identity/deployment-statement.jws"
        ))
    );
}

#[test]
fn online_identity_cannot_override_a_conflicting_offline_statement() {
    let online = DiscoveryStatement {
        schema: CONTROL_DISCOVERY_SCHEMA,
        product: nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT.to_owned(),
        deployment_id: "deployment-a".to_owned(),
        runtime_instance_id: "runtime-a".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        release: "v0.1.19".to_owned(),
        revision: "a".repeat(40),
        build_id: "build:test".to_owned(),
        control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
        operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
        instance_key_id: "instance-a".to_owned(),
        nonce: URL_SAFE_NO_PAD.encode([3; 32]),
        issued_at: 1,
        expires_at: 2,
    };
    let mut offline = DeploymentStatement {
        schema: online.schema,
        product: online.product.clone(),
        deployment_id: online.deployment_id.clone(),
        runtime_instance_id: online.runtime_instance_id.clone(),
        issuer: online.issuer.clone(),
        release: online.release.clone(),
        revision: online.revision.clone(),
        build_id: online.build_id.clone(),
        control_protocol_versions: online.control_protocol_versions.clone(),
        operator_protocol_versions: online.operator_protocol_versions.clone(),
        instance_key_id: online.instance_key_id.clone(),
        issued_at: 1,
    };
    assert!(statements_match(&online, &offline));
    offline.deployment_id = "deployment-b".to_owned();
    assert!(!statements_match(&online, &offline));
}
