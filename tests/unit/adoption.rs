use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    deployment::{ResourceScope, Responsibility, RuntimeBackendKind},
    filesystem::PrivateTempDir,
    runtime_backend::{NeutralMount, RuntimeObservation},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};

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

fn provider_manifest_fixture(
    work: &PrivateTempDir,
) -> (RecoveryEvidenceManifest, PathBuf, RecoveryProviderTrust) {
    let artifacts = [
        ("data", RecoveryArtifactRole::DataSnapshot, "data-evidence"),
        (
            "database",
            RecoveryArtifactRole::DatabaseRestore,
            "CREATE TABLE recovery_evidence;",
        ),
        (
            "release",
            RecoveryArtifactRole::LastTrustedArtifact,
            "release-evidence",
        ),
        (
            "verification",
            RecoveryArtifactRole::VerificationMaterial,
            "{\"schema\":1}",
        ),
    ]
    .into_iter()
    .map(|(name, role, content)| {
        let path = work.path().join(name);
        fs::write(&path, content.as_bytes()).unwrap();
        RecoveryArtifact {
            role: role.clone(),
            path: path.clone(),
            sha256: sha256(&work.path().join(name)).unwrap(),
            size: content.len() as u64,
            content_type: recovery_artifact_content_type(&role).to_owned(),
        }
    })
    .collect::<Vec<_>>();
    let signing = SigningKey::from_bytes(&[9_u8; 32]);
    let provider_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key());
    let mut manifest = RecoveryEvidenceManifest {
        schema: RECOVERY_EVIDENCE_SCHEMA,
        deployment_id: "deployment-test".to_owned(),
        release: "v0.1.19".to_owned(),
        data_snapshot: artifacts[0].clone(),
        database_restore: artifacts[1].clone(),
        last_trusted_artifact: artifacts[2].clone(),
        verification_material: artifacts[3].clone(),
        provider_attestation: ProviderAttestation {
            schema: PROVIDER_ATTESTATION_SCHEMA,
            provider_id: provider_id.clone(),
            deployment_id: "deployment-test".to_owned(),
            release: "v0.1.19".to_owned(),
            operation: RecoveryOperation::Rehearse,
            manifest_sha256: String::new(),
            lifecycle_sha256: "b".repeat(64),
            artifacts: Vec::new(),
            nonce: "nonce-adoption-provider".to_owned(),
            issued_at: Utc::now().timestamp(),
            expires_at: Utc::now().timestamp() + 60,
            signature: String::new(),
        },
    };
    manifest.provider_attestation.artifacts = recovery_artifacts(&manifest)
        .into_iter()
        .map(|(_, role, artifact)| ProviderArtifactReceipt {
            role,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
            content_type: artifact.content_type.clone(),
        })
        .collect();
    manifest.provider_attestation.manifest_sha256 = canonical_manifest_digest(&manifest).unwrap();
    let payload = ProviderAttestationPayload {
        schema: manifest.provider_attestation.schema,
        provider_id: &manifest.provider_attestation.provider_id,
        deployment_id: &manifest.provider_attestation.deployment_id,
        release: &manifest.provider_attestation.release,
        operation: manifest.provider_attestation.operation,
        manifest_sha256: &manifest.provider_attestation.manifest_sha256,
        lifecycle_sha256: &manifest.provider_attestation.lifecycle_sha256,
        artifacts: &manifest.provider_attestation.artifacts,
        nonce: &manifest.provider_attestation.nonce,
        issued_at: manifest.provider_attestation.issued_at,
        expires_at: manifest.provider_attestation.expires_at,
    };
    manifest.provider_attestation.signature = URL_SAFE_NO_PAD.encode(
        signing
            .sign(&serde_json::to_vec(&payload).unwrap())
            .to_bytes(),
    );
    let key_path = work.path().join("provider-key");
    atomic_write(&key_path, &signing.verifying_key().to_bytes(), 0o600).unwrap();
    let manifest_path = work.path().join("manifest-provider.json");
    atomic_write(
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest).unwrap(),
        0o600,
    )
    .unwrap();
    let trust = RecoveryProviderTrust {
        provider_id,
        roles: BTreeSet::from([
            RecoveryArtifactRole::DataSnapshot,
            RecoveryArtifactRole::DatabaseRestore,
            RecoveryArtifactRole::LastTrustedArtifact,
            RecoveryArtifactRole::VerificationMaterial,
        ]),
        verification_key: SafeReference::DigestBoundFile {
            path: key_path.clone(),
            sha256: sha256(&key_path).unwrap(),
        },
    };
    (manifest, manifest_path, trust)
}

fn write_manifest(path: &Path, manifest: &RecoveryEvidenceManifest) {
    atomic_write(path, &serde_json::to_vec_pretty(manifest).unwrap(), 0o600).unwrap();
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
        let content = match name {
            "database" => "CREATE TABLE recovery_evidence;".to_owned(),
            "verification" => "{\"schema\":1}".to_owned(),
            _ => format!("{name}-evidence"),
        };
        fs::write(&path, content.as_bytes()).unwrap();
        RecoveryArtifact {
            role: match name {
                "data" => RecoveryArtifactRole::DataSnapshot,
                "database" => RecoveryArtifactRole::DatabaseRestore,
                "release" => RecoveryArtifactRole::LastTrustedArtifact,
                "verification" => RecoveryArtifactRole::VerificationMaterial,
                _ => unreachable!(),
            },
            sha256: sha256(&path).unwrap(),
            path: path.clone(),
            size: fs::metadata(&path).unwrap().len(),
            content_type: match name {
                "data" => {
                    recovery_artifact_content_type(&RecoveryArtifactRole::DataSnapshot).to_owned()
                }
                "database" => {
                    recovery_artifact_content_type(&RecoveryArtifactRole::DatabaseRestore)
                        .to_owned()
                }
                "release" => {
                    recovery_artifact_content_type(&RecoveryArtifactRole::LastTrustedArtifact)
                        .to_owned()
                }
                "verification" => {
                    recovery_artifact_content_type(&RecoveryArtifactRole::VerificationMaterial)
                        .to_owned()
                }
                _ => unreachable!(),
            },
        }
    });
    let manifest_path = work.path().join("manifest.json");
    let mut manifest = RecoveryEvidenceManifest {
        schema: RECOVERY_EVIDENCE_SCHEMA,
        deployment_id: "deployment-test".to_owned(),
        release: "v0.1.19".to_owned(),
        data_snapshot: artifacts[0].clone(),
        database_restore: artifacts[1].clone(),
        last_trusted_artifact: artifacts[2].clone(),
        verification_material: artifacts[3].clone(),
        provider_attestation: ProviderAttestation {
            schema: PROVIDER_ATTESTATION_SCHEMA,
            provider_id: "provider-test".to_owned(),
            deployment_id: "deployment-test".to_owned(),
            release: "v0.1.19".to_owned(),
            operation: RecoveryOperation::Rehearse,
            manifest_sha256: "a".repeat(64),
            lifecycle_sha256: "b".repeat(64),
            artifacts: Vec::new(),
            nonce: "nonce-adoption-test".to_owned(),
            issued_at: Utc::now().timestamp(),
            expires_at: Utc::now().timestamp() + 60,
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        },
    };
    manifest.provider_attestation.artifacts = recovery_artifacts(&manifest)
        .into_iter()
        .map(|(_, role, artifact)| ProviderArtifactReceipt {
            role,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
            content_type: artifact.content_type.clone(),
        })
        .collect();
    manifest.provider_attestation.manifest_sha256 = canonical_manifest_digest(&manifest).unwrap();
    atomic_write(
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest).unwrap(),
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
fn provider_attestation_is_signed_provider_bound_and_single_use() {
    let work = PrivateTempDir::new("adoption-provider-attestation").unwrap();
    let (manifest, manifest_path, trust) = provider_manifest_fixture(&work);
    verify_provider_attestation_with_provider(
        &manifest_path,
        &manifest,
        &trust,
        &"b".repeat(64),
        RecoveryOperation::Rehearse,
        false,
    )
    .unwrap();

    let mut wrong_provider = trust.clone();
    wrong_provider.provider_id = "provider-wrong".to_owned();
    assert!(
        verify_provider_attestation_with_provider(
            &manifest_path,
            &manifest,
            &wrong_provider,
            &"b".repeat(64),
            RecoveryOperation::Rehearse,
            false,
        )
        .is_err()
    );

    verify_provider_attestation_with_provider(
        &manifest_path,
        &manifest,
        &trust,
        &"b".repeat(64),
        RecoveryOperation::Rehearse,
        true,
    )
    .unwrap();
    assert!(
        verify_provider_attestation_with_provider(
            &manifest_path,
            &manifest,
            &trust,
            &"b".repeat(64),
            RecoveryOperation::Rehearse,
            true,
        )
        .is_err()
    );
}

#[test]
fn recovery_evidence_rejects_alias_stale_wrong_role_unsigned_and_invalid_content() {
    let work = PrivateTempDir::new("adoption-recovery-contract-negative").unwrap();
    let (base, manifest_path, trust) = provider_manifest_fixture(&work);

    let mut alias = base.clone();
    alias.database_restore.path = alias.data_snapshot.path.clone();
    write_manifest(&manifest_path, &alias);
    assert!(verify_recovery_evidence(&manifest_path, "deployment-test", "v0.1.19").is_err());

    let mut stale = base.clone();
    stale.provider_attestation.issued_at = Utc::now().timestamp() - 1_000;
    write_manifest(&manifest_path, &stale);
    assert!(verify_recovery_evidence(&manifest_path, "deployment-test", "v0.1.19").is_err());

    let mut wrong_role = base.clone();
    wrong_role.data_snapshot.role = RecoveryArtifactRole::DatabaseRestore;
    write_manifest(&manifest_path, &wrong_role);
    assert!(verify_recovery_evidence(&manifest_path, "deployment-test", "v0.1.19").is_err());

    let mut unsigned = base.clone();
    unsigned.provider_attestation.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    write_manifest(&manifest_path, &unsigned);
    assert!(
        verify_provider_attestation_with_provider(
            &manifest_path,
            &unsigned,
            &trust,
            &"b".repeat(64),
            RecoveryOperation::Rehearse,
            false,
        )
        .is_err()
    );

    let mut content_invalid = base;
    fs::write(
        &content_invalid.database_restore.path,
        b"not a restore payload",
    )
    .unwrap();
    content_invalid.database_restore.sha256 =
        sha256(&content_invalid.database_restore.path).unwrap();
    content_invalid.database_restore.size = fs::metadata(&content_invalid.database_restore.path)
        .unwrap()
        .len();
    content_invalid.provider_attestation.artifacts = recovery_artifacts(&content_invalid)
        .into_iter()
        .map(|(_, role, artifact)| ProviderArtifactReceipt {
            role,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
            content_type: artifact.content_type.clone(),
        })
        .collect();
    content_invalid.provider_attestation.manifest_sha256 =
        canonical_manifest_digest(&content_invalid).unwrap();
    write_manifest(&manifest_path, &content_invalid);
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
