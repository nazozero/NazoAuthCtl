use super::*;
use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility},
    runtime_backend::{NeutralMount, RuntimeObservation},
};
use std::collections::BTreeMap;

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
