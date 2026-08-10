use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use super::*;
#[cfg(unix)]
use crate::test_support::write_shell_executable;
use crate::{
    filesystem::PrivateTempDir,
    model::{
        Artifact, DatabaseRestore, Dependencies, FrontendRelease, OciRelease, Operator,
        OperatorProtocolCompatibility, Postgres, Rollback, Runtime as RuntimeConfig, Ui, Valkey,
    },
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn self_update_install_path_is_normalized_and_non_symlink() {
    let work = PrivateTempDir::new("nazoauth-self-update-install-path").unwrap();
    let binary = work.path().join("nazoauthctl");
    fs::write(&binary, b"controller").unwrap();
    assert_eq!(controller_install_path(&binary).unwrap(), binary);
    assert!(controller_install_path(Path::new("relative/controller")).is_err());
    let navigated = work.path().join("missing/../controller");
    if navigated.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        assert!(controller_install_path(&navigated).is_err());
    } else {
        // Windows may normalize the joined PathBuf before the API observes it;
        // in that case the resulting value is already a normalized path.
        assert_eq!(controller_install_path(&navigated).unwrap(), navigated);
    }

    let directory = work.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(controller_install_path(&directory).is_err());
}

#[test]
fn self_update_journal_round_trip_preserves_phase_and_digest_bindings() {
    let work = PrivateTempDir::new("nazoauth-self-update-journal").unwrap();
    assert!(self_update_journal_round_trip_for_test(work.path()).unwrap());
}

#[test]
fn operation_results_are_machine_readable_json() {
    let value: serde_json::Value = serde_json::from_str(
        &operation_result_json(&operator::OperationResult {
            request_id: "request-test".to_owned(),
            result: nazo_operator_protocol::TaskResult::ConformanceLeaseCreated {
                lease: nazo_operator_protocol::ConformanceLeaseSummary {
                    lease_id: "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8a".to_owned(),
                    profile: "openid4vc".to_owned(),
                    material_sha256: "a".repeat(64),
                    created_at: 1,
                    expires_at: 2,
                    revoked_at: None,
                    cleaned_at: None,
                },
            },
            final_receipt: PathBuf::from("/audit/request-test.json"),
        })
        .unwrap(),
    )
    .unwrap();

    assert_eq!(value["request_id"], "request-test");
    assert_eq!(value["receipt"], "/audit/request-test.json");
    assert_eq!(
        value["result"]["lease"]["lease_id"],
        "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8a"
    );
}

fn manifest(version: &str, revision: char) -> ReleaseManifest {
    let target = crate::model::release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let binary = Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name: format!("nazoauth-{target}{suffix}"),
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 5,
        version: version.to_owned(),
        target: target.clone(),
        backend_commit: revision.to_string().repeat(40),
        release_identity: format!(
            "https://github.com/nazozero/NazoAuth/.github/workflows/release-security.yml@refs/tags/{version}"
        ),
        embedded: nazo_operator_protocol::EmbeddedIdentity {
            release: version.to_owned(),
            revision: revision.to_string().repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: format!("build:{version}"),
        },
        operator_protocol: Some(OperatorProtocolCompatibility {
            version: nazo_operator_protocol::PROTOCOL_VERSION,
            minimum_ctl_version: "0.1.19".to_owned(),
            maximum_ctl_version_exclusive: "0.2.0".to_owned(),
        }),
        artifacts: BTreeMap::from([("binary".to_owned(), binary)]),
        frontend: FrontendRelease {
            repository: "nazozero/NazoAuthWeb".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: "c".repeat(40),
            release_identity: "https://github.com/nazozero/NazoAuthWeb/.github/workflows/release.yml@refs/tags/v0.2.0".to_owned(),
            artifact: Artifact {
                repository: "nazozero/NazoAuthWeb".to_owned(),
                name: "nazoauth-web.tar.gz".to_owned(),
                sha256: "f".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "d".repeat(64)),
            platform_manifests: BTreeMap::from([
                ("linux/amd64".to_owned(), format!("sha256:{}", "1".repeat(64))),
                ("linux/arm64".to_owned(), format!("sha256:{}", "2".repeat(64))),
            ]),
        },
        rollback: Rollback {
            artifact: true,
            schema_compatible: true,
            database_restore: DatabaseRestore::Backup,
            irreversible_migration: false,
            minimum_supported_version: "0.0.0".to_owned(),
            migration_floor: "20260801000100".to_owned(),
            rationale: "additive migration".to_owned(),
        },
    }
}

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let absolute = |name: &str| work.path().join(name);
    UpdateConfig {
        schema: 2,
        trust: crate::deployment::TrustState::Adopted,
        capabilities: crate::deployment::CapabilityGrants::controller_installed(),
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        backup_root: absolute("backups"),
        deployment_root: absolute("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: absolute("operator/controller.key"),
            controller_public_key: absolute("operator/controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: absolute("operator/receipt.key"),
            receipt_public_key: absolute("operator/receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: absolute("operator/audit.key"),
            audit_public_key: absolute("operator/audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: absolute("operator/break-glass.key"),
            break_glass_public_key: absolute("operator/break-glass.pub"),
            active_identity_file: absolute("operator/active-generation.json"),
            identity_generations_directory: absolute("operator/generations"),
            recovery_generations_directory: absolute("recovery/generations"),
            secret_revision_file: absolute("operator/secret-revision"),
            state_directory: absolute("operator-state"),
            audit_directory: absolute("audit"),
            trust_state_file: absolute("operator/release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: RuntimeConfig {
            backend: RuntimeBackendKind::Systemd,
            dependency_backend: None,
            backend_command_override: None,
            container_name: "nazoauth".to_owned(),
            runtime_instance_id: "runtime-test".to_owned(),
            network: "nazoauth".to_owned(),
            ip_address: String::new(),
            publish_address: String::new(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: Vec::new(),
            snapshot_paths: Vec::new(),
            environment: BTreeMap::new(),
            service_name: "nazoauth.service".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: absolute("nazoauth"),
            binary_releases: absolute("releases"),
            working_directory: work.path().to_owned(),
        },
        postgres: Postgres {
            container_name: "postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "migrator".to_owned(),
            image: "postgres".to_owned(),
            validation_image: "postgres".to_owned(),
        },
        valkey: Valkey {
            container_name: "valkey".to_owned(),
            data_volume: "valkey-data".to_owned(),
            image: "valkey".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: PathBuf::new(),
        },
        ui: Ui {
            releases_root: absolute("ui-releases"),
        },
    }
}

fn journal(config: &UpdateConfig, phase: UpdatePhase) -> UpdateJournal {
    UpdateJournal {
        schema: 1,
        transaction_id: "update-test".to_owned(),
        started_at: "2026-08-01T00:00:00Z".to_owned(),
        phase,
        from_release: manifest("v0.1.2", 'b'),
        to_release: manifest("v0.2.0", 'e'),
        previous_runtime: config
            .runtime
            .binary_releases
            .join("b".repeat(40))
            .join("nazoauth")
            .display()
            .to_string(),
        previous_ui: Some(config.ui.releases_root.join("f".repeat(64))),
        candidate_runtime: config
            .runtime
            .binary_releases
            .join("e".repeat(40))
            .join("nazoauth")
            .display()
            .to_string(),
        candidate_ui: config.ui.releases_root.join("f".repeat(64)),
        backup: (phase >= UpdatePhase::BackupCreated)
            .then(|| config.backup_root.join("v0.2.0-test")),
    }
}

const OPENID4VC_TEST_LEAF: &str = "-----BEGIN CERTIFICATE-----\nMIIFWzCCBEOgAwIBAgISAyBIAwu7NBD5CTxX8suDCMgFMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA3MTIxMTEyMzBaFw0x\nOTEwMTAxMTEyMzBaMB0xGzAZBgNVBAMTEmxpc3RzLmZvci1vdXIuaW5mbzCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVoti34X46DaI2nX24C+aZ2Ofkm\nhKbidiXiRTon1MLSMGl1oNW9MyRyYYCzP4j6DNKChJnr8ZnVShh2oZD+yHWP9lpn\nXMGkbsUxejRMU9hnaAB50pXRIDAzavkVFCguFlJ8nKkv/Y1Avlw7tc2aZOd3lOZB\nEr8gJ8mRDGqqsNU+Z12I6slEstzGMpsq6AewCVw4lMjdWWgugzUrxQTRAsG87on6\ngOiQH2cMODN3L7Fq4KOLQIjb3/luQhAQhpdKmEGFLin3c+f5or3thCDuwwDtOU1l\nZf+8t9S8pZPLrZrIs6H2xjXqCRuUY7iRNbO18Ukc6rlDYhBj9LT+cpmBbHECAwEA\nAaOCAmYwggJiMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\nKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUJj2pvRtl3GloH3He6FX1\nds3X0VEwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUH\nAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5\ncHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5\ncHQub3JnLzAdBgNVHREEFjAUghJsaXN0cy5mb3Itb3VyLmluZm8wTAYDVR0gBEUw\nQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0cDov\nL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgAp\nPFGWVMg5ZbqqUPxYB9S3b79Yeily3KTDDPTlRUf0eAAAAWvmGV7yAAAEAwBHMEUC\nICQL2Sm14aCMLxX9a9RbySgyBfichMRdbu6QA2Mbrl4eAiEA1vgJ7snqUWCgoqEE\n3SEfK3ioMopzWBsPvG6LdCuCMRAAdQBvU3asMfAxGdiZAKRRFf93FRwR2QLBACkG\njbIImjfZEwAAAWvmGV9oAAAEAwBGMEQCIExGqw3Lo0nSCyUuTRf92FgGASwWYji5\nUGnXuYnpJrAvAiBw8AWVag8fzZ4ogAhY9EFRNdLrUcBjStipL888vyuxKzANBgkq\nhkiG9w0BAQsFAAOCAQEAF8BBLDvSWZg57B6aDtzfUTSGetCYs3k0vJqCJlL+Pz7/\nUruCSsojQzp5R6jvvgYQ83MaIdwe2mgt+OCQB5v7ylctyBzBmYIw9nPnxEC7HlcJ\nL2K/k5ZjJFRnv4kV1Si8+TIpEAV0ksf39KGKemG8kGi4GXV1v03zSv0p8aCarpuo\nSKBJ4qlB0CvmS2MqV4KnzO0O2h0c/ZQ4jg7l53eiN7VPdRMMO1DRw+MaW6I/hEZp\n+oZQ7hhKXgKUBvF4IGwyrfyIZ8AeWKG4IP98COgyRbz7qtrAVevRKCM0ZC2t04A2\nFcix40FKEeiE093Aj3cweMYxNLPgwgQP8Xu3kA5QEw==\n-----END CERTIFICATE-----\n";

const OPENID4VC_TEST_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIC5DCCAcygAwIBAgIULPew9IlvsTLtEgLZKaBAbHMWN6kwDQYJKoZIhvcNAQEL\nBQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA4MDExMTQ0MjNaFw0yNjA4MDIx\nMTQ0MjNaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQDdFDwuha9KOic60ADk6zfGqrLTu4cXMVqs21lSP9mRrrNMfxpx\nVHw3flH8dxwVKGEr7ekAtnyceSApK/zmfnzaR9yrAyRtxIpWnSK1mMG01s4GKEsV\nFDeQPWZoEeHTMN6OfJ0PIzjNYIU060Ek2Yv0PPwEscjLZYyDaMtIQyEmPo3HB2/K\nGGMXzPN4uyvGOvKhX9hj7+Mpazfiz7uiX5U0ddeUkKm0pmLL3CrRtrq9sEZhRaVp\nYqJd4t7rnMSe3Xvrq6t+RFvlKrWj8hRe902vqGdglIqiNllRH6x7HJbhf2iixVDM\nrS6K2MgtnCi5Eb6zL9TC+5bW7aSXc3bS95qZAgMBAAGjMjAwMB0GA1UdDgQWBBS9\nUVt3endltN1shOipGpPp4CJNkjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\nCwUAA4IBAQA4m2pWKEmz2YssnnyuZL7FHEVjlsDj0i8jGxHPUDbkeS0XLNCiY4NA\nPKZTjA9WJrcvgNcPaCC3GvWMRXLwNdUNjv4dF5VvscH9A3jo3HXl0Ht2zV7+g/lA\nCPSgIh58j6Tvduvl0TfplYnYFkKHq5+wjffZio5fqZ5heqxnREoJGTKtmUr0xJYj\nF3jUGLrX0QSqVaWloAbxR082dOJMHDcYosw0V/8cUuaHCWv2/wnH+RELG5tK59QS\nNgHe7Cd3DspxYA3jVdDINdFM10mklS8Di0twdoeAsrxyWYTR84RV5A/tHe1Zuxfb\n6P3fmVV6Dhj+M+skGJHFtiEap366e847\n-----END CERTIFICATE-----\n";

#[test]
fn openid4vc_trust_export_keeps_only_the_ca_certificate() {
    let anchors = extract_openid4vc_trust_anchors(
        format!("{OPENID4VC_TEST_LEAF}{OPENID4VC_TEST_CA}").as_bytes(),
    )
    .unwrap();
    let anchors = String::from_utf8(anchors).unwrap();
    assert_eq!(anchors.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    assert!(!anchors.contains("lists.for-our.info"));
    let (_, pem) = x509_parser::pem::parse_x509_pem(anchors.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    assert!(certificate.is_ca());
    assert!(extract_openid4vc_trust_anchors(OPENID4VC_TEST_CA.as_bytes()).is_err());
    assert!(
        extract_openid4vc_trust_anchors(
            format!("{OPENID4VC_TEST_CA}{OPENID4VC_TEST_LEAF}").as_bytes()
        )
        .is_err()
    );
    assert!(extract_openid4vc_trust_anchors(b"-----BEGIN PRIVATE KEY-----\nno\n").is_err());
    assert!(
        extract_openid4vc_trust_anchors(
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
        )
        .is_err()
    );
    assert!(
        extract_openid4vc_trust_anchors(
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        )
        .is_err()
    );
    let (_, leaf) = x509_parser::pem::parse_x509_pem(OPENID4VC_TEST_LEAF.as_bytes()).unwrap();
    let mut leaf_with_trailing_data = leaf.contents;
    leaf_with_trailing_data.push(0);
    let mut invalid_bundle = Vec::new();
    append_pem_certificate(&mut invalid_bundle, &leaf_with_trailing_data);
    assert!(extract_openid4vc_trust_anchors(&invalid_bundle).is_err());
    let oversized = vec![b' '; MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES + 1];
    assert!(extract_openid4vc_trust_anchors(&oversized).is_err());
    assert_eq!(trim_ascii_whitespace(b" \n\tcertificate"), b"certificate");
}

#[test]
fn openid4vc_trust_export_destination_is_absolute_regular_and_atomic() {
    let work = PrivateTempDir::new("openid4vc-trust-export-output").unwrap();
    let output = work.path().join("request-object-trust.pem");
    safe_export_destination(&output).unwrap();
    atomic_write(&output, b"old", 0o644).unwrap();
    safe_export_destination(&output).unwrap();
    atomic_write(&output, b"new", 0o644).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"new");
    assert!(safe_export_destination(Path::new("relative.pem")).is_err());
    assert!(safe_export_destination(&work.path().join("missing/output.pem")).is_err());
    let parent_file = work.path().join("parent-file");
    fs::write(&parent_file, b"not-a-directory").unwrap();
    assert!(safe_export_destination(&parent_file.join("output.pem")).is_err());
    let directory = work.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(safe_export_destination(&directory).is_err());
    #[cfg(unix)]
    {
        let target = work.path().join("target.pem");
        fs::write(&target, b"target").unwrap();
        let link = work.path().join("link.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(safe_export_destination(&link).is_err());

        let real_parent = work.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        let linked_parent = work.path().join("linked-parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
        assert!(safe_export_destination(&linked_parent.join("output.pem")).is_err());
    }
}

#[test]
fn openid4vc_trust_export_uses_only_the_managed_key_directory() {
    let work = PrivateTempDir::new("openid4vc-trust-export-managed-path").unwrap();
    let mut value = config(&work);
    value.install_profile = "standards-full".to_owned();
    let keys = work.path().join("app/keys");
    fs::create_dir_all(&keys).unwrap();
    value.runtime.snapshot_paths = vec![keys.clone()];
    assert_eq!(
        managed_openid4vc_bundle_path(&value).unwrap(),
        keys.join(OPENID4VC_CERTIFICATE_BUNDLE)
    );
    #[cfg(unix)]
    {
        let linked_root = work.path().join("linked-root");
        fs::create_dir(&linked_root).unwrap();
        let linked_keys = linked_root.join("keys");
        std::os::unix::fs::symlink(&keys, &linked_keys).unwrap();
        value.runtime.snapshot_paths = vec![linked_keys];
        assert!(managed_openid4vc_bundle_path(&value).is_err());
        value.runtime.snapshot_paths = vec![keys.clone()];
    }
    value
        .runtime
        .snapshot_paths
        .push(work.path().join("other/keys"));
    assert!(managed_openid4vc_bundle_path(&value).is_err());

    value.runtime.backend = RuntimeBackendKind::Podman;
    value.runtime.snapshot_paths.clear();
    value.runtime.mounts = vec![crate::model::Mount {
        source: keys.clone(),
        target: PathBuf::from(OPENID4VC_KEYS_MOUNT),
        read_only: false,
        selinux_relabel: true,
    }];
    assert_eq!(
        managed_openid4vc_bundle_path(&value).unwrap(),
        keys.join(OPENID4VC_CERTIFICATE_BUNDLE)
    );
    value.runtime.mounts[0].read_only = true;
    assert!(managed_openid4vc_bundle_path(&value).is_err());
}

#[cfg(unix)]
#[test]
fn openid4vc_trust_export_is_release_bound_audited_and_fail_closed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("openid4vc-trust-export-audit").unwrap();
    let output = work.path().join("export/trust-anchors.pem");
    fs::create_dir(output.parent().unwrap()).unwrap();

    let mut value = config(&work);
    assert!(export_openid4vc_trust(&value, &output).is_err());

    value.install_profile = "standards-full".to_owned();
    let keys = work.path().join("app/keys");
    fs::create_dir_all(&keys).unwrap();
    value.runtime.snapshot_paths = vec![keys.clone()];
    assert!(export_openid4vc_trust(&value, &output).is_err());

    let bundle = keys.join(OPENID4VC_CERTIFICATE_BUNDLE);
    fs::create_dir(&bundle).unwrap();
    assert!(export_openid4vc_trust(&value, &output).is_err());
    fs::remove_dir(&bundle).unwrap();
    fs::write(&bundle, format!("{OPENID4VC_TEST_LEAF}{OPENID4VC_TEST_CA}")).unwrap();

    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(export_openid4vc_trust(&value, &output).is_err());
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o644)).unwrap();

    let decoy = keys.join("decoy-certificate-bundle.pem");
    fs::write(&decoy, format!("{OPENID4VC_TEST_LEAF}{OPENID4VC_TEST_CA}")).unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o644)).unwrap();
    fs::remove_file(&bundle).unwrap();
    symlink(&decoy, &bundle).unwrap();
    assert!(export_openid4vc_trust(&value, &output).is_err());
    fs::remove_file(&bundle).unwrap();

    fs::write(&bundle, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(export_openid4vc_trust(&value, &output).is_err());
    fs::write(&bundle, format!("{OPENID4VC_TEST_LEAF}{OPENID4VC_TEST_CA}")).unwrap();

    fs::create_dir_all(&value.deployment_root).unwrap();
    write_active_release(&value, &manifest("v0.1.9", 'e')).unwrap();
    install_audit_key(&value);
    export_openid4vc_trust(&value, &output).unwrap();

    assert_eq!(fs::read_to_string(&output).unwrap(), OPENID4VC_TEST_CA);
    crate::operator::verify_audit(&value).unwrap();
    let mut operations = fs::read_dir(value.operator.audit_directory.join("management"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .map(|name| {
            crate::operator::load_management_event(&value, &name)
                .unwrap()
                .operation
        })
        .collect::<Vec<_>>();
    operations.sort();
    assert_eq!(
        operations,
        [
            "keys-export-openid4vc-trust-completed",
            "keys-export-openid4vc-trust-intent",
        ]
    );
}

#[test]
fn bootstrap_credentials_are_closed_bounded_json() {
    let parsed = parse_bootstrap_admin_credentials(
        br#"{"email":"Admin@Example.COM","password":"correct horse battery staple"}"#,
    )
    .unwrap();
    assert_eq!(parsed.email, "Admin@Example.COM");
    assert_eq!(parsed.password, "correct horse battery staple");

    for input in [
        br#"{"email":"admin@example.com"}"#.as_slice(),
        br#"{"email":"admin@example.com","password":"short"}"#.as_slice(),
        br#"{"email":"not-an-email","password":"correct horse battery staple"}"#.as_slice(),
        br#"{"email":"admin@example.com","password":"correct horse battery staple","token":"forbidden"}"#.as_slice(),
        br#"{"email":"admin@example.com","password":"correct horse battery staple"} trailing"#.as_slice(),
    ] {
        assert!(parse_bootstrap_admin_credentials(input).is_err());
    }
    assert!(
        parse_bootstrap_admin_credentials(&vec![b'x'; MAX_BOOTSTRAP_CREDENTIAL_BYTES as usize + 1])
            .is_err()
    );

    let work = PrivateTempDir::new("nazoauth-bootstrap-short-password").unwrap();
    let value = config(&work);
    assert!(
        claim_bootstrap_admin(
            &value,
            &BootstrapAdminCredentials {
                email: "admin@example.com".to_owned(),
                password: "too-short".to_owned(),
            },
            &uuid::Uuid::now_v7().to_string(),
            std::ffi::OsStr::new("unused-curl"),
            None,
        )
        .is_err()
    );
}

#[test]
fn bootstrap_endpoint_is_fixed_to_the_public_api() {
    assert_eq!(
        bootstrap_admin_endpoint("https://auth.example")
            .unwrap()
            .as_str(),
        "https://auth.example/auth/bootstrap-admin"
    );
    assert!(bootstrap_admin_endpoint("http://auth.example").is_err());
    assert!(bootstrap_admin_endpoint("https://user@auth.example").is_err());
    assert!(bootstrap_admin_endpoint("https://auth.example/other").is_err());
    assert!(bootstrap_admin_endpoint("https://auth.example?token=secret").is_err());
}

#[cfg(unix)]
fn write_bootstrap_fixture(
    work: &PrivateTempDir,
    config: &mut UpdateConfig,
    token: &str,
) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = work.path().join("bootstrap");
    fs::create_dir_all(config.operator.secret_revision_file.parent().unwrap()).unwrap();
    fs::write(
        &config.operator.secret_revision_file,
        b"stable-deployment-bootstrap-binding",
    )
    .unwrap();
    fs::set_permissions(
        &config.operator.secret_revision_file,
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let token_path = directory.join(BOOTSTRAP_TOKEN_FILE);
    fs::write(&token_path, token).unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    config.runtime.backend = RuntimeBackendKind::Docker;
    config.runtime.mounts = vec![crate::model::Mount {
        source: directory,
        target: PathBuf::from(BOOTSTRAP_MOUNT_TARGET),
        read_only: false,
        selinux_relabel: true,
    }];
    token_path
}

#[cfg(unix)]
fn write_fake_bootstrap_curl(
    work: &PrivateTempDir,
    response: &str,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let executable = work.path().join("fake-curl");
    let arguments = work.path().join("curl-arguments");
    let body = work.path().join("curl-body");
    let environment = work.path().join("curl-environment");
    write_shell_executable(
        &executable,
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\n/usr/bin/env > '{}'\n/bin/cat > '{}'\nprintf '%s\\n' '{}'\nprintf '%s' '201'",
            arguments.display(),
            environment.display(),
            body.display(),
            response
        ),
    );
    (executable, arguments, body, environment)
}

#[cfg(unix)]
fn write_bootstrap_pending_fixture(
    config: &UpdateConfig,
    email: &str,
    request_id: &str,
    status: BootstrapAdminPendingStatus,
) {
    fs::create_dir_all(config.operator.secret_revision_file.parent().unwrap()).unwrap();
    fs::write(
        &config.operator.secret_revision_file,
        b"stable-deployment-bootstrap-binding",
    )
    .unwrap();
    fs::set_permissions(
        &config.operator.secret_revision_file,
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let pending = BootstrapAdminPending {
        schema: 2,
        request_id: request_id.to_owned(),
        email_hmac_sha256: bootstrap_email_hmac(config, email).unwrap(),
        recovery_epoch: current_bootstrap_recovery_epoch(config).unwrap(),
        status,
        claimed_user_id: None,
        token_hmac_sha256: None,
    };
    fs::create_dir_all(&config.operator.state_directory).unwrap();
    atomic_write(
        &bootstrap_pending_path(config),
        &serde_json::to_vec_pretty(&pending).unwrap(),
        0o600,
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn bootstrap_submission_keeps_secrets_in_request_stdin_and_retains_retry_token() {
    let work = PrivateTempDir::new("nazoauth-bootstrap-admin").unwrap();
    let mut config = config(&work);
    let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let password = "password-canary-correct-horse-battery-staple";
    let token_path = write_bootstrap_fixture(&work, &mut config, token);
    let request_id = "bootstrap-admin-0123456789abcdef0123456789abcdef";
    let response = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"admin@example.com","role":"admin","next":"/ui/auth"}"#;
    let (curl, arguments, body, environment) = write_fake_bootstrap_curl(&work, response);
    let credentials = BootstrapAdminCredentials {
        email: "Admin@Example.COM".to_owned(),
        password: password.to_owned(),
    };

    claim_bootstrap_admin(&config, &credentials, request_id, curl.as_os_str(), None).unwrap();

    assert!(token_path.exists());
    let arguments = fs::read_to_string(arguments).unwrap();
    let environment = fs::read_to_string(environment).unwrap();
    for secret in [token, password, "Admin@Example.COM"] {
        assert!(!arguments.contains(secret));
        assert!(!environment.contains(secret));
    }
    assert!(arguments.contains("@-"));
    assert!(arguments.contains("https://auth.example/auth/bootstrap-admin"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(body).unwrap()).unwrap(),
        serde_json::json!({
            "request_id": request_id,
            "token": token,
            "email": "admin@example.com",
            "password": password,
        })
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_claim_rejects_response_substitution_without_consuming_the_token() {
    let work = PrivateTempDir::new("nazoauth-bootstrap-response").unwrap();
    let mut config = config(&work);
    let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let token_path = write_bootstrap_fixture(&work, &mut config, token);
    write_active_release(&config, &manifest("v0.2.0", 'e')).unwrap();
    install_audit_key(&config);
    write_bootstrap_pending_fixture(
        &config,
        "admin@example.com",
        "bootstrap-admin-0123456789abcdef0123456789abcdef",
        BootstrapAdminPendingStatus::Intent,
    );
    let response = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"admin@example.com","role":"admin","next":"/ui/login"}"#;
    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, response);
    let credentials = BootstrapAdminCredentials {
        email: "admin@example.com".to_owned(),
        password: "correct horse battery staple".to_owned(),
    };

    let error = audited_bootstrap_admin(&config, &credentials, curl.as_os_str(), None).unwrap_err();
    assert!(format!("{error:#}").contains("unexpected response contract"));
    assert!(token_path.exists());
    crate::operator::verify_audit(&config).unwrap();
    let mut operations = fs::read_dir(config.operator.audit_directory.join("management"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .map(|name| {
            crate::operator::load_management_event(&config, &name)
                .unwrap()
                .operation
        })
        .collect::<Vec<_>>();
    operations.sort();
    assert_eq!(
        operations,
        ["bootstrap-admin-intent", "bootstrap-admin-outcome-unknown"]
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_state_rejects_ambiguous_or_weak_secret_sources() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-bootstrap-boundaries").unwrap();
    let mut config = config(&work);
    let token_path = write_bootstrap_fixture(
        &work,
        &mut config,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    );
    assert_eq!(bootstrap_token_path(&config, None).unwrap(), token_path);

    config.runtime.mounts.push(config.runtime.mounts[0].clone());
    assert!(bootstrap_token_path(&config, None).is_err());
    config.runtime.mounts.pop();

    fs::set_permissions(
        token_path.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(bootstrap_token_path(&config, None).is_err());
}

#[cfg(unix)]
#[test]
fn bootstrap_owner_policy_matches_real_container_and_host_runtime_identities() {
    use std::os::unix::fs::MetadataExt as _;

    let work = PrivateTempDir::new("nazoauth-bootstrap-owner").unwrap();
    let mut config = config(&work);
    let token_path = write_bootstrap_fixture(
        &work,
        &mut config,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    );
    assert_eq!(bootstrap_state_owner_uid(&config).unwrap(), 10_001);

    let actual_uid = fs::metadata(token_path.parent().unwrap()).unwrap().uid();
    assert_eq!(
        bootstrap_token_path(&config, Some(actual_uid)).unwrap(),
        token_path
    );
    assert!(bootstrap_token_path(&config, Some(actual_uid.wrapping_add(1))).is_err());

    config.runtime.backend = RuntimeBackendKind::Systemd;
    config.runtime.service_user = Process::new("id")
        .arg("-un")
        .stdout()
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(bootstrap_state_owner_uid(&config).unwrap(), actual_uid);
}

#[cfg(unix)]
#[test]
fn bootstrap_token_descriptor_rejects_symlink_unsafe_mode_and_oversize_inputs() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("nazoauth-bootstrap-token-descriptor").unwrap();
    let mut config = config(&work);
    let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let token_path = write_bootstrap_fixture(&work, &mut config, token);
    let owner_uid = fs::metadata(&token_path).unwrap().uid();
    assert_eq!(
        read_bootstrap_token(&token_path, Some(owner_uid)).unwrap(),
        token
    );

    let decoy = token_path.with_file_name("decoy-token");
    fs::write(&decoy, token).unwrap();
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&token_path).unwrap();
    symlink(&decoy, &token_path).unwrap();
    assert!(read_bootstrap_token(&token_path, Some(owner_uid)).is_err());

    fs::remove_file(&token_path).unwrap();
    fs::write(&token_path, token).unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_bootstrap_token(&token_path, Some(owner_uid)).is_err());

    fs::write(
        &token_path,
        vec![b'x'; MAX_BOOTSTRAP_TOKEN_BYTES as usize + 1],
    )
    .unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_bootstrap_token(&token_path, Some(owner_uid)).is_err());
}

#[cfg(unix)]
#[test]
fn bootstrap_pending_binding_survives_controller_and_break_glass_key_rotation() {
    let work = PrivateTempDir::new("nazoauth-bootstrap-rotation").unwrap();
    let mut config = config(&work);
    write_bootstrap_fixture(
        &work,
        &mut config,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    );
    write_bootstrap_pending_fixture(
        &config,
        "admin@example.com",
        "bootstrap-admin-0123456789abcdef0123456789abcdef",
        BootstrapAdminPendingStatus::Intent,
    );
    fs::write(
        &config.operator.controller_private_key,
        b"controller-before",
    )
    .unwrap();
    fs::create_dir_all(config.operator.break_glass_private_key.parent().unwrap()).unwrap();
    fs::write(
        &config.operator.break_glass_private_key,
        b"break-glass-before",
    )
    .unwrap();
    let before = load_or_create_bootstrap_pending(&config, "admin@example.com").unwrap();

    fs::write(&config.operator.controller_private_key, b"controller-after").unwrap();
    fs::write(
        &config.operator.break_glass_private_key,
        b"break-glass-after",
    )
    .unwrap();
    let after = load_or_create_bootstrap_pending(&config, "admin@example.com").unwrap();

    assert_eq!(after.request_id, before.request_id);
    assert_eq!(after.email_hmac_sha256, before.email_hmac_sha256);
    assert_eq!(after.recovery_epoch, before.recovery_epoch);
}

#[cfg(unix)]
#[test]
fn recovery_epoch_invalidates_succeeded_receipt_without_deleting_a_new_token() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-bootstrap-recovery-epoch").unwrap();
    let mut config = config(&work);
    let old_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let token_path = write_bootstrap_fixture(&work, &mut config, old_token);
    write_active_release(&config, &manifest("v0.2.0", 'e')).unwrap();
    install_audit_key(&config);
    let old_request_id = "bootstrap-admin-0123456789abcdef0123456789abcdef";
    write_bootstrap_pending_fixture(
        &config,
        "admin@example.com",
        old_request_id,
        BootstrapAdminPendingStatus::Intent,
    );
    let response = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"admin@example.com","role":"admin","next":"/ui/auth"}"#;
    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, response);
    let credentials = BootstrapAdminCredentials {
        email: "admin@example.com".to_owned(),
        password: "correct horse battery staple".to_owned(),
    };
    audited_bootstrap_admin(&config, &credentials, curl.as_os_str(), None).unwrap();
    assert!(!token_path.exists());
    let succeeded: BootstrapAdminPending =
        serde_json::from_slice(&fs::read(bootstrap_pending_path(&config)).unwrap()).unwrap();
    assert_eq!(succeeded.status, BootstrapAdminPendingStatus::Succeeded);

    let next_epoch = rotate_bootstrap_recovery_epoch(&config).unwrap();
    let new_token = "a".repeat(64);
    fs::write(&token_path, &new_token).unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_credentials = BootstrapAdminCredentials {
        email: "replacement@example.com".to_owned(),
        password: "replacement horse battery staple".to_owned(),
    };
    let substituted = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"replacement@example.com","role":"admin","next":"/ui/auth"}"#;
    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, substituted);
    assert!(
        audited_bootstrap_admin(&config, &replacement_credentials, curl.as_os_str(), None,)
            .is_err()
    );
    assert_eq!(fs::read_to_string(&token_path).unwrap(), new_token);
    let reset: BootstrapAdminPending =
        serde_json::from_slice(&fs::read(bootstrap_pending_path(&config)).unwrap()).unwrap();
    assert_eq!(reset.status, BootstrapAdminPendingStatus::Intent);
    assert_ne!(reset.request_id, old_request_id);
    assert_eq!(reset.recovery_epoch, next_epoch);
    assert_eq!(
        reset.email_hmac_sha256,
        bootstrap_email_hmac(&config, "replacement@example.com").unwrap()
    );
    assert!(reset.claimed_user_id.is_none());
    assert!(reset.token_hmac_sha256.is_none());
}

#[cfg(unix)]
#[test]
fn succeeded_cleanup_replays_and_matches_the_application_receipt() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("nazoauth-bootstrap-receipt-replay").unwrap();
    let mut config = config(&work);
    let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let token_path = write_bootstrap_fixture(&work, &mut config, token);
    write_active_release(&config, &manifest("v0.2.0", 'e')).unwrap();
    install_audit_key(&config);
    let request_id = "bootstrap-admin-0123456789abcdef0123456789abcdef";
    write_bootstrap_pending_fixture(
        &config,
        "admin@example.com",
        request_id,
        BootstrapAdminPendingStatus::Intent,
    );
    let response = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"admin@example.com","role":"admin","next":"/ui/auth"}"#;
    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, response);
    let credentials = BootstrapAdminCredentials {
        email: "admin@example.com".to_owned(),
        password: "correct horse battery staple".to_owned(),
    };
    audited_bootstrap_admin(&config, &credentials, curl.as_os_str(), None).unwrap();
    fs::write(&token_path, token).unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();

    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, response);
    assert_eq!(
        audited_bootstrap_admin(&config, &credentials, curl.as_os_str(), None).unwrap(),
        request_id
    );
    assert!(!token_path.exists());
}

#[cfg(unix)]
#[test]
fn audited_bootstrap_claim_records_correlated_closed_events_without_secrets() {
    let work = PrivateTempDir::new("nazoauth-bootstrap-audit").unwrap();
    let mut config = config(&work);
    let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let password = "password-canary-correct-horse-battery-staple";
    write_bootstrap_fixture(&work, &mut config, token);
    write_active_release(&config, &manifest("v0.2.0", 'e')).unwrap();
    install_audit_key(&config);
    write_bootstrap_pending_fixture(
        &config,
        "admin@example.com",
        "bootstrap-admin-0123456789abcdef0123456789abcdef",
        BootstrapAdminPendingStatus::Intent,
    );
    let response = r#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","id":"550e8400-e29b-41d4-a716-446655440000","email":"admin@example.com","role":"admin","next":"/ui/auth"}"#;
    let (curl, _, _, _) = write_fake_bootstrap_curl(&work, response);
    let credentials = BootstrapAdminCredentials {
        email: "admin@example.com".to_owned(),
        password: password.to_owned(),
    };

    let request_id =
        audited_bootstrap_admin(&config, &credentials, curl.as_os_str(), None).unwrap();
    assert_eq!(
        request_id,
        "bootstrap-admin-0123456789abcdef0123456789abcdef"
    );
    assert!(
        !work
            .path()
            .join("bootstrap")
            .join(BOOTSTRAP_TOKEN_FILE)
            .exists()
    );
    crate::operator::verify_audit(&config).unwrap();
    let directory = config.operator.audit_directory.join("management");
    let mut events = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .map(|name| crate::operator::load_management_event(&config, &name).unwrap())
        .collect::<Vec<_>>();
    events.sort_by_key(|event| event.sequence);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].operation, "bootstrap-admin-intent");
    assert_eq!(events[0].request_id, format!("{request_id}-intent"));
    assert_eq!(events[1].operation, "bootstrap-admin-succeeded");
    assert_eq!(events[1].request_id, format!("{request_id}-succeeded"));
    let encoded = serde_json::to_string(&events).unwrap();
    assert!(!encoded.contains(token));
    assert!(!encoded.contains(password));
    assert!(!encoded.contains("admin@example.com"));
    let pending_bytes = fs::read(bootstrap_pending_path(&config)).unwrap();
    let pending_text = String::from_utf8(pending_bytes.clone()).unwrap();
    assert!(!pending_text.contains(token));
    assert!(!pending_text.contains(password));
    assert!(!pending_text.contains("admin@example.com"));
    let pending: BootstrapAdminPending = serde_json::from_slice(&pending_bytes).unwrap();
    assert_eq!(pending.request_id, request_id);
    assert_eq!(pending.status, BootstrapAdminPendingStatus::Succeeded);

    let resumed = audited_bootstrap_admin(
        &config,
        &credentials,
        work.path().join("curl-must-not-run").as_os_str(),
        None,
    )
    .unwrap();
    assert_eq!(resumed, request_id);
    assert_eq!(
        fs::read_dir(config.operator.audit_directory.join("management"))
            .unwrap()
            .count(),
        2
    );
}

fn assert_invalid_journal(config: &UpdateConfig, value: &UpdateJournal, expected_message: &str) {
    let error = validate_update_journal(config, value).unwrap_err();
    assert!(
        error.to_string().contains(expected_message),
        "unexpected error: {error:#}"
    );
}

#[test]
fn recovery_action_selects_restore_previous_before_migration() {
    let work = PrivateTempDir::new("nazoauth-update-phase").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::Prepared,
        UpdatePhase::WriterStopping,
        UpdatePhase::WriterStopped,
        UpdatePhase::BackupCreating,
        UpdatePhase::BackupCreated,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), false),
            UpdateRecoveryAction::RestorePrevious,
            "phase {phase:?}"
        );
    }
}

#[test]
fn mfa_totp_runtime_upgrade_keeps_inline_key_sources_unmounted() {
    let work = PrivateTempDir::new("nazoauth-mfa-totp-inline-upgrade").unwrap();
    let config_path = work.path().join("config/update.json");
    let config_dir = config_path.parent().unwrap();
    fs::create_dir_all(config_dir).unwrap();
    fs::write(
        config_dir.join(".env.yaml"),
        "MFA_TOTP_ENCRYPTION_KEY: \"inline-key\"\n",
    )
    .unwrap();
    let mut value = config(&work);

    persist_mfa_totp_runtime_upgrade(&config_path, &mut value).unwrap();

    let server_config = fs::read_to_string(config_dir.join(".env.yaml")).unwrap();
    assert!(server_config.contains("MFA_TOTP_ENCRYPTION_KEY: \"inline-key\"\n"));
    assert!(server_config.contains("MFA_TOTP_ENCRYPTION_KEY_ID: \"nazoauth-mfa-totp-v1\"\n"));
    assert!(value.runtime.snapshot_paths.is_empty());
    assert!(value.runtime.mounts.is_empty());
    assert!(!config_path.exists());
}

#[test]
fn recovery_action_selects_restore_previous_for_migration_faults() {
    let work = PrivateTempDir::new("nazoauth-update-migration").unwrap();
    let config = config(&work);
    let compatible = journal(&config, UpdatePhase::MigrationRunning);
    assert_eq!(
        recovery_action(&compatible, false),
        UpdateRecoveryAction::RestorePrevious
    );

    let mut barrier = compatible;
    barrier.to_release.rollback.schema_compatible = false;
    barrier.to_release.rollback.irreversible_migration = true;
    assert_eq!(
        recovery_action(&barrier, false),
        UpdateRecoveryAction::RestorePrevious
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn container_target_binds_the_platform_manifest_not_the_index() {
    let work = PrivateTempDir::new("nazoauth-platform-target").unwrap();
    let mut config = config(&work);
    config.runtime.backend = RuntimeBackendKind::Docker;
    let manifest = manifest("v0.2.0", 'e');

    assert_eq!(
        manifest.image_ref().unwrap(),
        format!("ghcr.io/nazozero/nazoauth@sha256:{}", "1".repeat(64))
    );
    assert_eq!(
        expected_target(&config, &manifest).unwrap().image_digest,
        format!("sha256:{}", "1".repeat(64))
    );
    assert_ne!(
        manifest.runtime_oci_digest().unwrap(),
        manifest.image_oci_digest()
    );
}

#[test]
fn recovery_action_selects_restore_previous_after_target_activation() {
    let work = PrivateTempDir::new("nazoauth-update-active").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::MigrationRunning,
        UpdatePhase::MigrationApplied,
        UpdatePhase::CandidateActivating,
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), true),
            UpdateRecoveryAction::RestorePrevious,
            "phase {phase:?}"
        );
    }
}

#[test]
fn recovery_action_selects_restore_previous_for_persisted_post_activation_phases() {
    let work = PrivateTempDir::new("nazoauth-update-persisted-active").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), false),
            UpdateRecoveryAction::RestorePrevious,
            "phase {phase:?}"
        );
    }
}

#[test]
fn update_journal_persists_rejects_unknown_fields_and_forbids_phase_regression() {
    let work = PrivateTempDir::new("nazoauth-update-journal").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir_all(&config.ui.releases_root).unwrap();
    fs::create_dir_all(&config.runtime.binary_releases).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();
    let loaded = load_update_journal(&config).unwrap().unwrap();
    assert_eq!(loaded.phase, UpdatePhase::Prepared);
    assert_eq!(loaded.transaction_id, "update-test");

    set_update_phase(&config, &mut value, UpdatePhase::WriterStopping).unwrap();
    assert_eq!(
        load_update_journal(&config).unwrap().unwrap().phase,
        UpdatePhase::WriterStopping
    );
    assert!(set_update_phase(&config, &mut value, UpdatePhase::Prepared).is_err());

    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(update_journal_path(&config)).unwrap()).unwrap();
    document["unknown"] = serde_json::json!(true);
    fs::write(
        update_journal_path(&config),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    assert!(load_update_journal(&config).is_err());
}

#[test]
fn update_journal_round_trips_each_persisted_phase() {
    let work = PrivateTempDir::new("nazoauth-update-fault-windows").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir_all(&config.ui.releases_root).unwrap();
    fs::create_dir_all(&config.runtime.binary_releases).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();

    for phase in [
        UpdatePhase::WriterStopping,
        UpdatePhase::WriterStopped,
        UpdatePhase::BackupCreating,
        UpdatePhase::BackupCreated,
        UpdatePhase::MigrationRunning,
        UpdatePhase::MigrationApplied,
        UpdatePhase::CandidateActivating,
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        if phase == UpdatePhase::BackupCreated {
            value.backup = Some(config.backup_root.join("v0.2.0-test"));
        }
        set_update_phase(&config, &mut value, phase).unwrap();
        let restarted = load_update_journal(&config).unwrap().unwrap();
        assert_eq!(restarted.phase, phase, "phase {phase:?}");
        assert_eq!(restarted.transaction_id, value.transaction_id);
        assert_eq!(restarted.previous_runtime, value.previous_runtime);
        assert_eq!(restarted.candidate_runtime, value.candidate_runtime);
        assert_eq!(restarted.backup, value.backup);
    }
}

#[test]
fn a_committed_backup_is_required_after_the_backup_phase() {
    let work = PrivateTempDir::new("nazoauth-update-backup").unwrap();
    let config = config(&work);
    let mut value = journal(&config, UpdatePhase::MigrationRunning);
    value.backup = None;
    assert!(validate_update_journal(&config, &value).is_err());
}

#[test]
fn journal_rejects_runtime_and_ui_paths_outside_managed_roots() {
    let work = PrivateTempDir::new("nazoauth-update-paths").unwrap();
    let config = config(&work);
    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_runtime = work.path().join("outside-runtime").display().to_string();
    assert!(validate_update_journal(&config, &value).is_err());

    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_ui = Some(work.path().join("outside-ui"));
    assert!(validate_update_journal(&config, &value).is_err());
}

#[test]
fn journal_validation_is_closed_over_headers_manifests_and_every_managed_path() {
    let work = PrivateTempDir::new("nazoauth-update-closed-journal").unwrap();
    let config = config(&work);
    let baseline = journal(&config, UpdatePhase::Prepared);
    validate_update_journal(&config, &baseline).unwrap();

    for transaction_id in [String::new(), "a".repeat(97), "unsafe/request".to_owned()] {
        let mut value = baseline.clone();
        value.transaction_id = transaction_id;
        assert_invalid_journal(&config, &value, "journal header is invalid");
    }
    for started_at in [String::new(), "a".repeat(65), "not-a-timestamp".to_owned()] {
        let mut value = baseline.clone();
        value.started_at = started_at;
        assert_invalid_journal(&config, &value, "journal header is invalid");
    }

    let mut value = baseline.clone();
    value.schema = 2;
    assert_invalid_journal(&config, &value, "journal header is invalid");

    let mut value = baseline.clone();
    value.to_release.release_identity = "https://attacker.example/release".to_owned();
    assert!(validate_update_journal(&config, &value).is_err());

    for clear_previous in [true, false] {
        let mut value = baseline.clone();
        if clear_previous {
            value.previous_runtime.clear();
        } else {
            value.candidate_runtime.clear();
        }
        assert_invalid_journal(&config, &value, "unsafe candidate path");
    }

    let mut value = baseline.clone();
    value.candidate_ui = work.path().join("wrong-candidate-ui");
    assert_invalid_journal(&config, &value, "candidate artifacts do not match");

    let mut value = baseline.clone();
    value.previous_ui = Some(work.path().join("wrong-previous-ui"));
    assert_invalid_journal(&config, &value, "previous UI does not match");

    let mut value = baseline.clone();
    value.previous_runtime = work.path().join("wrong-previous").display().to_string();
    assert_invalid_journal(&config, &value, "host runtime does not match");

    let mut value = baseline.clone();
    value.candidate_runtime = work.path().join("wrong-candidate").display().to_string();
    assert_invalid_journal(&config, &value, "host runtime does not match");

    let mut value = baseline;
    value.backup = Some(work.path().join("outside-backup-root"));
    assert_invalid_journal(&config, &value, "backup is outside");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn container_journal_binds_both_runtime_images_to_the_signed_platform_digest() {
    let work = PrivateTempDir::new("nazoauth-update-container-journal").unwrap();
    let mut config = config(&work);
    config.runtime.backend = RuntimeBackendKind::Podman;
    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    validate_update_journal(&config, &value).unwrap();

    value.candidate_runtime = format!(
        "{}@sha256:{}",
        value.to_release.oci.repository,
        "9".repeat(64)
    );
    assert_invalid_journal(&config, &value, "image runtime does not match");

    value.candidate_runtime = value.to_release.image_ref().unwrap();
    value.previous_runtime = format!(
        "{}@sha256:{}",
        value.from_release.oci.repository,
        "8".repeat(64)
    );
    assert_invalid_journal(&config, &value, "image runtime does not match");
}

#[test]
fn failed_phase_persistence_restores_the_in_memory_phase() {
    let work = PrivateTempDir::new("nazoauth-update-phase-write-failure").unwrap();
    let config = config(&work);
    fs::write(&config.deployment_root, b"not a directory").unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);

    assert!(set_update_phase(&config, &mut value, UpdatePhase::WriterStopping).is_err());
    assert_eq!(value.phase, UpdatePhase::Prepared);
}

#[test]
fn loading_a_journal_distinguishes_absent_non_regular_invalid_and_valid_state() {
    let work = PrivateTempDir::new("nazoauth-update-load-journal").unwrap();
    let config = config(&work);
    let path = update_journal_path(&config);

    assert!(load_update_journal(&config).unwrap().is_none());

    fs::create_dir_all(&path).unwrap();
    assert!(load_update_journal(&config).is_err());
    fs::remove_dir(&path).unwrap();

    fs::write(&path, b"not-json").unwrap();
    assert!(load_update_journal(&config).is_err());
    fs::remove_file(&path).unwrap();

    let value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();
    let loaded = load_update_journal(&config).unwrap().unwrap();
    assert_eq!(loaded.transaction_id, value.transaction_id);
    assert_eq!(loaded.phase, value.phase);
}

#[cfg(unix)]
#[test]
fn loading_a_journal_rejects_a_symlink_even_when_its_target_is_valid() {
    let work = PrivateTempDir::new("nazoauth-update-journal-symlink").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let target = work.path().join("journal-target.json");
    fs::write(
        &target,
        serde_json::to_vec(&journal(&config, UpdatePhase::Prepared)).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, update_journal_path(&config)).unwrap();

    assert!(load_update_journal(&config).is_err());
}

#[test]
fn verified_journal_backup_is_opened_only_from_the_configured_root() {
    let work = PrivateTempDir::new("nazoauth-update-journal-backup").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.backup_root).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    assert!(journal_backup(&config, &value).is_err());

    let backup = config.backup_root.join("verified-backup");
    fs::create_dir(&backup).unwrap();
    fs::write(backup.join("state.bin"), b"durable-state").unwrap();
    fs::write(
        backup.join("update-config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    fs::write(
        backup.join("SHA256SUMS"),
        format!(
            "{}  state.bin\n{}  update-config.json\n",
            crate::filesystem::sha256(&backup.join("state.bin")).unwrap(),
            crate::filesystem::sha256(&backup.join("update-config.json")).unwrap(),
        ),
    )
    .unwrap();
    let manifest_digest = crate::filesystem::sha256(&backup.join("SHA256SUMS")).unwrap();
    fs::write(
        backup.join("BACKUP-COMPLETE"),
        format!("marker=BACKUP-COMPLETE\nversion=1\nmanifest-sha256={manifest_digest}\n"),
    )
    .unwrap();
    value.backup = Some(backup.clone());

    assert_eq!(
        journal_backup(&config, &value).unwrap().path(),
        fs::canonicalize(backup).unwrap()
    );
}

#[test]
fn no_pending_update_is_an_idempotent_recovery_noop() {
    let work = PrivateTempDir::new("nazoauth-update-recovery-noop").unwrap();
    let config = config(&work);
    recover_pending_update(&work.path().join("config.json"), &config).unwrap();
    assert!(!update_journal_path(&config).exists());
}

#[test]
fn legacy_recovery_requires_all_runtime_and_provider_mutation_capabilities() {
    let work = PrivateTempDir::new("nazoauth-legacy-recovery-capabilities").unwrap();
    let mut config = config(&work);
    config.trust = crate::deployment::TrustState::Observed;
    assert!(require_legacy_recovery_capabilities(&config).is_err());

    config.trust = crate::deployment::TrustState::Adopted;
    config.capabilities.runtime.responsibility = Responsibility::External;
    assert!(require_legacy_recovery_capabilities(&config).is_err());

    config.capabilities.runtime.responsibility = Responsibility::Managed;
    config.capabilities.database.responsibility = Responsibility::External;
    assert!(require_legacy_recovery_capabilities(&config).is_err());
}

#[test]
fn public_rollback_rejects_unmanaged_lifecycle_before_reading_or_mutating_state() {
    let work = PrivateTempDir::new("nazoauth-public-rollback-capabilities").unwrap();
    let mut config = config(&work);
    let state = rollback_state_path(&config);

    config.trust = crate::deployment::TrustState::Observed;
    assert!(public_rollback(&config).is_err());
    assert!(!state.exists());

    config.trust = crate::deployment::TrustState::Adopted;
    config.capabilities.runtime.responsibility = Responsibility::External;
    assert!(public_rollback(&config).is_err());
    assert!(!state.exists());

    config.capabilities.runtime.responsibility = Responsibility::Managed;
    config.capabilities.artifact.responsibility = Responsibility::External;
    assert!(public_rollback(&config).is_err());
    assert!(!state.exists());

    config.capabilities.artifact.responsibility = Responsibility::Managed;
    config.capabilities.backups.responsibility = Responsibility::External;
    assert!(public_rollback(&config).is_err());
    assert!(!state.exists());
    assert!(!config.deployment_root.exists());
}

#[test]
fn backup_recovery_rejects_provider_mutation_without_reading_rollback_state() {
    let work = PrivateTempDir::new("nazoauth-backup-recovery-capabilities").unwrap();
    let mut config = config(&work);
    let state = rollback_state_path(&config);

    config.capabilities.database.responsibility = Responsibility::External;
    assert!(recover_from_backup(&config).is_err());
    assert!(!state.exists());

    config.capabilities.database.responsibility = Responsibility::Managed;
    config.capabilities.valkey.responsibility = Responsibility::External;
    assert!(recover_from_backup(&config).is_err());
    assert!(!state.exists());
    assert!(!config.deployment_root.exists());
}

#[test]
fn observation_lock_never_creates_persistent_state() {
    let work = PrivateTempDir::new("nazoauth-read-only-lock").unwrap();
    let missing = work.path().join("missing/lifecycle.lock");
    let error = acquire_lock_at(&missing, &Command::Status).unwrap_err();
    assert!(error.to_string().contains("read-only observation"));
    assert!(!missing.exists());
    assert!(!missing.parent().unwrap().exists());

    fs::create_dir_all(missing.parent().unwrap()).unwrap();
    fs::write(&missing, []).unwrap();
    crate::filesystem::set_mode(&missing, 0o600).unwrap();
    let lock = acquire_lock_at(&missing, &Command::Status).unwrap();
    assert_eq!(fs::metadata(&missing).unwrap().len(), 0);
    drop(lock);

    let created = work.path().join("created/lifecycle.lock");
    let lock = acquire_lock_at(&created, &Command::Rollback { yes: true }).unwrap();
    assert!(created.is_file());
    drop(lock);
}

#[test]
fn standards_full_bootstraps_a_bounded_revocation_snapshot_without_overwriting_it() {
    let work = PrivateTempDir::new("openid4vc-revocation-bootstrap").unwrap();
    let mut value = config(&work);
    value.install_profile = "standards-full".to_owned();
    value.runtime.expected_issuer = "https://auth.example/".to_owned();
    let keys = work.path().join("app/keys");
    fs::create_dir_all(&keys).unwrap();
    value.runtime.snapshot_paths = vec![keys.clone()];
    fs::write(
        keys.join(OPENID4VC_CERTIFICATE_BUNDLE),
        format!("{OPENID4VC_TEST_LEAF}{OPENID4VC_TEST_CA}"),
    )
    .unwrap();

    bootstrap_openid4vc_revocation_snapshot(&value).unwrap();
    let snapshot = keys.join(OPENID4VC_REVOCATION_SNAPSHOT);
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    assert_eq!(document["version"], 1);
    assert_eq!(document["entries"].as_array().unwrap().len(), 2);
    assert!(document["entries"].as_array().unwrap().iter().all(|entry| {
        entry["issuer"] == "https://auth.example"
            && entry["status"] == "good"
            && entry["certificate"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
    }));
    let this_update = document["this_update"].as_str().unwrap();
    let next_update = document["next_update"].as_str().unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(this_update).unwrap()
            < chrono::DateTime::parse_from_rfc3339(next_update).unwrap()
    );

    fs::write(&snapshot, b"operator-owned").unwrap();
    bootstrap_openid4vc_revocation_snapshot(&value).unwrap();
    assert_eq!(fs::read(&snapshot).unwrap(), b"operator-owned");
}

#[cfg(unix)]
#[test]
fn legacy_controller_lock_rejects_symlink_and_writable_entries() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let work = PrivateTempDir::new("nazoauth-controller-lock-boundary").unwrap();
    let target = work.path().join("target.lock");
    fs::write(&target, []).unwrap();

    let symlink_path = work.path().join("symlink.lock");
    symlink(&target, &symlink_path).unwrap();
    assert!(acquire_lock_at(&symlink_path, &Command::Rollback { yes: true }).is_err());

    let writable_path = work.path().join("writable.lock");
    fs::write(&writable_path, []).unwrap();
    fs::set_permissions(&writable_path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(acquire_lock_at(&writable_path, &Command::Rollback { yes: true }).is_err());
}

#[test]
fn only_observation_commands_use_the_shared_noncreating_lock() {
    assert!(command_is_read_only(&Command::Status));
    assert!(command_is_read_only(&Command::Doctor));
    assert!(command_is_read_only(&Command::AuditVerify));
    assert!(command_is_read_only(
        &Command::BreakGlassControllerAvailability
    ));
    assert!(command_is_read_only(&Command::Update(UpdateOptions {
        version: None,
        plan: true,
        yes: false,
        accept_migration_barrier: false,
    })));
    assert!(!command_is_read_only(&Command::Update(UpdateOptions {
        version: None,
        plan: false,
        yes: true,
        accept_migration_barrier: false,
    })));
    assert!(!command_is_read_only(&Command::RecoverUpdate { yes: true }));
    assert!(!command_is_read_only(&Command::RecoverIdentity {
        yes: true
    }));
}

#[cfg(unix)]
#[test]
fn config_permission_predicate_rejects_non_root_and_writable_modes() {
    assert!(config_permissions_are_safe(0, 0o100600));
    assert!(config_permissions_are_safe(0, 0o100640));
    assert!(!config_permissions_are_safe(1000, 0o100600));
    assert!(!config_permissions_are_safe(0, 0o100620));
    assert!(!config_permissions_are_safe(0, 0o100602));
}

fn settled_config(work: &PrivateTempDir) -> (PathBuf, UpdateConfig) {
    let config_path = work.path().join("update.json");
    let mut config = config(work);
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    crate::operator::initialize_identity_generation(
        &work.path().join("operator"),
        &work.path().join("recovery"),
    )
    .unwrap();
    crate::operator::recover_pending_rotation(&config_path, &mut config).unwrap();
    assert!(!crate::operator::identity_recovery_required(&config).unwrap());
    (config_path, config)
}

#[test]
fn public_command_dispatch_fails_closed_before_every_confirmed_mutation() {
    let work = PrivateTempDir::new("nazoauth-command-dispatch").unwrap();
    let (config_path, config) = settled_config(&work);
    let config_before = fs::read(&config_path).unwrap();
    let invoke = |command| {
        run(Cli {
            config: config_path.clone(),
            deployment: None,
            command,
        })
    };
    let root_available = require_root().is_ok();
    let assert_root_or_error = |result: anyhow::Result<()>, expected: &str| {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(expected)
                || (!root_available && error.contains("this command requires root")),
            "{error}"
        );
    };

    for command in [
        Command::BootstrapAdmin(BootstrapAdminOptions {
            credentials_stdin: false,
            yes: false,
        }),
        Command::Rollback { yes: false },
        Command::Recover { yes: false },
        Command::Migrate {
            yes: false,
            candidate: None,
        },
        Command::Keys(KeysCommand::GenerateLocal {
            alg: "ES256".to_owned(),
            purposes: vec!["credential".to_owned()],
            yes: false,
        }),
        Command::Keys(KeysCommand::RegisterExternal {
            kid: "external-test".to_owned(),
            alg: "ES256".to_owned(),
            key_ref: "kms:test".to_owned(),
            public_jwk: work.path().join("missing-public.jwk"),
            yes: false,
        }),
        Command::IdentityRotate { yes: false },
        Command::BreakGlassRehearseControllerLoss { yes: false },
        Command::BreakGlassRecover {
            yes: false,
            reason: "lost".to_owned(),
        },
    ] {
        assert!(invoke(command).is_err());
        assert_eq!(fs::read(&config_path).unwrap(), config_before);
    }

    assert_root_or_error(
        invoke(Command::RecoverUpdate { yes: false }),
        "no interrupted update",
    );
    assert_root_or_error(
        invoke(Command::RecoverIdentity { yes: false }),
        "no interrupted identity",
    );
    assert!(
        invoke(Command::Keys(KeysCommand::ExportOpenid4vcTrust {
            output: work.path().join("public/trust.pem"),
        }))
        .is_err()
    );
    invoke(Command::AuditVerify).unwrap();
    invoke(Command::AuditShow { request_id: None }).unwrap();
    if root_available {
        invoke(Command::BreakGlassControllerAvailability).unwrap();
    } else {
        assert_root_or_error(
            invoke(Command::BreakGlassControllerAvailability),
            "controller availability",
        );
    }

    fs::create_dir_all(&config.deployment_root).unwrap();
    write_update_journal(&config, &journal(&config, UpdatePhase::Prepared)).unwrap();
    assert!(invoke(Command::RecoverUpdate { yes: false }).is_err());
    assert_eq!(fs::read(&config_path).unwrap(), config_before);
    fs::remove_file(update_journal_path(&config)).unwrap();

    let abandoned = config
        .operator
        .identity_generations_directory
        .join("generation-abandoned");
    fs::create_dir_all(&abandoned).unwrap();
    fs::write(abandoned.join("controller.key"), b"pending-secret").unwrap();
    assert_root_or_error(
        invoke(Command::RecoverUpdate { yes: false }),
        "identity recovery is pending",
    );
    assert!(invoke(Command::RecoverIdentity { yes: false }).is_err());
    assert_eq!(fs::read(&config_path).unwrap(), config_before);
}

#[test]
fn config_loading_rejects_a_pending_update_without_mutating_it() {
    let work = PrivateTempDir::new("nazoauth-read-only-pending-update").unwrap();
    let (config_path, config) = settled_config(&work);
    write_update_journal(&config, &journal(&config, UpdatePhase::Prepared)).unwrap();
    let config_before = fs::read(&config_path).unwrap();
    let journal_before = fs::read(update_journal_path(&config)).unwrap();

    let error = load_config(&config_path).unwrap_err();

    assert!(error.to_string().contains("recover-update --yes"));
    assert_eq!(fs::read(&config_path).unwrap(), config_before);
    assert_eq!(
        fs::read(update_journal_path(&config)).unwrap(),
        journal_before
    );
}

#[test]
fn config_loading_rejects_identity_cleanup_without_mutating_it() {
    let work = PrivateTempDir::new("nazoauth-read-only-pending-identity").unwrap();
    let (config_path, config) = settled_config(&work);
    let abandoned = config
        .operator
        .identity_generations_directory
        .join("generation-abandoned");
    fs::create_dir_all(&abandoned).unwrap();
    fs::write(abandoned.join("controller.key"), b"pending-secret").unwrap();
    let config_before = fs::read(&config_path).unwrap();

    let error = load_config(&config_path).unwrap_err();

    assert!(error.to_string().contains("recover-identity --yes"));
    assert_eq!(fs::read(&config_path).unwrap(), config_before);
    assert_eq!(
        fs::read(abandoned.join("controller.key")).unwrap(),
        b"pending-secret"
    );
}

#[test]
fn early_update_faults_leave_the_last_durable_phase_for_restart() {
    for (initial, expected) in [
        (UpdatePhase::Prepared, UpdatePhase::WriterStopping),
        (UpdatePhase::WriterStopped, UpdatePhase::BackupCreating),
        (UpdatePhase::BackupCreated, UpdatePhase::MigrationRunning),
    ] {
        let work = PrivateTempDir::new("nazoauth-update-early-fault").unwrap();
        let config = config(&work);
        fs::create_dir_all(&config.deployment_root).unwrap();
        let mut value = journal(&config, initial);
        write_update_journal(&config, &value).unwrap();

        assert!(
            advance_update_transaction(&work.path().join("config.json"), &config, &mut value)
                .is_err(),
            "phase {initial:?} unexpectedly completed"
        );
        assert_eq!(value.phase, expected, "phase {initial:?}");
        assert_eq!(
            load_update_journal(&config).unwrap().unwrap().phase,
            expected,
            "phase {initial:?} was not durable"
        );
    }
}

#[test]
fn finishing_a_transaction_durably_removes_only_its_journal() {
    let work = PrivateTempDir::new("nazoauth-update-finish").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let value = journal(&config, UpdatePhase::AuditCommitted);
    write_update_journal(&config, &value).unwrap();
    let unrelated = config.deployment_root.join("keep.json");
    fs::write(&unrelated, b"keep").unwrap();

    finish_update_journal(&config, &value).unwrap();
    assert!(!update_journal_path(&config).exists());
    assert!(unrelated.exists());
    finish_update_journal(&config, &value).unwrap();
}

#[test]
fn transaction_ids_are_fixed_width_lower_hex_and_non_repeating() {
    let first = encode_transaction_id();
    let second = encode_transaction_id();
    for value in [&first, &second] {
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(value, &value.to_ascii_lowercase());
    }
    assert_ne!(first, second);
}

#[test]
fn active_release_round_trip_revalidates_the_release_identity() {
    let work = PrivateTempDir::new("nazoauth-active-release").unwrap();
    let mut config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let release = manifest("v0.2.0", 'e');
    write_active_release(&config, &release).unwrap();
    let loaded = load_active_release(&config).unwrap();
    assert_eq!(loaded.version, release.version);
    assert_eq!(loaded.backend_commit, release.backend_commit);

    config.repository = "attacker/NazoAuth".to_owned();
    assert!(load_active_release(&config).is_err());

    fs::write(active_release_path(&config), b"not-json").unwrap();
    assert!(load_active_release(&config).is_err());
}

#[test]
fn expected_target_separates_host_binary_and_release_aggregate_identity() {
    let work = PrivateTempDir::new("nazoauth-expected-host-target").unwrap();
    let config = config(&work);
    let mut release = manifest("v0.2.0", 'e');
    let expected = expected_target(&config, &release).unwrap();
    assert_eq!(expected.embedded, release.embedded);
    assert_eq!(expected.image_digest, release.oci.index_digest);
    assert_eq!(expected.binary_digest, "a".repeat(64));

    release.artifacts.remove("binary");
    assert!(expected_target(&config, &release).is_err());
}

#[test]
fn ui_cache_validation_rejects_missing_non_regular_and_malformed_artifacts() {
    let work = PrivateTempDir::new("nazoauth-frontend-cache-boundaries").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    assert!(!target_ui_is_active(&value));

    fs::create_dir_all(value.candidate_ui.parent().unwrap()).unwrap();
    fs::write(&value.candidate_ui, b"not a directory").unwrap();
    assert!(!target_ui_is_active(&value));
    fs::remove_file(&value.candidate_ui).unwrap();

    fs::create_dir_all(&value.candidate_ui).unwrap();
    assert!(!target_ui_is_active(&value));
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    assert!(!target_ui_is_active(&value));
    fs::write(value.candidate_ui.join(".nazoauth-ui.json"), b"not-json").unwrap();
    assert!(!target_ui_is_active(&value));
}

fn ui_server(body: &[u8]) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let length = stream.read(&mut request).unwrap();
        assert!(String::from_utf8_lossy(&request[..length]).starts_with("GET /ui/ "));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        stream.write_all(&body).unwrap();
    });
    (format!("http://{address}"), handle)
}

#[test]
fn ui_verification_binds_the_served_body_to_the_signed_runtime_cache() {
    let work = PrivateTempDir::new("nazoauth-frontend-served-binding").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    materialize_candidate_ui(&value);

    verify_ui_binding(&config, &value.to_release, b"ui").unwrap();
    assert!(verify_ui_binding(&config, &value.to_release, b"arbitrary-2xx").is_err());

    fs::write(value.candidate_ui.join("index.html"), b"").unwrap();
    assert!(verify_ui_binding(&config, &value.to_release, b"").is_err());
}

#[test]
fn ui_verification_rejects_an_unrelated_success_response_through_curl() {
    let work = PrivateTempDir::new("nazoauth-frontend-http-binding").unwrap();
    let mut config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    materialize_candidate_ui(&value);

    let (issuer, server) = ui_server(b"arbitrary-2xx");
    config.runtime.expected_issuer = issuer;
    assert!(verify_ui(&config, &value.to_release).is_err());
    server.join().unwrap();

    let (issuer, server) = ui_server(b"ui");
    config.runtime.expected_issuer = issuer;
    verify_ui(&config, &value.to_release).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn ui_cache_validation_rejects_symlinked_index_and_marker_files() {
    let work = PrivateTempDir::new("nazoauth-frontend-cache-symlinks").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    fs::create_dir_all(&value.candidate_ui).unwrap();
    let external_index = work.path().join("external-index.html");
    fs::write(&external_index, b"ui").unwrap();
    std::os::unix::fs::symlink(&external_index, value.candidate_ui.join("index.html")).unwrap();
    assert!(!target_ui_is_active(&value));

    fs::remove_file(value.candidate_ui.join("index.html")).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    let external_marker = work.path().join("external-marker.json");
    fs::write(&external_marker, b"{}").unwrap();
    std::os::unix::fs::symlink(
        &external_marker,
        value.candidate_ui.join(".nazoauth-ui.json"),
    )
    .unwrap();
    assert!(!target_ui_is_active(&value));
}

#[cfg(unix)]
fn host_identity_fixture(
    work: &PrivateTempDir,
    actual_identity: &nazo_operator_protocol::EmbeddedIdentity,
) -> (UpdateConfig, ReleaseManifest) {
    let mut config = config(work);
    config.dependencies.mode = "external".to_owned();
    let mut release = manifest("v0.2.0", 'e');
    let directory = config.runtime.binary_releases.join(&release.backend_commit);
    fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("nazoauth");
    let identity = serde_json::to_string(actual_identity).unwrap();
    assert!(!identity.contains('\''));
    write_shell_executable(
        &binary,
        &format!(
            "if [ \"${{1:-}}\" = build-identity ]; then\n  printf '%s\\n' '{identity}'\n  exit 0\nfi\nexit 1"
        ),
    );
    let metadata = fs::metadata(&binary).unwrap();
    let artifact = release.artifacts.get_mut("binary").unwrap();
    artifact.sha256 = crate::filesystem::sha256(&binary).unwrap();
    artifact.size = metadata.len();
    config.runtime.binary_path = binary;
    fs::create_dir_all(&config.deployment_root).unwrap();
    write_active_release(&config, &release).unwrap();
    (config, release)
}

#[cfg(unix)]
fn health_server() -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    (format!("http://{address}/ready"), handle)
}

#[cfg(target_os = "linux")]
fn public_server(requests: usize) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let issuer = format!("http://{address}");
    let response_issuer = issuer.clone();
    let handle = std::thread::spawn(move || {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                serde_json::json!({"issuer": response_issuer}).to_string()
            } else {
                "ui".to_owned()
            };
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
    });
    (issuer, handle)
}

#[cfg(target_os = "linux")]
fn fake_container_runtime(
    work: &PrivateTempDir,
    config: &UpdateConfig,
    candidate_commit: &str,
    candidate_active: bool,
) -> PathBuf {
    let engine = work.path().join(if candidate_active {
        "active-container-engine"
    } else {
        "inactive-container-engine"
    });
    let postgres_volume = format!("{}-data", config.postgres.container_name);
    let identity = crate::runtime_backend::managed_dependency_identity(
        &config.operator.deployment_id,
        &config.operator.controller_key_id,
        &config.runtime.runtime_instance_id,
        &config.runtime.network,
        &config.postgres.container_name,
        &postgres_volume,
        &config.postgres.image,
        &config.postgres.database,
        &config.postgres.user,
        &config.valkey.container_name,
        &config.valkey.data_volume,
        &config.valkey.image,
    );
    let runtime_image = format!("fixture@sha256:{}", "c".repeat(64));
    let inspect_json = serde_json::json!([{
        "Id": "fixture-container-id",
        "Name": "/nazoauth",
        "ImageName": runtime_image.clone(),
        "Config": {
            "Image": runtime_image.clone(),
            "Labels": {
                "io.nazoauth.deployment-id": config.operator.deployment_id.clone(),
                "io.nazoauth.control-authority": config.operator.controller_key_id.clone(),
                "io.nazoauth.runtime-instance-id": config.runtime.runtime_instance_id.clone(),
            },
            "Command": ["nazoauth", "server"]
        },
        "State": {"Running": true},
        "NetworkSettings": {"Ports": {}, "Networks": {}},
        "Mounts": []
    }])
    .to_string();
    let network_digest = crate::runtime_backend::managed_network_config_digest(
        &config.operator.deployment_id,
        &config.operator.controller_key_id,
        &config.runtime.network,
    );
    let embedded_identity = serde_json::to_string(&nazo_operator_protocol::EmbeddedIdentity {
        release: "v0.2.0".to_owned(),
        revision: candidate_commit.to_owned(),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "build:test".to_owned(),
    })
    .unwrap();
    let script = format!(
        "if [ \"${{1:-}}\" = image ] && [ \"${{2:-}}\" = inspect ]; then\n  image=\"${{3:-}}\"\n  digest=\"${{image##*@}}\"\n  printf '[\"fixture@%s\"]\\n' \"$digest\"\n  exit 0\nfi\nif [ \"${{1:-}}\" = network ] && [ \"${{2:-}}\" = inspect ]; then\n  case \"$*\" in\n    *io.nazoauth.deployment-id*) printf '%s\\n' '{deployment}' ;;\n    *io.nazoauth.control-authority*) printf '%s\\n' '{authority}' ;;\n    *io.nazoauth.resource-kind*) printf '%s\\n' 'network' ;;\n    *io.nazoauth.config-digest*) printf '%s\\n' '{network_digest}' ;;\n    *) printf '%s\\n' '{{\"subnets\":[{{\"gateway\":\"10.89.0.1\"}}]}}' ;;\n  esac\n  exit 0\nfi\nif [ \"${{1:-}}\" = volume ] && [ \"${{2:-}}\" = inspect ]; then\n  case \"$*\" in\n    *io.nazoauth.deployment-id*) printf '%s\\n' '{deployment}' ;;\n    *io.nazoauth.control-authority*) printf '%s\\n' '{authority}' ;;\n    *io.nazoauth.runtime-instance-id*) printf '%s\\n' '{runtime}' ;;\n    *io.nazoauth.resource-kind*) case \"$*\" in *{valkey_volume}*) printf '%s\\n' 'valkey-volume' ;; *) printf '%s\\n' 'postgres-volume' ;; esac ;;\n    *io.nazoauth.config-digest*) case \"$*\" in *{valkey_volume}*) printf '%s\\n' '{valkey_volume_digest}' ;; *) printf '%s\\n' '{postgres_volume_digest}' ;; esac ;;\n    *) printf '%s\\n' '{{}}' ;;\n  esac\n  exit 0\nfi\nif [ \"${{1:-}}\" = container ] && [ \"${{2:-}}\" = inspect ]; then\n  if [ \"{candidate_active}\" != true ]; then printf '%s\\n' 'no such object' >&2; exit 1; fi\n  shift 2\n  set -- inspect \"$@\"\nfi\nif [ \"${{1:-}}\" = inspect ]; then\n  case \"$*\" in\n    *--format*io.nazoauth.deployment-id*) printf '%s\\n' '{deployment}' ;;\n    *--format*io.nazoauth.control-authority*) printf '%s\\n' '{authority}' ;;\n    *--format*io.nazoauth.runtime-instance-id*) printf '%s\\n' '{runtime}' ;;\n    *--format*io.nazoauth.resource-kind*) case \"$*\" in *postgres*) printf '%s\\n' 'postgres' ;; *valkey*) printf '%s\\n' 'valkey' ;; *) printf '%s\\n' 'application' ;; esac ;;\n    *--format*io.nazoauth.config-digest*) case \"$*\" in *postgres*) printf '%s\\n' '{postgres_digest}' ;; *valkey*) printf '%s\\n' '{valkey_digest}' ;; *) printf '%s\\n' '{network_digest}' ;; esac ;;\n    *--format*) case \"$*\" in *postgres*) printf '%s\\n' '{postgres_image}' ;; *valkey*) printf '%s\\n' '{valkey_image}' ;; *) printf '%s\\n' '{runtime_image}' ;; esac ;;\n    *) printf '%s\\n' '{inspect_json}' ;;\n  esac\n  exit 0\nfi\nif [ \"${{1:-}}\" = run ] && [ \"${{*: -2}}\" = \"nazoauth build-identity\" ]; then\n  printf '%s\\n' '{embedded_identity}'\n  exit 0\nfi\ncat >/dev/null\nexit 0",
        deployment = config.operator.deployment_id,
        authority = config.operator.controller_key_id,
        runtime = config.runtime.runtime_instance_id,
        network_digest = network_digest,
        valkey_volume = config.valkey.data_volume,
        postgres_volume_digest = identity.postgres_volume_config_digest,
        valkey_volume_digest = identity.valkey_volume_config_digest,
        postgres_digest = identity.postgres_config_digest,
        valkey_digest = identity.valkey_config_digest,
        postgres_image = config.postgres.image,
        valkey_image = config.valkey.image,
        runtime_image = runtime_image,
        inspect_json = inspect_json,
        embedded_identity = embedded_identity,
    );
    let legacy_build_identity_case = format!(
        r#"if [ "${{1:-}}" = run ] && [ "${{*: -2}}" = "nazoauth build-identity" ]; then
  printf '%s\n' '{}'
  exit 0
fi"#,
        embedded_identity
    );
    let portable_build_identity_case = format!(
        r#"if [ "${{1:-}}" = run ]; then
  case "$*" in
    *'nazoauth build-identity') printf '%s\n' '{}'; exit 0 ;;
  esac
fi"#,
        embedded_identity
    );
    let script = script.replace(&legacy_build_identity_case, &portable_build_identity_case);
    let inspect_override = format!(
        r#"if [ "${{1:-}}" = inspect ]; then
  object="${{2:-}}"
  format="${{4:-}}"
  if [ -z "$format" ]; then
    printf '%s\n' '{inspect_json}'
    exit 0
  fi
  case "$format" in
    *io.nazoauth.deployment-id*) printf '%s\n' '{deployment}' ;;
    *io.nazoauth.control-authority*) printf '%s\n' '{authority}' ;;
    *io.nazoauth.runtime-instance-id*) printf '%s\n' '{runtime}' ;;
    *io.nazoauth.resource-kind*) case "$object" in '{postgres_object}') printf '%s\n' 'postgres' ;; '{valkey_object}') printf '%s\n' 'valkey' ;; *) printf '%s\n' 'application' ;; esac ;;
    *io.nazoauth.config-digest*) case "$object" in '{postgres_object}') printf '%s\n' '{postgres_digest}' ;; '{valkey_object}') printf '%s\n' '{valkey_digest}' ;; *) printf '%s\n' '{network_digest}' ;; esac ;;
    *Image*|*RepoDigests*) case "$object" in '{postgres_object}') printf '%s\n' '{postgres_image}' ;; '{valkey_object}') printf '%s\n' '{valkey_image}' ;; *) printf '%s\n' '{runtime_image}' ;; esac ;;
    *) printf '%s\n' '{inspect_json}' ;;
  esac
  exit 0
fi
if [ "${{1:-}}" = inspect ]; then
  case "$*" in"#,
        inspect_json = inspect_json,
        deployment = config.operator.deployment_id,
        authority = config.operator.controller_key_id,
        runtime = config.runtime.runtime_instance_id,
        postgres_object = config.postgres.container_name,
        valkey_object = config.valkey.container_name,
        postgres_digest = identity.postgres_config_digest,
        valkey_digest = identity.valkey_config_digest,
        network_digest = network_digest,
        postgres_image = config.postgres.image,
        valkey_image = config.valkey.image,
        runtime_image = runtime_image,
    );
    let script = script.replacen(
        "if [ \"${1:-}\" = inspect ]; then\n  case \"$*\" in",
        &inspect_override,
        1,
    );
    let script = script.replace("io.nazoauth.resource-kind", "io.nazoauth.managed-resource");
    write_shell_executable(&engine, &script);
    engine
}

#[cfg(target_os = "linux")]
#[test]
fn active_revision_uses_embedded_identity_without_optional_oci_revision_label() {
    let work = PrivateTempDir::new("nazoauth-active-revision-identity").unwrap();
    let mut config = config(&work);
    let revision = "d".repeat(40);
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override =
        Some(fake_container_runtime(&work, &config, &revision, true));

    assert_eq!(Runtime::new(&config).active_revision().unwrap(), revision);
}

#[cfg(target_os = "linux")]
fn materialize_trusted_recovery_release(config: &UpdateConfig, release: &ReleaseManifest) {
    let directory = release_cache_dir(config, release);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("server-release-manifest.json"),
        serde_json::to_vec_pretty(release).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("server-image.tar"),
        b"trusted OCI recovery archive",
    )
    .unwrap();
}

#[cfg(unix)]
fn install_audit_key(config: &UpdateConfig) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[7; 32]);
    fs::create_dir_all(config.operator.audit_private_key.parent().unwrap()).unwrap();
    fs::write(
        &config.operator.audit_private_key,
        URL_SAFE_NO_PAD.encode(key.to_bytes()),
    )
    .unwrap();
    fs::write(
        &config.operator.audit_public_key,
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    crate::filesystem::set_mode(&config.operator.audit_private_key, 0o400).unwrap();
    crate::filesystem::set_mode(&config.operator.audit_public_key, 0o444).unwrap();
}

#[cfg(target_os = "linux")]
fn configure_public_checks(config: &mut UpdateConfig, issuer: &str) {
    config.runtime.health_url = format!("{issuer}/ready");
    config.runtime.public_discovery_url = format!("{issuer}/.well-known/openid-configuration");
    config.runtime.expected_issuer = issuer.to_owned();
}

fn materialize_candidate_ui(value: &UpdateJournal) {
    fs::create_dir_all(&value.candidate_ui).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "repository": value.to_release.frontend.repository,
            "version": value.to_release.frontend.version,
            "commit": value.to_release.frontend.commit,
            "release_identity": value.to_release.frontend.release_identity,
            "artifact": value.to_release.frontend.artifact,
        }))
        .unwrap(),
    )
    .unwrap();
}

#[cfg(target_os = "linux")]
fn materialize_verified_backup(config: &UpdateConfig, path: &std::path::Path) {
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir(path).unwrap();
    fs::write(path.join("state.bin"), b"durable-state").unwrap();
    fs::write(
        path.join("update-config.json"),
        serde_json::to_vec_pretty(config).unwrap(),
    )
    .unwrap();
    fs::write(
        path.join("SHA256SUMS"),
        format!(
            "{}  state.bin\n{}  update-config.json\n",
            crate::filesystem::sha256(&path.join("state.bin")).unwrap(),
            crate::filesystem::sha256(&path.join("update-config.json")).unwrap(),
        ),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn host_status_reports_signed_binary_and_embedded_identity_match() {
    let work = PrivateTempDir::new("nazoauth-host-status").unwrap();
    let release = manifest("v0.2.0", 'e');
    let (mut config, _) = host_identity_fixture(&work, &release.embedded);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    status(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_status_remains_observable_when_embedded_identity_mismatches() {
    let work = PrivateTempDir::new("nazoauth-host-status-mismatch").unwrap();
    let release = manifest("v0.2.0", 'e');
    let mut actual = release.embedded.clone();
    actual.build_id = "build:substituted".to_owned();
    let (mut config, _) = host_identity_fixture(&work, &actual);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    status(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_doctor_accepts_the_exact_signed_binary_and_embedded_identity() {
    let work = PrivateTempDir::new("nazoauth-host-doctor").unwrap();
    let release = manifest("v0.2.0", 'e');
    let (mut config, _) = host_identity_fixture(&work, &release.embedded);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    doctor(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_doctor_rejects_embedded_identity_substitution_before_health_checks() {
    let work = PrivateTempDir::new("nazoauth-host-doctor-identity-mismatch").unwrap();
    let release = manifest("v0.2.0", 'e');
    let mut actual = release.embedded.clone();
    actual.revision = "9".repeat(40);
    let (config, _) = host_identity_fixture(&work, &actual);

    let error = doctor(&config).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime embedded build identity differs")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn pending_pre_migration_update_restores_previous_artifact_and_closes_the_journal() {
    let work = PrivateTempDir::new("nazoauth-recover-previous").unwrap();
    let mut config = config(&work);
    let mut value = journal(&config, UpdatePhase::WriterStopped);
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(fake_container_runtime(
        &work,
        &config,
        &value.to_release.backend_commit,
        false,
    ));
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    fs::create_dir_all(&config.deployment_root).unwrap();
    materialize_trusted_recovery_release(&config, &value.from_release);
    materialize_candidate_ui(&value);
    install_audit_key(&config);
    let (issuer, server) = public_server(3);
    configure_public_checks(&mut config, &issuer);
    write_update_journal(&config, &value).unwrap();

    let result = recover_pending_update(&work.path().join("config.json"), &config);
    assert!(result.is_ok(), "recovery failed: {result:#?}");
    server.join().unwrap();
    assert_eq!(
        load_active_release(&config).unwrap().version,
        value.from_release.version
    );
    assert!(!update_journal_path(&config).exists());
    crate::operator::verify_audit(&config).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn pending_active_candidate_restores_previous_release_and_closes_the_journal() {
    let work = PrivateTempDir::new("nazoauth-recover-active-unwind").unwrap();
    let mut config = config(&work);
    config.postgres.image = format!("postgres@sha256:{}", "a".repeat(64));
    config.postgres.validation_image = config.postgres.image.clone();
    config.valkey.image = format!("valkey@sha256:{}", "b".repeat(64));
    config.dependencies.migration_database_url_file =
        work.path().join("secrets/database-migration-url");
    fs::create_dir_all(
        config
            .dependencies
            .migration_database_url_file
            .parent()
            .unwrap(),
    )
    .unwrap();
    fs::write(
        &config.dependencies.migration_database_url_file,
        "postgresql://migrator:recovery-test@database.invalid/oauth",
    )
    .unwrap();
    let mut value = journal(&config, UpdatePhase::CandidateActive);
    config.runtime.backend = RuntimeBackendKind::Podman;
    config.runtime.backend_command_override = Some(fake_container_runtime(
        &work,
        &config,
        &value.to_release.backend_commit,
        true,
    ));
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    fs::create_dir_all(&config.deployment_root).unwrap();
    materialize_trusted_recovery_release(&config, &value.from_release);
    materialize_candidate_ui(&value);
    materialize_verified_backup(&config, value.backup.as_deref().unwrap());
    install_audit_key(&config);
    let (issuer, server) = public_server(3);
    configure_public_checks(&mut config, &issuer);
    write_update_journal(&config, &value).unwrap();

    let result = recover_pending_update(&work.path().join("config.json"), &config);
    assert!(result.is_ok(), "recovery failed: {result:#?}");
    server.join().unwrap();
    assert_eq!(
        load_active_release(&config).unwrap().version,
        value.from_release.version
    );
    assert!(!update_journal_path(&config).exists());
    crate::operator::verify_audit(&config).unwrap();
}

#[test]
fn update_deployment_record_is_idempotent_for_a_transaction() {
    let work = PrivateTempDir::new("nazoauth-update-record").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::StateCommitting);
    let backup = value.backup.as_deref().unwrap();

    write_update_record(&config, &value, "deployment-success", Some(backup)).unwrap();
    let path = config.deployment_root.join("update-update-test.json");
    let first = fs::read(&path).unwrap();
    write_update_record(&config, &value, "deployment-success", Some(backup)).unwrap();

    assert_eq!(fs::read(&path).unwrap(), first);
    assert_eq!(
        fs::read_dir(&config.deployment_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() == "update-update-test.json")
            .count(),
        1
    );
}

#[test]
fn update_noop_requires_exact_signed_state_identity_and_artifact() {
    let work = PrivateTempDir::new("nazoauth-update-noop-identity").unwrap();
    let mut config = config(&work);
    config.runtime.backend = RuntimeBackendKind::Systemd;
    let target = manifest("v0.2.0", 'b');
    let expected_digest = target.artifacts["binary"].sha256.clone();
    let exact = crate::runtime::ActiveBuildTarget {
        embedded: target.embedded.clone(),
        image_digest: String::new(),
        binary_digest: expected_digest,
    };

    assert!(active_target_matches_release(&config, &target, &exact, &target).unwrap());

    let mut local = exact;
    local.embedded.release = "v0.2.0-dev.bbbbbbbb".to_owned();
    local.embedded.build_id = format!("local:{}", local.embedded.revision);
    assert!(!active_target_matches_release(&config, &target, &local, &target).unwrap());

    let mut substituted = crate::runtime::ActiveBuildTarget {
        embedded: target.embedded.clone(),
        image_digest: String::new(),
        binary_digest: "c".repeat(64),
    };
    assert!(!active_target_matches_release(&config, &target, &substituted, &target).unwrap());

    let previous = manifest("v0.1.9", 'a');
    substituted.binary_digest = target.artifacts["binary"].sha256.clone();
    assert!(!active_target_matches_release(&config, &previous, &substituted, &target).unwrap());
}

#[test]
fn registered_update_plan_preserves_mixed_ownership_and_replica_identity() {
    let active = manifest("v0.1.19", 'a');
    let mut target = manifest("v0.2.0", 'b');
    target.rollback.schema_compatible = false;
    target.rollback.irreversible_migration = true;
    target.rollback.migration_floor = "20260808000200".to_owned();
    target.rollback.rationale = "encrypt TOTP secrets and clear plaintext".to_owned();
    let mut capabilities = crate::deployment::CapabilityGrants::observed();
    capabilities.runtime = CapabilityGrant {
        responsibility: Responsibility::Delegated,
        scope: crate::deployment::ResourceScope::Deployment,
    };
    capabilities.artifact = CapabilityGrant {
        responsibility: Responsibility::Managed,
        scope: crate::deployment::ResourceScope::Deployment,
    };
    let runtime =
        |runtime_instance_id: &str, object_reference: &str| crate::deployment::RuntimeInstance {
            runtime_instance_id: runtime_instance_id.to_owned(),
            backend: RuntimeBackendKind::Podman,
            object_reference: object_reference.to_owned(),
            artifact: crate::deployment::ArtifactReference::Oci {
                image_reference: "ghcr.io/nazozero/nazoauth".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            local_artifact_id: None,
            ports: Vec::new(),
            networks: vec!["shared-network".to_owned()],
            mounts: Vec::new(),
            instance_key_id: None,
            deployment_statement: None,
        };
    let record = DeploymentRecord {
        schema: crate::deployment::DEPLOYMENT_SCHEMA,
        deployment_id: "deployment-mixed".to_owned(),
        control_authority: "controller-mixed".to_owned(),
        alias: Some("mixed".to_owned()),
        issuer: "https://mixed.example".to_owned(),
        active_release: active.embedded.clone(),
        trust: crate::deployment::TrustState::Adopted,
        capabilities,
        runtime_instances: vec![
            runtime("runtime-a", "manual-a"),
            runtime("runtime-b", "manual-b"),
        ],
        resources: BTreeMap::from([(
            "database".to_owned(),
            SafeReference::Provider {
                provider: "external-database".to_owned(),
                key: "deployment-mixed".to_owned(),
            },
        )]),
        recovery: crate::deployment::RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: vec!["recovery-package-sha256".to_owned()],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: std::collections::BTreeSet::from([
            nazo_operator_protocol::PROTOCOL_VERSION,
        ]),
        control_protocol_versions: std::collections::BTreeSet::from([1]),
        declaration_revision: 1,
    };

    let plan = build_registered_update_plan(&record, &target).unwrap();
    let steps = plan["steps"].as_array().unwrap();
    assert_eq!(
        steps
            .iter()
            .filter(|step| {
                step["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("runtime-replace-"))
            })
            .count(),
        2
    );
    assert_eq!(
        steps
            .iter()
            .find(|step| step["id"] == "database-migration")
            .unwrap()["owner"],
        "provider-owned"
    );
    assert!(plan["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .is_some_and(|value| value.contains("lifecycle configuration"))
    }));
    assert_eq!(plan["core_recovery_requires_operator_task"], false);
    assert_eq!(plan["schema_compatible_rollback"], false);
    assert_eq!(plan["irreversible_migration_barrier"], true);
    assert_eq!(plan["migration_floor"], "20260808000200");
    assert_eq!(
        plan["migration_rationale"],
        "encrypt TOTP secrets and clear plaintext"
    );
}

#[test]
fn registered_update_rejects_a_downgrade_before_plan_side_effects() {
    let work = PrivateTempDir::new("nazoauth-registered-downgrade").unwrap();
    let active = manifest("v0.1.19", 'a');
    let target = manifest("v0.1.18", 'b');
    let record = DeploymentRecord {
        schema: crate::deployment::DEPLOYMENT_SCHEMA,
        deployment_id: "deployment-downgrade".to_owned(),
        control_authority: "controller-downgrade".to_owned(),
        alias: None,
        issuer: "https://downgrade.example".to_owned(),
        active_release: active.embedded,
        trust: crate::deployment::TrustState::Adopted,
        capabilities: crate::deployment::CapabilityGrants::observed(),
        runtime_instances: Vec::new(),
        resources: BTreeMap::new(),
        recovery: crate::deployment::RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: Vec::new(),
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: std::collections::BTreeSet::new(),
        control_protocol_versions: std::collections::BTreeSet::new(),
        declaration_revision: 1,
    };

    let error = build_registered_update_plan(&record, &target).unwrap_err();
    assert!(error.to_string().contains("anti-downgrade"));
    assert_eq!(fs::read_dir(work.path()).unwrap().count(), 0);
}

#[test]
fn frontend_cache_marker_must_exactly_match_the_signed_release() {
    let work = PrivateTempDir::new("nazoauth-frontend-marker").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    fs::create_dir_all(&value.candidate_ui).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    let expected = serde_json::json!({
        "schema": 1,
        "repository": value.to_release.frontend.repository,
        "version": value.to_release.frontend.version,
        "commit": value.to_release.frontend.commit,
        "release_identity": value.to_release.frontend.release_identity,
        "artifact": value.to_release.frontend.artifact,
    });
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    assert!(target_ui_is_active(&value));

    let mut changed = expected;
    changed["unexpected"] = serde_json::json!(true);
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(!target_ui_is_active(&value));
}

#[test]
fn candidate_target_is_oci_only_and_keeps_exact_embedded_identity() {
    let work = PrivateTempDir::new("nazoauth-candidate-target").unwrap();
    let mut config = config(&work);
    let candidate = CandidateTarget {
        release: "v0.1.19".to_owned(),
        revision: "a".repeat(40),
        build_id: format!("private-pre-release:{}", "a".repeat(40)),
        oci_digest: format!("sha256:{}", "b".repeat(64)),
    };
    assert!(candidate_expected_target(&config, &candidate).is_err());

    config.runtime.backend = RuntimeBackendKind::Podman;
    let expected = candidate_expected_target(&config, &candidate).unwrap();
    assert_eq!(expected.embedded.release, candidate.release);
    assert_eq!(expected.embedded.revision, candidate.revision);
    assert_eq!(expected.embedded.build_id, candidate.build_id);
    assert_eq!(expected.image_digest, candidate.oci_digest);
    assert!(expected.binary_digest.is_empty());
}

#[test]
fn conformance_commands_build_closed_operator_tasks() {
    let work = PrivateTempDir::new("nazoauth-conformance-operation").unwrap();
    let material = work.path().join("public-manifest.json");
    fs::write(&material, b"public conformance manifest").unwrap();
    let expected_sha256 = crate::filesystem::sha256(&material).unwrap();

    let create = conformance_operation(ConformanceLeaseCommand::Create {
        profile: "oidf-fapi2".to_owned(),
        material: material.clone(),
        dynamic_registration_token_file: None,
        ciba_automated_decision_token_file: None,
        ttl_seconds: 28_800,
        yes: true,
    })
    .unwrap();
    assert_eq!(
        create,
        TaskOperation::ConformanceLeaseCreate {
            profile: "oidf-fapi2".to_owned(),
            material_sha256: expected_sha256.clone(),
            public_material: None,
            dynamic_registration_initial_access_token_sha256: None,
            ciba_automated_decision_token_sha256: None,
            ttl_seconds: 28_800,
        }
    );

    let token_path = work.path().join("dynamic-registration-token");
    fs::write(&token_path, b"caller-supplied-high-entropy-token").unwrap();
    crate::filesystem::set_mode(&token_path, 0o600).unwrap();
    let token_sha256 = crate::filesystem::sha256(&token_path).unwrap();
    let ciba_token_path = work.path().join("ciba-automated-decision-token");
    fs::write(&ciba_token_path, b"ciba-decision-secret-material").unwrap();
    crate::filesystem::set_mode(&ciba_token_path, 0o600).unwrap();
    let ciba_token_sha256 = crate::filesystem::sha256(&ciba_token_path).unwrap();
    let token_create = conformance_operation(ConformanceLeaseCommand::Create {
        profile: "oidc-fapi-ciba".to_owned(),
        material: material.clone(),
        dynamic_registration_token_file: Some(token_path.clone()),
        ciba_automated_decision_token_file: Some(ciba_token_path.clone()),
        ttl_seconds: 300,
        yes: true,
    })
    .unwrap();
    assert_eq!(
        token_create,
        TaskOperation::ConformanceLeaseCreate {
            profile: "oidc-fapi-ciba".to_owned(),
            material_sha256: expected_sha256.clone(),
            public_material: None,
            dynamic_registration_initial_access_token_sha256: Some(token_sha256.clone()),
            ciba_automated_decision_token_sha256: Some(ciba_token_sha256.clone()),
            ttl_seconds: 300,
        }
    );
    let serialized = serde_json::to_string(&token_create).unwrap();
    assert!(!serialized.contains("caller-supplied-high-entropy-token"));
    assert!(!serialized.contains("ciba-decision-secret-material"));
    assert!(serialized.contains(&token_sha256));
    assert!(serialized.contains(&ciba_token_sha256));

    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidc-fapi-ciba".to_owned(),
            material: material.clone(),
            dynamic_registration_token_file: Some(work.path().join("missing-token")),
            ciba_automated_decision_token_file: None,
            ttl_seconds: 300,
            yes: true,
        })
        .is_err()
    );
    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidc-fapi-ciba".to_owned(),
            material: material.clone(),
            dynamic_registration_token_file: None,
            ciba_automated_decision_token_file: Some(work.path().join("missing-ciba-token")),
            ttl_seconds: 300,
            yes: true,
        })
        .is_err()
    );
    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidf-fapi2".to_owned(),
            material: material.clone(),
            dynamic_registration_token_file: None,
            ciba_automated_decision_token_file: Some(ciba_token_path.clone()),
            ttl_seconds: 300,
            yes: true,
        })
        .is_err()
    );

    let empty_token_path = work.path().join("empty-token");
    fs::write(&empty_token_path, []).unwrap();
    crate::filesystem::set_mode(&empty_token_path, 0o600).unwrap();
    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidc-fapi-ciba".to_owned(),
            material: material.clone(),
            dynamic_registration_token_file: Some(empty_token_path),
            ciba_automated_decision_token_file: None,
            ttl_seconds: 300,
            yes: true,
        })
        .is_err()
    );

    let oversized_token_path = work.path().join("oversized-token");
    fs::write(&oversized_token_path, vec![b'x'; 4097]).unwrap();
    crate::filesystem::set_mode(&oversized_token_path, 0o600).unwrap();
    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidc-fapi-ciba".to_owned(),
            material: material.clone(),
            dynamic_registration_token_file: Some(oversized_token_path),
            ciba_automated_decision_token_file: None,
            ttl_seconds: 300,
            yes: true,
        })
        .is_err()
    );

    #[cfg(unix)]
    {
        let wide_token_path = work.path().join("wide-token");
        fs::write(&wide_token_path, b"token").unwrap();
        crate::filesystem::set_mode(&wide_token_path, 0o644).unwrap();
        assert!(
            conformance_operation(ConformanceLeaseCommand::Create {
                profile: "oidc-fapi-ciba".to_owned(),
                material: material.clone(),
                dynamic_registration_token_file: Some(wide_token_path),
                ciba_automated_decision_token_file: None,
                ttl_seconds: 300,
                yes: true,
            })
            .is_err()
        );

        let symlink_token_path = work.path().join("symlink-token");
        std::os::unix::fs::symlink(&token_path, &symlink_token_path).unwrap();
        assert!(
            conformance_operation(ConformanceLeaseCommand::Create {
                profile: "oidc-fapi-ciba".to_owned(),
                material: material.clone(),
                dynamic_registration_token_file: Some(symlink_token_path),
                ciba_automated_decision_token_file: None,
                ttl_seconds: 300,
                yes: true,
            })
            .is_err()
        );

        let hardlink_token_path = work.path().join("hardlink-token");
        fs::hard_link(&token_path, &hardlink_token_path).unwrap();
        assert!(
            conformance_operation(ConformanceLeaseCommand::Create {
                profile: "oidc-fapi-ciba".to_owned(),
                material: material.clone(),
                dynamic_registration_token_file: Some(hardlink_token_path),
                ciba_automated_decision_token_file: None,
                ttl_seconds: 300,
                yes: true,
            })
            .is_err()
        );
    }

    assert_eq!(
        conformance_operation(ConformanceLeaseCommand::List).unwrap(),
        TaskOperation::ConformanceLeaseList
    );

    let openid4vc_material = work.path().join("openid4vc-public-trust.json");
    let trust = nazo_operator_protocol::Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: "https://suite.example/".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "client"}]}),
        key_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "holder"}]}),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".to_owned(),
    };
    fs::write(&openid4vc_material, serde_json::to_vec(&trust).unwrap()).unwrap();
    assert!(matches!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "openid4vc".to_owned(),
            material: openid4vc_material,
            dynamic_registration_token_file: None,
            ciba_automated_decision_token_file: None,
            ttl_seconds: 28_800,
            yes: true,
        })
        .unwrap(),
        TaskOperation::ConformanceLeaseCreate {
            public_material: Some(_),
            ..
        }
    ));

    let lease_id = uuid::Uuid::now_v7().to_string();
    assert_eq!(
        conformance_operation(ConformanceLeaseCommand::Revoke {
            lease_id: lease_id.clone(),
            yes: true,
        })
        .unwrap(),
        TaskOperation::ConformanceLeaseRevoke { lease_id }
    );
    assert_eq!(
        conformance_operation(ConformanceLeaseCommand::Cleanup { yes: true }).unwrap(),
        TaskOperation::ConformanceLeaseCleanup
    );

    assert!(
        conformance_operation(ConformanceLeaseCommand::Create {
            profile: "oidf-fapi2".to_owned(),
            material,
            dynamic_registration_token_file: None,
            ciba_automated_decision_token_file: None,
            ttl_seconds: 60,
            yes: false,
        })
        .is_err()
    );
    assert!(
        conformance_operation(ConformanceLeaseCommand::Revoke {
            lease_id: uuid::Uuid::nil().to_string(),
            yes: false,
        })
        .is_err()
    );
    assert!(conformance_operation(ConformanceLeaseCommand::Cleanup { yes: false }).is_err());
}
