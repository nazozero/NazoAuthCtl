use super::*;
use crate::filesystem::PrivateTempDir;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::RootCertStore;
use std::io::{Cursor, Read as _, Write as _};
use std::sync::Arc;

#[test]
fn tenant_and_hostname_bindings_are_canonical_and_path_safe() {
    assert_eq!(canonical_tenant("tenant-a").unwrap(), "tenant-a");
    assert!(canonical_tenant("../tenant").is_err());
    assert!(canonical_tenant("").is_err());

    assert_eq!(canonical_hostname("AUTH.Example").unwrap(), "auth.example");
    assert!(canonical_hostname("*.example").is_err());
    assert!(canonical_hostname("auth.example.").is_err());
    assert!(canonical_hostname("203.0.113.1").is_err());
    assert!(canonical_hostname("2001:db8::1").is_err());
}

#[test]
fn provider_and_journal_reject_unknown_fields() {
    let provider = serde_json::json!({
        "schema": 1,
        "protocol": PROVIDER_PROTOCOL,
        "tenant": "tenant-a",
        "hostname": "auth.example",
        "material_root": "/srv/nazoauth/tls/auth.example",
        "activation_link": "/srv/nazoauth/tls/auth.example/current",
        "trust_anchors": "/etc/ssl/auth-root.pem",
        "public_url": "https://auth.example/health/ready",
        "accepted_statuses": [200],
        "minimum_validity_seconds": 86400,
        "connect_timeout_seconds": 5,
        "request_timeout_seconds": 10,
        "validate": {"program": "/usr/sbin/nginx", "args": ["-t"]},
        "reload": {"program": "/usr/bin/systemctl", "args": ["reload", "nginx"]},
        "unexpected": true
    });
    assert!(serde_json::from_value::<ProviderConfig>(provider).is_err());
}

#[test]
fn transaction_provider_snapshot_detects_recovery_command_drift() {
    let mut transaction =
        test_transaction(PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example"));
    assert_eq!(
        transaction.provider_snapshot_sha256,
        "73acc5226ce093c67966d32c19b36216d019934c735f0111642566123b8dae32"
    );
    assert!(validate_provider_snapshot(&transaction).is_ok());
    transaction
        .provider
        .reload
        .args
        .push("--changed".to_owned());
    assert!(validate_provider_snapshot(&transaction).is_err());
}

#[cfg(unix)]
#[test]
fn provider_snapshot_path_encoding_preserves_unix_backslash_components() {
    assert_ne!(
        canonical_digest_path(Path::new("/srv/a\\b"), "test path").unwrap(),
        canonical_digest_path(Path::new("/srv/a/b"), "test path").unwrap()
    );
}

#[test]
fn transaction_phase_distinguishes_pre_activation_from_rollback_required() {
    assert!(!TransactionPhase::Prepared.activation_may_have_happened());
    assert!(!TransactionPhase::Staged.activation_may_have_happened());
    assert!(TransactionPhase::Activating.activation_may_have_happened());
    assert!(TransactionPhase::Activated.activation_may_have_happened());
    assert!(TransactionPhase::Reloaded.activation_may_have_happened());
    assert!(TransactionPhase::RollbackFailed.activation_may_have_happened());
}

#[test]
fn recovery_accepts_only_the_exact_previous_or_committed_receipt() {
    let material_root = PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example");
    let mut transaction = test_transaction(material_root.clone());
    assert!(validate_previous_receipt_binding(&transaction, None).is_ok());

    transaction.expected_revision = 1;
    transaction.target_revision = 2;
    transaction.previous_generation = Some(material_root.join("generations/1-previous"));
    transaction.previous_leaf_certificate_sha256 = Some("e".repeat(64));
    let mut previous = test_receipt(
        &transaction,
        "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8b",
        1,
        transaction.previous_generation.clone().unwrap(),
        "e".repeat(64),
    );
    transaction.previous_receipt_sha256 = Some(receipt_sha256(&previous).unwrap());
    assert!(validate_previous_receipt_binding(&transaction, Some(&previous)).is_ok());

    previous.public_url = "https://auth.example/changed".to_owned();
    assert!(validate_previous_receipt_binding(&transaction, Some(&previous)).is_err());
    previous.public_url = transaction.provider.public_url.clone();

    // Receipt identity is independent of the live pointer because the target
    // may already be active during recovery. A changed generation is still
    // rejected before any pointer or provider command can be touched.
    previous.generation = material_root.join("generations/1-replaced");
    assert!(validate_previous_receipt_binding(&transaction, Some(&previous)).is_err());

    let mut committed = test_receipt(
        &transaction,
        &transaction.jti,
        transaction.target_revision,
        transaction.generation.clone(),
        transaction.leaf_certificate_sha256.clone(),
    );
    assert!(validate_committed_receipt_binding(&transaction, &committed).is_ok());
    assert!(ensure_source_not_current(Some(&committed), &transaction.source).is_err());
    let different_source = CertificateSourceBinding::ExternalFiles {
        certificate_sha256: "1".repeat(64),
        private_key_sha256: "2".repeat(64),
    };
    assert!(ensure_source_not_current(Some(&committed), &different_source).is_ok());
    committed.provider_config_sha256 = "f".repeat(64);
    assert!(validate_committed_receipt_binding(&transaction, &committed).is_err());
}

#[test]
fn recovery_fences_activation_to_the_previous_or_target_generation() {
    let material_root = PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example");
    let mut transaction = test_transaction(material_root.clone());
    let previous = material_root.join("generations/1-previous");
    let unrelated = material_root.join("generations/unrelated");
    transaction.previous_generation = Some(previous.clone());

    transaction.phase = TransactionPhase::Prepared;
    assert!(validate_recovery_activation_state(&transaction, Some(previous.as_path())).is_ok());
    assert!(
        validate_recovery_activation_state(&transaction, Some(transaction.generation.as_path()))
            .is_err()
    );

    transaction.phase = TransactionPhase::Activated;
    assert!(validate_recovery_activation_state(&transaction, Some(previous.as_path())).is_ok());
    assert!(
        validate_recovery_activation_state(&transaction, Some(transaction.generation.as_path()))
            .is_ok()
    );
    assert!(validate_recovery_activation_state(&transaction, Some(unrelated.as_path())).is_err());
}

#[test]
fn receipt_archive_restores_only_identical_current_evidence_and_never_overwrites() {
    let work = PrivateTempDir::new("nazoauth-tls-receipt-archive").unwrap();
    let directory = work.path().join("binding");
    ensure_private_directory(&directory, "test TLS receipt binding").unwrap();
    let transaction = test_transaction(work.path().join("material"));
    let receipt = test_receipt(
        &transaction,
        &transaction.jti,
        transaction.target_revision,
        transaction.generation.clone(),
        transaction.leaf_certificate_sha256.clone(),
    );

    persist_receipt_at(&directory, &receipt).unwrap();
    let archive_path = receipt_archive_path(&directory, receipt.revision);
    let current_path = directory.join("receipt.json");
    let archive = fs::read(&archive_path).unwrap();
    let current = fs::read(&current_path).unwrap();
    assert_eq!(archive, current);
    assert!(ensure_receipt_archive_available(&directory, receipt.revision).is_err());

    // A crash after the immutable revision write but before the current pointer
    // is recoverable only from those exact archived bytes.
    fs::remove_file(&current_path).unwrap();
    persist_receipt_at(&directory, &receipt).unwrap();
    assert_eq!(fs::read(&archive_path).unwrap(), archive);
    assert_eq!(fs::read(&current_path).unwrap(), current);

    let mut conflicting = receipt;
    conflicting.jti = "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8b".to_owned();
    assert!(persist_receipt_at(&directory, &conflicting).is_err());
    assert_eq!(fs::read(&archive_path).unwrap(), archive);
    assert_eq!(fs::read(&current_path).unwrap(), current);
}

#[test]
fn certificate_source_binding_is_persistently_verifiable() {
    let certificate_sha256 = "c".repeat(64);
    let private_key_sha256 = "d".repeat(64);
    let leaf_sha256 = "e".repeat(64);
    let material_sha256 = sha256(format!("{leaf_sha256}:{certificate_sha256}").as_bytes());
    let external = CertificateSourceBinding::ExternalFiles {
        certificate_sha256: certificate_sha256.clone(),
        private_key_sha256: private_key_sha256.clone(),
    };
    assert!(valid_certificate_source_binding(
        &external,
        7,
        1_800_000_000,
        1_900_000_000,
    ));
    assert_eq!(
        source_material_sha256(&external, &leaf_sha256),
        material_sha256
    );

    let source = AcmeInstallSource {
        receipt_sha256: "a".repeat(64),
        issuance_jti: "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8b".to_owned(),
        issuance_declaration_revision: 7,
        issuance_revision: 3,
        acme_protocol: acme::CONFIG_PROTOCOL.to_owned(),
        acme_config_sha256: "b".repeat(64),
        certificate_path: PathBuf::from("/private/fullchain.pem"),
        private_key_path: PathBuf::from("/private/private-key.pem"),
        certificate_sha256: certificate_sha256.clone(),
        private_key_sha256: private_key_sha256.clone(),
        leaf_certificate_sha256: leaf_sha256.clone(),
        material_sha256: material_sha256.clone(),
        certificate_not_after: 1_900_000_000,
        issued_at: 1_799_999_000,
    };
    let material = ValidatedMaterial {
        certificate_pem: Vec::new(),
        private_key_pem: zeroize::Zeroizing::new(Vec::new()),
        certificate_sha256,
        private_key_sha256,
        leaf_sha256,
        material_sha256,
        not_after: 1_900_000_000,
        root_store: RootCertStore::empty(),
    };
    let binding = bind_certificate_source(
        &ResolvedCertificateSource::AcmeReceipt(Box::new(source.clone())),
        &material,
    )
    .unwrap();
    assert!(valid_certificate_source_binding(
        &binding,
        7,
        1_800_000_000,
        1_900_000_000,
    ));

    let mut changed = source;
    changed.material_sha256 = "f".repeat(64);
    assert!(
        bind_certificate_source(
            &ResolvedCertificateSource::AcmeReceipt(Box::new(changed)),
            &material,
        )
        .is_err()
    );
}

#[test]
fn readiness_revalidates_active_material_and_renewal_window() {
    assert_eq!(effective_warning_window(86_400, None).unwrap(), 86_400);
    assert_eq!(
        effective_warning_window(86_400, Some(604_800)).unwrap(),
        604_800
    );
    assert_eq!(
        effective_warning_window(604_800, Some(86_400)).unwrap(),
        604_800
    );
    assert!(effective_warning_window(86_400, Some(3599)).is_err());
    assert_eq!(
        ensure_outside_warning_window(1_800_700_001, 1_800_000_000, 604_800).unwrap(),
        700_001
    );
    assert!(ensure_outside_warning_window(1_800_604_800, 1_800_000_000, 604_800).is_err());

    let transaction = test_transaction(PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example"));
    let receipt = test_receipt(
        &transaction,
        &transaction.jti,
        transaction.target_revision,
        transaction.generation.clone(),
        transaction.leaf_certificate_sha256.clone(),
    );
    let (certificate_sha256, private_key_sha256) = source_file_sha256(&receipt.source);
    let mut material = ValidatedMaterial {
        certificate_pem: Vec::new(),
        private_key_pem: zeroize::Zeroizing::new(Vec::new()),
        certificate_sha256: certificate_sha256.to_owned(),
        private_key_sha256: private_key_sha256.to_owned(),
        leaf_sha256: receipt.leaf_certificate_sha256.clone(),
        material_sha256: receipt.material_sha256.clone(),
        not_after: receipt.certificate_not_after,
        root_store: RootCertStore::empty(),
    };
    assert!(validate_installed_material(&receipt, &material).is_ok());
    material.private_key_sha256 = "0".repeat(64);
    assert!(validate_installed_material(&receipt, &material).is_err());
}

#[test]
fn pending_journal_fences_one_activation_resource_across_deployments() {
    let work = PrivateTempDir::new("nazoauth-tls-provider-fence").unwrap();
    let store = DeploymentStore {
        config_root: work.path().join("config"),
        state_root: work.path().join("state"),
        break_glass_root: work.path().join("break-glass"),
    };
    let transaction = test_transaction(PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example"));
    let pending = pending_path(&store, &transaction);
    ensure_private_directory(pending.parent().unwrap(), "test TLS binding").unwrap();
    atomic_write(&pending, &serde_json::to_vec(&transaction).unwrap(), 0o600).unwrap();

    assert!(
        ensure_provider_not_pending(
            &store,
            "deployment-b",
            &transaction.provider,
            "tenant-b",
            "auth.example",
        )
        .is_err()
    );

    let mut independent = transaction.provider.clone();
    independent.material_root = PathBuf::from("/srv/nazoauth/tls/tenant-b/auth.example");
    independent.activation_link = independent.material_root.join("current");
    assert!(
        ensure_provider_not_pending(
            &store,
            "deployment-b",
            &independent,
            "tenant-b",
            "auth.example",
        )
        .is_ok()
    );
}

#[test]
fn public_verification_rejects_private_and_documentation_addresses() {
    assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
    assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
    assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
    assert!(!is_public_ip("198.18.0.1".parse().unwrap()));
    assert!(!is_public_ip("240.0.0.1".parse().unwrap()));
    assert!(!is_public_ip("192.0.2.1".parse().unwrap()));
    assert!(!is_public_ip("::1".parse().unwrap()));
    assert!(!is_public_ip("::ffff:127.0.0.1".parse().unwrap()));
    assert!(!is_public_ip("fc00::1".parse().unwrap()));
    assert!(!is_public_ip("2001:db8::1".parse().unwrap()));
    assert!(!is_public_ip("2002:7f00:1::1".parse().unwrap()));
    assert!(is_public_ip("1.1.1.1".parse().unwrap()));
    assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[test]
fn offline_validation_proves_chain_san_server_usage_and_key_match() {
    let work = PrivateTempDir::new("nazoauth-tls-material").unwrap();
    let certificate_path = work.path().join("fullchain.pem");
    let private_key_path = work.path().join("private-key.pem");

    let mut ca_params = CertificateParams::new(vec!["NazoAuth test root".to_owned()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["auth.example".to_owned()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
    fs::write(&certificate_path, leaf.pem()).unwrap();
    fs::write(&private_key_path, leaf_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let provider = LoadedProvider {
        config: ProviderConfig {
            schema: PROVIDER_SCHEMA,
            protocol: PROVIDER_PROTOCOL.to_owned(),
            tenant: "tenant-a".to_owned(),
            hostname: "auth.example".to_owned(),
            material_root: work.path().join("material"),
            activation_link: work.path().join("material/current"),
            trust_anchors: work.path().join("root.pem"),
            public_url: "https://auth.example/health/ready".to_owned(),
            accepted_statuses: BTreeSet::from([200]),
            minimum_validity_seconds: 3600,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            validate: ProviderCommand {
                program: work.path().join("validate"),
                args: Vec::new(),
            },
            reload: ProviderCommand {
                program: work.path().join("reload"),
                args: Vec::new(),
            },
        },
        config_sha256: "a".repeat(64),
        trust_anchors: ca.pem().into_bytes(),
        trust_anchors_sha256: "b".repeat(64),
        public_url: Url::parse("https://auth.example/health/ready").unwrap(),
    };
    let input = TlsCertificateInput {
        provider_config: work.path().join("provider.json"),
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        source: TlsCertificateSource::ExternalFiles {
            certificate: certificate_path,
            private_key: private_key_path.clone(),
        },
    };
    let (certificate, private_key) = match &input.source {
        TlsCertificateSource::ExternalFiles {
            certificate,
            private_key,
        } => (certificate.as_path(), private_key.as_path()),
        TlsCertificateSource::CurrentAcmeReceipt => unreachable!(),
    };
    let validated =
        load_and_validate_material(certificate, private_key, &input.hostname, &provider).unwrap();
    assert_eq!(validated.leaf_sha256.len(), 64);
    assert!(validated.not_after > Utc::now().timestamp());

    let mut transaction = test_transaction(provider.config.material_root.clone());
    transaction.provider = provider.config.clone();
    transaction.provider_config_sha256 = provider.config_sha256.clone();
    transaction.provider_snapshot_sha256 = provider_snapshot_sha256(&provider.config).unwrap();
    transaction.trust_anchors_sha256 = provider.trust_anchors_sha256.clone();
    transaction.source = CertificateSourceBinding::ExternalFiles {
        certificate_sha256: validated.certificate_sha256.clone(),
        private_key_sha256: validated.private_key_sha256.clone(),
    };
    transaction.material_sha256 = validated.material_sha256.clone();
    transaction.leaf_certificate_sha256 = validated.leaf_sha256.clone();
    transaction.certificate_not_after = validated.not_after;
    let receipt = test_receipt(
        &transaction,
        &transaction.jti,
        1,
        work.path().to_path_buf(),
        validated.leaf_sha256.clone(),
    );
    assert!(validate_rollback_material(&receipt, &provider).is_ok());
    let mut changed_provider = provider.clone();
    changed_provider.config_sha256 = "c".repeat(64);
    assert!(validate_rollback_material(&receipt, &changed_provider).is_err());

    let wrong_key = KeyPair::generate().unwrap();
    fs::write(&private_key_path, wrong_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(
        load_and_validate_material(certificate, private_key, &input.hostname, &provider).is_err()
    );
    assert!(validate_rollback_material(&receipt, &provider).is_err());
}

#[test]
fn public_verification_observes_real_tls_leaf_and_http_health() {
    use std::net::TcpListener;

    let (ca_pem, leaf_der, key_der) = test_server_identity();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der.clone()], key_der)
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (tcp, _) = listener.accept().unwrap();
            let connection =
                rustls::ServerConnection::new(Arc::new(server_config.clone())).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .unwrap();
            stream.flush().unwrap();
        }
    });

    let provider = ProviderConfig {
        schema: PROVIDER_SCHEMA,
        protocol: PROVIDER_PROTOCOL.to_owned(),
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        material_root: PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example"),
        activation_link: PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example/current"),
        trust_anchors: PathBuf::from("/etc/ssl/auth-root.pem"),
        public_url: "https://auth.example/health/ready".to_owned(),
        accepted_statuses: BTreeSet::from([200]),
        minimum_validity_seconds: 3600,
        connect_timeout_seconds: 2,
        request_timeout_seconds: 2,
        validate: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
        reload: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
    };
    verify_public_address(
        &Url::parse("https://auth.example/health/ready").unwrap(),
        "auth.example",
        address,
        &sha256(leaf_der.as_ref()),
        root_store_from_pem(ca_pem.as_bytes()).unwrap(),
        &provider,
    )
    .unwrap();
    verify_public_address_not_leaf(
        &Url::parse("https://auth.example/health/ready").unwrap(),
        "auth.example",
        address,
        &"0".repeat(64),
        root_store_from_pem(ca_pem.as_bytes()).unwrap(),
        &provider,
    )
    .unwrap();
    let error = verify_public_address_not_leaf(
        &Url::parse("https://auth.example/health/ready").unwrap(),
        "auth.example",
        address,
        &sha256(leaf_der.as_ref()),
        root_store_from_pem(ca_pem.as_bytes()).unwrap(),
        &provider,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("still presents"));
    server.join().unwrap();
}

#[test]
fn public_verification_uses_an_absolute_request_deadline() {
    use std::net::TcpListener;

    let (ca_pem, leaf_der, key_der) = test_server_identity();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der.clone()], key_der)
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1200));
    });
    let mut provider =
        test_transaction(PathBuf::from("/srv/nazoauth/tls/tenant-a/auth.example")).provider;
    provider.request_timeout_seconds = 1;
    let error = verify_public_address(
        &Url::parse("https://auth.example/health/ready").unwrap(),
        "auth.example",
        address,
        &sha256(leaf_der.as_ref()),
        root_store_from_pem(ca_pem.as_bytes()).unwrap(),
        &provider,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("absolute timeout"));
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn activated_generation_is_deactivated_before_rollback_public_proof() {
    let work = PrivateTempDir::new("nazoauth-tls-rollback").unwrap();
    let material_root = work.path().join("material");
    let provider = ProviderConfig {
        schema: PROVIDER_SCHEMA,
        protocol: PROVIDER_PROTOCOL.to_owned(),
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        activation_link: material_root.join("current"),
        material_root: material_root.clone(),
        trust_anchors: work.path().join("root.pem"),
        public_url: "https://auth.example/health/ready".to_owned(),
        accepted_statuses: BTreeSet::from([200]),
        minimum_validity_seconds: 3600,
        connect_timeout_seconds: 1,
        request_timeout_seconds: 1,
        validate: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
        reload: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
    };
    let generation = material_root.join("generations/1-test-jti");
    let mut transaction = CertificateTransaction {
        schema: TRANSACTION_SCHEMA,
        jti: "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8a".to_owned(),
        deployment_id: "deployment-a".to_owned(),
        declaration_revision: 7,
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        capability: "proxy_tls".to_owned(),
        expected_revision: 0,
        target_revision: 1,
        source: CertificateSourceBinding::ExternalFiles {
            certificate_sha256: "f".repeat(64),
            private_key_sha256: "e".repeat(64),
        },
        material_sha256: sha256(format!("{}:{}", "b".repeat(64), "f".repeat(64)).as_bytes()),
        leaf_certificate_sha256: "b".repeat(64),
        certificate_not_after: Utc::now().timestamp() + 86400,
        provider_config_sha256: "c".repeat(64),
        provider_snapshot_sha256: provider_snapshot_sha256(&provider).unwrap(),
        trust_anchors_sha256: "d".repeat(64),
        trust_anchors_pem: "test public anchor".to_owned(),
        provider: provider.clone(),
        generation: generation.clone(),
        previous_generation: None,
        previous_leaf_certificate_sha256: None,
        previous_receipt_sha256: None,
        created_at: Utc::now().timestamp(),
        expires_at: Utc::now().timestamp() + TRANSACTION_TTL_SECONDS,
        phase: TransactionPhase::Prepared,
        last_error: None,
    };
    let material = ValidatedMaterial {
        certificate_pem: b"public certificate".to_vec(),
        private_key_pem: zeroize::Zeroizing::new(b"private key".to_vec()),
        certificate_sha256: "f".repeat(64),
        private_key_sha256: "e".repeat(64),
        leaf_sha256: "b".repeat(64),
        material_sha256: transaction.material_sha256.clone(),
        not_after: transaction.certificate_not_after,
        root_store: RootCertStore::empty(),
    };
    stage_generation(&transaction, &material).unwrap();
    transaction.phase = TransactionPhase::Staged;
    activate(&transaction).unwrap();
    transaction.phase = TransactionPhase::Activated;
    assert_eq!(
        active_generation(&transaction.provider).unwrap(),
        Some(generation.clone())
    );
    restore_previous_activation(&transaction).unwrap();
    remove_inactive_generation(&transaction).unwrap();
    assert!(active_generation(&transaction.provider).unwrap().is_none());
    assert!(!generation.exists());
}

fn test_transaction(material_root: PathBuf) -> CertificateTransaction {
    let provider = ProviderConfig {
        schema: PROVIDER_SCHEMA,
        protocol: PROVIDER_PROTOCOL.to_owned(),
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        activation_link: material_root.join("current"),
        material_root: material_root.clone(),
        trust_anchors: PathBuf::from("/etc/ssl/auth-root.pem"),
        public_url: "https://auth.example/health/ready".to_owned(),
        accepted_statuses: BTreeSet::from([200]),
        minimum_validity_seconds: 3600,
        connect_timeout_seconds: 1,
        request_timeout_seconds: 1,
        validate: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
        reload: ProviderCommand {
            program: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        },
    };
    let now = Utc::now().timestamp();
    CertificateTransaction {
        schema: TRANSACTION_SCHEMA,
        jti: "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8a".to_owned(),
        deployment_id: "deployment-a".to_owned(),
        declaration_revision: 7,
        tenant: "tenant-a".to_owned(),
        hostname: "auth.example".to_owned(),
        capability: "proxy_tls".to_owned(),
        expected_revision: 0,
        target_revision: 1,
        source: CertificateSourceBinding::ExternalFiles {
            certificate_sha256: "f".repeat(64),
            private_key_sha256: "e".repeat(64),
        },
        material_sha256: sha256(format!("{}:{}", "b".repeat(64), "f".repeat(64)).as_bytes()),
        leaf_certificate_sha256: "b".repeat(64),
        certificate_not_after: now + 86400,
        provider_config_sha256: "c".repeat(64),
        provider_snapshot_sha256: provider_snapshot_sha256(&provider).unwrap(),
        trust_anchors_sha256: "d".repeat(64),
        trust_anchors_pem: "test public anchor".to_owned(),
        provider: provider.clone(),
        generation: material_root.join("generations/1-target"),
        previous_generation: None,
        previous_leaf_certificate_sha256: None,
        previous_receipt_sha256: None,
        created_at: now,
        expires_at: now + TRANSACTION_TTL_SECONDS,
        phase: TransactionPhase::Prepared,
        last_error: None,
    }
}

fn test_server_identity() -> (
    String,
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let mut ca_params = CertificateParams::new(vec!["NazoAuth test root".to_owned()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["auth.example".to_owned()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
    let key_der = rustls_pemfile::private_key(&mut Cursor::new(leaf_key.serialize_pem()))
        .unwrap()
        .unwrap();
    (ca.pem(), leaf.der().clone(), key_der)
}

fn test_receipt(
    transaction: &CertificateTransaction,
    jti: &str,
    revision: u64,
    generation: PathBuf,
    leaf_certificate_sha256: String,
) -> CertificateReceipt {
    CertificateReceipt {
        schema: RECEIPT_SCHEMA,
        jti: jti.to_owned(),
        deployment_id: transaction.deployment_id.clone(),
        declaration_revision: transaction.declaration_revision,
        tenant: transaction.tenant.clone(),
        hostname: transaction.hostname.clone(),
        capability: transaction.capability.clone(),
        revision,
        source: transaction.source.clone(),
        material_sha256: transaction.material_sha256.clone(),
        leaf_certificate_sha256,
        certificate_not_after: transaction.certificate_not_after,
        provider_protocol: PROVIDER_PROTOCOL.to_owned(),
        provider_config_sha256: transaction.provider_config_sha256.clone(),
        trust_anchors_sha256: transaction.trust_anchors_sha256.clone(),
        generation,
        activation_link: transaction.provider.activation_link.clone(),
        public_url: transaction.provider.public_url.clone(),
        transaction_created_at: transaction.created_at,
        transaction_expires_at: transaction.expires_at,
        verified_at: transaction.created_at,
    }
}
