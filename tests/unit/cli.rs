use super::*;

fn parse(values: &[&str]) -> anyhow::Result<Option<Cli>> {
    Cli::parse(values.iter().map(|value| (*value).to_owned()))
}

#[test]
fn parses_container_install_with_secure_dependency_input() {
    let cli = parse(&[
        "nazoauthctl",
        "--config",
        "/tmp/update.json",
        "install",
        "--runtime",
        "docker",
        "--external-dependencies",
        "--secrets-stdin",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(cli.config, PathBuf::from("/tmp/update.json"));
    let Command::Install(options) = cli.command else {
        panic!("expected install");
    };
    assert_eq!(options.runtime, "docker");
    assert!(options.external_dependencies);
    assert!(options.secrets_stdin);
    assert!(options.database_url.is_none());
    assert!(options.profile_secrets.is_none());
}

#[test]
fn dependency_secrets_are_rejected_in_argv() {
    assert!(
        parse(&[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--database-url",
            "postgresql://user:password@db/oauth",
        ])
        .is_err()
    );
}

#[test]
fn bootstrap_admin_accepts_only_explicit_secret_input_modes() {
    let command = parse(&[
        "nazoauthctl",
        "bootstrap-admin",
        "--credentials-stdin",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::BootstrapAdmin(BootstrapAdminOptions {
            credentials_stdin: true,
            yes: true,
        })
    ));

    assert!(matches!(
        parse(&["nazoauthctl", "bootstrap-admin"])
            .unwrap()
            .unwrap()
            .command,
        Command::BootstrapAdmin(BootstrapAdminOptions {
            credentials_stdin: false,
            yes: false,
        })
    ));

    for arguments in [
        &[
            "nazoauthctl",
            "bootstrap-admin",
            "--email",
            "admin@example.com",
        ][..],
        &["nazoauthctl", "bootstrap-admin", "--password", "secret"][..],
        &["nazoauthctl", "bootstrap-admin", "--yes", "--yes"][..],
        &[
            "nazoauthctl",
            "bootstrap-admin",
            "--credentials-stdin",
            "--credentials-stdin",
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }

    assert!(
        parse(&[
            "nazoauthctl",
            "adopt",
            "--target",
            "podman:manual-runtime-a",
            "--capability",
            "runtime=delegated",
            "--capability",
            "runtime=external",
            "--plan",
        ])
        .is_err()
    );
}

#[test]
fn update_rejects_mutable_versions() {
    assert!(parse(&["nazoauthctl", "update", "--to", "latest"]).is_err());
}

#[test]
fn audit_show_accepts_only_a_safe_optional_request_id() {
    let cli = parse(&[
        "nazoauthctl",
        "audit",
        "show",
        "--request-id",
        "request-0123",
    ])
    .unwrap()
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::AuditShow {
            request_id: Some(ref value)
        } if value == "request-0123"
    ));
    assert!(parse(&["nazoauthctl", "audit", "show", "--request-id", "../key"]).is_err());
}

#[test]
fn parses_every_read_only_command_and_help_boundary() {
    assert!(parse(&["nazoauthctl"]).unwrap().is_none());
    assert!(parse(&["nazoauthctl", "--help"]).unwrap().is_none());

    for (arguments, expected) in [
        (&["nazoauthctl", "status"][..], "status"),
        (&["nazoauthctl", "doctor"][..], "doctor"),
        (&["nazoauthctl", "check"][..], "check"),
        (&["nazoauthctl", "keys", "list"][..], "keys-list"),
        (&["nazoauthctl", "keys", "validate"][..], "keys-validate"),
        (&["nazoauthctl", "audit", "verify"][..], "audit-verify"),
        (&["nazoauthctl", "audit", "show"][..], "audit-show"),
    ] {
        let command = parse(arguments).unwrap().unwrap().command;
        assert!(matches!(
            (expected, command),
            ("status", Command::Status)
                | ("doctor", Command::Doctor)
                | ("check", Command::Check(None))
                | ("keys-list", Command::Keys(KeysCommand::List))
                | ("keys-validate", Command::Keys(KeysCommand::Validate))
                | ("audit-verify", Command::AuditVerify)
                | ("audit-show", Command::AuditShow { request_id: None })
        ));
    }

    let command = parse(&["nazoauthctl", "check", "--to", "v1.2.3"])
        .unwrap()
        .unwrap()
        .command;
    assert!(matches!(command, Command::Check(Some(version)) if version == "v1.2.3"));
}

#[test]
fn help_topics_follow_user_intent_even_with_an_explicit_config() {
    let values = |parts: &[&str]| {
        parts
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "--help"])),
        Some(HelpTopic::TopLevel)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "install", "--help"])),
        Some(HelpTopic::Install)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "bootstrap-admin", "--help"])),
        Some(HelpTopic::BootstrapAdmin)
    );
    assert_eq!(
        help_topic(&values(&[
            "nazoauthctl",
            "--config",
            "/tmp/update.json",
            "update",
            "--help",
        ])),
        Some(HelpTopic::Update)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "conformance", "--help"])),
        Some(HelpTopic::Conformance)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "tls", "--help"])),
        Some(HelpTopic::Tls)
    );
    assert_eq!(help_topic(&values(&["nazoauthctl", "status"])), None);
}

#[test]
fn parses_tls_certificate_plan_apply_recover_and_show() {
    let material = [
        "--provider-config",
        "/etc/nazoauth/tls-provider.json",
        "--tenant",
        "tenant-a",
        "--hostname",
        "auth.example",
        "--certificate",
        "/run/import/fullchain.pem",
        "--private-key",
        "/run/import/private-key.pem",
    ];
    let mut plan = vec!["nazoauthctl", "tls", "certificate", "plan"];
    plan.extend(material);
    assert!(matches!(
        parse(&plan).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Plan(_))
    ));

    let mut apply = vec!["nazoauthctl", "tls", "certificate", "apply"];
    apply.extend(material);
    apply.push("--yes");
    assert!(matches!(
        parse(&apply).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Apply { yes: true, .. })
    ));
    assert!(
        parse(&[
            "nazoauthctl",
            "tls",
            "certificate",
            "recover",
            "--tenant",
            "tenant-a",
            "--hostname",
            "auth.example",
            "--yes",
        ])
        .is_ok()
    );
    assert!(
        parse(&[
            "nazoauthctl",
            "tls",
            "certificate",
            "show",
            "--tenant",
            "tenant-a",
            "--hostname",
            "auth.example",
        ])
        .is_ok()
    );
    let mut invalid_plan = vec!["nazoauthctl", "tls", "certificate", "plan"];
    invalid_plan.extend(material);
    invalid_plan.push("--yes");
    assert!(parse(&invalid_plan).is_err());

    let acme_current = [
        "nazoauthctl",
        "tls",
        "certificate",
        "plan",
        "--provider-config",
        "/etc/nazoauth/tls-provider.json",
        "--tenant",
        "tenant-a",
        "--hostname",
        "auth.example",
        "--from-acme-current",
    ];
    assert!(matches!(
        parse(&acme_current).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Plan(TlsCertificateInput {
            source: TlsCertificateSource::CurrentAcmeReceipt,
            ..
        }))
    ));
    let mut mixed = acme_current.to_vec();
    mixed.extend(["--certificate", "/tmp/cert", "--private-key", "/tmp/key"]);
    assert!(parse(&mixed).is_err());

    let missing_source = &acme_current[..acme_current.len() - 1];
    assert!(parse(missing_source).is_err());

    let check = [
        "nazoauthctl",
        "tls",
        "certificate",
        "check",
        "--provider-config",
        "/etc/nazoauth/tls-provider.json",
        "--tenant",
        "tenant-a",
        "--hostname",
        "auth.example",
        "--warning-window-seconds",
        "1209600",
    ];
    assert!(matches!(
        parse(&check).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Check(TlsCertificateCheckInput {
            warning_window_seconds: Some(1_209_600),
            ..
        }))
    ));
    let mut duplicate_warning = check.to_vec();
    duplicate_warning.extend(["--warning-window-seconds", "2419200"]);
    assert!(parse(&duplicate_warning).is_err());
    let mut invalid_warning = check.to_vec();
    *invalid_warning.last_mut().unwrap() = "not-a-number";
    assert!(parse(&invalid_warning).is_err());
}

#[test]
fn parses_tls_acme_commands_and_requires_mutation_flags_only_for_issue() {
    let input = [
        "--acme-config",
        "/etc/nazoauth/acme.json",
        "--provider-config",
        "/etc/nazoauth/tls-provider.json",
        "--tenant",
        "tenant-a",
        "--hostname",
        "auth.example",
    ];
    let mut plan = vec!["nazoauthctl", "tls", "acme", "plan"];
    plan.extend(input);
    assert!(matches!(
        parse(&plan).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Acme(AcmeCommand::Plan(_)))
    ));

    let mut issue = vec!["nazoauthctl", "tls", "acme", "issue"];
    issue.extend(input);
    issue.extend(["--agree-terms", "--yes"]);
    assert!(matches!(
        parse(&issue).unwrap().unwrap().command,
        Command::Tls(TlsCommand::Acme(AcmeCommand::Issue {
            agree_terms: true,
            yes: true,
            ..
        }))
    ));
    for command in ["recover", "show"] {
        let mut args = vec![
            "nazoauthctl",
            "tls",
            "acme",
            command,
            "--tenant",
            "tenant-a",
            "--hostname",
            "auth.example",
        ];
        if command == "recover" {
            args.push("--yes");
        }
        assert!(parse(&args).is_ok());
    }

    let mut invalid_plan = vec!["nazoauthctl", "tls", "acme", "plan"];
    invalid_plan.extend(input);
    invalid_plan.push("--agree-terms");
    assert!(parse(&invalid_plan).is_err());
    let mut duplicate_agreement = issue;
    duplicate_agreement.push("--agree-terms");
    assert!(parse(&duplicate_agreement).is_err());
}

#[test]
fn help_topics_consume_each_global_option_before_the_command() {
    let values = |parts: &[&str]| {
        parts
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        help_topic(&values(&[
            "nazoauthctl",
            "--deployment",
            "deployment-a",
            "update",
            "--help",
        ])),
        Some(HelpTopic::Update)
    );
    assert_eq!(
        help_topic(&values(&[
            "nazoauthctl",
            "--config",
            "/tmp/update.json",
            "--deployment",
            "deployment-a",
            "install",
            "--help",
        ])),
        Some(HelpTopic::Install)
    );
    assert_eq!(
        help_topic(&values(&[
            "nazoauthctl",
            "--deployment",
            "deployment-a",
            "--config",
            "/tmp/update.json",
            "status",
            "--help",
        ])),
        Some(HelpTopic::TopLevel)
    );
}

#[test]
fn duplicate_global_and_command_scalar_options_are_rejected() {
    for arguments in [
        &[
            "nazoauthctl",
            "--config",
            "/tmp/one.json",
            "--config",
            "/tmp/two.json",
            "status",
        ][..],
        &[
            "nazoauthctl",
            "--deployment",
            "deployment-a",
            "--deployment",
            "deployment-b",
            "status",
        ][..],
        &["nazoauthctl", "update", "--plan", "--plan"][..],
        &["nazoauthctl", "update", "--yes", "--yes"][..],
        &[
            "nazoauthctl",
            "update",
            "--accept-migration-barrier",
            "--accept-migration-barrier",
        ][..],
        &["nazoauthctl", "update", "--to", "v1.2.3", "--to", "v1.2.4"][..],
        &[
            "nazoauthctl",
            "adopt",
            "--target",
            "podman:manual-runtime-a",
            "--plan",
            "--plan",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--runtime",
            "podman",
            "--runtime",
            "docker",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--external-dependencies",
        ][..],
        &[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--reason",
            "lost",
            "--reason",
            "stolen",
        ][..],
    ] {
        assert!(
            parse(arguments).is_err(),
            "accepted duplicate options {arguments:?}"
        );
    }
}

#[test]
fn parses_complete_install_contract_and_rejects_invalid_boundaries() {
    let command = parse(&[
        "nazoauthctl",
        "install",
        "--runtime",
        "host",
        "--public-url",
        "https://auth.example",
        "--profile",
        "standards-full",
        "--profile-material",
        "/srv/oidf-profile.json",
        "--trusted-proxy-cidr",
        "192.0.2.10/32",
        "--data-root",
        "/srv/nazoauth",
        "--port",
        "8443",
        "--external-dependencies",
        "--secret-fd",
        "9",
        "--profile-secret-fd",
        "10",
        "--to",
        "v1.2.3",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Install(options) = command else {
        panic!("expected install");
    };
    assert_eq!(options.runtime, "host");
    assert_eq!(options.public_url, "https://auth.example");
    assert_eq!(options.profile, "standards-full");
    assert_eq!(
        options.profile_material,
        Some(PathBuf::from("/srv/oidf-profile.json"))
    );
    assert_eq!(options.trusted_proxy_cidr.as_deref(), Some("192.0.2.10/32"));
    assert_eq!(options.data_root, PathBuf::from("/srv/nazoauth"));
    assert_eq!(options.port, 8443);
    assert_eq!(options.secret_fd, Some(9));
    assert_eq!(options.profile_secret_fd, Some(10));
    assert_eq!(options.version.as_deref(), Some("v1.2.3"));

    for arguments in [
        &["nazoauthctl", "install", "--runtime", "other"][..],
        &["nazoauthctl", "install", "--port", "0"][..],
        &["nazoauthctl", "install", "--port", "text"][..],
        &["nazoauthctl", "install", "--secret-fd", "text"][..],
        &["nazoauthctl", "install", "--secret-fd", "0"][..],
        &[
            "nazoauthctl",
            "install",
            "--profile",
            "standards-full",
            "--profile-material",
            "/tmp/material.json",
            "--profile-secret-fd",
            "2",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--public-url",
            "http://127.0.0.1:8000",
            "--profile",
            "standards-full",
            "--profile-material",
            "/tmp/material.json",
            "--trusted-proxy-cidr",
            "192.0.2.10/32",
        ][..],
        &["nazoauthctl", "install", "--profile", "standards-full"][..],
        &[
            "nazoauthctl",
            "install",
            "--profile-material",
            "/tmp/material.json",
        ][..],
        &["nazoauthctl", "install", "--public-url"][..],
        &[
            "nazoauthctl",
            "install",
            "--trusted-proxy-cidr",
            "192.0.2.0/24",
        ][..],
        &["nazoauthctl", "install", "--unknown", "value"][..],
        &["nazoauthctl", "--config"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn local_oci_candidate_install_requires_an_exact_complete_source_binding() {
    let revision = "a".repeat(40);
    let digest = format!("sha256:{}", "b".repeat(64));
    let source = format!("source:{revision}");
    let command = parse(&[
        "nazoauthctl",
        "install",
        "--runtime",
        "podman",
        "--public-url",
        "https://auth.example",
        "--profile",
        "standards-full",
        "--profile-material",
        "/srv/profile.json",
        "--trusted-proxy-cidr",
        "192.0.2.10/32",
        "--candidate-image",
        "nazoauth-candidate:459",
        "--candidate-release",
        "v0.1.41-candidate.459",
        "--candidate-revision",
        &revision,
        "--candidate-build-id",
        &source,
        "--candidate-oci-digest",
        &digest,
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Install(options) = command else {
        panic!("expected install");
    };
    assert!(!options.external_dependencies);
    let candidate = options
        .local_oci_candidate
        .as_ref()
        .expect("candidate input")
        .clone();
    assert_eq!(candidate.image, "nazoauth-candidate:459");
    assert_eq!(candidate.target.revision, revision);
    assert_eq!(candidate.target.oci_digest, digest);

    for arguments in [
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41-candidate.459",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            &source,
            "--candidate-oci-digest",
            &digest,
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41-candidate.459",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            &source,
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--runtime",
            "host",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41-candidate.459",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            &source,
            "--candidate-oci-digest",
            &digest,
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41-candidate.459",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            "local:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--candidate-oci-digest",
            &digest,
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41-candidate.459",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            &source,
            "--candidate-oci-digest",
            &digest,
            "--to",
            "v0.1.41",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--candidate-image",
            "candidate",
            "--candidate-release",
            "v0.1.41",
            "--candidate-revision",
            &revision,
            "--candidate-build-id",
            &source,
            "--candidate-oci-digest",
            &digest,
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn parses_pinned_container_network_and_rejects_incomplete_or_host_assignments() {
    let command = parse(&[
        "nazoauthctl",
        "install",
        "--runtime",
        "podman",
        "--network-subnet",
        "10.101.0.0/24",
        "--runtime-ip",
        "10.101.0.20",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Install(options) = command else {
        panic!("expected install");
    };
    assert_eq!(options.network_subnet.as_deref(), Some("10.101.0.0/24"));
    assert_eq!(options.runtime_ip.as_deref(), Some("10.101.0.20"));

    for arguments in [
        &[
            "nazoauthctl",
            "install",
            "--network-subnet",
            "10.101.0.0/24",
        ][..],
        &["nazoauthctl", "install", "--runtime-ip", "10.101.0.20"][..],
        &[
            "nazoauthctl",
            "install",
            "--runtime",
            "host",
            "--network-subnet",
            "10.101.0.0/24",
            "--runtime-ip",
            "10.101.0.20",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--network-subnet",
            "10.101.0.0/24",
            "--runtime-ip",
            "10.102.0.20",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--network-subnet",
            "10.101.0.0/33",
            "--runtime-ip",
            "10.101.0.20",
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn install_secret_channels_and_profile_flags_are_unambiguous() {
    for arguments in [
        &[
            "nazoauthctl",
            "install",
            "--secrets-stdin",
            "--secrets-stdin",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--profile-secrets-stdin",
            "--profile-secrets-stdin",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--secret-fd",
            "3",
            "--secret-fd",
            "4",
        ][..],
        &[
            "nazoauthctl",
            "install",
            "--profile",
            "standards-full",
            "--profile-material",
            "/tmp/material.json",
            "--profile-secret-fd",
            "3",
            "--profile-secret-fd",
            "4",
        ][..],
        &["nazoauthctl", "install", "--profile", "unsupported"][..],
        &["nazoauthctl", "install", "--profile-secrets-stdin"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn parses_update_and_recovery_authorization_without_weakening_plan_mode() {
    let command = parse(&[
        "nazoauthctl",
        "update",
        "--yes",
        "--to",
        "v2.0.0",
        "--accept-migration-barrier",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Update(options) = command else {
        panic!("expected update");
    };
    assert!(options.yes);
    assert!(options.accept_migration_barrier);
    assert_eq!(options.version.as_deref(), Some("v2.0.0"));

    let command = parse(&["nazoauthctl", "update", "--plan", "--to", "v2.0.0"])
        .unwrap()
        .unwrap()
        .command;
    assert!(matches!(command, Command::Update(options) if options.plan && !options.yes));

    for arguments in [
        &["nazoauthctl", "update", "--plan", "--yes"][..],
        &[
            "nazoauthctl",
            "update",
            "--plan",
            "--accept-migration-barrier",
        ][..],
        &["nazoauthctl", "update", "--unknown"][..],
        &["nazoauthctl", "check", "extra"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }

    assert!(matches!(
        parse(&["nazoauthctl", "rollback", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Rollback { yes: true }
    ));

    let command = parse(&[
        "nazoauthctl",
        "keys",
        "export-openid4vc-trust",
        "--output",
        "/run/nazoauth/oidf-request-object-trust.pem",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::ExportOpenid4vcTrust { output })
            if output == std::path::Path::new("/run/nazoauth/oidf-request-object-trust.pem")
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "recover", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Recover { yes: true }
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "recover-update", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::RecoverUpdate { yes: true }
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "recover-identity", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::RecoverIdentity { yes: true }
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "migrate", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Migrate {
            yes: true,
            candidate: None
        }
    ));
    assert!(parse(&["nazoauthctl", "rollback", "unexpected"]).is_err());
}

#[test]
fn development_activation_requires_one_explicit_local_artifact() {
    let command = parse(&[
        "nazoauthctl",
        "--deployment",
        "dev-instance",
        "development",
        "activate",
        "--artifact",
        "localhost/nazoauth:dev-abc12345",
        "--yes",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(command.deployment.as_deref(), Some("dev-instance"));
    assert!(matches!(
        command.command,
        Command::DevelopmentActivate(options)
            if options.artifact == "localhost/nazoauth:dev-abc12345" && options.yes
    ));

    for arguments in [
        &["nazoauthctl", "development", "activate"][..],
        &[
            "nazoauthctl",
            "development",
            "activate",
            "--artifact",
            "image-a",
            "--artifact",
            "image-b",
        ][..],
        &[
            "nazoauthctl",
            "development",
            "activate",
            "--artifact",
            "image-a",
            "--yes",
            "--yes",
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn parses_exact_candidate_migration_target() {
    let command = parse(&[
        "nazoauthctl",
        "migrate",
        "--candidate-release",
        "v0.1.19",
        "--candidate-revision",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--candidate-build-id",
        "private-pre-release:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--candidate-oci-digest",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Migrate {
        yes: true,
        candidate: Some(candidate),
    } = command
    else {
        panic!("expected candidate migration");
    };
    assert_eq!(candidate.release, "v0.1.19");
    assert_eq!(candidate.revision, "a".repeat(40));
    assert_eq!(candidate.oci_digest, format!("sha256:{}", "b".repeat(64)));
}

#[test]
fn coordination_commands_require_explicit_deployment_evidence_and_confirmation() {
    let cli = parse(&[
        "nazoauthctl",
        "--deployment",
        "deployment-a",
        "transaction",
        "evidence",
        "--file",
        "/run/evidence.json",
        "--yes",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(cli.deployment.as_deref(), Some("deployment-a"));
    assert!(matches!(
        cli.command,
        Command::TransactionEvidence { file, yes: true }
            if file == std::path::Path::new("/run/evidence.json")
    ));
    assert!(matches!(
        parse(&[
            "nazoauthctl",
            "--deployment",
            "deployment-a",
            "transaction",
            "resume",
            "--yes",
            "--accept-migration-barrier",
        ])
        .unwrap()
        .unwrap()
        .command,
        Command::TransactionResume {
            yes: true,
            accept_migration_barrier: true,
        }
    ));
    assert!(parse(&["nazoauthctl", "transaction", "evidence"]).is_err());
    assert!(parse(&["nazoauthctl", "transaction", "show", "extra"]).is_err());
}

#[test]
fn parses_capability_transitions_without_collapsing_ownership_or_scope() {
    let command = parse(&[
        "nazoauthctl",
        "--deployment",
        "deployment-a",
        "permissions",
        "set",
        "--capability",
        "runtime=delegated:deployment",
        "--capability",
        "database=external:shared",
        "--yes",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(command.deployment.as_deref(), Some("deployment-a"));
    let Command::PermissionsSet(options) = command.command else {
        panic!("expected permissions set");
    };
    assert!(options.yes);
    assert_eq!(options.changes.len(), 2);
    assert_eq!(options.changes[0].0, crate::deployment::Capability::Runtime);
    assert_eq!(
        options.changes[0].1.responsibility,
        crate::deployment::Responsibility::Delegated
    );
    assert_eq!(
        options.changes[1].1.scope,
        crate::deployment::ResourceScope::Shared
    );

    let command = parse(&[
        "nazoauthctl",
        "--deployment",
        "deployment-a",
        "relinquish",
        "--capability",
        "runtime",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Relinquish(RelinquishOptions { yes: true, .. })
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "--deployment", "deployment-a", "reconcile"])
            .unwrap()
            .unwrap()
            .command,
        Command::Reconcile
    ));

    for arguments in [
        &["nazoauthctl", "permissions", "set", "--yes"][..],
        &[
            "nazoauthctl",
            "permissions",
            "set",
            "--capability",
            "runtime=managed",
            "--capability",
            "runtime=delegated",
            "--yes",
        ][..],
        &["nazoauthctl", "relinquish", "--yes"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn parses_key_mutations_identity_rotation_and_break_glass() {
    let command = parse(&[
        "nazoauthctl",
        "keys",
        "generate-local",
        "--alg",
        "ES256",
        "--purposes",
        "credential,jarm",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::GenerateLocal { alg, purposes, yes })
            if alg == "ES256" && purposes == ["credential", "jarm"] && yes
    ));

    let command = parse(&[
        "nazoauthctl",
        "keys",
        "register-external",
        "--kid",
        "external-1",
        "--alg",
        "ES256",
        "--key-ref",
        "provider:key-1",
        "--public-jwk",
        "/run/public.jwk",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::RegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk,
            yes,
        }) if kid == "external-1"
            && alg == "ES256"
            && key_ref == "provider:key-1"
            && public_jwk == std::path::Path::new("/run/public.jwk")
            && yes
    ));

    assert!(matches!(
        parse(&["nazoauthctl", "identity", "rotate", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::IdentityRotate { yes: true }
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "break-glass", "controller-availability"])
            .unwrap()
            .unwrap()
            .command,
        Command::BreakGlassControllerAvailability
    ));
    assert!(matches!(
        parse(&[
            "nazoauthctl",
            "break-glass",
            "rehearse-controller-loss",
            "--yes",
        ])
        .unwrap()
        .unwrap()
        .command,
        Command::BreakGlassRehearseControllerLoss { yes: true }
    ));
    assert!(matches!(
        parse(&[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--reason",
            "stolen",
            "--yes",
        ])
        .unwrap()
        .unwrap()
        .command,
        Command::BreakGlassRecover { yes: true, reason } if reason == "stolen"
    ));

    for arguments in [
        &["nazoauthctl", "keys"][..],
        &["nazoauthctl", "keys", "generate-local", "--yes", "--yes"][..],
        &[
            "nazoauthctl",
            "keys",
            "generate-local",
            "--alg",
            "ES256",
            "--alg",
            "ES256",
        ][..],
        &[
            "nazoauthctl",
            "keys",
            "export-openid4vc-trust",
            "--output",
            "/tmp/a",
            "--output",
            "/tmp/b",
        ][..],
        &["nazoauthctl", "keys", "unknown"][..],
        &["nazoauthctl", "identity", "rotate", "extra"][..],
        &[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--reason",
            "other",
            "--yes",
        ][..],
        &[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--unknown",
        ][..],
        &["nazoauthctl", "unknown"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn legacy_conformance_lease_commands_are_not_part_of_the_controller_cli() {
    for arguments in [
        &["nazoauthctl", "conformance", "lease", "list"][..],
        &[
            "nazoauthctl",
            "conformance",
            "lease",
            "revoke",
            "--lease-id",
            "018f3f2a-7b55-7a25-8f20-6d526f8f44e1",
            "--yes",
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn internal_remote_exec_is_a_fixed_no_argument_command() {
    let command = parse(&["nazoauthctl", "remote", "exec"])
        .unwrap()
        .unwrap()
        .command;
    assert!(matches!(command, Command::RemoteExec));

    for arguments in [
        &["nazoauthctl", "remote"][..],
        &["nazoauthctl", "remote", "listen"][..],
        &["nazoauthctl", "remote", "exec", "--port", "8080"][..],
        &["nazoauthctl", "remote", "exec", "extra"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}
