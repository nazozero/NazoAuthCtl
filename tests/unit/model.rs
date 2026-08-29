use super::*;

fn valid_manifest() -> ReleaseManifest {
    let target = release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let artifact = |name: String| Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name,
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 5,
        version: "v0.2.0".to_owned(),
        target: target.clone(),
        backend_commit: "b".repeat(40),
        release_identity: "release-identity".to_owned(),
        embedded: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.2.0".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        operator_protocol: OperatorProtocolCompatibility {
            version: nazo_operator_protocol::PROTOCOL_VERSION,
            minimum_ctl_version: "0.2.0".to_owned(),
            maximum_ctl_version_exclusive: "0.3.0".to_owned(),
        },
        artifacts: BTreeMap::from([(
            "binary".to_owned(),
            artifact(format!("nazoauth-{target}{suffix}")),
        )]),
        frontend: FrontendRelease {
            repository: "nazozero/NazoAuthWeb".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: "c".repeat(40),
            release_identity: "https://github.com/nazozero/NazoAuthWeb/.github/workflows/release.yml@refs/tags/v0.2.0".to_owned(),
            artifact: Artifact {
                repository: "nazozero/NazoAuthWeb".to_owned(),
                name: "nazoauth-web.tar.gz".to_owned(),
                sha256: "d".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "e".repeat(64)),
            platform_manifests: BTreeMap::from([
                ("linux/amd64".to_owned(), format!("sha256:{}", "1".repeat(64))),
                ("linux/arm64".to_owned(), format!("sha256:{}", "2".repeat(64))),
            ]),
        },
        rollback: ReleaseRollbackPolicy {
            artifact: true,
            schema_compatible: true,
            database_restore: DatabaseRestore::Backup,
            irreversible_migration: false,
            minimum_supported_version: "0.1.2".to_owned(),
            migration_floor: "1".to_owned(),
            rationale: "compatible".to_owned(),
        },
    }
}

#[test]
fn semantic_versions_require_an_immutable_tag() {
    assert!(semantic_tag("v1.2.3"));
    assert!(semantic_tag("v1.2.3-rc.1"));
    assert!(!semantic_tag("latest"));
    assert!(!semantic_tag("v1.2"));
    assert!(!semantic_tag("1.2.3"));
}

#[test]
fn release_manifest_binds_every_binary_frontend_and_oci_identity() {
    let manifest = valid_manifest();
    manifest.validate("v0.2.0", "release-identity").unwrap();
    let platform = crate::model::container_oci_platform();
    assert_eq!(
        manifest
            .runtime_oci_digest_for(platform)
            .expect("the signed manifest must declare this runtime platform"),
        manifest.oci.platform_manifests[platform],
        "the accessor must agree with the signed platform map"
    );
    assert!(is_lower_hex(&manifest.frontend.commit, 40));

    let mut invalid = manifest.clone();
    invalid.schema = 4;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut missing_protocol = serde_json::to_value(&manifest).unwrap();
    missing_protocol
        .as_object_mut()
        .unwrap()
        .remove("operator_protocol");
    assert!(serde_json::from_value::<ReleaseManifest>(missing_protocol).is_err());
    assert_eq!(nazo_operator_protocol::PROTOCOL_VERSION, 2);
    let mut invalid = manifest.clone();
    invalid.embedded.protocol = 1;
    invalid.operator_protocol.version = 1;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.rollback.irreversible_migration = true;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.rollback.artifact = false;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.insert(
        "updater".to_owned(),
        Artifact {
            repository: "nazozero/NazoAuth".to_owned(),
            name: "nazoauthctl-unexpected".to_owned(),
            sha256: "a".repeat(64),
            size: 1,
        },
    );
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().name = "nazoauth-wrong-target".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().size = 0;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.frontend.artifact.name = "index.html".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.oci.platform_manifests.remove("linux/arm64");
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
}

#[test]
fn platform_mapping_is_total_over_every_published_release_target() {
    assert_eq!(executable_suffix("x86_64-pc-windows-msvc"), ".exe");
    assert_eq!(executable_suffix("x86_64-unknown-linux-gnu"), "");
    for (arch, os, env, expected) in [
        ("x86_64", "linux", "musl", Some("x86_64-unknown-linux-musl")),
        (
            "aarch64",
            "linux",
            "musl",
            Some("aarch64-unknown-linux-musl"),
        ),
        ("x86_64", "linux", "gnu", Some("x86_64-unknown-linux-gnu")),
        ("aarch64", "linux", "gnu", Some("aarch64-unknown-linux-gnu")),
        ("x86_64", "windows", "msvc", Some("x86_64-pc-windows-msvc")),
        (
            "aarch64",
            "windows",
            "msvc",
            Some("aarch64-pc-windows-msvc"),
        ),
        ("x86_64", "macos", "", Some("x86_64-apple-darwin")),
        ("aarch64", "macos", "", Some("aarch64-apple-darwin")),
        ("wasm32", "unknown", "", None),
    ] {
        assert_eq!(release_target_for(arch, os, env), expected);
    }
}
