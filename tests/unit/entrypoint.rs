use super::*;

#[test]
fn every_public_help_topic_is_complete_without_runtime_state() {
    for (topic, expected) in [
        (cli::HelpTopic::TopLevel, "Commands:"),
        (cli::HelpTopic::Host, "host forget"),
        (cli::HelpTopic::Instance, "instance relocate"),
        (cli::HelpTopic::Controller, "controller revoke"),
        (cli::HelpTopic::Install, "--public-url"),
        (cli::HelpTopic::Admin, "admin create"),
        (cli::HelpTopic::Update, "--to VERSION"),
        (cli::HelpTopic::SelfUpdate, "self update"),
    ] {
        let help = help_text(topic);
        assert!(help.starts_with("Usage:") || help.starts_with("nazoauthctl"));
        assert!(help.contains(expected));
    }
    assert!(!help_text(cli::HelpTopic::Install).contains("--artifact-sha256"));
    assert!(!help_text(cli::HelpTopic::Update).contains("--artifact-sha256"));
}

#[test]
fn release_workflow_requires_successful_ci_for_the_exact_tag_commit() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .unwrap();
    let gate = workflow
        .find("Require successful controller CI for exact tag commit")
        .unwrap();
    let build = workflow.find("\n  build:").unwrap();
    assert!(gate < build, "tag CI gate must precede the build job");
    for required in [
        "actions: read",
        "/actions/workflows/ci.yml/runs?event=push&head_sha=",
        ".head_sha == $sha",
        ".head_branch == \"main\"",
        ".status == \"completed\"",
        ".conclusion == \"success\"",
    ] {
        assert!(
            workflow.contains(required),
            "workflow lost contract: {required}"
        );
    }
    for line in workflow
        .lines()
        .filter(|line| line.trim_start().starts_with("- uses:"))
    {
        let reference = line
            .split_once('@')
            .and_then(|(_, value)| value.split_whitespace().next())
            .expect("workflow action must pin an immutable reference");
        assert!(
            reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "workflow action is not pinned to a full commit SHA: {line}"
        );
    }
}

#[test]
fn server_compatibility_is_current_only_and_keeps_tokens_out_of_controller_steps() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/server-compatibility.yml"
    ))
    .unwrap()
    .replace("\r\n", "\n");
    let top_level = workflow.split_once("\njobs:").unwrap().0;
    assert!(top_level.contains("permissions:\n  contents: read"));
    assert!(!top_level.contains("attestations: read"));
    assert!(!top_level.contains("packages: read"));
    assert!(!top_level.contains("pull_request:"));
    assert!(top_level.contains("server_release:"));
    assert!(top_level.contains("description: Exact supported NazoAuth release tag"));
    assert!(!workflow.contains("NAZOAUTHCTL_BUILD_COMMIT"));
    assert_eq!(
        workflow
            .matches("test \"$SERVER_RELEASE\" = v0.2.13")
            .count(),
        1
    );
    assert!(!workflow.contains("v0.2.2"));
    assert!(!workflow.contains("previous-v"));
    assert!(!workflow.contains("python3"));
    assert!(!workflow.contains("- name: Recover"));
    assert!(!workflow.contains("provider"));
    assert!(!workflow.contains("rollback"));
    assert!(workflow.contains(".protocol == 3"));
    assert!(workflow.contains("Execute VerifiedRelease current production verification"));
    assert!(workflow.contains("VerifiedRelease::verify"));
    assert!(!workflow.contains("SERVER_PEELED_COMMIT"));
    assert!(!workflow.contains("OPERATOR_PROTOCOL_REV"));
    assert!(workflow.contains("cosign verify \"$tagged_image\""));
    assert!(
        workflow.contains("sudo install -m 0755 \"$(command -v cosign)\" /usr/local/bin/cosign")
    );
    assert!(!workflow.contains("controller/nazoauthctl --help"));
    let protocol_schema = target::HOST_PROTOCOL_SCHEMA;
    assert!(workflow.contains(&format!(
        r#"{{"schema":{protocol_schema},"operation_id":"019018c0-0000-7000-8000-000000000001""#
    )));
    assert!(workflow.contains(&format!(".schema == {protocol_schema}")));
    assert!(workflow.contains(&format!(
        ".outcome.body.hello.remote_exec_schema == {protocol_schema}"
    )));

    let current_controller = workflow
        .split_once("\n  current-controller:")
        .unwrap()
        .1
        .split_once("\n  signed-current-server:")
        .unwrap()
        .0;
    assert!(current_controller.contains("permissions:\n      contents: read"));
    assert!(current_controller.contains("persist-credentials: false"));
    assert!(!current_controller.contains("GH_TOKEN"));

    let signed_current_server = workflow.split_once("\n  signed-current-server:").unwrap().1;
    assert!(!signed_current_server.contains("\n    env:\n      GH_TOKEN:"));
    assert!(!signed_current_server.contains("packages: read"));
    assert!(!signed_current_server.contains("docker/setup-buildx-action@"));
    assert!(signed_current_server.contains("docker manifest inspect \"$image\""));

    for step in [
        "Execute the exact controller artifact through its production protocol path",
        "Verify the protocol-3 host release identity",
        "Verify the signed OCI identity at its immutable digest",
        "Execute VerifiedRelease current production verification",
    ] {
        let marker = format!("- name: {step}");
        let section = workflow.split_once(marker.as_str()).unwrap().1;
        assert!(
            !section
                .split_once("\n      - name:")
                .map_or(section, |(current, _)| current)
                .contains("GH_TOKEN")
        );
    }
}

#[test]
fn release_compatibility_gate_pins_the_current_protocol_three_server() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .unwrap();
    let gate = workflow
        .split_once("\n  server-compatibility:")
        .unwrap()
        .1
        .split_once("\n  build:")
        .unwrap()
        .0;
    assert!(gate.contains("controller_ref: ${{ github.sha }}"));
    assert!(gate.contains("server_release: v0.2.13"));
    assert!(!gate.contains("previous"));
}

#[test]
fn release_does_not_treat_pre_cut_controller_as_an_update_source() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .unwrap();
    assert!(!workflow.contains("Resolve the previous controller release"));
    assert!(!workflow.contains("self_update_matrix"));
    assert!(!workflow.contains("PREVIOUS_RELEASE"));
    assert!(!workflow.contains("self-update-rollback:"));
}

#[test]
fn release_publish_is_resume_safe_and_accepts_only_the_current_asset_set() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .unwrap();
    for required in [
        "cancel-in-progress: false",
        "Publish the exact immutable controller asset set",
        "gh release view \"$RELEASE_TAG\"",
        "gh release create \"$RELEASE_TAG\"",
        "gh release upload \"$RELEASE_TAG\"",
        "cmp --silent \"release/$asset\"",
        "asset set is not exactly the current controller set",
    ] {
        assert!(
            workflow.contains(required),
            "workflow lost contract: {required}"
        );
    }
    assert!(!workflow.contains("--clobber"));
}

/// This is deliberately an ignored network test: the release workflow opts
/// into it for the one current supported pair.  It invokes the production
/// `VerifiedRelease::verify` entry point, rather than inferring compatibility
/// from CLI help or an unauthenticated release-identity command.
#[test]
#[ignore = "requires the signed official NazoAuth Release and Sigstore/GitHub attestation services"]
fn compatibility_executes_verified_release_for_the_current_server() {
    fn required(name: &str) -> String {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is required by the compatibility gate"))
    }

    assert_eq!(required("NAZOAUTHCTL_COMPAT_VERIFY_RELEASE"), "1");
    let version = required("EXPECTED_SERVER_RELEASE");
    let oci_index_digest = required("EXPECTED_OCI_INDEX_DIGEST");
    let oci_platform_digest = required("EXPECTED_OCI_PLATFORM_DIGEST");

    for (label, value, prefix, length) in [
        ("OCI index digest", &oci_index_digest, "sha256:", 64),
        ("OCI platform digest", &oci_platform_digest, "sha256:", 64),
    ] {
        let hexadecimal = value.strip_prefix(prefix).unwrap_or("");
        assert!(
            hexadecimal.len() == length
                && hexadecimal
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "{label} must be a lowercase hexadecimal identity"
        );
    }
    let release = crate::release::VerifiedRelease::verify(crate::release::ReleaseRequest {
        repository: crate::instance_lifecycle::SERVER_REPOSITORY,
        requested_version: Some(&version),
        trusted_version_floor: None,
    })
    .expect("the official current server release must pass VerifiedRelease::verify");

    assert_eq!(release.manifest.version, version);
    assert_eq!(
        release
            .manifest
            .runtime_oci_digest_for(crate::model::container_oci_platform())
            .expect("the signed manifest must declare this runtime platform"),
        oci_platform_digest
    );
}
