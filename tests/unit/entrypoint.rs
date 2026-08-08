use super::*;

#[test]
fn every_public_help_topic_is_complete_without_runtime_state() {
    for (topic, expected) in [
        (cli::HelpTopic::TopLevel, "Commands:"),
        (cli::HelpTopic::Install, "--external-dependencies"),
        (cli::HelpTopic::BootstrapAdmin, "--credentials-stdin"),
        (cli::HelpTopic::Update, "--accept-migration-barrier"),
        (cli::HelpTopic::Keys, "register-external"),
        (cli::HelpTopic::Audit, "audit verify"),
        (cli::HelpTopic::Identity, "identity rotate"),
        (cli::HelpTopic::BreakGlass, "recover-controller"),
    ] {
        let help = help_text(topic);
        assert!(help.starts_with("Usage:") || help.starts_with("nazoauthctl"));
        assert!(help.contains(expected));
    }
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
fn server_compatibility_does_not_expose_github_token_to_pr_controller() {
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

    let current_controller = workflow
        .split_once("\n  current-controller:")
        .unwrap()
        .1
        .split_once("\n  signed-server:")
        .unwrap()
        .0;
    assert!(current_controller.contains("permissions:\n      contents: read"));
    assert!(current_controller.contains("persist-credentials: false"));
    assert!(!current_controller.contains("GH_TOKEN"));

    for (job, next_job) in [
        ("signed-server", "real-backend-discovery"),
        ("real-backend-discovery", "__end__"),
    ] {
        let job_marker = format!("\n  {job}:");
        let section = workflow.split_once(job_marker.as_str()).unwrap().1;
        let section = if next_job == "__end__" {
            section
        } else {
            let next_job_marker = format!("\n  {next_job}:");
            section.split_once(next_job_marker.as_str()).unwrap().0
        };
        assert!(!section.contains("\n    env:\n      GH_TOKEN:"));
    }

    for step in [
        "Select controller artifact",
        "Verify server host identity",
        "Verify the downloaded host server identity",
        "Prove discovery is read-only",
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
fn release_self_update_validation_uses_a_generic_current_previous_transition() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .unwrap();
    for required in [
        "self_update_matrix: ${{ steps.resolve_self_update.outputs.matrix }}",
        "matrix: ${{ fromJSON(needs.policy.outputs.self_update_matrix) }}",
        "CURRENT_RELEASE: ${{ matrix.to_release }}",
        "PREVIOUS_RELEASE: ${{ matrix.from_release }}",
        "gh release download \"$CURRENT_RELEASE\"",
        "self update --to \"$CURRENT_RELEASE\" --yes",
        "self check --to \"$PREVIOUS_RELEASE\"",
    ] {
        assert!(
            workflow.contains(required),
            "workflow lost contract: {required}"
        );
    }
    assert!(!workflow.contains("github.ref_name == 'v0.1.23'"));
    assert!(!workflow.contains("gh release download v0.1.23"));
    assert!(!workflow.contains("self update --to v0.1.23"));
}
