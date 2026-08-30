use super::*;

fn render(code_line: &str, json_mode: bool) -> String {
    let error = anyhow::anyhow!("{code_line}: something specific happened");
    render_failure(
        "update",
        &EnvelopeContext {
            host: Some("server-a".to_owned()),
            instance: Some("production".to_owned()),
        },
        &error,
        json_mode,
    )
}

#[test]
fn text_envelope_covers_the_stable_codes() {
    for code in [
        crate::error_codes::HOST_NOT_REGISTERED,
        crate::error_codes::HOST_UNREACHABLE,
        crate::error_codes::SSH_AUTH_FAILED,
        crate::error_codes::SSH_HOST_KEY_FAILED,
        crate::error_codes::REMOTE_HELPER_MISMATCH,
        crate::error_codes::PRIVILEGE_REQUIRED,
        "SUDO_PASSWORD_REQUIRED", // mapped onto PRIVILEGE_REQUIRED
        crate::error_codes::INSTANCE_NOT_REGISTERED,
        crate::error_codes::INSTANCE_AMBIGUOUS,
        crate::error_codes::STATE_RESET_REQUIRED,
        crate::error_codes::CONTROL_BINDING_REQUIRED,
        crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED,
        crate::error_codes::CONTROLLER_SLOT_LIMIT,
        crate::error_codes::ADMIN_ACCESS_REQUIRED,
        crate::error_codes::ADMIN_EMAIL_CONFLICT,
        crate::error_codes::OPERATION_ID_CONFLICT,
        crate::error_codes::CONFIG_REVISION_MISMATCH,
        crate::error_codes::TARGET_IDENTITY_MISMATCH,
    ] {
        let rendered = render(code, false);
        assert!(rendered.starts_with("action:"), "{rendered}");
        assert!(rendered.contains("host:"), "{rendered}");
        assert!(rendered.contains("instance:"), "{rendered}");
        assert!(rendered.contains("side_effects:"), "{rendered}");
        assert!(rendered.contains("next_command:"), "{rendered}");
        let expected = if code == "SUDO_PASSWORD_REQUIRED" {
            crate::error_codes::PRIVILEGE_REQUIRED
        } else {
            code
        };
        assert!(
            rendered.lines().any(|line| line.contains(expected)),
            "{code} missing from:\n{rendered}"
        );
    }
}

#[test]
fn invalid_local_input_is_not_reported_as_a_host_failure() {
    let rendered = render(crate::error_codes::INPUT_INVALID, true);
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(value["code"], crate::error_codes::INPUT_INVALID);
    assert_eq!(value["side_effects"], "none");
    assert_eq!(value["next_command"], serde_json::Value::Null);
}

#[test]
fn json_envelope_carries_every_field() {
    for code in [
        crate::error_codes::HOST_UNREACHABLE,
        crate::error_codes::SSH_AUTH_FAILED,
        crate::error_codes::REMOTE_HELPER_MISMATCH,
        crate::error_codes::INSTANCE_AMBIGUOUS,
        crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED,
        crate::error_codes::OPERATION_ID_CONFLICT,
        crate::error_codes::STATE_RESET_REQUIRED,
        crate::error_codes::CONTROL_BINDING_REQUIRED,
        crate::error_codes::CONTROLLER_SLOT_LIMIT,
        crate::error_codes::ADMIN_ACCESS_REQUIRED,
        crate::error_codes::ADMIN_EMAIL_CONFLICT,
        crate::error_codes::CONFIG_REVISION_MISMATCH,
        crate::error_codes::TARGET_IDENTITY_MISMATCH,
    ] {
        let rendered = render(code, true);
        let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        for key in [
            "action",
            "host",
            "instance",
            "operation_id",
            "checkpoint",
            "side_effects",
            "code",
            "detail",
            "next_command",
        ] {
            assert!(value.get(key).is_some(), "{key} absent in {rendered}");
        }
        assert_eq!(value["success"], serde_json::Value::Bool(false));
    }
}

#[test]
fn side_effect_hints_distinguish_conflict_from_precondition() {
    let conflict = render(crate::error_codes::OPERATION_ID_CONFLICT, false);
    assert!(
        conflict.contains("possible from an earlier attempt"),
        "{conflict}"
    );
    let precondition = render(crate::error_codes::INSTANCE_AMBIGUOUS, false);
    let side_effects = precondition
        .lines()
        .find(|line| line.starts_with("side_effects:"))
        .expect("side_effects line");
    assert!(side_effects.contains("none"), "{precondition}");

    let incomplete_install = render(crate::target::INSTALL_OUTCOME_UNKNOWN, false);
    assert!(
        incomplete_install.contains("possible from an earlier attempt"),
        "{incomplete_install}"
    );
}

#[test]
fn operation_ids_are_lifted_out_of_the_chain() {
    let id = "01970000-0000-7000-8000-000000000001";
    let error = anyhow::anyhow!("the migration outcome is unknown; resume operation {id}");
    let rendered = render_failure("update", &EnvelopeContext::default(), &error, true);
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["operation_id"], serde_json::json!(id));

    let without = anyhow::anyhow!("no identifier here at all");
    let rendered = render_failure("update", &EnvelopeContext::default(), &without, true);
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["operation_id"], serde_json::Value::Null);
}

#[test]
fn unknown_failures_fall_back_to_a_conservative_code() {
    let rendered = render("TOTALLY_UNKNOWN_TOKEN", false);
    assert!(
        rendered
            .lines()
            .any(|line| line.contains(crate::error_codes::HOST_UNREACHABLE)),
        "{rendered}"
    );
}

#[test]
fn target_install_failure_keeps_remote_code_and_does_not_suggest_host_check() {
    let detail = "install failed on the target and was rolled back locally: SECRET_PROVISION_FAILED: imported MFA key is not base64url";
    let error = anyhow::anyhow!(detail);
    let rendered = render_failure(
        "install",
        &EnvelopeContext {
            host: Some("hostinger".to_owned()),
            instance: Some("production".to_owned()),
        },
        &error,
        true,
    );
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");

    assert_eq!(value["code"], crate::target::SECRET_PROVISION_FAILED);
    assert_eq!(value["detail"], detail);
    assert_eq!(value["side_effects"], "none");
    assert_eq!(value["next_command"], serde_json::Value::Null);
}
