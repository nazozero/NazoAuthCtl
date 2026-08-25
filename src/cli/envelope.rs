//! The one error envelope every command failure renders through (goal plan
//! 09 §5, I05).
//!
//! Shape (text = aligned lines, JSON = the same facts as an object):
//!
//! ```text
//! action:         update
//! host:           server-a        (when known)
//! instance:       production      (when known)
//! operation_id:   0197…           (when known)
//! checkpoint:     …               (when known)
//! side_effects:   none | possible; re-running resumes idempotently
//! code:           CONFIG_REVISION_MISMATCH
//! next_command:   nazoauthctl status --instance production
//! ```
//!
//! Rules pinned here:
//!
//! * codes come from the closed set in [`crate::error_codes`] plus the K-phase
//!   marker;
//! * secrets can never appear: only stable tokens and the bounded error chain
//!   are echoed;
//! * `next_command` is always a runnable command or absent — never prose.

use serde_json::json;

use crate::error_codes;

/// Everything the renderer needs beyond the error itself.
#[derive(Debug, Default)]
pub(crate) struct EnvelopeContext {
    pub(crate) host: Option<String>,
    pub(crate) instance: Option<String>,
}

/// Classify side-effect exposure from the stable code. Precondition codes by
/// definition fire BEFORE any effect; conflict/concurrency codes mean a prior
/// attempt may have landed something and resuming (never restarting) is safe.
fn side_effects_hint(code: &str) -> &'static str {
    match code {
        error_codes::OPERATION_ID_CONFLICT
        | error_codes::CONFIG_REVISION_MISMATCH
        | error_codes::TARGET_IDENTITY_MISMATCH => {
            "possible from an earlier attempt; re-run the SAME command to resume idempotently"
        }
        _ => "none",
    }
}

/// The suggested next command per stable code.
fn next_command(code: &str) -> Option<&'static str> {
    Some(match code {
        error_codes::HOST_NOT_REGISTERED => "nazoauthctl host add <alias> --ssh <profile>",
        error_codes::HOST_UNREACHABLE => "nazoauthctl host check <alias>; then retry",
        error_codes::SSH_AUTH_FAILED => "fix the SSH profile credentials, then retry",
        error_codes::SSH_HOST_KEY_FAILED => "verify the host key change yourself, then retry",
        error_codes::REMOTE_HELPER_MISMATCH => {
            "ssh <profile> -- nazoauthctl self update --yes; then retry"
        }
        error_codes::PRIVILEGE_REQUIRED => "ssh -t <profile> sudo -v; then retry",
        error_codes::INSTANCE_NOT_REGISTERED => {
            "nazoauthctl instance list; then retry with an exact alias or deployment id"
        }
        error_codes::INSTANCE_AMBIGUOUS => "re-run with --instance <alias>",
        error_codes::STATE_RESET_REQUIRED => {
            "back up salvageable files, clear the named state, then re-register"
        }
        error_codes::CONTROL_BINDING_REQUIRED => {
            "nazoauthctl bind --instance <alias> --label <name>"
        }
        error_codes::CONTROLLER_KEY_EXPIRED => "nazoauthctl controller rotate --instance <alias>",
        error_codes::CONTROLLER_SLOT_LIMIT => {
            "nazoauthctl controller list --instance <alias>; then revoke one slot"
        }
        error_codes::OPERATION_ID_CONFLICT => {
            "inspect nazoauthctl operation --instance <alias>, then resume with the same command"
        }
        error_codes::CONFIG_REVISION_MISMATCH => {
            "re-read live state via nazoauthctl status --instance <alias>, then rebuild"
        }
        error_codes::TARGET_IDENTITY_MISMATCH => {
            "nazoauthctl verify --instance <alias>, then re-check the artifact source"
        }
        error_codes::EXTERNAL_RESOURCE_PROTECTED => {
            "the resource is external/shared; deletion is refused by design"
        }
        error_codes::NOT_IMPLEMENTED_BEFORE_K_PHASE => {
            "see the message above for what lands in K phase"
        }
        _ => return None,
    })
}

/// Extract a plausible UUIDv7 operation id from the rendered chain without a
/// regex dependency.
fn extract_operation_id(rendered: &str) -> Option<String> {
    let bytes = rendered.as_bytes();
    if bytes.len() < 36 {
        return None;
    }
    for start in 0..=bytes.len() - 36 {
        let window = &bytes[start..start + 36];
        let hyphens_ok =
            window[8] == b'-' && window[13] == b'-' && window[18] == b'-' && window[23] == b'-';
        let hex_ok = window
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit());
        if hyphens_ok && hex_ok && window[14] == b'7' {
            return Some(rendered[start..start + 36].to_owned());
        }
    }
    None
}

/// Build and render the envelope for one failed command.
pub(crate) fn render_failure(
    action: &str,
    context: &EnvelopeContext,
    error: &anyhow::Error,
    json_mode: bool,
) -> String {
    let rendered = format!("{error:#}");
    let code = crate::fleet::fleet_read::stable_code(&rendered);
    let operation_id = extract_operation_id(&rendered);
    let checkpoint = rendered
        .contains("pending")
        .then(|| "a pending journal entry exists for this deployment".to_owned());

    if json_mode {
        return serde_json::to_string_pretty(&json!({
            "schema": 1,
            "success": false,
            "action": action,
            "host": context.host,
            "instance": context.instance,
            "operation_id": operation_id,
            "checkpoint": checkpoint,
            "side_effects": side_effects_hint(&code),
            "code": code,
            "detail": rendered,
            "next_command": next_command(&code),
        }))
        .unwrap_or_else(|_| format!("{{\"code\":\"{code}\"}}"));
    }

    let mut pairs: Vec<(&str, String)> = vec![("action", action.to_owned())];
    if let Some(host) = context.host.as_ref() {
        pairs.push(("host", host.clone()));
    }
    if let Some(instance) = context.instance.as_ref() {
        pairs.push(("instance", instance.clone()));
    }
    if let Some(operation_id) = operation_id {
        pairs.push(("operation_id", operation_id));
    }
    if let Some(checkpoint) = checkpoint {
        pairs.push(("checkpoint", checkpoint));
    }
    pairs.push(("side_effects", side_effects_hint(&code).to_owned()));
    let next = next_command(&code);
    pairs.push(("code", code));
    if let Some(next) = next {
        pairs.push(("next_command", next.to_owned()));
    }
    pairs
        .into_iter()
        .map(|(label, value)| format!("{label}:{:<15}{value}", ""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;
