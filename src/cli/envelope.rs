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
//! * codes come from the CLI set in [`crate::error_codes`] or a target
//!   operation's stable failure vocabulary;
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
        error_codes::TLS_RECOVERY_REQUIRED => {
            "possible; run tls certificate recover for the same deployment, tenant and hostname"
        }
        error_codes::OPERATION_ID_CONFLICT
        | error_codes::CONFIG_REVISION_MISMATCH
        | error_codes::TARGET_IDENTITY_MISMATCH
        | crate::target::INSTALL_OUTCOME_UNKNOWN => {
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
            "ssh <profile> -- nazoauthctl self update; then retry"
        }
        error_codes::PRIVILEGE_REQUIRED => "ssh -t <profile> sudo -v; then retry",
        error_codes::INSTANCE_NOT_REGISTERED => {
            "nazoauthctl instance list; then retry with an exact alias or deployment id"
        }
        error_codes::INSTANCE_AMBIGUOUS => "re-run with --instance <alias>",
        error_codes::STATE_RESET_REQUIRED => "nazoauthctl self verify-state",
        error_codes::CONTROL_BINDING_REQUIRED => {
            "nazoauthctl bind --instance <alias> --label <name>"
        }
        error_codes::CONTROLLER_KEY_UNAUTHORIZED => {
            "nazoauthctl controller list --instance <alias>; then rotate or recover as shown"
        }
        error_codes::CONTROLLER_SLOT_LIMIT => {
            "nazoauthctl controller list --instance <alias>; then revoke one slot"
        }
        error_codes::ADMIN_ACCESS_REQUIRED => {
            "authenticate interactively or provide --credentials-file; then retry"
        }
        error_codes::ADMIN_EMAIL_CONFLICT => "use a different administrator email, then retry",
        error_codes::OPERATION_ID_CONFLICT => {
            "inspect nazoauthctl operation --instance <alias>, then resume with the same command"
        }
        error_codes::CONFIG_REVISION_MISMATCH => {
            "re-read live state via nazoauthctl status --instance <alias>, then rebuild"
        }
        error_codes::TARGET_IDENTITY_MISMATCH => {
            "nazoauthctl verify --instance <alias>, then re-check the artifact source"
        }
        error_codes::INTERNAL_ERROR
        | error_codes::RELEASE_NOT_FOUND
        | error_codes::RELEASE_DOWNLOAD_FAILED
        | crate::target::ARTIFACT_UNVERIFIED => return None,
        _ => return None,
    })
}

/// A localized explanation accompanies the original diagnostic; protocol codes remain stable.
pub(crate) fn chinese_reason(code: &str) -> &'static str {
    match code {
        "INPUT_INVALID" => "参数或输入文件不符合要求。",
        "HOST_NOT_REGISTERED" => "此主机尚未注册。",
        "HOST_UNREACHABLE" => "无法连接目标主机，请检查网络和 SSH 配置。",
        "SSH_AUTH_FAILED" => "SSH 身份验证失败，请检查登录凭据。",
        "SSH_HOST_KEY_FAILED" => "SSH 主机密钥验证失败，请核实主机身份及密钥变更。",
        "REMOTE_HELPER_MISMATCH" => "目标主机上的 ctl 版本或协议不匹配。",
        "PRIVILEGE_REQUIRED" => "当前操作需要目标主机上的管理权限。",
        "INSTANCE_NOT_REGISTERED" => "没有找到所选实例。",
        "INSTANCE_AMBIGUOUS" => "存在多个实例，请使用 --instance 指定一个实例。",
        "STATE_RESET_REQUIRED" => {
            "本地状态无法读取或自动修复，请先运行 nazoauthctl self verify-state 查看具体问题。"
        }
        "CONTROL_BINDING_REQUIRED" => "此实例尚未绑定控制器，请先运行 bind。",
        "CONTROLLER_KEY_UNAUTHORIZED" => "控制器密钥未获授权，可能已到期或被撤销。",
        "CONTROLLER_SLOT_LIMIT" => "控制器授权数量已达到上限，请撤销不再使用的授权。",
        "ADMIN_ACCESS_REQUIRED" => "此操作需要管理员身份验证。",
        "ADMIN_EMAIL_CONFLICT" => "此管理员邮箱已存在，请使用其他邮箱。",
        "OPERATION_ID_CONFLICT" => "操作编号对应的请求内容发生冲突，请先检查操作记录。",
        "CONFIG_REVISION_MISMATCH" => "配置已被其他操作更新，请重新读取实例状态后重试。",
        "TARGET_IDENTITY_MISMATCH" => "目标实例与记录的发布版本不一致，请先验证实例及发布来源。",
        "CONTROL_OPERATION_FAILED" => "服务端操作失败，请根据诊断详情处理后重试。",
        "RELEASE_NOT_FOUND" => "未找到所选版本或当前平台的发布文件。",
        "RELEASE_DOWNLOAD_FAILED" => "发布文件下载失败，请检查网络后重试。",
        "ARTIFACT_UNVERIFIED" => "发布文件验证未通过，请检查文件来源与完整性。",
        "TLS_RECOVERY_REQUIRED" => {
            "证书操作尚未完成，请对同一实例、租户和域名运行 tls certificate recover。"
        }
        "INSTALL_OUTCOME_UNKNOWN" => "尚未确认安装结果，请使用相同参数重新执行以继续原操作。",
        _ => "命令未能完成，具体原因见下方诊断详情。",
    }
}

fn chinese_next(code: &str) -> Option<&'static str> {
    Some(match code {
        "HOST_UNREACHABLE" => "nazoauthctl host check <alias>；连接恢复后重试",
        "SSH_AUTH_FAILED" => "修正 SSH 登录凭据后重试",
        "SSH_HOST_KEY_FAILED" => "核实主机密钥变更后重试",
        "REMOTE_HELPER_MISMATCH" => "在目标主机运行 nazoauthctl self update 后重试",
        "PRIVILEGE_REQUIRED" => "以管理员身份执行；SSH 主机可先运行 ssh -t <profile> sudo -v",
        "INSTANCE_NOT_REGISTERED" => "运行 nazoauthctl instance list，然后使用准确的实例名称",
        "INSTANCE_AMBIGUOUS" => "追加 --instance <alias> 后重试",
        "CONTROLLER_KEY_UNAUTHORIZED" => {
            "运行 nazoauthctl controller list --instance <alias>，检查授权并轮换或恢复密钥"
        }
        "CONTROLLER_SLOT_LIMIT" => {
            "运行 nazoauthctl controller list --instance <alias>，撤销不再使用的授权"
        }
        "ADMIN_ACCESS_REQUIRED" => "在终端登录管理员账户，或使用 --credentials-file 提供凭据",
        "ADMIN_EMAIL_CONFLICT" => "使用其他管理员邮箱后重试",
        "OPERATION_ID_CONFLICT" => {
            "运行 nazoauthctl operation --instance <alias> 检查原操作，再继续原命令"
        }
        "CONFIG_REVISION_MISMATCH" => {
            "运行 nazoauthctl status --instance <alias> 重新读取状态后重试"
        }
        "TARGET_IDENTITY_MISMATCH" => "运行 nazoauthctl verify --instance <alias>，并检查发布来源",
        _ => return next_command(code),
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
        pairs.push((
            "checkpoint",
            if crate::chinese_output() {
                "此部署有待完成的操作记录".to_owned()
            } else {
                checkpoint
            },
        ));
    }
    let side_effects = if crate::chinese_output() {
        match side_effects_hint(&code) {
            "none" => "无",
            _ if code == error_codes::TLS_RECOVERY_REQUIRED => {
                "证书可能已启用；请先恢复待完成的证书操作"
            }
            _ => "此前的尝试可能已产生变更；使用相同命令继续原操作",
        }
    } else {
        side_effects_hint(&code)
    };
    pairs.push(("side_effects", side_effects.to_owned()));
    if crate::chinese_output() {
        pairs.push(("reason", chinese_reason(&code).to_owned()));
    }
    let next = if crate::chinese_output() {
        chinese_next(&code)
    } else {
        next_command(&code)
    };
    pairs.push(("code", code));
    pairs.push(("detail", rendered));
    if let Some(next) = next {
        pairs.push(("next_command", next.to_owned()));
    }
    pairs
        .into_iter()
        .map(|(label, value)| {
            let label = if crate::chinese_output() {
                match label {
                    "action" => "操作",
                    "host" => "主机",
                    "instance" => "实例",
                    "operation_id" => "操作 ID",
                    "checkpoint" => "检查点",
                    "side_effects" => "副作用",
                    "code" => "错误码",
                    "reason" => "原因",
                    "detail" => "诊断详情（原文）",
                    "next_command" => "下一步",
                    _ => label,
                }
            } else {
                label
            };
            let value = if crate::chinese_output() && value == "none" {
                "无".to_owned()
            } else {
                value
            };
            format!("{label}: {value}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;
