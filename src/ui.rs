//! Shared presentation rules for the command-line boundary.
use std::sync::atomic::{AtomicBool, Ordering};
use unicode_width::UnicodeWidthStr;

static JSON: AtomicBool = AtomicBool::new(false);

pub fn configure(json: bool) {
    JSON.store(json, Ordering::Relaxed);
    cliclack::set_theme(LocalizedTheme);
}

struct DefaultTheme;
impl cliclack::Theme for DefaultTheme {}

struct LocalizedTheme;
impl cliclack::Theme for LocalizedTheme {
    fn format_confirm(&self, state: &cliclack::ThemeState, confirmed: bool) -> String {
        let yes = self.radio_item(state, confirmed, text("Yes", "是"), "");
        let no = self.radio_item(state, !confirmed, text("No", "否"), "");
        let divider = if matches!(state, cliclack::ThemeState::Active) {
            " / "
        } else {
            ""
        };
        format!("│  {yes}{divider}{no}\n")
    }

    fn format_footer_with_message(&self, state: &cliclack::ThemeState, message: &str) -> String {
        if matches!(state, cliclack::ThemeState::Cancel) {
            DefaultTheme.format_footer_with_message(
                &cliclack::ThemeState::Active,
                text("Operation cancelled.", "操作已取消。"),
            )
        } else {
            DefaultTheme.format_footer_with_message(state, message)
        }
    }
}

pub(crate) fn during<T>(
    title: &str,
    action: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use std::io::IsTerminal as _;
    let progress = (!json_mode() && std::io::stderr().is_terminal()).then(cliclack::spinner);
    if let Some(progress) = &progress {
        progress.start(title);
    }
    let result = action();
    if let Some(progress) = progress {
        progress.clear();
    }
    result
}

#[allow(clippy::ptr_arg)] // cliclack's Validate<String> callback receives &String.
pub(crate) fn required_input(value: &String) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(text("Please enter a value.", "请输入内容。").into())
    } else {
        Ok(())
    }
}

pub(crate) fn json_mode() -> bool {
    JSON.load(Ordering::Relaxed)
}

pub fn text<'a>(english: &'a str, chinese: &'a str) -> &'a str {
    if crate::chinese_output() && !json_mode() {
        chinese
    } else {
        english
    }
}

/// Translate at the source; never rewrite runtime values or protocol payloads.
macro_rules! message {
    ($en:literal, $zh:literal $(, $($args:tt)*)?) => {
        if $crate::chinese_output() && !$crate::ui::json_mode() {
            format!($zh $(, $($args)*)?)
        } else {
            format!($en $(, $($args)*)?)
        }
    };
}
pub(crate) use message;

macro_rules! human {
    ($($args:tt)*) => { $crate::ui::print_report(&$crate::ui::message!($($args)*)) };
}
pub(crate) use human;

macro_rules! warning {
    ($($args:tt)*) => { eprintln!("{}", $crate::ui::message!($($args)*)) };
}
pub(crate) use warning;

macro_rules! fail {
    ($($args:tt)*) => { anyhow::bail!("{}", $crate::ui::message!($($args)*)) };
}
pub(crate) use fail;

pub(crate) fn fields(title: &str, values: &[(&str, String)]) -> String {
    let width = values.iter().map(|(key, _)| key.width()).max().unwrap_or(0);
    let mut lines = vec![title.to_owned(), String::new()];
    for (key, value) in values {
        lines.push(format!(
            "{key}{} : {value}",
            " ".repeat(width - key.width())
        ));
    }
    lines.join("\n")
}

pub(crate) fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = std::iter::once(headers.iter().map(|s| (*s).to_owned()).collect())
        .chain(rows.iter().cloned())
        .map(|row: Vec<String>| {
            row.into_iter()
                .map(|s| s.replace(['\r', '\n', '\t'], " "))
                .collect()
        })
        .collect();
    let widths: Vec<usize> = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row.get(column).map_or(0, |s| s.width()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        lines.push(
            widths
                .iter()
                .enumerate()
                .map(|(column, width)| {
                    let value = row.get(column).map_or("", String::as_str);
                    format!("{value}{}", " ".repeat(width - value.width()))
                })
                .collect::<Vec<_>>()
                .join(" | ")
                .trim_end()
                .to_owned(),
        );
        if index == 0 {
            lines.push(
                widths
                    .iter()
                    .map(|w| "-".repeat(*w))
                    .collect::<Vec<_>>()
                    .join("-+-"),
            );
        }
    }
    if rows.len() == 1 {
        lines.push(text("No records.", "暂无记录。").to_owned());
    }
    lines.join("\n")
}

pub(crate) fn print_report(report: &str) {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(report) {
        print_value(&value);
        return;
    }
    if json_mode() {
        println!("{}", serde_json::json!({"schema":1,"message":report}));
    } else {
        println!("{report}");
    }
}

pub(crate) fn label(key: &str) -> String {
    let chinese = match key {
        "schema" => "格式版本",
        "alias" | "name" => "名称",
        "deployment_id" => "部署编号",
        "host" => "主机",
        "id" => "编号",
        "transport" => "连接方式",
        "issuer" => "服务地址",
        "version" => "版本",
        "installed" => "已安装版本",
        "candidate" => "候选版本",
        "compatible" => "状态兼容",
        "deployments" => "部署数量",
        "repository" => "发布仓库",
        "controller_id" => "控制器编号",
        "controller_key_ref" => "控制器密钥引用",
        "oidf_tenant_domain" => "OIDF 租户域名",
        "oidf_suite_origin" => "OIDF 测试服务",
        "observation" => "最近检查",
        "observed_at" | "checked_at" => "检查时间",
        "reachable" => "可以连接",
        "marker" | "status" | "state" => "状态",
        "summary" => "说明",
        "hostname" | "domain" => "域名",
        "tenant_id" => "租户编号",
        "tenant" => "租户",
        "provider" => "提供器",
        "certificate" => "证书",
        "certificate_path" => "证书路径",
        "private_key_path" => "私钥路径",
        "chain_path" => "证书链路径",
        "path" => "路径",
        "not_before" => "生效时间",
        "not_after" | "expires_at" => "到期时间",
        "created_at" => "创建时间",
        "updated_at" => "更新时间",
        "verified_at" => "验证时间",
        "generation" => "证书代次",
        "previous_generation" => "上一代次",
        "active_generation" => "当前代次",
        "phase" => "阶段",
        "action" => "操作",
        "success" => "成功",
        "ready" => "就绪",
        "readiness" => "就绪检查",
        "detail" => "详情",
        "error" => "错误",
        "code" => "错误码",
        "reason" => "原因",
        "message" => "结果",
        "warnings" => "注意事项",
        "errors" => "错误",
        "next" | "next_command" => "下一步",
        "operation_id" => "操作编号",
        "transaction_id" => "事务编号",
        "source" => "来源",
        "destination" => "目标",
        "current" => "当前",
        "previous" => "上一版本",
        "renewal" => "续期",
        "renew_before_seconds" => "提前续期秒数",
        "directory_url" => "ACME 服务地址",
        "account" => "账户",
        "account_url" => "账户地址",
        "email" => "邮箱",
        "contact" => "联系方式",
        "challenge" => "域名验证",
        "challenge_type" => "验证方式",
        "order_url" => "订单地址",
        "identifiers" => "域名",
        "dns_names" | "sans" => "证书域名",
        "serial_number" => "证书序列号",
        "subject" => "证书主体",
        "algorithm" => "算法",
        "key_type" => "密钥类型",
        "revision" => "配置修订",
        "runtime" => "运行环境",
        "health" => "健康",
        "snapshot_id" => "快照编号",
        "backup" => "备份",
        "restore_tested_at" => "恢复验证时间",
        "isolated_database" => "隔离测试数据库",
        "restored_at" => "恢复时间",
        "receipt" => "执行回执",
        "command" => "命令",
        "total" => "总数",
        "failed" => "失败数",
        "results" => "结果",
        "instance" => "实例",
        "configured" => "配置已保存",
        "tenant_domain" => "租户域名",
        "suite_origin" => "测试服务地址",
        "artifact" => "制品",
        "opened" => "已打开并验证",
        "resolved" => "下载验证完成",
        "verified" => "验证通过",
        "cache" => "缓存",
        "resolution" => "下载结果",
        "artifact_id" => "制品编号",
        "signer_identity" => "签名者",
        "signer_key_id" => "签名密钥编号",
        "suite" => "测试服务",
        "origin" => "地址",
        "release" => "发布版本",
        "engine_protocol" => "执行协议版本",
        "required_capabilities" => "所需能力",
        "driver_schema" => "驱动格式版本",
        "driver_size" => "驱动大小（字节）",
        "driver_manifest_size" => "发布清单大小（字节）",
        "driver_handlers" => "驱动处理器数量",
        "matrix_size" => "矩阵大小（字节）",
        "matrix_groups" => "矩阵分组数",
        "matrix_plans" => "矩阵计划数",
        "matrix_modules" => "矩阵模块数",
        "matrix_clients" => "矩阵客户端数",
        "matrix_wall_clock_seconds" => "矩阵最长耗时（秒）",
        "resource_bounds" => "资源上限",
        "max_plans" => "最多计划数",
        "max_modules" => "最多模块数",
        "max_clients" => "最多客户端数",
        "max_wall_clock_seconds" => "最长耗时（秒）",
        "manifest_url" => "发布清单地址",
        "cache_entry" => "缓存路径",
        "artifact_cache_entry" => "制品缓存路径",
        "plan_jti" => "计划编号",
        "planned_at" => "计划生成时间",
        "caller_declared_capabilities" => "调用方声明的能力",
        "selection" => "选择范围",
        "selected_group_count" => "选中分组数",
        "selected_plan_count" => "选中计划数",
        "selected_resource_budget" => "预计资源用量",
        "latest_execution_start_at" => "最晚开始时间",
        "runner" => "执行约束",
        "plans" => "测试计划",
        "groups" => "分组",
        "excluded_plans" => "排除计划",
        "modules" => "模块数",
        "clients" => "客户端数",
        "wall_clock_seconds" => "耗时（秒）",
        "minimum_jobs" => "最少并行任务数",
        "maximum_jobs" => "最多并行任务数",
        "independent_plan_tasks_required" => "每个计划独立执行",
        "independent_evidence_required" => "独立保存证据",
        "failure_collection_required" => "收集失败结果",
        "finally_cleanup_required" => "最终执行清理",
        "task_jti" => "任务编号",
        "group_id" => "分组编号",
        "profile" => "协议规范",
        "group_variant_id" => "分组变体编号",
        "group_variant_values" => "分组变体参数",
        "plan_id" => "计划编号",
        "suite_plan_name" => "测试服务计划名称",
        "driver_handler" => "驱动处理器",
        "resource_budget" => "预计资源用量",
        "plan_variant_values" => "计划变体参数",
        "config_template" => "配置模板（原始字段）",
        "expected_skipped_modules" => "预期跳过的模块",
        "jti" => "事务编号",
        "check_jti" => "检查编号",
        "receipt_jti" => "回执编号",
        "declaration_revision" => "部署声明修订",
        "provider_protocol" => "证书管理协议",
        "acme_protocol" => "ACME 管理协议",
        "certificate_not_after" => "证书到期时间",
        "current_revision" => "当前修订",
        "target_revision" => "目标修订",
        "expected_revision" => "预期修订",
        "transaction_expires_at" => "事务到期时间",
        "transaction_created_at" => "事务创建时间",
        "evidence_expires_at" => "检查结果到期时间",
        "receipt_revision" => "回执修订",
        "renewal_required_at" => "应续期时间",
        "seconds_remaining" => "剩余秒数",
        "warning_window_seconds" => "到期提醒窗口（秒）",
        "public_url" => "公网地址",
        "active_generation_verified" => "当前证书验证通过",
        "source_authority_current" => "来源仍有效",
        "public_endpoint_verified" => "公网验证通过",
        "steps" => "执行步骤",
        "kind" => "类型",
        "issued_at" => "签发时间",
        "issuance_jti" => "签发编号",
        "issuance_revision" => "签发修订",
        "issuance_declaration_revision" => "签发时的部署修订",
        "allowed_origins" => "允许的服务地址",
        "terms_of_service_url" => "服务条款地址",
        "challenge_webroot" => "域名验证目录",
        "account_path" => "账户文件路径",
        "workspace" => "工作目录",
        "account_id" => "账户编号",
        "pending" => "待完成事务",
        "last_error" => "最近诊断详情（原文）",
        "challenge_path" => "域名验证文件",
        "activation_link" => "当前证书链接",
        "material_root" => "证书存储目录",
        "reader_gid" => "读取权限组编号",
        "native_proxy_program" => "代理程序",
        "trust_anchors" => "信任证书路径",
        "accepted_statuses" => "接受的 HTTP 状态码",
        "minimum_validity_seconds" => "最短剩余有效期（秒）",
        "connect_timeout_seconds" => "连接超时（秒）",
        "request_timeout_seconds" => "请求超时（秒）",
        "validate" => "配置检查",
        "reload" => "重新加载",
        "program" => "程序",
        "args" => "参数",
        "protocol" => "协议",
        "committed_at" => "提交时间",
        "activated_at" => "启用时间",
        "reloaded_at" => "重新加载时间",
        "backup_before_update" => "更新前备份策略",
        "max_age_seconds" => "最长备份间隔（秒）",
        "host_id" => "主机编号",
        "directory" => "目录",
        "platform" => "平台",
        _ => return key.replace('_', " "),
    };
    text(&key.replace('_', " "), chinese).to_owned()
}

pub(crate) fn render_value(value: &serde_json::Value) -> String {
    fn append(value: &serde_json::Value, depth: usize, key_context: &str, lines: &mut Vec<String>) {
        let indent = "  ".repeat(depth);
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if key == "schema"
                        || key.contains("sha256")
                        || key.ends_with("_digest")
                        || key == "trust_anchors_pem"
                        || (key == "artifact" && value.is_string())
                    {
                        continue;
                    }
                    let name = label(key);
                    if value.is_object() || value.is_array() {
                        lines.push(format!("{indent}{name}:"));
                        append(value, depth + 1, key, lines);
                    } else {
                        lines.push(format!("{indent}{name}: {}", scalar(value, key)));
                    }
                }
            }
            serde_json::Value::Array(items) => {
                if items.is_empty() {
                    lines.push(format!("{indent}{}", text("None", "无")));
                }
                for item in items {
                    append(item, depth, key_context, lines);
                    lines.push(String::new());
                }
            }
            _ => lines.push(format!("{indent}{}", scalar(value, key_context))),
        }
    }
    fn scalar(value: &serde_json::Value, key: &str) -> String {
        match value {
            serde_json::Value::Null => text("Not set", "未设置").to_owned(),
            serde_json::Value::Bool(v) => if *v {
                text("Yes", "是")
            } else {
                text("No", "否")
            }
            .to_owned(),
            serde_json::Value::String(s)
                if matches!(
                    key,
                    "status"
                        | "state"
                        | "health"
                        | "phase"
                        | "kind"
                        | "marker"
                        | "transport"
                        | "steps"
                ) =>
            {
                match s.as_str() {
                    "ok" | "passed" | "healthy" => text("Healthy", "正常").to_owned(),
                    "failed" | "failure" | "down" => text("Failed", "失败").to_owned(),
                    "pending" => text("Pending", "待完成").to_owned(),
                    "completed" | "succeeded" => text("Completed", "已完成").to_owned(),
                    "local" => text("Local", "本机").to_owned(),
                    "unknown" => text("Unknown", "未知").to_owned(),
                    "prepared" => text("prepared", "已准备").to_owned(),
                    "staged" => text("staged", "已暂存").to_owned(),
                    "activating" => text("activating", "正在启用").to_owned(),
                    "activated" => text("activated", "已启用").to_owned(),
                    "reloaded" => text("reloaded", "已重新加载").to_owned(),
                    "verified" => text("verified", "已验证").to_owned(),
                    "rollback_failed" => text("rollback failed", "回滚失败").to_owned(),
                    "rolled_back" => text("rolled back", "已回滚").to_owned(),
                    "committed" => text("committed", "已提交").to_owned(),
                    "account_ready" => text("account ready", "账户已就绪").to_owned(),
                    "order_created" => text("order created", "订单已创建").to_owned(),
                    "challenge_published" => {
                        text("challenge published", "域名验证已发布").to_owned()
                    }
                    "challenge_ready" => text("challenge ready", "域名验证已就绪").to_owned(),
                    "csr_ready" => text("csr ready", "证书申请已就绪").to_owned(),
                    "finalized" => text("finalized", "申请已提交").to_owned(),
                    "issued" => text("issued", "已签发").to_owned(),
                    "external_files" => text("external files", "外部证书文件").to_owned(),
                    "acme_receipt" => text("acme receipt", "ACME 签发记录").to_owned(),
                    "active" => text("active", "有效").to_owned(),
                    "revoked" => text("revoked", "已撤销").to_owned(),
                    "expired" => text("expired", "已过期").to_owned(),
                    "offline-chain-san-key-expiry-usage-validation" => text(
                        "offline chain san key expiry usage validation",
                        "离线检查证书链、域名、密钥、有效期与用途",
                    )
                    .to_owned(),
                    "unique-generation-write-fsync" => text(
                        "unique generation write fsync",
                        "保存候选证书并完成磁盘写入",
                    )
                    .to_owned(),
                    "candidate-provider-validation" => {
                        text("candidate provider validation", "检查候选证书配置").to_owned()
                    }
                    "atomic-current-pointer-replace" => {
                        text("atomic current pointer replace", "原子切换当前证书").to_owned()
                    }
                    "provider-reload" => text("provider reload", "重新加载证书").to_owned(),
                    "public-tls-identity-and-health-verification" => text(
                        "public tls identity and health verification",
                        "验证公网证书与健康状态",
                    )
                    .to_owned(),
                    "receipt-commit-or-rollback" => {
                        text("receipt commit or rollback", "成功后保存回执，失败则回滚").to_owned()
                    }
                    "persist-config-and-transaction" => {
                        text("persist config and transaction", "保存配置与操作记录").to_owned()
                    }
                    "create-or-restore-bound-account" => {
                        text("create or restore bound account", "创建或恢复 ACME 账户").to_owned()
                    }
                    "create-or-resume-exact-identifier-order" => text(
                        "create or resume exact identifier order",
                        "创建或继续此域名的证书订单",
                    )
                    .to_owned(),
                    "publish-http-01-challenge" => {
                        text("publish http 01 challenge", "发布 HTTP-01 域名验证文件").to_owned()
                    }
                    "poll-authorization" => {
                        text("poll authorization", "等待域名验证结果").to_owned()
                    }
                    "persist-key-and-csr" => {
                        text("persist key and csr", "保存密钥与证书申请").to_owned()
                    }
                    "finalize-order" => text("finalize order", "提交证书申请").to_owned(),
                    "validate-chain-san-key-expiry-usage" => {
                        text("validate chain san key expiry usage", "验证签发证书").to_owned()
                    }
                    "commit-receipt-and-retire-challenge" => text(
                        "commit receipt and retire challenge",
                        "保存签发回执并清理验证文件",
                    )
                    .to_owned(),
                    _ => s.clone(),
                }
            }
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n)
                if key.ends_with("_at")
                    || matches!(key, "not_before" | "not_after" | "certificate_not_after") =>
            {
                n.as_i64()
                    .and_then(|n| chrono::DateTime::from_timestamp(n, 0))
                    .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| n.to_string())
            }
            _ => value.to_string(),
        }
    }
    let mut lines = Vec::new();
    append(value, 0, "", &mut lines);
    lines.join("\n").trim_end().to_owned()
}

pub fn print_value(value: &serde_json::Value) {
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("JSON value")
        );
    } else {
        println!("{}", render_value(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_omits_digests_but_preserves_identity_objects_and_user_values() {
        let value = serde_json::json!({
            "artifact": {"artifact_id": "healthy", "sha256": "hidden-digest", "version": "v1"},
            "alias": "local",
            "created_at": 0,
        });
        let rendered = render_value(&value);
        assert!(rendered.contains("healthy") && rendered.contains("local"));
        assert!(rendered.contains("v1"));
        assert!(rendered.contains("1970-01-01 00:00:00 UTC"));
        assert!(!rendered.contains("hidden-digest"));
        assert_eq!(value["artifact"]["sha256"], "hidden-digest");
    }

    #[test]
    fn tables_align_wide_characters_and_keep_cells_on_one_line() {
        let table = table(
            &["实例", "Host"],
            &[vec!["生产\n环境".into(), "local".into()]],
        );
        let lines: Vec<_> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0].split('|').next().unwrap().width(),
            lines[2].split('|').next().unwrap().width()
        );
        assert!(table.contains("生产 环境"));
    }
}
