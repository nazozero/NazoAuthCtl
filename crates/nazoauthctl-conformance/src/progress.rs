use std::io::Write;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Matrix variants are normally short public labels. Still, a malformed or
/// private artifact must not turn a token-like value into terminal output.
pub fn redacted_variant(values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive_key = [
                "token",
                "secret",
                "password",
                "authorization",
                "private",
                "credential",
                "key",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            let safe_value = if sensitive_key
                || value.len() > 256
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                "<redacted>".to_owned()
            } else {
                value.clone()
            };
            (key.clone(), safe_value)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GroupStatus {
    Passed,
    Review,
    Skipped,
    Failed,
    Incomplete,
    Running,
    Remaining,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputLanguage {
    Chinese,
    #[default]
    English,
}

impl OutputLanguage {
    pub fn from_locale(locale: Option<&str>) -> Self {
        let language = locale
            .unwrap_or_default()
            .split(['-', '_', '.', '@', ':'])
            .next()
            .unwrap_or_default();
        if language.eq_ignore_ascii_case("zh") {
            Self::Chinese
        } else {
            Self::English
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressActivity {
    OpeningDeployment,
    LoadingMatrix,
    AuthenticatingSuite,
    PromptingSuiteToken,
    RecoveringPreviousRun,
    PreparingTenant {
        issuer: String,
    },
    CreatingTenant {
        issuer: String,
    },
    CheckingTenant {
        issuer: String,
    },
    ApplyingResources,
    StartingBrowser {
        current: usize,
        total: usize,
    },
    CreatingSuitePlan {
        current: usize,
        total: usize,
        plan: String,
    },
    CreatingSuiteModule {
        test: String,
    },
    WaitingForSuite {
        test: String,
        elapsed_seconds: u64,
    },
    InspectingCibaRequest {
        test: String,
    },
    SubmittingCibaDecision {
        test: String,
        approve: bool,
    },
    CleaningUp,
    WritingEvidence,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupProgress {
    pub id: String,
    pub profile: String,
    pub completed: usize,
    pub total: usize,
    pub status: GroupStatus,
    /// Item-level counters. `completed == passed + reviewed + skipped +
    /// failed + incomplete`; `running` is the currently instantiated Suite module.
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub reviewed: usize,
    #[serde(default)]
    pub skipped: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub incomplete: usize,
    #[serde(default)]
    pub running: usize,
    #[serde(default)]
    pub remaining: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub completed: usize,
    pub total: usize,
    pub groups: Vec<GroupProgress>,
    pub passed_groups: usize,
    pub review_groups: usize,
    pub skipped_groups: usize,
    pub failed_groups: usize,
    pub incomplete_groups: usize,
    pub running_groups: usize,
    pub remaining_groups: usize,
    /// Item-level counters used for the overall progress contract. The
    /// denominator is frozen from the Matrix modules defined during phase 1.
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub reviewed: usize,
    #[serde(default)]
    pub skipped: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub incomplete: usize,
    #[serde(default)]
    pub running: usize,
    #[serde(default)]
    pub remaining: usize,
    /// The currently executing Matrix context. This is deliberately a
    /// summary; Suite configuration and logs are never emitted here.
    pub current_profile: Option<String>,
    pub current_variant: Option<BTreeMap<String, String>>,
    pub current_test: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub snapshot: ProgressSnapshot,
}

pub trait ProgressSink {
    fn update(&mut self, event: &ProgressEvent);

    fn activity(&mut self, _activity: &ProgressActivity) {}
}

impl ProgressSink for () {
    fn update(&mut self, _event: &ProgressEvent) {}
}

pub struct StableRenderer<W: Write> {
    writer: W,
    language: OutputLanguage,
}

impl<W: Write> StableRenderer<W> {
    pub fn new(writer: W) -> Self {
        Self::localized(writer, OutputLanguage::English)
    }

    pub fn localized(writer: W, language: OutputLanguage) -> Self {
        Self { writer, language }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> ProgressSink for StableRenderer<W> {
    fn update(&mut self, event: &ProgressEvent) {
        let labels = labels(self.language);
        let _ = writeln!(
            self.writer,
            "{}: {}/{} ({:>3}%) {} {} · {} {} · {} {} · {} {} · {} {} · {} {} · {} {}{}",
            labels.title,
            event.snapshot.completed,
            event.snapshot.total,
            percent(event.snapshot.completed, event.snapshot.total),
            labels.passed,
            event.snapshot.passed,
            labels.review,
            event.snapshot.reviewed,
            labels.skipped,
            event.snapshot.skipped,
            labels.failed,
            event.snapshot.failed,
            labels.incomplete,
            event.snapshot.incomplete,
            labels.running,
            event.snapshot.running,
            labels.remaining,
            event.snapshot.remaining,
            current_label(&event.snapshot, self.language)
        );
        let _ = self.writer.flush();
    }

    fn activity(&mut self, activity: &ProgressActivity) {
        let _ = writeln!(
            self.writer,
            "{}: {}",
            labels(self.language).status,
            activity_label(activity, self.language)
        );
        let _ = self.writer.flush();
    }
}

struct Labels {
    title: &'static str,
    status: &'static str,
    current: &'static str,
    passed: &'static str,
    review: &'static str,
    skipped: &'static str,
    failed: &'static str,
    incomplete: &'static str,
    running: &'static str,
    remaining: &'static str,
}

fn labels(language: OutputLanguage) -> Labels {
    match language {
        OutputLanguage::Chinese => Labels {
            title: "NazoAuth OIDF 一致性测试",
            status: "状态",
            current: "当前",
            passed: "通过",
            review: "待复核",
            skipped: "跳过",
            failed: "失败",
            incomplete: "未完成",
            running: "运行中",
            remaining: "剩余",
        },
        OutputLanguage::English => Labels {
            title: "NazoAuth OIDF Conformance",
            status: "Status",
            current: "Current",
            passed: "Passed",
            review: "Review",
            skipped: "Skipped",
            failed: "Failed",
            incomplete: "Incomplete",
            running: "Running",
            remaining: "Remaining",
        },
    }
}

pub fn activity_label(activity: &ProgressActivity, language: OutputLanguage) -> String {
    match (language, activity) {
        (OutputLanguage::Chinese, ProgressActivity::OpeningDeployment) => {
            "正在读取实例配置".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::OpeningDeployment) => {
            "Reading instance configuration".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::LoadingMatrix) => {
            "正在加载 OIDF 测试计划".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::LoadingMatrix) => {
            "Loading OIDF test plan".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::AuthenticatingSuite) => {
            "正在连接并认证 OIDF Suite".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::AuthenticatingSuite) => {
            "Connecting to and authenticating with OIDF Suite".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::PromptingSuiteToken) => {
            "等待安全输入 OIDF Suite Token".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::PromptingSuiteToken) => {
            "Waiting for a securely entered OIDF Suite token".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::RecoveringPreviousRun) => {
            "正在检查并恢复上次未完成的运行".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::RecoveringPreviousRun) => {
            "Checking and recovering an unfinished run".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::PreparingTenant { issuer }) => {
            format!("正在准备临时租户 {issuer}")
        }
        (OutputLanguage::English, ProgressActivity::PreparingTenant { issuer }) => {
            format!("Preparing temporary tenant {issuer}")
        }
        (OutputLanguage::Chinese, ProgressActivity::CreatingTenant { issuer }) => {
            format!("正在创建临时租户 {issuer}")
        }
        (OutputLanguage::English, ProgressActivity::CreatingTenant { issuer }) => {
            format!("Creating temporary tenant {issuer}")
        }
        (OutputLanguage::Chinese, ProgressActivity::CheckingTenant { issuer }) => {
            format!("正在检查临时租户公网可达性 {issuer}")
        }
        (OutputLanguage::English, ProgressActivity::CheckingTenant { issuer }) => {
            format!("Checking public reachability for temporary tenant {issuer}")
        }
        (OutputLanguage::Chinese, ProgressActivity::ApplyingResources) => {
            "正在写入租户测试资源".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::ApplyingResources) => {
            "Applying tenant test resources".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::StartingBrowser { current, total }) => {
            format!("正在启动浏览器 {current}/{total}")
        }
        (OutputLanguage::English, ProgressActivity::StartingBrowser { current, total }) => {
            format!("Starting browser {current}/{total}")
        }
        (
            OutputLanguage::Chinese,
            ProgressActivity::CreatingSuitePlan {
                current,
                total,
                plan,
            },
        ) => format!("正在创建 Suite 计划 {current}/{total}: {plan}"),
        (
            OutputLanguage::English,
            ProgressActivity::CreatingSuitePlan {
                current,
                total,
                plan,
            },
        ) => format!("Creating Suite plan {current}/{total}: {plan}"),
        (OutputLanguage::Chinese, ProgressActivity::CreatingSuiteModule { test }) => {
            format!("正在创建测试模块: {test}")
        }
        (OutputLanguage::English, ProgressActivity::CreatingSuiteModule { test }) => {
            format!("Creating test module: {test}")
        }
        (
            OutputLanguage::Chinese,
            ProgressActivity::WaitingForSuite {
                test,
                elapsed_seconds,
            },
        ) => format!("正在等待 Suite: {test}（已等待 {elapsed_seconds} 秒）"),
        (
            OutputLanguage::English,
            ProgressActivity::WaitingForSuite {
                test,
                elapsed_seconds,
            },
        ) => format!("Waiting for Suite: {test} ({elapsed_seconds}s)"),
        (OutputLanguage::Chinese, ProgressActivity::InspectingCibaRequest { test }) => {
            format!("正在读取 CIBA 用户请求: {test}")
        }
        (OutputLanguage::English, ProgressActivity::InspectingCibaRequest { test }) => {
            format!("Reading CIBA user request: {test}")
        }
        (OutputLanguage::Chinese, ProgressActivity::SubmittingCibaDecision { test, approve }) => {
            format!(
                "正在{} CIBA 用户请求: {test}",
                if *approve { "批准" } else { "拒绝" }
            )
        }
        (OutputLanguage::English, ProgressActivity::SubmittingCibaDecision { test, approve }) => {
            format!(
                "{} CIBA user request: {test}",
                if *approve { "Approving" } else { "Rejecting" }
            )
        }
        (OutputLanguage::Chinese, ProgressActivity::CleaningUp) => {
            "正在清理临时租户和未保留的 Suite 资源".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::CleaningUp) => {
            "Cleaning up the temporary tenant and unretained Suite resources".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::WritingEvidence) => {
            "正在写入测试证据".to_owned()
        }
        (OutputLanguage::English, ProgressActivity::WritingEvidence) => {
            "Writing test evidence".to_owned()
        }
        (OutputLanguage::Chinese, ProgressActivity::Finished) => "运行结束".to_owned(),
        (OutputLanguage::English, ProgressActivity::Finished) => "Run finished".to_owned(),
    }
}

fn current_label(snapshot: &ProgressSnapshot, language: OutputLanguage) -> String {
    format!(
        " {}={}/{}",
        labels(language).current,
        current_matrix_label(
            snapshot.current_profile.as_deref(),
            snapshot.current_variant.as_ref()
        ),
        snapshot.current_test.as_deref().unwrap_or("-")
    )
}

pub fn current_matrix_label(
    profile: Option<&str>,
    variant: Option<&BTreeMap<String, String>>,
) -> String {
    let profile = profile.unwrap_or("-");
    let variant = variant
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    if variant.is_empty() {
        profile.to_owned()
    } else {
        format!("{profile}/{variant}")
    }
}

fn percent(completed: usize, total: usize) -> usize {
    completed
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_selects_chinese_only_for_zh() {
        assert_eq!(
            OutputLanguage::from_locale(Some("zh_CN.UTF-8")),
            OutputLanguage::Chinese
        );
        assert_eq!(
            OutputLanguage::from_locale(Some("zh-Hant-TW")),
            OutputLanguage::Chinese
        );
        assert_eq!(
            OutputLanguage::from_locale(Some("en_US.UTF-8")),
            OutputLanguage::English
        );
        assert_eq!(OutputLanguage::from_locale(None), OutputLanguage::English);
    }

    #[test]
    fn chinese_activity_reports_waiting_test_and_elapsed_time() {
        let mut output = Vec::new();
        let mut renderer = StableRenderer::localized(&mut output, OutputLanguage::Chinese);
        renderer.activity(&ProgressActivity::WaitingForSuite {
            test: "fapi-ciba-test".to_owned(),
            elapsed_seconds: 15,
        });
        let text = String::from_utf8(output).expect("utf8");
        assert_eq!(
            text,
            "状态: 正在等待 Suite: fapi-ciba-test（已等待 15 秒）\n"
        );
    }

    #[test]
    fn stable_renderer_has_no_escape_sequences() {
        let mut output = Vec::new();
        let mut renderer = StableRenderer::new(&mut output);
        renderer.update(&ProgressEvent {
            snapshot: ProgressSnapshot {
                completed: 1,
                total: 2,
                groups: vec![],
                passed_groups: 0,
                review_groups: 0,
                skipped_groups: 0,
                failed_groups: 0,
                incomplete_groups: 0,
                running_groups: 0,
                remaining_groups: 0,
                passed: 1,
                reviewed: 0,
                skipped: 0,
                failed: 0,
                incomplete: 0,
                running: 0,
                remaining: 1,
                current_profile: None,
                current_variant: None,
                current_test: None,
            },
        });
        assert!(!String::from_utf8(output).expect("utf8").contains('\u{1b}'));
    }

    #[test]
    fn renderer_includes_current_matrix_context_without_config() {
        let mut output = Vec::new();
        let mut renderer = StableRenderer::new(&mut output);
        let mut variant = BTreeMap::new();
        variant.insert("mode".to_owned(), "plain".to_owned());
        renderer.update(&ProgressEvent {
            snapshot: ProgressSnapshot {
                completed: 0,
                total: 1,
                groups: vec![GroupProgress {
                    id: "g".to_owned(),
                    profile: "oidc".to_owned(),
                    completed: 0,
                    total: 1,
                    status: GroupStatus::Running,
                    passed: 0,
                    reviewed: 0,
                    skipped: 0,
                    failed: 0,
                    incomplete: 0,
                    running: 1,
                    remaining: 0,
                }],
                passed_groups: 0,
                review_groups: 0,
                skipped_groups: 0,
                failed_groups: 0,
                incomplete_groups: 0,
                running_groups: 1,
                remaining_groups: 0,
                passed: 0,
                reviewed: 0,
                skipped: 0,
                failed: 0,
                incomplete: 0,
                running: 1,
                remaining: 0,
                current_profile: Some("oidc".to_owned()),
                current_variant: Some(variant),
                current_test: Some("test".to_owned()),
            },
        });
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("oidc/mode=plain/test"));
        assert!(!text.contains("config"));
    }
}
