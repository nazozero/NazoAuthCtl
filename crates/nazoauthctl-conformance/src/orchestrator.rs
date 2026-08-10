use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::browser::{BrowserAutomation, BrowserTargetOrigin, parse_browser_entries_owned};
use crate::client::{DeleteOutcome, ModuleDefinition, SuiteClient};
use crate::matrix::{MatrixError, SelectedMatrix};
use crate::origin::Origin;
use crate::progress::{
    GroupProgress, GroupStatus, ProgressEvent, ProgressSink, ProgressSnapshot, redacted_variant,
};
use crate::report::{
    CleanupFailure, CleanupReport, ConformanceReport, ModuleReport, OrchestrationIntegrity,
    PlanReport,
};

#[derive(Clone)]
pub struct RunControl {
    interrupted: Arc<AtomicBool>,
}

impl Default for RunControl {
    fn default() -> Self {
        Self {
            interrupted: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RunControl {
    pub fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
    }

    pub fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

pub struct ConformanceRunConfig {
    pub client: SuiteClient,
    pub matrix: SelectedMatrix,
    pub target_origin: Option<BrowserTargetOrigin>,
    pub poll_timeout: Duration,
    pub control: RunControl,
    /// Optional bounded Rust-native WebDriver driver.  It is invoked only for
    /// a Suite runner that exposes WAITING plus a URL and only with browser
    /// tasks from that plan's materialized config.
    pub browser: Option<Arc<Mutex<dyn BrowserAutomation>>>,
}

pub struct ConformanceRunner {
    config: ConformanceRunConfig,
}

/// A plan is deliberately kept separate from its public report while the run
/// is in progress. This allows every selected plan to be created and all
/// module definitions enumerated before any module is started, freezing the
/// progress denominator and ensuring later failures can clean up everything
/// already allocated by the Suite.
struct PlannedPlan {
    group_index: usize,
    matrix_plan_id: String,
    suite_plan_id: String,
    variant: BTreeMap<String, String>,
    modules: Vec<ModuleDefinition>,
    config: Value,
    report_index: usize,
}

impl ConformanceRunner {
    pub fn new(config: ConformanceRunConfig) -> Result<Self, OrchestrationError> {
        if config.poll_timeout.is_zero() {
            return Err(OrchestrationError::InvalidInput);
        }
        validate_matrix_origins(
            &config.matrix,
            config.client.origin(),
            config.target_origin.as_ref(),
        )?;
        Ok(Self { config })
    }

    pub fn run<S: ProgressSink>(&self, sink: &mut S) -> RunSummary {
        let mut groups = self
            .config
            .matrix
            .document
            .groups
            .iter()
            .map(|group| GroupProgress {
                id: group.id.clone(),
                profile: group.profile.clone(),
                completed: 0,
                total: 0,
                status: GroupStatus::Remaining,
                passed: 0,
                failed: 0,
                running: 0,
                remaining: 0,
            })
            .collect::<Vec<_>>();
        let mut plans = Vec::new();
        let mut planned = Vec::<PlannedPlan>::new();
        let mut modules = Vec::new();
        let mut cleanup = CleanupReport::default();
        let mut suite_plan_ids = Vec::<String>::new();
        let mut module_ids = Vec::<String>::new();
        let mut errors = Vec::<String>::new();
        let mut auth_probe = None;
        let mut current_profile = None;
        let mut current_variant = None;
        let mut current_test = None;

        match self.config.client.probe_auth() {
            Ok(probe) => auth_probe = Some(probe),
            Err(error) => errors.push(safe_error(&error)),
        }

        // Phase 1: create every selected plan and enumerate its modules. No
        // runner is started in this phase, so total is stable before progress
        // reporting or execution begins.
        if errors.is_empty() {
            'create: for (group_index, group) in
                self.config.matrix.document.groups.iter().enumerate()
            {
                if self.config.control.is_interrupted() {
                    errors.push("run interrupted".to_owned());
                    break;
                }
                current_profile = Some(group.profile.clone());
                for plan in &group.plans {
                    if self.config.control.is_interrupted() {
                        errors.push("run interrupted".to_owned());
                        break 'create;
                    }
                    let variant = group.effective_variant(plan);
                    current_variant = Some(redacted_variant(&variant));
                    current_test = None;
                    let created =
                        match self
                            .config
                            .client
                            .create_plan(&plan.plan, &variant, &plan.config)
                        {
                            Ok(created) => created,
                            Err(error) => {
                                errors.push(safe_error(&error));
                                groups[group_index].status = GroupStatus::Failed;
                                break 'create;
                            }
                        };
                    suite_plan_ids.push(created.id.clone());
                    let defined_modules = created.modules.len();
                    groups[group_index].total += defined_modules;
                    groups[group_index].remaining += defined_modules;
                    plans.push(PlanReport {
                        matrix_plan_id: plan.id.clone(),
                        suite_plan_id: Some(created.id.clone()),
                        plan_name: created.name.clone(),
                        defined_modules,
                        created_instances: 0,
                    });
                    let report_index = plans.len() - 1;
                    planned.push(PlannedPlan {
                        group_index,
                        matrix_plan_id: plan.id.clone(),
                        suite_plan_id: created.id,
                        variant,
                        modules: created.modules,
                        config: plan.config.clone(),
                        report_index,
                    });
                }
            }
        }

        // The denominator is now frozen. A plan-creation failure leaves the
        // successfully created subset visible, but no execution is attempted.
        emit_progress(
            sink,
            &groups,
            current_profile.clone(),
            current_variant.clone(),
            None,
        );

        // Phase 2: create and execute all runner instances. The first failure
        // stops new work while cleanup still covers every allocated resource.
        if errors.is_empty() {
            'execute: for plan in &mut planned {
                let group_index = plan.group_index;
                groups[group_index].status = GroupStatus::Running;
                current_profile = Some(groups[group_index].profile.clone());
                current_variant = Some(redacted_variant(&plan.variant));
                emit_progress(
                    sink,
                    &groups,
                    current_profile.clone(),
                    current_variant.clone(),
                    None,
                );
                for module in &plan.modules {
                    if self.config.control.is_interrupted() {
                        errors.push("run interrupted".to_owned());
                        groups[group_index].status = GroupStatus::Failed;
                        break 'execute;
                    }
                    current_test = Some(module.test_name.clone());
                    emit_progress(
                        sink,
                        &groups,
                        current_profile.clone(),
                        current_variant.clone(),
                        current_test.clone(),
                    );
                    let instance = match self
                        .config
                        .client
                        .create_module(&plan.suite_plan_id, module)
                    {
                        Ok(instance) => instance,
                        Err(error) => {
                            errors.push(safe_error(&error));
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    module_ids.push(instance.id.clone());
                    plans[plan.report_index].created_instances += 1;
                    groups[group_index].running += 1;
                    groups[group_index].remaining = groups[group_index].remaining.saturating_sub(1);
                    emit_progress(
                        sink,
                        &groups,
                        current_profile.clone(),
                        current_variant.clone(),
                        current_test.clone(),
                    );

                    // The Suite's create response normally auto-queues a
                    // runner. Explicit start is only valid for CONFIGURED;
                    // WAITING/RUNNING/terminal states are observed directly.
                    let initial = initial_runner_info(&instance.raw);
                    let initial = match initial {
                        Some(info) => Some(info),
                        None => match self.config.client.module_info(&instance.id) {
                            Ok(info) => Some(info),
                            Err(crate::client::SuiteClientError::HttpStatus(404)) => None,
                            Err(error) => {
                                errors.push(safe_error(&error));
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        },
                    };
                    let mut observed = initial;
                    if observed.as_ref().is_some_and(is_configured) {
                        emit_progress(
                            sink,
                            &groups,
                            current_profile.clone(),
                            current_variant.clone(),
                            current_test.clone(),
                        );
                        if let Err(error) = self.config.client.start_module(&instance.id) {
                            errors.push(safe_error(&error));
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                        observed = None;
                    }

                    if observed.is_none() {
                        observed = match self.config.client.wait_for_state(
                            &instance.id,
                            &["WAITING", "FINISHED", "INTERRUPTED"],
                            self.config.poll_timeout,
                        ) {
                            Ok(state) => Some(state),
                            Err(error) => {
                                errors.push(safe_error(&error));
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                    }

                    if observed.as_ref().is_some_and(is_waiting) {
                        let Some(browser) = &self.config.browser else {
                            errors.push(
                                "Suite runner is WAITING but browser automation is unavailable"
                                    .to_owned(),
                            );
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        };
                        let Some(browser_config) = plan.config.get("browser").cloned() else {
                            errors.push(
                                "Suite runner is WAITING but the Matrix plan has no browser tasks"
                                    .to_owned(),
                            );
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        };
                        let entries = match parse_browser_entries_owned(browser_config) {
                            Ok(entries) => entries,
                            Err(error) => {
                                errors.push(error.to_string());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                        let Some(runner_url) = instance.raw.get("url").and_then(Value::as_str)
                        else {
                            errors.push(
                                "Suite runner is WAITING but did not provide a browser URL"
                                    .to_owned(),
                            );
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        };
                        let runner_url = match Url::parse(runner_url) {
                            Ok(url) => url,
                            Err(_) => {
                                errors.push(
                                    "Suite runner returned an invalid browser URL".to_owned(),
                                );
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                        let mut driver = match browser.lock() {
                            Ok(driver) => driver,
                            Err(_) => {
                                errors.push("browser automation lock failed".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                        if let Err(error) = driver.execute(&runner_url, &entries) {
                            errors.push(error.to_string());
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    }

                    if !observed.as_ref().is_some_and(is_terminal_state)
                        && let Err(error) = self.config.client.wait_for_state(
                            &instance.id,
                            &["FINISHED", "INTERRUPTED"],
                            self.config.poll_timeout,
                        )
                    {
                        errors.push(safe_error(&error));
                        groups[group_index].status = GroupStatus::Failed;
                        break 'execute;
                    }
                    let info = match self.config.client.module_info(&instance.id) {
                        Ok(info) => info,
                        Err(error) => {
                            errors.push(safe_error(&error));
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    let log = match self.config.client.module_log(&instance.id) {
                        Ok(log) => log,
                        Err(error) => {
                            errors.push(safe_error(&error));
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    let terminal = is_terminal(&info);
                    if !terminal {
                        errors.push("Suite module did not reach a terminal status".to_owned());
                        groups[group_index].status = GroupStatus::Failed;
                    }
                    modules.push(ModuleReport::from_info(
                        plan.matrix_plan_id.clone(),
                        plan.suite_plan_id.clone(),
                        Some(instance.id.clone()),
                        module.test_name.clone(),
                        info,
                        log,
                        terminal,
                    ));
                    let module_pass = modules.last().is_some_and(official_module_pass);
                    if terminal {
                        groups[group_index].running = groups[group_index].running.saturating_sub(1);
                        groups[group_index].completed += 1;
                        if module_pass {
                            groups[group_index].passed += 1;
                        } else {
                            groups[group_index].failed += 1;
                        }
                    }
                    if !module_pass {
                        groups[group_index].status = GroupStatus::Failed;
                    }
                    emit_progress(
                        sink,
                        &groups,
                        current_profile.clone(),
                        current_variant.clone(),
                        current_test.clone(),
                    );
                    if !errors.is_empty() {
                        break 'execute;
                    }
                }
                if groups[group_index].status == GroupStatus::Running {
                    groups[group_index].status = GroupStatus::Passed;
                    emit_progress(
                        sink,
                        &groups,
                        current_profile.clone(),
                        current_variant.clone(),
                        None,
                    );
                }
            }
        }

        cleanup_all(
            &self.config.client,
            &module_ids,
            &suite_plan_ids,
            &mut cleanup,
        );
        let defined_modules = plans.iter().map(|plan| plan.defined_modules).sum::<usize>();
        let created_instances = plans
            .iter()
            .map(|plan| plan.created_instances)
            .sum::<usize>();
        let terminal_modules = modules.iter().filter(|module| module.terminal).count();
        let all_modules_instantiated = defined_modules == created_instances;
        let all_modules_terminal = all_modules_instantiated && terminal_modules == defined_modules;
        let cleanup_complete = cleanup.failures.is_empty();
        let suite_pass = all_modules_terminal && modules.iter().all(official_module_pass);
        if !suite_pass && errors.is_empty() {
            errors.push("Suite reported a non-success or incomplete module result".to_owned());
        }
        let orchestration_integrity = OrchestrationIntegrity {
            defined_modules,
            created_instances,
            terminal_modules,
            all_modules_instantiated,
            all_modules_terminal,
            cleanup_complete,
        };
        let local_success = errors.is_empty()
            && suite_pass
            && orchestration_integrity.all_modules_instantiated
            && orchestration_integrity.all_modules_terminal
            && orchestration_integrity.cleanup_complete;
        let snapshot = snapshot(&groups, current_profile, current_variant, current_test);
        let report = ConformanceReport {
            schema: 1,
            matrix_digest: self.config.matrix.digest.clone(),
            suite_origin: self.config.client.origin().to_string(),
            auth_probe,
            errors,
            local_success,
            suite_pass,
            orchestration_integrity,
            progress: snapshot,
            plans,
            modules,
            cleanup,
        };
        RunSummary { report }
    }
}

#[derive(Clone)]
pub struct RunSummary {
    pub report: ConformanceReport,
}

#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error("invalid conformance run input")]
    InvalidInput,
    #[error("matrix validation failed")]
    Matrix(#[from] MatrixError),
}

fn emit_progress(
    sink: &mut impl ProgressSink,
    groups: &[GroupProgress],
    current_profile: Option<String>,
    current_variant: Option<BTreeMap<String, String>>,
    current_test: Option<String>,
) {
    sink.update(&ProgressEvent {
        snapshot: snapshot(groups, current_profile, current_variant, current_test),
    });
}

fn snapshot(
    groups: &[GroupProgress],
    current_profile: Option<String>,
    current_variant: Option<BTreeMap<String, String>>,
    current_test: Option<String>,
) -> ProgressSnapshot {
    ProgressSnapshot {
        completed: groups.iter().map(|group| group.completed).sum(),
        total: groups.iter().map(|group| group.total).sum(),
        groups: groups.to_vec(),
        passed_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Passed)
            .count(),
        failed_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Failed)
            .count(),
        running_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Running)
            .count(),
        remaining_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Remaining)
            .count(),
        passed: groups.iter().map(|group| group.passed).sum(),
        failed: groups.iter().map(|group| group.failed).sum(),
        running: groups.iter().map(|group| group.running).sum(),
        remaining: groups.iter().map(|group| group.remaining).sum(),
        current_profile,
        current_variant,
        current_test,
    }
}

fn cleanup_all(
    client: &SuiteClient,
    module_ids: &[String],
    plan_ids: &[String],
    report: &mut CleanupReport,
) {
    // Cancellation is attempted before every plan deletion. A finalisation
    // race is an expected Suite outcome and is retained in `cancelled`.
    for module_id in module_ids {
        cancel_once(client, module_id, report);
    }
    for plan_id in plan_ids {
        match client.delete_plan(plan_id) {
            Ok(
                crate::client::DeleteOutcome::Deleted | crate::client::DeleteOutcome::AlreadyGone,
            ) => {
                report.deleted_plans.push(plan_id.clone());
            }
            Ok(DeleteOutcome::Immutable) => report.immutable_plans.push(plan_id.clone()),
            Err(first_error) => {
                // The official Suite can race plan finalisation with DELETE;
                // retry once after cancellation before reporting a failure.
                for module_id in module_ids {
                    cancel_once(client, module_id, report);
                }
                match client.delete_plan(plan_id) {
                    Ok(
                        crate::client::DeleteOutcome::Deleted
                        | crate::client::DeleteOutcome::AlreadyGone,
                    ) => {
                        report.deleted_plans.push(plan_id.clone());
                    }
                    Ok(DeleteOutcome::Immutable) => report.immutable_plans.push(plan_id.clone()),
                    Err(retry_error) => report.failures.push(CleanupFailure {
                        operation: "delete-plan".to_owned(),
                        target: plan_id.clone(),
                        error: format!(
                            "{}; retry: {}",
                            safe_error(&first_error),
                            safe_error(&retry_error)
                        ),
                    }),
                }
            }
        }
    }
}

fn cancel_once(client: &SuiteClient, module_id: &str, report: &mut CleanupReport) {
    match client.cancel_module(module_id) {
        Ok(_) => report.cancelled.push(module_id.to_owned()),
        Err(error) => report.failures.push(CleanupFailure {
            operation: "cancel-module".to_owned(),
            target: module_id.to_owned(),
            error: safe_error(&error),
        }),
    }
}

fn safe_error(error: &impl std::fmt::Display) -> String {
    error.to_string()
}

fn initial_runner_info(value: &Value) -> Option<Value> {
    (value.get("status").or_else(|| value.get("state"))).map(|_| value.clone())
}

fn status(value: &Value) -> Option<&str> {
    value
        .get("status")
        .or_else(|| value.get("state"))
        .and_then(Value::as_str)
}

fn is_configured(value: &Value) -> bool {
    status(value) == Some("CONFIGURED")
}

fn is_waiting(value: &Value) -> bool {
    matches!(
        status(value),
        Some("WAITING" | "WAITING_FOR_USER" | "WAITING_FOR_BROWSER")
    )
}

fn is_terminal_state(value: &Value) -> bool {
    matches!(status(value), Some("FINISHED" | "INTERRUPTED"))
}

fn is_terminal(value: &Value) -> bool {
    matches!(
        value.get("status").and_then(Value::as_str),
        Some("FINISHED" | "INTERRUPTED")
    )
}

fn official_module_pass(module: &ModuleReport) -> bool {
    module.terminal
        && module.official_status.as_deref() == Some("FINISHED")
        && module.official_result.as_deref() == Some("PASSED")
}

fn validate_matrix_origins(
    matrix: &SelectedMatrix,
    suite: &Origin,
    target: Option<&BrowserTargetOrigin>,
) -> Result<(), OrchestrationError> {
    for group in &matrix.document.groups {
        for plan in &group.plans {
            validate_value_origins(&plan.config, suite, target, None)
                .map_err(|_| OrchestrationError::InvalidInput)?;
        }
    }
    Ok(())
}

fn validate_value_origins(
    value: &Value,
    suite: &Origin,
    target: Option<&BrowserTargetOrigin>,
    key: Option<&str>,
) -> Result<(), ()> {
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_value_origins(value, suite, target, key)),
        Value::Object(object) => object
            .iter()
            .try_for_each(|(key, value)| validate_value_origins(value, suite, target, Some(key))),
        Value::String(text) if text.starts_with("//") => Err(()),
        Value::String(text) if text.contains("://") => {
            let parsed = Url::parse(text).map_err(|_| ())?;
            let _host = parsed.host_str().ok_or(())?;
            let same_target = target.is_some_and(|origin| same_browser_origin(origin, &parsed));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && same_target) {
                return Err(());
            }
            let same_suite = same_url_origin(suite, &parsed);
            let explicit_external =
                key.is_some_and(|key| matches!(key, "issuer" | "request_object_trust_anchor_uri"));
            if !(same_suite || same_target || explicit_external) {
                return Err(());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn same_browser_origin(origin: &BrowserTargetOrigin, url: &Url) -> bool {
    let expected = origin.as_url();
    expected.scheme() == url.scheme()
        && expected.host_str().map(str::to_ascii_lowercase)
            == url.host_str().map(str::to_ascii_lowercase)
        && expected.port_or_known_default() == url.port_or_known_default()
        && url.username().is_empty()
        && url.password().is_none()
}

fn same_url_origin(origin: &Origin, url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let mut authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    if let Some(port) = url.port()
        && port != 443
    {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    origin.as_str() == format!("https://{authority}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
    use crate::transport::{HttpRequest, HttpResponse, Transport, TransportError};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    struct FixtureTransport {
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl Transport for FixtureTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let path = request.url().path().to_owned();
            let mut requests = self.requests.lock().expect("lock");
            requests.push(request);
            let body = match path.as_str() {
                "/api/plan" if requests.len() == 1 => b"{}".to_vec(),
                "/api/plan" => serde_json::to_vec(
                    &serde_json::json!({"id":"p","name":"plan","modules":[{"testModule":"test"}]}),
                )
                .expect("json"),
                "/api/runner" => serde_json::to_vec(&serde_json::json!({"id":"m"})).expect("json"),
                "/api/runner/m/wait-state" => {
                    serde_json::to_vec(&serde_json::json!({"state":"FINISHED"})).expect("json")
                }
                "/api/info/m" => {
                    serde_json::to_vec(&serde_json::json!({"status":"FINISHED","result":"PASSED"}))
                        .expect("json")
                }
                "/api/log/m" => b"[]".to_vec(),
                "/api/plan/p" => Vec::new(),
                _ => b"{}".to_vec(),
            };
            let status = if path == "/api/plan" && requests.len() == 1 {
                401
            } else if path == "/api/plan/p" {
                204
            } else {
                200
            };
            Ok(HttpResponse {
                status,
                headers: vec![],
                body,
            })
        }
    }

    #[test]
    fn origin_validation_rejects_cross_origin_config() {
        let document = MatrixDocument {
            schema: 1,
            name: "matrix".into(),
            groups: vec![MatrixGroup {
                id: "g".into(),
                profile: "oidc".into(),
                variant: MatrixVariant {
                    id: "v".into(),
                    values: BTreeMap::new(),
                },
                plans: vec![MatrixPlan {
                    id: "p".into(),
                    plan: "plan".into(),
                    config: serde_json::json!({"audience":"https://evil.example"}),
                    variant: BTreeMap::new(),
                }],
            }],
        };
        let selected = SelectedMatrix {
            document,
            digest: "x".into(),
        };
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            None,
            Arc::new(FixtureTransport {
                requests: Mutex::new(Vec::new()),
            }),
            ClientConfig::default(),
        )
        .expect("client");
        assert!(
            ConformanceRunner::new(ConformanceRunConfig {
                client,
                matrix: selected,
                target_origin: None,
                poll_timeout: Duration::from_secs(1),
                control: RunControl::default(),
                browser: None
            })
            .is_err()
        );
    }

    #[test]
    fn official_result_is_not_rewritten_and_non_pass_fails_suite_check() {
        let report = ModuleReport::from_info(
            "p".into(),
            "s".into(),
            Some("m".into()),
            "test".into(),
            serde_json::json!({"status":"FINISHED","result":"FAILED"}),
            serde_json::json!([]),
            true,
        );
        assert_eq!(report.official_result.as_deref(), Some("FAILED"));
        assert!(!official_module_pass(&report));
    }
}
