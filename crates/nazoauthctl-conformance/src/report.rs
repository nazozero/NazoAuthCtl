use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

use crate::client::AuthProbe;
use crate::progress::ProgressSnapshot;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupFailure {
    pub operation: String,
    pub target: String,
    pub error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CleanupReport {
    pub cancelled: Vec<String>,
    pub deleted_plans: Vec<String>,
    /// Plans which the Suite owns immutably. This is an explicit outcome, not
    /// an orchestration failure: the client cannot delete what the Suite
    /// deliberately retains.
    pub immutable_plans: Vec<String>,
    pub failures: Vec<CleanupFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanReport {
    pub matrix_plan_id: String,
    pub suite_plan_id: Option<String>,
    pub plan_name: String,
    pub defined_modules: usize,
    pub created_instances: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ModuleReport {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: Option<String>,
    pub test_name: String,
    pub terminal: bool,
    /// The suite's status is preserved verbatim; it is not mapped to a local
    /// pass/fail result.
    pub official_status: Option<String>,
    /// The Suite's result is preserved verbatim and evaluated separately by
    /// the explicit outcome fields below.
    pub official_result: Option<String>,
    /// The signed Matrix exception applying to this exact module, if any.
    pub expected_result: Option<String>,
    /// Controller classification derived from the official status/result and
    /// raw condition log. Only `PASSED` contributes to an overall Suite pass.
    pub outcome: ModuleOutcome,
    /// `REVIEW`, `WARNING`, and a `PASSED` result with a warning log require
    /// human follow-up. `SKIPPED` remains a separate outcome.
    pub human_review_required: bool,
    /// Blocking FAILURE condition results found in the raw Suite log.
    pub blocking_log_results: Vec<String>,
    /// Non-blocking WARNING condition results found in the raw Suite log.
    pub advisory_log_results: Vec<String>,
    /// Public evidence omits config/owner/secret-bearing fields. The complete
    /// objects are retained in the in-memory fields below for evidence sinks.
    pub info: Value,
    pub log: Value,
    #[serde(skip)]
    pub raw_info: Value,
    #[serde(skip)]
    pub raw_log: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleOutcome {
    Passed,
    Review,
    Skipped,
    Failed,
    Incomplete,
}

pub(crate) struct ModuleReportContext {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: Option<String>,
    pub test_name: String,
    pub terminal: bool,
    pub expected_result: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestrationIntegrity {
    pub defined_modules: usize,
    pub created_instances: usize,
    pub terminal_modules: usize,
    pub all_modules_instantiated: bool,
    pub all_modules_terminal: bool,
    pub cleanup_complete: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub schema: u32,
    pub matrix_digest: String,
    pub suite_origin: String,
    pub auth_probe: Option<AuthProbe>,
    /// Local orchestration errors. Official Suite outcomes are represented by
    /// the outcome fields instead of synthetic error strings.
    pub errors: Vec<String>,
    /// Local orchestration, evidence collection, and cleanup completed. This
    /// does not claim that the Suite passed.
    pub local_success: bool,
    /// True only when at least one module was defined and every defined module
    /// reached the Suite's exact `FINISHED` / `PASSED` outcome without warning
    /// or failure conditions.
    pub suite_pass: bool,
    /// True when one or more modules returned REVIEW/WARNING or
    /// emitted a WARNING condition. These modules remain listed in `modules`
    /// and require explicit human follow-up.
    pub human_review_required: bool,
    /// Exact `matrix_plan_id/test_name` entries requiring human review.
    pub human_review_modules: Vec<String>,
    /// Exact entries that the Suite classified as `SKIPPED`. An expected skip
    /// remains skipped and never contributes to `suite_pass`.
    pub skipped_modules: Vec<String>,
    /// Exact entries with an explicit failed/unknown result or a blocking log.
    pub failed_modules: Vec<String>,
    /// Exact entries that never reached the Suite's `FINISHED` state.
    pub incomplete_modules: Vec<String>,
    pub orchestration_integrity: OrchestrationIntegrity,
    pub progress: ProgressSnapshot,
    pub plans: Vec<PlanReport>,
    pub modules: Vec<ModuleReport>,
    pub cleanup: CleanupReport,
}

impl ConformanceReport {
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }
}

impl ModuleReport {
    pub(crate) fn from_info(context: ModuleReportContext, raw_info: Value, raw_log: Value) -> Self {
        let official_status = raw_info
            .get("status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let official_result = raw_info
            .get("result")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut blocking_log_results = BTreeSet::new();
        let mut advisory_log_results = BTreeSet::new();
        collect_condition_log_results(
            &raw_log,
            &mut blocking_log_results,
            &mut advisory_log_results,
        );
        let blocking_log_results = blocking_log_results.into_iter().collect::<Vec<_>>();
        let advisory_log_results = advisory_log_results.into_iter().collect::<Vec<_>>();
        let outcome = if !context.terminal || official_status.as_deref() != Some("FINISHED") {
            ModuleOutcome::Incomplete
        } else if !blocking_log_results.is_empty() {
            ModuleOutcome::Failed
        } else {
            match official_result.as_deref() {
                Some("PASSED") if advisory_log_results.is_empty() => ModuleOutcome::Passed,
                Some("PASSED" | "REVIEW" | "WARNING") => ModuleOutcome::Review,
                Some("SKIPPED") => ModuleOutcome::Skipped,
                _ => ModuleOutcome::Failed,
            }
        };
        let human_review_required = outcome == ModuleOutcome::Review
            || (outcome == ModuleOutcome::Skipped && !advisory_log_results.is_empty());
        Self {
            matrix_plan_id: context.matrix_plan_id,
            suite_plan_id: context.suite_plan_id,
            module_id: context.module_id,
            test_name: context.test_name,
            terminal: context.terminal,
            official_status,
            official_result,
            expected_result: context.expected_result,
            outcome,
            human_review_required,
            blocking_log_results,
            advisory_log_results,
            info: public_info_summary(&raw_info),
            log: public_log_summary(&raw_log),
            raw_info,
            raw_log,
        }
    }
}

impl Drop for ModuleReport {
    fn drop(&mut self) {
        crate::matrix::zeroize_json_value(&mut self.raw_info);
        crate::matrix::zeroize_json_value(&mut self.raw_log);
    }
}

pub(crate) struct ModuleOutcomeSummary {
    pub all_passed: bool,
    pub human_review_modules: Vec<String>,
    pub skipped_modules: Vec<String>,
    pub failed_modules: Vec<String>,
    pub incomplete_modules: Vec<String>,
}

pub(crate) fn summarize_module_outcomes(modules: &[ModuleReport]) -> ModuleOutcomeSummary {
    let mut summary = ModuleOutcomeSummary {
        all_passed: !modules.is_empty(),
        human_review_modules: Vec::new(),
        skipped_modules: Vec::new(),
        failed_modules: Vec::new(),
        incomplete_modules: Vec::new(),
    };
    for module in modules {
        let identity = format!("{}/{}", module.matrix_plan_id, module.test_name);
        if module.human_review_required {
            summary.human_review_modules.push(identity.clone());
        }
        match module.outcome {
            ModuleOutcome::Passed => {}
            ModuleOutcome::Review => {
                summary.all_passed = false;
            }
            ModuleOutcome::Skipped => {
                summary.all_passed = false;
                summary.skipped_modules.push(identity);
            }
            ModuleOutcome::Failed => {
                summary.all_passed = false;
                summary.failed_modules.push(identity);
            }
            ModuleOutcome::Incomplete => {
                summary.all_passed = false;
                summary.incomplete_modules.push(identity);
            }
        }
    }
    summary
}

fn collect_condition_log_results(
    value: &Value,
    blocking: &mut BTreeSet<String>,
    advisory: &mut BTreeSet<String>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_condition_log_results(value, blocking, advisory);
            }
        }
        Value::Object(values) => {
            if let Some(result) = values.get("result").and_then(Value::as_str) {
                match result {
                    "FAILURE" => {
                        blocking.insert(result.to_owned());
                    }
                    "WARNING" => {
                        advisory.insert(result.to_owned());
                    }
                    _ => {}
                }
            }
            for value in values.values() {
                collect_condition_log_results(value, blocking, advisory);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn public_info_summary(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return Value::Object(Map::new());
    };
    // Keep only Suite lifecycle fields. In particular, config, owner, and
    // arbitrary extension fields are not copied into stdout/report JSON.
    let allowed = ["id", "name", "status", "result"];
    let mut output = Map::new();
    for key in allowed {
        if let Some(value) = object.get(key) {
            output.insert(key.to_owned(), public_scalar(value));
        }
    }
    Value::Object(output)
}

fn public_log_summary(value: &Value) -> Value {
    serde_json::json!({
        "entries": value.as_array().map_or(0, |values| values.len()),
        "present": !value.is_null(),
    })
}

fn public_scalar(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(text) => {
            // Lifecycle error text may be useful, but long opaque strings are
            // more likely to be tokens/assertions than operator diagnostics.
            if text.len() > 256 {
                Value::String("<redacted>".to_owned())
            } else {
                Value::String(text.clone())
            }
        }
        Value::Array(_) | Value::Object(_) => Value::String("<redacted>".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(
        test_name: &str,
        terminal: bool,
        status: &str,
        result: &str,
        log: Value,
    ) -> ModuleReport {
        ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some(format!("m-{test_name}")),
                test_name: test_name.into(),
                terminal,
                expected_result: None,
            },
            serde_json::json!({"status":status,"result":result}),
            log,
        )
    }

    #[test]
    fn public_report_redacts_config_and_secret_fields() {
        let raw = serde_json::json!({"status":"FINISHED","result":"PASSED","config":{"client_secret":"abc"},"token":"abc"});
        let log = serde_json::json!([{"message":"secret-value","token":"secret-token"}]);
        let report = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m".into()),
                test_name: "test".into(),
                terminal: true,
                expected_result: None,
            },
            raw,
            log,
        );
        let encoded = serde_json::to_string(&report).expect("report");
        assert!(!encoded.contains("client_secret"));
        assert!(!encoded.contains("abc"));
        assert!(!encoded.contains("secret-value"));
        assert_eq!(report.official_result.as_deref(), Some("PASSED"));
    }

    #[test]
    fn outcome_summary_never_promotes_review_skipped_or_incomplete_to_passed() {
        let modules = vec![
            module("passed", true, "FINISHED", "PASSED", serde_json::json!([])),
            module("review", true, "FINISHED", "REVIEW", serde_json::json!([])),
            module(
                "skipped",
                true,
                "FINISHED",
                "SKIPPED",
                serde_json::json!([]),
            ),
            module(
                "skipped-warning",
                true,
                "FINISHED",
                "SKIPPED",
                serde_json::json!([{"result":"WARNING"}]),
            ),
            module("failed", true, "FINISHED", "FAILED", serde_json::json!([])),
            module(
                "incomplete",
                true,
                "INTERRUPTED",
                "PASSED",
                serde_json::json!([]),
            ),
        ];
        let summary = summarize_module_outcomes(&modules);

        assert!(!summary.all_passed);
        assert_eq!(
            summary.human_review_modules,
            ["p/review", "p/skipped-warning"]
        );
        assert_eq!(summary.skipped_modules, ["p/skipped", "p/skipped-warning"]);
        assert_eq!(summary.failed_modules, ["p/failed"]);
        assert_eq!(summary.incomplete_modules, ["p/incomplete"]);
    }

    #[test]
    fn passed_with_warning_is_review_and_empty_run_is_not_a_suite_pass() {
        let warning = module(
            "warning",
            true,
            "FINISHED",
            "PASSED",
            serde_json::json!([{"result":"WARNING"}]),
        );
        assert_eq!(warning.outcome, ModuleOutcome::Review);
        assert!(warning.human_review_required);
        assert!(!summarize_module_outcomes(&[]).all_passed);
        assert!(
            summarize_module_outcomes(&[module(
                "passed",
                true,
                "FINISHED",
                "PASSED",
                serde_json::json!([]),
            )])
            .all_passed
        );
    }
}
