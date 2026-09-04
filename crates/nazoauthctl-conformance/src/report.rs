use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::client::AuthProbe;
use crate::progress::ProgressSnapshot;

#[derive(Clone, Debug, Serialize)]
pub struct CleanupFailure {
    pub operation: String,
    pub target: String,
    pub error: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CleanupReport {
    pub cancelled: Vec<String>,
    pub deleted_plans: Vec<String>,
    /// Plans which the Suite reported immutable. Without an authoritative
    /// Suite cleanup receipt this remains an orchestration failure and is
    /// retained alongside the corresponding cleanup failure for review.
    pub immutable_plans: Vec<String>,
    pub failures: Vec<CleanupFailure>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanReport {
    pub matrix_plan_id: String,
    pub suite_plan_id: Option<String>,
    pub plan_name: String,
    pub defined_modules: usize,
    pub created_instances: usize,
}

#[derive(Clone, Serialize)]
pub struct ModuleReport {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: Option<String>,
    pub test_name: String,
    /// Canonical Suite definition variant. Non-empty variants distinguish
    /// otherwise identical Suite test names.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub variant: BTreeMap<String, String>,
    pub terminal: bool,
    /// A signed OpenID4VP verifier module which remains at the Suite's
    /// deferred-review boundary. This is deliberately not a Suite terminal
    /// result and can only be retained with a locally verified required
    /// verification-result capture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_review_pending: Option<DeferredReviewPending>,
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
    /// Exact number of non-blocking WARNING condition entries. The result
    /// categories above are deduplicated, while this count preserves how many
    /// warnings the Suite emitted.
    #[serde(default)]
    pub advisory_log_count: usize,
    /// Public-safe names and counts of Suite WARNING conditions. Raw messages
    /// remain private evidence because they can contain request material.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory_conditions: Vec<WarningCondition>,
    /// Locally captured, root-private screenshots requested by a signed
    /// browser placeholder command. They are evidence references only; image
    /// bytes, browser URLs, and page content never enter this report.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub review_screenshots: Vec<ReviewScreenshotReport>,
    /// Exact signed required capture obligations reached while executing this
    /// module's authoritative browser URLs.
    #[serde(skip_serializing_if = "is_zero")]
    pub review_screenshots_required: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub review_screenshots_required_captured: usize,
    /// Optional signed screenshot markers that could not be captured. A
    /// required marker instead fails local orchestration before reporting.
    #[serde(skip_serializing_if = "is_zero")]
    pub review_screenshots_missing: usize,
    /// Public evidence omits config/owner/secret-bearing fields. The complete
    /// objects are retained in the in-memory fields below for evidence sinks.
    pub info: Value,
    pub log: Value,
    #[serde(skip)]
    pub raw_info: Value,
    #[serde(skip)]
    pub raw_log: Value,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ReviewScreenshotReport {
    pub path: std::path::PathBuf,
    pub sha256: String,
    pub size: usize,
}

/// Identity of the sole signed Suite placeholder that remains pending after a
/// locally verified NazoAuthWeb OpenID4VP result capture. The controller never
/// calls the Suite image API or marks this placeholder visited.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeferredReviewPending {
    pub placeholder_path: String,
    pub marker: crate::ReviewScreenshotMarker,
    pub obligation_index: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleOutcome {
    Passed,
    Review,
    Warning,
    DeferredReviewPending,
    Skipped,
    Failed,
    Incomplete,
}

#[derive(Clone)]
pub(crate) struct ModuleReportContext {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: Option<String>,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
    pub terminal: bool,
    pub expected_result: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OrchestrationIntegrity {
    pub defined_modules: usize,
    pub created_instances: usize,
    pub terminal_modules: usize,
    pub all_modules_instantiated: bool,
    pub all_modules_terminal: bool,
    /// Every module either reached an exact Suite terminal state or the
    /// constrained deferred-review state recorded below.
    #[serde(skip_serializing_if = "is_false")]
    pub all_modules_settled: bool,
    /// Count of explicit deferred-review modules. These are never Suite pass
    /// or acceptance pass results.
    #[serde(skip_serializing_if = "is_zero")]
    pub deferred_review_modules: usize,
    pub cleanup_complete: bool,
    /// A requested certification retention path is deliberately not cleanup.
    pub retention_requested: bool,
    /// Exact Suite plan ownership is eligible for durable review retention.
    /// This is either a fully settled requested certification run or the
    /// already-started portion of a run containing an official failure,
    /// automation error, or external review boundary.
    pub retention_eligible: bool,
    /// All exact Suite allocations are covered by a locally verified
    /// retention candidate, but ownership has not yet moved to its durable
    /// manifest. This lets the ordinary runner stage that handoff without
    /// falsely reporting retention as committed.
    #[serde(skip_serializing_if = "is_false")]
    pub retention_candidate_settled: bool,
    /// Exact Suite plan ownership was transferred to a retained manifest.
    /// This is deliberately distinct from ordinary cleanup completion.
    pub retention_committed: bool,
    /// Set after ordinary cleanup or a durable retained-manifest transition
    /// transfers exact plan ownership.
    pub suite_resources_settled: bool,
}

#[derive(Clone, Serialize)]
pub struct ConformanceReport {
    pub schema: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_plans: Vec<String>,
    pub fail_fast: bool,
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
    /// True when every terminal Suite outcome is acceptable under the signed
    /// Matrix: `PASSED`, or an exact declared `SKIPPED`, with no review,
    /// warning, failed, or incomplete outcome. `suite_pass` intentionally
    /// remains stricter and only represents all-PASSED Suite execution.
    pub acceptance_pass: bool,
    /// At least one module is retained at the Suite's deferred-review
    /// boundary. This is auditable local settlement, not certification.
    #[serde(skip_serializing_if = "is_false")]
    pub review_pending: bool,
    /// True when one or more modules returned REVIEW/WARNING or
    /// emitted a WARNING condition. These modules remain listed in `modules`
    /// and require explicit human follow-up.
    pub human_review_required: bool,
    /// Variant-qualified module identities requiring human review.
    pub human_review_modules: Vec<String>,
    /// Warnings reported by the Suite. This is separate from `REVIEW`: a
    /// module can have both an official review result and warning conditions.
    pub warning_modules: Vec<WarningModule>,
    /// Variant-qualified modules at the deferred Suite review boundary. These
    /// are settled locally but never terminal/passed Suite outcomes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deferred_review_modules: Vec<String>,
    /// Variant-qualified identities that the Suite classified as `SKIPPED`. An expected skip
    /// remains skipped and never contributes to `suite_pass`.
    pub skipped_modules: Vec<String>,
    /// Variant-qualified identities that actually finished
    /// `SKIPPED` and were explicitly allowed by the signed Matrix.
    pub expected_skipped_modules: Vec<String>,
    /// Variant-qualified identities that actually finished
    /// `SKIPPED` without an exact signed Matrix allowance.
    pub unexpected_skipped_modules: Vec<String>,
    /// Signed `SKIPPED` declarations whose test name was absent from, or was
    /// duplicated in, the Suite's definition of that Matrix plan.
    pub unknown_declared_skip_modules: Vec<String>,
    /// Exact configured-Suite plan IDs retained for certification or failure
    /// diagnosis. An empty list means every plan was cleaned up.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub retained_suite_plan_ids: Vec<String>,
    /// Whether every declared Matrix skip was unambiguously enumerated by the
    /// Suite and no module unexpectedly finished `SKIPPED`. This is separate
    /// from local orchestration success so evidence can distinguish a clean
    /// execution from an unacceptable signed-expectation mismatch.
    pub matrix_expectations_satisfied: bool,
    /// Variant-qualified identities with an explicit failed/unknown result or a blocking log.
    pub failed_modules: Vec<String>,
    /// Variant-qualified identities that never reached the Suite's `FINISHED` state.
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
        let mut advisory_log_count = 0;
        let mut advisory_conditions = BTreeMap::new();
        collect_condition_log_results(
            &raw_log,
            &mut blocking_log_results,
            &mut advisory_log_results,
            &mut advisory_log_count,
            &mut advisory_conditions,
        );
        let blocking_log_results = blocking_log_results.into_iter().collect::<Vec<_>>();
        let advisory_log_results = advisory_log_results.into_iter().collect::<Vec<_>>();
        let outcome =
            if !blocking_log_results.is_empty() || official_result.as_deref() == Some("FAILED") {
                ModuleOutcome::Failed
            } else if !context.terminal || official_status.as_deref() != Some("FINISHED") {
                ModuleOutcome::Incomplete
            } else {
                match official_result.as_deref() {
                    Some("PASSED") if advisory_log_results.is_empty() => ModuleOutcome::Passed,
                    Some("REVIEW") => ModuleOutcome::Review,
                    Some("WARNING") | Some("PASSED") => ModuleOutcome::Warning,
                    Some("SKIPPED") => ModuleOutcome::Skipped,
                    _ => ModuleOutcome::Failed,
                }
            };
        let human_review_required = matches!(
            outcome,
            ModuleOutcome::Review | ModuleOutcome::Warning | ModuleOutcome::DeferredReviewPending
        ) || (outcome == ModuleOutcome::Skipped
            && !advisory_log_results.is_empty());
        Self {
            matrix_plan_id: context.matrix_plan_id,
            suite_plan_id: context.suite_plan_id,
            module_id: context.module_id,
            test_name: context.test_name,
            variant: context.variant,
            terminal: context.terminal,
            deferred_review_pending: None,
            official_status,
            official_result,
            expected_result: context.expected_result,
            outcome,
            human_review_required,
            blocking_log_results,
            advisory_log_results,
            advisory_log_count,
            advisory_conditions: advisory_conditions
                .into_iter()
                .map(|(source, count)| WarningCondition { source, count })
                .collect(),
            review_screenshots: Vec::new(),
            review_screenshots_required: 0,
            review_screenshots_required_captured: 0,
            review_screenshots_missing: 0,
            info: public_info_summary(&raw_info),
            log: public_log_summary(&raw_log),
            raw_info,
            raw_log,
        }
    }

    pub(crate) fn mark_deferred_review_pending(&mut self, pending: DeferredReviewPending) {
        debug_assert!(!self.terminal);
        self.deferred_review_pending = Some(pending);
        self.outcome = ModuleOutcome::DeferredReviewPending;
        self.human_review_required = true;
    }

    pub(crate) fn mark_external_review_pending(&mut self) {
        debug_assert!(!self.terminal);
        self.outcome = ModuleOutcome::Review;
        self.human_review_required = true;
    }
}

impl ModuleReport {
    pub fn has_warning(&self) -> bool {
        self.official_result.as_deref() == Some("WARNING") || !self.advisory_log_results.is_empty()
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
    pub acceptance_pass: bool,
    pub human_review_modules: Vec<String>,
    pub warning_modules: Vec<WarningModule>,
    pub deferred_review_modules: Vec<String>,
    pub skipped_modules: Vec<String>,
    pub failed_modules: Vec<String>,
    pub incomplete_modules: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct WarningModule {
    pub module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub official_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub official_result: Option<String>,
    /// Public condition categories only; raw Suite log content remains in
    /// root-private evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub condition_results: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub condition_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warning_conditions: Vec<WarningCondition>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct WarningCondition {
    pub source: String,
    pub count: usize,
}

pub(crate) struct MatrixExpectationSummary {
    pub expected_skipped_modules: Vec<String>,
    pub unexpected_skipped_modules: Vec<String>,
}

pub(crate) fn summarize_module_outcomes(modules: &[ModuleReport]) -> ModuleOutcomeSummary {
    let mut summary = ModuleOutcomeSummary {
        all_passed: !modules.is_empty(),
        acceptance_pass: !modules.is_empty(),
        human_review_modules: Vec::new(),
        warning_modules: Vec::new(),
        deferred_review_modules: Vec::new(),
        skipped_modules: Vec::new(),
        failed_modules: Vec::new(),
        incomplete_modules: Vec::new(),
    };
    for module in modules {
        let identity = module_identity(module);
        if module.human_review_required {
            summary.human_review_modules.push(identity.clone());
        }
        if module.has_warning() {
            summary.warning_modules.push(WarningModule {
                module: identity.clone(),
                official_status: module.official_status.clone(),
                official_result: module.official_result.clone(),
                condition_results: module.advisory_log_results.clone(),
                condition_count: module.advisory_log_count,
                warning_conditions: module.advisory_conditions.clone(),
            });
        }
        match module.outcome {
            ModuleOutcome::Passed => {}
            ModuleOutcome::Review => {
                summary.all_passed = false;
                summary.acceptance_pass = false;
            }
            ModuleOutcome::Warning => {
                summary.all_passed = false;
                summary.acceptance_pass = false;
            }
            ModuleOutcome::DeferredReviewPending => {
                summary.all_passed = false;
                summary.acceptance_pass = false;
                summary.deferred_review_modules.push(identity);
            }
            ModuleOutcome::Skipped => {
                summary.all_passed = false;
                summary.skipped_modules.push(identity);
                if module.expected_result.as_deref() != Some("SKIPPED")
                    || module.human_review_required
                {
                    summary.acceptance_pass = false;
                }
            }
            ModuleOutcome::Failed => {
                summary.all_passed = false;
                summary.acceptance_pass = false;
                summary.failed_modules.push(identity);
            }
            ModuleOutcome::Incomplete => {
                summary.all_passed = false;
                summary.acceptance_pass = false;
                summary.incomplete_modules.push(identity);
            }
        }
    }
    summary
}

pub(crate) fn summarize_matrix_expectations(modules: &[ModuleReport]) -> MatrixExpectationSummary {
    let mut summary = MatrixExpectationSummary {
        expected_skipped_modules: Vec::new(),
        unexpected_skipped_modules: Vec::new(),
    };
    for module in modules {
        if module.outcome != ModuleOutcome::Skipped {
            continue;
        }
        let identity = module_identity(module);
        if module.expected_result.as_deref() == Some("SKIPPED") {
            summary.expected_skipped_modules.push(identity);
        } else {
            summary.unexpected_skipped_modules.push(identity);
        }
    }
    summary
}

pub(crate) fn module_identity(module: &ModuleReport) -> String {
    if module.variant.is_empty() {
        return format!("{}/{}", module.matrix_plan_id, module.test_name);
    }
    let canonical_variant = serde_json::to_string(&module.variant)
        .expect("BTreeMap<String, String> always serializes to JSON");
    format!(
        "{}/{}?variant={canonical_variant}",
        module.matrix_plan_id, module.test_name
    )
}

fn collect_condition_log_results(
    value: &Value,
    blocking: &mut BTreeSet<String>,
    advisory: &mut BTreeSet<String>,
    advisory_count: &mut usize,
    advisory_conditions: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_condition_log_results(
                    value,
                    blocking,
                    advisory,
                    advisory_count,
                    advisory_conditions,
                );
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
                        *advisory_count += 1;
                        *advisory_conditions
                            .entry(public_warning_condition_source(values))
                            .or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
            for value in values.values() {
                collect_condition_log_results(
                    value,
                    blocking,
                    advisory,
                    advisory_count,
                    advisory_conditions,
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn public_warning_condition_source(values: &Map<String, Value>) -> String {
    let Some(source) = values.get("src").and_then(Value::as_str) else {
        return "WARNING".to_owned();
    };
    if source.len() <= 128 && !source.bytes().any(|byte| byte.is_ascii_control()) {
        source.to_owned()
    } else {
        "<invalid warning source>".to_owned()
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
                variant: BTreeMap::new(),
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
                variant: BTreeMap::new(),
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
        assert_eq!(summary.warning_modules.len(), 1);
        assert_eq!(summary.warning_modules[0].module, "p/skipped-warning");
        assert_eq!(summary.warning_modules[0].condition_count, 1);
        assert_eq!(summary.failed_modules, ["p/failed"]);
        assert_eq!(summary.incomplete_modules, ["p/incomplete"]);
        assert!(!summary.acceptance_pass);
    }

    #[test]
    fn passed_with_warning_is_warning_and_empty_run_is_not_a_suite_pass() {
        let warning = module(
            "warning",
            true,
            "FINISHED",
            "PASSED",
            serde_json::json!([{"result":"WARNING", "src":"ValidateCertificate"}]),
        );
        assert_eq!(warning.outcome, ModuleOutcome::Warning);
        assert!(warning.human_review_required);
        assert_eq!(warning.advisory_log_count, 1);
        assert_eq!(warning.advisory_conditions[0].source, "ValidateCertificate");
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

    #[test]
    fn review_with_warning_preserves_review_and_records_every_warning_entry() {
        let review = module(
            "review-warning",
            true,
            "FINISHED",
            "REVIEW",
            serde_json::json!([
                {"result":"WARNING", "src":"ValidateA"},
                {"nested":{"result":"WARNING", "src":"ValidateA"}}
            ]),
        );
        assert_eq!(review.outcome, ModuleOutcome::Review);
        assert_eq!(review.advisory_log_count, 2);
        let summary = summarize_module_outcomes(&[review]);
        assert_eq!(summary.human_review_modules, ["p/review-warning"]);
        assert_eq!(summary.warning_modules.len(), 1);
        assert_eq!(summary.warning_modules[0].condition_count, 2);
        assert_eq!(
            summary.warning_modules[0].warning_conditions,
            [WarningCondition {
                source: "ValidateA".to_owned(),
                count: 2
            }]
        );
    }

    #[test]
    fn interrupted_official_failures_are_not_downgraded_to_incomplete() {
        let failed_result = module(
            "failed-result",
            true,
            "INTERRUPTED",
            "FAILED",
            serde_json::json!([]),
        );
        let blocking_log = module(
            "blocking-log",
            true,
            "INTERRUPTED",
            "PASSED",
            serde_json::json!([{"result":"FAILURE"}]),
        );
        let interrupted = module(
            "interrupted",
            true,
            "INTERRUPTED",
            "PASSED",
            serde_json::json!([]),
        );

        assert_eq!(failed_result.outcome, ModuleOutcome::Failed);
        assert_eq!(blocking_log.outcome, ModuleOutcome::Failed);
        assert_eq!(interrupted.outcome, ModuleOutcome::Incomplete);
    }

    #[test]
    fn variant_qualified_module_identity_distinguishes_same_named_definitions() {
        let mut plain = module(
            "happy-flow",
            true,
            "FINISHED",
            "FAILED",
            serde_json::json!([]),
        );
        plain.variant = BTreeMap::from([("credential_configuration".into(), "plain".into())]);
        let mut encrypted = module(
            "happy-flow",
            true,
            "FINISHED",
            "FAILED",
            serde_json::json!([]),
        );
        encrypted.variant =
            BTreeMap::from([("credential_configuration".into(), "encrypted".into())]);

        let summary = summarize_module_outcomes(&[plain, encrypted]);

        assert_eq!(
            summary.failed_modules,
            [
                "p/happy-flow?variant={\"credential_configuration\":\"plain\"}",
                "p/happy-flow?variant={\"credential_configuration\":\"encrypted\"}"
            ]
        );
    }

    #[test]
    fn skipped_modules_require_an_exact_signed_allowance() {
        let modules = vec![
            ModuleReport::from_info(
                ModuleReportContext {
                    matrix_plan_id: "p".into(),
                    suite_plan_id: "s".into(),
                    module_id: Some("expected".into()),
                    test_name: "expected-skip".into(),
                    variant: BTreeMap::new(),
                    terminal: true,
                    expected_result: Some("SKIPPED".into()),
                },
                serde_json::json!({"status":"FINISHED","result":"SKIPPED"}),
                serde_json::json!([]),
            ),
            module(
                "unexpected-skip",
                true,
                "FINISHED",
                "SKIPPED",
                serde_json::json!([]),
            ),
        ];

        let summary = summarize_matrix_expectations(&modules);

        assert_eq!(summary.expected_skipped_modules, ["p/expected-skip"]);
        assert_eq!(summary.unexpected_skipped_modules, ["p/unexpected-skip"]);
        assert!(!summarize_module_outcomes(&modules).acceptance_pass);

        let expected_only = summarize_module_outcomes(&modules[..1]);
        assert!(expected_only.acceptance_pass);
        assert!(!expected_only.all_passed);
    }

    #[test]
    fn deferred_review_is_settled_evidence_but_never_a_suite_acceptance() {
        let mut pending = module("vp-result", false, "WAITING", "", serde_json::json!([]));
        pending.mark_deferred_review_pending(DeferredReviewPending {
            placeholder_path: "/test/a/module-vp-result/verification-evidence".to_owned(),
            marker: crate::ReviewScreenshotMarker::Required,
            obligation_index: 0,
        });

        let summary = summarize_module_outcomes(&[pending]);

        assert!(!summary.all_passed);
        assert!(!summary.acceptance_pass);
        assert!(summary.incomplete_modules.is_empty());
        assert_eq!(
            summary.deferred_review_modules,
            vec!["p/vp-result".to_owned()]
        );
    }
}
