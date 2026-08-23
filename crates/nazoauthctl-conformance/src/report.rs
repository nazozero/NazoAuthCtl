use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Plans which the Suite reported immutable. Without an authoritative
    /// Suite cleanup receipt this remains an orchestration failure and is
    /// retained alongside the corresponding cleanup failure for review.
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
    /// Canonical Suite definition variant. Empty preserves the legacy
    /// name-only report shape while non-empty variants distinguish otherwise
    /// identical Suite test names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variant: BTreeMap<String, String>,
    pub terminal: bool,
    /// A signed OpenID4VP verifier module which remains at the Suite's
    /// deferred-review boundary. This is deliberately not a Suite terminal
    /// result and can only be retained with a locally verified required
    /// verification-result capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Locally captured, root-private screenshots requested by a signed
    /// browser placeholder command. They are evidence references only; image
    /// bytes, browser URLs, and page content never enter this report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_screenshots: Vec<ReviewScreenshotReport>,
    /// Exact signed required capture obligations reached while executing this
    /// module's authoritative browser URLs.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshots_required: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshots_required_captured: usize,
    /// Optional signed screenshot markers that could not be captured. A
    /// required marker instead fails local orchestration before reporting.
    #[serde(default, skip_serializing_if = "is_zero")]
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ReviewScreenshotReport {
    pub path: std::path::PathBuf,
    pub sha256: String,
    pub size: usize,
}

/// Identity of the sole signed Suite placeholder that remains pending after a
/// locally verified NazoAuthWeb OpenID4VP result capture. The controller never
/// calls the Suite image API or marks this placeholder visited.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleOutcome {
    Passed,
    Review,
    DeferredReviewPending,
    Skipped,
    Failed,
    Incomplete,
}

pub(crate) struct ModuleReportContext {
    pub matrix_plan_id: String,
    pub suite_plan_id: String,
    pub module_id: Option<String>,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
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
    /// Every module either reached an exact Suite terminal state or the
    /// constrained deferred-review state recorded below.
    #[serde(default, skip_serializing_if = "is_false")]
    pub all_modules_settled: bool,
    /// Count of explicit deferred-review modules. These are never Suite pass
    /// or acceptance pass results.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub deferred_review_modules: usize,
    pub cleanup_complete: bool,
    /// A requested certification retention path is deliberately not cleanup.
    #[serde(default)]
    pub retention_requested: bool,
    /// Every created module reached a terminal state with no orchestration error.
    #[serde(default)]
    pub retention_eligible: bool,
    /// Exact Suite plan ownership was transferred to a retained manifest.
    /// This is deliberately distinct from ordinary cleanup completion.
    #[serde(default)]
    pub retention_committed: bool,
    /// Set only after ordinary cleanup transfers exact plan ownership.
    #[serde(default)]
    pub suite_resources_settled: bool,
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
    /// True when every terminal Suite outcome is acceptable under the signed
    /// Matrix: `PASSED`, or an exact declared `SKIPPED`, with no review,
    /// warning, failed, or incomplete outcome. `suite_pass` intentionally
    /// remains stricter and only represents all-PASSED Suite execution.
    #[serde(default)]
    pub acceptance_pass: bool,
    /// At least one module is retained at the Suite's deferred-review
    /// boundary. This is auditable local settlement, not certification.
    #[serde(default, skip_serializing_if = "is_false")]
    pub review_pending: bool,
    /// True when one or more modules returned REVIEW/WARNING or
    /// emitted a WARNING condition. These modules remain listed in `modules`
    /// and require explicit human follow-up.
    pub human_review_required: bool,
    /// Variant-qualified module identities requiring human review.
    pub human_review_modules: Vec<String>,
    /// Variant-qualified modules at the deferred Suite review boundary. These
    /// are settled locally but never terminal/passed Suite outcomes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred_review_modules: Vec<String>,
    /// Variant-qualified identities that the Suite classified as `SKIPPED`. An expected skip
    /// remains skipped and never contributes to `suite_pass`.
    pub skipped_modules: Vec<String>,
    /// Variant-qualified identities that actually finished
    /// `SKIPPED` and were explicitly allowed by the signed Matrix.
    #[serde(default)]
    pub expected_skipped_modules: Vec<String>,
    /// Variant-qualified identities that actually finished
    /// `SKIPPED` without an exact signed Matrix allowance.
    #[serde(default)]
    pub unexpected_skipped_modules: Vec<String>,
    /// Signed `SKIPPED` declarations whose test name was absent from, or was
    /// duplicated in, the Suite's definition of that Matrix plan.
    #[serde(default)]
    pub unknown_declared_skip_modules: Vec<String>,
    /// Whether every declared Matrix skip was unambiguously enumerated by the
    /// Suite and no module unexpectedly finished `SKIPPED`. This is separate
    /// from local orchestration success so evidence can distinguish a clean
    /// execution from an unacceptable signed-expectation mismatch.
    #[serde(default = "matrix_expectations_satisfied_default")]
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
        let human_review_required = matches!(
            outcome,
            ModuleOutcome::Review | ModuleOutcome::DeferredReviewPending
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
    pub deferred_review_modules: Vec<String>,
    pub skipped_modules: Vec<String>,
    pub failed_modules: Vec<String>,
    pub incomplete_modules: Vec<String>,
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
        match module.outcome {
            ModuleOutcome::Passed => {}
            ModuleOutcome::Review => {
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

const fn matrix_expectations_satisfied_default() -> bool {
    false
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
        assert_eq!(summary.failed_modules, ["p/failed"]);
        assert_eq!(summary.incomplete_modules, ["p/incomplete"]);
        assert!(!summary.acceptance_pass);
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
    fn legacy_schema_three_report_without_skip_gate_fields_fails_closed() {
        let current = ConformanceReport {
            schema: 3,
            matrix_digest: "d".repeat(64),
            suite_origin: "https://suite.example".to_owned(),
            auth_probe: None,
            errors: Vec::new(),
            local_success: true,
            suite_pass: true,
            acceptance_pass: true,
            review_pending: false,
            human_review_required: false,
            human_review_modules: Vec::new(),
            deferred_review_modules: Vec::new(),
            skipped_modules: Vec::new(),
            expected_skipped_modules: Vec::new(),
            unexpected_skipped_modules: Vec::new(),
            unknown_declared_skip_modules: Vec::new(),
            matrix_expectations_satisfied: true,
            failed_modules: Vec::new(),
            incomplete_modules: Vec::new(),
            orchestration_integrity: OrchestrationIntegrity {
                defined_modules: 0,
                created_instances: 0,
                terminal_modules: 0,
                all_modules_instantiated: true,
                all_modules_terminal: true,
                all_modules_settled: true,
                deferred_review_modules: 0,
                cleanup_complete: true,
                retention_requested: false,
                retention_eligible: false,
                retention_committed: false,
                suite_resources_settled: true,
            },
            progress: ProgressSnapshot {
                completed: 0,
                total: 0,
                groups: Vec::new(),
                passed_groups: 0,
                review_groups: 0,
                skipped_groups: 0,
                failed_groups: 0,
                running_groups: 0,
                remaining_groups: 0,
                passed: 0,
                reviewed: 0,
                skipped: 0,
                failed: 0,
                running: 0,
                remaining: 0,
                current_profile: None,
                current_variant: None,
                current_test: None,
            },
            plans: Vec::new(),
            modules: Vec::new(),
            cleanup: CleanupReport::default(),
        };
        let mut legacy = serde_json::to_value(current).expect("current report");
        for field in [
            "acceptance_pass",
            "expected_skipped_modules",
            "unexpected_skipped_modules",
            "unknown_declared_skip_modules",
            "matrix_expectations_satisfied",
        ] {
            legacy.as_object_mut().expect("report object").remove(field);
        }

        let restored: ConformanceReport = serde_json::from_value(legacy).expect("legacy report");

        assert!(!restored.acceptance_pass);
        assert!(!restored.matrix_expectations_satisfied);
        assert!(restored.expected_skipped_modules.is_empty());
        assert!(restored.unexpected_skipped_modules.is_empty());
        assert!(restored.unknown_declared_skip_modules.is_empty());
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
