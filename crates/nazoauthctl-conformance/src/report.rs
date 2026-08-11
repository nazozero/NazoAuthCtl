use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, path::Path};

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
    /// the explicit acceptance fields below.
    pub official_result: Option<String>,
    /// The signed Matrix exception applying to this exact module, if any.
    pub expected_result: Option<String>,
    /// True only when the terminal Suite outcome satisfies the acceptance
    /// policy and the raw log contains no FAILURE/WARNING condition result.
    pub accepted: bool,
    /// `REVIEW` counts as accepted but must remain visible to a human.
    pub human_review_required: bool,
    /// Blocking condition results found in the raw Suite log.
    pub blocking_log_results: Vec<String>,
    /// Public evidence omits config/owner/secret-bearing fields. The complete
    /// objects are retained in the in-memory fields below for evidence sinks.
    pub info: Value,
    pub log: Value,
    #[serde(skip)]
    pub raw_info: Value,
    #[serde(skip)]
    pub raw_log: Value,
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
    pub errors: Vec<String>,
    pub local_success: bool,
    /// Whether every collected official module has an accepted terminal
    /// outcome: PASSED, REVIEW, or the Suite's exact SKIPPED result.
    pub suite_pass: bool,
    /// True when one or more accepted modules returned REVIEW. These modules
    /// remain listed in `modules` and require explicit human follow-up.
    pub human_review_required: bool,
    /// Exact `matrix_plan_id/test_name` entries requiring human review.
    pub human_review_modules: Vec<String>,
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

    /// Persist complete official `/api/info` and `/api/log` objects separately
    /// from the public report. This is intentionally Unix-only: on platforms
    /// where owner-only ACLs cannot be proven through the standard library we
    /// refuse to persist secrets rather than claiming equivalent protection.
    pub fn write_private_evidence(&self, root: &Path) -> Result<(), EvidenceError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(EvidenceError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let root =
                crate::secure_file::ensure_directory(root, true).map_err(map_secure_file_error)?;
            for (index, module) in self.modules.iter().enumerate() {
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "info": &module.raw_info,
                    "log": &module.raw_log,
                }))
                .map_err(|_| EvidenceError::Encoding)?;
                let path = root.join(format!("module-{index:04}.json"));
                crate::secure_file::write_atomic(&path, &bytes, true)
                    .map_err(map_secure_file_error)?;
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
fn map_secure_file_error(error: crate::secure_file::SecureFileError) -> EvidenceError {
    match error {
        crate::secure_file::SecureFileError::UnsupportedPlatform => {
            EvidenceError::UnsupportedPlatform
        }
        crate::secure_file::SecureFileError::UnsafePath => EvidenceError::UnsafePath,
        crate::secure_file::SecureFileError::NotFound
        | crate::secure_file::SecureFileError::Oversize
        | crate::secure_file::SecureFileError::Io => EvidenceError::Io,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EvidenceError {
    UnsupportedPlatform,
    UnsafePath,
    Encoding,
    Io,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "private evidence persistence is unavailable on this platform"
            }
            Self::UnsafePath => "private evidence path is not owner-only",
            Self::Encoding => "private evidence could not be encoded",
            Self::Io => "private evidence persistence failed",
        })
    }
}

impl std::error::Error for EvidenceError {}

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
        collect_blocking_log_results(&raw_log, &mut blocking_log_results);
        let blocking_log_results = blocking_log_results.into_iter().collect::<Vec<_>>();
        let human_review_required = context.terminal
            && official_status.as_deref() == Some("FINISHED")
            && official_result.as_deref() == Some("REVIEW")
            && blocking_log_results.is_empty();
        let accepted = context.terminal
            && official_status.as_deref() == Some("FINISHED")
            && blocking_log_results.is_empty()
            && matches!(
                official_result.as_deref(),
                Some("PASSED" | "REVIEW" | "SKIPPED")
            );
        Self {
            matrix_plan_id: context.matrix_plan_id,
            suite_plan_id: context.suite_plan_id,
            module_id: context.module_id,
            test_name: context.test_name,
            terminal: context.terminal,
            official_status,
            official_result,
            expected_result: context.expected_result,
            accepted,
            human_review_required,
            blocking_log_results,
            info: public_info_summary(&raw_info),
            log: public_log_summary(&raw_log),
            raw_info,
            raw_log,
        }
    }
}

fn collect_blocking_log_results(value: &Value, results: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_blocking_log_results(value, results);
            }
        }
        Value::Object(values) => {
            if let Some(result) = values.get("result").and_then(Value::as_str)
                && matches!(result, "FAILURE" | "WARNING")
            {
                results.insert(result.to_owned());
            }
            for value in values.values() {
                collect_blocking_log_results(value, results);
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
}
