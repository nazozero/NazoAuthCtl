use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::ReviewScreenshotMarker;
use crate::browser::ConformanceBinding;
use crate::client::{ClientConfig, SuiteClient};
use crate::credentials::BearerToken;
use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
use crate::origin::Origin;
use crate::report::{DeferredReviewPending, ModuleOutcome, ReviewScreenshotReport};
use crate::transport::{HttpMethod, HttpRequest, HttpResponse, Transport, TransportError};

struct ParallelFixtureTransport {
    active_waits: AtomicUsize,
    maximum_active_waits: AtomicUsize,
    finished: Mutex<HashSet<String>>,
    requests: Mutex<Vec<(HttpMethod, String)>>,
    created_plans: Mutex<Vec<String>>,
    fail_module_for_plan: Option<String>,
    module_result: String,
}

struct RejectCreatedPlanObserver;

struct RetainSuiteObserver;

impl SuiteResourceObserver for RetainSuiteObserver {
    fn retain_suite_plans_for_certification(&self) -> bool {
        true
    }

    fn plan_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
        Ok(())
    }

    fn plan_created(
        &self,
        _origin: &Origin,
        _intent_id: &str,
        _plan_id: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    fn module_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
        Ok(())
    }

    fn module_created(&self, _intent_id: &str, _module_id: &str) -> Result<(), String> {
        Ok(())
    }
}

impl SuiteResourceObserver for RejectCreatedPlanObserver {
    fn plan_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
        Ok(())
    }

    fn plan_created(
        &self,
        _origin: &Origin,
        _intent_id: &str,
        _plan_id: &str,
    ) -> Result<(), String> {
        Err("simulated durable plan persistence failure".to_owned())
    }

    fn module_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
        Ok(())
    }

    fn module_created(&self, _intent_id: &str, _module_id: &str) -> Result<(), String> {
        Ok(())
    }
}

impl ParallelFixtureTransport {
    fn response(status: u16, body: Value) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body: serde_json::to_vec(&body).expect("json"),
        })
    }

    fn record_maximum(&self, active: usize) {
        let mut observed = self.maximum_active_waits.load(Ordering::SeqCst);
        while active > observed {
            match self.maximum_active_waits.compare_exchange(
                observed,
                active,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
    }
}

impl Transport for ParallelFixtureTransport {
    fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
        let path = request.url().path();
        self.requests
            .lock()
            .expect("requests")
            .push((request.method(), path.to_owned()));
        if path == "/api/plan" && request.method() == HttpMethod::Get {
            return Self::response(
                if request.header("Authorization").is_some() {
                    200
                } else {
                    401
                },
                serde_json::json!({}),
            );
        }
        if path == "/api/plan" && request.method() == HttpMethod::Post {
            let plan = request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "planName")
                .map(|(_, value)| value.into_owned())
                .expect("planName");
            self.created_plans
                .lock()
                .expect("created plans")
                .push(plan.clone());
            return Self::response(
                201,
                serde_json::json!({
                    "id": plan,
                    "name": plan,
                    "modules": [{"testModule": format!("test-{plan}")}]
                }),
            );
        }
        if path == "/api/runner" && request.method() == HttpMethod::Post {
            let plan = request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "plan")
                .map(|(_, value)| value.into_owned())
                .expect("plan");
            if self.fail_module_for_plan.as_deref() == Some(plan.as_str()) {
                return Self::response(500, serde_json::json!({}));
            }
            return Self::response(201, serde_json::json!({"id": format!("m-{plan}")}));
        }
        if path.starts_with("/api/runner/m-") && path.ends_with("/wait-state") {
            let active = self.active_waits.fetch_add(1, Ordering::SeqCst) + 1;
            self.record_maximum(active);
            thread::sleep(Duration::from_millis(75));
            self.active_waits.fetch_sub(1, Ordering::SeqCst);
            let module_id = path
                .trim_start_matches("/api/runner/")
                .trim_end_matches("/wait-state")
                .trim_end_matches('/');
            self.finished
                .lock()
                .expect("finished")
                .insert(module_id.to_owned());
            return Self::response(200, serde_json::json!({"state":"FINISHED"}));
        }
        if let Some(module_id) = path.strip_prefix("/api/info/") {
            let finished = self.finished.lock().expect("finished").contains(module_id);
            return Self::response(
                200,
                if finished {
                    serde_json::json!({"status":"FINISHED","result":self.module_result})
                } else {
                    serde_json::json!({"status":"RUNNING"})
                },
            );
        }
        if path.starts_with("/api/log/") {
            return Self::response(200, serde_json::json!([]));
        }
        if path.starts_with("/api/runner/") && request.method() == HttpMethod::Delete {
            return Self::response(200, serde_json::json!({}));
        }
        if path.starts_with("/api/plan/") && request.method() == HttpMethod::Delete {
            return Self::response(204, Value::Null);
        }
        Self::response(404, serde_json::json!({}))
    }
}

fn test_binding() -> ConformanceBinding {
    ConformanceBinding::new(
        "019ff000-8190-7393-8c33-ab4339c3d85e",
        "request-0123456789abcdef0123456789abcdef",
    )
    .expect("binding")
}

fn parallel_fixture(
    config: Value,
    plan_ids: &[&str],
    fail_module_for_plan: Option<&str>,
) -> (ConformanceRunner, Arc<ParallelFixtureTransport>) {
    parallel_fixture_with_result(config, plan_ids, fail_module_for_plan, "PASSED")
}

fn parallel_fixture_with_result(
    config: Value,
    plan_ids: &[&str],
    fail_module_for_plan: Option<&str>,
    module_result: &str,
) -> (ConformanceRunner, Arc<ParallelFixtureTransport>) {
    parallel_fixture_with_lanes(config, plan_ids, fail_module_for_plan, module_result, &[])
}

fn parallel_fixture_with_lanes(
    config: Value,
    plan_ids: &[&str],
    fail_module_for_plan: Option<&str>,
    module_result: &str,
    ciba_plan_ids: &[&str],
) -> (ConformanceRunner, Arc<ParallelFixtureTransport>) {
    let transport = Arc::new(ParallelFixtureTransport {
        active_waits: AtomicUsize::new(0),
        maximum_active_waits: AtomicUsize::new(0),
        finished: Mutex::new(HashSet::new()),
        requests: Mutex::new(Vec::new()),
        created_plans: Mutex::new(Vec::new()),
        fail_module_for_plan: fail_module_for_plan.map(ToOwned::to_owned),
        module_result: module_result.to_owned(),
    });
    let client = SuiteClient::with_transport(
        Origin::parse("https://suite.example").expect("origin"),
        Some(BearerToken::new("suite-token").expect("token")),
        transport.clone(),
        ClientConfig::default(),
    )
    .expect("client");
    let plans = plan_ids
        .iter()
        .copied()
        .map(|id| MatrixPlan {
            id: id.to_owned(),
            plan: id.to_owned(),
            config: config.clone(),
            variant: BTreeMap::new(),
            expected_results: BTreeMap::new(),
        })
        .collect();
    let plan_lanes = plan_ids
        .iter()
        .map(|id| {
            (
                (*id).to_owned(),
                if ciba_plan_ids.contains(id) {
                    OidfDriverLane::Ciba
                } else {
                    OidfDriverLane::Parallel
                },
            )
        })
        .collect();
    let plan_resource_budgets = plan_ids
        .iter()
        .map(|id| {
            (
                (*id).to_owned(),
                OidfPlanResourceBudget {
                    modules: 1,
                    clients: 1,
                    wall_clock_seconds: 60,
                },
            )
        })
        .collect();
    let selected_plan_count = u32::try_from(plan_ids.len()).expect("fixture plan count");
    let runner = ConformanceRunner::new(ConformanceRunConfig {
        client,
        matrix: SelectedMatrix {
            document: MatrixDocument {
                schema: 1,
                name: "parallel-matrix".into(),
                groups: vec![MatrixGroup {
                    id: "g".into(),
                    profile: "oidc".into(),
                    variant: MatrixVariant {
                        id: "default".into(),
                        values: BTreeMap::new(),
                    },
                    plans,
                }],
            },
            digest: "digest".into(),
        },
        target_origin: None,
        binding: test_binding(),
        poll_timeout: Duration::from_secs(2),
        control: RunControl::default(),
        plan_lanes,
        plan_resource_budgets,
        selected_resource_budget: OidfPlanResourceBudget {
            modules: selected_plan_count,
            clients: selected_plan_count,
            wall_clock_seconds: u64::from(selected_plan_count) * 60,
        },
        jobs: 2,
        upload_review_screenshots: false,
        automation: Vec::new(),
        suite_resource_observer: None,
    })
    .expect("runner");
    (runner, transport)
}

#[derive(Default)]
struct RecordingSink(Vec<ProgressSnapshot>);

impl ProgressSink for RecordingSink {
    fn update(&mut self, event: &ProgressEvent) {
        self.0.push(event.snapshot.clone());
    }
}

#[test]
fn independent_plans_overlap_but_reports_remain_in_matrix_order() {
    let (runner, transport) = parallel_fixture(serde_json::json!({}), &["plan-a", "plan-b"], None);
    let mut progress = RecordingSink::default();

    let summary = runner.run(&mut progress);

    assert!(
        summary.report.local_success,
        "parallel run must pass: errors={:?}, integrity={:?}, cleanup={:?}, requests={:?}",
        summary.report.errors,
        summary.report.orchestration_integrity,
        summary.report.cleanup,
        transport.requests.lock().expect("requests"),
    );
    assert!(transport.maximum_active_waits.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        summary
            .report
            .plans
            .iter()
            .map(|plan| plan.matrix_plan_id.as_str())
            .collect::<Vec<_>>(),
        ["plan-a", "plan-b"]
    );
    assert_eq!(summary.report.orchestration_integrity.defined_modules, 2);
    assert_eq!(summary.report.orchestration_integrity.terminal_modules, 2);
    assert!(summary.report.cleanup.failures.is_empty());
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .all(|(method, path)| {
                !(*method == HttpMethod::Delete && path.starts_with("/api/runner/"))
            }),
        "parallel cleanup must use observed terminal reports instead of re-cancelling them"
    );
    assert!(!progress.0.is_empty());
    assert!(
        progress.0.iter().all(|snapshot| snapshot.total == 2),
        "the complete denominator must be frozen before any worker starts"
    );
    let requests = transport.requests.lock().expect("requests");
    let first_runner = requests
        .iter()
        .position(|(_, path)| path == "/api/runner")
        .expect("runner request");
    assert_eq!(
        requests[..first_runner]
            .iter()
            .filter(|(method, path)| *method == HttpMethod::Post && path == "/api/plan")
            .count(),
        2,
        "every selected plan must be created before module execution begins"
    );
}

#[test]
fn retained_parallel_run_launches_work_after_the_first_worker_finishes() {
    let (mut runner, transport) = parallel_fixture(
        serde_json::json!({}),
        &["plan-a", "plan-b", "plan-c", "plan-d", "plan-e"],
        None,
    );
    runner.config.jobs = 4;
    runner.config.suite_resource_observer = Some(Arc::new(RetainSuiteObserver));

    let summary = runner.run(&mut ());

    assert!(summary.report.errors.is_empty());
    assert!(summary.report.orchestration_integrity.retention_eligible);
    assert!(
        summary
            .report
            .orchestration_integrity
            .retention_candidate_settled
    );
    assert!(!summary.report.orchestration_integrity.retention_committed);
    assert!(!summary.report.orchestration_integrity.cleanup_complete);
    assert!(
        summary
            .report
            .orchestration_integrity
            .suite_resources_settled
    );
    assert!(summary.report.local_success);
    assert!(!summary.report.orchestration_integrity.cleanup_complete);
    assert_eq!(summary.report.orchestration_integrity.terminal_modules, 5);
    assert_eq!(
        transport.created_plans.lock().expect("plans").len(),
        5,
        "retention must not make the first finished worker stop the remaining queue"
    );
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .all(|(method, path)| {
                !(*method == HttpMethod::Delete && path.starts_with("/api/plan/"))
            }),
        "eligible retained plans remain for the caller's durable retention handoff"
    );
}

fn merge_terminal_and_deferred_review_workers(
    include_worker_error: bool,
) -> (RunSummary, Arc<ParallelFixtureTransport>) {
    let (mut runner, transport) =
        parallel_fixture(serde_json::json!({}), &["plan-a", "plan-b"], None);
    runner.config.suite_resource_observer = Some(Arc::new(RetainSuiteObserver));

    let mut prepared = runner.prepare_run();
    let work = plan_work(&mut prepared);
    let terminal = runner.run_prepared(&mut (), worker_prepared(&work[0]));
    let mut deferred = runner.run_prepared(&mut (), worker_prepared(&work[1]));
    let module = deferred
        .report
        .modules
        .first_mut()
        .expect("deferred worker module");
    module.terminal = false;
    module.official_status = Some("WAITING".to_owned());
    module.official_result = None;
    module.review_screenshots = vec![ReviewScreenshotReport {
        path: "review-screenshots/run-1/m-plan-b-0.png".into(),
        sha256: "a".repeat(64),
        size: 1,
    }];
    module.review_screenshots_required = 1;
    module.review_screenshots_required_captured = 1;
    module.mark_deferred_review_pending(DeferredReviewPending {
        placeholder_path: "/test/a/m-plan-b/verification-evidence".to_owned(),
        marker: ReviewScreenshotMarker::Required,
        obligation_index: 0,
    });
    if include_worker_error {
        deferred
            .report
            .errors
            .push("simulated deferred capture integrity failure".to_owned());
    }
    let snapshots = vec![
        Some(terminal.report.progress.clone()),
        Some(deferred.report.progress.clone()),
    ];

    (
        merge_reports(
            &runner,
            prepared,
            &work,
            snapshots,
            vec![true, true],
            vec![Some(terminal), Some(deferred)],
            false,
        ),
        transport,
    )
}

#[test]
fn parallel_aggregation_retains_terminal_and_deferred_review_workers_without_claiming_pass() {
    let (summary, transport) = merge_terminal_and_deferred_review_workers(false);
    let report = summary.report;

    assert!(report.errors.is_empty());
    assert!(report.orchestration_integrity.all_modules_settled);
    assert!(!report.orchestration_integrity.all_modules_terminal);
    assert_eq!(report.orchestration_integrity.terminal_modules, 1);
    assert_eq!(report.orchestration_integrity.deferred_review_modules, 1);
    assert!(report.orchestration_integrity.retention_eligible);
    assert!(report.orchestration_integrity.retention_candidate_settled);
    assert!(!report.orchestration_integrity.retention_committed);
    assert!(report.orchestration_integrity.suite_resources_settled);
    assert!(!report.orchestration_integrity.cleanup_complete);
    assert!(report.local_success);
    assert!(report.review_pending);
    assert!(!report.suite_pass);
    assert!(!report.acceptance_pass);
    assert!(
        report
            .modules
            .iter()
            .any(|module| module.outcome == ModuleOutcome::DeferredReviewPending)
    );
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .all(|(method, path)| {
                !(*method == HttpMethod::Delete
                    && (path.starts_with("/api/runner/") || path.starts_with("/api/plan/")))
            }),
        "the settled deferred review worker retains its module and plan for the durable handoff"
    );
}

#[test]
fn parallel_aggregation_cleans_deferred_review_workers_when_any_worker_reports_an_error() {
    let (summary, transport) = merge_terminal_and_deferred_review_workers(true);
    let report = summary.report;

    assert!(!report.orchestration_integrity.retention_eligible);
    assert!(report.orchestration_integrity.cleanup_complete);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("simulated deferred capture integrity failure"))
    );
    assert!(
        report
            .cleanup
            .deleted_plans
            .iter()
            .any(|plan| plan == "plan-a")
    );
    assert!(
        report
            .cleanup
            .deleted_plans
            .iter()
            .any(|plan| plan == "plan-b")
    );
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .any(|(method, path)| *method == HttpMethod::Delete && path == "/api/plan/plan-a")
    );
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .any(|(method, path)| *method == HttpMethod::Delete && path == "/api/plan/plan-b")
    );
}

#[test]
fn parallel_non_pass_outcomes_complete_locally_without_claiming_suite_pass() {
    let (review_runner, _) =
        parallel_fixture_with_result(serde_json::json!({}), &["plan-a", "plan-b"], None, "REVIEW");
    let review = review_runner.run(&mut ()).report;
    assert!(review.local_success);
    assert!(!review.suite_pass);
    assert!(review.errors.is_empty());
    assert!(review.human_review_required);
    assert_eq!(review.human_review_modules.len(), 2);
    assert!(review.skipped_modules.is_empty());
    assert_eq!(review.progress.reviewed, 2);
    assert_eq!(review.progress.review_groups, 1);
    assert_eq!(review.progress.groups[0].status, GroupStatus::Review);

    let (skipped_runner, _) = parallel_fixture_with_result(
        serde_json::json!({}),
        &["plan-a", "plan-b"],
        None,
        "SKIPPED",
    );
    let skipped = skipped_runner.run(&mut ()).report;
    assert!(skipped.local_success);
    assert!(!skipped.suite_pass);
    assert!(skipped.errors.is_empty());
    assert!(!skipped.human_review_required);
    assert_eq!(skipped.skipped_modules.len(), 2);
    assert_eq!(skipped.progress.skipped, 2);
    assert_eq!(skipped.progress.skipped_groups, 1);
    assert_eq!(skipped.progress.groups[0].status, GroupStatus::Skipped);

    let (failed_runner, _) =
        parallel_fixture_with_result(serde_json::json!({}), &["plan-a", "plan-b"], None, "FAILED");
    let failed = failed_runner.run(&mut ()).report;
    assert!(failed.local_success);
    assert!(!failed.suite_pass);
    assert!(failed.errors.is_empty());
    assert_eq!(failed.failed_modules.len(), 2);
    assert_eq!(failed.progress.failed, 2);
    assert_eq!(failed.progress.failed_groups, 1);
    assert_eq!(failed.progress.groups[0].status, GroupStatus::Failed);
}

#[test]
fn parallel_expected_skips_are_preserved_and_acceptance_is_exact() {
    let (mut runner, _) = parallel_fixture_with_result(
        serde_json::json!({}),
        &["plan-a", "plan-b"],
        None,
        "SKIPPED",
    );
    for plan in &mut runner.config.matrix.document.groups[0].plans {
        plan.expected_results
            .insert(format!("test-{}", plan.plan), "SKIPPED".to_owned());
    }

    let report = runner.run(&mut ()).report;

    assert!(report.local_success);
    assert!(!report.suite_pass, "SKIPPED must not be relabeled PASSED");
    assert!(report.acceptance_pass);
    assert!(report.matrix_expectations_satisfied);
    assert_eq!(
        report.expected_skipped_modules,
        ["plan-a/test-plan-a", "plan-b/test-plan-b"]
    );
    assert!(report.unexpected_skipped_modules.is_empty());
    assert!(report.unknown_declared_skip_modules.is_empty());
}

#[test]
fn ciba_plans_use_one_global_serial_lane() {
    let (runner, transport) = parallel_fixture_with_lanes(
        serde_json::json!({}),
        &["plan-a", "plan-b"],
        None,
        "PASSED",
        &["plan-a", "plan-b"],
    );

    let summary = runner.run(&mut ());

    assert!(summary.report.local_success);
    assert_eq!(transport.maximum_active_waits.load(Ordering::SeqCst), 1);
    assert_eq!(summary.report.orchestration_integrity.terminal_modules, 2);
    assert!(summary.report.cleanup.failures.is_empty());
}

#[test]
fn mutable_suite_plan_names_cannot_select_the_ciba_lane() {
    let (runner, transport) = parallel_fixture(
        serde_json::json!({}),
        &["ciba-in-name-a", "ciba-in-name-b"],
        None,
    );

    let summary = runner.run(&mut ());

    assert!(summary.report.local_success);
    assert!(transport.maximum_active_waits.load(Ordering::SeqCst) >= 2);
}

#[test]
fn orchestration_error_stops_queued_plans_and_drains_in_flight_cleanup() {
    let (runner, transport) = parallel_fixture(
        serde_json::json!({}),
        &["plan-a", "plan-b", "plan-c"],
        Some("plan-a"),
    );

    let summary = runner.run(&mut ());

    assert!(!summary.report.local_success);
    assert!(
        summary
            .report
            .errors
            .iter()
            .any(|error| error.contains("plan-a: HTTP response status 500"))
    );
    assert!(
        summary
            .report
            .errors
            .iter()
            .any(|error| error.contains("scheduler stopped before every selected"))
    );
    let created_plans = transport.created_plans.lock().expect("plans").clone();
    assert_eq!(created_plans, ["plan-a", "plan-b", "plan-c"]);
    assert_eq!(
        summary
            .report
            .plans
            .iter()
            .find(|plan| plan.matrix_plan_id == "plan-c")
            .expect("queued plan report")
            .created_instances,
        0,
        "phase 1 creates every plan, but a fatal worker error must stop the queued plan before module execution"
    );
    assert!(summary.report.cleanup.failures.is_empty());
    assert!(created_plans.iter().all(|plan| {
        summary
            .report
            .cleanup
            .deleted_plans
            .iter()
            .any(|deleted| deleted == plan)
    }));
}

#[test]
fn observer_failure_still_cleans_up_the_in_memory_plan_id() {
    let (mut runner, transport) = parallel_fixture(serde_json::json!({}), &["plan-a"], None);
    runner.config.suite_resource_observer = Some(Arc::new(RejectCreatedPlanObserver));

    let summary = runner.run(&mut ());

    assert!(!summary.report.local_success);
    assert!(
        summary
            .report
            .errors
            .iter()
            .any(|error| error == "simulated durable plan persistence failure")
    );
    assert_eq!(summary.report.cleanup.deleted_plans, vec!["plan-a"]);
    assert!(
        transport
            .requests
            .lock()
            .expect("requests")
            .iter()
            .any(|(method, path)| *method == HttpMethod::Delete && path == "/api/plan/plan-a")
    );
}
