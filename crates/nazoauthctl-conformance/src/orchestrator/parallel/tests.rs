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
    modules_per_plan: AtomicUsize,
    failed_modules: Mutex<HashSet<String>>,
    nonterminal_modules: Mutex<HashSet<String>>,
}

struct RejectCreatedPlanObserver;

struct RejectCreatedModuleObserver;

impl SuiteResourceObserver for RejectCreatedModuleObserver {
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
        Err("simulated durable module persistence failure".to_owned())
    }
}

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
                    "modules": (0..self.modules_per_plan.load(Ordering::SeqCst))
                        .map(|index| serde_json::json!({"testModule": if index == 0 {
                            format!("test-{plan}")
                        } else {
                            format!("test-{plan}-{index}")
                        }})).collect::<Vec<_>>()
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
            let test = request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "test")
                .unwrap()
                .1
                .into_owned();
            return Self::response(
                201,
                serde_json::json!({"id": format!("m-{}", test.trim_start_matches("test-"))}),
            );
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
            let finished = self.finished.lock().expect("finished").contains(module_id)
                && !self.nonterminal_modules.lock().unwrap().contains(module_id);
            return Self::response(
                200,
                if finished {
                    serde_json::json!({"status":"FINISHED","result":
                        if self.failed_modules.lock().unwrap().contains(module_id) { "FAILED" }
                        else { &self.module_result }})
                } else {
                    serde_json::json!({"status":"RUNNING"})
                },
            );
        }
        if path.starts_with("/api/log/") {
            return Self::response(200, serde_json::json!([]));
        }
        if path.starts_with("/api/runner/") && request.method() == HttpMethod::Delete {
            self.nonterminal_modules
                .lock()
                .unwrap()
                .remove(path.trim_start_matches("/api/runner/"));
            return Self::response(200, serde_json::json!({}));
        }
        if path.starts_with("/api/plan/") && request.method() == HttpMethod::Delete {
            return Self::response(204, Value::Null);
        }
        Self::response(404, serde_json::json!({}))
    }
}

fn test_binding() -> ConformanceBinding {
    ConformanceBinding::openid4vc_trust_policy(
        "openid4vc-trust-policy:test",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
        modules_per_plan: AtomicUsize::new(1),
        failed_modules: Mutex::new(HashSet::new()),
        nonterminal_modules: Mutex::new(HashSet::new()),
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

#[test]
fn module_persistence_failure_stops_dispatch_but_preserves_created_instance_for_cleanup() {
    let (mut runner, _) = parallel_fixture(serde_json::json!({}), &["plan-a", "plan-b"], None);
    runner.config.jobs = 1;
    runner.config.suite_resource_observer = Some(Arc::new(RejectCreatedModuleObserver));
    let report = runner.run(&mut ()).report;
    assert!(runner.config.control.is_interrupted());
    assert_eq!(report.plans[0].created_instances, 1);
    assert_eq!(report.plans[1].created_instances, 0);
    assert_eq!(report.modules.len(), 1);
    assert_eq!(report.modules[0].module_id.as_deref(), Some("m-plan-a"));
    assert_eq!(report.cleanup.cancelled, ["m-plan-a"]);
    assert!(!report.local_success);
}

#[test]
fn serial_failure_policy_controls_later_modules_and_plans() {
    for fail_fast in [false, true] {
        let (mut runner, transport) =
            parallel_fixture(serde_json::json!({}), &["plan-a", "plan-b"], None);
        runner.config.jobs = 1;
        runner.config.control = RunControl::with_fail_fast(fail_fast);
        runner.config.selected_resource_budget.modules = 4;
        for budget in runner.config.plan_resource_budgets.values_mut() {
            budget.modules = 2;
        }
        transport.modules_per_plan.store(2, Ordering::SeqCst);
        transport
            .failed_modules
            .lock()
            .unwrap()
            .insert("m-plan-a".to_owned());

        let report = runner.run(&mut ()).report;
        assert_eq!(report.modules.len(), if fail_fast { 1 } else { 4 });
        assert_eq!(
            report.plans[0].created_instances,
            if fail_fast { 1 } else { 2 }
        );
        assert_eq!(
            report.plans[1].created_instances,
            if fail_fast { 0 } else { 2 }
        );
        assert_eq!(report.modules[0].official_result.as_deref(), Some("FAILED"));
        assert_eq!(report.progress.groups[0].status, GroupStatus::Failed);
        assert!(!report.acceptance_pass);
        assert_eq!(report.fail_fast, fail_fast);
        if !fail_fast {
            assert!(
                report.modules[1..]
                    .iter()
                    .all(|module| module.outcome == ModuleOutcome::Passed)
            );
            assert!(report.orchestration_integrity.all_modules_terminal);
        }
    }
}

#[test]
fn continue_mode_does_not_reuse_an_unsettled_module_alias() {
    let (mut runner, transport) =
        parallel_fixture(serde_json::json!({}), &["plan-a", "plan-b"], None);
    runner.config.jobs = 1;
    runner.config.selected_resource_budget.modules = 4;
    for budget in runner.config.plan_resource_budgets.values_mut() {
        budget.modules = 2;
    }
    transport.modules_per_plan.store(2, Ordering::SeqCst);
    transport
        .nonterminal_modules
        .lock()
        .unwrap()
        .insert("m-plan-a".to_owned());
    let report = runner.run(&mut ()).report;
    assert_eq!(report.plans[0].created_instances, 1);
    assert_eq!(report.plans[1].created_instances, 2);
    assert_eq!(report.cleanup.cancelled, ["m-plan-a"]);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error == "Suite module did not reach a terminal status")
    );
    assert!(!report.local_success);
}

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

    let mut prepared = runner.prepare_run(&mut ());
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
}

#[test]
fn failed_outcome_continues_queued_plans_by_default() {
    let (runner, _) = parallel_fixture_with_result(
        serde_json::json!({}),
        &["plan-a", "plan-b", "plan-c"],
        None,
        "FAILED",
    );

    let report = runner.run(&mut ()).report;

    assert!(!report.suite_pass);
    assert!(!report.failed_modules.is_empty());
    assert_eq!(report.progress.failed_groups, 1);
    assert_eq!(report.progress.groups[0].status, GroupStatus::Failed);
    assert_eq!(
        report
            .plans
            .iter()
            .find(|plan| plan.matrix_plan_id == "plan-c")
            .expect("queued plan report")
            .created_instances,
        1,
        "a terminal Suite failure must not stop independent queued work by default"
    );
}

#[test]
fn explicit_fail_fast_stops_queued_plans() {
    let (mut runner, _) = parallel_fixture_with_result(
        serde_json::json!({}),
        &["plan-a", "plan-b", "plan-c"],
        None,
        "FAILED",
    );
    runner.config.control = RunControl::with_fail_fast(true);
    let report = runner.run(&mut ()).report;
    assert_eq!(
        report
            .plans
            .iter()
            .find(|plan| plan.matrix_plan_id == "plan-c")
            .expect("queued plan report")
            .created_instances,
        0
    );
}

#[test]
fn completed_plan_failure_detection_excludes_review_and_skipped_outcomes() {
    let failed =
        parallel_fixture_with_result(serde_json::json!({}), &["plan-a", "plan-b"], None, "FAILED")
            .0
            .run(&mut ())
            .report;
    assert!(completed_plan_stops_dispatch(&failed));

    for result in ["REVIEW", "SKIPPED"] {
        let report = parallel_fixture_with_result(
            serde_json::json!({}),
            &["plan-a", "plan-b"],
            None,
            result,
        )
        .0
        .run(&mut ())
        .report;
        assert!(
            !completed_plan_stops_dispatch(&report),
            "{result} must not stop independent plan dispatch as a failure"
        );
    }
}

#[test]
fn completed_plan_local_error_stops_dispatch_but_shared_interrupt_is_not_a_new_failure() {
    let mut report =
        parallel_fixture_with_result(serde_json::json!({}), &["plan-a", "plan-b"], None, "REVIEW")
            .0
            .run(&mut ())
            .report;
    assert!(!completed_plan_stops_dispatch(&report));

    report.errors.push("module automation failed".to_owned());
    assert!(completed_plan_stops_dispatch(&report));

    report.errors.clear();
    report.errors.push("run interrupted".to_owned());
    assert!(!completed_plan_stops_dispatch(&report));
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
fn independent_ciba_plans_run_in_parallel_within_the_jobs_limit() {
    let (runner, transport) = parallel_fixture_with_lanes(
        serde_json::json!({}),
        &["plan-a", "plan-b"],
        None,
        "PASSED",
        &["plan-a", "plan-b"],
    );

    let summary = runner.run(&mut ());

    assert!(summary.report.local_success);
    assert!(transport.maximum_active_waits.load(Ordering::SeqCst) >= 2);
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
fn plan_error_stops_independent_queued_plans() {
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
        "the first failed plan must stop independent queued work"
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
