use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::browser::ConformanceBinding;
use crate::client::{ClientConfig, SuiteClient};
use crate::credentials::BearerToken;
use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
use crate::origin::Origin;
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
        jobs: 2,
        automation: Vec::new(),
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
fn ciba_plans_use_one_global_serial_lane() {
    let (runner, transport) =
        parallel_fixture(serde_json::json!({}), &["ciba-plan-a", "ciba-plan-b"], None);

    let summary = runner.run(&mut ());

    assert!(summary.report.local_success);
    assert_eq!(transport.maximum_active_waits.load(Ordering::SeqCst), 1);
    assert_eq!(summary.report.orchestration_integrity.terminal_modules, 2);
    assert!(summary.report.cleanup.failures.is_empty());
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
