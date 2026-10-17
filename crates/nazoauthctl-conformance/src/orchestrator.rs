use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::browser::{
    BrowserPolicy, BrowserRunnerState, BrowserTargetOrigin, ConformanceBinding,
    MAX_REVIEW_SCREENSHOTS_PER_RUN, OpenId4VciError, OpenId4VciIssuerDriver, OpenId4VciModule,
    OpenId4VpStartRequest, OpenId4VpVerifier,
};
use crate::ciba_approval::{CibaUserApprovalClient, ciba_approval_requests};
use crate::client::{DeleteOutcome, ModuleDefinition, SuiteClient, SuiteClientError};
use crate::matrix::{SelectedMatrix, zeroize_json_value};
use crate::origin::Origin;
use crate::progress::{
    GroupProgress, GroupStatus, ProgressActivity, ProgressEvent, ProgressSink, ProgressSnapshot,
    redacted_variant,
};
use crate::report::{
    CleanupFailure, CleanupReport, ConformanceReport, ModuleOutcome, ModuleReport,
    ModuleReportContext, OrchestrationIntegrity, PlanReport, summarize_module_outcomes,
};
use crate::{OidfDriverLane, OidfPlanResourceBudget};

mod parallel;

pub const MAX_PARALLEL_JOBS: usize = 4;
pub const BOUNDED_PLAN_RUNNER_PROTOCOL: &str = "nazoauthctl-bounded-plan-runner-v1";
pub const MAX_POLL_TIMEOUT_SECONDS: u64 = 86_400;
pub const MAX_POLL_TIMEOUT: Duration = Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS);
/// One worker-owned interactive automation lane. A lane is never shared by
/// concurrent plan workers, so OpenID4VC driver state cannot interleave.
/// Browser sessions and cookies are owned by each Suite test module.
#[derive(Clone, Default)]
pub struct ConformanceAutomation {
    pub verifier: Option<Arc<Mutex<dyn OpenId4VpVerifier>>>,
    pub issuer: Option<Arc<Mutex<dyn OpenId4VciIssuerDriver>>>,
    pub ciba_approver: Option<Arc<CibaUserApprovalClient>>,
}

#[derive(Clone, Default)]
pub struct RunControl {
    interrupted: Arc<AtomicBool>,
    fail_fast: bool,
}

impl RunControl {
    pub fn interrupt(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
    }

    pub fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }

    pub fn with_fail_fast(enabled: bool) -> Self {
        Self {
            interrupted: Arc::new(AtomicBool::new(false)),
            fail_fast: enabled,
        }
    }

    pub fn is_fail_fast(&self) -> bool {
        self.fail_fast
    }
}

pub struct ConformanceRunConfig {
    pub client: SuiteClient,
    pub matrix: SelectedMatrix,
    pub target_origin: Option<BrowserTargetOrigin>,
    /// The deployment-owned trust-policy resource binding allocated for this
    /// run. Keeping it on the run config prevents partial requests.
    pub binding: Option<ConformanceBinding>,
    pub poll_timeout: Duration,
    pub control: RunControl,
    /// Exact signed execution lane for every selected Matrix plan. The map is
    /// required to match the selected plan ids one-for-one; the runner never
    /// derives CIBA semantics from mutable Suite plan names.
    pub plan_lanes: BTreeMap<String, OidfDriverLane>,
    /// Signed client/time budget for every selected Matrix plan. The map must
    /// cover the selected plan ids one-for-one; live module counts remain
    /// Suite-owned and are bounded only by the aggregate module ceiling.
    pub plan_resource_budgets: BTreeMap<String, OidfPlanResourceBudget>,
    /// Signed aggregate client/time budget plus the artifact-wide module ceiling.
    pub selected_resource_budget: OidfPlanResourceBudget,
    /// Maximum number of independent Suite plans executed at once. Modules
    /// inside one plan remain strictly ordered. Browser, verifier, and issuer
    /// automation retain their existing mutex-owned sessions, so parallel
    /// HTTP runners cannot interleave interactive state.
    pub jobs: usize,
    /// Worker-owned automation lanes. HTTP-only test fixtures may leave this
    /// empty; production creates one independent lane per configured job.
    pub automation: Vec<ConformanceAutomation>,
    /// Durable observer for externally allocated Suite resources. The
    /// controller installs this before creating plans so a process crash can
    /// recover recorded opaque IDs and fail closed for an unresolved create
    /// request.
    pub suite_resource_observer: Option<Arc<dyn SuiteResourceObserver>>,
}

/// Receives Suite allocation intents and outcomes synchronously.  An intent
/// is durably persisted before the remote create request; its opaque resource
/// ID atomically replaces the intent after a successful response. A surviving
/// intent deliberately blocks recovery completion because the current Suite
/// API cannot enumerate or deduplicate an unknown create outcome.
pub trait SuiteResourceObserver: Send + Sync {
    /// An explicitly authenticated operator request may retain fully terminal
    /// Suite plans for certification review.  The default preserves normal
    /// cleanup for every existing observer.
    fn retain_suite_plans_for_certification(&self) -> bool {
        false
    }

    /// Keep already-started plans when an official Suite module fails so the
    /// operator can inspect the same record in the configured Suite UI.
    fn retain_failed_suite_plans_for_diagnosis(&self) -> bool {
        false
    }

    fn plan_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String>;
    fn plan_created(&self, origin: &Origin, intent_id: &str, plan_id: &str) -> Result<(), String>;
    fn module_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String>;
    fn module_created(&self, intent_id: &str, module_id: &str) -> Result<(), String>;

    /// Shrink durable recovery ownership only after the Suite confirms that
    /// the exact plan is deleted or already absent.
    fn plan_deleted(&self, _plan_id: &str) -> Result<(), String> {
        Ok(())
    }
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
    plan_name: String,
    variant: BTreeMap<String, String>,
    runtime_variant: BTreeMap<String, String>,
    expected_results: BTreeMap<String, String>,
    modules: Vec<ModuleDefinition>,
    config: Value,
    report_index: usize,
    lane: OidfDriverLane,
}

impl Drop for PlannedPlan {
    fn drop(&mut self) {
        // Materialized plan configs own private client material independently
        // of the parent Matrix. ModuleDefinition clears its own variant values.
        zeroize_json_value(&mut self.config);
    }
}

struct PreparedRun {
    groups: Vec<GroupProgress>,
    plans: Vec<PlanReport>,
    planned: Vec<PlannedPlan>,
    suite_plan_ids: Vec<String>,
    errors: Vec<String>,
    unknown_declared_skip_modules: Vec<String>,
    matrix_expectations_satisfied: bool,
    all_selected_plan_definitions_enumerated: bool,
    auth_probe: Option<crate::client::AuthProbe>,
    current_profile: Option<String>,
    current_variant: Option<BTreeMap<String, String>>,
}

struct CreatedModule {
    group_index: usize,
    context: ModuleReportContext,
}

struct RunErrors {
    values: Vec<String>,
    control: RunControl,
}

impl RunErrors {
    fn new(values: Vec<String>, control: RunControl) -> Self {
        Self { values, control }
    }

    fn push(&mut self, error: String) {
        if self.control.is_fail_fast() {
            self.control.interrupt();
        }
        self.values.push(error);
    }

    fn push_fatal(&mut self, error: String) {
        self.control.interrupt();
        self.values.push(error);
    }

    fn into_inner(self) -> Vec<String> {
        self.values
    }
}

impl std::ops::Deref for RunErrors {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl ConformanceRunner {
    pub fn new(config: ConformanceRunConfig) -> Result<Self, OrchestrationError> {
        if config.poll_timeout.is_zero()
            || config.poll_timeout > MAX_POLL_TIMEOUT
            || !(1..=MAX_PARALLEL_JOBS).contains(&config.jobs)
            || (!config.automation.is_empty() && config.automation.len() != config.jobs)
        {
            return Err(OrchestrationError::InvalidInput);
        }
        if !plan_lanes_match_selected(&config.matrix, &config.plan_lanes)
            || !config
                .plan_lanes
                .keys()
                .eq(config.plan_resource_budgets.keys())
            || !resource_budget_totals_match(
                &config.plan_resource_budgets,
                &config.selected_resource_budget,
            )
        {
            return Err(OrchestrationError::InvalidInput);
        }
        validate_matrix_origins(
            &config.matrix,
            config.client.origin(),
            config.target_origin.as_ref(),
        )?;
        Ok(Self { config })
    }

    fn wait_for_state_interruptible<S: ProgressSink>(
        &self,
        sink: &mut S,
        test: &str,
        module_id: &str,
        states: &[&str],
    ) -> Result<Value, String> {
        let started = Instant::now();
        let deadline = started + self.config.poll_timeout;
        self.wait_for_state_until(sink, test, module_id, states, deadline, started)
    }

    fn wait_for_state_until<S: ProgressSink>(
        &self,
        sink: &mut S,
        test: &str,
        module_id: &str,
        states: &[&str],
        deadline: Instant,
        started: Instant,
    ) -> Result<Value, String> {
        loop {
            if self.config.control.is_interrupted() {
                return Err("run interrupted".to_owned());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SuiteClientError::Timeout.to_string());
            }
            sink.activity(&ProgressActivity::WaitingForSuite {
                test: test.to_owned(),
                elapsed_seconds: started.elapsed().as_secs(),
            });
            let slice = remaining.min(Duration::from_secs(5));
            match self.config.client.wait_for_state(module_id, states, slice) {
                Ok(state) => return Ok(state),
                Err(SuiteClientError::Timeout) => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    fn wait_for_runner_refresh(&self, deadline: Instant, context: &str) -> Result<(), String> {
        if self.config.control.is_interrupted() {
            return Err("run interrupted".to_owned());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("{context} WAITING drive timed out"));
        }
        thread::sleep(remaining.min(Duration::from_millis(200)));
        Ok(())
    }

    fn drive_ciba_waiting_interruptible<S: ProgressSink>(
        &self,
        sink: &mut S,
        approver: &Arc<CibaUserApprovalClient>,
        module: &ModuleDefinition,
        module_id: &str,
        initial: Value,
    ) -> Result<(Value, bool), String> {
        const USER_REJECTS_AUTHENTICATION: &str = "fapi-ciba-id1-user-rejects-authentication";

        let started = Instant::now();
        let deadline = started + self.config.poll_timeout;
        let approve = module.test_name != USER_REJECTS_AUTHENTICATION;
        let mut decided = BTreeSet::new();
        let mut observed = initial;
        let mut announced_log_inspection = false;
        let mut last_wait_report = None;
        loop {
            if self.config.control.is_interrupted() {
                return Err("run interrupted".to_owned());
            }
            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                return Err("CIBA user decision timed out".to_owned());
            }
            if is_terminal(&observed) {
                return Ok((observed, false));
            }
            if !is_waiting(&observed) {
                observed = self.wait_for_state_until(
                    sink,
                    &module.test_name,
                    module_id,
                    &["WAITING", "FINISHED", "INTERRUPTED"],
                    deadline,
                    started,
                )?;
                continue;
            }

            if !announced_log_inspection {
                sink.activity(&ProgressActivity::InspectingCibaRequest {
                    test: module.test_name.clone(),
                });
                announced_log_inspection = true;
            }
            let log = self
                .config
                .client
                .module_log(module_id)
                .map_err(|error| error.to_string())?;
            let mut made_decision = false;
            for auth_req_id in ciba_approval_requests(&log).map_err(|error| error.to_string())? {
                if decided.contains(&auth_req_id) {
                    continue;
                }
                sink.activity(&ProgressActivity::SubmittingCibaDecision {
                    test: module.test_name.clone(),
                    approve,
                });
                approver.decide(&auth_req_id, approve).map_err(|error| {
                    format!(
                        "CIBA user decision failed during {}",
                        error.approval_failure_stage()
                    )
                })?;
                decided.insert(auth_req_id);
                made_decision = true;
            }
            if !made_decision && !decided.is_empty() && suite_log_has_upload_placeholder(&log) {
                // A later WAITING state with no new CIBA request belongs to a
                // different Suite interaction, such as review evidence. Let
                // the normal interactive driver handle that boundary.
                return Ok((observed, true));
            }
            if !made_decision {
                emit_waiting_activity(sink, &module.test_name, started, &mut last_wait_report);
            }
            // A single Suite module can request more than one CIBA user
            // decision while remaining WAITING. Refresh both its state and log
            // after every decision instead of waiting exclusively for RUNNING,
            // otherwise the next auth_req_id can never be observed.
            self.wait_for_runner_refresh(deadline, "CIBA")?;
            observed = self
                .config
                .client
                .module_info(module_id)
                .map_err(|error| error.to_string())?;
        }
    }

    fn drive_vci_waiting_interruptible<S: ProgressSink>(
        &self,
        sink: &mut S,
        issuer: &Arc<Mutex<dyn OpenId4VciIssuerDriver>>,
        plan: &PlannedPlan,
        module: &ModuleDefinition,
        module_id: &str,
        initial: Value,
    ) -> Result<Value, String> {
        let started = Instant::now();
        let deadline = started + self.config.poll_timeout;
        let mut observed = initial;
        let mut first_round = true;
        let variant = runtime_variant_for_definition(plan, module);
        let mut last_wait_report = None;
        loop {
            if self.config.control.is_interrupted() {
                return Err("run interrupted".to_owned());
            }
            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                return Err("OpenID4VCI WAITING drive timed out".to_owned());
            }
            if !first_round {
                observed = self
                    .config
                    .client
                    .module_info(module_id)
                    .map_err(|error| error.to_string())?;
                if is_terminal(&observed) {
                    return Ok(observed);
                }
                if !is_waiting(&observed) {
                    observed = self.wait_for_state_until(
                        sink,
                        &module.test_name,
                        module_id,
                        &["WAITING", "FINISHED", "INTERRUPTED"],
                        deadline,
                        started,
                    )?;
                    if is_terminal(&observed) {
                        return Ok(observed);
                    }
                }
            }
            first_round = false;
            if !is_waiting(&observed) {
                return Ok(observed);
            }
            emit_waiting_activity(sink, &module.test_name, started, &mut last_wait_report);

            let runner = match self.config.client.runner_info(module_id) {
                Ok(runner) => runner,
                Err(SuiteClientError::HttpStatus(404)) => {
                    self.wait_for_runner_refresh(deadline, "OpenID4VCI")?;
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let module_context =
                OpenId4VciModule::new(module_id, &module.test_name, &variant, &plan.config, runner)
                    .map_err(|error| error.to_string())?;
            let drive_result = {
                let mut issuer = issuer
                    .lock()
                    .map_err(|_| "OpenID4VCI issuer lock failed".to_owned())?;
                issuer.drive(&module_context)
            };
            match drive_result {
                Ok(()) | Err(OpenId4VciError::Pending) => {}
                Err(error) => return Err(error.to_string()),
            }
            self.wait_for_runner_refresh(deadline, "OpenID4VCI")?;
        }
    }

    /// Once dispatch has stopped, refresh each created instance that still has
    /// no terminal Suite observation. This is the sole reconciliation path for
    /// browser errors and shared-interrupt workers, before cleanup can remove
    /// Suite evidence.
    fn collect_unreported_terminal_modules(
        &self,
        created_modules: &[CreatedModule],
        groups: &mut [GroupProgress],
        modules: &mut Vec<ModuleReport>,
        errors: &mut RunErrors,
        await_cancellation: bool,
    ) {
        let settled_reports = modules
            .iter()
            // A terminal observation is final. Deferred/external review owns
            // capture and retention metadata even before Suite termination.
            // Every other nonterminal snapshot must be refreshed: from_info
            // can classify a WAITING instance with a blocking log as Failed.
            .filter(|module| {
                module.terminal
                    || matches!(
                        module.outcome,
                        ModuleOutcome::DeferredReviewPending | ModuleOutcome::Review
                    )
            })
            .filter_map(|module| module.module_id.clone())
            .collect::<BTreeSet<_>>();
        for created in created_modules {
            let Some(module_id) = created.context.module_id.as_deref() else {
                continue;
            };
            if settled_reports.contains(module_id) {
                continue;
            }
            let mut info = match self.config.client.module_info(module_id) {
                Ok(info) => info,
                Err(error) => {
                    errors.push(format!(
                        "Suite module reconciliation info read failed for {module_id}: {error}"
                    ));
                    continue;
                }
            };
            if await_cancellation
                && !is_terminal(&info)
                && let Ok(settled) = self.config.client.wait_for_state(
                    module_id,
                    &["FINISHED", "INTERRUPTED"],
                    Duration::from_secs(5),
                )
            {
                info = settled;
            }
            let log = match self.config.client.module_log(module_id) {
                Ok(log) => log,
                Err(error) => {
                    errors.push(format!(
                        "Suite module reconciliation log read failed for {module_id}: {error}"
                    ));
                    continue;
                }
            };
            let mut context = created.context.clone();
            context.terminal = is_terminal(&info);
            let report = ModuleReport::from_info(context, info, log);
            if report.terminal {
                record_module_progress(&mut groups[created.group_index], &report);
            }
            // Replace a prior nonterminal snapshot for this exact instance.
            // A later cancellation can turn it into authoritative FINISHED or
            // INTERRUPTED state, but no result is invented when it does not.
            modules.retain(|module| module.module_id.as_deref() != Some(module_id));
            modules.push(report);
        }
    }

    pub fn run<S: ProgressSink>(&self, sink: &mut S) -> RunSummary {
        if self.config.jobs == 1 || self.config.matrix.document.plan_count() <= 1 {
            return self.run_serial(sink);
        }
        parallel::run(self, sink)
    }

    fn prepare_run<S: ProgressSink>(&self, sink: &mut S) -> PreparedRun {
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
                reviewed: 0,
                warnings: 0,
                skipped: 0,
                failed: 0,
                incomplete: 0,
                running: 0,
                remaining: 0,
            })
            .collect::<Vec<_>>();
        let mut plans = Vec::new();
        let mut planned = Vec::<PlannedPlan>::new();
        let mut suite_plan_ids = Vec::<String>::new();
        let mut errors = Vec::<String>::new();
        let mut unknown_declared_skip_modules = Vec::<String>::new();
        let mut matrix_expectations_satisfied = true;
        let selected_plan_count = self.config.matrix.document.plan_count();
        let mut enumerated_plan_count = 0usize;
        let mut auth_probe = None;
        let mut current_profile = None;
        let mut current_variant = None;
        let mut observed_modules = 0u32;

        sink.activity(&ProgressActivity::AuthenticatingSuite);
        match self.config.client.probe_auth() {
            Ok(probe) => auth_probe = Some(probe),
            Err(error) => errors.push(error.to_string()),
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
                    let runtime_variant = group.effective_runtime_variant(plan);
                    current_variant = Some(redacted_variant(&variant));
                    sink.activity(&ProgressActivity::CreatingSuitePlan {
                        current: enumerated_plan_count + 1,
                        total: selected_plan_count,
                        plan: plan.id.clone(),
                    });
                    let plan_create_intent =
                        if let Some(observer) = &self.config.suite_resource_observer {
                            let intent_id = uuid::Uuid::now_v7().to_string();
                            if let Err(error) =
                                observer.plan_create_intent(self.config.client.origin(), &intent_id)
                            {
                                errors.push(error);
                                groups[group_index].status = GroupStatus::Failed;
                                break 'create;
                            }
                            Some(intent_id)
                        } else {
                            None
                        };
                    let created =
                        match self
                            .config
                            .client
                            .create_plan(&plan.plan, &variant, &plan.config)
                        {
                            Ok(created) => created,
                            Err(error) => {
                                errors.push(error.to_string());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'create;
                            }
                        };
                    suite_plan_ids.push(created.id.clone());
                    // Persist the opaque ID before evaluating any returned
                    // definition or budget. A local rejection must never
                    // strand a durable create intent after the remote plan
                    // already exists.
                    if let (Some(observer), Some(intent_id)) =
                        (&self.config.suite_resource_observer, &plan_create_intent)
                        && let Err(error) = observer.plan_created(
                            self.config.client.origin(),
                            intent_id,
                            &created.id,
                        )
                    {
                        errors.push(error);
                        groups[group_index].status = GroupStatus::Failed;
                        break 'create;
                    }
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
                    // Validate the full Suite definition before any budget
                    // failure can stop phase 1. This keeps every signed skip
                    // declaration observable in the public evidence even
                    // when the Suite also exceeds a resource bound.
                    let mut module_name_counts = BTreeMap::<&str, usize>::new();
                    let mut definition_identities = BTreeSet::new();
                    let mut duplicate_definition_identities = Vec::new();
                    for module in &created.modules {
                        *module_name_counts
                            .entry(module.test_name.as_str())
                            .or_default() += 1;
                        if !definition_identities.insert((&module.test_name, &module.variant)) {
                            duplicate_definition_identities
                                .push(definition_identity(&plan.id, module));
                        }
                    }
                    let unknown_expected_skips = plan
                        .expected_results
                        .keys()
                        .filter(|test_name| {
                            module_name_counts.get(test_name.as_str()).copied() != Some(1)
                        })
                        .map(|test_name| format!("{}/{}", plan.id, test_name))
                        .collect::<Vec<_>>();
                    let expected_skip_definition_mismatch = !unknown_expected_skips.is_empty();
                    if expected_skip_definition_mismatch {
                        matrix_expectations_satisfied = false;
                        for identity in unknown_expected_skips {
                            errors.push(format!(
                                "signed Matrix expected SKIPPED module is not uniquely defined by Suite plan: {identity}"
                            ));
                            unknown_declared_skip_modules.push(identity);
                        }
                    }
                    enumerated_plan_count += 1;
                    let actual_modules = u32::try_from(defined_modules).ok();
                    let next_observed_modules =
                        actual_modules.and_then(|count| observed_modules.checked_add(count));
                    let over_budget = next_observed_modules
                        .is_none_or(|count| count > self.config.selected_resource_budget.modules);
                    if over_budget {
                        errors.push(
                            "Suite module allocation exceeds the artifact-wide resource bound"
                                .to_owned(),
                        );
                    }
                    let has_duplicate_definition = !duplicate_definition_identities.is_empty();
                    if has_duplicate_definition {
                        for identity in duplicate_definition_identities {
                            errors.push(format!(
                                "Suite plan defines an exact duplicate module definition: {identity}"
                            ));
                        }
                    }
                    if expected_skip_definition_mismatch || over_budget || has_duplicate_definition
                    {
                        groups[group_index].status = GroupStatus::Failed;
                        break 'create;
                    }
                    observed_modules = next_observed_modules
                        .expect("validated Suite module count must remain in range");
                    planned.push(PlannedPlan {
                        group_index,
                        matrix_plan_id: plan.id.clone(),
                        suite_plan_id: created.id,
                        plan_name: created.name,
                        variant,
                        runtime_variant,
                        expected_results: plan.expected_results.clone(),
                        modules: created.modules,
                        config: plan.config.clone(),
                        report_index,
                        lane: *self
                            .config
                            .plan_lanes
                            .get(&plan.id)
                            .expect("selected plan lanes were validated at construction"),
                    });
                }
            }
        }

        PreparedRun {
            groups,
            plans,
            planned,
            suite_plan_ids,
            errors,
            unknown_declared_skip_modules,
            matrix_expectations_satisfied,
            all_selected_plan_definitions_enumerated: enumerated_plan_count == selected_plan_count,
            auth_probe,
            current_profile,
            current_variant,
        }
    }

    fn run_serial<S: ProgressSink>(&self, sink: &mut S) -> RunSummary {
        let prepared = self.prepare_run(sink);
        self.run_prepared(sink, prepared, self.config.automation.first())
    }

    fn run_prepared<S: ProgressSink>(
        &self,
        sink: &mut S,
        prepared: PreparedRun,
        automation: Option<&ConformanceAutomation>,
    ) -> RunSummary {
        let PreparedRun {
            mut groups,
            mut plans,
            mut planned,
            suite_plan_ids,
            errors,
            unknown_declared_skip_modules,
            matrix_expectations_satisfied,
            all_selected_plan_definitions_enumerated,
            auth_probe,
            mut current_profile,
            mut current_variant,
        } = prepared;
        let mut errors = RunErrors::new(errors, self.config.control.clone());
        let mut modules = Vec::new();
        let mut created_modules = Vec::new();
        let mut cleanup = CleanupReport::default();
        let mut current_test = None;
        let retention_requested = self
            .config
            .suite_resource_observer
            .as_ref()
            .is_some_and(|observer| observer.retain_suite_plans_for_certification());

        // The denominator is now frozen. A plan-creation failure leaves the
        // successfully created subset visible, but no execution is attempted.
        emit_progress(
            sink,
            &groups,
            current_profile.clone(),
            current_variant.clone(),
            None,
        );

        // Phase 2: collect all terminal outcomes unless diagnostic fail-fast
        // or an unsafe execution boundary interrupts dispatch.
        if errors.is_empty() {
            'plans: for plan in &mut planned {
                if self.config.control.is_interrupted() {
                    break 'plans;
                }
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
                'execute: for module in &plan.modules {
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
                    sink.activity(&ProgressActivity::CreatingSuiteModule {
                        test: module.test_name.clone(),
                    });
                    let module_create_intent =
                        if let Some(observer) = &self.config.suite_resource_observer {
                            let intent_id = uuid::Uuid::now_v7().to_string();
                            if let Err(error) = observer
                                .module_create_intent(self.config.client.origin(), &intent_id)
                            {
                                errors.push_fatal(error);
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                            Some(intent_id)
                        } else {
                            None
                        };
                    let mut instance = match self
                        .config
                        .client
                        .create_module(&plan.suite_plan_id, module)
                    {
                        Ok(instance) => instance,
                        Err(error) => {
                            errors.push_fatal(error.to_string());
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    // Own the returned allocation before durable persistence can
                    // fail, so reconciliation and cleanup cannot lose its ID.
                    plans[plan.report_index].created_instances += 1;
                    created_modules.push(CreatedModule {
                        group_index,
                        context: ModuleReportContext {
                            matrix_plan_id: plan.matrix_plan_id.clone(),
                            suite_plan_id: plan.suite_plan_id.clone(),
                            module_id: Some(instance.id.clone()),
                            test_name: module.test_name.clone(),
                            variant: effective_module_identity_variant(plan, module),
                            terminal: false,
                            expected_result: plan.expected_results.get(&module.test_name).cloned(),
                        },
                    });
                    groups[group_index].running += 1;
                    groups[group_index].remaining = groups[group_index].remaining.saturating_sub(1);
                    if let (Some(observer), Some(intent_id)) =
                        (&self.config.suite_resource_observer, &module_create_intent)
                        && let Err(error) = observer.module_created(intent_id, &instance.id)
                    {
                        errors.push_fatal(error);
                        groups[group_index].status = GroupStatus::Failed;
                        break 'execute;
                    }
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
                    let alias = instance
                        .raw
                        .as_object_mut()
                        .and_then(|object| object.remove("alias"))
                        .and_then(|value| match value {
                            Value::String(alias) => Some(alias),
                            _ => None,
                        });
                    let initial = initial_runner_info(&mut instance.raw);
                    let initial = match initial {
                        Some(info) => Some(info),
                        None => match self.config.client.module_info(&instance.id) {
                            Ok(info) => Some(info),
                            Err(crate::client::SuiteClientError::HttpStatus(404)) => None,
                            Err(error) => {
                                errors.push(error.to_string());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        },
                    };
                    let mut observed = initial;
                    let mut external_review_pending = false;
                    let has_browser_config =
                        match module_has_browser_config(&plan.config, &module.test_name) {
                            Ok(value) => value,
                            Err(error) => {
                                errors.push(error);
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                    if observed.as_ref().is_some_and(is_configured) {
                        emit_progress(
                            sink,
                            &groups,
                            current_profile.clone(),
                            current_variant.clone(),
                            current_test.clone(),
                        );
                        if let Err(error) = self.config.client.start_module(&instance.id) {
                            errors.push(error.to_string());
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                        observed = None;
                    }

                    // A freshly-created runner may already report RUNNING
                    // before it reaches its interactive WAITING boundary.
                    // Do not skip automation merely because the first info
                    // document exists; only WAITING and terminal states are
                    // actionable here.
                    if needs_interactive_or_terminal_wait(observed.as_ref()) {
                        observed = match self.wait_for_state_interruptible(
                            sink,
                            &module.test_name,
                            &instance.id,
                            &["WAITING", "FINISHED", "INTERRUPTED"],
                        ) {
                            Ok(state) => Some(state),
                            Err(error) => {
                                errors.push(error);
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        };
                    }

                    if observed.as_ref().is_some_and(is_waiting) {
                        if plan.lane == OidfDriverLane::Ciba {
                            let Some(approver) =
                                automation.and_then(|automation| automation.ciba_approver.as_ref())
                            else {
                                errors.push("CIBA user automation is unavailable".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            match self.drive_ciba_waiting_interruptible(
                                sink,
                                approver,
                                module,
                                &instance.id,
                                observed.take().expect("waiting runner state"),
                            ) {
                                Ok((state, review_pending)) => {
                                    observed = Some(state);
                                    external_review_pending = review_pending;
                                }
                                Err(error) => {
                                    errors.push(error);
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            }
                        } else if plan.plan_name.starts_with("oid4vci-") {
                            let Some(issuer) =
                                automation.and_then(|automation| automation.issuer.as_ref())
                            else {
                                errors
                                    .push("OpenID4VCI issuer automation is unavailable".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            match self.drive_vci_waiting_interruptible(
                                sink,
                                issuer,
                                plan,
                                module,
                                &instance.id,
                                observed.take().expect("waiting runner state"),
                            ) {
                                Ok(state) => observed = Some(state),
                                Err(error) => {
                                    errors.push(error);
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            }
                        } else if is_openid4vp_verifier_plan(plan) {
                            let Some(verifier) =
                                automation.and_then(|automation| automation.verifier.as_ref())
                            else {
                                errors.push(
                                    "OpenID4VP verifier automation is unavailable".to_owned(),
                                );
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            let alias = alias
                                .as_deref()
                                .or_else(|| plan.config.get("alias").and_then(Value::as_str));
                            let Some(alias) = alias else {
                                errors.push("OpenID4VP module has no verifier alias".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            let haip = plan.plan_name == "oid4vp-1final-verifier-haip-test-plan";
                            let Some(binding) = self.config.binding.clone() else {
                                errors.push("OpenID4VP trust policy binding is missing".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            let request = match OpenId4VpStartRequest::new(
                                alias,
                                &module.test_name,
                                plan.variant.clone(),
                                haip,
                                binding,
                            ) {
                                Ok(request) => request,
                                Err(error) => {
                                    errors.push(error.to_string());
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            };
                            let mut verifier = match verifier.lock() {
                                Ok(verifier) => verifier,
                                Err(_) => {
                                    errors.push("OpenID4VP verifier lock failed".to_owned());
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            };
                            let presentation = match verifier.start(&request) {
                                Ok(presentation) => presentation,
                                Err(error) => {
                                    errors.push(error.to_string());
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            };
                            let submission_url = (|| -> Result<Url, String> {
                                let target_origin =
                                    self.config.target_origin.clone().ok_or_else(|| {
                                        "OpenID4VP target browser origin is unavailable".to_owned()
                                    })?;
                                let policy = BrowserPolicy::new(
                                    target_origin,
                                    self.config.client.origin().clone(),
                                );
                                let runner = self
                                    .config
                                    .client
                                    .runner_info(&instance.id)
                                    .map_err(|error| error.to_string())?;
                                let browser = runner.get("browser").ok_or_else(|| {
                                    "OpenID4VP runner has no URI-input request".to_owned()
                                })?;
                                BrowserRunnerState::parse(browser, &policy)
                                    .and_then(|state| {
                                        state.verifier_submission_url(
                                            &presentation.authorization_url,
                                        )
                                    })
                                    .map_err(|error| error.to_string())
                            })();
                            let presentation_delivery_url = match submission_url {
                                Ok(url) => url,
                                Err(error) => {
                                    errors.push(error);
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            };
                            match verifier.complete(&presentation, &presentation_delivery_url) {
                                Ok(_) => {}
                                Err(error) => {
                                    errors.push(error.to_string());
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            };
                        }
                    }

                    if !observed.as_ref().is_some_and(is_terminal)
                        && let Err(error) = self.wait_for_state_interruptible(
                            sink,
                            &module.test_name,
                            &instance.id,
                            &["FINISHED", "INTERRUPTED"],
                        )
                    {
                        errors.push(error);
                        groups[group_index].status = GroupStatus::Failed;
                        break 'execute;
                    }
                    let info = match self.config.client.module_info(&instance.id) {
                        Ok(info) => info,
                        Err(error) => {
                            errors.push(error.to_string());
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    let log = match self.config.client.module_log(&instance.id) {
                        Ok(log) => log,
                        Err(error) => {
                            errors.push(error.to_string());
                            groups[group_index].status = GroupStatus::Failed;
                            break 'execute;
                        }
                    };
                    let terminal = is_terminal(&info);
                    if !terminal && !external_review_pending {
                        errors.push("Suite module did not reach a terminal status".to_owned());
                        groups[group_index].status = GroupStatus::Failed;
                    } else if has_browser_config
                        && let Err(error) = validate_suite_browser_evidence(&log)
                    {
                        errors.push(error);
                        groups[group_index].status = GroupStatus::Failed;
                    }
                    let mut module_report = ModuleReport::from_info(
                        ModuleReportContext {
                            matrix_plan_id: plan.matrix_plan_id.clone(),
                            suite_plan_id: plan.suite_plan_id.clone(),
                            module_id: Some(instance.id.clone()),
                            test_name: module.test_name.clone(),
                            variant: effective_module_identity_variant(plan, module),
                            terminal,
                            expected_result: plan.expected_results.get(&module.test_name).cloned(),
                        },
                        info,
                        log,
                    );
                    if external_review_pending {
                        module_report.mark_external_review_pending();
                    }
                    let module_outcome = module_report.outcome;
                    let module_settled = terminal || external_review_pending;
                    if module_settled {
                        record_module_progress(&mut groups[group_index], &module_report);
                    }
                    modules.push(module_report);
                    if module_outcome == ModuleOutcome::Failed {
                        groups[group_index].status = GroupStatus::Failed;
                    } else if module_outcome == ModuleOutcome::Incomplete
                        && groups[group_index].status != GroupStatus::Failed
                    {
                        groups[group_index].status = GroupStatus::Incomplete;
                    }
                    emit_progress(
                        sink,
                        &groups,
                        current_profile.clone(),
                        current_variant.clone(),
                        current_test.clone(),
                    );
                    if !module_settled {
                        // The next module would reuse this plan's Suite alias.
                        // Keep an unsettled allocation at the plan boundary.
                        break 'execute;
                    }
                    if module_outcome == ModuleOutcome::Failed && self.config.control.is_fail_fast()
                    {
                        self.config.control.interrupt();
                        break 'execute;
                    }
                    if external_review_pending {
                        groups[group_index].status = GroupStatus::Review;
                        break 'execute;
                    }
                }
                if groups[group_index].status == GroupStatus::Running {
                    groups[group_index].status = if groups[group_index].failed > 0 {
                        GroupStatus::Failed
                    } else if groups[group_index].incomplete > 0 {
                        GroupStatus::Incomplete
                    } else if groups[group_index].reviewed > 0 {
                        GroupStatus::Review
                    } else if groups[group_index].warnings > 0 {
                        GroupStatus::Warning
                    } else if groups[group_index].skipped > 0 {
                        GroupStatus::Skipped
                    } else {
                        GroupStatus::Passed
                    };
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

        self.collect_unreported_terminal_modules(
            &created_modules,
            &mut groups,
            &mut modules,
            &mut errors,
            false,
        );

        // A terminal Suite module is already owned by its plan deletion.  A
        // cancellation after a terminal result can race the Suite's final
        // callback, while an unreported allocation still needs cancellation
        // before its plan is deleted.
        let defined_modules = plans.iter().map(|plan| plan.defined_modules).sum::<usize>();
        let created_instances = plans
            .iter()
            .map(|plan| plan.created_instances)
            .sum::<usize>();
        let terminal_modules = modules.iter().filter(|module| module.terminal).count();
        let all_modules_instantiated = defined_modules == created_instances;
        let deferred_review_modules = modules
            .iter()
            .filter(|module| module.deferred_review_pending.is_some())
            .count();
        let external_review_pending = modules
            .iter()
            .any(|module| !module.terminal && module.outcome == ModuleOutcome::Review);
        let all_modules_settled = all_modules_instantiated
            && terminal_modules
                .checked_add(deferred_review_modules)
                .is_some_and(|settled| settled == defined_modules);
        if let Err(error) = validate_review_screenshot_run_limit(&modules) {
            errors.push(error);
        }
        let outcomes = summarize_module_outcomes(&modules);
        let certification_retention = retention_requested
            && errors.is_empty()
            && all_selected_plan_definitions_enumerated
            && defined_modules > 0
            && all_modules_settled;
        let diagnostic_retention = self
            .config
            .suite_resource_observer
            .as_ref()
            .is_some_and(|observer| observer.retain_failed_suite_plans_for_diagnosis())
            && (!outcomes.failed_modules.is_empty()
                || external_review_pending
                || errors.iter().any(|error| error != "run interrupted"));
        let retained_suite_plan_ids = if certification_retention {
            suite_plan_ids.clone()
        } else if diagnostic_retention {
            plans
                .iter()
                .filter(|plan| plan.created_instances > 0)
                .filter_map(|plan| plan.suite_plan_id.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let cleanup_plan_ids = suite_plan_ids
            .iter()
            .filter(|plan_id| !retained_suite_plan_ids.contains(plan_id))
            .cloned()
            .collect::<Vec<_>>();
        if retained_suite_plan_ids.is_empty() {
            let created_module_ids = created_modules
                .iter()
                .filter_map(|created| created.context.module_id.clone())
                .collect::<Vec<_>>();
            let cancellable_module_ids = cancellable_module_ids(&created_module_ids, &modules);
            cleanup_all(
                &self.config.client,
                &cancellable_module_ids,
                &cleanup_plan_ids,
                self.config.suite_resource_observer.as_ref(),
                &mut cleanup,
                || {
                    self.collect_unreported_terminal_modules(
                        &created_modules,
                        &mut groups,
                        &mut modules,
                        &mut errors,
                        true,
                    );
                },
            );
        } else {
            cleanup_all(
                &self.config.client,
                &[],
                &cleanup_plan_ids,
                self.config.suite_resource_observer.as_ref(),
                &mut cleanup,
                || {
                    self.collect_unreported_terminal_modules(
                        &created_modules,
                        &mut groups,
                        &mut modules,
                        &mut errors,
                        true,
                    );
                },
            );
        }
        // Cancellation can settle modules that were still running when the
        // first stop snapshot was taken. Recompute final facts before the
        // report, while plan deletion has not yet discarded Suite evidence.
        let terminal_modules = modules.iter().filter(|module| module.terminal).count();
        let all_modules_terminal = all_modules_instantiated && terminal_modules == defined_modules;
        let deferred_review_modules = modules
            .iter()
            .filter(|module| module.deferred_review_pending.is_some())
            .count();
        let external_review_pending = modules
            .iter()
            .any(|module| !module.terminal && module.outcome == ModuleOutcome::Review);
        let all_modules_settled = all_modules_instantiated
            && terminal_modules
                .checked_add(deferred_review_modules)
                .is_some_and(|settled| settled == defined_modules);
        if let Err(error) = validate_review_screenshot_run_limit(&modules) {
            errors.push(error);
        }
        let outcomes = summarize_module_outcomes(&modules);
        let retention_candidate_settled =
            !retained_suite_plan_ids.is_empty() && cleanup.failures.is_empty();
        let cleanup_complete = retained_suite_plan_ids.is_empty() && cleanup.failures.is_empty();
        let matrix_expectations_satisfied = matrix_expectations_satisfied
            && all_selected_plan_definitions_enumerated
            && outcomes.unexpected_skipped_modules.is_empty()
            && unknown_declared_skip_modules.is_empty();
        let suite_pass = defined_modules > 0 && all_modules_terminal && outcomes.all_passed;
        let orchestration_integrity = OrchestrationIntegrity {
            defined_modules,
            created_instances,
            terminal_modules,
            all_modules_instantiated,
            all_modules_terminal,
            all_modules_settled,
            deferred_review_modules,
            cleanup_complete,
            retention_requested,
            retention_eligible: retention_candidate_settled,
            retention_candidate_settled,
            retention_committed: false,
            suite_resources_settled: suite_resources_settled(
                cleanup_complete,
                retention_candidate_settled,
            ),
        };
        let local_success = errors.is_empty()
            && orchestration_integrity.all_modules_instantiated
            && orchestration_integrity.all_modules_settled
            && orchestration_integrity.suite_resources_settled;
        let human_review_required = !outcomes.human_review_modules.is_empty();
        let snapshot = snapshot(groups, current_profile, current_variant, current_test);
        let report = ConformanceReport {
            excluded_plans: Vec::new(),
            fail_fast: self.config.control.is_fail_fast(),
            // Schema 5 adds explicit warning and execution-boundary facts.
            schema: 5,
            matrix_digest: self.config.matrix.digest.clone(),
            suite_origin: self.config.client.origin().to_string(),
            auth_probe,
            errors: errors.into_inner(),
            local_success,
            suite_pass,
            acceptance_pass: outcomes.acceptance_pass && matrix_expectations_satisfied,
            review_pending: deferred_review_modules > 0 || external_review_pending,
            human_review_required,
            human_review_modules: outcomes.human_review_modules,
            warning_modules: outcomes.warning_modules,
            deferred_review_modules: outcomes.deferred_review_modules,
            skipped_modules: outcomes.skipped_modules,
            expected_skipped_modules: outcomes.expected_skipped_modules,
            unexpected_skipped_modules: outcomes.unexpected_skipped_modules,
            unknown_declared_skip_modules,
            retained_suite_plan_ids,
            matrix_expectations_satisfied,
            failed_modules: outcomes.failed_modules,
            incomplete_modules: outcomes.incomplete_modules,
            orchestration_integrity,
            progress: snapshot,
            plans,
            modules,
            cleanup,
        };
        RunSummary { report }
    }
}

fn validate_suite_browser_evidence(log: &Value) -> Result<(), String> {
    let entries = log
        .as_array()
        .ok_or_else(|| "Suite browser log is not an array".to_owned())?;
    for entry in entries {
        if entry.get("result").and_then(Value::as_str) != Some("REVIEW") {
            continue;
        }
        if entry.get("upload").is_some() {
            return Err("Suite browser evidence placeholder remains unfilled".to_owned());
        }
        if let Some(source) = entry.get("page_source") {
            let source = source
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Suite browser evidence is empty".to_owned())?;
            let pattern = entry
                .get("matched_regexp")
                .and_then(Value::as_str)
                .ok_or_else(|| "Suite browser evidence has no matched expression".to_owned())?;
            // The Suite evaluates its expression against element text, not HTML.
            // Preserve that official assertion; do not re-run it on markup.
            if pattern.is_empty()
                || entry
                    .get("content_type")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || source.len() > 2 * 1024 * 1024
            {
                return Err("Suite browser evidence metadata is invalid".to_owned());
            }
        }
    }
    Ok(())
}

fn module_has_browser_config(plan_config: &Value, test_name: &str) -> Result<bool, String> {
    let override_browser = match plan_config.get("override") {
        None => false,
        Some(Value::Object(overrides)) => match overrides.get(test_name) {
            None => false,
            Some(Value::Object(module)) => module.get("browser").is_some(),
            Some(_) => return Err("module browser override is malformed".to_owned()),
        },
        Some(_) => return Err("browser override map is malformed".to_owned()),
    };
    Ok(override_browser || plan_config.get("browser").is_some())
}

/// `PlannedPlan` exists only after the signed Matrix was materialized and its
/// selected plan definitions were enumerated. The official OpenID4VP verifier
/// family is therefore a signed capability classification here, not a
/// suite/test-case exception (and never a p038-specific branch).
fn is_openid4vp_verifier_plan(plan: &PlannedPlan) -> bool {
    plan.plan_name.starts_with("oid4vp-1final-verifier")
}

pub(crate) fn validate_review_screenshot_run_limit(modules: &[ModuleReport]) -> Result<(), String> {
    let mut captures = 0usize;
    let mut bytes = 0usize;
    for module in modules {
        captures = captures
            .checked_add(module.review_screenshots.len())
            .and_then(|value| value.checked_add(module.review_screenshots_missing))
            .ok_or_else(|| "browser review screenshot limit exceeded".to_owned())?;
        if captures > MAX_REVIEW_SCREENSHOTS_PER_RUN {
            return Err("browser review screenshot limit exceeded".to_owned());
        }
        for screenshot in &module.review_screenshots {
            bytes = bytes
                .checked_add(screenshot.size)
                .ok_or_else(|| "browser review screenshot size limit exceeded".to_owned())?;
            if bytes > 32 * 1024 * 1024 {
                return Err("browser review screenshot size limit exceeded".to_owned());
            }
        }
    }
    Ok(())
}

fn plan_lanes_match_selected(
    matrix: &SelectedMatrix,
    plan_lanes: &BTreeMap<String, OidfDriverLane>,
) -> bool {
    let selected_plan_ids = matrix
        .document
        .groups
        .iter()
        .flat_map(|group| group.plans.iter().map(|plan| plan.id.as_str()))
        .collect::<BTreeSet<_>>();
    let selected_plan_count = matrix.document.plan_count();
    selected_plan_ids.len() == selected_plan_count
        && selected_plan_ids.len() == plan_lanes.len()
        && plan_lanes
            .keys()
            .all(|plan_id| selected_plan_ids.contains(plan_id.as_str()))
}

fn resource_budget_totals_match(
    plan_resource_budgets: &BTreeMap<String, OidfPlanResourceBudget>,
    selected_resource_budget: &OidfPlanResourceBudget,
) -> bool {
    let summed = plan_resource_budgets.values().try_fold(
        OidfPlanResourceBudget {
            modules: 0,
            clients: 0,
            wall_clock_seconds: 0,
        },
        |sum, budget| {
            Some(OidfPlanResourceBudget {
                modules: sum.modules.checked_add(budget.modules)?,
                clients: sum.clients.checked_add(budget.clients)?,
                wall_clock_seconds: sum
                    .wall_clock_seconds
                    .checked_add(budget.wall_clock_seconds)?,
            })
        },
    );
    summed.as_ref().is_some_and(|summed| {
        summed.modules <= selected_resource_budget.modules
            && summed.clients == selected_resource_budget.clients
            && summed.wall_clock_seconds == selected_resource_budget.wall_clock_seconds
    })
}

#[derive(Clone)]
pub struct RunSummary {
    pub report: ConformanceReport,
}

#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error("invalid conformance run input")]
    InvalidInput,
}

fn emit_waiting_activity<S: ProgressSink>(
    sink: &mut S,
    test: &str,
    started: Instant,
    last_reported: &mut Option<u64>,
) {
    let elapsed_seconds = started.elapsed().as_secs();
    if elapsed_seconds.is_multiple_of(5) && *last_reported != Some(elapsed_seconds) {
        sink.activity(&ProgressActivity::WaitingForSuite {
            test: test.to_owned(),
            elapsed_seconds,
        });
        *last_reported = Some(elapsed_seconds);
    }
}

fn emit_progress(
    sink: &mut impl ProgressSink,
    groups: &[GroupProgress],
    current_profile: Option<String>,
    current_variant: Option<BTreeMap<String, String>>,
    current_test: Option<String>,
) {
    sink.update(&ProgressEvent {
        snapshot: snapshot(
            groups.to_vec(),
            current_profile,
            current_variant,
            current_test,
        ),
    });
}

fn snapshot(
    groups: Vec<GroupProgress>,
    current_profile: Option<String>,
    current_variant: Option<BTreeMap<String, String>>,
    current_test: Option<String>,
) -> ProgressSnapshot {
    let mut snapshot = ProgressSnapshot {
        groups,
        current_profile,
        current_variant,
        current_test,
        ..ProgressSnapshot::default()
    };
    for group in &mut snapshot.groups {
        if group.status == GroupStatus::Failed && group.failed == 0 {
            group.status = GroupStatus::Incomplete;
        }
        snapshot.completed += group.completed;
        snapshot.total += group.total;
        snapshot.passed += group.passed;
        snapshot.reviewed += group.reviewed;
        snapshot.warnings += group.warnings;
        snapshot.skipped += group.skipped;
        snapshot.failed += group.failed;
        snapshot.incomplete += group.incomplete;
        snapshot.running += group.running;
        snapshot.remaining += group.remaining;
        match group.status {
            GroupStatus::Passed => snapshot.passed_groups += 1,
            GroupStatus::Review => snapshot.review_groups += 1,
            GroupStatus::Warning => snapshot.warning_groups += 1,
            GroupStatus::Skipped => snapshot.skipped_groups += 1,
            GroupStatus::Failed => snapshot.failed_groups += 1,
            GroupStatus::Incomplete => snapshot.incomplete_groups += 1,
            GroupStatus::Running => snapshot.running_groups += 1,
            GroupStatus::Remaining => snapshot.remaining_groups += 1,
        }
    }
    snapshot
}

fn record_module_progress(group: &mut GroupProgress, module: &ModuleReport) {
    group.running = group.running.saturating_sub(1);
    group.completed += 1;
    match module.outcome {
        ModuleOutcome::Passed => group.passed += 1,
        ModuleOutcome::Review | ModuleOutcome::DeferredReviewPending => group.reviewed += 1,
        ModuleOutcome::Warning => group.warnings += 1,
        ModuleOutcome::Skipped => group.skipped += 1,
        ModuleOutcome::Failed => group.failed += 1,
        ModuleOutcome::Incomplete => group.incomplete += 1,
    }
}

fn cleanup_all(
    client: &SuiteClient,
    module_ids: &[String],
    plan_ids: &[String],
    observer: Option<&Arc<dyn SuiteResourceObserver>>,
    report: &mut CleanupReport,
    after_cancel: impl FnOnce(),
) {
    // Cancellation is attempted before every plan deletion. A finalisation
    // race is an expected Suite outcome and is retained in `cancelled`.
    for module_id in module_ids {
        cancel_once(client, module_id, report);
    }
    after_cancel();
    for plan_id in plan_ids {
        match client.delete_plan(plan_id) {
            Ok(
                crate::client::DeleteOutcome::Deleted | crate::client::DeleteOutcome::AlreadyGone,
            ) => {
                report.deleted_plans.push(plan_id.clone());
                record_deleted_plan(observer, plan_id, report);
            }
            Ok(DeleteOutcome::Immutable) => {
                report.immutable_plans.push(plan_id.clone());
                report.failures.push(CleanupFailure {
                    operation: "delete-plan".to_owned(),
                    target: plan_id.clone(),
                    error:
                        "Suite retained an immutable plan without an authoritative cleanup receipt"
                            .to_owned(),
                });
            }
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
                        record_deleted_plan(observer, plan_id, report);
                    }
                    Ok(DeleteOutcome::Immutable) => {
                        report.immutable_plans.push(plan_id.clone());
                        report.failures.push(CleanupFailure {
                            operation: "delete-plan".to_owned(),
                            target: plan_id.clone(),
                            error: "Suite retained an immutable plan without an authoritative cleanup receipt"
                                .to_owned(),
                        });
                    }
                    Err(retry_error) => report.failures.push(CleanupFailure {
                        operation: "delete-plan".to_owned(),
                        target: plan_id.clone(),
                        error: format!("{first_error}; retry: {retry_error}"),
                    }),
                }
            }
        }
    }
}

fn record_deleted_plan(
    observer: Option<&Arc<dyn SuiteResourceObserver>>,
    plan_id: &str,
    report: &mut CleanupReport,
) {
    if let Some(observer) = observer
        && let Err(error) = observer.plan_deleted(plan_id)
    {
        report.failures.push(CleanupFailure {
            operation: "release-plan".to_owned(),
            target: plan_id.to_owned(),
            error,
        });
    }
}

fn cancellable_module_ids(module_ids: &[String], reports: &[ModuleReport]) -> Vec<String> {
    let terminal_module_ids = reports
        .iter()
        .filter(|module| module.terminal)
        .filter_map(|module| module.module_id.as_deref())
        .collect::<BTreeSet<_>>();
    module_ids
        .iter()
        .filter(|module_id| !terminal_module_ids.contains(module_id.as_str()))
        .cloned()
        .collect()
}

/// Idempotently clean only Suite resources durably recorded by the controller
/// before a crash.  The caller must bind the current authenticated Suite
/// client to the exact journal origin before invoking this function.
pub fn recover_suite_resources(
    client: &SuiteClient,
    state: &crate::recovery::SuiteRecoveryState,
) -> Result<(), String> {
    if client.origin().as_str() != state.origin {
        return Err("Suite recovery origin does not match the authenticated client".to_owned());
    }
    if !state.pending_create_intents.is_empty() {
        return Err(format!(
            "Suite recovery has {} unknown create allocation(s); the Suite API cannot safely reconcile them",
            state.pending_create_intents.len()
        ));
    }
    let mut cancellable_module_ids = Vec::with_capacity(state.module_ids.len());
    for module_id in &state.module_ids {
        match client.module_info(module_id) {
            Ok(info) if is_terminal(&info) => {}
            Ok(info) if status(&info).is_some() => cancellable_module_ids.push(module_id.clone()),
            Ok(_) => {
                return Err(format!(
                    "Suite recovery refused to cancel module {module_id}: current Suite state is missing"
                ));
            }
            Err(SuiteClientError::HttpStatus(404)) => {}
            Err(error) => {
                return Err(format!(
                    "Suite recovery refused to cancel module {module_id}: cannot read current Suite state: {error}"
                ));
            }
        }
    }
    let mut report = CleanupReport::default();
    cleanup_all(
        client,
        &cancellable_module_ids,
        &state.plan_ids,
        None,
        &mut report,
        || {},
    );
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Suite recovery cleanup failed for {} resource(s)",
            report.failures.len()
        ))
    }
}

fn cancel_once(client: &SuiteClient, module_id: &str, report: &mut CleanupReport) {
    match client.cancel_module(module_id) {
        Ok(_) => report.cancelled.push(module_id.to_owned()),
        Err(error) => report.failures.push(CleanupFailure {
            operation: "cancel-module".to_owned(),
            target: module_id.to_owned(),
            error: error.to_string(),
        }),
    }
}

fn runtime_variant_for_definition(
    plan: &PlannedPlan,
    module: &ModuleDefinition,
) -> BTreeMap<String, String> {
    let mut variant = plan.runtime_variant.clone();
    // The Suite definition fixes this concrete runner's behavior. It must
    // override the Matrix defaults used to create the containing plan.
    variant.extend(module.variant.clone());
    variant
}

fn effective_module_identity_variant(
    plan: &PlannedPlan,
    module: &ModuleDefinition,
) -> BTreeMap<String, String> {
    let mut variant = plan.variant.clone();
    // The containing plan supplies the baseline identity while a concrete
    // Suite definition may further specialize the otherwise identical test
    // name. Reports and review-capture receipts must bind the same effective
    // identity, with the Suite definition taking precedence.
    variant.extend(module.variant.clone());
    variant
}

fn definition_identity(matrix_plan_id: &str, module: &ModuleDefinition) -> String {
    if module.variant.is_empty() {
        return format!("{matrix_plan_id}/{}", module.test_name);
    }
    let variant = serde_json::to_string(&module.variant)
        .expect("BTreeMap<String, String> always serializes to JSON");
    format!("{matrix_plan_id}/{}?variant={variant}", module.test_name)
}

fn initial_runner_info(value: &mut Value) -> Option<Value> {
    value.get("status").or_else(|| value.get("state"))?;
    Some(std::mem::take(value))
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

fn is_terminal(value: &Value) -> bool {
    matches!(status(value), Some("FINISHED" | "INTERRUPTED"))
}

fn needs_interactive_or_terminal_wait(value: Option<&Value>) -> bool {
    value.is_none_or(|state| !is_waiting(state) && !is_terminal(state))
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
        // Browser command tuples have already passed the command schema. Their
        // selector argument may be the valid XPath `//*`; treating every `//`
        // command literal as a protocol-relative URL rejects the official
        // verification-evidence automation before any Suite resource exists.
        Value::String(text) if text.starts_with("//") && key != Some("commands") => Err(()),
        Value::String(text) if text.contains("://") => {
            let parsed = Url::parse(text).map_err(|_| ())?;
            let _host = parsed.host_str().ok_or(())?;
            let same_target = target.is_some_and(|origin| origin.allows(&parsed));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && same_target) {
                return Err(());
            }
            let same_suite = suite.same_origin_url(&parsed);
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

pub(crate) fn suite_resources_settled(
    cleanup_complete: bool,
    retention_candidate_settled: bool,
) -> bool {
    cleanup_complete || retention_candidate_settled
}

fn suite_log_has_upload_placeholder(value: &Value) -> bool {
    value.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry.get("upload").and_then(Value::as_str).is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_runner_info_transfers_the_response_instead_of_cloning_it() {
        let mut raw =
            serde_json::json!({"status":"WAITING", "exposed":{"payload":"kept allocation"}});
        let pointer = raw["exposed"]["payload"].as_str().unwrap().as_ptr();
        let info = initial_runner_info(&mut raw).unwrap();
        assert!(raw.is_null());
        assert_eq!(
            info["exposed"]["payload"].as_str().unwrap().as_ptr(),
            pointer
        );
        let mut missing = serde_json::json!({"id":"module"});
        assert!(initial_runner_info(&mut missing).is_none());
        assert_eq!(missing["id"], "module");
    }
    #[cfg(unix)]
    use crate::OpenId4VpCompletionOutcome;
    use crate::ReviewScreenshotReport;
    #[cfg(unix)]
    use crate::browser::OpenId4VpError;
    use crate::client::ClientConfig;
    use crate::credentials::BearerToken;
    use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
    use crate::report::DeferredReviewPending;
    use crate::transport::{HttpMethod, HttpRequest, HttpResponse, Transport, TransportError};
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    #[test]
    fn progress_does_not_report_orchestration_gaps_as_failed_tests() {
        let progress = snapshot(
            vec![GroupProgress {
                id: "vp".to_owned(),
                profile: "openid4vc".to_owned(),
                completed: 0,
                total: 1,
                status: GroupStatus::Failed,
                passed: 0,
                reviewed: 0,
                warnings: 0,
                skipped: 0,
                failed: 0,
                incomplete: 0,
                running: 1,
                remaining: 0,
            }],
            None,
            None,
            None,
        );
        assert_eq!(progress.failed_groups, 0);
        assert_eq!(progress.incomplete_groups, 1);
        assert_eq!(progress.groups[0].status, GroupStatus::Incomplete);
    }

    struct FixtureTransport {
        requests: Mutex<Vec<HttpRequest>>,
    }

    #[cfg(unix)]
    struct DeferredReviewTransport {
        requests: Mutex<Vec<(HttpMethod, String)>>,
        suite_origin: &'static str,
        test_name: &'static str,
        module_variant: BTreeMap<String, String>,
        info_after_capture: Value,
        wait_state_after_capture: Value,
        info_calls: AtomicUsize,
        upload_review: bool,
        uploaded: AtomicBool,
    }

    #[cfg(unix)]
    struct DeferredReviewVerifier {
        expected_delivery_host: &'static str,
        starts: usize,
        completes: usize,
        completion_outcome: OpenId4VpCompletionOutcome,
    }

    #[cfg(unix)]
    struct RetainingObserver;

    struct BudgetDriftTransport {
        requests: Mutex<Vec<(HttpMethod, String)>>,
    }

    struct DefinitionTransport {
        modules: Value,
        requests: Mutex<Vec<(HttpMethod, String)>>,
    }

    struct DuplicateDefinitionTransport {
        created_modules: AtomicUsize,
        module_info_calls: Mutex<BTreeMap<String, usize>>,
        requests: Mutex<Vec<(HttpMethod, String)>>,
        runner_variants: Mutex<Vec<String>>,
    }

    struct RecordingPlanObserver {
        persisted_plans: AtomicUsize,
        module_intents: AtomicUsize,
    }

    impl SuiteResourceObserver for RecordingPlanObserver {
        fn plan_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
            Ok(())
        }

        fn plan_created(
            &self,
            _origin: &Origin,
            _intent_id: &str,
            _plan_id: &str,
        ) -> Result<(), String> {
            self.persisted_plans.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn module_create_intent(&self, _origin: &Origin, _intent_id: &str) -> Result<(), String> {
            self.module_intents.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn module_created(&self, _intent_id: &str, _module_id: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[cfg(unix)]
    impl SuiteResourceObserver for RetainingObserver {
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

    struct RecoveryTransport {
        module_state: Value,
        module_status: u16,
        plan_status: u16,
        requests: Mutex<Vec<(HttpMethod, String)>>,
    }

    impl Transport for RecoveryTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let path = request.url().path().to_owned();
            self.requests
                .lock()
                .expect("recovery requests")
                .push((request.method(), path.clone()));
            let (status, body) = match (request.method(), path.as_str()) {
                (HttpMethod::Get, "/api/info/module-1") => {
                    (self.module_status, self.module_state.clone())
                }
                (HttpMethod::Delete, "/api/runner/module-1") => (200, serde_json::json!({})),
                (HttpMethod::Delete, "/api/plan/plan-1") => (self.plan_status, Value::Null),
                _ => (404, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("recovery json").into(),
            })
        }
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
                body: body.into(),
            })
        }
    }

    #[cfg(unix)]
    impl Transport for DeferredReviewTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let method = request.method();
            let path = request.url().path().to_owned();
            self.requests
                .lock()
                .expect("deferred review requests")
                .push((method, path.clone()));
            let (status, body) = match (method, path.as_str()) {
                (HttpMethod::Get, "/api/plan") => (
                    if request.header("Authorization").is_some() {
                        200
                    } else {
                        401
                    },
                    serde_json::json!({}),
                ),
                (HttpMethod::Post, "/api/plan") => (
                    201,
                    serde_json::json!({
                        "id":"suite-plan",
                        "name":"oid4vp-1final-verifier-test-plan",
                        "modules":[{
                            "testModule":self.test_name,
                            "variant":self.module_variant
                        }]
                    }),
                ),
                (HttpMethod::Post, "/api/runner") => {
                    (201, serde_json::json!({"id":"module-a","alias":"vp-alias"}))
                }
                (HttpMethod::Get, "/api/info/module-a") => {
                    let calls = self.info_calls.fetch_add(1, Ordering::SeqCst);
                    if self.uploaded.load(Ordering::SeqCst) {
                        (
                            200,
                            serde_json::json!({"status":"FINISHED","result":"REVIEW"}),
                        )
                    } else if calls == 0 {
                        (200, serde_json::json!({"status":"WAITING"}))
                    } else {
                        (200, self.info_after_capture.clone())
                    }
                }
                (HttpMethod::Get, "/api/runner/module-a") => (
                    200,
                    serde_json::json!({
                        "browser": {
                            "urls": [],
                            "visited": [],
                            "uriInputRequests": [{
                                "description": "Paste the verifier authorization request",
                                "submitUrl": format!(
                                    "{}/test/a/module-a/authorize",
                                    self.suite_origin
                                )
                            }]
                        }
                    }),
                ),
                (HttpMethod::Get, "/api/runner/module-a/wait-state") => {
                    if self.uploaded.load(Ordering::SeqCst) {
                        (200, serde_json::json!({"state":"FINISHED"}))
                    } else {
                        (200, self.wait_state_after_capture.clone())
                    }
                }
                (HttpMethod::Get, "/api/log/module-a/images") if self.upload_review => (
                    200,
                    serde_json::json!([{"_id":"log-a","upload":"placeholder-a"}]),
                ),
                (HttpMethod::Post, "/api/log/module-a/images/placeholder-a")
                    if self.upload_review =>
                {
                    self.uploaded.store(true, Ordering::SeqCst);
                    (200, serde_json::json!({"_id":"log-a","img":"stored"}))
                }
                (HttpMethod::Get, "/api/log/module-a") => (
                    200,
                    if self.upload_review {
                        serde_json::json!([{"result":"REVIEW","page_source":"<html>Deferred verification evidence</html>","content_type":"text/html","matched_regexp":".*Deferred verification evidence.*"}])
                    } else {
                        serde_json::json!([])
                    },
                ),
                // Suite cancellation accepts only 200, while plan deletion also
                // accepts 204. Keep this transport aligned with those distinct
                // production contracts so the negative cases exercise cleanup.
                (HttpMethod::Delete, "/api/runner/module-a") => (200, Value::Null),
                (HttpMethod::Delete, "/api/plan/suite-plan") => (204, Value::Null),
                _ => (404, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body)
                    .expect("deferred review JSON")
                    .into(),
            })
        }
    }

    #[cfg(unix)]
    impl OpenId4VpVerifier for DeferredReviewVerifier {
        fn start(
            &mut self,
            _request: &OpenId4VpStartRequest,
        ) -> Result<crate::browser::OpenId4VpPresentation, OpenId4VpError> {
            self.starts += 1;
            Ok(crate::browser::OpenId4VpPresentation::test_presentation())
        }

        fn complete(
            &mut self,
            _presentation: &crate::browser::OpenId4VpPresentation,
            delivery_url: &Url,
        ) -> Result<OpenId4VpCompletionOutcome, OpenId4VpError> {
            assert_eq!(delivery_url.host_str(), Some(self.expected_delivery_host));
            assert_eq!(delivery_url.path(), "/test/a/module-a/authorize");
            assert_eq!(delivery_url.query(), Some("request=opaque"));
            self.completes += 1;
            Ok(self.completion_outcome)
        }
    }

    impl Transport for BudgetDriftTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let method = request.method();
            let path = request.url().path().to_owned();
            self.requests
                .lock()
                .expect("budget drift requests")
                .push((method, path.clone()));
            let (status, body) = match (method, path.as_str()) {
                (HttpMethod::Get, "/api/plan") => (
                    if request.header("Authorization").is_some() {
                        200
                    } else {
                        401
                    },
                    serde_json::json!({}),
                ),
                (HttpMethod::Post, "/api/plan") => (
                    201,
                    serde_json::json!({
                        "id": "suite-plan",
                        "name": "plan",
                        "modules": [
                            {"testModule": "test-1"},
                            {"testModule": "test-2"}
                        ]
                    }),
                ),
                (HttpMethod::Delete, "/api/plan/suite-plan") => (204, Value::Null),
                _ => (500, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("budget drift json").into(),
            })
        }
    }

    impl Transport for DefinitionTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let method = request.method();
            let path = request.url().path().to_owned();
            self.requests
                .lock()
                .expect("definition requests")
                .push((method, path.clone()));
            let (status, body) = match (method, path.as_str()) {
                (HttpMethod::Get, "/api/plan") => (
                    if request.header("Authorization").is_some() {
                        200
                    } else {
                        401
                    },
                    serde_json::json!({}),
                ),
                (HttpMethod::Post, "/api/plan") => (
                    201,
                    serde_json::json!({
                        "id": "suite-plan",
                        "name": "plan",
                        "modules": self.modules.clone(),
                    }),
                ),
                (HttpMethod::Delete, "/api/plan/suite-plan") => (204, Value::Null),
                _ => (500, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("definition json").into(),
            })
        }
    }

    impl Transport for DuplicateDefinitionTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let method = request.method();
            let path = request.url().path().to_owned();
            if method == HttpMethod::Post && path == "/api/runner" {
                let variant = request
                    .url()
                    .query_pairs()
                    .find_map(|(key, value)| (key == "variant").then(|| value.into_owned()));
                if let Some(variant) = variant {
                    self.runner_variants
                        .lock()
                        .expect("duplicate definition variants")
                        .push(variant);
                }
            }
            self.requests
                .lock()
                .expect("duplicate definition requests")
                .push((method, path.clone()));
            let (status, body) = match (method, path.as_str()) {
                (HttpMethod::Get, "/api/plan") => (
                    if request.header("Authorization").is_some() {
                        200
                    } else {
                        401
                    },
                    serde_json::json!({}),
                ),
                (HttpMethod::Post, "/api/plan") => (
                    201,
                    serde_json::json!({
                        "id": "suite-plan",
                        "name": "oid4vci-issuer-test-plan",
                        "modules": [
                            {"testModule": "happy-flow", "variant": {
                                "credential_configuration": "plain",
                                "vci_authorization_code_flow_variant": "issuer_initiated"
                            }},
                            {"testModule": "happy-flow", "variant": {
                                "credential_configuration": "encrypted",
                                "vci_authorization_code_flow_variant": "issuer_initiated"
                            }}
                        ]
                    }),
                ),
                (HttpMethod::Post, "/api/runner") => {
                    let number = self.created_modules.fetch_add(1, Ordering::SeqCst) + 1;
                    (201, serde_json::json!({"id": format!("module-{number}")}))
                }
                (HttpMethod::Post, path) if path.starts_with("/api/runner/module-") => {
                    (200, serde_json::json!({}))
                }
                (HttpMethod::Get, path) if path.ends_with("/wait-state") => {
                    (200, serde_json::json!({"state":"FINISHED"}))
                }
                (HttpMethod::Get, path) if path.starts_with("/api/info/module-") => {
                    let calls = {
                        let mut calls = self
                            .module_info_calls
                            .lock()
                            .expect("duplicate definition module info");
                        let calls = calls.entry(path.to_owned()).or_default();
                        *calls += 1;
                        *calls
                    };
                    if calls == 1 {
                        (200, serde_json::json!({"status":"WAITING"}))
                    } else {
                        (
                            200,
                            serde_json::json!({"status":"FINISHED","result":"PASSED"}),
                        )
                    }
                }
                (HttpMethod::Get, path) if path.starts_with("/api/runner/module-") => {
                    (200, serde_json::json!({}))
                }
                (HttpMethod::Get, path) if path.starts_with("/api/log/module-") => {
                    (200, serde_json::json!([]))
                }
                (HttpMethod::Delete, "/api/plan/suite-plan") => (204, Value::Null),
                _ => (500, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body)
                    .expect("duplicate definition json")
                    .into(),
            })
        }
    }

    fn test_binding() -> ConformanceBinding {
        ConformanceBinding::openid4vc_trust_policy(
            "openid4vc-trust-policy:test",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("binding")
    }

    fn one_plan_matrix(config: Value) -> SelectedMatrix {
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
                    config,
                    variant: BTreeMap::new(),
                    expected_results: BTreeMap::new(),
                }],
            }],
        };
        SelectedMatrix {
            document,
            digest: "x".into(),
        }
    }

    fn budget(modules: u32, clients: u32, wall_clock_seconds: u64) -> OidfPlanResourceBudget {
        OidfPlanResourceBudget {
            modules,
            clients,
            wall_clock_seconds,
        }
    }

    fn one_plan_budgets() -> BTreeMap<String, OidfPlanResourceBudget> {
        BTreeMap::from([("p".to_owned(), budget(1, 1, 60))])
    }

    #[test]
    fn cleanup_cancels_only_modules_without_terminal_reports() {
        let terminal = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "plan".into(),
                suite_plan_id: "suite-plan".into(),
                module_id: Some("terminal".into()),
                test_name: "terminal-test".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"PASSED"}),
            serde_json::json!([]),
        );
        let incomplete = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "plan".into(),
                suite_plan_id: "suite-plan".into(),
                module_id: Some("incomplete".into()),
                test_name: "incomplete-test".into(),
                variant: BTreeMap::new(),
                terminal: false,
                expected_result: None,
            },
            serde_json::json!({"status":"RUNNING"}),
            serde_json::json!([]),
        );

        assert_eq!(
            cancellable_module_ids(
                &["terminal".into(), "incomplete".into(), "unobserved".into()],
                &[terminal, incomplete],
            ),
            vec!["incomplete", "unobserved"],
        );
    }

    fn recovery_client(transport: Arc<RecoveryTransport>) -> SuiteClient {
        SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport,
            ClientConfig::default(),
        )
        .expect("client")
    }

    #[test]
    fn recovery_queries_state_and_skips_terminal_modules() {
        let transport = Arc::new(RecoveryTransport {
            module_state: serde_json::json!({"state":"FINISHED"}),
            module_status: 200,
            plan_status: 204,
            requests: Mutex::new(Vec::new()),
        });
        let state = crate::recovery::SuiteRecoveryState {
            origin: "https://suite.example".to_owned(),
            plan_ids: vec!["plan-1".to_owned()],
            module_ids: vec!["module-1".to_owned()],
            pending_create_intents: Vec::new(),
            cleanup_complete: false,
        };

        recover_suite_resources(&recovery_client(transport.clone()), &state)
            .expect("terminal recovery cleanup");

        assert_eq!(
            *transport.requests.lock().expect("recovery requests"),
            vec![
                (HttpMethod::Get, "/api/info/module-1".to_owned()),
                (HttpMethod::Delete, "/api/plan/plan-1".to_owned()),
            ]
        );
    }

    #[test]
    fn recovery_fails_closed_when_module_state_cannot_be_observed() {
        let transport = Arc::new(RecoveryTransport {
            module_state: serde_json::json!({}),
            module_status: 200,
            plan_status: 204,
            requests: Mutex::new(Vec::new()),
        });
        let state = crate::recovery::SuiteRecoveryState {
            origin: "https://suite.example".to_owned(),
            plan_ids: vec!["plan-1".to_owned()],
            module_ids: vec!["module-1".to_owned()],
            pending_create_intents: Vec::new(),
            cleanup_complete: false,
        };

        let error = recover_suite_resources(&recovery_client(transport.clone()), &state)
            .expect_err("unobservable module state must retain the recovery journal");

        assert!(error.contains("current Suite state is missing"));
        assert_eq!(
            *transport.requests.lock().expect("recovery requests"),
            vec![(HttpMethod::Get, "/api/info/module-1".to_owned())]
        );
    }

    #[test]
    fn recovery_fails_closed_for_unknown_create_intent() {
        let transport = Arc::new(RecoveryTransport {
            module_state: serde_json::json!({"state":"RUNNING"}),
            module_status: 200,
            plan_status: 204,
            requests: Mutex::new(Vec::new()),
        });
        let state = crate::recovery::SuiteRecoveryState {
            origin: "https://suite.example".to_owned(),
            plan_ids: vec!["plan-1".to_owned()],
            module_ids: vec!["module-1".to_owned()],
            pending_create_intents: vec!["019ff000-8190-7393-8c33-ab4339c3d85e".to_owned()],
            cleanup_complete: false,
        };

        let error = recover_suite_resources(&recovery_client(transport.clone()), &state)
            .expect_err("unknown remote allocation must block recovery completion");

        assert!(error.contains("unknown create allocation"));
        assert!(
            transport
                .requests
                .lock()
                .expect("recovery requests")
                .is_empty()
        );
    }

    #[test]
    fn recovery_does_not_treat_immutable_plan_as_cleanup_complete() {
        let transport = Arc::new(RecoveryTransport {
            module_state: serde_json::json!({}),
            module_status: 200,
            plan_status: 405,
            requests: Mutex::new(Vec::new()),
        });
        let state = crate::recovery::SuiteRecoveryState {
            origin: "https://suite.example".to_owned(),
            plan_ids: vec!["plan-1".to_owned()],
            module_ids: Vec::new(),
            pending_create_intents: Vec::new(),
            cleanup_complete: false,
        };

        let error = recover_suite_resources(&recovery_client(transport.clone()), &state)
            .expect_err("an immutable plan has no authoritative cleanup receipt");

        assert!(error.contains("cleanup failed"));
        assert_eq!(
            *transport.requests.lock().expect("recovery requests"),
            vec![(HttpMethod::Delete, "/api/plan/plan-1".to_owned())]
        );
    }

    #[test]
    fn selected_plans_require_exact_signed_lane_coverage() {
        let selected = one_plan_matrix(serde_json::json!({}));
        assert!(plan_lanes_match_selected(
            &selected,
            &BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)])
        ));
        assert!(!plan_lanes_match_selected(&selected, &BTreeMap::new()));
        assert!(!plan_lanes_match_selected(
            &selected,
            &BTreeMap::from([("other".to_owned(), OidfDriverLane::Parallel)])
        ));
    }

    #[test]
    fn runner_construction_accepts_module_ceiling_and_rejects_inexact_client_or_time_budgets() {
        let selected = one_plan_matrix(serde_json::json!({}));
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(FixtureTransport {
                requests: Mutex::new(Vec::new()),
            }),
            ClientConfig::default(),
        )
        .expect("client");
        let make_config = |plan_resource_budgets, selected_resource_budget| ConformanceRunConfig {
            client: client.clone(),
            matrix: selected.clone(),
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets,
            selected_resource_budget,
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        };

        assert!(ConformanceRunner::new(make_config(BTreeMap::new(), budget(0, 0, 0))).is_err());
        assert!(
            ConformanceRunner::new(make_config(
                BTreeMap::from([("other".to_owned(), budget(1, 1, 60))]),
                budget(1, 1, 60)
            ))
            .is_err()
        );
        assert!(ConformanceRunner::new(make_config(one_plan_budgets(), budget(2, 1, 60))).is_ok());
        for inexact_total in [budget(1, 2, 60), budget(1, 1, 61)] {
            assert!(
                ConformanceRunner::new(make_config(one_plan_budgets(), inexact_total)).is_err()
            );
        }

        let mut overflow_matrix = selected.clone();
        let mut second_plan = overflow_matrix.document.groups[0].plans[0].clone();
        second_plan.id = "q".to_owned();
        overflow_matrix.document.groups[0].plans.push(second_plan);
        assert!(
            ConformanceRunner::new(ConformanceRunConfig {
                client,
                matrix: overflow_matrix,
                target_origin: None,
                binding: Some(test_binding()),
                poll_timeout: Duration::from_secs(1),
                control: RunControl::default(),
                plan_lanes: BTreeMap::from([
                    ("p".to_owned(), OidfDriverLane::Parallel),
                    ("q".to_owned(), OidfDriverLane::Parallel),
                ]),
                plan_resource_budgets: BTreeMap::from([
                    ("p".to_owned(), budget(u32::MAX, 1, 60)),
                    ("q".to_owned(), budget(1, 1, 60)),
                ]),
                selected_resource_budget: budget(u32::MAX, 2, 120),
                jobs: 1,

                automation: Vec::new(),
                suite_resource_observer: None,
            })
            .is_err()
        );
    }

    #[test]
    fn suite_module_count_over_budget_fails_before_runner_creation_and_cleans_plan() {
        let transport = Arc::new(BudgetDriftTransport {
            requests: Mutex::new(Vec::new()),
        });
        let observer = Arc::new(RecordingPlanObserver {
            persisted_plans: AtomicUsize::new(0),
            module_intents: AtomicUsize::new(0),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: one_plan_matrix(serde_json::json!({})),
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: one_plan_budgets(),
            selected_resource_budget: budget(1, 1, 60),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: Some(observer.clone()),
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert_eq!(
            report.errors,
            vec!["Suite module allocation exceeds the artifact-wide resource bound".to_owned()]
        );
        assert_eq!(report.progress.groups[0].status, GroupStatus::Incomplete);
        assert_eq!(report.plans.len(), 1);
        assert_eq!(report.plans[0].defined_modules, 2);
        assert_eq!(report.plans[0].created_instances, 0);
        assert_eq!(report.orchestration_integrity.created_instances, 0);
        assert!(report.modules.is_empty());
        assert_eq!(report.cleanup.deleted_plans, vec!["suite-plan".to_owned()]);
        assert!(report.cleanup.failures.is_empty());
        assert_eq!(observer.persisted_plans.load(Ordering::SeqCst), 1);
        assert_eq!(observer.module_intents.load(Ordering::SeqCst), 0);
        let requests = transport.requests.lock().expect("budget drift requests");
        assert_eq!(
            requests
                .iter()
                .filter(|(method, path)| *method == HttpMethod::Post && path == "/api/runner")
                .count(),
            0
        );
        assert!(requests.iter().any(|(method, path)| {
            *method == HttpMethod::Delete && path == "/api/plan/suite-plan"
        }));
    }

    #[test]
    fn same_name_distinct_variants_create_exact_suite_instances_and_runtime_overlays() {
        let transport = Arc::new(DuplicateDefinitionTransport {
            created_modules: AtomicUsize::new(0),
            module_info_calls: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(Vec::new()),
            runner_variants: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let mut matrix = one_plan_matrix(serde_json::json!({}));
        let matrix_plan = &mut matrix.document.groups[0].plans[0];
        matrix_plan.plan = "oid4vci-issuer-test-plan".to_owned();
        matrix_plan.variant = BTreeMap::from([
            (
                "vci_authorization_code_flow_variant".to_owned(),
                "wallet_initiated".to_owned(),
            ),
            (
                "credential_configuration".to_owned(),
                "matrix-default".to_owned(),
            ),
            ("matrix_only".to_owned(), "kept".to_owned()),
        ]);
        let issuer = Arc::new(Mutex::new(RecordingIssuer::default()));
        let issuer_driver: Arc<Mutex<dyn OpenId4VciIssuerDriver>> = issuer.clone();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix,
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: BTreeMap::from([("p".to_owned(), budget(2, 1, 60))]),
            selected_resource_budget: budget(2, 1, 60),
            jobs: 1,

            automation: vec![ConformanceAutomation {
                issuer: Some(issuer_driver),
                ..ConformanceAutomation::default()
            }],
            suite_resource_observer: None,
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert!(report.errors.is_empty());
        assert!(report.local_success);
        assert!(report.orchestration_integrity.all_modules_terminal);
        assert_eq!(report.modules.len(), 2);
        assert_eq!(
            report
                .modules
                .iter()
                .map(|module| module.test_name.as_str())
                .collect::<Vec<_>>(),
            ["happy-flow", "happy-flow"]
        );
        assert_eq!(
            report
                .modules
                .iter()
                .filter_map(|module| module.module_id.as_deref())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["module-1", "module-2"])
        );
        assert_eq!(
            report
                .modules
                .iter()
                .map(|module| module
                    .variant
                    .get("credential_configuration")
                    .map(String::as_str))
                .collect::<Vec<_>>(),
            [Some("plain"), Some("encrypted")]
        );
        assert_eq!(report.cleanup.deleted_plans, ["suite-plan"]);
        assert_eq!(
            transport
                .requests
                .lock()
                .expect("duplicate definition requests")
                .iter()
                .filter(|(method, path)| *method == HttpMethod::Post && path == "/api/runner")
                .count(),
            2
        );
        assert_eq!(
            transport
                .runner_variants
                .lock()
                .expect("duplicate definition variants")
                .as_slice(),
            [
                "{\"credential_configuration\":\"plain\",\"vci_authorization_code_flow_variant\":\"issuer_initiated\"}",
                "{\"credential_configuration\":\"encrypted\",\"vci_authorization_code_flow_variant\":\"issuer_initiated\"}"
            ]
        );
        let observed_variants = issuer.lock().expect("recording issuer").variants.clone();
        assert_eq!(observed_variants.len(), 2);
        assert!(observed_variants.iter().all(|variant| {
            variant.get("matrix_only").map(String::as_str) == Some("kept")
                && variant
                    .get("vci_authorization_code_flow_variant")
                    .map(String::as_str)
                    == Some("issuer_initiated")
        }));
        assert_eq!(
            observed_variants
                .iter()
                .map(|variant| variant.get("credential_configuration").map(String::as_str))
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([Some("plain"), Some("encrypted")])
        );
    }

    #[test]
    fn bundled_plain_vci_preflight_accepts_suite_without_encryption_test() {
        let bundled = crate::bundled_oidf_matrix().unwrap();
        let group = bundled
            .groups
            .iter()
            .find(|g| g.id == "openid4vc-vci")
            .unwrap();
        for id in [
            "openid4vc-vci-p028",
            "openid4vc-vci-p031",
            "openid4vc-vci-p032",
        ] {
            let plan = group.plans.iter().find(|p| p.id == id).unwrap();
            let transport = Arc::new(DefinitionTransport {
                // Suite 5.3.3 excludes the encryption-algorithm test from plain variants.
                modules: serde_json::json!([{"testModule": "oid4vci-1_0-issuer-metadata-test"}]),
                requests: Mutex::new(Vec::new()),
            });
            let client = SuiteClient::with_transport(
                Origin::parse("https://suite.example").unwrap(),
                Some(BearerToken::new("suite-token").unwrap()),
                transport,
                ClientConfig::default(),
            )
            .unwrap();
            let mut matrix = one_plan_matrix(serde_json::json!({}));
            matrix.document.groups[0].plans[0].expected_results = plan.expected_results.clone();
            let runner = ConformanceRunner::new(ConformanceRunConfig {
                client,
                matrix,
                target_origin: None,
                binding: Some(test_binding()),
                poll_timeout: Duration::from_secs(1),
                control: RunControl::default(),
                plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
                plan_resource_budgets: one_plan_budgets(),
                selected_resource_budget: budget(1, 1, 60),
                jobs: 1,
                automation: Vec::new(),
                suite_resource_observer: None,
            })
            .unwrap();

            let prepared = runner.prepare_run(&mut ());
            assert!(prepared.errors.is_empty(), "{id}: {:?}", prepared.errors);
            assert!(prepared.matrix_expectations_satisfied);
            assert_eq!(prepared.planned.len(), 1);
        }
    }

    #[test]
    fn duplicate_signed_skip_definition_stops_before_module_creation() {
        let transport = Arc::new(DefinitionTransport {
            modules: serde_json::json!([
                {"testModule": "declared-skip", "variant": {"credential_configuration": "plain"}},
                {"testModule": "declared-skip", "variant": {"credential_configuration": "encrypted"}}
            ]),
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let mut matrix = one_plan_matrix(serde_json::json!({}));
        matrix.document.groups[0].plans[0]
            .expected_results
            .insert("declared-skip".to_owned(), "SKIPPED".to_owned());
        let observer = Arc::new(RecordingPlanObserver {
            persisted_plans: AtomicUsize::new(0),
            module_intents: AtomicUsize::new(0),
        });
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix,
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: BTreeMap::from([("p".to_owned(), budget(2, 1, 60))]),
            selected_resource_budget: budget(2, 1, 60),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: Some(observer.clone()),
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert!(!report.matrix_expectations_satisfied);
        assert!(!report.acceptance_pass);
        assert_eq!(report.unknown_declared_skip_modules, ["p/declared-skip"]);
        assert!(report.errors.iter().any(|error| {
            error
                == "signed Matrix expected SKIPPED module is not uniquely defined by Suite plan: p/declared-skip"
        }));
        assert_eq!(report.cleanup.deleted_plans, ["suite-plan"]);
        assert!(report.modules.is_empty());
        assert_eq!(observer.persisted_plans.load(Ordering::SeqCst), 1);
        assert_eq!(observer.module_intents.load(Ordering::SeqCst), 0);
        assert_eq!(
            transport
                .requests
                .lock()
                .expect("definition requests")
                .iter()
                .filter(|(method, path)| *method == HttpMethod::Post && path == "/api/runner")
                .count(),
            0,
        );
    }

    #[test]
    fn exact_duplicate_suite_definition_with_reordered_variant_keys_stops_before_creation() {
        let transport = Arc::new(DefinitionTransport {
            modules: serde_json::json!([
                {"testModule": "duplicate", "variant": {"a": "one", "b": "two"}},
                {"testModule": "duplicate", "variant": {"b": "two", "a": "one"}}
            ]),
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: one_plan_matrix(serde_json::json!({})),
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: BTreeMap::from([("p".to_owned(), budget(2, 1, 60))]),
            selected_resource_budget: budget(2, 1, 60),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert!(report.errors.iter().any(|error| {
            error
                == "Suite plan defines an exact duplicate module definition: p/duplicate?variant={\"a\":\"one\",\"b\":\"two\"}"
        }));
        assert_eq!(report.plans[0].defined_modules, 2);
        assert_eq!(report.plans[0].created_instances, 0);
        assert!(report.modules.is_empty());
        assert_eq!(
            transport
                .requests
                .lock()
                .expect("definition requests")
                .iter()
                .filter(|(method, path)| *method == HttpMethod::Post && path == "/api/runner")
                .count(),
            0
        );
    }

    struct PlanCreateFailureTransport {
        requests: Mutex<Vec<(HttpMethod, String)>>,
    }

    impl Transport for PlanCreateFailureTransport {
        fn send(&self, request: HttpRequest, _max: usize) -> Result<HttpResponse, TransportError> {
            let method = request.method();
            let path = request.url().path().to_owned();
            self.requests
                .lock()
                .expect("plan-create failure requests")
                .push((method, path.clone()));
            let (status, body) = match (method, path.as_str()) {
                (HttpMethod::Get, "/api/plan") => (
                    if request.header("Authorization").is_some() {
                        200
                    } else {
                        401
                    },
                    serde_json::json!({}),
                ),
                (HttpMethod::Post, "/api/plan") => (500, serde_json::json!({})),
                _ => (500, serde_json::json!({})),
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: serde_json::to_vec(&body)
                    .expect("plan-create failure json")
                    .into(),
            })
        }
    }

    #[test]
    fn plan_creation_failure_marks_matrix_expectations_unverifiable() {
        let transport = Arc::new(PlanCreateFailureTransport {
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: one_plan_matrix(serde_json::json!({})),
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: one_plan_budgets(),
            selected_resource_budget: budget(1, 1, 60),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert!(!report.matrix_expectations_satisfied);
        assert!(!report.acceptance_pass);
        assert!(report.unknown_declared_skip_modules.is_empty());
        assert!(report.errors.iter().any(|error| error.contains("500")));
        let requests = transport
            .requests
            .lock()
            .expect("plan-create failure requests");
        assert!(
            requests
                .iter()
                .any(|(method, path)| { *method == HttpMethod::Post && path == "/api/plan" })
        );
        assert!(!requests.iter().any(|(method, path)| {
            *method == HttpMethod::Delete && path.starts_with("/api/plan/")
        }));
    }

    #[test]
    fn origin_validation_rejects_cross_origin_config() {
        let selected = one_plan_matrix(serde_json::json!({"audience":"https://evil.example"}));
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
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
                binding: Some(test_binding()),
                poll_timeout: Duration::from_secs(1),
                control: RunControl::default(),
                plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
                plan_resource_budgets: one_plan_budgets(),
                selected_resource_budget: budget(1, 1, 60),
                jobs: 1,

                automation: Vec::new(),
                suite_resource_observer: None,
            })
            .is_err()
        );
    }

    #[test]
    fn origin_validation_reuses_suite_and_target_origin_rules() {
        let suite = Origin::parse("https://[::1]:8443").unwrap();
        let target = BrowserTargetOrigin::parse("http://[::1]:8080").unwrap();
        for value in ["https://[::1]:8443/test/a", "http://[::1]:8080/callback"] {
            assert!(
                validate_value_origins(
                    &serde_json::json!({"audience": value}),
                    &suite,
                    Some(&target),
                    None
                )
                .is_ok()
            );
        }
        for value in [
            "https://[::1]:9443/test/a",
            "https://user@[::1]:8443/test/a",
            "http://[::1]:8081/callback",
            "http://user@[::1]:8080/callback",
        ] {
            assert!(
                validate_value_origins(
                    &serde_json::json!({"audience": value}),
                    &suite,
                    Some(&target),
                    None
                )
                .is_err()
            );
        }
    }

    #[test]
    fn origin_validation_accepts_suite_verification_evidence_glob() {
        let suite = Origin::parse("https://suite.example").expect("origin");
        let parsed =
            Url::parse("https://suite.example/test/a/*/verification-evidence").expect("glob URL");
        assert!(suite.same_origin_url(&parsed));
        let config = serde_json::json!({
            "browser": [{
                "match": "https://suite.example/test/a/*/verification-evidence",
                "tasks": [{
                    "match": "https://suite.example/test/a/*/verification-evidence",
                    "commands": [[
                        "wait", "xpath", "//*", 10,
                        ".*Deferred verification evidence.*",
                        "update-image-placeholder"
                    ]]
                }]
            }]
        });
        assert_eq!(validate_value_origins(&config, &suite, None, None), Ok(()));
    }

    #[test]
    fn origin_validation_rejects_untrusted_external_urls() {
        let suite = Origin::parse("https://suite.example").expect("origin");
        let callback = "https://callback.oidf.example/approval";
        assert_eq!(
            validate_value_origins(
                &serde_json::json!({"untrusted_url": callback}),
                &suite,
                None,
                None,
            ),
            Err(())
        );
    }

    #[test]
    fn failed_official_result_is_preserved_and_rejected() {
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
            serde_json::json!({"status":"FINISHED","result":"FAILED"}),
            serde_json::json!([]),
        );
        assert_eq!(report.official_result.as_deref(), Some("FAILED"));
        assert_eq!(report.outcome, ModuleOutcome::Failed);
    }

    #[test]
    fn ordinary_errors_are_collected_without_interrupt_and_fail_fast_is_explicit() {
        let control = RunControl::with_fail_fast(false);
        let mut errors = RunErrors::new(Vec::new(), control.clone());
        errors.push("terminal Suite failure".to_owned());
        assert_eq!(errors.values, ["terminal Suite failure"]);
        assert!(!control.is_interrupted());

        let control = RunControl::with_fail_fast(true);
        let mut errors = RunErrors::new(Vec::new(), control.clone());
        errors.push("terminal Suite failure".to_owned());
        assert!(control.is_interrupted());
        assert_eq!(errors.values, ["terminal Suite failure"]);
    }

    #[test]
    fn review_is_distinct_from_pass_and_requires_human_follow_up() {
        let report = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m".into()),
                test_name: "oidcc-review".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"REVIEW"}),
            serde_json::json!([{"result":"REVIEW"}]),
        );
        assert_eq!(report.outcome, ModuleOutcome::Review);
        assert!(report.human_review_required);
    }

    #[test]
    fn exact_skipped_remains_skipped_with_or_without_a_matrix_annotation() {
        let expected = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m".into()),
                test_name: "oidcc-skip".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: Some("SKIPPED".into()),
            },
            serde_json::json!({"status":"FINISHED","result":"SKIPPED"}),
            serde_json::json!([]),
        );
        assert_eq!(expected.outcome, ModuleOutcome::Skipped);

        let unexpected = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m".into()),
                test_name: "oidcc-other".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"SKIPPED"}),
            serde_json::json!([]),
        );
        assert_eq!(unexpected.outcome, ModuleOutcome::Skipped);
    }

    #[test]
    fn review_with_a_warning_remains_review_and_requires_human_follow_up() {
        let report = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m".into()),
                test_name: "oidcc-review".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"REVIEW"}),
            serde_json::json!([{"result":"WARNING"}]),
        );
        assert_eq!(report.outcome, ModuleOutcome::Review);
        assert!(report.human_review_required);
        assert!(report.blocking_log_results.is_empty());
        assert_eq!(report.advisory_log_results, vec!["WARNING"]);
    }

    #[test]
    fn warning_is_distinct_from_review_but_failure_log_is_failed() {
        let warning = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m-warning".into()),
                test_name: "oidcc-warning".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"WARNING"}),
            serde_json::json!([{"result":"WARNING"}]),
        );
        assert_eq!(warning.outcome, ModuleOutcome::Warning);
        assert!(warning.human_review_required);
        assert!(warning.blocking_log_results.is_empty());
        assert_eq!(warning.advisory_log_results, vec!["WARNING"]);

        let failure = ModuleReport::from_info(
            ModuleReportContext {
                matrix_plan_id: "p".into(),
                suite_plan_id: "s".into(),
                module_id: Some("m-failure".into()),
                test_name: "oidcc-failure".into(),
                variant: BTreeMap::new(),
                terminal: true,
                expected_result: None,
            },
            serde_json::json!({"status":"FINISHED","result":"WARNING"}),
            serde_json::json!([{"result":"WARNING"},{"result":"FAILURE"}]),
        );
        assert_eq!(failure.outcome, ModuleOutcome::Failed);
        assert!(!failure.human_review_required);
        assert_eq!(failure.blocking_log_results, vec!["FAILURE"]);
        assert_eq!(failure.advisory_log_results, vec!["WARNING"]);
    }

    #[test]
    fn interrupted_wait_stops_before_the_next_suite_request() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            None,
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let control = RunControl::default();
        control.interrupt();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(30),
            control,
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");

        assert_eq!(
            runner
                .wait_for_state_interruptible(&mut (), "test", "module", &["FINISHED"])
                .expect_err("interrupt must stop the wait"),
            "run interrupted"
        );
        assert!(transport.requests.lock().expect("lock").is_empty());
    }

    struct ReconciliationTransport;

    impl Transport for ReconciliationTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let body = match request.url().path() {
                "/api/info/passed" => serde_json::json!({"status":"FINISHED","result":"PASSED"}),
                "/api/info/interrupted" => serde_json::json!({"status":"INTERRUPTED"}),
                "/api/info/failed" => serde_json::json!({"status":"FINISHED","result":"FAILED"}),
                "/api/info/waiting" => serde_json::json!({"status":"WAITING"}),
                "/api/log/failed" => serde_json::json!([
                    {"result":"WARNING", "src":"ValidateDirectPostResponse"},
                    {"result":"FAILURE", "src":"EnsureHttpStatusCodeIs200"}
                ]),
                _ => serde_json::json!([]),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("json").into(),
            })
        }
    }

    #[test]
    fn stopped_run_reconciles_created_modules_without_inventing_a_terminal_state() {
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(ReconciliationTransport),
            ClientConfig::default(),
        )
        .expect("client");
        let control = RunControl::default();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(30),
            control: control.clone(),
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");
        control.interrupt();
        let mut groups = vec![GroupProgress {
            id: "g".into(),
            profile: "oidc".into(),
            completed: 0,
            total: 4,
            status: GroupStatus::Running,
            passed: 0,
            reviewed: 0,
            warnings: 0,
            skipped: 0,
            failed: 0,
            incomplete: 0,
            running: 4,
            remaining: 0,
        }];
        let created_modules = ["passed", "interrupted", "failed", "waiting"]
            .into_iter()
            .map(|module_id| CreatedModule {
                group_index: 0,
                context: ModuleReportContext {
                    matrix_plan_id: "p".into(),
                    suite_plan_id: "suite-plan".into(),
                    module_id: Some(module_id.to_owned()),
                    test_name: module_id.to_owned(),
                    variant: BTreeMap::new(),
                    terminal: false,
                    expected_result: None,
                },
            })
            .collect::<Vec<_>>();
        let mut modules = Vec::new();
        let mut errors = RunErrors::new(Vec::new(), control);

        runner.collect_unreported_terminal_modules(
            &created_modules,
            &mut groups,
            &mut modules,
            &mut errors,
            true,
        );

        assert!(errors.is_empty(), "{:?}", errors.values);
        assert_eq!(modules.len(), 4);
        assert_eq!(groups[0].completed, 3);
        assert_eq!(groups[0].running, 1);
        assert_eq!(groups[0].passed, 1);
        assert_eq!(groups[0].failed, 1);
        assert_eq!(groups[0].incomplete, 1);
        let outcomes = summarize_module_outcomes(&modules);
        assert_eq!(outcomes.failed_modules, ["p/failed"]);
        assert_eq!(outcomes.incomplete_modules, ["p/interrupted", "p/waiting"]);
        assert_eq!(outcomes.warning_modules.len(), 1);
        assert_eq!(
            outcomes.warning_modules[0].warning_conditions[0].source,
            "ValidateDirectPostResponse"
        );
    }

    #[test]
    fn reconciliation_refreshes_nonterminal_blocking_log_to_terminal_failure() {
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(ReconciliationTransport),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(30),
            control: RunControl::default(),
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");
        let context = ModuleReportContext {
            matrix_plan_id: "p".into(),
            suite_plan_id: "suite-plan".into(),
            module_id: Some("failed".into()),
            test_name: "failed".into(),
            variant: BTreeMap::new(),
            terminal: false,
            expected_result: None,
        };
        let nonterminal_failure = ModuleReport::from_info(
            context.clone(),
            serde_json::json!({"status":"WAITING"}),
            serde_json::json!([{"result":"FAILURE", "src":"EnsureHttpStatusCodeIs200"}]),
        );
        assert_eq!(nonterminal_failure.outcome, ModuleOutcome::Failed);
        assert!(!nonterminal_failure.terminal);
        let created = [CreatedModule {
            group_index: 0,
            context,
        }];
        let mut groups = vec![GroupProgress {
            id: "g".into(),
            profile: "openid4vc".into(),
            completed: 0,
            total: 1,
            status: GroupStatus::Running,
            passed: 0,
            reviewed: 0,
            warnings: 0,
            skipped: 0,
            failed: 0,
            incomplete: 0,
            running: 1,
            remaining: 0,
        }];
        let mut modules = vec![nonterminal_failure];
        let mut errors = RunErrors::new(Vec::new(), RunControl::default());

        runner.collect_unreported_terminal_modules(
            &created,
            &mut groups,
            &mut modules,
            &mut errors,
            true,
        );

        assert!(errors.is_empty());
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].outcome, ModuleOutcome::Failed);
        assert!(modules[0].terminal);
        assert_eq!(groups[0].completed, 1);
        assert_eq!(groups[0].running, 0);
        assert_eq!(groups[0].failed, 1);
    }

    #[test]
    fn reconciliation_preserves_deferred_review_evidence_without_another_suite_read() {
        let transport = Arc::new(FixtureTransport {
            requests: Mutex::new(Vec::new()),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(30),
            control: RunControl::default(),
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");
        let context = ModuleReportContext {
            matrix_plan_id: "p".into(),
            suite_plan_id: "suite-plan".into(),
            module_id: Some("deferred".into()),
            test_name: "deferred".into(),
            variant: BTreeMap::new(),
            terminal: false,
            expected_result: None,
        };
        let mut deferred = ModuleReport::from_info(
            context.clone(),
            serde_json::json!({"status":"WAITING"}),
            serde_json::json!([]),
        );
        deferred.mark_deferred_review_pending(DeferredReviewPending {
            placeholder_path: "/test/a/deferred/verification-evidence".into(),
            marker: crate::browser::ReviewScreenshotMarker::Required,
            obligation_index: 0,
        });
        deferred.review_screenshots = vec![ReviewScreenshotReport {
            path: "review-screenshots/run/deferred.png".into(),
            sha256: "a".repeat(64),
            size: 1,
        }];
        deferred.review_screenshots_required = 1;
        deferred.review_screenshots_required_captured = 1;
        let created = [CreatedModule {
            group_index: 0,
            context,
        }];
        let mut groups = vec![GroupProgress {
            id: "g".into(),
            profile: "openid4vc".into(),
            completed: 1,
            total: 1,
            status: GroupStatus::Review,
            passed: 0,
            reviewed: 1,
            warnings: 0,
            skipped: 0,
            failed: 0,
            incomplete: 0,
            running: 0,
            remaining: 0,
        }];
        let mut modules = vec![deferred];
        let mut errors = RunErrors::new(Vec::new(), RunControl::default());

        runner.collect_unreported_terminal_modules(
            &created,
            &mut groups,
            &mut modules,
            &mut errors,
            true,
        );

        assert!(errors.is_empty());
        assert!(transport.requests.lock().expect("requests").is_empty());
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].outcome, ModuleOutcome::DeferredReviewPending);
        assert!(modules[0].deferred_review_pending.is_some());
        assert_eq!(modules[0].review_screenshots.len(), 1);
        assert_eq!(modules[0].review_screenshots_required_captured, 1);
    }

    struct RepeatedCibaSuiteTransport {
        decisions: Arc<AtomicUsize>,
        refreshes_after_first_decision: AtomicUsize,
    }

    impl Transport for RepeatedCibaSuiteTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let decisions = self.decisions.load(Ordering::SeqCst);
            let body = match request.url().path() {
                "/api/log/m" if decisions == 0 => serde_json::json!([
                    {
                        "src": "CallBackchannelAuthenticationEndpoint",
                        "auth_req_id": "request-1"
                    },
                    {"src": "CallAutomatedCibaApprovalEndpoint"}
                ]),
                "/api/log/m" if self.refreshes_after_first_decision.load(Ordering::SeqCst) < 3 => {
                    serde_json::json!([
                        {
                            "src": "CallBackchannelAuthenticationEndpoint",
                            "auth_req_id": "request-1"
                        },
                        {"src": "CallAutomatedCibaApprovalEndpoint"}
                    ])
                }
                "/api/log/m" => serde_json::json!([
                    {
                        "src": "CallBackchannelAuthenticationEndpoint",
                        "auth_req_id": "request-1"
                    },
                    {"src": "CallAutomatedCibaApprovalEndpoint"},
                    {
                        "src": "CallBackchannelAuthenticationEndpoint",
                        "auth_req_id": "request-2"
                    },
                    {"src": "CallAutomatedCibaApprovalEndpoint"}
                ]),
                "/api/info/m" if decisions >= 2 => {
                    serde_json::json!({"status":"FINISHED","result":"PASSED"})
                }
                "/api/info/m" => {
                    if decisions == 1 {
                        self.refreshes_after_first_decision
                            .fetch_add(1, Ordering::SeqCst);
                    }
                    serde_json::json!({"status":"WAITING"})
                }
                _ => serde_json::json!({}),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("json").into(),
            })
        }
    }

    struct RepeatedCibaApprovalTransport {
        decisions: Arc<AtomicUsize>,
        decision_ids: Arc<Mutex<Vec<String>>>,
    }

    impl Transport for RepeatedCibaApprovalTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let path = request.url().path();
            let (headers, body) = if path == "/auth/login" {
                (
                    vec![
                        ("Set-Cookie".to_owned(), "session=opaque; Path=/".to_owned()),
                        (
                            "Set-Cookie".to_owned(),
                            "csrf=csrf-value; Path=/".to_owned(),
                        ),
                    ],
                    serde_json::json!({"csrf_token":"csrf-value","mfa_required":false}),
                )
            } else if request.method() == HttpMethod::Get {
                let auth_req_id = path
                    .strip_prefix("/auth/ciba/")
                    .expect("CIBA verification path");
                (
                    Vec::new(),
                    serde_json::json!({"auth_req_id":auth_req_id,"request":{"client_id":"client-1"}}),
                )
            } else {
                self.decision_ids.lock().expect("decision IDs lock").push(
                    path.strip_prefix("/auth/ciba/")
                        .expect("CIBA decision path")
                        .to_owned(),
                );
                self.decisions.fetch_add(1, Ordering::SeqCst);
                (Vec::new(), serde_json::json!({"success":true}))
            };
            Ok(HttpResponse {
                status: 200,
                headers,
                body: serde_json::to_vec(&body).expect("json").into(),
            })
        }
    }

    #[test]
    fn ciba_waiting_handles_two_decisions_without_observing_running() {
        let decisions = Arc::new(AtomicUsize::new(0));
        let decision_ids = Arc::new(Mutex::new(Vec::new()));
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(RepeatedCibaSuiteTransport {
                decisions: Arc::clone(&decisions),
                refreshes_after_first_decision: AtomicUsize::new(0),
            }),
            ClientConfig::default(),
        )
        .expect("client");
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(5),
            control: RunControl::default(),
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");
        let approver = Arc::new(
            CibaUserApprovalClient::new(
                url::Url::parse("https://tenant.example/").expect("issuer"),
                zeroize::Zeroizing::new("applicant@example.invalid".to_owned()),
                zeroize::Zeroizing::new("password".to_owned()),
                Arc::new(RepeatedCibaApprovalTransport {
                    decisions: Arc::clone(&decisions),
                    decision_ids: Arc::clone(&decision_ids),
                }),
                std::collections::HashSet::from(["client-1".to_owned()]),
            )
            .expect("approver"),
        );
        let module = ModuleDefinition {
            test_name: "fapi-ciba-id1".into(),
            variant: BTreeMap::new(),
        };

        let (observed, needs_interactive_driver) = runner
            .drive_ciba_waiting_interruptible(
                &mut (),
                &approver,
                &module,
                "m",
                serde_json::json!({"status":"WAITING"}),
            )
            .expect("both CIBA decisions");

        assert!(is_terminal(&observed));
        assert!(!needs_interactive_driver);
        assert_eq!(decisions.load(Ordering::SeqCst), 2);
        assert_eq!(
            decision_ids.lock().expect("decision IDs lock").as_slice(),
            ["request-1", "request-2"]
        );
    }

    struct PendingTransport;

    impl Transport for PendingTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let body = match request.url().path() {
                "/api/info/m" => serde_json::json!({"status":"WAITING"}),
                "/api/runner/m" => serde_json::json!({
                    "browser": {"urls": []}
                }),
                _ => serde_json::json!({}),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("json").into(),
            })
        }
    }

    struct PendingIssuer {
        drives: usize,
        config_address: usize,
        variant_address: Option<usize>,
    }

    #[derive(Default)]
    struct RecordingIssuer {
        variants: Vec<BTreeMap<String, String>>,
    }

    impl OpenId4VciIssuerDriver for RecordingIssuer {
        fn drive(&mut self, module: &OpenId4VciModule<'_>) -> Result<(), OpenId4VciError> {
            self.variants.push(module.variant.clone());
            Ok(())
        }
    }

    impl OpenId4VciIssuerDriver for PendingIssuer {
        fn drive(&mut self, module: &OpenId4VciModule<'_>) -> Result<(), OpenId4VciError> {
            assert_eq!(
                module.plan_config as *const Value as usize,
                self.config_address
            );
            let variant_address = module.variant as *const BTreeMap<String, String> as usize;
            if let Some(previous) = self.variant_address {
                assert_eq!(variant_address, previous);
            }
            self.variant_address = Some(variant_address);
            self.drives += 1;
            Err(OpenId4VciError::Pending)
        }
    }

    #[test]
    fn vci_waiting_empty_urls_are_refreshed_until_bounded_timeout() {
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(PendingTransport),
            ClientConfig::default(),
        )
        .expect("client");
        let control = RunControl::default();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix: SelectedMatrix {
                document: MatrixDocument {
                    schema: 1,
                    name: "matrix".into(),
                    groups: Vec::new(),
                },
                digest: "digest".into(),
            },
            target_origin: None,
            binding: Some(test_binding()),
            poll_timeout: Duration::from_millis(250),
            control,
            plan_lanes: BTreeMap::new(),
            plan_resource_budgets: BTreeMap::new(),
            selected_resource_budget: budget(0, 0, 0),
            jobs: 1,

            automation: Vec::new(),
            suite_resource_observer: None,
        })
        .expect("runner");
        let plan = PlannedPlan {
            group_index: 0,
            matrix_plan_id: "matrix-plan".into(),
            suite_plan_id: "suite-plan".into(),
            plan_name: "oid4vci-test-plan".into(),
            variant: BTreeMap::from([(
                "vci_authorization_code_flow_variant".into(),
                "wallet_initiated".into(),
            )]),
            runtime_variant: BTreeMap::from([(
                "vci_authorization_code_flow_variant".into(),
                "wallet_initiated".into(),
            )]),
            expected_results: BTreeMap::new(),
            modules: Vec::new(),
            config: serde_json::json!({}),
            report_index: 0,
            lane: OidfDriverLane::Parallel,
        };
        let module = ModuleDefinition {
            test_name: "test".into(),
            variant: BTreeMap::new(),
        };
        let issuer = Arc::new(Mutex::new(PendingIssuer {
            drives: 0,
            config_address: &plan.config as *const Value as usize,
            variant_address: None,
        }));
        let issuer_driver: Arc<Mutex<dyn OpenId4VciIssuerDriver>> = issuer.clone();
        let error = runner
            .drive_vci_waiting_interruptible(
                &mut (),
                &issuer_driver,
                &plan,
                &module,
                "m",
                serde_json::json!({"status":"WAITING"}),
            )
            .expect_err("pending VCI must not be treated as complete");
        assert!(
            error.contains("WAITING drive timed out"),
            "unexpected error: {error}"
        );
        assert!(issuer.lock().expect("issuer").drives >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn serial_vp_suite_html_review_reaches_terminal_without_local_browser() {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary root")
            .join(format!(
                "nazoauth-deferred-review-run-{}",
                uuid::Uuid::now_v7()
            ));
        crate::secure_file::ensure_directory(&root, true).expect("private evidence root");
        let transport = Arc::new(DeferredReviewTransport {
            requests: Mutex::new(Vec::new()),
            suite_origin: "https://suite.example",
            test_name: "happy-flow",
            module_variant: BTreeMap::from([(
                "response_mode".to_owned(),
                "direct_post.jwt".to_owned(),
            )]),
            info_after_capture: serde_json::json!({"status":"FINISHED","result":"REVIEW"}),
            wait_state_after_capture: serde_json::json!({"state":"FINISHED"}),
            info_calls: AtomicUsize::new(0),
            upload_review: true,
            uploaded: AtomicBool::new(false),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("configured Suite"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let mut matrix = one_plan_matrix(serde_json::json!({
            "alias":"vp-alias",
            "browser":[{
                "match":"https://issuer.example/authorize*",
                "tasks":[{
                    "match":"https://suite.example/test/a/module-a/verification-evidence",
                    "commands":[["wait","xpath","//*",1,"review","update-image-placeholder"]]
                }]
            }]
        }));
        matrix.digest = "b".repeat(64);
        matrix.document.groups[0].plans[0].plan = "oid4vp-1final-verifier-test-plan".to_owned();
        matrix.document.groups[0].plans[0]
            .variant
            .insert("credential_format".to_owned(), "dc+sd-jwt".to_owned());
        let effective_variant = BTreeMap::from([
            ("credential_format".to_owned(), "dc+sd-jwt".to_owned()),
            ("response_mode".to_owned(), "direct_post.jwt".to_owned()),
        ]);
        let verifier_state = Arc::new(Mutex::new(DeferredReviewVerifier {
            expected_delivery_host: "suite.example",
            starts: 0,
            completes: 0,
            completion_outcome: OpenId4VpCompletionOutcome::Completed,
        }));
        let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> = verifier_state.clone();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix,
            target_origin: Some(
                BrowserTargetOrigin::parse("https://issuer.example").expect("target"),
            ),
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: one_plan_budgets(),
            selected_resource_budget: budget(1, 1, 60),
            jobs: 1,

            automation: vec![ConformanceAutomation {
                verifier: Some(verifier.clone()),
                issuer: None,
                ciba_approver: None,
            }],
            suite_resource_observer: None,
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;
        let integrity = &report.orchestration_integrity;
        let module_outcomes = report
            .modules
            .iter()
            .map(|module| {
                (
                    module.outcome,
                    module.terminal,
                    module.deferred_review_pending.is_some(),
                )
            })
            .collect::<Vec<_>>();
        let fixture_diagnostic = format!(
            "errors={:?}; defined={}; created={}; terminal={}; deferred={}; instantiated={}; settled={}; retention_requested={}; retention_eligible={}; retention_candidate_settled={}; retention_committed={}; cleanup_complete={}; suite_resources_settled={}; module_outcomes={module_outcomes:?}",
            report.errors,
            integrity.defined_modules,
            integrity.created_instances,
            integrity.terminal_modules,
            integrity.deferred_review_modules,
            integrity.all_modules_instantiated,
            integrity.all_modules_settled,
            integrity.retention_requested,
            integrity.retention_eligible,
            integrity.retention_candidate_settled,
            integrity.retention_committed,
            integrity.cleanup_complete,
            integrity.suite_resources_settled,
        );

        assert!(report.errors.is_empty(), "{fixture_diagnostic}");
        assert_eq!(
            report
                .auth_probe
                .as_ref()
                .map(|probe| (probe.unauthenticated_status, probe.authenticated_status)),
            Some((401, 200)),
            "{fixture_diagnostic}"
        );
        assert_eq!(integrity.defined_modules, 1, "{fixture_diagnostic}");
        assert_eq!(integrity.created_instances, 1, "{fixture_diagnostic}");
        assert_eq!(integrity.terminal_modules, 1, "{fixture_diagnostic}");
        assert_eq!(integrity.deferred_review_modules, 0, "{fixture_diagnostic}");
        assert!(integrity.all_modules_instantiated, "{fixture_diagnostic}");
        assert!(integrity.all_modules_settled, "{fixture_diagnostic}");
        assert!(!integrity.retention_requested, "{fixture_diagnostic}");
        assert!(!integrity.retention_eligible, "{fixture_diagnostic}");
        assert!(!integrity.retention_committed, "{fixture_diagnostic}");
        assert!(integrity.cleanup_complete, "{fixture_diagnostic}");
        assert!(integrity.suite_resources_settled, "{fixture_diagnostic}");
        assert!(!report.suite_pass);
        assert!(!report.acceptance_pass);
        assert!(!report.review_pending);
        assert!(report.human_review_required);
        assert!(report.deferred_review_modules.is_empty());
        assert_eq!(report.modules.len(), 1);
        let module = &report.modules[0];
        assert_eq!(module.outcome, ModuleOutcome::Review);
        assert!(module.terminal);
        assert_eq!(module.review_screenshots.len(), 0);
        assert_eq!(module.variant, effective_variant);
        assert_eq!(module.review_screenshots_required, 0);
        assert_eq!(module.review_screenshots_required_captured, 0);
        assert!(module.deferred_review_pending.is_none());
        assert!(integrity.all_modules_terminal, "{fixture_diagnostic}");

        let verifier = verifier_state.lock().expect("verifier");
        assert_eq!((verifier.starts, verifier.completes), (1, 1));
        let requests = transport.requests.lock().expect("requests");
        assert!(
            requests
                .iter()
                .any(|(method, path)| *method == HttpMethod::Post && path == "/api/plan"),
            "the authenticated probe must complete before production plan creation: {fixture_diagnostic}"
        );
        let plan_create = requests
            .iter()
            .position(|(method, path)| *method == HttpMethod::Post && path == "/api/plan")
            .expect("plan creation asserted above");
        assert_eq!(
            requests[..plan_create]
                .iter()
                .filter(|(method, path)| *method == HttpMethod::Get && path == "/api/plan")
                .count(),
            2,
            "both authentication probe calls must precede production plan creation: {fixture_diagnostic}"
        );
        assert!(
            requests
                .iter()
                .any(|(method, _)| *method == HttpMethod::Delete)
        );
        assert_eq!(
            requests
                .iter()
                .filter(|(method, path)| {
                    *method == HttpMethod::Post && path == "/api/log/module-a/images/placeholder-a"
                })
                .count(),
            0
        );
        assert!(report.local_success, "{fixture_diagnostic}");
        drop(requests);
        std::fs::remove_dir_all(root).expect("remove temporary evidence root");
    }

    #[cfg(unix)]
    #[test]
    fn serial_vp_expected_immediate_rejection_skips_receipt_and_deferred_review() {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary root")
            .join(format!(
                "nazoauth-vp-expected-rejection-{}",
                uuid::Uuid::now_v7()
            ));
        crate::secure_file::ensure_directory(&root, true).expect("private evidence root");
        let transport = Arc::new(DeferredReviewTransport {
            requests: Mutex::new(Vec::new()),
            suite_origin: "https://www.certification.openid.net",
            test_name: "oid4vp-1final-verifier-invalid-kb-jwt-signature",
            module_variant: BTreeMap::new(),
            info_after_capture: serde_json::json!({"status":"FINISHED","result":"PASSED"}),
            wait_state_after_capture: serde_json::json!({"state":"FINISHED"}),
            info_calls: AtomicUsize::new(0),
            upload_review: false,
            uploaded: AtomicBool::new(false),
        });
        let client = SuiteClient::with_transport(
            Origin::parse("https://www.certification.openid.net").expect("official Suite"),
            Some(BearerToken::new("suite-token").expect("token")),
            transport.clone(),
            ClientConfig::default(),
        )
        .expect("client");
        let mut matrix = one_plan_matrix(serde_json::json!({
            "alias":"vp-alias",
            "browser":[{
                "match":"https://issuer.example/authorize*",
                "tasks":[{"commands":[]}]
            }]
        }));
        matrix.digest = "b".repeat(64);
        matrix.document.groups[0].plans[0].plan = "oid4vp-1final-verifier-test-plan".to_owned();
        let verifier_state = Arc::new(Mutex::new(DeferredReviewVerifier {
            expected_delivery_host: "www.certification.openid.net",
            starts: 0,
            completes: 0,
            completion_outcome: OpenId4VpCompletionOutcome::ExpectedImmediateRejection,
        }));
        let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> = verifier_state.clone();
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client,
            matrix,
            target_origin: Some(
                BrowserTargetOrigin::parse("https://issuer.example").expect("target"),
            ),
            binding: Some(test_binding()),
            poll_timeout: Duration::from_secs(1),
            control: RunControl::default(),
            plan_lanes: BTreeMap::from([("p".to_owned(), OidfDriverLane::Parallel)]),
            plan_resource_budgets: one_plan_budgets(),
            selected_resource_budget: budget(1, 1, 60),
            jobs: 1,

            automation: vec![ConformanceAutomation {
                verifier: Some(verifier),
                issuer: None,
                ciba_approver: None,
            }],
            suite_resource_observer: Some(Arc::new(RetainingObserver)),
        })
        .expect("runner");

        let report = runner.run(&mut ()).report;

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.local_success);
        assert!(report.suite_pass);
        assert!(report.acceptance_pass);
        assert!(!report.review_pending);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].outcome, ModuleOutcome::Passed);
        assert!(report.modules[0].terminal);
        assert!(report.modules[0].deferred_review_pending.is_none());
        assert!(report.modules[0].review_screenshots.is_empty());

        let verifier = verifier_state.lock().expect("verifier");
        assert_eq!((verifier.starts, verifier.completes), (1, 1));
        drop(verifier);
        let requests = transport.requests.lock().expect("requests");
        assert!(requests.iter().all(|(method, path)| {
            *method != HttpMethod::Delete && !path.contains("image") && !path.contains("visited")
        }));
        drop(requests);
        std::fs::remove_dir_all(root).expect("remove temporary evidence root");
    }
    #[test]
    fn suite_html_evidence_accepts_official_snapshot_but_not_pending_or_empty_evidence() {
        let valid = serde_json::json!([{"result":"REVIEW","page_source":"<html>Login</html>","content_type":"text/html","matched_regexp":".*"}]);
        assert!(validate_suite_browser_evidence(&valid).is_ok());
        for invalid in [
            serde_json::json!([{"result":"REVIEW","upload":"pending"}]),
            serde_json::json!([{"result":"REVIEW","page_source":"","content_type":"text/html","matched_regexp":".*"}]),
            serde_json::json!([{"result":"REVIEW","page_source":"<html>Login</html>","matched_regexp":".*"}]),
            serde_json::json!([{"result":"REVIEW","page_source":"<html>Login</html>","content_type":"text/html"}]),
        ] {
            assert!(validate_suite_browser_evidence(&invalid).is_err());
        }
    }
}
