use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::browser::{
    BrowserAutomation, BrowserPolicy, BrowserRunnerState, BrowserTargetOrigin, ConformanceBinding,
    OpenId4VciError, OpenId4VciIssuerDriver, OpenId4VciModule, OpenId4VpStartRequest,
    OpenId4VpVerifier, browser_config_for_module, parse_browser_entries_owned,
};
use crate::client::{DeleteOutcome, ModuleDefinition, SuiteClient, SuiteClientError};
use crate::matrix::{MatrixError, SelectedMatrix, zeroize_json_value};
use crate::origin::Origin;
use crate::progress::{
    GroupProgress, GroupStatus, ProgressEvent, ProgressSink, ProgressSnapshot, redacted_variant,
};
use crate::report::{
    CleanupFailure, CleanupReport, ConformanceReport, ModuleOutcome, ModuleReport,
    ModuleReportContext, OrchestrationIntegrity, PlanReport, summarize_matrix_expectations,
    summarize_module_outcomes,
};
use crate::{OidfDriverLane, OidfPlanResourceBudget};

mod parallel;

pub const MAX_PARALLEL_JOBS: usize = 4;
pub const BOUNDED_PLAN_RUNNER_PROTOCOL: &str = "nazoauthctl-bounded-plan-runner-v1";
pub const MAX_POLL_TIMEOUT_SECONDS: u64 = 86_400;
pub const MAX_POLL_TIMEOUT: Duration = Duration::from_secs(MAX_POLL_TIMEOUT_SECONDS);

/// One worker-owned interactive automation lane. A lane is never shared by
/// concurrent plan workers, so WebDriver cookies/navigation and OpenID4VC
/// driver state cannot interleave across plans.
#[derive(Clone, Default)]
pub struct ConformanceAutomation {
    pub browser: Option<Arc<Mutex<dyn BrowserAutomation>>>,
    pub verifier: Option<Arc<Mutex<dyn OpenId4VpVerifier>>>,
    pub issuer: Option<Arc<Mutex<dyn OpenId4VciIssuerDriver>>>,
}

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
    /// The deployment-owned binding allocated for this run. OpenID4VP
    /// verifier starts carry either an ordinary trust-policy resource id and
    /// digest or the complete legacy lease/task pair. Keeping the disjoint
    /// binding on the run config prevents partial and mixed requests.
    pub binding: ConformanceBinding,
    pub poll_timeout: Duration,
    pub control: RunControl,
    /// Exact signed execution lane for every selected Matrix plan. The map is
    /// required to match the selected plan ids one-for-one; the runner never
    /// derives CIBA semantics from mutable Suite plan names.
    pub plan_lanes: BTreeMap<String, OidfDriverLane>,
    /// Exact signed resource budget for every selected Matrix plan. The map
    /// must cover the selected plan ids one-for-one.
    pub plan_resource_budgets: BTreeMap<String, OidfPlanResourceBudget>,
    /// Signed aggregate budget for exactly the selected Matrix plans.
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
    fn plan_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String>;
    fn plan_created(&self, origin: &Origin, intent_id: &str, plan_id: &str) -> Result<(), String>;
    fn module_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String>;
    fn module_created(&self, intent_id: &str, module_id: &str) -> Result<(), String>;
}

pub struct ConformanceRunner {
    config: ConformanceRunConfig,
}

/// A plan is deliberately kept separate from its public report while the run
/// is in progress. This allows every selected plan to be created and all
/// module definitions enumerated before any module is started, freezing the
/// progress denominator and ensuring later failures can clean up everything
/// already allocated by the Suite.
#[derive(Clone)]
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
        // Suite responses and materialized Matrix configs may contain private
        // client material. Every worker-owned clone must clear its own config;
        // clearing only the parent Matrix cannot cover these independent
        // allocations. ModuleDefinition owns and clears its response Values.
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
            || !resource_budgets_match_selected(
                &config.matrix,
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

    fn wait_for_state_interruptible(
        &self,
        module_id: &str,
        states: &[&str],
    ) -> Result<Value, String> {
        let deadline = Instant::now()
            .checked_add(self.config.poll_timeout)
            .ok_or_else(|| "Suite poll timeout is out of range".to_owned())?;
        self.wait_for_state_until(module_id, states, deadline)
    }

    fn reset_browser_session(&self) -> Result<(), String> {
        let Some(browser) = self
            .config
            .automation
            .first()
            .and_then(|automation| automation.browser.as_ref())
        else {
            return Ok(());
        };
        browser
            .lock()
            .map_err(|_| "browser automation lock failed".to_owned())?
            .reset_session()
            .map_err(|error| error.to_string())
    }

    fn wait_for_state_until(
        &self,
        module_id: &str,
        states: &[&str],
        deadline: Instant,
    ) -> Result<Value, String> {
        loop {
            if self.config.control.is_interrupted() {
                return Err("run interrupted".to_owned());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SuiteClientError::Timeout.to_string());
            }
            let slice = remaining.min(Duration::from_secs(5));
            match self.config.client.wait_for_state(module_id, states, slice) {
                Ok(state) => return Ok(state),
                Err(SuiteClientError::Timeout) => continue,
                Err(error) => return Err(safe_error(&error)),
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

    fn drive_vci_waiting_interruptible(
        &self,
        issuer: &Arc<Mutex<dyn OpenId4VciIssuerDriver>>,
        plan: &PlannedPlan,
        module: &ModuleDefinition,
        module_id: &str,
        initial: Value,
    ) -> Result<Value, String> {
        let deadline = Instant::now()
            .checked_add(self.config.poll_timeout)
            .ok_or_else(|| "OpenID4VCI poll timeout is out of range".to_owned())?;
        let mut observed = initial;
        let mut first_round = true;
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
                    .map_err(|error| safe_error(&error))?;
                if is_terminal_state(&observed) {
                    return Ok(observed);
                }
                if !is_waiting(&observed) {
                    observed = self.wait_for_state_until(
                        module_id,
                        &["WAITING", "FINISHED", "INTERRUPTED"],
                        deadline,
                    )?;
                    if is_terminal_state(&observed) {
                        return Ok(observed);
                    }
                }
            }
            first_round = false;
            if !is_waiting(&observed) {
                return Ok(observed);
            }

            let runner = match self.config.client.runner_info(module_id) {
                Ok(runner) => runner,
                Err(SuiteClientError::HttpStatus(404)) => {
                    self.wait_for_runner_refresh(deadline, "OpenID4VCI")?;
                    continue;
                }
                Err(error) => return Err(safe_error(&error)),
            };
            let module_context = OpenId4VciModule::new(
                module_id.to_owned(),
                module.test_name.clone(),
                runtime_variant_for_definition(plan, module),
                plan.config.clone(),
                runner,
            )
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

    fn drive_browser_waiting_interruptible(
        &self,
        browser: &Arc<Mutex<dyn BrowserAutomation>>,
        plan: &PlannedPlan,
        module: &ModuleDefinition,
        module_id: &str,
        initial: Value,
    ) -> Result<Value, String> {
        let browser_config = browser_config_for_module(&plan.config, &module.test_name)
            .map_err(|error| error.to_string())?;
        let entries =
            parse_browser_entries_owned(browser_config).map_err(|error| error.to_string())?;
        let target_origin = self.config.target_origin.clone().ok_or_else(|| {
            "Suite runner is WAITING but the target browser origin is unavailable".to_owned()
        })?;
        let policy = BrowserPolicy::new(target_origin, self.config.client.origin().clone())
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now()
            .checked_add(self.config.poll_timeout)
            .ok_or_else(|| "browser poll timeout is out of range".to_owned())?;
        let mut observed = initial;
        let mut first_round = true;
        let mut completed_url_digests = BTreeSet::<[u8; 32]>::new();

        loop {
            if self.config.control.is_interrupted() {
                return Err("run interrupted".to_owned());
            }
            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                return Err("browser WAITING drive timed out".to_owned());
            }
            if !first_round {
                observed = self
                    .config
                    .client
                    .module_info(module_id)
                    .map_err(|error| safe_error(&error))?;
                if is_terminal_state(&observed) {
                    return Ok(observed);
                }
                if !is_waiting(&observed) {
                    observed = self.wait_for_state_until(
                        module_id,
                        &["WAITING", "FINISHED", "INTERRUPTED"],
                        deadline,
                    )?;
                    if is_terminal_state(&observed) {
                        return Ok(observed);
                    }
                }
            }
            first_round = false;
            if !is_waiting(&observed) {
                return Ok(observed);
            }

            let runner = match self.config.client.runner_info(module_id) {
                Ok(runner) => runner,
                Err(SuiteClientError::HttpStatus(404)) => {
                    self.wait_for_runner_refresh(deadline, "browser")?;
                    continue;
                }
                Err(error) => return Err(safe_error(&error)),
            };
            let Some(browser_state) = runner.get("browser") else {
                self.wait_for_runner_refresh(deadline, "browser")?;
                continue;
            };
            let browser_state = BrowserRunnerState::parse(browser_state, &policy)
                .map_err(|error| error.to_string())?;
            let pending_url = browser_state.urls().iter().find(|url| {
                let digest: [u8; 32] = Sha256::digest(url.as_str().as_bytes()).into();
                !browser_state
                    .visited()
                    .iter()
                    .any(|visited| visited == *url)
                    && !completed_url_digests.contains(&digest)
            });
            let Some(pending_url) = pending_url else {
                self.wait_for_runner_refresh(deadline, "browser")?;
                continue;
            };
            {
                let mut driver = browser
                    .lock()
                    .map_err(|_| "browser automation lock failed".to_owned())?;
                driver
                    .execute(pending_url, &entries)
                    .map_err(|error| error.to_string())?;
            }
            completed_url_digests.insert(Sha256::digest(pending_url.as_str().as_bytes()).into());
            self.wait_for_runner_refresh(deadline, "browser")?;
        }
    }

    pub fn run<S: ProgressSink>(&self, sink: &mut S) -> RunSummary {
        if self.config.jobs == 1 || self.config.matrix.document.plan_count() <= 1 {
            return self.run_serial(sink);
        }
        parallel::run(self, sink)
    }

    fn prepare_run(&self) -> PreparedRun {
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
                skipped: 0,
                failed: 0,
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
        let selected_plan_count = self
            .config
            .matrix
            .document
            .groups
            .iter()
            .map(|group| group.plans.len())
            .sum::<usize>();
        let mut enumerated_plan_count = 0usize;
        let mut auth_probe = None;
        let mut current_profile = None;
        let mut current_variant = None;
        let mut observed_modules = 0u32;

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
                    let runtime_variant = group.effective_runtime_variant(plan);
                    current_variant = Some(redacted_variant(&variant));
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
                    let mut created =
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
                    // `PlanCreated::raw` is a response-owned Value separate
                    // from each module's raw copy. Clear it before the
                    // response wrapper is partially moved below.
                    zeroize_json_value(&mut created.raw);
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
                        if !definition_identities
                            .insert((module.test_name.clone(), module.variant.clone()))
                        {
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
                    let plan_budget =
                        self.config.plan_resource_budgets.get(&plan.id).expect(
                            "selected plan resource budgets were validated at construction",
                        );
                    let next_observed_modules =
                        actual_modules.and_then(|count| observed_modules.checked_add(count));
                    let over_budget = actual_modules
                        .is_none_or(|count| count > plan_budget.modules)
                        || next_observed_modules.is_none_or(|count| {
                            count > self.config.selected_resource_budget.modules
                        });
                    if over_budget {
                        errors.push(
                            "Suite plan module allocation exceeds signed resource budget"
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
        self.run_prepared(sink, self.prepare_run())
    }

    fn run_prepared<S: ProgressSink>(&self, sink: &mut S, prepared: PreparedRun) -> RunSummary {
        let PreparedRun {
            mut groups,
            mut plans,
            mut planned,
            suite_plan_ids,
            mut errors,
            unknown_declared_skip_modules,
            matrix_expectations_satisfied,
            all_selected_plan_definitions_enumerated,
            auth_probe,
            mut current_profile,
            mut current_variant,
        } = prepared;
        let mut modules = Vec::new();
        let mut cleanup = CleanupReport::default();
        let mut module_ids = Vec::<String>::new();
        let mut current_test = None;

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
                    if let Err(error) = self.reset_browser_session() {
                        errors.push(error);
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
                    let module_create_intent =
                        if let Some(observer) = &self.config.suite_resource_observer {
                            let intent_id = uuid::Uuid::now_v7().to_string();
                            if let Err(error) = observer
                                .module_create_intent(self.config.client.origin(), &intent_id)
                            {
                                errors.push(error);
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                            Some(intent_id)
                        } else {
                            None
                        };
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
                    if let (Some(observer), Some(intent_id)) =
                        (&self.config.suite_resource_observer, &module_create_intent)
                        && let Err(error) = observer.module_created(intent_id, &instance.id)
                    {
                        errors.push(error);
                        groups[group_index].status = GroupStatus::Failed;
                        break 'execute;
                    }
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

                    // A freshly-created runner may already report RUNNING
                    // before it reaches its interactive WAITING boundary.
                    // Do not skip automation merely because the first info
                    // document exists; only WAITING and terminal states are
                    // actionable here.
                    if needs_interactive_or_terminal_wait(observed.as_ref()) {
                        observed = match self.wait_for_state_interruptible(
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
                        if plan.plan_name.starts_with("oid4vci-") {
                            let Some(issuer) = self
                                .config
                                .automation
                                .first()
                                .and_then(|automation| automation.issuer.as_ref())
                            else {
                                errors
                                    .push("OpenID4VCI issuer automation is unavailable".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            match self.drive_vci_waiting_interruptible(
                                issuer,
                                plan,
                                module,
                                &instance.id,
                                observed.clone().expect("waiting runner state"),
                            ) {
                                Ok(state) => observed = Some(state),
                                Err(error) => {
                                    errors.push(error);
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            }
                        } else if plan.plan_name.starts_with("oid4vp-1final-verifier") {
                            let Some(verifier) = self
                                .config
                                .automation
                                .first()
                                .and_then(|automation| automation.verifier.as_ref())
                            else {
                                errors.push(
                                    "OpenID4VP verifier automation is unavailable".to_owned(),
                                );
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            let alias = instance
                                .raw
                                .get("alias")
                                .and_then(Value::as_str)
                                .or_else(|| plan.config.get("alias").and_then(Value::as_str));
                            let Some(alias) = alias else {
                                errors.push("OpenID4VP module has no verifier alias".to_owned());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            let haip = plan.plan_name == "oid4vp-1final-verifier-haip-test-plan";
                            let request = match OpenId4VpStartRequest::new(
                                alias,
                                &module.test_name,
                                plan.variant.clone(),
                                haip,
                                self.config.binding.clone(),
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
                            if let Err(error) = verifier.complete(&presentation) {
                                errors.push(error.to_string());
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            }
                        } else if plan.config.get("browser").is_some() {
                            let Some(browser) = self
                                .config
                                .automation
                                .first()
                                .and_then(|automation| automation.browser.as_ref())
                            else {
                                errors.push(
                                    "Suite runner is WAITING but browser automation is unavailable"
                                        .to_owned(),
                                );
                                groups[group_index].status = GroupStatus::Failed;
                                break 'execute;
                            };
                            match self.drive_browser_waiting_interruptible(
                                browser,
                                plan,
                                module,
                                &instance.id,
                                observed.clone().expect("waiting runner state"),
                            ) {
                                Ok(state) => observed = Some(state),
                                Err(error) => {
                                    errors.push(error);
                                    groups[group_index].status = GroupStatus::Failed;
                                    break 'execute;
                                }
                            }
                        }
                    }

                    if !observed.as_ref().is_some_and(is_terminal_state)
                        && let Err(error) = self.wait_for_state_interruptible(
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
                        ModuleReportContext {
                            matrix_plan_id: plan.matrix_plan_id.clone(),
                            suite_plan_id: plan.suite_plan_id.clone(),
                            module_id: Some(instance.id.clone()),
                            test_name: module.test_name.clone(),
                            variant: module.variant.clone(),
                            terminal,
                            expected_result: plan.expected_results.get(&module.test_name).cloned(),
                        },
                        info,
                        log,
                    ));
                    let module_outcome = modules.last().map(|module| module.outcome);
                    if terminal {
                        groups[group_index].running = groups[group_index].running.saturating_sub(1);
                        groups[group_index].completed += 1;
                        match module_outcome {
                            Some(ModuleOutcome::Passed) => groups[group_index].passed += 1,
                            Some(ModuleOutcome::Review) => groups[group_index].reviewed += 1,
                            Some(ModuleOutcome::Skipped) => groups[group_index].skipped += 1,
                            Some(ModuleOutcome::Failed | ModuleOutcome::Incomplete) | None => {
                                groups[group_index].failed += 1;
                            }
                        }
                    }
                    if matches!(
                        module_outcome,
                        Some(ModuleOutcome::Failed | ModuleOutcome::Incomplete) | None
                    ) {
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
                    groups[group_index].status = if groups[group_index].reviewed > 0 {
                        GroupStatus::Review
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

        // A terminal Suite module is already owned by its plan deletion.  A
        // cancellation after a terminal result can race the Suite's final
        // callback, while an unreported allocation still needs cancellation
        // before its plan is deleted.
        let cancellable_module_ids = cancellable_module_ids(&module_ids, &modules);
        cleanup_all(
            &self.config.client,
            &cancellable_module_ids,
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
        let outcomes = summarize_module_outcomes(&modules);
        let matrix_expectations = summarize_matrix_expectations(&modules);
        let matrix_expectations_satisfied = matrix_expectations_satisfied
            && all_selected_plan_definitions_enumerated
            && matrix_expectations.unexpected_skipped_modules.is_empty()
            && unknown_declared_skip_modules.is_empty();
        let suite_pass = defined_modules > 0 && all_modules_terminal && outcomes.all_passed;
        let orchestration_integrity = OrchestrationIntegrity {
            defined_modules,
            created_instances,
            terminal_modules,
            all_modules_instantiated,
            all_modules_terminal,
            cleanup_complete,
        };
        let local_success = errors.is_empty()
            && orchestration_integrity.all_modules_instantiated
            && orchestration_integrity.all_modules_terminal
            && orchestration_integrity.cleanup_complete;
        let human_review_required = !outcomes.human_review_modules.is_empty();
        let snapshot = snapshot(&groups, current_profile, current_variant, current_test);
        let report = ConformanceReport {
            // Schema 3 separates local execution from exact Suite outcomes.
            schema: 3,
            matrix_digest: self.config.matrix.digest.clone(),
            suite_origin: self.config.client.origin().to_string(),
            auth_probe,
            errors,
            local_success,
            suite_pass,
            acceptance_pass: outcomes.acceptance_pass && matrix_expectations_satisfied,
            human_review_required,
            human_review_modules: outcomes.human_review_modules,
            skipped_modules: outcomes.skipped_modules,
            expected_skipped_modules: matrix_expectations.expected_skipped_modules,
            unexpected_skipped_modules: matrix_expectations.unexpected_skipped_modules,
            unknown_declared_skip_modules,
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
    let selected_plan_count = matrix
        .document
        .groups
        .iter()
        .map(|group| group.plans.len())
        .sum::<usize>();
    selected_plan_ids.len() == selected_plan_count
        && selected_plan_ids.len() == plan_lanes.len()
        && plan_lanes
            .keys()
            .all(|plan_id| selected_plan_ids.contains(plan_id.as_str()))
}

fn resource_budgets_match_selected(
    matrix: &SelectedMatrix,
    plan_resource_budgets: &BTreeMap<String, OidfPlanResourceBudget>,
    selected_resource_budget: &OidfPlanResourceBudget,
) -> bool {
    let selected_plan_ids = matrix
        .document
        .groups
        .iter()
        .flat_map(|group| group.plans.iter().map(|plan| plan.id.as_str()))
        .collect::<BTreeSet<_>>();
    let selected_plan_count = matrix
        .document
        .groups
        .iter()
        .map(|group| group.plans.len())
        .sum::<usize>();
    if selected_plan_ids.len() != selected_plan_count
        || selected_plan_ids.len() != plan_resource_budgets.len()
        || !plan_resource_budgets
            .keys()
            .all(|plan_id| selected_plan_ids.contains(plan_id.as_str()))
    {
        return false;
    }

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
    summed.as_ref() == Some(selected_resource_budget)
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
        review_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Review)
            .count(),
        skipped_groups: groups
            .iter()
            .filter(|group| group.status == GroupStatus::Skipped)
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
        reviewed: groups.iter().map(|group| group.reviewed).sum(),
        skipped: groups.iter().map(|group| group.skipped).sum(),
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
                    "Suite recovery refused to cancel module {module_id}: cannot read current Suite state: {}",
                    safe_error(&error)
                ));
            }
        }
    }
    let mut report = CleanupReport::default();
    cleanup_all(
        client,
        &cancellable_module_ids,
        &state.plan_ids,
        &mut report,
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
            error: safe_error(&error),
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

fn definition_identity(matrix_plan_id: &str, module: &ModuleDefinition) -> String {
    if module.variant.is_empty() {
        return format!("{matrix_plan_id}/{}", module.test_name);
    }
    let variant = serde_json::to_string(&module.variant)
        .expect("BTreeMap<String, String> always serializes to JSON");
    format!("{matrix_plan_id}/{}?variant={variant}", module.test_name)
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

fn needs_interactive_or_terminal_wait(value: Option<&Value>) -> bool {
    value.is_none_or(|state| !is_waiting(state) && !is_terminal_state(state))
}

fn is_terminal(value: &Value) -> bool {
    is_terminal_state(value)
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
    use crate::browser::BrowserError;
    use crate::client::ClientConfig;
    use crate::credentials::BearerToken;
    use crate::matrix::{MatrixDocument, MatrixGroup, MatrixPlan, MatrixVariant, SelectedMatrix};
    use crate::transport::{HttpMethod, HttpRequest, HttpResponse, Transport, TransportError};
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    struct FixtureTransport {
        requests: Mutex<Vec<HttpRequest>>,
    }

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
                body: serde_json::to_vec(&body).expect("recovery json"),
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
                body,
            })
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
                body: serde_json::to_vec(&body).expect("budget drift json"),
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
                body: serde_json::to_vec(&body).expect("definition json"),
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
                body: serde_json::to_vec(&body).expect("duplicate definition json"),
            })
        }
    }

    fn test_binding() -> ConformanceBinding {
        ConformanceBinding::new(
            "019ff000-8190-7393-8c33-ab4339c3d85e",
            "request-0123456789abcdef0123456789abcdef",
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
    fn runner_construction_rejects_inexact_signed_resource_budgets() {
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
            binding: test_binding(),
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
        for inexact_total in [budget(2, 1, 60), budget(1, 2, 60), budget(1, 1, 61)] {
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
                binding: test_binding(),
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
            binding: test_binding(),
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
            vec!["Suite plan module allocation exceeds signed resource budget".to_owned()]
        );
        assert_eq!(report.progress.groups[0].status, GroupStatus::Failed);
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
            binding: test_binding(),
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
            binding: test_binding(),
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
            binding: test_binding(),
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
                body: serde_json::to_vec(&body).expect("plan-create failure json"),
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
            binding: test_binding(),
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
                binding: test_binding(),
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
    fn origin_validation_accepts_suite_verification_evidence_glob() {
        let suite = Origin::parse("https://suite.example").expect("origin");
        let parsed =
            Url::parse("https://suite.example/test/a/*/verification-evidence").expect("glob URL");
        assert!(same_url_origin(&suite, &parsed));
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
    fn warning_requires_review_but_failure_log_is_failed() {
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
        assert_eq!(warning.outcome, ModuleOutcome::Review);
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
            binding: test_binding(),
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
                .wait_for_state_interruptible("module", &["FINISHED"])
                .expect_err("interrupt must stop the wait"),
            "run interrupted"
        );
        assert!(transport.requests.lock().expect("lock").is_empty());
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
                body: serde_json::to_vec(&body).expect("json"),
            })
        }
    }

    struct PendingIssuer {
        drives: usize,
    }

    #[derive(Default)]
    struct RecordingIssuer {
        variants: Vec<BTreeMap<String, String>>,
    }

    impl OpenId4VciIssuerDriver for RecordingIssuer {
        fn drive(&mut self, module: &OpenId4VciModule) -> Result<(), OpenId4VciError> {
            self.variants.push(module.variant.clone());
            Ok(())
        }
    }

    impl OpenId4VciIssuerDriver for PendingIssuer {
        fn drive(&mut self, _module: &OpenId4VciModule) -> Result<(), OpenId4VciError> {
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
            binding: test_binding(),
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
        let issuer = Arc::new(Mutex::new(PendingIssuer { drives: 0 }));
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
            raw: serde_json::json!({}),
        };
        let issuer_driver: Arc<Mutex<dyn OpenId4VciIssuerDriver>> = issuer.clone();
        let error = runner
            .drive_vci_waiting_interruptible(
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

    struct BrowserWaitingTransport {
        completed: Arc<AtomicBool>,
    }

    impl Transport for BrowserWaitingTransport {
        fn send(
            &self,
            request: HttpRequest,
            _max_response_bytes: usize,
        ) -> Result<HttpResponse, TransportError> {
            let body = match request.url().path() {
                "/api/info/m" if self.completed.load(Ordering::SeqCst) => {
                    serde_json::json!({"status":"FINISHED","result":"PASSED"})
                }
                "/api/info/m" => serde_json::json!({"status":"WAITING"}),
                "/api/runner/m" => serde_json::json!({
                    "browser": {
                        "urls": ["https://target.example/authorize?state=opaque"],
                        "visited": []
                    }
                }),
                _ => serde_json::json!({}),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::to_vec(&body).expect("json"),
            })
        }
    }

    struct CompletingBrowser {
        completed: Arc<AtomicBool>,
    }

    impl BrowserAutomation for CompletingBrowser {
        fn execute(
            &mut self,
            authorization_url: &Url,
            entries: &[crate::browser::BrowserEntry],
        ) -> Result<crate::browser::BrowserRunReport, BrowserError> {
            assert_eq!(authorization_url.path(), "/authorize");
            assert_eq!(entries.len(), 1);
            self.completed.store(true, Ordering::SeqCst);
            Ok(crate::browser::BrowserRunReport {
                steps: 0,
                tasks: 0,
                entry_index: 0,
                final_origin: "https://target.example".into(),
            })
        }

        fn navigate(&mut self, _url: &Url) -> Result<(), BrowserError> {
            Ok(())
        }
    }

    #[test]
    fn generic_waiting_uses_authoritative_runner_browser_url_until_terminal() {
        let completed = Arc::new(AtomicBool::new(false));
        let client = SuiteClient::with_transport(
            Origin::parse("https://suite.example").expect("origin"),
            Some(BearerToken::new("suite-token").expect("token")),
            Arc::new(BrowserWaitingTransport {
                completed: completed.clone(),
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
            target_origin: Some(
                BrowserTargetOrigin::parse("https://target.example").expect("target"),
            ),
            binding: test_binding(),
            poll_timeout: Duration::from_secs(2),
            control: RunControl::default(),
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
            plan_name: "oidcc-basic-certification-test-plan".into(),
            variant: BTreeMap::new(),
            runtime_variant: BTreeMap::new(),
            expected_results: BTreeMap::new(),
            modules: Vec::new(),
            config: serde_json::json!({
                "browser": [{
                    "match": "https://target.example/authorize*",
                    "tasks": []
                }]
            }),
            report_index: 0,
            lane: OidfDriverLane::Parallel,
        };
        let browser: Arc<Mutex<dyn BrowserAutomation>> = Arc::new(Mutex::new(CompletingBrowser {
            completed: completed.clone(),
        }));
        let module = ModuleDefinition {
            test_name: "browser-module".to_owned(),
            variant: BTreeMap::new(),
            raw: Value::Null,
        };

        let observed = runner
            .drive_browser_waiting_interruptible(
                &browser,
                &plan,
                &module,
                "m",
                serde_json::json!({"status":"WAITING"}),
            )
            .expect("browser drive");
        assert_eq!(status(&observed), Some("FINISHED"));
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn running_initial_state_must_reach_an_interactive_or_terminal_boundary() {
        let running = serde_json::json!({"status":"RUNNING"});
        let waiting = serde_json::json!({"status":"WAITING"});
        let finished = serde_json::json!({"status":"FINISHED"});
        assert!(needs_interactive_or_terminal_wait(None));
        assert!(needs_interactive_or_terminal_wait(Some(&running)));
        assert!(!needs_interactive_or_terminal_wait(Some(&waiting)));
        assert!(!needs_interactive_or_terminal_wait(Some(&finished)));
    }

    #[test]
    fn terminal_detection_accepts_state_only_suite_responses() {
        assert!(is_terminal(&serde_json::json!({"state":"FINISHED"})));
        assert!(is_terminal(&serde_json::json!({"state":"INTERRUPTED"})));
        assert!(!is_terminal(&serde_json::json!({"state":"RUNNING"})));
    }
}
