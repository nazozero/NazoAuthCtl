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
    ModuleReportContext, OrchestrationIntegrity, PlanReport, summarize_module_outcomes,
};

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
    /// The lease and task identity allocated for this run.  OpenID4VP
    /// verifier starts must carry the complete pair; keeping it on the run
    /// config lets the request and verifier client be checked against the
    /// same capability instead of accepting a partial/mixed binding.
    pub binding: ConformanceBinding,
    pub poll_timeout: Duration,
    pub control: RunControl,
    /// Maximum number of independent Suite plans executed at once. Modules
    /// inside one plan remain strictly ordered. Browser, verifier, and issuer
    /// automation retain their existing mutex-owned sessions, so parallel
    /// HTTP runners cannot interleave interactive state.
    pub jobs: usize,
    /// Worker-owned automation lanes. HTTP-only test fixtures may leave this
    /// empty; production creates one independent lane per configured job.
    pub automation: Vec<ConformanceAutomation>,
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
                plan.runtime_variant.clone(),
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
        let mut auth_probe = None;
        let mut current_profile = None;
        let mut current_variant = None;

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
                        plan_name: created.name,
                        variant,
                        runtime_variant,
                        expected_results: plan.expected_results.clone(),
                        modules: created.modules,
                        config: plan.config.clone(),
                        report_index,
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
        let outcomes = summarize_module_outcomes(&modules);
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
            human_review_required,
            human_review_modules: outcomes.human_review_modules,
            skipped_modules: outcomes.skipped_modules,
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

fn needs_interactive_or_terminal_wait(value: Option<&Value>) -> bool {
    value.is_none_or(|state| !is_waiting(state) && !is_terminal_state(state))
}

fn is_terminal(value: &Value) -> bool {
    matches!(
        value.get("status").and_then(Value::as_str),
        Some("FINISHED" | "INTERRUPTED")
    )
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

    fn test_binding() -> ConformanceBinding {
        ConformanceBinding::new(
            "019ff000-8190-7393-8c33-ab4339c3d85e",
            "request-0123456789abcdef0123456789abcdef",
        )
        .expect("binding")
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
                    expected_results: BTreeMap::new(),
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
                binding: test_binding(),
                poll_timeout: Duration::from_secs(1),
                control: RunControl::default(),
                jobs: 1,
                automation: Vec::new(),
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
            jobs: 1,
            automation: Vec::new(),
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
            jobs: 1,
            automation: Vec::new(),
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
        };
        let module = ModuleDefinition {
            test_name: "test".into(),
            variant: None,
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
            jobs: 1,
            automation: Vec::new(),
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
        };
        let browser: Arc<Mutex<dyn BrowserAutomation>> = Arc::new(Mutex::new(CompletingBrowser {
            completed: completed.clone(),
        }));
        let module = ModuleDefinition {
            test_name: "browser-module".to_owned(),
            variant: None,
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
}
