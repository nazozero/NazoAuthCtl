//! Bounded-concurrency read-only fleet execution (goal plan 09 §3, I03).
//!
//! One runner fans a read-only job out over every registered instance with:
//!
//! * bounded concurrency (std threads, hard cap [`MAX_CONCURRENCY`]);
//! * a transport-owned per-target wall-clock timeout — OpenSSH is terminated
//!   and reaped by [`crate::process::Process`] before its worker slot returns;
//! * strict partial-failure isolation — one offline host never hides or
//!   truncates another host's successful result;
//! * stable ordering — results are always emitted in Registry order (alias
//!   order, which is exactly what [`RegistryStore::list_instances`] returns),
//!   in both text and JSON form;
//! * no global mutation lock — the runner touches only the user-scoped
//!   Registry and the verified per-target handshake.
//!
//! There are no detached per-target threads. Each worker owns exactly one
//! target at a time and a slot is released only after the transport returns.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context as _;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error_codes;
use crate::registry::{HostRecord, InstanceRecord, RegistryStore};
use crate::target::{ExecutionTarget, InstanceInspection};

/// Hard upper bound for concurrent targets (I03: cap ~8).
pub(crate) const MAX_CONCURRENCY: usize = 8;

/// Wall-clock budget for one target's whole read-only job.
pub(crate) const DEFAULT_PER_TARGET_TIMEOUT: Duration = Duration::from_secs(60);

/// A read-only unit of work executed once per instance+host pair.
pub(crate) type ReadJob = dyn Fn(&InstanceRecord, &HostRecord, &dyn ExecutionTarget) -> anyhow::Result<Value>
    + Send
    + Sync;

type SharedFactory =
    dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> + Send + Sync;

/// One per-instance outcome in stable Registry order.
pub(crate) struct FleetItemOutcome {
    pub(crate) instance: InstanceRecord,
    pub(crate) host_alias: String,
    /// `Ok(payload)` on success, `Err((code, detail))` on isolated failure.
    pub(crate) result: Result<Value, (String, String)>,
}

pub(crate) struct FleetReadRunner {
    factory: Arc<SharedFactory>,
    concurrency: usize,
}

impl FleetReadRunner {
    pub(crate) fn new(factory: Arc<SharedFactory>, concurrency: usize) -> Self {
        Self {
            factory,
            concurrency: concurrency.clamp(1, MAX_CONCURRENCY),
        }
    }

    /// Production runner: real transports, capped concurrency, default
    /// per-target timeout.
    pub(crate) fn production() -> Self {
        Self::new(
            Arc::new(|record| {
                crate::fleet::production_target_with_ssh_timeout(record, DEFAULT_PER_TARGET_TIMEOUT)
            }),
            MAX_CONCURRENCY,
        )
    }

    /// Run `job` over `items` and return one outcome per item in the exact
    /// input order.
    pub(crate) fn run(
        &self,
        items: Vec<(InstanceRecord, HostRecord)>,
        job: Arc<ReadJob>,
    ) -> Vec<FleetItemOutcome> {
        let total = items.len();
        if total == 0 {
            return Vec::new();
        }
        let cursor = Arc::new(AtomicUsize::new(0));
        let items = Arc::new(items);
        let (sender, receiver) = mpsc::channel::<(usize, FleetItemOutcome)>();
        let sender = Arc::new(sender);
        let budget = self.concurrency.clamp(1, MAX_CONCURRENCY).min(total);
        let mut workers = Vec::new();
        for worker_index in 0..budget {
            let cursor = cursor.clone();
            let items = items.clone();
            let factory = self.factory.clone();
            let sender = sender.clone();
            let job = job.clone();
            workers.push(
                std::thread::Builder::new()
                    .name(format!("nazoauthctl-fleet-worker-{worker_index}"))
                    .spawn(move || {
                        loop {
                            let index = cursor.fetch_add(1, Ordering::SeqCst);
                            if index >= items.len() {
                                break;
                            }
                            let (instance, host) = (&items[index].0, &items[index].1);
                            let result = execute_one(instance, host, factory.as_ref(), job.clone());
                            let _ = sender.send((
                                index,
                                FleetItemOutcome {
                                    instance: instance.clone(),
                                    host_alias: host.alias.clone(),
                                    result,
                                },
                            ));
                        }
                    })
                    .expect("fleet worker thread spawns"),
            );
        }
        drop(sender);
        let mut indexed: Vec<Option<FleetItemOutcome>> = (0..total).map(|_| None).collect();
        for (index, outcome) in receiver {
            indexed[index] = Some(outcome);
        }
        for worker in workers {
            let _ = worker.join();
        }
        indexed
            .into_iter()
            .zip(items.iter())
            .map(|(slot, (instance, host))| {
                slot.unwrap_or_else(|| FleetItemOutcome {
                    instance: instance.clone(),
                    host_alias: host.alias.clone(),
                    result: Err((
                        error_codes::HOST_UNREACHABLE.to_owned(),
                        "the runner produced no outcome for this target".to_owned(),
                    )),
                })
            })
            .collect()
    }
}

fn execute_one(
    instance: &InstanceRecord,
    host: &HostRecord,
    factory: &(
         dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> + Send + Sync
     ),
    job: Arc<ReadJob>,
) -> Result<Value, (String, String)> {
    // Transport construction happens INSIDE the worker thread; the produced
    // target never crosses a thread boundary afterwards.
    let target = match factory(host) {
        Ok(target) => target,
        Err(error) => {
            return Err((
                error_codes::HOST_UNREACHABLE.to_owned(),
                format!("transport for host '{}' failed: {error:#}", host.alias),
            ));
        }
    };
    job(instance, host, target.as_ref())
        .map_err(|error| (stable_code(&format!("{error:#}")), format!("{error:#}")))
}

// ------------------------------------------------------------------ jobs

/// Live probe + authoritative inspection projected into the status document.
/// Both transports answer through the identical [`ExecutionTarget`] contract.
pub(crate) fn status_job(
    record: &InstanceRecord,
    host: &HostRecord,
    target: &dyn ExecutionTarget,
) -> anyhow::Result<Value> {
    let hello = crate::fleet::live_probe(target, host)
        .with_context(|| format!("host '{}' failed its live verification", host.alias))?;
    let inspection = target.inspect_instance(&record.deployment_id)?;
    Ok(status_document(
        record,
        &crate::fleet::summarize_hello(&hello),
        &inspection,
    ))
}

/// Doctor adds observational diagnostics on top of the status document. No
/// gate, no mutation: diagnostics only describe.
pub(crate) fn doctor_job(
    record: &InstanceRecord,
    host: &HostRecord,
    target: &dyn ExecutionTarget,
) -> anyhow::Result<Value> {
    let mut document = status_job(record, host, target)?;
    let mut diagnostics: Vec<String> = Vec::new();

    match record.last_observation.as_ref() {
        None => diagnostics.push("observation cache: never observed".to_owned()),
        Some(observation) if !observation.reachable => {
            diagnostics.push("observation cache: last contact FAILED".to_owned());
        }
        Some(_) => diagnostics.push("observation cache: fresh contact recorded".to_owned()),
    }

    diagnostics.push(
        "backup/public checks are independent observations; they never gate install/update"
            .to_owned(),
    );

    if let Some(object) = document.as_object_mut() {
        object.insert("diagnostics".to_owned(), json!(diagnostics));
    }
    Ok(document)
}

/// Project one inspection into the stable status document shape.
pub(crate) fn status_document(
    record: &InstanceRecord,
    helper: &str,
    inspection: &InstanceInspection,
) -> Value {
    json!({
        "deployment_id": inspection.deployment_id,
        "issuer": inspection.issuer,
        "helper": helper,
        "revision": inspection.revision,
        "runtime": {"kind": inspection.runtime.kind, "object": inspection.runtime.object},
        "config": {"reference": inspection.config_reference, "schema": inspection.config_schema},
        "artifact": {"current": inspection.artifact.current, "previous": inspection.artifact.previous},
        "health": {"state": if inspection.healthy { "ok" } else { "down" }, "summary": inspection.health_summary},
        "backup": inspection.backup,
        "controller": controller_fact_line(record),
    })
}

/// Controller binding line derived only from registry references. Slot status
/// and expiry are deliberately absent: only an explicit live controller-list
/// response may present those server-owned facts.
fn controller_fact_line(record: &InstanceRecord) -> String {
    if record.controller_id.is_none() && record.controller_key_ref.is_none() {
        "unbound".to_owned()
    } else {
        "local binding recorded (live slot status not queried)".to_owned()
    }
}

// ------------------------------------------------------------------ rendering

/// Render one fleet report in stable order; returns the number of failures.
pub(crate) fn render_fleet_report(
    title: &str,
    outcomes: &[FleetItemOutcome],
    json_mode: bool,
) -> usize {
    let failed = outcomes.iter().filter(|item| item.result.is_err()).count();
    if json_mode {
        let results: Vec<Value> = outcomes
            .iter()
            .map(|item| match &item.result {
                Ok(payload) => json!({
                    "alias": item.instance.alias,
                    "deployment_id": item.instance.deployment_id,
                    "host": item.host_alias,
                    "ok": true,
                    "data": payload,
                }),
                Err((code, detail)) => json!({
                    "alias": item.instance.alias,
                    "deployment_id": item.instance.deployment_id,
                    "host": item.host_alias,
                    "ok": false,
                    "code": code,
                    "detail": detail,
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": 1,
                "command": title,
                "total": outcomes.len(),
                "failed": failed,
                "results": results,
            }))
            .expect("fleet report is valid JSON")
        );
    } else {
        println!("{title}: {} instance(s)", outcomes.len());
        for item in outcomes {
            match &item.result {
                Ok(payload) => println!(
                    "[ok]     {} ({}) @ {} — {}",
                    item.instance.alias,
                    item.instance.deployment_id,
                    item.host_alias,
                    compact_summary(payload),
                ),
                Err((code, detail)) => println!(
                    "[FAILED] {} ({}) @ {} — {code}: {detail}",
                    item.instance.alias, item.instance.deployment_id, item.host_alias,
                ),
            }
        }
    }
    failed
}

fn compact_summary(payload: &Value) -> String {
    format!(
        "health={} rev={} artifact={} backup={} controller={}",
        value_str(payload.pointer("/health/state")),
        payload
            .get("revision")
            .and_then(Value::as_u64)
            .map_or_else(|| "-".to_owned(), |v| v.to_string()),
        value_str(payload.pointer("/artifact/current")),
        value_str(payload.pointer("/backup/snapshot/created_at")),
        value_str(payload.get("controller")),
    )
}

fn value_str(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("-").to_owned()
}

/// Marker error distinguishing "some fleet members failed" (full report
/// already printed; exit nonzero WITHOUT a duplicate envelope) from ordinary
/// command failures.
#[derive(Debug)]
pub(crate) struct PartialFleetFailure {
    pub(crate) total: usize,
    pub(crate) failed: usize,
}

impl std::fmt::Display for PartialFleetFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}/{} fleet targets failed; every successful result is shown above",
            self.failed, self.total
        )
    }
}

impl std::error::Error for PartialFleetFailure {}

// ------------------------------------------------------------ registry views

/// Resolve the selector under the I02 rules, fan out (`--all`) or run one
/// target, then render.
pub(crate) fn run_status_like(
    store: &RegistryStore,
    selector: Option<&str>,
    all: bool,
    json_mode: bool,
    command: &str,
    doctor: bool,
) -> anyhow::Result<()> {
    if all {
        if selector.is_some() {
            anyhow::bail!("{command} --all covers every registered instance; drop --instance");
        }
        let instances = store.list_instances()?;
        if instances.is_empty() {
            println!("{command}: no instances are registered");
            return Ok(());
        }
        let mut items = Vec::with_capacity(instances.len());
        for instance in instances {
            let host = store.host_by_id(instance.host_id)?.with_context(|| {
                format!(
                    "instance '{}' references missing host {}",
                    instance.alias, instance.host_id
                )
            })?;
            items.push((instance, host));
        }
        let runner = FleetReadRunner::production();
        let job: Arc<ReadJob> = Arc::new(if doctor { doctor_job } else { status_job });
        let outcomes = runner.run(items, job);
        let failed = render_fleet_report(command, &outcomes, json_mode);
        if failed > 0 {
            return Err(anyhow::Error::new(PartialFleetFailure {
                total: outcomes.len(),
                failed,
            }));
        }
        return Ok(());
    }

    let record = crate::fleet::resolve_instance(store, selector, command)?;
    let host = store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;
    let runner = FleetReadRunner::production();
    let job: Arc<ReadJob> = Arc::new(if doctor { doctor_job } else { status_job });
    let outcomes = runner.run(vec![(record.clone(), host.clone())], job);
    let outcome = outcomes.into_iter().next().expect("one input, one outcome");
    match outcome.result {
        Ok(payload) => {
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).expect("status doc is valid JSON")
                );
            } else {
                print_single_status(&record, &host.alias, &payload, doctor);
            }
            Ok(())
        }
        Err((code, detail)) => Err(anyhow::anyhow!("{code}: {detail}")),
    }
}

fn print_single_status(record: &InstanceRecord, host_alias: &str, payload: &Value, doctor: bool) {
    println!(
        "instance '{}' (deployment {}) on host '{host_alias}'",
        record.alias,
        value_str(payload.get("deployment_id")),
    );
    println!("issuer: {}", value_str(payload.get("issuer")));
    println!("helper: {}", value_str(payload.get("helper")));
    println!(
        "runtime: {}/{} revision {}",
        value_str(payload.pointer("/runtime/kind")),
        value_str(payload.pointer("/runtime/object")),
        payload
            .get("revision")
            .and_then(Value::as_u64)
            .map_or_else(|| "-".to_owned(), |v| v.to_string()),
    );
    println!(
        "config: {} (schema {})",
        value_str(payload.pointer("/config/reference")),
        value_str(payload.pointer("/config/schema")),
    );
    println!(
        "artifacts: current={} previous={}",
        value_str(payload.pointer("/artifact/current")),
        value_str(payload.pointer("/artifact/previous")),
    );
    println!(
        "health: {} — {}",
        value_str(payload.pointer("/health/state")),
        value_str(payload.pointer("/health/summary")),
    );
    println!(
        "backup snapshot: {}",
        value_str(payload.pointer("/backup/snapshot/created_at"))
    );
    println!("controller: {}", value_str(payload.get("controller")));
    if doctor && let Some(diagnostics) = payload.get("diagnostics").and_then(Value::as_array) {
        println!("diagnostics:");
        for entry in diagnostics {
            println!("  - {}", entry.as_str().unwrap_or("-"));
        }
    }
}

/// Read-only operation-log view (H04): control-side dispatch journal plus the
/// authoritative target-side journal projection over the same fixed protocol
/// for local and SSH targets.
pub(crate) fn run_operation_view(
    store: &RegistryStore,
    keys: &crate::controller_identity::store::ControllerKeyStore,
    selector: Option<&str>,
    limit: usize,
    json_mode: bool,
) -> anyhow::Result<()> {
    let record = crate::fleet::resolve_instance(store, selector, "operation")?;
    let host = store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;

    // Control side: the single-slot dispatch journal (E06).
    let journal = crate::controller_identity::journal::OperationJournal::open(
        keys.instance_dir(&record.deployment_id)?,
    )?;
    let pending = journal.load()?;

    let target = crate::fleet::production_target(&host)?;
    crate::fleet::live_probe(target.as_ref(), &host)?;
    let result = target.execute_host_operation(&crate::target::HostOperation::journal_read(
        Uuid::now_v7().to_string(),
        &record.deployment_id,
        limit,
    ))?;
    let entries = match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::JournalRead { entries },
        } => entries,
        crate::target::HostOutcome::Completed { .. } => {
            anyhow::bail!("target returned an unexpected operation-log completion")
        }
        crate::target::HostOutcome::Failed { code, detail } => {
            anyhow::bail!("{code}: {detail}")
        }
    };

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": 1,
                "alias": record.alias,
                "deployment_id": record.deployment_id,
                "dispatch_journal": pending,
                "target_operations": entries,
            }))?
        );
        return Ok(());
    }

    println!(
        "operation log for '{}' (deployment {})",
        record.alias, record.deployment_id
    );
    match &pending {
        Some(entry) => println!(
            "control dispatch journal: operation {} state {:?} since {} (kid {})",
            entry.operation_id,
            entry.state,
            entry.created_at.to_rfc3339(),
            entry.kid
        ),
        None => println!("control dispatch journal: empty"),
    }
    match &entries {
        entries if entries.is_empty() => println!("target operations: none recorded"),
        entries => {
            println!("recent target operations:");
            for entry in entries.iter().rev() {
                let outcome = match &entry.outcome {
                    Some(crate::target::OperationOutcomeSummary::Completed) => {
                        "completed".to_owned()
                    }
                    Some(crate::target::OperationOutcomeSummary::Failed { code, detail }) => {
                        format!("failed {code}: {detail}")
                    }
                    None => "pending".to_owned(),
                };
                println!(
                    "  {} {} [{}] {} — {outcome}",
                    entry.recorded_at.to_rfc3339(),
                    entry.operation_id,
                    match entry.status {
                        crate::target::JournalStatus::Pending => "pending",
                        crate::target::JournalStatus::Completed => "completed",
                        crate::target::JournalStatus::Failed => "failed",
                    },
                    entry.action,
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_logs_view(
    store: &RegistryStore,
    selector: Option<&str>,
    limit: usize,
    json_mode: bool,
) -> anyhow::Result<()> {
    let record = crate::fleet::resolve_instance(store, selector, "logs")?;
    let host = store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;
    let target = crate::fleet::production_target(&host)?;
    crate::fleet::live_probe(target.as_ref(), &host)?;
    let result = target.execute_host_operation(&crate::target::HostOperation::runtime_logs(
        Uuid::now_v7().to_string(),
        &record.deployment_id,
        limit,
    ))?;
    let lines = match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::RuntimeLogs { lines },
        } => lines,
        crate::target::HostOutcome::Completed { .. } => {
            anyhow::bail!("target returned an unexpected runtime-log completion")
        }
        crate::target::HostOutcome::Failed { code, detail } => {
            anyhow::bail!("{code}: {detail}")
        }
    };
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": 1,
                "alias": record.alias,
                "deployment_id": record.deployment_id,
                "lines": lines,
            }))?
        );
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

/// Target-owned backup evidence.  This view never invents readiness from a
/// controller cache: it displays the live manifest/restore-test projection.
pub(crate) fn run_backup_view(
    store: &RegistryStore,
    selector: Option<&str>,
    json_mode: bool,
) -> anyhow::Result<()> {
    let record = crate::fleet::resolve_instance(store, selector, "backup")?;
    let host = store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;
    let runner = FleetReadRunner::production();
    let job: Arc<ReadJob> = Arc::new(status_job);
    let outcomes = runner.run(vec![(record.clone(), host)], job);
    let outcome = outcomes.into_iter().next().expect("one input, one outcome");
    let payload = outcome
        .result
        .map_err(|(code, detail)| anyhow::anyhow!("{code}: {detail}"))?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    println!(
        "backup evidence for '{}' (deployment {}):",
        record.alias, record.deployment_id
    );
    println!(
        "  snapshot: {}",
        value_str(payload.pointer("/backup/snapshot/created_at"))
    );
    println!(
        "  local rollback: {}",
        value_str(payload.pointer("/backup/local_rollback_ready"))
    );
    println!(
        "  restore tested: {}",
        value_str(payload.pointer("/backup/snapshot/restore_tested_at"))
    );
    Ok(())
}

/// Stable-code classifier shared with the error envelope: scan the rendered
/// error chain for known stable tokens.
pub(crate) fn stable_code(rendered: &str) -> String {
    const ORDERED: [(&str, &str); 14] = [
        (
            error_codes::REMOTE_HELPER_MISMATCH,
            error_codes::REMOTE_HELPER_MISMATCH,
        ),
        (error_codes::SSH_AUTH_FAILED, error_codes::SSH_AUTH_FAILED),
        (
            error_codes::SSH_HOST_KEY_FAILED,
            error_codes::SSH_HOST_KEY_FAILED,
        ),
        (
            error_codes::SUDO_PASSWORD_REQUIRED,
            error_codes::PRIVILEGE_REQUIRED,
        ),
        (
            error_codes::PRIVILEGE_REQUIRED,
            error_codes::PRIVILEGE_REQUIRED,
        ),
        (
            error_codes::INSTANCE_NOT_REGISTERED,
            error_codes::INSTANCE_NOT_REGISTERED,
        ),
        (
            error_codes::INSTANCE_AMBIGUOUS,
            error_codes::INSTANCE_AMBIGUOUS,
        ),
        (
            error_codes::STATE_RESET_REQUIRED,
            error_codes::STATE_RESET_REQUIRED,
        ),
        (
            error_codes::CONTROL_BINDING_REQUIRED,
            error_codes::CONTROL_BINDING_REQUIRED,
        ),
        (
            error_codes::CONTROLLER_KEY_EXPIRED,
            error_codes::CONTROLLER_KEY_EXPIRED,
        ),
        (
            error_codes::CONTROLLER_SLOT_LIMIT,
            error_codes::CONTROLLER_SLOT_LIMIT,
        ),
        (
            error_codes::OPERATION_ID_CONFLICT,
            error_codes::OPERATION_ID_CONFLICT,
        ),
        (
            error_codes::CONFIG_REVISION_MISMATCH,
            error_codes::CONFIG_REVISION_MISMATCH,
        ),
        (
            error_codes::TARGET_IDENTITY_MISMATCH,
            error_codes::TARGET_IDENTITY_MISMATCH,
        ),
    ];
    for (token, code) in ORDERED {
        if rendered.contains(token) {
            return code.to_owned();
        }
    }
    if rendered.contains(error_codes::EXTERNAL_RESOURCE_PROTECTED) {
        return error_codes::EXTERNAL_RESOURCE_PROTECTED.to_owned();
    }
    if rendered.contains(error_codes::HOST_NOT_REGISTERED) {
        return error_codes::HOST_NOT_REGISTERED.to_owned();
    }
    if rendered.contains("did not answer within") || rendered.contains("timed out") {
        return error_codes::HOST_UNREACHABLE.to_owned();
    }
    error_codes::HOST_UNREACHABLE.to_owned()
}

#[cfg(test)]
mod tests;
