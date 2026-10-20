//! Instance update, rollback and uninstall over the same local/SSH target boundary.
//! Live inspections supply planning facts; target-side journals and revision checks
//! own mutations. Registry observations are display-only.

pub(crate) mod privilege;
mod rollback;
mod uninstall;
mod update;

#[cfg(test)]
mod tests;

pub(crate) use rollback::run_rollback;
pub(crate) use uninstall::run_uninstall;
pub(crate) use update::{UpdateRequest, run_update};

use anyhow::Context as _;

use crate::fleet::{live_probe, production_target, resolve_instance};
use crate::registry::{HostRecord, ObservationCache, RegistryStore};
use crate::target::{
    ExecutionTarget, HostCompletionBody, HostOutcome, HostResult, InstanceInspection,
};

/// The official server release repository pinned for lifecycle operations.
pub(crate) const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";

/// Injectable context mirroring the clean-install context: the user-scoped
/// registry plus a way to reach hosts. Tests substitute scripted targets.
pub(crate) type TargetFactory =
    dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>>;

pub(crate) struct LifecycleContext {
    pub(crate) registry: RegistryStore,
    pub(crate) factory: Box<TargetFactory>,
}

impl LifecycleContext {
    pub(crate) fn production() -> anyhow::Result<Self> {
        Ok(Self {
            registry: RegistryStore::open_default()?,
            factory: Box::new(production_target),
        })
    }

    fn target_for(&self, record: &HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
        (self.factory)(record)
    }
}

/// Resolve the instance selector, reach its host through a verified live
/// probe, and read the authoritative DeploymentState inspection. Every
/// lifecycle action starts here so plans are always built from live facts.
pub(crate) fn resolve_live_instance(
    context: &LifecycleContext,
    selector: Option<&str>,
    action: &str,
) -> anyhow::Result<(
    crate::registry::InstanceRecord,
    HostRecord,
    Box<dyn ExecutionTarget + Send>,
    InstanceInspection,
)> {
    let (record, host, target) = resolve_instance_target(context, selector, action)?;
    let inspection = target
        .inspect_instance(&record.deployment_id)
        .with_context(|| {
            format!(
                "the deployment state of '{}' could not be read; {} changed nothing",
                record.deployment_id, action
            )
        })?;
    Ok((record, host, target, inspection))
}

/// Resolves the registered target without requiring a still-installed runtime.
/// Uninstall completion may legitimately outlive its DeploymentState.
fn resolve_instance_target(
    context: &LifecycleContext,
    selector: Option<&str>,
    action: &str,
) -> anyhow::Result<(
    crate::registry::InstanceRecord,
    HostRecord,
    Box<dyn ExecutionTarget + Send>,
)> {
    let record = resolve_instance(&context.registry, selector, action)?;
    let host = context
        .registry
        .host_by_id(record.host_id)?
        .with_context(|| format!("instance '{}' references a missing host", record.alias))?;
    let target = context.target_for(&host)?;
    // Verify the helper before reading or mutating target state.
    live_probe(target.as_ref(), &host).with_context(|| {
        format!(
            "host '{}' failed its live verification; {} changed nothing",
            host.alias, action
        )
    })?;
    Ok((record, host, target))
}

/// Extract a typed failure from a HostResult, preserving the stable code.
fn require_completed(
    result: &HostResult,
    expected: impl Fn(&HostCompletionBody) -> Option<String>,
    what: &str,
) -> anyhow::Result<String> {
    match &result.outcome {
        HostOutcome::Completed { body } => expected(body).ok_or_else(|| {
            anyhow::anyhow!("{what}: the target answered an unexpected completion body")
        }),
        HostOutcome::Failed { code, detail } => Err(anyhow::anyhow!(
            "{what} failed on the target: {code}: {detail}"
        )),
    }
}

/// Refresh the instance observation cache after a lifecycle mutation with a
/// real inspection summary (display-only; never authority).
fn record_observation(
    context: &LifecycleContext,
    deployment_id: &str,
    inspection: &InstanceInspection,
) {
    let _ = context.registry.set_instance_observation(
        deployment_id,
        ObservationCache::now(true, crate::fleet::summarize_inspection(inspection)),
    );
}
