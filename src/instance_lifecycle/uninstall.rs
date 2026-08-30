//! G06 — uninstall that touches only ctl-owned deployment-scoped resources
//! (goal plan 07 §7).
//!
//! Plan first, then execute:
//!
//! * the deletion plan is generated from the LIVE DeploymentState and lists
//!   exactly the managed+deployment resources plus the runtime object and
//!   config file; external/shared resources are printed as kept — they have
//!   zero-delete paths by construction;
//! * execution requires explicit confirmation; the target derives deletions
//!   from its own authoritative state rather than trusting a duplicated plan;
//!   container runtime identity remains bound by the deployment label;
//! * completion removes ONLY this instance's InstanceRecord — never the
//!   HostRecord and never sibling instances on the same host;
//! * local Controller Key material is deleted with the local InstanceRecord;
//!   Controller Slot rows remain inside any external database the plan keeps.

use anyhow::{Context as _, bail};

use super::{LifecycleContext, resolve_live_instance};
use crate::controller_identity::store::ControllerKeyStore;
use crate::file_lock::FileLock;
use crate::target::{
    ExecutionTarget, HostOperation, HostOutcome, ResourceOwnership, ResourceScope,
    StateMutationPayload,
};

/// One uninstall plan: exact deletions plus everything deliberately kept.
pub(crate) struct UninstallPlan {
    pub(crate) deployment_id: String,
    pub(crate) alias: String,
    pub(crate) host_alias: String,
    pub(crate) revision: u64,
    pub(crate) managed_deletions: Vec<(String, String, String)>, // id, kind, locator
    pub(crate) runtime_object: String,
    pub(crate) config_reference: String,
    pub(crate) kept_external: Vec<(String, String, String)>,
}

/// Render the human-readable plan. The plan precedes any destructive action;
/// nothing has been touched when this string is all the user asked for.
impl UninstallPlan {
    pub(crate) fn render(&self) -> String {
        let mut text = format!(
            "uninstall plan for '{}' (deployment {}, host '{}')\n",
            self.alias, self.deployment_id, self.host_alias
        );
        text.push_str("deletions (managed + deployment-scoped only):\n");
        text.push_str(&format!(
            "  - runtime object '{}' (target-owned runtime identity)\n",
            self.runtime_object
        ));
        for (id, kind, locator) in &self.managed_deletions {
            text.push_str(&format!("  - {id} ({kind}): {locator}\n"));
        }
        text.push_str(&format!(
            "  - config file {}\n  - ctl state document (journal retained)\n",
            self.config_reference
        ));
        if self.kept_external.is_empty() {
            text.push_str("kept: none declared\n");
        } else {
            text.push_str("kept (external/shared — ZERO DELETE):\n");
            for (id, kind, locator) in &self.kept_external {
                text.push_str(&format!("  - {id} ({kind}): {locator}\n"));
            }
        }
        text.push_str("untouched: HostRecord and sibling instances on this host\n");
        text.push_str(
            "Controller Slots in kept external data are unchanged; revoke them before uninstall if required\n",
        );
        text.push_str(
            "local cleanup after target success: InstanceRecord and this deployment's controller key material\n",
        );
        text
    }
}

/// Generate the exact deletion plan from live facts (read-only).
#[cfg(test)]
pub(crate) fn plan_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<UninstallPlan> {
    Ok(prepare_uninstall(context, selector)?.0)
}

fn prepare_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<(UninstallPlan, Box<dyn ExecutionTarget + Send>)> {
    let (record, host, target, inspection) = resolve_live_instance(context, selector, "uninstall")?;
    let mut managed_deletions = Vec::new();
    let mut kept_external = Vec::new();
    for resource in &inspection.resources {
        // Container-kind resources are deleted through the dedicated runtime
        // surface object (ownership label + digest re-confirmation), never as
        // a second deletion entry — declaring them here would double-delete.
        if resource.kind == "container" {
            continue;
        }
        let entry = (
            resource.resource_id.clone(),
            resource.kind.clone(),
            resource.locator.clone(),
        );
        match (resource.ownership, resource.scope) {
            (ResourceOwnership::Managed, ResourceScope::Deployment) => {
                managed_deletions.push(entry)
            }
            _ => kept_external.push(entry),
        }
    }
    Ok((
        UninstallPlan {
            deployment_id: inspection.deployment_id.clone(),
            alias: record.alias.clone(),
            host_alias: host.alias.clone(),
            revision: inspection.revision,
            managed_deletions,
            runtime_object: inspection.runtime.object.clone(),
            config_reference: inspection.config_reference.clone(),
            kept_external,
        },
        target,
    ))
}

/// Execute a previously shown plan. `confirmed` must be an explicit operator
/// decision; without it only the plan is rendered. Confirmed execution reuses
/// the same live read and relies on the target-side revision CAS for drift.
pub(crate) fn run_uninstall(
    context: &LifecycleContext,
    controller_keys: &ControllerKeyStore,
    selector: Option<&str>,
    confirmed: bool,
) -> anyhow::Result<String> {
    let action = "uninstall";
    let (plan, target) = prepare_uninstall(context, selector)?;
    if !confirmed {
        return Ok(format!(
            "{}\nre-run with explicit confirmation (--yes at the CLI boundary) to execute",
            plan.render()
        ));
    }
    let instance_dir = controller_keys.instance_dir(&plan.deployment_id)?;
    crate::filesystem::ensure_private_directory(
        &instance_dir,
        "controller instance lifecycle directory",
    )?;
    // All instance-scoped long-running flows take one of these outer locks
    // before entering the shared key/journal lock. Holding them in that same
    // order makes uninstall a single linearized lifecycle action without a
    // second recovery framework.
    let _bind_lock = FileLock::acquire(&instance_dir.join("bind.lock"))?;
    let _controller_recovery_lock = FileLock::acquire(&instance_dir.join("recovery.lock"))?;
    let _data_recovery_lock = FileLock::acquire(&instance_dir.join("recovery-plan.lock"))?;
    let _transfer_lock = FileLock::acquire(&instance_dir.join("backup-transfer.lock"))?;
    ensure_no_pending_remote_cleanup(controller_keys, &plan.deployment_id)?;

    let operation = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        plan.deployment_id.clone(),
        Some(plan.revision),
        StateMutationPayload::Uninstall {},
    );
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        HostOutcome::Completed { .. } => {}
        HostOutcome::Failed { code, detail } => {
            bail!("{action} failed on the target: {code}: {detail}")
        }
    }

    // Completion removes this instance's two local ownership records. HostRecord
    // and siblings stay. Controller Slot rows are part of an external database
    // and therefore follow the plan's explicit keep decision.
    controller_keys
        .remove_instance(&plan.deployment_id)
        .with_context(|| {
            format!(
                "instance '{}' was uninstalled, but its local controller key cleanup failed; the InstanceRecord was retained so cleanup can be retried",
                plan.alias
            )
        })?;
    context
        .registry
        .forget_instance_by_deployment(&plan.deployment_id)
        .with_context(|| {
            format!(
                "instance '{}' was uninstalled and its local controller keys were removed, but its stale InstanceRecord could not be forgotten",
                plan.alias
            )
        })?;

    Ok(format!(
        "uninstalled instance '{}' (deployment {})\n\
         managed resources removed per plan; external/shared resources were never touched\n\
         Controller Slots in kept external data were unchanged\n\
         InstanceRecord and local controller key material removed; HostRecord '{}' and sibling instances remain\n",
        plan.alias, plan.deployment_id, plan.host_alias,
    ))
}

fn ensure_no_pending_remote_cleanup(
    controller_keys: &ControllerKeyStore,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let instance_dir = controller_keys.instance_dir(deployment_id)?;
    for (file, operation) in [
        ("recovery-plan.json", "disaster recovery"),
        ("backup-transfer.json", "off-host backup transfer"),
    ] {
        let path = instance_dir.join(file);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                bail!(
                    "cannot uninstall while this instance has an incomplete {operation}; resume that operation so its remote staging is cleaned first"
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }
    Ok(())
}
