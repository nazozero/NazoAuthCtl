//! G06 — uninstall that touches only ctl-owned deployment-scoped resources
//! (goal plan 07 §7).
//!
//! Plan first, then execute:
//!
//! * the deletion plan is generated from the LIVE DeploymentState and lists
//!   exactly the managed+deployment resources plus the runtime object and
//!   config file; external/shared resources are printed as kept — they have
//!   zero-delete paths by construction;
//! * execution requires the operator's explicit confirmation AND target-side
//!   re-confirmation of every fact (resource locator equality, runtime object
//!   ownership label); any drift fails closed with `OBJECT_IDENTITY_MISMATCH`;
//! * completion removes ONLY this instance's InstanceRecord — never the
//!   HostRecord and never sibling instances on the same host;
//! * Controller binding removal is an independent NazoAuth-side step
//!   (`controller revoke`, D08): it is printed as follow-up guidance and
//!   deliberately not conflated with uninstall.

use anyhow::{Context as _, bail};

use super::{LifecycleContext, resolve_live_instance};
use crate::target::{
    HostOperation, HostOutcome, OBJECT_IDENTITY_MISMATCH, PlannedResourceDeletion,
    ResourceOwnership, ResourceScope, StateMutationPayload,
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
            "  - runtime object '{}' (identity re-confirmed by ownership label)\n",
            self.runtime_object
        ));
        for (id, kind, locator) in &self.managed_deletions {
            text.push_str(&format!("  - {id} ({kind}): {locator}\n"));
        }
        text.push_str(&format!(
            "  - config file {}\n  - ctl state document + bootstrap material (journal retained)\n",
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
        text.push_str(
            "untouched: HostRecord, sibling instances on this host, controller slots at NazoAuth\n",
        );
        text
    }
}

/// Generate the exact deletion plan from live facts (read-only).
pub(crate) fn plan_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<UninstallPlan> {
    let (record, host, _target, inspection) =
        resolve_live_instance(context, selector, "uninstall")?;
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
    Ok(UninstallPlan {
        deployment_id: inspection.deployment_id.clone(),
        alias: record.alias.clone(),
        host_alias: host.alias.clone(),
        revision: inspection.revision,
        managed_deletions,
        runtime_object: inspection.runtime.object.clone(),
        config_reference: inspection.config_reference.clone(),
        kept_external,
    })
}

/// Execute a previously shown plan. `confirmed` must be an explicit operator
/// decision; without it only the plan is rendered. The plan is regenerated
/// from live facts immediately before execution so drift between show-time
/// and execution fails closed on the target's identity re-confirmation.
pub(crate) fn run_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
    confirmed: bool,
) -> anyhow::Result<String> {
    let action = "uninstall";
    let plan = plan_uninstall(context, selector)?;
    if !confirmed {
        return Ok(format!(
            "{}\nre-run with explicit confirmation (--yes at the CLI boundary) to execute",
            plan.render()
        ));
    }

    // Live facts again: the destructive operation is built from THIS moment's
    // state, and its expected_revision CAS makes concurrent drift fail closed.
    let (_record, host, target, inspection) =
        resolve_live_instance(context, Some(&plan.deployment_id), action)?;
    if host.alias != plan.host_alias || inspection.revision != plan.revision {
        bail!(
            "{OBJECT_IDENTITY_MISMATCH}: the deployment changed since the plan was generated; \
             regenerate the plan before executing"
        );
    }

    let planned = plan
        .managed_deletions
        .iter()
        .map(|(id, _, locator)| PlannedResourceDeletion {
            resource_id: id.clone(),
            locator: locator.clone(),
        })
        .collect::<Vec<_>>();

    let operation = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        plan.deployment_id.clone(),
        Some(inspection.revision),
        StateMutationPayload::Uninstall { resources: planned },
    );
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        HostOutcome::Completed { .. } => {}
        HostOutcome::Failed { code, detail } => {
            bail!("{action} failed on the target: {code}: {detail}")
        }
    }

    // Completion removes ONLY the InstanceRecord. HostRecord and siblings
    // stay; controller slots stay (independent revoke step).
    context
        .registry
        .forget_instance_by_deployment(&plan.deployment_id)
        .with_context(|| format!("failed to forget instance {}", plan.alias))?;

    Ok(format!(
        "uninstalled instance '{}' (deployment {})\n\
         managed resources removed per plan; external/shared resources were never touched\n\
         InstanceRecord removed from the registry; HostRecord '{}' and sibling instances remain\n\
         \n\
         independent follow-ups (NOT part of uninstall):\n\
         - revoke the Controller Slot at NazoAuth if one exists:\n\
             nazoauthctl controller list --instance {alias}\n\
         - local controller key material stays until the revoke flow cleans it up\n",
        plan.alias,
        plan.deployment_id,
        plan.host_alias,
        alias = plan.alias,
    ))
}
