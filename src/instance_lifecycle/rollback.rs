//! G04 — explicit rollback to the previous verified artifact (goal plan 07
//! §5).
//!
//! Rollback is a normal, explicit user action — never a bypass of the
//! anti-downgrade floor and never a break-glass flow:
//!
//! * the artifact rolls back to the previously verified reference saved in
//!   the target DeploymentState; the handle is verified OFFLINE against the
//!   local engine image store before anything moves;
//! * the config snapshot is restored only when it was explicitly saved by an
//!   update AND still belongs to the deployment's current config generation
//!   (schema-compatible with what the target runs);
//! * data restore is a separate recovery command and stays out of scope;
//! * no application mutation (no ControlOperation) is ever created here;
//! * failure restores the original current references.

use anyhow::bail;

use super::{LifecycleContext, record_observation, require_completed, resolve_live_instance};
use crate::target::{
    HostCompletionBody, HostOperation, ROLLBACK_UNAVAILABLE, StateMutationPayload,
};

/// The G04 entry point. Delivery boundary: wired into the CLI by the I wave.
pub(crate) fn run_rollback(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<String> {
    let action = "rollback";
    let (record, _host, target, inspection) = resolve_live_instance(context, selector, action)?;
    let deployment_id = inspection.deployment_id.clone();
    let revision = inspection.revision;
    if inspection.artifact.previous.is_none() {
        bail!(
            "{ROLLBACK_UNAVAILABLE}: deployment '{deployment_id}' has no previous verified \
             artifact reference saved; rollback restores saved facts only and never guesses"
        );
    }

    // One lifecycle operation id per attempt. Retries after a drop re-execute
    // idempotent steps under a fresh id or replay the stored result for the
    // same id; the config/artifact CAS on the target makes double-apply
    // impossible either way.
    let operation = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        deployment_id.clone(),
        Some(revision),
        StateMutationPayload::Rollback {},
    );
    let result = target.execute_host_operation(&operation)?;
    let applied_revision = require_completed(
        &result,
        |body| match body {
            HostCompletionBody::StateMutateApplied { revision } => Some(revision.to_string()),
            _ => None,
        },
        action,
    )?;

    let fresh = target.inspect_instance(&deployment_id)?;
    record_observation(context, &deployment_id, &fresh);

    Ok(format!(
        "rolled instance '{alias}' (deployment {deployment_id}) back to its previous verified \
         artifact\n\
         current artifact: {current}\n\
         state committed at revision {applied_revision}; local health verified\n\
         note: rollback restores artifact/config references only — data restore remains the \
         separate recovery command\n\
         next: nazoauthctl verify --instance {alias}\n",
        alias = record.alias,
        current = fresh
            .artifact
            .current
            .clone()
            .unwrap_or_else(|| "-".to_owned()),
    ))
}
