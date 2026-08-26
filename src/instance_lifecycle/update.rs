//! G03 — minimal crash-safe update (goal plan 07 §4).
//!
//! Control-side flow, exactly the plan's seven steps:
//!
//! 1. live read of current state + expected config revision;
//! 2. digest-pinned verified target artifact (verified on the target);
//! 3. lifecycle journal: ONE operation id shared by both journals —
//!    `previous` is preserved in the target state swap, never deleted;
//! 4. application migration through exactly one pre-signed ControlOperation
//!    delivered via the control-operation kind (resume-safe: the E06 journal
//!    rebuilds a byte-identical envelope and the server dedupes by id+hash,
//!    so response loss can never duplicate the migration);
//! 5. stage/activate/local health inside one journaled HostOperation;
//! 6. activation/health failure rolls artifact/config REFERENCES back on the
//!    target automatically — data changes are never faked as reversible;
//! 7. success commits atomically.
//!
//! No provider/DR gates exist anywhere here, and there is no `--all`.

use anyhow::{Context as _, bail};
use nazo_operator_protocol::{ControlBuildIdentity, ControlOperationPayload, ControlTarget};
use sha2::{Digest as _, Sha256};

use super::{LifecycleContext, record_observation, require_completed, resolve_live_instance};
use crate::controller_identity::dispatch::{
    DispatchVerdict, dispatch_via_target, prepare_control_operation, settle_journal,
};
use crate::controller_identity::journal::OperationJournal;
use crate::controller_identity::operation::ControlOperationInput;
use crate::controller_identity::store::ControllerKeyStore;
use crate::target::{
    BuildIdentity, HostCompletionBody, HostOperation, OfficialArtifactRef, StagedConfig,
    StateMutationPayload,
};

/// One update invocation. Defaults are minimal: only facts that cannot be
/// safely inferred are accepted from the operator.
pub(crate) struct UpdateRequest {
    /// Optional exact instance selector (alias or deployment id).
    pub(crate) instance: Option<String>,
    /// Optional immutable official Release tag pin; absent = latest official.
    pub(crate) version: Option<String>,
    /// Optional subject-digest pin closing the resolve/fetch gap.
    pub(crate) expected_artifact_sha256: Option<String>,
    /// Optional new configuration content staged with this update; requires
    /// `config_schema`.
    pub(crate) config_content: Option<String>,
    /// Schema token for the staged configuration.
    pub(crate) config_schema: Option<String>,
}

impl UpdateRequest {
    fn staged_config(&self) -> anyhow::Result<Option<StagedConfig>> {
        match (&self.config_content, &self.config_schema) {
            (None, _) => Ok(None),
            (Some(content), Some(schema)) => {
                let staged = StagedConfig {
                    content: content.clone(),
                    sha256: hex_digest(content.as_bytes()),
                    schema: schema.clone(),
                };
                staged
                    .validate()
                    .map_err(|rejection| anyhow::anyhow!("{rejection}"))?;
                Ok(Some(staged))
            }
            (Some(_), None) => {
                bail!("staging a configuration requires its schema token alongside the content")
            }
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The G03 entry point. Delivery boundary: wired into the CLI by the I wave.
pub(crate) fn run_update(
    context: &LifecycleContext,
    keys: &ControllerKeyStore,
    request: &UpdateRequest,
) -> anyhow::Result<String> {
    let action = "update";
    // 1.+2. Live facts through the verified handshake (C08 gate upstream of
    // every mutation kind).
    let (record, _host, target, inspection) =
        resolve_live_instance(context, request.instance.as_deref(), action)?;
    let deployment_id = inspection.deployment_id.clone();
    let revision = inspection.revision;
    let Some(current_artifact) = inspection.artifact.current.clone() else {
        bail!(
            "{action}: deployment '{deployment_id}' records no current artifact reference; \
             adopt or install it first"
        );
    };
    let Some(build_identity) = inspection.current_build_identity.clone() else {
        bail!(
            "{action}: deployment '{deployment_id}' carries no recorded build identity for its \
             current artifact; re-register the instance with verified facts or reinstall"
        );
    };

    let pinned = OfficialArtifactRef {
        repository: super::SERVER_REPOSITORY.to_owned(),
        version: request.version.clone(),
        expected_subject_sha256: request.expected_artifact_sha256.clone(),
    };

    // 3.+4. Application migration: exactly ONE pre-signed ControlOperation.
    // Its operation id IS the lifecycle id of this attempt — the HostOperation
    // below reuses it verbatim so retries of one logical attempt carry one
    // identity on both journals (goal plan 07 §4). prepare_control_operation
    // resumes byte-identically after any drop or crash.
    //
    // config_revision is the target's marker content verbatim (P0-6 single
    // authority): the operator admission compares the envelope against the
    // mounted marker byte-for-byte. A missing marker fails closed — guessing
    // the CAS counter would sign an operation that can never be admitted.
    let config_revision = inspection.config_revision_marker.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "{action}: deployment '{deployment_id}' has no config-revision marker on its \
             scope directory; the operator would reject any signed operation, so refusing \
             to sign one"
        )
    })?;
    let journal = OperationJournal::open(keys.instance_dir(&record.deployment_id)?)?;
    let prepared = prepare_control_operation(
        &context.registry,
        keys,
        &journal,
        &record.deployment_id,
        ControlOperationInput {
            operation: ControlOperationPayload::MigrateApply,
            artifact_target: control_target_for(&current_artifact, &build_identity),
            config_revision,
        },
    )
    .context("preparing the migration operation failed; the update changed nothing")?;
    let lifecycle_id = prepared.signed.operation_id.clone();
    let verdict = dispatch_via_target(target.as_ref(), &prepared)?;
    match &verdict {
        DispatchVerdict::Accepted => {}
        DispatchVerdict::FailedDurably { outcome } => {
            // P0-5: a durable business failure (migration executed and
            // failed) must terminate the update BEFORE any activation or
            // state mutation. The journal record stays terminal for this id;
            // rerunning identical inputs replays the identical durable
            // failure instead of re-executing.
            settle_journal(&journal, &prepared, &verdict)?;
            let error_code = outcome
                .error
                .map(|code| format!("{code:?}"))
                .unwrap_or_else(|| "unspecified".to_owned());
            bail!(
                "the application migration failed durably (operation {lifecycle_id}, error \
                 {error_code}); the target artifact/config were NOT activated — inspect \
                 `nazoauthctl operation` for the durable result"
            );
        }
        DispatchVerdict::DefinitivelyRejected => {
            settle_journal(&journal, &prepared, &verdict)?;
            bail!(
                "the migration was refused before acceptance; fix the cause and retry — \
                 the update changed nothing"
            );
        }
        DispatchVerdict::OutcomeUnknown => bail!(
            "the migration outcome is unknown (dispatch failed after journaling); re-run the \
             same update to resume operation {lifecycle_id} instead of starting over"
        ),
    }

    // 5.-7. Stage + activate + local health + commit inside ONE journaled
    // HostOperation carrying the single lifecycle operation id.
    let operation = HostOperation::state_mutate(
        lifecycle_id.clone(),
        deployment_id.clone(),
        Some(revision),
        StateMutationPayload::Update {
            artifact: pinned,
            config: request.staged_config()?,
        },
    );
    let result = target.execute_host_operation(&operation)?;
    let applied_revision = require_completed(
        &result,
        |body| match body {
            HostCompletionBody::StateMutateApplied { revision } => Some(revision.to_string()),
            _ => None,
        },
        "update",
    )?;

    settle_journal(&journal, &prepared, &verdict)?;

    // Refresh the observation cache from a real post-update inspection
    // (display-only; the target state stays the authority).
    let fresh = target.inspect_instance(&deployment_id)?;
    record_observation(context, &deployment_id, &fresh);

    Ok(format!(
        "updated instance '{}' (deployment {deployment_id}) to artifact {}\n\
         previous artifact preserved for explicit rollback\n\
         migration: migrate-apply via ControlOperation {lifecycle_id} (accepted once)\n\
         state committed at revision {applied_revision}; local health verified\n\
         \n\
         data boundary: database or other external mutations performed by the migration are NOT \
         rolled back automatically — consult the release operation contract for irreversible \
         steps before discarding the previous artifact\n\
         next: nazoauthctl verify --instance {}\n",
        record.alias,
        fresh
            .artifact
            .current
            .clone()
            .unwrap_or_else(|| "-".to_owned()),
        record.alias,
    ))
}

/// Build the artifact identity binding for the ControlOperation envelope from
/// the facts recorded at install/update time on the target.
fn control_target_for(current_artifact: &str, identity: &BuildIdentity) -> ControlTarget {
    ControlTarget::OciImage {
        image_digest: current_artifact.to_owned(),
        embedded: ControlBuildIdentity {
            product: identity.product.clone(),
            version: identity.version.clone(),
            commit: identity.commit.clone(),
        },
    }
}
