//! G03 — minimal crash-safe update (goal plan 07 §4).
//!
//! Control-side flow, exactly the plan's seven steps:
//!
//! 1. live read of current state + expected config revision;
//! 2. digest-pinned official artifact (verified on the target);
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
use chrono::Utc;
use nazo_operator_protocol::ControlOperationPayload;
use sha2::{Digest as _, Sha256};

use super::{LifecycleContext, record_observation, resolve_live_instance};
use crate::controller_identity::dispatch::{
    DispatchVerdict, prepare_control_operation, settle_journal,
};
use crate::controller_identity::journal::OperationJournal;
use crate::controller_identity::operation::ControlOperationInput;
use crate::controller_identity::store::ControllerKeyStore;
use crate::registry::BackupBeforeUpdatePolicy;
use crate::target::{
    HostCompletionBody, HostOperation, HostOutcome, OfficialArtifactRef, StagedConfig,
    StateMutationPayload, UpdateBackupPrecondition,
};

/// One update invocation. Defaults are minimal: only facts that cannot be
/// safely inferred are accepted from the operator.
pub(crate) struct UpdateRequest {
    /// Optional exact instance selector (alias or deployment id).
    pub(crate) instance: Option<String>,
    /// Optional immutable official Release tag pin; absent = latest official.
    pub(crate) version: Option<String>,
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
    if inspection.artifact.current.is_none() {
        bail!(
            "{action}: deployment '{deployment_id}' records no current artifact reference; \
             adopt or install it first"
        );
    }
    let backup_precondition = match &record.backup_before_update {
        BackupBeforeUpdatePolicy::Off => UpdateBackupPrecondition::NotRequired,
        BackupBeforeUpdatePolicy::Warn => {
            if restore_test_age_seconds(&inspection).is_none() {
                crate::ui::warning!(
                    "nazoauthctl: warning: update proceeds without a current restore-tested snapshot for '{}'",
                    "注意：实例“{}”没有经过恢复验证的当前备份；按现有策略继续更新。",
                    record.alias
                );
            }
            UpdateBackupPrecondition::NotRequired
        }
        BackupBeforeUpdatePolicy::Require { max_age_seconds } => {
            let Some(snapshot) = inspection.backup.snapshot.as_ref() else {
                bail!(
                    "update: backup-before-update=require for '{}' needs a restore-tested snapshot",
                    record.alias
                );
            };
            let Some(restore_tested_at) = snapshot.restore_tested_at else {
                bail!(
                    "update: backup-before-update=require for '{}' needs a restore-tested snapshot",
                    record.alias
                );
            };
            let Some(age_seconds) = restore_test_age_seconds(&inspection) else {
                bail!(
                    "update: backup-before-update=require for '{}' has a restore-test timestamp in the future",
                    record.alias
                );
            };
            if age_seconds > *max_age_seconds {
                bail!(
                    "update: backup-before-update=require for '{}' needs a restore-test no older than {} seconds (current age {} seconds)",
                    record.alias,
                    max_age_seconds,
                    age_seconds
                );
            }
            UpdateBackupPrecondition::Require {
                manifest_sha256: snapshot.manifest_sha256.clone(),
                restore_tested_at,
                max_age_seconds: *max_age_seconds,
            }
        }
    };

    let pinned = OfficialArtifactRef {
        repository: super::SERVER_REPOSITORY.to_owned(),
        version: request.version.clone(),
    };

    let staged_config = request.staged_config()?;

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
            config_revision,
        },
    )
    .context("preparing the migration operation failed; the update changed nothing")?;
    let lifecycle_id = prepared.signed.operation_id.clone();

    // 5.-7. Stage + activate + local health + commit inside ONE journaled
    // HostOperation carrying the single lifecycle operation id and signed migration.
    let operation = HostOperation::state_mutate(
        lifecycle_id.clone(),
        deployment_id.clone(),
        Some(revision),
        StateMutationPayload::Update {
            artifact: pinned,
            backup_precondition,
            config: staged_config,
            migration_jws: Some(prepared.signed.compact_jws.clone()),
            migration_request_hash: Some(prepared.signed.request_hash.clone()),
        },
    );
    let result = target.execute_host_operation(&operation)?;
    let applied_revision = match &result.outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::StateMutateNoop { revision },
        } => {
            // The target verified the selected artifact and proved that no
            // config change was requested.  The prepared ControlOperation was
            // never delivered, so there is no ControlResult to settle; clear
            // its write-ahead slot directly and report the target's explicit
            // no-op.
            journal.clear()?;
            record_observation(context, &deployment_id, &inspection);
            return Ok(crate::ui::message!(
                "instance '{}' already runs the target-verified artifact; no migration or target mutation was needed (revision {})\n",
                "实例“{}”已是所选版本，无需更新或迁移（配置修订 {}）。\n",
                record.alias,
                revision
            ));
        }
        HostOutcome::Completed { body } => match body {
            HostCompletionBody::StateMutateApplied {
                revision,
                control_result: Some(control_result),
            } => {
                settle_journal(
                    &journal,
                    &prepared,
                    &DispatchVerdict::Terminal(control_result.clone()),
                    |_| Ok(()),
                )?;
                revision.to_string()
            }
            HostCompletionBody::StateMutateMigrationFailed { result } => {
                settle_journal(
                    &journal,
                    &prepared,
                    &DispatchVerdict::Terminal(result.clone()),
                    |_| Ok(()),
                )?;
                bail!(
                    "the application migration failed durably (operation {lifecycle_id}); target artifact/config were NOT activated"
                );
            }
            HostCompletionBody::StateMutateRecoveryRequired { result, detail } => {
                settle_journal(
                    &journal,
                    &prepared,
                    &DispatchVerdict::Terminal(result.clone()),
                    |_| Ok(()),
                )?;
                bail!(
                    "{}: migration succeeded but activation/readiness could not commit safely; {detail}",
                    crate::target::ROLLBACK_RECOVERY_REQUIRED
                );
            }
            HostCompletionBody::StateMutateApplied {
                control_result: None,
                ..
            } => bail!("update: target omitted the MigrateApply ControlResult"),
            _ => bail!("update: the target answered an unexpected completion body"),
        },
        HostOutcome::Failed { code, detail } => {
            if code == "MIGRATION_FAILED" || detail.contains("migration failed durably") {
                // A terminal FAILED ControlResult means NazoAuth accepted the
                // signed operation. The exact result remains authoritative in
                // NazoAuth's durable journal; the ctl journal only records the
                // accepted authorization snapshot and must never fabricate a
                // replacement ControlResult with invented timestamps.
                bail!(
                    "the application migration failed durably (operation {lifecycle_id}, error \
                     {code}); the target artifact/config were NOT activated — inspect \
                     `nazoauthctl operation` for the durable result"
                );
            }
            if code == "CONTROL_OUTCOME_UNKNOWN" || detail.contains("CONTROL_OUTCOME_UNKNOWN") {
                settle_journal(
                    &journal,
                    &prepared,
                    &DispatchVerdict::OutcomeUnknown,
                    |_| Ok(()),
                )?;
                bail!(
                    "the migration outcome is unknown (dispatch failed after journaling); re-run the \
                     same update to resume operation {lifecycle_id} instead of starting over ({code}: {detail})"
                );
            }
            settle_journal(
                &journal,
                &prepared,
                &DispatchVerdict::DefinitivelyRejected {
                    code: "REJECTED".to_owned(),
                },
                |_| Ok(()),
            )?;
            bail!("update failed on the target: {code}: {detail}");
        }
    };

    // Refresh the observation cache from a real post-update inspection
    // (display-only; the target state stays the authority).
    let fresh = target.inspect_instance(&deployment_id)?;
    record_observation(context, &deployment_id, &fresh);

    let title = crate::ui::message!("Updated instance '{}'", "实例“{}”更新完成", record.alias);
    let mut report = crate::ui::fields(
        &title,
        &[
            (
                crate::ui::text("Version", "版本"),
                fresh
                    .current_release
                    .as_ref()
                    .map(|release| release.version.clone())
                    .unwrap_or_else(|| "-".into()),
            ),
            (
                crate::ui::text("Health", "健康"),
                crate::ui::text("Local health verified", "本机健康检查通过").into(),
            ),
            (
                crate::ui::text("Migration", "数据迁移"),
                crate::ui::text("Completed (accepted once)", "已完成").into(),
            ),
            (
                crate::ui::text("Configuration revision", "配置修订"),
                applied_revision.to_string(),
            ),
            (
                crate::ui::text("Artifact rollback", "程序回滚"),
                if fresh.artifact.previous.is_some() {
                    crate::ui::text("Previous version available", "可回滚至上一版本")
                } else {
                    crate::ui::text(
                        "Unavailable; use backup recovery if needed",
                        "不可直接回滚，需要时从备份恢复",
                    )
                }
                .into(),
            ),
        ],
    );
    report.push_str(crate::ui::text(
        "\n\nDatabase changes are not undone by an artifact rollback.",
        "\n\n程序回滚不会撤销已执行的数据库迁移。",
    ));
    report.push_str(&crate::ui::message!(
        "\nNext: nazoauthctl verify --instance {}\n",
        "\n下一步：nazoauthctl verify --instance {}\n",
        record.alias
    ));
    Ok(report)
}

fn restore_test_age_seconds(inspection: &crate::target::InstanceInspection) -> Option<u64> {
    let restored_at = inspection.backup.snapshot.as_ref()?.restore_tested_at?;
    let age = Utc::now().signed_duration_since(restored_at).num_seconds();
    u64::try_from(age).ok()
}
