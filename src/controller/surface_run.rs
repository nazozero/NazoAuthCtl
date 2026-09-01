//! Dispatcher for the final command surface (goal plan 09 §1, I01/I02).
//!
//! Every arm wires one tested use-case module; this file contains no business
//! logic of its own beyond selector merging, confirmation prompts, and the
//! stable error rendering.

use std::path::Path;

use anyhow::{Context as _, bail};

use crate::admin_credentials::{AdminCredentialsInput, read_admin_credentials};
use crate::clean_install::{
    CleanInstallContext, CleanInstallRequest, CurlPublicProber, admin_provision_password_material,
    verify_public,
};
use crate::cli::{
    AdminCommand, AdminCreateArgs, BackupArgs, BackupCommand, Cli, Command, InstallArgs,
    InstanceCommand, InstanceSelector, PolicyArgs, RecoverArgs, UpdateArgs,
};
use crate::controller::recovery_journal::{self, CandidatePointer, RecoveryJournal, RecoveryPhase};
use crate::controller::recovery_transport::RecoveryCeremonyTransport;
use crate::controller::transfer_journal::{TransferJournal, TransferPhase, TransferRecord};
use crate::controller_identity::lifecycle as identity;
use crate::controller_identity::store::ControllerKeyStore;
use crate::discover_adopt::{DiscoverRequest, DiscoveryContext};
use crate::instance_lifecycle::{LifecycleContext, UpdateRequest};
use crate::registry::{HostTransport, RegistryStore};

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    // Copied out before the command is moved; selector helpers close over these.
    let global_instance = cli.instance.clone();
    let json_mode = cli.json;
    let instance_flag = global_instance.as_deref();
    match cli.command {
        // ---- primary 18-command surface ------------------------------------
        Command::Host(command) => crate::fleet::run_host(command),
        Command::Instance(mut command) => {
            // P1-2: fold the global --instance into the command-level selector,
            // strictly rejecting collisions where both channels are present.
            let apply_merge = |sel: &mut InstanceSelector, label: &str| -> anyhow::Result<()> {
                if let Some(merged) = sel.merge_global(instance_flag, label)? {
                    sel.positional = Some(merged);
                    sel.named = None;
                }
                Ok(())
            };
            match &mut command {
                InstanceCommand::Show(selector) => apply_merge(selector, "instance show")?,
                InstanceCommand::Forget(selector) => apply_merge(selector, "instance forget")?,
                InstanceCommand::Rename {
                    source: selector, ..
                } => apply_merge(selector, "instance rename")?,
                InstanceCommand::Relocate { selector, .. } => {
                    apply_merge(selector, "instance relocate")?
                }
                _ => {}
            }
            crate::fleet::run_instance(command)
        }
        Command::Controller(command) => identity::run_controller_command(command, instance_flag),
        Command::Bind(options) => identity::run_bind(options, instance_flag),
        Command::Install(args) => run_install(args),
        Command::Discover { host } => {
            let context = DiscoveryContext::production()?;
            let report = crate::discover_adopt::run_discover(&context, DiscoverRequest { host })?;
            println!("{report}");
            Ok(())
        }
        Command::Status { selector, all } => {
            selector_scoped(&selector, instance_flag, "status", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_status_like(
                    &store,
                    merged.as_deref(),
                    all,
                    json_mode,
                    "status",
                    false,
                )
            })
        }
        Command::Doctor { selector, all } => {
            selector_scoped(&selector, instance_flag, "doctor", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_status_like(
                    &store,
                    merged.as_deref(),
                    all,
                    json_mode,
                    "doctor",
                    true,
                )
            })
        }
        Command::Logs { selector, limit } => {
            selector_scoped(&selector, instance_flag, "logs", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_logs_view(&store, merged.as_deref(), limit, json_mode)
            })
        }
        Command::Verify { selector } => {
            selector_scoped(&selector, instance_flag, "verify", run_verify)
        }
        Command::Update(args) => run_update(args, instance_flag),
        Command::Rollback { selector } => {
            let merged = merge(&selector, instance_flag, "rollback")?;
            let context = LifecycleContext::production()?;
            let report = crate::instance_lifecycle::run_rollback(&context, merged.as_deref())?;
            println!("{report}");
            Ok(())
        }
        Command::Operation { selector, limit } => {
            selector_scoped(&selector, instance_flag, "operation", |merged| {
                let store = RegistryStore::open_default()?;
                let keys = ControllerKeyStore::open_default()?;
                crate::fleet::fleet_read::run_operation_view(
                    &store,
                    &keys,
                    merged.as_deref(),
                    limit,
                    json_mode,
                )
            })
        }
        Command::Backup(args) => run_backup(args, instance_flag, json_mode),
        Command::Policy(args) => run_policy(args, instance_flag),
        Command::Recover(args) => run_recover(args, instance_flag),
        Command::Uninstall { selector, yes } => {
            let merged = merge(&selector, instance_flag, "uninstall")?;
            let context = LifecycleContext::production()?;
            let keys = ControllerKeyStore::open_default()?;
            let report =
                crate::instance_lifecycle::run_uninstall(&context, &keys, merged.as_deref(), yes)?;
            println!("{report}");
            Ok(())
        }
        // ---- final-model maintenance surface --------------------------------
        Command::Admin(command) => run_admin(command, instance_flag),
        Command::Tls(command) => crate::tls::run(instance_flag, command, super::require_root),
        Command::RemoteExec => crate::target::remote_exec::run_stdio(),
        Command::SelfCheck(version) => super::self_update::controller_check(version.as_deref()),
        Command::SelfUpdate { version } => {
            super::require_self_update_privilege()?;
            super::self_update::controller_update(version.as_deref())
        }
        Command::SelfRollback => {
            super::require_self_update_privilege()?;
            super::self_update::controller_rollback()
        }
    }
}

// ------------------------------------------------------------------ helpers

/// Apply the I02 exactly-one rule between the global `--instance` and any
/// command-level channel.
fn merge(
    selector: &InstanceSelector,
    global: Option<&str>,
    action: &str,
) -> anyhow::Result<Option<String>> {
    selector.merge_global(global, action)
}

fn selector_scoped<T>(
    selector: &InstanceSelector,
    global: Option<&str>,
    action: &str,
    body: impl FnOnce(Option<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    body(merge(selector, global, action)?)
}

fn run_backup(args: BackupArgs, global: Option<&str>, json_mode: bool) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "backup")?;
    if args.command == BackupCommand::Show {
        let store = RegistryStore::open_default()?;
        return crate::fleet::fleet_read::run_backup_view(&store, merged.as_deref(), json_mode);
    }
    let context = LifecycleContext::production()?;
    let (record, source_host, target, inspection) =
        crate::instance_lifecycle::resolve_live_instance(&context, merged.as_deref(), "backup")?;
    if let BackupCommand::Copy { to_host } = args.command {
        return run_backup_copy(
            &context.registry,
            &record,
            &source_host,
            target.as_ref(),
            &inspection.deployment_id,
            &to_host,
        );
    }
    let operation = match args.command {
        BackupCommand::Snapshot => crate::target::HostOperation::backup_snapshot(
            uuid::Uuid::now_v7(),
            inspection.deployment_id,
        ),
        BackupCommand::RestoreTest => crate::target::HostOperation::backup_restore_test(
            uuid::Uuid::now_v7(),
            inspection.deployment_id,
        ),
        BackupCommand::Show => unreachable!(),
        BackupCommand::Copy { .. } => {
            unreachable!("copy returned before constructing a single-target operation")
        }
    };
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupSnapshotCreated { manifest },
        } => println!(
            "snapshot {} created for '{}' at {}\nmanifest sha256: {}\nnext: nazoauthctl --instance {} backup restore-test",
            manifest.snapshot_id,
            record.alias,
            manifest.created_at.to_rfc3339(),
            manifest.manifest_sha256,
            record.alias,
        ),
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupRestoreTested { receipt },
        } => println!(
            "snapshot {} was actually restored into isolated database {} at {}",
            receipt.snapshot_id,
            receipt.isolated_database,
            receipt.restored_at.to_rfc3339(),
        ),
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup: target returned an unexpected completion")
        }
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup failed: {code}: {detail}")
        }
    }
    Ok(())
}

/// Copy one immutable snapshot strictly through the two targets' journaled
/// HostOperation channels.  The controller never receives a remote path and
/// cannot invoke a second transfer protocol.
fn run_backup_copy(
    registry: &RegistryStore,
    record: &crate::registry::InstanceRecord,
    source_host: &crate::registry::HostRecord,
    source_target: &dyn crate::target::ExecutionTarget,
    deployment_id: &str,
    destination_alias: &str,
) -> anyhow::Result<()> {
    let keys = ControllerKeyStore::open_default()?;
    let journal = TransferJournal::open(&keys.instance_dir(deployment_id)?)?;
    let existing = journal.load()?;
    if let Some(existing) = &existing
        && (existing.deployment_id != deployment_id
            || existing.source_host_id != source_host.host_id.to_string()
            || existing.destination_alias != destination_alias)
    {
        return transfer_binding_error(existing, &record.alias);
    }
    let destination_host = registry.host_by_alias(destination_alias)?.with_context(|| {
        if let Some(existing) = &existing {
            format!(
                "backup copy: unfinished transfer requires destination '{}' with host id {}; restore that exact host registration and rerun `nazoauthctl --instance {} backup copy --to-host {}`",
                existing.destination_alias,
                existing.destination_host_id,
                record.alias,
                existing.destination_alias,
            )
        } else {
            format!("backup copy: unknown destination host '{destination_alias}'")
        }
    })?;
    if destination_host.host_id == source_host.host_id {
        bail!("backup copy requires a distinct registered destination host");
    }
    let mut transfer = match existing {
        Some(existing) => {
            validate_transfer_binding(
                &existing,
                deployment_id,
                &source_host.host_id.to_string(),
                &destination_host.host_id.to_string(),
                &destination_host.alias,
                &record.alias,
            )?;
            existing
        }
        None => {
            let created = TransferRecord::new(
                deployment_id.to_owned(),
                source_host.host_id.to_string(),
                destination_host.host_id.to_string(),
                destination_host.alias.clone(),
            );
            journal.store(&created)?;
            created
        }
    };
    crate::fleet::live_probe(source_target, source_host)
        .context("backup copy: source target identity probe failed")?;
    let destination_target = crate::fleet::production_target(&destination_host)?;
    crate::fleet::live_probe(destination_target.as_ref(), &destination_host)
        .context("backup copy: destination target identity probe failed")?;
    let receipt = resume_backup_transfer(
        &journal,
        &mut transfer,
        source_target,
        destination_target.as_ref(),
    )?;
    println!(
        "snapshot {} copied from '{}' to distinct host '{}' at {}\nmanifest sha256: {}",
        receipt.snapshot_id,
        record.alias,
        destination_host.alias,
        receipt.verified_at.to_rfc3339(),
        receipt.manifest_sha256,
    );
    Ok(())
}

fn validate_transfer_binding(
    transfer: &TransferRecord,
    deployment_id: &str,
    source_host_id: &str,
    destination_host_id: &str,
    destination_alias: &str,
    instance_alias: &str,
) -> anyhow::Result<()> {
    if transfer.deployment_id != deployment_id
        || transfer.source_host_id != source_host_id
        || transfer.destination_host_id != destination_host_id
        || transfer.destination_alias != destination_alias
    {
        return transfer_binding_error(transfer, instance_alias);
    }
    Ok(())
}

fn transfer_binding_error<T>(transfer: &TransferRecord, instance_alias: &str) -> anyhow::Result<T> {
    bail!(
        "backup copy: an unfinished transfer is bound to deployment '{}', source host '{}', and destination '{}' ({}); restore those exact registry facts and rerun `nazoauthctl --instance {} backup copy --to-host {}`, because starting a second transfer would orphan target staging",
        transfer.deployment_id,
        transfer.source_host_id,
        transfer.destination_alias,
        transfer.destination_host_id,
        instance_alias,
        transfer.destination_alias,
    )
}

fn resume_backup_transfer(
    journal: &TransferJournal,
    transfer: &mut TransferRecord,
    source: &dyn crate::target::ExecutionTarget,
    destination: &dyn crate::target::ExecutionTarget,
) -> anyhow::Result<crate::target::backup::OffHostCopyReceipt> {
    loop {
        match transfer.phase {
            TransferPhase::SourcePrepare => {
                let plan = expect_transfer_plan(
                    source.execute_host_operation(
                        &crate::target::HostOperation::backup_export_prepare(
                            &transfer.transfer_operation_id,
                            &transfer.deployment_id,
                        ),
                    )?,
                    "source export preparation",
                )?;
                validate_source_plan(transfer, &plan)?;
                transfer.source_plan = Some(plan);
                transfer.phase = TransferPhase::DestinationPrepare;
                journal.store(transfer)?;
            }
            TransferPhase::DestinationPrepare => {
                let plan = expect_transfer_plan(
                    destination.execute_host_operation(
                        &crate::target::HostOperation::backup_import_prepare(
                            &transfer.transfer_operation_id,
                            &transfer.deployment_id,
                        ),
                    )?,
                    "destination import preparation",
                )?;
                if plan.operation_id != transfer.transfer_operation_id
                    || plan.deployment_id != transfer.deployment_id
                    || !plan.manifest_sha256.is_empty()
                    || !plan.files.is_empty()
                {
                    bail!(
                        "backup copy: destination returned a transfer plan with mismatched immutable bindings; the durable transfer was retained for exact retry"
                    );
                }
                transfer.reset_cursor(0, 0);
                transfer.phase = TransferPhase::Copying;
                journal.store(transfer)?;
            }
            TransferPhase::Copying => {
                copy_one_backup_chunk(journal, transfer, source, destination)?;
            }
            TransferPhase::Finalize => {
                let plan = transfer
                    .source_plan
                    .as_ref()
                    .context("backup copy: durable source plan is missing")?;
                let receipt = expect_import_receipt(destination.execute_host_operation(
                    &crate::target::HostOperation::backup_import_finalize(
                        &transfer.finalize_operation_id,
                        &transfer.deployment_id,
                        transfer.transfer_operation_id.clone(),
                        plan.manifest_sha256.clone(),
                        transfer.source_host_id.clone(),
                        transfer.destination_host_id.clone(),
                    ),
                )?)?;
                validate_receipt(transfer, &receipt)?;
                transfer.receipt = Some(receipt);
                transfer.phase = TransferPhase::RecordSourceReceipt;
                journal.store(transfer)?;
            }
            TransferPhase::RecordSourceReceipt => {
                let receipt = transfer
                    .receipt
                    .clone()
                    .context("backup copy: durable destination receipt is missing")?;
                expect_offhost_recorded(source.execute_host_operation(
                    &crate::target::HostOperation::backup_offhost_record(
                        &transfer.source_receipt_operation_id,
                        &transfer.deployment_id,
                        receipt,
                    ),
                )?)?;
                transfer.phase = TransferPhase::CleanupSource;
                journal.store(transfer)?;
            }
            TransferPhase::CleanupSource => {
                execute_transfer_cleanup(
                    source,
                    &transfer.source_cleanup_operation_id,
                    &transfer.deployment_id,
                    &transfer.transfer_operation_id,
                    "source",
                )?;
                transfer.phase = TransferPhase::CleanupDestination;
                journal.store(transfer)?;
            }
            TransferPhase::CleanupDestination => {
                execute_transfer_cleanup(
                    destination,
                    &transfer.destination_cleanup_operation_id,
                    &transfer.deployment_id,
                    &transfer.transfer_operation_id,
                    "destination",
                )?;
                let receipt = transfer
                    .receipt
                    .clone()
                    .context("backup copy: durable destination receipt is missing")?;
                journal.clear()?;
                return Ok(receipt);
            }
        }
    }
}

fn validate_source_plan(
    transfer: &TransferRecord,
    plan: &crate::target::backup_exec::BackupTransferPlan,
) -> anyhow::Result<()> {
    if plan.operation_id != transfer.transfer_operation_id
        || plan.deployment_id != transfer.deployment_id
        || plan.manifest_sha256.len() != 64
        || !plan
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || plan.files.is_empty()
    {
        bail!(
            "backup copy: source returned a transfer plan with mismatched immutable bindings; the durable transfer was retained for exact retry"
        );
    }
    Ok(())
}

fn validate_receipt(
    transfer: &TransferRecord,
    receipt: &crate::target::backup::OffHostCopyReceipt,
) -> anyhow::Result<()> {
    let plan = transfer
        .source_plan
        .as_ref()
        .context("backup copy: durable source plan is missing")?;
    if receipt.schema != crate::target::backup::OFF_HOST_COPY_RECEIPT_SCHEMA
        || receipt.deployment_id != transfer.deployment_id
        || receipt.source_host_id != transfer.source_host_id
        || receipt.destination_host_id != transfer.destination_host_id
        || receipt.manifest_sha256 != plan.manifest_sha256
    {
        bail!(
            "backup copy: destination receipt is not bound to this durable transfer; the transfer record was retained for exact retry"
        );
    }
    crate::registry::validate_identifier(&receipt.snapshot_id, 128, "backup snapshot id")
}

fn expect_transfer_plan(
    result: crate::target::HostResult,
    phase: &str,
) -> anyhow::Result<crate::target::backup_exec::BackupTransferPlan> {
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupTransferPrepared { plan },
        } => Ok(plan),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup copy {phase} failed: {code}: {detail}")
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup copy {phase} returned an unexpected completion")
        }
    }
}

fn expect_import_receipt(
    result: crate::target::HostResult,
) -> anyhow::Result<crate::target::backup::OffHostCopyReceipt> {
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupImportFinalized { receipt },
        } => Ok(receipt),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup copy import finalization failed: {code}: {detail}")
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup copy import finalization returned an unexpected completion")
        }
    }
}

fn expect_offhost_recorded(result: crate::target::HostResult) -> anyhow::Result<()> {
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupOffHostRecorded {},
        } => Ok(()),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup copy source receipt recording failed: {code}: {detail}")
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup copy source receipt recording returned an unexpected completion")
        }
    }
}

fn execute_transfer_cleanup(
    target: &dyn crate::target::ExecutionTarget,
    cleanup_operation_id: &str,
    deployment_id: &str,
    transfer_operation_id: &str,
    side: &str,
) -> anyhow::Result<()> {
    match target
        .execute_host_operation(&crate::target::HostOperation::backup_transfer_cleanup(
            cleanup_operation_id,
            deployment_id,
            transfer_operation_id.to_owned(),
        ))?
        .outcome
    {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupTransferCleaned {},
        } => Ok(()),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!(
                "backup copy {side} cleanup failed: {code}: {detail}; the durable transfer record was retained, so rerun the same backup copy command to retry this exact cleanup"
            )
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!(
                "backup copy {side} cleanup returned an unexpected completion; the durable transfer record was retained for exact retry"
            )
        }
    }
}

fn copy_one_backup_chunk(
    journal: &TransferJournal,
    transfer: &mut TransferRecord,
    source: &dyn crate::target::ExecutionTarget,
    destination: &dyn crate::target::ExecutionTarget,
) -> anyhow::Result<()> {
    let plan = transfer
        .source_plan
        .as_ref()
        .context("backup copy: durable source plan is missing")?;
    let cursor = transfer
        .cursor
        .as_ref()
        .context("backup copy: durable copy cursor is missing")?;
    let file = plan
        .files
        .get(cursor.file_index)
        .context("backup copy: durable copy cursor references an absent file")?;
    let chunk = expect_transfer_chunk(source.execute_host_operation(
        &crate::target::HostOperation::backup_transfer_read(
            &cursor.read_operation_id,
            &transfer.deployment_id,
            &transfer.transfer_operation_id,
            &file.path,
            cursor.offset,
        ),
    )?)?;
    if chunk.transfer_operation_id != transfer.transfer_operation_id
        || chunk.file_name != file.path
        || chunk.offset != cursor.offset
        || chunk.total_bytes != file.size
        || chunk.file_sha256 != file.sha256
        || chunk.bytes.as_bytes().is_empty()
    {
        bail!(
            "backup copy: source returned a chunk with mismatched immutable bindings; the durable cursor was retained for exact retry"
        );
    }
    let consumed = chunk.bytes.as_bytes().len() as u64;
    expect_transfer_written(destination.execute_host_operation(
        &crate::target::HostOperation::backup_transfer_write(
            &cursor.write_operation_id,
            &transfer.deployment_id,
            &transfer.transfer_operation_id,
            chunk,
        ),
    )?)?;
    let next_offset = cursor
        .offset
        .checked_add(consumed)
        .context("backup copy: chunk offset overflow")?;
    if next_offset < file.size {
        transfer.reset_cursor(cursor.file_index, next_offset);
    } else if cursor.file_index + 1 < plan.files.len() {
        transfer.reset_cursor(cursor.file_index + 1, 0);
    } else {
        transfer.cursor = None;
        transfer.phase = TransferPhase::Finalize;
    }
    journal.store(transfer)?;
    Ok(())
}

fn expect_transfer_chunk(
    result: crate::target::HostResult,
) -> anyhow::Result<crate::target::wire::BackupTransferChunk> {
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupTransferChunk { chunk },
        } => Ok(chunk),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup copy source chunk read failed: {code}: {detail}")
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup copy source chunk read returned an unexpected completion")
        }
    }
}

fn expect_transfer_written(result: crate::target::HostResult) -> anyhow::Result<()> {
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::BackupTransferWritten {},
        } => Ok(()),
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("backup copy destination chunk write failed: {code}: {detail}")
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("backup copy destination chunk write returned an unexpected completion")
        }
    }
}

fn run_policy(args: PolicyArgs, global: Option<&str>) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "policy")?;
    let store = RegistryStore::open_default()?;
    let record = crate::fleet::resolve_instance(&store, merged.as_deref(), "policy")?;
    let updated = store.set_backup_before_update(&record.deployment_id, args.mode)?;
    println!(
        "backup-before-update policy updated for '{}' to {:?}",
        updated.alias, updated.backup_before_update
    );
    Ok(())
}

fn run_recover(args: RecoverArgs, global: Option<&str>) -> anyhow::Result<()> {
    use nazo_operator_protocol::{ControlOutcome, ControlResultData};

    let merged = merge(&args.selector, global, "recover")?;
    let context = LifecycleContext::production()?;
    let (record, host, target, inspection) =
        crate::instance_lifecycle::resolve_live_instance(&context, merged.as_deref(), "recover")?;
    let snapshot = inspection
        .backup
        .snapshot
        .as_ref()
        .context("recover requires an existing immutable snapshot")?;
    validate_recovery_snapshot(snapshot)?;
    let keys = ControllerKeyStore::open_default()?;
    let journal = RecoveryJournal::open(&keys.instance_dir(&record.deployment_id)?)?;
    let mut plan = match journal.load()? {
        Some(plan) => {
            if plan.deployment_id != record.deployment_id {
                bail!("recovery journal belongs to a different deployment")
            }
            plan
        }
        None => {
            let plan = recovery_journal::new_plan(
                record.deployment_id.clone(),
                inspection.revision,
                snapshot.manifest_sha256.clone(),
            );
            journal.store(&plan)?;
            plan
        }
    };
    if let Some(requested) = args.version.as_ref()
        && plan.target_version.as_ref() != Some(requested)
    {
        if let Some(candidate) = plan.candidate.clone() {
            let operation_id = plan
                .cleanup_operation_id
                .get_or_insert_with(|| uuid::Uuid::now_v7().to_string())
                .clone();
            journal.store(&plan)?;
            let endpoint = crate::runtime_backend::RecoveryCandidateEndpoint {
                object_reference: candidate.object_reference,
                object_id: candidate.object_id,
                deployment_id: record.deployment_id.clone(),
                operation_id: plan.recover_operation_id.clone(),
                loopback_port: candidate.loopback_port,
            };
            let result = target.execute_host_operation(
                &crate::target::HostOperation::backup_recovery_candidate_cleanup(
                    operation_id,
                    record.deployment_id.clone(),
                    endpoint,
                ),
            )?;
            match result.outcome {
                crate::target::HostOutcome::Completed {
                    body: crate::target::HostCompletionBody::BackupRecoveryCandidateCleaned {},
                } => {}
                crate::target::HostOutcome::Failed { code, detail } => {
                    bail!("recover candidate cleanup failed: {code}: {detail}")
                }
                crate::target::HostOutcome::Completed { .. } => {
                    bail!("recover: target returned an unexpected candidate cleanup")
                }
            }
        }
        plan.phase = RecoveryPhase::Restoring;
        plan.target_version = Some(requested.clone());
        plan.candidate_stage_operation_id = None;
        plan.candidate = None;
        plan.invalidation_operation_id = None;
        plan.invalidation_request_hash = None;
        plan.candidate_control_operation_id = None;
        plan.not_before = None;
        plan.activate_operation_id = None;
        plan.cleanup_operation_id = None;
        journal.store(&plan)?;
    }

    if matches!(plan.phase, RecoveryPhase::Restoring) && plan.restored_revision.is_none() {
        let result =
            target.execute_host_operation(&crate::target::HostOperation::backup_recover(
                plan.recover_operation_id.clone(),
                record.deployment_id.clone(),
                plan.source_revision,
                plan.manifest_sha256.clone(),
            ))?;
        let (manifest_sha256, revision) = match result.outcome {
            crate::target::HostOutcome::Completed {
                body:
                    crate::target::HostCompletionBody::BackupRecovered {
                        manifest_sha256,
                        revision,
                        ..
                    },
            } => (manifest_sha256, revision),
            crate::target::HostOutcome::Failed { code, detail } => {
                bail!("recover target failed: {code}: {detail}")
            }
            crate::target::HostOutcome::Completed { .. } => {
                bail!("recover: target returned an unexpected completion")
            }
        };
        if manifest_sha256 != plan.manifest_sha256 || revision != plan.source_revision + 1 {
            bail!(
                "recover: target recovery completion does not bind the expected revision and manifest"
            )
        }
        plan.restored_revision = Some(revision);
        journal.store(&plan)?;
    }

    if plan.candidate.is_none() {
        let revision = plan
            .restored_revision
            .context("recovery journal has no restored revision")?;
        let operation_id = plan
            .candidate_stage_operation_id
            .get_or_insert_with(|| uuid::Uuid::now_v7().to_string())
            .clone();
        journal.store(&plan)?;
        let result = target.execute_host_operation(
            &crate::target::HostOperation::backup_recovery_candidate_stage(
                operation_id,
                record.deployment_id.clone(),
                revision,
                plan.recover_operation_id.clone(),
                plan.state_epoch.clone(),
                crate::target::OfficialArtifactRef {
                    repository: crate::clean_install::SERVER_REPOSITORY.to_owned(),
                    version: plan.target_version.clone(),
                },
            ),
        )?;
        let endpoint = match result.outcome {
            crate::target::HostOutcome::Completed {
                body: crate::target::HostCompletionBody::BackupRecoveryCandidateStaged { endpoint },
            } => endpoint,
            crate::target::HostOutcome::Failed { code, detail } => {
                bail!("recover candidate stage failed: {code}: {detail}")
            }
            crate::target::HostOutcome::Completed { .. } => {
                bail!("recover: target returned an unexpected candidate completion")
            }
        };
        if endpoint.deployment_id != record.deployment_id
            || endpoint.operation_id != plan.recover_operation_id
        {
            bail!("recover: target candidate identity is not bound to this recovery")
        }
        plan.candidate = Some(CandidatePointer {
            object_reference: endpoint.object_reference,
            object_id: endpoint.object_id,
            loopback_port: endpoint.loopback_port,
        });
        plan.phase = RecoveryPhase::Invalidating;
        journal.store(&plan)?;
    }

    // The recovery journal lock spans the whole command.  Ceremony success
    // therefore continues this bounded phase loop instead of recursively
    // re-entering `run_recover` and attempting to take the same lock again.
    while matches!(plan.phase, RecoveryPhase::Invalidating) {
        let restored = target.inspect_instance(&record.deployment_id)?;
        let revision = plan
            .restored_revision
            .context("recovery journal has no restored revision")?;
        if restored.revision != revision
            || restored.active_host_operation.as_deref() != Some(&plan.recover_operation_id)
        {
            bail!("recover: target state no longer proves the recorded recovery")
        }
        let config_revision = restored
            .config_revision_marker
            .clone()
            .context("recover: restored target has no config-revision marker")?;
        let control_journal = crate::controller_identity::journal::OperationJournal::open(
            keys.instance_dir(&record.deployment_id)?,
        )?;
        if control_journal.load()?.is_none()
            && (plan.invalidation_operation_id.is_some()
                || plan.invalidation_request_hash.is_some())
        {
            plan.invalidation_operation_id = None;
            plan.invalidation_request_hash = None;
            plan.candidate_control_operation_id = None;
            journal.store(&plan)?;
        }
        let prepared = crate::controller_identity::prepare_control_operation(
            &context.registry,
            &keys,
            &control_journal,
            &record.deployment_id,
            crate::controller_identity::ControlOperationInput {
                operation: nazo_operator_protocol::ControlOperationPayload::RecoveryInvalidate {
                    state_epoch: plan.state_epoch.clone(),
                },
                config_revision,
            },
        )?;
        match (
            &plan.invalidation_operation_id,
            &plan.invalidation_request_hash,
        ) {
            (None, None) => {
                plan.invalidation_operation_id = Some(prepared.signed.operation_id.clone());
                plan.invalidation_request_hash = Some(prepared.signed.request_hash.clone());
                journal.store(&plan)?;
            }
            (Some(operation_id), Some(request_hash))
                if operation_id == &prepared.signed.operation_id
                    && request_hash == &prepared.signed.request_hash => {}
            _ => bail!(
                "recover: control-operation journal does not match the recorded recovery invalidation"
            ),
        }
        let candidate = plan
            .candidate
            .clone()
            .context("recover: recovery journal has no candidate pointer")?;
        let wrapper_operation_id = plan
            .candidate_control_operation_id
            .get_or_insert_with(|| uuid::Uuid::now_v7().to_string())
            .clone();
        journal.store(&plan)?;
        let host_result = target.execute_host_operation(
            &crate::target::HostOperation::backup_recovery_candidate_control(
                wrapper_operation_id,
                record.deployment_id.clone(),
                revision,
                crate::runtime_backend::RecoveryCandidateEndpoint {
                    object_reference: candidate.object_reference.clone(),
                    object_id: candidate.object_id.clone(),
                    deployment_id: record.deployment_id.clone(),
                    operation_id: plan.recover_operation_id.clone(),
                    loopback_port: candidate.loopback_port,
                },
                plan.state_epoch.clone(),
                prepared.signed.operation_id.clone(),
                prepared.signed.compact_jws.clone(),
            ),
        )?;
        let receipt = crate::target::control_operation_receipt(
            prepared.signed.operation_id.clone(),
            host_result.outcome,
        )?;
        let verdict = crate::controller_identity::classify_control_receipt(&prepared, receipt)?;
        match &verdict {
            crate::controller_identity::DispatchVerdict::DefinitivelyRejected { code }
                if requires_controller_identity_recovery(code) =>
            {
                crate::controller_identity::settle_journal(
                    &control_journal,
                    &prepared,
                    &verdict,
                    |_| Ok(()),
                )?;
                let Some(secret_path) = args.recovery_secret_file.as_deref() else {
                    bail!(
                        "recover: restored registry rejected the current controller identity ({code}); rerun with --recovery-secret-file after providing the offline Recovery Secret"
                    )
                };
                // The rejected JWS was never accepted and is already settled
                // in the authoritative OperationJournal.  Clear only this
                // cross-stage pointer *before* the recovery commit so a crash
                // after the new key lands necessarily prepares a fresh JWS.
                plan.invalidation_operation_id = None;
                plan.invalidation_request_hash = None;
                plan.candidate_control_operation_id = None;
                journal.store(&plan)?;

                let candidate = plan
                    .candidate
                    .as_ref()
                    .context("recover: recovery journal has no candidate pointer")?;
                let secret = read_recovery_secret_file(secret_path)?;
                let (local_port, forward) = match select_recovery_ceremony_route(
                    host.transport,
                    host.ssh_profile.as_deref(),
                    candidate.loopback_port,
                )? {
                    RecoveryCeremonyRoute::DirectLoopback { local_port } => (local_port, None),
                    RecoveryCeremonyRoute::SshForward {
                        profile,
                        remote_port,
                    } => {
                        let forward =
                            crate::target::ssh::RecoverySshForward::start(profile, remote_port)?;
                        (forward.local_port(), Some(forward))
                    }
                };
                let api = crate::controller_identity::admin_api::HttpControllerRegistryApi::with_transport(
                    &record.issuer,
                    crate::controller_identity::admin_api::AdminAccess::default(),
                    Box::new(RecoveryCeremonyTransport::new(
                        &record.issuer,
                        local_port,
                    )?),
                )?;
                let delivery = crate::controller_identity::recovery::InteractiveSecretDelivery;
                crate::controller_identity::recovery::recover_controller_identity(
                    &context.registry,
                    &keys,
                    &api,
                    Some(&record.deployment_id),
                    &secret,
                    "recovered-controller",
                    &delivery,
                )?;
                drop(forward);
                // `recover_controller_identity` owns its own crash journal for
                // the ceremony.  Re-enter only this phase so the same
                // RecoveryJournal lock, restored target, and candidate remain
                // authoritative; a new key necessarily prepares a new JWS.
                continue;
            }
            crate::controller_identity::DispatchVerdict::DefinitivelyRejected { code } => {
                plan.invalidation_operation_id = None;
                plan.invalidation_request_hash = None;
                plan.candidate_control_operation_id = None;
                journal.store(&plan)?;
                crate::controller_identity::settle_journal(
                    &control_journal,
                    &prepared,
                    &verdict,
                    |_| Ok(()),
                )?;
                bail!("recover: server rejected invalidation before acceptance: {code}")
            }
            crate::controller_identity::DispatchVerdict::OutcomeUnknown
            | crate::controller_identity::DispatchVerdict::InProgressAccepted => {
                crate::controller_identity::settle_journal(
                    &control_journal,
                    &prepared,
                    &verdict,
                    |_| Ok(()),
                )?;
                bail!(
                    "recover: invalidation has no terminal result; rerun to resume the exact operation"
                )
            }
            crate::controller_identity::DispatchVerdict::Terminal(result) => {
                if result.outcome != ControlOutcome::Succeeded {
                    plan.invalidation_operation_id = None;
                    plan.invalidation_request_hash = None;
                    plan.candidate_control_operation_id = None;
                    journal.store(&plan)?;
                    crate::controller_identity::settle_journal(
                        &control_journal,
                        &prepared,
                        &verdict,
                        |_| Ok(()),
                    )?;
                    bail!(
                        "{}: recover: server completed invalidation unsuccessfully",
                        crate::error_codes::CONTROL_OPERATION_FAILED
                    )
                }
                let Some(ControlResultData::RecoveryInvalidation {
                    state_epoch,
                    not_before,
                    ..
                }) = result.result.as_ref()
                else {
                    bail!("recover: terminal invalidation result lacks its typed recovery facts")
                };
                if state_epoch != &plan.state_epoch {
                    bail!(
                        "recover: invalidation result state epoch does not match the staged candidate"
                    )
                }
                plan.not_before = Some(*not_before);
                plan.phase = RecoveryPhase::WaitingForDeadline;
                journal.store(&plan)?;
                crate::controller_identity::settle_journal(
                    &control_journal,
                    &prepared,
                    &verdict,
                    |_| Ok(()),
                )?;
            }
        }
    }

    if matches!(plan.phase, RecoveryPhase::WaitingForDeadline) {
        let not_before = plan
            .not_before
            .context("recovery journal has no invalidation deadline")?;
        while chrono::Utc::now().timestamp() <= not_before {
            let remaining = not_before
                .saturating_sub(chrono::Utc::now().timestamp())
                .saturating_add(1);
            eprintln!(
                "recover: invalidation is durable; waiting {remaining}s before activating the recovered runtime"
            );
            std::thread::sleep(std::time::Duration::from_secs(remaining.min(60) as u64));
        }
        let revision = plan
            .restored_revision
            .context("recovery journal has no restored revision")?;
        let operation_id = plan
            .activate_operation_id
            .get_or_insert_with(|| uuid::Uuid::now_v7().to_string())
            .clone();
        journal.store(&plan)?;
        let result = target.execute_host_operation(
            &crate::target::HostOperation::backup_recovery_activate(
                operation_id,
                record.deployment_id.clone(),
                revision,
                plan.recover_operation_id.clone(),
                plan.state_epoch.clone(),
                not_before,
            ),
        )?;
        if !matches!(
            result.outcome,
            crate::target::HostOutcome::Completed {
                body: crate::target::HostCompletionBody::BackupRecoveryActivated {}
            }
        ) {
            bail!("recover: target did not confirm activation after the deadline")
        }
        plan.phase = RecoveryPhase::CleanupPending;
        journal.store(&plan)?;
    }

    if matches!(plan.phase, RecoveryPhase::CleanupPending) {
        let candidate = plan
            .candidate
            .as_ref()
            .context("recovery journal has no candidate pointer")?;
        let operation_id = plan
            .cleanup_operation_id
            .get_or_insert_with(|| uuid::Uuid::now_v7().to_string())
            .clone();
        journal.store(&plan)?;
        let endpoint = crate::runtime_backend::RecoveryCandidateEndpoint {
            object_reference: candidate.object_reference.clone(),
            object_id: candidate.object_id.clone(),
            deployment_id: record.deployment_id.clone(),
            operation_id: plan.recover_operation_id.clone(),
            loopback_port: candidate.loopback_port,
        };
        let result = target.execute_host_operation(
            &crate::target::HostOperation::backup_recovery_candidate_cleanup(
                operation_id,
                record.deployment_id.clone(),
                endpoint,
            ),
        )?;
        if !matches!(
            result.outcome,
            crate::target::HostOutcome::Completed {
                body: crate::target::HostCompletionBody::BackupRecoveryCandidateCleaned {}
            }
        ) {
            bail!("recover: target did not confirm exact candidate cleanup")
        }
        journal.clear()?;
        println!("recovery completed for '{}'", record.alias);
    }
    Ok(())
}

fn validate_recovery_snapshot(
    snapshot: &crate::target::backup::SnapshotProjection,
) -> anyhow::Result<()> {
    if snapshot.restore_tested_at.is_none() {
        bail!("recover requires a restore-tested snapshot")
    }
    Ok(())
}

fn requires_controller_identity_recovery(code: &str) -> bool {
    code == crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED
}

#[derive(Debug, Eq, PartialEq)]
enum RecoveryCeremonyRoute<'a> {
    DirectLoopback { local_port: u16 },
    SshForward { profile: &'a str, remote_port: u16 },
}

fn select_recovery_ceremony_route(
    transport: HostTransport,
    ssh_profile: Option<&str>,
    candidate_loopback_port: u16,
) -> anyhow::Result<RecoveryCeremonyRoute<'_>> {
    match transport {
        HostTransport::Local => Ok(RecoveryCeremonyRoute::DirectLoopback {
            local_port: candidate_loopback_port,
        }),
        HostTransport::Ssh => Ok(RecoveryCeremonyRoute::SshForward {
            profile: ssh_profile.context("recover: SSH host has no OpenSSH profile")?,
            remote_port: candidate_loopback_port,
        }),
    }
}

fn read_password_file(
    path: &std::path::Path,
    flag: &str,
) -> anyhow::Result<crate::target::SecretMaterial> {
    read_password_file_inner(path, flag)
        .map_err(|error| anyhow::anyhow!("{}: {error:#}", crate::error_codes::INPUT_INVALID))
}

fn read_password_file_inner(
    path: &std::path::Path,
    flag: &str,
) -> anyhow::Result<crate::target::SecretMaterial> {
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    let raw =
        crate::filesystem::read_secure_regular_file(path, flag, true, MAX_PASSWORD_FILE_BYTES)
            .with_context(|| format!("{flag}: failed to read {}", path.display()))?;
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    if end == 0 {
        bail!("{flag}: {} is empty", path.display());
    }
    crate::target::SecretMaterial::try_new(raw[..end].to_vec())
        .map_err(|error| anyhow::anyhow!(error.detail))
}

/// Top-level `recover` deliberately accepts the offline Recovery Secret only
/// from a private file, and only after the registry has proved the current key
/// is unusable.  It never enters argv, a target operation, or either journal.
fn read_recovery_secret_file(path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
    const MAX_SECRET_FILE_BYTES: u64 = 4096;
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "recovery secret",
        true,
        MAX_SECRET_FILE_BYTES,
    )
    .with_context(|| format!("--recovery-secret-file: failed to read {}", path.display()))?;
    let value = String::from_utf8(bytes.to_vec()).with_context(|| {
        format!(
            "--recovery-secret-file: {} is not valid UTF-8",
            path.display()
        )
    })?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        bail!("--recovery-secret-file: {} is empty", path.display());
    }
    Ok(zeroize::Zeroizing::new(value.to_owned()))
}

fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    let context = CleanInstallContext::production()?;
    let database_runtime_password = read_password_file(
        &args.database_runtime_password_file,
        "--database-runtime-password-file",
    )?;
    let database_lifecycle_password = read_password_file(
        &args.database_lifecycle_password_file,
        "--database-lifecycle-password-file",
    )?;
    let valkey_password = read_password_file(&args.valkey_password_file, "--valkey-password-file")?;
    let request = CleanInstallRequest {
        host: args.host,
        instance_alias: args.name,
        issuer: args.public_url,
        version: args.version,
        runtime: args.runtime,
        install_root: args.install_root,
        database_runtime_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: args.database_host.clone(),
            port: args.database_port,
            name: args.database_name.clone(),
            user: args.database_runtime_user,
        },
        database_lifecycle_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: args.database_host,
            port: args.database_port,
            name: args.database_name,
            user: args.database_lifecycle_user,
        },
        valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: args.valkey_host,
            port: args.valkey_port,
            name: String::new(),
            user: String::new(),
        },
        database_runtime_password: Some(database_runtime_password),
        database_lifecycle_password: Some(database_lifecycle_password),
        valkey_password: Some(valkey_password),
        import_data_root: args.import_data_root,
        import_mfa_key_file: args.import_mfa_key_file,
    };
    let report = crate::clean_install::run_clean_install(&context, request)?;
    println!("{report}");
    Ok(())
}

fn run_verify(merged: Option<String>) -> anyhow::Result<()> {
    let store = RegistryStore::open_default()?;
    let record = crate::fleet::resolve_instance(&store, merged.as_deref(), "verify")?;
    let prober = CurlPublicProber;
    let report = verify_public(&prober, &record.issuer);
    println!("{}", report.render());
    Ok(())
}

fn run_admin(command: AdminCommand, global: Option<&str>) -> anyhow::Result<()> {
    match command {
        AdminCommand::Create(args) => run_admin_create(args, global),
    }
}

/// Create one administrator through the target's deployment-root HostOperation.
/// The target resolves runtime/config paths from its live DeploymentState and
/// invokes only the fixed `nazoauth admin-provision` entry point.
fn run_admin_create(args: AdminCreateArgs, global: Option<&str>) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "admin create")?;
    let context = LifecycleContext::production()?;
    let (record, _host, target, inspection) = crate::instance_lifecycle::resolve_live_instance(
        &context,
        merged.as_deref(),
        "admin create",
    )?;
    let credentials = read_admin_credentials(
        if args.credentials_stdin {
            AdminCredentialsInput::Stdin
        } else {
            AdminCredentialsInput::Interactive
        },
        "admin create",
    )?;
    let password = admin_provision_password_material(&credentials)?;
    let operation_id = admin_operation_id();
    let operation = crate::target::HostOperation::admin_create(
        operation_id,
        inspection.deployment_id.clone(),
        credentials.email.clone(),
        password,
    );
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::AdminCreated { receipt },
        } => {
            println!(
                "administrator '{}' created for instance '{}' (user id: {})",
                receipt.email, record.alias, receipt.user_id
            );
            Ok(())
        }
        crate::target::HostOutcome::Completed { .. } => {
            bail!("admin create: target returned an unexpected completion")
        }
        crate::target::HostOutcome::Failed { code, detail } => {
            bail!("admin create failed: {code}: {detail}")
        }
    }
}

/// One user invocation owns one operation identity. Transport retries reuse
/// the constructed operation, while a later invocation must be able to retry
/// after a corrected target failure. Database uniqueness and the provisioning
/// receipt remain the authoritative administrator idempotency boundary.
fn admin_operation_id() -> uuid::Uuid {
    uuid::Uuid::now_v7()
}

fn run_update(args: UpdateArgs, global: Option<&str>) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "update")?;
    let config_content = match &args.config_file {
        Some(path) => Some(read_config_file(path)?),
        None => None,
    };
    let request = UpdateRequest {
        instance: merged,
        version: args.version,
        config_content,
        config_schema: args.config_schema,
    };
    let context = LifecycleContext::production()?;
    let keys = ControllerKeyStore::open_default()?;
    let report = crate::instance_lifecycle::run_update(&context, &keys, &request)?;
    println!("{report}");
    Ok(())
}

fn read_config_file(path: &std::path::Path) -> anyhow::Result<String> {
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "staged configuration",
        false,
        MAX_CONFIG_BYTES,
    )
    .with_context(|| format!("failed to read {}", path.display()))?;
    String::from_utf8(bytes.to_vec())
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod admin_create_tests {
    use super::admin_operation_id;

    #[test]
    fn each_user_invocation_gets_a_fresh_operation_id() {
        let first = admin_operation_id();
        let second = admin_operation_id();
        assert_eq!(first.get_version_num(), 7);
        assert_eq!(second.get_version_num(), 7);
        assert_ne!(first, second);
    }
}

#[cfg(test)]
mod install_input_tests {
    use super::read_password_file;

    #[test]
    fn local_password_file_failures_are_typed_as_invalid_input() {
        let error = read_password_file(
            std::path::Path::new("relative-password-file"),
            "--database-runtime-password-file",
        )
        .expect_err("relative input path must be rejected");
        assert!(
            format!("{error:#}").starts_with(crate::error_codes::INPUT_INVALID),
            "{error:#}"
        );
    }
}

#[cfg(test)]
mod recover_tests {
    use super::{
        RecoveryCeremonyRoute, requires_controller_identity_recovery,
        select_recovery_ceremony_route, validate_recovery_snapshot,
    };
    use crate::registry::HostTransport;
    use crate::target::backup::SnapshotProjection;
    use chrono::Utc;

    fn snapshot(restore_tested: bool, off_host_verified: bool) -> SnapshotProjection {
        SnapshotProjection {
            snapshot_id: uuid::Uuid::now_v7().to_string(),
            created_at: Utc::now(),
            manifest_sha256: "a".repeat(64),
            restore_tested_at: restore_tested.then(Utc::now),
            off_host_verified_at: off_host_verified.then(Utc::now),
        }
    }

    #[test]
    fn restore_tested_local_snapshot_is_recoverable_without_an_off_host_copy() {
        validate_recovery_snapshot(&snapshot(true, false))
            .expect("off-host redundancy must not block a usable local recovery");
    }

    #[test]
    fn untested_snapshot_cannot_be_recovered_even_with_an_off_host_copy() {
        let error = validate_recovery_snapshot(&snapshot(false, true))
            .expect_err("an untested snapshot must not be restored");
        assert_eq!(
            error.to_string(),
            "recover requires a restore-tested snapshot"
        );
    }

    #[test]
    fn only_stable_identity_rejections_may_read_a_recovery_secret() {
        assert!(requires_controller_identity_recovery(
            crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED
        ));
        for code in [
            "CONTROL_OUTCOME_UNKNOWN",
            "INTERNAL_ERROR",
            "HTTP_503",
            "CONTROLLER_KEY_REVOKED",
            "unexpected-proxy-text",
        ] {
            assert!(
                !requires_controller_identity_recovery(code),
                "{code} must not enter Recovery Secret ceremony"
            );
        }
    }

    #[test]
    fn local_recovery_uses_the_candidate_loopback_port_directly() -> anyhow::Result<()> {
        assert_eq!(
            select_recovery_ceremony_route(HostTransport::Local, None, 42123)?,
            RecoveryCeremonyRoute::DirectLoopback { local_port: 42123 }
        );
        Ok(())
    }

    #[test]
    fn ssh_recovery_forwards_the_candidate_loopback_port() -> anyhow::Result<()> {
        assert_eq!(
            select_recovery_ceremony_route(HostTransport::Ssh, Some("hostinger"), 42123)?,
            RecoveryCeremonyRoute::SshForward {
                profile: "hostinger",
                remote_port: 42123,
            }
        );
        Ok(())
    }

    #[test]
    fn ssh_recovery_without_a_profile_fails_closed() {
        let error = select_recovery_ceremony_route(HostTransport::Ssh, None, 42123)
            .expect_err("an SSH target without a profile must not enter the ceremony");
        assert!(
            error
                .to_string()
                .contains("SSH host has no OpenSSH profile")
        );
    }
}

#[cfg(test)]
mod backup_transfer_tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use anyhow::anyhow;
    use chrono::Utc;

    use super::*;
    use crate::target::{
        HostCompletionBody, HostOperation, HostOperationBody, HostResult,
        backup::{OFF_HOST_COPY_RECEIPT_SCHEMA, OffHostCopyReceipt, SnapshotFile},
        backup_exec::BackupTransferPlan,
        wire::{BackupTransferBytes, BackupTransferChunk},
    };

    const DEPLOYMENT: &str = "deployment-a";
    const SOURCE: &str = "source-host";
    const DESTINATION: &str = "destination-host";
    const MANIFEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FILE_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[derive(Clone, Copy)]
    enum Role {
        Source,
        Destination,
    }

    #[derive(Default)]
    struct FakeState {
        cached: HashMap<String, HostResult>,
        calls: Vec<(String, String)>,
        fail_kind_once: Option<&'static str>,
        failed: bool,
    }

    struct FakeTarget {
        role: Role,
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeTarget {
        fn new(role: Role, fail_kind_once: Option<&'static str>) -> Self {
            Self {
                role,
                state: Arc::new(Mutex::new(FakeState {
                    fail_kind_once,
                    ..FakeState::default()
                })),
            }
        }

        fn replayed_fixed_id(&self, kind: &str) -> bool {
            let state = self.state.lock().expect("fake target lock");
            state.calls.iter().any(|(_, id)| {
                state
                    .calls
                    .iter()
                    .filter(|(candidate_kind, candidate_id)| {
                        candidate_kind == kind && candidate_id == id
                    })
                    .count()
                    >= 2
            })
        }

        fn response(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
            let body = match (&self.role, &operation.operation) {
                (Role::Source, HostOperationBody::BackupExportPrepare {}) => {
                    HostCompletionBody::BackupTransferPrepared {
                        plan: BackupTransferPlan {
                            operation_id: operation.operation_id.clone(),
                            deployment_id: DEPLOYMENT.to_owned(),
                            manifest_sha256: MANIFEST.to_owned(),
                            files: vec![SnapshotFile {
                                path: "deployment.tar".to_owned(),
                                size: 3,
                                sha256: FILE_SHA256.to_owned(),
                            }],
                        },
                    }
                }
                (Role::Destination, HostOperationBody::BackupImportPrepare {}) => {
                    HostCompletionBody::BackupTransferPrepared {
                        plan: BackupTransferPlan {
                            operation_id: operation.operation_id.clone(),
                            deployment_id: DEPLOYMENT.to_owned(),
                            manifest_sha256: String::new(),
                            files: Vec::new(),
                        },
                    }
                }
                (
                    Role::Source,
                    HostOperationBody::BackupTransferRead {
                        transfer_operation_id,
                        file_name,
                        offset,
                        ..
                    },
                ) => HostCompletionBody::BackupTransferChunk {
                    chunk: BackupTransferChunk {
                        transfer_operation_id: transfer_operation_id.clone(),
                        file_name: file_name.clone(),
                        offset: *offset,
                        total_bytes: 3,
                        file_sha256: FILE_SHA256.to_owned(),
                        bytes: BackupTransferBytes::try_new(b"abc".to_vec())?,
                    },
                },
                (Role::Destination, HostOperationBody::BackupTransferWrite { .. }) => {
                    HostCompletionBody::BackupTransferWritten {}
                }
                (
                    Role::Destination,
                    HostOperationBody::BackupImportFinalize {
                        source_host_id,
                        destination_host_id,
                        ..
                    },
                ) => HostCompletionBody::BackupImportFinalized {
                    receipt: OffHostCopyReceipt {
                        schema: OFF_HOST_COPY_RECEIPT_SCHEMA,
                        deployment_id: DEPLOYMENT.to_owned(),
                        snapshot_id: uuid::Uuid::now_v7().to_string(),
                        manifest_sha256: MANIFEST.to_owned(),
                        source_host_id: source_host_id.clone(),
                        destination_host_id: destination_host_id.clone(),
                        verified_at: Utc::now(),
                    },
                },
                (Role::Source, HostOperationBody::BackupOffHostRecord { .. }) => {
                    HostCompletionBody::BackupOffHostRecorded {}
                }
                (_, HostOperationBody::BackupTransferCleanup { .. }) => {
                    HostCompletionBody::BackupTransferCleaned {}
                }
                _ => {
                    return Err(anyhow!(
                        "unexpected fake operation {}",
                        operation.operation.kind()
                    ));
                }
            };
            Ok(HostResult::completed(&operation.operation_id, body))
        }
    }

    impl crate::target::ExecutionTarget for FakeTarget {
        fn inspect_host(&self) -> anyhow::Result<crate::target::HostOverview> {
            unreachable!("not used by transfer coordinator tests")
        }

        fn inspect_instance(
            &self,
            _deployment_id: &str,
        ) -> anyhow::Result<crate::target::wire::InstanceInspection> {
            unreachable!("not used by transfer coordinator tests")
        }

        fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
            let kind = operation.operation.kind().to_owned();
            let mut state = self.state.lock().expect("fake target lock");
            state
                .calls
                .push((kind.clone(), operation.operation_id.clone()));
            if let Some(cached) = state.cached.get(&operation.operation_id) {
                return Ok(cached.clone());
            }
            drop(state);
            let result = self.response(operation)?;
            let mut state = self.state.lock().expect("fake target lock");
            state
                .cached
                .insert(operation.operation_id.clone(), result.clone());
            if state.fail_kind_once == Some(kind.as_str()) && !state.failed {
                state.failed = true;
                return Err(anyhow!("simulated crash after remote {kind} commit"));
            }
            Ok(result)
        }

        fn execute_control_operation(
            &self,
            _request: crate::target::ControlOperationRequest,
        ) -> anyhow::Result<crate::target::ControlOperationReceipt> {
            unreachable!("not used by transfer coordinator tests")
        }

        fn read_health(
            &self,
            _deployment_id: &str,
        ) -> anyhow::Result<crate::target::HealthSnapshot> {
            unreachable!("not used by transfer coordinator tests")
        }
    }

    fn new_journal() -> anyhow::Result<(crate::filesystem::PrivateTempDir, TransferJournal)> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-transfer-controller")?;
        let journal = TransferJournal::open(temp.path())?;
        Ok((temp, journal))
    }

    fn new_record(journal: &TransferJournal) -> anyhow::Result<TransferRecord> {
        let record = TransferRecord::new(
            DEPLOYMENT.to_owned(),
            SOURCE.to_owned(),
            DESTINATION.to_owned(),
            "archive".to_owned(),
        );
        journal.store(&record)?;
        Ok(record)
    }

    fn assert_single_crash_resumes(
        source_failure: Option<&'static str>,
        destination_failure: Option<&'static str>,
        expected_phase: TransferPhase,
        failed_kind: &'static str,
        failure_on_source: bool,
    ) -> anyhow::Result<()> {
        let (_temp, journal) = new_journal()?;
        let mut record = new_record(&journal)?;
        let source = FakeTarget::new(Role::Source, source_failure);
        let destination = FakeTarget::new(Role::Destination, destination_failure);
        assert!(
            resume_backup_transfer(&journal, &mut record, &source, &destination).is_err(),
            "the injected crash must interrupt the first run"
        );
        let mut resumed = journal.load()?.expect("durable transfer remains");
        assert_eq!(resumed.phase, expected_phase);
        resume_backup_transfer(&journal, &mut resumed, &source, &destination)?;
        assert!(!journal.exists());
        let failed_target = if failure_on_source {
            &source
        } else {
            &destination
        };
        assert!(failed_target.replayed_fixed_id(failed_kind));
        Ok(())
    }

    #[test]
    fn every_remote_phase_resumes_with_the_same_operation_id() -> anyhow::Result<()> {
        for (source, destination, phase, kind, on_source) in [
            (
                Some("backup-export-prepare"),
                None,
                TransferPhase::SourcePrepare,
                "backup-export-prepare",
                true,
            ),
            (
                None,
                Some("backup-import-prepare"),
                TransferPhase::DestinationPrepare,
                "backup-import-prepare",
                false,
            ),
            (
                None,
                Some("backup-transfer-write"),
                TransferPhase::Copying,
                "backup-transfer-write",
                false,
            ),
            (
                None,
                Some("backup-import-finalize"),
                TransferPhase::Finalize,
                "backup-import-finalize",
                false,
            ),
            (
                Some("backup-offhost-record"),
                None,
                TransferPhase::RecordSourceReceipt,
                "backup-offhost-record",
                true,
            ),
            (
                Some("backup-transfer-cleanup"),
                None,
                TransferPhase::CleanupSource,
                "backup-transfer-cleanup",
                true,
            ),
            (
                None,
                Some("backup-transfer-cleanup"),
                TransferPhase::CleanupDestination,
                "backup-transfer-cleanup",
                false,
            ),
        ] {
            assert_single_crash_resumes(source, destination, phase, kind, on_source)?;
        }
        Ok(())
    }

    #[test]
    fn both_cleanup_crashes_remain_separately_retryable() -> anyhow::Result<()> {
        let (_temp, journal) = new_journal()?;
        let mut record = new_record(&journal)?;
        let source = FakeTarget::new(Role::Source, Some("backup-transfer-cleanup"));
        let destination = FakeTarget::new(Role::Destination, Some("backup-transfer-cleanup"));

        assert!(resume_backup_transfer(&journal, &mut record, &source, &destination).is_err());
        let mut after_source = journal.load()?.expect("source cleanup retry");
        assert_eq!(after_source.phase, TransferPhase::CleanupSource);
        assert!(
            resume_backup_transfer(&journal, &mut after_source, &source, &destination).is_err()
        );
        let mut after_destination = journal.load()?.expect("destination cleanup retry");
        assert_eq!(after_destination.phase, TransferPhase::CleanupDestination);
        resume_backup_transfer(&journal, &mut after_destination, &source, &destination)?;
        assert!(!journal.exists());
        assert!(source.replayed_fixed_id("backup-transfer-cleanup"));
        assert!(destination.replayed_fixed_id("backup-transfer-cleanup"));
        Ok(())
    }

    #[test]
    fn unfinished_transfer_rejects_every_binding_drift() {
        let transfer = TransferRecord::new(
            DEPLOYMENT.to_owned(),
            SOURCE.to_owned(),
            DESTINATION.to_owned(),
            "archive".to_owned(),
        );
        for (deployment, source, destination, alias) in [
            ("other-deployment", SOURCE, DESTINATION, "archive"),
            (DEPLOYMENT, "other-source", DESTINATION, "archive"),
            (DEPLOYMENT, SOURCE, "other-destination", "archive"),
            (DEPLOYMENT, SOURCE, DESTINATION, "other-alias"),
        ] {
            let error = validate_transfer_binding(
                &transfer,
                deployment,
                source,
                destination,
                alias,
                "primary",
            )
            .expect_err("fact drift must fail closed");
            let message = error.to_string();
            assert!(message.contains("restore those exact registry facts"));
            assert!(message.contains("backup copy --to-host archive"));
        }
    }
}
