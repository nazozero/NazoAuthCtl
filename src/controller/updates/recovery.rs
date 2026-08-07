use super::*;

pub(crate) fn target_is_active(config: &UpdateConfig, journal: &UpdateJournal) -> bool {
    let runtime = Runtime::new(config);
    if config.runtime.backend != RuntimeBackendKind::Systemd && !runtime.container_exists() {
        return false;
    }
    runtime
        .active_revision()
        .is_ok_and(|revision| revision == journal.to_release.backend_commit)
}

pub(crate) fn recovery_action(
    _journal: &UpdateJournal,
    _target_is_active: bool,
) -> UpdateRecoveryAction {
    // Recovery is deliberately an unwind operation. Continuing forward could
    // require the current broken server artifact to execute operator-task,
    // which would make recovery depend on the failure it is meant to contain.
    UpdateRecoveryAction::RestorePrevious
}

pub(crate) fn uses_legacy_lock(command: &Command) -> bool {
    if DeploymentStore::system().registry_path().exists() {
        return matches!(command, Command::Install(_));
    }
    !matches!(
        command,
        Command::Discover
            | Command::Adopt(_)
            | Command::DeploymentsList
            | Command::TransactionShow
            | Command::TransactionEvidence { .. }
            | Command::TransactionResume { .. }
            | Command::PermissionsSet(_)
            | Command::Relinquish(_)
            | Command::Reconcile
            | Command::SelfCheck(_)
            | Command::SelfUpdate { .. }
            | Command::SelfRollback { .. }
    )
}

pub(crate) fn recover_pending_update(
    config_path: &Path,
    config: &UpdateConfig,
) -> anyhow::Result<()> {
    let Some(journal) = load_update_journal(config)? else {
        return Ok(());
    };
    eprintln!(
        "nazoauthctl: recovering update transaction {} at phase {:?}",
        journal.transaction_id, journal.phase
    );
    let _ = config_path;
    match recovery_action(&journal, target_is_active(config, &journal)) {
        UpdateRecoveryAction::RestorePrevious => restore_previous_transaction(config, &journal)?,
    }
    append_update_management_event(
        config,
        &journal,
        "artifact-restored",
        "update-recovered-to-previous",
        &journal.from_release.version,
        if journal.phase >= UpdatePhase::MigrationRunning {
            "database-backup"
        } else {
            "artifact-only"
        },
    )?;
    finish_update_journal(config, &journal)?;
    eprintln!(
        "nazoauthctl: interrupted update transaction {} restored {}",
        journal.transaction_id, journal.from_release.version
    );
    Ok(())
}

pub(crate) fn restore_previous_transaction(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    ensure_trusted_runtime_available(config, &journal.from_release, &journal.previous_runtime)?;
    if journal.phase >= UpdatePhase::MigrationRunning {
        let backup = journal_backup(config, journal)?;
        rotate_bootstrap_recovery_epoch(config)
            .context("failed to invalidate bootstrap receipts before update recovery")?;
        let runtime = Runtime::new(config);
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            runtime.stop_service().ok();
        } else if runtime.container_exists() {
            runtime.remove_container().ok();
        }
        backup.restore_databases(config)?;
        backup.restore_snapshots()?;
        install::grant_runtime_database(config)?;
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            symlink_atomic(
                Path::new(&journal.previous_runtime),
                &config.runtime.binary_path,
            )?;
            runtime.start_service()?;
        } else {
            runtime.start_container(&journal.previous_runtime)?;
        }
        wait_ready(config)?;
    } else {
        let runtime = Runtime::new(config);
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            runtime.stop_service().ok();
        } else if runtime.container_exists() {
            runtime.remove_container()?;
        }
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            symlink_atomic(
                Path::new(&journal.previous_runtime),
                &config.runtime.binary_path,
            )?;
            runtime.start_service()?;
        } else {
            runtime.start_container(&journal.previous_runtime)?;
        }
        wait_ready(config)?;
    }
    verify_public(config)?;
    verify_ui(config, &journal.from_release)?;
    write_active_release(config, &journal.from_release)
}

pub(crate) fn handle_update_failure(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    error: anyhow::Error,
) -> anyhow::Result<()> {
    if !journal.to_release.rollback.schema_compatible
        || journal.to_release.rollback.irreversible_migration
    {
        write_record(
            config,
            &journal.to_release,
            "recovery-required-after-update-failure",
            journal.backup.as_deref(),
        )
        .ok();
        append_update_management_event(
            config,
            journal,
            "recovery-required",
            "update-failed-recovery-required",
            &journal.to_release.version,
            recovery_boundary_name(journal.to_release.rollback.database_restore),
        )?;
        bail!(
            "update failed across a schema rollback barrier at phase {:?}: {error:#}; run nazoauthctl recover-update --yes to continue the persisted transaction; database recovery boundary={:?}; backup={}",
            journal.phase,
            journal.to_release.rollback.database_restore,
            journal.backup.as_deref().map_or_else(
                || "unavailable".to_owned(),
                |path| path.display().to_string()
            )
        );
    }
    let recovery = restore_previous_transaction(config, journal);
    if let Err(recovery_error) = recovery {
        append_update_management_event(
            config,
            journal,
            "rollback-failed",
            "update-failed-rollback-failed",
            &journal.to_release.version,
            "persisted-recovery-required",
        )?;
        bail!(
            "update failed at phase {:?}: {error:#}; persisted recovery also failed: {recovery_error:#}; run nazoauthctl recover-update --yes",
            journal.phase
        );
    }
    append_update_management_event(
        config,
        journal,
        "artifact-restored",
        "update-artifact-restored",
        &journal.from_release.version,
        "schema-compatible",
    )?;
    finish_update_journal(config, journal)?;
    bail!(
        "update failed at phase {:?} and the previous runtime was restored: {error:#}",
        journal.phase
    )
}
