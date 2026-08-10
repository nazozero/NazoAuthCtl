use super::*;

pub(crate) fn rollback(
    config: &UpdateConfig,
    previous_runtime: &str,
    previous_ui: Option<&Path>,
    backup: &Backup,
) -> anyhow::Result<()> {
    config.require_managed_lifecycle()?;
    let runtime = Runtime::new(config);
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        runtime.stop_service().ok();
    } else if runtime.container_exists() {
        runtime.remove_container().ok();
    }
    let _ = previous_ui;
    backup.restore_snapshots(&config.runtime.snapshot_paths)?;
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        symlink_atomic(Path::new(previous_runtime), &config.runtime.binary_path)?;
        runtime.start_service()?;
    } else {
        runtime.start_container(previous_runtime)?;
    }
    wait_ready(config)
}

pub(crate) fn rollback_state_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("rollback-state.json")
}

pub(crate) fn write_rollback_state(
    config: &UpdateConfig,
    state: RollbackState,
) -> anyhow::Result<()> {
    atomic_write(
        &rollback_state_path(config),
        &serde_json::to_vec_pretty(&state)?,
        0o600,
    )
}

pub(crate) fn public_rollback(config: &UpdateConfig) -> anyhow::Result<()> {
    config.require_managed_lifecycle()?;
    let state_path = rollback_state_path(config);
    let state_bytes = crate::filesystem::read_secure_regular_file(
        &state_path,
        "rollback state",
        true,
        1024 * 1024,
    )?;
    let state: RollbackState =
        serde_json::from_slice(&state_bytes).context("rollback state is invalid")?;
    if state.schema != 1 {
        bail!("unsupported rollback state");
    }
    let active = load_active_release(config)?;
    if active.version != state.to_release.version
        || !active.rollback.schema_compatible
        || active.rollback.irreversible_migration
    {
        bail!(
            "artifact rollback is not schema compatible; database recovery must use the declared {:?} boundary",
            active.rollback.database_restore
        );
    }
    let backup = Backup::open_existing(config, &state.backup)?;
    ensure_trusted_runtime_available(config, &state.from_release, &state.previous_runtime)?;
    crate::operator::append_management_event(
        config,
        "artifact-rollback-intent",
        &state.from_release.version,
        "schema-compatible",
    )?;
    rollback(
        config,
        &state.previous_runtime,
        state.previous_ui.as_deref(),
        &backup,
    )?;
    verify_public(config)?;
    verify_ui(config, &state.from_release)?;
    write_active_release(config, &state.from_release)?;
    crate::operator::append_management_event(
        config,
        "artifact-rollback",
        &state.from_release.version,
        "schema-compatible",
    )?;
    println!(
        "artifact rollback completed to {}; database was not restored; schema compatibility was verified from the signed Release policy",
        state.from_release.version
    );
    Ok(())
}

pub(crate) fn recover_from_backup(config: &UpdateConfig) -> anyhow::Result<()> {
    require_legacy_recovery_capabilities(config)?;
    let state_path = rollback_state_path(config);
    let state_bytes = crate::filesystem::read_secure_regular_file(
        &state_path,
        "recovery state",
        true,
        1024 * 1024,
    )?;
    let state: RollbackState =
        serde_json::from_slice(&state_bytes).context("recovery state is invalid")?;
    if state.schema != 1
        || state.to_release.rollback.database_restore != crate::model::DatabaseRestore::Backup
    {
        bail!("the signed Release does not declare backup-based database recovery");
    }
    let backup = Backup::open_existing(config, &state.backup)?;
    ensure_trusted_runtime_available(config, &state.from_release, &state.previous_runtime)?;
    crate::operator::append_management_event(
        config,
        "backup-recovery-intent",
        &state.from_release.version,
        "database-backup",
    )?;
    rotate_bootstrap_recovery_epoch(config)
        .context("failed to invalidate bootstrap receipts before database recovery")?;
    let runtime = Runtime::new(config);
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        runtime.stop_service()?;
    } else if runtime.container_exists() {
        runtime.remove_container()?;
    }
    backup.restore_databases(config)?;
    backup.restore_snapshots(&config.runtime.snapshot_paths)?;
    install::grant_runtime_database(config)?;
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        symlink_atomic(
            Path::new(&state.previous_runtime),
            &config.runtime.binary_path,
        )?;
        runtime.start_service()?;
    } else {
        runtime.start_container(&state.previous_runtime)?;
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config, &state.from_release)?;
    write_active_release(config, &state.from_release)?;
    crate::operator::append_management_event(
        config,
        "backup-recovery",
        &state.from_release.version,
        "database-backup",
    )?;
    println!(
        "backup recovery completed from {}; application={} database=restored valkey=restored",
        state.backup.display(),
        state.from_release.version
    );
    Ok(())
}
