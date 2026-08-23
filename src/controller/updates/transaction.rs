use super::*;

pub(crate) fn update(
    config_path: &Path,
    config: &UpdateConfig,
    options: UpdateOptions,
) -> anyhow::Result<()> {
    let mut config = config.clone();
    let release = VerifiedRelease::fetch(
        &config.repository,
        options.version.as_deref(),
        config.container_backend(),
    )?;
    enforce_release_trust(&config, &release.manifest)?;
    let tenant_resource_controller_changed = if options.plan {
        false
    } else {
        persist_tenant_resource_controller_runtime_upgrade(config_path, &mut config)?
    };
    if resume_persisted_update(config_path, &config, &release.manifest, &options)? {
        return Ok(());
    }
    let active_target = Runtime::new(&config).active_build_target()?;
    let current = active_target.embedded.revision.clone();
    let active = load_active_release(&config)?;
    let minimum = format!("v{}", release.manifest.rollback.minimum_supported_version);
    if compare_versions(&active.version, &minimum)? == std::cmp::Ordering::Less {
        bail!(
            "active Release {} is below the target's minimum supported {}; use an intermediate signed Release",
            active.version,
            minimum
        );
    }
    if options.plan {
        print_update_plan(&config, &active.version, &current, &release.manifest)?;
        return Ok(());
    }
    release.persist_verification_evidence(&release_cache_dir(&config, &release.manifest))?;
    if active_target_matches_release(&config, &active, &active_target, &release.manifest)?
        && !tenant_resource_controller_changed
    {
        println!(
            "NazoAuth is already at {} ({})",
            release.manifest.version, current
        );
        return Ok(());
    }
    require_confirmation(options.yes, "apply the signed Release update")?;
    if release.manifest.rollback.irreversible_migration && !options.accept_migration_barrier {
        bail!(
            "this Release crosses an irreversible migration barrier; inspect update --plan and repeat with --accept-migration-barrier --yes"
        );
    }
    // Complete legacy MFA configuration before the update journal and its
    // recovery backup are created. The backup must include the durable key.
    persist_mfa_totp_runtime_upgrade(config_path, &mut config)?;
    let runtime = Runtime::new(&config);
    crate::operator::append_management_event(
        &config,
        "update-intent",
        &release.manifest.version,
        recovery_boundary_name(release.manifest.rollback.database_restore),
    )?;
    let runtime_artifact = if config.runtime.backend == RuntimeBackendKind::Systemd {
        Some(release.artifact("binary", &config.repository)?)
    } else {
        None
    };
    let previous_manifest = load_active_release(&config)?;
    let previous_ui = Some(
        config
            .ui
            .releases_root
            .join(&previous_manifest.frontend.artifact.sha256),
    );
    let previous_runtime = if config.runtime.backend == RuntimeBackendKind::Systemd {
        std::fs::canonicalize(&config.runtime.binary_path)
            .context("failed to resolve previous host binary")?
            .to_string_lossy()
            .into_owned()
    } else {
        previous_manifest.image_ref()?
    };
    cache_trusted_runtime(&config, &previous_manifest, &previous_runtime)?;

    let previous_rollback_state = load_optional_rollback_state(&config)?;

    let candidate = if config.runtime.backend == RuntimeBackendKind::Systemd {
        install_host_candidate(
            &config,
            &release,
            runtime_artifact
                .as_deref()
                .context("host Release has no binary artifact")?,
        )?
        .to_string_lossy()
        .into_owned()
    } else {
        let image_ref = release.manifest.image_ref()?;
        runtime.pull_image(&image_ref)?;
        if runtime.image_revision(&image_ref)? != release.manifest.backend_commit {
            bail!("pulled image revision does not match signed manifest");
        }
        image_ref
    };
    let candidate_ui = config
        .ui
        .releases_root
        .join(&release.manifest.frontend.artifact.sha256);
    crate::filesystem::ensure_directory_chain(&config.deployment_root)?;
    let mut journal = UpdateJournal {
        schema: 1,
        transaction_id: format!("update-{}", encode_transaction_id()),
        started_at: Utc::now().to_rfc3339(),
        phase: UpdatePhase::Prepared,
        from_release: previous_manifest,
        to_release: release.manifest.clone(),
        previous_runtime,
        previous_ui,
        candidate_runtime: candidate,
        candidate_ui,
        backup: None,
        rollback_state_captured: true,
        previous_rollback_state,
    };
    write_update_journal(&config, &journal)?;
    if let Err(error) = advance_update_transaction(config_path, &config, &mut journal) {
        return handle_update_failure(&config, &journal, error);
    }
    println!(
        "NazoAuth updated to {} ({})",
        release.manifest.version, release.manifest.backend_commit
    );
    Ok(())
}

pub(crate) fn resume_persisted_update(
    config_path: &Path,
    config: &UpdateConfig,
    target: &ReleaseManifest,
    options: &UpdateOptions,
) -> anyhow::Result<bool> {
    if let Some(mut journal) = load_update_journal(config)? {
        if options.plan {
            bail!(
                "update transaction {} is already pending at phase {:?}; inspect or recover the existing transaction instead of creating a new plan",
                journal.transaction_id,
                journal.phase
            );
        }
        if journal.to_release != *target {
            bail!(
                "pending update transaction targets {}; refusing to resume it with {}",
                journal.to_release.version,
                target.version
            );
        }
        require_confirmation(options.yes, "resume the persisted signed Release update")?;
        if journal.to_release.rollback.irreversible_migration && !options.accept_migration_barrier {
            bail!(
                "this Release crosses an irreversible migration barrier; resume with --accept-migration-barrier --yes"
            );
        }
        if let Err(error) = advance_update_transaction(config_path, config, &mut journal) {
            handle_update_failure(config, &journal, error)?;
        }
        println!(
            "NazoAuth updated to {} ({})",
            journal.to_release.version, journal.to_release.backend_commit
        );
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn active_target_matches_release(
    config: &UpdateConfig,
    recorded: &ReleaseManifest,
    observed: &crate::runtime::ActiveBuildTarget,
    target: &ReleaseManifest,
) -> anyhow::Result<bool> {
    if recorded != target || observed.embedded != target.embedded {
        return Ok(false);
    }
    match config.runtime.backend {
        RuntimeBackendKind::Systemd => Ok(observed.binary_digest
            == target
                .artifacts
                .get("binary")
                .context("signed Release has no runtime binary artifact")?
                .sha256
                .as_str()),
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
            Ok(observed.image_digest == target.runtime_oci_digest()?)
        }
    }
}

pub(crate) fn persist_mfa_totp_runtime_upgrade(
    config_path: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<()> {
    let config_dir = config_path
        .parent()
        .context("update config path has no parent directory")?;
    if !install::ensure_mfa_totp_runtime(config_dir, config)? {
        return Ok(());
    }
    atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    Ok(())
}

pub(crate) fn persist_tenant_resource_controller_runtime_upgrade(
    config_path: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<bool> {
    let config_dir = config_path
        .parent()
        .context("update config path has no parent directory")?;
    if !install::ensure_tenant_resource_controller_runtime(config_dir, config)? {
        return Ok(false);
    }
    atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    Ok(true)
}

pub(crate) fn advance_update_transaction(
    config_path: &Path,
    config: &UpdateConfig,
    journal: &mut UpdateJournal,
) -> anyhow::Result<()> {
    // An update journal can resume at any phase.  Verify the live external
    // contract before it can change a phase, runtime, or audit state.
    install::verify_live_external_dependencies(config)?;
    if journal.phase >= UpdatePhase::BackupCreated {
        journal_backup(config, journal)?;
    }
    let runtime = Runtime::new(config);
    let resuming_activated_target = journal.phase >= UpdatePhase::CandidateActive;
    if resuming_activated_target {
        activate_candidate(config, &runtime, journal)?;
    }
    if journal.phase >= UpdatePhase::UiActive && !target_ui_is_active(config, journal) {
        bail!("candidate application did not retain its signed frontend cache");
    }
    if journal.phase >= UpdatePhase::HealthVerified {
        wait_ready(config)?;
        verify_public(config)?;
        verify_ui(config, &journal.to_release)?;
    }
    if journal.phase < UpdatePhase::WriterStopped {
        set_update_phase(config, journal, UpdatePhase::WriterStopping)?;
        stop_active_runtime(config, &runtime)?;
        set_update_phase(config, journal, UpdatePhase::WriterStopped)?;
    }
    if journal.phase < UpdatePhase::BackupCreated {
        set_update_phase(config, journal, UpdatePhase::BackupCreating)?;
        let backup = Backup::create(config_path, config, &journal.to_release.version)?;
        journal.backup = Some(backup.path().to_owned());
        set_update_phase(config, journal, UpdatePhase::BackupCreated)?;
    }
    if journal.phase < UpdatePhase::MigrationApplied {
        // A durable update journal may be replayed after external provider
        // credentials have changed.  Verify both the live five-secret binding
        // and the committed backup before advancing a phase or running DDL.
        set_update_phase(config, journal, UpdatePhase::MigrationRunning)?;
        execute_manifest_task(
            config,
            &journal.to_release,
            &journal.candidate_runtime,
            TaskOperation::MigrateApply,
            None,
        )?;
        install::grant_runtime_database(config)?;
        set_update_phase(config, journal, UpdatePhase::MigrationApplied)?;
    }
    if journal.phase < UpdatePhase::CandidateActive {
        set_update_phase(config, journal, UpdatePhase::CandidateActivating)?;
        activate_candidate(config, &runtime, journal)?;
        set_update_phase(config, journal, UpdatePhase::CandidateActive)?;
    }
    if journal.phase < UpdatePhase::UiActive {
        set_update_phase(config, journal, UpdatePhase::UiActivating)?;
        wait_ready(config)?;
        verify_ui(config, &journal.to_release)?;
        if !target_ui_is_active(config, journal) {
            bail!("candidate application did not materialize its signed frontend cache");
        }
        set_update_phase(config, journal, UpdatePhase::UiActive)?;
    }
    if journal.phase < UpdatePhase::HealthVerified {
        set_update_phase(config, journal, UpdatePhase::HealthChecking)?;
        wait_ready(config)?;
        verify_public(config)?;
        verify_ui(config, &journal.to_release)?;
        set_update_phase(config, journal, UpdatePhase::HealthVerified)?;
    }
    if journal.phase < UpdatePhase::StateCommitted {
        set_update_phase(config, journal, UpdatePhase::StateCommitting)?;
        let backup = journal_backup(config, journal)?;
        write_active_release(config, &journal.to_release)?;
        write_rollback_state(
            config,
            RollbackState {
                schema: 1,
                from_release: journal.from_release.clone(),
                to_release: journal.to_release.clone(),
                previous_runtime: journal.previous_runtime.clone(),
                previous_ui: journal.previous_ui.clone(),
                backup: backup.path().to_owned(),
            },
        )?;
        write_update_record(config, journal, "deployment-success", Some(backup.path()))?;
        set_update_phase(config, journal, UpdatePhase::StateCommitted)?;
    }
    if journal.phase < UpdatePhase::TrustCommitted {
        set_update_phase(config, journal, UpdatePhase::TrustCommitting)?;
        commit_release_trust(config, &journal.to_release)?;
        set_update_phase(config, journal, UpdatePhase::TrustCommitted)?;
    }
    if journal.phase < UpdatePhase::AuditCommitted {
        set_update_phase(config, journal, UpdatePhase::AuditCommitting)?;
        append_update_management_event(
            config,
            journal,
            "completed",
            "update",
            &journal.to_release.version,
            recovery_boundary_name(journal.to_release.rollback.database_restore),
        )?;
        set_update_phase(config, journal, UpdatePhase::AuditCommitted)?;
    }
    finish_update_journal(config, journal)
}

pub(crate) fn update_journal_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("update-transaction.json")
}

pub(crate) fn write_update_journal(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    validate_update_journal(config, journal)?;
    atomic_write(
        &update_journal_path(config),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

pub(crate) fn set_update_phase(
    config: &UpdateConfig,
    journal: &mut UpdateJournal,
    phase: UpdatePhase,
) -> anyhow::Result<()> {
    if phase < journal.phase {
        bail!("update transaction phase cannot move backwards");
    }
    let previous = journal.phase;
    journal.phase = phase;
    if let Err(error) = write_update_journal(config, journal) {
        journal.phase = previous;
        return Err(error);
    }
    Ok(())
}

pub(crate) fn validate_update_journal(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    if journal.schema != 1
        || journal.transaction_id.is_empty()
        || journal.transaction_id.len() > 96
        || !journal
            .transaction_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        || journal.started_at.is_empty()
        || journal.started_at.len() > 64
        || chrono::DateTime::parse_from_rfc3339(&journal.started_at).is_err()
    {
        bail!("update transaction journal header is invalid");
    }
    for manifest in [&journal.from_release, &journal.to_release] {
        let identity = format!(
            "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{}",
            config.repository, manifest.version
        );
        manifest.validate(&manifest.version, &identity)?;
    }
    if journal.previous_runtime.is_empty() || journal.candidate_runtime.is_empty() {
        bail!("update transaction journal contains an unsafe candidate path");
    }
    let expected_candidate_ui = config
        .ui
        .releases_root
        .join(&journal.to_release.frontend.artifact.sha256);
    if journal.candidate_ui != expected_candidate_ui {
        bail!("update transaction candidate artifacts do not match the signed Release");
    }
    if let Some(previous_ui) = &journal.previous_ui {
        let expected_previous_ui = config
            .ui
            .releases_root
            .join(&journal.from_release.frontend.artifact.sha256);
        if previous_ui != &expected_previous_ui {
            bail!("update transaction previous UI does not match the active Release");
        }
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        let expected_previous_runtime = config
            .runtime
            .binary_releases
            .join(&journal.from_release.backend_commit)
            .join("nazoauth");
        let expected_candidate_runtime = config
            .runtime
            .binary_releases
            .join(&journal.to_release.backend_commit)
            .join("nazoauth");
        if Path::new(&journal.previous_runtime) != expected_previous_runtime
            || Path::new(&journal.candidate_runtime) != expected_candidate_runtime
        {
            bail!("update transaction host runtime does not match its signed Release");
        }
    } else if journal.candidate_runtime != journal.to_release.image_ref()?
        || journal.previous_runtime != journal.from_release.image_ref()?
    {
        bail!("update transaction image runtime does not match its signed Release");
    }
    if let Some(backup) = &journal.backup
        && !backup.starts_with(&config.backup_root)
    {
        bail!("update transaction backup is outside the backup root");
    }
    if journal.phase >= UpdatePhase::BackupCreated && journal.backup.is_none() {
        bail!("update transaction lost its committed backup path");
    }
    if !journal.rollback_state_captured && journal.previous_rollback_state.is_some() {
        bail!("update transaction rollback-state snapshot is inconsistent");
    }
    if let Some(previous) = &journal.previous_rollback_state {
        if previous.schema != 1 || previous.to_release != journal.from_release {
            bail!("update transaction previous rollback state is not bound to its source Release");
        }
        let identity = format!(
            "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{}",
            config.repository, previous.from_release.version
        );
        previous
            .from_release
            .validate(&previous.from_release.version, &identity)?;
        if !previous.backup.starts_with(&config.backup_root) {
            bail!("update transaction previous rollback backup is outside the backup root");
        }
    }
    Ok(())
}

pub(crate) fn load_update_journal(config: &UpdateConfig) -> anyhow::Result<Option<UpdateJournal>> {
    let path = update_journal_path(config);
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() || path.is_symlink() {
        bail!("update transaction journal must be a regular non-symlink file");
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "update transaction journal",
        true,
        2 * 1024 * 1024,
    )?;
    let journal: UpdateJournal =
        serde_json::from_slice(&bytes).context("update transaction journal is invalid")?;
    validate_update_journal(config, &journal)?;
    Ok(Some(journal))
}

pub(crate) fn journal_backup(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<Backup> {
    Backup::open_existing(
        config,
        journal
            .backup
            .as_deref()
            .context("update transaction has no verified backup")?,
    )
}

pub(crate) fn activate_candidate(
    config: &UpdateConfig,
    runtime: &Runtime<'_>,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    // This helper is reachable from recovery/resume paths as well as the
    // initial update.  Keep the runtime transition fail-closed even if a
    // caller supplied a stale configuration snapshot.
    config.require_managed_lifecycle()?;
    if target_is_active(config, journal) {
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            runtime.start_service()?;
        } else {
            runtime.restart()?;
        }
        return Ok(());
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        runtime.stop_service().ok();
        symlink_atomic(
            Path::new(&journal.candidate_runtime),
            &config.runtime.binary_path,
        )?;
        runtime.start_service()
    } else {
        if runtime.container_exists() {
            runtime.remove_container()?;
        }
        runtime.start_container(&journal.candidate_runtime)
    }
}

pub(crate) fn frontend_cache_matches(
    config: &UpdateConfig,
    candidate_ui: &Path,
    release: &ReleaseManifest,
) -> bool {
    fn regular_file(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    if !matches!(
        fs::symlink_metadata(candidate_ui),
        Ok(metadata) if metadata.is_dir()
    ) || !regular_file(&candidate_ui.join("index.html"))
    {
        return false;
    }
    let marker = candidate_ui.join(".nazoauth-ui.json");
    if !regular_file(&marker) {
        return false;
    }
    let Ok(bytes) = crate::runtime::read_runtime_owned_regular_file(
        config,
        &marker,
        "frontend cache marker",
        false,
        64 * 1024,
    ) else {
        return false;
    };
    let Ok(actual) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    actual
        == json!({
            "schema": 1,
            "repository": release.frontend.repository,
            "version": release.frontend.version,
            "commit": release.frontend.commit,
            "release_identity": release.frontend.release_identity,
            "artifact": release.frontend.artifact,
        })
}

pub(crate) fn target_ui_is_active(config: &UpdateConfig, journal: &UpdateJournal) -> bool {
    frontend_cache_matches(config, &journal.candidate_ui, &journal.to_release)
}

pub(crate) fn finish_update_journal(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    let _ = journal;
    remove_file_durable(&update_journal_path(config))
}

pub(crate) fn append_update_management_event(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    event: &str,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    operator::append_management_event_idempotent(
        config,
        &format!("request-{}-{event}", journal.transaction_id),
        operation,
        release,
        recovery_boundary,
    )
}

pub(crate) fn encode_transaction_id() -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(32);
    for byte in rand::random::<[u8; 16]>() {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub(crate) fn stop_active_runtime(
    config: &UpdateConfig,
    runtime: &Runtime<'_>,
) -> anyhow::Result<()> {
    config.require_managed_lifecycle()?;
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        runtime.stop_service()
    } else if runtime.container_exists() {
        runtime.remove_container()
    } else {
        bail!("active application container is unavailable")
    }
}
