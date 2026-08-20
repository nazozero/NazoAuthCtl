use super::*;

pub(super) fn list_deployments() -> anyhow::Result<()> {
    let store = crate::deployment::DeploymentStore::system();
    let registry = store.load_registry()?;
    let deployments = registry
        .deployments
        .keys()
        .map(|deployment_id| store.load(deployment_id))
        .collect::<anyhow::Result<Vec<_>>>()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": 1,
            "deployments": deployments,
        }))?
    );
    Ok(())
}

pub(super) fn registered_status(
    record: &crate::deployment::DeploymentRecord,
    doctor: bool,
) -> anyhow::Result<()> {
    use crate::deployment::{ArtifactReference, Responsibility};
    use crate::runtime_backend::backend;

    let observations = record
        .runtime_instances
        .iter()
        .map(|runtime| {
            let runtime_backend = backend(runtime.backend);
            let described_mounts = runtime_backend
                .describe_mounts(&runtime.object_reference)
                .map(|mounts| mounts.len());
            let observation = runtime_backend.inspect(&runtime.object_reference);
            match observation {
                Ok(observation) => {
                    let artifact_matches = runtime.local_artifact_id.as_ref().map_or_else(
                        || match (&runtime.artifact, &observation.artifact) {
                            (
                                ArtifactReference::Oci {
                                    digest: expected, ..
                                },
                                ArtifactReference::Oci { digest: actual, .. },
                            ) => expected == actual,
                            (
                                ArtifactReference::HostBinary {
                                    sha256: expected, ..
                                },
                                ArtifactReference::HostBinary { sha256: actual, .. },
                            ) => expected == actual,
                            _ => false,
                        },
                        |expected| observation.local_artifact_id.as_ref() == Some(expected),
                    );
                    serde_json::json!({
                        "runtime_instance_id": runtime.runtime_instance_id,
                        "backend": runtime.backend,
                        "object_reference": runtime.object_reference,
                        "present": true,
                        "running": observation.running,
                        "artifact_matches_declaration": artifact_matches,
                        "mounts_verified": described_mounts.is_ok(),
                        "mount_count": described_mounts.unwrap_or_default(),
                    })
                }
                Err(_) => serde_json::json!({
                    "runtime_instance_id": runtime.runtime_instance_id,
                    "backend": runtime.backend,
                    "object_reference": runtime.object_reference,
                    "present": false,
                    "running": false,
                    "artifact_matches_declaration": false,
                    "mounts_verified": false,
                    "mount_count": 0,
                }),
            }
        })
        .collect::<Vec<_>>();
    let managed_runtime_drift = record.capabilities.runtime.responsibility
        == Responsibility::Managed
        && observations.iter().any(|observation| {
            !observation
                .get("present")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || !observation
                    .get("artifact_matches_declaration")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
        });
    let report = serde_json::json!({
        "schema": 1,
        "deployment_id": record.deployment_id,
        "alias": record.alias,
        "issuer": record.issuer,
        "active_release": record.active_release,
        "trust": record.trust,
        "capabilities": record.capabilities,
        "core_recovery_proven": record.core_recovery_is_proven(),
        "machine_loss_requires_off_host_package": true,
        "managed_runtime_drift": managed_runtime_drift,
        "runtime_instances": observations,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    if doctor && managed_runtime_drift {
        bail!("managed runtime drift requires explicit re-verification; no state was overwritten");
    }
    Ok(())
}

pub(super) fn command_is_read_only(command: &Command) -> bool {
    match command {
        Command::Discover
        | Command::DeploymentsList
        | Command::TransactionShow
        | Command::Reconcile
        | Command::Status
        | Command::Doctor
        | Command::Check(_)
        | Command::AuditVerify
        | Command::AuditShow { .. }
        | Command::BreakGlassControllerAvailability => true,
        Command::Update(options) => options.plan,
        _ => false,
    }
}

pub(super) fn acquire_lock(command: &Command) -> anyhow::Result<File> {
    // Installation, update, identity rotation and break-glass recovery mutate
    // one lifecycle state machine and therefore must share one lock even when
    // a test or operator overrides its location.
    let path = std::env::var_os("NAZOAUTHCTL_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    acquire_lock_at(&path, command)
}

/// The standalone OIDF runner does not enter `main_entry`, so it explicitly
/// participates in the same lifecycle lock as update and recovery. Shared mode
/// allows independent read-mostly runs to overlap while excluding mutations.
pub(super) fn acquire_oidf_run_shared_lock() -> anyhow::Result<File> {
    let path = std::env::var_os("NAZOAUTHCTL_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    acquire_oidf_run_shared_lock_at(&path)
}

pub(super) fn acquire_oidf_run_shared_lock_at(path: &Path) -> anyhow::Result<File> {
    let file = open_lock_file(path, false, "lifecycle lock")
        .with_context(|| format!("failed to open lifecycle lock {}", path.display()))?;
    match file.try_lock_shared() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another nazoauthctl lifecycle operation is already running")
        }
        Err(TryLockError::Error(error)) => {
            Err(error).context("failed to acquire shared lifecycle lock")
        }
    }
}

pub(super) fn acquire_lock_at(path: &Path, command: &Command) -> anyhow::Result<File> {
    let read_only = command_is_read_only(command);
    let file = open_lock_file(path, read_only, "lifecycle lock").with_context(|| {
        if read_only {
            format!(
                "failed to open existing lifecycle lock {} for read-only observation",
                path.display()
            )
        } else {
            format!("failed to open lifecycle lock {}", path.display())
        }
    })?;
    let result = if read_only {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match result {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another nazoauthctl lifecycle operation is already running")
        }
        Err(TryLockError::Error(error)) => Err(error).context("failed to acquire lifecycle lock"),
    }
}

pub(super) fn install(
    config_path: PathBuf,
    options: crate::cli::InstallOptions,
) -> anyhow::Result<()> {
    require_root()?;
    let mut config_present = match fs::symlink_metadata(&config_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
        Ok(_) => bail!(
            "update config must be a regular non-symlink file: {}",
            config_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", config_path.display()));
        }
    };
    if !config_present
        && let Some(_intent) = install::load_local_oci_candidate_prepare_intent(&config_path)?
    {
        let candidate = options.local_oci_candidate.as_ref().context(
            "a durable local OCI candidate prepare intent exists; repeat its exact candidate install command",
        )?;
        // This verifies the candidate tuple and the serialized config digest
        // before restoring the config file that was lost in the intent→config
        // publication window.
        install::restore_local_oci_candidate_prepare_intent(&config_path, candidate)?;
        config_present = true;
    }
    if config_present {
        let config = load_config(&config_path)?;
        config.require_managed_lifecycle()?;
        if let Some(candidate) = options.local_oci_candidate.as_ref() {
            if let Some(state) = load_local_oci_candidate_install_state(&config)? {
                return install_local_oci_candidate_transaction(
                    &config_path,
                    &config,
                    candidate,
                    Some(state),
                );
            }
            // A state-less existing config is permitted only when the
            // candidate prepare intent binds these exact config bytes and
            // caller tuple.  Arbitrary legacy/signed configs cannot enter the
            // candidate transaction.
            install::validate_existing_local_oci_candidate_prepare_intent(
                &config_path,
                &config,
                candidate,
            )?;
            return install_local_oci_candidate_transaction(&config_path, &config, candidate, None);
        }
        if load_local_oci_candidate_install_state(&config)?.is_some() {
            bail!(
                "local OCI candidate installation is pending or complete; do not switch this controller config to a signed Release install"
            );
        }
        if install::load_local_oci_candidate_prepare_intent(&config_path)?.is_some() {
            bail!(
                "local OCI candidate prepare intent is present; repeat its exact candidate install command instead of switching this config to a signed Release"
            );
        }
        let store = DeploymentStore::system();
        if store.registry_present()?
            && store
                .load_registry()?
                .deployments
                .contains_key(&config.operator.deployment_id)
        {
            let resolved = store.resolve(Some(&config.operator.deployment_id), true)?;
            let _deployment_lock = store.deployment_lock(&resolved.deployment_id)?;
            let record = store.load(&resolved.deployment_id)?;
            match record.resources.get("controller_config") {
                Some(SafeReference::File { path }) if path == &config_path => {}
                _ => bail!("registered install config path is not declaration-bound"),
            }
            super::verify_control_binding(&record, &config)?;
            if crate::coordination::active_update_exists(&store, &record) {
                bail!("install cannot reconcile while a coordinated update transaction is active");
            }
            if !install_is_complete(&config)? {
                bail!(
                    "registered deployment installation is incomplete; use recover-update or controller-independent recovery instead of replaying install"
                );
            }
            let active = load_active_release(&config)?;
            if active.embedded != record.active_release {
                bail!("registered install active release differs from the deployment declaration");
            }
            let managed_secrets_changed = install::reconcile_managed_secrets(&config)?;
            if managed_secrets_changed {
                install::start_managed_dependencies(&config)?;
                Runtime::new(&config).restart()?;
            }
            if !health_ready(&config) {
                bail!("managed installation is complete but not healthy; run nazoauthctl doctor");
            }
            println!(
                "NazoAuth is already installed and ready; use nazoauthctl update for releases"
            );
            return Ok(());
        }
        let managed_secrets_changed = install::reconcile_managed_secrets(&config)?;
        if install_is_complete(&config)? {
            if managed_secrets_changed {
                install::start_managed_dependencies(&config)?;
                Runtime::new(&config).restart()?;
            }
            if !health_ready(&config) {
                bail!("managed installation is complete but not healthy; run nazoauthctl doctor");
            }
            let completion = load_install_completion(&config)?;
            if !completion.recovery_backup.as_os_str().is_empty() {
                let active = load_active_release(&config)?;
                register_installed_deployment(
                    &config_path,
                    &config,
                    &active,
                    &completion.recovery_backup,
                )?;
            }
            println!(
                "NazoAuth is already installed and ready; use nazoauthctl update for releases"
            );
            return Ok(());
        }
        println!("Resuming the existing managed installation");
        let resume_version = options.version.clone().or_else(|| {
            load_active_release(&config)
                .ok()
                .map(|release| release.version)
        });
        return install_transaction(&config_path, &config, resume_version.as_deref());
    }
    let requested_version = options.version.clone();
    let PreparedInstall {
        config,
        config_path,
        local_oci_candidate,
    } = install::prepare(&config_path, options)?;
    let result = if let Some(candidate) = local_oci_candidate.as_ref() {
        install_local_oci_candidate_transaction(&config_path, &config, candidate, None)
    } else {
        install_transaction(&config_path, &config, requested_version.as_deref())
    };
    if let Err(error) = result {
        eprintln!(
            "nazoauthctl: install stopped; persisted data was retained for a safe retry: {error:#}"
        );
        return Err(error);
    }
    Ok(())
}

pub(super) fn install_transaction(
    config_path: &Path,
    config: &UpdateConfig,
    version: Option<&str>,
) -> anyhow::Result<()> {
    crate::operator::append_management_event(config, "install-intent", "pending", "backup")?;
    install::start_managed_dependencies(config)?;
    let release = VerifiedRelease::fetch(&config.repository, version, config.container_backend())?;
    enforce_release_trust(config, &release.manifest)?;
    release.persist_verification_evidence(&release_cache_dir(config, &release.manifest))?;
    let backup = Backup::create(config_path, config, &release.manifest.version)?;

    if config.runtime.backend == RuntimeBackendKind::Systemd {
        let binary = release.artifact("binary", &config.repository)?;
        let candidate = install_host_candidate(config, &release, &binary)?;
        cache_trusted_runtime(
            config,
            &release.manifest,
            candidate.to_string_lossy().as_ref(),
        )?;
        install::install_systemd(config)?;
        execute_release_task(
            config,
            &release,
            candidate.to_string_lossy().as_ref(),
            TaskOperation::MigrateApply,
            None,
        )?;
        bootstrap_profile_keys(config, &release, candidate.to_string_lossy().as_ref())?;
        symlink_atomic(&candidate, &config.runtime.binary_path)?;
        Runtime::new(config).start_service()?;
    } else {
        let runtime = Runtime::new(config);
        let image_ref = release.manifest.image_ref()?;
        runtime.pull_image(&image_ref)?;
        if runtime.image_revision(&image_ref)? != release.manifest.backend_commit {
            bail!("pulled image revision does not match signed manifest");
        }
        cache_trusted_runtime(config, &release.manifest, &image_ref)?;
        execute_release_task(
            config,
            &release,
            &image_ref,
            TaskOperation::MigrateApply,
            None,
        )?;
        bootstrap_profile_keys(config, &release, &image_ref)?;
        if runtime.container_exists() {
            runtime.remove_container()?;
        }
        runtime.start_container(&image_ref)?;
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config, &release.manifest)?;
    write_active_release(config, &release.manifest)?;
    commit_release_trust(config, &release.manifest)?;
    write_record(config, &release.manifest, "install-success", None)?;
    let management_event = crate::operator::append_management_event(
        config,
        "install",
        &release.manifest.version,
        "backup",
    )?;
    let management_event_file = management_event
        .file_name()
        .and_then(|name| name.to_str())
        .context("management audit event has no valid file name")?
        .to_owned();
    atomic_write(
        &install_completion_path(config),
        &serde_json::to_vec_pretty(&InstallCompletion {
            schema: 2,
            version: release.manifest.version.clone(),
            backend_commit: release.manifest.backend_commit.clone(),
            management_event_file,
            management_event_sha256: crate::filesystem::sha256(&management_event)?,
            recovery_backup: backup.path().to_owned(),
        })?,
        0o600,
    )?;
    register_installed_deployment(config_path, config, &release.manifest, backup.path())?;
    println!(
        "NazoAuth installed at {} ({})",
        release.manifest.version, release.manifest.backend_commit
    );
    println!(
        "Break-glass recovery key: {} (root-only; copy it to protected offline storage)",
        config.operator.break_glass_private_key.display()
    );
    println!("Create the first administrator with: nazoauthctl bootstrap-admin");
    Ok(())
}

fn local_oci_candidate_install_state_path(config: &UpdateConfig) -> PathBuf {
    config
        .deployment_root
        .join("local-oci-candidate-install.json")
}

fn load_local_oci_candidate_install_state(
    config: &UpdateConfig,
) -> anyhow::Result<Option<LocalOciCandidateInstallState>> {
    let path = local_oci_candidate_install_state_path(config);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("local OCI candidate installation state is not a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("failed to inspect local OCI candidate installation state");
        }
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "local OCI candidate installation state",
        true,
        256 * 1024,
    )?;
    let state: LocalOciCandidateInstallState = serde_json::from_slice(&bytes)
        .context("local OCI candidate installation state is invalid")?;
    if state.schema != 1 || state.local_artifact_id.is_empty() {
        bail!("local OCI candidate installation state has an unsupported schema or identity");
    }
    Ok(Some(state))
}

pub(super) fn local_oci_candidate_install_is_pending(
    config: &UpdateConfig,
) -> anyhow::Result<bool> {
    Ok(load_local_oci_candidate_install_state(config)?.is_some_and(|state| !state.completed))
}

pub(super) fn local_oci_candidate_install_is_completed(
    config: &UpdateConfig,
) -> anyhow::Result<bool> {
    Ok(load_local_oci_candidate_install_state(config)?.is_some_and(|state| state.completed))
}

pub(super) fn validate_completed_local_oci_candidate_provenance(
    config: &UpdateConfig,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    let state = load_local_oci_candidate_install_state(config)?
        .context("local OCI candidate deployment has no durable candidate state")?;
    if !state.completed {
        bail!("local OCI candidate deployment is not complete");
    }
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate deployment has no runtime binding")?;
    let crate::deployment::ArtifactReference::Oci { digest, .. } = &runtime.artifact else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    if record.active_release.release != state.candidate.target.release
        || record.active_release.revision != state.candidate.target.revision
        || record.active_release.build_id != state.candidate.target.build_id
        || runtime.local_artifact_id.as_deref() != Some(&state.local_artifact_id)
        || digest != &state.candidate.target.oci_digest
    {
        bail!("local OCI candidate deployment does not match its completed durable state");
    }
    let event_file = state
        .management_event_file
        .as_deref()
        .context("completed local OCI candidate install has no management audit event")?;
    let event_sha256 = state
        .management_event_sha256
        .as_deref()
        .context("completed local OCI candidate install has no management audit digest")?;
    let event_path = config
        .operator
        .audit_directory
        .join("management")
        .join(event_file);
    if crate::filesystem::sha256(&event_path)? != event_sha256 {
        bail!("completed local OCI candidate install management audit digest mismatch");
    }
    let event = operator::load_management_event(config, event_file)?;
    if event.operation != "local-oci-candidate-install"
        || event.release != state.candidate.target.release
    {
        bail!("completed local OCI candidate install management audit event is inconsistent");
    }
    Ok(())
}

pub(super) fn local_oci_candidate_install_resource_path(config: &UpdateConfig) -> PathBuf {
    local_oci_candidate_install_state_path(config)
}

pub(super) const LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE: &str = "local_oci_candidate_install";

fn candidate_registration_journal_present(
    store: &DeploymentStore,
    deployment_id: &str,
) -> anyhow::Result<bool> {
    let path = store.registration_journal_path(deployment_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!(
            "local OCI candidate registration journal is not a regular non-symlink file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect local OCI candidate registration journal {}",
                path.display()
            )
        }),
    }
}

/// Admit either an entirely unregistered candidate retry or the narrow crash
/// window after this exact candidate's registration started.  The latter is
/// reconciled before any application task; every other existing declaration
/// remains a fresh-only failure.
fn ensure_local_oci_candidate_retry_is_unregistered(
    config: &UpdateConfig,
    allow_registration_recovery: bool,
) -> anyhow::Result<bool> {
    let store = DeploymentStore::system();
    // Keep the same global-to-specific order used by registration.  A retry
    // therefore cannot observe a registry between phases while a declaration
    // is being committed for this deployment.
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&config.operator.deployment_id)?;
    if store.registration_pending_except(Some(&config.operator.deployment_id))? {
        bail!(
            "deployment registration transaction is pending; recover it before a local OCI candidate retry"
        );
    }
    let candidate_journal =
        candidate_registration_journal_present(&store, &config.operator.deployment_id)?;
    let registry = store.load_registry()?;
    let registry_binding = registry
        .deployments
        .contains_key(&config.operator.deployment_id);
    let declaration = store.declaration_path(&config.operator.deployment_id);
    let declaration_present = declaration.exists();
    if crate::coordination::active_update_exists_for_deployment(
        &store,
        &config.operator.deployment_id,
    ) {
        bail!("local OCI candidate retry is blocked by an active deployment update");
    }
    let registration_recovery = candidate_journal || registry_binding || declaration_present;
    if registration_recovery && !allow_registration_recovery {
        bail!(
            "local OCI candidate retry refuses an existing deployment binding; only the exact post-registration crash recovery is permitted"
        );
    }
    Ok(registration_recovery)
}

fn persist_local_oci_candidate_install_state(
    config: &UpdateConfig,
    state: &LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    atomic_write(
        &local_oci_candidate_install_state_path(config),
        &serde_json::to_vec_pretty(state)?,
        0o600,
    )
}

fn local_oci_candidate_expected_target(
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
) -> anyhow::Result<ExpectedReleaseTarget> {
    operator::expected_release_target(
        config,
        nazo_operator_protocol::EmbeddedIdentity {
            release: candidate.target.release.clone(),
            revision: candidate.target.revision.clone(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: candidate.target.build_id.clone(),
        },
        candidate.target.oci_digest.clone(),
        String::new(),
    )
}

fn install_local_oci_candidate_transaction(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    persisted: Option<LocalOciCandidateInstallState>,
) -> anyhow::Result<()> {
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        bail!("local OCI candidate installation requires a container runtime");
    }
    if config.install_profile != "standards-full" {
        bail!("local OCI candidate installation requires the standards-full profile");
    }
    let runtime = Runtime::new(config);
    let local = runtime.inspect_local_development_artifact(&candidate.image)?;
    let local_artifact_id = local
        .local_artifact_id
        .as_deref()
        .context("local OCI candidate did not resolve to an immutable local image ID")?;
    let actual_digest = runtime.image_digest(local_artifact_id)?;
    crate::controller::commands::validate_local_oci_candidate_observation(
        &candidate.target,
        &local.embedded,
        local_artifact_id,
        &actual_digest,
    )?;

    let mut state = match persisted {
        Some(state) => {
            if state.candidate != *candidate || state.local_artifact_id != local_artifact_id {
                bail!(
                    "local OCI candidate retry does not match the persisted candidate identity and local image ID"
                );
            }
            state
        }
        None => LocalOciCandidateInstallState {
            schema: 1,
            candidate: candidate.clone(),
            local_artifact_id: local_artifact_id.to_owned(),
            recovery_backup: None,
            management_event_file: None,
            management_event_sha256: None,
            completed: false,
        },
    };
    if state.completed {
        validate_completed_local_oci_candidate_install(config_path, config, &state)?;
        if !health_ready(config) {
            bail!(
                "local OCI candidate installation is complete but not healthy; run nazoauthctl doctor"
            );
        }
        println!("NazoAuth local OCI candidate is already installed and ready");
        return Ok(());
    }

    let registration_recovery =
        ensure_local_oci_candidate_retry_is_unregistered(config, state.recovery_backup.is_some())?;
    if registration_recovery {
        return finish_local_oci_candidate_registration_recovery(
            config_path,
            config,
            candidate,
            local_artifact_id,
            &mut state,
        );
    }

    // Persist the exact image ID before any task, database mutation, or
    // container replacement. A retry must prove the same local object again.
    persist_local_oci_candidate_install_state(config, &state)?;
    crate::operator::append_management_event(
        config,
        "local-oci-candidate-install-intent",
        &candidate.target.release,
        "backup",
    )?;
    install::start_managed_dependencies(config)?;
    if state.recovery_backup.is_none() {
        let backup = Backup::create(config_path, config, &candidate.target.release)?;
        state.recovery_backup = Some(backup.path().to_owned());
        persist_local_oci_candidate_install_state(config, &state)?;
    }
    let expected = local_oci_candidate_expected_target(config, candidate)?;
    operator::execute(
        config,
        local_artifact_id,
        &expected,
        TaskOperation::MigrateApply,
        None,
    )?;
    install::grant_runtime_database(config)?;
    operator::execute(
        config,
        local_artifact_id,
        &expected,
        TaskOperation::KeysGenerateLocal {
            alg: "ES256".to_owned(),
            purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
        },
        None,
    )?;
    bootstrap_openid4vc_revocation_snapshot(config)?;
    runtime.activate_local_development_artifact(&local)?;
    wait_ready(config)?;
    verify_public(config)?;

    let backup = state
        .recovery_backup
        .as_deref()
        .context("local OCI candidate installation lost its recovery backup path")?;
    register_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
        backup,
    )?;
    let store = DeploymentStore::system();
    // `register_local_oci_candidate_deployment` uses `persist_exact_locked`;
    // loading only after it returns is the exact-record proof needed before
    // this installation writes its completion audit/state.
    let record = store.load(&config.operator.deployment_id)?;
    crate::lifecycle::cache_trusted_runtime(&store, &record)?;
    let management_event = crate::operator::append_management_event(
        config,
        "local-oci-candidate-install",
        &candidate.target.release,
        "backup",
    )?;
    state.management_event_file = management_event
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned);
    state.management_event_sha256 = Some(crate::filesystem::sha256(&management_event)?);
    state.completed = true;
    persist_local_oci_candidate_install_state(config, &state)?;
    validate_registered_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
    )?;
    println!(
        "NazoAuth local OCI candidate installed at {} ({})",
        candidate.target.release, candidate.target.revision
    );
    Ok(())
}

/// A crash after declaration/registry persistence but before the completed
/// candidate state must not replay migrations, key generation, or container
/// replacement.  `persist_exact_locked` below first proves the declaration is
/// byte-for-byte the candidate binding; only then may this finish the audit
/// and release the global unsettled-state guard.
fn finish_local_oci_candidate_registration_recovery(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
    state: &mut LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    let backup = state
        .recovery_backup
        .as_deref()
        .context("local OCI candidate registration recovery has no durable backup")?;
    register_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
        backup,
    )?;
    let store = DeploymentStore::system();
    let record = store.load(&config.operator.deployment_id)?;
    if !health_ready(config) {
        bail!(
            "local OCI candidate registration is durable but the runtime is not healthy; do not release the pending install state"
        );
    }
    crate::lifecycle::cache_trusted_runtime(&store, &record)?;
    let management_event = crate::operator::append_management_event(
        config,
        "local-oci-candidate-install",
        &candidate.target.release,
        "backup",
    )?;
    state.management_event_file = management_event
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned);
    state.management_event_sha256 = Some(crate::filesystem::sha256(&management_event)?);
    state.completed = true;
    persist_local_oci_candidate_install_state(config, state)?;
    validate_registered_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
    )?;
    println!(
        "NazoAuth local OCI candidate registration recovery completed at {} ({})",
        candidate.target.release, candidate.target.revision
    );
    Ok(())
}

fn validate_completed_local_oci_candidate_install(
    config_path: &Path,
    config: &UpdateConfig,
    state: &LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    validate_registered_local_oci_candidate_deployment(
        config_path,
        config,
        &state.candidate,
        &state.local_artifact_id,
    )?;
    Ok(())
}

fn validate_registered_local_oci_candidate_deployment(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
) -> anyhow::Result<DeploymentRecord> {
    let store = DeploymentStore::system();
    let record = store.load(&config.operator.deployment_id)?;
    match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) if path == config_path => {}
        _ => bail!(
            "local OCI candidate deployment is not declaration-bound to its controller config"
        ),
    }
    crate::controller::commands::validate_declared_local_artifact(&record, config)?;
    if record.active_release.release != candidate.target.release
        || record.active_release.revision != candidate.target.revision
        || record.active_release.build_id != candidate.target.build_id
        || record.runtime_instances.len() != 1
        || record.runtime_instances[0].local_artifact_id.as_deref() != Some(local_artifact_id)
    {
        bail!("local OCI candidate deployment differs from its exact persisted binding");
    }
    let crate::deployment::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &record.runtime_instances[0].artifact
    else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    if image_reference != local_artifact_id || digest != &candidate.target.oci_digest {
        bail!(
            "local OCI candidate deployment artifact differs from its local ID or expected digest"
        );
    }
    Ok(record)
}

pub(super) fn bootstrap_profile_keys(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    target: &str,
) -> anyhow::Result<()> {
    if config.install_profile != "standards-full" {
        return Ok(());
    }
    execute_release_task(
        config,
        release,
        target,
        TaskOperation::KeysGenerateLocal {
            alg: "ES256".to_owned(),
            purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
        },
        None,
    )?;
    bootstrap_openid4vc_revocation_snapshot(config)
}

pub(super) fn install_completion_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("managed-install-complete.json")
}

pub(super) fn install_is_complete(config: &UpdateConfig) -> anyhow::Result<bool> {
    let path = install_completion_path(config);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("managed installation completion marker is not a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let completion = load_install_completion(config)?;
    if !matches!(completion.schema, 1 | 2) {
        bail!("unsupported managed installation completion marker");
    }
    let active = load_active_release(config)?;
    if completion.version != active.version || completion.backend_commit != active.backend_commit {
        bail!("managed installation completion marker does not match the active Release");
    }
    let event_path = config
        .operator
        .audit_directory
        .join("management")
        .join(&completion.management_event_file);
    if crate::filesystem::sha256(&event_path)? != completion.management_event_sha256 {
        bail!("managed installation completion audit digest mismatch");
    }
    let event = operator::load_management_event(config, &completion.management_event_file)?;
    if event.operation != "install" || event.release != completion.version {
        bail!("managed installation completion audit event is inconsistent");
    }
    Ok(true)
}

pub(super) fn load_install_completion(config: &UpdateConfig) -> anyhow::Result<InstallCompletion> {
    let path = install_completion_path(config);
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "managed installation completion marker",
        true,
        256 * 1024,
    )?;
    serde_json::from_slice(&bytes).context("managed installation completion marker is invalid")
}

pub(super) fn register_installed_deployment(
    config_path: &Path,
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    backup: &Path,
) -> anyhow::Result<()> {
    use crate::deployment::{
        ArtifactReference, DEPLOYMENT_SCHEMA, DeploymentRecord, DeploymentStore, MountReference,
        RecoveryAssessment, RecoveryConclusion, ResourceScope, Responsibility, RuntimeBackendKind,
        RuntimeInstance, TrustState,
    };
    use std::collections::BTreeSet;

    let backend = config.runtime.backend;
    let artifact = if backend == RuntimeBackendKind::Systemd {
        ArtifactReference::HostBinary {
            path: config.runtime.binary_path.clone(),
            sha256: manifest
                .artifacts
                .get("binary")
                .context("server Release has no host binary")?
                .sha256
                .clone(),
        }
    } else {
        ArtifactReference::Oci {
            image_reference: manifest.image_ref()?,
            digest: manifest.runtime_oci_digest()?.to_owned(),
        }
    };
    let object_reference = if backend == RuntimeBackendKind::Systemd {
        config.runtime.service_name.clone()
    } else {
        config.runtime.container_name.clone()
    };
    let resources = installed_deployment_resources(config_path, config)?;
    let record = DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: config.operator.deployment_id.clone(),
        control_authority: config.operator.controller_key_id.clone(),
        alias: None,
        issuer: config.runtime.expected_issuer.clone(),
        active_release: manifest.embedded.clone(),
        trust: TrustState::Adopted,
        capabilities: config.capabilities.clone(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: config.runtime.runtime_instance_id.clone(),
            backend,
            object_reference,
            artifact,
            local_artifact_id: None,
            ports: (!config.runtime.publish_address.is_empty())
                .then(|| config.runtime.publish_address.clone())
                .into_iter()
                .collect(),
            networks: (!config.runtime.network.is_empty())
                .then(|| config.runtime.network.clone())
                .into_iter()
                .collect(),
            mounts: config
                .runtime
                .mounts
                .iter()
                .map(|mount| MountReference {
                    source: mount.source.clone(),
                    destination: mount.target.clone(),
                    read_only: mount.read_only,
                    selinux_relabel: mount.selinux_relabel,
                    scope: ResourceScope::Deployment,
                    ownership: Responsibility::Managed,
                })
                .collect(),
            instance_key_id: None,
            deployment_statement: config.runtime.mounts.iter().find_map(|mount| {
                (mount.target == Path::new("/var/lib/nazo_oauth/instance"))
                    .then(|| mount.source.join("deployment-statement.jws"))
            }),
        }],
        resources,
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: vec![
                format!("backup:{}", backup.display()),
                format!(
                    "release-cache:{}",
                    release_cache_dir(config, manifest).display()
                ),
            ],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: BTreeSet::from([nazo_operator_protocol::PROTOCOL_VERSION]),
        control_protocol_versions: BTreeSet::from([1]),
        declaration_revision: 1,
    };
    let store = DeploymentStore::system();
    store.persist(&record)
}

fn register_local_oci_candidate_deployment(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
    backup: &Path,
) -> anyhow::Result<()> {
    use crate::deployment::{
        ArtifactReference, DEPLOYMENT_SCHEMA, DeploymentRecord, DeploymentStore, MountReference,
        RecoveryAssessment, RecoveryConclusion, ResourceScope, Responsibility, RuntimeInstance,
        TrustState,
    };
    use std::collections::BTreeSet;

    let backend = config.runtime.backend;
    if backend == RuntimeBackendKind::Systemd {
        bail!("local OCI candidate deployment cannot use the host runtime");
    }
    let mut resources = installed_deployment_resources(config_path, config)?;
    resources.insert(
        LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE.to_owned(),
        SafeReference::File {
            path: local_oci_candidate_install_resource_path(config),
        },
    );
    let record = DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: config.operator.deployment_id.clone(),
        control_authority: config.operator.controller_key_id.clone(),
        alias: None,
        issuer: config.runtime.expected_issuer.clone(),
        active_release: nazo_operator_protocol::EmbeddedIdentity {
            release: candidate.target.release.clone(),
            revision: candidate.target.revision.clone(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: candidate.target.build_id.clone(),
        },
        trust: TrustState::Adopted,
        capabilities: config.capabilities.clone(),
        runtime_instances: vec![RuntimeInstance {
            runtime_instance_id: config.runtime.runtime_instance_id.clone(),
            backend,
            object_reference: config.runtime.container_name.clone(),
            artifact: ArtifactReference::Oci {
                image_reference: local_artifact_id.to_owned(),
                digest: candidate.target.oci_digest.clone(),
            },
            local_artifact_id: Some(local_artifact_id.to_owned()),
            ports: (!config.runtime.publish_address.is_empty())
                .then(|| config.runtime.publish_address.clone())
                .into_iter()
                .collect(),
            networks: (!config.runtime.network.is_empty())
                .then(|| config.runtime.network.clone())
                .into_iter()
                .collect(),
            mounts: config
                .runtime
                .mounts
                .iter()
                .map(|mount| MountReference {
                    source: mount.source.clone(),
                    destination: mount.target.clone(),
                    read_only: mount.read_only,
                    selinux_relabel: mount.selinux_relabel,
                    scope: ResourceScope::Deployment,
                    ownership: Responsibility::Managed,
                })
                .collect(),
            instance_key_id: None,
            deployment_statement: config.runtime.mounts.iter().find_map(|mount| {
                (mount.target == Path::new("/var/lib/nazo_oauth/instance"))
                    .then(|| mount.source.join("deployment-statement.jws"))
            }),
        }],
        resources,
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::RequiresUserEvidence,
            evidence: vec![
                format!("backup:{}", backup.display()),
                format!("local-oci-image-id:{local_artifact_id}"),
                format!("local-oci-digest:{}", candidate.target.oci_digest),
            ],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: BTreeSet::from([nazo_operator_protocol::PROTOCOL_VERSION]),
        control_protocol_versions: BTreeSet::from([1]),
        declaration_revision: 1,
    };
    let store = DeploymentStore::system();
    // Match DeploymentStore::persist lock ordering explicitly: registry first,
    // then this deployment.  Candidate registration cannot race an ordinary
    // declaration write into a retained older record.
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    store.persist_exact_locked(&record)
}

fn installed_deployment_resources(
    config_path: &Path,
    config: &UpdateConfig,
) -> anyhow::Result<std::collections::BTreeMap<String, SafeReference>> {
    use std::collections::BTreeMap;

    Ok(BTreeMap::from([
        (
            "controller_config".to_owned(),
            SafeReference::File {
                path: config_path.to_owned(),
            },
        ),
        (
            "audit_private_key".to_owned(),
            SafeReference::File {
                path: config.operator.audit_private_key.clone(),
            },
        ),
        (
            "audit_public_key".to_owned(),
            SafeReference::File {
                path: config.operator.audit_public_key.clone(),
            },
        ),
        (
            "break_glass_private_key".to_owned(),
            SafeReference::File {
                path: config.operator.break_glass_private_key.clone(),
            },
        ),
        (
            "database".to_owned(),
            if config.dependencies.mode == "managed" {
                SafeReference::RuntimeObject {
                    backend: config
                        .container_backend()
                        .context("managed database has no typed container backend")?,
                    object_reference: config.postgres.container_name.clone(),
                }
            } else {
                SafeReference::File {
                    path: config.dependencies.database_url_file.clone(),
                }
            },
        ),
        (
            "valkey".to_owned(),
            if config.dependencies.mode == "managed" {
                SafeReference::RuntimeObject {
                    backend: config
                        .container_backend()
                        .context("managed Valkey has no typed container backend")?,
                    object_reference: config.valkey.container_name.clone(),
                }
            } else {
                SafeReference::File {
                    path: config.dependencies.valkey_url_file.clone(),
                }
            },
        ),
        ("proxy_tls".to_owned(), SafeReference::NotObserved),
    ]))
}
