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
    install::verify_live_external_dependencies(config)?;
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
    validate_local_oci_candidate_install_state(&state)?;
    Ok(Some(state))
}

/// Candidate schema 1 predates durable task receipts, immutable recovery
/// packages, and the completion provenance checks.  It cannot be upgraded in
/// place without inventing evidence, so an old pending state is deliberately
/// an operator-visible, fail-closed boundary rather than a best-effort retry.
fn validate_local_oci_candidate_install_state(
    state: &LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    if state.schema == 1 {
        bail!(
            "local OCI candidate state schema 1 is not recoverable; preserve it for evidence and recreate the deployment with a fresh managed candidate install"
        );
    }
    if state.schema == 2 {
        bail!(
            "local OCI candidate state schema 2 predates generation-bound dependency-image recovery evidence; preserve it for incident evidence and recreate a fresh managed candidate deployment"
        );
    }
    if state.schema != 3
        || state.local_artifact_id.is_empty()
        || state.attempt == 0
        || state.migration_jti.is_empty()
        || state.keys_jti.is_empty()
    {
        bail!("local OCI candidate installation state has an unsupported schema or identity");
    }
    let receipt_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte >= b'a'))
    };
    for value in [
        state.migration_receipt_sha256.as_deref(),
        state.keys_receipt_sha256.as_deref(),
        state.recovery_archive_sha256.as_deref(),
        state.recovery_cache_sha256.as_deref(),
        state.management_event_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !receipt_digest(value) {
            bail!("local OCI candidate state contains an invalid digest");
        }
    }
    let migration_committed = matches!(
        state.phase,
        LocalOciCandidatePhase::MigrationApplied
            | LocalOciCandidatePhase::KeysStarted
            | LocalOciCandidatePhase::KeysApplied
            | LocalOciCandidatePhase::RuntimeStarted
            | LocalOciCandidatePhase::BaselineCreated
            | LocalOciCandidatePhase::Registered
            | LocalOciCandidatePhase::Completed
    );
    let keys_committed = matches!(
        state.phase,
        LocalOciCandidatePhase::KeysApplied
            | LocalOciCandidatePhase::RuntimeStarted
            | LocalOciCandidatePhase::BaselineCreated
            | LocalOciCandidatePhase::Registered
            | LocalOciCandidatePhase::Completed
    );
    if state.migration_receipt_sha256.is_some() != migration_committed
        || state.keys_receipt_sha256.is_some() != keys_committed
        || (state.completed != (state.phase == LocalOciCandidatePhase::Completed))
    {
        bail!("local OCI candidate state phase and receipts are inconsistent");
    }
    let recovery_material_required = matches!(
        state.phase,
        LocalOciCandidatePhase::BaselineCreated
            | LocalOciCandidatePhase::Registered
            | LocalOciCandidatePhase::Completed
    );
    let has_recovery_material = state.baseline_backup.is_some()
        && state.recovery_package.is_some()
        && state.recovery_archive_sha256.is_some()
        && state.recovery_cache_sha256.is_some()
        && state.recovery_postgres_archive_sha256.is_some()
        && state.recovery_valkey_archive_sha256.is_some();
    if recovery_material_required != has_recovery_material {
        if recovery_material_required
            && (state.recovery_postgres_archive_sha256.is_none()
                || state.recovery_valkey_archive_sha256.is_none())
        {
            bail!(
                "local OCI candidate state predates dependency-image recovery evidence; preserve it for incident evidence and recreate a fresh managed candidate deployment"
            );
        }
        bail!("local OCI candidate state recovery package does not match its phase");
    }
    if state.completed
        && (state.management_event_file.is_none() || state.management_event_sha256.is_none())
    {
        bail!("completed local OCI candidate state has no management audit binding");
    }
    Ok(())
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
    if record.recovery.conclusion != RecoveryConclusion::Proven
        || !record.recovery.off_host_package_required_for_machine_loss
    {
        bail!("local OCI candidate deployment has no proven recovery conclusion");
    }
    let package = state
        .recovery_package
        .as_deref()
        .context("completed local OCI candidate install has no recovery package")?;
    let package_digest = state
        .recovery_cache_sha256
        .as_deref()
        .context("completed local OCI candidate install has no recovery package digest")?;
    match record.resources.get("candidate_recovery_package") {
        Some(SafeReference::DigestBoundFile { path, sha256 })
            if path == package && sha256 == package_digest => {}
        _ => {
            bail!("completed local OCI candidate install recovery package is not declaration-bound")
        }
    }
    if crate::filesystem::sha256(package)? != package_digest {
        bail!("completed local OCI candidate install recovery package digest mismatch");
    }
    let archive = package
        .parent()
        .context("completed local OCI candidate recovery package has no parent")?
        .join("image.tar");
    let archive_digest = state
        .recovery_archive_sha256
        .as_deref()
        .context("completed local OCI candidate install has no recovery archive digest")?;
    match record.resources.get("candidate_recovery_archive") {
        Some(SafeReference::DigestBoundFile { path, sha256 })
            if path == &archive && sha256 == archive_digest => {}
        _ => bail!("completed local OCI candidate archive is not declaration-bound"),
    }
    if crate::filesystem::sha256(&archive)? != archive_digest {
        bail!("completed local OCI candidate recovery archive digest mismatch");
    }
    for (name, file, expected) in [
        (
            "candidate_recovery_postgres_archive",
            package
                .parent()
                .context("completed local OCI candidate recovery package has no parent")?
                .join("postgres-image.tar"),
            state.recovery_postgres_archive_sha256.as_deref(),
        ),
        (
            "candidate_recovery_valkey_archive",
            package
                .parent()
                .context("completed local OCI candidate recovery package has no parent")?
                .join("valkey-image.tar"),
            state.recovery_valkey_archive_sha256.as_deref(),
        ),
    ] {
        let expected =
            expected.context("completed local OCI candidate has no dependency archive digest")?;
        match record.resources.get(name) {
            Some(SafeReference::DigestBoundFile { path, sha256 })
                if path == &file && sha256 == expected => {}
            _ => bail!("completed local OCI candidate {name} is not declaration-bound"),
        }
        if crate::filesystem::sha256(&file)? != expected {
            bail!("completed local OCI candidate {name} digest mismatch");
        }
    }
    let baseline = state
        .baseline_backup
        .as_deref()
        .context("completed local OCI candidate install has no baseline backup")?;
    Backup::open_existing(config, baseline)?;
    for (name, file) in [
        (
            "candidate_baseline_checksum_manifest",
            baseline.join("SHA256SUMS"),
        ),
        (
            "candidate_baseline_completion_marker",
            baseline.join("BACKUP-COMPLETE"),
        ),
    ] {
        match record.resources.get(name) {
            Some(SafeReference::DigestBoundFile { path, sha256 }) if path == &file => {
                if crate::filesystem::sha256(&file)? != *sha256 {
                    bail!("completed local OCI candidate {name} digest mismatch");
                }
            }
            _ => bail!("completed local OCI candidate {name} is not declaration-bound"),
        }
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

/// Candidate deployments are permanently frozen to their exact image, but
/// they retain this dedicated, managed-only recovery transaction.  It never
/// enters signed update/development/adoption machinery and rotates the
/// recoverable baseline before replacing the declaration.
pub(super) fn recover_registered_local_oci_candidate(
    config_path: &Path,
    config: &UpdateConfig,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    // Match declaration persistence's global-to-specific lock ordering for
    // the complete restore/activation/CAS transaction.
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let record = store.load(&record.deployment_id)?;
    let config = super::load_bound_control_config_unsettled(config_path)?;
    match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) if path == config_path => {}
        _ => bail!("registered local OCI candidate has no exact controller config binding"),
    }
    super::verify_control_binding(&record, &config)?;
    record.require_mutation(&[
        Capability::Runtime,
        Capability::Artifact,
        Capability::Database,
        Capability::Valkey,
        Capability::Backups,
        Capability::OperatorTasks,
    ])?;
    if crate::coordination::active_update_exists_for_deployment(&store, &record.deployment_id)
        || store.registration_pending_except(Some(&record.deployment_id))?
    {
        bail!(
            "registered local OCI candidate recovery is blocked by an unsettled declaration or update transaction"
        );
    }
    let pending_journal = find_local_oci_candidate_recovery_journal(&config)?;
    let generation = pending_journal.as_ref().map_or_else(
        || {
            record
                .declaration_revision
                .checked_add(1)
                .context("local OCI candidate recovery generation overflow")
        },
        |journal| Ok(journal.generation),
    )?;
    let expected_record_sha256 = local_oci_candidate_record_sha256(&record)?;
    let mut journal = match pending_journal {
        Some(journal) => {
            let expected_revision =
                if journal.phase < LocalOciCandidateRecoveryPhase::DeclarationCommitted {
                    journal.expected_declaration_revision
                } else {
                    journal
                        .expected_declaration_revision
                        .checked_add(1)
                        .context("candidate recovery declaration revision overflow")?
                };
            if expected_revision != record.declaration_revision
                || (journal.phase < LocalOciCandidateRecoveryPhase::DeclarationCommitted
                    && journal.expected_record_sha256 != expected_record_sha256)
            {
                bail!("local OCI candidate recovery journal does not bind the locked declaration");
            }
            journal
        }
        None => {
            validate_completed_local_oci_candidate_provenance(&config, &record)?;
            let journal = LocalOciCandidateRecoveryJournal {
                schema: 1,
                deployment_id: record.deployment_id.clone(),
                runtime_instance_id: config.runtime.runtime_instance_id.clone(),
                generation,
                expected_declaration_revision: record.declaration_revision,
                expected_record_sha256,
                phase: LocalOciCandidateRecoveryPhase::Prepared,
                staged_state: None,
            };
            write_local_oci_candidate_recovery_journal(&config, &journal)?;
            journal
        }
    };
    let mut state = journal.staged_state.clone().map_or_else(
        || {
            load_local_oci_candidate_install_state(&config)?
                .context("registered local OCI candidate has no durable state")
        },
        Ok,
    )?;
    if journal.phase < LocalOciCandidateRecoveryPhase::DeclarationCommitted {
        validate_completed_local_oci_candidate_provenance(&config, &record)?;
    }
    let state_from_record = load_local_oci_candidate_install_state(&config)?
        .context("registered local OCI candidate has no durable state")?;
    let baseline_path = state_from_record
        .baseline_backup
        .as_deref()
        .context("registered local OCI candidate has no baseline backup")?;
    let baseline = Backup::open_existing(&config, baseline_path)?;
    let package = state
        .recovery_package
        .as_deref()
        .context("registered local OCI candidate has no recovery package")?;
    let package_sha256 = state_from_record
        .recovery_cache_sha256
        .as_deref()
        .context("registered local OCI candidate has no recovery package digest")?;
    if crate::filesystem::sha256(package)? != package_sha256 {
        bail!("registered local OCI candidate recovery package changed");
    }
    let package_value: serde_json::Value =
        serde_json::from_slice(&crate::filesystem::read_secure_regular_file(
            package,
            "local OCI candidate recovery package",
            true,
            128 * 1024,
        )?)?;
    if package_value
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
    {
        bail!("local OCI candidate recovery package has an unsupported schema");
    }
    let archive = package
        .parent()
        .context("local OCI candidate recovery package has no parent")?
        .join("image.tar");
    let archive_sha256 = package_value
        .get("archive_sha256")
        .and_then(serde_json::Value::as_str)
        .context("local OCI candidate recovery package has no archive digest")?;
    if state_from_record.recovery_archive_sha256.as_deref() != Some(archive_sha256)
        || crate::filesystem::sha256(&archive)? != archive_sha256
    {
        bail!("registered local OCI candidate recovery archive changed");
    }
    let dependency_archive =
        |name: &str, field: &str, expected_image: &str, expected_digest: Option<&str>| {
            let archive = package
                .parent()
                .context("local OCI candidate recovery package has no parent")?
                .join(name);
            let declared = package_value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("local OCI candidate recovery package has no {field}"))?;
            if expected_digest != Some(declared) || crate::filesystem::sha256(&archive)? != declared
            {
                bail!("registered local OCI candidate {name} archive changed");
            }
            Ok::<_, anyhow::Error>((archive, expected_image.to_owned()))
        };
    let (postgres_archive, postgres_image) = dependency_archive(
        "postgres-image.tar",
        "postgres_archive_sha256",
        &config.postgres.image,
        state_from_record
            .recovery_postgres_archive_sha256
            .as_deref(),
    )?;
    let (valkey_archive, valkey_image) = dependency_archive(
        "valkey-image.tar",
        "valkey_archive_sha256",
        &config.valkey.image,
        state_from_record.recovery_valkey_archive_sha256.as_deref(),
    )?;

    let runtime = Runtime::new(&config);
    if journal.phase < LocalOciCandidateRecoveryPhase::Quiesced {
        runtime.quiesce_local_oci_candidate()?;
        journal.phase = LocalOciCandidateRecoveryPhase::Quiesced;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    if journal.phase < LocalOciCandidateRecoveryPhase::Restored {
        runtime.import_image(&postgres_archive, &postgres_image)?;
        runtime.import_image(&valkey_archive, &valkey_image)?;
        install::start_managed_dependencies(&config)?;
        baseline.restore_databases(&config)?;
        baseline.restore_snapshots(&config.runtime.snapshot_paths)?;
        runtime.import_image(&archive, &state.local_artifact_id)?;
        crate::operator::append_management_event(
            &config,
            "local-oci-candidate-registered-restore",
            &state.candidate.target.release,
            "backup",
        )?;
        journal.phase = LocalOciCandidateRecoveryPhase::Restored;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    if journal.phase < LocalOciCandidateRecoveryPhase::Staged {
        // Both backups are made with the writer absent. The journal, rather
        // than the old completed state, owns this new immutable generation
        // until declaration CAS commits it.
        let rollback = Backup::create(config_path, &config, &state.candidate.target.release)?;
        let baseline = Backup::create(config_path, &config, &state.candidate.target.release)?;
        state.rollback_backup = Some(rollback.path().to_owned());
        state.baseline_backup = Some(baseline.path().to_owned());
        cache_local_oci_candidate_recovery_package(
            &config,
            &state.candidate,
            &state.local_artifact_id,
            &mut state,
            &format!("registered-recovery-{}", journal.generation),
        )?;
        journal.staged_state = Some(state.clone());
        journal.phase = LocalOciCandidateRecoveryPhase::Staged;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    state = journal
        .staged_state
        .clone()
        .context("staged local OCI candidate recovery has no durable state")?;
    // A crash after staging can coincide with loss of the runtime image
    // cache. Re-import the staged generation by immutable archive before the
    // active-image observation; import is idempotent and never pulls.
    let staged_archive = state
        .recovery_package
        .as_deref()
        .context("staged local OCI candidate recovery has no package")?
        .parent()
        .context("staged local OCI candidate recovery package has no parent")?
        .join("image.tar");
    runtime.import_image(&staged_archive, &state.local_artifact_id)?;
    let local = runtime.inspect_local_development_artifact(&state.local_artifact_id)?;
    let actual_digest = runtime.image_digest(&state.local_artifact_id)?;
    crate::controller::commands::validate_local_oci_candidate_observation(
        &state.candidate.target,
        &local.embedded,
        &state.local_artifact_id,
        &actual_digest,
    )?;
    if journal.phase < LocalOciCandidateRecoveryPhase::Accepted {
        runtime.activate_local_development_artifact(&local)?;
        wait_ready(&config)?;
        verify_public_local_oci_candidate(&config, &state.candidate.target)?;
        journal.phase = LocalOciCandidateRecoveryPhase::Accepted;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    if journal.phase < LocalOciCandidateRecoveryPhase::DeclarationCommitted {
        register_local_oci_candidate_deployment_locked(
            config_path,
            &config,
            &state.candidate,
            &state.local_artifact_id,
            state.rollback_backup.as_deref().expect("set above"),
            state.baseline_backup.as_deref().expect("set above"),
            state.recovery_package.as_deref().expect("set above"),
            state.recovery_archive_sha256.as_deref().expect("set above"),
            state.recovery_cache_sha256.as_deref().expect("set above"),
            Some(&record),
        )?;
        journal.phase = LocalOciCandidateRecoveryPhase::DeclarationCommitted;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    let record = DeploymentStore::system().load(&config.operator.deployment_id)?;
    verify_local_oci_candidate_completion_preconditions(
        &config,
        &record,
        &state.candidate,
        &state.local_artifact_id,
    )?;
    if journal.phase < LocalOciCandidateRecoveryPhase::StateCommitted {
        let management_event = crate::operator::append_management_event(
            &config,
            "local-oci-candidate-registered-recover",
            &state.candidate.target.release,
            "backup",
        )?;
        state.management_event_file = management_event
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned);
        state.management_event_sha256 = Some(crate::filesystem::sha256(&management_event)?);
        persist_local_oci_candidate_install_state(&config, &state)?;
        journal.staged_state = Some(state.clone());
        journal.phase = LocalOciCandidateRecoveryPhase::StateCommitted;
        write_local_oci_candidate_recovery_journal(&config, &journal)?;
    }
    validate_completed_local_oci_candidate_provenance(&config, &record)?;
    remove_file_durable(&local_oci_candidate_registered_recovery_journal_path(
        &config,
        journal.generation,
    )?)
}

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

fn verify_public_local_oci_candidate(
    config: &UpdateConfig,
    candidate: &CandidateTarget,
) -> anyhow::Result<()> {
    verify_public(config)?;
    crate::discovery::verify_public_candidate_control_identity(config, candidate)
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

    if config.dependencies.mode != "managed" {
        bail!(
            "local OCI candidate installation requires controller-managed PostgreSQL and Valkey dependencies"
        );
    }
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
            schema: 3,
            candidate: candidate.clone(),
            local_artifact_id: local_artifact_id.to_owned(),
            phase: LocalOciCandidatePhase::Prepared,
            attempt: 1,
            migration_jti: local_oci_candidate_task_jti(
                candidate,
                local_artifact_id,
                1,
                "migration",
            ),
            keys_jti: local_oci_candidate_task_jti(candidate, local_artifact_id, 1, "keys"),
            migration_receipt_sha256: None,
            keys_receipt_sha256: None,
            rollback_backup: None,
            baseline_backup: None,
            recovery_package: None,
            recovery_archive_sha256: None,
            recovery_cache_sha256: None,
            recovery_postgres_archive_sha256: None,
            recovery_valkey_archive_sha256: None,
            management_event_file: None,
            management_event_sha256: None,
            completed: false,
        },
    };
    if state.completed {
        validate_completed_local_oci_candidate_install(config_path, config, &state)?;
        let record = DeploymentStore::system().load(&config.operator.deployment_id)?;
        verify_local_oci_candidate_completion_preconditions(
            config,
            &record,
            &state.candidate,
            &state.local_artifact_id,
        )?;
        println!("NazoAuth local OCI candidate is already installed and ready");
        return Ok(());
    }

    // A started task without a durably recorded receipt is deliberately
    // unknown.  It is never replayed forward: stop the exact managed runtime,
    // restore the pre-mutation backup, rotate to a new backup and task JTI,
    // and only then start a new attempt.
    verify_local_oci_candidate_retry_preconditions(config, &state)?;

    let registration_recovery = ensure_local_oci_candidate_retry_is_unregistered(
        config,
        state.phase == LocalOciCandidatePhase::Registered,
    )?;
    if registration_recovery {
        return finish_local_oci_candidate_registration_recovery(
            config_path,
            config,
            candidate,
            local_artifact_id,
            &mut state,
        );
    }

    let expected = local_oci_candidate_expected_target(config, candidate)?;
    match state.phase {
        LocalOciCandidatePhase::MigrationStarted => {
            if let Some(receipt) = crate::operator::reconcile_final_receipt(
                config,
                &expected,
                &TaskOperation::MigrateApply,
                &state.migration_jti,
            )? {
                state.migration_receipt_sha256 =
                    Some(crate::filesystem::sha256(&receipt.final_receipt)?);
                state.phase = LocalOciCandidatePhase::MigrationApplied;
                persist_local_oci_candidate_install_state(config, &state)?;
            } else {
                recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
            }
        }
        LocalOciCandidatePhase::KeysStarted => {
            let operation = local_oci_candidate_keys_operation();
            if let Some(receipt) = crate::operator::reconcile_final_receipt(
                config,
                &expected,
                &operation,
                &state.keys_jti,
            )? {
                state.keys_receipt_sha256 =
                    Some(crate::filesystem::sha256(&receipt.final_receipt)?);
                state.phase = LocalOciCandidatePhase::KeysApplied;
                persist_local_oci_candidate_install_state(config, &state)?;
            } else {
                recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
            }
        }
        _ => {}
    }
    if !matches!(
        state.phase,
        LocalOciCandidatePhase::Prepared
            | LocalOciCandidatePhase::MigrationApplied
            | LocalOciCandidatePhase::KeysApplied
    ) {
        recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
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
    if state.rollback_backup.is_none() {
        let backup = Backup::create(config_path, config, &candidate.target.release)?;
        state.rollback_backup = Some(backup.path().to_owned());
        persist_local_oci_candidate_install_state(config, &state)?;
    }
    if state.phase == LocalOciCandidatePhase::Prepared {
        state.phase = LocalOciCandidatePhase::MigrationStarted;
        persist_local_oci_candidate_install_state(config, &state)?;
        let migration = crate::operator::execute_with_requested_jti(
            config,
            local_artifact_id,
            &expected,
            TaskOperation::MigrateApply,
            None,
            Some(&state.migration_jti),
        );
        let migration = match migration {
            Ok(result) => result,
            Err(error) => {
                recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
                return Err(error).context("local OCI candidate migration failed; managed state was restored and the next retry has a new task identity");
            }
        };
        state.migration_receipt_sha256 = Some(crate::filesystem::sha256(&migration.final_receipt)?);
        state.phase = LocalOciCandidatePhase::MigrationApplied;
        persist_local_oci_candidate_install_state(config, &state)?;
    }
    install::grant_runtime_database(config)?;
    if state.phase == LocalOciCandidatePhase::MigrationApplied {
        state.phase = LocalOciCandidatePhase::KeysStarted;
        persist_local_oci_candidate_install_state(config, &state)?;
        let keys = crate::operator::execute_with_requested_jti(
            config,
            local_artifact_id,
            &expected,
            local_oci_candidate_keys_operation(),
            None,
            Some(&state.keys_jti),
        );
        let keys = match keys {
            Ok(result) => result,
            Err(error) => {
                recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
                return Err(error).context("local OCI candidate key initialization failed; managed state was restored and the next retry has a new task identity");
            }
        };
        state.keys_receipt_sha256 = Some(crate::filesystem::sha256(&keys.final_receipt)?);
        state.phase = LocalOciCandidatePhase::KeysApplied;
        persist_local_oci_candidate_install_state(config, &state)?;
    }
    bootstrap_openid4vc_revocation_snapshot(config)?;
    state.phase = LocalOciCandidatePhase::RuntimeStarted;
    persist_local_oci_candidate_install_state(config, &state)?;
    if let Err(error) = (|| {
        runtime.activate_local_development_artifact(&local)?;
        wait_ready(config)?;
        verify_public_local_oci_candidate(config, &candidate.target)
    })() {
        recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
        return Err(error)
            .context("local OCI candidate runtime acceptance failed; managed state was restored");
    }

    // A baseline is written only while the application is absent.  This is
    // the package registered deployments use for their candidate-only
    // recovery transaction.
    runtime.quiesce_local_oci_candidate()?;
    let baseline = Backup::create(config_path, config, &candidate.target.release)?;
    state.baseline_backup = Some(baseline.path().to_owned());
    cache_local_oci_candidate_recovery_package(
        config,
        candidate,
        local_artifact_id,
        &mut state,
        &format!("install-attempt-{}", state.attempt),
    )?;
    state.phase = LocalOciCandidatePhase::BaselineCreated;
    persist_local_oci_candidate_install_state(config, &state)?;
    if let Err(error) = (|| {
        runtime.activate_local_development_artifact(&local)?;
        wait_ready(config)?;
        verify_public_local_oci_candidate(config, &candidate.target)
    })() {
        recover_local_oci_candidate_attempt(config_path, config, &mut state)?;
        return Err(error).context(
            "local OCI candidate post-baseline acceptance failed; managed state was restored",
        );
    }

    let backup = state
        .rollback_backup
        .as_deref()
        .context("local OCI candidate installation lost its recovery backup path")?;
    state.phase = LocalOciCandidatePhase::Registered;
    persist_local_oci_candidate_install_state(config, &state)?;
    register_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
        backup,
        state
            .baseline_backup
            .as_deref()
            .context("local OCI candidate installation lost its baseline backup")?,
        state
            .recovery_package
            .as_deref()
            .context("local OCI candidate installation lost its recovery package")?,
        state
            .recovery_archive_sha256
            .as_deref()
            .context("local OCI candidate installation lost its recovery archive digest")?,
        state
            .recovery_cache_sha256
            .as_deref()
            .context("local OCI candidate installation lost its recovery cache digest")?,
    )?;
    let store = DeploymentStore::system();
    // `register_local_oci_candidate_deployment` uses `persist_exact_locked`;
    // loading only after it returns is the exact-record proof needed before
    // this installation writes its completion audit/state.
    let record = store.load(&config.operator.deployment_id)?;
    verify_local_oci_candidate_completion_preconditions(
        config,
        &record,
        candidate,
        local_artifact_id,
    )?;
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
    state.phase = LocalOciCandidatePhase::Completed;
    state.completed = true;
    persist_local_oci_candidate_install_state(config, &state)?;
    validate_completed_local_oci_candidate_install(config_path, config, &state)?;
    println!(
        "NazoAuth local OCI candidate installed at {} ({})",
        candidate.target.release, candidate.target.revision
    );
    Ok(())
}

fn local_oci_candidate_task_jti(
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
    attempt: u64,
    operation: &str,
) -> String {
    let digest = Sha256::digest(
        serde_json::to_vec(&serde_json::json!({
            "candidate": candidate,
            "local_artifact_id": local_artifact_id,
            "attempt": attempt,
            "operation": operation,
        }))
        .expect("candidate task identity is serializable"),
    );
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("request-{suffix}")
}

fn local_oci_candidate_keys_operation() -> TaskOperation {
    TaskOperation::KeysGenerateLocal {
        alg: "ES256".to_owned(),
        purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
    }
}

fn local_oci_candidate_recovery_directory(
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    generation: &str,
) -> anyhow::Result<PathBuf> {
    let root = config
        .backup_root
        .parent()
        .context("candidate recovery root is unavailable")?;
    let digest = candidate
        .target
        .oci_digest
        .strip_prefix("sha256:")
        .context("candidate OCI digest is invalid")?;
    if generation.is_empty()
        || generation.len() > 128
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("local OCI candidate recovery generation is invalid");
    }
    // Recovery artifacts are immutable generations.  Sharing a digest-only
    // directory lets a later retry overwrite the archive referenced by a
    // previously durable state or declaration.
    Ok(root
        .join("local-oci-candidate-recovery")
        .join(&config.operator.deployment_id)
        .join(&config.runtime.runtime_instance_id)
        .join(digest)
        .join(generation))
}

fn local_oci_candidate_registered_recovery_journal_path(
    config: &UpdateConfig,
    generation: u64,
) -> anyhow::Result<PathBuf> {
    if generation == 0 {
        bail!("local OCI candidate registered recovery generation is invalid");
    }
    let root = config
        .backup_root
        .parent()
        .context("candidate recovery root is unavailable")?;
    Ok(root
        .join("local-oci-candidate-recovery-control")
        .join(&config.operator.deployment_id)
        .join(&config.runtime.runtime_instance_id)
        .join(format!("generation-{generation}.json")))
}

fn local_oci_candidate_record_sha256(record: &DeploymentRecord) -> anyhow::Result<String> {
    let digest = Sha256::digest(serde_json::to_vec(record)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn write_local_oci_candidate_recovery_journal(
    config: &UpdateConfig,
    journal: &LocalOciCandidateRecoveryJournal,
) -> anyhow::Result<()> {
    let path = local_oci_candidate_registered_recovery_journal_path(config, journal.generation)?;
    let parent = path
        .parent()
        .context("candidate recovery journal has no parent")?;
    crate::filesystem::ensure_directory_chain(parent)?;
    atomic_write(&path, &serde_json::to_vec_pretty(journal)?, 0o600)
}

fn load_local_oci_candidate_recovery_journal(
    config: &UpdateConfig,
    generation: u64,
) -> anyhow::Result<Option<LocalOciCandidateRecoveryJournal>> {
    let path = local_oci_candidate_registered_recovery_journal_path(config, generation)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("local OCI candidate recovery journal is not a regular file"),
        Err(error) => {
            return Err(error).context("failed to inspect local OCI candidate recovery journal");
        }
    }
    let journal: LocalOciCandidateRecoveryJournal =
        serde_json::from_slice(&crate::filesystem::read_secure_regular_file(
            &path,
            "local OCI candidate recovery journal",
            true,
            256 * 1024,
        )?)?;
    if journal.schema != 1
        || journal.generation != generation
        || journal.deployment_id != config.operator.deployment_id
        || journal.runtime_instance_id != config.runtime.runtime_instance_id
        || journal.expected_record_sha256.len() != 64
        || !journal
            .expected_record_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    {
        bail!("local OCI candidate recovery journal has an unsupported schema or binding");
    }
    Ok(Some(journal))
}

fn find_local_oci_candidate_recovery_journal(
    config: &UpdateConfig,
) -> anyhow::Result<Option<LocalOciCandidateRecoveryJournal>> {
    let root = config
        .backup_root
        .parent()
        .context("candidate recovery root is unavailable")?
        .join("local-oci-candidate-recovery-control")
        .join(&config.operator.deployment_id)
        .join(&config.runtime.runtime_instance_id);
    let entries = match fs::read_dir(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(entries) => entries,
        Err(error) => {
            return Err(error).context("failed to inspect candidate recovery journal root");
        }
    };
    let mut found = None;
    for entry in entries {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("candidate recovery journal root contains an unsafe entry");
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("candidate recovery journal name is not UTF-8")?;
        let Some(number) = name
            .strip_prefix("generation-")
            .and_then(|value| value.strip_suffix(".json"))
        else {
            bail!("candidate recovery journal root contains an unexpected entry");
        };
        let generation: u64 = number
            .parse()
            .context("candidate recovery journal generation is invalid")?;
        let journal = load_local_oci_candidate_recovery_journal(config, generation)?
            .context("candidate recovery journal disappeared during inspection")?;
        if found.replace(journal).is_some() {
            bail!("multiple candidate recovery journals are pending");
        }
    }
    Ok(found)
}

/// Write the exact local image to the independent recovery root before it is
/// declared recoverable.  The small package is digest-bound and contains no
/// secrets; database and filesystem material remains in the managed backup.
fn cache_local_oci_candidate_recovery_package(
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
    state: &mut LocalOciCandidateInstallState,
    generation: &str,
) -> anyhow::Result<()> {
    let directory = local_oci_candidate_recovery_directory(config, candidate, generation)?;
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!(
            "local OCI candidate recovery generation already exists; refusing to overwrite {}",
            directory.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect local OCI candidate recovery generation {}",
                    directory.display()
                )
            });
        }
    }
    crate::filesystem::ensure_directory_chain(&directory)?;
    let archive = directory.join("image.tar");
    let runtime = Runtime::new(config);
    runtime.export_image(local_artifact_id, &archive)?;
    let archive_sha256 = crate::filesystem::sha256(&archive)?;
    // A Proven package must also bootstrap the exact managed dependency
    // images. The package deliberately contains only image blobs and digest
    // bindings; passwords remain in their controller-owned secret files.
    let postgres_archive = directory.join("postgres-image.tar");
    runtime.export_image(&config.postgres.image, &postgres_archive)?;
    let postgres_archive_sha256 = crate::filesystem::sha256(&postgres_archive)?;
    let valkey_archive = directory.join("valkey-image.tar");
    runtime.export_image(&config.valkey.image, &valkey_archive)?;
    let valkey_archive_sha256 = crate::filesystem::sha256(&valkey_archive)?;
    let package = directory.join("package.json");
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": 2,
        "deployment_id": config.operator.deployment_id,
        "control_authority": config.operator.controller_key_id,
        "runtime_instance_id": config.runtime.runtime_instance_id,
        "candidate": candidate,
        "local_artifact_id": local_artifact_id,
        "archive": archive,
        "archive_sha256": archive_sha256,
        "postgres_image": config.postgres.image,
        "postgres_archive": postgres_archive,
        "postgres_archive_sha256": postgres_archive_sha256,
        "valkey_image": config.valkey.image,
        "valkey_archive": valkey_archive,
        "valkey_archive_sha256": valkey_archive_sha256,
    }))?;
    atomic_write(&package, &bytes, 0o600)?;
    state.recovery_package = Some(package);
    state.recovery_archive_sha256 = Some(archive_sha256);
    state.recovery_postgres_archive_sha256 = Some(postgres_archive_sha256);
    state.recovery_valkey_archive_sha256 = Some(valkey_archive_sha256);
    state.recovery_cache_sha256 = Some(crate::filesystem::sha256(
        state.recovery_package.as_deref().expect("set above"),
    )?);
    Ok(())
}

/// A candidate task that might have reached the runtime is never retried in
/// place.  The app is first proven absent, then the immutable managed backup
/// restores PostgreSQL, Valkey and every snapshot.  A fresh backup and fresh
/// request IDs fence the next attempt from both the old task and its restore
/// journal.
fn recover_local_oci_candidate_attempt(
    config_path: &Path,
    config: &UpdateConfig,
    state: &mut LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    let backup_path = state
        .rollback_backup
        .as_deref()
        .context("local OCI candidate recovery has no pre-mutation managed backup")?;
    // A Started phase has an uncertain runtime-side effect.  Its exact
    // durable JTI determines the only task object we may remove.  Quiesce it
    // before the application, and prove both absent before restoring managed
    // database/Valkey/snapshot state.  A normal `--rm` task absence is safe;
    // a label, CID, or engine-inspection mismatch is not.
    let runtime = Runtime::new(config);
    match state.phase {
        LocalOciCandidatePhase::MigrationStarted => {
            let identity = crate::operator::managed_one_shot_identity_for_task(
                config,
                &TaskOperation::MigrateApply,
                &state.migration_jti,
            )?;
            runtime.quiesce_managed_one_shot(&identity)?;
        }
        LocalOciCandidatePhase::KeysStarted => {
            let operation = local_oci_candidate_keys_operation();
            let identity = crate::operator::managed_one_shot_identity_for_task(
                config,
                &operation,
                &state.keys_jti,
            )?;
            runtime.quiesce_managed_one_shot(&identity)?;
        }
        _ => {}
    }
    runtime.quiesce_local_oci_candidate()?;
    let backup = Backup::open_existing(config, backup_path)?;
    backup.restore_databases(config)?;
    backup.restore_snapshots(&config.runtime.snapshot_paths)?;
    crate::operator::append_management_event(
        config,
        "local-oci-candidate-restore",
        &state.candidate.target.release,
        "backup",
    )?;
    state.attempt = state
        .attempt
        .checked_add(1)
        .context("local OCI candidate attempt counter overflow")?;
    state.migration_jti = local_oci_candidate_task_jti(
        &state.candidate,
        &state.local_artifact_id,
        state.attempt,
        "migration",
    );
    state.keys_jti = local_oci_candidate_task_jti(
        &state.candidate,
        &state.local_artifact_id,
        state.attempt,
        "keys",
    );
    state.migration_receipt_sha256 = None;
    state.keys_receipt_sha256 = None;
    state.phase = LocalOciCandidatePhase::Prepared;
    state.baseline_backup = None;
    state.recovery_package = None;
    state.recovery_archive_sha256 = None;
    state.recovery_cache_sha256 = None;
    state.recovery_postgres_archive_sha256 = None;
    state.recovery_valkey_archive_sha256 = None;
    // Do not reuse the backup whose restore journal has just been consumed.
    let backup = Backup::create(config_path, config, &state.candidate.target.release)?;
    state.rollback_backup = Some(backup.path().to_owned());
    persist_local_oci_candidate_install_state(config, state)
}

/// This is deliberately called before a retry can persist state, append audit
/// evidence, start dependencies, or replay an operator task.
pub(super) fn verify_local_oci_candidate_retry_preconditions(
    config: &UpdateConfig,
    state: &LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    if config.dependencies.mode != "managed" {
        bail!("local OCI candidate retry requires managed dependencies");
    }
    if let Some(backup) = state.rollback_backup.as_deref() {
        Backup::open_existing(config, backup)?;
    }
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
        .rollback_backup
        .as_deref()
        .context("local OCI candidate registration recovery has no durable backup")?;
    Backup::open_existing(config, backup)?;
    let baseline = state
        .baseline_backup
        .as_deref()
        .context("local OCI candidate registration recovery has no durable baseline")?;
    Backup::open_existing(config, baseline)?;
    let package = state
        .recovery_package
        .as_deref()
        .context("local OCI candidate registration recovery has no recovery package")?;
    let archive_sha256 = state
        .recovery_archive_sha256
        .as_deref()
        .context("local OCI candidate registration recovery has no recovery archive digest")?;
    let cache_sha256 = state
        .recovery_cache_sha256
        .as_deref()
        .context("local OCI candidate registration recovery has no recovery cache digest")?;
    register_local_oci_candidate_deployment(
        config_path,
        config,
        candidate,
        local_artifact_id,
        backup,
        baseline,
        package,
        archive_sha256,
        cache_sha256,
    )?;
    let store = DeploymentStore::system();
    let record = store.load(&config.operator.deployment_id)?;
    verify_local_oci_candidate_completion_preconditions(
        config,
        &record,
        candidate,
        local_artifact_id,
    )?;
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
    state.phase = LocalOciCandidatePhase::Completed;
    state.completed = true;
    persist_local_oci_candidate_install_state(config, state)?;
    validate_completed_local_oci_candidate_install(config_path, config, state)?;
    println!(
        "NazoAuth local OCI candidate registration recovery completed at {} ({})",
        candidate.target.release, candidate.target.revision
    );
    Ok(())
}

/// Completion is a second, post-registration trust boundary.  A registration
/// crash must not release the candidate's unsettled-state guard merely because
/// a declaration exists: the active object, immutable image identity, local
/// readiness, and public issuer must all still be exact.
fn verify_local_oci_candidate_completion_preconditions(
    config: &UpdateConfig,
    record: &DeploymentRecord,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
) -> anyhow::Result<()> {
    crate::controller::commands::validate_active_local_oci_candidate_runtime(
        record,
        config,
        &candidate.target,
        local_artifact_id,
    )?;
    wait_ready(config)?;
    verify_public_local_oci_candidate(config, &candidate.target)
}

fn validate_completed_local_oci_candidate_install(
    config_path: &Path,
    config: &UpdateConfig,
    state: &LocalOciCandidateInstallState,
) -> anyhow::Result<()> {
    if !state.completed {
        bail!("local OCI candidate completion validation requires completed state");
    }
    let record = validate_registered_local_oci_candidate_deployment(
        config_path,
        config,
        &state.candidate,
        &state.local_artifact_id,
    )?;
    validate_completed_local_oci_candidate_provenance(config, &record)
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
        schema: expected_existing.map_or(DEPLOYMENT_SCHEMA, |existing| existing.schema),
        deployment_id: expected_existing.map_or_else(
            || config.operator.deployment_id.clone(),
            |existing| existing.deployment_id.clone(),
        ),
        control_authority: expected_existing.map_or_else(
            || config.operator.controller_key_id.clone(),
            |existing| existing.control_authority.clone(),
        ),
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
    rollback_backup: &Path,
    baseline_backup: &Path,
    recovery_package: &Path,
    recovery_archive_sha256: &str,
    recovery_cache_sha256: &str,
) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&config.operator.deployment_id)?;
    register_local_oci_candidate_deployment_locked(
        config_path,
        config,
        candidate,
        local_artifact_id,
        rollback_backup,
        baseline_backup,
        recovery_package,
        recovery_archive_sha256,
        recovery_cache_sha256,
        None,
    )
}

fn register_local_oci_candidate_deployment_locked(
    config_path: &Path,
    config: &UpdateConfig,
    candidate: &LocalOciCandidateInstall,
    local_artifact_id: &str,
    rollback_backup: &Path,
    baseline_backup: &Path,
    recovery_package: &Path,
    recovery_archive_sha256: &str,
    recovery_cache_sha256: &str,
    expected_existing: Option<&DeploymentRecord>,
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
    // A registered recovery has no authority to reconstruct the declaration
    // from a mutable config file.  Its predecessor was reloaded under the
    // deployment lock; retain every non-recovery declaration field exactly
    // and replace only the newly staged recovery evidence below.
    let mut resources = match expected_existing {
        Some(existing) => existing.resources.clone(),
        None => installed_deployment_resources(config_path, config)?,
    };
    resources.insert(
        LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE.to_owned(),
        SafeReference::File {
            path: local_oci_candidate_install_resource_path(config),
        },
    );
    let baseline_manifest = baseline_backup.join("SHA256SUMS");
    let baseline_completion = baseline_backup.join("BACKUP-COMPLETE");
    let recovery_archive = recovery_package
        .parent()
        .context("local OCI candidate recovery package has no parent")?
        .join("image.tar");
    let recovery_package_value: serde_json::Value =
        serde_json::from_slice(&crate::filesystem::read_secure_regular_file(
            recovery_package,
            "local OCI candidate recovery package",
            true,
            128 * 1024,
        )?)?;
    if recovery_package_value
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
    {
        bail!("local OCI candidate recovery package has an unsupported schema");
    }
    let postgres_recovery_archive = recovery_package
        .parent()
        .context("local OCI candidate recovery package has no parent")?
        .join("postgres-image.tar");
    let postgres_recovery_digest = recovery_package_value
        .get("postgres_archive_sha256")
        .and_then(serde_json::Value::as_str)
        .context("local OCI candidate recovery package has no PostgreSQL archive digest")?;
    let valkey_recovery_archive = recovery_package
        .parent()
        .context("local OCI candidate recovery package has no parent")?
        .join("valkey-image.tar");
    let valkey_recovery_digest = recovery_package_value
        .get("valkey_archive_sha256")
        .and_then(serde_json::Value::as_str)
        .context("local OCI candidate recovery package has no Valkey archive digest")?;
    let baseline_manifest_sha256 = crate::filesystem::sha256(&baseline_manifest)?;
    let baseline_completion_sha256 = crate::filesystem::sha256(&baseline_completion)?;
    for (name, path, digest) in [
        (
            "candidate_recovery_package",
            recovery_package,
            recovery_cache_sha256,
        ),
        (
            "candidate_recovery_archive",
            &recovery_archive,
            recovery_archive_sha256,
        ),
        (
            "candidate_recovery_postgres_archive",
            &postgres_recovery_archive,
            postgres_recovery_digest,
        ),
        (
            "candidate_recovery_valkey_archive",
            &valkey_recovery_archive,
            valkey_recovery_digest,
        ),
        (
            "candidate_baseline_checksum_manifest",
            &baseline_manifest,
            &baseline_manifest_sha256,
        ),
        (
            "candidate_baseline_completion_marker",
            &baseline_completion,
            &baseline_completion_sha256,
        ),
    ] {
        resources.insert(
            name.to_owned(),
            SafeReference::DigestBoundFile {
                path: path.to_owned(),
                sha256: digest.to_owned(),
            },
        );
    }
    let record = DeploymentRecord {
        schema: DEPLOYMENT_SCHEMA,
        deployment_id: config.operator.deployment_id.clone(),
        control_authority: config.operator.controller_key_id.clone(),
        alias: expected_existing.and_then(|existing| existing.alias.clone()),
        issuer: expected_existing.map_or_else(
            || config.runtime.expected_issuer.clone(),
            |existing| existing.issuer.clone(),
        ),
        active_release: expected_existing.map_or_else(
            || nazo_operator_protocol::EmbeddedIdentity {
                release: candidate.target.release.clone(),
                revision: candidate.target.revision.clone(),
                protocol: nazo_operator_protocol::PROTOCOL_VERSION,
                build_id: candidate.target.build_id.clone(),
            },
            |existing| existing.active_release.clone(),
        ),
        trust: expected_existing.map_or(TrustState::Adopted, |existing| existing.trust),
        capabilities: expected_existing.map_or_else(
            || config.capabilities.clone(),
            |existing| existing.capabilities.clone(),
        ),
        runtime_instances: expected_existing.map_or_else(
            || {
                vec![RuntimeInstance {
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
                }]
            },
            |existing| existing.runtime_instances.clone(),
        ),
        resources,
        recovery: RecoveryAssessment {
            conclusion: RecoveryConclusion::Proven,
            evidence: vec![
                format!("rollback-backup:{}", rollback_backup.display()),
                format!("candidate-baseline:{}", baseline_backup.display()),
                format!("candidate-recovery-package:{}", recovery_package.display()),
                format!("local-oci-image-id:{local_artifact_id}"),
                format!("local-oci-digest:{}", candidate.target.oci_digest),
                format!("candidate-recovery-archive-sha256:{recovery_archive_sha256}"),
                format!("candidate-recovery-cache-sha256:{recovery_cache_sha256}"),
            ],
            off_host_package_required_for_machine_loss: true,
        },
        operator_protocol_versions: expected_existing.map_or_else(
            || BTreeSet::from([nazo_operator_protocol::PROTOCOL_VERSION]),
            |existing| existing.operator_protocol_versions.clone(),
        ),
        control_protocol_versions: expected_existing.map_or_else(
            || BTreeSet::from([1]),
            |existing| existing.control_protocol_versions.clone(),
        ),
        declaration_revision: expected_existing
            .map(|existing| {
                existing
                    .declaration_revision
                    .checked_add(1)
                    .context("local OCI candidate declaration revision overflow")
            })
            .transpose()?
            .unwrap_or(1),
    };
    let store = DeploymentStore::system();
    if let Some(expected) = expected_existing {
        // Registered recovery is a new declaration generation.  It must not
        // masquerade as a fresh exact persistence: the record loaded under
        // the deployment lock is the CAS predecessor and every rotated
        // baseline/package binding advances its revision exactly once.
        store.persist_declaration_cas_locked(expected, &record)
    } else {
        store.persist_exact_locked(&record)
    }
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
