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
    if config_path.exists() {
        let config = load_config(&config_path)?;
        config.require_managed_lifecycle()?;
        if install_is_complete(&config)? {
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
        let resume_version = options.version.or_else(|| {
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
    } = install::prepare(&config_path, options)?;
    let result = install_transaction(&config_path, &config, requested_version.as_deref());
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
    if !path.exists() {
        return Ok(false);
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
    serde_json::from_slice(&fs::read(install_completion_path(config))?)
        .context("managed installation completion marker is invalid")
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
        RuntimeInstance, SafeReference, TrustState,
    };
    use std::collections::{BTreeMap, BTreeSet};

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
    let resources = BTreeMap::from([
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
    ]);
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
            ports: vec![config.runtime.publish_address.clone()],
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
    if store.declaration_path(&record.deployment_id).exists() {
        let existing = store.load(&record.deployment_id)?;
        if existing.control_authority != record.control_authority
            || existing.issuer != record.issuer
            || existing.runtime_instances.first().map(|runtime| {
                (
                    &runtime.runtime_instance_id,
                    runtime.backend,
                    &runtime.object_reference,
                )
            }) != record.runtime_instances.first().map(|runtime| {
                (
                    &runtime.runtime_instance_id,
                    runtime.backend,
                    &runtime.object_reference,
                )
            })
        {
            bail!("installed deployment registry identity differs from the completed installation");
        }
        return Ok(());
    }
    store.persist(&record)
}
