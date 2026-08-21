use super::*;

const MAX_EXTERNAL_PUBLIC_JWK_BYTES: u64 = 1024 * 1024;

/// Read an external public JWK through one secure descriptor, hash those exact
/// bytes, and stage them under the declaration-bound operator state directory.
/// The runtime task receives only the staged path, so a caller cannot replace
/// the original path between validation, hashing, and execution.
fn stage_external_public_jwk(
    config: &UpdateConfig,
    source: &Path,
) -> anyhow::Result<(PathBuf, String)> {
    let file = crate::filesystem::open_secure_regular_file(source, "external public JWK", false)?;
    let mut bytes = Vec::new();
    file.take(MAX_EXTERNAL_PUBLIC_JWK_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read external public JWK {}", source.display()))?;
    if bytes.is_empty() {
        bail!("external public JWK must not be empty");
    }
    if bytes.len() as u64 > MAX_EXTERNAL_PUBLIC_JWK_BYTES {
        bail!("external public JWK exceeds the 1 MiB limit");
    }
    let state_directory = &config.operator.state_directory;
    let metadata = fs::symlink_metadata(state_directory).with_context(|| {
        format!(
            "failed to inspect operator state directory {}",
            state_directory.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("operator state directory is not a real directory");
    }
    let staged = state_directory.join(format!(".nazoauth-public-jwk-{}.jwk", uuid::Uuid::now_v7()));
    // The value is public key material; the runtime service identity must be
    // able to read it while the staged path remains confined to operator
    // state.  It is removed immediately after the task returns.
    atomic_write(&staged, &bytes, 0o444)?;
    Ok((staged, encode_controller_digest(&Sha256::digest(&bytes))))
}

pub(super) fn validate_local_development_identity(
    identity: &EmbeddedIdentity,
) -> anyhow::Result<()> {
    if identity.protocol != nazo_operator_protocol::PROTOCOL_VERSION {
        bail!(
            "local development artifact uses operator protocol {}, expected {}",
            identity.protocol,
            nazo_operator_protocol::PROTOCOL_VERSION
        );
    }
    if identity.revision.len() != 40
        || !identity
            .revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("local development artifact revision is not a full lowercase commit SHA");
    }
    if identity.build_id != format!("local:{}", identity.revision) {
        bail!("local development artifact build ID must be local:<full-revision>");
    }
    let version = identity
        .release
        .strip_prefix('v')
        .context("local development artifact release has no v prefix")?;
    let version = semver::Version::parse(version)
        .context("local development artifact release is not semantic")?;
    if version.pre.is_empty() {
        bail!("local development artifact release must use a unique prerelease version");
    }
    if !version.pre.as_str().contains(&identity.revision[..8]) {
        bail!("local development prerelease must contain the first eight revision characters");
    }
    Ok(())
}

pub(super) fn validate_local_oci_candidate_identity(
    candidate: &CandidateTarget,
    identity: &EmbeddedIdentity,
) -> anyhow::Result<()> {
    let expected = EmbeddedIdentity {
        release: candidate.release.clone(),
        revision: candidate.revision.clone(),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: candidate.build_id.clone(),
    };
    if identity.protocol != nazo_operator_protocol::PROTOCOL_VERSION || identity != &expected {
        bail!("local OCI candidate embedded identity does not match the exact candidate binding");
    }
    if candidate.build_id != format!("source:{}", candidate.revision) {
        bail!("local OCI candidate build ID must be source:<full-revision>");
    }
    Ok(())
}

pub(super) fn validate_local_oci_candidate_observation(
    candidate: &CandidateTarget,
    identity: &EmbeddedIdentity,
    local_artifact_id: &str,
    actual_oci_digest: &str,
) -> anyhow::Result<()> {
    validate_local_oci_candidate_identity(candidate, identity)?;
    if !local_artifact_id
        .strip_prefix("sha256:")
        .is_some_and(|value| {
            value.len() == 64
                && value.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        bail!("local OCI candidate did not resolve to an immutable local image ID");
    }
    if actual_oci_digest != candidate.oci_digest {
        bail!("local OCI candidate image digest does not match --candidate-oci-digest");
    }
    Ok(())
}

pub(super) fn is_local_oci_candidate_record(record: &DeploymentRecord) -> bool {
    record
        .resources
        .contains_key(crate::controller::deployment::LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE)
}

pub(super) fn validate_declared_local_artifact(
    record: &DeploymentRecord,
    config: &UpdateConfig,
) -> anyhow::Result<()> {
    let marker = record
        .resources
        .get(crate::controller::deployment::LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE);
    if marker.is_none() && record.active_release.build_id.starts_with("local:") {
        return validate_local_development_identity(&record.active_release);
    }
    let marker = marker
        .context("deployment does not declare an explicit local OCI candidate provenance marker")?;
    match marker {
        crate::deployment::SafeReference::File { path }
            if path
                == &crate::controller::deployment::local_oci_candidate_install_resource_path(
                    config,
                ) => {}
        _ => bail!("local OCI candidate provenance marker is not bound to the controller state"),
    }
    crate::controller::deployment::validate_completed_local_oci_candidate_provenance(
        config, record,
    )?;
    if !record.active_release.build_id.starts_with("source:") {
        bail!("local OCI candidate build ID is not source-bound");
    }
    if record.runtime_instances.len() != 1 || config.runtime.backend == RuntimeBackendKind::Systemd
    {
        bail!("local OCI candidate declaration must bind exactly one container runtime");
    }
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate declaration has no runtime")?;
    let crate::deployment::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &runtime.artifact
    else {
        bail!("local OCI candidate declaration has no OCI artifact");
    };
    if runtime.local_artifact_id.is_none()
        || !digest.strip_prefix("sha256:").is_some_and(|value| {
            value.len() == 64
                && value.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        bail!("local OCI candidate declaration is missing its immutable local artifact binding");
    }
    if runtime.local_artifact_id.as_deref() != Some(image_reference.as_str()) {
        bail!("local OCI candidate declaration does not bind its exact local image ID");
    }
    if record.active_release.revision.len() != 40
        || !record
            .active_release
            .revision
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        || !crate::model::semantic_tag(&record.active_release.release)
    {
        bail!("local OCI candidate declaration has an invalid release or full revision");
    }
    let candidate = CandidateTarget {
        release: record.active_release.release.clone(),
        revision: record.active_release.revision.clone(),
        build_id: record.active_release.build_id.clone(),
        oci_digest: digest.clone(),
    };
    validate_local_oci_candidate_identity(&candidate, &record.active_release)
}

/// Re-observe the running local OCI candidate immediately before an operation
/// treats its registered binding as complete.  The declaration check belongs
/// to the caller because registration recovery deliberately runs before the
/// durable state is marked complete.
pub(crate) fn validate_active_local_oci_candidate_runtime(
    record: &DeploymentRecord,
    config: &UpdateConfig,
    candidate: &CandidateTarget,
    expected_local_artifact_id: &str,
) -> anyhow::Result<crate::runtime::ActiveBuildTarget> {
    let active = Runtime::new(config).active_build_target()?;
    validate_active_local_oci_candidate_observation(
        record,
        config,
        candidate,
        expected_local_artifact_id,
        &active,
    )?;
    Ok(active)
}

pub(crate) fn validate_active_local_oci_candidate_observation(
    record: &DeploymentRecord,
    config: &UpdateConfig,
    candidate: &CandidateTarget,
    expected_local_artifact_id: &str,
    active: &crate::runtime::ActiveBuildTarget,
) -> anyhow::Result<()> {
    let declared_runtime = record
        .runtime_instances
        .first()
        .filter(|_| record.runtime_instances.len() == 1)
        .context("local OCI candidate deployment must bind exactly one runtime")?;
    if config.runtime.backend == RuntimeBackendKind::Systemd
        || declared_runtime.backend != config.runtime.backend
        || declared_runtime.object_reference != config.runtime.container_name
    {
        bail!("local OCI candidate runtime declaration does not match the active container");
    }
    let crate::deployment::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &declared_runtime.artifact
    else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    if record.active_release.release != candidate.release
        || record.active_release.revision != candidate.revision
        || record.active_release.build_id != candidate.build_id
        || declared_runtime.local_artifact_id.as_deref() != Some(expected_local_artifact_id)
        || image_reference != expected_local_artifact_id
        || digest != &candidate.oci_digest
    {
        bail!("local OCI candidate deployment differs from its exact persisted binding");
    }

    let active_local_artifact_id = active
        .local_artifact_id
        .as_deref()
        .context("active local OCI runtime exposes no immutable local image ID")?;
    if active_local_artifact_id != expected_local_artifact_id {
        bail!("active local OCI image ID differs from the deployment declaration");
    }
    validate_local_oci_candidate_observation(
        candidate,
        &active.embedded,
        active_local_artifact_id,
        &active.image_digest,
    )?;
    Ok(())
}

/// The completed-state caller first validates durable candidate provenance;
/// registration recovery instead supplies the exact pending state explicitly.
pub(crate) fn active_local_oci_candidate_build_target(
    record: &DeploymentRecord,
    config: &UpdateConfig,
) -> anyhow::Result<crate::runtime::ActiveBuildTarget> {
    validate_declared_local_artifact(record, config)?;
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate deployment has no runtime binding")?;
    let crate::deployment::ArtifactReference::Oci { digest, .. } = &runtime.artifact else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    let local_artifact_id = runtime
        .local_artifact_id
        .as_deref()
        .context("local OCI candidate deployment has no immutable local image ID")?;
    let candidate = CandidateTarget {
        release: record.active_release.release.clone(),
        revision: record.active_release.revision.clone(),
        build_id: record.active_release.build_id.clone(),
        oci_digest: digest.clone(),
    };
    validate_active_local_oci_candidate_runtime(record, config, &candidate, local_artifact_id)
}

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    let configured_path = cli.config.clone();
    let selector = cli.deployment.clone();
    match cli.command {
        Command::Discover => {
            let report = crate::discovery::discover()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Adopt(options) => {
            require_root()?;
            crate::adoption::run(options)
        }
        Command::DeploymentsList => list_deployments(),
        Command::TransactionShow => {
            let store = DeploymentStore::system();
            let record = store.resolve(selector.as_deref(), false)?;
            let transaction = crate::coordination::show(&store, &record)?;
            println!("{}", serde_json::to_string_pretty(&transaction)?);
            Ok(())
        }
        Command::TransactionEvidence { file, yes } => {
            require_root()?;
            require_confirmation(yes, "accept deployment-bound external step evidence")?;
            let store = DeploymentStore::system();
            let record = store.resolve(selector.as_deref(), true)?;
            super::reject_pending_local_oci_candidate_record(&record)?;
            super::reject_completed_local_oci_candidate_transition(&record)?;
            let transaction = crate::coordination::submit_evidence(&store, &record, &file)?;
            println!("{}", serde_json::to_string_pretty(&transaction)?);
            Ok(())
        }
        Command::TransactionResume {
            yes,
            accept_migration_barrier,
        } => {
            require_root()?;
            require_confirmation(yes, "resume the deployment-bound update transaction")?;
            let store = DeploymentStore::system();
            let record = store.resolve(selector.as_deref(), true)?;
            super::reject_pending_local_oci_candidate_record(&record)?;
            super::reject_completed_local_oci_candidate_transition(&record)?;
            let transaction = crate::coordination::resume(&store, &record)?;
            let current_record = store.load(&record.deployment_id)?;
            if matches!(
                transaction.state,
                crate::coordination::CoordinationState::ReadyForController
                    | crate::coordination::CoordinationState::Committed
            ) {
                let transaction = if current_record.resources.contains_key("lifecycle_contract") {
                    crate::lifecycle::execute_coordinated_update(
                        &store,
                        &current_record,
                        &transaction,
                    )?
                } else if current_record.resources.contains_key("controller_config") {
                    let context = control_config(
                        &configured_path,
                        selector.as_deref(),
                        &[
                            Capability::Runtime,
                            Capability::Artifact,
                            Capability::ServerConfig,
                            Capability::Database,
                            Capability::Valkey,
                            Capability::Backups,
                            Capability::OperatorTasks,
                        ],
                        true,
                        true,
                        true, // a resumed coordination may already own a config update journal
                    )?;
                    if transaction.state == crate::coordination::CoordinationState::Committed {
                        let current_record = context.record.as_ref().context(
                            "committed config-backed update lost its deployment declaration",
                        )?;
                        finalize_config_backed_update_locked(
                            &store,
                            current_record,
                            &transaction,
                            &context.path,
                        )?
                    } else {
                        let bound_record = context
                            .record
                            .as_ref()
                            .context("config-backed update lost its deployment declaration")?;
                        resume_config_backed_update_locked(
                            &store,
                            bound_record,
                            &transaction,
                            &context.path,
                            &context.config,
                            accept_migration_barrier,
                        )?
                    }
                } else {
                    bail!("update transaction has no executable lifecycle authority");
                };
                println!("{}", serde_json::to_string_pretty(&transaction)?);
                return Ok(());
            }
            println!("{}", serde_json::to_string_pretty(&transaction)?);
            Ok(())
        }
        Command::PermissionsSet(options) => {
            require_root()?;
            require_confirmation(options.yes, "change deployment capability grants")?;
            let store = DeploymentStore::system();
            let record = store.resolve(selector.as_deref(), true)?;
            super::reject_pending_local_oci_candidate_record(&record)?;
            crate::governance::set_permissions(cli.deployment.as_deref(), &options.changes)
        }
        Command::Relinquish(options) => {
            require_root()?;
            require_confirmation(
                options.yes,
                "relinquish deployment capabilities without deleting resources",
            )?;
            let store = DeploymentStore::system();
            let record = store.resolve(selector.as_deref(), true)?;
            super::reject_pending_local_oci_candidate_record(&record)?;
            crate::governance::relinquish(cli.deployment.as_deref(), &options.capabilities)
        }
        Command::Reconcile => crate::governance::reconcile(cli.deployment.as_deref()),
        Command::Install(options) => install(cli.config, *options),
        Command::Status => {
            let store = crate::deployment::DeploymentStore::system();
            match store.registry_present() {
                Ok(true) => {
                    let record = store.resolve(cli.deployment.as_deref(), false)?;
                    registered_status(&record, false)
                }
                Ok(false) => status(&load_config(&cli.config)?),
                Err(error) => {
                    let config = load_config_unsettled(&cli.config)?;
                    if deployment::local_oci_candidate_install_is_pending(&config)?
                        || deployment::local_oci_candidate_registered_recovery_is_pending(&config)?
                    {
                        return status(&config);
                    }
                    Err(error)
                }
            }
        }
        Command::Doctor => {
            let store = crate::deployment::DeploymentStore::system();
            match store.registry_present() {
                Ok(true) => {
                    let record = store.resolve(cli.deployment.as_deref(), false)?;
                    registered_status(&record, true)
                }
                Ok(false) => doctor(&load_config(&cli.config)?),
                Err(error) => {
                    let config = load_config_unsettled(&cli.config)?;
                    if deployment::local_oci_candidate_install_is_pending(&config)?
                        || deployment::local_oci_candidate_registered_recovery_is_pending(&config)?
                    {
                        return doctor(&config);
                    }
                    Err(error)
                }
            }
        }
        Command::BootstrapAdmin(options) => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(options.yes, "create the first NazoAuth administrator")?;
            bootstrap_admin(&context.config, options)
        }
        Command::Check(version) => {
            if DeploymentStore::system().registry_present()? {
                let record = DeploymentStore::system().resolve(selector.as_deref(), false)?;
                return registered_update_plan(
                    &record,
                    &UpdateOptions {
                        version,
                        plan: true,
                        yes: false,
                        accept_migration_barrier: false,
                    },
                );
            }
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[],
                false,
                false,
                false,
            )?;
            update(
                &context.path,
                &context.config,
                UpdateOptions {
                    version,
                    plan: true,
                    yes: false,
                    accept_migration_barrier: false,
                },
            )
        }
        Command::Update(options) => {
            if DeploymentStore::system().registry_present()? {
                let store = DeploymentStore::system();
                let record = store.resolve(selector.as_deref(), !options.plan)?;
                if options.plan {
                    registered_update_plan(&record, &options)
                } else {
                    require_root()?;
                    require_confirmation(
                        options.yes,
                        "prepare a deployment-bound update transaction",
                    )?;
                    super::reject_pending_local_oci_candidate_record(&record)?;
                    super::reject_completed_local_oci_candidate_transition(&record)?;
                    registered_update_prepare(&store, &record, &options)
                }
            } else {
                require_root()?;
                let required = [
                    Capability::Runtime,
                    Capability::Artifact,
                    Capability::ServerConfig,
                    Capability::Database,
                    Capability::Valkey,
                    Capability::Backups,
                ];
                let context = control_config(
                    &configured_path,
                    selector.as_deref(),
                    &required,
                    false,
                    false,
                    false,
                )?;
                update(&context.path, &context.config, options)
            }
        }
        Command::DevelopmentActivate(options) => {
            require_root()?;
            require_confirmation(
                options.yes,
                "replace the managed runtime with an unsigned local development artifact",
            )?;
            let store = DeploymentStore::system();
            if !store.registry_present()? {
                bail!("development activation requires a registered deployment");
            }
            let mut context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::Runtime, Capability::Artifact],
                false,
                false,
                false,
            )?;
            let record = context.record.clone().context(
                "development activation requires a declaration-bound controller context",
            )?;
            if record.runtime_instances.len() != 1 {
                bail!("development activation currently requires exactly one runtime instance");
            }
            if crate::coordination::active_update_exists(&store, &record) {
                bail!("development activation is forbidden while an update transaction is active");
            }
            let runtime = Runtime::new(&context.config);
            let target = runtime.inspect_local_development_artifact(&options.artifact)?;
            validate_local_development_identity(&target.embedded)?;
            crate::controller::updates::persist_tenant_resource_controller_runtime_upgrade(
                &context.path,
                &mut context.config,
            )?;
            let runtime = Runtime::new(&context.config);
            crate::lifecycle::cache_trusted_runtime(&store, &record)?;
            runtime.activate_local_development_artifact(&target)?;
            let mut updated = record.clone();
            updated.active_release = target.embedded.clone();
            let declared = updated
                .runtime_instances
                .first_mut()
                .context("registered deployment has no runtime instance")?;
            if declared.runtime_instance_id != context.config.runtime.runtime_instance_id {
                bail!("registered runtime does not match the controller configuration");
            }
            declared.artifact = target.declared_artifact.clone();
            declared.local_artifact_id = target.local_artifact_id.clone();
            declared.ports = (!context.config.runtime.publish_address.is_empty())
                .then(|| context.config.runtime.publish_address.clone())
                .into_iter()
                .collect();
            declared.networks = (!context.config.runtime.network.is_empty())
                .then(|| context.config.runtime.network.clone())
                .into_iter()
                .collect();
            declared.mounts = context
                .config
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
                .collect();
            let artifact = declared.artifact.clone();
            let local_artifact_id = declared.local_artifact_id.clone();
            updated.declaration_revision = record
                .declaration_revision
                .checked_add(1)
                .context("deployment declaration revision overflow")?;
            let request_id = format!("development-{:020}", updated.declaration_revision);
            crate::governance::prepare_management_audit_intent(
                &store,
                &record,
                &updated,
                &request_id,
                "local-development-activation",
                &updated.active_release.release,
                "controller-state",
            )?;
            store.persist_declaration_cas_locked(&record, &updated)?;
            crate::governance::mark_management_audit_intent_committed(&store, &updated)?;
            crate::governance::append_management_audit(
                &store,
                &updated,
                &request_id,
                "local-development-activation",
                &updated.active_release.release,
            )?;
            crate::governance::finish_management_audit_intent(&store, &updated.deployment_id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "mode": "development-local",
                    "deployment_id": updated.deployment_id,
                    "active_release": updated.active_release,
                    "artifact": artifact,
                    "local_artifact_id": local_artifact_id,
                    "migrations_applied": false,
                    "release_trust_updated": false,
                }))?
            );
            Ok(())
        }
        Command::Rollback { yes } => {
            require_root()?;
            if DeploymentStore::system().registry_present()? {
                let store = DeploymentStore::system();
                let record = store.resolve(selector.as_deref(), true)?;
                if is_local_oci_candidate_record(&record) {
                    bail!(
                        "local OCI candidates are frozen; use nazoauthctl recover --yes for their dedicated managed recovery transaction"
                    );
                }
                require_registered_recovery_authority(
                    "rollback",
                    crate::coordination::active_update_exists(&store, &record),
                    record.resources.contains_key("lifecycle_contract"),
                    record.resources.contains_key("controller_config"),
                )?;
                if record.resources.contains_key("lifecycle_contract") {
                    require_confirmation(
                        yes,
                        "rollback the deployment runtimes to the cached previous trusted Release without restoring provider data",
                    )?;
                    return crate::lifecycle::rollback_registered(&store, &record);
                }
                unreachable!("registered rollback authority guard returned without a lifecycle");
            }
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[
                    Capability::Runtime,
                    Capability::Artifact,
                    Capability::Backups,
                ],
                false,
                false,
                false,
            )?;
            require_confirmation(
                yes,
                "rollback the application artifact without restoring the database",
            )?;
            public_rollback(&context.config)
        }
        Command::Recover { yes } => {
            require_root()?;
            if DeploymentStore::system().registry_present()? {
                let store = DeploymentStore::system();
                let record = store.resolve(selector.as_deref(), true)?;
                if is_local_oci_candidate_record(&record) {
                    require_confirmation(
                        yes,
                        "restore the exact local OCI candidate from its controller-managed baseline and recovery package",
                    )?;
                    record.require_mutation(&[
                        Capability::Runtime,
                        Capability::Artifact,
                        Capability::Database,
                        Capability::Valkey,
                        Capability::Backups,
                        Capability::OperatorTasks,
                    ])?;
                    let path = match record.resources.get("controller_config") {
                        Some(crate::deployment::SafeReference::File { path }) => path,
                        _ => {
                            bail!("registered local OCI candidate has no controller configuration")
                        }
                    };
                    let config = load_config_unsettled(path)?;
                    super::verify_control_binding(&record, &config)?;
                    return super::deployment::recover_registered_local_oci_candidate(
                        path, &config, &record,
                    );
                }
                require_registered_recovery_authority(
                    "recovery",
                    crate::coordination::active_update_exists(&store, &record),
                    record.resources.contains_key("lifecycle_contract"),
                    record.resources.contains_key("controller_config"),
                )?;
                if record.resources.contains_key("lifecycle_contract") {
                    require_confirmation(
                        yes,
                        "execute the deployment-bound offline recovery contract and activate the cached trusted runtime",
                    )?;
                    return crate::lifecycle::recover_registered(&store, &record);
                }
                unreachable!("registered recovery authority guard returned without a lifecycle");
            }
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[
                    Capability::Runtime,
                    Capability::Artifact,
                    Capability::Database,
                    Capability::Valkey,
                    Capability::Backups,
                ],
                false,
                true,
                false,
            )?;
            require_confirmation(
                yes,
                "restore the declared database backup and previous application artifact",
            )?;
            recover_from_backup(&context.config)
        }
        Command::RecoverUpdate { yes } => {
            require_root()?;
            if DeploymentStore::system().registry_present()? {
                let store = DeploymentStore::system();
                let record = store.resolve(selector.as_deref(), true)?;
                require_confirmation(
                    yes,
                    "resume the deployment-bound interrupted update transaction",
                )?;
                let transaction = crate::coordination::resume(&store, &record)?;
                let current_record = store.load(&record.deployment_id)?;
                let transaction = if current_record.resources.contains_key("lifecycle_contract") {
                    crate::lifecycle::execute_coordinated_update(
                        &store,
                        &current_record,
                        &transaction,
                    )?
                } else if current_record.resources.contains_key("controller_config") {
                    let context = control_config(
                        &configured_path,
                        selector.as_deref(),
                        &[
                            Capability::Runtime,
                            Capability::Artifact,
                            Capability::ServerConfig,
                            Capability::Database,
                            Capability::Valkey,
                            Capability::Backups,
                            Capability::OperatorTasks,
                        ],
                        true,
                        true,
                        true, // recovery must load the config that owns the interrupted journal
                    )?;
                    if transaction.state == crate::coordination::CoordinationState::Committed {
                        let current_record = context.record.as_ref().context(
                            "committed config-backed update lost its deployment declaration",
                        )?;
                        finalize_config_backed_update_locked(
                            &store,
                            current_record,
                            &transaction,
                            &context.path,
                        )?
                    } else {
                        let bound_record = context
                            .record
                            .as_ref()
                            .context("config-backed update lost its deployment declaration")?;
                        let legacy_recovery_pending =
                            load_update_journal(&context.config)?.is_some();
                        if legacy_recovery_pending
                            || matches!(
                                transaction.state,
                                crate::coordination::CoordinationState::Aborting
                                    | crate::coordination::CoordinationState::Aborted
                            )
                        {
                            let transaction =
                                crate::coordination::mark_controller_update_aborting_locked(
                                    &store,
                                    bound_record,
                                    &transaction.transaction_id,
                                )?;
                            if legacy_recovery_pending {
                                recover_pending_update(&context.path, &context.config)?;
                            }
                            let current_record = store.reload_locked(bound_record)?;
                            crate::coordination::abort_controller_update_locked(
                                &store,
                                &current_record,
                                &transaction.transaction_id,
                            )?
                        } else {
                            resume_config_backed_update_locked(
                                &store,
                                bound_record,
                                &transaction,
                                &context.path,
                                &context.config,
                                true,
                            )?
                        }
                    }
                } else {
                    bail!("registered update recovery has no executable lifecycle authority");
                };
                println!("{}", serde_json::to_string_pretty(&transaction)?);
                return Ok(());
            }
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[
                    Capability::Runtime,
                    Capability::Artifact,
                    Capability::Database,
                    Capability::Valkey,
                    Capability::Backups,
                ],
                false,
                true,
                true,
            )?;
            if crate::operator::identity_recovery_required(&context.config)? {
                bail!("identity recovery is pending; run nazoauthctl recover-identity --yes first");
            }
            let journal = load_update_journal(&context.config)?
                .context("no interrupted update transaction requires recovery")?;
            require_confirmation(
                yes,
                &format!(
                    "recover update transaction {} from phase {:?}",
                    journal.transaction_id, journal.phase
                ),
            )?;
            recover_pending_update(&context.path, &context.config)?;
            load_config(&context.path).map(|_| ())
        }
        Command::RecoverIdentity { yes } => {
            require_root()?;
            let mut context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                true,
            )?;
            ensure_no_pending_update(&context.config)?;
            if !crate::operator::identity_recovery_required(&context.config)? {
                bail!("no interrupted identity transition requires recovery");
            }
            require_confirmation(yes, "recover the interrupted identity transition")?;
            crate::operator::recover_pending_rotation(&context.path, &mut context.config)?;
            load_config(&context.path).map(|_| ())
        }
        Command::Migrate { yes, candidate } => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::Database, Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(yes, "apply pending database migrations")?;
            if let Some(candidate) = candidate.as_ref() {
                candidate_app_command(&context.config, TaskOperation::MigrateApply, candidate)?;
                install::grant_runtime_database(&context.config)
            } else {
                app_command(&context.config, TaskOperation::MigrateApply, None)
            }
        }
        Command::Keys(command) => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            let (operation, staged_public_jwk) = match command {
                KeysCommand::List => (TaskOperation::KeysList, None),
                KeysCommand::Validate => (TaskOperation::KeysValidate, None),
                KeysCommand::ExportOpenid4vcTrust { output } => {
                    return export_openid4vc_trust(&context.config, &output);
                }
                KeysCommand::GenerateLocal { alg, purposes, yes } => {
                    require_confirmation(yes, "mutate the application signing keyset")?;
                    (TaskOperation::KeysGenerateLocal { alg, purposes }, None)
                }
                KeysCommand::RegisterExternal {
                    kid,
                    alg,
                    key_ref,
                    public_jwk,
                    yes,
                } => {
                    require_confirmation(yes, "mutate the application signing keyset")?;
                    let (staged, public_jwk_sha256) =
                        stage_external_public_jwk(&context.config, &public_jwk)?;
                    (
                        TaskOperation::KeysRegisterExternal {
                            kid,
                            alg,
                            key_ref,
                            public_jwk_sha256,
                        },
                        Some(staged),
                    )
                }
            };
            let result = app_command(&context.config, operation, staged_public_jwk.as_deref());
            if let Some(path) = staged_public_jwk {
                let cleanup = remove_file_durable(&path);
                if let Err(error) = cleanup
                    && result.is_ok()
                {
                    return Err(error).context("failed to remove staged external public JWK");
                }
            }
            result
        }
        Command::Tls(command) => crate::tls::run(
            selector.as_deref(),
            command,
            require_root,
            require_confirmation,
        ),
        Command::AuditVerify => {
            if let Some((store, record, config)) = registered_audit_context(selector.as_deref())? {
                let (governance_sequence, governance_head) =
                    crate::governance::verify_management_audit(&store, &record)?;
                let operator = config
                    .as_ref()
                    .map(crate::operator::verify_audit_chain)
                    .transpose()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema": 1,
                        "deployment_id": record.deployment_id,
                        "governance": {
                            "verified": true,
                            "events": governance_sequence,
                            "head": governance_head,
                        },
                        "operator": operator.map(|(sequence, head)| json!({
                            "verified": true,
                            "receipts": sequence,
                            "head": head,
                        })),
                    }))?
                );
                Ok(())
            } else {
                let context = control_config(
                    &configured_path,
                    selector.as_deref(),
                    &[],
                    false,
                    false,
                    false,
                )?;
                crate::operator::verify_audit(&context.config)
            }
        }
        Command::AuditShow { request_id } => {
            if let Some((store, record, config)) = registered_audit_context(selector.as_deref())? {
                let governance = crate::governance::management_audit_entries(
                    &store,
                    &record,
                    request_id.as_deref(),
                )?;
                let operator = config
                    .as_ref()
                    .map(|config| crate::operator::audit_entries(config, request_id.as_deref()))
                    .transpose()?
                    .unwrap_or_default();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema": 1,
                        "deployment_id": record.deployment_id,
                        "governance": governance,
                        "operator": operator,
                    }))?
                );
                Ok(())
            } else {
                let context = control_config(
                    &configured_path,
                    selector.as_deref(),
                    &[],
                    false,
                    false,
                    false,
                )?;
                crate::operator::show_audit(&context.config, request_id.as_deref())
            }
        }
        Command::IdentityRotate { yes } => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(yes, "rotate the controller identity")?;
            let rotation = if let Some(record) = context.record.as_ref() {
                crate::operator::rotate_registered_controller(
                    &DeploymentStore::system(),
                    record,
                    &context.path,
                    &context.config,
                    false,
                    "normal",
                )?
            } else {
                crate::operator::rotate_controller(&context.path, &context.config, false, "normal")?
            };
            let current = load_config(&context.path)?;
            let release = load_active_release(&current)?;
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
        Command::BreakGlassControllerAvailability => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[],
                false,
                false,
                false,
            )?;
            crate::operator::report_controller_availability(&context.config).map(|_| ())
        }
        Command::BreakGlassRehearseControllerLoss { yes } => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(
                yes,
                "rehearse controller-key loss with a simulated unavailable file provider",
            )?;
            let rotation = if let Some(record) = context.record.as_ref() {
                crate::operator::rehearse_registered_controller_loss(
                    &DeploymentStore::system(),
                    record,
                    &context.path,
                    &context.config,
                )?
            } else {
                crate::operator::rehearse_controller_loss(&context.path, &context.config)?
            };
            let current = load_config(&context.path)?;
            let release = load_active_release(&current)?;
            crate::operator::append_management_event(
                &current,
                "break-glass-controller-loss-rehearsal",
                &release.version,
                "simulated-unavailable:file-provider-only:copied-key-status-not-provable",
            )?;
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
        Command::BreakGlassRecover { yes, reason } => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(yes, "perform break-glass controller recovery")?;
            let rotation = if let Some(record) = context.record.as_ref() {
                crate::operator::recover_registered_controller_without_controller_key(
                    &DeploymentStore::system(),
                    record,
                    &context.path,
                    &context.config,
                    &reason,
                )?
            } else {
                crate::operator::recover_controller_without_controller_key(
                    &context.path,
                    &context.config,
                    &reason,
                )?
            };
            let current = load_config(&context.path)?;
            let release = load_active_release(&current)?;
            if reason == "lost" {
                crate::operator::append_management_event(
                    &current,
                    "break-glass-loss-assumption",
                    &release.version,
                    "file-provider-unavailability-not-proven",
                )?;
            } else {
                crate::operator::append_management_event(
                    &current,
                    "break-glass-stolen-assumption",
                    &release.version,
                    "copied-key-risk-assumed:file-provider-cannot-prove-non-copy",
                )?;
            }
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
        Command::SelfCheck(version) => controller_check(version.as_deref()),
        Command::SelfUpdate { version, yes } => {
            require_root()?;
            require_confirmation(yes, "replace nazoauthctl with a signed controller Release")?;
            controller_update(version.as_deref())
        }
        Command::SelfRollback { yes } => {
            require_root()?;
            require_confirmation(yes, "restore the previous signed nazoauthctl binary")?;
            controller_rollback()
        }
    }
}

fn require_registered_recovery_authority(
    operation: &str,
    active_update: bool,
    has_lifecycle_contract: bool,
    has_controller_config: bool,
) -> anyhow::Result<()> {
    if active_update {
        bail!(
            "registered {operation} is forbidden while an update transaction is active; resume or recover the deployment-bound transaction first"
        );
    }
    if has_lifecycle_contract {
        return Ok(());
    }
    if has_controller_config {
        bail!(
            "registered config-backed {operation} is not implemented as a deployment transaction; refusing to use the legacy mutator because it cannot update the DeploymentRecord atomically"
        );
    }
    bail!("registered {operation} has no approved lifecycle authority")
}

/// Select a registered deployment once for audit inspection.  The returned
/// declaration is the same snapshot used to derive the optional bound
/// operator configuration; AuditVerify/AuditShow never resolve the selector a
/// second time and never mutate either chain.
fn registered_audit_context(
    selector: Option<&str>,
) -> anyhow::Result<Option<(DeploymentStore, DeploymentRecord, Option<UpdateConfig>)>> {
    let store = DeploymentStore::system();
    if !store.registry_present()? {
        return Ok(None);
    }
    let record = store.resolve(selector, false)?;
    let config = match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) => {
            let config = crate::controller::load_bound_control_config(path)?;
            if config.operator.deployment_id != record.deployment_id
                || config.operator.controller_key_id != record.control_authority
            {
                bail!("controller configuration is bound to a different deployment authority");
            }
            Some(config)
        }
        Some(_) => bail!("controller configuration resource is not a regular file reference"),
        None => None,
    };
    Ok(Some((store, record, config)))
}

#[cfg(test)]
mod development_identity_tests {
    use super::*;

    fn identity() -> EmbeddedIdentity {
        let revision = "52bca844beac0889d82f138cde1e48f8ce4e06e4".to_owned();
        EmbeddedIdentity {
            release: "v0.1.28-dev.52bca844".to_owned(),
            build_id: format!("local:{revision}"),
            revision,
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        }
    }

    #[test]
    fn local_development_identity_is_bound_to_revision_and_prerelease() {
        validate_local_development_identity(&identity()).unwrap();

        let mut wrong_build = identity();
        wrong_build.build_id = format!("local:{}", "a".repeat(40));
        assert!(validate_local_development_identity(&wrong_build).is_err());

        let mut signed_release = identity();
        signed_release.release = "v0.1.28".to_owned();
        assert!(validate_local_development_identity(&signed_release).is_err());

        let mut unrelated_prerelease = identity();
        unrelated_prerelease.release = "v0.1.28-dev.unrelated".to_owned();
        assert!(validate_local_development_identity(&unrelated_prerelease).is_err());
    }

    #[test]
    fn registered_recovery_never_falls_back_to_legacy_mutation() {
        for operation in ["rollback", "recovery"] {
            let active =
                require_registered_recovery_authority(operation, true, true, false).unwrap_err();
            assert!(active.to_string().contains("transaction is active"));

            let config_backed =
                require_registered_recovery_authority(operation, false, false, true).unwrap_err();
            assert!(config_backed.to_string().contains("legacy mutator"));

            let unbound =
                require_registered_recovery_authority(operation, false, false, false).unwrap_err();
            assert!(
                unbound
                    .to_string()
                    .contains("no approved lifecycle authority")
            );

            require_registered_recovery_authority(operation, false, true, false).unwrap();
        }
    }
}
