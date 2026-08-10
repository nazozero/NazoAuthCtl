use super::*;
pub(crate) fn conformance_operation(
    command: ConformanceLeaseCommand,
) -> anyhow::Result<TaskOperation> {
    Ok(match command {
        ConformanceLeaseCommand::Create {
            profile,
            material,
            dynamic_registration_token_file,
            ciba_automated_decision_token_file,
            ttl_seconds,
            yes,
        } => {
            require_confirmation(yes, "create a temporary conformance lease")?;
            let (material_sha256, material_bytes) =
                read_conformance_material(&material, profile == "openid4vc")?;
            let dynamic_registration_initial_access_token_sha256 = if let Some(path) =
                dynamic_registration_token_file
            {
                if profile != "oidc-fapi-ciba" {
                    bail!(
                        "--dynamic-registration-token-file is supported only for the oidc-fapi-ciba profile"
                    );
                }
                Some(read_conformance_token_sha256(&path)?)
            } else {
                None
            };
            let ciba_automated_decision_token_sha256 = if let Some(path) =
                ciba_automated_decision_token_file
            {
                if profile != "oidc-fapi-ciba" {
                    bail!(
                        "--ciba-automated-decision-token-file is supported only for the oidc-fapi-ciba profile"
                    );
                }
                Some(read_conformance_token_sha256(&path)?)
            } else {
                None
            };
            let public_material = if profile == "openid4vc" {
                Some(
                    serde_json::from_slice::<nazo_operator_protocol::Openid4vcConformanceTrust>(
                        material_bytes
                            .as_deref()
                            .context("OpenID4VC conformance material was not retained")?,
                    )
                    .context("OpenID4VC conformance material must be strict JSON")?,
                )
            } else {
                None
            };
            TaskOperation::ConformanceLeaseCreate {
                profile,
                material_sha256,
                public_material,
                dynamic_registration_initial_access_token_sha256,
                ciba_automated_decision_token_sha256,
                ttl_seconds,
            }
        }
        ConformanceLeaseCommand::List => TaskOperation::ConformanceLeaseList,
        ConformanceLeaseCommand::Revoke { lease_id, yes } => {
            require_confirmation(
                yes,
                "revoke the conformance lease and deactivate its clients",
            )?;
            TaskOperation::ConformanceLeaseRevoke { lease_id }
        }
        ConformanceLeaseCommand::Cleanup { yes } => {
            require_confirmation(yes, "delete revoked and expired conformance clients")?;
            TaskOperation::ConformanceLeaseCleanup
        }
    })
}

const MAX_CONFORMANCE_TOKEN_FILE_BYTES: u64 = 4096;
const MAX_CONFORMANCE_MATERIAL_BYTES: u64 = 4 * 1024 * 1024;

const MAX_EXTERNAL_PUBLIC_JWK_BYTES: u64 = 1024 * 1024;

fn read_conformance_material(
    path: &Path,
    retain_bytes: bool,
) -> anyhow::Result<(String, Option<Vec<u8>>)> {
    let mut file =
        crate::filesystem::open_secure_regular_file(path, "conformance material", false)?;
    let mut digest = Sha256::new();
    let mut retained = if retain_bytes { Some(Vec::new()) } else { None };
    let mut buffer = [0_u8; 8192];
    let mut total = 0_usize;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read conformance material {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total.saturating_add(read);
        if total as u64 > MAX_CONFORMANCE_MATERIAL_BYTES {
            bail!(
                "conformance material exceeds the {} MiB limit",
                MAX_CONFORMANCE_MATERIAL_BYTES / (1024 * 1024)
            );
        }
        if let Some(bytes) = retained.as_mut() {
            if total > 32 * 1024 {
                bail!(
                    "OpenID4VC conformance material must be a regular file from 1 through 32768 bytes"
                );
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    if total == 0 {
        bail!("conformance material must not be empty");
    }
    Ok((encode_controller_digest(&digest.finalize()), retained))
}

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

fn read_conformance_token_sha256(path: &Path) -> anyhow::Result<String> {
    let file = crate::filesystem::open_secure_regular_file(path, "conformance token file", true)?;
    let opened_metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened conformance token file {}",
            path.display()
        )
    })?;
    validate_conformance_token_metadata(&opened_metadata)?;

    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONFORMANCE_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read conformance token file {}", path.display()))?;
    if bytes.is_empty() {
        bail!("conformance token file must not be empty");
    }
    if bytes.len() as u64 > MAX_CONFORMANCE_TOKEN_FILE_BYTES {
        bail!(
            "conformance token file exceeds the {} byte limit",
            MAX_CONFORMANCE_TOKEN_FILE_BYTES
        );
    }
    Ok(encode_controller_digest(&Sha256::digest(bytes.as_slice())))
}

#[cfg(unix)]
fn validate_conformance_token_metadata(metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let current_uid = Process::new("id")
        .arg("-u")
        .stdout()?
        .trim()
        .parse::<u32>()
        .context("current process has no valid numeric UID")?;
    if metadata.uid() != 0 && metadata.uid() != current_uid {
        bail!("conformance token file has an unexpected owner");
    }
    if metadata.nlink() != 1 {
        bail!("conformance token file must have exactly one hard link");
    }
    let mode = metadata.mode() & 0o7777;
    if mode & !0o600 != 0 || mode & 0o400 == 0 {
        bail!("conformance token file permissions must be 0400 or 0600");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_conformance_token_metadata(_metadata: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
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
            let transaction = crate::coordination::resume(&store, &record)?;
            if transaction.state == crate::coordination::CoordinationState::ReadyForController {
                let transaction = if record.resources.contains_key("lifecycle_contract") {
                    crate::lifecycle::execute_coordinated_update(&store, &record, &transaction)?
                } else if record.resources.contains_key("controller_config") {
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
                        false,
                    )?;
                    resume_config_backed_update_locked(
                        &store,
                        &record,
                        &transaction,
                        &context.path,
                        &context.config,
                        accept_migration_barrier,
                    )?
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
            crate::governance::set_permissions(cli.deployment.as_deref(), &options.changes)
        }
        Command::Relinquish(options) => {
            require_root()?;
            require_confirmation(
                options.yes,
                "relinquish deployment capabilities without deleting resources",
            )?;
            crate::governance::relinquish(cli.deployment.as_deref(), &options.capabilities)
        }
        Command::Reconcile => crate::governance::reconcile(cli.deployment.as_deref()),
        Command::Install(options) => install(cli.config, *options),
        Command::Status => {
            if crate::deployment::DeploymentStore::system().registry_present()? {
                let record = crate::deployment::DeploymentStore::system()
                    .resolve(cli.deployment.as_deref(), false)?;
                return registered_status(&record, false);
            }
            let config = load_config(&cli.config)?;
            status(&config)
        }
        Command::Doctor => {
            if crate::deployment::DeploymentStore::system().registry_present()? {
                let record = crate::deployment::DeploymentStore::system()
                    .resolve(cli.deployment.as_deref(), false)?;
                return registered_status(&record, true);
            }
            let config = load_config(&cli.config)?;
            doctor(&config)
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
            let context = control_config(
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
                if record.resources.contains_key("lifecycle_contract") {
                    require_confirmation(
                        yes,
                        "rollback the deployment runtimes to the cached previous trusted Release without restoring provider data",
                    )?;
                    return crate::lifecycle::rollback_registered(&store, &record);
                }
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
                if record.resources.contains_key("lifecycle_contract") {
                    require_confirmation(
                        yes,
                        "execute the deployment-bound offline recovery contract and activate the cached trusted runtime",
                    )?;
                    return crate::lifecycle::recover_registered(&store, &record);
                }
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
                if record.resources.contains_key("lifecycle_contract") {
                    require_confirmation(
                        yes,
                        "resume the deployment-bound interrupted update transaction",
                    )?;
                    let transaction = crate::coordination::resume(&store, &record)?;
                    let transaction = crate::lifecycle::execute_coordinated_update(
                        &store,
                        &record,
                        &transaction,
                    )?;
                    println!("{}", serde_json::to_string_pretty(&transaction)?);
                    return Ok(());
                }
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
        Command::Conformance(command) => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            let operation = conformance_operation(command.lease)?;
            let local_development =
                if command.candidate.is_none() && DeploymentStore::system().registry_present()? {
                    if let Some(record) = context.record.as_ref()
                        && record.active_release.build_id.starts_with("local:")
                    {
                        validate_local_development_identity(&record.active_release)?;
                        Some(record.active_release.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
            conformance_app_command(
                &context.config,
                operation,
                command.candidate.as_ref(),
                local_development.as_ref(),
            )
        }
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
}
