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
            let material_sha256 = crate::filesystem::sha256(&material)?;
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
                let metadata = fs::symlink_metadata(&material)
                    .context("failed to inspect OpenID4VC conformance material")?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() == 0
                    || metadata.len() > 32 * 1024
                {
                    bail!(
                        "OpenID4VC conformance material must be a regular file from 1 through 32768 bytes"
                    );
                }
                Some(
                    serde_json::from_slice::<nazo_operator_protocol::Openid4vcConformanceTrust>(
                        &fs::read(&material)?,
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

fn read_conformance_token_sha256(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect conformance token file {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "conformance token file must be a regular non-symlink file: {}",
            path.display()
        );
    }
    validate_conformance_token_metadata(&metadata)?;

    let file = File::open(path)
        .with_context(|| format!("failed to open conformance token file {}", path.display()))?;
    let opened_metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened conformance token file {}",
            path.display()
        )
    })?;
    validate_same_file(&metadata, &opened_metadata, "conformance token file")?;
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
            if crate::deployment::DeploymentStore::system()
                .registry_path()
                .exists()
            {
                let record = crate::deployment::DeploymentStore::system()
                    .resolve(cli.deployment.as_deref(), false)?;
                return registered_status(&record, false);
            }
            let config = load_config(&cli.config)?;
            status(&config)
        }
        Command::Doctor => {
            if crate::deployment::DeploymentStore::system()
                .registry_path()
                .exists()
            {
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
            if DeploymentStore::system().registry_path().exists() {
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
            if DeploymentStore::system().registry_path().exists() {
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
        Command::Rollback { yes } => {
            require_root()?;
            if DeploymentStore::system().registry_path().exists() {
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
            if DeploymentStore::system().registry_path().exists() {
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
            if DeploymentStore::system().registry_path().exists() {
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
            let (operation, public_jwk) = match command {
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
                    let public_jwk_sha256 = crate::filesystem::sha256(&public_jwk)?;
                    (
                        TaskOperation::KeysRegisterExternal {
                            kid,
                            alg,
                            key_ref,
                            public_jwk_sha256,
                        },
                        Some(public_jwk),
                    )
                }
            };
            app_command(&context.config, operation, public_jwk.as_deref())
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
            conformance_app_command(&context.config, operation, command.candidate.as_ref())
        }
        Command::AuditVerify => {
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
        Command::AuditShow { request_id } => {
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
            let rotation = crate::operator::rotate_controller(
                &context.path,
                &context.config,
                false,
                "normal",
            )?;
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
            let rotation =
                crate::operator::rehearse_controller_loss(&context.path, &context.config)?;
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
            let rotation = crate::operator::recover_controller_without_controller_key(
                &context.path,
                &context.config,
                &reason,
            )?;
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
