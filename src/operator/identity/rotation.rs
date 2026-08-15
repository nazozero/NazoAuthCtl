use super::*;

fn archive_public_key(path: &Path, source: &Path) -> anyhow::Result<()> {
    let source_bytes = crate::filesystem::read_secure_regular_file(
        source,
        "identity generation public key",
        false,
        4096,
    )?;
    if path_present(path)? {
        let archived_bytes = crate::filesystem::read_secure_regular_file(
            path,
            "historical identity public key",
            false,
            4096,
        )?;
        if archived_bytes.as_slice() != source_bytes.as_slice() {
            bail!("historical trust public key conflicts with staged generation")
        }
        return Ok(());
    }
    atomic_write(path, source_bytes.as_slice(), 0o444)
}

pub(crate) fn archive_generation_publics(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, _) = generation_paths(layout, active);
    for directory in [
        layout.operator_directory.join("trusted-controllers"),
        layout.operator_directory.join("trusted-audit"),
        layout.operator_directory.join("trusted-break-glass"),
    ] {
        crate::filesystem::ensure_directory_chain(&directory)?;
        crate::filesystem::set_mode(&directory, 0o700)?;
    }
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-controllers")
            .join(format!("{}.pub", active.controller_key_id)),
        &generation.join("controller.pub"),
    )?;
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-audit")
            .join(format!("{}.pub", active.audit_key_id)),
        &generation.join("audit.pub"),
    )?;
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-break-glass")
            .join(format!("{}.pub", active.break_glass_key_id)),
        &generation.join("break-glass.pub"),
    )
}

pub(crate) fn verify_rotation_intent(
    config: &UpdateConfig,
    active: &ActiveIdentity,
    next: &ActiveIdentity,
    intent: &RotationIntent,
) -> anyhow::Result<()> {
    let active_is_previous = active.controller_key_id == intent.previous_key_id
        && active.audit_key_id == intent.previous_audit_key_id
        && active.break_glass_key_id == intent.previous_break_glass_key_id;
    let active_is_next = active.controller_key_id == next.controller_key_id
        && active.audit_key_id == next.audit_key_id
        && active.break_glass_key_id == next.break_glass_key_id;
    if !active_is_previous && !active_is_next {
        bail!("controller rotation intent does not connect to the active generation")
    }
    let header = protected_header(&intent.compact_transition)?;
    let key = if header.kid == intent.previous_key_id {
        if active_is_previous {
            read_verifying_key(&config.operator.controller_public_key)?
        } else {
            trusted_controller_key(config, &header.kid)?
        }
    } else if header.kid == intent.previous_break_glass_key_id {
        if active_is_previous {
            read_verifying_key(&config.operator.break_glass_public_key)?
        } else {
            trusted_break_glass_key(config, &header.kid)?
        }
    } else {
        bail!("controller rotation intent signer is not active controller or break-glass identity")
    };
    let transition = verify_trust_transition(&intent.compact_transition, &header.kid, &key)?;
    if transition.deployment_id != config.operator.deployment_id
        || transition.previous_key_id != intent.previous_key_id
        || transition.next_key_id != next.controller_key_id
        || transition.previous_audit_key_id != intent.previous_audit_key_id
        || transition.next_audit_key_id != next.audit_key_id
        || transition.previous_break_glass_key_id != intent.previous_break_glass_key_id
        || transition.next_break_glass_key_id != next.break_glass_key_id
    {
        bail!("controller rotation intent transition does not bind the staged generation")
    }
    match transition.authorization {
        TransitionAuthorization::Controller if header.kid == intent.previous_key_id => Ok(()),
        TransitionAuthorization::BreakGlass if header.kid == intent.previous_break_glass_key_id => {
            Ok(())
        }
        _ => bail!("controller rotation intent authorization does not match its signer"),
    }
}

pub(crate) fn retire_non_active_private_material(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    retire_generation_private_material(
        &layout.generations,
        Some(&active.generation),
        &["controller.key", "audit.key"],
    )?;
    retire_generation_private_material(
        &layout.recovery_generations,
        Some(&active.generation),
        &["break-glass.key"],
    )?;
    for legacy in [
        layout.operator_directory.join("controller.key"),
        layout.operator_directory.join("audit.key"),
        layout
            .recovery_generations
            .parent()
            .context("recovery generation directory has no parent")?
            .join("break-glass.key"),
    ] {
        if path_present(&legacy)? {
            remove_managed_regular_file(&legacy)?;
        }
    }
    Ok(())
}

pub(crate) fn generation_private_material_present(
    directory: &Path,
    active_generation: &str,
    private_names: &[&str],
) -> anyhow::Result<bool> {
    if !path_present(directory)? {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("identity generations path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("identity generation name is not UTF-8"))?;
        if !safe_identity_component(&name) || !entry.file_type()?.is_dir() {
            bail!("identity generations directory contains an unsafe entry")
        }
        if name == active_generation {
            continue;
        }
        for private_name in private_names {
            let path = entry.path().join(private_name);
            if managed_regular_file_present(&path)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(crate) fn retire_generation_private_material(
    directory: &Path,
    active_generation: Option<&str>,
    private_names: &[&str],
) -> anyhow::Result<()> {
    if !path_present(directory)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("identity generations path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("identity generation name is not UTF-8"))?;
        if !safe_identity_component(&name) || !entry.file_type()?.is_dir() {
            bail!("identity generations directory contains an unsafe entry")
        }
        if active_generation == Some(name.as_str()) {
            continue;
        }
        for private_name in private_names {
            remove_managed_regular_file(&entry.path().join(private_name))?;
        }
    }
    Ok(())
}

fn retirement_probe(config: &UpdateConfig, old_key: &SigningKey) -> anyhow::Result<String> {
    let now = Utc::now().timestamp();
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{}", config.operator.deployment_id),
        aud: format!("runtime:{}", config.operator.deployment_id),
        jti: format!("probe-{}", encode_hex(&rand::random::<[u8; 16]>())),
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: config.operator.deployment_id.clone(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        target: nazo_operator_protocol::TargetExpectation::HostBinary {
            path: "/nazoauth-retirement-probe".to_owned(),
            sha256: "0".repeat(64),
        },
        embedded: EmbeddedIdentity {
            release: "retirement-probe".to_owned(),
            revision: "retirement-probe".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "retirement-probe".to_owned(),
        },
        config: ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: "0".repeat(64),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "retirement-probe".to_owned(),
            },
        },
        operation: TaskOperation::KeysValidate,
    };
    Ok(sign_task(
        &task,
        &config.operator.controller_key_id,
        old_key,
    )?)
}

pub(crate) fn verify_retired_controller_probe(
    config: &UpdateConfig,
    rotation: &RotationResult,
    release: &str,
    expected: &ExpectedReleaseTarget,
) -> anyhow::Result<()> {
    verify_retired_controller_probe_with(config, rotation, release, |probe| {
        let operation = TaskOperation::KeysValidate;
        let manifest = canonical_manifest(config, &operation)?;
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let runtime = Runtime::new(config);
        let target = if config.runtime.backend == RuntimeBackendKind::Systemd {
            config.runtime.binary_path.to_string_lossy().into_owned()
        } else {
            runtime.active_image()?
        };
        // This must create and execute the same constrained application task
        // used by public key validation.  A local verifier alone cannot
        // establish the runtime mount/context boundary.
        let prepared = runtime.prepare_app_task(&target, &operation, None, &manifest_bytes)?;
        verify_target_expectation(&prepared.target, expected)?;
        let embedded = runtime.embedded_identity(&target)?;
        if embedded != expected.embedded {
            bail!("runtime embedded build identity does not match the active signed Release")
        }
        prepared.expect_authorization_rejection(probe)?;
        runtime.verify_prepared_target(&prepared.target)?;
        Ok(RetirementProbeExecution {
            controller_verified_target: prepared.target.clone(),
            application_reported_embedded_identity: embedded,
        })
    })
}

pub(crate) fn verify_retired_controller_probe_with<F>(
    config: &UpdateConfig,
    rotation: &RotationResult,
    release: &str,
    runtime_rejection: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&str) -> anyhow::Result<RetirementProbeExecution>,
{
    let Some(probe) = rotation.retirement_probe.as_deref() else {
        let evidence =
            encode_retirement_probe_audit_evidence(&RetirementProbeAuditEvidence::NotIssued {
                schema: 1,
                previous_controller_key_id: rotation.previous_controller_key_id.clone(),
                previous_controller_public_sha256: rotation
                    .previous_controller_public_sha256
                    .clone(),
                reason: "controller-private-unavailable".to_owned(),
            })?;
        append_management_event(config, "controller-retirement-probe", release, &evidence)?;
        println!(
            "retired controller probe not issued: previous={} previous_public_sha256={} release={} category=controller-private-unavailable",
            rotation.previous_controller_key_id,
            rotation.previous_controller_public_sha256,
            release
        );
        return Ok(());
    };
    let execution = runtime_rejection(probe)?;
    let probe_digest = compact_sha256(probe);
    let evidence = encode_retirement_probe_audit_evidence(
        &RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema: 1,
            previous_controller_key_id: rotation.previous_controller_key_id.clone(),
            active_controller_key_id: config.operator.controller_key_id.clone(),
            probe_sha256: probe_digest,
            controller_verified_target: execution.controller_verified_target,
            application_reported_embedded_identity: execution
                .application_reported_embedded_identity,
        },
    )?;
    append_management_event(config, "controller-retirement-probe", release, &evidence)?;
    println!(
        "retired controller probe rejected: previous={} previous_public_sha256={} release={}",
        rotation.previous_controller_key_id, rotation.previous_controller_public_sha256, release
    );
    Ok(())
}

/// File-provider truthfulness boundary: this observes only the key available to
/// the current root process.  It cannot prove that an attacker did not copy it.
pub(crate) fn report_controller_availability(config: &UpdateConfig) -> anyhow::Result<bool> {
    let available = read_signing_key(&config.operator.controller_private_key)
        .ok()
        .is_some_and(|key| {
            read_verifying_key(&config.operator.controller_public_key)
                .is_ok_and(|public| key.verifying_key() == public)
        });
    println!(
        "controller-key-availability={}; provider=file; copied-key-status=not-provable",
        if available {
            "available"
        } else {
            "unavailable"
        }
    );
    Ok(available)
}

const REGISTERED_ROTATION_SCHEMA: u32 = 1;
const REGISTERED_ROTATION_JOURNAL_MAX_BYTES: u64 = 256 * 1024;

pub(crate) fn rotate_registered_controller_with_access(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
    controller_access: ControllerSigningAccess,
) -> anyhow::Result<RotationResult> {
    if crate::coordination::active_update_exists(store, record) {
        bail!("controller identity cannot rotate while a coordinated update transaction is active");
    }
    match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) if path == config_path => {}
        _ => bail!("registered identity rotation config path is not declaration-bound"),
    }
    if config.operator.deployment_id != record.deployment_id
        || config.operator.controller_key_id != record.control_authority
    {
        bail!("registered identity rotation is not bound to the declaration authority");
    }
    let journal_path = store.identity_rotation_journal_path(&record.deployment_id);
    let journal = if path_present(&journal_path)? {
        let journal = load_registered_rotation_journal(&journal_path, &record.deployment_id)?;
        let resume_reason =
            break_glass && matches!(&controller_access, ControllerSigningAccess::Unavailable);
        if journal.break_glass != break_glass || (journal.reason != reason && !resume_reason) {
            bail!("a different registered identity rotation is pending; resume its original plan");
        }
        journal
    } else {
        prepare_registered_rotation(
            record,
            config,
            break_glass,
            reason,
            controller_access,
            &journal_path,
        )?
    };
    resume_registered_rotation(store, config_path, config, record, journal, &journal_path)
}

pub(crate) fn recover_registered_rotation_locked(
    store: &DeploymentStore,
    config_path: &Path,
    expected_record: &DeploymentRecord,
) -> anyhow::Result<bool> {
    let journal_path = store.identity_rotation_journal_path(&expected_record.deployment_id);
    if !path_present(&journal_path)? {
        return Ok(false);
    }
    if crate::coordination::active_update_exists(store, expected_record) {
        bail!(
            "controller identity recovery cannot continue while a coordinated update transaction is active"
        );
    }
    let bound_config_path = match expected_record.resources.get("controller_config") {
        Some(SafeReference::File { path }) => path.clone(),
        _ => config_path.to_owned(),
    };
    let config = crate::controller::load_bound_control_config_unsettled(&bound_config_path)?;
    let current = store.load(&expected_record.deployment_id)?;
    let journal = load_registered_rotation_journal(&journal_path, &current.deployment_id)?;
    let _ = resume_registered_rotation(
        store,
        &bound_config_path,
        &config,
        &current,
        journal,
        &journal_path,
    )?;
    Ok(true)
}

fn prepare_registered_rotation(
    record: &DeploymentRecord,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
    controller_access: ControllerSigningAccess,
    journal_path: &Path,
) -> anyhow::Result<IdentityRotationJournal> {
    if record.trust != TrustState::Adopted {
        bail!("identity rotation requires an adopted deployment");
    }
    let layout = identity_layout(config)?;
    let previous = read_active_identity(&layout.active_file)?;
    if break_glass {
        validate_generation_for_break_glass_recovery(&layout, &previous)?;
    } else {
        validate_generation(&layout, &previous)?;
    }
    if previous.controller_key_id != record.control_authority
        || config.operator.controller_key_id != previous.controller_key_id
        || config.operator.audit_key_id != previous.audit_key_id
        || config.operator.break_glass_key_id != previous.break_glass_key_id
    {
        bail!("active identity does not match the declaration authority");
    }
    match record.resources.get("audit_private_key") {
        Some(SafeReference::File { path }) if path == &config.operator.audit_private_key => {}
        _ => bail!("registered deployment audit key resource is not config-bound"),
    }
    match record.resources.get("break_glass_private_key") {
        Some(SafeReference::File { path }) if path == &config.operator.break_glass_private_key => {}
        _ => bail!("registered deployment break-glass key resource is not config-bound"),
    }
    let old_controller_public = read_verifying_key(&config.operator.controller_public_key)?;
    let previous_controller_public_sha256 =
        encode_hex(&Sha256::digest(old_controller_public.to_bytes()));
    let retirement_probe = controller_access
        .controller_for_retirement_probe(&config.operator.controller_private_key)?
        .map(|key| retirement_probe(config, &key))
        .transpose()?;
    let new_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let new_audit_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next_break_glass = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next = new_active_identity(&new_key, &new_audit_key, &next_break_glass);
    let (authorization, signer_id, signer) = if break_glass {
        (
            TransitionAuthorization::BreakGlass,
            config.operator.break_glass_key_id.as_str(),
            read_signing_key(&config.operator.break_glass_private_key)?,
        )
    } else {
        (
            TransitionAuthorization::Controller,
            config.operator.controller_key_id.as_str(),
            controller_access
                .controller_for_normal_rotation(&config.operator.controller_private_key)?,
        )
    };
    let transition = ControllerTrustTransition {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        issued_at: Utc::now().timestamp(),
        authorization,
        previous_key_id: previous.controller_key_id.clone(),
        next_key_id: next.controller_key_id.clone(),
        next_public_key_sha256: encode_hex(&Sha256::digest(new_key.verifying_key().to_bytes())),
        previous_audit_key_id: previous.audit_key_id.clone(),
        next_audit_key_id: next.audit_key_id.clone(),
        next_audit_public_key_sha256: encode_hex(&Sha256::digest(
            new_audit_key.verifying_key().to_bytes(),
        )),
        previous_break_glass_key_id: previous.break_glass_key_id.clone(),
        next_break_glass_key_id: next.break_glass_key_id.clone(),
        next_break_glass_public_key_sha256: encode_hex(&Sha256::digest(
            next_break_glass.verifying_key().to_bytes(),
        )),
        reason: reason.to_owned(),
    };
    let compact_transition = sign_trust_transition(&transition, signer_id, &signer)?;
    let transitions = config.operator.audit_directory.join("trust-transitions");
    let transition_file = format!(
        "{}-{}-to-{}.jws",
        Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        previous.controller_key_id,
        next.controller_key_id
    );
    let transition_path = transitions.join(&transition_file);
    let mut next_record = record.clone();
    next_record.control_authority = next.controller_key_id.clone();
    let (next_generation, next_recovery_generation) = generation_paths(&layout, &next);
    match next_record.resources.get_mut("audit_private_key") {
        Some(SafeReference::File { path }) => *path = next_generation.join("audit.key"),
        _ => bail!("registered deployment has no file-bound audit key resource"),
    }
    next_record.resources.insert(
        "audit_public_key".to_owned(),
        SafeReference::File {
            path: next_generation.join("audit.pub"),
        },
    );
    match next_record.resources.get_mut("break_glass_private_key") {
        Some(SafeReference::File { path }) => {
            *path = next_recovery_generation.join("break-glass.key")
        }
        _ => bail!("registered deployment has no file-bound break-glass key resource"),
    }
    next_record.declaration_revision = record
        .declaration_revision
        .checked_add(1)
        .context("deployment declaration revision overflow")?;
    next_record.validate()?;
    let journal = IdentityRotationJournal {
        schema: REGISTERED_ROTATION_SCHEMA,
        request_id: format!("identity-rotation-{}", uuid::Uuid::now_v7()),
        deployment_id: record.deployment_id.clone(),
        break_glass,
        reason: reason.to_owned(),
        from_revision: record.declaration_revision,
        previous_record: record.clone(),
        next_record,
        previous: previous.clone(),
        previous_controller_public_sha256,
        next: next.clone(),
        transition_file,
        compact_transition: compact_transition.clone(),
        retirement_probe,
        phase: IdentityRotationPhase::GenerationCommitted,
    };
    let journal_bytes = serde_json::to_vec_pretty(&journal)?;
    if journal_bytes.len() as u64 > REGISTERED_ROTATION_JOURNAL_MAX_BYTES {
        bail!("identity rotation journal exceeds its size limit");
    }
    is_real_directory_or_missing(&transitions, "trust-transition directory")?;
    crate::filesystem::ensure_directory_chain(&transitions)?;
    write_generation(&layout, &next, &new_key, &new_audit_key, &next_break_glass)?;
    archive_generation_publics(&layout, &previous)?;
    archive_generation_publics(&layout, &next)?;
    atomic_write(&transition_path, compact_transition.as_bytes(), 0o400)?;
    write_registered_rotation_journal(journal_path, &journal)?;
    Ok(journal)
}

fn write_registered_rotation_journal(
    path: &Path,
    journal: &IdentityRotationJournal,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() as u64 > REGISTERED_ROTATION_JOURNAL_MAX_BYTES {
        bail!("identity rotation journal exceeds its size limit");
    }
    atomic_write(path, &bytes, 0o600)
}

fn load_registered_rotation_journal(
    path: &Path,
    deployment_id: &str,
) -> anyhow::Result<IdentityRotationJournal> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("identity rotation journal must be a regular non-symlink file");
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "identity rotation journal",
        true,
        REGISTERED_ROTATION_JOURNAL_MAX_BYTES,
    )?;
    let journal: IdentityRotationJournal =
        serde_json::from_slice(&bytes).context("identity rotation journal is invalid")?;
    if journal.schema != REGISTERED_ROTATION_SCHEMA
        || journal.deployment_id != deployment_id
        || journal.previous.controller_key_id == journal.next.controller_key_id
        || !safe_identity_component(&journal.transition_file)
        || !journal.transition_file.ends_with(".jws")
    {
        bail!("identity rotation journal is invalid or crosses deployment boundaries");
    }
    Ok(journal)
}

fn resume_registered_rotation(
    store: &DeploymentStore,
    config_path: &Path,
    config: &UpdateConfig,
    record: &DeploymentRecord,
    mut journal: IdentityRotationJournal,
    journal_path: &Path,
) -> anyhow::Result<RotationResult> {
    let expected_next_revision = journal
        .from_revision
        .checked_add(1)
        .context("identity rotation declaration revision overflow")?;
    if journal.schema != REGISTERED_ROTATION_SCHEMA
        || journal.deployment_id != record.deployment_id
        || journal.from_revision > record.declaration_revision
        || journal.previous_record.deployment_id != journal.deployment_id
        || journal.next_record.deployment_id != journal.deployment_id
        || journal.previous_record.declaration_revision != journal.from_revision
        || journal.next_record.declaration_revision != expected_next_revision
        || journal.previous_record.control_authority != journal.previous.controller_key_id
        || journal.next_record.control_authority != journal.next.controller_key_id
    {
        bail!("identity rotation journal does not match the deployment declaration");
    }
    let layout = identity_layout(config)?;
    validate_generation(&layout, &journal.next)?;
    let (previous_generation, previous_recovery_generation) =
        generation_paths(&layout, &journal.previous);
    let (next_generation, next_recovery_generation) = generation_paths(&layout, &journal.next);
    let journal_deployment_id = journal.deployment_id.clone();
    let config_matches =
        |identity: &ActiveIdentity, generation: &Path, recovery_generation: &Path| {
            config.operator.deployment_id == journal_deployment_id
                && config.operator.controller_key_id == identity.controller_key_id
                && config.operator.controller_private_key == generation.join("controller.key")
                && config.operator.controller_public_key == generation.join("controller.pub")
                && config.operator.audit_key_id == identity.audit_key_id
                && config.operator.audit_private_key == generation.join("audit.key")
                && config.operator.audit_public_key == generation.join("audit.pub")
                && config.operator.break_glass_key_id == identity.break_glass_key_id
                && config.operator.break_glass_private_key
                    == recovery_generation.join("break-glass.key")
                && config.operator.break_glass_public_key == generation.join("break-glass.pub")
        };
    let config_matches_previous = config_matches(
        &journal.previous,
        &previous_generation,
        &previous_recovery_generation,
    );
    let config_matches_next =
        config_matches(&journal.next, &next_generation, &next_recovery_generation);
    let config_allowed = match journal.phase {
        IdentityRotationPhase::GenerationCommitted => config_matches_previous,
        IdentityRotationPhase::DeclarationCommitted => {
            config_matches_previous || config_matches_next
        }
        IdentityRotationPhase::ActiveCommitted | IdentityRotationPhase::AuditCommitted => {
            config_matches_next
        }
    };
    if !config_allowed {
        bail!("identity rotation configuration does not match its committed phase");
    }
    let audit_resource_matches = matches!(
        journal.next_record.resources.get("audit_private_key"),
        Some(SafeReference::File { path }) if path == &next_generation.join("audit.key")
    );
    let break_glass_resource_matches = matches!(
        journal.next_record.resources.get("break_glass_private_key"),
        Some(SafeReference::File { path })
            if path == &next_recovery_generation.join("break-glass.key")
    );
    if !audit_resource_matches || !break_glass_resource_matches {
        bail!("identity rotation journal key resources do not match its staged generation");
    }
    let active = read_active_identity(&layout.active_file)?;
    let intent = RotationIntent {
        schema: 1,
        next_generation: journal.next.generation.clone(),
        previous_key_id: journal.previous.controller_key_id.clone(),
        next_key_id: journal.next.controller_key_id.clone(),
        previous_audit_key_id: journal.previous.audit_key_id.clone(),
        next_audit_key_id: journal.next.audit_key_id.clone(),
        previous_break_glass_key_id: journal.previous.break_glass_key_id.clone(),
        next_break_glass_key_id: journal.next.break_glass_key_id.clone(),
        transition_file: journal.transition_file.clone(),
        compact_transition: journal.compact_transition.clone(),
    };
    verify_rotation_intent(config, &active, &journal.next, &intent)?;
    let transition_path = config
        .operator
        .audit_directory
        .join("trust-transitions")
        .join(&journal.transition_file);
    if !path_present(&transition_path)? {
        atomic_write(
            &transition_path,
            journal.compact_transition.as_bytes(),
            0o400,
        )?;
    } else {
        let existing = crate::filesystem::read_secure_regular_file(
            &transition_path,
            "identity rotation transition",
            false,
            64 * 1024,
        )?;
        let existing = std::str::from_utf8(&existing)
            .context("identity rotation transition is not valid UTF-8")?;
        if existing.trim() != journal.compact_transition {
            bail!("identity rotation transition file conflicts with its journal");
        }
    }

    if journal.phase == IdentityRotationPhase::GenerationCommitted {
        let current = store.load(&record.deployment_id)?;
        if current == journal.previous_record {
            store.persist_declaration_cas_locked(&journal.previous_record, &journal.next_record)?;
        } else if current == journal.next_record {
            // The CAS committed before the process stopped; continue idempotently.
        } else {
            bail!("identity rotation declaration changed during identity rotation");
        }
        journal.phase = IdentityRotationPhase::DeclarationCommitted;
        write_registered_rotation_journal(journal_path, &journal)?;
    }

    if journal.phase >= IdentityRotationPhase::DeclarationCommitted {
        let current = store.load(&record.deployment_id)?;
        if current != journal.next_record {
            bail!("identity rotation declaration is not at its committed target");
        }
    }

    if journal.phase == IdentityRotationPhase::DeclarationCommitted {
        let mut next_config = config.clone();
        write_active_identity(&layout, &journal.next)?;
        apply_active_identity(&mut next_config, &layout, &journal.next);
        atomic_write(
            config_path,
            &serde_json::to_vec_pretty(&next_config)?,
            0o600,
        )?;
        journal.phase = IdentityRotationPhase::ActiveCommitted;
        write_registered_rotation_journal(journal_path, &journal)?;
    }

    if journal.phase == IdentityRotationPhase::ActiveCommitted {
        let active_config = crate::controller::load_bound_control_config_unsettled(config_path)?;
        crate::operator::append_management_event_idempotent(
            &active_config,
            &journal.request_id,
            "identity-rotation",
            &journal.next.generation,
            if journal.break_glass {
                "break-glass"
            } else {
                "normal"
            },
        )?;
        journal.phase = IdentityRotationPhase::AuditCommitted;
        write_registered_rotation_journal(journal_path, &journal)?;
    }

    if journal.phase == IdentityRotationPhase::AuditCommitted {
        let active_config = crate::controller::load_bound_control_config_unsettled(config_path)?;
        let active_layout = identity_layout(&active_config)?;
        retire_non_active_private_material(&active_layout, &journal.next)?;
        let legacy_intent = active_layout
            .operator_directory
            .join("rotation-intent.json");
        if path_present(&legacy_intent)? {
            crate::filesystem::remove_file_durable(&legacy_intent)?;
        }
        crate::filesystem::remove_file_durable(journal_path)?;
    }
    Ok(RotationResult {
        previous_controller_key_id: journal.previous.controller_key_id,
        previous_controller_public_sha256: journal.previous_controller_public_sha256,
        retirement_probe: journal.retirement_probe,
    })
}

pub(crate) fn rotate_controller(
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    rotate_controller_with_access(
        config_path,
        config,
        break_glass,
        reason,
        ControllerSigningAccess::Available,
    )
}

pub(crate) fn rotate_controller_with_access(
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
    controller_access: ControllerSigningAccess,
) -> anyhow::Result<RotationResult> {
    let layout = identity_layout(config)?;
    let current = read_active_identity(&layout.active_file)?;
    if break_glass {
        validate_generation_for_break_glass_recovery(&layout, &current)?;
    } else {
        validate_generation(&layout, &current)?;
    }
    let old_controller_public = read_verifying_key(&config.operator.controller_public_key)?;
    let old_controller_digest = encode_hex(&Sha256::digest(old_controller_public.to_bytes()));
    let probe = controller_access
        .controller_for_retirement_probe(&config.operator.controller_private_key)?
        .map(|key| retirement_probe(config, &key))
        .transpose()?;
    let new_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let new_audit_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next_break_glass = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next = new_active_identity(&new_key, &new_audit_key, &next_break_glass);
    let (authorization, signer_id, signer) = if break_glass {
        (
            TransitionAuthorization::BreakGlass,
            config.operator.break_glass_key_id.as_str(),
            read_signing_key(&config.operator.break_glass_private_key)?,
        )
    } else {
        (
            TransitionAuthorization::Controller,
            config.operator.controller_key_id.as_str(),
            controller_access
                .controller_for_normal_rotation(&config.operator.controller_private_key)?,
        )
    };
    let transition = ControllerTrustTransition {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        issued_at: Utc::now().timestamp(),
        authorization,
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: next.controller_key_id.clone(),
        next_public_key_sha256: encode_hex(&Sha256::digest(new_key.verifying_key().to_bytes())),
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: next.audit_key_id.clone(),
        next_audit_public_key_sha256: encode_hex(&Sha256::digest(
            new_audit_key.verifying_key().to_bytes(),
        )),
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: next.break_glass_key_id.clone(),
        next_break_glass_public_key_sha256: encode_hex(&Sha256::digest(
            next_break_glass.verifying_key().to_bytes(),
        )),
        reason: reason.to_owned(),
    };
    let compact = sign_trust_transition(&transition, signer_id, &signer)?;
    let transitions = config.operator.audit_directory.join("trust-transitions");
    crate::filesystem::ensure_directory_chain(&transitions)?;
    let transition_file = format!(
        "{}-{}-to-{}.jws",
        Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        config.operator.controller_key_id,
        next.controller_key_id
    );
    let transition_path = transitions.join(&transition_file);
    write_generation(&layout, &next, &new_key, &new_audit_key, &next_break_glass)?;
    archive_generation_publics(&layout, &current)?;
    archive_generation_publics(&layout, &next)?;
    atomic_write(
        &layout.operator_directory.join("rotation-intent.json"),
        &serde_json::to_vec_pretty(&RotationIntent {
            schema: 1,
            next_generation: next.generation.clone(),
            previous_key_id: config.operator.controller_key_id.clone(),
            next_key_id: next.controller_key_id.clone(),
            previous_audit_key_id: config.operator.audit_key_id.clone(),
            next_audit_key_id: next.audit_key_id.clone(),
            previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
            next_break_glass_key_id: next.break_glass_key_id.clone(),
            transition_file,
            compact_transition: compact.clone(),
        })?,
        0o600,
    )?;
    atomic_write(&transition_path, compact.as_bytes(), 0o400)?;
    let mut next_config = config.clone();
    write_active_identity(&layout, &next)?;
    apply_active_identity(&mut next_config, &layout, &next);
    atomic_write(
        config_path,
        &serde_json::to_vec_pretty(&next_config)?,
        0o600,
    )?;
    retire_non_active_private_material(&layout, &next)?;
    crate::filesystem::remove_file_durable(
        &layout.operator_directory.join("rotation-intent.json"),
    )?;
    println!(
        "controller/audit identity rotated: previous={} next={} previous_audit={} next_audit={} previous_break_glass={} next_break_glass={} authorization={authorization:?} transition={}",
        config.operator.controller_key_id,
        next.controller_key_id,
        config.operator.audit_key_id,
        next.audit_key_id,
        config.operator.break_glass_key_id,
        next.break_glass_key_id,
        transition_path.display()
    );
    Ok(RotationResult {
        previous_controller_key_id: current.controller_key_id,
        previous_controller_public_sha256: old_controller_digest,
        retirement_probe: probe,
    })
}
