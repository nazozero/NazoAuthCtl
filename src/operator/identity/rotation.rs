use super::*;

fn archive_public_key(path: &Path, source: &Path) -> anyhow::Result<()> {
    if path_present(path)? {
        if fs::read(path)? != fs::read(source)? {
            bail!("historical trust public key conflicts with staged generation")
        }
        return Ok(());
    }
    atomic_write(path, fs::read(source)?.as_slice(), 0o444)
}

pub(crate) fn archive_generation_publics(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, _) = generation_paths(layout, active);
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
    fs::create_dir_all(&transitions)?;
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
