use super::*;

/// This is an actual recovery transition under a simulated unavailable file
/// provider.  The active controller private key is loaded only before the
/// guard is established, solely to construct the post-transition rejection
/// probe; the rotation itself cannot read it.
pub(crate) fn rehearse_controller_loss(
    config_path: &Path,
    config: &UpdateConfig,
) -> anyhow::Result<RotationResult> {
    let probe_key = read_signing_key(&config.operator.controller_private_key)?;
    rotate_controller_with_access(
        config_path,
        config,
        true,
        "simulated-unavailable",
        ControllerSigningAccess::ForbiddenForRehearsal(Box::new(probe_key)),
    )
}

pub(crate) fn recover_controller_without_controller_key(
    config_path: &Path,
    config: &UpdateConfig,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    rotate_controller_with_access(
        config_path,
        config,
        true,
        reason,
        ControllerSigningAccess::Unavailable,
    )
}

/// Inspect whether the identity state needs an explicitly authorized recovery.
/// This function is deliberately read-only: observation commands use it to fail
/// closed instead of completing a rotation, adopting legacy identity, or
/// retiring key material as a side effect of loading configuration.
pub(crate) fn identity_recovery_required(config: &UpdateConfig) -> anyhow::Result<bool> {
    let layout = identity_layout(config)?;
    if !path_present(&layout.active_file)? {
        return Ok(true);
    }
    let active = read_active_identity(&layout.active_file)?;
    validate_generation_for_break_glass_recovery(&layout, &active)?;

    let mut expected = config.clone();
    apply_active_identity(&mut expected, &layout, &active);
    if serde_json::to_vec(&expected)? != serde_json::to_vec(config)? {
        return Ok(true);
    }
    if path_present(&layout.operator_directory.join("legacy-adoption.json"))?
        || path_present(&layout.operator_directory.join("rotation-intent.json"))?
        || generation_private_material_present(
            &layout.generations,
            &active.generation,
            &["controller.key", "audit.key"],
        )?
        || generation_private_material_present(
            &layout.recovery_generations,
            &active.generation,
            &["break-glass.key"],
        )?
    {
        return Ok(true);
    }
    for legacy in [
        layout.operator_directory.join("controller.key"),
        layout.operator_directory.join("audit.key"),
        layout
            .recovery_generations
            .parent()
            .context("recovery generation directory has no parent")?
            .join("break-glass.key"),
    ] {
        if managed_regular_file_present(&legacy)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn recover_pending_rotation(
    config_path: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<()> {
    let layout = identity_layout(config)?;
    if !path_present(&layout.active_file)? {
        adopt_legacy_identity(config_path, config, &layout)?;
    }
    let mut active = read_active_identity(&layout.active_file)?;
    validate_generation_for_break_glass_recovery(&layout, &active)?;
    let config_before_repair = serde_json::to_vec(config)?;
    apply_active_identity(config, &layout, &active);
    let adoption_path = layout.operator_directory.join("legacy-adoption.json");
    let adoption_pending = if path_present(&adoption_path)? {
        let adoption_bytes = crate::filesystem::read_secure_regular_file(
            &adoption_path,
            "legacy adoption journal",
            true,
            64 * 1024,
        )?;
        let adoption: LegacyAdoptionIntent = serde_json::from_slice(&adoption_bytes)?;
        if adoption.schema != 1
            || adoption.generation != active.generation
            || adoption.controller_key_id != active.controller_key_id
            || adoption.audit_key_id != active.audit_key_id
            || adoption.break_glass_key_id != active.break_glass_key_id
        {
            bail!("legacy identity adoption intent conflicts with the active generation")
        }
        true
    } else {
        false
    };
    let intent_path = layout.operator_directory.join("rotation-intent.json");
    if adoption_pending && path_present(&intent_path)? {
        bail!("legacy adoption and controller rotation cannot be pending together")
    }
    if path_present(&intent_path)? {
        let intent_bytes = crate::filesystem::read_secure_regular_file(
            &intent_path,
            "identity rotation intent",
            true,
            256 * 1024,
        )?;
        let intent: RotationIntent = serde_json::from_slice(&intent_bytes)?;
        if intent.schema != 1
            || !safe_identity_component(&intent.next_generation)
            || intent.transition_file.is_empty()
            || intent.transition_file.starts_with('.')
            || intent.transition_file.contains(['/', '\\'])
        {
            bail!("controller rotation intent is invalid")
        }
        let next = ActiveIdentity {
            schema: 1,
            generation: intent.next_generation.clone(),
            controller_key_id: intent.next_key_id.clone(),
            audit_key_id: intent.next_audit_key_id.clone(),
            break_glass_key_id: intent.next_break_glass_key_id.clone(),
        };
        validate_generation(&layout, &next)?;
        verify_rotation_intent(config, &active, &next, &intent)?;
        archive_generation_publics(&layout, &active)?;
        archive_generation_publics(&layout, &next)?;
        let transition_path = config
            .operator
            .audit_directory
            .join("trust-transitions")
            .join(&intent.transition_file);
        if !path_present(&transition_path)? {
            crate::filesystem::ensure_directory_chain(
                transition_path
                    .parent()
                    .context("rotation transition path has no parent")?,
            )?;
            atomic_write(
                &transition_path,
                intent.compact_transition.as_bytes(),
                0o400,
            )?;
        }
        if active.generation != next.generation {
            write_active_identity(&layout, &next)?;
            active = next;
        }
        apply_active_identity(config, &layout, &active);
        atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    }
    retire_non_active_private_material(&layout, &active)?;
    if serde_json::to_vec(config)? != config_before_repair {
        atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    }
    if adoption_pending {
        crate::filesystem::remove_file_durable(&adoption_path)?;
    }
    if path_present(&intent_path)? {
        crate::filesystem::remove_file_durable(&intent_path)?;
    }
    Ok(())
}
