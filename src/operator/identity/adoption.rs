use super::*;

pub(crate) fn adopt_legacy_identity(
    config_path: &Path,
    config: &mut UpdateConfig,
    layout: &IdentityLayout,
) -> anyhow::Result<()> {
    let controller = read_signing_key(&config.operator.controller_private_key)?;
    let controller_public = read_verifying_key(&config.operator.controller_public_key)?;
    let audit = read_signing_key(&config.operator.audit_private_key)?;
    let audit_public = read_verifying_key(&config.operator.audit_public_key)?;
    let break_glass = read_signing_key(&config.operator.break_glass_private_key)?;
    let break_glass_public = read_verifying_key(&config.operator.break_glass_public_key)?;
    if controller.verifying_key() != controller_public
        || audit.verifying_key() != audit_public
        || break_glass.verifying_key() != break_glass_public
    {
        bail!("legacy operator identity is inconsistent; refuse automatic adoption")
    }
    let active = ActiveIdentity {
        schema: 1,
        generation: format!("legacy-{}", config.operator.controller_key_id),
        controller_key_id: config.operator.controller_key_id.clone(),
        audit_key_id: config.operator.audit_key_id.clone(),
        break_glass_key_id: config.operator.break_glass_key_id.clone(),
    };
    validate_active_identity(&active)?;
    let intent_path = layout.operator_directory.join("legacy-adoption.json");
    let intent = LegacyAdoptionIntent {
        schema: 1,
        generation: active.generation.clone(),
        controller_key_id: active.controller_key_id.clone(),
        audit_key_id: active.audit_key_id.clone(),
        break_glass_key_id: active.break_glass_key_id.clone(),
    };
    refuse_ambiguous_legacy_adoption(config, layout, &intent_path, &intent)?;
    if !path_present(&intent_path)? {
        atomic_write(&intent_path, &serde_json::to_vec_pretty(&intent)?, 0o600)?;
    }
    if path_present(&generation_paths(layout, &active).0)?
        || path_present(&generation_paths(layout, &active).1)?
    {
        match validate_generation(layout, &active) {
            Ok(()) => {
                let (generation, recovery_generation) = generation_paths(layout, &active);
                if read_signing_key(&generation.join("controller.key"))?.to_bytes()
                    != controller.to_bytes()
                    || read_signing_key(&generation.join("audit.key"))?.to_bytes()
                        != audit.to_bytes()
                    || read_signing_key(&recovery_generation.join("break-glass.key"))?.to_bytes()
                        != break_glass.to_bytes()
                {
                    bail!("staged legacy adoption conflicts with configured identity")
                }
            }
            Err(_) => {
                remove_uncommitted_generation(layout, &active)?;
                write_generation(layout, &active, &controller, &audit, &break_glass)?;
            }
        }
    } else {
        write_generation(layout, &active, &controller, &audit, &break_glass)?;
    }
    write_active_identity(layout, &active)?;
    apply_active_identity(config, layout, &active);
    atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    crate::filesystem::remove_file_durable(&intent_path)
}

pub(crate) fn refuse_ambiguous_legacy_adoption(
    config: &UpdateConfig,
    layout: &IdentityLayout,
    intent_path: &Path,
    expected: &LegacyAdoptionIntent,
) -> anyhow::Result<()> {
    if path_present(&layout.operator_directory.join("rotation-intent.json"))?
        || directory_has_entries(&config.operator.audit_directory.join("trust-transitions"))?
    {
        bail!("legacy identity cannot be adopted from an ambiguous rotation state")
    }
    if path_present(intent_path)? {
        let actual: LegacyAdoptionIntent = serde_json::from_slice(&fs::read(intent_path)?)?;
        if actual.schema != expected.schema
            || actual.generation != expected.generation
            || actual.controller_key_id != expected.controller_key_id
            || actual.audit_key_id != expected.audit_key_id
            || actual.break_glass_key_id != expected.break_glass_key_id
        {
            bail!("legacy identity adoption intent conflicts with configured identity")
        }
        ensure_only_expected_generation(&layout.generations, &expected.generation)?;
        ensure_only_expected_generation(&layout.recovery_generations, &expected.generation)?;
        return Ok(());
    }
    if directory_has_entries(&layout.generations)?
        || directory_has_entries(&layout.recovery_generations)?
    {
        bail!("legacy identity exists with uncommitted generation state")
    }
    Ok(())
}

fn directory_has_entries(path: &Path) -> anyhow::Result<bool> {
    if !path_present(path)? {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed identity path must be a regular non-symlink directory")
    }
    Ok(fs::read_dir(path)?.next().transpose()?.is_some())
}

pub(crate) fn ensure_only_expected_generation(
    directory: &Path,
    expected: &str,
) -> anyhow::Result<()> {
    if !path_present(directory)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed identity path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_str() != Some(expected) || !entry.file_type()?.is_dir() {
            bail!("legacy adoption contains an unexpected identity generation")
        }
    }
    Ok(())
}

pub(crate) fn remove_uncommitted_generation(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    remove_allowlisted_generation_directory(
        &generation,
        &[
            "controller.key",
            "controller.pub",
            "audit.key",
            "audit.pub",
            "break-glass.pub",
        ],
    )?;
    remove_allowlisted_generation_directory(&recovery_generation, &["break-glass.key"])
}

pub(crate) fn remove_allowlisted_generation_directory(
    path: &Path,
    allowed: &[&str],
) -> anyhow::Result<()> {
    if !path_present(path)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("uncommitted identity generation is not a regular directory")
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("uncommitted identity entry is not UTF-8"))?;
        if !allowed.contains(&name.as_str()) || !entry.file_type()?.is_file() {
            bail!("uncommitted identity generation contains an unexpected entry")
        }
        remove_managed_regular_file(&entry.path())?;
    }
    fs::remove_dir(path).with_context(|| format!("failed to remove {}", path.display()))
}
