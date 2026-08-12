use super::*;

pub(crate) fn initialize_identity_generation(
    operator_directory: &Path,
    recovery_directory: &Path,
) -> anyhow::Result<()> {
    let active_file = operator_directory.join("active-generation.json");
    let layout = IdentityLayout {
        operator_directory: operator_directory.to_owned(),
        active_file: active_file.clone(),
        generations: operator_directory.join("generations"),
        recovery_generations: recovery_directory.join("generations"),
    };
    if path_present(&active_file)? {
        ensure_static_identity_files(operator_directory)?;
        let active = read_active_identity(&active_file)?;
        validate_generation(&layout, &active)?;
        return Ok(());
    }
    for legacy in [
        operator_directory.join("controller.key"),
        operator_directory.join("controller.pub"),
        operator_directory.join("audit.key"),
        operator_directory.join("audit.pub"),
        recovery_directory.join("break-glass.key"),
        recovery_directory.join("break-glass.pub"),
    ] {
        if path_present(&legacy)? {
            bail!(
                "legacy operator identity exists without an active generation; refuse ambiguous fresh install"
            )
        }
    }
    create_private_directory(operator_directory)?;
    create_private_directory(recovery_directory)?;
    repair_uncommitted_receipt_identity(operator_directory)?;
    ensure_static_identity_files(operator_directory)?;
    retire_generation_private_material(
        &layout.generations,
        None,
        &["controller.key", "audit.key"],
    )?;
    retire_generation_private_material(&layout.recovery_generations, None, &["break-glass.key"])?;
    let controller = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let audit = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let break_glass = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let active = new_active_identity(&controller, &audit, &break_glass);
    write_generation(&layout, &active, &controller, &audit, &break_glass)?;
    write_active_identity(&layout, &active)
}

fn repair_uncommitted_receipt_identity(directory: &Path) -> anyhow::Result<()> {
    let paths = [
        directory.join("receipt.key"),
        directory.join("receipt.pub"),
        directory.join("receipt.kid"),
    ];
    let present = paths
        .iter()
        .map(|path| path_present(path))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter(|present| *present)
        .count();
    if present == 0 || present == paths.len() {
        return Ok(());
    }
    for path in paths {
        remove_managed_regular_file(&path)?;
    }
    Ok(())
}

pub(crate) fn read_active_identity(path: &Path) -> anyhow::Result<ActiveIdentity> {
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "active identity record",
        true,
        64 * 1024,
    )?;
    let active: ActiveIdentity = serde_json::from_slice(&bytes)?;
    validate_active_identity(&active)?;
    Ok(active)
}

pub(crate) fn identity_layout(config: &UpdateConfig) -> anyhow::Result<IdentityLayout> {
    let active_file = if config.operator.active_identity_file.as_os_str().is_empty() {
        config
            .operator
            .controller_private_key
            .parent()
            .context("operator directory is unavailable")?
            .join("active-generation.json")
    } else {
        config.operator.active_identity_file.clone()
    };
    let operator_directory = active_file
        .parent()
        .context("active identity record has no operator directory")?
        .to_owned();
    let recovery_directory = config
        .operator
        .break_glass_private_key
        .parent()
        .context("recovery private key has no parent directory")?;
    Ok(IdentityLayout {
        generations: if config
            .operator
            .identity_generations_directory
            .as_os_str()
            .is_empty()
        {
            operator_directory.join("generations")
        } else {
            config.operator.identity_generations_directory.clone()
        },
        recovery_generations: if config
            .operator
            .recovery_generations_directory
            .as_os_str()
            .is_empty()
        {
            recovery_directory.join("generations")
        } else {
            config.operator.recovery_generations_directory.clone()
        },
        operator_directory,
        active_file,
    })
}

fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    crate::filesystem::ensure_directory_chain(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    crate::filesystem::set_mode(path, 0o700)
}

pub(crate) fn ensure_static_identity_files(directory: &Path) -> anyhow::Result<()> {
    for (name, private_mode) in [("deployment-id", 0o400), ("secret-revision", 0o400)] {
        let path = directory.join(name);
        if !path_present(&path)? {
            let value = if name == "deployment-id" {
                format!("deployment-{}", encode_hex(&rand::random::<[u8; 16]>()))
            } else {
                format!("secret-{}", encode_hex(&rand::random::<[u8; 16]>()))
            };
            atomic_write(&path, value.as_bytes(), private_mode)?;
        } else if !is_regular_non_symlink(&path)? || read_single_line(&path)?.len() > 128 {
            bail!(
                "static operator identity file is invalid: {}",
                path.display()
            )
        }
    }
    let private = directory.join("receipt.key");
    let public = directory.join("receipt.pub");
    let kid = directory.join("receipt.kid");
    if path_present(&private)? || path_present(&public)? || path_present(&kid)? {
        if !(is_regular_non_symlink(&private)?
            && is_regular_non_symlink(&public)?
            && is_regular_non_symlink(&kid)?)
        {
            bail!("incomplete receipt identity requires review")
        }
        let verifying = read_verifying_key(&public)?;
        let expected_kid = format!(
            "receipt-{}",
            &encode_hex(&Sha256::digest(verifying.to_bytes()))[..16]
        );
        if read_signing_key(&private)?.verifying_key() != verifying
            || read_single_line(&kid)? != expected_kid
        {
            bail!("receipt identity is inconsistent")
        }
        return Ok(());
    }
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public_bytes = key.verifying_key().to_bytes();
    let digest = encode_hex(&Sha256::digest(public_bytes));
    atomic_write(
        &private,
        URL_SAFE_NO_PAD.encode(key.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &public,
        URL_SAFE_NO_PAD.encode(public_bytes).as_bytes(),
        0o444,
    )?;
    atomic_write(&kid, format!("receipt-{}", &digest[..16]).as_bytes(), 0o444)
}

pub(crate) fn new_active_identity(
    controller: &SigningKey,
    audit: &SigningKey,
    break_glass: &SigningKey,
) -> ActiveIdentity {
    let controller_digest = encode_hex(&Sha256::digest(controller.verifying_key().to_bytes()));
    let audit_digest = encode_hex(&Sha256::digest(audit.verifying_key().to_bytes()));
    let break_glass_digest = encode_hex(&Sha256::digest(break_glass.verifying_key().to_bytes()));
    ActiveIdentity {
        schema: 1,
        generation: format!("generation-{}", &controller_digest[..24]),
        controller_key_id: format!("controller-{}", &controller_digest[..16]),
        audit_key_id: format!("audit-{}", &audit_digest[..16]),
        break_glass_key_id: format!("break-glass-{}", &break_glass_digest[..16]),
    }
}

pub(crate) fn validate_active_identity(active: &ActiveIdentity) -> anyhow::Result<()> {
    if active.schema != 1
        || !safe_identity_component(&active.generation)
        || !safe_identity_component(&active.controller_key_id)
        || !safe_identity_component(&active.audit_key_id)
        || !safe_identity_component(&active.break_glass_key_id)
    {
        bail!("active identity record is invalid")
    }
    Ok(())
}

pub(crate) fn generation_paths(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> (PathBuf, PathBuf) {
    (
        layout.generations.join(&active.generation),
        layout.recovery_generations.join(&active.generation),
    )
}

pub(crate) fn write_generation(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
    controller: &SigningKey,
    audit: &SigningKey,
    break_glass: &SigningKey,
) -> anyhow::Result<()> {
    validate_active_identity(active)?;
    let (generation, recovery_generation) = generation_paths(layout, active);
    if path_present(&generation)? || path_present(&recovery_generation)? {
        bail!("identity generation already exists")
    }
    create_private_directory(&generation)?;
    create_private_directory(&recovery_generation)?;
    atomic_write(
        &generation.join("controller.key"),
        URL_SAFE_NO_PAD.encode(controller.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("controller.pub"),
        URL_SAFE_NO_PAD
            .encode(controller.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    atomic_write(
        &generation.join("audit.key"),
        URL_SAFE_NO_PAD.encode(audit.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("audit.pub"),
        URL_SAFE_NO_PAD
            .encode(audit.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    atomic_write(
        &recovery_generation.join("break-glass.key"),
        URL_SAFE_NO_PAD.encode(break_glass.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("break-glass.pub"),
        URL_SAFE_NO_PAD
            .encode(break_glass.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    validate_generation(layout, active)
}

pub(crate) fn validate_generation(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    let controller_public = read_verifying_key(&generation.join("controller.pub"))?;
    let audit_public = read_verifying_key(&generation.join("audit.pub"))?;
    let break_glass_public = read_verifying_key(&generation.join("break-glass.pub"))?;
    if read_signing_key(&generation.join("controller.key"))?.verifying_key() != controller_public
        || read_signing_key(&generation.join("audit.key"))?.verifying_key() != audit_public
        || read_signing_key(&recovery_generation.join("break-glass.key"))?.verifying_key()
            != break_glass_public
        || active.controller_key_id
            != format!(
                "controller-{}",
                &encode_hex(&Sha256::digest(controller_public.to_bytes()))[..16]
            )
        || active.audit_key_id
            != format!(
                "audit-{}",
                &encode_hex(&Sha256::digest(audit_public.to_bytes()))[..16]
            )
        || active.break_glass_key_id
            != format!(
                "break-glass-{}",
                &encode_hex(&Sha256::digest(break_glass_public.to_bytes()))[..16]
            )
    {
        bail!("identity generation key material is inconsistent")
    }
    Ok(())
}

pub(crate) fn validate_generation_for_break_glass_recovery(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    let controller_public = read_verifying_key(&generation.join("controller.pub"))?;
    let audit_public = read_verifying_key(&generation.join("audit.pub"))?;
    let break_glass_public = read_verifying_key(&generation.join("break-glass.pub"))?;
    if read_signing_key(&generation.join("audit.key"))?.verifying_key() != audit_public
        || read_signing_key(&recovery_generation.join("break-glass.key"))?.verifying_key()
            != break_glass_public
        || active.controller_key_id
            != format!(
                "controller-{}",
                &encode_hex(&Sha256::digest(controller_public.to_bytes()))[..16]
            )
        || active.audit_key_id
            != format!(
                "audit-{}",
                &encode_hex(&Sha256::digest(audit_public.to_bytes()))[..16]
            )
        || active.break_glass_key_id
            != format!(
                "break-glass-{}",
                &encode_hex(&Sha256::digest(break_glass_public.to_bytes()))[..16]
            )
    {
        bail!("identity generation recovery material is inconsistent")
    }
    Ok(())
}

pub(crate) fn write_active_identity(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    validate_generation(layout, active)?;
    atomic_write(
        &layout.active_file,
        &serde_json::to_vec_pretty(active)?,
        0o600,
    )
}

pub(crate) fn apply_active_identity(
    config: &mut UpdateConfig,
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) {
    let (generation, recovery_generation) = generation_paths(layout, active);
    config.operator.controller_key_id = active.controller_key_id.clone();
    config.operator.controller_private_key = generation.join("controller.key");
    config.operator.controller_public_key = generation.join("controller.pub");
    config.operator.audit_key_id = active.audit_key_id.clone();
    config.operator.audit_private_key = generation.join("audit.key");
    config.operator.audit_public_key = generation.join("audit.pub");
    config.operator.break_glass_key_id = active.break_glass_key_id.clone();
    config.operator.break_glass_private_key = recovery_generation.join("break-glass.key");
    config.operator.break_glass_public_key = generation.join("break-glass.pub");
    config.operator.active_identity_file = layout.active_file.clone();
    config.operator.identity_generations_directory = layout.generations.clone();
    config.operator.recovery_generations_directory = layout.recovery_generations.clone();
}
