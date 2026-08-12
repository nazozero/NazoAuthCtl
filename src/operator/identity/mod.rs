use super::*;

mod adoption;
mod generation;
mod recovery;
mod rotation;

pub(super) use adoption::adopt_legacy_identity;
#[cfg(test)]
pub(super) use adoption::{
    ensure_only_expected_generation, refuse_ambiguous_legacy_adoption,
    remove_allowlisted_generation_directory, remove_uncommitted_generation,
};
#[cfg(test)]
pub(super) use generation::ensure_static_identity_files;
pub(crate) use generation::initialize_identity_generation;
pub(crate) use generation::read_active_identity;
pub(super) use generation::{
    apply_active_identity, generation_paths, identity_layout, new_active_identity,
    validate_active_identity, validate_generation, validate_generation_for_break_glass_recovery,
    write_active_identity, write_generation,
};
pub(crate) use recovery::{
    identity_recovery_required, recover_controller_without_controller_key,
    recover_pending_rotation, rehearse_controller_loss,
};
#[cfg(test)]
pub(super) use rotation::verify_retired_controller_probe_with;
pub(super) use rotation::{
    archive_generation_publics, generation_private_material_present,
    retire_generation_private_material, retire_non_active_private_material,
    rotate_controller_with_access, verify_rotation_intent,
};
pub(crate) use rotation::{
    recover_registered_rotation_locked, report_controller_availability, rotate_controller,
    rotate_registered_controller_with_access, verify_retired_controller_probe,
};

pub(super) fn safe_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

pub(super) fn path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

pub(super) fn is_real_directory_or_missing(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("{description} is not a real directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

pub(super) fn is_regular_non_symlink(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

pub(super) fn managed_regular_file_present(path: &Path) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "managed identity path is not a regular non-symlink file: {}",
            path.display()
        )
    }
    Ok(true)
}

pub(super) fn remove_managed_regular_file(path: &Path) -> anyhow::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "managed identity path is not a regular non-symlink file: {}",
            path.display()
        )
    }
    crate::filesystem::remove_file_durable(path)
}

pub(super) fn read_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(read_private_single_line(path)?)
        .context("operator private key is not canonical base64url")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(super) fn read_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = read_key(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid verifying key length"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid verifying key")
}

pub(super) fn read_key(path: &Path) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(read_single_line(path)?)
        .context("operator key is not canonical base64url")
}

fn read_private_single_line(path: &Path) -> anyhow::Result<String> {
    let bytes =
        crate::filesystem::read_secure_regular_file(path, "operator private key", true, 256)?;
    let value = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("operator private key is not UTF-8: {}", path.display()))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("operator private key is invalid: {}", path.display());
    }
    Ok(value)
}

pub(super) fn read_single_line(path: &Path) -> anyhow::Result<String> {
    let bytes =
        crate::filesystem::read_secure_regular_file(path, "operator identity file", false, 256)?;
    let value = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("operator identity file is not UTF-8: {}", path.display()))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("operator identity file is invalid: {}", path.display());
    }
    Ok(value)
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn trusted_controller_key(
    config: &UpdateConfig,
    key_id: &str,
) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.controller_key_id {
        return read_verifying_key(&config.operator.controller_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
        .join("trusted-controllers");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

pub(crate) fn trusted_audit_key(
    config: &UpdateConfig,
    key_id: &str,
) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.audit_key_id {
        return read_verifying_key(&config.operator.audit_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
        .join("trusted-audit");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

pub(super) fn trusted_break_glass_key(
    config: &UpdateConfig,
    key_id: &str,
) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.break_glass_key_id {
        return read_verifying_key(&config.operator.break_glass_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
        .join("trusted-break-glass");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}
