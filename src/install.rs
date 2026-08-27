//! Deployment-stable machine identity paths for the conformance session
//! wiring (tenant-resource controller identity).
//!
//! The legacy fresh-install pipeline was removed with the J-A wave; clean
//! installation is owned by [`crate::clean_install`] and the target executors.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;

const TENANT_RESOURCE_CONTROLLER_PRIVATE_FILE: &str = "tenant-resource-controller.key";
pub(crate) fn tenant_resource_controller_private_key_path(config_dir: &Path) -> PathBuf {
    config_dir
        .join("operator")
        .join(TENANT_RESOURCE_CONTROLLER_PRIVATE_FILE)
}

pub(crate) fn read_tenant_resource_controller_signing_key(
    path: &Path,
) -> anyhow::Result<SigningKey> {
    let encoded = crate::filesystem::read_secure_regular_file(
        path,
        "tenant-resource controller private key",
        true,
        256,
    )?;
    if encoded.is_empty() || encoded.contains(&b'\n') || encoded.contains(&b'\r') {
        bail!("tenant-resource controller private key is invalid");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_slice())
        .context("tenant-resource controller private key is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&decoded).as_bytes() != encoded.as_slice() {
        bail!("tenant-resource controller private key is not canonical base64url");
    }
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        anyhow::anyhow!("tenant-resource controller private key has invalid length")
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}
