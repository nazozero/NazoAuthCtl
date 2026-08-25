//! Deployment-stable machine identity paths and read-only runtime privilege
//! verification.
//!
//! The legacy fresh-install pipeline was removed with the J-A wave; clean
//! installation is owned by [`crate::clean_install`] and the target executors.
//! What remains here serves the conformance session wiring (tenant-resource
//! controller identity) and `doctor` (runtime DDL privilege check).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;

use crate::{model::UpdateConfig, secret_provider::PostgresProvider};

const TENANT_RESOURCE_CONTROLLER_PRIVATE_FILE: &str = "tenant-resource-controller.key";
const TENANT_RESOURCE_CONTROLLER_PUBLIC_FILE: &str = "tenant-resource-controller.pub";
const TENANT_RESOURCE_CONTROLLER_KEY_ID_FILE: &str = "tenant-resource-controller.kid";

pub(crate) fn tenant_resource_controller_private_key_path(config_dir: &Path) -> PathBuf {
    config_dir
        .join("operator")
        .join(TENANT_RESOURCE_CONTROLLER_PRIVATE_FILE)
}

pub(crate) fn tenant_resource_controller_public_key_path(config_dir: &Path) -> PathBuf {
    config_dir
        .join("operator")
        .join(TENANT_RESOURCE_CONTROLLER_PUBLIC_FILE)
}

pub(crate) fn tenant_resource_controller_key_id_path(config_dir: &Path) -> PathBuf {
    config_dir
        .join("operator")
        .join(TENANT_RESOURCE_CONTROLLER_KEY_ID_FILE)
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

/// Confirm the managed runtime account still owns its database schema without
/// holding DDL privileges that an update could silently abuse.
pub(crate) fn verify_runtime_no_ddl(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.dependencies.mode != "managed" {
        eprintln!(
            "doctor: external PostgreSQL privileges are operator-owned and were not modified"
        );
        return Ok(());
    }
    let postgres = PostgresProvider::from_url_file(&config.dependencies.database_url_file)?;
    crate::runtime_backend::backend(
        config
            .container_backend()
            .context("managed PostgreSQL requires a container backend")?,
    )
    .verify_runtime_database_privileges(
        &crate::runtime_backend::RuntimeDatabasePrivilegeProbe {
            network: config.runtime.network.clone(),
            service_file: postgres.service_file().to_owned(),
            password_file: postgres.password_file().to_owned(),
            image: config.postgres.validation_image.clone(),
        },
    )
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}
