//! Descriptor-bound runtime identity verification.
//!
//! The long-lived deployment statement is never a trust root by itself: it is
//! verified under the instance public key read from its descriptor-bound host
//! projection. This module owns that boundary for the conformance session
//! wiring.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ed25519_dalek::VerifyingKey;
use nazo_operator_protocol::{
    DeploymentStatement, decode_instance_public_key, protected_header, verify_deployment_statement,
};

#[cfg(unix)]
use crate::filesystem::read_secure_regular_file_for_uid;

use crate::{
    filesystem::read_secure_regular_file,
    runtime_backend::{RuntimeBackendKind, RuntimeObservation},
};

pub(crate) struct VerifiedRuntimeIdentity {
    pub(crate) statement: DeploymentStatement,
    pub(crate) public_key: VerifyingKey,
}

/// Load the runtime identity only from its descriptor-bound host projection.
/// The network discovery response is intentionally not a trust root: the
/// long-lived deployment statement must verify under the locally mounted
/// instance public key.
pub(crate) fn verified_runtime_identity_for_uid(
    runtime: &RuntimeObservation,
    expected_owner_uid: u32,
) -> anyhow::Result<VerifiedRuntimeIdentity> {
    let host_identity_dir = runtime_identity_host_directory(runtime)?
        .context("runtime exposes no descriptor-bound instance identity directory")?;
    load_verified_runtime_identity(&host_identity_dir, Some(expected_owner_uid))
}

fn load_verified_runtime_identity(
    host_identity_dir: &Path,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<VerifiedRuntimeIdentity> {
    let statement_path = host_identity_dir.join("deployment-statement.jws");
    let public_key_path = host_identity_dir.join("identity.pub");
    let statement = read_bounded_for_owner(&statement_path, 64 * 1024, expected_owner_uid)?;
    let public_key = read_bounded_for_owner(&public_key_path, 1024, expected_owner_uid)?;
    let public_key = decode_instance_public_key(public_key.trim())?;
    let header = protected_header(statement.trim())?;
    let statement = verify_deployment_statement(statement.trim(), &header.kid, &public_key)?;
    Ok(VerifiedRuntimeIdentity {
        statement,
        public_key,
    })
}

fn runtime_identity_host_directory(
    runtime: &RuntimeObservation,
) -> anyhow::Result<Option<PathBuf>> {
    let data_dir = runtime.safe_environment.get("DATA_DIR").map(PathBuf::from);
    let Some(identity_dir) = runtime
        .safe_environment
        .get("INSTANCE_IDENTITY_DIR")
        .map(PathBuf::from)
        .or_else(|| data_dir.map(|path| path.join("instance")))
        .or_else(|| {
            (runtime.backend != RuntimeBackendKind::Systemd)
                .then(|| PathBuf::from("/var/lib/nazo_oauth/instance"))
        })
    else {
        return Ok(None);
    };
    Ok(map_runtime_path(runtime, &identity_dir))
}

fn map_runtime_path(runtime: &RuntimeObservation, runtime_path: &Path) -> Option<PathBuf> {
    if runtime.backend == RuntimeBackendKind::Systemd {
        return Some(runtime_path.to_owned());
    }
    runtime.mounts.iter().find_map(|mount| {
        let relative = runtime_path.strip_prefix(&mount.destination).ok()?;
        Some(mount.source.join(relative))
    })
}

fn read_bounded_for_owner(
    path: &Path,
    maximum: u64,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<String> {
    #[cfg(unix)]
    let bytes = match expected_owner_uid {
        Some(expected_owner_uid) => read_secure_regular_file_for_uid(
            path,
            "instance identity evidence",
            false,
            maximum,
            expected_owner_uid,
        )?,
        None => read_secure_regular_file(path, "instance identity evidence", false, maximum)?,
    };
    #[cfg(not(unix))]
    let bytes = {
        let _ = expected_owner_uid;
        read_secure_regular_file(path, "instance identity evidence", false, maximum)?
    };
    String::from_utf8(bytes.to_vec()).context("instance identity evidence is not valid UTF-8")
}
