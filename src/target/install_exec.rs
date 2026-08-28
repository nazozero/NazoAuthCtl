//! Target-side execution of the clean-install order (goal plan 07, task G01).
//!
//! A [`HostOperation`] of kind `state-mutate` whose [`Bootstrap`] mutation
//! carries an [`InstallOrder`] makes the target perform the complete fresh
//! install inside the one journaled operation: verify the official artifact,
//! write the configuration atomically, provision target-local secrets and the
//! fresh-install bootstrap capability, start the runtime, confirm it serves
//! exactly the verified artifact, and probe local health. Only then does the
//! dispatcher commit the DeploymentState as `local healthy / control unbound`.
//!
//! Artifact transfer decision (recorded per the task brief): verified bytes
//! are **obtained on the target** ("download-on-target"), reusing the same
//! verified-artifact pipeline used by update on the target. The control side
//! sends only reference facts (repository and optional version pin);
//! multi-hundred-megabyte blobs never
//! cross the 64 KiB HostOperation wire, and secrets are generated on the
//! target so they never leave it.
//!
//! The executor is an injected seam ([`InstallExecutor`]): production uses
//! [`HostInstallExecutor`], tests substitute a scripted double so container
//! engine calls never run on development machines. Every step is resumable by
//! re-execution (idempotent writes, start-if-needed) because the C07 journal
//! replays interrupted operations; on failure the executor rolls back its own
//! partial work before returning the stable [`INSTALL_FAILED`] family code.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::{self, atomic_write},
    process::Process,
    runtime_backend::{self, RuntimeBackendKind},
};

use super::{
    bootstrap_authority,
    deployment_state::{Failure, INSTALL_FAILED, RuntimeSurface},
    wire::{HOST_ERR_OPERATION_INVALID, InstanceInspection, sanitize},
};

/// Stable failure codes for the clean-install sequence. All abort before or
/// roll back to a pre-install target; none ever leave partial state behind.
pub const ARTIFACT_UNVERIFIED: &str = "ARTIFACT_UNVERIFIED";
pub const CONFIG_PATH_OCCUPIED: &str = "CONFIG_PATH_OCCUPIED";
pub const CONFIG_INVALID: &str = "CONFIG_INVALID";
pub const SECRET_PROVISION_FAILED: &str = "SECRET_PROVISION_FAILED";
pub const RUNTIME_START_FAILED: &str = "RUNTIME_START_FAILED";
pub const TARGET_IDENTITY_MISMATCH: &str = "TARGET_IDENTITY_MISMATCH";
pub const HEALTH_PROBE_FAILED: &str = "HEALTH_PROBE_FAILED";
pub(crate) const LOCAL_READINESS_PATH: &str = "/health";
/// Cleanup could not prove whether the install still owns live resources.
/// The target journal deliberately keeps this operation pending and the
/// control-side prepared-install pointer must be retained for exact replay.
pub const INSTALL_OUTCOME_UNKNOWN: &str = "OUTCOME_UNKNOWN";

/// Closed vocabulary of secret files written on the target. External
/// dependency credentials are supplied by the operator and cross a remote
/// boundary only inside the encrypted host protocol; the MFA key is generated
/// on the target.
pub const SECRET_PURPOSES: &[&str] = &[
    "database-runtime-url",
    "database-lifecycle-url",
    "valkey-url",
    "mfa-totp-key",
];

/// Hard cap for the rendered config content riding inside one HostOperation
/// (the whole operation must stay under `MAX_HOST_OPERATION_BYTES`).
pub const MAX_CONFIG_CONTENT_BYTES: usize = 32 * 1024;

// Container-internal contract frozen with NazoAuth's configuration loader:
// the server loads `.env.yaml` (or `NAZOAUTH_SERVER_CONFIG_FILE`) at startup,
// resolves secret files by path, and persists under DATA_DIR. The control
// side renders these exact references into the seed configuration and mounts
// the host facts onto exactly these destinations.
/// Configuration file inside the container (`WORKDIR /app`).
pub const CONTAINER_CONFIG_FILE: &str = "/app/.env.yaml";
/// Read-only mount point for the target-local secret files.
pub const CONTAINER_SECRETS_DIR: &str = "/run/secrets";
/// Persistent data directory inside the container.
pub const CONTAINER_DATA_DIR: &str = "/var/lib/nazo_oauth";
/// NazoAuth environment key overriding the configuration file location.
pub const SERVER_CONFIG_FILE_ENV: &str = "NAZOAUTH_SERVER_CONFIG_FILE";

/// The official artifact a fresh install obtains and verifies on the target.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialArtifactRef {
    /// Signed-release repository, e.g. `nazozero/NazoAuth`.
    pub repository: String,
    /// Immutable semantic tag; absent means "latest official Release".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One target-local secret file: purpose token + absolute path. External
/// credentials come from the operator; the MFA key is generated on the
/// target. The rendered server config references every secret by path.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSecret {
    /// One of [`SECRET_PURPOSES`].
    pub purpose: String,
    pub path: String,
    /// P0-1: operator-provided credential content for external-dependency
    /// URLs (the two PostgreSQL roles and Valkey). The external roles and
    /// Valkey ACL already know these values — ctl never invents them. Absent
    /// for target-minted material (`mfa-totp-key`). Rides the encrypted
    /// transport exactly once; the journal directory is root-only 0700.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<super::wire::SecretMaterial>,
}

/// Optional current-format material copied entirely on the target before the
/// first runtime start. It is path-only wire data, never imported bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentDataImport {
    pub source_data_root: String,
    pub source_mfa_key_file: String,
}

/// New configuration content staged by an update (G03). Values follow the
/// same rules as the install order's config: bounded content plus the exact
/// SHA-256 over its bytes so wire corruption can never reach disk. The
/// declared `schema` token is what makes a later rollback decision possible:
/// the update's config snapshot records both the replaced and the replacing
/// schema, and rollback restores the snapshot only while the deployment still
/// runs the replacing schema (goal plan 07 §5).
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedConfig {
    pub content: String,
    pub sha256: String,
    pub schema: String,
}

impl StagedConfig {
    /// Admission-level checks shared by wire validation and executors.
    pub fn validate(&self) -> Result<(), super::wire::MessageRejection> {
        if self.content.is_empty() || self.content.len() > MAX_CONFIG_CONTENT_BYTES {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                format!("update config content must be 1-{MAX_CONFIG_CONTENT_BYTES} bytes"),
            ));
        }
        if !valid_lower_hex_sha256(&self.sha256) {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "update config sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        crate::registry::validate_identifier(&self.schema, 64, "update config schema").map_err(
            |error| {
                super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    error.to_string(),
                )
            },
        )?;
        Ok(())
    }
}

/// One concrete resource deletion planned by an uninstall (G06). The pair is
/// re-confirmed against the live DeploymentState on the target before any
/// destructive step; a mismatch fails closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedResourceDeletion {
    pub resource_id: String,
    /// Exact locator copied from the plan; must equal the declared locator.
    pub locator: String,
}

impl PlannedResourceDeletion {
    pub fn validate(&self) -> Result<(), super::wire::MessageRejection> {
        let token = |value: &str, max: usize| {
            !value.is_empty()
                && value.chars().count() <= max
                && value
                    .chars()
                    .all(|character| character.is_ascii_graphic() && character != ' ')
        };
        if !token(&self.resource_id, 128) {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "uninstall resource_id must be a bounded single-line identifier",
            ));
        }
        if self.locator.is_empty()
            || self.locator.len() > 512
            || self
                .locator
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "uninstall resource locator must be a single-line reference",
            ));
        }
        Ok(())
    }
}

/// The typed payload carrying everything the target needs to execute one
/// clean install (G01). Rides inside the `Bootstrap` state mutation, so the
/// C07 journal binds the exact order to the operation id via its canonical
/// hash — a tampered order is a conflict, not a retry.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallOrder {
    pub artifact: OfficialArtifactRef,
    /// Complete rendered server configuration. Secret *values* appear only
    /// as file references; written atomically at the Bootstrap mutation's
    /// `config_reference` path.
    pub config_content: String,
    /// SHA-256 over the exact `config_content` bytes; checked before the
    /// atomic write so a wire-level corruption can never reach disk.
    pub config_sha256: String,
    /// Absolute directories/files the deployment owns (managed facts).
    pub data_root: String,
    /// Permanent binary directory for the systemd host runtime. Absent for
    /// container runtimes, whose executable lives inside the verified image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_root: Option<String>,
    /// Target-local secret files backing the config references.
    pub secrets: Vec<PlannedSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_data_import: Option<CurrentDataImport>,
    /// G02 hook: provision the single-use initial-admin bootstrap capability
    /// bound to this exact install operation id.
    pub fresh_bootstrap: bool,
    /// External PostgreSQL endpoint facts supplied by the operator (G01 item
    /// 3: real external facts are the only install inputs). Credentials live
    /// in the matching planned secret entries, not in this public endpoint.
    pub database_runtime_endpoint: ExternalEndpoint,
    pub database_lifecycle_endpoint: ExternalEndpoint,
    /// External Valkey endpoint facts supplied by the operator.
    pub valkey_endpoint: ExternalEndpoint,
}

/// Operator-supplied coordinates of one external dependency. Credential
/// material is carried separately in the matching planned secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEndpoint {
    pub host: String,
    pub port: u16,
    /// PostgreSQL database name; unused by Valkey.
    pub name: String,
    /// PostgreSQL role name; unused by Valkey.
    pub user: String,
}

impl InstallOrder {
    /// Enforce every invariant dispatch relies on. Called from
    /// `HostOperation::validate` so malformed orders fail at admission.
    pub fn validate(&self) -> Result<(), super::wire::MessageRejection> {
        for (label, endpoint) in [
            (
                "database runtime endpoint host",
                &self.database_runtime_endpoint.host,
            ),
            (
                "database lifecycle endpoint host",
                &self.database_lifecycle_endpoint.host,
            ),
            ("valkey endpoint host", &self.valkey_endpoint.host),
        ] {
            if endpoint.is_empty() || endpoint.len() > 253 {
                return Err(super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    format!("{label} must be 1-253 characters"),
                ));
            }
        }
        if self.database_runtime_endpoint.port == 0
            || self.database_lifecycle_endpoint.port == 0
            || self.valkey_endpoint.port == 0
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "external dependency ports must be non-zero",
            ));
        }
        let postgres_token = |value: &str| {
            !value.is_empty()
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        };
        if !postgres_token(&self.database_runtime_endpoint.name)
            || !postgres_token(&self.database_runtime_endpoint.user)
            || !postgres_token(&self.database_lifecycle_endpoint.name)
            || !postgres_token(&self.database_lifecycle_endpoint.user)
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "PostgreSQL database and role names must be bounded alphanumeric tokens",
            ));
        }
        if self.config_content.is_empty() || self.config_content.len() > MAX_CONFIG_CONTENT_BYTES {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                format!("install config content must be 1-{MAX_CONFIG_CONTENT_BYTES} bytes"),
            ));
        }
        if !valid_lower_hex_sha256(&self.config_sha256) {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install config_sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        if !safe_absolute_install_path(&self.data_root) {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install data_root must be a bounded absolute path",
            ));
        }
        if self
            .runtime_root
            .as_ref()
            .is_some_and(|path| !safe_absolute_install_path(path))
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install runtime_root must be a bounded absolute path",
            ));
        }
        if self.database_runtime_endpoint.host != self.database_lifecycle_endpoint.host
            || self.database_runtime_endpoint.port != self.database_lifecycle_endpoint.port
            || self.database_runtime_endpoint.name != self.database_lifecycle_endpoint.name
            || self.database_runtime_endpoint.user == self.database_lifecycle_endpoint.user
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install requires distinct runtime/lifecycle roles for one PostgreSQL database",
            ));
        }
        if let Some(import) = &self.current_data_import
            && (!safe_absolute_install_path(&import.source_data_root)
                || !safe_absolute_install_path(&import.source_mfa_key_file)
                || import.source_data_root == self.data_root
                || Path::new(&import.source_mfa_key_file).starts_with(&self.data_root))
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "current data import requires distinct bounded absolute target paths",
            ));
        }
        if self.secrets.len() != SECRET_PURPOSES.len() {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install must declare the complete closed secret purpose set",
            ));
        }
        let mut seen = Vec::with_capacity(self.secrets.len());
        for secret in &self.secrets {
            if !SECRET_PURPOSES.contains(&secret.purpose.as_str()) || seen.contains(&secret.purpose)
            {
                return Err(super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    format!(
                        "install secret purpose '{}' is outside the closed set or duplicated",
                        sanitize(secret.purpose.clone())
                    ),
                ));
            }
            if !safe_absolute_install_path(&secret.path)
                || Path::new(&secret.path).parent().is_none()
            {
                return Err(super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    "install secret path must be a bounded absolute path",
                ));
            }
            let should_carry_value = secret.purpose != "mfa-totp-key";
            if secret.value.is_some() != should_carry_value {
                return Err(super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    "only external dependency URL secrets carry operator material",
                ));
            }
            seen.push(secret.purpose.clone());
        }
        // The runtime mounts exactly one read-only secrets directory; the
        // rendered configuration references every file through it.
        if let Some((first, rest)) = self.secrets.split_first()
            && let Some(shared) = Path::new(&first.path).parent()
            && rest
                .iter()
                .any(|secret| Path::new(&secret.path).parent() != Some(shared))
        {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install secret files must live in one shared host directory",
            ));
        }
        Ok(())
    }
}

fn valid_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_absolute_install_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 512
        && (path.is_absolute() || value.starts_with('/'))
        && !value.chars().any(char::is_control)
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

const MAX_IMPORT_FILES: usize = 100_000;
const MAX_IMPORT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_IMPORT_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const IMPORT_APP_SECRETS: &[&str] = &[
    "client-secret-pepper",
    "dynamic-client-registration-initial-access-token",
    "token-issuance-response-encryption-key",
];

fn import_current_data(source: &Path, destination: &Path) -> Result<(), Failure> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    if !source_metadata.is_dir() || source_metadata.file_type().is_symlink() {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            "--import-data-root must be a real target-local directory",
        ));
    }
    let source = fs::canonicalize(source)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    let destination = fs::canonicalize(destination)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    if source == destination || source.starts_with(&destination) || destination.starts_with(&source)
    {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            "current data import source and managed data root must be disjoint",
        ));
    }

    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    let source_keys = source.join("keys");
    if !source_keys.exists() {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            "current data import requires the source keys directory",
        ));
    }
    copy_import_tree(
        &source_keys,
        &destination.join("keys"),
        &mut file_count,
        &mut total_bytes,
    )?;
    let source_avatars = source.join("avatars");
    if source_avatars.exists() {
        copy_import_tree(
            &source_avatars,
            &destination.join("avatars"),
            &mut file_count,
            &mut total_bytes,
        )?;
    }
    for name in IMPORT_APP_SECRETS {
        let source_file = source.join("secrets").join(name);
        let destination_file = destination.join("secrets").join(name);
        copy_import_regular(
            &source_file,
            &destination_file,
            &mut file_count,
            &mut total_bytes,
            0o600,
        )?;
    }
    Ok(())
}

fn copy_import_tree(
    source: &Path,
    destination: &Path,
    file_count: &mut usize,
    total_bytes: &mut u64,
) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            format!("{} must be a real directory", source.display()),
        ));
    }
    if destination.exists() {
        let destination_metadata = fs::symlink_metadata(destination)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
        if !destination_metadata.is_dir() || destination_metadata.file_type().is_symlink() {
            return Err(Failure::new(
                SECRET_PROVISION_FAILED,
                format!(
                    "{} is not a real destination directory",
                    destination.display()
                ),
            ));
        }
    } else {
        fs::create_dir(destination)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    }

    let mut source_names = std::collections::BTreeSet::new();
    let entries = fs::read_dir(source)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
        let name = entry.file_name();
        source_names.insert(name.clone());
        let source_path = entry.path();
        let destination_path = destination.join(name);
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
        if metadata.file_type().is_symlink() {
            return Err(Failure::new(
                SECRET_PROVISION_FAILED,
                format!(
                    "current data import rejects symlink {}",
                    source_path.display()
                ),
            ));
        }
        if metadata.is_dir() {
            copy_import_tree(&source_path, &destination_path, file_count, total_bytes)?;
        } else if metadata.is_file() {
            copy_import_regular(
                &source_path,
                &destination_path,
                file_count,
                total_bytes,
                0o600,
            )?;
        } else {
            return Err(Failure::new(
                SECRET_PROVISION_FAILED,
                format!(
                    "current data import rejects special file {}",
                    source_path.display()
                ),
            ));
        }
    }
    let destination_entries = fs::read_dir(destination)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    for entry in destination_entries {
        let entry = entry
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
        if !source_names.contains(&entry.file_name()) {
            return Err(Failure::new(
                SECRET_PROVISION_FAILED,
                format!(
                    "current data import destination contains material absent from the source: {}",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
}

fn copy_import_regular(
    source: &Path,
    destination: &Path,
    file_count: &mut usize,
    total_bytes: &mut u64,
    mode: u32,
) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            format!("{} must be a real regular file", source.display()),
        ));
    }
    if metadata.len() > MAX_IMPORT_FILE_BYTES {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            format!(
                "current data import file exceeds 256 MiB: {}",
                source.display()
            ),
        ));
    }
    *file_count += 1;
    *total_bytes = total_bytes.saturating_add(metadata.len());
    if *file_count > MAX_IMPORT_FILES || *total_bytes > MAX_IMPORT_TOTAL_BYTES {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            "current data import exceeds its 100000-file/4-GiB bound",
        ));
    }
    if let Some(parent) = destination.parent() {
        filesystem::ensure_directory_chain(parent)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    }
    if destination.exists() {
        let destination_metadata = fs::symlink_metadata(destination)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
        if !destination_metadata.is_file()
            || destination_metadata.file_type().is_symlink()
            || destination_metadata.len() != metadata.len()
            || filesystem::sha256(destination).map_err(|error| {
                Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
            })? != filesystem::sha256(source).map_err(|error| {
                Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
            })?
        {
            return Err(Failure::new(
                SECRET_PROVISION_FAILED,
                format!(
                    "current data import destination differs from source: {}",
                    destination.display()
                ),
            ));
        }
        return Ok(());
    }
    let mut source_file =
        filesystem::open_secure_regular_file(source, "current data import", false)
            .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    filesystem::copy_atomic_from_file(&mut source_file, destination, mode)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))
}

fn copy_import_file(source: &Path, destination: &Path, label: &str) -> Result<(), Failure> {
    let bytes = filesystem::read_secure_regular_file(source, label, false, 128)
        .map_err(|error| Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string())))?;
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&bytes[..end])
        .map_err(|_| Failure::new(SECRET_PROVISION_FAILED, "imported MFA key is not base64url"))?;
    if decoded.len() != 32 {
        return Err(Failure::new(
            SECRET_PROVISION_FAILED,
            "imported MFA key must decode to exactly 32 bytes",
        ));
    }
    let mut count = 0;
    let mut bytes = 0;
    copy_import_regular(source, destination, &mut count, &mut bytes, 0o440)
        .map_err(|failure| Failure::new(failure.code, format!("{label}: {}", failure.detail)))
}

/// Everything the executor needs besides the order itself. Built by dispatch
/// from the accepted operation; never serialized.
pub(crate) struct InstallJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    /// The single validated runtime fact source from the Bootstrap surface.
    pub runtime: &'a RuntimeSurface,
    pub config_reference: &'a str,
    /// `<state root>/deployments/<deployment id>/` — where the fresh-install
    /// bootstrap context and token live beside the journal.
    pub scope_dir: &'a Path,
    pub order: &'a InstallOrder,
}

/// What a completed install reports back to the dispatcher: the content-
/// addressed digest handle recorded into `DeploymentState.artifact.current`
/// plus the verified manifest's embedded build identity facts (the G03
/// ControlOperation envelope binding source).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InstallFacts {
    pub artifact_reference: String,
    pub build_identity: Option<super::deployment_state::BuildIdentity>,
    pub rollback_policy: crate::model::ReleaseRollbackPolicy,
}

/// The injectable seam executing one clean-install order on the target.
///
/// Contract: resumable by re-execution. The executor retains its exact
/// performed-step receipt until `commit` has durably published the matching
/// DeploymentState; any execution or commit failure is rolled back before an
/// ordinary `Err` is returned. Incomplete cleanup returns
/// [`INSTALL_OUTCOME_UNKNOWN`] so the same operation can be replayed.
pub(crate) trait InstallExecutor: Send + Sync {
    fn execute_install(
        &self,
        job: &InstallJob<'_>,
        commit: &mut dyn FnMut(&InstallFacts) -> Result<InstanceInspection, Failure>,
    ) -> Result<InstanceInspection, Failure>;
}

/// Production executor backed by the real adapters: the H01/H02 official
/// verification pipeline, the runtime backend trait, the shared filesystem
/// primitives, and the fresh-bootstrap authority.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostInstallExecutor;

impl InstallExecutor for HostInstallExecutor {
    fn execute_install(
        &self,
        job: &InstallJob<'_>,
        commit: &mut dyn FnMut(&InstallFacts) -> Result<InstanceInspection, Failure>,
    ) -> Result<InstanceInspection, Failure> {
        let mut performed = PerformedSteps::default();
        match self.run(job, &mut performed) {
            Ok(facts) => commit(&facts)
                .map_err(|failure| rollback_or_outcome_unknown(job, &performed, failure)),
            Err(failure) => Err(rollback_or_outcome_unknown(job, &performed, failure)),
        }
    }
}

pub(crate) fn rollback_or_outcome_unknown(
    job: &InstallJob<'_>,
    performed: &PerformedSteps,
    failure: Failure,
) -> Failure {
    match rollback(job, performed) {
        Ok(()) => failure,
        Err(cleanup) => Failure::new(
            INSTALL_OUTCOME_UNKNOWN,
            format!(
                "{}; install rollback was incomplete: {}",
                failure.detail, cleanup.detail
            ),
        ),
    }
}

/// Steps an executor has durably performed, driving precise rollback.
/// Visible to the scripted test executors so rollback semantics exist exactly
/// once for production and tests alike.
#[derive(Default)]
pub(crate) struct PerformedSteps {
    pub(crate) wrote_config: bool,
    pub(crate) wrote_config_marker: bool,
    pub(crate) generated_secrets: Vec<String>,
    pub(crate) provisioned_bootstrap: bool,
    pub(crate) installed_runtime: bool,
    pub(crate) started_runtime: bool,
    pub(crate) created_directories: Vec<PathBuf>,
}

impl HostInstallExecutor {
    fn run(
        &self,
        job: &InstallJob<'_>,
        performed: &mut PerformedSteps,
    ) -> Result<InstallFacts, Failure> {
        let config_path = PathBuf::from(job.config_reference);
        if !safe_absolute_install_path(job.config_reference) {
            return Err(Failure::new(
                CONFIG_INVALID,
                "clean install requires an absolute configuration path without traversal",
            ));
        }
        let config_owned = PathBuf::from(format!("{}.nazoauth-owned", config_path.display()));
        let config_metadata = std::fs::symlink_metadata(&config_path).ok();
        let config_or_marker_exists =
            config_metadata.is_some() || std::fs::symlink_metadata(&config_owned).is_ok();
        if config_or_marker_exists
            && (!config_metadata
                .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
                || !ownership_marker_matches(&config_owned, job.deployment_id))
        {
            return Err(Failure::new(
                CONFIG_PATH_OCCUPIED,
                format!(
                    "{} exists without this install operation's ownership proof",
                    config_path.display()
                ),
            ));
        }

        let secret_root = job
            .order
            .secrets
            .first()
            .and_then(|secret| Path::new(&secret.path).parent())
            .ok_or_else(|| {
                Failure::new(
                    SECRET_PROVISION_FAILED,
                    "clean install requires one explicit secrets directory",
                )
            })?
            .to_path_buf();
        let config_dir = config_path.parent().ok_or_else(|| {
            Failure::new(
                CONFIG_INVALID,
                "clean-install configuration path requires a deployment directory",
            )
        })?;
        let mut managed_directories = vec![
            config_dir.to_path_buf(),
            PathBuf::from(&job.order.data_root),
            secret_root,
        ];
        if let Some(runtime_root) = &job.order.runtime_root {
            managed_directories.push(PathBuf::from(runtime_root));
        }
        for (index, path) in managed_directories.iter().enumerate() {
            if let Ok(metadata) = std::fs::symlink_metadata(path)
                && (!metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || !ownership_marker_matches(&path.join(".nazoauth-owned"), job.deployment_id))
            {
                return Err(Failure::new(
                    CONFIG_PATH_OCCUPIED,
                    format!(
                        "{} exists without this install operation's ownership proof",
                        path.display()
                    ),
                ));
            }
            if managed_directories
                .iter()
                .enumerate()
                .any(|(other_index, other)| {
                    index != other_index && (path.starts_with(other) || other.starts_with(path))
                })
            {
                return Err(Failure::new(
                    CONFIG_INVALID,
                    "clean-install config, data, secrets, and runtime paths must be disjoint",
                ));
            }
        }

        // 1. Official artifact: verify first, use afterwards (H01 single entry).
        let kind = job.runtime.kind;
        require_loopback_port_available(kind, &job.runtime.object, job.runtime.loopback_port)?;
        for (label, endpoint) in [
            ("database runtime", &job.order.database_runtime_endpoint),
            ("database lifecycle", &job.order.database_lifecycle_endpoint),
            ("Valkey", &job.order.valkey_endpoint),
        ] {
            validate_endpoint_reachability(kind, label, &endpoint.host)?;
        }
        let verified = super::update_exec::verify_pinned_artifact_facts(
            &job.order.artifact,
            kind,
            None,
            job.order.runtime_root.as_deref(),
        )?;
        let subject_digest = verified.digest.clone();

        for directory in &managed_directories {
            prepare_owned_directory(directory, job.deployment_id, performed)?;
        }

        // 2. Atomic config write with integrity check.
        let content_bytes = job.order.config_content.as_bytes();
        if valid_lower_hex_sha256(&job.order.config_sha256) {
            let digest = sha256_hex(content_bytes);
            if digest != job.order.config_sha256 {
                return Err(Failure::new(
                    CONFIG_INVALID,
                    "config content does not match its declared digest",
                ));
            }
        }
        atomic_write(&config_path, content_bytes, 0o600)
            .map_err(|error| Failure::new(CONFIG_INVALID, sanitize(error.to_string())))?;
        performed.wrote_config = true;
        // The container reads this file as the image's fixed runtime UID;
        // bind mounts keep host ownership, so hand it over group-readable.
        if kind.is_container() {
            set_runtime_identity(&config_path, false)?;
        }
        // P1-1: the deletion credential for the uninstall executor — proves
        // ctl created this exact file during install.
        atomic_write(&config_owned, job.deployment_id.as_bytes(), 0o440).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!("failed to write config ownership marker: {error}")),
            )
        })?;
        performed.wrote_config_marker = true;

        // 3. Target-local secrets. External dependency credentials were
        // supplied by the operator; only the new MFA key is minted here.
        for secret in &job.order.secrets {
            let path = PathBuf::from(&secret.path);
            let existed = path.exists();
            if existed {
                filesystem::open_secure_regular_file(&path, "resumed install secret", false)
                    .map_err(|error| {
                        Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
                    })?;
            }
            match secret.purpose.as_str() {
                // The server decodes this key with base64url-no-pad and
                // requires exactly 32 bytes (settings.rs
                // parse_required_32_byte_key); hex would fail that contract.
                "mfa-totp-key" => {
                    if let Some(import) = &job.order.current_data_import {
                        copy_import_file(
                            Path::new(&import.source_mfa_key_file),
                            &path,
                            "imported MFA key",
                        )?;
                    } else if !existed {
                        use base64::Engine as _;
                        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(rand::random::<[u8; 32]>());
                        atomic_write(&path, value.as_bytes(), 0o440).map_err(|error| {
                            Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
                        })?;
                    }
                }
                // URL-shaped values combine operator-supplied endpoint facts
                // with the operator-provided external credential (P0-1): the
                // PostgreSQL role and Valkey ACL already know this password,
                // so ctl must never invent one. An existing file keeps its
                // original value: retries must not rotate what a failed
                // attempt already handed to the external dependency.
                // Endpoint hosts are exact operator facts. Container-loopback
                // inputs were rejected before any side effect instead of
                // silently changing their network meaning here.
                "database-runtime-url" | "database-lifecycle-url" | "valkey-url" => {
                    if !existed {
                        let credential = secret.value.as_ref().ok_or_else(|| {
                            Failure::new(
                                SECRET_PROVISION_FAILED,
                                format!(
                                    "no operator credential for '{}'; the external dependency \
                                     would reject an invented password",
                                    secret.purpose
                                ),
                            )
                        })?;
                        let value = match secret.purpose.as_str() {
                            "database-runtime-url" => format!(
                                "postgresql://{}:{}@{}:{}/{}",
                                job.order.database_runtime_endpoint.user,
                                percent_encode_credential(credential.as_bytes()),
                                job.order.database_runtime_endpoint.host,
                                job.order.database_runtime_endpoint.port,
                                job.order.database_runtime_endpoint.name,
                            ),
                            "database-lifecycle-url" => format!(
                                "postgresql://{}:{}@{}:{}/{}",
                                job.order.database_lifecycle_endpoint.user,
                                percent_encode_credential(credential.as_bytes()),
                                job.order.database_lifecycle_endpoint.host,
                                job.order.database_lifecycle_endpoint.port,
                                job.order.database_lifecycle_endpoint.name,
                            ),
                            _ => format!(
                                "valkey://:{}@{}:{}",
                                percent_encode_credential(credential.as_bytes()),
                                job.order.valkey_endpoint.host,
                                job.order.valkey_endpoint.port,
                            ),
                        };
                        atomic_write(&path, value.as_bytes(), 0o440).map_err(|error| {
                            Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
                        })?;
                    }
                }
                other => {
                    return Err(Failure::new(
                        SECRET_PROVISION_FAILED,
                        format!("unsupported secret purpose '{other}'"),
                    ));
                }
            }
            if kind.is_container() {
                set_runtime_identity(&path, false)?;
                if let Some(parent) = path.parent() {
                    set_runtime_identity_directory(parent)?;
                }
            }
            performed.generated_secrets.push(secret.path.clone());
        }

        // The writable data directory is mounted straight into the container:
        // it must already exist AND be owned by the runtime UID, or the
        // engine silently creates a root-owned directory the application
        // cannot write to.
        let data_root = PathBuf::from(&job.order.data_root);
        if filesystem::ensure_directory_chain(&data_root).is_err() {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "failed to prepare data directory {}",
                    data_root.display()
                )),
            ));
        }
        if let Some(import) = &job.order.current_data_import {
            import_current_data(Path::new(&import.source_data_root), &data_root)?;
        }
        if kind.is_container() {
            set_runtime_identity_directory_data(&data_root)?;
        }

        // 4. Fresh-install application setup (G02 hook): the install-binding
        // capability record. The bootstrap token has exactly one authority —
        // NazoAuth itself generates it inside DATA_DIR at startup; nothing is
        // provisioned or mounted here.
        if job.order.fresh_bootstrap {
            bootstrap_authority::provision(job.scope_dir, job, &subject_digest).map_err(
                |error| Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string())),
            )?;
            performed.provisioned_bootstrap = true;
        }

        // 5. Write the operator's config-revision marker BEFORE the runtime
        // starts: the container backend bind-mounts this exact file, and a
        // missing mount source fails the run with exit 125 (E04 admission
        // step 5 reads it back through the mount).
        let revision_marker = job.scope_dir.join("config-revision");
        atomic_write(&revision_marker, job.order.config_sha256.as_bytes(), 0o440).map_err(
            |error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    sanitize(format!("failed to write config-revision marker: {error}")),
                )
            },
        )?;

        // 6. Start the runtime and confirm it serves the verified artifact.
        match kind {
            RuntimeBackendKind::Host => {
                start_systemd_runtime(job, &verified, performed)?;
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                start_container_runtime(job, &verified, kind, performed)?;
            }
        }

        // 7. Local health/readiness probe. Public reachability is deliberately
        // absent here (G08): loopback readiness is the only install gate.
        probe_local_health(job.runtime.loopback_port)?;

        Ok(InstallFacts {
            artifact_reference: format!("sha256:{subject_digest}"),
            build_identity: verified.build_identity,
            rollback_policy: verified.rollback_policy,
        })
    }
}

fn require_loopback_port_available(
    kind: RuntimeBackendKind,
    runtime_object: &str,
    port: u16,
) -> Result<(), Failure> {
    let backend = runtime_backend::backend(kind);
    if backend
        .inspect(runtime_object)
        .is_ok_and(|observation| observation.running)
    {
        return Ok(());
    }
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .map(drop)
        .map_err(|_| {
            Failure::new(
                RUNTIME_START_FAILED,
                format!("loopback port {port} is already in use on the target"),
            )
        })
}

fn validate_endpoint_reachability(
    kind: RuntimeBackendKind,
    label: &str,
    host: &str,
) -> Result<(), Failure> {
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if kind.is_container() && loopback {
        return Err(Failure::new(
            CONFIG_INVALID,
            format!(
                "{label} endpoint '{host}' is container loopback, not the target host; provide the exact hostname or address reachable from the container"
            ),
        ));
    }
    Ok(())
}

fn prepare_owned_directory(
    path: &Path,
    deployment_id: &str,
    performed: &mut PerformedSteps,
) -> Result<(), Failure> {
    filesystem::ensure_directory_chain(path)
        .map_err(|error| Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string())))?;
    let marker = path.join(".nazoauth-owned");
    atomic_write(&marker, deployment_id.as_bytes(), 0o440)
        .map_err(|error| Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string())))?;
    performed.created_directories.push(path.to_path_buf());
    Ok(())
}

fn ownership_marker_matches(marker: &Path, deployment_id: &str) -> bool {
    let Ok(bytes) =
        filesystem::read_secure_regular_file(marker, "install ownership marker", false, 256)
    else {
        return false;
    };
    std::str::from_utf8(bytes.as_ref()).is_ok_and(|owner| owner.trim() == deployment_id)
}

fn start_container_runtime(
    job: &InstallJob<'_>,
    verified: &super::update_exec::VerifiedArtifactFacts,
    kind: RuntimeBackendKind,
    performed: &mut PerformedSteps,
) -> Result<(), Failure> {
    let runtime_artifact = match &verified.runtime_artifact {
        runtime_backend::ArtifactReference::Oci { .. } => verified.runtime_artifact.clone(),
        _ => {
            return Err(Failure::new(
                RUNTIME_START_FAILED,
                "container install requires a verified OCI artifact",
            ));
        }
    };
    let backend = runtime_backend::backend(kind);
    // 5a. Initialize the database schema BEFORE activation: `nazauth server`
    // preflights the active tenant boundary, which requires the migrated and
    // seeded tables. The diesel migration ledger (deduplicated re-entry) plus
    // the advisory lock make this idempotent across crash-retry resumes.
    run_schema_migration(job, backend.as_ref(), &runtime_artifact)?;

    let observation = backend.inspect(&job.runtime.object);
    if observation
        .as_ref()
        .is_ok_and(|observed| observed.running && observed.artifact == runtime_artifact)
    {
        // Resume: the exact verified runtime is already up.
        performed.installed_runtime = true;
        performed.started_runtime = true;
        return Ok(());
    }
    if let Ok(observed) = &observation {
        // An object under our name that is NOT the verified artifact is a
        // conflict, never a silent replacement target.
        return Err(Failure::new(
            TARGET_IDENTITY_MISMATCH,
            format!(
                "runtime object '{}' already exists serving a different artifact ({})",
                job.runtime.object,
                sanitize(format!("{:?}", observed.artifact))
            ),
        ));
    }
    let mut mounts = vec![
        mount(
            PathBuf::from(job.config_reference),
            CONTAINER_CONFIG_FILE,
            true,
        ),
        mount(
            PathBuf::from(&job.order.data_root),
            CONTAINER_DATA_DIR,
            false,
        ),
    ];
    // The long-lived runtime receives only its three runtime secrets. The
    // lifecycle PostgreSQL URL is mounted solely into one-shot lifecycle
    // tasks and is therefore unreachable from the server process.
    for secret in &job.order.secrets {
        if secret.purpose == "database-lifecycle-url" {
            continue;
        }
        mounts.push(mount(
            PathBuf::from(&secret.path),
            &format!("{CONTAINER_SECRETS_DIR}/{}", secret.purpose),
            true,
        ));
    }
    // The issuer lives ONLY in the mounted configuration (`PUBLIC_BASE_URL`);
    // duplicating it here would let updates of the file drift from a stale
    // environment variable.
    let mut environment: std::collections::BTreeMap<String, String> = [
        (
            SERVER_CONFIG_FILE_ENV.to_owned(),
            CONTAINER_CONFIG_FILE.to_owned(),
        ),
        ("DATA_DIR".to_owned(), CONTAINER_DATA_DIR.to_owned()),
        ("DEPLOYMENT_ID".to_owned(), job.deployment_id.to_owned()),
    ]
    .into_iter()
    .collect();
    // Config-revision marker: the one-shot operator reads this file during
    // E04 admission step 5 to fence operations against stale configuration.
    let config_revision_host = job.scope_dir.join("config-revision");
    let config_revision_container = "/run/nazoauth-operator/config-revision";
    mounts.push(mount(config_revision_host, config_revision_container, true));
    environment.insert(
        "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
        config_revision_container.to_owned(),
    );
    for secret in &job.order.secrets {
        let key = match secret.purpose.as_str() {
            "database-runtime-url" => "DATABASE_URL_FILE",
            "database-lifecycle-url" => continue,
            "valkey-url" => "VALKEY_URL_FILE",
            "mfa-totp-key" => "MFA_TOTP_ENCRYPTION_KEY_FILE",
            other => {
                return Err(Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!(
                        "unsupported install secret purpose '{}'",
                        sanitize(other.to_owned())
                    ),
                ));
            }
        };
        environment.insert(
            key.to_owned(),
            format!("{CONTAINER_SECRETS_DIR}/{}", secret.purpose),
        );
    }
    let replacement = runtime_backend::RuntimeReplacement {
        object_reference: job.runtime.object.clone(),
        artifact: runtime_artifact.clone(),
        local_artifact_id: verified.local_artifact_id.clone(),
        command: vec!["nazoauth".to_owned(), "server".to_owned()],
        mounts,
        environment,
        networks: Vec::new(),
        ip_address: None,
        ports: vec![format!("127.0.0.1:{}:8000/tcp", job.runtime.loopback_port)],
        labels: [(
            "io.nazoauth.deployment-id".to_owned(),
            job.deployment_id.to_owned(),
        )]
        .into_iter()
        .collect(),
        container_policy: Some(runtime_backend::ContainerRuntimePolicy::managed_default()),
    };
    backend
        .replace(&replacement)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    performed.installed_runtime = true;
    backend
        .start(&job.runtime.object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    performed.started_runtime = true;

    // Embedded identity check: the running object must report the verified
    // image digest and be running. Drift here fails the install.
    let observed = backend
        .inspect(&job.runtime.object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    let expected = runtime_artifact;
    if !observed.running || observed.artifact != expected {
        return Err(Failure::new(
            TARGET_IDENTITY_MISMATCH,
            sanitize(format!(
                "the started runtime does not serve the verified artifact \
                 (running={}, observed_artifact={:?}, expected_artifact={:?})",
                observed.running, observed.artifact, expected
            )),
        ));
    }
    Ok(())
}

/// Percent-encode an operator-provided credential for safe inclusion in a
/// URL userinfo component. Unreserved characters (RFC 3986 §2.3) pass
/// through; everything else becomes `%XX` so `@:/?#` and control bytes can
/// never break the URL or smuggle a host change.
pub fn percent_encode_credential(credential: impl AsRef<[u8]>) -> String {
    let credential = credential.as_ref();
    let mut encoded = String::with_capacity(credential.len());
    for &byte in credential {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

fn start_systemd_runtime(
    job: &InstallJob<'_>,
    verified: &super::update_exec::VerifiedArtifactFacts,
    performed: &mut PerformedSteps,
) -> Result<(), Failure> {
    crate::instance_lifecycle::privilege::ensure_systemd_access()
        .map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))?;
    let runtime_root = job.order.runtime_root.as_deref().ok_or_else(|| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "systemd install requires an explicit runtime_root",
        )
    })?;
    let (source_binary, digest) = match &verified.runtime_artifact {
        runtime_backend::ArtifactReference::HostBinary { path, sha256 } => {
            (path.clone(), sha256.clone())
        }
        _ => {
            return Err(Failure::new(
                RUNTIME_START_FAILED,
                "systemd install requires a verified host binary",
            ));
        }
    };
    let binary = PathBuf::from(runtime_root).join("nazoauth");
    let service_user = format!(
        "nazoauth-{}",
        job.deployment_id
            .trim_start_matches("deploy-")
            .chars()
            .take(12)
            .collect::<String>()
    );
    let secret_paths = job
        .order
        .secrets
        .iter()
        .filter(|secret| secret.purpose != "database-lifecycle-url")
        .map(|secret| PathBuf::from(&secret.path))
        .collect::<Vec<_>>();
    let backend = runtime_backend::backend(RuntimeBackendKind::Host);
    // From this point rollback must remove both a partial unit and the
    // deployment-specific service account created by the backend.
    performed.installed_runtime = true;
    backend
        .install_host_service(&runtime_backend::HostServiceInstall {
            service_name: job.runtime.object.clone(),
            deployment_id: job.deployment_id.to_owned(),
            service_user: service_user.clone(),
            source_binary,
            binary: binary.clone(),
            config: PathBuf::from(job.config_reference),
            data_root: PathBuf::from(&job.order.data_root),
            secret_paths: secret_paths.clone(),
        })
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    let mut environment = std::collections::BTreeMap::new();
    environment.insert(
        SERVER_CONFIG_FILE_ENV.to_owned(),
        job.config_reference.to_owned(),
    );
    let lifecycle_url = job
        .order
        .secrets
        .iter()
        .find(|secret| secret.purpose == "database-lifecycle-url")
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "systemd migration requires the lifecycle PostgreSQL URL",
            )
        })?;
    environment.insert("DATABASE_URL_FILE".to_owned(), lifecycle_url.path.clone());
    let task = runtime_backend::OneShotTask {
        artifact: runtime_backend::ArtifactReference::HostBinary {
            path: binary.clone(),
            sha256: digest.clone(),
        },
        command: vec!["nazoauth".to_owned(), "migrate".to_owned()],
        network: Some("host".to_owned()),
        mounts: Vec::new(),
        environment,
        working_directory: Some(PathBuf::from(&job.order.data_root)),
        service_user: None,
        transient_credentials: std::collections::BTreeMap::new(),
        read_only_paths: std::iter::once(PathBuf::from(job.config_reference))
            .chain(secret_paths)
            .collect(),
        read_write_paths: vec![PathBuf::from(&job.order.data_root)],
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin: Vec::new(),
    };
    backend
        .run_one_shot(&task)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    backend
        .start(&job.runtime.object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    performed.started_runtime = true;
    let observed = backend
        .inspect(&job.runtime.object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    let expected = runtime_backend::ArtifactReference::HostBinary {
        path: binary,
        sha256: digest,
    };
    if !observed.running || observed.artifact != expected {
        return Err(Failure::new(
            TARGET_IDENTITY_MISMATCH,
            "the started systemd unit does not serve the verified host binary",
        ));
    }
    Ok(())
}

/// Store one verified host binary in the deployment-owned rollback cache.
/// Cache directories are root-owned and traversable but not writable by the
/// service account; the binary itself is executable for pre-activation
/// migration tasks.
pub(super) fn cache_systemd_artifact(
    source: &Path,
    runtime_root: &Path,
    digest: &str,
) -> anyhow::Result<PathBuf> {
    if filesystem::sha256(source)? != digest {
        anyhow::bail!("verified systemd binary changed before caching");
    }
    let artifacts_root = runtime_root.join("artifacts");
    let cache_dir = artifacts_root.join(digest);
    filesystem::ensure_directory_chain(&cache_dir)?;
    for directory in [runtime_root, artifacts_root.as_path(), cache_dir.as_path()] {
        filesystem::set_mode(directory, 0o755)?;
    }
    let cached = cache_dir.join("nazoauth");
    let mut source_file =
        filesystem::open_secure_regular_file(source, "verified systemd release binary", false)?;
    filesystem::copy_atomic_from_file(&mut source_file, &cached, 0o555)?;
    if filesystem::sha256(&cached)? != digest {
        anyhow::bail!("cached systemd binary does not match its verified digest");
    }
    Ok(cached)
}

/// One-shot `nazauth migrate` against the verified image, sharing the exact
/// secret mounts the runtime receives. Runs before the long-lived container
/// so its tenant-boundary preflight sees a migrated database.
fn run_schema_migration(
    job: &InstallJob<'_>,
    backend: &dyn runtime_backend::RuntimeBackend,
    artifact: &runtime_backend::ArtifactReference,
) -> Result<(), Failure> {
    let secrets_dir = job
        .order
        .secrets
        .first()
        .and_then(|secret| Path::new(&secret.path).parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "install order carries no secrets; the database URL is required".to_owned(),
            )
        })?;
    let mut environment = std::collections::BTreeMap::new();
    environment.insert(
        SERVER_CONFIG_FILE_ENV.to_owned(),
        CONTAINER_CONFIG_FILE.to_owned(),
    );
    for secret in &job.order.secrets {
        let key = match secret.purpose.as_str() {
            "database-lifecycle-url" => "DATABASE_URL_FILE",
            "valkey-url" => "VALKEY_URL_FILE",
            _ => continue,
        };
        environment.insert(
            key.to_owned(),
            format!("{CONTAINER_SECRETS_DIR}/{}", secret.purpose),
        );
    }
    let task = runtime_backend::OneShotTask {
        artifact: artifact.clone(),
        command: vec!["nazoauth".to_owned(), "migrate".to_owned()],
        network: None,
        mounts: vec![
            mount(
                PathBuf::from(job.config_reference),
                CONTAINER_CONFIG_FILE,
                true,
            ),
            mount(secrets_dir, CONTAINER_SECRETS_DIR, true),
        ],
        environment,
        working_directory: Some(std::path::PathBuf::from("/app")),
        service_user: Some(runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned()),
        transient_credentials: std::collections::BTreeMap::new(),
        read_only_paths: Vec::new(),
        read_write_paths: Vec::new(),
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin: Vec::new(),
    };
    backend
        .run_one_shot(&task)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    Ok(())
}

/// The official NazoAuth image runs as the fixed non-root identity
/// `10001:10001` (`NON_ROOT_ONE_SHOT_USER`). OCI bind mounts retain host
/// ownership, so files handed to the runtime must be group-readable by that
/// exact identity: `root:<uid>` mode 0440, matching the production layout.
#[cfg(unix)]
fn set_runtime_identity(path: &Path, _directory: bool) -> Result<(), Failure> {
    use std::os::unix::fs::{PermissionsExt as _, chown};
    let apply = || -> std::io::Result<()> {
        chown(path, Some(0), Some(10_001))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o440))
    };
    apply().map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            sanitize(format!(
                "failed to grant runtime read access to {}: {error}",
                path.display()
            )),
        )
    })
}

/// Writable data tree handed to the runtime: every node is owned outright by
/// the runtime UID so the application can create its keys, bootstrap state
/// and generated secret files. Recursive because ctl pre-creates nested
/// directories (e.g. the secrets directory) as root.
#[cfg(unix)]
fn set_runtime_identity_directory_data(path: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::{PermissionsExt as _, lchown};
    let mut stack = vec![path.to_path_buf()];
    while let Some(node) = stack.pop() {
        let metadata = fs::symlink_metadata(&node).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "failed to inspect runtime data node {}: {error}",
                    node.display()
                )),
            )
        })?;

        if metadata.file_type().is_symlink() {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "runtime data ownership rejects symlink {}",
                    node.display()
                )),
            ));
        }
        let is_directory = metadata.is_dir();
        if !is_directory && !metadata.is_file() {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "runtime data ownership rejects special file {}",
                    node.display()
                )),
            ));
        }

        lchown(&node, Some(10_001), Some(10_001)).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "failed to grant runtime ownership of {}: {error}",
                    node.display()
                )),
            )
        })?;
        if is_directory {
            fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    sanitize(format!(
                        "failed to restrict runtime data directory {}: {error}",
                        node.display()
                    )),
                )
            })?;
            for entry in std::fs::read_dir(&node).map_err(|error| {
                Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
            })? {
                stack.push(
                    entry
                        .map_err(|error| {
                            Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
                        })?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

/// Read-only secrets directory: the runtime UID needs traverse (`x`) to open
/// the files beneath it, but never write access.
#[cfg(unix)]
fn set_runtime_identity_directory(path: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::{PermissionsExt as _, chown};
    let apply = || -> std::io::Result<()> {
        chown(path, Some(0), Some(10_001))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))
    };
    apply().map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            sanitize(format!(
                "failed to grant runtime traverse on {}: {error}",
                path.display()
            )),
        )
    })
}

#[cfg(not(unix))]
fn set_runtime_identity(_path: &Path, _directory: bool) -> Result<(), Failure> {
    Ok(())
}

#[cfg(not(unix))]
fn set_runtime_identity_directory_data(_path: &Path) -> Result<(), Failure> {
    Ok(())
}

#[cfg(not(unix))]
fn set_runtime_identity_directory(_path: &Path) -> Result<(), Failure> {
    Ok(())
}

fn mount(source: PathBuf, destination: &str, read_only: bool) -> runtime_backend::NeutralMount {
    runtime_backend::NeutralMount {
        source,
        destination: PathBuf::from(destination),
        read_only,
        selinux_relabel: false,
        ownership: runtime_backend::Responsibility::Managed,
        scope: crate::runtime_backend::RuntimeResourceScope::Deployment,
    }
}

/// Bounded loopback readiness probe against `http://127.0.0.1:{port}/health`.
/// Shared with the update/rollback executors (G03/G04): activation is only
/// ever gated by the same local readiness fact. This is a LOOPBACK probe —
/// it must never depend on public DNS, TLS, or any external boundary (G08).
pub(crate) fn probe_local_health(port: u16) -> Result<(), Failure> {
    let endpoint = format!("http://127.0.0.1:{port}{LOCAL_READINESS_PATH}");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut last: Option<Failure> = None;
    while std::time::Instant::now() < deadline {
        let attempt = Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                "3",
                "--max-time",
                "5",
                &endpoint,
            ])
            .run_quiet();
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = Some(Failure::new(
                    HEALTH_PROBE_FAILED,
                    sanitize(error.to_string()),
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(last
        .unwrap_or_else(|| Failure::new(HEALTH_PROBE_FAILED, "local readiness probe timed out")))
}

/// Roll every performed step back. Every cleanup is attempted, and any
/// residue is returned to the caller instead of being hidden behind the
/// original install failure.
pub(crate) fn rollback(job: &InstallJob<'_>, performed: &PerformedSteps) -> Result<(), Failure> {
    let mut errors = Vec::new();
    if performed.installed_runtime {
        let backend = runtime_backend::backend(job.runtime.kind);
        if performed.started_runtime
            && let Err(error) = backend.stop(&job.runtime.object)
        {
            errors.push(format!("stopping runtime failed: {error}"));
        }
        if let Err(error) = backend.remove(&job.runtime.object) {
            errors.push(format!("removing runtime failed: {error}"));
        }
    }
    if performed.provisioned_bootstrap
        && let Err(error) = bootstrap_authority::delete_material(job.scope_dir)
    {
        errors.push(format!("removing bootstrap material failed: {error}"));
    }
    for path in &performed.generated_secrets {
        if let Err(error) = filesystem::remove_file_durable(Path::new(path)) {
            errors.push(format!("removing secret file failed: {error}"));
        }
    }
    if performed.wrote_config
        && let Err(error) = filesystem::remove_file_durable(Path::new(job.config_reference))
    {
        errors.push(format!("removing configuration failed: {error}"));
    }
    if performed.wrote_config_marker {
        let config_marker = PathBuf::from(format!("{}.nazoauth-owned", job.config_reference));
        if let Err(error) = filesystem::remove_file_durable(&config_marker) {
            errors.push(format!("removing configuration marker failed: {error}"));
        }
    }
    for directory in performed.created_directories.iter().rev() {
        let marker = directory.join(".nazoauth-owned");
        let owned = std::fs::read_to_string(&marker)
            .map(|value| value.trim() == job.deployment_id)
            .unwrap_or(false);
        if !owned {
            errors.push(format!(
                "refusing to remove created directory without its ownership marker: {}",
                directory.display()
            ));
            continue;
        }
        if let Err(error) = std::fs::remove_dir_all(directory) {
            errors.push(format!(
                "removing created directory {} failed: {error}",
                directory.display()
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Failure::new(INSTALL_FAILED, sanitize(errors.join("; "))))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod endpoint_tests {
    use super::{RuntimeBackendKind, validate_endpoint_reachability};

    #[test]
    fn container_endpoints_keep_exact_network_semantics() {
        for host in ["localhost", "127.0.0.1", "127.20.30.40", "::1"] {
            assert!(
                validate_endpoint_reachability(RuntimeBackendKind::Podman, "Valkey", host).is_err(),
                "{host}"
            );
        }
        for host in ["host.containers.internal", "database.internal", "10.88.0.1"] {
            assert!(
                validate_endpoint_reachability(RuntimeBackendKind::Podman, "Valkey", host).is_ok(),
                "{host}"
            );
        }
        assert!(
            validate_endpoint_reachability(RuntimeBackendKind::Host, "Valkey", "127.0.0.1").is_ok()
        );
    }
}

#[cfg(test)]
mod current_data_import_tests {
    use super::*;

    fn source_fixture(root: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(root.join("keys"))?;
        fs::create_dir_all(root.join("avatars"))?;
        fs::create_dir_all(root.join("secrets"))?;
        fs::create_dir_all(root.join("instance"))?;
        fs::create_dir_all(root.join("bootstrap"))?;
        fs::create_dir_all(root.join("ui-releases"))?;
        fs::write(root.join("keys/signing.pem"), b"key")?;
        fs::write(root.join("avatars/user.jpg"), b"avatar")?;
        for name in IMPORT_APP_SECRETS {
            fs::write(root.join("secrets").join(name), name.as_bytes())?;
        }
        fs::write(root.join("secrets/unknown"), b"excluded")?;
        fs::write(root.join("instance/state"), b"excluded")?;
        fs::write(root.join("bootstrap/token"), b"excluded")?;
        fs::write(root.join("ui-releases/bundle"), b"excluded")?;
        fs::write(root.join("unknown"), b"excluded")?;
        Ok(())
    }

    #[test]
    fn import_copies_only_current_material_and_resumes_exactly() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("current-data-import")?;
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir(&source)?;
        fs::create_dir(&destination)?;
        source_fixture(&source)?;

        import_current_data(&source, &destination)
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;
        import_current_data(&source, &destination)
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;
        assert_eq!(fs::read(destination.join("keys/signing.pem"))?, b"key");
        assert_eq!(fs::read(destination.join("avatars/user.jpg"))?, b"avatar");
        for name in IMPORT_APP_SECRETS {
            assert!(destination.join("secrets").join(name).is_file());
        }
        for excluded in [
            "instance",
            "bootstrap",
            "ui-releases",
            "unknown",
            "secrets/unknown",
        ] {
            assert!(!destination.join(excluded).exists(), "copied {excluded}");
        }

        fs::write(destination.join("keys/signing.pem"), b"drift")?;
        assert!(import_current_data(&source, &destination).is_err());

        let mfa_source = temp.path().join("mfa-source");
        let mfa_destination = temp.path().join("mfa-destination");
        use base64::Engine as _;
        fs::write(
            &mfa_source,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        )?;
        copy_import_file(&mfa_source, &mfa_destination, "MFA")
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;
        copy_import_file(&mfa_source, &mfa_destination, "MFA")
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;
        fs::write(&mfa_source, b"invalid")?;
        assert!(copy_import_file(&mfa_source, &mfa_destination, "MFA").is_err());
        Ok(())
    }

    #[test]
    fn mfa_import_accepts_terminal_line_endings_but_rejects_other_whitespace() -> anyhow::Result<()>
    {
        let temp = crate::filesystem::PrivateTempDir::new("mfa-import-format")?;
        use base64::Engine as _;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);

        for (suffix, name) in [("\n", "lf"), ("\r\n", "crlf")] {
            let source = temp.path().join(format!("source-{name}"));
            let destination = temp.path().join(format!("destination-{name}"));
            fs::write(&source, format!("{key}{suffix}"))?;
            copy_import_file(&source, &destination, "MFA")
                .map_err(|failure| anyhow::anyhow!(failure.detail))?;
        }

        for (value, name) in [
            (format!(" {key}"), "leading-space"),
            (format!("\n{key}"), "leading-lf"),
            (format!("{}\n{}", &key[..20], &key[20..]), "internal-lf"),
            (format!("{key} "), "trailing-space"),
            (format!("{key}="), "padding"),
            ("0123456789abcdef".repeat(4), "hex"),
        ] {
            let source = temp.path().join(format!("invalid-source-{name}"));
            let destination = temp.path().join(format!("invalid-destination-{name}"));
            fs::write(&source, value)?;
            assert!(
                copy_import_file(&source, &destination, "MFA").is_err(),
                "{name}"
            );
        }

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn runtime_data_ownership_covers_nested_files_without_changing_file_modes() -> anyhow::Result<()>
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown, symlink};

        let temp = crate::filesystem::PrivateTempDir::new("runtime-data-ownership")?;
        let root = temp.path().join("data");
        let nested = root.join("nested/deeper");
        fs::create_dir_all(&nested)?;
        let file = nested.join("secret");
        fs::write(&file, b"secret")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;

        let probe = temp.path().join("chown-probe");
        fs::write(&probe, b"probe")?;
        match chown(&probe, Some(10_001), Some(10_001)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(error) => return Err(error.into()),
        }

        set_runtime_identity_directory_data(&root)
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;

        let root_metadata = fs::metadata(&root)?;
        assert_eq!(root_metadata.uid(), 10_001);
        assert_eq!(root_metadata.gid(), 10_001);
        assert_eq!(root_metadata.permissions().mode() & 0o7777, 0o700);
        let nested_metadata = fs::metadata(&nested)?;
        assert_eq!(nested_metadata.uid(), 10_001);
        assert_eq!(nested_metadata.gid(), 10_001);
        assert_eq!(nested_metadata.permissions().mode() & 0o7777, 0o700);
        let file_metadata = fs::metadata(&file)?;
        assert_eq!(file_metadata.uid(), 10_001);
        assert_eq!(file_metadata.gid(), 10_001);
        assert_eq!(file_metadata.permissions().mode() & 0o7777, 0o600);

        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside")?;
        let outside_before = fs::metadata(&outside)?;
        let link = nested.join("link");
        symlink(&outside, &link)?;
        assert!(set_runtime_identity_directory_data(&root).is_err());
        let outside_after = fs::metadata(&outside)?;
        assert_eq!(outside_after.uid(), outside_before.uid());
        assert_eq!(outside_after.gid(), outside_before.gid());
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn import_rejects_symlinks_in_selected_trees() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        let temp = crate::filesystem::PrivateTempDir::new("current-data-import-link")?;
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir(&source)?;
        fs::create_dir(&destination)?;
        source_fixture(&source)?;
        symlink(source.join("keys/signing.pem"), source.join("keys/link"))?;
        assert!(import_current_data(&source, &destination).is_err());
        Ok(())
    }
}
