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
//! official-verification pipeline used on the target —
//! `VerifiedRelease::verify` plus the runtime backend pull. The control side
//! sends only reference/digest facts (repository, optional version pin,
//! optional expected subject digest); multi-hundred-megabyte blobs never
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
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    filesystem::{self, atomic_write},
    process::Process,
    release::{ReleaseRequest, VerifiedRelease},
    runtime_backend::{self, RuntimeBackendKind},
};

use super::{
    bootstrap_authority,
    deployment_state::{Failure, INSTALL_FAILED},
    wire::{HOST_ERR_OPERATION_INVALID, sanitize},
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

/// Closed vocabulary of target-generated secret files. The control side names
/// paths only; values are minted on the target and never enter the wire.
pub const SECRET_PURPOSES: &[&str] = &["database-url", "valkey-url", "mfa-totp-key"];

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
/// Read-only mount point for the target-generated secret files.
pub const CONTAINER_SECRETS_DIR: &str = "/run/secrets";
/// Persistent data directory inside the container.
pub const CONTAINER_DATA_DIR: &str = "/var/lib/nazo_oauth";
/// NazoAuth environment key overriding the configuration file location.
pub const SERVER_CONFIG_FILE_ENV: &str = "NAZOAUTH_SERVER_CONFIG_FILE";

/// The official artifact a fresh install obtains and verifies on the target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialArtifactRef {
    /// Signed-release repository, e.g. `nazozero/NazoAuth`.
    pub repository: String,
    /// Immutable semantic tag; absent means "latest official Release".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional pin: after on-target verification the subject digest must
    /// equal this value, closing the gap between control-side resolve and
    /// target-side fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_subject_sha256: Option<String>,
}

/// One target-generated secret file: purpose token + absolute path. Values
/// are generated in place by the target (`generate_secret`-class primitives)
/// and referenced from the rendered config by path, never by value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSecret {
    /// One of [`SECRET_PURPOSES`].
    pub purpose: String,
    pub path: String,
    /// P0-1: operator-provided credential content for external-dependency
    /// URLs (`database-url`, `valkey-url`). The external PostgreSQL role and
    /// Valkey ACL already know these values — ctl never invents them. Absent
    /// for target-minted material (`mfa-totp-key`). Rides the encrypted
    /// transport exactly once; the journal directory is root-only 0700.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// New configuration content staged by an update (G03). Values follow the
/// same rules as the install order's config: bounded content plus the exact
/// SHA-256 over its bytes so wire corruption can never reach disk. The
/// declared `schema` token is what makes a later rollback decision possible:
/// the update's config snapshot records both the replaced and the replacing
/// schema, and rollback restores the snapshot only while the deployment still
/// runs the replacing schema (goal plan 07 §5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    /// Target-generated secret files backing the config references.
    pub secrets: Vec<PlannedSecret>,
    /// G02 hook: provision the single-use initial-admin bootstrap capability
    /// bound to this exact install operation id.
    pub fresh_bootstrap: bool,
    /// Host port the runtime publishes on (loopback unless a public boundary
    /// is configured later; public reachability is never an install input).
    pub port: u16,
    /// External PostgreSQL endpoint facts supplied by the operator (G01 item
    /// 3: real external facts are the only install inputs). The credential is
    /// still minted on the target and never crosses the wire.
    pub database_endpoint: ExternalEndpoint,
    /// External Valkey endpoint facts supplied by the operator.
    pub valkey_endpoint: ExternalEndpoint,
}

/// Operator-supplied coordinates of one external dependency. No secret
/// material: the password is minted target-side around these facts.
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
            ("database endpoint host", &self.database_endpoint.host),
            ("valkey endpoint host", &self.valkey_endpoint.host),
        ] {
            if endpoint.is_empty() || endpoint.len() > 253 {
                return Err(super::wire::MessageRejection::new(
                    super::wire::RejectionCode::OperationMalformed,
                    format!("{label} must be 1-253 characters"),
                ));
            }
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
        if self.secrets.len() > SECRET_PURPOSES.len() {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install declares more secrets than the closed purpose set",
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

/// Everything the executor needs besides the order itself. Built by dispatch
/// from the accepted operation; never serialized.
pub(crate) struct InstallJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub issuer: &'a str,
    /// Runtime class token from the Bootstrap surface (`podman`, `docker`).
    pub runtime_kind: &'a str,
    pub runtime_object: &'a str,
    pub config_reference: &'a str,
    /// `<state root>/deployments/<deployment id>/` — where the fresh-install
    /// bootstrap context and token live beside the journal.
    pub scope_dir: &'a Path,
    pub order: &'a InstallOrder,
}

impl InstallJob<'_> {
    fn backend_kind(&self) -> Result<RuntimeBackendKind, Failure> {
        match self.runtime_kind {
            "podman" => Ok(RuntimeBackendKind::Podman),
            "docker" => Ok(RuntimeBackendKind::Docker),
            "host" | "systemd" => Ok(RuntimeBackendKind::Systemd),
            other => Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                format!("unsupported runtime kind '{}'", sanitize(other.to_owned())),
            )),
        }
    }
}

/// What a completed install reports back to the dispatcher: the content-
/// addressed digest handle recorded into `DeploymentState.artifact.current`
/// plus the verified manifest's embedded build identity facts (the G03
/// ControlOperation envelope binding source).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InstallFacts {
    pub artifact_reference: String,
    pub build_identity: Option<super::deployment_state::BuildIdentity>,
}

/// The injectable seam executing one clean-install order on the target.
///
/// Contract: resumable by re-execution; on any failure the implementation has
/// already rolled back its own partial work (config, secrets, bootstrap
/// material, started runtime) before returning `Err`.
pub(crate) trait InstallExecutor: Send + Sync {
    fn execute_install(&self, job: &InstallJob<'_>) -> Result<InstallFacts, Failure>;
}

/// Production executor backed by the real adapters: the H01/H02 official
/// verification pipeline, the runtime backend trait, the shared filesystem
/// primitives, and the fresh-bootstrap authority.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostInstallExecutor;

impl InstallExecutor for HostInstallExecutor {
    fn execute_install(&self, job: &InstallJob<'_>) -> Result<InstallFacts, Failure> {
        let mut performed = PerformedSteps::default();
        match self.run(job, &mut performed) {
            Ok(facts) => Ok(facts),
            Err(failure) => match rollback(job, &performed) {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(Failure::new(
                    failure.code,
                    format!(
                        "{}; rollback was incomplete: {}",
                        failure.detail, cleanup.detail
                    ),
                )),
            },
        }
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
        let mut managed_directories = vec![PathBuf::from(&job.order.data_root), secret_root];
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
            if config_path.starts_with(path)
                || managed_directories
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
        let kind = job.backend_kind()?;
        let release = VerifiedRelease::verify(ReleaseRequest {
            repository: &job.order.artifact.repository,
            requested_version: job.order.artifact.version.as_deref(),
            container_backend: (kind != RuntimeBackendKind::Systemd).then_some(kind),
            trusted_version_floor: None,
        })
        .map_err(|error| Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string())))?;
        let (subject_digest, pin_digest) = match kind {
            RuntimeBackendKind::Systemd => {
                let binary = release
                    .artifact("binary", &job.order.artifact.repository)
                    .map_err(|error| {
                        Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string()))
                    })?;
                let digest = filesystem::sha256(&binary).map_err(|error| {
                    Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string()))
                })?;
                (digest.clone(), digest)
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                // Container backends always run Linux images regardless of the
                // control machine's OS (real-acceptance finding on Windows).
                let digest = release
                    .manifest
                    .runtime_oci_digest_for(crate::model::container_oci_platform())
                    .map_err(|error| {
                        Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string()))
                    })?;
                let image = format!(
                    "{}@{digest}",
                    release.manifest.oci.repository.trim_end_matches('/')
                );
                let backend = runtime_backend::backend(kind);
                if let Err(pull_error) = backend.pull_image(&image) {
                    // Registry unreachable (restricted network, anonymous
                    // rate-limiting): the digest pin IS the verification
                    // anchor, so an image already present locally under the
                    // exact repo@digest reference is equally trustworthy.
                    // Anything else (absent, or a different digest) fails.
                    if !backend.local_image_matches_digest(&image) {
                        return Err(Failure::new(
                            ARTIFACT_UNVERIFIED,
                            sanitize(format!(
                                "{pull_error:#}; and no local image matches {image}"
                            )),
                        ));
                    }
                    // Local exact-digest match: proceed without network.
                }
                let platform_digest = digest.trim_start_matches("sha256:").to_owned();
                let index_digest = release
                    .manifest
                    .image_oci_digest()
                    .trim_start_matches("sha256:")
                    .to_owned();
                (platform_digest, index_digest)
            }
        };
        if let Some(expected) = &job.order.artifact.expected_subject_sha256
            && expected != &pin_digest
        {
            return Err(Failure::new(
                ARTIFACT_UNVERIFIED,
                "verified subject digest differs from the requested pin",
            ));
        }

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
        if let Some(parent) = config_path.parent()
            && filesystem::ensure_directory_chain(parent).is_err()
        {
            return Err(Failure::new(
                CONFIG_INVALID,
                format!("failed to prepare {}", parent.display()),
            ));
        }
        atomic_write(&config_path, content_bytes, 0o600)
            .map_err(|error| Failure::new(CONFIG_INVALID, sanitize(error.to_string())))?;
        performed.wrote_config = true;
        // The container reads this file as the image's fixed runtime UID;
        // bind mounts keep host ownership, so hand it over group-readable.
        if kind != RuntimeBackendKind::Systemd {
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

        // 3. Target-local secrets (values are minted here, never shipped).
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
                    if !existed {
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
                //
                // Operator endpoints address the target HOST; inside the
                // container namespace loopback would be the container itself,
                // so a loopback endpoint is rewritten to the engine's
                // host-gateway name.
                "database-url" | "valkey-url" => {
                    if !existed {
                        let credential = secret.value.as_deref().ok_or_else(|| {
                            Failure::new(
                                SECRET_PROVISION_FAILED,
                                format!(
                                    "no operator credential for '{}'; the external dependency \
                                     would reject an invented password",
                                    secret.purpose
                                ),
                            )
                        })?;
                        let gateway = |host: &str| -> String {
                            match host {
                                "127.0.0.1" | "::1" | "localhost" => match kind {
                                    RuntimeBackendKind::Docker => "host.docker.internal".to_owned(),
                                    RuntimeBackendKind::Podman => {
                                        "host.containers.internal".to_owned()
                                    }
                                    RuntimeBackendKind::Systemd => host.to_owned(),
                                },
                                other => other.to_owned(),
                            }
                        };
                        let value = match secret.purpose.as_str() {
                            "database-url" => format!(
                                "postgresql://{}:{}@{}:{}/{}",
                                job.order.database_endpoint.user,
                                percent_encode_credential(credential),
                                gateway(&job.order.database_endpoint.host),
                                job.order.database_endpoint.port,
                                job.order.database_endpoint.name,
                            ),
                            _ => format!(
                                "valkey://:{}@{}:{}",
                                percent_encode_credential(credential),
                                gateway(&job.order.valkey_endpoint.host),
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
            if kind != RuntimeBackendKind::Systemd {
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
        if kind != RuntimeBackendKind::Systemd {
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
            RuntimeBackendKind::Systemd => {
                start_systemd_runtime(job, &release, &subject_digest, performed)?;
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                start_container_runtime(job, &release, kind, performed)?;
            }
        }

        // 7. Local health/readiness probe. Public reachability is deliberately
        // absent here (G08): loopback readiness is the only install gate.
        probe_local_health(job.order.port)?;

        Ok(InstallFacts {
            artifact_reference: format!("sha256:{subject_digest}"),
            build_identity: Some(
                super::deployment_state::BuildIdentity::new(
                    super::deployment_state::BUILD_IDENTITY_PRODUCT,
                    &release.manifest.version,
                    &release.manifest.backend_commit,
                )
                .map_err(|error| {
                    Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
                })?,
            ),
        })
    }
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
    release: &VerifiedRelease,
    kind: RuntimeBackendKind,
    performed: &mut PerformedSteps,
) -> Result<(), Failure> {
    let image = match kind {
        RuntimeBackendKind::Systemd => release
            .manifest
            .image_ref()
            .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?,
        _ => {
            let digest = release
                .manifest
                .runtime_oci_digest_for(crate::model::container_oci_platform())
                .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
            format!(
                "{}@{digest}",
                release.manifest.oci.repository.trim_end_matches('/')
            )
        }
    };
    // The runtime identity anchor is the digest embedded in `image` itself:
    // the platform manifest digest for container backends (what the engine
    // records in RepoDigests and what inspection resolves back) or the
    // host-platform runtime digest for systemd. The manifest-list index
    // digest is a separate verification anchor consumed upstream; asserting
    // it against the running object would compare two different layers.
    let digest = image
        .rsplit_once('@')
        .map(|(_, digest)| digest.trim_start_matches("sha256:").to_owned())
        .ok_or_else(|| {
            Failure::new(
                RUNTIME_START_FAILED,
                sanitize(format!("release image reference has no digest: {image}")),
            )
        })?;
    let backend = runtime_backend::backend(kind);
    // 5a. Initialize the database schema BEFORE activation: `nazauth server`
    // preflights the active tenant boundary, which requires the migrated and
    // seeded tables. The diesel migration ledger (deduplicated re-entry) plus
    // the advisory lock make this idempotent across crash-retry resumes.
    run_schema_migration(job, backend.as_ref(), kind, &image)?;

    let observation = backend.inspect(job.runtime_object);
    if observation.as_ref().is_ok_and(|observed| {
        observed.running && observed.artifact == artifact_reference(&image, &digest)
    }) {
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
                job.runtime_object,
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
    // Secret files share one host directory (enforced by InstallOrder
    // validation); it is mounted read-only at the fixed container location
    // the seed configuration references.
    if let Some(secrets_dir) = job
        .order
        .secrets
        .first()
        .and_then(|secret| Path::new(&secret.path).parent())
    {
        mounts.push(mount(
            secrets_dir.to_path_buf(),
            CONTAINER_SECRETS_DIR,
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
            "database-url" => "DATABASE_URL_FILE",
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
        object_reference: job.runtime_object.to_owned(),
        artifact: artifact_reference(&image, &digest),
        local_artifact_id: None,
        command: vec!["nazoauth".to_owned(), "server".to_owned()],
        mounts,
        environment,
        networks: Vec::new(),
        ip_address: None,
        ports: vec![format!("127.0.0.1:{}:8000/tcp", job.order.port)],
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
    backend
        .start(job.runtime_object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    performed.installed_runtime = true;
    performed.started_runtime = true;

    // Embedded identity check: the running object must report the verified
    // image digest and be running. Drift here fails the install.
    let observed = backend
        .inspect(job.runtime_object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    let expected = artifact_reference(&image, &digest);
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

fn artifact_reference(image: &str, digest: &str) -> runtime_backend::ArtifactReference {
    runtime_backend::ArtifactReference::Oci {
        image_reference: image.to_owned(),
        digest: format!("sha256:{digest}"),
    }
}

/// Percent-encode an operator-provided credential for safe inclusion in a
/// URL userinfo component. Unreserved characters (RFC 3986 §2.3) pass
/// through; everything else becomes `%XX` so `@:/?#` and control bytes can
/// never break the URL or smuggle a host change.
pub fn percent_encode_credential(credential: &str) -> String {
    let mut encoded = String::with_capacity(credential.len());
    for byte in credential.bytes() {
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
    release: &VerifiedRelease,
    digest: &str,
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
    let verified_source = release
        .artifact("binary", &job.order.artifact.repository)
        .map_err(|error| Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string())))?;
    let source_binary =
        cache_systemd_artifact(&verified_source, Path::new(runtime_root), digest)
            .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
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
        .map(|secret| PathBuf::from(&secret.path))
        .collect::<Vec<_>>();
    let backend = runtime_backend::backend(RuntimeBackendKind::Systemd);
    // From this point rollback must remove both a partial unit and the
    // deployment-specific service account created by the backend.
    performed.installed_runtime = true;
    backend
        .install_host_service(&runtime_backend::HostServiceInstall {
            service_name: job.runtime_object.to_owned(),
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
    let task = runtime_backend::OneShotTask {
        artifact: runtime_backend::ArtifactReference::HostBinary {
            path: binary.clone(),
            sha256: digest.to_owned(),
        },
        command: vec!["nazoauth".to_owned(), "migrate".to_owned()],
        network: Some("host".to_owned()),
        mounts: Vec::new(),
        environment,
        working_directory: Some(PathBuf::from(&job.order.data_root)),
        service_user: Some(service_user),
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
        .start(job.runtime_object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    performed.started_runtime = true;
    let observed = backend
        .inspect(job.runtime_object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    let expected = runtime_backend::ArtifactReference::HostBinary {
        path: binary,
        sha256: digest.to_owned(),
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
    kind: RuntimeBackendKind,
    image: &str,
) -> Result<(), Failure> {
    let digest = image
        .rsplit_once('@')
        .map(|(_, d)| d.trim_start_matches("sha256:").to_owned())
        .ok_or_else(|| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!("release image reference has no digest: {image}")),
            )
        })?;
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
        if matches!(secret.purpose.as_str(), "database-url" | "valkey-url") {
            environment.insert(
                format!("{}_FILE", secret.purpose.to_uppercase().replace('-', "_")),
                format!("{CONTAINER_SECRETS_DIR}/{}", secret.purpose),
            );
        }
    }
    let task = runtime_backend::OneShotTask {
        artifact: artifact_reference(image, &digest),
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
    let _ = kind;
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
    use std::os::unix::fs::{PermissionsExt as _, chown};
    let apply_node = |node: &Path| -> std::io::Result<()> {
        chown(node, Some(10_001), Some(10_001))?;
        if node.is_dir() {
            std::fs::set_permissions(node, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    };
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        apply_node(&dir).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!(
                    "failed to grant runtime ownership of {}: {error}",
                    dir.display()
                )),
            )
        })?;
        for entry in std::fs::read_dir(&dir).map_err(|error| {
            Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
        })? {
            let child = entry
                .map_err(|error| {
                    Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
                })?
                .path();
            if child.is_dir() && !child.is_symlink() {
                stack.push(child);
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

/// Bounded loopback readiness probe against `http://127.0.0.1:{port}/readyz`.
/// Shared with the update/rollback executors (G03/G04): activation is only
/// ever gated by the same local readiness fact. This is a LOOPBACK probe —
/// it must never depend on public DNS, TLS, or any external boundary (G08).
pub(crate) fn probe_local_health(port: u16) -> Result<(), Failure> {
    let endpoint = format!("http://127.0.0.1:{port}/readyz");
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
    if performed.installed_runtime
        && let Ok(kind) = job.backend_kind()
    {
        let backend = runtime_backend::backend(kind);
        if performed.started_runtime
            && let Err(error) = backend.stop(job.runtime_object)
        {
            errors.push(format!("stopping runtime failed: {error}"));
        }
        if let Err(error) = backend.remove(job.runtime_object) {
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
