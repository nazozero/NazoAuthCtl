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
//! official-verification pipeline the legacy install ran on the host —
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
    deployment::RuntimeBackendKind,
    filesystem::{self, atomic_write},
    process::Process,
    release::{ReleaseRequest, VerifiedRelease},
    runtime_backend,
};

use super::{
    bootstrap_authority,
    deployment_state::Failure,
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
        if self.data_root.is_empty() || self.data_root.len() > 512 {
            return Err(super::wire::MessageRejection::new(
                super::wire::RejectionCode::OperationMalformed,
                "install data_root must be a bounded absolute path",
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
            if secret.path.is_empty() || secret.path.len() > 512 {
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

/// Everything the executor needs besides the order itself. Built by dispatch
/// from the accepted operation; never serialized.
pub(crate) struct InstallJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub issuer: &'a str,
    /// Runtime class token from the Bootstrap surface (`podman`, `docker`,
    /// `host`).
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
            Err(failure) => {
                rollback(job, &performed);
                Err(failure)
            }
        }
    }
}

/// Steps an executor has durably performed, driving precise rollback.
/// Visible to the scripted test executors so rollback semantics exist exactly
/// once for production and tests alike.
#[derive(Default)]
pub(crate) struct PerformedSteps {
    pub(crate) wrote_config: bool,
    pub(crate) generated_secrets: Vec<String>,
    pub(crate) provisioned_bootstrap: bool,
    pub(crate) started_runtime: bool,
}

impl HostInstallExecutor {
    fn run(
        &self,
        job: &InstallJob<'_>,
        performed: &mut PerformedSteps,
    ) -> Result<InstallFacts, Failure> {
        let config_path = PathBuf::from(job.config_reference);
        // Fresh installs never overwrite an existing configuration.
        if config_path.exists() {
            return Err(Failure::new(
                CONFIG_PATH_OCCUPIED,
                format!(
                    "{} already exists; clean install never replaces an existing configuration",
                    config_path.display()
                ),
            ));
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
        let subject_digest = match kind {
            RuntimeBackendKind::Systemd => {
                let binary = release
                    .artifact("binary", &job.order.artifact.repository)
                    .map_err(|error| {
                        Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string()))
                    })?;
                filesystem::sha256(&binary).map_err(|error| {
                    Failure::new(ARTIFACT_UNVERIFIED, sanitize(error.to_string()))
                })?
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
                    let present = backend.inspect_optional(&image).ok().flatten().is_some();
                    if !present {
                        return Err(Failure::new(
                            ARTIFACT_UNVERIFIED,
                            sanitize(format!(
                                "{pull_error:#}; and no local image matches {image}"
                            )),
                        ));
                    }
                    // Local exact-digest match: proceed without network.
                }
                release
                    .manifest
                    .image_oci_digest()
                    .trim_start_matches("sha256:")
                    .to_owned()
            }
        };
        if let Some(expected) = &job.order.artifact.expected_subject_sha256
            && expected != &subject_digest
        {
            return Err(Failure::new(
                ARTIFACT_UNVERIFIED,
                "verified subject digest differs from the requested pin",
            ));
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

        // 3. Target-local secrets (values are minted here, never shipped).
        for secret in &job.order.secrets {
            let path = PathBuf::from(&secret.path);
            let existed = path.exists();
            match secret.purpose.as_str() {
                "mfa-totp-key" => {
                    filesystem::generate_secret(&path).map_err(|error| {
                        Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
                    })?;
                }
                // URL-shaped values combine operator-supplied endpoint facts
                // with a fresh CSPRNG credential minted here, so the password
                // never crosses the wire. An existing file keeps its original
                // credential: retries must not rotate what a failed attempt
                // already handed to the external dependency.
                "database-url" | "valkey-url" => {
                    if existed {
                        continue;
                    }
                    let credential = hex(rand::random::<[u8; 16]>().as_slice());
                    let value = match secret.purpose.as_str() {
                        "database-url" => format!(
                            "postgresql://{}:{}@{}:{}/{}",
                            job.order.database_endpoint.user,
                            credential,
                            job.order.database_endpoint.host,
                            job.order.database_endpoint.port,
                            job.order.database_endpoint.name,
                        ),
                        _ => format!(
                            "valkey://:{}@{}:{}",
                            credential,
                            job.order.valkey_endpoint.host,
                            job.order.valkey_endpoint.port,
                        ),
                    };
                    atomic_write(&path, value.as_bytes(), 0o440).map_err(|error| {
                        Failure::new(SECRET_PROVISION_FAILED, sanitize(error.to_string()))
                    })?;
                }
                other => {
                    return Err(Failure::new(
                        SECRET_PROVISION_FAILED,
                        format!("unsupported secret purpose '{other}'"),
                    ));
                }
            }
            if !existed {
                performed.generated_secrets.push(secret.path.clone());
            }
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
                return Err(Failure::new(
                    RUNTIME_START_FAILED,
                    "the systemd host backend joins the lifecycle waves with the K-phase \
                     integration; use Podman or Docker for the clean-install path",
                ));
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                start_container_runtime(job, &release, kind, performed)?;
            }
        }

        // 7. Local health/readiness probe. Public reachability is deliberately
        // absent here (G08): loopback readiness is the only install gate.
        probe_local_health(job.order.port)?;

        // 8. Ownership marker: proves ctl created and manages this directory.
        // Uninstall verifies it before any destructive action (P0-3/W2.4).
        let owned_marker = PathBuf::from(&job.order.data_root).join(".nazoauth-owned");
        atomic_write(&owned_marker, job.deployment_id.as_bytes(), 0o440).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                sanitize(format!("failed to write ownership marker: {error}")),
            )
        })?;

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
    let digest = release
        .manifest
        .image_oci_digest()
        .trim_start_matches("sha256:")
        .to_owned();
    let backend = runtime_backend::backend(kind);
    let observation = backend.inspect(job.runtime_object);
    if observation.as_ref().is_ok_and(|observed| {
        observed.running && observed.artifact == artifact_reference(&image, &digest)
    }) {
        // Resume: the exact verified runtime is already up.
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
    performed.started_runtime = true;

    // Embedded identity check: the running object must report the verified
    // image digest and be running. Drift here fails the install.
    let observed = backend
        .inspect(job.runtime_object)
        .map_err(|error| Failure::new(RUNTIME_START_FAILED, sanitize(error.to_string())))?;
    if !observed.running || observed.artifact != artifact_reference(&image, &digest) {
        return Err(Failure::new(
            TARGET_IDENTITY_MISMATCH,
            "the started runtime does not serve the verified artifact",
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

/// Roll every performed step back. Best-effort per step but total in intent:
/// a failed clean install leaves the target exactly as it found it.
pub(crate) fn rollback(job: &InstallJob<'_>, performed: &PerformedSteps) {
    if performed.started_runtime
        && let Ok(kind) = job.backend_kind()
        && kind != RuntimeBackendKind::Systemd
    {
        let backend = runtime_backend::backend(kind);
        let _ = backend.stop(job.runtime_object);
        let _ = backend.remove(job.runtime_object);
    }
    if performed.provisioned_bootstrap {
        let _ = bootstrap_authority::delete_material(job.scope_dir);
    }
    for path in &performed.generated_secrets {
        let _ = filesystem::remove_file_durable(Path::new(path));
    }
    if performed.wrote_config {
        let _ = filesystem::remove_file_durable(Path::new(job.config_reference));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
