//! Target-side execution of delivered ControlOperations (goal plan 05 §6,
//! task G-wave decision 1).
//!
//! A `control-operation` HostOperation makes the target invoke its LOCAL
//! NazoAuth one-shot operator inside the deployment's verified OCI artifact,
//! with the compact JWS on stdin and a
//! single-line durable [`ControlResult`] on stdout under a bounded timeout.
//! The target never parses, verifies, or authorizes the envelope: admission,
//! accept-once journaling, and execution stay entirely server-side.
//!
//! Classification contract (mirrors NazoAuth's own exit semantics):
//!
//! * parsable terminal/in-progress result ⇒ authoritative answer;
//! * no parsable result ⇒ [`CONTROL_OUTCOME_UNKNOWN`] — the operation may or
//!   may not have been accepted, so the only safe retry is the resumed resend
//!   of the SAME envelope (server dedupes by id + request hash);
//! * engine/socket privilege problems surface before any run through the
//!   G07 sunk privilege checks.
//!
//! The executor is an injected seam like [`super::install_exec`]: production
//! uses [`HostControlOperator`], tests substitute scripted doubles so container
//! engines never spawn on development machines.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nazo_operator_protocol::ControlResult;

use super::deployment_state::Failure;
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};

/// Stable failure code: the operator ran (or may have run) but produced no
/// parsable ControlResult. The outcome is unknown by construction; retries
/// must resume the same operation id instead of minting a new one.
pub const CONTROL_OUTCOME_UNKNOWN: &str = "CONTROL_OUTCOME_UNKNOWN";

/// Stable failure code: the local NazoAuth operator could not be invoked at
/// all (engine missing or unsupported runtime backend). No
/// envelope was presented to any authority.
pub const CONTROL_EXECUTION_UNAVAILABLE: &str = "CONTROL_EXECUTION_UNAVAILABLE";

/// Stable failure code: the running runtime object serves a different
/// artifact than the deployment state records. The operator is never invoked
/// against an object whose identity drifted.
pub const CONTROL_TARGET_DRIFT: &str = "CONTROL_TARGET_DRIFT";

/// Everything the executor needs besides the JWS itself. Built by dispatch
/// from live target facts; never serialized.
pub(crate) struct ControlJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    /// The deployment's recorded current artifact reference (`sha256:<hex>`).
    pub artifact_reference: &'a str,
    pub runtime_kind: &'a str,
    pub runtime_object: &'a str,
    pub config_reference: &'a str,
    pub data_root: &'a str,
    pub scope_dir: &'a Path,
    pub compact_jws: &'a str,
}

/// The injectable seam executing one delivered ControlOperation on the
/// target. Contract: on `Ok` the result is the operator's durable answer; on
/// `Err` nothing authoritative was learned.
pub(crate) trait ControlOperationExecutor: Send + Sync {
    fn execute(&self, job: &ControlJob<'_>) -> Result<ControlResult, Failure>;
}

/// Production executor backed by the runtime backends' one-shot machinery.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostControlOperator;

impl ControlOperationExecutor for HostControlOperator {
    fn execute(&self, job: &ControlJob<'_>) -> Result<ControlResult, Failure> {
        let kind = match job.runtime_kind {
            "podman" => crate::runtime_backend::RuntimeBackendKind::Podman,
            "docker" => crate::runtime_backend::RuntimeBackendKind::Docker,
            "host" | "systemd" => crate::runtime_backend::RuntimeBackendKind::Systemd,
            other => {
                return Err(Failure::new(
                    CONTROL_EXECUTION_UNAVAILABLE,
                    format!(
                        "deployment '{}': unsupported runtime backend '{other}'",
                        sanitize(job.deployment_id.to_owned())
                    ),
                ));
            }
        };
        let backend = crate::runtime_backend::backend(kind);
        if kind != crate::runtime_backend::RuntimeBackendKind::Systemd {
            if let Err(error) = crate::instance_lifecycle::privilege::ensure_engine_access(
                job.runtime_kind,
                &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
            ) {
                return Err(Failure::new(error.code(), sanitize(error.to_string())));
            }
        } else if let Err(error) = crate::instance_lifecycle::privilege::ensure_systemd_access() {
            return Err(Failure::new(error.code(), sanitize(error.to_string())));
        }
        let observation = backend
            .inspect(job.runtime_object)
            .map_err(|error| Failure::new(CONTROL_TARGET_DRIFT, sanitize(error.to_string())))?;
        let digest = match &observation.artifact {
            crate::runtime_backend::ArtifactReference::Oci { digest, .. } => digest,
            crate::runtime_backend::ArtifactReference::HostBinary { sha256, .. } => sha256,
            crate::runtime_backend::ArtifactReference::Unknown => {
                return Err(Failure::new(
                    CONTROL_TARGET_DRIFT,
                    "the running runtime object does not report a digest-bound artifact",
                ));
            }
        };
        let expected = job
            .artifact_reference
            .trim_start_matches("sha256:")
            .to_owned();
        if *digest != expected {
            return Err(Failure::new(
                CONTROL_TARGET_DRIFT,
                format!(
                    "runtime object '{}' serves {} while the deployment state records {}",
                    job.runtime_object,
                    sanitize(digest.clone()),
                    sanitize(expected)
                ),
            ));
        }

        let systemd = kind == crate::runtime_backend::RuntimeBackendKind::Systemd;
        let mut environment = BTreeMap::new();
        let mut read_only_paths = Vec::new();
        let mut read_write_paths = Vec::new();
        if systemd {
            environment.insert(
                super::install_exec::SERVER_CONFIG_FILE_ENV.to_owned(),
                job.config_reference.to_owned(),
            );
            environment.insert(
                "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
                job.scope_dir
                    .join("config-revision")
                    .to_string_lossy()
                    .into_owned(),
            );
            environment.insert(
                "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
                Path::new(job.data_root)
                    .join("operator-state")
                    .to_string_lossy()
                    .into_owned(),
            );
            read_only_paths.push(PathBuf::from(job.config_reference));
            read_write_paths.push(PathBuf::from(job.data_root));
        }
        let task = crate::runtime_backend::OneShotTask {
            artifact: observation.artifact.clone(),
            // The frozen NazoAuth one-shot entry: compact JWS on stdin, the
            // durable ControlResult JSON on stdout.
            command: vec!["nazoauth".to_owned(), "operator-task".to_owned()],
            network: observation.networks.first().cloned(),
            mounts: observation.mounts.clone(),
            environment,
            working_directory: if systemd {
                Some(PathBuf::from(job.data_root))
            } else {
                Some(PathBuf::from("/app"))
            },
            service_user: Some(if systemd {
                super::update_exec::systemd_service_user(job.deployment_id)
            } else {
                crate::runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned()
            }),
            transient_credentials: BTreeMap::new(),
            read_only_paths,
            read_write_paths,
            inaccessible_paths: Vec::new(),
            private_mounts: false,
            stdin: format!("{}\n", job.compact_jws).into_bytes(),
        };
        let stdout = backend
            .run_one_shot(&task)
            .map_err(|error| Failure::new(CONTROL_OUTCOME_UNKNOWN, sanitize(error.to_string())))?;
        decode_operator_answer(&stdout, job.operation_id)
    }
}

/// Decode the operator's single-line answer and pin it to the presented
/// operation id. Empty or unparsable output means the outcome is unknown —
/// never a refusal.
pub(crate) fn decode_operator_answer(
    stdout: &str,
    operation_id: &str,
) -> Result<ControlResult, Failure> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Failure::new(
            CONTROL_OUTCOME_UNKNOWN,
            "the local NazoAuth operator produced no ControlResult; the outcome is unknown and \
             only a resumed resend of the same operation can resolve it",
        ));
    }
    let line = trimmed.lines().next().unwrap_or(trimmed);
    let result =
        nazo_operator_protocol::decode_control_result(line.as_bytes()).map_err(|error| {
            Failure::new(
                CONTROL_OUTCOME_UNKNOWN,
                format!(
                    "the operator answer did not parse as a ControlResult ({}); the outcome is \
                     unknown",
                    sanitize(error.to_string())
                ),
            )
        })?;
    if result.operation_id != operation_id {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!(
                "the operator answered operation '{}' while '{}' was presented",
                sanitize(result.operation_id.clone()),
                sanitize(operation_id.to_owned())
            ),
        ));
    }
    Ok(result)
}
