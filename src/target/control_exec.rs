//! Target-side execution of delivered ControlOperations (goal plan 05 §6,
//! task G-wave decision 1).
//!
//! A `control-operation` HostOperation makes the target invoke its LOCAL
//! NazoAuth one-shot operator — the exact binary the legacy runtime drove as
//! `nazauth operator-task` inside the deployment's verified OCI artifact (or
//! the `operator-task` host binary on systemd targets, see legacy
//! `src/runtime.rs` argv patterns) — with the compact JWS on stdin and a
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

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::ControlResult;

use super::deployment_state::Failure;
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};

/// Stable failure code: the operator ran (or may have run) but produced no
/// parsable ControlResult. The outcome is unknown by construction; retries
/// must resume the same operation id instead of minting a new one.
pub const CONTROL_OUTCOME_UNKNOWN: &str = "CONTROL_OUTCOME_UNKNOWN";

/// Stable failure code: the local NazoAuth operator could not be invoked at
/// all (engine missing, systemd backend not integrated in this wave). No
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
            "podman" => crate::deployment::RuntimeBackendKind::Podman,
            "docker" => crate::deployment::RuntimeBackendKind::Docker,
            // The systemd host backend joins the lifecycle waves with the
            // K-phase integration, exactly like the install order.
            other => {
                return Err(Failure::new(
                    CONTROL_EXECUTION_UNAVAILABLE,
                    format!(
                        "deployment '{}': the '{other}' runtime backend cannot drive the local \
                         NazoAuth operator yet; use Podman or Docker deployments",
                        sanitize(job.deployment_id.to_owned())
                    ),
                ));
            }
        };
        let backend = crate::runtime_backend::backend(kind);
        if let Err(error) = crate::instance_lifecycle::privilege::ensure_engine_access(
            job.runtime_kind,
            &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
        ) {
            return Err(Failure::new(error.code(), sanitize(error.to_string())));
        }
        let observation = backend
            .inspect(job.runtime_object)
            .map_err(|error| Failure::new(CONTROL_TARGET_DRIFT, sanitize(error.to_string())))?;
        let crate::runtime_backend::ArtifactReference::Oci {
            image_reference: _,
            digest,
        } = &observation.artifact
        else {
            return Err(Failure::new(
                CONTROL_TARGET_DRIFT,
                "the running runtime object does not report a digest-bound OCI artifact",
            ));
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

        let task = crate::runtime_backend::OneShotTask {
            artifact: observation.artifact.clone(),
            // The frozen NazoAuth one-shot entry: compact JWS on stdin, the
            // durable ControlResult JSON on stdout (legacy `operator-task`).
            command: vec!["nazauth".to_owned(), "operator-task".to_owned()],
            network: observation.networks.first().cloned(),
            mounts: observation.mounts.clone(),
            environment: BTreeMap::new(),
            working_directory: Some(std::path::PathBuf::from("/app")),
            service_user: Some(crate::runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned()),
            transient_credentials: BTreeMap::new(),
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
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

/// Extract the operation id carried by a compact JWS payload segment without
/// verifying it. Verification is the server's job; this exists only so the
/// transport can refuse answers that do not echo the presented identity.
pub(crate) fn control_operation_id_from_jws(compact_jws: &str) -> anyhow::Result<String> {
    use anyhow::Context as _;
    let mut segments = compact_jws.split('.');
    let (_, payload, _) = match (segments.next(), segments.next(), segments.next()) {
        (Some(p), Some(l), Some(s)) if !p.is_empty() && !l.is_empty() && !s.is_empty() => (p, l, s),
        _ => anyhow::bail!("compact_jws is not a three-segment JWS"),
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .context("compact_jws payload is not base64url")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("compact_jws payload is not JSON")?;
    Ok(value["operation_id"]
        .as_str()
        .context("compact_jws payload carries no operation_id")?
        .to_owned())
}
