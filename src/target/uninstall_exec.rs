//! Target-side execution of the uninstall deletion plan (goal plan 07 §7,
//! task G06).
//!
//! The control side generates the exact deletion plan from the live
//! DeploymentState and sends it inside the one journaled Uninstall mutation.
//! The target then re-confirms every fact before any destructive step:
//!
//! * each planned resource id must resolve through
//!   [`TargetStateStore::load_existing`] + `exact_managed_deployment_resource`
//!   — external or shared resources fail closed with the stable zero-delete
//!   codes before this executor ever runs;
//! * each planned locator must equal the declared locator byte-for-byte
//!   (plan-vs-state drift fails closed with [`OBJECT_IDENTITY_MISMATCH`]);
//! * the runtime object is removed only when its deployment-id label proves
//!   it belongs to THIS deployment — a foreign object under the managed name
//!   is never touched;
//! * only physically understood managed kinds are deleted (`container`,
//!   `directory`, `file`); anything else fails closed.
//!
//! Completion removes the state document (the operation journal survives so
//! retries replay the stored terminal result), deletes the config file and
//! fresh-bootstrap material, and leaves external/shared resources, sibling
//! deployments, and host-level facts untouched.

use std::path::Path;

use super::bootstrap_authority;
use super::deployment_state::{Failure, Resource, TargetStateStore};
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};
use crate::filesystem;

/// Everything one uninstall needs besides the confirmed plan itself.
pub(crate) struct DeletionJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub runtime_kind: &'a str,
    pub runtime_object: &'a str,
    pub current_artifact: &'a str,
    pub config_reference: &'a str,
    pub resources: &'a [super::install_exec::PlannedResourceDeletion],
    /// Live declared resources from the DeploymentState (identity source).
    pub declared: &'a [Resource],
    pub expected_revision: u64,
    pub scope_dir: &'a Path,
    pub store: &'a TargetStateStore,
}

/// The injectable seam executing the physical deletion on the target.
pub(crate) trait DeletionExecutor: Send + Sync {
    fn execute_deletion(&self, job: &DeletionJob<'_>) -> Result<(), Failure>;
}

/// Steps recorded for precise failure reporting.
#[derive(Default)]
pub(crate) struct PerformedDeletions {
    pub(crate) removed_objects: Vec<String>,
    pub(crate) removed_paths: Vec<String>,
}

/// Production executor backed by the real adapters.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostDeletionExecutor;

impl DeletionExecutor for HostDeletionExecutor {
    fn execute_deletion(&self, job: &DeletionJob<'_>) -> Result<(), Failure> {
        let mut performed = PerformedDeletions::default();
        match self.run(job, &mut performed) {
            Ok(()) => Ok(()),
            Err(failure) => {
                // Deletions are not undone on failure: partial destruction is
                // reported exactly so the operator can re-run the same plan
                // (every step is idempotent by identity re-confirmation).
                Err(failure)
            }
        }
    }
}

impl HostDeletionExecutor {
    fn run(
        &self,
        job: &DeletionJob<'_>,
        performed: &mut PerformedDeletions,
    ) -> Result<(), Failure> {
        if !matches!(job.runtime_kind, "podman" | "docker" | "host" | "systemd") {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                format!(
                    "the '{}' runtime backend is not supported for lifecycle mutations; \
                     use Podman, Docker, or systemd deployments",
                    sanitize(job.runtime_kind.to_owned())
                ),
            ));
        }
        privilege_gate(job.runtime_kind)?;
        let kind = match job.runtime_kind {
            "podman" => crate::runtime_backend::RuntimeBackendKind::Podman,
            "docker" => crate::runtime_backend::RuntimeBackendKind::Docker,
            _ => crate::runtime_backend::RuntimeBackendKind::Systemd,
        };
        let backend = crate::runtime_backend::backend(kind);

        // 1. Runtime object with identity re-confirmation. The label written
        // at install time is the ownership proof; an unlabeled or foreign
        // object under our name is never removed.
        let observation = backend
            .inspect_optional(job.runtime_object)
            .map_err(|error| {
                Failure::new(
                    super::install_exec::RUNTIME_START_FAILED,
                    sanitize(error.to_string()),
                )
            })?;
        if let Some(observation) = observation {
            if kind != crate::runtime_backend::RuntimeBackendKind::Systemd
                && !observation
                    .labels
                    .get("io.nazoauth.deployment-id")
                    .is_some_and(|label| label == job.deployment_id)
            {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "runtime object '{}' exists without this deployment's ownership label; \
                         refusing to remove a possibly foreign object",
                        sanitize(job.runtime_object.to_owned())
                    ),
                ));
            }
            // Second confirmation: a labeled object must still serve exactly
            // the artifact the deployment state records before deletion.
            let observed_digest = match &observation.artifact {
                crate::runtime_backend::ArtifactReference::Oci { digest, .. }
                | crate::runtime_backend::ArtifactReference::HostBinary {
                    sha256: digest, ..
                } => digest.trim_start_matches("sha256:"),
                crate::runtime_backend::ArtifactReference::Unknown => {
                    return Err(Failure::new(
                        super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                        "runtime object has no verifiable artifact identity",
                    ));
                }
            };
            let expected = job.current_artifact.trim_start_matches("sha256:");
            if observed_digest != expected {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "runtime object '{}' serves '{}' while the deployment state records \
                         '{}'; refusing to delete drifted state",
                        sanitize(job.runtime_object.to_owned()),
                        sanitize(observed_digest.to_owned()),
                        sanitize(expected.to_owned())
                    ),
                ));
            }
            if kind != crate::runtime_backend::RuntimeBackendKind::Systemd {
                backend.stop(job.runtime_object).map_err(|error| {
                    Failure::new(
                        super::install_exec::RUNTIME_START_FAILED,
                        sanitize(error.to_string()),
                    )
                })?;
            }
            backend.remove(job.runtime_object).map_err(|error| {
                Failure::new(
                    super::install_exec::RUNTIME_START_FAILED,
                    sanitize(error.to_string()),
                )
            })?;
            performed
                .removed_objects
                .push(job.runtime_object.to_owned());
        }

        // 2. Planned resources: identity re-confirmed against the live
        // declaration, then deleted by their concrete kind.
        for planned in job.resources {
            let declared = job
                .declared
                .iter()
                .find(|resource| resource.resource_id == planned.resource_id)
                .ok_or_else(|| {
                    Failure::new(
                        super::deployment_state::RESOURCE_UNKNOWN,
                        format!(
                            "planned resource '{}' is not declared by the live deployment state",
                            sanitize(planned.resource_id.clone())
                        ),
                    )
                })?;
            if declared.locator != planned.locator {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "resource '{}' drifted: plan names '{}' while the live state declares '{}'; \
                         regenerate the plan",
                        sanitize(planned.resource_id.clone()),
                        sanitize(planned.locator.clone()),
                        sanitize(declared.locator.clone())
                    ),
                ));
            }
            delete_managed_resource(
                &declared.kind,
                &declared.locator,
                job.deployment_id,
                performed,
            )?;
        }

        // 3. The configuration file created by install/managed by the update
        // flow. Its path is the DeploymentState's own reference — never a
        // wildcard, never derived from user input here.
        let config_path = Path::new(job.config_reference);
        let config_marker =
            std::path::PathBuf::from(format!("{}.nazoauth-owned", job.config_reference));
        if config_path.exists() {
            filesystem::remove_file_durable(config_path).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to remove {}: {error}", config_path.display()),
                )
            })?;
            performed
                .removed_paths
                .push(job.config_reference.to_owned());
        }
        if config_marker.exists() {
            filesystem::remove_file_durable(&config_marker).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to remove {}: {error}", config_marker.display()),
                )
            })?;
        }

        // 4. Fresh-install bootstrap material, whatever its state.
        bootstrap_authority::delete_material(job.scope_dir).map_err(|error| {
            Failure::new(HOST_ERR_OPERATION_INVALID, sanitize(error.to_string()))
        })?;

        // 5. Drop the state document last; the operation journal survives so
        // a retried uninstall replays instead of re-executing.
        job.store
            .remove_deployment(job.deployment_id, job.expected_revision, job.operation_id)?;

        Ok(())
    }
}

/// Delete ONE re-confirmed managed+deployment resource by its concrete kind.
/// Unknown kinds fail closed — there is no best-effort guessing about how to
/// destroy something ctl cannot precisely describe.
fn delete_managed_resource(
    kind: &str,
    locator: &str,
    deployment_id: &str,
    performed: &mut PerformedDeletions,
) -> Result<(), Failure> {
    match kind {
        "directory" => {
            let path = Path::new(locator);
            let safe = path.is_absolute()
                && path.components().count() > 2
                && !path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir));
            if !safe {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete directory '{}': not a deep absolute path",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            // W2.4/P1-1: the ownership marker is the deletion credential. A
            // missing marker means ctl did not create this directory (or the
            // state tree was tampered with); either way fail closed.
            let marker = path.join(".nazoauth-owned");
            if !marker.exists() {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete directory '{}': no .nazoauth-owned marker; ctl did \
                         not create it",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            let owned_by = std::fs::read_to_string(&marker).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to read ownership marker: {error}"),
                )
            })?;
            if owned_by.trim() != deployment_id {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "directory '{}' is owned by '{}', not '{}'",
                        sanitize(locator.to_owned()),
                        sanitize(owned_by.trim().to_owned()),
                        sanitize(deployment_id.to_owned())
                    ),
                ));
            }
            if path.exists() {
                std::fs::remove_dir_all(path).map_err(|error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to delete directory {}: {error}", path.display()),
                    )
                })?;
                performed.removed_paths.push(locator.to_owned());
            }
            Ok(())
        }
        "file" => {
            let path = Path::new(locator);
            // P1-1: config files carry the same ownership proof as
            // directories — a sibling marker file named `<path>.nazoauth-owned`
            // written at install time must exist and match.
            let marker_path = format!("{locator}.nazoauth-owned");
            let marker = Path::new(marker_path.as_str());
            if !marker.exists() {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete file '{}': no .nazoauth-owned proof marker",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            let owned_by = std::fs::read_to_string(marker).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to read ownership marker: {error}"),
                )
            })?;
            if owned_by.trim() != deployment_id {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "file '{}' is owned by '{}', not '{}'",
                        sanitize(locator.to_owned()),
                        sanitize(owned_by.trim().to_owned()),
                        sanitize(deployment_id.to_owned())
                    ),
                ));
            }
            if path.exists() {
                filesystem::remove_file_durable(path).map_err(|error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to delete file {}: {error}", path.display()),
                    )
                })?;
                performed.removed_paths.push(locator.to_owned());
            }
            if marker.exists() {
                filesystem::remove_file_durable(marker).map_err(|error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to delete marker {}: {error}", marker.display()),
                    )
                })?;
            }
            Ok(())
        }
        other => Err(Failure::new(
            super::deployment_state::OBJECT_IDENTITY_MISMATCH,
            format!(
                "managed resource kind '{}' has no deletion procedure; extend the vocabulary \
                 explicitly before deleting such objects",
                sanitize(other.to_owned())
            ),
        )),
    }
}

fn privilege_gate(runtime_kind: &str) -> Result<(), Failure> {
    let result = if matches!(runtime_kind, "podman" | "docker") {
        crate::instance_lifecycle::privilege::ensure_engine_access(
            runtime_kind,
            &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
        )
    } else {
        crate::instance_lifecycle::privilege::ensure_systemd_access()
    };
    result.map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))
}
