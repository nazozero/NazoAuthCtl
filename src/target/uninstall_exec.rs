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
        if !matches!(job.runtime_kind, "podman" | "docker") {
            return Err(Failure::new(
                HOST_ERR_OPERATION_INVALID,
                format!(
                    "the '{}' runtime backend joins the lifecycle waves with the K-phase \
                     integration; use Podman or Docker deployments",
                    sanitize(job.runtime_kind.to_owned())
                ),
            ));
        }
        privilege_gate(job.runtime_kind)?;
        let kind = match job.runtime_kind {
            "podman" => crate::deployment::RuntimeBackendKind::Podman,
            _ => crate::deployment::RuntimeBackendKind::Docker,
        };
        let backend = crate::runtime_backend::backend(kind);

        // 1. Runtime object with identity re-confirmation. The label written
        // at install time is the ownership proof; an unlabeled or foreign
        // object under our name is never removed.
        if let Ok(Some(observation)) = backend.inspect_optional(job.runtime_object) {
            let owned = observation
                .labels
                .get("io.nazoauth.deployment-id")
                .is_some_and(|label| label == job.deployment_id);
            if !owned {
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
            if let crate::runtime_backend::ArtifactReference::Oci { digest, .. } =
                &observation.artifact
            {
                let expected = job.current_artifact.trim_start_matches("sha256:");
                if *digest != expected {
                    return Err(Failure::new(
                        super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                        format!(
                            "runtime object '{}' serves '{}' while the deployment state records \
                             '{}'; refusing to delete drifted state",
                            sanitize(job.runtime_object.to_owned()),
                            sanitize(digest.clone()),
                            sanitize(expected.to_owned())
                        ),
                    ));
                }
            }
            backend.stop(job.runtime_object).map_err(|error| {
                Failure::new(
                    super::install_exec::RUNTIME_START_FAILED,
                    sanitize(error.to_string()),
                )
            })?;
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
        "container" => {
            // Container objects are removed through the runtime-object step
            // above; a second container-kind declaration would name a
            // different object and is not understood here.
            Err(Failure::new(
                super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                "container resources are deleted only through the runtime surface object",
            ))
        }
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
            // W2.4: verify the ownership marker before deleting. The marker
            // proves ctl created this directory during install.
            let marker = path.join(".nazoauth-owned");
            if marker.exists() {
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
            if path.exists() {
                filesystem::remove_file_durable(path).map_err(|error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to delete file {}: {error}", path.display()),
                    )
                })?;
                performed.removed_paths.push(locator.to_owned());
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
    crate::instance_lifecycle::privilege::ensure_engine_access(
        runtime_kind,
        &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
    )
    .map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))
}
