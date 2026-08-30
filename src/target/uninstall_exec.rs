//! Target-side execution of the uninstall deletion plan (goal plan 07 §7,
//! task G06).
//!
//! The control side shows the live DeploymentState as a deletion preview.
//! The target then uses that same authoritative state for the one journaled
//! Uninstall mutation:
//!
//! * only resources declared `managed + deployment` are deleted; external or
//!   shared resources have no deletion path;
//! * the runtime object is removed only when its deployment-id label proves
//!   it belongs to THIS deployment — a foreign object under the managed name
//!   is never touched;
//! * the runtime uses its dedicated adapter; only physically understood
//!   managed filesystem kinds (`directory`, `file`) are deleted.
//!
//! Completion removes the state document (the operation journal survives so
//! retries replay the stored terminal result), deletes the config file and
//! and leaves external/shared resources, sibling deployments, and host-level
//! facts untouched.

use std::path::Path;

use super::deployment_state::{Failure, Resource, TargetStateStore};
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};
use crate::filesystem;

/// Everything one uninstall needs besides the confirmed plan itself.
pub(crate) struct DeletionJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    pub runtime_kind: crate::runtime_backend::RuntimeBackendKind,
    pub runtime_object: &'a str,
    pub config_reference: &'a str,
    /// Live resources from the target-owned DeploymentState.
    pub declared: &'a [Resource],
    pub expected_revision: u64,
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
        let kind = job.runtime_kind;
        privilege_gate(kind)?;
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
            if kind.is_container()
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
            if kind.is_container() {
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

        // 2. Delete only resources the authoritative target state classifies
        // as managed and deployment-scoped. The runtime object has its own
        // adapter above and must not be deleted twice.
        for resource in job.declared.iter().filter(|resource| {
            resource.ownership == super::deployment_state::ResourceOwnership::Managed
                && resource.scope == super::deployment_state::ResourceScope::Deployment
                && resource.kind != "container"
        }) {
            delete_managed_resource(&resource.kind, &resource.locator, performed)?;
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

        // 4. Drop the state document last; the operation journal survives so
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
    performed: &mut PerformedDeletions,
) -> Result<(), Failure> {
    match kind {
        "directory" => {
            let path = Path::new(locator);
            if !safe_managed_path(path) {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete directory '{}': not a deep absolute path",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            // Absence is the durable completion fact for this exact resource.
            // The locator was already re-confirmed against DeploymentState
            // before the first attempt. A crash after remove_dir_all must not
            // turn the now-absent ownership marker into a replay failure.
            if !path.exists() {
                return Ok(());
            }
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to inspect managed directory: {error}"),
                )
            })?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete directory '{}': locator is not a real directory",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            make_tree_removable(path)?;
            std::fs::remove_dir_all(path).map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to delete directory {}: {error}", path.display()),
                )
            })?;
            performed.removed_paths.push(locator.to_owned());
            Ok(())
        }
        "file" => {
            let path = Path::new(locator);
            if !safe_managed_path(path) {
                return Err(Failure::new(
                    super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                    format!(
                        "refusing to delete file '{}': not a deep absolute path",
                        sanitize(locator.to_owned())
                    ),
                ));
            }
            let marker_path = format!("{locator}.nazoauth-owned");
            let marker = Path::new(marker_path.as_str());
            if !path.exists() && !marker.exists() {
                return Ok(());
            }
            if path.exists() {
                let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                    Failure::new(
                        HOST_ERR_OPERATION_INVALID,
                        format!("failed to inspect managed file: {error}"),
                    )
                })?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(Failure::new(
                        super::deployment_state::OBJECT_IDENTITY_MISMATCH,
                        format!(
                            "refusing to delete file '{}': locator is not a real file",
                            sanitize(locator.to_owned())
                        ),
                    ));
                }
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

fn safe_managed_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 2
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

/// Applications may make immutable release subdirectories inside their
/// writable data root. The rootless installer still owns those directories,
/// so restore owner write/traverse permission before removing the exact
/// target-state-owned tree. Symlinks are never followed.
fn make_tree_removable(path: &Path) -> Result<(), Failure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!("failed to inspect managed path {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    #[cfg(unix)]
    if metadata.is_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o700)).map_err(
            |error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!(
                        "failed to make managed directory {} removable: {error}",
                        path.display()
                    ),
                )
            },
        )?;
    }

    #[cfg(windows)]
    if metadata.permissions().readonly() {
        clear_windows_readonly(path, &metadata)?;
    }

    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|error| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                format!(
                    "failed to enumerate managed directory {}: {error}",
                    path.display()
                ),
            )
        })? {
            let entry = entry.map_err(|error| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    format!("failed to enumerate managed directory entry: {error}"),
                )
            })?;
            make_tree_removable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(
    clippy::permissions_set_readonly_false,
    reason = "Windows readonly is a file attribute, not a Unix permission mask"
)]
fn clear_windows_readonly(path: &Path, metadata: &std::fs::Metadata) -> Result<(), Failure> {
    let mut permissions = metadata.permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions).map_err(|error| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!(
                "failed to make managed path {} removable: {error}",
                path.display()
            ),
        )
    })
}

fn privilege_gate(runtime_kind: crate::runtime_backend::RuntimeBackendKind) -> Result<(), Failure> {
    let result = if runtime_kind.is_container() {
        crate::instance_lifecycle::privilege::ensure_engine_access(
            runtime_kind.as_str(),
            &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
        )
    } else {
        crate::instance_lifecycle::privilege::ensure_systemd_access()
    };
    result.map_err(|error| Failure::new(error.code(), sanitize(error.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_directory_deletion_uses_target_state_and_is_resume_safe() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("uninstall-directory-replay")?;
        let path = temp.path().join("managed").join("data");
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("value"), b"data")?;
        let release = path.join("ui-releases").join("immutable");
        std::fs::create_dir_all(&release)?;
        std::fs::write(release.join("asset"), b"asset")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&release, std::fs::Permissions::from_mode(0o555))?;
        }
        #[cfg(windows)]
        {
            let mut permissions = std::fs::metadata(&release)?.permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&release, permissions)?;
        }
        let locator = path.to_string_lossy().into_owned();
        let mut performed = PerformedDeletions::default();

        delete_managed_resource("directory", &locator, &mut performed)?;
        assert!(!path.exists());
        delete_managed_resource("directory", &locator, &mut performed)?;

        let error = delete_managed_resource("directory", "relative/path", &mut performed)
            .expect_err("a non-absolute locator remains protected");
        assert_eq!(
            error.code,
            super::super::deployment_state::OBJECT_IDENTITY_MISMATCH
        );
        Ok(())
    }

    #[test]
    fn managed_file_deletion_converges_after_each_durable_step() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("uninstall-file-replay")?;
        let path = temp.path().join("managed-file");
        let locator = path.to_string_lossy().into_owned();
        let marker = std::path::PathBuf::from(format!("{locator}.nazoauth-owned"));
        std::fs::write(&marker, "deploy-alpha")?;
        let mut performed = PerformedDeletions::default();

        // This is the exact crash window after the file was removed but
        // before its sibling ownership marker was removed.
        delete_managed_resource("file", &locator, &mut performed)?;
        assert!(!marker.exists());
        delete_managed_resource("file", &locator, &mut performed)?;

        std::fs::write(&path, b"managed by authoritative target state")?;
        delete_managed_resource("file", &locator, &mut performed)?;
        assert!(!path.exists());
        Ok(())
    }
}
