//! Process execution and runtime adapter boundary for NazoAuthCtl.
//!
//! This crate owns the neutral runtime contract and the Docker/Podman
//! implementations, systemd integration, and the audited filesystem
//! primitives used by the controller core.

pub mod filesystem;
pub mod process;
pub mod runtime_backend;

pub use runtime_backend::{
    ArtifactReference, BlobAttestationVerification, ContainerRestartPolicy, ContainerRuntimePolicy,
    HostServiceInstall, ManagedDependencies, ManagedDependencyBackup, ManagedDependencyIdentity,
    ManagedNetwork, ManagedPostgresCommand, ManagedPostgresRestore, ManagedValkeyRestore,
    MountReference, NeutralMount, NeutralTmpfs, OneShotTask, ResourceScope, Responsibility,
    RuntimeBackend, RuntimeBackendKind, RuntimeDatabasePrivilegeProbe, RuntimeInstance,
    RuntimeObservation, RuntimeReplacement, RuntimeSurfaceDrift, compare_declared_runtime_surface,
    managed_config_digest, managed_dependency_identity, managed_network_config_digest,
    normalize_local_image_id, safe_systemd_path,
};

#[cfg(debug_assertions)]
pub use runtime_backend::DebugArtifactTask;

#[cfg(all(test, unix))]
#[path = "../../../tests/unit/support.rs"]
mod test_support;
