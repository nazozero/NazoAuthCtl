//! Core integration for the runtime adapters owned by `nazoauthctl-runtime`.
//!
//! This module keeps the existing core-facing backend selection API while the
//! concrete adapters, process runner, and filesystem primitives live in the
//! runtime crate.

pub(crate) use nazoauthctl_runtime::runtime_backend::{
    ArtifactReference, BlobAttestationVerification, ContainerRuntimePolicy, HostServiceInstall,
    MANAGED_VALKEY_BACKUP_USER, MANAGED_VALKEY_RUNTIME_USER, ManagedDependencies,
    ManagedDependencyBackup, ManagedDependencyIdentity, ManagedNetwork, ManagedPostgresCommand,
    ManagedPostgresRestore, ManagedValkeyRestore, NeutralMount, OneShotTask,
    ResourceScope as RuntimeResourceScope, Responsibility, RuntimeBackend, RuntimeBackendKind,
    RuntimeDatabasePrivilegeProbe, RuntimeObservation, RuntimeReplacement, SystemdBackend,
    compare_declared_runtime_surface, managed_dependency_identity, normalize_local_image_id,
    oci_backup_digests,
};

#[cfg(test)]
pub(crate) use nazoauthctl_runtime::runtime_backend::{
    ContainerRestartPolicy, managed_config_digest, parse_systemd_version, render_host_service_unit,
};

#[cfg(all(test, target_os = "linux"))]
pub(crate) use nazoauthctl_runtime::runtime_backend::managed_network_config_digest;

#[cfg(debug_assertions)]
pub(crate) use nazoauthctl_runtime::runtime_backend::DebugArtifactTask;

pub(crate) fn installed_backends() -> Vec<Box<dyn RuntimeBackend>> {
    let backends: Vec<Box<dyn RuntimeBackend>> = vec![
        Box::new(nazoauthctl_runtime::runtime_backend::PodmanBackend::default()),
        Box::new(nazoauthctl_runtime::runtime_backend::DockerBackend::default()),
        Box::new(SystemdBackend),
    ];
    backends
        .into_iter()
        .filter(|backend| backend.available())
        .collect()
}

pub(crate) fn backend(kind: RuntimeBackendKind) -> Box<dyn RuntimeBackend> {
    match kind {
        RuntimeBackendKind::Podman => {
            Box::new(nazoauthctl_runtime::runtime_backend::PodmanBackend::default())
        }
        RuntimeBackendKind::Docker => {
            Box::new(nazoauthctl_runtime::runtime_backend::DockerBackend::default())
        }
        RuntimeBackendKind::Systemd => Box::new(SystemdBackend),
    }
}

#[cfg(test)]
pub(crate) fn backend_with_command(
    kind: RuntimeBackendKind,
    command: impl Into<std::ffi::OsString>,
) -> Box<dyn RuntimeBackend> {
    match kind {
        RuntimeBackendKind::Podman => {
            Box::new(nazoauthctl_runtime::runtime_backend::PodmanBackend::with_command(command))
        }
        RuntimeBackendKind::Docker => {
            Box::new(nazoauthctl_runtime::runtime_backend::DockerBackend::with_command(command))
        }
        RuntimeBackendKind::Systemd => Box::new(SystemdBackend),
    }
}
