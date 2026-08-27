//! Core integration for the runtime adapters owned by `nazoauthctl-runtime`.
//!
//! This module keeps the existing core-facing backend selection API while the
//! concrete adapters, process runner, and filesystem primitives live in the
//! runtime crate.

pub(crate) use nazoauthctl_runtime::runtime_backend::{
    ArtifactReference, BlobAttestationVerification, ContainerRuntimePolicy, HostServiceInstall,
    NON_ROOT_ONE_SHOT_USER, NeutralMount, OneShotTask, ResourceScope as RuntimeResourceScope,
    Responsibility, RuntimeBackend, RuntimeBackendKind, RuntimeObservation, RuntimeReplacement,
    SystemdBackend,
};

#[cfg(all(test, target_os = "linux"))]
pub(crate) use nazoauthctl_runtime::runtime_backend::managed_network_config_digest;

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
