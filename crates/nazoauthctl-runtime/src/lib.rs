//! Process execution and runtime adapter boundary for NazoAuthCtl.
//!
//! This crate owns the neutral runtime contract and the Docker/Podman
//! implementations, systemd integration, and the audited filesystem
//! primitives used by the controller core.

pub mod filesystem;
pub mod process;
pub mod runtime_backend;
pub mod secure_file;

pub use runtime_backend::{
    ArtifactReference, BlobAttestationVerification, ContainerRestartPolicy, ContainerRuntimePolicy,
    HostServiceInstall, NeutralMount, NeutralTmpfs, OneShotTask, RecoveryCandidateEndpoint,
    RecoveryCandidateRequest, ResourceScope, Responsibility, RuntimeBackend, RuntimeBackendKind,
    RuntimeObservation, RuntimeReplacement, normalize_local_image_id, safe_systemd_path,
};

#[cfg(all(test, unix))]
#[path = "../../../tests/unit/support.rs"]
mod test_support;
