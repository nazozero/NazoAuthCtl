//! Podman runtime backend façade.
//!
//! The backend owns only the Podman executable and the `RuntimeBackend`
//! contract.  Podman discovery, lifecycle operations, one-shot tasks, and
//! managed dependency handling live in focused sibling modules so that the
//! command policy remains auditable without changing the public backend API.

mod discovery;
mod managed_dependencies;
mod one_shot;
mod operations;

use std::ffi::OsString;

use crate::{ArtifactReference, RuntimeBackendKind};

#[cfg(debug_assertions)]
use super::DebugArtifactTask;
use super::{
    BlobAttestationVerification, HostServiceInstall, ManagedDependencies, ManagedDependencyBackup,
    ManagedPostgresCommand, ManagedPostgresRestore, ManagedValkeyRestore, NeutralMount,
    OneShotTask, RecoveryCandidateEndpoint, RecoveryCandidateRequest, RuntimeBackend,
    RuntimeObservation, RuntimeReplacement,
};

pub struct PodmanBackend {
    command: OsString,
}

impl Default for PodmanBackend {
    fn default() -> Self {
        Self {
            command: OsString::from("podman"),
        }
    }
}

impl PodmanBackend {
    pub fn with_command(command: impl Into<OsString>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

impl RuntimeBackend for PodmanBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Podman
    }

    fn available(&self) -> bool {
        operations::available(&self.command)
    }

    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>> {
        discovery::discover(&self.command)
    }

    fn inspect(&self, object_reference: &str) -> anyhow::Result<RuntimeObservation> {
        discovery::inspect(&self.command, object_reference)
    }

    fn inspect_optional(
        &self,
        object_reference: &str,
    ) -> anyhow::Result<Option<RuntimeObservation>> {
        discovery::inspect_optional(&self.command, object_reference)
    }

    fn read_logs(&self, object_reference: &str, limit: usize) -> anyhow::Result<Vec<String>> {
        discovery::inspect(&self.command, object_reference)?;
        let output = crate::process::Process::new(self.command.clone())
            .args(["logs", "--tail"])
            .arg(limit.to_string())
            .arg(object_reference)
            .stdout()?;
        Ok(output.lines().map(str::to_owned).collect())
    }

    fn start(&self, object_reference: &str) -> anyhow::Result<()> {
        operations::start(&self.command, object_reference)
    }

    fn stop(&self, object_reference: &str) -> anyhow::Result<()> {
        operations::stop(&self.command, object_reference)
    }

    fn quiesce_for_recovery(&self, object_reference: &str) -> anyhow::Result<()> {
        operations::quiesce_for_recovery(&self.command, object_reference)
    }

    fn restart(&self, object_reference: &str) -> anyhow::Result<()> {
        operations::restart(&self.command, object_reference)
    }

    fn remove(&self, object_reference: &str) -> anyhow::Result<()> {
        operations::remove(&self.command, object_reference)
    }

    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()> {
        operations::replace(&self.command, replacement)
    }

    fn stage_recovery_candidate(
        &self,
        request: &RecoveryCandidateRequest,
    ) -> anyhow::Result<RecoveryCandidateEndpoint> {
        super::container_shared::stage_recovery_candidate(
            &self.command,
            "Podman",
            &discovery::inspect(&self.command, &request.source_object_reference)?,
            request,
            false,
        )
    }

    fn cleanup_recovery_candidate(
        &self,
        endpoint: &RecoveryCandidateEndpoint,
    ) -> anyhow::Result<()> {
        super::container_shared::cleanup_recovery_candidate(&self.command, "Podman", endpoint)
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        one_shot::run(&self.command, task)
    }

    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool> {
        one_shot::run_authorization_probe(&self.command, task)
    }

    fn pull_image(&self, image_reference: &str) -> anyhow::Result<()> {
        operations::pull_image(&self.command, image_reference)
    }

    fn export_image(&self, image_reference: &str, archive: &std::path::Path) -> anyhow::Result<()> {
        operations::export_image(&self.command, image_reference, archive)
    }

    fn import_image(&self, archive: &std::path::Path) -> anyhow::Result<()> {
        operations::import_image(&self.command, archive)
    }

    fn restore_managed_postgres(&self, restore: &ManagedPostgresRestore) -> anyhow::Result<()> {
        managed_dependencies::restore_postgres(&self.command, restore)
    }

    fn restore_managed_valkey(&self, restore: &ManagedValkeyRestore) -> anyhow::Result<()> {
        managed_dependencies::restore_valkey(&self.command, restore)
    }

    fn execute_managed_postgres(&self, command: &ManagedPostgresCommand) -> anyhow::Result<()> {
        managed_dependencies::execute_postgres(&self.command, command)
    }

    fn backup_managed_dependencies(&self, backup: &ManagedDependencyBackup) -> anyhow::Result<()> {
        managed_dependencies::backup(&self.command, backup)
    }

    fn ensure_managed_network(
        &self,
        network: &super::ManagedNetwork,
    ) -> anyhow::Result<std::net::IpAddr> {
        managed_dependencies::ensure_network(&self.command, network)
    }

    fn ensure_managed_dependencies(
        &self,
        dependencies: &ManagedDependencies,
    ) -> anyhow::Result<()> {
        managed_dependencies::ensure_dependencies(&self.command, dependencies)
    }

    fn install_host_service(&self, install: &HostServiceInstall) -> anyhow::Result<()> {
        operations::install_host_service(install)
    }

    #[cfg(debug_assertions)]
    fn run_debug_artifact_task(&self, task: &DebugArtifactTask) -> anyhow::Result<()> {
        operations::run_debug_artifact_task(&self.command, task)
    }

    fn verify_blob_attestation(
        &self,
        verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()> {
        operations::verify_blob_attestation(&self.command, verification)
    }

    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String> {
        discovery::resolve_image_digest(&self.command, image_reference, None)
    }

    fn local_image_matches_digest(&self, image_reference: &str) -> bool {
        discovery::local_image_matches_digest(&self.command, image_reference)
    }

    fn resolve_local_image_id(&self, image_reference: &str) -> anyhow::Result<String> {
        discovery::resolve_local_image_id(&self.command, image_reference)
    }

    fn read_build_identity(
        &self,
        artifact: &ArtifactReference,
        local_artifact_id: Option<&str>,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>> {
        discovery::read_build_identity(&self.command, artifact, local_artifact_id)
    }

    fn describe_mounts(&self, object_reference: &str) -> anyhow::Result<Vec<NeutralMount>> {
        Ok(self.inspect(object_reference)?.mounts)
    }
}
