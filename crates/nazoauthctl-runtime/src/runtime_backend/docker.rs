//! Docker runtime backend façade.
//!
//! The backend owns only the Docker executable and the `RuntimeBackend`
//! contract.  Docker discovery, lifecycle operations, one-shot tasks, and
//! managed dependency handling live in focused sibling modules so that the
//! command policy remains auditable without changing the public backend API.

mod discovery;
mod one_shot;
mod operations;

use std::ffi::OsString;

use crate::RuntimeBackendKind;

use super::{
    BlobAttestationVerification, HostServiceInstall, OneShotTask, RecoveryCandidateEndpoint,
    RecoveryCandidateRequest, RuntimeBackend, RuntimeObservation, RuntimeReplacement,
};

pub struct DockerBackend {
    command: OsString,
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self {
            command: OsString::from("docker"),
        }
    }
}

impl DockerBackend {
    pub fn with_command(command: impl Into<OsString>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

impl RuntimeBackend for DockerBackend {
    fn kind(&self) -> RuntimeBackendKind {
        RuntimeBackendKind::Docker
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
        let document = super::container_shared::inspect_document(
            &self.command,
            &["container", "inspect", &request.source_object_reference],
            "Docker",
        )?;
        super::container_shared::stage_recovery_candidate(
            &self.command,
            "Docker",
            &discovery::observation_from_document(&self.command, &document)?,
            &document,
            request,
            true,
            false,
        )
    }

    fn cleanup_recovery_candidate(
        &self,
        endpoint: &RecoveryCandidateEndpoint,
    ) -> anyhow::Result<()> {
        super::container_shared::cleanup_recovery_candidate(&self.command, "Docker", endpoint)
    }

    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String> {
        one_shot::run(&self.command, task)
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

    fn install_host_service(&self, install: &HostServiceInstall) -> anyhow::Result<()> {
        operations::install_host_service(install)
    }

    fn verify_blob_attestation(
        &self,
        verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()> {
        operations::verify_blob_attestation(&self.command, verification)
    }

    fn local_image_matches_digest(&self, image_reference: &str) -> bool {
        discovery::local_image_matches_digest(&self.command, image_reference)
    }

    fn resolve_local_image_id(&self, image_reference: &str) -> anyhow::Result<String> {
        discovery::resolve_local_image_id(&self.command, image_reference)
    }
}
