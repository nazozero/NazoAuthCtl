//! Read-only observation of the bound NazoAuth runtime object.
//!
//! Mutation entry points moved to the target executors (`target/*_exec`) with
//! the J-A deletion wave; what remains is the identity/digest observation
//! surface shared by status, doctor and the conformance session.

use std::fs;

use anyhow::{Context as _, bail};

use crate::{
    deployment::{ArtifactReference, RuntimeBackendKind},
    filesystem::sha256,
    model::UpdateConfig,
    runtime_backend,
};

pub(crate) fn runtime_service_owner_uid(config: &UpdateConfig) -> anyhow::Result<u32> {
    if config.runtime.backend != RuntimeBackendKind::Systemd {
        return Ok(10_001);
    }
    crate::process::Process::new("id")
        .args(["-u", config.runtime.service_user.as_str()])
        .stdout()?
        .trim()
        .parse()
        .context("managed host service user has no valid numeric UID")
}

pub(crate) struct Runtime<'a> {
    config: &'a UpdateConfig,
}

pub(crate) struct ActiveBuildTarget {
    pub(crate) embedded: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) image_digest: String,
    pub(crate) binary_digest: String,
    /// Container runtimes expose an engine-local immutable object ID in
    /// addition to the registry manifest digest.  Local-candidate
    /// conformance binds both so a mutable tag cannot redirect a task.
    pub(crate) local_artifact_id: Option<String>,
}

impl<'a> Runtime<'a> {
    pub(crate) fn new(config: &'a UpdateConfig) -> Self {
        Self { config }
    }

    pub(crate) fn active_revision(&self) -> anyhow::Result<String> {
        if self.backend_kind()? == RuntimeBackendKind::Systemd {
            return Ok(self
                .embedded_identity(&self.config.runtime.binary_path.to_string_lossy())?
                .revision);
        }
        Ok(self.active_build_target()?.embedded.revision)
    }

    pub(crate) fn active_image(&self) -> anyhow::Result<String> {
        let kind = self.backend_kind()?;
        if kind == RuntimeBackendKind::Systemd {
            bail!("host runtime does not have an active image");
        }
        match self
            .backend()?
            .inspect(self.object_reference(kind))?
            .artifact
        {
            ArtifactReference::Oci {
                image_reference, ..
            } => Ok(image_reference),
            _ => bail!("runtime object does not expose an OCI artifact"),
        }
    }

    fn backend_kind(&self) -> anyhow::Result<RuntimeBackendKind> {
        Ok(self.config.runtime.backend)
    }

    fn command_override(&self) -> Option<std::ffi::OsString> {
        self.config
            .runtime
            .backend_command_override
            .as_ref()
            .map(|path| path.as_os_str().to_os_string())
    }

    fn backend(&self) -> anyhow::Result<Box<dyn runtime_backend::RuntimeBackend>> {
        Ok(selected_backend(
            self.backend_kind()?,
            self.command_override().as_deref(),
        ))
    }

    fn object_reference(&self, kind: RuntimeBackendKind) -> &str {
        match kind {
            RuntimeBackendKind::Systemd => &self.config.runtime.service_name,
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                &self.config.runtime.container_name
            }
        }
    }

    pub(crate) fn active_build_target(&self) -> anyhow::Result<ActiveBuildTarget> {
        let kind = self.backend_kind()?;
        let backend = self.backend()?;
        let observation = backend.inspect(self.object_reference(kind))?;
        if !observation.running {
            bail!("active runtime is not running");
        }
        let embedded = backend
            .read_build_identity(
                &observation.artifact,
                observation.local_artifact_id.as_deref(),
            )?
            .context("active runtime exposes no embedded build identity")?;
        let (image_digest, binary_digest) = match &observation.artifact {
            ArtifactReference::Oci {
                image_reference, ..
            } => (
                backend.resolve_image_digest(image_reference)?,
                String::new(),
            ),
            ArtifactReference::HostBinary {
                path,
                sha256: expected_sha256,
            } => {
                if sha256(path)? != *expected_sha256 {
                    bail!("active host binary changed while resolving its build target");
                }
                (String::new(), expected_sha256.clone())
            }
            ArtifactReference::Unknown => bail!("active runtime artifact is unidentified"),
        };
        Ok(ActiveBuildTarget {
            embedded,
            image_digest,
            binary_digest,
            local_artifact_id: observation.local_artifact_id,
        })
    }

    pub(crate) fn image_digest(&self, image: &str) -> anyhow::Result<String> {
        if let Some(expected_local_id) = runtime_backend::normalize_local_image_id(image, false) {
            let actual_local_id = self.backend()?.resolve_local_image_id(image)?;
            if actual_local_id != expected_local_id {
                bail!("container engine retained a different local OCI identity");
            }
            return self.backend()?.resolve_image_digest(image);
        }
        let (_, expected_digest) = image
            .rsplit_once('@')
            .context("managed OCI image reference is not pinned by digest")?;
        let normalized = expected_digest.strip_prefix("sha256:").unwrap_or("");
        if normalized.len() != 64
            || !normalized
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("managed OCI image reference has an invalid digest");
        }
        let actual = self.backend()?.resolve_image_digest(image)?;
        if actual != expected_digest.to_ascii_lowercase() {
            bail!("container engine retained a different OCI digest");
        }
        Ok(actual)
    }

    pub(crate) fn embedded_identity(
        &self,
        image_or_binary: &str,
    ) -> anyhow::Result<nazo_operator_protocol::EmbeddedIdentity> {
        let kind = self.backend_kind()?;
        let artifact = match kind {
            RuntimeBackendKind::Systemd => {
                let path = fs::canonicalize(image_or_binary)
                    .context("failed to resolve host binary for build identity")?;
                ArtifactReference::HostBinary {
                    sha256: sha256(&path)?,
                    path,
                }
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => ArtifactReference::Oci {
                image_reference: image_or_binary.to_owned(),
                digest: self.image_digest(image_or_binary)?,
            },
        };
        self.backend()?
            .read_build_identity(&artifact, None)
            .context("runtime embedded build identity is invalid")?
            .context("runtime backend returned no build identity")
    }
}

fn selected_backend(
    kind: RuntimeBackendKind,
    command_override: Option<&std::ffi::OsStr>,
) -> Box<dyn runtime_backend::RuntimeBackend> {
    let _ = command_override;
    runtime_backend::backend(kind)
}
