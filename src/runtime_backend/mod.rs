mod docker;
mod podman;
mod systemd;

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind};

pub(crate) use docker::DockerBackend;
pub(crate) use podman::PodmanBackend;
pub(crate) use systemd::SystemdBackend;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeObservation {
    pub(crate) backend: RuntimeBackendKind,
    pub(crate) object_reference: String,
    pub(crate) display_name: String,
    pub(crate) running: bool,
    pub(crate) server_command_verified: bool,
    pub(crate) artifact: ArtifactReference,
    pub(crate) ports: Vec<String>,
    pub(crate) networks: Vec<String>,
    pub(crate) mounts: Vec<NeutralMount>,
    pub(crate) safe_environment: BTreeMap<String, String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) evidence: Vec<String>,
    pub(crate) missing: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NeutralMount {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) read_only: bool,
    pub(crate) selinux_relabel: bool,
    pub(crate) ownership: Responsibility,
    pub(crate) scope: ResourceScope,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeReplacement {
    pub(crate) object_reference: String,
    pub(crate) artifact: ArtifactReference,
    pub(crate) command: Vec<String>,
    pub(crate) mounts: Vec<NeutralMount>,
    pub(crate) environment_files: Vec<PathBuf>,
    pub(crate) labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct OneShotTask {
    pub(crate) artifact: ArtifactReference,
    pub(crate) command: Vec<String>,
    pub(crate) network_enabled: bool,
    pub(crate) mounts: Vec<NeutralMount>,
}

pub(crate) trait RuntimeBackend {
    fn kind(&self) -> RuntimeBackendKind;
    fn available(&self) -> bool;
    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>>;
    fn inspect(&self, object_reference: &str) -> anyhow::Result<RuntimeObservation>;
    fn start(&self, object_reference: &str) -> anyhow::Result<()>;
    fn stop(&self, object_reference: &str) -> anyhow::Result<()>;
    fn restart(&self, object_reference: &str) -> anyhow::Result<()>;
    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()>;
    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String>;
    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String>;
    fn read_build_identity(
        &self,
        observation: &RuntimeObservation,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>>;
    fn describe_mounts(&self, object_reference: &str) -> anyhow::Result<Vec<NeutralMount>> {
        Ok(self.inspect(object_reference)?.mounts)
    }
    fn verify_ownership(
        &self,
        object_reference: &str,
        deployment_id: &str,
        control_authority: &str,
    ) -> anyhow::Result<()> {
        let observation = self.inspect(object_reference)?;
        let deployment_matches = observation
            .labels
            .get("io.nazoauth.deployment-id")
            .is_some_and(|value| value == deployment_id);
        let authority_matches = observation
            .labels
            .get("io.nazoauth.control-authority")
            .is_some_and(|value| value == control_authority);
        if !deployment_matches || !authority_matches {
            bail!("runtime ownership labels do not match the authorized deployment")
        }
        Ok(())
    }
}

pub(crate) fn installed_backends() -> Vec<Box<dyn RuntimeBackend>> {
    let backends: Vec<Box<dyn RuntimeBackend>> = vec![
        Box::new(PodmanBackend),
        Box::new(DockerBackend),
        Box::new(SystemdBackend),
    ];
    backends
        .into_iter()
        .filter(|backend| backend.available())
        .collect()
}

pub(crate) fn backend(kind: RuntimeBackendKind) -> Box<dyn RuntimeBackend> {
    match kind {
        RuntimeBackendKind::Podman => Box::new(PodmanBackend),
        RuntimeBackendKind::Docker => Box::new(DockerBackend),
        RuntimeBackendKind::Systemd => Box::new(SystemdBackend),
    }
}

pub(super) fn safe_environment(values: &[serde_json::Value]) -> BTreeMap<String, String> {
    const ALLOWED: [&str; 6] = [
        "ISSUER",
        "PUBLIC_BASE_URL",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "RUNTIME_INSTANCE_ID",
        "INSTANCE_IDENTITY_DIR",
    ];
    values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|entry| entry.split_once('='))
        .filter(|(name, _)| ALLOWED.contains(name))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

pub(super) fn server_command_verified(values: &[String]) -> bool {
    values.windows(2).any(|pair| pair == ["nazoauth", "server"])
        || values.first().is_some_and(|value| {
            value.ends_with("nazoauth") && values.get(1).is_some_and(|value| value == "server")
        })
}

pub(super) fn labels(value: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    value
        .and_then(serde_json::Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|value| (name.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}
