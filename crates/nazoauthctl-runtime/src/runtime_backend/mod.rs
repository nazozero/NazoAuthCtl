mod container_shared;
mod docker;
mod podman;
mod systemd;

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

/// Validate a path before rendering it into a systemd unit directive.
pub fn safe_systemd_path(path: &std::path::Path) -> anyhow::Result<()> {
    let value = path.to_str().context("systemd path must be valid UTF-8")?;
    let unix_absolute = value.starts_with('/');
    if unix_absolute {
        if value == "/"
            || value
                .split('/')
                .skip(1)
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            bail!("systemd path must be a normalized absolute non-root path: {value}");
        }
    } else {
        safe_absolute(path)?;
    }
    if value.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(character, '%' | '\'' | '"')
            || (unix_absolute && character == '\\')
    }) {
        bail!("systemd path contains unsupported whitespace or quoting: {value}");
    }
    Ok(())
}

fn safe_absolute(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!(
            "path must be a normalized absolute non-root path: {}",
            path.display()
        );
    }
    Ok(())
}

/// The verified NazoAuth OCI artifact declares this immutable numeric
/// identity; one-shot operator tasks must never inherit engine root merely
/// because image metadata drifts (exposed for the G-wave control executor).
pub use container_shared::NON_ROOT_ONE_SHOT_USER;
pub use container_shared::normalize_local_image_id;
pub use docker::DockerBackend;
pub use podman::PodmanBackend;
pub use systemd::{
    SystemdBackend, parse_systemd_version, render_host_service_unit, systemd_service_user,
    systemd_service_user_uid,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Responsibility {
    External,
    Managed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceScope {
    Deployment,
    Shared,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeBackendKind {
    Podman,
    Docker,
    Host,
}

impl RuntimeBackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Podman => "podman",
            Self::Docker => "docker",
            Self::Host => "host",
        }
    }

    pub const fn is_container(self) -> bool {
        matches!(self, Self::Podman | Self::Docker)
    }
}

impl std::fmt::Display for RuntimeBackendKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for RuntimeBackendKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "podman" => Ok(Self::Podman),
            "docker" => Ok(Self::Docker),
            "host" => Ok(Self::Host),
            other => anyhow::bail!(
                "unsupported runtime kind '{other}'; expected podman, docker, or host"
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArtifactReference {
    Oci {
        image_reference: String,
        digest: String,
    },
    HostBinary {
        path: PathBuf,
        sha256: String,
    },
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservation {
    pub backend: RuntimeBackendKind,
    pub object_reference: String,
    pub display_name: String,
    pub running: bool,
    pub server_command_verified: bool,
    pub artifact: ArtifactReference,
    /// Backend-native immutable content identity. This is evidence for a
    /// locally cached artifact and is not a substitute for a signed Release
    /// digest during discovery or adoption.
    pub local_artifact_id: Option<String>,
    pub ports: Vec<String>,
    pub networks: Vec<String>,
    pub mounts: Vec<NeutralMount>,
    pub safe_environment: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub evidence: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralMount {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub read_only: bool,
    pub selinux_relabel: bool,
    pub ownership: Responsibility,
    pub scope: ResourceScope,
}

#[derive(Clone, Debug)]
pub struct RuntimeReplacement {
    pub object_reference: String,
    pub artifact: ArtifactReference,
    pub local_artifact_id: Option<String>,
    pub command: Vec<String>,
    pub mounts: Vec<NeutralMount>,
    pub environment: BTreeMap<String, String>,
    pub networks: Vec<String>,
    pub ip_address: Option<String>,
    pub ports: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub container_policy: Option<ContainerRuntimePolicy>,
}

/// The only container shape accepted for a closed recovery candidate.
///
/// This is deliberately not a general clone specification. The backend
/// inspects one stopped deployment runtime, copies only its safe environment
/// and single non-host network, replaces its data/config and current secret
/// file mounts from the restored snapshot, and publishes one application port
/// on IPv4 loopback.
#[derive(Clone, Debug)]
pub struct RecoveryCandidateRequest {
    pub source_object_reference: String,
    pub candidate_object_reference: String,
    pub deployment_id: String,
    pub operation_id: String,
    pub artifact: ArtifactReference,
    pub data_source: PathBuf,
    pub secrets_source: PathBuf,
    pub config_source: PathBuf,
    pub valkey_state_epoch: String,
    /// Parsed from the restored configuration by the target, never inferred from the issuer.
    pub https: bool,
    /// The three existing TLS file settings; only their source read-only mounts may be retained.
    pub tls_files: Vec<PathBuf>,
}

/// Immutable cleanup identity and the sole endpoint exposed by a recovery
/// candidate. Controllers may forward `127.0.0.1:loopback_port` through their
/// existing OpenSSH transport; no public address is ever returned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryCandidateEndpoint {
    pub object_reference: String,
    pub object_id: String,
    pub deployment_id: String,
    pub operation_id: String,
    pub loopback_port: u16,
    #[serde(default)]
    pub https: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerRestartPolicy {
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralTmpfs {
    pub destination: PathBuf,
    pub read_only: bool,
    pub no_exec: bool,
    pub no_suid: bool,
    pub no_device: bool,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRuntimePolicy {
    pub restart: ContainerRestartPolicy,
    pub service_user: Option<String>,
    pub read_only_root: bool,
    pub no_new_privileges: bool,
    pub drop_all_capabilities: bool,
    pub pids_limit: Option<u32>,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit_millis: Option<u32>,
    pub tmpfs: Vec<NeutralTmpfs>,
}

impl ContainerRuntimePolicy {
    pub fn managed_default() -> Self {
        Self {
            restart: ContainerRestartPolicy::UnlessStopped,
            service_user: None,
            read_only_root: true,
            no_new_privileges: true,
            drop_all_capabilities: true,
            pids_limit: Some(512),
            memory_limit_bytes: Some(1024 * 1024 * 1024),
            cpu_limit_millis: Some(2000),
            tmpfs: [
                ("/tmp", 64 * 1024 * 1024),
                ("/run/postgresql", 16 * 1024 * 1024),
            ]
            .into_iter()
            .map(|(destination, size_bytes)| NeutralTmpfs {
                destination: PathBuf::from(destination),
                read_only: false,
                no_exec: true,
                no_suid: true,
                no_device: true,
                size_bytes,
            })
            .collect(),
        }
    }

    /// Policy for the application container.  Dependency containers have
    /// image-specific service identities, while the application image has a
    /// controller-owned uid/gid contract that must not inherit a mutable
    /// image user.
    pub fn managed_app() -> Self {
        let mut policy = Self::managed_default();
        policy.service_user = Some("10001:10001".to_owned());
        policy
    }

    fn recovery_candidate() -> Self {
        let mut policy = Self::managed_app();
        policy.restart = ContainerRestartPolicy::No;
        policy
    }
}

#[derive(Clone, Debug)]
pub struct OneShotTask {
    pub artifact: ArtifactReference,
    pub command: Vec<String>,
    pub network: Option<String>,
    pub mounts: Vec<NeutralMount>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: Option<PathBuf>,
    pub service_user: Option<String>,
    pub transient_credentials: BTreeMap<String, PathBuf>,
    pub read_only_paths: Vec<PathBuf>,
    pub read_write_paths: Vec<PathBuf>,
    pub inaccessible_paths: Vec<PathBuf>,
    pub private_mounts: bool,
    pub stdin: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HostServiceInstall {
    pub service_name: String,
    pub deployment_id: String,
    pub service_user: String,
    /// Verified, immutable source bytes held by the target operation.
    pub source_binary: PathBuf,
    /// Permanent executable path referenced by the unit.
    pub binary: PathBuf,
    pub config: PathBuf,
    pub data_root: PathBuf,
    pub secret_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct BlobAttestationVerification {
    pub work: PathBuf,
    pub bundle: String,
    pub blob: String,
    pub certificate_identity: String,
    pub predicate_type: String,
    pub cosign_image: String,
}

pub trait RuntimeBackend {
    fn kind(&self) -> RuntimeBackendKind;
    fn available(&self) -> bool;
    fn discover(&self) -> anyhow::Result<Vec<RuntimeObservation>>;
    fn inspect(&self, object_reference: &str) -> anyhow::Result<RuntimeObservation>;
    /// Inspect a locator when it may legitimately be absent. Backends must
    /// distinguish a confirmed not-found result from an inspection failure;
    /// callers use this before destructive replacement.
    fn inspect_optional(
        &self,
        object_reference: &str,
    ) -> anyhow::Result<Option<RuntimeObservation>> {
        self.inspect(object_reference).map(Some)
    }
    /// Read a bounded tail of application logs for an already-authorized
    /// runtime object. Callers own redaction before crossing a public wire.
    fn read_logs(&self, object_reference: &str, limit: usize) -> anyhow::Result<Vec<String>>;
    fn start(&self, object_reference: &str) -> anyhow::Result<()>;
    fn stop(&self, object_reference: &str) -> anyhow::Result<()>;
    fn quiesce_for_recovery(&self, object_reference: &str) -> anyhow::Result<()>;
    fn restart(&self, object_reference: &str) -> anyhow::Result<()>;
    fn remove(&self, object_reference: &str) -> anyhow::Result<()>;
    /// Replace the runtime object without starting it. The caller restores the desired running state.
    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()>;
    /// Create a one-use, loopback-only candidate from a stopped runtime after
    /// proving the complete recover-only container surface.
    fn stage_recovery_candidate(
        &self,
        request: &RecoveryCandidateRequest,
    ) -> anyhow::Result<RecoveryCandidateEndpoint>;
    /// Idempotently remove the exact immutable candidate returned by
    /// [`RuntimeBackend::stage_recovery_candidate`].
    fn cleanup_recovery_candidate(
        &self,
        endpoint: &RecoveryCandidateEndpoint,
    ) -> anyhow::Result<()>;
    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String>;
    fn pull_image(&self, image_reference: &str) -> anyhow::Result<()>;
    /// Whether the local image store already holds an image whose repository
    /// digests contain exactly the digest embedded in `image_reference`.
    /// Digest-pinned installs fall back to this when the registry is
    /// unreachable: a locally cached exact-digest image is equally
    /// trustworthy because the signed Release manifest anchors that digest.
    fn local_image_matches_digest(&self, image_reference: &str) -> bool;
    fn export_image(&self, image_reference: &str, archive: &std::path::Path) -> anyhow::Result<()>;
    fn import_image(&self, archive: &std::path::Path) -> anyhow::Result<()>;
    fn install_host_service(&self, install: &HostServiceInstall) -> anyhow::Result<()>;
    fn verify_blob_attestation(
        &self,
        verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()>;
    fn resolve_local_image_id(&self, image_reference: &str) -> anyhow::Result<String>;
}

pub fn safe_environment(values: &[serde_json::Value]) -> BTreeMap<String, String> {
    const ALLOWED: [&str; 8] = [
        "ISSUER",
        "PUBLIC_BASE_URL",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "RUNTIME_INSTANCE_ID",
        "CONTROL_AUTHORITY",
        "INSTANCE_IDENTITY_DIR",
        "VALKEY_STATE_EPOCH",
    ];
    values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|entry| entry.split_once('='))
        .filter(|(name, _)| ALLOWED.contains(name))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

pub fn server_command_verified(values: &[String]) -> bool {
    values.windows(2).any(|pair| pair == ["nazoauth", "server"])
        || values.first().is_some_and(|value| {
            value.ends_with("nazoauth") && values.get(1).is_some_and(|value| value == "server")
        })
}

pub fn labels(value: Option<&serde_json::Value>) -> BTreeMap<String, String> {
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

#[cfg(test)]
mod tests {
    use super::{RuntimeBackendKind, safe_environment};

    #[test]
    fn state_epoch_is_observable_without_exposing_secrets() {
        let environment = safe_environment(&[
            serde_json::Value::String(
                "VALKEY_STATE_EPOCH=01900000-0000-7000-8000-000000000001".to_owned(),
            ),
            serde_json::Value::String("DATABASE_URL=secret".to_owned()),
        ]);

        assert_eq!(
            environment.get("VALKEY_STATE_EPOCH").map(String::as_str),
            Some("01900000-0000-7000-8000-000000000001")
        );
        assert!(!environment.contains_key("DATABASE_URL"));
    }

    #[test]
    fn runtime_kind_has_exactly_three_wire_tokens() -> anyhow::Result<()> {
        for (kind, token) in [
            (RuntimeBackendKind::Podman, "podman"),
            (RuntimeBackendKind::Docker, "docker"),
            (RuntimeBackendKind::Host, "host"),
        ] {
            assert_eq!(kind.as_str(), token);
            assert_eq!(serde_json::to_string(&kind)?, format!("\"{token}\""));
            assert_eq!(token.parse::<RuntimeBackendKind>()?, kind);
        }
        assert!("systemd".parse::<RuntimeBackendKind>().is_err());
        assert!(serde_json::from_str::<RuntimeBackendKind>("\"systemd\"").is_err());
        Ok(())
    }
}
