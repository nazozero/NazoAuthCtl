mod container_shared;
mod docker;
mod podman;
mod systemd;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::PathBuf,
};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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
pub use container_shared::oci_backup_digests;
pub use docker::DockerBackend;
pub use podman::PodmanBackend;
pub use systemd::{SystemdBackend, parse_systemd_version, render_host_service_unit};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Responsibility {
    External,
    Managed,
}

impl Responsibility {
    pub fn permits_mutation(self) -> bool {
        matches!(self, Self::Managed)
    }
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
    #[serde(alias = "host")]
    Systemd,
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
pub struct RuntimeInstance {
    pub runtime_instance_id: String,
    pub backend: RuntimeBackendKind,
    pub object_reference: String,
    pub artifact: ArtifactReference,
    #[serde(default)]
    pub local_artifact_id: Option<String>,
    pub ports: Vec<String>,
    pub networks: Vec<String>,
    pub mounts: Vec<MountReference>,
    pub instance_key_id: Option<String>,
    pub deployment_statement: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountReference {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub read_only: bool,
    pub selinux_relabel: bool,
    pub scope: ResourceScope,
    pub ownership: Responsibility,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeSurfaceDrift {
    pub ports: bool,
    pub networks: bool,
    pub mounts: bool,
}

pub fn compare_declared_runtime_surface(
    declared: &RuntimeInstance,
    observed: &RuntimeObservation,
) -> anyhow::Result<RuntimeSurfaceDrift> {
    let container = matches!(
        declared.backend,
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker
    );
    let expected_ports = if container {
        declared
            .ports
            .iter()
            .map(|port| {
                let Some((host_binding, container_port)) = port.rsplit_once(':') else {
                    bail!("declared container port has no host binding");
                };
                if host_binding.is_empty() || container_port.is_empty() {
                    bail!("declared container port binding is incomplete");
                }
                Ok(format!("{host_binding}->{container_port}/tcp"))
            })
            .collect::<anyhow::Result<BTreeSet<_>>>()?
    } else {
        declared.ports.iter().cloned().collect()
    };
    let observed_ports = observed.ports.iter().cloned().collect::<BTreeSet<_>>();

    let expected_mounts = declared
        .mounts
        .iter()
        .map(|mount| {
            (
                mount.source.clone(),
                mount.destination.clone(),
                mount.read_only,
                (!container).then_some(mount.selinux_relabel),
            )
        })
        .collect::<BTreeSet<_>>();
    let observed_mounts = observed
        .mounts
        .iter()
        .map(|mount| {
            (
                mount.source.clone(),
                mount.destination.clone(),
                mount.read_only,
                (!container).then_some(mount.selinux_relabel),
            )
        })
        .collect::<BTreeSet<_>>();

    Ok(RuntimeSurfaceDrift {
        ports: expected_ports != observed_ports,
        networks: declared.networks.iter().collect::<BTreeSet<_>>()
            != observed.networks.iter().collect::<BTreeSet<_>>(),
        mounts: expected_mounts != observed_mounts,
    })
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

    pub fn managed_postgres() -> Self {
        let mut policy = Self::managed_default();
        policy.service_user = Some("999:999".to_owned());
        policy
    }

    pub fn managed_valkey() -> Self {
        let mut policy = Self::managed_default();
        policy.service_user = Some("999:1000".to_owned());
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
pub struct ManagedPostgresRestore {
    pub network: String,
    pub postgres_object: String,
    pub postgres_image: String,
    pub backup_directory: PathBuf,
    pub service_file: PathBuf,
    pub password_file: PathBuf,
    pub image: String,
    pub manifest_digest: String,
    pub completion_marker_digest: String,
    pub identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub struct ManagedValkeyRestore {
    pub network: String,
    pub object_reference: String,
    pub data_volume: String,
    pub backup_directory: PathBuf,
    pub image: String,
    pub manifest_digest: String,
    pub completion_marker_digest: String,
    pub identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub struct ManagedPostgresCommand {
    pub object_reference: String,
    pub network: String,
    pub database: String,
    pub user: String,
    pub stdin: Vec<u8>,
    pub image: String,
    pub identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub struct ManagedDependencyBackup {
    pub destination: PathBuf,
    pub network: String,
    pub postgres_object: String,
    pub postgres_volume: String,
    pub postgres_image: String,
    pub postgres_user: String,
    pub postgres_database: String,
    pub postgres_validation_image: String,
    pub valkey_object: String,
    pub valkey_volume: String,
    pub valkey_image: String,
    pub valkey_rdb_path: String,
    pub valkey_password_file: Option<PathBuf>,
    pub valkey_user: Option<String>,
    pub identity: ManagedDependencyIdentity,
}

/// Immutable identities and configuration digests used when a managed
/// dependency is touched.  Runtime/deployment labels alone are not enough:
/// the digest binds the expected object role, names, network, volumes and
/// pinned images to the operation that is about to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDependencyIdentity {
    pub deployment_id: String,
    pub control_authority: String,
    pub runtime_instance_id: String,
    pub network_config_digest: String,
    pub postgres_config_digest: String,
    pub postgres_volume_config_digest: String,
    pub valkey_config_digest: String,
    pub valkey_volume_config_digest: String,
}

#[derive(Clone, Debug)]
pub struct ManagedNetwork {
    pub name: String,
    pub subnet: Option<String>,
    pub deployment_id: String,
    pub control_authority: String,
}

#[derive(Clone, Debug)]
pub struct ManagedDependencies {
    pub network: ManagedNetwork,
    pub runtime_instance_id: String,
    pub postgres_object: String,
    pub postgres_volume: String,
    pub postgres_image: String,
    pub postgres_database: String,
    pub postgres_user: String,
    pub postgres_password_file: PathBuf,
    pub valkey_object: String,
    pub valkey_volume: String,
    pub valkey_image: String,
    pub valkey_password_file: PathBuf,
    pub valkey_acl_file: PathBuf,
    pub valkey_user: String,
}

pub const MANAGED_VALKEY_RUNTIME_USER: &str = "nazoauth_runtime";
pub const MANAGED_VALKEY_BACKUP_USER: &str = "nazoauth_backup";

impl ManagedDependencies {
    pub fn identity(&self) -> ManagedDependencyIdentity {
        managed_dependency_identity(
            &self.network.deployment_id,
            &self.network.control_authority,
            &self.runtime_instance_id,
            &self.network.name,
            self.network.subnet.as_deref(),
            &self.postgres_object,
            &self.postgres_volume,
            &self.postgres_image,
            &self.postgres_database,
            &self.postgres_user,
            &self.valkey_object,
            &self.valkey_volume,
            &self.valkey_image,
        )
    }
}

/// Build a stable, length-delimited digest for a managed resource's
/// immutable configuration.  Length prefixes avoid ambiguity when values are
/// concatenated (for example `ab` + `c` versus `a` + `bc`).
pub fn managed_config_digest(resource_kind: &str, fields: &[(&str, &str)]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nazoauthctl-managed-resource-v1\0");
    update_digest_part(&mut digest, "resource-kind", resource_kind);
    for (name, value) in fields {
        update_digest_part(&mut digest, name, value);
    }
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing digest to String cannot fail");
    }
    format!("sha256:{encoded}")
}

fn update_digest_part(digest: &mut Sha256, name: &str, value: &str) {
    digest.update(name.len().to_string().as_bytes());
    digest.update(b":");
    digest.update(name.as_bytes());
    digest.update(value.len().to_string().as_bytes());
    digest.update(b":");
    digest.update(value.as_bytes());
    digest.update(b"\0");
}

pub fn managed_network_config_digest(
    deployment_id: &str,
    control_authority: &str,
    network: &str,
    subnet: Option<&str>,
) -> String {
    let mut fields = vec![
        ("deployment-id", deployment_id),
        ("control-authority", control_authority),
        ("network", network),
    ];
    if let Some(subnet) = subnet {
        fields.push(("subnet", subnet));
    }
    managed_config_digest("network", &fields)
}

#[allow(clippy::too_many_arguments)]
pub fn managed_dependency_identity(
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: &str,
    network: &str,
    network_subnet: Option<&str>,
    postgres_object: &str,
    postgres_volume: &str,
    postgres_image: &str,
    postgres_database: &str,
    postgres_user: &str,
    valkey_object: &str,
    valkey_volume: &str,
    valkey_image: &str,
) -> ManagedDependencyIdentity {
    let common = [
        ("deployment-id", deployment_id),
        ("control-authority", control_authority),
        ("runtime-instance-id", runtime_instance_id),
        ("network", network),
    ];
    // A network is deployment-scoped and may be ensured before the runtime
    // instance is materialized.  Its immutable digest therefore binds the
    // network's own deployment/authority/name identity; dependency resources
    // additionally bind the runtime instance below.
    let mut network_fields = vec![
        ("deployment-id", deployment_id),
        ("control-authority", control_authority),
        ("network", network),
    ];
    if let Some(subnet) = network_subnet {
        network_fields.push(("subnet", subnet));
    }
    let network_config_digest = managed_config_digest("network", &network_fields);

    let mut postgres_fields = common.to_vec();
    postgres_fields.extend([
        ("role", "postgres"),
        ("object", postgres_object),
        ("volume", postgres_volume),
        ("image", postgres_image),
        ("database", postgres_database),
        ("user", postgres_user),
    ]);
    let postgres_config_digest = managed_config_digest("postgres", &postgres_fields);

    let mut postgres_volume_fields = common.to_vec();
    postgres_volume_fields.extend([("role", "postgres-volume"), ("volume", postgres_volume)]);
    let postgres_volume_config_digest =
        managed_config_digest("postgres-volume", &postgres_volume_fields);

    let mut valkey_fields = common.to_vec();
    valkey_fields.extend([
        ("role", "valkey"),
        ("object", valkey_object),
        ("volume", valkey_volume),
        ("image", valkey_image),
    ]);
    let valkey_config_digest = managed_config_digest("valkey", &valkey_fields);

    let mut valkey_volume_fields = common.to_vec();
    valkey_volume_fields.extend([("role", "valkey-volume"), ("volume", valkey_volume)]);
    let valkey_volume_config_digest = managed_config_digest("valkey-volume", &valkey_volume_fields);

    ManagedDependencyIdentity {
        deployment_id: deployment_id.to_owned(),
        control_authority: control_authority.to_owned(),
        runtime_instance_id: runtime_instance_id.to_owned(),
        network_config_digest,
        postgres_config_digest,
        postgres_volume_config_digest,
        valkey_config_digest,
        valkey_volume_config_digest,
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeDatabasePrivilegeProbe {
    pub network: String,
    pub service_file: PathBuf,
    pub password_file: PathBuf,
    pub image: String,
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

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct DebugArtifactTask {
    pub target: String,
    pub arguments: Vec<String>,
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
    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()>;
    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String>;
    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool>;
    fn pull_image(&self, image_reference: &str) -> anyhow::Result<()>;
    /// Whether the local image store already holds an image whose repository
    /// digests contain exactly the digest embedded in `image_reference`.
    /// Digest-pinned installs fall back to this when the registry is
    /// unreachable: a locally cached exact-digest image is equally
    /// trustworthy because the signed Release manifest anchors that digest.
    fn local_image_matches_digest(&self, image_reference: &str) -> bool;
    fn export_image(&self, image_reference: &str, archive: &std::path::Path) -> anyhow::Result<()>;
    fn import_image(&self, archive: &std::path::Path) -> anyhow::Result<()>;
    fn restore_managed_postgres(&self, restore: &ManagedPostgresRestore) -> anyhow::Result<()>;
    fn restore_managed_valkey(&self, restore: &ManagedValkeyRestore) -> anyhow::Result<()>;
    fn execute_managed_postgres(&self, command: &ManagedPostgresCommand) -> anyhow::Result<()>;
    fn backup_managed_dependencies(&self, backup: &ManagedDependencyBackup) -> anyhow::Result<()>;
    fn ensure_managed_network(&self, network: &ManagedNetwork) -> anyhow::Result<std::net::IpAddr>;
    fn ensure_managed_dependencies(&self, dependencies: &ManagedDependencies)
    -> anyhow::Result<()>;
    fn verify_runtime_database_privileges(
        &self,
        probe: &RuntimeDatabasePrivilegeProbe,
    ) -> anyhow::Result<()>;
    fn install_host_service(&self, install: &HostServiceInstall) -> anyhow::Result<()>;
    #[cfg(debug_assertions)]
    fn run_debug_artifact_task(&self, task: &DebugArtifactTask) -> anyhow::Result<()>;
    fn verify_blob_attestation(
        &self,
        verification: &BlobAttestationVerification,
    ) -> anyhow::Result<()>;
    fn resolve_image_digest(&self, image_reference: &str) -> anyhow::Result<String>;
    fn resolve_local_image_id(&self, image_reference: &str) -> anyhow::Result<String>;
    fn read_build_identity(
        &self,
        artifact: &ArtifactReference,
        local_artifact_id: Option<&str>,
    ) -> anyhow::Result<Option<nazo_operator_protocol::EmbeddedIdentity>>;
    fn describe_mounts(&self, object_reference: &str) -> anyhow::Result<Vec<NeutralMount>> {
        Ok(self.inspect(object_reference)?.mounts)
    }
}

pub fn safe_environment(values: &[serde_json::Value]) -> BTreeMap<String, String> {
    const ALLOWED: [&str; 7] = [
        "ISSUER",
        "PUBLIC_BASE_URL",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "RUNTIME_INSTANCE_ID",
        "CONTROL_AUTHORITY",
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
