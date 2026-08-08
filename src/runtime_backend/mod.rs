mod container_shared;
mod docker;
mod podman;
mod systemd;

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind};

pub(crate) use docker::DockerBackend;
pub(crate) use podman::PodmanBackend;
pub(crate) use systemd::SystemdBackend;
#[cfg(test)]
pub(crate) use systemd::{parse_systemd_version, render_host_service_unit};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeObservation {
    pub(crate) backend: RuntimeBackendKind,
    pub(crate) object_reference: String,
    pub(crate) display_name: String,
    pub(crate) running: bool,
    pub(crate) server_command_verified: bool,
    pub(crate) artifact: ArtifactReference,
    /// Backend-native immutable content identity. This is evidence for a
    /// locally cached artifact and is not a substitute for a signed Release
    /// digest during discovery or adoption.
    pub(crate) local_artifact_id: Option<String>,
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
    pub(crate) local_artifact_id: Option<String>,
    pub(crate) command: Vec<String>,
    pub(crate) mounts: Vec<NeutralMount>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) networks: Vec<String>,
    pub(crate) ip_address: Option<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) container_policy: Option<ContainerRuntimePolicy>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ContainerRestartPolicy {
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NeutralTmpfs {
    pub(crate) destination: PathBuf,
    pub(crate) read_only: bool,
    pub(crate) no_exec: bool,
    pub(crate) no_suid: bool,
    pub(crate) no_device: bool,
    pub(crate) size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContainerRuntimePolicy {
    pub(crate) restart: ContainerRestartPolicy,
    pub(crate) read_only_root: bool,
    pub(crate) no_new_privileges: bool,
    pub(crate) drop_all_capabilities: bool,
    pub(crate) pids_limit: Option<u32>,
    pub(crate) memory_limit_bytes: Option<u64>,
    pub(crate) cpu_limit_millis: Option<u32>,
    pub(crate) tmpfs: Vec<NeutralTmpfs>,
}

impl ContainerRuntimePolicy {
    pub(crate) fn managed_default() -> Self {
        Self {
            restart: ContainerRestartPolicy::UnlessStopped,
            read_only_root: true,
            no_new_privileges: true,
            drop_all_capabilities: true,
            pids_limit: Some(512),
            memory_limit_bytes: Some(1024 * 1024 * 1024),
            cpu_limit_millis: Some(2000),
            tmpfs: vec![NeutralTmpfs {
                destination: PathBuf::from("/tmp"),
                read_only: false,
                no_exec: true,
                no_suid: true,
                no_device: true,
                size_bytes: 64 * 1024 * 1024,
            }],
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OneShotTask {
    pub(crate) artifact: ArtifactReference,
    pub(crate) command: Vec<String>,
    pub(crate) network: Option<String>,
    pub(crate) mounts: Vec<NeutralMount>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) working_directory: Option<PathBuf>,
    pub(crate) service_user: Option<String>,
    pub(crate) transient_credentials: BTreeMap<String, PathBuf>,
    pub(crate) read_only_paths: Vec<PathBuf>,
    pub(crate) read_write_paths: Vec<PathBuf>,
    pub(crate) inaccessible_paths: Vec<PathBuf>,
    pub(crate) private_mounts: bool,
    pub(crate) stdin: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedPostgresRestore {
    pub(crate) network: String,
    pub(crate) postgres_object: String,
    pub(crate) postgres_image: String,
    pub(crate) backup_directory: PathBuf,
    pub(crate) service_file: PathBuf,
    pub(crate) password_file: PathBuf,
    pub(crate) image: String,
    pub(crate) identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedValkeyRestore {
    pub(crate) network: String,
    pub(crate) object_reference: String,
    pub(crate) data_volume: String,
    pub(crate) backup_directory: PathBuf,
    pub(crate) image: String,
    pub(crate) identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedPostgresCommand {
    pub(crate) object_reference: String,
    pub(crate) network: String,
    pub(crate) database: String,
    pub(crate) user: String,
    pub(crate) stdin: Vec<u8>,
    pub(crate) image: String,
    pub(crate) identity: ManagedDependencyIdentity,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedDependencyBackup {
    pub(crate) destination: PathBuf,
    pub(crate) network: String,
    pub(crate) postgres_object: String,
    pub(crate) postgres_volume: String,
    pub(crate) postgres_image: String,
    pub(crate) postgres_user: String,
    pub(crate) postgres_database: String,
    pub(crate) postgres_validation_image: String,
    pub(crate) valkey_object: String,
    pub(crate) valkey_volume: String,
    pub(crate) valkey_image: String,
    pub(crate) valkey_rdb_path: String,
    pub(crate) valkey_password_file: Option<PathBuf>,
    pub(crate) identity: ManagedDependencyIdentity,
}

/// Immutable identities and configuration digests used when a managed
/// dependency is touched.  Runtime/deployment labels alone are not enough:
/// the digest binds the expected object role, names, network, volumes and
/// pinned images to the operation that is about to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedDependencyIdentity {
    pub(crate) deployment_id: String,
    pub(crate) control_authority: String,
    pub(crate) runtime_instance_id: String,
    pub(crate) network_config_digest: String,
    pub(crate) postgres_config_digest: String,
    pub(crate) postgres_volume_config_digest: String,
    pub(crate) valkey_config_digest: String,
    pub(crate) valkey_volume_config_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedNetwork {
    pub(crate) name: String,
    pub(crate) subnet: Option<String>,
    pub(crate) deployment_id: String,
    pub(crate) control_authority: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedDependencies {
    pub(crate) network: ManagedNetwork,
    pub(crate) runtime_instance_id: String,
    pub(crate) postgres_object: String,
    pub(crate) postgres_volume: String,
    pub(crate) postgres_image: String,
    pub(crate) postgres_database: String,
    pub(crate) postgres_user: String,
    pub(crate) postgres_password_file: PathBuf,
    pub(crate) valkey_object: String,
    pub(crate) valkey_volume: String,
    pub(crate) valkey_image: String,
    pub(crate) valkey_password_file: PathBuf,
    pub(crate) valkey_acl_file: PathBuf,
}

impl ManagedDependencies {
    pub(crate) fn identity(&self) -> ManagedDependencyIdentity {
        managed_dependency_identity(
            &self.network.deployment_id,
            &self.network.control_authority,
            &self.runtime_instance_id,
            &self.network.name,
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
pub(crate) fn managed_config_digest(resource_kind: &str, fields: &[(&str, &str)]) -> String {
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

pub(crate) fn managed_network_config_digest(
    deployment_id: &str,
    control_authority: &str,
    network: &str,
) -> String {
    managed_config_digest(
        "network",
        &[
            ("deployment-id", deployment_id),
            ("control-authority", control_authority),
            ("network", network),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn managed_dependency_identity(
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: &str,
    network: &str,
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
    let network_fields = [
        ("deployment-id", deployment_id),
        ("control-authority", control_authority),
        ("network", network),
    ];
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
pub(crate) struct RuntimeDatabasePrivilegeProbe {
    pub(crate) network: String,
    pub(crate) service_file: PathBuf,
    pub(crate) password_file: PathBuf,
    pub(crate) image: String,
}

#[derive(Clone, Debug)]
pub(crate) struct HostServiceInstall {
    pub(crate) service_name: String,
    pub(crate) deployment_id: String,
    pub(crate) runtime_instance_id: String,
    pub(crate) control_authority: String,
    pub(crate) service_user: String,
    pub(crate) working_directory: PathBuf,
    pub(crate) binary: PathBuf,
    pub(crate) app_root: PathBuf,
    pub(crate) ui_releases: PathBuf,
    pub(crate) operator_state: PathBuf,
    pub(crate) operator_directory: PathBuf,
    pub(crate) recovery_directory: PathBuf,
    pub(crate) migration_url: PathBuf,
    pub(crate) receipt_private_key: PathBuf,
    pub(crate) runtime_readable_secret_names: Vec<String>,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub(crate) struct DebugArtifactTask {
    pub(crate) target: String,
    pub(crate) arguments: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct BlobAttestationVerification {
    pub(crate) work: PathBuf,
    pub(crate) bundle: String,
    pub(crate) blob: String,
    pub(crate) certificate_identity: String,
    pub(crate) predicate_type: String,
    pub(crate) cosign_image: String,
}

pub(crate) trait RuntimeBackend {
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
    fn start(&self, object_reference: &str) -> anyhow::Result<()>;
    fn stop(&self, object_reference: &str) -> anyhow::Result<()>;
    fn quiesce_for_recovery(&self, object_reference: &str) -> anyhow::Result<()>;
    fn restart(&self, object_reference: &str) -> anyhow::Result<()>;
    fn remove(&self, object_reference: &str) -> anyhow::Result<()>;
    fn replace(&self, replacement: &RuntimeReplacement) -> anyhow::Result<()>;
    fn run_one_shot(&self, task: &OneShotTask) -> anyhow::Result<String>;
    fn run_one_shot_authorization_probe(&self, task: &OneShotTask) -> anyhow::Result<bool>;
    fn pull_image(&self, image_reference: &str) -> anyhow::Result<()>;
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
    fn verify_ownership(
        &self,
        object_reference: &str,
        deployment_id: &str,
        runtime_instance_id: &str,
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
        let runtime_matches = observation
            .labels
            .get("io.nazoauth.runtime-instance-id")
            .is_some_and(|value| value == runtime_instance_id);
        if !deployment_matches || !runtime_matches || !authority_matches {
            bail!("runtime ownership labels do not match the authorized deployment and runtime")
        }
        Ok(())
    }
}

pub(crate) fn installed_backends() -> Vec<Box<dyn RuntimeBackend>> {
    let backends: Vec<Box<dyn RuntimeBackend>> = vec![
        Box::new(PodmanBackend::default()),
        Box::new(DockerBackend::default()),
        Box::new(SystemdBackend),
    ];
    backends
        .into_iter()
        .filter(|backend| backend.available())
        .collect()
}

pub(crate) fn backend(kind: RuntimeBackendKind) -> Box<dyn RuntimeBackend> {
    match kind {
        RuntimeBackendKind::Podman => Box::new(PodmanBackend::default()),
        RuntimeBackendKind::Docker => Box::new(DockerBackend::default()),
        RuntimeBackendKind::Systemd => Box::new(SystemdBackend),
    }
}

#[cfg(test)]
pub(crate) fn backend_with_command(
    kind: RuntimeBackendKind,
    command: impl Into<std::ffi::OsString>,
) -> Box<dyn RuntimeBackend> {
    match kind {
        RuntimeBackendKind::Podman => Box::new(PodmanBackend::with_command(command)),
        RuntimeBackendKind::Docker => Box::new(DockerBackend::with_command(command)),
        RuntimeBackendKind::Systemd => backend(kind),
    }
}

pub(super) fn safe_environment(values: &[serde_json::Value]) -> BTreeMap<String, String> {
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
