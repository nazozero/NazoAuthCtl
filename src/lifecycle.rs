use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    deployment::{
        ArtifactReference, Capability, CapabilityGrants, DeploymentRecord, DeploymentStore,
        Responsibility, RuntimeBackendKind, SafeReference,
    },
    discovery::DiscoveredDeployment,
    filesystem::{atomic_write, copy_atomic, remove_file_durable, set_mode, sha256},
    process::Process,
    release::VerifiedRelease,
    runtime_backend::{ContainerRuntimePolicy, NeutralMount, RuntimeReplacement, backend},
};

mod staging;
mod transaction;
mod validation;
pub(crate) use staging::{cache_trusted_runtime, stage_update_release};
use transaction::*;
pub(crate) use transaction::{execute_coordinated_update, recover_registered, rollback_registered};
pub(crate) use validation::invoke_recovery_driver;
use validation::*;

const LIFECYCLE_SCHEMA: u32 = 2;
const RECOVERY_DRIVER_SCHEMA: u32 = 1;
const TRUSTED_RUNTIME_CACHE_SCHEMA: u32 = 2;
const MAX_LIFECYCLE_BYTES: u64 = 256 * 1024;
const MAX_DRIVER_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_INSTANCES: usize = 128;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_TMPFS_MOUNTS: usize = 16;
const MAX_PIDS_LIMIT: u32 = 1_000_000;
const MAX_MEMORY_LIMIT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_CPU_LIMIT_MILLIS: u32 = 256_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedRuntimeCache {
    schema: u32,
    deployment_id: String,
    release: nazo_operator_protocol::EmbeddedIdentity,
    runtimes: BTreeMap<String, CachedRuntimeArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoverySlot {
    schema: u32,
    deployment_id: String,
    trusted_release: nazo_operator_protocol::EmbeddedIdentity,
    recovery_manifest: PathBuf,
    recovery_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum CachedRuntimeArtifact {
    OciArchive {
        image_reference: String,
        digest: String,
        local_image_id: String,
        archive: PathBuf,
        archive_sha256: String,
    },
    HostBinary {
        binary: PathBuf,
        sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RecoveryTransactionState {
    Prepared,
    RuntimesQuiesced,
    ProviderRestored,
    RuntimesRestored,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryTransaction {
    schema: u32,
    transaction_id: String,
    deployment_id: String,
    release: String,
    lifecycle_sha256: String,
    cache_sha256: String,
    recovery_manifest_sha256: String,
    state: RecoveryTransactionState,
    completed_runtimes: BTreeSet<String>,
    updated_at: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UpdateExecutionState {
    Prepared,
    RecoveryPointCreated,
    RuntimesActivated,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateExecution {
    schema: u32,
    transaction_id: String,
    deployment_id: String,
    from_release: nazo_operator_protocol::EmbeddedIdentity,
    target_release: nazo_operator_protocol::EmbeddedIdentity,
    lifecycle_sha256: String,
    from_cache_sha256: String,
    target_cache_sha256: String,
    state: UpdateExecutionState,
    completed_runtimes: BTreeSet<String>,
    recovery_manifest: Option<PathBuf>,
    recovery_manifest_sha256: Option<String>,
    updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleManifest {
    schema: u32,
    pub(crate) deployment_id: String,
    pub(crate) runtimes: Vec<RuntimeLifecycle>,
    pub(crate) recovery_driver: RecoveryDriver,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeLifecycle {
    pub(crate) runtime_instance_id: String,
    pub(crate) backend: RuntimeBackendKind,
    pub(crate) object_reference: String,
    pub(crate) command: Vec<String>,
    pub(crate) mounts: Vec<NeutralMount>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) networks: Vec<String>,
    pub(crate) ip_address: Option<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) container_policy: Option<ContainerRuntimePolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDriver {
    pub(crate) program: PathBuf,
    pub(crate) program_sha256: String,
    #[serde(default)]
    pub(crate) arguments: Vec<String>,
    pub(crate) rehearsal_workspace: PathBuf,
    #[serde(default)]
    pub(crate) credentials: BTreeMap<String, CredentialReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CredentialReference {
    File { path: PathBuf },
    Provider { provider: String, key: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecoveryOperation {
    Rehearse,
    Checkpoint,
    Restore,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryDriverRequest<'a> {
    schema: u32,
    request_id: String,
    deployment_id: &'a str,
    release: &'a str,
    operation: RecoveryOperation,
    lifecycle_sha256: &'a str,
    recovery_manifest: &'a Path,
    recovery_manifest_sha256: &'a str,
    rehearsal_workspace: Option<&'a Path>,
    credentials: &'a BTreeMap<String, CredentialReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDriverReceipt {
    schema: u32,
    request_id: String,
    pub(crate) deployment_id: String,
    pub(crate) release: String,
    pub(crate) operation: RecoveryOperation,
    lifecycle_sha256: String,
    recovery_manifest_sha256: String,
    status: RecoveryStatus,
    pub(crate) components: BTreeSet<String>,
    #[serde(default)]
    pub(crate) checkpoint_manifest: Option<PathBuf>,
    #[serde(default)]
    pub(crate) checkpoint_manifest_sha256: Option<String>,
    issued_at: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RecoveryStatus {
    Succeeded,
}

impl LifecycleManifest {
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect lifecycle contract {}", path.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_LIFECYCLE_BYTES
        {
            bail!("lifecycle contract must be a regular file from 1 through 262144 bytes");
        }
        let manifest: Self =
            serde_json::from_slice(&fs::read(path)?).context("lifecycle contract is invalid")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn validate_for_adoption(
        &self,
        candidates: &[DiscoveredDeployment],
        _capabilities: &CapabilityGrants,
    ) -> anyhow::Result<()> {
        self.validate()?;
        let discovered = candidates
            .iter()
            .filter_map(|candidate| {
                candidate.runtime_instance_id.as_ref().map(|runtime_id| {
                    (
                        runtime_id.as_str(),
                        (
                            candidate.runtime.backend,
                            candidate.runtime.object_reference.as_str(),
                            &candidate.runtime.mounts,
                        ),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        if discovered.len() != candidates.len() || discovered.len() != self.runtimes.len() {
            bail!("lifecycle contract must describe every discovered runtime exactly once");
        }
        for runtime in &self.runtimes {
            let Some((backend, object_reference, mounts)) = discovered
                .get(runtime.runtime_instance_id.as_str())
                .copied()
            else {
                bail!("lifecycle contract contains an unknown runtime instance");
            };
            if runtime.backend != backend || runtime.object_reference != object_reference {
                bail!("lifecycle runtime binding differs from discovered runtime identity");
            }
            for observed in mounts {
                if !runtime.mounts.iter().any(|declared| declared == observed) {
                    bail!("lifecycle contract omits a discovered runtime mount");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn digest(path: &Path) -> anyhow::Result<String> {
        sha256(path)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.schema != LIFECYCLE_SCHEMA {
            bail!("unsupported lifecycle contract schema");
        }
        validate_file_identifier(&self.deployment_id, "lifecycle deployment ID")?;
        if self.runtimes.is_empty() || self.runtimes.len() > MAX_RUNTIME_INSTANCES {
            bail!("lifecycle contract has an invalid runtime count");
        }
        let mut runtime_ids = BTreeSet::new();
        for runtime in &self.runtimes {
            validate_file_identifier(&runtime.runtime_instance_id, "runtime instance ID")?;
            if !runtime_ids.insert(&runtime.runtime_instance_id) {
                bail!("lifecycle contract contains a duplicate runtime instance ID");
            }
            validate_boundary(&runtime.object_reference, "runtime object reference")?;
            validate_server_command(&runtime.command)?;
            if runtime.backend == RuntimeBackendKind::Systemd
                && !Path::new(&runtime.command[0]).is_absolute()
            {
                bail!("systemd lifecycle command must use an absolute binary path");
            }
            validate_container_policy(runtime.backend, runtime.container_policy.as_ref())?;
            validate_environment(runtime.backend, &runtime.environment)?;
            for mount in &runtime.mounts {
                validate_absolute_path(&mount.source, "runtime mount source")?;
                if !runtime_path_is_absolute(runtime.backend, &mount.destination) {
                    bail!("runtime mount destination must be absolute");
                }
            }
            for value in runtime.networks.iter().chain(runtime.ports.iter()) {
                validate_boundary(value, "runtime network or port")?;
            }
            if let Some(ip_address) = &runtime.ip_address {
                ip_address
                    .parse::<std::net::IpAddr>()
                    .context("runtime lifecycle IP address is invalid")?;
            }
        }
        let store = DeploymentStore::system();
        store.validate_failure_domains()?;
        for runtime in &self.runtimes {
            for mount in &runtime.mounts {
                for protected in [
                    &store.config_root,
                    &store.state_root,
                    &store.break_glass_root,
                ] {
                    if paths_overlap(&mount.source, protected) {
                        bail!("runtime lifecycle mount overlaps controller or break-glass state");
                    }
                }
            }
        }
        self.recovery_driver.validate(&self.runtimes)
    }
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
