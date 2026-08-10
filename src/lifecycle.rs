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
        RuntimeBackendKind, SafeReference,
    },
    discovery::DiscoveredDeployment,
    filesystem::{
        atomic_write, copy_atomic_verified, open_secure_regular_file, read_secure_regular_file,
        remove_file_durable, set_mode, sha256, sha256_file,
    },
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

const LIFECYCLE_SCHEMA: u32 = 3;
const RECOVERY_DRIVER_SCHEMA: u32 = 1;
const TRUSTED_RUNTIME_CACHE_SCHEMA: u32 = 2;
const ROLLBACK_EXECUTION_SCHEMA: u32 = 1;
const MAX_LIFECYCLE_BYTES: u64 = 256 * 1024;
const MAX_DRIVER_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_INSTANCES: usize = 128;
const MAX_ACCEPTANCE_ATTEMPTS: u32 = 120;
const MAX_ACCEPTANCE_INTERVAL_SECONDS: u64 = 60;
const MAX_ACCEPTANCE_WAIT_SECONDS: u64 = 600;
const MAX_ACCEPTANCE_UI_BYTES: u64 = 1024 * 1024;
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
    AcceptanceFailed,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RollbackExecutionState {
    Prepared,
    RuntimesActivated,
    DeclarationCommitted,
    AuditCommitted,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackExecution {
    schema: u32,
    transaction_id: String,
    deployment_id: String,
    source_release: nazo_operator_protocol::EmbeddedIdentity,
    target_release: nazo_operator_protocol::EmbeddedIdentity,
    lifecycle_sha256: String,
    cache_sha256: String,
    target_release_sha256: String,
    state: RollbackExecutionState,
    completed_runtimes: BTreeSet<String>,
    updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleManifest {
    schema: u32,
    pub(crate) deployment_id: String,
    pub(crate) runtimes: Vec<RuntimeLifecycle>,
    pub(crate) recovery_driver: RecoveryDriver,
    pub(crate) recovery_providers: Vec<RecoveryProviderTrust>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecoveryArtifactRole {
    DataSnapshot,
    DatabaseRestore,
    LastTrustedArtifact,
    VerificationMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryProviderTrust {
    pub(crate) provider_id: String,
    pub(crate) roles: BTreeSet<RecoveryArtifactRole>,
    pub(crate) verification_key: SafeReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeAcceptance {
    pub(crate) readiness_url: String,
    pub(crate) expected_issuer: String,
    pub(crate) discovery_url: String,
    pub(crate) ui_url: String,
    pub(crate) ui_sha256: String,
    pub(crate) ui_size: u64,
    pub(crate) attempts: u32,
    pub(crate) interval_seconds: u64,
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
    pub(crate) acceptance: RuntimeAcceptance,
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
        let bytes =
            read_secure_regular_file(path, "lifecycle contract", false, MAX_LIFECYCLE_BYTES)?;
        if bytes.is_empty() {
            bail!("lifecycle contract must be a regular file from 1 through 262144 bytes");
        }
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).context("lifecycle contract is invalid")?;
        if document.get("schema").and_then(serde_json::Value::as_u64)
            != Some(u64::from(LIFECYCLE_SCHEMA))
        {
            bail!("unsupported lifecycle contract schema; migrate to schema 3");
        }
        let manifest: Self =
            serde_json::from_value(document).context("lifecycle contract is invalid")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn validate_for_adoption(
        &self,
        candidates: &[DiscoveredDeployment],
        capabilities: &CapabilityGrants,
    ) -> anyhow::Result<()> {
        capabilities.validate()?;
        self.validate()?;
        let discovered = candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .runtime_instance_id
                    .as_ref()
                    .map(|runtime_id| (runtime_id.as_str(), candidate))
            })
            .collect::<BTreeMap<_, _>>();
        if discovered.len() != candidates.len() || discovered.len() != self.runtimes.len() {
            bail!("lifecycle contract must describe every discovered runtime exactly once");
        }
        for runtime in &self.runtimes {
            let Some(candidate) = discovered
                .get(runtime.runtime_instance_id.as_str())
                .copied()
            else {
                bail!("lifecycle contract contains an unknown runtime instance");
            };
            if runtime.backend != candidate.runtime.backend
                || runtime.object_reference != candidate.runtime.object_reference
            {
                bail!("lifecycle runtime binding differs from discovered runtime identity");
            }
            if candidate.issuer.as_deref() != Some(runtime.acceptance.expected_issuer.as_str()) {
                bail!("lifecycle acceptance issuer differs from discovered deployment issuer");
            }
            if runtime.networks.iter().collect::<BTreeSet<_>>()
                != candidate.runtime.networks.iter().collect::<BTreeSet<_>>()
                || runtime.ports.iter().collect::<BTreeSet<_>>()
                    != candidate.runtime.ports.iter().collect::<BTreeSet<_>>()
            {
                bail!("lifecycle runtime network or port bindings differ from discovery");
            }
            for (name, value) in &candidate.runtime.safe_environment {
                if runtime.environment.get(name) != Some(value) {
                    bail!("lifecycle runtime environment differs from discovery");
                }
            }
            let mut matched = vec![false; runtime.mounts.len()];
            for observed in &candidate.runtime.mounts {
                let Some(index) =
                    runtime
                        .mounts
                        .iter()
                        .enumerate()
                        .position(|(index, declared)| {
                            !matched[index]
                                && mount_matches(
                                    declared,
                                    observed,
                                    candidate.sensitive_mount_sources.get(&observed.destination),
                                )
                        })
                else {
                    bail!("lifecycle contract does not exactly match discovered runtime mounts");
                };
                matched[index] = true;
            }
            if matched.iter().any(|matched| !matched) {
                bail!("lifecycle contract declares an undiscovered runtime mount");
            }
        }
        self.validate_mutation_scope(capabilities)
    }

    pub(crate) fn validate_mutation_scope(
        &self,
        capabilities: &CapabilityGrants,
    ) -> anyhow::Result<()> {
        if capabilities.runtime.responsibility.permits_mutation()
            && self
                .runtimes
                .iter()
                .flat_map(|runtime| runtime.mounts.iter())
                .any(|mount| mount.scope == crate::deployment::ResourceScope::Shared)
        {
            bail!(
                "mutable lifecycle runtime cannot use a shared mount without provider-specific locking and deletion evidence"
            );
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
            let mut mount_destinations = BTreeSet::new();
            for mount in &runtime.mounts {
                validate_absolute_path(&mount.source, "runtime mount source")?;
                if !runtime_path_is_absolute(runtime.backend, &mount.destination) {
                    bail!("runtime mount destination must be absolute");
                }
                if !mount_destinations.insert(&mount.destination) {
                    bail!("lifecycle runtime contains duplicate mount destinations");
                }
            }
            let mut network_and_ports = BTreeSet::new();
            for value in runtime.networks.iter().chain(runtime.ports.iter()) {
                validate_boundary(value, "runtime network or port")?;
                if !network_and_ports.insert(value) {
                    bail!("lifecycle runtime contains duplicate network or port bindings");
                }
            }
            if let Some(ip_address) = &runtime.ip_address {
                ip_address
                    .parse::<std::net::IpAddr>()
                    .context("runtime lifecycle IP address is invalid")?;
            }
            runtime.acceptance.validate()?;
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
        self.validate_recovery_providers()?;
        self.recovery_driver.validate(&self.runtimes)
    }

    fn validate_recovery_providers(&self) -> anyhow::Result<()> {
        if self.recovery_providers.is_empty() {
            bail!("lifecycle contract must pin at least one recovery provider");
        }
        let required = BTreeSet::from([
            RecoveryArtifactRole::DataSnapshot,
            RecoveryArtifactRole::DatabaseRestore,
            RecoveryArtifactRole::LastTrustedArtifact,
            RecoveryArtifactRole::VerificationMaterial,
        ]);
        let mut covered = BTreeSet::new();
        let mut provider_ids = BTreeSet::new();
        let store = DeploymentStore::system();
        for provider in &self.recovery_providers {
            validate_file_identifier(&provider.provider_id, "recovery provider ID")?;
            if !provider_ids.insert(&provider.provider_id) {
                bail!("lifecycle contract contains a duplicate recovery provider ID");
            }
            if provider.roles.is_empty() {
                bail!("recovery provider must pin at least one artifact role");
            }
            let SafeReference::DigestBoundFile {
                path,
                sha256: expected,
            } = &provider.verification_key
            else {
                bail!("recovery provider verification key must be a digest-bound file");
            };
            validate_absolute_path(path, "recovery provider verification key")?;
            validate_lower_hex(expected)?;
            if self.runtimes.iter().any(|runtime| {
                runtime
                    .mounts
                    .iter()
                    .any(|mount| paths_overlap(path, &mount.source))
            }) {
                bail!("recovery provider verification key is inside an application failure domain");
            }
            for protected in [
                &store.config_root,
                &store.state_root,
                &store.break_glass_root,
            ] {
                if paths_overlap(path, protected) {
                    bail!(
                        "recovery provider verification key overlaps controller or break-glass state"
                    );
                }
            }
            let mut key =
                open_secure_regular_file(path, "recovery provider verification key", false)?;
            if key.metadata()?.len() == 0
                || sha256_file(&mut key, &path.display().to_string())? != *expected
            {
                bail!(
                    "recovery provider verification key digest does not match the lifecycle contract"
                );
            }
            for role in &provider.roles {
                if !covered.insert(role.clone()) {
                    bail!("recovery artifact role is pinned by more than one provider");
                }
            }
        }
        if covered != required {
            bail!("lifecycle recovery providers do not cover every recovery artifact role");
        }
        Ok(())
    }
}

impl RuntimeAcceptance {
    fn validate(&self) -> anyhow::Result<()> {
        if self.attempts == 0 || self.attempts > MAX_ACCEPTANCE_ATTEMPTS {
            bail!("lifecycle acceptance attempts must be from 1 through {MAX_ACCEPTANCE_ATTEMPTS}");
        }
        if self.interval_seconds > MAX_ACCEPTANCE_INTERVAL_SECONDS {
            bail!(
                "lifecycle acceptance interval must be at most {MAX_ACCEPTANCE_INTERVAL_SECONDS} seconds"
            );
        }
        if u64::from(self.attempts).saturating_mul(self.interval_seconds)
            > MAX_ACCEPTANCE_WAIT_SECONDS
        {
            bail!(
                "lifecycle acceptance retry window must be at most {MAX_ACCEPTANCE_WAIT_SECONDS} seconds"
            );
        }
        if self.ui_size == 0 || self.ui_size > MAX_ACCEPTANCE_UI_BYTES {
            bail!("lifecycle acceptance UI size is outside the verification boundary");
        }
        validate_lower_hex(&self.ui_sha256)?;
        validate_acceptance_string(
            &self.expected_issuer,
            "lifecycle acceptance expected issuer",
        )?;

        let issuer = crate::model::parse_public_origin(
            &self.expected_issuer,
            "lifecycle acceptance expected issuer",
        )?;
        let readiness =
            validate_acceptance_url(&self.readiness_url, "lifecycle acceptance readiness URL")?;
        let discovery =
            validate_acceptance_url(&self.discovery_url, "lifecycle acceptance Discovery URL")?;
        let ui = validate_acceptance_url(&self.ui_url, "lifecycle acceptance UI URL")?;
        if readiness.origin() != issuer.origin()
            || discovery.origin() != issuer.origin()
            || ui.origin() != issuer.origin()
        {
            bail!("lifecycle acceptance endpoints must share the expected issuer origin");
        }
        if discovery.path() != "/.well-known/openid-configuration" {
            bail!(
                "lifecycle acceptance Discovery URL must be the expected issuer origin's OIDC Discovery endpoint"
            );
        }
        Ok(())
    }
}

pub(crate) fn validate_lifecycle_acceptance_record_binding(
    lifecycle: &LifecycleManifest,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    if lifecycle
        .runtimes
        .iter()
        .any(|runtime| runtime.acceptance.expected_issuer != record.issuer)
    {
        bail!("lifecycle acceptance issuer no longer matches the deployment declaration");
    }
    Ok(())
}

pub(crate) fn rollback_execution_path(store: &DeploymentStore, deployment_id: &str) -> PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("active-lifecycle-rollback.json")
}

pub(crate) fn load_rollback_execution(path: &Path) -> anyhow::Result<RollbackExecution> {
    let bytes = read_secure_regular_file(
        path,
        "lifecycle rollback execution journal",
        true,
        MAX_LIFECYCLE_BYTES,
    )?;
    serde_json::from_slice(&bytes).context("lifecycle rollback execution journal is invalid")
}

pub(crate) fn persist_rollback_execution(
    path: &Path,
    execution: &RollbackExecution,
) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(execution)?, 0o600)
}

pub(crate) fn embedded_identity_digest(
    identity: &nazo_operator_protocol::EmbeddedIdentity,
) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(identity)?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_acceptance_url(value: &str, label: &str) -> anyhow::Result<url::Url> {
    validate_acceptance_string(value, label)?;
    let url = url::Url::parse(value).with_context(|| format!("{label} must be an absolute URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("{label} must not contain credentials, query, or fragment");
    }
    let mut origin = url.clone();
    origin.set_path("");
    crate::model::parse_public_origin(origin.as_str(), label)?;
    Ok(url)
}

fn validate_acceptance_string(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > MAX_ARGUMENT_BYTES || value.contains(['\0', '\r', '\n']) {
        bail!("{label} is empty, too long, or contains a control character");
    }
    Ok(())
}

fn mount_matches(
    declared: &NeutralMount,
    observed: &NeutralMount,
    sensitive_source: Option<&PathBuf>,
) -> bool {
    let observed_source = sensitive_source.unwrap_or(&observed.source);
    declared.source == *observed_source
        && declared.destination == observed.destination
        && declared.read_only == observed.read_only
        && declared.selinux_relabel == observed.selinux_relabel
        && declared.ownership == observed.ownership
        && declared.scope == observed.scope
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
