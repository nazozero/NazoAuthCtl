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
    runtime_backend::{NeutralMount, RuntimeReplacement, backend},
};

const LIFECYCLE_SCHEMA: u32 = 1;
const RECOVERY_DRIVER_SCHEMA: u32 = 1;
const MAX_LIFECYCLE_BYTES: u64 = 256 * 1024;
const MAX_DRIVER_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_INSTANCES: usize = 128;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4096;

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

pub(crate) fn cache_trusted_runtime(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    record.validate()?;
    let directory =
        trusted_runtime_directory(store, &record.deployment_id, &record.active_release.release)?;
    let manifest_path = directory.join("cache.json");
    if manifest_path.exists() {
        let cache = load_cache(&manifest_path, record)?;
        validate_cached_artifacts(&cache)?;
        ensure_adoption_recovery_slot(store, record)?;
        return Ok(());
    }
    fs::create_dir_all(&directory)?;
    let mut runtimes = BTreeMap::new();
    for runtime in &record.runtime_instances {
        let artifact_directory = directory.join(&runtime.runtime_instance_id);
        fs::create_dir_all(&artifact_directory)?;
        let cached = match &runtime.artifact {
            ArtifactReference::Oci {
                image_reference,
                digest,
            } => {
                validate_oci_digest(digest)?;
                let archive = artifact_directory.join("image.tar");
                if !archive.exists() {
                    let temporary = artifact_directory.join("image.partial.tar");
                    if temporary.exists() {
                        fs::remove_file(&temporary)?;
                    }
                    backend(runtime.backend).export_image(
                        &format!(
                            "{}@{digest}",
                            image_reference.split('@').next().unwrap_or(image_reference)
                        ),
                        &temporary,
                    )?;
                    let metadata = fs::symlink_metadata(&temporary)?;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_file()
                        || metadata.len() == 0
                    {
                        bail!("runtime backend exported an invalid OCI recovery archive");
                    }
                    fs::rename(&temporary, &archive)?;
                }
                CachedRuntimeArtifact::OciArchive {
                    image_reference: image_reference.clone(),
                    digest: digest.clone(),
                    archive_sha256: sha256(&archive)?,
                    archive,
                }
            }
            ArtifactReference::HostBinary {
                path,
                sha256: expected,
            } => {
                validate_lower_hex(expected)?;
                if sha256(path)? != *expected {
                    bail!("host runtime binary changed before recovery caching");
                }
                let binary = artifact_directory.join(if cfg!(windows) {
                    "nazoauth.exe"
                } else {
                    "nazoauth"
                });
                copy_atomic(path, &binary, 0o500)?;
                set_mode(&binary, 0o500)?;
                if sha256(&binary)? != *expected {
                    bail!("cached host runtime binary changed during persistence");
                }
                CachedRuntimeArtifact::HostBinary {
                    binary,
                    sha256: expected.clone(),
                }
            }
            ArtifactReference::Unknown => {
                bail!("cannot cache an unidentified runtime artifact for recovery")
            }
        };
        runtimes.insert(runtime.runtime_instance_id.clone(), cached);
    }
    let cache = TrustedRuntimeCache {
        schema: 1,
        deployment_id: record.deployment_id.clone(),
        release: record.active_release.clone(),
        runtimes,
    };
    atomic_write(&manifest_path, &serde_json::to_vec_pretty(&cache)?, 0o600)?;
    validate_cached_artifacts(&load_cache(&manifest_path, record)?)?;
    ensure_adoption_recovery_slot(store, record)
}

fn ensure_adoption_recovery_slot(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    let adoption_manifest = store
        .deployment_state_dir(&record.deployment_id)
        .join("recovery")
        .join("adoption")
        .join("manifest.json");
    if adoption_manifest.is_file() && !recovery_slot_path(store, &record.deployment_id).exists() {
        persist_recovery_slot(
            store,
            &RecoverySlot {
                schema: 1,
                deployment_id: record.deployment_id.clone(),
                trusted_release: record.active_release.clone(),
                recovery_manifest_sha256: sha256(&adoption_manifest)?,
                recovery_manifest: adoption_manifest,
            },
        )?;
    }
    Ok(())
}

pub(crate) fn stage_update_release(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    release: &VerifiedRelease,
) -> anyhow::Result<()> {
    let directory =
        trusted_runtime_directory(store, &record.deployment_id, &release.manifest.version)?;
    let manifest_path = directory.join("cache.json");
    if manifest_path.exists() {
        let staged_record = DeploymentRecord {
            active_release: release.manifest.embedded.clone(),
            ..record.clone()
        };
        let cache = load_cache(&manifest_path, &staged_record)?;
        return validate_cached_artifacts(&cache);
    }
    fs::create_dir_all(&directory)?;
    let mut runtimes = BTreeMap::new();
    for runtime in &record.runtime_instances {
        let artifact_directory = directory.join(&runtime.runtime_instance_id);
        fs::create_dir_all(&artifact_directory)?;
        let cached = if runtime.backend == RuntimeBackendKind::Systemd {
            let source = release.artifact("binary", "nazozero/NazoAuth")?;
            let expected = crate::filesystem::sha256(&source)?;
            let binary = artifact_directory.join(if cfg!(windows) {
                "nazoauth.exe"
            } else {
                "nazoauth"
            });
            copy_atomic(&source, &binary, 0o500)?;
            set_mode(&binary, 0o500)?;
            if crate::filesystem::sha256(&binary)? != expected {
                bail!("staged host Release changed while entering the recovery cache");
            }
            CachedRuntimeArtifact::HostBinary {
                binary,
                sha256: expected,
            }
        } else {
            let runtime_backend = backend(runtime.backend);
            let image_reference = release.manifest.image_ref()?;
            let digest = release.manifest.image_oci_digest().to_owned();
            validate_oci_digest(&digest)?;
            runtime_backend.pull_image(&image_reference)?;
            if runtime_backend.resolve_image_digest(&image_reference)? != digest {
                bail!("staged OCI Release does not match the signed runtime digest");
            }
            let archive = artifact_directory.join("image.tar");
            let temporary = artifact_directory.join("image.partial.tar");
            if temporary.exists() {
                fs::remove_file(&temporary)?;
            }
            runtime_backend.export_image(
                &format!(
                    "{}@{digest}",
                    image_reference
                        .split('@')
                        .next()
                        .unwrap_or(&image_reference)
                ),
                &temporary,
            )?;
            let metadata = fs::symlink_metadata(&temporary)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                bail!("runtime backend exported an invalid staged OCI archive");
            }
            fs::rename(&temporary, &archive)?;
            CachedRuntimeArtifact::OciArchive {
                image_reference,
                digest,
                archive_sha256: sha256(&archive)?,
                archive,
            }
        };
        runtimes.insert(runtime.runtime_instance_id.clone(), cached);
    }
    let cache = TrustedRuntimeCache {
        schema: 1,
        deployment_id: record.deployment_id.clone(),
        release: release.manifest.embedded.clone(),
        runtimes,
    };
    atomic_write(&manifest_path, &serde_json::to_vec_pretty(&cache)?, 0o600)?;
    validate_cached_artifacts(&cache)
}

pub(crate) fn execute_coordinated_update(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    transaction: &crate::coordination::UpdateCoordination,
) -> anyhow::Result<crate::coordination::UpdateCoordination> {
    use crate::coordination::{CoordinationState, StepOwner, StepState};

    if transaction.deployment_id != record.deployment_id {
        bail!("update transaction is bound to a different deployment");
    }
    if transaction.state == CoordinationState::Committed {
        crate::governance::append_management_audit(
            store,
            record,
            &transaction.transaction_id,
            "lifecycle-update",
            &transaction.target_release.release,
        )?;
        crate::coordination::finalize_committed_locked(store, record, &transaction.transaction_id)?;
        archive_update_execution(store, &record.deployment_id, &transaction.transaction_id)?;
        return Ok(transaction.clone());
    }
    if transaction.state != CoordinationState::ReadyForController {
        bail!("update transaction is not ready for controller execution");
    }
    record.require_mutation(&[Capability::Runtime, Capability::Artifact])?;
    if !record.core_recovery_is_proven() {
        bail!("controller update is forbidden until offline recovery is proven");
    }

    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let lifecycle_path = lifecycle_path(record)?;
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    let from_cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &record.active_release.release)?
            .join("cache.json");
    let target_cache_path = trusted_runtime_directory(
        store,
        &record.deployment_id,
        &transaction.target_release.release,
    )?
    .join("cache.json");
    let from_cache = load_cache(&from_cache_path, record)?;
    let target_record = DeploymentRecord {
        active_release: transaction.target_release.clone(),
        ..record.clone()
    };
    let target_cache = load_cache(&target_cache_path, &target_record)?;
    validate_cached_artifacts(&from_cache)?;
    validate_cached_artifacts(&target_cache)?;

    let execution_path = update_execution_path(store, &record.deployment_id);
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let from_cache_sha256 = sha256(&from_cache_path)?;
    let target_cache_sha256 = sha256(&target_cache_path)?;
    let mut execution = if execution_path.exists() {
        let execution: UpdateExecution = serde_json::from_slice(&fs::read(&execution_path)?)
            .context("lifecycle update execution journal is invalid")?;
        if execution.schema != 1
            || execution.transaction_id != transaction.transaction_id
            || execution.deployment_id != record.deployment_id
            || execution.from_release != record.active_release
            || execution.target_release != transaction.target_release
            || execution.lifecycle_sha256 != lifecycle_sha256
            || execution.from_cache_sha256 != from_cache_sha256
            || execution.target_cache_sha256 != target_cache_sha256
        {
            bail!("lifecycle update journal binding changed after preparation");
        }
        execution
    } else {
        UpdateExecution {
            schema: 1,
            transaction_id: transaction.transaction_id.clone(),
            deployment_id: record.deployment_id.clone(),
            from_release: record.active_release.clone(),
            target_release: transaction.target_release.clone(),
            lifecycle_sha256,
            from_cache_sha256,
            target_cache_sha256,
            state: UpdateExecutionState::Prepared,
            completed_runtimes: BTreeSet::new(),
            recovery_manifest: None,
            recovery_manifest_sha256: None,
            updated_at: Utc::now().timestamp(),
        }
    };
    persist_update_execution(&execution_path, &execution)?;
    let mut current = crate::coordination::show(store, record)?;

    if controller_step_pending(&current, "recovery-point") {
        record.require_mutation(&[Capability::Backups])?;
        let slot = load_recovery_slot(store, record)?;
        let receipt = invoke_recovery_driver(
            lifecycle_path,
            &lifecycle,
            &slot.recovery_manifest,
            &record.active_release.release,
            RecoveryOperation::Checkpoint,
            &record.capabilities,
        )?;
        let source = receipt
            .checkpoint_manifest
            .as_deref()
            .context("checkpoint receipt did not return a recovery manifest")?;
        let recovery_directory = store
            .deployment_state_dir(&record.deployment_id)
            .join("transactions")
            .join(&transaction.transaction_id)
            .join("recovery");
        crate::adoption::persist_bound_recovery_package(
            source,
            &record.deployment_id,
            &record.active_release.release,
            &recovery_directory,
        )?;
        let persisted = recovery_directory.join("manifest.json");
        execution.recovery_manifest_sha256 = Some(sha256(&persisted)?);
        execution.recovery_manifest = Some(persisted);
        execution.state = UpdateExecutionState::RecoveryPointCreated;
        execution.updated_at = Utc::now().timestamp();
        persist_update_execution(&execution_path, &execution)?;
        current = crate::coordination::complete_controller_step_locked(
            store,
            record,
            &transaction.transaction_id,
            "recovery-point",
            &sha256(&execution_path)?,
        )?;
    }

    if controller_step_pending(&current, "database-migration") {
        bail!(
            "the offline lifecycle contract cannot execute application migrations; enroll operator-task authority or provide this step as external evidence"
        );
    }

    for runtime in &lifecycle.runtimes {
        let step_id = format!("runtime-replace-{}", runtime.runtime_instance_id);
        let step = current
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .with_context(|| {
                format!("update plan omits runtime {}", runtime.runtime_instance_id)
            })?;
        match (step.owner, step.state) {
            (StepOwner::CtlOwned, StepState::Pending) => {
                let cached = target_cache
                    .runtimes
                    .get(&runtime.runtime_instance_id)
                    .context("target cache omits a lifecycle runtime")?;
                activate_cached_runtime(record, runtime, &transaction.target_release, cached)?;
                execution
                    .completed_runtimes
                    .insert(runtime.runtime_instance_id.clone());
                execution.updated_at = Utc::now().timestamp();
                persist_update_execution(&execution_path, &execution)?;
                current = crate::coordination::complete_controller_step_locked(
                    store,
                    record,
                    &transaction.transaction_id,
                    &step_id,
                    &sha256(&execution_path)?,
                )?;
            }
            (StepOwner::UserRequired | StepOwner::ProviderOwned, StepState::EvidenceAccepted)
            | (StepOwner::CtlOwned, StepState::ControllerCompleted) => {
                let cached = target_cache
                    .runtimes
                    .get(&runtime.runtime_instance_id)
                    .context("target cache omits a lifecycle runtime")?;
                verify_active_runtime(runtime, &transaction.target_release, cached)?;
                execution
                    .completed_runtimes
                    .insert(runtime.runtime_instance_id.clone());
            }
            _ => bail!("runtime update step is not ready for execution"),
        }
    }
    execution.state = UpdateExecutionState::RuntimesActivated;
    execution.updated_at = Utc::now().timestamp();
    persist_update_execution(&execution_path, &execution)?;

    if controller_step_pending(&current, "acceptance") {
        for runtime in &lifecycle.runtimes {
            let cached = target_cache
                .runtimes
                .get(&runtime.runtime_instance_id)
                .context("target cache omits a lifecycle runtime")?;
            verify_active_runtime(runtime, &transaction.target_release, cached)?;
        }
        let old_slot = load_recovery_slot(store, record)?;
        let rollback_manifest = execution
            .recovery_manifest
            .clone()
            .unwrap_or(old_slot.recovery_manifest);
        let rollback_manifest_sha256 = execution
            .recovery_manifest_sha256
            .clone()
            .unwrap_or(old_slot.recovery_manifest_sha256);
        persist_recovery_slot(
            store,
            &RecoverySlot {
                schema: 1,
                deployment_id: record.deployment_id.clone(),
                trusted_release: record.active_release.clone(),
                recovery_manifest: rollback_manifest,
                recovery_manifest_sha256: rollback_manifest_sha256,
            },
        )?;
        let mut updated = record.clone();
        updated.active_release = transaction.target_release.clone();
        for declared in &mut updated.runtime_instances {
            let runtime = lifecycle
                .runtimes
                .iter()
                .find(|runtime| runtime.runtime_instance_id == declared.runtime_instance_id)
                .context("lifecycle lost a declared runtime during update commit")?;
            let cached = target_cache
                .runtimes
                .get(&declared.runtime_instance_id)
                .context("target cache lost a declared runtime during update commit")?;
            declared.artifact = activated_artifact_reference(runtime, cached)?;
        }
        updated.declaration_revision += 1;
        current = crate::coordination::commit_controller_update_locked(
            store,
            record,
            &updated,
            &transaction.transaction_id,
            "acceptance",
            &sha256(&target_cache_path)?,
        )?;
        execution.state = UpdateExecutionState::Committed;
        execution.updated_at = Utc::now().timestamp();
        persist_update_execution(&execution_path, &execution)?;
        crate::governance::append_management_audit(
            store,
            &updated,
            &transaction.transaction_id,
            "lifecycle-update",
            &transaction.target_release.release,
        )?;
        crate::coordination::finalize_committed_locked(
            store,
            &updated,
            &transaction.transaction_id,
        )?;
        archive_update_execution(store, &record.deployment_id, &transaction.transaction_id)?;
    }
    Ok(current)
}

pub(crate) fn rollback_registered(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    record.require_mutation(&[Capability::Runtime, Capability::Artifact])?;
    if !record.core_recovery_is_proven() {
        bail!("deployment has no proven controller-independent rollback contract");
    }
    let _deployment_lock = store.deployment_lock(&record.deployment_id)?;
    let lifecycle_path = lifecycle_path(record)?;
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    let slot = load_recovery_slot(store, record)?;
    let trusted_record = DeploymentRecord {
        active_release: slot.trusted_release.clone(),
        ..record.clone()
    };
    let cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &slot.trusted_release.release)?
            .join("cache.json");
    let cache = load_cache(&cache_path, &trusted_record)?;
    validate_cached_artifacts(&cache)?;
    for runtime in &lifecycle.runtimes {
        let cached = cache
            .runtimes
            .get(&runtime.runtime_instance_id)
            .context("rollback cache omits a lifecycle runtime")?;
        activate_cached_runtime(record, runtime, &slot.trusted_release, cached)?;
    }
    let mut rolled_back = record.clone();
    rolled_back.active_release = slot.trusted_release;
    for declared in &mut rolled_back.runtime_instances {
        let runtime = lifecycle
            .runtimes
            .iter()
            .find(|runtime| runtime.runtime_instance_id == declared.runtime_instance_id)
            .context("lifecycle lost a declared runtime during rollback")?;
        let cached = cache
            .runtimes
            .get(&declared.runtime_instance_id)
            .context("rollback cache lost a declared runtime")?;
        declared.artifact = activated_artifact_reference(runtime, cached)?;
    }
    if rolled_back != *record {
        rolled_back.declaration_revision += 1;
        store.persist_declaration_locked(&rolled_back)?;
    }
    crate::governance::append_management_audit(
        store,
        &rolled_back,
        &format!("rollback-{:020}", record.declaration_revision),
        "lifecycle-rollback",
        &rolled_back.active_release.release,
    )?;
    Ok(())
}

pub(crate) fn recover_registered(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    record.require_mutation(&[
        Capability::Runtime,
        Capability::Artifact,
        Capability::Backups,
    ])?;
    if !record.core_recovery_is_proven() {
        bail!("deployment has no proven controller-independent recovery contract");
    }
    let lifecycle_path = match record.resources.get("lifecycle_contract") {
        Some(SafeReference::File { path }) => path,
        _ => bail!("deployment has no executable lifecycle contract"),
    };
    let lifecycle = LifecycleManifest::load(lifecycle_path)?;
    validate_lifecycle_record_binding(&lifecycle, record)?;
    let slot = load_recovery_slot(store, record)?;
    let recovery_manifest = slot.recovery_manifest.clone();
    let cache_path =
        trusted_runtime_directory(store, &record.deployment_id, &slot.trusted_release.release)?
            .join("cache.json");
    let trusted_record = DeploymentRecord {
        active_release: slot.trusted_release.clone(),
        ..record.clone()
    };
    let cache = load_cache(&cache_path, &trusted_record)?;
    validate_cached_artifacts(&cache)?;
    let transaction_path = store
        .deployment_state_dir(&record.deployment_id)
        .join("transactions")
        .join("active-recovery.json");
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let cache_sha256 = sha256(&cache_path)?;
    let mut transaction = if transaction_path.exists() {
        let transaction: RecoveryTransaction =
            serde_json::from_slice(&fs::read(&transaction_path)?)
                .context("recovery transaction is invalid")?;
        if transaction.schema != 1
            || transaction.deployment_id != record.deployment_id
            || transaction.release != slot.trusted_release.release
            || transaction.lifecycle_sha256 != lifecycle_sha256
            || transaction.cache_sha256 != cache_sha256
        {
            bail!("recovery transaction binding changed after preparation");
        }
        transaction
    } else {
        RecoveryTransaction {
            schema: 1,
            transaction_id: uuid::Uuid::now_v7().to_string(),
            deployment_id: record.deployment_id.clone(),
            release: slot.trusted_release.release.clone(),
            lifecycle_sha256,
            cache_sha256,
            state: RecoveryTransactionState::Prepared,
            completed_runtimes: BTreeSet::new(),
            updated_at: Utc::now().timestamp(),
        }
    };
    persist_recovery_transaction(&transaction_path, &transaction)?;
    if transaction.state < RecoveryTransactionState::ProviderRestored {
        let receipt = invoke_recovery_driver(
            lifecycle_path,
            &lifecycle,
            &recovery_manifest,
            &slot.trusted_release.release,
            RecoveryOperation::Restore,
            &record.capabilities,
        )?;
        atomic_write(
            &store
                .deployment_state_dir(&record.deployment_id)
                .join("recovery")
                .join("latest-driver-receipt.json"),
            &serde_json::to_vec_pretty(&receipt)?,
            0o600,
        )?;
        transaction.state = RecoveryTransactionState::ProviderRestored;
        transaction.updated_at = Utc::now().timestamp();
        persist_recovery_transaction(&transaction_path, &transaction)?;
    }
    for runtime in &lifecycle.runtimes {
        if transaction
            .completed_runtimes
            .contains(&runtime.runtime_instance_id)
        {
            continue;
        }
        let artifact = cache
            .runtimes
            .get(&runtime.runtime_instance_id)
            .context("trusted runtime cache omits a lifecycle runtime")?;
        activate_cached_runtime(record, runtime, &slot.trusted_release, artifact)?;
        transaction
            .completed_runtimes
            .insert(runtime.runtime_instance_id.clone());
        transaction.updated_at = Utc::now().timestamp();
        persist_recovery_transaction(&transaction_path, &transaction)?;
    }
    transaction.state = RecoveryTransactionState::RuntimesRestored;
    transaction.updated_at = Utc::now().timestamp();
    persist_recovery_transaction(&transaction_path, &transaction)?;
    let mut recovered = record.clone();
    recovered.active_release = slot.trusted_release.clone();
    for runtime in &mut recovered.runtime_instances {
        let lifecycle_runtime = lifecycle
            .runtimes
            .iter()
            .find(|entry| entry.runtime_instance_id == runtime.runtime_instance_id)
            .context("recovery lifecycle lost a declared runtime")?;
        let cached = cache
            .runtimes
            .get(&runtime.runtime_instance_id)
            .context("recovery cache lost a declared runtime")?;
        runtime.artifact = activated_artifact_reference(lifecycle_runtime, cached)?;
    }
    if recovered != *record {
        recovered.declaration_revision += 1;
        store.persist_declaration_locked(&recovered)?;
    }
    transaction.state = RecoveryTransactionState::Committed;
    transaction.updated_at = Utc::now().timestamp();
    persist_recovery_transaction(&transaction_path, &transaction)?;
    crate::governance::append_management_audit(
        store,
        &recovered,
        &transaction.transaction_id,
        "lifecycle-recover",
        &recovered.active_release.release,
    )?;
    let history =
        transaction_path.with_file_name(format!("recovery-{}.json", transaction.transaction_id));
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&transaction_path)
}

fn activate_cached_runtime(
    record: &DeploymentRecord,
    runtime: &RuntimeLifecycle,
    expected_release: &nazo_operator_protocol::EmbeddedIdentity,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<()> {
    let backend = backend(runtime.backend);
    let artifact = match cached {
        CachedRuntimeArtifact::OciArchive {
            image_reference,
            digest,
            archive,
            archive_sha256,
        } => {
            if sha256(archive)? != *archive_sha256 {
                bail!("cached OCI recovery archive changed before activation");
            }
            backend.import_image(archive)?;
            let resolved = backend.resolve_image_digest(image_reference)?;
            if resolved != *digest {
                bail!("imported OCI recovery artifact does not match its trusted digest");
            }
            ArtifactReference::Oci {
                image_reference: image_reference.clone(),
                digest: digest.clone(),
            }
        }
        CachedRuntimeArtifact::HostBinary { binary, sha256 } => {
            if crate::filesystem::sha256(binary)? != *sha256 {
                bail!("cached host recovery artifact changed before activation");
            }
            ArtifactReference::HostBinary {
                path: binary.clone(),
                sha256: sha256.clone(),
            }
        }
    };
    let embedded = backend
        .read_build_identity(&artifact)?
        .context("trusted recovery artifact exposes no embedded build identity")?;
    if embedded != *expected_release {
        bail!("trusted recovery artifact embedded identity changed before activation");
    }
    if let Ok(observation) = backend.inspect(&runtime.object_reference) {
        if observation.running {
            backend.stop(&runtime.object_reference)?;
        }
        if runtime.backend != RuntimeBackendKind::Systemd {
            backend.remove(&runtime.object_reference)?;
        }
    }
    let replacement = RuntimeReplacement {
        object_reference: runtime.object_reference.clone(),
        artifact: artifact.clone(),
        command: runtime.command.clone(),
        mounts: runtime.mounts.clone(),
        environment: runtime.environment.clone(),
        networks: runtime.networks.clone(),
        ip_address: runtime.ip_address.clone(),
        ports: runtime.ports.clone(),
        labels: BTreeMap::from([
            (
                "io.nazoauth.deployment-id".to_owned(),
                record.deployment_id.clone(),
            ),
            (
                "io.nazoauth.runtime-instance-id".to_owned(),
                runtime.runtime_instance_id.clone(),
            ),
            (
                "io.nazoauth.control-authority".to_owned(),
                record.control_authority.clone(),
            ),
        ]),
    };
    backend.replace(&replacement)?;
    let observation = backend.inspect(&runtime.object_reference)?;
    if !observation.running || !artifact_identity_matches(&observation.artifact, &artifact) {
        bail!("restored runtime did not retain the trusted artifact identity");
    }
    if record.capabilities.runtime.responsibility == Responsibility::Managed {
        backend.verify_ownership(
            &runtime.object_reference,
            &record.deployment_id,
            &record.control_authority,
        )?;
    }
    Ok(())
}

fn validate_lifecycle_record_binding(
    lifecycle: &LifecycleManifest,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    if lifecycle.deployment_id != record.deployment_id
        || lifecycle.runtimes.len() != record.runtime_instances.len()
    {
        bail!("lifecycle contract no longer matches the deployment declaration");
    }
    for runtime in &lifecycle.runtimes {
        if !record.runtime_instances.iter().any(|declared| {
            declared.runtime_instance_id == runtime.runtime_instance_id
                && declared.backend == runtime.backend
                && declared.object_reference == runtime.object_reference
        }) {
            bail!("lifecycle runtime no longer matches the deployment declaration");
        }
    }
    Ok(())
}

fn lifecycle_path(record: &DeploymentRecord) -> anyhow::Result<&Path> {
    match record.resources.get("lifecycle_contract") {
        Some(SafeReference::File { path }) => Ok(path),
        _ => bail!("deployment has no executable lifecycle contract"),
    }
}

fn controller_step_pending(
    transaction: &crate::coordination::UpdateCoordination,
    step_id: &str,
) -> bool {
    transaction.steps.iter().any(|step| {
        step.id == step_id
            && step.owner == crate::coordination::StepOwner::CtlOwned
            && step.state == crate::coordination::StepState::Pending
    })
}

fn verify_active_runtime(
    runtime: &RuntimeLifecycle,
    expected_release: &nazo_operator_protocol::EmbeddedIdentity,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<()> {
    let expected_artifact = activated_artifact_reference(runtime, cached)?;
    let runtime_backend = backend(runtime.backend);
    let observation = runtime_backend.inspect(&runtime.object_reference)?;
    if !observation.running || !artifact_identity_matches(&observation.artifact, &expected_artifact)
    {
        bail!("runtime does not expose the expected active artifact identity");
    }
    let embedded = runtime_backend
        .read_build_identity(&expected_artifact)?
        .context("active runtime artifact exposes no embedded build identity")?;
    if embedded != *expected_release {
        bail!("active runtime artifact exposes a different Release identity");
    }
    Ok(())
}

fn load_cache(path: &Path, record: &DeploymentRecord) -> anyhow::Result<TrustedRuntimeCache> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect trusted runtime cache {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("trusted runtime cache manifest is not a regular file");
    }
    let cache: TrustedRuntimeCache =
        serde_json::from_slice(&fs::read(path)?).context("trusted runtime cache is invalid")?;
    if cache.schema != 1
        || cache.deployment_id != record.deployment_id
        || cache.release != record.active_release
        || cache.runtimes.len() != record.runtime_instances.len()
    {
        bail!("trusted runtime cache is bound to a different deployment or Release");
    }
    Ok(cache)
}

fn validate_cached_artifacts(cache: &TrustedRuntimeCache) -> anyhow::Result<()> {
    for artifact in cache.runtimes.values() {
        match artifact {
            CachedRuntimeArtifact::OciArchive {
                digest,
                archive,
                archive_sha256,
                ..
            } => {
                validate_oci_digest(digest)?;
                validate_lower_hex(archive_sha256)?;
                validate_regular_artifact(archive, "trusted OCI recovery archive")?;
                if sha256(archive)? != *archive_sha256 {
                    bail!("trusted OCI recovery archive digest is invalid");
                }
            }
            CachedRuntimeArtifact::HostBinary {
                binary,
                sha256: digest,
            } => {
                validate_lower_hex(digest)?;
                validate_regular_artifact(binary, "trusted host recovery binary")?;
                if sha256(binary)? != *digest {
                    bail!("trusted host recovery binary digest is invalid");
                }
            }
        }
    }
    Ok(())
}

fn trusted_runtime_directory(
    store: &DeploymentStore,
    deployment_id: &str,
    release: &str,
) -> anyhow::Result<PathBuf> {
    validate_file_identifier(release, "trusted runtime Release")?;
    Ok(store
        .deployment_state_dir(deployment_id)
        .join("recovery")
        .join("trusted-runtime")
        .join(release))
}

fn artifact_identity_matches(left: &ArtifactReference, right: &ArtifactReference) -> bool {
    match (left, right) {
        (
            ArtifactReference::Oci { digest: left, .. },
            ArtifactReference::Oci { digest: right, .. },
        ) => left == right,
        (
            ArtifactReference::HostBinary { sha256: left, .. },
            ArtifactReference::HostBinary { sha256: right, .. },
        ) => left == right,
        _ => false,
    }
}

fn activated_artifact_reference(
    runtime: &RuntimeLifecycle,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<ArtifactReference> {
    Ok(match cached {
        CachedRuntimeArtifact::OciArchive {
            image_reference,
            digest,
            ..
        } => ArtifactReference::Oci {
            image_reference: image_reference.clone(),
            digest: digest.clone(),
        },
        CachedRuntimeArtifact::HostBinary { sha256, .. } => ArtifactReference::HostBinary {
            path: PathBuf::from(
                runtime
                    .command
                    .first()
                    .context("systemd lifecycle command has no binary path")?,
            ),
            sha256: sha256.clone(),
        },
    })
}

fn recovery_slot_path(store: &DeploymentStore, deployment_id: &str) -> PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("recovery")
        .join("rollback-slot.json")
}

fn persist_recovery_slot(store: &DeploymentStore, slot: &RecoverySlot) -> anyhow::Result<()> {
    atomic_write(
        &recovery_slot_path(store, &slot.deployment_id),
        &serde_json::to_vec_pretty(slot)?,
        0o600,
    )
}

fn load_recovery_slot(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<RecoverySlot> {
    let path = recovery_slot_path(store, &record.deployment_id);
    let metadata = fs::symlink_metadata(&path)
        .context("deployment has no controller-independent recovery slot")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("deployment recovery slot is not a regular file");
    }
    let slot: RecoverySlot =
        serde_json::from_slice(&fs::read(&path)?).context("deployment recovery slot is invalid")?;
    if slot.schema != 1 || slot.deployment_id != record.deployment_id {
        bail!("deployment recovery slot is bound to a different deployment");
    }
    validate_file_identifier(&slot.trusted_release.release, "recovery slot Release")?;
    validate_lower_hex(&slot.recovery_manifest_sha256)?;
    validate_regular_artifact(&slot.recovery_manifest, "deployment recovery manifest")?;
    if sha256(&slot.recovery_manifest)? != slot.recovery_manifest_sha256 {
        bail!("deployment recovery manifest changed after slot commit");
    }
    Ok(slot)
}

fn persist_recovery_transaction(
    path: &Path,
    transaction: &RecoveryTransaction,
) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(transaction)?, 0o600)
}

fn validate_regular_artifact(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        bail!("{label} is not a non-empty regular file");
    }
    Ok(())
}

fn update_execution_path(store: &DeploymentStore, deployment_id: &str) -> PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("active-lifecycle-update.json")
}

fn persist_update_execution(path: &Path, execution: &UpdateExecution) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(execution)?, 0o600)
}

fn archive_update_execution(
    store: &DeploymentStore,
    deployment_id: &str,
    transaction_id: &str,
) -> anyhow::Result<()> {
    let active = update_execution_path(store, deployment_id);
    if !active.exists() {
        return Ok(());
    }
    let execution: UpdateExecution = serde_json::from_slice(&fs::read(&active)?)
        .context("lifecycle update execution journal is invalid")?;
    if execution.transaction_id != transaction_id
        || execution.state != UpdateExecutionState::Committed
    {
        bail!("lifecycle update execution cannot be archived before commit");
    }
    let history = active.with_file_name(format!("lifecycle-update-{transaction_id}.json"));
    atomic_write(&history, &serde_json::to_vec_pretty(&execution)?, 0o600)?;
    remove_file_durable(&active)
}

fn validate_oci_digest(value: &str) -> anyhow::Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("OCI recovery artifact has no sha256 digest")?;
    validate_lower_hex(digest)
}

impl RecoveryDriver {
    fn validate(&self, runtimes: &[RuntimeLifecycle]) -> anyhow::Result<()> {
        validate_absolute_path(&self.program, "recovery driver program")?;
        for runtime in runtimes {
            for mount in &runtime.mounts {
                if paths_overlap(&self.program, &mount.source) {
                    bail!("recovery driver program is inside the application failure domain");
                }
            }
        }
        let metadata = fs::symlink_metadata(&self.program).with_context(|| {
            format!(
                "failed to inspect recovery driver {}",
                self.program.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            bail!("recovery driver must be a non-empty regular file");
        }
        validate_lower_hex(&self.program_sha256)?;
        if sha256(&self.program)? != self.program_sha256 {
            bail!("recovery driver digest does not match the lifecycle contract");
        }
        if self.arguments.len() > MAX_ARGUMENTS {
            bail!("recovery driver has too many arguments");
        }
        for argument in &self.arguments {
            if argument.is_empty()
                || argument.len() > MAX_ARGUMENT_BYTES
                || argument.contains(['\0', '\r', '\n'])
            {
                bail!("recovery driver argument is invalid");
            }
        }
        validate_absolute_path(&self.rehearsal_workspace, "recovery rehearsal workspace")?;
        for runtime in runtimes {
            for mount in &runtime.mounts {
                if paths_overlap(&self.rehearsal_workspace, &mount.source) {
                    bail!("recovery rehearsal workspace overlaps an application mount");
                }
            }
        }
        for (name, reference) in &self.credentials {
            validate_file_identifier(name, "recovery credential name")?;
            match reference {
                CredentialReference::File { path } => {
                    validate_absolute_path(path, "recovery credential file")?;
                    if runtimes.iter().any(|runtime| {
                        runtime
                            .mounts
                            .iter()
                            .any(|mount| paths_overlap(path, &mount.source))
                    }) {
                        bail!("recovery credential is inside the application failure domain");
                    }
                    let metadata = fs::symlink_metadata(path).with_context(|| {
                        format!("failed to inspect recovery credential {}", path.display())
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        bail!("recovery credential reference must name a regular file");
                    }
                }
                CredentialReference::Provider { provider, key } => {
                    validate_file_identifier(provider, "recovery credential provider")?;
                    validate_file_identifier(key, "recovery credential key")?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn invoke_recovery_driver(
    lifecycle_path: &Path,
    lifecycle: &LifecycleManifest,
    recovery_manifest: &Path,
    release: &str,
    operation: RecoveryOperation,
    capabilities: &CapabilityGrants,
) -> anyhow::Result<RecoveryDriverReceipt> {
    lifecycle.validate()?;
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let recovery_manifest_sha256 = sha256(recovery_manifest)?;
    let request_id = uuid::Uuid::now_v7().to_string();
    let request = RecoveryDriverRequest {
        schema: RECOVERY_DRIVER_SCHEMA,
        request_id: request_id.clone(),
        deployment_id: &lifecycle.deployment_id,
        release,
        operation,
        lifecycle_sha256: &lifecycle_sha256,
        recovery_manifest,
        recovery_manifest_sha256: &recovery_manifest_sha256,
        rehearsal_workspace: (operation == RecoveryOperation::Rehearse)
            .then_some(lifecycle.recovery_driver.rehearsal_workspace.as_path()),
        credentials: &lifecycle.recovery_driver.credentials,
    };
    let request = serde_json::to_vec(&request)?;
    if request.len() > MAX_LIFECYCLE_BYTES as usize {
        bail!("recovery driver request exceeds the protocol limit");
    }
    if sha256(&lifecycle.recovery_driver.program)? != lifecycle.recovery_driver.program_sha256 {
        bail!("recovery driver changed after lifecycle validation");
    }
    let output = Process::new(lifecycle.recovery_driver.program.as_os_str())
        .args(
            lifecycle
                .recovery_driver
                .arguments
                .iter()
                .map(String::as_str),
        )
        .env(
            "NAZOAUTHCTL_RECOVERY_OPERATION",
            match operation {
                RecoveryOperation::Rehearse => "rehearse",
                RecoveryOperation::Checkpoint => "checkpoint",
                RecoveryOperation::Restore => "restore",
            },
        )
        .stdin_stdout(&request)?;
    if output.len() > MAX_DRIVER_OUTPUT_BYTES {
        bail!("recovery driver receipt exceeds the protocol limit");
    }
    let receipt: RecoveryDriverReceipt =
        serde_json::from_str(&output).context("recovery driver returned an invalid receipt")?;
    if operation != RecoveryOperation::Checkpoint
        && sha256(recovery_manifest)? != recovery_manifest_sha256
    {
        bail!("recovery driver changed immutable recovery evidence during validation or restore");
    }
    validate_receipt(
        &receipt,
        &request_id,
        lifecycle,
        release,
        operation,
        &lifecycle_sha256,
        &recovery_manifest_sha256,
        capabilities,
    )?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt(
    receipt: &RecoveryDriverReceipt,
    request_id: &str,
    lifecycle: &LifecycleManifest,
    release: &str,
    operation: RecoveryOperation,
    lifecycle_sha256: &str,
    recovery_manifest_sha256: &str,
    capabilities: &CapabilityGrants,
) -> anyhow::Result<()> {
    if receipt.schema != RECOVERY_DRIVER_SCHEMA
        || receipt.request_id != request_id
        || receipt.deployment_id != lifecycle.deployment_id
        || receipt.release != release
        || receipt.operation != operation
        || receipt.lifecycle_sha256 != lifecycle_sha256
        || receipt.recovery_manifest_sha256 != recovery_manifest_sha256
        || receipt.status != RecoveryStatus::Succeeded
    {
        bail!("recovery driver receipt is not bound to the requested operation");
    }
    if receipt.issued_at <= 0 || (Utc::now().timestamp() - receipt.issued_at).abs() > 300 {
        bail!("recovery driver receipt is outside its freshness window");
    }
    match operation {
        RecoveryOperation::Checkpoint => {
            let path = receipt
                .checkpoint_manifest
                .as_deref()
                .context("recovery checkpoint receipt has no recovery manifest")?;
            let expected = receipt
                .checkpoint_manifest_sha256
                .as_deref()
                .context("recovery checkpoint receipt has no manifest digest")?;
            validate_absolute_path(path, "recovery checkpoint manifest")?;
            validate_lower_hex(expected)?;
            let metadata = fs::symlink_metadata(path)
                .context("failed to inspect recovery checkpoint manifest")?;
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                bail!("recovery checkpoint manifest must be a non-empty regular file");
            }
            if sha256(path)? != expected {
                bail!("recovery checkpoint manifest digest does not match its receipt");
            }
        }
        RecoveryOperation::Rehearse | RecoveryOperation::Restore => {
            if receipt.checkpoint_manifest.is_some() || receipt.checkpoint_manifest_sha256.is_some()
            {
                bail!("non-checkpoint recovery receipt contains a checkpoint output");
            }
        }
    }
    let required = required_components(capabilities);
    if !required.is_subset(&receipt.components)
        || receipt
            .components
            .iter()
            .any(|component| !allowed_components().contains(component.as_str()))
    {
        bail!("recovery driver receipt does not prove every authorized recovery component");
    }
    Ok(())
}

fn required_components(capabilities: &CapabilityGrants) -> BTreeSet<String> {
    let mut required = BTreeSet::from(["artifact".to_owned(), "verification".to_owned()]);
    for (capability, component) in [
        (Capability::ServerConfig, "data"),
        (Capability::Database, "database"),
        (Capability::Valkey, "valkey"),
    ] {
        if capabilities
            .grant(capability)
            .responsibility
            .permits_mutation()
        {
            required.insert(component.to_owned());
        }
    }
    required
}

fn allowed_components() -> BTreeSet<&'static str> {
    BTreeSet::from(["artifact", "data", "database", "valkey", "verification"])
}

fn validate_server_command(command: &[String]) -> anyhow::Result<()> {
    if command.is_empty() || command.len() > MAX_ARGUMENTS {
        bail!("runtime lifecycle command is empty or too large");
    }
    for argument in command {
        if argument.is_empty()
            || argument.len() > MAX_ARGUMENT_BYTES
            || argument.contains(['\0', '\r', '\n'])
        {
            bail!("runtime lifecycle command contains an invalid argument");
        }
    }
    let executable = Path::new(&command[0]);
    if !executable
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "nazoauth" | "nazoauth.exe"))
        || command.get(1).map(String::as_str) != Some("server")
    {
        bail!("runtime lifecycle command is not nazoauth server");
    }
    Ok(())
}

fn validate_environment(
    backend: RuntimeBackendKind,
    environment: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    const ALLOWED: &[&str] = &[
        "CONFIG_PATH",
        "DATABASE_URL_FILE",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "INSTANCE_IDENTITY_DIR",
        "ISSUER",
        "PROFILE_SECRET_ROOT",
        "PUBLIC_BASE_URL",
        "RUNTIME_INSTANCE_ID",
        "VALKEY_URL_FILE",
    ];
    if environment.len() > 64 {
        bail!("runtime lifecycle environment exceeds the policy limit");
    }
    for (name, value) in environment {
        if !ALLOWED.contains(&name.as_str())
            || value.is_empty()
            || value.len() > MAX_ARGUMENT_BYTES
            || value.contains(['\0', '\r', '\n'])
        {
            bail!("runtime lifecycle environment contains an unsafe entry");
        }
        if name.ends_with("_FILE") && !runtime_path_is_absolute(backend, Path::new(value)) {
            bail!("runtime secret file reference must be absolute");
        }
    }
    Ok(())
}

fn runtime_path_is_absolute(backend: RuntimeBackendKind, path: &Path) -> bool {
    match backend {
        RuntimeBackendKind::Docker | RuntimeBackendKind::Podman => path
            .to_str()
            .is_some_and(|value| value.starts_with('/') && !value.starts_with("//")),
        RuntimeBackendKind::Systemd => path.is_absolute(),
    }
}

fn validate_absolute_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || path.parent().is_none()
    {
        bail!("{label} must be a normalized absolute non-root path");
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_file_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .with_context(|| format!("invalid {label}"))
}

fn validate_boundary(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_ARGUMENT_BYTES
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+,-=[]".contains(character))
    {
        bail!("{label} contains unsafe characters");
    }
    Ok(())
}

fn validate_lower_hex(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("digest must contain 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
