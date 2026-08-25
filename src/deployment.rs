use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::filesystem::{open_lock_file, read_secure_regular_file};

pub(crate) const REGISTRY_SCHEMA: u32 = 1;
pub(crate) const DEPLOYMENT_SCHEMA: u32 = 1;
const REGISTRY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DEPLOYMENT_DECLARATION_MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TrustState {
    Observed,
    Adopted,
}

pub(crate) use nazoauthctl_runtime::{
    ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind, RuntimeInstance,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Capability {
    Runtime,
    Artifact,
    ServerConfig,
    Database,
    Valkey,
    OperatorTasks,
    Backups,
    ProxyTls,
}

impl Capability {
    pub(crate) const ALL: [Self; 8] = [
        Self::Runtime,
        Self::Artifact,
        Self::ServerConfig,
        Self::Database,
        Self::Valkey,
        Self::OperatorTasks,
        Self::Backups,
        Self::ProxyTls,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Artifact => "artifact",
            Self::ServerConfig => "server_config",
            Self::Database => "database",
            Self::Valkey => "valkey",
            Self::OperatorTasks => "operator_tasks",
            Self::Backups => "backups",
            Self::ProxyTls => "proxy_tls",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityGrant {
    pub(crate) responsibility: Responsibility,
    pub(crate) scope: ResourceScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityGrants {
    pub(crate) runtime: CapabilityGrant,
    pub(crate) artifact: CapabilityGrant,
    pub(crate) server_config: CapabilityGrant,
    pub(crate) database: CapabilityGrant,
    pub(crate) valkey: CapabilityGrant,
    pub(crate) operator_tasks: CapabilityGrant,
    pub(crate) backups: CapabilityGrant,
    pub(crate) proxy_tls: CapabilityGrant,
}

impl CapabilityGrants {
    /// Test-only fixture: the canonical controller-installed grant set.
    #[cfg(test)]
    pub(crate) fn controller_installed() -> Self {
        let managed = || CapabilityGrant {
            responsibility: Responsibility::Managed,
            scope: ResourceScope::Deployment,
        };
        Self {
            runtime: managed(),
            artifact: managed(),
            server_config: managed(),
            database: managed(),
            valkey: managed(),
            operator_tasks: managed(),
            backups: managed(),
            proxy_tls: CapabilityGrant {
                responsibility: Responsibility::External,
                scope: ResourceScope::Shared,
            },
        }
    }

    pub(crate) fn grant(&self, capability: Capability) -> &CapabilityGrant {
        match capability {
            Capability::Runtime => &self.runtime,
            Capability::Artifact => &self.artifact,
            Capability::ServerConfig => &self.server_config,
            Capability::Database => &self.database,
            Capability::Valkey => &self.valkey,
            Capability::OperatorTasks => &self.operator_tasks,
            Capability::Backups => &self.backups,
            Capability::ProxyTls => &self.proxy_tls,
        }
    }

    /// Validate the capability lattice at every persistence boundary.
    ///
    /// A shared resource may be delegated or left external, but it cannot be
    /// declared controller-managed: the controller has no exclusive ownership
    /// or deletion proof for a resource shared with another deployment.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        for capability in Capability::ALL {
            let grant = self.grant(capability);
            if grant.scope == ResourceScope::Shared
                && grant.responsibility == Responsibility::Managed
            {
                bail!(
                    "capability {} cannot be managed when its resource scope is shared",
                    capability.name()
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SafeReference {
    File {
        path: PathBuf,
    },
    DigestBoundFile {
        path: PathBuf,
        sha256: String,
    },
    Provider {
        provider: String,
        key: String,
    },
    RuntimeObject {
        backend: RuntimeBackendKind,
        object_reference: String,
    },
    NotObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecoveryConclusion {
    Proven,
    RequiresUserEvidence,
    Unproven,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryAssessment {
    pub(crate) conclusion: RecoveryConclusion,
    pub(crate) evidence: Vec<String>,
    pub(crate) off_host_package_required_for_machine_loss: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeploymentRecord {
    pub(crate) schema: u32,
    pub(crate) deployment_id: String,
    pub(crate) control_authority: String,
    pub(crate) alias: Option<String>,
    pub(crate) issuer: String,
    pub(crate) active_release: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) trust: TrustState,
    pub(crate) capabilities: CapabilityGrants,
    pub(crate) runtime_instances: Vec<RuntimeInstance>,
    pub(crate) resources: BTreeMap<String, SafeReference>,
    pub(crate) recovery: RecoveryAssessment,
    pub(crate) operator_protocol_versions: BTreeSet<u32>,
    pub(crate) control_protocol_versions: BTreeSet<u32>,
    pub(crate) declaration_revision: u64,
}

impl DeploymentRecord {
    pub(crate) fn require_mutation(&self, capabilities: &[Capability]) -> anyhow::Result<()> {
        if self.trust != TrustState::Adopted {
            bail!("deployment is observed, not adopted; mutation is forbidden");
        }
        let denied = capabilities
            .iter()
            .copied()
            .filter(|capability| {
                !self
                    .capabilities
                    .grant(*capability)
                    .responsibility
                    .permits_mutation()
            })
            .map(Capability::name)
            .collect::<Vec<_>>();
        if !denied.is_empty() {
            bail!(
                "operation exceeds granted deployment capabilities: {}",
                denied.join(", ")
            );
        }
        Ok(())
    }

    pub(crate) fn core_recovery_is_proven(&self) -> bool {
        self.trust == TrustState::Adopted
            && self.recovery.conclusion == RecoveryConclusion::Proven
            && (matches!(
                self.resources.get("controller_config"),
                Some(SafeReference::File { .. })
            ) || matches!(
                self.resources.get("lifecycle_contract"),
                Some(SafeReference::DigestBoundFile { .. })
            ))
            && self.capabilities.runtime.responsibility.permits_mutation()
            && self.capabilities.artifact.responsibility.permits_mutation()
            && self.capabilities.backups.responsibility.permits_mutation()
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != DEPLOYMENT_SCHEMA {
            bail!("unsupported deployment declaration schema");
        }
        self.capabilities.validate()?;
        validate_identifier(&self.deployment_id, "deployment ID")?;
        validate_identifier(&self.control_authority, "control authority")?;
        if let Some(alias) = &self.alias {
            validate_identifier(alias, "deployment alias")?;
        }
        if self.issuer.is_empty()
            || self.active_release.release.is_empty()
            || self.active_release.revision.is_empty()
            || self.active_release.build_id.is_empty()
            || self.active_release.protocol == 0
            || self.runtime_instances.is_empty()
        {
            bail!("deployment declaration is incomplete");
        }
        for reference in self.resources.values() {
            if let SafeReference::DigestBoundFile { sha256, .. } = reference
                && (sha256.len() != 64
                    || !sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
            {
                bail!("digest-bound resource has an invalid SHA-256 digest");
            }
        }
        let mut runtime_ids = BTreeSet::new();
        for runtime in &self.runtime_instances {
            validate_identifier(&runtime.runtime_instance_id, "runtime instance ID")?;
            if !runtime_ids.insert(&runtime.runtime_instance_id) {
                bail!("duplicate runtime instance ID in deployment declaration");
            }
            if runtime.object_reference.is_empty() {
                bail!("runtime object reference is empty");
            }
            if let Some(local_id) = &runtime.local_artifact_id {
                let Some(digest) = local_id.strip_prefix("sha256:") else {
                    bail!("runtime local artifact identity is invalid");
                };
                if digest.len() != 64
                    || !digest
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
                {
                    bail!("runtime local artifact identity is invalid");
                }
            }
        }
        if self.trust == TrustState::Observed
            && Capability::ALL.iter().any(|capability| {
                self.capabilities
                    .grant(*capability)
                    .responsibility
                    .permits_mutation()
            })
        {
            bail!("observed deployment cannot carry mutation capabilities");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    pub(crate) schema: u32,
    pub(crate) deployments: BTreeMap<String, RegistryEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryEntry {
    pub(crate) alias: Option<String>,
    pub(crate) declaration: PathBuf,
}

pub(crate) struct DeploymentStore {
    pub(crate) config_root: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) break_glass_root: PathBuf,
}

impl DeploymentStore {
    pub(crate) fn system() -> Self {
        let (config_default, state_default, break_glass_default) = if cfg!(windows) {
            (
                r"C:\ProgramData\NazoAuthCtl\config",
                r"C:\ProgramData\NazoAuthCtl\state",
                r"C:\ProgramData\NazoAuthCtl-BreakGlass",
            )
        } else if cfg!(target_os = "macos") {
            (
                "/private/etc/nazoauthctl",
                "/private/var/lib/nazoauthctl",
                "/private/var/lib/nazoauthctl-break-glass",
            )
        } else {
            (
                "/etc/nazoauthctl",
                "/var/lib/nazoauthctl",
                "/var/lib/nazoauthctl-break-glass",
            )
        };
        Self {
            config_root: root_from_env("NAZOAUTHCTL_CONFIG_ROOT", config_default),
            state_root: root_from_env("NAZOAUTHCTL_STATE_ROOT", state_default),
            break_glass_root: root_from_env("NAZOAUTHCTL_BREAK_GLASS_ROOT", break_glass_default),
        }
    }

    pub(crate) fn registry_path(&self) -> PathBuf {
        self.config_root.join("registry.json")
    }

    /// Return whether the registration registry exists without following a
    /// link.  Callers use this only to choose the registered/legacy command
    /// boundary; the subsequent load still validates the same descriptor.
    pub(crate) fn registry_present(&self) -> anyhow::Result<bool> {
        self.validate_failure_domains()?;
        if self.registration_pending()? {
            bail!("deployment registration transaction is pending; rerun install to reconcile it");
        }
        let path = self.registry_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => bail!(
                "deployment registry must be a regular non-symlink file: {}",
                path.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if self.registered_artifacts_present()? {
                    bail!(
                        "deployment registry is missing while registered deployment artifacts remain; restore or reconcile the registry before using legacy commands"
                    );
                }
                Ok(false)
            }
            Err(error) => Err(error).with_context(|| {
                format!("failed to inspect deployment registry {}", path.display())
            }),
        }
    }

    fn registered_artifacts_present(&self) -> anyhow::Result<bool> {
        for directory in [
            self.config_root.join("deployments"),
            self.state_root.join("deployments"),
            self.break_glass_root.join("deployments"),
        ] {
            let metadata = match fs::symlink_metadata(&directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to inspect {}", directory.display()));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "registered deployment artifact root must be a real directory: {}",
                    directory.display()
                );
            }
            if fs::read_dir(&directory)?.next().transpose()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn registration_pending(&self) -> anyhow::Result<bool> {
        self.registration_pending_except(None)
    }

    /// Check registration journals while permitting one caller-owned
    /// deployment journal to be reconciled under the registry/deployment
    /// locks.  All other journals remain a global unsettled-state guard.
    pub(crate) fn registration_pending_except(
        &self,
        permitted_deployment_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        let directory = self.state_root.join("transactions");
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", directory.display()));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("controller transaction directory is not a real directory");
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("registration-") && name.ends_with(".json") {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!("registration journal must be a regular non-symlink file");
                }
                if permitted_deployment_id.is_some_and(|deployment_id| {
                    name == format!("registration-{deployment_id}.json")
                }) {
                    continue;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn validate_failure_domains(&self) -> anyhow::Result<()> {
        for (label, path) in [
            ("controller configuration root", &self.config_root),
            ("controller state root", &self.state_root),
            ("break-glass root", &self.break_glass_root),
        ] {
            validate_storage_root(path, label, label == "break-glass root")?;
        }
        let config_identity = storage_identity(&self.config_root)?;
        let state_identity = storage_identity(&self.state_root)?;
        let break_glass_identity = storage_identity(&self.break_glass_root)?;
        if paths_overlap(&break_glass_identity, &state_identity)
            || paths_overlap(&state_identity, &config_identity)
            || paths_overlap(&break_glass_identity, &config_identity)
        {
            bail!("controller configuration, state, and break-glass roots must not overlap");
        }
        validate_independent_recovery_device(
            &self.break_glass_root,
            &[
                ("controller configuration root", &self.config_root),
                ("controller state root", &self.state_root),
            ],
            "break-glass root",
        )?;
        Ok(())
    }

    /// Create the three controller roots only after validating every existing
    /// path component.  The second validation closes the common create-time
    /// symlink substitution window and makes all later atomic writes/locks
    /// inherit a trusted parent chain.
    fn ensure_storage_roots(&self) -> anyhow::Result<()> {
        self.validate_failure_domains()?;
        for (label, path, private) in [
            ("controller configuration root", &self.config_root, false),
            ("controller state root", &self.state_root, false),
            ("break-glass root", &self.break_glass_root, true),
        ] {
            if matches!(fs::symlink_metadata(path), Err(error) if error.kind() == ErrorKind::NotFound)
            {
                crate::filesystem::ensure_directory_chain(path)
                    .with_context(|| format!("failed to create {label} {}", path.display()))?;
                crate::filesystem::set_mode(path, 0o700)?;
            }
            validate_storage_root(path, label, private)?;
        }
        let transactions = self.state_root.join("transactions");
        if !path_present(&transactions)? {
            crate::filesystem::ensure_directory_chain(&transactions)
                .with_context(|| format!("failed to create {}", transactions.display()))?;
            crate::filesystem::set_mode(&transactions, 0o700)?;
        }
        ensure_real_directory(&transactions, "controller transaction directory")?;
        self.validate_failure_domains()
    }

    pub(crate) fn declaration_path(&self, deployment_id: &str) -> PathBuf {
        self.config_root
            .join("deployments")
            .join(deployment_id)
            .join("deployment.json")
    }

    pub(crate) fn deployment_state_dir(&self, deployment_id: &str) -> PathBuf {
        self.state_root.join("deployments").join(deployment_id)
    }

    pub(crate) fn load_registry(&self) -> anyhow::Result<Registry> {
        self.validate_failure_domains()?;
        let path = self.registry_path();
        let bytes = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!(
                        "registry must be a regular non-symlink file: {}",
                        path.display()
                    );
                }
                read_secure_regular_file(&path, "deployment registry", false, REGISTRY_MAX_BYTES)?
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Registry {
                    schema: REGISTRY_SCHEMA,
                    deployments: BTreeMap::new(),
                });
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        };
        let registry: Registry = serde_json::from_slice(&bytes).context("registry is invalid")?;
        if registry.schema != REGISTRY_SCHEMA {
            bail!("unsupported registry schema");
        }
        Ok(registry)
    }

    pub(crate) fn load(&self, deployment_id: &str) -> anyhow::Result<DeploymentRecord> {
        self.validate_failure_domains()?;
        validate_identifier(deployment_id, "deployment ID")?;
        let path = self.declaration_path(deployment_id);
        let bytes = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!(
                        "deployment declaration must be a regular non-symlink file: {}",
                        path.display()
                    );
                }
                read_secure_regular_file(
                    &path,
                    "deployment declaration",
                    false,
                    DEPLOYMENT_DECLARATION_MAX_BYTES,
                )?
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                bail!("failed to read {}", path.display());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        };
        let record: DeploymentRecord =
            serde_json::from_slice(&bytes).context("deployment declaration is invalid")?;
        record.validate()?;
        if record.deployment_id != deployment_id {
            bail!("deployment declaration ID does not match its registry key");
        }
        Ok(record)
    }

    pub(crate) fn resolve(
        &self,
        selector: Option<&str>,
        destructive: bool,
    ) -> anyhow::Result<DeploymentRecord> {
        let registry = self.load_registry()?;
        let deployment_id = match selector {
            Some(selector) => {
                if registry.deployments.contains_key(selector) {
                    selector.to_owned()
                } else {
                    let matches = registry
                        .deployments
                        .iter()
                        .filter(|(_, entry)| entry.alias.as_deref() == Some(selector))
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>();
                    match matches.as_slice() {
                        [deployment_id] => deployment_id.clone(),
                        [] => bail!("deployment selector does not match a registered deployment"),
                        _ => bail!("deployment alias is ambiguous"),
                    }
                }
            }
            None if registry.deployments.len() == 1 => registry
                .deployments
                .keys()
                .next()
                .cloned()
                .context("registry became empty")?,
            None if registry.deployments.is_empty() => bail!("no deployments are registered"),
            None => {
                let candidates = registry.deployments.keys().cloned().collect::<Vec<_>>();
                let command = if destructive {
                    "destructive command"
                } else {
                    "command"
                };
                bail!(
                    "{command} requires --deployment because multiple deployments exist: {}",
                    candidates.join(", ")
                )
            }
        };
        self.load(&deployment_id)
    }

    /// Reload a declaration after its deployment lock has been acquired and
    /// reject a caller that still holds an older snapshot.  This is intentionally
    /// a separate operation from `load`: callers must establish the lock before
    /// invoking it.
    pub(crate) fn reload_locked(
        &self,
        expected: &DeploymentRecord,
    ) -> anyhow::Result<DeploymentRecord> {
        let current = self.load(&expected.deployment_id)?;
        if current != *expected {
            bail!("deployment declaration changed while the operation was being prepared");
        }
        Ok(current)
    }

    pub(crate) fn deployment_lock(&self, deployment_id: &str) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        validate_identifier(deployment_id, "deployment ID")?;
        FileLock::acquire(
            &self
                .state_root
                .join("locks")
                .join(format!("deployment-{deployment_id}.lock")),
        )
    }

    /// Hold a stable deployment snapshot while a lease-scoped operation runs.
    /// Multiple conformance sessions may share this lock; every deployment
    /// mutation continues to take the exclusive `deployment_lock` above.
    pub(crate) fn deployment_shared_lock(&self, deployment_id: &str) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        validate_identifier(deployment_id, "deployment ID")?;
        FileLock::acquire_shared(
            &self
                .state_root
                .join("locks")
                .join(format!("deployment-{deployment_id}.lock")),
        )
    }

    pub(crate) fn shared_resource_lock(&self, resource_id: &str) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        validate_identifier(resource_id, "shared resource ID")?;
        FileLock::acquire(
            &self
                .state_root
                .join("locks")
                .join(format!("shared-{resource_id}.lock")),
        )
    }

    pub(crate) fn shared_resource_shared_lock(
        &self,
        resource_id: &str,
    ) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        validate_identifier(resource_id, "shared resource ID")?;
        FileLock::acquire_shared(
            &self
                .state_root
                .join("locks")
                .join(format!("shared-{resource_id}.lock")),
        )
    }

    /// Acquire deterministic operational locks for capabilities whose backing
    /// resource is shared with another deployment.  The capability name is the
    /// stable lock identity because declarations intentionally carry provider
    /// references, not a controller-owned resource locator.
    pub(crate) fn shared_capability_locks(
        &self,
        record: &DeploymentRecord,
        capabilities: &[Capability],
    ) -> anyhow::Result<Vec<FileLock>> {
        let mut shared = capabilities
            .iter()
            .copied()
            .filter(|capability| {
                record.capabilities.grant(*capability).scope == ResourceScope::Shared
            })
            .map(Capability::name)
            .collect::<Vec<_>>();
        shared.sort_unstable();
        shared.dedup();
        shared
            .into_iter()
            .map(|capability| self.shared_resource_lock(capability))
            .collect()
    }

    pub(crate) fn shared_capability_shared_locks(
        &self,
        record: &DeploymentRecord,
        capabilities: &[Capability],
    ) -> anyhow::Result<Vec<FileLock>> {
        let mut shared = capabilities
            .iter()
            .copied()
            .filter(|capability| {
                record.capabilities.grant(*capability).scope == ResourceScope::Shared
            })
            .map(Capability::name)
            .collect::<Vec<_>>();
        shared.sort_unstable();
        shared.dedup();
        shared
            .into_iter()
            .map(|capability| self.shared_resource_shared_lock(capability))
            .collect()
    }

    pub(crate) fn controller_self_lock(&self) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        FileLock::acquire(&self.state_root.join("locks").join("controller-self.lock"))
    }
}

fn validate_storage_root(path: &Path, label: &str, break_glass: bool) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("{label} must be a normalized absolute non-root path");
    }

    // Inspect every existing component, including the nearest existing
    // ancestor when the configured root has not yet been created.  A normal
    // metadata/stat call follows symlinks; symlink_metadata is deliberate so
    // a link cannot silently redirect controller state or lock files.
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!(
                        "{label} contains a symlink component: {}",
                        candidate.display()
                    );
                }
                if !metadata.is_dir() {
                    bail!(
                        "{label} component is not a directory: {}",
                        candidate.display()
                    );
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {label} {}", candidate.display()));
            }
        }
        current = candidate.parent();
    }

    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_storage_directory_metadata(&metadata, path, label, break_glass)?;
    }
    Ok(())
}

fn validate_storage_directory_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
    break_glass: bool,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            bail!("{label} is group/world writable: {}", path.display());
        }
        if break_glass && mode & 0o077 != 0 {
            bail!("{label} must be owner-only: {}", path.display());
        }
        if let Some(uid) = effective_uid()
            && metadata.uid() != uid
        {
            bail!(
                "{label} is not owned by the controller user: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, path, label, break_glass);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Option<u32> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("Uid:")?.split_whitespace().nth(1)?;
                value.parse().ok()
            })
        })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn effective_uid() -> Option<u32> {
    None
}

fn storage_identity(path: &Path) -> anyhow::Result<PathBuf> {
    let mut existing = path;
    while matches!(
        fs::symlink_metadata(existing),
        Err(error) if error.kind() == ErrorKind::NotFound
    ) {
        existing = existing
            .parent()
            .context("storage root has no existing ancestor")?;
    }
    let canonical = fs::canonicalize(existing).with_context(|| {
        format!(
            "failed to canonicalize storage ancestor {}",
            existing.display()
        )
    })?;
    let suffix = path
        .strip_prefix(existing)
        .context("storage root is not below its existing ancestor")?;
    Ok(canonical.join(suffix))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn ensure_real_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => bail!("{label} is not a real directory: {}", path.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

#[cfg(all(not(test), unix))]
pub(crate) fn validate_independent_recovery_device(
    recovery: &Path,
    primary_roots: &[(&str, &Path)],
    recovery_label: &str,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(recovery).with_context(|| {
        format!(
            "{recovery_label} must be a pre-provisioned mounted failure domain: {}",
            recovery.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{recovery_label} must be a real pre-provisioned directory");
    }
    let recovery_device = metadata.dev();
    for (label, path) in primary_roots {
        let existing = nearest_existing_ancestor(path)?;
        if fs::symlink_metadata(existing)?.dev() == recovery_device {
            bail!("{recovery_label} must be mounted on a different filesystem device from {label}");
        }
    }
    Ok(())
}

#[cfg(all(not(test), windows))]
pub(crate) fn validate_independent_recovery_device(
    recovery: &Path,
    primary_roots: &[(&str, &Path)],
    recovery_label: &str,
) -> anyhow::Result<()> {
    use std::path::Component;

    if !recovery.is_dir() {
        bail!("{recovery_label} must be a pre-provisioned mounted failure domain");
    }
    let volume = |path: &Path| -> anyhow::Result<std::ffi::OsString> {
        let existing = nearest_existing_ancestor(path)?;
        match existing.components().next() {
            Some(Component::Prefix(prefix)) => Ok(prefix.as_os_str().to_owned()),
            _ => bail!("storage root has no provable Windows volume boundary"),
        }
    };
    let recovery_volume = volume(recovery)?;
    for (label, path) in primary_roots {
        if volume(path)? == recovery_volume {
            bail!("{recovery_label} must use a different Windows volume from {label}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_independent_recovery_device(
    _: &Path,
    _: &[(&str, &Path)],
    _: &str,
) -> anyhow::Result<()> {
    // Unit-test temporary directories necessarily share one device. Production
    // binaries compile the platform-specific proof above; overlap and symlink
    // semantics remain covered in unit tests.
    Ok(())
}

#[cfg(all(not(test), not(any(unix, windows))))]
pub(crate) fn validate_independent_recovery_device(
    _: &Path,
    _: &[(&str, &Path)],
    recovery_label: &str,
) -> anyhow::Result<()> {
    bail!("this platform cannot prove an independent {recovery_label} storage device")
}

#[cfg(not(test))]
fn nearest_existing_ancestor(mut path: &Path) -> anyhow::Result<&Path> {
    loop {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(path),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                path = path
                    .parent()
                    .context("storage root has no existing ancestor")?;
            }
            Err(error) => return Err(error).context("failed to inspect storage ancestor"),
        }
    }
}

pub(crate) struct FileLock {
    file: File,
}

impl FileLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let file = open_lock_file(path, false, "deployment lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }

    fn acquire_shared(path: &Path) -> anyhow::Result<Self> {
        let file = open_lock_file(path, false, "deployment lock")?;
        file.try_lock_shared()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn root_from_env(key: &str, default: &str) -> PathBuf {
    env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .with_context(|| format!("invalid {label}"))
}
