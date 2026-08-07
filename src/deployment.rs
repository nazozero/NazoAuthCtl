use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::filesystem::{atomic_write, read_regular_file};

pub(crate) const REGISTRY_SCHEMA: u32 = 1;
pub(crate) const DEPLOYMENT_SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TrustState {
    Observed,
    Adopted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Responsibility {
    External,
    Delegated,
    Managed,
}

impl Responsibility {
    pub(crate) fn permits_mutation(self) -> bool {
        matches!(self, Self::Delegated | Self::Managed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResourceScope {
    Deployment,
    Shared,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RuntimeBackendKind {
    Podman,
    Docker,
    #[serde(alias = "host")]
    Systemd,
}

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
    pub(crate) fn observed() -> Self {
        let external = || CapabilityGrant {
            responsibility: Responsibility::External,
            scope: ResourceScope::Deployment,
        };
        Self {
            runtime: external(),
            artifact: external(),
            server_config: external(),
            database: external(),
            valkey: external(),
            operator_tasks: external(),
            backups: external(),
            proxy_tls: external(),
        }
    }

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

    pub(crate) fn grant_mut(&mut self, capability: Capability) -> &mut CapabilityGrant {
        match capability {
            Capability::Runtime => &mut self.runtime,
            Capability::Artifact => &mut self.artifact,
            Capability::ServerConfig => &mut self.server_config,
            Capability::Database => &mut self.database,
            Capability::Valkey => &mut self.valkey,
            Capability::OperatorTasks => &mut self.operator_tasks,
            Capability::Backups => &mut self.backups,
            Capability::ProxyTls => &mut self.proxy_tls,
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
pub(crate) enum ArtifactReference {
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
pub(crate) struct RuntimeInstance {
    pub(crate) runtime_instance_id: String,
    pub(crate) backend: RuntimeBackendKind,
    pub(crate) object_reference: String,
    pub(crate) artifact: ArtifactReference,
    #[serde(default)]
    pub(crate) local_artifact_id: Option<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) networks: Vec<String>,
    pub(crate) mounts: Vec<MountReference>,
    pub(crate) instance_key_id: Option<String>,
    pub(crate) deployment_statement: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MountReference {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) read_only: bool,
    pub(crate) selinux_relabel: bool,
    pub(crate) scope: ResourceScope,
    pub(crate) ownership: Responsibility,
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
            bail!("break-glass material must use a separate storage failure domain");
        }
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
                fs::create_dir_all(path)
                    .with_context(|| format!("failed to create {label} {}", path.display()))?;
                crate::filesystem::set_mode(path, 0o700)?;
            }
            validate_storage_root(path, label, private)?;
        }
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

    pub(crate) fn break_glass_dir(&self, deployment_id: &str) -> PathBuf {
        self.break_glass_root
            .join("deployments")
            .join(deployment_id)
    }

    pub(crate) fn load_registry(&self) -> anyhow::Result<Registry> {
        self.validate_failure_domains()?;
        let path = self.registry_path();
        let Some(bytes) = read_regular_file(&path)? else {
            return Ok(Registry {
                schema: REGISTRY_SCHEMA,
                deployments: BTreeMap::new(),
            });
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
        let bytes = read_regular_file(&path)?
            .with_context(|| format!("failed to read {}", path.display()))?;
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

    pub(crate) fn persist(&self, record: &DeploymentRecord) -> anyhow::Result<()> {
        self.ensure_storage_roots()?;
        record.validate()?;
        let _registry_lock = self.registry_lock()?;
        let _deployment_lock = self.deployment_lock(&record.deployment_id)?;
        self.persist_locked(record)
    }

    pub(crate) fn persist_locked(&self, record: &DeploymentRecord) -> anyhow::Result<()> {
        self.ensure_storage_roots()?;
        record.validate()?;
        let mut registry = self.load_registry()?;
        if registry.deployments.iter().any(|(id, entry)| {
            id != &record.deployment_id && record.alias.is_some() && entry.alias == record.alias
        }) {
            bail!("deployment alias is already registered");
        }
        let declaration = self.declaration_path(&record.deployment_id);
        atomic_write(&declaration, &serde_json::to_vec_pretty(record)?, 0o640)?;
        registry.deployments.insert(
            record.deployment_id.clone(),
            RegistryEntry {
                alias: record.alias.clone(),
                declaration,
            },
        );
        atomic_write(
            &self.registry_path(),
            &serde_json::to_vec_pretty(&registry)?,
            0o640,
        )?;
        for directory in ["identities", "audit", "transactions", "recovery"] {
            fs::create_dir_all(
                self.deployment_state_dir(&record.deployment_id)
                    .join(directory),
            )?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn persist_declaration_locked(
        &self,
        record: &DeploymentRecord,
    ) -> anyhow::Result<()> {
        record.validate()?;
        let current = self.load(&record.deployment_id)?;
        let expected_revision = current
            .declaration_revision
            .checked_add(1)
            .context("deployment declaration revision overflow")?;
        if record.declaration_revision != expected_revision {
            bail!(
                "deployment declaration revision is stale; expected {}, got {}",
                expected_revision,
                record.declaration_revision
            );
        }
        self.persist_declaration_file_locked(record)
    }

    /// Persist a declaration only if the caller still owns the exact record it
    /// loaded while holding the deployment lock.  A revision check alone is
    /// insufficient: a stale caller could otherwise replay a different
    /// declaration with the same expected revision.
    pub(crate) fn persist_declaration_cas_locked(
        &self,
        expected: &DeploymentRecord,
        updated: &DeploymentRecord,
    ) -> anyhow::Result<()> {
        expected.validate()?;
        updated.validate()?;
        if expected.deployment_id != updated.deployment_id {
            bail!("deployment declaration CAS crossed deployment boundaries");
        }
        let expected_revision = expected
            .declaration_revision
            .checked_add(1)
            .context("deployment declaration revision overflow")?;
        if updated.declaration_revision != expected_revision {
            bail!(
                "deployment declaration CAS must advance revision from {} to {}",
                expected.declaration_revision,
                expected_revision
            );
        }
        let current = self.load(&expected.deployment_id)?;
        if current != *expected {
            bail!("deployment declaration changed while the operation was in progress");
        }
        self.persist_declaration_file_locked(updated)
    }

    fn persist_declaration_file_locked(&self, record: &DeploymentRecord) -> anyhow::Result<()> {
        let registry = self.load_registry()?;
        if !registry.deployments.contains_key(&record.deployment_id) {
            bail!("deployment declaration is not registered");
        }
        atomic_write(
            &self.declaration_path(&record.deployment_id),
            &serde_json::to_vec_pretty(record)?,
            0o640,
        )
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

    pub(crate) fn registry_lock(&self) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        FileLock::acquire(&self.state_root.join("locks").join("registry.lock"))
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

pub(crate) struct FileLock {
    file: File,
}

impl FileLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let parent = path.parent().context("lock path has no parent")?;
        crate::filesystem::ensure_directory_chain(parent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open lock {}", path.display()))?;
        file.try_lock_exclusive()
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

#[cfg(test)]
#[path = "../tests/unit/deployment.rs"]
mod tests;
