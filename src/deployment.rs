use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::filesystem::atomic_write;

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
            && matches!(
                self.resources.get("controller_config"),
                Some(SafeReference::File { .. })
            )
            && self.capabilities.runtime.responsibility.permits_mutation()
            && self.capabilities.artifact.responsibility.permits_mutation()
            && self.capabilities.backups.responsibility.permits_mutation()
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != DEPLOYMENT_SCHEMA {
            bail!("unsupported deployment declaration schema");
        }
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
        let mut runtime_ids = BTreeSet::new();
        for runtime in &self.runtime_instances {
            validate_identifier(&runtime.runtime_instance_id, "runtime instance ID")?;
            if !runtime_ids.insert(&runtime.runtime_instance_id) {
                bail!("duplicate runtime instance ID in deployment declaration");
            }
            if runtime.object_reference.is_empty() {
                bail!("runtime object reference is empty");
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
        Self {
            config_root: root_from_env("NAZOAUTHCTL_CONFIG_ROOT", "/etc/nazoauthctl"),
            state_root: root_from_env("NAZOAUTHCTL_STATE_ROOT", "/var/lib/nazoauthctl"),
            break_glass_root: root_from_env(
                "NAZOAUTHCTL_BREAK_GLASS_ROOT",
                "/var/lib/nazoauthctl-break-glass",
            ),
        }
    }

    pub(crate) fn registry_path(&self) -> PathBuf {
        self.config_root.join("registry.json")
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
        let path = self.registry_path();
        if !path.exists() {
            return Ok(Registry {
                schema: REGISTRY_SCHEMA,
                deployments: BTreeMap::new(),
            });
        }
        let registry: Registry = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
        )
        .context("registry is invalid")?;
        if registry.schema != REGISTRY_SCHEMA {
            bail!("unsupported registry schema");
        }
        Ok(registry)
    }

    pub(crate) fn load(&self, deployment_id: &str) -> anyhow::Result<DeploymentRecord> {
        validate_identifier(deployment_id, "deployment ID")?;
        let path = self.declaration_path(deployment_id);
        let record: DeploymentRecord = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
        )
        .context("deployment declaration is invalid")?;
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
        record.validate()?;
        let _registry_lock = self.registry_lock()?;
        let _deployment_lock = self.deployment_lock(&record.deployment_id)?;
        self.persist_locked(record)
    }

    pub(crate) fn persist_locked(&self, record: &DeploymentRecord) -> anyhow::Result<()> {
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

    pub(crate) fn registry_lock(&self) -> anyhow::Result<FileLock> {
        FileLock::acquire(&self.state_root.join("locks").join("registry.lock"))
    }

    pub(crate) fn deployment_lock(&self, deployment_id: &str) -> anyhow::Result<FileLock> {
        validate_identifier(deployment_id, "deployment ID")?;
        FileLock::acquire(
            &self
                .state_root
                .join("locks")
                .join(format!("deployment-{deployment_id}.lock")),
        )
    }

    pub(crate) fn shared_resource_lock(&self, resource_id: &str) -> anyhow::Result<FileLock> {
        validate_identifier(resource_id, "shared resource ID")?;
        FileLock::acquire(
            &self
                .state_root
                .join("locks")
                .join(format!("shared-{resource_id}.lock")),
        )
    }
}

pub(crate) struct FileLock {
    file: File,
}

impl FileLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let parent = path.parent().context("lock path has no parent")?;
        fs::create_dir_all(parent)?;
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
