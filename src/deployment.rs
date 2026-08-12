use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, TryLockError},
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::filesystem::{atomic_write, open_lock_file, read_secure_regular_file};

pub(crate) const REGISTRY_SCHEMA: u32 = 1;
pub(crate) const DEPLOYMENT_SCHEMA: u32 = 1;
const REGISTRATION_JOURNAL_SCHEMA: u32 = 1;
const REGISTRY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DEPLOYMENT_DECLARATION_MAX_BYTES: u64 = 4 * 1024 * 1024;
const REGISTRATION_JOURNAL_MAX_BYTES: u64 = 512 * 1024;
const OPERATOR_TASK_LOCK_TIMEOUT: Duration = Duration::from_secs(120);
const OPERATOR_TASK_LOCK_RETRY: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TrustState {
    Observed,
    Adopted,
}

pub(crate) use nazoauthctl_runtime::{
    ArtifactReference, MountReference, ResourceScope, Responsibility, RuntimeBackendKind,
    RuntimeInstance,
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
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| {
                format!("failed to inspect deployment registry {}", path.display())
            }),
        }
    }

    fn registration_pending(&self) -> anyhow::Result<bool> {
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

    pub(crate) fn registration_journal_path(&self, deployment_id: &str) -> PathBuf {
        self.state_root
            .join("transactions")
            .join(format!("registration-{deployment_id}.json"))
    }

    pub(crate) fn identity_rotation_journal_path(&self, deployment_id: &str) -> PathBuf {
        self.deployment_state_dir(deployment_id)
            .join("transactions")
            .join("identity-rotation.json")
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
        let journal_path = self.registration_journal_path(&record.deployment_id);
        let registration_journal_present = match fs::symlink_metadata(&journal_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!(
                        "registration journal must be a regular non-symlink file: {}",
                        journal_path.display()
                    );
                }
                true
            }
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", journal_path.display()));
            }
        };
        if registration_journal_present {
            let journal_bytes = read_secure_regular_file(
                &journal_path,
                "registration journal",
                true,
                REGISTRATION_JOURNAL_MAX_BYTES,
            )?;
            let journal: RegistrationJournal = serde_json::from_slice(&journal_bytes)
                .context("registration journal is invalid")?;
            if journal.schema != REGISTRATION_JOURNAL_SCHEMA
                || journal.deployment_id != record.deployment_id
            {
                bail!("registration journal does not bind to the requested deployment");
            }
            if journal.record != *record && !registration_identity_matches(&journal.record, record)
            {
                bail!("a different registration is already pending for this deployment");
            }
            self.reconcile_registration_locked(&journal, &journal_path)?;
            return Ok(());
        }

        let declaration = self.declaration_path(&record.deployment_id);
        let mut target_record = record.clone();
        if path_present(&declaration)? {
            let existing = self.load(&record.deployment_id)?;
            if existing != *record {
                if !registration_identity_matches(&existing, record) {
                    bail!("deployment declaration already exists with different identity");
                }
                // A completed install may be retried after later declaration
                // revisions.  Reconcile the authoritative existing record
                // and its registry/state fan-out; never replace it with the
                // stale install snapshot.
                target_record = existing;
            }
        }
        let registry = self.load_registry()?;
        if registry.deployments.iter().any(|(id, entry)| {
            id != &target_record.deployment_id
                && target_record.alias.is_some()
                && entry.alias == target_record.alias
        }) {
            bail!("deployment alias is already registered");
        }
        let journal = RegistrationJournal {
            schema: REGISTRATION_JOURNAL_SCHEMA,
            deployment_id: target_record.deployment_id.clone(),
            phase: RegistrationPhase::Prepared,
            record: target_record,
        };
        self.write_registration_journal(&journal_path, &journal)?;
        self.reconcile_registration_locked(&journal, &journal_path)?;
        Ok(())
    }

    fn write_registration_journal(
        &self,
        path: &Path,
        journal: &RegistrationJournal,
    ) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(journal)?;
        if bytes.len() as u64 > REGISTRATION_JOURNAL_MAX_BYTES {
            bail!("registration journal exceeds its size limit");
        }
        atomic_write(path, &bytes, 0o600)
    }

    fn reconcile_registration_locked(
        &self,
        journal: &RegistrationJournal,
        journal_path: &Path,
    ) -> anyhow::Result<()> {
        if journal.schema != REGISTRATION_JOURNAL_SCHEMA
            || journal.deployment_id != journal.record.deployment_id
        {
            bail!("registration journal is invalid");
        }
        journal.record.validate()?;
        let declaration = self.declaration_path(&journal.deployment_id);
        let deployment_dir = declaration
            .parent()
            .context("deployment declaration path has no deployment directory")?;
        let deployments_dir = deployment_dir
            .parent()
            .context("deployment declaration path has no deployments directory")?;
        ensure_real_directory(deployments_dir, "deployment declarations directory")?;
        if !path_present(deployments_dir)? {
            crate::filesystem::ensure_directory_chain(deployments_dir)?;
            crate::filesystem::set_mode(deployments_dir, 0o700)?;
        }
        ensure_real_directory(deployment_dir, "deployment declaration directory")?;
        if !path_present(deployment_dir)? {
            crate::filesystem::ensure_directory_chain(deployment_dir)?;
            crate::filesystem::set_mode(deployment_dir, 0o700)?;
        }
        if path_present(&declaration)? {
            let existing = self.load(&journal.deployment_id)?;
            if existing != journal.record {
                bail!("deployment declaration conflicts with registration journal");
            }
        } else {
            atomic_write(
                &declaration,
                &serde_json::to_vec_pretty(&journal.record)?,
                0o640,
            )?;
        }
        if journal.phase == RegistrationPhase::Prepared {
            let mut next = journal.clone();
            next.phase = RegistrationPhase::DeclarationCommitted;
            self.write_registration_journal(journal_path, &next)?;
        }

        let mut registry = self.load_registry()?;
        if registry.deployments.iter().any(|(id, entry)| {
            id != &journal.deployment_id
                && journal.record.alias.is_some()
                && entry.alias == journal.record.alias
        }) {
            bail!("deployment alias is already registered");
        }
        let registry_entry = RegistryEntry {
            alias: journal.record.alias.clone(),
            declaration: declaration.clone(),
        };
        if registry.deployments.get(&journal.deployment_id) != Some(&registry_entry) {
            registry
                .deployments
                .insert(journal.deployment_id.clone(), registry_entry);
            atomic_write(
                &self.registry_path(),
                &serde_json::to_vec_pretty(&registry)?,
                0o640,
            )?;
        }
        if journal.phase <= RegistrationPhase::DeclarationCommitted {
            let mut next = journal.clone();
            next.phase = RegistrationPhase::RegistryCommitted;
            self.write_registration_journal(journal_path, &next)?;
        }

        let state = self.deployment_state_dir(&journal.deployment_id);
        let deployments = state
            .parent()
            .context("deployment state path has no deployments parent")?;
        ensure_real_directory(deployments, "deployment state deployments directory")?;
        if !path_present(deployments)? {
            crate::filesystem::ensure_directory_chain(deployments)?;
            crate::filesystem::set_mode(deployments, 0o700)?;
        }
        ensure_real_directory(&state, "deployment state directory")?;
        if !path_present(&state)? {
            crate::filesystem::ensure_directory_chain(&state)?;
            crate::filesystem::set_mode(&state, 0o700)?;
        }
        for directory in ["identities", "audit", "transactions", "recovery"] {
            let path = state.join(directory);
            ensure_real_directory(&path, "deployment state subdirectory")?;
            if !path_present(&path)? {
                crate::filesystem::ensure_directory_chain(&path)?;
                crate::filesystem::set_mode(&path, 0o700)?;
            }
        }
        if journal.phase <= RegistrationPhase::RegistryCommitted {
            let mut next = journal.clone();
            next.phase = RegistrationPhase::StateCommitted;
            self.write_registration_journal(journal_path, &next)?;
        }
        crate::filesystem::remove_file_durable(journal_path)
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

    /// Serialize the short controller-side operator task transaction (intent,
    /// runtime receipt and audit-chain append) without serializing the remote
    /// Suite execution that happens between onboarding and cleanup.
    pub(crate) fn operator_task_lock(&self, deployment_id: &str) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        validate_identifier(deployment_id, "deployment ID")?;
        FileLock::acquire_exclusive_bounded(
            &self
                .state_root
                .join("locks")
                .join(format!("operator-task-{deployment_id}.lock")),
            OPERATOR_TASK_LOCK_TIMEOUT,
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

fn registration_identity_matches(
    existing: &DeploymentRecord,
    requested: &DeploymentRecord,
) -> bool {
    let runtime_identity = |record: &DeploymentRecord| {
        record
            .runtime_instances
            .iter()
            .map(|runtime| {
                (
                    runtime.runtime_instance_id.clone(),
                    runtime.backend,
                    runtime.object_reference.clone(),
                )
            })
            .collect::<BTreeSet<_>>()
    };
    existing.deployment_id == requested.deployment_id
        && existing.control_authority == requested.control_authority
        && existing.issuer == requested.issuer
        && runtime_identity(existing) == runtime_identity(requested)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RegistrationPhase {
    Prepared,
    DeclarationCommitted,
    RegistryCommitted,
    StateCommitted,
}

/// Durable intent for the multi-file registration commit.  Declaration,
/// registry and state directories live in separate failure domains, so a
/// retry must know the exact declaration it is reconciling rather than
/// treating an existing declaration as proof that registration completed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationJournal {
    schema: u32,
    deployment_id: String,
    phase: RegistrationPhase,
    record: DeploymentRecord,
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

    fn acquire_exclusive_bounded(path: &Path, timeout: Duration) -> anyhow::Result<Self> {
        let file = open_lock_file(path, false, "operator task lock")?;
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(TryLockError::WouldBlock) if elapsed < timeout => {
                    thread::sleep(OPERATOR_TASK_LOCK_RETRY.min(timeout.saturating_sub(elapsed)));
                }
                Err(TryLockError::WouldBlock) => {
                    bail!(
                        "timed out after {} seconds waiting for the operator task writer {}",
                        timeout.as_secs(),
                        path.display()
                    );
                }
                Err(TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("failed to acquire operator task writer {}", path.display())
                    });
                }
            }
        }
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
