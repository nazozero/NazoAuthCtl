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

pub(crate) use nazoauthctl_runtime::{ArtifactReference, RuntimeBackendKind, RuntimeInstance};

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
#[serde(deny_unknown_fields)]
pub(crate) struct DeploymentRecord {
    pub(crate) schema: u32,
    pub(crate) deployment_id: String,
    pub(crate) control_authority: String,
    pub(crate) alias: Option<String>,
    pub(crate) issuer: String,
    pub(crate) active_release: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) runtime_instances: Vec<RuntimeInstance>,
    pub(crate) resources: BTreeMap<String, SafeReference>,
    pub(crate) operator_protocol_versions: BTreeSet<u32>,
    pub(crate) control_protocol_versions: BTreeSet<u32>,
    /// Config-revision CAS anchor for the surviving TLS certificate-provider
    /// transactions; every receipt must bind the declaration revision it was
    /// planned against.
    pub(crate) declaration_revision: u64,
}

impl DeploymentRecord {
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
}

impl DeploymentStore {
    pub(crate) fn system() -> Self {
        let (config_default, state_default) = if cfg!(windows) {
            (
                r"C:\ProgramData\NazoAuthCtl\config",
                r"C:\ProgramData\NazoAuthCtl\state",
            )
        } else if cfg!(target_os = "macos") {
            ("/private/etc/nazoauthctl", "/private/var/lib/nazoauthctl")
        } else {
            ("/etc/nazoauthctl", "/var/lib/nazoauthctl")
        };
        Self {
            config_root: root_from_env("NAZOAUTHCTL_CONFIG_ROOT", config_default),
            state_root: root_from_env("NAZOAUTHCTL_STATE_ROOT", state_default),
        }
    }

    pub(crate) fn registry_path(&self) -> PathBuf {
        self.config_root.join("registry.json")
    }

    /// Return whether the registration registry exists without following a
    /// link.  Callers use this only to choose the registered/unregistered
    /// control boundary; the subsequent load still validates the same
    /// descriptor.
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
                        "deployment registry is missing while registered deployment artifacts remain; restore or reconcile the registry before running controller commands"
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
        ] {
            validate_storage_root(path, label)?;
        }
        let config_identity = storage_identity(&self.config_root)?;
        let state_identity = storage_identity(&self.state_root)?;
        if paths_overlap(&state_identity, &config_identity) {
            bail!("controller configuration and state roots must not overlap");
        }
        Ok(())
    }

    /// Create the controller roots only after validating every existing path
    /// component.  The second validation closes the common create-time
    /// symlink substitution window and makes all later atomic writes/locks
    /// inherit a trusted parent chain.
    fn ensure_storage_roots(&self) -> anyhow::Result<()> {
        self.validate_failure_domains()?;
        for (label, path) in [
            ("controller configuration root", &self.config_root),
            ("controller state root", &self.state_root),
        ] {
            if matches!(fs::symlink_metadata(path), Err(error) if error.kind() == ErrorKind::NotFound)
            {
                crate::filesystem::ensure_directory_chain(path)
                    .with_context(|| format!("failed to create {label} {}", path.display()))?;
                crate::filesystem::set_mode(path, 0o700)?;
            }
            validate_storage_root(path, label)?;
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

    pub(crate) fn controller_self_lock(&self) -> anyhow::Result<FileLock> {
        self.ensure_storage_roots()?;
        FileLock::acquire(&self.state_root.join("locks").join("controller-self.lock"))
    }
}

fn validate_storage_root(path: &Path, label: &str) -> anyhow::Result<()> {
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
        validate_storage_directory_metadata(&metadata, path, label)?;
    }
    Ok(())
}

fn validate_storage_directory_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            bail!("{label} is group/world writable: {}", path.display());
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
        let _ = (metadata, path, label);
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
