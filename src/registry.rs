//! User-scoped Host and Instance Registry.
//!
//! The Registry is inventory-only (goal plan 01, evidence A03 rows 1/2/10):
//! it records which hosts and instances this controller has managed, how to
//! reach them, and the last cached observation. It never becomes a second
//! authority for deployment state, ownership, or controller validity; every
//! mutation must re-resolve the live target before acting.
//!
//! Storage layout (user-scoped, no root required):
//!
//! ```text
//! <platform config dir>/nazoauthctl/registry/
//!   registry.lock              fs2 exclusive lock for every operation
//!   hosts/<host_id>.json       one HostRecord per file, keyed by UUIDv7
//!   instances/<deployment_id>.json
//! ```
//!
//! Every record is written atomically through the shared filesystem
//! primitive, read back through the secure regular-file reader (regular,
//! non-symlink, non-reparse, single hard link, owner-safe mode), bounded by a
//! size cap, and parsed with `deny_unknown_fields` plus an explicit `schema`
//! discriminator. Any unreadable, oversized, or non-conforming record fails
//! closed with the stable `STATE_RESET_REQUIRED` code instead of being
//! repaired or interpreted leniently.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::filesystem;
use crate::target::wire::{RemoteHello, verify_remote_hello};

/// Schema discriminator carried by every persisted registry record.
pub const REGISTRY_RECORD_SCHEMA: u32 = 1;

/// Reserved host alias for the control machine itself.
pub const LOCAL_HOST_ALIAS: &str = "local";

/// Upper bound for a single persisted registry record (~4 MiB).
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// Stable error code emitted when any registry file cannot be parsed as the
/// current schema. The only supported remedy is backing up salvageable files
/// and clearing the registry store; no fallback parsing exists.
///
/// Canonical name lives in [`crate::error_codes`]; re-exported here so every
/// historical call site keeps one stable path.
pub use crate::error_codes::STATE_RESET_REQUIRED;

/// Maximum length of a user-facing selector or reference string.
const MAX_KEY_CHARS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostTransport {
    Local,
    Ssh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostPrivilege {
    Direct,
    Sudo,
}

/// Cached observation attached to a host or instance record.
///
/// This is a pure cache (authority ADR row 10): it must carry `observed_at`, it never
/// authorizes a mutation, and it is never written back onto a live target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCache {
    pub observed_at: DateTime<Utc>,
    pub reachable: bool,
    /// Short human-readable summary of what was observed. Free text on
    /// purpose: typed observation payloads arrive with the B06 refresh wave.
    pub summary: String,
}

impl ObservationCache {
    pub fn now(reachable: bool, summary: impl Into<String>) -> Self {
        Self {
            observed_at: Utc::now(),
            reachable,
            summary: summary.into(),
        }
    }
}

/// One managed host: the control machine itself or an SSH target.
///
/// SSH hosts store only the OpenSSH `Host` alias (authority ADR rule R6).
/// HostName, User, IdentityFile, ProxyJump, passwords, private keys, and
/// known_hosts copies are deliberately unrepresentable in this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecord {
    pub schema: u32,
    /// Stable inventory identity. Renames and privilege changes never alter it.
    pub host_id: Uuid,
    /// User-friendly name, unique across the store. `local` is reserved.
    pub alias: String,
    pub transport: HostTransport,
    /// OpenSSH config Host alias. Present if and only if transport is `ssh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_profile: Option<String>,
    pub privilege: HostPrivilege,
    /// Remote executor basename only (`nazoauthctl remote exec` helper).
    /// Path components are rejected; transports build the fixed command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_exec_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observation: Option<ObservationCache>,
}

impl HostRecord {
    pub fn new_local() -> Self {
        Self {
            schema: REGISTRY_RECORD_SCHEMA,
            host_id: Uuid::now_v7(),
            alias: LOCAL_HOST_ALIAS.to_owned(),
            transport: HostTransport::Local,
            ssh_profile: None,
            privilege: HostPrivilege::Direct,
            remote_exec_path: None,
            last_observation: None,
        }
    }

    pub fn new_ssh(
        alias: impl Into<String>,
        ssh_profile: impl Into<String>,
        privilege: HostPrivilege,
    ) -> anyhow::Result<Self> {
        let mut record = Self::new_local();
        record.host_id = Uuid::now_v7();
        record.alias = alias.into();
        record.transport = HostTransport::Ssh;
        record.ssh_profile = Some(ssh_profile.into());
        record.privilege = privilege;
        record.validate()?;
        Ok(record)
    }

    /// Enforce every invariant the store relies on. Called by the
    /// constructors and again by the store before persisting, so a
    /// hand-built record cannot bypass the rules.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != REGISTRY_RECORD_SCHEMA {
            bail!("unsupported host record schema {}", self.schema);
        }
        validate_key(&self.alias, "host alias")?;
        if self.transport == HostTransport::Local {
            if self.alias != LOCAL_HOST_ALIAS {
                bail!("the '{LOCAL_HOST_ALIAS}' alias is reserved for the built-in local host");
            }
            if self.ssh_profile.is_some() {
                bail!("a local host must not carry an ssh profile");
            }
        } else {
            let Some(profile) = self.ssh_profile.as_deref() else {
                bail!("an ssh host requires an OpenSSH Host alias");
            };
            validate_key(profile, "ssh profile alias")?;
            if self.alias == LOCAL_HOST_ALIAS {
                bail!("the '{LOCAL_HOST_ALIAS}' alias is reserved for the built-in local host");
            }
        }
        if let Some(exec) = self.remote_exec_path.as_deref() {
            validate_key(exec, "remote exec path")?;
        }
        Ok(())
    }

    pub fn set_last_observation(&mut self, observation: ObservationCache) {
        self.last_observation = Some(observation);
    }
}

/// One managed NazoAuth instance bound to a host.
///
/// Identity versus selector (goal plan 02 §3): `deployment_id` and `issuer` are the
/// security identity, `alias` is only a local selector. Controller material
/// is stored strictly as references — never embedded key bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRecord {
    pub schema: u32,
    /// Real instance identity; unique across the store and used as the
    /// record filename so duplicates cannot be created even concurrently.
    pub deployment_id: String,
    /// User-friendly selector, unique across the store. Renaming keeps every
    /// binding below untouched.
    pub alias: String,
    /// Reference to the managing [`HostRecord`].
    pub host_id: Uuid,
    /// Canonical issuer origin of the instance (https/http URL reference).
    pub issuer: String,
    /// Optional controller identity reference (e.g. key id at the server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_id: Option<String>,
    /// Reference into the local per-instance controller key store. This is a
    /// locator only; private-key bytes are never stored in the Registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_key_ref: Option<String>,
    /// Reference to the target-side DeploymentState location (authority ADR row 4);
    /// interpreted by the deployment waves, opaque here.
    pub target_state_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observation: Option<ObservationCache>,
}

impl InstanceRecord {
    pub fn new(
        deployment_id: impl Into<String>,
        alias: impl Into<String>,
        host_id: Uuid,
        issuer: impl Into<String>,
        target_state_ref: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let record = Self {
            schema: REGISTRY_RECORD_SCHEMA,
            deployment_id: deployment_id.into(),
            alias: alias.into(),
            host_id,
            issuer: issuer.into(),
            controller_id: None,
            controller_key_ref: None,
            target_state_ref: target_state_ref.into(),
            last_observation: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != REGISTRY_RECORD_SCHEMA {
            bail!("unsupported instance record schema {}", self.schema);
        }
        validate_key(&self.deployment_id, "deployment id")?;
        validate_key(&self.alias, "instance alias")?;
        validate_reference(&self.target_state_ref, "target state ref")?;
        validate_issuer(&self.issuer)?;
        if let Some(id) = self.controller_id.as_deref() {
            validate_key(id, "controller id")?;
        }
        if let Some(key_ref) = self.controller_key_ref.as_deref() {
            validate_reference(key_ref, "controller key ref")?;
            // Belt-and-braces guard: the field is a locator, not key material.
            if key_ref.contains("-----BEGIN") || key_ref.contains("PRIVATE KEY") {
                bail!("controller key ref must be a reference, not embedded key material");
            }
        }
        Ok(())
    }

    /// Rename the local selector without touching any binding fact.
    pub fn renamed(mut self, new_alias: impl Into<String>) -> anyhow::Result<Self> {
        self.alias = new_alias.into();
        self.validate()?;
        Ok(self)
    }
}

/// Schema discriminator for [`DiscoveryEvidence`] artifacts.
pub const DISCOVERY_EVIDENCE_SCHEMA: u32 = 1;

/// Exact `evidence` kind tag carried by every discovery evidence artifact.
pub const DISCOVERY_EVIDENCE_KIND: &str = "instance-discovery-v1";

/// Live-observed deployment binding produced by a real hello/inspect run
/// against one managed host (goal plan 02, task B04).
///
/// `instance register` accepts deployment identities only through this
/// artifact; hand-typed `deployment_id` + `issuer` pairs have no input path.
/// Producers: since G05, `discover_adopt::run_adopt` fills the `deployment`
/// fields from the target's own DeploymentState over a verified channel —
/// operator input no longer supplies them there. The interim `instance
/// observe` helper still captures them from operator input at observation
/// time until the I-wave CLI rewiring retires it; everything around those
/// fields — host identity, verified [`RemoteHello`], timestamp — is
/// live-observed on every path. Registration re-verifies the live helper
/// identity against the artifact before trusting it, so a stale or
/// fabricated envelope fails closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryEvidence {
    pub schema: u32,
    pub evidence: String,
    pub observed_at: DateTime<Utc>,
    pub host_id: Uuid,
    pub host_alias: String,
    pub transport: HostTransport,
    pub hello: RemoteHello,
    pub deployment: DiscoveredDeployment,
}

/// The deployment binding carried inside a [`DiscoveryEvidence`] artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredDeployment {
    pub deployment_id: String,
    pub issuer: String,
}

impl DiscoveryEvidence {
    /// Build an evidence artifact the way the observe helper does: the hello
    /// must come from a just-completed live probe of `host`.
    pub fn new(
        host: &HostRecord,
        hello: RemoteHello,
        deployment_id: impl Into<String>,
        issuer: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let evidence = Self {
            schema: DISCOVERY_EVIDENCE_SCHEMA,
            evidence: DISCOVERY_EVIDENCE_KIND.to_owned(),
            observed_at: Utc::now(),
            host_id: host.host_id,
            host_alias: host.alias.clone(),
            transport: host.transport,
            hello,
            deployment: DiscoveredDeployment {
                deployment_id: deployment_id.into(),
                issuer: issuer.into(),
            },
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Enforce every invariant registration relies on. Unknown fields, wrong
    /// schema/kind tags, unverifiable helper identities, and malformed
    /// deployment bindings all fail closed here.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != DISCOVERY_EVIDENCE_SCHEMA {
            bail!(
                "unsupported discovery evidence schema {} (expected {DISCOVERY_EVIDENCE_SCHEMA})",
                self.schema
            );
        }
        if self.evidence != DISCOVERY_EVIDENCE_KIND {
            bail!(
                "unsupported evidence kind '{}' (expected '{DISCOVERY_EVIDENCE_KIND}')",
                self.evidence
            );
        }
        validate_key(&self.host_alias, "evidence host alias")?;
        verify_remote_hello(&self.hello).map_err(|reason| {
            anyhow::anyhow!("evidence helper identity is not verifiable: {reason}")
        })?;
        validate_key(&self.deployment.deployment_id, "evidence deployment id")?;
        validate_issuer(&self.deployment.issuer)?;
        Ok(())
    }
}

fn validate_key(value: &str, label: &str) -> anyhow::Result<()> {
    validate_identifier(value, MAX_KEY_CHARS, label)
}

/// Crate-visible alias for sibling stores (clean-install id generation).
pub(crate) fn validate_registry_key(value: &str, label: &str) -> anyhow::Result<()> {
    validate_key(value, label)
}

/// Shared identifier rule for store-legal tokens across ctl stores
/// (registry keys and target DeploymentState identifiers alike): 1..=max
/// characters from `[A-Za-z0-9.:_+-]`, never `.` or `..`.
pub(crate) fn validate_identifier(
    value: &str,
    max_chars: usize,
    label: &str,
) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > max_chars
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
        || value == "."
        || value == ".."
    {
        bail!("{label} must be 1-{max_chars} characters from [A-Za-z0-9.:_+-]");
    }
    Ok(())
}

fn validate_reference(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        bail!("{label} must be a single-line reference of at most 512 characters");
    }
    Ok(())
}

pub(crate) fn validate_issuer(value: &str) -> anyhow::Result<()> {
    let parsed =
        Url::parse(value).with_context(|| format!("issuer is not a valid URL: {value}"))?;
    if parsed.cannot_be_a_base()
        || !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("issuer must be an http(s) origin URL without credentials");
    }
    Ok(())
}

/// Exclusive registry lock held across a store operation.
struct StoreLock {
    file: fs::File,
}

impl StoreLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let file = filesystem::open_lock_file(path, false, "registry lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Handle to the user-scoped registry store.
#[derive(Clone, Debug)]
pub struct RegistryStore {
    root: PathBuf,
}

impl RegistryStore {
    /// Open (creating if needed) the store layout under `root`.
    pub fn open(root: PathBuf) -> anyhow::Result<Self> {
        filesystem::ensure_private_directory(&root, "registry root")?;
        let store = Self { root };
        filesystem::ensure_private_directory(&store.hosts_dir(), "registry hosts directory")
            .with_context(|| format!("failed to prepare {}", store.hosts_dir().display()))?;
        filesystem::ensure_private_directory(
            &store.instances_dir(),
            "registry instances directory",
        )
        .with_context(|| format!("failed to prepare {}", store.instances_dir().display()))?;
        Ok(store)
    }

    /// Platform user configuration directory for the registry:
    /// `%APPDATA%\nazoauthctl\registry` on Windows,
    /// `$XDG_CONFIG_HOME/nazoauthctl/registry` or
    /// `$HOME/.config/nazoauthctl/registry` elsewhere.
    pub fn default_root() -> anyhow::Result<PathBuf> {
        config_root().map(|base| base.join("nazoauthctl").join("registry"))
    }

    /// Open the store at the platform default location.
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(Self::default_root()?)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn hosts_dir(&self) -> PathBuf {
        self.root.join("hosts")
    }

    fn instances_dir(&self) -> PathBuf {
        self.root.join("instances")
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join("registry.lock")
    }

    fn lock(&self) -> anyhow::Result<StoreLock> {
        StoreLock::acquire(&self.lock_path())
    }

    /// Create the reserved built-in `local` host exactly once.
    pub fn ensure_local_host(&self) -> anyhow::Result<HostRecord> {
        let _lock = self.lock()?;
        if let Some(existing) = self.find_host_by_alias_locked(LOCAL_HOST_ALIAS)? {
            return Ok(existing);
        }
        let record = HostRecord::new_local();
        self.write_host_locked(&record)?;
        Ok(record)
    }

    /// Register a new host. Rejects duplicate aliases and duplicate ids.
    pub fn add_host(&self, record: HostRecord) -> anyhow::Result<HostRecord> {
        record.validate()?;
        let _lock = self.lock()?;
        if self.find_host_by_alias_locked(&record.alias)?.is_some() {
            bail!("duplicate host alias '{}'", record.alias);
        }
        if self.find_host_by_id_locked(record.host_id)?.is_some() {
            bail!("duplicate host id {}", record.host_id);
        }
        self.write_host_locked(&record)?;
        Ok(record)
    }

    /// Rename a host alias. The `host_id`, transport, profile, and privilege
    /// are preserved; referencing instance records keep working because they
    /// bind to `host_id`. The built-in `local` host keeps its reserved alias.
    pub fn rename_host(
        &self,
        old_alias: &str,
        new_alias: impl Into<String>,
    ) -> anyhow::Result<HostRecord> {
        let _lock = self.lock()?;
        let mut record = self
            .find_host_by_alias_locked(old_alias)?
            .with_context(|| format!("unknown host alias '{old_alias}'"))?;
        let new_alias = new_alias.into();
        if record.alias == LOCAL_HOST_ALIAS {
            bail!("the '{LOCAL_HOST_ALIAS}' host cannot be renamed; its alias is reserved");
        }
        if new_alias != record.alias && self.find_host_by_alias_locked(&new_alias)?.is_some() {
            bail!("duplicate host alias '{new_alias}'");
        }
        record.alias = new_alias;
        record.validate()?;
        self.write_host_locked(&record)?;
        Ok(record)
    }

    pub fn host_by_alias(&self, alias: &str) -> anyhow::Result<Option<HostRecord>> {
        let _lock = self.lock()?;
        self.find_host_by_alias_locked(alias)
    }

    pub fn list_hosts(&self) -> anyhow::Result<Vec<HostRecord>> {
        let _lock = self.lock()?;
        let mut hosts = Vec::new();
        for (_, record) in self.load_all_locked::<HostRecord>(Directory::Hosts)? {
            hosts.push(record);
        }
        hosts.sort_by(|left, right| left.alias.cmp(&right.alias));
        Ok(hosts)
    }

    /// Register a new instance. Duplicate `deployment_id` and duplicate
    /// `alias` are both rejected; the referenced host must exist.
    pub fn add_instance(&self, record: InstanceRecord) -> anyhow::Result<InstanceRecord> {
        record.validate()?;
        let _lock = self.lock()?;
        if self
            .find_instance_by_deployment_locked(&record.deployment_id)?
            .is_some()
        {
            bail!(
                "duplicate deployment id '{}' (one registry entry per real instance)",
                record.deployment_id
            );
        }
        if self.find_instance_by_alias_locked(&record.alias)?.is_some() {
            bail!("duplicate instance alias '{}'", record.alias);
        }
        if self.find_host_by_id_locked(record.host_id)?.is_none() {
            bail!(
                "instance '{}' references unknown host {}",
                record.deployment_id,
                record.host_id
            );
        }
        let path = self.instance_path(&record.deployment_id);
        write_record(&path, "instance record", &record)?;
        Ok(record)
    }

    /// Rename an instance selector. Identity facts (`deployment_id`,
    /// `issuer`, `host_id`, controller references) are preserved verbatim.
    pub fn rename_instance(
        &self,
        old_alias: &str,
        new_alias: impl Into<String>,
    ) -> anyhow::Result<InstanceRecord> {
        let _lock = self.lock()?;
        let record = self
            .find_instance_by_alias_locked(old_alias)?
            .with_context(|| format!("unknown instance alias '{old_alias}'"))?;
        let new_alias = new_alias.into();
        if new_alias != record.alias && self.find_instance_by_alias_locked(&new_alias)?.is_some() {
            bail!("duplicate instance alias '{new_alias}'");
        }
        let renamed = record.renamed(new_alias)?;
        let path = self.instance_path(&renamed.deployment_id);
        write_record(&path, "instance record", &renamed)?;
        Ok(renamed)
    }

    pub fn instance_by_alias(&self, alias: &str) -> anyhow::Result<Option<InstanceRecord>> {
        let _lock = self.lock()?;
        self.find_instance_by_alias_locked(alias)
    }

    pub fn instance_by_deployment(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<Option<InstanceRecord>> {
        let _lock = self.lock()?;
        self.find_instance_by_deployment_locked(deployment_id)
    }

    pub fn list_instances(&self) -> anyhow::Result<Vec<InstanceRecord>> {
        let _lock = self.lock()?;
        let mut instances = Vec::new();
        for (_, record) in self.load_all_locked::<InstanceRecord>(Directory::Instances)? {
            instances.push(record);
        }
        instances.sort_by(|left, right| left.alias.cmp(&right.alias));
        Ok(instances)
    }

    pub fn host_by_id(&self, host_id: Uuid) -> anyhow::Result<Option<HostRecord>> {
        let _lock = self.lock()?;
        self.find_host_by_id_locked(host_id)
    }

    /// Controlled registration path (task B04): the only way an
    /// [`InstanceRecord`] enters the store from a deployment binding. The
    /// evidence must carry a verifiable live-observed helper identity and must
    /// match the stored host record; duplicate `deployment_id` (reported as a
    /// relocation candidate, never silently updated) and duplicate aliases are
    /// rejected. `observation` is the caller's fresh live observation and
    /// becomes the record's first cache entry.
    pub fn register_instance(
        &self,
        evidence: &DiscoveryEvidence,
        alias: Option<&str>,
        observation: ObservationCache,
    ) -> anyhow::Result<InstanceRecord> {
        evidence.validate()?;
        let _lock = self.lock()?;
        let host = self
            .find_host_by_id_locked(evidence.host_id)?
            .with_context(|| format!("evidence names unknown host {}", evidence.host_id))?;
        if host.alias != evidence.host_alias || host.transport != evidence.transport {
            bail!(
                "registry host '{}' drifted from the evidence artifact (alias or transport changed); \
                 re-run the discovery step against the current registry",
                host.alias
            );
        }
        if self
            .find_instance_by_deployment_locked(&evidence.deployment.deployment_id)?
            .is_some()
        {
            bail!(
                "duplicate deployment id '{}' (one registry entry per real instance). If this \
                 instance relocated to another host, verify it there and use \
                 `instance relocate --to-host <alias>` instead of registering it a second time",
                evidence.deployment.deployment_id
            );
        }
        let alias = alias.unwrap_or(&evidence.deployment.deployment_id);
        if self.find_instance_by_alias_locked(alias)?.is_some() {
            bail!("duplicate instance alias '{alias}'");
        }
        let mut record = InstanceRecord::new(
            &evidence.deployment.deployment_id,
            alias,
            evidence.host_id,
            &evidence.deployment.issuer,
            format!(
                "target-state/{}/{}",
                evidence.host_id, evidence.deployment.deployment_id
            ),
        )?;
        record.last_observation = Some(observation);
        record.validate()?;
        let path = self.instance_path(&record.deployment_id);
        write_record(&path, "instance record", &record)?;
        Ok(record)
    }

    /// Forget one host. Registry-only by construction: no target operation
    /// exists on this path. Hosts still referenced by instance records are
    /// rejected unless `cascade` is set, in which case those local instance
    /// records are forgotten too — the remote deployments themselves keep
    /// running untouched.
    pub fn forget_host(
        &self,
        alias: &str,
        cascade: bool,
    ) -> anyhow::Result<(HostRecord, Vec<InstanceRecord>)> {
        let _lock = self.lock()?;
        let host = self
            .find_host_by_alias_locked(alias)?
            .with_context(|| format!("unknown host alias '{alias}'"))?;
        if host.transport == HostTransport::Local {
            bail!(
                "the built-in '{}' host cannot be forgotten",
                LOCAL_HOST_ALIAS
            );
        }
        let mut referencing = Vec::new();
        for (_, record) in self.load_all_locked::<InstanceRecord>(Directory::Instances)? {
            if record.host_id == host.host_id {
                referencing.push(record);
            }
        }
        if !referencing.is_empty() && !cascade {
            let names = referencing
                .iter()
                .map(|record| record.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "host '{alias}' still has {} registered instance(s) ({names}); re-run with \
                 --cascade to forget those local records as well — remote instances are never \
                 uninstalled or unbound by this command",
                referencing.len()
            );
        }
        for record in &referencing {
            filesystem::remove_file_durable(&self.instance_path(&record.deployment_id))
                .with_context(|| format!("failed to forget instance '{}'", record.alias))?;
        }
        filesystem::remove_file_durable(&self.host_path(host.host_id))
            .with_context(|| format!("failed to forget host '{alias}'"))?;
        Ok((host, referencing))
    }

    /// Forget one instance record by its canonical identity. Registry-only:
    /// controller slots at the server are not revoked and remote deployments
    /// are not touched.
    pub fn forget_instance_by_deployment(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<InstanceRecord> {
        let _lock = self.lock()?;
        let record = self
            .find_instance_by_deployment_locked(deployment_id)?
            .with_context(|| format!("unknown instance deployment id '{deployment_id}'"))?;
        filesystem::remove_file_durable(&self.instance_path(deployment_id))
            .with_context(|| format!("failed to forget instance '{deployment_id}'"))?;
        Ok(record)
    }

    /// Write a fresh observation cache entry for a host, preserving every
    /// other field. Cache writes never authorize anything; they only record
    /// what the last live contact saw.
    pub fn set_host_observation(
        &self,
        host_id: Uuid,
        observation: ObservationCache,
    ) -> anyhow::Result<()> {
        let _lock = self.lock()?;
        let mut host = self
            .find_host_by_id_locked(host_id)?
            .with_context(|| format!("unknown host {host_id}"))?;
        host.last_observation = Some(observation);
        host.validate()?;
        self.write_host_locked(&host)
    }

    /// Write a fresh observation cache entry for an instance, preserving every
    /// other field.
    pub fn set_instance_observation(
        &self,
        deployment_id: &str,
        observation: ObservationCache,
    ) -> anyhow::Result<()> {
        let _lock = self.lock()?;
        let mut record = self
            .find_instance_by_deployment_locked(deployment_id)?
            .with_context(|| format!("unknown instance '{deployment_id}'"))?;
        record.last_observation = Some(observation);
        record.validate()?;
        write_record(
            &self.instance_path(deployment_id),
            "instance record",
            &record,
        )
    }

    /// Update the controller identity binding of one instance (tasks
    /// D04/D06/D07/D08): `controller_id` is the server-assigned slot identity
    /// and `key_ref` the caller-resolved locator into the Controller Key
    /// store. Clearing both marks the instance locally unbound without
    /// touching key material. Both values pass full record validation.
    pub fn update_controller_binding(
        &self,
        deployment_id: &str,
        controller_id: Option<&str>,
        key_ref: Option<&str>,
    ) -> anyhow::Result<InstanceRecord> {
        let _lock = self.lock()?;
        let mut record = self
            .find_instance_by_deployment_locked(deployment_id)?
            .with_context(|| format!("unknown instance '{deployment_id}'"))?;
        record.controller_id = controller_id.map(str::to_owned);
        record.controller_key_ref = key_ref.map(str::to_owned);
        record.validate()?;
        write_record(
            &self.instance_path(deployment_id),
            "instance record",
            &record,
        )?;
        Ok(record)
    }

    /// Move an instance to another host. Callers must have verified the target
    /// DeploymentState identity through the new host first (task B07); this
    /// method only performs the local rebinding and clears the stale cache
    /// entry that described the old host.
    pub fn relocate_instance(
        &self,
        deployment_id: &str,
        new_host_id: Uuid,
    ) -> anyhow::Result<InstanceRecord> {
        let _lock = self.lock()?;
        let mut record = self
            .find_instance_by_deployment_locked(deployment_id)?
            .with_context(|| format!("unknown instance '{deployment_id}'"))?;
        if record.host_id == new_host_id {
            bail!("instance '{deployment_id}' is already bound to host {new_host_id}");
        }
        let new_host = self
            .find_host_by_id_locked(new_host_id)?
            .with_context(|| format!("cannot relocate to unknown host {new_host_id}"))?;
        // P1-2: update the target_state_ref to encode the new host so stale
        // references to the old host's state directory are never trusted.
        record.host_id = new_host_id;
        record.target_state_ref = format!(
            "target-state/{}/{}",
            new_host_id, record.deployment_id
        );
        record.last_observation = None;
        record.validate()?;
        write_record(
            &self.instance_path(deployment_id),
            "instance record",
            &record,
        )?;
        Ok(record)
    }

    fn host_path(&self, host_id: Uuid) -> PathBuf {
        self.hosts_dir().join(format!("{host_id}.json"))
    }

    fn instance_path(&self, deployment_id: &str) -> PathBuf {
        self.instances_dir().join(format!("{deployment_id}.json"))
    }

    fn write_host_locked(&self, record: &HostRecord) -> anyhow::Result<()> {
        write_record(&self.host_path(record.host_id), "host record", record)
    }

    fn find_host_by_alias_locked(&self, alias: &str) -> anyhow::Result<Option<HostRecord>> {
        Ok(self
            .load_all_locked::<HostRecord>(Directory::Hosts)?
            .into_iter()
            .find(|(_, record)| record.alias == alias)
            .map(|(_, record)| record))
    }

    fn find_host_by_id_locked(&self, host_id: Uuid) -> anyhow::Result<Option<HostRecord>> {
        Ok(self
            .load_all_locked::<HostRecord>(Directory::Hosts)?
            .into_iter()
            .find(|(_, record)| record.host_id == host_id)
            .map(|(_, record)| record))
    }

    fn find_instance_by_deployment_locked(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<Option<InstanceRecord>> {
        Ok(self
            .load_all_locked::<InstanceRecord>(Directory::Instances)?
            .into_iter()
            .find(|(_, record)| record.deployment_id == deployment_id)
            .map(|(_, record)| record))
    }

    fn find_instance_by_alias_locked(&self, alias: &str) -> anyhow::Result<Option<InstanceRecord>> {
        Ok(self
            .load_all_locked::<InstanceRecord>(Directory::Instances)?
            .into_iter()
            .find(|(_, record)| record.alias == alias)
            .map(|(_, record)| record))
    }

    /// Load every record of one directory. Filenames other than `*.json`
    /// (for example leftover staging files from an interrupted atomic write)
    /// are ignored; anything that claims to be a record must fully conform.
    ///
    /// `_directory` selects the subdirectory; it is passed explicitly so the
    /// compiler proves callers never mix host and instance namespaces.
    fn load_all_locked<T: ConformingRecord>(
        &self,
        _directory: Directory,
    ) -> anyhow::Result<Vec<(String, T)>> {
        let dir = match _directory {
            Directory::Hosts => self.hosts_dir(),
            Directory::Instances => self.instances_dir(),
        };
        let mut entries = fs::read_dir(&dir)
            .with_context(|| format!("failed to list {}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to list {}", dir.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut records = Vec::new();
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .with_context(|| format!("unreadable record name {}", path.display()))?
                .to_owned();
            records.push((stem, read_record::<T>(&path)?));
        }
        Ok(records)
    }
}

#[derive(Clone, Copy, Debug)]
enum Directory {
    Hosts,
    Instances,
}

fn write_record<T: Serialize>(path: &Path, label: &str, record: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(record)
        .with_context(|| format!("failed to serialize {label} {}", path.display()))?;
    filesystem::atomic_write(path, &bytes, 0o600)
        .with_context(|| format!("failed to persist {label} {}", path.display()))
}

/// Load-time invariant check for persisted records. Wiring record
/// validation into deserialization keeps every stored file conforming to
/// the current schema, so drift fails closed as STATE_RESET_REQUIRED.
trait ConformingRecord: serde::de::DeserializeOwned {
    fn validate_loaded(&self) -> anyhow::Result<()>;
}

impl ConformingRecord for HostRecord {
    fn validate_loaded(&self) -> anyhow::Result<()> {
        self.validate()
    }
}

impl ConformingRecord for InstanceRecord {
    fn validate_loaded(&self) -> anyhow::Result<()> {
        self.validate()
    }
}

fn read_record<T: ConformingRecord>(path: &Path) -> anyhow::Result<T> {
    let bytes =
        filesystem::read_secure_regular_file(path, "registry record", false, MAX_RECORD_BYTES)
            .map_err(|error| {
                error.context(format!(
                    "{STATE_RESET_REQUIRED}: registry record is missing, unsafe to read, \
                     or exceeds the size limit ({})",
                    path.display()
                ))
            })?;
    let record = serde_json::from_slice::<T>(&bytes).map_err(|error| {
        anyhow::Error::new(error).context(format!(
            "{STATE_RESET_REQUIRED}: record does not parse as the current schema ({})",
            path.display()
        ))
    })?;
    record.validate_loaded().map_err(|error| {
        error.context(format!(
            "{STATE_RESET_REQUIRED}: record violates the current schema ({})",
            path.display()
        ))
    })?;
    Ok(record)
}

/// Platform user configuration directory that scopes all ctl local state:
/// `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `$HOME/.config` elsewhere.
pub(crate) fn config_root() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .with_context(|| "APPDATA is not set; cannot locate the user registry directory")
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            let path = PathBuf::from(xdg);
            if path.is_absolute() {
                return Ok(path);
            }
            bail!("XDG_CONFIG_HOME must be an absolute path");
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .with_context(|| "neither XDG_CONFIG_HOME nor HOME is set")?;
        Ok(home.join(".config"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> anyhow::Result<(filesystem::PrivateTempDir, RegistryStore)> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-registry-test")?;
        let store = RegistryStore::open(temp.path().join("registry"))?;
        Ok((temp, store))
    }

    #[test]
    fn local_host_is_created_exactly_once() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let first = store.ensure_local_host()?;
        let second = store.ensure_local_host()?;
        assert_eq!(first, second);
        assert_eq!(first.alias, LOCAL_HOST_ALIAS);
        assert_eq!(first.transport, HostTransport::Local);
        assert_eq!(store.list_hosts()?.len(), 1);
        Ok(())
    }

    #[test]
    fn corrupt_record_fails_closed_with_reset_code() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let host_file = store
            .root()
            .join("hosts")
            .join(format!("{}.json", host.host_id));
        filesystem::atomic_write(&host_file, b"{ not json", 0o600)?;
        let error = store.list_hosts().expect_err("corrupt record must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(STATE_RESET_REQUIRED), "{rendered}");
        assert!(
            rendered.contains(host_file.to_string_lossy().as_ref()),
            "{rendered}"
        );
        Ok(())
    }

    #[test]
    fn truncated_partial_record_fails_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let path = store
            .root()
            .join("hosts")
            .join(format!("{}.json", host.host_id));
        let bytes = serde_json::to_vec_pretty(&host)?;
        filesystem::atomic_write(&path, &bytes[..bytes.len() / 2], 0o600)?;
        let error = store.list_hosts().expect_err("partial record must fail");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));
        Ok(())
    }

    #[test]
    fn unknown_field_and_schema_mismatch_fail_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let path = store
            .root()
            .join("hosts")
            .join(format!("{}.json", host.host_id));

        let mut value: serde_json::Value = serde_json::to_value(&host)?;
        value
            .as_object_mut()
            .expect("host record serializes to an object")
            .insert("secret_extra".to_owned(), serde_json::Value::from("x"));
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&value)?, 0o600)?;
        let error = store.list_hosts().expect_err("unknown field must fail");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));

        value.as_object_mut().unwrap().remove("secret_extra");
        value["schema"] = serde_json::Value::from(REGISTRY_RECORD_SCHEMA + 7);
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&value)?, 0o600)?;
        let error = store.list_hosts().expect_err("schema mismatch must fail");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));
        Ok(())
    }

    #[test]
    fn oversize_record_fails_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let path = store
            .root()
            .join("hosts")
            .join(format!("{}.json", host.host_id));
        let mut padded = host.clone();
        padded.set_last_observation(ObservationCache {
            observed_at: Utc::now(),
            reachable: true,
            summary: "x".repeat((MAX_RECORD_BYTES + 4096) as usize),
        });
        let bytes = serde_json::to_vec_pretty(&padded)?;
        assert!(bytes.len() as u64 > MAX_RECORD_BYTES);
        filesystem::atomic_write(&path, &bytes, 0o600)?;
        let error = store.list_hosts().expect_err("oversize record must fail");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_record_is_rejected() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let real = std::env::temp_dir().join(format!(
            "nazoauthctl-registry-target-{}.json",
            uuid::Uuid::now_v7()
        ));
        filesystem::atomic_write(&real, &serde_json::to_vec_pretty(&host)?, 0o600)?;
        let link = store
            .root()
            .join("hosts")
            .join("00deadbeef-0000-7000-8000-000000000000.json");
        symlink(&real, &link).context("symlink creation requires a unix test environment")?;
        let error = store.list_hosts().expect_err("symlink must fail");
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        let _ = fs::remove_file(&real);
        Ok(())
    }

    #[test]
    fn duplicate_host_alias_is_rejected() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        store.ensure_local_host()?;
        let clash = HostRecord::new_ssh("server-a", "prod-a", HostPrivilege::Sudo)?;
        store.add_host(clash)?;
        let duplicate = HostRecord {
            host_id: Uuid::now_v7(),
            ..HostRecord::new_ssh("server-a", "prod-b", HostPrivilege::Direct)?
        };
        let error = store.add_host(duplicate).expect_err("duplicate alias");
        assert!(error.to_string().contains("duplicate host alias"));
        Ok(())
    }

    #[test]
    fn local_alias_cannot_be_reused_by_ssh_host() {
        let record = HostRecord::new_ssh(LOCAL_HOST_ALIAS, "prod-a", HostPrivilege::Sudo);
        assert!(record.is_err());
    }

    #[test]
    fn ssh_transport_rules_are_enforced() -> anyhow::Result<()> {
        let ssh = HostRecord::new_ssh("server-a", "prod-a", HostPrivilege::Sudo)?;
        assert_eq!(ssh.ssh_profile.as_deref(), Some("prod-a"));

        let mut missing_profile = ssh.clone();
        missing_profile.ssh_profile = None;
        assert!(
            missing_profile.validate().is_err(),
            "ssh host without profile"
        );

        // A local host must never carry an SSH profile.
        let mut local = HostRecord::new_local();
        local.ssh_profile = Some("prod-a".to_owned());
        assert!(local.validate().is_err(), "local host with a profile");
        local.ssh_profile = None;
        assert!(local.validate().is_ok());

        let mut local = HostRecord::new_local();
        local.remote_exec_path = Some("/usr/bin/nazoauthctl".to_owned());
        assert!(
            local.validate().is_err(),
            "remote exec path must be a basename"
        );
        local.remote_exec_path = Some("..".to_owned());
        assert!(local.validate().is_err());
        local.remote_exec_path = Some("nazoauthctl.exe".to_owned());
        assert!(local.validate().is_ok());
        Ok(())
    }

    #[test]
    fn duplicate_deployment_id_and_alias_are_rejected() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let issuer = "https://auth.example.com";
        store.add_instance(InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            issuer,
            "targets/deploy-alpha",
        )?)?;

        let same_deployment =
            InstanceRecord::new("deploy-alpha", "staging", host.host_id, issuer, "ref")?;
        let error = store
            .add_instance(same_deployment)
            .expect_err("duplicate deployment id");
        assert!(error.to_string().contains("duplicate deployment id"));

        let same_alias =
            InstanceRecord::new("deploy-beta", "production", host.host_id, issuer, "ref")?;
        let error = store.add_instance(same_alias).expect_err("duplicate alias");
        assert!(error.to_string().contains("duplicate instance alias"));
        Ok(())
    }

    #[test]
    fn instance_requires_known_host() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let orphan =
            InstanceRecord::new("deploy-x", "x", Uuid::now_v7(), "https://x.example", "r")?;
        let error = store.add_instance(orphan).expect_err("unknown host");
        assert!(error.to_string().contains("unknown host"));
        Ok(())
    }

    #[test]
    fn rename_instance_keeps_identity_and_bindings() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let mut instance = InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
            "targets/deploy-alpha",
        )?;
        instance.controller_id = Some("ctrl-key-1".to_owned());
        instance.controller_key_ref = Some("keys/deploy-alpha/controller".to_owned());
        store.add_instance(instance)?;

        let renamed = store.rename_instance("production", "auth-prod")?;
        assert_eq!(renamed.alias, "auth-prod");
        assert_eq!(renamed.deployment_id, "deploy-alpha");
        assert_eq!(renamed.host_id, host.host_id);
        assert_eq!(renamed.issuer, "https://auth.example.com");
        assert_eq!(renamed.controller_id.as_deref(), Some("ctrl-key-1"));
        assert_eq!(
            renamed.controller_key_ref.as_deref(),
            Some("keys/deploy-alpha/controller")
        );

        assert!(store.instance_by_alias("production")?.is_none());
        let fetched = store
            .instance_by_alias("auth-prod")?
            .expect("renamed record");
        assert_eq!(fetched, renamed);
        assert_eq!(store.list_instances()?.len(), 1);
        Ok(())
    }

    #[test]
    fn rename_host_keeps_identity_and_instance_binding() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        store.ensure_local_host()?;
        let host = store.add_host(HostRecord::new_ssh(
            "server-a",
            "prod-a",
            HostPrivilege::Sudo,
        )?)?;
        store.add_instance(InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
            "ref",
        )?)?;

        let renamed = store.rename_host("server-a", "server-a2")?;
        assert_eq!(renamed.host_id, host.host_id);
        assert_eq!(renamed.ssh_profile.as_deref(), Some("prod-a"));
        assert!(store.host_by_alias("server-a")?.is_none());

        let instance = store.instance_by_alias("production")?.expect("instance");
        let resolved_host = store.host_by_alias("server-a2")?.expect("renamed host");
        assert_eq!(instance.host_id, resolved_host.host_id);

        // The reserved local alias cannot be moved away.
        let error = store
            .rename_host(LOCAL_HOST_ALIAS, "control-machine")
            .expect_err("reserved");
        assert!(error.to_string().contains("reserved"), "{error}");
        assert!(store.host_by_alias(LOCAL_HOST_ALIAS)?.is_some());
        Ok(())
    }

    #[test]
    fn update_controller_binding_round_trips_and_clears() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        store.add_instance(InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
            "ref",
        )?)?;

        let bound = store.update_controller_binding(
            "deploy-alpha",
            Some("01900000-0000-7000-8000-00000000000a"),
            Some("controller-keys/deploy-alpha"),
        )?;
        assert_eq!(
            bound.controller_id.as_deref(),
            Some("01900000-0000-7000-8000-00000000000a")
        );
        assert_eq!(
            bound.controller_key_ref.as_deref(),
            Some("controller-keys/deploy-alpha")
        );

        // Clearing keeps every other fact intact.
        let cleared = store.update_controller_binding("deploy-alpha", None, None)?;
        assert!(cleared.controller_id.is_none());
        assert!(cleared.controller_key_ref.is_none());
        assert_eq!(cleared.deployment_id, "deploy-alpha");
        assert_eq!(cleared.alias, "production");

        // Embedded key material stays rejected through this path too.
        assert!(
            store
                .update_controller_binding(
                    "deploy-alpha",
                    Some("c"),
                    Some("-----BEGIN PRIVATE KEY-----")
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn controller_key_ref_never_accepts_key_material() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let host = store.ensure_local_host()?;
        let mut instance = InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
            "ref",
        )?;

        instance.controller_key_ref = Some("-----BEGIN PRIVATE KEY-----".to_owned());
        let error = instance.validate().expect_err("key material rejected");
        assert!(error.to_string().contains("controller key ref"), "{error}");

        // Same guard for a marker without separators that would pass the
        // generic reference-shape check.
        instance.controller_key_ref = Some("store/-----BEGINPRIVATEKEY".to_owned());
        let error = instance.validate().expect_err("marker rejected");
        assert!(
            error
                .to_string()
                .contains("reference, not embedded key material"),
            "{error}"
        );
        Ok(())
    }

    // ---------- B04 controlled registration / evidence ----------

    fn evidence_for(host: &HostRecord) -> DiscoveryEvidence {
        let hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
        DiscoveryEvidence::new(host, hello, "deploy-alpha", "https://auth.example.com")
            .expect("valid evidence")
    }

    #[test]
    fn register_instance_persists_the_controlled_binding_with_first_observation() {
        let (_temp, store) = test_store().unwrap();
        let host = store.ensure_local_host().unwrap();
        let evidence = evidence_for(&host);

        let record = store
            .register_instance(&evidence, None, ObservationCache::now(true, "observed"))
            .expect("controlled registration");
        assert_eq!(record.alias, "deploy-alpha", "alias defaults to the id");
        assert_eq!(record.deployment_id, "deploy-alpha");
        assert_eq!(record.host_id, host.host_id);
        assert_eq!(record.issuer, "https://auth.example.com");
        assert!(record.last_observation.is_some(), "first cache entry");
        assert_eq!(store.list_instances().unwrap().len(), 1);

        let explicit = store
            .register_instance(
                &evidence,
                Some("prod"),
                ObservationCache::now(true, "again"),
            )
            .expect_err("duplicate deployment");
        assert!(explicit.to_string().contains("relocate"), "{explicit}");
    }

    #[test]
    fn register_instance_rejects_unknown_and_drifted_hosts() {
        let (_temp, store) = test_store().unwrap();
        let host = store.ensure_local_host().unwrap();
        let mut evidence = evidence_for(&host);

        evidence.host_id = uuid::Uuid::now_v7();
        let error = store
            .register_instance(&evidence, None, ObservationCache::now(true, "x"))
            .expect_err("unknown host");
        assert!(error.to_string().contains("unknown host"), "{error}");

        evidence = evidence_for(&host);
        evidence.host_alias = "renamed".to_owned();
        let error = store
            .register_instance(&evidence, None, ObservationCache::now(true, "x"))
            .expect_err("drifted alias");
        assert!(error.to_string().contains("drifted"), "{error}");
    }

    #[test]
    fn discovery_evidence_validation_fails_closed() {
        let (_temp, store) = test_store().unwrap();
        let host = store.ensure_local_host().unwrap();
        let good = evidence_for(&host);

        for mutate in [
            |e: &mut DiscoveryEvidence| e.schema += 1,
            |e: &mut DiscoveryEvidence| {
                e.evidence = "hand-typed".to_owned();
            },
            |e: &mut DiscoveryEvidence| {
                e.hello.version = "0.0.1-old".to_owned();
            },
            |e: &mut DiscoveryEvidence| {
                e.deployment.deployment_id = String::new();
            },
            |e: &mut DiscoveryEvidence| {
                e.deployment.issuer = "ftp://auth.example.com".to_owned();
            },
        ] {
            let mut broken = good.clone();
            mutate(&mut broken);
            assert!(
                store
                    .register_instance(&broken, None, ObservationCache::now(true, "x"))
                    .is_err(),
                "evidence must fail closed"
            );
        }

        let raw = serde_json::to_vec_pretty(&good).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("hand_written".to_owned(), serde_json::Value::from(true));
        assert!(
            serde_json::from_value::<DiscoveryEvidence>(value).is_err(),
            "unknown fields are denied"
        );
    }

    // ---------- B03/B07 forget constraints ----------

    #[test]
    fn forget_host_defaults_to_rejecting_referenced_instances() {
        let (_temp, store) = test_store().unwrap();
        store.ensure_local_host().unwrap();
        let host = store
            .add_host(HostRecord::new_ssh("server-a", "prod-a", HostPrivilege::Sudo).unwrap())
            .unwrap();
        store
            .add_instance(
                InstanceRecord::new(
                    "deploy-alpha",
                    "production",
                    host.host_id,
                    "https://auth.example.com",
                    "ref",
                )
                .unwrap(),
            )
            .unwrap();

        let error = store.forget_host("server-a", false).expect_err("blocked");
        let rendered = error.to_string();
        assert!(rendered.contains("--cascade"), "{rendered}");
        assert!(rendered.contains("never"), "{rendered}");
        assert!(store.host_by_alias("server-a").unwrap().is_some());
        assert_eq!(store.list_instances().unwrap().len(), 1);

        let (forgotten, removed) = store.forget_host("server-a", true).unwrap();
        assert_eq!(forgotten.host_id, host.host_id);
        assert_eq!(removed.len(), 1);
        assert!(store.host_by_alias("server-a").unwrap().is_none());
        assert!(store.list_instances().unwrap().is_empty());

        assert!(store.forget_host("server-a", false).is_err(), "unknown");
        assert!(
            store.forget_host(LOCAL_HOST_ALIAS, true).is_err(),
            "built-in local host cannot be forgotten"
        );
        assert!(store.host_by_alias(LOCAL_HOST_ALIAS).unwrap().is_some());
    }

    #[test]
    fn observation_writers_preserve_every_other_field() {
        let (_temp, store) = test_store().unwrap();
        let host = store.ensure_local_host().unwrap();
        let mut instance = InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
            "target-state/x",
        )
        .unwrap();
        instance.controller_key_ref = Some("keys/alpha".to_owned());
        store.add_instance(instance).unwrap();

        store
            .set_host_observation(host.host_id, ObservationCache::now(false, "unreachable"))
            .unwrap();
        store
            .set_instance_observation(
                "deploy-alpha",
                ObservationCache::now(true, "helper verified"),
            )
            .unwrap();

        let host = store.host_by_alias(LOCAL_HOST_ALIAS).unwrap().unwrap();
        let observation = host.last_observation.expect("host cache written");
        assert!(!observation.reachable);

        let instance = store.instance_by_alias("production").unwrap().unwrap();
        assert_eq!(
            instance.controller_key_ref.as_deref(),
            Some("keys/alpha"),
            "cache writes must not disturb bindings"
        );
        assert!(
            instance
                .last_observation
                .expect("instance cache written")
                .reachable
        );

        assert!(
            store
                .set_instance_observation("missing", ObservationCache::now(true, "x"))
                .is_err()
        );
    }

    #[test]
    fn relocate_instance_rebinds_host_and_clears_stale_cache() {
        let (_temp, store) = test_store().unwrap();
        let old = store.ensure_local_host().unwrap();
        let new_host = store
            .add_host(HostRecord::new_ssh("server-b", "prod-b", HostPrivilege::Direct).unwrap())
            .unwrap();
        let mut record = InstanceRecord::new(
            "deploy-alpha",
            "production",
            old.host_id,
            "https://auth.example.com",
            "target-state/x",
        )
        .unwrap();
        record.last_observation = Some(ObservationCache::now(true, "old host view"));
        store.add_instance(record).unwrap();

        let moved = store
            .relocate_instance("deploy-alpha", new_host.host_id)
            .unwrap();
        assert_eq!(moved.host_id, new_host.host_id);
        assert!(moved.last_observation.is_none(), "old-host cache dropped");

        assert!(
            store
                .relocate_instance("deploy-alpha", new_host.host_id)
                .is_err(),
            "same host relocation rejected"
        );
        assert!(
            store
                .relocate_instance("deploy-alpha", uuid::Uuid::now_v7())
                .is_err(),
            "unknown target host rejected"
        );
        assert!(
            store.relocate_instance("missing", old.host_id).is_err(),
            "unknown instance rejected"
        );
    }
}
