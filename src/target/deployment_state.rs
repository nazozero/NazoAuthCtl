//! Target-side DeploymentState: the lifecycle authority on the target host
//! (goal plan 06 §2, tasks F01/F02/F04; authority ADR row 4).
//!
//! One typed JSON document per deployment lives beside that deployment's
//! operation journal under the formalized target state root:
//!
//! ```text
//! <target state root>            (%ProgramData%\nazauthctl\target-state on
//!                                Windows, /var/lib/nazauthctl/target-state on
//!                                Linux, NAZOAUTHCTL_TARGET_STATE_ROOT override)
//!   deployments/
//!     <deployment_id>/           one directory per real deployment
//!       state.json               this module's DeploymentState document
//!       operations.jsonl         the C07 host-operation journal (same scope)
//! ```
//!
//! This freezes `TargetJournal::path_for`: the per-scope layout is
//! `deployments/<scope>/operations.jsonl`, and the state document shares that
//! exact directory. Nothing else may construct these paths.
//!
//! Ownership model (goal plan 06 §3, converged by H06): resources are
//! concrete `resource_id/kind/locator` facts classified only by `ownership`
//! (managed/external) and `scope` (deployment/shared). There are no
//! capability enums, no permits_mutation matrices, and no trust states. Hard
//! rules enforced at construction *and* load time:
//!
//! - `managed + shared` is unrepresentable — rejected as a schema violation;
//! - destructive paths may touch exactly `managed + deployment` resources;
//!   external and shared resources have zero-delete paths ([`Failure`] with
//!   [`EXTERNAL_RESOURCE_PROTECTED`]);
//! - admin identity never changes ownership.
//!
//! External/shared PostgreSQL, Valkey, proxy, DNS, or KMS objects are owned by
//! their own platforms: ctl records ONLY the reference facts above (locator +
//! scope). It runs no health gating over them, manages none of their secrets,
//! and exercises no lifecycle control on their paths — uninstall plans print
//! them as kept and nothing else. Connection facts (URLs, principals,
//! credentials) live in NazoAuth's own configuration under the config CAS
//! revision, never in DeploymentState or the control-side Registry; no
//! endpoint/principal digest matrix exists anywhere on these target-side
//! paths.
//!
//! Concurrency is one explicit fact (F04): the monotonic
//! [`ConfigState::revision`]. Every mutation carries the expected revision;
//! a mismatch fails closed with [`CONFIG_REVISION_MISMATCH`] and never
//! last-write-wins. Mutations record their `operation_id` in
//! [`DeploymentState::active_host_operation`], which makes an interrupted
//! apply resumable by re-execution instead of double-applied. The window
//! between "state written" and "terminal journal line appended" resolves to
//! an explicit revision mismatch on retry — fail-closed reconciliation by a
//! fresh inspect, never silent re-application.
//!
//! Store conventions match every other ctl store: atomic writes, secure
//! regular-file reads with size caps, `deny_unknown_fields` plus an explicit
//! schema discriminator, exclusive fs2 locking for read-modify-write, and
//! fail-closed errors. A document that does not parse as the current schema
//! fails with the stable [`crate::registry::STATE_RESET_REQUIRED`] code
//! naming the file; there is no lenient reader and no conversion.

use std::path::{Path, PathBuf};

use anyhow::bail;
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::filesystem;
use crate::registry::{STATE_RESET_REQUIRED, validate_issuer};

use super::install_exec::InstallOrder;
use super::journal;

/// Schema discriminator carried by the persisted DeploymentState document.
pub const DEPLOYMENT_STATE_SCHEMA: u32 = 1;

/// Upper bound for one persisted DeploymentState document (~1 MiB).
const MAX_STATE_BYTES: u64 = 1024 * 1024;

/// Maximum number of concrete resources one deployment may declare.
pub const MAX_RESOURCES: usize = 64;

/// Upper bound for one discovery sweep (task G05): a target holding more
/// deployments than this fails the listing closed instead of silently
/// truncating discovery output.
pub const MAX_LISTED_DEPLOYMENTS: usize = 256;

/// Stable failure code: a discovery sweep exceeded
/// [`MAX_LISTED_DEPLOYMENTS`]; nothing is truncated away silently.
pub const DEPLOYMENT_LIMIT_EXCEEDED: &str = "DEPLOYMENT_LIMIT_EXCEEDED";

/// Stable failure code: no DeploymentState exists for the addressed
/// deployment id on this target.
pub const DEPLOYMENT_UNKNOWN: &str = "DEPLOYMENT_UNKNOWN";

/// Stable failure code: a DeploymentState already exists where bootstrap
/// tried to create one. Existing state is never silently overwritten.
pub const DEPLOYMENT_EXISTS: &str = "DEPLOYMENT_EXISTS";

/// Stable failure code: the named resource is not part of the deployment's
/// declared resources.
pub const RESOURCE_UNKNOWN: &str = "RESOURCE_UNKNOWN";

/// Stable failure code: the resource exists but has zero-delete protection
/// (external ownership, or a shared resource of any kind).
pub const EXTERNAL_RESOURCE_PROTECTED: &str = "EXTERNAL_RESOURCE_PROTECTED";

/// Stable failure code: config/state CAS mismatch (goal plan 06 F04). The
/// caller must re-read live state and rebuild its intent; last-write-wins
/// does not exist.
///
/// Canonical name lives in [`crate::error_codes`]; re-exported here so the
/// historical call sites keep one stable path.
pub use crate::error_codes::CONFIG_REVISION_MISMATCH;

/// Stable failure code: a clean-install execution order failed on the target
/// and the target rolled its own partial work back. The DeploymentState was
/// never created; the journal carries the failure for the resume decision.
pub const INSTALL_FAILED: &str = "INSTALL_FAILED";

/// Stable failure code: a rollback was requested but no previous verified
/// artifact reference exists to restore (goal plan 07 §5). Rollback is an
/// explicit action over saved facts only; it never guesses.
pub const ROLLBACK_UNAVAILABLE: &str = "ROLLBACK_UNAVAILABLE";

/// Stable failure code: a planned deletion (or runtime identity hook)
/// disagrees with the live target facts — declared locator drift, a foreign
/// runtime object under the managed name, or an unsupported physical kind.
/// Nothing is deleted when this fires.
pub const OBJECT_IDENTITY_MISMATCH: &str = "OBJECT_IDENTITY_MISMATCH";

/// A stable, bounded failure outcome produced by state operations and mapped
/// onto [`super::wire::HostOutcome::Failed`] by dispatch. Codes come from the
/// closed set above; details quote only validated identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub code: &'static str,
    pub detail: String,
}

impl Failure {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl From<Failure> for anyhow::Error {
    fn from(failure: Failure) -> Self {
        anyhow::anyhow!("{}: {}", failure.code, failure.detail)
    }
}

/// Concrete ownership classification (goal plan 06 §3). No capability
/// semantics attach to these values: they are facts about who owns the
/// object, not permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceOwnership {
    /// Created and exclusively governed by this ctl deployment.
    Managed,
    /// Pre-existing or shared infrastructure this deployment only references.
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceScope {
    /// Dedicated to exactly this deployment.
    Deployment,
    /// Shared beyond this deployment; always external (schema-enforced).
    Shared,
}

/// One concrete resource fact: stable id, kind, locator, and its
/// ownership + scope classification. Secrets live elsewhere by reference
/// only; nothing here is authorization material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub resource_id: String,
    /// Closed-vocabulary token describing the object class (for example
    /// `postgres`, `valkey`, `proxy`). Not a capability.
    pub kind: String,
    /// Concrete locator of the object (name/unit/URL) used to re-confirm
    /// object identity before any destructive step.
    pub locator: String,
    pub ownership: ResourceOwnership,
    pub scope: ResourceScope,
}

impl Resource {
    pub fn new(
        resource_id: impl Into<String>,
        kind: impl Into<String>,
        locator: impl Into<String>,
        ownership: ResourceOwnership,
        scope: ResourceScope,
    ) -> anyhow::Result<Self> {
        let resource = Self {
            resource_id: resource_id.into(),
            kind: kind.into(),
            locator: locator.into(),
            ownership,
            scope,
        };
        resource.validate()?;
        Ok(resource)
    }

    /// Enforce every invariant the schema relies on, including the
    /// managed+shared prohibition. Called by constructors and again after
    /// deserialization so hand-written JSON cannot smuggle the combination in.
    pub fn validate(&self) -> anyhow::Result<()> {
        crate::registry::validate_identifier(&self.resource_id, 128, "resource id")?;
        crate::registry::validate_identifier(&self.kind, 64, "resource kind")?;
        if self.locator.is_empty()
            || self.locator.len() > 512
            || self
                .locator
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            bail!("resource locator must be a single-line reference of at most 512 characters");
        }
        if self.ownership == ResourceOwnership::Managed && self.scope == ResourceScope::Shared {
            bail!("managed + shared resources are not supported; shared resources are external");
        }
        Ok(())
    }
}

/// The runtime surface this deployment runs on. Recorded facts only — the
/// lifecycle waves (G) own how objects are driven.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSurface {
    /// Runtime class token (`podman`, `docker`, `host`, ...).
    pub kind: String,
    /// Concrete object name (container name or systemd unit).
    pub object: String,
}

impl RuntimeSurface {
    pub fn new(kind: impl Into<String>, object: impl Into<String>) -> anyhow::Result<Self> {
        let surface = Self {
            kind: kind.into(),
            object: object.into(),
        };
        if surface.kind.is_empty() || surface.kind.len() > 32 {
            bail!("runtime kind must be 1-32 characters");
        }
        if !surface
            .kind
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
        {
            bail!("runtime kind must be alphanumeric tokens");
        }
        if surface.object.is_empty()
            || surface.object.len() > 256
            || surface
                .object
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            bail!("runtime object must be a single-line name of at most 256 characters");
        }
        Ok(surface)
    }
}

/// Artifact revision references (digest handles), current and previous.
/// Content-addressed references only; verification happens before these are
/// ever written, never inside this module.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
}

impl ArtifactRefs {
    pub fn validate(&self) -> anyhow::Result<()> {
        for reference in [&self.current, &self.previous].into_iter().flatten() {
            crate::registry::validate_identifier(reference, 256, "artifact reference")?;
        }
        Ok(())
    }
}

/// Config state with the single monotonic CAS revision (goal plan 06 §4).
/// The reference points at the config source; secrets appear only as
/// references, never values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigState {
    pub reference: String,
    pub schema: String,
    pub revision: u64,
}

impl ConfigState {
    fn seed(revision: u64, reference: String, schema: String) -> anyhow::Result<Self> {
        let candidate = Self {
            revision,
            reference,
            schema,
        };
        if candidate.reference.is_empty() || candidate.reference.len() > 512 {
            bail!("config reference must be 1-512 characters");
        }
        crate::registry::validate_identifier(&candidate.schema, 64, "config schema")?;
        Ok(candidate)
    }

    fn advance(&mut self, reference: String, schema: String) -> anyhow::Result<()> {
        let seeded = Self::seed(self.revision + 1, reference, schema)?;
        *self = seeded;
        Ok(())
    }
}

/// Target-local health record backing `read_health`. Written by whoever can
/// actually observe the runtime; inspection reports it verbatim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRecord {
    pub healthy: bool,
    pub summary: String,
    pub checked_at: DateTime<Utc>,
}

/// Backup/DR maturity of one deployment (goal plan 08 §5, task H05). This is
/// an INFORMATIONAL maturity fact only: it records what explicit backup
/// operations have reported, and nothing in install, update, rollback,
/// uninstall, status, or doctor ever requires, blocks on, or gates through it
/// (goal plan README hard constraint: backup/DR never becomes a default gate;
/// item 16 of the goal definition). There is deliberately no restore-rehearsal
/// machinery behind it — a rehearsal that returns would re-create the deleted
/// global recovery gate (A04 §5).
///
/// Transitions are written ONLY through
/// [`TargetStateStore::record_backup_maturity`] by explicit backup operations
/// under the same operation-ownership discipline as health observations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BackupMaturity {
    /// No explicit backup operation has ever reported for this deployment.
    /// The initial state of every fresh DeploymentState.
    #[default]
    Unknown,
    /// An explicit backup operation reported that no usable data backup is
    /// configured for this deployment.
    NotConfigured { observed_at: DateTime<Utc> },
    /// An explicit backup operation recorded a configured data backup.
    Configured { observed_at: DateTime<Utc> },
    /// An explicit backup operation verified restorability (for example a
    /// restore check performed by the backup tooling itself) at that time.
    Verified { observed_at: DateTime<Utc> },
}

impl BackupMaturity {
    /// Stable lowercase token used by status/doctor style displays.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotConfigured { .. } => "not-configured",
            Self::Configured { .. } => "configured",
            Self::Verified { .. } => "verified",
        }
    }

    /// The observation timestamp of the reporting operation, when one exists.
    pub fn observed_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Unknown => None,
            Self::NotConfigured { observed_at }
            | Self::Configured { observed_at }
            | Self::Verified { observed_at } => Some(*observed_at),
        }
    }
}

/// Embedded build identity of one deployed artifact, recorded by whoever
/// performed the on-target official verification (goal plan 07 G03): the
/// ControlOperation envelope's J1 binding needs these facts, so they live in
/// the target lifecycle authority next to the artifact references they
/// belong to. Optional because adopted deployments may not know them yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub product: String,
    pub version: String,
    pub commit: String,
}

/// The server product token every NazoAuth build identity carries.
pub const BUILD_IDENTITY_PRODUCT: &str = "nazauth";

impl BuildIdentity {
    pub fn new(product: &str, version: &str, commit: &str) -> anyhow::Result<Self> {
        let identity = Self {
            product: product.to_owned(),
            version: version.to_owned(),
            commit: commit.to_owned(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        crate::registry::validate_identifier(&self.product, 64, "build identity product")?;
        crate::registry::validate_identifier(&self.version, 64, "build identity version")?;
        crate::registry::validate_identifier(&self.commit, 128, "build identity commit")?;
        Ok(())
    }
}

/// Reference to the host operation that produced the current state revision
/// (the journal index required by goal plan 06 §2). This is a pointer into
/// the C07 journal — never a second copy of journal state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveHostOperationRef {
    pub operation_id: String,
    pub applied_at: DateTime<Utc>,
}

/// The target-side lifecycle source of truth (goal plan 06 §2). The control
/// machine's Registry holds only `deployment_id` references and observation
/// caches; nothing here may be reconstructed from those caches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentState {
    pub schema: u32,
    pub deployment_id: String,
    pub issuer: String,
    pub runtime: RuntimeSurface,
    pub artifact: ArtifactRefs,
    pub config: ConfigState,
    pub resources: Vec<Resource>,
    pub local_health: HealthRecord,
    /// Backup/DR maturity (H05): informational only, updated exclusively by
    /// explicit backup operations, never consulted by lifecycle gating.
    #[serde(default)]
    pub backup_maturity: BackupMaturity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_host_operation: Option<ActiveHostOperationRef>,
    /// Embedded build identity of `artifact.current`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_build_identity: Option<BuildIdentity>,
    /// Embedded build identity of `artifact.previous`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_build_identity: Option<BuildIdentity>,
}

impl DeploymentState {
    /// Validate every structural invariant beyond serde's field checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != DEPLOYMENT_STATE_SCHEMA {
            bail!(
                "unsupported DeploymentState schema {} (expected {DEPLOYMENT_STATE_SCHEMA})",
                self.schema
            );
        }
        journal::deployment_scope(&self.deployment_id)?;
        validate_issuer(&self.issuer)?;
        RuntimeSurface::new(self.runtime.kind.clone(), self.runtime.object.clone())?;
        self.artifact.validate()?;
        if self.config.reference.is_empty() || self.config.reference.len() > 512 {
            bail!("config reference must be 1-512 characters");
        }
        crate::registry::validate_identifier(&self.config.schema, 64, "config schema")?;
        if self.config.revision == 0 {
            bail!("config revision is monotonic from 1");
        }
        if self.resources.len() > MAX_RESOURCES {
            bail!(
                "a deployment declares at most {MAX_RESOURCES} resources (found {})",
                self.resources.len()
            );
        }
        let mut seen = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            resource.validate()?;
            if seen.contains(&resource.resource_id) {
                bail!("duplicate resource id '{}'", resource.resource_id);
            }
            seen.push(resource.resource_id.clone());
        }
        if self.local_health.summary.len() > 512 {
            bail!("health summary must be at most 512 characters");
        }
        if let Some(active) = &self.active_host_operation
            && (active.operation_id.is_empty() || active.operation_id.len() > 128)
        {
            bail!("active_host_operation.operation_id is not a valid token");
        }
        for identity in [&self.current_build_identity, &self.previous_build_identity]
            .into_iter()
            .flatten()
        {
            identity.validate()?;
        }
        Ok(())
    }

    /// Resolve the exact resource a destructive action names. Only
    /// `managed + deployment` passes; everything else fails closed with the
    /// stable zero-delete codes (goal plan 06 F03). Object-identity
    /// reconfirmation against the runtime remains the caller's next step.
    pub fn exact_managed_deployment_resource(
        &self,
        resource_id: &str,
    ) -> Result<&Resource, Failure> {
        let Some(resource) = self
            .resources
            .iter()
            .find(|resource| resource.resource_id == resource_id)
        else {
            return Err(Failure::new(
                RESOURCE_UNKNOWN,
                format!("no resource '{resource_id}' is declared by this deployment"),
            ));
        };
        match (resource.ownership, resource.scope) {
            (ResourceOwnership::Managed, ResourceScope::Deployment) => Ok(resource),
            (ResourceOwnership::External, _) => Err(Failure::new(
                EXTERNAL_RESOURCE_PROTECTED,
                format!(
                    "resource '{}' is external; external resources have zero-delete paths",
                    resource.resource_id
                ),
            )),
            // Unreachable through the schema, but fail closed rather than trust it.
            (ResourceOwnership::Managed, ResourceScope::Shared) => Err(Failure::new(
                EXTERNAL_RESOURCE_PROTECTED,
                format!(
                    "resource '{}' is shared; shared resources have zero-delete paths",
                    resource.resource_id
                ),
            )),
        }
    }
}

/// The closed set of DeploymentState mutations (task F01). Deliberately
/// minimal: bootstrap creates the initial document, apply-config is the one
/// CAS-guarded config mutation. Lifecycle waves (G) extend this set; nothing
/// here ever deletes a resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mutation", rename_all = "kebab-case", deny_unknown_fields)]
// The G01 install order makes Bootstrap deliberately the dominant variant;
// StateMutationPayload is a short-lived wire value where an indirection would
// buy nothing but churn at every match site (same call as HostOutcome).
#[allow(clippy::large_enum_variant)]
pub enum StateMutationPayload {
    /// Create fresh state at revision 1. Fails with `DEPLOYMENT_EXISTS`
    /// over any existing state.
    ///
    /// The G01 clean-install wave extends the bare seed with an optional
    /// [`InstallOrder`]: when present, the target executes the full
    /// fresh-install sequence (verify artifact → atomic config write →
    /// fresh-install setup → start runtime → identity + health) *before* the
    /// state document is created, and only a fully healthy target commits
    /// `local_healthy` state. Replay of an interrupted bootstrap re-runs the
    /// resumable order and then replays the stored state.
    Bootstrap {
        issuer: String,
        runtime: RuntimeSurface,
        artifact: ArtifactRefs,
        config_reference: String,
        config_schema: String,
        resources: Vec<Resource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        install: Option<InstallOrder>,
    },
    /// CAS-guarded config application (goal plan 06 §4): load current →
    /// build candidate → validate → commit against `expected_revision`.
    ApplyConfig { reference: String, schema: String },
    /// Lifecycle update (G03): stage the digest-pinned official artifact,
    /// swap `previous=current`, optionally apply a staged config, activate,
    /// probe local health, then commit — all inside this one journaled
    /// operation so an interrupted attempt resumes without repeating side
    /// effects. The ControlOperation for the application migration is
    /// dispatched separately by the control side (one pre-signed envelope).
    Update {
        artifact: super::install_exec::OfficialArtifactRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<super::install_exec::StagedConfig>,
    },
    /// Explicit rollback to the previous verified artifact reference (G04).
    /// Never runs application mutations and never touches data restore.
    Rollback {},
    /// Uninstall (G06): delete exactly the planned managed+deployment
    /// resources after target-side identity re-confirmation, remove the
    /// runtime object and config file, and drop the state document.
    /// External/shared resources have zero-delete paths by construction.
    Uninstall {
        resources: Vec<super::install_exec::PlannedResourceDeletion>,
    },
}

/// Caller-supplied content for bootstrapping one fresh DeploymentState.
/// Mirrors the flat fields of `StateMutationPayload::Bootstrap` so the wire
/// shape stays stable while the store API stays readable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapParams {
    pub issuer: String,
    pub runtime: RuntimeSurface,
    pub artifact: ArtifactRefs,
    pub config_reference: String,
    pub config_schema: String,
    pub resources: Vec<Resource>,
    /// Embedded build identity of the verified artifact when its official
    /// verification already produced these facts on the target (G01).
    pub current_build_identity: Option<BuildIdentity>,
}

/// Handle to one target's DeploymentState store rooted at the formalized
/// target state root. Path construction stays inside this type.
#[derive(Clone, Debug)]
pub struct TargetStateStore {
    root: PathBuf,
}

impl TargetStateStore {
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        filesystem::ensure_private_directory(&root, "target state root")?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The per-deployment scope directory (state document + journal +
    /// fresh-install bootstrap material). Path construction stays inside the
    /// target modules.
    pub(crate) fn scope_dir(&self, deployment_id: &str) -> Result<PathBuf, Failure> {
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        Ok(scope_path(&self.root, &scope))
    }

    /// The single decision point for where one deployment's state document
    /// lives: beside its operation journal in the same scope directory.
    fn state_path(&self, scope: &str) -> PathBuf {
        self.root.join("deployments").join(scope).join("state.json")
    }

    /// Load one deployment's state, failing with [`DEPLOYMENT_UNKNOWN`] when
    /// absent and with `STATE_RESET_REQUIRED` when present but non-conforming.
    /// This is the live re-resolve entry point every mutation and inspection
    /// flows through; caches are never consulted here.
    pub fn load_existing(&self, deployment_id: &str) -> Result<DeploymentState, Failure> {
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        let path = self.state_path(&scope);
        let bytes = filesystem::read_secure_regular_file(
            &path,
            "target DeploymentState",
            false,
            MAX_STATE_BYTES,
        )
        .map_err(|error| unreadable_state(deployment_id, &path, &error))?;
        let state: DeploymentState =
            serde_json::from_slice(&bytes).map_err(|error| invalid_state(&path, &error))?;
        state
            .validate()
            .map_err(|error| invalid_state(&path, &error))?;
        Ok(state)
    }

    /// Enumerate every deployment whose state document exists under this root
    /// (task G05), sorted by deployment id for deterministic discovery
    /// output. Directories without a `state.json` — the host-level journal
    /// scope, or a scope left behind by an interrupted install that never
    /// committed — are not deployments. A directory that claims a state
    /// document which fails to load fails the whole sweep closed with the
    /// same stable codes as [`Self::load_existing`]: discovery exists exactly
    /// to surface broken target state, so corruption is never skipped over.
    pub fn list_deployments(&self) -> Result<Vec<DeploymentState>, Failure> {
        let deployments_dir = self.root.join("deployments");
        let entries = match std::fs::read_dir(&deployments_dir) {
            Ok(entries) => entries.collect::<Result<Vec<_>, _>>().map_err(|error| {
                Failure::new(
                    DEPLOYMENT_UNKNOWN,
                    format!("failed to list {}: {error}", deployments_dir.display()),
                )
            })?,
            // A fresh target has no deployments directory yet: zero findings.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(Failure::new(
                    DEPLOYMENT_UNKNOWN,
                    format!("failed to list {}: {error}", deployments_dir.display()),
                ));
            }
        };
        let mut scopes: Vec<String> = Vec::new();
        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if !path.join("state.json").is_file() {
                continue;
            }
            match path.file_name().and_then(|name| name.to_str()) {
                Some(scope) => scopes.push(scope.to_owned()),
                None => scopes.push(String::from("")),
            }
        }
        scopes.sort();
        let mut states = Vec::with_capacity(scopes.len());
        for scope in scopes {
            if states.len() >= MAX_LISTED_DEPLOYMENTS {
                return Err(Failure::new(
                    DEPLOYMENT_LIMIT_EXCEEDED,
                    format!(
                        "this target holds more than {MAX_LISTED_DEPLOYMENTS} deployments; \
                         split or retire hosts instead of truncating discovery output"
                    ),
                ));
            }
            states.push(self.load_existing(&scope)?);
        }
        Ok(states)
    }

    /// Bootstrap (F01): create the initial state document for a fresh
    /// deployment at revision 1. Re-executing the same interrupted bootstrap
    /// replays the stored state; bootstrapping over different existing state
    /// fails with [`DEPLOYMENT_EXISTS`].
    pub fn bootstrap(
        &self,
        deployment_id: &str,
        params: BootstrapParams,
        operation_id: &str,
    ) -> Result<DeploymentState, Failure> {
        let BootstrapParams {
            issuer,
            runtime,
            artifact,
            config_reference,
            config_schema,
            resources,
            current_build_identity,
        } = params;
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        if let Ok(existing) = self.load_existing(deployment_id) {
            if existing
                .active_host_operation
                .as_ref()
                .is_some_and(|active| active.operation_id == operation_id)
            {
                return Ok(existing);
            }
            return Err(Failure::new(
                DEPLOYMENT_EXISTS,
                format!(
                    "a DeploymentState already exists for '{deployment_id}' at revision {}; \
                     bootstrap never overwrites existing state",
                    existing.config.revision
                ),
            ));
        }
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        let config = ConfigState::seed(1, config_reference, config_schema).map_err(|error| {
            Failure::new(super::wire::HOST_ERR_OPERATION_INVALID, error.to_string())
        })?;
        let state = DeploymentState {
            schema: DEPLOYMENT_STATE_SCHEMA,
            deployment_id: deployment_id.to_owned(),
            issuer,
            active_host_operation: Some(ActiveHostOperationRef {
                operation_id: operation_id.to_owned(),
                applied_at: Utc::now(),
            }),
            runtime,
            artifact,
            config,
            resources,
            local_health: HealthRecord {
                healthy: false,
                summary: "bootstrapped; runtime health not yet observed".to_owned(),
                checked_at: Utc::now(),
            },
            backup_maturity: BackupMaturity::Unknown,
            current_build_identity,
            previous_build_identity: None,
        };
        state.validate().map_err(|error| {
            Failure::new(super::wire::HOST_ERR_OPERATION_INVALID, error.to_string())
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(state)
    }

    /// Apply a config change under revision CAS (F04). `expected_revision`
    /// must equal the current revision; success advances it by exactly one
    /// and records this operation as the producing one. Re-executing an
    /// interrupted apply replays without advancing again.
    pub fn apply_config(
        &self,
        deployment_id: &str,
        expected_revision: u64,
        reference: String,
        schema: String,
        operation_id: &str,
    ) -> Result<ConfigState, Failure> {
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let mut state = self.load_existing(deployment_id)?;
        if state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id)
        {
            return Ok(state.config);
        }
        if state.config.revision != expected_revision {
            return Err(Failure::new(
                CONFIG_REVISION_MISMATCH,
                format!(
                    "expected config revision {expected_revision} but target holds revision {} \
                     for '{deployment_id}'; re-read the live state and rebuild the change",
                    state.config.revision
                ),
            ));
        }
        // Drift discipline: the candidate is built from the just-loaded live
        // state and committed atomically — caches are never consulted here.
        state
            .config
            .advance(reference, schema)
            .map_err(|error| Failure::new(CONFIG_REVISION_MISMATCH, error.to_string()))?;
        state.active_host_operation = Some(ActiveHostOperationRef {
            operation_id: operation_id.to_owned(),
            applied_at: Utc::now(),
        });
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(state.config)
    }

    /// Commit an update (G03): swap `previous=current`, point `current` at
    /// the newly verified artifact, optionally advance the config CAS, and
    /// record this operation as the producing one. Re-executing the same
    /// interrupted commit replays without advancing again; a stale revision
    /// expectation fails closed.
    pub fn apply_update(
        &self,
        deployment_id: &str,
        expected_revision: u64,
        new_current: String,
        new_build: Option<BuildIdentity>,
        config: Option<(String, String)>,
        operation_id: &str,
    ) -> Result<DeploymentState, Failure> {
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let mut state = self.load_existing(deployment_id)?;
        if state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id)
        {
            return Ok(state);
        }
        if state.config.revision != expected_revision {
            return Err(Failure::new(
                CONFIG_REVISION_MISMATCH,
                format!(
                    "expected config revision {expected_revision} but target holds revision {} \
                     for '{deployment_id}'; re-read the live state and rebuild the change",
                    state.config.revision
                ),
            ));
        }
        crate::registry::validate_identifier(&new_current, 256, "artifact reference").map_err(
            |error| Failure::new(super::wire::HOST_ERR_OPERATION_INVALID, error.to_string()),
        )?;
        if let Some(identity) = &new_build {
            identity.validate().map_err(|error| {
                Failure::new(super::wire::HOST_ERR_OPERATION_INVALID, error.to_string())
            })?;
        }
        state.artifact.previous = state.artifact.current.take();
        state.artifact.current = Some(new_current);
        // The build identity swap mirrors the artifact reference swap so the
        // envelope facts stay attached to the right generation.
        state.previous_build_identity = state.current_build_identity.take();
        state.current_build_identity = new_build;
        if let Some((reference, schema)) = config {
            state
                .config
                .advance(reference, schema)
                .map_err(|error| Failure::new(CONFIG_REVISION_MISMATCH, error.to_string()))?;
        }
        state.active_host_operation = Some(ActiveHostOperationRef {
            operation_id: operation_id.to_owned(),
            applied_at: Utc::now(),
        });
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(state)
    }

    /// Commit an explicit rollback (G04): swap `current` and `previous`,
    /// optionally restore a saved config snapshot under its recorded schema,
    /// CAS-guarded. Refuses when no previous reference exists — rollback is
    /// never guessed.
    pub fn apply_rollback(
        &self,
        deployment_id: &str,
        expected_revision: u64,
        config: Option<(String, String)>,
        operation_id: &str,
    ) -> Result<DeploymentState, Failure> {
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let mut state = self.load_existing(deployment_id)?;
        if state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id)
        {
            return Ok(state);
        }
        if state.config.revision != expected_revision {
            return Err(Failure::new(
                CONFIG_REVISION_MISMATCH,
                format!(
                    "expected config revision {expected_revision} but target holds revision {} \
                     for '{deployment_id}'",
                    state.config.revision
                ),
            ));
        }
        let Some(previous) = state.artifact.previous.clone() else {
            return Err(Failure::new(
                ROLLBACK_UNAVAILABLE,
                format!(
                    "no previous verified artifact reference is saved for '{deployment_id}'; \
                     rollback restores saved facts only and never guesses"
                ),
            ));
        };
        // Exact swap: current <- old previous, previous <- old current, so a
        // follow-up rollback can always reverse the reversal (goal plan 07 §5
        // item 5: atomically update current/previous). The build identity
        // pairs follow their artifact references.
        let old_current = state.artifact.current.take();
        state.artifact.current = Some(previous);
        state.artifact.previous = old_current;
        let old_build = state.current_build_identity.take();
        state.current_build_identity = state.previous_build_identity.take();
        state.previous_build_identity = old_build;
        if let Some((reference, schema)) = config {
            state
                .config
                .advance(reference, schema)
                .map_err(|error| Failure::new(CONFIG_REVISION_MISMATCH, error.to_string()))?;
        }
        state.active_host_operation = Some(ActiveHostOperationRef {
            operation_id: operation_id.to_owned(),
            applied_at: Utc::now(),
        });
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(state)
    }

    /// Remove the state document after a completed uninstall (G06). The
    /// operation journal survives so a retried uninstall replays its stored
    /// terminal result instead of re-executing. External/shared resources are
    /// never consulted here: deletion happened in the executor against
    /// re-confirmed managed facts only.
    pub fn remove_deployment(
        &self,
        deployment_id: &str,
        expected_revision: u64,
        operation_id: &str,
    ) -> Result<(), Failure> {
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let state_path = self.state_path(&scope);
        if !state_path.exists() {
            // Already removed by the interrupted attempt this operation id
            // resumes; completion is idempotent.
            return Ok(());
        }
        let state = self.load_existing(deployment_id)?;
        if state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id)
        {
            // The removing attempt already committed; finish the removal.
            filesystem::remove_file_durable(&state_path).map_err(|error| {
                Failure::new(
                    DEPLOYMENT_UNKNOWN,
                    format!("failed to remove {}: {error}", state_path.display()),
                )
            })?;
            return Ok(());
        }
        if state.config.revision != expected_revision {
            return Err(Failure::new(
                CONFIG_REVISION_MISMATCH,
                format!(
                    "expected config revision {expected_revision} but target holds revision {} \
                     for '{deployment_id}'",
                    state.config.revision
                ),
            ));
        }
        filesystem::remove_file_durable(&state_path).map_err(|error| {
            Failure::new(
                DEPLOYMENT_UNKNOWN,
                format!("failed to remove {}: {error}", state_path.display()),
            )
        })?;
        Ok(())
    }

    /// Record a target-local health fact (goal plan 06 §2: `local_health` is
    /// written by whoever can actually observe the runtime). This is an
    /// observation, not a config change: the CAS revision does not move.
    /// Only the operation that produced the current state revision may write
    /// the health record — a stale or foreign operation id is rejected so
    /// interrupted lifecycles cannot stamp observations they never made.
    pub fn record_local_health(
        &self,
        deployment_id: &str,
        healthy: bool,
        summary: String,
        operation_id: &str,
    ) -> Result<HealthRecord, Failure> {
        if summary.len() > 512 {
            return Err(Failure::new(
                super::wire::HOST_ERR_OPERATION_INVALID,
                "health summary must be at most 512 characters",
            ));
        }
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let mut state = self.load_existing(deployment_id)?;
        let owns = state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id);
        if !owns {
            return Err(Failure::new(
                DEPLOYMENT_UNKNOWN,
                format!(
                    "health observation rejected: '{deployment_id}' is not currently owned by \
                     operation {operation_id}"
                ),
            ));
        }
        let record = HealthRecord {
            healthy,
            summary,
            checked_at: Utc::now(),
        };
        state.local_health = record.clone();
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(record)
    }

    /// Record a backup/DR maturity fact (H05). ONLY explicit backup
    /// operations may write it, enforced by the same operation-ownership
    /// discipline as [`Self::record_local_health`]: the reporting operation
    /// must own the deployment's current state revision. This is an
    /// observation, not a config change: the CAS revision does not move, and
    /// no lifecycle use case ever consults this fact for gating.
    pub fn record_backup_maturity(
        &self,
        deployment_id: &str,
        maturity: BackupMaturity,
        operation_id: &str,
    ) -> Result<BackupMaturity, Failure> {
        let _guard = StateLock::acquire(self.lock_path(deployment_id)?)?;
        let mut state = self.load_existing(deployment_id)?;
        let owns = state
            .active_host_operation
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id);
        if !owns {
            return Err(Failure::new(
                DEPLOYMENT_UNKNOWN,
                format!(
                    "backup maturity rejected: '{deployment_id}' is not currently owned by \
                     operation {operation_id}; only an explicit backup operation over the live \
                     state revision may report maturity"
                ),
            ));
        }
        state.backup_maturity = maturity;
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        persist(&scope_path(&self.root, &scope), &state)?;
        Ok(maturity)
    }

    fn lock_path(&self, deployment_id: &str) -> Result<PathBuf, Failure> {
        let scope = journal::deployment_scope(deployment_id).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, sanitize_detail(&error.to_string()))
        })?;
        Ok(scope_path(&self.root, &scope).with_extension("lock"))
    }
}

/// `<root>/deployments/<scope>/` — the frozen per-scope layout shared with
/// the C07 operation journal (`operations.jsonl` beside `state.json`).
fn scope_path(root: &Path, scope: &str) -> PathBuf {
    root.join("deployments").join(scope)
}

fn persist(path: &Path, state: &DeploymentState) -> Result<(), Failure> {
    let target = path.join("state.json");
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| Failure::new(DEPLOYMENT_UNKNOWN, error.to_string()))?;
    filesystem::atomic_write(&target, &bytes, 0o600).map_err(|error| {
        Failure::new(
            DEPLOYMENT_UNKNOWN,
            format!("failed to persist {}: {error}", target.display()),
        )
    })
}

/// Exclusive lock serializing read-modify-write cycles on one deployment's
/// state document. Always acquired *inside* the journal lock, keeping the
/// global ordering journal → state deadlock-free.
struct StateLock {
    file: std::fs::File,
}

impl StateLock {
    fn acquire(path: PathBuf) -> Result<Self, Failure> {
        let parent = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        filesystem::ensure_directory_chain(&parent).map_err(|error| {
            Failure::new(DEPLOYMENT_UNKNOWN, format!("{}: {error}", parent.display()))
        })?;
        let file = filesystem::open_lock_file(&path, false, "target state lock")
            .map_err(|error| Failure::new(DEPLOYMENT_UNKNOWN, error.to_string()))?;
        file.try_lock_exclusive().map_err(|error| {
            Failure::new(
                DEPLOYMENT_UNKNOWN,
                format!("another writer holds {}: {error}", path.display()),
            )
        })?;
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn unreadable_state(deployment_id: &str, path: &Path, error: &dyn std::fmt::Display) -> Failure {
    if !path.exists() {
        return Failure::new(
            DEPLOYMENT_UNKNOWN,
            format!(
                "no DeploymentState for '{deployment_id}' under {}; register or discover the \
                 instance first",
                path.parent().unwrap_or(path).display()
            ),
        );
    }
    Failure::new(
        DEPLOYMENT_UNKNOWN,
        format!(
            "{STATE_RESET_REQUIRED}: target DeploymentState is missing, unsafe to read, or \
             oversized ({path_display}): {error}; back the file up, remove the deployment \
             directory, then re-register/bootstrap the instance",
            path_display = path.display()
        ),
    )
}

fn invalid_state(path: &Path, error: &dyn std::fmt::Display) -> Failure {
    Failure::new(
        DEPLOYMENT_UNKNOWN,
        format!(
            "{STATE_RESET_REQUIRED}: target DeploymentState does not conform to the current \
             schema ({path_display}): {error}; back the file up, remove the deployment \
             directory, then re-register/bootstrap the instance",
            path_display = path.display()
        ),
    )
}

fn sanitize_detail(text: &str) -> String {
    text.chars()
        .take(200)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params(issuer: &str, runtime_object: &str) -> BootstrapParams {
        BootstrapParams {
            issuer: issuer.to_owned(),
            runtime: RuntimeSurface::new("podman", runtime_object).expect("runtime"),
            artifact: ArtifactRefs::default(),
            config_reference: "/etc/nazauth/config.toml".to_owned(),
            config_schema: "nazauth-config-v1".to_owned(),
            resources: Vec::new(),
            current_build_identity: None,
        }
    }

    #[test]
    fn list_deployments_is_sorted_skips_journal_only_scopes_and_fails_closed() -> anyhow::Result<()>
    {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-state-list")?;
        let store = TargetStateStore::open(temp.path().join("state"))?;

        // A fresh target without a deployments directory lists empty.
        assert!(store.list_deployments()?.is_empty());

        // Two real deployments plus a journal-only scope (the host-level
        // journal lives under deployments/host) and a stray non-directory.
        store.bootstrap(
            "deploy-zeta",
            sample_params("https://z.example", "nz-z"),
            "op",
        )?;
        store.bootstrap(
            "deploy-alpha",
            sample_params("https://a.example", "nz-a"),
            "op",
        )?;
        let host_scope = temp.path().join("state").join("deployments").join("host");
        crate::filesystem::ensure_directory_chain(&host_scope)?;
        crate::filesystem::atomic_write(&host_scope.join("operations.jsonl"), b"\n", 0o600)?;
        let loose_file = temp
            .path()
            .join("state")
            .join("deployments")
            .join("loose-file");
        crate::filesystem::atomic_write(&loose_file, b"not a deployment", 0o600)?;

        let listed = store.list_deployments()?;
        let ids: Vec<&str> = listed.iter().map(|s| s.deployment_id.as_str()).collect();
        assert_eq!(ids, ["deploy-alpha", "deploy-zeta"], "sorted, scoped");

        // A present-but-corrupt state document fails the whole sweep closed
        // with the stable reset code — discovery never skips corruption.
        let broken_dir = temp
            .path()
            .join("state")
            .join("deployments")
            .join("deploy-broken");
        crate::filesystem::ensure_directory_chain(&broken_dir)?;
        crate::filesystem::atomic_write(&broken_dir.join("state.json"), b"{ not json", 0o600)?;
        let error = store.list_deployments().expect_err("corrupt document");
        assert!(
            error.detail.contains(crate::registry::STATE_RESET_REQUIRED),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn list_deployments_refuses_to_truncate_beyond_the_cap() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-state-list-cap")?;
        let store = TargetStateStore::open(temp.path().join("state"))?;
        for index in 0..=MAX_LISTED_DEPLOYMENTS {
            let id = format!("deploy-{index:03}");
            store.bootstrap(&id, sample_params("https://x.example", &id), "op")?;
        }
        let failure = store.list_deployments().expect_err("over the cap");
        assert_eq!(failure.code, DEPLOYMENT_LIMIT_EXCEEDED, "{failure:?}");
        Ok(())
    }

    // ------------------------------------------------------------- H05

    #[test]
    fn backup_maturity_transitions_are_recorded_by_owning_operations_only() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-backup-maturity")?;
        let store = TargetStateStore::open(temp.path().join("state"))?;
        store.bootstrap(
            "deploy-alpha",
            sample_params("https://a.example", "nz-a"),
            "op-1",
        )?;

        // Fresh state starts at Unknown: no explicit backup statement yet.
        let state = store.load_existing("deploy-alpha")?;
        assert_eq!(state.backup_maturity, BackupMaturity::Unknown);
        assert_eq!(state.backup_maturity.token(), "unknown");
        assert!(state.backup_maturity.observed_at().is_none());

        // A foreign operation id is rejected: only an explicit backup
        // operation owning the live revision may report maturity.
        let foreign = store.record_backup_maturity(
            "deploy-alpha",
            BackupMaturity::NotConfigured {
                observed_at: Utc::now(),
            },
            "not-the-owner",
        );
        assert!(foreign.is_err());
        assert_eq!(
            store.load_existing("deploy-alpha")?.backup_maturity,
            BackupMaturity::Unknown,
            "rejected writes change nothing"
        );

        let recorded = store.record_backup_maturity(
            "deploy-alpha",
            BackupMaturity::NotConfigured {
                observed_at: Utc::now(),
            },
            "op-1",
        )?;
        assert_eq!(recorded.token(), "not-configured");

        let configured = store.record_backup_maturity(
            "deploy-alpha",
            BackupMaturity::Configured {
                observed_at: Utc::now(),
            },
            "op-1",
        )?;
        assert!(matches!(configured, BackupMaturity::Configured { .. }));

        // The fact persists verbatim and never moves the CAS revision.
        let state = store.load_existing("deploy-alpha")?;
        assert_eq!(state.backup_maturity.token(), "configured");
        assert!(state.backup_maturity.observed_at().is_some());
        assert_eq!(state.config.revision, 1);

        let verified = store.record_backup_maturity(
            "deploy-alpha",
            BackupMaturity::Verified {
                observed_at: Utc::now(),
            },
            "op-1",
        )?;
        assert_eq!(verified.token(), "verified");

        // Round-trips through strict deserialization.
        let raw = std::fs::read_to_string(
            temp.path()
                .join("state/deployments/deploy-alpha/state.json"),
        )?;
        assert!(
            raw.contains(r#""state": "verified""#) || raw.contains(r#""state":"verified""#),
            "{raw}"
        );
        Ok(())
    }
}
