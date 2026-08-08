use std::{
    fs::{self, File, TryLockError},
    io::{IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use nazo_operator_protocol::{EmbeddedIdentity, TaskOperation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::deployment::{
    Capability, CapabilityGrant, DeploymentRecord, DeploymentStore, FileLock, RecoveryConclusion,
    Responsibility, RuntimeBackendKind, SafeReference,
};
use crate::{
    backup::Backup,
    cli::{
        BootstrapAdminOptions, CandidateTarget, Cli, Command, ConformanceLeaseCommand, KeysCommand,
        UpdateOptions,
    },
    filesystem::{
        atomic_write, copy_atomic, open_lock_file, remove_file_durable, set_mode, symlink_atomic,
    },
    install::{self, PreparedInstall},
    model::{ReleaseManifest, UpdateConfig},
    operator::{self, ExpectedReleaseTarget},
    process::Process,
    release::{VerifiedRelease, commit_release_trust, compare_versions, enforce_release_trust},
    runtime::Runtime,
};

mod bootstrap;
mod commands;
mod deployment;
mod diagnostics;
mod keys;
mod self_update;
mod updates;
use bootstrap::*;
#[cfg(test)]
pub(crate) use commands::conformance_operation;
use deployment::*;
use diagnostics::*;
use keys::*;
use self_update::*;
use updates::*;

struct ControlConfig {
    path: PathBuf,
    config: UpdateConfig,
    _deployment_lock: Option<FileLock>,
    _shared_capability_locks: Vec<FileLock>,
}

fn control_config(
    config_path: &Path,
    selector: Option<&str>,
    capabilities: &[Capability],
    application_task: bool,
    core_recovery: bool,
    unsettled: bool,
) -> anyhow::Result<ControlConfig> {
    let store = DeploymentStore::system();
    if !store.registry_path().exists() {
        let config = if unsettled {
            load_config_unsettled(config_path)?
        } else {
            load_config(config_path)?
        };
        return Ok(ControlConfig {
            path: config_path.to_path_buf(),
            config,
            _deployment_lock: None,
            _shared_capability_locks: Vec::new(),
        });
    }

    let destructive = !capabilities.is_empty() || core_recovery;
    let resolved = store.resolve(selector, destructive)?;
    let deployment_lock = destructive
        .then(|| store.deployment_lock(&resolved.deployment_id))
        .transpose()?;
    let record = store.load(&resolved.deployment_id)?;
    let shared_capability_locks = if destructive {
        store.shared_capability_locks(&record, capabilities)?
    } else {
        Vec::new()
    };
    if !capabilities.is_empty() {
        record.require_mutation(capabilities)?;
    }
    if core_recovery && !record.core_recovery_is_proven() {
        bail!(
            "deployment {} has no proven controller-independent recovery package",
            record.deployment_id
        );
    }
    if application_task
        && !record
            .operator_protocol_versions
            .contains(&nazo_operator_protocol::PROTOCOL_VERSION)
    {
        bail!(
            "deployment {} does not support operator protocol {}; application task refused",
            record.deployment_id,
            nazo_operator_protocol::PROTOCOL_VERSION
        );
    }
    let path = match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) => path.clone(),
        _ => bail!(
            "deployment {} has no verified controller configuration; create and approve a lifecycle plan before mutation",
            record.deployment_id
        ),
    };
    let mut config = if unsettled {
        load_config_unsettled(&path)?
    } else {
        load_config(&path)?
    };
    verify_control_binding(&record, &config)?;
    // The declaration is the authoritative capability state.  Keep the
    // in-memory legacy config aligned after the lock/reload boundary so a
    // stale file cannot grant extra authority (or deny an intentional
    // capability transition) to runtime helpers.
    config.trust = record.trust;
    config.capabilities = record.capabilities.clone();
    Ok(ControlConfig {
        path,
        config,
        _deployment_lock: deployment_lock,
        _shared_capability_locks: shared_capability_locks,
    })
}

fn verify_control_binding(record: &DeploymentRecord, config: &UpdateConfig) -> anyhow::Result<()> {
    if config.operator.deployment_id != record.deployment_id
        || config.operator.controller_key_id != record.control_authority
    {
        bail!("controller configuration is bound to a different deployment authority");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackState {
    schema: u32,
    from_release: ReleaseManifest,
    to_release: ReleaseManifest,
    previous_runtime: String,
    previous_ui: Option<PathBuf>,
    backup: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UpdatePhase {
    Prepared,
    WriterStopping,
    WriterStopped,
    BackupCreating,
    BackupCreated,
    MigrationRunning,
    MigrationApplied,
    CandidateActivating,
    CandidateActive,
    UiActivating,
    UiActive,
    HealthChecking,
    HealthVerified,
    StateCommitting,
    StateCommitted,
    TrustCommitting,
    TrustCommitted,
    AuditCommitting,
    AuditCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateJournal {
    schema: u32,
    transaction_id: String,
    started_at: String,
    phase: UpdatePhase,
    from_release: ReleaseManifest,
    to_release: ReleaseManifest,
    previous_runtime: String,
    previous_ui: Option<PathBuf>,
    candidate_runtime: String,
    candidate_ui: PathBuf,
    backup: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateRecoveryAction {
    RestorePrevious,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallCompletion {
    schema: u32,
    version: String,
    backend_commit: String,
    management_event_file: String,
    management_event_sha256: String,
    #[serde(default)]
    recovery_backup: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerTrustState {
    schema: u32,
    version: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerRollbackState {
    schema: u32,
    version: String,
    sha256: String,
    artifact: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerUpdateJournal {
    schema: u32,
    from_version: String,
    from_sha256: String,
    to_version: String,
    to_sha256: String,
    staged_artifact: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerSelfAuditEvent {
    schema: u32,
    sequence: u64,
    previous_sha256: String,
    operation: String,
    from_version: String,
    to_version: String,
    artifact_sha256: String,
    recorded_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerSelfAuditRecord {
    schema: u32,
    key_id: String,
    event: ControllerSelfAuditEvent,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerSelfAuditHead {
    schema: u32,
    sequence: u64,
    sha256: String,
}

const BOOTSTRAP_MOUNT_TARGET: &str = "/var/lib/nazo_oauth/bootstrap";
const BOOTSTRAP_TOKEN_FILE: &str = "initial-admin-token";
const MAX_BOOTSTRAP_CREDENTIAL_BYTES: u64 = 8 * 1024;
const MAX_BOOTSTRAP_TOKEN_BYTES: u64 = 2 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminCredentials {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct BootstrapAdminRequest<'a> {
    request_id: &'a str,
    token: &'a str,
    email: &'a str,
    password: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminResponse {
    request_id: String,
    id: String,
    email: String,
    role: String,
    next: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BootstrapAdminPendingStatus {
    Intent,
    Succeeded,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminPending {
    schema: u32,
    request_id: String,
    email_hmac_sha256: String,
    recovery_epoch: String,
    status: BootstrapAdminPendingStatus,
    claimed_user_id: Option<String>,
    token_hmac_sha256: Option<String>,
}

#[derive(Debug)]
struct VerifiedBootstrapReceipt {
    claimed_user_id: uuid::Uuid,
    token_hmac_sha256: String,
}

#[derive(Debug)]
struct BootstrapOutcomeUnknown;

impl std::fmt::Display for BootstrapOutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("initial administrator request outcome is unknown")
    }
}

impl std::error::Error for BootstrapOutcomeUnknown {}

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    commands::run(cli)
}

pub(crate) fn acquire_lock(command: &Command) -> anyhow::Result<File> {
    deployment::acquire_lock(command)
}

pub(crate) fn uses_legacy_lock(command: &Command) -> bool {
    updates::recovery_uses_legacy_lock(command)
}

fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        bail!("this command requires root on a Unix host");
    }
    #[cfg(unix)]
    {
        if Process::new("id").arg("-u").stdout()?.trim() != "0" {
            bail!("this command requires root");
        }
        Ok(())
    }
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

fn require_confirmation(yes: bool, action: &str) -> anyhow::Result<()> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("{action} requires --yes in non-interactive mode");
    }
    eprint!("Confirm: {action} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("operation cancelled")
    }
}

#[cfg(test)]
#[path = "../tests/unit/controller.rs"]
mod tests;
