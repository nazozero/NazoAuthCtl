use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::file_lock::FileLock;
use crate::filesystem::{
    atomic_write, copy_atomic_from_file, ensure_private_directory, open_secure_regular_file,
    read_secure_regular_file, remove_file_durable, sha256_file,
};
use crate::process::Process;
use crate::release::compare_versions;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControllerTrustState {
    pub(super) schema: u32,
    pub(super) version: String,
    pub(super) sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControllerRollbackState {
    pub(super) schema: u32,
    pub(super) version: String,
    pub(super) sha256: String,
    pub(super) artifact: PathBuf,
}

/// A controller self-update state file has exactly one supported on-disk
/// schema.  Reading a different or unsafe state must stop before it can
/// influence an update or rollback; this is deliberately not a migration
/// boundary.
trait CurrentSelfState {
    const SCHEMA: u32;

    fn schema(&self) -> u32;
}

impl CurrentSelfState for ControllerTrustState {
    const SCHEMA: u32 = 1;

    fn schema(&self) -> u32 {
        self.schema
    }
}

impl CurrentSelfState for ControllerRollbackState {
    const SCHEMA: u32 = 1;

    fn schema(&self) -> u32 {
        self.schema
    }
}

const SELF_UPDATE_JOURNAL_SCHEMA: u32 = 2;
const SELF_UPDATE_JOURNAL_MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SelfUpdateOperation {
    Update,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SelfUpdatePhase {
    Intent,
    RollbackPrepared,
    CandidatePrepared,
    CandidateVerified,
    Installed,
    RollbackStateCommitted,
    TrustCommitted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SelfUpdateJournal {
    schema: u32,
    transaction_id: String,
    operation: SelfUpdateOperation,
    phase: SelfUpdatePhase,
    install_path: PathBuf,
    from_version: String,
    from_sha256: String,
    to_version: String,
    to_sha256: String,
    rollback_artifact: PathBuf,
    rollback_sha256: String,
    #[serde(default)]
    staged_artifact: Option<PathBuf>,
}

impl CurrentSelfState for SelfUpdateJournal {
    const SCHEMA: u32 = SELF_UPDATE_JOURNAL_SCHEMA;

    fn schema(&self) -> u32 {
        self.schema
    }
}

pub(super) fn controller_state_directory() -> anyhow::Result<PathBuf> {
    let registry = crate::registry::RegistryStore::open_default()?;
    Ok(registry.root().join("controller-self"))
}

pub(super) fn controller_check(version: Option<&str>) -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    let _lock = FileLock::acquire(&directory.join(".lock"))?;
    recover_controller_self_operation()?;
    let release = crate::release::VerifiedControllerRelease::verify(version, None)?;
    enforce_controller_trust(&release.version, &release.sha256)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "installed": env!("CARGO_PKG_VERSION"),
            "candidate": release.version,
            "sha256": release.sha256,
            "repository": "nazozero/NazoAuthCtl",
        }))?
    );
    Ok(())
}

pub(super) fn controller_update(version: Option<&str>) -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    let _lock = FileLock::acquire(&directory.join(".lock"))?;
    recover_controller_self_operation()?;
    let release = crate::release::VerifiedControllerRelease::verify(version, None)?;
    enforce_controller_trust(&release.version, &release.sha256)?;
    release.persist_evidence(&directory.join("evidence").join(&release.version))?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    let mut current_file = open_secure_regular_file(&install_path, "running controller", false)?;
    let previous_sha256 = sha256_file(&mut current_file, "running controller")?;
    let previous_version = controller_trust_state()?
        .map(|state| state.version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let rollback_artifact = directory.join(format!("rollback-{previous_sha256}"));
    let staged = directory.join(format!("candidate-{}", release.sha256));
    let mut journal = SelfUpdateJournal {
        schema: SELF_UPDATE_JOURNAL_SCHEMA,
        transaction_id: uuid::Uuid::now_v7().to_string(),
        operation: SelfUpdateOperation::Update,
        phase: SelfUpdatePhase::Intent,
        install_path: install_path.clone(),
        from_version: previous_version.clone(),
        from_sha256: previous_sha256.clone(),
        to_version: release.version.clone(),
        to_sha256: release.sha256.clone(),
        rollback_artifact: rollback_artifact.clone(),
        rollback_sha256: previous_sha256.clone(),
        staged_artifact: Some(staged.clone()),
    };
    persist_self_update_journal(&directory, &journal)?;

    copy_atomic_from_file(&mut current_file, &rollback_artifact, 0o500)?;
    ensure_digest(&rollback_artifact, &previous_sha256, "rollback artifact")?;
    journal.phase = SelfUpdatePhase::RollbackPrepared;
    persist_self_update_journal(&directory, &journal)?;

    let mut candidate_file =
        open_secure_regular_file(&release.artifact(), "verified controller candidate", false)?;
    copy_atomic_from_file(&mut candidate_file, &staged, 0o500)?;
    ensure_digest(&staged, &release.sha256, "staged controller candidate")?;
    journal.phase = SelfUpdatePhase::CandidatePrepared;
    persist_self_update_journal(&directory, &journal)?;
    Process::new(&staged).arg("--help").run_quiet()?;
    journal.phase = SelfUpdatePhase::CandidateVerified;
    persist_self_update_journal(&directory, &journal)?;

    let mut staged_file = open_secure_regular_file(&staged, "staged controller candidate", false)?;
    copy_atomic_from_file(&mut staged_file, &install_path, 0o755)?;
    ensure_digest(&install_path, &release.sha256, "installed controller")?;
    journal.phase = SelfUpdatePhase::Installed;
    persist_self_update_journal(&directory, &journal)?;
    commit_controller_rollback_state(
        &directory,
        &previous_version,
        &previous_sha256,
        &rollback_artifact,
    )?;
    journal.phase = SelfUpdatePhase::RollbackStateCommitted;
    persist_self_update_journal(&directory, &journal)?;
    write_controller_trust(&release.version, &release.sha256)?;
    journal.phase = SelfUpdatePhase::TrustCommitted;
    persist_self_update_journal(&directory, &journal)?;
    finish_self_update_journal(&directory, &journal)?;
    println!("nazoauthctl updated independently to {}", release.version);
    Ok(())
}

pub(super) fn controller_rollback() -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    let _lock = FileLock::acquire(&directory.join(".lock"))?;
    recover_controller_self_operation()?;
    let rollback_path = directory.join("rollback.json");
    if !current_self_state_is_present(&rollback_path, "controller rollback state")? {
        bail!(
            "controller rollback state is unavailable: no rollback state at {}",
            rollback_path.display()
        );
    }
    let state: ControllerRollbackState =
        read_current_self_state(&rollback_path, "controller rollback state")?;
    validate_digest(&state.sha256, "controller rollback state digest")?;
    validate_bound_path(&state.artifact, "controller rollback artifact")?;
    ensure_digest(
        &state.artifact,
        &state.sha256,
        "controller rollback artifact",
    )?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    let mut current_file = open_secure_regular_file(&install_path, "running controller", false)?;
    let from_sha256 = sha256_file(&mut current_file, "running controller")?;
    let from_version = controller_trust_state()?
        .map(|value| value.version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let mut journal = SelfUpdateJournal {
        schema: SELF_UPDATE_JOURNAL_SCHEMA,
        transaction_id: uuid::Uuid::now_v7().to_string(),
        operation: SelfUpdateOperation::Rollback,
        phase: SelfUpdatePhase::Intent,
        install_path: install_path.clone(),
        from_version: from_version.clone(),
        from_sha256,
        to_version: state.version.clone(),
        to_sha256: state.sha256.clone(),
        rollback_artifact: state.artifact.clone(),
        rollback_sha256: state.sha256.clone(),
        staged_artifact: None,
    };
    persist_self_update_journal(&directory, &journal)?;
    let mut rollback_file =
        open_secure_regular_file(&state.artifact, "controller rollback artifact", false)?;
    copy_atomic_from_file(&mut rollback_file, &install_path, 0o755)?;
    ensure_digest(&install_path, &state.sha256, "restored controller")?;
    journal.phase = SelfUpdatePhase::Installed;
    persist_self_update_journal(&directory, &journal)?;
    write_controller_trust(&state.version, &state.sha256)?;
    journal.phase = SelfUpdatePhase::TrustCommitted;
    persist_self_update_journal(&directory, &journal)?;
    finish_self_update_journal(&directory, &journal)?;
    println!("nazoauthctl rolled back independently to {}", state.version);
    Ok(())
}

pub(super) fn controller_trust_state() -> anyhow::Result<Option<ControllerTrustState>> {
    let path = controller_state_directory()?.join("trust.json");
    if !current_self_state_is_present(&path, "controller trust state")? {
        return Ok(None);
    }
    let state: ControllerTrustState = read_current_self_state(&path, "controller trust state")?;
    validate_digest(&state.sha256, "controller trust state digest")?;
    compare_versions(&state.version, &state.version)?;
    Ok(Some(state))
}

pub(super) fn enforce_controller_trust(version: &str, sha256: &str) -> anyhow::Result<()> {
    validate_digest(sha256, "controller candidate digest")?;
    let Some(state) = controller_trust_state()? else {
        // A missing trust file is the bootstrap case, not an unrestricted
        // update window.  The binary that is currently executing establishes
        // the initial version/digest floor until a durable trust state exists.
        let current =
            std::env::current_exe().context("failed to resolve the running controller")?;
        let current = controller_install_path(&current)?;
        let current_version = format!("v{}", env!("CARGO_PKG_VERSION"));
        let current_sha256 = secure_digest(&current, "running controller")?;
        match compare_versions(version, &current_version)? {
            std::cmp::Ordering::Less => {
                bail!("controller anti-downgrade policy requires explicit self rollback")
            }
            std::cmp::Ordering::Equal if sha256 != current_sha256 => {
                bail!("immutable controller Release changed for the running version")
            }
            _ => return Ok(()),
        }
    };
    match compare_versions(version, &state.version)? {
        std::cmp::Ordering::Less => {
            bail!("controller anti-downgrade policy requires explicit self rollback")
        }
        std::cmp::Ordering::Equal if state.sha256 != sha256 => {
            bail!("immutable controller Release changed for an already trusted version")
        }
        _ => Ok(()),
    }
}

pub(super) fn write_controller_trust(version: &str, sha256: &str) -> anyhow::Result<()> {
    validate_digest(sha256, "controller trust digest")?;
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    atomic_write(
        &directory.join("trust.json"),
        &serde_json::to_vec_pretty(&ControllerTrustState {
            schema: 1,
            version: version.to_owned(),
            sha256: sha256.to_owned(),
        })?,
        0o600,
    )
}

pub(super) fn controller_install_path(current: &Path) -> anyhow::Result<PathBuf> {
    let path = current.to_path_buf();
    let has_lexical_navigation = path
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| matches!(segment, "." | ".."));
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || has_lexical_navigation
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("controller install path must be a normalized absolute file path");
    }
    if path_is_present(&path)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("controller install path must be a regular non-symlink file");
        }
    }
    Ok(path)
}

fn recover_controller_self_operation() -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    let path = directory.join("update-transaction.json");
    if !current_self_state_is_present(&path, "controller self-update journal")? {
        return Ok(());
    }
    let mut journal = load_self_update_journal(&path)?;
    if journal.transaction_id.trim().is_empty() {
        bail!("controller self-update journal has no transaction id");
    }
    validate_digest(&journal.from_sha256, "controller self-update source digest")?;
    validate_digest(
        &journal.to_sha256,
        "controller self-update candidate digest",
    )?;
    validate_digest(
        &journal.rollback_sha256,
        "controller self-update rollback digest",
    )?;
    validate_bound_path(&journal.rollback_artifact, "controller rollback artifact")?;
    if let Some(staged) = journal.staged_artifact.as_ref() {
        validate_bound_path(staged, "staged controller candidate")?;
    }
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    if install_path != journal.install_path {
        bail!("controller self-update journal is bound to a different install path");
    }
    match journal.operation {
        SelfUpdateOperation::Update => recover_update_journal(&directory, &mut journal)?,
        SelfUpdateOperation::Rollback => recover_rollback_journal(&directory, &mut journal)?,
    }
    Ok(())
}

fn load_self_update_journal(path: &Path) -> anyhow::Result<SelfUpdateJournal> {
    read_current_self_state(path, "controller self-update journal")
}

fn recover_update_journal(directory: &Path, journal: &mut SelfUpdateJournal) -> anyhow::Result<()> {
    let current_digest = optional_secure_digest(&journal.install_path, "running controller")?;
    let rollback_digest = optional_secure_digest(&journal.rollback_artifact, "rollback artifact")?;
    if let Some(value) = rollback_digest.as_deref()
        && value != journal.rollback_sha256.as_str()
    {
        bail!("controller rollback artifact digest differs from its journal binding");
    }
    let staged = journal.staged_artifact.as_ref();
    let staged_digest = match staged {
        Some(path) => optional_secure_digest(path, "staged controller candidate")?,
        None => None,
    };
    if let Some(value) = staged_digest.as_deref()
        && value != journal.to_sha256.as_str()
    {
        bail!("staged controller candidate digest differs from its journal binding");
    }
    let mut installed = current_digest.as_deref() == Some(journal.to_sha256.as_str());
    if !installed {
        if current_digest.is_some()
            && current_digest.as_deref() != Some(journal.from_sha256.as_str())
        {
            bail!("controller install digest is neither the journal source nor candidate");
        }
        if staged_digest.as_deref() == Some(journal.to_sha256.as_str()) {
            if journal.phase != SelfUpdatePhase::CandidateVerified {
                Process::new(staged.context("controller candidate journal path is missing")?)
                    .arg("--help")
                    .run_quiet()?;
                journal.phase = SelfUpdatePhase::CandidateVerified;
                persist_self_update_journal(directory, journal)?;
            }
            let mut staged_file = open_secure_regular_file(
                staged.context("controller candidate journal path is missing")?,
                "staged controller candidate",
                false,
            )?;
            copy_atomic_from_file(&mut staged_file, &journal.install_path, 0o755)?;
            ensure_digest(
                &journal.install_path,
                &journal.to_sha256,
                "installed controller",
            )?;
            installed = true;
            journal.phase = SelfUpdatePhase::Installed;
            persist_self_update_journal(directory, journal)?;
        } else if current_digest.as_deref() == Some(journal.from_sha256.as_str())
            && matches!(
                journal.phase,
                SelfUpdatePhase::Intent | SelfUpdatePhase::RollbackPrepared
            )
        {
            // The release download/staging never completed.  No install
            // mutation occurred, so retiring this journal is idempotent and
            // does not hide a changed binary.
            discard_unstarted_self_update_journal(directory, journal)?;
            return Ok(());
        } else {
            bail!("controller self-update journal cannot recover its candidate");
        }
    }
    if !installed {
        bail!("controller self-update did not reach an installed candidate");
    }
    if matches!(
        journal.phase,
        SelfUpdatePhase::Intent
            | SelfUpdatePhase::RollbackPrepared
            | SelfUpdatePhase::CandidatePrepared
            | SelfUpdatePhase::CandidateVerified
    ) {
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    }
    commit_controller_rollback_state(
        directory,
        &journal.from_version,
        &journal.from_sha256,
        &journal.rollback_artifact,
    )?;
    if journal.phase == SelfUpdatePhase::Installed {
        journal.phase = SelfUpdatePhase::RollbackStateCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    write_controller_trust(&journal.to_version, &journal.to_sha256)?;
    if journal.phase == SelfUpdatePhase::RollbackStateCommitted {
        journal.phase = SelfUpdatePhase::TrustCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    finish_self_update_journal(directory, journal)
}

fn recover_rollback_journal(
    directory: &Path,
    journal: &mut SelfUpdateJournal,
) -> anyhow::Result<()> {
    let artifact_digest = optional_secure_digest(&journal.rollback_artifact, "rollback artifact")?
        .context("controller rollback artifact is missing")?;
    if artifact_digest != journal.rollback_sha256 || journal.rollback_sha256 != journal.to_sha256 {
        bail!("controller rollback journal is not bound to its artifact digest");
    }
    let current_digest = optional_secure_digest(&journal.install_path, "running controller")?;
    if current_digest.as_deref() != Some(journal.to_sha256.as_str()) {
        if current_digest.is_some()
            && current_digest.as_deref() != Some(journal.from_sha256.as_str())
        {
            bail!("controller install digest is neither rollback source nor target");
        }
        let mut artifact = open_secure_regular_file(
            &journal.rollback_artifact,
            "controller rollback artifact",
            false,
        )?;
        copy_atomic_from_file(&mut artifact, &journal.install_path, 0o755)?;
        ensure_digest(
            &journal.install_path,
            &journal.to_sha256,
            "restored controller",
        )?;
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    } else if journal.phase == SelfUpdatePhase::Intent {
        // The install replacement may have reached durable storage before
        // the phase checkpoint.  Infer only this monotonic transition from
        // the bound target digest; never infer the trust commit this way.
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    }
    write_controller_trust(&journal.to_version, &journal.to_sha256)?;
    if journal.phase == SelfUpdatePhase::Installed {
        journal.phase = SelfUpdatePhase::TrustCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    finish_self_update_journal(directory, journal)
}

fn persist_self_update_journal(
    directory: &Path,
    journal: &SelfUpdateJournal,
) -> anyhow::Result<()> {
    atomic_write(
        &directory.join("update-transaction.json"),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

fn finish_self_update_journal(directory: &Path, journal: &SelfUpdateJournal) -> anyhow::Result<()> {
    if journal.phase != SelfUpdatePhase::TrustCommitted {
        bail!("controller self-update journal cannot be retired before the trust commit");
    }
    if let Some(staged) = journal.staged_artifact.as_ref()
        && let Some(digest) = optional_secure_digest(staged, "staged controller candidate")?
    {
        if digest != journal.to_sha256.as_str() {
            bail!("staged controller candidate changed before cleanup");
        }
        remove_file_durable(staged)?;
    }
    remove_file_durable(&directory.join("update-transaction.json"))
}

fn discard_unstarted_self_update_journal(
    directory: &Path,
    journal: &SelfUpdateJournal,
) -> anyhow::Result<()> {
    if !matches!(
        journal.phase,
        SelfUpdatePhase::Intent | SelfUpdatePhase::RollbackPrepared
    ) {
        bail!("controller self-update journal is no longer unstarted");
    }
    if let Some(staged) = journal.staged_artifact.as_ref()
        && let Some(digest) = optional_secure_digest(staged, "staged controller candidate")?
    {
        if digest != journal.to_sha256.as_str() {
            bail!("staged controller candidate changed before cleanup");
        }
        remove_file_durable(staged)?;
    }
    remove_file_durable(&directory.join("update-transaction.json"))
}

fn commit_controller_rollback_state(
    directory: &Path,
    version: &str,
    sha256: &str,
    artifact: &Path,
) -> anyhow::Result<()> {
    validate_bound_path(artifact, "controller rollback artifact")?;
    ensure_digest(artifact, sha256, "rollback artifact")?;
    atomic_write(
        &directory.join("rollback.json"),
        &serde_json::to_vec_pretty(&ControllerRollbackState {
            schema: 1,
            version: version.to_owned(),
            sha256: sha256.to_owned(),
            artifact: artifact.to_owned(),
        })?,
        0o600,
    )
}

fn read_current_self_state<T: CurrentSelfState + DeserializeOwned>(
    path: &Path,
    label: &str,
) -> anyhow::Result<T> {
    let bytes = read_secure_regular_file(path, label, true, SELF_UPDATE_JOURNAL_MAX_BYTES)
        .map_err(|error| {
            state_reset_required(path, label, format!("cannot read it safely: {error:#}"))
        })?;
    let state: T = serde_json::from_slice(bytes.as_slice()).map_err(|error| {
        state_reset_required(
            path,
            label,
            format!("it is not valid current JSON: {error}"),
        )
    })?;
    if state.schema() != T::SCHEMA {
        return Err(state_reset_required(
            path,
            label,
            format!(
                "unsupported schema {} (the current controller accepts only schema {})",
                state.schema(),
                T::SCHEMA
            ),
        ));
    }
    Ok(state)
}

fn state_reset_required(path: &Path, label: &str, reason: String) -> anyhow::Error {
    anyhow!(
        "{}: {label} at {} is not safe for the current controller: {reason}. Back up this file first, then delete it and reinstall the current nazoauthctl release before retrying. Do not migrate, reinterpret, or reuse this state.",
        crate::error_codes::STATE_RESET_REQUIRED,
        path.display(),
    )
}

fn current_self_state_is_present(path: &Path, label: &str) -> anyhow::Result<bool> {
    path_is_present(path).map_err(|error| {
        state_reset_required(path, label, format!("cannot inspect it safely: {error:#}"))
    })
}

fn path_is_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn optional_secure_digest(path: &Path, label: &str) -> anyhow::Result<Option<String>> {
    if !path_is_present(path)? {
        return Ok(None);
    }
    secure_digest(path, label).map(Some)
}

fn secure_digest(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut file = open_secure_regular_file(path, label, false)?;
    sha256_file(&mut file, label)
}

fn ensure_digest(path: &Path, expected: &str, label: &str) -> anyhow::Result<()> {
    validate_digest(expected, label)?;
    let actual = secure_digest(path, label)?;
    if actual != expected {
        bail!("{label} digest differs from its trusted binding");
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} is not a SHA-256 digest");
    }
    Ok(())
}

fn validate_bound_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("{label} must be a normalized absolute path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_state_reset_required(error: anyhow::Error, path: &Path) {
        let rendered = format!("{error:#}");
        assert!(rendered.contains(crate::error_codes::STATE_RESET_REQUIRED));
        assert!(rendered.contains(&path.display().to_string()));
        assert!(rendered.contains("Back up this file first, then delete it"));
        assert!(rendered.contains("reinstall the current nazoauthctl release"));
        assert!(rendered.contains("Do not migrate, reinterpret, or reuse this state"));
    }

    #[test]
    fn trust_state_rejects_unknown_schema_with_clean_lineage_remediation() -> anyhow::Result<()> {
        let directory = crate::filesystem::PrivateTempDir::new("nazoauthctl-self-state")?;
        let path = directory.path().join("trust.json");
        atomic_write(
            &path,
            br#"{"schema":999,"version":"v0.2.0","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            0o600,
        )?;

        let error =
            read_current_self_state::<ControllerTrustState>(&path, "controller trust state")
                .expect_err("unknown trust schema must fail closed");
        assert_state_reset_required(error, &path);
        Ok(())
    }

    #[test]
    fn rollback_state_rejects_unknown_schema_with_clean_lineage_remediation() -> anyhow::Result<()>
    {
        let directory = crate::filesystem::PrivateTempDir::new("nazoauthctl-self-state")?;
        let path = directory.path().join("rollback.json");
        atomic_write(
            &path,
            br#"{"schema":999,"version":"v0.2.0","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":"/current/rollback"}"#,
            0o600,
        )?;

        let error =
            read_current_self_state::<ControllerRollbackState>(&path, "controller rollback state")
                .expect_err("unknown rollback schema must fail closed");
        assert_state_reset_required(error, &path);
        Ok(())
    }

    #[test]
    fn self_update_journal_rejects_unknown_schema_with_clean_lineage_remediation()
    -> anyhow::Result<()> {
        let directory = crate::filesystem::PrivateTempDir::new("nazoauthctl-self-state")?;
        let path = directory.path().join("update-transaction.json");
        atomic_write(
            &path,
            br#"{"schema":999,"transaction_id":"018f5555-5555-7555-8555-555555555555","operation":"update","phase":"intent","install_path":"/current/nazoauthctl","from_version":"v0.2.0","from_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to_version":"v0.2.1","to_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_artifact":"/current/rollback","rollback_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            0o600,
        )?;

        let error = load_self_update_journal(&path)
            .expect_err("unknown self-update journal schema must fail closed");
        assert_state_reset_required(error, &path);
        Ok(())
    }
}
