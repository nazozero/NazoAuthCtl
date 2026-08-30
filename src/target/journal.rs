//! Target-side durable operation journal — THE operational log of a target
//! host (goal plan 03 §3.2/§5 task C07, converged by H04).
//!
//! Before a target performs the first side effect of an accepted HostOperation,
//! one `{operation_id, canonical hash, status}` line is durably appended to
//! that deployment's journal under the target state root. Reconnects after a
//! dropped SSH session resolve through this journal alone:
//!
//! - same id + same canonical hash ⇒ replay; the stored result is returned
//!   verbatim (idempotent);
//! - same id + different hash ⇒ stable `OPERATION_ID_CONFLICT`; the original
//!   intent is never overwritten;
//! - an interrupted operation stays `pending` and is resumed by re-execution —
//!   which is only safe because every journaled kind must be resumable by its
//!   own checkpoints (the DeploymentState wave, F01).
//!
//! ## One operational-log story (H04)
//!
//! There is exactly one operational-log story across both journals ctl owns:
//!
//! * this target-side JSONL is the full per-deployment/per-host operation log
//!   and the resume authority for host operations; a target-verified update
//!   no-op removes its temporary pending line because it had no side effect to
//!   resume or audit;
//! * the control-side dispatch journal
//!   ([`crate::controller_identity::journal::OperationJournal`]) is a bounded
//!   single-slot pointer that lets ctl reuse `operation_id + request_hash`
//!   when resuming an app-level ControlOperation.
//!
//! Both are PLAIN durable records. No signing key exists anywhere on these
//! paths: same-host signing identities prove nothing against the one attacker
//! who could tamper with them anyway (host root), so tamper evidence is
//! delegated to plain-journal hygiene plus external WORM/SIEM shipping when a
//! deployment needs strong audit. A log-write failure after a committed state
//! mutation surfaces as an error but NEVER rolls the mutation back.
//!
//! ## Retention and bounding (H04)
//!
//! The journal is append-only within bounds and compacted in place beyond
//! them. Every effectful lifecycle mutation appends exactly ONE terminal line;
//! interrupted attempts leave their `pending` line as the resume point. The
//! bounds ([`JournalBounds::default`]) are:
//!
//! * steady-state cap 16 MiB per file — an append that crosses it triggers
//!   compaction on the next journal use;
//! * compaction keeps the newest terminal history down to an 8 MiB budget,
//!   never fewer than the newest 128 terminal lines, plus exactly the latest
//!   still-unsettled `pending` line for each interrupted operation;
//! * reads tolerate up to 32 MiB so a crash between an oversized append and
//!   its compaction still parses and self-heals instead of wedging.
//!
//! Within the retained window, replay/conflict answers are authoritative.
//! Beyond it, a retried ancient id simply executes again, which stays safe by
//! the same C07 invariant that makes interrupted resumes safe: every journaled
//! kind is resumable without double side effects.
//!
//! Lines are schema-checked (`deny_unknown_fields`), bounded, and parsed
//! strictly: a torn append or foreign byte fails closed with the stable
//! [`TARGET_JOURNAL_INVALID`] code instead of being repaired. The read-only
//! [`TargetJournal::operation_log`] view projects recent operations with their
//! status and outcome for status/doctor surfaces (CLI wiring lands with the
//! I wave); the controller never needs these lines for authorization.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error_codes::OPERATION_ID_CONFLICT;
use crate::filesystem;

use super::wire::{HOST_OPERATION_KINDS, HostOperation, HostResult, canonical_operation_hash};

/// Schema discriminator for every journal line. Version 2 added `action` and
/// `recorded_at` so the operation-log view can show what ran and when without
/// re-deriving facts the writer already held (H04). Older files fail closed.
pub const JOURNAL_SCHEMA: u32 = 2;

/// Stable error prefix for any journal content that does not parse as the
/// current schema or violates its own invariants. Repair is manual and
/// explicit; there is no lenient reader.
pub const TARGET_JOURNAL_INVALID: &str = "TARGET_JOURNAL_INVALID";

/// Steady-state upper bound for one deployment's journal file. An append that
/// crosses it schedules compaction before the next journal use.
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Compaction keeps the newest terminal history down to this byte budget.
const TRIM_TARGET_BYTES: u64 = 8 * 1024 * 1024;

/// Compaction always retains at least this many of the newest terminal lines,
/// even when they exceed the byte budget together.
const MIN_RETAINED_TERMINAL_LINES: usize = 128;

/// Read tolerance above the steady-state cap: a crash between an oversized
/// append and its compaction must still parse so compaction can run.
const READ_TOLERANCE_BYTES: u64 = 32 * 1024 * 1024;

/// Retention bounds for one journal file (H04). Production uses
/// [`JournalBounds::default`]; tests inject tiny numbers through
/// [`TargetJournal::with_bounds`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct JournalBounds {
    /// Steady-state cap: appends beyond this trigger compaction.
    pub(crate) max_bytes: u64,
    /// Byte budget the newest terminal history is kept within.
    pub(crate) target_bytes: u64,
    /// Minimum number of newest terminal lines always retained.
    pub(crate) min_terminal_retained: usize,
    /// Read cap used while parsing (>= `max_bytes` so recovery stays possible).
    pub(crate) read_cap: u64,
}

impl Default for JournalBounds {
    fn default() -> Self {
        Self {
            max_bytes: MAX_JOURNAL_BYTES,
            target_bytes: TRIM_TARGET_BYTES,
            min_terminal_retained: MIN_RETAINED_TERMINAL_LINES,
            read_cap: READ_TOLERANCE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalStatus {
    /// Durably recorded before the first side effect of the operation.
    Pending,
    /// The operation finished with a completed result.
    Completed,
    /// The operation finished with a failed result.
    Failed,
}

/// One append-only journal record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalLine {
    pub schema: u32,
    pub operation_id: String,
    /// Canonical SHA-256 over the accepted HostOperation (wire contract).
    pub operation_hash: String,
    /// Closed wire kind of the operation (`ping`, `state-mutate`, ...). Plain
    /// display fact for the operation-log view; the authoritative payload is
    /// the canonical hash.
    pub action: String,
    /// When this line was appended: acceptance time for pending lines,
    /// completion time for terminal ones.
    pub recorded_at: DateTime<Utc>,
    pub status: JournalStatus,
    /// Present exactly when `status` is terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<HostResult>,
}

/// Read-only projection of one journal line for status/doctor style surfaces
/// (H04; CLI wiring lands with the I wave). Never carries secret material:
/// HostResult payloads are already sanitized at the wire boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLogEntry {
    pub operation_id: String,
    /// Closed wire kind token (`state-mutate`, `control-operation`, ...).
    pub action: String,
    pub status: JournalStatus,
    pub recorded_at: DateTime<Utc>,
    /// Terminal outcome summary; absent while the entry is pending.
    pub outcome: Option<OperationOutcomeSummary>,
}

/// Outcome half of an [`OperationLogEntry`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationOutcomeSummary {
    Completed,
    Failed { code: String, detail: String },
}

/// Handle to the per-target operation journals under one state root.
///
/// The root is provisional until F01 formalizes target DeploymentState
/// storage; every path below the root is decided by [`TargetJournal::path_for`]
/// and nowhere else.
#[derive(Clone, Debug)]
pub struct TargetJournal {
    root: PathBuf,
    bounds: JournalBounds,
}

impl TargetJournal {
    /// Open (creating if needed) the journal root directory.
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        filesystem::ensure_private_directory(&root, "target state root")?;
        Ok(Self {
            root,
            bounds: JournalBounds::default(),
        })
    }

    /// Test seam: production semantics with tiny retention bounds so bounding
    /// behavior stays observable without multi-megabyte fixtures.
    #[cfg(test)]
    fn with_bounds(root: impl Into<PathBuf>, bounds: JournalBounds) -> anyhow::Result<Self> {
        let mut journal = Self::open(root)?;
        journal.bounds = bounds;
        Ok(journal)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The single decision point for where one scope's journal lives under
    /// the target state root. Nothing else may construct a journal path; F01
    /// replaces only the root selection, not this function's ownership.
    fn path_for(&self, scope: &str) -> PathBuf {
        self.root
            .join("deployments")
            .join(scope)
            .join("operations.jsonl")
    }

    /// Execute `operation` under the C07 journal contract.
    ///
    /// `execute` runs only for fresh (or interrupted-pending) operations and
    /// must be side-effect-safe to resume. Transport-level failures propagate
    /// without a terminal line, leaving the pending entry as the resume point.
    pub fn run_journaled(
        &self,
        operation: &HostOperation,
        execute: impl FnOnce(&HostOperation) -> HostResult,
    ) -> anyhow::Result<HostResult> {
        let scope = scope_slug(operation.deployment_id.as_deref())?;
        let path = self.path_for(&scope);
        let _lock = JournalLock::acquire(&path)?;
        // Bounding first: an oversized leftover from a crash between append
        // and compaction must shrink before strict parsing, never wedge.
        self.compact_if_needed(&path)?;
        let operation_hash = canonical_operation_hash(operation)?;
        let lines = read_lines_with(&path, self.bounds.read_cap)?;

        let mut latest: Option<JournalLine> = None;
        for line in lines
            .into_iter()
            .filter(|line| line.operation_id == operation.operation_id)
        {
            if line.operation_hash != operation_hash {
                return Ok(HostResult::failed(
                    operation.operation_id.clone(),
                    OPERATION_ID_CONFLICT,
                    format!(
                        "generate a new operation_id instead of retrying; this id was already \
                         accepted with request hash {} instead of {}",
                        line.operation_hash, operation_hash
                    ),
                ));
            }
            latest = Some(line);
        }

        let resumed = latest
            .as_ref()
            .is_some_and(|line| matches!(line.status, JournalStatus::Pending));

        // A terminal stored result is the authoritative idempotent answer.
        // A completed transfer-read intentionally stores no result bytes:
        // the immutable export can reproduce the same offset/hash response,
        // while retaining archive chunks here would turn the journal into a
        // second backup store. A pending line likewise resumes by execution.
        if let Some(line) = latest
            && !matches!(line.status, JournalStatus::Pending)
            && let Some(result) = line.result
        {
            return Ok(result);
        }

        let action = operation.operation.kind().to_owned();
        if !resumed {
            self.append(
                &path,
                &JournalLine {
                    schema: JOURNAL_SCHEMA,
                    operation_id: operation.operation_id.clone(),
                    operation_hash: operation_hash.clone(),
                    action: action.clone(),
                    recorded_at: Utc::now(),
                    status: JournalStatus::Pending,
                    result: None,
                },
            )?;
            self.compact_if_needed(&path)?;
        }
        let result = execute(operation);
        if matches!(
            (&operation.operation, &result.outcome),
            (
                super::wire::HostOperationBody::StateMutate {
                    mutation: super::deployment_state::StateMutationPayload::Update { .. }
                },
                super::wire::HostOutcome::Completed {
                    body: super::wire::HostCompletionBody::StateMutateNoop { .. }
                }
            )
        ) {
            self.remove_operation(&path, &operation.operation_id)?;
            return Ok(result);
        }
        if let super::wire::HostOutcome::Failed { ref code, .. } = result.outcome
            && (code == "CONTROL_OUTCOME_UNKNOWN" || code == "OUTCOME_UNKNOWN")
        {
            return Ok(result);
        }
        self.append(
            &path,
            &JournalLine {
                schema: JOURNAL_SCHEMA,
                operation_id: operation.operation_id.clone(),
                operation_hash: operation_hash.clone(),
                action,
                recorded_at: Utc::now(),
                status: match result.outcome {
                    super::wire::HostOutcome::Completed { .. } => JournalStatus::Completed,
                    super::wire::HostOutcome::Failed { .. } => JournalStatus::Failed,
                },
                result: if operation.operation.is_ephemeral_backup_read()
                    && matches!(result.outcome, super::wire::HostOutcome::Completed { .. })
                {
                    None
                } else {
                    Some(result.clone())
                },
            },
        )?;
        self.compact_if_needed(&path)?;
        Ok(result)
    }

    fn remove_operation(&self, path: &Path, operation_id: &str) -> anyhow::Result<()> {
        let lines = read_lines_with(path, self.bounds.read_cap)?;
        let mut bytes = Vec::new();
        for line in lines
            .into_iter()
            .filter(|line| line.operation_id != operation_id)
        {
            serde_json::to_writer(&mut bytes, &line)
                .with_context(|| format!("failed to re-encode the journal {}", path.display()))?;
            bytes.push(b'\n');
        }
        filesystem::atomic_write(path, &bytes, 0o600).with_context(|| {
            format!(
                "failed to discard no-op operation '{}' from {}",
                operation_id,
                path.display()
            )
        })
    }

    /// Durably append one line: single write call on an O_APPEND handle,
    /// followed by a file sync and a parent-directory sync.
    fn append(&self, path: &Path, line: &JournalLine) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(line).with_context(|| {
            format!("failed to serialize a journal line for {}", path.display())
        })?;
        bytes.push(b'\n');
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open the journal {}", path.display()))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("failed to persist the journal {}", path.display()))?;
        filesystem::sync_parent(path)
    }

    /// Enforce the H04 retention bounds: once the file exceeds
    /// [`JournalBounds::max_bytes`], rewrite it keeping exactly the lines
    /// [`keep_mask`] selects. Compaction runs under the exclusive journal lock
    /// and commits through the platform-atomic write path, so a crash leaves
    /// either the old or the new complete journal — never a torn mixture.
    fn compact_if_needed(&self, path: &Path) -> anyhow::Result<()> {
        let Ok(metadata) = fs::metadata(path) else {
            return Ok(());
        };
        if metadata.len() <= self.bounds.max_bytes {
            return Ok(());
        }
        let lines = read_lines_with(path, self.bounds.read_cap)?;
        let mask = keep_mask(&lines, &self.bounds);
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        for (line, keep) in lines.iter().zip(mask) {
            if !keep {
                continue;
            }
            serde_json::to_writer(&mut bytes, line)
                .with_context(|| format!("failed to re-encode the journal {}", path.display()))?;
            bytes.push(b'\n');
        }
        filesystem::atomic_write(path, &bytes, 0o600)
            .with_context(|| format!("failed to compact the journal {}", path.display()))
    }

    /// Read-only operation-log view for one deployment (H04): most recent
    /// operations in journal order with status and outcome projections.
    /// Purely observational — never consulted for authorization.
    pub fn operation_log(&self, deployment_id: &str) -> anyhow::Result<Vec<OperationLogEntry>> {
        let scope = deployment_scope(deployment_id)?;
        self.project_log(&self.path_for(&scope))
    }

    /// Read-only operation-log view for the host-level scope (operations
    /// carrying no deployment binding).
    pub fn host_operation_log(&self) -> anyhow::Result<Vec<OperationLogEntry>> {
        self.project_log(&self.path_for(HOST_SCOPE))
    }

    fn project_log(&self, path: &Path) -> anyhow::Result<Vec<OperationLogEntry>> {
        let lines = read_lines_with(path, self.bounds.read_cap)?;
        Ok(lines.iter().map(project_entry).collect())
    }
}

/// Project one journal line into the read-only view type.
fn project_entry(line: &JournalLine) -> OperationLogEntry {
    OperationLogEntry {
        operation_id: line.operation_id.clone(),
        action: line.action.clone(),
        status: line.status,
        recorded_at: line.recorded_at,
        outcome: match (&line.status, &line.result) {
            (
                JournalStatus::Completed | JournalStatus::Failed,
                Some(super::wire::HostResult {
                    outcome: super::wire::HostOutcome::Completed { .. },
                    ..
                }),
            ) => Some(OperationOutcomeSummary::Completed),
            (
                JournalStatus::Completed | JournalStatus::Failed,
                Some(super::wire::HostResult {
                    outcome: super::wire::HostOutcome::Failed { code, detail },
                    ..
                }),
            ) => Some(OperationOutcomeSummary::Failed {
                code: code.clone(),
                detail: detail.clone(),
            }),
            _ => None,
        },
    }
}

/// Pure retention decision for compaction (H04): walk newest → oldest and keep
///
/// * the newest `pending` line for an operation only when no newer terminal
///   line settles it;
/// * terminal lines while the retained byte budget lasts, plus at least
///   `bounds.min_terminal_retained` newest terminal lines regardless of size.
///
/// Superseded and duplicate pending lines carry no recovery information. If
/// retained forever, every successful operation permanently consumes journal
/// space and eventually makes the journal exceed its own hard read cap.
pub(crate) fn keep_mask(lines: &[JournalLine], bounds: &JournalBounds) -> Vec<bool> {
    let mut mask = vec![false; lines.len()];
    let mut budget = bounds.target_bytes;
    let mut retained_terminals = 0usize;
    let mut terminal_seen = HashSet::new();
    let mut pending_seen = HashSet::new();
    for index in (0..lines.len()).rev() {
        if matches!(lines[index].status, JournalStatus::Pending) {
            if !terminal_seen.contains(lines[index].operation_id.as_str())
                && pending_seen.insert(lines[index].operation_id.as_str())
            {
                mask[index] = true;
            }
            continue;
        }
        terminal_seen.insert(lines[index].operation_id.as_str());
        let size = serde_json::to_vec(&lines[index]).map_or(0, |bytes| bytes.len() as u64);
        if retained_terminals < bounds.min_terminal_retained || budget >= size {
            mask[index] = true;
            retained_terminals += 1;
            budget = budget.saturating_sub(size);
        }
    }
    mask
}

/// Exclusive lock serializing journal readers and writers per scope, so two
/// concurrent remote-exec processes cannot interleave acceptance decisions.
struct JournalLock {
    file: fs::File,
}

impl JournalLock {
    fn acquire(journal_path: &Path) -> anyhow::Result<Self> {
        let parent = journal_path
            .parent()
            .context("journal path has no parent directory")?;
        filesystem::ensure_directory_chain(parent)?;
        let lock_path = journal_path.with_extension("lock");
        let file = filesystem::open_lock_file(&lock_path, false, "target operation journal lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another controller holds {}", lock_path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Deployment ids become path components here, so they are re-validated at
/// the boundary that consumes them: registry-legal identifiers pass, anything
/// with separators or traversal segments fails closed.
///
/// This is the single rule source for deployment-scope directory names; the
/// DeploymentState store (F01) reuses it so a state document and its journal
/// always share one scope directory.
pub(crate) fn deployment_scope(deployment_id: &str) -> anyhow::Result<String> {
    let legal = !deployment_id.is_empty()
        && deployment_id.len() <= 128
        && deployment_id != "."
        && deployment_id != ".."
        && deployment_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character));
    if legal {
        Ok(deployment_id.to_owned())
    } else {
        bail!("{TARGET_JOURNAL_INVALID}: deployment_id is not usable as a journal scope")
    }
}

fn scope_slug(deployment_id: Option<&str>) -> anyhow::Result<String> {
    match deployment_id {
        None => Ok(HOST_SCOPE.to_owned()),
        Some(id) => deployment_scope(id),
    }
}

/// Journal scope for host-level operations that carry no deployment binding.
const HOST_SCOPE: &str = "host";

fn read_lines_with(path: &Path, read_cap: u64) -> anyhow::Result<Vec<JournalLine>> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(Vec::new());
    }
    let bytes =
        filesystem::read_secure_regular_file(path, "target operation journal", false, read_cap)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        anyhow::anyhow!(
            "{TARGET_JOURNAL_INVALID}: journal is not UTF-8 ({})",
            path.display()
        )
    })?;
    if !text.is_empty() && !text.ends_with('\n') {
        bail!(
            "{TARGET_JOURNAL_INVALID}: journal ends mid-line after an interrupted append; \
             inspect and truncate {} before retrying",
            path.display()
        );
    }
    let mut lines = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            bail!(
                "{TARGET_JOURNAL_INVALID}: blank journal line {} ({})",
                index + 1,
                path.display()
            );
        }
        let entry: JournalLine = serde_json::from_str(line).map_err(|error| {
            anyhow::anyhow!(
                "{TARGET_JOURNAL_INVALID}: journal line {} does not parse ({error})",
                index + 1
            )
        })?;
        validate_entry(&entry, index + 1)?;
        lines.push(entry);
    }
    Ok(lines)
}

fn validate_entry(entry: &JournalLine, line_number: usize) -> anyhow::Result<()> {
    if entry.schema != JOURNAL_SCHEMA {
        bail!(
            "{TARGET_JOURNAL_INVALID}: journal line {line_number} carries schema {} (expected \
             {JOURNAL_SCHEMA})",
            entry.schema
        );
    }
    if Uuid::parse_str(&entry.operation_id).is_err() {
        bail!("{TARGET_JOURNAL_INVALID}: journal line {line_number} has a malformed operation_id");
    }
    let hash_legal = entry.operation_hash.len() == 64
        && entry
            .operation_hash
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase());
    if !hash_legal {
        bail!(
            "{TARGET_JOURNAL_INVALID}: journal line {line_number} has a malformed operation_hash"
        );
    }
    if !HOST_OPERATION_KINDS.contains(&entry.action.as_str()) {
        bail!(
            "{TARGET_JOURNAL_INVALID}: journal line {line_number} carries unknown action '{}'",
            crate::target::wire::sanitize(entry.action.clone())
        );
    }
    match entry.status {
        JournalStatus::Pending if entry.result.is_none() => Ok(()),
        JournalStatus::Completed
            if entry.action == "backup-transfer-read" && entry.result.is_none() =>
        {
            Ok(())
        }
        JournalStatus::Completed | JournalStatus::Failed => match &entry.result {
            Some(result) if result.operation_id == entry.operation_id => Ok(()),
            _ => bail!(
                "{TARGET_JOURNAL_INVALID}: terminal journal line {line_number} must carry \
                     its own result"
            ),
        },
        JournalStatus::Pending => bail!(
            "{TARGET_JOURNAL_INVALID}: pending journal line {line_number} must not carry a result"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::wire::{HostCompletionBody, HostOutcome};

    fn ping_operation(nonce: &str) -> HostOperation {
        HostOperation::ping(Uuid::now_v7().to_string(), nonce)
    }

    fn update_operation() -> HostOperation {
        HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(4),
            super::super::deployment_state::StateMutationPayload::Update {
                artifact: super::super::install_exec::OfficialArtifactRef {
                    repository: "nazozero/NazoAuth".to_owned(),
                    version: Some("v0.2.6".to_owned()),
                },
                backup_precondition:
                    super::super::deployment_state::UpdateBackupPrecondition::NotRequired,
                config: None,
                migration_jws: None,
                migration_request_hash: None,
            },
        )
    }

    #[test]
    fn transfer_read_terminal_omits_archive_bytes_but_other_terminals_cannot() {
        let base = JournalLine {
            schema: JOURNAL_SCHEMA,
            operation_id: Uuid::now_v7().to_string(),
            operation_hash: "a".repeat(64),
            action: "backup-transfer-read".to_owned(),
            recorded_at: Utc::now(),
            status: JournalStatus::Completed,
            result: None,
        };
        assert!(validate_entry(&base, 1).is_ok());
        let ordinary = JournalLine {
            action: "backup-transfer-write".to_owned(),
            ..base
        };
        assert!(validate_entry(&ordinary, 1).is_err());
    }

    fn echo_result(operation: &HostOperation) -> HostResult {
        HostResult::completed(
            operation.operation_id.clone(),
            match &operation.operation {
                super::super::wire::HostOperationBody::Ping { nonce } => HostCompletionBody::Ping {
                    nonce: nonce.clone(),
                },
                _ => unreachable!("tests only dispatch pings"),
            },
        )
    }

    /// A fully valid synthetic journal line whose stored result matches its
    /// own operation id, so compaction's strict re-parse accepts it.
    fn synthetic_line(operation_id: String, status: JournalStatus) -> JournalLine {
        JournalLine {
            schema: JOURNAL_SCHEMA,
            operation_id: operation_id.clone(),
            operation_hash: "ab".repeat(32),
            action: "ping".to_owned(),
            recorded_at: Utc::now(),
            status,
            result: match status {
                JournalStatus::Pending => None,
                _ => Some(HostResult::completed(
                    operation_id,
                    HostCompletionBody::Ping {
                        nonce: "seed".to_owned(),
                    },
                )),
            },
        }
    }

    #[test]
    fn fresh_operations_are_journaled_pending_then_terminal() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = ping_operation("probe");

        // Observe the intermediate state from inside the executed closure.
        let scope_dir = temp
            .path()
            .join("state")
            .join("deployments")
            .join(HOST_SCOPE);
        let observed_pending = std::sync::Mutex::new(false);
        let hook_operation: HostOperation = serde_json::from_slice(
            &serde_json::to_vec(&operation).expect("serialize public test operation"),
        )
        .expect("deserialize public test operation");
        let hook_journal = journal.clone();
        let observed = &observed_pending;
        let result = hook_journal.run_journaled(&hook_operation, |operation| {
            // The journal file exists and holds exactly the pending line.
            let raw = fs::read_to_string(scope_dir.join("operations.jsonl"))
                .expect("pending journal line must be durable before execution");
            let lines: Vec<&str> = raw.lines().collect();
            assert_eq!(lines.len(), 1, "{raw}");
            assert!(lines[0].contains("\"pending\""), "{raw}");
            *observed.lock().unwrap() = true;
            echo_result(operation)
        })?;

        assert!(observed_pending.lock().unwrap().to_owned());
        assert_eq!(result, echo_result(&operation));

        // The terminal line is appended after execution.
        let raw = fs::read_to_string(scope_dir.join("operations.jsonl"))?;
        assert_eq!(raw.lines().count(), 2);
        let last = serde_json::from_str::<JournalLine>(raw.lines().last().unwrap())?;
        assert_eq!(last.status, JournalStatus::Completed);
        assert_eq!(last.result, Some(echo_result(&operation)));
        assert_eq!(last.action, "ping");
        Ok(())
    }

    #[test]
    fn target_verified_update_noop_leaves_no_journal_history() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-noop-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = update_operation();
        let path = journal.path_for("deploy-alpha");

        let result = journal.run_journaled(&operation, |operation| {
            let pending = fs::read_to_string(&path).expect("pending line must exist during verify");
            assert_eq!(pending.lines().count(), 1, "{pending}");
            HostResult::completed(
                operation.operation_id.clone(),
                HostCompletionBody::StateMutateNoop { revision: 4 },
            )
        })?;
        assert!(matches!(
            result.outcome,
            HostOutcome::Completed {
                body: HostCompletionBody::StateMutateNoop { revision: 4 }
            }
        ));
        assert_eq!(fs::read_to_string(&path)?, "");
        assert!(journal.operation_log("deploy-alpha")?.is_empty());

        let retried = std::cell::Cell::new(false);
        journal.run_journaled(&operation, |operation| {
            retried.set(true);
            HostResult::completed(
                operation.operation_id.clone(),
                HostCompletionBody::StateMutateNoop { revision: 4 },
            )
        })?;
        assert!(retried.get(), "a no-op has no replay authority to retain");
        assert_eq!(fs::read_to_string(path)?, "");
        Ok(())
    }

    #[test]
    fn replays_return_the_stored_result_without_reexecution() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = ping_operation("same");

        let first = journal.run_journaled(&operation, echo_result)?;
        // If this closure ever ran, the divergent nonce would prove re-execution.
        let second = journal.run_journaled(&operation, |operation| {
            HostResult::completed(
                operation.operation_id.clone(),
                HostCompletionBody::Ping {
                    nonce: "reexecuted".to_owned(),
                },
            )
        })?;
        assert_eq!(second, first);
        assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
        Ok(())
    }

    #[test]
    fn same_id_with_a_different_payload_is_a_stable_conflict() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let mut operation = ping_operation("original");
        let _ = journal.run_journaled(&operation, echo_result)?;

        operation.operation = crate::target::wire::HostOperationBody::Ping {
            nonce: "tampered".to_owned(),
        };
        let conflict = journal.run_journaled(&operation, echo_result)?;
        let HostOutcome::Failed { code, detail } = conflict.outcome else {
            panic!("conflict must surface as a failed outcome");
        };
        assert_eq!(code, OPERATION_ID_CONFLICT);
        assert!(detail.contains("generate a new operation_id"), "{detail}");
        Ok(())
    }

    #[test]
    fn deployment_scopes_are_isolated_and_host_level_uses_the_host_scope() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;

        let mut bound = ping_operation("scoped");
        bound.deployment_id = Some("deploy-alpha".to_owned());
        journal.run_journaled(&bound, echo_result)?;
        journal.run_journaled(&ping_operation("host"), echo_result)?;

        assert!(
            temp.path()
                .join("state/deployments/deploy-alpha/operations.jsonl")
                .is_file()
        );
        assert!(
            temp.path()
                .join(format!("state/deployments/{HOST_SCOPE}/operations.jsonl"))
                .is_file()
        );
        Ok(())
    }

    #[test]
    fn unsafe_deployment_ids_never_become_path_components() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        for hostile in ["../escape", "a/b", r"back\slash", ".", "..", "", "sp ace"] {
            let mut operation = ping_operation("x");
            operation.deployment_id = Some(hostile.to_owned());
            let error = journal
                .run_journaled(&operation, echo_result)
                .expect_err(hostile);
            assert!(
                error.to_string().contains(TARGET_JOURNAL_INVALID),
                "{hostile}: {error}"
            );
        }
        // Legal registry-style identifiers keep working. (Registry ids may
        // also contain ':', which is legal on the Linux target hosts but not
        // as a directory name on Windows development machines.)
        let mut operation = ping_operation("ok");
        operation.deployment_id = Some("deploy-alpha_2-beta-x.1".to_owned());
        journal.run_journaled(&operation, echo_result)?;
        Ok(())
    }

    #[test]
    fn corrupt_or_torn_journals_fail_closed() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let path = temp
            .path()
            .join("state/deployments")
            .join(HOST_SCOPE)
            .join("operations.jsonl");

        filesystem::atomic_write(&path, b"{ not json\n", 0o600)?;
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("corrupt");
        assert!(
            error.to_string().contains(TARGET_JOURNAL_INVALID),
            "{error}"
        );

        filesystem::atomic_write(&path, b"{\"schema\":2}", 0o600)?; // torn: no newline
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("torn");
        assert!(error.to_string().contains("mid-line"), "{error}");

        // A foreign schema version is rejected instead of interpreted.
        let stale = format!(
            "{{\"schema\":1,\"operation_id\":\"{}\",\"operation_hash\":\"{}\",\"action\":\"ping\",\"recorded_at\":\"2026-08-24T00:00:00Z\",\"status\":\"pending\"}}\n",
            Uuid::now_v7(),
            "0".repeat(64),
        );
        filesystem::atomic_write(&path, stale.as_bytes(), 0o600)?;
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("stale schema");
        assert!(error.to_string().contains("carries schema 1"), "{error}");

        // A pending line carrying a result violates the line invariant.
        let poisoned = format!(
            "{{\"schema\":2,\"operation_id\":\"{}\",\"operation_hash\":\"{}\",\"action\":\"ping\",\"recorded_at\":\"2026-08-24T00:00:00Z\",\"status\":\"pending\",\"result\":{{\"schema\":2,\"operation_id\":\"{}\",\"outcome\":{{\"status\":\"failed\",\"code\":\"X\",\"detail\":\"d\"}}}}}}\n",
            Uuid::now_v7(),
            "0".repeat(64),
            Uuid::now_v7()
        );
        filesystem::atomic_write(&path, poisoned.as_bytes(), 0o600)?;
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("invariant");
        assert!(
            error.to_string().contains(TARGET_JOURNAL_INVALID),
            "{error}"
        );

        // Unknown actions fail closed too: the action set mirrors the wire.
        let hostile_action = format!(
            "{{\"schema\":2,\"operation_id\":\"{}\",\"operation_hash\":\"{}\",\"action\":\"teleport\",\"recorded_at\":\"2026-08-24T00:00:00Z\",\"status\":\"pending\"}}\n",
            Uuid::now_v7(),
            "0".repeat(64),
        );
        filesystem::atomic_write(&path, hostile_action.as_bytes(), 0o600)?;
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("unknown action");
        assert!(error.to_string().contains("unknown action"), "{error}");
        Ok(())
    }

    #[test]
    fn interrupted_pending_entries_resume_by_execution() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-test")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = ping_operation("resume-me");

        // Simulate a crash between the pending append and the terminal append.
        let path = temp
            .path()
            .join("state/deployments")
            .join(HOST_SCOPE)
            .join("operations.jsonl");
        filesystem::ensure_directory_chain(path.parent().expect("journal parent"))?;
        let hash = canonical_operation_hash(&operation)?;
        journal.append(
            &path,
            &JournalLine {
                schema: JOURNAL_SCHEMA,
                operation_id: operation.operation_id.clone(),
                operation_hash: hash,
                action: "ping".to_owned(),
                recorded_at: Utc::now(),
                status: JournalStatus::Pending,
                result: None,
            },
        )?;

        let executions = std::cell::Cell::new(0u8);
        let resumed = journal.run_journaled(&operation, |operation| {
            executions.set(executions.get() + 1);
            echo_result(operation)
        })?;
        assert_eq!(executions.get(), 1, "pending entries resume by running");
        assert_eq!(resumed, echo_result(&operation));
        let raw = fs::read_to_string(&path)?;
        assert_eq!(raw.lines().count(), 2, "one pending + terminal");
        Ok(())
    }

    // ------------------------------------------------------------- H04 bounds

    fn tiny_bounds() -> JournalBounds {
        JournalBounds {
            max_bytes: 1_400,
            target_bytes: 500,
            min_terminal_retained: 2,
            read_cap: 64 * 1024,
        }
    }

    #[test]
    fn keep_mask_keeps_only_unsettled_pendings_and_the_newest_terminal_window() {
        // Oldest -> newest: [terminal_old, pending, terminal_mid, recent1,
        // recent2]. With a zero byte budget and a floor of two retained
        // terminals, exactly the two newest terminals plus the pending line
        // survive; older history trims first.
        let mk = |status| synthetic_line(Uuid::now_v7().to_string(), status);
        let lines = vec![
            mk(JournalStatus::Completed),
            mk(JournalStatus::Pending),
            mk(JournalStatus::Completed),
            mk(JournalStatus::Completed),
            mk(JournalStatus::Completed),
        ];
        let bounds = JournalBounds {
            max_bytes: 10_000,
            target_bytes: 0,
            min_terminal_retained: 2,
            read_cap: 64 * 1024,
        };
        assert_eq!(
            keep_mask(&lines, &bounds),
            vec![false, true, false, true, true]
        );

        // A generous budget keeps everything terminal as well.
        let generous = JournalBounds {
            max_bytes: 10_000,
            target_bytes: u64::MAX,
            min_terminal_retained: 0,
            read_cap: 64 * 1024,
        };
        assert_eq!(
            keep_mask(&lines, &generous),
            vec![true, true, true, true, true]
        );

        let settled_id = Uuid::now_v7().to_string();
        let unresolved_id = Uuid::now_v7().to_string();
        let lines = vec![
            synthetic_line(settled_id.clone(), JournalStatus::Pending),
            synthetic_line(settled_id, JournalStatus::Completed),
            synthetic_line(unresolved_id.clone(), JournalStatus::Pending),
            synthetic_line(unresolved_id, JournalStatus::Pending),
        ];
        assert_eq!(
            keep_mask(&lines, &generous),
            vec![false, true, false, true],
            "settled and duplicate pending lines carry no recovery state"
        );
    }

    #[test]
    fn bounding_trims_old_terminals_but_keeps_unsettled_pending_entries() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-bounds")?;
        let journal = TargetJournal::with_bounds(temp.path().join("state"), tiny_bounds())?;
        let path = temp
            .path()
            .join("state/deployments/deploy-alpha/operations.jsonl");

        // Build an over-cap journal directly: one ancient PENDING entry (the
        // resumable window) followed by eight completed entries. Direct
        // appends bypass run_journaled's lock-time directory creation.
        filesystem::ensure_directory_chain(path.parent().expect("journal parent"))?;
        let mut ids = Vec::new();
        let pending_id = Uuid::now_v7().to_string();
        journal.append(
            &path,
            &synthetic_line(pending_id.clone(), JournalStatus::Pending),
        )?;
        for _ in 0..8 {
            let id = Uuid::now_v7().to_string();
            ids.push(id.clone());
            journal.append(&path, &synthetic_line(id, JournalStatus::Completed))?;
        }
        assert!(fs::metadata(&path)?.len() > tiny_bounds().max_bytes);

        // The next journal use compacts first, then executes normally.
        let mut fresh = ping_operation("after-compaction");
        fresh.deployment_id = Some("deploy-alpha".to_owned());
        let result = journal.run_journaled(&fresh, echo_result)?;
        assert_eq!(result, echo_result(&fresh));

        let raw = fs::read_to_string(&path)?;
        let survivors: Vec<JournalLine> = raw
            .lines()
            .map(serde_json::from_str::<JournalLine>)
            .collect::<Result<_, _>>()?;

        // The pending window survived verbatim.
        assert!(
            survivors.iter().any(
                |line| line.operation_id == pending_id && line.status == JournalStatus::Pending
            ),
            "the unsettled pending entry must survive"
        );
        // At least the minimum newest-terminal floor survived, and the oldest
        // terminals were actually trimmed away.
        let terminal_survivors = survivors
            .iter()
            .filter(|line| line.status != JournalStatus::Pending)
            .count();
        assert!(
            terminal_survivors >= tiny_bounds().min_terminal_retained,
            "{terminal_survivors}"
        );
        let oldest_seed_dropped = ids
            .first()
            .is_some_and(|id| !survivors.iter().any(|line| &line.operation_id == id));
        assert!(oldest_seed_dropped, "oldest terminal lines must trim first");
        // Steady-state cap holds again after the fresh execution.
        assert!(
            fs::metadata(&path)?.len() <= tiny_bounds().max_bytes,
            "{} bytes",
            fs::metadata(&path)?.len()
        );
        // And the fresh operation replays idempotently through the compacted
        // journal.
        let replay = journal.run_journaled(&fresh, echo_result)?;
        assert_eq!(replay, result);
        Ok(())
    }

    #[test]
    fn compaction_drops_historical_pending_lines_settled_by_terminals() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-settled-pending")?;
        let journal = TargetJournal::with_bounds(temp.path().join("state"), tiny_bounds())?;
        let path = temp
            .path()
            .join("state/deployments/deploy-alpha/operations.jsonl");
        filesystem::ensure_directory_chain(path.parent().expect("journal parent"))?;
        for _ in 0..24 {
            let operation_id = Uuid::now_v7().to_string();
            journal.append(
                &path,
                &synthetic_line(operation_id.clone(), JournalStatus::Pending),
            )?;
            journal.append(
                &path,
                &synthetic_line(operation_id, JournalStatus::Completed),
            )?;
        }
        assert!(fs::metadata(&path)?.len() > tiny_bounds().max_bytes);

        let mut fresh = ping_operation("compact-settled");
        fresh.deployment_id = Some("deploy-alpha".to_owned());
        journal.run_journaled(&fresh, echo_result)?;
        let survivors: Vec<JournalLine> = fs::read_to_string(&path)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert!(
            survivors
                .iter()
                .filter(|line| line.operation_id != fresh.operation_id)
                .all(|line| !matches!(line.status, JournalStatus::Pending)),
            "settled pending history must not survive compaction"
        );
        assert!(fs::metadata(&path)?.len() <= tiny_bounds().max_bytes);
        Ok(())
    }

    #[test]
    fn compaction_never_wedges_an_oversized_leftover() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-wedge")?;
        let journal = TargetJournal::with_bounds(temp.path().join("state"), tiny_bounds())?;
        let path = temp
            .path()
            .join("state/deployments/deploy-alpha/operations.jsonl");
        // Over-cap file built while bounds were large: simulate by direct
        // appends with the default-sized journal handle.
        filesystem::ensure_directory_chain(path.parent().expect("journal parent"))?;
        let loose = TargetJournal::open(temp.path().join("state"))?;
        for _ in 0..40 {
            loose.append(
                &path,
                &synthetic_line(Uuid::now_v7().to_string(), JournalStatus::Completed),
            )?;
        }
        assert!(fs::metadata(&path)?.len() > tiny_bounds().max_bytes);

        // Strict parsing under the tiny read tolerance would fail; compaction
        // uses the larger read cap and brings the file back under control.
        let mut fresh = ping_operation("recover");
        fresh.deployment_id = Some("deploy-alpha".to_owned());
        let result = journal.run_journaled(&fresh, echo_result)?;
        assert_eq!(result, echo_result(&fresh));
        assert!(fs::metadata(&path)?.len() <= tiny_bounds().max_bytes);
        Ok(())
    }

    #[test]
    fn every_executed_mutation_appends_exactly_one_terminal_line() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-terminal")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;

        let first = ping_operation("one");
        journal.run_journaled(&first, echo_result)?;
        let second = ping_operation("two");
        let failed = HostResult::failed(&second.operation_id, "X_CODE", "scripted failure");
        let executed = journal.run_journaled(&second, |_| failed.clone())?;
        assert_eq!(executed, failed);
        // A retry of the SAME id replays the stored terminal answer and must
        // not append anything new.
        let replayed = journal.run_journaled(&second, echo_result)?;
        assert_eq!(replayed, failed);

        let entries = journal.host_operation_log()?;
        for operation_id in [first.operation_id.as_str(), second.operation_id.as_str()] {
            let terminals = entries
                .iter()
                .filter(|entry| entry.operation_id == operation_id)
                .filter(|entry| entry.status != JournalStatus::Pending)
                .count();
            assert_eq!(terminals, 1, "{operation_id}: exactly one terminal line");
        }
        Ok(())
    }

    #[test]
    fn operation_log_view_reports_status_outcome_and_replays() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-journal-view")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;

        let completed = ping_operation("view-ok");
        journal.run_journaled(&completed, echo_result)?;
        let failing = ping_operation("view-fail");
        let failed = HostResult::failed(
            &failing.operation_id,
            "DEPLOYMENT_UNKNOWN",
            "no such instance",
        );
        journal.run_journaled(&failing, |_| failed.clone())?;
        // Replay adds nothing but the view still shows the stored outcome.
        journal.run_journaled(&completed, echo_result)?;

        let entries = journal.host_operation_log()?;
        assert_eq!(entries.len(), 4, "pending+terminal per executed attempt");
        let completed_entry = entries
            .iter()
            .filter(|entry| entry.status != JournalStatus::Pending)
            .find(|entry| entry.operation_id == completed.operation_id)
            .expect("completed terminal entry present");
        assert_eq!(completed_entry.action, "ping");
        assert_eq!(
            completed_entry.outcome,
            Some(OperationOutcomeSummary::Completed)
        );
        let failed_entry = entries
            .iter()
            .filter(|entry| entry.status != JournalStatus::Pending)
            .find(|entry| entry.operation_id == failing.operation_id)
            .expect("failed terminal entry present");
        assert_eq!(
            failed_entry.outcome,
            Some(OperationOutcomeSummary::Failed {
                code: "DEPLOYMENT_UNKNOWN".to_owned(),
                detail: "no such instance".to_owned(),
            })
        );
        assert!(completed_entry.recorded_at <= failed_entry.recorded_at);
        Ok(())
    }
}
