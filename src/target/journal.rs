//! Target-side durable operation journal — THE operational log of a target
//! host (goal plan 03 §3.2/§5 task C07, converged by H04).
//!
//! Before a target performs the first side effect of an accepted HostOperation,
//! one `{operation_id, canonical hash, status}` line is durably appended to
//! that deployment's journal under the target state root. Reconnects after a
//! dropped SSH session resolve through this journal alone:
//!
//! - same id + same canonical hash ⇒ replay; the stored result is returned
//!   verbatim (idempotent), except failed recovery-phase operations, whose own
//!   operation-bound checkpoints require the same id for forward resumption;
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
//!   preferring the newest 128 terminal lines within the 16 MiB cap, plus the latest
//!   still-unsettled `pending` line for each interrupted operation;
//! * new operations stop at 8 MiB of unsettled entries, reserving room for
//!   terminal receipts; existing pending operations can still resume;
//! * reads tolerate up to 32 MiB so a crash between an oversized append and
//!   its compaction still parses and self-heals instead of wedging.
//!
//! Within the retained window, replay/conflict answers are authoritative.
//! Beyond it, a retried ancient id simply executes again, which stays safe by
//! the same C07 invariant that makes interrupted resumes safe: every journaled
//! kind is resumable without double side effects.
//!
//! Lines are schema-checked (`deny_unknown_fields`), bounded, and parsed
//! strictly: only an incomplete final JSON record is discarded under the writer lock.
//! Complete malformed records fail closed with the stable
//! [`TARGET_JOURNAL_INVALID`] code instead of being repaired. The read-only
//! [`TargetJournal::operation_log`] view projects recent operations with their
//! status and outcome for status/doctor surfaces (CLI wiring lands with the
//! I wave); the controller never needs these lines for authorization.

use std::{
    collections::HashSet,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error_codes::OPERATION_ID_CONFLICT;
use crate::{file_lock::FileLock, filesystem};

use super::wire::{HOST_OPERATION_KINDS, HostOperation, HostResult, canonical_operation_hash};

/// Schema discriminator for every journal line. Version 2 added `action` and
/// `recorded_at` so the operation-log view can show what ran and when without
/// re-deriving facts the writer already held (H04). Older files fail closed.
pub const JOURNAL_SCHEMA: u32 = 2;

/// Stable error prefix for any journal content that does not parse as the
/// current schema or violates its own invariants. Repair is manual and
/// explicit; there is no lenient reader.
pub const TARGET_JOURNAL_INVALID: &str = "TARGET_JOURNAL_INVALID";
pub const TARGET_JOURNAL_CAPACITY: &str = "TARGET_JOURNAL_CAPACITY";

/// Steady-state upper bound for one deployment's journal file. An append that
/// crosses it schedules compaction before the next journal use.
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Compaction keeps the newest terminal history down to this byte budget.
const TRIM_TARGET_BYTES: u64 = 8 * 1024 * 1024;

/// Preferred terminal count, subordinate to the steady-state byte cap.
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
    /// Unsettled admissions leave room for the largest terminal receipt.
    pub(crate) max_pending_bytes: u64,
    /// Byte budget the newest terminal history is kept within.
    pub(crate) target_bytes: u64,
    /// Preferred number of newest terminal lines within the hard byte budget.
    pub(crate) min_terminal_retained: usize,
    /// Read cap used while parsing (>= `max_bytes` so recovery stays possible).
    pub(crate) read_cap: u64,
}

impl Default for JournalBounds {
    fn default() -> Self {
        Self {
            max_bytes: MAX_JOURNAL_BYTES,
            max_pending_bytes: 8 * 1024 * 1024,
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
        let path = self.path_for(scope);
        filesystem::ensure_directory_chain(path.parent().expect("journal has a scope directory"))?;
        let _lock = FileLock::acquire(&path.with_extension("lock"))?;
        // Bounding first: an oversized leftover from a crash between append
        // and compaction must shrink before strict parsing, never wedge.
        let compacted = self.compact_if_needed(&path)?;
        let operation_hash = canonical_operation_hash(operation)?;
        let lines = match compacted {
            Some(lines) => lines,
            None => read_lines_with(&path, self.bounds.read_cap, true)?,
        };

        let mut latest: Option<JournalLine> = None;
        for line in lines
            .iter()
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
            latest = Some(line.clone());
        }

        let resumed = latest
            .as_ref()
            .is_some_and(|line| matches!(line.status, JournalStatus::Pending));

        let retry_failed_phase = latest.as_ref().is_some_and(|line| {
            matches!(line.status, JournalStatus::Failed)
                && matches!(
                    operation.operation,
                    super::wire::HostOperationBody::BackupRecover { .. }
                        | super::wire::HostOperationBody::BackupRecoveryCandidateStage { .. }
                        | super::wire::HostOperationBody::BackupRecoveryCandidateControl { .. }
                        | super::wire::HostOperationBody::BackupRecoveryCandidateCleanup { .. }
                        | super::wire::HostOperationBody::BackupRecoveryActivate { .. }
                        | super::wire::HostOperationBody::StateMutate {
                            mutation: super::deployment_state::StateMutationPayload::Uninstall {}
                        }
                )
        });

        // A terminal stored result is the authoritative idempotent answer.
        // A completed transfer-read intentionally stores no result bytes:
        // the immutable export can reproduce the same offset/hash response,
        // while retaining archive chunks here would turn the journal into a
        // second backup store. A pending line likewise resumes by execution.
        // Recovery stages and uninstall completion are bound to this operation
        // id. Their owners resume idempotently, including partial deletion.
        if let Some(line) = latest
            && !matches!(line.status, JournalStatus::Pending)
            && !retry_failed_phase
            && let Some(result) = line.result
        {
            return Ok(result);
        }

        let action = operation.operation.kind().to_owned();
        if !resumed {
            let pending = JournalLine {
                schema: JOURNAL_SCHEMA,
                operation_id: operation.operation_id.clone(),
                operation_hash: operation_hash.clone(),
                action: action.clone(),
                recorded_at: Utc::now(),
                status: JournalStatus::Pending,
                result: None,
            };
            let mut pending_bytes = serde_json::to_vec(&pending)?.len() as u64 + 1;
            let mut seen = HashSet::new();
            for line in lines.iter().rev() {
                if seen.insert(&line.operation_id) && matches!(line.status, JournalStatus::Pending)
                {
                    pending_bytes += serde_json::to_vec(line)?.len() as u64 + 1;
                }
            }
            if pending_bytes > self.bounds.max_pending_bytes {
                return Ok(HostResult::failed(
                    operation.operation_id.clone(),
                    TARGET_JOURNAL_CAPACITY,
                    "unsettled operations fill the journal admission budget; resume those operations before starting another",
                ));
            }
            self.append(&path, &pending)?;
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
            && matches!(
                code.as_str(),
                super::control_exec::CONTROL_OUTCOME_UNKNOWN
                    | super::control_exec::CONTROL_EXECUTION_UNAVAILABLE
                    | "OUTCOME_UNKNOWN"
                    // This code comes only from the host privilege preflight,
                    // before the first execution side effect.
                    | crate::error_codes::PRIVILEGE_REQUIRED
            )
        {
            return Ok(result);
        }
        let terminal = JournalLine {
            schema: JOURNAL_SCHEMA,
            operation_id: operation.operation_id.clone(),
            operation_hash,
            action,
            recorded_at: Utc::now(),
            status: match result.outcome {
                super::wire::HostOutcome::Completed { .. } => JournalStatus::Completed,
                super::wire::HostOutcome::Failed { .. } => JournalStatus::Failed,
            },
            result: Some(result),
        };
        self.append(&path, &terminal)?;
        self.compact_if_needed(&path)?;
        Ok(terminal.result.expect("terminal line owns the result"))
    }

    fn remove_operation(&self, path: &Path, operation_id: &str) -> anyhow::Result<()> {
        let lines = read_lines_with(path, self.bounds.read_cap, true)?;
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
        #[cfg(windows)]
        let mut file = filesystem::open_append_file(path, "target operation journal")?;
        #[cfg(not(windows))]
        let mut options = OpenOptions::new();
        #[cfg(not(windows))]
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(not(windows))]
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
    /// [`compact_lines`] selects. Compaction runs under the exclusive journal lock
    /// and commits through the platform-atomic write path, so a crash leaves
    /// either the old or the new complete journal — never a torn mixture.
    fn compact_if_needed(&self, path: &Path) -> anyhow::Result<Option<Vec<JournalLine>>> {
        let Ok(metadata) = fs::metadata(path) else {
            return Ok(None);
        };
        if metadata.len() <= self.bounds.max_bytes {
            return Ok(None);
        }
        let mut lines = read_lines_with(path, self.bounds.read_cap, true)?;
        let bytes = compact_lines(&mut lines, &self.bounds)
            .with_context(|| format!("failed to re-encode the journal {}", path.display()))?;
        filesystem::atomic_write(path, &bytes, 0o600)
            .with_context(|| format!("failed to compact the journal {}", path.display()))?;
        Ok(Some(lines))
    }

    /// Read-only operation-log view for one deployment (H04): most recent
    /// operations in journal order with status and outcome projections.
    /// Purely observational — never consulted for authorization.
    pub fn operation_log(&self, deployment_id: &str) -> anyhow::Result<Vec<OperationLogEntry>> {
        let scope = deployment_scope(deployment_id)?;
        self.project_log(&self.path_for(scope))
    }

    /// Read-only operation-log view for the host-level scope (operations
    /// carrying no deployment binding).
    pub fn host_operation_log(&self) -> anyhow::Result<Vec<OperationLogEntry>> {
        self.project_log(&self.path_for(HOST_SCOPE))
    }

    fn project_log(&self, path: &Path) -> anyhow::Result<Vec<OperationLogEntry>> {
        let lines = read_lines_with(path, self.bounds.read_cap, false)?;
        Ok(lines.into_iter().map(project_entry).collect())
    }
}

/// Project one journal line into the read-only view type.
fn project_entry(line: JournalLine) -> OperationLogEntry {
    OperationLogEntry {
        operation_id: line.operation_id,
        action: line.action,
        status: line.status,
        recorded_at: line.recorded_at,
        outcome: match (line.status, line.result) {
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
            ) => Some(OperationOutcomeSummary::Failed { code, detail }),
            _ => None,
        },
    }
}

/// Encode each line once, then retain its byte range in place. Walk newest → oldest and keep
///
/// * the newest `pending` line for an operation only when no newer terminal
///   line settles it;
/// * terminal lines while the retained byte budget lasts, plus at least
///   `bounds.min_terminal_retained` newest terminal lines within the hard cap.
///
/// Superseded and duplicate pending lines carry no recovery information. If
/// retained forever, every successful operation permanently consumes journal
/// space and eventually makes the journal exceed its own hard read cap.
fn compact_lines(
    lines: &mut Vec<JournalLine>,
    bounds: &JournalBounds,
) -> serde_json::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut ranges = Vec::with_capacity(lines.len());
    for line in lines.iter() {
        let start = bytes.len();
        serde_json::to_writer(&mut bytes, line)?;
        bytes.push(b'\n');
        ranges.push(start..bytes.len());
    }
    let mut mask = vec![false; lines.len()];
    let mut budget = bounds.target_bytes;
    let mut retained_terminals = 0usize;
    let mut seen = HashSet::new();
    let mut hard_budget = bounds.max_bytes;
    // Unsettled operations own their resume record; reserve their space before
    // selecting terminal history, including the preferred minimum count.
    for index in (0..lines.len()).rev() {
        if seen.insert(lines[index].operation_id.as_str())
            && matches!(lines[index].status, JournalStatus::Pending)
        {
            mask[index] = true;
            hard_budget = hard_budget.saturating_sub(ranges[index].len() as u64);
        }
    }
    seen.clear();
    for index in (0..lines.len()).rev() {
        let newest = seen.insert(lines[index].operation_id.as_str());
        if matches!(lines[index].status, JournalStatus::Pending) {
            mask[index] = newest;
            continue;
        }
        let size = ranges[index].len() as u64;
        if hard_budget >= size
            && (retained_terminals < bounds.min_terminal_retained || budget >= size)
        {
            mask[index] = true;
            retained_terminals += 1;
            budget = budget.saturating_sub(size);
            hard_budget -= size;
        }
    }
    let mut retained_bytes = 0;
    let mut decisions = mask.into_iter().zip(ranges);
    lines.retain(|_| {
        let (keep, range) = decisions.next().expect("one range per encoded line");
        if keep {
            let len = range.len();
            bytes.copy_within(range, retained_bytes);
            retained_bytes += len;
        }
        keep
    });
    bytes.truncate(retained_bytes);
    Ok(bytes)
}

/// Deployment ids become path components here, so they are re-validated at
/// the boundary that consumes them: registry-legal identifiers pass, anything
/// with separators or traversal segments fails closed.
///
/// This is the single rule source for deployment-scope directory names; the
/// DeploymentState store (F01) reuses it so a state document and its journal
/// always share one scope directory.
pub(crate) fn deployment_scope(deployment_id: &str) -> anyhow::Result<&str> {
    let legal = !deployment_id.is_empty()
        && deployment_id.len() <= 128
        && deployment_id != "."
        && deployment_id != ".."
        && deployment_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character));
    if legal {
        Ok(deployment_id)
    } else {
        bail!("{TARGET_JOURNAL_INVALID}: deployment_id is not usable as a journal scope")
    }
}

fn scope_slug(deployment_id: Option<&str>) -> anyhow::Result<&str> {
    match deployment_id {
        None => Ok(HOST_SCOPE),
        Some(id) => deployment_scope(id),
    }
}

/// Journal scope for host-level operations that carry no deployment binding.
const HOST_SCOPE: &str = "host";

fn read_lines_with(
    path: &Path,
    read_cap: u64,
    repair_tail: bool,
) -> anyhow::Result<Vec<JournalLine>> {
    let mut bytes = match filesystem::read_secure_regular_file(
        path,
        "target operation journal",
        false,
        read_cap,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut tail_changed = false;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        let start = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        match serde_json::from_slice::<JournalLine>(&bytes[start..]) {
            Ok(_) => bytes.push(b'\n'),
            Err(error) if error.is_eof() => bytes.truncate(start),
            Err(error) => bail!("{TARGET_JOURNAL_INVALID}: invalid final journal record ({error})"),
        }
        tail_changed = true;
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        anyhow::anyhow!(
            "{TARGET_JOURNAL_INVALID}: journal is not UTF-8 ({})",
            path.display()
        )
    })?;
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
    if tail_changed && repair_tail {
        // Only the exclusive writer repairs, and only after validating every
        // complete record. Read-only status never mutates the journal.
        filesystem::atomic_write(path, &bytes, 0o600)?;
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
            crate::target::wire::sanitize(&entry.action)
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
    fn pending_capacity_rejects_new_work_but_allows_recovery() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-capacity")?;
        let mut journal = TargetJournal::open(temp.path().join("state"))?;
        let first = ping_operation("first");
        let second = ping_operation("second");
        journal.run_journaled(&first, |op| {
            HostResult::failed(op.operation_id.clone(), "OUTCOME_UNKNOWN", "interrupted")
        })?;
        let path = journal.path_for(HOST_SCOPE);
        let before = fs::read(&path)?;
        journal.bounds.max_pending_bytes = before.len() as u64;
        let rejected =
            journal.run_journaled(&second, |_| panic!("capacity must precede execution"))?;
        assert!(
            matches!(rejected.outcome, super::super::wire::HostOutcome::Failed { code, .. }
            if code == TARGET_JOURNAL_CAPACITY)
        );
        assert_eq!(fs::read(&path)?, before);
        assert_eq!(
            journal.run_journaled(&first, echo_result)?,
            echo_result(&first)
        );
        assert_eq!(
            journal.run_journaled(&second, echo_result)?,
            echo_result(&second)
        );
        Ok(())
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
    fn failed_backup_recovery_reexecutes_with_the_same_operation_id() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-recovery-retry")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = HostOperation::backup_recover(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            2,
            "a".repeat(64),
            Uuid::now_v7().to_string(),
        );
        let first = journal.run_journaled(&operation, |operation| {
            HostResult::failed(&operation.operation_id, "RESTORE_TEST_FAILED", "first")
        })?;
        assert!(matches!(first.outcome, HostOutcome::Failed { .. }));

        let reexecuted = std::cell::Cell::new(false);
        let second = journal.run_journaled(&operation, |operation| {
            reexecuted.set(true);
            HostResult::failed(&operation.operation_id, "RETRY_EXECUTED", "second")
        })?;
        assert!(reexecuted.get());
        assert!(matches!(
            second.outcome,
            HostOutcome::Failed { ref code, .. } if code == "RETRY_EXECUTED"
        ));
        Ok(())
    }

    #[test]
    fn privilege_preflight_and_partial_uninstall_allow_exact_retry() -> anyhow::Result<()> {
        for (operation, code) in [
            (
                ping_operation("privilege"),
                crate::error_codes::PRIVILEGE_REQUIRED,
            ),
            (
                HostOperation::state_mutate(
                    Uuid::now_v7().to_string(),
                    "deploy-alpha",
                    Some(2),
                    super::super::deployment_state::StateMutationPayload::Uninstall {},
                ),
                "DELETION_FAILED",
            ),
        ] {
            let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-host-retry")?;
            let journal = TargetJournal::open(temp.path().join("state"))?;
            journal.run_journaled(&operation, |operation| {
                HostResult::failed(&operation.operation_id, code, "first")
            })?;
            let reexecuted = std::cell::Cell::new(false);
            journal.run_journaled(&operation, |operation| {
                reexecuted.set(true);
                HostResult::completed(
                    operation.operation_id.clone(),
                    HostCompletionBody::StateMutateNoop { revision: 2 },
                )
            })?;
            assert!(reexecuted.get(), "{code}");
        }
        Ok(())
    }

    #[test]
    fn failed_recovery_candidate_stage_reexecutes_with_the_same_operation_id() -> anyhow::Result<()>
    {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-candidate-retry")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let operation = HostOperation::backup_recovery_candidate_stage(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            3,
            Uuid::now_v7().to_string(),
            Uuid::now_v7().to_string(),
            crate::target::install_exec::OfficialArtifactRef {
                repository: "nazozero/NazoAuth".to_owned(),
                version: Some("v1".to_owned()),
            },
        );
        journal.run_journaled(&operation, |operation| {
            HostResult::failed(&operation.operation_id, "RESTORE_TEST_FAILED", "first")
        })?;

        let reexecuted = std::cell::Cell::new(false);
        let second = journal.run_journaled(&operation, |operation| {
            reexecuted.set(true);
            HostResult::failed(&operation.operation_id, "RETRY_EXECUTED", "second")
        })?;
        assert!(reexecuted.get());
        assert!(matches!(
            second.outcome,
            HostOutcome::Failed { ref code, .. } if code == "RETRY_EXECUTED"
        ));
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
        assert!(
            error.to_string().contains(TARGET_JOURNAL_INVALID),
            "{error}"
        );
        // An incomplete final JSON record is a recoverable interrupted append.
        filesystem::atomic_write(&path, b"{\"schema\":", 0o600)?;
        let operation = ping_operation("recovered-tail");
        let result = journal.run_journaled(&operation, echo_result)?;
        assert_eq!(result, echo_result(&operation));
        let replay = journal.run_journaled(&operation, |_| panic!("must replay receipt"))?;
        assert_eq!(replay, result);

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
            max_pending_bytes: 1_400,
            target_bytes: 500,
            min_terminal_retained: 2,
            read_cap: 64 * 1024,
        }
    }

    fn assert_compaction(lines: &[JournalLine], bounds: &JournalBounds, expected: &[usize]) {
        let mut retained = lines.to_vec();
        let bytes = compact_lines(&mut retained, bounds).unwrap();
        let expected: Vec<_> = expected.iter().map(|index| lines[*index].clone()).collect();
        assert_eq!(retained, expected);
        let decoded: Vec<JournalLine> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            decoded, expected,
            "persisted bytes must match the returned retained lines"
        );
        assert!(bytes.is_empty() || bytes.ends_with(b"\n"));
    }

    #[test]
    fn compaction_byte_budget_includes_line_delimiters() {
        let line = synthetic_line(Uuid::now_v7().to_string(), JournalStatus::Completed);
        let size = serde_json::to_vec(&line).unwrap().len() as u64 + 1;
        let lines = vec![line.clone(), line];
        let mut bounds = tiny_bounds();
        bounds.min_terminal_retained = 0;
        bounds.target_bytes = size * 2 - 1;
        assert_compaction(&lines, &bounds, &[1]);
        bounds.target_bytes += 1;
        assert_compaction(&lines, &bounds, &[0, 1]);
    }

    #[test]
    fn compaction_keeps_only_unsettled_pendings_and_the_newest_terminal_window() {
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
            max_pending_bytes: 10_000,
            target_bytes: 0,
            min_terminal_retained: 2,
            read_cap: 64 * 1024,
        };
        assert_compaction(&lines, &bounds, &[1, 3, 4]);

        // A generous budget keeps everything terminal as well.
        let generous = JournalBounds {
            max_bytes: 10_000,
            max_pending_bytes: 10_000,
            target_bytes: u64::MAX,
            min_terminal_retained: 0,
            read_cap: 64 * 1024,
        };
        assert_compaction(&lines, &generous, &[0, 1, 2, 3, 4]);

        let settled_id = Uuid::now_v7().to_string();
        let unresolved_id = Uuid::now_v7().to_string();
        let lines = vec![
            synthetic_line(settled_id.clone(), JournalStatus::Pending),
            synthetic_line(settled_id, JournalStatus::Completed),
            synthetic_line(unresolved_id.clone(), JournalStatus::Pending),
            synthetic_line(unresolved_id, JournalStatus::Pending),
        ];
        assert_compaction(&lines, &generous, &[1, 3]);
    }

    #[test]
    fn terminal_count_floor_never_overrides_the_byte_cap() {
        let lines = (0..128)
            .map(|_| synthetic_line(Uuid::now_v7().to_string(), JournalStatus::Completed))
            .collect::<Vec<_>>();
        let mut retained = lines.clone();
        let bounds = JournalBounds {
            max_bytes: 2000,
            max_pending_bytes: 2000,
            target_bytes: 500,
            min_terminal_retained: 128,
            read_cap: 4000,
        };
        let bytes = compact_lines(&mut retained, &bounds).unwrap();
        assert!(bytes.len() as u64 <= bounds.max_bytes);
        assert!(retained.len() < 128);
        assert_eq!(retained.last(), lines.last());
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
