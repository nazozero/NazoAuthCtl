//! Target-side durable operation journal (goal plan 03 §3.2/§5, task C07).
//!
//! Before a target performs the first side effect of an accepted HostOperation,
//! one `{operation_id, canonical hash, status}` line is durably appended to
//! that deployment's journal under the target state root. Reconnects after a
//! dropped SSH session resolve through this journal alone:
//!
//! - same id + same canonical hash ⇒ replay; the stored result is returned
//!   verbatim (idempotent);
//! - same id + different hash ⇒ stable `OPERATION_CONFLICT`; the original
//!   intent is never overwritten;
//! - an interrupted operation stays `pending` and is resumed by re-execution —
//!   which is only safe because every journaled kind must be resumable by its
//!   own checkpoints (the DeploymentState wave, F01).
//!
//! The controller never sees these lines; it keeps summaries only. Journal
//! lines are append-only, schema-checked (`deny_unknown_fields`), bounded in
//! size, and parsed strictly: a torn append or foreign byte fails closed with
//! the stable `TARGET_JOURNAL_INVALID` code instead of being repaired.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::filesystem;

use super::wire::{
    HOST_ERR_OPERATION_CONFLICT, HostOperation, HostResult, canonical_operation_hash,
};

/// Schema discriminator for every journal line.
pub const JOURNAL_SCHEMA: u32 = 1;

/// Stable error prefix for any journal content that does not parse as the
/// current schema or violates its own invariants. Repair is manual and
/// explicit; there is no lenient reader.
pub const TARGET_JOURNAL_INVALID: &str = "TARGET_JOURNAL_INVALID";

/// Upper bound for one deployment's journal file.
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Journal scope for host-level operations that carry no deployment binding.
const HOST_SCOPE: &str = "host";

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
    pub status: JournalStatus,
    /// Present exactly when `status` is terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<HostResult>,
}

/// Handle to the per-target operation journals under one state root.
///
/// The root is provisional until F01 formalizes target DeploymentState
/// storage; every path below the root is decided by [`TargetJournal::path_for`]
/// and nowhere else.
#[derive(Clone, Debug)]
pub struct TargetJournal {
    root: PathBuf,
}

impl TargetJournal {
    /// Open (creating if needed) the journal root directory.
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        filesystem::ensure_private_directory(&root, "target state root")?;
        Ok(Self { root })
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
        let operation_hash = canonical_operation_hash(operation)?;
        let lines = read_lines(&path)?;

        let mut latest: Option<JournalLine> = None;
        for line in lines
            .into_iter()
            .filter(|line| line.operation_id == operation.operation_id)
        {
            if line.operation_hash != operation_hash {
                return Ok(HostResult::failed(
                    operation.operation_id.clone(),
                    HOST_ERR_OPERATION_CONFLICT,
                    format!(
                        "generate a new operation_id instead of retrying; this id was already \
                         accepted with request hash {} instead of {}",
                        line.operation_hash, operation_hash
                    ),
                ));
            }
            latest = Some(line);
        }

        // A terminal stored result is the authoritative idempotent answer.
        // A pending line means an earlier attempt was interrupted after
        // acceptance but before completion: resume by executing again.
        if let Some(line) = latest
            && !matches!(line.status, JournalStatus::Pending)
            && let Some(result) = line.result
        {
            return Ok(result);
        }

        self.append(
            &path,
            &JournalLine {
                schema: JOURNAL_SCHEMA,
                operation_id: operation.operation_id.clone(),
                operation_hash: operation_hash.clone(),
                status: JournalStatus::Pending,
                result: None,
            },
        )?;
        let result = execute(operation);
        self.append(
            &path,
            &JournalLine {
                schema: JOURNAL_SCHEMA,
                operation_id: operation.operation_id.clone(),
                operation_hash: operation_hash.clone(),
                status: match result.outcome {
                    super::wire::HostOutcome::Completed { .. } => JournalStatus::Completed,
                    super::wire::HostOutcome::Failed { .. } => JournalStatus::Failed,
                },
                result: Some(result.clone()),
            },
        )?;
        Ok(result)
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

fn read_lines(path: &Path) -> anyhow::Result<Vec<JournalLine>> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(Vec::new());
    }
    let bytes = filesystem::read_secure_regular_file(
        path,
        "target operation journal",
        false,
        MAX_JOURNAL_BYTES,
    )?;
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
            "{TARGET_JOURNAL_INVALID}: journal line {line_number} carries schema {}",
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
    match entry.status {
        JournalStatus::Pending if entry.result.is_none() => Ok(()),
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
        let hook_operation = operation.clone();
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
        Ok(())
    }

    #[test]
    fn replays_return_the_stored_result_without_reexecution() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-test")?;
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
        let temp = filesystem::PrivateTempDir::new("nazoauthctl-journal-test")?;
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
        assert_eq!(code, HOST_ERR_OPERATION_CONFLICT);
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

        filesystem::atomic_write(&path, b"{\"schema\":1}", 0o600)?; // torn: no newline
        let error = journal
            .run_journaled(&ping_operation("x"), echo_result)
            .expect_err("torn");
        assert!(error.to_string().contains("mid-line"), "{error}");

        // A pending line carrying a result violates the line invariant.
        let poisoned = format!(
            "{{\"schema\":1,\"operation_id\":\"{}\",\"operation_hash\":\"{}\",\"status\":\"pending\",\"result\":{{\"schema\":1,\"operation_id\":\"{}\",\"outcome\":{{\"status\":\"failed\",\"code\":\"X\",\"detail\":\"d\"}}}}}}\n",
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
        assert_eq!(
            raw.lines().count(),
            3,
            "pending + resume pending + terminal"
        );
        Ok(())
    }
}
