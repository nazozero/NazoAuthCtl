//! Control-operation journal on the control side (goal plan 05 §4/§5, task
//! E06 ctl half).
//!
//! One small journal file per instance records the identity of the most
//! recent top-level ControlOperation this ctl prepared:
//!
//! ```text
//! { "schema": 1, "operation_id": …, "request_hash": …, "kid": …,
//!   "created_at": …, "state": "dispatched" | "accepted" }
//! ```
//!
//! Placement decision: the journal lives inside the per-instance Controller
//! Key directory (`controller-keys/<deployment_id>/operation-journal.json`)
//! rather than beside the Registry record. The key directory already provides
//! exactly the properties a dispatch journal needs — private directory
//! permissions, an fs2 instance lock, secure-read validation, and one
//! directory per immutable deployment id — while the Registry is inventory
//! only and must never become a second authority for operation state. The
//! server-side operation journal (E03) remains the sole authority for
//! acceptance; this file only lets ctl reuse `operation_id + request_hash`
//! instead of minting a new identity.
//!
//! Operational-log convergence (H04): this journal and the target-side
//! `operations.jsonl` tell ONE plain-record story. Neither carries signing
//! keys or signature verification — same-host signing identities prove
//! nothing (P4), so tamper evidence comes from file hygiene plus external
//! WORM/SIEM shipping where a deployment needs strong audit. Retention here
//! is the tightest bound ctl owns: exactly one slot per instance, capped at
//! one entry, cleared only by a definitive unaccepted rejection.
//!
//! Invariants implemented here:
//!
//! * Write-ahead: the entry is durable before the signed operation leaves ctl,
//!   so a crash between signing and dispatch still resumes with the same id.
//! * Same content ⇒ same id: resume rebuilds the envelope with the stored
//!   operation id and re-signs; Ed25519 determinism yields byte-identical JWS,
//!   so the server sees one operation, never duplicate side effects.
//! * A definitively rejected (unaccepted) operation clears its entry; the next
//!   attempt after fixing the cause mints a fresh operation_id.
//! * Any drift in the journal file fails closed instead of being repaired.

use std::fs;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use crate::error_codes::STATE_RESET_REQUIRED;
use crate::filesystem;

/// Exclusive per-instance lock shared with the Controller Key store, so
/// journal writes serialize against key-store mutations of the same
/// deployment. Locking is fail-fast (`try_lock`): contention surfaces as an
/// error instead of corrupting state.
struct InstanceJournalLock {
    file: fs::File,
}

impl InstanceJournalLock {
    fn acquire(instance_dir: &std::path::Path) -> anyhow::Result<Self> {
        let path = instance_dir.join("keys.lock");
        let file = filesystem::open_lock_file(&path, false, "control operation journal lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for InstanceJournalLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Schema discriminator for the operation journal file.
pub const OPERATION_JOURNAL_SCHEMA: u32 = 1;

/// Upper bound for the journal file (~1 KiB); real entries are ~300 bytes.
const MAX_JOURNAL_BYTES: u64 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalState {
    /// Durable before dispatch; outcome unknown to ctl.
    Dispatched,
    /// The target confirmed acceptance (E03 accept-once reached).
    Accepted,
}

/// One persisted dispatch record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationJournalEntry {
    pub schema: u32,
    pub operation_id: String,
    pub request_hash: String,
    pub kid: String,
    pub created_at: DateTime<Utc>,
    pub state: JournalState,
}

impl OperationJournalEntry {
    pub fn new(operation_id: String, request_hash: String, kid: String) -> Self {
        Self {
            schema: OPERATION_JOURNAL_SCHEMA,
            operation_id,
            request_hash,
            kid,
            created_at: Utc::now(),
            state: JournalState::Dispatched,
        }
    }
}

/// Handle to one instance's operation journal.
#[derive(Clone, Debug)]
pub struct OperationJournal {
    path: std::path::PathBuf,
}

impl OperationJournal {
    fn validate_entry(entry: &OperationJournalEntry, path: &std::path::Path) -> anyhow::Result<()> {
        if entry.schema != OPERATION_JOURNAL_SCHEMA {
            bail!(
                "{STATE_RESET_REQUIRED}: unsupported operation journal schema {} ({})",
                entry.schema,
                path.display()
            );
        }
        let hex = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let operation_id = uuid::Uuid::parse_str(&entry.operation_id).ok();
        if operation_id.is_none_or(|value| value.get_version_num() != 7)
            || !hex(&entry.request_hash)
            || super::store::validate_kid_shape(&entry.kid).is_err()
        {
            bail!(
                "{STATE_RESET_REQUIRED}: operation journal entry does not conform ({})",
                path.display()
            );
        }
        Ok(())
    }

    /// Build the journal handle from the key store layout. The file is created
    /// lazily by write operations; reads treat absence as "no pending
    /// operation".
    pub fn open(instance_dir: std::path::PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            path: instance_dir.join("operation-journal.json"),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Load the current entry, or `None` when no operation was ever prepared.
    pub fn load(&self) -> anyhow::Result<Option<OperationJournalEntry>> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", self.path.display()));
            }
        }
        let bytes = filesystem::read_secure_regular_file(
            &self.path,
            "control operation journal",
            true,
            MAX_JOURNAL_BYTES,
        )
        .map_err(|error| {
            error.context(format!(
                "{STATE_RESET_REQUIRED}: operation journal is unreadable, unsafe, or exceeds \
                 the size limit ({})",
                self.path.display()
            ))
        })?;
        let entry: OperationJournalEntry = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "{STATE_RESET_REQUIRED}: operation journal does not parse as the current \
                     schema ({})",
                self.path.display()
            ))
        })?;
        Self::validate_entry(&entry, &self.path)?;
        Ok(Some(entry))
    }

    /// Durably persist the write-ahead entry before dispatch.
    ///
    /// P1-2: the journal slot is single-occupancy. An existing entry in any
    /// state must never be silently replaced — the caller reconciles through
    /// [`Self::load`] first, and a conflicting operation id means a different
    /// logical attempt is trying to steal the slot.
    pub fn record_dispatched(&self, entry: &OperationJournalEntry) -> anyhow::Result<()> {
        Self::validate_entry(entry, &self.path)?;
        if entry.state != JournalState::Dispatched {
            bail!("a fresh journal entry must start in the dispatched state");
        }
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        if let Some(existing) = self.load()? {
            if existing.operation_id == entry.operation_id {
                // Byte-identical rebuild of the SAME attempt: safe to persist
                // again (idempotent retry of the write itself).
                if existing.state != JournalState::Dispatched {
                    bail!(
                        "operation '{}' is already journaled as {:?}; refusing to rewind it to \
                         dispatched",
                        existing.operation_id,
                        existing.state
                    );
                }
            } else {
                let existing_state = format!("{:?}", existing.state);
                bail!(
                    "the operation journal already holds operation '{}' ({existing_state}); a \
                     different operation '{}' may not overwrite it — settle or clear the \
                     existing entry explicitly",
                    existing.operation_id,
                    entry.operation_id
                );
            }
        }
        let bytes = serde_json::to_vec_pretty(entry)
            .context("failed to serialize the operation journal entry")?;
        filesystem::atomic_write(&self.path, &bytes, 0o600)
            .with_context(|| format!("failed to persist {}", self.path.display()))
    }

    /// Transition the entry to accepted after the target acknowledged it.
    pub fn mark_accepted(&self, operation_id: &str) -> anyhow::Result<()> {
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        let Some(mut entry) = self.load()? else {
            bail!("no journaled operation to mark accepted");
        };
        if entry.operation_id != operation_id {
            bail!(
                "journaled operation {} cannot be marked accepted for foreign id {operation_id}",
                entry.operation_id
            );
        }
        entry.state = JournalState::Accepted;
        let bytes = serde_json::to_vec_pretty(&entry)
            .context("failed to serialize the operation journal entry")?;
        filesystem::atomic_write(&self.path, &bytes, 0o600)
            .with_context(|| format!("failed to persist {}", self.path.display()))
    }

    /// Remove the entry after a definitive unaccepted rejection so the next
    /// attempt mints a fresh operation id. Absence is already fine.
    pub fn clear(&self) -> anyhow::Result<()> {
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", self.path.display()));
            }
        }
        filesystem::remove_file_durable(&self.path)
            .with_context(|| format!("failed to clear {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_identity::store::{ControllerKeyStore, controller_key_ref_for};
    use crate::filesystem;

    struct Fixture {
        _temp: filesystem::PrivateTempDir,
        keys: ControllerKeyStore,
        deployment: &'static str,
    }

    fn fixture() -> anyhow::Result<Fixture> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-opjournal-test")?;
        let keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        Ok(Fixture {
            _temp: temp,
            keys,
            deployment: "deploy-alpha",
        })
    }

    fn journal(fixture: &Fixture) -> anyhow::Result<OperationJournal> {
        OperationJournal::open(fixture.keys.instance_dir(fixture.deployment)?)
    }

    fn sample_entry(operation_id: &str) -> OperationJournalEntry {
        OperationJournalEntry::new(operation_id.to_owned(), "ab".repeat(32), "a".repeat(43))
    }

    #[test]
    fn write_ahead_record_and_accept_transition_round_trip() -> anyhow::Result<()> {
        let f = fixture()?;
        let journal = journal(&f)?;
        assert!(journal.load()?.is_none(), "absence means no pending op");

        let entry = sample_entry("01900000-0000-7000-8000-000000000001");
        journal.record_dispatched(&entry)?;
        let loaded = journal.load()?.expect("persisted");
        assert_eq!(loaded, entry);
        assert_eq!(loaded.state, JournalState::Dispatched);

        journal.mark_accepted(&entry.operation_id)?;
        let loaded = journal.load()?.expect("accepted entry");
        assert_eq!(loaded.state, JournalState::Accepted);

        // Foreign ids are refused.
        assert!(journal.mark_accepted("other-id").is_err());
        Ok(())
    }

    #[test]
    fn clear_removes_the_entry_and_is_idempotent() -> anyhow::Result<()> {
        let f = fixture()?;
        let journal = journal(&f)?;
        journal.clear()?; // absent already

        journal.record_dispatched(&sample_entry("01900000-0000-7000-8000-000000000002"))?;
        journal.clear()?;
        assert!(journal.load()?.is_none());
        journal.clear()?;
        Ok(())
    }

    #[test]
    fn corrupt_or_tampered_journal_fails_closed() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.instance_dir(f.deployment)?; // ensure dir exists
        let dir = f.keys.instance_dir(f.deployment)?;
        let path = dir.join("operation-journal.json");

        filesystem::atomic_write(&path, b"{ not json", 0o600)?;
        let error = OperationJournal::open(dir.clone())?
            .load()
            .expect_err("corrupt");
        assert!(
            format!("{error:#}").contains(STATE_RESET_REQUIRED),
            "{error:#}"
        );

        // Oversize entries must fail closed too.
        filesystem::atomic_write(&path, &[b'x'; (MAX_JOURNAL_BYTES + 1) as usize], 0o600)?;
        let error = OperationJournal::open(dir.clone())?
            .load()
            .expect_err("oversize");
        assert!(format!("{error:#}").contains("size limit"), "{error:#}");

        // A structurally valid but non-conforming hash must fail closed.
        let mut tampered = sample_entry("01900000-0000-7000-8000-000000000003");
        tampered.request_hash = "ZZZZ".to_owned();
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&tampered)?, 0o600)?;
        let error = OperationJournal::open(dir.clone())?
            .load()
            .expect_err("tampered");
        assert!(
            format!("{error:#}").contains(STATE_RESET_REQUIRED),
            "{error:#}"
        );

        let mut old_operation = sample_entry("01900000-0000-4000-8000-000000000003");
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&old_operation)?, 0o600)?;
        let error = OperationJournal::open(dir.clone())?
            .load()
            .expect_err("non-v7 operation id");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));

        old_operation.operation_id = "01900000-0000-7000-8000-000000000003".to_owned();
        old_operation.kid = "not-a-controller-kid".to_owned();
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&old_operation)?, 0o600)?;
        let error = OperationJournal::open(dir)?
            .load()
            .expect_err("malformed controller kid");
        assert!(format!("{error:#}").contains(STATE_RESET_REQUIRED));
        Ok(())
    }

    #[test]
    fn fresh_entries_must_start_dispatched() -> anyhow::Result<()> {
        let f = fixture()?;
        let journal = journal(&f)?;
        let mut entry = sample_entry("01900000-0000-7000-8000-000000000004");
        entry.state = JournalState::Accepted;
        assert!(journal.record_dispatched(&entry).is_err());
        Ok(())
    }

    #[test]
    fn journal_file_never_lives_outside_the_key_directory() -> anyhow::Result<()> {
        let f = fixture()?;
        let reference = controller_key_ref_for(f.deployment)?;
        assert_eq!(reference, format!("controller-keys/{}", f.deployment));
        let journal = journal(&f)?;
        assert!(
            journal
                .path()
                .starts_with(f.keys.instance_dir(f.deployment)?)
        );
        Ok(())
    }
}
