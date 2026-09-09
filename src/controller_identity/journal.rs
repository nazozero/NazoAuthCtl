//! Control-operation journal on the control side (goal plan 05 §4/§5, task
//! E06 ctl half).
//!
//! One small journal file per instance records the identity of the most
//! recent top-level ControlOperation this ctl prepared:
//!
//! ```text
//! { "schema": 2, "operation_id": …, "request_hash": …, "kid": …,
//!   "compact_jws": …,
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
//! acceptance; this file retains the exact accepted-or-pending signed request
//! so recovery does not depend on the current active key or configuration.
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
//! * Same content ⇒ same id: resume proves the current command maps to the
//!   stored request hash, then resends the original compact JWS. A key rotation
//!   or retirement cannot turn an already accepted operation into a new one.
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
pub const OPERATION_JOURNAL_SCHEMA: u32 = 2;

/// Schema written before the immutable compact JWS was retained. It is read
/// only so a still-valid original key can perform one exact, deterministic
/// migration; it is never written again.
const LEGACY_OPERATION_JOURNAL_SCHEMA: u32 = 1;

/// The compact JWS is bounded by the shared protocol. The remaining envelope
/// fields are deliberately capped tightly enough to reject accidental files
/// that are not one journal entry.
const MAX_JOURNAL_BYTES: u64 = nazo_operator_protocol::MAX_COMPACT_JWS_BYTES as u64 + 2048;

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
    /// The exact original request. This is public protocol data, never
    /// change-set material; it lets accepted-operation recovery survive key
    /// rotation and local retirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_jws: Option<String>,
    pub created_at: DateTime<Utc>,
    pub state: JournalState,
}

impl OperationJournalEntry {
    pub fn new(
        operation_id: String,
        request_hash: String,
        kid: String,
        compact_jws: String,
    ) -> Self {
        Self {
            schema: OPERATION_JOURNAL_SCHEMA,
            operation_id,
            request_hash,
            kid,
            compact_jws: Some(compact_jws),
            created_at: Utc::now(),
            state: JournalState::Dispatched,
        }
    }

    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
            && self.request_hash == other.request_hash
            && self.kid == other.kid
            && self.compact_jws == other.compact_jws
    }

    pub fn is_legacy(&self) -> bool {
        self.schema == LEGACY_OPERATION_JOURNAL_SCHEMA
    }
}

/// Handle to one instance's operation journal.
#[derive(Clone, Debug)]
pub struct OperationJournal {
    path: std::path::PathBuf,
}

impl OperationJournal {
    fn validate_entry(entry: &OperationJournalEntry, path: &std::path::Path) -> anyhow::Result<()> {
        if !matches!(
            entry.schema,
            LEGACY_OPERATION_JOURNAL_SCHEMA | OPERATION_JOURNAL_SCHEMA
        ) {
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
        match entry.schema {
            LEGACY_OPERATION_JOURNAL_SCHEMA if entry.compact_jws.is_none() => {}
            LEGACY_OPERATION_JOURNAL_SCHEMA => bail!(
                "{STATE_RESET_REQUIRED}: legacy operation journal entry carries unsupported recovery fields ({})",
                path.display()
            ),
            OPERATION_JOURNAL_SCHEMA => {
                let compact_jws = entry.compact_jws.as_deref().with_context(|| {
                    format!(
                        "{STATE_RESET_REQUIRED}: operation journal lacks its original compact JWS ({})",
                        path.display()
                    )
                })?;
                let header = nazo_operator_protocol::protected_header(compact_jws).map_err(|error| {
                    anyhow::anyhow!(
                        "{STATE_RESET_REQUIRED}: operation journal compact JWS is malformed ({error}) ({})",
                        path.display()
                    )
                })?;
                if header.kid != entry.kid
                    || header.typ != nazo_operator_protocol::CONTROL_OPERATION_JWS_TYPE
                {
                    bail!(
                        "{STATE_RESET_REQUIRED}: operation journal recovery fields do not conform ({})",
                        path.display()
                    );
                }
            }
            _ => unreachable!("validated schema set is closed"),
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
                if !existing.has_same_identity(entry) {
                    bail!(
                        "operation '{}' is already journaled with different content or signing identity",
                        existing.operation_id
                    );
                }
                if existing.state != JournalState::Dispatched {
                    bail!(
                        "operation '{}' is already journaled as {:?}; refusing to rewind it to \
                         dispatched",
                        existing.operation_id,
                        existing.state
                    );
                }
                // The same attempt is already durable. Preserve its original
                // timestamp and avoid another filesystem replacement.
                return Ok(());
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

    /// Convert the only legacy representation to the current recovery
    /// envelope. The caller must have rebuilt the same canonical request with
    /// the still-valid original key; this method merely makes that exact JWS
    /// durable while preserving the observed journal state.
    pub fn upgrade_legacy_if_matches(
        &self,
        expected: &OperationJournalEntry,
        upgraded: &OperationJournalEntry,
    ) -> anyhow::Result<()> {
        if !expected.is_legacy() || upgraded.schema != OPERATION_JOURNAL_SCHEMA {
            bail!("operation journal migration requires legacy-to-current entries");
        }
        Self::validate_entry(upgraded, &self.path)?;
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        let Some(current) = self.load()? else {
            bail!("the legacy journaled operation is no longer present");
        };
        if !current.is_legacy()
            || current.operation_id != expected.operation_id
            || current.request_hash != expected.request_hash
            || current.kid != expected.kid
        {
            bail!(
                "the operation journal changed while legacy operation '{}' was being migrated",
                expected.operation_id
            );
        }
        let mut upgraded = upgraded.clone();
        upgraded.created_at = current.created_at;
        upgraded.state = current.state;
        let bytes = serde_json::to_vec_pretty(&upgraded)
            .context("failed to serialize the upgraded operation journal entry")?;
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

    /// Transition only the exact operation observed by the caller. State and
    /// timestamp are intentionally excluded: a concurrent retry may already
    /// have moved the same operation from dispatched to accepted.
    pub fn mark_accepted_if_matches(&self, expected: &OperationJournalEntry) -> anyhow::Result<()> {
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        let Some(mut entry) = self.load()? else {
            bail!("the expected journaled operation is no longer present");
        };
        if !entry.has_same_identity(expected) {
            bail!(
                "the operation journal changed while operation '{}' was settling",
                expected.operation_id
            );
        }
        entry.state = JournalState::Accepted;
        let bytes = serde_json::to_vec_pretty(&entry)
            .context("failed to serialize the operation journal entry")?;
        filesystem::atomic_write(&self.path, &bytes, 0o600)
            .with_context(|| format!("failed to persist {}", self.path.display()))
    }

    /// Remove only the exact operation observed by the caller. This prevents
    /// a late completion from deleting a newer single-slot journal entry.
    pub fn clear_if_matches(&self, expected: &OperationJournalEntry) -> anyhow::Result<()> {
        let _lock = InstanceJournalLock::acquire(
            self.path
                .parent()
                .context("journal path has no parent directory")?,
        )?;
        let Some(entry) = self.load()? else {
            bail!("the expected journaled operation is no longer present");
        };
        if !entry.has_same_identity(expected) {
            bail!(
                "the operation journal changed while operation '{}' was settling",
                expected.operation_id
            );
        }
        filesystem::remove_file_durable(&self.path)
            .with_context(|| format!("failed to clear {}", self.path.display()))
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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
        let kid = "a".repeat(43);
        let header = serde_json::json!({
            "alg": "EdDSA",
            "kid": kid,
            "typ": nazo_operator_protocol::CONTROL_OPERATION_JWS_TYPE,
        });
        let compact_jws = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("test header serializes")),
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode([0u8; 64]),
        );
        OperationJournalEntry::new(operation_id.to_owned(), "ab".repeat(32), kid, compact_jws)
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
    fn compare_and_clear_never_removes_a_newer_operation() -> anyhow::Result<()> {
        let f = fixture()?;
        let journal = journal(&f)?;
        let first = sample_entry("01900000-0000-7000-8000-000000000010");
        let second = sample_entry("01900000-0000-7000-8000-000000000011");
        journal.record_dispatched(&first)?;
        journal.clear()?;
        journal.record_dispatched(&second)?;

        assert!(journal.clear_if_matches(&first).is_err());
        assert!(journal.mark_accepted_if_matches(&first).is_err());
        assert_eq!(journal.load()?.context("newer entry")?, second);
        journal.clear_if_matches(&second)?;
        assert!(journal.load()?.is_none());
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
    fn dispatched_retry_preserves_original_record_and_rejects_identity_drift() -> anyhow::Result<()>
    {
        let f = fixture()?;
        let journal = journal(&f)?;
        let original = sample_entry("01900000-0000-7000-8000-000000000020");
        journal.record_dispatched(&original)?;
        let original_bytes = fs::read(journal.path())?;
        let original_modified = fs::metadata(journal.path())?.modified()?;

        let mut retry = original.clone();
        retry.created_at += chrono::Duration::seconds(1);
        journal.record_dispatched(&retry)?;
        assert_eq!(fs::read(journal.path())?, original_bytes);
        assert_eq!(fs::metadata(journal.path())?.modified()?, original_modified);

        retry.request_hash = "cd".repeat(32);
        assert!(journal.record_dispatched(&retry).is_err());
        retry = original.clone();
        retry.kid = "b".repeat(43);
        assert!(journal.record_dispatched(&retry).is_err());
        retry = original.clone();
        retry.operation_id = "01900000-0000-7000-8000-000000000021".to_owned();
        assert!(journal.record_dispatched(&retry).is_err());
        assert_eq!(fs::read(journal.path())?, original_bytes);
        assert_eq!(fs::metadata(journal.path())?.modified()?, original_modified);

        journal.mark_accepted(&original.operation_id)?;
        let accepted_bytes = fs::read(journal.path())?;
        assert!(journal.record_dispatched(&original).is_err());
        assert_eq!(fs::read(journal.path())?, accepted_bytes);
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
