use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};

use super::{Link, valid_path_segment};
use crate::{Origin, SuiteRecoveryState, secure_file};

const JOURNAL_FILE: &str = "rp-recovery.json";
const LOCK_FILE: &str = "rp-recovery.lock";
const MAX_JOURNAL_BYTES: usize = 128 * 1024;
const MAX_PENDING_RUNS: usize = 64;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Completion {
    Active,
    Deleted,
    Retained,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    suite: SuiteRecoveryState,
    target_origin: String,
    account_id: String,
    baseline_links: Vec<Link>,
    provider_ids: Vec<String>,
    completion: Completion,
}

/// Owns only Suite allocations and the fixture account's link baseline.
/// The production tenant and credentials never enter this journal.
pub(super) struct Recovery {
    directory: PathBuf,
    journal: Journal,
    // Keep the stable inode locked until this run or recovery attempt ends.
    _lock: File,
}

impl Recovery {
    pub(super) fn create(
        evidence_dir: &Path,
        suite_origin: &Origin,
        target_origin: &Origin,
        account_id: String,
        baseline_links: Vec<Link>,
        provider_ids: Vec<String>,
    ) -> anyhow::Result<Self> {
        let directory = secure_file::ensure_directory(evidence_dir, true)
            .map_err(|error| anyhow::anyhow!("invalid RP evidence directory: {error:?}"))?;
        let lock = lock_run(&directory)?;
        match secure_file::read_bounded(&directory.join(JOURNAL_FILE), 1, true) {
            Err(secure_file::SecureFileError::NotFound) => {}
            Ok(_) | Err(secure_file::SecureFileError::Oversize) => {
                bail!("RP recovery journal already exists")
            }
            Err(error) => bail!("failed to inspect RP recovery journal: {error:?}"),
        }
        let recovery = Self {
            directory,
            journal: Journal {
                schema: 1,
                suite: SuiteRecoveryState {
                    origin: suite_origin.to_string(),
                    plan_ids: Vec::new(),
                    module_ids: Vec::new(),
                    pending_create_intents: Vec::new(),
                    cleanup_complete: false,
                },
                target_origin: target_origin.to_string(),
                account_id,
                baseline_links,
                provider_ids,
                completion: Completion::Active,
            },
            _lock: lock,
        };
        recovery.persist()?;
        Ok(recovery)
    }

    /// Claim pending RP runs under the deployment's existing evidence root.
    /// OP evidence directories have no RP journal and are left untouched.
    pub(super) fn pending(evidence_root: &Path) -> anyhow::Result<Vec<Self>> {
        let root = match secure_file::validate_directory(evidence_root, true) {
            Ok(root) => root,
            Err(secure_file::SecureFileError::NotFound) => return Ok(Vec::new()),
            Err(error) => bail!("invalid RP evidence root: {error:?}"),
        };
        let mut pending = Vec::new();
        for entry in fs::read_dir(&root).context("failed to list RP evidence")? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let directory = entry.path();
            let path = directory.join(JOURNAL_FILE);
            match fs::symlink_metadata(&path) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("failed to inspect RP journal"),
            }
            let lock = lock_run(&directory)?;
            let bytes = secure_file::read_bounded(&path, MAX_JOURNAL_BYTES, true)
                .map_err(|error| anyhow::anyhow!("failed to read RP journal: {error:?}"))?;
            let journal: Journal =
                serde_json::from_slice(&bytes).context("invalid RP recovery journal")?;
            validate_journal(&journal)?;
            if journal.completion != Completion::Active {
                continue;
            }
            if pending.len() == MAX_PENDING_RUNS {
                bail!("RP pending recovery count exceeds policy");
            }
            pending.push(Self {
                directory,
                journal,
                _lock: lock,
            });
        }
        pending.sort_by(|left, right| left.directory.cmp(&right.directory));
        Ok(pending)
    }

    pub(super) fn before_create(&mut self, intent: &str) -> anyhow::Result<()> {
        self.require_active()?;
        if !valid_path_segment(intent)
            || self
                .journal
                .suite
                .pending_create_intents
                .iter()
                .any(|pending| pending == intent)
        {
            bail!("RP Suite create intent is invalid or already pending");
        }
        self.journal
            .suite
            .pending_create_intents
            .push(intent.to_owned());
        self.persist()
    }

    pub(super) fn plan_created(&mut self, intent: &str, plan_id: &str) -> anyhow::Result<()> {
        self.resolve_intent(intent, plan_id)?;
        if !self.journal.suite.plan_ids.iter().any(|id| id == plan_id) {
            self.journal.suite.plan_ids.push(plan_id.to_owned());
        }
        self.persist()
    }

    pub(super) fn module_created(&mut self, intent: &str, module_id: &str) -> anyhow::Result<()> {
        self.resolve_intent(intent, module_id)?;
        if !self
            .journal
            .suite
            .module_ids
            .iter()
            .any(|id| id == module_id)
        {
            self.journal.suite.module_ids.push(module_id.to_owned());
        }
        self.persist()
    }

    fn resolve_intent(&mut self, intent: &str, resource_id: &str) -> anyhow::Result<()> {
        self.require_active()?;
        if !valid_path_segment(resource_id) {
            bail!("RP Suite resource ID is invalid");
        }
        let pending = &mut self.journal.suite.pending_create_intents;
        let index = pending
            .iter()
            .position(|id| id == intent)
            .context("RP Suite create intent is not pending")?;
        pending.remove(index);
        Ok(())
    }

    pub(super) fn state(&self) -> &SuiteRecoveryState {
        &self.journal.suite
    }

    pub(super) fn target_origin(&self) -> &str {
        &self.journal.target_origin
    }

    pub(super) fn account_id(&self) -> &str {
        &self.journal.account_id
    }

    pub(super) fn baseline_links(&self) -> &[Link] {
        &self.journal.baseline_links
    }

    pub(super) fn provider_ids(&self) -> &[String] {
        &self.journal.provider_ids
    }

    pub(super) fn evidence_dir(&self) -> &Path {
        &self.directory
    }

    /// Call only after production-link cleanup and Suite deletion or explicit
    /// retention have completed. Keep exact resource IDs as ownership evidence.
    pub(super) fn settle(&mut self, retained: bool) -> anyhow::Result<()> {
        self.require_active()?;
        if !self.journal.suite.pending_create_intents.is_empty() {
            bail!("RP recovery has an unresolved Suite create allocation");
        }
        self.journal.suite.cleanup_complete = !retained;
        self.journal.completion = if retained {
            Completion::Retained
        } else {
            Completion::Deleted
        };
        self.persist()
    }

    fn require_active(&self) -> anyhow::Result<()> {
        if self.journal.completion != Completion::Active {
            bail!("RP recovery is already settled");
        }
        Ok(())
    }

    fn persist(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.journal)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("RP recovery journal exceeds policy");
        }
        secure_file::write_atomic(&self.directory.join(JOURNAL_FILE), &bytes, true)
            .map_err(|error| anyhow::anyhow!("failed to persist RP recovery journal: {error:?}"))
    }
}

fn lock_run(directory: &Path) -> anyhow::Result<File> {
    let lock = secure_file::open_lock_file(&directory.join(LOCK_FILE), true)
        .map_err(|error| anyhow::anyhow!("failed to open RP recovery lock: {error:?}"))?;
    lock.try_lock_exclusive()
        .context("another controller owns this RP recovery transaction")?;
    Ok(lock)
}

fn validate_journal(journal: &Journal) -> anyhow::Result<()> {
    let suite = &journal.suite;
    if journal.schema != 1
        || Origin::parse_suite(&suite.origin)?.as_str() != suite.origin
        || Origin::parse(&journal.target_origin)?.as_str() != journal.target_origin
        || !valid_path_segment(&journal.account_id)
        || journal
            .provider_ids
            .iter()
            .any(|id| !valid_path_segment(id))
        || journal
            .baseline_links
            .iter()
            .any(|link| !valid_path_segment(&link.id) || !valid_path_segment(&link.provider_id))
        || suite
            .plan_ids
            .iter()
            .chain(&suite.module_ids)
            .chain(&suite.pending_create_intents)
            .any(|id| !valid_path_segment(id))
        || (suite.cleanup_complete != (journal.completion == Completion::Deleted))
        || (journal.completion != Completion::Active && !suite.pending_create_intents.is_empty())
    {
        bail!("RP recovery journal has invalid identity or completion state");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nazoauthctl_runtime::filesystem::PrivateTempDir;

    struct Fixture(PrivateTempDir);

    impl Fixture {
        fn new() -> Self {
            Self(PrivateTempDir::new("rp-recovery").unwrap())
        }

        fn create(&self) -> Recovery {
            Recovery::create(
                &self.0.path().join("run-1"),
                &Origin::parse_suite("https://suite.example").unwrap(),
                &Origin::parse("https://login.example").unwrap(),
                "account-1".to_owned(),
                vec![Link {
                    id: "existing-link".to_owned(),
                    provider_id: "existing-provider".to_owned(),
                }],
                vec!["rp-provider".to_owned()],
            )
            .unwrap()
        }
    }

    #[test]
    fn reopening_preserves_suite_ownership_and_the_production_link_baseline() {
        let fixture = Fixture::new();
        let mut recovery = fixture.create();
        recovery.before_create("plan-intent").unwrap();
        recovery.plan_created("plan-intent", "suite-plan").unwrap();
        recovery.before_create("module-intent").unwrap();
        recovery
            .module_created("module-intent", "suite-module")
            .unwrap();
        drop(recovery);

        let pending = Recovery::pending(fixture.0.path()).unwrap();
        assert_eq!(pending.len(), 1);
        let reopened = &pending[0];
        assert_eq!(reopened.state().origin, "https://suite.example");
        assert_eq!(reopened.state().plan_ids, ["suite-plan"]);
        assert_eq!(reopened.state().module_ids, ["suite-module"]);
        assert!(reopened.state().pending_create_intents.is_empty());
        assert_eq!(reopened.target_origin(), "https://login.example");
        assert_eq!(reopened.account_id(), "account-1");
        assert_eq!(reopened.baseline_links()[0].id, "existing-link");
        assert_eq!(reopened.provider_ids(), ["rp-provider"]);
    }

    #[test]
    fn lost_create_response_survives_restart_and_blocks_settlement() {
        let fixture = Fixture::new();
        let mut recovery = fixture.create();
        recovery.before_create("unknown-allocation").unwrap();
        drop(recovery);

        let mut pending = Recovery::pending(fixture.0.path()).unwrap();
        let recovery = &mut pending[0];
        assert_eq!(
            recovery.state().pending_create_intents,
            ["unknown-allocation"]
        );
        assert!(recovery.settle(false).is_err());
        assert!(recovery.settle(true).is_err());
        recovery
            .plan_created("unknown-allocation", "reconciled-plan")
            .unwrap();
        recovery.settle(false).unwrap();
        drop(pending);
        assert!(Recovery::pending(fixture.0.path()).unwrap().is_empty());
    }

    #[test]
    fn retained_and_deleted_runs_keep_ids_but_are_not_reclaimed() {
        for retained in [false, true] {
            let fixture = Fixture::new();
            let mut recovery = fixture.create();
            recovery.before_create("plan-intent").unwrap();
            recovery.plan_created("plan-intent", "suite-plan").unwrap();
            recovery.settle(retained).unwrap();
            assert_eq!(recovery.state().plan_ids, ["suite-plan"]);
            assert_eq!(recovery.state().cleanup_complete, !retained);
            assert!(recovery.before_create("another-intent").is_err());
            drop(recovery);
            assert!(Recovery::pending(fixture.0.path()).unwrap().is_empty());
            assert!(fixture.0.path().join("run-1").join(JOURNAL_FILE).is_file());
        }
    }

    #[test]
    fn a_running_controller_keeps_the_recovery_lease() {
        let fixture = Fixture::new();
        let recovery = fixture.create();
        assert!(Recovery::pending(fixture.0.path()).is_err());
        drop(recovery);
        assert_eq!(Recovery::pending(fixture.0.path()).unwrap().len(), 1);
    }

    #[test]
    fn disk_boundary_rejects_a_resource_id_that_could_change_the_cleanup_path() {
        let fixture = Fixture::new();
        let mut recovery = fixture.create();
        recovery
            .journal
            .suite
            .plan_ids
            .push("../unowned-plan".to_owned());
        recovery.persist().unwrap();
        drop(recovery);
        assert!(Recovery::pending(fixture.0.path()).is_err());
    }
}
