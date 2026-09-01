//! Shared local-use-case tests for G03/G04/G06/G07.
//!
//! The use cases are transport-agnostic, so these scenarios exercise the exact
//! code both local and SSH lifecycles run. The target-side executors are
//! injected seams that perform the REAL state-document commits through
//! [`crate::target::TargetStateStore`] (mirroring the production executor
//! tail), so assertions cover genuine CAS/journal semantics instead of mocks
//! asserting on themselves.

use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{ControlOutcome, ControlResult};

use super::privilege::{PrivilegeStep, ensure_engine_access};
use super::uninstall::plan_uninstall;
use super::update::{UpdateRequest, run_update};
use super::{LifecycleContext, rollback::run_rollback, uninstall::run_uninstall};
use crate::controller_identity::journal::OperationJournal;
use crate::controller_identity::store::{ControllerKeyStore, controller_key_ref_for};
use crate::filesystem::PrivateTempDir;
use crate::registry::{DiscoveryEvidence, InstanceRecord, RegistryStore};
use crate::target::{
    ExecutionTarget, Failure, HostOperation, HostOutcome, LocalTarget, StateMutationPayload,
    TargetStateStore, UpdateBackupPrecondition,
    control_exec::{CONTROL_OUTCOME_UNKNOWN, ControlJob, ControlOperationExecutor},
    uninstall_exec::{DeletionExecutor, DeletionJob},
    update_exec::{
        ACTIVATION_FAILED, LifecycleExecutor, LifecycleFacts, RollbackJob, UpdateExecution,
        UpdateJob,
    },
    wire::local_hello,
};

const ISSUER: &str = "https://auth.example.com";
const DEPLOYMENT: &str = "deploy-lifecycle-test";
const CURRENT_REF: &str = "sha256:aaaa00000000000000000000000000000000000000000000000000000000aaaa";
const NEW_REF: &str = "sha256:bbbb00000000000000000000000000000000000000000000000000000000bbbb";

// ------------------------------------------------------------------ fixtures

/// Scripted delivered-ControlOperation operator: records every presented id
/// and answers either a durable succeeded result or an outcome-unknown
/// refusal, driven by the current slot.
struct ScriptedControl {
    presented: Mutex<Vec<String>>,
    answer: Mutex<Option<()>>,  // None => outcome unknown
    fail_business: Mutex<bool>, // Some(true) => durable Failed result
}

impl ControlOperationExecutor for ScriptedControl {
    fn execute(&self, job: &ControlJob<'_>) -> Result<ControlResult, Failure> {
        self.presented
            .lock()
            .unwrap()
            .push(job.operation_id.to_owned());
        let known = self.answer.lock().unwrap().is_some();
        if !known {
            return Err(Failure::new(
                CONTROL_OUTCOME_UNKNOWN,
                "scripted: the operator produced no parsable answer",
            ));
        }
        let payload = job
            .compact_jws
            .split('.')
            .nth(1)
            .ok_or_else(|| Failure::new("CONTROL_OUTCOME_UNKNOWN", "scripted malformed JWS"))?;
        let operation: nazo_operator_protocol::ControlOperation = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| Failure::new("CONTROL_OUTCOME_UNKNOWN", "scripted malformed JWS"))?,
        )
        .map_err(|_| Failure::new("CONTROL_OUTCOME_UNKNOWN", "scripted malformed JWS"))?;
        let request_hash = nazo_operator_protocol::control_operation_request_hash(&operation)
            .map_err(|_| Failure::new("CONTROL_OUTCOME_UNKNOWN", "scripted request hash failed"))?;
        if *self.fail_business.lock().unwrap() {
            // Durable terminal FAILED result, exactly like a real operator
            // whose migration executed and failed (P0-5).
            let now = chrono::Utc::now().timestamp();
            return Ok(ControlResult {
                schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
                operation_id: job.operation_id.to_owned(),
                request_hash,
                outcome: ControlOutcome::Failed,
                error: Some(nazo_operator_protocol::ControlErrorCode::ExecutionFailed),
                accepted_at: now,
                completed_at: Some(now),
                result: None,
            });
        }
        let now = chrono::Utc::now().timestamp();
        Ok(ControlResult {
            schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
            operation_id: job.operation_id.to_owned(),
            request_hash,
            outcome: ControlOutcome::Succeeded,
            error: None,
            accepted_at: now,
            completed_at: Some(now),
            result: None,
        })
    }
}

struct ScriptedLifecycle {
    control: Arc<ScriptedControl>,
    fail_update_activation: Mutex<bool>,
    no_op_update: Mutex<bool>,
    update_calls: Mutex<u32>,
    rollback_calls: Mutex<u32>,
}

impl ScriptedLifecycle {
    fn set_fail_update(&self, value: bool) {
        *self.fail_update_activation.lock().unwrap() = value;
    }
}

impl LifecycleExecutor for ScriptedLifecycle {
    fn execute_update(&self, job: &UpdateJob<'_>) -> Result<UpdateExecution, Failure> {
        *self.update_calls.lock().unwrap() += 1;
        if *self.no_op_update.lock().unwrap() {
            return Ok(UpdateExecution::Noop {
                revision: job.expected_revision,
            });
        }
        let mut migration_result = None;
        if let Some(jws) = job.migration_jws {
            let res = self.control.execute(&ControlJob {
                operation_id: job.operation_id,
                deployment_id: job.deployment_id,
                runtime_kind: job.runtime_kind,
                runtime_object: job.runtime_object,
                artifact_reference: job.current_artifact,
                config_reference: job.config_reference,
                data_root: job.data_root,
                secrets_root: job.secrets_root,
                scope_dir: job.scope_dir,
                compact_jws: jws,
                change_set: None,
            })?;
            if res.outcome == ControlOutcome::Failed {
                return Ok(UpdateExecution::MigrationFailed(res));
            }
            if res.outcome != ControlOutcome::Succeeded {
                return Err(Failure::new(
                    "CONTROL_OUTCOME_UNKNOWN",
                    "migration remains in progress",
                ));
            }
            migration_result = Some(res);
        }
        if *self.fail_update_activation.lock().unwrap() {
            // Contract: undo own partial work before failing; the state
            // document was never touched because apply_update runs last.
            return Err(Failure::new(
                ACTIVATION_FAILED,
                "scripted: readiness never answered after activation",
            ));
        }
        let config = job
            .config
            .map(|staged| (job.config_reference.to_owned(), staged.schema.clone()));
        let state = job.store.apply_update_healthy(
            job.deployment_id,
            job.expected_revision,
            crate::target::deployment_state::UpdateCommit {
                artifact: NEW_REF.to_owned(),
                release: Some(crate::target::ReleaseVersion::new("v9").expect("identity")),
                rollback_policy: crate::model::test_release_rollback_policy(),
                config,
                operation_id: job.operation_id.to_owned(),
            },
        )?;
        Ok(UpdateExecution::Activated(LifecycleFacts {
            revision: state.config.revision,
            release: Some(crate::target::ReleaseVersion::new("v9").expect("identity")),
            migration_result,
        }))
    }

    fn execute_rollback(&self, job: &RollbackJob<'_>) -> Result<LifecycleFacts, Failure> {
        *self.rollback_calls.lock().unwrap() += 1;
        let state = job.store.apply_rollback_healthy(
            job.deployment_id,
            job.expected_revision,
            None,
            job.operation_id,
        )?;
        Ok(LifecycleFacts {
            revision: state.config.revision,
            release: None,
            migration_result: None,
        })
    }
}

#[derive(Default)]
struct ScriptedDeletion {
    calls: Mutex<u32>,
    /// Resource ids actually handed to the deletion executor.
    planned: Mutex<Vec<String>>,
}

impl DeletionExecutor for ScriptedDeletion {
    fn execute_deletion(&self, job: &DeletionJob<'_>) -> Result<(), Failure> {
        *self.calls.lock().unwrap() += 1;
        self.planned.lock().unwrap().extend(
            job.declared
                .iter()
                .filter(|resource| {
                    resource.ownership == crate::target::ResourceOwnership::Managed
                        && resource.scope == crate::target::ResourceScope::Deployment
                        && resource.kind != "container"
                })
                .map(|resource| resource.resource_id.clone()),
        );
        Ok(())
    }
}

struct Fixture {
    _temp: PrivateTempDir,
    context: LifecycleContext,
    keys: ControllerKeyStore,
    state_root: std::path::PathBuf,
    control: Arc<ScriptedControl>,
    lifecycle: Arc<ScriptedLifecycle>,
    deletion: Arc<ScriptedDeletion>,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        Self::with_current_release(Some(
            crate::target::ReleaseVersion::new("v1").expect("release version"),
        ))
    }

    fn with_current_release(
        current_release: Option<crate::target::ReleaseVersion>,
    ) -> anyhow::Result<Self> {
        let temp = PrivateTempDir::new("nazauthctl-instance-lifecycle")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        let host = registry.ensure_local_host()?;
        let mut hello = local_hello(vec!["podman".to_owned()]);
        hello.target_id = host.host_id.to_string();
        let state_root = temp.path().join("state");

        // Two sibling instances on one host prove uninstall isolation.
        for deployment in [DEPLOYMENT, "deploy-sibling"] {
            let evidence = DiscoveryEvidence::new(&host, hello.clone(), deployment, ISSUER)?;
            let _: InstanceRecord = registry.register_instance(
                &evidence,
                Some(&format!("inst-{deployment}")),
                crate::registry::ObservationCache::now(true, "registered by fixture".to_owned()),
            )?;
        }

        // Bootstrap the target state for the primary deployment: revision 1,
        // one managed file resource plus one external shared database, and a
        // verified current artifact reference.
        let store = TargetStateStore::open(&state_root)?;
        crate::filesystem::atomic_write(
            &state_root.join("target-id"),
            host.host_id.to_string().as_bytes(),
            0o600,
        )?;
        let runtime =
            crate::target::RuntimeSurface::new("podman", format!("nazauth-{DEPLOYMENT}"), 8000)?;
        let artifact = crate::target::ArtifactRefs {
            current: Some(CURRENT_REF.to_owned()),
            previous: None,
        };
        let resources = vec![
            crate::target::Resource::new(
                "app-data",
                "directory",
                temp.path().join("data").to_string_lossy().as_ref(),
                crate::target::ResourceOwnership::Managed,
                crate::target::ResourceScope::Deployment,
            )?,
            // A real install records the deployment-owned secrets directory;
            // update derives the runtime database role from it.
            crate::target::Resource::new(
                "app-secrets",
                "directory",
                temp.path().join("secrets").to_string_lossy().as_ref(),
                crate::target::ResourceOwnership::Managed,
                crate::target::ResourceScope::Deployment,
            )?,
            crate::target::Resource::new(
                "shared-db",
                "postgres",
                "postgres://10.0.0.8:5432/nazoauth",
                crate::target::ResourceOwnership::External,
                crate::target::ResourceScope::Shared,
            )?,
        ];
        store.bootstrap(
            DEPLOYMENT,
            crate::target::BootstrapParams {
                issuer: ISSUER.to_owned(),
                runtime,
                artifact,
                config_reference: temp.path().join("config.yaml").to_string_lossy().into(),
                config_schema: "nazauth-seed-v1".to_owned(),
                resources,
                current_release,
                current_rollback_policy: crate::model::test_release_rollback_policy(),
            },
            "bootstrap-op-0001",
        )?;

        // The config-revision marker is the single CAS authority the signed
        // operation must carry (P0-6); a real install writes it on the scope
        // directory before the runtime starts.
        let scope_marker = state_root
            .join("deployments")
            .join(DEPLOYMENT)
            .join("config-revision");
        std::fs::create_dir_all(scope_marker.parent().expect("scope parent"))?;
        std::fs::write(&scope_marker, "c".repeat(64))?;

        // Bind the controller key store so migrations can be signed.
        let keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        keys.get_or_create_active(DEPLOYMENT)?;
        let key_ref = controller_key_ref_for(DEPLOYMENT)?;
        registry.update_controller_binding(DEPLOYMENT, None, Some(key_ref.as_str()))?;

        let control = Arc::new(ScriptedControl {
            presented: Mutex::new(Vec::new()),
            answer: Mutex::new(Some(())),
            fail_business: Mutex::new(false),
        });
        let lifecycle = Arc::new(ScriptedLifecycle {
            control: control.clone(),
            fail_update_activation: Mutex::new(false),
            no_op_update: Mutex::new(false),
            update_calls: Mutex::new(0),
            rollback_calls: Mutex::new(0),
        });
        let deletion = Arc::new(ScriptedDeletion::default());
        let target = LocalTarget::with_state_root(&state_root)
            .with_control_executor(control.clone())
            .with_lifecycle_executor(lifecycle.clone())
            .with_deletion_executor(deletion.clone());
        let context = LifecycleContext {
            registry,
            factory: Box::new(move |_record| {
                Ok(Box::new(target.clone()) as Box<dyn ExecutionTarget + Send>)
            }),
        };
        Ok(Self {
            _temp: temp,
            context,
            keys,
            state_root,
            control,
            lifecycle,
            deletion,
        })
    }

    fn store(&self) -> anyhow::Result<TargetStateStore> {
        TargetStateStore::open(&self.state_root)
    }

    fn update_request(&self) -> UpdateRequest {
        UpdateRequest {
            instance: Some(format!("inst-{DEPLOYMENT}")),
            version: Some("v9.9.9".to_owned()),
            config_content: None,
            config_schema: None,
        }
    }
}

// -------------------------------------------------------------------- G03

#[test]
fn update_dispatches_migration_once_and_commits_new_revision() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let report = run_update(&fixture.context, &fixture.keys, &fixture.update_request())?;
    assert!(report.contains("accepted once"), "{report}");
    assert_eq!(
        *fixture.lifecycle.update_calls.lock().unwrap(),
        1,
        "one lifecycle order per attempt"
    );
    assert_eq!(
        fixture.control.presented.lock().unwrap().len(),
        1,
        "exactly one ControlOperation per attempt"
    );
    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(NEW_REF));
    assert_eq!(state.artifact.previous.as_deref(), Some(CURRENT_REF));
    // F04: the monotonic CAS revision tracks CONFIG changes; an artifact-only
    // update swaps references without advancing it.
    assert_eq!(state.config.revision, 1);
    Ok(())
}

#[test]
fn target_noop_clears_prepared_migration_without_a_control_result() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    *fixture.lifecycle.no_op_update.lock().unwrap() = true;
    let report = run_update(&fixture.context, &fixture.keys, &fixture.update_request())?;

    assert!(
        report.contains("target-verified artifact") && report.contains("no migration"),
        "{report}"
    );
    assert_eq!(*fixture.lifecycle.update_calls.lock().unwrap(), 1);
    assert!(fixture.control.presented.lock().unwrap().is_empty());
    let journal = OperationJournal::open(fixture.keys.instance_dir(DEPLOYMENT)?)?;
    assert!(
        journal.load()?.is_none(),
        "the unsubmitted migration is cleared"
    );
    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(CURRENT_REF));
    assert_eq!(state.artifact.previous, None);
    Ok(())
}

#[test]
fn adopted_artifact_without_release_version_can_update() -> anyhow::Result<()> {
    let fixture = Fixture::with_current_release(None)?;

    run_update(&fixture.context, &fixture.keys, &fixture.update_request())?;

    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(NEW_REF));
    assert_eq!(state.artifact.previous.as_deref(), Some(CURRENT_REF));
    assert_eq!(
        state
            .current_release
            .as_ref()
            .map(|release| release.version.as_str()),
        Some("v9")
    );
    assert_eq!(state.previous_release, None);
    Ok(())
}

#[test]
fn target_backup_gate_runs_before_lifecycle_and_update_replay_is_idempotent() -> anyhow::Result<()>
{
    let fixture = Fixture::new()?;
    let target = LocalTarget::with_state_root(&fixture.state_root)
        .with_lifecycle_executor(fixture.lifecycle.clone());
    let artifact = || crate::target::OfficialArtifactRef {
        repository: "nazozero/NazoAuth".to_owned(),
        version: Some("v9.9.9".to_owned()),
    };
    let rejected = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        DEPLOYMENT,
        Some(1),
        StateMutationPayload::Update {
            artifact: artifact(),
            backup_precondition: UpdateBackupPrecondition::Require {
                manifest_sha256: "a".repeat(64),
                restore_tested_at: chrono::Utc::now(),
                max_age_seconds: 300,
            },
            config: None,
            migration_jws: None,
            migration_request_hash: None,
        },
    );
    let result = target.execute_host_operation(&rejected)?;
    let HostOutcome::Failed { code, .. } = result.outcome else {
        panic!("missing backup evidence must reject the update")
    };
    assert_eq!(
        code,
        crate::target::update_exec::BACKUP_UPDATE_PRECONDITION_FAILED
    );
    assert_eq!(
        *fixture.lifecycle.update_calls.lock().unwrap(),
        0,
        "backup drift must reject before artifact or migration execution"
    );

    let accepted = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        DEPLOYMENT,
        Some(1),
        StateMutationPayload::Update {
            artifact: artifact(),
            backup_precondition: UpdateBackupPrecondition::NotRequired,
            config: None,
            migration_jws: None,
            migration_request_hash: None,
        },
    );
    assert!(matches!(
        target.execute_host_operation(&accepted)?.outcome,
        HostOutcome::Completed { .. }
    ));
    assert!(matches!(
        target.execute_host_operation(&accepted)?.outcome,
        HostOutcome::Completed { .. }
    ));
    assert_eq!(
        *fixture.lifecycle.update_calls.lock().unwrap(),
        1,
        "the same accepted operation replays its stored terminal result"
    );
    Ok(())
}

#[test]
fn update_activation_failure_commits_nothing_and_reports_stable_code() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.lifecycle.set_fail_update(true);
    let error = run_update(&fixture.context, &fixture.keys, &fixture.update_request())
        .expect_err("activation failure must fail the update");
    assert!(error.to_string().contains(ACTIVATION_FAILED), "{error}");
    // Migration was accepted server-side (journaled), but the target state
    // commit never happened: references and revision stay untouched.
    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(CURRENT_REF));
    assert_eq!(state.artifact.previous, None);
    assert_eq!(state.config.revision, 1);
    Ok(())
}

#[test]
fn unknown_outcome_resumes_with_the_same_operation_id() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    *fixture.control.answer.lock().unwrap() = None;
    let error = run_update(&fixture.context, &fixture.keys, &fixture.update_request())
        .expect_err("outcome unknown must fail closed");
    assert!(
        error.to_string().contains(CONTROL_OUTCOME_UNKNOWN),
        "{error}"
    );

    // The write-ahead journal entry survived so the retry resumes instead of
    // minting a new operation.
    *fixture.control.answer.lock().unwrap() = Some(());
    let second = fixture.control.presented.lock().unwrap().len();
    let _ = run_update(&fixture.context, &fixture.keys, &fixture.update_request())?;
    let presented = fixture.control.presented.lock().unwrap();
    assert_eq!(presented.len(), second + 1);
    assert_eq!(
        presented[0], presented[1],
        "resume re-sends the identical operation id"
    );
    Ok(())
}

// -------------------------------------------------------------------- G04

#[test]
fn rollback_without_previous_reference_refuses_to_guess() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let error = run_rollback(&fixture.context, Some(&format!("inst-{DEPLOYMENT}")))
        .expect_err("rollback without a saved previous artifact must refuse");
    assert!(
        error.to_string().contains("ROLLBACK_UNAVAILABLE"),
        "{error}"
    );
    assert_eq!(*fixture.lifecycle.rollback_calls.lock().unwrap(), 0);
    Ok(())
}

#[test]
fn rollback_restores_the_previous_verified_reference() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    // Establish previous=current history exactly like a prior update would.
    fixture.store()?.apply_update_healthy(
        DEPLOYMENT,
        1,
        crate::target::deployment_state::UpdateCommit {
            artifact: NEW_REF.to_owned(),
            release: None,
            rollback_policy: crate::model::test_release_rollback_policy(),
            config: None,
            operation_id: "prior-update-op".to_owned(),
        },
    )?;

    let report = run_rollback(&fixture.context, Some(&format!("inst-{DEPLOYMENT}")))?;
    assert!(report.contains("previous verified"), "{report}");
    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(CURRENT_REF));
    assert_eq!(state.artifact.previous.as_deref(), Some(NEW_REF));
    assert_eq!(state.config.revision, 1);
    Ok(())
}

// -------------------------------------------------------------------- G06

#[test]
fn uninstall_plan_zero_deletes_external_resources() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let plan = plan_uninstall(&fixture.context, Some(&format!("inst-{DEPLOYMENT}")))?;
    assert_eq!(
        plan.managed_deletions.len(),
        2,
        "the managed data and secrets directories"
    );
    assert_eq!(plan.kept_external.len(), 1, "the shared database stays");
    let rendered = plan.render();
    assert!(rendered.contains("ZERO DELETE"), "{rendered}");
    assert!(rendered.contains("sibling instances"), "{rendered}");

    // Plan-only mode executes nothing.
    let preview = run_uninstall(
        &fixture.context,
        &fixture.keys,
        Some(&format!("inst-{DEPLOYMENT}")),
        false,
    )?;
    assert!(preview.contains("--yes"), "{preview}");
    assert_eq!(*fixture.deletion.calls.lock().unwrap(), 0);
    assert!(fixture.keys.load_active(DEPLOYMENT)?.is_some());
    Ok(())
}

#[test]
fn uninstall_refuses_to_orphan_remote_recovery_or_transfer_staging() -> anyhow::Result<()> {
    for journal in ["recovery-plan.json", "backup-transfer.json"] {
        let fixture = Fixture::new()?;
        std::fs::write(
            fixture.keys.instance_dir(DEPLOYMENT)?.join(journal),
            b"pending",
        )?;

        let error = run_uninstall(
            &fixture.context,
            &fixture.keys,
            Some(&format!("inst-{DEPLOYMENT}")),
            true,
        )
        .expect_err("pending remote cleanup must block uninstall");

        assert!(error.to_string().contains("incomplete"), "{error}");
        assert_eq!(*fixture.deletion.calls.lock().unwrap(), 0);
        assert!(fixture.keys.load_active(DEPLOYMENT)?.is_some());
        assert!(
            fixture
                .context
                .registry
                .instance_by_deployment(DEPLOYMENT)?
                .is_some()
        );
    }
    Ok(())
}

#[test]
fn uninstall_removes_local_instance_state_and_keeps_siblings() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let report = run_uninstall(
        &fixture.context,
        &fixture.keys,
        Some(&format!("inst-{DEPLOYMENT}")),
        true,
    )?;
    assert!(report.contains("HostRecord"), "{report}");
    assert!(report.contains("Controller Slots"), "{report}");
    assert!(!report.contains("controller list --instance"), "{report}");
    assert_eq!(*fixture.deletion.calls.lock().unwrap(), 1);

    // Primary record gone...
    let error = fixture
        .context
        .registry
        .update_controller_binding(DEPLOYMENT, None, None)
        .expect_err("the uninstalled instance must be forgotten");
    assert!(error.to_string().contains("unknown instance"), "{error}");
    assert!(fixture.keys.load_active(DEPLOYMENT)?.is_none());
    assert!(fixture.keys.list_keys(DEPLOYMENT)?.is_empty());
    // ...while the sibling on the same host survives.
    fixture
        .context
        .registry
        .update_controller_binding("deploy-sibling", None, None)?;
    assert!(
        fixture
            .context
            .registry
            .host_by_alias(crate::registry::LOCAL_HOST_ALIAS)?
            .is_some()
    );
    Ok(())
}

// ---------------------------------------------------------------- H04/H06

#[test]
fn uninstall_plan_and_operation_log_keep_external_resources_listed() -> anyhow::Result<()> {
    use crate::target::TargetJournal;

    let fixture = Fixture::new()?;

    // The plan lists the external shared database as kept (H06: reference
    // facts stay visible; nothing external is ever deleted).
    let plan = plan_uninstall(&fixture.context, Some(&format!("inst-{DEPLOYMENT}")))?;
    let kept = plan
        .kept_external
        .iter()
        .find(|(id, _, _)| id == "shared-db")
        .expect("the shared database stays listed as kept");
    assert_eq!(kept.1, "postgres");
    let rendered = plan.render();
    assert!(rendered.contains("shared-db"), "{rendered}");
    assert!(rendered.contains("ZERO DELETE"), "{rendered}");

    let report = run_uninstall(
        &fixture.context,
        &fixture.keys,
        Some(&format!("inst-{DEPLOYMENT}")),
        true,
    )?;
    assert!(
        report.contains("external/shared resources were never touched"),
        "{report}"
    );

    // The destructive path received ONLY the managed resources — the external
    // locator never enters a deletion order.
    let planned = fixture.deletion.planned.lock().unwrap().clone();
    assert_eq!(
        planned,
        vec!["app-data".to_owned(), "app-secrets".to_owned()],
        "{planned:?}"
    );

    // The journaled operation log records the uninstall as one terminal,
    // completed mutation beside the retained journal.
    let entries = TargetJournal::open(&fixture.state_root)?.operation_log(DEPLOYMENT)?;
    let uninstall_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.status != crate::target::journal::JournalStatus::Pending)
        .collect();
    assert_eq!(uninstall_entries.len(), 1, "{entries:?}");
    assert_eq!(uninstall_entries[0].action, "state-mutate");
    assert_eq!(
        uninstall_entries[0].outcome,
        Some(crate::target::journal::OperationOutcomeSummary::Completed)
    );
    Ok(())
}

// -------------------------------------------------------------------- G07

#[test]
fn privilege_matrix_requires_elevation_only_for_genuinely_elevated_steps() {
    use PrivilegeStep::*;
    for step in [RegistryRead, DeploymentStateRead, HealthProbe] {
        assert!(
            !step.requires_elevation(),
            "{} must stay unprivileged",
            step.label()
        );
    }
    for step in [
        EngineSocketAccess,
        SystemdUnitManagement,
        PrivilegedPortBind,
    ] {
        assert!(
            step.requires_elevation(),
            "{} must be classified elevated",
            step.label()
        );
    }
}

#[test]
fn engine_access_check_names_the_step_and_never_runs_sudo() {
    struct Responsive(bool);
    impl super::privilege::PrivilegeProbe for Responsive {
        fn engine_responsive(&self, _engine: &str) -> anyhow::Result<bool> {
            Ok(self.0)
        }
    }

    let missing = ensure_engine_access("definitely-not-a-real-engine", &Responsive(true))
        .expect_err("a missing engine binary must be refused");
    assert_eq!(missing.code(), "PRIVILEGE_REQUIRED");
    assert!(missing.to_string().contains("not installed"));

    let refused = ensure_engine_access("podman", &Responsive(false))
        .expect_err("an unresponsive socket must be refused");
    assert_eq!(refused.code(), "PRIVILEGE_REQUIRED");
    assert!(refused.to_string().contains("sudo -v") || refused.to_string().contains("NOPASSWD"));

    let shell = if cfg!(windows) { "cmd" } else { "sh" };
    ensure_engine_access(shell, &Responsive(true)).expect("a responsive engine passes");
}

// ------------------------------------------------------------------ P0-5

#[test]
fn durable_failed_migration_terminates_update_before_activation() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    *fixture.control.fail_business.lock().unwrap() = true;

    let request = UpdateRequest {
        instance: Some(format!("inst-{DEPLOYMENT}")),
        version: None,
        config_content: None,
        config_schema: None,
    };
    let error = super::update::run_update(&fixture.context, &fixture.keys, &request)
        .expect_err("a durably failed migration must terminate the update");

    assert!(
        error.to_string().contains("migration failed durably"),
        "{error}"
    );

    // The update order ran migration, aborted before activation, and committed no state advance.
    assert_eq!(*fixture.lifecycle.update_calls.lock().unwrap(), 1);
    let state = fixture.store()?.load_existing(DEPLOYMENT)?;
    assert_eq!(state.artifact.current.as_deref(), Some(CURRENT_REF));
    assert_eq!(state.config.revision, 1);

    // The journal keeps the accepted record terminal for this id so a rerun
    // with identical inputs replays the identical durable failure.
    let presented = fixture.control.presented.lock().unwrap();
    assert_eq!(presented.len(), 1, "one dispatch per attempt");
    Ok(())
}

#[test]
fn durable_failed_migration_clears_controller_slot_after_persistence() -> anyhow::Result<()> {
    // Two sequential attempts with the same inputs must both dispatch (the
    // first terminal answer is durably carried by the target host journal and
    // then clears ctl's single slot. A new invocation is a new attempt, so it
    // receives a new operation identity rather than pinning the controller.
    let fixture = Fixture::new()?;
    *fixture.control.fail_business.lock().unwrap() = true;
    let request = UpdateRequest {
        instance: Some(format!("inst-{DEPLOYMENT}")),
        version: None,
        config_content: None,
        config_schema: None,
    };
    for _ in 0..2 {
        let error = super::update::run_update(&fixture.context, &fixture.keys, &request)
            .expect_err("durable failure repeats");
        assert!(error.to_string().contains("migration failed durably"));
    }
    let presented = fixture.control.presented.lock().unwrap();
    assert!(!presented.is_empty());
    assert_eq!(
        presented
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2,
        "each post-terminal invocation receives a fresh operation identity"
    );
    Ok(())
}
