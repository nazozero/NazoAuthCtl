//! Offline compatibility check run by the candidate before replacing a working controller.
use crate::registry::RegistryStore;
use crate::target::{TargetJournal, TargetStateStore, backup};
use anyhow::Context as _;

pub(super) fn run() -> anyhow::Result<()> {
    let registry_root = RegistryStore::default_root()?;
    if registry_root.try_exists()? {
        super::self_update::validate_self_state(&registry_root.join("controller-self"))?;
        let registry = RegistryStore::open(registry_root)?;
        registry.list_hosts()?;
        let keys = crate::controller_identity::store::ControllerKeyStore::open_default()?;
        for instance in registry.list_instances()? {
            let directory = keys.instance_dir(&instance.deployment_id)?;
            keys.load_active(&instance.deployment_id)?;
            keys.list_keys(&instance.deployment_id)?;
            crate::controller_identity::journal::OperationJournal::open(directory.clone())?
                .load()?;
            if directory.join("recovery-plan.json").try_exists()? {
                super::recovery_journal::RecoveryJournal::open(&directory)?.load()?;
            }
        }
    }
    let root = crate::target::target_state_root()?;
    let mut deployments = 0;
    if root.try_exists()? {
        let store = TargetStateStore::open(&root)?;
        let journal = TargetJournal::open(&root)?;
        for state in store.list_deployments()? {
            let scope = store.scope_dir(&state.deployment_id)?;
            backup::backup_projection(&scope, &state).with_context(|| {
                format!("backup state for {} is incompatible", state.deployment_id)
            })?;
            let snapshots = scope.join("backup").join("snapshots");
            if snapshots.try_exists()? {
                for entry in std::fs::read_dir(&snapshots)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        backup::load_manifest_at(&entry.path().join("snapshot-manifest.json"))?;
                    }
                }
            }
            journal.operation_log(&state.deployment_id)?;
            deployments += 1;
        }
    }
    crate::ui::print_value(
        &serde_json::json!({"schema":1,"compatible":true,"deployments":deployments}),
    );
    Ok(())
}
