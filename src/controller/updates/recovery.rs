use super::*;

pub(crate) fn uses_legacy_lock(command: &LegacyCommand) -> bool {
    if DeploymentStore::system().registry_path().exists() {
        return false;
    }
    !matches!(
        command,
        LegacyCommand::SelfCheck(_)
            | LegacyCommand::SelfUpdate { .. }
            | LegacyCommand::SelfRollback { .. }
            // The target-side stdio executor never touches controller state.
            | LegacyCommand::RemoteExec
            // Fleet registry commands own their user-scoped store lock and
            // never touch the deployment lifecycle state machine.
            | LegacyCommand::Host(_)
            | LegacyCommand::Instance(_)
            // Controller identity lifecycle owns the user-scoped Registry and
            // key stores; it never touches the legacy deployment state either.
            | LegacyCommand::Controller(_)
    )
}
