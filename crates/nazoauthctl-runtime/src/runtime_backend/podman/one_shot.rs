//! Podman one-shot tasks.

use std::ffi::OsStr;

use super::super::{OneShotTask, container_shared};

pub(super) fn run(command: &OsStr, task: &OneShotTask) -> anyhow::Result<String> {
    // The controller validates the returned runtime receipt before accepting
    // this output.  Keep a durable, signed result even if Podman reports a
    // later non-zero engine cleanup status.
    let (_, stdout) = container_shared::one_shot_process(command, task, "Podman")?
        .stdin_stdout_with_status(&task.stdin)?;
    Ok(stdout)
}

pub(super) fn run_authorization_probe(command: &OsStr, task: &OneShotTask) -> anyhow::Result<bool> {
    container_shared::one_shot_process(command, task, "Podman")?
        .stdin_authorization_rejected(&task.stdin)
}
