//! Docker one-shot task execution.

use std::ffi::OsStr;

use super::super::{OneShotTask, container_shared};

pub(super) fn run(command: &OsStr, task: &OneShotTask) -> anyhow::Result<String> {
    container_shared::one_shot_process(command, task, "Docker")?.stdin_stdout(&task.stdin)
}

pub(super) fn run_authorization_probe(command: &OsStr, task: &OneShotTask) -> anyhow::Result<bool> {
    container_shared::one_shot_process(command, task, "Docker")?
        .stdin_authorization_rejected(&task.stdin)
}
