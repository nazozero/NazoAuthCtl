//! Docker one-shot task execution.

use std::ffi::OsStr;

use super::super::{OneShotTask, container_shared};

pub(super) fn run(command: &OsStr, task: &OneShotTask) -> anyhow::Result<String> {
    container_shared::one_shot_process(
        command,
        task,
        "Docker",
        false,
        Some("host.docker.internal:host-gateway"),
    )?
    .stdin_stdout(&task.stdin)
}
