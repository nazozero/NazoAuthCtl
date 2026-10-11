//! Podman one-shot tasks.

use std::ffi::OsStr;

use super::super::{OneShotTask, container_shared};

pub(super) fn run(command: &OsStr, task: &OneShotTask) -> anyhow::Result<String> {
    task.capture_result(container_shared::one_shot_process(
        command,
        task,
        "Podman",
        super::is_rootless(),
        None,
    )?)
}
