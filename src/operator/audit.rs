use std::path::Path;

use super::*;

mod chain;
mod evidence;
mod execution;
mod management;

pub(super) fn read_audit_text(path: &Path, label: &str) -> anyhow::Result<String> {
    const MAX_AUDIT_TEXT_BYTES: u64 = 256 * 1024;
    let bytes =
        crate::filesystem::read_secure_regular_file(path, label, false, MAX_AUDIT_TEXT_BYTES)?;
    String::from_utf8(bytes.to_vec())
        .with_context(|| format!("{label} is not UTF-8: {}", path.display()))
}

use evidence::verify_trust_transitions;
use management::verify_management_events;

pub(crate) use chain::audit_entries;
pub(crate) use chain::verify_audit_chain;
pub(super) use chain::{append_audit, audit_head, repair_audit_head_for_append};
pub(crate) use chain::{show_audit, verify_audit};

pub(crate) use execution::execute_with_io;
pub(super) use execution::{canonical_manifest, verify_target_expectation};
pub(crate) use execution::{execute, expected_release_target};
#[cfg(test)]
pub(super) use execution::{execute_test_task, load_or_issue_task};
#[cfg(test)]
pub(super) use execution::{operation_name, target_expectation, validate_runtime_receipt};

pub(crate) use management::{
    append_management_event, append_management_event_idempotent, load_management_event,
};

pub(super) use evidence::{
    encode_retirement_probe_audit_evidence, validate_retirement_probe_audit_evidence,
};
