use super::*;

mod chain;
mod evidence;
mod execution;
mod management;

use chain::verify_audit_chain;
use evidence::verify_trust_transitions;
use management::verify_management_events;

#[cfg(test)]
pub(super) use chain::audit_entries;
pub(super) use chain::{append_audit, audit_head};
pub(crate) use chain::{show_audit, verify_audit};

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
