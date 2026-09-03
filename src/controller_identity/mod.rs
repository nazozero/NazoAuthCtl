//! Per-instance Controller Private Key store, ControlOperation signing,
//! identity lifecycle flows, and the control-side operation journal
//! (goal plan 04/05, tasks D03–D09 and E06 ctl half; authority ADR row 3).
//!
//! Every managed NazoAuth deployment is controlled with its own Ed25519
//! Controller Key. The private key is minted on the control machine from a
//! CSPRNG seeded by OS entropy and **never leaves it**: no module here offers
//! an API that could persist or forward private material to a NazoAuth
//! instance, an SSH target, argv/env, or a log line. NazoAuth only ever
//! receives public keys through the bind/add/rotate/revoke flows
//! ([`lifecycle`]); the server-side registry is the sole authority for
//! controller validity and the 30-day expiry.
//!
//! Storage layout (user-scoped, sibling of the Registry store):
//!
//! ```text
//! <platform config dir>/nazoauthctl/controller-keys/
//!   <deployment_id>/              one directory per instance
//!     keys.lock                   fs2 exclusive lock for every operation
//!     active.json                 atomic pointer naming the active kid
//!     keys/<kid>.json             one key record per kid (private material)
//!     operation-journal.json      E06 ctl-side dispatch journal
//! ```
//!
//! One directory per `deployment_id` (never per instance alias): the
//! deployment id is the immutable cross-store instance identity, while
//! aliases may be renamed freely. Multiple key records per directory are
//! allowed so candidate keys can coexist with the active one; the
//! `active.json` pointer selects among them atomically.
//!
//! Every record follows the shared store conventions: atomic writes through
//! the runtime filesystem helpers, fs2 locks, secure regular-file reads
//! (regular, non-symlink, non-reparse, single hard link, owner-safe mode,
//! size caps), strict JSON with `deny_unknown_fields` plus a schema tag, and
//! fail-closed errors on any drift. On Windows the portable std API cannot
//! inspect ACLs, so confidentiality rests on the user-profile ACL of the
//! platform config directory plus the path/reparse-point validation shared
//! with every other ctl store.
//!
//! Module map:
//!
//! * [`store`] — D03 key store (generate/set-active/load/list/retire).
//! * [`operation`] — the only place that signs ControlOperations.
//! * [`admin_api`] — HTTPS client for the frozen controller-registry admin
//!   contract; TLS verification is structural, never optional.
//! * [`lifecycle`] — bind/add/rotate/revoke/slots flows (D04/D06/D07/D08)
//!   and their CLI entry point, including crash reconciliation against the
//!   authoritative slot list.
//! * [`expiry`] — D09 rendering of the server-owned 30-day clock from an
//!   explicit live slot response; display observations never authorize work.
//! * [`journal`] — E06 ctl-half write-ahead dispatch journal.
//! * [`dispatch`] — prepare/resume/dispatch glue keeping "one authorization =
//!   one operation lifetime".
//! * [`recovery`] — Recovery Secret client half (D10/D11/D12): offline-root
//!   enrollment/rotation and the break-glass challenge flow. Secret bytes and
//!   derived seeds exist only inside these functions and are zeroized.

pub mod admin_api;
pub mod dispatch;
pub mod expiry;
pub mod journal;
pub mod lifecycle;
pub mod operation;
pub(crate) mod recovery;
pub mod store;

pub use dispatch::{
    AttemptKind, DispatchVerdict, PreparedOperation, classify_control_receipt, dispatch_via_target,
    prepare_control_operation, prepare_pending_control_operation, settle_journal,
    validate_control_change_set, validate_control_result_binding,
};
pub use journal::{JournalState, OperationJournal, OperationJournalEntry};
pub use operation::{
    CONTROLLER_KEY_REF_PREFIX, ControlOperationInput, SignedControlOperation,
    build_signed_control_operation, deployment_from_key_ref,
};
pub use store::{
    ControllerKeyStore, ControllerKeySummary, LoadedControllerKey, controller_key_ref_for,
};
