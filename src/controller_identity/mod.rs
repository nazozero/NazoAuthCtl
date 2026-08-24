//! Per-instance Controller Private Key store and ControlOperation signing
//! entry point (goal plan 04 §2/§5, task D03, authority ADR row 3).
//!
//! Every managed NazoAuth deployment is controlled with its own Ed25519
//! Controller Key. The private key is minted on the control machine from a
//! CSPRNG seeded by OS entropy and **never leaves it**: this module contains
//! no network code and offers no API that could persist or forward private
//! material to a NazoAuth instance, an SSH target, argv/env, or a log line.
//! NazoAuth only ever receives the public key through the bind/rotate
//! proposal flows (D04+); the server-side registry (D01) is the sole
//! authority for controller validity and the 30-day expiry.
//!
//! Storage layout (user-scoped, sibling of the Registry store):
//!
//! ```text
//! <platform config dir>/nazoauthctl/controller-keys/
//!   <deployment_id>/            one directory per instance
//!     keys.lock                 fs2 exclusive lock for every operation
//!     active.json               atomic pointer naming the active kid
//!     keys/<kid>.json           one key record per kid (private material)
//! ```
//!
//! One directory per `deployment_id` (never per instance alias): the
//! deployment id is the immutable cross-store instance identity, while
//! aliases may be renamed freely (`registry.rs`). Multiple key records per
//! directory are allowed so candidate keys can coexist with the active one;
//! the `active.json` pointer selects among them atomically. This makes the
//! structure rotation-ready (D07 reuses `generate_candidate` +
//! `set_active_kid`), without implementing any rotation ceremony here.
//!
//! Every record follows the shared store conventions: atomic writes through
//! the runtime filesystem helpers, an fs2 lock, secure regular-file reads
//! (regular, non-symlink, non-reparse, single hard link, owner-safe mode,
//! size caps), strict JSON with `deny_unknown_fields` plus a schema tag, and
//! fail-closed errors on any drift. On Windows the portable std API cannot
//! inspect ACLs, so confidentiality rests on the user-profile ACL of the
//! platform config directory plus the path/reparse-point validation shared
//! with every other ctl store.
//!
//! [`operation`] is the only place in ctl that signs ControlOperations:
//! callers supply the operation payload, artifact target, and config
//! revision; the helper resolves the instance, loads its active private key,
//! canonicalizes, hashes, and signs exactly once per operation.

pub mod operation;
pub mod store;

pub use operation::{
    CONTROLLER_KEY_REF_PREFIX, ControlOperationInput, SignedControlOperation,
    build_signed_control_operation, deployment_from_key_ref,
};
pub use store::{
    ControllerKeyStore, ControllerKeySummary, LoadedControllerKey, controller_key_ref_for,
};
