//! The single authority for the stable CLI error codes (goal plan 09 §5, I05).
//!
//! Every user-visible failure carries exactly one code from the closed set
//! below. Codes originate at the layer that owns the fact — the target state
//! store, the wire protocol, the Registry, the privilege sink, or the admin
//! API — and this module only names them once so the error envelope, tests,
//! and documentation cannot drift apart.
//!
/// The host alias is not in the control-side Host Registry.
pub const HOST_NOT_REGISTERED: &str = "HOST_NOT_REGISTERED";

/// A command-local argument or input file failed validation before any target
/// operation was attempted.
pub const INPUT_INVALID: &str = "INPUT_INVALID";

/// The host could not be contacted (network failure or per-target timeout).
pub const HOST_UNREACHABLE: &str = "HOST_UNREACHABLE";

/// OpenSSH reported an authentication failure for the configured profile.
pub const SSH_AUTH_FAILED: &str = "SSH_AUTH_FAILED";

/// OpenSSH host key verification failed; the user's own SSH configuration
/// owns the decision and disabling StrictHostKeyChecking is never an option.
pub const SSH_HOST_KEY_FAILED: &str = "SSH_HOST_KEY_FAILED";

/// The remote helper's product/schema/release version failed the C08 handshake.
pub const REMOTE_HELPER_MISMATCH: &str = "REMOTE_HELPER_MISMATCH";

/// A step requires elevated privileges that the current session cannot
/// provide non-interactively.
pub const PRIVILEGE_REQUIRED: &str = "PRIVILEGE_REQUIRED";

/// No registered instance matches the exact selector.
pub const INSTANCE_NOT_REGISTERED: &str = "INSTANCE_NOT_REGISTERED";

/// Several instances are registered, so the action demands one explicit
/// selector; fuzzy selection does not exist.
pub const INSTANCE_AMBIGUOUS: &str = "INSTANCE_AMBIGUOUS";

/// Persisted ctl state does not conform to the current schema; the only
/// supported path is the documented STATE_RESET procedure.
pub const STATE_RESET_REQUIRED: &str = "STATE_RESET_REQUIRED";

/// An application-level operation requires a controller binding that the
/// instance does not have yet (`bind` first).
pub const CONTROL_BINDING_REQUIRED: &str = "CONTROL_BINDING_REQUIRED";

/// NazoAuth did not authorize the presented Controller Key. The public slot
/// list is the authority for whether the key is unknown, revoked, or expired.
pub const CONTROLLER_KEY_UNAUTHORIZED: &str = "CONTROLLER_KEY_UNAUTHORIZED";

/// The deployment already holds the maximum number of controller slots.
pub const CONTROLLER_SLOT_LIMIT: &str = "CONTROLLER_SLOT_LIMIT";

/// An identity-changing controller command needs an authenticated admin
/// session (and the server may additionally require fresh MFA).
pub const ADMIN_ACCESS_REQUIRED: &str = "ADMIN_ACCESS_REQUIRED";

/// The same operation id arrived with a different canonical request hash; the
/// original intent is authoritative and must never be overwritten.
pub const OPERATION_ID_CONFLICT: &str = "OPERATION_ID_CONFLICT";

/// Config/state optimistic-concurrency mismatch; re-read live state and
/// rebuild the intent.
pub const CONFIG_REVISION_MISMATCH: &str = "CONFIG_REVISION_MISMATCH";

/// The target's recorded release version disagrees with the verified artifact.
pub const TARGET_IDENTITY_MISMATCH: &str = "TARGET_IDENTITY_MISMATCH";

/// Transport-level sudo refusal code (C06). Not part of the 16-code CLI set:
/// the envelope maps it onto [`PRIVILEGE_REQUIRED`] because the remedy is the
/// same one-time interactive credential establishment.
pub const SUDO_PASSWORD_REQUIRED: &str = "SUDO_PASSWORD_REQUIRED";
