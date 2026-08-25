//! Fresh-install bootstrap authority (goal plan 07, task G02).
//!
//! A fresh NazoAuth cannot enroll an administrator before it runs, and its
//! very first administrator cannot exist before initialization. The clean
//! install closes exactly this loop — and nothing more: the target provisions
//! one single-use capability that may create the initial admin account, and
//! the capability dies at its first successful use (or with a failed install).
//!
//! Hard rules, all enforced in code:
//!
//! 1. The allowlist is a compile-time constant: [`FRESH_BOOTSTRAP_ALLOWLIST`]
//!    contains exactly `create-initial-admin`. No other operation can ever be
//!    provisioned or authorized through this path.
//! 2. The capability is bound to the fresh-install journal: authorization
//!    requires that the live DeploymentState was produced by the exact install
//!    operation id recorded in the context, carries the exact verified
//!    artifact digest and the untouched config revision recorded then. Any
//!    drift (tampered artifact/config, later operation) rejects.
//! 3. Closure deletes the token and context files durably. Because
//!    `bootstrap` state mutations fail closed over existing state
//!    (`DEPLOYMENT_EXISTS`), a deleted capability can never be regenerated:
//!    there is no permanent unsigned operator and no `--force-bootstrap`.
//!
//! Server-side note: NazoAuth's `/auth/bootstrap-admin` endpoint accepts the
//! one-time token for exactly one account creation; treating the token as an
//! ordinary operator credential afterwards is a server-side enforcement point
//! outside this repository's control surface (tracked as an open question).

use std::path::Path;

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::filesystem;

use super::{
    deployment_state::{DeploymentState, Failure},
    install_exec::InstallJob,
    wire::sanitize,
};

/// The complete hardcoded allowlist of fresh-install bootstrap operations.
/// Extending this set requires changing this constant — deliberately not a
/// configuration input.
pub const FRESH_BOOTSTRAP_ALLOWLIST: &[&str] = &["create-initial-admin"];

/// Stable rejection: any bootstrap attempt without an open, journal-bound,
/// untampered fresh-install capability. Covers closed, consumed, absent, and
/// drifted capabilities alike — absence of capability is itself the closure.
pub const BOOTSTRAP_CLOSED: &str = "BOOTSTRAP_CLOSED";

/// Schema discriminator for the persisted context document.
pub const FRESH_BOOTSTRAP_SCHEMA: u32 = 1;

/// Context file name inside the deployment scope directory.
pub const CONTEXT_FILE_NAME: &str = "fresh-bootstrap.json";

/// Token file name inside the deployment scope directory. Root-private by
/// directory mode; read once per claim attempt and never logged.
pub const TOKEN_FILE_NAME: &str = "fresh-bootstrap-token";

/// Durable record binding the bootstrap capability to one exact fresh install.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshBootstrapContext {
    pub schema: u32,
    /// Copy of the allowlist valid at provisioning time; load-time equality
    /// against the constant turns an allowlist change into a hard failure
    /// instead of silently widening old capabilities.
    pub allowlist: Vec<String>,
    /// The install operation whose journal produced the deployment.
    pub install_operation_id: String,
    pub deployment_id: String,
    pub issuer: String,
    pub artifact_subject_sha256: String,
    /// Config revision at install commit (fresh installs commit revision 1);
    /// claims after any config change reject.
    pub config_revision: u64,
    pub created_at: DateTime<Utc>,
}

impl FreshBootstrapContext {
    fn validate(&self) -> anyhow::Result<()> {
        if self.schema != FRESH_BOOTSTRAP_SCHEMA {
            bail!("unsupported fresh-bootstrap context schema {}", self.schema);
        }
        if self.allowlist != FRESH_BOOTSTRAP_ALLOWLIST {
            bail!("fresh-bootstrap context allowlist differs from the compiled allowlist");
        }
        Ok(())
    }
}

/// Provision the single-use initial-admin capability for a fresh install.
/// Called by the install executor *before* the runtime starts (the runtime
/// bind-mounts the token); refuses to shadow an existing capability. The
/// capability is bound to the exact install operation id and the exact
/// verified artifact digest.
pub(crate) fn provision(
    scope_dir: &Path,
    job: &InstallJob<'_>,
    subject_digest: &str,
) -> anyhow::Result<()> {
    if load_context(scope_dir)?.is_some() {
        bail!("a fresh-bootstrap capability already exists; refusing to re-provision");
    }
    filesystem::generate_secret(&scope_dir.join(TOKEN_FILE_NAME))
        .context("failed to persist the fresh-bootstrap token")?;
    let context = FreshBootstrapContext {
        schema: FRESH_BOOTSTRAP_SCHEMA,
        allowlist: FRESH_BOOTSTRAP_ALLOWLIST
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        install_operation_id: job.operation_id.to_owned(),
        deployment_id: job.deployment_id.to_owned(),
        issuer: job.issuer.to_owned(),
        artifact_subject_sha256: subject_digest.to_owned(),
        config_revision: 1,
        created_at: Utc::now(),
    };
    filesystem::atomic_write(
        &scope_dir.join(CONTEXT_FILE_NAME),
        &serde_json::to_vec_pretty(&context)?,
        0o600,
    )
}

/// Load the capability record. `Ok(None)` means "no capability exists" —
/// which authorizes nothing and is indistinguishable from closure by design.
pub(crate) fn load_context(scope_dir: &Path) -> anyhow::Result<Option<FreshBootstrapContext>> {
    let path = scope_dir.join(CONTEXT_FILE_NAME);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        filesystem::read_secure_regular_file(&path, "fresh-bootstrap context", false, 16 * 1024)?;
    let context: FreshBootstrapContext = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} does not parse as fresh-bootstrap context",
            path.display()
        )
    })?;
    context.validate()?;
    Ok(Some(context))
}

/// Read the one-time token. Exists only while the capability is open.
pub(crate) fn read_token(scope_dir: &Path) -> anyhow::Result<String> {
    let path = scope_dir.join(TOKEN_FILE_NAME);
    let bytes = filesystem::read_secure_regular_file(&path, "fresh-bootstrap token", true, 4096)?;
    let token = std::str::from_utf8(&bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("fresh-bootstrap token has an invalid format");
    }
    Ok(token)
}

/// Delete token + context durably. Missing files are tolerated so rollback
/// paths and claim paths can both call it unconditionally.
pub(crate) fn delete_material(scope_dir: &Path) -> anyhow::Result<()> {
    for name in [TOKEN_FILE_NAME, CONTEXT_FILE_NAME] {
        let path = scope_dir.join(name);
        match filesystem::remove_file_durable(&path) {
            Ok(()) => {}
            Err(error) if !path.exists() => {
                let _ = error; // already gone — closure is idempotent
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to delete fresh-bootstrap material {}",
                        path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

/// The G02 gate: authorize one bootstrap request against the compiled
/// allowlist, the open capability, and the live fresh-install facts.
///
/// Every mismatch collapses into [`BOOTSTRAP_CLOSED`] — diagnostics stay
/// bounded and never distinguish "closed" from "tampered" to callers.
pub(crate) fn authorize_claim(
    context: Option<&FreshBootstrapContext>,
    request_operation: &str,
    state: &DeploymentState,
) -> Result<(), Failure> {
    if !FRESH_BOOTSTRAP_ALLOWLIST.contains(&request_operation) {
        return Err(Failure::new(
            BOOTSTRAP_CLOSED,
            format!(
                "'{}' is not in the fresh-install bootstrap allowlist",
                sanitize(request_operation.to_owned())
            ),
        ));
    }
    let Some(context) = context else {
        return Err(Failure::new(
            BOOTSTRAP_CLOSED,
            "no open fresh-install bootstrap capability exists for this deployment",
        ));
    };
    // Bound to the fresh-install journal: the state must still be owned by
    // the exact install operation that provisioned the capability.
    let owns_state = state
        .active_host_operation
        .as_ref()
        .is_some_and(|active| active.operation_id == context.install_operation_id);
    if !owns_state {
        return Err(Failure::new(
            BOOTSTRAP_CLOSED,
            "the deployment state is no longer owned by the install operation bound to this \
             bootstrap capability",
        ));
    }
    // Exact artifact/config: any drift between provisioning and claim rejects.
    let digest_matches = state.artifact.current.as_deref().is_some_and(|reference| {
        reference.trim_start_matches("sha256:") == context.artifact_subject_sha256
    });
    if !digest_matches {
        return Err(Failure::new(
            BOOTSTRAP_CLOSED,
            "the deployed artifact differs from the one bound to this bootstrap capability",
        ));
    }
    if state.config.revision != context.config_revision {
        return Err(Failure::new(
            BOOTSTRAP_CLOSED,
            "the configuration changed after install; this bootstrap capability is closed",
        ));
    }
    Ok(())
}
