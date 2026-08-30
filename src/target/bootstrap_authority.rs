//! Fresh-install bootstrap authority (goal plan 07, task G02).
//!
//! A fresh NazoAuth cannot enroll an administrator before it runs, and its
//! very first administrator cannot exist before initialization. NazoAuth
//! itself owns that capability: at startup it generates the one-time token at
//! `DATA_DIR/bootstrap/initial-admin-token` and validates every claim against
//! it. This module is the control-side half — and nothing more:
//!
//! 1. This path authorizes exactly one operation: creating the initial
//!    administrator. It is a dedicated API, not a configurable capability set.
//! 2. There is exactly ONE bootstrap token authority: the server. Ctl never
//!    mints, stores, or mounts a second token; it only records the
//!    install-binding context ([`FreshBootstrapContext`], including the data
//!    root where the server publishes its token) and later reads the
//!    server-generated token back through the target's inspect surface.
//! 3. The capability is bound to the fresh-install journal: authorization
//!    requires that the live DeploymentState was produced by the exact install
//!    operation id recorded in the context, carries the exact verified
//!    artifact digest and the untouched config revision recorded then. Any
//!    drift (tampered artifact/config, later operation) rejects.
//! 4. Closure deletes the server token and context durably. Because
//!    `bootstrap` state mutations fail closed over existing state
//!    (`DEPLOYMENT_EXISTS`), a deleted capability can never be regenerated:
//!    there is no permanent unsigned operator and no `--force-bootstrap`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::filesystem;

use super::{
    deployment_state::{DeploymentState, Failure},
    install_exec::InstallJob,
};

/// Stable rejection: any bootstrap attempt without an open, journal-bound,
/// untampered fresh-install capability. Covers closed, consumed, absent, and
/// drifted capabilities alike — absence of capability is itself the closure.
pub const BOOTSTRAP_CLOSED: &str = "BOOTSTRAP_CLOSED";

/// Schema discriminator for the persisted context document.
pub const FRESH_BOOTSTRAP_SCHEMA: u32 = 3;

/// Context file name inside the deployment scope directory.
pub const CONTEXT_FILE_NAME: &str = "fresh-bootstrap.json";

/// Server-owned token location relative to the deployment data root
/// (`DATA_DIR` inside the runtime). NazoAuth generates this file; ctl only
/// reads it while the fresh-install capability is open and removes it after
/// the server's successful claim receipt has been confirmed.
pub const SERVER_TOKEN_RELATIVE_PATH: &str = "bootstrap/initial-admin-token";

/// Durable record binding the bootstrap capability to one exact fresh install.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshBootstrapContext {
    pub schema: u32,
    /// The install operation whose journal produced the deployment.
    pub install_operation_id: String,
    pub artifact_subject_sha256: String,
    /// Config revision at install commit (fresh installs commit revision 1);
    /// claims after any config change reject.
    pub config_revision: u64,
    /// Host-side data root backing the runtime's `DATA_DIR`; the deployment
    /// fact that locates the server-generated bootstrap token.
    pub data_root: String,
}

impl FreshBootstrapContext {
    fn validate(&self) -> anyhow::Result<()> {
        if self.schema != FRESH_BOOTSTRAP_SCHEMA {
            bail!("unsupported fresh-bootstrap context schema {}", self.schema);
        }
        Ok(())
    }
}

/// Provision the fresh-install capability record for a clean install. Called
/// by the install executor before the runtime starts. No token exists here:
/// the running NazoAuth creates the single authoritative token inside the
/// mounted data root when it initializes its bootstrap endpoint.
pub(crate) fn provision(
    scope_dir: &Path,
    job: &InstallJob<'_>,
    subject_digest: &str,
) -> anyhow::Result<()> {
    if load_context(scope_dir)?.is_some() {
        bail!("a fresh-bootstrap capability already exists; refusing to re-provision");
    }
    let context = FreshBootstrapContext {
        schema: FRESH_BOOTSTRAP_SCHEMA,
        install_operation_id: job.operation_id.to_owned(),
        artifact_subject_sha256: subject_digest.to_owned(),
        config_revision: 1,
        data_root: job.order.data_root.clone(),
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

fn server_token_path(context: &FreshBootstrapContext) -> PathBuf {
    Path::new(&context.data_root).join(SERVER_TOKEN_RELATIVE_PATH)
}

/// Same shape NazoAuth enforces for its generated tokens (48 random bytes,
/// unpadded base64url).
fn valid_initial_admin_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Read the SERVER-generated one-time token from the deployment's data root.
/// Ctl never writes or regenerates it.
pub(crate) fn read_server_token(
    context: &FreshBootstrapContext,
    state: &DeploymentState,
) -> anyhow::Result<String> {
    let path = server_token_path(context);
    let bytes = super::read_runtime_owned_file(
        &path,
        "initial administrator bootstrap token",
        true,
        4096,
        state,
    )?;
    let token = std::str::from_utf8(&bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?
        .trim()
        .to_owned();
    if !valid_initial_admin_token(&token) {
        bail!(
            "the server-generated bootstrap token at {} has an unexpected format",
            path.display()
        );
    }
    Ok(token)
}

/// Delete the server token and capability context durably. The context is
/// loaded first so its data root remains the sole source for the token path.
/// Missing files are tolerated so rollback paths and claim paths can both call
/// this unconditionally. The token is removed before the context, and a token
/// deletion failure leaves the context available for a later close attempt.
pub(crate) fn delete_material(scope_dir: &Path) -> anyhow::Result<()> {
    let Some(context) = load_context(scope_dir)? else {
        return Ok(());
    };
    let token_path = server_token_path(&context);
    filesystem::remove_file_durable(&token_path).with_context(|| {
        format!(
            "failed to delete server bootstrap token {}",
            token_path.display()
        )
    })?;
    let context_path = scope_dir.join(CONTEXT_FILE_NAME);
    filesystem::remove_file_durable(&context_path).with_context(|| {
        format!(
            "failed to delete fresh-bootstrap context {}",
            context_path.display()
        )
    })?;
    Ok(())
}

/// Read-only view of an OPEN fresh-install bootstrap capability, surfaced
/// through `state-inspect` only while the capability is genuinely claimable
/// (goal plan 07 G-A decision: the frozen stdio contract is the only channel;
/// there is no ad-hoc token read). The token rides the SSH-encrypted
/// transport exactly once per inspection and never appears in any other wire
/// message.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshBootstrapMaterialView {
    pub install_operation_id: String,
    pub token: String,
}

impl std::fmt::Debug for FreshBootstrapMaterialView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreshBootstrapMaterialView")
            .field("install_operation_id", &self.install_operation_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Build the view for one deployment's scope directory, or `None` whenever
/// the capability is absent, closed, drifted, or otherwise unauthorized.
/// Absence and closure are deliberately indistinguishable from refusal.
pub(crate) fn surface_material_view(
    scope_dir: &Path,
    state: &DeploymentState,
) -> Option<FreshBootstrapMaterialView> {
    let context = load_context(scope_dir).ok()??;
    authorize_initial_admin_claim(Some(&context), state).ok()?;
    let token = read_server_token(&context, state).ok()?;
    Some(FreshBootstrapMaterialView {
        install_operation_id: context.install_operation_id,
        token,
    })
}

/// The G02 gate: authorize the initial-administrator request against the open
/// capability and the live fresh-install facts.
///
/// Every mismatch collapses into [`BOOTSTRAP_CLOSED`] — diagnostics stay
/// bounded and never distinguish "closed" from "tampered" to callers.
pub(crate) fn authorize_initial_admin_claim(
    context: Option<&FreshBootstrapContext>,
    state: &DeploymentState,
) -> Result<(), Failure> {
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
