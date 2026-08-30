//! Controller identity lifecycle flows (goal plan 04, tasks D04, D06, D07,
//! D08) plus their CLI entry point.
//!
//! Every flow follows the same shape demanded by the goal plan:
//!
//! ```text
//! resolve instance → authoritative server snapshot (list_slots)
//!   → crash reconciliation (D06: adopt a committed candidate; retire
//!      material the server no longer lists)
//!   → build proposal payload (public key/kid/deployment binding only)
//!   → obtain a single-use approval token (the server enforces fresh MFA;
//!      ctl establishes the standard admin session and completes MFA, or
//!      accepts an explicitly supplied token)
//!   → atomic server commit (approval consumption + registry mutation share
//!      one transaction on the NazoAuth side)
//!   → local activation (pointer switch / registry fields), ordered so the
//!      SERVER is always the authority and every local step is recoverable by
//!      re-running reconciliation from `list_slots`
//! ```
//!
//! Crash windows and their recovery:
//!
//! * killed before the commit — no server change; re-running resumes with the
//!   same local candidate (D04.6: no second keypair is minted);
//! * killed after the commit but before any local update — the next bind /
//!   rotate / add / slots command reconciles: the committed kid is found among
//!   the stored candidates, activated, and superseded keys retired (D06.5,
//!   D07.3);
//! * self-revocation clears the local active pointer only after the server
//!   confirmed the terminal state, so no dangling pointer can brick loads.
//!
//! Approval tokens are secrets: they stay inside the injected approval
//! callback and are never logged, echoed, or persisted.

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::admin_credentials::{AdminCredentialsInput, read_admin_credentials};
use crate::cli::{BindOptions, ControllerCommand, InstanceSelector};
use crate::file_lock::FileLock;
use crate::filesystem;
use crate::registry::{InstanceRecord, RegistryStore, validate_issuer};

use super::admin_api::{
    self, AdminAccess, ApprovalRequestBody, ControllerRegistryApi, ControllerSlotView,
    HttpAdminSessionApi, IssuedApproval, RevokeCommitBody, RotateCommitBody, SlotCommitBody,
    SlotStatus, SlotsSnapshot, short_kid,
};
use super::expiry;
use super::recovery::{self as recovery, generate_material, material_from_display};
use super::store::{ControllerKeyStore, controller_key_ref_for};

const PENDING_BIND_RECOVERY_SCHEMA: u32 = 1;
const PENDING_BIND_RECOVERY_FILE: &str = "bind-recovery-pending.json";
const MAX_PENDING_BIND_RECOVERY_BYTES: u64 = 4 * 1024;

/// The only temporarily persisted Recovery Secret: the one already delivered
/// for a first-bind proposal whose server commit has not yet completed. It is
/// scoped to the controller-key directory, never copied into Registry or the
/// ordinary operation journal, and is erased as soon as reconciliation proves
/// the bind terminal.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBindRecovery {
    schema: u32,
    deployment_id: String,
    controller_kid: String,
    label: String,
    recovery_secret: String,
}

impl Drop for PendingBindRecovery {
    fn drop(&mut self) {
        self.recovery_secret.zeroize();
    }
}

fn pending_bind_recovery_path(
    keys: &ControllerKeyStore,
    deployment_id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    Ok(keys
        .instance_dir(deployment_id)?
        .join(PENDING_BIND_RECOVERY_FILE))
}

fn load_pending_bind_recovery(
    keys: &ControllerKeyStore,
    deployment_id: &str,
) -> anyhow::Result<Option<PendingBindRecovery>> {
    let path = pending_bind_recovery_path(keys, deployment_id)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let bytes = filesystem::read_secure_regular_file(
        &path,
        "pending first-bind recovery material",
        true,
        MAX_PENDING_BIND_RECOVERY_BYTES,
    )?;
    let pending: PendingBindRecovery = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "pending first-bind recovery material is invalid: {}",
            path.display()
        )
    })?;
    if pending.schema != PENDING_BIND_RECOVERY_SCHEMA
        || pending.deployment_id != deployment_id
        || pending.controller_kid.is_empty()
        || pending.label.is_empty()
    {
        bail!("pending first-bind recovery material does not match deployment '{deployment_id}'");
    }
    Ok(Some(pending))
}

fn save_pending_bind_recovery(
    keys: &ControllerKeyStore,
    pending: &PendingBindRecovery,
) -> anyhow::Result<()> {
    let path = pending_bind_recovery_path(keys, &pending.deployment_id)?;
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(pending).context("serializing pending first-bind recovery material")?,
    );
    filesystem::atomic_write(&path, &bytes, 0o600).with_context(|| {
        format!(
            "failed to persist exact first-bind recovery material at {}",
            path.display()
        )
    })
}

fn clear_pending_bind_recovery(
    keys: &ControllerKeyStore,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let path = pending_bind_recovery_path(keys, deployment_id)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => filesystem::remove_file_durable(&path)
            .with_context(|| format!("failed to erase {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

/// Exact public proposal facts used for display and approval issuance.
#[derive(Clone, Debug)]
pub struct ProposalPresentation {
    pub action: &'static str,
    pub alias: String,
    pub deployment_id: String,
    pub issuer: String,
    pub label: String,
    /// Present for rotate/revoke, absent for bind/add.
    pub controller_id: Option<String>,
    pub kid: String,
    pub public_key_b64: String,
    /// P0-3 atomic first binding: present ONLY for bind, so approval and
    /// commit cover the same recovery material.
    pub recovery_kid: Option<String>,
    pub recovery_public_key_b64: Option<String>,
}

impl ProposalPresentation {
    pub fn render(&self) -> String {
        let mut text = format!(
            "Controller identity change requires fresh administrator 2FA.\n\
             \x20 deployment: {dep}\n\
             \x20 issuer:     {issuer}\n\
             \x20 action:     {action}\n\
             \x20 label:      {label}\n",
            dep = self.deployment_id,
            issuer = self.issuer,
            action = self.action,
            label = self.label,
        );
        if let Some(controller_id) = &self.controller_id {
            text.push_str(&format!("  controller: {controller_id}\n"));
        }
        text.push_str(&format!(
            "  new kid:    {}\n  public key: {}…\n",
            short_kid(&self.kid),
            &self.public_key_b64[..self.public_key_b64.len().min(16)]
        ));
        if let (Some(recovery_kid), Some(recovery_public_key)) =
            (&self.recovery_kid, &self.recovery_public_key_b64)
        {
            text.push_str(&format!(
                "  recovery kid: {}\n  recovery public key: {}…\n",
                short_kid(recovery_kid),
                &recovery_public_key[..recovery_public_key.len().min(16)]
            ));
        }
        text.push_str(
            "\nApproval must cover this exact payload and a fresh administrator 2FA ceremony \
             within 10 minutes; the key expires 30 days after enrollment.\n",
        );
        text
    }
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn resolve_record(
    registry: &RegistryStore,
    selector: Option<&str>,
) -> anyhow::Result<InstanceRecord> {
    let instances = registry.list_instances()?;
    if let Some(selector) = selector {
        return instances
            .iter()
            .find(|record| record.alias == selector || record.deployment_id == selector)
            .cloned()
            .with_context(|| {
                format!(
                    "{}: no registered instance matches '{selector}' exactly",
                    crate::error_codes::INSTANCE_NOT_REGISTERED
                )
            });
    }
    match instances.as_slice() {
        [] => bail!("no instances are registered yet"),
        [single] => Ok(single.clone()),
        many => {
            let candidates = many
                .iter()
                .map(|record| record.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{}: multiple instances are registered ({candidates}); \
                 pass --instance SELECTOR",
                crate::error_codes::INSTANCE_AMBIGUOUS
            )
        }
    }
}

fn load_public_key(
    keys: &ControllerKeyStore,
    deployment_id: &str,
    kid: &str,
) -> anyhow::Result<String> {
    keys.list_keys(deployment_id)?
        .into_iter()
        .find(|summary| summary.kid == kid)
        .map(|summary| summary.public_key)
        .with_context(|| format!("kid '{kid}' vanished from the local store"))
}

/// Pick a pending local candidate for a NEW proposal: newest non-active key
/// that the server does not list at all. Material already known to the server
/// is never re-proposed — committed candidates belong to reconciliation, and
/// other controllers' keys stay untouched.
fn select_pending_candidate(
    keys: &ControllerKeyStore,
    deployment_id: &str,
    snapshot: &SlotsSnapshot,
) -> anyhow::Result<Option<String>> {
    Ok(keys
        .list_keys(deployment_id)?
        .into_iter()
        .filter(|summary| !summary.active)
        .filter(|summary| !snapshot.items.iter().any(|slot| slot.kid == summary.kid))
        .max_by_key(|summary| summary.created_at)
        .map(|summary| summary.kid))
}

/// Adopt a committed-but-not-yet-activated identity after a crash, and retire
/// local candidates the server no longer lists. Returns the recovery report,
/// or `None` when the local state is already fully consistent with the
/// authoritative snapshot.
fn reconcile_from_snapshot(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    record: &InstanceRecord,
    snapshot: &SlotsSnapshot,
) -> anyhow::Result<Option<String>> {
    let deployment = record.deployment_id.as_str();
    let local_kids: Vec<String> = keys
        .list_keys(deployment)?
        .into_iter()
        .map(|summary| summary.kid)
        .collect();

    // A committed candidate waiting for local activation?
    if let Some(slot) = snapshot
        .active_slots()
        .into_iter()
        .find(|slot| local_kids.iter().any(|kid| kid == &slot.kid))
    {
        let previous_active = keys.load_active(deployment)?;
        let needs_pointer = previous_active
            .as_ref()
            .map(|loaded| loaded.kid() != slot.kid)
            .unwrap_or(true);
        let needs_fields = record.controller_id.as_deref() != Some(slot.controller_id.as_str())
            || record.controller_key_ref.is_none();

        // Switch the pointer BEFORE retiring anything: retirement refuses the
        // active kid, so this ordering keeps every intermediate state
        // loadable and never orphans the pointer.
        if needs_fields {
            persist_binding_fields(registry, deployment, Some(&slot.controller_id))?;
        }
        if needs_pointer {
            keys.set_active_kid(deployment, &slot.kid)?;
        }

        // Retire local candidates the server neither lists in any state nor
        // keeps active (superseded rotate material, abandoned proposals).
        let listed_kids: Vec<&str> = snapshot
            .items
            .iter()
            .map(|item| item.kid.as_str())
            .collect();
        let mut retired = Vec::new();
        for kid in local_kids
            .iter()
            .filter(|kid| !listed_kids.contains(&kid.as_str()))
        {
            if kid == &slot.kid {
                continue;
            }
            if keys.retire_kid(deployment, kid).is_ok() {
                retired.push(kid.clone());
            } else {
                eprintln!(
                    "nazauthctl: warning: superseded local controller key {kid} could not be \
                     retired"
                );
            }
        }

        // Fully consistent? Then there is nothing to recover.
        if !needs_pointer && !needs_fields && retired.is_empty() {
            return Ok(None);
        }

        let mut report = format!(
            "recovered controller binding for '{}' from the authoritative server list\n  \
             controller {} kid {} activated locally\n",
            record.alias,
            slot.controller_id,
            short_kid(&slot.kid)
        );
        if !retired.is_empty() {
            report.push_str(&format!(
                "  superseded local keys retired: {}\n",
                retired.join(", ")
            ));
        }
        return Ok(Some(report));
    }

    // Our recorded controller identity has no active slot anymore (revoked
    // elsewhere): drop the local pointer to it instead of pretending it is
    // still valid. By construction no local kid matches any active slot here.
    if let Some(controller_id) = record.controller_id.as_deref() {
        let still_listed = snapshot
            .items
            .iter()
            .any(|slot| slot.controller_id == controller_id && slot.status == SlotStatus::Active);
        if !still_listed {
            persist_binding_fields(registry, deployment, None)?;
            keys.clear_active(deployment)?;
            return Ok(Some(format!(
                "controller identity {controller_id} of '{}' is no longer active at the \
                 server; the local binding was cleared. Enroll again with `nazoauthctl bind` \
                 once the cause is resolved\n",
                record.alias
            )));
        }
    }
    Ok(None)
}

fn persist_binding_fields(
    registry: &RegistryStore,
    deployment_id: &str,
    controller_id: Option<&str>,
) -> anyhow::Result<()> {
    registry.update_controller_binding(
        deployment_id,
        controller_id,
        Some(controller_key_ref_for(deployment_id)?.as_str()),
    )?;
    Ok(())
}

fn require_bound(record: &InstanceRecord) -> anyhow::Result<String> {
    record.controller_id.clone().with_context(|| {
        format!(
            "instance '{}' has no bound controller identity; run `nazoauthctl bind` first",
            record.alias
        )
    })
}

fn validate_label(label: &str) -> anyhow::Result<()> {
    if label.is_empty() || label.len() > 128 {
        bail!("--label must be 1-128 characters");
    }
    if label.chars().any(char::is_control) {
        bail!("--label must not contain control characters");
    }
    Ok(())
}

fn verify_committed_slot(
    slot: &ControllerSlotView,
    deployment_id: &str,
    kid: &str,
    action: &'static str,
) -> anyhow::Result<()> {
    if slot.deployment_id != deployment_id || slot.kid != kid || slot.status != SlotStatus::Active {
        bail!(
            "{action} commit returned an unexpected slot ({} / {} / {:?}); refusing to activate \
             locally",
            slot.deployment_id,
            short_kid(&slot.kid),
            slot.status
        );
    }
    Ok(())
}

/// Shared post-commit tail: persist the registry fields, switch the active
/// pointer, and render the live commit response. Server state stays the
/// authority throughout; both local steps are recoverable via
/// [`reconcile_from_snapshot`] on any later command.
fn finish_activation(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    alias: &str,
    deployment: &str,
    kid: &str,
    committed_slot: ControllerSlotView,
) -> anyhow::Result<String> {
    persist_binding_fields(registry, deployment, Some(&committed_slot.controller_id))?;
    keys.set_active_kid(deployment, kid)?;
    let status = expiry::ExpiryStatus::classify(chrono::Utc::now(), committed_slot.expires_at);
    Ok(format!(
        "controller identity committed for '{alias}' (deployment {deployment})\n  controller \
         {} kid {} slot {}\n  expiry: {}\n",
        committed_slot.controller_id,
        short_kid(kid),
        committed_slot.slot_index,
        status.render(),
    ))
}

// ---------------------------------------------------------------------------
// D04 + D06: bind
// ---------------------------------------------------------------------------

/// First bind: propose the newest unused local candidate (or mint exactly one
/// new keypair), obtain the single-use approval, and commit atomically.
/// P0-3: the SAME transaction enrolls a freshly generated Recovery Root, and
/// its secret is delivered to the operator BEFORE the commit — a first
/// binding can never exist without a recoverable root.
pub(crate) fn bind_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
    label: &str,
    approval: impl FnOnce(&ProposalPresentation) -> anyhow::Result<String>,
    delivery: &dyn recovery::ReplacementSecretDelivery,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    validate_label(label)?;
    let deployment = record.deployment_id.clone();
    let instance_dir = keys.instance_dir(&deployment)?;
    filesystem::ensure_private_directory(&instance_dir, "controller key directory")?;
    let _bind_lock = FileLock::acquire(&instance_dir.join("bind.lock"))?;
    let snapshot = api.list_slots(&deployment)?;

    // D06: a previous run may have committed server-side already.
    if let Some(report) = reconcile_from_snapshot(registry, keys, &record, &snapshot)? {
        clear_pending_bind_recovery(keys, &deployment)?;
        return Ok(format!("bind complete via crash recovery.\n{report}"));
    }

    if !snapshot.active_slots().is_empty() || record.controller_id.is_some() {
        bail!(
            "instance '{}' already has an active controller identity; use `controller rotate` \
             (same controller) or `controller add` (additional slot up to three)",
            record.alias
        );
    }

    // D04.6: resume the exact still-pending proposal. The controller key and
    // Recovery Root are one approval/commit unit; neither may change after a
    // secret has been delivered.
    let pending_recovery = load_pending_bind_recovery(keys, &deployment)?;
    let kid = match pending_recovery.as_ref() {
        Some(pending) => {
            if pending.label != label {
                bail!(
                    "a first-bind proposal for label '{}' is already pending; retry that exact label",
                    pending.label
                );
            }
            if snapshot
                .items
                .iter()
                .any(|slot| slot.kid == pending.controller_kid)
            {
                bail!(
                    "pending first-bind controller key is already present server-side but was not reconcilable"
                );
            }
            pending.controller_kid.clone()
        }
        None => match select_pending_candidate(keys, &deployment, &snapshot)? {
            Some(pending) => pending,
            None => keys.generate_candidate(&deployment)?.kid,
        },
    };
    let public_key = load_public_key(keys, &deployment, &kid)?;

    let recovery_material = match pending_recovery {
        Some(pending) => material_from_display(&deployment, &pending.recovery_secret)?,
        None => {
            let material = generate_material(&deployment);
            save_pending_bind_recovery(
                keys,
                &PendingBindRecovery {
                    schema: PENDING_BIND_RECOVERY_SCHEMA,
                    deployment_id: deployment.clone(),
                    controller_kid: kid.clone(),
                    label: label.to_owned(),
                    recovery_secret: material.display.clone(),
                },
            )?;
            material
        }
    };

    let presentation = ProposalPresentation {
        action: "bind",
        alias: record.alias.clone(),
        deployment_id: deployment.clone(),
        issuer: record.issuer.clone(),
        label: label.to_owned(),
        controller_id: None,
        kid: kid.clone(),
        public_key_b64: public_key.clone(),
        recovery_kid: Some(recovery_material.kid.clone()),
        recovery_public_key_b64: Some(b64url(&recovery_material.public_key)),
    };
    let token = approval(&presentation)?;

    delivery.deliver(&recovery_material.display).context(
        "replacement secret delivery was not acknowledged; NOTHING was committed — the \
             pending proposal can be resumed after fixing delivery",
    )?;

    let slot = api.commit_slot(&SlotCommitBody {
        approval_token: token,
        action: "bind",
        deployment_id: deployment.clone(),
        label: label.to_owned(),
        public_key,
        kid: kid.clone(),
        recovery_public_key: Some(b64url(&recovery_material.public_key)),
        recovery_kid: Some(recovery_material.kid.clone()),
    })?;
    verify_committed_slot(&slot, &deployment, &kid, "bind")?;

    let report = finish_activation(registry, keys, &record.alias, &deployment, &kid, slot)?;
    clear_pending_bind_recovery(keys, &deployment)?;
    Ok(report)
}

fn b64url(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// D07: rotate
// ---------------------------------------------------------------------------

pub fn rotate_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
    label: Option<&str>,
    approval: impl FnOnce(&ProposalPresentation) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    let deployment = record.deployment_id.clone();
    let controller_id = require_bound(&record)?;
    let snapshot = api.list_slots(&deployment)?;

    // D07.3: an interrupted rotation finishes through reconciliation first —
    // never by proposing yet another key.
    if let Some(report) = reconcile_from_snapshot(registry, keys, &record, &snapshot)? {
        return Ok(format!("rotation completed via crash recovery.\n{report}"));
    }

    // Expired keys may still start rotation (goal plan 04 §7 rule 3); the
    // only hard requirement is knowing WHICH controller id rotates.
    let ours = snapshot
        .items
        .iter()
        .find(|slot| slot.controller_id == controller_id)
        .with_context(|| {
            format!(
                "controller {controller_id} has no slot at '{}'; use `controller revoke`/`add` \
                 instead",
                record.issuer
            )
        })?
        .clone();
    let label = match label {
        Some(label) => {
            validate_label(label)?;
            label.to_owned()
        }
        None => ours.label.clone(),
    };

    let kid = match select_pending_candidate(keys, &deployment, &snapshot)? {
        Some(pending) => pending,
        None => keys.generate_candidate(&deployment)?.kid,
    };
    let public_key = load_public_key(keys, &deployment, &kid)?;

    let presentation = ProposalPresentation {
        action: "rotate",
        alias: record.alias.clone(),
        deployment_id: deployment.clone(),
        issuer: record.issuer.clone(),
        label: label.clone(),
        controller_id: Some(controller_id.clone()),
        kid: kid.clone(),
        public_key_b64: public_key.clone(),
        recovery_kid: None,
        recovery_public_key_b64: None,
    };
    let token = approval(&presentation)?;

    let slot = api.rotate_slot(&RotateCommitBody {
        approval_token: token,
        deployment_id: deployment.clone(),
        controller_id: controller_id.clone(),
        label,
        public_key,
        kid: kid.clone(),
    })?;
    verify_committed_slot(&slot, &deployment, &kid, "rotate")?;
    if slot.controller_id != controller_id {
        bail!(
            "rotate returned controller {} instead of {controller_id}; refusing to activate \
             locally",
            slot.controller_id
        );
    }

    let previous = keys
        .load_active(&deployment)?
        .map(|loaded| loaded.kid().to_owned());
    let report = finish_activation(registry, keys, &record.alias, &deployment, &kid, slot)?;

    // Retire the old private key only after the confirmed atomic replace
    // (the server row now carries the new kid exclusively).
    if let Some(previous) = previous.filter(|previous| previous.as_str() != kid)
        && let Err(error) = keys.retire_kid(&deployment, &previous)
    {
        eprintln!(
            "nazauthctl: warning: old controller key {previous} could not be unlinked \
             locally: {error:#}; the next reconciliation retires it"
        );
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// D08: add / revoke
// ---------------------------------------------------------------------------

pub fn add_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
    label: &str,
    approval: impl FnOnce(&ProposalPresentation) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    validate_label(label)?;
    require_bound(&record)?;
    let deployment = record.deployment_id.clone();
    let snapshot = api.list_slots(&deployment)?;

    if let Some(report) = reconcile_from_snapshot(registry, keys, &record, &snapshot)? {
        return Ok(format!("identity recovered before adding.\n{report}"));
    }

    // Max-3 awareness (D08): refuse BEFORE burning a single-use approval when
    // the server already reports a full board; the transaction-level limit
    // stays server-enforced.
    let max = snapshot.max_active_slots;
    let active = snapshot.active_slots().len();
    if active >= max as usize {
        let mut message = format!(
            "{}: '{}' already has {active} of {max} active controller slots; \
             revoke one before adding:",
            crate::error_codes::CONTROLLER_SLOT_LIMIT,
            record.alias
        );
        for slot in snapshot.active_slots() {
            message.push_str(&format!(
                "\n  - controller {} label '{}' kid {} expires {}",
                slot.controller_id,
                slot.label,
                short_kid(&slot.kid),
                slot.expires_at.to_rfc3339()
            ));
        }
        bail!("{message}");
    }

    let kid = match select_pending_candidate(keys, &deployment, &snapshot)? {
        Some(pending) => pending,
        None => keys.generate_candidate(&deployment)?.kid,
    };
    let public_key = load_public_key(keys, &deployment, &kid)?;

    let presentation = ProposalPresentation {
        action: "add",
        alias: record.alias.clone(),
        deployment_id: deployment.clone(),
        issuer: record.issuer.clone(),
        label: label.to_owned(),
        controller_id: None,
        kid: kid.clone(),
        public_key_b64: public_key.clone(),
        recovery_kid: None,
        recovery_public_key_b64: None,
    };
    let token = approval(&presentation)?;

    let slot = api.commit_slot(&SlotCommitBody {
        approval_token: token,
        action: "add",
        deployment_id: deployment.clone(),
        label: label.to_owned(),
        public_key,
        kid: kid.clone(),
        recovery_public_key: None,
        recovery_kid: None,
    })?;
    verify_committed_slot(&slot, &deployment, &kid, "add")?;

    // This ctl adopts its NEW slot as the identity it signs with; the
    // previous key stays enrolled until its own expiry or explicit revocation.
    let report = finish_activation(registry, keys, &record.alias, &deployment, &kid, slot)?;
    Ok(format!(
        "{report}note: the previous controller key remains enrolled and valid until its own \
         expiry or explicit revocation\n"
    ))
}

pub fn revoke_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
    controller_id: &str,
    approval: impl FnOnce(&ProposalPresentation) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    let deployment = record.deployment_id.clone();
    let snapshot = api.list_slots(&deployment)?;

    let target = snapshot
        .items
        .iter()
        .find(|slot| slot.controller_id == controller_id)
        .with_context(|| {
            format!(
                "controller id '{controller_id}' has no slot for deployment '{deployment}'; \
                 revocation requires the exact id (`nazoauthctl controller list --instance {}` \
                 lists them)",
                record.alias
            )
        })?
        .clone();
    if target.status == SlotStatus::Revoked {
        bail!("controller {controller_id} is already revoked at the server; nothing to do");
    }

    let self_revoked = record.controller_id.as_deref() == Some(controller_id);
    if self_revoked {
        eprintln!(
            "nazauthctl: warning: you are revoking THIS control machine's own controller \
             identity; application-level mutations will stop working afterwards until a new \
             key is enrolled"
        );
    }

    let presentation = ProposalPresentation {
        action: "revoke",
        alias: record.alias.clone(),
        deployment_id: deployment.clone(),
        issuer: record.issuer.clone(),
        label: target.label.clone(),
        controller_id: Some(target.controller_id.clone()),
        kid: target.kid.clone(),
        public_key_b64: String::new(),
        recovery_kid: None,
        recovery_public_key_b64: None,
    };
    let token = approval(&presentation)?;

    let revoked = api.revoke_slot(&RevokeCommitBody {
        approval_token: token,
        deployment_id: deployment.clone(),
        controller_id: target.controller_id.clone(),
    })?;
    if revoked.status != SlotStatus::Revoked {
        bail!(
            "revoke returned non-terminal status {:?}; refusing local cleanup",
            revoked.status
        );
    }

    // Local cleanup strictly AFTER server confirmation (D08.5).
    let mut report = format!(
        "revoked controller {} (label '{}', kid {}) at deployment {}\n",
        revoked.controller_id,
        revoked.label,
        short_kid(&revoked.kid),
        deployment
    );

    if self_revoked {
        persist_binding_fields(registry, &deployment, None)?;
        keys.clear_active(&deployment)?;
        report.push_str(
            "this machine's active pointer was cleared; remaining local key records stay on \
             disk for diagnostics\n",
        );
    } else if keys
        .list_keys(&deployment)?
        .iter()
        .any(|summary| summary.kid == revoked.kid)
    {
        // Material for a REMOTE controller must not exist here under normal
        // operation; if it does, retire it now that the server confirmed.
        keys.retire_kid(&deployment, &revoked.kid)?;
        report.push_str("matching stale local key record retired\n");
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// D09: slots view (status surface)
// ---------------------------------------------------------------------------

pub fn slots_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    let deployment = record.deployment_id.clone();
    let snapshot = api.list_slots(&deployment)?;

    // Opportunistic crash reconciliation keeps status honest about pending
    // activations before rendering.
    let recovery = reconcile_from_snapshot(registry, keys, &record, &snapshot)?;

    let now = chrono::Utc::now();
    let mut report = String::new();
    if let Some(line) = recovery {
        report.push_str(line.trim_end());
        report.push('\n');
    }
    report.push_str(&format!(
        "controller slots for '{}' (deployment {}, issuer {}): {} item(s), max {}\n",
        record.alias, deployment, record.issuer, snapshot.total, snapshot.max_active_slots
    ));
    if snapshot.items.is_empty() {
        report.push_str("  none enrolled; run `nazoauthctl bind`\n");
    }
    for slot in &snapshot.items {
        for row in expiry::render_slot_line(slot, now).split('\n') {
            report.push_str("  ");
            report.push_str(row);
            report.push('\n');
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

const MAX_APPROVAL_TOKEN_CHARS: usize = 512;

fn token_length_ok(token: &str) -> bool {
    (16..=MAX_APPROVAL_TOKEN_CHARS).contains(&token.len())
}

fn obtain_approval_token(flag: Option<&str>, action: &str) -> anyhow::Result<String> {
    if let Some(flag) = flag {
        let trimmed = flag.trim();
        if !token_length_ok(trimmed) {
            bail!("--approval-token has an unexpected length");
        }
        return Ok(trimmed.to_owned());
    }
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        let prompt = format!("Paste the {action} approval token (input hidden): ");
        let token =
            rpassword::prompt_password(prompt).context("failed to read the approval token")?;
        let trimmed = token.trim().to_owned();
        if !token_length_ok(&trimmed) {
            bail!("the pasted approval token has an unexpected length");
        }
        Ok(trimmed)
    } else {
        eprintln!("Paste the {action} approval token on one line:");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read the approval token from stdin")?;
        let trimmed = line.trim().to_owned();
        if !token_length_ok(&trimmed) {
            bail!("the piped approval token has an unexpected length");
        }
        Ok(trimmed)
    }
}

fn make_public_api(issuer: &str) -> anyhow::Result<admin_api::HttpControllerRegistryApi> {
    validate_issuer(issuer).context("registered issuer is invalid")?;
    admin_api::HttpControllerRegistryApi::new(issuer, AdminAccess::default())
}

fn make_authenticated_api(
    issuer: &str,
    credentials_file: Option<&std::path::Path>,
) -> anyhow::Result<admin_api::HttpControllerRegistryApi> {
    use std::io::IsTerminal as _;

    validate_issuer(issuer).context("registered issuer is invalid")?;
    if !std::io::stdin().is_terminal() {
        bail!(
            "administrator MFA requires an interactive terminal; use --approval-token for non-interactive controller changes"
        );
    }
    let credentials = read_admin_credentials(
        credentials_file.map_or(
            AdminCredentialsInput::Interactive,
            AdminCredentialsInput::File,
        ),
        "controller approval",
    )?;
    let mut session = HttpAdminSessionApi::new(issuer)?;
    let login = session.login(&credentials.email, credentials.password.as_str())?;
    drop(credentials);

    if login.mfa_required {
        let code = prompt_mfa_code("Administrator MFA code: ")?;
        session.verify_mfa(&code)?;
    } else {
        let enrollment = session.begin_totp()?;
        print_totp_enrollment(&enrollment)?;
        let code = prompt_mfa_code("Enter the current code from your authenticator: ")?;
        let confirmation = session.confirm_totp(&code)?;
        eprintln!("MFA enabled. Store these one-time backup codes now:");
        for code in &confirmation.backup_codes {
            eprintln!("  {}", code.as_str());
        }
    }
    session.into_controller_registry_api()
}

fn prompt_mfa_code(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let code = zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).context("failed to read administrator MFA code")?,
    );
    let trimmed = code.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.chars().any(char::is_control) {
        bail!("administrator MFA code is invalid");
    }
    Ok(zeroize::Zeroizing::new(trimmed.to_owned()))
}

fn print_totp_enrollment(enrollment: &admin_api::TotpEnrollment) -> anyhow::Result<()> {
    let qr = qrcode::QrCode::new(enrollment.otpauth_uri.as_bytes())
        .context("failed to render the TOTP enrollment QR code")?;
    let rendered = qr
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    eprintln!("This administrator has no MFA yet. Scan this QR code:");
    eprintln!("{rendered}");
    eprintln!(
        "If scanning is unavailable, enter this secret manually: {}",
        enrollment.secret_base32.as_str()
    );
    Ok(())
}

fn approval_request(presentation: &ProposalPresentation) -> anyhow::Result<ApprovalRequestBody> {
    let common = || ApprovalRequestBody {
        action: presentation.action,
        deployment_id: presentation.deployment_id.clone(),
        controller_id: presentation.controller_id.clone(),
        label: Some(presentation.label.clone()),
        public_key: Some(presentation.public_key_b64.clone()),
        kid: Some(presentation.kid.clone()),
        recovery_public_key: None,
        recovery_kid: None,
    };
    Ok(match presentation.action {
        "bind" => ApprovalRequestBody {
            recovery_public_key: presentation.recovery_public_key_b64.clone(),
            recovery_kid: presentation.recovery_kid.clone(),
            ..common()
        },
        "add" | "rotate" => common(),
        "revoke" => ApprovalRequestBody {
            action: "revoke",
            deployment_id: presentation.deployment_id.clone(),
            controller_id: presentation.controller_id.clone(),
            label: None,
            public_key: None,
            kid: None,
            recovery_public_key: None,
            recovery_kid: None,
        },
        action => bail!("unsupported controller approval action '{action}'"),
    })
}

fn validate_issued_approval(issued: &IssuedApproval, expected_action: &str) -> anyhow::Result<()> {
    if issued.action != expected_action || !issued.single_use {
        bail!("the server returned an invalid fresh controller approval");
    }
    Ok(())
}

fn approval_callback<'a, A: ControllerRegistryApi>(
    api: &'a A,
    token: Option<&'a str>,
    issue_with_admin_access: bool,
) -> impl FnOnce(&ProposalPresentation) -> anyhow::Result<String> + 'a {
    move |presentation| {
        println!("{}", presentation.render());
        if token.is_some() || !issue_with_admin_access {
            return obtain_approval_token(token, presentation.action);
        }
        let issued = api.issue_approval(&approval_request(presentation)?)?;
        validate_issued_approval(&issued, presentation.action)?;
        Ok(issued.approval_token)
    }
}

/// Dispatch `nazauthctl controller …` commands (goal plan 09 §1). Runs
/// entirely against user-scoped stores; no root, no legacy lifecycle lock.
/// The global `--instance` channel is merged here under the I02 exactly-one
/// rule.
pub(crate) fn run_controller_command(
    command: ControllerCommand,
    global: Option<&str>,
) -> anyhow::Result<()> {
    let registry = RegistryStore::open_default()?;
    let keys = ControllerKeyStore::open_default()?;
    match command {
        ControllerCommand::List { selector } => {
            let explicit = merge_global(selector, global, "controller list")?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_public_api(&record.issuer)?;
            let report = slots_flow(&api, &registry, &keys, explicit.as_deref())?;
            println!("{report}");
        }
        ControllerCommand::Add {
            selector,
            label,
            approval_token,
            credentials_file,
        } => {
            let explicit = merge_global(selector, global, "controller add")?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let issue_approval = approval_token.is_none();
            let api = if issue_approval {
                make_authenticated_api(&record.issuer, credentials_file.as_deref())?
            } else {
                make_public_api(&record.issuer)?
            };
            let report = add_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                &label,
                approval_callback(&api, approval_token.as_deref(), issue_approval),
            )?;
            println!("{report}");
        }
        ControllerCommand::Rotate {
            selector,
            label,
            approval_token,
            credentials_file,
        } => {
            let explicit = merge_global(selector, global, "controller rotate")?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let issue_approval = approval_token.is_none();
            let api = if issue_approval {
                make_authenticated_api(&record.issuer, credentials_file.as_deref())?
            } else {
                make_public_api(&record.issuer)?
            };
            let report = rotate_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                label.as_deref(),
                approval_callback(&api, approval_token.as_deref(), issue_approval),
            )?;
            println!("{report}");
        }
        ControllerCommand::Revoke {
            selector,
            controller_id,
            approval_token,
            credentials_file,
        } => {
            let explicit = merge_global(selector, global, "controller revoke")?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let issue_approval = approval_token.is_none();
            let api = if issue_approval {
                make_authenticated_api(&record.issuer, credentials_file.as_deref())?
            } else {
                make_public_api(&record.issuer)?
            };
            let report = revoke_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                &controller_id,
                approval_callback(&api, approval_token.as_deref(), issue_approval),
            )?;
            println!("{report}");
        }
        ControllerCommand::Recover {
            selector,
            label,
            secret_file,
            rotate_secret,
            credentials_file,
            output_secret_file,
        } => {
            let explicit = merge_global(selector, global, "controller recover")?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = if rotate_secret {
                make_authenticated_api(&record.issuer, credentials_file.as_deref())?
            } else {
                make_public_api(&record.issuer)?
            };
            // P0-4 delivery channel: an explicit create-new owner-only file
            // for non-interactive runs; the terminal handshake everywhere
            // else. A missing channel fails closed instead of losing the
            // only copy of the replacement secret.
            let delivery: std::sync::Arc<dyn recovery::ReplacementSecretDelivery> =
                match output_secret_file.as_ref() {
                    Some(path) => std::sync::Arc::new(recovery::OutputFileSecretDelivery {
                        path: path.clone(),
                    }),
                    None => std::sync::Arc::new(recovery::InteractiveSecretDelivery),
                };
            if rotate_secret {
                // D10 first enrollment / D12 proactive rotation.
                let report = recovery::rotate_root_with_new_secret(
                    &api,
                    &record.deployment_id,
                    delivery.as_ref(),
                )?;
                println!("{report}");
            } else {
                let secret_text = read_recovery_secret(secret_file.as_deref())?;
                let recovered = recovery::recover_controller_identity(
                    &registry,
                    &keys,
                    &api,
                    explicit.as_deref(),
                    &secret_text,
                    &label,
                    delivery.as_ref(),
                )?;
                println!("{}", render_recovered(&record.alias, &recovered));
            }
        }
    }
    Ok(())
}

/// Top-level `nazoauthctl bind …` (goal plan 09 §6): the initial slot change
/// for one instance.
pub(crate) fn run_bind(options: BindOptions, global: Option<&str>) -> anyhow::Result<()> {
    let BindOptions {
        selector,
        label,
        approval_token,
        credentials_file,
        output_secret_file,
    } = options;
    let registry = RegistryStore::open_default()?;
    let keys = ControllerKeyStore::open_default()?;
    let explicit = merge_global(selector, global, "bind")?;
    let record = resolve_record(&registry, explicit.as_deref())?;
    let issue_approval = approval_token.is_none();
    let api = if issue_approval {
        make_authenticated_api(&record.issuer, credentials_file.as_deref())?
    } else {
        make_public_api(&record.issuer)?
    };
    // P0-4/P0-3: bind now also mints the Recovery Root, so its secret needs a
    // delivery channel with exactly the same fail-closed rules as recovery.
    let delivery: std::sync::Arc<dyn recovery::ReplacementSecretDelivery> =
        match output_secret_file.as_ref() {
            Some(path) => {
                std::sync::Arc::new(recovery::OutputFileSecretDelivery { path: path.clone() })
            }
            None => std::sync::Arc::new(recovery::InteractiveSecretDelivery),
        };
    let report = bind_flow(
        &api,
        &registry,
        &keys,
        explicit.as_deref(),
        &label,
        approval_callback(&api, approval_token.as_deref(), issue_approval),
        delivery.as_ref(),
    )?;
    println!("{report}");
    Ok(())
}

fn merge_global(
    selector: InstanceSelector,
    global: Option<&str>,
    action: &str,
) -> anyhow::Result<Option<String>> {
    selector.merge_global(global, action)
}

/// Recovery Secret input: a private file when given, otherwise one hidden
/// prompt (TTY) or one piped stdin line. Never argv, never echoed.
fn read_recovery_secret(path: Option<&std::path::Path>) -> anyhow::Result<String> {
    const MAX_SECRET_BYTES: u64 = 4096;
    if let Some(path) = path {
        let bytes =
            filesystem::read_secure_regular_file(path, "recovery secret", true, MAX_SECRET_BYTES)?;
        let text =
            String::from_utf8(bytes.to_vec()).context("recovery secret is not valid UTF-8")?;
        return Ok(text.trim().to_owned());
    }
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        let secret =
            rpassword::prompt_password("Paste the offline Recovery Secret (input hidden): ")
                .context("failed to read the recovery secret")?;
        Ok(secret.trim().to_owned())
    } else {
        eprintln!("Paste the offline Recovery Secret on one line:");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read the recovery secret from stdin")?;
        Ok(line.trim().to_owned())
    }
}

fn render_recovered(alias: &str, recovered: &recovery::RecoveredIdentity) -> String {
    format!(
        "controller identity recovered for instance '{alias}'\n\
         controller id: {}\n\
         kid: {}\n\
         expires: {} (30-day lifetime from the server clock)\n\
         recovery root generation: {}\n\
         \n\
         the replacement Recovery Secret was delivered and acknowledged BEFORE this commit ran; \
         the old secret stopped verifying when it landed. Verify your offline copy now — it is \
         the only way to run this recovery again.\n\
         next: nazoauthctl status --instance {alias}\n",
        recovered.controller_id,
        short_kid(&recovered.kid),
        recovered.expires_at.to_rfc3339(),
        recovered.recovery_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_identity::admin_api::{
        AdminApiError, ApprovalRequestBody, IssuedApproval, SlotSummary,
    };
    use crate::filesystem;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{Duration, Utc};

    const CONTROLLER_A: &str = "01900000-0000-7000-8000-00000000000a";
    const CONTROLLER_B: &str = "01900000-0000-7000-8000-00000000000b";
    const KID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0";

    struct Fixture {
        _temp: filesystem::PrivateTempDir,
        registry: RegistryStore,
        keys: ControllerKeyStore,
    }

    fn fixture() -> anyhow::Result<Fixture> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-lifecycle-test")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        let keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        let host = registry.ensure_local_host()?;
        let instance = InstanceRecord::new(
            "deploy-alpha",
            "production",
            host.host_id,
            "https://auth.example.com",
        )?;
        registry.add_instance(instance)?;
        Ok(Fixture {
            _temp: temp,
            registry,
            keys,
        })
    }

    impl Fixture {
        fn mark_bound(&self, controller_id: &str) -> anyhow::Result<()> {
            let key_ref = controller_key_ref_for("deploy-alpha")?;
            self.registry.update_controller_binding(
                "deploy-alpha",
                Some(controller_id),
                Some(key_ref.as_str()),
            )?;
            Ok(())
        }
    }

    fn slot_view(
        controller_id: &str,
        kid: &str,
        status: SlotStatus,
        days_to_expiry: i64,
    ) -> ControllerSlotView {
        ControllerSlotView {
            deployment_id: "deploy-alpha".to_owned(),
            controller_id: controller_id.to_owned(),
            label: "ops".to_owned(),
            kid: kid.to_owned(),
            slot_index: 0,
            issued_at: Utc::now() - Duration::days(30 - days_to_expiry),
            expires_at: Utc::now() + Duration::days(days_to_expiry),
            status,
            warning: None,
        }
    }

    /// Scripted API double recording every mutating call. Snapshots are
    /// consumed strictly FIFO so tests pin the exact call sequence.
    #[derive(Default)]
    struct FakeApi {
        snapshots: std::cell::RefCell<Vec<SlotsSnapshot>>,
        commits: std::cell::RefCell<Vec<serde_json::Value>>,
        commit_attempts: std::cell::RefCell<Vec<SlotCommitBody>>,
        rotate_calls: std::cell::RefCell<Vec<RotateCommitBody>>,
        revoke_calls: std::cell::RefCell<Vec<RevokeCommitBody>>,
        approval_requests: std::cell::RefCell<Vec<ApprovalRequestBody>>,
        approval_errors: std::cell::RefCell<Vec<AdminApiError>>,
        commit_errors: std::cell::RefCell<Vec<AdminApiError>>,
        assigned_controller_ids: std::cell::RefCell<Vec<String>>,
    }

    impl FakeApi {
        fn push_snapshot(&self, items: Vec<ControllerSlotView>) {
            self.snapshots.borrow_mut().push(SlotsSnapshot {
                deployment_id: "deploy-alpha".to_owned(),
                total: items.len() as u32,
                max_active_slots: 3,
                items,
            });
        }

        fn fail_next_commit(&self, error: AdminApiError) {
            self.commit_errors.borrow_mut().push(error);
        }

        fn fail_next_approval(&self, error: AdminApiError) {
            self.approval_errors.borrow_mut().push(error);
        }

        fn assign_next_commit_controller_id(&self, controller_id: &str) {
            self.assigned_controller_ids
                .borrow_mut()
                .push(controller_id.to_owned());
        }
    }

    impl ControllerRegistryApi for FakeApi {
        fn list_slots(&self, _deployment_id: &str) -> Result<SlotsSnapshot, AdminApiError> {
            let mut queue = self.snapshots.borrow_mut();
            assert!(!queue.is_empty(), "scripted snapshot missing for a call");
            Ok(queue.remove(0))
        }

        fn issue_approval(
            &self,
            body: &ApprovalRequestBody,
        ) -> Result<IssuedApproval, AdminApiError> {
            self.approval_requests.borrow_mut().push(body.clone());
            if let Some(error) = self.approval_errors.borrow_mut().pop() {
                return Err(error);
            }
            Ok(IssuedApproval {
                approval_token: "fresh-approval-token".to_owned(),
                action: body.action.to_owned(),
                action_sha256: "a".repeat(64),
                expires_at: Utc::now() + Duration::minutes(10),
                single_use: true,
            })
        }

        fn commit_slot(&self, body: &SlotCommitBody) -> Result<ControllerSlotView, AdminApiError> {
            self.commit_attempts.borrow_mut().push(body.clone());
            if let Some(error) = self.commit_errors.borrow_mut().pop() {
                return Err(error);
            }
            self.commits
                .borrow_mut()
                .push(serde_json::to_value(body).unwrap());
            let controller_id = self
                .assigned_controller_ids
                .borrow_mut()
                .pop()
                .unwrap_or_else(|| CONTROLLER_A.to_owned());
            Ok(ControllerSlotView {
                deployment_id: body.deployment_id.clone(),
                controller_id,
                label: body.label.clone(),
                kid: body.kid.clone(),
                slot_index: 0,
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(30),
                status: SlotStatus::Active,
                warning: None,
            })
        }

        fn rotate_slot(
            &self,
            body: &RotateCommitBody,
        ) -> Result<ControllerSlotView, AdminApiError> {
            self.rotate_calls.borrow_mut().push(body.clone());
            Ok(ControllerSlotView {
                deployment_id: body.deployment_id.clone(),
                controller_id: body.controller_id.clone(),
                label: body.label.clone(),
                kid: body.kid.clone(),
                slot_index: 0,
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(30),
                status: SlotStatus::Active,
                warning: None,
            })
        }

        fn revoke_slot(
            &self,
            body: &RevokeCommitBody,
        ) -> Result<ControllerSlotView, AdminApiError> {
            self.revoke_calls.borrow_mut().push(body.clone());
            Ok(ControllerSlotView {
                deployment_id: body.deployment_id.clone(),
                controller_id: body.controller_id.clone(),
                label: "ops".to_owned(),
                kid: KID_A.to_owned(),
                slot_index: 0,
                issued_at: Utc::now(),
                expires_at: Utc::now(),
                status: SlotStatus::Revoked,
                warning: None,
            })
        }

        fn recovery_root_view(
            &self,
            deployment_id: &str,
        ) -> Result<super::admin_api::RecoveryRootView, AdminApiError> {
            Ok(super::admin_api::RecoveryRootView {
                deployment_id: deployment_id.to_owned(),
                present: false,
                recovery_kid: None,
                kdf: None,
                generation: None,
            })
        }

        fn issue_recovery_root_approval(
            &self,
            _body: &super::admin_api::RecoveryRootApprovalBody,
        ) -> Result<IssuedApproval, AdminApiError> {
            unimplemented!("recovery-root approvals are not part of the lifecycle flows")
        }

        fn rotate_recovery_root(
            &self,
            _body: &super::admin_api::RecoveryRootRotateBody,
        ) -> Result<super::admin_api::RecoveryRootView, AdminApiError> {
            unimplemented!("recovery-root rotations are not part of the lifecycle flows")
        }

        fn issue_recovery_challenge(
            &self,
            _body: &super::admin_api::RecoveryChallengeBody,
        ) -> Result<super::admin_api::IssuedRecoveryChallenge, AdminApiError> {
            unimplemented!("break-glass challenges are not part of the lifecycle flows")
        }

        fn submit_recovery_answer(
            &self,
            _body: &super::admin_api::RecoveryAnswerBody,
        ) -> Result<super::admin_api::RecoveryCommitView, AdminApiError> {
            unimplemented!("break-glass commits are not part of the lifecycle flows")
        }
    }

    fn fixed_approval(
        token: &'static str,
    ) -> impl FnOnce(&ProposalPresentation) -> anyhow::Result<String> {
        move |presentation| {
            assert!(!presentation.deployment_id.is_empty());
            // Bind/add/rotate carry the proposed public key; revoke does not
            // (the server already knows the key it is revoking).
            assert!(
                presentation.public_key_b64.is_empty() || presentation.public_key_b64.len() == 43
            );
            assert!(token.len() >= 16);
            Ok(token.to_owned())
        }
    }

    fn real_public_key_length() -> bool {
        // Ed25519 raw public keys encode as exactly 43 unpadded base64url
        // characters; every stored candidate satisfies this.
        URL_SAFE_NO_PAD.encode([7u8; 32]).len() == 43
    }

    /// P0-3 test double: accepts the delivery silently so flows can run.
    struct SilentDelivery;

    impl recovery::ReplacementSecretDelivery for SilentDelivery {
        fn deliver(&self, _display: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingDelivery(std::cell::RefCell<Vec<String>>);

    impl recovery::ReplacementSecretDelivery for RecordingDelivery {
        fn deliver(&self, display: &str) -> anyhow::Result<()> {
            self.0.borrow_mut().push(display.to_owned());
            Ok(())
        }
    }

    #[test]
    fn bind_generates_exactly_one_candidate_and_persists_the_binding() -> anyhow::Result<()> {
        assert!(real_public_key_length());
        let f = fixture()?;
        let api = FakeApi::default();
        api.push_snapshot(vec![]); // pre-commit view

        let report = bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            approval_callback(&api, None, true),
            &SilentDelivery,
        )?;
        assert!(report.contains("committed for 'production'"), "{report}");

        let record = f.registry.instance_by_alias("production")?.unwrap();
        assert_eq!(record.controller_id.as_deref(), Some(CONTROLLER_A));
        assert_eq!(
            record.controller_key_ref.as_deref(),
            Some("controller-keys/deploy-alpha")
        );
        let active = f.keys.load_active("deploy-alpha")?.expect("activated");
        assert_eq!(f.keys.list_keys("deploy-alpha")?.len(), 1);

        let commit = api.commits.borrow()[0].clone();
        assert_eq!(commit["action"], "bind");
        assert_eq!(commit["deployment_id"], "deploy-alpha");
        assert_eq!(commit["kid"], active.kid());
        assert_eq!(
            commit["public_key"],
            f.keys.list_keys("deploy-alpha")?[0].public_key
        );
        // P0-3: the atomic first binding carries the recovery material.
        assert!(
            commit["recovery_public_key"].is_string() && commit["recovery_kid"].is_string(),
            "bind must enroll a Recovery Root in the same transaction: {commit}"
        );
        let approval = &api.approval_requests.borrow()[0];
        assert_eq!(approval.action, "bind");
        assert_eq!(
            Some(approval.deployment_id.as_str()),
            commit["deployment_id"].as_str()
        );
        assert_eq!(approval.label.as_deref(), commit["label"].as_str());
        assert_eq!(
            approval.public_key.as_deref(),
            commit["public_key"].as_str()
        );
        assert_eq!(approval.kid.as_deref(), commit["kid"].as_str());
        assert_eq!(
            approval.recovery_public_key.as_deref(),
            commit["recovery_public_key"].as_str()
        );
        assert_eq!(
            approval.recovery_kid.as_deref(),
            commit["recovery_kid"].as_str()
        );

        assert!(
            record.last_observation.is_none(),
            "live slot facts must not be copied into the display observation cache"
        );

        // Re-running bind against a bound instance is refused up front.
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            active.kid(),
            SlotStatus::Active,
            29,
        )]);
        let error = bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            fixed_approval("approval-token-2"),
            &SilentDelivery,
        )
        .expect_err("already bound");
        assert!(
            error
                .to_string()
                .contains("already has an active controller"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn explicit_approval_token_never_requests_a_second_approval() -> anyhow::Result<()> {
        let f = fixture()?;
        let api = FakeApi::default();
        api.push_snapshot(vec![]);
        bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            approval_callback(&api, Some("explicit-approval-token"), true),
            &SilentDelivery,
        )?;
        assert!(api.approval_requests.borrow().is_empty());
        assert_eq!(
            api.commit_attempts.borrow()[0].approval_token,
            "explicit-approval-token"
        );
        Ok(())
    }

    #[test]
    fn rejected_fresh_approval_never_commits_a_slot() -> anyhow::Result<()> {
        let f = fixture()?;
        let api = FakeApi::default();
        api.push_snapshot(vec![]);
        api.fail_next_approval(AdminApiError::Rejected {
            status: 403,
            error: "fresh_mfa_required".to_owned(),
            description: "fresh MFA required".to_owned(),
        });
        let error = bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            approval_callback(&api, None, true),
            &SilentDelivery,
        )
        .expect_err("approval rejection must stop bind");
        assert!(
            error.to_string().contains("fresh_mfa_required"),
            "{error:#}"
        );
        assert!(api.commit_attempts.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn bind_resume_reuses_pending_candidate_instead_of_minting_new_keys() -> anyhow::Result<()> {
        let f = fixture()?;
        let api = FakeApi::default();
        let delivery = RecordingDelivery::default();

        // First attempt dies at the commit (expired approval): the candidate
        // stays, nothing activates locally.
        api.push_snapshot(vec![]); // attempt 1 pre-commit
        api.fail_next_commit(AdminApiError::Rejected {
            status: 400,
            error: "invalid_request".to_owned(),
            description: "审批令牌已过期；请在十分钟窗口内完成提交.".to_owned(),
        });
        let error = bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            fixed_approval("expired-token-0001"),
            &delivery,
        )
        .expect_err("rejected");
        assert!(error.downcast_ref::<AdminApiError>().is_some(), "{error:#}");
        assert!(
            f.keys.load_active("deploy-alpha")?.is_none(),
            "not activated"
        );
        let first_candidate = f.keys.list_keys("deploy-alpha")?[0].kid.clone();
        let pending_path = pending_bind_recovery_path(&f.keys, "deploy-alpha")?;
        assert!(
            pending_path.is_file(),
            "failed commit must retain exact root material"
        );

        // Second attempt resumes with the SAME candidate (D04.6).
        api.push_snapshot(vec![]); // attempt 2 pre-commit
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            &first_candidate,
            SlotStatus::Active,
            30,
        )]);
        bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            fixed_approval("good-token-000002"),
            &delivery,
        )?;
        let active = f.keys.load_active("deploy-alpha")?.expect("activated");
        assert_eq!(active.kid(), first_candidate);
        assert_eq!(f.keys.list_keys("deploy-alpha")?.len(), 1, "no orphan keys");
        let attempts = api.commit_attempts.borrow();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].kid, attempts[1].kid);
        assert_eq!(attempts[0].recovery_kid, attempts[1].recovery_kid);
        assert_eq!(
            attempts[0].recovery_public_key,
            attempts[1].recovery_public_key
        );
        let delivered = delivery.0.borrow();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], delivered[1]);
        assert!(
            !pending_path.exists(),
            "terminal bind must erase pending secret"
        );
        Ok(())
    }

    #[test]
    fn crash_between_commit_and_local_update_is_recovered_from_server_list() -> anyhow::Result<()> {
        let f = fixture()?;
        // Crash window: candidate generated, server committed, local
        // pointer/registry untouched.
        let candidate = f.keys.generate_candidate("deploy-alpha")?;

        let api = FakeApi::default();
        let snap = vec![slot_view(
            CONTROLLER_A,
            &candidate.kid,
            SlotStatus::Active,
            30,
        )];
        api.push_snapshot(snap);

        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        let recovered =
            reconcile_from_snapshot(&f.registry, &f.keys, &record, &api.snapshots.borrow()[0])?
                .expect("adopted");
        assert!(recovered.contains(&candidate.kid[..12]), "{recovered}");

        let active = f.keys.load_active("deploy-alpha")?.expect("activated");
        assert_eq!(active.kid(), candidate.kid);
        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        assert_eq!(record.controller_id.as_deref(), Some(CONTROLLER_A));
        Ok(())
    }

    #[test]
    fn consistent_state_is_not_reported_as_recovery() -> anyhow::Result<()> {
        let f = fixture()?;
        let active = f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;
        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            active.kid(),
            SlotStatus::Active,
            20,
        )]);

        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        let recovered =
            reconcile_from_snapshot(&f.registry, &f.keys, &record, &api.snapshots.borrow()[0])?;
        assert!(recovered.is_none(), "consistent state needs no repair");
        Ok(())
    }

    #[test]
    fn rotate_switches_pointer_and_retires_the_old_key_after_confirmation() -> anyhow::Result<()> {
        let f = fixture()?;
        let original = f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;

        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            original.kid(),
            SlotStatus::Active,
            2,
        )]); // reconcile view

        let report = rotate_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            None,
            fixed_approval("rotate-token-001"),
        )?;
        assert!(report.contains("committed for 'production'"), "{report}");

        let rotated = f.keys.load_active("deploy-alpha")?.expect("new active");
        assert_ne!(rotated.kid(), original.kid());
        let summaries = f.keys.list_keys("deploy-alpha")?;
        assert_eq!(summaries.len(), 1, "old key retired after confirmation");
        assert_eq!(summaries[0].kid, rotated.kid());

        let call = &api.rotate_calls.borrow()[0];
        assert_eq!(call.controller_id, CONTROLLER_A);
        assert_eq!(call.kid, rotated.kid());

        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        assert_eq!(record.controller_id.as_deref(), Some(CONTROLLER_A));
        Ok(())
    }

    #[test]
    fn rotate_recovers_when_a_previous_run_crashed_after_commit_before_switch() -> anyhow::Result<()>
    {
        let f = fixture()?;
        let old_key = f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;
        // Candidate exists (generated pre-crash); the server already switched
        // to it while the local pointer still names the OLD kid.
        let candidate = f.keys.generate_candidate("deploy-alpha")?;

        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            &candidate.kid,
            SlotStatus::Active,
            30,
        )]);

        let report = rotate_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            None,
            fixed_approval("unused-token-01"),
        )?;
        assert!(report.contains("crash recovery"), "{report}");
        assert_eq!(
            f.keys.load_active("deploy-alpha")?.expect("switched").kid(),
            candidate.kid
        );
        assert!(
            !f.keys
                .list_keys("deploy-alpha")?
                .iter()
                .any(|s| s.kid == old_key.kid()),
            "superseded old key retired"
        );
        assert!(
            api.rotate_calls.borrow().is_empty(),
            "no new proposal needed"
        );
        Ok(())
    }

    #[test]
    fn add_enrolls_a_second_controller_and_keeps_the_old_one() -> anyhow::Result<()> {
        let f = fixture()?;
        let original = f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;

        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            original.kid(),
            SlotStatus::Active,
            20,
        )]);
        api.assign_next_commit_controller_id(CONTROLLER_B);

        let report = add_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "backup",
            fixed_approval("add-token-000001"),
        )?;
        assert!(report.contains("remains enrolled"), "{report}");

        // The new identity became THIS ctl's signing identity.
        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        assert_eq!(record.controller_id.as_deref(), Some(CONTROLLER_B));
        assert_eq!(
            f.keys.load_active("deploy-alpha")?.unwrap().kid(),
            api.commits.borrow()[0]["kid"]
        );
        // Old material survives as a still-enrolled slot.
        assert!(
            f.keys
                .list_keys("deploy-alpha")?
                .iter()
                .any(|s| s.kid == original.kid())
        );
        Ok(())
    }

    #[test]
    fn add_refuses_locally_when_three_slots_are_already_active() -> anyhow::Result<()> {
        let f = fixture()?;
        f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;

        let api = FakeApi::default();
        api.push_snapshot(vec![
            slot_view(
                "c1",
                "1111111111111111111111111111111111111111111",
                SlotStatus::Active,
                20,
            ),
            slot_view(
                "c2",
                "2222222222222222222222222222222222222222222",
                SlotStatus::Active,
                20,
            ),
            slot_view(CONTROLLER_A, KID_A, SlotStatus::Active, 20),
        ]);
        let error = add_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "more",
            fixed_approval("never-consumed-tok"),
        )
        .expect_err("full board");
        let rendered = error.to_string();
        assert!(rendered.contains("CONTROLLER_SLOT_LIMIT"), "{rendered}");
        assert!(rendered.contains("revoke one before adding"), "{rendered}");
        assert!(
            rendered.contains(&KID_A[..12]),
            "non-secret summaries listed: {rendered}"
        );
        // No proposal was presented and no commit was attempted.
        assert!(api.commits.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn server_slot_limit_error_surfaces_with_slot_summaries() {
        let error: anyhow::Error = AdminApiError::SlotLimit(vec![SlotSummary {
            controller_id: "c9".to_owned(),
            label: "old".to_owned(),
            kid: KID_A.to_owned(),
            slot_index: 2,
            expires_at: Utc::now() + Duration::days(4),
        }])
        .into();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("CONTROLLER_SLOT_LIMIT"), "{rendered}");
        assert!(rendered.contains("c9"), "{rendered}");
    }

    #[test]
    fn revoke_requires_exact_id_and_cleans_up_only_after_confirmation() -> anyhow::Result<()> {
        let f = fixture()?;
        let own_key = f.keys.get_or_create_active("deploy-alpha")?;
        f.mark_bound(CONTROLLER_A)?;

        // Unknown controller id fails before any approval is requested.
        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            own_key.kid(),
            SlotStatus::Active,
            10,
        )]);
        let error = revoke_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "unknown-controller",
            fixed_approval("never-consumed-tok"),
        )
        .expect_err("unknown id");
        assert!(
            error.to_string().contains("requires the exact id"),
            "{error}"
        );

        // Own revocation clears the pointer but keeps material for diagnostics.
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            own_key.kid(),
            SlotStatus::Active,
            10,
        )]);
        let report = revoke_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            CONTROLLER_A,
            fixed_approval("revoke-token-00001"),
        )?;
        assert!(report.contains("revoked controller"), "{report}");
        assert!(report.contains("active pointer was cleared"), "{report}");
        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        assert!(record.controller_id.is_none());
        assert!(f.keys.load_active("deploy-alpha")?.is_none());
        assert_eq!(f.keys.list_keys("deploy-alpha")?.len(), 1, "material kept");
        assert_eq!(api.revoke_calls.borrow()[0].controller_id, CONTROLLER_A);

        // Already-revoked targets refuse cleanly instead of burning approvals.
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            own_key.kid(),
            SlotStatus::Revoked,
            0,
        )]);
        let error = revoke_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            CONTROLLER_A,
            fixed_approval("never-consumed-tok"),
        )
        .expect_err("already revoked");
        assert!(error.to_string().contains("already revoked"), "{error}");
        Ok(())
    }

    #[test]
    fn slots_flow_reports_live_expiry_classes_without_persisting_the_snapshot() -> anyhow::Result<()>
    {
        let f = fixture()?;
        let api = FakeApi::default();
        api.push_snapshot(vec![slot_view(CONTROLLER_A, KID_A, SlotStatus::Active, 20)]);
        let report = slots_flow(&api, &f.registry, &f.keys, None)?;
        assert!(report.contains("valid ("), "{report}");
        assert!(report.contains(&KID_A[..12]), "{report}");

        api.push_snapshot(vec![slot_view(CONTROLLER_A, KID_A, SlotStatus::Active, 3)]);
        let report = slots_flow(&api, &f.registry, &f.keys, None)?;
        assert!(report.contains("WARNING"), "{report}");

        api.push_snapshot(vec![slot_view(CONTROLLER_A, KID_A, SlotStatus::Active, 0)]);
        let report = slots_flow(&api, &f.registry, &f.keys, None)?;
        assert!(report.contains("EXPIRED"), "{report}");

        let record = f.registry.instance_by_deployment("deploy-alpha")?.unwrap();
        assert!(
            record.last_observation.is_none(),
            "explicit live list output must not become a second expiry authority"
        );
        Ok(())
    }

    #[test]
    fn presentation_renders_proposal_facts_without_private_material() -> anyhow::Result<()> {
        let f = fixture()?;
        let candidate = f.keys.generate_candidate("deploy-alpha")?;
        let summary = f
            .keys
            .list_keys("deploy-alpha")?
            .into_iter()
            .find(|s| s.kid == candidate.kid)
            .unwrap();
        let presentation = ProposalPresentation {
            action: "bind",
            alias: "production".to_owned(),
            deployment_id: "deploy-alpha".to_owned(),
            issuer: "https://auth.example.com".to_owned(),
            label: "ops".to_owned(),
            controller_id: None,
            kid: candidate.kid.clone(),
            public_key_b64: summary.public_key.clone(),
            recovery_kid: Some("recovery-kid-placeholder".to_owned()),
            recovery_public_key_b64: Some("recovery-public-key-placeholder".to_owned()),
        };
        let rendered = presentation.render();
        assert!(rendered.contains("deployment: deploy-alpha"), "{rendered}");
        assert!(rendered.contains("action:     bind"), "{rendered}");
        assert!(rendered.contains("fresh administrator 2FA"), "{rendered}");
        assert!(rendered.contains("exact payload"), "{rendered}");
        assert!(!rendered.contains("port forward"), "{rendered}");
        assert!(rendered.contains("recovery kid"), "{rendered}");
        // Public fingerprint only; the full kid and any seed bytes never show.
        assert!(!rendered.contains(candidate.kid.as_str()), "{rendered}");
        assert!(!rendered.contains(&summary.public_key), "{rendered}");
        Ok(())
    }
}
