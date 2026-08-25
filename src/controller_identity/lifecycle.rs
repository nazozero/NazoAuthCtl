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
//!   → obtain a single-use approval token (browser 2FA happens at the
//!      instance admin surface; ctl only ever carries the token)
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
//! Approval tokens are secrets: they arrive through the injected approval
//! callback (CLI: `--approval-token` flag for automation, hidden prompt or
//! piped stdin for humans), and are never logged, echoed, or persisted.

use anyhow::{Context as _, bail};

use crate::cli::{ControllerCommand, InstanceSelector};
use crate::filesystem;
use crate::registry::{InstanceRecord, ObservationCache, RegistryStore, validate_issuer};

use super::admin_api::{
    self, AdminAccess, AdminAccessFile, ControllerRegistryApi, ControllerSlotView,
    RevokeCommitBody, RotateCommitBody, SlotCommitBody, SlotStatus, SlotsSnapshot, short_kid,
};
use super::expiry;
use super::store::{ControllerKeyStore, controller_key_ref_for};

/// What one flow presents to the human approver (goal plan 04 §3): exact
/// action/deployment/label/kid fingerprints, never private bytes.
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
        text.push_str(
            "\nApprove this exact payload in the instance admin console (fresh 2FA) within \
             10 minutes; the key expires 30 days after enrollment. Then paste the single-use \
             approval token here, or abort.\n",
        );
        if self.action == "bind" {
            text.push_str(
                "If the admin console is only reachable from the target host, an OpenSSH port \
                 forward of its admin port is supported; ctl never reads SSH secrets.\n",
            );
        }
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
            .with_context(|| format!("no registered instance matches '{selector}' exactly"));
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
                "INSTANCE_SELECTOR_REQUIRED: multiple instances are registered ({candidates}); \
                 pass --instance SELECTOR"
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

        cache_snapshot(registry, deployment, snapshot)?;

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
                 server; the local binding was cleared. Enroll again with `controller bind` \
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

/// Cache the latest authoritative snapshot in the instance observation so
/// fleet/status surfaces can show expiry warnings without contact (task D09).
/// Pure display data; never consulted for authorization.
fn cache_snapshot(
    registry: &RegistryStore,
    deployment_id: &str,
    snapshot: &SlotsSnapshot,
) -> anyhow::Result<()> {
    registry.set_instance_observation(
        deployment_id,
        ObservationCache::now(true, expiry::summarize_slots(snapshot)),
    )
}

fn require_bound(record: &InstanceRecord) -> anyhow::Result<String> {
    record.controller_id.clone().with_context(|| {
        format!(
            "instance '{}' has no bound controller identity; run `controller bind` first",
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

/// Shared post-commit tail: refresh the authoritative snapshot, persist the
/// registry fields, switch the active pointer, and render the completion
/// report. Server state stays the authority throughout; both local steps are
/// recoverable via [`reconcile_from_snapshot`] on any later command.
fn finish_activation<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    alias: &str,
    deployment: &str,
    kid: &str,
    committed_slot: ControllerSlotView,
) -> anyhow::Result<String> {
    let snapshot = api.list_slots(deployment)?;
    persist_binding_fields(registry, deployment, Some(&committed_slot.controller_id))?;
    keys.set_active_kid(deployment, kid)?;
    cache_snapshot(registry, deployment, &snapshot)?;
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
pub fn bind_flow<A: ControllerRegistryApi>(
    api: &A,
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    selector: Option<&str>,
    label: &str,
    approval: impl FnOnce(&ProposalPresentation) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let record = resolve_record(registry, selector)?;
    validate_label(label)?;
    let deployment = record.deployment_id.clone();
    let snapshot = api.list_slots(&deployment)?;

    // D06: a previous run may have committed server-side already.
    if let Some(report) = reconcile_from_snapshot(registry, keys, &record, &snapshot)? {
        return Ok(format!("bind complete via crash recovery.\n{report}"));
    }

    if !snapshot.active_slots().is_empty() || record.controller_id.is_some() {
        bail!(
            "instance '{}' already has an active controller identity; use `controller rotate` \
             (same controller) or `controller add` (additional slot up to three)",
            record.alias
        );
    }

    // D04.6: resume a still-pending proposal instead of minting new material.
    let kid = match select_pending_candidate(keys, &deployment, &snapshot)? {
        Some(pending) => pending,
        None => keys.generate_candidate(&deployment)?.kid,
    };
    let public_key = load_public_key(keys, &deployment, &kid)?;

    let presentation = ProposalPresentation {
        action: "bind",
        alias: record.alias.clone(),
        deployment_id: deployment.clone(),
        issuer: record.issuer.clone(),
        label: label.to_owned(),
        controller_id: None,
        kid: kid.clone(),
        public_key_b64: public_key.clone(),
    };
    let token = approval(&presentation)?;

    let slot = api.commit_slot(&SlotCommitBody {
        approval_token: token,
        action: "bind",
        deployment_id: deployment.clone(),
        label: label.to_owned(),
        public_key,
        kid: kid.clone(),
    })?;
    verify_committed_slot(&slot, &deployment, &kid, "bind")?;

    finish_activation(api, registry, keys, &record.alias, &deployment, &kid, slot)
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
    let report = finish_activation(api, registry, keys, &record.alias, &deployment, &kid, slot)?;

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
            "CONTROLLER_SLOT_LIMIT: '{}' already has {active} of {max} active controller slots; \
             revoke one before adding:",
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
    };
    let token = approval(&presentation)?;

    let slot = api.commit_slot(&SlotCommitBody {
        approval_token: token,
        action: "add",
        deployment_id: deployment.clone(),
        label: label.to_owned(),
        public_key,
        kid: kid.clone(),
    })?;
    verify_committed_slot(&slot, &deployment, &kid, "add")?;

    // This ctl adopts its NEW slot as the identity it signs with; the
    // previous key stays enrolled until its own expiry or explicit revocation.
    let report = finish_activation(api, registry, keys, &record.alias, &deployment, &kid, slot)?;
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
                 revocation requires the exact id (`controller slots` lists them)"
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

    let refreshed = api.list_slots(&deployment)?;
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
    cache_snapshot(registry, &deployment, &refreshed)?;
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
        report.push_str("  none enrolled; run `controller bind`\n");
    }
    for slot in &snapshot.items {
        for row in expiry::render_slot_line(slot, now).split('\n') {
            report.push_str("  ");
            report.push_str(row);
            report.push('\n');
        }
    }
    cache_snapshot(registry, &deployment, &snapshot)?;
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

fn access_from_file(path: &std::path::Path) -> anyhow::Result<AdminAccess> {
    const MAX_ACCESS_BYTES: u64 = 8192;
    let bytes =
        filesystem::read_secure_regular_file(path, "admin access file", true, MAX_ACCESS_BYTES)?;
    let parsed: AdminAccessFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid admin access document", path.display()))?;
    Ok(AdminAccess::new(parsed.session_cookie, parsed.csrf_token))
}

fn make_api(
    issuer: &str,
    admin_access_file: Option<&std::path::Path>,
) -> anyhow::Result<admin_api::HttpControllerRegistryApi> {
    let access = match admin_access_file {
        Some(path) => access_from_file(path)?,
        None => AdminAccess::default(),
    };
    validate_issuer(issuer).context("registered issuer is invalid")?;
    admin_api::HttpControllerRegistryApi::new(issuer, access)
}

fn approval_callback<'a>(
    token: Option<&'a str>,
) -> impl FnOnce(&ProposalPresentation) -> anyhow::Result<String> + 'a {
    move |presentation| {
        println!("{}", presentation.render());
        obtain_approval_token(token, presentation.action)
    }
}

fn merged_selector(selector: InstanceSelector) -> anyhow::Result<Option<String>> {
    selector.explicit().context("conflicting selectors")
}

/// Dispatch `nazauthctl controller …` commands (goal plan 04, tasks
/// D04–D09). Runs entirely against user-scoped stores; no root, no legacy
/// lifecycle lock.
pub(crate) fn run_command(command: ControllerCommand) -> anyhow::Result<()> {
    let registry = RegistryStore::open_default()?;
    let keys = ControllerKeyStore::open_default()?;
    match command {
        ControllerCommand::Bind {
            selector,
            label,
            approval_token,
            admin_access_file,
        } => {
            let explicit = merged_selector(selector)?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_api(&record.issuer, admin_access_file.as_deref())?;
            let report = bind_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                &label,
                approval_callback(approval_token.as_deref()),
            )?;
            println!("{report}");
        }
        ControllerCommand::Add {
            selector,
            label,
            approval_token,
            admin_access_file,
        } => {
            let explicit = merged_selector(selector)?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_api(&record.issuer, admin_access_file.as_deref())?;
            let report = add_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                &label,
                approval_callback(approval_token.as_deref()),
            )?;
            println!("{report}");
        }
        ControllerCommand::Rotate {
            selector,
            label,
            approval_token,
            admin_access_file,
        } => {
            let explicit = merged_selector(selector)?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_api(&record.issuer, admin_access_file.as_deref())?;
            let report = rotate_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                label.as_deref(),
                approval_callback(approval_token.as_deref()),
            )?;
            println!("{report}");
        }
        ControllerCommand::Revoke {
            selector,
            controller_id,
            yes,
            approval_token,
            admin_access_file,
        } => {
            if !yes {
                bail!(
                    "revocation is destructive: re-run with --yes after confirming the exact \
                     controller id"
                );
            }
            let explicit = merged_selector(selector)?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_api(&record.issuer, admin_access_file.as_deref())?;
            let report = revoke_flow(
                &api,
                &registry,
                &keys,
                explicit.as_deref(),
                &controller_id,
                approval_callback(approval_token.as_deref()),
            )?;
            println!("{report}");
        }
        ControllerCommand::Slots {
            selector,
            admin_access_file,
        } => {
            let explicit = merged_selector(selector)?;
            let record = resolve_record(&registry, explicit.as_deref())?;
            let api = make_api(&record.issuer, admin_access_file.as_deref())?;
            let report = slots_flow(&api, &registry, &keys, explicit.as_deref())?;
            println!("{report}");
        }
    }
    Ok(())
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
            "ref",
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
        rotate_calls: std::cell::RefCell<Vec<RotateCommitBody>>,
        revoke_calls: std::cell::RefCell<Vec<RevokeCommitBody>>,
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
            _body: &ApprovalRequestBody,
        ) -> Result<IssuedApproval, AdminApiError> {
            unimplemented!("approvals are issued by humans in the browser flow")
        }

        fn commit_slot(&self, body: &SlotCommitBody) -> Result<ControllerSlotView, AdminApiError> {
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

    #[test]
    fn bind_generates_exactly_one_candidate_and_persists_the_binding() -> anyhow::Result<()> {
        assert!(real_public_key_length());
        let f = fixture()?;
        let api = FakeApi::default();
        api.push_snapshot(vec![]); // pre-commit view
        api.push_snapshot(vec![slot_view(CONTROLLER_A, KID_A, SlotStatus::Active, 30)]); // post-commit

        let report = bind_flow(
            &api,
            &f.registry,
            &f.keys,
            None,
            "ops",
            fixed_approval("approval-token-1"),
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

        let cached = expiry::parse_cached_slots(&record.last_observation.unwrap().summary);
        assert!(cached.is_some(), "slot facts cached for D09");

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
    fn bind_resume_reuses_pending_candidate_instead_of_minting_new_keys() -> anyhow::Result<()> {
        let f = fixture()?;
        let api = FakeApi::default();

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
        )
        .expect_err("rejected");
        assert!(error.downcast_ref::<AdminApiError>().is_some(), "{error:#}");
        assert!(
            f.keys.load_active("deploy-alpha")?.is_none(),
            "not activated"
        );
        let first_candidate = f.keys.list_keys("deploy-alpha")?[0].kid.clone();

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
        )?;
        let active = f.keys.load_active("deploy-alpha")?.expect("activated");
        assert_eq!(active.kid(), first_candidate);
        assert_eq!(f.keys.list_keys("deploy-alpha")?.len(), 1, "no orphan keys");
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
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            original.kid(),
            SlotStatus::Active,
            2,
        )]); // post-commit refresh

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
        api.push_snapshot(vec![
            slot_view(CONTROLLER_A, original.kid(), SlotStatus::Active, 20),
            slot_view(
                CONTROLLER_B,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1",
                SlotStatus::Active,
                30,
            ),
        ]);
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
        api.push_snapshot(vec![slot_view(
            CONTROLLER_A,
            own_key.kid(),
            SlotStatus::Revoked,
            0,
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
    fn slots_flow_reports_expiry_classes_and_caches_the_snapshot() -> anyhow::Result<()> {
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
        assert!(expiry::parse_cached_slots(&record.last_observation.unwrap().summary).is_some());
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
        };
        let rendered = presentation.render();
        assert!(rendered.contains("deployment: deploy-alpha"), "{rendered}");
        assert!(rendered.contains("action:     bind"), "{rendered}");
        assert!(rendered.contains("fresh 2FA"), "{rendered}");
        assert!(rendered.contains("port forward"), "{rendered}");
        // Public fingerprint only; the full kid and any seed bytes never show.
        assert!(!rendered.contains(candidate.kid.as_str()), "{rendered}");
        assert!(!rendered.contains(&summary.public_key), "{rendered}");
        Ok(())
    }
}
