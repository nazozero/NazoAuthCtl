use std::fs;

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nazo_operator_protocol::{
    Actor, ActorKind, ManagementAuditEvent, PROTOCOL_VERSION, compact_sha256, protected_header,
    sign_management_event, verify_management_event,
};
use serde::{Deserialize, Serialize};

use crate::{
    deployment::{
        Capability, CapabilityGrant, DeploymentRecord, DeploymentStore, RecoveryConclusion,
        ResourceScope, Responsibility, SafeReference, TrustState,
    },
    filesystem::{atomic_write, remove_file_durable},
    runtime_backend::backend,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TransitionState {
    Prepared,
    DeclarationCommitted,
    Committed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuditIntentState {
    Prepared,
    DeclarationCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagementAuditIntent {
    schema: u32,
    state: AuditIntentState,
    request_id: String,
    deployment_id: String,
    previous: DeploymentRecord,
    target: DeploymentRecord,
    operation: String,
    release: String,
    recovery_boundary: String,
}

const MANAGEMENT_AUDIT_INTENT_SCHEMA: u32 = 1;
const MANAGEMENT_AUDIT_INTENT_MAX_BYTES: u64 = 512 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityTransition {
    schema: u32,
    state: TransitionState,
    request_id: String,
    operation: String,
    from_revision: u64,
    target: DeploymentRecord,
}

pub(crate) fn set_permissions(
    selector: Option<&str>,
    changes: &[(Capability, CapabilityGrant)],
) -> anyhow::Result<()> {
    transition(selector, changes, "capability-grant", false)
}

pub(crate) fn relinquish(
    selector: Option<&str>,
    capabilities: &[Capability],
) -> anyhow::Result<()> {
    let changes = capabilities
        .iter()
        .copied()
        .map(|capability| {
            (
                capability,
                CapabilityGrant {
                    responsibility: Responsibility::External,
                    scope: ResourceScope::Deployment,
                },
            )
        })
        .collect::<Vec<_>>();
    transition(selector, &changes, "capability-relinquish", true)
}

fn transition(
    selector: Option<&str>,
    changes: &[(Capability, CapabilityGrant)],
    operation: &str,
    handoff: bool,
) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let selected = store.resolve(selector, true)?;
    crate::controller::reject_pending_local_oci_candidate_record(&selected)?;
    crate::controller::reject_completed_local_oci_candidate_transition(&selected)?;
    let _registry_lock = store.registry_lock()?;
    let resolved = store.resolve(selector, true)?;
    if resolved.deployment_id != selected.deployment_id {
        bail!("deployment selection changed while capability transition was being prepared");
    }
    crate::controller::reject_pending_local_oci_candidate_record(&resolved)?;
    crate::controller::reject_completed_local_oci_candidate_transition(&resolved)?;
    // Resolve only chooses the deployment ID.  The declaration must be
    // reloaded after the registry/deployment lock is held so a caller cannot
    // replay capability changes from a stale snapshot.
    let _deployment_lock = store.deployment_lock(&resolved.deployment_id)?;
    let record = store.load(&resolved.deployment_id)?;
    crate::controller::reject_pending_local_oci_candidate_record(&record)?;
    crate::controller::reject_completed_local_oci_candidate_transition(&record)?;
    let mut shared_resources = changes
        .iter()
        .filter(|(capability, grant)| {
            grant.scope == ResourceScope::Shared
                || record.capabilities.grant(*capability).scope == ResourceScope::Shared
        })
        .map(|(capability, _)| capability.name())
        .collect::<Vec<_>>();
    shared_resources.sort_unstable();
    shared_resources.dedup();
    let _shared_locks = shared_resources
        .into_iter()
        .map(|resource| store.shared_resource_lock(resource))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if crate::coordination::active_update_exists(&store, &record) {
        bail!("capabilities cannot change while a coordinated update transaction is active");
    }
    if record.trust != TrustState::Adopted {
        bail!("capabilities cannot change until the deployment is adopted");
    }
    let active_path = store
        .deployment_state_dir(&record.deployment_id)
        .join("transactions")
        .join("capability-transition.json");
    let mut transaction = if path_present(&active_path)? {
        let transaction_bytes = crate::filesystem::read_secure_regular_file(
            &active_path,
            "capability transition journal",
            true,
            512 * 1024,
        )?;
        let transaction: CapabilityTransition = serde_json::from_slice(&transaction_bytes)
            .context("capability transition is invalid")?;
        if transaction.schema != 1
            || transaction.target.deployment_id != record.deployment_id
            || transaction.operation != operation
            || changes.iter().any(|(capability, grant)| {
                let target = transaction.target.capabilities.grant(*capability);
                if handoff {
                    target.responsibility != Responsibility::External
                } else {
                    target != grant
                }
            })
        {
            bail!("a different capability transition is pending; resume it with its original plan");
        }
        transaction
    } else {
        let mut target = record.clone();
        for (capability, grant) in changes {
            if handoff {
                target.capabilities.grant_mut(*capability).responsibility =
                    Responsibility::External;
            } else {
                validate_grant_transition(&record, *capability, grant)?;
                *target.capabilities.grant_mut(*capability) = grant.clone();
            }
        }
        target.declaration_revision = target
            .declaration_revision
            .checked_add(1)
            .context("deployment declaration revision overflow")?;
        target.validate()?;
        let transaction = CapabilityTransition {
            schema: 1,
            state: TransitionState::Prepared,
            request_id: uuid::Uuid::now_v7().to_string(),
            operation: operation.to_owned(),
            from_revision: record.declaration_revision,
            target,
        };
        atomic_write(
            &active_path,
            &serde_json::to_vec_pretty(&transaction)?,
            0o600,
        )?;
        transaction
    };
    if transaction.state == TransitionState::Prepared {
        match record.declaration_revision {
            revision if revision == transaction.from_revision => {
                store.persist_declaration_cas_locked(&record, &transaction.target)?;
            }
            revision if revision == transaction.target.declaration_revision => {
                if record.capabilities != transaction.target.capabilities {
                    bail!("deployment declaration revision was reused with different capabilities");
                }
            }
            _ => bail!("deployment declaration changed during the capability transition"),
        }
        transaction.state = TransitionState::DeclarationCommitted;
        atomic_write(
            &active_path,
            &serde_json::to_vec_pretty(&transaction)?,
            0o600,
        )?;
    }
    if transaction.state == TransitionState::DeclarationCommitted {
        append_audit_idempotent(&store, &transaction)?;
        if handoff {
            write_handoff(&store, &transaction.target)?;
        }
        transaction.state = TransitionState::Committed;
        atomic_write(
            &active_path,
            &serde_json::to_vec_pretty(&transaction)?,
            0o600,
        )?;
    }
    let history = active_path.with_file_name(format!("capability-{}.json", transaction.request_id));
    atomic_write(&history, &serde_json::to_vec_pretty(&transaction)?, 0o600)?;
    remove_file_durable(&active_path)?;
    println!("{}", serde_json::to_string_pretty(&transaction.target)?);
    Ok(())
}

fn validate_grant_transition(
    record: &DeploymentRecord,
    capability: Capability,
    grant: &CapabilityGrant,
) -> anyhow::Result<()> {
    if grant.scope == ResourceScope::Shared && grant.responsibility == Responsibility::Managed {
        bail!(
            "shared resources cannot become managed until a shared-resource provider and deletion proof exist"
        );
    }
    let current = record.capabilities.grant(capability);
    if responsibility_rank(grant.responsibility) > responsibility_rank(current.responsibility)
        && record.recovery.conclusion != RecoveryConclusion::Proven
    {
        bail!("capability expansion requires a proven recovery package");
    }
    if capability == Capability::Runtime
        && grant.responsibility.permits_mutation()
        && record.runtime_instances.iter().any(|runtime| {
            backend(runtime.backend)
                .verify_ownership(
                    &runtime.object_reference,
                    &record.deployment_id,
                    &runtime.runtime_instance_id,
                    &record.control_authority,
                )
                .is_err()
        })
    {
        bail!(
            "runtime cannot become mutable without exact deployment, runtime-instance, and control-authority labels"
        );
    }
    Ok(())
}

fn responsibility_rank(value: Responsibility) -> u8 {
    match value {
        Responsibility::External => 0,
        Responsibility::Delegated => 1,
        Responsibility::Managed => 2,
    }
}

fn append_audit_idempotent(
    store: &DeploymentStore,
    transaction: &CapabilityTransition,
) -> anyhow::Result<()> {
    append_management_audit(
        store,
        &transaction.target,
        &transaction.request_id,
        &transaction.operation,
        "controller-state",
    )
}

pub(crate) fn append_management_audit(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    request_id: &str,
    operation: &str,
    release: &str,
) -> anyhow::Result<()> {
    // Controller-backed deployments use the operator management chain as
    // their canonical ledger.  This keeps lifecycle events visible through
    // the same AuditVerify/AuditShow trust boundary as operator tasks.
    if let Some(SafeReference::File { path }) = record.resources.get("controller_config") {
        let config = crate::controller::load_bound_control_config(path)?;
        if config.operator.deployment_id != record.deployment_id
            || config.operator.controller_key_id != record.control_authority
        {
            bail!("controller configuration is bound to a different deployment authority");
        }
        crate::operator::append_management_event_idempotent(
            &config,
            request_id,
            operation,
            release,
            "controller-state",
        )?;
        return Ok(());
    }

    let (key_id, signing) = state_audit_signing_key(store, record)?;
    let audit_dir = store
        .deployment_state_dir(&record.deployment_id)
        .join("audit");
    ensure_real_directory_or_missing(&audit_dir, "deployment management audit directory")?;
    crate::filesystem::ensure_directory_chain(&audit_dir)?;
    let entries = read_management_entries(
        store,
        record,
        &audit_dir,
        &record.deployment_id,
        &key_id,
        &signing.verifying_key(),
    )?;
    for (_, _compact, event) in &entries {
        if event.request_id == request_id {
            if event.operation != operation
                || event.release != release
                || event.recovery_boundary
                    != recovery_boundary_for(record.recovery.conclusion.clone())
            {
                bail!("management audit request ID was reused with different content");
            }
            return Ok(());
        }
    }
    let (sequence, previous_sha256) = if let Some((_, compact, event)) = entries.last() {
        (
            event
                .sequence
                .checked_add(1)
                .context("deployment management audit sequence overflow")?,
            compact_sha256(compact),
        )
    } else {
        (1, "0".repeat(64))
    };
    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: record.deployment_id.clone(),
        sequence,
        previous_sha256,
        request_id: request_id.to_owned(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: operation.to_owned(),
        release: release.to_owned(),
        recovery_boundary: recovery_boundary_for(record.recovery.conclusion.clone()).to_owned(),
    };
    let compact = sign_management_event(&event, &key_id, &signing)?;
    let path = audit_dir.join(format!("{sequence:020}.jws"));
    if path_present(&path)? {
        bail!("deployment management audit sequence path is already occupied");
    }
    atomic_write(&path, compact.as_bytes(), 0o600)?;
    Ok(())
}

fn management_audit_intent_path(
    store: &DeploymentStore,
    deployment_id: &str,
) -> std::path::PathBuf {
    store
        .deployment_state_dir(deployment_id)
        .join("transactions")
        .join("management-audit.json")
}

pub(crate) fn management_audit_intent_pending(
    store: &DeploymentStore,
    deployment_id: &str,
) -> anyhow::Result<bool> {
    path_present(&management_audit_intent_path(store, deployment_id))
}

/// Persist the smallest declaration-bound intent needed to finish a
/// management audit after a declaration CAS.  This is a recovery pointer,
/// not a second audit chain; the signed operator/governance event remains the
/// only ledger.
pub(crate) fn prepare_management_audit_intent(
    store: &DeploymentStore,
    previous: &DeploymentRecord,
    target: &DeploymentRecord,
    request_id: &str,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<()> {
    previous.validate()?;
    target.validate()?;
    let expected_revision = previous
        .declaration_revision
        .checked_add(1)
        .context("management audit declaration revision overflow")?;
    if target.deployment_id != previous.deployment_id
        || target.declaration_revision != expected_revision
    {
        bail!("management audit intent is not a single declaration revision transition");
    }
    let path = management_audit_intent_path(store, &previous.deployment_id);
    if path_present(&path)? {
        let bytes = crate::filesystem::read_secure_regular_file(
            &path,
            "management audit intent",
            true,
            MANAGEMENT_AUDIT_INTENT_MAX_BYTES,
        )?;
        let intent: ManagementAuditIntent =
            serde_json::from_slice(&bytes).context("management audit intent is invalid")?;
        if intent.schema != MANAGEMENT_AUDIT_INTENT_SCHEMA
            || intent.deployment_id != previous.deployment_id
            || intent.previous != *previous
            || intent.target != *target
            || intent.request_id != request_id
            || intent.operation != operation
            || intent.release != release
            || intent.recovery_boundary != recovery_boundary
        {
            bail!("a different management audit intent is already pending");
        }
        return Ok(());
    }
    let transactions = path
        .parent()
        .context("management audit intent has no transactions directory")?;
    crate::filesystem::ensure_directory_chain(transactions)?;
    let intent = ManagementAuditIntent {
        schema: MANAGEMENT_AUDIT_INTENT_SCHEMA,
        state: AuditIntentState::Prepared,
        request_id: request_id.to_owned(),
        deployment_id: previous.deployment_id.clone(),
        previous: previous.clone(),
        target: target.clone(),
        operation: operation.to_owned(),
        release: release.to_owned(),
        recovery_boundary: recovery_boundary.to_owned(),
    };
    write_management_audit_intent(&path, &intent)
}

fn write_management_audit_intent(
    path: &std::path::Path,
    intent: &ManagementAuditIntent,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(intent)?;
    if bytes.len() as u64 > MANAGEMENT_AUDIT_INTENT_MAX_BYTES {
        bail!("management audit intent exceeds its size limit");
    }
    atomic_write(path, &bytes, 0o600)
}

pub(crate) fn mark_management_audit_intent_committed(
    store: &DeploymentStore,
    target: &DeploymentRecord,
) -> anyhow::Result<()> {
    let path = management_audit_intent_path(store, &target.deployment_id);
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "management audit intent",
        true,
        MANAGEMENT_AUDIT_INTENT_MAX_BYTES,
    )?;
    let mut intent: ManagementAuditIntent =
        serde_json::from_slice(&bytes).context("management audit intent is invalid")?;
    if intent.schema != MANAGEMENT_AUDIT_INTENT_SCHEMA
        || intent.deployment_id != target.deployment_id
        || intent.target != *target
    {
        bail!("management audit intent does not match the committed declaration");
    }
    intent.state = AuditIntentState::DeclarationCommitted;
    write_management_audit_intent(&path, &intent)
}

pub(crate) fn finish_management_audit_intent(
    store: &DeploymentStore,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let path = management_audit_intent_path(store, deployment_id);
    if path_present(&path)? {
        crate::filesystem::remove_file_durable(&path)?;
    }
    Ok(())
}

/// Recover the declaration-bound management audit intent while the caller
/// holds the deployment lock.  A prepared intent whose declaration never
/// committed is discarded; an exact target declaration advances idempotently
/// to the signed audit event.
pub(crate) fn recover_pending_management_audit_intent_locked(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<bool> {
    let path = management_audit_intent_path(store, &record.deployment_id);
    if !path_present(&path)? {
        return Ok(false);
    }
    let bytes = crate::filesystem::read_secure_regular_file(
        &path,
        "management audit intent",
        true,
        MANAGEMENT_AUDIT_INTENT_MAX_BYTES,
    )?;
    let mut intent: ManagementAuditIntent =
        serde_json::from_slice(&bytes).context("management audit intent is invalid")?;
    if intent.schema != MANAGEMENT_AUDIT_INTENT_SCHEMA
        || intent.deployment_id != record.deployment_id
    {
        bail!("management audit intent crosses deployment boundaries");
    }
    let current = store.load(&record.deployment_id)?;
    match intent.state {
        AuditIntentState::Prepared if current == intent.previous => {
            crate::filesystem::remove_file_durable(&path)?;
            return Ok(false);
        }
        AuditIntentState::Prepared if current == intent.target => {
            intent.state = AuditIntentState::DeclarationCommitted;
            write_management_audit_intent(&path, &intent)?;
        }
        AuditIntentState::Prepared => {
            bail!("management audit declaration changed before intent recovery");
        }
        AuditIntentState::DeclarationCommitted if current != intent.target => {
            bail!("management audit declaration no longer matches its intent");
        }
        AuditIntentState::DeclarationCommitted => {}
    }
    append_management_audit(
        store,
        &current,
        &intent.request_id,
        &intent.operation,
        &intent.release,
    )?;
    finish_management_audit_intent(store, &current.deployment_id)?;
    Ok(true)
}

fn recovery_boundary_for(conclusion: RecoveryConclusion) -> &'static str {
    match conclusion {
        RecoveryConclusion::Proven => "recovery:proven",
        RecoveryConclusion::RequiresUserEvidence => "recovery:user-required",
        RecoveryConclusion::Unproven => "recovery:unproven",
    }
}

fn ensure_real_directory_or_missing(
    path: &std::path::Path,
    description: &str,
) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("{description} is not a real directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect {description} {}", path.display())),
    }
}

fn path_present(path: &std::path::Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn read_management_entries(
    _store: &DeploymentStore,
    record: &DeploymentRecord,
    directory: &std::path::Path,
    expected_deployment_id: &str,
    expected_key_id: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> anyhow::Result<Vec<(std::path::PathBuf, String, ManagementAuditEvent)>> {
    if !ensure_real_directory_or_missing(directory, "deployment management audit directory")? {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut entries = Vec::with_capacity(paths.len());
    let mut previous = "0".repeat(64);
    let mut sequence = 0_u64;
    for entry in paths {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("jws")
        {
            bail!("deployment management audit directory contains an unexpected entry");
        }
        let compact = crate::filesystem::read_secure_regular_file(
            &path,
            "deployment management audit event",
            false,
            256 * 1024,
        )?;
        let compact = std::str::from_utf8(&compact)
            .with_context(|| format!("management audit event is not UTF-8: {}", path.display()))?
            .trim()
            .to_owned();
        let header = protected_header(&compact)?;
        let event = if header.kid == expected_key_id {
            verify_management_event(&compact, &header.kid, verifying_key)?
        } else {
            let config_path = match record.resources.get("controller_config") {
                Some(SafeReference::File { path }) => path,
                _ => bail!(
                    "deployment management audit uses historical key {} without a declared controller trust archive",
                    header.kid
                ),
            };
            let config = crate::controller::load_bound_control_config(config_path)?;
            if config.operator.deployment_id != record.deployment_id
                || config.operator.controller_key_id != record.control_authority
            {
                bail!("controller configuration is bound to a different deployment authority");
            }
            let key = crate::operator::trusted_audit_key(&config, &header.kid)?;
            verify_management_event(&compact, &header.kid, &key)?
        };
        let expected_sequence = sequence
            .checked_add(1)
            .context("deployment management audit sequence overflow")?;
        if event.deployment_id != expected_deployment_id
            || event.sequence != expected_sequence
            || event.previous_sha256 != previous
        {
            bail!(
                "deployment management audit chain is discontinuous at {}",
                path.display()
            );
        }
        sequence = event.sequence;
        previous = compact_sha256(&compact);
        entries.push((path, compact, event));
    }
    Ok(entries)
}

fn state_audit_signing_key(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<(String, SigningKey)> {
    let private_path = match record.resources.get("audit_private_key") {
        Some(SafeReference::File { path }) => path.clone(),
        _ => store
            .deployment_state_dir(&record.deployment_id)
            .join("identities")
            .join("audit.key"),
    };
    let encoded =
        crate::filesystem::read_secure_regular_file(&private_path, "audit private key", true, 256)?;
    let encoded = std::str::from_utf8(&encoded)
        .with_context(|| format!("audit private key is not UTF-8: {}", private_path.display()))?;
    let private = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("audit private key is invalid")?;
    let private: [u8; 32] = private
        .try_into()
        .map_err(|_| anyhow::anyhow!("audit private key has an invalid length"))?;
    let signing = SigningKey::from_bytes(&private);
    let key_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key()).replacen(
        "instance-",
        "audit-",
        1,
    );
    Ok((key_id, signing))
}

fn state_audit_verifying_key(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<(String, VerifyingKey)> {
    let public_path = match record.resources.get("audit_public_key") {
        Some(SafeReference::File { path }) => path.clone(),
        _ => match record.resources.get("audit_private_key") {
            Some(SafeReference::File { path }) => path.with_file_name("audit.pub"),
            _ => store
                .deployment_state_dir(&record.deployment_id)
                .join("identities")
                .join("audit.pub"),
        },
    };
    let encoded =
        crate::filesystem::read_secure_regular_file(&public_path, "audit public key", false, 256)?;
    let encoded = std::str::from_utf8(&encoded)
        .with_context(|| format!("audit public key is not UTF-8: {}", public_path.display()))?;
    let public = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("audit public key is invalid")?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("audit public key has an invalid length"))?;
    let verifying = VerifyingKey::from_bytes(&public).context("audit public key is invalid")?;
    let key_id =
        nazo_operator_protocol::instance_key_id(&verifying).replacen("instance-", "audit-", 1);
    Ok((key_id, verifying))
}

/// Verify the deployment-owned governance chain without repairing any
/// derived state.  The returned tuple is `(last_sequence, last_hash)`.
pub(crate) fn verify_management_audit(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<(u64, String)> {
    let directory = store
        .deployment_state_dir(&record.deployment_id)
        .join("audit");
    if !ensure_real_directory_or_missing(&directory, "deployment management audit directory")? {
        return Ok((0, "0".repeat(64)));
    }
    let (key_id, verifying) = state_audit_verifying_key(store, record)?;
    let entries = read_management_entries(
        store,
        record,
        &directory,
        &record.deployment_id,
        &key_id,
        &verifying,
    )?;
    Ok(entries
        .last()
        .map_or((0, "0".repeat(64)), |(_, compact, event)| {
            (event.sequence, compact_sha256(compact))
        }))
}

pub(crate) fn management_audit_entries(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    request_id: Option<&str>,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let directory = store
        .deployment_state_dir(&record.deployment_id)
        .join("audit");
    if !ensure_real_directory_or_missing(&directory, "deployment management audit directory")? {
        return Ok(Vec::new());
    }
    let (key_id, verifying) = state_audit_verifying_key(store, record)?;
    let entries = read_management_entries(
        store,
        record,
        &directory,
        &record.deployment_id,
        &key_id,
        &verifying,
    )?;
    let mut values = Vec::new();
    for (_, compact, event) in entries {
        if request_id.is_some_and(|expected| expected != event.request_id) {
            continue;
        }
        let event_key_id = protected_header(&compact)?.kid;
        values.push(serde_json::json!({
            "kind": "deployment-management-event",
            "key_id": event_key_id,
            "event": event,
        }));
    }
    Ok(values)
}

fn write_handoff(store: &DeploymentStore, record: &DeploymentRecord) -> anyhow::Result<()> {
    let path = store
        .deployment_state_dir(&record.deployment_id)
        .join("recovery")
        .join(format!("handoff-{:020}.json", record.declaration_revision));
    atomic_write(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1,
            "deployment_id": record.deployment_id,
            "declaration_revision": record.declaration_revision,
            "runtime_instances": record.runtime_instances,
            "resources": record.resources,
            "capabilities": record.capabilities,
            "recovery": record.recovery,
            "created_at": Utc::now().to_rfc3339(),
            "resources_deleted": false,
        }))?,
        0o600,
    )
}

pub(crate) fn reconcile(selector: Option<&str>) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let record = store.resolve(selector, false)?;
    let mut drift = Vec::new();
    for runtime in &record.runtime_instances {
        let observation = backend(runtime.backend).inspect(&runtime.object_reference)?;
        let artifact_matches = runtime.local_artifact_id.as_ref().map_or_else(
            || observation.artifact == runtime.artifact,
            |expected| observation.local_artifact_id.as_ref() == Some(expected),
        );
        if !artifact_matches {
            drift.push(format!("{}:artifact", runtime.runtime_instance_id));
        }
        let surface =
            crate::runtime_backend::compare_declared_runtime_surface(runtime, &observation)?;
        if surface.ports {
            drift.push(format!("{}:ports", runtime.runtime_instance_id));
        }
        if surface.networks {
            drift.push(format!("{}:networks", runtime.runtime_instance_id));
        }
        if surface.mounts {
            drift.push(format!("{}:mounts", runtime.runtime_instance_id));
        }
    }
    let managed_drift = !drift.is_empty()
        && (record.capabilities.runtime.responsibility == Responsibility::Managed
            || record.capabilities.artifact.responsibility == Responsibility::Managed);
    let report = serde_json::json!({
        "schema": 1,
        "deployment_id": record.deployment_id,
        "declaration_revision": record.declaration_revision,
        "drift": drift,
        "action": if managed_drift { "fail-closed" } else { "report-only" },
        "external_resources_overwritten": false,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    if managed_drift {
        bail!("managed runtime drift requires explicit re-verification");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/governance.rs"]
mod tests;
