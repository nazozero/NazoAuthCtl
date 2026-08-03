use std::{collections::BTreeSet, fs};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    Actor, ActorKind, ManagementAuditEvent, PROTOCOL_VERSION, sign_management_event,
    verify_management_event,
};
use serde::{Deserialize, Serialize};

use crate::{
    deployment::{
        Capability, CapabilityGrant, DeploymentRecord, DeploymentStore, RecoveryConclusion,
        ResourceScope, Responsibility, TrustState,
    },
    filesystem::{atomic_write, remove_file_durable, sha256},
    runtime_backend::backend,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TransitionState {
    Prepared,
    DeclarationCommitted,
    Committed,
}

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
    let resolved = store.resolve(selector, true)?;
    let _registry_lock = store.registry_lock()?;
    let _deployment_lock = store.deployment_lock(&resolved.deployment_id)?;
    let record = store.load(&resolved.deployment_id)?;
    if record.trust != TrustState::Adopted {
        bail!("capabilities cannot change until the deployment is adopted");
    }
    let active_path = store
        .deployment_state_dir(&record.deployment_id)
        .join("transactions")
        .join("capability-transition.json");
    let mut transaction = if active_path.exists() {
        let transaction: CapabilityTransition = serde_json::from_slice(&fs::read(&active_path)?)
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
                store.persist_locked(&transaction.target)?;
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
        && grant.responsibility == Responsibility::Managed
        && record.runtime_instances.iter().any(|runtime| {
            backend(runtime.backend)
                .verify_ownership(
                    &runtime.object_reference,
                    &record.deployment_id,
                    &record.control_authority,
                )
                .is_err()
        })
    {
        bail!(
            "runtime cannot become managed without exact deployment and control-authority labels"
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
    let identity_dir = store
        .deployment_state_dir(&transaction.target.deployment_id)
        .join("identities");
    let private = URL_SAFE_NO_PAD
        .decode(fs::read_to_string(identity_dir.join("audit.key"))?.trim())
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
    let audit_dir = store
        .deployment_state_dir(&transaction.target.deployment_id)
        .join("audit");
    fs::create_dir_all(&audit_dir)?;
    let mut entries = fs::read_dir(&audit_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "jws"))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in &entries {
        let compact = fs::read_to_string(entry.path())?;
        let event = verify_management_event(compact.trim(), &key_id, &signing.verifying_key())?;
        if event.request_id == transaction.request_id {
            return Ok(());
        }
    }
    let (sequence, previous_sha256) = if let Some(last) = entries.last() {
        let compact = fs::read_to_string(last.path())?;
        let event = verify_management_event(compact.trim(), &key_id, &signing.verifying_key())?;
        (event.sequence + 1, sha256(&last.path())?)
    } else {
        (1, "0".repeat(64))
    };
    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: transaction.target.deployment_id.clone(),
        sequence,
        previous_sha256,
        request_id: transaction.request_id.clone(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: transaction.operation.clone(),
        release: "controller-state".to_owned(),
        recovery_boundary: match transaction.target.recovery.conclusion {
            RecoveryConclusion::Proven => "recovery:proven",
            RecoveryConclusion::RequiresUserEvidence => "recovery:user-required",
            RecoveryConclusion::Unproven => "recovery:unproven",
        }
        .to_owned(),
    };
    let compact = sign_management_event(&event, &key_id, &signing)?;
    atomic_write(
        &audit_dir.join(format!("{sequence:020}.jws")),
        compact.as_bytes(),
        0o600,
    )
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
        if observation.artifact != runtime.artifact {
            drift.push(format!("{}:artifact", runtime.runtime_instance_id));
        }
        if sorted(&observation.ports) != sorted(&runtime.ports) {
            drift.push(format!("{}:ports", runtime.runtime_instance_id));
        }
        if sorted(&observation.networks) != sorted(&runtime.networks) {
            drift.push(format!("{}:networks", runtime.runtime_instance_id));
        }
        let expected_mounts = runtime
            .mounts
            .iter()
            .map(|mount| {
                format!(
                    "{}:{}:{}:{}",
                    mount.source.display(),
                    mount.destination.display(),
                    mount.read_only,
                    mount.selinux_relabel
                )
            })
            .collect::<BTreeSet<_>>();
        let actual_mounts = observation
            .mounts
            .iter()
            .map(|mount| {
                format!(
                    "{}:{}:{}:{}",
                    mount.source.display(),
                    mount.destination.display(),
                    mount.read_only,
                    mount.selinux_relabel
                )
            })
            .collect::<BTreeSet<_>>();
        if expected_mounts != actual_mounts {
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

fn sorted(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

#[cfg(test)]
#[path = "../tests/unit/governance.rs"]
mod tests;
