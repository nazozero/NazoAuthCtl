use super::*;

pub(super) struct Identities {
    pub(super) controller_key_id: String,
    pub(super) receipt_key_id: String,
    pub(super) receipt: SigningKey,
    pub(super) audit: SigningKey,
}

pub(super) fn create_identities(
    store: &DeploymentStore,
    deployment_id: &str,
) -> anyhow::Result<Identities> {
    let active = store.deployment_state_dir(deployment_id).join("identities");
    let break_glass = store.break_glass_dir(deployment_id);
    fs::create_dir_all(&active)?;
    fs::create_dir_all(&break_glass)?;
    let controller = create_identity(&active, "controller")?;
    let receipt = create_identity(&active, "receipt")?;
    let audit = create_identity(&active, "audit")?;
    let break_glass_identity = create_identity(&break_glass, "break-glass")?;
    let identity_ids = [
        controller.0.as_str(),
        receipt.0.as_str(),
        audit.0.as_str(),
        break_glass_identity.0.as_str(),
    ];
    if identity_ids
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != identity_ids.len()
    {
        bail!("deployment identities are not distinct");
    }
    Ok(Identities {
        controller_key_id: controller.0,
        receipt_key_id: receipt.0,
        receipt: receipt.1,
        audit: audit.1,
    })
}

fn create_identity(directory: &Path, name: &str) -> anyhow::Result<(String, SigningKey)> {
    let private_path = directory.join(format!("{name}.key"));
    let public_path = directory.join(format!("{name}.pub"));
    if private_path.exists() {
        let private = URL_SAFE_NO_PAD
            .decode(fs::read_to_string(&private_path)?.trim())
            .context("stored identity private key is invalid")?;
        let private: [u8; 32] = private
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored identity private key has an invalid length"))?;
        let signing = SigningKey::from_bytes(&private);
        let public = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        if public_path.exists() {
            if fs::read_to_string(&public_path)?.trim() != public {
                bail!("stored identity public key does not match its private key");
            }
        } else {
            atomic_write(&public_path, public.as_bytes(), 0o640)?;
        }
        let key_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key()).replacen(
            "instance-",
            &format!("{name}-"),
            1,
        );
        return Ok((key_id, signing));
    }
    if public_path.exists() {
        bail!("stored identity has a public key but no private key");
    }
    let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let key_id = nazo_operator_protocol::instance_key_id(&signing.verifying_key()).replacen(
        "instance-",
        &format!("{name}-"),
        1,
    );
    atomic_write(
        &private_path,
        URL_SAFE_NO_PAD.encode(signing.to_bytes()).as_bytes(),
        0o600,
    )?;
    atomic_write(
        &public_path,
        URL_SAFE_NO_PAD
            .encode(signing.verifying_key().to_bytes())
            .as_bytes(),
        0o640,
    )?;
    Ok((key_id, signing))
}

pub(super) fn initialize_audit(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    key: &SigningKey,
) -> anyhow::Result<()> {
    let key_id = nazo_operator_protocol::instance_key_id(&key.verifying_key()).replacen(
        "instance-",
        "audit-",
        1,
    );
    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: record.deployment_id.clone(),
        sequence: 1,
        previous_sha256: "0".repeat(64),
        request_id: uuid::Uuid::now_v7().to_string(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: if record.trust == TrustState::Adopted {
            "adopt"
        } else {
            "observe"
        }
        .to_owned(),
        release: record
            .runtime_instances
            .first()
            .map(|_| "verified-release")
            .unwrap_or("unknown")
            .to_owned(),
        recovery_boundary: match record.recovery.conclusion {
            RecoveryConclusion::Proven => "recovery:proven",
            RecoveryConclusion::RequiresUserEvidence => "recovery:user-required",
            RecoveryConclusion::Unproven => "recovery:unproven",
        }
        .to_owned(),
    };
    let compact = sign_management_event(&event, &key_id, key)?;
    atomic_write(
        &store
            .deployment_state_dir(&record.deployment_id)
            .join("audit")
            .join("00000000000000000001.jws"),
        compact.as_bytes(),
        0o600,
    )
}
