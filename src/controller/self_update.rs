use super::*;

pub(super) fn controller_state_directory() -> anyhow::Result<PathBuf> {
    let store = DeploymentStore::system();
    store.validate_failure_domains()?;
    Ok(store.state_root.join("controller-self"))
}

pub(super) fn controller_check(version: Option<&str>) -> anyhow::Result<()> {
    verify_controller_self_audit()?;
    let release = crate::release::VerifiedControllerRelease::fetch(version, None)?;
    enforce_controller_trust(&release.version, &release.sha256)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "installed": env!("CARGO_PKG_VERSION"),
            "candidate": release.version,
            "sha256": release.sha256,
            "repository": "nazozero/NazoAuthCtl",
        }))?
    );
    Ok(())
}

pub(super) fn controller_update(version: Option<&str>) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _lock = store.controller_self_lock()?;
    verify_controller_self_audit()?;
    controller_self_audit_signer()?;
    let release = crate::release::VerifiedControllerRelease::fetch(version, None)?;
    enforce_controller_trust(&release.version, &release.sha256)?;
    let directory = controller_state_directory()?;
    fs::create_dir_all(&directory)?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    let previous_sha256 = crate::filesystem::sha256(&current)?;
    let previous_version = controller_trust_state()?
        .map(|state| state.version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    append_controller_self_audit(
        "controller-update-intent",
        &previous_version,
        &release.version,
        &release.sha256,
    )?;
    let rollback_artifact = directory.join(format!("rollback-{previous_sha256}"));
    copy_atomic(&current, &rollback_artifact, 0o500)?;
    let staged = directory.join(format!("candidate-{}", release.sha256));
    copy_atomic(&release.artifact(), &staged, 0o500)?;
    Process::new(&staged).arg("--help").run_quiet()?;
    release.persist_evidence(&directory.join("evidence").join(&release.version))?;
    atomic_write(
        &directory.join("update-transaction.json"),
        &serde_json::to_vec_pretty(&ControllerUpdateJournal {
            schema: 1,
            from_version: previous_version.clone(),
            from_sha256: previous_sha256.clone(),
            to_version: release.version.clone(),
            to_sha256: release.sha256.clone(),
            staged_artifact: staged.clone(),
        })?,
        0o600,
    )?;
    copy_atomic(&staged, &install_path, 0o755)?;
    if crate::filesystem::sha256(&install_path)? != release.sha256 {
        bail!("installed controller digest differs from the verified candidate");
    }
    atomic_write(
        &directory.join("rollback.json"),
        &serde_json::to_vec_pretty(&ControllerRollbackState {
            schema: 1,
            version: previous_version.clone(),
            sha256: previous_sha256,
            artifact: rollback_artifact,
        })?,
        0o600,
    )?;
    write_controller_trust(&release.version, &release.sha256)?;
    remove_file_durable(&directory.join("update-transaction.json"))?;
    remove_file_durable(&staged)?;
    append_controller_self_audit(
        "controller-update",
        &previous_version,
        &release.version,
        &release.sha256,
    )?;
    println!("nazoauthctl updated independently to {}", release.version);
    Ok(())
}

pub(super) fn controller_rollback() -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _lock = store.controller_self_lock()?;
    verify_controller_self_audit()?;
    controller_self_audit_signer()?;
    let directory = controller_state_directory()?;
    let state: ControllerRollbackState = serde_json::from_slice(
        &fs::read(directory.join("rollback.json"))
            .context("controller rollback state is unavailable")?,
    )
    .context("controller rollback state is invalid")?;
    if state.schema != 1 || crate::filesystem::sha256(&state.artifact)? != state.sha256 {
        bail!("controller rollback artifact is not the persisted trusted binary");
    }
    let from_version = controller_trust_state()?
        .map(|value| value.version)
        .unwrap_or_else(|| "unknown".to_owned());
    append_controller_self_audit(
        "controller-rollback-intent",
        &from_version,
        &state.version,
        &state.sha256,
    )?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    copy_atomic(&state.artifact, &install_path, 0o755)?;
    if crate::filesystem::sha256(&install_path)? != state.sha256 {
        bail!("restored controller digest differs from rollback state");
    }
    write_controller_trust(&state.version, &state.sha256)?;
    append_controller_self_audit(
        "controller-rollback",
        &from_version,
        &state.version,
        &state.sha256,
    )?;
    println!("nazoauthctl rolled back independently to {}", state.version);
    Ok(())
}

pub(super) fn controller_trust_state() -> anyhow::Result<Option<ControllerTrustState>> {
    let path = controller_state_directory()?.join("trust.json");
    if !path.exists() {
        return Ok(None);
    }
    let state: ControllerTrustState =
        serde_json::from_slice(&fs::read(path)?).context("controller trust state is invalid")?;
    if state.schema != 1 || state.sha256.len() != 64 {
        bail!("controller trust state has an unsupported schema");
    }
    Ok(Some(state))
}

pub(super) fn enforce_controller_trust(version: &str, sha256: &str) -> anyhow::Result<()> {
    let Some(state) = controller_trust_state()? else {
        return Ok(());
    };
    match compare_versions(version, &state.version)? {
        std::cmp::Ordering::Less => {
            bail!("controller anti-downgrade policy requires explicit self rollback")
        }
        std::cmp::Ordering::Equal if state.sha256 != sha256 => {
            bail!("immutable controller Release changed for an already trusted version")
        }
        _ => Ok(()),
    }
}

pub(super) fn write_controller_trust(version: &str, sha256: &str) -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    fs::create_dir_all(&directory)?;
    atomic_write(
        &directory.join("trust.json"),
        &serde_json::to_vec_pretty(&ControllerTrustState {
            schema: 1,
            version: version.to_owned(),
            sha256: sha256.to_owned(),
        })?,
        0o600,
    )
}

pub(super) fn controller_install_path(current: &Path) -> anyhow::Result<PathBuf> {
    let path = current.to_path_buf();
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("controller install path must be a normalized absolute file path");
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("controller install path must be a regular non-symlink file");
        }
    }
    Ok(path)
}

pub(super) fn controller_self_audit_directory() -> anyhow::Result<PathBuf> {
    Ok(controller_state_directory()?.join("audit"))
}

pub(super) fn controller_self_audit_signer() -> anyhow::Result<(String, SigningKey)> {
    let identity = controller_state_directory()?.join("identity");
    fs::create_dir_all(&identity)?;
    let private_path = identity.join("audit.key");
    let public_path = identity.join("audit.pub");
    if private_path.exists() != public_path.exists() {
        bail!("controller self-audit identity is incomplete");
    }
    if !private_path.exists() {
        let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        atomic_write(
            &private_path,
            URL_SAFE_NO_PAD.encode(key.to_bytes()).as_bytes(),
            0o400,
        )?;
        atomic_write(
            &public_path,
            URL_SAFE_NO_PAD
                .encode(key.verifying_key().to_bytes())
                .as_bytes(),
            0o444,
        )?;
    }
    let private = URL_SAFE_NO_PAD
        .decode(fs::read_to_string(&private_path)?.trim())
        .context("controller self-audit private key is invalid")?;
    let private: [u8; 32] = private
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller self-audit private key has invalid length"))?;
    let key = SigningKey::from_bytes(&private);
    let public = URL_SAFE_NO_PAD
        .decode(fs::read_to_string(&public_path)?.trim())
        .context("controller self-audit public key is invalid")?;
    if public != key.verifying_key().to_bytes() {
        bail!("controller self-audit key pair does not match");
    }
    let key_id = format!(
        "controller-self-audit-{}",
        &crate::filesystem::sha256(&public_path)?[..16]
    );
    Ok((key_id, key))
}

pub(super) fn verify_controller_self_audit() -> anyhow::Result<(u64, String)> {
    let directory = controller_self_audit_directory()?;
    if !directory.exists() {
        return Ok((0, "0".repeat(64)));
    }
    let public_path = controller_state_directory()?
        .join("identity")
        .join("audit.pub");
    let public = URL_SAFE_NO_PAD
        .decode(fs::read_to_string(&public_path)?.trim())
        .context("controller self-audit public key is invalid")?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller self-audit public key has invalid length"))?;
    let verifying_key = VerifyingKey::from_bytes(&public)?;
    let key_id = format!(
        "controller-self-audit-{}",
        &crate::filesystem::sha256(&public_path)?[..16]
    );
    let records = directory.join("records");
    let mut entries = if records.exists() {
        fs::read_dir(&records)?.collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut sequence = 0u64;
    let mut previous = "0".repeat(64);
    for entry in entries {
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            bail!("controller self-audit record directory contains an unexpected entry");
        }
        let bytes = fs::read(entry.path())?;
        let record: ControllerSelfAuditRecord =
            serde_json::from_slice(&bytes).context("controller self-audit record is invalid")?;
        if record.schema != 1
            || record.key_id != key_id
            || record.event.schema != 1
            || record.event.sequence != sequence + 1
            || record.event.previous_sha256 != previous
        {
            bail!("controller self-audit chain is discontinuous");
        }
        let signature = URL_SAFE_NO_PAD
            .decode(&record.signature)
            .context("controller self-audit signature is invalid")?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| anyhow::anyhow!("controller self-audit signature has invalid length"))?;
        verifying_key
            .verify(&serde_json::to_vec(&record.event)?, &signature)
            .map_err(|_| anyhow::anyhow!("controller self-audit signature verification failed"))?;
        sequence = record.event.sequence;
        previous = encode_controller_digest(&Sha256::digest(&bytes));
    }
    let head_path = directory.join("head.json");
    if sequence == 0 {
        if head_path.exists() {
            bail!("controller self-audit head exists without records");
        }
    } else {
        let head: ControllerSelfAuditHead = serde_json::from_slice(&fs::read(&head_path)?)
            .context("controller self-audit head is invalid")?;
        if head.schema != 1 || head.sequence != sequence || head.sha256 != previous {
            bail!("controller self-audit head does not match the verified chain");
        }
    }
    Ok((sequence, previous))
}

pub(super) fn append_controller_self_audit(
    operation: &str,
    from_version: &str,
    to_version: &str,
    artifact_sha256: &str,
) -> anyhow::Result<()> {
    let (sequence, previous) = verify_controller_self_audit()?;
    let (key_id, signer) = controller_self_audit_signer()?;
    let event = ControllerSelfAuditEvent {
        schema: 1,
        sequence: sequence + 1,
        previous_sha256: previous,
        operation: operation.to_owned(),
        from_version: from_version.to_owned(),
        to_version: to_version.to_owned(),
        artifact_sha256: artifact_sha256.to_owned(),
        recorded_at: Utc::now().to_rfc3339(),
    };
    let signature = signer.sign(&serde_json::to_vec(&event)?);
    let record = ControllerSelfAuditRecord {
        schema: 1,
        key_id,
        event,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    let bytes = serde_json::to_vec_pretty(&record)?;
    let directory = controller_self_audit_directory()?;
    let records = directory.join("records");
    fs::create_dir_all(&records)?;
    atomic_write(
        &records.join(format!("{:020}.json", sequence + 1)),
        &bytes,
        0o400,
    )?;
    atomic_write(
        &directory.join("head.json"),
        &serde_json::to_vec_pretty(&ControllerSelfAuditHead {
            schema: 1,
            sequence: sequence + 1,
            sha256: encode_controller_digest(&Sha256::digest(&bytes)),
        })?,
        0o600,
    )
}

pub(super) fn encode_controller_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) const OPENID4VC_CERTIFICATE_BUNDLE: &str = "openid4vc-certificate-bundle.pem";
pub(super) const OPENID4VC_REVOCATION_SNAPSHOT: &str = "openid4vc-revocation-snapshot.json";
pub(super) const OPENID4VC_KEYS_MOUNT: &str = "/var/lib/nazo_oauth/keys";
pub(super) const MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES: usize = 1024 * 1024;
