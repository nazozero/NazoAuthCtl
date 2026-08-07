use super::*;

pub(crate) fn append_management_event(
    config: &UpdateConfig,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    let request_id = format!("request-{}", encode_hex(&rand::random::<[u8; 16]>()));
    append_management_event_idempotent(config, &request_id, operation, release, recovery_boundary)
}

pub(crate) fn append_management_event_idempotent(
    config: &UpdateConfig,
    request_id: &str,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    verify_audit_chain(config)?;
    let directory = config.operator.audit_directory.join("management");
    fs::create_dir_all(&directory)?;
    let suffix = format!("-{request_id}.jws");
    let existing = fs::read_dir(&directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry.file_name().to_string_lossy().ends_with(&suffix)
        })
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        bail!("management audit request id is not unique");
    }
    if let Some(entry) = existing.first() {
        let file_name = entry.file_name();
        let event = load_management_event(config, &file_name.to_string_lossy())?;
        if event.request_id != request_id
            || event.operation != operation
            || event.release != release
            || event.recovery_boundary != recovery_boundary
        {
            bail!("management audit request id was reused with different content");
        }
        return Ok(entry.path());
    }
    let head_path = config.operator.audit_directory.join("management-head.json");
    let (sequence, previous) = if head_path.exists() {
        let head: AuditHead = serde_json::from_slice(&fs::read(&head_path)?)?;
        (head.sequence + 1, head.sha256)
    } else {
        (1, "0".repeat(64))
    };
    let event = ManagementAuditEvent {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        sequence,
        previous_sha256: previous,
        request_id: request_id.to_owned(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: operation.to_owned(),
        release: release.to_owned(),
        recovery_boundary: recovery_boundary.to_owned(),
    };
    let key = read_signing_key(&config.operator.audit_private_key)?;
    let compact = sign_management_event(&event, &config.operator.audit_key_id, &key)?;
    let path = directory.join(format!("{sequence:020}-{request_id}.jws"));
    atomic_write(&path, compact.as_bytes(), 0o400)?;
    atomic_write(
        &head_path,
        &serde_json::to_vec_pretty(&AuditHead {
            sequence,
            sha256: compact_sha256(&compact),
        })?,
        0o600,
    )?;
    Ok(path)
}

pub(crate) fn load_management_event(
    config: &UpdateConfig,
    file_name: &str,
) -> anyhow::Result<ManagementAuditEvent> {
    verify_audit_chain(config)?;
    let candidate = Path::new(file_name);
    if candidate.components().count() != 1 || candidate.file_name().is_none() {
        bail!("management audit event must be a plain file name");
    }
    let path = config
        .operator
        .audit_directory
        .join("management")
        .join(candidate);
    let compact = fs::read_to_string(&path)
        .with_context(|| format!("failed to read management audit event {}", path.display()))?;
    let header = protected_header(&compact)?;
    let key = trusted_audit_key(config, &header.kid)?;
    let event = verify_management_event(&compact, &header.kid, &key)?;
    if event.deployment_id != config.operator.deployment_id {
        bail!("management audit event belongs to a different deployment");
    }
    Ok(event)
}

pub(crate) fn verify_management_events(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("management");
    let head_path = config.operator.audit_directory.join("management-head.json");
    if !is_real_directory_or_missing(&directory, "management audit directory")? {
        if path_present(&head_path)? {
            bail!("management audit directory is missing while a management audit head exists");
        }
        return Ok(());
    }
    let mut paths = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut sequence = 0;
    let mut previous = "0".repeat(64);
    let mut checkpoints = BTreeMap::from([(0_u64, previous.clone())]);
    for entry in paths {
        if !entry.file_type()?.is_file() {
            bail!("management audit directory contains an unexpected entry");
        }
        let compact = fs::read_to_string(entry.path())?;
        let header = protected_header(&compact)?;
        let key = trusted_audit_key(config, &header.kid)?;
        let event = verify_management_event(&compact, &header.kid, &key)?;
        if event.sequence != sequence + 1
            || event.previous_sha256 != previous
            || event.deployment_id != config.operator.deployment_id
        {
            bail!("management audit chain is discontinuous");
        }
        if event.operation == "controller-retirement-probe" {
            validate_retirement_probe_audit_evidence(&event.recovery_boundary)?;
        }
        sequence = event.sequence;
        previous = compact_sha256(&compact);
        checkpoints.insert(sequence, previous.clone());
    }
    let head = if head_path.exists() {
        Some(serde_json::from_slice::<AuditHead>(&fs::read(&head_path)?)?)
    } else {
        None
    };
    if let Some(head) = &head
        && (head.sequence > sequence || checkpoints.get(&head.sequence) != Some(&head.sha256))
    {
        bail!("management audit head conflicts with the verified chain");
    }
    if head.is_none_or(|head| head.sequence != sequence || head.sha256 != previous) {
        atomic_write(
            &head_path,
            &serde_json::to_vec_pretty(&AuditHead {
                sequence,
                sha256: previous,
            })?,
            0o600,
        )?;
    }
    Ok(())
}
