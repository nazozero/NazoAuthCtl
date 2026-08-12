use super::*;

pub(crate) fn audit_head(config: &UpdateConfig) -> anyhow::Result<(u64, String)> {
    verify_audit_chain(config)?;
    let path = config.operator.audit_directory.join("head.json");
    if !is_regular_non_symlink(&path)? {
        return Ok((1, "0".repeat(64)));
    }
    let head_bytes =
        crate::filesystem::read_secure_regular_file(&path, "audit head", true, 16 * 1024)?;
    let head: AuditHead = serde_json::from_slice(&head_bytes)?;
    Ok((
        head.sequence
            .checked_add(1)
            .context("audit sequence overflow")?,
        head.sha256,
    ))
}

pub(crate) fn append_audit(
    config: &UpdateConfig,
    sequence: u64,
    request_id: &str,
    compact_final: &str,
) -> anyhow::Result<PathBuf> {
    let receipts = config.operator.audit_directory.join("receipts");
    is_real_directory_or_missing(&receipts, "audit receipt directory")?;
    crate::filesystem::ensure_directory_chain(&receipts)?;
    let path = receipts.join(format!("{sequence:020}-{request_id}.jws"));
    atomic_write(&path, compact_final.as_bytes(), 0o400)?;
    let digest = compact_sha256(compact_final);
    atomic_write(
        &config.operator.audit_directory.join("head.json"),
        &serde_json::to_vec_pretty(&AuditHead {
            sequence,
            sha256: digest,
        })?,
        0o600,
    )?;
    Ok(path)
}

pub(crate) fn verify_audit(config: &UpdateConfig) -> anyhow::Result<()> {
    let (sequence, head) = verify_audit_chain(config)?;
    if sequence == 0 {
        eprintln!("audit: empty chain verified");
    } else {
        eprintln!("audit: verified {sequence} signed checkpoints; head={head}");
    }
    Ok(())
}

pub(crate) fn verify_audit_chain(config: &UpdateConfig) -> anyhow::Result<(u64, String)> {
    let _receipts = config.operator.audit_directory.join("receipts");
    let head_path = config.operator.audit_directory.join("head.json");
    let (sequence, previous) = verify_receipt_chain(config)?;
    let head = if is_regular_non_symlink(&head_path)? {
        Some(serde_json::from_slice::<AuditHead>(
            &crate::filesystem::read_secure_regular_file(
                &head_path,
                "audit head",
                true,
                16 * 1024,
            )?,
        )?)
    } else if path_present(&head_path)? {
        bail!("audit head must be a regular non-symlink file");
    } else {
        None
    };
    if let Some(head) = &head
        && (head.sequence != sequence || head.sha256 != previous)
    {
        bail!("audit head conflicts with the verified receipt chain");
    }
    if sequence > 0 && head.is_none() {
        bail!("audit head is missing while signed receipts exist");
    }
    if sequence == 0 && head.is_some() {
        bail!("audit head exists without a signed receipt chain");
    }
    verify_pending_intents(config)?;
    verify_management_events(config)?;
    verify_trust_transitions(config)?;
    Ok((sequence, previous))
}

/// Rebuild the derived receipt head only from a verified chain.  This is
/// intentionally callable from writer/recovery paths, never from the
/// read-only verify/show commands.
pub(crate) fn repair_audit_head_for_append(config: &UpdateConfig) -> anyhow::Result<()> {
    let (sequence, previous) = verify_receipt_chain(config)?;
    let head_path = config.operator.audit_directory.join("head.json");
    if path_present(&head_path)? && !is_regular_non_symlink(&head_path)? {
        bail!("audit head must be a regular non-symlink file");
    }
    if sequence == 0 {
        if path_present(&head_path)? {
            crate::filesystem::remove_file_durable(&head_path)?;
        }
        return Ok(());
    }
    let needs_write = if is_regular_non_symlink(&head_path)? {
        let head: AuditHead =
            serde_json::from_slice(&crate::filesystem::read_secure_regular_file(
                &head_path,
                "audit head",
                true,
                16 * 1024,
            )?)?;
        head.sequence != sequence || head.sha256 != previous
    } else {
        true
    };
    if needs_write {
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

fn verify_receipt_chain(config: &UpdateConfig) -> anyhow::Result<(u64, String)> {
    let receipts = config.operator.audit_directory.join("receipts");
    if !is_real_directory_or_missing(&receipts, "audit receipt directory")? {
        return Ok((0, "0".repeat(64)));
    }
    let mut paths = fs::read_dir(&receipts)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut previous = "0".repeat(64);
    let mut sequence = 0_u64;
    for entry in paths {
        if !is_regular_non_symlink(&entry.path())?
            || entry.path().extension().and_then(|v| v.to_str()) != Some("jws")
        {
            bail!("audit receipt directory contains an unexpected entry");
        }
        let compact = read_audit_text(&entry.path(), "audit receipt")?;
        let header = protected_header(&compact)?;
        let key = trusted_audit_key(config, &header.kid)?;
        let receipt = verify_final_receipt(&compact, &header.kid, &key)?;
        let expected_sequence = sequence.checked_add(1).context("audit sequence overflow")?;
        if receipt.audit_sequence != expected_sequence || receipt.audit_previous_sha256 != previous
        {
            bail!(
                "audit receipt chain is discontinuous at {}",
                entry.path().display()
            );
        }
        sequence = receipt.audit_sequence;
        previous = compact_sha256(&compact);
    }
    Ok((sequence, previous))
}

pub(crate) fn show_audit(config: &UpdateConfig, request_id: Option<&str>) -> anyhow::Result<()> {
    let entries = audit_entries(config, request_id)?;
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

pub(crate) fn audit_entries(
    config: &UpdateConfig,
    request_id: Option<&str>,
) -> anyhow::Result<Vec<serde_json::Value>> {
    verify_audit_chain(config)?;
    let mut entries = Vec::new();
    let intents = config.operator.audit_directory.join("intents");
    if is_real_directory_or_missing(&intents, "operator intent directory")? {
        let mut paths = fs::read_dir(&intents)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            if !is_regular_non_symlink(&entry.path())?
                || entry.path().extension().and_then(|value| value.to_str()) != Some("jws")
            {
                bail!("operator intent directory contains an unexpected entry");
            }
            let compact = read_audit_text(&entry.path(), "operator task intent")?;
            let header = protected_header(&compact)?;
            let task = verify_task_signature(
                &compact,
                &header.kid,
                &trusted_controller_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == task.jti) {
                entries.push(serde_json::json!({
                    "kind": "pending-task-intent",
                    "key_id": header.kid,
                    "task": task,
                }));
            }
        }
    }
    let receipts = config.operator.audit_directory.join("receipts");
    if is_real_directory_or_missing(&receipts, "audit receipt directory")? {
        let mut paths = fs::read_dir(&receipts)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            let compact = read_audit_text(&entry.path(), "audit receipt")?;
            let header = protected_header(&compact)?;
            let receipt = verify_final_receipt(
                &compact,
                &header.kid,
                &trusted_audit_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == receipt.jti) {
                entries.push(serde_json::json!({
                    "kind": "task-receipt",
                    "key_id": header.kid,
                    "receipt": receipt,
                }));
            }
        }
    }
    let management = config.operator.audit_directory.join("management");
    if is_real_directory_or_missing(&management, "management audit directory")? {
        let mut paths = fs::read_dir(&management)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            let compact = read_audit_text(&entry.path(), "management audit event")?;
            let header = protected_header(&compact)?;
            let event = verify_management_event(
                &compact,
                &header.kid,
                &trusted_audit_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == event.request_id) {
                entries.push(serde_json::json!({
                    "kind": "management-event",
                    "key_id": header.kid,
                    "event": event,
                }));
            }
        }
    }
    if request_id.is_none() {
        let transitions = config.operator.audit_directory.join("trust-transitions");
        if is_real_directory_or_missing(&transitions, "trust-transition directory")? {
            let mut paths = fs::read_dir(&transitions)?.collect::<Result<Vec<_>, _>>()?;
            paths.sort_by_key(std::fs::DirEntry::file_name);
            for entry in paths {
                if !is_regular_non_symlink(&entry.path())?
                    || entry.path().extension().and_then(|value| value.to_str()) != Some("jws")
                {
                    bail!("trust-transition directory contains an unexpected entry");
                }
                let compact = read_audit_text(&entry.path(), "trust transition")?;
                let header = protected_header(&compact)?;
                let key = if header.kid.starts_with("break-glass-") {
                    trusted_break_glass_key(config, &header.kid)?
                } else {
                    trusted_controller_key(config, &header.kid)?
                };
                entries.push(serde_json::json!({
                    "kind": "trust-transition",
                    "key_id": header.kid,
                    "transition": verify_trust_transition(&compact, &header.kid, &key)?,
                }));
            }
        }
    }
    Ok(entries)
}

fn verify_pending_intents(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("intents");
    if !is_real_directory_or_missing(&directory, "operator intent directory")? {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !is_regular_non_symlink(&entry.path())?
            || entry.path().extension().and_then(|value| value.to_str()) != Some("jws")
        {
            bail!("operator intent directory contains an unexpected entry");
        }
        let compact = read_audit_text(&entry.path(), "operator task intent")?;
        let header = protected_header(&compact)?;
        let task = verify_task_signature(
            &compact,
            &header.kid,
            &trusted_controller_key(config, &header.kid)?,
        )?;
        if task.deployment_id != config.operator.deployment_id {
            bail!("operator intent belongs to a different deployment");
        }
    }
    Ok(())
}
