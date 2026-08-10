use anyhow::{Context, bail};
use serde::de::DeserializeOwned;

use crate::filesystem::{
    copy_atomic_from_file, ensure_private_directory, open_secure_regular_file,
    read_secure_regular_file, sha256_file,
};

use super::*;

const SELF_UPDATE_JOURNAL_SCHEMA: u32 = 2;
const SELF_UPDATE_JOURNAL_MAX_BYTES: u64 = 64 * 1024;
const SELF_AUDIT_RECORD_MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SelfUpdateOperation {
    Update,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SelfUpdatePhase {
    Intent,
    RollbackPrepared,
    CandidatePrepared,
    CandidateVerified,
    Installed,
    RollbackStateCommitted,
    TrustCommitted,
    AuditCommitted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SelfUpdateJournal {
    schema: u32,
    transaction_id: String,
    operation: SelfUpdateOperation,
    phase: SelfUpdatePhase,
    install_path: PathBuf,
    from_version: String,
    from_sha256: String,
    to_version: String,
    to_sha256: String,
    rollback_artifact: PathBuf,
    rollback_sha256: String,
    #[serde(default)]
    staged_artifact: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SelfAuditHeadPending {
    schema: u32,
    sequence: u64,
    previous_head_sha256: String,
    record_sha256: String,
}

pub(super) fn controller_state_directory() -> anyhow::Result<PathBuf> {
    let store = DeploymentStore::system();
    store.validate_failure_domains()?;
    Ok(store.state_root.join("controller-self"))
}

pub(super) fn controller_check(version: Option<&str>) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _lock = store.controller_self_lock()?;
    recover_controller_self_operation()?;
    controller_self_audit_signer()?;
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
    recover_controller_self_operation()?;
    controller_self_audit_signer()?;
    verify_controller_self_audit()?;
    let release = crate::release::VerifiedControllerRelease::fetch(version, None)?;
    enforce_controller_trust(&release.version, &release.sha256)?;
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    release.persist_evidence(&directory.join("evidence").join(&release.version))?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    let mut current_file = open_secure_regular_file(&install_path, "running controller", false)?;
    let previous_sha256 = sha256_file(&mut current_file, "running controller")?;
    let previous_version = controller_trust_state()?
        .map(|state| state.version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let rollback_artifact = directory.join(format!("rollback-{previous_sha256}"));
    let staged = directory.join(format!("candidate-{}", release.sha256));
    let mut journal = SelfUpdateJournal {
        schema: SELF_UPDATE_JOURNAL_SCHEMA,
        transaction_id: uuid::Uuid::now_v7().to_string(),
        operation: SelfUpdateOperation::Update,
        phase: SelfUpdatePhase::Intent,
        install_path: install_path.clone(),
        from_version: previous_version.clone(),
        from_sha256: previous_sha256.clone(),
        to_version: release.version.clone(),
        to_sha256: release.sha256.clone(),
        rollback_artifact: rollback_artifact.clone(),
        rollback_sha256: previous_sha256.clone(),
        staged_artifact: Some(staged.clone()),
    };
    persist_self_update_journal(&directory, &journal)?;
    append_controller_self_audit(
        "controller-update-intent",
        &previous_version,
        &release.version,
        &release.sha256,
    )?;

    copy_atomic_from_file(&mut current_file, &rollback_artifact, 0o500)?;
    ensure_digest(&rollback_artifact, &previous_sha256, "rollback artifact")?;
    journal.phase = SelfUpdatePhase::RollbackPrepared;
    persist_self_update_journal(&directory, &journal)?;

    let mut candidate_file =
        open_secure_regular_file(&release.artifact(), "verified controller candidate", false)?;
    copy_atomic_from_file(&mut candidate_file, &staged, 0o500)?;
    ensure_digest(&staged, &release.sha256, "staged controller candidate")?;
    journal.phase = SelfUpdatePhase::CandidatePrepared;
    persist_self_update_journal(&directory, &journal)?;
    Process::new(&staged).arg("--help").run_quiet()?;
    journal.phase = SelfUpdatePhase::CandidateVerified;
    persist_self_update_journal(&directory, &journal)?;

    let mut staged_file = open_secure_regular_file(&staged, "staged controller candidate", false)?;
    copy_atomic_from_file(&mut staged_file, &install_path, 0o755)?;
    ensure_digest(&install_path, &release.sha256, "installed controller")?;
    journal.phase = SelfUpdatePhase::Installed;
    persist_self_update_journal(&directory, &journal)?;
    commit_controller_rollback_state(
        &directory,
        &previous_version,
        &previous_sha256,
        &rollback_artifact,
    )?;
    journal.phase = SelfUpdatePhase::RollbackStateCommitted;
    persist_self_update_journal(&directory, &journal)?;
    write_controller_trust(&release.version, &release.sha256)?;
    journal.phase = SelfUpdatePhase::TrustCommitted;
    persist_self_update_journal(&directory, &journal)?;
    append_controller_self_audit(
        "controller-update",
        &previous_version,
        &release.version,
        &release.sha256,
    )?;
    journal.phase = SelfUpdatePhase::AuditCommitted;
    persist_self_update_journal(&directory, &journal)?;
    finish_self_update_journal(&directory, &journal)?;
    println!("nazoauthctl updated independently to {}", release.version);
    Ok(())
}

pub(super) fn controller_rollback() -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    let _lock = store.controller_self_lock()?;
    recover_controller_self_operation()?;
    controller_self_audit_signer()?;
    verify_controller_self_audit()?;
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
    let state: ControllerRollbackState = read_secure_json(
        &directory.join("rollback.json"),
        "controller rollback state",
        true,
        SELF_UPDATE_JOURNAL_MAX_BYTES,
    )
    .context("controller rollback state is unavailable")?;
    if state.schema != 1 {
        bail!("controller rollback state is invalid");
    }
    validate_digest(&state.sha256, "controller rollback state digest")?;
    validate_bound_path(&state.artifact, "controller rollback artifact")?;
    ensure_digest(
        &state.artifact,
        &state.sha256,
        "controller rollback artifact",
    )?;
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    let mut current_file = open_secure_regular_file(&install_path, "running controller", false)?;
    let from_sha256 = sha256_file(&mut current_file, "running controller")?;
    let from_version = controller_trust_state()?
        .map(|value| value.version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let mut journal = SelfUpdateJournal {
        schema: SELF_UPDATE_JOURNAL_SCHEMA,
        transaction_id: uuid::Uuid::now_v7().to_string(),
        operation: SelfUpdateOperation::Rollback,
        phase: SelfUpdatePhase::Intent,
        install_path: install_path.clone(),
        from_version: from_version.clone(),
        from_sha256,
        to_version: state.version.clone(),
        to_sha256: state.sha256.clone(),
        rollback_artifact: state.artifact.clone(),
        rollback_sha256: state.sha256.clone(),
        staged_artifact: None,
    };
    persist_self_update_journal(&directory, &journal)?;
    append_controller_self_audit(
        "controller-rollback-intent",
        &from_version,
        &state.version,
        &state.sha256,
    )?;
    let mut rollback_file =
        open_secure_regular_file(&state.artifact, "controller rollback artifact", false)?;
    copy_atomic_from_file(&mut rollback_file, &install_path, 0o755)?;
    ensure_digest(&install_path, &state.sha256, "restored controller")?;
    journal.phase = SelfUpdatePhase::Installed;
    persist_self_update_journal(&directory, &journal)?;
    write_controller_trust(&state.version, &state.sha256)?;
    journal.phase = SelfUpdatePhase::TrustCommitted;
    persist_self_update_journal(&directory, &journal)?;
    append_controller_self_audit(
        "controller-rollback",
        &from_version,
        &state.version,
        &state.sha256,
    )?;
    journal.phase = SelfUpdatePhase::AuditCommitted;
    persist_self_update_journal(&directory, &journal)?;
    finish_self_update_journal(&directory, &journal)?;
    println!("nazoauthctl rolled back independently to {}", state.version);
    Ok(())
}

pub(super) fn controller_trust_state() -> anyhow::Result<Option<ControllerTrustState>> {
    let path = controller_state_directory()?.join("trust.json");
    if !path_is_present(&path)? {
        return Ok(None);
    }
    let state: ControllerTrustState = read_secure_json(
        &path,
        "controller trust state",
        true,
        SELF_UPDATE_JOURNAL_MAX_BYTES,
    )
    .context("controller trust state is invalid")?;
    if state.schema != 1 {
        bail!("controller trust state has an unsupported schema");
    }
    validate_digest(&state.sha256, "controller trust state digest")?;
    compare_versions(&state.version, &state.version)?;
    Ok(Some(state))
}

pub(super) fn enforce_controller_trust(version: &str, sha256: &str) -> anyhow::Result<()> {
    validate_digest(sha256, "controller candidate digest")?;
    let Some(state) = controller_trust_state()? else {
        // A missing trust file is the bootstrap case, not an unrestricted
        // update window.  The binary that is currently executing establishes
        // the initial version/digest floor until a durable trust state exists.
        let current =
            std::env::current_exe().context("failed to resolve the running controller")?;
        let current = controller_install_path(&current)?;
        let current_version = format!("v{}", env!("CARGO_PKG_VERSION"));
        let current_sha256 = secure_digest(&current, "running controller")?;
        match compare_versions(version, &current_version)? {
            std::cmp::Ordering::Less => {
                bail!("controller anti-downgrade policy requires explicit self rollback")
            }
            std::cmp::Ordering::Equal if sha256 != current_sha256 => {
                bail!("immutable controller Release changed for the running version")
            }
            _ => return Ok(()),
        }
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
    validate_digest(sha256, "controller trust digest")?;
    let directory = controller_state_directory()?;
    ensure_private_directory(&directory, "controller self-update state")?;
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
    let has_lexical_navigation = path
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| matches!(segment, "." | ".."));
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || has_lexical_navigation
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("controller install path must be a normalized absolute file path");
    }
    if path_is_present(&path)? {
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
    ensure_private_directory(&identity, "controller self-audit identity")?;
    let private_path = identity.join("audit.key");
    let public_path = identity.join("audit.pub");
    let private_exists = path_is_present(&private_path)?;
    let public_exists = path_is_present(&public_path)?;
    if private_exists && !public_exists {
        let key = read_audit_private_key(&private_path)?;
        if audit_material_exists()? {
            bail!("controller self-audit identity is incomplete");
        }
        atomic_write(
            &public_path,
            URL_SAFE_NO_PAD
                .encode(key.verifying_key().to_bytes())
                .as_bytes(),
            0o444,
        )?;
    } else if !private_exists && public_exists {
        if audit_material_exists()? {
            bail!("controller self-audit identity is incomplete");
        }
        remove_file_durable(&public_path)?;
    }
    if !path_is_present(&private_path)? {
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
    let key = read_audit_private_key(&private_path)?;
    let public = read_audit_public_key(&public_path)?;
    if public != key.verifying_key().to_bytes() {
        bail!("controller self-audit key pair does not match");
    }
    let public_digest = secure_digest(&public_path, "controller self-audit public key")?;
    let key_id = format!("controller-self-audit-{}", &public_digest[..16]);
    Ok((key_id, key))
}

pub(super) fn verify_controller_self_audit() -> anyhow::Result<(u64, String)> {
    let directory = controller_self_audit_directory()?;
    if !path_is_present(&directory)? {
        return Ok((0, "0".repeat(64)));
    }
    let audit_metadata = fs::symlink_metadata(&directory)?;
    if audit_metadata.file_type().is_symlink() || !audit_metadata.is_dir() {
        bail!("controller self-audit directory is not a regular directory");
    }
    let public_path = controller_state_directory()?
        .join("identity")
        .join("audit.pub");
    let public = read_audit_public_key(&public_path)?;
    let verifying_key = VerifyingKey::from_bytes(&public)?;
    let public_digest = secure_digest(&public_path, "controller self-audit public key")?;
    let key_id = format!("controller-self-audit-{}", &public_digest[..16]);
    let records = directory.join("records");
    if let Ok(metadata) = fs::symlink_metadata(&records)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        bail!("controller self-audit records path is not a regular directory");
    }
    let mut entries = if path_is_present(&records)? {
        fs::read_dir(&records)?.collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut sequence = 0u64;
    let mut previous = "0".repeat(64);
    let mut last_record_bytes = None;
    for entry in entries {
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            bail!("controller self-audit record directory contains an unexpected entry");
        }
        let bytes = read_secure_regular_file(
            &entry.path(),
            "controller self-audit record",
            true,
            SELF_AUDIT_RECORD_MAX_BYTES,
        )?;
        let record: ControllerSelfAuditRecord = serde_json::from_slice(bytes.as_slice())
            .context("controller self-audit record is invalid")?;
        let expected_name = format!("{:020}.json", sequence + 1);
        if entry.file_name().to_string_lossy() != expected_name.as_str() {
            bail!("controller self-audit record filename is not its sequence");
        }
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
        last_record_bytes = Some(bytes);
    }
    let head_path = directory.join("head.json");
    let pending_path = directory.join("head.pending");
    let head = path_is_present(&head_path)?.then(|| {
        read_secure_json::<ControllerSelfAuditHead>(
            &head_path,
            "controller self-audit head",
            true,
            SELF_AUDIT_RECORD_MAX_BYTES,
        )
    });
    let head = match head {
        Some(result) => Some(result?),
        None => None,
    };
    let pending = path_is_present(&pending_path)?.then(|| {
        read_secure_json::<SelfAuditHeadPending>(
            &pending_path,
            "controller self-audit head pending marker",
            true,
            SELF_AUDIT_RECORD_MAX_BYTES,
        )
    });
    let pending = match pending {
        Some(result) => Some(result?),
        None => None,
    };
    if sequence == 0 && head.is_some() {
        bail!("controller self-audit head exists without records");
    }
    if let Some(head) = head.as_ref() {
        if head.schema != 1 || head.sequence != sequence || head.sha256 != previous {
            // A pending marker can prove that the head update was the only
            // interrupted step.  Without that marker, never overwrite a
            // mismatching head: it may be deliberate tampering.
            if pending.is_none() {
                bail!("controller self-audit head does not match the verified chain");
            }
        }
    } else if sequence > 0 && pending.is_none() {
        bail!("controller self-audit head is missing");
    }
    if let Some(pending) = pending {
        validate_digest(
            &pending.record_sha256,
            "controller self-audit pending digest",
        )?;
        validate_digest(
            &pending.previous_head_sha256,
            "controller self-audit pending previous-head digest",
        )?;
        if pending.schema != 1 {
            bail!("controller self-audit pending marker has an unsupported schema");
        }
        if pending.sequence == sequence {
            let Some(bytes) = last_record_bytes.as_ref() else {
                bail!("controller self-audit pending record is missing");
            };
            if encode_controller_digest(&Sha256::digest(bytes)) != pending.record_sha256 {
                bail!("controller self-audit pending record digest differs");
            }
            let last_record: ControllerSelfAuditRecord =
                serde_json::from_slice(bytes.as_slice())
                    .context("controller self-audit pending record is invalid")?;
            if last_record.event.previous_sha256 != pending.previous_head_sha256 {
                bail!("controller self-audit pending previous-head digest differs");
            }
            let head_already_committed = head.as_ref().is_some_and(|head| {
                head.schema == 1 && head.sequence == sequence && head.sha256 == previous
            });
            if !head_already_committed {
                if let Some(head) = head.as_ref()
                    && (head.schema != 1
                        || head.sequence != sequence.saturating_sub(1)
                        || head.sha256 != pending.previous_head_sha256)
                {
                    bail!("controller self-audit head does not match its pending predecessor");
                }
                atomic_write(
                    &head_path,
                    &serde_json::to_vec_pretty(&ControllerSelfAuditHead {
                        schema: 1,
                        sequence,
                        sha256: previous.clone(),
                    })?,
                    0o600,
                )?;
            }
            remove_file_durable(&pending_path)?;
        } else if pending.sequence == sequence + 1 {
            // The record write never became visible.  The existing chain is
            // still valid; retire only the marker that proves this was an
            // uncommitted append.
            if let Some(head) = head.as_ref()
                && (head.schema != 1 || head.sequence != sequence || head.sha256 != previous)
            {
                bail!("controller self-audit head does not match the verified chain");
            }
            remove_file_durable(&pending_path)?;
        } else {
            bail!("controller self-audit pending sequence is invalid");
        }
    } else if sequence > 0 {
        let head = head.context("controller self-audit head is missing")?;
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
    validate_digest(artifact_sha256, "controller self-audit artifact digest")?;
    let (key_id, signer) = controller_self_audit_signer()?;
    let (sequence, previous) = verify_controller_self_audit()?;
    if let Some(last) = controller_self_audit_last_event(sequence)?
        && last.operation == operation
        && last.from_version == from_version
        && last.to_version == to_version
        && last.artifact_sha256 == artifact_sha256
    {
        return Ok(());
    }
    let event = ControllerSelfAuditEvent {
        schema: 1,
        sequence: sequence + 1,
        previous_sha256: previous.clone(),
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
    ensure_private_directory(&directory, "controller self-audit")?;
    let records = directory.join("records");
    ensure_private_directory(&records, "controller self-audit records")?;
    let pending_path = directory.join("head.pending");
    atomic_write(
        &pending_path,
        &serde_json::to_vec_pretty(&SelfAuditHeadPending {
            schema: 1,
            sequence: sequence + 1,
            previous_head_sha256: previous.clone(),
            record_sha256: encode_controller_digest(&Sha256::digest(&bytes)),
        })?,
        0o600,
    )?;
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
    )?;
    remove_file_durable(&pending_path)
}

fn recover_controller_self_operation() -> anyhow::Result<()> {
    let directory = controller_state_directory()?;
    controller_self_audit_signer()?;
    verify_controller_self_audit()?;
    let path = directory.join("update-transaction.json");
    if !path_is_present(&path)? {
        return Ok(());
    }
    let mut journal = load_self_update_journal(&directory, &path)?;
    if journal.schema != SELF_UPDATE_JOURNAL_SCHEMA {
        bail!("controller self-update journal has an unsupported schema");
    }
    if journal.transaction_id.trim().is_empty() {
        bail!("controller self-update journal has no transaction id");
    }
    validate_digest(&journal.from_sha256, "controller self-update source digest")?;
    validate_digest(
        &journal.to_sha256,
        "controller self-update candidate digest",
    )?;
    validate_digest(
        &journal.rollback_sha256,
        "controller self-update rollback digest",
    )?;
    validate_bound_path(&journal.rollback_artifact, "controller rollback artifact")?;
    if let Some(staged) = journal.staged_artifact.as_ref() {
        validate_bound_path(staged, "staged controller candidate")?;
    }
    let current = std::env::current_exe().context("failed to resolve the running controller")?;
    let install_path = controller_install_path(&current)?;
    if install_path != journal.install_path {
        bail!("controller self-update journal is bound to a different install path");
    }
    match journal.operation {
        SelfUpdateOperation::Update => recover_update_journal(&directory, &mut journal)?,
        SelfUpdateOperation::Rollback => recover_rollback_journal(&directory, &mut journal)?,
    }
    Ok(())
}

fn load_self_update_journal(directory: &Path, path: &Path) -> anyhow::Result<SelfUpdateJournal> {
    let bytes = read_secure_regular_file(
        path,
        "controller self-update journal",
        true,
        SELF_UPDATE_JOURNAL_MAX_BYTES,
    )?;
    let value: serde_json::Value = serde_json::from_slice(bytes.as_slice())
        .context("controller self-update journal is invalid")?;
    if value.get("schema").and_then(serde_json::Value::as_u64) == Some(1) {
        let legacy: ControllerUpdateJournal = serde_json::from_value(value)?;
        validate_digest(&legacy.from_sha256, "legacy controller source digest")?;
        validate_digest(&legacy.to_sha256, "legacy controller candidate digest")?;
        let current =
            std::env::current_exe().context("failed to resolve the running controller")?;
        let install_path = controller_install_path(&current)?;
        return Ok(SelfUpdateJournal {
            schema: SELF_UPDATE_JOURNAL_SCHEMA,
            transaction_id: "legacy-controller-update".to_owned(),
            operation: SelfUpdateOperation::Update,
            // The legacy journal was written after staging and verification,
            // immediately before the install replacement.
            phase: SelfUpdatePhase::CandidateVerified,
            install_path,
            from_version: legacy.from_version,
            from_sha256: legacy.from_sha256.clone(),
            to_version: legacy.to_version,
            to_sha256: legacy.to_sha256.clone(),
            rollback_artifact: directory.join(format!("rollback-{}", legacy.from_sha256)),
            rollback_sha256: legacy.from_sha256,
            staged_artifact: Some(legacy.staged_artifact),
        });
    }
    serde_json::from_value(value).context("controller self-update journal is invalid")
}

fn recover_update_journal(directory: &Path, journal: &mut SelfUpdateJournal) -> anyhow::Result<()> {
    let current_digest = optional_secure_digest(&journal.install_path, "running controller")?;
    let rollback_digest = optional_secure_digest(&journal.rollback_artifact, "rollback artifact")?;
    if let Some(value) = rollback_digest.as_deref()
        && value != journal.rollback_sha256.as_str()
    {
        bail!("controller rollback artifact digest differs from its journal binding");
    }
    let staged = journal.staged_artifact.as_ref();
    let staged_digest = match staged {
        Some(path) => optional_secure_digest(path, "staged controller candidate")?,
        None => None,
    };
    if let Some(value) = staged_digest.as_deref()
        && value != journal.to_sha256.as_str()
    {
        bail!("staged controller candidate digest differs from its journal binding");
    }
    if matches!(
        journal.phase,
        SelfUpdatePhase::Intent
            | SelfUpdatePhase::RollbackPrepared
            | SelfUpdatePhase::CandidatePrepared
            | SelfUpdatePhase::CandidateVerified
    ) {
        append_controller_self_audit(
            "controller-update-intent",
            &journal.from_version,
            &journal.to_version,
            &journal.to_sha256,
        )?;
    }
    let mut installed = current_digest.as_deref() == Some(journal.to_sha256.as_str());
    if !installed {
        if current_digest.is_some()
            && current_digest.as_deref() != Some(journal.from_sha256.as_str())
        {
            bail!("controller install digest is neither the journal source nor candidate");
        }
        if staged_digest.as_deref() == Some(journal.to_sha256.as_str()) {
            if journal.phase != SelfUpdatePhase::CandidateVerified {
                Process::new(staged.context("controller candidate journal path is missing")?)
                    .arg("--help")
                    .run_quiet()?;
                journal.phase = SelfUpdatePhase::CandidateVerified;
                persist_self_update_journal(directory, journal)?;
            }
            let mut staged_file = open_secure_regular_file(
                staged.context("controller candidate journal path is missing")?,
                "staged controller candidate",
                false,
            )?;
            copy_atomic_from_file(&mut staged_file, &journal.install_path, 0o755)?;
            ensure_digest(
                &journal.install_path,
                &journal.to_sha256,
                "installed controller",
            )?;
            installed = true;
            journal.phase = SelfUpdatePhase::Installed;
            persist_self_update_journal(directory, journal)?;
        } else if current_digest.as_deref() == Some(journal.from_sha256.as_str())
            && matches!(
                journal.phase,
                SelfUpdatePhase::Intent | SelfUpdatePhase::RollbackPrepared
            )
        {
            // The release download/staging never completed.  No install
            // mutation occurred, so retiring this journal is idempotent and
            // does not hide a changed binary.
            append_controller_self_audit(
                "controller-update-aborted",
                &journal.from_version,
                &journal.to_version,
                &journal.to_sha256,
            )?;
            discard_unstarted_self_update_journal(directory, journal)?;
            return Ok(());
        } else {
            bail!("controller self-update journal cannot recover its candidate");
        }
    }
    if !installed {
        bail!("controller self-update did not reach an installed candidate");
    }
    if matches!(
        journal.phase,
        SelfUpdatePhase::Intent
            | SelfUpdatePhase::RollbackPrepared
            | SelfUpdatePhase::CandidatePrepared
            | SelfUpdatePhase::CandidateVerified
    ) {
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    }
    commit_controller_rollback_state(
        directory,
        &journal.from_version,
        &journal.from_sha256,
        &journal.rollback_artifact,
    )?;
    if journal.phase == SelfUpdatePhase::Installed {
        journal.phase = SelfUpdatePhase::RollbackStateCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    write_controller_trust(&journal.to_version, &journal.to_sha256)?;
    if journal.phase == SelfUpdatePhase::RollbackStateCommitted {
        journal.phase = SelfUpdatePhase::TrustCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    append_controller_self_audit(
        "controller-update",
        &journal.from_version,
        &journal.to_version,
        &journal.to_sha256,
    )?;
    if journal.phase == SelfUpdatePhase::TrustCommitted {
        journal.phase = SelfUpdatePhase::AuditCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    finish_self_update_journal(directory, journal)
}

fn recover_rollback_journal(
    directory: &Path,
    journal: &mut SelfUpdateJournal,
) -> anyhow::Result<()> {
    let artifact_digest = optional_secure_digest(&journal.rollback_artifact, "rollback artifact")?
        .context("controller rollback artifact is missing")?;
    if artifact_digest != journal.rollback_sha256 || journal.rollback_sha256 != journal.to_sha256 {
        bail!("controller rollback journal is not bound to its artifact digest");
    }
    if journal.phase == SelfUpdatePhase::Intent {
        append_controller_self_audit(
            "controller-rollback-intent",
            &journal.from_version,
            &journal.to_version,
            &journal.to_sha256,
        )?;
    }
    let current_digest = optional_secure_digest(&journal.install_path, "running controller")?;
    if current_digest.as_deref() != Some(journal.to_sha256.as_str()) {
        if current_digest.is_some()
            && current_digest.as_deref() != Some(journal.from_sha256.as_str())
        {
            bail!("controller install digest is neither rollback source nor target");
        }
        let mut artifact = open_secure_regular_file(
            &journal.rollback_artifact,
            "controller rollback artifact",
            false,
        )?;
        copy_atomic_from_file(&mut artifact, &journal.install_path, 0o755)?;
        ensure_digest(
            &journal.install_path,
            &journal.to_sha256,
            "restored controller",
        )?;
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    } else if journal.phase == SelfUpdatePhase::Intent {
        // The install replacement may have reached durable storage before
        // the phase checkpoint.  Infer only this monotonic transition from
        // the bound target digest; never infer a trust/audit commit this way.
        journal.phase = SelfUpdatePhase::Installed;
        persist_self_update_journal(directory, journal)?;
    }
    write_controller_trust(&journal.to_version, &journal.to_sha256)?;
    if journal.phase == SelfUpdatePhase::Installed {
        journal.phase = SelfUpdatePhase::TrustCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    append_controller_self_audit(
        "controller-rollback",
        &journal.from_version,
        &journal.to_version,
        &journal.to_sha256,
    )?;
    if journal.phase == SelfUpdatePhase::TrustCommitted {
        journal.phase = SelfUpdatePhase::AuditCommitted;
        persist_self_update_journal(directory, journal)?;
    }
    finish_self_update_journal(directory, journal)
}

fn persist_self_update_journal(
    directory: &Path,
    journal: &SelfUpdateJournal,
) -> anyhow::Result<()> {
    atomic_write(
        &directory.join("update-transaction.json"),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

fn finish_self_update_journal(directory: &Path, journal: &SelfUpdateJournal) -> anyhow::Result<()> {
    if journal.phase != SelfUpdatePhase::AuditCommitted {
        bail!("controller self-update journal cannot be retired before audit commit");
    }
    if let Some(staged) = journal.staged_artifact.as_ref()
        && let Some(digest) = optional_secure_digest(staged, "staged controller candidate")?
    {
        if digest != journal.to_sha256.as_str() {
            bail!("staged controller candidate changed before cleanup");
        }
        remove_file_durable(staged)?;
    }
    remove_file_durable(&directory.join("update-transaction.json"))
}

fn discard_unstarted_self_update_journal(
    directory: &Path,
    journal: &SelfUpdateJournal,
) -> anyhow::Result<()> {
    if !matches!(
        journal.phase,
        SelfUpdatePhase::Intent | SelfUpdatePhase::RollbackPrepared
    ) {
        bail!("controller self-update journal is no longer unstarted");
    }
    if let Some(staged) = journal.staged_artifact.as_ref()
        && let Some(digest) = optional_secure_digest(staged, "staged controller candidate")?
    {
        if digest != journal.to_sha256.as_str() {
            bail!("staged controller candidate changed before cleanup");
        }
        remove_file_durable(staged)?;
    }
    remove_file_durable(&directory.join("update-transaction.json"))
}

fn commit_controller_rollback_state(
    directory: &Path,
    version: &str,
    sha256: &str,
    artifact: &Path,
) -> anyhow::Result<()> {
    validate_bound_path(artifact, "controller rollback artifact")?;
    ensure_digest(artifact, sha256, "rollback artifact")?;
    atomic_write(
        &directory.join("rollback.json"),
        &serde_json::to_vec_pretty(&ControllerRollbackState {
            schema: 1,
            version: version.to_owned(),
            sha256: sha256.to_owned(),
            artifact: artifact.to_owned(),
        })?,
        0o600,
    )
}

fn controller_self_audit_last_event(
    sequence: u64,
) -> anyhow::Result<Option<ControllerSelfAuditEvent>> {
    if sequence == 0 {
        return Ok(None);
    }
    let path = controller_self_audit_directory()?
        .join("records")
        .join(format!("{:020}.json", sequence));
    let record: ControllerSelfAuditRecord = read_secure_json(
        &path,
        "controller self-audit record",
        true,
        SELF_AUDIT_RECORD_MAX_BYTES,
    )?;
    Ok(Some(record.event))
}

fn read_audit_private_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = read_secure_regular_file(path, "controller self-audit private key", true, 256)?;
    let encoded =
        std::str::from_utf8(&bytes).context("controller self-audit private key is invalid")?;
    let private = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("controller self-audit private key is invalid")?;
    let private: [u8; 32] = private
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller self-audit private key has invalid length"))?;
    Ok(SigningKey::from_bytes(&private))
}

fn read_audit_public_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    let bytes = read_secure_regular_file(path, "controller self-audit public key", false, 256)?;
    let encoded =
        std::str::from_utf8(&bytes).context("controller self-audit public key is invalid")?;
    let public = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("controller self-audit public key is invalid")?;
    public
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller self-audit public key has invalid length"))
}

fn audit_material_exists() -> anyhow::Result<bool> {
    let directory = controller_self_audit_directory()?;
    for path in [directory.join("head.json"), directory.join("head.pending")] {
        if path_is_present(&path)? {
            return Ok(true);
        }
    }
    let records = directory.join("records");
    if let Ok(metadata) = fs::symlink_metadata(&records)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        bail!("controller self-audit records path is not a regular directory");
    }
    Ok(path_is_present(&records)? && fs::read_dir(records)?.next().transpose()?.is_some())
}

fn read_secure_json<T: DeserializeOwned>(
    path: &Path,
    label: &str,
    private: bool,
    max_bytes: u64,
) -> anyhow::Result<T> {
    let bytes = read_secure_regular_file(path, label, private, max_bytes)?;
    serde_json::from_slice(bytes.as_slice()).with_context(|| format!("{label} is invalid"))
}

fn path_is_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn optional_secure_digest(path: &Path, label: &str) -> anyhow::Result<Option<String>> {
    if !path_is_present(path)? {
        return Ok(None);
    }
    secure_digest(path, label).map(Some)
}

fn secure_digest(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut file = open_secure_regular_file(path, label, false)?;
    sha256_file(&mut file, label)
}

fn ensure_digest(path: &Path, expected: &str, label: &str) -> anyhow::Result<()> {
    validate_digest(expected, label)?;
    let actual = secure_digest(path, label)?;
    if actual != expected {
        bail!("{label} digest differs from its trusted binding");
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} is not a SHA-256 digest");
    }
    Ok(())
}

fn validate_bound_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("{label} must be a normalized absolute path");
    }
    Ok(())
}

pub(super) fn encode_controller_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) const OPENID4VC_CERTIFICATE_BUNDLE: &str = "openid4vc-certificate-bundle.pem";
pub(super) const OPENID4VC_REVOCATION_SNAPSHOT: &str = "openid4vc-revocation-snapshot.json";
pub(super) const OPENID4VC_KEYS_MOUNT: &str = "/var/lib/nazo_oauth/keys";
pub(super) const MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES: usize = 1024 * 1024;

#[cfg(test)]
pub(super) fn self_update_journal_round_trip_for_test(directory: &Path) -> anyhow::Result<bool> {
    let journal = SelfUpdateJournal {
        schema: SELF_UPDATE_JOURNAL_SCHEMA,
        transaction_id: "test-transaction".to_owned(),
        operation: SelfUpdateOperation::Update,
        phase: SelfUpdatePhase::CandidateVerified,
        install_path: directory.join("install"),
        from_version: "v0.1.0".to_owned(),
        from_sha256: "a".repeat(64),
        to_version: "v0.2.0".to_owned(),
        to_sha256: "b".repeat(64),
        rollback_artifact: directory.join("rollback-a"),
        rollback_sha256: "a".repeat(64),
        staged_artifact: Some(directory.join("candidate-b")),
    };
    persist_self_update_journal(directory, &journal)?;
    let loaded = load_self_update_journal(directory, &directory.join("update-transaction.json"))?;
    Ok(loaded.schema == SELF_UPDATE_JOURNAL_SCHEMA
        && loaded.phase == SelfUpdatePhase::CandidateVerified
        && loaded.from_sha256 == journal.from_sha256
        && loaded.to_sha256 == journal.to_sha256)
}
