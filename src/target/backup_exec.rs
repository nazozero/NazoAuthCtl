//! Target-local snapshot creation and real isolated restore rehearsal.
//!
//! A readable archive is not a restore test. A receipt is written only after
//! an isolated database and exact OCI candidate pass application probes and
//! all temporary resources are removed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    net::TcpListener,
    path::{Component, Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail, ensure};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tar::{Builder as TarBuilder, EntryType, Header as TarHeader};
use url::Url;
use uuid::Uuid;

use super::{
    backup::{self, RestoreTestEnvironment, RestoreTestReceipt, SnapshotFile, SnapshotManifest},
    deployment_state::{
        DeploymentState, Failure, ReleaseVersion, ResourceOwnership, ResourceScope,
    },
    install_exec::{
        CONTAINER_CONFIG_FILE, CONTAINER_DATA_DIR, CONTAINER_SECRETS_DIR, LOCAL_READINESS_PATH,
        MIGRATION_RUNTIME_ROLE_ENV, SERVER_CONFIG_FILE_ENV,
    },
    wire::{
        BackupTransferBytes, BackupTransferChunk, HOST_ERR_OPERATION_INVALID,
        MAX_BACKUP_TRANSFER_CHUNK_BYTES, MAX_BACKUP_TRANSFER_FILE_BYTES, sanitize,
    },
};
use crate::runtime_backend::{
    self, ArtifactReference, ContainerRuntimePolicy, NeutralMount, RecoveryCandidateEndpoint,
    RecoveryCandidateRequest, Responsibility, RuntimeBackend, RuntimeBackendKind,
    RuntimeReplacement,
};

pub const BACKUP_EXECUTION_FAILED: &str = "BACKUP_EXECUTION_FAILED";
pub const RESTORE_TEST_FAILED: &str = "RESTORE_TEST_FAILED";
const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_VALKEY_CLEANUP_OUTPUT: usize = 1024 * 1024;
const DATABASE_SENTINEL_SQL: &str = "SELECT concat_ws('|',
    'controller_recovery_roots=' || (SELECT COUNT(*) FROM controller_recovery_roots),
    'controller_registry_slots=' || (SELECT COUNT(*) FROM controller_registry_slots),
    'migration_head=' || COALESCE((SELECT MAX(version)::text FROM __diesel_schema_migrations), ''),
    'oauth_clients=' || (SELECT COUNT(*) FROM oauth_clients),
    'oauth_tokens=' || (SELECT COUNT(*) FROM oauth_tokens),
    'recovery_invalidations=' || (SELECT COUNT(*) FROM recovery_invalidations),
    'tenants=' || (SELECT COUNT(*) FROM tenants),
    'user_totp_credentials=' || (SELECT COUNT(*) FROM user_totp_credentials),
    'users=' || (SELECT COUNT(*) FROM users))";
const SNAPSHOT_SENTINEL_FILE: &str = "snapshot-sentinel";
const IMMUTABLE_MANIFEST_FILE: &str = "snapshot-manifest.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTransferPlan {
    pub operation_id: String,
    pub deployment_id: String,
    pub manifest_sha256: String,
    pub files: Vec<SnapshotFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryFacts {
    pub operation_id: String,
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub restored_database: String,
    pub artifact: ArtifactReference,
    pub release: ReleaseVersion,
    pub rollback_policy: crate::model::ReleaseRollbackPolicy,
    pub config_schema: String,
}

pub(crate) fn snapshot(
    scope_dir: &Path,
    state: &DeploymentState,
    operation_id: &str,
) -> Result<SnapshotManifest, Failure> {
    let snapshot_id = Uuid::parse_str(operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup operation id must be a UUID for deterministic crash recovery",
        )
    })?;
    state.validate().map_err(backup_failure)?;
    let snapshots_root = scope_dir.join("backup").join("snapshots");
    let final_dir = snapshots_root.join(snapshot_id.to_string());
    let partial_dir = snapshots_root.join(format!(".{}.partial", snapshot_id));
    let immutable_manifest = final_dir.join(IMMUTABLE_MANIFEST_FILE);
    if final_dir.exists() {
        let existing = backup::load_manifest_at(&immutable_manifest)
            .map_err(backup_failure)?
            .ok_or_else(|| {
                Failure::new(
                    BACKUP_EXECUTION_FAILED,
                    "completed snapshot directory has no immutable manifest",
                )
            })?;
        if existing.snapshot_id != snapshot_id.to_string()
            || existing.deployment_id != state.deployment_id
        {
            return Err(Failure::new(
                BACKUP_EXECUTION_FAILED,
                "immutable snapshot manifest does not bind this operation and deployment",
            ));
        }
        verify_snapshot_files(&final_dir, &existing).map_err(backup_failure)?;
        backup::write_manifest(scope_dir, &existing).map_err(backup_failure)?;
        remove_receipt_if_present(scope_dir).map_err(backup_failure)?;
        return Ok(existing);
    }
    crate::filesystem::ensure_private_directory(&snapshots_root, "snapshot root")
        .map_err(backup_failure)?;
    if partial_dir.exists() {
        fs::remove_dir_all(&partial_dir).map_err(|error| backup_failure(error.into()))?;
    }
    fs::create_dir(&partial_dir).map_err(|error| backup_failure(error.into()))?;
    crate::filesystem::ensure_private_directory(&partial_dir, "snapshot staging directory")
        .map_err(backup_failure)?;
    let result = create_snapshot(&partial_dir, state, snapshot_id).and_then(|manifest| {
        backup::write_manifest_at(&partial_dir.join(IMMUTABLE_MANIFEST_FILE), &manifest)?;
        fs::rename(&partial_dir, &final_dir)
            .context("failed to atomically publish completed snapshot directory")?;
        backup::write_manifest(scope_dir, &manifest)?;
        remove_receipt_if_present(scope_dir)?;
        Ok(manifest)
    });
    if result.is_err() && partial_dir.exists() {
        let _ = fs::remove_dir_all(&partial_dir);
    }
    result.map_err(backup_failure)
}

fn create_snapshot(
    staging: &Path,
    state: &DeploymentState,
    snapshot_id: Uuid,
) -> anyhow::Result<SnapshotManifest> {
    let data = managed_directory(state, "app-data")?;
    let secrets = managed_directory(state, "app-secrets")?;
    let config = secure_regular_path(Path::new(&state.config.reference), "deployment config")?;
    let database_url = secure_regular_path(
        &secrets.join("database-lifecycle-url"),
        "lifecycle database URL",
    )?;
    let mfa_key = secure_regular_path(&secrets.join("mfa-totp-key"), "MFA key")?;
    let release = state
        .current_release
        .clone()
        .context("deployment has no current release version")?;
    let runtime_artifact = observe_exact_runtime_artifact(state)?;
    let oidc_signing_key_ids = source_oidc_signing_key_ids(state)?;
    let runtime_instance_key_id = verify_runtime_identity(&data, state)?;
    let mfa_key_sha256 = crate::filesystem::sha256(&mfa_key)?;
    let database_sentinel_sha256 = database_sentinel(&database_url)?;
    let dump_path = staging.join("postgresql.dump");
    let archive_path = staging.join("deployment.tar");
    run_pg_dump(&database_url, &dump_path)?;
    let archive_files = create_deployment_archive(
        &archive_path,
        &data,
        &secrets,
        &config,
        snapshot_id.to_string().as_bytes(),
    )?;
    let files = [dump_path, archive_path]
        .iter()
        .map(|path| snapshot_file(path, staging))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut manifest = SnapshotManifest {
        schema: backup::BACKUP_MANIFEST_SCHEMA,
        deployment_id: state.deployment_id.clone(),
        snapshot_id: snapshot_id.to_string(),
        created_at: Utc::now(),
        runtime_artifact,
        release,
        rollback_policy: state.current_rollback_policy.clone(),
        config_schema: state.config.schema.clone(),
        files,
        archive_files,
        database_sentinel_sha256,
        mfa_key_sha256,
        runtime_instance_key_id,
        oidc_signing_key_ids,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    manifest.validate()?;
    Ok(manifest)
}

pub(crate) fn restore_test(
    scope_dir: &Path,
    state: &DeploymentState,
) -> Result<RestoreTestReceipt, Failure> {
    let manifest = backup::load_manifest(scope_dir)
        .map_err(restore_failure)?
        .ok_or_else(|| Failure::new(RESTORE_TEST_FAILED, "no snapshot manifest exists"))?;
    if manifest.deployment_id != state.deployment_id {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "snapshot manifest is not bound to this deployment",
        ));
    }
    state.validate().map_err(restore_failure)?;
    let snapshot_dir = scope_dir
        .join("backup")
        .join("snapshots")
        .join(&manifest.snapshot_id);
    verify_snapshot_files(&snapshot_dir, &manifest).map_err(restore_failure)?;
    let rehearsal_id = Uuid::now_v7();
    let restore_root = scope_dir
        .join("backup")
        .join("restore-tests")
        .join(rehearsal_id.to_string());
    let candidate = candidate_name(&state.runtime.object, rehearsal_id);
    let database = format!("nazo_restore_{}", rehearsal_id.simple());
    let valkey_epoch = Uuid::now_v7().to_string();
    fs::create_dir_all(&restore_root).map_err(|error| restore_failure(error.into()))?;
    crate::filesystem::ensure_private_directory(&restore_root, "restore-test directory")
        .map_err(restore_failure)?;
    let result = run_restore_rehearsal(
        &restore_root,
        &snapshot_dir,
        state,
        &manifest,
        &candidate,
        &database,
        &valkey_epoch,
    );
    let tree_cleanup =
        fs::remove_dir_all(&restore_root).context("failed to remove restore-test tree");
    if let Err(error) = result {
        write_restore_failure(scope_dir, &manifest, rehearsal_id, &error.to_string());
        let _ = tree_cleanup;
        return Err(restore_failure(error));
    }
    tree_cleanup.map_err(restore_failure)?;
    remove_file_if_present(&scope_dir.join("backup").join("restore-test-failure.json"))
        .map_err(restore_failure)?;
    let receipt = RestoreTestReceipt {
        schema: backup::RESTORE_TEST_RECEIPT_SCHEMA,
        deployment_id: state.deployment_id.clone(),
        snapshot_id: manifest.snapshot_id.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        restored_at: Utc::now(),
        isolated_database: database,
        candidate_runtime_object: candidate,
        runtime_instance_key_id: manifest.runtime_instance_key_id.clone(),
        database_sentinel_sha256: manifest.database_sentinel_sha256.clone(),
        environment: RestoreTestEnvironment::SameHostIsolated,
    };
    receipt
        .validate_against(&manifest)
        .map_err(restore_failure)?;
    backup::write_receipt(scope_dir, &receipt).map_err(restore_failure)?;
    Ok(receipt)
}

/// Prepare an owner-only, immutable export view. Hard links avoid duplicating
/// multi-gigabyte snapshot bytes; the source snapshot itself remains the
/// authority and every link is revalidated before the plan is returned.
pub(crate) fn prepare_export(
    scope_dir: &Path,
    state: &DeploymentState,
    operation_id: &str,
) -> Result<BackupTransferPlan, Failure> {
    let operation = Uuid::parse_str(operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    let manifest = backup::load_manifest(scope_dir)
        .map_err(backup_failure)?
        .ok_or_else(|| Failure::new(BACKUP_EXECUTION_FAILED, "no snapshot manifest exists"))?;
    if manifest.deployment_id != state.deployment_id {
        return Err(Failure::new(
            BACKUP_EXECUTION_FAILED,
            "snapshot manifest is not bound to this deployment",
        ));
    }
    let snapshot_dir = scope_dir
        .join("backup")
        .join("snapshots")
        .join(&manifest.snapshot_id);
    verify_snapshot_files(&snapshot_dir, &manifest).map_err(backup_failure)?;
    let directory = scope_dir
        .join("backup")
        .join("transfers")
        .join(format!("export-{operation}"));
    if directory.exists() {
        fs::remove_dir_all(&directory).map_err(|error| backup_failure(error.into()))?;
    }
    crate::filesystem::ensure_private_directory(&directory, "backup export directory")
        .map_err(backup_failure)?;
    for name in ["postgresql.dump", "deployment.tar", IMMUTABLE_MANIFEST_FILE] {
        fs::hard_link(snapshot_dir.join(name), directory.join(name))
            .map_err(|error| backup_failure(error.into()))?;
    }
    verify_snapshot_files(&directory, &manifest).map_err(backup_failure)?;
    let mut files = manifest.files;
    files.push(
        snapshot_file(&directory.join(IMMUTABLE_MANIFEST_FILE), &directory)
            .map_err(backup_failure)?,
    );
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(BackupTransferPlan {
        operation_id: operation.to_string(),
        deployment_id: state.deployment_id.clone(),
        manifest_sha256: manifest.manifest_sha256,
        files,
    })
}

/// Create the only directory into which an off-host transfer may write.
/// Finalization accepts no caller-selected path.
pub(crate) fn prepare_import(
    scope_dir: &Path,
    deployment_id: &str,
    operation_id: &str,
) -> Result<BackupTransferPlan, Failure> {
    crate::registry::validate_identifier(deployment_id, 128, "backup deployment id")
        .map_err(backup_failure)?;
    let operation = Uuid::parse_str(operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    let directory = scope_dir
        .join("backup")
        .join("transfers")
        .join(format!("import-{operation}.partial"));
    if directory.exists() {
        fs::remove_dir_all(&directory).map_err(|error| backup_failure(error.into()))?;
    }
    crate::filesystem::ensure_private_directory(&directory, "backup import directory")
        .map_err(backup_failure)?;
    Ok(BackupTransferPlan {
        operation_id: operation.to_string(),
        deployment_id: deployment_id.to_owned(),
        manifest_sha256: String::new(),
        files: Vec::new(),
    })
}

/// Read one fixed-size piece of the source export.  The export directory was
/// created by the journaled prepare operation and contains hard links to an
/// immutable snapshot, so this operation never accepts a filesystem path.
pub(crate) fn read_transfer_chunk(
    scope_dir: &Path,
    transfer_operation_id: &str,
    file_name: &str,
    offset: u64,
    maximum_bytes: u32,
) -> Result<BackupTransferChunk, Failure> {
    let operation = Uuid::parse_str(transfer_operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    if !matches!(
        file_name,
        "postgresql.dump" | "deployment.tar" | IMMUTABLE_MANIFEST_FILE
    ) || maximum_bytes == 0
        || maximum_bytes as usize > MAX_BACKUP_TRANSFER_CHUNK_BYTES
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup transfer requested an invalid bounded file chunk",
        ));
    }
    let directory = scope_dir
        .join("backup")
        .join("transfers")
        .join(format!("export-{operation}"));
    let manifest = backup::load_manifest_at(&directory.join(IMMUTABLE_MANIFEST_FILE))
        .map_err(backup_failure)?
        .ok_or_else(|| Failure::new(BACKUP_EXECUTION_FAILED, "backup export has no manifest"))?;
    let expected = if file_name == IMMUTABLE_MANIFEST_FILE {
        snapshot_file(&directory.join(file_name), &directory).map_err(backup_failure)?
    } else {
        manifest
            .files
            .iter()
            .find(|file| file.path == file_name)
            .cloned()
            .ok_or_else(|| {
                Failure::new(
                    BACKUP_EXECUTION_FAILED,
                    "backup export lacks requested file",
                )
            })?
    };
    let path = secure_regular_path(&directory.join(file_name), "backup transfer source")
        .map_err(backup_failure)?;
    let size = fs::metadata(&path)
        .map_err(|error| backup_failure(error.into()))?
        .len();
    if size != expected.size || offset >= size {
        return Err(Failure::new(
            BACKUP_EXECUTION_FAILED,
            "backup transfer source no longer matches its immutable export",
        ));
    }
    let count = (size - offset).min(maximum_bytes as u64) as usize;
    let mut bytes = vec![0_u8; count];
    let mut file = fs::File::open(&path).map_err(|error| backup_failure(error.into()))?;
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|error| backup_failure(error.into()))?;
    Ok(BackupTransferChunk {
        transfer_operation_id: operation.to_string(),
        file_name: file_name.to_owned(),
        offset,
        total_bytes: size,
        file_sha256: expected.sha256,
        bytes: BackupTransferBytes::try_new(bytes)
            .map_err(|error| Failure::new(HOST_ERR_OPERATION_INVALID, error.detail))?,
    })
}

/// Append one exact chunk to the operation-bound destination partial tree.
/// A replay has the same operation id and canonical hash, so TargetJournal
/// returns its acknowledgement; an interrupted pending write can safely
/// rewrite the same offset after checking the partial length.
pub(crate) fn write_transfer_chunk(
    scope_dir: &Path,
    transfer_operation_id: &str,
    file_name: &str,
    offset: u64,
    total_bytes: u64,
    file_sha256: &str,
    bytes: &BackupTransferBytes,
) -> Result<(), Failure> {
    let operation = Uuid::parse_str(transfer_operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    if !matches!(
        file_name,
        "postgresql.dump" | "deployment.tar" | IMMUTABLE_MANIFEST_FILE
    ) || total_bytes == 0
        || total_bytes > MAX_BACKUP_TRANSFER_FILE_BYTES
        || !valid_sha256(file_sha256)
        || offset
            .checked_add(bytes.as_bytes().len() as u64)
            .is_none_or(|end| end > total_bytes)
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup transfer write has an invalid chunk binding",
        ));
    }
    let directory = scope_dir
        .join("backup")
        .join("transfers")
        .join(format!("import-{operation}.partial"));
    let path = directory.join(file_name);
    if offset > 0 {
        let metadata = fs::symlink_metadata(&path).map_err(|error| backup_failure(error.into()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != offset {
            return Err(Failure::new(
                BACKUP_EXECUTION_FAILED,
                "backup transfer destination offset does not match its partial file",
            ));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    if offset == 0 {
        options.truncate(true);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| backup_failure(error.into()))?;
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(bytes.as_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(|error| backup_failure(error.into()))?;
    let written = fs::metadata(&path)
        .map_err(|error| backup_failure(error.into()))?
        .len();
    if written != offset + bytes.as_bytes().len() as u64 {
        return Err(Failure::new(
            BACKUP_EXECUTION_FAILED,
            "backup transfer destination did not persist the exact chunk length",
        ));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Verify every received byte against the transferred immutable manifest,
/// atomically publish the snapshot on the destination, and return the receipt
/// which the source target persists only after it verifies distinct host ids.
pub(crate) fn finalize_import(
    scope_dir: &Path,
    deployment_id: &str,
    transfer_operation_id: &str,
    expected_manifest_sha256: &str,
    source_host_id: &str,
    destination_host_id: &str,
) -> Result<backup::OffHostCopyReceipt, Failure> {
    if source_host_id == destination_host_id {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup import source and destination target identities must differ",
        ));
    }
    let operation = Uuid::parse_str(transfer_operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    let incoming = scope_dir
        .join("backup")
        .join("transfers")
        .join(format!("import-{operation}.partial"));
    let manifest = backup::load_manifest_at(&incoming.join(IMMUTABLE_MANIFEST_FILE))
        .map_err(backup_failure)?
        .ok_or_else(|| {
            Failure::new(
                BACKUP_EXECUTION_FAILED,
                "backup import has no immutable manifest",
            )
        })?;
    if manifest.deployment_id != deployment_id
        || manifest.manifest_sha256 != expected_manifest_sha256
    {
        return Err(Failure::new(
            BACKUP_EXECUTION_FAILED,
            "backup import manifest binding differs from the transfer request",
        ));
    }
    verify_snapshot_files(&incoming, &manifest).map_err(backup_failure)?;
    let final_dir = scope_dir
        .join("backup")
        .join("snapshots")
        .join(&manifest.snapshot_id);
    if final_dir.exists() {
        let existing = backup::load_manifest_at(&final_dir.join(IMMUTABLE_MANIFEST_FILE))
            .map_err(backup_failure)?
            .ok_or_else(|| {
                Failure::new(
                    BACKUP_EXECUTION_FAILED,
                    "destination snapshot has no immutable manifest",
                )
            })?;
        if existing.manifest_sha256 != manifest.manifest_sha256 {
            return Err(Failure::new(
                BACKUP_EXECUTION_FAILED,
                "destination snapshot id is occupied by different bytes",
            ));
        }
        fs::remove_dir_all(&incoming).map_err(|error| backup_failure(error.into()))?;
    } else {
        crate::filesystem::ensure_private_directory(
            final_dir.parent().expect("snapshot has parent"),
            "off-host snapshot root",
        )
        .map_err(backup_failure)?;
        fs::rename(&incoming, &final_dir).map_err(|error| backup_failure(error.into()))?;
    }
    let receipt = backup::OffHostCopyReceipt {
        schema: backup::OFF_HOST_COPY_RECEIPT_SCHEMA,
        deployment_id: deployment_id.to_owned(),
        snapshot_id: manifest.snapshot_id.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        source_host_id: source_host_id.to_owned(),
        destination_host_id: destination_host_id.to_owned(),
        verified_at: Utc::now(),
    };
    receipt
        .validate_against(&manifest)
        .map_err(backup_failure)?;
    Ok(receipt)
}

pub(crate) fn record_off_host_copy(
    scope_dir: &Path,
    receipt: &backup::OffHostCopyReceipt,
) -> Result<(), Failure> {
    let manifest = backup::load_manifest(scope_dir)
        .map_err(backup_failure)?
        .ok_or_else(|| Failure::new(BACKUP_EXECUTION_FAILED, "no snapshot manifest exists"))?;
    receipt
        .validate_against(&manifest)
        .map_err(backup_failure)?;
    backup::write_off_host_receipt(scope_dir, receipt).map_err(backup_failure)
}

pub(crate) fn cleanup_transfer(scope_dir: &Path, operation_id: &str) -> Result<(), Failure> {
    let operation = Uuid::parse_str(operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "backup copy operation id must be a UUID",
        )
    })?;
    for name in [
        format!("export-{operation}"),
        format!("import-{operation}.partial"),
    ] {
        let path = scope_dir.join("backup").join("transfers").join(name);
        if path.exists() {
            fs::remove_dir_all(path).map_err(|error| backup_failure(error.into()))?;
        }
    }
    Ok(())
}

/// Restore the current validated snapshot into the deployment's formal paths
/// while the runtime remains stopped. The new PostgreSQL database and sibling
/// filesystem stages are prepared before any path switch. Each rename is
/// forward-resumable from the fixed operation id; old paths and the old
/// database are retained under operation-bound rollback names.
///
/// Server-side recovery invalidation and ingress control are intentionally
/// outside this function. The caller must prove the runtime is stopped before
/// entry and must not restart it until the authoritative invalidation result
/// has been durably recorded.
pub(crate) fn recover(
    scope_dir: &Path,
    state: &DeploymentState,
    expected_manifest_sha256: &str,
    operation_id: &str,
) -> Result<RecoveryFacts, Failure> {
    let operation = Uuid::parse_str(operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery operation id must be a UUID",
        )
    })?;
    let manifest = backup::load_manifest(scope_dir)
        .map_err(restore_failure)?
        .ok_or_else(|| Failure::new(RESTORE_TEST_FAILED, "no snapshot manifest exists"))?;
    if manifest.deployment_id != state.deployment_id
        || manifest.manifest_sha256 != expected_manifest_sha256
    {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery manifest binding differs from the accepted operation",
        ));
    }
    let backend = runtime_backend::backend(state.runtime.kind);
    let live = backend
        .inspect(&state.runtime.object)
        .map_err(restore_failure)?;
    if live.running {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery requires the deployment runtime to remain stopped",
        ));
    }
    let snapshot_dir = scope_dir
        .join("backup")
        .join("snapshots")
        .join(&manifest.snapshot_id);
    verify_snapshot_files(&snapshot_dir, &manifest).map_err(restore_failure)?;
    let recovery_root = scope_dir
        .join("backup")
        .join("recoveries")
        .join(operation.to_string());
    crate::filesystem::ensure_private_directory(&recovery_root, "recovery operation directory")
        .map_err(restore_failure)?;
    let completed_path = recovery_root.join("completed.json");
    if completed_path.exists() {
        let bytes = crate::filesystem::read_secure_regular_file(
            &completed_path,
            "recovery completion",
            false,
            64 * 1024,
        )
        .map_err(restore_failure)?;
        let facts: RecoveryFacts =
            serde_json::from_slice(&bytes).map_err(|error| restore_failure(error.into()))?;
        if facts.operation_id != operation.to_string()
            || facts.snapshot_id != manifest.snapshot_id
            || facts.manifest_sha256 != manifest.manifest_sha256
            || facts.artifact != manifest.runtime_artifact
            || facts.release != manifest.release
            || facts.rollback_policy != manifest.rollback_policy
            || facts.config_schema != manifest.config_schema
        {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "recovery completion does not bind the accepted operation",
            ));
        }
        crate::registry::validate_identifier(&facts.restored_database, 128, "restored database")
            .map_err(restore_failure)?;
        let secrets = managed_directory(state, "app-secrets").map_err(restore_failure)?;
        let connection = postgres_connection(&secrets.join("database-lifecycle-url"))
            .map_err(restore_failure)?;
        if connection.url_without_password.path() != format!("/{}", facts.restored_database)
            || database_sentinel_with_connection(&connection).map_err(restore_failure)?
                != manifest.database_sentinel_sha256
        {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "completed recovery database no longer matches its snapshot",
            ));
        }
        return Ok(facts);
    }
    let extracted = recovery_root.join("extracted");
    if extracted.exists() {
        let mut found = Vec::new();
        collect_regular_files(&extracted, &extracted, &mut found).map_err(restore_failure)?;
        found.sort_by(|left, right| left.path.cmp(&right.path));
        let mut expected = manifest.archive_files.clone();
        expected.sort_by(|left, right| left.path.cmp(&right.path));
        if found != expected {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "recovery staging differs from the snapshot manifest",
            ));
        }
    } else {
        fs::create_dir(&extracted).map_err(|error| restore_failure(error.into()))?;
        extract_deployment_archive(
            &snapshot_dir.join("deployment.tar"),
            &extracted,
            &manifest.archive_files,
        )
        .map_err(restore_failure)?;
    }
    let extracted_data = extracted.join("app-data");
    let extracted_secrets = extracted.join("app-secrets");
    let extracted_config = extracted.join("config.yaml");
    if crate::filesystem::sha256(&extracted_secrets.join("mfa-totp-key"))
        .map_err(restore_failure)?
        != manifest.mfa_key_sha256
        || verify_runtime_identity(&extracted_data, state).map_err(restore_failure)?
            != manifest.runtime_instance_key_id
    {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery key material differs from the snapshot",
        ));
    }
    let original_connection =
        postgres_connection(&extracted_secrets.join("database-lifecycle-url"))
            .map_err(restore_failure)?;
    let database = format!("nazo_recovered_{}", operation.simple());
    let database_plan = recovery_root.join("database-plan.json");
    let database_preexisting =
        database_exists(&original_connection, &database).map_err(restore_failure)?;
    if database_plan.exists() {
        let bytes = crate::filesystem::read_secure_regular_file(
            &database_plan,
            "recovery database plan",
            false,
            64 * 1024,
        )
        .map_err(restore_failure)?;
        let plan: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| restore_failure(error.into()))?;
        if plan.get("operation_id").and_then(serde_json::Value::as_str) != Some(operation_id)
            || plan
                .get("manifest_sha256")
                .and_then(serde_json::Value::as_str)
                != Some(manifest.manifest_sha256.as_str())
            || plan.get("database").and_then(serde_json::Value::as_str) != Some(database.as_str())
        {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "recovery database plan does not bind the accepted operation",
            ));
        }
    } else {
        if database_preexisting {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "recovery database name was occupied before this operation",
            ));
        }
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1,
            "operation_id": operation_id,
            "manifest_sha256": manifest.manifest_sha256,
            "database": database,
        }))
        .map_err(|error| restore_failure(error.into()))?;
        crate::filesystem::atomic_write(&database_plan, &bytes, 0o600).map_err(restore_failure)?;
    }
    let already_restored = database_preexisting
        && database_sentinel_with_connection(&original_connection.with_database(&database))
            .is_ok_and(|digest| digest == manifest.database_sentinel_sha256);
    if !already_restored {
        if database_preexisting {
            drop_database(&original_connection, &database).map_err(restore_failure)?;
        }
        create_database(&original_connection, &database).map_err(restore_failure)?;
        if let Err(error) = restore_database(
            &original_connection,
            &snapshot_dir.join("postgresql.dump"),
            &database,
        ) {
            let _ = drop_database(&original_connection, &database);
            return Err(restore_failure(error));
        }
        if database_sentinel_with_connection(&original_connection.with_database(&database))
            .map_err(restore_failure)?
            != manifest.database_sentinel_sha256
        {
            return Err(Failure::new(
                RESTORE_TEST_FAILED,
                "restored recovery database has the wrong snapshot sentinel",
            ));
        }
    }
    write_secret(
        &extracted_secrets.join("database-lifecycle-url"),
        &original_connection
            .with_database(&database)
            .with_password_url()
            .map_err(restore_failure)?,
    )
    .map_err(restore_failure)?;
    let runtime_connection = postgres_connection(&extracted_secrets.join("database-runtime-url"))
        .map_err(restore_failure)?;
    write_secret(
        &extracted_secrets.join("database-runtime-url"),
        &runtime_connection
            .with_database(&database)
            .with_password_url()
            .map_err(restore_failure)?,
    )
    .map_err(restore_failure)?;

    let target_data = managed_directory_locator(state, "app-data").map_err(restore_failure)?;
    let target_secrets =
        managed_directory_locator(state, "app-secrets").map_err(restore_failure)?;
    let target_config = PathBuf::from(&state.config.reference);
    let staged_data =
        sibling_operation_path(&target_data, operation, "data-stage").map_err(restore_failure)?;
    let staged_secrets = sibling_operation_path(&target_secrets, operation, "secrets-stage")
        .map_err(restore_failure)?;
    let staged_config = sibling_operation_path(&target_config, operation, "config-stage")
        .map_err(restore_failure)?;
    if !staged_data.exists()
        && !recovery_path_switched(&target_data, operation, "data").map_err(restore_failure)?
    {
        copy_tree(&extracted_data, &staged_data).map_err(restore_failure)?;
    }
    if !staged_secrets.exists()
        && !recovery_path_switched(&target_secrets, operation, "secrets")
            .map_err(restore_failure)?
    {
        copy_tree(&extracted_secrets, &staged_secrets).map_err(restore_failure)?;
    }
    if !staged_config.exists()
        && !recovery_path_switched(&target_config, operation, "config").map_err(restore_failure)?
    {
        fs::copy(&extracted_config, &staged_config)
            .map_err(|error| restore_failure(error.into()))?;
    }
    prepare_stage_ownership_if_present(
        state.runtime.kind,
        &staged_data,
        &staged_secrets,
        &staged_config,
    )
    .map_err(restore_failure)?;
    crate::filesystem::atomic_write(
        &recovery_root.join("paths-switching"),
        operation_id.as_bytes(),
        0o600,
    )
    .map_err(restore_failure)?;
    switch_recovery_path(&target_data, &staged_data, operation, "data").map_err(restore_failure)?;
    switch_recovery_path(&target_secrets, &staged_secrets, operation, "secrets")
        .map_err(restore_failure)?;
    switch_recovery_path(&target_config, &staged_config, operation, "config")
        .map_err(restore_failure)?;
    let facts = RecoveryFacts {
        operation_id: operation.to_string(),
        snapshot_id: manifest.snapshot_id,
        manifest_sha256: manifest.manifest_sha256,
        restored_database: database,
        artifact: manifest.runtime_artifact,
        release: manifest.release,
        rollback_policy: manifest.rollback_policy,
        config_schema: manifest.config_schema,
    };
    let bytes = serde_json::to_vec_pretty(&facts).map_err(|error| restore_failure(error.into()))?;
    crate::filesystem::atomic_write(&completed_path, &bytes, 0o600).map_err(restore_failure)?;
    Ok(facts)
}

/// Start the restored deployment only as an exact, loopback-only recovery
/// candidate.  The normal runtime remains stopped; public activation is a
/// separate operation after the server has durably invalidated old tokens.
pub(crate) fn stage_recovery_candidate(
    scope_dir: &Path,
    state: &DeploymentState,
    recovery_operation_id: &str,
    state_epoch: &str,
) -> Result<RecoveryCandidateEndpoint, Failure> {
    let operation = Uuid::parse_str(recovery_operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery candidate operation id must be a UUID",
        )
    })?;
    let epoch = Uuid::parse_str(state_epoch).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery state epoch must be a UUID",
        )
    })?;
    if epoch.get_version_num() != 7 {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery state epoch must be UUIDv7",
        ));
    }
    let manifest = backup::load_manifest(scope_dir)
        .map_err(restore_failure)?
        .ok_or_else(|| Failure::new(RESTORE_TEST_FAILED, "no snapshot manifest exists"))?;
    if state
        .active_host_operation
        .as_ref()
        .is_none_or(|active| active.operation_id != recovery_operation_id)
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery candidate is not bound to the active restored deployment",
        ));
    }
    let completed_path = scope_dir
        .join("backup")
        .join("recoveries")
        .join(operation.to_string())
        .join("completed.json");
    let completed = crate::filesystem::read_secure_regular_file(
        &completed_path,
        "recovery completion",
        false,
        64 * 1024,
    )
    .map_err(restore_failure)?;
    let facts: RecoveryFacts =
        serde_json::from_slice(&completed).map_err(|error| restore_failure(error.into()))?;
    if facts.operation_id != recovery_operation_id
        || facts.manifest_sha256 != manifest.manifest_sha256
        || facts.artifact != manifest.runtime_artifact
        || facts.release != manifest.release
        || facts.rollback_policy != manifest.rollback_policy
        || facts.config_schema != manifest.config_schema
        || state.current_rollback_policy != facts.rollback_policy
    {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery candidate facts do not bind the accepted snapshot",
        ));
    }
    let kind = state.runtime.kind;
    if !matches!(
        kind,
        RuntimeBackendKind::Podman | RuntimeBackendKind::Docker
    ) {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery requires an OCI runtime for the isolated candidate",
        ));
    }
    let data = managed_directory(state, "app-data").map_err(restore_failure)?;
    let secrets = managed_directory(state, "app-secrets").map_err(restore_failure)?;
    let config = secure_regular_path(Path::new(&state.config.reference), "deployment config")
        .map_err(restore_failure)?;
    let backend = runtime_backend::backend(kind);
    let request = RecoveryCandidateRequest {
        source_object_reference: state.runtime.object.clone(),
        candidate_object_reference: format!("nazoauth-recovery-{operation}"),
        deployment_id: state.deployment_id.clone(),
        operation_id: recovery_operation_id.to_owned(),
        artifact: facts.artifact,
        data_source: data,
        secrets_source: secrets,
        config_source: config,
        valkey_state_epoch: state_epoch.to_owned(),
    };
    let endpoint = backend
        .stage_recovery_candidate(&request)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))?;
    let checked = (|| -> anyhow::Result<()> {
        let authority = issuer_authority(&state.issuer)?;
        fetch_http(endpoint.loopback_port, LOCAL_READINESS_PATH, &authority)?;
        ensure!(
            oidc_signing_key_ids(endpoint.loopback_port, &state.issuer)?
                == manifest.oidc_signing_key_ids,
            "recovery candidate OIDC signing keys differ from the snapshot"
        );
        Ok(())
    })();
    if let Err(error) = checked {
        let cleanup = backend.cleanup_recovery_candidate(&endpoint);
        let detail = match cleanup {
            Ok(()) => error.to_string(),
            Err(cleanup) => format!("{error}; candidate cleanup failed: {cleanup}"),
        };
        return Err(Failure::new(RESTORE_TEST_FAILED, sanitize(detail)));
    }
    Ok(endpoint)
}

/// Remove only the candidate whose immutable backend identity was returned by
/// [`stage_recovery_candidate`].
pub(crate) fn cleanup_recovery_candidate(
    state: &DeploymentState,
    endpoint: &RecoveryCandidateEndpoint,
) -> Result<(), Failure> {
    if endpoint.deployment_id != state.deployment_id {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery candidate belongs to a different deployment",
        ));
    }
    let kind = state.runtime.kind;
    runtime_backend::backend(kind)
        .cleanup_recovery_candidate(endpoint)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))
}

/// Start the original runtime only after the controller has waited past the
/// server-issued invalidation deadline.  It reuses the update replacement
/// constructor so recovery cannot invent a second activation policy.
pub(crate) fn activate_recovered_runtime(
    scope_dir: &Path,
    state: &DeploymentState,
    recovery_operation_id: &str,
    state_epoch: &str,
    not_before: i64,
) -> Result<(), Failure> {
    if Utc::now().timestamp() <= not_before {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "target clock has not passed the recovery invalidation deadline",
        ));
    }
    let operation = Uuid::parse_str(recovery_operation_id).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery activation operation id must be a UUID",
        )
    })?;
    let epoch = Uuid::parse_str(state_epoch).map_err(|_| {
        Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery activation state epoch must be a UUID",
        )
    })?;
    if epoch.get_version_num() != 7
        || state
            .active_host_operation
            .as_ref()
            .is_none_or(|active| active.operation_id != recovery_operation_id)
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "recovery activation is not bound to the restored deployment and UUIDv7 epoch",
        ));
    }
    let manifest = backup::load_manifest(scope_dir)
        .map_err(restore_failure)?
        .ok_or_else(|| Failure::new(RESTORE_TEST_FAILED, "no snapshot manifest exists"))?;
    let completed_path = scope_dir
        .join("backup")
        .join("recoveries")
        .join(operation.to_string())
        .join("completed.json");
    let completed = crate::filesystem::read_secure_regular_file(
        &completed_path,
        "recovery completion",
        false,
        64 * 1024,
    )
    .map_err(restore_failure)?;
    let facts: RecoveryFacts =
        serde_json::from_slice(&completed).map_err(|error| restore_failure(error.into()))?;
    if facts.operation_id != recovery_operation_id
        || facts.artifact != manifest.runtime_artifact
        || facts.release != manifest.release
        || facts.rollback_policy != manifest.rollback_policy
        || state.current_release.as_ref() != Some(&facts.release)
        || state.current_rollback_policy != facts.rollback_policy
    {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery activation facts do not bind the restored runtime",
        ));
    }
    let kind = state.runtime.kind;
    let backend = runtime_backend::backend(kind);
    let observed = backend
        .inspect(&state.runtime.object)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))?;
    if observed.running {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery activation refuses a runtime that is already running",
        ));
    }
    let mut replacement = super::update_exec::replacement_from_observation(
        &observed,
        &state.runtime.object,
        &facts.artifact,
    )?;
    replacement
        .environment
        .insert("VALKEY_STATE_EPOCH".to_owned(), state_epoch.to_owned());
    backend
        .replace(&replacement)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))?;
    backend
        .start(&state.runtime.object)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))?;
    let activated = backend
        .inspect(&state.runtime.object)
        .map_err(|error| Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string())))?;
    if !activated.running || activated.artifact != facts.artifact {
        return Err(Failure::new(
            RESTORE_TEST_FAILED,
            "recovery activation did not start the exact snapshot artifact",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_restore_rehearsal(
    restore_root: &Path,
    snapshot_dir: &Path,
    state: &DeploymentState,
    manifest: &SnapshotManifest,
    candidate: &str,
    database: &str,
    valkey_epoch: &str,
) -> anyhow::Result<()> {
    extract_deployment_archive(
        &snapshot_dir.join("deployment.tar"),
        restore_root,
        &manifest.archive_files,
    )?;
    let data = restore_root.join("app-data");
    let secrets = restore_root.join("app-secrets");
    let config = restore_root.join("config.yaml");
    ensure!(
        crate::filesystem::sha256(&secrets.join("mfa-totp-key"))? == manifest.mfa_key_sha256,
        "restored MFA key does not match the snapshot"
    );
    ensure!(
        verify_runtime_identity(&data, state)? == manifest.runtime_instance_key_id,
        "restored runtime identity does not match the snapshot"
    );
    let lifecycle_url_path = secrets.join("database-lifecycle-url");
    let original_connection = postgres_connection(&lifecycle_url_path)?;
    let isolated_lifecycle_url = original_connection.with_database(database);
    write_secret(
        &lifecycle_url_path,
        &isolated_lifecycle_url.with_password_url()?,
    )?;
    let runtime_url_path = secrets.join("database-runtime-url");
    let runtime_connection = postgres_connection(&runtime_url_path)?;
    write_secret(
        &runtime_url_path,
        &runtime_connection
            .with_database(database)
            .with_password_url()?,
    )?;
    prepare_runtime_ownership(state.runtime.kind, &data, &secrets, &config)?;
    create_database(&original_connection, database)?;
    let backend_kind = state.runtime.kind;
    let backend = runtime_backend::backend(backend_kind);
    let mut candidate_created = false;
    let rehearsal = (|| -> anyhow::Result<()> {
        restore_database(
            &original_connection,
            &snapshot_dir.join("postgresql.dump"),
            database,
        )?;
        ensure!(
            database_sentinel_with_connection(&original_connection.with_database(database))?
                == manifest.database_sentinel_sha256,
            "restored database sentinel does not match the snapshot"
        );
        // The snapshot was taken with --no-privileges, so the restored
        // database carries no runtime grants. `nazoauth migrate` is the sole
        // grant authority: run the same one-shot the install uses, pointed at
        // the isolated database, before the candidate starts.
        let runtime_role = {
            let connection = postgres_connection(&runtime_url_path)?;
            connection.url_without_password.username().to_owned()
        };
        run_restore_migration(
            backend.as_ref(),
            &manifest.runtime_artifact,
            &data,
            &config,
            &secrets,
            &runtime_role,
        )?;
        start_candidate(
            backend.as_ref(),
            backend_kind,
            state,
            manifest,
            candidate,
            &data,
            &secrets,
            &config,
            valkey_epoch,
        )?;
        candidate_created = true;
        Ok(())
    })();
    let mut cleanup_errors = Vec::new();
    if (candidate_created || backend.inspect_optional(candidate).ok().flatten().is_some())
        && let Err(error) = backend.remove(candidate)
    {
        cleanup_errors.push(format!("candidate removal failed: {error}"));
    }
    if let Err(error) = cleanup_valkey_namespace(
        &secrets.join("valkey-url"),
        &state.deployment_id,
        valkey_epoch,
    ) {
        cleanup_errors.push(format!("Valkey namespace cleanup failed: {error}"));
    }
    if let Err(error) = drop_database(&original_connection, database) {
        cleanup_errors.push(format!("isolated database cleanup failed: {error}"));
    }
    match (rehearsal, cleanup_errors.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => bail!(
            "restore-test cleanup was incomplete: {}",
            cleanup_errors.join("; ")
        ),
        (Err(error), true) => Err(error),
        (Err(error), false) => bail!(
            "{error}; restore-test cleanup was incomplete: {}",
            cleanup_errors.join("; ")
        ),
    }
}

/// Run the product's one-shot `nazoauth migrate` against the isolated restore
/// database so `configure_runtime_role` re-converges the runtime grant the
/// privilege-free dump dropped. Mirrors the install one-shot contract: the
/// lifecycle URL is supplied directly to the bounded one-shot environment.
fn run_restore_migration(
    backend: &dyn RuntimeBackend,
    artifact: &crate::runtime_backend::ArtifactReference,
    data: &Path,
    config: &Path,
    secrets: &Path,
    runtime_role: &str,
) -> anyhow::Result<()> {
    let lifecycle_url_path = secrets.join("database-lifecycle-url");
    let lifecycle_url = crate::filesystem::read_secure_regular_file(
        &lifecycle_url_path,
        "restore lifecycle database URL",
        false,
        16 * 1024,
    )?;
    let lifecycle_url = std::str::from_utf8(&lifecycle_url)
        .context("restore lifecycle database URL is not UTF-8")?
        .trim()
        .to_owned();
    ensure!(
        !lifecycle_url.is_empty(),
        "restore lifecycle database URL is empty"
    );
    let mut mounts = vec![
        NeutralMount {
            source: config.to_path_buf(),
            destination: PathBuf::from(CONTAINER_CONFIG_FILE),
            read_only: true,
            selinux_relabel: false,
            ownership: Responsibility::Managed,
            scope: crate::runtime_backend::RuntimeResourceScope::Deployment,
        },
        NeutralMount {
            source: data.to_path_buf(),
            destination: PathBuf::from(CONTAINER_DATA_DIR),
            read_only: false,
            selinux_relabel: false,
            ownership: Responsibility::Managed,
            scope: crate::runtime_backend::RuntimeResourceScope::Deployment,
        },
    ];
    mounts.extend(
        crate::target::install_exec::SECRET_PURPOSES
            .iter()
            .map(|name| NeutralMount {
                source: secrets.join(name),
                destination: Path::new(CONTAINER_SECRETS_DIR).join(name),
                read_only: true,
                selinux_relabel: false,
                ownership: Responsibility::Managed,
                scope: crate::runtime_backend::RuntimeResourceScope::Deployment,
            }),
    );
    let task = runtime_backend::OneShotTask {
        artifact: artifact.clone(),
        command: vec!["nazoauth".to_owned(), "migrate".to_owned()],
        network: Some("bridge".to_owned()),
        mounts,
        environment: BTreeMap::from([
            (
                SERVER_CONFIG_FILE_ENV.to_owned(),
                CONTAINER_CONFIG_FILE.to_owned(),
            ),
            ("DATABASE_URL".to_owned(), lifecycle_url),
            (
                MIGRATION_RUNTIME_ROLE_ENV.to_owned(),
                runtime_role.to_owned(),
            ),
        ]),
        working_directory: Some(PathBuf::from("/app")),
        service_user: Some(runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned()),
        transient_credentials: BTreeMap::new(),
        read_only_paths: Vec::new(),
        read_write_paths: Vec::new(),
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin: Vec::new(),
    };
    backend
        .run_one_shot(&task)
        .map(|_: String| ())
        .map_err(|error| anyhow::anyhow!(sanitize(error.to_string())))
}

fn managed_directory(state: &DeploymentState, id: &str) -> anyhow::Result<PathBuf> {
    let path = managed_directory_locator(state, id)?;
    let meta = fs::symlink_metadata(&path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("backup resource is not a real directory");
    }
    Ok(path)
}

fn managed_directory_locator(state: &DeploymentState, id: &str) -> anyhow::Result<PathBuf> {
    let resource = state
        .resources
        .iter()
        .find(|resource| resource.resource_id == id)
        .context("deployment lacks required managed backup resource")?;
    if resource.kind != "directory"
        || resource.ownership != ResourceOwnership::Managed
        || resource.scope != ResourceScope::Deployment
    {
        bail!("backup resource has an invalid ownership contract");
    }
    Ok(PathBuf::from(&resource.locator))
}

fn secure_regular_path(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} is not a real regular file");
    }
    Ok(path.to_path_buf())
}

fn snapshot_file(path: &Path, root: &Path) -> anyhow::Result<SnapshotFile> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SNAPSHOT_FILE_BYTES
    {
        bail!("snapshot artifact is not an allowed regular file");
    }
    Ok(SnapshotFile {
        path: relative_archive_path(path.strip_prefix(root)?)?,
        size: metadata.len(),
        sha256: crate::filesystem::sha256(path)?,
    })
}

fn verify_snapshot_files(root: &Path, manifest: &SnapshotManifest) -> anyhow::Result<()> {
    manifest.validate()?;
    let expected: BTreeSet<&str> = ["postgresql.dump", "deployment.tar"].into_iter().collect();
    let actual = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "snapshot manifest does not contain the required artifact set"
    );
    for file in &manifest.files {
        verify_file(root, file)?;
    }
    Ok(())
}

fn verify_file(root: &Path, expected: &SnapshotFile) -> anyhow::Result<()> {
    expected.validate()?;
    let path = root.join(&expected.path);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != expected.size
        || crate::filesystem::sha256(&path)? != expected.sha256
    {
        bail!(
            "snapshot file '{}' does not match its manifest",
            expected.path
        );
    }
    Ok(())
}

fn create_deployment_archive(
    destination: &Path,
    data: &Path,
    secrets: &Path,
    config: &Path,
    sentinel: &[u8],
) -> anyhow::Result<Vec<SnapshotFile>> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut archive = TarBuilder::new(file);
    let mut files = Vec::new();
    append_tree(&mut archive, data, Path::new("app-data"), &mut files)?;
    append_directory(&mut archive, Path::new("app-secrets"))?;
    for name in crate::target::install_exec::SECRET_PURPOSES {
        append_regular(
            &mut archive,
            &secrets.join(name),
            &Path::new("app-secrets").join(name),
            &mut files,
        )?;
    }
    append_regular(&mut archive, config, Path::new("config.yaml"), &mut files)?;
    append_bytes(
        &mut archive,
        Path::new(SNAPSHOT_SENTINEL_FILE),
        sentinel,
        &mut files,
    )?;
    archive.finish()?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn append_tree(
    archive: &mut TarBuilder<fs::File>,
    source: &Path,
    archive_path: &Path,
    files: &mut Vec<SnapshotFile>,
) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("snapshot source tree is not a real directory");
    }
    append_directory(archive, archive_path)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().context("snapshot tree entry is not UTF-8")?;
        let child_archive = archive_path.join(name);
        let child = entry.path();
        let child_meta = fs::symlink_metadata(&child)?;
        if child_meta.file_type().is_symlink() {
            bail!("snapshot source tree contains a symbolic link");
        }
        if child_meta.is_dir() {
            append_tree(archive, &child, &child_archive, files)?;
        } else if child_meta.is_file() {
            append_regular(archive, &child, &child_archive, files)?;
        } else {
            bail!("snapshot source tree contains a non-regular entry");
        }
    }
    Ok(())
}

fn append_directory(archive: &mut TarBuilder<fs::File>, archive_path: &Path) -> anyhow::Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_mode(0o700);
    header.set_size(0);
    header.set_entry_type(EntryType::Directory);
    header.set_cksum();
    archive.append_data(&mut header, archive_path, std::io::empty())?;
    Ok(())
}

fn append_regular(
    archive: &mut TarBuilder<fs::File>,
    source: &Path,
    archive_path: &Path,
    files: &mut Vec<SnapshotFile>,
) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SNAPSHOT_FILE_BYTES
    {
        bail!("snapshot source is not an allowed regular file");
    }
    let mut file = fs::File::open(source)?;
    archive.append_file(archive_path, &mut file)?;
    files.push(SnapshotFile {
        path: relative_archive_path(archive_path)?,
        size: metadata.len(),
        sha256: crate::filesystem::sha256(source)?,
    });
    Ok(())
}

fn append_bytes(
    archive: &mut TarBuilder<fs::File>,
    archive_path: &Path,
    bytes: &[u8],
    files: &mut Vec<SnapshotFile>,
) -> anyhow::Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_mode(0o600);
    header.set_size(bytes.len() as u64);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    archive.append_data(&mut header, archive_path, bytes)?;
    files.push(SnapshotFile {
        path: relative_archive_path(archive_path)?,
        size: bytes.len() as u64,
        sha256: backup::hex_digest(bytes),
    });
    Ok(())
}

fn relative_archive_path(path: &Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            bail!("snapshot path is not normalized and relative");
        };
        parts.push(value.to_str().context("snapshot path is not UTF-8")?);
    }
    ensure!(!parts.is_empty(), "snapshot path is empty");
    Ok(parts.join("/"))
}

fn extract_deployment_archive(
    archive_path: &Path,
    destination: &Path,
    expected: &[SnapshotFile],
) -> anyhow::Result<()> {
    let file = fs::File::open(archive_path)?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if !matches!(entry_type, EntryType::Regular | EntryType::Directory) {
            bail!("deployment archive contains a non-file entry");
        }
        let path = entry.path()?.into_owned();
        relative_archive_path(&path)?;
        if !entry.unpack_in(destination)? {
            bail!("deployment archive entry escapes the restore-test directory");
        }
    }
    let mut found = Vec::new();
    collect_regular_files(destination, destination, &mut found)?;
    found.sort_by(|left, right| left.path.cmp(&right.path));
    let mut expected = expected.to_vec();
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    ensure!(
        found == expected,
        "extracted deployment files do not match the manifest"
    );
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<SnapshotFile>,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("extracted deployment tree contains a symbolic link");
        }
        if metadata.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(snapshot_file(&path, root)?);
        } else {
            bail!("extracted deployment tree contains a non-regular entry");
        }
    }
    Ok(())
}

fn observe_exact_runtime_artifact(state: &DeploymentState) -> anyhow::Result<ArtifactReference> {
    let kind = state.runtime.kind;
    let backend = runtime_backend::backend(kind);
    let observation = backend.inspect(&state.runtime.object)?;
    ensure!(observation.running, "deployment runtime is not running");
    artifact_matches_state(&observation.artifact, state)?;
    Ok(observation.artifact)
}

fn artifact_matches_state(
    artifact: &ArtifactReference,
    state: &DeploymentState,
) -> anyhow::Result<()> {
    let current = state
        .artifact
        .current
        .as_deref()
        .context("deployment has no current artifact reference")?;
    match artifact {
        ArtifactReference::Oci { digest, .. } => {
            ensure!(
                digest == current,
                "runtime artifact differs from DeploymentState"
            );
        }
        ArtifactReference::HostBinary { sha256, .. } => {
            ensure!(
                current == format!("sha256:{sha256}"),
                "host runtime artifact differs from DeploymentState"
            );
        }
        ArtifactReference::Unknown => bail!("runtime artifact is unknown"),
    }
    Ok(())
}

fn verify_runtime_identity(data: &Path, state: &DeploymentState) -> anyhow::Result<String> {
    let identity_dir = data.join("instance");
    let public_bytes = super::read_runtime_owned_file(
        &identity_dir.join("identity.pub"),
        "runtime instance public key",
        false,
        MAX_KEY_BYTES,
        state,
    )?;
    let encoded = std::str::from_utf8(public_bytes.trim_ascii())?;
    let public_key = nazo_operator_protocol::decode_instance_public_key(encoded)?;
    let key_id = nazo_operator_protocol::instance_key_id(&public_key);
    let statement_bytes = super::read_runtime_owned_file(
        &identity_dir.join("deployment-statement.jws"),
        "runtime deployment statement",
        false,
        nazo_operator_protocol::MAX_COMPACT_JWS_BYTES as u64,
        state,
    )?;
    let statement = nazo_operator_protocol::verify_deployment_statement(
        std::str::from_utf8(statement_bytes.trim_ascii())?,
        &key_id,
        &public_key,
    )?;
    ensure!(
        statement.deployment_id == state.deployment_id
            && statement.issuer == state.issuer
            && statement.product == nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT,
        "runtime deployment statement does not match DeploymentState"
    );
    Ok(key_id)
}

fn run_pg_dump(database_url_file: &Path, output: &Path) -> anyhow::Result<()> {
    let connection = postgres_connection(database_url_file)?;
    run_postgres_command(
        "pg_dump",
        &connection,
        [
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--file",
            output.to_str().context("snapshot path is not UTF-8")?,
        ],
    )?;
    Ok(())
}
fn create_database(connection: &PostgresConnection, database: &str) -> anyhow::Result<()> {
    run_postgres_util("createdb", &connection.maintenance(), [database])?;
    Ok(())
}
fn restore_database(
    connection: &PostgresConnection,
    dump: &Path,
    database: &str,
) -> anyhow::Result<()> {
    run_postgres_command(
        "pg_restore",
        &connection.with_database(database),
        [
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
            dump.to_str().context("snapshot path is not UTF-8")?,
        ],
    )?;
    Ok(())
}
fn drop_database(connection: &PostgresConnection, database: &str) -> anyhow::Result<()> {
    run_postgres_util(
        "dropdb",
        &connection.maintenance(),
        ["--if-exists", database],
    )?;
    Ok(())
}

#[derive(Clone)]
struct PostgresConnection {
    url_without_password: Url,
    password: String,
}
impl PostgresConnection {
    fn with_database(&self, database: &str) -> Self {
        let mut url = self.url_without_password.clone();
        url.set_path(&format!("/{database}"));
        Self {
            url_without_password: url,
            password: self.password.clone(),
        }
    }
    fn maintenance(&self) -> Self {
        self.with_database("postgres")
    }
    fn with_password_url(&self) -> anyhow::Result<String> {
        let mut url = self.url_without_password.clone();
        url.set_password(Some(&self.password))
            .map_err(|_| anyhow::anyhow!("cannot restore database password"))?;
        Ok(url.into())
    }
}
fn postgres_connection(path: &Path) -> anyhow::Result<PostgresConnection> {
    let bytes = crate::filesystem::read_secure_regular_file(path, "database URL", false, 4096)?;
    let mut url =
        Url::parse(std::str::from_utf8(&bytes)?.trim()).context("database URL is invalid")?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        bail!("database URL is not PostgreSQL");
    }
    let password = urlencoding::decode(url.password().context("database URL has no password")?)
        .context("database URL password is not valid percent-encoding")?
        .into_owned();
    ensure!(
        !password.contains(['\r', '\n', '\0']),
        "database password is invalid"
    );
    url.set_password(None)
        .map_err(|_| anyhow::anyhow!("cannot remove database password"))?;
    Ok(PostgresConnection {
        url_without_password: url,
        password,
    })
}
fn run_postgres_command<'a>(
    program: &str,
    connection: &PostgresConnection,
    extra: impl IntoIterator<Item = &'a str>,
) -> anyhow::Result<Output> {
    let output = Command::new(program)
        .arg("--dbname")
        .arg(connection.url_without_password.as_str())
        .args(extra)
        .env("PGPASSWORD", &connection.password)
        .output()
        .with_context(|| format!("failed to start {program}"))?;
    ensure_postgres_output(program, output)
}

/// `createdb` and `dropdb` take the database name positionally and have no
/// `--dbname` connection flag; they receive the connection as flags instead.
fn run_postgres_util<'a>(
    program: &str,
    connection: &PostgresConnection,
    extra: impl IntoIterator<Item = &'a str>,
) -> anyhow::Result<Output> {
    let url = &connection.url_without_password;
    let host = url.host_str().context("database URL has no host")?;
    let port = url.port().unwrap_or(5432);
    let user = url.username();
    ensure!(!user.is_empty(), "database URL has no user");
    let output = Command::new(program)
        .arg("--host")
        .arg(host)
        .arg("--port")
        .arg(port.to_string())
        .arg("--username")
        .arg(user)
        .args(extra)
        .env("PGPASSWORD", &connection.password)
        .output()
        .with_context(|| format!("failed to start {program}"))?;
    ensure_postgres_output(program, output)
}

fn ensure_postgres_output(program: &str, output: std::process::Output) -> anyhow::Result<Output> {
    if !output.status.success() {
        bail!(
            "{program} failed with {}: {}",
            output.status,
            sanitize(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        );
    }
    Ok(output)
}
fn database_sentinel(database_url_file: &Path) -> anyhow::Result<String> {
    database_sentinel_with_connection(&postgres_connection(database_url_file)?)
}
fn database_sentinel_with_connection(connection: &PostgresConnection) -> anyhow::Result<String> {
    let output = run_postgres_command(
        "psql",
        connection,
        [
            "--no-align",
            "--tuples-only",
            "--command",
            DATABASE_SENTINEL_SQL,
        ],
    )?;
    ensure!(
        output.stdout.len() <= 1024,
        "database sentinel output is unexpectedly large"
    );
    let value = std::str::from_utf8(&output.stdout)?.trim();
    ensure!(!value.is_empty(), "database has no migration sentinel");
    Ok(backup::hex_digest(value.as_bytes()))
}

fn database_exists(connection: &PostgresConnection, database: &str) -> anyhow::Result<bool> {
    let query = database_exists_query(database)?;
    let output = run_postgres_command(
        "psql",
        &connection.maintenance(),
        ["--no-align", "--tuples-only", "--command", &query],
    )?;
    Ok(std::str::from_utf8(&output.stdout)?.trim() == "t")
}

fn database_exists_query(database: &str) -> anyhow::Result<String> {
    crate::registry::validate_identifier(database, 128, "database name")?;
    Ok(format!(
        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = '{database}')"
    ))
}

pub(crate) fn recovery_path_switch_started(
    scope_dir: &Path,
    operation_id: &str,
) -> anyhow::Result<bool> {
    let operation = Uuid::parse_str(operation_id).context("recovery operation id is not a UUID")?;
    Ok(scope_dir
        .join("backup")
        .join("recoveries")
        .join(operation.to_string())
        .join("paths-switching")
        .try_exists()?)
}

fn sibling_operation_path(target: &Path, operation: Uuid, suffix: &str) -> anyhow::Result<PathBuf> {
    let parent = target.parent().context("recovery target has no parent")?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .context("recovery target name is not UTF-8")?;
    Ok(parent.join(format!(".{name}.nazo-recovery-{operation}-{suffix}")))
}

fn copy_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "recovery source is not a real directory"
    );
    fs::create_dir(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source = entry.path();
        let destination = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink() {
            bail!("recovery source contains a symbolic link");
        }
        if metadata.is_dir() {
            copy_tree(&source, &destination)?;
        } else if metadata.is_file() {
            fs::copy(&source, &destination)?;
        } else {
            bail!("recovery source contains a non-regular entry");
        }
    }
    Ok(())
}

fn switch_recovery_path(
    target: &Path,
    staged: &Path,
    operation: Uuid,
    label: &str,
) -> anyhow::Result<()> {
    let rollback = sibling_operation_path(target, operation, &format!("{label}-rollback"))?;
    match (target.exists(), staged.exists(), rollback.exists()) {
        (true, true, false) => {
            fs::rename(target, &rollback)?;
            fs::rename(staged, target)?;
        }
        (false, true, true) => fs::rename(staged, target)?,
        (true, false, true) => {}
        (true, true, true) => bail!(
            "recovery {label} has both current and staged paths after rollback was established"
        ),
        _ => bail!("recovery {label} path state is not forward-resumable"),
    }
    Ok(())
}

fn recovery_path_switched(target: &Path, operation: Uuid, label: &str) -> anyhow::Result<bool> {
    let rollback = sibling_operation_path(target, operation, &format!("{label}-rollback"))?;
    Ok(target.exists() && rollback.exists())
}

#[allow(clippy::too_many_arguments)]
fn start_candidate(
    backend: &dyn RuntimeBackend,
    kind: RuntimeBackendKind,
    state: &DeploymentState,
    manifest: &SnapshotManifest,
    candidate: &str,
    data: &Path,
    secrets: &Path,
    config: &Path,
    valkey_epoch: &str,
) -> anyhow::Result<()> {
    ensure!(
        matches!(
            kind,
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker
        ),
        "restore-test candidate requires the deployment's OCI runtime; systemd cannot safely run a second instance from current state"
    );
    ensure!(
        backend.inspect_optional(candidate)?.is_none(),
        "restore-test candidate name is occupied"
    );
    let live = backend.inspect(&state.runtime.object)?;
    ensure!(
        live.running && live.artifact == manifest.runtime_artifact,
        "source runtime artifact changed after snapshot"
    );
    let mut mounts = live.mounts.clone();
    replace_mount(&mut mounts, CONTAINER_DATA_DIR, data, false)?;
    // The runtime mounts each allowlisted secret file individually, never the
    // directory; repoint every one into the restored secrets directory.
    let mut secret_mounts = 0;
    for mount in mounts.iter_mut() {
        let relative = match mount
            .destination
            .strip_prefix(Path::new(CONTAINER_SECRETS_DIR))
        {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let name = relative
            .file_name()
            .context("secret mount destination has no file name")?;
        mount.source = secrets.join(name);
        mount.read_only = true;
        secret_mounts += 1;
    }
    ensure!(
        secret_mounts > 0,
        "runtime mounts no secrets under {CONTAINER_SECRETS_DIR}"
    );
    replace_mount(&mut mounts, CONTAINER_CONFIG_FILE, config, true)?;
    let port = reserve_loopback_port()?;
    let mut environment = live.safe_environment.clone();
    environment.insert(
        SERVER_CONFIG_FILE_ENV.to_owned(),
        CONTAINER_CONFIG_FILE.to_owned(),
    );
    environment.insert("BIND".to_owned(), "0.0.0.0:8000".to_owned());
    environment.insert("VALKEY_STATE_EPOCH".to_owned(), valkey_epoch.to_owned());
    let replacement = RuntimeReplacement {
        object_reference: candidate.to_owned(),
        artifact: manifest.runtime_artifact.clone(),
        // Start from the manifest's digest-bound reference, never the bare
        // local image ID: the observed artifact must equal the recorded one.
        local_artifact_id: None,
        command: vec!["nazoauth".to_owned(), "server".to_owned()],
        mounts,
        environment,
        networks: live.networks.clone(),
        ip_address: None,
        ports: vec![format!("127.0.0.1:{port}:8000/tcp")],
        // Never copy reverse-proxy/ingress labels from the production object.
        // The only label is ownership identity; the only published socket is
        // loopback below.
        labels: BTreeMap::from([(
            "io.nazoauth.deployment-id".to_owned(),
            state.deployment_id.clone(),
        )]),
        container_policy: Some(ContainerRuntimePolicy::managed_app()),
    };
    backend.replace(&replacement)?;
    let authority = issuer_authority(&state.issuer)?;
    fetch_http(port, LOCAL_READINESS_PATH, &authority)?;
    ensure!(
        oidc_signing_key_ids(port, &state.issuer)? == manifest.oidc_signing_key_ids,
        "candidate OIDC signing keys differ from the snapshot"
    );
    let observed = backend.inspect(candidate)?;
    ensure!(
        observed.running
            && observed.server_command_verified
            && observed.artifact == manifest.runtime_artifact,
        "restore-test candidate runtime identity is not the exact snapshot artifact"
    );
    Ok(())
}
fn replace_mount(
    mounts: &mut [NeutralMount],
    destination: &str,
    source: &Path,
    read_only: bool,
) -> anyhow::Result<()> {
    let matching = mounts
        .iter_mut()
        .filter(|mount| mount.destination == Path::new(destination))
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "runtime does not have exactly one {destination} mount"
    );
    let mount = matching.into_iter().next().expect("length checked");
    mount.source = source.to_path_buf();
    mount.read_only = read_only;
    Ok(())
}
fn reserve_loopback_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}
fn fetch_http(port: u16, path: &str, host: &str) -> anyhow::Result<Vec<u8>> {
    let endpoint = format!("http://127.0.0.1:{port}{path}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::from("probe did not run");
    while Instant::now() < deadline {
        let mut command = Command::new("curl");
        command.args([
            "--silent",
            "--show-error",
            "--fail",
            "--connect-timeout",
            "2",
            "--max-time",
            "5",
        ]);
        command.args(["--header", &format!("Host: {host}")]);
        let output = command.arg(&endpoint).output();
        match output {
            Ok(output) if output.status.success() => {
                ensure!(
                    output.stdout.len() <= 1024 * 1024,
                    "HTTP probe response is too large"
                );
                return Ok(output.stdout);
            }
            Ok(output) => {
                last = sanitize(String::from_utf8_lossy(&output.stderr).trim().to_owned())
            }
            Err(error) => last = sanitize(error.to_string()),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("candidate probe {path} failed: {last}")
}

fn source_oidc_signing_key_ids(state: &DeploymentState) -> anyhow::Result<Vec<String>> {
    let backend = runtime_backend::backend(state.runtime.kind);
    let observation = backend.inspect(&state.runtime.object)?;
    let port = observation
        .ports
        .iter()
        .find_map(|binding| host_port_for_container_8000(binding))
        .context("runtime has no loopback host binding for container port 8000")?;
    oidc_signing_key_ids(port, &state.issuer)
}

fn host_port_for_container_8000(binding: &str) -> Option<u16> {
    let host = binding
        .strip_suffix("->8000/tcp")
        .or_else(|| binding.strip_suffix(":8000/tcp"))?;
    host.trim_end_matches(':').rsplit(':').next()?.parse().ok()
}

fn oidc_signing_key_ids(port: u16, expected_issuer: &str) -> anyhow::Result<Vec<String>> {
    let issuer = Url::parse(expected_issuer)?;
    let authority = issuer_authority(expected_issuer)?;
    let discovery: serde_json::Value = serde_json::from_slice(&fetch_http(
        port,
        "/.well-known/openid-configuration",
        &authority,
    )?)?;
    ensure!(
        discovery.get("issuer").and_then(serde_json::Value::as_str) == Some(expected_issuer),
        "OIDC discovery issuer differs from DeploymentState"
    );
    let jwks = Url::parse(
        discovery
            .get("jwks_uri")
            .and_then(serde_json::Value::as_str)
            .context("OIDC discovery omitted jwks_uri")?,
    )?;
    ensure!(
        issuer.scheme() == jwks.scheme()
            && issuer.host_str() == jwks.host_str()
            && issuer.port_or_known_default() == jwks.port_or_known_default(),
        "OIDC jwks_uri is outside the deployment issuer origin"
    );
    let path = match jwks.query() {
        Some(query) => format!("{}?{query}", jwks.path()),
        None => jwks.path().to_owned(),
    };
    let document: serde_json::Value =
        serde_json::from_slice(&fetch_http(port, &path, &authority)?)?;
    let mut key_ids = document
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .context("JWKS omitted keys")?
        .iter()
        .map(|key| {
            key.get("kid")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .context("JWKS key omitted kid")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    key_ids.sort();
    key_ids.dedup();
    ensure!(
        !key_ids.is_empty() && key_ids.len() <= 32,
        "JWKS key set is empty or too large"
    );
    Ok(key_ids)
}

fn issuer_authority(expected_issuer: &str) -> anyhow::Result<String> {
    let issuer = Url::parse(expected_issuer)?;
    let host = issuer.host_str().context("deployment issuer has no host")?;
    Ok(match issuer.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
fn candidate_name(source: &str, id: Uuid) -> String {
    format!(
        "{}-restore-{}",
        source.chars().take(180).collect::<String>(),
        id.simple()
    )
}
fn write_secret(path: &Path, value: &str) -> anyhow::Result<()> {
    crate::filesystem::atomic_write(path, value.as_bytes(), 0o440)
}

fn prepare_stage_ownership_if_present(
    kind: RuntimeBackendKind,
    data: &Path,
    secrets: &Path,
    config: &Path,
) -> anyhow::Result<()> {
    if !data.exists() && !secrets.exists() && !config.exists() {
        return Ok(());
    }
    let preserve_owner = preserve_runtime_owner(kind, [data, secrets, config])?;
    if data.exists() {
        runtime_ownership(super::install_exec::set_runtime_identity_directory_data(
            data,
            preserve_owner,
        ))?;
    }
    if secrets.exists() {
        prepare_secrets_ownership(secrets, preserve_owner)?;
    }
    if config.exists() {
        runtime_ownership(super::install_exec::set_runtime_identity(
            config,
            false,
            preserve_owner,
        ))?;
    }
    Ok(())
}

fn prepare_runtime_ownership(
    kind: RuntimeBackendKind,
    data: &Path,
    secrets: &Path,
    config: &Path,
) -> anyhow::Result<()> {
    let preserve_owner = preserve_runtime_owner(kind, [data, secrets, config])?;
    runtime_ownership(super::install_exec::set_runtime_identity_directory_data(
        data,
        preserve_owner,
    ))?;
    prepare_secrets_ownership(secrets, preserve_owner)?;
    runtime_ownership(super::install_exec::set_runtime_identity(
        config,
        false,
        preserve_owner,
    ))
}

fn prepare_secrets_ownership(secrets: &Path, preserve_owner: bool) -> anyhow::Result<()> {
    runtime_ownership(super::install_exec::set_runtime_identity_directory(
        secrets,
        preserve_owner,
    ))?;
    for entry in fs::read_dir(secrets)? {
        let path = entry?.path();
        runtime_ownership(super::install_exec::set_runtime_identity(
            &path,
            false,
            preserve_owner,
        ))?;
    }
    Ok(())
}

fn preserve_runtime_owner<'a>(
    kind: RuntimeBackendKind,
    paths: impl IntoIterator<Item = &'a Path>,
) -> anyhow::Result<bool> {
    if kind != RuntimeBackendKind::Podman {
        return Ok(false);
    }
    let path = paths
        .into_iter()
        .find(|path| path.exists())
        .context("runtime ownership has no existing path")?;
    Ok(super::install_exec::path_is_owned_by_non_root(path)?)
}

fn runtime_ownership(result: Result<(), Failure>) -> anyhow::Result<()> {
    result.map_err(|failure| anyhow::anyhow!(failure.detail))
}

fn cleanup_valkey_namespace(
    valkey_url_file: &Path,
    deployment_id: &str,
    epoch: &str,
) -> anyhow::Result<()> {
    let bytes =
        crate::filesystem::read_secure_regular_file(valkey_url_file, "Valkey URL", false, 4096)?;
    let mut url = Url::parse(std::str::from_utf8(&bytes)?.trim())?;
    ensure!(
        matches!(url.scheme(), "redis" | "rediss" | "valkey"),
        "Valkey URL has an invalid scheme"
    );
    let password = url
        .password()
        .context("Valkey URL has no password")?
        .to_owned();
    url.set_password(None)
        .map_err(|_| anyhow::anyhow!("cannot remove Valkey password"))?;
    let prefix = format!("nazo:state:v1:{deployment_id}:{epoch}:");
    let output = Command::new("valkey-cli")
        .args([
            "--no-auth-warning",
            "-u",
            url.as_str(),
            "--scan",
            "--pattern",
        ])
        .arg(format!("{prefix}*"))
        .env("REDISCLI_AUTH", &password)
        .output()
        .context("failed to start valkey-cli cleanup")?;
    ensure!(output.status.success(), "Valkey namespace scan failed");
    ensure!(
        output.stdout.len() <= MAX_VALKEY_CLEANUP_OUTPUT,
        "Valkey cleanup key set is too large"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let keys = text
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        keys.len() <= 4096 && keys.iter().all(|key| key.starts_with(&prefix)),
        "Valkey cleanup returned an invalid key set"
    );
    for batch in keys.chunks(256) {
        let output = Command::new("valkey-cli")
            .args(["--no-auth-warning", "-u", url.as_str(), "UNLINK"])
            .args(batch)
            .env("REDISCLI_AUTH", &password)
            .output()?;
        ensure!(output.status.success(), "Valkey namespace unlink failed");
    }
    Ok(())
}
fn remove_receipt_if_present(scope_dir: &Path) -> anyhow::Result<()> {
    for path in [
        backup::receipt_path(scope_dir),
        backup::off_host_receipt_path(scope_dir),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("failed to remove stale backup receipt");
            }
        }
    }
    Ok(())
}

fn write_restore_failure(
    scope_dir: &Path,
    manifest: &SnapshotManifest,
    rehearsal_id: Uuid,
    detail: &str,
) {
    let bounded = sanitize(detail.chars().take(2048).collect::<String>());
    let document = serde_json::json!({
        "schema": 1,
        "deployment_id": manifest.deployment_id,
        "snapshot_id": manifest.snapshot_id,
        "manifest_sha256": manifest.manifest_sha256,
        "rehearsal_id": rehearsal_id,
        "failed_at": Utc::now(),
        "detail": bounded,
    });
    if let Ok(bytes) = serde_json::to_vec_pretty(&document) {
        let path = scope_dir.join("backup").join("restore-test-failure.json");
        let _ = crate::filesystem::atomic_write(&path, &bytes, 0o600);
    }
}

fn remove_file_if_present(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn backup_failure(error: anyhow::Error) -> Failure {
    Failure::new(BACKUP_EXECUTION_FAILED, sanitize(error.to_string()))
}
fn restore_failure(error: anyhow::Error) -> Failure {
    Failure::new(RESTORE_TEST_FAILED, sanitize(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_of_published_snapshot_finishes_receipt_cleanup() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-published-replay")?;
        let store = super::super::deployment_state::TargetStateStore::open(temp.path())?;
        let deployment_id = "deploy-alpha";
        let operation_id = Uuid::now_v7().to_string();
        let artifact_digest = "a".repeat(64);
        store.bootstrap(
            deployment_id,
            super::super::deployment_state::BootstrapParams {
                issuer: "https://auth.example.com".to_owned(),
                runtime: super::super::deployment_state::RuntimeSurface::new(
                    "host",
                    "nazoauth.service",
                    8000,
                )?,
                artifact: super::super::deployment_state::ArtifactRefs {
                    current: Some(format!("sha256:{artifact_digest}")),
                    previous: None,
                },
                config_reference: temp
                    .path()
                    .join("config.yaml")
                    .to_string_lossy()
                    .into_owned(),
                config_schema: "nazoauth-config-v1".to_owned(),
                resources: Vec::new(),
                current_release: Some(ReleaseVersion::new("v1")?),
                current_rollback_policy: crate::model::test_release_rollback_policy(),
            },
            "bootstrap-op",
        )?;
        let state = store.load_existing(deployment_id)?;
        let scope_dir = store.scope_dir(deployment_id)?;
        let final_dir = scope_dir
            .join("backup/snapshots")
            .join(operation_id.as_str());
        fs::create_dir_all(&final_dir)?;
        fs::write(final_dir.join("postgresql.dump"), b"database")?;
        fs::write(final_dir.join("deployment.tar"), b"archive")?;
        let files = ["postgresql.dump", "deployment.tar"]
            .into_iter()
            .map(|name| snapshot_file(&final_dir.join(name), &final_dir))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut manifest = SnapshotManifest {
            schema: backup::BACKUP_MANIFEST_SCHEMA,
            deployment_id: deployment_id.to_owned(),
            snapshot_id: operation_id.clone(),
            created_at: Utc::now(),
            runtime_artifact: ArtifactReference::HostBinary {
                path: temp.path().join("nazoauth"),
                sha256: artifact_digest,
            },
            release: ReleaseVersion::new("v1")?,
            rollback_policy: crate::model::test_release_rollback_policy(),
            config_schema: "nazoauth-config-v1".to_owned(),
            files,
            archive_files: vec![SnapshotFile {
                path: SNAPSHOT_SENTINEL_FILE.to_owned(),
                size: 0,
                sha256: backup::hex_digest(b""),
            }],
            database_sentinel_sha256: "b".repeat(64),
            mfa_key_sha256: "c".repeat(64),
            runtime_instance_key_id: "instance-key".to_owned(),
            oidc_signing_key_ids: vec!["signing-key".to_owned()],
            manifest_sha256: String::new(),
        };
        manifest.manifest_sha256 = manifest.computed_sha256()?;
        backup::write_manifest_at(&final_dir.join(IMMUTABLE_MANIFEST_FILE), &manifest)?;
        fs::write(backup::receipt_path(&scope_dir), b"stale")?;
        fs::write(backup::off_host_receipt_path(&scope_dir), b"stale")?;

        let replayed = snapshot(&scope_dir, &state, &operation_id)?;
        assert_eq!(replayed, manifest);
        assert!(!backup::receipt_path(&scope_dir).exists());
        assert!(!backup::off_host_receipt_path(&scope_dir).exists());
        assert_eq!(backup::load_manifest(&scope_dir)?, Some(manifest));
        Ok(())
    }

    #[test]
    fn transfer_writes_are_bounded_offset_exact_and_resume_safe() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-transfer-write")?;
        let operation = Uuid::now_v7().to_string();
        prepare_import(temp.path(), "deploy-alpha", &operation)?;
        let digest = "a".repeat(64);
        let first = BackupTransferBytes::try_new(b"abc".to_vec())?;
        write_transfer_chunk(
            temp.path(),
            &operation,
            "deployment.tar",
            0,
            6,
            &digest,
            &first,
        )?;
        let second = BackupTransferBytes::try_new(b"def".to_vec())?;
        write_transfer_chunk(
            temp.path(),
            &operation,
            "deployment.tar",
            3,
            6,
            &digest,
            &second,
        )?;
        let path = temp
            .path()
            .join("backup/transfers")
            .join(format!("import-{operation}.partial"))
            .join("deployment.tar");
        assert_eq!(fs::read(path)?, b"abcdef");
        assert!(
            write_transfer_chunk(
                temp.path(),
                &operation,
                "deployment.tar",
                1,
                6,
                &digest,
                &second,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn archive_round_trip_binds_every_regular_file_and_rejects_extra_bytes() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-archive-test")?;
        let data = temp.path().join("data");
        let secrets = temp.path().join("secrets");
        fs::create_dir_all(data.join("instance"))?;
        fs::create_dir_all(&secrets)?;
        fs::write(data.join("instance/identity.pub"), b"identity")?;
        for name in crate::target::install_exec::SECRET_PURPOSES {
            fs::write(secrets.join(name), name.as_bytes())?;
        }
        fs::write(secrets.join("unknown-legacy-secret"), b"excluded")?;
        let config = temp.path().join("config.yaml");
        fs::write(&config, b"BIND: 0.0.0.0:8000")?;
        let archive = temp.path().join("deployment.tar");
        let files = create_deployment_archive(&archive, &data, &secrets, &config, b"sentinel")?;
        let restored = temp.path().join("restored");
        fs::create_dir(&restored)?;
        extract_deployment_archive(&archive, &restored, &files)?;
        for name in crate::target::install_exec::SECRET_PURPOSES {
            assert_eq!(
                fs::read(restored.join("app-secrets").join(name))?,
                name.as_bytes()
            );
        }
        assert!(!restored.join("app-secrets/unknown-legacy-secret").exists());
        fs::write(restored.join("extra"), b"not in manifest")?;
        let second = temp.path().join("second");
        fs::create_dir(&second)?;
        extract_deployment_archive(&archive, &second, &files)?;
        fs::write(second.join("extra"), b"not in manifest")?;
        let mut found = Vec::new();
        collect_regular_files(&second, &second, &mut found)?;
        assert_ne!(found.len(), files.len());
        Ok(())
    }
    #[test]
    fn postgres_database_urls_use_maintenance_database_for_create_and_drop() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-postgres-url-test")?;
        let path = temp.path().join("database-lifecycle-url");
        fs::write(&path, "postgresql://user:s%2Be%3Dcret@db.example/app")?;
        let connection = postgres_connection(&path)?;
        assert_eq!(connection.password, "s+e=cret");
        assert_eq!(
            connection.maintenance().url_without_password.path(),
            "/postgres"
        );
        assert_eq!(
            connection
                .with_database("restore")
                .url_without_password
                .path(),
            "/restore"
        );
        assert!(!connection.url_without_password.as_str().contains("cret"));
        Ok(())
    }

    #[test]
    fn database_existence_query_is_a_complete_validated_psql_command() -> anyhow::Result<()> {
        let query = database_exists_query("nazoauth_restore_01")?;
        assert_eq!(
            query,
            "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'nazoauth_restore_01')"
        );
        assert!(!query.contains(":"));
        assert!(database_exists_query("unsafe'database").is_err());
        Ok(())
    }

    #[test]
    fn recovery_switch_marker_distinguishes_safe_abort_from_path_mutation() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-recovery-marker-test")?;
        let operation = Uuid::now_v7();
        assert!(!recovery_path_switch_started(
            temp.path(),
            &operation.to_string()
        )?);
        let recovery = temp
            .path()
            .join("backup/recoveries")
            .join(operation.to_string());
        fs::create_dir_all(&recovery)?;
        fs::write(recovery.join("paths-switching"), operation.to_string())?;
        assert!(recovery_path_switch_started(
            temp.path(),
            &operation.to_string()
        )?);
        Ok(())
    }
    #[test]
    fn archive_paths_reject_parent_and_absolute_components() {
        assert!(relative_archive_path(Path::new("app-data/key")).is_ok());
        assert!(relative_archive_path(Path::new("../escape")).is_err());
        assert!(relative_archive_path(Path::new("/absolute")).is_err());
    }

    #[test]
    fn recovery_resumes_after_current_was_renamed_to_rollback() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("backup-recovery-rename-test")?;
        let operation = Uuid::parse_str("019c8ca2-30a6-7000-8000-0000000000f1")?;
        let target = temp.path().join("data");
        let staged = sibling_operation_path(&target, operation, "data-stage")?;
        let rollback = sibling_operation_path(&target, operation, "data-rollback")?;
        fs::create_dir(&target)?;
        fs::write(target.join("value"), b"old")?;
        fs::create_dir(&staged)?;
        fs::write(staged.join("value"), b"restored")?;
        fs::rename(&target, &rollback)?;

        switch_recovery_path(&target, &staged, operation, "data")?;

        assert_eq!(fs::read(target.join("value"))?, b"restored");
        assert_eq!(fs::read(rollback.join("value"))?, b"old");
        assert!(!staged.exists());
        Ok(())
    }
}
