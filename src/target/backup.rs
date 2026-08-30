//! Target-owned backup evidence.
//!
//! A deployment does not carry an asserted "backup maturity" flag.  The only
//! durable backup facts are the snapshot manifest and, after an *actual*
//! isolated restore, its receipt.  Everything shown by status is derived from
//! those two documents plus the live [`DeploymentState`].

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::filesystem;
use crate::runtime_backend::ArtifactReference;

use super::deployment_state::{DeploymentState, ReleaseVersion};

pub const BACKUP_MANIFEST_SCHEMA: u32 = 4;
pub const RESTORE_TEST_RECEIPT_SCHEMA: u32 = 2;
pub const OFF_HOST_COPY_RECEIPT_SCHEMA: u32 = 1;
const MAX_BACKUP_EVIDENCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 4_096;

/// One immutable file comprising a snapshot.  `path` is relative to the
/// target-owned snapshot directory; no absolute or parent path is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

impl SnapshotFile {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.path.is_empty()
            || self.path.len() > 512
            || self.path.starts_with('/')
            || self
                .path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !self
                .path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
        {
            bail!("backup file path is not a bounded relative path");
        }
        validate_sha256(&self.sha256, "backup file sha256")
    }
}

/// The authoritative, target-owned statement for one completed snapshot.
/// It is not a policy assertion: every byte required for a restore is named
/// and checksummed here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema: u32,
    pub deployment_id: String,
    pub snapshot_id: String,
    pub created_at: DateTime<Utc>,
    /// Exact artifact observed from the live runtime, not reconstructed from
    /// a release tag or controller cache.
    pub runtime_artifact: ArtifactReference,
    /// Verified release version paired with the current artifact.
    pub release: ReleaseVersion,
    /// Verified Release rollback contract belonging to this exact artifact
    /// generation. Recovery restores it together with the artifact.
    pub rollback_policy: crate::model::ReleaseRollbackPolicy,
    /// Configuration schema paired with the archived config bytes. Recovery
    /// advances the live revision monotonically; it never restores a revision.
    pub config_schema: String,
    /// Every top-level snapshot artifact (custom PostgreSQL dump and tar).
    pub files: Vec<SnapshotFile>,
    /// Every regular file inside deployment.tar, including the snapshot
    /// sentinel. This lets restore validate the extracted bytes individually
    /// instead of treating a readable tar stream as proof of a usable backup.
    pub archive_files: Vec<SnapshotFile>,
    /// Digest of a stable, read-only database fact captured immediately
    /// before pg_dump and compared after pg_restore.
    pub database_sentinel_sha256: String,
    /// Digests/identity derived from the exact archived key material. No key
    /// bytes enter evidence documents.
    pub mfa_key_sha256: String,
    pub runtime_instance_key_id: String,
    /// Sorted active signing-key ids returned by the source runtime's JWKS.
    /// Restore-test must obtain the same set from the isolated candidate.
    pub oidc_signing_key_ids: Vec<String>,
    /// Hash over the exact manifest bytes with this field omitted.  This makes
    /// the restore receipt bind one immutable manifest, not a status label.
    pub manifest_sha256: String,
}

impl SnapshotManifest {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema != BACKUP_MANIFEST_SCHEMA {
            bail!("unsupported backup manifest schema {}", self.schema);
        }
        crate::registry::validate_identifier(&self.deployment_id, 128, "backup deployment id")?;
        Uuid::parse_str(&self.snapshot_id).context("backup snapshot id is not a UUID")?;
        self.release.validate()?;
        self.rollback_policy.validate()?;
        crate::registry::validate_identifier(&self.config_schema, 64, "backup config schema")?;
        validate_runtime_artifact(&self.runtime_artifact)?;
        if self.files.len() != 2 {
            bail!("backup manifest must name exactly the database dump and deployment archive");
        }
        let mut paths = Vec::with_capacity(self.files.len());
        for file in &self.files {
            file.validate()?;
            if paths.contains(&file.path) {
                bail!("backup manifest contains duplicate file paths");
            }
            paths.push(file.path.clone());
        }
        if self.archive_files.is_empty() || self.archive_files.len() > MAX_ARCHIVE_FILES {
            bail!("backup manifest must name 1-{MAX_ARCHIVE_FILES} archived files");
        }
        let mut archive_paths = Vec::with_capacity(self.archive_files.len());
        for file in &self.archive_files {
            file.validate()?;
            if archive_paths.contains(&file.path) {
                bail!("backup manifest contains duplicate archive paths");
            }
            archive_paths.push(file.path.clone());
        }
        for (value, label) in [
            (&self.database_sentinel_sha256, "database sentinel sha256"),
            (&self.mfa_key_sha256, "MFA key sha256"),
        ] {
            validate_sha256(value, label)?;
        }
        crate::registry::validate_identifier(
            &self.runtime_instance_key_id,
            128,
            "runtime instance key id",
        )?;
        if self.oidc_signing_key_ids.is_empty() || self.oidc_signing_key_ids.len() > 32 {
            bail!("backup manifest must bind 1-32 OIDC signing key ids");
        }
        let mut previous: Option<&str> = None;
        for key_id in &self.oidc_signing_key_ids {
            crate::registry::validate_identifier(key_id, 256, "OIDC signing key id")?;
            if previous.is_some_and(|value| value >= key_id.as_str()) {
                bail!("backup OIDC signing key ids must be unique and sorted");
            }
            previous = Some(key_id);
        }
        validate_sha256(&self.manifest_sha256, "backup manifest sha256")?;
        if self.manifest_sha256 != self.computed_sha256()? {
            bail!("backup manifest hash does not bind its contents");
        }
        Ok(())
    }

    pub fn computed_sha256(&self) -> anyhow::Result<String> {
        let mut unsigned = self.clone();
        unsigned.manifest_sha256.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        Ok(hex_digest(&bytes))
    }
}

/// Proof that the exact manifest was restored into an isolated target and
/// the database restore command reached completion.  A checksum-only pass is
/// intentionally not a receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreTestReceipt {
    pub schema: u32,
    pub deployment_id: String,
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub restored_at: DateTime<Utc>,
    pub isolated_database: String,
    pub candidate_runtime_object: String,
    pub runtime_instance_key_id: String,
    pub database_sentinel_sha256: String,
    /// A restore-test candidate on the source host is useful rehearsal but is
    /// never off-host backup evidence.
    pub environment: RestoreTestEnvironment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreTestEnvironment {
    SameHostIsolated,
}

/// Independently verified copy evidence. A same-host restore-test never
/// creates this document and therefore can never satisfy an off-host policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffHostCopyReceipt {
    pub schema: u32,
    pub deployment_id: String,
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub source_host_id: String,
    pub destination_host_id: String,
    pub verified_at: DateTime<Utc>,
}

impl OffHostCopyReceipt {
    pub fn validate_against(&self, manifest: &SnapshotManifest) -> anyhow::Result<()> {
        if self.schema != OFF_HOST_COPY_RECEIPT_SCHEMA
            || self.deployment_id != manifest.deployment_id
            || self.snapshot_id != manifest.snapshot_id
            || self.manifest_sha256 != manifest.manifest_sha256
        {
            bail!("off-host receipt does not bind the current snapshot manifest");
        }
        crate::registry::validate_identifier(&self.source_host_id, 128, "source host id")?;
        crate::registry::validate_identifier(
            &self.destination_host_id,
            128,
            "destination host id",
        )?;
        if self.source_host_id == self.destination_host_id {
            bail!("off-host receipt names the source host as its destination");
        }
        Ok(())
    }
}

impl RestoreTestReceipt {
    pub fn validate_against(&self, manifest: &SnapshotManifest) -> anyhow::Result<()> {
        if self.schema != RESTORE_TEST_RECEIPT_SCHEMA {
            bail!("unsupported restore-test receipt schema {}", self.schema);
        }
        if self.deployment_id != manifest.deployment_id
            || self.snapshot_id != manifest.snapshot_id
            || self.manifest_sha256 != manifest.manifest_sha256
        {
            bail!("restore-test receipt does not bind the current snapshot manifest");
        }
        crate::registry::validate_identifier(
            &self.isolated_database,
            128,
            "isolated restore database",
        )?;
        crate::registry::validate_identifier(
            &self.candidate_runtime_object,
            256,
            "restore-test runtime object",
        )?;
        if self.runtime_instance_key_id != manifest.runtime_instance_key_id
            || self.database_sentinel_sha256 != manifest.database_sentinel_sha256
        {
            bail!("restore-test receipt does not bind restored identity and database facts");
        }
        Ok(())
    }
}

/// A projection only.  It is recomputed on every target inspection and is
/// deliberately absent from DeploymentState, Registry, and policy storage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupProjection {
    pub local_rollback_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotProjection {
    pub snapshot_id: String,
    pub created_at: DateTime<Utc>,
    pub manifest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_tested_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub off_host_verified_at: Option<DateTime<Utc>>,
}

pub fn backup_projection(
    scope_dir: &Path,
    state: &DeploymentState,
) -> anyhow::Result<BackupProjection> {
    let local_rollback_ready = state.artifact.previous.is_some();
    let Some(manifest) = load_manifest(scope_dir)? else {
        return Ok(BackupProjection {
            local_rollback_ready,
            snapshot: None,
        });
    };
    if manifest.deployment_id != state.deployment_id {
        bail!("backup manifest deployment does not match DeploymentState");
    }
    let receipt = load_receipt(scope_dir)?;
    let restore_tested_at = match receipt {
        Some(receipt) => {
            receipt.validate_against(&manifest)?;
            Some(receipt.restored_at)
        }
        None => None,
    };
    let off_host_verified_at = match load_off_host_receipt(scope_dir)? {
        Some(receipt) => {
            receipt.validate_against(&manifest)?;
            Some(receipt.verified_at)
        }
        None => None,
    };
    Ok(BackupProjection {
        local_rollback_ready,
        snapshot: Some(SnapshotProjection {
            snapshot_id: manifest.snapshot_id,
            created_at: manifest.created_at,
            manifest_sha256: manifest.manifest_sha256,
            restore_tested_at,
            off_host_verified_at,
        }),
    })
}

pub fn manifest_path(scope_dir: &Path) -> PathBuf {
    scope_dir.join("backup").join("snapshot-manifest.json")
}

pub fn receipt_path(scope_dir: &Path) -> PathBuf {
    scope_dir.join("backup").join("restore-test-receipt.json")
}

pub fn off_host_receipt_path(scope_dir: &Path) -> PathBuf {
    scope_dir.join("backup").join("off-host-copy-receipt.json")
}

pub fn load_manifest(scope_dir: &Path) -> anyhow::Result<Option<SnapshotManifest>> {
    load_manifest_at(&manifest_path(scope_dir))
}

pub(crate) fn load_manifest_at(path: &Path) -> anyhow::Result<Option<SnapshotManifest>> {
    load_evidence(path, "backup snapshot manifest", |bytes| {
        let manifest: SnapshotManifest = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    })
}

pub fn load_receipt(scope_dir: &Path) -> anyhow::Result<Option<RestoreTestReceipt>> {
    load_evidence(
        &receipt_path(scope_dir),
        "backup restore-test receipt",
        |bytes| Ok(serde_json::from_slice(bytes)?),
    )
}

pub fn load_off_host_receipt(scope_dir: &Path) -> anyhow::Result<Option<OffHostCopyReceipt>> {
    load_evidence(
        &off_host_receipt_path(scope_dir),
        "off-host backup copy receipt",
        |bytes| Ok(serde_json::from_slice(bytes)?),
    )
}

pub fn write_manifest(scope_dir: &Path, manifest: &SnapshotManifest) -> anyhow::Result<()> {
    write_manifest_at(&manifest_path(scope_dir), manifest)
}

pub(crate) fn write_manifest_at(path: &Path, manifest: &SnapshotManifest) -> anyhow::Result<()> {
    manifest.validate()?;
    write_evidence(path, manifest)
}

pub fn write_receipt(scope_dir: &Path, receipt: &RestoreTestReceipt) -> anyhow::Result<()> {
    write_evidence(&receipt_path(scope_dir), receipt)
}

pub fn write_off_host_receipt(
    scope_dir: &Path,
    receipt: &OffHostCopyReceipt,
) -> anyhow::Result<()> {
    write_evidence(&off_host_receipt_path(scope_dir), receipt)
}

fn load_evidence<T>(
    path: &Path,
    label: &str,
    parse: impl FnOnce(&[u8]) -> anyhow::Result<T>,
) -> anyhow::Result<Option<T>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            filesystem::read_secure_regular_file(path, label, false, MAX_BACKUP_EVIDENCE_BYTES)
                .and_then(|bytes| parse(&bytes))
                .map(Some)
                .with_context(|| format!("failed to read {label}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {label}")),
    }
}

fn write_evidence<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path.parent().context("backup evidence has no parent")?;
    filesystem::ensure_private_directory(parent, "backup evidence directory")?;
    let bytes = serde_json::to_vec_pretty(value)?;
    filesystem::atomic_write(path, &bytes, 0o600).context("failed to persist backup evidence")
}

fn validate_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

pub fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_runtime_artifact(artifact: &ArtifactReference) -> anyhow::Result<()> {
    match artifact {
        ArtifactReference::Oci {
            image_reference,
            digest,
        } => {
            if image_reference.is_empty()
                || image_reference.len() > 512
                || image_reference.chars().any(char::is_whitespace)
            {
                bail!("backup OCI image reference is invalid");
            }
            let digest = digest
                .strip_prefix("sha256:")
                .context("backup OCI artifact digest must use sha256")?;
            validate_sha256(digest, "backup OCI artifact digest")
        }
        ArtifactReference::HostBinary { path, sha256 } => {
            if !path.is_absolute() {
                bail!("backup host artifact path is not absolute");
            }
            validate_sha256(sha256, "backup host artifact sha256")
        }
        ArtifactReference::Unknown => bail!("backup runtime artifact is unknown"),
    }
}
