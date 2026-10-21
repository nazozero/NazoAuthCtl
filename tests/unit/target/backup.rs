use super::*;

#[test]
fn large_manifest_survives_evidence_and_host_result_roundtrip() -> anyhow::Result<()> {
    let mut manifest: SnapshotManifest = serde_json::from_slice(include_bytes!(
        "../../fixtures/persistence/v0.2.28/snapshot-manifest.json"
    ))?;
    let file = manifest.archive_files[0].clone();
    manifest.archive_files = (0..MAX_ARCHIVE_FILES)
        .map(|index| SnapshotFile {
            path: format!("data/{index:04}/{}.bin", "x".repeat(200)),
            ..file.clone()
        })
        .collect();
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    manifest.validate()?;
    assert!(serde_json::to_vec(&manifest)?.len() > 1024 * 1024);
    let temp = filesystem::PrivateTempDir::new("nazoauthctl-large-manifest")?;
    write_manifest(temp.path(), &manifest)?;
    assert_eq!(load_manifest(temp.path())?, Some(manifest.clone()));
    let result = super::super::wire::HostResult::completed(
        uuid::Uuid::now_v7().to_string(),
        super::super::wire::HostCompletionBody::BackupSnapshotCreated { manifest },
    );
    let encoded = super::super::wire::encode_host_result(&result)?;
    assert_eq!(super::super::wire::parse_host_result(&encoded)?, result);
    let path = manifest_path(temp.path());
    let before = std::fs::read(&path)?;
    assert!(write_evidence(&path, &"x".repeat(MAX_BACKUP_EVIDENCE_BYTES as usize)).is_err());
    assert_eq!(std::fs::read(path)?, before);
    Ok(())
}

#[test]
fn maximum_archive_manifest_rejects_duplicate_paths_and_excess_entries() -> anyhow::Result<()> {
    let mut manifest: SnapshotManifest = serde_json::from_slice(include_bytes!(
        "../../fixtures/persistence/v0.2.28/snapshot-manifest.json"
    ))?;
    let file = manifest.archive_files[0].clone();
    manifest.archive_files = (0..MAX_ARCHIVE_FILES)
        .map(|index| SnapshotFile {
            path: format!("data/{index:04}.bin"),
            ..file.clone()
        })
        .collect();
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    manifest.validate()?;

    manifest.archive_files.last_mut().unwrap().path = manifest.archive_files[0].path.clone();
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    assert!(
        manifest
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate archive paths")
    );

    manifest.archive_files.push(file);
    assert!(
        manifest
            .validate()
            .unwrap_err()
            .to_string()
            .contains("1-4096")
    );
    Ok(())
}

#[test]
fn manifest_hash_stream_preserves_serialized_bytes() -> anyhow::Result<()> {
    let mut manifest: SnapshotManifest = serde_json::from_slice(include_bytes!(
        "../../fixtures/persistence/v0.2.28/snapshot-manifest.json"
    ))?;
    manifest.manifest_sha256.clear();
    assert_eq!(
        manifest.computed_sha256()?,
        hex_digest(&serde_json::to_vec(&manifest)?)
    );
    for hash in ["", "invalid", &"A".repeat(64)] {
        manifest.manifest_sha256 = hash.to_owned();
        assert!(manifest.validate().is_err());
    }
    Ok(())
}
