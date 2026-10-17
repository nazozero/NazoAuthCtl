use super::*;

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
