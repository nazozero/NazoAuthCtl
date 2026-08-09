use super::*;

pub(crate) fn cache_trusted_runtime(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    record.validate()?;
    let directory =
        trusted_runtime_directory(store, &record.deployment_id, &record.active_release.release)?;
    let manifest_path = directory.join("cache.json");
    if manifest_path.exists() {
        let cache = load_cache(&manifest_path, record)?;
        validate_cached_artifacts(&cache)?;
        ensure_adoption_recovery_slot(store, record)?;
        return Ok(());
    }
    fs::create_dir_all(&directory)?;
    let mut runtimes = BTreeMap::new();
    for runtime in &record.runtime_instances {
        let artifact_directory = directory.join(&runtime.runtime_instance_id);
        fs::create_dir_all(&artifact_directory)?;
        let cached = match &runtime.artifact {
            ArtifactReference::Oci {
                image_reference,
                digest,
            } => {
                validate_oci_digest(digest)?;
                let runtime_backend = backend(runtime.backend);
                let local_image_id = runtime_backend.resolve_local_image_id(image_reference)?;
                let local_development = record.active_release.build_id.starts_with("local:");
                if local_development {
                    if runtime.local_artifact_id.as_deref() != Some(local_image_id.as_str()) {
                        bail!("local development runtime no longer matches its immutable image ID");
                    }
                } else if runtime_backend.resolve_image_digest(image_reference)? != *digest {
                    bail!("runtime OCI artifact no longer matches its signed Release digest");
                }
                let archive = artifact_directory.join("image.tar");
                let temporary = artifact_directory.join("image.partial.tar");
                for stale in [&temporary, &archive] {
                    if stale.exists() {
                        fs::remove_file(stale)?;
                    }
                }
                let export_reference = if local_development {
                    local_image_id.clone()
                } else {
                    format!(
                        "{}@{digest}",
                        image_reference.split('@').next().unwrap_or(image_reference)
                    )
                };
                runtime_backend.export_image(&export_reference, &temporary)?;
                if runtime_backend.resolve_local_image_id(image_reference)? != local_image_id {
                    bail!("runtime OCI artifact changed while entering the recovery cache");
                }
                let metadata = fs::symlink_metadata(&temporary)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                    bail!("runtime backend exported an invalid OCI recovery archive");
                }
                fs::rename(&temporary, &archive)?;
                CachedRuntimeArtifact::OciArchive {
                    image_reference: image_reference.clone(),
                    digest: digest.clone(),
                    local_image_id,
                    archive_sha256: sha256(&archive)?,
                    archive,
                }
            }
            ArtifactReference::HostBinary {
                path,
                sha256: expected,
            } => {
                validate_lower_hex(expected)?;
                if sha256(path)? != *expected {
                    bail!("host runtime binary changed before recovery caching");
                }
                let binary = artifact_directory.join(if cfg!(windows) {
                    "nazoauth.exe"
                } else {
                    "nazoauth"
                });
                copy_atomic(path, &binary, 0o500)?;
                set_mode(&binary, 0o500)?;
                if sha256(&binary)? != *expected {
                    bail!("cached host runtime binary changed during persistence");
                }
                CachedRuntimeArtifact::HostBinary {
                    binary,
                    sha256: expected.clone(),
                }
            }
            ArtifactReference::Unknown => {
                bail!("cannot cache an unidentified runtime artifact for recovery")
            }
        };
        runtimes.insert(runtime.runtime_instance_id.clone(), cached);
    }
    let cache = TrustedRuntimeCache {
        schema: TRUSTED_RUNTIME_CACHE_SCHEMA,
        deployment_id: record.deployment_id.clone(),
        release: record.active_release.clone(),
        runtimes,
    };
    atomic_write(&manifest_path, &serde_json::to_vec_pretty(&cache)?, 0o600)?;
    validate_cached_artifacts(&load_cache(&manifest_path, record)?)?;
    ensure_adoption_recovery_slot(store, record)
}

pub(super) fn ensure_adoption_recovery_slot(
    store: &DeploymentStore,
    record: &DeploymentRecord,
) -> anyhow::Result<()> {
    let adoption_manifest = store
        .deployment_state_dir(&record.deployment_id)
        .join("recovery")
        .join("adoption")
        .join("manifest.json");
    if adoption_manifest.is_file() && !recovery_slot_path(store, &record.deployment_id).exists() {
        persist_recovery_slot(
            store,
            &RecoverySlot {
                schema: 1,
                deployment_id: record.deployment_id.clone(),
                trusted_release: record.active_release.clone(),
                recovery_manifest_sha256: sha256(&adoption_manifest)?,
                recovery_manifest: adoption_manifest,
            },
        )?;
    }
    Ok(())
}

pub(crate) fn stage_update_release(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    release: &VerifiedRelease,
) -> anyhow::Result<()> {
    let directory =
        trusted_runtime_directory(store, &record.deployment_id, &release.manifest.version)?;
    let manifest_path = directory.join("cache.json");
    if manifest_path.exists() {
        let staged_record = DeploymentRecord {
            active_release: release.manifest.embedded.clone(),
            ..record.clone()
        };
        let cache = load_cache(&manifest_path, &staged_record)?;
        return validate_cached_artifacts(&cache);
    }
    fs::create_dir_all(&directory)?;
    let mut runtimes = BTreeMap::new();
    for runtime in &record.runtime_instances {
        let artifact_directory = directory.join(&runtime.runtime_instance_id);
        fs::create_dir_all(&artifact_directory)?;
        let cached = if runtime.backend == RuntimeBackendKind::Systemd {
            let source = release.artifact("binary", "nazozero/NazoAuth")?;
            let expected = crate::filesystem::sha256(&source)?;
            let binary = artifact_directory.join(if cfg!(windows) {
                "nazoauth.exe"
            } else {
                "nazoauth"
            });
            copy_atomic(&source, &binary, 0o500)?;
            set_mode(&binary, 0o500)?;
            if crate::filesystem::sha256(&binary)? != expected {
                bail!("staged host Release changed while entering the recovery cache");
            }
            CachedRuntimeArtifact::HostBinary {
                binary,
                sha256: expected,
            }
        } else {
            let runtime_backend = backend(runtime.backend);
            let image_reference = release.manifest.image_ref()?;
            let digest = release.manifest.image_oci_digest().to_owned();
            validate_oci_digest(&digest)?;
            runtime_backend.pull_image(&image_reference)?;
            if runtime_backend.resolve_image_digest(&image_reference)? != digest {
                bail!("staged OCI Release does not match the signed runtime digest");
            }
            let local_image_id = runtime_backend.resolve_local_image_id(&image_reference)?;
            let archive = artifact_directory.join("image.tar");
            let temporary = artifact_directory.join("image.partial.tar");
            for stale in [&temporary, &archive] {
                if stale.exists() {
                    fs::remove_file(stale)?;
                }
            }
            runtime_backend.export_image(
                &format!(
                    "{}@{digest}",
                    image_reference
                        .split('@')
                        .next()
                        .unwrap_or(&image_reference)
                ),
                &temporary,
            )?;
            if runtime_backend.resolve_local_image_id(&image_reference)? != local_image_id {
                bail!("staged OCI artifact changed while entering the recovery cache");
            }
            let metadata = fs::symlink_metadata(&temporary)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                bail!("runtime backend exported an invalid staged OCI archive");
            }
            fs::rename(&temporary, &archive)?;
            CachedRuntimeArtifact::OciArchive {
                image_reference,
                digest,
                local_image_id,
                archive_sha256: sha256(&archive)?,
                archive,
            }
        };
        runtimes.insert(runtime.runtime_instance_id.clone(), cached);
    }
    let cache = TrustedRuntimeCache {
        schema: TRUSTED_RUNTIME_CACHE_SCHEMA,
        deployment_id: record.deployment_id.clone(),
        release: release.manifest.embedded.clone(),
        runtimes,
    };
    atomic_write(&manifest_path, &serde_json::to_vec_pretty(&cache)?, 0o600)?;
    validate_cached_artifacts(&cache)
}
