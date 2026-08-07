use super::*;

pub(crate) fn activate_cached_runtime(
    record: &DeploymentRecord,
    runtime: &RuntimeLifecycle,
    expected_release: &nazo_operator_protocol::EmbeddedIdentity,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<()> {
    let backend = backend(runtime.backend);
    let mut trusted_local_artifact_id = None;
    let artifact = match cached {
        CachedRuntimeArtifact::OciArchive {
            image_reference,
            digest,
            local_image_id,
            archive,
            archive_sha256,
        } => {
            if sha256(archive)? != *archive_sha256 {
                bail!("cached OCI recovery archive changed before activation");
            }
            backend.import_image(archive)?;
            let resolved = backend.resolve_local_image_id(local_image_id)?;
            if resolved != *local_image_id {
                bail!("imported OCI recovery artifact does not match its trusted local identity");
            }
            trusted_local_artifact_id = Some(local_image_id.clone());
            ArtifactReference::Oci {
                image_reference: image_reference.clone(),
                digest: digest.clone(),
            }
        }
        CachedRuntimeArtifact::HostBinary { binary, sha256 } => {
            if crate::filesystem::sha256(binary)? != *sha256 {
                bail!("cached host recovery artifact changed before activation");
            }
            ArtifactReference::HostBinary {
                path: binary.clone(),
                sha256: sha256.clone(),
            }
        }
    };
    let embedded = backend
        .read_build_identity(&artifact, trusted_local_artifact_id.as_deref())?
        .context("trusted recovery artifact exposes no embedded build identity")?;
    if embedded != *expected_release {
        bail!("trusted recovery artifact embedded identity changed before activation");
    }
    if let Some(observation) = backend.inspect_optional(&runtime.object_reference)? {
        if record
            .capabilities
            .runtime
            .responsibility
            .permits_mutation()
        {
            backend.verify_ownership(
                &runtime.object_reference,
                &record.deployment_id,
                &runtime.runtime_instance_id,
                &record.control_authority,
            )?;
        }
        if observation.running {
            backend.stop(&runtime.object_reference)?;
        }
        if runtime.backend != RuntimeBackendKind::Systemd {
            backend.remove(&runtime.object_reference)?;
        }
    }
    let replacement = RuntimeReplacement {
        object_reference: runtime.object_reference.clone(),
        artifact: artifact.clone(),
        local_artifact_id: trusted_local_artifact_id.clone(),
        command: runtime.command.clone(),
        mounts: runtime.mounts.clone(),
        environment: runtime.environment.clone(),
        networks: runtime.networks.clone(),
        ip_address: runtime.ip_address.clone(),
        ports: runtime.ports.clone(),
        labels: BTreeMap::from([
            (
                "io.nazoauth.deployment-id".to_owned(),
                record.deployment_id.clone(),
            ),
            (
                "io.nazoauth.runtime-instance-id".to_owned(),
                runtime.runtime_instance_id.clone(),
            ),
            (
                "io.nazoauth.control-authority".to_owned(),
                record.control_authority.clone(),
            ),
        ]),
        container_policy: runtime.container_policy.clone(),
    };
    backend.replace(&replacement)?;
    let observation = backend.inspect(&runtime.object_reference)?;
    let artifact_matches = trusted_local_artifact_id.as_ref().map_or_else(
        || artifact_identity_matches(&observation.artifact, &artifact),
        |expected| observation.local_artifact_id.as_ref() == Some(expected),
    );
    if !observation.running {
        bail!("restored runtime did not remain active after replacement");
    }
    if !artifact_matches {
        bail!(
            "restored runtime artifact identity mismatch: expected local identity {:?}, observed local identity {:?}, observed artifact {:?}",
            trusted_local_artifact_id,
            observation.local_artifact_id,
            observation.artifact
        );
    }
    if record
        .capabilities
        .runtime
        .responsibility
        .permits_mutation()
    {
        backend.verify_ownership(
            &runtime.object_reference,
            &record.deployment_id,
            &runtime.runtime_instance_id,
            &record.control_authority,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_active_runtime(
    runtime: &RuntimeLifecycle,
    expected_release: &nazo_operator_protocol::EmbeddedIdentity,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<()> {
    let expected_artifact = activated_artifact_reference(runtime, cached)?;
    let expected_local_artifact_id = match cached {
        CachedRuntimeArtifact::OciArchive { local_image_id, .. } => Some(local_image_id.as_str()),
        CachedRuntimeArtifact::HostBinary { .. } => None,
    };
    let runtime_backend = backend(runtime.backend);
    let observation = runtime_backend.inspect(&runtime.object_reference)?;
    let artifact_matches = expected_local_artifact_id.map_or_else(
        || artifact_identity_matches(&observation.artifact, &expected_artifact),
        |expected| observation.local_artifact_id.as_deref() == Some(expected),
    );
    if !observation.running || !artifact_matches {
        bail!("runtime does not expose the expected active artifact identity");
    }
    let embedded = runtime_backend
        .read_build_identity(&expected_artifact, expected_local_artifact_id)?
        .context("active runtime artifact exposes no embedded build identity")?;
    if embedded != *expected_release {
        bail!("active runtime artifact exposes a different Release identity");
    }
    Ok(())
}

pub(crate) fn artifact_identity_matches(
    left: &ArtifactReference,
    right: &ArtifactReference,
) -> bool {
    match (left, right) {
        (
            ArtifactReference::Oci { digest: left, .. },
            ArtifactReference::Oci { digest: right, .. },
        ) => left == right,
        (
            ArtifactReference::HostBinary { sha256: left, .. },
            ArtifactReference::HostBinary { sha256: right, .. },
        ) => left == right,
        _ => false,
    }
}

pub(crate) fn cached_local_artifact_id(cached: &CachedRuntimeArtifact) -> Option<String> {
    match cached {
        CachedRuntimeArtifact::OciArchive { local_image_id, .. } => Some(local_image_id.clone()),
        CachedRuntimeArtifact::HostBinary { .. } => None,
    }
}

pub(crate) fn activated_artifact_reference(
    runtime: &RuntimeLifecycle,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<ArtifactReference> {
    Ok(match cached {
        CachedRuntimeArtifact::OciArchive {
            image_reference,
            digest,
            ..
        } => ArtifactReference::Oci {
            image_reference: image_reference.clone(),
            digest: digest.clone(),
        },
        CachedRuntimeArtifact::HostBinary { sha256, .. } => ArtifactReference::HostBinary {
            path: PathBuf::from(
                runtime
                    .command
                    .first()
                    .context("systemd lifecycle command has no binary path")?,
            ),
            sha256: sha256.clone(),
        },
    })
}
