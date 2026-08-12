use super::*;

use std::{thread, time::Duration};

const MAX_ACCEPTANCE_RESPONSE_BYTES: u64 = 64 * 1024;
const ACCEPTANCE_REQUEST_TIMEOUT_SECONDS: u64 = 10;

struct HttpProbeResponse {
    status: u16,
    body: Vec<u8>,
}

pub(crate) fn activate_cached_runtime(
    record: &DeploymentRecord,
    runtime: &RuntimeLifecycle,
    expected_release: &nazo_operator_protocol::EmbeddedIdentity,
    cached: &CachedRuntimeArtifact,
) -> anyhow::Result<()> {
    record.require_mutation(&[Capability::Runtime])?;
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
        backend.verify_ownership(
            &runtime.object_reference,
            &record.deployment_id,
            &runtime.runtime_instance_id,
            &record.control_authority,
        )?;
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
    backend.verify_ownership(
        &runtime.object_reference,
        &record.deployment_id,
        &runtime.runtime_instance_id,
        &record.control_authority,
    )?;
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

/// Verify the complete immutable acceptance contract after a runtime has been
/// activated.  The contract is deliberately explicit: no endpoint is inferred
/// from the runtime command, issuer, port mapping, or UI cache.
pub(crate) fn verify_runtime_acceptance(runtime: &RuntimeLifecycle) -> anyhow::Result<()> {
    runtime.acceptance.validate()?;
    let acceptance = &runtime.acceptance;
    let mut readiness_error = None;
    for attempt in 0..acceptance.attempts {
        match probe_http(&acceptance.readiness_url, MAX_ACCEPTANCE_RESPONSE_BYTES).and_then(
            |response| {
                if (200..300).contains(&response.status) {
                    Ok(())
                } else {
                    bail!("readiness endpoint returned HTTP {}", response.status);
                }
            },
        ) {
            Ok(()) => {
                readiness_error = None;
                break;
            }
            Err(error) => {
                readiness_error = Some(error);
                if attempt + 1 < acceptance.attempts && acceptance.interval_seconds > 0 {
                    thread::sleep(Duration::from_secs(acceptance.interval_seconds));
                }
            }
        }
    }
    if let Some(error) = readiness_error {
        return Err(error).context("lifecycle readiness acceptance failed");
    }

    let discovery = probe_http(&acceptance.discovery_url, MAX_ACCEPTANCE_RESPONSE_BYTES)?;
    if discovery.status != 200 {
        bail!(
            "public Discovery acceptance requires HTTP 200, received {}",
            discovery.status
        );
    }
    let discovery: serde_json::Value = serde_json::from_slice(&discovery.body)
        .context("public Discovery acceptance response is not valid JSON")?;
    if discovery.get("issuer").and_then(serde_json::Value::as_str)
        != Some(acceptance.expected_issuer.as_str())
    {
        bail!("public Discovery issuer does not match the lifecycle acceptance contract");
    }

    let ui = probe_http(&acceptance.ui_url, acceptance.ui_size)?;
    if ui.status != 200 {
        bail!(
            "served UI acceptance requires HTTP 200, received {}",
            ui.status
        );
    }
    if ui.body.len() as u64 != acceptance.ui_size {
        bail!(
            "served UI size differs from the lifecycle acceptance contract: expected {}, observed {}",
            acceptance.ui_size,
            ui.body.len()
        );
    }
    if acceptance_digest_bytes(&ui.body) != acceptance.ui_sha256 {
        bail!("served UI bytes differ from the lifecycle acceptance digest");
    }
    Ok(())
}

fn probe_http(url: &str, max_body_bytes: u64) -> anyhow::Result<HttpProbeResponse> {
    let parsed = url::Url::parse(url).context("lifecycle acceptance URL is invalid")?;
    let proto = if parsed.scheme() == "https" {
        "=https"
    } else {
        "=http"
    };
    let output = Process::new("curl")
        .timeout(Duration::from_secs(ACCEPTANCE_REQUEST_TIMEOUT_SECONDS))
        .args([
            "--silent",
            "--show-error",
            "--proto",
            proto,
            "--max-time",
            &ACCEPTANCE_REQUEST_TIMEOUT_SECONDS.to_string(),
            "--max-filesize",
            &max_body_bytes.to_string(),
            "--write-out",
            "%{http_code}",
        ])
        .arg(url)
        .output()
        .context("lifecycle acceptance HTTP probe failed to execute")?;
    if !output.status.success() {
        bail!("lifecycle acceptance HTTP probe failed");
    }
    if output.stdout.len() < 3 {
        bail!("lifecycle acceptance HTTP probe returned no status code");
    }
    let status_start = output.stdout.len() - 3;
    let status = std::str::from_utf8(&output.stdout[status_start..])
        .context("lifecycle acceptance HTTP probe returned an invalid status code")?
        .parse::<u16>()
        .context("lifecycle acceptance HTTP probe returned an invalid status code")?;
    let body = output.stdout[..status_start].to_vec();
    if body.len() as u64 > max_body_bytes {
        bail!("lifecycle acceptance HTTP response exceeds its bounded size");
    }
    Ok(HttpProbeResponse { status, body })
}

fn acceptance_digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
