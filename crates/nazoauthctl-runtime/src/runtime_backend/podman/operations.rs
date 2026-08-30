//! Podman lifecycle and image operations.

use std::{ffi::OsStr, path::Path};

use anyhow::{Context as _, bail};

use crate::process::Process;

#[cfg(debug_assertions)]
use super::super::DebugArtifactTask;
use super::super::{
    ArtifactReference, BlobAttestationVerification, ContainerRuntimePolicy, HostServiceInstall,
    RuntimeReplacement, container_shared,
};

pub(super) fn available(command: &OsStr) -> bool {
    Process::new(command)
        .args(["info", "--format", "json"])
        .succeeds()
}

pub(super) fn verify_blob_attestation(
    command: &OsStr,
    verification: &BlobAttestationVerification,
) -> anyhow::Result<()> {
    container_shared::append_cosign_sandbox(Process::new(command).args(["run", "--rm"]))
        .arg("-v")
        .arg(format!("{}:/work:ro,Z", verification.work.display()))
        .arg(&verification.cosign_image)
        .args(["verify-blob-attestation", "--bundle"])
        .arg(format!("/work/{}", verification.bundle))
        .args(["--type", verification.predicate_type.as_str()])
        .args([
            "--certificate-identity",
            verification.certificate_identity.as_str(),
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ])
        .arg(format!("/work/{}", verification.blob))
        .run_quiet()
}

pub(super) fn start(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["start", object_reference])
        .run_quiet()
}

pub(super) fn stop(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["stop", object_reference])
        .run_quiet()
}

pub(super) fn quiesce_for_recovery(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    let output = Process::new(command)
        .args(["inspect", "--type", "container", object_reference])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("no such object")
            || stderr.contains("no such container")
            || stderr.contains("no container with name or id")
        {
            return Ok(());
        }
        bail!("Podman could not prove the recovery runtime is stopped or absent");
    }
    if super::discovery::inspect(command, object_reference)?.running {
        stop(command, object_reference)?;
    }
    if super::discovery::inspect(command, object_reference)?.running {
        bail!("Podman recovery runtime remained active after stop");
    }
    Ok(())
}

pub(super) fn restart(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["restart", object_reference])
        .run_quiet()
}

pub(super) fn remove(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["rm", "--force", object_reference])
        .run_quiet()
}

pub(super) fn replace(command: &OsStr, replacement: &RuntimeReplacement) -> anyhow::Result<()> {
    let ArtifactReference::Oci {
        image_reference,
        digest,
    } = &replacement.artifact
    else {
        bail!("Podman replacement requires a digest-bound OCI artifact");
    };
    let image = replacement.local_artifact_id.clone().unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let policy: &ContainerRuntimePolicy = replacement
        .container_policy
        .as_ref()
        .context("Podman replacement has no explicit container policy")?;
    let mut command = container_shared::append_container_policy(
        super::append_rootless_user_namespace(
            Process::new(command)
                .args(["run", "-d", "--name"])
                .arg(&replacement.object_reference),
        ),
        policy,
    );
    for (name, value) in &replacement.labels {
        command = command.arg("--label").arg(format!("{name}={value}"));
    }
    for (name, value) in &replacement.environment {
        command = command.arg("--env").arg(format!("{name}={value}"));
    }
    if super::is_rootless()
        && (replacement.networks.is_empty()
            || matches!(replacement.networks.as_slice(), [network] if network == "pasta"))
    {
        command = command.arg("--network").arg("pasta:--map-gw");
    } else {
        for network in &replacement.networks {
            command = command.arg("--network").arg(network);
        }
    }
    if let Some(ip_address) = &replacement.ip_address {
        command = command.arg("--ip").arg(ip_address);
    }
    for port in &replacement.ports {
        command = command.arg("--publish").arg(port);
    }
    command = container_shared::append_mounts(command, &replacement.mounts);
    command.arg(image).args(&replacement.command).run_quiet()
}

pub(super) fn pull_image(command: &OsStr, image_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["pull", image_reference])
        .run_quiet()
}

pub(super) fn export_image(
    command: &OsStr,
    image_reference: &str,
    archive: &Path,
) -> anyhow::Result<()> {
    Process::new(command)
        .args(["image", "save", "--output"])
        .arg(archive)
        .arg(image_reference)
        .run_quiet()
}

pub(super) fn import_image(command: &OsStr, archive: &Path) -> anyhow::Result<()> {
    Process::new(command)
        .args(["image", "load", "--input"])
        .arg(archive)
        .run_quiet()
}

pub(super) fn install_host_service(_install: &HostServiceInstall) -> anyhow::Result<()> {
    bail!("Podman does not install systemd host services")
}

#[cfg(debug_assertions)]
pub(super) fn run_debug_artifact_task(
    command: &OsStr,
    task: &DebugArtifactTask,
) -> anyhow::Result<()> {
    Process::new(command)
        .args(["run", "--rm"])
        .arg(&task.target)
        .arg("nazoauth")
        .args(&task.arguments)
        .run_quiet()
}
