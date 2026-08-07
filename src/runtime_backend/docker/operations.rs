//! Docker lifecycle, artifact transfer, and replacement operations.

use std::ffi::OsStr;

use anyhow::{Context as _, bail};

use crate::process::Process;

#[cfg(debug_assertions)]
use super::super::DebugArtifactTask;
use super::super::{
    ArtifactReference, BlobAttestationVerification, HostServiceInstall, RuntimeReplacement,
    container_shared,
};
use super::discovery;

pub(super) fn available(command: &OsStr) -> bool {
    Process::new(command)
        .args(["info", "--format", "{{.ServerVersion}}"])
        .succeeds()
}

pub(super) fn verify_blob_attestation(
    command: &OsStr,
    verification: &BlobAttestationVerification,
) -> anyhow::Result<()> {
    Process::new(command)
        .args(["run", "--rm", "--user", "0:0", "--cap-drop", "ALL"])
        .args(["--read-only", "--security-opt", "no-new-privileges"])
        .args(["--pids-limit", "64", "--tmpfs"])
        .arg("/root/.sigstore:rw,noexec,nosuid,nodev,size=16m")
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/work,readonly",
            verification.work.display()
        ))
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
        if stderr.contains("no such object") || stderr.contains("no such container") {
            return Ok(());
        }
        bail!("Docker could not prove the recovery runtime is stopped or absent");
    }
    if discovery::inspect(command, object_reference)?.running {
        stop(command, object_reference)?;
    }
    if discovery::inspect(command, object_reference)?.running {
        bail!("Docker recovery runtime remained active after stop");
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
        bail!("Docker replacement requires a digest-bound OCI artifact");
    };
    let image = replacement.local_artifact_id.clone().unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let policy = replacement
        .container_policy
        .as_ref()
        .context("Docker replacement has no explicit container policy")?;
    let mut process = container_shared::append_container_policy(
        Process::new(command)
            .args(["run", "-d", "--name"])
            .arg(&replacement.object_reference),
        policy,
    );
    for (name, value) in &replacement.labels {
        process = process.arg("--label").arg(format!("{name}={value}"));
    }
    for (name, value) in &replacement.environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    for network in &replacement.networks {
        process = process.arg("--network").arg(network);
    }
    if let Some(ip_address) = &replacement.ip_address {
        process = process.arg("--ip").arg(ip_address);
    }
    for port in &replacement.ports {
        process = process.arg("--publish").arg(port);
    }
    process = container_shared::append_mounts(process, &replacement.mounts);
    process.arg(image).args(&replacement.command).run_quiet()
}

pub(super) fn pull_image(command: &OsStr, image_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["pull", image_reference])
        .run_quiet()
}

pub(super) fn export_image(
    command: &OsStr,
    image_reference: &str,
    archive: &std::path::Path,
) -> anyhow::Result<()> {
    Process::new(command)
        .args(["image", "save", "--output"])
        .arg(archive)
        .arg(image_reference)
        .run_quiet()
}

pub(super) fn import_image(command: &OsStr, archive: &std::path::Path) -> anyhow::Result<()> {
    Process::new(command)
        .args(["image", "load", "--input"])
        .arg(archive)
        .run_quiet()
}

pub(super) fn install_host_service(_install: &HostServiceInstall) -> anyhow::Result<()> {
    bail!("Docker does not install systemd host services")
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
