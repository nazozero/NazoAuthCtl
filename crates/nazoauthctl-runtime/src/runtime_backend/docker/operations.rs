//! Docker lifecycle, artifact transfer, and replacement operations.

use std::{ffi::OsStr, path::Path};

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
    container_shared::append_cosign_sandbox(Process::new(command).args(["run", "--rm"]))
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/work,readonly",
            docker_bind_source(&verification.work)
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

fn docker_bind_source(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(path) = rendered.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{path}");
        }
        if let Some(path) = rendered.strip_prefix(r"\\?\") {
            return path.to_owned();
        }
    }
    rendered.into_owned()
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
    let image = container_shared::runnable_oci_image(
        image_reference,
        digest,
        replacement.local_artifact_id.as_deref(),
    );
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
    // Loopback endpoints in the operator-provided configuration address the
    // HOST, not the container namespace; Docker resolves the host gateway
    // name only when explicitly mapped (Podman provides
    // host.containers.internal out of the box).
    process = process.args(["--add-host", "host.docker.internal:host-gateway"]);
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn docker_bind_source_preserves_ordinary_paths() {
        let path = if cfg!(windows) {
            Path::new(r"C:\work\release")
        } else {
            Path::new("/work/release")
        };
        assert_eq!(super::docker_bind_source(path), path.to_string_lossy());
    }

    #[cfg(windows)]
    #[test]
    fn docker_bind_source_removes_windows_verbatim_prefixes() {
        assert_eq!(
            super::docker_bind_source(Path::new(r"\\?\C:\work\release")),
            r"C:\work\release"
        );
        assert_eq!(
            super::docker_bind_source(Path::new(r"\\?\UNC\server\share\release")),
            r"\\server\share\release"
        );
    }
}
