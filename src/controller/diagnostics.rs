use super::*;

use std::time::Duration;

pub(super) fn status(config: &UpdateConfig) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let revision = runtime.active_revision()?;
    let release = load_active_release(config)?;
    let (target, runtime_name) = if config.runtime.backend == RuntimeBackendKind::Systemd {
        let path = fs::canonicalize(&config.runtime.binary_path)?;
        let target = json!({
            "kind": "host-binary",
            "path": path,
            "sha256": crate::filesystem::sha256(&config.runtime.binary_path)?,
        });
        (target, path.display().to_string())
    } else {
        let image = runtime.active_image()?;
        let image_digest = runtime.image_digest(&image)?;
        (
            json!({
                "kind": "oci-image",
                "image_ref": image,
                "image_digest": image_digest,
            }),
            image,
        )
    };
    let actual_embedded = runtime.embedded_identity(&runtime_name)?;
    let embedded_identity_matches_release = actual_embedded == release.embedded;
    let value = json!({
        "backend": config.runtime.backend,
        "revision": revision,
        "release": release.version,
        "release_identity": release.release_identity,
        "runtime_target": target,
        "embedded_build_identity": actual_embedded,
        "embedded_identity_matches_release": embedded_identity_matches_release,
        "health_url": config.runtime.health_url,
        "ready": health_ready(config),
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(super) fn doctor(config: &UpdateConfig) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let release = load_active_release(config)?;
    let expected = expected_target(config, &release)?;
    let (runtime_name, target, digest_matches) =
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            let path = fs::canonicalize(&config.runtime.binary_path)?;
            let sha256 = crate::filesystem::sha256(&config.runtime.binary_path)?;
            let target = json!({
                "kind": "host-binary",
                "path": path,
                "sha256": sha256,
            });
            (
                config.runtime.binary_path.to_string_lossy().into_owned(),
                target,
                sha256 == expected.binary_digest,
            )
        } else {
            let image = runtime.active_image()?;
            let image_digest = runtime.image_digest(&image)?;
            let target = json!({
                "kind": "oci-image",
                "image_ref": image,
                "image_digest": image_digest,
            });
            let name = image.clone();
            (name, target, image_digest == expected.image_digest)
        };
    if !digest_matches {
        bail!("doctor: active runtime artifact differs from the signed Release");
    }
    if runtime.embedded_identity(&runtime_name)? != release.embedded {
        bail!("doctor: runtime embedded build identity differs from the signed Release");
    }
    if !health_ready(config) {
        bail!("doctor: readiness endpoint is not healthy");
    }
    crate::install::verify_runtime_no_ddl(config)?;
    println!(
        "doctor: ok; release={}; revision={}; target={target}",
        release.version, release.backend_commit
    );
    Ok(())
}

pub(super) fn health_ready(config: &UpdateConfig) -> bool {
    Process::new("curl")
        .timeout(Duration::from_secs(10))
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=http,https",
            "--max-time",
            "5",
            config.runtime.health_url.as_str(),
        ])
        .succeeds()
}
