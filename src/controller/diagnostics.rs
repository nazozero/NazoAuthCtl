use super::*;

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
    let target = if config.runtime.backend == RuntimeBackendKind::Systemd {
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary {
            path: fs::canonicalize(&config.runtime.binary_path)?
                .display()
                .to_string(),
            sha256: crate::filesystem::sha256(&config.runtime.binary_path)?,
        }
    } else {
        let image = runtime.active_image()?;
        nazo_operator_protocol::RuntimeTargetClaim::OciImage {
            image_digest: runtime.image_digest(&image)?,
            image_ref: image,
        }
    };
    let expected = expected_target(config, &release)?;
    let runtime_name = match &target {
        nazo_operator_protocol::RuntimeTargetClaim::OciImage { image_ref, .. } => image_ref,
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary { path, .. } => path,
    };
    if runtime.embedded_identity(runtime_name)? != release.embedded {
        bail!("doctor: runtime embedded build identity differs from the signed Release");
    }
    match &target {
        nazo_operator_protocol::RuntimeTargetClaim::OciImage { image_digest, .. }
            if image_digest != &expected.image_digest =>
        {
            bail!("doctor: active OCI digest differs from the signed Release")
        }
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary { sha256, .. }
            if sha256 != &expected.binary_digest =>
        {
            bail!("doctor: active host binary digest differs from the signed Release")
        }
        _ => {}
    }
    if !health_ready(config) {
        bail!("doctor: readiness endpoint is not healthy");
    }
    crate::operator::verify_audit(config)?;
    install::verify_runtime_no_ddl(config)?;
    println!(
        "doctor: ok; release={}; revision={}; target={target:?}",
        release.version, release.backend_commit
    );
    Ok(())
}

pub(super) fn wait_ready(config: &UpdateConfig) -> anyhow::Result<()> {
    for _ in 0..config.runtime.readiness_attempts {
        if health_ready(config) {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(
            config.runtime.readiness_interval_seconds,
        ));
    }
    bail!("NazoAuth did not become ready at the configured health endpoint")
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

pub(super) fn retry_runtime_transport<T>(
    attempts: u32,
    interval: Duration,
    mut operation: impl FnMut() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut last_error = None;
    for attempt in 0..attempts.max(1) {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < attempts.max(1) {
            thread::sleep(interval);
        }
    }
    Err(last_error.expect("at least one runtime transport attempt is made"))
}

pub(super) fn verify_public(config: &UpdateConfig) -> anyhow::Result<()> {
    let response = retry_runtime_transport(
        config.runtime.readiness_attempts,
        Duration::from_secs(config.runtime.readiness_interval_seconds),
        || {
            Process::new("curl")
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--proto",
                    "=http,https",
                    "--max-time",
                    "10",
                    config.runtime.public_discovery_url.as_str(),
                ])
                .stdout()
        },
    )?;
    let value: serde_json::Value =
        serde_json::from_str(&response).context("Discovery response is not valid JSON")?;
    if value.get("issuer").and_then(serde_json::Value::as_str)
        != Some(config.runtime.expected_issuer.as_str())
    {
        bail!("public Discovery issuer does not match configured issuer");
    }
    Ok(())
}

const MAX_UI_INDEX_BYTES: u64 = 1024 * 1024;

pub(super) fn signed_ui_index(
    config: &UpdateConfig,
    release: &ReleaseManifest,
) -> anyhow::Result<Vec<u8>> {
    let cache = config
        .ui
        .releases_root
        .join(&release.frontend.artifact.sha256);
    if !frontend_cache_matches(config, &cache, release) {
        bail!("runtime frontend cache does not match the signed Release descriptor");
    }
    let index = cache.join("index.html");
    let content = crate::runtime::read_runtime_owned_regular_file(
        config,
        &index,
        "signed frontend index",
        false,
        MAX_UI_INDEX_BYTES,
    )?;
    if content.is_empty() {
        bail!("runtime frontend index is empty or exceeds the verification boundary");
    }
    Ok(content.to_vec())
}

pub(super) fn verify_ui_binding(
    config: &UpdateConfig,
    release: &ReleaseManifest,
    served: &[u8],
) -> anyhow::Result<()> {
    let expected = signed_ui_index(config, release)?;
    if served != expected {
        bail!("served frontend does not match the signed runtime cache");
    }
    Ok(())
}

pub(super) fn verify_ui(config: &UpdateConfig, release: &ReleaseManifest) -> anyhow::Result<()> {
    let expected = signed_ui_index(config, release)?;
    let url = format!(
        "{}/ui/",
        config.runtime.expected_issuer.trim_end_matches('/')
    );
    let output = retry_runtime_transport(
        config.runtime.readiness_attempts,
        Duration::from_secs(config.runtime.readiness_interval_seconds),
        || {
            let output = Process::new("curl")
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--proto",
                    "=http,https",
                    "--max-time",
                    "10",
                ])
                .arg("--max-filesize")
                .arg(expected.len().to_string())
                .arg(&url)
                .output()?;
            if !output.status.success() {
                bail!("public frontend verification request failed");
            }
            Ok(output)
        },
    )?;
    verify_ui_binding(config, release, &output.stdout)
}

pub(super) fn install_host_candidate(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    binary: &Path,
) -> anyhow::Result<PathBuf> {
    let directory = config
        .runtime
        .binary_releases
        .join(&release.manifest.backend_commit);
    crate::filesystem::ensure_directory_chain(&directory)?;
    set_mode(&directory, 0o755)?;
    let target = directory.join("nazoauth");
    let mut source =
        crate::filesystem::open_secure_regular_file(binary, "signed host binary artifact", false)?;
    let source_sha256 = crate::filesystem::sha256_file(&mut source, "signed host binary artifact")?;
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            let mut existing = crate::filesystem::open_secure_regular_file(
                &target,
                "installed host binary",
                false,
            )?;
            if crate::filesystem::sha256_file(&mut existing, "installed host binary")?
                != source_sha256
            {
                bail!("existing host binary differs from the signed artifact");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::filesystem::copy_atomic_from_file(&mut source, &target, 0o755)?;
        }
        Err(error) => return Err(error).context("failed to inspect installed host binary"),
    }
    let mut activated =
        crate::filesystem::open_secure_regular_file(&target, "activated host binary", false)?;
    if crate::filesystem::sha256_file(&mut activated, "activated host binary")? != source_sha256 {
        bail!("activated host binary differs from the signed artifact");
    }
    let binary_parent = config
        .runtime
        .binary_path
        .parent()
        .context("host binary path has no parent")?;
    crate::filesystem::ensure_directory_chain(binary_parent)?;
    set_mode(binary_parent, 0o755)?;
    // The releases directory is controller-owned and non-writable to the
    // service account. The descriptor hash above binds the exact file that
    // was installed before this bounded smoke execution.
    Process::new(&target).arg("--help").run_quiet()?;
    Ok(target)
}

pub(super) fn write_record(
    config: &UpdateConfig,
    release: &ReleaseManifest,
    status: &str,
    backup: Option<&Path>,
) -> anyhow::Result<()> {
    crate::filesystem::ensure_directory_chain(&config.deployment_root)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
    let value = json!({
        "status": status,
        "version": release.version,
        "backend_commit": release.backend_commit,
        "frontend_commit": release.frontend_commit(),
        "frontend_version": release.frontend.version,
        "frontend_artifact_sha256": release.frontend.artifact.sha256,
        "backend": config.runtime.backend,
        "backup": backup.map(|path| path.display().to_string()),
        "recorded_at": Utc::now().to_rfc3339(),
    });
    atomic_write(
        &config
            .deployment_root
            .join(format!("{}-{}.json", release.version, stamp)),
        &(serde_json::to_vec_pretty(&value)?),
        0o600,
    )
}

pub(super) fn write_update_record(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    status: &str,
    backup: Option<&Path>,
) -> anyhow::Result<()> {
    crate::filesystem::ensure_directory_chain(&config.deployment_root)?;
    let value = json!({
        "status": status,
        "transaction_id": journal.transaction_id,
        "version": journal.to_release.version,
        "backend_commit": journal.to_release.backend_commit,
        "frontend_commit": journal.to_release.frontend_commit(),
        "frontend_version": journal.to_release.frontend.version,
        "frontend_artifact_sha256": journal.to_release.frontend.artifact.sha256,
        "backend": config.runtime.backend,
        "backup": backup.map(|path| path.display().to_string()),
        "recorded_at": journal.started_at,
    });
    atomic_write(
        &config
            .deployment_root
            .join(format!("update-{}.json", journal.transaction_id)),
        &serde_json::to_vec_pretty(&value)?,
        0o600,
    )
}
