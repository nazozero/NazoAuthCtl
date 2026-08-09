use super::*;

pub(crate) fn app_command(
    config: &UpdateConfig,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<()> {
    let migration = matches!(operation, TaskOperation::MigrateApply);
    let runtime = Runtime::new(config);
    let target = if config.runtime.backend == RuntimeBackendKind::Systemd {
        config.runtime.binary_path.to_string_lossy().into_owned()
    } else {
        runtime.active_image()?
    };
    let release = load_active_release(config)?;
    let result = execute_manifest_task(config, &release, &target, operation, public_jwk)?;
    if migration {
        install::grant_runtime_database(config)?;
    }
    println!("{}", operation_result_json(&result)?);
    Ok(())
}

pub(crate) fn conformance_app_command(
    config: &UpdateConfig,
    operation: TaskOperation,
    candidate: Option<&CandidateTarget>,
    local_development: Option<&EmbeddedIdentity>,
) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let target = if config.runtime.backend == RuntimeBackendKind::Systemd {
        config.runtime.binary_path.to_string_lossy().into_owned()
    } else {
        runtime.active_image()?
    };
    let expected = if let Some(candidate) = candidate {
        candidate_expected_target(config, candidate)?
    } else if let Some(local_development) = local_development {
        let active = runtime.active_build_target()?;
        if &active.embedded != local_development {
            bail!("active local development identity differs from the deployment declaration");
        }
        operator::expected_release_target(
            config,
            active.embedded,
            active.image_digest,
            active.binary_digest,
        )?
    } else {
        let release = load_active_release(config)?;
        expected_target(config, &release)?
    };
    let result = operator::execute(config, &target, &expected, operation, None)?;
    println!("{}", operation_result_json(&result)?);
    Ok(())
}

pub(crate) fn candidate_app_command(
    config: &UpdateConfig,
    operation: TaskOperation,
    candidate: &CandidateTarget,
) -> anyhow::Result<()> {
    let target = Runtime::new(config).active_image()?;
    let expected = candidate_expected_target(config, candidate)?;
    let result = operator::execute(config, &target, &expected, operation, None)?;
    println!("{}", operation_result_json(&result)?);
    Ok(())
}

pub(crate) fn candidate_expected_target(
    config: &UpdateConfig,
    candidate: &CandidateTarget,
) -> anyhow::Result<ExpectedReleaseTarget> {
    if config.runtime.backend == RuntimeBackendKind::Systemd {
        bail!("candidate targets require an OCI runtime");
    }
    operator::expected_release_target(
        config,
        EmbeddedIdentity {
            release: candidate.release.clone(),
            revision: candidate.revision.clone(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: candidate.build_id.clone(),
        },
        candidate.oci_digest.clone(),
        String::new(),
    )
}

pub(crate) fn operation_result_json(result: &operator::OperationResult) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "request_id": result.request_id,
        "receipt": result.final_receipt,
        "result": result.result,
    }))?)
}

pub(crate) fn execute_release_task(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    target: &str,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<operator::OperationResult> {
    let migration = matches!(operation, TaskOperation::MigrateApply);
    let result = execute_manifest_task(config, &release.manifest, target, operation, public_jwk)?;
    if migration {
        install::grant_runtime_database(config)?;
    }
    Ok(result)
}

pub(crate) fn execute_manifest_task(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    target: &str,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<operator::OperationResult> {
    let expected = expected_target(config, manifest)?;
    operator::execute(config, target, &expected, operation, public_jwk)
}

pub(crate) fn expected_target(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<ExpectedReleaseTarget> {
    operator::expected_release_target(
        config,
        manifest.embedded.clone(),
        if config.runtime.backend == RuntimeBackendKind::Systemd {
            manifest.image_oci_digest()
        } else {
            manifest.runtime_oci_digest()?
        }
        .to_owned(),
        manifest
            .artifacts
            .get("binary")
            .context("Release manifest has no binary artifact")?
            .sha256
            .clone(),
    )
}
