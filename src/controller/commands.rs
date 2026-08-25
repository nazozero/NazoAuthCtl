use super::*;

pub(super) fn validate_local_development_identity(
    identity: &EmbeddedIdentity,
) -> anyhow::Result<()> {
    if identity.protocol != nazo_operator_protocol::PROTOCOL_VERSION {
        bail!(
            "local development artifact uses operator protocol {}, expected {}",
            identity.protocol,
            nazo_operator_protocol::PROTOCOL_VERSION
        );
    }
    if identity.revision.len() != 40
        || !identity
            .revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("local development artifact revision is not a full lowercase commit SHA");
    }
    if identity.build_id != format!("local:{}", identity.revision) {
        bail!("local development artifact build ID must be local:<full-revision>");
    }
    let version = identity
        .release
        .strip_prefix('v')
        .context("local development artifact release has no v prefix")?;
    let version = semver::Version::parse(version)
        .context("local development artifact release is not semantic")?;
    if version.pre.is_empty() {
        bail!("local development artifact release must use a unique prerelease version");
    }
    if !version.pre.as_str().contains(&identity.revision[..8]) {
        bail!("local development prerelease must contain the first eight revision characters");
    }
    Ok(())
}

pub(super) fn validate_local_oci_candidate_identity(
    candidate: &CandidateTarget,
    identity: &EmbeddedIdentity,
) -> anyhow::Result<()> {
    let expected = EmbeddedIdentity {
        release: candidate.release.clone(),
        revision: candidate.revision.clone(),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: candidate.build_id.clone(),
    };
    if identity.protocol != nazo_operator_protocol::PROTOCOL_VERSION || identity != &expected {
        bail!("local OCI candidate embedded identity does not match the exact candidate binding");
    }
    if candidate.build_id != format!("source:{}", candidate.revision) {
        bail!("local OCI candidate build ID must be source:<full-revision>");
    }
    Ok(())
}

pub(super) fn validate_local_oci_candidate_observation(
    candidate: &CandidateTarget,
    identity: &EmbeddedIdentity,
    local_artifact_id: &str,
    actual_oci_digest: &str,
) -> anyhow::Result<()> {
    validate_local_oci_candidate_identity(candidate, identity)?;
    if !local_artifact_id
        .strip_prefix("sha256:")
        .is_some_and(|value| {
            value.len() == 64
                && value.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        bail!("local OCI candidate did not resolve to an immutable local image ID");
    }
    if actual_oci_digest != candidate.oci_digest {
        bail!("local OCI candidate image digest does not match --candidate-oci-digest");
    }
    Ok(())
}

pub(super) fn is_local_oci_candidate_record(record: &DeploymentRecord) -> bool {
    record
        .resources
        .contains_key(crate::controller::deployment::LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE)
}

pub(super) fn validate_declared_local_artifact(
    record: &DeploymentRecord,
    config: &UpdateConfig,
) -> anyhow::Result<()> {
    let marker = record
        .resources
        .get(crate::controller::deployment::LOCAL_OCI_CANDIDATE_INSTALL_RESOURCE);
    if marker.is_none() && record.active_release.build_id.starts_with("local:") {
        return validate_local_development_identity(&record.active_release);
    }
    let marker = marker
        .context("deployment does not declare an explicit local OCI candidate provenance marker")?;
    match marker {
        crate::deployment::SafeReference::File { path }
            if path
                == &crate::controller::deployment::local_oci_candidate_install_resource_path(
                    config,
                ) => {}
        _ => bail!("local OCI candidate provenance marker is not bound to the controller state"),
    }
    crate::controller::deployment::validate_completed_local_oci_candidate_provenance(
        config, record,
    )?;
    if !record.active_release.build_id.starts_with("source:") {
        bail!("local OCI candidate build ID is not source-bound");
    }
    if record.runtime_instances.len() != 1 || config.runtime.backend == RuntimeBackendKind::Systemd
    {
        bail!("local OCI candidate declaration must bind exactly one container runtime");
    }
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate declaration has no runtime")?;
    let crate::deployment::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &runtime.artifact
    else {
        bail!("local OCI candidate declaration has no OCI artifact");
    };
    if runtime.local_artifact_id.is_none()
        || !digest.strip_prefix("sha256:").is_some_and(|value| {
            value.len() == 64
                && value.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
    {
        bail!("local OCI candidate declaration is missing its immutable local artifact binding");
    }
    if runtime.local_artifact_id.as_deref() != Some(image_reference.as_str()) {
        bail!("local OCI candidate declaration does not bind its exact local image ID");
    }
    if record.active_release.revision.len() != 40
        || !record
            .active_release
            .revision
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        || !crate::model::semantic_tag(&record.active_release.release)
    {
        bail!("local OCI candidate declaration has an invalid release or full revision");
    }
    let candidate = CandidateTarget {
        release: record.active_release.release.clone(),
        revision: record.active_release.revision.clone(),
        build_id: record.active_release.build_id.clone(),
        oci_digest: digest.clone(),
    };
    validate_local_oci_candidate_identity(&candidate, &record.active_release)
}

/// Re-observe the running local OCI candidate immediately before an operation
/// treats its registered binding as complete.  The declaration check belongs
/// to the caller because registration recovery deliberately runs before the
/// durable state is marked complete.
pub(crate) fn validate_active_local_oci_candidate_runtime(
    record: &DeploymentRecord,
    config: &UpdateConfig,
    candidate: &CandidateTarget,
    expected_local_artifact_id: &str,
) -> anyhow::Result<crate::runtime::ActiveBuildTarget> {
    let active = Runtime::new(config).active_build_target()?;
    validate_active_local_oci_candidate_observation(
        record,
        config,
        candidate,
        expected_local_artifact_id,
        &active,
    )?;
    Ok(active)
}

pub(crate) fn validate_active_local_oci_candidate_observation(
    record: &DeploymentRecord,
    config: &UpdateConfig,
    candidate: &CandidateTarget,
    expected_local_artifact_id: &str,
    active: &crate::runtime::ActiveBuildTarget,
) -> anyhow::Result<()> {
    let declared_runtime = record
        .runtime_instances
        .first()
        .filter(|_| record.runtime_instances.len() == 1)
        .context("local OCI candidate deployment must bind exactly one runtime")?;
    if config.runtime.backend == RuntimeBackendKind::Systemd
        || declared_runtime.backend != config.runtime.backend
        || declared_runtime.object_reference != config.runtime.container_name
    {
        bail!("local OCI candidate runtime declaration does not match the active container");
    }
    let crate::deployment::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &declared_runtime.artifact
    else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    if record.active_release.release != candidate.release
        || record.active_release.revision != candidate.revision
        || record.active_release.build_id != candidate.build_id
        || declared_runtime.local_artifact_id.as_deref() != Some(expected_local_artifact_id)
        || image_reference != expected_local_artifact_id
        || digest != &candidate.oci_digest
    {
        bail!("local OCI candidate deployment differs from its exact persisted binding");
    }

    let active_local_artifact_id = active
        .local_artifact_id
        .as_deref()
        .context("active local OCI runtime exposes no immutable local image ID")?;
    if active_local_artifact_id != expected_local_artifact_id {
        bail!("active local OCI image ID differs from the deployment declaration");
    }
    validate_local_oci_candidate_observation(
        candidate,
        &active.embedded,
        active_local_artifact_id,
        &active.image_digest,
    )?;
    Ok(())
}

/// The completed-state caller first validates durable candidate provenance;
/// registration recovery instead supplies the exact pending state explicitly.
pub(crate) fn active_local_oci_candidate_build_target(
    record: &DeploymentRecord,
    config: &UpdateConfig,
) -> anyhow::Result<crate::runtime::ActiveBuildTarget> {
    validate_declared_local_artifact(record, config)?;
    let runtime = record
        .runtime_instances
        .first()
        .context("local OCI candidate deployment has no runtime binding")?;
    let crate::deployment::ArtifactReference::Oci { digest, .. } = &runtime.artifact else {
        bail!("local OCI candidate deployment artifact is not OCI");
    };
    let local_artifact_id = runtime
        .local_artifact_id
        .as_deref()
        .context("local OCI candidate deployment has no immutable local image ID")?;
    let candidate = CandidateTarget {
        release: record.active_release.release.clone(),
        revision: record.active_release.revision.clone(),
        build_id: record.active_release.build_id.clone(),
        oci_digest: digest.clone(),
    };
    validate_active_local_oci_candidate_runtime(record, config, &candidate, local_artifact_id)
}

/// Frozen pre-goal dispatcher. Argv cannot reach it any more (I01); it stays
/// compiled so the remaining legacy handler bodies keep building until the
/// second J-phase pass deletes this function together with
/// [`crate::cli::legacy_types`]. The J-A deletion wave already removed every
/// arm anchored in the deleted identity-ceremony, governance, coordination,
/// adoption and discovery machinery; only read-only status surfaces,
/// bootstrap-admin, TLS and self-maintenance remain.
#[allow(dead_code)]
pub(crate) fn run_legacy(
    configured_path: PathBuf,
    selector: Option<String>,
    command: LegacyCommand,
) -> anyhow::Result<()> {
    match command {
        // Internal fixed stdio executor (goal plan 03 §3.2). Runs on the
        // target machine — no legacy lock, no controller state access.
        LegacyCommand::RemoteExec => crate::target::remote_exec::run_stdio(),
        // Fleet registry commands (goal plan 02): user-scoped store, their own
        // registry lock, no lifecycle lock and no root requirement.
        LegacyCommand::Host(command) => crate::fleet::run_host(command),
        LegacyCommand::Instance(command) => {
            // The final surface (09 §1) owns `instance`; argv can no longer
            // reach this arm. Kept compiling until J-phase removes it.
            let _ = command;
            anyhow::bail!(
                "{}: the legacy instance surface was replaced by `nazoauthctl instance`",
                crate::error_codes::NOT_IMPLEMENTED_BEFORE_K_PHASE
            );
        }
        // Controller identity lifecycle (goal plan 04 D04–D09): user-scoped
        // Registry + key store; the only network peer is the instance issuer's
        // admin surface. No root and no legacy lock for the same reasons.
        LegacyCommand::Controller(command) => {
            crate::controller_identity::lifecycle::run_command_legacy(command)
        }
        LegacyCommand::DeploymentsList => list_deployments(),
        LegacyCommand::Status => {
            let store = crate::deployment::DeploymentStore::system();
            match store.registry_present() {
                Ok(true) => {
                    let record = store.resolve(selector.as_deref(), false)?;
                    registered_status(&record, false)
                }
                Ok(false) => status(&load_config(&configured_path)?),
                Err(error) => {
                    let config = load_config_unsettled(&configured_path)?;
                    if deployment::local_oci_candidate_install_is_pending(&config)? {
                        return status(&config);
                    }
                    Err(error)
                }
            }
        }
        LegacyCommand::Doctor => {
            let store = crate::deployment::DeploymentStore::system();
            match store.registry_present() {
                Ok(true) => {
                    let record = store.resolve(selector.as_deref(), false)?;
                    registered_status(&record, true)
                }
                Ok(false) => doctor(&load_config(&configured_path)?),
                Err(error) => {
                    let config = load_config_unsettled(&configured_path)?;
                    if deployment::local_oci_candidate_install_is_pending(&config)? {
                        return doctor(&config);
                    }
                    Err(error)
                }
            }
        }
        LegacyCommand::BootstrapAdmin(options) => {
            require_root()?;
            let context = control_config(
                &configured_path,
                selector.as_deref(),
                &[Capability::OperatorTasks],
                true,
                false,
                false,
            )?;
            require_confirmation(options.yes, "create the first NazoAuth administrator")?;
            bootstrap_admin(&context.config, options)
        }
        LegacyCommand::Tls(command) => crate::tls::run(
            selector.as_deref(),
            command,
            require_root,
            require_confirmation,
        ),
        LegacyCommand::SelfCheck(version) => controller_check(version.as_deref()),
        LegacyCommand::SelfUpdate { version, yes } => {
            require_root()?;
            require_confirmation(yes, "replace nazoauthctl with a signed controller Release")?;
            controller_update(version.as_deref())
        }
        LegacyCommand::SelfRollback { yes } => {
            require_root()?;
            require_confirmation(yes, "restore the previous signed nazoauthctl binary")?;
            controller_rollback()
        }
    }
}

#[cfg(test)]
mod development_identity_tests {
    use super::*;

    fn identity() -> EmbeddedIdentity {
        let revision = "52bca844beac0889d82f138cde1e48f8ce4e06e4".to_owned();
        EmbeddedIdentity {
            release: "v0.1.28-dev.52bca844".to_owned(),
            build_id: format!("local:{revision}"),
            revision,
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        }
    }

    #[test]
    fn local_development_identity_is_bound_to_revision_and_prerelease() {
        validate_local_development_identity(&identity()).unwrap();

        let mut wrong_build = identity();
        wrong_build.build_id = format!("local:{}", "a".repeat(40));
        assert!(validate_local_development_identity(&wrong_build).is_err());

        let mut signed_release = identity();
        signed_release.release = "v0.1.28".to_owned();
        assert!(validate_local_development_identity(&signed_release).is_err());

        let mut unrelated_prerelease = identity();
        unrelated_prerelease.release = "v0.1.28-dev.unrelated".to_owned();
        assert!(validate_local_development_identity(&unrelated_prerelease).is_err());
    }
}
