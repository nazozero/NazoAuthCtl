use std::{
    collections::BTreeSet,
    fs::{self, File, TryLockError},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_operator_protocol::EmbeddedIdentity;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::deployment::{
    DeploymentRecord, DeploymentStore, FileLock, RuntimeBackendKind, SafeReference,
};
use crate::{
    filesystem::{atomic_write, open_lock_file, remove_file_durable},
    model::{ReleaseManifest, UpdateConfig},
    process::Process,
    release::{ExpectedReleaseTarget, compare_versions, expected_release_target, expected_target},
    runtime::Runtime,
};

mod commands;
mod deployment;
mod keys;
pub(crate) use keys::{
    extract_openid4vc_trust_anchors, managed_openid4vc_bundle_path, read_managed_openid4vc_bundle,
};
mod self_update;
mod surface_run;
pub(crate) use surface_run::run;
mod updates;
use self_update::*;
use updates::*;

/// Durable provenance for a deliberately local-only OCI target.  The installer
/// entry is gone; the shape survives as the persisted candidate state that the
/// pending/completed guards parse fail-closed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LocalOciCandidateInstall {
    pub(crate) image: String,
    pub(crate) target: CandidateTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct CandidateTarget {
    pub(crate) release: String,
    pub(crate) revision: String,
    pub(crate) build_id: String,
    pub(crate) oci_digest: String,
}

pub(crate) struct ControlConfig {
    path: PathBuf,
    pub(crate) config: UpdateConfig,
    /// The declaration selected at the same boundary as the configuration.
    ///
    /// Registered commands must use this snapshot instead of resolving the
    /// selector a second time after acquiring the deployment lock.  A
    /// legacy, unregistered configuration has no declaration and therefore
    /// keeps this field as `None`.
    record: Option<DeploymentRecord>,
    _legacy_lock: Option<File>,
    _deployment_lock: Option<FileLock>,
}

impl ControlConfig {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn conformance_control_context(
    config_path: &Path,
    selector: Option<&str>,
) -> anyhow::Result<(ControlConfig, String, ExpectedReleaseTarget)> {
    require_root()?;
    let context = control_config(config_path, selector, true, false)?;
    let runtime = Runtime::new(&context.config);
    let target = if context.config.runtime.backend == RuntimeBackendKind::Systemd {
        context
            .config
            .runtime
            .binary_path
            .to_string_lossy()
            .into_owned()
    } else {
        runtime.active_image()?
    };
    let expected = if let Some(record) = context.record.as_ref()
        && commands::is_local_oci_candidate_record(record)
    {
        let active = commands::active_local_oci_candidate_build_target(record, &context.config)?;
        let expected_oci_digest = record
            .runtime_instances
            .first()
            .and_then(|runtime| match &runtime.artifact {
                crate::deployment::ArtifactReference::Oci { digest, .. } => Some(digest),
                _ => None,
            })
            .context("local OCI deployment declaration has no OCI artifact binding")?;
        expected_release_target(
            &context.config,
            active.embedded,
            expected_oci_digest.to_owned(),
            active.binary_digest,
        )?
    } else if let Some(record) = context.record.as_ref()
        && record.active_release.build_id.starts_with("local:")
    {
        // Development activation retains its established host-or-container
        // semantics.  It is deliberately not inferred from `source:`: the
        // candidate path above has explicit durable provenance.
        commands::validate_local_development_identity(&record.active_release)?;
        let active = runtime.active_build_target()?;
        if active.embedded != record.active_release {
            bail!("active local development identity differs from the deployment declaration");
        }
        expected_release_target(
            &context.config,
            active.embedded,
            active.image_digest,
            active.binary_digest,
        )?
    } else {
        let release = load_active_release(&context.config)?;
        expected_target(&context.config, &release)?
    };
    Ok((context, target, expected))
}

fn control_config(
    config_path: &Path,
    selector: Option<&str>,
    application_task: bool,
    unsettled: bool,
) -> anyhow::Result<ControlConfig> {
    let store = DeploymentStore::system();
    if !store.registry_present()? {
        let _legacy_lock = deployment::acquire_oidf_run_shared_lock()?;
        let config = if unsettled {
            load_config_unsettled(config_path)?
        } else {
            load_config(config_path)?
        };
        if deployment::local_oci_candidate_install_is_pending(&config)? {
            bail!(
                "local OCI candidate installation is pending; repeat its exact install command or inspect status before running controller commands"
            );
        }
        return Ok(ControlConfig {
            path: config_path.to_path_buf(),
            config,
            record: None,
            _legacy_lock: Some(_legacy_lock),
            _deployment_lock: None,
        });
    }

    // Every remaining entry into a registered deployment context runs
    // application tasks against one shared deployment snapshot.
    let resolved = store.resolve(selector, true)?;
    let deployment_lock = Some(store.deployment_shared_lock(&resolved.deployment_id)?);
    let record = store.load(&resolved.deployment_id)?;
    if !record
        .control_protocol_versions
        .contains(&nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA)
    {
        bail!(
            "deployment {} does not support controller protocol {}; command refused",
            record.deployment_id,
            nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA
        );
    }
    if application_task
        && !record
            .operator_protocol_versions
            .contains(&nazo_operator_protocol::PROTOCOL_VERSION)
    {
        bail!(
            "deployment {} does not support operator protocol {}; application task refused",
            record.deployment_id,
            nazo_operator_protocol::PROTOCOL_VERSION
        );
    }
    let path = match record.resources.get("controller_config") {
        Some(SafeReference::File { path }) => path.clone(),
        _ => bail!(
            "deployment {} has no verified controller configuration; create and approve a lifecycle plan before mutation",
            record.deployment_id
        ),
    };
    let config = if unsettled {
        load_config_unsettled(&path)?
    } else {
        load_config(&path)?
    };
    if deployment::local_oci_candidate_install_is_pending(&config)? {
        bail!(
            "local OCI candidate installation is pending; repeat its exact install command or inspect status before running controller commands"
        );
    }
    verify_control_binding(&record, &config)?;
    Ok(ControlConfig {
        path,
        config,
        record: Some(record),
        _legacy_lock: None,
        _deployment_lock: deployment_lock,
    })
}

fn verify_control_binding(record: &DeploymentRecord, config: &UpdateConfig) -> anyhow::Result<()> {
    if config.operator.deployment_id != record.deployment_id
        || config.operator.controller_key_id != record.control_authority
    {
        bail!("controller configuration is bound to a different deployment authority");
    }
    let [runtime] = record.runtime_instances.as_slice() else {
        bail!("controller configuration requires exactly one declaration-bound runtime instance");
    };
    let object_reference = if config.runtime.backend == RuntimeBackendKind::Systemd {
        &config.runtime.service_name
    } else {
        &config.runtime.container_name
    };
    if runtime.backend != config.runtime.backend
        || runtime.runtime_instance_id != config.runtime.runtime_instance_id
        || &runtime.object_reference != object_reference
    {
        bail!("controller configuration runtime identity differs from the deployment declaration");
    }
    let configured_ports = (!config.runtime.publish_address.is_empty())
        .then(|| config.runtime.publish_address.clone())
        .into_iter()
        .collect::<BTreeSet<_>>();
    let configured_networks = (!config.runtime.network.is_empty())
        .then(|| config.runtime.network.clone())
        .into_iter()
        .collect::<BTreeSet<_>>();
    let configured_mounts = config
        .runtime
        .mounts
        .iter()
        .map(|mount| {
            (
                mount.source.clone(),
                mount.target.clone(),
                mount.read_only,
                mount.selinux_relabel,
            )
        })
        .collect::<BTreeSet<_>>();
    let declared_mounts = runtime
        .mounts
        .iter()
        .map(|mount| {
            (
                mount.source.clone(),
                mount.destination.clone(),
                mount.read_only,
                mount.selinux_relabel,
            )
        })
        .collect::<BTreeSet<_>>();
    if runtime.ports.iter().cloned().collect::<BTreeSet<_>>() != configured_ports
        || runtime.networks.iter().cloned().collect::<BTreeSet<_>>() != configured_networks
        || declared_mounts != configured_mounts
    {
        bail!("controller configuration runtime surface differs from the deployment declaration");
    }
    Ok(())
}

/// Durable state for the explicit local-OCI install path.  It exists before
/// the first privileged operator task, so a crash can only be resumed with the
/// same four identity bindings and immutable local image ID.
/// The installer entry was removed with the J-A wave; the persisted shape is
/// still parsed fail-closed by the pending/completed guards.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalOciCandidateInstallState {
    schema: u32,
    candidate: LocalOciCandidateInstall,
    local_artifact_id: String,
    #[serde(default)]
    recovery_backup: Option<PathBuf>,
    #[serde(default)]
    management_event_file: Option<String>,
    #[serde(default)]
    management_event_sha256: Option<String>,
    completed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerTrustState {
    schema: u32,
    version: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerRollbackState {
    schema: u32,
    version: String,
    sha256: String,
    artifact: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerUpdateJournal {
    schema: u32,
    from_version: String,
    from_sha256: String,
    to_version: String,
    to_sha256: String,
    staged_artifact: PathBuf,
}

fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        bail!("this command requires root on a Unix host");
    }
    #[cfg(unix)]
    {
        if Process::new("id").arg("-u").stdout()?.trim() != "0" {
            bail!("this command requires root");
        }
        Ok(())
    }
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

fn require_confirmation(yes: bool, action: &str) -> anyhow::Result<()> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("{action} requires --yes in non-interactive mode");
    }
    eprint!("Confirm: {action} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("operation cancelled")
    }
}
