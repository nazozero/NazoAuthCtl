//! Shared OCI container policy, inspect, and surface-validation primitives.
//!
//! Engine-specific command dialects stay in their backend modules; this module
//! owns the common policy and fail-closed object-surface checks.

use std::{ffi::OsStr, path::Path, thread, time::Duration};

use crate::filesystem::{open_secure_regular_file, sha256_file};
use crate::process::Process;
use anyhow::{Context as _, bail};

use super::super::{
    ContainerRestartPolicy, ContainerRuntimePolicy, ManagedNetwork, managed_network_config_digest,
};

const ENGINE_FIXED_MOUNT_DESTINATIONS: &[&str] =
    &["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"];
const ENGINE_FIXED_ENV_NAMES: &[&str] = &["HOSTNAME", "HOME", "TERM", "LC_ALL", "container"];

const DEPLOYMENT_LABEL: &str = "io.nazoauth.deployment-id";
const AUTHORITY_LABEL: &str = "io.nazoauth.control-authority";
const RUNTIME_INSTANCE_LABEL: &str = "io.nazoauth.runtime-instance-id";
const RESOURCE_KIND_LABEL: &str = "io.nazoauth.managed-resource";
const CONFIG_DIGEST_LABEL: &str = "io.nazoauth.config-digest";

pub(crate) fn network_config_digest(network: &ManagedNetwork) -> String {
    managed_network_config_digest(
        &network.deployment_id,
        &network.control_authority,
        &network.name,
        network.subnet.as_deref(),
    )
}

/// Build the common hardening flags used by managed containers.
pub(crate) fn append_container_policy(
    mut command: Process,
    policy: &ContainerRuntimePolicy,
) -> Process {
    command = match policy.restart {
        ContainerRestartPolicy::No => command,
        ContainerRestartPolicy::OnFailure => command.args(["--restart", "on-failure"]),
        ContainerRestartPolicy::Always => command.args(["--restart", "always"]),
        ContainerRestartPolicy::UnlessStopped => command.args(["--restart", "unless-stopped"]),
    };
    if let Some(user) = &policy.service_user {
        command = command.arg("--user").arg(user);
    }
    if policy.drop_all_capabilities {
        command = command.arg("--cap-drop=ALL");
    }
    if policy.no_new_privileges {
        command = command.arg("--security-opt=no-new-privileges");
    }
    if policy.read_only_root {
        command = command.arg("--read-only");
    }
    if let Some(value) = policy.pids_limit {
        command = command.arg("--pids-limit").arg(value.to_string());
    }
    if let Some(value) = policy.memory_limit_bytes {
        command = command.arg("--memory").arg(value.to_string());
    }
    if let Some(value) = policy.cpu_limit_millis {
        command = command
            .arg("--cpus")
            .arg(format!("{}.{:03}", value / 1000, value % 1000));
    }
    for tmpfs in &policy.tmpfs {
        let mut options = vec![if tmpfs.read_only { "ro" } else { "rw" }];
        if tmpfs.no_exec {
            options.push("noexec");
        }
        if tmpfs.no_suid {
            options.push("nosuid");
        }
        if tmpfs.no_device {
            options.push("nodev");
        }
        command = command.arg("--tmpfs").arg(format!(
            "{}:{},size={}",
            tmpfs.destination.display(),
            options.join(","),
            tmpfs.size_bytes
        ));
    }
    command
}

/// Require the complete managed-resource identity before an operation can
/// inspect or mutate an engine object.  A deployment/authority pair is only a
/// coarse namespace; runtime id, resource role and configuration digest close
/// the cross-instance and stale-configuration gaps.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_managed_labels(
    command: &OsStr,
    arguments: &[&str],
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let mut expected_labels = vec![
        (DEPLOYMENT_LABEL, deployment_id),
        (AUTHORITY_LABEL, control_authority),
        (RESOURCE_KIND_LABEL, resource_kind),
        (CONFIG_DIGEST_LABEL, config_digest),
    ];
    if let Some(runtime_instance_id) = runtime_instance_id {
        expected_labels.push((RUNTIME_INSTANCE_LABEL, runtime_instance_id));
    }
    let document = inspect_document(command, arguments, backend_name)?;
    let labels = object_member_case_insensitive(&document, "config")
        .and_then(|config| object_member_case_insensitive(config, "labels"))
        .or_else(|| object_member_case_insensitive(&document, "labels"))
        .and_then(serde_json::Value::as_object);
    for (label, expected) in expected_labels {
        if !labels
            .and_then(|labels| labels.get(label))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == expected)
        {
            bail!(
                "refusing to manage a {backend_name} object without the expected immutable managed-resource identity"
            );
        }
    }
    Ok(())
}

/// Rebind an atomically replaced host secret into an existing managed
/// container. OCI bind mounts retain the old inode until the container is
/// started again, so comparing only the configured source path misses secret
/// and ACL rotations.
pub(crate) fn reconcile_bound_file(
    command: &OsStr,
    object_reference: &str,
    host_path: &Path,
    container_path: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let mut host = open_secure_regular_file(host_path, "managed dependency bound file", false)?;
    let expected = sha256_file(&mut host, "managed dependency bound file")?;
    let observed = container_file_digest(command, object_reference, container_path)?;
    if observed == expected {
        return Ok(());
    }

    Process::new(command)
        .args(["restart", object_reference])
        .run_quiet()
        .with_context(|| format!("failed to restart managed {backend_name} dependency"))?;
    for _ in 0..30 {
        if container_file_digest(command, object_reference, container_path)
            .is_ok_and(|observed| observed == expected)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("managed {backend_name} dependency did not load the current bound file")
}

fn container_file_digest(
    command: &OsStr,
    object_reference: &str,
    container_path: &str,
) -> anyhow::Result<String> {
    let output = Process::new(command)
        .args(["exec", object_reference, "sha256sum", container_path])
        .stdout()?;
    let digest = output
        .split_whitespace()
        .next()
        .context("managed dependency returned no bound-file digest")?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("managed dependency returned an invalid bound-file digest");
    }
    Ok(digest.to_ascii_lowercase())
}

fn object_member_case_insensitive<'a>(
    value: &'a serde_json::Value,
    expected: &str,
) -> Option<&'a serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(expected).then_some(value))
}

/// Compare the engine-reported image reference before touching a managed
/// container.  The image reference is expected to be digest-pinned by the
/// install/recovery policy; accepting a tag or an unavailable inspect field
/// would turn the labels back into the only trust boundary.
pub(crate) fn assert_container_image(
    command: &OsStr,
    arguments: &[&str],
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    require_digest_pinned_image(expected_image, backend_name)?;
    let expected_digest = expected_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| format!("sha256:{digest}"))
        .filter(|digest| super::valid_digest(digest))
        .context("managed dependency image has an invalid digest")?;
    let document = inspect_document(command, arguments, backend_name)?;
    let mut actual = Vec::new();
    for value in [
        document.pointer("/Config/Image"),
        document.get("ImageName"),
        document.pointer("/Config/ImageName"),
    ]
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    {
        actual.push(value.to_owned());
    }
    if let Some(values) = document
        .get("RepoDigests")
        .and_then(serde_json::Value::as_array)
    {
        actual.extend(
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        );
    }
    if actual.iter().any(|value| {
        value == expected_image
            || value == &expected_digest
            || value.ends_with(&format!("@{expected_digest}"))
    }) {
        return Ok(());
    }
    bail!("refusing to manage a {backend_name} container whose immutable image does not match")
}

pub(crate) fn require_digest_pinned_image(
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let Some((_, digest)) = expected_image.rsplit_once('@') else {
        bail!("{backend_name} managed dependency image is not digest-pinned");
    };
    if super::valid_digest(digest) {
        return Ok(());
    }
    bail!("{backend_name} managed dependency image is not digest-pinned")
}

pub(crate) fn append_managed_labels(
    mut command: Process,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
) -> Process {
    command = command
        .arg("--label")
        .arg(format!("{DEPLOYMENT_LABEL}={deployment_id}"))
        .arg("--label")
        .arg(format!("{AUTHORITY_LABEL}={control_authority}"))
        .arg("--label")
        .arg(format!("{RESOURCE_KIND_LABEL}={resource_kind}"))
        .arg("--label")
        .arg(format!("{CONFIG_DIGEST_LABEL}={config_digest}"));
    if let Some(runtime_instance_id) = runtime_instance_id {
        command = command
            .arg("--label")
            .arg(format!("{RUNTIME_INSTANCE_LABEL}={runtime_instance_id}"));
    }
    command
}

pub(crate) fn network_gateway(document: &serde_json::Value) -> Option<std::net::IpAddr> {
    match document {
        serde_json::Value::Object(object) => object.iter().find_map(|(key, value)| {
            if key.eq_ignore_ascii_case("gateway") {
                value.as_str().and_then(|value| value.parse().ok())
            } else {
                network_gateway(value)
            }
        }),
        serde_json::Value::Array(values) => values.iter().find_map(network_gateway),
        _ => None,
    }
}

pub(crate) fn ensure_volume(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let arguments = ["volume", "inspect", name];
    if inspect_document_optional(command, &arguments, backend_name)?.is_some() {
        return assert_managed_labels(
            command,
            &arguments,
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        );
    }
    append_managed_labels(
        Process::new(command).args(["volume", "create"]),
        &network.deployment_id,
        &network.control_authority,
        Some(runtime_instance_id),
        resource_kind,
        config_digest,
    )
    .arg(name)
    .run_quiet()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_container(
    command: &OsStr,
    name: &str,
    network: &ManagedNetwork,
    runtime_instance_id: &str,
    resource_kind: &str,
    config_digest: &str,
    expected_image: &str,
    create: Process,
    backend_name: &str,
    policy: &ContainerRuntimePolicy,
    expected_mounts: &[(&str, bool, Option<&str>)],
    expected_environment: &[(&str, &str)],
) -> anyhow::Result<()> {
    let arguments = ["container", "inspect", name];
    if inspect_document_optional(command, &arguments, backend_name)?.is_some() {
        assert_managed_labels(
            command,
            &arguments,
            &network.deployment_id,
            &network.control_authority,
            Some(runtime_instance_id),
            resource_kind,
            config_digest,
            backend_name,
        )?;
        assert_container_image(command, &arguments, expected_image, backend_name)?;
        let image_environment = inspect_image_environment(command, expected_image, backend_name)?;
        assert_managed_container_policy(
            command,
            &arguments,
            backend_name,
            policy,
            &network.name,
            expected_mounts,
            expected_environment,
            &image_environment,
        )?;
        return Process::new(command).args(["start", name]).run_quiet();
    }
    create.run_quiet()
}

/// Return the immutable id of a temporary managed container only after both
/// the name lookup and the id lookup carry the complete managed-resource
/// identity.  A name collision with an unrelated object therefore fails
/// closed instead of being removed or reused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn inspect_managed_container_id(
    command: &OsStr,
    object_reference: &str,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<Option<String>> {
    let name_arguments = ["container", "inspect", object_reference];
    let Some(document) = inspect_document_optional(command, &name_arguments, backend_name)? else {
        return Ok(None);
    };
    assert_managed_labels(
        command,
        &name_arguments,
        deployment_id,
        control_authority,
        runtime_instance_id,
        resource_kind,
        config_digest,
        backend_name,
    )?;
    let id = object_member_case_insensitive(&document, "id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context(format!(
            "{backend_name} temporary managed container omitted immutable id"
        ))?
        .to_owned();
    let id_arguments = ["container", "inspect", id.as_str()];
    let id_document = inspect_document(command, &id_arguments, backend_name)?;
    let observed_id = object_member_case_insensitive(&id_document, "id")
        .and_then(serde_json::Value::as_str)
        .context(format!(
            "{backend_name} temporary managed container id inspect omitted immutable id"
        ))?;
    if observed_id != id {
        bail!("{backend_name} temporary managed container immutable id changed");
    }
    assert_managed_labels(
        command,
        &id_arguments,
        deployment_id,
        control_authority,
        runtime_instance_id,
        resource_kind,
        config_digest,
        backend_name,
    )?;
    Ok(Some(id))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn remove_managed_container_by_id(
    command: &OsStr,
    object_id: &str,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let arguments = ["container", "inspect", object_id];
    let Some(document) = inspect_document_optional(command, &arguments, backend_name)? else {
        return Ok(());
    };
    let observed_id = object_member_case_insensitive(&document, "id")
        .and_then(serde_json::Value::as_str)
        .context(format!(
            "{backend_name} temporary managed container id inspect omitted immutable id"
        ))?;
    if observed_id != object_id {
        bail!("{backend_name} temporary managed container immutable id changed");
    }
    assert_managed_labels(
        command,
        &arguments,
        deployment_id,
        control_authority,
        runtime_instance_id,
        resource_kind,
        config_digest,
        backend_name,
    )?;
    Process::new(command)
        .args(["rm", "--force", object_id])
        .run_quiet()
        .with_context(|| format!("failed to remove managed {backend_name} temporary container"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn remove_managed_container_by_name(
    command: &OsStr,
    object_reference: &str,
    deployment_id: &str,
    control_authority: &str,
    runtime_instance_id: Option<&str>,
    resource_kind: &str,
    config_digest: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let Some(object_id) = inspect_managed_container_id(
        command,
        object_reference,
        deployment_id,
        control_authority,
        runtime_instance_id,
        resource_kind,
        config_digest,
        backend_name,
    )?
    else {
        return Ok(());
    };
    remove_managed_container_by_id(
        command,
        &object_id,
        deployment_id,
        control_authority,
        runtime_instance_id,
        resource_kind,
        config_digest,
        backend_name,
    )
}

pub(crate) fn inspect_image_environment(
    command: &OsStr,
    image: &str,
    backend_name: &str,
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let document = inspect_document(command, &["image", "inspect", image], backend_name)?;
    let values = document
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .context("managed image inspect omitted environment")?;
    let mut environment = std::collections::BTreeMap::new();
    for value in values.iter().filter_map(serde_json::Value::as_str) {
        let (name, value) = value
            .split_once('=')
            .context("managed image contains an invalid environment entry")?;
        if name.is_empty()
            || environment
                .insert(name.to_owned(), value.to_owned())
                .is_some()
        {
            bail!("managed image environment is ambiguous");
        }
    }
    Ok(environment)
}

pub(crate) fn prepare_managed_volume_ownership(
    command: &OsStr,
    volume: &str,
    image: &str,
    destination: &str,
    owner: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    require_digest_pinned_image(image, backend_name)?;
    Process::new(command)
        .args([
            "run",
            "--rm",
            "--user",
            "0:0",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_OVERRIDE",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "134217728",
            "--cpus",
            "1.000",
            "--volume",
        ])
        .arg(format!("{volume}:{destination}"))
        .args(["--entrypoint", "chown"])
        .arg(image)
        .args(["-R", owner, destination])
        .run_quiet()
        .with_context(|| format!("failed to initialize {backend_name} managed volume ownership"))
}

/// Inspect a single engine object as JSON.  The JSON path is deliberately
/// shared by Docker and Podman so a template failure cannot be mistaken for a
/// missing object.  Engine/daemon failures are surfaced as a distinct,
/// fail-closed error instead of triggering create-on-failure behavior.
pub(crate) fn inspect_document(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<serde_json::Value> {
    inspect_document_optional(command, arguments, backend_name)?
        .context(format!("{backend_name} managed object is absent"))
}

pub(crate) fn inspect_document_optional(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let output = Process::new(command)
        .args(arguments)
        .arg("--format")
        .arg("{{json .}}")
        .output()
        .with_context(|| format!("{backend_name} engine unavailable"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr_engine_unavailable(&stderr) {
            bail!("{backend_name} engine unavailable while inspecting a managed object");
        }
        if is_not_found_error(&stderr) {
            return Ok(None);
        }
        bail!("{backend_name} object inspection failed");
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{backend_name} inspect returned invalid JSON"))?;
    let value = parsed
        .as_array()
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or(parsed);
    Ok(Some(value))
}

pub(crate) fn container_is_running(
    command: &OsStr,
    object: &str,
    backend_name: &str,
) -> anyhow::Result<bool> {
    let arguments = ["container", "inspect", object];
    let document = inspect_document(command, &arguments, backend_name)?;
    document
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .context("container inspect omitted running state")
}

pub(crate) fn command_stdout(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
) -> anyhow::Result<String> {
    let output = Process::new(command)
        .args(arguments)
        .output()
        .with_context(|| format!("{backend_name} engine unavailable"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr_engine_unavailable(&stderr) {
            bail!("{backend_name} engine unavailable");
        }
        bail!("{backend_name} command failed");
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("{backend_name} command returned non-UTF-8 output"))
}

pub(crate) fn is_engine_unavailable_error(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("engine unavailable")
}

fn is_not_found_error(stderr: &str) -> bool {
    stderr.contains("no such object")
        || stderr.contains("no such container")
        || stderr.contains("no such volume")
        || stderr.contains("no such network")
        || stderr.contains("no volume with name")
        || stderr.contains("no container with name or id")
        || stderr.contains("network not found")
        || stderr.contains("volume not found")
}

fn stderr_engine_unavailable(stderr: &str) -> bool {
    stderr.contains("cannot connect")
        || stderr.contains("connection refused")
        || stderr.contains("unable to connect")
        || stderr.contains("connection to")
        || stderr.contains("is the docker daemon running")
        || stderr.contains("podman machine")
        || stderr.contains("failed to connect")
        || stderr.contains("cannot communicate")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_managed_container_policy(
    command: &OsStr,
    arguments: &[&str],
    backend_name: &str,
    policy: &ContainerRuntimePolicy,
    expected_network: &str,
    expected_mounts: &[(&str, bool, Option<&str>)],
    expected_environment: &[(&str, &str)],
    image_environment: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let document = inspect_document(command, arguments, backend_name)?;
    let host_config = document
        .get("HostConfig")
        .context("container inspect omitted HostConfig")?;

    if let Some(value) = host_config.get("Privileged")
        && !value.is_null()
        && value.as_bool().with_context(|| {
            format!("{backend_name} inspect returned an invalid Privileged flag")
        })?
    {
        bail!("{backend_name} managed container cannot run privileged");
    }
    for field in [
        "NetworkMode",
        "PidMode",
        "IpcMode",
        "UTSMode",
        "CgroupnsMode",
        "UsernsMode",
    ] {
        let Some(value) = host_config.get(field) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let mode = value
            .as_str()
            .with_context(|| format!("{backend_name} inspect returned an invalid {field}"))?;
        if mode.eq_ignore_ascii_case("host") {
            bail!("{backend_name} managed container cannot use the host {field} namespace");
        }
    }

    let restart = host_config
        .pointer("/RestartPolicy/Name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expected_restart = match policy.restart {
        ContainerRestartPolicy::No => "no",
        ContainerRestartPolicy::OnFailure => "on-failure",
        ContainerRestartPolicy::Always => "always",
        ContainerRestartPolicy::UnlessStopped => "unless-stopped",
    };
    if restart != expected_restart {
        bail!("{backend_name} managed container restart policy drifted");
    }
    if let Some(expected_user) = &policy.service_user {
        let observed_user = object_member_case_insensitive(&document, "config")
            .and_then(|config| object_member_case_insensitive(config, "user"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if observed_user != expected_user {
            bail!("{backend_name} managed container service user drifted");
        }
    }
    if policy.read_only_root
        && !host_config
            .get("ReadonlyRootfs")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        bail!("{backend_name} managed container read-only root policy drifted");
    }
    if policy.no_new_privileges
        && !host_config
            .get("SecurityOpt")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|value| {
                value.eq_ignore_ascii_case("no-new-privileges")
                    || value.to_ascii_lowercase().starts_with("no-new-privileges=")
            })
    {
        bail!("{backend_name} managed container no-new-privileges policy drifted");
    }
    if policy.drop_all_capabilities {
        let dropped = host_config
            .get("CapDrop")
            .and_then(serde_json::Value::as_array)
            .context("container inspect omitted dropped capabilities")?;
        let added = host_config
            .get("CapAdd")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        if added != 0 || !observed_cap_drop_all(dropped) {
            bail!("{backend_name} managed container capability policy drifted");
        }
    }
    if let Some(limit) = policy.pids_limit
        && host_config
            .get("PidsLimit")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u32::try_from(value).ok())
            != Some(limit)
    {
        bail!("{backend_name} managed container pids limit drifted");
    }
    if let Some(limit) = policy.memory_limit_bytes
        && host_config
            .get("Memory")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok())
            != Some(limit)
    {
        bail!("{backend_name} managed container memory limit drifted");
    }
    if let Some(limit) = policy.cpu_limit_millis {
        let expected_nano_cpus = u64::from(limit) * 1_000_000;
        let expected_quota = u64::from(limit) * 100;
        let nano_cpus = inspect_u64_field(host_config, "NanoCpus", backend_name)?;
        let quota = inspect_u64_field(host_config, "CpuQuota", backend_name)?;
        let period = inspect_u64_field(host_config, "CpuPeriod", backend_name)?;
        let nano_matches = nano_cpus == Some(expected_nano_cpus);
        let quota_matches = quota == Some(expected_quota);
        let nano_unset = nano_cpus.is_none() || nano_cpus == Some(0);
        let quota_unset = quota.is_none() || quota == Some(0);
        if !(nano_matches || quota_matches)
            || (!nano_unset && !nano_matches)
            || (!quota_unset && !quota_matches)
            || (quota_matches && period.is_some_and(|value| value != 0 && value != 100_000))
        {
            bail!("{backend_name} managed container CPU limit drifted");
        }
    }
    let observed_tmpfs = host_config
        .get("Tmpfs")
        .and_then(serde_json::Value::as_object)
        .context("container inspect omitted tmpfs policy")?;
    let expected_tmpfs = policy
        .tmpfs
        .iter()
        .map(|tmpfs| tmpfs.destination.to_string_lossy().into_owned())
        .collect::<std::collections::BTreeSet<_>>();
    if observed_tmpfs
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected_tmpfs
    {
        bail!("{backend_name} managed container tmpfs surface drifted");
    }
    for tmpfs in &policy.tmpfs {
        let destination = tmpfs.destination.to_string_lossy();
        let observed = host_config
            .get("Tmpfs")
            .and_then(serde_json::Value::as_object)
            .and_then(|tmpfses| tmpfses.get(destination.as_ref()));
        let Some(observed) = observed else {
            bail!("{backend_name} managed container tmpfs policy drifted");
        };
        let observed = parse_tmpfs_options(observed, backend_name, destination.as_ref())?;
        let expected = expected_tmpfs_options(tmpfs);
        if observed != expected {
            bail!("{backend_name} managed container tmpfs policy drifted");
        }
    }

    let networks = document
        .pointer("/NetworkSettings/Networks")
        .or_else(|| document.pointer("/NetworkSettings/Networks"))
        .and_then(serde_json::Value::as_object)
        .context("container inspect omitted network membership")?;
    if networks.len() != 1 || !networks.contains_key(expected_network) {
        bail!("{backend_name} managed container network policy drifted");
    }

    let mounts = document
        .get("Mounts")
        .and_then(serde_json::Value::as_array)
        .context("container inspect omitted managed mounts")?;
    let mut expected_destinations = expected_mounts
        .iter()
        .map(|(destination, _, _)| (*destination).to_owned())
        .collect::<std::collections::BTreeSet<String>>();
    expected_destinations.extend(
        policy
            .tmpfs
            .iter()
            .map(|tmpfs| tmpfs.destination.to_string_lossy().into_owned()),
    );
    for mount in mounts {
        let destination = mount
            .get("Destination")
            .and_then(serde_json::Value::as_str)
            .context("container inspect returned a mount without a destination")?;
        if !expected_destinations
            .iter()
            .any(|expected| expected.as_str() == destination)
            && !ENGINE_FIXED_MOUNT_DESTINATIONS.contains(&destination)
        {
            bail!("{backend_name} managed container contains an undeclared mount");
        }
    }
    for (destination, read_only, expected_source) in expected_mounts {
        let Some(mount) = mounts.iter().find(|mount| {
            mount.get("Destination").and_then(serde_json::Value::as_str) == Some(*destination)
        }) else {
            bail!("{backend_name} managed container mount policy drifted");
        };
        let observed_read_only = mount
            .get("RW")
            .and_then(serde_json::Value::as_bool)
            .map_or_else(
                || {
                    mount
                        .get("Mode")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|mode| mode.split(',').any(|value| value == "ro"))
                },
                |read_write| !read_write,
            );
        if observed_read_only != *read_only {
            bail!("{backend_name} managed container mount policy drifted");
        }
        if let Some(expected_source) = *expected_source {
            let observed_source = mount
                .get("Source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !mount_source_matches(observed_source, expected_source) {
                bail!("{backend_name} managed container mount source drifted");
            }
        }
    }

    let env = document
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .context("container inspect omitted environment")?;
    let expected_names = expected_environment
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    let mut observed_environment = std::collections::BTreeMap::new();
    for entry in env.iter().filter_map(serde_json::Value::as_str) {
        let (name, value) = entry
            .split_once('=')
            .context("managed container contains an invalid environment entry")?;
        if observed_environment
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            bail!("{backend_name} managed container environment is ambiguous");
        }
        if !expected_names.contains(name)
            && !ENGINE_FIXED_ENV_NAMES.contains(&name)
            && image_environment.get(name).map(String::as_str) != Some(value)
        {
            bail!("{backend_name} managed container contains an undeclared environment variable");
        }
    }
    for name in env
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|value| value.split_once('=').map(|(name, _)| name))
    {
        if (name.to_ascii_uppercase().contains("PASSWORD")
            || name.to_ascii_uppercase().contains("SECRET"))
            && !expected_names.contains(name)
        {
            bail!(
                "{backend_name} managed container contains an unauthorized secret environment variable"
            );
        }
    }
    for (name, expected) in image_environment {
        if expected_names.contains(name.as_str()) || ENGINE_FIXED_ENV_NAMES.contains(&name.as_str())
        {
            continue;
        }
        if observed_environment.get(name) != Some(expected) {
            bail!("{backend_name} managed container image environment drifted");
        }
    }
    for (name, expected) in expected_environment {
        let prefix = format!("{name}=");
        let observed = env
            .iter()
            .filter_map(serde_json::Value::as_str)
            .find_map(|value| value.strip_prefix(&prefix));
        if observed != Some(*expected) {
            bail!("{backend_name} managed container environment policy drifted");
        }
    }
    Ok(())
}

pub(crate) fn observed_cap_drop_all(values: &[serde_json::Value]) -> bool {
    let normalized = values
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|value| {
            let upper = value.to_ascii_uppercase();
            upper.strip_prefix("CAP_").unwrap_or(&upper).to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    if normalized.contains("ALL") {
        return true;
    }
    // Podman expands `--cap-drop ALL` to its complete default bounding set in
    // inspect output. Requiring every member distinguishes that dialect from
    // a partial drop while remaining fail-closed if the engine adds a new
    // default capability that this controller does not understand.
    const PODMAN_DEFAULT_CAPABILITIES: &[&str] = &[
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "NET_BIND_SERVICE",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYS_CHROOT",
    ];
    normalized.len() == PODMAN_DEFAULT_CAPABILITIES.len()
        && PODMAN_DEFAULT_CAPABILITIES
            .iter()
            .all(|capability| normalized.contains(*capability))
}

fn mount_source_matches(observed: &str, expected: &str) -> bool {
    observed == expected
        || (!expected.contains('/')
            && !expected.contains('\\')
            && (observed.ends_with(&format!("/{expected}/_data"))
                || observed.ends_with(&format!("\\{expected}\\_data"))))
}

fn inspect_u64_field(
    object: &serde_json::Value,
    field: &str,
    backend_name: &str,
) -> anyhow::Result<Option<u64>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_u64()
        .map(Some)
        .with_context(|| format!("{backend_name} inspect returned an invalid {field}"))
}

fn expected_tmpfs_options(
    tmpfs: &super::super::NeutralTmpfs,
) -> std::collections::BTreeSet<String> {
    let mut options = std::collections::BTreeSet::new();
    options.insert(if tmpfs.read_only { "ro" } else { "rw" }.to_owned());
    if tmpfs.no_exec {
        options.insert("noexec".to_owned());
    }
    if tmpfs.no_suid {
        options.insert("nosuid".to_owned());
    }
    if tmpfs.no_device {
        options.insert("nodev".to_owned());
    }
    options.insert(format!("size={}", tmpfs.size_bytes));
    options
}

fn parse_tmpfs_options(
    value: &serde_json::Value,
    backend_name: &str,
    destination: &str,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let mut options = std::collections::BTreeSet::new();
    let mut add = |option: &str| {
        let option = option.trim().to_ascii_lowercase();
        if option.is_empty() || !options.insert(option) {
            return Err(anyhow::anyhow!(
                "{backend_name} managed container returned duplicate or empty tmpfs option for {destination}"
            ));
        }
        Ok(())
    };
    match value {
        serde_json::Value::String(value) => {
            for option in value.split(',') {
                add(option)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                let value = value.as_str().with_context(|| {
                    format!(
                        "{backend_name} managed container returned a non-string tmpfs option for {destination}"
                    )
                })?;
                for option in value.split(',') {
                    add(option)?;
                }
            }
        }
        _ => {
            bail!(
                "{backend_name} managed container returned an invalid tmpfs option list for {destination}"
            );
        }
    }
    // Podman injects these two propagation/copy-up annotations when it
    // serializes tmpfs mounts through inspect. They do not relax the tmpfs
    // security policy and are not part of the user-declared mount contract.
    // Keep the exception engine-specific: Docker and every other caller must
    // still match the declared option set exactly.
    if backend_name == "Podman" {
        options.remove("rprivate");
        options.remove("tmpcopyup");
    }
    Ok(options)
}
