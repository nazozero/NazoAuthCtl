//! Shared command construction and parsing for OCI container backends.
//!
//! Docker and Podman intentionally keep their runtime-specific discovery and
//! lifecycle details in their respective façades.  The command policy,
//! ownership checks, one-shot setup, and digest parsing are the same security
//! rules for both engines, so they live here to keep the two backends from
//! drifting.

use std::{ffi::OsStr, path::Path, thread, time::Duration};

use crate::filesystem::{open_secure_regular_file, sha256_file};
use crate::process::Process;
use anyhow::{Context as _, bail};

use super::{
    ContainerRestartPolicy, ContainerRuntimePolicy, ManagedNetwork, NeutralMount, OneShotTask,
    managed_network_config_digest,
};

mod managed_dependencies;

pub use managed_dependencies::oci_backup_digests;
pub(crate) use managed_dependencies::{
    TemporaryPostgresCredentials, backup_managed_dependencies, load_dependency_restore_journal,
    persist_dependency_restore_journal, postgres_database_from_service_file,
    temporary_postgres_credentials, validate_sql_identifier, verify_oci_backup_artifacts,
};

/// Numeric uid/gid used for OCI one-shot work.  A name supplied by an image
/// is not an authorization boundary: the caller must provide the explicit
/// uid:gid contract and the engine must accept it.
pub(crate) const NON_ROOT_ONE_SHOT_USER: &str = "10001:10001";

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
        .filter(|digest| valid_digest(digest))
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
    if valid_digest(digest) {
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

fn inspect_image_environment(
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
        if is_not_found_error(&stderr) {
            return Ok(None);
        }
        if stderr_engine_unavailable(&stderr) {
            bail!("{backend_name} engine unavailable while inspecting a managed object");
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
        || stderr.contains("not found")
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
        let nano_cpus = host_config
            .get("NanoCpus")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok());
        let quota = host_config
            .get("CpuQuota")
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| u64::try_from(value).ok());
        if nano_cpus != Some(expected_nano_cpus) && quota != Some(u64::from(limit) * 100) {
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
        let options = match observed {
            Some(serde_json::Value::String(value)) => value.to_ascii_lowercase(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
                .to_ascii_lowercase(),
            _ => String::new(),
        };
        let size = format!("size={}", tmpfs.size_bytes);
        if observed.is_none()
            || (tmpfs.read_only && !options.contains("ro"))
            || (!tmpfs.read_only && !options.contains("rw"))
            || (tmpfs.no_exec && !options.contains("noexec"))
            || (tmpfs.no_suid && !options.contains("nosuid"))
            || (tmpfs.no_device && !options.contains("nodev"))
            || !options.contains(&size)
        {
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

fn observed_cap_drop_all(values: &[serde_json::Value]) -> bool {
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

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use crate::runtime_backend::{ManagedDependencyBackup, managed_dependency_identity};
    use crate::{
        filesystem::PrivateTempDir, process::Process, runtime_backend::ManagedNetwork,
        test_support::write_shell_executable,
    };

    #[test]
    fn container_lookup_cannot_resolve_a_volume_with_the_container_name_as_prefix() {
        let work = PrivateTempDir::new("runtime-container-inspect-type").unwrap();
        let engine = work.path().join("fake-podman");
        let generic_marker = work.path().join("generic-inspect-was-used");
        let create_argv = work.path().join("create-argv");
        write_shell_executable(
            &engine,
            &format!(
                "if [ \"$*\" = 'container inspect managed-postgres --format {{{{json .}}}}' ]; then printf '%s\\n' 'no such object' >&2; exit 1; fi\nif [ \"$*\" = 'inspect managed-postgres' ]; then : > '{}'; exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\n",
                generic_marker.display(),
                create_argv.display(),
            ),
        );
        let network = ManagedNetwork {
            name: "managed-network".to_owned(),
            subnet: None,
            deployment_id: "deployment-test".to_owned(),
            control_authority: "controller-test".to_owned(),
        };
        super::ensure_container(
            engine.as_os_str(),
            "managed-postgres",
            &network,
            "runtime-test",
            "postgres",
            &format!("sha256:{}", "c".repeat(64)),
            "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Process::new(engine.as_os_str()).args(["run", "--name", "managed-postgres"]),
            "Podman",
            &super::ContainerRuntimePolicy::managed_default(),
            &[],
            &[],
        )
        .unwrap();
        assert!(!generic_marker.exists());
        assert_eq!(
            fs::read_to_string(create_argv).unwrap(),
            "run\n--name\nmanaged-postgres\n"
        );
    }

    #[test]
    fn image_identity_uses_valid_engine_templates() {
        let work = PrivateTempDir::new("runtime-image-inspect-template").unwrap();
        let engine = work.path().join("fake-podman");
        let expected = "docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        write_shell_executable(
            &engine,
            "if [ \"$*\" = 'container inspect managed-postgres --format {{json .}}' ]; then\n  printf '%s\\n' '{\"Config\":{\"Image\":\"docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'\n  exit 0\nfi\nexit 1",
        );
        super::assert_container_image(
            engine.as_os_str(),
            &["container", "inspect", "managed-postgres"],
            expected,
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn managed_identity_accepts_podman_lowercase_label_surface() {
        let work = PrivateTempDir::new("runtime-podman-label-surface").unwrap();
        let engine = work.path().join("fake-podman");
        write_shell_executable(
            &engine,
            "printf '%s\n' '{\"labels\":{\"io.nazoauth.deployment-id\":\"deployment-test\",\"io.nazoauth.control-authority\":\"controller-test\",\"io.nazoauth.managed-resource\":\"network\",\"io.nazoauth.config-digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'",
        );
        super::assert_managed_labels(
            engine.as_os_str(),
            &["network", "inspect", "managed-network"],
            "deployment-test",
            "controller-test",
            None,
            "network",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Podman",
        )
        .unwrap();
    }

    #[test]
    fn managed_dependency_policy_runs_services_as_the_image_non_root_identity() {
        let work = PrivateTempDir::new("runtime-managed-service-user").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );
        super::append_container_policy(
            Process::new(engine.as_os_str()).arg("run"),
            &super::ContainerRuntimePolicy::managed_postgres(),
        )
        .run_quiet()
        .unwrap();
        let arguments = fs::read_to_string(arguments).unwrap();
        assert!(arguments.contains("--user\n999:999\n"));
        assert!(arguments.contains("--cap-drop=ALL\n"));
        assert!(arguments.contains("--read-only\n"));
    }

    #[test]
    fn build_identity_policy_is_closed_before_the_image_positional() {
        let work = PrivateTempDir::new("runtime-build-identity-order").unwrap();
        let engine = work.path().join("fake-engine");
        let arguments = work.path().join("arguments");
        write_shell_executable(
            &engine,
            &format!("printf '%s\\n' \"$@\" > '{}'", arguments.display()),
        );
        let image = "example.invalid/nazoauth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        super::build_identity_process(engine.as_os_str())
            .args(["--network", "none"])
            .arg(image)
            .arg("nazoauth")
            .arg("build-identity")
            .run_quiet()
            .unwrap();

        let arguments = fs::read_to_string(arguments).unwrap();
        let arguments = arguments.lines().collect::<Vec<_>>();
        let policy = arguments
            .iter()
            .position(|argument| *argument == "--cap-drop=ALL")
            .unwrap();
        let image = arguments
            .iter()
            .position(|argument| *argument == image)
            .unwrap();
        assert!(policy < image);
        assert!(!arguments.contains(&"ALL"));
    }

    #[test]
    fn podman_expanded_cap_drop_all_is_recognized_without_accepting_partial_sets() {
        let complete = [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ]
        .into_iter()
        .map(serde_json::Value::from)
        .collect::<Vec<_>>();
        assert!(super::observed_cap_drop_all(&complete));
        assert!(!super::observed_cap_drop_all(&complete[..10]));
    }

    #[test]
    fn managed_valkey_backup_reads_auth_from_stdin_without_a_secret_environment_variable() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("managed-valkey-backup-auth").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let engine = work.path().join("fake-podman");
        let argv = work.path().join("argv");
        let lastsave_seen = work.path().join("lastsave-seen");
        let password_file = work.path().join("valkey-password");
        fs::create_dir(work.path().join("backup")).unwrap();
        chown(work.path().join("backup"), Some(0), Some(10001)).unwrap();
        fs::set_permissions(
            work.path().join("backup"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::write(&password_file, "secret-canary").unwrap();
        fs::set_permissions(&password_file, fs::Permissions::from_mode(0o400)).unwrap();
        write_shell_executable(
            &engine,
            &format!(
                "case \"$*\" in *--interactive*) IFS= read -r _ || true ;; esac\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  *LASTSAVE*) if [ -e '{}' ]; then printf '101\\n'; else : > '{}'; printf '100\\n'; fi ;;\n  *) if [ \"$1\" = cp ]; then : > \"$3\"; fi; exit 0 ;;\nesac",
                argv.display(),
                lastsave_seen.display(),
                lastsave_seen.display(),
            ),
        );
        let postgres_image = format!("postgres@sha256:{}", "a".repeat(64));
        let valkey_image = format!("valkey@sha256:{}", "b".repeat(64));
        let backup = ManagedDependencyBackup {
            destination: work.path().join("backup"),
            network: "managed-network".to_owned(),
            postgres_object: "managed-postgres".to_owned(),
            postgres_volume: "managed-postgres-data".to_owned(),
            postgres_image: postgres_image.clone(),
            postgres_user: "nazoauth_runtime".to_owned(),
            postgres_database: "oauth".to_owned(),
            postgres_validation_image: postgres_image.clone(),
            valkey_object: "managed-valkey".to_owned(),
            valkey_volume: "managed-valkey-data".to_owned(),
            valkey_image: valkey_image.clone(),
            valkey_rdb_path: "/data/dump.rdb".to_owned(),
            valkey_password_file: Some(password_file),
            valkey_user: Some(super::super::MANAGED_VALKEY_BACKUP_USER.to_owned()),
            identity: managed_dependency_identity(
                "deployment-test",
                "controller-test",
                "runtime-test",
                "managed-network",
                "managed-postgres",
                "managed-postgres-data",
                &postgres_image,
                "oauth",
                "nazoauth_runtime",
                "managed-valkey",
                "managed-valkey-data",
                &valkey_image,
            ),
        };
        super::backup_managed_dependencies(engine.as_os_str(), &backup, true).unwrap();
        let arguments = fs::read_to_string(argv).unwrap();
        assert!(arguments.contains("valkey-cli --user nazoauth_backup --askpass"));
        assert!(!arguments.contains("VALKEYCLI_AUTH"));
        assert!(!arguments.contains("REDISCLI_AUTH"));
        assert!(!arguments.contains("secret-canary"));
    }

    #[test]
    fn managed_restore_journal_rejects_backend_drift() {
        let work = PrivateTempDir::new("managed-restore-journal-drift").unwrap();
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("SHA256SUMS"), b"placeholder\n").unwrap();
        let image = format!("postgres@sha256:{}", "a".repeat(64));
        let identity = managed_dependency_identity(
            "deployment-test",
            "controller-test",
            "runtime-test",
            "managed-network",
            "managed-postgres",
            "managed-postgres-data",
            &image,
            "oauth",
            "nazoauth_runtime",
            "managed-valkey",
            "managed-valkey-data",
            &format!("valkey@sha256:{}", "b".repeat(64)),
        );
        let (path, journal) =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap();
        super::persist_dependency_restore_journal(&path, &journal).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Podman", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
        let mut tampered = journal.clone();
        tampered.deployment_id = "other-deployment".to_owned();
        super::persist_dependency_restore_journal(&path, &tampered).unwrap();
        let error =
            super::load_dependency_restore_journal(&backup, "Docker", &identity).unwrap_err();
        assert!(error.to_string().contains("not bound"));
    }

    #[test]
    fn managed_container_surface_rejects_extra_mounts_and_environment() {
        let policy = super::ContainerRuntimePolicy::managed_default();
        let tmpfs = serde_json::json!({
            "/tmp": "rw,noexec,nosuid,nodev,size=67108864",
            "/run/postgresql": "rw,noexec,nosuid,nodev,size=16777216"
        });
        for (extra_mount, extra_env, expected_error) in [
            (true, false, "undeclared mount"),
            (false, true, "undeclared environment"),
        ] {
            let work = PrivateTempDir::new("managed-container-surface").unwrap();
            let engine = work.path().join("fake-engine");
            let mut mounts = vec![serde_json::json!({
                "Destination": "/data",
                "RW": true,
                "Source": "managed-data"
            })];
            if extra_mount {
                mounts.push(serde_json::json!({
                    "Destination": "/unexpected",
                    "RW": true,
                    "Source": "unexpected"
                }));
            }
            let mut environment = vec!["POSTGRES_DB=oauth", "PATH=/usr/local/bin"];
            if extra_env {
                environment.push("UNDECLARED=value");
            }
            let document = serde_json::json!({
                "HostConfig": {
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "ReadonlyRootfs": true,
                    "SecurityOpt": ["no-new-privileges"],
                    "CapDrop": ["ALL"],
                    "PidsLimit": 512,
                    "Memory": 1073741824_i64,
                    "NanoCpus": 2000000000_i64,
                    "Tmpfs": tmpfs.clone(),
                },
                "NetworkSettings": {"Networks": {"managed-network": {}}},
                "Mounts": mounts,
                "Config": {"Env": environment},
            });
            write_shell_executable(&engine, &format!("printf '%s\\n' '{}'", document));
            let error = super::assert_managed_container_policy(
                engine.as_os_str(),
                &["container", "inspect", "managed"],
                "Docker",
                &policy,
                "managed-network",
                &[("/data", false, Some("managed-data"))],
                &[("POSTGRES_DB", "oauth")],
                &std::collections::BTreeMap::from([(
                    "PATH".to_owned(),
                    "/usr/local/bin".to_owned(),
                )]),
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn oci_backup_completion_and_artifact_digests_are_bound() {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};

        let work = PrivateTempDir::new("oci-backup-completion-bound").unwrap();
        if fs::metadata(work.path()).unwrap().uid() != 0 {
            return;
        }
        let backup = work.path().join("backup");
        fs::create_dir(&backup).unwrap();
        chown(&backup, Some(0), Some(10001)).unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o750)).unwrap();
        let payload = backup.join("payload");
        fs::write(&payload, b"payload").unwrap();
        let digest = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let payload_digest = digest(b"payload");
        fs::write(
            backup.join("SHA256SUMS"),
            format!("{payload_digest}  payload\n"),
        )
        .unwrap();
        let manifest_bytes = fs::read(backup.join("SHA256SUMS")).unwrap();
        let manifest_digest = digest(&manifest_bytes);
        fs::write(
            backup.join("BACKUP-COMPLETE"),
            format!("marker=BACKUP-COMPLETE\nversion=1\nmanifest-sha256={manifest_digest}\n"),
        )
        .unwrap();
        for name in ["payload", "SHA256SUMS", "BACKUP-COMPLETE"] {
            let path = backup.join(name);
            chown(&path, Some(0), Some(10001)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        }
        let marker_digest = digest(&fs::read(backup.join("BACKUP-COMPLETE")).unwrap());
        super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest).unwrap();
        fs::write(&payload, b"tampered").unwrap();
        let error = super::verify_oci_backup_artifacts(&backup, &manifest_digest, &marker_digest)
            .unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }
}

pub(crate) fn append_mounts(mut command: Process, mounts: &[NeutralMount]) -> Process {
    for mount in mounts {
        let access = if mount.read_only { "ro" } else { "rw" };
        let relabel = if mount.selinux_relabel { ",Z" } else { "" };
        command = command.arg("--volume").arg(format!(
            "{}:{}:{access}{relabel}",
            mount.source.display(),
            mount.destination.display()
        ));
    }
    command
}

pub(crate) fn one_shot_process(
    command: &OsStr,
    task: &OneShotTask,
    backend_name: &str,
) -> anyhow::Result<Process> {
    let super::ArtifactReference::Oci {
        image_reference,
        digest,
    } = &task.artifact
    else {
        bail!("{backend_name} one-shot task requires a digest-bound OCI artifact");
    };
    let image = normalize_local_image_id(image_reference, false).unwrap_or_else(|| {
        format!(
            "{}@{}",
            image_reference.split('@').next().unwrap_or(image_reference),
            digest
        )
    });
    let user = task
        .service_user
        .as_deref()
        .context("OCI one-shot task requires an explicit non-root UID:GID")?;
    validate_non_root_user(user, backend_name)?;
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    let mut process = append_container_policy(
        Process::new(command)
            .timeout(Duration::from_secs(300))
            .args(["run", "--rm", "--interactive"]),
        &policy,
    )
    .arg("--user")
    .arg(user)
    .arg("--network")
    .arg(task.network.as_deref().unwrap_or("none"));
    if let Some(directory) = &task.working_directory {
        process = process.arg("--workdir").arg(directory);
    }
    for (name, value) in &task.environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    Ok(append_mounts(process, &task.mounts)
        .arg(image)
        .args(&task.command))
}

/// Start a hardened one-shot container command before any caller-controlled
/// engine options or image reference are appended.
///
/// Taking the engine binary rather than a partially assembled `Process`
/// makes it impossible to append policy flags after the image positional.
pub(crate) fn build_identity_process(command: &OsStr) -> Process {
    let mut policy = ContainerRuntimePolicy::managed_default();
    policy.restart = ContainerRestartPolicy::No;
    append_container_policy(Process::new(command).args(["run", "--rm"]), &policy)
        .arg("--user")
        .arg(NON_ROOT_ONE_SHOT_USER)
}

fn validate_non_root_user(user: &str, backend_name: &str) -> anyhow::Result<()> {
    let Some((uid, gid)) = user.split_once(':') else {
        bail!("{backend_name} one-shot user must be an explicit UID:GID");
    };
    if uid.is_empty()
        || gid.is_empty()
        || !uid.chars().all(|value| value.is_ascii_digit())
        || !gid.chars().all(|value| value.is_ascii_digit())
        || uid.parse::<u32>().ok().is_none_or(|value| value == 0)
        || gid.parse::<u32>().ok().is_none_or(|value| value == 0)
    {
        bail!("{backend_name} one-shot user must be a non-root UID:GID");
    }
    Ok(())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

pub(crate) fn requested_digest_matches(image_reference: &str, digest: &str) -> bool {
    let Some((_, requested)) = image_reference.rsplit_once('@') else {
        return true;
    };
    requested.eq_ignore_ascii_case(digest)
}

/// Normalize an engine's local image identity.  Docker emits `sha256:...`;
/// Podman may emit the same digest without the algorithm prefix.
pub fn normalize_local_image_id(value: &str, allow_bare_digest: bool) -> Option<String> {
    if allow_bare_digest {
        let digest = value.strip_prefix("sha256:").unwrap_or(value);
        return (digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        .then(|| format!("sha256:{}", digest.to_ascii_lowercase()));
    }
    let normalized = value.to_ascii_lowercase();
    valid_digest(&normalized).then_some(normalized)
}

#[cfg(test)]
mod policy_tests {
    use super::{
        ContainerRestartPolicy, ContainerRuntimePolicy, NON_ROOT_ONE_SHOT_USER,
        requested_digest_matches, validate_non_root_user,
    };

    #[test]
    fn requested_digest_cannot_be_replaced_by_another_repo_digest() {
        let image = "registry.example/nazoauth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(requested_digest_matches(
            image,
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!requested_digest_matches(
            image,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(requested_digest_matches(
            "registry.example/nazoauth:stable",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[test]
    fn one_shot_user_contract_rejects_root_and_names() {
        assert!(validate_non_root_user(NON_ROOT_ONE_SHOT_USER, "Docker").is_ok());
        assert!(validate_non_root_user("0:0", "Docker").is_err());
        assert!(validate_non_root_user("nobody", "Docker").is_err());
        assert!(validate_non_root_user("65532", "Docker").is_err());
    }

    #[test]
    fn managed_policy_has_explicit_resource_and_restart_bounds() {
        let policy = ContainerRuntimePolicy::managed_default();
        assert_eq!(policy.restart, ContainerRestartPolicy::UnlessStopped);
        assert!(policy.read_only_root);
        assert!(policy.no_new_privileges);
        assert!(policy.drop_all_capabilities);
        assert_eq!(policy.pids_limit, Some(512));
        assert_eq!(policy.memory_limit_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(policy.cpu_limit_millis, Some(2_000));
        assert_eq!(policy.tmpfs.len(), 2);
        assert_eq!(
            policy.tmpfs[1].destination,
            std::path::Path::new("/run/postgresql")
        );
    }
}
