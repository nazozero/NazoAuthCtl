//! Shared OCI container policy, inspect, and surface-validation primitives.
//!
//! Engine-specific command dialects stay in their backend modules; this module
//! owns the common policy and fail-closed object-surface checks.

use std::ffi::OsStr;

use crate::process::Process;
use anyhow::{Context as _, bail};

use super::super::{ContainerRestartPolicy, ContainerRuntimePolicy};

const ENGINE_FIXED_MOUNT_DESTINATIONS: &[&str] =
    &["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"];
const ENGINE_FIXED_ENV_NAMES: &[&str] = &["HOSTNAME", "HOME", "TERM", "LC_ALL", "container"];

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

/// Compare the engine-reported image reference before touching a managed
/// container.  The image reference is expected to be digest-pinned by the
/// install/recovery policy; accepting a tag or an unavailable inspect field
/// would turn the labels back into the only trust boundary.
pub(crate) fn assert_container_image(
    document: &serde_json::Value,
    expected_image: &str,
    backend_name: &str,
) -> anyhow::Result<()> {
    let expected_digest = expected_image
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .filter(|digest| super::valid_digest(digest))
        .with_context(|| format!("{backend_name} managed dependency image is not digest-pinned"))?;
    let mut actual = [
        document.pointer("/Config/Image"),
        document.get("ImageName"),
        document.pointer("/Config/ImageName"),
    ]
    .into_iter()
    .flatten()
    .chain(
        document
            .get("RepoDigests")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten(),
    )
    .filter_map(serde_json::Value::as_str);
    if actual.any(|value| {
        value == expected_image
            || value == expected_digest
            || value
                .rsplit_once('@')
                .is_some_and(|(_, digest)| digest == expected_digest)
    }) {
        return Ok(());
    }
    bail!("refusing to manage a {backend_name} container whose immutable image does not match")
}

pub(crate) fn image_environment(
    document: &serde_json::Value,
) -> anyhow::Result<std::collections::BTreeMap<&str, &str>> {
    let values = document
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .context("managed image inspect omitted environment")?;
    let mut environment = std::collections::BTreeMap::new();
    for value in values.iter().filter_map(serde_json::Value::as_str) {
        let (name, value) = value
            .split_once('=')
            .context("managed image contains an invalid environment entry")?;
        if name.is_empty() || environment.insert(name, value).is_some() {
            bail!("managed image environment is ambiguous");
        }
    }
    Ok(environment)
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
    let value = match parsed {
        serde_json::Value::Array(mut values) if !values.is_empty() => values.swap_remove(0),
        value => value,
    };
    Ok(Some(value))
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
    document: &serde_json::Value,
    backend_name: &str,
    policy: &ContainerRuntimePolicy,
    expected_network: &str,
    expected_mounts: &[(&str, bool, Option<&str>)],
    expected_environment: &[(&str, &str)],
    image_environment: &std::collections::BTreeMap<&str, &str>,
) -> anyhow::Result<()> {
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
        let observed_user = object_member_case_insensitive(document, "config")
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
                    || value
                        .split_once('=')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case("no-new-privileges"))
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
        .map(|tmpfs| tmpfs.destination.to_string_lossy())
        .collect::<std::collections::BTreeSet<_>>();
    if observed_tmpfs.len() != expected_tmpfs.len()
        || !expected_tmpfs
            .iter()
            .all(|destination| observed_tmpfs.contains_key(destination.as_ref()))
    {
        bail!("{backend_name} managed container tmpfs surface drifted");
    }
    for tmpfs in &policy.tmpfs {
        let destination = tmpfs.destination.to_string_lossy();
        let observed = observed_tmpfs.get(destination.as_ref());
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
        .map(|(destination, _, _)| *destination)
        .collect::<std::collections::BTreeSet<_>>();
    expected_destinations.extend(
        expected_tmpfs
            .iter()
            .map(|destination| destination.as_ref()),
    );
    for mount in mounts {
        let destination = mount
            .get("Destination")
            .and_then(serde_json::Value::as_str)
            .context("container inspect returned a mount without a destination")?;
        if !expected_destinations.contains(destination)
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
        if observed_environment.insert(name, value).is_some() {
            bail!("{backend_name} managed container environment is ambiguous");
        }
        if !expected_names.contains(name)
            && !ENGINE_FIXED_ENV_NAMES.contains(&name)
            && image_environment.get(name).copied() != Some(value)
        {
            bail!("{backend_name} managed container contains an undeclared environment variable");
        }
        let normalized_name = name.to_ascii_uppercase();
        if (normalized_name.contains("PASSWORD") || normalized_name.contains("SECRET"))
            && !expected_names.contains(name)
        {
            bail!(
                "{backend_name} managed container contains an unauthorized secret environment variable"
            );
        }
    }
    for (name, expected) in image_environment {
        if expected_names.contains(name) || ENGINE_FIXED_ENV_NAMES.contains(name) {
            continue;
        }
        if observed_environment.get(name).copied() != Some(*expected) {
            bail!("{backend_name} managed container image environment drifted");
        }
    }
    for (name, expected) in expected_environment {
        let observed = observed_environment.get(name).copied();
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
            let mut upper = value.to_ascii_uppercase();
            if upper.starts_with("CAP_") {
                upper.drain(..4);
            }
            upper
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
            && [('/', "/_data"), ('\\', "\\_data")]
                .into_iter()
                .any(|(separator, suffix)| {
                    observed
                        .strip_suffix(suffix)
                        .and_then(|parent| parent.rsplit_once(separator))
                        .is_some_and(|(_, name)| name == expected)
                }))
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

fn object_member_case_insensitive<'a>(
    value: &'a serde_json::Value,
    expected: &str,
) -> Option<&'a serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(expected).then_some(value))
}

/// Fresh creation must not remove a name that appeared after admission. Updates
/// remove only a stopped, deployment-owned object by its immutable engine ID.
pub(crate) fn remove_replacement_source(
    command: &OsStr,
    replacement: &super::super::RuntimeReplacement,
    backend_name: &str,
) -> anyhow::Result<()> {
    let Some(document) = inspect_document_optional(
        command,
        &["container", "inspect", &replacement.object_reference],
        backend_name,
    )?
    else {
        return Ok(());
    };
    let expected = replacement
        .labels
        .get("io.nazoauth.deployment-id")
        .context("replacement has no deployment ownership")?;
    if document
        .pointer("/Config/Labels/io.nazoauth.deployment-id")
        .and_then(serde_json::Value::as_str)
        != Some(expected.as_str())
    {
        bail!("replacement source belongs to a different deployment");
    }
    if document
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        bail!("replacement source is not confirmed stopped");
    }
    let id = document
        .get("Id")
        .or_else(|| document.get("ID"))
        .and_then(serde_json::Value::as_str)
        .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .context("replacement source has no immutable container ID")?;
    // No --force: a runtime restarted after inspection must not be killed.
    Process::new(command).args(["rm", id]).run_quiet()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_index_preserves_declared_image_and_duplicate_rules() {
        let policy = ContainerRuntimePolicy::managed_default();
        let image = std::collections::BTreeMap::from([("PATH", "/bin"), ("MODE", "image-default")]);
        for (env, error) in [
            (
                vec!["PATH=/bin", "MODE=managed", "API_SECRET=approved"],
                None,
            ),
            (
                vec![
                    "PATH=/bin",
                    "MODE=managed",
                    "MODE=managed",
                    "API_SECRET=approved",
                ],
                Some("ambiguous"),
            ),
            (
                vec!["PATH=/other", "MODE=managed", "API_SECRET=approved"],
                Some("undeclared environment"),
            ),
            (
                vec!["PATH=/bin", "MODE=image-default", "API_SECRET=approved"],
                Some("environment policy drifted"),
            ),
            (
                vec!["MODE=managed", "API_SECRET=approved"],
                Some("image environment drifted"),
            ),
            (
                vec!["PATH=/bin", "MODE=managed"],
                Some("environment policy drifted"),
            ),
        ] {
            let document = serde_json::json!({
                "HostConfig": {
                    "RestartPolicy": {"Name":"unless-stopped"},
                    "ReadonlyRootfs":true, "SecurityOpt":["no-new-privileges"],
                    "CapDrop":["ALL"], "PidsLimit":512, "Memory":1073741824_i64,
                    "NanoCpus":2000000000_i64,
                    "Tmpfs":{
                        "/tmp":"rw,noexec,nosuid,nodev,size=67108864",
                        "/run/postgresql":"rw,noexec,nosuid,nodev,size=16777216"
                    }
                },
                "NetworkSettings":{"Networks":{"managed":{}}},
                "Mounts":[], "Config":{"Env":env}
            });
            let result = assert_managed_container_policy(
                &document,
                "test",
                &policy,
                "managed",
                &[],
                &[("MODE", "managed"), ("API_SECRET", "approved")],
                &image,
            );
            match error {
                Some(error) => assert!(result.unwrap_err().to_string().contains(error)),
                None => result.unwrap(),
            }
        }
    }

    #[test]
    fn image_identity_accepts_each_inspect_field_only_for_the_expected_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = format!("registry.example/image@{digest}");
        let alternate = format!("mirror.example/image@{digest}");
        for document in [
            serde_json::json!({"Config":{"Image":reference}}),
            serde_json::json!({"Config":{"Image":digest}}),
            serde_json::json!({"ImageName":alternate}),
            serde_json::json!({"Config":{"ImageName":alternate}}),
            serde_json::json!({"RepoDigests":["invalid",alternate]}),
        ] {
            assert_container_image(&document, &reference, "test").unwrap();
            assert!(assert_container_image(&document, "image:tag", "test").is_err());
            assert!(assert_container_image(&document, "image@sha256:short", "test").is_err());
        }
        let wrong = serde_json::json!({"ImageName":format!("image@sha256:{}", "b".repeat(64))});
        assert!(assert_container_image(&wrong, &reference, "test").is_err());
    }
}
