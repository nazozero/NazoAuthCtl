//! Recover-only OCI candidate staging.
//!
//! This is intentionally narrower than ordinary runtime replacement. It can
//! consume only one stopped, identity-matched NazoAuth container and emits one
//! hardened candidate with three mounts, one existing non-host network, and a
//! single IPv4-loopback port binding.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    net::TcpListener,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, bail, ensure};
use uuid::Uuid;

use crate::process::Process;

use super::{append_container_policy, append_mounts, inspect_document, inspect_document_optional};
use crate::runtime_backend::{
    ArtifactReference, NeutralMount, RecoveryCandidateEndpoint, RecoveryCandidateRequest,
    ResourceScope, Responsibility,
};

const DEPLOYMENT_LABEL: &str = "io.nazoauth.deployment-id";
const RECOVERY_OPERATION_LABEL: &str = "io.nazoauth.recovery-operation-id";
const CONTAINER_DATA_DIR: &str = "/var/lib/nazo_oauth";
const CONTAINER_SECRETS_DIR: &str = "/run/secrets";
const CONTAINER_CONFIG_FILE: &str = "/app/.env.yaml";
const SERVER_CONFIG_FILE_ENV: &str = "NAZOAUTH_SERVER_CONFIG_FILE";
const CANDIDATE_PORT: &str = "8000/tcp";

pub(crate) fn stage_recovery_candidate(
    command: &OsStr,
    backend_name: &str,
    source_mounts: &[NeutralMount],
    source_document: &serde_json::Value,
    request: &RecoveryCandidateRequest,
    add_docker_host_gateway: bool,
    rootless_podman: bool,
) -> anyhow::Result<RecoveryCandidateEndpoint> {
    validate_request(request)?;
    let source_id = source_document
        .get("Id")
        .or_else(|| source_document.get("ID"))
        .and_then(serde_json::Value::as_str)
        .context("recovery source inspect omitted immutable id")?;
    let source_name = source_document
        .get("Name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(source_id)
        .trim_start_matches('/');
    ensure!(
        source_name == request.source_object_reference,
        "{backend_name} recovery source identity changed during inspection"
    );
    assert_server_command(source_document, backend_name)?;
    // Only the stopped source's network and mounts are needed. The snapshot
    // artifact below owns the candidate image, so do not resolve the source image.
    let mut environment = super::super::safe_environment(
        source_document
            .pointer("/Config/Env")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    ensure!(
        environment.get("DEPLOYMENT_ID") == Some(&request.deployment_id),
        "{backend_name} recovery source environment identity differs"
    );
    let networks = source_document
        .pointer("/NetworkSettings/Networks")
        .and_then(serde_json::Value::as_object)
        .context("recovery source inspect omitted networks")?;
    ensure!(
        networks.len() == 1,
        "{backend_name} recovery source must have exactly one required network"
    );
    let network = networks.keys().next().expect("one network").as_str();
    ensure!(
        !network.is_empty()
            && !network.eq_ignore_ascii_case("host")
            && !network.eq_ignore_ascii_case("none")
            && !network.to_ascii_lowercase().starts_with("container:"),
        "{backend_name} recovery source uses an unsafe network namespace"
    );
    assert_source_surface(source_document, backend_name, request)?;

    let mounts = recovery_mounts(source_mounts, request)?;
    environment.insert("DATA_DIR".to_owned(), CONTAINER_DATA_DIR.to_owned());
    environment.insert(
        SERVER_CONFIG_FILE_ENV.to_owned(),
        CONTAINER_CONFIG_FILE.to_owned(),
    );
    environment.insert("BIND".to_owned(), "0.0.0.0:8000".to_owned());
    environment.insert(
        "VALKEY_STATE_EPOCH".to_owned(),
        request.valkey_state_epoch.clone(),
    );

    let image = recovery_image(&request.artifact)?;
    let policy = super::super::ContainerRuntimePolicy::recovery_candidate();
    if let Some(candidate_document) = inspect_document_optional(
        command,
        &["container", "inspect", &request.candidate_object_reference],
        backend_name,
    )? {
        let endpoint = endpoint_from_document(&candidate_document, request, backend_name)?;
        assert_candidate_surface(
            command,
            backend_name,
            &candidate_document,
            request,
            network,
            &mounts,
            &environment,
            &image,
            &policy,
        )
        .context("pre-existing recovery candidate does not match this operation")?;
        return Ok(endpoint);
    }

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("failed to reserve a recovery loopback port")?;
    let loopback_port = listener.local_addr()?.port();
    let process = Process::new(command)
        .args(["run", "-d", "--name"])
        .arg(&request.candidate_object_reference);
    let process = if rootless_podman {
        process.arg("--userns=keep-id:uid=10001,gid=10001")
    } else {
        process
    };
    let mut process = append_container_policy(process, &policy);
    if add_docker_host_gateway {
        process = process.args(["--add-host", "host.docker.internal:host-gateway"]);
    }
    process = process
        .arg("--label")
        .arg(format!("{DEPLOYMENT_LABEL}={}", request.deployment_id))
        .arg("--label")
        .arg(format!(
            "{RECOVERY_OPERATION_LABEL}={}",
            request.operation_id
        ));
    for (name, value) in &environment {
        process = process.arg("--env").arg(format!("{name}={value}"));
    }
    let runtime_network = if rootless_podman && network == "pasta" {
        "pasta:--map-gw"
    } else {
        network
    };
    process = process
        .arg("--network")
        .arg(runtime_network)
        .arg("--publish")
        .arg(format!("127.0.0.1:{loopback_port}:{CANDIDATE_PORT}"));
    // Keep the reservation until the fully constrained engine argv exists.
    // The engine must bind the selected port, so release it immediately
    // before spawn rather than leaving a broad retry/fallback surface.
    drop(listener);
    append_mounts(process, &mounts)
        .arg(&image)
        .args(["nazoauth", "server"])
        .run_quiet()
        .with_context(|| format!("failed to start {backend_name} recovery candidate"))?;

    let candidate_document = inspect_document(
        command,
        &["container", "inspect", &request.candidate_object_reference],
        backend_name,
    )?;
    let endpoint = endpoint_from_document(&candidate_document, request, backend_name)?;
    ensure!(
        endpoint.loopback_port == loopback_port,
        "{backend_name} recovery engine published an unexpected host port"
    );
    if let Err(error) = assert_candidate_surface(
        command,
        backend_name,
        &candidate_document,
        request,
        network,
        &mounts,
        &environment,
        &image,
        &policy,
    ) {
        return match cleanup_recovery_candidate(command, backend_name, &endpoint) {
            Ok(()) => Err(error.context("recovery candidate failed closed and was removed")),
            Err(cleanup) => Err(error.context(format!(
                "recovery candidate validation failed and exact cleanup also failed: {cleanup}"
            ))),
        };
    }
    Ok(endpoint)
}

fn endpoint_from_document(
    document: &serde_json::Value,
    request: &RecoveryCandidateRequest,
    backend_name: &str,
) -> anyhow::Result<RecoveryCandidateEndpoint> {
    let object_id = document
        .get("Id")
        .or_else(|| document.get("ID"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("recovery candidate inspect omitted immutable id")?
        .to_owned();
    let bindings = observed_port_bindings(document, backend_name)?;
    let (container_port, host_ip, loopback_port) = bindings
        .iter()
        .next()
        .context("recovery candidate has no loopback binding")?;
    ensure!(
        bindings.len() == 1 && container_port == CANDIDATE_PORT && host_ip == "127.0.0.1",
        "{backend_name} recovery candidate does not have one exact loopback binding"
    );
    Ok(RecoveryCandidateEndpoint {
        object_reference: request.candidate_object_reference.clone(),
        object_id,
        deployment_id: request.deployment_id.clone(),
        operation_id: request.operation_id.clone(),
        loopback_port: *loopback_port,
        https: request.https,
    })
}

pub(crate) fn cleanup_recovery_candidate(
    command: &OsStr,
    backend_name: &str,
    endpoint: &RecoveryCandidateEndpoint,
) -> anyhow::Result<()> {
    validate_endpoint(endpoint)?;
    let Some(document) = inspect_document_optional(
        command,
        &["container", "inspect", &endpoint.object_id],
        backend_name,
    )?
    else {
        return Ok(());
    };
    let observed_id = document
        .get("Id")
        .or_else(|| document.get("ID"))
        .and_then(serde_json::Value::as_str)
        .context("recovery candidate cleanup inspect omitted immutable id")?;
    ensure!(
        observed_id == endpoint.object_id,
        "{backend_name} recovery candidate immutable id changed"
    );
    let labels = document
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .context("recovery candidate cleanup inspect omitted labels")?;
    ensure!(
        labels
            .get(DEPLOYMENT_LABEL)
            .and_then(serde_json::Value::as_str)
            == Some(endpoint.deployment_id.as_str())
            && labels
                .get(RECOVERY_OPERATION_LABEL)
                .and_then(serde_json::Value::as_str)
                == Some(endpoint.operation_id.as_str()),
        "{backend_name} recovery candidate cleanup identity differs"
    );
    Process::new(command)
        .args(["rm", "--force", &endpoint.object_id])
        .run_quiet()
        .with_context(|| format!("failed to remove exact {backend_name} recovery candidate"))
}

fn validate_request(request: &RecoveryCandidateRequest) -> anyhow::Result<()> {
    validate_token(
        &request.source_object_reference,
        "recovery source object",
        256,
    )?;
    validate_token(
        &request.candidate_object_reference,
        "recovery candidate object",
        256,
    )?;
    ensure!(
        request.source_object_reference != request.candidate_object_reference,
        "recovery candidate must not replace the deployment runtime"
    );
    validate_token(&request.deployment_id, "recovery deployment id", 128)?;
    validate_uuid_v7(&request.operation_id, "recovery operation id")?;
    validate_token(&request.valkey_state_epoch, "Valkey state epoch", 128)?;
    for (path, label) in [
        (&request.data_source, "recovery data source"),
        (&request.secrets_source, "recovery secrets source"),
        (&request.config_source, "recovery config source"),
    ] {
        validate_absolute_path(path, label)?;
    }
    Ok(())
}

fn validate_endpoint(endpoint: &RecoveryCandidateEndpoint) -> anyhow::Result<()> {
    validate_token(&endpoint.object_reference, "recovery candidate object", 256)?;
    validate_token(&endpoint.object_id, "recovery candidate immutable id", 256)?;
    validate_token(&endpoint.deployment_id, "recovery deployment id", 128)?;
    validate_uuid_v7(&endpoint.operation_id, "recovery operation id")?;
    ensure!(
        endpoint.loopback_port != 0,
        "recovery candidate loopback port is invalid"
    );
    Ok(())
}

fn validate_token(value: &str, label: &str, maximum: usize) -> anyhow::Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= maximum
            && !value.starts_with('-')
            && !value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()),
        "{label} is invalid"
    );
    Ok(())
}

fn validate_uuid_v7(value: &str, label: &str) -> anyhow::Result<()> {
    let parsed = Uuid::parse_str(value).with_context(|| format!("{label} is not a UUID"))?;
    ensure!(parsed.get_version_num() == 7, "{label} must be UUIDv7");
    Ok(())
}

fn validate_absolute_path(path: &Path, label: &str) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute()
            && path.parent().is_some()
            && !path
                .components()
                .any(|component| { matches!(component, Component::ParentDir | Component::CurDir) })
            && !path
                .to_string_lossy()
                .chars()
                .any(|character| character.is_control()),
        "{label} must be a normalized absolute non-root path"
    );
    Ok(())
}

fn recovery_image(artifact: &ArtifactReference) -> anyhow::Result<String> {
    let ArtifactReference::Oci {
        image_reference,
        digest,
    } = artifact
    else {
        bail!("recovery container candidate requires an OCI artifact");
    };
    let encoded = digest
        .strip_prefix("sha256:")
        .context("recovery OCI artifact digest must use sha256")?;
    ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && !image_reference.is_empty()
            && !image_reference
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()),
        "recovery OCI artifact reference is invalid"
    );
    Ok(format!(
        "{}@{}",
        image_reference.split('@').next().unwrap_or(image_reference),
        digest
    ))
}

fn recovery_mounts(
    source_mounts: &[NeutralMount],
    request: &RecoveryCandidateRequest,
) -> anyhow::Result<Vec<NeutralMount>> {
    let mut replacements = vec![
        (
            Path::new(CONTAINER_DATA_DIR),
            request.data_source.clone(),
            false,
        ),
        (
            Path::new(CONTAINER_CONFIG_FILE),
            request.config_source.clone(),
            true,
        ),
    ];
    let mut secret_names = std::collections::BTreeSet::new();
    for mount in source_mounts {
        if let Ok(relative) = mount.destination.strip_prefix(CONTAINER_SECRETS_DIR) {
            let name = relative
                .to_str()
                .context("runtime secret destination is not UTF-8")?;
            ensure!(
                crate::runtime_backend::RUNTIME_SECRET_NAMES.contains(&name)
                    && secret_names.insert(name),
                "recovery source has an unknown or duplicate secret mount"
            );
        }
    }
    for mount in source_mounts
        .iter()
        .filter(|mount| mount.destination.parent() == Some(Path::new(CONTAINER_SECRETS_DIR)))
    {
        let name = mount
            .destination
            .file_name()
            .context("recovery source secret mount has no file name")?;
        let destination = mount.destination.as_path();
        replacements.push((destination, request.secrets_source.join(name), true));
    }
    let mut mounts = replacements
        .into_iter()
        .map(|(destination, replacement, read_only)| {
            let mut matching = source_mounts
                .iter()
                .filter(|mount| mount.destination == destination);
            let original = matching.next().with_context(|| {
                format!("recovery source has no {} mount", destination.display())
            })?;
            ensure!(
                matching.next().is_none(),
                "recovery source has duplicate {} mounts",
                destination.display()
            );
            Ok(NeutralMount {
                source: replacement,
                destination: PathBuf::from(destination),
                read_only,
                selinux_relabel: original.selinux_relabel,
                ownership: Responsibility::External,
                scope: ResourceScope::Deployment,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        request.tls_files.len() <= 3,
        "too many recovery TLS file settings"
    );
    for path in &request.tls_files {
        // These are Linux container paths even when the controller runs on Windows.
        let text = path.to_str().context("recovery TLS path is not UTF-8")?;
        ensure!(
            text.starts_with('/') && !text.split('/').any(|part| matches!(part, "." | "..")),
            "recovery TLS file must use an absolute container path without traversal"
        );
        let mut matching = source_mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.destination));
        let original = matching
            .next()
            .context("recovery TLS file has no existing mount")?;
        ensure!(
            original.read_only && matching.next().is_none(),
            "recovery TLS file must be covered by exactly one existing read-only mount"
        );
        if !mounts
            .iter()
            .any(|mount| mount.destination == original.destination)
        {
            let mut retained = original.clone();
            retained.ownership = Responsibility::External;
            mounts.push(retained);
        }
    }
    Ok(mounts)
}

fn assert_source_surface(
    document: &serde_json::Value,
    backend_name: &str,
    request: &RecoveryCandidateRequest,
) -> anyhow::Result<()> {
    let running = document
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .context("recovery source inspect omitted running state")?;
    ensure!(!running, "{backend_name} recovery source is still running");
    let labels = document
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .context("recovery source inspect omitted labels")?;
    ensure!(
        labels
            .get(DEPLOYMENT_LABEL)
            .and_then(serde_json::Value::as_str)
            == Some(request.deployment_id.as_str()),
        "{backend_name} recovery source deployment label differs"
    );
    assert_no_dangerous_runtime_attributes(document, backend_name)
}

#[allow(clippy::too_many_arguments)]
fn assert_candidate_surface(
    command: &OsStr,
    backend_name: &str,
    document: &serde_json::Value,
    request: &RecoveryCandidateRequest,
    network: &str,
    mounts: &[NeutralMount],
    environment: &BTreeMap<String, String>,
    image: &str,
    policy: &super::super::ContainerRuntimePolicy,
) -> anyhow::Result<()> {
    assert_no_dangerous_runtime_attributes(document, backend_name)?;
    assert_server_command(document, backend_name)?;
    let running = document
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .context("recovery candidate inspect omitted running state")?;
    ensure!(running, "{backend_name} recovery candidate is not running");
    let labels = document
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .context("recovery candidate inspect omitted labels")?;
    let image_document = inspect_document(command, &["image", "inspect", image], backend_name)?;
    let mut expected_labels = image_labels(&image_document)?;
    ensure!(
        expected_labels
            .keys()
            .all(|name| !is_public_ingress_label(name)),
        "{backend_name} recovery artifact carries a public ingress label"
    );
    expected_labels.insert(DEPLOYMENT_LABEL, &request.deployment_id);
    expected_labels.insert(RECOVERY_OPERATION_LABEL, &request.operation_id);
    ensure!(
        labels.len() == expected_labels.len()
            && expected_labels.iter().all(|(name, value)| {
                labels.get(*name).and_then(serde_json::Value::as_str) == Some(*value)
            }),
        "{backend_name} recovery candidate labels differ from artifact metadata and recovery identity"
    );
    let expected_mounts = mounts
        .iter()
        .map(|mount| {
            (
                mount.destination.to_string_lossy(),
                mount.read_only,
                mount.source.to_string_lossy(),
            )
        })
        .collect::<Vec<_>>();
    let expected_mount_refs = expected_mounts
        .iter()
        .map(|(destination, read_only, source)| {
            (destination.as_ref(), *read_only, Some(source.as_ref()))
        })
        .collect::<Vec<_>>();
    let expected_environment = environment
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let image_environment = super::image_environment(&image_document)?;
    super::assert_container_image(document, image, backend_name)?;
    super::assert_managed_container_policy(
        document,
        backend_name,
        policy,
        network,
        &expected_mount_refs,
        &expected_environment,
        &image_environment,
    )
}

fn assert_server_command(document: &serde_json::Value, backend_name: &str) -> anyhow::Result<()> {
    let (executable, arguments) = if backend_name == "Docker" {
        (document.get("Path"), document.get("Args"))
    } else {
        let config = document
            .get("Config")
            .context("recovery candidate inspect omitted Config")?;
        (
            config.get("Entrypoint"),
            config.get("Command").or_else(|| config.get("Cmd")),
        )
    };
    ensure!(
        super::super::server_command_verified(
            executable
                .and_then(serde_json::Value::as_str)
                .into_iter()
                .chain(
                    arguments
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(serde_json::Value::as_str),
                ),
        ),
        "{backend_name} recovery runtime command is not the NazoAuth server"
    );
    Ok(())
}

fn image_labels(document: &serde_json::Value) -> anyhow::Result<BTreeMap<&str, &str>> {
    document
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .map(|(name, value)| {
                    value
                        .as_str()
                        .map(|value| (name.as_str(), value))
                        .context("recovery artifact contains a non-string label")
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn is_public_ingress_label(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("traefik.")
        || name.starts_with("caddy")
        || name.starts_with("nginx.")
        || name.contains("ingress")
        || name.contains("reverse-proxy")
}

fn assert_no_dangerous_runtime_attributes(
    document: &serde_json::Value,
    backend_name: &str,
) -> anyhow::Result<()> {
    let host = document
        .get("HostConfig")
        .context("container inspect omitted HostConfig")?;
    ensure!(
        !host
            .get("Privileged")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "{backend_name} recovery runtime cannot be privileged"
    );
    for field in [
        "PidMode",
        "IpcMode",
        "UTSMode",
        "CgroupnsMode",
        "UsernsMode",
    ] {
        let mode = host
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        ensure!(
            mode.is_empty()
                || mode.eq_ignore_ascii_case("private")
                || (field == "IpcMode" && mode.eq_ignore_ascii_case("shareable")),
            "{backend_name} recovery runtime has an extra {field} namespace"
        );
    }
    let network_mode = host
        .get("NetworkMode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    ensure!(
        !network_mode.eq_ignore_ascii_case("host")
            && !network_mode.to_ascii_lowercase().starts_with("container:"),
        "{backend_name} recovery runtime has an unsafe network namespace"
    );
    for field in ["CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules"] {
        let count = host
            .get(field)
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        ensure!(
            count == 0,
            "{backend_name} recovery runtime contains an extra dangerous {field} surface"
        );
    }
    Ok(())
}

fn observed_port_bindings(
    document: &serde_json::Value,
    backend_name: &str,
) -> anyhow::Result<BTreeSet<(String, String, u16)>> {
    let raw = document
        .pointer("/NetworkSettings/Ports")
        .and_then(serde_json::Value::as_object)
        .context("recovery candidate inspect omitted port bindings")?;
    let mut bindings = BTreeSet::new();
    for (container_port, values) in raw {
        let values = values
            .as_array()
            .with_context(|| format!("{backend_name} recovery port binding is invalid"))?;
        for value in values {
            let host_ip = value
                .get("HostIp")
                .and_then(serde_json::Value::as_str)
                .context("recovery candidate port binding omitted HostIp")?;
            let host_port = value
                .get("HostPort")
                .and_then(serde_json::Value::as_str)
                .context("recovery candidate port binding omitted HostPort")?
                .parse::<u16>()
                .context("recovery candidate HostPort is invalid")?;
            bindings.insert((container_port.clone(), host_ip.to_owned(), host_port));
        }
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_document(host_ip: &str, host_port: &str) -> serde_json::Value {
        serde_json::json!({
            "State": {"Running": true},
            "Config": {"Labels": {
                DEPLOYMENT_LABEL: "deploy-a",
                RECOVERY_OPERATION_LABEL: "018f47f3-7f55-7a10-8a88-64c5f904c001"
            }},
            "HostConfig": {
                "Privileged": false,
                "NetworkMode": "nazo-internal",
                "PidMode": "",
                "IpcMode": "",
                "UTSMode": "",
                "CgroupnsMode": "private",
                "UsernsMode": "",
                "CapAdd": [],
                "Devices": [],
                "DeviceRequests": [],
                "DeviceCgroupRules": []
            },
            "NetworkSettings": {"Ports": {"8000/tcp": [{
                "HostIp": host_ip,
                "HostPort": host_port
            }]}}
        })
    }

    #[cfg(unix)]
    #[test]
    fn candidate_validation_reads_image_labels_and_environment_once() -> anyhow::Result<()> {
        let work = crate::filesystem::PrivateTempDir::new("recovery-image-query")?;
        let command = work.path().join("engine");
        let calls = work.path().join("calls");
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = format!("example/nazo@{digest}");
        crate::test_support::write_shell_executable(
            &command,
            &format!(
                "[ \"$*\" = 'image inspect {image} --format {{{{json .}}}}' ] || exit 91\nprintf '%s\\n' inspect >> '{}'\nprintf '%s' '{{\"Config\":{{\"Labels\":{{\"org.opencontainers.image.title\":\"NazoAuth\"}},\"Env\":[\"PATH=/bin\"]}}}}'",
                calls.display()
            ),
        );
        let request = RecoveryCandidateRequest {
            source_object_reference: "live".into(),
            candidate_object_reference: "candidate".into(),
            deployment_id: "deploy-a".into(),
            operation_id: Uuid::now_v7().to_string(),
            artifact: ArtifactReference::Oci {
                image_reference: "example/nazo".into(),
                digest,
            },
            data_source: work.path().join("data"),
            secrets_source: work.path().join("secrets"),
            config_source: work.path().join("config"),
            valkey_state_epoch: Uuid::now_v7().to_string(),
            https: false,
            tls_files: Vec::new(),
        };
        let mut document = safe_document("127.0.0.1", "48123");
        document["Path"] = serde_json::json!("nazoauth");
        document["Args"] = serde_json::json!(["server"]);
        document["Config"]["Image"] = serde_json::json!(image);
        document["Config"]["Env"] = serde_json::json!(["PATH=/bin"]);
        document["Config"]["Labels"][RECOVERY_OPERATION_LABEL] =
            serde_json::json!(request.operation_id);
        document["Config"]["Labels"]["org.opencontainers.image.title"] =
            serde_json::json!("NazoAuth");
        document["NetworkSettings"]["Networks"] = serde_json::json!({"nazo-internal":{}});
        document["Mounts"] = serde_json::json!([]);
        let policy = super::super::super::ContainerRuntimePolicy::managed_default();
        let host = document["HostConfig"].as_object_mut().unwrap();
        for (name, value) in serde_json::json!({
            "RestartPolicy":{"Name":"unless-stopped"},
            "ReadonlyRootfs":true, "SecurityOpt":["no-new-privileges"],
            "CapDrop":["ALL"], "PidsLimit":512, "Memory":1073741824_i64,
            "NanoCpus":2000000000_i64,
            "Tmpfs":{
                "/tmp":"rw,noexec,nosuid,nodev,size=67108864",
                "/run/postgresql":"rw,noexec,nosuid,nodev,size=16777216"
            }
        })
        .as_object()
        .unwrap()
        {
            host.insert(name.clone(), value.clone());
        }
        assert_candidate_surface(
            command.as_os_str(),
            "Docker",
            &document,
            &request,
            "nazo-internal",
            &[],
            &BTreeMap::new(),
            &image,
            &policy,
        )?;
        assert_eq!(std::fs::read_to_string(&calls)?, "inspect\n");

        // Recovery only needs the old container's deployment surface. Its image
        // may no longer exist; resolving it must not be a recovery dependency.
        let mut source = document;
        source["Id"] = serde_json::json!("source-id");
        source["Name"] = serde_json::json!("/live");
        source["State"] = serde_json::json!({"Running":false});
        source["Config"]["Env"] = serde_json::json!(["DEPLOYMENT_ID=deploy-a"]);
        source["Config"]["Image"] = serde_json::json!("removed/source:old");
        source["Config"]["Labels"] = serde_json::json!({DEPLOYMENT_LABEL:"deploy-a"});
        source["Mounts"] = serde_json::json!([
            {"Source":"/live/data","Destination":CONTAINER_DATA_DIR,"RW":true},
            {"Source":"/live/config","Destination":CONTAINER_CONFIG_FILE,"RW":false}
        ]);
        std::fs::write(work.path().join("source.json"), source.to_string())?;
        std::fs::write(&calls, "")?;
        crate::test_support::write_shell_executable(
            &command,
            &format!(
                r#"printf '%s\n' "$*" >> '{}'
case "$*" in
 'container inspect live --format {{{{json .}}}}') cat '{}';;
 'container inspect candidate --format {{{{json .}}}}') echo 'candidate inspection stopped by test' >&2; exit 1;;
 *) echo 'unexpected command' >&2; exit 92;;
esac"#,
                calls.display(),
                work.path().join("source.json").display()
            ),
        );
        use crate::runtime_backend::RuntimeBackend as _;
        let error = crate::runtime_backend::DockerBackend::with_command(command)
            .stage_recovery_candidate(&request)
            .unwrap_err();
        assert_eq!(error.to_string(), "Docker object inspection failed");
        assert_eq!(
            std::fs::read_to_string(calls)?,
            "container inspect live --format {{json .}}\ncontainer inspect candidate --format {{json .}}\n"
        );
        Ok(())
    }

    #[test]
    fn recovery_port_proof_accepts_only_the_exact_ipv4_loopback_binding() {
        let safe = safe_document("127.0.0.1", "48123");
        assert_eq!(
            observed_port_bindings(&safe, "test").unwrap(),
            BTreeSet::from([("8000/tcp".to_owned(), "127.0.0.1".to_owned(), 48123)])
        );
        for address in ["0.0.0.0", "::", "::1", "127.0.0.2"] {
            let observed =
                observed_port_bindings(&safe_document(address, "48123"), "test").unwrap();
            assert_ne!(
                observed,
                BTreeSet::from([("8000/tcp".to_owned(), "127.0.0.1".to_owned(), 48123)])
            );
        }
    }

    #[test]
    fn recovery_runtime_rejects_privilege_capability_device_and_host_namespaces() {
        let mut document = safe_document("127.0.0.1", "48123");
        assert_no_dangerous_runtime_attributes(&document, "test").unwrap();
        *document.pointer_mut("/HostConfig/IpcMode").unwrap() = serde_json::json!("shareable");
        assert_no_dangerous_runtime_attributes(&document, "test").unwrap();
        *document.pointer_mut("/HostConfig/IpcMode").unwrap() = serde_json::json!("host");
        assert!(assert_no_dangerous_runtime_attributes(&document, "test").is_err());

        let mut document = safe_document("127.0.0.1", "48123");
        *document.pointer_mut("/HostConfig/Privileged").unwrap() = serde_json::json!(true);
        assert!(assert_no_dangerous_runtime_attributes(&document, "test").is_err());

        let mut document = safe_document("127.0.0.1", "48123");
        *document.pointer_mut("/HostConfig/NetworkMode").unwrap() = serde_json::json!("host");
        assert!(assert_no_dangerous_runtime_attributes(&document, "test").is_err());

        let mut document = safe_document("127.0.0.1", "48123");
        *document.pointer_mut("/HostConfig/CapAdd").unwrap() = serde_json::json!(["SYS_ADMIN"]);
        assert!(assert_no_dangerous_runtime_attributes(&document, "test").is_err());

        let mut document = safe_document("127.0.0.1", "48123");
        *document.pointer_mut("/HostConfig/Devices").unwrap() =
            serde_json::json!([{"PathOnHost": "/dev/sda"}]);
        assert!(assert_no_dangerous_runtime_attributes(&document, "test").is_err());
    }

    #[test]
    fn recovery_candidate_accepts_only_server_command_and_no_ingress_labels() {
        let docker = serde_json::json!({"Path": "nazoauth", "Args": ["server"]});
        assert_server_command(&docker, "Docker").unwrap();
        let podman = serde_json::json!({"Config": {"Command": ["nazoauth", "server"]}});
        assert_server_command(&podman, "Podman").unwrap();
        let wrong = serde_json::json!({"Path": "sh", "Args": ["-c", "nazoauth server"]});
        assert!(assert_server_command(&wrong, "Docker").is_err());

        for label in [
            "traefik.http.routers.nazo.rule",
            "caddy",
            "nginx.proxy-pass",
            "example.ingress.enabled",
            "reverse-proxy.route",
        ] {
            assert!(is_public_ingress_label(label), "{label}");
        }
        assert!(!is_public_ingress_label(
            "org.opencontainers.image.revision"
        ));
    }

    #[test]
    fn recovery_request_is_current_only_and_requires_three_absolute_sources() {
        let root = std::env::current_dir().unwrap().join("recovery-test");
        let request = RecoveryCandidateRequest {
            source_object_reference: "nazo-live".to_owned(),
            candidate_object_reference: "nazo-recovery".to_owned(),
            deployment_id: "deploy-a".to_owned(),
            operation_id: "018f47f3-7f55-7a10-8a88-64c5f904c001".to_owned(),
            artifact: ArtifactReference::Oci {
                image_reference: "example/nazo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            },
            data_source: root.join("data"),
            secrets_source: root.join("secrets"),
            config_source: root.join("config.yaml"),
            valkey_state_epoch: "018f47f3-7f55-7a10-8a88-64c5f904c002".to_owned(),
            https: false,
            tls_files: Vec::new(),
        };
        validate_request(&request).unwrap();
        let mut invalid = request.clone();
        invalid.config_source = PathBuf::from("relative/config.yaml");
        assert!(validate_request(&invalid).is_err());
        invalid = request;
        invalid.artifact = ArtifactReference::Unknown;
        assert!(recovery_image(&invalid.artifact).is_err());
    }

    #[test]
    fn recovery_mounts_follow_the_current_secret_file_surface() -> anyhow::Result<()> {
        let root = std::env::current_dir()?.join("recovery-mount-test");
        let mount = |destination: &str| NeutralMount {
            source: root.join("live").join(destination.trim_start_matches('/')),
            destination: PathBuf::from(destination),
            read_only: destination != CONTAINER_DATA_DIR,
            selinux_relabel: false,
            ownership: Responsibility::Managed,
            scope: ResourceScope::Deployment,
        };
        let mut source_mounts = vec![
            mount(CONTAINER_DATA_DIR),
            mount(CONTAINER_CONFIG_FILE),
            mount("/run/secrets/client-secret-pepper"),
            mount("/run/nazoauth-operator/config-revision"),
        ];
        let mut request = RecoveryCandidateRequest {
            source_object_reference: "nazo-live".to_owned(),
            candidate_object_reference: "nazo-recovery".to_owned(),
            deployment_id: "deploy-a".to_owned(),
            operation_id: Uuid::now_v7().to_string(),
            artifact: ArtifactReference::Oci {
                image_reference: "example/nazo".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            data_source: root.join("restored-data"),
            secrets_source: root.join("restored-secrets"),
            config_source: root.join("restored-config.yaml"),
            valkey_state_epoch: Uuid::now_v7().to_string(),
            https: false,
            tls_files: Vec::new(),
        };

        let mounts = recovery_mounts(&source_mounts, &request)?;
        let destinations = mounts
            .iter()
            .map(|mount| mount.destination.as_path())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            destinations,
            BTreeSet::from([
                Path::new(CONTAINER_DATA_DIR),
                Path::new(CONTAINER_CONFIG_FILE),
                Path::new("/run/secrets/client-secret-pepper"),
            ])
        );
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.destination == Path::new("/run/secrets/client-secret-pepper"))
                .expect("current secret mount")
                .source,
            request.secrets_source.join("client-secret-pepper")
        );
        for forbidden in [
            "/run/secrets/database-lifecycle-url",
            "/run/secrets/nested/secret",
            "/run/secrets/client-secret-pepper",
            "/run/secrets",
        ] {
            source_mounts.push(mount(forbidden));
            assert!(
                recovery_mounts(&source_mounts, &request).is_err(),
                "{forbidden}"
            );
            source_mounts.pop();
        }
        source_mounts.push(mount("/etc/nazoauth/tls"));
        source_mounts.push(mount("/etc/unrelated"));
        request.https = true;
        request.tls_files = vec![
            PathBuf::from("/etc/nazoauth/tls/current/fullchain.pem"),
            PathBuf::from("/etc/nazoauth/tls/current/private-key.pem"),
        ];
        let mounts = recovery_mounts(&source_mounts, &request)?;
        assert_eq!(mounts.len(), 4);
        let retained = mounts
            .iter()
            .find(|mount| mount.destination == Path::new("/etc/nazoauth/tls"))
            .unwrap();
        assert_eq!(retained.source, source_mounts[4].source);
        assert!(retained.read_only);
        assert!(
            !mounts
                .iter()
                .any(|mount| mount.destination == Path::new("/etc/unrelated"))
        );
        source_mounts[4].read_only = false;
        assert!(recovery_mounts(&source_mounts, &request).is_err());
        source_mounts[4].read_only = true;
        request.tls_files[0] = PathBuf::from("/etc/nazoauth/tls/../unrelated/private-key.pem");
        assert!(recovery_mounts(&source_mounts, &request).is_err());
        request.tls_files[0] = PathBuf::from("/etc/missing/private-key.pem");
        assert!(recovery_mounts(&source_mounts, &request).is_err());
        Ok(())
    }
}
