use super::*;

pub(crate) fn invoke_recovery_driver(
    lifecycle_path: &Path,
    lifecycle: &LifecycleManifest,
    recovery_manifest: &Path,
    release: &str,
    operation: RecoveryOperation,
    capabilities: &CapabilityGrants,
) -> anyhow::Result<RecoveryDriverReceipt> {
    lifecycle.validate()?;
    let lifecycle_sha256 = sha256(lifecycle_path)?;
    let recovery_manifest_sha256 = sha256(recovery_manifest)?;
    let request_id = uuid::Uuid::now_v7().to_string();
    let request = RecoveryDriverRequest {
        schema: RECOVERY_DRIVER_SCHEMA,
        request_id: request_id.clone(),
        deployment_id: &lifecycle.deployment_id,
        release,
        operation,
        lifecycle_sha256: &lifecycle_sha256,
        recovery_manifest,
        recovery_manifest_sha256: &recovery_manifest_sha256,
        rehearsal_workspace: (operation == RecoveryOperation::Rehearse)
            .then_some(lifecycle.recovery_driver.rehearsal_workspace.as_path()),
        credentials: &lifecycle.recovery_driver.credentials,
    };
    let request = serde_json::to_vec(&request)?;
    if request.len() > MAX_LIFECYCLE_BYTES as usize {
        bail!("recovery driver request exceeds the protocol limit");
    }
    if sha256(&lifecycle.recovery_driver.program)? != lifecycle.recovery_driver.program_sha256 {
        bail!("recovery driver changed after lifecycle validation");
    }
    let output = Process::new(lifecycle.recovery_driver.program.as_os_str())
        .args(
            lifecycle
                .recovery_driver
                .arguments
                .iter()
                .map(String::as_str),
        )
        .env(
            "NAZOAUTHCTL_RECOVERY_OPERATION",
            match operation {
                RecoveryOperation::Rehearse => "rehearse",
                RecoveryOperation::Checkpoint => "checkpoint",
                RecoveryOperation::Restore => "restore",
            },
        )
        .stdin_stdout(&request)?;
    if output.len() > MAX_DRIVER_OUTPUT_BYTES {
        bail!("recovery driver receipt exceeds the protocol limit");
    }
    let receipt: RecoveryDriverReceipt =
        serde_json::from_str(&output).context("recovery driver returned an invalid receipt")?;
    if operation != RecoveryOperation::Checkpoint
        && sha256(recovery_manifest)? != recovery_manifest_sha256
    {
        bail!("recovery driver changed immutable recovery evidence during validation or restore");
    }
    validate_receipt(
        &receipt,
        &request_id,
        lifecycle,
        release,
        operation,
        &lifecycle_sha256,
        &recovery_manifest_sha256,
        capabilities,
    )?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_receipt(
    receipt: &RecoveryDriverReceipt,
    request_id: &str,
    lifecycle: &LifecycleManifest,
    release: &str,
    operation: RecoveryOperation,
    lifecycle_sha256: &str,
    recovery_manifest_sha256: &str,
    capabilities: &CapabilityGrants,
) -> anyhow::Result<()> {
    if receipt.schema != RECOVERY_DRIVER_SCHEMA
        || receipt.request_id != request_id
        || receipt.deployment_id != lifecycle.deployment_id
        || receipt.release != release
        || receipt.operation != operation
        || receipt.lifecycle_sha256 != lifecycle_sha256
        || receipt.recovery_manifest_sha256 != recovery_manifest_sha256
        || receipt.status != RecoveryStatus::Succeeded
    {
        bail!("recovery driver receipt is not bound to the requested operation");
    }
    if receipt.issued_at <= 0 || (Utc::now().timestamp() - receipt.issued_at).abs() > 300 {
        bail!("recovery driver receipt is outside its freshness window");
    }
    match operation {
        RecoveryOperation::Checkpoint => {
            let path = receipt
                .checkpoint_manifest
                .as_deref()
                .context("recovery checkpoint receipt has no recovery manifest")?;
            let expected = receipt
                .checkpoint_manifest_sha256
                .as_deref()
                .context("recovery checkpoint receipt has no manifest digest")?;
            validate_absolute_path(path, "recovery checkpoint manifest")?;
            validate_lower_hex(expected)?;
            let metadata = fs::symlink_metadata(path)
                .context("failed to inspect recovery checkpoint manifest")?;
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                bail!("recovery checkpoint manifest must be a non-empty regular file");
            }
            if sha256(path)? != expected {
                bail!("recovery checkpoint manifest digest does not match its receipt");
            }
        }
        RecoveryOperation::Rehearse | RecoveryOperation::Restore => {
            if receipt.checkpoint_manifest.is_some() || receipt.checkpoint_manifest_sha256.is_some()
            {
                bail!("non-checkpoint recovery receipt contains a checkpoint output");
            }
        }
    }
    let required = required_components(capabilities);
    if !required.is_subset(&receipt.components)
        || receipt
            .components
            .iter()
            .any(|component| !allowed_components().contains(component.as_str()))
    {
        bail!("recovery driver receipt does not prove every authorized recovery component");
    }
    Ok(())
}

pub(super) fn required_components(capabilities: &CapabilityGrants) -> BTreeSet<String> {
    let mut required = BTreeSet::from(["artifact".to_owned(), "verification".to_owned()]);
    for (capability, component) in [
        (Capability::ServerConfig, "data"),
        (Capability::Database, "database"),
        (Capability::Valkey, "valkey"),
    ] {
        if capabilities
            .grant(capability)
            .responsibility
            .permits_mutation()
        {
            required.insert(component.to_owned());
        }
    }
    required
}

pub(super) fn allowed_components() -> BTreeSet<&'static str> {
    BTreeSet::from(["artifact", "data", "database", "valkey", "verification"])
}

pub(super) fn validate_server_command(command: &[String]) -> anyhow::Result<()> {
    if command.is_empty() || command.len() > MAX_ARGUMENTS {
        bail!("runtime lifecycle command is empty or too large");
    }
    for argument in command {
        if argument.is_empty()
            || argument.len() > MAX_ARGUMENT_BYTES
            || argument.contains(['\0', '\r', '\n'])
        {
            bail!("runtime lifecycle command contains an invalid argument");
        }
    }
    let executable = Path::new(&command[0]);
    if !executable
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "nazoauth" | "nazoauth.exe"))
        || command.get(1).map(String::as_str) != Some("server")
    {
        bail!("runtime lifecycle command is not nazoauth server");
    }
    Ok(())
}

pub(super) fn validate_environment(
    backend: RuntimeBackendKind,
    environment: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    const ALLOWED: &[&str] = &[
        "CONFIG_PATH",
        "DATABASE_URL_FILE",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "INSTANCE_IDENTITY_DIR",
        "ISSUER",
        "PROFILE_SECRET_ROOT",
        "PUBLIC_BASE_URL",
        "RUNTIME_INSTANCE_ID",
        "VALKEY_URL_FILE",
    ];
    if environment.len() > 64 {
        bail!("runtime lifecycle environment exceeds the policy limit");
    }
    for (name, value) in environment {
        if !ALLOWED.contains(&name.as_str())
            || value.is_empty()
            || value.len() > MAX_ARGUMENT_BYTES
            || value.contains(['\0', '\r', '\n'])
        {
            bail!("runtime lifecycle environment contains an unsafe entry");
        }
        if name.ends_with("_FILE") && !runtime_path_is_absolute(backend, Path::new(value)) {
            bail!("runtime secret file reference must be absolute");
        }
    }
    Ok(())
}

pub(super) fn runtime_path_is_absolute(backend: RuntimeBackendKind, path: &Path) -> bool {
    match backend {
        RuntimeBackendKind::Docker | RuntimeBackendKind::Podman => path
            .to_str()
            .is_some_and(|value| value.starts_with('/') && !value.starts_with("//")),
        RuntimeBackendKind::Systemd => path.is_absolute(),
    }
}

pub(super) fn validate_absolute_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || path.parent().is_none()
    {
        bail!("{label} must be a normalized absolute non-root path");
    }
    Ok(())
}

pub(super) fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub(super) fn validate_file_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .with_context(|| format!("invalid {label}"))
}

pub(super) fn validate_boundary(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_ARGUMENT_BYTES
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+,-=[]".contains(character))
    {
        bail!("{label} contains unsafe characters");
    }
    Ok(())
}

pub(super) fn validate_lower_hex(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("digest must contain 64 lowercase hexadecimal characters");
    }
    Ok(())
}
