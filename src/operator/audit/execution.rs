use super::*;

pub(crate) fn execute(
    config: &UpdateConfig,
    target: &str,
    expected: &ExpectedReleaseTarget,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<OperationResult> {
    execute_with_io(
        config, target, expected, operation, public_jwk, None, None, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_with_io(
    config: &UpdateConfig,
    target: &str,
    expected: &ExpectedReleaseTarget,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
    conformance_bundle: Option<&Path>,
    conformance_output_directory: Option<&Path>,
    requested_jti: Option<&str>,
) -> anyhow::Result<OperationResult> {
    match &operation {
        TaskOperation::ConformanceMatrixDescribe => {
            if conformance_bundle.is_some()
                || conformance_output_directory.is_none()
                || requested_jti.is_some()
            {
                bail!("conformance matrix task I/O contract is invalid");
            }
        }
        TaskOperation::ConformanceOnboardingApply { .. } => {
            if conformance_bundle.is_none()
                || conformance_output_directory.is_none()
                || requested_jti.is_none()
            {
                bail!("conformance onboarding task I/O contract is invalid");
            }
        }
        _ => {
            if conformance_bundle.is_some()
                || conformance_output_directory.is_some()
                || requested_jti.is_some()
            {
                bail!("operator task does not accept conformance I/O");
            }
        }
    }
    // A privileged operation is admissible only while the existing audit,
    // intent and trust-transition state is verifiably intact.  Checking after
    // the runtime side effect would be too late: the mutation could succeed
    // even though ctl can no longer append a trustworthy receipt.
    verify_audit(config).context("operator audit preflight failed")?;
    #[cfg(debug_assertions)]
    if std::env::var_os("NAZOAUTHCTL_TESTING").is_some() {
        return execute_test_task(config, target, operation);
    }
    let manifest = canonical_manifest(config, &operation)?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let config_sha256 = canonical_config_sha256(&manifest)?;

    // Runtime/image, network, mounts, task context and sandbox are prepared before issuance.
    let runtime = Runtime::new(config);
    let prepared = runtime.prepare_app_task(
        target,
        &operation,
        public_jwk,
        conformance_bundle,
        conformance_output_directory,
        &manifest_bytes,
    )?;
    verify_target_expectation(&prepared.target, expected)?;

    let secret_revision = read_single_line(&config.operator.secret_revision_file)?;
    let config_binding = ConfigBinding {
        manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        config_sha256,
        secret_binding: SecretBinding::OpaqueRevision {
            revision: secret_revision,
        },
    };
    let (task, compact_task, intent_path) = load_or_issue_task(
        config,
        target_expectation(&prepared.target),
        expected.embedded.clone(),
        config_binding.clone(),
        operation,
        requested_jti,
    )?;
    let request_id = task.jti.clone();
    if let Some(result) = existing_final_result(config, &task, &compact_task)? {
        if path_present(&intent_path)? {
            if !is_regular_non_symlink(&intent_path)? {
                bail!("operator task intent is not a regular non-symlink file");
            }
            crate::filesystem::remove_file_durable(&intent_path)?;
        }
        return Ok(result);
    }

    let compact_runtime_receipt = prepared.execute(&compact_task)?;
    let receipt_key = read_verifying_key(&config.operator.receipt_public_key)?;
    let runtime_receipt = verify_runtime_receipt(
        compact_runtime_receipt.trim(),
        &config.operator.receipt_key_id,
        &receipt_key,
    )?;
    validate_runtime_receipt(&runtime_receipt, &task, &compact_task)?;
    runtime.verify_prepared_target(&prepared.target)?;

    // Revalidate immediately before reading the head and appending.  The
    // lifecycle lock excludes another ctl writer; this second check also
    // catches out-of-band corruption during the runtime operation.
    // A stale derived head may be recovered only on this writer path, after
    // the runtime receipt has been verified and while the caller holds the
    // lifecycle/deployment lock.  AuditVerify/AuditShow remain strictly
    // read-only and fail closed on the same condition.
    repair_audit_head_for_append(config)?;
    verify_audit(config).context("operator audit changed during task execution")?;
    let (sequence, previous) = audit_head(config)?;
    let final_receipt = FinalReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: task.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: request_id.clone(),
        request_sha256: compact_sha256(&compact_task),
        deployment_id: config.operator.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        completed_at: runtime_receipt.completed_at,
        audit_sequence: sequence,
        audit_previous_sha256: previous,
        controller_verified_target: prepared.target,
        embedded: runtime_receipt.embedded.clone(),
        config: runtime_receipt.config.clone(),
        runtime_receipt_sha256: compact_sha256(compact_runtime_receipt.trim()),
        outcome: runtime_receipt.outcome.clone(),
    };
    let audit_key = read_signing_key(&config.operator.audit_private_key)?;
    let compact_final =
        sign_final_receipt(&final_receipt, &config.operator.audit_key_id, &audit_key)?;
    let final_path = append_audit(config, sequence, &request_id, &compact_final)?;
    if path_present(&intent_path)? {
        if !is_regular_non_symlink(&intent_path)? {
            bail!("operator task intent is not a regular non-symlink file");
        }
        crate::filesystem::remove_file_durable(&intent_path)?;
    }
    match runtime_receipt.outcome {
        TaskOutcome::Succeeded { result } => Ok(OperationResult {
            request_id,
            result,
            final_receipt: final_path,
        }),
        TaskOutcome::Failed { code } => bail!(
            "operator task failed with code {code}; request_id={request_id}; receipt={}",
            final_path.display()
        ),
    }
}

pub(crate) fn load_or_issue_task(
    config: &UpdateConfig,
    target: nazo_operator_protocol::TargetExpectation,
    embedded: EmbeddedIdentity,
    config_binding: ConfigBinding,
    operation: TaskOperation,
    requested_jti: Option<&str>,
) -> anyhow::Result<(TaskEnvelope, String, PathBuf)> {
    if let Some(requested_jti) = requested_jti {
        validate_requested_jti(requested_jti)?;
    }
    let actor = Actor {
        kind: ActorKind::LocalRoot,
        id: "uid:0".to_owned(),
    };
    let fingerprint = encode_hex(&Sha256::digest(serde_json::to_vec(&serde_json::json!({
        "deployment_id": config.operator.deployment_id,
        "target": target,
        "embedded": embedded,
        "config": config_binding,
        "operation": operation,
        "actor": actor,
        "requested_jti": requested_jti,
    }))?));
    let directory = config.operator.audit_directory.join("intents");
    crate::filesystem::ensure_directory_chain(&directory)?;
    let path = directory.join(format!("{fingerprint}.jws"));
    let now = Utc::now().timestamp();
    if path_present(&path)? {
        if !is_regular_non_symlink(&path)? {
            bail!("persisted operator intent is not a regular non-symlink file");
        }
        let compact = read_audit_text(&path, "persisted operator intent")?;
        let header = protected_header(&compact)?;
        let task = verify_task_signature(
            &compact,
            &header.kid,
            &trusted_controller_key(config, &header.kid)?,
        )?;
        let matches = task.deployment_id == config.operator.deployment_id
            && task.iss == format!("controller:{}", config.operator.deployment_id)
            && task.aud == format!("runtime:{}", config.operator.deployment_id)
            && task.actor == actor
            && task.target == target
            && task.embedded == embedded
            && task.config == config_binding
            && task.operation == operation
            && requested_jti.is_none_or(|requested| task.jti == requested);
        if !matches {
            bail!("persisted operator intent does not match the requested operation");
        }
        let cached_receipt = config
            .operator
            .state_directory
            .join(format!("{}.receipt.jws", task.jti));
        let request_claim = config
            .operator
            .state_directory
            .join(format!("{}.request.sha256", task.jti));
        let lifecycle = config
            .operator
            .state_directory
            .join(format!("{}.lifecycle.json", task.jti));
        let receipt_temporary = cached_receipt.with_extension("receipt.jws.tmp");
        let cached_receipt_present = path_present(&cached_receipt)?;
        if cached_receipt_present && !is_regular_non_symlink(&cached_receipt)? {
            bail!("cached runtime receipt is not a regular non-symlink file");
        }
        let runtime_has_observed_request = path_present(&request_claim)?
            || path_present(&lifecycle)?
            || path_present(&receipt_temporary)?;
        if task.exp >= now || cached_receipt_present || runtime_has_observed_request {
            return Ok((task, compact, path));
        }
        crate::filesystem::remove_file_durable(&path)?;
    }
    let request_id = requested_jti
        .map(str::to_owned)
        .unwrap_or_else(|| format!("request-{}", encode_hex(&rand::random::<[u8; 16]>())));
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{}", config.operator.deployment_id),
        aud: format!("runtime:{}", config.operator.deployment_id),
        jti: request_id,
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: config.operator.deployment_id.clone(),
        actor,
        target,
        embedded,
        config: config_binding,
        operation,
    };
    let controller_key = read_signing_key(&config.operator.controller_private_key)?;
    let compact = sign_task(&task, &config.operator.controller_key_id, &controller_key)?;
    atomic_write(&path, compact.as_bytes(), 0o400)?;
    Ok((task, compact, path))
}

fn validate_requested_jti(value: &str) -> anyhow::Result<()> {
    let Some(suffix) = value.strip_prefix("request-") else {
        bail!("operator request JTI is invalid");
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("operator request JTI is invalid");
    }
    Ok(())
}

fn existing_final_result(
    config: &UpdateConfig,
    task: &TaskEnvelope,
    compact_task: &str,
) -> anyhow::Result<Option<OperationResult>> {
    let request_id = &task.jti;
    let directory = config.operator.audit_directory.join("receipts");
    if !is_real_directory_or_missing(&directory, "audit receipt directory")? {
        return Ok(None);
    }
    let suffix = format!("-{request_id}.jws");
    let mut matches = fs::read_dir(&directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(&suffix))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        bail!("audit contains duplicate final receipts for one request ID");
    }
    let Some(entry) = matches.pop() else {
        return Ok(None);
    };
    let compact = read_audit_text(&entry.path(), "audit receipt")?;
    let header = protected_header(&compact)?;
    let receipt = verify_final_receipt(
        &compact,
        &header.kid,
        &trusted_audit_key(config, &header.kid)?,
    )?;
    let target = match &task.target {
        nazo_operator_protocol::TargetExpectation::OciImage {
            image_ref,
            image_digest,
        } => RuntimeTargetClaim::OciImage {
            image_ref: image_ref.clone(),
            image_digest: image_digest.clone(),
        },
        nazo_operator_protocol::TargetExpectation::HostBinary { path, sha256 } => {
            RuntimeTargetClaim::HostBinary {
                path: path.clone(),
                sha256: sha256.clone(),
            }
        }
    };
    if receipt.request_sha256 != compact_sha256(compact_task)
        || receipt.deployment_id != task.deployment_id
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.controller_verified_target != target
        || receipt.embedded != task.embedded
        || receipt.config != task.config
    {
        bail!("persisted final receipt is not bound to the pending intent");
    }
    match receipt.outcome {
        TaskOutcome::Succeeded { result } => Ok(Some(OperationResult {
            request_id: request_id.clone(),
            result,
            final_receipt: entry.path(),
        })),
        TaskOutcome::Failed { code } => bail!(
            "operator task previously failed with code {code}; request_id={request_id}; receipt={}",
            entry.path().display()
        ),
    }
}

#[cfg(debug_assertions)]
pub(crate) fn execute_test_task(
    config: &UpdateConfig,
    target: &str,
    operation: TaskOperation,
) -> anyhow::Result<OperationResult> {
    let arguments = match &operation {
        TaskOperation::MigrateApply => vec!["migrate".to_owned()],
        TaskOperation::KeysList => vec!["keyctl".to_owned(), "list".to_owned()],
        TaskOperation::KeysValidate => vec!["keyctl".to_owned(), "validate".to_owned()],
        TaskOperation::KeysGenerateLocal { .. } | TaskOperation::KeysRegisterExternal { .. } => {
            bail!("test task adapter does not implement key mutation")
        }
        TaskOperation::ConformanceMatrixDescribe
        | TaskOperation::ConformanceOnboardingApply { .. }
        | TaskOperation::ConformanceLeaseCreate { .. }
        | TaskOperation::ConformanceLeaseList
        | TaskOperation::ConformanceLeaseRevoke { .. }
        | TaskOperation::ConformanceLeaseCleanup => {
            bail!("test task adapter does not implement conformance lease operations")
        }
    };
    crate::runtime_backend::backend(config.runtime.backend).run_debug_artifact_task(
        &crate::runtime_backend::DebugArtifactTask {
            target: target.to_owned(),
            arguments,
        },
    )?;
    let request_id = format!("request-test-{}", encode_hex(&rand::random::<[u8; 8]>()));
    let directory = config.operator.audit_directory.join("test-receipts");
    crate::filesystem::ensure_directory_chain(&directory)?;
    let receipt = directory.join(format!("{request_id}.txt"));
    atomic_write(&receipt, b"debug-build-test-adapter", 0o400)?;
    Ok(OperationResult {
        request_id,
        result: match operation {
            TaskOperation::MigrateApply => TaskResult::Migration { applied: true },
            TaskOperation::KeysList => TaskResult::KeyList {
                keyset_revision: "test".to_owned(),
            },
            TaskOperation::KeysValidate => TaskResult::KeyValidation {
                keyset_revision: "test".to_owned(),
            },
            TaskOperation::KeysGenerateLocal { .. }
            | TaskOperation::KeysRegisterExternal { .. }
            | TaskOperation::ConformanceMatrixDescribe
            | TaskOperation::ConformanceOnboardingApply { .. }
            | TaskOperation::ConformanceLeaseCreate { .. }
            | TaskOperation::ConformanceLeaseList
            | TaskOperation::ConformanceLeaseRevoke { .. }
            | TaskOperation::ConformanceLeaseCleanup => unreachable!(),
        },
        final_receipt: receipt,
    })
}

#[cfg(all(test, not(debug_assertions)))]
pub(crate) fn execute_test_task(
    _config: &UpdateConfig,
    _target: &str,
    _operation: TaskOperation,
) -> anyhow::Result<OperationResult> {
    bail!("test task adapter is unavailable in release builds")
}

pub(crate) fn canonical_manifest(
    config: &UpdateConfig,
    operation: &TaskOperation,
) -> anyhow::Result<CanonicalConfigManifest> {
    let server_config = if config.runtime.backend == RuntimeBackendKind::Systemd {
        config.runtime.working_directory.join(".env.yaml")
    } else {
        config
            .runtime
            .mounts
            .iter()
            .find(|mount| mount.target == Path::new("/app/.env.yaml"))
            .context("server configuration mount is unavailable")?
            .source
            .clone()
    };
    Ok(CanonicalConfigManifest {
        version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            (
                "deployment_id".to_owned(),
                config.operator.deployment_id.clone(),
            ),
            ("operation".to_owned(), operation_name(operation).to_owned()),
            ("server_config_sha256".to_owned(), sha256(&server_config)?),
        ]),
    })
}

pub(crate) fn operation_name(operation: &TaskOperation) -> &'static str {
    match operation {
        TaskOperation::MigrateApply => "migrate-apply",
        TaskOperation::ConformanceMatrixDescribe => "conformance-matrix-describe",
        TaskOperation::ConformanceOnboardingApply { .. } => "conformance-onboarding-apply",
        TaskOperation::ConformanceLeaseCreate { .. } => "conformance-lease-create",
        TaskOperation::ConformanceLeaseList => "conformance-lease-list",
        TaskOperation::ConformanceLeaseRevoke { .. } => "conformance-lease-revoke",
        TaskOperation::ConformanceLeaseCleanup => "conformance-lease-cleanup",
        TaskOperation::KeysList => "keys-list",
        TaskOperation::KeysValidate => "keys-validate",
        TaskOperation::KeysGenerateLocal { .. } => "keys-generate-local",
        TaskOperation::KeysRegisterExternal { .. } => "keys-register-external",
    }
}

pub(crate) fn verify_target_expectation(
    actual: &RuntimeTargetClaim,
    expected: &ExpectedReleaseTarget,
) -> anyhow::Result<()> {
    match actual {
        RuntimeTargetClaim::OciImage { image_digest, .. } => {
            if image_digest != &expected.image_digest {
                bail!("actual OCI image digest does not match the signed Release manifest");
            }
        }
        RuntimeTargetClaim::HostBinary { sha256, .. } => {
            if sha256 != &expected.binary_digest {
                bail!("actual host binary digest does not match the signed Release manifest");
            }
        }
    }
    Ok(())
}

pub(crate) fn target_expectation(
    target: &RuntimeTargetClaim,
) -> nazo_operator_protocol::TargetExpectation {
    match target {
        RuntimeTargetClaim::OciImage {
            image_ref,
            image_digest,
        } => nazo_operator_protocol::TargetExpectation::OciImage {
            image_ref: image_ref.clone(),
            image_digest: image_digest.clone(),
        },
        RuntimeTargetClaim::HostBinary { path, sha256 } => {
            nazo_operator_protocol::TargetExpectation::HostBinary {
                path: path.clone(),
                sha256: sha256.clone(),
            }
        }
    }
}

pub(crate) fn validate_runtime_receipt(
    receipt: &RuntimeReceipt,
    task: &TaskEnvelope,
    compact_task: &str,
) -> anyhow::Result<()> {
    if receipt.jti != task.jti
        || receipt.request_sha256 != compact_sha256(compact_task)
        || receipt.deployment_id != task.deployment_id
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.embedded != task.embedded
        || receipt.config != task.config
        || receipt.started_at < task.iat
        || receipt.completed_at < receipt.started_at
    {
        bail!("runtime receipt is not bound to the authorized task");
    }
    Ok(())
}

pub(crate) fn expected_release_target(
    config: &UpdateConfig,
    embedded: EmbeddedIdentity,
    image_digest: String,
    binary_digest: String,
) -> anyhow::Result<ExpectedReleaseTarget> {
    if embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION {
        bail!("Release operator protocol version is unsupported");
    }
    if config.runtime.backend == RuntimeBackendKind::Systemd && binary_digest.len() != 64 {
        bail!("Release binary digest is invalid");
    }
    Ok(ExpectedReleaseTarget {
        embedded,
        image_digest,
        binary_digest,
    })
}
