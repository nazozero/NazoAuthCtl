//! Ordinary tenant-resource backed OIDF orchestration.
//!
//! This is the only producer path for `conformance run`. The signed artifact
//! owns executable Matrix facts; NazoAuth owns ordinary tenant resources; the
//! Suite remains an external test runner. No conformance lease or Suite-only
//! NazoAuth management endpoint is used here.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazoauthctl_conformance::{
    ArtifactMaterializationBinding, ArtifactTrustPolicy, AuthenticatedProviderAuthorization,
    BearerToken, BrowserAutomation, BrowserExecutor, BrowserPolicy, BrowserReviewScreenshotCapture,
    BrowserTargetOrigin, CibaUserApprovalBridge, CibaUserApprovalClient, ClientConfig,
    ConformanceAutomation, ConformanceBinding, ConformanceProxyRecovery, ConformanceRecoveryStore,
    ConformanceRunConfig, ConformanceRunner, CredentialStore, DescriptorMaterializer,
    EvidenceBundleIdentity, EvidenceBundleReceipt, EvidenceDeploymentIdentity,
    EvidenceProviderCapability, EvidenceProviderIdentity, EvidenceProviderReceipt,
    EvidenceRuntimeIdentity, EvidenceSourceIdentity, HttpTransport, ManagedWebDriver,
    MatrixSelection, OidfArtifactMatrix, OidfDriverLane, OidfPlanResourceBudget, OidfPlanSelection,
    OidfProviderExecutionBinding, OpenId4VciIssuerClient, OpenId4VciIssuerConfig,
    OpenId4VciIssuerDriver, OpenId4VpEvidenceRunContext, OpenId4VpEvidenceVerifier,
    OpenId4VpVerifier, OpenId4VpVerifierClient, Origin, ProxyTrustGuard, RunControl,
    StableRenderer, SuiteClient, SuiteResourceObserver, SuiteRetentionDeferredReview,
    SuiteRetentionManifest, SuiteRetentionManifestReceipt, SuiteRetentionPlan,
    SuiteRetentionScreenshotManifest, TenantResourceApplyOutput, TenantResourceReceiptIdentity,
    TenantResourceRecoveryBinding, TtyRenderer, WebDriverClient, WebDriverEndpoint,
    authorize_oidf_driver_execution, open_cached_oidf_driver_plan, read_artifact_driver,
    read_artifact_matrix, read_compact_manifest, recover_suite_resources,
    validate_private_evidence_directory, verify_oidf_artifact,
    write_private_provider_evidence_bundle, write_review_screenshot_manifest,
};
use nazoauthctl_core::tenant_resources::{
    TenantResourceCapabilitySession, TenantResourceClient, TenantResourceClientError,
    TenantResourceReceiptResult,
};
use serde::Serialize;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use super::RunInvocation;

const MAX_STDIN_TOKEN_BYTES: u64 = 16 * 1024;

/// Capabilities implemented by this binary's signed-artifact runner. These
/// are local engine facts, not NazoAuth provider permissions.
const RUNNER_CAPABILITIES: &[&str] = &["nazoauth.client.create"];

pub(super) fn execute(mut invocation: RunInvocation) -> anyhow::Result<i32> {
    let suite_origin = Origin::from_suite_arg(invocation.suite.as_deref())
        .context("invalid OpenID Foundation Conformance Suite origin")?;
    let session = nazoauthctl_core::ConformanceSession::open(
        &invocation.config,
        invocation.deployment.as_deref(),
    )
    .context("deployment is not ready for ordinary conformance orchestration")?;
    let deployment = session.deployment_evidence();
    let recovery_directory = session.recovery_directory()?;
    let recovery_store =
        ConformanceRecoveryStore::open(&recovery_directory, &deployment.deployment_id)?;

    let trust = ArtifactTrustPolicy::from_path(&invocation.trust_policy)
        .context("signed-artifact trust policy is invalid")?;
    let runner_capabilities = RUNNER_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    let now = current_unix_time()?;
    let mut driver_plan = open_cached_oidf_driver_plan(
        &invocation.artifact_cache,
        &invocation.artifact_digest,
        &trust,
        &runner_capabilities,
        OidfPlanSelection {
            groups: invocation.groups.clone(),
            plans: invocation.plans.clone(),
        },
        now,
    )
    .context("exact cached signed OIDF artifact cannot be opened")?;
    if driver_plan.artifact.suite.origin != suite_origin.as_str() {
        bail!("--suite does not match the origin signed by the OIDF artifact");
    }
    if invocation.retain_suite_plans_for_certification {
        if suite_origin != Origin::official() {
            bail!(
                "--retain-suite-plans-for-certification is restricted to the canonical official Suite origin"
            );
        }
        let evidence_directory = invocation
            .evidence_directory
            .as_deref()
            .context("--retain-suite-plans-for-certification requires --evidence-dir")?;
        validate_private_evidence_directory(evidence_directory).context(
            "retention evidence directory must be an existing root-owned private directory",
        )?;
    }
    if invocation.capture_review_screenshots {
        if suite_origin != Origin::official() {
            bail!(
                "--capture-review-screenshots is restricted to the canonical official Suite origin"
            );
        }
        let evidence_directory = invocation
            .evidence_directory
            .as_ref()
            .expect("CLI requires --evidence-dir for review screenshots");
        validate_private_evidence_directory(evidence_directory)
            .context("review screenshot evidence directory must be root-owned and private")?;
    }

    let (token, prompted) = resolve_token(&mut invocation, &suite_origin)?;
    let suite_client =
        SuiteClient::new(suite_origin.clone(), token.clone(), ClientConfig::default())
            .context("failed to initialize the Suite client")?;
    suite_client
        .probe_auth()
        .context("Suite API token authentication failed")?;
    let recovered_retention = recover_pending_runs(&session, &recovery_store, &suite_client)?;
    if !recovered_retention.is_empty() {
        serde_json::to_writer_pretty(
            io::stdout().lock(),
            &RecoveredRetentionOutput {
                schema: 1,
                recovered: true,
                retention: recovered_retention,
            },
        )
        .context("failed to write recovered retention report")?;
        writeln!(io::stdout()).context("failed to finish recovered retention report")?;
        return Ok(0);
    }
    if prompted {
        offer_credential_persistence(&suite_origin, &token)?;
    }

    let compact_manifest =
        read_compact_manifest(&driver_plan.artifact_cache_entry.join("manifest.jws"))
            .context("failed to reread the cached signed artifact manifest")?;
    let driver_bytes = read_artifact_driver(&driver_plan.artifact_cache_entry.join("driver.json"))
        .context("failed to reread the cached artifact driver")?;
    let matrix_bytes = read_artifact_matrix(&driver_plan.artifact_cache_entry.join("matrix.json"))
        .context("failed to reread the cached artifact Matrix")?;
    let consumed_artifact = verify_oidf_artifact(
        &compact_manifest,
        &driver_bytes,
        &matrix_bytes,
        &trust,
        &runner_capabilities,
        current_unix_time()?,
    )
    .context("cached signed artifact changed before materialization")?;
    if consumed_artifact != driver_plan.artifact {
        bail!("cached signed artifact identity changed before materialization");
    }
    let matrix: OidfArtifactMatrix = serde_json::from_slice(&matrix_bytes)
        .context("verified cached artifact Matrix is malformed")?;
    let selected_plan_ids = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.group_id.clone(), plan.plan_id.clone()))
        .collect::<BTreeSet<_>>();
    let matrix = select_artifact_matrix_for_run(matrix, &selected_plan_ids)?;
    let request_jti = format!("request-{}", hex(rand::random::<[u8; 16]>()));
    let materialization_now = current_unix_time()?;
    if materialization_now > driver_plan.latest_execution_start_at {
        bail!("signed artifact no longer has enough validity remaining for the selected run");
    }
    let ciba_callback = prepare_ciba_user_approval_callback(
        &invocation,
        driver_plan
            .plans
            .iter()
            .any(|entry| entry.driver_handler.lane == OidfDriverLane::Ciba),
    )?;
    let deployment_trust_anchor = session
        .openid4vc_request_object_trust_anchor_pem()
        .context("failed to load the deployment OpenID4VC trust anchor")?;
    let dynamic_registration_initial_access_token = session
        .dynamic_registration_initial_access_token()
        .context("failed to load the deployment RFC 7591 initial access token")?;
    let prepared = DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(
        &matrix,
        ArtifactMaterializationBinding {
            artifact_source_release: &driver_plan.artifact.revision,
            artifact_source_digest: &invocation.artifact_digest,
            raw_matrix_sha256: &driver_plan.artifact.matrix_sha256,
            target_issuer: session.target_issuer(),
            suite_origin: &suite_origin,
            request_jti: &request_jti,
            credential_trust_anchor_pem: &deployment_trust_anchor,
            dynamic_registration_initial_access_token: Some(
                dynamic_registration_initial_access_token.as_str(),
            ),
            ciba_user_approval_callback_url: ciba_callback
                .as_ref()
                .map(|value| value.public_url.as_str()),
        },
    )
    .context("failed to prepare ordinary run material from the signed Matrix")?;
    let manifest = prepared
        .tenant_resource_manifest(&request_jti)
        .context("failed to materialize run-unique tenant resources")?;
    let run_secrets = RunSecrets {
        tx_code: prepared.tx_code(),
        applicant_email: Zeroizing::new(prepared.applicant_email().to_owned()),
        applicant_password: prepared.applicant_password(),
        mtls_trust_anchor_pem: prepared.mtls_trust_anchor_pem(),
    };

    let tenant_resource_client_config = session
        .tenant_resource_client_config(&invocation.tenant_id)
        .context("failed to bind the tenant-resource client to the selected runtime")?;
    let vp_evidence_verifier = invocation
        .capture_review_screenshots
        .then(|| {
            OpenId4VpEvidenceVerifier::new(
                tenant_resource_client_config.deployment_id.clone(),
                invocation.tenant_id.clone(),
                tenant_resource_client_config.runtime_instance_id.clone(),
                tenant_resource_client_config.runtime_key_id.clone(),
                tenant_resource_client_config.runtime_public_key,
            )
        })
        .transpose()
        .context("failed to bind OpenID4VP evidence receipts to the selected runtime")?;
    let vp_evidence_trust_anchor = vp_evidence_verifier
        .as_ref()
        .map(|verifier| verifier.recovery_trust_anchor(session.target_issuer()))
        .transpose()
        .context("failed to persist the OpenID4VP evidence runtime trust anchor")?;
    let client = TenantResourceClient::with_curl(tenant_resource_client_config)?;
    let capability = client
        .discover_capability()
        .context("failed to discover the signed tenant-resource capability")?;

    let provider_actions = capability.capability.actions.iter().copied().collect();
    let provider_resource_kinds = capability
        .capability
        .resource_kinds
        .iter()
        .copied()
        .collect();
    let binding = OidfProviderExecutionBinding {
        deployment_id: capability.capability.deployment_id.clone(),
        tenant_id: capability.capability.tenant_id.clone(),
        runtime_instance_id: capability.capability.runtime_instance_id.clone(),
        runtime_build_id: capability.capability.embedded.build_id.clone(),
        capability_jti: capability.capability.jti.clone(),
        capability_sha256: capability.compact_sha256(),
        runner_capabilities: runner_capabilities.clone(),
        provider_actions,
        provider_resource_kinds,
        current_revision: capability.capability.revision,
        current_manifest_sha256: capability.capability.resource_manifest_sha256.clone(),
        artifact_source: driver_plan.artifact.source.clone(),
        suite_origin: suite_origin.to_string(),
    };
    let authorization = AuthenticatedProviderAuthorization {
        deployment_id: binding.deployment_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        runtime_instance_id: binding.runtime_instance_id.clone(),
        runtime_build_id: binding.runtime_build_id.clone(),
        capability_jti: binding.capability_jti.clone(),
        capability_sha256: binding.capability_sha256.clone(),
        capability_issued_at: capability.capability.issued_at,
        capability_expires_at: capability.capability.expires_at,
        runner_capabilities: binding.runner_capabilities.clone(),
        provider_actions: binding.provider_actions.clone(),
        provider_resource_kinds: binding.provider_resource_kinds.clone(),
        current_revision: binding.current_revision,
        current_manifest_sha256: binding.current_manifest_sha256.clone(),
        artifact_source: binding.artifact_source.clone(),
        suite_origin: binding.suite_origin.clone(),
    };
    authorize_oidf_driver_execution(
        &mut driver_plan,
        &binding,
        &authorization,
        current_unix_time()?,
    )
    .context("signed driver plan is not authorized by the selected provider")?;
    let plan_lanes = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.plan_id.clone(), plan.driver_handler.lane))
        .collect::<BTreeMap<_, _>>();
    if plan_lanes.len() != driver_plan.plans.len() {
        bail!("signed driver plan contains duplicate Matrix plan ids");
    }
    let plan_resource_budgets = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.plan_id.clone(), plan.resource_budget.clone()))
        .collect::<BTreeMap<_, _>>();
    if plan_resource_budgets.len() != driver_plan.plans.len() {
        bail!("signed driver plan contains duplicate Matrix plan ids");
    }
    let selected_resource_budget = driver_plan.selected_resource_budget.clone();

    let baseline = client
        .enumerate(
            &capability,
            &format!("{request_jti}-baseline"),
            &invocation.artifact_digest,
            Vec::new(),
        )
        .context("failed to enumerate the tenant-resource baseline")?;
    let mut final_active = baseline.receipt().resources.clone();
    for delta in manifest.resource_identities() {
        if let Some(existing) = final_active.iter().find(|existing| {
            existing.kind == delta.kind && existing.resource_id == delta.resource_id
        }) {
            if existing.digest != delta.digest {
                bail!("run-unique tenant resource conflicts with the active baseline");
            }
        } else {
            final_active.push(delta.clone());
        }
    }
    final_active.sort_by(|left, right| {
        (left.kind, left.resource_id.as_str()).cmp(&(right.kind, right.resource_id.as_str()))
    });

    let prepared_apply = client
        .prepare_apply(
            &capability,
            &format!("{request_jti}-apply"),
            manifest.bytes().as_bytes(),
            manifest.resource_identities().to_vec(),
            final_active.clone(),
            current_unix_time()?,
        )
        .context("failed to freeze the exact tenant-resource Apply request")?;
    let private_manifest_path = recovery_directory.join(format!("manifest-{request_jti}.json"));
    manifest
        .write_private(&private_manifest_path)
        .context("failed to durably persist the private Apply manifest")?;
    let prepared_identity = prepared_apply.recovery_binding();
    let proxy_recovery = match (
        invocation.proxy_trust_bundle.as_ref(),
        invocation.proxy_reload_executable.as_ref(),
    ) {
        (Some(bundle_path), Some(reload_executable)) => Some(ConformanceProxyRecovery {
            bundle_path: bundle_path.clone(),
            reload_executable: reload_executable.clone(),
        }),
        (None, None) => None,
        _ => unreachable!("CLI validates proxy arguments as an atomic pair"),
    };
    let recovery_binding = TenantResourceRecoveryBinding {
        deployment_id: deployment.deployment_id.clone(),
        tenant_id: invocation.tenant_id.clone(),
        request_jti: prepared_identity.jti().to_owned(),
        capability_jws: prepared_identity.capability_jws().to_owned(),
        capability_sha256: prepared_identity.capability_sha256().to_owned(),
        task_jws: prepared_identity.task_jws().to_owned(),
        task_sha256: prepared_identity.task_sha256().to_owned(),
        change_set_id: prepared_identity.change_set_id().to_owned(),
        change_set_sha256: prepared_identity.change_set_sha256().to_owned(),
        request_sha256: prepared_identity.request_sha256().to_owned(),
        operation: prepared_identity.operation(),
        expected_revision: prepared_apply.task().expected_revision,
        manifest_path: Some(private_manifest_path.clone()),
        proxy: proxy_recovery,
        vp_evidence_trust_anchor,
        resource_identities: manifest.resource_identities().to_vec(),
    };
    let recovery = match recovery_store.begin_tenant_resource(recovery_binding) {
        Ok(recovery) => Arc::new(Mutex::new(recovery)),
        Err(error) => {
            return match std::fs::remove_file(&private_manifest_path) {
                Ok(()) => Err(error).context(
                    "failed to persist the ordinary recovery intent; private manifest removed",
                ),
                Err(removal) => bail!(
                    "failed to persist the ordinary recovery intent and remove its private manifest: journal={error:#}; manifest-removal={removal:#}"
                ),
            };
        }
    };
    let apply_receipt = match client.execute_prepared_live(&prepared_apply) {
        Ok(receipt) => receipt,
        Err(error) if is_deterministic_uncommitted_rejection(&error) => {
            // Proxy installation is deliberately after receipt persistence,
            // so a pre-receipt rejection proves that no proxy side effect was
            // reached even when the intent carries a future proxy binding.
            let mut guard = lock_recovery(&recovery)?;
            if !guard.proxy_cleanup_complete() {
                guard.mark_proxy_cleanup_complete()?;
            }
            drop(guard);
            take_recovery(recovery)?.abort_uncommitted_tenant_resource()?;
            return Err(error).context("ordinary tenant-resource Apply was rejected");
        }
        Err(error) => {
            return Err(error).context("ordinary tenant-resource Apply failed");
        }
    };
    lock_recovery(&recovery)?.record_tenant_resource_receipt(
        TenantResourceReceiptIdentity::from_verified_receipt(
            apply_receipt.receipt(),
            &apply_receipt.receipt_sha256(),
        )?,
    )?;
    let apply_output = TenantResourceApplyOutput::from_verified_receipt(
        apply_receipt.receipt().clone(),
        prepared_apply.task().jti.as_str(),
        prepared_apply.task().change_set_id.as_str(),
        &prepared_apply.request_sha256(),
        &manifest,
        final_active,
    )?;
    let ordinary = DescriptorMaterializer::finalize_tenant_resources(
        prepared,
        apply_output,
        deployment_trust_anchor,
    )
    .context("provider Apply mappings do not match the prepared signed Matrix")?;
    let mut deployment_report = DeploymentReport {
        deployment_id: deployment.deployment_id.clone(),
        tenant_id: invocation.tenant_id.clone(),
        target_issuer: deployment.target_issuer.clone(),
        artifact_digest: invocation.artifact_digest.clone(),
        artifact_revision: driver_plan.artifact.revision.clone(),
        matrix_sha256: ordinary.matrix_sha256().to_owned(),
        selected_groups: driver_plan.selected_group_count,
        selected_plans: driver_plan.selected_plan_count,
        apply_task_jti: ordinary.task_jti().to_owned(),
        change_set_id: ordinary.change_set_id().to_owned(),
        resource_manifest_sha256: ordinary.resource_manifest_sha256().to_owned(),
        trust_policy_resource_id: ordinary.trust_policy_resource_id().to_owned(),
        trust_policy_digest: ordinary.trust_policy_digest().to_owned(),
        applicant_id: ordinary.applicant_id().to_string(),
        client_count: u32::try_from(ordinary.clients().len())
            .context("ordinary client mapping count exceeds the report bound")?,
        cleanup_complete: false,
    };

    let mut proxy = match (
        invocation.proxy_trust_bundle.as_deref(),
        invocation.proxy_reload_executable.as_deref(),
    ) {
        (Some(bundle_path), Some(reload_executable)) => match ProxyTrustGuard::install(
            bundle_path,
            reload_executable,
            run_secrets.mtls_trust_anchor_pem.as_bytes(),
        ) {
            Ok(proxy) => Some(proxy),
            Err(install) => {
                let proxy_cleanup = ProxyTrustGuard::recover(bundle_path, reload_executable);
                if proxy_cleanup.is_ok() {
                    lock_recovery(&recovery)?.mark_proxy_cleanup_complete()?;
                }
                let mut recovery = take_recovery(recovery)?;
                let resource_cleanup = cleanup_run_resources(&client, &mut recovery);
                if resource_cleanup.is_ok()
                    && proxy_cleanup.is_ok()
                    && recovery.suite_cleanup_complete()
                {
                    recovery.finish()?;
                }
                bail!(
                    "proxy-install={install:#}; proxy-recovery={}; resource-cleanup={}",
                    proxy_cleanup
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| format!("{error:#}")),
                    resource_cleanup
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| format!("{error:#}"))
                );
            }
        },
        (None, None) => None,
        _ => unreachable!("CLI validates proxy arguments as an atomic pair"),
    };

    // The OpenID4VP client and runner are being generalized in the adjacent
    // slice. Keep this typed boundary ordinary-only: a lease-shaped adapter is
    // deliberately impossible here.
    let ciba_bridge = start_ciba_user_approval_bridge(ciba_callback, &session, &run_secrets)?;
    let run_result = run_signed_suite(
        ordinary,
        suite_client.clone(),
        token,
        run_secrets,
        &session,
        &invocation,
        &suite_origin,
        plan_lanes,
        plan_resource_budgets,
        selected_resource_budget,
        recovery.clone(),
        ciba_bridge,
        vp_evidence_verifier,
    );

    let mut recovery = take_recovery(recovery)?;
    let mut retention_eligible = run_result
        .as_ref()
        .is_ok_and(|report| report.orchestration_integrity.retention_eligible);
    let mut errors = Vec::new();
    // This root-private, module-bound manifest is the manual upload list for
    // NazoAuthWeb VP result captures. It performs no Suite upload and is
    // produced even when retention was not requested; only a later retention
    // transition binds its digest into the Suite journal.
    let review_screenshot_manifest = if invocation.capture_review_screenshots {
        match (run_result.as_ref(), invocation.evidence_directory.as_ref()) {
            (Ok(report), Some(directory)) => match write_review_screenshot_manifest(
                report,
                directory,
                recovery
                    .tenant_resource_binding()
                    .context("missing ordinary recovery binding")?
                    .request_jti
                    .as_str(),
                &invocation.artifact_digest,
                session.target_issuer(),
            ) {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    retention_eligible = false;
                    errors.push(format!("review-screenshot-manifest={error}"));
                    None
                }
            },
            _ => {
                retention_eligible = false;
                errors.push("review-screenshot-manifest=identity".to_owned());
                None
            }
        }
    } else {
        None
    };
    if run_result
        .as_ref()
        .is_ok_and(|report| report.orchestration_integrity.cleanup_complete)
    {
        recovery.mark_suite_cleanup_complete()?;
    } else if retention_eligible {
        let prepared = (|| -> anyhow::Result<()> {
            let manifest = suite_retention_manifest(
                &recovery,
                run_result
                    .as_ref()
                    .expect("retention eligibility requires report"),
                &invocation.artifact_digest,
                &deployment_report.matrix_sha256,
                review_screenshot_manifest.as_ref(),
            )?;
            let evidence_directory = invocation
                .evidence_directory
                .as_ref()
                .expect("retention preflight requires evidence directory");
            let manifest_path = suite_retention_manifest_path(evidence_directory, &manifest);
            recovery.prepare_suite_plan_retention(manifest, manifest_path)
        })();
        if let Err(error) = prepared {
            retention_eligible = false;
            errors.push(format!("suite-retention-prepare={error:#}"));
        }
    }
    let proxy_cleanup = proxy.as_mut().map(ProxyTrustGuard::restore).transpose();
    if proxy_cleanup.is_ok() && !recovery.proxy_cleanup_complete() {
        recovery.mark_proxy_cleanup_complete()?;
    }
    let cleanup = cleanup_run_resources(&client, &mut recovery);
    let mut report = match run_result {
        Ok(report) => Some(report),
        Err(error) => {
            errors.push(format!("run={error:#}"));
            None
        }
    };
    let proxy_cleanup_complete = proxy_cleanup.is_ok();
    if let Err(error) = proxy_cleanup {
        errors.push(format!("proxy-cleanup={error:#}"));
    }
    let cleanup_evidence = match cleanup {
        Ok(evidence) => Some(evidence),
        Err(error) => {
            errors.push(format!("resource-cleanup={error:#}"));
            None
        }
    };
    let cleanup_complete = cleanup_evidence.is_some()
        && proxy_cleanup_complete
        && !errors
            .iter()
            .any(|error| error.starts_with("resource-cleanup="));
    let retention_commit_possible =
        retention_eligible && proxy_cleanup_complete && cleanup_evidence.is_some();
    // Screenshot evidence, not the optional provider bundle, is the durable
    // certification-retention boundary.  The screenshot manifest was bound
    // to the Prepared journal above and is revalidated by stage, commit,
    // publish, recovery claim, and finish.  Provider evidence is written only
    // after ownership has transferred and the final report is fixed.
    let mut retention_committed = if retention_commit_possible {
        match (|| -> anyhow::Result<()> {
            recovery.stage_suite_retention_manifest()?;
            recovery.commit_suite_plan_retention()?;
            let manifest_path = recovery.publish_committed_suite_retention_manifest()?;
            eprintln!(
                "Suite plans retained for certification review: review/publish them in the official Suite UI, then use a controlled deletion procedure; manifest={}",
                manifest_path.display()
            );
            Ok(())
        })() {
            Ok(()) => true,
            Err(error) => {
                errors.push(format!("suite-retention={error:#}"));
                // `commit_suite_plan_retention` transfers plan ownership and
                // compacts the journal before final publication. A later
                // publish failure is recoverable Retained state, not ordinary
                // cleanup: deleting here would lose exact ownership and make
                // a retry unsafe. Only Prepared failures retain plan IDs and
                // may fall back to exact deletion.
                if !recovery.suite_retention_committed()
                    && recovery.suite_retention_commit_resolution()
                        != nazoauthctl_conformance::SuiteRetentionCommitResolution::Ambiguous
                {
                    cleanup_unretained_suite(&mut recovery, &suite_client)?;
                }
                false
            }
        }
    } else {
        cleanup_unretained_suite(&mut recovery, &suite_client)?;
        false
    };
    // A crash or I/O failure may occur after the durable Retained transition
    // but before the pending manifest promotion reports success. Retry the
    // idempotent promotion before deriving the final report; a successful
    // retry is not a failed run.
    if !retention_committed && recovery.suite_retention_committed() {
        match recovery.publish_committed_suite_retention_manifest() {
            Ok(manifest_path) => {
                retention_committed = true;
                errors.retain(|error| !error.starts_with("suite-retention="));
                eprintln!(
                    "Suite plans retained for certification review: review/publish them in the official Suite UI, then use a controlled deletion procedure; manifest={}",
                    manifest_path.display()
                );
            }
            Err(error) => errors.push(format!("suite-retention-retry={error:#}")),
        }
    }
    if let Some(report) = report.as_mut() {
        report.orchestration_integrity.retention_eligible = retention_eligible;
        report.orchestration_integrity.retention_candidate_settled = retention_eligible
            && (recovery.suite_retention_committed()
                || recovery.suite_retention_manifest().is_some());
        report.orchestration_integrity.retention_committed = recovery.suite_retention_committed();
        report.orchestration_integrity.suite_resources_settled = recovery.suite_cleanup_complete();
        report.orchestration_integrity.cleanup_complete = !recovery.suite_retention_committed()
            && !retention_committed
            && report.orchestration_integrity.suite_resources_settled;
        if errors
            .iter()
            .any(|error| error.starts_with("suite-retention"))
        {
            report.errors.extend(
                errors
                    .iter()
                    .filter(|error| error.starts_with("suite-retention"))
                    .cloned(),
            );
        }
        report.local_success = report.errors.is_empty()
            && report.orchestration_integrity.all_modules_instantiated
            && report.orchestration_integrity.all_modules_settled
            && report.orchestration_integrity.suite_resources_settled;
    }
    // Ordinary evidence is intentionally post-retention: a writer failure
    // must not delete official Suite plans after their journal-owned
    // retention transition.  The report above is the exact report supplied to
    // a successful writer and to FinalOutput; a failed writer is represented
    // only by outer diagnostics and an absent receipt.
    let mut evidence = None;
    if let (Some(report), Some(directory), Some(cleanup_evidence)) = (
        report.as_ref(),
        invocation.evidence_directory.as_ref(),
        cleanup_evidence.as_ref(),
    ) {
        let runtime = evidence_runtime(&deployment.runtime);
        let identity = EvidenceBundleIdentity {
            run_jti: request_jti.clone(),
            deployment: EvidenceDeploymentIdentity {
                deployment_id: deployment.deployment_id.clone(),
                target_issuer: deployment.target_issuer.clone(),
                release: deployment.release.clone(),
                revision: deployment.revision.clone(),
                build_id: deployment.build_id.clone(),
                runtime: runtime.clone(),
            },
            source: EvidenceSourceIdentity::SignedOidfArtifact {
                suite_origin: suite_origin.to_string(),
                artifact: Box::new(driver_plan.artifact.clone()),
            },
            provider: Some(EvidenceProviderIdentity {
                deployment_id: deployment.deployment_id.clone(),
                runtime_instance_id: capability.capability.runtime_instance_id.clone(),
                runtime,
                release: capability.capability.embedded.release.clone(),
                runtime_revision: capability.capability.embedded.revision.clone(),
                protocol: capability.capability.embedded.protocol,
                build_id: capability.capability.embedded.build_id.clone(),
                capabilities: vec![
                    evidence_capability(&capability, &[baseline.clone(), apply_receipt.clone()]),
                    evidence_capability(&cleanup_evidence.capability, &cleanup_evidence.receipts),
                ],
                cleanup_complete,
            }),
            outer_cleanup_complete: cleanup_complete,
        };
        evidence = record_provider_evidence_result(
            || {
                write_private_provider_evidence_bundle(
                    report,
                    directory,
                    &identity,
                    recovery.tenant_resource_binding(),
                )
            },
            &mut errors,
        );
    }
    let retention = if retention_committed {
        recovery.suite_retention_manifest_receipt()?
    } else {
        None
    };
    if cleanup_evidence.is_some()
        && proxy_cleanup_complete
        && recovery.suite_cleanup_complete()
        && let Err(error) = recovery.finish()
    {
        // `finish` consumes the guard but leaves its durable journal in
        // place on failure. The already-published retention receipt
        // remains honest; report a structured incomplete local result
        // rather than deleting plans or losing stdout evidence.
        errors.push(format!("recovery-finish={error:#}"));
    }
    deployment_report.cleanup_complete = cleanup_complete;
    let success = errors.is_empty()
        && report.as_ref().is_some_and(|report| {
            conformance_acceptance_succeeds(
                report.local_success,
                report.acceptance_pass,
                report.matrix_expectations_satisfied,
            )
        });
    let output = FinalOutput {
        schema: 3,
        success,
        errors,
        report,
        retention,
        evidence,
        deployment: deployment_report,
    };
    serde_json::to_writer_pretty(io::stdout().lock(), &output)
        .context("failed to write the structured ordinary conformance report")?;
    writeln!(io::stdout()).context("failed to finish the structured conformance report")?;
    Ok(if success { 0 } else { 1 })
}

fn conformance_acceptance_succeeds(
    local_success: bool,
    acceptance_pass: bool,
    matrix_expectations_satisfied: bool,
) -> bool {
    local_success && acceptance_pass && matrix_expectations_satisfied
}

#[derive(Serialize)]
struct FinalOutput {
    schema: u32,
    success: bool,
    errors: Vec<String>,
    report: Option<nazoauthctl_conformance::ConformanceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention: Option<SuiteRetentionManifestReceipt>,
    evidence: Option<EvidenceBundleReceipt>,
    deployment: DeploymentReport,
}

#[derive(Serialize)]
struct RecoveredRetentionOutput {
    schema: u32,
    recovered: bool,
    retention: Vec<SuiteRetentionManifestReceipt>,
}

#[derive(Serialize)]
struct DeploymentReport {
    deployment_id: String,
    tenant_id: String,
    target_issuer: String,
    artifact_digest: String,
    artifact_revision: String,
    matrix_sha256: String,
    selected_groups: u32,
    selected_plans: u32,
    apply_task_jti: String,
    change_set_id: String,
    resource_manifest_sha256: String,
    trust_policy_resource_id: String,
    trust_policy_digest: String,
    applicant_id: String,
    client_count: u32,
    cleanup_complete: bool,
}

struct RunSecrets {
    tx_code: Option<Zeroizing<String>>,
    applicant_email: Zeroizing<String>,
    applicant_password: Zeroizing<String>,
    mtls_trust_anchor_pem: Zeroizing<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_signed_suite(
    mut materialized: nazoauthctl_conformance::TenantResourceMaterializedMatrix,
    suite_client: SuiteClient,
    token: BearerToken,
    secrets: RunSecrets,
    session: &nazoauthctl_core::ConformanceSession,
    invocation: &RunInvocation,
    suite_origin: &Origin,
    plan_lanes: BTreeMap<String, OidfDriverLane>,
    plan_resource_budgets: BTreeMap<String, OidfPlanResourceBudget>,
    selected_resource_budget: OidfPlanResourceBudget,
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
    ciba_bridge: Option<CibaUserApprovalBridge>,
    vp_evidence_verifier: Option<OpenId4VpEvidenceVerifier>,
) -> anyhow::Result<nazoauthctl_conformance::ConformanceReport> {
    if let Some(bridge) = &ciba_bridge {
        bridge
            .ensure_healthy()
            .context("CIBA user approval callback is unhealthy")?;
    }
    let binding = ConformanceBinding::openid4vc_trust_policy(
        materialized.trust_policy_resource_id(),
        materialized.trust_policy_digest(),
    )?;
    let target_origin = BrowserTargetOrigin::parse(session.target_issuer())?;
    let applicant_id = *materialized.applicant_id();
    let openid4vci_management_token = session
        .openid4vci_management_token()
        .context("failed to load the deployment OpenID4VCI management token")?;
    let openid4vp_management_token = session
        .openid4vp_management_token()
        .context("failed to load the deployment OpenID4VP management token")?;
    let review_screenshot_run_jti = recovery
        .lock()
        .map_err(|_| anyhow::anyhow!("ordinary recovery lock is poisoned"))?
        .tenant_resource_binding()
        .context("ordinary screenshot capture has no recovery binding")?
        .request_jti
        .clone();
    let review_screenshot_capture = invocation
        .capture_review_screenshots
        .then(|| {
            BrowserReviewScreenshotCapture::new(
                invocation
                    .evidence_directory
                    .as_ref()
                    .expect("CLI requires --evidence-dir for review screenshots")
                    .clone(),
                &review_screenshot_run_jti,
            )
        })
        .transpose()
        .context("review screenshot evidence directory must be root-owned and private")?;

    let selected = materialized
        .take_matrix()
        .select(&MatrixSelection {
            groups: invocation.groups.clone(),
            profiles: Vec::new(),
            plans: invocation.plans.clone(),
        })
        .context("requested selection is outside the signed artifact Matrix")?;
    let vp_evidence = invocation
        .capture_review_screenshots
        .then(|| {
            OpenId4VpEvidenceRunContext::new(
                &review_screenshot_run_jti,
                invocation.artifact_digest.as_str(),
                selected.digest.as_str(),
            )
        })
        .transpose()
        .context("OpenID4VP review evidence binding is invalid")?;
    let mut automation = Vec::with_capacity(invocation.jobs);
    for worker_index in 0..invocation.jobs {
        let browser = build_browser(
            invocation.webdriver.get(worker_index).map(String::as_str),
            session.target_issuer(),
            suite_origin,
        )?;
        let issuer: Arc<Mutex<dyn OpenId4VciIssuerDriver>> =
            Arc::new(Mutex::new(OpenId4VciIssuerClient::new(
                OpenId4VciIssuerConfig::new(
                    target_origin.clone(),
                    suite_origin.clone(),
                    applicant_id,
                    secrets.tx_code.clone(),
                    secrets.applicant_email.clone(),
                    secrets.applicant_password.clone(),
                    Duration::from_secs(30),
                )?,
                openid4vci_management_token.clone(),
                token.clone(),
            )?));
        let verifier_client = OpenId4VpVerifierClient::new(
            target_origin.clone(),
            suite_origin.clone(),
            openid4vp_management_token.clone(),
            Duration::from_secs(30),
            binding.clone(),
        )?;
        let verifier_client = match &vp_evidence_verifier {
            Some(evidence_verifier) => {
                verifier_client.with_evidence_verifier(evidence_verifier.clone())
            }
            None => verifier_client,
        };
        let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> = Arc::new(Mutex::new(verifier_client));
        automation.push(ConformanceAutomation {
            browser: Some(browser),
            review_screenshot_capture: review_screenshot_capture.clone(),
            vp_evidence: vp_evidence.clone(),
            verifier: Some(verifier),
            issuer: Some(issuer),
        });
    }
    let control = RunControl::default();
    let interrupt = control.clone();
    ctrlc::set_handler(move || interrupt.interrupt())
        .context("failed to install the conformance interrupt handler")?;
    let runner = ConformanceRunner::new(ConformanceRunConfig {
        client: suite_client,
        matrix: selected,
        target_origin: Some(target_origin),
        binding,
        poll_timeout: invocation.poll_timeout,
        control,
        plan_lanes,
        plan_resource_budgets,
        selected_resource_budget,
        jobs: invocation.jobs,
        automation,
        suite_resource_observer: Some(Arc::new(DurableSuiteObserver {
            recovery,
            retain_suite_plans_for_certification: invocation.retain_suite_plans_for_certification,
        })),
    })?;
    let summary = if io::stderr().is_terminal() {
        let mut renderer = TtyRenderer::new(io::stderr().lock());
        runner.run(&mut renderer)
    } else {
        let mut renderer = StableRenderer::new(io::stderr().lock());
        runner.run(&mut renderer)
    };
    if let Some(bridge) = &ciba_bridge {
        bridge
            .ensure_healthy()
            .context("CIBA user approval callback failed")?;
    }
    Ok(summary.report)
}

struct CibaUserApprovalCallback {
    public_url: Zeroizing<String>,
    callback_path: String,
    listen_addr: SocketAddr,
    approval_token: Zeroizing<String>,
}

fn prepare_ciba_user_approval_callback(
    invocation: &RunInvocation,
    requires_ciba: bool,
) -> anyhow::Result<Option<CibaUserApprovalCallback>> {
    let (Some(url), Some(listen_addr)) = (
        invocation.ciba_user_approval_callback_url.as_deref(),
        invocation.ciba_user_approval_listen,
    ) else {
        if requires_ciba {
            bail!(
                "selected CIBA plans require --ciba-user-approval-callback-url and --ciba-user-approval-listen"
            );
        }
        return Ok(None);
    };
    let public_url =
        Url::parse(url).context("--ciba-user-approval-callback-url must be a valid HTTPS URL")?;
    if public_url.scheme() != "https"
        || public_url.host_str().is_none()
        || public_url.path() == "/"
        || public_url.query().is_some()
        || public_url.fragment().is_some()
        || !public_url.username().is_empty()
        || public_url.password().is_some()
    {
        bail!(
            "--ciba-user-approval-callback-url must be an HTTPS URL with a non-root path and no query, fragment, or credentials"
        );
    }
    let callback_path = public_url.path().to_owned();
    let approval_token = Zeroizing::new(random_urlsafe_token(32));
    Ok(Some(CibaUserApprovalCallback {
        public_url: Zeroizing::new(format!(
            "{public_url}?approval_token={}&auth_req_id={{auth_req_id}}&action={{action}}",
            approval_token.as_str()
        )),
        callback_path,
        listen_addr,
        approval_token,
    }))
}

fn start_ciba_user_approval_bridge(
    callback: Option<CibaUserApprovalCallback>,
    session: &nazoauthctl_core::ConformanceSession,
    secrets: &RunSecrets,
) -> anyhow::Result<Option<CibaUserApprovalBridge>> {
    let Some(callback) = callback else {
        return Ok(None);
    };
    let issuer = Url::parse(session.target_issuer())
        .context("deployment target issuer is not a valid CIBA approval URL")?;
    let transport = Arc::new(
        HttpTransport::new(Duration::from_secs(30))
            .context("failed to initialize normal CIBA user-approval transport")?,
    );
    let approver = Arc::new(
        CibaUserApprovalClient::new(
            issuer,
            secrets.applicant_email.clone(),
            secrets.applicant_password.clone(),
            transport,
        )
        .context("failed to initialize normal CIBA user approval")?,
    );
    CibaUserApprovalBridge::start(
        callback.listen_addr,
        &callback.callback_path,
        callback.approval_token,
        approver,
    )
    .map(Some)
    .context("failed to start CIBA user-approval callback bridge")
}

fn random_urlsafe_token(bytes: usize) -> String {
    let mut material = vec![0u8; bytes];
    for value in &mut material {
        *value = rand::random();
    }
    URL_SAFE_NO_PAD.encode(material)
}

struct DurableSuiteObserver {
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
    retain_suite_plans_for_certification: bool,
}

impl SuiteResourceObserver for DurableSuiteObserver {
    fn retain_suite_plans_for_certification(&self) -> bool {
        self.retain_suite_plans_for_certification
    }

    fn plan_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| {
                recovery.begin_suite_create_with_retention(
                    origin.as_str(),
                    intent_id,
                    self.retain_suite_plans_for_certification,
                )
            })
            .map_err(|error| format!("failed to persist Suite plan create intent: {error:#}"))
    }

    fn plan_created(&self, origin: &Origin, intent_id: &str, plan_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| {
                recovery.record_suite_plan(origin.as_str(), intent_id, plan_id)
            })
            .map_err(|error| format!("failed to persist Suite plan allocation: {error:#}"))
    }

    fn module_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| {
                recovery.begin_suite_create_with_retention(
                    origin.as_str(),
                    intent_id,
                    self.retain_suite_plans_for_certification,
                )
            })
            .map_err(|error| format!("failed to persist Suite module create intent: {error:#}"))
    }

    fn module_created(&self, intent_id: &str, module_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| recovery.record_suite_module(intent_id, module_id))
            .map_err(|error| format!("failed to persist Suite module allocation: {error:#}"))
    }
}

fn lock_recovery(
    recovery: &Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
) -> anyhow::Result<std::sync::MutexGuard<'_, nazoauthctl_conformance::ConformanceRecoveryGuard>> {
    recovery
        .lock()
        .map_err(|_| anyhow::anyhow!("ordinary recovery lock is poisoned"))
}

fn take_recovery(
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
) -> anyhow::Result<nazoauthctl_conformance::ConformanceRecoveryGuard> {
    let recovery = Arc::try_unwrap(recovery)
        .map_err(|_| anyhow::anyhow!("ordinary recovery is still referenced by Suite execution"))?;
    recovery
        .into_inner()
        .map_err(|_| anyhow::anyhow!("ordinary recovery lock is poisoned"))
}

fn build_browser(
    endpoint: Option<&str>,
    target_issuer: &str,
    suite_origin: &Origin,
) -> anyhow::Result<Arc<Mutex<dyn BrowserAutomation>>> {
    let target = BrowserTargetOrigin::parse(target_issuer)?;
    let policy = BrowserPolicy::new(target, suite_origin.clone())?;
    if let Some(endpoint) = endpoint {
        let endpoint = WebDriverEndpoint::parse(endpoint)?;
        let mut driver = WebDriverClient::connect(endpoint, Duration::from_secs(30))?;
        driver.start_chrome()?;
        Ok(Arc::new(Mutex::new(BrowserExecutor::new(driver, policy))))
    } else {
        let driver = ManagedWebDriver::start_default(Duration::from_secs(30))?;
        Ok(Arc::new(Mutex::new(BrowserExecutor::new(driver, policy))))
    }
}

struct CleanupEvidence {
    capability: TenantResourceCapabilitySession,
    receipts: Vec<TenantResourceReceiptResult>,
}

fn cleanup_change_set_id(request_jti: &str, phase: &str, capability_sha256: &str) -> String {
    let generation = capability_sha256.chars().take(16).collect::<String>();
    format!("{request_jti}-cleanup-{phase}-{generation}")
}

fn suite_retention_manifest(
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
    report: &nazoauthctl_conformance::ConformanceReport,
    artifact_digest: &str,
    matrix_sha256: &str,
    review_screenshot_manifest: Option<&nazoauthctl_conformance::ReviewScreenshotManifestReceipt>,
) -> anyhow::Result<SuiteRetentionManifest> {
    let binding = recovery
        .tenant_resource_binding()
        .context("missing ordinary recovery binding")?;
    let plans = report
        .plans
        .iter()
        .map(|plan| {
            let suite_plan_id = plan
                .suite_plan_id
                .clone()
                .context("settled retained report has no Suite plan ID")?;
            Ok(SuiteRetentionPlan {
                matrix_plan_id: plan.matrix_plan_id.clone(),
                suite_plan_id,
                plan_name: plan.plan_name.clone(),
                plan_alias_sha256: SuiteRetentionManifest::plan_alias_sha256(&plan.matrix_plan_id),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(SuiteRetentionManifest {
        schema: if report.review_pending { 2 } else { 1 },
        suite_origin: report.suite_origin.clone(),
        artifact_digest: artifact_digest.to_owned(),
        matrix_sha256: matrix_sha256.to_owned(),
        deployment_id: binding.deployment_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        run_id: binding.request_jti.clone(),
        review_screenshot_manifest: review_screenshot_manifest.map(|manifest| {
            SuiteRetentionScreenshotManifest {
                path: manifest.path.clone(),
                sha256: manifest.sha256.clone(),
            }
        }),
        deferred_review_pending: report
            .modules
            .iter()
            .filter_map(|module| {
                let pending = module.deferred_review_pending.as_ref()?;
                Some(SuiteRetentionDeferredReview {
                    matrix_plan_id: module.matrix_plan_id.clone(),
                    suite_plan_id: module.suite_plan_id.clone(),
                    module_id: module.module_id.clone()?,
                    test_name: module.test_name.clone(),
                    variant: module.variant.clone(),
                    placeholder_path: pending.placeholder_path.clone(),
                    marker: pending.marker,
                    obligation_index: pending.obligation_index,
                })
            })
            .collect(),
        plans,
    })
}

fn suite_retention_manifest_path(
    evidence_directory: &Path,
    manifest: &SuiteRetentionManifest,
) -> PathBuf {
    evidence_directory.join(format!("retained-suite-{}.json", manifest.run_id))
}

fn cleanup_unretained_suite(
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
    suite_client: &SuiteClient,
) -> anyhow::Result<()> {
    if recovery.suite_cleanup_complete() {
        return Ok(());
    }
    recovery.discard_prepared_suite_retention_staging()?;
    let suite = recovery
        .suite_recovery()
        .context("ordinary Suite recovery state is incomplete")?;
    recover_suite_resources(suite_client, suite).map_err(|error| anyhow::anyhow!(error))?;
    recovery.mark_suite_cleanup_complete()
}

fn cleanup_run_resources<T>(
    client: &TenantResourceClient<T>,
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<CleanupEvidence>
where
    T: nazoauthctl_core::tenant_resources::TenantResourceHttpTransport,
{
    let capability = client.discover_capability()?;
    let cleanup_capability_sha256 = capability.compact_sha256();
    let request_jti = recovery
        .tenant_resource_binding()
        .context("missing ordinary recovery binding")?
        .request_jti
        .clone();
    let listed = client.enumerate(
        &capability,
        &cleanup_change_set_id(&request_jti, "observe", &cleanup_capability_sha256),
        recovery
            .tenant_resource_binding()
            .context("missing ordinary recovery binding")?
            .change_set_sha256
            .as_str(),
        Vec::new(),
    )?;
    let mut receipts = vec![listed.clone()];
    let bound = recovery
        .tenant_resource_binding()
        .context("missing ordinary recovery binding")?
        .resource_identities
        .clone();
    if listed.receipt().resources.iter().any(|candidate| {
        bound.iter().any(|identity| {
            identity.kind == candidate.kind
                && identity.resource_id == candidate.resource_id
                && identity.digest != candidate.digest
        })
    }) {
        bail!("run-scoped tenant resource identity reappeared with a different digest");
    }
    let present = listed
        .receipt()
        .resources
        .iter()
        .filter(|candidate| {
            bound.iter().any(|identity| {
                identity.kind == candidate.kind
                    && identity.resource_id == candidate.resource_id
                    && identity.digest == candidate.digest
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    recovery.record_tenant_resource_enumeration(present.clone())?;
    if !present.is_empty() {
        let current = listed.receipt().resources.clone();
        let final_active = current
            .iter()
            .filter(|candidate| {
                !present.iter().any(|identity| {
                    identity.kind == candidate.kind
                        && identity.resource_id == candidate.resource_id
                        && identity.digest == candidate.digest
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let revoke_change_set_sha256 =
            nazoauthctl_core::tenant_resources::tenant_resource_manifest_sha256(&present)?;
        let final_digest =
            nazoauthctl_core::tenant_resources::tenant_resource_manifest_sha256(&final_active)?;
        let revoke = client.revoke(
            &capability,
            &cleanup_change_set_id(&request_jti, "revoke", &cleanup_capability_sha256),
            &revoke_change_set_sha256,
            present.clone(),
            &final_digest,
        )?;
        if revoke.receipt().resources.len() != present.len()
            || revoke
                .receipt()
                .resources
                .iter()
                .any(|received| !present.iter().any(|expected| expected == received))
        {
            bail!("tenant-resource Revoke receipt does not match the observed run resources");
        }
        for identity in &present {
            recovery.record_tenant_resource_revoke(
                identity,
                nazoauthctl_conformance::TenantResourceRevokeOutcome::Revoked,
            )?;
        }
        receipts.push(revoke);
    }
    if !recovery.tenant_resource_cleanup_complete() {
        bail!("ordinary cleanup obligations remain pending");
    }
    Ok(CleanupEvidence {
        capability,
        receipts,
    })
}

fn recover_pending_runs(
    session: &nazoauthctl_core::ConformanceSession,
    store: &ConformanceRecoveryStore,
    suite_client: &SuiteClient,
) -> anyhow::Result<Vec<SuiteRetentionManifestReceipt>> {
    let pending = store.claim_pending()?;
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let mut failures = Vec::new();
    let mut retained = Vec::new();
    for mut recovery in pending {
        let Some(binding) = recovery.tenant_resource_binding().cloned() else {
            // Legacy journals remain readable, but this ordinary command must
            // never revive the removed lease management API.
            failures.push("legacy-read-only: use the release that created this journal".to_owned());
            continue;
        };
        let result = (|| -> anyhow::Result<Option<SuiteRetentionManifestReceipt>> {
            // Retained is a durable transfer of exact Suite-plan ownership.
            // Its commit precondition already proves provider, proxy, and
            // ordinary cleanup.  A recovery must therefore publish/read the
            // retained receipt and stop before constructing any live Apply
            // client; retrying an Apply here could create a second resource
            // set after certification plans have been preserved.
            if retained_recovery_stops_before_live_apply(recovery.suite_retention_committed()) {
                recovery.publish_committed_suite_retention_manifest()?;
                let receipt = recovery.suite_retention_manifest_receipt()?;
                if recovery.suite_cleanup_complete() && recovery.proxy_cleanup_complete() {
                    recovery.finish()?;
                }
                return Ok(receipt);
            }
            if recovery.tenant_resource_abort_uncommitted_intent() {
                recovery.abort_uncommitted_tenant_resource()?;
                return Ok(None);
            }
            let client = TenantResourceClient::with_curl(
                session.tenant_resource_client_config(&binding.tenant_id)?,
            )?;
            if recovery.tenant_resource_receipt().is_none() {
                let manifest = binding
                    .manifest_path
                    .as_ref()
                    .context("pending Apply recovery has no private manifest path")?;
                let manifest = std::fs::read(manifest)
                    .context("failed to read the persisted private Apply manifest")?;
                let prepared = client.restore_from_persisted(
                    &binding.capability_jws,
                    &binding.task_jws,
                    &binding.capability_sha256,
                    &binding.task_sha256,
                    &binding.request_sha256,
                    binding.operation,
                    &binding.request_jti,
                    &binding.change_set_id,
                    &binding.change_set_sha256,
                    Some(&manifest),
                )?;
                let receipt = match client.execute_prepared_live(&prepared) {
                    Ok(receipt) => receipt,
                    Err(error) if is_deterministic_uncommitted_rejection(&error) => {
                        // The ordinary producer installs proxy trust only
                        // after persisting a receipt.  With no receipt this is
                        // a marker for an action that was never reached.
                        if !recovery.proxy_cleanup_complete() {
                            recovery.mark_proxy_cleanup_complete()?;
                        }
                        recovery.abort_uncommitted_tenant_resource()?;
                        return Ok(None);
                    }
                    Err(error) => return Err(error.into()),
                };
                recovery.record_tenant_resource_receipt(
                    TenantResourceReceiptIdentity::from_verified_receipt(
                        receipt.receipt(),
                        &receipt.receipt_sha256(),
                    )?,
                )?;
            }
            if !recovery.suite_cleanup_complete() {
                recovery.discard_prepared_suite_retention_staging()?;
                let suite = recovery
                    .suite_recovery()
                    .context("ordinary recovery Suite state is incomplete")?;
                recover_suite_resources(suite_client, suite)
                    .map_err(|error| anyhow::anyhow!(error))?;
                recovery.mark_suite_cleanup_complete()?;
            }
            if !recovery.proxy_cleanup_complete() {
                let proxy = binding
                    .proxy
                    .as_ref()
                    .context("ordinary recovery proxy state is incomplete")?;
                ProxyTrustGuard::recover(&proxy.bundle_path, &proxy.reload_executable)?;
                recovery.mark_proxy_cleanup_complete()?;
            }
            cleanup_run_resources(&client, &mut recovery)?;
            let receipt = recovery.suite_retention_manifest_receipt()?;
            if recovery.suite_cleanup_complete() && recovery.proxy_cleanup_complete() {
                recovery.finish()?;
            }
            Ok(receipt)
        })();
        match result {
            Ok(Some(receipt)) => retained.push(receipt),
            Ok(None) => {}
            Err(error) => failures.push(format!("{}: {error:#}", binding.request_jti)),
        }
    }
    if failures.is_empty() {
        Ok(retained)
    } else {
        bail!(
            "pending conformance cleanup could not be recovered: {}",
            failures.join("; ")
        )
    }
}

fn is_deterministic_uncommitted_rejection(error: &TenantResourceClientError) -> bool {
    matches!(
        error,
        TenantResourceClientError::InvalidRequest(_)
            | TenantResourceClientError::Unauthorized(_)
            | TenantResourceClientError::Forbidden(_)
    )
}

fn evidence_runtime(
    runtime: &nazoauthctl_core::ConformanceRuntimeEvidence,
) -> EvidenceRuntimeIdentity {
    match runtime {
        nazoauthctl_core::ConformanceRuntimeEvidence::OciImage { digest } => {
            EvidenceRuntimeIdentity::OciImage {
                digest: digest.clone(),
            }
        }
        nazoauthctl_core::ConformanceRuntimeEvidence::HostBinary { sha256 } => {
            EvidenceRuntimeIdentity::HostBinary {
                sha256: sha256.clone(),
            }
        }
    }
}

// Keep the provider-bundle failure boundary explicit and independently
// testable.  Retention ownership is committed before this callback and is
// intentionally not an input here, so a writer failure cannot select Suite
// cleanup or change a retained-plan decision.
fn record_provider_evidence_result<F, E>(
    writer: F,
    errors: &mut Vec<String>,
) -> Option<EvidenceBundleReceipt>
where
    F: FnOnce() -> Result<EvidenceBundleReceipt, E>,
    E: std::fmt::Display,
{
    match writer() {
        Ok(receipt) => Some(receipt),
        Err(error) => {
            errors.push(format!("evidence={error}"));
            None
        }
    }
}

fn retained_recovery_stops_before_live_apply(retention_committed: bool) -> bool {
    retention_committed
}

fn evidence_capability(
    capability: &TenantResourceCapabilitySession,
    receipts: &[TenantResourceReceiptResult],
) -> EvidenceProviderCapability {
    EvidenceProviderCapability {
        capability_compact_sha256: capability.compact_sha256(),
        capability_jti: capability.capability.jti.clone(),
        tenant_id: capability.capability.tenant_id.clone(),
        revision: capability.capability.revision,
        resource_manifest_sha256: capability.capability.resource_manifest_sha256.clone(),
        receipts: receipts
            .iter()
            .map(|result| {
                let receipt = result.receipt();
                EvidenceProviderReceipt {
                    action: receipt.operation,
                    compact_sha256: result.receipt_sha256(),
                    jti: receipt.jti.clone(),
                    request_sha256: receipt.request_sha256.clone(),
                    deployment_id: receipt.deployment_id.clone(),
                    tenant_id: receipt.tenant_id.clone(),
                    capability_jti: receipt.capability_jti.clone(),
                    capability_compact_sha256: receipt.capability_sha256.clone(),
                    expected_revision: receipt.expected_revision,
                    revision: receipt.revision,
                    change_set_id: receipt.change_set_id.clone(),
                    change_set_sha256: receipt.change_set_sha256.clone(),
                    baseline_manifest_sha256: receipt.baseline_manifest_sha256.clone(),
                    resource_manifest_sha256: receipt.resource_manifest_sha256.clone(),
                    outcome: receipt.outcome.clone(),
                    audit_sequence: receipt.audit_sequence,
                    audit_previous_sha256: receipt.audit_previous_sha256.clone(),
                }
            })
            .collect(),
    }
}

fn resolve_token(
    invocation: &mut RunInvocation,
    origin: &Origin,
) -> anyhow::Result<(BearerToken, bool)> {
    if let Some(mut value) = invocation.token.take() {
        eprintln!("warning: --token is visible in argv and may be retained by shell history");
        let token = BearerToken::new(value.as_str().to_owned())?;
        value.zeroize();
        return Ok((token, false));
    }
    if let Some(path) = &invocation.token_file {
        return Ok((BearerToken::read_file(path)?, false));
    }
    if invocation.token_stdin {
        let mut bytes = Zeroizing::new(Vec::new());
        io::stdin()
            .take(MAX_STDIN_TOKEN_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to read the Suite token from stdin")?;
        if bytes.len() as u64 > MAX_STDIN_TOKEN_BYTES {
            bail!("Suite token from stdin exceeds the size limit");
        }
        let value = std::str::from_utf8(&bytes).context("Suite token from stdin is not UTF-8")?;
        return Ok((BearerToken::new(value.to_owned())?, false));
    }
    if let Some(fd) = invocation.token_fd {
        return Ok((CredentialStore::read_descriptor(fd)?, false));
    }
    let store = CredentialStore::new(credential_root()?)?;
    if let Some(token) = store.load(origin)? {
        return Ok((token, false));
    }
    if !io::stdin().is_terminal() {
        bail!("no Suite API token is available; use a token option in non-TTY environments");
    }
    let value = rpassword::prompt_password("OpenID Foundation Conformance Suite API Token:")?;
    Ok((BearerToken::new(value)?, true))
}

fn offer_credential_persistence(origin: &Origin, token: &BearerToken) -> anyhow::Result<()> {
    if !io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("Save this token securely for {}? [y/N] ", origin.as_str());
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let save = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    answer.zeroize();
    if save {
        CredentialStore::new(credential_root()?)?.save(origin, token)?;
    }
    Ok(())
}

fn credential_root() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    let root = env::var_os("APPDATA")
        .map(PathBuf::from)
        .context("APPDATA is not set")?;
    #[cfg(not(windows))]
    let root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .context("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(root.join("nazoauthctl").join("conformance-credentials"))
}

fn current_unix_time() -> anyhow::Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system clock exceeds the supported range")
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn select_artifact_matrix_for_run(
    mut matrix: OidfArtifactMatrix,
    selected_plan_ids: &BTreeSet<(String, String)>,
) -> anyhow::Result<OidfArtifactMatrix> {
    let mut retained = BTreeSet::new();
    matrix.groups.retain_mut(|group| {
        group.plans.retain(|plan| {
            let selected = selected_plan_ids.contains(&(group.id.clone(), plan.id.clone()));
            if selected {
                retained.insert((group.id.clone(), plan.id.clone()));
            }
            selected
        });
        !group.plans.is_empty()
    });
    if retained != *selected_plan_ids {
        bail!("selected signed Matrix plans changed before materialization");
    }
    Ok(matrix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nazoauthctl_conformance::{
        CryptoPolicy, OIDF_MATRIX_SCHEMA_VERSION, OidfArtifactMatrixGroup, OidfArtifactMatrixPlan,
        OidfArtifactMatrixVariant, OidfPlanResourceBudget,
    };
    use serde_json::json;

    fn artifact_group(id: &str, plan_ids: &[&str]) -> OidfArtifactMatrixGroup {
        OidfArtifactMatrixGroup {
            id: id.to_owned(),
            profile: id.to_owned(),
            variant: OidfArtifactMatrixVariant {
                id: "default".to_owned(),
                values: BTreeMap::new(),
            },
            required_roles: Vec::new(),
            plans: plan_ids
                .iter()
                .map(|plan_id| OidfArtifactMatrixPlan {
                    id: (*plan_id).to_owned(),
                    plan: format!("suite-{plan_id}"),
                    driver_handler: "default".to_owned(),
                    resource_budget: OidfPlanResourceBudget {
                        modules: 1,
                        clients: 1,
                        wall_clock_seconds: 60,
                    },
                    config_template: json!({"plan": plan_id}),
                    variant: BTreeMap::new(),
                    required_capabilities: Vec::new(),
                    expected_results: BTreeMap::new(),
                    required_roles: Vec::new(),
                    secret_bindings: BTreeMap::new(),
                    crypto: CryptoPolicy::default(),
                })
                .collect(),
        }
    }

    #[test]
    fn materialization_matrix_contains_only_the_signed_selected_plans() {
        let matrix = OidfArtifactMatrix {
            schema: OIDF_MATRIX_SCHEMA_VERSION,
            name: "matrix".to_owned(),
            openid4vc_credential_datasets: BTreeMap::new(),
            openid4vc_suite_mdoc_trust_anchor_pem: "anchor".to_owned(),
            groups: vec![
                artifact_group("oidc", &["p001", "unselected-dcr"]),
                artifact_group("ciba", &["unselected-ciba"]),
            ],
        };
        let selected = BTreeSet::from([("oidc".to_owned(), "p001".to_owned())]);

        let filtered = select_artifact_matrix_for_run(matrix, &selected).unwrap();
        assert_eq!(filtered.groups.len(), 1);
        assert_eq!(filtered.groups[0].id, "oidc");
        assert_eq!(filtered.groups[0].plans.len(), 1);
        assert_eq!(filtered.groups[0].plans[0].id, "p001");

        let missing = BTreeSet::from([("oidc".to_owned(), "missing-signed-plan".to_owned())]);
        assert!(select_artifact_matrix_for_run(filtered, &missing).is_err());
    }

    #[test]
    fn cleanup_change_sets_are_scoped_to_the_discovered_capability_generation() {
        let first = cleanup_change_set_id(
            "tenant-resource-01a00401-6fee-7063-94bd-26c86029d4c2",
            "observe",
            &"1".repeat(64),
        );
        let second = cleanup_change_set_id(
            "tenant-resource-01a00401-6fee-7063-94bd-26c86029d4c2",
            "observe",
            &"2".repeat(64),
        );

        assert_ne!(first, second);
        assert!(first.len() <= 128);
    }

    #[test]
    fn ordinary_success_requires_accepted_suite_outcomes_and_matrix_expectations() {
        assert!(conformance_acceptance_succeeds(true, true, true));
        assert!(!conformance_acceptance_succeeds(false, true, true));
        assert!(!conformance_acceptance_succeeds(true, false, true));
        assert!(!conformance_acceptance_succeeds(true, true, false));
    }

    #[test]
    fn provider_evidence_failure_is_diagnostic_only_after_retention_commit() {
        let mut errors = Vec::new();
        let retention_committed = true;
        let evidence = record_provider_evidence_result(
            || -> Result<EvidenceBundleReceipt, &'static str> { Err("injected writer failure") },
            &mut errors,
        );
        assert!(retention_committed);
        assert!(evidence.is_none());
        assert_eq!(errors, vec!["evidence=injected writer failure"]);
    }

    #[test]
    fn retained_recovery_never_reenters_live_apply() {
        assert!(retained_recovery_stops_before_live_apply(true));
        assert!(!retained_recovery_stops_before_live_apply(false));
    }

    #[test]
    fn retained_suite_manifest_path_uses_the_recovery_binding_jti() {
        let local_request_jti = "request-local-0123456789abcdef";
        let binding_request_jti = "tenant-request-0123456789abcdef";
        assert_ne!(local_request_jti, binding_request_jti);
        let manifest = SuiteRetentionManifest {
            schema: 1,
            suite_origin: "https://www.certification.openid.net".to_owned(),
            artifact_digest: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            deployment_id: "deployment-a".to_owned(),
            tenant_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            run_id: binding_request_jti.to_owned(),
            review_screenshot_manifest: None,
            deferred_review_pending: Vec::new(),
            plans: Vec::new(),
        };

        let path = suite_retention_manifest_path(Path::new("/evidence"), &manifest);

        assert_eq!(
            path,
            Path::new("/evidence").join(format!("retained-suite-{binding_request_jti}.json"))
        );
        assert!(!path.to_string_lossy().contains(local_request_jti));
    }
}
