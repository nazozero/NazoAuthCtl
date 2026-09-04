//! Ordinary tenant-resource backed OIDF orchestration.
//!
//! This is the only producer path for `conformance run`. The signed artifact
//! owns executable Matrix facts; NazoAuth owns ordinary tenant resources; the
//! Suite remains an external test runner. No conformance lease or Suite-only
//! NazoAuth management endpoint is used here.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use nazo_operator_protocol::{ControlOperationPayload, ControlResultData, ControlTenantBoundary};
use nazoauthctl_conformance::{
    ArtifactMaterializationBinding, BearerToken, BrowserAutomation, BrowserExecutor, BrowserPolicy,
    BrowserReviewScreenshotCapture, BrowserTargetOrigin, CibaUserApprovalClient, ClientConfig,
    ConformanceAutomation, ConformanceBinding, ConformanceRecoveryStore, ConformanceRunConfig,
    ConformanceRunner, CredentialStore, DescriptorMaterializer, EvidenceBundleIdentity,
    EvidenceBundleReceipt, EvidenceControlIdentity, EvidenceControlOperation,
    EvidenceDeploymentIdentity, EvidenceRuntimeIdentity, EvidenceSourceIdentity, GroupStatus,
    HttpRequest, HttpTransport, ManagedWebDriver, MatrixSelection, ModuleOutcome,
    OidfArtifactMatrix, OidfDriverAutomation, OidfDriverLane, OidfPlanResourceBudget,
    OidfPlanSelection, OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver,
    OpenId4VpVerifier, OpenId4VpVerifierClient, Origin, OutputLanguage, ProgressActivity,
    ProgressSink, ProxyTrustGuard, RunControl, StableRenderer, SuiteClient, SuiteClientError,
    SuiteResourceObserver, SuiteRetentionDeferredReview, SuiteRetentionManifest,
    SuiteRetentionManifestReceipt, SuiteRetentionPlan, SuiteRetentionScreenshotManifest,
    TenantResourceApplyOutput, TenantResourceControlOperation, TenantResourceRecoveryBinding,
    TenantResourceRecoveryPhase, TerminalTheme, Transport, TtyRenderer, bundled_oidf_matrix,
    open_bundled_oidf_driver_plan, recover_suite_resources, write_private_control_evidence_bundle,
    write_review_screenshot_manifest,
};
use serde::Serialize;
use url::Url;
use zeroize::Zeroizing;

use super::RunInvocation;

const MAX_STDIN_TOKEN_BYTES: u64 = 16 * 1024;
pub(super) fn execute(invocation: RunInvocation) -> anyhow::Result<i32> {
    let language = super::output_language();
    let control = RunControl::default();
    let user_interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_notice = match language {
        OutputLanguage::Chinese => "收到 Ctrl+C，正在终止测试并清理临时资源……",
        OutputLanguage::English => {
            "Ctrl+C received; stopping the test and cleaning up temporary resources..."
        }
    };
    if io::stderr().is_terminal() {
        execute_with_progress(
            invocation,
            &mut TtyRenderer::localized(io::stderr(), language),
            language,
            control,
            user_interrupted,
            interrupt_notice,
        )
    } else {
        execute_with_progress(
            invocation,
            &mut StableRenderer::localized(io::stderr(), language),
            language,
            control,
            user_interrupted,
            interrupt_notice,
        )
    }
}

fn execute_with_progress<S: ProgressSink>(
    invocation: RunInvocation,
    progress: &mut S,
    language: OutputLanguage,
    control: RunControl,
    user_interrupted: Arc<AtomicBool>,
    interrupt_notice: &'static str,
) -> anyhow::Result<i32> {
    progress.activity(&ProgressActivity::OpeningDeployment);
    let session = nazoauthctl_core::ConformanceSession::open(invocation.instance.as_deref())
        .context("deployment is not ready for ordinary conformance orchestration")?;
    let suite_origin = Origin::parse_public_suite(session.oidf_suite_origin())
        .map_err(|error| anyhow::anyhow!("configured OIDF Suite origin is invalid: {error}"))?;
    let deployment = session.deployment_evidence();
    let recovery_directory = session.recovery_directory()?;
    let recovery_store =
        ConformanceRecoveryStore::open(&recovery_directory, &deployment.deployment_id)?;
    let _orchestration_lock = recovery_store.acquire_orchestration_lock()?;

    progress.activity(&ProgressActivity::LoadingMatrix);
    let now = current_unix_time()?;
    let driver_plan = open_bundled_oidf_driver_plan(
        OidfPlanSelection {
            groups: invocation.groups.clone(),
            plans: invocation.plans.clone(),
        },
        &suite_origin,
        now,
    )
    .context("bundled OIDF Matrix cannot be opened")?;
    let requires_browser = driver_plan
        .plans
        .iter()
        .any(|plan| !matches!(plan.driver_handler.automation, OidfDriverAutomation::None));
    let captures_review_screenshots = driver_plan.plans.iter().any(|plan| {
        matches!(
            plan.driver_handler.automation,
            OidfDriverAutomation::Openid4vp { .. }
        )
    });
    let artifact_digest = driver_plan.artifact.driver_manifest_sha256.clone();

    progress.activity(&ProgressActivity::AuthenticatingSuite);
    let (suite_client, token) = authenticate_suite(&invocation, &suite_origin, language)?;
    progress.activity(&ProgressActivity::RecoveringPreviousRun);
    let recovered_retention = recover_pending_runs(&session, &recovery_store, &suite_client)?;
    if !recovered_retention.is_empty() {
        let theme = TerminalTheme::detect(io::stdout().is_terminal() && !invocation.json);
        write_recovered_retention_output(
            io::stdout().lock(),
            &recovered_retention,
            language,
            invocation.json,
            theme,
        )?;
        progress.activity(&ProgressActivity::Finished);
        return Ok(0);
    }
    let matrix: OidfArtifactMatrix =
        bundled_oidf_matrix().context("bundled OIDF Matrix is malformed")?;
    let selected_plan_ids = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.group_id.clone(), plan.plan_id.clone()))
        .collect::<BTreeSet<_>>();
    let matrix = select_artifact_matrix_for_run(matrix, &selected_plan_ids)?;
    let plan_lanes = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.plan_id.clone(), plan.driver_handler.lane))
        .collect::<BTreeMap<_, _>>();
    if plan_lanes.len() != driver_plan.plans.len() {
        bail!("signed driver plan contains duplicate Matrix plan IDs");
    }
    let plan_resource_budgets = driver_plan
        .plans
        .iter()
        .map(|plan| (plan.plan_id.clone(), plan.resource_budget.clone()))
        .collect::<BTreeMap<_, _>>();
    if plan_resource_budgets.len() != driver_plan.plans.len() {
        bail!("signed driver plan contains duplicate Matrix plan IDs");
    }
    let mut selected_resource_budget = driver_plan.selected_resource_budget.clone();
    // The official Suite owns each plan's live module list and may add tests
    // without changing the plan identity. Bound the run by the artifact-wide
    // module ceiling instead of treating an old per-plan count as immutable.
    selected_resource_budget.modules = driver_plan.artifact.resource_bounds.max_modules;
    let request_jti = format!("request-{}", hex(rand::random::<[u8; 16]>()));
    let evidence_directory = create_evidence_directory(&recovery_directory, &request_jti)?;
    let ephemeral_tenant =
        EphemeralTenant::new(&invocation.tenant_id, session.oidf_tenant_domain())?;
    progress.activity(&ProgressActivity::PreparingTenant {
        issuer: ephemeral_tenant.issuer.clone(),
    });
    let materialization_now = current_unix_time()?;
    if materialization_now > driver_plan.latest_execution_start_at {
        bail!("signed artifact no longer has enough validity remaining for the selected run");
    }
    let requires_ciba = driver_plan
        .plans
        .iter()
        .any(|entry| entry.driver_handler.lane == OidfDriverLane::Ciba);
    let dynamic_registration_initial_access_token = session
        .dynamic_registration_initial_access_token(&invocation.tenant_id)
        .context("failed to derive the run tenant RFC 7591 initial access token")?;
    let prepared = DescriptorMaterializer::prepare_tenant_resources_from_artifact_matrix(
        &matrix,
        ArtifactMaterializationBinding {
            artifact_source_release: &driver_plan.artifact.revision,
            artifact_source_digest: &artifact_digest,
            raw_matrix_sha256: &driver_plan.artifact.matrix_sha256,
            target_issuer: &ephemeral_tenant.issuer,
            suite_origin: &suite_origin,
            request_jti: &request_jti,
            dynamic_registration_initial_access_token: Some(
                dynamic_registration_initial_access_token.as_str(),
            ),
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
    };

    let private_manifest_path = recovery_directory.join(format!("material-{request_jti}.json"));
    manifest
        .write_private(&private_manifest_path)
        .context("failed to durably persist private Apply material")?;
    let tenant_create_expected_revision = directory_revision(&session)?;
    let recovery = match recovery_store.begin_ordinary_run(TenantResourceRecoveryBinding {
        deployment_id: deployment.deployment_id.clone(),
        tenant_id: invocation.tenant_id.clone(),
        tenant_domain: session.oidf_tenant_domain().to_owned(),
        realm_id: ephemeral_tenant.realm_id.clone(),
        organization_id: ephemeral_tenant.organization_id.clone(),
        run_id: request_jti.clone(),
        tenant_create_expected_revision,
        manifest_path: Some(private_manifest_path.clone()),
        material_sha256: Some(manifest.raw_sha256().to_owned()),
        proxy: None,
        vp_evidence_trust_anchor: None,
        resource_identities: manifest.resource_identities().to_vec(),
    }) {
        Ok(recovery) => Arc::new(Mutex::new(recovery)),
        Err(error) => {
            let cleanup = ConformanceRecoveryStore::remove_private_material(&private_manifest_path);
            return match cleanup {
                Ok(()) => Err(error).context("failed to persist ordinary recovery intent"),
                Err(cleanup_error) => Err(anyhow::anyhow!(
                    "failed to persist ordinary recovery intent: {error:#}; failed to remove private Apply material: {cleanup_error:#}"
                )),
            };
        }
    };
    let setup_result = (|| -> anyhow::Result<_> {
        progress.activity(&ProgressActivity::CreatingTenant {
            issuer: ephemeral_tenant.issuer.clone(),
        });
        let deployment_trust_anchor =
            provision_ephemeral_tenant(&session, &ephemeral_tenant, &recovery)
                .context("failed to provision the run-scoped OIDF tenant")?;
        progress.activity(&ProgressActivity::CheckingTenant {
            issuer: ephemeral_tenant.issuer.clone(),
        });
        probe_ephemeral_tenant(&ephemeral_tenant.issuer).context(
            "the temporary tenant is not publicly reachable; verify wildcard DNS, TLS, and host routing for the configured OIDF tenant domain",
        )?;
        progress.activity(&ProgressActivity::ApplyingResources);
        let baseline = session
            .execute_control_operation(
                ControlOperationPayload::TenantResourceEnumerate {
                    tenant_id: invocation.tenant_id.clone(),
                    selectors: Vec::new(),
                },
                None,
                |completion| {
                    lock_recovery(&recovery)?.record_terminal_completion(
                        TenantResourceRecoveryPhase::BaselineEnumerated,
                        control_operation(completion),
                    )?;
                    Ok(())
                },
            )
            .context("failed to enumerate the tenant-resource baseline")?;
        let baseline = successful_control_result(baseline, "baseline Enumerate")?;
        let ControlResultData::TenantResourceEnumerate {
            resources: baseline_resources,
            ..
        } = baseline
        else {
            bail!("baseline ControlOperation returned the wrong typed result");
        };
        let mut final_active = baseline_resources;
        for delta in manifest.resource_identities() {
            if let Some(existing) = final_active.iter().find(|existing| {
                existing.kind == delta.kind && existing.resource_id == delta.resource_id
            }) {
                if existing.digest != delta.digest {
                    bail!("run-unique tenant resource conflicts with active baseline");
                }
            } else {
                final_active.push(delta.clone());
            }
        }
        final_active.sort_by(|left, right| {
            (left.kind, left.resource_id.as_str()).cmp(&(right.kind, right.resource_id.as_str()))
        });
        let apply = session
            .execute_control_operation(
                ControlOperationPayload::TenantResourceApply {
                    tenant_id: invocation.tenant_id.clone(),
                    resources: manifest.resource_identities().to_vec(),
                },
                Some(manifest.bytes().as_bytes().to_vec()),
                |completion| {
                    lock_recovery(&recovery)?.record_terminal_completion(
                        TenantResourceRecoveryPhase::Applied,
                        control_operation(completion),
                    )?;
                    Ok(())
                },
            )
            .context("ordinary tenant-resource Apply failed")?;
        let apply = successful_control_completion(apply, "Apply")?;
        let apply_output = TenantResourceApplyOutput::from_control_result(
            &apply.result,
            &apply.identity.operation_id,
            &apply.identity.request_hash,
            &apply.identity.kid,
            &manifest,
            final_active,
        )
        .context("Apply typed mappings do not match the prepared signed Matrix")?;
        DescriptorMaterializer::finalize_tenant_resources(
            prepared,
            apply_output,
            deployment_trust_anchor,
        )
        .context("Apply typed mappings do not match the prepared signed Matrix")
    })();
    let ordinary = match setup_result {
        Ok(ordinary) => ordinary,
        Err(error) => {
            progress.activity(&ProgressActivity::CleaningUp);
            return cleanup_failed_pre_suite_setup(&session, recovery, error);
        }
    };
    let mut deployment_report = DeploymentReport {
        deployment_id: deployment.deployment_id.clone(),
        tenant_id: invocation.tenant_id.clone(),
        target_issuer: ephemeral_tenant.issuer.clone(),
        artifact_digest: artifact_digest.clone(),
        artifact_revision: driver_plan.artifact.revision.clone(),
        matrix_sha256: ordinary.matrix_sha256().to_owned(),
        selected_groups: driver_plan.selected_group_count,
        selected_plans: driver_plan.selected_plan_count,
        apply_operation_id: ordinary.operation_id().to_owned(),
        apply_request_hash: ordinary.request_hash().to_owned(),
        apply_controller_kid: ordinary.controller_kid().to_owned(),
        apply_revision: ordinary.applied_revision(),
        resource_manifest_sha256: ordinary.resource_manifest_sha256().to_owned(),
        trust_policy_resource_id: ordinary.trust_policy_resource_id().to_owned(),
        trust_policy_digest: ordinary.trust_policy_digest().to_owned(),
        applicant_id: ordinary.applicant_id().to_string(),
        client_count: u32::try_from(ordinary.clients().len())
            .context("ordinary client mapping count exceeds the report bound")?,
        cleanup_complete: false,
    };

    // The OpenID4VP client and runner are being generalized in the adjacent
    // slice. Keep this typed boundary ordinary-only: a lease-shaped adapter is
    // deliberately impossible here.
    let ciba_approver =
        build_ciba_user_approver(requires_ciba, &ephemeral_tenant.issuer, &run_secrets)?;
    let run_result = run_signed_suite(
        ordinary,
        suite_client.clone(),
        token,
        run_secrets,
        &session,
        &invocation,
        &ephemeral_tenant.issuer,
        &suite_origin,
        plan_lanes,
        plan_resource_budgets,
        selected_resource_budget,
        recovery.clone(),
        ciba_approver,
        &evidence_directory,
        requires_browser,
        captures_review_screenshots,
        control,
        Arc::clone(&user_interrupted),
        interrupt_notice,
        progress,
    );

    progress.activity(&ProgressActivity::CleaningUp);
    let mut recovery = take_recovery(recovery)?;
    let user_cancelled = user_interrupted.load(Ordering::SeqCst);
    let mut retention_eligible = !user_cancelled
        && run_result
            .as_ref()
            .is_ok_and(|report| report.orchestration_integrity.retention_eligible);
    let mut errors = if user_cancelled {
        vec!["run=interrupted by Ctrl+C".to_owned()]
    } else {
        Vec::new()
    };
    // The runner has already uploaded required NazoAuthWeb VP result captures;
    // this root-private manifest preserves their exact local evidence.
    let review_screenshot_manifest = if captures_review_screenshots && retention_eligible {
        match run_result.as_ref() {
            Ok(report) => match write_review_screenshot_manifest(
                report,
                &evidence_directory,
                recovery.ordinary_binding().run_id.as_str(),
                &artifact_digest,
                &ephemeral_tenant.issuer,
            ) {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    retention_eligible = false;
                    errors.push(format!("review-screenshot-manifest={error}"));
                    None
                }
            },
            Err(_) => None,
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
                &artifact_digest,
                &deployment_report.matrix_sha256,
                review_screenshot_manifest.as_ref(),
            )?;
            let manifest_path = suite_retention_manifest_path(&evidence_directory, &manifest);
            recovery.prepare_suite_plan_retention(manifest, manifest_path)
        })();
        if let Err(error) = prepared {
            retention_eligible = false;
            errors.push(format!("suite-retention-prepare={error:#}"));
        }
    }
    if !recovery.proxy_cleanup_complete() {
        recovery.mark_proxy_cleanup_complete()?;
    }
    let cleanup = cleanup_run_resources(&session, &mut recovery);
    let mut report = match run_result {
        Ok(mut report) => {
            if user_cancelled {
                report.errors.clear();
                report.retained_suite_plan_ids.clear();
            }
            Some(report)
        }
        Err(error) => {
            if !user_cancelled {
                errors.push(format!("run={error:#}"));
            }
            None
        }
    };
    let cleanup_evidence = match cleanup {
        Ok(evidence) => Some(evidence),
        Err(error) => {
            errors.push(format!("resource-cleanup={error:#}"));
            None
        }
    };
    let cleanup_complete = cleanup_evidence.is_some()
        && !errors
            .iter()
            .any(|error| error.starts_with("resource-cleanup="));
    let retention_commit_possible = retention_eligible && cleanup_evidence.is_some();
    // Screenshot evidence, not the optional control evidence, is the durable
    // certification-retention boundary.  The screenshot manifest was bound
    // to the Prepared journal above and is revalidated by stage, commit,
    // publish, recovery claim, and finish. Control-operation evidence is written only
    // after ownership has transferred and the final report is fixed.
    let mut retention_committed = if retention_commit_possible {
        match (|| -> anyhow::Result<()> {
            recovery.stage_suite_retention_manifest()?;
            recovery.commit_suite_plan_retention()?;
            let manifest_path = recovery.publish_committed_suite_retention_manifest()?;
            eprintln!(
                "Suite plans retained for review: suite={} plans={} manifest={}",
                suite_origin,
                report
                    .as_ref()
                    .map(|report| report.retained_suite_plan_ids.join(","))
                    .unwrap_or_default(),
                manifest_path.display(),
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
                    "Suite plans retained for review: suite={} plans={} manifest={}",
                    suite_origin,
                    report
                        .as_ref()
                        .map(|report| report.retained_suite_plan_ids.join(","))
                        .unwrap_or_default(),
                    manifest_path.display(),
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
    if let (Some(report), Some(cleanup_operations)) = (report.as_ref(), cleanup_evidence.as_ref()) {
        progress.activity(&ProgressActivity::WritingEvidence);
        let runtime = evidence_runtime(&deployment.runtime);
        let identity = EvidenceBundleIdentity {
            run_jti: request_jti.clone(),
            deployment: EvidenceDeploymentIdentity {
                deployment_id: deployment.deployment_id.clone(),
                target_issuer: ephemeral_tenant.issuer.clone(),
                release: deployment.release.clone(),
                runtime: runtime.clone(),
            },
            source: EvidenceSourceIdentity {
                suite_origin: suite_origin.to_string(),
                artifact: Box::new(driver_plan.artifact.clone()),
            },
            control: EvidenceControlIdentity {
                deployment_id: deployment.deployment_id.clone(),
                tenant_id: invocation.tenant_id.clone(),
                operations: cleanup_operations.clone(),
                cleanup_complete,
            },
            outer_cleanup_complete: cleanup_complete,
        };
        evidence = record_control_evidence_result(
            || {
                write_private_control_evidence_bundle(
                    report,
                    &evidence_directory,
                    &identity,
                    recovery.ordinary_binding(),
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
            conformance_run_succeeds(
                report.local_success,
                report.matrix_expectations_satisfied,
                report.failed_modules.len(),
                report.incomplete_modules.len(),
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
    progress.activity(&ProgressActivity::Finished);
    let theme = TerminalTheme::detect(io::stdout().is_terminal() && !invocation.json);
    write_final_output(
        io::stdout().lock(),
        &output,
        language,
        invocation.json,
        theme,
    )?;
    Ok(if user_interrupted.load(Ordering::SeqCst) {
        130
    } else if success {
        0
    } else {
        1
    })
}

fn conformance_run_succeeds(
    local_success: bool,
    matrix_expectations_satisfied: bool,
    failed_modules: usize,
    incomplete_modules: usize,
) -> bool {
    local_success && matrix_expectations_satisfied && failed_modules == 0 && incomplete_modules == 0
}

#[cfg(test)]
mod acceptance_tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    use nazo_operator_protocol::ControlOperationPayload;
    #[cfg(target_os = "linux")]
    use nazo_operator_protocol::{
        CONTROL_RESULT_SCHEMA, ControlOutcome, ControlResult, ControlResultData,
        TenantResourceIdentity, TenantResourceKind, TenantResourceMapping,
    };
    #[cfg(target_os = "linux")]
    use nazoauthctl_conformance::{
        ConformanceRecoveryStore, TenantResourceControlOperation, TenantResourceRecoveryBinding,
        TenantResourceRecoveryPhase,
    };

    use super::{
        DeploymentReport, EphemeralTenant, FinalOutput, PendingRecoveryCandidate,
        PendingRecoveryStep, conformance_run_succeeds, select_unique_pending_candidate,
        write_final_output,
    };
    #[cfg(target_os = "linux")]
    use super::{
        completed_lifecycle_candidate, next_pending_for_run, persist_pending_recovery_completion,
        persisted_candidate_for_pending, pre_suite_requires_resource_cleanup,
    };

    #[test]
    fn temporary_tenant_uses_the_instance_owned_domain() {
        let tenant =
            EphemeralTenant::new("00000000-0000-0000-0000-000000000001", "oidf.example.com")
                .expect("temporary tenant");
        assert_eq!(
            tenant.issuer,
            "https://00000000-0000-0000-0000-000000000001.oidf.example.com"
        );
    }

    #[test]
    fn review_only_run_is_successful() {
        assert!(conformance_run_succeeds(true, true, 0, 0));
    }

    #[test]
    fn failed_or_incomplete_module_fails_the_run() {
        assert!(!conformance_run_succeeds(true, true, 1, 0));
        assert!(!conformance_run_succeeds(true, true, 0, 1));
    }

    #[test]
    fn concise_output_is_the_default_human_interface() {
        let output = FinalOutput {
            schema: 3,
            success: false,
            errors: vec!["test failure".to_owned()],
            report: None,
            retention: None,
            evidence: None,
            deployment: DeploymentReport {
                deployment_id: "deployment".to_owned(),
                tenant_id: "tenant".to_owned(),
                target_issuer: "https://tenant.example".to_owned(),
                artifact_digest: "digest".to_owned(),
                artifact_revision: "revision".to_owned(),
                matrix_sha256: "matrix".to_owned(),
                selected_groups: 1,
                selected_plans: 1,
                apply_operation_id: "operation".to_owned(),
                apply_request_hash: "request".to_owned(),
                apply_controller_kid: "kid".to_owned(),
                apply_revision: 1,
                resource_manifest_sha256: "manifest".to_owned(),
                trust_policy_resource_id: "policy".to_owned(),
                trust_policy_digest: "policy-digest".to_owned(),
                applicant_id: "applicant".to_owned(),
                client_count: 1,
                cleanup_complete: true,
            },
        };
        let mut text = Vec::new();

        write_final_output(
            &mut text,
            &output,
            nazoauthctl_conformance::OutputLanguage::Chinese,
            false,
            nazoauthctl_conformance::TerminalTheme::plain(),
        )
        .expect("summary");
        let text = String::from_utf8(text).expect("UTF-8");

        assert!(text.contains("OIDF 结果：未通过"));
        assert!(text.contains("错误：test failure"));
        assert!(!text.contains('{'));
        assert!(!text.contains("artifact_digest"));

        let mut terminal_text = Vec::new();
        write_final_output(
            &mut terminal_text,
            &output,
            nazoauthctl_conformance::OutputLanguage::Chinese,
            false,
            nazoauthctl_conformance::TerminalTheme::detect(true),
        )
        .expect("terminal summary");
        let terminal_text = String::from_utf8(terminal_text).expect("UTF-8");
        assert!(terminal_text.contains("╭─"));
        assert!(terminal_text.contains("NazoAuth OIDF 一致性测试"));
        assert!(terminal_text.contains("✗ 未通过"));
        assert!(terminal_text.contains("test failure"));
    }

    #[cfg(target_os = "linux")]
    fn recovery_operation(
        result: ControlResultData,
        operation_id: &str,
    ) -> TenantResourceControlOperation {
        TenantResourceControlOperation {
            operation_id: operation_id.to_owned(),
            request_hash: "b".repeat(64),
            controller_kid: "c".repeat(43),
            result: ControlResult {
                schema: CONTROL_RESULT_SCHEMA,
                operation_id: operation_id.to_owned(),
                request_hash: "b".repeat(64),
                outcome: ControlOutcome::Succeeded,
                error: None,
                accepted_at: 1,
                completed_at: Some(2),
                result: Some(result),
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn failed_recovery_operation(operation_id: &str) -> TenantResourceControlOperation {
        TenantResourceControlOperation {
            operation_id: operation_id.to_owned(),
            request_hash: "b".repeat(64),
            controller_kid: "c".repeat(43),
            result: ControlResult {
                schema: CONTROL_RESULT_SCHEMA,
                operation_id: operation_id.to_owned(),
                request_hash: "b".repeat(64),
                outcome: ControlOutcome::Failed,
                error: Some(nazo_operator_protocol::ControlErrorCode::ExecutionFailed),
                accepted_at: 1,
                completed_at: Some(2),
                result: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn applied_recovery_selects_cleanup_enumerate_as_the_only_next_control_step() {
        let root = std::env::temp_dir().join(format!(
            "nazoauthctl-ordinary-recovery-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("recovery root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private recovery root");
        let store = ConformanceRecoveryStore::open(&root, "deployment-1").expect("store");
        let resource = TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client-1".to_owned(),
            digest: "a".repeat(64),
        };
        let mut recovery = store
            .begin_ordinary_run(TenantResourceRecoveryBinding {
                deployment_id: "deployment-1".to_owned(),
                tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
                tenant_domain: "oidf.example.com".to_owned(),
                realm_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                organization_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                run_id: "request-recovery-test".to_owned(),
                tenant_create_expected_revision: 0,
                manifest_path: None,
                material_sha256: None,
                proxy: None,
                vp_evidence_trust_anchor: None,
                resource_identities: vec![resource.clone()],
            })
            .expect("begin recovery");
        recovery.mark_tenant_created().expect("tenant created");
        assert_eq!(
            completed_lifecycle_candidate(0, &recovery)
                .expect("derive completed Create")
                .expect("completed Create candidate")
                .step,
            PendingRecoveryStep::TenantCreate(0)
        );
        recovery
            .mark_tenant_key_generated()
            .expect("tenant key generated");
        assert_eq!(
            completed_lifecycle_candidate(0, &recovery)
                .expect("derive completed key generation")
                .expect("completed key generation candidate")
                .step,
            PendingRecoveryStep::TenantKeyGenerate(0)
        );
        recovery.prepare_tenant_reload(1).expect("prepare reload");
        recovery.mark_tenant_reloaded().expect("tenant reloaded");
        assert_eq!(
            completed_lifecycle_candidate(0, &recovery)
                .expect("derive completed Reload")
                .expect("completed Reload candidate")
                .step,
            PendingRecoveryStep::TenantReload(0)
        );
        recovery
            .record_terminal_completion(
                TenantResourceRecoveryPhase::BaselineEnumerated,
                recovery_operation(
                    ControlResultData::TenantResourceEnumerate {
                        revision: 2,
                        resources: Vec::new(),
                        resource_manifest_sha256: "d".repeat(64),
                    },
                    "550e8400-e29b-41d4-a716-446655440001",
                ),
            )
            .expect("baseline");
        recovery
            .record_terminal_completion(
                TenantResourceRecoveryPhase::Applied,
                recovery_operation(
                    ControlResultData::TenantResourceApply {
                        revision: 3,
                        resources: vec![resource.clone()],
                        resource_mappings: vec![TenantResourceMapping {
                            kind: resource.kind,
                            resource_id: resource.resource_id.clone(),
                            public_id: "public-client-1".to_owned(),
                        }],
                        resource_manifest_sha256: "e".repeat(64),
                    },
                    "550e8400-e29b-41d4-a716-446655440002",
                ),
            )
            .expect("apply");
        assert!(pre_suite_requires_resource_cleanup(&recovery));

        let candidate = next_pending_for_run(0, &recovery)
            .expect("derive next step")
            .expect("cleanup enumerate candidate");
        assert_eq!(candidate.step, PendingRecoveryStep::CleanupEnumerate(0));
        assert_eq!(
            candidate.operation,
            ControlOperationPayload::TenantResourceEnumerate {
                tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
                selectors: Vec::new(),
            }
        );
        recovery
            .record_terminal_completion(
                TenantResourceRecoveryPhase::CleanupEnumerated,
                recovery_operation(
                    ControlResultData::TenantResourceEnumerate {
                        revision: 4,
                        resources: vec![resource.clone()],
                        resource_manifest_sha256: "f".repeat(64),
                    },
                    "550e8400-e29b-41d4-a716-446655440003",
                ),
            )
            .expect("cleanup enumerate");
        let persisted =
            persisted_candidate_for_pending(0, &recovery, "550e8400-e29b-41d4-a716-446655440003")
                .expect("derive persisted operation")
                .expect("persisted cleanup enumerate candidate");
        assert_eq!(persisted.step, PendingRecoveryStep::CleanupEnumerate(0));
        assert_eq!(
            persisted.operation,
            ControlOperationPayload::TenantResourceEnumerate {
                tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
                selectors: Vec::new(),
            }
        );
        recovery
            .prepare_tenant_disable(4)
            .expect("prepare failure cleanup disable");
        let candidate = next_pending_for_run(0, &recovery)
            .expect("derive lifecycle recovery")
            .expect("disable candidate");
        assert_eq!(candidate.step, PendingRecoveryStep::TenantDisable(0));
        assert_eq!(
            candidate.operation,
            ControlOperationPayload::TenantDirectoryDisable {
                expected_revision: 4,
                tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
            }
        );
        recovery.mark_tenant_disabled().expect("tenant disabled");
        assert_eq!(
            completed_lifecycle_candidate(0, &recovery)
                .expect("derive completed Disable")
                .expect("completed Disable candidate")
                .step,
            PendingRecoveryStep::TenantDisable(0)
        );
        recovery
            .prepare_tenant_finalize(5)
            .expect("prepare finalize");
        recovery
            .mark_tenant_cleanup_complete()
            .expect("tenant finalized");
        assert_eq!(
            completed_lifecycle_candidate(0, &recovery)
                .expect("derive completed Finalize")
                .expect("completed Finalize candidate")
                .step,
            PendingRecoveryStep::TenantFinalize(0)
        );
        recovery.mark_tenant_absent(6).expect("tenant absent");
        assert!(
            next_pending_for_run(0, &recovery)
                .expect("derive absent recovery")
                .is_none(),
            "an authoritative absence must suppress every tenant operation candidate"
        );
        drop(recovery);
        fs::remove_dir_all(root).expect("remove recovery root");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persisted_terminal_failure_rebuilds_the_attempted_resource_operation() {
        let root = std::env::temp_dir().join(format!(
            "nazoauthctl-ordinary-failure-recovery-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("recovery root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private recovery root");
        let store = ConformanceRecoveryStore::open(&root, "deployment-1").expect("store");
        let mut recovery = store
            .begin_ordinary_run(TenantResourceRecoveryBinding {
                deployment_id: "deployment-1".to_owned(),
                tenant_id: "00000000-0000-0000-0000-000000000010".to_owned(),
                tenant_domain: "oidf.example.com".to_owned(),
                realm_id: "00000000-0000-0000-0000-000000000011".to_owned(),
                organization_id: "00000000-0000-0000-0000-000000000012".to_owned(),
                run_id: "request-failure-recovery-test".to_owned(),
                tenant_create_expected_revision: 0,
                manifest_path: None,
                material_sha256: None,
                proxy: None,
                vp_evidence_trust_anchor: None,
                resource_identities: vec![TenantResourceIdentity {
                    kind: TenantResourceKind::OauthClient,
                    resource_id: "client-failure".to_owned(),
                    digest: "a".repeat(64),
                }],
            })
            .expect("begin recovery");
        recovery.mark_tenant_created().expect("tenant created");
        recovery
            .mark_tenant_key_generated()
            .expect("tenant key generated");
        recovery.prepare_tenant_reload(1).expect("prepare reload");
        recovery.mark_tenant_reloaded().expect("tenant reloaded");
        let operation_id = "550e8400-e29b-41d4-a716-446655440010";
        let failed = failed_recovery_operation(operation_id);
        persist_pending_recovery_completion(
            PendingRecoveryStep::BaselineEnumerate(0),
            &mut recovery,
            &nazoauthctl_core::ConformanceControlCompletion {
                identity: nazoauthctl_core::ControlOperationIdentity {
                    operation_id: failed.operation_id.clone(),
                    request_hash: failed.request_hash.clone(),
                    kid: failed.controller_kid.clone(),
                },
                result: failed.result.clone(),
            },
        )
        .expect("persist replayed baseline failure before controller journal clear");
        assert_eq!(
            recovery
                .terminal_failure()
                .expect("replayed failure identity must be durable"),
            &failed
        );
        assert!(
            !pre_suite_requires_resource_cleanup(&recovery),
            "a failed pre-Suite operation must delete the temporary tenant directly"
        );

        let candidate = persisted_candidate_for_pending(0, &recovery, operation_id)
            .expect("derive persisted failure")
            .expect("persisted failure candidate");
        assert_eq!(candidate.step, PendingRecoveryStep::BaselineEnumerate(0));
        assert_eq!(
            candidate.operation,
            ControlOperationPayload::TenantResourceEnumerate {
                tenant_id: "00000000-0000-0000-0000-000000000010".to_owned(),
                selectors: Vec::new(),
            }
        );
        drop(recovery);
        fs::remove_dir_all(root).expect("remove recovery root");
    }

    #[test]
    fn ambiguous_pending_recovery_fails_before_dispatch_selection() {
        let candidate = || PendingRecoveryCandidate {
            step: PendingRecoveryStep::Describe,
            operation: ControlOperationPayload::TenantDirectoryDescribe,
        };
        let error = select_unique_pending_candidate(vec![candidate(), candidate()])
            .expect_err("ambiguous candidates must fail closed");
        assert!(format!("{error:#}").contains("ambiguous recovery"));
    }
}

fn control_operation(
    completion: &nazoauthctl_core::ConformanceControlCompletion,
) -> TenantResourceControlOperation {
    TenantResourceControlOperation {
        operation_id: completion.identity.operation_id.clone(),
        request_hash: completion.identity.request_hash.clone(),
        controller_kid: completion.identity.kid.clone(),
        result: completion.result.clone(),
    }
}

fn successful_control_completion(
    outcome: nazoauthctl_core::ConformanceControlOutcome,
    label: &str,
) -> anyhow::Result<nazoauthctl_core::ConformanceControlCompletion> {
    match outcome {
        nazoauthctl_core::ConformanceControlOutcome::Succeeded(completion) => Ok(completion),
        nazoauthctl_core::ConformanceControlOutcome::Failed(completion) => bail!(
            "{label} ControlOperation failed durably: operation_id={} request_hash={}",
            completion.identity.operation_id,
            completion.identity.request_hash,
        ),
    }
}

fn successful_control_result(
    outcome: nazoauthctl_core::ConformanceControlOutcome,
    label: &str,
) -> anyhow::Result<ControlResultData> {
    let completion = successful_control_completion(outcome, label)?;
    completion
        .result
        .result
        .context("successful ControlOperation omitted its typed result")
}

struct EphemeralTenant {
    tenant_id: String,
    realm_id: String,
    organization_id: String,
    issuer: String,
    external_host: String,
    slug: String,
}

impl EphemeralTenant {
    fn new(tenant_id: &str, tenant_domain: &str) -> anyhow::Result<Self> {
        let tenant_id = uuid::Uuid::parse_str(tenant_id)
            .context("generated OIDF tenant ID is invalid")?
            .to_string();
        let realm_id = uuid::Uuid::now_v7().to_string();
        let organization_id = uuid::Uuid::now_v7().to_string();
        Self::from_ids(&tenant_id, &realm_id, &organization_id, tenant_domain)
    }

    fn from_ids(
        tenant_id: &str,
        realm_id: &str,
        organization_id: &str,
        tenant_domain: &str,
    ) -> anyhow::Result<Self> {
        let tenant_id = uuid::Uuid::parse_str(tenant_id)
            .context("OIDF tenant ID is invalid")?
            .to_string();
        let realm_id = uuid::Uuid::parse_str(realm_id)
            .context("OIDF realm ID is invalid")?
            .to_string();
        let organization_id = uuid::Uuid::parse_str(organization_id)
            .context("OIDF organization ID is invalid")?
            .to_string();
        if tenant_id == realm_id || tenant_id == organization_id || realm_id == organization_id {
            bail!("OIDF tenant boundaries must use distinct IDs");
        }
        let external_host = format!("{tenant_id}.{tenant_domain}");
        Ok(Self {
            slug: format!("oidf-{}", tenant_id.replace('-', "")),
            issuer: format!("https://{external_host}"),
            external_host,
            tenant_id,
            realm_id,
            organization_id,
        })
    }

    fn create_operation(&self, expected_revision: u64) -> ControlOperationPayload {
        let boundary = |kind: &str, id: &str| ControlTenantBoundary {
            id: id.to_owned(),
            slug: format!("{}-{kind}", self.slug),
            display_name: format!("OIDF temporary {kind} {}", self.tenant_id),
        };
        ControlOperationPayload::TenantDirectoryCreate {
            expected_revision,
            tenant: boundary("tenant", &self.tenant_id),
            realm: boundary("realm", &self.realm_id),
            organization: boundary("organization", &self.organization_id),
            issuer: self.issuer.clone(),
            external_host: self.external_host.clone(),
        }
    }
}

fn directory_revision(session: &nazoauthctl_core::ConformanceSession) -> anyhow::Result<u64> {
    let result = session.execute_control_operation(
        ControlOperationPayload::TenantDirectoryDescribe,
        None,
        |_| Ok(()),
    )?;
    let ControlResultData::TenantDirectoryDescribe { revision, .. } =
        successful_control_result(result, "tenant directory Describe")?
    else {
        bail!("tenant directory Describe returned the wrong typed result");
    };
    Ok(revision)
}

fn tenant_directory_presence(
    session: &nazoauthctl_core::ConformanceSession,
    tenant_id: &str,
) -> anyhow::Result<(u64, bool)> {
    let result = session.execute_control_operation(
        ControlOperationPayload::TenantDirectoryDescribe,
        None,
        |_| Ok(()),
    )?;
    let ControlResultData::TenantDirectoryDescribe { revision, tenants } =
        successful_control_result(result, "tenant directory Describe")?
    else {
        bail!("tenant directory Describe returned the wrong typed result");
    };
    Ok((
        revision,
        tenants.iter().any(|tenant| tenant.tenant_id == tenant_id),
    ))
}

fn probe_ephemeral_tenant(issuer: &str) -> anyhow::Result<()> {
    let mut metadata_url = Url::parse(issuer).context("temporary tenant issuer is invalid")?;
    metadata_url.set_path("/.well-known/openid-configuration");
    let transport = HttpTransport::new(Duration::from_secs(15))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match transport.send(HttpRequest::get(metadata_url.clone()), 128 * 1024) {
            Ok(response) if response.status == 200 => {
                let metadata: serde_json::Value = serde_json::from_slice(&response.body)
                    .context("temporary tenant discovery is not JSON")?;
                if metadata.get("issuer").and_then(serde_json::Value::as_str) != Some(issuer) {
                    bail!("temporary tenant discovery issuer does not match its routed issuer");
                }
                return Ok(());
            }
            Ok(response) if Instant::now() >= deadline => {
                bail!(
                    "temporary tenant discovery returned HTTP {} after directory reload",
                    response.status
                );
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(error).context(
                    "temporary tenant discovery remained unreachable after directory reload",
                );
            }
            Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn provision_ephemeral_tenant(
    session: &nazoauthctl_core::ConformanceSession,
    tenant: &EphemeralTenant,
    recovery: &Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
) -> anyhow::Result<String> {
    let (created, expected_revision) = {
        let recovery = lock_recovery(recovery)?;
        (
            recovery.tenant_created(),
            recovery.ordinary_binding().tenant_create_expected_revision,
        )
    };
    if !created {
        let outcome = session.execute_control_operation(
            tenant.create_operation(expected_revision),
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    lock_recovery(recovery)?.mark_tenant_created()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "temporary tenant Create")?;
    }

    let key = session.execute_control_operation(
        ControlOperationPayload::TenantKeysGenerateLocal {
            tenant_id: tenant.tenant_id.clone(),
            alg: "ES256".to_owned(),
            purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
        },
        None,
        |completion| {
            if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                lock_recovery(recovery)?.mark_tenant_key_generated()?;
            }
            Ok(())
        },
    )?;
    let ControlResultData::TenantKeyGenerated {
        tenant_id,
        certificate_chain_pem,
        ..
    } = successful_control_result(key, "temporary tenant key generation")?
    else {
        bail!("temporary tenant key generation returned the wrong typed result");
    };
    if tenant_id != tenant.tenant_id {
        bail!("temporary tenant key generation returned another tenant");
    }

    if !lock_recovery(recovery)?.tenant_reloaded() {
        let prepared_revision = { lock_recovery(recovery)?.tenant_reload_expected_revision() };
        let expected_revision = match prepared_revision {
            Some(revision) => revision,
            None => {
                let revision = directory_revision(session)?;
                lock_recovery(recovery)?.prepare_tenant_reload(revision)?;
                revision
            }
        };
        let outcome = session.execute_control_operation(
            ControlOperationPayload::TenantDirectoryReload {
                expected_revision,
                tenant_id: tenant.tenant_id.clone(),
            },
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    lock_recovery(recovery)?.mark_tenant_reloaded()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "temporary tenant Reload")?;
    }
    Ok(certificate_chain_pem)
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
struct RecoveredRetentionOutput<'a> {
    schema: u32,
    recovered: bool,
    retention: &'a [SuiteRetentionManifestReceipt],
}

fn write_recovered_retention_output<W: io::Write>(
    mut writer: W,
    retention: &[SuiteRetentionManifestReceipt],
    language: OutputLanguage,
    json: bool,
    theme: TerminalTheme,
) -> anyhow::Result<()> {
    if json {
        serde_json::to_writer_pretty(
            &mut writer,
            &RecoveredRetentionOutput {
                schema: 1,
                recovered: true,
                retention,
            },
        )
        .context("failed to write recovered retention report")?;
    } else if theme.is_terminal() {
        let message = match language {
            OutputLanguage::Chinese => {
                format!("已恢复上次运行保留的 {} 个 Suite 计划", retention.len())
            }
            OutputLanguage::English => format!(
                "Recovered {} retained Suite plan(s) from the previous run",
                retention.len()
            ),
        };
        write!(writer, "{}  {}", theme.success('✓'), theme.strong(message))?;
    } else {
        match language {
            OutputLanguage::Chinese => {
                write!(
                    writer,
                    "已恢复上次运行保留的 {} 个 Suite 计划。",
                    retention.len()
                )?;
            }
            OutputLanguage::English => {
                write!(
                    writer,
                    "Recovered {} retained Suite plan(s) from the previous run.",
                    retention.len()
                )?;
            }
        }
    }
    writeln!(writer).context("failed to finish recovered retention output")
}

fn write_final_output<W: io::Write>(
    mut writer: W,
    output: &FinalOutput,
    language: OutputLanguage,
    json: bool,
    theme: TerminalTheme,
) -> anyhow::Result<()> {
    if json {
        serde_json::to_writer_pretty(&mut writer, output)
            .context("failed to write the structured ordinary conformance report")?;
        return writeln!(writer).context("failed to finish the structured conformance report");
    }

    if theme.is_terminal() {
        return write_terminal_final_output(&mut writer, output, language, theme);
    }

    let status = match (language, output.success) {
        (OutputLanguage::Chinese, true) => "OIDF 结果：通过",
        (OutputLanguage::Chinese, false) => "OIDF 结果：未通过",
        (OutputLanguage::English, true) => "OIDF result: passed",
        (OutputLanguage::English, false) => "OIDF result: not passed",
    };
    writeln!(writer, "{status}")?;

    if let Some(report) = &output.report {
        let mut passed = 0usize;
        let mut review = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;
        let mut incomplete = 0usize;
        for module in &report.modules {
            if module.human_review_required {
                review += 1;
                continue;
            }
            match module.outcome {
                ModuleOutcome::Passed => passed += 1,
                ModuleOutcome::Review | ModuleOutcome::DeferredReviewPending => review += 1,
                ModuleOutcome::Skipped => skipped += 1,
                ModuleOutcome::Failed => failed += 1,
                ModuleOutcome::Incomplete => incomplete += 1,
            }
        }
        match language {
            OutputLanguage::Chinese => writeln!(
                writer,
                "模块：通过 {passed} · 复核 {review} · 跳过 {skipped} · 失败 {failed} · 未完成 {incomplete}"
            )?,
            OutputLanguage::English => writeln!(
                writer,
                "Modules: passed {passed} · review {review} · skipped {skipped} · failed {failed} · incomplete {incomplete}"
            )?,
        }
    }
    if let Some(evidence) = &output.evidence {
        match language {
            OutputLanguage::Chinese => {
                writeln!(writer, "证据：{}", evidence.directory.display())?;
            }
            OutputLanguage::English => {
                writeln!(writer, "Evidence: {}", evidence.directory.display())?;
            }
        }
    }
    if output.retention.is_some() {
        writeln!(
            writer,
            "{}",
            match language {
                OutputLanguage::Chinese => "Suite 计划已按要求保留。",
                OutputLanguage::English => "Suite plans were retained as requested.",
            }
        )?;
    }
    for error in &output.errors {
        match language {
            OutputLanguage::Chinese => writeln!(writer, "错误：{error}")?,
            OutputLanguage::English => writeln!(writer, "Error: {error}")?,
        }
    }
    Ok(())
}

fn write_terminal_final_output<W: io::Write>(
    writer: &mut W,
    output: &FinalOutput,
    language: OutputLanguage,
    theme: TerminalTheme,
) -> anyhow::Result<()> {
    let (title, result_label, modules_label, evidence_label, records_label) = match language {
        OutputLanguage::Chinese => (
            "NazoAuth OIDF 一致性测试",
            "结果",
            "模块",
            "证据",
            "Suite 记录",
        ),
        OutputLanguage::English => (
            "NazoAuth OIDF Conformance",
            "Result",
            "Modules",
            "Evidence",
            "Suite records",
        ),
    };
    writeln!(writer, "╭─ {}", theme.heading(title))?;
    writeln!(writer, "│")?;
    let outcome = match (language, output.success) {
        (OutputLanguage::Chinese, true) => theme.success("✓ 通过"),
        (OutputLanguage::Chinese, false) => theme.error("✗ 未通过"),
        (OutputLanguage::English, true) => theme.success("✓ Passed"),
        (OutputLanguage::English, false) => theme.error("✗ Not passed"),
    };
    writeln!(
        writer,
        "│  {} {outcome}",
        theme.muted(format!("{result_label:<10}"))
    )?;

    if let Some(report) = &output.report {
        let mut passed = 0usize;
        let mut review = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;
        let mut incomplete = 0usize;
        for module in &report.modules {
            if module.human_review_required {
                review += 1;
                continue;
            }
            match module.outcome {
                ModuleOutcome::Passed => passed += 1,
                ModuleOutcome::Review | ModuleOutcome::DeferredReviewPending => review += 1,
                ModuleOutcome::Skipped => skipped += 1,
                ModuleOutcome::Failed => failed += 1,
                ModuleOutcome::Incomplete => incomplete += 1,
            }
        }
        let labels = match language {
            OutputLanguage::Chinese => ["通过", "待复核", "跳过", "失败", "未完成"],
            OutputLanguage::English => ["passed", "review", "skipped", "failed", "incomplete"],
        };
        let summary = [
            (GroupStatus::Passed, passed),
            (GroupStatus::Review, review),
            (GroupStatus::Skipped, skipped),
            (GroupStatus::Failed, failed),
            (GroupStatus::Incomplete, incomplete),
        ]
        .into_iter()
        .zip(labels)
        .map(|((status, count), label)| theme.status(status, count, format!("{count} {label}")))
        .collect::<Vec<_>>()
        .join(" · ");
        writeln!(
            writer,
            "│  {} {summary}",
            theme.muted(format!("{modules_label:<10}"))
        )?;
    }
    if let Some(evidence) = &output.evidence {
        writeln!(
            writer,
            "│  {} {}",
            theme.muted(format!("{evidence_label:<10}")),
            theme.accent(evidence.directory.display())
        )?;
    }
    if output.retention.is_some() {
        let retained = match language {
            OutputLanguage::Chinese => "已保留，可在 OIDF Suite 中查看",
            OutputLanguage::English => "Retained and available in the OIDF Suite",
        };
        writeln!(
            writer,
            "│  {} {}",
            theme.muted(format!("{records_label:<10}")),
            theme.success(retained)
        )?;
    }
    for error in &output.errors {
        writeln!(writer, "│  {}  {error}", theme.error('✗'))?;
    }
    writeln!(writer, "╰─")?;
    Ok(())
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
    apply_operation_id: String,
    apply_request_hash: String,
    apply_controller_kid: String,
    apply_revision: u64,
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
}

#[allow(clippy::too_many_arguments)]
fn run_signed_suite<S: ProgressSink>(
    mut materialized: nazoauthctl_conformance::TenantResourceMaterializedMatrix,
    suite_client: SuiteClient,
    token: BearerToken,
    secrets: RunSecrets,
    session: &nazoauthctl_core::ConformanceSession,
    invocation: &RunInvocation,
    target_issuer: &str,
    suite_origin: &Origin,
    plan_lanes: BTreeMap<String, OidfDriverLane>,
    plan_resource_budgets: BTreeMap<String, OidfPlanResourceBudget>,
    selected_resource_budget: OidfPlanResourceBudget,
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
    ciba_approver: Option<Arc<CibaUserApprovalClient>>,
    evidence_directory: &Path,
    requires_browser: bool,
    captures_review_screenshots: bool,
    control: RunControl,
    user_interrupted: Arc<AtomicBool>,
    interrupt_notice: &'static str,
    progress: &mut S,
) -> anyhow::Result<nazoauthctl_conformance::ConformanceReport> {
    let binding = ConformanceBinding::openid4vc_trust_policy(
        materialized.trust_policy_resource_id(),
        materialized.trust_policy_digest(),
    )?;
    let target_origin = BrowserTargetOrigin::parse(target_issuer)?;
    let applicant_id = *materialized.applicant_id();
    let openid4vci_management_token = session
        .openid4vci_management_token(&invocation.tenant_id)
        .context("failed to derive the run tenant OpenID4VCI management token")?;
    let openid4vp_management_token = session
        .openid4vp_management_token(&invocation.tenant_id)
        .context("failed to derive the run tenant OpenID4VP management token")?;
    let review_screenshot_run_jti = recovery
        .lock()
        .map_err(|_| anyhow::anyhow!("ordinary recovery lock is poisoned"))?
        .ordinary_binding()
        .run_id
        .clone();
    let review_screenshot_capture = captures_review_screenshots
        .then(|| {
            BrowserReviewScreenshotCapture::new(
                evidence_directory.to_path_buf(),
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
    let interrupt = control.clone();
    ctrlc::set_handler(move || {
        if !user_interrupted.swap(true, Ordering::SeqCst) {
            eprintln!("{interrupt_notice}");
        }
        interrupt.interrupt();
    })
    .context("failed to install the conformance interrupt handler")?;
    let mut managed_browsers = Vec::with_capacity(invocation.jobs);
    let run_result = (|| -> anyhow::Result<nazoauthctl_conformance::ConformanceReport> {
        if control.is_interrupted() {
            bail!("run interrupted");
        }
        let mut automation = Vec::with_capacity(invocation.jobs);
        for index in 0..invocation.jobs {
            if control.is_interrupted() {
                bail!("run interrupted");
            }
            let browser: Option<Arc<Mutex<dyn BrowserAutomation>>> = if requires_browser {
                progress.activity(&ProgressActivity::StartingBrowser {
                    current: index + 1,
                    total: invocation.jobs,
                });
                let managed_browser = build_browser(target_issuer, suite_origin)?;
                managed_browsers.push(managed_browser.clone());
                Some(managed_browser)
            } else {
                None
            };
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
            let verifier: Arc<Mutex<dyn OpenId4VpVerifier>> = Arc::new(Mutex::new(verifier_client));
            automation.push(ConformanceAutomation {
                browser,
                review_screenshot_capture: review_screenshot_capture.clone(),
                verifier: Some(verifier),
                issuer: Some(issuer),
                ciba_approver: ciba_approver.clone(),
            });
        }
        let runner = ConformanceRunner::new(ConformanceRunConfig {
            client: suite_client,
            matrix: selected,
            target_origin: Some(target_origin),
            binding,
            poll_timeout: invocation.poll_timeout,
            control: control.clone(),
            plan_lanes,
            plan_resource_budgets,
            selected_resource_budget,
            jobs: invocation.jobs,
            upload_review_screenshots: captures_review_screenshots,
            automation,
            suite_resource_observer: Some(Arc::new(DurableSuiteObserver {
                recovery,
                retain_suite_plans: !invocation.delete_suite_plans,
            })),
        })?;
        Ok(runner.run(progress).report)
    })();
    let mut browser_cleanup_errors = Vec::new();
    for (index, browser) in managed_browsers.iter().enumerate() {
        match browser.lock() {
            Ok(mut browser) => {
                if let Err(error) = browser.driver_mut().shutdown() {
                    browser_cleanup_errors.push(format!("browser {}: {error}", index + 1));
                }
            }
            Err(_) => browser_cleanup_errors.push(format!("browser {}: lock poisoned", index + 1)),
        }
    }
    let cleanup_result = if browser_cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "failed to stop managed browser infrastructure: {}",
            browser_cleanup_errors.join("; ")
        ))
    };
    match (run_result, cleanup_result) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "managed browser cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn build_ciba_user_approver(
    requires_ciba: bool,
    target_issuer: &str,
    secrets: &RunSecrets,
) -> anyhow::Result<Option<Arc<CibaUserApprovalClient>>> {
    if !requires_ciba {
        return Ok(None);
    }
    let issuer = Url::parse(target_issuer)
        .context("deployment target issuer is not a valid CIBA approval URL")?;
    let transport = Arc::new(
        HttpTransport::new(Duration::from_secs(30))
            .context("failed to initialize normal CIBA user-approval transport")?,
    );
    Ok(Some(Arc::new(
        CibaUserApprovalClient::new(
            issuer,
            secrets.applicant_email.clone(),
            secrets.applicant_password.clone(),
            transport,
        )
        .context("failed to initialize normal CIBA user approval")?,
    )))
}

struct DurableSuiteObserver {
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
    retain_suite_plans: bool,
}

impl SuiteResourceObserver for DurableSuiteObserver {
    fn retain_suite_plans_for_certification(&self) -> bool {
        self.retain_suite_plans
    }

    fn retain_failed_suite_plans_for_diagnosis(&self) -> bool {
        self.retain_suite_plans
    }

    fn plan_create_intent(&self, origin: &Origin, intent_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| {
                recovery.begin_suite_create_with_retention(origin.as_str(), intent_id, true)
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
                recovery.begin_suite_create_with_retention(origin.as_str(), intent_id, true)
            })
            .map_err(|error| format!("failed to persist Suite module create intent: {error:#}"))
    }

    fn module_created(&self, intent_id: &str, module_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| recovery.record_suite_module(intent_id, module_id))
            .map_err(|error| format!("failed to persist Suite module allocation: {error:#}"))
    }

    fn plan_deleted(&self, plan_id: &str) -> Result<(), String> {
        lock_recovery(&self.recovery)
            .and_then(|mut recovery| recovery.release_deleted_suite_plan(plan_id))
            .map_err(|error| format!("failed to release deleted Suite plan: {error:#}"))
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

fn cleanup_failed_pre_suite_setup<T>(
    session: &nazoauthctl_core::ConformanceSession,
    recovery: Arc<Mutex<nazoauthctl_conformance::ConformanceRecoveryGuard>>,
    setup_error: anyhow::Error,
) -> anyhow::Result<T> {
    let mut recovery = match take_recovery(recovery) {
        Ok(recovery) => recovery,
        Err(cleanup_error) => {
            bail!("pre-Suite setup failed: {setup_error:#}; cleanup-state={cleanup_error:#}")
        }
    };
    let mut cleanup_errors = Vec::new();
    if !recovery.suite_cleanup_complete()
        && let Err(error) = recovery.mark_suite_cleanup_complete()
    {
        cleanup_errors.push(format!("suite={error:#}"));
    }
    if !recovery.proxy_cleanup_complete()
        && let Err(error) = recovery.mark_proxy_cleanup_complete()
    {
        cleanup_errors.push(format!("proxy={error:#}"));
    }
    let pending_settled = match session.pending_control_operation() {
        Ok(Some(_)) => {
            match resume_pending_conformance_operation(session, std::slice::from_mut(&mut recovery))
            {
                Ok(()) => match session.pending_control_operation() {
                    Ok(None) => true,
                    Ok(Some(_)) => {
                        cleanup_errors.push(
                            "control-journal=pending operation remained after exact recovery"
                                .to_owned(),
                        );
                        false
                    }
                    Err(error) => {
                        cleanup_errors.push(format!("control-journal={error:#}"));
                        false
                    }
                },
                Err(error) => {
                    cleanup_errors.push(format!("control-journal={error:#}"));
                    false
                }
            }
        }
        Ok(None) => true,
        Err(error) => {
            cleanup_errors.push(format!("control-journal={error:#}"));
            false
        }
    };
    let resources_clean = if pending_settled {
        let cleanup = if pre_suite_requires_resource_cleanup(&recovery) {
            cleanup_run_resources(session, &mut recovery).map(|_| ())
        } else {
            tenant_directory_presence(session, &recovery.ordinary_binding().tenant_id).and_then(
                |(revision, present)| {
                    if present {
                        cleanup_ephemeral_tenant(session, &mut recovery)
                    } else {
                        recovery.mark_tenant_absent(revision)
                    }
                },
            )
        };
        match cleanup {
            Ok(_) => true,
            Err(error) => {
                cleanup_errors.push(format!("resources={error:#}"));
                false
            }
        }
    } else {
        false
    };
    if resources_clean
        && recovery.suite_cleanup_complete()
        && recovery.proxy_cleanup_complete()
        && let Err(error) = recovery.finish()
    {
        cleanup_errors.push(format!("journal={error:#}"));
    }
    let cleanup = if cleanup_errors.is_empty() {
        "ok".to_owned()
    } else {
        cleanup_errors.join("; ")
    };
    bail!("pre-Suite setup failed: {setup_error:#}; cleanup={cleanup}")
}

fn pre_suite_requires_resource_cleanup(
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> bool {
    recovery.apply_operation().is_some() && recovery.terminal_failure().is_none()
}

fn build_browser(
    target_issuer: &str,
    suite_origin: &Origin,
) -> anyhow::Result<Arc<Mutex<BrowserExecutor<ManagedWebDriver>>>> {
    let target = BrowserTargetOrigin::parse(target_issuer)?;
    let policy = BrowserPolicy::new(target, suite_origin.clone())?;
    let driver = ManagedWebDriver::start_default(Duration::from_secs(30))?;
    Ok(Arc::new(Mutex::new(BrowserExecutor::new(driver, policy))))
}

fn suite_retention_manifest(
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
    report: &nazoauthctl_conformance::ConformanceReport,
    artifact_digest: &str,
    matrix_sha256: &str,
    review_screenshot_manifest: Option<&nazoauthctl_conformance::ReviewScreenshotManifestReceipt>,
) -> anyhow::Result<SuiteRetentionManifest> {
    let binding = recovery.ordinary_binding();
    let retained_plan_ids = report
        .retained_suite_plan_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if retained_plan_ids.is_empty() {
        bail!("retained report has no Suite plan IDs");
    }
    let plans = report
        .plans
        .iter()
        .filter(|plan| {
            plan.suite_plan_id
                .as_ref()
                .is_some_and(|plan_id| retained_plan_ids.contains(plan_id))
        })
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
        schema: 2,
        suite_origin: report.suite_origin.clone(),
        artifact_digest: artifact_digest.to_owned(),
        matrix_sha256: matrix_sha256.to_owned(),
        deployment_id: binding.deployment_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        run_id: binding.run_id.clone(),
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
                if !retained_plan_ids.contains(&module.suite_plan_id) {
                    return None;
                }
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

fn cleanup_run_resources(
    session: &nazoauthctl_core::ConformanceSession,
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<Vec<EvidenceControlOperation>> {
    if recovery.tenant_absent() {
        cleanup_ephemeral_tenant(session, recovery)?;
        return Ok(Vec::new());
    }
    let enumerate = match recovery.cleanup_enumerate_operation() {
        Some(operation) => operation.clone(),
        None => {
            let outcome = session.execute_control_operation(
                ControlOperationPayload::TenantResourceEnumerate {
                    tenant_id: recovery.ordinary_binding().tenant_id.clone(),
                    selectors: Vec::new(),
                },
                None,
                |completion| {
                    recovery.record_terminal_completion(
                        TenantResourceRecoveryPhase::CleanupEnumerated,
                        control_operation(completion),
                    )?;
                    Ok(())
                },
            )?;
            control_operation(&successful_control_completion(
                outcome,
                "cleanup Enumerate",
            )?)
        }
    };
    let ControlResultData::TenantResourceEnumerate { resources, .. } = enumerate
        .result
        .result
        .as_ref()
        .context("cleanup Enumerate omitted result")?
    else {
        bail!("cleanup Enumerate returned the wrong result");
    };
    let present = resources
        .iter()
        .filter(|candidate| {
            recovery
                .ordinary_binding()
                .resource_identities
                .iter()
                .any(|bound| bound == *candidate)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !present.is_empty() && recovery.cleanup_revoke_operation().is_none() {
        let revoke = session.execute_control_operation(
            ControlOperationPayload::TenantResourceRevoke {
                tenant_id: recovery.ordinary_binding().tenant_id.clone(),
                resources: present,
            },
            None,
            |completion| {
                recovery.record_terminal_completion(
                    TenantResourceRecoveryPhase::CleanupRevoked,
                    control_operation(completion),
                )?;
                Ok(())
            },
        )?;
        successful_control_completion(revoke, "cleanup Revoke")?;
    }
    if !recovery.ordinary_cleanup_complete() {
        bail!("ordinary cleanup obligations remain pending");
    }
    let mut operations = Vec::new();
    for operation in [
        recovery.baseline_enumerate_operation(),
        recovery.apply_operation(),
        recovery.cleanup_enumerate_operation(),
        recovery.cleanup_revoke_operation(),
    ]
    .into_iter()
    .flatten()
    {
        operations.push(EvidenceControlOperation {
            operation_id: operation.operation_id.clone(),
            request_sha256: operation.request_hash.clone(),
            controller_kid: operation.controller_kid.clone(),
            result: operation
                .result
                .result
                .clone()
                .context("persisted control operation omitted its typed result")?,
        });
    }
    cleanup_ephemeral_tenant(session, recovery)?;
    Ok(operations)
}

fn cleanup_ephemeral_tenant(
    session: &nazoauthctl_core::ConformanceSession,
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<()> {
    if recovery.tenant_cleanup_complete() {
        return Ok(());
    }
    let tenant_id = recovery.ordinary_binding().tenant_id.clone();
    if !recovery.tenant_disabled() {
        let expected_revision = match recovery.tenant_disable_expected_revision() {
            Some(revision) => revision,
            None => {
                let revision = directory_revision(session)?;
                recovery.prepare_tenant_disable(revision)?;
                revision
            }
        };
        let outcome = session.execute_control_operation(
            ControlOperationPayload::TenantDirectoryDisable {
                expected_revision,
                tenant_id: tenant_id.clone(),
            },
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    recovery.mark_tenant_disabled()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "temporary tenant Disable")?;
    }
    let expected_revision = match recovery.tenant_finalize_expected_revision() {
        Some(revision) => revision,
        None => {
            let revision = directory_revision(session)?;
            recovery.prepare_tenant_finalize(revision)?;
            revision
        }
    };
    let outcome = session.execute_control_operation(
        ControlOperationPayload::TenantDirectoryFinalize {
            expected_revision,
            tenant_id: tenant_id.clone(),
        },
        None,
        |completion| {
            if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                recovery.mark_tenant_cleanup_complete()?;
            }
            Ok(())
        },
    )?;
    let completion = successful_control_completion(outcome, "temporary tenant Finalize")?;
    let ControlResultData::TenantDirectoryMutation {
        action,
        tenant_id: finalized_tenant_id,
        revision,
        ..
    } = completion
        .result
        .result
        .as_ref()
        .context("temporary tenant Finalize omitted its typed result")?
    else {
        bail!("temporary tenant Finalize returned the wrong typed result");
    };
    if action != "finalize" || finalized_tenant_id != &tenant_id {
        bail!("temporary tenant Finalize returned another operation");
    }
    recovery.mark_tenant_absent(*revision)?;
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRecoveryStep {
    Describe,
    TenantCreate(usize),
    TenantKeyGenerate(usize),
    TenantReload(usize),
    BaselineEnumerate(usize),
    Apply(usize),
    CleanupEnumerate(usize),
    CleanupRevoke(usize),
    TenantDisable(usize),
    TenantFinalize(usize),
}

#[derive(Debug)]
struct PendingRecoveryCandidate {
    step: PendingRecoveryStep,
    operation: ControlOperationPayload,
}

fn pending_recovery_candidate(
    step: PendingRecoveryStep,
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<PendingRecoveryCandidate> {
    let binding = recovery.ordinary_binding();
    let tenant_id = binding.tenant_id.clone();
    let operation = match step {
        PendingRecoveryStep::Describe => ControlOperationPayload::TenantDirectoryDescribe,
        PendingRecoveryStep::TenantCreate(_) => EphemeralTenant::from_ids(
            &binding.tenant_id,
            &binding.realm_id,
            &binding.organization_id,
            &binding.tenant_domain,
        )?
        .create_operation(binding.tenant_create_expected_revision),
        PendingRecoveryStep::TenantKeyGenerate(_) => {
            ControlOperationPayload::TenantKeysGenerateLocal {
                tenant_id,
                alg: "ES256".to_owned(),
                purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
            }
        }
        PendingRecoveryStep::TenantReload(_) => ControlOperationPayload::TenantDirectoryReload {
            expected_revision: recovery
                .tenant_reload_expected_revision()
                .context("tenant Reload candidate has no persisted revision")?,
            tenant_id,
        },
        PendingRecoveryStep::BaselineEnumerate(_) | PendingRecoveryStep::CleanupEnumerate(_) => {
            ControlOperationPayload::TenantResourceEnumerate {
                tenant_id,
                selectors: Vec::new(),
            }
        }
        PendingRecoveryStep::Apply(_) => ControlOperationPayload::TenantResourceApply {
            tenant_id,
            resources: binding.resource_identities.clone(),
        },
        PendingRecoveryStep::CleanupRevoke(_) => {
            let enumerate = recovery
                .cleanup_enumerate_operation()
                .context("cleanup Revoke candidate has no persisted enumeration")?;
            let ControlResultData::TenantResourceEnumerate { resources, .. } = enumerate
                .result
                .result
                .as_ref()
                .context("cleanup Enumerate omitted result")?
            else {
                bail!("cleanup Enumerate returned the wrong result");
            };
            let present = resources
                .iter()
                .filter(|candidate| {
                    binding
                        .resource_identities
                        .iter()
                        .any(|bound| bound == *candidate)
                })
                .cloned()
                .collect();
            ControlOperationPayload::TenantResourceRevoke {
                tenant_id,
                resources: present,
            }
        }
        PendingRecoveryStep::TenantDisable(_) => ControlOperationPayload::TenantDirectoryDisable {
            expected_revision: recovery
                .tenant_disable_expected_revision()
                .context("tenant Disable candidate has no persisted revision")?,
            tenant_id,
        },
        PendingRecoveryStep::TenantFinalize(_) => {
            ControlOperationPayload::TenantDirectoryFinalize {
                expected_revision: recovery
                    .tenant_finalize_expected_revision()
                    .context("tenant Finalize candidate has no persisted revision")?,
                tenant_id,
            }
        }
    };
    Ok(PendingRecoveryCandidate { step, operation })
}

fn select_unique_pending_candidate(
    mut matching: Vec<PendingRecoveryCandidate>,
) -> anyhow::Result<PendingRecoveryCandidate> {
    match matching.len() {
        1 => Ok(matching.pop().expect("one matching candidate")),
        0 => bail!(
            "pending ControlOperation does not match any operation reconstructible from the conformance recovery journals"
        ),
        count => bail!(
            "pending ControlOperation matches {count} conformance recovery candidates; refusing ambiguous recovery"
        ),
    }
}

fn next_pending_for_run(
    recovery_index: usize,
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<Option<PendingRecoveryCandidate>> {
    if recovery.tenant_absent() {
        return Ok(None);
    }
    if !recovery.tenant_created() {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantCreate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if !recovery.tenant_key_generated() {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantKeyGenerate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if !recovery.tenant_reloaded() {
        return recovery
            .tenant_reload_expected_revision()
            .map(|_| {
                pending_recovery_candidate(
                    PendingRecoveryStep::TenantReload(recovery_index),
                    recovery,
                )
            })
            .transpose();
    }
    if !recovery.tenant_disabled() && recovery.tenant_disable_expected_revision().is_some() {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantDisable(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if !recovery.tenant_cleanup_complete() && recovery.tenant_finalize_expected_revision().is_some()
    {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantFinalize(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if recovery.terminal_failure().is_some()
        || retained_recovery_stops_before_live_apply(recovery.suite_retention_committed())
    {
        return Ok(None);
    }
    if recovery.baseline_enumerate_operation().is_none() {
        return pending_recovery_candidate(
            PendingRecoveryStep::BaselineEnumerate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if recovery.apply_operation().is_none() {
        return pending_recovery_candidate(PendingRecoveryStep::Apply(recovery_index), recovery)
            .map(Some);
    }
    if recovery.cleanup_enumerate_operation().is_none() {
        return pending_recovery_candidate(
            PendingRecoveryStep::CleanupEnumerate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if recovery.cleanup_revoke_operation().is_none() {
        let candidate = pending_recovery_candidate(
            PendingRecoveryStep::CleanupRevoke(recovery_index),
            recovery,
        )?;
        if matches!(
            &candidate.operation,
            ControlOperationPayload::TenantResourceRevoke { resources, .. }
                if !resources.is_empty()
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn persisted_candidate_for_pending(
    recovery_index: usize,
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
    operation_id: &str,
) -> anyhow::Result<Option<PendingRecoveryCandidate>> {
    let step = if recovery
        .baseline_enumerate_operation()
        .is_some_and(|operation| operation.operation_id == operation_id)
    {
        Some(PendingRecoveryStep::BaselineEnumerate(recovery_index))
    } else if recovery
        .apply_operation()
        .is_some_and(|operation| operation.operation_id == operation_id)
    {
        Some(PendingRecoveryStep::Apply(recovery_index))
    } else if recovery
        .cleanup_enumerate_operation()
        .is_some_and(|operation| operation.operation_id == operation_id)
    {
        Some(PendingRecoveryStep::CleanupEnumerate(recovery_index))
    } else if recovery
        .cleanup_revoke_operation()
        .is_some_and(|operation| operation.operation_id == operation_id)
    {
        Some(PendingRecoveryStep::CleanupRevoke(recovery_index))
    } else if recovery
        .terminal_failure()
        .is_some_and(|operation| operation.operation_id == operation_id)
    {
        Some(match recovery.ordinary_phase() {
            TenantResourceRecoveryPhase::Intent => {
                PendingRecoveryStep::BaselineEnumerate(recovery_index)
            }
            TenantResourceRecoveryPhase::BaselineEnumerated => {
                PendingRecoveryStep::Apply(recovery_index)
            }
            TenantResourceRecoveryPhase::Applied => {
                PendingRecoveryStep::CleanupEnumerate(recovery_index)
            }
            TenantResourceRecoveryPhase::CleanupEnumerated => {
                PendingRecoveryStep::CleanupRevoke(recovery_index)
            }
            TenantResourceRecoveryPhase::CleanupRevoked => {
                bail!("terminal failure cannot follow completed cleanup Revoke")
            }
        })
    } else {
        None
    };
    step.map(|step| pending_recovery_candidate(step, recovery))
        .transpose()
}

fn completed_lifecycle_candidate(
    recovery_index: usize,
    recovery: &nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<Option<PendingRecoveryCandidate>> {
    if recovery.tenant_absent() {
        return Ok(None);
    }
    if recovery.tenant_cleanup_complete() {
        return recovery
            .tenant_finalize_expected_revision()
            .map(|_| {
                pending_recovery_candidate(
                    PendingRecoveryStep::TenantFinalize(recovery_index),
                    recovery,
                )
            })
            .transpose();
    }
    if recovery.tenant_disabled() && recovery.tenant_finalize_expected_revision().is_none() {
        return recovery
            .tenant_disable_expected_revision()
            .map(|_| {
                pending_recovery_candidate(
                    PendingRecoveryStep::TenantDisable(recovery_index),
                    recovery,
                )
            })
            .transpose();
    }
    if recovery.ordinary_phase() != TenantResourceRecoveryPhase::Intent
        || recovery.terminal_failure().is_some()
        || recovery.tenant_disable_expected_revision().is_some()
    {
        return Ok(None);
    }
    if recovery.tenant_reloaded() {
        return recovery
            .tenant_reload_expected_revision()
            .map(|_| {
                pending_recovery_candidate(
                    PendingRecoveryStep::TenantReload(recovery_index),
                    recovery,
                )
            })
            .transpose();
    }
    if recovery.tenant_key_generated() && recovery.tenant_reload_expected_revision().is_none() {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantKeyGenerate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    if recovery.tenant_created() && !recovery.tenant_key_generated() {
        return pending_recovery_candidate(
            PendingRecoveryStep::TenantCreate(recovery_index),
            recovery,
        )
        .map(Some);
    }
    Ok(None)
}

fn resume_pending_candidate<F>(
    session: &nazoauthctl_core::ConformanceSession,
    expected: &nazoauthctl_core::controller_identity::OperationJournalEntry,
    operation: ControlOperationPayload,
    change_set: Option<Vec<u8>>,
    persist: F,
) -> anyhow::Result<nazoauthctl_core::ConformanceControlOutcome>
where
    F: FnOnce(&nazoauthctl_core::ConformanceControlCompletion) -> anyhow::Result<()>,
{
    session
        .resume_pending_control_operation(expected, operation, change_set, persist)?
        .context("the pending ControlOperation changed before recovery dispatch")
}

fn persist_pending_recovery_completion(
    step: PendingRecoveryStep,
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
    completion: &nazoauthctl_core::ConformanceControlCompletion,
) -> anyhow::Result<()> {
    if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Failed {
        let phase = recovery.ordinary_phase();
        return recovery.record_terminal_completion(phase, control_operation(completion));
    }
    match step {
        PendingRecoveryStep::TenantCreate(_) => recovery.mark_tenant_created(),
        PendingRecoveryStep::TenantKeyGenerate(_) => recovery.mark_tenant_key_generated(),
        PendingRecoveryStep::TenantReload(_) => recovery.mark_tenant_reloaded(),
        PendingRecoveryStep::BaselineEnumerate(_) => recovery.record_terminal_completion(
            TenantResourceRecoveryPhase::BaselineEnumerated,
            control_operation(completion),
        ),
        PendingRecoveryStep::Apply(_) => recovery.record_terminal_completion(
            TenantResourceRecoveryPhase::Applied,
            control_operation(completion),
        ),
        PendingRecoveryStep::CleanupEnumerate(_) => recovery.record_terminal_completion(
            TenantResourceRecoveryPhase::CleanupEnumerated,
            control_operation(completion),
        ),
        PendingRecoveryStep::CleanupRevoke(_) => recovery.record_terminal_completion(
            TenantResourceRecoveryPhase::CleanupRevoked,
            control_operation(completion),
        ),
        PendingRecoveryStep::TenantDisable(_) => recovery.mark_tenant_disabled(),
        PendingRecoveryStep::TenantFinalize(_) => recovery.mark_tenant_cleanup_complete(),
        PendingRecoveryStep::Describe => unreachable!(),
    }
}

fn execute_pending_recovery_candidate(
    session: &nazoauthctl_core::ConformanceSession,
    expected: &nazoauthctl_core::controller_identity::OperationJournalEntry,
    candidate: PendingRecoveryCandidate,
    recoveries: &mut [nazoauthctl_conformance::ConformanceRecoveryGuard],
) -> anyhow::Result<()> {
    let operation = candidate.operation;
    match candidate.step {
        PendingRecoveryStep::Describe => {
            let outcome = resume_pending_candidate(session, expected, operation, None, |_| Ok(()))?;
            successful_control_completion(outcome, "recovery pending tenant directory Describe")?;
            Ok(())
        }
        step => {
            let index = match step {
                PendingRecoveryStep::TenantCreate(index)
                | PendingRecoveryStep::TenantKeyGenerate(index)
                | PendingRecoveryStep::TenantReload(index)
                | PendingRecoveryStep::BaselineEnumerate(index)
                | PendingRecoveryStep::Apply(index)
                | PendingRecoveryStep::CleanupEnumerate(index)
                | PendingRecoveryStep::CleanupRevoke(index)
                | PendingRecoveryStep::TenantDisable(index)
                | PendingRecoveryStep::TenantFinalize(index) => index,
                PendingRecoveryStep::Describe => unreachable!(),
            };
            let recovery = &mut recoveries[index];
            let change_set = matches!(step, PendingRecoveryStep::Apply(_))
                .then(|| recovery.read_private_material().map(|value| value.to_vec()))
                .transpose()?;
            let _ =
                resume_pending_candidate(session, expected, operation, change_set, |completion| {
                    persist_pending_recovery_completion(step, recovery, completion)
                })?;
            Ok(())
        }
    }
}

fn resume_pending_conformance_operation(
    session: &nazoauthctl_core::ConformanceSession,
    recoveries: &mut [nazoauthctl_conformance::ConformanceRecoveryGuard],
) -> anyhow::Result<()> {
    let Some(expected) = session.pending_control_operation()? else {
        return Ok(());
    };
    let mut candidates = vec![PendingRecoveryCandidate {
        step: PendingRecoveryStep::Describe,
        operation: ControlOperationPayload::TenantDirectoryDescribe,
    }];
    for (index, recovery) in recoveries.iter().enumerate() {
        if let Some(candidate) =
            persisted_candidate_for_pending(index, recovery, &expected.operation_id)?
        {
            candidates.push(candidate);
        }
        if let Some(candidate) = completed_lifecycle_candidate(index, recovery)? {
            candidates.push(candidate);
        }
        if let Some(candidate) = next_pending_for_run(index, recovery)? {
            candidates.push(candidate);
        }
    }
    let mut matching = Vec::new();
    for candidate in candidates {
        if session.pending_control_operation_matches(&expected, candidate.operation.clone())? {
            matching.push(candidate);
        }
    }
    execute_pending_recovery_candidate(
        session,
        &expected,
        select_unique_pending_candidate(matching)?,
        recoveries,
    )
}

fn recover_pending_runs(
    session: &nazoauthctl_core::ConformanceSession,
    store: &ConformanceRecoveryStore,
    suite_client: &SuiteClient,
) -> anyhow::Result<Vec<SuiteRetentionManifestReceipt>> {
    let mut retained = Vec::new();
    let mut failures = Vec::new();
    let mut pending = store.claim_pending()?;
    resume_pending_conformance_operation(session, &mut pending)?;
    for mut recovery in pending {
        let binding = recovery.ordinary_binding().clone();
        let result = (|| -> anyhow::Result<Option<SuiteRetentionManifestReceipt>> {
            let (directory_revision, tenant_present) =
                tenant_directory_presence(session, &binding.tenant_id)?;
            let terminal_failure = recovery.terminal_failure().cloned();
            if let Some(failure) = terminal_failure {
                let tenant_cleanup = if tenant_present {
                    cleanup_ephemeral_tenant(session, &mut recovery)
                } else {
                    recovery.mark_tenant_absent(directory_revision)
                };
                bail!(
                    "ordinary recovery is blocked by durable failed ControlOperation: operation_id={} request_hash={} error={}; tenant_cleanup={}",
                    failure.operation_id,
                    failure.request_hash,
                    failure
                        .result
                        .error
                        .map(|error| format!("{error:?}"))
                        .unwrap_or_else(|| "missing".to_owned()),
                    tenant_cleanup
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| format!("{error:#}")),
                );
            }
            if tenant_present {
                recover_ephemeral_tenant(session, &mut recovery)?;
            } else {
                recovery.mark_tenant_absent(directory_revision)?;
            }
            if retained_recovery_stops_before_live_apply(recovery.suite_retention_committed()) {
                recovery.publish_committed_suite_retention_manifest()?;
                let receipt = recovery.suite_retention_manifest_receipt()?;
                cleanup_ephemeral_tenant(session, &mut recovery)?;
                if recovery.suite_cleanup_complete() && recovery.proxy_cleanup_complete() {
                    recovery.finish()?;
                }
                return Ok(receipt);
            }
            if !recovery.tenant_absent() && recovery.baseline_enumerate_operation().is_none() {
                let outcome = session.execute_control_operation(
                    ControlOperationPayload::TenantResourceEnumerate {
                        tenant_id: binding.tenant_id.clone(),
                        selectors: Vec::new(),
                    },
                    None,
                    |completion| {
                        recovery.record_terminal_completion(
                            TenantResourceRecoveryPhase::BaselineEnumerated,
                            control_operation(completion),
                        )?;
                        Ok(())
                    },
                )?;
                successful_control_completion(outcome, "recovery baseline Enumerate")?;
            }
            if !recovery.tenant_absent() && recovery.apply_operation().is_none() {
                let material = recovery.read_private_material()?;
                let outcome = session.execute_control_operation(
                    ControlOperationPayload::TenantResourceApply {
                        tenant_id: binding.tenant_id.clone(),
                        resources: binding.resource_identities.clone(),
                    },
                    Some(material.to_vec()),
                    |completion| {
                        recovery.record_terminal_completion(
                            TenantResourceRecoveryPhase::Applied,
                            control_operation(completion),
                        )?;
                        Ok(())
                    },
                )?;
                successful_control_completion(outcome, "recovery Apply")?;
            }
            if !recovery.suite_cleanup_complete() {
                recovery.discard_prepared_suite_retention_staging()?;
                if let Some(suite) = recovery.suite_recovery() {
                    recover_suite_resources(suite_client, suite)
                        .map_err(|error| anyhow::anyhow!(error))?;
                }
                recovery.mark_suite_cleanup_complete()?;
            }
            if !recovery.proxy_cleanup_complete() {
                if let Some(proxy) = binding.proxy.as_ref() {
                    ProxyTrustGuard::recover(&proxy.bundle_path, &proxy.reload_executable)?;
                }
                recovery.mark_proxy_cleanup_complete()?;
            }
            cleanup_run_resources(session, &mut recovery)?;
            let receipt = recovery.suite_retention_manifest_receipt()?;
            if recovery.suite_cleanup_complete() && recovery.proxy_cleanup_complete() {
                recovery.finish()?;
            }
            Ok(receipt)
        })();
        match result {
            Ok(Some(receipt)) => retained.push(receipt),
            Ok(None) => {}
            Err(error) => failures.push(format!("{}: {error:#}", binding.run_id)),
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

fn recover_ephemeral_tenant(
    session: &nazoauthctl_core::ConformanceSession,
    recovery: &mut nazoauthctl_conformance::ConformanceRecoveryGuard,
) -> anyhow::Result<()> {
    let tenant = EphemeralTenant::from_ids(
        &recovery.ordinary_binding().tenant_id,
        &recovery.ordinary_binding().realm_id,
        &recovery.ordinary_binding().organization_id,
        &recovery.ordinary_binding().tenant_domain,
    )?;
    if !recovery.tenant_created() {
        let expected_revision = recovery.ordinary_binding().tenant_create_expected_revision;
        let outcome = session.execute_control_operation(
            tenant.create_operation(expected_revision),
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    recovery.mark_tenant_created()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "recovery temporary tenant Create")?;
    }
    if !recovery.tenant_key_generated() {
        let outcome = session.execute_control_operation(
            ControlOperationPayload::TenantKeysGenerateLocal {
                tenant_id: tenant.tenant_id.clone(),
                alg: "ES256".to_owned(),
                purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
            },
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    recovery.mark_tenant_key_generated()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "recovery tenant key generation")?;
    }
    if !recovery.tenant_reloaded() {
        let expected_revision = match recovery.tenant_reload_expected_revision() {
            Some(revision) => revision,
            None => {
                let revision = directory_revision(session)?;
                recovery.prepare_tenant_reload(revision)?;
                revision
            }
        };
        let outcome = session.execute_control_operation(
            ControlOperationPayload::TenantDirectoryReload {
                expected_revision,
                tenant_id: tenant.tenant_id,
            },
            None,
            |completion| {
                if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                    recovery.mark_tenant_reloaded()?;
                }
                Ok(())
            },
        )?;
        successful_control_completion(outcome, "recovery temporary tenant Reload")?;
    }
    Ok(())
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

// Keep the control-evidence failure boundary explicit and independently
// testable.  Retention ownership is committed before this callback and is
// intentionally not an input here, so a writer failure cannot select Suite
// cleanup or change a retained-plan decision.
fn record_control_evidence_result<F, E>(
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

fn resolve_token(
    invocation: &RunInvocation,
    origin: &Origin,
    language: OutputLanguage,
) -> anyhow::Result<(BearerToken, bool)> {
    if let Some(token) = &invocation.token {
        return Ok((token.clone(), false));
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
    let store = CredentialStore::new(credential_root()?)?;
    if let Some(token) = store.load(origin)? {
        return Ok((token, false));
    }
    if !io::stdin().is_terminal() {
        bail!(match language {
            OutputLanguage::Chinese => {
                "未保存 OIDF Suite API Token；请使用 --token TOKEN 或 --token-stdin 提供"
            }
            OutputLanguage::English => {
                "no OIDF Suite API token is stored; provide one with --token TOKEN or --token-stdin"
            }
        });
    }
    Ok((prompt_token(language)?, true))
}

fn prompt_token(language: OutputLanguage) -> anyhow::Result<BearerToken> {
    let prompt = match language {
        OutputLanguage::Chinese => "OIDF Suite API Token：",
        OutputLanguage::English => "OIDF Suite API Token: ",
    };
    BearerToken::new(rpassword::prompt_password(prompt)?).map_err(Into::into)
}

fn authenticate_suite(
    invocation: &RunInvocation,
    origin: &Origin,
    language: OutputLanguage,
) -> anyhow::Result<(SuiteClient, BearerToken)> {
    let transient_token = invocation.token.is_some() || invocation.token_stdin;
    let (mut token, mut prompted) = resolve_token(invocation, origin, language)?;
    loop {
        let client = SuiteClient::new(origin.clone(), token.clone(), ClientConfig::default())
            .context("failed to initialize the Suite client")?;
        match client.probe_auth() {
            Ok(_) => {
                if prompted && !transient_token {
                    CredentialStore::new(credential_root()?)?.save(origin, &token)?;
                }
                return Ok((client, token));
            }
            Err(
                error @ (SuiteClientError::AuthenticationRejected
                | SuiteClientError::AuthenticationResponseMalformed),
            ) if io::stdin().is_terminal() => {
                eprintln!(
                    "{}",
                    match (language, error) {
                        (OutputLanguage::Chinese, SuiteClientError::AuthenticationRejected) =>
                            "OIDF Suite 拒绝了当前 Token，请重新输入（Ctrl+C 取消）。",
                        (OutputLanguage::English, SuiteClientError::AuthenticationRejected) =>
                            "The OIDF Suite rejected the current token. Enter another token (Ctrl+C to cancel).",
                        (
                            OutputLanguage::Chinese,
                            SuiteClientError::AuthenticationResponseMalformed,
                        ) => {
                            "OIDF Suite 无法确认当前 Token（认证响应不是 JSON），请重新输入（Ctrl+C 取消）。"
                        }
                        (
                            OutputLanguage::English,
                            SuiteClientError::AuthenticationResponseMalformed,
                        ) => {
                            "The OIDF Suite could not validate the current token because its authentication response was not JSON. Enter another token (Ctrl+C to cancel)."
                        }
                        _ => unreachable!(),
                    }
                );
                token = prompt_token(language)?;
                prompted = true;
            }
            Err(error) => {
                return Err(error).context("Suite API token authentication failed");
            }
        }
    }
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

fn create_evidence_directory(recovery_directory: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    let root = recovery_directory.join("evidence");
    fs::create_dir_all(&root).context("failed to create the OIDF evidence root")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .context("failed to make the OIDF evidence root private")?;
        let directory = root.join(run_id);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .context("failed to create the run evidence directory")?;
        nazoauthctl_conformance::validate_private_evidence_directory(&directory)
            .context("automatic evidence directory is not root-owned and private")?;
        Ok(directory)
    }
    #[cfg(not(unix))]
    {
        let directory = root.join(run_id);
        fs::create_dir(&directory).context("failed to create the run evidence directory")?;
        Ok(directory)
    }
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
