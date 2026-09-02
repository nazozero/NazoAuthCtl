//! Ordinary tenant-resource backed OIDF orchestration.
//!
//! This is the only producer path for `conformance run`. The signed artifact
//! owns executable Matrix facts; NazoAuth owns ordinary tenant resources; the
//! Suite remains an external test runner. No conformance lease or Suite-only
//! NazoAuth management endpoint is used here.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{ControlOperationPayload, ControlResultData, ControlTenantBoundary};
use nazoauthctl_conformance::{
    ArtifactMaterializationBinding, BearerToken, BrowserAutomation, BrowserExecutor, BrowserPolicy,
    BrowserReviewScreenshotCapture, BrowserTargetOrigin, CibaUserApprovalBridge,
    CibaUserApprovalClient, ClientConfig, ConformanceAutomation, ConformanceBinding,
    ConformanceRecoveryStore, ConformanceRunConfig, ConformanceRunner, CredentialStore,
    DescriptorMaterializer, EvidenceBundleIdentity, EvidenceBundleReceipt, EvidenceControlIdentity,
    EvidenceControlOperation, EvidenceDeploymentIdentity, EvidenceRuntimeIdentity,
    EvidenceSourceIdentity, HttpRequest, HttpTransport, ManagedWebDriver, MatrixSelection,
    OidfArtifactMatrix, OidfDriverLane, OidfPlanResourceBudget, OidfPlanSelection,
    OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver, OpenId4VpVerifier,
    OpenId4VpVerifierClient, Origin, ProxyTrustGuard, RunControl, StableRenderer, SuiteClient,
    SuiteResourceObserver, SuiteRetentionDeferredReview, SuiteRetentionManifest,
    SuiteRetentionManifestReceipt, SuiteRetentionPlan, SuiteRetentionScreenshotManifest,
    TenantResourceApplyOutput, TenantResourceControlOperation, TenantResourceRecoveryBinding,
    TenantResourceRecoveryPhase, Transport, TtyRenderer, bundled_oidf_matrix,
    open_bundled_oidf_driver_plan, recover_suite_resources, write_private_control_evidence_bundle,
    write_review_screenshot_manifest,
};
use serde::Serialize;
use url::Url;
use zeroize::Zeroizing;

use super::RunInvocation;

const MAX_STDIN_TOKEN_BYTES: u64 = 16 * 1024;
const OIDF_TENANT_DOMAIN: &str = "oidf.nazoauth.com";

pub(super) fn execute(invocation: RunInvocation) -> anyhow::Result<i32> {
    let suite_origin = Origin::official();
    let session = nazoauthctl_core::ConformanceSession::open(invocation.instance.as_deref())
        .context("deployment is not ready for ordinary conformance orchestration")?;
    let deployment = session.deployment_evidence();
    let recovery_directory = session.recovery_directory()?;
    let recovery_store =
        ConformanceRecoveryStore::open(&recovery_directory, &deployment.deployment_id)?;

    let now = current_unix_time()?;
    let driver_plan = open_bundled_oidf_driver_plan(
        OidfPlanSelection {
            groups: invocation.groups.clone(),
            plans: invocation.plans.clone(),
        },
        now,
    )
    .context("bundled OIDF Matrix cannot be opened")?;
    let artifact_digest = driver_plan.artifact.driver_manifest_sha256.clone();

    let (token, prompted) = resolve_token(&invocation, &suite_origin)?;
    let suite_client =
        SuiteClient::new(suite_origin.clone(), token.clone(), ClientConfig::default())
            .context("failed to initialize the Suite client")?;
    suite_client
        .probe_auth()
        .context("Suite API token authentication failed")?;
    if prompted {
        CredentialStore::new(credential_root()?)?.save(&suite_origin, &token)?;
    }
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
    let ephemeral_tenant = EphemeralTenant::new(&invocation.tenant_id)?;
    let materialization_now = current_unix_time()?;
    if materialization_now > driver_plan.latest_execution_start_at {
        bail!("signed artifact no longer has enough validity remaining for the selected run");
    }
    let ciba_callback = prepare_ciba_user_approval_callback(
        &ephemeral_tenant.issuer,
        driver_plan
            .plans
            .iter()
            .any(|entry| entry.driver_handler.lane == OidfDriverLane::Ciba),
    )?;
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
    };

    let private_manifest_path = recovery_directory.join(format!("material-{request_jti}.json"));
    manifest
        .write_private(&private_manifest_path)
        .context("failed to durably persist private Apply material")?;
    let tenant_create_expected_revision = directory_revision(&session)?;
    let recovery = match recovery_store.begin_ordinary_run(TenantResourceRecoveryBinding {
        deployment_id: deployment.deployment_id.clone(),
        tenant_id: invocation.tenant_id.clone(),
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
        let deployment_trust_anchor =
            provision_ephemeral_tenant(&session, &ephemeral_tenant, &recovery)
                .context("failed to provision the run-scoped OIDF tenant")?;
        probe_ephemeral_tenant(&ephemeral_tenant.issuer).context(
            "the temporary tenant is not publicly reachable; verify wildcard TLS and host routing for *.oidf.nazoauth.com",
        )?;
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
        Err(error) => return cleanup_failed_pre_suite_setup(&session, recovery, error),
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
    let ciba_bridge =
        start_ciba_user_approval_bridge(ciba_callback, &ephemeral_tenant.issuer, &run_secrets)?;
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
        ciba_bridge,
        &evidence_directory,
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
            Err(_) => {
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
        Ok(report) => Some(report),
        Err(error) => {
            errors.push(format!("run={error:#}"));
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
    if let (Some(report), Some(cleanup_operations)) = (report.as_ref(), cleanup_evidence.as_ref()) {
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
    serde_json::to_writer_pretty(io::stdout().lock(), &output)
        .context("failed to write the structured ordinary conformance report")?;
    writeln!(io::stdout()).context("failed to finish the structured conformance report")?;
    Ok(if success { 0 } else { 1 })
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
    use super::{conformance_run_succeeds, prepare_ciba_user_approval_callback};

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
    fn ciba_callback_is_derived_from_the_temporary_tenant() {
        let callback = prepare_ciba_user_approval_callback(
            "https://00000000-0000-0000-0000-000000000001.oidf.nazoauth.com",
            true,
        )
        .unwrap()
        .unwrap();
        assert!(
            callback
                .public_url
                .starts_with("https://00000000-0000-0000-0000-000000000001.oidf.nazoauth.com/__nazoauthctl/ciba-approval?approval_token=")
        );
        assert_eq!(callback.callback_path, "/__nazoauthctl/ciba-approval");
        assert_eq!(
            callback.listen_addr,
            std::net::SocketAddr::from(([127, 0, 0, 1], 19046))
        );
        assert!(
            prepare_ciba_user_approval_callback(
                "https://00000000-0000-0000-0000-000000000001.oidf.nazoauth.com",
                false,
            )
            .unwrap()
            .is_none()
        );
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
    fn new(tenant_id: &str) -> anyhow::Result<Self> {
        let tenant_id = uuid::Uuid::parse_str(tenant_id)
            .context("generated OIDF tenant ID is invalid")?
            .to_string();
        let realm_id = uuid::Uuid::now_v7().to_string();
        let organization_id = uuid::Uuid::now_v7().to_string();
        Self::from_ids(&tenant_id, &realm_id, &organization_id)
    }

    fn from_ids(tenant_id: &str, realm_id: &str, organization_id: &str) -> anyhow::Result<Self> {
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
        let external_host = format!("{tenant_id}.{OIDF_TENANT_DOMAIN}");
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
fn run_signed_suite(
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
    ciba_bridge: Option<CibaUserApprovalBridge>,
    evidence_directory: &Path,
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
    let review_screenshot_capture = invocation
        .capture_review_screenshots
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
    let mut automation = Vec::with_capacity(invocation.jobs);
    for _ in 0..invocation.jobs {
        let browser = build_browser(target_issuer, suite_origin)?;
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
            browser: Some(browser),
            review_screenshot_capture: review_screenshot_capture.clone(),
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
        upload_review_screenshots: invocation.upload_review_screenshots,
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
    target_issuer: &str,
    requires_ciba: bool,
) -> anyhow::Result<Option<CibaUserApprovalCallback>> {
    if !requires_ciba {
        return Ok(None);
    }
    let mut public_url = Url::parse(target_issuer)
        .context("temporary tenant issuer is not a valid CIBA callback origin")?;
    public_url.set_path("/__nazoauthctl/ciba-approval");
    let callback_path = public_url.path().to_owned();
    let approval_token = Zeroizing::new(random_urlsafe_token(32));
    Ok(Some(CibaUserApprovalCallback {
        public_url: Zeroizing::new(format!(
            "{public_url}?approval_token={}&auth_req_id={{auth_req_id}}&action={{action}}",
            approval_token.as_str()
        )),
        callback_path,
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 19046)),
        approval_token,
    }))
}

fn start_ciba_user_approval_bridge(
    callback: Option<CibaUserApprovalCallback>,
    target_issuer: &str,
    secrets: &RunSecrets,
) -> anyhow::Result<Option<CibaUserApprovalBridge>> {
    let Some(callback) = callback else {
        return Ok(None);
    };
    let issuer = Url::parse(target_issuer)
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
    let resources_clean = match cleanup_run_resources(session, &mut recovery) {
        Ok(_) => true,
        Err(error) => {
            cleanup_errors.push(format!("resources={error:#}"));
            false
        }
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

fn build_browser(
    target_issuer: &str,
    suite_origin: &Origin,
) -> anyhow::Result<Arc<Mutex<dyn BrowserAutomation>>> {
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
            tenant_id,
        },
        None,
        |completion| {
            if completion.result.outcome == nazo_operator_protocol::ControlOutcome::Succeeded {
                recovery.mark_tenant_cleanup_complete()?;
            }
            Ok(())
        },
    )?;
    successful_control_completion(outcome, "temporary tenant Finalize")?;
    Ok(())
}
fn recover_pending_runs(
    session: &nazoauthctl_core::ConformanceSession,
    store: &ConformanceRecoveryStore,
    suite_client: &SuiteClient,
) -> anyhow::Result<Vec<SuiteRetentionManifestReceipt>> {
    let mut retained = Vec::new();
    let mut failures = Vec::new();
    for mut recovery in store.claim_pending()? {
        let binding = recovery.ordinary_binding().clone();
        let result = (|| -> anyhow::Result<Option<SuiteRetentionManifestReceipt>> {
            let (directory_revision, tenant_present) =
                tenant_directory_presence(session, &binding.tenant_id)?;
            if tenant_present {
                recover_ephemeral_tenant(session, &mut recovery)?;
            } else {
                recovery.mark_tenant_absent(directory_revision)?;
            }
            if let Some(failure) = recovery.terminal_failure().cloned() {
                let tenant_cleanup = cleanup_ephemeral_tenant(session, &mut recovery);
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
) -> anyhow::Result<(BearerToken, bool)> {
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
        bail!("no official Suite API token is stored; pipe it with --token-stdin once");
    }
    let value = rpassword::prompt_password("OpenID Foundation Conformance Suite API Token:")?;
    let token = BearerToken::new(value)?;
    Ok((token, true))
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
        return Ok(directory);
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
