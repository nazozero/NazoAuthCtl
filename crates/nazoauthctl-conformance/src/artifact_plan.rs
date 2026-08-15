//! Pure, offline compilation of a verified artifact Matrix into an inspection plan.
//!
//! This boundary intentionally does not create an executable deployment run.
//! A signed executable driver and sandbox, authenticated capability negotiation,
//! ordinary NazoAuth resource providers, target/Suite origin policy, and a
//! deployment-bound recovery journal do not exist yet; the plan records those
//! blockers instead of treating caller-supplied capability names as proof.
//! Execution-stage code may later supply an authenticated provider
//! authorization fact through [`authorize_oidf_driver_execution`].  This
//! module checks that fact's bindings and freshness but does not parse or
//! reimplement the provider's compact-JWS verifier.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use nazo_operator_protocol::{TenantResourceKind, TenantResourceOperation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{CachedOidfArtifact, OidfArtifactMatrix, OidfDriverHandler, OidfPlanResourceBudget};

pub const OIDF_DRIVER_INSPECTION_PLAN_SCHEMA: u32 = 5;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfPlanSelection {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub plans: Vec<String>,
}

/// The deployment/runtime identity and capability facts expected by the
/// execution stage.  These values come from the authenticated task/capability
/// exchange; an offline inspection plan must not invent them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidfProviderExecutionBinding {
    pub deployment_id: String,
    pub tenant_id: String,
    pub runtime_instance_id: String,
    pub runtime_build_id: String,
    pub capability_jti: String,
    pub capability_sha256: String,
    /// Capabilities required by the signed driver/runner. These are not
    /// tenant-resource operations and must remain a separate fact set.
    pub runner_capabilities: BTreeSet<String>,
    /// Provider actions authorized for this run; all three closed operations
    /// are required regardless of runner capability names.
    pub provider_actions: BTreeSet<TenantResourceOperation>,
    pub provider_resource_kinds: BTreeSet<TenantResourceKind>,
    pub current_revision: u64,
    pub current_manifest_sha256: String,
    pub artifact_source: String,
    pub suite_origin: String,
}

/// A freshness-verified provider authorization fact supplied only at the
/// execution boundary.  The compact capability itself is intentionally kept
/// outside this crate; its authenticated digest/JTI and decoded claims are
/// passed in after the provider verifier has accepted it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProviderAuthorization {
    pub deployment_id: String,
    pub tenant_id: String,
    pub runtime_instance_id: String,
    pub runtime_build_id: String,
    pub capability_jti: String,
    pub capability_sha256: String,
    pub capability_issued_at: i64,
    pub capability_expires_at: i64,
    pub runner_capabilities: BTreeSet<String>,
    pub provider_actions: BTreeSet<TenantResourceOperation>,
    pub provider_resource_kinds: BTreeSet<TenantResourceKind>,
    pub current_revision: u64,
    pub current_manifest_sha256: String,
    pub artifact_source: String,
    pub suite_origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverPlanEntry {
    pub task_jti: String,
    pub group_id: String,
    pub profile: String,
    pub group_variant_id: String,
    pub group_variant_values: BTreeMap<String, String>,
    pub plan_id: String,
    pub suite_plan_name: String,
    pub driver_handler: OidfDriverHandler,
    pub resource_budget: OidfPlanResourceBudget,
    pub plan_variant_values: BTreeMap<String, String>,
    pub config_template: Value,
    pub required_capabilities: Vec<String>,
    pub expected_skipped_modules: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfBoundedRunnerContract {
    pub protocol: String,
    pub minimum_jobs: u32,
    pub maximum_jobs: u32,
    pub independent_plan_tasks_required: bool,
    pub independent_evidence_required: bool,
    pub failure_collection_required: bool,
    pub finally_cleanup_required: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverInspectionPlan {
    pub schema: u32,
    pub plan_jti: String,
    pub planned_at: i64,
    pub artifact_cache_entry: PathBuf,
    pub manifest_url: String,
    pub artifact: crate::VerifiedOidfArtifact,
    pub caller_declared_capabilities: Vec<String>,
    pub selection: OidfPlanSelection,
    pub selected_group_count: u32,
    pub selected_plan_count: u32,
    pub selected_resource_budget: OidfPlanResourceBudget,
    pub latest_execution_start_at: i64,
    pub runner: OidfBoundedRunnerContract,
    pub plans: Vec<OidfDriverPlanEntry>,
    pub deployment_bound: bool,
    pub capabilities_attested: bool,
    pub execution_permitted: bool,
    pub execution_blockers: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum OidfPlanError {
    #[error("verified artifact cache identity is unsupported")]
    CacheIdentity,
    #[error("verified artifact Matrix could not be decoded")]
    MalformedMatrix,
    #[error("verified artifact Matrix identity changed before planning")]
    MatrixIdentity,
    #[error("plan selection contains an invalid or duplicate identifier")]
    InvalidSelection,
    #[error("plan selection names an unknown group or plan")]
    UnknownSelection,
    #[error("group and plan filters select no common plan")]
    EmptySelection,
    #[error("selected plan resources exceed the signed artifact bounds")]
    ResourceBound,
    #[error("artifact validity cannot contain the selected resource budget")]
    ArtifactValidity,
    #[error("execution authorization is missing, stale, or not bound to the plan")]
    ExecutionAuthorization,
}

const CAPABILITY_MAX_LIFETIME_SECONDS: i64 = 60;
const REQUIRED_PROVIDER_ACTIONS: [TenantResourceOperation; 3] = [
    TenantResourceOperation::Apply,
    TenantResourceOperation::Enumerate,
    TenantResourceOperation::Revoke,
];
const REQUIRED_PROVIDER_RESOURCE_KINDS: [TenantResourceKind; 6] = [
    TenantResourceKind::OauthClient,
    TenantResourceKind::MtlsTrustAnchor,
    TenantResourceKind::CibaDecisionBinding,
    TenantResourceKind::Openid4vcDataset,
    TenantResourceKind::Openid4vcTrustPolicy,
    TenantResourceKind::User,
];

pub(crate) fn compile_oidf_driver_inspection_plan(
    cached: CachedOidfArtifact,
    driver_bytes: &[u8],
    matrix_bytes: &[u8],
    caller_declared_capabilities: &BTreeSet<String>,
    selection: OidfPlanSelection,
    now: i64,
) -> Result<OidfDriverInspectionPlan, OidfPlanError> {
    if cached.schema != crate::OIDF_ARTIFACT_CACHE_SCHEMA_VERSION {
        return Err(OidfPlanError::CacheIdentity);
    }
    let driver = crate::artifact_driver::validate_oidf_driver(
        driver_bytes,
        cached.artifact.driver_schema,
        cached.artifact.driver_size,
        &cached.artifact.driver_sha256,
        cached.artifact.engine_protocol,
    )
    .map_err(|_| OidfPlanError::CacheIdentity)?;
    let driver_handlers = driver
        .handlers
        .into_iter()
        .map(|handler| (handler.id.clone(), handler))
        .collect::<BTreeMap<_, _>>();
    if matrix_bytes.len() as u64 != cached.artifact.matrix_size
        || sha256(matrix_bytes) != cached.artifact.matrix_sha256
    {
        return Err(OidfPlanError::MatrixIdentity);
    }
    let matrix: OidfArtifactMatrix =
        serde_json::from_slice(matrix_bytes).map_err(|_| OidfPlanError::MalformedMatrix)?;
    if matrix.schema != crate::OIDF_MATRIX_SCHEMA_VERSION {
        return Err(OidfPlanError::MalformedMatrix);
    }
    let groups = selection_set(&selection.groups)?;
    let plans = selection_set(&selection.plans)?;
    if groups
        .iter()
        .any(|wanted| !matrix.groups.iter().any(|group| &group.id == wanted))
        || plans.iter().any(|wanted| {
            !matrix
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| &plan.id == wanted)
        })
    {
        return Err(OidfPlanError::UnknownSelection);
    }

    let mut selected_groups = BTreeSet::new();
    let mut entries = Vec::new();
    let mut selected_resource_budget = OidfPlanResourceBudget {
        modules: 0,
        clients: 0,
        wall_clock_seconds: 0,
    };
    for group in matrix.groups {
        if !groups.is_empty() && !groups.contains(&group.id) {
            continue;
        }
        for plan in group.plans {
            if !plans.is_empty() && !plans.contains(&plan.id) {
                continue;
            }
            selected_resource_budget.modules = selected_resource_budget
                .modules
                .checked_add(plan.resource_budget.modules)
                .ok_or(OidfPlanError::ResourceBound)?;
            selected_resource_budget.clients = selected_resource_budget
                .clients
                .checked_add(plan.resource_budget.clients)
                .ok_or(OidfPlanError::ResourceBound)?;
            selected_resource_budget.wall_clock_seconds = selected_resource_budget
                .wall_clock_seconds
                .checked_add(plan.resource_budget.wall_clock_seconds)
                .ok_or(OidfPlanError::ResourceBound)?;
            selected_groups.insert(group.id.clone());
            let driver_handler = driver_handlers
                .get(&plan.driver_handler)
                .cloned()
                .ok_or(OidfPlanError::CacheIdentity)?;
            entries.push(OidfDriverPlanEntry {
                task_jti: uuid::Uuid::now_v7().to_string(),
                group_id: group.id.clone(),
                profile: group.profile.clone(),
                group_variant_id: group.variant.id.clone(),
                group_variant_values: group.variant.values.clone(),
                plan_id: plan.id,
                suite_plan_name: plan.plan,
                driver_handler,
                resource_budget: plan.resource_budget,
                plan_variant_values: plan.variant,
                config_template: plan.config_template,
                required_capabilities: plan.required_capabilities,
                expected_skipped_modules: plan.expected_results.into_keys().collect(),
            });
        }
    }
    if entries.is_empty() {
        return Err(OidfPlanError::EmptySelection);
    }
    let selected_plan_count =
        u32::try_from(entries.len()).map_err(|_| OidfPlanError::ResourceBound)?;
    if selected_plan_count > cached.artifact.resource_bounds.max_plans {
        return Err(OidfPlanError::ResourceBound);
    }
    if selected_resource_budget.modules > cached.artifact.resource_bounds.max_modules
        || selected_resource_budget.clients > cached.artifact.resource_bounds.max_clients
        || selected_resource_budget.wall_clock_seconds
            > cached.artifact.resource_bounds.max_wall_clock_seconds
    {
        return Err(OidfPlanError::ResourceBound);
    }
    let selected_wall_clock = i64::try_from(selected_resource_budget.wall_clock_seconds)
        .map_err(|_| OidfPlanError::ArtifactValidity)?;
    let latest_execution_start_at = cached
        .artifact
        .expires_at
        .checked_sub(selected_wall_clock)
        .and_then(|value| value.checked_sub(1))
        .ok_or(OidfPlanError::ArtifactValidity)?;
    if now < cached.artifact.not_before
        || now >= cached.artifact.expires_at
        || now > latest_execution_start_at
    {
        return Err(OidfPlanError::ArtifactValidity);
    }
    let selected_group_count =
        u32::try_from(selected_groups.len()).map_err(|_| OidfPlanError::ResourceBound)?;
    let maximum_jobs =
        u32::try_from(crate::MAX_PARALLEL_JOBS).map_err(|_| OidfPlanError::ResourceBound)?;
    Ok(OidfDriverInspectionPlan {
        schema: OIDF_DRIVER_INSPECTION_PLAN_SCHEMA,
        plan_jti: uuid::Uuid::now_v7().to_string(),
        planned_at: now,
        artifact_cache_entry: cached.cache_entry,
        manifest_url: cached.manifest_url,
        artifact: cached.artifact,
        caller_declared_capabilities: caller_declared_capabilities.iter().cloned().collect(),
        selection,
        selected_group_count,
        selected_plan_count,
        selected_resource_budget,
        latest_execution_start_at,
        runner: OidfBoundedRunnerContract {
            protocol: crate::BOUNDED_PLAN_RUNNER_PROTOCOL.to_owned(),
            minimum_jobs: if selected_plan_count > 1 { 2 } else { 1 },
            maximum_jobs,
            independent_plan_tasks_required: true,
            independent_evidence_required: true,
            failure_collection_required: true,
            finally_cleanup_required: true,
        },
        plans: entries,
        deployment_bound: false,
        capabilities_attested: false,
        execution_permitted: false,
        execution_blockers: vec![
            "authenticated-capability-negotiation",
            "ordinary-resource-provider",
            "target-and-suite-origin-policy",
            "deployment-bound-crash-safe-execution-journal",
        ],
    })
}

/// Apply an authenticated provider authorization to an inspection plan.
///
/// Offline compilation intentionally leaves execution disabled.  This helper
/// is the only transition that can set `execution_permitted`; it validates
/// every identity, capability, action/kind, revision/manifest, and
/// artifact/Suite origin binding before mutating the plan.  A failed check
/// leaves the plan in its offline, non-executable state.
pub fn authorize_oidf_driver_execution(
    plan: &mut OidfDriverInspectionPlan,
    binding: &OidfProviderExecutionBinding,
    authorization: &AuthenticatedProviderAuthorization,
    now: i64,
) -> Result<(), OidfPlanError> {
    if plan.deployment_bound || plan.capabilities_attested || plan.execution_permitted {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    validate_provider_execution_binding(plan, binding)?;
    validate_authenticated_provider_authorization(binding, authorization, now)?;
    plan.deployment_bound = true;
    plan.capabilities_attested = true;
    plan.execution_permitted = true;
    plan.execution_blockers.clear();
    Ok(())
}

fn validate_provider_execution_binding(
    plan: &OidfDriverInspectionPlan,
    binding: &OidfProviderExecutionBinding,
) -> Result<(), OidfPlanError> {
    for identity in [
        &binding.deployment_id,
        &binding.tenant_id,
        &binding.runtime_instance_id,
        &binding.runtime_build_id,
        &binding.capability_jti,
    ] {
        if crate::artifact::validate_identifier(identity, 256).is_err() {
            return Err(OidfPlanError::ExecutionAuthorization);
        }
    }
    if !is_lower_hex_sha256(&binding.capability_sha256)
        || !is_lower_hex_sha256(&binding.current_manifest_sha256)
        || binding.artifact_source != plan.artifact.source
        || !artifact_source_covers_manifest(&binding.artifact_source, &plan.manifest_url)
        || !is_suite_origin(&binding.suite_origin)
        || binding.suite_origin != plan.artifact.suite.origin
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    validate_runner_capabilities(&binding.runner_capabilities)?;
    validate_provider_actions(&binding.provider_actions)?;
    validate_provider_resource_kinds(&binding.provider_resource_kinds)?;
    let mut runner_capabilities = BTreeSet::new();
    runner_capabilities.extend(plan.artifact.required_capabilities.iter().cloned());
    for entry in &plan.plans {
        runner_capabilities.extend(entry.required_capabilities.iter().cloned());
    }
    if binding.runner_capabilities != runner_capabilities {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    Ok(())
}

fn validate_authenticated_provider_authorization(
    binding: &OidfProviderExecutionBinding,
    authorization: &AuthenticatedProviderAuthorization,
    now: i64,
) -> Result<(), OidfPlanError> {
    if authorization.deployment_id != binding.deployment_id
        || authorization.tenant_id != binding.tenant_id
        || authorization.runtime_instance_id != binding.runtime_instance_id
        || authorization.runtime_build_id != binding.runtime_build_id
        || authorization.capability_jti != binding.capability_jti
        || authorization.capability_sha256 != binding.capability_sha256
        || authorization.current_revision != binding.current_revision
        || authorization.current_manifest_sha256 != binding.current_manifest_sha256
        || authorization.artifact_source != binding.artifact_source
        || authorization.suite_origin != binding.suite_origin
        || authorization.runner_capabilities != binding.runner_capabilities
        || authorization.provider_actions != binding.provider_actions
        || authorization.provider_resource_kinds != binding.provider_resource_kinds
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    if !is_lower_hex_sha256(&authorization.capability_sha256)
        || !is_lower_hex_sha256(&authorization.current_manifest_sha256)
        || !is_suite_origin(&authorization.suite_origin)
        || authorization.capability_issued_at <= 0
        || authorization.capability_expires_at <= authorization.capability_issued_at
        || authorization
            .capability_expires_at
            .checked_sub(authorization.capability_issued_at)
            .is_none_or(|lifetime| lifetime > CAPABILITY_MAX_LIFETIME_SECONDS)
        || now < authorization.capability_issued_at
        || now >= authorization.capability_expires_at
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    validate_runner_capabilities(&authorization.runner_capabilities)?;
    validate_provider_actions(&authorization.provider_actions)?;
    validate_provider_resource_kinds(&authorization.provider_resource_kinds)?;
    Ok(())
}

fn validate_runner_capabilities(values: &BTreeSet<String>) -> Result<(), OidfPlanError> {
    if values.is_empty()
        || values.len() > 64
        || values
            .iter()
            .any(|value| crate::artifact::validate_identifier(value, 128).is_err())
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    Ok(())
}

fn validate_provider_actions(
    values: &BTreeSet<TenantResourceOperation>,
) -> Result<(), OidfPlanError> {
    if values.is_empty()
        || values.len() > 16
        || REQUIRED_PROVIDER_ACTIONS
            .iter()
            .any(|required| !values.contains(required))
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    Ok(())
}

fn validate_provider_resource_kinds(
    values: &BTreeSet<TenantResourceKind>,
) -> Result<(), OidfPlanError> {
    if values.is_empty()
        || values.len() > 16
        || REQUIRED_PROVIDER_RESOURCE_KINDS
            .iter()
            .any(|required| !values.contains(required))
    {
        return Err(OidfPlanError::ExecutionAuthorization);
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_suite_origin(value: &str) -> bool {
    crate::origin::Origin::parse_suite(value).is_ok_and(|origin| origin.as_str() == value)
}

fn artifact_source_covers_manifest(source: &str, manifest: &str) -> bool {
    let Ok(source) = url::Url::parse(source) else {
        return false;
    };
    let Ok(manifest) = url::Url::parse(manifest) else {
        return false;
    };
    source.scheme() == manifest.scheme()
        && source.host() == manifest.host()
        && source.port_or_known_default() == manifest.port_or_known_default()
        && manifest.path().starts_with(source.path())
        && manifest.path().len() > source.path().len()
}

fn selection_set(values: &[String]) -> Result<BTreeSet<String>, OidfPlanError> {
    let mut selected = BTreeSet::new();
    for value in values {
        if crate::artifact::validate_identifier(value, 128).is_err()
            || !selected.insert(value.clone())
        {
            return Err(OidfPlanError::InvalidSelection);
        }
    }
    Ok(selected)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::{
        OidfArtifactMatrixGroup, OidfArtifactMatrixPlan, OidfArtifactMatrixVariant,
        OidfDriverAutomation, OidfDriverHandler, OidfDriverLane, OidfDriverProgram,
        OidfPlanResourceBudget, OidfResourceBounds, OidfSuiteIdentity, VerifiedOidfArtifact,
    };

    #[test]
    fn compiles_exact_selection_without_claiming_execution_readiness() {
        let matrix = matrix_bytes();
        let plan = compile_oidf_driver_inspection_plan(
            cached(&matrix),
            &matrix,
            &BTreeSet::from(["nazoauth.client.create".to_owned()]),
            OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p002".to_owned()],
            },
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(plan.selected_group_count, 1);
        assert_eq!(plan.selected_plan_count, 1);
        assert_eq!(plan.plans[0].plan_id, "p002");
        assert_eq!(
            plan.selected_resource_budget,
            OidfPlanResourceBudget {
                modules: 10,
                clients: 1,
                wall_clock_seconds: 100,
            }
        );
        assert_eq!(plan.latest_execution_start_at, 1_800_000_899);
        assert_eq!(
            plan.caller_declared_capabilities,
            ["nazoauth.client.create"]
        );
        assert_eq!(plan.plans[0].expected_skipped_modules, ["module-b"]);
        assert_eq!(
            plan.plans[0].config_template,
            json!({"alias": "{{run.alias}}", "id": "p002"})
        );
        assert_eq!(
            plan.plans[0].group_variant_values.get("profile"),
            Some(&"standard".to_owned())
        );
        assert_eq!(
            plan.plans[0].plan_variant_values.get("response_type"),
            Some(&"code".to_owned())
        );
        assert_eq!(plan.plans[0].driver_handler.id, "default");
        assert!(uuid::Uuid::parse_str(&plan.plans[0].task_jti).is_ok());
        assert_eq!(plan.runner.protocol, crate::BOUNDED_PLAN_RUNNER_PROTOCOL);
        assert_eq!(plan.runner.minimum_jobs, 1);
        assert_eq!(plan.runner.maximum_jobs, 4);
        assert!(plan.runner.independent_plan_tasks_required);
        assert!(plan.runner.independent_evidence_required);
        assert!(plan.runner.failure_collection_required);
        assert!(plan.runner.finally_cleanup_required);
        assert!(!plan.deployment_bound);
        assert!(!plan.capabilities_attested);
        assert!(!plan.execution_permitted);
        assert_eq!(plan.execution_blockers.len(), 4);
    }

    #[test]
    fn execution_requires_authenticated_provider_authorization_and_exact_bindings() {
        let matrix = matrix_bytes();
        let now = 1_800_000_000;
        let mut plan = compile_oidf_driver_inspection_plan(
            cached(&matrix),
            &matrix,
            &BTreeSet::from(["nazoauth.client.create".to_owned()]),
            OidfPlanSelection::default(),
            now,
        )
        .expect("inspection plan");
        let binding = OidfProviderExecutionBinding {
            deployment_id: "deployment-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            runtime_instance_id: "runtime-1".to_owned(),
            runtime_build_id: "build-2026.08".to_owned(),
            capability_jti: "capability-1".to_owned(),
            capability_sha256: "a".repeat(64),
            runner_capabilities: BTreeSet::from(["nazoauth.client.create".to_owned()]),
            provider_actions: BTreeSet::from([
                nazo_operator_protocol::TenantResourceOperation::Apply,
                nazo_operator_protocol::TenantResourceOperation::Enumerate,
                nazo_operator_protocol::TenantResourceOperation::Revoke,
            ]),
            provider_resource_kinds: BTreeSet::from([
                nazo_operator_protocol::TenantResourceKind::OauthClient,
                nazo_operator_protocol::TenantResourceKind::MtlsTrustAnchor,
                nazo_operator_protocol::TenantResourceKind::CibaDecisionBinding,
                nazo_operator_protocol::TenantResourceKind::Openid4vcDataset,
                nazo_operator_protocol::TenantResourceKind::Openid4vcTrustPolicy,
                nazo_operator_protocol::TenantResourceKind::User,
            ]),
            current_revision: 7,
            current_manifest_sha256: "b".repeat(64),
            artifact_source: plan.artifact.source.clone(),
            suite_origin: "https://suite.example".to_owned(),
        };
        let authorization = AuthenticatedProviderAuthorization {
            deployment_id: binding.deployment_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            runtime_instance_id: binding.runtime_instance_id.clone(),
            runtime_build_id: binding.runtime_build_id.clone(),
            capability_jti: binding.capability_jti.clone(),
            capability_sha256: binding.capability_sha256.clone(),
            capability_issued_at: now - 10,
            capability_expires_at: now + 50,
            runner_capabilities: binding.runner_capabilities.clone(),
            provider_actions: binding.provider_actions.clone(),
            provider_resource_kinds: binding.provider_resource_kinds.clone(),
            current_revision: binding.current_revision,
            current_manifest_sha256: binding.current_manifest_sha256.clone(),
            artifact_source: binding.artifact_source.clone(),
            suite_origin: binding.suite_origin.clone(),
        };

        let mut invalid = authorization.clone();
        invalid.capability_expires_at = now;
        assert!(authorize_oidf_driver_execution(&mut plan, &binding, &invalid, now).is_err());
        assert!(!plan.execution_permitted);

        let mut invalid = authorization.clone();
        invalid
            .runner_capabilities
            .insert("provider.apply".to_owned());
        assert!(authorize_oidf_driver_execution(&mut plan, &binding, &invalid, now).is_err());
        let mut invalid = authorization.clone();
        invalid.current_revision += 1;
        assert!(authorize_oidf_driver_execution(&mut plan, &binding, &invalid, now).is_err());
        let mut invalid = binding.clone();
        invalid.tenant_id.clear();
        assert!(authorize_oidf_driver_execution(&mut plan, &invalid, &authorization, now).is_err());
        let mut invalid = binding.clone();
        invalid.suite_origin = "https://suite.example/path".to_owned();
        assert!(authorize_oidf_driver_execution(&mut plan, &invalid, &authorization, now).is_err());
        let mut invalid = binding.clone();
        invalid.suite_origin = "https://other-suite.example".to_owned();
        assert!(authorize_oidf_driver_execution(&mut plan, &invalid, &authorization, now).is_err());
        let mut invalid = binding.clone();
        invalid.provider_actions =
            BTreeSet::from([nazo_operator_protocol::TenantResourceOperation::Enumerate]);
        assert!(authorize_oidf_driver_execution(&mut plan, &invalid, &authorization, now).is_err());
        let mut invalid = binding.clone();
        invalid.provider_resource_kinds =
            BTreeSet::from([nazo_operator_protocol::TenantResourceKind::User]);
        assert!(authorize_oidf_driver_execution(&mut plan, &invalid, &authorization, now).is_err());

        authorize_oidf_driver_execution(&mut plan, &binding, &authorization, now)
            .expect("all authenticated authorization facts are bound");
        assert!(plan.deployment_bound);
        assert!(plan.capabilities_attested);
        assert!(plan.execution_permitted);
        assert!(plan.execution_blockers.is_empty());
        assert!(authorize_oidf_driver_execution(&mut plan, &binding, &authorization, now).is_err());
    }

    #[test]
    fn multi_plan_contract_requires_existing_bounded_parallel_runner() {
        let matrix = matrix_bytes();
        let plan = compile_oidf_driver_inspection_plan(
            cached(&matrix),
            &matrix,
            &BTreeSet::from(["nazoauth.client.create".to_owned()]),
            OidfPlanSelection::default(),
            1_800_000_000,
        )
        .expect("inspection plan");

        assert!(plan.selected_plan_count > 1);
        assert_eq!(plan.runner.minimum_jobs, 2);
        assert_eq!(plan.runner.maximum_jobs, crate::MAX_PARALLEL_JOBS as u32);
        assert!(
            plan.plans
                .iter()
                .map(|entry| entry.task_jti.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == plan.plans.len()
        );
        assert!(!plan.execution_permitted);
    }

    #[test]
    fn rejects_unknown_duplicate_and_conflicting_selection() {
        let matrix = matrix_bytes();
        let compile = |selection| {
            compile_oidf_driver_inspection_plan(
                cached(&matrix),
                &matrix,
                &BTreeSet::from(["nazoauth.client.create".to_owned()]),
                selection,
                1_800_000_000,
            )
        };
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["missing".to_owned()],
                plans: Vec::new(),
            })
            .unwrap_err(),
            OidfPlanError::UnknownSelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned(), "oidc".to_owned()],
                plans: Vec::new(),
            })
            .unwrap_err(),
            OidfPlanError::InvalidSelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p003".to_owned()],
            })
            .unwrap_err(),
            OidfPlanError::EmptySelection
        );
    }

    #[test]
    fn rejects_changed_matrix_identity_and_plan_count_above_signed_bound() {
        let matrix = matrix_bytes();
        let capabilities = BTreeSet::from(["nazoauth.client.create".to_owned()]);
        let mut unsupported_cache = cached(&matrix);
        unsupported_cache.schema += 1;
        assert_eq!(
            compile_oidf_driver_inspection_plan(
                unsupported_cache,
                &matrix,
                &capabilities,
                OidfPlanSelection::default(),
                1_800_000_000,
            )
            .unwrap_err(),
            OidfPlanError::CacheIdentity
        );
        let mut changed = matrix.clone();
        changed.push(b' ');
        assert_eq!(
            compile_oidf_driver_inspection_plan(
                cached(&matrix),
                &changed,
                &capabilities,
                OidfPlanSelection::default(),
                1_800_000_000,
            )
            .unwrap_err(),
            OidfPlanError::MatrixIdentity
        );

        let mut bounded = cached(&matrix);
        bounded.artifact.resource_bounds.max_plans = 2;
        assert_eq!(
            compile_oidf_driver_inspection_plan(
                bounded,
                &matrix,
                &capabilities,
                OidfPlanSelection::default(),
                1_800_000_000,
            )
            .unwrap_err(),
            OidfPlanError::ResourceBound
        );
    }

    #[test]
    fn selection_uses_the_signed_matrix_identifier_contract() {
        assert_eq!(
            selection_set(&["profile:v1/plan@issuer+wallet".to_owned()]).unwrap(),
            BTreeSet::from(["profile:v1/plan@issuer+wallet".to_owned()])
        );
        assert_eq!(
            selection_set(&["not allowed".to_owned()]).unwrap_err(),
            OidfPlanError::InvalidSelection
        );
    }

    #[test]
    fn planning_requires_time_for_the_selected_budget_before_exclusive_expiry() {
        let matrix = matrix_bytes();
        let capabilities = BTreeSet::from(["nazoauth.client.create".to_owned()]);
        assert_eq!(
            compile_oidf_driver_inspection_plan(
                cached(&matrix),
                &matrix,
                &capabilities,
                OidfPlanSelection {
                    groups: Vec::new(),
                    plans: vec!["p001".to_owned()],
                },
                1_800_000_900,
            )
            .unwrap_err(),
            OidfPlanError::ArtifactValidity
        );
        assert_eq!(
            compile_oidf_driver_inspection_plan(
                cached(&matrix),
                &matrix,
                &capabilities,
                OidfPlanSelection::default(),
                1_800_001_000,
            )
            .unwrap_err(),
            OidfPlanError::ArtifactValidity
        );
    }

    fn matrix_bytes() -> Vec<u8> {
        serde_json::to_vec(&OidfArtifactMatrix {
            schema: crate::OIDF_MATRIX_SCHEMA_VERSION,
            name: "matrix".to_owned(),
            openid4vc_credential_datasets: BTreeMap::new(),
            openid4vc_suite_mdoc_trust_anchor_pem: "suite-mdoc-anchor".to_owned(),
            groups: vec![
                group("oidc", &["p001", "p002"]),
                group("openid4vc", &["p003"]),
            ],
        })
        .unwrap()
    }

    fn group(id: &str, plans: &[&str]) -> OidfArtifactMatrixGroup {
        OidfArtifactMatrixGroup {
            id: id.to_owned(),
            profile: id.to_owned(),
            variant: OidfArtifactMatrixVariant {
                id: "default".to_owned(),
                values: BTreeMap::from([("profile".to_owned(), "standard".to_owned())]),
            },
            required_roles: Vec::new(),
            plans: plans
                .iter()
                .map(|id| OidfArtifactMatrixPlan {
                    id: (*id).to_owned(),
                    plan: format!("suite-{id}"),
                    driver_handler: "default".to_owned(),
                    resource_budget: OidfPlanResourceBudget {
                        modules: 10,
                        clients: 1,
                        wall_clock_seconds: 100,
                    },
                    config_template: json!({"alias": "{{run.alias}}", "id": id}),
                    variant: BTreeMap::from([("response_type".to_owned(), "code".to_owned())]),
                    required_capabilities: vec!["nazoauth.client.create".to_owned()],
                    expected_results: if *id == "p002" {
                        BTreeMap::from([("module-b".to_owned(), "SKIPPED".to_owned())])
                    } else {
                        BTreeMap::new()
                    },
                    required_roles: Vec::new(),
                    secret_bindings: BTreeMap::new(),
                    crypto: crate::CryptoPolicy::default(),
                })
                .collect(),
        }
    }

    fn driver_bytes() -> Vec<u8> {
        serde_json::to_vec(&OidfDriverProgram {
            schema: crate::OIDF_DRIVER_SCHEMA_VERSION,
            engine_protocol: crate::OIDF_DRIVER_ENGINE_PROTOCOL,
            handlers: vec![OidfDriverHandler {
                id: "default".to_owned(),
                automation: OidfDriverAutomation::None,
                lane: OidfDriverLane::Parallel,
            }],
        })
        .expect("driver")
    }

    fn compile_oidf_driver_inspection_plan(
        cached: CachedOidfArtifact,
        matrix_bytes: &[u8],
        caller_declared_capabilities: &BTreeSet<String>,
        selection: OidfPlanSelection,
        now: i64,
    ) -> Result<OidfDriverInspectionPlan, OidfPlanError> {
        super::compile_oidf_driver_inspection_plan(
            cached,
            &driver_bytes(),
            matrix_bytes,
            caller_declared_capabilities,
            selection,
            now,
        )
    }

    fn cached(matrix: &[u8]) -> CachedOidfArtifact {
        let driver = driver_bytes();
        CachedOidfArtifact {
            schema: crate::OIDF_ARTIFACT_CACHE_SCHEMA_VERSION,
            manifest_url: "https://artifacts.example/oidf/driver.jws".to_owned(),
            opened_at: 1_800_000_000,
            cache_entry: PathBuf::from("/var/lib/nazoauthctl/oidf/artifacts/a"),
            artifact: VerifiedOidfArtifact {
                artifact_id: "driver".to_owned(),
                revision: "a".repeat(40),
                source: "https://artifacts.example/oidf/".to_owned(),
                signer_identity: "https://artifacts.example/signer".to_owned(),
                signer_key_id: format!("oidf-es256-{}", "b".repeat(32)),
                driver_manifest_sha256: "c".repeat(64),
                driver_manifest_size: 1024,
                suite: OidfSuiteIdentity {
                    origin: "https://suite.example".to_owned(),
                    release: "v1".to_owned(),
                    revision: "d".repeat(40),
                    image_digest: format!("sha256:{}", "e".repeat(64)),
                },
                engine_protocol: crate::OIDF_DRIVER_ENGINE_PROTOCOL,
                required_capabilities: vec!["nazoauth.client.create".to_owned()],
                driver_schema: crate::OIDF_DRIVER_SCHEMA_VERSION,
                driver_sha256: sha256(&driver),
                driver_size: driver.len() as u64,
                driver_handlers: 1,
                matrix_sha256: sha256(matrix),
                matrix_size: matrix.len() as u64,
                matrix_groups: 2,
                matrix_plans: 3,
                matrix_modules: 30,
                matrix_clients: 3,
                matrix_wall_clock_seconds: 300,
                not_before: 1_799_999_000,
                expires_at: 1_800_001_000,
                resource_bounds: OidfResourceBounds {
                    max_plans: 8,
                    max_modules: 128,
                    max_clients: 16,
                    max_wall_clock_seconds: 3600,
                },
            },
        }
    }
}
