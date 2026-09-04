//! Pure, offline compilation of a verified artifact Matrix into an inspection plan.
//!
//! This boundary intentionally does not create an executable deployment run.
//! Execution is deliberately outside this offline boundary. Runtime control
//! authorization is supplied only by the current controller operation API.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    CachedOidfArtifact, OIDF_ARTIFACT_CACHE_SCHEMA_VERSION, OIDF_DRIVER_ENGINE_PROTOCOL,
    OIDF_DRIVER_SCHEMA_VERSION, OIDF_MATRIX_SCHEMA_VERSION, OidfArtifactMatrix, OidfDriverHandler,
    OidfPlanResourceBudget, OidfResourceBounds, OidfSuiteIdentity, Origin, VerifiedOidfArtifact,
};

const BUNDLED_DRIVER: &[u8] = include_bytes!("../resources/oidf/driver.json");
const BUNDLED_MATRIX: &[u8] = include_bytes!("../resources/oidf/matrix.json");
const BUNDLED_SOURCE_REVISION: &str = "77c362f9fc62e5114f3c61e2b4420f864d7112ab";

pub const OIDF_DRIVER_INSPECTION_PLAN_SCHEMA: u32 = 5;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfPlanSelection {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub plans: Vec<String>,
    /// Explicit operator omissions. These are never inferred defaults.
    #[serde(default)]
    pub excluded_plans: Vec<String>,
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
}

/// Resolve the single user-facing selector against the Matrix bundled with
/// this exact ctl release. An absent selector means the complete Matrix.
pub fn resolve_bundled_oidf_selection(
    selector: Option<&str>,
) -> Result<OidfPlanSelection, OidfPlanError> {
    let Some(selector) = selector else {
        return Ok(OidfPlanSelection::default());
    };
    let matrix = bundled_oidf_matrix()?;
    let matching_groups = |predicate: &dyn Fn(&str) -> bool| {
        matrix
            .groups
            .iter()
            .filter(|group| predicate(&group.id))
            .map(|group| group.id.clone())
            .collect::<Vec<_>>()
    };
    let groups = match selector {
        "oidc" => matching_groups(&|id| id == "oidc-core"),
        "ciba" => matching_groups(&|id| id == "fapi-ciba"),
        "fapi" => matching_groups(&|id| id.starts_with("fapi-")),
        "openid4vci" => matching_groups(&|id| id.starts_with("openid4vc-vci")),
        "openid4vp" => matching_groups(&|id| id.starts_with("openid4vc-vp")),
        "openid4vc" => matching_groups(&|id| id.starts_with("openid4vc-")),
        exact if matrix.groups.iter().any(|group| group.id == exact) => vec![exact.to_owned()],
        exact
            if matrix
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| plan.id == exact) =>
        {
            return Ok(OidfPlanSelection {
                groups: Vec::new(),
                plans: vec![exact.to_owned()],
                excluded_plans: Vec::new(),
            });
        }
        _ => return Err(OidfPlanError::UnknownSelection),
    };
    if groups.is_empty() {
        return Err(OidfPlanError::UnknownSelection);
    }
    Ok(OidfPlanSelection {
        groups,
        plans: Vec::new(),
        excluded_plans: Vec::new(),
    })
}

pub fn bundled_oidf_selection_choices() -> Result<Vec<String>, OidfPlanError> {
    let matrix = bundled_oidf_matrix()?;
    let mut choices = [
        "oidc",
        "ciba",
        "fapi",
        "openid4vci",
        "openid4vp",
        "openid4vc",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect::<Vec<_>>();
    choices.extend(matrix.groups.iter().map(|group| group.id.clone()));
    choices.extend(
        matrix
            .groups
            .iter()
            .flat_map(|group| &group.plans)
            .map(|plan| plan.id.clone()),
    );
    Ok(choices)
}

pub fn resolve_bundled_oidf_plan_id(reference: &str) -> Result<String, OidfPlanError> {
    let matrix = bundled_oidf_matrix()?;
    let matches = matrix
        .groups
        .iter()
        .flat_map(|group| group.plans.iter())
        .filter(|plan| {
            plan.id == reference
                || plan
                    .id
                    .rsplit('-')
                    .next()
                    .is_some_and(|segment| segment == reference)
        })
        .map(|plan| plan.id.clone())
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches.into_iter().next().expect("one match"))
    } else {
        Err(OidfPlanError::UnknownSelection)
    }
}

pub fn bundled_oidf_matrix() -> Result<OidfArtifactMatrix, OidfPlanError> {
    let matrix: OidfArtifactMatrix =
        serde_json::from_slice(BUNDLED_MATRIX).map_err(|_| OidfPlanError::MalformedMatrix)?;
    if matrix.schema != OIDF_MATRIX_SCHEMA_VERSION {
        return Err(OidfPlanError::MalformedMatrix);
    }
    Ok(matrix)
}

/// Compile the immutable Matrix and driver embedded in the ctl binary. Their
/// content identity remains in evidence, but is no longer operator input.
pub fn open_bundled_oidf_driver_plan(
    selection: OidfPlanSelection,
    suite_origin: &Origin,
    now: i64,
) -> Result<OidfDriverInspectionPlan, OidfPlanError> {
    let matrix = bundled_oidf_matrix()?;
    let plan_count = matrix
        .groups
        .iter()
        .map(|group| group.plans.len())
        .sum::<usize>();
    let mut budget = OidfPlanResourceBudget {
        modules: 0,
        clients: 0,
        wall_clock_seconds: 0,
    };
    for plan in matrix.groups.iter().flat_map(|group| &group.plans) {
        budget.modules = budget
            .modules
            .checked_add(plan.resource_budget.modules)
            .ok_or(OidfPlanError::ResourceBound)?;
        budget.clients = budget
            .clients
            .checked_add(plan.resource_budget.clients)
            .ok_or(OidfPlanError::ResourceBound)?;
        budget.wall_clock_seconds = budget
            .wall_clock_seconds
            .checked_add(plan.resource_budget.wall_clock_seconds)
            .ok_or(OidfPlanError::ResourceBound)?;
    }
    let driver: crate::OidfDriverProgram =
        serde_json::from_slice(BUNDLED_DRIVER).map_err(|_| OidfPlanError::CacheIdentity)?;
    let driver_sha256 = sha256(BUNDLED_DRIVER);
    let matrix_sha256 = sha256(BUNDLED_MATRIX);
    let artifact_digest = sha256([BUNDLED_DRIVER, BUNDLED_MATRIX].concat().as_slice());
    let artifact = VerifiedOidfArtifact {
        artifact_id: "nazoauthctl-bundled-oidf-v5.2.2".to_owned(),
        revision: BUNDLED_SOURCE_REVISION.to_owned(),
        source: "nazoauthctl-bundled".to_owned(),
        signer_identity: "nazoauthctl-release".to_owned(),
        signer_key_id: "nazoauthctl-release".to_owned(),
        driver_manifest_sha256: artifact_digest,
        driver_manifest_size: u64::try_from(BUNDLED_DRIVER.len() + BUNDLED_MATRIX.len())
            .map_err(|_| OidfPlanError::ResourceBound)?,
        suite: OidfSuiteIdentity {
            origin: suite_origin.as_str().to_owned(),
            release: "release-v5.2.2".to_owned(),
            revision: "321bc5bc53601b9690b54c023c0cbfac0f0230f2".to_owned(),
            image_digest: "sha256:ca3fb5be36fc2f471942f474ad7ff40677f29d40ce7a9f7525db1102b89b0415"
                .to_owned(),
        },
        engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
        required_capabilities: vec!["nazoauth.client.create".to_owned()],
        driver_schema: OIDF_DRIVER_SCHEMA_VERSION,
        driver_sha256,
        driver_size: u64::try_from(BUNDLED_DRIVER.len())
            .map_err(|_| OidfPlanError::ResourceBound)?,
        driver_handlers: u32::try_from(driver.handlers.len())
            .map_err(|_| OidfPlanError::ResourceBound)?,
        matrix_sha256,
        matrix_size: u64::try_from(BUNDLED_MATRIX.len())
            .map_err(|_| OidfPlanError::ResourceBound)?,
        matrix_groups: u32::try_from(matrix.groups.len())
            .map_err(|_| OidfPlanError::ResourceBound)?,
        matrix_plans: u32::try_from(plan_count).map_err(|_| OidfPlanError::ResourceBound)?,
        matrix_modules: budget.modules,
        matrix_clients: budget.clients,
        matrix_wall_clock_seconds: budget.wall_clock_seconds,
        not_before: 0,
        expires_at: i64::MAX,
        resource_bounds: OidfResourceBounds {
            max_plans: u32::try_from(plan_count).map_err(|_| OidfPlanError::ResourceBound)?,
            max_modules: budget.modules,
            max_clients: budget.clients,
            max_wall_clock_seconds: budget.wall_clock_seconds,
        },
    };
    compile_oidf_driver_inspection_plan(
        CachedOidfArtifact {
            schema: OIDF_ARTIFACT_CACHE_SCHEMA_VERSION,
            manifest_url: "nazoauthctl-bundled".to_owned(),
            opened_at: now,
            cache_entry: PathBuf::new(),
            artifact,
        },
        BUNDLED_DRIVER,
        BUNDLED_MATRIX,
        &BTreeSet::from(["nazoauth.client.create".to_owned()]),
        selection,
        now,
    )
}

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
    let excluded_plans = selection_set(&selection.excluded_plans)?;
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
        || excluded_plans.iter().any(|wanted| {
            !matrix
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| &plan.id == wanted)
        })
    {
        return Err(OidfPlanError::UnknownSelection);
    }
    let selected_before_exclusions = matrix
        .groups
        .iter()
        .filter(|group| groups.is_empty() || groups.contains(&group.id))
        .flat_map(|group| group.plans.iter())
        .filter(|plan| plans.is_empty() || plans.contains(&plan.id))
        .map(|plan| plan.id.as_str())
        .collect::<BTreeSet<_>>();
    if excluded_plans
        .iter()
        .any(|plan| !selected_before_exclusions.contains(plan.as_str()))
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
            if excluded_plans.contains(&plan.id) {
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
    })
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
    fn bundled_matrix_resolves_public_aliases_and_exact_ids() {
        assert_eq!(
            resolve_bundled_oidf_selection(None).unwrap(),
            OidfPlanSelection::default()
        );
        assert_eq!(
            resolve_bundled_oidf_selection(Some("ciba")).unwrap().groups,
            ["fapi-ciba"]
        );
        assert_eq!(
            resolve_bundled_oidf_selection(Some("openid4vci"))
                .unwrap()
                .groups,
            ["openid4vc-vci", "openid4vc-vci-haip"]
        );
        assert_eq!(
            resolve_bundled_oidf_selection(Some("oidc-core-p001"))
                .unwrap()
                .plans,
            ["oidc-core-p001"]
        );
        assert_eq!(
            resolve_bundled_oidf_selection(Some("missing")).unwrap_err(),
            OidfPlanError::UnknownSelection
        );
    }

    #[test]
    fn bundled_matrix_compiles_without_external_artifact_inputs() {
        let selection = resolve_bundled_oidf_selection(Some("ciba")).unwrap();
        let suite = Origin::parse("https://suite.example").unwrap();
        let plan = open_bundled_oidf_driver_plan(selection, &suite, 1_800_000_000).unwrap();
        assert_eq!(plan.selected_group_count, 1);
        assert!(!plan.plans.is_empty());
        assert!(plan.plans.iter().all(|entry| entry.group_id == "fapi-ciba"));
        assert_eq!(plan.artifact.suite.origin, "https://suite.example");
    }

    #[test]
    fn compiles_exact_selection() {
        let matrix = matrix_bytes();
        let plan = compile_oidf_driver_inspection_plan(
            cached(&matrix),
            &matrix,
            &BTreeSet::from(["nazoauth.client.create".to_owned()]),
            OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p002".to_owned()],
                excluded_plans: Vec::new(),
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
    }

    #[test]
    fn exclusion_reference_requires_exact_id_or_final_plan_segment() {
        assert_eq!(
            resolve_bundled_oidf_plan_id("p040").expect("p040 suffix"),
            "openid4vc-vp-p040"
        );
        assert_eq!(
            resolve_bundled_oidf_plan_id("040"),
            Err(OidfPlanError::UnknownSelection)
        );
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
                excluded_plans: Vec::new(),
            })
            .unwrap_err(),
            OidfPlanError::UnknownSelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned(), "oidc".to_owned()],
                plans: Vec::new(),
                excluded_plans: Vec::new(),
            })
            .unwrap_err(),
            OidfPlanError::InvalidSelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p003".to_owned()],
                excluded_plans: Vec::new(),
            })
            .unwrap_err(),
            OidfPlanError::EmptySelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: Vec::new(),
                excluded_plans: vec!["p001".to_owned(), "p002".to_owned()],
            })
            .unwrap_err(),
            OidfPlanError::EmptySelection
        );
        assert_eq!(
            compile(OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p001".to_owned()],
                excluded_plans: vec!["p002".to_owned()],
            })
            .unwrap_err(),
            OidfPlanError::UnknownSelection
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
                    excluded_plans: Vec::new(),
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
