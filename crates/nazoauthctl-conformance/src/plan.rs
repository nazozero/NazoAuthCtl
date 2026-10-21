use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    BundledOidfMatrix, OIDF_MATRIX_SCHEMA_VERSION, OidfDriverHandler, OidfPlanResourceBudget,
    OidfTestSource,
};

const BUNDLED_DRIVER: &[u8] = include_bytes!("../resources/oidf/driver.json");
const BUNDLED_MATRIX: &[u8] = include_bytes!("../resources/oidf/matrix.json");
const BUNDLED_SUITE: &[u8] = include_bytes!("../resources/oidf/suite.json");

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
    pub group_id: String,
    pub plan_id: String,
    pub driver_handler: OidfDriverHandler,
    pub resource_budget: OidfPlanResourceBudget,
    pub expected_skipped_modules: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfExecutionPlan {
    pub source: OidfTestSource,
    pub selected_group_count: u32,
    pub selected_plan_count: u32,
    pub selected_resource_budget: OidfPlanResourceBudget,
    pub module_limit: u32,
    pub plans: Vec<OidfDriverPlanEntry>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum OidfPlanError {
    #[error("bundled driver handler is missing")]
    MalformedDriver,
    #[error("bundled Matrix could not be decoded")]
    MalformedMatrix,
    #[error("plan selection contains an invalid or duplicate identifier")]
    InvalidSelection,
    #[error("plan selection names an unknown group or plan")]
    UnknownSelection,
    #[error("group and plan filters select no common plan")]
    EmptySelection,
    #[error("selected plan resource budget overflow")]
    ResourceBound,
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
    let mut matches = matrix
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
        .map(|plan| plan.id.as_str());
    match (matches.next(), matches.next()) {
        (Some(id), None) => Ok(id.to_owned()),
        _ => Err(OidfPlanError::UnknownSelection),
    }
}

pub fn bundled_oidf_matrix() -> Result<&'static BundledOidfMatrix, OidfPlanError> {
    // Every selector reads the same immutable bytes embedded in this binary.
    static MATRIX: LazyLock<Result<BundledOidfMatrix, OidfPlanError>> = LazyLock::new(|| {
        let matrix: BundledOidfMatrix =
            serde_json::from_slice(BUNDLED_MATRIX).map_err(|_| OidfPlanError::MalformedMatrix)?;
        if matrix.schema != OIDF_MATRIX_SCHEMA_VERSION {
            return Err(OidfPlanError::MalformedMatrix);
        }
        Ok(matrix)
    });
    MATRIX.as_ref().map_err(|_| OidfPlanError::MalformedMatrix)
}

/// Compile the immutable Matrix and driver embedded in the ctl binary. Their
/// content identity remains in evidence, but is no longer operator input.
pub fn open_bundled_oidf_driver_plan(
    selection: OidfPlanSelection,
) -> Result<OidfExecutionPlan, OidfPlanError> {
    let matrix = bundled_oidf_matrix()?;
    let driver: crate::OidfDriverProgram =
        serde_json::from_slice(BUNDLED_DRIVER).map_err(|_| OidfPlanError::MalformedDriver)?;
    let suite_reference =
        serde_json::from_slice(BUNDLED_SUITE).map_err(|_| OidfPlanError::MalformedDriver)?;
    let mut digest = Sha256::new();
    digest.update(BUNDLED_DRIVER);
    digest.update(BUNDLED_MATRIX);
    let content_sha256 = hex::encode(digest.finalize());
    let source = OidfTestSource {
        controller_version: env!("CARGO_PKG_VERSION").to_owned(),
        revision: content_sha256[..40].to_owned(),
        content_sha256,
        driver_sha256: sha256(BUNDLED_DRIVER),
        matrix_sha256: sha256(BUNDLED_MATRIX),
        suite_reference,
    };
    compile_oidf_plan(matrix, &driver, source, selection)
}

fn compile_oidf_plan(
    matrix: &BundledOidfMatrix,
    driver: &crate::OidfDriverProgram,
    source: OidfTestSource,
    selection: OidfPlanSelection,
) -> Result<OidfExecutionPlan, OidfPlanError> {
    let module_limit = matrix
        .groups
        .iter()
        .flat_map(|group| &group.plans)
        .try_fold(0u32, |sum, plan| {
            sum.checked_add(plan.resource_budget.modules)
        })
        .ok_or(OidfPlanError::ResourceBound)?;
    let driver_handlers = driver
        .handlers
        .iter()
        .map(|handler| (handler.id.as_str(), handler))
        .collect::<BTreeMap<_, _>>();
    let groups = selection_set(&selection.groups)?;
    let plans = selection_set(&selection.plans)?;
    let excluded_plans = selection_set(&selection.excluded_plans)?;
    if groups
        .iter()
        .any(|wanted| !matrix.groups.iter().any(|group| group.id == *wanted))
        || plans.iter().any(|wanted| {
            !matrix
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| plan.id == *wanted)
        })
        || excluded_plans.iter().any(|wanted| {
            !matrix
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| plan.id == *wanted)
        })
    {
        return Err(OidfPlanError::UnknownSelection);
    }
    let selected_before_exclusions = matrix
        .groups
        .iter()
        .filter(|group| groups.is_empty() || groups.contains(group.id.as_str()))
        .flat_map(|group| group.plans.iter())
        .filter(|plan| plans.is_empty() || plans.contains(plan.id.as_str()))
        .map(|plan| plan.id.as_str())
        .collect::<BTreeSet<_>>();
    if excluded_plans
        .iter()
        .any(|plan| !selected_before_exclusions.contains(plan))
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
    for group in &matrix.groups {
        if !groups.is_empty() && !groups.contains(group.id.as_str()) {
            continue;
        }
        for plan in &group.plans {
            if !plans.is_empty() && !plans.contains(plan.id.as_str()) {
                continue;
            }
            if excluded_plans.contains(plan.id.as_str()) {
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
                .get(plan.driver_handler.as_str())
                .map(|handler| (*handler).clone())
                .ok_or(OidfPlanError::MalformedDriver)?;
            entries.push(OidfDriverPlanEntry {
                group_id: group.id.clone(),
                plan_id: plan.id.clone(),
                driver_handler,
                resource_budget: plan.resource_budget.clone(),
                expected_skipped_modules: plan.expected_results.keys().cloned().collect(),
            });
        }
    }
    if entries.is_empty() {
        return Err(OidfPlanError::EmptySelection);
    }
    let selected_plan_count =
        u32::try_from(entries.len()).map_err(|_| OidfPlanError::ResourceBound)?;
    let selected_group_count =
        u32::try_from(selected_groups.len()).map_err(|_| OidfPlanError::ResourceBound)?;
    Ok(OidfExecutionPlan {
        source,
        module_limit,
        selected_group_count,
        selected_plan_count,
        selected_resource_budget,
        plans: entries,
    })
}

fn selection_set(values: &[String]) -> Result<BTreeSet<&str>, OidfPlanError> {
    let mut selected = BTreeSet::new();
    for value in values {
        if validate_identifier(value, 128).is_err() || !selected.insert(value.as_str()) {
            return Err(OidfPlanError::InvalidSelection);
        }
    }
    Ok(selected)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn validate_identifier(value: &str, maximum: usize) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
    {
        return Err("identifier is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_ciba_clients_use_ciba_audiences_without_fapi2_assurance() {
        let matrix: serde_json::Value = serde_json::from_slice(BUNDLED_MATRIX).unwrap();
        let group = matrix["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["id"] == "fapi-ciba")
            .unwrap();
        let mut checked = 0;
        for plan in group["plans"].as_array().unwrap() {
            for role in plan["required_roles"].as_array().unwrap() {
                let registration = &role["registration_template"];
                assert_eq!(registration["security_policy"]["assurance"], "baseline");
                assert_eq!(
                    registration["security_policy"]["allow_cross_device_flows"],
                    true
                );
                assert_eq!(registration["require_mtls_bound_tokens"], true);
                assert_eq!(registration["require_par_request_object"], true);
                assert_eq!(registration["id_token_signed_response_alg"], "PS256");
                assert_eq!(
                    registration["backchannel_authentication_request_signing_alg"],
                    "PS256"
                );
                if registration["token_endpoint_auth_method"] == "private_key_jwt" {
                    assert_eq!(
                        registration["allow_client_assertion_endpoint_audience"],
                        true
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 8);
    }

    #[test]
    fn bundled_haip_clients_require_pushed_authorization() {
        let matrix: serde_json::Value = serde_json::from_slice(BUNDLED_MATRIX).unwrap();
        let mut checked = 0;
        for group in matrix["groups"].as_array().unwrap() {
            if group["id"] != "openid4vc-vci-haip" {
                continue;
            }
            for plan in group["plans"].as_array().unwrap() {
                for role in plan["required_roles"].as_array().unwrap() {
                    let registration = &role["registration_template"];
                    assert_eq!(
                        registration["security_policy"]["require_pushed_authorization_requests"],
                        true
                    );
                    assert_eq!(
                        registration["token_endpoint_auth_method"],
                        "attest_jwt_client_auth"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 8);
    }

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
        let plan = open_bundled_oidf_driver_plan(selection).unwrap();
        assert_eq!(plan.selected_group_count, 1);
        assert!(!plan.plans.is_empty());
        assert!(plan.plans.iter().all(|entry| entry.group_id == "fapi-ciba"));
        assert_eq!(plan.source.suite_reference.release, "release-v5.3.3");
    }

    #[test]
    fn bundled_plans_have_unique_ids_and_exact_skip_exceptions() {
        let matrix = bundled_oidf_matrix().unwrap();
        let driver: crate::OidfDriverProgram = serde_json::from_slice(BUNDLED_DRIVER).unwrap();
        let handler_ids: BTreeSet<_> = driver.handlers.iter().map(|handler| &handler.id).collect();
        assert_eq!(handler_ids.len(), driver.handlers.len());
        let mut ids = BTreeSet::new();
        for group in &matrix.groups {
            for plan in &group.plans {
                assert!(ids.insert(&plan.id));
                assert!(handler_ids.contains(&plan.driver_handler));
                assert!(
                    plan.expected_results
                        .values()
                        .all(|result| result == "SKIPPED")
                );
                assert!(plan.resource_budget.modules > 0);
                assert!(plan.resource_budget.wall_clock_seconds > 0);
            }
        }
        let all = open_bundled_oidf_driver_plan(OidfPlanSelection::default()).unwrap();
        assert_eq!(all.plans.len(), ids.len());
        assert_eq!(all.source.matrix_sha256, sha256(BUNDLED_MATRIX));
        assert_eq!(all.source.driver_sha256, sha256(BUNDLED_DRIVER));
    }

    #[test]
    fn selection_and_exclusion_preserve_plan_budgets() {
        let selected = OidfPlanSelection {
            plans: vec!["oidc-core-p001".into()],
            ..Default::default()
        };
        let one = open_bundled_oidf_driver_plan(selected.clone()).unwrap();
        assert_eq!(one.selected_plan_count, 1);
        assert_eq!(one.selected_resource_budget, one.plans[0].resource_budget);
        let all = open_bundled_oidf_driver_plan(OidfPlanSelection::default()).unwrap();
        let excluded = open_bundled_oidf_driver_plan(OidfPlanSelection {
            excluded_plans: selected.plans,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(all.selected_plan_count, excluded.selected_plan_count + 1);
        assert_eq!(all.source, excluded.source);
        assert_eq!(all.module_limit, excluded.module_limit);
        assert_eq!(
            all.selected_resource_budget.modules,
            excluded.selected_resource_budget.modules + one.selected_resource_budget.modules
        );
        for selection in [
            OidfPlanSelection {
                plans: vec!["missing".into()],
                ..Default::default()
            },
            OidfPlanSelection {
                groups: vec!["oidc-core".into(), "oidc-core".into()],
                ..Default::default()
            },
            OidfPlanSelection {
                plans: vec!["oidc-core-p001".into()],
                excluded_plans: vec!["oidc-core-p001".into()],
                ..Default::default()
            },
        ] {
            assert!(open_bundled_oidf_driver_plan(selection).is_err());
        }
    }
}
