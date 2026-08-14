//! Pure, offline compilation of a verified artifact Matrix into an inspection plan.
//!
//! This boundary intentionally does not create an executable deployment run.
//! A signed executable driver and sandbox, authenticated capability negotiation,
//! ordinary NazoAuth resource providers, target/Suite origin policy, and a
//! deployment-bound recovery journal do not exist yet; the plan records those
//! blockers instead of treating caller-supplied capability names as proof.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{CachedOidfArtifact, OidfArtifactMatrix, OidfPlanResourceBudget};

pub const OIDF_DRIVER_INSPECTION_PLAN_SCHEMA: u32 = 3;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfPlanSelection {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub plans: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverPlanEntry {
    pub group_id: String,
    pub profile: String,
    pub group_variant_id: String,
    pub group_variant_values: BTreeMap<String, String>,
    pub plan_id: String,
    pub suite_plan_name: String,
    pub resource_budget: OidfPlanResourceBudget,
    pub plan_variant_values: BTreeMap<String, String>,
    pub config_template: Value,
    pub required_capabilities: Vec<String>,
    pub expected_skipped_modules: Vec<String>,
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
}

pub(crate) fn compile_oidf_driver_inspection_plan(
    cached: CachedOidfArtifact,
    matrix_bytes: &[u8],
    caller_declared_capabilities: &BTreeSet<String>,
    selection: OidfPlanSelection,
    now: i64,
) -> Result<OidfDriverInspectionPlan, OidfPlanError> {
    if cached.schema != crate::OIDF_ARTIFACT_CACHE_SCHEMA_VERSION {
        return Err(OidfPlanError::CacheIdentity);
    }
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
            entries.push(OidfDriverPlanEntry {
                group_id: group.id.clone(),
                profile: group.profile.clone(),
                group_variant_id: group.variant.id.clone(),
                group_variant_values: group.variant.values.clone(),
                plan_id: plan.id,
                suite_plan_name: plan.plan,
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
        plans: entries,
        deployment_bound: false,
        capabilities_attested: false,
        execution_permitted: false,
        execution_blockers: vec![
            "signed-driver-payload-and-runtime-sandbox",
            "authenticated-capability-negotiation",
            "ordinary-resource-provider",
            "target-and-suite-origin-policy",
            "deployment-bound-crash-safe-execution-journal",
        ],
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
        assert!(!plan.deployment_bound);
        assert!(!plan.capabilities_attested);
        assert!(!plan.execution_permitted);
        assert_eq!(plan.execution_blockers.len(), 5);
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
            plans: plans
                .iter()
                .map(|id| OidfArtifactMatrixPlan {
                    id: (*id).to_owned(),
                    plan: format!("suite-{id}"),
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
                })
                .collect(),
        }
    }

    fn cached(matrix: &[u8]) -> CachedOidfArtifact {
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
                    release: "v1".to_owned(),
                    revision: "d".repeat(40),
                    image_digest: format!("sha256:{}", "e".repeat(64)),
                },
                engine_protocol: crate::OIDF_DRIVER_ENGINE_PROTOCOL,
                required_capabilities: vec!["nazoauth.client.create".to_owned()],
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
