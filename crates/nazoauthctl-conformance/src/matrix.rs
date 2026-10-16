use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

pub const MATRIX_SCHEMA_VERSION: u32 = 1;

/// Versioned, machine-readable input to orchestration. The CLI never invents
/// a plan expression or variant: every selected request must originate here.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixDocument {
    pub schema: u32,
    pub name: String,
    pub groups: Vec<MatrixGroup>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixGroup {
    pub id: String,
    pub profile: String,
    pub variant: MatrixVariant,
    pub plans: Vec<MatrixPlan>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixVariant {
    pub id: String,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixPlan {
    pub id: String,
    /// Official suite test-plan name, passed as `planName`.
    pub plan: String,
    /// Fully materialized JSON configuration sent to the official suite.
    pub config: Value,
    /// Optional per-plan overrides; the group variant remains the baseline.
    #[serde(default)]
    pub variant: BTreeMap<String, String>,
    /// Exact Suite module names allowed to finish as `SKIPPED` by the signed
    /// Matrix. Other non-PASSED outcomes are interpreted at run time.
    #[serde(default)]
    pub expected_results: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixSelection {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub plans: Vec<String>,
}

#[derive(Clone)]
pub struct SelectedMatrix {
    pub document: MatrixDocument,
    pub digest: String,
}

impl SelectedMatrix {
    pub fn select(mut self, selection: &MatrixSelection) -> Result<Self, MatrixError> {
        let groups_filter = filter_set(&selection.groups)?;
        let profiles_filter = filter_set(&selection.profiles)?;
        let plans_filter = filter_set(&selection.plans)?;
        for wanted in &groups_filter {
            if !self.document.groups.iter().any(|group| group.id == *wanted) {
                return Err(MatrixError::UnknownSelection((*wanted).to_owned()));
            }
        }
        for wanted in &profiles_filter {
            if !self
                .document
                .groups
                .iter()
                .any(|group| group.profile == *wanted)
            {
                return Err(MatrixError::UnknownSelection((*wanted).to_owned()));
            }
        }
        for wanted in &plans_filter {
            if !self
                .document
                .groups
                .iter()
                .flat_map(|group| &group.plans)
                .any(|plan| plan.id == *wanted)
            {
                return Err(MatrixError::UnknownSelection((*wanted).to_owned()));
            }
        }
        self.document.groups.retain(|group| {
            (groups_filter.is_empty() || groups_filter.contains(group.id.as_str()))
                && (profiles_filter.is_empty() || profiles_filter.contains(group.profile.as_str()))
        });
        for group in &mut self.document.groups {
            group
                .plans
                .retain(|plan| plans_filter.is_empty() || plans_filter.contains(plan.id.as_str()));
        }
        self.document.groups.retain(|group| !group.plans.is_empty());
        if self.document.groups.is_empty() {
            return Err(MatrixError::EmptySelection);
        }
        Ok(self)
    }
    /// Build a selected matrix from a trusted, already-materialized document.
    ///
    /// The digest is supplied by the caller because private configuration
    /// values (client secrets and private keys) must not participate in the
    /// public matrix identity.  Callers must therefore compute it from the
    /// descriptor and public selection metadata before handing the document
    /// to the Suite client.
    pub(crate) fn from_materialized(document: MatrixDocument, digest: String) -> Self {
        Self { document, digest }
    }

    pub(crate) fn zeroize_config(&mut self) {
        for group in &mut self.document.groups {
            for plan in &mut group.plans {
                zeroize_json_value(&mut plan.config);
            }
        }
    }
}

impl Drop for SelectedMatrix {
    fn drop(&mut self) {
        self.zeroize_config();
    }
}

pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl MatrixDocument {
    pub fn plan_count(&self) -> usize {
        self.groups.iter().map(|group| group.plans.len()).sum()
    }
}

impl MatrixGroup {
    pub fn effective_variant(&self, plan: &MatrixPlan) -> BTreeMap<String, String> {
        let mut values = self.variant.values.clone();
        values.extend(
            plan.variant
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        values
    }

    /// Expand local driver semantics without changing the compact official
    /// variant sent to the Suite. This mirrors the Python materializer's
    /// `full_vci_variant`: profile defaults are the baseline, group values
    /// override them, and plan values have final precedence.
    pub(crate) fn effective_runtime_variant(&self, plan: &MatrixPlan) -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        if self.variant.id == "vci-haip" {
            values.extend([
                ("sender_constrain".to_owned(), "dpop".to_owned()),
                (
                    "client_auth_type".to_owned(),
                    "client_attestation".to_owned(),
                ),
                ("authorization_request_type".to_owned(), "simple".to_owned()),
                ("openid".to_owned(), "plain_oauth".to_owned()),
                ("fapi_request_method".to_owned(), "unsigned".to_owned()),
                ("vci_grant_type".to_owned(), "authorization_code".to_owned()),
                ("vci_credential_encryption".to_owned(), "plain".to_owned()),
                ("fapi_profile".to_owned(), "vci_haip".to_owned()),
                ("fapi_response_mode".to_owned(), "plain_response".to_owned()),
            ]);
        }
        values.extend(
            self.variant
                .values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        values.extend(
            plan.variant
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        values
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MatrixError {
    DuplicateId(String),
    EmptyField(&'static str),
    EmptySelection,
    UnknownSelection(String),
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateId(id) => write!(formatter, "matrix contains duplicate id {id}"),
            Self::EmptyField(field) => write!(formatter, "matrix field {field} must not be empty"),
            Self::EmptySelection => formatter.write_str("matrix selection contains no groups"),
            Self::UnknownSelection(value) => {
                write!(formatter, "matrix selection is unknown: {value}")
            }
        }
    }
}

impl std::error::Error for MatrixError {}

fn filter_set(values: &[String]) -> Result<BTreeSet<&str>, MatrixError> {
    let mut set = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(MatrixError::EmptyField("selection"));
        }
        if !set.insert(value.as_str()) {
            return Err(MatrixError::DuplicateId(value.clone()));
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SelectedMatrix {
        SelectedMatrix::from_materialized(serde_json::from_slice(br#"{"schema":1,"name":"fixture","groups":[{"id":"g","profile":"oidc","variant":{"id":"v","values":{"mode":"plain"}},"plans":[{"id":"p","plan":"oidcc-basic-certification-test-plan","config":{"alias":"a"},"expected_results":{"oidcc-expected-skip":"SKIPPED"}}]}]}"#).unwrap(), "fixture-descriptor-digest".into())
    }

    #[test]
    fn vci_haip_runtime_defaults_do_not_change_the_official_suite_variant() {
        let group = MatrixGroup {
            id: "openid4vc-vci-haip".to_owned(),
            profile: "openid4vc".to_owned(),
            variant: MatrixVariant {
                id: "vci-haip".to_owned(),
                values: BTreeMap::new(),
            },
            plans: Vec::new(),
        };
        let plan = MatrixPlan {
            id: "openid4vc-vci-haip-p036".to_owned(),
            plan: "oid4vci-1_0-issuer-haip-test-plan".to_owned(),
            config: serde_json::json!({}),
            variant: BTreeMap::from([
                (
                    "vci_authorization_code_flow_variant".to_owned(),
                    "issuer_initiated".to_owned(),
                ),
                ("credential_format".to_owned(), "sd_jwt_vc".to_owned()),
            ]),
            expected_results: BTreeMap::new(),
        };

        let suite = group.effective_variant(&plan);
        assert_eq!(suite.len(), 2);
        assert!(!suite.contains_key("vci_grant_type"));

        let runtime = group.effective_runtime_variant(&plan);
        assert_eq!(
            runtime.get("vci_grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(
            runtime.get("client_auth_type").map(String::as_str),
            Some("client_attestation")
        );
        assert_eq!(
            runtime.get("sender_constrain").map(String::as_str),
            Some("dpop")
        );
        assert_eq!(
            runtime.get("fapi_profile").map(String::as_str),
            Some("vci_haip")
        );
    }

    #[test]
    fn digest_and_selection_are_stable() {
        let artifact = fixture();
        assert_eq!(artifact.document.plan_count(), 1);
        assert_eq!(
            artifact.document.groups[0].plans[0]
                .expected_results
                .get("oidcc-expected-skip")
                .map(String::as_str),
            Some("SKIPPED")
        );
        assert_eq!(
            artifact
                .select(&MatrixSelection::default())
                .expect("selection")
                .digest,
            "fixture-descriptor-digest"
        );
    }

    #[test]
    fn unknown_selection_is_rejected() {
        let artifact = fixture();
        let selection = MatrixSelection {
            groups: vec!["missing".into()],
            profiles: vec![],
            plans: vec![],
        };
        assert!(matches!(
            artifact.select(&selection),
            Err(MatrixError::UnknownSelection(_))
        ));
    }

    #[test]
    fn plan_selection_filters_without_changing_the_descriptor_digest() {
        let artifact = fixture();
        let selected = artifact
            .select(&MatrixSelection {
                groups: vec![],
                profiles: vec![],
                plans: vec!["p".into()],
            })
            .expect("selection");
        assert_eq!(selected.document.plan_count(), 1);
        assert_eq!(selected.digest, "fixture-descriptor-digest");

        assert!(matches!(
            fixture().select(&MatrixSelection {
                groups: vec![],
                profiles: vec![],
                plans: vec!["missing".into()],
            }),
            Err(MatrixError::UnknownSelection(_))
        ));
    }

    #[test]
    fn selected_matrix_zeroizes_nested_configuration_values() {
        let mut selected = SelectedMatrix::from_materialized(
            MatrixDocument {
                schema: MATRIX_SCHEMA_VERSION,
                name: "sensitive".into(),
                groups: vec![MatrixGroup {
                    id: "g".into(),
                    profile: "oidc".into(),
                    variant: MatrixVariant {
                        id: "v".into(),
                        values: BTreeMap::new(),
                    },
                    plans: vec![MatrixPlan {
                        id: "p".into(),
                        plan: "plan".into(),
                        config: serde_json::json!({
                            "nested": ["secret", {"key": "private-key"}]
                        }),
                        variant: BTreeMap::new(),
                        expected_results: BTreeMap::new(),
                    }],
                }],
            },
            "digest".into(),
        );
        selected.zeroize_config();
        assert_eq!(
            selected.document.groups[0].plans[0].config,
            serde_json::json!({"nested": ["", {"key": ""}]})
        );
    }
}
