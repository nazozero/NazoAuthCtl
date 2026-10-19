use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OIDF_MATRIX_SCHEMA_VERSION: u32 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfSuiteReference {
    pub release: String,
    pub revision: String,
    pub image_digest: String,
}

/// Identity of the bundled test inputs, not an attestation of the remote Suite.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfTestSource {
    pub controller_version: String,
    pub revision: String,
    pub content_sha256: String,
    pub matrix_sha256: String,
    pub driver_sha256: String,
    pub suite_reference: OidfSuiteReference,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledOidfMatrix {
    pub schema: u32,
    pub name: String,
    /// Public OpenID4VC claims are matrix authority, not executable-plan
    /// configuration.  Every VCI plan is bound to one entry by the single
    /// descriptor validator during materialization.
    pub openid4vc_credential_datasets: std::collections::BTreeMap<String, Value>,
    /// The Suite's mdoc trust root is part of the bundled Matrix.
    /// It is deliberately required so a missing trust boundary fails closed.
    pub openid4vc_suite_mdoc_trust_anchor_pem: String,
    pub groups: Vec<BundledOidfMatrixGroup>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledOidfMatrixGroup {
    pub id: String,
    pub profile: String,
    pub variant: BundledOidfMatrixVariant,
    pub required_roles: Vec<crate::materializer::RoleRequirement>,
    pub plans: Vec<BundledOidfMatrixPlan>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledOidfMatrixVariant {
    pub id: String,
    #[serde(default)]
    pub values: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledOidfMatrixPlan {
    pub id: String,
    pub plan: String,
    pub driver_handler: String,
    pub resource_budget: OidfPlanResourceBudget,
    pub config_template: Value,
    #[serde(default)]
    pub variant: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub expected_results: std::collections::BTreeMap<String, String>,
    pub required_roles: Vec<crate::materializer::RoleRequirement>,
    pub secret_bindings: std::collections::BTreeMap<String, String>,
    pub crypto: crate::materializer::CryptoPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfPlanResourceBudget {
    pub modules: u32,
    pub clients: u32,
    pub wall_clock_seconds: u64,
}
