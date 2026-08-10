use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MATRIX_SCHEMA_VERSION: u32 = 1;
pub const MAX_MATRIX_BYTES: usize = 8 * 1024 * 1024;

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
}

#[derive(Clone)]
pub struct MatrixArtifact {
    pub document: MatrixDocument,
    digest: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixSelection {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone)]
pub struct SelectedMatrix {
    pub document: MatrixDocument,
    pub digest: String,
}

impl MatrixArtifact {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MatrixError> {
        if bytes.len() > MAX_MATRIX_BYTES {
            return Err(MatrixError::Oversize);
        }
        let document: MatrixDocument =
            serde_json::from_slice(bytes).map_err(|_| MatrixError::Malformed)?;
        validate_document(&document)?;
        Ok(Self {
            document,
            digest: digest_hex(bytes),
        })
    }

    pub fn from_path(path: &Path) -> Result<Self, MatrixError> {
        let bytes =
            crate::secure_file::read_bounded(path, MAX_MATRIX_BYTES, false).map_err(|error| {
                match error {
                    crate::secure_file::SecureFileError::Oversize => MatrixError::Oversize,
                    crate::secure_file::SecureFileError::UnsafePath => MatrixError::UnsafePath,
                    _ => MatrixError::Io,
                }
            })?;
        Self::from_bytes(&bytes)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn select(&self, selection: &MatrixSelection) -> Result<SelectedMatrix, MatrixError> {
        let groups_filter = filter_set(&selection.groups)?;
        let profiles_filter = filter_set(&selection.profiles)?;
        for wanted in &groups_filter {
            if !self.document.groups.iter().any(|group| &group.id == wanted) {
                return Err(MatrixError::UnknownSelection(wanted.clone()));
            }
        }
        for wanted in &profiles_filter {
            if !self
                .document
                .groups
                .iter()
                .any(|group| &group.profile == wanted)
            {
                return Err(MatrixError::UnknownSelection(wanted.clone()));
            }
        }
        let groups = self
            .document
            .groups
            .iter()
            .filter(|group| {
                (groups_filter.is_empty() || groups_filter.contains(&group.id))
                    && (profiles_filter.is_empty() || profiles_filter.contains(&group.profile))
            })
            .cloned()
            .collect::<Vec<_>>();
        if groups.is_empty() {
            return Err(MatrixError::EmptySelection);
        }
        Ok(SelectedMatrix {
            document: MatrixDocument {
                schema: self.document.schema,
                name: self.document.name.clone(),
                groups,
            },
            digest: self.digest.clone(),
        })
    }
}

impl SelectedMatrix {
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

fn zeroize_json_value(value: &mut Value) {
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

    pub fn module_aliases(&self) -> Vec<String> {
        self.groups
            .iter()
            .flat_map(|group| group.plans.iter())
            .filter_map(|plan| {
                plan.config
                    .get("alias")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect()
    }
}

impl MatrixGroup {
    pub fn effective_variant(&self, plan: &MatrixPlan) -> BTreeMap<String, String> {
        let mut values = self.variant.values.clone();
        values.extend(plan.variant.clone());
        values
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MatrixError {
    Io,
    Oversize,
    Malformed,
    UnsupportedSchema(u32),
    EmptyDocument,
    DuplicateId(String),
    EmptyField(&'static str),
    ConfigNotObject(String),
    UnsafePath,
    EmptySelection,
    UnknownSelection(String),
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => formatter.write_str("matrix input could not be read"),
            Self::Oversize => formatter.write_str("matrix input exceeds the size limit"),
            Self::Malformed => formatter.write_str("matrix input is malformed JSON"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported matrix schema {version}")
            }
            Self::EmptyDocument => formatter.write_str("matrix has no groups or plans"),
            Self::DuplicateId(id) => write!(formatter, "matrix contains duplicate id {id}"),
            Self::EmptyField(field) => write!(formatter, "matrix field {field} must not be empty"),
            Self::ConfigNotObject(id) => {
                write!(formatter, "matrix plan {id} config must be a JSON object")
            }
            Self::UnsafePath => {
                formatter.write_str("matrix input path is not a stable regular file")
            }
            Self::EmptySelection => formatter.write_str("matrix selection contains no groups"),
            Self::UnknownSelection(value) => {
                write!(formatter, "matrix selection is unknown: {value}")
            }
        }
    }
}

impl std::error::Error for MatrixError {}

fn validate_document(document: &MatrixDocument) -> Result<(), MatrixError> {
    if document.schema != MATRIX_SCHEMA_VERSION {
        return Err(MatrixError::UnsupportedSchema(document.schema));
    }
    if document.name.trim().is_empty() {
        return Err(MatrixError::EmptyField("name"));
    }
    if document.groups.is_empty() {
        return Err(MatrixError::EmptyDocument);
    }
    let mut group_ids = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    for group in &document.groups {
        if group.id.trim().is_empty() {
            return Err(MatrixError::EmptyField("groups.id"));
        }
        if group.profile.trim().is_empty() {
            return Err(MatrixError::EmptyField("groups.profile"));
        }
        if group.variant.id.trim().is_empty() {
            return Err(MatrixError::EmptyField("groups.variant.id"));
        }
        if group.plans.is_empty() {
            return Err(MatrixError::EmptyField("groups.plans"));
        }
        if !group_ids.insert(group.id.clone()) {
            return Err(MatrixError::DuplicateId(group.id.clone()));
        }
        for plan in &group.plans {
            if plan.id.trim().is_empty() {
                return Err(MatrixError::EmptyField("plans.id"));
            }
            if plan.plan.trim().is_empty() {
                return Err(MatrixError::EmptyField("plans.plan"));
            }
            if !plan.config.is_object() {
                return Err(MatrixError::ConfigNotObject(plan.id.clone()));
            }
            if !plan_ids.insert(plan.id.clone()) {
                return Err(MatrixError::DuplicateId(plan.id.clone()));
            }
        }
    }
    Ok(())
}

fn filter_set(values: &[String]) -> Result<BTreeSet<String>, MatrixError> {
    let mut set = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(MatrixError::EmptyField("selection"));
        }
        if !set.insert(value.clone()) {
            return Err(MatrixError::DuplicateId(value.clone()));
        }
    }
    Ok(set)
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        br#"{"schema":1,"name":"fixture","groups":[{"id":"g","profile":"oidc","variant":{"id":"v","values":{"mode":"plain"}},"plans":[{"id":"p","plan":"oidcc-basic-certification-test-plan","config":{"alias":"a"}}]}]}"#.to_vec()
    }

    #[test]
    fn digest_and_selection_are_stable() {
        let artifact = MatrixArtifact::from_bytes(&fixture()).expect("matrix");
        assert_eq!(artifact.document.plan_count(), 1);
        assert_eq!(
            artifact
                .select(&MatrixSelection::default())
                .expect("selection")
                .digest,
            artifact.digest
        );
    }

    #[test]
    fn unknown_selection_is_rejected() {
        let artifact = MatrixArtifact::from_bytes(&fixture()).expect("matrix");
        let selection = MatrixSelection {
            groups: vec!["missing".into()],
            profiles: vec![],
        };
        assert!(matches!(
            artifact.select(&selection),
            Err(MatrixError::UnknownSelection(_))
        ));
    }

    #[test]
    fn malformed_and_oversize_artifacts_are_rejected_before_selection() {
        assert!(matches!(
            MatrixArtifact::from_bytes(br#"{"#),
            Err(MatrixError::Malformed)
        ));
        let bytes = vec![b' '; MAX_MATRIX_BYTES + 1];
        assert!(matches!(
            MatrixArtifact::from_bytes(&bytes),
            Err(MatrixError::Oversize)
        ));
    }
}
