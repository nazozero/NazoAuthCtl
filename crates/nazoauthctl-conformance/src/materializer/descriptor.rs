use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use super::MaterializerError;

pub const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;
pub const MAX_DESCRIPTOR_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorSource {
    pub release: String,
    pub digest: String,
}

/// Non-secret matrix authority.  Test plan names and profile/variant choices
/// come from this document; no plan is selected in Rust code.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixDescriptor {
    pub schema: u32,
    pub source: DescriptorSource,
    /// Public OpenID4VC claims, keyed by credential configuration id.  This
    /// map is the only dataset authority; executable plan templates may
    /// repeat a dataset only as a consistency check.
    #[serde(default)]
    pub openid4vc_credential_datasets: BTreeMap<String, Value>,
    /// Public mdoc trust anchor advertised by the OIDF Suite.  The value is
    /// part of the signed/raw matrix and is deliberately required rather than
    /// defaulted: silently accepting a descriptor without the Suite trust
    /// root would make a VCI run depend on an unrelated deployment setting.
    pub openid4vc_suite_mdoc_trust_anchor_pem: String,
    pub groups: Vec<DescriptorGroup>,
    #[serde(skip)]
    pub(super) raw_sha256: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorGroup {
    pub id: String,
    pub profile: String,
    pub variant: DescriptorVariant,
    #[serde(default)]
    pub required_roles: Vec<RoleRequirement>,
    pub plans: Vec<DescriptorPlan>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorVariant {
    pub id: String,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorPlan {
    pub id: String,
    /// Official Suite `planName`.
    pub plan: String,
    pub config_template: Value,
    #[serde(default)]
    pub variant: BTreeMap<String, String>,
    /// Exact Suite module names which the signed Matrix permits to finish as
    /// `SKIPPED`. `REVIEW` is a live result and is never pre-approved.
    #[serde(default)]
    pub expected_results: BTreeMap<String, String>,
    #[serde(default)]
    pub required_roles: Vec<RoleRequirement>,
    /// Local aliases.  Values must be one complete placeholder.
    #[serde(default)]
    pub secret_bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub crypto: CryptoPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRequirement {
    pub role: String,
    /// When omitted, the role name is the logical client id.
    #[serde(default)]
    pub logical_client_id: Option<String>,
    #[serde(default)]
    pub secret_refs: Vec<String>,
    /// Complete non-secret CreateClientRequest template.  Only roles with a
    /// registration template create a client in the onboarding bundle.
    #[serde(default)]
    pub registration_template: Option<Value>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoPolicy {
    #[serde(default = "default_rsa_bits")]
    pub rsa_bits: u16,
    #[serde(default = "default_ec_curve")]
    pub ec_curve: String,
    #[serde(default = "default_mtls_signature")]
    pub mtls_signature: String,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            rsa_bits: default_rsa_bits(),
            ec_curve: default_ec_curve(),
            mtls_signature: default_mtls_signature(),
        }
    }
}

fn default_rsa_bits() -> u16 {
    2048
}

fn default_ec_curve() -> String {
    "P-256".to_owned()
}

fn default_mtls_signature() -> String {
    "ECDSA-P256-SHA256".to_owned()
}

pub(super) fn validate_descriptor(descriptor: &MatrixDescriptor) -> Result<(), MaterializerError> {
    if descriptor.schema != DESCRIPTOR_SCHEMA_VERSION {
        return Err(MaterializerError::UnsupportedSchema(descriptor.schema));
    }
    validate_name(&descriptor.source.release, "source.release")?;
    validate_digest(&descriptor.source.digest, "source.digest")?;
    validate_single_mdoc_trust_anchor(
        &descriptor.openid4vc_suite_mdoc_trust_anchor_pem,
        "openid4vc_suite_mdoc_trust_anchor_pem",
    )?;
    if descriptor.groups.is_empty() {
        return Err(MaterializerError::InvalidField("groups"));
    }
    let mut groups = BTreeSet::new();
    let mut plans = BTreeSet::new();
    for group in &descriptor.groups {
        validate_name(&group.id, "group.id")?;
        validate_name(&group.profile, "group.profile")?;
        validate_name(&group.variant.id, "variant.id")?;
        if !groups.insert(group.id.clone()) {
            return Err(MaterializerError::DuplicateId(group.id.clone()));
        }
        role_names(&group.required_roles)?;
        if group.plans.is_empty() {
            return Err(MaterializerError::InvalidField("group.plans"));
        }
        for plan in &group.plans {
            validate_name(&plan.id, "plan.id")?;
            validate_name(&plan.plan, "plan")?;
            if !plan.config_template.is_object() {
                return Err(MaterializerError::InvalidField("plan.config_template"));
            }
            if !plans.insert(plan.id.clone()) {
                return Err(MaterializerError::DuplicateId(plan.id.clone()));
            }
            if plan.expected_results.len() > 64 {
                return Err(MaterializerError::InvalidField("plan.expected_results"));
            }
            for (test_name, result) in &plan.expected_results {
                validate_name(test_name, "plan.expected_results.module")?;
                if result != "SKIPPED" {
                    return Err(MaterializerError::InvalidField(
                        "plan.expected_results.result",
                    ));
                }
            }
            role_names(&plan.required_roles)?;
            validate_crypto_policy(&plan.crypto)?;
            validate_bindings(plan)?;
            validate_value_template(&plan.config_template)?;
            validate_vci_dynamic_policy(plan)?;
            validate_template_references(&plan.config_template, &plan.secret_bindings)?;
            validate_role_refs(plan, group, &group.required_roles, &plan.required_roles)?;
        }
    }
    validate_openid4vc_credential_datasets(descriptor)?;
    let clients = collect_client_policies(descriptor)?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for group in &descriptor.groups {
        for plan in &group.plans {
            validate_template_clients(&plan.config_template, &plan.secret_bindings, &clients)?;
            for template in plan.secret_bindings.values() {
                validate_template_clients(
                    &Value::String(template.clone()),
                    &plan.secret_bindings,
                    &clients,
                )?;
            }
        }
    }
    Ok(())
}

/// Parse and validate one trust anchor used by the OpenID4VC mdoc verifier.
///
/// This is intentionally stricter than the request-object trust material: the
/// mdoc anchor is an actual cryptographic root.  Textual PEM checks alone
/// would allow malformed, expired, non-CA, or attacker-controlled leaf data to
/// reach the server bundle.
pub(super) fn validate_single_mdoc_trust_anchor(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, MaterializerError> {
    let upper = value.to_ascii_uppercase();
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.contains('\0')
        || upper.contains("PRIVATE KEY")
        || !value.starts_with("-----BEGIN CERTIFICATE-----\n")
        || !value.ends_with("-----END CERTIFICATE-----\n")
    {
        return Err(MaterializerError::InvalidField(field));
    }

    let (remaining, pem) =
        parse_x509_pem(value.as_bytes()).map_err(|_| MaterializerError::InvalidField(field))?;
    if pem.label != "CERTIFICATE" || !remaining.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(MaterializerError::InvalidField(field));
    }
    let (der_remaining, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| MaterializerError::InvalidField(field))?;
    if !der_remaining.is_empty()
        || !certificate.is_ca()
        || !certificate.validity().is_valid()
        || certificate.issuer() != certificate.subject()
        || certificate
            .verify_signature(Some(certificate.public_key()))
            .is_err()
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(pem.contents)
}

const MAX_OPENID4VC_DATASETS: usize = 16;
const MAX_OPENID4VC_DATASET_BYTES: usize = 64 * 1024;
const MAX_OPENID4VC_DATASET_TOTAL_BYTES: usize = 512 * 1024;
const MAX_OPENID4VC_DATASET_DEPTH: usize = 8;
const MAX_OPENID4VC_DATASET_NODES: usize = 512;
const MAX_OPENID4VC_DATASET_STRING_BYTES: usize = 4096;

/// Validate the public dataset authority and prove that every VCI plan is
/// bound to exactly one entry.  Keeping this check at descriptor validation
/// means prepare cannot accidentally onboard a dataset for a different plan
/// or silently omit one referenced by the executable configuration.
fn validate_openid4vc_credential_datasets(
    descriptor: &MatrixDescriptor,
) -> Result<(), MaterializerError> {
    if descriptor.openid4vc_credential_datasets.len() > MAX_OPENID4VC_DATASETS {
        return Err(MaterializerError::Oversize);
    }
    let mut referenced = BTreeMap::<String, Option<Value>>::new();
    for group in &descriptor.groups {
        for plan in &group.plans {
            if !plan.plan.starts_with("oid4vci-") {
                continue;
            }
            let configuration_id = descriptor_vci_configuration_id(plan)?;
            let dataset = descriptor
                .openid4vc_credential_datasets
                .get(&configuration_id)
                .ok_or(MaterializerError::InvalidField(
                    "openid4vc_credential_datasets",
                ))?;
            validate_public_credential_dataset(dataset)?;

            // The plan-local value is not authoritative.  If present, it is
            // required to match the descriptor map byte-for-byte so an
            // executable template cannot smuggle a second claims source.
            if let Some(plan_dataset) = plan
                .config_template
                .get("nazo")
                .and_then(Value::as_object)
                .and_then(|nazo| nazo.get("credential_dataset"))
                && plan_dataset != dataset
            {
                return Err(MaterializerError::InvalidField("nazo.credential_dataset"));
            }

            if let Some(previous) = referenced.get(&configuration_id)
                && previous.as_ref() != Some(dataset)
            {
                return Err(MaterializerError::InvalidField(
                    "openid4vc_credential_datasets",
                ));
            }
            referenced.insert(configuration_id, Some(dataset.clone()));
        }
    }

    if descriptor.openid4vc_credential_datasets.len() != referenced.len()
        || descriptor
            .openid4vc_credential_datasets
            .keys()
            .any(|key| !referenced.contains_key(key))
    {
        return Err(MaterializerError::InvalidField(
            "openid4vc_credential_datasets",
        ));
    }
    let mut total_bytes = 0usize;
    for dataset in descriptor.openid4vc_credential_datasets.values() {
        let encoded_len = serde_json::to_vec(dataset)
            .map_err(|_| MaterializerError::Encoding)?
            .len();
        total_bytes = total_bytes
            .checked_add(encoded_len)
            .ok_or(MaterializerError::Oversize)?;
        if total_bytes > MAX_OPENID4VC_DATASET_TOTAL_BYTES {
            return Err(MaterializerError::Oversize);
        }
    }
    Ok(())
}

fn descriptor_vci_configuration_id(plan: &DescriptorPlan) -> Result<String, MaterializerError> {
    let configured = plan
        .config_template
        .get("vci")
        .and_then(Value::as_object)
        .and_then(|vci| vci.get("credential_configuration_id"))
        .and_then(Value::as_str);
    let declared = plan
        .variant
        .get("credential_configuration_id")
        .map(String::as_str);
    let value = match (configured, declared) {
        (Some(configured), Some(declared)) if configured != declared => {
            return Err(MaterializerError::InvalidField(
                "vci.credential_configuration_id",
            ));
        }
        (Some(configured), _) => configured,
        (None, Some(declared)) => declared,
        (None, None) => {
            return Err(MaterializerError::InvalidField(
                "vci.credential_configuration_id",
            ));
        }
    };
    if is_placeholder(value) {
        return Err(MaterializerError::InvalidField(
            "vci.credential_configuration_id",
        ));
    }
    validate_name(value, "vci.credential_configuration_id")?;
    Ok(value.to_owned())
}

fn validate_public_credential_dataset(value: &Value) -> Result<(), MaterializerError> {
    let object = value
        .as_object()
        .filter(|object| !object.is_empty())
        .ok_or(MaterializerError::InvalidField(
            "openid4vc_credential_datasets",
        ))?;
    let bytes = serde_json::to_vec(value).map_err(|_| MaterializerError::Encoding)?;
    if bytes.len() > MAX_OPENID4VC_DATASET_BYTES {
        return Err(MaterializerError::Oversize);
    }
    let mut nodes = 0;
    validate_public_dataset_object(object, 0, &mut nodes)
}

fn validate_public_dataset_object(
    object: &serde_json::Map<String, Value>,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), MaterializerError> {
    *nodes = (*nodes).checked_add(1).ok_or(MaterializerError::Oversize)?;
    if depth > MAX_OPENID4VC_DATASET_DEPTH || *nodes > MAX_OPENID4VC_DATASET_NODES {
        return Err(MaterializerError::Oversize);
    }
    for (key, value) in object {
        validate_public_dataset_key(key)?;
        validate_public_dataset_value(value, depth + 1, nodes)?;
    }
    Ok(())
}

fn validate_public_dataset_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), MaterializerError> {
    *nodes = (*nodes).checked_add(1).ok_or(MaterializerError::Oversize)?;
    if depth > MAX_OPENID4VC_DATASET_DEPTH || *nodes > MAX_OPENID4VC_DATASET_NODES {
        return Err(MaterializerError::Oversize);
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                validate_public_dataset_key(key)?;
                validate_public_dataset_value(child, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|child| validate_public_dataset_value(child, depth + 1, nodes)),
        Value::String(text) => validate_public_dataset_string(text),
        _ => Ok(()),
    }
}

fn validate_public_dataset_key(key: &str) -> Result<(), MaterializerError> {
    let key_lower = key.to_ascii_lowercase();
    if key.trim().is_empty()
        || key.len() > 255
        || key
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || matches!(
            key_lower.as_str(),
            "client_secret"
                | "password"
                | "secret"
                | "token"
                | "access_token"
                | "refresh_token"
                | "authorization_code"
                | "tx_code"
                | "password_hash"
                | "private_key"
                | "private_jwk"
                | "private_jwks"
                | "private_key_pem"
                | "d"
                | "p"
                | "q"
                | "dp"
                | "dq"
                | "qi"
                | "oth"
                | "k"
        )
    {
        return Err(MaterializerError::EmbeddedSecret);
    }
    Ok(())
}

fn validate_public_dataset_string(value: &str) -> Result<(), MaterializerError> {
    if value.len() > MAX_OPENID4VC_DATASET_STRING_BYTES {
        return Err(MaterializerError::Oversize);
    }
    if value.contains("PRIVATE KEY")
        || value.contains("{{")
        || value.contains("}}")
        || value.contains("${")
    {
        return Err(MaterializerError::EmbeddedSecret);
    }
    Ok(())
}

fn validate_vci_dynamic_policy(plan: &DescriptorPlan) -> Result<(), MaterializerError> {
    if !plan.plan.starts_with("oid4vci-") {
        return Ok(());
    }
    let config = plan
        .config_template
        .as_object()
        .ok_or(MaterializerError::InvalidField("plan.config_template"))?;
    let vci = config.get("vci").and_then(Value::as_object);
    if vci.is_some_and(|vci| vci.contains_key("static_tx_code")) {
        return Err(MaterializerError::InvalidField("vci.static_tx_code"));
    }
    if vci.is_some_and(|vci| vci.contains_key("key_attestation_jwks")) {
        return Err(MaterializerError::InvalidField("vci.key_attestation_jwks"));
    }
    let is_haip = plan.plan.contains("haip")
        || plan.variant.get("fapi_profile").map(String::as_str) == Some("vci_haip");
    if is_haip && config.contains_key("client_attestation") {
        return Err(MaterializerError::InvalidField("client_attestation"));
    }
    Ok(())
}

fn validate_role_refs(
    plan: &DescriptorPlan,
    group: &DescriptorGroup,
    group_roles: &[RoleRequirement],
    plan_roles: &[RoleRequirement],
) -> Result<(), MaterializerError> {
    let mut roles = BTreeSet::new();
    for requirement in group_roles.iter().chain(plan_roles) {
        let logical = logical_client_id(requirement)?;
        if !roles.insert(logical.clone()) {
            return Err(MaterializerError::DuplicateRole(logical));
        }
        for reference in &requirement.secret_refs {
            validate_binding_reference(reference, &plan.secret_bindings, &mut BTreeSet::new())?;
        }
        if let Some(template) = &requirement.registration_template {
            validate_registration_template(template)?;
        }
    }
    let _ = group;
    Ok(())
}

pub(super) fn collect_client_policies(
    descriptor: &MatrixDescriptor,
) -> Result<BTreeMap<String, CryptoPolicy>, MaterializerError> {
    let mut policies = BTreeMap::new();
    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                if role.registration_template.is_none() {
                    continue;
                }
                let logical = logical_client_id(role)?;
                if let Some(previous) = policies.get(&logical)
                    && previous != &plan.crypto
                {
                    return Err(MaterializerError::InvalidField("client crypto policy"));
                }
                policies.insert(logical, plan.crypto.clone());
            }
        }
    }
    Ok(policies)
}

pub(super) fn collect_registrations(
    descriptor: &MatrixDescriptor,
) -> Result<BTreeMap<String, Value>, MaterializerError> {
    let mut registrations = BTreeMap::new();
    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                let Some(template) = &role.registration_template else {
                    continue;
                };
                let logical = logical_client_id(role)?;
                if let Some(previous) = registrations.get(&logical)
                    && previous != template
                {
                    return Err(MaterializerError::InvalidField("registration_template"));
                }
                registrations.insert(logical, template.clone());
            }
        }
    }
    Ok(registrations)
}

fn logical_client_id(role: &RoleRequirement) -> Result<String, MaterializerError> {
    let value = role.logical_client_id.as_deref().unwrap_or(&role.role);
    validate_name(value, "logical_client_id")?;
    Ok(value.to_owned())
}

fn role_names(roles: &[RoleRequirement]) -> Result<BTreeSet<String>, MaterializerError> {
    let mut names = BTreeSet::new();
    for role in roles {
        validate_name(&role.role, "role")?;
        if !names.insert(role.role.clone()) {
            return Err(MaterializerError::DuplicateRole(role.role.clone()));
        }
        if let Some(logical) = &role.logical_client_id {
            validate_name(logical, "logical_client_id")?;
        }
    }
    Ok(names)
}

fn validate_bindings(plan: &DescriptorPlan) -> Result<(), MaterializerError> {
    for (name, template) in &plan.secret_bindings {
        validate_name(name, "secret binding")?;
        let reference = parse_placeholder(template)?;
        validate_binding_reference(reference, &plan.secret_bindings, &mut BTreeSet::new())?;
    }
    Ok(())
}

pub(super) fn validate_binding_reference(
    reference: &str,
    bindings: &BTreeMap<String, String>,
    stack: &mut BTreeSet<String>,
) -> Result<(), MaterializerError> {
    let name = reference.trim();
    if name.starts_with("plan.") || name.starts_with("group.") || name.contains("::") {
        return Err(MaterializerError::CrossPlanReference(name.to_owned()));
    }
    if let Some(binding_name) = name.strip_prefix("secret.") {
        if !bindings.contains_key(binding_name) {
            return Err(MaterializerError::UnknownSecretReference(name.to_owned()));
        }
        if !stack.insert(binding_name.to_owned()) {
            return Err(MaterializerError::SecretCycle);
        }
        let nested = parse_placeholder(
            bindings
                .get(binding_name)
                .ok_or(MaterializerError::InvalidPlaceholder)?,
        )?;
        let result = validate_binding_reference(nested, bindings, stack);
        stack.remove(binding_name);
        return result;
    }
    if bindings.contains_key(name) {
        return validate_binding_reference(&format!("secret.{name}"), bindings, stack);
    }
    if is_builtin_reference(name) {
        return Ok(());
    }
    Err(MaterializerError::UnknownSecretReference(name.to_owned()))
}

fn validate_value_template(value: &Value) -> Result<(), MaterializerError> {
    match value {
        Value::Array(values) => values.iter().try_for_each(validate_value_template),
        Value::Object(values) => {
            for (key, child) in values {
                if is_sensitive_key(key)
                    && matches!(child, Value::String(text) if !is_placeholder(text))
                {
                    return Err(MaterializerError::EmbeddedSecret);
                }
                validate_value_template(child)?;
            }
            Ok(())
        }
        Value::String(text)
            if text.contains("{{") || text.contains("}}") || text.contains("${") =>
        {
            parse_placeholder(text).map(|_| ())
        }
        _ => Ok(()),
    }
}

fn validate_registration_template(value: &Value) -> Result<(), MaterializerError> {
    let object = value
        .as_object()
        .ok_or(MaterializerError::InvalidField("registration_template"))?;
    for required in [
        "client_name",
        "client_type",
        "redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "token_endpoint_auth_method",
    ] {
        if !object.contains_key(required) {
            return Err(MaterializerError::InvalidField("registration_template"));
        }
    }
    validate_registration_value(value)
}

fn validate_registration_value(value: &Value) -> Result<(), MaterializerError> {
    match value {
        Value::Array(values) => values.iter().try_for_each(validate_registration_value),
        Value::Object(values) => {
            for (key, child) in values {
                if matches!(
                    key.as_str(),
                    "client_secret" | "private_key" | "private_key_pem" | "mtls_client_key"
                ) {
                    return Err(MaterializerError::EmbeddedSecret);
                }
                validate_registration_value(child)?;
            }
            Ok(())
        }
        Value::String(text)
            if text.contains("{{") || text.contains("}}") || text.contains("${") =>
        {
            parse_placeholder(text).map(|_| ())
        }
        _ => Ok(()),
    }
}

fn validate_template_references(
    value: &Value,
    bindings: &BTreeMap<String, String>,
) -> Result<(), MaterializerError> {
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_template_references(value, bindings)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_template_references(value, bindings)),
        Value::String(text) if is_placeholder(text) => {
            validate_binding_reference(parse_placeholder(text)?, bindings, &mut BTreeSet::new())
        }
        _ => Ok(()),
    }
}

fn validate_template_clients(
    value: &Value,
    bindings: &BTreeMap<String, String>,
    clients: &BTreeSet<String>,
) -> Result<(), MaterializerError> {
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_template_clients(value, bindings, clients)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_template_clients(value, bindings, clients)),
        Value::String(text) if is_placeholder(text) => validate_reference_client(
            parse_placeholder(text)?,
            bindings,
            clients,
            &mut BTreeSet::new(),
        ),
        _ => Ok(()),
    }
}

fn validate_reference_client(
    name: &str,
    bindings: &BTreeMap<String, String>,
    clients: &BTreeSet<String>,
    stack: &mut BTreeSet<String>,
) -> Result<(), MaterializerError> {
    if let Some(binding_name) = name.strip_prefix("secret.") {
        if !stack.insert(binding_name.to_owned()) {
            return Err(MaterializerError::SecretCycle);
        }
        let nested = parse_placeholder(
            bindings
                .get(binding_name)
                .ok_or(MaterializerError::UnknownSecretReference(name.to_owned()))?,
        )?;
        let result = validate_reference_client(nested, bindings, clients, stack);
        stack.remove(binding_name);
        return result;
    }
    if bindings.contains_key(name) {
        return validate_reference_client(&format!("secret.{name}"), bindings, clients, stack);
    }
    if let Some(rest) = name.strip_prefix("client.") {
        let logical = rest
            .split_once('.')
            .map(|(logical, _)| logical)
            .ok_or_else(|| MaterializerError::UnknownClientReference(rest.to_owned()))?;
        if !clients.contains(logical) {
            return Err(MaterializerError::UnknownClientReference(
                logical.to_owned(),
            ));
        }
    } else if matches!(name, "onboarding.client_id" | "onboarding.client_secret")
        && clients.len() != 1
    {
        return Err(MaterializerError::AmbiguousClientReference);
    }
    Ok(())
}

fn is_builtin_reference(name: &str) -> bool {
    matches!(
        name,
        "generated.applicant_password"
            | "generated.client_secret"
            | "generated.rsa.private_jwks"
            | "generated.rsa.public_jwks"
            | "generated.ec.private_jwks"
            | "generated.ec.public_jwks"
            | "generated.mtls.ca_cert"
            | "generated.mtls.client_cert"
            | "generated.mtls.client_key"
            | "generated.mtls.cert_sha256"
            | "generated.dynamic_registration_initial_access_token"
            | "generated.ciba_automated_decision_token"
            | "generated.applicant_email"
            | "generated.credential_holder_email_sha256"
            | "onboarding.applicant_id"
            | "onboarding.openid4vc_request_object_trust_anchor_pem"
            | "onboarding.client_id"
            | "onboarding.client_secret"
            | "target.issuer"
            | "target.host"
            | "target.ciba_automated_decision_url"
            | "target.suite"
            | "suite.origin"
    ) || name.starts_with("client.")
        || name.starts_with("target.url.")
        || name.starts_with("target.pattern.")
        || name.starts_with("run.alias.")
        || name.starts_with("suite.test.")
        || name.starts_with("suite.test_query.")
        || name.starts_with("suite.pattern.")
}

pub(super) fn descriptor_requires_reference(
    descriptor: &MatrixDescriptor,
    reference: &str,
) -> bool {
    descriptor.groups.iter().any(|group| {
        group.required_roles.iter().any(|role| {
            role.secret_refs.iter().any(|secret_ref| {
                secret_ref.trim() == reference
                    || value_contains_reference(&Value::String(secret_ref.clone()), reference)
            })
        }) || group.plans.iter().any(|plan| {
            value_contains_reference(&plan.config_template, reference)
                || plan.secret_bindings.values().any(|binding| {
                    value_contains_reference(&Value::String(binding.clone()), reference)
                })
                || plan.required_roles.iter().any(|role| {
                    role.secret_refs.iter().any(|secret_ref| {
                        secret_ref.trim() == reference
                            || value_contains_reference(
                                &Value::String(secret_ref.clone()),
                                reference,
                            )
                    })
                })
        })
    })
}

fn value_contains_reference(value: &Value, reference: &str) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_reference(value, reference)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_reference(value, reference)),
        Value::String(text) => {
            is_placeholder(text) && parse_placeholder(text).ok() == Some(reference)
        }
        _ => false,
    }
}

pub(super) fn parse_placeholder(value: &str) -> Result<&str, MaterializerError> {
    if !value.starts_with("{{") || !value.ends_with("}}") || value.len() < 5 {
        return Err(MaterializerError::InvalidPlaceholder);
    }
    let name = value[2..value.len() - 2].trim();
    if name.is_empty()
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || name.contains("{{")
        || name.contains("}}")
    {
        return Err(MaterializerError::InvalidPlaceholder);
    }
    Ok(name)
}

pub(super) fn is_placeholder(value: &str) -> bool {
    value.starts_with("{{") && value.ends_with("}}") && parse_placeholder(value).is_ok()
}

fn validate_crypto_policy(policy: &CryptoPolicy) -> Result<(), MaterializerError> {
    if !matches!(policy.rsa_bits, 2048 | 3072 | 4096)
        || policy.ec_curve != "P-256"
        || policy.mtls_signature != "ECDSA-P256-SHA256"
    {
        return Err(MaterializerError::WeakAlgorithm);
    }
    Ok(())
}

fn validate_name(value: &str, field: &'static str) -> Result<(), MaterializerError> {
    if value.trim().is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

pub(super) fn validate_digest(value: &str, field: &'static str) -> Result<(), MaterializerError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value != value.to_ascii_lowercase()
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "client_secret" | "password" | "token" | "private_key" | "private_key_pem" | "secret"
    )
}
