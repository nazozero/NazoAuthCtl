use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::crypto::GeneratedAttestationMaterial;
use super::{
    MaterializationBindings, MaterializerError, PreparedMaterialization, digest_hex,
    is_placeholder, parse_placeholder, validate_binding_reference, validate_request_jti,
};

const USER_REJECT_MODULES: [&str; 2] = [
    "fapi2-security-profile-final-user-rejects-authentication",
    "fapi2-security-profile-id2-user-rejects-authentication",
];
const PAR_REUSE_BEFORE_AUTH_MODULES: [&str; 2] = [
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds",
    "fapi2-security-profile-id2-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds",
];

pub(super) fn materialize_value(
    value: &Value,
    bindings: &BTreeMap<String, String>,
    prepared: &PreparedMaterialization,
    onboarding: &MaterializationBindings,
    stack: &mut BTreeSet<String>,
) -> Result<Value, MaterializerError> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| materialize_value(value, bindings, prepared, onboarding, stack))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                output.insert(
                    key.clone(),
                    materialize_value(value, bindings, prepared, onboarding, stack)?,
                );
            }
            Ok(Value::Object(output))
        }
        Value::String(text) if is_placeholder(text) => resolve_reference(
            parse_placeholder(text)?,
            bindings,
            prepared,
            onboarding,
            stack,
        ),
        Value::String(text)
            if text.contains("{{") || text.contains("}}") || text.contains("${") =>
        {
            Err(MaterializerError::InvalidPlaceholder)
        }
        _ => Ok(value.clone()),
    }
}

/// Normalize the small amount of issuer-side configuration that the official
/// OpenID4VC materializer derives from a VCI plan.  The descriptor remains the
/// authority for the credential configuration id and variant; this function
/// only binds that declared configuration to the current issuer and rejects a
/// conflicting pre-materialized value.
#[allow(clippy::too_many_arguments)]
pub(super) fn materialize_vci_config(
    plan_name: &str,
    variant: &BTreeMap<String, String>,
    config: Value,
    target_issuer: &str,
    suite_origin: &str,
    tx_code: Option<&str>,
    attestation: Option<&GeneratedAttestationMaterial>,
    credential_trust_anchor_pem: &str,
) -> Result<Value, MaterializerError> {
    if !plan_name.starts_with("oid4vci-") {
        return Ok(config);
    }
    let Value::Object(mut root) = config else {
        return Err(MaterializerError::InvalidField("plan.config_template"));
    };
    let alias =
        root.get("alias")
            .and_then(Value::as_str)
            .ok_or(MaterializerError::InvalidField(
                "plan.config_template.alias",
            ))?;
    validate_vci_string(alias, "plan.config_template.alias")?;

    let mut vci = match root.remove("vci") {
        None => serde_json::Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(MaterializerError::InvalidField("vci")),
    };
    let pre_authorized =
        variant.get("vci_grant_type").map(String::as_str) == Some("pre_authorization_code");
    if pre_authorized {
        let tx_code = tx_code.ok_or(MaterializerError::InvalidField("generated.tx_code"))?;
        if vci.contains_key("static_tx_code") {
            return Err(MaterializerError::InvalidField("vci.static_tx_code"));
        }
        validate_tx_code(tx_code)?;
        vci.insert(
            "static_tx_code".to_owned(),
            Value::String(tx_code.to_owned()),
        );
    } else if vci.contains_key("static_tx_code") {
        return Err(MaterializerError::InvalidField("vci.static_tx_code"));
    }
    let declared_id = variant.get("credential_configuration_id");
    let configured_id = vci
        .get("credential_configuration_id")
        .and_then(Value::as_str);
    let credential_configuration_id = match (configured_id, declared_id) {
        (Some(configured), Some(declared)) if configured != declared.as_str() => {
            return Err(MaterializerError::InvalidField(
                "vci.credential_configuration_id",
            ));
        }
        (Some(configured), _) => configured.to_owned(),
        (None, Some(declared)) => declared.to_owned(),
        (None, None) => {
            return Err(MaterializerError::InvalidField(
                "vci.credential_configuration_id",
            ));
        }
    };
    validate_vci_string(
        &credential_configuration_id,
        "vci.credential_configuration_id",
    )?;
    vci.insert(
        "credential_configuration_id".to_owned(),
        Value::String(credential_configuration_id),
    );
    if let Some(configured_issuer) = vci.get("credential_issuer_url")
        && configured_issuer.as_str() != Some(target_issuer)
    {
        return Err(MaterializerError::InvalidField("vci.credential_issuer_url"));
    }
    vci.insert(
        "credential_issuer_url".to_owned(),
        Value::String(target_issuer.to_owned()),
    );
    let attestation = attestation.ok_or(MaterializerError::InvalidField(
        "generated.vci_key_attestation",
    ))?;
    let key_attestation_jwks = jwks_value(&attestation.key_attestation_private_jwks)?;
    if let Some(existing) = vci.get("key_attestation_jwks")
        && existing != &key_attestation_jwks
    {
        return Err(MaterializerError::InvalidField("vci.key_attestation_jwks"));
    }
    vci.insert(
        "key_attestation_jwks".to_owned(),
        key_attestation_jwks.clone(),
    );
    let haip = plan_name.contains("haip")
        || variant.get("fapi_profile").map(String::as_str) == Some("vci_haip");
    if haip {
        if root.contains_key("client_attestation") {
            return Err(MaterializerError::InvalidField("client_attestation"));
        }
        root.insert(
            "client_attestation".to_owned(),
            serde_json::json!({
                "issuer": format!("{}/", suite_origin.trim_end_matches('/')),
                "trust_anchor": attestation.trust_anchor_pem.to_string(),
                "key_attestation_trust_anchor_pem": attestation.trust_anchor_pem.to_string(),
                "attester_jwks": jwks_value(&attestation.attester_private_jwks)?,
                "key_attestation_jwks": key_attestation_jwks,
            }),
        );
    }
    let mut credential = match root.remove("credential") {
        None => serde_json::Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(MaterializerError::InvalidField("credential")),
    };
    for field in ["trust_anchor_pem", "status_list_trust_anchor_pem"] {
        if let Some(existing) = credential.get(field)
            && existing.as_str() != Some(credential_trust_anchor_pem)
        {
            return Err(MaterializerError::InvalidField("credential.trust_anchor"));
        }
        credential.insert(
            field.to_owned(),
            Value::String(credential_trust_anchor_pem.to_owned()),
        );
    }
    root.insert("credential".to_owned(), Value::Object(credential));
    root.insert("vci".to_owned(), Value::Object(vci));

    let mut nazo = match root.remove("nazo") {
        None => serde_json::Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(MaterializerError::InvalidField("nazo")),
    };
    ensure_vci_field(&mut nazo, "openid4vc_role", "issuer")?;
    if let Some(client_auth_type) = variant.get("client_auth_type") {
        validate_vci_string(client_auth_type, "variant.client_auth_type")?;
        ensure_vci_field(&mut nazo, "client_auth_type", client_auth_type)?;
    }
    let variant_format = variant.get("credential_format");
    let configured_format = nazo.get("credential_format").and_then(Value::as_str);
    let credential_format = match (configured_format, variant_format) {
        (Some(configured), Some(declared)) if configured != declared => {
            return Err(MaterializerError::InvalidField("nazo.credential_format"));
        }
        (Some(configured), _) => configured.to_owned(),
        (None, Some(declared)) => declared.to_owned(),
        (None, None) => {
            return Err(MaterializerError::InvalidField("nazo.credential_format"));
        }
    };
    validate_vci_string(&credential_format, "nazo.credential_format")?;
    nazo.insert(
        "credential_format".to_owned(),
        Value::String(credential_format),
    );
    root.insert("nazo".to_owned(), Value::Object(nazo));
    materialize_vci_browser_overrides(&mut root, target_issuer)?;
    Ok(Value::Object(root))
}

/// Materialize the module-specific Suite WebRunner configuration before the
/// plan is created.  The Suite executes these overrides itself; changing only
/// the local browser driver would race the default approval/login workflow.
fn materialize_vci_browser_overrides(
    root: &mut serde_json::Map<String, Value>,
    target_issuer: &str,
) -> Result<(), MaterializerError> {
    let Some(browser) = root.get("browser") else {
        return Ok(());
    };
    let browser = browser
        .as_array()
        .ok_or(MaterializerError::InvalidField("browser"))?;
    let authorization_match = format!("{}/authorize*", target_issuer.trim_end_matches('/'));
    let login_match = format!("{}/ui/auth*", target_issuer.trim_end_matches('/'));
    let authorization_entries = browser
        .iter()
        .filter(|entry| entry.get("match").and_then(Value::as_str) == Some(&authorization_match))
        .cloned()
        .collect::<Vec<_>>();
    if authorization_entries.len() != 1 {
        return Err(MaterializerError::InvalidField("browser.authorize"));
    }

    let mut rejection_browser = authorization_entries.clone();
    let mut denial_controls = 0usize;
    replace_consent_approval_with_denial(&mut rejection_browser, &mut denial_controls)?;
    if denial_controls < 2 {
        return Err(MaterializerError::InvalidField("browser.consent_deny"));
    }

    let mut second_authorization = authorization_entries[0].clone();
    second_authorization
        .as_object_mut()
        .ok_or(MaterializerError::InvalidField("browser.authorize"))?
        .remove("match-limit");
    let first_authorization = serde_json::json!({
        "comment": "This module requires the first authorization endpoint visit to stop at the login page without authenticating.",
        "match": authorization_match,
        "match-limit": 1,
        "tasks": [{
            "task": "Observe first login page without authentication",
            "match": login_match,
            "commands": [[
                "wait", "id", "nazo-login-email", 30, ".*",
                "update-image-placeholder-optional"
            ]]
        }]
    });
    let par_browser = Value::Array(vec![first_authorization, second_authorization]);
    let rejection_browser = Value::Array(rejection_browser);

    let overrides = match root.entry("override".to_owned()) {
        serde_json::map::Entry::Vacant(entry) => {
            entry.insert(Value::Object(serde_json::Map::new()))
        }
        serde_json::map::Entry::Occupied(entry) => entry.into_mut(),
    };
    let overrides = overrides
        .as_object_mut()
        .ok_or(MaterializerError::InvalidField("override"))?;
    for module in USER_REJECT_MODULES {
        insert_exact_browser_override(overrides, module, &rejection_browser)?;
    }
    for module in PAR_REUSE_BEFORE_AUTH_MODULES {
        insert_exact_browser_override(overrides, module, &par_browser)?;
    }
    Ok(())
}

fn replace_consent_approval_with_denial(
    values: &mut [Value],
    denial_controls: &mut usize,
) -> Result<(), MaterializerError> {
    for entry in values {
        let tasks = entry
            .get_mut("tasks")
            .and_then(Value::as_array_mut)
            .ok_or(MaterializerError::InvalidField("browser.tasks"))?;
        for task in tasks {
            let commands = task
                .get_mut("commands")
                .and_then(Value::as_array_mut)
                .ok_or(MaterializerError::InvalidField("browser.commands"))?;
            for command in commands {
                let tuple = command
                    .as_array_mut()
                    .ok_or(MaterializerError::InvalidField("browser.command"))?;
                if tuple.get(1).and_then(Value::as_str) == Some("id") {
                    match tuple.get(2).and_then(Value::as_str) {
                        Some("nazo-consent-approve") => {
                            tuple[2] = Value::String("nazo-consent-deny".to_owned());
                            *denial_controls += 1;
                        }
                        Some("nazo-consent-deny") => *denial_controls += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

fn insert_exact_browser_override(
    overrides: &mut serde_json::Map<String, Value>,
    module: &str,
    browser: &Value,
) -> Result<(), MaterializerError> {
    let expected = serde_json::json!({"browser": browser});
    match overrides.get(module) {
        None => {
            overrides.insert(module.to_owned(), expected);
            Ok(())
        }
        Some(existing) if existing == &expected => Ok(()),
        Some(_) => Err(MaterializerError::InvalidField("override.browser")),
    }
}

pub(super) fn materialize_vp_config(
    plan_name: &str,
    variant: &BTreeMap<String, String>,
    config: Value,
    suite_base_url: &str,
    request_object_trust_anchor_pem: &str,
    attestation: Option<&GeneratedAttestationMaterial>,
) -> Result<Value, MaterializerError> {
    if !plan_name.starts_with("oid4vp-") {
        return Ok(config);
    }
    let Value::Object(mut root) = config else {
        return Err(MaterializerError::InvalidField("plan.config_template"));
    };
    let attestation = attestation.ok_or(MaterializerError::InvalidField(
        "generated.vp_credential_signer",
    ))?;
    let signing_jwk: Value =
        serde_json::from_str(attestation.credential_signing_private_jwk.as_str())
            .map_err(|_| MaterializerError::Encoding)?;
    let mut credential = match root.remove("credential") {
        None => serde_json::Map::new(),
        Some(Value::Object(value)) => value,
        Some(_) => return Err(MaterializerError::InvalidField("credential")),
    };
    if let Some(existing) = credential.get("signing_jwk")
        && existing != &signing_jwk
    {
        return Err(MaterializerError::InvalidField("credential.signing_jwk"));
    }
    credential.insert("signing_jwk".to_owned(), signing_jwk);
    for field in ["trust_anchor_pem", "status_list_trust_anchor_pem"] {
        if let Some(existing) = credential.get(field)
            && existing.as_str() != Some(attestation.trust_anchor_pem.as_str())
        {
            return Err(MaterializerError::InvalidField("credential.trust_anchor"));
        }
        credential.insert(
            field.to_owned(),
            Value::String(attestation.trust_anchor_pem.to_string()),
        );
    }
    root.insert("credential".to_owned(), Value::Object(credential));
    materialize_vp_verification_evidence_browser(&mut root, suite_base_url)?;
    let request_method = variant.get("request_method").map(String::as_str);
    // The official verifier HAIP plan is request-URI signed even though its
    // executable Matrix variant does not repeat the transport selector.
    let request_uri_signed = plan_name == "oid4vp-1final-verifier-haip-test-plan"
        || request_method.is_some_and(|value| value.starts_with("request_uri_signed"));
    if !root.contains_key("client") {
        if request_uri_signed {
            return Err(MaterializerError::InvalidField("client"));
        }
        return Ok(Value::Object(root));
    }
    let client_value = root
        .get_mut("client")
        .ok_or(MaterializerError::InvalidField("client"))?;
    let Value::Object(client) = client_value else {
        return Err(MaterializerError::InvalidField("client"));
    };
    if request_uri_signed {
        if let Some(existing) = client.get("request_object_trust_anchor_pem")
            && existing.as_str() != Some(request_object_trust_anchor_pem)
        {
            return Err(MaterializerError::InvalidField(
                "client.request_object_trust_anchor_pem",
            ));
        }
        client.insert(
            "request_object_trust_anchor_pem".to_owned(),
            Value::String(request_object_trust_anchor_pem.to_owned()),
        );
    } else if request_method == Some("url_query")
        && client.contains_key("request_object_trust_anchor_pem")
    {
        return Err(MaterializerError::InvalidField(
            "client.request_object_trust_anchor_pem",
        ));
    }
    Ok(Value::Object(root))
}

fn materialize_vp_verification_evidence_browser(
    root: &mut serde_json::Map<String, Value>,
    suite_base_url: &str,
) -> Result<(), MaterializerError> {
    let evidence_url = format!(
        "{}/test/a/*/verification-evidence",
        suite_base_url.trim_end_matches('/')
    );
    let authorization_url = format!(
        "{}/test/a/*/authorize*",
        suite_base_url.trim_end_matches('/')
    );
    let expected = serde_json::json!([{
        "comment": "drive the signed VP authorization entry; its required evidence task authorizes a NazoAuth verification-result capture",
        "match": authorization_url,
        "tasks": [{
            "task": "Capture verification evidence",
            "match": evidence_url,
            "commands": [[
                "wait", "xpath", "//*", 10,
                ".*Deferred verification evidence.*",
                "update-image-placeholder"
            ]]
        }]
    }]);
    match root.get("browser") {
        None => {
            root.insert("browser".to_owned(), expected);
            Ok(())
        }
        Some(existing) if existing == &expected => Ok(()),
        Some(_) => Err(MaterializerError::InvalidField("browser")),
    }
}

fn ensure_vci_field(
    object: &mut serde_json::Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), MaterializerError> {
    if let Some(value) = object.get(field)
        && value.as_str() != Some(expected)
    {
        return Err(MaterializerError::InvalidField("nazo"));
    }
    object.insert(field.to_owned(), Value::String(expected.to_owned()));
    Ok(())
}

fn validate_vci_string(value: &str, field: &'static str) -> Result<(), MaterializerError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(MaterializerError::InvalidField(field));
    }
    Ok(())
}

fn validate_tx_code(value: &str) -> Result<(), MaterializerError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MaterializerError::InvalidField("generated.tx_code"));
    }
    Ok(())
}

fn jwks_value(value: &Zeroizing<String>) -> Result<Value, MaterializerError> {
    serde_json::from_str(value.as_str()).map_err(|_| MaterializerError::Encoding)
}

fn resolve_reference(
    name: &str,
    bindings: &BTreeMap<String, String>,
    prepared: &PreparedMaterialization,
    onboarding: &MaterializationBindings,
    stack: &mut BTreeSet<String>,
) -> Result<Value, MaterializerError> {
    validate_binding_reference(name, bindings, &mut BTreeSet::new())?;
    if let Some(binding_name) = name.strip_prefix("secret.") {
        if !stack.insert(binding_name.to_owned()) {
            return Err(MaterializerError::SecretCycle);
        }
        let nested = parse_placeholder(
            bindings
                .get(binding_name)
                .ok_or(MaterializerError::InvalidPlaceholder)?,
        )?;
        let result = resolve_reference(nested, bindings, prepared, onboarding, stack);
        stack.remove(binding_name);
        return result;
    }
    if bindings.contains_key(name) {
        return resolve_reference(
            &format!("secret.{name}"),
            bindings,
            prepared,
            onboarding,
            stack,
        );
    }
    if name == "target.issuer" {
        return Ok(Value::String(prepared.target_issuer.clone()));
    }
    if matches!(name, "target.suite" | "suite.origin") {
        return Ok(Value::String(prepared.suite_base_url.clone()));
    }
    if name == "target.host" {
        return Ok(Value::String(target_host(&prepared.target_issuer)?));
    }
    if let Some(path) = name.strip_prefix("target.url.") {
        return Ok(Value::String(resolve_target_url(
            &prepared.target_issuer,
            path,
            false,
        )?));
    }
    if let Some(path) = name.strip_prefix("target.pattern.") {
        return Ok(Value::String(resolve_target_url(
            &prepared.target_issuer,
            path,
            true,
        )?));
    }
    if let Some(endpoint) = name.strip_prefix("suite.pattern.") {
        validate_url_segment(endpoint)?;
        return Ok(Value::String(format!("*/test/*/{endpoint}*")));
    }
    if let Some(alias_key) = name.strip_prefix("run.alias.") {
        return Ok(Value::String(resolve_run_alias(
            &prepared.request_jti,
            alias_key,
        )?));
    }
    if let Some(reference) = name.strip_prefix("suite.test.") {
        return Ok(Value::String(resolve_suite_test_url(
            &prepared.suite_base_url,
            &prepared.request_jti,
            reference,
        )?));
    }
    if let Some(reference) = name.strip_prefix("suite.test_query.") {
        return Ok(Value::String(format!(
            "{}?dummy1=lorem&dummy2=ipsum",
            resolve_suite_test_url(&prepared.suite_base_url, &prepared.request_jti, reference,)?
        )));
    }
    if name == "generated.applicant_email" {
        return Ok(Value::String(prepared.applicant_email.to_string()));
    }
    if name == "generated.applicant_password" {
        return Ok(Value::String(prepared.applicant_password.to_string()));
    }
    if name == "generated.credential_holder_email_sha256" {
        return Ok(Value::String(digest_hex(
            prepared.applicant_email.as_bytes(),
        )));
    }
    if name == "onboarding.applicant_id" {
        return Ok(Value::String(onboarding.applicant_id.clone()));
    }
    if name == "onboarding.openid4vc_request_object_trust_anchor_pem" {
        return Ok(Value::String(
            onboarding.openid4vc_request_object_trust_anchor_pem.clone(),
        ));
    }
    if name == "generated.dynamic_registration_initial_access_token" {
        return prepared
            .dynamic_registration_initial_access_token
            .as_ref()
            .map(|value| Value::String(value.to_string()))
            .ok_or(MaterializerError::UnknownSecretReference(name.to_owned()));
    }
    if name == "onboarding.client_id" || name == "onboarding.client_secret" {
        if prepared.clients.len() != 1 {
            return Err(MaterializerError::AmbiguousClientReference);
        }
        let logical = prepared
            .clients
            .keys()
            .next()
            .ok_or(MaterializerError::AmbiguousClientReference)?;
        let field = if name == "onboarding.client_id" {
            "id"
        } else {
            "client_secret"
        };
        return resolve_client_reference(logical, field, prepared, &onboarding.clients);
    }
    if let Some(client_reference) = name.strip_prefix("client.") {
        let (logical, field) = client_reference.split_once('.').ok_or_else(|| {
            MaterializerError::UnknownClientReference(client_reference.to_owned())
        })?;
        return resolve_client_reference(logical, field, prepared, &onboarding.clients);
    }
    if name.starts_with("generated.") {
        if prepared.clients.len() != 1 {
            return Err(MaterializerError::AmbiguousClientReference);
        }
        let logical = prepared
            .clients
            .keys()
            .next()
            .ok_or(MaterializerError::AmbiguousClientReference)?;
        return resolve_client_reference(
            logical,
            name.strip_prefix("generated.").unwrap_or_default(),
            prepared,
            &onboarding.clients,
        );
    }
    Err(MaterializerError::UnknownSecretReference(name.to_owned()))
}

fn resolve_client_reference(
    logical: &str,
    field: &str,
    prepared: &PreparedMaterialization,
    actual_clients: &BTreeMap<String, String>,
) -> Result<Value, MaterializerError> {
    let client = prepared
        .clients
        .get(logical)
        .ok_or_else(|| MaterializerError::UnknownClientReference(logical.to_owned()))?;
    match field {
        "id" => actual_clients
            .get(logical)
            .map(|id| Value::String(id.clone()))
            .ok_or(MaterializerError::MissingClientMapping),
        "client_secret" => Ok(Value::String(client.client_secret.to_string())),
        "rsa.private_jwks" => json_value(&client.rsa_private_jwks),
        "rsa.public_jwks" => json_value(&client.rsa_public_jwks),
        "ec.private_jwks" => json_value(&client.ec_private_jwks),
        "ec.public_jwks" => json_value(&client.ec_public_jwks),
        "mtls.ca_cert" => Ok(Value::String(client.mtls_ca_certificate.to_string())),
        "mtls.client_cert" => Ok(Value::String(client.mtls_client_certificate.to_string())),
        "mtls.client_key" => Ok(Value::String(client.mtls_client_key.to_string())),
        "mtls.cert_sha256" => Ok(Value::String(client.mtls_client_certificate_sha256.clone())),
        _ => Err(MaterializerError::UnknownSecretReference(field.to_owned())),
    }
}

fn json_value(value: &Zeroizing<String>) -> Result<Value, MaterializerError> {
    serde_json::from_str(value.as_str()).map_err(|_| MaterializerError::Encoding)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn materialize_registration_template(
    value: &Value,
    logical_client_id: &str,
    target_issuer: &str,
    suite_origin: &str,
    rsa_public_jwks: &str,
    ec_public_jwks: &str,
    mtls_ca_certificate: &str,
    mtls_client_certificate: &str,
    mtls_client_certificate_sha256: &str,
    request_jti: &str,
) -> Result<Value, MaterializerError> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                materialize_registration_template(
                    value,
                    logical_client_id,
                    target_issuer,
                    suite_origin,
                    rsa_public_jwks,
                    ec_public_jwks,
                    mtls_ca_certificate,
                    mtls_client_certificate,
                    mtls_client_certificate_sha256,
                    request_jti,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut output = serde_json::Map::new();
            for (key, child) in values {
                output.insert(
                    key.clone(),
                    materialize_registration_template(
                        child,
                        logical_client_id,
                        target_issuer,
                        suite_origin,
                        rsa_public_jwks,
                        ec_public_jwks,
                        mtls_ca_certificate,
                        mtls_client_certificate,
                        mtls_client_certificate_sha256,
                        request_jti,
                    )?,
                );
            }
            Ok(Value::Object(output))
        }
        Value::String(text) if is_placeholder(text) => {
            let name = parse_placeholder(text)?;
            let value = match name {
                "target.issuer" => Value::String(target_issuer.to_owned()),
                "target.suite" | "suite.origin" => Value::String(suite_origin.to_owned()),
                "target.host" => Value::String(target_host(target_issuer)?),
                name if name.starts_with("target.url.") => Value::String(resolve_target_url(
                    target_issuer,
                    name.trim_start_matches("target.url."),
                    false,
                )?),
                name if name.starts_with("target.pattern.") => Value::String(resolve_target_url(
                    target_issuer,
                    name.trim_start_matches("target.pattern."),
                    true,
                )?),
                name if name.starts_with("run.alias.") => Value::String(resolve_run_alias(
                    request_jti,
                    name.trim_start_matches("run.alias."),
                )?),
                name if name.starts_with("suite.test.") => Value::String(resolve_suite_test_url(
                    suite_origin,
                    request_jti,
                    name.trim_start_matches("suite.test."),
                )?),
                name if name.starts_with("suite.test_query.") => Value::String(format!(
                    "{}?dummy1=lorem&dummy2=ipsum",
                    resolve_suite_test_url(
                        suite_origin,
                        request_jti,
                        name.trim_start_matches("suite.test_query."),
                    )?
                )),
                "client.id" | "onboarding.client_id" => {
                    return Err(MaterializerError::InvalidField(
                        "registration_template.client_id",
                    ));
                }
                "client.rsa.public_jwks" | "generated.rsa.public_jwks" => {
                    serde_json::from_str(rsa_public_jwks)
                        .map_err(|_| MaterializerError::Encoding)?
                }
                "client.ec.public_jwks" | "generated.ec.public_jwks" => {
                    serde_json::from_str(ec_public_jwks).map_err(|_| MaterializerError::Encoding)?
                }
                "client.mtls.ca_cert" | "generated.mtls.ca_cert" => {
                    Value::String(mtls_ca_certificate.to_owned())
                }
                "client.mtls.client_cert" | "generated.mtls.client_cert" => {
                    Value::String(mtls_client_certificate.to_owned())
                }
                "client.mtls.cert_sha256" | "generated.mtls.cert_sha256" => {
                    Value::String(mtls_client_certificate_sha256.to_owned())
                }
                name if name.starts_with("client.") => {
                    let prefix = format!("client.{logical_client_id}.");
                    if !name.starts_with(&prefix) {
                        return Err(MaterializerError::UnknownClientReference(name.to_owned()));
                    }
                    match name.strip_prefix(&prefix) {
                        Some("rsa.public_jwks") => serde_json::from_str(rsa_public_jwks)
                            .map_err(|_| MaterializerError::Encoding)?,
                        Some("ec.public_jwks") => serde_json::from_str(ec_public_jwks)
                            .map_err(|_| MaterializerError::Encoding)?,
                        Some("mtls.ca_cert") => Value::String(mtls_ca_certificate.to_owned()),
                        Some("mtls.client_cert") => {
                            Value::String(mtls_client_certificate.to_owned())
                        }
                        Some("mtls.cert_sha256") => {
                            Value::String(mtls_client_certificate_sha256.to_owned())
                        }
                        _ => {
                            return Err(MaterializerError::UnknownSecretReference(name.to_owned()));
                        }
                    }
                }
                _ => return Err(MaterializerError::UnknownSecretReference(name.to_owned())),
            };
            Ok(value)
        }
        Value::String(text)
            if text.contains("{{") || text.contains("}}") || text.contains("${") =>
        {
            Err(MaterializerError::InvalidPlaceholder)
        }
        _ => Ok(value.clone()),
    }
}

pub(super) fn validate_target_issuer(value: &str) -> Result<(), MaterializerError> {
    let parsed = Url::parse(value.trim()).map_err(|_| MaterializerError::UnsafeIssuer)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
        || parsed.path().contains("//")
        || parsed.path().split('/').any(|part| part == "..")
    {
        return Err(MaterializerError::UnsafeIssuer);
    }
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() != "http" {
        return Err(MaterializerError::UnsafeIssuer);
    }
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    if matches!(host, "localhost" | "localhost.localdomain")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        Ok(())
    } else {
        Err(MaterializerError::UnsafeIssuer)
    }
}

fn target_host(target_issuer: &str) -> Result<String, MaterializerError> {
    Url::parse(target_issuer)
        .map_err(|_| MaterializerError::UnsafeIssuer)?
        .host_str()
        .map(str::to_owned)
        .ok_or(MaterializerError::UnsafeIssuer)
}

fn resolve_target_url(
    target_issuer: &str,
    suffix: &str,
    allow_trailing_wildcard: bool,
) -> Result<String, MaterializerError> {
    let (path, wildcard) = if allow_trailing_wildcard && suffix.ends_with('*') {
        (&suffix[..suffix.len() - 1], true)
    } else {
        (suffix, false)
    };
    if !path.starts_with('/')
        || path.len() > 512
        || path.contains(['?', '#', '\\', '{', '}'])
        || path.contains("//")
        || path.split('/').any(|segment| segment == "..")
        || (!allow_trailing_wildcard && suffix.contains('*'))
        || (allow_trailing_wildcard && suffix.trim_end_matches('*').contains('*'))
    {
        return Err(MaterializerError::InvalidPlaceholder);
    }
    let result = format!("{}{}", target_issuer.trim_end_matches('/'), path);
    Url::parse(&result).map_err(|_| MaterializerError::UnsafeIssuer)?;
    Ok(if wildcard {
        format!("{result}*")
    } else {
        result
    })
}

fn validate_url_segment(value: &str) -> Result<(), MaterializerError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MaterializerError::InvalidPlaceholder);
    }
    Ok(())
}

fn resolve_run_alias(request_jti: &str, alias_key: &str) -> Result<String, MaterializerError> {
    validate_url_segment(alias_key)?;
    validate_request_jti(request_jti)?;
    let suffix = request_jti
        .strip_prefix("request-")
        .ok_or(MaterializerError::InvalidPlaceholder)?;
    Ok(format!("nazo-{suffix}-{alias_key}"))
}

fn resolve_suite_test_url(
    suite_origin: &str,
    request_jti: &str,
    reference: &str,
) -> Result<String, MaterializerError> {
    let (alias_key, endpoint) = reference
        .split_once('.')
        .ok_or(MaterializerError::InvalidPlaceholder)?;
    validate_url_segment(endpoint)?;
    let alias = resolve_run_alias(request_jti, alias_key)?;
    Ok(format!(
        "{}/test/a/{alias}/{endpoint}",
        suite_origin.trim_end_matches('/')
    ))
}
