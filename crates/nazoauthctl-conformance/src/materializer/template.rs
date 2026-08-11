use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::{
    MaterializerError, OnboardingOutput, PreparedMaterialization, digest_hex, is_placeholder,
    parse_placeholder, validate_binding_reference, validate_request_jti,
};

pub(super) fn materialize_value(
    value: &Value,
    bindings: &BTreeMap<String, String>,
    prepared: &PreparedMaterialization,
    onboarding: &OnboardingOutput,
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

fn resolve_reference(
    name: &str,
    bindings: &BTreeMap<String, String>,
    prepared: &PreparedMaterialization,
    onboarding: &OnboardingOutput,
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
    if name == "target.ciba_automated_decision_url" {
        let token = prepared
            .ciba_automated_decision_token
            .as_ref()
            .ok_or_else(|| MaterializerError::UnknownSecretReference(name.to_owned()))?;
        return Ok(Value::String(format!(
            "{}/auth/ciba-automated-decision?token={{auth_req_id}}&type={{action}}&decision_token={}",
            prepared.target_issuer.trim_end_matches('/'),
            token.as_str()
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
    if name == "deployment.dynamic_registration_initial_access_token" {
        return prepared
            .dynamic_registration_initial_access_token
            .as_ref()
            .map(|value| Value::String(value.to_string()))
            .ok_or(MaterializerError::UnknownSecretReference(name.to_owned()));
    }
    if name == "deployment.ciba_automated_decision_token" {
        return prepared
            .ciba_automated_decision_token
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
        "rsa.private_jwk" => json_value(&client.rsa_private_jwk),
        "rsa.public_jwks" => json_value(&client.rsa_public_jwks),
        "ec.private_jwk" => json_value(&client.ec_private_jwk),
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
