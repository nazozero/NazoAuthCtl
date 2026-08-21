use super::*;
use std::collections::BTreeMap;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StandardsFullProfileMaterial {
    #[serde(default)]
    client_attestation_issuer: Option<String>,
    #[serde(default)]
    client_attestation_jwks: Option<serde_json::Value>,
    #[serde(default)]
    key_attestation_jwks: Option<serde_json::Value>,
    credential_configurations: BTreeMap<String, CredentialConfiguration>,
    wallet_authorization_origins: Vec<String>,
    ciba_notification_private_origins: Vec<String>,
    backchannel_logout_private_origins: Vec<String>,
}

// This is deliberately the exact input contract accepted by NazoAuth
// 45959681's `nazo_openid4vci::CredentialConfiguration`.  Ctl must reject an
// invalid profile before it creates a controller identity, config file, or
// managed dependency; otherwise an ordinary server startup error strands a
// fresh candidate deployment.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialConfiguration {
    format: CredentialFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cryptographic_binding_methods_supported: Vec<String>,
    credential_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    proof_types_supported: BTreeMap<String, ProofTypeMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vct: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    doctype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_metadata: Option<CredentialMetadata>,
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialFormat {
    #[serde(rename = "dc+sd-jwt")]
    SdJwtVc,
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ProofTypeMetadata {
    proof_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_attestations_required: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    display: Vec<CredentialDisplay>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDisplay {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logo: Option<Logo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    background_image: Option<Logo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text_color: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Logo {
    uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alt_text: Option<String>,
}

pub(super) fn load_and_validate_install_profile(
    options: &InstallOptions,
) -> anyhow::Result<Option<StandardsFullProfileMaterial>> {
    if options.profile == "baseline" {
        return Ok(None);
    }
    let source = options
        .profile_material
        .as_deref()
        .context("standards-full profile material is unavailable")?;
    safe_absolute(source)?;
    let material_bytes = crate::filesystem::read_secure_regular_file(
        source,
        "standards-full profile material",
        false,
        256 * 1024,
    )?;
    let material: StandardsFullProfileMaterial = serde_json::from_slice(&material_bytes)
        .context("standards-full profile material must be strict JSON")?;
    validate_standards_full_profile_material(&material)?;
    Ok(Some(material))
}

#[cfg(test)]
pub(super) fn write_install_profile(
    config_dir: &Path,
    options: &InstallOptions,
) -> anyhow::Result<Option<String>> {
    let material = load_and_validate_install_profile(options)?;
    write_prevalidated_install_profile(config_dir, options, material.as_ref())
}

pub(super) fn write_prevalidated_install_profile(
    config_dir: &Path,
    options: &InstallOptions,
    material: Option<&StandardsFullProfileMaterial>,
) -> anyhow::Result<Option<String>> {
    if options.profile == "baseline" {
        if material.is_some() {
            bail!("baseline profile must not receive standards-full profile material");
        }
        return Ok(None);
    }
    let material = material.context("standards-full profile material is unavailable")?;
    validate_standards_full_profile_material(material)?;
    write_profile_secrets_and_render(config_dir, options, material)
}

fn validate_standards_full_profile_material(
    material: &StandardsFullProfileMaterial,
) -> anyhow::Result<()> {
    match (
        &material.client_attestation_issuer,
        &material.client_attestation_jwks,
    ) {
        (Some(issuer), Some(jwks)) => {
            validate_https_origin(issuer, "client attestation issuer")?;
            validate_attestation_jwks(
                jwks,
                "client attestation JWKS",
                AttestationJwkPurpose::Client,
            )?;
        }
        (None, None) => {}
        _ => bail!("client attestation issuer and JWKS must be supplied together"),
    }
    if let Some(jwks) = &material.key_attestation_jwks {
        validate_attestation_jwks(
            jwks,
            "key attestation JWKS",
            AttestationJwkPurpose::HolderKey,
        )?;
    }
    if material.credential_configurations.is_empty() {
        bail!("credential configurations must be a non-empty object");
    }
    if material
        .credential_configurations
        .keys()
        .any(|key| key.trim().is_empty())
    {
        bail!("credential configuration identifiers must not be empty");
    }
    for configuration in material.credential_configurations.values() {
        validate_credential_configuration(configuration)?;
    }
    for (name, origins) in [
        (
            "wallet authorization",
            &material.wallet_authorization_origins,
        ),
        (
            "CIBA notification",
            &material.ciba_notification_private_origins,
        ),
        (
            "back-channel logout",
            &material.backchannel_logout_private_origins,
        ),
    ] {
        if origins.is_empty() {
            bail!("{name} origins must not be empty");
        }
        for origin in origins {
            validate_https_origin(origin, &format!("{name} origin"))?;
        }
    }
    Ok(())
}

fn validate_credential_configuration(
    configuration: &CredentialConfiguration,
) -> anyhow::Result<()> {
    let binding_declared = !configuration
        .cryptographic_binding_methods_supported
        .is_empty();
    let proofs_declared = !configuration.proof_types_supported.is_empty();
    if configuration
        .credential_signing_alg_values_supported
        .as_slice()
        != ["ES256"]
        || binding_declared != proofs_declared
        || configuration
            .cryptographic_binding_methods_supported
            .iter()
            .any(|method| method != "jwk")
        || configuration
            .proof_types_supported
            .iter()
            .any(|(proof_type, proof)| {
                !matches!(proof_type.as_str(), "jwt" | "attestation")
                    || proof.proof_signing_alg_values_supported.is_empty()
                    || proof
                        .proof_signing_alg_values_supported
                        .iter()
                        .any(|algorithm| !matches!(algorithm.as_str(), "ES256" | "EdDSA"))
            })
    {
        bail!("credential configuration algorithm or proof metadata is unsupported");
    }
    match configuration.format {
        CredentialFormat::SdJwtVc
            if configuration.vct.as_deref().unwrap_or_default().is_empty() =>
        {
            bail!("dc+sd-jwt credential configuration requires a non-empty vct")
        }
        CredentialFormat::MsoMdoc
            if configuration
                .doctype
                .as_deref()
                .unwrap_or_default()
                .is_empty() =>
        {
            bail!("mso_mdoc credential configuration requires a non-empty doctype")
        }
        CredentialFormat::MsoMdoc if !binding_declared => {
            bail!("mso_mdoc credential configuration requires binding and proof metadata")
        }
        _ if configuration.scope.as_deref().is_some_and(|scope| {
            scope.is_empty()
                || scope
                    .bytes()
                    .any(|byte| byte <= b' ' || byte == b'"' || byte == b'\\')
        }) =>
        {
            bail!("credential configuration scope is invalid")
        }
        _ => Ok(()),
    }
}

fn write_profile_secrets_and_render(
    config_dir: &Path,
    options: &InstallOptions,
    material: &StandardsFullProfileMaterial,
) -> anyhow::Result<Option<String>> {
    let secrets = config_dir.join("secrets");
    let provided = options.profile_secrets.as_ref();
    if let Some(provided) = provided {
        validate_explicit_profile_secrets(provided)?;
    }
    write_or_verify_profile_secret(
        &secrets.join("dynamic-registration-token"),
        "dynamic_registration_initial_access_token",
        provided.map(|secrets| secrets.dynamic_registration_initial_access_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("ciba-decision-token"),
        "ciba_automated_decision_token",
        provided.map(|secrets| secrets.ciba_automated_decision_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("openid4vci-management-token"),
        "openid4vci_management_token",
        provided.map(|secrets| secrets.openid4vci_management_token.as_str()),
    )?;
    write_or_verify_profile_secret(
        &secrets.join("openid4vp-management-token"),
        "openid4vp_management_token",
        provided.map(|secrets| secrets.openid4vp_management_token.as_str()),
    )?;
    let encryption_key_path = secrets.join("openid4vc-data-encryption-key");
    let encryption_key =
        load_or_create_profile_secret(&encryption_key_path, "OpenID4VC data encryption key", 4096)?;
    if encryption_key.contains(['\n', '\r'])
        || URL_SAFE_NO_PAD
            .decode(encryption_key.as_bytes())
            .ok()
            .is_none_or(|decoded| decoded.len() != 32)
    {
        bail!("persisted OpenID4VC data encryption key is invalid");
    }

    let scalar = |value: &str| serde_json::to_string(value).expect("serialize YAML scalar");
    let mut lines = vec![
        "ENABLE_AUTHORIZATION_DETAILS: true".to_owned(),
        "ENABLE_NATIVE_SSO: true".to_owned(),
        "ENABLE_OPENID4VCI_ISSUER: true".to_owned(),
        "ENABLE_OPENID4VP_VERIFIER: true".to_owned(),
        format!(
            "MTLS_ENDPOINT_BASE_URL: {}",
            scalar(options.public_url.trim_end_matches('/'))
        ),
        "TRUSTED_PROXY_CIDRS: \"${TRUSTED_PROXY_CIDR}\"".to_owned(),
        "MTLS_CERTIFICATE_SOURCE: \"rfc9440\"".to_owned(),
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/dynamic-registration-token\"".to_owned(),
        "OPENID4VC_DATA_ENCRYPTION_KEY_FILE: \"${PROFILE_SECRET_ROOT}/openid4vc-data-encryption-key\"".to_owned(),
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vci-management-token\"".to_owned(),
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vp-management-token\"".to_owned(),
        "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
        "OPENID4VC_TRUST_ANCHORS_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
        "OPENID4VC_REVOCATION_POLICY: \"required\"".to_owned(),
        "OPENID4VC_REVOCATION_SNAPSHOT_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-revocation-snapshot.json\"".to_owned(),
    ];
    if let (Some(issuer), Some(jwks)) = (
        &material.client_attestation_issuer,
        &material.client_attestation_jwks,
    ) {
        lines.push(format!(
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER: {}",
            scalar(issuer)
        ));
        lines.push(format!(
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(jwks)?)
        ));
    }
    if let Some(jwks) = &material.key_attestation_jwks {
        lines.push(format!(
            "OPENID4VC_KEY_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(jwks)?)
        ));
    }
    lines.extend([
        format!(
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON: {}",
            scalar(&serde_json::to_string(&material.credential_configurations)?)
        ),
        format!(
            "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS: {}",
            scalar(&material.wallet_authorization_origins.join(","))
        ),
        format!(
            "CIBA_NOTIFICATION_PRIVATE_ORIGINS: {}",
            scalar(&material.ciba_notification_private_origins.join(","))
        ),
        format!(
            "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS: {}",
            scalar(&material.backchannel_logout_private_origins.join(","))
        ),
    ]);
    Ok(Some(format!("{}\n", lines.join("\n"))))
}

pub(super) fn write_or_verify_profile_secret(
    path: &Path,
    name: &str,
    provided: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(value) = provided {
        validate_profile_secret_value(name, value)?;
        if path.exists() {
            let persisted = load_profile_secret(path, name, MAX_PROFILE_SECRET_VALUE_BYTES)?;
            validate_profile_secret_value(name, &persisted)?;
            if persisted.as_str() != value {
                bail!(
                    "provided profile secret {name} does not match the persisted installation state"
                );
            }
        } else {
            atomic_write(path, value.as_bytes(), 0o440)?;
        }
        return Ok(());
    }

    let generated_or_persisted =
        load_or_create_profile_secret(path, name, MAX_PROFILE_SECRET_VALUE_BYTES as u64)?;
    validate_profile_secret_value(name, &generated_or_persisted)
}
pub(super) fn load_profile_secret(
    path: &Path,
    name: &str,
    max_bytes: usize,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let bytes = crate::filesystem::read_secure_secret_file(
        path,
        &format!("persisted profile secret {name}"),
        max_bytes as u64,
    )?;
    let value = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("persisted profile secret {name} is not UTF-8"))?;
    Ok(zeroize::Zeroizing::new(value))
}

fn load_or_create_profile_secret(
    path: &Path,
    name: &str,
    max_bytes: u64,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_profile_secret(path, name, max_bytes as usize),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let generated =
                zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
            atomic_write(path, generated.as_bytes(), 0o440)?;
            load_profile_secret(path, name, max_bytes as usize)
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect persisted profile secret {name}"))
        }
    }
}

pub(super) fn validate_https_origin(value: &str, label: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("invalid {label}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("{label} must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}
pub(super) fn validate_public_jwks(value: &serde_json::Value, label: &str) -> anyhow::Result<()> {
    let keys = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .with_context(|| format!("{label} must contain a non-empty keys array"))?;
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if keys.iter().any(|key| {
        key.as_object().is_none_or(|object| {
            PRIVATE_MEMBERS
                .iter()
                .any(|name| object.contains_key(*name))
        })
    }) {
        bail!("{label} must contain public asymmetric keys only");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AttestationJwkPurpose {
    Client,
    HolderKey,
}

fn validate_attestation_jwks(
    value: &serde_json::Value,
    label: &str,
    purpose: AttestationJwkPurpose,
) -> anyhow::Result<()> {
    validate_public_jwks(value, label)?;
    let keys = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .expect("validate_public_jwks verified a non-empty keys array");
    let mut key_ids = std::collections::BTreeSet::new();
    for key in keys {
        let object = key
            .as_object()
            .expect("validate_public_jwks verified JWK objects");
        let kid = object
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|kid| !kid.is_empty())
            .context("attestation JWK keys must have a non-empty kid")?;
        if !key_ids.insert(kid) {
            bail!("{label} must not contain duplicate kid values");
        }
        let has_x = object.get("x").is_some_and(serde_json::Value::is_string);
        let has_y = object.get("y").is_some_and(serde_json::Value::is_string);
        let supported = match (
            purpose,
            object.get("kty").and_then(serde_json::Value::as_str),
            object.get("crv").and_then(serde_json::Value::as_str),
        ) {
            (AttestationJwkPurpose::Client, Some("EC"), Some("P-256")) => has_x && has_y,
            (AttestationJwkPurpose::HolderKey, Some("EC"), Some("P-256")) => has_x && has_y,
            (AttestationJwkPurpose::HolderKey, Some("OKP"), Some("Ed25519")) => has_x,
            _ => false,
        };
        if !supported {
            let purpose = match purpose {
                AttestationJwkPurpose::Client => "client attestation",
                AttestationJwkPurpose::HolderKey => "holder key attestation",
            };
            bail!("{label} contains a key unsupported for {purpose}");
        }
    }
    Ok(())
}
