use super::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardsFullProfileMaterial {
    #[serde(default)]
    client_attestation_issuer: Option<String>,
    #[serde(default)]
    client_attestation_jwks: Option<serde_json::Value>,
    #[serde(default)]
    key_attestation_jwks: Option<serde_json::Value>,
    credential_configurations: serde_json::Value,
    wallet_authorization_origins: Vec<String>,
    ciba_notification_private_origins: Vec<String>,
    backchannel_logout_private_origins: Vec<String>,
}

pub(super) fn write_install_profile(
    config_dir: &Path,
    options: &InstallOptions,
) -> anyhow::Result<Option<String>> {
    if options.profile == "baseline" {
        return Ok(None);
    }
    let source = options
        .profile_material
        .as_deref()
        .context("standards-full profile material is unavailable")?;
    safe_absolute(source)?;
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect profile material {}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 * 1024 {
        bail!("profile material must be a regular file no larger than 256 KiB");
    }
    let material: StandardsFullProfileMaterial = serde_json::from_slice(&fs::read(source)?)
        .context("standards-full profile material must be strict JSON")?;
    match (
        &material.client_attestation_issuer,
        &material.client_attestation_jwks,
    ) {
        (Some(issuer), Some(jwks)) => {
            validate_https_origin(issuer, "client attestation issuer")?;
            validate_public_jwks(jwks, "client attestation JWKS")?;
        }
        (None, None) => {}
        _ => bail!("client attestation issuer and JWKS must be supplied together"),
    }
    if let Some(jwks) = &material.key_attestation_jwks {
        validate_public_jwks(jwks, "key attestation JWKS")?;
    }
    let credential_configurations = material
        .credential_configurations
        .as_object()
        .filter(|value| !value.is_empty())
        .context("credential configurations must be a non-empty object")?;
    if credential_configurations
        .keys()
        .any(|key| key.trim().is_empty())
    {
        bail!("credential configuration identifiers must not be empty");
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
    let secrets = config_dir.join("secrets");
    let provided = options.profile_secrets.as_ref();
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
    if !encryption_key_path.exists() {
        let value = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        atomic_write(&encryption_key_path, value.as_bytes(), 0o440)?;
    }
    let encryption_key = fs::read_to_string(&encryption_key_path)?;
    if encryption_key.contains(['\n', '\r'])
        || URL_SAFE_NO_PAD
            .decode(&encryption_key)
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
        "MTLS_CERTIFICATE_SOURCE: \"legacy-verified-headers\"".to_owned(),
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/dynamic-registration-token\"".to_owned(),
        "OPENID4VC_DATA_ENCRYPTION_KEY_FILE: \"${PROFILE_SECRET_ROOT}/openid4vc-data-encryption-key\"".to_owned(),
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vci-management-token\"".to_owned(),
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vp-management-token\"".to_owned(),
        "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
        "OPENID4VC_TRUST_ANCHORS_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-certificate-bundle.pem\"".to_owned(),
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
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to inspect persisted profile secret {name}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("persisted profile secret {name} is not a regular file");
            }
            let persisted = zeroize::Zeroizing::new(
                fs::read_to_string(path)
                    .with_context(|| format!("failed to read persisted profile secret {name}"))?,
            );
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

    let generated_or_persisted = zeroize::Zeroizing::new(generate_secret(path)?);
    validate_profile_secret_value(name, &generated_or_persisted)
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

pub(super) fn host_cidr(address: std::net::IpAddr) -> String {
    match address {
        std::net::IpAddr::V4(address) => format!("{address}/32"),
        std::net::IpAddr::V6(address) => format!("{address}/128"),
    }
}
