use super::MaterializerError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

pub(super) const MTLS_CLIENT_SAN_DNS: &str = "nazoauthctl-client";

pub(super) struct GeneratedClientCrypto {
    pub(super) client_secret: Zeroizing<String>,
    pub(super) rsa_private_jwk: Zeroizing<String>,
    pub(super) rsa_public_jwks: Zeroizing<String>,
    pub(super) ec_private_jwk: Zeroizing<String>,
    pub(super) ec_public_jwks: Zeroizing<String>,
    pub(super) mtls_ca_certificate: Zeroizing<String>,
    pub(super) mtls_client_certificate: Zeroizing<String>,
    pub(super) mtls_client_key: Zeroizing<String>,
    pub(super) mtls_client_certificate_sha256: String,
}

pub(super) fn generate_client_crypto(
    policy: &super::CryptoPolicy,
) -> Result<GeneratedClientCrypto, MaterializerError> {
    let client_secret = Zeroizing::new(random_secret(32));
    let mut rng = OsRng;
    let rsa = RsaPrivateKey::new(&mut rng, policy.rsa_bits as usize)
        .map_err(|_| MaterializerError::Crypto)?;
    let (rsa_private_jwk, rsa_public_jwks) = rsa_jwks(&rsa)?;
    let ec = SigningKey::random(&mut rng);
    let (ec_private_jwk, ec_public_jwks) = ec_jwks(&ec)?;
    let (
        mtls_ca_certificate,
        mtls_client_certificate,
        mtls_client_key,
        mtls_client_certificate_sha256,
    ) = generate_mtls()?;
    Ok(GeneratedClientCrypto {
        client_secret,
        rsa_private_jwk: Zeroizing::new(rsa_private_jwk),
        rsa_public_jwks: Zeroizing::new(rsa_public_jwks),
        ec_private_jwk: Zeroizing::new(ec_private_jwk),
        ec_public_jwks: Zeroizing::new(ec_public_jwks),
        mtls_ca_certificate: Zeroizing::new(mtls_ca_certificate),
        mtls_client_certificate: Zeroizing::new(mtls_client_certificate),
        mtls_client_key: Zeroizing::new(mtls_client_key),
        mtls_client_certificate_sha256,
    })
}

pub(super) fn random_secret(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    let mut rng = OsRng;
    rng.fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

pub(super) fn random_hex(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    let mut rng = OsRng;
    rng.fill_bytes(&mut random);
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn rsa_jwks(key: &RsaPrivateKey) -> Result<(String, String), MaterializerError> {
    let public = serde_json::json!({
        "kty": "RSA", "n": b64(key.n().to_bytes_be()), "e": b64(key.e().to_bytes_be()),
        "alg": "PS256", "use": "sig", "key_ops": ["verify"]
    });
    let private = serde_json::json!({
        "kty": "RSA", "n": b64(key.n().to_bytes_be()), "e": b64(key.e().to_bytes_be()),
        "d": b64(key.d().to_bytes_be()),
        "p": b64(key.primes().first().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "q": b64(key.primes().get(1).ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "dp": b64(key.dp().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "dq": b64(key.dq().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "qi": b64(key.qinv().and_then(|value| value.to_biguint()).ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "alg": "PS256", "use": "sig", "key_ops": ["sign"]
    });
    let private_string =
        serde_json::to_string(&private).map_err(|_| MaterializerError::Encoding)?;
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((private_string, public_jwks))
}

pub(super) fn ec_jwks(key: &SigningKey) -> Result<(String, String), MaterializerError> {
    let encoded = key.verifying_key().to_encoded_point(false);
    let x = encoded.x().ok_or(MaterializerError::Crypto)?;
    let y = encoded.y().ok_or(MaterializerError::Crypto)?;
    let mut digest = Sha256::new();
    digest.update(x);
    digest.update(y);
    let kid = URL_SAFE_NO_PAD.encode(&digest.finalize()[..8]);
    let public = serde_json::json!({
        "kty":"EC", "crv":"P-256", "x":b64(x), "y":b64(y), "kid":kid,
        "alg":"ES256", "use":"sig", "key_ops":["verify"]
    });
    let private = serde_json::json!({
        "kty":"EC", "crv":"P-256", "x":b64(x), "y":b64(y), "d":b64(key.to_bytes()), "kid":kid,
        "alg":"ES256", "use":"sig", "key_ops":["sign"]
    });
    let private_string =
        serde_json::to_string(&private).map_err(|_| MaterializerError::Encoding)?;
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((private_string, public_jwks))
}

pub(super) fn generate_mtls() -> Result<(String, String, String, String), MaterializerError> {
    let now = OffsetDateTime::now_utc();
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    ca_params.not_before = now - TimeDuration::days(1);
    ca_params.not_after = now + TimeDuration::days(365);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().map_err(|_| MaterializerError::Crypto)?;
    let ca =
        CertifiedIssuer::self_signed(ca_params, ca_key).map_err(|_| MaterializerError::Crypto)?;
    let mut client_params = CertificateParams::new(vec![MTLS_CLIENT_SAN_DNS.to_owned()])
        .map_err(|_| MaterializerError::Crypto)?;
    client_params.not_before = now - TimeDuration::days(1);
    client_params.not_after = now + TimeDuration::days(365);
    client_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().map_err(|_| MaterializerError::Crypto)?;
    let client = client_params
        .signed_by(&client_key, &ca)
        .map_err(|_| MaterializerError::Crypto)?;
    let certificate_sha256 = digest_hex(client.der().as_ref());
    Ok((
        ca.pem(),
        client.pem(),
        client_key.serialize_pem(),
        certificate_sha256,
    ))
}

pub(super) fn b64<T: AsRef<[u8]>>(value: T) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub(super) fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn validate_materialized_mtls_registration(
    request: &Value,
    generated_certificate_sha256: &str,
) -> Result<(), MaterializerError> {
    if request
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        != Some("tls_client_auth")
    {
        return Ok(());
    }
    let expected_dns = [Value::String(MTLS_CLIENT_SAN_DNS.to_owned())];
    let dns_matches = request
        .get("tls_client_auth_san_dns")
        .and_then(Value::as_array)
        .is_some_and(|values| values.as_slice() == expected_dns);
    let other_selectors_absent = request
        .get("tls_client_auth_subject_dn")
        .is_none_or(Value::is_null)
        && [
            "tls_client_auth_san_uri",
            "tls_client_auth_san_ip",
            "tls_client_auth_san_email",
        ]
        .iter()
        .all(|field| {
            request
                .get(*field)
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        });
    let digest_matches = request
        .get("tls_client_auth_cert_sha256")
        .and_then(Value::as_str)
        == Some(generated_certificate_sha256);
    if !dns_matches || !other_selectors_absent || !digest_matches {
        return Err(MaterializerError::InvalidField(
            "registration_template.mtls_identity",
        ));
    }
    Ok(())
}

pub(super) fn registration_requires_mtls(request: &Value) -> bool {
    request
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .is_some_and(|method| matches!(method, "tls_client_auth" | "self_signed_tls_client_auth"))
        || request
            .get("require_mtls_bound_tokens")
            .and_then(Value::as_bool)
            == Some(true)
        || ["tls_client_auth_subject_dn", "tls_client_auth_cert_sha256"]
            .iter()
            .any(|field| {
                request
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            })
        || [
            "tls_client_auth_san_dns",
            "tls_client_auth_san_uri",
            "tls_client_auth_san_ip",
            "tls_client_auth_san_email",
        ]
        .iter()
        .any(|field| {
            request
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty())
        })
}
