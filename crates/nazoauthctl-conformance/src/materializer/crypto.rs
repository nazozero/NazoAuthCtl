use super::MaterializerError;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

pub(super) const MTLS_CLIENT_SAN_DNS: &str = "nazoauthctl-client";

pub(super) struct GeneratedClientCrypto {
    pub(super) client_secret: Zeroizing<String>,
    pub(super) rsa_private_jwks: Zeroizing<String>,
    pub(super) rsa_public_jwks: Zeroizing<String>,
    pub(super) ec_private_jwks: Zeroizing<String>,
    pub(super) ec_public_jwks: Zeroizing<String>,
    pub(super) mtls_ca_certificate: Zeroizing<String>,
    pub(super) mtls_client_certificate: Zeroizing<String>,
    pub(super) mtls_client_key: Zeroizing<String>,
    pub(super) mtls_client_certificate_sha256: String,
}

/// Run-scoped OpenID4VC proof and HAIP attestation material.  Every VCI plan
/// receives the proof key because the Suite may select an attestation proof;
/// HAIP plans additionally consume the attester identity and trust anchor.
/// Private JWKs remain only in the prepared Suite configuration and are
/// zeroized with the preparation state.
pub(super) struct GeneratedAttestationMaterial {
    pub(super) trust_anchor_pem: Zeroizing<String>,
    pub(super) attester_private_jwks: Zeroizing<String>,
    pub(super) attester_public_jwks: Zeroizing<String>,
    pub(super) key_attestation_private_jwks: Zeroizing<String>,
    pub(super) key_attestation_public_jwks: Zeroizing<String>,
    pub(super) credential_signing_private_jwk: Zeroizing<String>,
}

impl Zeroize for GeneratedAttestationMaterial {
    fn zeroize(&mut self) {
        self.trust_anchor_pem.zeroize();
        self.attester_private_jwks.zeroize();
        self.attester_public_jwks.zeroize();
        self.key_attestation_private_jwks.zeroize();
        self.key_attestation_public_jwks.zeroize();
        self.credential_signing_private_jwk.zeroize();
    }
}

pub(super) fn generate_client_crypto(
    policy: &super::CryptoPolicy,
) -> Result<GeneratedClientCrypto, MaterializerError> {
    let client_secret = Zeroizing::new(random_secret(32));
    let mut rng = OsRng;
    let rsa = RsaPrivateKey::new(&mut rng, policy.rsa_bits as usize)
        .map_err(|_| MaterializerError::Crypto)?;
    let (rsa_private_jwks, rsa_public_jwks) = rsa_jwks(&rsa)?;
    let ec = SigningKey::random(&mut rng);
    let (ec_private_jwks, ec_public_jwks) = ec_jwks(&ec)?;
    let (
        mtls_ca_certificate,
        mtls_client_certificate,
        mtls_client_key,
        mtls_client_certificate_sha256,
    ) = generate_mtls()?;
    Ok(GeneratedClientCrypto {
        client_secret,
        rsa_private_jwks: Zeroizing::new(rsa_private_jwks),
        rsa_public_jwks: Zeroizing::new(rsa_public_jwks),
        ec_private_jwks: Zeroizing::new(ec_private_jwks),
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

pub(super) fn random_tx_code() -> String {
    const RANGE: u32 = 1_000_000;
    let limit = u32::MAX - (u32::MAX % RANGE);
    let mut rng = OsRng;
    loop {
        let value = rng.next_u32();
        if value < limit {
            return format!("{:06}", value % RANGE);
        }
    }
}

/// Generate independent P-256 proof/attester identities for VCI and VCI-HAIP.
/// The key material comes from `OsRng`, then is wrapped in a run-local CA so
/// the Suite can validate x5c chains without deployment secrets.  No generated
/// private value is returned in the onboarding bundle.
pub(super) fn generate_attestation_material(
    suite_host: &str,
) -> Result<GeneratedAttestationMaterial, MaterializerError> {
    let now = OffsetDateTime::now_utc();
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    ca_params.not_before = now - TimeDuration::days(1);
    ca_params.not_after = now + TimeDuration::days(2);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut rng = OsRng;
    let ca_key = p256::ecdsa::SigningKey::random(&mut rng);
    let ca_key_der = Zeroizing::new(ec_pkcs8_der(&ca_key));
    let ca_key_pair =
        KeyPair::try_from(ca_key_der.as_slice()).map_err(|_| MaterializerError::Crypto)?;
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key_pair)
        .map_err(|_| MaterializerError::Crypto)?;
    let trust_anchor_pem = Zeroizing::new(ca.pem().replace("\r\n", "\n"));

    let (attester_private_jwks, attester_public_jwks) =
        generate_attestation_leaf(&ca, "NazoAuth client attestation")?;
    let (key_attestation_private_jwks, key_attestation_public_jwks) =
        generate_attestation_leaf(&ca, "NazoAuth key attestation")?;
    let credential_signing_private_jwk = generate_credential_signing_leaf(&ca, suite_host)?;
    Ok(GeneratedAttestationMaterial {
        trust_anchor_pem,
        attester_private_jwks,
        attester_public_jwks,
        key_attestation_private_jwks,
        key_attestation_public_jwks,
        credential_signing_private_jwk,
    })
}

fn generate_attestation_leaf<'a>(
    ca: &CertifiedIssuer<'a, KeyPair>,
    common_name: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>), MaterializerError> {
    let mut rng = OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let key_der = Zeroizing::new(ec_pkcs8_der(&signing_key));
    let key_pair = KeyPair::try_from(key_der.as_slice()).map_err(|_| MaterializerError::Crypto)?;
    let now = OffsetDateTime::now_utc();
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(2);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name.to_owned());
    let certificate = params
        .signed_by(&key_pair, ca)
        .map_err(|_| MaterializerError::Crypto)?;
    let encoded_certificate = STANDARD.encode(certificate.der().as_ref());
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().ok_or(MaterializerError::Crypto)?);
    let y = URL_SAFE_NO_PAD.encode(point.y().ok_or(MaterializerError::Crypto)?);
    let d = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let kid = format!("nazo-openid4vc-attestation-{}", random_hex(8));
    let public = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x": x,
        "y": y,
        "x5c": [encoded_certificate]
    });
    let private = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x": x,
        "y": y,
        "d": d,
        "x5c": [encoded_certificate]
    });
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    let private_jwks = serde_json::to_string(&serde_json::json!({"keys": [private]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((Zeroizing::new(private_jwks), Zeroizing::new(public_jwks)))
}

/// Generate the Suite-side credential issuer identity for one conformance
/// run. This key is independent from client/key attestation identities and is
/// returned as a single private JWK because that is the Suite's exact wire
/// contract. It never enters the onboarding bundle.
fn generate_credential_signing_leaf<'a>(
    ca: &CertifiedIssuer<'a, KeyPair>,
    suite_host: &str,
) -> Result<Zeroizing<String>, MaterializerError> {
    let mut rng = OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let key_der = Zeroizing::new(ec_pkcs8_der(&signing_key));
    let key_pair = KeyPair::try_from(key_der.as_slice()).map_err(|_| MaterializerError::Crypto)?;
    let now = OffsetDateTime::now_utc();
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(2);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![1, 0, 18013, 5, 1, 2])];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "NazoAuth credential".to_owned());
    let canonical_host = suite_host.trim_matches(['[', ']']);
    let san = match canonical_host.parse::<IpAddr>() {
        Ok(address) => SanType::IpAddress(address),
        Err(_) => SanType::DnsName(
            canonical_host
                .to_owned()
                .try_into()
                .map_err(|_| MaterializerError::Crypto)?,
        ),
    };
    params.subject_alt_names = vec![san];
    let certificate = params
        .signed_by(&key_pair, ca)
        .map_err(|_| MaterializerError::Crypto)?;
    let encoded_certificate = STANDARD.encode(certificate.der().as_ref());
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().ok_or(MaterializerError::Crypto)?);
    let y = URL_SAFE_NO_PAD.encode(point.y().ok_or(MaterializerError::Crypto)?);
    let d = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let private = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": format!("nazo-openid4vc-credential-{}", random_hex(8)),
        "x": x,
        "y": y,
        "d": d,
        "x5c": [encoded_certificate]
    });
    serde_json::to_string(&private)
        .map(Zeroizing::new)
        .map_err(|_| MaterializerError::Encoding)
}

fn ec_pkcs8_der(signing_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let scalar = signing_key.to_bytes();
    let ec_private = der_sequence(&[
        der_tlv(0x02, &[0x01]),
        der_tlv(0x04, scalar.as_ref()),
        der_tlv(
            0xa0,
            &der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ),
        der_tlv(0xa1, &der_tlv(0x03, &[&[0x00], point.as_bytes()].concat())),
    ]);
    der_sequence(&[
        der_tlv(0x02, &[0x00]),
        der_sequence(&[
            der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]),
        der_tlv(0x04, &ec_private),
    ])
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let payload = parts.concat();
    der_tlv(0x30, &payload)
}

fn der_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    let length = payload.len();
    if length < 128 {
        output.push(length as u8);
    } else {
        let bytes = (length as u32).to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        output.push(0x80 | u8::try_from(4 - first).unwrap_or(4));
        output.extend_from_slice(&bytes[first..]);
    }
    output.extend_from_slice(payload);
    output
}

pub(super) fn rsa_jwks(key: &RsaPrivateKey) -> Result<(String, String), MaterializerError> {
    let n = b64(key.n().to_bytes_be());
    let e = b64(key.e().to_bytes_be());
    let kid = jwk_thumbprint(&format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#));
    let public = serde_json::json!({
        "kty": "RSA", "n": n, "e": e, "kid": kid,
        "alg": "PS256", "use": "sig", "key_ops": ["verify"]
    });
    let private = serde_json::json!({
        "kty": "RSA", "n": n, "e": e, "kid": kid,
        "d": b64(key.d().to_bytes_be()),
        "p": b64(key.primes().first().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "q": b64(key.primes().get(1).ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "dp": b64(key.dp().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "dq": b64(key.dq().ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "qi": b64(key.qinv().and_then(|value| value.to_biguint()).ok_or(MaterializerError::Crypto)?.to_bytes_be()),
        "alg": "PS256", "use": "sig", "key_ops": ["sign"]
    });
    let private_string = serde_json::to_string(&serde_json::json!({"keys": [private]}))
        .map_err(|_| MaterializerError::Encoding)?;
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((private_string, public_jwks))
}

pub(super) fn ec_jwks(key: &SigningKey) -> Result<(String, String), MaterializerError> {
    let encoded = key.verifying_key().to_encoded_point(false);
    let x = encoded.x().ok_or(MaterializerError::Crypto)?;
    let y = encoded.y().ok_or(MaterializerError::Crypto)?;
    let x = b64(x);
    let y = b64(y);
    let kid = jwk_thumbprint(&format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
    ));
    let public = serde_json::json!({
        "kty":"EC", "crv":"P-256", "x":x, "y":y, "kid":kid,
        "alg":"ES256", "use":"sig", "key_ops":["verify"]
    });
    let private = serde_json::json!({
        "kty":"EC", "crv":"P-256", "x":x, "y":y, "d":b64(key.to_bytes()), "kid":kid,
        "alg":"ES256", "use":"sig", "key_ops":["sign"]
    });
    let private_string = serde_json::to_string(&serde_json::json!({"keys": [private]}))
        .map_err(|_| MaterializerError::Encoding)?;
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((private_string, public_jwks))
}

fn jwk_thumbprint(canonical_public_members: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_public_members.as_bytes()))
}

pub(super) fn generate_mtls() -> Result<(String, String, String, String), MaterializerError> {
    let now = OffsetDateTime::now_utc();
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("NazoAuthCtl OIDF mTLS Root {}", random_hex(12)),
    );
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
    // A leaf with the same subject and issuer DN is classified as self-signed
    // by OpenSSL/HAProxy even when its signature was produced by another key.
    // Keep the identities distinct so strict proxy verification can build the
    // generated client -> run-scoped CA chain without ignore-error flags.
    client_params
        .distinguished_name
        .push(DnType::CommonName, MTLS_CLIENT_SAN_DNS);
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
