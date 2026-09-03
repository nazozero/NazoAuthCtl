use super::MaterializerError;
use aws_lc_rs::{
    digest::{SHA1_FOR_LEGACY_USE_ONLY, digest},
    encoding::AsDer,
    rsa::{KeyPair as RsaKeyPair, KeySize as RsaKeySize},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate as _};
use pkcs1::RsaPrivateKey as Pkcs1RsaPrivateKey;
use pkcs8::PrivateKeyInfoRef;
use rand::{TryRng as _, rngs::SysRng};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CrlDistributionPoint, CustomExtension,
    DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    string::PrintableString,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;
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
    let rsa = RsaKeyPair::generate(rsa_key_size(policy.rsa_bits)?)
        .map_err(|_| MaterializerError::Crypto)?;
    let rsa_pkcs8 = Zeroizing::new(
        rsa.as_der()
            .map_err(|_| MaterializerError::Crypto)?
            .as_ref()
            .to_vec(),
    );
    let (rsa_private_jwks, rsa_public_jwks) = rsa_jwks(rsa_pkcs8.as_slice())?;
    let ec = SigningKey::generate();
    let (ec_private_jwks, ec_public_jwks) = ec_jwks(&ec)?;
    let (
        mtls_ca_certificate,
        mtls_client_certificate,
        mtls_client_key,
        mtls_client_certificate_sha256,
    ) = generate_mtls()?;
    Ok(GeneratedClientCrypto {
        client_secret,
        rsa_private_jwks,
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
    SysRng
        .try_fill_bytes(&mut random)
        .expect("operating-system CSPRNG unavailable");
    URL_SAFE_NO_PAD.encode(random)
}

pub(super) fn random_hex(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    SysRng
        .try_fill_bytes(&mut random)
        .expect("operating-system CSPRNG unavailable");
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn random_tx_code() -> String {
    const RANGE: u32 = 1_000_000;
    let limit = u32::MAX - (u32::MAX % RANGE);
    let mut rng = SysRng;
    loop {
        let value = rng
            .try_next_u32()
            .expect("operating-system CSPRNG unavailable");
        if value < limit {
            return format!("{:06}", value % RANGE);
        }
    }
}

/// Generate independent P-256 proof/attester identities for VCI and VCI-HAIP.
/// The key material comes from the operating-system CSPRNG, then is wrapped in a run-local CA so
/// the Suite can validate x5c chains without deployment secrets.  No generated
/// private value is returned in the onboarding bundle.
pub(super) fn generate_attestation_material(
    suite_origin: &str,
    issuing_country: Option<&str>,
) -> Result<GeneratedAttestationMaterial, MaterializerError> {
    let now = OffsetDateTime::now_utc();
    let ca_key = p256::ecdsa::SigningKey::generate();
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    ca_params.not_before = now - TimeDuration::days(1);
    ca_params.not_after = now + TimeDuration::days(2);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(issuing_country) = issuing_country {
        configure_mdoc_identity(
            &mut ca_params,
            &ca_key,
            issuing_country,
            "NazoAuth conformance IACA",
        )?;
        ca_params
            .custom_extensions
            .push(issuer_alternative_name(suite_origin));
        ca_params.crl_distribution_points = vec![mdoc_crl_distribution_point(suite_origin)];
    }
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
    let credential_signing_private_jwk =
        generate_credential_signing_leaf(&ca, suite_origin, issuing_country)?;
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
    let signing_key = p256::ecdsa::SigningKey::generate();
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
    let point = signing_key.verifying_key().to_sec1_point(false);
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
    suite_origin: &str,
    issuing_country: Option<&str>,
) -> Result<Zeroizing<String>, MaterializerError> {
    let signing_key = p256::ecdsa::SigningKey::generate();
    let key_der = Zeroizing::new(ec_pkcs8_der(&signing_key));
    let key_pair = KeyPair::try_from(key_der.as_slice()).map_err(|_| MaterializerError::Crypto)?;
    let now = OffsetDateTime::now_utc();
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| MaterializerError::Crypto)?;
    params.not_before = now - TimeDuration::days(1);
    params.not_after = now + TimeDuration::days(2);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params
        .custom_extensions
        .push(subject_alternative_name(suite_origin)?);
    if let Some(issuing_country) = issuing_country {
        configure_mdoc_identity(
            &mut params,
            &signing_key,
            issuing_country,
            "NazoAuth conformance document signer",
        )?;
        params.use_authority_key_identifier_extension = true;
        params.crl_distribution_points = vec![mdoc_crl_distribution_point(suite_origin)];
        params
            .custom_extensions
            .push(subject_key_identifier(&signing_key));
        params
            .custom_extensions
            .push(issuer_alternative_name(suite_origin));
        let mut document_signer_eku = CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            der_sequence(&[der_tlv(0x06, &[0x28, 0x81, 0x8c, 0x5d, 0x05, 0x01, 0x02])]),
        );
        document_signer_eku.set_criticality(true);
        params.custom_extensions.push(document_signer_eku);
    } else {
        params
            .distinguished_name
            .push(DnType::CommonName, "NazoAuth credential".to_owned());
    }
    let certificate = params
        .signed_by(&key_pair, ca)
        .map_err(|_| MaterializerError::Crypto)?;
    let encoded_certificate = STANDARD.encode(certificate.der().as_ref());
    let point = signing_key.verifying_key().to_sec1_point(false);
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

fn configure_mdoc_identity(
    params: &mut CertificateParams,
    signing_key: &SigningKey,
    issuing_country: &str,
    common_name: &str,
) -> Result<(), MaterializerError> {
    let country =
        PrintableString::try_from(issuing_country).map_err(|_| MaterializerError::Crypto)?;
    params
        .distinguished_name
        .push(DnType::CountryName, DnValue::PrintableString(country));
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_owned());
    params.key_identifier_method =
        KeyIdMethod::PreSpecified(mdoc_subject_key_identifier(signing_key));
    Ok(())
}

fn mdoc_subject_key_identifier(signing_key: &SigningKey) -> Vec<u8> {
    let point = signing_key.verifying_key().to_sec1_point(false);
    digest(&SHA1_FOR_LEGACY_USE_ONLY, point.as_bytes())
        .as_ref()
        .to_vec()
}

fn subject_key_identifier(signing_key: &SigningKey) -> CustomExtension {
    CustomExtension::from_oid_content(
        &[2, 5, 29, 14],
        der_tlv(0x04, &mdoc_subject_key_identifier(signing_key)),
    )
}

fn issuer_alternative_name(suite_origin: &str) -> CustomExtension {
    CustomExtension::from_oid_content(
        &[2, 5, 29, 18],
        der_sequence(&[der_tlv(0x86, suite_origin.as_bytes())]),
    )
}

fn subject_alternative_name(suite_origin: &str) -> Result<CustomExtension, MaterializerError> {
    let suite_host = Url::parse(suite_origin)
        .map_err(|_| MaterializerError::Crypto)?
        .host_str()
        .ok_or(MaterializerError::Crypto)?
        .as_bytes()
        .to_vec();
    Ok(CustomExtension::from_oid_content(
        &[2, 5, 29, 17],
        der_sequence(&[
            der_tlv(0x82, &suite_host),
            der_tlv(0x86, suite_origin.as_bytes()),
        ]),
    ))
}

fn mdoc_crl_distribution_point(suite_origin: &str) -> CrlDistributionPoint {
    CrlDistributionPoint {
        uris: vec![format!(
            "{}/nazoauthctl-mdoc.crl",
            suite_origin.trim_end_matches('/')
        )],
    }
}

fn ec_pkcs8_der(signing_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = signing_key.verifying_key().to_sec1_point(false);
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

fn rsa_key_size(bits: u16) -> Result<RsaKeySize, MaterializerError> {
    match bits {
        2048 => Ok(RsaKeySize::Rsa2048),
        3072 => Ok(RsaKeySize::Rsa3072),
        4096 => Ok(RsaKeySize::Rsa4096),
        _ => Err(MaterializerError::Crypto),
    }
}

pub(super) fn rsa_jwks(pkcs8_der: &[u8]) -> Result<(Zeroizing<String>, String), MaterializerError> {
    const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    let private_key_info =
        PrivateKeyInfoRef::try_from(pkcs8_der).map_err(|_| MaterializerError::Crypto)?;
    if private_key_info.algorithm.oid.as_bytes() != RSA_ENCRYPTION_OID
        || !private_key_info
            .algorithm
            .parameters
            .is_some_and(|parameter| parameter.is_null())
    {
        return Err(MaterializerError::Crypto);
    }
    let key = Pkcs1RsaPrivateKey::try_from(private_key_info.private_key.as_bytes())
        .map_err(|_| MaterializerError::Crypto)?;
    if key.other_prime_infos.is_some()
        || [
            key.modulus,
            key.public_exponent,
            key.private_exponent,
            key.prime1,
            key.prime2,
            key.exponent1,
            key.exponent2,
            key.coefficient,
        ]
        .iter()
        .any(|component| component.is_empty())
    {
        return Err(MaterializerError::Crypto);
    }

    let n = b64(key.modulus.as_bytes());
    let e = b64(key.public_exponent.as_bytes());
    let kid = jwk_thumbprint(&format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#));
    let public = serde_json::json!({
        "kty": "RSA", "n": n, "e": e, "kid": kid,
        "alg": "PS256", "use": "sig", "key_ops": ["verify"]
    });
    let d = Zeroizing::new(b64(key.private_exponent.as_bytes()));
    let p = Zeroizing::new(b64(key.prime1.as_bytes()));
    let q = Zeroizing::new(b64(key.prime2.as_bytes()));
    let dp = Zeroizing::new(b64(key.exponent1.as_bytes()));
    let dq = Zeroizing::new(b64(key.exponent2.as_bytes()));
    let qi = Zeroizing::new(b64(key.coefficient.as_bytes()));
    let mut private_jwks = Zeroizing::new(String::new());
    write!(
        private_jwks,
        r#"{{"keys":[{{"kty":"RSA","n":"{n}","e":"{e}","kid":"{kid}","d":"{}","p":"{}","q":"{}","dp":"{}","dq":"{}","qi":"{}","alg":"PS256","use":"sig","key_ops":["sign"]}}]}}"#,
        d.as_str(),
        p.as_str(),
        q.as_str(),
        dp.as_str(),
        dq.as_str(),
        qi.as_str(),
    )
    .map_err(|_| MaterializerError::Encoding)?;
    let public_jwks = serde_json::to_string(&serde_json::json!({"keys": [public]}))
        .map_err(|_| MaterializerError::Encoding)?;
    Ok((private_jwks, public_jwks))
}

pub(super) fn ec_jwks(key: &SigningKey) -> Result<(String, String), MaterializerError> {
    let encoded = key.verifying_key().to_sec1_point(false);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::CryptoPolicy;
    use p256::{
        ecdsa::{
            Signature,
            signature::{Signer as _, Verifier as _},
        },
        pkcs8::DecodePrivateKey as _,
    };

    #[test]
    fn rsa_key_size_accepts_only_policy_supported_sizes() {
        for bits in [2048, 3072, 4096] {
            assert!(
                rsa_key_size(bits).is_ok(),
                "{bits}-bit RSA must be supported"
            );
        }
        for bits in [0, 1024, 1536, 8192] {
            assert!(matches!(rsa_key_size(bits), Err(MaterializerError::Crypto)));
        }
    }

    #[test]
    fn generated_rsa_jwk_has_complete_ps256_two_prime_components() {
        let material = generate_client_crypto(&CryptoPolicy::default()).expect("client crypto");
        let private: Value = serde_json::from_str(material.rsa_private_jwks.as_str())
            .expect("private RSA JWKS JSON");
        let public: Value =
            serde_json::from_str(material.rsa_public_jwks.as_str()).expect("public RSA JWKS JSON");
        let private = private["keys"]
            .as_array()
            .and_then(|keys| keys.first())
            .expect("one private RSA JWK");
        let public = public["keys"]
            .as_array()
            .and_then(|keys| keys.first())
            .expect("one public RSA JWK");

        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            let value = private
                .get(field)
                .and_then(Value::as_str)
                .expect("private JWK component must be present");
            assert!(!value.is_empty(), "private JWK is missing {field}");
            assert!(!value.contains('='), "private JWK {field} must be unpadded");
            assert!(
                URL_SAFE_NO_PAD
                    .decode(value)
                    .is_ok_and(|component| !component.is_empty()),
                "private JWK {field} must be base64url"
            );
        }
        assert_eq!(private["kty"], "RSA");
        assert_eq!(private["alg"], "PS256");
        assert_eq!(private["use"], "sig");
        assert_eq!(private["key_ops"], serde_json::json!(["sign"]));
        assert_eq!(public["kty"], "RSA");
        assert_eq!(public["alg"], "PS256");
        assert_eq!(public["use"], "sig");
        assert_eq!(public["key_ops"], serde_json::json!(["verify"]));
        for field in ["n", "e", "kid"] {
            assert_eq!(private[field], public[field], "RSA {field} must match");
        }
    }

    #[test]
    fn ec_jwk_pkcs8_and_es256_raw_signature_keep_the_wire_contract() {
        let key = SigningKey::from_slice(&[7; 32]).expect("fixed P-256 signing key");
        let (private_jwks, public_jwks) = ec_jwks(&key).expect("EC JWKS");
        let private: Value = serde_json::from_str(&private_jwks).expect("private EC JWKS JSON");
        let public: Value = serde_json::from_str(&public_jwks).expect("public EC JWKS JSON");
        let private = private["keys"]
            .as_array()
            .and_then(|keys| keys.first())
            .expect("one private EC JWK");
        let public = public["keys"]
            .as_array()
            .and_then(|keys| keys.first())
            .expect("one public EC JWK");

        for field in ["x", "y", "d"] {
            let value = private
                .get(field)
                .and_then(Value::as_str)
                .expect("private EC JWK component must be present");
            assert!(!value.contains('='), "private EC {field} must be unpadded");
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(value)
                    .expect("private EC JWK component must be base64url")
                    .len(),
                32,
                "private EC {field} must be a P-256 field element"
            );
        }
        assert_eq!(private["kty"], "EC");
        assert_eq!(private["crv"], "P-256");
        assert_eq!(private["alg"], "ES256");
        assert_eq!(private["use"], "sig");
        assert_eq!(private["key_ops"], serde_json::json!(["sign"]));
        assert_eq!(public["kty"], "EC");
        assert_eq!(public["crv"], "P-256");
        assert_eq!(public["alg"], "ES256");
        assert_eq!(public["use"], "sig");
        assert_eq!(public["key_ops"], serde_json::json!(["verify"]));
        for field in ["x", "y", "kid"] {
            assert_eq!(private[field], public[field], "EC {field} must match");
        }
        assert!(public.get("d").is_none(), "public EC JWK must not expose d");

        let message = b"OIDF ES256 raw signature contract";
        let signature: Signature = key.sign(message);
        assert_eq!(signature.to_bytes().len(), 64, "ES256 must remain raw R||S");
        key.verifying_key()
            .verify(message, &signature)
            .expect("ES256 raw signature verifies");

        let der = Zeroizing::new(ec_pkcs8_der(&key));
        let parsed = p256::SecretKey::from_pkcs8_der(der.as_slice())
            .expect("generated P-256 PKCS#8 parses as P-256");
        assert_eq!(parsed.to_bytes(), key.to_bytes(), "PKCS#8 preserves d");
        KeyPair::try_from(der.as_slice()).expect("rcgen accepts generated P-256 PKCS#8");
    }

    #[test]
    fn rsa_jwks_rejects_a_non_rsa_pkcs8_algorithm_identifier() {
        let key = RsaKeyPair::generate(RsaKeySize::Rsa2048).expect("RSA key");
        let mut pkcs8_der = Zeroizing::new(key.as_der().expect("RSA PKCS#8").as_ref().to_vec());
        const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let oid_start = pkcs8_der
            .windows(RSA_ENCRYPTION_OID.len())
            .position(|window| window == RSA_ENCRYPTION_OID)
            .expect("RSA algorithm identifier");
        pkcs8_der[oid_start + RSA_ENCRYPTION_OID.len() - 1] = 0x02;

        assert!(matches!(
            rsa_jwks(pkcs8_der.as_slice()),
            Err(MaterializerError::Crypto)
        ));
    }

    #[test]
    fn rsa_jwks_rejects_rsa_encryption_with_non_null_parameters() {
        let key = RsaKeyPair::generate(RsaKeySize::Rsa2048).expect("RSA key");
        let mut pkcs8_der = Zeroizing::new(key.as_der().expect("RSA PKCS#8").as_ref().to_vec());
        const RSA_ALGORITHM_IDENTIFIER: &[u8] = &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ];
        let parameter_tag = pkcs8_der
            .windows(RSA_ALGORITHM_IDENTIFIER.len())
            .position(|window| window == RSA_ALGORITHM_IDENTIFIER)
            .expect("RSA algorithm identifier")
            + RSA_ALGORITHM_IDENTIFIER.len()
            - 2;
        pkcs8_der[parameter_tag] = 0x04;

        assert!(matches!(
            rsa_jwks(pkcs8_der.as_slice()),
            Err(MaterializerError::Crypto)
        ));
    }
}
