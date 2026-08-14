//! Offline PKI validation for imported public-server TLS material.

use std::{io::Cursor, sync::Arc};

use anyhow::{Context, bail};
use chrono::Utc;
use rustls::{
    RootCertStore,
    pki_types::{ServerName, UnixTime},
    sign::CertifiedKey,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer as _};

use super::{
    LoadedProvider, MAX_CERTIFICATE_BYTES, MAX_PRIVATE_KEY_BYTES, canonical_hostname, sha256,
};
use crate::{cli::TlsCertificateInput, filesystem::read_secure_regular_file};

pub(super) struct ValidatedMaterial {
    pub(super) certificate_pem: Vec<u8>,
    pub(super) private_key_pem: zeroize::Zeroizing<Vec<u8>>,
    pub(super) leaf_sha256: String,
    pub(super) material_sha256: String,
    pub(super) not_after: i64,
    pub(super) root_store: RootCertStore,
}

pub(super) fn load_and_validate_material(
    input: &TlsCertificateInput,
    provider: &LoadedProvider,
) -> anyhow::Result<ValidatedMaterial> {
    let certificate_pem = read_secure_regular_file(
        &input.certificate,
        "TLS certificate chain",
        false,
        MAX_CERTIFICATE_BYTES,
    )?;
    let private_key_pem = read_secure_regular_file(
        &input.private_key,
        "TLS private key",
        true,
        MAX_PRIVATE_KEY_BYTES,
    )?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate_pem.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .context("TLS certificate PEM is invalid")?;
    if certificates.is_empty() {
        bail!("TLS certificate chain contains no certificate");
    }
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key_pem.as_slice()))
        .context("TLS private key PEM is invalid")?
        .context("TLS private key PEM contains no supported private key")?;
    let crypto = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = crypto
        .key_provider
        .load_private_key(private_key)
        .context("TLS private key algorithm is unsupported")?;
    CertifiedKey::new(certificates.clone(), signing_key)
        .keys_match()
        .context("TLS certificate and private key do not match")?;

    let root_store = root_store_from_pem(&provider.trust_anchors)?;
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store.clone()),
        Arc::new(crypto.clone()),
    )
    .build()
    .context("TLS trust anchor set is invalid")?;
    let server_name = ServerName::try_from(canonical_hostname(&input.hostname)?)
        .context("TLS hostname cannot be represented as SNI")?;
    use rustls::client::danger::ServerCertVerifier as _;
    verifier
        .verify_server_cert(
            &certificates[0],
            &certificates[1..],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .context("TLS certificate chain, SAN, validity, or serverAuth usage is invalid")?;

    let (_, leaf) = X509Certificate::from_der(certificates[0].as_ref())
        .context("TLS leaf certificate DER is invalid")?;
    let not_after = leaf.validity().not_after.timestamp();
    let now = Utc::now().timestamp();
    let minimum_validity = i64::try_from(provider.config.minimum_validity_seconds)
        .context("TLS minimum validity does not fit signed time")?;
    if not_after <= now.saturating_add(minimum_validity) {
        bail!("TLS certificate expires before the provider minimum validity window");
    }
    let leaf_sha256 = sha256(certificates[0].as_ref());
    let chain_sha256 = sha256(&certificate_pem);
    let material_sha256 = sha256(format!("{leaf_sha256}:{chain_sha256}").as_bytes());
    Ok(ValidatedMaterial {
        certificate_pem: certificate_pem.to_vec(),
        private_key_pem,
        leaf_sha256,
        material_sha256,
        not_after,
        root_store,
    })
}

pub(super) fn root_store_from_pem(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .context("TLS trust anchor PEM is invalid")?;
    if certificates.is_empty() {
        bail!("TLS trust anchor PEM contains no certificate");
    }
    let mut store = RootCertStore::empty();
    let (accepted, rejected) = store.add_parsable_certificates(certificates);
    if accepted == 0 || rejected != 0 {
        bail!("TLS trust anchor PEM contains an invalid certificate");
    }
    Ok(store)
}
