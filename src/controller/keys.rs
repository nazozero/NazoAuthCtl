use super::*;

pub(crate) fn managed_openid4vc_bundle_path(config: &UpdateConfig) -> anyhow::Result<PathBuf> {
    let key_directories = if config.runtime.backend == RuntimeBackendKind::Systemd {
        config
            .runtime
            .snapshot_paths
            .iter()
            .filter(|path| path.file_name().is_some_and(|name| name == "keys"))
            .collect::<Vec<_>>()
    } else {
        config
            .runtime
            .mounts
            .iter()
            .filter(|mount| {
                mount.target == Path::new(OPENID4VC_KEYS_MOUNT)
                    && !mount.read_only
                    && mount.source.file_name().is_some_and(|name| name == "keys")
            })
            .map(|mount| &mount.source)
            .collect::<Vec<_>>()
    };
    if key_directories.len() != 1 {
        bail!("managed installation must expose exactly one writable OpenID4VC key directory");
    }
    let keys = key_directories[0];
    crate::model::safe_absolute(keys)?;
    let metadata = fs::symlink_metadata(keys)
        .with_context(|| format!("failed to inspect managed key directory {}", keys.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed OpenID4VC key directory must be a real directory");
    }
    Ok(keys.join(OPENID4VC_CERTIFICATE_BUNDLE))
}

pub(crate) fn read_managed_openid4vc_bundle(
    config: &UpdateConfig,
    bundle: &Path,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        crate::filesystem::read_secure_regular_file_for_uid(
            bundle,
            "managed OpenID4VC certificate bundle",
            false,
            MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES as u64,
            crate::runtime::runtime_service_owner_uid(config)?,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        crate::filesystem::read_secure_regular_file(
            bundle,
            "managed OpenID4VC certificate bundle",
            false,
            MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES as u64,
        )
    }
}

pub(crate) fn extract_openid4vc_trust_anchors(bundle: &[u8]) -> anyhow::Result<Vec<u8>> {
    let certificates = parse_managed_openid4vc_bundle(bundle)?;
    let mut output = Vec::new();
    append_pem_certificate(&mut output, &certificates[1]);
    Ok(output)
}

pub(super) fn parse_managed_openid4vc_bundle(bundle: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    if bundle.len() > MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES {
        bail!("managed OpenID4VC certificate bundle exceeds 1 MiB");
    }
    let mut remaining = trim_ascii_whitespace(bundle);
    let mut certificate_count = 0;
    let mut ca_count = 0;
    let mut leaf_count = 0;
    let mut certificates = Vec::new();
    while !remaining.is_empty() {
        if !remaining.starts_with(b"-----BEGIN CERTIFICATE-----") {
            bail!("managed OpenID4VC certificate bundle contains a non-certificate block");
        }
        let (rest, pem) = x509_parser::pem::parse_x509_pem(remaining).map_err(|_| {
            anyhow::anyhow!("managed OpenID4VC certificate bundle is not valid PEM")
        })?;
        if pem.label != "CERTIFICATE" {
            bail!("managed OpenID4VC certificate bundle contains a non-certificate block");
        }
        let (der_remaining, certificate) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|_| {
                anyhow::anyhow!("managed OpenID4VC certificate bundle contains invalid X.509 data")
            })?;
        if !der_remaining.is_empty() {
            bail!("managed OpenID4VC certificate bundle contains trailing X.509 data");
        }
        certificate_count += 1;
        let is_ca = certificate.is_ca();
        if (certificate_count == 1 && is_ca) || (certificate_count == 2 && !is_ca) {
            bail!("managed OpenID4VC certificate bundle must order leaf before CA trust anchor");
        }
        if is_ca {
            ca_count += 1;
        } else {
            leaf_count += 1;
        }
        certificates.push(pem.contents);
        remaining = trim_ascii_whitespace(rest);
    }
    if certificate_count != 2 || ca_count != 1 || leaf_count != 1 {
        bail!(
            "managed OpenID4VC certificate bundle must contain exactly one leaf certificate and one CA trust anchor"
        );
    }
    Ok(certificates)
}

pub(super) fn append_pem_certificate(output: &mut Vec<u8>, der: &[u8]) {
    output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    let encoded = STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END CERTIFICATE-----\n");
}

pub(super) fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        value = rest;
    }
    value
}
