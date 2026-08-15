use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::secure_file::{read_bounded, write_atomic};

const MAX_PROXY_TRUST_BUNDLE_BYTES: usize = 1024 * 1024;

/// Recoverable installation of a run-scoped public client-CA bundle.
///
/// The reload executable is deployment-owned. The guard owns only the exact
/// bundle file and a sibling recovery copy; it never owns proxy configuration.
pub struct ProxyTrustGuard {
    bundle_path: PathBuf,
    recovery_path: PathBuf,
    reload_executable: PathBuf,
    active: bool,
    _lock: File,
}

impl ProxyTrustGuard {
    pub fn recover(
        bundle_path: impl AsRef<Path>,
        reload_executable: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let bundle_path = bundle_path.as_ref();
        let reload_executable = reload_executable.as_ref();
        validate_reload_executable(reload_executable)?;
        let file_name = bundle_path
            .file_name()
            .context("proxy trust bundle path has no file name")?
            .to_string_lossy();
        let recovery_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-restore"));
        let lock_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-lock"));
        let _lock = open_provider_lock(&lock_path)?;
        match fs::symlink_metadata(&recovery_path) {
            Ok(_) => {
                let recovery = read_private(&recovery_path, "proxy trust recovery bundle")?;
                write_private(bundle_path, &recovery, "proxy trust recovery")?;
                reload(reload_executable, "recover stale proxy trust transaction")?;
                remove_recovery(&recovery_path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to inspect proxy trust recovery bundle"),
        }
    }

    pub fn install(
        bundle_path: impl AsRef<Path>,
        reload_executable: impl AsRef<Path>,
        run_bundle: &[u8],
    ) -> anyhow::Result<Self> {
        let bundle_path = bundle_path.as_ref().to_owned();
        let reload_executable = reload_executable.as_ref().to_owned();
        validate_reload_executable(&reload_executable)?;
        let file_name = bundle_path
            .file_name()
            .context("proxy trust bundle path has no file name")?
            .to_string_lossy();
        let recovery_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-restore"));
        let lock_path = bundle_path.with_file_name(format!(".{file_name}.nazoauthctl-lock"));
        let lock = open_provider_lock(&lock_path)?;

        if recovery_path.exists() {
            let recovery = read_private(&recovery_path, "proxy trust recovery bundle")?;
            write_private(&bundle_path, &recovery, "proxy trust recovery")?;
            reload(&reload_executable, "recover stale proxy trust transaction")?;
            remove_recovery(&recovery_path)?;
        }

        let original = read_private(&bundle_path, "active proxy trust bundle")?;
        let combined = merge_public_trust_bundles(&original, run_bundle)?;
        write_private(&recovery_path, &original, "proxy trust recovery bundle")?;
        if let Err(error) = write_private(
            &bundle_path,
            &combined,
            "combined run-scoped proxy trust bundle",
        )
        .and_then(|()| reload(&reload_executable, "activate run-scoped proxy trust"))
        {
            let rollback = write_private(&bundle_path, &original, "proxy trust rollback")
                .and_then(|()| reload(&reload_executable, "roll back proxy trust"));
            if rollback.is_ok() {
                let _ = remove_recovery(&recovery_path);
            }
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => Err(anyhow::anyhow!(
                    "proxy trust activation failed and rollback also failed: activation={error:#}; rollback={rollback:#}"
                )),
            };
        }

        Ok(Self {
            bundle_path,
            recovery_path,
            reload_executable,
            active: true,
            _lock: lock,
        })
    }

    pub fn restore(&mut self) -> anyhow::Result<()> {
        if !self.active {
            return Ok(());
        }
        let original = read_private(&self.recovery_path, "proxy trust recovery bundle")?;
        write_private(&self.bundle_path, &original, "proxy trust rollback")?;
        reload(&self.reload_executable, "restore proxy trust")?;
        remove_recovery(&self.recovery_path)?;
        self.active = false;
        Ok(())
    }
}

fn merge_public_trust_bundles(original: &[u8], run_bundle: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut certificates = BTreeSet::new();
    let mut ordered = Vec::new();
    for (bytes, label) in [
        (original, "active proxy trust bundle"),
        (run_bundle, "run-scoped proxy trust bundle"),
    ] {
        for certificate in parse_public_ca_bundle(bytes, label)? {
            if certificates.insert(certificate.clone()) {
                ordered.push(certificate);
            }
        }
    }
    if ordered.is_empty() {
        bail!("combined proxy trust bundle contains no CA certificate");
    }
    let mut merged = Vec::new();
    for certificate in ordered {
        merged.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(certificate);
        for line in encoded.as_bytes().chunks(64) {
            merged.extend_from_slice(line);
            merged.push(b'\n');
        }
        merged.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    if merged.len() > MAX_PROXY_TRUST_BUNDLE_BYTES {
        bail!("combined proxy trust bundle is oversized");
    }
    Ok(merged)
}

fn parse_public_ca_bundle(bytes: &[u8], label: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    if bytes.len() > MAX_PROXY_TRUST_BUNDLE_BYTES
        || bytes.contains(&0)
        || String::from_utf8_lossy(bytes)
            .to_ascii_uppercase()
            .contains("PRIVATE KEY")
    {
        bail!("{label} contains private, binary, or oversized material");
    }
    let mut remaining = bytes;
    let mut certificates = Vec::new();
    loop {
        let offset = remaining
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(remaining.len());
        remaining = &remaining[offset..];
        if remaining.is_empty() {
            break;
        }
        let before = remaining.len();
        let (next, pem) =
            parse_x509_pem(remaining).with_context(|| format!("{label} contains malformed PEM"))?;
        if pem.label != "CERTIFICATE" || next.len() >= before {
            bail!("{label} contains a non-certificate PEM object");
        }
        let (der_remaining, certificate) = parse_x509_certificate(&pem.contents)
            .with_context(|| format!("{label} contains malformed X.509"))?;
        if !der_remaining.is_empty()
            || !certificate.is_ca()
            || !certificate.validity().is_valid()
            || certificate.issuer() != certificate.subject()
            || certificate
                .verify_signature(Some(certificate.public_key()))
                .is_err()
        {
            bail!("{label} contains an invalid CA trust anchor");
        }
        certificates.push(pem.contents);
        remaining = next;
    }
    Ok(certificates)
}

fn open_provider_lock(path: &Path) -> anyhow::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let owned = rustix::fs::open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .context("failed to open proxy trust provider lock")?;
        let file = File::from(owned);
        file.try_lock()
            .context("another conformance run owns the proxy trust bundle")?;
        let metadata = file.metadata()?;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            bail!("proxy trust provider lock must be root-owned and owner-only");
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("proxy trust mutation is supported only on Unix hosts")
    }
}

impl Drop for ProxyTrustGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn read_private(path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
    read_bounded(path, MAX_PROXY_TRUST_BUNDLE_BYTES, true)
        .map_err(|error| anyhow::anyhow!("failed to read {label}: {error:?}"))
}

fn write_private(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_PROXY_TRUST_BUNDLE_BYTES {
        bail!("{label} is empty or oversized");
    }
    write_atomic(path, bytes, true)
        .map_err(|error| anyhow::anyhow!("failed to write {label}: {error:?}"))
}

fn remove_recovery(path: &Path) -> anyhow::Result<()> {
    fs::remove_file(path).context("failed to remove proxy trust recovery bundle")?;
    let parent = path
        .parent()
        .context("proxy trust recovery bundle has no parent")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("failed to synchronize proxy trust recovery directory")
}

fn reload(executable: &Path, operation: &str) -> anyhow::Result<()> {
    let status = Command::new(executable)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .status()
        .with_context(|| format!("failed to {operation}"))?;
    if !status.success() {
        bail!("failed to {operation}: reload executable returned {status}");
    }
    Ok(())
}

fn validate_reload_executable(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        bail!("proxy reload executable must be an absolute path");
    }
    let metadata =
        fs::symlink_metadata(path).context("failed to inspect proxy reload executable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("proxy reload executable must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            bail!("proxy reload executable must be root-owned and not group/world-writable");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    use super::*;

    fn test_ca(common_name: &str) -> String {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().expect("key");
        parameters.self_signed(&key).expect("certificate").pem()
    }

    #[test]
    fn merge_preserves_existing_anchors_adds_run_anchors_and_deduplicates() {
        let existing = test_ca("existing");
        let run = test_ca("run");
        let run_bundle = format!("{run}{existing}");
        let merged = merge_public_trust_bundles(existing.as_bytes(), run_bundle.as_bytes())
            .expect("merged trust bundle");
        let merged = String::from_utf8(merged).expect("UTF-8 PEM");
        assert_eq!(merged.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert!(!merged.contains("PRIVATE KEY"));
    }

    #[test]
    fn merge_rejects_private_or_malformed_material() {
        let existing = test_ca("existing");
        assert!(
            merge_public_trust_bundles(existing.as_bytes(), b"-----BEGIN PRIVATE KEY-----\n")
                .is_err()
        );
        assert!(merge_public_trust_bundles(existing.as_bytes(), b"not a certificate").is_err());
    }
}
