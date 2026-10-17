use std::path::{Path, PathBuf};

#[cfg(unix)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Origin;

#[cfg(unix)]
const STORE_SCHEMA: u32 = 1;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A bearer token that cannot accidentally be printed through `Debug` or
/// `Display`. The token is only exposed to the request builder internally.
#[derive(Clone)]
pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialStoreError> {
        let mut value = Zeroizing::new(value.into());
        let leading = value.len() - value.trim_start().len();
        let trimmed = value[leading..].trim_end();
        if trimmed.is_empty()
            || trimmed.len() > MAX_TOKEN_BYTES
            || !trimmed.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CredentialStoreError::InvalidToken);
        }
        let len = trimmed.len();
        value.drain(..leading);
        value.truncate(len);
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken(REDACTED)")
    }
}

impl std::fmt::Display for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted bearer token>")
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential<S> {
    schema: u32,
    origin: S,
    token: S,
}

/// A per-origin credential store. Unix uses an owner-only file with descriptor
/// and inode checks; Windows uses Credential Manager/DPAPI. Other platforms
/// reject persistence rather than silently falling back to plaintext storage.
pub struct CredentialStore {
    root: PathBuf,
}

impl CredentialStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, CredentialStoreError> {
        let root = root.into();
        ensure_private_directory(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn save(&self, origin: &Origin, token: &BearerToken) -> Result<(), CredentialStoreError> {
        #[cfg(windows)]
        {
            windows_save(&self.root, origin, token)
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = (origin, token);
            return Err(CredentialStoreError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let path = self.path_for(origin);
            let record = StoredCredential {
                schema: STORE_SCHEMA,
                origin: origin.as_str(),
                token: token.as_str(),
            };
            let bytes = serde_json::to_vec(&record).map_err(|_| CredentialStoreError::Encoding)?;
            crate::secure_file::write_atomic(&path, &bytes, true).map_err(map_secure_file_error)
        }
    }

    pub fn load(&self, origin: &Origin) -> Result<Option<BearerToken>, CredentialStoreError> {
        #[cfg(windows)]
        {
            windows_load(&self.root, origin)
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = origin;
            return Err(CredentialStoreError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let path = self.path_for(origin);
            let bytes = match crate::secure_file::read_bounded(&path, MAX_TOKEN_BYTES * 2, true) {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(crate::secure_file::SecureFileError::NotFound) => return Ok(None),
                Err(error) => return Err(map_secure_file_error(error)),
            };
            let record: StoredCredential<String> =
                serde_json::from_slice(&bytes).map_err(|_| CredentialStoreError::Malformed)?;
            if record.schema != STORE_SCHEMA || record.origin != origin.as_str() {
                return Err(CredentialStoreError::OriginMismatch);
            }
            BearerToken::new(record.token).map(Some)
        }
    }

    pub fn remove(&self, origin: &Origin) -> Result<(), CredentialStoreError> {
        #[cfg(windows)]
        {
            windows_remove(&self.root, origin)
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = origin;
            return Err(CredentialStoreError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let path = self.path_for(origin);
            match crate::secure_file::remove_file(&path, true) {
                Ok(()) | Err(crate::secure_file::SecureFileError::NotFound) => Ok(()),
                Err(error) => Err(map_secure_file_error(error)),
            }
        }
    }

    #[cfg(unix)]
    fn path_for(&self, origin: &Origin) -> PathBuf {
        self.root
            .join(format!("{}.json", digest_hex(origin.as_str().as_bytes())))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CredentialStoreError {
    UnsupportedPlatform,
    InvalidToken,
    NotFound,
    OriginMismatch,
    Oversize,
    Malformed,
    Encoding,
    Io,
    UnsafePath,
}

impl std::fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "secure credential persistence is unavailable on this platform"
            }
            Self::InvalidToken => "bearer token is invalid",
            Self::NotFound => "credential was not found",
            Self::OriginMismatch => "credential origin does not match the requested Suite origin",
            Self::Oversize => "credential exceeds the size limit",
            Self::Malformed => "credential record is malformed",
            Self::Encoding => "credential record could not be encoded",
            Self::Io => "secure credential storage I/O failed",
            Self::UnsafePath => "credential storage path is not private",
        })
    }
}

impl std::error::Error for CredentialStoreError {}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(windows)]
fn windows_entry(root: &Path, origin: &Origin) -> Result<keyring::Entry, CredentialStoreError> {
    // The service and account are opaque digests, so neither a filesystem
    // path nor an origin (which may contain tenant identifiers) is exposed in
    // Credential Manager metadata. Credential Manager encrypts the value for
    // the current Windows user via the native DPAPI-backed store.
    let namespace = digest_hex(root.to_string_lossy().as_bytes());
    let account = digest_hex(origin.as_str().as_bytes());
    keyring::Entry::new(
        &format!("nazoauthctl-conformance-{namespace}"),
        &format!("origin-{account}"),
    )
    .map_err(|_| CredentialStoreError::Io)
}

#[cfg(windows)]
fn windows_save(
    root: &Path,
    origin: &Origin,
    token: &BearerToken,
) -> Result<(), CredentialStoreError> {
    windows_entry(root, origin)?
        .set_password(token.as_str())
        .map_err(|_| CredentialStoreError::Io)
}

#[cfg(windows)]
fn windows_load(root: &Path, origin: &Origin) -> Result<Option<BearerToken>, CredentialStoreError> {
    match windows_entry(root, origin)?.get_password() {
        Ok(value) => BearerToken::new(value).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(CredentialStoreError::Io),
    }
}

#[cfg(windows)]
fn windows_remove(root: &Path, origin: &Origin) -> Result<(), CredentialStoreError> {
    match windows_entry(root, origin)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(CredentialStoreError::Io),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), CredentialStoreError> {
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = path;
        return Err(CredentialStoreError::UnsupportedPlatform);
    }
    #[cfg(windows)]
    {
        // The path is a namespace only on Windows; secret bytes never enter
        // the filesystem. Credential Manager enforces the user boundary.
        let _ = path;
        Ok(())
    }
    #[cfg(unix)]
    {
        crate::secure_file::ensure_directory(path, true)
            .map(|_| ())
            .map_err(map_secure_file_error)
    }
}

#[cfg(unix)]
fn map_secure_file_error(error: crate::secure_file::SecureFileError) -> CredentialStoreError {
    match error {
        crate::secure_file::SecureFileError::UnsupportedPlatform => {
            CredentialStoreError::UnsupportedPlatform
        }
        crate::secure_file::SecureFileError::NotFound => CredentialStoreError::NotFound,
        crate::secure_file::SecureFileError::Oversize => CredentialStoreError::Oversize,
        crate::secure_file::SecureFileError::UnsafePath => CredentialStoreError::UnsafePath,
        crate::secure_file::SecureFileError::Io => CredentialStoreError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use zeroize::Zeroize;

    #[test]
    fn token_normalization_reuses_owned_storage_and_rejects_non_header_bytes() {
        for input in ["token", " \r\ntoken\t", "\u{2003}token\u{a0}"] {
            let owned = input.to_owned();
            let storage = owned.as_ptr();
            let token = BearerToken::new(owned).unwrap();
            assert_eq!(token.as_str(), "token");
            assert_eq!(token.as_str().as_ptr(), storage);
        }
        for invalid in [
            "",
            " \r\n\t",
            "to ken",
            "to\tken",
            "to\0ken",
            "to\u{7f}ken",
            "tökén",
        ] {
            assert!(matches!(
                BearerToken::new(invalid),
                Err(CredentialStoreError::InvalidToken)
            ));
        }
        assert!(BearerToken::new("a".repeat(MAX_TOKEN_BYTES)).is_ok());
        assert!(matches!(
            BearerToken::new("a".repeat(MAX_TOKEN_BYTES + 1)),
            Err(CredentialStoreError::InvalidToken)
        ));
    }

    #[test]
    fn token_does_not_debug_print() {
        let token = BearerToken::new("top-secret").expect("token");
        assert!(!format!("{token:?}").contains("top-secret"));
        assert!(!format!("{token}").contains("top-secret"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_credential_namespace_matches_published_service_and_user() {
        // Construct only: no existing Credential Manager values are read or written.
        let root = Path::new(r"C:\NazoAuthCtlCredentialFixture");
        let origin = Origin::parse("https://suite.example").expect("origin");
        let entry = windows_entry(root, &origin).expect("entry");
        assert_eq!(
            entry.inner.get_specifiers(),
            Some((
                "nazoauthctl-conformance-609f14757e8864afb5a194282c0d9993d78d235981255bdee1e3a3a40933ab4a".to_owned(),
                "origin-4d15bdf5a6cabec09a37e1ce891726fdb4f9f83ba7c70ac27a86245a414396b9".to_owned(),
            ))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_reads_native_legacy_format_credentials_and_isolates_origins() {
        let work = nazoauthctl_runtime::filesystem::PrivateTempDir::new("legacy-credential")
            .expect("private temporary namespace");
        let store = CredentialStore::new(work.path()).expect("store");
        let first = Origin::parse("https://legacy-suite.example").expect("origin");
        let second = Origin::parse("https://other-suite.example").expect("origin");
        // The product initializes Keyring's native store; both names are unique to this fixture.
        assert!(store.load(&first).expect("new namespace").is_none());
        let service = format!(
            "nazoauthctl-conformance-{}",
            digest_hex(work.path().to_string_lossy().as_bytes())
        );
        let user = format!("origin-{}", digest_hex(first.as_str().as_bytes()));
        // Keyring 3.6.3 used user.service, Generic/Enterprise and UTF-16LE password bytes.
        let target = format!("{user}.{service}");
        let modifiers = std::collections::HashMap::from([
            ("target", target.as_str()),
            ("persistence", "Enterprise"),
        ]);
        let legacy = keyring_core::Entry::new_with_modifiers(&service, &user, &modifiers)
            .expect("native legacy-format entry");
        assert!(matches!(
            legacy.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
        struct Cleanup(keyring_core::Entry);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.delete_credential();
            }
        }
        let legacy = Cleanup(legacy);
        let mut bytes = Zeroizing::new(
            "legacy-token"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        legacy
            .0
            .set_secret(&bytes)
            .expect("write frozen legacy encoding");
        bytes.zeroize();
        assert_eq!(
            store
                .load(&first)
                .expect("load legacy entry")
                .expect("token")
                .as_str(),
            "legacy-token"
        );
        assert!(store.load(&second).expect("other origin").is_none());
        store.remove(&first).expect("remove legacy entry");
        assert!(matches!(
            legacy.0.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
        assert!(store.load(&first).expect("removed entry").is_none());
        store.remove(&first).expect("remove missing entry");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn origin_isolation_uses_distinct_records() {
        let work = nazoauthctl_runtime::filesystem::PrivateTempDir::new("credential-upgrade")
            .expect("private temporary namespace");
        let store = CredentialStore::new(work.path()).expect("store");
        let first = Origin::parse("https://suite-one.example").expect("origin");
        let second = Origin::parse("https://suite-two.example").expect("origin");
        struct Cleanup<'a>(&'a CredentialStore, &'a Origin, &'a Origin);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.0.remove(self.1);
                let _ = self.0.remove(self.2);
            }
        }
        let _cleanup = Cleanup(&store, &first, &second);
        assert!(store.load(&first).expect("missing entry").is_none());
        store.remove(&first).expect("remove missing entry");
        let token = BearerToken::new("token-one").expect("token");
        store.save(&first, &token).expect("save");
        assert!(store.load(&second).expect("other origin").is_none());
        assert_eq!(
            store.load(&first).expect("load").expect("token").as_str(),
            "token-one"
        );
        store.remove(&first).expect("remove stored entry");
        assert!(store.load(&first).expect("removed entry").is_none());
        store.remove(&first).expect("repeated remove");
    }
}
