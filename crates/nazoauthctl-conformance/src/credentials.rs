#[cfg(all(test, unix))]
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Origin;

#[cfg(unix)]
const STORE_SCHEMA: u32 = 1;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A bearer token that cannot accidentally be printed through `Debug` or
/// `Display`. The token is only exposed to the request builder internally.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialStoreError> {
        let value = Zeroizing::new(value.into());
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_TOKEN_BYTES {
            return Err(CredentialStoreError::InvalidToken);
        }
        if trimmed
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
            || !trimmed.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CredentialStoreError::InvalidToken);
        }
        Ok(Self(Zeroizing::new(trimmed.to_owned())))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read a token from an owner-only regular file using the shared bounded
    /// secure-file primitive.  The token value is never included in errors.
    pub fn read_file(path: &Path) -> Result<Self, CredentialStoreError> {
        let bytes = crate::secure_file::read_bounded(path, MAX_TOKEN_BYTES, true)
            .map_err(map_secure_file_error)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CredentialStoreError::InvalidToken)?;
        Self::new(text).map_err(|_| CredentialStoreError::InvalidToken)
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
struct StoredCredential {
    schema: u32,
    origin: String,
    token: String,
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
        ensure_private_directory(&self.root)?;
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
                origin: origin.as_str().to_owned(),
                token: token.as_str().to_owned(),
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
            let record: StoredCredential =
                serde_json::from_slice(&bytes).map_err(|_| CredentialStoreError::Malformed)?;
            if record.schema != STORE_SCHEMA || record.origin != origin.as_str() {
                return Err(CredentialStoreError::OriginMismatch);
            }
            BearerToken::new(record.token)
                .map(Some)
                .map_err(|_| CredentialStoreError::InvalidToken)
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

    /// Read a token from an inherited descriptor without putting the value in
    /// argv or an environment variable. The descriptor is reopened and its
    /// resulting object is checked as a regular owner-only file. Anonymous
    /// pipes are intentionally unsupported here; callers should use a private
    /// file or pass an already parsed token from the CLI's channel layer.
    #[cfg(unix)]
    pub fn read_descriptor(fd: u32) -> Result<BearerToken, CredentialStoreError> {
        if fd < 3 {
            return Err(CredentialStoreError::InvalidDescriptor);
        }
        let bytes = crate::secure_file::read_descriptor(fd, MAX_TOKEN_BYTES, true)
            .map(Zeroizing::new)
            .map_err(map_secure_file_error)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CredentialStoreError::InvalidToken)?;
        BearerToken::new(text).map_err(|_| CredentialStoreError::InvalidToken)
    }

    #[cfg(not(unix))]
    pub fn read_descriptor(_fd: u32) -> Result<BearerToken, CredentialStoreError> {
        Err(CredentialStoreError::UnsupportedPlatform)
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
    InvalidDescriptor,
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
            Self::InvalidDescriptor => "credential descriptor is invalid",
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
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
        Ok(value) => {
            let value = Zeroizing::new(value);
            BearerToken::new(value.as_str().to_owned())
                .map(Some)
                .map_err(|_| CredentialStoreError::InvalidToken)
        }
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

    #[test]
    fn token_does_not_debug_print() {
        let token = BearerToken::new("top-secret").expect("token");
        assert!(!format!("{token:?}").contains("top-secret"));
        assert!(!format!("{token}").contains("top-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn origin_isolation_uses_distinct_records() {
        let root = std::env::temp_dir().join(format!("nazo-conformance-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = CredentialStore::new(&root).expect("store");
        let first = Origin::parse("https://suite-one.example").expect("origin");
        let second = Origin::parse("https://suite-two.example").expect("origin");
        let token = BearerToken::new("token-one").expect("token");
        store.save(&first, &token).expect("save");
        assert!(store.load(&second).expect("load").is_none());
        assert_eq!(
            store.load(&first).expect("load").expect("token").as_str(),
            "token-one"
        );
        let _ = fs::remove_dir_all(root);
    }
}
