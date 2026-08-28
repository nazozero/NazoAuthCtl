//! Local Controller Key store: one private key directory per deployment
//! (goal plan 04 §2, task D03).
//!
//! Invariants enforced here:
//!
//! * Private material exists only inside `keys/<kid>.json` records under the
//!   instance directory, written atomically at creation and never rewritten.
//! * `active.json` is a separate pointer file; selecting a different kid is
//!   one atomic pointer write, so a crash can never produce half an active
//!   key and candidate keys never become authoritative implicitly.
//! * Loading validates the full chain every time: secure regular-file read,
//!   strict schema, base64url lengths, derived-kid equality with both the
//!   record field and the filename, and public/private consistency. Any
//!   drift fails closed instead of being repaired.
//! * Diagnostics ([`ControllerKeySummary`]) expose only public material:
//!   kid, public key, creation time, active flag.

use std::{fs, path::PathBuf};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use fs2::FileExt as _;
use nazo_operator_protocol::controller_key_id;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::error_codes::STATE_RESET_REQUIRED;
use crate::filesystem;

/// Schema discriminator carried by every persisted controller-key record.
pub const CONTROLLER_KEY_STORE_SCHEMA: u32 = 1;

/// Unpadded base64url length of an Ed25519 raw public key (32 bytes).
pub const PUBLIC_KEY_B64_LENGTH: usize = 43;

/// Unpadded base64url length of the SHA-256 digest of a raw public key.
const KID_LENGTH: usize = 43;

/// Upper bound for one key record (~4 KiB); real records are ~400 bytes.
const MAX_KEY_RECORD_BYTES: u64 = 4096;

/// Upper bound for the active-pointer record.
const MAX_ACTIVE_POINTER_BYTES: u64 = 1024;

/// Registry-side reference format pointing at one instance's key directory
/// (authority ADR row 2/3: reference only, never key material).
pub(crate) const KEY_REF_SCHEME: &str = "controller-keys";

/// Build the canonical [`crate::registry::InstanceRecord::controller_key_ref`]
/// value for a deployment. The ref is a locator; it carries no key bytes.
pub fn controller_key_ref_for(deployment_id: &str) -> anyhow::Result<String> {
    validate_instance_identifier(deployment_id)?;
    Ok(format!("{KEY_REF_SCHEME}/{deployment_id}"))
}

/// Validate a deployment identifier used as a key-store directory name. The
/// charset matches the registry's identifier rule, so any registry-legal
/// deployment id is store-legal too.
pub(crate) fn validate_instance_identifier(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
        || value == "."
        || value == ".."
    {
        bail!(
            "deployment identifier must be 1-128 characters from [A-Za-z0-9.:_+-] without \
             path separators"
        );
    }
    Ok(())
}

/// Validate the unpadded base64url shape of a kid (43 characters). The value
/// itself is re-derived from key material on load; this check only bounds the
/// string before it is used in paths or comparisons.
pub(super) fn validate_kid_shape(kid: &str) -> anyhow::Result<()> {
    if kid.len() != KID_LENGTH
        || !kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("kid must be unpadded base64url SHA-256 of the raw public key");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    schema: u32,
    kid: String,
    /// Unpadded base64url of the raw Ed25519 verifying key (32 bytes).
    public_key: String,
    /// Unpadded base64url of the raw Ed25519 seed (32 bytes). This is the
    /// only secret field in the store.
    private_key: String,
    created_at: DateTime<Utc>,
}

impl KeyRecord {
    /// Public-material view for diagnostics; never includes the seed.
    fn summary(&self, active: bool) -> ControllerKeySummary {
        ControllerKeySummary {
            kid: self.kid.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at,
            active,
        }
    }
}

/// Public-material diagnostics for one stored key. Safe to print: no
/// private bytes exist on this type by construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerKeySummary {
    pub kid: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivePointer {
    schema: u32,
    active_kid: String,
}

/// A loaded active signing identity. The Ed25519 seed lives inside
/// [`SigningKey`], which zeroizes its secret scalar on drop; no accessor
/// exposes private bytes.
#[derive(Clone)]
pub struct LoadedControllerKey {
    kid: String,
    signing_key: SigningKey,
}

impl LoadedControllerKey {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl std::fmt::Debug for LoadedControllerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedControllerKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A key record after full load-time validation: usable signing identity
/// plus its public diagnostics.
struct ValidatedKeyRecord {
    loaded: LoadedControllerKey,
    public_key: String,
    created_at: DateTime<Utc>,
}

/// Exclusive per-instance lock held across a store operation.
struct InstanceKeyLock {
    file: fs::File,
}

impl InstanceKeyLock {
    fn acquire(path: &std::path::Path) -> anyhow::Result<Self> {
        let file = filesystem::open_lock_file(path, false, "controller key lock")?;
        file.try_lock_exclusive()
            .with_context(|| format!("another operation holds {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for InstanceKeyLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Handle to the user-scoped per-instance Controller Key store.
#[derive(Clone, Debug)]
pub struct ControllerKeyStore {
    root: PathBuf,
}

impl ControllerKeyStore {
    /// Open (creating if needed) the store root at `root`.
    pub fn open(root: PathBuf) -> anyhow::Result<Self> {
        filesystem::ensure_private_directory(&root, "controller key store root")?;
        Ok(Self { root })
    }

    /// Platform default location:
    /// `%APPDATA%\nazoauthctl\controller-keys` on Windows,
    /// `$XDG_CONFIG_HOME/nazoauthctl/controller-keys` or
    /// `$HOME/.config/nazoauthctl/controller-keys` elsewhere — the sibling of
    /// [`crate::registry::RegistryStore::default_root`].
    pub fn default_root() -> anyhow::Result<PathBuf> {
        Ok(crate::registry::config_root()?
            .join("nazoauthctl")
            .join("controller-keys"))
    }

    /// Open the store at the platform default location.
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(Self::default_root()?)
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Directory holding one instance's keys. Created lazily by write
    /// operations; read operations treat a missing directory as unbound.
    pub fn instance_dir(&self, deployment_id: &str) -> anyhow::Result<PathBuf> {
        validate_instance_identifier(deployment_id)?;
        Ok(self.instance_dir_unchecked(deployment_id))
    }

    fn instance_dir_unchecked(&self, deployment_id: &str) -> PathBuf {
        self.root.join(deployment_id)
    }

    fn keys_dir(dir: &std::path::Path) -> PathBuf {
        dir.join("keys")
    }

    fn key_path(dir: &std::path::Path, kid: &str) -> PathBuf {
        Self::keys_dir(dir).join(format!("{kid}.json"))
    }

    fn active_path(dir: &std::path::Path) -> PathBuf {
        dir.join("active.json")
    }

    fn lock_path(dir: &std::path::Path) -> PathBuf {
        dir.join("keys.lock")
    }

    /// Mint a fresh keypair from a CSPRNG seeded by OS entropy and persist it
    /// as a candidate: the active pointer is untouched. Rotation (D07) and
    /// first bind (D04) build on this primitive.
    pub fn generate_candidate(&self, deployment_id: &str) -> anyhow::Result<ControllerKeySummary> {
        validate_instance_identifier(deployment_id)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        filesystem::ensure_private_directory(&dir, "controller key directory")?;
        filesystem::ensure_private_directory(
            &Self::keys_dir(&dir),
            "controller key material directory",
        )?;
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        self.generate_candidate_locked(&dir)
    }

    fn generate_candidate_locked(
        &self,
        dir: &std::path::Path,
    ) -> anyhow::Result<ControllerKeySummary> {
        // rand's ThreadRng is reseeded from the OS entropy source; the code
        // base uses the same generator for persisted secrets.
        let mut seed: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&seed);
        let private_text = URL_SAFE_NO_PAD.encode(seed);
        seed.zeroize();
        let verifying_key = signing_key.verifying_key();
        let kid = controller_key_id(&verifying_key);
        let record = KeyRecord {
            schema: CONTROLLER_KEY_STORE_SCHEMA,
            kid: kid.clone(),
            public_key: URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
            private_key: private_text,
            created_at: Utc::now(),
        };
        let path = Self::key_path(dir, &kid);
        if fs::symlink_metadata(&path).is_ok() {
            bail!(
                "controller key record already exists; refusing to overwrite ({})",
                path.display()
            );
        }
        let bytes = serde_json::to_vec_pretty(&record)
            .context("failed to serialize controller key record")?;
        filesystem::atomic_write(&path, &bytes, 0o600)
            .with_context(|| format!("failed to persist controller key {}", path.display()))?;
        drop(signing_key);
        Ok(record.summary(false))
    }

    /// Atomically point the instance at `kid`. The target key must already be
    /// stored and fully valid. This is the single switch point rotation (D07)
    /// will reuse; no ceremony lives here.
    pub fn set_active_kid(&self, deployment_id: &str, kid: &str) -> anyhow::Result<()> {
        validate_instance_identifier(deployment_id)?;
        validate_kid_shape(kid)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        self.set_active_kid_locked(&dir, kid)
    }

    fn set_active_kid_locked(&self, dir: &std::path::Path, kid: &str) -> anyhow::Result<()> {
        // Load the full record so an invalid or missing target fails before
        // the pointer moves.
        self.read_key_record(dir, kid)?;
        let pointer = ActivePointer {
            schema: CONTROLLER_KEY_STORE_SCHEMA,
            active_kid: kid.to_owned(),
        };
        let bytes = serde_json::to_vec_pretty(&pointer)
            .context("failed to serialize active controller key pointer")?;
        filesystem::atomic_write(&Self::active_path(dir), &bytes, 0o600)
            .with_context(|| "failed to persist active controller key pointer".to_owned())
    }

    /// Load the active signing identity, or `None` when the instance has no
    /// bound key yet. Present-but-invalid state fails closed; absence does
    /// not, because unbound instances are a normal pre-bind condition.
    pub fn load_active(&self, deployment_id: &str) -> anyhow::Result<Option<LoadedControllerKey>> {
        validate_instance_identifier(deployment_id)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        match self.read_active_pointer(&dir)? {
            Some(pointer) => Ok(Some(
                self.read_key_record(&dir, &pointer.active_kid)?.loaded,
            )),
            None => Ok(None),
        }
    }

    /// Idempotent get-or-create: return the active key, minting and
    /// activating exactly one new key iff none exists. Repeated calls return
    /// the same identity.
    pub fn get_or_create_active(&self, deployment_id: &str) -> anyhow::Result<LoadedControllerKey> {
        if let Some(loaded) = self.load_active(deployment_id)? {
            return Ok(loaded);
        }
        validate_instance_identifier(deployment_id)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        filesystem::ensure_private_directory(&dir, "controller key directory")?;
        filesystem::ensure_private_directory(
            &Self::keys_dir(&dir),
            "controller key material directory",
        )?;
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        // Re-check under the lock: a concurrent creator may have finished
        // between the unlocked probe and now.
        if let Some(pointer) = self.read_active_pointer(&dir)? {
            return self
                .read_key_record(&dir, &pointer.active_kid)
                .map(|validated| validated.loaded);
        }
        let candidate = self.generate_candidate_locked(&dir)?;
        self.set_active_kid_locked(&dir, &candidate.kid)?;
        let pointer = self
            .read_active_pointer(&dir)?
            .expect("active pointer was just written");
        Ok(self.read_key_record(&dir, &pointer.active_kid)?.loaded)
    }

    /// List all stored keys of an instance with public material only,
    /// sorted by creation time. Any non-conforming record fails closed.
    pub fn list_keys(&self, deployment_id: &str) -> anyhow::Result<Vec<ControllerKeySummary>> {
        validate_instance_identifier(deployment_id)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        let keys_dir = Self::keys_dir(&dir);
        if fs::symlink_metadata(&keys_dir).is_err() {
            return Ok(Vec::new());
        }
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        let active_kid = match self.read_active_pointer(&dir)? {
            Some(pointer) => Some(pointer.active_kid),
            None => None,
        };
        let mut summaries = Vec::new();
        for entry in fs::read_dir(&keys_dir)
            .with_context(|| format!("failed to list {}", keys_dir.display()))?
        {
            let entry = entry.with_context(|| format!("failed to list {}", keys_dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .with_context(|| format!("unreadable key record name {}", path.display()))?
                .to_owned();
            let validated = self.read_key_record(&dir, &stem)?;
            summaries.push(ControllerKeySummary {
                kid: validated.loaded.kid().to_owned(),
                public_key: validated.public_key,
                created_at: validated.created_at,
                active: active_kid.as_deref() == Some(stem.as_str()),
            });
        }
        summaries.sort_by_key(|summary| summary.created_at);
        Ok(summaries)
    }

    /// Atomically remove the active pointer, returning the instance to the
    /// unbound state while keeping every key record on disk. Used after a
    /// confirmed self-revocation (task D08): deleting key files while a
    /// pointer still names them would brick loads with fail-closed errors, so
    /// the pointer goes first.
    pub fn clear_active(&self, deployment_id: &str) -> anyhow::Result<()> {
        validate_instance_identifier(deployment_id)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        let path = Self::active_path(&dir);
        if fs::symlink_metadata(&path).is_err() {
            return Ok(());
        }
        filesystem::remove_file_durable(&path)
            .with_context(|| format!("failed to clear {}", path.display()))
    }

    /// Newest non-active candidate kid, or `None` when every stored key is
    /// active (or none exist). Bind resume reuses this candidate instead of
    /// minting another keypair for a repeated proposal (task D04).
    pub fn newest_candidate_kid(&self, deployment_id: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .list_keys(deployment_id)?
            .into_iter()
            .filter(|summary| !summary.active)
            .max_by_key(|summary| summary.created_at)
            .map(|summary| summary.kid))
    }

    /// Durable local retirement of one non-active key record (tasks D07/D08):
    /// the old private key is unlinked only after callers have confirmed the
    /// server-side change. The active pointer can never be retired through
    /// this method; switching first and retiring second keeps a crash window
    /// where both records still exist but never one where none does.
    pub fn retire_kid(&self, deployment_id: &str, kid: &str) -> anyhow::Result<()> {
        validate_instance_identifier(deployment_id)?;
        validate_kid_shape(kid)?;
        let dir = self.instance_dir_unchecked(deployment_id);
        let _lock = InstanceKeyLock::acquire(&Self::lock_path(&dir))?;
        if let Some(pointer) = self.read_active_pointer(&dir)?
            && pointer.active_kid == kid
        {
            bail!(
                "refusing to retire controller key '{kid}' while it is still the active \
                 identity; switch the active pointer first"
            );
        }
        // Validate the full record before unlinking so retirement never
        // destroys material whose identity was not proven.
        self.read_key_record(&dir, kid)?;
        let path = Self::key_path(&dir, kid);
        filesystem::remove_file_durable(&path)
            .with_context(|| format!("failed to retire controller key {}", path.display()))
    }

    fn read_active_pointer(&self, dir: &std::path::Path) -> anyhow::Result<Option<ActivePointer>> {
        let path = Self::active_path(dir);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect active controller key pointer {}",
                        path.display()
                    )
                });
            }
        }
        let bytes = filesystem::read_secure_regular_file(
            &path,
            "active controller key pointer",
            true,
            MAX_ACTIVE_POINTER_BYTES,
        )
        .map_err(|error| {
            error.context(format!(
                "{STATE_RESET_REQUIRED}: active controller key pointer is unreadable, unsafe, \
                 or exceeds the size limit ({})",
                path.display()
            ))
        })?;
        let pointer: ActivePointer = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "{STATE_RESET_REQUIRED}: active controller key pointer does not parse as \
                     the current schema ({})",
                path.display()
            ))
        })?;
        if pointer.schema != CONTROLLER_KEY_STORE_SCHEMA {
            bail!(
                "{STATE_RESET_REQUIRED}: unsupported active pointer schema {} ({})",
                pointer.schema,
                path.display()
            );
        }
        validate_kid_shape(&pointer.active_kid).map_err(|error| {
            error.context(format!(
                "{STATE_RESET_REQUIRED}: active pointer names an invalid kid ({})",
                path.display()
            ))
        })?;
        Ok(Some(pointer))
    }

    /// Load and fully validate one key record: secure read, strict schema,
    /// filename/record/kid agreement, and public/private consistency.
    fn read_key_record(
        &self,
        dir: &std::path::Path,
        kid: &str,
    ) -> anyhow::Result<ValidatedKeyRecord> {
        validate_kid_shape(kid)?;
        let path = Self::key_path(dir, kid);
        let fail = |error: anyhow::Error| {
            error.context(format!(
                "{STATE_RESET_REQUIRED}: controller key record is corrupt, unsafe to read, or \
                 does not conform ({})",
                path.display()
            ))
        };
        let bytes = filesystem::read_secure_regular_file(
            &path,
            "controller private key record",
            true,
            MAX_KEY_RECORD_BYTES,
        )
        .map_err(fail)?;
        let record: KeyRecord =
            serde_json::from_slice(&bytes).map_err(|error| fail(anyhow::Error::new(error)))?;
        if record.schema != CONTROLLER_KEY_STORE_SCHEMA {
            bail!(
                "{STATE_RESET_REQUIRED}: unsupported controller key record schema {} ({})",
                record.schema,
                path.display()
            );
        }
        if record.kid != kid {
            bail!(
                "{STATE_RESET_REQUIRED}: controller key record kid '{}' does not match its \
                 filename '{}'",
                record.kid,
                kid
            );
        }
        let private_seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(record.private_key.as_bytes())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .with_context(|| {
                format!(
                    "{STATE_RESET_REQUIRED}: controller key record private material is not \
                     32 base64url bytes ({})",
                    path.display()
                )
            })?;
        let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(record.public_key.as_bytes())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .with_context(|| {
                format!(
                    "{STATE_RESET_REQUIRED}: controller key record public material is not 32 \
                     base64url bytes ({})",
                    path.display()
                )
            })?;
        let signing_key = SigningKey::from_bytes(&private_seed);
        let verifying_key = signing_key.verifying_key();
        let derived_kid = controller_key_id(&verifying_key);
        if derived_kid != record.kid {
            bail!(
                "{STATE_RESET_REQUIRED}: stored private key derives kid '{}' but the record \
                 claims '{}'; refusing to sign with mismatched material ({})",
                derived_kid,
                record.kid,
                path.display()
            );
        }
        if verifying_key.to_bytes() != public_bytes {
            bail!(
                "{STATE_RESET_REQUIRED}: stored public key does not match the private key ({})",
                path.display()
            );
        }
        Ok(ValidatedKeyRecord {
            loaded: LoadedControllerKey {
                kid: record.kid,
                signing_key,
            },
            public_key: record.public_key,
            created_at: record.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, Verifier as _};

    fn test_store() -> anyhow::Result<(filesystem::PrivateTempDir, ControllerKeyStore)> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-controller-keys-test")?;
        let store = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        Ok((temp, store))
    }

    #[test]
    fn get_or_create_is_idempotent() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let first = store.get_or_create_active("deploy-alpha")?;
        let second = store.get_or_create_active("deploy-alpha")?;
        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.verifying_key(), second.verifying_key());
        assert_eq!(first.signing_key.to_bytes(), second.signing_key.to_bytes());

        let summaries = store.list_keys("deploy-alpha")?;
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].active);
        assert_eq!(summaries[0].kid, first.kid());
        assert_eq!(summaries[0].public_key.len(), PUBLIC_KEY_B64_LENGTH);
        Ok(())
    }

    #[test]
    fn candidates_never_become_active_implicitly() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        assert!(store.load_active("deploy-alpha")?.is_none());

        let first = store.generate_candidate("deploy-alpha")?;
        assert!(!first.active);
        assert!(store.load_active("deploy-alpha")?.is_none());

        let second = store.generate_candidate("deploy-alpha")?;
        assert_ne!(first.kid, second.kid, "each candidate is a fresh keypair");
        assert_eq!(store.list_keys("deploy-alpha")?.len(), 2);

        store.set_active_kid("deploy-alpha", &second.kid)?;
        let loaded = store.load_active("deploy-alpha")?.expect("active key");
        assert_eq!(loaded.kid(), second.kid);

        let summaries = store.list_keys("deploy-alpha")?;
        let active: Vec<_> = summaries.iter().filter(|s| s.active).collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kid, second.kid);
        Ok(())
    }

    #[test]
    fn corrupt_record_fails_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        // Activation happens while the record is intact...
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        assert!(store.load_active("deploy-alpha")?.is_some());
        // ...then on-disk corruption must fail closed, not fall back.
        let path = store
            .instance_dir("deploy-alpha")?
            .join("keys")
            .join(format!("{}.json", summary.kid));
        filesystem::atomic_write(&path, b"{ not json", 0o600)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("corrupt record must fail closed");
        assert!(
            format!("{error:#}").contains(STATE_RESET_REQUIRED),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn truncated_record_fails_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        let path = store
            .instance_dir("deploy-alpha")?
            .join("keys")
            .join(format!("{}.json", summary.kid));
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": CONTROLLER_KEY_STORE_SCHEMA,
            "kid": summary.kid,
            "public_key": summary.public_key,
            "private_key": "AAAA",
            "created_at": summary.created_at
        }))?;
        filesystem::atomic_write(&path, &bytes[..bytes.len() / 2], 0o600)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("truncated record must fail closed");
        assert!(
            format!("{error:#}").contains(STATE_RESET_REQUIRED),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn oversize_record_fails_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        let path = store
            .instance_dir("deploy-alpha")?
            .join("keys")
            .join(format!("{}.json", summary.kid));
        filesystem::atomic_write(&path, &[b'x'; (MAX_KEY_RECORD_BYTES + 1) as usize], 0o600)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("oversize record must fail closed");
        assert!(
            format!("{error:#}").contains(STATE_RESET_REQUIRED),
            "{error:#}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_record_fails_closed() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        let path = store
            .instance_dir("deploy-alpha")?
            .join("keys")
            .join(format!("{}.json", summary.kid));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("world-readable private key must fail closed");
        assert!(format!("{error:#}").contains("owner-readable"), "{error:#}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_record_fails_closed() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        let dir = store.instance_dir("deploy-alpha")?;
        let path = dir.join("keys").join(format!("{}.json", summary.kid));
        let outside = std::env::temp_dir().join(format!(
            "nazauthctl-key-target-{}.json",
            uuid::Uuid::now_v7()
        ));
        fs::rename(&path, &outside)?;
        symlink(&outside, &path)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("symlinked key must fail closed");
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        let _ = fs::remove_file(&outside);
        Ok(())
    }

    #[test]
    fn tampered_kid_and_material_fail_closed() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let summary = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &summary.kid)?;
        let dir = store.instance_dir("deploy-alpha")?;

        // Record whose kid field points somewhere else (valid 43-char shape).
        let other = store.generate_candidate("deploy-beta")?;
        let path = dir.join("keys").join(format!("{}.json", summary.kid));
        let swapped = serde_json::json!({
            "schema": CONTROLLER_KEY_STORE_SCHEMA,
            "kid": other.kid,
            "public_key": summary.public_key,
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "created_at": summary.created_at
        });
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&swapped)?, 0o600)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("kid/filename mismatch must fail closed");
        assert!(format!("{error:#}").contains("filename"), "{error:#}");

        // Restore a consistent-looking record whose private key does not
        // derive the claimed kid.
        let wrong_seed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let inconsistent = serde_json::json!({
            "schema": CONTROLLER_KEY_STORE_SCHEMA,
            "kid": summary.kid,
            "public_key": summary.public_key,
            "private_key": URL_SAFE_NO_PAD.encode(wrong_seed.to_bytes()),
            "created_at": summary.created_at
        });
        filesystem::atomic_write(&path, &serde_json::to_vec_pretty(&inconsistent)?, 0o600)?;
        let error = store
            .load_active("deploy-alpha")
            .expect_err("material/kid mismatch must fail closed");
        assert!(format!("{error:#}").contains("derives kid"), "{error:#}");
        Ok(())
    }

    #[test]
    fn instances_are_isolated() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let alpha = store.get_or_create_active("deploy-alpha")?;
        let beta = store.get_or_create_active("deploy-beta")?;
        assert_ne!(alpha.kid(), beta.kid());
        assert_ne!(
            alpha.signing_key.to_bytes(),
            beta.signing_key.to_bytes(),
            "per-instance keys are independent"
        );

        let message = b"instance isolation probe";
        let alpha_signature = alpha.signing_key.sign(message);
        assert!(
            beta.verifying_key()
                .verify(message, &alpha_signature)
                .is_err(),
            "one instance's key must not verify another instance's signature"
        );
        assert_eq!(
            store.list_keys("deploy-alpha")?.len(),
            1,
            "no cross-instance bleed"
        );
        Ok(())
    }

    #[test]
    fn invalid_identifiers_are_rejected_before_touching_disk() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        for bad in ["../evil", "a/b", "", ".", "..", "has space"] {
            assert!(
                store.generate_candidate(bad).is_err(),
                "identifier '{bad}' must be rejected"
            );
            assert!(
                store.load_active(bad).is_err(),
                "identifier '{bad}' must be rejected"
            );
        }
        assert!(store.root().read_dir()?.next().is_none(), "nothing written");
        Ok(())
    }

    #[test]
    fn canonical_ref_format_round_trips() -> anyhow::Result<()> {
        let reference = controller_key_ref_for("deploy-alpha")?;
        assert_eq!(reference, "controller-keys/deploy-alpha");
        assert!(controller_key_ref_for("../evil").is_err());
        assert!(controller_key_ref_for("").is_err());
        Ok(())
    }

    #[test]
    fn retirement_refuses_active_kids_and_durable_unlinks_candidates() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let active = store.get_or_create_active("deploy-alpha")?;
        let candidate = store.generate_candidate("deploy-alpha")?;

        // Active material can never be retired through this path.
        let error = store
            .retire_kid("deploy-alpha", active.kid())
            .expect_err("active kid");
        assert!(error.to_string().contains("refusing to retire"), "{error}");
        assert!(
            store.load_active("deploy-alpha")?.is_some(),
            "active key untouched"
        );

        store.retire_kid("deploy-alpha", &candidate.kid)?;
        assert_eq!(
            store.list_keys("deploy-alpha")?.len(),
            1,
            "candidate durably removed"
        );
        // Retiring an unknown kid fails instead of silently succeeding.
        assert!(store.retire_kid("deploy-alpha", &candidate.kid).is_err());
        Ok(())
    }

    #[test]
    fn clear_active_returns_to_unbound_while_keeping_material() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        let active = store.get_or_create_active("deploy-alpha")?;
        store.clear_active("deploy-alpha")?;
        assert!(store.load_active("deploy-alpha")?.is_none());
        // Material survives so diagnostics can still enumerate it; a later
        // bind may adopt it back if the server still lists the kid.
        assert_eq!(store.list_keys("deploy-alpha")?.len(), 1);
        assert!(!store.list_keys("deploy-alpha")?[0].active);
        assert_eq!(
            store.newest_candidate_kid("deploy-alpha")?,
            Some(active.kid().to_owned())
        );
        store.clear_active("deploy-alpha")?; // idempotent
        Ok(())
    }

    #[test]
    fn newest_candidate_prefers_the_freshest_non_active_record() -> anyhow::Result<()> {
        let (_temp, store) = test_store()?;
        assert!(store.newest_candidate_kid("deploy-alpha")?.is_none());

        let first = store.get_or_create_active("deploy-alpha")?;
        assert!(
            store.newest_candidate_kid("deploy-alpha")?.is_none(),
            "an all-active instance has no candidate"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = store.generate_candidate("deploy-alpha")?;
        assert_eq!(
            store.newest_candidate_kid("deploy-alpha")?,
            Some(second.kid.clone())
        );

        // After activating the newest candidate it stops being a candidate;
        // the previously active key is superseded into one, so the freshest
        // candidate is the third key.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let third = store.generate_candidate("deploy-alpha")?;
        store.set_active_kid("deploy-alpha", &second.kid)?;
        assert_eq!(store.newest_candidate_kid("deploy-alpha")?, Some(third.kid));
        assert_ne!(first.kid(), second.kid);
        Ok(())
    }
}
