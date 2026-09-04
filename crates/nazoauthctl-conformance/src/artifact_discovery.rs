use std::{
    collections::BTreeSet,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactError, ArtifactTrustPolicy, MAX_ARTIFACT_DRIVER_BYTES, MAX_ARTIFACT_MATRIX_BYTES,
    MAX_SIGNED_DRIVER_BYTES, OidfDriverInspectionPlan, OidfPlanError, OidfPlanSelection,
    VerifiedOidfArtifact, artifact::verify_oidf_matrix_with_driver,
    artifact_plan::compile_oidf_driver_inspection_plan, verify_oidf_artifact,
    verify_oidf_driver_manifest,
};

pub const OIDF_ARTIFACT_CACHE_SCHEMA_VERSION: u32 = 5;
pub const OIDF_ARTIFACT_CACHE_MAX_ENTRIES: usize = 64;
pub const OIDF_ARTIFACT_CACHE_MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
const CACHE_RECORD_SCHEMA: u32 = OIDF_ARTIFACT_CACHE_SCHEMA_VERSION;
const MAX_CACHE_RECORD_BYTES: usize = 128 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_LOCK_RETRY: Duration = Duration::from_millis(25);
static CACHE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedOidfArtifact {
    pub schema: u32,
    pub manifest_url: String,
    pub resolved_at: i64,
    pub cache_entry: PathBuf,
    pub cache_hit: bool,
    pub artifact: VerifiedOidfArtifact,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachedOidfArtifact {
    pub schema: u32,
    pub manifest_url: String,
    pub opened_at: i64,
    pub cache_entry: PathBuf,
    pub artifact: VerifiedOidfArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    schema: u32,
    manifest_url: String,
    artifact: VerifiedOidfArtifact,
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactDiscoveryError {
    #[error("artifact manifest URL is outside the trusted source")]
    UntrustedManifestUrl,
    #[error("artifact HTTPS client could not be initialized")]
    Client,
    #[error("artifact HTTPS request failed")]
    Network,
    #[error("artifact HTTPS response status is not successful")]
    HttpStatus,
    #[error("artifact HTTPS response exceeds its signed or policy size bound")]
    Oversize,
    #[error("artifact HTTPS response is not a compact UTF-8 manifest")]
    ManifestEncoding,
    #[error("artifact verification failed: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("artifact cache path is unsafe or unsupported")]
    UnsafeCache,
    #[error("artifact cache operation failed")]
    CacheIo,
    #[error("artifact cache transaction lock could not be acquired in time")]
    CacheBusy,
    #[error("artifact cache capacity policy rejects a new write")]
    CacheCapacity,
    #[error("artifact cache contains a conflicting committed entry")]
    CacheConflict,
    #[error("artifact cache record is malformed")]
    CacheRecord,
    #[error("artifact manifest digest must be 64 lowercase hexadecimal characters")]
    InvalidManifestDigest,
    #[error("artifact cache entry failed immutable identity verification")]
    CacheIdentity,
    #[error("verified artifact driver plan is invalid: {0}")]
    Plan(#[from] OidfPlanError),
}

pub fn open_cached_oidf_artifact(
    cache_root: &Path,
    manifest_digest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<CachedOidfArtifact, ArtifactDiscoveryError> {
    open_cached_entry(
        cache_root,
        manifest_digest,
        trust,
        available_capabilities,
        now,
    )
    .map(|(cached, _, _)| cached)
}

pub fn open_cached_oidf_driver_plan(
    cache_root: &Path,
    manifest_digest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    selection: OidfPlanSelection,
    now: i64,
) -> Result<OidfDriverInspectionPlan, ArtifactDiscoveryError> {
    let (cached, driver, matrix) = open_cached_entry(
        cache_root,
        manifest_digest,
        trust,
        available_capabilities,
        now,
    )?;
    Ok(compile_oidf_driver_inspection_plan(
        cached,
        &driver,
        &matrix,
        available_capabilities,
        selection,
        now,
    )?)
}

fn open_cached_entry(
    cache_root: &Path,
    manifest_digest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<(CachedOidfArtifact, Vec<u8>, Vec<u8>), ArtifactDiscoveryError> {
    if !cache_root.is_absolute() || cache_root.file_name().is_none() {
        return Err(ArtifactDiscoveryError::UnsafeCache);
    }
    if !is_lowercase_sha256(manifest_digest) {
        return Err(ArtifactDiscoveryError::InvalidManifestDigest);
    }

    crate::secure_file::validate_directory(cache_root, true).map_err(map_cache_file_error)?;
    let artifacts = cache_root.join("artifacts");
    crate::secure_file::validate_directory(&artifacts, true).map_err(map_cache_file_error)?;
    let cache_entry = artifacts.join(manifest_digest);
    crate::secure_file::validate_directory(&cache_entry, true).map_err(map_cache_file_error)?;
    let record_bytes = read_cache(&cache_entry.join("verified.json"), MAX_CACHE_RECORD_BYTES)?;
    let compact_manifest = read_cache(&cache_entry.join("manifest.jws"), MAX_SIGNED_DRIVER_BYTES)?;
    let driver = read_cache(&cache_entry.join("driver.json"), MAX_ARTIFACT_DRIVER_BYTES)?;
    let matrix = read_cache(&cache_entry.join("matrix.json"), MAX_ARTIFACT_MATRIX_BYTES)?;
    let record = verify_cached_entry(
        CachedVerificationInput {
            record: &record_bytes,
            compact_manifest: &compact_manifest,
            driver: &driver,
            matrix: &matrix,
            manifest_digest,
        },
        trust,
        available_capabilities,
        now,
    )?;

    Ok((
        CachedOidfArtifact {
            schema: OIDF_ARTIFACT_CACHE_SCHEMA_VERSION,
            manifest_url: record.manifest_url,
            opened_at: now,
            cache_entry,
            artifact: record.artifact,
        },
        driver,
        matrix,
    ))
}

pub fn resolve_oidf_artifact(
    manifest_url: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    cache_root: &Path,
    now: i64,
) -> Result<ResolvedOidfArtifact, ArtifactDiscoveryError> {
    if !cache_root.is_absolute() || cache_root.file_name().is_none() {
        return Err(ArtifactDiscoveryError::UnsafeCache);
    }
    let transport = HttpArtifactTransport::new()?;
    let fetched =
        fetch_verified_artifact(&transport, manifest_url, trust, available_capabilities, now)?;
    let (cache_entry, cache_hit) = persist_verified_cache(
        cache_root,
        manifest_url,
        &fetched.compact_manifest,
        &fetched.driver,
        &fetched.matrix,
        &fetched.artifact,
    )?;
    Ok(ResolvedOidfArtifact {
        schema: OIDF_ARTIFACT_CACHE_SCHEMA_VERSION,
        manifest_url: manifest_url.to_owned(),
        resolved_at: now,
        cache_entry,
        cache_hit,
        artifact: fetched.artifact,
    })
}

struct FetchedArtifact {
    compact_manifest: String,
    driver: Vec<u8>,
    matrix: Vec<u8>,
    artifact: VerifiedOidfArtifact,
}

trait ArtifactTransport {
    fn get(&self, url: &str, maximum: u64) -> Result<Vec<u8>, ArtifactDiscoveryError>;
}

struct HttpArtifactTransport {
    client: reqwest::blocking::Client,
}

impl HttpArtifactTransport {
    fn new() -> Result<Self, ArtifactDiscoveryError> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("nazoauthctl/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ArtifactDiscoveryError::Client)?;
        Ok(Self { client })
    }
}

impl ArtifactTransport for HttpArtifactTransport {
    fn get(&self, url: &str, maximum: u64) -> Result<Vec<u8>, ArtifactDiscoveryError> {
        let mut response = self
            .client
            .get(url)
            .send()
            .map_err(|_| ArtifactDiscoveryError::Network)?;
        if !response.status().is_success() {
            return Err(ArtifactDiscoveryError::HttpStatus);
        }
        if response.content_length().is_some_and(|size| size > maximum) {
            return Err(ArtifactDiscoveryError::Oversize);
        }
        let mut bytes = Vec::new();
        (&mut response)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactDiscoveryError::Network)?;
        if bytes.len() as u64 > maximum {
            return Err(ArtifactDiscoveryError::Oversize);
        }
        Ok(bytes)
    }
}

fn fetch_verified_artifact(
    transport: &impl ArtifactTransport,
    manifest_url: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<FetchedArtifact, ArtifactDiscoveryError> {
    if !trust.accepts_url(manifest_url) {
        return Err(ArtifactDiscoveryError::UntrustedManifestUrl);
    }
    let manifest_bytes = transport.get(manifest_url, MAX_SIGNED_DRIVER_BYTES as u64)?;
    let compact_manifest = compact_manifest(&manifest_bytes)?;
    let driver =
        verify_oidf_driver_manifest(&compact_manifest, trust, available_capabilities, now)?;
    let driver_url = driver.driver_url().to_owned();
    let driver_size = driver.driver_size();
    let matrix_url = driver.matrix_url().to_owned();
    let matrix_size = driver.matrix_size();
    if matrix_size == 0 || matrix_size > MAX_ARTIFACT_MATRIX_BYTES as u64 {
        return Err(ArtifactDiscoveryError::Oversize);
    }
    let driver_payload = transport.get(&driver_url, driver_size)?;
    let driver_program = driver.verify_driver_payload(&driver_payload)?;
    let matrix = transport.get(&matrix_url, matrix_size)?;
    let artifact = verify_oidf_matrix_with_driver(driver, driver_program, &matrix)?;
    Ok(FetchedArtifact {
        compact_manifest,
        driver: driver_payload,
        matrix,
        artifact,
    })
}

fn compact_manifest(bytes: &[u8]) -> Result<String, ArtifactDiscoveryError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ArtifactDiscoveryError::ManifestEncoding)?;
    let compact = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if compact.is_empty() || compact.chars().any(char::is_whitespace) {
        return Err(ArtifactDiscoveryError::ManifestEncoding);
    }
    Ok(compact.to_owned())
}

struct CachedVerificationInput<'a> {
    record: &'a [u8],
    compact_manifest: &'a [u8],
    driver: &'a [u8],
    matrix: &'a [u8],
    manifest_digest: &'a str,
}

fn verify_cached_entry(
    input: CachedVerificationInput<'_>,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<CacheRecord, ArtifactDiscoveryError> {
    if !is_lowercase_sha256(input.manifest_digest) {
        return Err(ArtifactDiscoveryError::InvalidManifestDigest);
    }
    let record: CacheRecord =
        serde_json::from_slice(input.record).map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
    if record.schema != CACHE_RECORD_SCHEMA || !trust.accepts_url(&record.manifest_url) {
        return Err(ArtifactDiscoveryError::CacheRecord);
    }

    let compact_manifest = compact_manifest(input.compact_manifest)?;
    let artifact = verify_oidf_artifact(
        &compact_manifest,
        input.driver,
        input.matrix,
        trust,
        available_capabilities,
        now,
    )?;
    if artifact.driver_manifest_sha256 != input.manifest_digest || artifact != record.artifact {
        return Err(ArtifactDiscoveryError::CacheIdentity);
    }
    Ok(record)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn persist_verified_cache(
    root: &Path,
    manifest_url: &str,
    compact_manifest: &str,
    driver: &[u8],
    matrix: &[u8],
    artifact: &VerifiedOidfArtifact,
) -> Result<(PathBuf, bool), ArtifactDiscoveryError> {
    // Advisory file-lock ownership differs across Unix implementations. Keep
    // threads in this process ordered, then use the file lock for other
    // processes that share the cache root.
    let _process_guard = CACHE_PROCESS_LOCK
        .lock()
        .map_err(|_| ArtifactDiscoveryError::CacheIo)?;
    crate::secure_file::ensure_directory(root, true).map_err(map_cache_file_error)?;
    let lock = crate::secure_file::open_lock_file(&root.join(".oidf-cache.lock"), true)
        .map_err(map_cache_file_error)?;
    acquire_cache_lock(&lock)?;

    let artifacts = root.join("artifacts");
    crate::secure_file::ensure_directory(&artifacts, true).map_err(map_cache_file_error)?;
    let (entry_count, entry_exists) =
        cache_inventory(&artifacts, &artifact.driver_manifest_sha256)?;
    if !entry_exists && entry_count >= OIDF_ARTIFACT_CACHE_MAX_ENTRIES {
        return Err(ArtifactDiscoveryError::CacheCapacity);
    }
    let entry = artifacts.join(&artifact.driver_manifest_sha256);
    crate::secure_file::ensure_directory(&entry, true).map_err(map_cache_file_error)?;
    let manifest_path = entry.join("manifest.jws");
    let driver_path = entry.join("driver.json");
    let matrix_path = entry.join("matrix.json");
    let record_path = entry.join("verified.json");
    let expected = CacheRecord {
        schema: CACHE_RECORD_SCHEMA,
        manifest_url: manifest_url.to_owned(),
        artifact: artifact.clone(),
    };
    let record =
        serde_json::to_vec_pretty(&expected).map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
    if record.len() > MAX_CACHE_RECORD_BYTES {
        return Err(ArtifactDiscoveryError::CacheRecord);
    }

    if let Some(record_bytes) = read_optional_cache(&record_path, MAX_CACHE_RECORD_BYTES)? {
        let cached_manifest = read_cache(&manifest_path, MAX_SIGNED_DRIVER_BYTES)?;
        let cached_driver = read_cache(&driver_path, MAX_ARTIFACT_DRIVER_BYTES)?;
        let cached_matrix = read_cache(&matrix_path, MAX_ARTIFACT_MATRIX_BYTES)?;
        let record: CacheRecord = serde_json::from_slice(&record_bytes)
            .map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
        if cached_manifest != compact_manifest.as_bytes()
            || cached_driver != driver
            || cached_matrix != matrix
            || record != expected
        {
            return Err(ArtifactDiscoveryError::CacheConflict);
        }
        return Ok((entry, true));
    }

    enforce_cache_space(
        root,
        compact_manifest.len(),
        driver.len(),
        matrix.len(),
        record.len(),
    )?;
    write_cache(&manifest_path, compact_manifest.as_bytes())?;
    write_cache(&driver_path, driver)?;
    write_cache(&matrix_path, matrix)?;
    // The record is the commit marker. A crash before this write leaves an
    // incomplete entry which is never accepted as verified cache state.
    write_cache(&record_path, &record)?;
    Ok((entry, false))
}

fn acquire_cache_lock(lock: &fs::File) -> Result<(), ArtifactDiscoveryError> {
    let started = Instant::now();
    loop {
        match FileExt::try_lock_exclusive(lock) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= CACHE_LOCK_TIMEOUT {
                    return Err(ArtifactDiscoveryError::CacheBusy);
                }
                thread::sleep(CACHE_LOCK_RETRY);
            }
            Err(_) => return Err(ArtifactDiscoveryError::CacheIo),
        }
    }
}

fn cache_inventory(
    artifacts: &Path,
    target_digest: &str,
) -> Result<(usize, bool), ArtifactDiscoveryError> {
    let mut count = 0usize;
    let mut target_exists = false;
    for entry in fs::read_dir(artifacts).map_err(|_| ArtifactDiscoveryError::CacheIo)? {
        let entry = entry.map_err(|_| ArtifactDiscoveryError::CacheIo)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ArtifactDiscoveryError::UnsafeCache)?;
        let file_type = entry
            .file_type()
            .map_err(|_| ArtifactDiscoveryError::CacheIo)?;
        if !is_lowercase_sha256(&name) || !file_type.is_dir() || file_type.is_symlink() {
            return Err(ArtifactDiscoveryError::UnsafeCache);
        }
        crate::secure_file::validate_directory(&entry.path(), true)
            .map_err(map_cache_file_error)?;
        count = count
            .checked_add(1)
            .ok_or(ArtifactDiscoveryError::CacheCapacity)?;
        target_exists |= name == target_digest;
    }
    Ok((count, target_exists))
}

fn enforce_cache_space(
    root: &Path,
    manifest_size: usize,
    driver_size: usize,
    matrix_size: usize,
    record_size: usize,
) -> Result<(), ArtifactDiscoveryError> {
    let required = u64::try_from(manifest_size)
        .ok()
        .and_then(|value| value.checked_add(u64::try_from(driver_size).ok()?))
        .and_then(|value| value.checked_add(u64::try_from(matrix_size).ok()?))
        .and_then(|value| value.checked_add(u64::try_from(record_size).ok()?))
        .and_then(|value| value.checked_add(OIDF_ARTIFACT_CACHE_MIN_FREE_BYTES))
        .ok_or(ArtifactDiscoveryError::CacheCapacity)?;
    let available = fs2::available_space(root).map_err(|_| ArtifactDiscoveryError::CacheIo)?;
    if available < required {
        return Err(ArtifactDiscoveryError::CacheCapacity);
    }
    Ok(())
}

fn read_optional_cache(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, ArtifactDiscoveryError> {
    match crate::secure_file::read_bounded(path, maximum, true) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(crate::secure_file::SecureFileError::NotFound) => Ok(None),
        Err(error) => Err(map_cache_file_error(error)),
    }
}

fn read_cache(path: &Path, maximum: usize) -> Result<Vec<u8>, ArtifactDiscoveryError> {
    crate::secure_file::read_bounded(path, maximum, true).map_err(map_cache_file_error)
}

fn write_cache(path: &Path, bytes: &[u8]) -> Result<(), ArtifactDiscoveryError> {
    crate::secure_file::write_atomic(path, bytes, true).map_err(map_cache_file_error)
}

fn map_cache_file_error(error: crate::secure_file::SecureFileError) -> ArtifactDiscoveryError {
    match error {
        crate::secure_file::SecureFileError::UnsafePath
        | crate::secure_file::SecureFileError::UnsupportedPlatform => {
            ArtifactDiscoveryError::UnsafeCache
        }
        crate::secure_file::SecureFileError::Oversize => ArtifactDiscoveryError::Oversize,
        crate::secure_file::SecureFileError::NotFound | crate::secure_file::SecureFileError::Io => {
            ArtifactDiscoveryError::CacheIo
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    #[cfg(unix)]
    use std::sync::{Arc, Barrier};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use sha2::{Digest as _, Sha256};

    use crate::{
        OIDF_ARTIFACT_SCHEMA_VERSION, OIDF_DRIVER_ENGINE_PROTOCOL, OIDF_DRIVER_SCHEMA_VERSION,
        OIDF_MATRIX_SCHEMA_VERSION, OIDF_TRUST_POLICY_SCHEMA_VERSION, OidfArtifactMatrix,
        OidfArtifactMatrixGroup, OidfArtifactMatrixPlan, OidfArtifactMatrixVariant,
        OidfDriverAutomation, OidfDriverHandler, OidfDriverIdentity, OidfDriverLane,
        OidfDriverManifest, OidfDriverProgram, OidfMatrixIdentity, OidfPlanResourceBudget,
        OidfResourceBounds, OidfSuiteIdentity,
    };

    use super::*;

    const NOW: i64 = 1_800_000_000;
    const MANIFEST_URL: &str = "https://artifacts.example/oidf/stable/driver.jws";
    const DRIVER_URL: &str = "https://artifacts.example/oidf/v1/driver.json";
    const MATRIX_URL: &str = "https://artifacts.example/oidf/v1/matrix.json";

    struct FakeTransport {
        responses: BTreeMap<String, Vec<u8>>,
        requests: RefCell<Vec<(String, u64)>>,
    }

    impl ArtifactTransport for FakeTransport {
        fn get(&self, url: &str, maximum: u64) -> Result<Vec<u8>, ArtifactDiscoveryError> {
            self.requests.borrow_mut().push((url.to_owned(), maximum));
            let bytes = self
                .responses
                .get(url)
                .cloned()
                .ok_or(ArtifactDiscoveryError::Network)?;
            if bytes.len() as u64 > maximum {
                return Err(ArtifactDiscoveryError::Oversize);
            }
            Ok(bytes)
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[9; 32]).expect("signing key")
    }

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn trust() -> ArtifactTrustPolicy {
        let key = signing_key();
        let point = key.verifying_key().to_sec1_point(true);
        ArtifactTrustPolicy {
            schema: OIDF_TRUST_POLICY_SCHEMA_VERSION,
            source: "https://artifacts.example/oidf/".to_owned(),
            signer_identity: "https://artifacts.example/signers/release-v1".to_owned(),
            key_id: format!("oidf-es256-{}", &digest(point.as_bytes())[..32]),
            public_key_sec1: URL_SAFE_NO_PAD.encode(point.as_bytes()),
        }
    }

    fn matrix() -> Vec<u8> {
        serde_json::to_vec(&OidfArtifactMatrix {
            schema: OIDF_MATRIX_SCHEMA_VERSION,
            name: "matrix".to_owned(),
            openid4vc_credential_datasets: BTreeMap::new(),
            openid4vc_suite_mdoc_trust_anchor_pem: "suite-mdoc-anchor".to_owned(),
            groups: vec![OidfArtifactMatrixGroup {
                id: "oidc".to_owned(),
                profile: "oidc".to_owned(),
                variant: OidfArtifactMatrixVariant {
                    id: "default".to_owned(),
                    values: BTreeMap::new(),
                },
                required_roles: Vec::new(),
                plans: vec![OidfArtifactMatrixPlan {
                    id: "p001".to_owned(),
                    plan: "oidcc-basic-certification-test-plan".to_owned(),
                    driver_handler: "default".to_owned(),
                    resource_budget: OidfPlanResourceBudget {
                        modules: 16,
                        clients: 2,
                        wall_clock_seconds: 300,
                    },
                    config_template: serde_json::json!({"alias":"{{run.alias.oidc-core-p001}}"}),
                    variant: BTreeMap::new(),
                    required_capabilities: vec!["nazoauth.client.create".to_owned()],
                    expected_results: BTreeMap::new(),
                    required_roles: Vec::new(),
                    secret_bindings: BTreeMap::new(),
                    crypto: crate::CryptoPolicy::default(),
                }],
            }],
        })
        .expect("matrix")
    }

    fn driver() -> Vec<u8> {
        serde_json::to_vec(&OidfDriverProgram {
            schema: OIDF_DRIVER_SCHEMA_VERSION,
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            handlers: vec![OidfDriverHandler {
                id: "default".to_owned(),
                automation: OidfDriverAutomation::None,
                lane: OidfDriverLane::Parallel,
            }],
        })
        .expect("driver")
    }

    fn verify_cached_entry(
        record_bytes: &[u8],
        compact_manifest_bytes: &[u8],
        matrix: &[u8],
        manifest_digest: &str,
        trust: &ArtifactTrustPolicy,
        available_capabilities: &BTreeSet<String>,
        now: i64,
    ) -> Result<CacheRecord, ArtifactDiscoveryError> {
        super::verify_cached_entry(
            CachedVerificationInput {
                record: record_bytes,
                compact_manifest: compact_manifest_bytes,
                driver: &driver(),
                matrix,
                manifest_digest,
            },
            trust,
            available_capabilities,
            now,
        )
    }

    fn manifest(matrix: &[u8], expires_at: i64) -> OidfDriverManifest {
        let driver = driver();
        OidfDriverManifest {
            schema: OIDF_ARTIFACT_SCHEMA_VERSION,
            artifact_id: "official-driver".to_owned(),
            revision: "a".repeat(40),
            source: trust().source,
            signer_identity: trust().signer_identity,
            issued_at: NOW - 60,
            not_before: NOW - 30,
            expires_at,
            suite: OidfSuiteIdentity {
                origin: "https://suite.example".to_owned(),
                release: "v5.2.2".to_owned(),
                revision: "b".repeat(40),
                image_digest: format!("sha256:{}", "c".repeat(64)),
            },
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            required_capabilities: vec!["nazoauth.client.create".to_owned()],
            driver: OidfDriverIdentity {
                schema: OIDF_DRIVER_SCHEMA_VERSION,
                url: DRIVER_URL.to_owned(),
                sha256: digest(&driver),
                size: driver.len() as u64,
            },
            matrix: OidfMatrixIdentity {
                schema: OIDF_MATRIX_SCHEMA_VERSION,
                url: MATRIX_URL.to_owned(),
                sha256: digest(matrix),
                size: matrix.len() as u64,
            },
            resource_bounds: OidfResourceBounds {
                max_plans: 16,
                max_modules: 256,
                max_clients: 32,
                max_wall_clock_seconds: 3600,
            },
        }
    }

    fn sign(manifest: &OidfDriverManifest) -> String {
        let key = signing_key();
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "ES256",
                "kid": trust().key_id,
                "typ": "nazoauth-oidf-driver-manifest+jws"
            }))
            .expect("header"),
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(manifest).expect("manifest"));
        let input = format!("{protected}.{payload}");
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn capabilities() -> BTreeSet<String> {
        BTreeSet::from(["nazoauth.client.create".to_owned()])
    }

    fn fake_transport(expires_at: i64) -> FakeTransport {
        let driver = driver();
        let matrix = matrix();
        let compact = sign(&manifest(&matrix, expires_at));
        FakeTransport {
            responses: BTreeMap::from([
                (MANIFEST_URL.to_owned(), compact.into_bytes()),
                (DRIVER_URL.to_owned(), driver),
                (MATRIX_URL.to_owned(), matrix),
            ]),
            requests: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn verifies_manifest_before_downloading_signed_driver_and_matrix_urls() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        assert_eq!(fetched.artifact.suite.release, "v5.2.2");
        assert_eq!(fetched.artifact.suite.origin, "https://suite.example");
        assert_eq!(
            transport.requests.into_inner(),
            vec![
                (MANIFEST_URL.to_owned(), MAX_SIGNED_DRIVER_BYTES as u64),
                (DRIVER_URL.to_owned(), fetched.driver.len() as u64),
                (MATRIX_URL.to_owned(), fetched.matrix.len() as u64),
            ]
        );
    }

    #[test]
    fn rejects_untrusted_channel_and_expired_driver_before_matrix_download() {
        let transport = fake_transport(NOW + 3600);
        assert!(matches!(
            fetch_verified_artifact(
                &transport,
                "https://attacker.example/driver.jws",
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactDiscoveryError::UntrustedManifestUrl)
        ));
        assert!(transport.requests.borrow().is_empty());

        let expired = fake_transport(NOW - 1);
        assert!(matches!(
            fetch_verified_artifact(&expired, MANIFEST_URL, &trust(), &capabilities(), NOW),
            Err(ArtifactDiscoveryError::Artifact(
                ArtifactError::ManifestPolicy(_)
            ))
        ));
        assert_eq!(expired.requests.borrow().len(), 1);

        let unsupported = fake_transport(NOW + 3600);
        assert!(matches!(
            fetch_verified_artifact(&unsupported, MANIFEST_URL, &trust(), &BTreeSet::new(), NOW),
            Err(ArtifactDiscoveryError::Artifact(
                ArtifactError::UnsupportedCapability(_)
            ))
        ));
        assert_eq!(unsupported.requests.borrow().len(), 1);

        let mut tampered_driver = fake_transport(NOW + 3600);
        tampered_driver
            .responses
            .insert(DRIVER_URL.to_owned(), b"tampered".to_vec());
        assert!(matches!(
            fetch_verified_artifact(
                &tampered_driver,
                MANIFEST_URL,
                &trust(),
                &capabilities(),
                NOW
            ),
            Err(ArtifactDiscoveryError::Artifact(
                ArtifactError::DriverPolicy(_)
            ))
        ));
        assert_eq!(tampered_driver.requests.borrow().len(), 2);
    }

    #[test]
    fn production_resolver_rejects_relative_or_root_cache_paths_before_network() {
        for path in [
            Path::new("relative-cache"),
            Path::new(std::path::MAIN_SEPARATOR_STR),
        ] {
            assert!(matches!(
                resolve_oidf_artifact(MANIFEST_URL, &trust(), &capabilities(), path, NOW),
                Err(ArtifactDiscoveryError::UnsafeCache)
            ));
        }
    }

    #[test]
    fn cached_entry_is_reverified_against_current_trust_time_and_capabilities() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let record = CacheRecord {
            schema: CACHE_RECORD_SCHEMA,
            manifest_url: MANIFEST_URL.to_owned(),
            artifact: fetched.artifact.clone(),
        };
        let record_bytes = serde_json::to_vec(&record).expect("cache record");

        let verified = verify_cached_entry(
            &record_bytes,
            fetched.compact_manifest.as_bytes(),
            &fetched.matrix,
            &fetched.artifact.driver_manifest_sha256,
            &trust(),
            &capabilities(),
            NOW + 1,
        )
        .expect("reverified cache");
        assert_eq!(verified, record);

        assert!(matches!(
            verify_cached_entry(
                &record_bytes,
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &fetched.artifact.driver_manifest_sha256.to_uppercase(),
                &trust(),
                &capabilities(),
                NOW + 1,
            ),
            Err(ArtifactDiscoveryError::InvalidManifestDigest)
        ));
        assert!(matches!(
            verify_cached_entry(
                &record_bytes,
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &"0".repeat(64),
                &trust(),
                &capabilities(),
                NOW + 1,
            ),
            Err(ArtifactDiscoveryError::CacheIdentity)
        ));
        let mut tampered_matrix = fetched.matrix.clone();
        tampered_matrix.push(b' ');
        assert!(matches!(
            verify_cached_entry(
                &record_bytes,
                fetched.compact_manifest.as_bytes(),
                &tampered_matrix,
                &fetched.artifact.driver_manifest_sha256,
                &trust(),
                &capabilities(),
                NOW + 1,
            ),
            Err(ArtifactDiscoveryError::Artifact(_))
        ));
        assert!(matches!(
            verify_cached_entry(
                &record_bytes,
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &fetched.artifact.driver_manifest_sha256,
                &trust(),
                &BTreeSet::new(),
                NOW + 1,
            ),
            Err(ArtifactDiscoveryError::Artifact(
                ArtifactError::UnsupportedCapability(_)
            ))
        ));
        assert!(matches!(
            verify_cached_entry(
                &record_bytes,
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &fetched.artifact.driver_manifest_sha256,
                &trust(),
                &capabilities(),
                NOW + 3601,
            ),
            Err(ArtifactDiscoveryError::Artifact(
                ArtifactError::ManifestPolicy(_)
            ))
        ));
    }

    #[test]
    fn cached_entry_rejects_untrusted_or_inconsistent_commit_records() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let mut record = CacheRecord {
            schema: CACHE_RECORD_SCHEMA,
            manifest_url: "https://attacker.example/driver.jws".to_owned(),
            artifact: fetched.artifact.clone(),
        };
        let verify = |record: &CacheRecord, now| {
            verify_cached_entry(
                &serde_json::to_vec(record).expect("cache record"),
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &fetched.artifact.driver_manifest_sha256,
                &trust(),
                &capabilities(),
                now,
            )
        };
        assert!(matches!(
            verify(&record, NOW + 1),
            Err(ArtifactDiscoveryError::CacheRecord)
        ));

        record.manifest_url = MANIFEST_URL.to_owned();
        let mut unknown_field = serde_json::to_value(&record).expect("cache record");
        unknown_field["resolved_at"] = serde_json::json!(NOW);
        assert!(matches!(
            verify_cached_entry(
                &serde_json::to_vec(&unknown_field).expect("cache record with unknown field"),
                fetched.compact_manifest.as_bytes(),
                &fetched.matrix,
                &fetched.artifact.driver_manifest_sha256,
                &trust(),
                &capabilities(),
                NOW + 1,
            ),
            Err(ArtifactDiscoveryError::CacheRecord)
        ));

        record.schema = CACHE_RECORD_SCHEMA + 1;
        assert!(matches!(
            verify(&record, NOW + 1),
            Err(ArtifactDiscoveryError::CacheRecord)
        ));

        record.schema = CACHE_RECORD_SCHEMA;
        record.artifact.matrix_groups += 1;
        assert!(matches!(
            verify(&record, NOW + 1),
            Err(ArtifactDiscoveryError::CacheIdentity)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn offline_open_requires_exact_committed_entry_and_performs_no_write() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical system temp directory");
        let root = temp_root.join(format!("nazo-oidf-open-{}", uuid::Uuid::now_v7()));
        let (entry, _) = persist_verified_cache(
            &root,
            MANIFEST_URL,
            &fetched.compact_manifest,
            &fetched.driver,
            &fetched.matrix,
            &fetched.artifact,
        )
        .expect("persist cache");
        let before = std::fs::metadata(entry.join("verified.json"))
            .expect("record metadata")
            .modified()
            .expect("record modified time");

        let opened = open_cached_oidf_artifact(
            &root,
            &fetched.artifact.driver_manifest_sha256,
            &trust(),
            &capabilities(),
            NOW + 1,
        )
        .expect("open cache");
        assert_eq!(opened.opened_at, NOW + 1);
        assert_eq!(opened.cache_entry, entry);
        assert_eq!(opened.artifact, fetched.artifact);
        assert_eq!(
            std::fs::metadata(opened.cache_entry.join("verified.json"))
                .expect("record metadata")
                .modified()
                .expect("record modified time"),
            before
        );

        let plan = open_cached_oidf_driver_plan(
            &root,
            &opened.artifact.driver_manifest_sha256,
            &trust(),
            &capabilities(),
            OidfPlanSelection {
                groups: vec!["oidc".to_owned()],
                plans: vec!["p001".to_owned()],
                excluded_plans: Vec::new(),
            },
            NOW + 1,
        )
        .expect("compile reverified cached plan");
        assert_eq!(plan.artifact, opened.artifact);
        assert_eq!(plan.selected_group_count, 1);
        assert_eq!(plan.selected_plan_count, 1);
        assert_eq!(
            std::fs::metadata(plan.artifact_cache_entry.join("verified.json"))
                .expect("record metadata")
                .modified()
                .expect("record modified time"),
            before
        );

        std::fs::remove_file(opened.cache_entry.join("verified.json")).expect("remove marker");
        assert!(matches!(
            open_cached_oidf_artifact(
                &root,
                &opened.artifact.driver_manifest_sha256,
                &trust(),
                &capabilities(),
                NOW + 2,
            ),
            Err(ArtifactDiscoveryError::CacheIo)
        ));
        std::fs::remove_dir_all(root).expect("remove test cache");
    }

    #[cfg(unix)]
    #[test]
    fn cache_commits_marker_last_and_rejects_committed_conflicts() {
        use std::os::unix::fs::PermissionsExt as _;

        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical system temp directory");
        let root = temp_root.join(format!("nazo-oidf-cache-{}", uuid::Uuid::now_v7()));
        let (entry, hit) = persist_verified_cache(
            &root,
            MANIFEST_URL,
            &fetched.compact_manifest,
            &fetched.driver,
            &fetched.matrix,
            &fetched.artifact,
        )
        .expect("persist cache");
        assert!(!hit);
        assert!(entry.join("verified.json").is_file());
        for directory in [&root, &root.join("artifacts"), &entry] {
            assert_eq!(
                std::fs::metadata(directory)
                    .expect("private cache directory")
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        assert_eq!(
            std::fs::metadata(root.join(".oidf-cache.lock"))
                .expect("private cache lock")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert!(
            persist_verified_cache(
                &root,
                MANIFEST_URL,
                &fetched.compact_manifest,
                &fetched.driver,
                &fetched.matrix,
                &fetched.artifact,
            )
            .expect("cache hit")
            .1
        );

        std::fs::set_permissions(
            entry.join("matrix.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("permissions");
        std::fs::write(entry.join("matrix.json"), b"tampered").expect("tamper cache");
        assert!(matches!(
            persist_verified_cache(
                &root,
                MANIFEST_URL,
                &fetched.compact_manifest,
                &fetched.driver,
                &fetched.matrix,
                &fetched.artifact,
            ),
            Err(ArtifactDiscoveryError::CacheConflict)
        ));
        std::fs::remove_dir_all(root).expect("remove test cache");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_cache_commit_serializes_one_identity_winner() {
        let transport = fake_transport(NOW + 3600);
        let fetched = Arc::new(
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch"),
        );
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical system temp directory");
        let root = temp_root.join(format!("nazo-oidf-race-{}", uuid::Uuid::now_v7()));
        let barrier = Arc::new(Barrier::new(2));
        let run = |manifest_url: &'static str| {
            let root = root.clone();
            let fetched = Arc::clone(&fetched);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                persist_verified_cache(
                    &root,
                    manifest_url,
                    &fetched.compact_manifest,
                    &fetched.driver,
                    &fetched.matrix,
                    &fetched.artifact,
                )
            })
        };
        let first = run(MANIFEST_URL);
        let second = run("https://artifacts.example/oidf/alternate/driver.jws");
        let outcomes = [
            first.join().expect("first writer"),
            second.join().expect("second writer"),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok((_, false))))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(ArtifactDiscoveryError::CacheConflict)))
                .count(),
            1
        );
        std::fs::remove_dir_all(root).expect("remove test cache");
    }

    #[cfg(unix)]
    #[test]
    fn cache_capacity_fails_closed_without_evicting_existing_entries() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical system temp directory");
        let root = temp_root.join(format!("nazo-oidf-capacity-{}", uuid::Uuid::now_v7()));
        let artifacts = root.join("artifacts");
        crate::secure_file::ensure_directory(&root, true).expect("private cache root");
        crate::secure_file::ensure_directory(&artifacts, true).expect("private artifacts root");
        for index in 0..OIDF_ARTIFACT_CACHE_MAX_ENTRIES {
            crate::secure_file::ensure_directory(&artifacts.join(format!("{index:064x}")), true)
                .expect("bounded cache entry");
        }
        assert!(matches!(
            persist_verified_cache(
                &root,
                MANIFEST_URL,
                &fetched.compact_manifest,
                &fetched.driver,
                &fetched.matrix,
                &fetched.artifact,
            ),
            Err(ArtifactDiscoveryError::CacheCapacity)
        ));
        assert_eq!(
            std::fs::read_dir(&artifacts)
                .expect("artifacts root")
                .count(),
            OIDF_ARTIFACT_CACHE_MAX_ENTRIES
        );
        std::fs::remove_dir_all(root).expect("remove test cache");
    }
}
