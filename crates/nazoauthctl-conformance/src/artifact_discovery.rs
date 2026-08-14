use std::{
    collections::BTreeSet,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    ArtifactError, ArtifactTrustPolicy, MAX_ARTIFACT_MATRIX_BYTES, MAX_SIGNED_DRIVER_BYTES,
    VerifiedOidfArtifact, verify_oidf_artifact, verify_oidf_driver_manifest, verify_oidf_matrix,
};

const CACHE_RECORD_SCHEMA: u32 = 1;
const MAX_CACHE_RECORD_BYTES: usize = 128 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

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
    pub cached_at: i64,
    pub opened_at: i64,
    pub cache_entry: PathBuf,
    pub artifact: VerifiedOidfArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    schema: u32,
    manifest_url: String,
    resolved_at: i64,
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
    #[error("artifact cache contains a conflicting committed entry")]
    CacheConflict,
    #[error("artifact cache record is malformed")]
    CacheRecord,
    #[error("artifact manifest digest must be 64 lowercase hexadecimal characters")]
    InvalidManifestDigest,
    #[error("artifact cache entry failed immutable identity verification")]
    CacheIdentity,
}

pub fn open_cached_oidf_artifact(
    cache_root: &Path,
    manifest_digest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<CachedOidfArtifact, ArtifactDiscoveryError> {
    if !cache_root.is_absolute() || cache_root.file_name().is_none() {
        return Err(ArtifactDiscoveryError::UnsafeCache);
    }
    if !is_lowercase_sha256(manifest_digest) {
        return Err(ArtifactDiscoveryError::InvalidManifestDigest);
    }

    let cache_entry = cache_root.join("artifacts").join(manifest_digest);
    let record_bytes = read_cache(&cache_entry.join("verified.json"), MAX_CACHE_RECORD_BYTES)?;
    let compact_manifest = read_cache(&cache_entry.join("driver.jws"), MAX_SIGNED_DRIVER_BYTES)?;
    let matrix = read_cache(&cache_entry.join("matrix.json"), MAX_ARTIFACT_MATRIX_BYTES)?;
    let record = verify_cached_entry(
        &record_bytes,
        &compact_manifest,
        &matrix,
        manifest_digest,
        trust,
        available_capabilities,
        now,
    )?;

    Ok(CachedOidfArtifact {
        schema: 1,
        manifest_url: record.manifest_url,
        cached_at: record.resolved_at,
        opened_at: now,
        cache_entry,
        artifact: record.artifact,
    })
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
        &fetched.matrix,
        &fetched.artifact,
        now,
    )?;
    Ok(ResolvedOidfArtifact {
        schema: 1,
        manifest_url: manifest_url.to_owned(),
        resolved_at: now,
        cache_entry,
        cache_hit,
        artifact: fetched.artifact,
    })
}

struct FetchedArtifact {
    compact_manifest: String,
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
    let matrix_url = driver.matrix_url().to_owned();
    let matrix_size = driver.matrix_size();
    if matrix_size == 0 || matrix_size > MAX_ARTIFACT_MATRIX_BYTES as u64 {
        return Err(ArtifactDiscoveryError::Oversize);
    }
    let matrix = transport.get(&matrix_url, matrix_size)?;
    let artifact = verify_oidf_matrix(driver, &matrix)?;
    Ok(FetchedArtifact {
        compact_manifest,
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

fn verify_cached_entry(
    record_bytes: &[u8],
    compact_manifest_bytes: &[u8],
    matrix: &[u8],
    manifest_digest: &str,
    trust: &ArtifactTrustPolicy,
    available_capabilities: &BTreeSet<String>,
    now: i64,
) -> Result<CacheRecord, ArtifactDiscoveryError> {
    if !is_lowercase_sha256(manifest_digest) {
        return Err(ArtifactDiscoveryError::InvalidManifestDigest);
    }
    let record: CacheRecord =
        serde_json::from_slice(record_bytes).map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
    if record.schema != CACHE_RECORD_SCHEMA
        || !trust.accepts_url(&record.manifest_url)
        || record.resolved_at < record.artifact.not_before
        || record.resolved_at > record.artifact.expires_at
        || record.resolved_at > now
    {
        return Err(ArtifactDiscoveryError::CacheRecord);
    }

    let compact_manifest = compact_manifest(compact_manifest_bytes)?;
    let artifact = verify_oidf_artifact(
        &compact_manifest,
        matrix,
        trust,
        available_capabilities,
        now,
    )?;
    if artifact.driver_manifest_sha256 != manifest_digest || artifact != record.artifact {
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
    matrix: &[u8],
    artifact: &VerifiedOidfArtifact,
    now: i64,
) -> Result<(PathBuf, bool), ArtifactDiscoveryError> {
    let entry = root
        .join("artifacts")
        .join(&artifact.driver_manifest_sha256);
    crate::secure_file::ensure_directory(&entry, true).map_err(map_cache_file_error)?;
    let manifest_path = entry.join("driver.jws");
    let matrix_path = entry.join("matrix.json");
    let record_path = entry.join("verified.json");
    let expected = CacheRecord {
        schema: CACHE_RECORD_SCHEMA,
        manifest_url: manifest_url.to_owned(),
        resolved_at: now,
        artifact: artifact.clone(),
    };

    if record_path.exists() {
        let cached_manifest = read_cache(&manifest_path, MAX_SIGNED_DRIVER_BYTES)?;
        let cached_matrix = read_cache(&matrix_path, MAX_ARTIFACT_MATRIX_BYTES)?;
        let record_bytes = read_cache(&record_path, MAX_CACHE_RECORD_BYTES)?;
        let record: CacheRecord = serde_json::from_slice(&record_bytes)
            .map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
        if cached_manifest != compact_manifest.as_bytes()
            || cached_matrix != matrix
            || record.schema != CACHE_RECORD_SCHEMA
            || record.manifest_url != manifest_url
            || record.artifact != *artifact
        {
            return Err(ArtifactDiscoveryError::CacheConflict);
        }
        return Ok((entry, true));
    }

    write_cache(&manifest_path, compact_manifest.as_bytes())?;
    write_cache(&matrix_path, matrix)?;
    let record =
        serde_json::to_vec_pretty(&expected).map_err(|_| ArtifactDiscoveryError::CacheRecord)?;
    if record.len() > MAX_CACHE_RECORD_BYTES {
        return Err(ArtifactDiscoveryError::CacheRecord);
    }
    // The record is the commit marker. A crash before this write leaves an
    // incomplete entry which is never accepted as verified cache state.
    write_cache(&record_path, &record)?;
    Ok((entry, false))
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

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use sha2::{Digest as _, Sha256};

    use crate::{
        OidfArtifactMatrix, OidfArtifactMatrixGroup, OidfArtifactMatrixPlan,
        OidfArtifactMatrixVariant, OidfDriverManifest, OidfMatrixIdentity, OidfResourceBounds,
        OidfSuiteIdentity,
    };

    use super::*;

    const NOW: i64 = 1_800_000_000;
    const MANIFEST_URL: &str = "https://artifacts.example/oidf/stable/driver.jws";
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
        let point = key.verifying_key().to_encoded_point(true);
        ArtifactTrustPolicy {
            schema: 1,
            source: "https://artifacts.example/oidf/".to_owned(),
            signer_identity: "https://artifacts.example/signers/release-v1".to_owned(),
            key_id: format!("oidf-es256-{}", &digest(point.as_bytes())[..32]),
            public_key_sec1: URL_SAFE_NO_PAD.encode(point.as_bytes()),
        }
    }

    fn matrix() -> Vec<u8> {
        serde_json::to_vec(&OidfArtifactMatrix {
            schema: 1,
            name: "matrix".to_owned(),
            groups: vec![OidfArtifactMatrixGroup {
                id: "oidc".to_owned(),
                profile: "oidc".to_owned(),
                variant: OidfArtifactMatrixVariant {
                    id: "default".to_owned(),
                    values: BTreeMap::new(),
                },
                plans: vec![OidfArtifactMatrixPlan {
                    id: "p001".to_owned(),
                    plan: "oidcc-basic-certification-test-plan".to_owned(),
                    config_template: serde_json::json!({"alias":"{{run.alias}}"}),
                    variant: BTreeMap::new(),
                    required_capabilities: vec!["nazoauth.client.create".to_owned()],
                    expected_results: BTreeMap::new(),
                }],
            }],
        })
        .expect("matrix")
    }

    fn manifest(matrix: &[u8], expires_at: i64) -> OidfDriverManifest {
        OidfDriverManifest {
            schema: 1,
            artifact_id: "official-driver".to_owned(),
            revision: "a".repeat(40),
            source: trust().source,
            signer_identity: trust().signer_identity,
            issued_at: NOW - 60,
            not_before: NOW - 30,
            expires_at,
            suite: OidfSuiteIdentity {
                release: "v5.2.2".to_owned(),
                revision: "b".repeat(40),
                image_digest: format!("sha256:{}", "c".repeat(64)),
            },
            engine_protocol: 1,
            required_capabilities: vec!["nazoauth.client.create".to_owned()],
            matrix: OidfMatrixIdentity {
                schema: 1,
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
        let matrix = matrix();
        let compact = sign(&manifest(&matrix, expires_at));
        FakeTransport {
            responses: BTreeMap::from([
                (MANIFEST_URL.to_owned(), compact.into_bytes()),
                (MATRIX_URL.to_owned(), matrix),
            ]),
            requests: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn verifies_manifest_before_downloading_the_signed_matrix_url() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        assert_eq!(fetched.artifact.suite.release, "v5.2.2");
        assert_eq!(
            transport.requests.into_inner(),
            vec![
                (MANIFEST_URL.to_owned(), MAX_SIGNED_DRIVER_BYTES as u64),
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
            resolved_at: NOW,
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
    fn cached_entry_rejects_untrusted_or_impossible_commit_records() {
        let transport = fake_transport(NOW + 3600);
        let fetched =
            fetch_verified_artifact(&transport, MANIFEST_URL, &trust(), &capabilities(), NOW)
                .expect("verified fetch");
        let mut record = CacheRecord {
            schema: CACHE_RECORD_SCHEMA,
            manifest_url: "https://attacker.example/driver.jws".to_owned(),
            resolved_at: NOW,
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
        record.resolved_at = NOW + 2;
        assert!(matches!(
            verify(&record, NOW + 1),
            Err(ArtifactDiscoveryError::CacheRecord)
        ));

        record.resolved_at = fetched.artifact.not_before - 1;
        assert!(matches!(
            verify(&record, NOW + 1),
            Err(ArtifactDiscoveryError::CacheRecord)
        ));

        record.resolved_at = NOW;
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
            &fetched.matrix,
            &fetched.artifact,
            NOW,
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
        assert_eq!(opened.cached_at, NOW);
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
            &fetched.matrix,
            &fetched.artifact,
            NOW,
        )
        .expect("persist cache");
        assert!(!hit);
        assert!(entry.join("verified.json").is_file());
        assert!(
            persist_verified_cache(
                &root,
                MANIFEST_URL,
                &fetched.compact_manifest,
                &fetched.matrix,
                &fetched.artifact,
                NOW + 1,
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
                &fetched.matrix,
                &fetched.artifact,
                NOW + 2,
            ),
            Err(ArtifactDiscoveryError::CacheConflict)
        ));
        std::fs::remove_dir_all(root).expect("remove test cache");
    }
}
