//! Official release verification and the trusted release cache.
//!
//! H01: `VerifiedRelease::verify` is the single authoritative entry for
//! official NazoAuth server Releases, and `VerifiedControllerRelease::verify`
//! is the controller self-update entry. Both run the same bounded pipeline
//! exactly once per candidate artifact — bounded download, digest check,
//! GitHub attestation query, Sigstore/cosign verification with pinned
//! workflow identity — and hand out an immutable handle; callers never see
//! unverified bytes and never repeat a proof already covered by the handle.
//!
//! H03 digest-semantics ledger: every remaining digest expresses exactly one
//! distinct fact.
//! 1. Attestation subject digest: a signed in-toto statement binds the exact
//!    downloaded bytes. Supply-chain binding, established once here.
//! 2. Signed manifest digests (`ReleaseManifest.artifacts[*].sha256`, OCI
//!    index/platform digests): the signed policy binds the artifact set (J3);
//!    its coherence with fact 1 is checked once during verification.
//! 3. Cache entry address (`official|local/<subject>` directory name): which
//!    signed subject the cached bytes claim to be.
//! 4. Cache `blob_sha256` (OCI archives only): integrity of the exported
//!    archive transport encoding, which has no other local identity.
//! 5. `ArtifactHandle::verify_integrity`: one re-hash of cached bytes against
//!    fact 3/4 detects in-place mutation before consumption. It is never a
//!    second supply-chain proof.
//! 6. `active-release.json`, update journals, rollback states, and the
//!    controller self-update journal pin deployed/candidate identities for
//!    crash-safe lifecycle state; they are durable pointers, not repeated
//!    proofs over the same bytes.
//! 7. Attestation bundles persisted under `evidence/` are archival evidence;
//!    no trust decision consumes them.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    deployment::RuntimeBackendKind,
    filesystem::{
        PrivateTempDir, atomic_write, copy_atomic_verified, open_secure_regular_file,
        read_secure_regular_file, sha256, sha256_file,
    },
    model::{Artifact, ReleaseManifest, release_target, semantic_tag},
    process::{Process, command_exists},
    runtime_backend::{BlobAttestationVerification, backend},
};

const COSIGN_IMAGE: &str = "ghcr.io/sigstore/cosign/cosign@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00";
const RELEASE_PREDICATE: &str = "https://nazo.run/attestations/release-manifest/v1";
const CONTROLLER_PROVENANCE_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const CONTROLLER_REPOSITORY: &str = "nazozero/NazoAuthCtl";
const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const MAX_ATTESTATIONS: usize = 20;
const ATTESTATION_PAGE_SIZE: usize = MAX_ATTESTATIONS + 1;
const MAX_GITHUB_JSON_BYTES: u64 = 1024 * 1024;
const MAX_UNATTESTED_UPDATER_BYTES: u64 = 256 * 1024 * 1024;
const GITHUB_REQUEST_SECONDS: u64 = 30;
const RELEASE_DOWNLOAD_SECONDS: u64 = 300;
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationResponse {
    attestations: Vec<Attestation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    #[serde(rename = "bundle_url")]
    _bundle_url: String,
    initiator: String,
    repository_id: u64,
    bundle: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InTotoSubject {
    name: String,
    digest: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustState {
    schema: u32,
    version: String,
    backend_commit: String,
    image_oci_digest: String,
    release_identity: String,
}

pub(crate) struct VerifiedRelease {
    work: PrivateTempDir,
    pub(crate) manifest: ReleaseManifest,
}

pub(crate) struct VerifiedControllerRelease {
    work: PrivateTempDir,
    pub(crate) version: String,
    artifact_name: String,
    pub(crate) sha256: String,
}

/// The single official-verification request handed to
/// [`VerifiedRelease::verify`] (H01).
///
/// `trusted_version_floor` carries the version anti-downgrade floor (C6) into
/// the one authoritative entry so every consumer is floored identically; flows
/// whose floor lives in richer state (the UpdateConfig trust-state file or the
/// controller trust state) keep enforcing that state directly at the call site
/// until the J-phase cleanup retires it.
pub(crate) struct ReleaseRequest<'a> {
    pub(crate) repository: &'a str,
    pub(crate) requested_version: Option<&'a str>,
    pub(crate) container_backend: Option<RuntimeBackendKind>,
    pub(crate) trusted_version_floor: Option<&'a str>,
}

impl VerifiedRelease {
    /// Verify an official server Release through the single entry point.
    ///
    /// Exactly once per accepted artifact this performs: the bounded download,
    /// its content-digest check, the bounded GitHub attestation query, cosign
    /// bundle verification under the pinned release-workflow identity, the
    /// signed-manifest policy validation, controller compatibility, and the
    /// anti-downgrade floor. The returned handle covers those facts; callers
    /// must not re-run them.
    pub(crate) fn verify(request: ReleaseRequest<'_>) -> anyhow::Result<Self> {
        let version = resolve_version(request.repository, request.requested_version)?;
        let work = PrivateTempDir::new("nazoauth-release")?;
        let target = release_target().context("this platform has no official Release binary")?;
        let suffix = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let identity = format!(
            "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{version}",
            request.repository
        );
        let mut candidates = vec![format!("nazoauth-{target}{suffix}")];
        if matches!(version.as_str(), "v0.1.18" | "v0.1.19") {
            candidates.push(format!("nazoauthctl-{target}{suffix}"));
        }
        let mut last_error = None;
        let mut verified = None;
        for blob in &candidates {
            match verified_release_candidate(
                request.repository,
                &version,
                work.path(),
                blob,
                &identity,
                request.container_backend,
            ) {
                Ok(manifest) => {
                    verified = Some(manifest);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let manifest = verified.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                anyhow::anyhow!("no official Release artifact could be verified")
            })
        })?;
        manifest.validate(&version, &identity)?;
        manifest.validate_controller_compatibility()?;
        if let Some(floor) = request.trusted_version_floor {
            enforce_release_trust_floor(floor, &manifest)?;
        }
        Ok(Self { work, manifest })
    }

    /// Materialize one declared artifact inside the private handle workspace.
    ///
    /// Each artifact's digest is checked exactly once, when its bytes first
    /// enter the workspace: attested subjects were digest-bound during
    /// [`Self::verify`], and artifacts fetched on demand (for example the
    /// frontend tarball) are bound here against their signed manifest entry.
    /// The workspace is private to this handle, so existence implies coverage;
    /// re-hashing on every access would only duplicate the same fact (H03).
    pub(crate) fn artifact(&self, key: &str, repository: &str) -> anyhow::Result<PathBuf> {
        let artifact = self
            .manifest
            .artifacts
            .get(key)
            .with_context(|| format!("release manifest does not contain {key}"))?;
        if artifact.repository != repository {
            bail!("release artifact repository does not match controller policy");
        }
        let path = self.work.path().join(&artifact.name);
        if !path.exists() {
            download(
                &artifact.repository,
                &self.manifest.version,
                &artifact.name,
                self.work.path(),
                artifact.size,
            )?;
            verify_artifact(&path, artifact)?;
        }
        Ok(path)
    }

    pub(crate) fn persist_verification_evidence(&self, destination: &Path) -> anyhow::Result<()> {
        crate::filesystem::ensure_directory_chain(destination)?;
        atomic_write(
            &destination.join("server-release-manifest.json"),
            &serde_json::to_vec_pretty(&self.manifest)?,
            0o400,
        )?;
        for entry in fs::read_dir(self.work.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("release-attestation-") || !name.ends_with(".json") {
                continue;
            }
            let metadata = entry.metadata()?;
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_GITHUB_JSON_BYTES
            {
                bail!("verified Release evidence contains an invalid bundle");
            }
            let bytes = read_secure_regular_file(
                &entry.path(),
                "verified Release attestation",
                false,
                MAX_GITHUB_JSON_BYTES,
            )?;
            atomic_write(&destination.join(name), &bytes, 0o400)?;
        }
        Ok(())
    }
}

impl VerifiedControllerRelease {
    /// Verify an official controller Release through the shared pipeline.
    ///
    /// This is the same primitive as [`VerifiedRelease::verify`] with the
    /// SLSA provenance policy instead of the release-manifest policy: bounded
    /// download, digest check, bounded attestation query, cosign verification
    /// pinned to the controller release-workflow identity, and provenance
    /// subject binding happen exactly once here.
    pub(crate) fn verify(
        requested_version: Option<&str>,
        container_backend: Option<RuntimeBackendKind>,
    ) -> anyhow::Result<Self> {
        let version = resolve_version(CONTROLLER_REPOSITORY, requested_version)?;
        let target = release_target().context("this platform has no official controller target")?;
        let suffix = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let artifact_name = format!("nazoauthctl-{target}{suffix}");
        let work = PrivateTempDir::new("nazoauthctl-release")?;
        download(
            CONTROLLER_REPOSITORY,
            &version,
            &artifact_name,
            work.path(),
            MAX_UNATTESTED_UPDATER_BYTES,
        )?;
        let digest = sha256(&work.path().join(&artifact_name))?;
        let response = fetch_github_attestation_response(
            CONTROLLER_REPOSITORY,
            &digest,
            CONTROLLER_PROVENANCE_PREDICATE,
        )?;
        let response: AttestationResponse = serde_json::from_str(&response)
            .context("GitHub controller attestation response is invalid")?;
        if response.attestations.is_empty() || response.attestations.len() > MAX_ATTESTATIONS {
            bail!("GitHub returned no bounded controller attestation set");
        }
        let identity = format!(
            "https://github.com/{CONTROLLER_REPOSITORY}/.github/workflows/release.yml@refs/tags/{version}"
        );
        let mut accepted = 0usize;
        for (index, attestation) in response.attestations.into_iter().enumerate() {
            check_attestation_envelope("controller", &attestation)?;
            let statement = statement_from_bundle(&attestation.bundle)?;
            if statement.kind != IN_TOTO_STATEMENT_V1
                || statement.predicate_type != CONTROLLER_PROVENANCE_PREDICATE
            {
                continue;
            }
            require_subject_binding(&statement, &artifact_name, &digest, "controller provenance")?;
            let bundle_name = format!("controller-attestation-{index}.json");
            atomic_write(
                &work.path().join(&bundle_name),
                &serde_json::to_vec(&attestation.bundle)?,
                0o400,
            )?;
            verify_blob_attestation(
                work.path(),
                &bundle_name,
                &artifact_name,
                &identity,
                CONTROLLER_PROVENANCE_PREDICATE,
                container_backend,
            )?;
            accepted += 1;
        }
        if accepted == 0 {
            bail!("no verified controller provenance matched the requested target");
        }
        Ok(Self {
            work,
            version,
            artifact_name,
            sha256: digest,
        })
    }

    pub(crate) fn artifact(&self) -> PathBuf {
        self.work.path().join(&self.artifact_name)
    }

    pub(crate) fn persist_evidence(&self, destination: &Path) -> anyhow::Result<()> {
        crate::filesystem::ensure_directory_chain(destination)?;
        for entry in fs::read_dir(self.work.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("controller-attestation-") && name.ends_with(".json") {
                let bytes = read_secure_regular_file(
                    &entry.path(),
                    "verified controller attestation",
                    false,
                    MAX_GITHUB_JSON_BYTES,
                )?;
                atomic_write(&destination.join(name), &bytes, 0o400)?;
            }
        }
        Ok(())
    }
}

/// One bounded download plus its complete official verification chain.
///
/// Shared by both entry points so the mechanics exist exactly once (H01):
/// bounded curl download, single digest computation, single bounded GitHub
/// attestation query, and the caller's policy pass over the response.
fn verified_release_candidate(
    repository: &str,
    version: &str,
    work: &Path,
    blob: &str,
    identity: &str,
    container_backend: Option<RuntimeBackendKind>,
) -> anyhow::Result<ReleaseManifest> {
    download(
        repository,
        version,
        blob,
        work,
        MAX_UNATTESTED_UPDATER_BYTES,
    )?;
    let digest = sha256(&work.join(blob))?;
    let response = fetch_github_attestation_response(repository, &digest, RELEASE_PREDICATE)?;
    verified_manifest_from_attestations(
        &response,
        version,
        work,
        blob,
        &digest,
        identity,
        |work, bundle, blob, identity| {
            verify_blob_attestation(
                work,
                bundle,
                blob,
                identity,
                RELEASE_PREDICATE,
                container_backend,
            )
        },
    )
}

pub(crate) fn enforce_release_trust(
    config: &crate::model::UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    let path = &config.operator.trust_state_file;
    if !path.exists() {
        return Ok(());
    }
    let bytes = read_secure_regular_file(path, "Release trust state", true, 64 * 1024)?;
    let state: ReleaseTrustState =
        serde_json::from_slice(&bytes).context("Release trust state is invalid")?;
    if state.schema != 1 {
        bail!("unsupported Release trust state");
    }
    enforce_release_trust_state(&state, manifest)
}

pub(crate) fn enforce_release_trust_floor(
    trusted_version: &str,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    if compare_versions(&manifest.version, trusted_version)? == std::cmp::Ordering::Less {
        bail!(
            "Release anti-downgrade policy rejected {} below trusted {}; use the explicit rollback or break-glass recovery flow",
            manifest.version,
            trusted_version
        );
    }
    Ok(())
}

fn enforce_release_trust_state(
    state: &ReleaseTrustState,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    enforce_release_trust_floor(&state.version, manifest)?;
    if compare_versions(&manifest.version, &state.version)? == std::cmp::Ordering::Equal
        && (manifest.backend_commit != state.backend_commit
            || manifest.image_oci_digest() != state.image_oci_digest
            || manifest.release_identity != state.release_identity)
    {
        bail!("immutable Release identity changed for an already trusted version");
    }
    Ok(())
}

pub(crate) fn commit_release_trust(
    config: &crate::model::UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    let state = ReleaseTrustState {
        schema: 1,
        version: manifest.version.clone(),
        backend_commit: manifest.backend_commit.clone(),
        image_oci_digest: manifest.image_oci_digest().to_owned(),
        release_identity: manifest.release_identity.clone(),
    };
    atomic_write(
        &config.operator.trust_state_file,
        &serde_json::to_vec_pretty(&state)?,
        0o600,
    )
}

pub(crate) fn compare_versions(left: &str, right: &str) -> anyhow::Result<std::cmp::Ordering> {
    fn parse(value: &str) -> anyhow::Result<semver::Version> {
        let value = value
            .strip_prefix('v')
            .context("Release version has no v prefix")?;
        semver::Version::parse(value).context("Release version is not semantic")
    }
    Ok(parse(left)?.cmp_precedence(&parse(right)?))
}

// ---------------------------------------------------------------------------
// Content-addressed trusted-release cache with opaque handles (H02)
// ---------------------------------------------------------------------------

const CACHE_RECORD_SCHEMA: u32 = 1;
const CACHE_RECORD_MAX_BYTES: u64 = 64 * 1024;

/// Trust origin recorded on every durable artifact handle (H02).
///
/// [`ArtifactOrigin::Local`] marks explicitly declared local development
/// material (`source=local`). It carries no attestation, no signed manifest,
/// and can therefore never satisfy an official-verification gate; there is no
/// path that blends it into the official trust floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ArtifactOrigin {
    Official,
    Local,
}

impl ArtifactOrigin {
    fn directory_name(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Local => "local",
        }
    }
}

/// What kind of signed subject the cached bytes materialize.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CachedArtifactKind {
    HostBinary { artifact_name: String },
    OciArchive { image_reference: String },
}

/// Commit marker written last into every cache entry. The entry address is the
/// subject digest; `blob_sha256` exists only where the cached encoding has an
/// independent transport identity (exported OCI archives).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedArtifactRecord {
    schema: u32,
    origin: ArtifactOrigin,
    kind: CachedArtifactKind,
    version: String,
    target: String,
    subject_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob_sha256: Option<String>,
}

/// Opaque handle to verified artifact bytes in the content-addressed cache.
///
/// Consumers receive `(address, blob)` pairs only through
/// [`commit_artifact_handle`] / [`open_artifact_handle`]; both re-hash the
/// bytes before handing out the handle so in-place mutation is detected at the
/// consumption boundary rather than being assumed away.
#[derive(Clone, Debug)]
pub(crate) struct ArtifactHandle {
    blob: PathBuf,
    record: CachedArtifactRecord,
}

impl ArtifactHandle {
    pub(crate) fn blob(&self) -> &Path {
        &self.blob
    }

    /// The one mutation-detection fact of this handle: the cached bytes still
    /// hash to the digest that addresses them. This is local-integrity only;
    /// supply-chain facts are never recomputed here.
    pub(crate) fn verify_integrity(&self) -> anyhow::Result<()> {
        let expected = match (&self.record.kind, self.record.blob_sha256.as_deref()) {
            (CachedArtifactKind::HostBinary { .. }, _) => &self.record.subject_sha256,
            (CachedArtifactKind::OciArchive { .. }, Some(blob)) => blob,
            (CachedArtifactKind::OciArchive { .. }, None) => {
                bail!("cached OCI archive handle carries no transport digest")
            }
        };
        validate_lower_hex_digest(expected, "cached artifact digest")?;
        let mut file = open_secure_regular_file(&self.blob, "cached release artifact", false)?;
        let actual = sha256_file(&mut file, "cached release artifact")?;
        if actual != *expected {
            bail!("cached release artifact bytes were modified after verification");
        }
        Ok(())
    }

    /// Official gate (no blending): LOCAL-origin handles always fail here.
    pub(crate) fn require_official(&self) -> anyhow::Result<()> {
        if self.record.origin != ArtifactOrigin::Official {
            bail!("local development artifacts can never satisfy official release verification");
        }
        Ok(())
    }

    fn open_validated(directory: PathBuf) -> anyhow::Result<Self> {
        let metadata = fs::symlink_metadata(&directory)
            .with_context(|| format!("failed to inspect {}", directory.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("trusted release cache entry is not a regular directory");
        }
        let blob = directory.join("blob");
        let record_path = directory.join("handle.json");
        let bytes = read_secure_regular_file(
            &record_path,
            "trusted release cache handle",
            true,
            CACHE_RECORD_MAX_BYTES,
        )
        .with_context(|| format!("cache entry {} is not committed", directory.display()))?;
        let record: CachedArtifactRecord = serde_json::from_slice(bytes.as_slice())
            .context("trusted release cache handle is invalid")?;
        if record.schema != CACHE_RECORD_SCHEMA {
            bail!("trusted release cache handle has an unsupported schema");
        }
        // The directory address is itself the content claim; the record must
        // agree with it instead of restating a second copy of the fact.
        let Some(address) = directory.file_name().and_then(|name| name.to_str()) else {
            bail!("trusted release cache entry address is not a plain digest");
        };
        validate_lower_hex_digest(address, "cache entry address")?;
        if record.subject_sha256 != address {
            bail!("cache handle subject differs from its content address");
        }
        match (&record.kind, &record.blob_sha256) {
            (CachedArtifactKind::HostBinary { .. }, None) => {}
            (CachedArtifactKind::OciArchive { .. }, Some(_)) => {}
            _ => bail!("cache handle digest bindings are inconsistent"),
        }
        validate_release_tag(&record.version)?;
        validate_cache_identifier(&record.target, "cache handle target")?;
        let handle = Self { blob, record };
        handle.verify_integrity()?;
        Ok(handle)
    }
}

/// Description of a verified artifact entering the cache. For host binaries
/// the subject digest is also the byte digest; exported OCI archives carry the
/// separate transport digest recorded at commit time.
pub(crate) struct CachedArtifactDescriptor<'a> {
    pub(crate) origin: ArtifactOrigin,
    pub(crate) kind: CachedArtifactKind,
    pub(crate) version: &'a str,
    pub(crate) target: &'a str,
    pub(crate) subject_sha256: &'a str,
}

/// Idempotently commit verified bytes under their content address and return
/// the opaque handle. The commit marker is written last, so a partially
/// written entry is never opened as a hit.
pub(crate) fn commit_artifact_handle(
    cache_root: &Path,
    descriptor: &CachedArtifactDescriptor<'_>,
    source_blob: &Path,
) -> anyhow::Result<ArtifactHandle> {
    validate_lower_hex_digest(descriptor.subject_sha256, "release artifact subject digest")?;
    validate_release_tag(descriptor.version)?;
    validate_cache_identifier(descriptor.target, "release target")?;
    let directory = cache_root
        .join(descriptor.origin.directory_name())
        .join(descriptor.subject_sha256);
    if directory.join("handle.json").exists() {
        let existing = ArtifactHandle::open_validated(directory)?;
        let matches = existing.record.origin == descriptor.origin
            && existing.record.kind == descriptor.kind
            && existing.record.version == descriptor.version
            && existing.record.target == descriptor.target;
        if !matches {
            bail!("cached artifact handle exists with different provenance");
        }
        return Ok(existing);
    }
    let transport_digest = match &descriptor.kind {
        CachedArtifactKind::HostBinary { .. } => None,
        CachedArtifactKind::OciArchive { .. } => {
            Some(sha256(source_blob).context("failed to digest the staged OCI archive")?)
        }
    };
    crate::filesystem::ensure_directory_chain(&directory)?;
    copy_atomic_verified(
        source_blob,
        &directory.join("blob"),
        0o500,
        transport_digest
            .as_deref()
            .unwrap_or(descriptor.subject_sha256),
    )?;
    let record = CachedArtifactRecord {
        schema: CACHE_RECORD_SCHEMA,
        origin: descriptor.origin,
        kind: descriptor.kind.clone(),
        version: descriptor.version.to_owned(),
        target: descriptor.target.to_owned(),
        subject_sha256: descriptor.subject_sha256.to_owned(),
        blob_sha256: transport_digest,
    };
    let handle = ArtifactHandle {
        blob: directory.join("blob"),
        record,
    };
    atomic_write(
        &directory.join("handle.json"),
        &serde_json::to_vec_pretty(&handle.record)?,
        0o400,
    )?;
    handle.verify_integrity()?;
    Ok(handle)
}

/// Open a committed cache entry by origin and subject digest. Fails closed on
/// missing markers, address/record disagreement, or mutated bytes.
pub(crate) fn open_artifact_handle(
    cache_root: &Path,
    origin: ArtifactOrigin,
    subject_sha256: &str,
) -> anyhow::Result<ArtifactHandle> {
    validate_lower_hex_digest(subject_sha256, "release artifact subject digest")?;
    let directory = cache_root
        .join(origin.directory_name())
        .join(subject_sha256);
    let handle = ArtifactHandle::open_validated(directory)?;
    if handle.record.origin != origin {
        bail!("cached artifact handle origin differs from the requested trust origin");
    }
    Ok(handle)
}

fn validate_lower_hex_digest(value: &str, label: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_release_tag(value: &str) -> anyhow::Result<()> {
    if !semantic_tag(value) {
        bail!("cache handle version is not an immutable semantic tag");
    }
    Ok(())
}

fn validate_cache_identifier(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{label} contains characters outside the safe release identifier set");
    }
    Ok(())
}

fn bounded_https_curl_arguments(max_time: u64, max_filesize: u64) -> Vec<String> {
    vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--location".to_owned(),
        "--proto".to_owned(),
        "=https".to_owned(),
        "--proto-redir".to_owned(),
        "=https".to_owned(),
        "--max-redirs".to_owned(),
        "5".to_owned(),
        "--tlsv1.2".to_owned(),
        "--connect-timeout".to_owned(),
        "10".to_owned(),
        "--max-time".to_owned(),
        max_time.to_string(),
        "--max-filesize".to_owned(),
        max_filesize.to_string(),
    ]
}

/// The single bounded GitHub attestation query used by both entry points.
fn fetch_github_attestation_response(
    repository: &str,
    digest: &str,
    predicate_type: &str,
) -> anyhow::Result<String> {
    Process::new("curl")
        .args(bounded_https_curl_arguments(
            GITHUB_REQUEST_SECONDS,
            MAX_GITHUB_JSON_BYTES,
        ))
        .args([
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            &format!(
                "https://api.github.com/repos/{repository}/attestations/sha256%3A{digest}?per_page={ATTESTATION_PAGE_SIZE}&predicate_type={}",
                urlencoding::encode(predicate_type)
            ),
        ])
        .stdout()
}

/// Metadata and Sigstore media-type checks shared by both entry points.
fn check_attestation_envelope(kind_label: &str, attestation: &Attestation) -> anyhow::Result<()> {
    if attestation.repository_id == 0 || attestation.initiator.trim().is_empty() {
        bail!("GitHub returned invalid {kind_label} attestation metadata");
    }
    if attestation
        .bundle
        .get("mediaType")
        .and_then(serde_json::Value::as_str)
        != Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
    {
        bail!("GitHub returned an unsupported {kind_label} Sigstore bundle");
    }
    Ok(())
}

fn require_subject_binding(
    statement: &InTotoStatement,
    blob: &str,
    digest: &str,
    label: &str,
) -> anyhow::Result<()> {
    if !statement.subject.iter().any(|subject| {
        subject.name == blob
            && subject
                .digest
                .get("sha256")
                .is_some_and(|value| value == digest)
    }) {
        bail!("{label} does not bind the downloaded artifact bytes");
    }
    Ok(())
}

fn verified_manifest_from_attestations(
    response: &str,
    version: &str,
    work: &Path,
    blob: &str,
    digest: &str,
    identity: &str,
    mut verify_attestation: impl FnMut(&Path, &str, &str, &str) -> anyhow::Result<()>,
) -> anyhow::Result<ReleaseManifest> {
    let response: AttestationResponse =
        serde_json::from_str(response).context("GitHub attestation response is invalid")?;
    if response.attestations.is_empty() || response.attestations.len() > MAX_ATTESTATIONS {
        bail!("GitHub returned no bounded Release attestation set");
    }
    let mut verified: Option<ReleaseManifest> = None;
    for (index, attestation) in response.attestations.into_iter().enumerate() {
        let bundle_name = format!("release-attestation-{index}.json");
        check_attestation_envelope("Release", &attestation)?;
        atomic_write(
            &work.join(&bundle_name),
            &serde_json::to_vec(&attestation.bundle)?,
            0o600,
        )?;
        let Some(candidate) = manifest_from_bundle(&attestation.bundle, blob, digest)? else {
            continue;
        };
        if candidate.version != version || candidate.release_identity != identity {
            continue;
        }
        verify_attestation(work, &bundle_name, blob, identity)?;
        candidate.validate(version, identity)?;
        let subject = candidate
            .artifacts
            .values()
            .find(|artifact| artifact.name == blob)
            .context("Release attestation subject is not a declared server artifact")?;
        if subject.sha256 != digest || subject.size != fs::metadata(work.join(blob))?.len() {
            bail!("Release attestation does not bind the downloaded server artifact");
        }
        accept_verified_manifest(&mut verified, candidate)?;
    }
    verified.context("no verified Release attestation matched the requested target")
}

fn accept_verified_manifest(
    verified: &mut Option<ReleaseManifest>,
    candidate: ReleaseManifest,
) -> anyhow::Result<()> {
    if let Some(existing) = verified {
        if existing == &candidate {
            return Ok(());
        }
        bail!("matching Release attestations contain conflicting predicates");
    }
    *verified = Some(candidate);
    Ok(())
}

fn manifest_from_bundle(
    bundle: &serde_json::Value,
    blob: &str,
    digest: &str,
) -> anyhow::Result<Option<ReleaseManifest>> {
    let statement = statement_from_bundle(bundle)?;
    if statement.kind != IN_TOTO_STATEMENT_V1 || statement.predicate_type != RELEASE_PREDICATE {
        return Ok(None);
    }
    require_subject_binding(&statement, blob, digest, "Release attestation subject")?;
    let manifest = serde_json::from_value(statement.predicate)
        .context("Release attestation predicate is not a closed manifest")?;
    Ok(Some(manifest))
}

fn statement_from_bundle(bundle: &serde_json::Value) -> anyhow::Result<InTotoStatement> {
    let payload = bundle
        .get("dsseEnvelope")
        .and_then(|envelope| envelope.get("payload"))
        .and_then(serde_json::Value::as_str)
        .context("Release attestation has no DSSE payload")?;
    let statement: InTotoStatement = serde_json::from_slice(
        &STANDARD
            .decode(payload)
            .context("Release attestation payload is not base64")?,
    )
    .context("Release attestation statement is invalid")?;
    Ok(statement)
}

fn resolve_version(repository: &str, requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(version) = requested {
        if !semantic_tag(version) {
            bail!("release version is not an immutable semantic tag");
        }
        return Ok(version.to_owned());
    }
    let response = Process::new("curl")
        .args(bounded_https_curl_arguments(
            GITHUB_REQUEST_SECONDS,
            MAX_GITHUB_JSON_BYTES,
        ))
        .args([
            "-H",
            "Accept: application/vnd.github+json",
            &format!("https://api.github.com/repos/{repository}/releases/latest"),
        ])
        .stdout()?;
    let value: serde_json::Value =
        serde_json::from_str(&response).context("GitHub latest release response is invalid")?;
    let version = value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .context("GitHub latest release response has no tag_name")?;
    if !semantic_tag(version) {
        bail!("release version is not an immutable semantic tag");
    }
    Ok(version.to_owned())
}

fn download(
    repository: &str,
    version: &str,
    name: &str,
    destination: &Path,
    maximum_size: u64,
) -> anyhow::Result<()> {
    if maximum_size == 0 {
        bail!("release artifact has no bounded download size");
    }
    Process::new("curl")
        .args(bounded_https_curl_arguments(
            RELEASE_DOWNLOAD_SECONDS,
            maximum_size,
        ))
        .arg("--output")
        .arg(destination.join(name))
        .arg(format!(
            "https://github.com/{repository}/releases/download/{version}/{name}"
        ))
        .run_quiet()
}

fn verify_blob_attestation(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
    predicate: &str,
    container_backend: Option<RuntimeBackendKind>,
) -> anyhow::Result<()> {
    if command_exists("cosign") {
        return Process::new("cosign")
            .args(["verify-blob-attestation", "--bundle"])
            .arg(work.join(bundle))
            .args([
                "--type",
                predicate,
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ])
            .arg(work.join(blob))
            .run_quiet();
    }
    let kind = container_backend.context("Cosign is required when no container backend exists")?;
    backend(kind).verify_blob_attestation(&BlobAttestationVerification {
        work: work.to_path_buf(),
        bundle: bundle.to_owned(),
        blob: blob.to_owned(),
        certificate_identity: identity.to_owned(),
        predicate_type: predicate.to_owned(),
        cosign_image: COSIGN_IMAGE.to_owned(),
    })
}

fn verify_artifact(path: &Path, artifact: &Artifact) -> anyhow::Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() != artifact.size {
        bail!("artifact size mismatch: {}", artifact.name);
    }
    if sha256(path)? != artifact.sha256 {
        bail!("artifact digest mismatch: {}", artifact.name);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/release.rs"]
mod tests;
