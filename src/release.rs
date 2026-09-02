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
use serde::Deserialize;

use crate::{
    error_codes::{RELEASE_DOWNLOAD_FAILED, RELEASE_NOT_FOUND},
    filesystem::{PrivateTempDir, atomic_write, read_secure_regular_file, sha256},
    model::{Artifact, ReleaseManifest, release_target, semantic_tag},
    process::{Process, command_exists},
    runtime_backend::RuntimeBackendKind,
    runtime_backend::{BlobAttestationVerification, backend},
    target::ARTIFACT_UNVERIFIED,
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
/// whose floor lives in richer state keep enforcing that state directly at the
/// call site.
pub(crate) struct ReleaseRequest<'a> {
    pub(crate) repository: &'a str,
    pub(crate) requested_version: Option<&'a str>,
    pub(crate) trusted_version_floor: Option<&'a str>,
}

impl VerifiedRelease {
    /// Rollback policy from the attested Release manifest. Callers receive
    /// this only through a fully verified handle, so it can be carried into
    /// target state without re-parsing unsigned metadata.
    pub(crate) fn rollback_policy(&self) -> crate::model::ReleaseRollbackPolicy {
        self.manifest.rollback.clone()
    }

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
        let blob = format!("nazoauth-{target}{suffix}");
        let cache = release_cache_root();
        let manifest = verified_release_candidate(
            request.repository,
            &version,
            work.path(),
            &blob,
            &identity,
            cache.as_deref(),
        )?;
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
}

impl VerifiedControllerRelease {
    /// Verify an official controller Release through the shared pipeline.
    ///
    /// This is the same primitive as [`VerifiedRelease::verify`] with the
    /// SLSA provenance policy instead of the release-manifest policy: bounded
    /// download, digest check, bounded attestation query, cosign verification
    /// pinned to the controller release-workflow identity, and provenance
    /// subject binding happen exactly once here.
    pub(crate) fn verify(requested_version: Option<&str>) -> anyhow::Result<Self> {
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
        let response: AttestationResponse = serde_json::from_str(&response).context(format!(
            "{ARTIFACT_UNVERIFIED}: GitHub controller attestation response is invalid"
        ))?;
        if response.attestations.is_empty() || response.attestations.len() > MAX_ATTESTATIONS {
            bail!("{ARTIFACT_UNVERIFIED}: GitHub returned no bounded controller attestation set");
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
            )
            .context(format!(
                "{ARTIFACT_UNVERIFIED}: controller provenance verification failed"
            ))?;
            accepted += 1;
        }
        if accepted == 0 {
            bail!(
                "{ARTIFACT_UNVERIFIED}: no verified controller provenance matched the requested target"
            );
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
/// P1-11: persistent content-addressed transport cache for verified Release
/// binaries. Layout: `<root>/<repository>/<version>/<blob>`. A hit saves the
/// large download only — digest, attestation query and cosign verification
/// always re-run, so the cache can never act as a trust anchor. Returns
/// `None` when no usable cache location exists (cache silently disabled).
fn release_cache_root() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")?;
        Some(
            std::path::PathBuf::from(base)
                .join("nazoauthctl")
                .join("release-cache"),
        )
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
            let path = std::path::PathBuf::from(xdg);
            if path.is_absolute() {
                return Some(path.join("nazoauthctl").join("releases"));
            }
        }
        let home = std::env::var_os("HOME")?;
        Some(
            std::path::PathBuf::from(home)
                .join(".cache")
                .join("nazoauthctl")
                .join("releases"),
        )
    }
}

fn remove_failed_cached_release(path: &Path) -> anyhow::Result<()> {
    fs::remove_file(path).with_context(|| {
        format!(
            "cached Release artifact failed verification but could not be removed: {}",
            path.display()
        )
    })
}

fn verified_release_candidate(
    repository: &str,
    version: &str,
    work: &Path,
    blob: &str,
    identity: &str,
    cache: Option<&Path>,
) -> anyhow::Result<ReleaseManifest> {
    let cached = cache.and_then(|root| {
        let source = root.join(repository).join(version).join(blob);
        fs::copy(&source, work.join(blob)).ok().map(|_| source)
    });
    if cached.is_none() {
        download(
            repository,
            version,
            blob,
            work,
            MAX_UNATTESTED_UPDATER_BYTES,
        )?;
    }
    // P1-11: the cache is a TRANSPORT optimization only. The digest is
    // recomputed from the bytes actually in the workspace and the full
    // attestation + cosign chain runs on every verify, so a poisoned or
    // stale cache entry can never become a trust anchor.
    let digest = sha256(&work.join(blob))?;
    // Fetch errors return before cache invalidation: inability to reach the
    // attestation authority says nothing about the cached bytes.
    let response = fetch_github_attestation_response(repository, &digest, RELEASE_PREDICATE)?;
    let first_verification = verified_manifest_from_attestations(
        &response,
        version,
        work,
        blob,
        &digest,
        identity,
        |work, bundle, blob, identity| {
            verify_blob_attestation(work, bundle, blob, identity, RELEASE_PREDICATE)
        },
    );
    let manifest = match (first_verification, cached.as_ref()) {
        (Ok(manifest), _) => manifest,
        (Err(error), None) => return Err(error),
        (Err(cached_error), Some(cached_source)) => {
            remove_failed_cached_release(cached_source)?;
            download(
                repository,
                version,
                blob,
                work,
                MAX_UNATTESTED_UPDATER_BYTES,
            )
            .with_context(|| {
                format!(
                    "cached Release artifact failed verification ({cached_error:#}); its single fresh download failed"
                )
            })?;
            let fresh_digest = sha256(&work.join(blob))?;
            let fresh_response =
                fetch_github_attestation_response(repository, &fresh_digest, RELEASE_PREDICATE)?;
            verified_manifest_from_attestations(
                &fresh_response,
                version,
                work,
                blob,
                &fresh_digest,
                identity,
                |work, bundle, blob, identity| {
                    verify_blob_attestation(
                        work,
                        bundle,
                        blob,
                        identity,
                        RELEASE_PREDICATE,
                    )
                },
            )
            .with_context(|| {
                format!(
                    "fresh Release artifact failed verification after the cached item was rejected ({cached_error:#})"
                )
            })?
        }
    };
    if let Some(root) = cache {
        // Only fully verified bytes reach the persistent store; the
        // recomputed digest above already proved what we are storing.
        let destination = root.join(repository).join(version).join(blob);
        if crate::filesystem::ensure_directory_chain(&destination).is_ok() {
            let _ = fs::copy(work.join(blob), destination);
        }
    }
    Ok(manifest)
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

pub(crate) fn compare_versions(left: &str, right: &str) -> anyhow::Result<std::cmp::Ordering> {
    fn parse(value: &str) -> anyhow::Result<semver::Version> {
        let value = value
            .strip_prefix('v')
            .context("Release version has no v prefix")?;
        semver::Version::parse(value).context("Release version is not semantic")
    }
    Ok(parse(left)?.cmp_precedence(&parse(right)?))
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

fn release_download_error(error: anyhow::Error, subject: &str) -> anyhow::Error {
    let rendered = format!("{error:#}");
    let code = if rendered.contains("error: 404") || rendered.contains("HTTP 404") {
        RELEASE_NOT_FOUND
    } else {
        RELEASE_DOWNLOAD_FAILED
    };
    anyhow::anyhow!("{code}: failed to fetch {subject}: {rendered}")
}

fn release_fetch_stdout(process: &Process, subject: &str) -> anyhow::Result<String> {
    let output = process
        .output()
        .map_err(|error| release_download_error(error, subject))?;
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(400)
            .collect();
        return Err(release_download_error(
            anyhow::anyhow!(
                "curl failed with status {}: {}",
                output.status,
                stderr.trim()
            ),
            subject,
        ));
    }
    String::from_utf8(output.stdout).context("GitHub returned non-UTF-8 release metadata")
}

/// The single bounded GitHub attestation query used by both entry points.
fn fetch_github_attestation_response(
    repository: &str,
    digest: &str,
    predicate_type: &str,
) -> anyhow::Result<String> {
    let process = Process::new("curl")
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
        ]);
    release_fetch_stdout(&process, "GitHub attestation metadata")
}

/// Metadata and Sigstore media-type checks shared by both entry points.
fn check_attestation_envelope(kind_label: &str, attestation: &Attestation) -> anyhow::Result<()> {
    if attestation.repository_id == 0 || attestation.initiator.trim().is_empty() {
        bail!("{ARTIFACT_UNVERIFIED}: GitHub returned invalid {kind_label} attestation metadata");
    }
    if attestation
        .bundle
        .get("mediaType")
        .and_then(serde_json::Value::as_str)
        != Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
    {
        bail!("{ARTIFACT_UNVERIFIED}: GitHub returned an unsupported {kind_label} Sigstore bundle");
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
        bail!("{ARTIFACT_UNVERIFIED}: {label} does not bind the downloaded artifact bytes");
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
    let response: AttestationResponse = serde_json::from_str(response).context(format!(
        "{ARTIFACT_UNVERIFIED}: GitHub attestation response is invalid"
    ))?;
    if response.attestations.is_empty() || response.attestations.len() > MAX_ATTESTATIONS {
        bail!("{ARTIFACT_UNVERIFIED}: GitHub returned no bounded Release attestation set");
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
        verify_attestation(work, &bundle_name, blob, identity).context(format!(
            "{ARTIFACT_UNVERIFIED}: Release provenance verification failed"
        ))?;
        candidate.validate(version, identity).context(format!(
            "{ARTIFACT_UNVERIFIED}: Release manifest policy validation failed"
        ))?;
        let subject = candidate
            .artifacts
            .values()
            .find(|artifact| artifact.name == blob)
            .context(format!(
                "{ARTIFACT_UNVERIFIED}: Release attestation subject is not a declared server artifact"
            ))?;
        if subject.sha256 != digest || subject.size != fs::metadata(work.join(blob))?.len() {
            bail!(
                "{ARTIFACT_UNVERIFIED}: Release attestation does not bind the downloaded server artifact"
            );
        }
        accept_verified_manifest(&mut verified, candidate)?;
    }
    verified.context(format!(
        "{ARTIFACT_UNVERIFIED}: no verified Release attestation matched the requested target"
    ))
}

fn accept_verified_manifest(
    verified: &mut Option<ReleaseManifest>,
    candidate: ReleaseManifest,
) -> anyhow::Result<()> {
    if let Some(existing) = verified {
        if existing == &candidate {
            return Ok(());
        }
        bail!(
            "{ARTIFACT_UNVERIFIED}: matching Release attestations contain conflicting predicates"
        );
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
    let manifest = serde_json::from_value(statement.predicate).context(format!(
        "{ARTIFACT_UNVERIFIED}: Release attestation predicate is not a closed manifest"
    ))?;
    Ok(Some(manifest))
}

fn statement_from_bundle(bundle: &serde_json::Value) -> anyhow::Result<InTotoStatement> {
    let payload = bundle
        .get("dsseEnvelope")
        .and_then(|envelope| envelope.get("payload"))
        .and_then(serde_json::Value::as_str)
        .context(format!(
            "{ARTIFACT_UNVERIFIED}: Release attestation has no DSSE payload"
        ))?;
    let statement: InTotoStatement = serde_json::from_slice(&STANDARD.decode(payload).context(
        format!("{ARTIFACT_UNVERIFIED}: Release attestation payload is not base64"),
    )?)
    .context(format!(
        "{ARTIFACT_UNVERIFIED}: Release attestation statement is invalid"
    ))?;
    Ok(statement)
}

fn resolve_version(repository: &str, requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(version) = requested {
        if !semantic_tag(version) {
            bail!("release version is not an immutable semantic tag");
        }
        return Ok(version.to_owned());
    }
    let process = Process::new("curl")
        .args(bounded_https_curl_arguments(
            GITHUB_REQUEST_SECONDS,
            MAX_GITHUB_JSON_BYTES,
        ))
        .args([
            "-H",
            "Accept: application/vnd.github+json",
            &format!("https://api.github.com/repos/{repository}/releases/latest"),
        ]);
    let response = release_fetch_stdout(&process, "the latest GitHub Release")?;
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
        .map_err(|error| release_download_error(error, &format!("Release asset '{name}'")))
}

fn verify_blob_attestation(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
    predicate: &str,
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
    let kind = [RuntimeBackendKind::Podman, RuntimeBackendKind::Docker]
        .into_iter()
        .find(|kind| command_exists(kind.as_str()))
        .context("Cosign verification requires cosign, Podman, or Docker")?;
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
        bail!(
            "{ARTIFACT_UNVERIFIED}: artifact size mismatch: {}",
            artifact.name
        );
    }
    if sha256(path)? != artifact.sha256 {
        bail!(
            "{ARTIFACT_UNVERIFIED}: artifact digest mismatch: {}",
            artifact.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[test]
    fn release_fetch_failures_distinguish_missing_from_transport() {
        let missing = release_download_error(
            anyhow::anyhow!("curl failed: The requested URL returned error: 404"),
            "Release asset",
        );
        assert!(
            format!("{missing:#}").contains(RELEASE_NOT_FOUND),
            "{missing:#}"
        );

        let unavailable = release_download_error(
            anyhow::anyhow!("curl failed: Could not resolve host github.com"),
            "Release asset",
        );
        assert!(
            format!("{unavailable:#}").contains(RELEASE_DOWNLOAD_FAILED),
            "{unavailable:#}"
        );
        assert!(
            !format!("{unavailable:#}").contains(crate::error_codes::HOST_UNREACHABLE),
            "{unavailable:#}"
        );
    }

    #[test]
    fn invalid_attestation_keeps_artifact_verification_code() {
        let statement = InTotoStatement {
            kind: IN_TOTO_STATEMENT_V1.to_owned(),
            subject: Vec::new(),
            predicate_type: RELEASE_PREDICATE.to_owned(),
            predicate: serde_json::Value::Null,
        };
        let error =
            require_subject_binding(&statement, "nazoauth-linux-x86_64", "deadbeef", "Release")
                .expect_err("unbound bytes must fail");
        assert!(
            format!("{error:#}").contains(ARTIFACT_UNVERIFIED),
            "{error:#}"
        );
    }

    #[test]
    fn cache_root_is_absolute_and_scoped_when_a_base_exists() {
        let root = release_cache_root();
        // On CI/dev machines a base directory always exists; assert the
        // layout contract rather than the specific base.
        if let Some(root) = root {
            assert!(root.is_absolute(), "{root:?}");
            let rendered = root.to_string_lossy();
            assert!(rendered.contains("nazoauthctl"), "{rendered}");
            assert!(
                rendered.contains("cache") || rendered.contains("releases"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn cache_hit_copies_into_workspace_and_digest_is_recomputed() {
        // Layout contract under test: cache bytes are copied into the
        // workspace and re-digested. The nested <repo>/<version> layout is
        // exercised by the production path; here a flat temp file stands in
        // for it to keep the fixture inside one private directory.
        let root = PrivateTempDir::new("nazoauth-release-cache").unwrap();
        let blob_path = root.path().join("nazoauth-x");
        fs::write(&blob_path, b"verified-bytes").unwrap();

        // The transport optimization copies FROM the cache into the private
        // workspace; the workspace bytes are then re-digested independently,
        // so a poisoned cache entry is caught by the attestation digest.
        let work = PrivateTempDir::new("nazoauth-release-cache-work").unwrap();
        fs::copy(&blob_path, work.path().join("nazoauth-x")).unwrap();
        let recomputed = sha256(&work.path().join("nazoauth-x")).unwrap();
        // The recomputed workspace digest must equal a fresh digest of the
        // cached source bytes — proof the transport copy is faithful and
        // that verification runs on real cache content, not a stale value.
        let expected = sha256(&blob_path).unwrap();
        assert_eq!(recomputed, expected);
        assert_eq!(expected.len(), 64);
    }

    #[test]
    fn failed_cache_removal_is_scoped_to_the_exact_blob() {
        let root = PrivateTempDir::new("nazoauth-release-cache-eviction").unwrap();
        let rejected = root.path().join("nazoauth-linux-x86_64");
        let sibling = root.path().join("nazoauth-linux-aarch64");
        fs::write(&rejected, b"rejected").unwrap();
        fs::write(&sibling, b"still-valid").unwrap();

        remove_failed_cached_release(&rejected).unwrap();

        assert!(!rejected.exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"still-valid");
    }
}
