use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    filesystem::atomic_write,
    filesystem::{PrivateTempDir, sha256},
    model::{Artifact, ReleaseManifest, release_target, semantic_tag},
    process::{Process, command_exists},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustState {
    schema: u32,
    version: String,
    backend_commit: String,
    image_oci_digest: String,
    release_identity: String,
}

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

pub(crate) fn enforce_release_trust(
    config: &crate::model::UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    let path = &config.operator.trust_state_file;
    if !path.exists() {
        return Ok(());
    }
    let state: ReleaseTrustState =
        serde_json::from_slice(&fs::read(path)?).context("Release trust state is invalid")?;
    if state.schema != 1 {
        bail!("unsupported Release trust state");
    }
    enforce_release_trust_state(&state, manifest)
}

fn enforce_release_trust_state(
    state: &ReleaseTrustState,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    match compare_versions(&manifest.version, &state.version)? {
        std::cmp::Ordering::Less => bail!(
            "Release anti-downgrade policy rejected {} below trusted {}; use the explicit rollback or break-glass recovery flow",
            manifest.version,
            state.version
        ),
        std::cmp::Ordering::Equal => {
            if manifest.backend_commit != state.backend_commit
                || manifest.image_oci_digest() != state.image_oci_digest
                || manifest.release_identity != state.release_identity
            {
                bail!("immutable Release identity changed for an already trusted version");
            }
        }
        std::cmp::Ordering::Greater => {}
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

impl VerifiedRelease {
    pub(crate) fn fetch(
        repository: &str,
        requested_version: Option<&str>,
        container_engine: Option<&str>,
    ) -> anyhow::Result<Self> {
        let version = resolve_version(repository, requested_version)?;
        let work = PrivateTempDir::new("nazoauth-release")?;
        let target = release_target().context("this platform has no official Release binary")?;
        let suffix = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let updater = format!("nazoauthctl-{target}{suffix}");
        let identity = format!(
            "https://github.com/{repository}/.github/workflows/release-security.yml@refs/tags/{version}"
        );
        let binary = format!("nazoauth-{target}{suffix}");
        download(
            repository,
            &version,
            &binary,
            work.path(),
            MAX_UNATTESTED_UPDATER_BYTES,
        )?;
        let manifest = verified_attested_manifest(
            repository,
            &version,
            work.path(),
            &binary,
            &identity,
            container_engine,
        )
        .or_else(|binary_error| {
            if !matches!(version.as_str(), "v0.1.18" | "v0.1.19") {
                return Err(binary_error);
            }
            download(
                repository,
                &version,
                &updater,
                work.path(),
                MAX_UNATTESTED_UPDATER_BYTES,
            )?;
            verified_attested_manifest(
                repository,
                &version,
                work.path(),
                &updater,
                &identity,
                container_engine,
            )
        })?;
        manifest.validate(&version, &identity)?;
        manifest.validate_controller_compatibility()?;
        Ok(Self { work, manifest })
    }

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
        }
        verify_artifact(&path, artifact)?;
        Ok(path)
    }

    pub(crate) fn persist_verification_evidence(&self, destination: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(destination)?;
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
            atomic_write(&destination.join(name), &fs::read(entry.path())?, 0o400)?;
        }
        Ok(())
    }
}

impl VerifiedControllerRelease {
    pub(crate) fn fetch(
        requested_version: Option<&str>,
        container_engine: Option<&str>,
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
        let response = Process::new("curl")
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
                    "https://api.github.com/repos/{CONTROLLER_REPOSITORY}/attestations/sha256%3A{digest}?per_page={ATTESTATION_PAGE_SIZE}&predicate_type={}",
                    urlencoding::encode(CONTROLLER_PROVENANCE_PREDICATE)
                ),
            ])
            .stdout()?;
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
            if attestation.repository_id == 0 || attestation.initiator.trim().is_empty() {
                bail!("GitHub returned invalid controller attestation metadata");
            }
            if attestation
                .bundle
                .get("mediaType")
                .and_then(serde_json::Value::as_str)
                != Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
            {
                bail!("GitHub returned an unsupported controller Sigstore bundle");
            }
            let statement = statement_from_bundle(&attestation.bundle)?;
            if statement.kind != "https://in-toto.io/Statement/v1"
                || statement.predicate_type != CONTROLLER_PROVENANCE_PREDICATE
            {
                continue;
            }
            if !statement.subject.iter().any(|subject| {
                subject.name == artifact_name
                    && subject
                        .digest
                        .get("sha256")
                        .is_some_and(|value| value == &digest)
            }) {
                bail!("controller provenance does not bind the downloaded binary");
            }
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
                container_engine,
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
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(self.work.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("controller-attestation-") && name.ends_with(".json") {
                atomic_write(&destination.join(name), &fs::read(entry.path())?, 0o400)?;
            }
        }
        Ok(())
    }
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

fn verified_attested_manifest(
    repository: &str,
    version: &str,
    work: &Path,
    blob: &str,
    identity: &str,
    container_engine: Option<&str>,
) -> anyhow::Result<ReleaseManifest> {
    let digest = sha256(&work.join(blob))?;
    let response = Process::new("curl")
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
                urlencoding::encode(RELEASE_PREDICATE)
            ),
        ])
        .stdout()?;
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
                container_engine,
            )
        },
    )
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
        if attestation.repository_id == 0 || attestation.initiator.trim().is_empty() {
            bail!("GitHub returned invalid Release attestation metadata");
        }
        if attestation
            .bundle
            .get("mediaType")
            .and_then(serde_json::Value::as_str)
            != Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
        {
            bail!("GitHub returned an unsupported Sigstore bundle");
        }
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
    if statement.kind != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != RELEASE_PREDICATE
    {
        return Ok(None);
    }
    if !statement.subject.iter().any(|subject| {
        subject.name == blob
            && subject
                .digest
                .get("sha256")
                .is_some_and(|subject_digest| subject_digest == digest)
    }) {
        bail!("Release attestation subject does not bind the downloaded artifact");
    }
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
    container_engine: Option<&str>,
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
    let engine = container_engine.context("Cosign is required when no container engine exists")?;
    Process::new(engine)
        .args(containerized_cosign_attestation_arguments(
            work, bundle, blob, identity, predicate,
        ))
        .run_quiet()
}

fn containerized_cosign_attestation_arguments(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
    predicate: &str,
) -> Vec<String> {
    vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--user".to_owned(),
        "0:0".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--read-only".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--pids-limit".to_owned(),
        "64".to_owned(),
        "--tmpfs".to_owned(),
        "/root/.sigstore:rw,noexec,nosuid,nodev,size=16m".to_owned(),
        "-v".to_owned(),
        format!("{}:/work:ro,Z", work.display()),
        COSIGN_IMAGE.to_owned(),
        "verify-blob-attestation".to_owned(),
        "--bundle".to_owned(),
        format!("/work/{bundle}"),
        "--type".to_owned(),
        predicate.to_owned(),
        "--certificate-identity".to_owned(),
        identity.to_owned(),
        "--certificate-oidc-issuer".to_owned(),
        "https://token.actions.githubusercontent.com".to_owned(),
        format!("/work/{blob}"),
    ]
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
