use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

fn safe_protocol_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseManifest {
    pub(crate) schema: u32,
    pub(crate) version: String,
    pub(crate) target: String,
    pub(crate) backend_commit: String,
    pub(crate) release_identity: String,
    pub(crate) embedded: nazo_operator_protocol::EmbeddedIdentity,
    #[serde(default)]
    pub(crate) operator_protocol: Option<OperatorProtocolCompatibility>,
    pub(crate) artifacts: BTreeMap<String, Artifact>,
    pub(crate) frontend: FrontendRelease,
    pub(crate) oci: OciRelease,
    pub(crate) rollback: Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorProtocolCompatibility {
    pub(crate) version: u32,
    pub(crate) minimum_ctl_version: String,
    pub(crate) maximum_ctl_version_exclusive: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) repository: String,
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrontendRelease {
    pub(crate) repository: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) release_identity: String,
    pub(crate) artifact: Artifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OciRelease {
    pub(crate) repository: String,
    pub(crate) index_digest: String,
    pub(crate) platform_manifests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollback {
    pub(crate) artifact: bool,
    pub(crate) schema_compatible: bool,
    pub(crate) database_restore: DatabaseRestore,
    pub(crate) irreversible_migration: bool,
    pub(crate) minimum_supported_version: String,
    pub(crate) migration_floor: String,
    pub(crate) rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DatabaseRestore {
    Backup,
    Pitr,
    None,
}

impl ReleaseManifest {
    pub(crate) fn validate(&self, version: &str, expected_identity: &str) -> anyhow::Result<()> {
        let target = release_target().context("this platform has no official Release target")?;
        if !matches!(self.schema, 4 | 5)
            || self.version != version
            || self.target != target
            || self.release_identity != expected_identity
            || self.embedded.release != self.version
            || self.embedded.revision != self.backend_commit
            || self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION
            || !safe_protocol_identifier(&self.embedded.build_id)
            || !is_lower_hex(&self.backend_commit, 40)
        {
            bail!("signed release manifest failed policy validation");
        }
        match (self.schema, &self.operator_protocol) {
            (4, None) => {}
            (5, Some(protocol)) if protocol.version == self.embedded.protocol => {}
            _ => bail!("signed release manifest has an invalid operator protocol contract"),
        }
        if self.rollback.rationale.trim().is_empty()
            || !semantic_tag(&format!("v{}", self.rollback.minimum_supported_version))
            || !self
                .rollback
                .migration_floor
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            bail!("signed release manifest has invalid recovery policy");
        }
        if self.rollback.irreversible_migration && self.rollback.schema_compatible {
            bail!("irreversible migrations cannot claim schema-compatible rollback");
        }
        if self.rollback.schema_compatible && !self.rollback.artifact {
            bail!("schema-compatible rollback requires a retained artifact");
        }
        let expected = if self.schema == 4 {
            BTreeSet::from(["binary".to_owned(), "updater".to_owned()])
        } else {
            BTreeSet::from(["binary".to_owned()])
        };
        if self.artifacts.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("signed release manifest has an unexpected artifact set");
        }
        let executable_suffix = executable_suffix(&self.target);
        let expected_binary = format!("nazoauth-{}{executable_suffix}", self.target);
        if self.artifacts["binary"].name != expected_binary {
            bail!("signed release manifest artifact does not match its target");
        }
        if self.schema == 4 {
            let expected_updater = format!("nazoauthctl-{}{executable_suffix}", self.target);
            if self.artifacts["updater"].name != expected_updater {
                bail!("signed release manifest artifact does not match its target");
            }
        }
        for artifact in self.artifacts.values() {
            if artifact.size == 0
                || artifact.repository != "nazozero/NazoAuth"
                || !safe_artifact_name(&artifact.name)
                || !is_lower_hex(&artifact.sha256, 64)
            {
                bail!("signed release manifest contains an invalid artifact");
            }
        }
        self.validate_frontend()?;
        self.validate_oci()?;
        Ok(())
    }

    pub(crate) fn validate_controller_compatibility(&self) -> anyhow::Result<()> {
        if self.schema == 4 {
            if !matches!(self.version.as_str(), "v0.1.18" | "v0.1.19")
                || self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION
            {
                bail!("legacy server Release is outside the closed extraction baseline");
            }
            return Ok(());
        }
        let protocol = self
            .operator_protocol
            .as_ref()
            .context("server Release has no operator protocol compatibility contract")?;
        if protocol.version != nazo_operator_protocol::PROTOCOL_VERSION {
            bail!("server Release operator protocol version is unsupported");
        }
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        let minimum = semver::Version::parse(&protocol.minimum_ctl_version)
            .context("server Release minimum ctl version is invalid")?;
        let maximum = semver::Version::parse(&protocol.maximum_ctl_version_exclusive)
            .context("server Release maximum ctl version is invalid")?;
        if minimum >= maximum || current < minimum || current >= maximum {
            bail!("controller version is outside the server Release compatibility range");
        }
        Ok(())
    }

    pub(crate) fn image_ref(&self) -> anyhow::Result<String> {
        Ok(format!(
            "{}@{}",
            self.oci.repository,
            self.runtime_oci_digest()?
        ))
    }

    pub(crate) fn image_oci_digest(&self) -> &str {
        &self.oci.index_digest
    }

    pub(crate) fn runtime_oci_digest(&self) -> anyhow::Result<&str> {
        let platform = runtime_oci_platform(std::env::consts::OS, std::env::consts::ARCH)?;
        self.runtime_oci_digest_for(platform)
    }

    pub(crate) fn runtime_oci_digest_for(&self, platform: &str) -> anyhow::Result<&str> {
        self.oci
            .platform_manifests
            .get(platform)
            .map(String::as_str)
            .context("signed Release has no manifest for this OCI platform")
    }

    fn validate_frontend(&self) -> anyhow::Result<()> {
        let frontend = &self.frontend;
        let expected_identity = format!(
            "https://github.com/{}/.github/workflows/release.yml@refs/tags/{}",
            frontend.repository, frontend.version
        );
        if frontend.repository != "nazozero/NazoAuthWeb"
            || !semantic_tag(&frontend.version)
            || !is_lower_hex(&frontend.commit, 40)
            || frontend.release_identity != expected_identity
            || frontend.artifact.repository != frontend.repository
            || frontend.artifact.name != "nazoauth-web.tar.gz"
            || frontend.artifact.size == 0
            || frontend.artifact.size > 64 * 1024 * 1024
            || !is_lower_hex(&frontend.artifact.sha256, 64)
        {
            bail!("signed release manifest contains an invalid frontend release");
        }
        Ok(())
    }

    fn validate_oci(&self) -> anyhow::Result<()> {
        let expected_platforms =
            BTreeSet::from(["linux/amd64".to_owned(), "linux/arm64".to_owned()]);
        if self.oci.repository != "ghcr.io/nazozero/nazoauth"
            || !oci_digest(&self.oci.index_digest)
            || self
                .oci
                .platform_manifests
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != expected_platforms
            || self
                .oci
                .platform_manifests
                .values()
                .any(|digest| !oci_digest(digest))
        {
            bail!("signed release manifest contains an invalid OCI index");
        }
        Ok(())
    }
}

fn executable_suffix(target: &str) -> &'static str {
    if target.contains("windows") {
        ".exe"
    } else {
        ""
    }
}

fn runtime_oci_platform(os: &str, arch: &str) -> anyhow::Result<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("linux/amd64"),
        ("linux", "aarch64") => Ok("linux/arm64"),
        _ => bail!("managed OCI runtime is supported only on Linux x86-64 and Arm64"),
    }
}

/// Platform key for a container backend: Linux images run identically under
/// Docker/Podman on any host OS (including Windows hosts with a Linux
/// daemon), so the container's platform governs — not the host's.
pub(crate) fn container_oci_platform() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "linux/arm64"
    } else {
        "linux/amd64"
    }
}

pub(crate) fn release_target() -> Option<&'static str> {
    let target_env = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else {
        ""
    };
    release_target_for(std::env::consts::ARCH, std::env::consts::OS, target_env)
}

fn release_target_for(arch: &str, os: &str, target_env: &str) -> Option<&'static str> {
    match (arch, os, target_env) {
        ("x86_64", "linux", "musl") => Some("x86_64-unknown-linux-musl"),
        ("aarch64", "linux", "musl") => Some("aarch64-unknown-linux-musl"),
        ("x86_64", "linux", _) => Some("x86_64-unknown-linux-gnu"),
        ("aarch64", "linux", _) => Some("aarch64-unknown-linux-gnu"),
        ("x86_64", "windows", _) => Some("x86_64-pc-windows-msvc"),
        ("aarch64", "windows", _) => Some("aarch64-pc-windows-msvc"),
        ("x86_64", "macos", _) => Some("x86_64-apple-darwin"),
        ("aarch64", "macos", _) => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

fn oci_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

pub(crate) fn semantic_tag(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(rest).is_ok_and(|parsed| parsed.to_string() == rest)
}

fn safe_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
