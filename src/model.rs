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
    pub(crate) operator_protocol: OperatorProtocolCompatibility,
    pub(crate) artifacts: BTreeMap<String, Artifact>,
    pub(crate) frontend: FrontendRelease,
    pub(crate) oci: OciRelease,
    pub(crate) rollback: ReleaseRollbackPolicy,
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
pub struct ReleaseRollbackPolicy {
    pub artifact: bool,
    pub schema_compatible: bool,
    pub database_restore: DatabaseRestore,
    pub irreversible_migration: bool,
    pub minimum_supported_version: String,
    pub migration_floor: String,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseRestore {
    Backup,
    Pitr,
    None,
}

impl ReleaseRollbackPolicy {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.rationale.trim().is_empty()
            || !semantic_tag(&format!("v{}", self.minimum_supported_version))
            || self.migration_floor.is_empty()
            || !self
                .migration_floor
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            bail!("signed release manifest has invalid recovery policy");
        }
        if self.irreversible_migration && self.schema_compatible {
            bail!("irreversible migrations cannot claim schema-compatible rollback");
        }
        if self.schema_compatible && !self.artifact {
            bail!("schema-compatible rollback requires a retained artifact");
        }
        Ok(())
    }

    pub(crate) fn artifact_rollback_allowed_after_migration(&self) -> bool {
        self.artifact && self.schema_compatible && !self.irreversible_migration
    }
}

#[cfg(test)]
pub(crate) fn test_release_rollback_policy() -> ReleaseRollbackPolicy {
    ReleaseRollbackPolicy {
        artifact: true,
        schema_compatible: true,
        database_restore: DatabaseRestore::Backup,
        irreversible_migration: false,
        minimum_supported_version: "0.2.0".to_owned(),
        migration_floor: "20260828000600".to_owned(),
        rationale: "test release permits schema-compatible artifact rollback".to_owned(),
    }
}

impl ReleaseManifest {
    pub(crate) fn validate(&self, version: &str, expected_identity: &str) -> anyhow::Result<()> {
        let target = release_target().context("this platform has no official Release target")?;
        if self.schema != 5
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
        if self.operator_protocol.version != self.embedded.protocol {
            bail!("signed release manifest has an invalid operator protocol contract");
        }
        self.rollback.validate()?;
        let expected = BTreeSet::from(["binary".to_owned()]);
        if self.artifacts.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("signed release manifest has an unexpected artifact set");
        }
        let executable_suffix = executable_suffix(&self.target);
        let expected_binary = format!("nazoauth-{}{executable_suffix}", self.target);
        if self.artifacts["binary"].name != expected_binary {
            bail!("signed release manifest artifact does not match its target");
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
        let protocol = &self.operator_protocol;
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
