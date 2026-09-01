use anyhow::{Context as _, ensure};
use serde::Deserialize;

use crate::{
    model::ReleaseRollbackPolicy,
    target::{OfficialArtifactRef, ReleaseVersion},
};

const EMBEDDED_CANDIDATE: Option<&str> = option_env!("NAZOAUTHCTL_PRE_RELEASE_CANDIDATE_JSON");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateRelease {
    pub(crate) repository: String,
    pub(crate) version: String,
    oci_image: Option<String>,
    oci_digest: Option<String>,
    host_binary_path: Option<String>,
    host_binary_sha256: Option<String>,
    pub(crate) rollback: ReleaseRollbackPolicy,
}

impl CandidateRelease {
    pub(crate) fn release_version(&self) -> anyhow::Result<ReleaseVersion> {
        ReleaseVersion::new(&self.version)
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.repository == crate::instance_lifecycle::SERVER_REPOSITORY,
            "pre-release candidate repository is not NazoAuth"
        );
        ensure!(
            self.oci_image.is_some() || self.host_binary_path.is_some(),
            "pre-release candidate has no runtime artifact"
        );
        ensure!(
            self.oci_image.is_some() == self.oci_digest.is_some(),
            "pre-release candidate OCI artifact is incomplete"
        );
        ensure!(
            self.host_binary_path.is_some() == self.host_binary_sha256.is_some(),
            "pre-release candidate host binary artifact is incomplete"
        );
        if let Some((image, digest)) = self.oci_artifact() {
            ensure!(
                !image.trim().is_empty() && !image.chars().any(char::is_control),
                "pre-release candidate OCI image is invalid"
            );
            validate_sha256(
                digest
                    .strip_prefix("sha256:")
                    .context("pre-release candidate OCI digest must use sha256")?,
                "OCI digest",
            )?;
        }
        if let Some((path, digest)) = self.host_binary_artifact() {
            ensure!(
                !path.trim().is_empty() && !path.chars().any(char::is_control),
                "pre-release candidate host binary path is invalid"
            );
            validate_sha256(digest, "host binary digest")?;
        }
        self.release_version()?;
        self.rollback.validate()
    }

    pub(crate) fn oci_artifact(&self) -> Option<(&str, &str)> {
        self.oci_image.as_deref().zip(self.oci_digest.as_deref())
    }

    pub(crate) fn host_binary_artifact(&self) -> Option<(&str, &str)> {
        self.host_binary_path
            .as_deref()
            .zip(self.host_binary_sha256.as_deref())
    }

    pub(crate) fn enforce_floor(&self, trusted_version: Option<&str>) -> anyhow::Result<()> {
        if let Some(trusted_version) = trusted_version {
            ensure!(
                crate::release::compare_versions(&self.version, trusted_version)?
                    != std::cmp::Ordering::Less,
                "pre-release candidate is below the trusted version floor"
            );
        }
        Ok(())
    }
}

fn validate_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    ensure!(
        value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit()),
        "pre-release candidate {label} is invalid"
    );
    Ok(())
}

pub(crate) fn resolve(pinned: &OfficialArtifactRef) -> anyhow::Result<Option<CandidateRelease>> {
    let Some(encoded) = EMBEDDED_CANDIDATE else {
        return Ok(None);
    };
    let candidate: CandidateRelease =
        serde_json::from_str(encoded).context("embedded pre-release candidate is invalid")?;
    candidate.validate()?;
    if pinned.repository != candidate.repository
        || pinned.version.as_deref() != Some(candidate.version.as_str())
    {
        return Ok(None);
    }
    Ok(Some(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_manifest_is_closed_and_current() -> anyhow::Result<()> {
        let encoded = format!(
            r#"{{
                "repository":"nazozero/NazoAuth",
                "version":"v0.2.4-candidate",
                "oci_image":"localhost/nazoauth:candidate",
                "oci_digest":"sha256:{}",
                "host_binary_path":"/opt/nazoauth-candidate",
                "host_binary_sha256":"{}",
                "rollback":{{
                    "artifact":true,
                    "schema_compatible":false,
                    "database_restore":"backup",
                    "irreversible_migration":true,
                    "minimum_supported_version":"0.2.2",
                    "migration_floor":"20260828000700",
                    "rationale":"candidate migration requires verified backup recovery"
                }}
            }}"#,
            "a".repeat(64),
            "b".repeat(64),
        );
        let candidate: CandidateRelease = serde_json::from_str(&encoded)?;
        candidate.validate()?;

        let unknown = encoded.replacen("\"repository\"", "\"unknown\":true,\"repository\"", 1);
        assert!(serde_json::from_str::<CandidateRelease>(&unknown).is_err());

        let mut container_only: serde_json::Value = serde_json::from_str(&encoded)?;
        let container_only_object = container_only.as_object_mut().expect("candidate object");
        container_only_object.remove("host_binary_path");
        container_only_object.remove("host_binary_sha256");
        let candidate: CandidateRelease = serde_json::from_value(container_only.clone())?;
        candidate.validate()?;

        container_only
            .as_object_mut()
            .expect("candidate object")
            .remove("oci_digest");
        assert!(
            serde_json::from_value::<CandidateRelease>(container_only)?
                .validate()
                .is_err()
        );
        Ok(())
    }
}
