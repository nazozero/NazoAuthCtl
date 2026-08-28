use anyhow::{Context as _, ensure};
use serde::Deserialize;

use crate::{
    model::ReleaseRollbackPolicy,
    target::{BuildIdentity, OfficialArtifactRef},
};

const EMBEDDED_CANDIDATE: Option<&str> = option_env!("NAZOAUTHCTL_PRE_RELEASE_CANDIDATE_JSON");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateRelease {
    pub(crate) repository: String,
    pub(crate) version: String,
    pub(crate) oci_image: String,
    pub(crate) oci_digest: String,
    pub(crate) backend_commit: String,
    pub(crate) rollback: ReleaseRollbackPolicy,
}

impl CandidateRelease {
    pub(crate) fn identity(&self) -> anyhow::Result<BuildIdentity> {
        BuildIdentity::new(
            nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT,
            &self.version,
            &self.backend_commit,
        )
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.repository == crate::instance_lifecycle::SERVER_REPOSITORY,
            "pre-release candidate repository is not NazoAuth"
        );
        ensure!(
            !self.oci_image.trim().is_empty() && !self.oci_image.chars().any(char::is_control),
            "pre-release candidate OCI image is invalid"
        );
        let digest = self
            .oci_digest
            .strip_prefix("sha256:")
            .context("pre-release candidate OCI digest must use sha256")?;
        ensure!(
            digest.len() == 64
                && digest
                    .chars()
                    .all(|character| character.is_ascii_hexdigit()),
            "pre-release candidate OCI digest is invalid"
        );
        self.identity()?;
        self.rollback.validate()
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
                "backend_commit":"{}",
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
            "b".repeat(40),
        );
        let candidate: CandidateRelease = serde_json::from_str(&encoded)?;
        candidate.validate()?;

        let unknown = encoded.replacen("\"repository\"", "\"unknown\":true,\"repository\"", 1);
        assert!(serde_json::from_str::<CandidateRelease>(&unknown).is_err());
        Ok(())
    }
}
