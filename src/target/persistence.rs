//! Readers for published persistent formats. Keep these when the current writer evolves.
//! Reads preserve source files; existing locked mutations save normalized state.

use super::deployment_state::{DEPLOYMENT_STATE_SCHEMA, DeploymentState};
use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Recovery constraints recorded by v0.2.27, also included in hashed backup manifests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRollbackPolicy {
    pub artifact: bool,
    pub schema_compatible: bool,
    pub database_restore: LegacyDatabaseRestore,
    pub irreversible_migration: bool,
    pub minimum_supported_version: String,
    pub migration_floor: String,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LegacyDatabaseRestore {
    Backup,
    Pitr,
    None,
}

impl LegacyRollbackPolicy {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        semver::Version::parse(&self.minimum_supported_version)?;
        if self.rationale.trim().is_empty()
            || self.migration_floor.is_empty()
            || !self.migration_floor.bytes().all(|c| c.is_ascii_digit())
            || (self.irreversible_migration && self.schema_compatible)
            || (self.schema_compatible && !self.artifact)
        {
            bail!("invalid historical rollback policy");
        }
        Ok(())
    }

    fn allows_artifact_rollback(&self) -> bool {
        self.artifact && self.schema_compatible && !self.irreversible_migration
    }
}

pub(crate) fn read_deployment_state(bytes: &[u8]) -> anyhow::Result<DeploymentState> {
    #[derive(Deserialize)]
    struct Schema {
        schema: u32,
    }
    if serde_json::from_slice::<Schema>(bytes)?.schema == DEPLOYMENT_STATE_SCHEMA {
        let state: DeploymentState = serde_json::from_slice(bytes)?;
        state.validate()?;
        return Ok(state);
    }
    let mut value: Value = serde_json::from_slice(bytes)?;
    match value.get("schema").and_then(Value::as_u64) {
        Some(7) => {
            let object = value
                .as_object_mut()
                .context("deployment state must be an object")?;
            let policy: LegacyRollbackPolicy = serde_json::from_value(
                object
                    .remove("current_rollback_policy")
                    .context("schema 7 requires its rollback policy")?,
            )?;
            policy.validate()?;
            if let Some(previous) = object
                .remove("previous_rollback_policy")
                .filter(|v| !v.is_null())
            {
                serde_json::from_value::<LegacyRollbackPolicy>(previous)?.validate()?;
            }
            // Preserve the old prohibition even when it retained a previous artifact.
            if !policy.allows_artifact_rollback() {
                if let Some(artifact) = object.get_mut("artifact").and_then(Value::as_object_mut) {
                    artifact.insert("previous".into(), Value::Null);
                }
                object.remove("previous_release");
            }
            if let Some(migration) = object
                .get_mut("applied_migration")
                .and_then(Value::as_object_mut)
            {
                let policy = migration
                    .remove("rollback_policy")
                    .context("schema 7 migration requires its rollback policy")?;
                serde_json::from_value::<LegacyRollbackPolicy>(policy)?.validate()?;
            }
            object.insert("schema".into(), DEPLOYMENT_STATE_SCHEMA.into());
        }
        Some(version) if version == u64::from(DEPLOYMENT_STATE_SCHEMA) => {}
        other => bail!(
            "unsupported deployment state schema {other:?}; preserve this state and use a controller supporting its format"
        ),
    }
    let state: DeploymentState = serde_json::from_value(value)?;
    state.validate()?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetStateStore;
    const V027: &[u8] = include_bytes!("../../tests/fixtures/persistence/v0.2.27/state.json");

    #[test]
    fn published_v028_formats_remain_readable() -> anyhow::Result<()> {
        let state = read_deployment_state(include_bytes!(
            "../../tests/fixtures/persistence/v0.2.28/state.json"
        ))?;
        assert_eq!(state.config.revision, 8);
        let manifest: crate::target::SnapshotManifest = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/persistence/v0.2.28/snapshot-manifest.json"
        ))?;
        manifest.validate()?;
        Ok(())
    }

    #[test]
    fn published_snapshot_preserves_checksum_and_rejects_tampering() -> anyhow::Result<()> {
        let bytes =
            include_bytes!("../../tests/fixtures/persistence/v0.2.27/snapshot-manifest.json");
        let mut manifest: crate::target::SnapshotManifest = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        let original_hash = manifest.manifest_sha256.clone();
        let roundtrip: crate::target::SnapshotManifest =
            serde_json::from_slice(&serde_json::to_vec(&manifest)?)?;
        roundtrip.validate()?;
        assert_eq!(roundtrip.manifest_sha256, original_hash);
        manifest
            .rollback_policy
            .as_mut()
            .unwrap()
            .rationale
            .push_str("tampered");
        assert!(manifest.validate().is_err());
        Ok(())
    }

    #[test]
    fn published_state_reads_without_writes_and_normalizes_on_mutation() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("ctl-state-compat")?;
        let store = TargetStateStore::open(temp.path())?;
        let scope = store.scope_dir("deploy-upgrade")?;
        crate::filesystem::ensure_private_directory(&scope, "fixture state")?;
        let path = scope.join("state.json");
        crate::filesystem::atomic_write(&path, V027, 0o600)?;
        let state = store.load_existing("deploy-upgrade")?;
        assert_eq!(state.config.revision, 8);
        assert_eq!(state.current_release.as_ref().unwrap().version, "0.2.11");
        assert!(state.artifact.current.is_some());
        assert!(state.artifact.previous.is_none());
        assert_eq!(std::fs::read(&path)?, V027);
        store.apply_config(
            "deploy-upgrade",
            8,
            "/etc/nazoauth/config.json".into(),
            "nazoauth-config-v1".into(),
            "config-update",
        )?;
        let saved: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(saved["schema"], DEPLOYMENT_STATE_SCHEMA);
        assert!(saved.get("current_rollback_policy").is_none());
        assert_eq!(store.load_existing("deploy-upgrade")?.config.revision, 9);
        Ok(())
    }

    #[test]
    fn pending_migration_and_allowed_rollback_keep_their_facts() -> anyhow::Result<()> {
        let mut value: Value = serde_json::from_slice(V027)?;
        value["current_rollback_policy"] = value["previous_rollback_policy"].clone();
        let readable = read_deployment_state(&serde_json::to_vec(&value)?)?;
        assert!(readable.artifact.previous.is_some());
        value["applied_migration"] = serde_json::json!({
            "operation_id":"01900000-0000-7000-8000-000000000002",
            "target_artifact":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "rollback_policy":value["current_rollback_policy"],"applied_at":"2026-09-05T16:00:00Z"
        });
        let state = read_deployment_state(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            state.applied_migration.unwrap().operation_id,
            "01900000-0000-7000-8000-000000000002"
        );
        value["unknown_authority"] = true.into();
        assert!(read_deployment_state(&serde_json::to_vec(&value)?).is_err());
        Ok(())
    }
}
