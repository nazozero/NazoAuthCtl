//! Client-side ControlOperation construction (goal plan 05 §2, frozen
//! contract in `nazo-operator-protocol::control_operation`).
//!
//! [`build_signed_control_operation`] is the selector-facing entry point for
//! the only place in ctl that signs a ControlOperation. The dispatch path
//! resolves its selector before reaching the signer and passes the resulting
//! [`InstanceRecord`] directly, so the record is read only once. The signer
//! loads the active private key via the instance's `controller_key_ref`, fills
//! the envelope (`deployment_id` from the record; config revision and
//! operation payload supplied by the caller), mints one UUIDv7
//! `operation_id`, canonicalizes, computes the request hash, and signs
//! exactly once. The returned id/hash pair is what the journaling layer (E06)
//! records before dispatch.

use anyhow::{Context, bail};
use nazo_operator_protocol::{
    CONTROL_OPERATION_SCHEMA, ControlOperation, ControlOperationPayload,
    control_operation_request_hash, sign_control_operation,
};
use uuid::Uuid;

use crate::registry::{InstanceRecord, RegistryStore};

use super::store::{ControllerKeyStore, LoadedControllerKey};

/// Prefix every [`InstanceRecord::controller_key_ref`] resolved by this
/// module must carry.
pub const CONTROLLER_KEY_REF_PREFIX: &str = "controller-keys/";

/// Caller-supplied content of one control operation. The envelope identity
/// fields (`operation_id`, `kid`, `deployment_id`) are owned by this module.
pub struct ControlOperationInput {
    pub operation: ControlOperationPayload,
    pub config_revision: String,
}

/// One signed, ready-to-dispatch control operation plus the identifiers the
/// journal must persist. Only public material; safe to log.
#[derive(Clone, Debug)]
pub struct SignedControlOperation {
    /// Full envelope as signed (canonical encoding enforced by the contract).
    pub operation: ControlOperation,
    /// Compact JWS (`header.payload.signature`, EdDSA over canonical bytes).
    pub compact_jws: String,
    /// Lowercase hex SHA-256 of the canonical payload bytes.
    pub request_hash: String,
    /// Echo of `operation.operation_id` for journaling ergonomics.
    pub operation_id: String,
    /// Echo of the signing controller kid.
    pub kid: String,
    /// Echo of the audience deployment id.
    pub deployment_id: String,
}

/// Extract the deployment identifier a key reference points at. References
/// are strictly `<PREFIX><deployment_id>` with a store-legal identifier;
/// anything else fails closed so a tampered registry record cannot redirect
/// key loading to another path.
pub fn deployment_from_key_ref(key_ref: &str) -> anyhow::Result<&str> {
    let rest = key_ref
        .strip_prefix(CONTROLLER_KEY_REF_PREFIX)
        .with_context(|| {
            format!("controller key ref must start with '{CONTROLLER_KEY_REF_PREFIX}'")
        })?;
    if rest.contains('\\') {
        bail!("controller key ref must not contain path separators");
    }
    super::store::validate_instance_identifier(rest)
        .with_context(|| "controller key ref must address exactly one instance key directory")?;
    Ok(rest)
}

/// Resolve a selector to its registry record: exact deployment id first,
/// then unique alias. Both namespaces are unique, so at most one fallback
/// candidate can exist.
fn resolve_instance(registry: &RegistryStore, selector: &str) -> anyhow::Result<InstanceRecord> {
    if let Some(record) = registry.instance_by_deployment(selector)? {
        return Ok(record);
    }
    if let Some(record) = registry.instance_by_alias(selector)? {
        return Ok(record);
    }
    bail!("unknown instance selector '{selector}' (no registered deployment id or alias matches)")
}

/// Build, hash, and sign one ControlOperation for the selected instance.
///
/// Signing requires an already-active local key: this function never mints
/// keys silently. Unbound instances must go through the bind flow first.
pub fn build_signed_control_operation(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    instance_selector: &str,
    input: ControlOperationInput,
) -> anyhow::Result<SignedControlOperation> {
    let record = resolve_instance(registry, instance_selector)?;
    build_signed_control_operation_with_id(keys, &record, input, None)
}

/// Same as [`build_signed_control_operation`] with an explicit operation id.
/// `None` mints a fresh UUIDv7; `Some(id)` rebuilds the exact envelope for a
/// journaled resume (E06): combined with deterministic Ed25519 this yields a
/// byte-identical compact JWS, so the server sees one operation, never a new
/// identity. The caller owns resume-safety checks (hash equality); this
/// function performs no gating of its own. The caller must pass the already
/// resolved record so selector lookup is not repeated inside a dispatch.
pub(crate) fn build_signed_control_operation_with_id(
    keys: &ControllerKeyStore,
    record: &InstanceRecord,
    input: ControlOperationInput,
    operation_id: Option<&str>,
) -> anyhow::Result<SignedControlOperation> {
    let key_ref = record.controller_key_ref.as_deref().with_context(|| {
        format!(
            "{}: instance '{}' has no bound controller key; run `nazoauthctl bind --instance {}` first",
            crate::error_codes::CONTROL_BINDING_REQUIRED,
            record.alias,
            record.alias
        )
    })?;
    let ref_deployment = deployment_from_key_ref(key_ref)?;
    if ref_deployment != record.deployment_id {
        bail!(
            "{}: instance '{}' carries controller key ref for deployment '{ref_deployment}' but is \
             registered as '{}'; refusing to sign with mismatched binding",
            crate::error_codes::CONTROL_BINDING_REQUIRED,
            record.alias,
            record.deployment_id
        );
    }
    let loaded: LoadedControllerKey =
        keys.load_active(&record.deployment_id)?.with_context(|| {
            format!(
                "instance '{}' has no locally stored active controller key",
                record.alias
            )
        })?;

    let operation = ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: match operation_id {
            Some(id) => id.to_owned(),
            None => Uuid::now_v7().to_string(),
        },
        kid: loaded.kid().to_owned(),
        deployment_id: record.deployment_id.clone(),
        config_revision: input.config_revision,
        operation: input.operation,
    };
    let request_hash = control_operation_request_hash(&operation)?;
    let compact_jws = sign_control_operation(&operation, loaded.signing_key())?;
    Ok(SignedControlOperation {
        operation_id: operation.operation_id.clone(),
        kid: loaded.kid().to_owned(),
        deployment_id: record.deployment_id.clone(),
        request_hash,
        compact_jws,
        operation,
    })
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use nazo_operator_protocol::{ProtocolError, verify_control_operation_signature};

    use super::*;
    use crate::controller_identity::store::controller_key_ref_for;
    use crate::filesystem;
    use crate::registry::InstanceRecord;

    struct Fixture {
        _temp: filesystem::PrivateTempDir,
        registry: RegistryStore,
        keys: ControllerKeyStore,
    }

    fn fixture() -> anyhow::Result<Fixture> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-control-op-test")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        let keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        Ok(Fixture {
            _temp: temp,
            registry,
            keys,
        })
    }

    fn register_instance(
        fixture: &Fixture,
        alias: &str,
        deployment_id: &str,
    ) -> anyhow::Result<()> {
        let host = fixture.registry.ensure_local_host()?;
        let mut instance = InstanceRecord::new(
            deployment_id,
            alias,
            host.host_id,
            "https://auth.example.com",
        )?;
        instance.controller_key_ref = Some(controller_key_ref_for(deployment_id)?);
        fixture.registry.add_instance(instance)?;
        Ok(())
    }

    fn sample_input() -> ControlOperationInput {
        ControlOperationInput {
            operation: ControlOperationPayload::MigrateApply,
            config_revision: "rev-1".to_owned(),
        }
    }

    fn is_uuidv7(value: &str) -> bool {
        value.len() == 36 && value.as_bytes()[14] == b'7'
    }

    #[test]
    fn roundtrip_against_contract_verify_api() -> anyhow::Result<()> {
        let f = fixture()?;
        register_instance(&f, "production", "deploy-alpha")?;
        f.keys.get_or_create_active("deploy-alpha")?;

        let signed =
            build_signed_control_operation(&f.registry, &f.keys, "production", sample_input())?;

        assert!(is_uuidv7(&signed.operation_id));
        assert_eq!(signed.operation_id, signed.operation.operation_id);
        assert_eq!(signed.kid, signed.operation.kid);
        assert_eq!(signed.deployment_id, "deploy-alpha");
        assert_eq!(
            signed.request_hash,
            control_operation_request_hash(&signed.operation)?
        );

        let store_key = f.keys.load_active("deploy-alpha")?.expect("active");
        let decoded = verify_control_operation_signature(
            &signed.compact_jws,
            signed.kid.as_str(),
            &store_key.verifying_key(),
        )?;
        assert_eq!(decoded, signed.operation);
        Ok(())
    }

    #[test]
    fn wrong_signing_key_is_rejected() -> anyhow::Result<()> {
        let f = fixture()?;
        register_instance(&f, "alpha", "deploy-alpha")?;
        register_instance(&f, "beta", "deploy-beta")?;
        f.keys.get_or_create_active("deploy-alpha")?;
        f.keys.get_or_create_active("deploy-beta")?;

        let alpha_signed =
            build_signed_control_operation(&f.registry, &f.keys, "alpha", sample_input())?;
        let beta_key = f.keys.load_active("deploy-beta")?.expect("beta active");

        // Verifying under beta's kid fails at the header/kid binding before
        // any cryptographic work happens.
        let error = verify_control_operation_signature(
            &alpha_signed.compact_jws,
            beta_key.kid(),
            &beta_key.verifying_key(),
        )
        .expect_err("another instance's kid must not verify this signature");
        assert!(matches!(error, ProtocolError::Header), "{error:?}");

        // Claiming alpha's kid while presenting beta's verifying key fails
        // the signature check itself.
        let error = verify_control_operation_signature(
            &alpha_signed.compact_jws,
            alpha_signed.kid.as_str(),
            &beta_key.verifying_key(),
        )
        .expect_err("another instance's key must not verify this signature");
        assert!(matches!(error, ProtocolError::Signature), "{error:?}");

        // Contract-level guard: an envelope claiming alpha's kid may never be
        // signed by beta's key.
        let mut forged = alpha_signed.operation.clone();
        forged.operation_id = Uuid::now_v7().to_string();
        let error = sign_control_operation(&forged, beta_key.signing_key())
            .expect_err("kid/signer mismatch must be rejected");
        assert!(matches!(error, ProtocolError::Policy(_)), "{error:?}");
        Ok(())
    }

    #[test]
    fn kid_mismatch_is_rejected() -> anyhow::Result<()> {
        let f = fixture()?;
        register_instance(&f, "production", "deploy-alpha")?;
        f.keys.get_or_create_active("deploy-alpha")?;
        let signed =
            build_signed_control_operation(&f.registry, &f.keys, "production", sample_input())?;
        let store_key = f.keys.load_active("deploy-alpha")?.expect("active");

        // A syntactically valid but different kid fails verification even
        // though the signature itself is untouched and correct for the
        // original kid.
        let other_kid = URL_SAFE_NO_PAD.encode([42u8; 32]);
        let error = verify_control_operation_signature(
            &signed.compact_jws,
            other_kid.as_str(),
            &store_key.verifying_key(),
        )
        .expect_err("expected-kid mismatch must fail closed");
        assert!(
            matches!(error, ProtocolError::Header | ProtocolError::Policy(_)),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn signing_is_deterministic_per_envelope() -> anyhow::Result<()> {
        let f = fixture()?;
        register_instance(&f, "production", "deploy-alpha")?;
        let store_key = f.keys.get_or_create_active("deploy-alpha")?;

        let build = |revision: &str| ControlOperation {
            schema: CONTROL_OPERATION_SCHEMA,
            operation_id: "01900000-0000-7000-8000-000000000001".to_owned(),
            kid: store_key.kid().to_owned(),
            deployment_id: "deploy-alpha".to_owned(),
            config_revision: revision.to_owned(),
            operation: ControlOperationPayload::MigrateApply,
        };

        let first = sign_control_operation(&build("rev-1"), store_key.signing_key())?;
        let second = sign_control_operation(&build("rev-1"), store_key.signing_key())?;
        assert_eq!(first, second, "Ed25519 signs deterministically");

        let changed = sign_control_operation(&build("rev-2"), store_key.signing_key())?;
        assert_ne!(first, changed, "any envelope change alters the JWS");
        assert_ne!(
            control_operation_request_hash(&build("rev-1"))?,
            control_operation_request_hash(&build("rev-2"))?
        );
        Ok(())
    }

    #[test]
    fn helper_resolves_alias_and_deployment_selectors() -> anyhow::Result<()> {
        let f = fixture()?;
        register_instance(&f, "production", "deploy-alpha")?;
        f.keys.get_or_create_active("deploy-alpha")?;

        let by_alias =
            build_signed_control_operation(&f.registry, &f.keys, "production", sample_input())?;
        let by_id =
            build_signed_control_operation(&f.registry, &f.keys, "deploy-alpha", sample_input())?;
        assert_eq!(by_alias.kid, by_id.kid);
        assert_ne!(by_alias.operation_id, by_id.operation_id);

        let error = build_signed_control_operation(&f.registry, &f.keys, "missing", sample_input())
            .expect_err("unknown selector");
        assert!(error.to_string().contains("unknown instance selector"));
        Ok(())
    }

    #[test]
    fn unbound_and_misbound_instances_refuse_to_sign() -> anyhow::Result<()> {
        let f = fixture()?;
        let host = f.registry.ensure_local_host()?;

        // Unbound: no controller_key_ref at all.
        let bare = InstanceRecord::new(
            "deploy-bare",
            "bare",
            host.host_id,
            "https://auth.example.com",
        )?;
        f.registry.add_instance(bare)?;
        let error = build_signed_control_operation(&f.registry, &f.keys, "bare", sample_input())
            .expect_err("unbound instance");
        assert!(
            error.to_string().contains("has no bound controller key")
                && error
                    .to_string()
                    .contains("nazoauthctl bind --instance bare"),
            "{error}"
        );

        // Misbound: ref points at another deployment's directory.
        let mut misbound = InstanceRecord::new(
            "deploy-mis",
            "mis",
            host.host_id,
            "https://auth.example.com",
        )?;
        misbound.controller_key_ref = Some(controller_key_ref_for("deploy-other")?);
        f.registry.add_instance(misbound)?;
        let error = build_signed_control_operation(&f.registry, &f.keys, "mis", sample_input())
            .expect_err("mismatched ref");
        assert!(error.to_string().contains("mismatched binding"), "{error}");

        // Correctly bound but no local key material yet.
        register_instance(&f, "pending", "deploy-pending")?;
        let error = build_signed_control_operation(&f.registry, &f.keys, "pending", sample_input())
            .expect_err("no local key yet");
        assert!(
            error.to_string().contains("active controller key"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn key_refs_are_parsed_strictly() {
        assert_eq!(
            deployment_from_key_ref("controller-keys/deploy-alpha").expect("valid"),
            "deploy-alpha"
        );
        for bad in [
            "keys/deploy-alpha",
            "controller-keys/",
            "controller-keys/a/b",
            "controller-keys/../secret",
            "controller-keys/with space",
            "",
        ] {
            assert!(deployment_from_key_ref(bad).is_err(), "'{bad}' rejected");
        }
    }

    #[test]
    fn registry_json_stays_free_of_private_key_material() -> anyhow::Result<()> {
        use std::fs;

        let f = fixture()?;
        register_instance(&f, "production", "deploy-alpha")?;
        f.keys.get_or_create_active("deploy-alpha")?;

        // The only secret in the whole setup lives in the key store:
        let store_root = f.keys.root();
        let mut secrets = Vec::new();
        for entry in fs::read_dir(store_root.join("deploy-alpha").join("keys"))? {
            let path = entry?.path();
            let text = fs::read_to_string(&path)?;
            let value: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(material) = value.get("private_key").and_then(|v| v.as_str()) {
                secrets.push(material.to_owned());
            }
        }
        assert!(!secrets.is_empty(), "fixture sanity: one key stored");

        // ...and none of it may appear anywhere under the registry root.
        let registry_root = f.registry.root().to_path_buf();
        let mut checked = 0;
        for entry in walk_json(&registry_root) {
            let text = fs::read_to_string(&entry)?;
            checked += 1;
            for secret in &secrets {
                assert!(
                    !text.contains(secret.as_str()),
                    "private key material leaked into {}",
                    entry.display()
                );
            }
            for marker in ["PRIVATE KEY", "-----BEGIN", "private_key"] {
                assert!(
                    !text.contains(marker),
                    "marker '{marker}' found in {}",
                    entry.display()
                );
            }
        }
        assert!(checked >= 1, "expected at least one registry record");

        // The stored reference is exactly the canonical locator.
        let instance = f.registry.instance_by_alias("production")?.unwrap();
        assert_eq!(
            instance.controller_key_ref.as_deref(),
            Some("controller-keys/deploy-alpha")
        );
        Ok(())
    }

    fn walk_json(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let entries = std::fs::read_dir(dir).expect("registry root readable");
        for entry in entries {
            let path = entry.expect("entry readable").path();
            if path.is_dir() {
                found.extend(walk_json(&path));
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                found.push(path);
            }
        }
        found.sort();
        found
    }
}
