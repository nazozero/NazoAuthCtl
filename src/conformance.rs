use std::path::PathBuf;

use anyhow::{Context as _, bail};
use nazo_operator_protocol::{ControlOperationPayload, ControlOutcome, ControlResult};

use crate::{
    controller_identity::{
        OperationJournal, operation::ControlOperationInput, prepare_control_operation,
        store::ControllerKeyStore, validate_control_change_set, validate_control_result_binding,
    },
    filesystem::ensure_private_directory,
    registry::RegistryStore,
    runtime_backend::RuntimeBackendKind,
    target::{ControlOperationReceipt, ExecutionTarget, SecretMaterial},
};

const MAX_PROFILE_TOKEN_BYTES: u64 = 4 * 1024;
const DYNAMIC_REGISTRATION_TOKEN_NAME: &str = "dynamic-registration-token";
const CIBA_DECISION_TOKEN_NAME: &str = "ciba-decision-token";
const OPENID4VP_MANAGEMENT_TOKEN_NAME: &str = "openid4vp-management-token";
const OPENID4VCI_MANAGEMENT_TOKEN_NAME: &str = "openid4vci-management-token";

pub struct ConformanceDeploymentEvidence {
    pub deployment_id: String,
    pub target_issuer: String,
    pub release: String,
    pub runtime: ConformanceRuntimeEvidence,
}

pub enum ConformanceRuntimeEvidence {
    OciImage { digest: String },
    HostBinary { sha256: String },
}

/// Holds the deployment/capability observation used by one ordinary provider run.
pub struct ConformanceSession {
    pub deployment_id: String,
    pub target_issuer: String,
    pub evidence: ConformanceDeploymentEvidence,
    pub recovery_dir: PathBuf,
    oidf_tenant_domain: String,
    oidf_suite_origin: String,
    secrets_dir: PathBuf,
    registry: RegistryStore,
    target: Box<dyn ExecutionTarget>,
    controller_keys: ControllerKeyStore,
    config_revision: String,
    openid4vp_evidence_verifier_inputs: OpenId4VpEvidenceVerifierInputs,
}

/// Target-inspected runtime identity used to verify OpenID4VP evidence. The
/// public key is sourced from the managed runtime identity directory and is
/// cryptographically bound to this deployment and issuer by NazoAuth's signed
/// deployment statement. It is never a controller key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenId4VpEvidenceVerifierInputs {
    pub target_issuer: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub instance_public_key_base64: String,
}

/// Immutable controller authorization identity persisted with conformance
/// evidence before the local operation journal is cleared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlOperationIdentity {
    pub operation_id: String,
    pub request_hash: String,
    pub kid: String,
}

/// One durable server answer and the controller authorization that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceControlCompletion {
    pub identity: ControlOperationIdentity,
    pub result: ControlResult,
}

/// Business success and failure are distinct typed outcomes. Both contain the
/// durable result and both must be persisted by the caller callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceControlOutcome {
    Succeeded(ConformanceControlCompletion),
    Failed(ConformanceControlCompletion),
}

fn openid4vp_verifier_inputs(
    target_issuer: &str,
    deployment_id: &str,
    identity: Option<&crate::target::RuntimeInstanceIdentity>,
) -> anyhow::Result<OpenId4VpEvidenceVerifierInputs> {
    let identity =
        identity.context("conformance requires the target's current runtime instance identity")?;
    let instance_public_key =
        nazo_operator_protocol::decode_instance_public_key(&identity.instance_public_key_base64)
            .context("target returned an invalid runtime instance public key")?;
    if nazo_operator_protocol::instance_key_id(&instance_public_key) != identity.instance_key_id {
        bail!("target runtime instance key id does not match its public key");
    }
    Ok(OpenId4VpEvidenceVerifierInputs {
        target_issuer: target_issuer.to_owned(),
        deployment_id: deployment_id.to_owned(),
        runtime_instance_id: identity.runtime_instance_id.clone(),
        instance_key_id: identity.instance_key_id.clone(),
        instance_public_key_base64: nazo_operator_protocol::encode_instance_public_key(
            &instance_public_key,
        ),
    })
}

impl ConformanceSession {
    pub fn open(selector: Option<&str>) -> anyhow::Result<Self> {
        let registry = RegistryStore::open_default()?;
        let record = crate::fleet::resolve_instance(&registry, selector, "conformance")?;
        let oidf_tenant_domain = record.oidf_tenant_domain.clone().with_context(|| {
            format!(
                "OIDF tenant domain is not configured for instance '{}'; run `nazoauthctl --instance {} oidf configure --tenant-domain <domain> --suite <https-origin>` once",
                record.alias, record.alias
            )
        })?;
        let oidf_suite_origin = record.oidf_suite_origin.clone().with_context(|| {
            format!(
                "OIDF Suite origin is not configured for instance '{}'; run `nazoauthctl --instance {} oidf configure --tenant-domain <domain> --suite <https-origin>` once",
                record.alias, record.alias
            )
        })?;
        let host = registry
            .host_by_id(record.host_id)?
            .context("instance references missing host")?;
        let target = crate::fleet::production_target(&host)?;
        crate::fleet::live_probe(target.as_ref(), &host)
            .context("conformance target helper verification failed")?;
        let inspection = target.inspect_instance(&record.deployment_id)?;
        if inspection.deployment_id != record.deployment_id || inspection.issuer != record.issuer {
            bail!(
                "conformance target identity drift: registry binds deployment '{}' to issuer '{}', target reported '{}' and '{}'",
                record.deployment_id,
                record.issuer,
                inspection.deployment_id,
                inspection.issuer
            );
        }
        let openid4vp_evidence_verifier_inputs = openid4vp_verifier_inputs(
            &inspection.issuer,
            &inspection.deployment_id,
            inspection.current_instance_identity.as_ref(),
        )?;

        let artifact = inspection.artifact.current.clone().context(
            "conformance requires a verified current artifact in target DeploymentState",
        )?;
        let identity = inspection
            .current_release
            .as_ref()
            .context("conformance requires verified release version in target DeploymentState")?;
        let runtime = match inspection.runtime.kind {
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                ConformanceRuntimeEvidence::OciImage { digest: artifact }
            }
            RuntimeBackendKind::Host => {
                let sha256 = artifact
                    .strip_prefix("sha256:")
                    .unwrap_or(&artifact)
                    .to_owned();
                ConformanceRuntimeEvidence::HostBinary { sha256 }
            }
        };
        let release = identity.version.clone();

        let evidence = ConformanceDeploymentEvidence {
            deployment_id: record.deployment_id.clone(),
            target_issuer: inspection.issuer.clone(),
            release,
            runtime,
        };

        let recovery_dir = registry
            .root()
            .join("conformance-recovery")
            .join(&record.deployment_id);
        ensure_private_directory(&recovery_dir, "conformance recovery directory")?;

        let secrets_dir = registry.root().join("secrets").join(&record.deployment_id);
        let config_revision = inspection
            .config_revision_marker
            .context("conformance requires the target's current config-revision marker")?;
        let controller_keys = ControllerKeyStore::open_default()?;

        Ok(Self {
            deployment_id: record.deployment_id,
            target_issuer: inspection.issuer,
            evidence,
            recovery_dir,
            oidf_tenant_domain,
            oidf_suite_origin,
            secrets_dir,
            registry,
            target,
            controller_keys,
            config_revision,
            openid4vp_evidence_verifier_inputs,
        })
    }

    pub fn target_issuer(&self) -> &str {
        &self.target_issuer
    }

    pub fn oidf_tenant_domain(&self) -> &str {
        &self.oidf_tenant_domain
    }

    pub fn oidf_suite_origin(&self) -> &str {
        &self.oidf_suite_origin
    }

    pub fn openid4vp_evidence_verifier_inputs(&self) -> &OpenId4VpEvidenceVerifierInputs {
        &self.openid4vp_evidence_verifier_inputs
    }

    pub fn deployment_evidence(&self) -> ConformanceDeploymentEvidence {
        ConformanceDeploymentEvidence {
            deployment_id: self.evidence.deployment_id.clone(),
            target_issuer: self.evidence.target_issuer.clone(),
            release: self.evidence.release.clone(),
            runtime: match &self.evidence.runtime {
                ConformanceRuntimeEvidence::OciImage { digest } => {
                    ConformanceRuntimeEvidence::OciImage {
                        digest: digest.clone(),
                    }
                }
                ConformanceRuntimeEvidence::HostBinary { sha256 } => {
                    ConformanceRuntimeEvidence::HostBinary {
                        sha256: sha256.clone(),
                    }
                }
            },
        }
    }

    pub fn recovery_directory(&self) -> anyhow::Result<PathBuf> {
        Ok(self.recovery_dir.clone())
    }

    /// Execute the one current ControlOperation path. Apply requires exactly
    /// one bounded material blob; every other operation rejects one. A durable
    /// result is passed to `persist` before the ctl journal is cleared. If the
    /// callback fails, the accepted journal entry remains and the next
    /// identical call replays the same server result and controller identity.
    pub fn execute_control_operation<F>(
        &self,
        operation: ControlOperationPayload,
        change_set: Option<Vec<u8>>,
        persist: F,
    ) -> anyhow::Result<ConformanceControlOutcome>
    where
        F: FnOnce(&ConformanceControlCompletion) -> anyhow::Result<()>,
    {
        validate_control_change_set(&operation, change_set.as_deref())?;
        let expected_operation = operation.clone();

        let journal =
            OperationJournal::open(self.controller_keys.instance_dir(&self.deployment_id)?)?;
        let prepared = prepare_control_operation(
            &self.registry,
            &self.controller_keys,
            &journal,
            &self.deployment_id,
            ControlOperationInput {
                operation,
                config_revision: self.config_revision.clone(),
            },
        )?;
        let secret_material = change_set
            .map(SecretMaterial::try_new)
            .transpose()
            .map_err(|error| anyhow::anyhow!("invalid Apply material: {}", error.detail))?;
        let receipt: ControlOperationReceipt = self
            .target
            .execute_control_operation(prepared.request(secret_material)?)?;
        if receipt.operation_id != prepared.signed.operation_id {
            bail!(
                "target returned operation '{}' for controller operation '{}'",
                receipt.operation_id,
                prepared.signed.operation_id
            );
        }
        if !receipt.accepted {
            journal.clear()?;
            bail!("the target definitively rejected the ControlOperation before acceptance");
        }
        journal.mark_accepted(&prepared.signed.operation_id)?;
        let result = receipt.result.context(
            "the target accepted the ControlOperation without returning its durable result",
        )?;
        validate_control_result_binding(
            &prepared.signed.operation_id,
            &prepared.signed.request_hash,
            &expected_operation,
            &result,
        )?;
        let completion = ConformanceControlCompletion {
            identity: ControlOperationIdentity {
                operation_id: prepared.signed.operation_id,
                request_hash: prepared.signed.request_hash,
                kid: prepared.signed.kid,
            },
            result,
        };
        let outcome = match completion.result.outcome {
            ControlOutcome::Succeeded => ConformanceControlOutcome::Succeeded(completion.clone()),
            ControlOutcome::Failed => ConformanceControlOutcome::Failed(completion.clone()),
            ControlOutcome::InProgress => {
                bail!(
                    "the ControlOperation is durably in progress; its accepted journal entry was preserved for replay"
                )
            }
        };
        persist(&completion)?;
        journal.clear()?;
        Ok(outcome)
    }

    pub fn openid4vp_management_token(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.derive_tenant_token(
            OPENID4VP_MANAGEMENT_TOKEN_NAME,
            "OpenID4VP management token",
            tenant_id,
            b"nazoauth/openid4vp/management/v1",
        )
    }

    pub fn openid4vci_management_token(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.derive_tenant_token(
            OPENID4VCI_MANAGEMENT_TOKEN_NAME,
            "OpenID4VCI management token",
            tenant_id,
            b"nazoauth/openid4vci/management/v1",
        )
    }

    pub fn dynamic_registration_initial_access_token(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.derive_tenant_token(
            DYNAMIC_REGISTRATION_TOKEN_NAME,
            "dynamic-registration initial access token",
            tenant_id,
            b"nazoauth/dynamic-client-registration/initial-access/v1",
        )
    }

    pub fn ciba_automated_decision_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(CIBA_DECISION_TOKEN_NAME, "CIBA automated-decision token")
    }

    fn read_profile_secret(
        &self,
        name: &str,
        label: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let path = self.secrets_dir.join(name);
        let bytes =
            crate::filesystem::read_secure_secret_file(&path, label, MAX_PROFILE_TOKEN_BYTES)?;
        let value = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
        if value.len() < 32
            || value.len() > MAX_PROFILE_TOKEN_BYTES as usize
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            bail!("{label} is invalid");
        }
        Ok(zeroize::Zeroizing::new(value.to_owned()))
    }

    fn derive_tenant_token(
        &self,
        name: &str,
        label: &str,
        tenant_id: &str,
        purpose: &'static [u8],
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        use base64::Engine as _;

        let root = self.read_profile_secret(name, label)?;
        let tenant_id = uuid::Uuid::parse_str(tenant_id)
            .with_context(|| format!("{label} tenant ID is invalid"))?;
        let token = nazo_operator_protocol::hkdf_sha256_v1(
            root.as_bytes(),
            tenant_id.as_bytes(),
            purpose,
            32,
        );
        Ok(zeroize::Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token),
        ))
    }
}

pub fn configure_oidf(
    selector: Option<&str>,
    tenant_domain: &str,
    suite_origin: &str,
) -> anyhow::Result<(String, String, String)> {
    let registry = RegistryStore::open_default()?;
    let record = crate::fleet::resolve_instance(&registry, selector, "OIDF configuration")?;
    let record =
        registry.set_oidf_configuration(&record.deployment_id, tenant_domain, suite_origin)?;
    Ok((
        record.alias,
        record.oidf_tenant_domain.unwrap_or_default(),
        record.oidf_suite_origin.unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;

    use super::*;
    use crate::{
        controller_identity::store::controller_key_ref_for,
        registry::RegistryStore,
        target::{HealthSnapshot, HostOperation, HostOverview, HostResult, InstanceInspection},
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedRequest {
        operation_id: String,
        deployment_id: String,
        compact_jws: String,
        change_set_len: Option<usize>,
    }

    struct RecordingTarget {
        requests: Rc<RefCell<Vec<RecordedRequest>>>,
        outcome: Rc<RefCell<ControlOutcome>>,
        result_data: Rc<RefCell<Option<nazo_operator_protocol::ControlResultData>>>,
    }

    impl ExecutionTarget for RecordingTarget {
        fn inspect_host(&self) -> anyhow::Result<HostOverview> {
            anyhow::bail!("unused")
        }

        fn inspect_instance(&self, _: &str) -> anyhow::Result<InstanceInspection> {
            anyhow::bail!("unused")
        }

        fn execute_host_operation(&self, _: &HostOperation) -> anyhow::Result<HostResult> {
            anyhow::bail!("unused")
        }

        fn execute_control_operation(
            &self,
            request: crate::target::ControlOperationRequest,
        ) -> anyhow::Result<ControlOperationReceipt> {
            self.requests.borrow_mut().push(RecordedRequest {
                operation_id: request.operation_id.clone(),
                deployment_id: request.deployment_id.clone(),
                compact_jws: request.compact_jws.clone(),
                change_set_len: request
                    .change_set
                    .as_ref()
                    .map(|value| value.as_bytes().len()),
            });
            let payload = request
                .compact_jws
                .split('.')
                .nth(1)
                .context("missing JWS payload")?;
            let operation: nazo_operator_protocol::ControlOperation =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
            let outcome = *self.outcome.borrow();
            Ok(ControlOperationReceipt {
                operation_id: request.operation_id.clone(),
                accepted: true,
                rejection_code: None,
                result: Some(ControlResult {
                    schema: nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
                    operation_id: request.operation_id.clone(),
                    request_hash: nazo_operator_protocol::control_operation_request_hash(
                        &operation,
                    )?,
                    outcome,
                    error: (outcome == ControlOutcome::Failed)
                        .then_some(nazo_operator_protocol::ControlErrorCode::ExecutionFailed),
                    accepted_at: 1,
                    completed_at: Some(2),
                    result: self.result_data.borrow().clone(),
                }),
            })
        }

        fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
            Ok(HealthSnapshot {
                deployment_id: deployment_id.to_owned(),
                healthy: true,
                summary: "healthy".to_owned(),
                observed_at: Utc::now(),
            })
        }
    }

    #[test]
    fn openid4vp_verifier_inputs_require_the_exact_runtime_public_key_binding() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]).verifying_key();
        let encoded = nazo_operator_protocol::encode_instance_public_key(&key);
        let key_id = nazo_operator_protocol::instance_key_id(&key);
        assert!(
            openid4vp_verifier_inputs("https://auth.example.com", "deploy-alpha", None).is_err()
        );
        let mut identity = crate::target::RuntimeInstanceIdentity {
            runtime_instance_id: "runtime-alpha".to_owned(),
            instance_key_id: "wrong-key-id".to_owned(),
            instance_public_key_base64: encoded.clone(),
        };
        assert!(
            openid4vp_verifier_inputs("https://auth.example.com", "deploy-alpha", Some(&identity))
                .is_err()
        );
        identity.instance_key_id = key_id.clone();
        let inputs =
            openid4vp_verifier_inputs("https://auth.example.com", "deploy-alpha", Some(&identity))
                .expect("valid runtime identity");
        assert_eq!(inputs.target_issuer, "https://auth.example.com");
        assert_eq!(inputs.deployment_id, "deploy-alpha");
        assert_eq!(inputs.runtime_instance_id, "runtime-alpha");
        assert_eq!(inputs.instance_key_id, key_id);
        assert_eq!(inputs.instance_public_key_base64, encoded);
    }

    #[test]
    fn result_binding_and_callback_persistence_both_gate_journal_clear() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("conformance-control-test")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        let host = registry.ensure_local_host()?;
        let deployment_id = "deploy-alpha";
        let mut hello = crate::target::wire::local_hello(vec!["host".to_owned()]);
        hello.target_id = host.host_id.to_string();
        let evidence = crate::registry::DiscoveryEvidence::new(
            &host,
            hello,
            deployment_id,
            "https://auth.example.com",
        )?;
        registry.register_instance(
            &evidence,
            Some("production"),
            crate::registry::ObservationCache::now(true, "test observation"),
        )?;
        registry.update_controller_binding(
            deployment_id,
            None,
            Some(&controller_key_ref_for(deployment_id)?),
        )?;
        let controller_keys = ControllerKeyStore::open(temp.path().join("controller-keys"))?;
        controller_keys.get_or_create_active(deployment_id)?;
        let requests = Rc::new(RefCell::new(Vec::new()));
        let target_outcome = Rc::new(RefCell::new(ControlOutcome::Succeeded));
        let result_data = Rc::new(RefCell::new(None));
        let session = ConformanceSession {
            deployment_id: deployment_id.to_owned(),
            target_issuer: "https://auth.example.com".to_owned(),
            evidence: ConformanceDeploymentEvidence {
                deployment_id: deployment_id.to_owned(),
                target_issuer: "https://auth.example.com".to_owned(),
                release: "1.0.0".to_owned(),
                runtime: ConformanceRuntimeEvidence::HostBinary {
                    sha256: "ab".repeat(32),
                },
            },
            recovery_dir: temp.path().join("recovery"),
            oidf_tenant_domain: "oidf.example.com".to_owned(),
            oidf_suite_origin: "https://suite.example".to_owned(),
            secrets_dir: temp.path().join("secrets"),
            registry,
            target: Box::new(RecordingTarget {
                requests: requests.clone(),
                outcome: target_outcome.clone(),
                result_data: result_data.clone(),
            }),
            controller_keys,
            config_revision: "revision-1".to_owned(),
            openid4vp_evidence_verifier_inputs: OpenId4VpEvidenceVerifierInputs {
                target_issuer: "https://auth.example.com".to_owned(),
                deployment_id: deployment_id.to_owned(),
                runtime_instance_id: "runtime-1".to_owned(),
                instance_key_id: "instance-key-1".to_owned(),
                instance_public_key_base64: "unused-in-this-test".to_owned(),
            },
        };

        let journal = OperationJournal::open(
            session
                .controller_keys
                .instance_dir(&session.deployment_id)?,
        )?;
        assert!(
            session
                .execute_control_operation(
                    ControlOperationPayload::KeysValidate,
                    Some(b"unused".to_vec()),
                    |_| Ok(())
                )
                .is_err()
        );
        assert!(
            journal.load()?.is_none(),
            "invalid material must be rejected before journaling"
        );

        *result_data.borrow_mut() = Some(
            nazo_operator_protocol::ControlResultData::TenantResourceEnumerate {
                revision: 1,
                resources: Vec::new(),
                resource_manifest_sha256: "ab".repeat(32),
            },
        );
        let callback_called = Rc::new(RefCell::new(false));
        let callback_called_on_invalid_result = callback_called.clone();
        let error = session
            .execute_control_operation(ControlOperationPayload::KeysValidate, None, move |_| {
                *callback_called_on_invalid_result.borrow_mut() = true;
                Ok(())
            })
            .expect_err("typed result mismatch must fail before persistence");
        assert!(
            format!("{error:#}").contains("does not match the prepared operation contract"),
            "{error:#}"
        );
        assert!(
            !*callback_called.borrow(),
            "invalid target results must never reach the persistence callback"
        );
        let kept = journal.load()?.context("journal must remain")?;
        assert_eq!(
            kept.state,
            crate::controller_identity::journal::JournalState::Accepted
        );

        *result_data.borrow_mut() = None;
        let error = session
            .execute_control_operation(ControlOperationPayload::KeysValidate, None, |_| {
                anyhow::bail!("evidence persistence failed")
            })
            .expect_err("callback failure must surface");
        assert!(format!("{error:#}").contains("evidence persistence failed"));
        assert_eq!(
            journal.load()?.context("journal must remain")?.state,
            crate::controller_identity::journal::JournalState::Accepted
        );

        let mut persisted = None;
        let outcome = session.execute_control_operation(
            ControlOperationPayload::KeysValidate,
            None,
            |completion| {
                persisted = Some(completion.clone());
                Ok(())
            },
        )?;
        let ConformanceControlOutcome::Succeeded(completion) = outcome else {
            panic!("expected typed success")
        };
        assert_eq!(persisted.as_ref(), Some(&completion));
        assert_eq!(requests.borrow().len(), 3);
        assert_eq!(requests.borrow()[0], requests.borrow()[1]);
        assert_eq!(requests.borrow()[1], requests.borrow()[2]);
        assert_eq!(completion.identity.operation_id, kept.operation_id);
        assert_eq!(completion.identity.request_hash, kept.request_hash);
        assert_eq!(completion.identity.kid, kept.kid);
        assert!(
            journal.load()?.is_none(),
            "successful persistence clears journal"
        );

        *target_outcome.borrow_mut() = ControlOutcome::Failed;
        let mut persisted_failure = None;
        let outcome = session.execute_control_operation(
            ControlOperationPayload::KeysValidate,
            None,
            |completion| {
                persisted_failure = Some(completion.clone());
                Ok(())
            },
        )?;
        let ConformanceControlOutcome::Failed(completion) = outcome else {
            panic!("expected durable business failure")
        };
        assert_eq!(persisted_failure.as_ref(), Some(&completion));
        assert_eq!(completion.result.outcome, ControlOutcome::Failed);
        assert!(completion.result.result.is_none());
        assert!(completion.result.error.is_some());
        assert!(
            journal.load()?.is_none(),
            "persisted durable failure clears the dispatch journal"
        );
        Ok(())
    }
}
