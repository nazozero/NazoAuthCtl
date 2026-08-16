use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    ActorKind, EmbeddedIdentity, TenantResourceCapability, TenantResourceIdentity,
    TenantResourceKind, TenantResourceMapping, TenantResourceOperation, TenantResourceOutcome,
    TenantResourceReceipt, TenantResourceTask, TenantResourceTaskPayload,
    canonical_tenant_resource_manifest_sha256, compact_sha256, instance_key_id,
    sign_tenant_resource_capability, sign_tenant_resource_receipt, sign_tenant_resource_task,
    verify_tenant_resource_capability_signature, verify_tenant_resource_task_signature,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use nazoauthctl_core::tenant_resources::{
    MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES, PreparedTenantResourceRequest,
    TenantResourceCapabilitySession, TenantResourceClient, TenantResourceClientConfig,
    TenantResourceClientError, TenantResourceHttpResponse, TenantResourceHttpTransport,
    tenant_resource_manifest_sha256,
};

const NOW: i64 = 1_700_000_000;
const DEPLOYMENT: &str = "deployment-test";
const TENANT: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Clone, Copy)]
enum FakeMode {
    Success,
    WrongCapabilityKey,
    WrongCapabilityBinding,
    ExpiredCapability,
    TamperedReceipt,
    ReplayExpired,
    ExpiredNoReplay,
    NextSecondCapability,
    NextSecondReceipt,
    Status(u16),
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    path: String,
    body: Vec<u8>,
    task: Option<TenantResourceTask>,
}

struct FakeTransport {
    runtime: SigningKey,
    controller: SigningKey,
    runtime_key_id: String,
    controller_key_id: String,
    embedded: EmbeddedIdentity,
    mode: FakeMode,
    now: i64,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl TenantResourceHttpTransport for FakeTransport {
    fn post_json(
        &self,
        endpoint: &Url,
        body: &[u8],
    ) -> Result<TenantResourceHttpResponse, TenantResourceClientError> {
        let path = endpoint.path().to_owned();
        if let FakeMode::Status(status) = self.mode {
            return Ok(TenantResourceHttpResponse {
                status,
                body: b"{\"error\":\"stable\"}".to_vec(),
            });
        }
        let value: Value = serde_json::from_slice(body)
            .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;
        if path.ends_with("/capability") {
            let nonce = value["nonce"].as_str().ok_or_else(|| {
                TenantResourceClientError::Transport("missing nonce in test request".into())
            })?;
            let (signing_key, key_id) = if matches!(self.mode, FakeMode::WrongCapabilityKey) {
                let wrong = SigningKey::from_bytes(&[99; 32]);
                let wrong_id = instance_key_id(&wrong.verifying_key());
                (wrong, wrong_id)
            } else {
                (self.runtime.clone(), self.runtime_key_id.clone())
            };
            let baseline_identity = TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: "user-existing".to_owned(),
                digest: sha256(b"existing"),
            };
            let baseline_manifest =
                canonical_tenant_resource_manifest_sha256(&[baseline_identity]).unwrap();
            let capability_now = if matches!(self.mode, FakeMode::NextSecondCapability) {
                let target = unix_now() + 1;
                while unix_now() < target {
                    thread::sleep(Duration::from_millis(5));
                }
                target
            } else {
                self.now
            };
            let (issued_at, expires_at) = if matches!(self.mode, FakeMode::ExpiredCapability) {
                (self.now - 120, self.now - 60)
            } else if matches!(self.mode, FakeMode::NextSecondCapability) {
                (capability_now, capability_now + 60)
            } else {
                (self.now - 1, self.now + 59)
            };
            let (deployment_id, tenant_id) =
                if matches!(self.mode, FakeMode::WrongCapabilityBinding) {
                    (
                        "deployment-other".to_owned(),
                        "00000000-0000-4000-8000-000000000002".to_owned(),
                    )
                } else {
                    (DEPLOYMENT.to_owned(), TENANT.to_owned())
                };
            let capability = TenantResourceCapability {
                ver: nazo_operator_protocol::PROTOCOL_VERSION,
                capability_version: nazo_operator_protocol::TENANT_RESOURCE_CAPABILITY_VERSION,
                jti: "capability-1".to_owned(),
                nonce: nonce.to_owned(),
                deployment_id: deployment_id.clone(),
                tenant_id,
                runtime_instance_id: "runtime-1".to_owned(),
                issuer: format!("runtime:{deployment_id}"),
                instance_key_id: key_id.clone(),
                embedded: self.embedded.clone(),
                revision: 7,
                resource_manifest_sha256: baseline_manifest,
                resource_kinds: vec![
                    TenantResourceKind::User,
                    TenantResourceKind::OauthClient,
                    TenantResourceKind::MtlsTrustAnchor,
                    TenantResourceKind::Openid4vcDataset,
                ],
                actions: vec![
                    TenantResourceOperation::Apply,
                    TenantResourceOperation::Enumerate,
                    TenantResourceOperation::Revoke,
                ],
                issued_at,
                expires_at,
            };
            let compact = sign_tenant_resource_capability(&capability, &key_id, &signing_key)
                .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;
            self.requests.lock().unwrap().push(RecordedRequest {
                path,
                body: body.to_vec(),
                task: None,
            });
            return Ok(json_response(json!({"capability_jws": compact})));
        }

        if matches!(self.mode, FakeMode::ExpiredNoReplay) {
            return Ok(TenantResourceHttpResponse {
                status: 403,
                body: b"{\"error\":\"expired\"}".to_vec(),
            });
        }

        let capability_jws = value["capability_jws"].as_str().ok_or_else(|| {
            TenantResourceClientError::Transport("missing capability JWS in test request".into())
        })?;
        let task_jws = value["task_jws"].as_str().ok_or_else(|| {
            TenantResourceClientError::Transport("missing task JWS in test request".into())
        })?;
        let _capability = verify_tenant_resource_capability_signature(
            capability_jws,
            &self.runtime_key_id,
            &self.runtime.verifying_key(),
        )
        .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;
        let task = verify_tenant_resource_task_signature(
            task_jws,
            &self.controller_key_id,
            &self.controller.verifying_key(),
        )
        .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;
        let resources = match &task.payload {
            TenantResourceTaskPayload::Apply { resources }
            | TenantResourceTaskPayload::Revoke { resources } => resources.clone(),
            TenantResourceTaskPayload::Enumerate { .. } => Vec::new(),
        };
        let revision = match task.operation {
            TenantResourceOperation::Enumerate => task.expected_revision,
            TenantResourceOperation::Apply | TenantResourceOperation::Revoke => {
                task.expected_revision + 1
            }
        };
        let resource_mappings = if matches!(task.operation, TenantResourceOperation::Apply) {
            resources
                .iter()
                .filter_map(|resource| match resource.kind {
                    TenantResourceKind::User => Some(TenantResourceMapping {
                        kind: resource.kind,
                        resource_id: resource.resource_id.clone(),
                        public_id: TENANT.to_owned(),
                    }),
                    TenantResourceKind::OauthClient => Some(TenantResourceMapping {
                        kind: resource.kind,
                        resource_id: resource.resource_id.clone(),
                        public_id: format!("client-{}", resource.resource_id),
                    }),
                    TenantResourceKind::MtlsTrustAnchor
                    | TenantResourceKind::Openid4vcDataset
                    | TenantResourceKind::Openid4vcTrustPolicy => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        let receipt_time = if matches!(self.mode, FakeMode::NextSecondReceipt) {
            let target = unix_now() + 1;
            while unix_now() < target {
                thread::sleep(Duration::from_millis(5));
            }
            target
        } else {
            self.now
        };
        let mut receipt = TenantResourceReceipt {
            ver: nazo_operator_protocol::PROTOCOL_VERSION,
            iss: format!("runtime:{DEPLOYMENT}"),
            aud: format!("controller:{DEPLOYMENT}"),
            jti: task.jti.clone(),
            request_sha256: sha256(body),
            deployment_id: task.deployment_id.clone(),
            tenant_id: task.tenant_id.clone(),
            capability_jti: task.capability_jti.clone(),
            capability_sha256: task.capability_sha256.clone(),
            actor: task.actor.clone(),
            change_set_id: task.change_set_id.clone(),
            change_set_sha256: task.change_set_sha256.clone(),
            operation: task.operation,
            expected_revision: task.expected_revision,
            revision,
            outcome: TenantResourceOutcome::Succeeded,
            resources,
            resource_mappings,
            baseline_manifest_sha256: task.baseline_manifest_sha256.clone(),
            resource_manifest_sha256: task.resource_manifest_sha256.clone(),
            started_at: receipt_time,
            completed_at: receipt_time,
            exp: receipt_time + 60,
            audit_sequence: 1,
            audit_previous_sha256: "0".repeat(64),
        };
        if matches!(self.mode, FakeMode::TamperedReceipt) {
            receipt.request_sha256 = "f".repeat(64);
        }
        let compact = sign_tenant_resource_receipt(&receipt, &self.runtime_key_id, &self.runtime)
            .map_err(|error| TenantResourceClientError::Transport(error.to_string()))?;
        self.requests.lock().unwrap().push(RecordedRequest {
            path,
            body: body.to_vec(),
            task: Some(task),
        });
        Ok(json_response(json!({"receipt_jws": compact})))
    }
}

fn json_response(value: Value) -> TenantResourceHttpResponse {
    TenantResourceHttpResponse {
        status: 200,
        body: serde_json::to_vec(&value).unwrap(),
    }
}

fn client(
    mode: FakeMode,
) -> (
    TenantResourceClient<FakeTransport>,
    Arc<Mutex<Vec<RecordedRequest>>>,
) {
    client_at(mode, NOW)
}

fn client_at(
    mode: FakeMode,
    now: i64,
) -> (
    TenantResourceClient<FakeTransport>,
    Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let runtime = SigningKey::from_bytes(&[7; 32]);
    let controller = SigningKey::from_bytes(&[8; 32]);
    let runtime_key_id = instance_key_id(&runtime.verifying_key());
    let controller_key_id = instance_key_id(&controller.verifying_key());
    let embedded = EmbeddedIdentity {
        release: "release-1".to_owned(),
        revision: "revision-1".to_owned(),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "build-1".to_owned(),
    };
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeTransport {
        runtime: runtime.clone(),
        controller: controller.clone(),
        runtime_key_id: runtime_key_id.clone(),
        controller_key_id: controller_key_id.clone(),
        embedded: embedded.clone(),
        mode,
        now,
        requests: requests.clone(),
    };
    let config = TenantResourceClientConfig {
        base_url: Url::parse("https://nazoauth.test/").unwrap(),
        deployment_id: DEPLOYMENT.to_owned(),
        tenant_id: TENANT.to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        runtime_key_id,
        runtime_public_key: runtime.verifying_key(),
        controller_key_id,
        controller_public_key: controller.verifying_key(),
        controller_signing_key: Some(controller),
        actor_id: "nazoauthctl".to_owned(),
        embedded,
    };
    (
        TenantResourceClient::new(config, transport).unwrap(),
        requests,
    )
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn discover(client: &TenantResourceClient<FakeTransport>) -> TenantResourceCapabilitySession {
    client
        .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([1; 32]), NOW)
        .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identity(id: &str, payload: &[u8]) -> TenantResourceIdentity {
    TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: id.to_owned(),
        digest: sha256(payload),
    }
}

fn user_manifest(resource_id: &str, payload: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": 1,
        "resources": [{
            "kind": "user",
            "resource_id": resource_id,
            "payload_base64url": URL_SAFE_NO_PAD.encode(payload),
        }],
    }))
    .unwrap()
}

#[test]
fn discovery_and_apply_bind_nonce_actor_revision_and_exact_digests() {
    let (client, requests) = client(FakeMode::Success);
    let session = discover(&client);
    let baseline = identity("user-existing", b"existing");
    let payload = br#"{"username":"alice","email":"alice@example.com","password":"pass-1","email_verified":false}"#;
    let delta = identity("user-1", payload);
    let raw_manifest = user_manifest("user-1", payload);
    let final_active = vec![baseline, delta.clone()];
    let expected_manifest = canonical_tenant_resource_manifest_sha256(&final_active).unwrap();
    assert_eq!(
        tenant_resource_manifest_sha256(&final_active).unwrap(),
        expected_manifest
    );
    assert_eq!(
        session.compact_sha256(),
        compact_sha256(&session.compact_jws)
    );
    let result = client
        .apply_at(
            &session,
            "change-1",
            &raw_manifest,
            vec![delta.clone()],
            final_active,
            NOW,
        )
        .unwrap();
    assert_eq!(result.receipt().operation, TenantResourceOperation::Apply);
    assert_eq!(result.receipt().expected_revision, 7);
    assert_eq!(result.receipt().revision, 8);
    assert_eq!(result.receipt().resources, vec![delta]);
    let requests = requests.lock().unwrap();
    assert_eq!(requests[0].path, "/management/tenant-resources/capability");
    let execute = requests
        .iter()
        .find(|request| request.task.is_some())
        .unwrap();
    assert_eq!(execute.path, "/management/tenant-resources/execute");
    let task = execute.task.as_ref().unwrap();
    assert_eq!(task.actor.kind, ActorKind::Automation);
    assert_eq!(
        task.baseline_manifest_sha256,
        session.capability.resource_manifest_sha256
    );
    assert_eq!(task.resource_manifest_sha256, expected_manifest);
    assert_eq!(task.change_set_sha256, sha256(&raw_manifest));
    let body: Value = serde_json::from_slice(&execute.body).unwrap();
    let encoded_manifest = URL_SAFE_NO_PAD.encode(&raw_manifest);
    assert_eq!(
        body["manifest_base64url"].as_str(),
        Some(encoded_manifest.as_str())
    );
}

#[test]
fn live_execution_validates_receipt_with_the_post_response_clock() {
    let now = unix_now();
    let (client, _) = client_at(FakeMode::NextSecondReceipt, now);
    let session = client
        .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([6; 32]), now)
        .unwrap();
    let baseline = identity("user-existing", b"existing");
    let payload = br#"{"username":"clock","email":"clock@example.com","password":"pass-clock","email_verified":false}"#;
    let delta = identity("user-clock", payload);
    let raw_manifest = user_manifest("user-clock", payload);
    let prepared = client
        .prepare_apply(
            &session,
            "change-clock",
            &raw_manifest,
            vec![delta.clone()],
            vec![baseline, delta],
            now,
        )
        .unwrap();

    let receipt = client.execute_prepared_live(&prepared).unwrap();
    assert!(receipt.receipt().completed_at > now);
}

#[test]
fn live_discovery_validates_capability_with_the_post_response_clock() {
    let now = unix_now();
    let (client, _) = client_at(FakeMode::NextSecondCapability, now);

    let session = client
        .discover_capability_with_nonce(&URL_SAFE_NO_PAD.encode([9; 32]))
        .unwrap();

    assert!(session.capability.issued_at > now);
}

#[test]
fn rejects_wrong_runtime_key_and_expired_capability() {
    let (wrong_key_client, _) = client(FakeMode::WrongCapabilityKey);
    let wrong_key = wrong_key_client
        .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([2; 32]), NOW)
        .unwrap_err();
    assert_eq!(wrong_key.status_code(), Some(401));

    let (expired_client, _) = client(FakeMode::ExpiredCapability);
    let expired = expired_client
        .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([3; 32]), NOW)
        .unwrap_err();
    assert_eq!(expired.status_code(), Some(403));

    let (binding_client, _) = client(FakeMode::WrongCapabilityBinding);
    let binding = binding_client
        .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([5; 32]), NOW)
        .unwrap_err();
    assert_eq!(binding.status_code(), Some(403));
}

#[test]
fn validates_receipt_request_digest_and_supports_enumerate_and_revoke() {
    let (client, requests) = client(FakeMode::Success);
    let session = discover(&client);
    let result = client
        .enumerate_at(
            &session,
            "change-enumerate",
            &"1".repeat(64),
            Vec::new(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        result.receipt().operation,
        TenantResourceOperation::Enumerate
    );
    let resource = identity("user-2", b"payload-2");
    client
        .revoke_at(
            &session,
            "change-revoke",
            &"2".repeat(64),
            vec![resource],
            &canonical_tenant_resource_manifest_sha256(&[]).unwrap(),
            NOW,
        )
        .unwrap();
    let requests = requests.lock().unwrap();
    let execute_requests = requests
        .iter()
        .filter(|request| request.task.is_some())
        .collect::<Vec<_>>();
    assert_eq!(execute_requests.len(), 2);
    let enumerate_body: Value = serde_json::from_slice(&execute_requests[0].body).unwrap();
    assert!(enumerate_body.get("manifest_base64url").is_none());
    assert_eq!(
        execute_requests[0].task.as_ref().unwrap().operation,
        TenantResourceOperation::Enumerate
    );
    assert_eq!(
        execute_requests[1].task.as_ref().unwrap().operation,
        TenantResourceOperation::Revoke
    );
}

#[test]
fn prepared_request_freezes_jti_body_and_accepts_exact_expired_replay() {
    let (client, requests) = client(FakeMode::ReplayExpired);
    let session = discover(&client);
    let payload = br#"{"username":"replay","email":"replay@example.com","password":"pass-2","email_verified":false}"#;
    let delta = identity("user-replay", payload);
    let raw_manifest = user_manifest("user-replay", payload);
    let prepared = client
        .prepare_apply(
            &session,
            "change-replay",
            &raw_manifest,
            vec![delta.clone()],
            vec![delta],
            NOW,
        )
        .unwrap();
    let body = prepared.body().to_vec();
    let jti = prepared.task().jti.clone();
    let binding = prepared.recovery_binding();
    assert_eq!(binding.capability_sha256(), prepared.capability_sha256());
    assert_eq!(binding.task_sha256(), prepared.task_sha256());
    assert_eq!(binding.request_sha256(), prepared.request_sha256());
    let restored = client
        .restore_from_recovery(&binding, prepared.raw_manifest())
        .unwrap();
    let restored_from_persisted = client
        .restore_from_persisted(
            prepared.capability_jws(),
            prepared.task_jws(),
            binding.capability_sha256(),
            binding.task_sha256(),
            binding.request_sha256(),
            binding.operation(),
            binding.jti(),
            binding.change_set_id(),
            binding.change_set_sha256(),
            prepared.raw_manifest(),
        )
        .unwrap();
    assert_eq!(restored_from_persisted.body(), body);
    assert_eq!(restored_from_persisted.task().jti, jti);
    let receipt = client.execute_prepared(&restored, NOW + 120).unwrap();
    assert_eq!(receipt.receipt().jti, jti);
    assert_eq!(receipt.evidence().receipt().jti, jti);
    assert_eq!(
        receipt.compact_sha256(),
        receipt.evidence().compact_sha256()
    );
    assert_eq!(
        receipt.receipt_sha256(),
        receipt.evidence().receipt_sha256()
    );
    let requests = requests.lock().unwrap();
    let execute = requests
        .iter()
        .find(|request| request.task.is_some())
        .unwrap();
    assert_eq!(execute.body, body);
    assert_eq!(execute.task.as_ref().unwrap().jti, jti);
    assert!(!format!("{prepared:?}").contains(&prepared.task_jws()[..8]));
}

#[test]
fn expired_prepared_request_without_exact_replay_is_rejected() {
    let (client, _) = client(FakeMode::ExpiredNoReplay);
    let session = discover(&client);
    let payload = br#"{"username":"noreplay","email":"noreplay@example.com","password":"pass-3","email_verified":false}"#;
    let delta = identity("user-no-replay", payload);
    let raw_manifest = user_manifest("user-no-replay", payload);
    let prepared = client
        .prepare_apply(
            &session,
            "change-no-replay",
            &raw_manifest,
            vec![delta.clone()],
            vec![delta],
            NOW,
        )
        .unwrap();
    let error = client.execute_prepared(&prepared, NOW + 60).unwrap_err();
    assert_eq!(error.status_code(), Some(403));
}

#[test]
fn rejects_wrong_controller_task_key_before_transport_and_bad_recovery_body() {
    let (client, requests) = client(FakeMode::Success);
    let session = discover(&client);
    let payload = br#"{"username":"wrong-key","email":"wrong-key@example.com","password":"pass-5","email_verified":false}"#;
    let delta = identity("user-wrong-key", payload);
    let raw_manifest = user_manifest("user-wrong-key", payload);
    let prepared = client
        .prepare_apply(
            &session,
            "change-wrong-key",
            &raw_manifest,
            vec![delta.clone()],
            vec![delta],
            NOW,
        )
        .unwrap();
    let wrong_controller = SigningKey::from_bytes(&[77; 32]);
    let wrong_key_id = instance_key_id(&wrong_controller.verifying_key());
    let wrong_task_jws =
        sign_tenant_resource_task(prepared.task(), &wrong_key_id, &wrong_controller).unwrap();
    let mut envelope: Value = serde_json::from_slice(prepared.body()).unwrap();
    envelope["task_jws"] = Value::String(wrong_task_jws.clone());
    let forged_body = serde_json::to_vec(&envelope).unwrap();
    let forged = PreparedTenantResourceRequest::restore(
        prepared.capability_jws().to_owned(),
        wrong_task_jws,
        prepared.task().clone(),
        prepared.raw_manifest().map(|manifest| manifest.to_vec()),
        forged_body,
    )
    .unwrap();
    let error = client.execute_prepared(&forged, NOW).unwrap_err();
    assert_eq!(error.status_code(), Some(401));
    assert_eq!(requests.lock().unwrap().len(), 1);

    let malformed = PreparedTenantResourceRequest::restore(
        prepared.capability_jws().to_owned(),
        prepared.task_jws().to_owned(),
        prepared.task().clone(),
        prepared.raw_manifest().map(|manifest| manifest.to_vec()),
        b"not-json".to_vec(),
    )
    .unwrap_err();
    assert_eq!(malformed.status_code(), Some(400));
    let too_large = PreparedTenantResourceRequest::restore(
        prepared.capability_jws().to_owned(),
        prepared.task_jws().to_owned(),
        prepared.task().clone(),
        prepared.raw_manifest().map(|manifest| manifest.to_vec()),
        vec![0; MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES + 1],
    )
    .unwrap_err();
    assert_eq!(too_large.status_code(), Some(413));
}

#[test]
fn maps_stable_http_errors_and_rejects_tampered_receipt() {
    let (invalid_nonce_client, requests) = client(FakeMode::Success);
    let invalid_nonce = invalid_nonce_client
        .discover_capability_with_nonce_at("not-a-nonce", NOW)
        .unwrap_err();
    assert_eq!(invalid_nonce.status_code(), Some(400));
    assert!(requests.lock().unwrap().is_empty());

    for (status, expected) in [
        (400, 400),
        (401, 401),
        (403, 403),
        (409, 409),
        (413, 413),
        (500, 503),
        (503, 503),
    ] {
        let (client, _) = client(FakeMode::Status(status));
        let error = client
            .discover_capability_with_nonce_at(&URL_SAFE_NO_PAD.encode([4; 32]), NOW)
            .unwrap_err();
        assert_eq!(error.status_code(), Some(expected));
    }

    let (tampered_client, _) = client(FakeMode::TamperedReceipt);
    let session = discover(&tampered_client);
    let payload = br#"{"username":"tampered","email":"tampered@example.com","password":"pass-4","email_verified":false}"#;
    let raw_manifest = user_manifest("user-3", payload);
    let error = tampered_client
        .apply_at(
            &session,
            "change-tampered",
            &raw_manifest,
            vec![identity("user-3", payload)],
            vec![identity("user-3", payload)],
            NOW,
        )
        .unwrap_err();
    assert_eq!(error.status_code(), Some(403));
}
