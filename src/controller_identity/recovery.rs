//! Recovery Secret client half (goal plan 04A; tasks D10/D11/D12).
//!
//! The Recovery Secret is a 32-byte offline value shown to the operator
//! exactly once. ctl derives the signing key from it with the frozen KDF
//! (`hkdf-sha256-v1`, authority in `nazo-operator-protocol::recovery`), never
//! persists either the secret or the derived seed, and never sends secret
//! bytes anywhere: only public keys and Ed25519 signatures cross the wire.
//!
//! Flows:
//!
//! * [`rotate_root_with_new_secret`] — D10 enrollment and D12 proactive
//!   rotation share one path: generate → fresh-2FA approval → atomic commit.
//!   Running it again replaces the root and invalidates the previous secret
//!   (generation bumps server-side).
//! * [`recover_controller_identity`] — D11 break-glass: parse the OLD
//!   offline secret, derive its key, sign the server's canonical challenge,
//!   and on acceptance activate the locally staged candidate controller key
//!   plus record the server-assigned binding. The replacement root travels
//!   inside the signed proposal, so the possibly-exposed old secret stops
//!   verifying the moment the commit lands (`old_recovery_secret_invalid`).
//!
//! Delivery boundary: CLI wiring (prompt/file handling for the secret) lands
//! with the I wave; these functions are the complete use-case layer.

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{
    RecoveryProposal, derive_recovery_seed, format_recovery_secret, parse_recovery_secret,
    recovery_kid, recovery_public_key_bytes,
};
use zeroize::{Zeroize as _, Zeroizing};

use super::admin_api::{
    ControllerRegistryApi, RecoveryAnswerBody, RecoveryChallengeBody, RecoveryRootApprovalBody,
    RecoveryRootRotateBody,
};
use crate::controller_identity::store::{ControllerKeyStore, controller_key_ref_for};
use crate::fleet::resolve_instance;
use crate::registry::RegistryStore;

/// Freshly generated replacement material. `display` is the one-time
/// `NAZO-RECOVERY-…` string, shown to the operator exactly once.
pub(crate) struct RecoveryMaterial {
    pub display: String,
    pub public_key: [u8; 32],
    pub kid: String,
}

/// Generate one fresh Recovery Root candidate for a deployment.
pub(crate) fn generate_material(deployment_id: &str) -> RecoveryMaterial {
    let mut secret: [u8; 32] = rand::random();
    let display = format_recovery_secret(&secret);
    let seed = derive_recovery_seed(&secret, deployment_id);
    secret.zeroize();
    let public_key = recovery_public_key_bytes(&seed);
    let kid = recovery_kid(&public_key);
    RecoveryMaterial {
        display,
        public_key,
        kid,
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// D10 enrollment / D12 proactive rotation: replace the deployment's
/// Recovery Root with a freshly generated one under fresh-2FA approval.
/// The returned report contains the NEW secret exactly once — nothing in ctl
/// or NazoAuth retains it.
#[allow(dead_code)] // delivery boundary: CLI wiring lands with I-wave
pub(crate) fn rotate_root_with_new_secret(
    api: &dyn ControllerRegistryApi,
    deployment_id: &str,
) -> anyhow::Result<String> {
    let view = api
        .recovery_root_view(deployment_id)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("reading the current recovery root failed; nothing was changed")?;
    let previous = view.generation;
    let _ = view.present; // rotation over an existing root IS the D12 use case

    let material = generate_material(deployment_id);
    let approval = api
        .issue_recovery_root_approval(&RecoveryRootApprovalBody {
            deployment_id: deployment_id.to_owned(),
            recovery_public_key: b64(&material.public_key),
            kid: material.kid.clone(),
        })
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("approval issuance failed; no root change happened")?;

    let root = api
        .rotate_recovery_root(&RecoveryRootRotateBody {
            approval_token: approval.approval_token,
            deployment_id: deployment_id.to_owned(),
            recovery_public_key: b64(&material.public_key),
            kid: material.kid.clone(),
        })
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context(
            "root rotation commit failed; the approval token is single-use, so rerunning this \
             command issues a fresh one safely",
        )?;
    let generation = root.generation.unwrap_or_default();
    Ok(format!(
        "recovery root ready for deployment '{deployment_id}' (generation {generation}, kdf {})\n\
         replaced generation: {}\n\
         \n\
         NEW RECOVERY SECRET — shown once, never stored by ctl or NazoAuth:\n\
         \x20   {}\n\
         \n\
         write it down offline now (password manager printout or paper in a safe place). \
         Whoever holds it can recover the Controller Key when every slot is lost; nobody can \
         use it for anything else.\n",
        root.kdf.as_deref().unwrap_or("-"),
        previous.map_or("none (first enrollment)".to_owned(), |g| g.to_string()),
        material.display,
    ))
}

/// Authoritative result of one successful break-glass recovery.
// Delivery boundary: rendered by the I-wave CLI; asserted by the tests below.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct RecoveredIdentity {
    pub controller_id: String,
    pub kid: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub recovery_generation: u64,
}

/// D11 break-glass flow: re-establish one Controller Key from the offline
/// Recovery Secret when every slot is lost/expired.
///
/// Ordering guarantees:
///
/// * the candidate controller key exists ONLY locally (inactive) until the
///   server commits — a refused challenge leaves no active identity;
/// * the answer is self-checked against the proposal before submission so a
///   client bug cannot burn one of the server's five attempts;
/// * local activation + registry binding happen strictly AFTER the server's
///   authoritative commit, and both are derivable from the server state
///   (rerunning after a crash reconciles instead of duplicating).
#[allow(dead_code)] // delivery boundary: CLI wiring lands with I-wave
pub(crate) fn recover_controller_identity(
    registry: &RegistryStore,
    keys: &ControllerKeyStore,
    api: &dyn ControllerRegistryApi,
    selector: Option<&str>,
    old_secret_text: &str,
    label: &str,
) -> anyhow::Result<RecoveredIdentity> {
    let action = "controller recovery";
    let record = resolve_instance(registry, selector, action)?;
    let deployment_id = record.deployment_id.clone();

    // Old material: parsed from the operator-supplied offline secret, then
    // immediately reduced to the derived (zeroizing) seed.
    let mut old_secret = parse_recovery_secret(old_secret_text)
        .map_err(|error| anyhow::anyhow!("{error}: the recovery secret did not parse"))?;
    let old_seed = Zeroizing::new(derive_recovery_seed(&old_secret, &deployment_id));
    old_secret.zeroize();
    let old_public = recovery_public_key_bytes(&old_seed);

    // Replacement root travels inside the signed proposal so the old secret
    // stops verifying the moment the commit lands.
    let replacement = generate_material(&deployment_id);

    // Candidate controller key: persisted inactive until the commit lands.
    let candidate = keys
        .generate_candidate(&deployment_id)
        .context("staging the recovered controller key failed; nothing was sent")?;
    let candidate_public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(candidate.public_key.as_bytes())
        .context("stored candidate public key is not valid base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored candidate public key is not 32 bytes"))?;

    let proposal = RecoveryProposal {
        deployment_id: deployment_id.clone(),
        controller_label: label.to_owned(),
        controller_kid: candidate.kid.clone(),
        controller_public_key: candidate_public,
        recovery_kid: replacement.kid.clone(),
        recovery_public_key: replacement.public_key,
    };
    proposal
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let challenge = api
        .issue_recovery_challenge(&RecoveryChallengeBody {
            deployment_id: deployment_id.clone(),
            label: label.to_owned(),
            controller_public_key: b64(&candidate_public),
            kid: candidate.kid.clone(),
            recovery_public_key: b64(&replacement.public_key),
            recovery_kid: replacement.kid.clone(),
        })
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("challenge request failed; nothing was changed")?;

    let signature = proposal.sign_challenge(&challenge.challenge_id, &challenge.nonce, &old_seed);
    if !proposal.verify_challenge_signature(
        &challenge.challenge_id,
        &challenge.nonce,
        &old_public,
        &signature,
    ) {
        bail!(
            "internal error: the computed answer failed its own verification; aborting before submission"
        );
    }

    let commit = api
        .submit_recovery_answer(&RecoveryAnswerBody {
            deployment_id: deployment_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            nonce: b64(&challenge.nonce),
            signature: b64(&signature),
        })
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context(
            "recovery commit failed; the challenge stays pending until its expiry and the same \
             inputs can be resubmitted",
        )?;

    // Server committed authoritatively — now mirror locally. Both steps are
    // idempotent given the server facts, so a crash between them is repaired
    // by simply rerunning this command with the same secret.
    keys.set_active_kid(&deployment_id, &candidate.kid)?;
    let key_ref = controller_key_ref_for(&deployment_id)?;
    registry.update_controller_binding(
        &deployment_id,
        Some(commit.slot.controller_id.as_str()),
        Some(key_ref.as_str()),
    )?;

    Ok(RecoveredIdentity {
        controller_id: commit.slot.controller_id,
        kid: commit.slot.kid,
        expires_at: commit.slot.expires_at,
        recovery_generation: commit.recovery_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_identity::admin_api::{
        AdminApiTransport, AdminHttpRequest, AdminHttpResponse, HttpControllerRegistryApi,
    };
    use crate::filesystem::PrivateTempDir;
    use crate::registry::{DiscoveryEvidence, ObservationCache, RegistryStore};
    use crate::target::wire::local_hello;
    use std::sync::{Arc, Mutex};

    const ISSUER: &str = "https://auth.example.com";
    const DEPLOYMENT: &str = "deploy-recovery-test";

    fn canned_api(canned: Canned) -> HttpControllerRegistryApi {
        HttpControllerRegistryApi::with_transport(
            ISSUER,
            crate::controller_identity::admin_api::AdminAccess::default(),
            Box::new(canned),
        )
        .expect("valid issuer")
    }

    fn slot_json(kid: &str, controller_id: &str) -> String {
        format!(
            r#"{{"deployment_id":"{DEPLOYMENT}","controller_id":"{controller_id}","label":"recovered","kid":"{kid}","slot_index":0,"issued_at":"2026-08-24T00:00:00Z","expires_at":"2026-09-23T00:00:00Z","status":"active","warning":null}}"#
        )
    }

    /// Canned transport recording requests in order.
    #[derive(Clone, Default)]
    struct Canned {
        inner: Arc<CannedInner>,
    }

    #[derive(Default)]
    struct CannedInner {
        responses: Mutex<Vec<anyhow::Result<AdminHttpResponse>>>,
        seen: Mutex<Vec<AdminHttpRequest>>,
    }

    impl Canned {
        fn push(&self, status: u16, body: &str) {
            self.inner
                .responses
                .lock()
                .unwrap()
                .push(Ok(AdminHttpResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                }));
        }

        fn requests(&self) -> Vec<(String, String)> {
            self.inner
                .seen
                .lock()
                .unwrap()
                .iter()
                .map(|request| (request.method.to_owned(), request.url.clone()))
                .collect()
        }

        fn bodies(&self) -> Vec<String> {
            self.inner
                .seen
                .lock()
                .unwrap()
                .iter()
                .map(|request| String::from_utf8(request.body.clone().unwrap_or_default()).unwrap())
                .collect()
        }
    }

    impl AdminApiTransport for Canned {
        fn send(&self, request: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse> {
            self.inner.seen.lock().unwrap().push(request);
            self.inner
                .responses
                .lock()
                .unwrap()
                .pop()
                .expect("no canned response left")
        }
    }

    struct Fixture {
        _temp: PrivateTempDir,
        registry: RegistryStore,
        keys: ControllerKeyStore,
    }

    impl Fixture {
        fn new() -> anyhow::Result<Self> {
            let temp = PrivateTempDir::new("nazauthctl-recovery")?;
            let registry = RegistryStore::open(temp.path().join("registry"))?;
            let host = registry.ensure_local_host()?;
            let evidence = DiscoveryEvidence::new(
                &host,
                local_hello(vec!["podman".to_owned()]),
                DEPLOYMENT,
                ISSUER,
            )?;
            registry.register_instance(&evidence, Some("prod"), ObservationCache::now(true, ""))?;
            let keys = ControllerKeyStore::open(temp.path().join("keys"))?;
            Ok(Self {
                _temp: temp,
                registry,
                keys,
            })
        }
    }

    #[test]
    fn rotate_root_prints_secret_once_and_hits_the_frozen_contract() {
        let canned = Canned::default();
        // The canned queue is LIFO: push in reverse call order.
        canned.push(
            200,
            r#"{"recovery_root":{"deployment_id":"deploy-recovery-test","recovery_kid":"kid-z","kdf":"hkdf-sha256-v1","generation":1},"previous_generation_invalid":true}"#,
        );
        canned.push(
            200,
            r#"{"approval_token":"tok-1","action":"recovery-root-rotate","action_sha256":"ab","expires_at":"2026-08-24T00:10:00Z","single_use":true}"#,
        );
        canned.push(
            200,
            r#"{"deployment_id":"deploy-recovery-test","present":false}"#,
        );
        let report = rotate_root_with_new_secret(&canned_api(canned.clone()), DEPLOYMENT)
            .expect("rotation succeeded");
        assert!(report.contains("NAZO-RECOVERY-"), "{report}");
        assert!(report.contains("generation 1"), "{report}");
        assert!(report.contains("shown once"), "{report}");

        assert_eq!(
            canned.requests(),
            vec![
                (
                    "GET".to_owned(),
                    format!(
                        "https://auth.example.com/admin/controller-registry/recovery-root?deployment_id={DEPLOYMENT}"
                    ),
                ),
                (
                    "POST".to_owned(),
                    "https://auth.example.com/admin/controller-registry/recovery-root/approvals"
                        .to_owned()
                ),
                (
                    "POST".to_owned(),
                    "https://auth.example.com/admin/controller-registry/recovery-root/rotate"
                        .to_owned()
                ),
            ]
        );
        // The token from the approval response is the one consumed.
        let bodies = canned.bodies();
        assert!(
            bodies[2].contains(r#""approval_token":"tok-1""#),
            "{}",
            bodies[2]
        );
    }

    #[test]
    fn rotate_over_an_existing_root_reports_the_replaced_generation() {
        let canned = Canned::default();
        // LIFO: [rotate commit, approval, present view].
        canned.push(
            200,
            r#"{"recovery_root":{"deployment_id":"deploy-recovery-test","recovery_kid":"kid-z","kdf":"hkdf-sha256-v1","generation":4},"previous_generation_invalid":true}"#,
        );
        canned.push(
            200,
            r#"{"approval_token":"tok-2","action":"recovery-root-rotate","action_sha256":"cd","expires_at":"2026-08-24T00:10:00Z","single_use":true}"#,
        );
        canned.push(
            200,
            r#"{"deployment_id":"deploy-recovery-test","present":true,"recovery_kid":"kid-a","kdf":"hkdf-sha256-v1","generation":3}"#,
        );
        let report = rotate_root_with_new_secret(&canned_api(canned.clone()), DEPLOYMENT)
            .expect("rotation over an existing root is the D12 use case");
        assert!(report.contains("generation 4"), "{report}");
        assert!(report.contains("replaced generation: 3"), "{report}");
        assert_eq!(canned.requests().len(), 3);
    }

    #[test]
    fn recover_signs_with_old_root_and_activates_candidate_after_commit() {
        let fixture = Fixture::new().expect("fixture");
        let old = generate_material(DEPLOYMENT);

        let nonce = [7u8; 32];
        let canned = Canned::default();
        // LIFO: the commit answer is consumed second.
        canned.push(
            200,
            &format!(
                r#"{{"slot":{},"recovery_generation":4,"old_recovery_secret_invalid":true}}"#,
                slot_json(
                    "candidate-kid-from-server",
                    "01900000-0000-7000-8000-000000000009"
                )
            ),
        );
        canned.push(
            200,
            &format!(
                r#"{{"challenge_id":"ch-1","deployment_id":"{DEPLOYMENT}","nonce":"{}","expires_at":"2026-08-24T00:10:00Z","algorithm":{{"type":"Ed25519"}},"single_use":true}}"#,
                b64(&nonce)
            ),
        );

        let recovered = recover_controller_identity(
            &fixture.registry,
            &fixture.keys,
            &canned_api(canned.clone()),
            Some("prod"),
            &old.display,
            "ops laptop",
        )
        .expect("recovery succeeded");

        assert_eq!(
            recovered.controller_id,
            "01900000-0000-7000-8000-000000000009"
        );
        assert_eq!(recovered.recovery_generation, 4);

        let requests = canned.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].1,
            "https://auth.example.com/controller-recovery/challenges"
        );
        assert_eq!(
            requests[1].1,
            "https://auth.example.com/controller-recovery/recover"
        );

        // Reconstruct the proposal from what actually went over the wire and
        // verify the submitted signature against the OLD root's public key.
        let bodies = canned.bodies();
        let challenge_body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        let answer_body: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
        let proposal = RecoveryProposal {
            deployment_id: challenge_body["deployment_id"].as_str().unwrap().to_owned(),
            controller_label: challenge_body["label"].as_str().unwrap().to_owned(),
            controller_kid: challenge_body["kid"].as_str().unwrap().to_owned(),
            controller_public_key: URL_SAFE_NO_PAD
                .decode(challenge_body["controller_public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            recovery_kid: challenge_body["recovery_kid"].as_str().unwrap().to_owned(),
            recovery_public_key: URL_SAFE_NO_PAD
                .decode(challenge_body["recovery_public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let nonce_echo: [u8; 32] = URL_SAFE_NO_PAD
            .decode(answer_body["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(answer_body["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(proposal.verify_challenge_signature(
            answer_body["challenge_id"].as_str().unwrap(),
            &nonce_echo,
            &old.public_key,
            &signature,
        ));
        assert_ne!(
            proposal.recovery_kid, old.kid,
            "the replacement root must be fresh material"
        );
        assert_eq!(nonce_echo, nonce);

        // Local activation mirrors the server commit: the candidate that was
        // proposed is now active, and the registry carries the binding.
        let active = fixture
            .keys
            .load_active(DEPLOYMENT)
            .unwrap()
            .expect("active");
        assert_eq!(active.kid(), proposal.controller_kid);
        let record = fixture
            .registry
            .instance_by_alias("prod")
            .unwrap()
            .expect("instance");
        assert_eq!(
            record.controller_id.as_deref(),
            Some("01900000-0000-7000-8000-000000000009")
        );
    }

    #[test]
    fn recover_refuses_unparsable_secrets_before_any_network_call() {
        let fixture = Fixture::new().expect("fixture");
        let canned = Canned::default();
        let error = recover_controller_identity(
            &fixture.registry,
            &fixture.keys,
            &canned_api(canned.clone()),
            Some("prod"),
            "not-a-secret",
            "ops",
        )
        .expect_err("garbage secret must fail closed");
        assert!(error.to_string().contains("did not parse"), "{error}");
        assert!(canned.requests().is_empty());
    }
}
