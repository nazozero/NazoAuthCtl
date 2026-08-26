//! Control-side half of the fresh-install bootstrap authority (task G02).
//!
//! NazoAuth owns the bootstrap token end to end: at startup it generates the
//! one-time token at `DATA_DIR/bootstrap/initial-admin-token` and validates
//! every claim against it plus the deployment identity. This module is the
//! control-side flow, from the control machine:
//!
//! 1. resolve the instance and refuse any deployment that already carries a
//!    controller binding (bootstrap is for the unbound window only);
//! 2. read the live DeploymentState, the install-binding context, and the
//!    SERVER-generated token through the target's inspect/read surface;
//! 3. pass the hardcoded allowlist/journal/artifact/config gate;
//! 4. POST the `/auth/bootstrap-admin` contract — credentials ride only in
//!    the HTTPS request body, never in argv/env/logs/output;
//! 5. close the capability durably on success; because bootstrap mutations
//!    fail closed over existing state they can never be regenerated. Every
//!    later attempt answers `BOOTSTRAP_CLOSED`.

use anyhow::{Context as _, bail};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::fleet::resolve_instance;
use crate::process::Process;
use crate::registry::RegistryStore;
use crate::target::{
    BOOTSTRAP_CLOSED, ExecutionTarget, FreshBootstrapContext, TargetStateStore,
    bootstrap_authority, target_state_root,
};

/// Initial administrator credentials. The password is zeroized on drop.
pub(crate) struct AdminCredentials {
    pub(crate) email: String,
    pub(crate) password: Zeroizing<String>,
}

/// Request payload mirroring NazoAuth's frozen `/auth/bootstrap-admin`
/// contract: the server-generated token, the deployment identity being
/// claimed, and the initial administrator credentials.
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminRequest<'a> {
    request_id: &'a str,
    token: &'a str,
    deployment_id: &'a str,
    email: &'a str,
    password: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminResponse {
    id: String,
    request_id: String,
    email: String,
    role: String,
    next: String,
}

/// Transport seam so tests never touch a network. Production posts through
/// bounded curl with credentials on stdin of the child process only.
pub(crate) trait InitialAdminTransport {
    fn post_initial_admin(&self, endpoint: &Url, body: &[u8]) -> anyhow::Result<(u16, Vec<u8>)>;
}

/// Production transport: one bounded HTTPS POST (HTTP allowed on loopback).
pub(crate) struct CurlInitialAdminTransport;

impl InitialAdminTransport for CurlInitialAdminTransport {
    fn post_initial_admin(&self, endpoint: &Url, body: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
        let protocol = if endpoint.scheme() == "https" {
            "=https"
        } else {
            "=http"
        };
        let output = Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proto",
                protocol,
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(endpoint.as_str())
            .stdin_stdout(body)
            .context("initial administrator request failed")?;
        let Some((body, status)) = output.rsplit_once('\n') else {
            bail!("initial administrator response omitted its HTTP status");
        };
        let status = status
            .trim()
            .parse::<u16>()
            .with_context(|| "initial administrator response carried an invalid status")?;
        Ok((status, body.as_bytes().to_vec()))
    }
}

/// Where the control side reads the capability material and live state from.
///
/// The local implementation reads the formalized target state root directly.
/// The remote implementation drives the read-only state-inspect (which
/// surfaces the capability view) and the explicit `bootstrap-close` host
/// operation over the fixed SSH transport, so the token only ever rides the
/// encrypted channel (P0-2).
pub(crate) trait BootstrapMaterialSource {
    /// Full G02 gate: allowlist, open capability, install-operation ownership,
    /// exact artifact, unchanged config revision.
    fn authorize(&self, deployment_id: &str) -> anyhow::Result<()>;
    /// The server-generated bootstrap token, while the capability is open.
    fn read_token(&self, deployment_id: &str) -> anyhow::Result<Zeroizing<String>>;
    fn close(&self, deployment_id: &str) -> anyhow::Result<()>;
}

/// Local-target material source over the formalized target state root.
pub(crate) struct LocalBootstrapMaterial {
    state_root: std::path::PathBuf,
}

impl LocalBootstrapMaterial {
    /// Delivery boundary: the I wave wires this into the CLI parser.
    #[allow(dead_code)]
    pub(crate) fn production() -> anyhow::Result<Self> {
        Ok(Self {
            state_root: target_state_root()?,
        })
    }

    #[cfg(test)]
    fn with_state_root(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_root: root.into(),
        }
    }

    fn scope_dir(&self, deployment_id: &str) -> anyhow::Result<std::path::PathBuf> {
        let store = TargetStateStore::open(&self.state_root)?;
        store
            .scope_dir(deployment_id)
            .map_err(|failure| anyhow::anyhow!("{}: {}", failure.code, failure.detail))
    }
}

impl LocalBootstrapMaterial {
    fn load_open_context(&self, deployment_id: &str) -> anyhow::Result<FreshBootstrapContext> {
        let scope = self.scope_dir(deployment_id)?;
        bootstrap_authority::load_context(&scope)?
            .with_context(|| format!("{BOOTSTRAP_CLOSED}: no fresh-install capability exists"))
    }
}

impl BootstrapMaterialSource for LocalBootstrapMaterial {
    fn authorize(&self, deployment_id: &str) -> anyhow::Result<()> {
        let store = TargetStateStore::open(&self.state_root)?;
        let state = store
            .load_existing(deployment_id)
            .map_err(|failure| anyhow::anyhow!("{}: {}", failure.code, failure.detail))?;
        let context = self.load_open_context(deployment_id)?;
        bootstrap_authority::authorize_claim(Some(&context), "create-initial-admin", &state)
            .map_err(|failure| anyhow::anyhow!("{}: {}", failure.code, failure.detail))
    }

    fn read_token(&self, deployment_id: &str) -> anyhow::Result<Zeroizing<String>> {
        // The token is the SERVER-generated one inside the deployment's data
        // root; ctl only reads it while the capability is open.
        let context = self.load_open_context(deployment_id)?;
        Ok(Zeroizing::new(bootstrap_authority::read_server_token(
            &context,
        )?))
    }

    fn close(&self, deployment_id: &str) -> anyhow::Result<()> {
        bootstrap_authority::delete_material(&self.scope_dir(deployment_id)?)
    }
}

/// P0-2 remote source: every fact arrives through the fixed SSH transport.
/// The target-side state-inspect already runs the FULL authorization gate
/// (allowlist, ownership, artifact/config binding) before it surfaces the
/// material view — an absent view is exactly `BOOTSTRAP_CLOSED`. Closing
/// drives the explicit `bootstrap-close` host operation; the security
/// boundary remains the server's own token consumption.
pub(crate) struct RemoteBootstrapMaterial {
    pub(crate) target: std::sync::Arc<std::sync::Mutex<Box<dyn ExecutionTarget + Send>>>,
}

impl RemoteBootstrapMaterial {
    fn open_material(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<crate::target::FreshBootstrapMaterialView> {
        let guard = self
            .target
            .lock()
            .map_err(|_| anyhow::anyhow!("target transport poisoned"))?;
        let inspection = guard.inspect_instance(deployment_id)?;
        inspection.bootstrap_material.ok_or_else(|| {
            anyhow::anyhow!("{BOOTSTRAP_CLOSED}: no fresh-install capability exists")
        })
    }
}

impl BootstrapMaterialSource for RemoteBootstrapMaterial {
    fn authorize(&self, deployment_id: &str) -> anyhow::Result<()> {
        self.open_material(deployment_id).map(|_| ())
    }

    fn read_token(&self, deployment_id: &str) -> anyhow::Result<Zeroizing<String>> {
        let view = self.open_material(deployment_id)?;
        Ok(Zeroizing::new(view.token))
    }

    fn close(&self, deployment_id: &str) -> anyhow::Result<()> {
        use crate::target::{HostCompletionBody, HostOperation, HostOutcome};
        let operation = HostOperation::bootstrap_close(
            format!("bootstrap-close-{:032x}", rand::random::<u128>()),
            deployment_id,
        );
        if let Err(rejection) = operation.validate() {
            return Err(anyhow::anyhow!(
                "internal error: close operation rejected: {}",
                rejection.detail
            ));
        }
        let guard = self
            .target
            .lock()
            .map_err(|_| anyhow::anyhow!("target transport poisoned"))?;
        let outcome = guard
            .execute_host_operation(&operation)
            .map_err(|error| anyhow::anyhow!("{error:#}"))?
            .outcome;
        match outcome {
            HostOutcome::Completed {
                body: HostCompletionBody::BootstrapClosed {},
            } => Ok(()),
            HostOutcome::Completed { .. } => {
                unreachable!("close answers with a bootstrap-closed completion")
            }
            HostOutcome::Failed { code, detail } => {
                // An older target helper without this kind reports
                // OPERATION_KIND_UNKNOWN. The server already consumed the
                // token on success, so the capability cannot be reused; the
                // residual file is hygiene only and the operator is told so.
                if detail.contains("unknown kind") || detail.contains("KIND_UNKNOWN") {
                    anyhow::bail!(
                        "{BOOTSTRAP_CLOSED}: the target helper predates `bootstrap-close`; the \
                         capability token was consumed by NazoAuth itself, but remove the \
                         stale context file on the target manually"
                    );
                }
                anyhow::bail!("{code}: {detail}")
            }
        }
    }
}

/// `{issuer}/auth/bootstrap-admin` with the loopback-only plain-HTTP rule the
/// legacy client enforced.
fn initial_admin_endpoint(issuer: &str) -> anyhow::Result<Url> {
    let mut endpoint =
        Url::parse(issuer).with_context(|| format!("issuer is not a valid URL: {issuer}"))?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("configured issuer is not an HTTP origin");
    }
    let loopback = endpoint.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if endpoint.scheme() == "http" && !loopback {
        bail!("initial administrator bootstrap requires HTTPS outside loopback trial mode");
    }
    endpoint.set_path("/auth/bootstrap-admin");
    Ok(endpoint)
}

/// Validate claim input without ever logging or storing it.
fn validate_credentials(credentials: &AdminCredentials) -> anyhow::Result<()> {
    let email = &credentials.email;
    if !(5..=254).contains(&email.len())
        || !email.contains('@')
        || email.contains(['\n', '\r', '\0', ' '])
    {
        bail!("administrator email is invalid");
    }
    if !(12..=1024).contains(&credentials.password.chars().count()) {
        bail!("administrator password must contain between 12 and 1024 characters");
    }
    Ok(())
}

/// The G02 claim entry point. On success the capability is closed permanently
/// and the report names the MFA-enrollment next step at NazoAuth itself.
///
/// Delivery boundary: wired into the CLI by the I wave.
pub(crate) fn claim_initial_admin(
    registry: &RegistryStore,
    material: &dyn BootstrapMaterialSource,
    transport: &dyn InitialAdminTransport,
    selector: Option<&str>,
    credentials: AdminCredentials,
) -> anyhow::Result<String> {
    validate_credentials(&credentials)?;

    // 1. Unbound-window guard: any controller binding closes bootstrap forever.
    let record = resolve_instance(registry, selector, "bootstrap-admin")?;
    if record.controller_id.is_some() || record.controller_key_ref.is_some() {
        bail!(
            "{BOOTSTRAP_CLOSED}: instance '{}' carries a controller binding; the fresh-install \
             bootstrap capability is unusable after bind",
            record.alias
        );
    }

    // 2. Full gate first, then the token — both through the source that owns
    // the transport (local files or the fixed SSH channel, P0-2).
    material.authorize(&record.deployment_id)?;
    let token = material.read_token(&record.deployment_id)?;

    // 3. Exact legacy endpoint contract.
    let endpoint = initial_admin_endpoint(&record.issuer)?;
    let request_id = format!("bootstrap-admin-{:032x}", rand::random::<u128>());
    let body = serde_json::to_vec(&BootstrapAdminRequest {
        request_id: &request_id,
        token: &token,
        deployment_id: &record.deployment_id,
        email: &credentials.email,
        password: &credentials.password,
    })?;
    let normalized_email = credentials.email.trim().to_ascii_lowercase();
    let (status, response_bytes) = transport.post_initial_admin(&endpoint, &body)?;
    if status != 201 {
        bail!("initial administrator endpoint returned HTTP {status}");
    }
    let response: BootstrapAdminResponse = serde_json::from_slice(&response_bytes)
        .context("initial administrator endpoint returned an invalid response")?;
    if response.request_id != request_id
        || response.email != normalized_email
        || response.role != "admin"
        || response.next != "/ui/auth"
        || Uuid::parse_str(&response.id).is_err()
    {
        bail!("initial administrator endpoint returned an unexpected response contract");
    }

    // 4. Close permanently: delete the install-binding context. The
    // server-owned token file is consumed by NazoAuth itself; regeneration of
    // the capability is impossible because bootstrap mutations fail closed
    // over existing state.
    material.close(&record.deployment_id)?;

    Ok(format!(
        "initial administrator created (request ID: {request_id}); the fresh-install bootstrap \
         capability is now closed and its secret material deleted\n\
         continue with MFA enrollment at {}/ui/auth using fresh 2FA, then:\n\
         nazoauthctl controller bind --instance {}\n",
        record.issuer.trim_end_matches('/'),
        record.alias
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem;
    use crate::filesystem::PrivateTempDir;
    use crate::registry::{InstanceRecord, RegistryStore};
    use crate::target::{
        BOOTSTRAP_CLOSED, FreshBootstrapContext, TargetStateStore, bootstrap_authority,
        install_exec,
    };

    const ISSUER: &str = "https://auth.example.com";
    const OP_ID: &str = "018f0000-0000-7000-8000-000000000001";
    /// Server-generated token shape (48 bytes unpadded base64url).
    const SERVER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn digest() -> String {
        format!("c0ffee{:0>58}", "")
    }

    struct Fixture {
        _temp: PrivateTempDir,
        registry: RegistryStore,
        material: LocalBootstrapMaterial,
        deployment_id: String,
        data_root: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> anyhow::Result<Self> {
            let temp = PrivateTempDir::new("nazauthctl-bootstrap-claim")?;
            let registry = RegistryStore::open(temp.path().join("registry"))?;
            let host = registry.ensure_local_host()?;
            let state_root = temp.path().join("state");
            let store = TargetStateStore::open(&state_root)?;
            let deployment_id = "deploy-test".to_owned();
            store
                .bootstrap(
                    &deployment_id,
                    crate::target::BootstrapParams {
                        current_build_identity: None,
                        issuer: ISSUER.to_owned(),
                        runtime: crate::target::RuntimeSurface::new("podman", "nazoauth-x")?,
                        artifact: crate::target::ArtifactRefs {
                            current: Some(format!("sha256:{}", digest())),
                            previous: None,
                        },
                        config_reference: "/cfg/config.json".to_owned(),
                        config_schema: "nazauth-seed-v2".to_owned(),
                        resources: Vec::new(),
                    },
                    OP_ID,
                )
                .map_err(|failure| anyhow::anyhow!(failure.detail))?;
            // Provision the capability bound to the install operation.
            let scope = state_root.join("deployments").join(&deployment_id);
            filesystem::ensure_directory_chain(&scope)?;
            let data_root = temp.path().join("data-root");
            let order = minimal_order(&data_root);
            bootstrap_authority::provision(
                &scope,
                &install_exec::InstallJob {
                    operation_id: OP_ID,
                    deployment_id: &deployment_id,
                    issuer: ISSUER,
                    runtime_kind: "podman",
                    runtime_object: "nazoauth-x",
                    config_reference: "/cfg/config.json",
                    scope_dir: &scope,
                    order: &order,
                },
                &digest(),
            )?;
            // Simulate the running NazoAuth having published its own token
            // inside the mounted data root.
            filesystem::ensure_directory_chain(
                data_root
                    .join(bootstrap_authority::SERVER_TOKEN_RELATIVE_PATH)
                    .parent()
                    .expect("token parent"),
            )?;
            filesystem::atomic_write(
                &data_root.join(bootstrap_authority::SERVER_TOKEN_RELATIVE_PATH),
                SERVER_TOKEN.as_bytes(),
                0o600,
            )?;

            registry.add_instance(InstanceRecord::new(
                &deployment_id,
                "production",
                host.host_id,
                ISSUER,
                "target-state/x",
            )?)?;

            Ok(Self {
                _temp: temp,
                registry,
                material: LocalBootstrapMaterial::with_state_root(&state_root),
                deployment_id,
                data_root,
            })
        }

        fn credentials() -> AdminCredentials {
            AdminCredentials {
                email: "admin@example.com".to_owned(),
                password: Zeroizing::new("correct horse battery staple".to_owned()),
            }
        }
    }

    fn minimal_order(data_root: &std::path::Path) -> install_exec::InstallOrder {
        install_exec::InstallOrder {
            artifact: install_exec::OfficialArtifactRef {
                repository: "nazozero/NazoAuth".to_owned(),
                version: None,
                expected_subject_sha256: None,
            },
            config_content: "BIND: \"0.0.0.0:8000\"".to_owned(),
            config_sha256: "0".repeat(64),
            data_root: data_root.to_string_lossy().into_owned(),
            secrets: vec![],
            database_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "oauth".to_owned(),
                user: "nazauth".to_owned(),
            },
            valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "cache.internal".to_owned(),
                port: 6379,
                name: String::new(),
                user: String::new(),
            },
            fresh_bootstrap: false,
            port: 8000,
        }
    }

    struct FakeTransport {
        expected_status: u16,
        seen_endpoint: std::sync::Mutex<Option<Url>>,
        seen_request: std::sync::Mutex<Option<serde_json::Value>>,
    }

    impl FakeTransport {
        fn ok() -> Self {
            Self {
                expected_status: 201,
                seen_endpoint: std::sync::Mutex::new(None),
                seen_request: std::sync::Mutex::new(None),
            }
        }
    }

    impl InitialAdminTransport for FakeTransport {
        fn post_initial_admin(
            &self,
            endpoint: &Url,
            body: &[u8],
        ) -> anyhow::Result<(u16, Vec<u8>)> {
            *self.seen_endpoint.lock().unwrap() = Some(endpoint.clone());
            let request: serde_json::Value = serde_json::from_slice(body)?;
            *self.seen_request.lock().unwrap() = Some(request.clone());
            let response = serde_json::json!({
                "id": uuid::Uuid::now_v7(),
                "request_id": request["request_id"],
                "email": request["email"],
                "role": "admin",
                "next": "/ui/auth",
            });
            Ok((self.expected_status, serde_json::to_vec(&response)?))
        }
    }

    #[test]
    fn successful_claim_posts_the_server_token_then_closes_the_capability_forever()
    -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        let transport = FakeTransport::ok();

        let report = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &transport,
            Some("production"),
            Fixture::credentials(),
        )?;

        // Exact endpoint + response contract.
        let endpoint = transport.seen_endpoint.lock().unwrap().clone().unwrap();
        assert_eq!(endpoint.path(), "/auth/bootstrap-admin");
        assert_eq!(endpoint.scheme(), "https");
        assert!(report.contains("closed"), "{report}");
        assert!(report.contains("MFA enrollment"), "{report}");
        assert!(
            report.contains("controller bind --instance production"),
            "{report}"
        );

        // The claim carried the SERVER-generated token and this exact
        // deployment identity — never a ctl-minted credential.
        let request = transport.seen_request.lock().unwrap().clone().unwrap();
        assert_eq!(request["token"], SERVER_TOKEN);
        assert_eq!(request["deployment_id"], fixture.deployment_id);

        // Closure deleted the install-binding context; the token file itself
        // stays under NazoAuth's exclusive ownership.
        let scope = fixture
            ._temp
            .path()
            .join("state")
            .join("deployments")
            .join(&fixture.deployment_id);
        assert!(!scope.join(bootstrap_authority::CONTEXT_FILE_NAME).exists());
        assert!(
            fixture
                .data_root
                .join(bootstrap_authority::SERVER_TOKEN_RELATIVE_PATH)
                .exists()
        );

        // Any retry — even with valid credentials — is refused forever.
        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &transport,
            Some("production"),
            Fixture::credentials(),
        )
        .expect_err("capability closed");
        assert!(error.to_string().contains(BOOTSTRAP_CLOSED), "{error:#}");
        Ok(())
    }

    #[test]
    fn config_drift_after_install_closes_the_claim_window() -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        // Tamper: the configuration advanced past the recorded revision.
        let store = TargetStateStore::open(fixture._temp.path().join("state"))?;
        store
            .apply_config(
                &fixture.deployment_id,
                1,
                "/cfg/v2.json".to_owned(),
                "schema-v2".to_owned(),
                "018f0000-0000-7000-8000-000000000009",
            )
            .map_err(|failure| anyhow::anyhow!(failure.detail))?;

        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &FakeTransport::ok(),
            Some("production"),
            Fixture::credentials(),
        )
        .expect_err("config drift");
        assert!(error.to_string().contains(BOOTSTRAP_CLOSED), "{error:#}");
        Ok(())
    }

    #[test]
    fn artifact_drift_after_install_closes_the_claim_window() -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        // Tamper: rewrite the committed artifact reference to another digest.
        let state_path = fixture
            ._temp
            .path()
            .join("state")
            .join("deployments")
            .join(&fixture.deployment_id)
            .join("state.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path)?)?;
        value["artifact"]["current"] =
            serde_json::Value::from(format!("sha256:{}", "f".repeat(64)));
        filesystem::atomic_write(&state_path, &serde_json::to_vec_pretty(&value)?, 0o600)?;

        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &FakeTransport::ok(),
            Some("production"),
            Fixture::credentials(),
        )
        .expect_err("artifact drift");
        assert!(error.to_string().contains(BOOTSTRAP_CLOSED), "{error:#}");
        Ok(())
    }

    #[test]
    fn a_bound_instance_can_never_bootstrap_and_unknown_ops_are_outside_the_allowlist() {
        let fixture = Fixture::new().unwrap();
        fixture
            .registry
            .update_controller_binding(&fixture.deployment_id, Some("ctrl-1"), Some("keys/x"))
            .unwrap();
        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &FakeTransport::ok(),
            Some("production"),
            Fixture::credentials(),
        )
        .expect_err("bound instance");
        assert!(error.to_string().contains(BOOTSTRAP_CLOSED), "{error:#}");

        // The allowlist itself rejects anything but create-initial-admin.
        let store = TargetStateStore::open(fixture._temp.path().join("state")).unwrap();
        let state = store.load_existing(&fixture.deployment_id).unwrap();
        let context: FreshBootstrapContext = serde_json::from_slice(
            &filesystem::read_secure_regular_file(
                &fixture
                    ._temp
                    .path()
                    .join("state/deployments")
                    .join(&fixture.deployment_id)
                    .join(bootstrap_authority::CONTEXT_FILE_NAME),
                "ctx",
                false,
                16 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        for operation in ["adopt", "rotate-keys", "arbitrary"] {
            let failure = bootstrap_authority::authorize_claim(Some(&context), operation, &state)
                .expect_err(operation);
            assert_eq!(failure.code, BOOTSTRAP_CLOSED, "{operation}");
        }
    }

    #[test]
    fn non_success_status_is_rejected_without_closing_the_capability() -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        let transport = FakeTransport {
            expected_status: 409,
            seen_endpoint: std::sync::Mutex::new(None),
            seen_request: std::sync::Mutex::new(None),
        };
        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &transport,
            Some("production"),
            Fixture::credentials(),
        )
        .expect_err("409");
        assert!(format!("{error:#}").contains("409"), "{error:#}");

        // The capability stays open so the operator can retry after fixing.
        let context = fixture.material.load_open_context(&fixture.deployment_id)?;
        assert_eq!(context.install_operation_id, OP_ID);
        Ok(())
    }

    #[test]
    fn endpoint_rules_pin_https_outside_loopback() {
        assert!(initial_admin_endpoint("https://auth.example.com").is_ok());
        assert!(initial_admin_endpoint("http://localhost:8000").is_ok());
        assert!(initial_admin_endpoint("http://127.0.0.1:8000").is_ok());
        let public_http =
            initial_admin_endpoint("http://auth.example.com").expect_err("public http");
        assert!(
            format!("{public_http:#}").contains("HTTPS outside loopback"),
            "{public_http:#}"
        );
        assert!(initial_admin_endpoint("ftp://x").is_err());
        assert!(initial_admin_endpoint("https://u:p@example.com").is_err());
    }

    #[test]
    fn weak_credentials_are_rejected_before_any_contact() {
        let fixture = Fixture::new().unwrap();
        let weak = AdminCredentials {
            email: "admin@example.com".to_owned(),
            password: Zeroizing::new("short".to_owned()),
        };
        let error = claim_initial_admin(
            &fixture.registry,
            &fixture.material,
            &FakeTransport::ok(),
            Some("production"),
            weak,
        )
        .expect_err("weak password");
        assert!(format!("{error:#}").contains("12"), "{error:#}");
    }
}
