//! Shared clean-install use-case scenarios (C01 acceptance, install entry).
//!
//! The identical scenario functions run twice per case: once through a real
//! [`LocalTarget`] backed by a temp target-state root and a scripted install
//! executor (proving the full target-side semantics: journal, state commit,
//! rollback, bootstrap material), and once through an [`SshTarget`] driven by
//! an OpenSSH-shaped stub answering the frozen wire contract (proving the
//! control side behaves identically over remote exec). Container engines are
//! never spawned; every engine call lives behind the executor seam.

use super::*;
use crate::filesystem::{self, PrivateTempDir};
use crate::registry::{HostPrivilege, HostRecord};
use crate::target::{
    ARTIFACT_UNVERIFIED, HEALTH_PROBE_FAILED, TargetStateStore, bootstrap_authority,
    encode_host_result, install_exec,
};

const ISSUER: &str = "https://auth.example.com";

fn test_target_os() -> &'static str {
    if cfg!(windows) { "windows" } else { "linux" }
}

fn test_hello(supported_runtimes: Vec<String>) -> crate::target::wire::RemoteHello {
    let mut hello = crate::target::wire::local_hello(supported_runtimes);
    hello.os = test_target_os().to_owned();
    hello
}

#[test]
fn helper_runtime_announcement_is_a_closed_three_value_contract() {
    let rejected = select_runtime(&["podman".to_owned(), "systemd".to_owned()], None)
        .expect_err("legacy helper runtime token accepted");
    assert!(
        rejected
            .to_string()
            .contains("target helper announced unsupported runtime kind 'systemd'")
    );
}

/// Valid 64-char lowercase-hex subject digest shared by executor, stub, and
/// assertions.
fn digest() -> String {
    format!("c0ffee{:0>58}", "")
}

fn install_order(operation: &HostOperation) -> &InstallOrder {
    let crate::target::HostOperationBody::StateMutate {
        mutation:
            StateMutationPayload::Bootstrap {
                install: Some(order),
                ..
            },
    } = &operation.operation
    else {
        panic!("expected a clean-install bootstrap operation")
    };
    order
}

fn test_secret(value: &str) -> Option<crate::target::SecretMaterial> {
    Some(crate::target::SecretMaterial::try_new(value.as_bytes().to_vec()).expect("test secret"))
}

// ------------------------------------------------------------------ fixtures

/// Failure injection point for the scripted executor.
#[derive(Clone, Copy, PartialEq)]
enum FailAt {
    ArtifactVerify,
    Health,
    StateCommit,
}

/// Scripted executor performing REAL filesystem work with REAL rollback so
/// failure-path assertions exercise production rollback semantics.
struct ScriptedInstall {
    fail_at: Option<FailAt>,
    steps: std::sync::Mutex<Vec<&'static str>>,
}

impl install_exec::InstallExecutor for ScriptedInstall {
    fn execute_install(
        &self,
        job: &install_exec::InstallJob<'_>,
        commit: &mut dyn FnMut(
            &install_exec::InstallFacts,
        )
            -> Result<crate::target::InstanceInspection, crate::target::Failure>,
    ) -> Result<crate::target::InstanceInspection, crate::target::Failure> {
        let mut performed = install_exec::PerformedSteps::default();
        self.steps.lock().unwrap().push("verify");
        if self.fail_at == Some(FailAt::ArtifactVerify) {
            // Nothing has been touched yet — abort before any side effect.
            return Err(crate::target::Failure::new(
                ARTIFACT_UNVERIFIED,
                "scripted verification refusal",
            ));
        }

        let config_path = std::path::PathBuf::from(job.config_reference);
        filesystem::atomic_write(&config_path, job.order.config_content.as_bytes(), 0o600)
            .expect("scripted config write");
        performed.wrote_config = true;

        for secret in &job.order.secrets {
            let path = std::path::PathBuf::from(&secret.path);
            filesystem::ensure_directory_chain(path.parent().expect("secret parent"))
                .expect("secret parent");
            filesystem::atomic_write(&path, b"generated", 0o600).expect("secret write");
            performed.generated_secrets.push(secret.path.clone());
        }

        if job.order.fresh_bootstrap {
            bootstrap_authority::provision(job.scope_dir, job, &digest()).expect("provision");
            performed.provisioned_bootstrap = true;
        }

        self.steps.lock().unwrap().push("start");
        if self.fail_at == Some(FailAt::Health) {
            // Executor contract: undo own partial work before failing.
            install_exec::rollback(job, &performed).expect("fixture rollback");
            return Err(crate::target::Failure::new(
                HEALTH_PROBE_FAILED,
                "readiness never answered",
            ));
        }
        performed.started_runtime = true;
        if self.fail_at == Some(FailAt::StateCommit) {
            std::fs::create_dir(job.scope_dir.join("state.json"))
                .expect("block the scripted state commit");
        }
        let facts = install_exec::InstallFacts {
            build_identity: None,
            artifact_reference: format!("sha256:{}", digest()),
            rollback_policy: crate::model::test_release_rollback_policy(),
        };
        commit(&facts)
            .map_err(|failure| install_exec::rollback_or_outcome_unknown(job, &performed, failure))
    }
}

/// Local fixture: temp registry + temp target-state root + scripted executor.
/// A thin wrapper pins deterministic handshake runtimes so scenarios do not
/// depend on which container binaries exist on this machine.
struct LocalFixture {
    _temp: PrivateTempDir,
    context: CleanInstallContext,
    executor: std::sync::Arc<ScriptedInstall>,
    state_root: std::path::PathBuf,
}

struct HelloOverride {
    inner: crate::target::LocalTarget,
}

impl ExecutionTarget for HelloOverride {
    fn inspect_host(&self) -> anyhow::Result<crate::target::HostOverview> {
        self.inner.inspect_host()
    }
    fn inspect_instance(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<crate::target::InstanceInspection> {
        self.inner.inspect_instance(deployment_id)
    }
    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        if matches!(
            operation.operation,
            crate::target::HostOperationBody::Hello {}
        ) {
            let HostOutcome::Completed {
                body: HostCompletionBody::Hello { mut hello },
            } = self.inner.execute_host_operation(operation)?.outcome
            else {
                unreachable!("LocalTarget must complete Hello")
            };
            hello.os = test_target_os().to_owned();
            hello.supported_runtimes = vec!["podman".to_owned()];
            return Ok(HostResult::completed(
                &operation.operation_id,
                HostCompletionBody::Hello { hello },
            ));
        }
        self.inner.execute_host_operation(operation)
    }
    fn execute_control_operation(
        &self,
        request: crate::target::ControlOperationRequest,
    ) -> anyhow::Result<crate::target::ControlOperationReceipt> {
        self.inner.execute_control_operation(request)
    }
    fn read_health(&self, deployment_id: &str) -> anyhow::Result<crate::target::HealthSnapshot> {
        self.inner.read_health(deployment_id)
    }
}

impl LocalFixture {
    fn new(fail_at: Option<FailAt>) -> anyhow::Result<Self> {
        let temp = PrivateTempDir::new("nazauthctl-clean-install")?;
        let registry = RegistryStore::open(temp.path().join("registry"))?;
        registry.ensure_local_host()?;
        let state_root = temp.path().join("registry/local-target-state");
        let executor = std::sync::Arc::new(ScriptedInstall {
            fail_at,
            steps: std::sync::Mutex::new(Vec::new()),
        });
        let local = crate::target::LocalTarget::with_state_root(&state_root)
            .with_install_executor(executor.clone());
        let context = CleanInstallContext {
            registry,
            factory: Box::new(move |_record| {
                Ok(Box::new(HelloOverride {
                    inner: local.clone(),
                }) as Box<dyn ExecutionTarget + Send>)
            }),
        };
        Ok(Self {
            _temp: temp,
            context,
            executor,
            state_root,
        })
    }

    fn local_target(&self) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
        (self.context.factory)(
            self.context
                .registry
                .host_by_alias(crate::registry::LOCAL_HOST_ALIAS)?
                .as_ref()
                .expect("local host ensured"),
        )
    }

    fn store(&self) -> anyhow::Result<TargetStateStore> {
        TargetStateStore::open(&self.state_root)
    }

    fn request(&self, alias: Option<&str>) -> CleanInstallRequest {
        CleanInstallRequest {
            host: None,
            instance_alias: alias.map(str::to_owned),
            issuer: ISSUER.to_owned(),
            version: Some("v0.2.0".to_owned()),
            runtime: None,
            install_root: Some(self._temp.path().join("install")),
            database_runtime_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "oauth".to_owned(),
                user: "nazoauth_runtime".to_owned(),
            },
            database_lifecycle_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "oauth".to_owned(),
                user: "nazoauth_lifecycle".to_owned(),
            },
            valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "cache.internal".to_owned(),
                port: 6379,
                name: String::new(),
                user: String::new(),
            },
            database_runtime_password: test_secret("db-runtime-secret"),
            database_lifecycle_password: test_secret("db-lifecycle-secret"),
            valkey_password: test_secret("cache-secret"),
            import_data_root: None,
            import_mfa_key_file: None,
        }
    }
}

/// OpenSSH-shaped stub answering hello plus the install completion over the
/// fixed `remote exec` protocol (pattern proven by the C05 test suite).
struct SshStub {
    _dir: PrivateTempDir,
    program: std::path::PathBuf,
    target_id: uuid::Uuid,
}

impl SshStub {
    fn new(install_fails: bool) -> anyhow::Result<Self> {
        let dir = PrivateTempDir::new("nazauthctl-clean-install-ssh")?;
        let root = dir.path();

        let target_id = uuid::Uuid::now_v7();
        let mut identity = test_hello(vec!["podman".to_owned()]);
        identity.target_id = target_id.to_string();
        let hello = serde_json::json!({
            "schema": crate::target::wire::HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {"completion": "hello", "hello": identity}},
        });
        let inspection = serde_json::json!({
            "deployment_id": "__DEPLOYMENT_ID__",
            "issuer": ISSUER,
            "observed_at": chrono::Utc::now(),
            "revision": 1,
            "runtime": {"kind": "podman", "object": "nazoauth-main", "loopback_port": 8000},
            "artifact": {"current": format!("sha256:{}", digest()), "previous": null},
            "config_reference": "/cfg/config.json",
            "config_schema": CONFIG_SCHEMA_SEED,
            "resources": [],
            "healthy": true,
            "health_summary": "local readiness probe passed after clean install",
            "active_host_operation": "__OPERATION_ID__",
            "backup": {"local_rollback_ready": false},
        });
        let install = serde_json::json!({
            "schema": crate::target::wire::HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {
                "completion": "install-applied", "inspection": inspection}},
        });

        filesystem::atomic_write(
            &root.join("response-hello.json"),
            serde_json::to_vec(&hello)?.as_slice(),
            0o600,
        )?;
        filesystem::atomic_write(
            &root.join("response-install.json"),
            serde_json::to_vec(&install)?.as_slice(),
            0o600,
        )?;
        filesystem::atomic_write(
            &root.join("mode.txt"),
            if install_fails {
                b"fail".as_slice()
            } else {
                b"ok".as_slice()
            },
            0o600,
        )?;

        #[cfg(unix)]
        let program = {
            let script = root.join("ssh");
            filesystem::atomic_write(&script, unix_stub().as_bytes(), 0o755)?;
            script
        };
        #[cfg(windows)]
        let program = {
            filesystem::atomic_write(&root.join("ssh.cmd"), windows_stub_cmd().as_bytes(), 0o600)?;
            filesystem::atomic_write(&root.join("stub.ps1"), windows_stub_ps1().as_bytes(), 0o600)?;
            root.join("ssh.cmd")
        };
        Ok(Self {
            _dir: dir,
            program,
            target_id,
        })
    }
}

#[cfg(unix)]
fn unix_stub() -> String {
    r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.txt"
input=$(cat)
id=$(printf '%s' "$input" | sed -n 's/.*"operation_id":"\([0-9a-fA-F-]*\)".*/\1/p')
dep=$(printf '%s' "$input" | sed -n 's/.*"deployment_id":"\([0-9a-zA-Z._:+-]*\)".*/\1/p')
nonce=$(printf '%s' "$input" | sed -n 's/.*"nonce":"\([0-9A-Za-z._:+-]*\)".*/\1/p')
case "$input" in
  *'"kind":"hello"'*)
    out="$(dirname "$0")/response-hello.json"
    sed "s/__OPERATION_ID__/${id:-none}/g" "$out"
    exit 0
    ;;
esac
case "$input" in
  *'"kind":"ping"'*)
    printf '{"schema":5,"operation_id":"%s","outcome":{"status":"completed","body":{"completion":"ping","nonce":"%s"}}}' "${id:-none}" "${nonce:-none}"
    exit 0
    ;;
esac
case "$input" in
  *'"kind":"state-inspect"'*)
    printf '{"schema":5,"operation_id":"%s","outcome":{"status":"failed","code":"DEPLOYMENT_UNKNOWN","detail":"stub fresh target"}}' "${id:-none}"
    exit 0
    ;;
esac
if printf '%s' "$input" | grep -q '"kind":"state-mutate"' && [ "$(cat "$(dirname "$0")/mode.txt")" = "fail" ]; then
  printf '{"schema":5,"operation_id":"%s","outcome":{"status":"failed","code":"ARTIFACT_UNVERIFIED","detail":"stub refuses"}}' "${id:-none}"
  exit 0
fi
sed -e "s/__OPERATION_ID__/${id:-none}/g" -e "s/__DEPLOYMENT_ID__/${dep:-none}/g" \
    "$(dirname "$0")/response-install.json"
exit 0
"#
    .to_owned()
}

#[cfg(windows)]
fn windows_stub_cmd() -> String {
    [
        "@echo off",
        "\"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile \
         -ExecutionPolicy Bypass -File \"%~dp0stub.ps1\" %*",
        "exit /b %ERRORLEVEL%",
        "",
    ]
    .join("\r\n")
}

#[cfg(windows)]
fn windows_stub_ps1() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "$here = Split-Path -Parent $MyInvocation.MyCommand.Path",
        "$stdinText = [Console]::In.ReadToEnd()",
        "$m = [regex]::Match($stdinText, '\"operation_id\":\"([0-9a-fA-F-]+)\"')",
        "$callerId = if ($m.Success) { $m.Groups[1].Value } else { 'none' }",
        "$dep = [regex]::Match($stdinText, '\"deployment_id\":\"([0-9a-zA-Z._:+-]+)\"')",
        "$depId = if ($dep.Success) { $dep.Groups[1].Value } else { 'none' }",
        "if ($stdinText -match '\"kind\":\"hello\"') {",
        "  $raw = Get-Content -LiteralPath (Join-Path $here 'response-hello.json') -Raw",
        "  [Console]::Out.Write($raw.Replace('__OPERATION_ID__', $callerId))",
        "} elseif ($stdinText -match '\"kind\":\"ping\"') {",
        "  $n = [regex]::Match($stdinText, '\"nonce\":\"([0-9A-Za-z._:+-]+)\"').Groups[1].Value",
        "  $pong = '{\"schema\":5,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"completed\",\"body\":{\"completion\":\"ping\",\"nonce\":\"' + $n + '\"}}}'",
        "  [Console]::Out.Write($pong)",
        "} elseif ($stdinText -match '\"kind\":\"state-inspect\"') {",
        "  $missing = '{\"schema\":5,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"failed\",\"code\":\"DEPLOYMENT_UNKNOWN\",\"detail\":\"stub fresh target\"}}'",
        "  [Console]::Out.Write($missing)",
        "} elseif ((Get-Content (Join-Path $here 'mode.txt')) -eq 'fail') {",
        "  $failed = '{\"schema\":5,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"failed\",\"code\":\"ARTIFACT_UNVERIFIED\",\"detail\":\"stub refuses\"}}'",
        "  [Console]::Out.Write($failed)",
        "} else {",
        "  $raw = Get-Content -LiteralPath (Join-Path $here 'response-install.json') -Raw",
        "  [Console]::Out.Write($raw.Replace('__OPERATION_ID__', $callerId).Replace('__DEPLOYMENT_ID__', $depId))",
        "}",
        "exit 0",
        "",
    ]
    .join("\r\n")
}

struct SshFixture {
    stub: SshStub,
    context: CleanInstallContext,
    host_alias: &'static str,
}

impl SshFixture {
    fn new(install_fails: bool) -> anyhow::Result<Self> {
        let stub = SshStub::new(install_fails)?;
        let registry = RegistryStore::open(stub._dir.path().join("registry"))?;
        registry.ensure_local_host()?;
        registry.add_host(HostRecord::new_ssh(
            "server-a",
            "prod-a",
            HostPrivilege::Direct,
            stub.target_id,
        )?)?;
        let program = stub.program.clone();
        let context = CleanInstallContext {
            registry,
            factory: Box::new(move |record| {
                Ok(Box::new(
                    crate::target::SshTarget::from_record(record)?.with_program(program.clone()),
                ) as Box<dyn ExecutionTarget + Send>)
            }),
        };
        Ok(Self {
            stub,
            context,
            host_alias: "server-a",
        })
    }

    fn request(&self, alias: Option<&str>) -> CleanInstallRequest {
        CleanInstallRequest {
            host: Some(self.host_alias.to_owned()),
            instance_alias: alias.map(str::to_owned),
            issuer: ISSUER.to_owned(),
            version: Some("v0.2.0".to_owned()),
            runtime: None,
            install_root: Some(self.stub._dir.path().join("install")),
            database_runtime_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "oauth".to_owned(),
                user: "nazoauth_runtime".to_owned(),
            },
            database_lifecycle_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "oauth".to_owned(),
                user: "nazoauth_lifecycle".to_owned(),
            },
            valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
                host: "cache.internal".to_owned(),
                port: 6379,
                name: String::new(),
                user: String::new(),
            },
            database_runtime_password: test_secret("db-runtime-secret"),
            database_lifecycle_password: test_secret("db-lifecycle-secret"),
            valkey_password: test_secret("cache-secret"),
            import_data_root: None,
            import_mfa_key_file: None,
        }
    }
}

// -------------------------------------------------- shared scenario: happy

#[test]
fn local_happy_path_commits_state_and_writes_instance_record() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let text = run_clean_install(&fixture.context, fixture.request(Some("production")))?;

    // Report: committed facts plus exact next steps (G01 items 10/11, G02/G08 wording).
    assert!(
        text.contains("local=healthy control_binding=unbound public=unknown"),
        "{text}"
    );
    assert!(
        text.contains("bootstrap-admin --instance production"),
        "{text}"
    );
    assert!(
        text.contains("nazoauthctl bind --instance production"),
        "{text}"
    );
    assert!(text.contains("verify --instance production"), "{text}");
    assert!(text.contains("MFA"), "{text}");

    // InstanceRecord written through the B04 register evidence path.
    let record = fixture
        .context
        .registry
        .instance_by_alias("production")?
        .expect("registered");
    assert!(record.deployment_id.starts_with("deploy-"));
    assert_eq!(record.issuer, ISSUER);
    let observation = record.last_observation.expect("first observation");
    assert!(observation.reachable);
    assert!(observation.summary.starts_with("rev=1"), "{observation:?}");

    // Target DeploymentState committed healthy under the same identity.
    let store = fixture.store()?;
    let state = store.load_existing(&record.deployment_id)?;
    assert!(state.local_health.healthy);
    assert_eq!(state.config.revision, 1);
    assert_eq!(
        state.artifact.current.as_deref(),
        Some(format!("sha256:{}", digest()).as_str())
    );
    assert!(state.active_host_operation.is_some());

    // Journal carries pending → terminal completed for the install op.
    let journal_path = fixture
        .state_root
        .join("deployments")
        .join(&record.deployment_id)
        .join("operations.jsonl");
    let raw = std::fs::read_to_string(journal_path)?;
    assert!(raw.contains("\"pending\""), "{raw}");
    assert!(raw.contains("\"completed\""), "{raw}");

    // Fresh-install bootstrap capability is OPEN after install (G02 hook):
    // the install-binding context exists, and NO ctl-side token was minted
    // (the bootstrap token is NazoAuth's own, inside its data root).
    let scope = fixture
        .state_root
        .join("deployments")
        .join(&record.deployment_id);
    assert!(scope.join(bootstrap_authority::CONTEXT_FILE_NAME).is_file());

    // Ordering pin: verification strictly precedes runtime start.
    assert_eq!(
        fixture.executor.steps.lock().unwrap().clone(),
        vec!["verify", "start"]
    );
    Ok(())
}

#[test]
fn ssh_happy_path_registers_through_the_wire_contract() -> anyhow::Result<()> {
    let fixture = SshFixture::new(false)?;
    let text = run_clean_install(&fixture.context, fixture.request(Some("production")))?;

    assert!(
        text.contains("installed NazoAuth instance 'production'"),
        "{text}"
    );
    assert!(text.contains("local=healthy"), "{text}");
    assert!(
        text.contains("bootstrap-admin --instance production"),
        "{text}"
    );
    let record = fixture
        .context
        .registry
        .instance_by_alias("production")?
        .expect("registered through the B04 evidence path");
    let host = fixture
        .context
        .registry
        .host_by_alias(fixture.host_alias)?
        .expect("ssh host");
    assert_eq!(record.host_id, host.host_id);
    assert_eq!(record.issuer, ISSUER);
    assert!(record.last_observation.unwrap().reachable);
    Ok(())
}

// ------------------------------------------- shared scenario: artifact abort

#[test]
fn artifact_failure_aborts_before_runtime_start_and_registers_nothing_local() -> anyhow::Result<()>
{
    let fixture = LocalFixture::new(Some(FailAt::ArtifactVerify))?;
    let error = run_clean_install(&fixture.context, fixture.request(Some("production")))
        .expect_err("artifact refusal");
    assert!(error.to_string().contains(ARTIFACT_UNVERIFIED), "{error:#}");

    assert!(
        fixture
            .context
            .registry
            .instance_by_alias("production")?
            .is_none(),
        "failed installs never register"
    );
    let deployments = fixture.state_root.join("deployments");
    for entry in std::fs::read_dir(&deployments)? {
        let entry = entry?;
        assert!(
            !entry.path().join("state.json").exists(),
            "no DeploymentState may exist: {}",
            entry.path().display()
        );
    }
    assert_eq!(
        fixture.executor.steps.lock().unwrap().clone(),
        vec!["verify"],
        "abort happens before any later step"
    );
    Ok(())
}

#[test]
fn artifact_failure_over_ssh_reports_stable_code_without_registering() -> anyhow::Result<()> {
    let fixture = SshFixture::new(true)?;
    let error = run_clean_install(&fixture.context, fixture.request(Some("production")))
        .expect_err("failed install");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(ARTIFACT_UNVERIFIED), "{rendered}");
    assert!(rendered.contains("rolled back"), "{rendered}");
    assert!(
        fixture
            .context
            .registry
            .instance_by_alias("production")?
            .is_none(),
        "nothing registered over the remote failure either"
    );
    Ok(())
}

// ------------------------------------------------ shared scenario: rollback

#[test]
fn health_failure_rolls_back_config_secrets_and_bootstrap_material_locally() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(Some(FailAt::Health))?;
    let hello = test_hello(vec!["podman".to_owned()]);
    let mut request = fixture.request(Some("production"));
    let prepared = prepare_install_operation(&mut request, &hello)?;
    let install_root = request.install_root.clone().unwrap();
    let deployment_id = prepared.deployment_id.clone();

    let result = fixture
        .local_target()?
        .execute_host_operation(&prepared.operation)?;
    match result.outcome {
        HostOutcome::Failed { code, .. } => assert_eq!(code, HEALTH_PROBE_FAILED),
        other => panic!("expected the failed outcome: {other:?}"),
    }

    // Registry untouched.
    assert!(
        fixture
            .context
            .registry
            .instance_by_alias("production")?
            .is_none()
    );

    // Rollback restored the pre-install filesystem exactly.
    let config_file = install_root
        .join("config")
        .join(&deployment_id)
        .join("config.json");
    assert!(!config_file.exists(), "rolled-back config must be gone");
    let secrets_dir = install_root.join("data").join("secrets");
    if secrets_dir.exists() {
        assert!(
            secrets_dir.read_dir()?.next().is_none(),
            "generated secrets must be removed"
        );
    }
    let scope = fixture.state_root.join("deployments").join(&deployment_id);
    assert!(
        !scope.join(bootstrap_authority::CONTEXT_FILE_NAME).exists(),
        "bootstrap context must be deleted on rollback"
    );
    assert!(
        !scope.join("state.json").exists(),
        "no DeploymentState may exist after a rolled-back install"
    );

    // The journal records the terminal failure for the resume decision.
    let raw = std::fs::read_to_string(scope.join("operations.jsonl"))?;
    assert!(raw.contains("\"failed\""), "{raw}");

    // Both steps ran before the rollback undid them.
    assert_eq!(
        fixture.executor.steps.lock().unwrap().clone(),
        vec!["verify", "start"]
    );
    Ok(())
}

#[test]
fn state_commit_failure_rolls_back_the_completed_install() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(Some(FailAt::StateCommit))?;
    let hello = test_hello(vec!["podman".to_owned()]);
    let mut request = fixture.request(Some("production"));
    let prepared = prepare_install_operation(&mut request, &hello)?;
    let install_root = request.install_root.clone().unwrap();
    let deployment_id = prepared.deployment_id.clone();

    let result = fixture
        .local_target()?
        .execute_host_operation(&prepared.operation)?;
    assert!(matches!(result.outcome, HostOutcome::Failed { .. }));

    let config = install_root
        .join("config")
        .join(&deployment_id)
        .join("config.json");
    assert!(!config.exists(), "state failure must roll the config back");
    let scope = fixture.state_root.join("deployments").join(deployment_id);
    assert!(
        !scope.join(bootstrap_authority::CONTEXT_FILE_NAME).exists(),
        "state failure must close the bootstrap capability"
    );
    assert!(
        !scope.join("state.json").is_file(),
        "a failed commit must not publish DeploymentState"
    );
    Ok(())
}

// ------------------------------------------------------- journal idempotency

#[test]
fn interrupted_install_replays_identically_without_reexecution_on_local_target()
-> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let hello = test_hello(vec!["podman".to_owned()]);
    let prepared = prepare_install_operation(&mut fixture.request(None), &hello)?;
    let mut operation: HostOperation = serde_json::from_slice(
        &serde_json::to_vec(&prepared.operation).expect("serialize public test operation"),
    )
    .expect("deserialize public test operation");
    operation.operation_id = uuid::Uuid::now_v7().to_string();

    let target = fixture.local_target()?;
    let first = target.execute_host_operation(&operation)?;
    let replayed = target.execute_host_operation(&operation)?;

    // Same operation id + same canonical hash ⇒ stored result replays
    // byte-for-byte without re-running the order.
    assert_eq!(first.outcome, replayed.outcome);
    assert_eq!(encode_host_result(&first)?, encode_host_result(&replayed)?);
    assert_eq!(
        fixture.executor.steps.lock().unwrap().clone(),
        vec!["verify", "start"],
        "replay must not re-execute the order"
    );

    let store = fixture.store()?;
    let state = store.load_existing(&prepared.deployment_id)?;
    assert!(state.local_health.healthy);
    Ok(())
}

#[test]
fn every_prepared_deployment_has_one_distinct_non_nil_valkey_epoch() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let hello = test_hello(vec!["podman".to_owned()]);
    let first = prepare_install_operation(&mut fixture.request(None), &hello)?;
    let second = prepare_install_operation(&mut fixture.request(None), &hello)?;

    let epoch = |operation: &HostOperation| -> anyhow::Result<Uuid> {
        let line = install_order(operation)
            .config_content
            .lines()
            .find(|line| line.starts_with("VALKEY_STATE_EPOCH: "))
            .context("seed config omitted VALKEY_STATE_EPOCH")?;
        let value = line
            .strip_prefix("VALKEY_STATE_EPOCH: \"")
            .and_then(|value| value.strip_suffix('"'))
            .context("VALKEY_STATE_EPOCH was not a quoted UUID")?;
        Ok(Uuid::parse_str(value)?)
    };
    let first_epoch = epoch(&first.operation)?;
    let second_epoch = epoch(&second.operation)?;
    assert!(!first_epoch.is_nil());
    assert!(!second_epoch.is_nil());
    assert_ne!(first_epoch, second_epoch);
    Ok(())
}

#[test]
fn prepared_install_records_its_deployment_specific_loopback_port() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let hello = test_hello(vec!["podman".to_owned()]);
    let prepared = prepare_install_operation(&mut fixture.request(None), &hello)?;
    let order = install_order(&prepared.operation);
    assert!(order.config_content.contains("BIND: \"0.0.0.0:8000\""));

    let StateMutationPayload::Bootstrap {
        runtime, resources, ..
    } = (match &prepared.operation.operation {
        crate::target::HostOperationBody::StateMutate { mutation } => mutation,
        _ => panic!("prepared install is not a state mutation"),
    })
    else {
        panic!("prepared install is not a bootstrap mutation");
    };
    assert!(
        (LOOPBACK_PORT_FIRST..LOOPBACK_PORT_FIRST + LOOPBACK_PORT_COUNT)
            .contains(&runtime.loopback_port)
    );
    assert!(
        !resources
            .iter()
            .any(|resource| resource.resource_id == "app-loopback")
    );
    assert_eq!(
        runtime.loopback_port,
        deployment_loopback_port(&prepared.deployment_id)
    );
    Ok(())
}

#[test]
fn deployment_loopback_port_is_stable_and_identity_specific() {
    let first = deployment_loopback_port("deploy-00000000-0000-7000-8000-000000000001");
    let repeat = deployment_loopback_port("deploy-00000000-0000-7000-8000-000000000001");
    let second = deployment_loopback_port("deploy-00000000-0000-7000-8000-000000000002");
    assert_eq!(first, repeat);
    assert_ne!(first, second);
    assert!((LOOPBACK_PORT_FIRST..LOOPBACK_PORT_FIRST + LOOPBACK_PORT_COUNT).contains(&first));
    assert!((LOOPBACK_PORT_FIRST..LOOPBACK_PORT_FIRST + LOOPBACK_PORT_COUNT).contains(&second));
}

#[test]
fn linux_target_paths_are_posix_even_when_constructed_on_windows() -> anyhow::Result<()> {
    let mut request = LocalFixture::new(None)?.request(None);
    request.install_root = Some(std::path::PathBuf::from("/srv/nazoauth"));
    let mut hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
    hello.os = "linux".to_owned();
    let prepared = prepare_install_operation(&mut request, &hello)?;
    let order = install_order(&prepared.operation);
    let StateMutationPayload::Bootstrap { resources, .. } = (match &prepared.operation.operation {
        crate::target::HostOperationBody::StateMutate { mutation } => mutation,
        _ => panic!("prepared install is not a state mutation"),
    }) else {
        panic!("prepared install is not a bootstrap mutation")
    };

    assert_eq!(
        order.data_root,
        format!("/srv/nazoauth/data/{}", prepared.deployment_id)
    );
    assert!(resources.iter().any(|resource| {
        resource.resource_id == "app-config"
            && resource.locator == format!("/srv/nazoauth/config/{}", prepared.deployment_id)
    }));
    assert!(
        order
            .secrets
            .iter()
            .all(|secret| secret.path.starts_with('/'))
    );
    assert!(
        order
            .config_content
            .contains("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: \"true\"")
    );
    assert!(order.config_content.contains("database-runtime-url"));
    assert!(!order.config_content.contains("database-lifecycle-url"));
    assert_eq!(
        order
            .secrets
            .iter()
            .map(|secret| secret.purpose.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "database-runtime-url",
            "database-lifecycle-url",
            "valkey-url",
            "mfa-totp-key",
        ])
    );
    assert!(!format!("{order:?}").contains("db-runtime-secret"));
    assert!(
        order
            .secrets
            .iter()
            .all(|secret| !secret.path.contains('\\'))
    );
    let encoded = serde_json::to_string(&prepared.operation)?;
    assert!(!encoded.contains("\\\\srv\\\\nazoauth"), "{encoded}");
    Ok(())
}

#[test]
fn windows_host_seed_uses_yaml_safe_target_paths() -> anyhow::Result<()> {
    let mut request = LocalFixture::new(None)?.request(None);
    request.runtime = Some(crate::runtime_backend::RuntimeBackendKind::Host);
    request.install_root = Some(std::path::PathBuf::from(r"C:\NazoAuth"));
    let mut hello = crate::target::wire::local_hello(vec!["host".to_owned()]);
    hello.os = "windows".to_owned();
    let prepared = prepare_install_operation(&mut request, &hello)?;
    let order = install_order(&prepared.operation);

    assert!(
        order.config_content.contains(&format!(
            "DATA_DIR: \"C:/NazoAuth/data/{}\"",
            prepared.deployment_id
        )),
        "{}",
        order.config_content
    );
    assert!(order.config_content.contains(&format!(
        "DATABASE_URL_FILE: \"C:/NazoAuth/secrets/{}/database-runtime-url\"",
        prepared.deployment_id
    )));
    assert!(
        order
            .secrets
            .iter()
            .all(|secret| secret.path.starts_with(r"C:\NazoAuth\secrets\")),
        "planned target writes retain Windows path semantics"
    );
    Ok(())
}

#[test]
fn unsupported_target_os_fails_before_an_install_order_is_built() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let mut hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
    hello.os = "macos".to_owned();
    let error = prepare_install_operation(&mut fixture.request(None), &hello)
        .expect_err("unsupported target os");
    assert!(
        error.to_string().contains("supports only target os"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn registry_alias_does_not_fork_the_prepared_target_identity() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let host_id = fixture
        .context
        .registry
        .host_by_alias(crate::registry::LOCAL_HOST_ALIAS)?
        .context("local host")?
        .host_id;
    let first = canonical_install_request_hash(&fixture.request(Some("first")), host_id)?;
    let second = canonical_install_request_hash(&fixture.request(Some("corrected")), host_id)?;
    assert_eq!(first, second);

    let mut different_target = fixture.request(Some("first"));
    different_target.valkey_endpoint.port += 1;
    assert_ne!(
        first,
        canonical_install_request_hash(&different_target, host_id)?
    );
    Ok(())
}

struct DropFirstInstallResponse {
    inner: HelloOverride,
    drop_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ExecutionTarget for DropFirstInstallResponse {
    fn inspect_host(&self) -> anyhow::Result<crate::target::HostOverview> {
        self.inner.inspect_host()
    }

    fn inspect_instance(
        &self,
        deployment_id: &str,
    ) -> anyhow::Result<crate::target::InstanceInspection> {
        self.inner.inspect_instance(deployment_id)
    }

    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        let result = self.inner.execute_host_operation(operation)?;
        if matches!(
            operation.operation,
            crate::target::HostOperationBody::StateMutate { .. }
        ) && self
            .drop_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("scripted SSH response loss after target commit");
        }
        Ok(result)
    }

    fn execute_control_operation(
        &self,
        request: crate::target::ControlOperationRequest,
    ) -> anyhow::Result<crate::target::ControlOperationReceipt> {
        self.inner.execute_control_operation(request)
    }

    fn read_health(&self, deployment_id: &str) -> anyhow::Result<crate::target::HealthSnapshot> {
        self.inner.read_health(deployment_id)
    }
}

#[test]
fn lost_install_response_resumes_exact_identity_without_a_second_instance() -> anyhow::Result<()> {
    let temp = PrivateTempDir::new("nazauthctl-clean-install-resume")?;
    let registry = RegistryStore::open(temp.path().join("registry"))?;
    registry.ensure_local_host()?;
    let state_root = temp.path().join("registry/local-target-state");
    let executor = std::sync::Arc::new(ScriptedInstall {
        fail_at: None,
        steps: std::sync::Mutex::new(Vec::new()),
    });
    let local = crate::target::LocalTarget::with_state_root(&state_root)
        .with_install_executor(executor.clone());
    let drop_once = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let context = CleanInstallContext {
        registry,
        factory: Box::new(move |_record| {
            Ok(Box::new(DropFirstInstallResponse {
                inner: HelloOverride {
                    inner: local.clone(),
                },
                drop_once: drop_once.clone(),
            }) as Box<dyn ExecutionTarget + Send>)
        }),
    };
    let request = || CleanInstallRequest {
        host: None,
        instance_alias: Some("production".to_owned()),
        issuer: ISSUER.to_owned(),
        version: Some("v0.2.0".to_owned()),
        runtime: None,
        install_root: Some(temp.path().join("install")),
        database_runtime_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: "db.internal".to_owned(),
            port: 5432,
            name: "oauth".to_owned(),
            user: "nazoauth_runtime".to_owned(),
        },
        database_lifecycle_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: "db.internal".to_owned(),
            port: 5432,
            name: "oauth".to_owned(),
            user: "nazoauth_lifecycle".to_owned(),
        },
        valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: "cache.internal".to_owned(),
            port: 6379,
            name: String::new(),
            user: String::new(),
        },
        database_runtime_password: test_secret("db-runtime-secret"),
        database_lifecycle_password: test_secret("db-lifecycle-secret"),
        valkey_password: test_secret("cache-secret"),
        import_data_root: None,
        import_mfa_key_file: None,
    };

    let first = run_clean_install(&context, request()).expect_err("first response is lost");
    assert!(first.to_string().contains("response loss"), "{first:#}");
    let journal_dir = context.registry.root().join("prepared-installs");
    let journal_path = std::fs::read_dir(&journal_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .context("lost response must retain one prepared install journal")?;
    let journal = std::fs::read_to_string(&journal_path)?;
    assert!(!journal.contains("db-secret"), "{journal}");
    assert!(!journal.contains("cache-secret"), "{journal}");
    assert!(!journal.contains("config_content"), "{journal}");
    let prepared: serde_json::Value = serde_json::from_str(&journal)?;
    let prepared_deployment_id = prepared["deployment_id"]
        .as_str()
        .context("prepared journal omitted deployment id")?
        .to_owned();
    let prepared_operation_id = prepared["operation_id"]
        .as_str()
        .context("prepared journal omitted operation id")?
        .to_owned();

    let report = run_clean_install(&context, request())?;
    assert!(report.contains("deployment deploy-"), "{report}");
    assert_eq!(context.registry.list_instances()?.len(), 1);
    assert_eq!(
        executor.steps.lock().unwrap().clone(),
        vec!["verify", "start"],
        "target journal must replay instead of re-running install"
    );
    assert!(
        !journal_path.exists(),
        "registry commit clears resume pointer"
    );

    let deployments = std::fs::read_dir(state_root.join("deployments"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("state.json").is_file())
        .count();
    assert_eq!(
        deployments, 1,
        "response loss must not create a second deployment"
    );
    let state = TargetStateStore::open(&state_root)?.load_existing(&prepared_deployment_id)?;
    assert_eq!(
        state
            .active_host_operation
            .as_ref()
            .map(|operation| operation.operation_id.as_str()),
        Some(prepared_operation_id.as_str()),
        "retry must reuse the exact operation id"
    );
    Ok(())
}

// ------------------------------------------------------------ selector rules

#[test]
fn multi_host_registries_demand_an_explicit_host_selector() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    fixture.context.registry.add_host(HostRecord::new_ssh(
        "server-a",
        "prod-a",
        HostPrivilege::Direct,
        uuid::Uuid::now_v7(),
    )?)?;
    let error = run_clean_install(&fixture.context, fixture.request(Some("production")))
        .expect_err("ambiguous hosts");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("--host"), "{rendered}");
    assert!(rendered.contains("server-a"), "{rendered}");
    assert!(
        fixture.context.registry.list_instances()?.is_empty(),
        "ambiguous resolution registers nothing"
    );

    let unknown = run_clean_install(
        &fixture.context,
        CleanInstallRequest {
            host: Some("ghost".to_owned()),
            ..fixture.request(Some("production"))
        },
    )
    .expect_err("unknown host");
    assert!(
        format!("{unknown:#}").contains("unknown host alias"),
        "{unknown:#}"
    );
    Ok(())
}

// -------------------------------------------------------------------- G08 pin

#[test]
fn public_verification_failure_never_touches_committed_local_state() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let text = run_clean_install(&fixture.context, fixture.request(Some("production")))?;
    assert!(text.contains("public=unknown"), "{text}");

    struct FailingProber;
    impl super::public_verify::PublicProber for FailingProber {
        fn tls_handshake(&self, _issuer: &url::Url) -> Result<(), String> {
            Err("DNS did not resolve".to_owned())
        }
        fn oidc_discovery(&self, _issuer: &url::Url) -> Result<String, String> {
            Err("connection refused".to_owned())
        }
    }

    let report = super::public_verify::verify_public(&FailingProber, ISSUER);
    match &report.verdict {
        super::public_verify::PublicVerdict::Failed { failures } => {
            assert_eq!(failures.len(), 2, "{failures:?}");
        }
        other => panic!("expected a failed public verdict: {other:?}"),
    }
    assert!(!report.loopback_trial);

    // The committed local state is completely unaffected.
    let record = fixture
        .context
        .registry
        .instance_by_alias("production")?
        .expect("InstanceRecord survives public failures");
    let store = fixture.store()?;
    let state = store.load_existing(&record.deployment_id)?;
    assert!(
        state.local_health.healthy,
        "local health is independent of public state"
    );
    Ok(())
}
