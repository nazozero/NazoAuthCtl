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

/// Valid 64-char lowercase-hex subject digest shared by executor, stub, and
/// assertions.
fn digest() -> String {
    format!("c0ffee{:0>58}", "")
}

// ------------------------------------------------------------------ fixtures

/// Failure injection point for the scripted executor.
#[derive(Clone, Copy, PartialEq)]
enum FailAt {
    ArtifactVerify,
    Health,
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
    ) -> Result<install_exec::InstallFacts, crate::target::Failure> {
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
            install_exec::rollback(job, &performed);
            return Err(crate::target::Failure::new(
                HEALTH_PROBE_FAILED,
                "readiness never answered",
            ));
        }
        performed.started_runtime = true;
        Ok(install_exec::InstallFacts {
            artifact_reference: format!("sha256:{}", digest()),
        })
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
            return Ok(HostResult::completed(
                &operation.operation_id,
                HostCompletionBody::Hello {
                    hello: crate::target::wire::local_hello(vec!["podman".to_owned()]),
                },
            ));
        }
        self.inner.execute_host_operation(operation)
    }
    fn execute_control_operation(
        &self,
        request: &crate::target::ControlOperationRequest,
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
        let state_root = temp.path().join("state");
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
                }) as Box<dyn ExecutionTarget>)
            }),
        };
        Ok(Self {
            _temp: temp,
            context,
            executor,
            state_root,
        })
    }

    fn local_target(&self) -> anyhow::Result<Box<dyn ExecutionTarget>> {
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
            expected_artifact_sha256: None,
            runtime: None,
            install_root: Some(self._temp.path().join("install")),
        }
    }
}

/// OpenSSH-shaped stub answering hello plus the install completion over the
/// fixed `remote exec` protocol (pattern proven by the C05 test suite).
struct SshStub {
    _dir: PrivateTempDir,
    program: std::path::PathBuf,
}

impl SshStub {
    fn new(install_fails: bool) -> anyhow::Result<Self> {
        let dir = PrivateTempDir::new("nazauthctl-clean-install-ssh")?;
        let root = dir.path();

        let identity = crate::target::wire::local_hello(vec!["podman".to_owned()]);
        let hello = serde_json::json!({
            "schema": crate::target::wire::HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {"result": "hello", "hello": identity}},
        });
        let inspection = serde_json::json!({
            "deployment_id": "__DEPLOYMENT_ID__",
            "issuer": ISSUER,
            "observed_at": chrono::Utc::now(),
            "revision": 1,
            "runtime": {"kind": "podman", "object": "nazoauth-main"},
            "artifact": {"current": format!("sha256:{}", digest()), "previous": null},
            "config_reference": "/cfg/config.json",
            "config_schema": CONFIG_SCHEMA_SEED,
            "resources": [],
            "healthy": true,
            "health_summary": "local readiness probe passed after clean install",
            "active_host_operation": "__OPERATION_ID__",
        });
        let install = serde_json::json!({
            "schema": crate::target::wire::HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {
                "result": "install-applied", "inspection": inspection}},
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
        Ok(Self { _dir: dir, program })
    }
}

#[cfg(unix)]
fn unix_stub() -> String {
    r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.txt"
input=$(cat)
id=$(printf '%s' "$input" | sed -n 's/.*"operation_id":"\([0-9a-fA-F-]*\)".*/\1p')
dep=$(printf '%s' "$input" | sed -n 's/.*"deployment_id":"\([0-9a-zA-Z._:+-]*\)".*/\1p')
nonce=$(printf '%s' "$input" | sed -n 's/.*"nonce":"\([0-9A-Za-z._:+-]*\)".*/\1p')
case "$input" in
  *'"kind":"hello'"'"''*)
    out="$(dirname "$0")/response-hello.json"
    sed "s/__OPERATION_ID__/${id:-none}/g" "$out"
    exit 0
    ;;
esac
case "$input" in
  *'"kind":"ping"'*)
    printf '{"schema":1,"operation_id":"%s","outcome":{"status":"completed","body":{"result":"ping","nonce":"%s"}}}' "${id:-none}" "${nonce:-none}"
    exit 0
    ;;
esac
case "$input" in
  *'"kind":"state-inspect"'*)
    printf '{"schema":1,"operation_id":"%s","outcome":{"status":"failed","code":"DEPLOYMENT_UNKNOWN","detail":"stub fresh target"}}' "${id:-none}"
    exit 0
    ;;
esac
if printf '%s' "$input" | grep -q '"kind":"state-mutate"' && [ "$(cat "$(dirname "$0")/mode.txt")" = "fail" ]; then
  printf '{"schema":1,"operation_id":"%s","outcome":{"status":"failed","code":"ARTIFACT_UNVERIFIED","detail":"stub refuses"}}' "${id:-none}"
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
        "  $pong = '{\"schema\":1,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"completed\",\"body\":{\"result\":\"ping\",\"nonce\":\"' + $n + '\"}}}'",
        "  [Console]::Out.Write($pong)",
        "} elseif ($stdinText -match '\"kind\":\"state-inspect\"') {",
        "  $missing = '{\"schema\":1,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"failed\",\"code\":\"DEPLOYMENT_UNKNOWN\",\"detail\":\"stub fresh target\"}}'",
        "  [Console]::Out.Write($missing)",
        "} elseif ((Get-Content (Join-Path $here 'mode.txt')) -eq 'fail') {",
        "  $failed = '{\"schema\":1,\"operation_id\":\"' + $callerId + '\",\"outcome\":{\"status\":\"failed\",\"code\":\"ARTIFACT_UNVERIFIED\",\"detail\":\"stub refuses\"}}'",
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
        )?)?;
        let program = stub.program.clone();
        let context = CleanInstallContext {
            registry,
            factory: Box::new(move |record| {
                Ok(Box::new(
                    crate::target::SshTarget::from_record(record)?.with_program(program.clone()),
                ) as Box<dyn ExecutionTarget>)
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
            expected_artifact_sha256: None,
            runtime: None,
            install_root: Some(self.stub._dir.path().join("install")),
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
        text.contains("controller bind --instance production"),
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

    // Fresh-install bootstrap capability is OPEN after install (G02 hook).
    let scope = fixture
        .state_root
        .join("deployments")
        .join(&record.deployment_id);
    assert!(scope.join(bootstrap_authority::CONTEXT_FILE_NAME).is_file());
    assert!(scope.join(bootstrap_authority::TOKEN_FILE_NAME).is_file());

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
    let deployments = fixture._temp.path().join("state").join("deployments");
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
    let hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
    let request = fixture.request(Some("production"));
    let prepared = prepare_install_operation(&request, &hello)?;
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
        !scope.join(bootstrap_authority::TOKEN_FILE_NAME).exists(),
        "bootstrap token must be deleted on rollback"
    );
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

// ------------------------------------------------------- journal idempotency

#[test]
fn interrupted_install_replays_identically_without_reexecution_on_local_target()
-> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    let hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
    let prepared = prepare_install_operation(&fixture.request(None), &hello)?;
    let mut operation = prepared.operation.clone();
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

// ------------------------------------------------------------ selector rules

#[test]
fn multi_host_registries_demand_an_explicit_host_selector() -> anyhow::Result<()> {
    let fixture = LocalFixture::new(None)?;
    fixture.context.registry.add_host(HostRecord::new_ssh(
        "server-a",
        "prod-a",
        HostPrivilege::Direct,
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
        fn oidc_discovery(&self, _issuer: &url::Url) -> Result<(), String> {
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
