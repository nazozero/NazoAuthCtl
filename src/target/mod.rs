//! Execution target boundary between lifecycle use cases and transports.
//!
//! Use cases must not know whether Docker/systemd operations run on the
//! control machine or on a remote host (goal plan 03 §1). [`ExecutionTarget`]
//! is that seam, kept at exactly five methods; selectors are resolved before
//! anything enters a target, and transports surface failures through one
//! result model while preserving diagnostics.
//!
//! Only two implementations exist by design: [`LocalTarget`] and the
//! OpenSSH-based [`SshTarget`] (task C05), which pipes the frozen wire types
//! from [`wire`] through system OpenSSH into the fixed `remote exec` helper
//! ([`remote_exec`], task C04). No HTTP/Kubernetes/agent targets exist.

pub mod journal;
pub(crate) mod remote_exec;
pub mod ssh;
pub mod wire;

use chrono::{DateTime, Utc};

pub use journal::{JournalStatus, TargetJournal};
pub use ssh::SshTarget;
pub use wire::{
    HELLO_PRODUCT, HOST_ERR_OPERATION_CONFLICT, HOST_ERR_OPERATION_INVALID,
    HOST_ERR_REMOTE_HELPER_MISMATCH, HOST_ERR_REVISION_MISMATCH, HOST_OPERATION_KINDS,
    HOST_PROTOCOL_SCHEMA, HostCompletionBody, HostOperation, HostOperationBody, HostOutcome,
    HostResult, LOCAL_BUILD_COMMIT, MAX_HOST_OPERATION_BYTES, MAX_HOST_RESULT_BYTES,
    MessageRejection, RejectionCode, RemoteHello, canonical_operation_hash, encode_host_operation,
    encode_host_result, local_hello, parse_host_operation, parse_host_result, verify_remote_hello,
};

/// Stable code for capabilities whose owning wave has not landed yet.
///
/// This is a delivery boundary, not a compatibility shim: the contract is
/// frozen ahead of its executors so C04/C05 can answer identically over
/// stdio. It disappears once DeploymentState (F01) and ControlOperation
/// execution (E01/E03) provide real behavior behind these methods.
pub const TARGET_CAPABILITY_UNAVAILABLE: &str = "TARGET_CAPABILITY_UNAVAILABLE";

/// Read-only facts about an execution host (goal plan 03 §6 fields that have
/// producers today). The remote handshake wave (C08) extends this type with
/// build identity and supported runtimes when their consumers exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOverview {
    pub product: String,
    /// Highest HostOperation/HostResult wire schema this target answers.
    pub protocol_schema: u32,
    pub version: String,
    pub os: String,
    pub arch: String,
}

/// Minimal instance inspection seam. Filled out by the DeploymentState wave.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceInspection {
    pub deployment_id: String,
    pub observed_at: DateTime<Utc>,
}

/// Minimal health snapshot. `read_health` becomes authoritative once the
/// target-side DeploymentState exists; until then it reports availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub deployment_id: String,
    pub healthy: bool,
    pub summary: String,
}

/// An app-level NazoAuth operation, signed by the instance's Controller Key
/// and carried opaquely by any transport (goal plan 03 §3.3, rule R4).
/// The compact JWS form keeps private-key bytes on the control machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlOperationRequest {
    pub deployment_id: String,
    pub compact_jws: String,
}

/// Receipt of an accepted/rejected app-level operation. Shape stays minimal
/// until E01 freezes the ControlOperation wire it mirrors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlOperationReceipt {
    pub operation_id: String,
    pub accepted: bool,
}

/// The complete surface a transport exposes to lifecycle use cases.
///
/// Exactly the five methods of goal plan 03 §1 — no more, no fewer. Every
/// method takes resolved identifiers (never user selectors) and every
/// failure keeps its diagnostic context for the unified error reporter.
pub trait ExecutionTarget {
    /// Read-only host facts used by `host add`/`check` style flows.
    fn inspect_host(&self) -> anyhow::Result<HostOverview>;

    /// Read-only inspection of one registered instance on this target.
    fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection>;

    /// Execute one host-level operation and return the uniform result model
    /// (goal plan 03 §2: local runs natively, remote via the frozen stdio
    /// contract; both answer with the same [`HostResult`]).
    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult>;

    /// Execute an already-signed app-level ControlOperation against one
    /// instance. Never signs; never touches Controller Key material.
    fn execute_control_operation(
        &self,
        request: &ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt>;

    /// Read the current health view of one instance.
    fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot>;
}

/// The control machine itself.
///
/// Executes through the existing process/filesystem adapters with the OS's
/// own privileges (goal plan 03 §2): no session keys, no JSON loopback — a local
/// caller hands typed values straight to native dispatch, exactly what the
/// remote executor does after parsing the same operation from stdin.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalTarget;

impl LocalTarget {
    pub fn new() -> Self {
        Self
    }

    fn unavailable(method: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "{TARGET_CAPABILITY_UNAVAILABLE}: {method} executes once the target \
             DeploymentState (F01) and ControlOperation waves land"
        )
    }

    /// Execute with the target-side journal contract (task C07): a replay of
    /// an accepted id returns the stored result, the same id with a different
    /// payload conflicts, and fresh operations are journaled pending before
    /// dispatch and finalized after.
    pub fn execute_journaled(
        &self,
        operation: &HostOperation,
        journal: &TargetJournal,
    ) -> anyhow::Result<HostResult> {
        if let Err(rejection) = operation.validate() {
            return Ok(HostResult::failed(
                &operation.operation_id,
                HOST_ERR_OPERATION_INVALID,
                format!("{}: {}", rejection.code.as_str(), rejection.detail),
            ));
        }
        journal.run_journaled(operation, dispatch_host_operation)
    }
}

/// Shared dispatch for validated host operations. [`LocalTarget`] answers
/// natively with it and the remote exec helper answers through the identical
/// function after parsing stdin, so both transports cannot drift apart.
pub(crate) fn dispatch_host_operation(operation: &HostOperation) -> HostResult {
    debug_assert!(
        operation.validate().is_ok(),
        "dispatch requires a validated operation"
    );
    match &operation.operation {
        HostOperationBody::Ping { nonce } => HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::Ping {
                nonce: nonce.clone(),
            },
        ),
        HostOperationBody::Hello {} => HostResult::completed(
            &operation.operation_id,
            HostCompletionBody::Hello {
                hello: local_hello(local_supported_runtimes()),
            },
        ),
    }
}

/// Runtimes this installation could drive, detected without spawning engines:
/// engine binaries present on PATH plus the systemd host backend on Linux.
fn local_supported_runtimes() -> Vec<String> {
    let mut runtimes = Vec::new();
    for engine in ["podman", "docker"] {
        if crate::process::command_exists(engine) {
            runtimes.push(engine.to_owned());
        }
    }
    if cfg!(target_os = "linux") {
        runtimes.push("host".to_owned());
    }
    runtimes
}

impl ExecutionTarget for LocalTarget {
    fn inspect_host(&self) -> anyhow::Result<HostOverview> {
        Ok(HostOverview {
            product: "nazoauthctl".to_owned(),
            protocol_schema: HOST_PROTOCOL_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn inspect_instance(&self, _deployment_id: &str) -> anyhow::Result<InstanceInspection> {
        Err(Self::unavailable("inspect_instance"))
    }

    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        // Mirror the remote executor's admission order (parse → validate →
        // dispatch) so local and remote targets accept the same inputs.
        // [`HostOperation::validate`] owns every semantic rule, including
        // per-kind payload constraints; [`dispatch_host_operation`] stays
        // mechanical and shared with the remote helper.
        if let Err(rejection) = operation.validate() {
            return Ok(HostResult::failed(
                &operation.operation_id,
                HOST_ERR_OPERATION_INVALID,
                format!("{}: {}", rejection.code.as_str(), rejection.detail),
            ));
        }
        Ok(dispatch_host_operation(operation))
    }

    fn execute_control_operation(
        &self,
        _request: &ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt> {
        Err(Self::unavailable("execute_control_operation"))
    }

    fn read_health(&self, _deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
        Err(Self::unavailable("read_health"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn local_ping_smoke_executes_without_json_loopback() -> anyhow::Result<()> {
        let target = LocalTarget::new();
        let operation = HostOperation::ping(Uuid::now_v7().to_string(), "smoke-probe");
        let result = target.execute_host_operation(&operation)?;
        assert_eq!(result.operation_id, operation.operation_id);
        assert_eq!(
            result.outcome,
            HostOutcome::Completed {
                body: HostCompletionBody::Ping {
                    nonce: "smoke-probe".to_owned(),
                },
            }
        );
        // The identical bytes must survive the full stdio round trip so a
        // remote executor can answer the same message (C04 readiness).
        let encoded = encode_host_result(&result)?;
        assert_eq!(parse_host_result(&encoded)?, result);
        Ok(())
    }

    #[test]
    fn local_target_reports_host_facts() -> anyhow::Result<()> {
        let overview = LocalTarget::new().inspect_host()?;
        assert_eq!(overview.product, "nazoauthctl");
        assert_eq!(overview.protocol_schema, HOST_PROTOCOL_SCHEMA);
        assert!(!overview.version.is_empty());
        assert!(!overview.os.is_empty());
        assert!(!overview.arch.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_operations_fail_through_the_shared_model() -> anyhow::Result<()> {
        let target = LocalTarget::new();
        let mut operation = HostOperation::ping(Uuid::now_v7().to_string(), "probe");
        operation.expected_revision = Some(4);
        let result = target.execute_host_operation(&operation)?;
        let HostOutcome::Failed { code, detail } = result.outcome else {
            panic!("expected failed outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_INVALID);
        assert!(detail.contains("expected_revision"), "{detail}");

        let mut operation = HostOperation::ping(Uuid::now_v7().to_string(), "probe");
        // A well-formed UUID that is not v7 must be rejected.
        operation.operation_id = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        let result = target.execute_host_operation(&operation)?;
        let HostOutcome::Failed { code, detail } = result.outcome else {
            panic!("expected failed outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_INVALID);
        assert!(detail.contains("UUIDv7"), "{detail}");
        Ok(())
    }

    #[test]
    fn local_hello_reports_the_helper_identity() -> anyhow::Result<()> {
        let target = LocalTarget::new();
        let hello = HostOperation::hello(Uuid::now_v7().to_string());
        let result = target.execute_host_operation(&hello)?;
        let HostOutcome::Completed {
            body: HostCompletionBody::Hello { hello },
        } = result.outcome
        else {
            panic!("expected a hello completion");
        };
        verify_remote_hello(&hello).expect("local helper answers its own handshake");
        Ok(())
    }

    #[test]
    fn journaled_execution_replays_and_conflicts_through_local_target() -> anyhow::Result<()> {
        let temp = crate::filesystem::PrivateTempDir::new("nazauthctl-local-journaled")?;
        let journal = TargetJournal::open(temp.path().join("state"))?;
        let target = LocalTarget::new();

        let operation = HostOperation::ping(Uuid::now_v7().to_string(), "journaled");
        let first = target.execute_journaled(&operation, &journal)?;
        let second = target.execute_journaled(&operation, &journal)?;
        assert_eq!(first, second, "replay returns the stored result");

        let mut conflict = operation.clone();
        conflict.operation = HostOperationBody::Ping {
            nonce: "different".to_owned(),
        };
        let result = target.execute_journaled(&conflict, &journal)?;
        let HostOutcome::Failed { code, .. } = result.outcome else {
            panic!("expected the conflict outcome");
        };
        assert_eq!(code, HOST_ERR_OPERATION_CONFLICT);
        Ok(())
    }

    #[test]
    fn pending_capabilities_report_a_stable_code() {
        let target = LocalTarget::new();
        for error in [
            target.inspect_instance("deploy-alpha").err().unwrap(),
            target
                .execute_control_operation(&ControlOperationRequest {
                    deployment_id: "deploy-alpha".to_owned(),
                    compact_jws: "jws".to_owned(),
                })
                .err()
                .unwrap(),
            target.read_health("deploy-alpha").err().unwrap(),
        ] {
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains(TARGET_CAPABILITY_UNAVAILABLE),
                "{rendered}"
            );
        }
    }
}
