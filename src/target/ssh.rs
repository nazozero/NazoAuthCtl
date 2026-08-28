//! OpenSSH execution target (goal plan 03 §3, tasks C05/C06/C08).
//!
//! Remote execution reuses the system OpenSSH client instead of implementing
//! SSH: the spawned argv is always exactly
//!
//! ```text
//! ssh <ssh_profile> -- <remote command>
//! ssh <ssh_profile> -- sudo -n <remote command>   (HostRecord.privilege = sudo)
//! ```
//!
//! with the remote command fixed to `<helper> remote exec` and the
//! HostOperation JSON riding on stdin. Host authenticity, user authentication,
//! ProxyJump, IdentityFile, agent use, and known_hosts handling are delegated
//! to the user's own SSH configuration by construction: this module passes no
//! `-o` options at all, so `StrictHostKeyChecking=no`, changed-key acceptance,
//! key copying, and config rewriting are unrepresentable. No shell ever
//! interprets a string here — every element is one argv token.
//!
//! The spawned program name is injectable (`with_program`) purely as a test
//! seam; production always uses [`SSH_PROGRAM`].
//!
//! C06 keeps passwords out of the protocol: formal operations run under clean
//! `sudo -n`; when the timestamp is missing an interactive user is sent
//! through exactly one `ssh -t <profile> sudo -v`, while automation receives
//! instructions instead of ever reading a password.
//!
//! C08 gates host-level mutations behind a verified [`RemoteHello`]; any
//! product/schema/version/commit drift fails closed with
//! `REMOTE_HELPER_MISMATCH` and names the exact upgrade command.

use std::{
    cell::RefCell,
    ffi::OsString,
    io::IsTerminal as _,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command as StdCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use uuid::Uuid;

use crate::error_codes::REMOTE_HELPER_MISMATCH;

use crate::process::Process;
use crate::registry::{HostPrivilege, HostRecord, HostTransport};

use super::{
    ControlOperationReceipt, ExecutionTarget, HealthSnapshot, HostOverview, InstanceInspection,
    accepted_control_operation_receipt,
    wire::{
        HOST_ERR_OPERATION_INVALID, HostCompletionBody, HostOperation, HostOutcome, HostResult,
        RemoteHello, encode_host_operation, parse_host_result, sanitize, verify_remote_hello,
    },
};

/// Production OpenSSH client binary name.
pub const SSH_PROGRAM: &str = "ssh";

/// Helper basename used when a HostRecord does not override it.
pub const DEFAULT_REMOTE_EXEC_BASENAME: &str = "nazoauthctl";

/// Monotonic per-operation deadline for one SSH round trip.
pub const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(600);

/// Stable prefix for sudo failures that need human credentials. Automation
/// reads the instruction; nothing ever captures the password itself.
const HOST_ERR_SUDO_PASSWORD_REQUIRED: &str = crate::error_codes::SUDO_PASSWORD_REQUIRED;

/// Startup budget for the one-purpose recovery tunnel.  `ExitOnForwardFailure`
/// makes a bind or remote-connect refusal terminal; the local probe only
/// distinguishes that refusal from an SSH process which is still starting.
const RECOVERY_FORWARD_START_TIMEOUT: Duration = Duration::from_secs(5);

/// A short-lived, loopback-only OpenSSH forward used exclusively for the
/// controller-key recovery ceremony.  It deliberately is not a general SSH
/// transport: callers receive only the randomized local port and no facility
/// to choose a remote host, destination, or request path.
pub(crate) struct RecoverySshForward {
    child: Child,
    local_port: u16,
}

impl RecoverySshForward {
    /// Start `ssh -N -L` with independent argv tokens.  `profile` is the
    /// registry's already-validated OpenSSH Host alias and `remote_port` is
    /// the candidate endpoint's immutable loopback port.
    pub(crate) fn start(profile: &str, remote_port: u16) -> anyhow::Result<Self> {
        if !is_safe_ssh_profile(profile) {
            bail!("recovery tunnel requires a valid OpenSSH Host alias");
        }
        if remote_port == 0 {
            bail!("recovery tunnel requires a non-zero candidate loopback port");
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .context("recovery tunnel could not reserve a local loopback port")?;
        let local_port = listener
            .local_addr()
            .context("recovery tunnel could not read the local loopback port")?
            .port();
        drop(listener);

        let argv = recovery_forward_argv(profile, local_port, remote_port);
        let mut child = StdCommand::new(SSH_PROGRAM)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start recovery SSH forward for '{profile}'"))?;

        let deadline = Instant::now() + RECOVERY_FORWARD_START_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .context("failed to observe recovery SSH forward startup")?
            {
                bail!("recovery SSH forward for '{profile}' exited during startup ({status})");
            }
            if TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], local_port)),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                return Ok(Self { child, local_port });
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("recovery SSH forward for '{profile}' did not open its loopback listener");
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    pub(crate) fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for RecoverySshForward {
    fn drop(&mut self) {
        // This child owns precisely one `-N -L` process.  Always reap it so a
        // failure or crash-resume never leaves a credential-bearing forward.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn is_safe_ssh_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 128
        && !profile.starts_with('-')
        && profile.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'+' | b'-')
        })
}

fn recovery_forward_argv(profile: &str, local_port: u16, remote_port: u16) -> Vec<String> {
    vec![
        "-N".to_owned(),
        "-o".to_owned(),
        "ExitOnForwardFailure=yes".to_owned(),
        "-L".to_owned(),
        format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"),
        profile.to_owned(),
    ]
}

/// An SSH-attached host reached through the system OpenSSH client.
#[derive(Debug)]
pub struct SshTarget {
    profile: String,
    registered_host_id: Option<Uuid>,
    host_alias: String,
    privilege: HostPrivilege,
    remote_exec_basename: String,
    /// Test seam only. Production value: [`SSH_PROGRAM`].
    program: PathBuf,
    timeout: Duration,
    handshake: RefCell<Option<RemoteHello>>,
}

impl SshTarget {
    /// Build the transport for one registered SSH host record.
    pub fn from_record(record: &HostRecord) -> anyhow::Result<Self> {
        if record.transport != HostTransport::Ssh {
            bail!("an SshTarget requires a host record with ssh transport");
        }
        let profile = record
            .ssh_profile
            .clone()
            .context("the ssh host record carries no OpenSSH profile")?;
        Ok(Self {
            registered_host_id: (!record.host_id.is_nil()).then_some(record.host_id),
            host_alias: record.alias.clone(),
            privilege: record.privilege,
            remote_exec_basename: record
                .remote_exec_path
                .clone()
                .unwrap_or_else(|| DEFAULT_REMOTE_EXEC_BASENAME.to_owned()),
            program: PathBuf::from(SSH_PROGRAM),
            profile,
            timeout: DEFAULT_EXEC_TIMEOUT,
            handshake: RefCell::new(None),
        })
    }

    /// Test seam: spawn this program instead of the real OpenSSH client.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The fixed remote command tokens. User input never joins this vector;
    /// the helper basename comes from the validated registry record.
    pub(crate) fn remote_command_argv(&self) -> Vec<String> {
        let mut command = Vec::with_capacity(5);
        if self.privilege == HostPrivilege::Sudo {
            command.push("sudo".to_owned());
            command.push("-n".to_owned());
        }
        command.push(self.remote_exec_basename.clone());
        command.push("remote".to_owned());
        command.push("exec".to_owned());
        command
    }

    /// Arguments for one remote exec round trip. The executable is supplied
    /// separately to [`Process::new`], so it must never appear in this list.
    pub(crate) fn exec_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::with_capacity(2 + self.remote_command_argv().len());
        args.push(self.profile.clone().into());
        args.push("--".into());
        args.extend(self.remote_command_argv().into_iter().map(OsString::from));
        args
    }

    /// Probe argv for non-interactive sudo availability (goal plan 03 §4).
    pub(crate) fn sudo_probe_args(&self) -> Vec<OsString> {
        vec![
            self.profile.clone().into(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            "true".into(),
        ]
    }

    /// Interactive pre-authorization argv. Options precede the destination.
    pub(crate) fn sudo_interactive_args(&self) -> Vec<OsString> {
        vec![
            "-t".into(),
            self.profile.clone().into(),
            "sudo".into(),
            "-v".into(),
        ]
    }

    /// One bounded stdin→stdout round trip through the fixed argv.
    fn transmit(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        let payload = encode_host_operation(operation)?;
        let output = Process::new(self.program.clone())
            .args(self.exec_args())
            .timeout(self.timeout)
            .stdin_output(&payload)
            .context(format!(
                "failed to start the OpenSSH client ({}) for profile '{}'",
                self.program.display(),
                self.profile
            ))?;
        if !output.status.success() {
            bail!("{}", self.transport_failure(output.status, &output.stderr));
        }
        let result = parse_host_result(&output.stdout).map_err(|rejection| {
            anyhow::anyhow!(
                "remote exec on '{}' did not return a valid HostResult ({rejection}); \
                 stdout must carry exactly one answer",
                self.profile
            )
        })?;
        if result.operation_id != operation.operation_id {
            bail!(
                "remote exec on '{}' answered operation {} while {} was in flight",
                self.profile,
                result.operation_id,
                operation.operation_id
            );
        }
        Ok(result)
    }

    /// Classify a failed SSH invocation into closed, actionable categories.
    /// Diagnostics stay bounded and sanitized; secrets never appear because
    /// none are ever passed to the child.
    fn transport_failure(&self, status: std::process::ExitStatus, stderr: &[u8]) -> String {
        let lossy = String::from_utf8_lossy(stderr);
        let excerpt = sanitize(lossy.trim().to_owned());
        if lossy.contains("sudo:") {
            format!(
                "{HOST_ERR_SUDO_PASSWORD_REQUIRED}: sudo refused the non-interactive request \
                 on '{0}' ({excerpt}); establish credentials once with \
                 `ssh -t {0} sudo -v` or configure passwordless sudo (NOPASSWD); \
                 nazoauthctl never reads sudo passwords",
                self.profile
            )
        } else if lossy.contains("Host key verification failed") {
            format!(
                "{}: OpenSSH host key verification failed for '{}'; resolve the unknown or changed \
                 host key in your own SSH configuration — disabling StrictHostKeyChecking is \
                 never an option ({excerpt})",
                crate::error_codes::SSH_HOST_KEY_FAILED,
                self.profile
            )
        } else if lossy.contains("Permission denied") {
            let profile = &self.profile;
            format!(
                "{}: OpenSSH authentication failed for '{profile}' ({excerpt}); fix the \
                 credentials or key setup for this profile in your own SSH configuration",
                crate::error_codes::SSH_AUTH_FAILED,
            )
        } else {
            format!("ssh to '{}' exited with {status} ({excerpt})", self.profile)
        }
    }

    /// Fetch (or reuse) and verify the remote helper identity (task C08).
    ///
    /// Any failure — including an outdated helper that cannot parse the hello
    /// kind — becomes `REMOTE_HELPER_MISMATCH` naming the exact upgrade
    /// command for the target host. There is no fallback path.
    fn handshake(&self) -> anyhow::Result<RemoteHello> {
        if let Some(cached) = self.handshake.borrow().as_ref() {
            return Ok(cached.clone());
        }
        let probe = HostOperation::hello(Uuid::now_v7().to_string());
        let answered = (|| -> anyhow::Result<RemoteHello> {
            let result = self.transmit(&probe)?;
            match result.outcome {
                HostOutcome::Completed {
                    body: HostCompletionBody::Hello { hello },
                } => Ok(hello),
                HostOutcome::Failed { code, .. } => {
                    bail!("the helper answered failure {code} instead of a hello identity")
                }
                HostOutcome::Completed { .. } => {
                    bail!(
                        "the helper answered an unexpected completion instead of a hello identity"
                    )
                }
            }
        })();
        let hello = answered.map_err(|error| {
            anyhow::anyhow!(
                "{REMOTE_HELPER_MISMATCH}: the helper on '{}' does not speak the \
                 current remote exec contract ({error}). Upgrade the target helper first: \
                 `ssh {0} -- {} self update --yes`, then retry; no fallback exists.",
                self.profile,
                self.remote_exec_basename
            )
        })?;
        if let Err(reason) = verify_remote_hello(&hello) {
            bail!(
                "{REMOTE_HELPER_MISMATCH}: {reason}. Upgrade the target helper first: \
                 `ssh {} -- {} self update --yes`, then retry; no fallback exists.",
                self.profile,
                self.remote_exec_basename
            );
        }
        if let Some(host_id) = self.registered_host_id {
            crate::registry::verify_registered_target_identity(host_id, &self.host_alias, &hello)?;
        }
        *self.handshake.borrow_mut() = Some(hello.clone());
        Ok(hello)
    }

    /// Non-interactive sudo probe over the same fixed argv pattern.
    ///
    /// P1-8: exit status alone cannot distinguish "sudo wants a password"
    /// from "the transport itself failed". A transport failure surfaces as
    /// the OpenSSH client's own error text (host-key refusal, auth failure,
    /// network unreachable) and must propagate as a typed host failure, not
    /// masquerade as `PasswordRequired`.
    pub fn probe_sudo(&self) -> anyhow::Result<SudoPreflight> {
        if self.privilege != HostPrivilege::Sudo {
            bail!("host privilege is direct; sudo preflight does not apply");
        }
        let output = Process::new(self.program.clone())
            .args(self.sudo_probe_args())
            .timeout(self.timeout)
            .stdin_output(b"")
            .context("failed to start the OpenSSH client for the sudo probe")?;
        if output.status.success() {
            return Ok(SudoPreflight::Ready);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let transport_failed = [
            "permission denied (publickey",
            "host key verification failed",
            "connection refused",
            "connection timed out",
            "could not resolve hostname",
            "network is unreachable",
            "port 22: connection",
        ]
        .iter()
        .any(|needle| stderr.to_ascii_lowercase().contains(needle));
        if transport_failed {
            bail!(
                "HOST_UNREACHABLE: the sudo probe failed inside the SSH transport, not at \
                 sudo: {}",
                stderr.trim().chars().take(200).collect::<String>()
            );
        }
        Ok(SudoPreflight::PasswordRequired)
    }

    /// Establish a sudo timestamp interactively — at most one real
    /// `ssh -t <profile> sudo -v`, always in a genuine TTY (task C06).
    ///
    /// This is the only place an interactive child is spawned directly:
    /// password entry requires inheriting the terminal, which the capturing
    /// [`Process`] wrapper deliberately never does. The child argv stays
    /// fixed and no password material is read, echoed, or stored.
    pub fn establish_sudo(&self) -> anyhow::Result<()> {
        if self.privilege != HostPrivilege::Sudo {
            bail!("host privilege is direct; sudo preflight does not apply");
        }
        if self.probe_sudo()? == SudoPreflight::Ready {
            return Ok(());
        }
        if !std::io::stdin().is_terminal() {
            bail!(
                "{HOST_ERR_SUDO_PASSWORD_REQUIRED}: sudo on '{0}' requires a password and this \
                 session has no TTY. Run `ssh -t {0} sudo -v` once yourself, or configure \
                 NOPASSWD for automation; nazoauthctl never reads sudo passwords.",
                self.profile
            );
        }
        eprintln!(
            "nazoauthctl: establishing sudo credentials on '{}' — complete the prompt",
            self.profile
        );
        let status = StdCommand::new(&self.program)
            .args(self.sudo_interactive_args())
            .status()
            .context("failed to run the interactive sudo pre-authorization")?;
        if !status.success() {
            bail!(
                "sudo pre-authorization on '{}' failed with {status}; fix your SSH or sudo \
                 setup and retry — no password material was read or stored",
                self.profile
            );
        }
        if self.probe_sudo()? != SudoPreflight::Ready {
            bail!(
                "the sudo timestamp on '{0}' was not established; run `ssh -t {0} sudo -v` again",
                self.profile
            );
        }
        Ok(())
    }
}

/// Result of probing non-interactive sudo availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SudoPreflight {
    /// `sudo -n` works right now.
    Ready,
    /// A password would be required; see [`SshTarget::establish_sudo`].
    PasswordRequired,
}

impl ExecutionTarget for SshTarget {
    fn inspect_host(&self) -> anyhow::Result<HostOverview> {
        // `host add`/`check` flows are themselves the handshake.
        let hello = self.handshake()?;
        Ok(HostOverview {
            product: hello.product,
            protocol_schema: hello.remote_exec_schema,
            version: hello.version,
            os: hello.os,
            arch: hello.arch,
        })
    }

    fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
        // Live read of the target-side DeploymentState through the fixed
        // stdio contract (F01). The state-inspect kind is handshake-gated
        // like every non-probe kind, so an unverified helper can never be
        // asked about deployments.
        let operation = HostOperation::state_inspect(Uuid::now_v7().to_string(), deployment_id);
        match self.execute_host_operation(&operation)?.outcome {
            HostOutcome::Completed {
                body: HostCompletionBody::StateInspect { inspection },
            } => Ok(inspection),
            HostOutcome::Completed { .. } => bail!(
                "the helper on '{}' answered an unexpected completion instead of a deployment \
                 inspection",
                self.profile
            ),
            HostOutcome::Failed { code, detail } => Err(anyhow::anyhow!("{code}: {detail}")),
        }
    }

    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        // Same admission order as LocalTarget: validate before anything moves.
        if let Err(rejection) = operation.validate() {
            return Ok(HostResult::failed(
                &operation.operation_id,
                HOST_ERR_OPERATION_INVALID,
                format!("{}: {}", rejection.code.as_str(), rejection.detail),
            ));
        }
        if requires_handshake(operation.operation.kind()) {
            // C08: mutations confirm the remote helper identity first.
            self.handshake()?;
        }
        self.transmit(operation)
    }

    fn execute_control_operation(
        &self,
        request: super::ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt> {
        use super::control_exec::CONTROL_OUTCOME_UNKNOWN;
        // The signed envelope is public data (no secret material), so it
        // rides the handshake-gated stdio contract like every other kind and
        // the target journals the delivery under its C07 contract.
        let request_operation_id = request.operation_id.clone();
        let operation = HostOperation::control_operation(
            request.operation_id,
            request.deployment_id,
            request.compact_jws,
            request.change_set,
        );
        operation.validate().map_err(|rejection| {
            anyhow::anyhow!(
                "{HOST_ERR_OPERATION_INVALID}: {}: {}",
                rejection.code.as_str(),
                rejection.detail
            )
        })?;
        let result = self.execute_host_operation(&operation)?;
        match result.outcome {
            HostOutcome::Completed {
                body:
                    HostCompletionBody::ControlOperationExecuted {
                        result: control_result,
                    },
            } => accepted_control_operation_receipt(request_operation_id.clone(), control_result),
            HostOutcome::Completed { .. } => bail!(
                "{HOST_ERR_OPERATION_INVALID}: the helper on '{}' answered an unexpected \
                 completion instead of a ControlOperation result",
                self.profile
            ),
            HostOutcome::Failed { code, detail } => {
                if code == CONTROL_OUTCOME_UNKNOWN || detail.contains(CONTROL_OUTCOME_UNKNOWN) {
                    // The operator may have executed; only a resumed resend of
                    // the same envelope can resolve the outcome.
                    bail!("{code}: {detail}")
                }
                // Admission-grade refusal before acceptance.
                Ok(ControlOperationReceipt {
                    operation_id: request_operation_id,
                    accepted: false,
                    result: None,
                    rejection_code: Some(code),
                })
            }
        }
    }

    fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
        let inspection = self.inspect_instance(deployment_id)?;
        Ok(HealthSnapshot {
            deployment_id: inspection.deployment_id,
            healthy: inspection.healthy,
            summary: inspection.health_summary,
            observed_at: inspection.observed_at,
        })
    }
}

/// C08 gating policy. Read-only probes (`ping`, `hello`) are exempt — they
/// are exactly what you run to diagnose a broken handshake. Every later kind
/// defaults to gated, so new mutation kinds cannot skip the check.
fn requires_handshake(kind: &str) -> bool {
    !matches!(kind, "ping" | "hello")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem;
    use crate::registry::HostRecord;
    use crate::target::wire::{
        HELLO_PRODUCT, HOST_PROTOCOL_SCHEMA, HostOperationBody, LOCAL_BUILD_COMMIT, local_hello,
        parse_host_operation,
    };
    use std::fs;

    const PROFILE: &str = "prod-a";
    const TEST_TARGET_ID: &str = "019d0000-0000-7000-8000-000000000001";
    const CUSTOM_BASENAME: &str = "nazoauthctl.test";

    #[test]
    fn recovery_forward_is_loopback_only_and_exit_on_forward_failure() {
        assert_eq!(
            recovery_forward_argv("hostinger", 43123, 42123),
            [
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                "127.0.0.1:43123:127.0.0.1:42123",
                "hostinger",
            ]
        );
        assert!(is_safe_ssh_profile("hostinger"));
        assert!(!is_safe_ssh_profile("-oProxyCommand=bad"));
    }

    // ---------- fixture stub transport ----------

    /// A stand-in "OpenSSH client" that records its argv, drains stdin, and
    /// replays a canned scenario. Materialized as a platform script next to
    /// data files so scenarios stay pure data.
    struct SshStub {
        dir: filesystem::PrivateTempDir,
        program: PathBuf,
    }

    struct StubScenario<'a> {
        response_json: &'a str,
        stderr_text: Option<&'a str>,
        exit_code: i32,
    }

    impl SshStub {
        fn install(scenario: &StubScenario) -> anyhow::Result<Self> {
            Self::install_with_hello(scenario, None)
        }

        /// Install a stub whose hello answers come from `hello_response_json`
        /// while every other kind gets `scenario.response_json`. Used to prove
        /// the handshake gate really runs before DeploymentState kinds.
        fn install_with_hello(
            scenario: &StubScenario,
            hello_response_json: Option<&str>,
        ) -> anyhow::Result<Self> {
            let dir = filesystem::PrivateTempDir::new("nazauthctl-ssh-stub")?;
            let root = dir.path();
            filesystem::atomic_write(
                &root.join("response.json"),
                scenario.response_json.as_bytes(),
                0o600,
            )?;
            if let Some(hello_response_json) = hello_response_json {
                filesystem::atomic_write(
                    &root.join("hello-response.json"),
                    hello_response_json.as_bytes(),
                    0o600,
                )?;
            }
            if let Some(stderr_text) = scenario.stderr_text {
                filesystem::atomic_write(&root.join("stderr.txt"), stderr_text.as_bytes(), 0o600)?;
            }
            filesystem::atomic_write(
                &root.join("exitcode.txt"),
                scenario.exit_code.to_string().as_bytes(),
                0o600,
            )?;
            #[cfg(unix)]
            let program = {
                use std::os::unix::fs::PermissionsExt;

                let script = root.join("ssh");
                fs::write(&script, unix_stub_script().as_bytes())?;
                fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
                script
            };
            #[cfg(windows)]
            let program = {
                filesystem::atomic_write(
                    &root.join("ssh.cmd"),
                    windows_stub_cmd().as_bytes(),
                    0o600,
                )?;
                filesystem::atomic_write(
                    &root.join("stub.ps1"),
                    windows_stub_ps1().as_bytes(),
                    0o600,
                )?;
                root.join("ssh.cmd")
            };
            Ok(Self { dir, program })
        }

        fn recorded_argv(&self) -> String {
            fs::read_to_string(self.dir.path().join("argv.txt")).expect("stub records its argv")
        }

        fn recorded_stdin(&self) -> String {
            fs::read_to_string(self.dir.path().join("stdin.json")).expect("stub records its stdin")
        }

        /// Invocation arguments after the program token, one entry per call.
        fn argv_invocations(&self) -> Vec<String> {
            self.recorded_argv().lines().map(str::to_owned).collect()
        }
    }

    #[cfg(unix)]
    fn unix_stub_script() -> String {
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.txt"
input=$(cat)
printf '%s' "$input" > "$(dirname "$0")/stdin.json"
caller=$(printf '%s' "$input" | sed -n 's/.*"operation_id":"\([0-9a-fA-F-]*\)".*/\1/p')
response="$(dirname "$0")/response.json"
case "$input" in
  *'"kind":"hello"'*)
    if [ -f "$(dirname "$0")/hello-response.json" ]; then
      response="$(dirname "$0")/hello-response.json"
    fi ;;
esac
sed "s/__OPERATION_ID__/${caller:-none}/g" "$response"
if [ -f "$(dirname "$0")/stderr.txt" ]; then
  cat "$(dirname "$0")/stderr.txt" >&2
fi
exit "$(cat "$(dirname "$0")/exitcode.txt")"
"#
        .to_owned()
    }

    #[cfg(windows)]
    fn windows_stub_cmd() -> String {
        [
            "@echo off",
            "pwsh -NoProfile -File \"%~dp0stub.ps1\" %*",
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
            "Add-Content -LiteralPath (Join-Path $here 'argv.txt') -Encoding Ascii -Value ($args -join ' ')",
            "$stdinText = [Console]::In.ReadToEnd()",
            "[IO.File]::WriteAllText((Join-Path $here 'stdin.json'), $stdinText, [Text.UTF8Encoding]::new($false))",
            "$m = [regex]::Match($stdinText, '\"operation_id\":\"([0-9a-fA-F-]+)\"')",
            "$callerId = if ($m.Success) { $m.Groups[1].Value } else { '' }",
            "$responsePath = Join-Path $here 'response.json'",
            "if ($stdinText -match '\"kind\":\"hello\"') {",
            "  $helloPath = Join-Path $here 'hello-response.json'",
            "  if (Test-Path -LiteralPath $helloPath) { $responsePath = $helloPath }",
            "}",
            "$template = Get-Content -LiteralPath $responsePath -Raw",
            "[Console]::Out.Write($template.Replace('__OPERATION_ID__', $callerId))",
            "[Console]::Out.Write(\"`n\")",
            "$stderrPath = Join-Path $here 'stderr.txt'",
            "if (Test-Path $stderrPath) { [Console]::Error.Write((Get-Content -LiteralPath $stderrPath -Raw)) }",
            "$codePath = Join-Path $here 'exitcode.txt'",
            "if (Test-Path $codePath) { exit [int](Get-Content -LiteralPath $codePath -Raw) }",
            "exit 0",
            "",
        ]
        .join("\r\n")
    }

    // ---------- canned responses built from live constants ----------

    fn hello_response_json(version: &str, commit: &str) -> String {
        let identity = local_hello(Vec::new());
        serde_json::json!({
            "schema": HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {"completion": "hello", "hello": {
                "product": identity.product,
                "target_id": TEST_TARGET_ID,
                "remote_exec_schema": identity.remote_exec_schema,
                "version": version,
                "commit": commit,
                "os": identity.os,
                "arch": identity.arch,
                "supported_runtimes": ["podman"],
            }}}
        })
        .to_string()
    }

    fn ping_response_json(nonce: &str) -> String {
        serde_json::json!({
            "schema": HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {"completion": "ping", "nonce": nonce}}
        })
        .to_string()
    }

    fn ssh_target(privilege: HostPrivilege, stub: &SshStub) -> anyhow::Result<SshTarget> {
        Ok(SshTarget::from_record(&HostRecord::new_ssh(
            "server-a",
            PROFILE,
            privilege,
            Uuid::parse_str(TEST_TARGET_ID)?,
        )?)?
        .with_program(stub.program.clone()))
    }

    // ---------- argv shape (no spawning required) ----------

    #[test]
    fn exec_args_are_fixed_and_delegation_only() {
        let direct = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Direct, Uuid::now_v7())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            direct.exec_args(),
            [PROFILE, "--", "nazoauthctl", "remote", "exec"]
        );

        let sudo = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Sudo, Uuid::now_v7()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            sudo.exec_args(),
            [PROFILE, "--", "sudo", "-n", "nazoauthctl", "remote", "exec"]
        );

        let mut custom =
            HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Direct, Uuid::now_v7())
                .unwrap();
        custom.remote_exec_path = Some(CUSTOM_BASENAME.to_owned());
        let custom = SshTarget::from_record(&custom).unwrap();
        assert_eq!(
            custom.exec_args(),
            [PROFILE, "--", CUSTOM_BASENAME, "remote", "exec"]
        );

        // Delegation by construction: no option overrides of any kind, ever.
        for argv in [direct.exec_args(), sudo.exec_args(), custom.exec_args()] {
            for token in argv {
                let token = token.to_string_lossy();
                assert!(!token.contains("StrictHostKeyChecking"), "{token}");
                assert!(!token.contains("accept-new"), "{token}");
                assert!(!token.contains("UserKnownHostsFile"), "{token}");
                assert!(!token.contains("ForwardAgent"), "{token}");
                assert_ne!(token, "-o");
            }
        }
    }

    #[test]
    fn sudo_probe_and_interactive_argv_have_the_documented_shape() {
        let sudo = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Sudo, Uuid::now_v7()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            sudo.sudo_probe_args(),
            [PROFILE, "--", "sudo", "-n", "true"]
        );
        assert_eq!(sudo.sudo_interactive_args(), ["-t", PROFILE, "sudo", "-v"]);
    }

    // ---------- behavior over the stub transport ----------

    #[test]
    fn handshake_verifies_and_inspect_host_maps_the_announcement() {
        let stub = SshStub::install(&StubScenario {
            response_json: &hello_response_json(env!("CARGO_PKG_VERSION"), LOCAL_BUILD_COMMIT),
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let overview = target.inspect_host().expect("handshake verifies");
        assert_eq!(overview.product, HELLO_PRODUCT);
        assert_eq!(overview.protocol_schema, HOST_PROTOCOL_SCHEMA);
        assert_eq!(overview.version, env!("CARGO_PKG_VERSION"));
        assert!(!overview.os.is_empty());
        assert!(!overview.arch.is_empty());

        // Exactly the fixed argv ran; nothing else was appended to it.
        let invocations = stub.argv_invocations();
        assert_eq!(invocations.len(), 1, "{invocations:?}");
        assert_eq!(
            invocations[0],
            format!("{PROFILE} -- {DEFAULT_REMOTE_EXEC_BASENAME} remote exec")
        );
    }

    #[test]
    fn mutation_kinds_default_to_handshake_gating() {
        assert!(
            !requires_handshake("ping"),
            "probes diagnose broken handshakes"
        );
        assert!(!requires_handshake("hello"));
        // F01 DeploymentState kinds are gated like every other non-probe.
        assert!(requires_handshake("state-inspect"));
        assert!(requires_handshake("state-mutate"));
        // The G05 discovery sweep is read-only but still gated: an unverified
        // helper is never asked what deployments exist.
        assert!(requires_handshake("state-list"));
        // Closed-set default: every future mutation kind is gated.
        for kind in ["install", "update", "uninstall", "rollback"] {
            assert!(requires_handshake(kind), "{kind}");
        }
    }

    fn inspection_response_json(inspection: &InstanceInspection) -> String {
        serde_json::json!({
            "schema": HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {
                "completion": "state-inspect",
                "inspection": serde_json::to_value(inspection).expect("inspection serializes"),
            }}
        })
        .to_string()
    }

    fn sample_inspection() -> InstanceInspection {
        InstanceInspection {
            current_build_identity: None,
            current_instance_identity: None,
            deployment_id: "deploy-alpha".to_owned(),
            issuer: "https://auth.example.com".to_owned(),
            observed_at: chrono::Utc::now(),
            revision: 4,
            runtime: crate::target::deployment_state::RuntimeSurface::new(
                "podman",
                "nazoauth-main",
                8000,
            )
            .unwrap(),
            artifact: Default::default(),
            config_reference: "/etc/nazauth/config.toml".to_owned(),
            config_schema: "nazauth-config-v1".to_owned(),
            resources: vec![
                crate::target::deployment_state::Resource::new(
                    "shared-db",
                    "postgres",
                    "pg-main.example.internal:5432",
                    crate::target::deployment_state::ResourceOwnership::External,
                    crate::target::deployment_state::ResourceScope::Shared,
                )
                .unwrap(),
            ],
            healthy: true,
            health_summary: "runtime healthy".to_owned(),
            backup: crate::target::BackupProjection {
                local_rollback_ready: false,
                snapshot: None,
            },
            active_host_operation: None,
            config_revision_marker: None,
        }
    }

    #[test]
    fn state_inspect_runs_only_after_a_verified_handshake() -> anyhow::Result<()> {
        let inspection = sample_inspection();
        let stub = SshStub::install_with_hello(
            &StubScenario {
                response_json: &inspection_response_json(&inspection),
                stderr_text: None,
                exit_code: 0,
            },
            Some(&hello_response_json(
                env!("CARGO_PKG_VERSION"),
                LOCAL_BUILD_COMMIT,
            )),
        )?;
        let target = ssh_target(HostPrivilege::Direct, &stub)?;

        let seen = target.inspect_instance("deploy-alpha")?;
        assert_eq!(seen, inspection);

        // Exactly two fixed round trips ran: the gated handshake first, then
        // the state-inspect operation — both through the same argv shape.
        let invocations = stub.argv_invocations();
        assert_eq!(invocations.len(), 2, "{invocations:?}");
        assert!(
            invocations
                .iter()
                .all(|line| line.ends_with("-- nazoauthctl remote exec")),
            "{invocations:?}"
        );
        Ok(())
    }

    #[test]
    fn a_mismatched_helper_is_never_asked_about_deployments() -> anyhow::Result<()> {
        let stub = SshStub::install_with_hello(
            &StubScenario {
                response_json: &inspection_response_json(&sample_inspection()),
                stderr_text: None,
                exit_code: 0,
            },
            Some(&hello_response_json("0.0.1-old", LOCAL_BUILD_COMMIT)),
        )?;
        let target = ssh_target(HostPrivilege::Direct, &stub)?;

        let error = target.inspect_instance("deploy-alpha").expect_err("drift");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(REMOTE_HELPER_MISMATCH), "{rendered}");
        assert_eq!(
            stub.argv_invocations().len(),
            1,
            "only the failing hello may reach the wire"
        );
        Ok(())
    }

    #[test]
    fn another_current_physical_helper_is_never_asked_about_deployments() -> anyhow::Result<()> {
        let other_target = Uuid::now_v7();
        let foreign_hello = hello_response_json(env!("CARGO_PKG_VERSION"), LOCAL_BUILD_COMMIT)
            .replace(TEST_TARGET_ID, &other_target.to_string());
        let stub = SshStub::install_with_hello(
            &StubScenario {
                response_json: &inspection_response_json(&sample_inspection()),
                stderr_text: None,
                exit_code: 0,
            },
            Some(&foreign_hello),
        )?;
        let target = ssh_target(HostPrivilege::Direct, &stub)?;

        let error = target
            .inspect_instance("deploy-alpha")
            .expect_err("target-owned identity mismatch");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(crate::error_codes::TARGET_IDENTITY_MISMATCH),
            "{rendered}"
        );
        assert!(rendered.contains(TEST_TARGET_ID), "{rendered}");
        assert!(rendered.contains(&other_target.to_string()), "{rendered}");
        assert_eq!(
            stub.argv_invocations().len(),
            1,
            "only the failing hello may reach the wire"
        );
        Ok(())
    }

    #[test]
    fn stale_helper_identity_fails_closed_naming_the_upgrade_command() {
        let stub = SshStub::install(&StubScenario {
            response_json: &hello_response_json("0.0.1-old", LOCAL_BUILD_COMMIT),
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target.inspect_host().expect_err("version drift rejected");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(REMOTE_HELPER_MISMATCH), "{rendered}");
        assert!(
            rendered.contains(&format!(
                "ssh {PROFILE} -- {DEFAULT_REMOTE_EXEC_BASENAME} self update --yes"
            )),
            "must name the exact upgrade command: {rendered}"
        );
        assert!(rendered.contains("no fallback"), "{rendered}");

        // The same mismatch blocks the ping path once a mutation arrives;
        // until F01 introduces mutation kinds the gate itself is pinned by
        // mutation_kinds_default_to_handshake_gating above.
    }

    #[test]
    fn helpers_that_cannot_answer_hello_fail_as_mismatch() {
        // A pre-hello helper exits nonzero on the unknown "hello" kind.
        let stub = SshStub::install(&StubScenario {
            response_json: "{}",
            stderr_text: Some(
                "nazoauthctl: HOST_OPERATION_KIND_UNKNOWN: unsupported operation kind 'hello'\n",
            ),
            exit_code: 2,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target.inspect_host().expect_err("old helper");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(REMOTE_HELPER_MISMATCH), "{rendered}");
        assert!(rendered.contains("self update --yes"), "{rendered}");
    }

    #[test]
    fn host_key_failures_surface_the_openssh_diagnostic() {
        let stub = SshStub::install(&StubScenario {
            response_json: "{}",
            stderr_text: Some("Host key verification failed.\r\n"),
            exit_code: 255,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target
            .execute_host_operation(&HostOperation::ping(Uuid::now_v7().to_string(), "x"))
            .expect_err("host key failure");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("host key verification failed"),
            "{rendered}"
        );
        assert!(rendered.contains("StrictHostKeyChecking"), "{rendered}");
    }

    #[test]
    fn permission_denied_reports_authentication_failure() {
        let stub = SshStub::install(&StubScenario {
            response_json: "{}",
            stderr_text: Some("Permission denied (publickey,password).\r\n"),
            exit_code: 255,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target
            .execute_host_operation(&HostOperation::ping(Uuid::now_v7().to_string(), "x"))
            .expect_err("auth failure");
        assert!(
            format!("{error:#}").contains("authentication failed"),
            "{error:#}"
        );
    }

    #[test]
    fn corrupt_helper_stdout_is_a_transport_error_not_a_result() {
        let stub = SshStub::install(&StubScenario {
            response_json: "{\"schema\":1,\"operation_id\":\"__OPERATION_ID__\",\"outcome\":{\"status\":\"completed\",\"body\":{\"result\":\"ping\",\"nonce\":\"ok\"}}} trailing garbage",
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target
            .execute_host_operation(&HostOperation::ping(Uuid::now_v7().to_string(), "x"))
            .expect_err("garbage tail");
        assert!(
            format!("{error:#}").contains("did not return a valid HostResult"),
            "{error:#}"
        );
    }

    #[test]
    fn results_for_other_operations_are_rejected() {
        let stub = SshStub::install(&StubScenario {
            response_json: &serde_json::json!({
                "schema": HOST_PROTOCOL_SCHEMA,
                "operation_id": Uuid::now_v7().to_string(),
                "outcome": {"status": "completed", "body": {"completion": "ping", "nonce": "foreign"}}
            })
            .to_string(),
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let error = target
            .execute_host_operation(&HostOperation::ping(Uuid::now_v7().to_string(), "x"))
            .expect_err("foreign result");
        assert!(
            format!("{error:#}").contains("answered operation"),
            "{error:#}"
        );
    }

    #[test]
    fn invalid_operations_fail_before_any_transport_activity() {
        let stub = SshStub::install(&StubScenario {
            response_json: &ping_response_json("unused"),
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Direct, &stub).unwrap();

        let mut invalid = HostOperation::ping(Uuid::now_v7().to_string(), "x");
        invalid.deployment_id = Some("deploy-alpha".to_owned());
        let result = target
            .execute_host_operation(&invalid)
            .expect("typed failure");
        match result.outcome {
            HostOutcome::Failed { code, detail } => {
                assert_eq!(code, HOST_ERR_OPERATION_INVALID);
                assert!(detail.contains("deployment_id"), "{detail}");
            }
            _ => panic!("expected typed rejection"),
        }
        assert!(
            !stub.dir.path().join("argv.txt").exists(),
            "rejected operations must not reach the transport"
        );
    }

    // ---------- sudo preflight (C06) ----------

    #[test]
    fn sudo_probe_reports_ready_when_sudo_n_succeeds() {
        let stub = SshStub::install(&StubScenario {
            response_json: &ping_response_json("ignored-by-probe"),
            stderr_text: None,
            exit_code: 0,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Sudo, &stub).unwrap();

        assert_eq!(target.probe_sudo().unwrap(), SudoPreflight::Ready);
        let invocations = stub.argv_invocations();
        assert_eq!(invocations.len(), 1, "{invocations:?}");
        assert_eq!(invocations[0], format!("{PROFILE} -- sudo -n true"));
    }

    #[test]
    fn automation_never_attempts_interactive_password_entry() {
        let stub = SshStub::install(&StubScenario {
            response_json: &ping_response_json("ignored"),
            stderr_text: Some("sudo: a password is required\r\nsudo: no password was provided\r\n"),
            exit_code: 1,
        })
        .unwrap();
        let target = ssh_target(HostPrivilege::Sudo, &stub).unwrap();

        assert_eq!(
            target.probe_sudo().unwrap(),
            SudoPreflight::PasswordRequired
        );

        // Test processes have no TTY: establish_sudo must fail with clear
        // next-step instructions and must never spawn the interactive variant.
        let error = target.establish_sudo().expect_err("no tty available");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(HOST_ERR_SUDO_PASSWORD_REQUIRED),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("ssh -t {PROFILE} sudo -v")),
            "{rendered}"
        );
        assert!(rendered.contains("NOPASSWD"), "{rendered}");

        // Two explicit probes ran (one direct, one inside establish_sudo);
        // no `ssh -t` invocation ever happened.
        let invocations = stub.argv_invocations();
        assert_eq!(invocations.len(), 2, "{invocations:?}");
        assert!(
            invocations
                .iter()
                .all(|line| line.ends_with("-- sudo -n true"))
        );
    }

    #[test]
    fn formal_operations_under_sudo_still_use_the_clean_prefix() {
        // The sudo record's exec argv keeps `sudo -n`; nothing in the flow
        // downgrades to interactive forms for the JSON operation itself.
        let target = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Sudo, Uuid::now_v7()).unwrap(),
        )
        .unwrap();
        let joined = target
            .exec_args()
            .into_iter()
            .map(|token| token.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains(&format!("-- sudo -n {DEFAULT_REMOTE_EXEC_BASENAME}")),
            "{joined}"
        );
        assert!(!joined.contains(" -t "), "formal ops never allocate a tty");
    }

    #[test]
    fn direct_privilege_rejects_sudo_preflight() {
        let target = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Direct, Uuid::now_v7())
                .unwrap(),
        )
        .unwrap();
        let error = target.probe_sudo().expect_err("direct host");
        assert!(format!("{error:#}").contains("direct"), "{error:#}");
    }

    // ---------- shared trait plumbing ----------

    #[test]
    fn control_operations_over_ssh_reject_invalid_operation_ids_before_transport() {
        let target = SshTarget::from_record(
            &HostRecord::new_ssh("server-a", PROFILE, HostPrivilege::Direct, Uuid::now_v7())
                .unwrap(),
        )
        .unwrap();
        let error = target
            .execute_control_operation(super::super::ControlOperationRequest {
                operation_id: String::new(),
                deployment_id: "deploy-alpha".to_owned(),
                compact_jws: "not a jws".to_owned(),
                change_set: None,
            })
            .err()
            .unwrap();
        let rendered = format!("{error:#}");
        assert!(rendered.contains(HOST_ERR_OPERATION_INVALID), "{rendered}");
    }

    #[test]
    fn ssh_control_operation_carries_exact_change_set_bytes() -> anyhow::Result<()> {
        let response = serde_json::json!({
            "schema": HOST_PROTOCOL_SCHEMA,
            "operation_id": "__OPERATION_ID__",
            "outcome": {"status": "completed", "body": {
                "completion": "control-operation-executed",
                "result": {
                    "schema": nazo_operator_protocol::CONTROL_RESULT_SCHEMA,
                    "operation_id": "__OPERATION_ID__",
                    "request_hash": "0".repeat(64),
                    "outcome": "succeeded",
                    "error": null,
                    "accepted_at": 1,
                    "completed_at": 2
                }
            }}
        })
        .to_string();
        let hello = hello_response_json(env!("CARGO_PKG_VERSION"), LOCAL_BUILD_COMMIT);
        let stub = SshStub::install_with_hello(
            &StubScenario {
                response_json: &response,
                stderr_text: None,
                exit_code: 0,
            },
            Some(&hello),
        )?;
        let target = SshTarget::from_record(&HostRecord::new_ssh(
            "server-a",
            PROFILE,
            HostPrivilege::Direct,
            Uuid::parse_str(TEST_TARGET_ID)?,
        )?)?
        .with_program(stub.program.clone());
        let operation_id = Uuid::now_v7().to_string();
        let material = vec![0, 1, 2, 0xff, b'\n'];
        let receipt = target.execute_control_operation(super::super::ControlOperationRequest {
            operation_id: operation_id.clone(),
            deployment_id: "deploy-alpha".to_owned(),
            compact_jws: format!("{}.{}.{}", "a".repeat(40), "b".repeat(40), "c".repeat(64)),
            change_set: Some(super::super::SecretMaterial::try_new(material.clone())?),
        })?;
        assert!(receipt.accepted);
        let operation = parse_host_operation(stub.recorded_stdin().as_bytes())?;
        let HostOperationBody::ControlOperation {
            change_set: Some(change_set),
            ..
        } = operation.operation
        else {
            panic!("SSH wire omitted the change set")
        };
        assert_eq!(change_set.as_bytes(), material);
        Ok(())
    }
}
