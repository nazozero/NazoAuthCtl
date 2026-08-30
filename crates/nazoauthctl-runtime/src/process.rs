#[cfg(unix)]
use std::fs::File;
use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::{Read as _, Write as _},
    path::Path,
    process::{Command, Output, Stdio},
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use wait_timeout::ChildExt as _;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct Process {
    program: OsString,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    timeout: Duration,
}

impl Process {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            environment: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(value.into());
        self
    }

    pub fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        #[cfg(unix)]
        command.process_group(0);
        if !test_environment_passthrough() {
            command.env_clear();
            #[cfg(unix)]
            command.env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
            #[cfg(unix)]
            command.env(
                "HOME",
                std::env::var_os("HOME").unwrap_or_else(|| "/root".into()),
            );
            #[cfg(unix)]
            if let Some(value) = std::env::var_os("XDG_RUNTIME_DIR") {
                command.env("XDG_RUNTIME_DIR", value);
            }
            #[cfg(unix)]
            command.env("LC_ALL", "C");
            #[cfg(windows)]
            // Windows OpenSSH needs both roots to resolve the user's
            // `.ssh` directory and the system SSH configuration.
            for key in [
                "PATH",
                "PATHEXT",
                "SystemRoot",
                "ComSpec",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "ProgramData",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        }
        command.args(&self.args).envs(self.environment.clone());
        command
    }

    pub fn output(&self) -> anyhow::Result<Output> {
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        self.collect_output(child, None)
    }

    pub fn run_quiet(&self) -> anyhow::Result<()> {
        let output = self.output()?;
        if !output.status.success() {
            // Bounded stderr echo: daemon rejections (auth, manifest unknown,
            // platform mismatch) are exactly the operator-actionable facts.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            let stderr_note = if stderr.is_empty() {
                String::new()
            } else {
                let bounded: String = stderr.chars().take(400).collect();
                format!(": {bounded}")
            };
            bail!(
                "{} failed with status {}{}",
                self.display_name(),
                output.status,
                stderr_note
            );
        }
        Ok(())
    }

    pub fn stdout(&self) -> anyhow::Result<String> {
        let output = self.output()?;
        if !output.status.success() {
            bail!(
                "{} failed with status {}",
                self.display_name(),
                output.status
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} produced non-UTF-8 output", self.display_name()))
    }

    pub fn stdin_stdout(&self, input: &[u8]) -> anyhow::Result<String> {
        let output = self.stdin_output(input)?;
        if !output.status.success() {
            // Bounded stderr echo, matching run_quiet: one-shot container
            // failures surface their application error on the engine's stderr.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            let stderr_note = if stderr.is_empty() {
                String::new()
            } else {
                let bounded: String = stderr.chars().take(400).collect();
                format!(": {bounded}")
            };
            bail!(
                "{} failed with status {}{}",
                self.display_name(),
                output.status,
                stderr_note
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} produced non-UTF-8 output", self.display_name()))
    }

    /// Feeds `input` on stdin and captures the complete bounded output,
    /// including stderr, for protocol transports that classify failures from
    /// the child's diagnostic stream (for example OpenSSH exec wrappers).
    pub fn stdin_output(&self, input: &[u8]) -> anyhow::Result<Output> {
        let mut command = self.command();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        self.collect_output(child, Some(input))
    }

    pub fn stdout_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .with_context(|| format!("failed to create command output {}", path.display()))?;
        let durable = file
            .try_clone()
            .with_context(|| format!("failed to retain command output {}", path.display()))?;
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to execute {}", self.display_name()))?;
        let status = wait_or_kill(&mut child, self.timeout, &self.display_name())?;
        if !status.success() {
            bail!("{} failed with status {status}", self.display_name());
        }
        durable
            .sync_all()
            .with_context(|| format!("failed to persist command output {}", path.display()))?;
        #[cfg(unix)]
        File::open(
            path.parent()
                .context("command output has no parent directory")?,
        )
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "failed to persist command output directory for {}",
                path.display()
            )
        })?;
        Ok(())
    }

    pub fn succeeds(&self) -> bool {
        let mut command = self.command();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        wait_or_kill(&mut child, self.timeout, &self.display_name())
            .is_ok_and(|status| status.success())
    }

    fn collect_output(
        &self,
        mut child: std::process::Child,
        input: Option<&[u8]>,
    ) -> anyhow::Result<Output> {
        let stdout = child
            .stdout
            .take()
            .context("child stdout was unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("child stderr was unavailable")?;
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        spawn_reader(stdout, stdout_sender);
        spawn_reader(stderr, stderr_sender);
        if let Some(input) = input {
            let mut stdin = child.stdin.take().context("child stdin was unavailable")?;
            if let Err(error) = stdin.write_all(input) {
                terminate_and_reap(&mut child);
                drain_reader(stdout_receiver);
                drain_reader(stderr_receiver);
                return Err(error).context("failed to write bounded child stdin");
            }
        }
        let status = wait_or_kill(&mut child, self.timeout, &self.display_name());
        let stdout = receive_reader(stdout_receiver);
        let stderr = receive_reader(stderr_receiver);
        Ok(Output {
            status: status?,
            stdout: stdout?,
            stderr: stderr?,
        })
    }

    fn display_name(&self) -> String {
        Path::new(&self.program)
            .file_name()
            .unwrap_or_else(|| OsStr::new("command"))
            .to_string_lossy()
            .into_owned()
    }
}

fn read_bounded(reader: impl std::io::Read) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        bail!("child output exceeded the capture limit");
    }
    Ok(bytes)
}

fn wait_or_kill(
    child: &mut std::process::Child,
    timeout: Duration,
    display_name: &str,
) -> anyhow::Result<std::process::ExitStatus> {
    if let Some(status) = child.wait_timeout(timeout)? {
        return Ok(status);
    }
    terminate_and_reap(child);
    bail!(
        "{display_name} timed out after {} seconds",
        timeout.as_secs()
    )
}

impl std::fmt::Debug for Process {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Process")
            .field("program", &self.display_name())
            .field("argument_count", &self.args.len())
            .field("environment_count", &self.environment.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

fn spawn_reader(
    reader: impl std::io::Read + Send + 'static,
    sender: SyncSender<anyhow::Result<Vec<u8>>>,
) {
    thread::spawn(move || {
        let _ = sender.send(read_bounded(reader));
    });
}

fn receive_reader(receiver: Receiver<anyhow::Result<Vec<u8>>>) -> anyhow::Result<Vec<u8>> {
    receiver
        .recv_timeout(OUTPUT_DRAIN_TIMEOUT)
        .map_err(|error| anyhow::anyhow!("child output drain exceeded bound: {error}"))?
}

fn drain_reader(receiver: Receiver<anyhow::Result<Vec<u8>>>) {
    let _ = receiver.recv_timeout(OUTPUT_DRAIN_TIMEOUT);
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let pid = child.id();
    terminate_process_tree(pid);
    child.kill().ok();
    if child
        .wait_timeout(OUTPUT_DRAIN_TIMEOUT)
        .ok()
        .flatten()
        .is_none()
    {
        // The caller must still return on the timeout boundary when the
        // platform process-tree primitive fails. A second group signal is
        // best-effort; reader draining remains independently bounded.
        terminate_process_tree(pid);
    }
}

/// Terminate descendants that may still hold stdout/stderr after the direct
/// child timed out. Unix process_group(0) establishes a fresh process group
/// before exec; rustix issues the native group signal without unsafe FFI in
/// this crate. Windows taskkill /T provides the equivalent process-tree
/// operation without introducing unsafe Job Object bindings.
fn terminate_process_tree(pid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pid)
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
}

fn test_environment_passthrough() -> bool {
    cfg!(debug_assertions) && std::env::var_os("NAZOAUTHCTL_TESTING").is_some()
}

pub fn command_exists(name: &str) -> bool {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let direct = directory.join(name);
        if direct.is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            for extension in ["exe", "cmd", "bat"] {
                if directory.join(format!("{name}.{extension}")).is_file() {
                    return true;
                }
            }
        }
        false
    })
}

#[cfg(all(test, unix))]
#[path = "../../../tests/unit/process.rs"]
mod tests;

#[cfg(all(test, unix))]
mod descendant_tests {
    use super::Process;
    use std::time::{Duration, Instant};

    #[test]
    fn timeout_terminates_descendant_holding_output_pipe() {
        let started = Instant::now();
        let error = Process::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .timeout(Duration::from_millis(25))
            .run_quiet()
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

#[cfg(test)]
mod process_tests {
    use super::Process;

    #[cfg(windows)]
    #[test]
    fn preserves_windows_ssh_configuration_roots() {
        for name in ["USERPROFILE", "ProgramData"] {
            let expected = std::env::var(name).expect("Windows SSH configuration root");
            let command = format!("echo %{name}%");
            let observed = Process::new("cmd")
                .args(["/D", "/C", &command])
                .stdout()
                .expect("read child environment");

            assert_eq!(observed.trim(), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn stdin_stdout_rejects_nonzero_exit_even_when_stdout_exists() {
        let error = Process::new("/bin/sh")
            .args(["-c", "printf ignored-output; exit 3"])
            .stdin_stdout(b"")
            .expect_err("nonzero one-shot exit must fail");
        assert!(error.to_string().contains("status"));
    }

    #[cfg(windows)]
    #[test]
    fn stdin_stdout_rejects_nonzero_exit_even_when_stdout_exists() {
        let error = Process::new("cmd")
            .args(["/C", "<nul set /p =ignored-output & exit /b 3"])
            .stdin_stdout(b"")
            .expect_err("nonzero one-shot exit must fail");
        assert!(error.to_string().contains("status"));
    }
}
