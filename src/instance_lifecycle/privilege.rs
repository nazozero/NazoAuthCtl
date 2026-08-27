//! Privilege sinking (goal plan 07, task G07; A04 §5 item 7).
//!
//! Root/sudo is required only at genuine privileged steps. The matrix below
//! is the single classification source:
//!
//! | step                     | elevated? | why                                  |
//! |--------------------------|-----------|--------------------------------------|
//! | registry reads           | no        | user-scoped store, caller permissions |
//! | deployment state reads   | no        | target state file, caller permissions |
//! | health probes            | no        | loopback HTTP, unprivileged          |
//! | engine socket access     | YES       | podman/docker socket ownership       |
//! | systemd unit management  | YES       | unit start/stop/install              |
//! | privileged port bind     | YES       | ports <1024 need CAP_NET_BIND_SERVICE |
//!
//! New lifecycle paths never gate whole commands: the check happens inside
//! the failing step, names the exact step, and prints the sudo/resume
//! instruction (G07 items 1/4/5). Nothing ever runs sudo automatically and
//! nothing ever stores a password (G07 prohibitions).

use anyhow::Context as _;

/// Stable failure code for every sunk privilege refusal.
///
/// Canonical name lives in [`crate::error_codes`]; re-exported here so the
/// historical call sites keep one stable path.
pub use crate::error_codes::PRIVILEGE_REQUIRED;

/// The closed set of steps whose privilege requirements this module owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivilegeStep {
    /// Reading the local instance/host registry.
    #[cfg(test)]
    RegistryRead,
    /// Reading one deployment's target-side DeploymentState.
    #[cfg(test)]
    DeploymentStateRead,
    /// Probing `{issuer}/readyz` on loopback.
    #[cfg(test)]
    HealthProbe,
    /// Talking to the container engine socket (podman/docker info or any
    /// engine mutation).
    EngineSocketAccess,
    /// Starting/stopping/installing systemd units.
    SystemdUnitManagement,
    /// Binding a privileged (<1024) host port.
    #[cfg(test)]
    PrivilegedPortBind,
}

impl PrivilegeStep {
    pub(crate) fn label(self) -> &'static str {
        match self {
            #[cfg(test)]
            Self::RegistryRead => "registry read",
            #[cfg(test)]
            Self::DeploymentStateRead => "deployment state read",
            #[cfg(test)]
            Self::HealthProbe => "local health probe",
            Self::EngineSocketAccess => "container engine socket access",
            Self::SystemdUnitManagement => "systemd unit management",
            #[cfg(test)]
            Self::PrivilegedPortBind => "privileged port bind",
        }
    }

    /// The matrix itself, pinned by the unit tests below. Everything not
    /// listed here is unprivileged by construction — adding a step means
    /// extending this match, never gating a command up front.
    #[cfg(test)]
    pub(crate) fn requires_elevation(self) -> bool {
        matches!(
            self,
            Self::EngineSocketAccess | Self::SystemdUnitManagement | Self::PrivilegedPortBind
        )
    }

    fn remedy(self) -> &'static str {
        match self {
            Self::EngineSocketAccess => {
                "run the operation as a user in the engine's socket group (e.g. `podman` or \
                 `docker`), or establish sudo once with `sudo -v` / configure NOPASSWD"
            }
            Self::SystemdUnitManagement => {
                "establish sudo once (`sudo -v` or NOPASSWD) so unit management can run"
            }
            #[cfg(test)]
            Self::PrivilegedPortBind => {
                "grant CAP_NET_BIND_SERVICE to the runtime or use an unprivileged port"
            }
            #[cfg(test)]
            _ => "no elevation is required for this step",
        }
    }
}

/// Require the target helper to be running as effective root immediately
/// before a systemd mutation. Remote transport may establish that identity;
/// the helper itself never prompts for or stores a password.
pub(crate) fn ensure_systemd_access() -> Result<(), PrivilegeError> {
    if !crate::process::command_exists("systemctl") {
        return Err(PrivilegeError {
            step: PrivilegeStep::SystemdUnitManagement,
            detail: "the 'systemctl' binary is not installed on this host".to_owned(),
        });
    }
    let is_root = crate::process::Process::new("id")
        .arg("-u")
        .stdout()
        .map(|uid| uid.trim() == "0")
        .unwrap_or(false);
    if is_root {
        Ok(())
    } else {
        Err(PrivilegeError {
            step: PrivilegeStep::SystemdUnitManagement,
            detail: "the target helper is not running with effective uid 0".to_owned(),
        })
    }
}

/// A failed privilege check: exact step plus the resume instruction. Rendered
/// through [`std::fmt::Display`] into stable-code diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrivilegeError {
    pub(crate) step: PrivilegeStep,
    pub(crate) detail: String,
}

impl PrivilegeError {
    pub(crate) fn code(&self) -> &'static str {
        PRIVILEGE_REQUIRED
    }
}

impl std::fmt::Display for PrivilegeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{PRIVILEGE_REQUIRED}: step '{}' requires elevated privileges ({}); {}; then \
             resume the same operation id — nazoauthctl never reads or stores passwords",
            self.step.label(),
            self.detail,
            self.step.remedy()
        )
    }
}

/// Injectable probe seam so tests classify failures without real engines.
pub(crate) trait PrivilegeProbe {
    /// One cheap, side-effect-free engine call (`<engine> info`). `Ok(true)`
    /// means the calling context may use the engine right now.
    fn engine_responsive(&self, engine: &str) -> anyhow::Result<bool>;
}

/// Production probe over the shared bounded process runner.
pub(crate) struct ProcessPrivilegeProbe;

impl PrivilegeProbe for ProcessPrivilegeProbe {
    fn engine_responsive(&self, engine: &str) -> anyhow::Result<bool> {
        Ok(crate::process::Process::new(engine)
            .arg("info")
            .run_quiet()
            .is_ok())
    }
}

/// G07 item 3/4: check the engine socket's ACTUAL permission right before a
/// step needs it. Never called for read-only flows.
pub(crate) fn ensure_engine_access(
    engine: &str,
    probe: &dyn PrivilegeProbe,
) -> Result<(), PrivilegeError> {
    if !crate::process::command_exists(engine) {
        return Err(PrivilegeError {
            step: PrivilegeStep::EngineSocketAccess,
            detail: format!("the '{engine}' binary is not installed on this host"),
        });
    }
    let responsive = probe
        .engine_responsive(engine)
        .with_context(|| format!("the '{engine}' privilege probe failed to spawn"))
        .map_err(|error| PrivilegeError {
            step: PrivilegeStep::EngineSocketAccess,
            detail: error.to_string(),
        })?;
    if responsive {
        return Ok(());
    }
    Err(PrivilegeError {
        step: PrivilegeStep::EngineSocketAccess,
        detail: format!(
            "the '{engine}' socket refused the unprivileged call (rootless engines work; \
             rootful sockets need group membership)"
        ),
    })
}
