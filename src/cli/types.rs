//! Command-line model for the final command surface (goal plan 09 §1, I01).
//!
//! The parser can only ever produce the commands in [`Command`] plus the
//! small set of maintenance commands that the final model itself requires
//! (`remote exec` transport boundary, controller self-updates, and the TLS
//! certificate-provider family).

use std::path::PathBuf;

use anyhow::{Context as _, bail};

use crate::registry::HostPrivilege;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelpTopic {
    TopLevel,
    Host,
    Instance,
    Controller,
    Install,
    Update,
    Tls,
    SelfUpdate,
    Admin,
}

/// Global options shared by every invocation (I02). `--instance` is accepted
/// before the command; instance-scoped families additionally accept a
/// command-level selector channel, and the two are merged with an
/// exactly-one rule.
#[derive(Debug)]
pub(crate) struct Cli {
    /// Explicit instance selector from the global `--instance` flag.
    pub(crate) instance: Option<String>,
    /// Machine-readable output switch (`--json`), read-only view commands.
    pub(crate) json: bool,
    pub(crate) command: Command,
}

/// The complete user-facing top-level surface (goal plan 09 §1):
///
/// ```text
/// host instance controller install discover bind status logs doctor verify
/// update rollback operation backup oidf uninstall
/// ```
///
/// `oidf` is parsed by the binary entrypoint (`crates/nazoauthctl`) before
/// this library parser runs, so it has no variant here. `RemoteExec`,
/// `SelfCheck`, `SelfUpdate`, and `SelfRollback` are part of the final model's
/// own machinery, not legacy surface.
// Install carries the complete one-shot external dependency fact set. Command
// values are parsed once and immediately consumed; boxing this sole large
// variant would add allocation and indirection without reducing retained state.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Command {
    /// Fleet host registry (add/list/show/check/forget).
    Host(HostCommand),
    /// Fleet instance registry (list/show/register/rename/forget/relocate).
    Instance(InstanceCommand),
    /// Per-instance Controller Key lifecycle: list/add/rotate/revoke/recover.
    Controller(ControllerCommand),
    /// Initial Controller Key enrollment for one instance (top-level form of
    /// the first `controller add`-shaped slot change; goal plan 09 §6).
    Bind(BindOptions),
    /// Clean install of a fresh NazoAuth instance onto one host (G01).
    Install(InstallArgs),
    /// Read-only DeploymentState sweep over one target host (G05).
    Discover {
        host: Option<String>,
    },
    /// Instance state summary; `--all` fans out over the whole fleet (I03).
    Status {
        selector: InstanceSelector,
        all: bool,
    },
    /// Bounded, redacted application log tail for one instance.
    Logs {
        selector: InstanceSelector,
        limit: usize,
    },
    /// Health/security diagnostics; `--all` fans out over the fleet.
    Doctor {
        selector: InstanceSelector,
        all: bool,
    },
    /// Independent public DNS/TLS/OIDC verification report (G08).
    Verify {
        selector: InstanceSelector,
    },
    /// Crash-safe update to a verified official artifact (G03).
    Update(UpdateArgs),
    /// Explicit rollback to the previous verified artifact (G04).
    Rollback {
        selector: InstanceSelector,
    },
    /// Read-only operation-log view over the two journals (H04).
    Operation {
        selector: InstanceSelector,
        limit: usize,
    },
    /// Backup maturity facts observed from the deployment (H05).
    Backup(BackupArgs),
    /// Configure the one explicit backup-before-update gate for one instance.
    Policy(PolicyArgs),
    /// Restore is intentionally separate from rollback.  The current surface
    /// only permits a recorded recovery transaction once server-side token
    /// invalidation authority is available.
    Recover(RecoverArgs),
    /// Exact deletion of managed + deployment-scoped resources (G06).
    Uninstall {
        selector: InstanceSelector,
        yes: bool,
    },
    /// Create an administrator through the target deployment root.
    Admin(AdminCommand),
    /// Deployment-owned TLS certificate material via the external
    /// file-provider contract (`tls certificate|acme ...`).
    Tls(TlsCommand),
    /// Internal fixed stdio executor (`nazoauthctl remote exec`, goal plan 03
    /// §3.2): one bounded HostOperation JSON on stdin, one HostResult JSON on
    /// stdout, no daemon. Invoked only through OpenSSH by the control side.
    RemoteExec,
    /// Controller self-maintenance: signed NazoAuthCtl releases only.
    SelfCheck(Option<String>),
    SelfUpdate {
        version: Option<String>,
    },
    SelfRollback,
}

/// Deployment-root administrator management. The current surface exposes one
/// operation: creating an administrator through the fixed target provisioner.
#[derive(Debug)]
pub(crate) enum AdminCommand {
    Create(AdminCreateArgs),
}

/// `controller` family (goal plan 09 §1): everything runs against the
/// user-scoped Registry and per-instance key store; the only network peer is
/// the instance issuer's admin surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControllerCommand {
    /// Authoritative slots view (the D09 read-only surface).
    List { selector: InstanceSelector },
    Add {
        selector: InstanceSelector,
        label: String,
        approval_token: Option<String>,
        admin_access_file: Option<PathBuf>,
    },
    Rotate {
        selector: InstanceSelector,
        label: Option<String>,
        approval_token: Option<String>,
        admin_access_file: Option<PathBuf>,
    },
    Revoke {
        selector: InstanceSelector,
        controller_id: String,
        approval_token: Option<String>,
        admin_access_file: Option<PathBuf>,
    },
    /// Recovery-Secret flows: default recovers the Controller Identity from
    /// the offline secret (D11); `--rotate-secret` issues a replacement
    /// secret under fresh 2FA (D10/D12).
    Recover {
        selector: InstanceSelector,
        label: String,
        secret_file: Option<PathBuf>,
        rotate_secret: bool,
        admin_access_file: Option<PathBuf>,
        /// Delivery channel for the REPLACEMENT Recovery Secret. The secret
        /// is delivered BEFORE the irreversible commit; interactive runs
        /// confirm on the terminal, non-TTY runs must name a create-new,
        /// owner-only output file.
        output_secret_file: Option<PathBuf>,
    },
}

/// Options shared by `bind` (and shaped identically by `controller add`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindOptions {
    pub(crate) selector: InstanceSelector,
    pub(crate) label: String,
    pub(crate) approval_token: Option<String>,
    pub(crate) admin_access_file: Option<PathBuf>,
    /// P0-3/P0-4 delivery channel for the Recovery Root minted with the
    /// first binding; interactive runs confirm on the terminal instead.
    pub(crate) output_secret_file: Option<PathBuf>,
}

/// `host` command family (task B03). All of it operates on the user-scoped
/// Registry; only `add` and `check` contact the target, and `forget` never
/// reaches a remote host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostCommand {
    Add {
        alias: String,
        ssh_profile: String,
        privilege: HostPrivilege,
    },
    List {
        refresh: bool,
    },
    Show {
        alias: String,
    },
    Check {
        alias: String,
    },
    Forget {
        alias: String,
        cascade: bool,
    },
}

/// The two selector channels shared by the instance-scoped subcommands
/// (task B05): the positional argument and the explicit per-command
/// `--instance` flag. The command layer merges them with the global
/// `--instance`; supplying more than one source is rejected so the effective
/// selector is never ambiguous.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InstanceSelector {
    pub(crate) positional: Option<String>,
    pub(crate) named: Option<String>,
}

impl InstanceSelector {
    /// Merge the positional and per-command channels. Both set — even to the
    /// same value — is rejected: one action carries at most one explicit
    /// selection channel.
    pub(crate) fn explicit(&self) -> anyhow::Result<Option<String>> {
        match (&self.positional, &self.named) {
            (Some(_), Some(_)) => {
                bail!(
                    "select the instance with either --instance or the positional selector, not both"
                )
            }
            (Some(value), None) | (None, Some(value)) => Ok(Some(value.clone())),
            (None, None) => Ok(None),
        }
    }

    /// Fold the global `--instance` into this selector under the I02
    /// exactly-one rule: the global channel and any command-level channel are
    /// mutually exclusive, whatever their values.
    pub(crate) fn merge_global(
        &self,
        global: Option<&str>,
        action: &str,
    ) -> anyhow::Result<Option<String>> {
        let local = self
            .explicit()
            .with_context(|| format!("{action}: conflicting selectors"))?;
        match (global, local) {
            (Some(global_value), Some(local_value)) => bail!(
                "{action}: select the instance once — either the global \
                 --instance {global_value} or the command-level selector \
                 '{local_value}', not both"
            ),
            (Some(global_value), None) => Ok(Some(global_value.to_owned())),
            (None, local) => Ok(local),
        }
    }
}

/// `instance` command family (tasks B04–B07 + G05 takeover).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InstanceCommand {
    List {
        refresh: bool,
    },
    Show(InstanceSelector),
    /// Controlled takeover of one live-discovered deployment (G05): the
    /// deployment binding comes from the target's own DeploymentState over a
    /// verified handshake; nothing else binds.
    Register {
        host: String,
        deployment_id: String,
        alias: Option<String>,
    },
    Rename {
        source: InstanceSelector,
        new_alias: String,
    },
    Forget(InstanceSelector),
    Relocate {
        selector: InstanceSelector,
        to_host: String,
    },
}

/// Clean-install arguments (G01); maps onto
/// [`crate::clean_install::CleanInstallRequest`].
#[derive(Debug)]
pub(crate) struct InstallArgs {
    pub(crate) host: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) public_url: String,
    pub(crate) version: Option<String>,
    pub(crate) runtime: Option<crate::runtime_backend::RuntimeBackendKind>,
    pub(crate) install_root: Option<PathBuf>,
    pub(crate) database_host: String,
    pub(crate) database_port: u16,
    pub(crate) database_name: String,
    pub(crate) database_runtime_user: String,
    pub(crate) database_runtime_password_file: PathBuf,
    pub(crate) database_lifecycle_user: String,
    pub(crate) database_lifecycle_password_file: PathBuf,
    pub(crate) valkey_host: String,
    pub(crate) valkey_port: u16,
    pub(crate) valkey_password_file: PathBuf,
    /// Optional target-local current-format material. These paths are sent as
    /// path facts only; no imported bytes cross the control transport.
    pub(crate) import_data_root: Option<PathBuf>,
    pub(crate) import_mfa_key_file: Option<PathBuf>,
}

/// Update arguments (G03); maps onto
/// [`crate::instance_lifecycle::UpdateRequest`].
#[derive(Debug)]
pub(crate) struct UpdateArgs {
    pub(crate) selector: InstanceSelector,
    pub(crate) version: Option<String>,
    pub(crate) config_file: Option<PathBuf>,
    pub(crate) config_schema: Option<String>,
}

/// Backup maturity display arguments (H05).
#[derive(Debug)]
pub(crate) struct BackupArgs {
    pub(crate) selector: InstanceSelector,
    pub(crate) command: BackupCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BackupCommand {
    Show,
    Snapshot,
    RestoreTest,
    Copy { to_host: String },
}

#[derive(Debug)]
pub(crate) struct PolicyArgs {
    pub(crate) selector: InstanceSelector,
    pub(crate) mode: crate::registry::BackupBeforeUpdatePolicy,
}

#[derive(Debug)]
pub(crate) struct RecoverArgs {
    pub(crate) selector: InstanceSelector,
    /// Optional owner-only file containing the offline Recovery Secret.  It
    /// is read only if the restored registry rejects the current controller
    /// identity; the value is never an argv token or target payload.
    pub(crate) recovery_secret_file: Option<std::path::PathBuf>,
}

/// Administrator creation arguments. Credentials are read after parsing and
/// are never represented in this command value.
#[derive(Debug)]
pub(crate) struct AdminCreateArgs {
    pub(crate) selector: InstanceSelector,
    pub(crate) credentials_stdin: bool,
}

/// TLS certificate-provider family (surviving provider contract, J wave):
/// the inputs are file paths plus tenant/hostname bindings; no secret ever
/// travels through argv.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsCertificateInput {
    pub(crate) provider_config: PathBuf,
    pub(crate) tenant: String,
    pub(crate) hostname: String,
    pub(crate) source: TlsCertificateSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TlsCertificateSource {
    ExternalFiles {
        certificate: PathBuf,
        private_key: PathBuf,
    },
    CurrentAcmeReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsCertificateCheckInput {
    pub(crate) provider_config: PathBuf,
    pub(crate) tenant: String,
    pub(crate) hostname: String,
    pub(crate) warning_window_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcmeCertificateInput {
    pub(crate) acme_config: PathBuf,
    pub(crate) provider_config: PathBuf,
    pub(crate) tenant: String,
    pub(crate) hostname: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcmeCommand {
    Plan(AcmeCertificateInput),
    Issue {
        input: AcmeCertificateInput,
        agree_terms: bool,
    },
    Recover {
        tenant: String,
        hostname: String,
    },
    Show {
        tenant: String,
        hostname: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TlsCommand {
    Check(TlsCertificateCheckInput),
    Plan(TlsCertificateInput),
    Apply(TlsCertificateInput),
    Recover { tenant: String, hostname: String },
    Show { tenant: String, hostname: String },
    Acme(AcmeCommand),
}
