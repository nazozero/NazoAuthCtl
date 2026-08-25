//! Frozen pre-goal CLI command set (goal plan A04/J).
//!
//! The I wave replaced the argv surface with the final 18-command model
//! (`cli::types`). Nothing in this module is constructible from argv any
//! more; it exists only so the legacy handler bodies keep compiling until
//! the J-phase deletion pass removes them together with their dispatch.
//! Do not add anything here, and do not route new commands through it.

#![allow(dead_code)]
use std::path::PathBuf;

pub(crate) struct Cli {
    pub(crate) config: PathBuf,
    pub(crate) deployment: Option<String>,
    pub(crate) command: Command,
}

pub(crate) enum Command {
    DeploymentsList,
    BootstrapAdmin(BootstrapAdminOptions),
    Status,
    Doctor,
    Tls(TlsCommand),
    SelfCheck(Option<String>),
    SelfUpdate {
        version: Option<String>,
        yes: bool,
    },
    SelfRollback {
        yes: bool,
    },
    /// Internal fixed stdio executor (`nazoauthctl remote exec`, goal plan 03
    /// §3.2). Not user-facing automation surface: one bounded HostOperation
    /// JSON on stdin, one HostResult JSON on stdout, no daemon, no socket.
    RemoteExec,
    /// Fleet host registry commands (goal plan 02, tasks B03/B06/B07).
    Host(HostCommand),
    /// Fleet instance registry commands (goal plan 02, tasks B04–B07).
    Instance(InstanceCommand),
    /// Controller identity lifecycle commands (goal plan 04, tasks D04–D09):
    /// bind/add/rotate/revoke against the instance Controller Registry plus
    /// the authoritative slots view.
    Controller(ControllerCommand),
}

/// `controller` command family (tasks D04–D09). Everything runs against the
/// user-scoped Registry and per-instance key store; the only network peer is
/// the instance issuer's admin surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControllerCommand {
    Bind {
        selector: InstanceSelector,
        label: String,
        approval_token: Option<String>,
        admin_access_file: Option<PathBuf>,
    },
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
        yes: bool,
        approval_token: Option<String>,
        admin_access_file: Option<PathBuf>,
    },
    Slots {
        selector: InstanceSelector,
        admin_access_file: Option<PathBuf>,
    },
}

/// `host` family: the frozen runner shares the FINAL types — they are
/// structurally identical and `fleet::run_host` is unchanged.
pub(crate) use super::types::{HostCommand, InstanceSelector};

/// Frozen `instance` family subset. The interim evidence-file registration
/// variants were superseded by G05 takeover and removed with the I wave.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InstanceCommand {
    List {
        refresh: bool,
    },
    Show(InstanceSelector),
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
        yes: bool,
    },
    Recover {
        tenant: String,
        hostname: String,
        yes: bool,
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
    Apply {
        input: TlsCertificateInput,
        yes: bool,
    },
    Recover {
        tenant: String,
        hostname: String,
        yes: bool,
    },
    Show {
        tenant: String,
        hostname: String,
    },
    Acme(AcmeCommand),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct CandidateTarget {
    pub(crate) release: String,
    pub(crate) revision: String,
    pub(crate) build_id: String,
    pub(crate) oci_digest: String,
}

/// A deliberately local-only OCI target for a fresh standards installation.
///
/// This is not an unsigned replacement for `update` or `development activate`:
/// the caller supplies the release identity and the expected OCI manifest digest,
/// and install proves them against an image that is already present in the
/// selected container runtime.  No registry resolution or pull is performed.
///
/// The installer entry was removed with the J-A wave; the type survives as the
/// persisted provenance shape that the completed-candidate guards validate.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LocalOciCandidateInstall {
    pub(crate) image: String,
    pub(crate) target: CandidateTarget,
}

#[derive(Debug)]
pub(crate) struct BootstrapAdminOptions {
    pub(crate) credentials_stdin: bool,
    pub(crate) yes: bool,
}
