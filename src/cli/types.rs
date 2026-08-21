use std::path::PathBuf;

use crate::adoption::AdoptionOptions;
use crate::deployment::{Capability, CapabilityGrant};

pub(crate) const DEFAULT_CONFIG: &str = "/etc/nazoauth/update.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelpTopic {
    TopLevel,
    Install,
    BootstrapAdmin,
    Update,
    Keys,
    Conformance,
    Tls,
    Audit,
    Identity,
    BreakGlass,
    Controller,
}

pub(crate) struct Cli {
    pub(crate) config: PathBuf,
    pub(crate) deployment: Option<String>,
    pub(crate) command: Command,
}

pub(crate) enum Command {
    Discover,
    Adopt(AdoptionOptions),
    DeploymentsList,
    TransactionShow,
    TransactionEvidence {
        file: PathBuf,
        yes: bool,
    },
    TransactionResume {
        yes: bool,
        accept_migration_barrier: bool,
    },
    PermissionsSet(PermissionOptions),
    Relinquish(RelinquishOptions),
    Reconcile,
    Install(Box<InstallOptions>),
    BootstrapAdmin(BootstrapAdminOptions),
    Status,
    Doctor,
    Check(Option<String>),
    Update(UpdateOptions),
    DevelopmentActivate(DevelopmentActivateOptions),
    Rollback {
        yes: bool,
    },
    Recover {
        yes: bool,
    },
    RecoverUpdate {
        yes: bool,
    },
    RecoverIdentity {
        yes: bool,
    },
    Migrate {
        yes: bool,
        candidate: Option<CandidateTarget>,
    },
    Keys(KeysCommand),
    Tls(TlsCommand),
    AuditVerify,
    AuditShow {
        request_id: Option<String>,
    },
    IdentityRotate {
        yes: bool,
    },
    BreakGlassControllerAvailability,
    BreakGlassRehearseControllerLoss {
        yes: bool,
    },
    BreakGlassRecover {
        yes: bool,
        reason: String,
    },
    SelfCheck(Option<String>),
    SelfUpdate {
        version: Option<String>,
        yes: bool,
    },
    SelfRollback {
        yes: bool,
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

#[derive(Debug)]
pub(crate) struct DevelopmentActivateOptions {
    pub(crate) artifact: String,
    pub(crate) yes: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PermissionOptions {
    pub(crate) changes: Vec<(Capability, CapabilityGrant)>,
    pub(crate) yes: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RelinquishOptions {
    pub(crate) capabilities: Vec<Capability>,
    pub(crate) yes: bool,
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
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LocalOciCandidateInstall {
    pub(crate) image: String,
    pub(crate) target: CandidateTarget,
}

#[derive(Debug)]
pub(crate) enum KeysCommand {
    List,
    Validate,
    ExportOpenid4vcTrust {
        output: PathBuf,
    },
    GenerateLocal {
        alg: String,
        purposes: Vec<String>,
        yes: bool,
    },
    RegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk: PathBuf,
        yes: bool,
    },
}

#[derive(Debug)]
pub(crate) struct UpdateOptions {
    pub(crate) version: Option<String>,
    pub(crate) plan: bool,
    pub(crate) yes: bool,
    pub(crate) accept_migration_barrier: bool,
}

pub(crate) struct InstallOptions {
    pub(crate) runtime: String,
    pub(crate) public_url: String,
    pub(crate) profile: String,
    pub(crate) profile_material: Option<PathBuf>,
    pub(crate) trusted_proxy_cidr: Option<String>,
    pub(crate) data_root: PathBuf,
    pub(crate) control_root: PathBuf,
    pub(crate) recovery_root: PathBuf,
    pub(crate) port: u16,
    pub(crate) network_subnet: Option<String>,
    pub(crate) runtime_ip: Option<String>,
    pub(crate) database_url: Option<String>,
    pub(crate) migration_database_url: Option<String>,
    pub(crate) database_backup_url: Option<String>,
    pub(crate) valkey_url: Option<String>,
    pub(crate) valkey_backup_url: Option<String>,
    pub(crate) external_valkey_backup_scope: Option<String>,
    pub(crate) external_dependencies: bool,
    pub(crate) secrets_stdin: bool,
    pub(crate) secret_fd: Option<u32>,
    pub(crate) profile_secrets_stdin: bool,
    pub(crate) profile_secret_fd: Option<u32>,
    pub(crate) profile_secrets: Option<StandardsProfileSecrets>,
    pub(crate) version: Option<String>,
    pub(crate) local_oci_candidate: Option<LocalOciCandidateInstall>,
}

impl Drop for InstallOptions {
    fn drop(&mut self) {
        for value in [
            &mut self.database_url,
            &mut self.migration_database_url,
            &mut self.database_backup_url,
            &mut self.valkey_url,
            &mut self.valkey_backup_url,
        ] {
            if let Some(value) = value.as_mut() {
                zeroize::Zeroize::zeroize(value);
            }
        }
    }
}

/// Profile-scoped bearer secrets. This deliberately has no `Debug` implementation,
/// and its owned values are zeroized on drop: command parsing and error paths must
/// never render its contents or retain avoidable plaintext copies.
#[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct StandardsProfileSecrets {
    pub(crate) dynamic_registration_initial_access_token: String,
    pub(crate) ciba_automated_decision_token: String,
    pub(crate) openid4vci_management_token: String,
    pub(crate) openid4vp_management_token: String,
}

#[derive(Debug)]
pub(crate) struct BootstrapAdminOptions {
    pub(crate) credentials_stdin: bool,
    pub(crate) yes: bool,
}
