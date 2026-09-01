//! Target-side execution of delivered ControlOperations (goal plan 05 §6,
//! task G-wave decision 1).
//!
//! A `control-operation` HostOperation makes the target invoke its LOCAL
//! NazoAuth one-shot operator inside the deployment's verified OCI artifact,
//! with the compact JWS on stdin and a
//! single-line durable [`ControlResult`] on stdout under a bounded timeout.
//! The target never parses, verifies, or authorizes the envelope: admission,
//! accept-once journaling, and execution stay entirely server-side.
//!
//! Classification contract (mirrors NazoAuth's own exit semantics):
//!
//! * parsable terminal/in-progress result ⇒ authoritative answer;
//! * the server's exact closed rejection marker ⇒ one stable ctl code;
//! * no parsable result ⇒ [`CONTROL_OUTCOME_UNKNOWN`] — the operation may or
//!   may not have been accepted, so the only safe retry is the resumed resend
//!   of the SAME envelope (server dedupes by id + request hash);
//! * engine/socket privilege problems surface before any run through the
//!   G07 sunk privilege checks.
//!
//! The executor is an injected seam like [`super::install_exec`]: production
//! uses [`HostControlOperator`], tests substitute scripted doubles so container
//! engines never spawn on development machines.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nazo_operator_protocol::ControlResult;

use super::deployment_state::Failure;
use super::wire::{HOST_ERR_OPERATION_INVALID, sanitize};

const CHANGE_SET_ENV: &str = "NAZOAUTH_OPERATOR_CHANGE_SET_FILE";
const CHANGE_SET_CREDENTIAL: &str = "operator-change-set";
const CONTAINER_CHANGE_SET_PATH: &str = "/run/nazoauth/operator-change-set";
const OPERATOR_REJECTION_PREFIX: &str = "nazoauth-operator-rejection=";
const ADMIN_PROVISION_REJECTION_PREFIX: &str = "nazoauth-admin-provision-rejection=";

/// The only fixed one-shot commands the target may launch. Keeping the
/// command choice closed here makes it impossible for a HostOperation field
/// to become a shell/argv injection point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedOneShotKind {
    ControlOperation,
    AdminProvision,
}

impl FixedOneShotKind {
    fn command(self) -> &'static [&'static str] {
        match self {
            Self::ControlOperation => &["nazoauth", "operator-task"],
            Self::AdminProvision => &["nazoauth", "admin-provision"],
        }
    }
}

/// Runtime facts captured from the target's live DeploymentState. This is
/// deliberately the shared input to both fixed one-shot operations.
pub(crate) struct FixedOneShotJob<'a> {
    pub(crate) deployment_id: &'a str,
    pub(crate) artifact_reference: &'a str,
    pub(crate) runtime_kind: crate::runtime_backend::RuntimeBackendKind,
    pub(crate) runtime_object: &'a str,
    pub(crate) config_reference: &'a str,
    pub(crate) data_root: &'a str,
    pub(crate) scope_dir: &'a Path,
}

/// The single secret input file for a fixed one-shot command. The name and
/// destination are constants owned by the caller; credential bytes never
/// appear in a command, environment value, journal result, or diagnostic.
pub(crate) struct FixedSecretFile<'a> {
    pub(crate) credential_name: &'static str,
    pub(crate) container_path: &'static str,
    pub(crate) environment_name: &'static str,
    pub(crate) bytes: &'a [u8],
}

struct StagedSecretFile {
    _directory: crate::filesystem::PrivateTempDir,
    path: PathBuf,
}

#[cfg(test)]
struct StagedChangeSet {
    _directory: crate::filesystem::PrivateTempDir,
    path: PathBuf,
}

fn stage_secret_file(file: &FixedSecretFile<'_>) -> anyhow::Result<StagedSecretFile> {
    let directory = crate::filesystem::PrivateTempDir::new("nazoauthctl-one-shot")?;
    let path = directory.path().join(file.credential_name);
    // The 0700 parent is the host-side privacy boundary. The file itself
    // is read-only so the non-root OCI task can read its direct bind mount.
    crate::filesystem::atomic_write(&path, file.bytes, 0o444)?;
    Ok(StagedSecretFile {
        _directory: directory,
        path,
    })
}

#[cfg(test)]
fn stage_change_set(bytes: &[u8]) -> anyhow::Result<StagedChangeSet> {
    let file = FixedSecretFile {
        credential_name: CHANGE_SET_CREDENTIAL,
        container_path: CONTAINER_CHANGE_SET_PATH,
        environment_name: CHANGE_SET_ENV,
        bytes,
    };
    let staged = stage_secret_file(&file)?;
    Ok(StagedChangeSet {
        path: staged.path,
        _directory: staged._directory,
    })
}

fn configure_secret_file_access(
    host: bool,
    path: &Path,
    file: &FixedSecretFile<'_>,
    environment: &mut BTreeMap<String, String>,
    transient_credentials: &mut BTreeMap<String, PathBuf>,
    mounts: &mut Vec<crate::runtime_backend::NeutralMount>,
) {
    if host {
        transient_credentials.insert(file.credential_name.to_owned(), path.to_owned());
        environment.insert(
            file.environment_name.to_owned(),
            format!("%d/{}", file.credential_name),
        );
    } else {
        mounts.push(crate::runtime_backend::NeutralMount {
            source: path.to_owned(),
            destination: PathBuf::from(file.container_path),
            read_only: true,
            selinux_relabel: false,
            ownership: crate::runtime_backend::Responsibility::Managed,
            scope: crate::runtime_backend::RuntimeResourceScope::Deployment,
        });
        environment.insert(
            file.environment_name.to_owned(),
            file.container_path.to_owned(),
        );
    }
}

#[cfg(test)]
fn configure_change_set_access(
    host: bool,
    path: &Path,
    environment: &mut BTreeMap<String, String>,
    transient_credentials: &mut BTreeMap<String, PathBuf>,
    mounts: &mut Vec<crate::runtime_backend::NeutralMount>,
) {
    let file = FixedSecretFile {
        credential_name: CHANGE_SET_CREDENTIAL,
        container_path: CONTAINER_CHANGE_SET_PATH,
        environment_name: CHANGE_SET_ENV,
        bytes: &[],
    };
    configure_secret_file_access(
        host,
        path,
        &file,
        environment,
        transient_credentials,
        mounts,
    );
}

/// Execute one closed-set NazoAuth one-shot command after proving the live
/// runtime object still serves the artifact recorded by DeploymentState.
/// ControlOperation and administrator provisioning share this exact runtime,
/// privilege, temporary-file, mount, and output plumbing.
pub(crate) fn execute_fixed_one_shot(
    job: &FixedOneShotJob<'_>,
    kind: FixedOneShotKind,
    mut environment: BTreeMap<String, String>,
    secret_file: Option<&FixedSecretFile<'_>>,
    stdin: Vec<u8>,
) -> Result<String, Failure> {
    let runtime_kind = job.runtime_kind;
    let backend = crate::runtime_backend::backend(runtime_kind);
    if runtime_kind.is_container() {
        if let Err(error) = crate::instance_lifecycle::privilege::ensure_engine_access(
            runtime_kind.as_str(),
            &crate::instance_lifecycle::privilege::ProcessPrivilegeProbe,
        ) {
            return Err(Failure::new(error.code(), sanitize(error.to_string())));
        }
    } else if let Err(error) = crate::instance_lifecycle::privilege::ensure_systemd_access() {
        return Err(Failure::new(error.code(), sanitize(error.to_string())));
    }
    let observation = backend
        .inspect(job.runtime_object)
        .map_err(|error| Failure::new(CONTROL_TARGET_DRIFT, sanitize(error.to_string())))?;
    let digest = super::update_exec::observation_digest(&observation).ok_or_else(|| {
        Failure::new(
            CONTROL_TARGET_DRIFT,
            "the running runtime object does not report a digest-bound artifact",
        )
    })?;
    let expected = job
        .artifact_reference
        .trim_start_matches("sha256:")
        .to_owned();
    if digest != expected {
        return Err(Failure::new(
            CONTROL_TARGET_DRIFT,
            format!(
                "runtime object '{}' serves {} while the deployment state records {}",
                job.runtime_object,
                sanitize(digest),
                sanitize(expected)
            ),
        ));
    }

    let staged = secret_file
        .map(|file| {
            stage_secret_file(file).map_err(|error| {
                Failure::new(CONTROL_EXECUTION_UNAVAILABLE, sanitize(error.to_string()))
            })
        })
        .transpose()?;
    let host = runtime_kind == crate::runtime_backend::RuntimeBackendKind::Host;
    let mut read_only_paths = Vec::new();
    let mut read_write_paths = Vec::new();
    let mut transient_credentials = BTreeMap::new();
    let mut mounts = observation.mounts.clone();
    if host {
        environment.insert(
            super::install_exec::SERVER_CONFIG_FILE_ENV.to_owned(),
            job.config_reference.to_owned(),
        );
        environment.insert(
            "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
            job.scope_dir
                .join("config-revision")
                .to_string_lossy()
                .into_owned(),
        );
        environment.insert(
            "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
            Path::new(job.data_root)
                .join("operator-state")
                .to_string_lossy()
                .into_owned(),
        );
        read_only_paths.push(PathBuf::from(job.config_reference));
        read_write_paths.push(PathBuf::from(job.data_root));
    } else if kind == FixedOneShotKind::ControlOperation {
        environment.insert(
            "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE".to_owned(),
            super::install_exec::CONTAINER_OPERATOR_CONFIG_REVISION_FILE.to_owned(),
        );
        environment.insert(
            "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
            format!("{}/operator-state", super::install_exec::CONTAINER_DATA_DIR),
        );
    }
    if let (Some(file), Some(staged)) = (secret_file, &staged) {
        configure_secret_file_access(
            host,
            &staged.path,
            file,
            &mut environment,
            &mut transient_credentials,
            &mut mounts,
        );
    }
    let task = crate::runtime_backend::OneShotTask {
        artifact: observation.artifact,
        command: kind
            .command()
            .iter()
            .map(|part| (*part).to_owned())
            .collect(),
        network: if host {
            Some("host".to_owned())
        } else {
            observation.networks.first().cloned()
        },
        mounts,
        environment,
        working_directory: if host {
            Some(PathBuf::from(job.data_root))
        } else {
            Some(PathBuf::from("/app"))
        },
        service_user: Some(if host {
            crate::runtime_backend::systemd_service_user(job.deployment_id)
        } else {
            crate::runtime_backend::NON_ROOT_ONE_SHOT_USER.to_owned()
        }),
        transient_credentials,
        read_only_paths,
        read_write_paths,
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin,
    };
    backend.run_one_shot(&task).map_err(|error| {
        let detail = error.to_string();
        let code = fixed_one_shot_rejection_code(kind, &detail).unwrap_or(CONTROL_OUTCOME_UNKNOWN);
        Failure::new(code, sanitize(detail))
    })
}

/// Stable failure code: the operator ran (or may have run) but produced no
/// parsable ControlResult. The outcome is unknown by construction; retries
/// must resume the same operation id instead of minting a new one.
pub const CONTROL_OUTCOME_UNKNOWN: &str = "CONTROL_OUTCOME_UNKNOWN";

/// Stable failure code: the local NazoAuth operator could not be invoked at
/// all (engine missing or unsupported runtime backend). No
/// envelope was presented to any authority.
pub const CONTROL_EXECUTION_UNAVAILABLE: &str = "CONTROL_EXECUTION_UNAVAILABLE";

/// Stable failure code: the running runtime object serves a different
/// artifact than the deployment state records. The operator is never invoked
/// against an object whose identity drifted.
pub const CONTROL_TARGET_DRIFT: &str = "CONTROL_TARGET_DRIFT";

/// Everything the executor needs besides the JWS itself. Built by dispatch
/// from live target facts; never serialized.
pub(crate) struct ControlJob<'a> {
    pub operation_id: &'a str,
    pub deployment_id: &'a str,
    /// The deployment's recorded current artifact reference (`sha256:<hex>`).
    pub artifact_reference: &'a str,
    pub runtime_kind: crate::runtime_backend::RuntimeBackendKind,
    pub runtime_object: &'a str,
    pub config_reference: &'a str,
    pub data_root: &'a str,
    pub secrets_root: &'a str,
    pub scope_dir: &'a Path,
    pub compact_jws: &'a str,
    pub change_set: Option<&'a [u8]>,
}

/// The injectable seam executing one delivered ControlOperation on the
/// target. Contract: on `Ok` the result is the operator's durable answer; on
/// `Err` nothing authoritative was learned.
pub(crate) trait ControlOperationExecutor: Send + Sync {
    fn execute(&self, job: &ControlJob<'_>) -> Result<ControlResult, Failure>;
}

/// Production executor backed by the runtime backends' one-shot machinery.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostControlOperator;

impl ControlOperationExecutor for HostControlOperator {
    fn execute(&self, job: &ControlJob<'_>) -> Result<ControlResult, Failure> {
        let secret_file = job.change_set.map(|bytes| FixedSecretFile {
            credential_name: CHANGE_SET_CREDENTIAL,
            container_path: CONTAINER_CHANGE_SET_PATH,
            environment_name: CHANGE_SET_ENV,
            bytes,
        });
        let fixed_job = FixedOneShotJob {
            deployment_id: job.deployment_id,
            artifact_reference: job.artifact_reference,
            runtime_kind: job.runtime_kind,
            runtime_object: job.runtime_object,
            config_reference: job.config_reference,
            data_root: job.data_root,
            scope_dir: job.scope_dir,
        };
        let mut environment = BTreeMap::new();
        environment.insert(
            super::install_exec::MIGRATION_RUNTIME_ROLE_ENV.to_owned(),
            super::update_exec::runtime_database_role(job.secrets_root)?,
        );
        environment.insert(
            "DATABASE_URL".to_owned(),
            super::update_exec::lifecycle_database_url(job.secrets_root)?,
        );
        let stdout = execute_fixed_one_shot(
            &fixed_job,
            FixedOneShotKind::ControlOperation,
            environment,
            secret_file.as_ref(),
            format!("{}\n", job.compact_jws).into_bytes(),
        )?;
        decode_operator_answer(&stdout, job.operation_id)
    }
}

fn operator_rejection_code(detail: &str) -> Option<&'static str> {
    let class = detail.lines().find_map(|line| {
        let line = line.trim();
        let marker = line.rsplit_once(": ").map_or(line, |(_, suffix)| suffix);
        marker.strip_prefix(OPERATOR_REJECTION_PREFIX)
    })?;
    match class {
        "request" => Some(crate::error_codes::INPUT_INVALID),
        "authorization" => Some(crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED),
        "deployment" => Some(crate::error_codes::TARGET_IDENTITY_MISMATCH),
        "revision" => Some(crate::error_codes::CONFIG_REVISION_MISMATCH),
        "conflict" => Some(crate::error_codes::OPERATION_ID_CONFLICT),
        // Transient pre-acceptance unavailability keeps the prepared operation
        // so an ordinary retry reuses the same id.
        "unavailable" => None,
        _ => None,
    }
}

fn fixed_one_shot_rejection_code(kind: FixedOneShotKind, detail: &str) -> Option<&'static str> {
    match kind {
        FixedOneShotKind::ControlOperation => operator_rejection_code(detail),
        FixedOneShotKind::AdminProvision => admin_provision_rejection_code(detail),
    }
}

fn admin_provision_rejection_code(detail: &str) -> Option<&'static str> {
    detail.lines().map(str::trim).find_map(|line| {
        let marker = line.rsplit_once(": ").map_or(line, |(_, suffix)| suffix);
        match marker.strip_prefix(ADMIN_PROVISION_REJECTION_PREFIX)? {
            "input" => Some(crate::error_codes::INPUT_INVALID),
            "email-conflict" => Some(crate::error_codes::ADMIN_EMAIL_CONFLICT),
            "operation-conflict" => Some(crate::error_codes::OPERATION_ID_CONFLICT),
            _ => None,
        }
    })
}

/// Decode the operator's single-line answer and pin it to the presented
/// operation id. Empty or unparsable output means the outcome is unknown —
/// never a refusal.
pub(crate) fn decode_operator_answer(
    stdout: &str,
    operation_id: &str,
) -> Result<ControlResult, Failure> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Failure::new(
            CONTROL_OUTCOME_UNKNOWN,
            "the local NazoAuth operator produced no ControlResult; the outcome is unknown and \
             only a resumed resend of the same operation can resolve it",
        ));
    }
    let mut frames = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let line = frames.next().unwrap_or(trimmed);
    if frames.next().is_some() {
        return Err(Failure::new(
            CONTROL_OUTCOME_UNKNOWN,
            "the local NazoAuth operator emitted more than one non-empty ControlResult frame; the outcome is unknown",
        ));
    }
    let result =
        nazo_operator_protocol::decode_control_result(line.as_bytes()).map_err(|error| {
            Failure::new(
                CONTROL_OUTCOME_UNKNOWN,
                format!(
                    "the operator answer did not parse as a ControlResult ({}); the outcome is \
                     unknown",
                    sanitize(error.to_string())
                ),
            )
        })?;
    if result.operation_id != operation_id {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            format!(
                "the operator answered operation '{}' while '{}' was presented",
                sanitize(result.operation_id.clone()),
                sanitize(operation_id.to_owned())
            ),
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    use super::{
        CHANGE_SET_CREDENTIAL, CHANGE_SET_ENV, CONTAINER_CHANGE_SET_PATH, FixedOneShotKind,
        admin_provision_rejection_code, configure_change_set_access, fixed_one_shot_rejection_code,
        operator_rejection_code, stage_change_set,
    };

    #[test]
    fn staged_change_set_is_exact_and_removed_on_scope_exit() -> anyhow::Result<()> {
        let staged = stage_change_set(b"exact change-set bytes")?;
        let path = staged.path.clone();
        assert_eq!(std::fs::read(&path)?, b"exact change-set bytes");
        drop(staged);
        assert!(
            !path.exists(),
            "private material must be removed after execution"
        );
        Ok(())
    }

    #[test]
    fn change_set_access_is_read_only_and_backend_specific() {
        let source = Path::new("/private/change-set");

        let mut environment = BTreeMap::new();
        let mut credentials = BTreeMap::new();
        let mut mounts = Vec::new();
        configure_change_set_access(
            false,
            source,
            &mut environment,
            &mut credentials,
            &mut mounts,
        );
        assert_eq!(
            environment.get(CHANGE_SET_ENV).map(String::as_str),
            Some(CONTAINER_CHANGE_SET_PATH)
        );
        assert!(credentials.is_empty());
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].source, source);
        assert_eq!(mounts[0].destination, Path::new(CONTAINER_CHANGE_SET_PATH));
        assert!(mounts[0].read_only);

        environment.clear();
        mounts.clear();
        configure_change_set_access(
            true,
            source,
            &mut environment,
            &mut credentials,
            &mut mounts,
        );
        assert_eq!(
            environment.get(CHANGE_SET_ENV).map(String::as_str),
            Some("%d/operator-change-set")
        );
        assert_eq!(
            credentials.get(CHANGE_SET_CREDENTIAL).map(PathBuf::as_path),
            Some(source)
        );
        assert!(mounts.is_empty());
    }

    #[test]
    fn exact_server_rejection_classes_map_once() {
        assert_eq!(
            operator_rejection_code(
                "nazoauth failed with status 1: nazoauth-operator-rejection=authorization"
            ),
            Some(crate::error_codes::CONTROLLER_KEY_UNAUTHORIZED)
        );
        assert_eq!(
            operator_rejection_code("wrapper failed:\nnazoauth-operator-rejection=revision"),
            Some(crate::error_codes::CONFIG_REVISION_MISMATCH)
        );
        assert_eq!(
            operator_rejection_code(
                "nazoauth failed: prefix-nazoauth-operator-rejection=authorization"
            ),
            None
        );
        assert_eq!(
            operator_rejection_code("nazoauth-operator-rejection=unavailable"),
            None
        );
    }

    #[test]
    fn admin_rejection_markers_are_closed_and_kind_specific() {
        assert_eq!(
            admin_provision_rejection_code("nazoauth-admin-provision-rejection=input"),
            Some(crate::error_codes::INPUT_INVALID)
        );
        assert_eq!(
            admin_provision_rejection_code(
                "nazoauth failed with status 1: nazoauth-admin-provision-rejection=email-conflict",
            ),
            Some(crate::error_codes::ADMIN_EMAIL_CONFLICT)
        );
        assert_eq!(
            fixed_one_shot_rejection_code(
                FixedOneShotKind::AdminProvision,
                "nazoauth-admin-provision-rejection=operation-conflict",
            ),
            Some(crate::error_codes::OPERATION_ID_CONFLICT)
        );
        assert_eq!(
            fixed_one_shot_rejection_code(
                FixedOneShotKind::ControlOperation,
                "nazoauth-admin-provision-rejection=input",
            ),
            None
        );
        assert_eq!(
            fixed_one_shot_rejection_code(
                FixedOneShotKind::AdminProvision,
                "nazoauth-operator-rejection=authorization",
            ),
            None
        );
        assert_eq!(admin_provision_rejection_code("database hash failed"), None);
    }
}
