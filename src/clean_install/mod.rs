//! Clean install: the shortest supported deployment path (goal plan 07 §1-§3,
//! tasks G01/G02/G08).
//!
//! One command resolves the host, builds a single typed HostOperation, lets
//! the target execute and journal the whole fresh install, commits the target
//! DeploymentState as `local healthy / control unbound / public unknown`, and
//! writes the InstanceRecord through the B04 register evidence path. No
//! recovery device, provider evidence, rehearsal, backup, or public gate
//! exists anywhere on this path (goal plan 00 rule 16).
//!
//! Module map:
//!
//! * [`initial_admin`] — G02: the closed fresh-install bootstrap authority on
//!   the control side: claim flow, closure, rejection semantics.
//! * [`public_verify`] — G08: the explicit, separate public verification
//!   report. It consumes no lifecycle state and can never roll one back.
//!
//! The use case is transport-agnostic by construction: it speaks only to an
//! [`ExecutionTarget`], so local and SSH installs share this exact code and
//! this exact test suite.

mod initial_admin;
mod install_journal;
mod public_verify;

// CLI-surface re-exports (I wave): the dispatcher consumes these without the
// private module paths.
pub(crate) use initial_admin::{
    AdminCredentials, CurlInitialAdminTransport, LocalBootstrapMaterial, RemoteBootstrapMaterial,
    claim_initial_admin,
};
pub(crate) use public_verify::{CurlPublicProber, verify_public};

use anyhow::{Context as _, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::error_codes::REMOTE_HELPER_MISMATCH;
use crate::fleet::{live_probe, production_target, resolve_host_selector, summarize_inspection};
use crate::registry::{
    DiscoveryEvidence, ObservationCache, RegistryStore, validate_issuer,
    validate_registry_key as validate_key,
};
use crate::runtime_backend::RuntimeBackendKind;
use crate::target::{
    DEPLOYMENT_UNKNOWN, ExecutionTarget, HostCompletionBody, HostOperation, HostOutcome,
    HostResult, InstallOrder, OfficialArtifactRef, PlannedSecret, Resource, ResourceOwnership,
    ResourceScope, RuntimeSurface, SecretMaterial, StateMutationPayload,
};

/// Official server release repository pinned for clean installs.
pub(crate) const SERVER_REPOSITORY: &str = "nazozero/NazoAuth";

/// Default listen port; the only port default that is safe to infer.
pub(crate) const DEFAULT_PORT: u16 = 8000;

/// Config schema token recorded in the DeploymentState for seed documents.
pub(crate) const CONFIG_SCHEMA_SEED: &str = "nazauth-seed-v2";

/// One clean-install invocation. Defaults are deliberately minimal: only the
/// issuer is mandatory because it is a real external fact that cannot be
/// safely inferred. Everything else — deployment id, runtime names, secret
/// files, paths, port — is generated.
pub(crate) struct CleanInstallRequest {
    /// Optional exact host alias. Absent means "the only registered host",
    /// with the built-in local host auto-created on first use.
    pub(crate) host: Option<String>,
    pub(crate) instance_alias: Option<String>,
    /// Public issuer origin (`--public-url`). The one required external fact.
    pub(crate) issuer: String,
    /// Optional immutable official Release tag pin.
    pub(crate) version: Option<String>,
    /// Optional subject-digest pin closing the resolve/fetch gap.
    pub(crate) expected_artifact_sha256: Option<String>,
    /// Optional runtime class override (`podman` | `docker` | `host`).
    pub(crate) runtime: Option<RuntimeBackendKind>,
    /// Optional custom installation root. Absent resolves to the platform
    /// defaults; set, every managed path derives from it.
    pub(crate) install_root: Option<std::path::PathBuf>,
    /// External PostgreSQL endpoint (host, port, database, role).
    pub(crate) database_runtime_endpoint: crate::target::install_exec::ExternalEndpoint,
    pub(crate) database_lifecycle_endpoint: crate::target::install_exec::ExternalEndpoint,
    /// External Valkey endpoint (host, port).
    pub(crate) valkey_endpoint: crate::target::install_exec::ExternalEndpoint,
    /// P0-1: the ALREADY-KNOWN external credentials. The PostgreSQL role and
    /// Valkey ACL predate this install; ctl never invents passwords those
    /// systems do not accept.
    pub(crate) database_runtime_password: Option<SecretMaterial>,
    pub(crate) database_lifecycle_password: Option<SecretMaterial>,
    pub(crate) valkey_password: Option<SecretMaterial>,
    pub(crate) import_data_root: Option<std::path::PathBuf>,
    pub(crate) import_mfa_key_file: Option<std::path::PathBuf>,
}

/// Injectable context mirroring the fleet command context: the user-scoped
/// registry plus a way to reach hosts. Tests substitute scripted targets.
pub(crate) type TargetFactory =
    dyn Fn(&crate::registry::HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>>;

pub(crate) struct CleanInstallContext {
    pub(crate) registry: RegistryStore,
    pub(crate) factory: Box<TargetFactory>,
}

impl CleanInstallContext {
    pub(crate) fn production() -> anyhow::Result<Self> {
        Ok(Self {
            registry: RegistryStore::open_default()?,
            factory: Box::new(production_target),
        })
    }

    fn target_for(
        &self,
        record: &crate::registry::HostRecord,
    ) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
        (self.factory)(record)
    }
}

/// Absolute paths rendered into the install order. They remain strings on the
/// control side so a Windows controller never applies Windows `PathBuf`
/// semantics to a Linux target (or the inverse).
pub(crate) struct InstallPaths {
    pub(crate) data_root: String,
    pub(crate) config_reference: String,
    pub(crate) secrets_dir: String,
    pub(crate) runtime_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetOs {
    Linux,
    Windows,
}

impl TargetOs {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            _ => bail!(
                "clean install supports only target os 'linux' and 'windows'; helper announced '{value}'"
            ),
        }
    }

    fn join(self, root: &str, components: &[&str]) -> anyhow::Result<String> {
        validate_target_root(self, root)?;
        if components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.contains(['/', '\\'])
                || component.chars().any(char::is_control)
        }) {
            bail!("target install path contains an invalid component");
        }
        let separator = match self {
            Self::Linux => '/',
            Self::Windows => '\\',
        };
        let mut value = root.trim_end_matches(separator).to_owned();
        for component in components {
            value.push(separator);
            value.push_str(component);
        }
        Ok(value)
    }
}

fn validate_target_root(target_os: TargetOs, root: &str) -> anyhow::Result<()> {
    if root.is_empty() || root.contains('"') || root.chars().any(char::is_control) {
        bail!("--install-root must be a non-empty target path");
    }
    match target_os {
        TargetOs::Linux => {
            if !root.starts_with('/') || root.contains('\\') {
                bail!("--install-root must be an absolute POSIX path for a Linux target");
            }
            if root != "/" && (root.starts_with("//") || root.ends_with('/')) {
                bail!("--install-root must be a normalized absolute POSIX path");
            }
            let tail = root.trim_start_matches('/');
            if !tail.is_empty()
                && tail
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                bail!("--install-root must be a normalized absolute POSIX path");
            }
        }
        TargetOs::Windows => {
            let bytes = root.as_bytes();
            let tail_start = if bytes.len() >= 7
                && &bytes[..4] == b"\\\\?\\"
                && bytes[4].is_ascii_alphabetic()
                && bytes[5] == b':'
                && bytes[6] == b'\\'
            {
                7
            } else if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
            {
                3
            } else {
                bail!("--install-root must be an absolute drive path for a Windows target");
            };
            if root.contains('/') {
                bail!("--install-root must be an absolute drive path for a Windows target");
            }
            let tail = &root[tail_start..];
            if !tail.is_empty()
                && tail
                    .split('\\')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                bail!("--install-root must be a normalized absolute Windows drive path");
            }
        }
    }
    Ok(())
}

pub(crate) fn default_install_paths(
    target_os: &str,
    deployment_id: &str,
) -> anyhow::Result<InstallPaths> {
    match TargetOs::parse(target_os)? {
        TargetOs::Linux => Ok(InstallPaths {
            data_root: format!("/var/lib/nazauth/deployments/{deployment_id}"),
            config_reference: format!("/etc/nazoauth/deployments/{deployment_id}/config.json"),
            secrets_dir: format!("/var/lib/nazauth/secrets/{deployment_id}"),
            runtime_root: format!("/usr/local/lib/nazauth/{deployment_id}"),
        }),
        TargetOs::Windows => Ok(InstallPaths {
            data_root: format!(r"C:\ProgramData\nazoauth\data\{deployment_id}"),
            config_reference: format!(
                r"C:\ProgramData\nazoauth\config\{deployment_id}\config.json"
            ),
            secrets_dir: format!(r"C:\ProgramData\nazoauth\secrets\{deployment_id}"),
            runtime_root: format!(r"C:\ProgramData\nazoauth\runtime\{deployment_id}"),
        }),
    }
}

/// Path resolution for one install: the custom root when provided (also the
/// test seam that keeps development machines off system paths), platform
/// defaults otherwise. Every path is scoped under the deployment id so two
/// instances on one host can never share data, secrets, or config (P0-3).
fn resolve_paths(
    request: &CleanInstallRequest,
    target_os: &str,
    deployment_id: &str,
) -> anyhow::Result<InstallPaths> {
    let target_os = TargetOs::parse(target_os)?;
    match &request.install_root {
        Some(root) => {
            let root = root
                .to_str()
                .context("--install-root must be valid UTF-8")?;
            Ok(InstallPaths {
                config_reference: target_os
                    .join(root, &["config", deployment_id, "config.json"])?,
                data_root: target_os.join(root, &["data", deployment_id])?,
                secrets_dir: target_os.join(root, &["secrets", deployment_id])?,
                runtime_root: target_os.join(root, &["runtime", deployment_id])?,
            })
        }
        None => default_install_paths(target_os_name(target_os), deployment_id),
    }
}

fn target_os_name(target_os: TargetOs) -> &'static str {
    match target_os {
        TargetOs::Linux => "linux",
        TargetOs::Windows => "windows",
    }
}

fn config_path(target_os: TargetOs, path: &str) -> String {
    match target_os {
        TargetOs::Linux => path.to_owned(),
        // Forward slashes are native-path compatible on Windows and keep the
        // double-quoted YAML scalar free of backslash escape sequences.
        TargetOs::Windows => path.replace('\\', "/"),
    }
}

fn target_path(path: &std::path::Path, flag: &str) -> anyhow::Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{flag} must be valid UTF-8"))
}

/// Render the server configuration seed as the exact `.env.yaml` document
/// NazoAuth's single loader accepts: uppercase allowlisted keys, secret values
/// only as container-internal file references, LF endings. The container-side
/// paths are the frozen mount contract in `target::install_exec`.
///
/// TRANSPORT_MODE is `trusted-proxy`: the container terminates plain HTTP on
/// a loopback-published port and the public TLS endpoint is an external
/// reverse proxy — the only topology a containerized install creates. A
/// loopback HTTP issuer keeps the server-side default (loopback-http).
struct RuntimeSeedConfig {
    bind: String,
    trusted_proxy_cidrs: String,
    data_dir: String,
    database_url_file: String,
    valkey_url_file: String,
    mfa_totp_key_file: String,
}

fn render_config_yaml(
    issuer: &str,
    deployment_id: &str,
    state_epoch: &str,
    runtime: &RuntimeSeedConfig,
) -> anyhow::Result<String> {
    if issuer.contains(['"', '\\']) || issuer.chars().any(|c| c.is_control()) {
        bail!("issuer must not contain YAML-special characters");
    }
    let transport_mode = if issuer.starts_with("https://") {
        // The engine-default bridge networks and the host loopback are the
        // only sources that can reach the loopback-published container port.
        // Operators with a dedicated proxy network tighten this via
        // `update --config-file`.
        let cidrs = format!("TRUSTED_PROXY_CIDRS: \"{}\"\n", runtime.trusted_proxy_cidrs);
        // trusted-proxy requires an explicit mTLS certificate source; a
        // fresh install has no client-certificate proxy contract yet, so it
        // starts disabled instead of claiming an mTLS capability the edge
        // does not provide. Enable rfc9440 explicitly once the proxy forwards
        // `Client-Cert`.
        let mtls = "MTLS_CERTIFICATE_SOURCE: \"disabled\"\n";
        format!("TRANSPORT_MODE: \"trusted-proxy\"\n{cidrs}{mtls}")
    } else {
        String::new()
    };
    Ok(format!(
        "BIND: \"{}\"\n\
         PUBLIC_BASE_URL: \"{issuer}\"\n\
         DEPLOYMENT_ID: \"{deployment_id}\"\n\
         VALKEY_STATE_EPOCH: \"{state_epoch}\"\n\
         {transport_mode}\
         SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: \"true\"\n\
         DATABASE_URL_FILE: \"{}\"\n\
         VALKEY_URL_FILE: \"{}\"\n\
         MFA_TOTP_ENCRYPTION_KEY_FILE: \"{}\"\n\
         DATA_DIR: \"{}\"\n",
        runtime.bind,
        runtime.database_url_file,
        runtime.valkey_url_file,
        runtime.mfa_totp_key_file,
        runtime.data_dir,
    ))
}

/// Pick the runtime class from what the verified helper actually announced.
fn select_runtime(
    hello_runtimes: &[String],
    requested: Option<RuntimeBackendKind>,
) -> anyhow::Result<RuntimeBackendKind> {
    let announced = hello_runtimes
        .iter()
        .map(|runtime| {
            runtime.parse::<RuntimeBackendKind>().with_context(|| {
                format!("target helper announced unsupported runtime kind '{runtime}'")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let preference = [
        RuntimeBackendKind::Podman,
        RuntimeBackendKind::Docker,
        RuntimeBackendKind::Host,
    ];
    if let Some(requested) = requested {
        if announced.contains(&requested) {
            return Ok(requested);
        }
        bail!(
            "runtime '{requested}' was not announced by the target helper (announced: {})",
            if hello_runtimes.is_empty() {
                "-".to_owned()
            } else {
                hello_runtimes.join(",")
            }
        );
    }
    preference
        .into_iter()
        .find(|candidate| announced.contains(candidate))
        .with_context(|| {
            "the target helper announced no supported runtime; install Podman, Docker, or \
             systemd there first"
        })
}

/// Build everything the target needs for one clean-install operation.
fn build_install_order(
    request: &mut CleanInstallRequest,
    paths: &InstallPaths,
    target_os: TargetOs,
    runtime_kind: RuntimeBackendKind,
    deployment_id: &str,
    state_epoch: &str,
) -> anyhow::Result<InstallOrder> {
    let database_runtime_url_file =
        target_os.join(&paths.secrets_dir, &["database-runtime-url"])?;
    let database_lifecycle_url_file =
        target_os.join(&paths.secrets_dir, &["database-lifecycle-url"])?;
    let valkey_url_file = target_os.join(&paths.secrets_dir, &["valkey-url"])?;
    let mfa_totp_key_file = target_os.join(&paths.secrets_dir, &["mfa-totp-key"])?;

    let runtime = if runtime_kind == RuntimeBackendKind::Host {
        RuntimeSeedConfig {
            data_dir: config_path(target_os, &paths.data_root),
            database_url_file: config_path(target_os, &database_runtime_url_file),
            valkey_url_file: config_path(target_os, &valkey_url_file),
            mfa_totp_key_file: config_path(target_os, &mfa_totp_key_file),
            bind: format!("127.0.0.1:{DEFAULT_PORT}"),
            trusted_proxy_cidrs: "127.0.0.0/8,::1/128".to_owned(),
        }
    } else {
        RuntimeSeedConfig {
            data_dir: crate::target::install_exec::CONTAINER_DATA_DIR.to_owned(),
            database_url_file: format!(
                "{}/database-runtime-url",
                crate::target::install_exec::CONTAINER_SECRETS_DIR
            ),
            valkey_url_file: format!(
                "{}/valkey-url",
                crate::target::install_exec::CONTAINER_SECRETS_DIR
            ),
            mfa_totp_key_file: format!(
                "{}/mfa-totp-key",
                crate::target::install_exec::CONTAINER_SECRETS_DIR
            ),
            bind: format!("0.0.0.0:{DEFAULT_PORT}"),
            trusted_proxy_cidrs: "127.0.0.0/8,::1/128,10.88.0.0/16".to_owned(),
        }
    };
    let config_content = render_config_yaml(&request.issuer, deployment_id, state_epoch, &runtime)?;
    let config_sha256 = hex_digest(config_content.as_bytes());

    let order =
        InstallOrder {
            artifact: OfficialArtifactRef {
                repository: SERVER_REPOSITORY.to_owned(),
                version: request.version.clone(),
                expected_subject_sha256: request.expected_artifact_sha256.clone(),
            },
            config_content,
            config_sha256,
            data_root: paths.data_root.clone(),
            runtime_root: (runtime_kind == RuntimeBackendKind::Host)
                .then(|| paths.runtime_root.clone()),
            secrets: vec![
            PlannedSecret {
                purpose: "database-runtime-url".to_owned(),
                path: database_runtime_url_file,
                value: Some(request.database_runtime_password.take().context(
                    "runtime PostgreSQL password was already consumed by this install attempt",
                )?),
            },
            PlannedSecret {
                purpose: "database-lifecycle-url".to_owned(),
                path: database_lifecycle_url_file,
                value: Some(request.database_lifecycle_password.take().context(
                    "lifecycle PostgreSQL password was already consumed by this install attempt",
                )?),
            },
            PlannedSecret {
                purpose: "valkey-url".to_owned(),
                path: valkey_url_file,
                value: Some(request.valkey_password.take().context(
                    "Valkey password was already consumed by this install attempt",
                )?),
            },
            PlannedSecret {
                purpose: "mfa-totp-key".to_owned(),
                path: mfa_totp_key_file,
                value: None,
            },
        ],
            current_data_import: match (&request.import_data_root, &request.import_mfa_key_file) {
                (Some(data), Some(mfa)) => Some(crate::target::install_exec::CurrentDataImport {
                    source_data_root: target_path(data, "--import-data-root")?,
                    source_mfa_key_file: target_path(mfa, "--import-mfa-key-file")?,
                }),
                (None, None) => None,
                _ => bail!("current data import requires both target-local source paths"),
            },
            database_runtime_endpoint: request.database_runtime_endpoint.clone(),
            database_lifecycle_endpoint: request.database_lifecycle_endpoint.clone(),
            valkey_endpoint: request.valkey_endpoint.clone(),
            // G02 hook: provision the single-use initial-admin capability bound
            // to this exact install operation.
            fresh_bootstrap: true,
            port: DEFAULT_PORT,
        };
    Ok(order)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Serialize)]
struct CanonicalInstallRequest<'a> {
    schema: u32,
    host_id: String,
    issuer: &'a str,
    version: &'a Option<String>,
    expected_artifact_sha256: &'a Option<String>,
    runtime: &'a Option<RuntimeBackendKind>,
    install_root: Option<&'a str>,
    database_runtime_endpoint: &'a crate::target::install_exec::ExternalEndpoint,
    database_lifecycle_endpoint: &'a crate::target::install_exec::ExternalEndpoint,
    valkey_endpoint: &'a crate::target::install_exec::ExternalEndpoint,
    import_data_root: Option<&'a str>,
    import_mfa_key_file: Option<&'a str>,
}

/// Hash the exact non-secret target facts that identify an unfinished clean
/// install. The registry-only alias is not target identity, so correcting an
/// alias collision resumes the prepared deployment instead of creating one
/// more. Credential bytes are intentionally absent; the target journal's full
/// operation hash still rejects a changed operation after first acceptance.
fn canonical_install_request_hash(
    request: &CleanInstallRequest,
    host_id: Uuid,
) -> anyhow::Result<String> {
    let install_root = request
        .install_root
        .as_ref()
        .map(|path| path.to_str().context("--install-root must be valid UTF-8"))
        .transpose()?;
    let import_data_root = request
        .import_data_root
        .as_ref()
        .map(|path| {
            path.to_str()
                .context("--import-data-root must be valid UTF-8")
        })
        .transpose()?;
    let import_mfa_key_file = request
        .import_mfa_key_file
        .as_ref()
        .map(|path| {
            path.to_str()
                .context("--import-mfa-key-file must be valid UTF-8")
        })
        .transpose()?;
    let canonical = CanonicalInstallRequest {
        schema: 1,
        host_id: host_id.to_string(),
        issuer: &request.issuer,
        version: &request.version,
        expected_artifact_sha256: &request.expected_artifact_sha256,
        runtime: &request.runtime,
        install_root,
        database_runtime_endpoint: &request.database_runtime_endpoint,
        database_lifecycle_endpoint: &request.database_lifecycle_endpoint,
        valkey_endpoint: &request.valkey_endpoint,
        import_data_root,
        import_mfa_key_file,
    };
    Ok(hex_digest(&serde_json::to_vec(&canonical)?))
}

/// Everything one install operation consists of, fully generated from the
/// request plus the live handshake. Shared by the use case and the test
/// suite so tests drive exactly what production drives.
#[derive(Debug)]
pub(crate) struct PreparedInstallOperation {
    pub(crate) operation: HostOperation,
    pub(crate) deployment_id: String,
}

#[cfg(test)]
fn prepare_install_operation(
    request: &mut CleanInstallRequest,
    hello: &crate::target::RemoteHello,
) -> anyhow::Result<PreparedInstallOperation> {
    let deployment_id = format!("deploy-{}", Uuid::now_v7().simple());
    let operation_id = Uuid::now_v7();
    let state_epoch = Uuid::now_v7();
    prepare_install_operation_with_identity(
        request,
        hello,
        &deployment_id,
        operation_id,
        state_epoch,
        None,
    )
}

fn prepare_install_operation_with_identity(
    request: &mut CleanInstallRequest,
    hello: &crate::target::RemoteHello,
    deployment_id: &str,
    operation_id: Uuid,
    state_epoch: Uuid,
    resumed_runtime_kind: Option<RuntimeBackendKind>,
) -> anyhow::Result<PreparedInstallOperation> {
    validate_key(deployment_id, "generated deployment id")?;
    if state_epoch.is_nil() {
        bail!("generated Valkey state epoch must not be nil");
    }
    let target_os = TargetOs::parse(&hello.os)?;
    let runtime_kind = match resumed_runtime_kind {
        Some(runtime_kind) => {
            if request.runtime.is_some_and(|value| value != runtime_kind) {
                bail!("prepared install runtime no longer matches the verified target");
            }
            select_runtime(&hello.supported_runtimes, Some(runtime_kind))?
        }
        None => select_runtime(&hello.supported_runtimes, request.runtime)?,
    };
    let runtime_object = if runtime_kind == RuntimeBackendKind::Host {
        format!(
            "nazoauth-{}.service",
            deployment_id.trim_start_matches("deploy-")
        )
    } else {
        format!("nazoauth-{}", deployment_id.trim_start_matches("deploy-"))
    };
    let paths = resolve_paths(request, &hello.os, deployment_id)?;
    let order = build_install_order(
        request,
        &paths,
        target_os,
        runtime_kind,
        deployment_id,
        &state_epoch.to_string(),
    )?;
    let resources = declare_resources(
        &paths.data_root,
        &paths.secrets_dir,
        (runtime_kind == RuntimeBackendKind::Host).then(|| paths.runtime_root.clone()),
        &request.database_runtime_endpoint,
        &request.valkey_endpoint,
    )?;
    let operation = HostOperation::state_mutate(
        operation_id,
        deployment_id,
        None,
        StateMutationPayload::Bootstrap {
            issuer: request.issuer.clone(),
            runtime: RuntimeSurface::new(runtime_kind.as_str(), &runtime_object)?,
            artifact: None,
            config_reference: paths.config_reference,
            config_schema: CONFIG_SCHEMA_SEED.to_owned(),
            resources,
            install: Some(order),
        },
    );
    Ok(PreparedInstallOperation {
        operation,
        deployment_id: deployment_id.to_owned(),
    })
}

/// Managed/external resource facts declared at install time. External/shared
/// classification is what gives them zero-delete protection later. The
/// locator for each external dependency comes from the operator-supplied
/// endpoint facts, not a hardcoded loopback address.
fn declare_resources(
    data_root: &str,
    secrets_root: &str,
    runtime_root: Option<String>,
    runtime_database_endpoint: &crate::target::install_exec::ExternalEndpoint,
    valkey_endpoint: &crate::target::install_exec::ExternalEndpoint,
) -> anyhow::Result<Vec<Resource>> {
    let mut resources = vec![
        Resource::new(
            "app-data",
            "directory",
            data_root,
            ResourceOwnership::Managed,
            ResourceScope::Deployment,
        )?,
        Resource::new(
            "app-secrets",
            "directory",
            secrets_root,
            ResourceOwnership::Managed,
            ResourceScope::Deployment,
        )?,
        // Dependency processes are not provisioned by the clean-install wave;
        // they stay external + shared so no lifecycle path may ever delete or
        // replace them (goal plan 06 §3, F03). Locators reflect the actual
        // operator-supplied endpoints.
        Resource::new(
            "shared-postgres",
            "postgres",
            format!(
                "{}:{}:{}",
                runtime_database_endpoint.host,
                runtime_database_endpoint.port,
                runtime_database_endpoint.name
            ),
            ResourceOwnership::External,
            ResourceScope::Shared,
        )?,
        Resource::new(
            "shared-valkey",
            "valkey",
            format!("{}:{}", valkey_endpoint.host, valkey_endpoint.port),
            ResourceOwnership::External,
            ResourceScope::Shared,
        )?,
    ];
    if let Some(runtime_root) = runtime_root {
        resources.push(Resource::new(
            "app-binary",
            "directory",
            runtime_root,
            ResourceOwnership::Managed,
            ResourceScope::Deployment,
        )?);
    }
    Ok(resources)
}

/// The G01 entry point. Returns the full human report including the precise
/// next-step instructions (bootstrap/MFA, bind, verify).
///
/// Delivery boundary: the I-wave wires this into the CLI parser; until then
/// the use case and its shared test suite are the contract.
pub(crate) fn run_clean_install(
    context: &CleanInstallContext,
    mut request: CleanInstallRequest,
) -> anyhow::Result<String> {
    validate_issuer(&request.issuer).context("--public-url must be an http(s) origin URL")?;

    // 1. Resolve --host via the registry selector rules.
    let host_record = resolve_host_selector(&context.registry, request.host.as_deref())?;

    // 2. Live verified contact before anything else (C08 gate upstream of
    //    every mutation kind).
    let target = context.target_for(&host_record)?;
    let hello = live_probe(target.as_ref(), &host_record).context(format!(
        "host '{}' failed its live verification; nothing was installed or registered",
        host_record.alias
    ))?;

    // 3. Acquire the one prepared-install identity for this exact request.
    //    It survives a lost SSH response, but carries no password/config
    //    material and is removed after registry commit.
    let request_hash = canonical_install_request_hash(&request, host_record.host_id)?;
    let lease =
        install_journal::PreparedInstallLease::acquire(context.registry.root(), &request_hash)?;
    let stored_plan = lease.load(&request_hash)?;
    let resumed = stored_plan.is_some();
    let prepared = match stored_plan {
        Some(plan) => {
            if plan.host_id != host_record.host_id.to_string() || plan.target_os != hello.os {
                bail!(
                    "prepared install target identity drifted; refusing to create another instance"
                );
            }
            let operation_id = Uuid::parse_str(&plan.operation_id)
                .context("prepared install operation id is invalid")?;
            let state_epoch = Uuid::parse_str(&plan.state_epoch)
                .context("prepared install state epoch is invalid")?;
            prepare_install_operation_with_identity(
                &mut request,
                &hello,
                &plan.deployment_id,
                operation_id,
                state_epoch,
                Some(
                    plan.runtime_kind
                        .parse::<RuntimeBackendKind>()
                        .with_context(
                            || "prepared install journal contains an unsupported runtime kind",
                        )?,
                ),
            )?
        }
        None => {
            let deployment_id = format!("deploy-{}", Uuid::now_v7().simple());
            let operation_id = Uuid::now_v7();
            let state_epoch = Uuid::now_v7();
            let runtime_kind = select_runtime(&hello.supported_runtimes, request.runtime)?;
            let prepared = prepare_install_operation_with_identity(
                &mut request,
                &hello,
                &deployment_id,
                operation_id,
                state_epoch,
                Some(runtime_kind),
            )?;
            let plan = install_journal::PreparedInstallPlan::new(
                request_hash.clone(),
                host_record.host_id.to_string(),
                deployment_id,
                operation_id.to_string(),
                state_epoch.to_string(),
                runtime_kind.as_str().to_owned(),
                hello.os.clone(),
            );
            lease.persist(&plan)?;
            prepared
        }
    };
    let deployment_id = prepared.deployment_id.clone();

    // A crash after Registry commit but before journal cleanup is harmless:
    // the exact committed record closes the prepared pointer.
    if let Some(record) = context.registry.instance_by_deployment(&deployment_id)? {
        if record.host_id != host_record.host_id || record.issuer != request.issuer {
            bail!("prepared install points at a conflicting registry record");
        }
        let inspection = target.inspect_instance(&deployment_id)?;
        if inspection.deployment_id != deployment_id || inspection.issuer != request.issuer {
            bail!("prepared install registry record drifted from target DeploymentState");
        }
        lease.clear()?;
        return Ok(render_success_report(&record.alias, &inspection));
    }

    if let Some(alias) = request.instance_alias.as_deref()
        && let Some(existing) = context.registry.instance_by_alias(alias)?
    {
        bail!(
            "instance alias '{alias}' already names deployment '{}'; choose another alias and rerun to resume this prepared install",
            existing.deployment_id
        );
    }

    // A clean install never replaces an existing deployment.
    match target.inspect_instance(&deployment_id) {
        Err(error) if error.to_string().contains(DEPLOYMENT_UNKNOWN) => {}
        Ok(existing)
            if resumed
                && existing.deployment_id == deployment_id
                && existing.issuer == request.issuer => {}
        Ok(existing) => {
            bail!(
                "deployment '{}' already exists on host '{}'; install never overwrites existing state",
                existing.deployment_id,
                host_record.alias
            )
        }
        Err(error) => return Err(error.context("pre-install inspection failed")),
    }

    // 4. Execute: LocalTarget runs natively under its journal, SshTarget over
    //    one fixed remote exec round trip — identical result model.
    let result = target.execute_host_operation(&prepared.operation)?;
    if matches!(&result.outcome, HostOutcome::Failed { .. }) {
        lease.clear()?;
        return Err(interpret_result(&result).expect_err("failed host outcome must be an error"));
    }
    let inspection = interpret_result(&result)?;

    // 6. Register through the B04 controlled-evidence path.
    let evidence = DiscoveryEvidence::new(
        &host_record,
        hello,
        &inspection.deployment_id,
        &inspection.issuer,
    )?;
    let record = context.registry.register_instance(
        &evidence,
        request.instance_alias.as_deref(),
        ObservationCache::now(true, summarize_inspection(inspection)),
    )?;
    lease.clear()?;

    // 7. Report committed facts plus the exact next steps.
    Ok(render_success_report(&record.alias, inspection))
}

fn interpret_result(result: &HostResult) -> anyhow::Result<&crate::target::InstanceInspection> {
    match &result.outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::InstallApplied { inspection },
        } => Ok(inspection),
        HostOutcome::Completed { .. } => {
            bail!("the target answered an unexpected completion instead of an install receipt")
        }
        HostOutcome::Failed { code, detail } => {
            if code == REMOTE_HELPER_MISMATCH || detail.contains(REMOTE_HELPER_MISMATCH) {
                bail!("{code}: {detail}")
            }
            bail!("install failed on the target and was rolled back locally: {code}: {detail}")
        }
    }
}

fn render_success_report(alias: &str, inspection: &crate::target::InstanceInspection) -> String {
    let artifact = inspection
        .artifact
        .current
        .clone()
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "installed NazoAuth instance '{alias}' (deployment {}) on the target\n\
         issuer: {}\nartifact: {artifact}\nstate committed: local=healthy control_binding=unbound public=unknown\n\
         InstanceRecord written to the registry (`nazoauthctl instance list`)\n\
         \n\
         next steps:\n\
         1. create the initial administrator (single-use capability; closes on first success):\n\
            nazoauthctl bootstrap-admin --instance {alias}\n\
            then enroll MFA at {}/ui/auth — ctl never receives passwords or TOTP secrets\n\
         2. establish the controller binding after MFA enrollment:\n\
            nazoauthctl bind --instance {alias} --label production\n\
         3. public DNS/TLS/OIDC checks are independent of this install; verify separately:\n\
            nazoauthctl verify --instance {alias}\n",
        inspection.deployment_id,
        inspection.issuer,
        inspection.issuer.trim_end_matches('/'),
    )
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests;
