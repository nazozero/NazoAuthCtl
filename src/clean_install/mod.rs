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
mod public_verify;

// CLI-surface re-exports (I wave): the dispatcher consumes these without the
// private module paths.
pub(crate) use initial_admin::{
    AdminCredentials, CurlInitialAdminTransport, LocalBootstrapMaterial, claim_initial_admin,
};
pub(crate) use public_verify::{CurlPublicProber, verify_public};

use std::path::PathBuf;

use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::fleet::{live_probe, production_target, resolve_host_selector, summarize_inspection};
use crate::registry::{
    DiscoveryEvidence, ObservationCache, RegistryStore, validate_issuer,
    validate_registry_key as validate_key,
};
use crate::target::{
    DEPLOYMENT_UNKNOWN, ExecutionTarget, HostCompletionBody, HostOperation, HostOutcome,
    HostResult, InstallOrder, OfficialArtifactRef, PlannedSecret, REMOTE_HELPER_MISMATCH, Resource,
    ResourceOwnership, ResourceScope, RuntimeSurface, StateMutationPayload,
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
    pub(crate) runtime: Option<String>,
    /// Optional custom installation root. Absent resolves to the platform
    /// defaults; set, every managed path derives from it.
    pub(crate) install_root: Option<PathBuf>,
    /// External PostgreSQL endpoint (host, port, database, role). The
    /// password is minted on the target and never crosses the wire.
    pub(crate) database_endpoint: crate::target::install_exec::ExternalEndpoint,
    /// External Valkey endpoint (host, port).
    pub(crate) valkey_endpoint: crate::target::install_exec::ExternalEndpoint,
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
    /// Delivery boundary: the I wave wires this into the CLI parser.
    #[allow(dead_code)]
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

/// Absolute paths rendered into the install order. Linux targets are the
/// supported install surface; the Windows branch exists so development
/// machines resolve concrete, non-colliding defaults instead of POSIX strings.
pub(crate) struct InstallPaths {
    pub(crate) data_root: PathBuf,
    pub(crate) config_reference: PathBuf,
    pub(crate) secrets_dir: PathBuf,
}

pub(crate) fn default_install_paths(deployment_id: &str) -> anyhow::Result<InstallPaths> {
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData")
            .context("ProgramData is not set; cannot derive default install paths")?;
        let base = PathBuf::from(program_data).join("nazoauth");
        Ok(InstallPaths {
            config_reference: base.join("config").join(deployment_id).join("config.json"),
            data_root: base.join("data").join(deployment_id),
            secrets_dir: base.join("data").join(deployment_id).join("secrets"),
        })
    }
    #[cfg(not(windows))]
    {
        Ok(InstallPaths {
            data_root: PathBuf::from("/var/lib/nazauth")
                .join("deployments")
                .join(deployment_id),
            config_reference: PathBuf::from("/etc/nazoauth")
                .join("deployments")
                .join(deployment_id)
                .join("config.json"),
            secrets_dir: PathBuf::from("/var/lib/nazauth")
                .join("deployments")
                .join(deployment_id)
                .join("secrets"),
        })
    }
}

/// Path resolution for one install: the custom root when provided (also the
/// test seam that keeps development machines off system paths), platform
/// defaults otherwise. Every path is scoped under the deployment id so two
/// instances on one host can never share data, secrets, or config (P0-3).
fn resolve_paths(
    request: &CleanInstallRequest,
    deployment_id: &str,
) -> anyhow::Result<InstallPaths> {
    match &request.install_root {
        Some(root) => Ok(InstallPaths {
            config_reference: root.join("config").join(deployment_id).join("config.json"),
            data_root: root.join("data").join(deployment_id),
            secrets_dir: root.join("data").join(deployment_id).join("secrets"),
        }),
        None => default_install_paths(deployment_id),
    }
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
fn render_config_yaml(issuer: &str) -> anyhow::Result<String> {
    if issuer.contains(['"', '\\']) || issuer.chars().any(|c| c.is_control()) {
        bail!("issuer must not contain YAML-special characters");
    }
    use crate::target::install_exec::{CONTAINER_DATA_DIR, CONTAINER_SECRETS_DIR};
    let transport_mode = if issuer.starts_with("https://") {
        // The engine-default bridge networks and the host loopback are the
        // only sources that can reach the loopback-published container port.
        // Operators with a dedicated proxy network tighten this via
        // `update --config-file`.
        let cidrs = "TRUSTED_PROXY_CIDRS: \"127.0.0.0/8,::1/128,10.88.0.0/16\"\n";
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
        "BIND: \"0.0.0.0:{DEFAULT_PORT}\"\n\
         PUBLIC_BASE_URL: \"{issuer}\"\n\
         {transport_mode}\
         DATABASE_URL_FILE: \"{CONTAINER_SECRETS_DIR}/database-url\"\n\
         VALKEY_URL_FILE: \"{CONTAINER_SECRETS_DIR}/valkey-url\"\n\
         MFA_TOTP_ENCRYPTION_KEY_FILE: \"{CONTAINER_SECRETS_DIR}/mfa-totp-key\"\n\
         DATA_DIR: \"{CONTAINER_DATA_DIR}\"\n"
    ))
}

/// Pick the runtime class from what the verified helper actually announced.
fn select_runtime(hello_runtimes: &[String], requested: Option<&str>) -> anyhow::Result<String> {
    let preference = ["podman", "docker", "host"];
    if let Some(requested) = requested {
        if hello_runtimes.iter().any(|runtime| runtime == requested) {
            return Ok(requested.to_owned());
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
        .find(|candidate| hello_runtimes.iter().any(|runtime| runtime == candidate))
        .map(str::to_owned)
        .with_context(|| {
            "the target helper announced no supported runtime; install Podman or Docker there \
             first"
        })
}

/// Build everything the target needs for one clean-install operation.
fn build_install_order(
    request: &CleanInstallRequest,
    paths: &InstallPaths,
) -> anyhow::Result<InstallOrder> {
    let database_url_file = paths
        .secrets_dir
        .join("database-url")
        .to_string_lossy()
        .into_owned();
    let valkey_url_file = paths
        .secrets_dir
        .join("valkey-url")
        .to_string_lossy()
        .into_owned();
    let mfa_totp_key_file = paths
        .secrets_dir
        .join("mfa-totp-key")
        .to_string_lossy()
        .into_owned();

    // The seed is the real `.env.yaml` the server loads; secret values are
    // only container-internal file references into the mounted secrets dir.
    let config_content = render_config_yaml(&request.issuer)?;
    let config_sha256 = hex_digest(config_content.as_bytes());

    let order = InstallOrder {
        artifact: OfficialArtifactRef {
            repository: SERVER_REPOSITORY.to_owned(),
            version: request.version.clone(),
            expected_subject_sha256: request.expected_artifact_sha256.clone(),
        },
        config_content,
        config_sha256,
        data_root: paths.data_root.to_string_lossy().into_owned(),
        secrets: vec![
            PlannedSecret {
                purpose: "database-url".to_owned(),
                path: database_url_file,
            },
            PlannedSecret {
                purpose: "valkey-url".to_owned(),
                path: valkey_url_file,
            },
            PlannedSecret {
                purpose: "mfa-totp-key".to_owned(),
                path: mfa_totp_key_file,
            },
        ],
        database_endpoint: request.database_endpoint.clone(),
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

/// Everything one install operation consists of, fully generated from the
/// request plus the live handshake. Shared by the use case and the test
/// suite so tests drive exactly what production drives.
pub(crate) struct PreparedInstallOperation {
    pub(crate) operation: HostOperation,
    pub(crate) deployment_id: String,
}

fn prepare_install_operation(
    request: &CleanInstallRequest,
    hello: &crate::target::RemoteHello,
) -> anyhow::Result<PreparedInstallOperation> {
    let deployment_id = format!("deploy-{}", Uuid::now_v7().simple());
    validate_key(&deployment_id, "generated deployment id")?;
    let runtime_kind = select_runtime(&hello.supported_runtimes, request.runtime.as_deref())?;
    let runtime_object = format!("nazoauth-{}", deployment_id.trim_start_matches("deploy-"));
    let paths = resolve_paths(request, &deployment_id)?;
    let order = build_install_order(request, &paths)?;
    let resources = declare_resources(
        &runtime_object,
        &paths.data_root.to_string_lossy(),
        &request.database_endpoint,
        &request.valkey_endpoint,
    )?;
    let operation = HostOperation::state_mutate(
        Uuid::now_v7(),
        &deployment_id,
        None,
        StateMutationPayload::Bootstrap {
            issuer: request.issuer.clone(),
            runtime: RuntimeSurface::new(&runtime_kind, &runtime_object)?,
            // Placeholder overwritten by the target's verified facts; kept
            // empty here so no unverified identity ever crosses the wire.
            artifact: Default::default(),
            config_reference: paths.config_reference.to_string_lossy().into_owned(),
            config_schema: CONFIG_SCHEMA_SEED.to_owned(),
            resources,
            install: Some(order),
        },
    );
    Ok(PreparedInstallOperation {
        operation,
        deployment_id,
    })
}

/// Managed/external resource facts declared at install time. External/shared
/// classification is what gives them zero-delete protection later. The
/// locator for each external dependency comes from the operator-supplied
/// endpoint facts, not a hardcoded loopback address.
fn declare_resources(
    runtime_object: &str,
    data_root: &str,
    database_endpoint: &crate::target::install_exec::ExternalEndpoint,
    valkey_endpoint: &crate::target::install_exec::ExternalEndpoint,
) -> anyhow::Result<Vec<Resource>> {
    Ok(vec![
        Resource::new(
            "app-runtime",
            "container",
            runtime_object,
            ResourceOwnership::Managed,
            ResourceScope::Deployment,
        )?,
        Resource::new(
            "app-data",
            "directory",
            data_root,
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
                database_endpoint.host, database_endpoint.port, database_endpoint.name
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
    ])
}

/// The G01 entry point. Returns the full human report including the precise
/// next-step instructions (bootstrap/MFA, bind, verify).
///
/// Delivery boundary: the I-wave wires this into the CLI parser; until then
/// the use case and its shared test suite are the contract.
pub(crate) fn run_clean_install(
    context: &CleanInstallContext,
    request: CleanInstallRequest,
) -> anyhow::Result<String> {
    validate_issuer(&request.issuer).context("--public-url must be an http(s) origin URL")?;

    // 1. Resolve --host via the registry selector rules.
    let host_record = resolve_host_selector(&context.registry, request.host.as_deref())?;

    // 2. Live verified contact before anything else (C08 gate upstream of
    //    every mutation kind).
    let target = context.target_for(&host_record)?;
    let hello = live_probe(target.as_ref()).context(format!(
        "host '{}' failed its live verification; nothing was installed or registered",
        host_record.alias
    ))?;

    // 3. Auto-generate every safely inferable fact and build the ONE
    //    HostOperation carrying the complete typed install order.
    let prepared = prepare_install_operation(&request, &hello)?;
    let deployment_id = prepared.deployment_id.clone();

    // A clean install never replaces an existing deployment.
    match target.inspect_instance(&deployment_id) {
        Err(error) if error.to_string().contains(DEPLOYMENT_UNKNOWN) => {}
        Ok(existing) => bail!(
            "deployment '{}' already exists on host '{}'; install never overwrites existing state",
            existing.deployment_id,
            host_record.alias
        ),
        Err(error) => return Err(error.context("pre-install inspection failed")),
    }

    // 4. Execute: LocalTarget runs natively under its journal, SshTarget over
    //    one fixed remote exec round trip — identical result model.
    let result = target.execute_host_operation(&prepared.operation)?;
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
            nazoauthctl controller bind --instance {alias} --label production\n\
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
