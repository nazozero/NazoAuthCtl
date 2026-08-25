//! Dispatcher for the final command surface (goal plan 09 §1, I01/I02).
//!
//! Every arm wires one tested use-case module; this file contains no business
//! logic of its own beyond selector merging, confirmation prompts, and the
//! stable K-phase placeholders.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};

use crate::clean_install::{
    CleanInstallContext, CleanInstallRequest, CurlInitialAdminTransport, CurlPublicProber,
    LocalBootstrapMaterial, claim_initial_admin, verify_public,
};
use crate::cli::{Cli, Command, InstallArgs, InstanceSelector, UpdateArgs};
use crate::controller_identity::lifecycle as identity;
use crate::controller_identity::store::ControllerKeyStore;
use crate::discover_adopt::{DiscoverRequest, DiscoveryContext};
use crate::error_codes;
use crate::instance_lifecycle::{LifecycleContext, UpdateRequest};
use crate::registry::RegistryStore;

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    // Copied out before the command is moved; selector helpers close over these.
    let global_instance = cli.instance.clone();
    let json_mode = cli.json;
    let instance_flag = global_instance.as_deref();
    match cli.command {
        // ---- primary 18-command surface ------------------------------------
        Command::Host(command) => crate::fleet::run_host(command),
        Command::Instance(command) => crate::fleet::run_instance(command),
        Command::Controller(command) => identity::run_controller_command(command, instance_flag),
        Command::Bind(options) => identity::run_bind(options, instance_flag),
        Command::Install(args) => run_install(args),
        Command::Discover { host } => {
            let context = DiscoveryContext::production()?;
            let report = crate::discover_adopt::run_discover(&context, DiscoverRequest { host })?;
            println!("{report}");
            Ok(())
        }
        Command::Status { selector, all } => {
            selector_scoped(&selector, instance_flag, "status", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_status_like(
                    &store,
                    merged.as_deref(),
                    all,
                    json_mode,
                    "status",
                    false,
                )
            })
        }
        Command::Doctor { selector, all } => {
            selector_scoped(&selector, instance_flag, "doctor", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_status_like(
                    &store,
                    merged.as_deref(),
                    all,
                    json_mode,
                    "doctor",
                    true,
                )
            })
        }
        Command::Logs { .. } => Err(not_implemented(
            "the remote application log view",
            "`logs` reads NazoAuth runtime logs through the fixed target protocol; that read-only \
             kind lands with the K-phase acceptance work",
        )),
        Command::Verify { selector } => {
            selector_scoped(&selector, instance_flag, "verify", run_verify)
        }
        Command::Update(args) => run_update(args, instance_flag),
        Command::Rollback { selector, yes } => {
            let merged = merge(&selector, instance_flag, "rollback")?;
            super::require_root()?;
            super::require_confirmation(
                yes,
                "roll back to the previous verified artifact reference saved on the target",
            )?;
            let context = LifecycleContext::production()?;
            let report = crate::instance_lifecycle::run_rollback(&context, merged.as_deref())?;
            println!("{report}");
            Ok(())
        }
        Command::Operation { selector, limit } => {
            selector_scoped(&selector, instance_flag, "operation", |merged| {
                let store = RegistryStore::open_default()?;
                let keys = ControllerKeyStore::open_default()?;
                crate::fleet::fleet_read::run_operation_view(
                    &store,
                    &keys,
                    merged.as_deref(),
                    limit,
                    json_mode,
                )
            })
        }
        Command::Policy => Err(not_implemented(
            "the explicit policy store",
            "policies such as `backup-before-update` become explicit, off-by-default entries in \
             the K-phase acceptance work; nothing is policy-gated today",
        )),
        Command::Backup(args) if args.snapshot => {
            let _ = merge(&args.selector, instance_flag, "backup snapshot")?;
            Err(not_implemented(
                "the explicit backup snapshot operation",
                "snapshot execution over external dependency endpoints lands with the K-phase \
                 acceptance work; maturity facts are available via `nazoauthctl backup`",
            ))
        }
        Command::Backup(args) => {
            selector_scoped(&args.selector, instance_flag, "backup", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_backup_view(&store, merged.as_deref(), json_mode)
            })
        }
        Command::Recover { .. } => Err(not_implemented(
            "data restore beyond artifact rollback",
            "`recover` performs the explicit data restore; it lands with the K-phase acceptance \
             work. Artifact/config rollback stays available via `nazoauthctl rollback --yes`",
        )),
        Command::Uninstall { selector, yes } => {
            let merged = merge(&selector, instance_flag, "uninstall")?;
            let context = LifecycleContext::production()?;
            let report =
                crate::instance_lifecycle::run_uninstall(&context, merged.as_deref(), yes)?;
            println!("{report}");
            Ok(())
        }
        // ---- final-model maintenance surface --------------------------------
        Command::BootstrapAdmin(args) => run_bootstrap_admin(args, instance_flag),
        Command::Tls(command) => crate::tls::run(
            instance_flag,
            command,
            super::require_root,
            super::require_confirmation,
        ),
        Command::RemoteExec => crate::target::remote_exec::run_stdio(),
        Command::SelfCheck(version) => super::self_update::controller_check(version.as_deref()),
        Command::SelfUpdate { version, yes } => {
            super::require_root()?;
            super::require_confirmation(
                yes,
                "replace nazoauthctl with a signed controller Release",
            )?;
            super::self_update::controller_update(version.as_deref())
        }
        Command::SelfRollback { yes } => {
            super::require_root()?;
            super::require_confirmation(yes, "restore the previous signed nazoauthctl binary")?;
            super::self_update::controller_rollback()
        }
    }
}

// ------------------------------------------------------------------ helpers

/// Apply the I02 exactly-one rule between the global `--instance` and any
/// command-level channel.
fn merge(
    selector: &InstanceSelector,
    global: Option<&str>,
    action: &str,
) -> anyhow::Result<Option<String>> {
    selector.merge_global(global, action)
}

fn selector_scoped<T>(
    selector: &InstanceSelector,
    global: Option<&str>,
    action: &str,
    body: impl FnOnce(Option<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    body(merge(selector, global, action)?)
}

fn not_implemented(what: &str, detail: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{}: {} is not available yet — {}",
        error_codes::NOT_IMPLEMENTED_BEFORE_K_PHASE,
        what,
        detail
    )
}

fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    let context = CleanInstallContext::production()?;
    let request = CleanInstallRequest {
        host: args.host,
        instance_alias: args.name,
        issuer: args.public_url,
        version: args.version,
        expected_artifact_sha256: args.artifact_sha256,
        runtime: args.runtime,
        install_root: args.install_root,
    };
    let report = crate::clean_install::run_clean_install(&context, request)?;
    println!("{report}");
    Ok(())
}

fn run_verify(merged: Option<String>) -> anyhow::Result<()> {
    let store = RegistryStore::open_default()?;
    let record = crate::fleet::resolve_instance(&store, merged.as_deref(), "verify")?;
    let prober = CurlPublicProber;
    let report = verify_public(&prober, &record.issuer);
    println!("{}", report.render());
    Ok(())
}

fn run_update(args: UpdateArgs, global: Option<&str>) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "update")?;
    super::require_root()?;
    super::require_confirmation(
        args.yes,
        "update the instance to a verified official artifact (migration included)",
    )?;
    let config_content = match &args.config_file {
        Some(path) => Some(read_config_file(path)?),
        None => None,
    };
    let request = UpdateRequest {
        instance: merged,
        version: args.version,
        expected_artifact_sha256: args.artifact_sha256,
        config_content,
        config_schema: args.config_schema,
    };
    let context = LifecycleContext::production()?;
    let keys = ControllerKeyStore::open_default()?;
    let report = crate::instance_lifecycle::run_update(&context, &keys, &request)?;
    println!("{report}");
    Ok(())
}

fn read_config_file(path: &std::path::Path) -> anyhow::Result<String> {
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "staged configuration",
        false,
        MAX_CONFIG_BYTES,
    )
    .with_context(|| format!("failed to read {}", path.display()))?;
    String::from_utf8(bytes.to_vec())
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn run_bootstrap_admin(
    args: crate::cli::BootstrapAdminArgs,
    global: Option<&str>,
) -> anyhow::Result<()> {
    let merged = merge(&args.selector, global, "bootstrap-admin")?;
    let registry = RegistryStore::open_default()?;
    let material = LocalBootstrapMaterial::production()?;
    let credentials = read_admin_credentials(args.credentials_stdin)?;
    let report = claim_initial_admin(
        &registry,
        &material,
        &CurlInitialAdminTransport,
        merged.as_deref(),
        credentials,
    )?;
    println!("{report}");
    Ok(())
}

fn read_admin_credentials(
    stdin_mode: bool,
) -> anyhow::Result<crate::clean_install::AdminCredentials> {
    use zeroize::Zeroizing;
    if stdin_mode {
        let mut line = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut line)
            .context("failed to read the credentials JSON from stdin")?;
        #[derive(serde::Deserialize)]
        struct Raw {
            email: String,
            password: String,
        }
        let raw: Raw = serde_json::from_str(line.trim())
            .context("stdin credentials must be strict JSON with email and password")?;
        return Ok(crate::clean_install::AdminCredentials {
            email: raw.email,
            password: Zeroizing::new(raw.password),
        });
    }
    use std::io::Write as _;
    if !std::io::stdin().is_terminal() {
        bail!(
            "bootstrap-admin requires --credentials-stdin in non-interactive mode; passwords are \
             never accepted on argv"
        );
    }
    eprint!("Administrator email: ");
    std::io::stderr().flush()?;
    let mut email = String::new();
    std::io::stdin()
        .read_line(&mut email)
        .context("failed to read administrator email")?;
    let password = rpassword::prompt_password("Administrator password: ")
        .context("failed to read administrator password")?;
    Ok(crate::clean_install::AdminCredentials {
        email: email.trim().to_owned(),
        password: Zeroizing::new(password),
    })
}

/// Keep PathBuf referenced so unused-import lints stay honest when arms
/// evolve during J-phase deletions.
#[allow(dead_code)]
fn _touch(_: PathBuf) {}
