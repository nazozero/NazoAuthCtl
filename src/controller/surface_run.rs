//! Dispatcher for the final command surface (goal plan 09 §1, I01/I02).
//!
//! Every arm wires one tested use-case module; this file contains no business
//! logic of its own beyond selector merging, confirmation prompts, and the
//! stable error rendering.

use std::io::IsTerminal as _;

use anyhow::{Context as _, bail};

use crate::clean_install::{
    CleanInstallContext, CleanInstallRequest, CurlInitialAdminTransport, CurlPublicProber,
    LocalBootstrapMaterial, RemoteBootstrapMaterial, claim_initial_admin, verify_public,
};
use crate::cli::{Cli, Command, InstallArgs, InstanceCommand, InstanceSelector, UpdateArgs};
use crate::controller_identity::lifecycle as identity;
use crate::controller_identity::store::ControllerKeyStore;
use crate::discover_adopt::{DiscoverRequest, DiscoveryContext};
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
        Command::Instance(mut command) => {
            // P1-2: fold the global --instance into the command-level selector,
            // strictly rejecting collisions where both channels are present.
            let apply_merge = |sel: &mut InstanceSelector, label: &str| -> anyhow::Result<()> {
                if let Some(merged) = sel.merge_global(instance_flag, label)? {
                    sel.positional = Some(merged);
                    sel.named = None;
                }
                Ok(())
            };
            match &mut command {
                InstanceCommand::Show(selector) => apply_merge(selector, "instance show")?,
                InstanceCommand::Forget(selector) => apply_merge(selector, "instance forget")?,
                InstanceCommand::Rename {
                    source: selector, ..
                } => apply_merge(selector, "instance rename")?,
                InstanceCommand::Relocate { selector, .. } => {
                    apply_merge(selector, "instance relocate")?
                }
                _ => {}
            }
            crate::fleet::run_instance(command)
        }
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
        Command::Logs { selector, limit } => {
            selector_scoped(&selector, instance_flag, "logs", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_logs_view(&store, merged.as_deref(), limit, json_mode)
            })
        }
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
        Command::Backup(args) => {
            selector_scoped(&args.selector, instance_flag, "backup", |merged| {
                let store = RegistryStore::open_default()?;
                crate::fleet::fleet_read::run_backup_view(&store, merged.as_deref(), json_mode)
            })
        }
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

fn read_password_file(path: &std::path::Path, flag: &str) -> anyhow::Result<String> {
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    let raw =
        crate::filesystem::read_secure_regular_file(path, flag, true, MAX_PASSWORD_FILE_BYTES)
            .with_context(|| format!("{flag}: failed to read {}", path.display()))?;
    let value = String::from_utf8(raw.to_vec())
        .with_context(|| format!("{flag}: {} is not UTF-8", path.display()))?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        bail!("{flag}: {} is empty", path.display());
    }
    Ok(trimmed.to_owned())
}

fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    let context = CleanInstallContext::production()?;
    let database_password =
        read_password_file(&args.database_password_file, "--database-password-file")?;
    let valkey_password = read_password_file(&args.valkey_password_file, "--valkey-password-file")?;
    let request = CleanInstallRequest {
        host: args.host,
        instance_alias: args.name,
        issuer: args.public_url,
        version: args.version,
        expected_artifact_sha256: args.artifact_sha256,
        runtime: args.runtime,
        install_root: args.install_root,
        database_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: args.database_host,
            port: args.database_port,
            name: args.database_name,
            user: args.database_user,
        },
        valkey_endpoint: crate::target::install_exec::ExternalEndpoint {
            host: args.valkey_host,
            port: args.valkey_port,
            name: String::new(),
            user: String::new(),
        },
        database_password,
        valkey_password,
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
    let credentials = read_admin_credentials(args.credentials_stdin)?;
    // P0-2: resolve the instance's HOST and pick the material source that
    // owns its transport. Local hosts read the state root directly; SSH
    // hosts drive inspect/bootstrap-close over the fixed stdio executor so
    // the token only rides the encrypted channel.
    let record = crate::fleet::resolve_instance(&registry, merged.as_deref(), "bootstrap-admin")?;
    let host = registry
        .host_by_id(record.host_id)?
        .with_context(|| format!("instance '{}' references a missing host", record.alias))?;

    let report = if host.transport == crate::registry::HostTransport::Local {
        let material = LocalBootstrapMaterial::production()?;
        claim_initial_admin(
            &registry,
            &material,
            &CurlInitialAdminTransport,
            merged.as_deref(),
            credentials,
        )?
    } else {
        let context = crate::clean_install::CleanInstallContext::production()?;
        let target = (context.factory)(&host)?;
        let material = RemoteBootstrapMaterial {
            target: std::sync::Arc::new(std::sync::Mutex::new(target)),
        };
        claim_initial_admin(
            &registry,
            &material,
            &CurlInitialAdminTransport,
            merged.as_deref(),
            credentials,
        )?
    };
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
