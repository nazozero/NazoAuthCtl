//! Command-line model and parser façade.
//!
//! The public-in-crate surface stays here so controller and integration tests keep their stable
//! paths. Definitions live in [`types`], the frozen pre-goal command set in [`legacy_types`],
//! help routing in [`help`], and token parsing in [`parser`]; none of those modules owns
//! command execution.

pub(crate) mod envelope;
mod help;
pub(crate) mod legacy_types;
mod parser;
mod types;

use anyhow::{Context, bail};

pub(crate) use help::help_topic;
pub(crate) use types::{
    BindOptions, BootstrapAdminArgs, Cli, Command, ControllerCommand, HelpTopic, HostCommand,
    InstallArgs, InstanceCommand, InstanceSelector, UpdateArgs,
};

/// Frozen pre-goal types. The legacy handler bodies (and the J-phase
/// deletion list) reference them through these stable paths.
pub(crate) use legacy_types::{
    AcmeCertificateInput, AcmeCommand, CandidateTarget, TlsCertificateCheckInput,
    TlsCertificateInput, TlsCertificateSource, TlsCommand,
};

/// Consume the leading options which are shared by every command.
///
/// Keeping this boundary in the CLI façade means command parsing and help routing agree on
/// which token is the command. Scalar global options are intentionally single-use: accepting
/// a second value would make a typo silently select a different instance or output mode.
/// The final surface has exactly two global flags: `--instance SELECTOR` and `--json`.
pub(crate) struct GlobalOptions {
    pub(crate) instance: Option<String>,
    pub(crate) json: bool,
    pub(crate) consumed: usize,
}

pub(crate) fn parse_global_options(values: &[String]) -> anyhow::Result<GlobalOptions> {
    let mut instance = None;
    let mut json = false;
    let mut consumed = 0;
    while consumed < values.len() {
        let flag = values[consumed].as_str();
        match flag {
            "--instance" => {
                if instance.is_some() {
                    bail!("--instance may be specified only once");
                }
                let value = values
                    .get(consumed + 1)
                    .with_context(|| format!("{flag} requires a value"))?;
                if value.is_empty() {
                    bail!("--instance requires a non-empty selector");
                }
                instance = Some(value.clone());
                consumed += 2;
            }
            "--json" => {
                if json {
                    bail!("--json may be specified only once");
                }
                json = true;
                consumed += 1;
            }
            "--config" | "--deployment" => bail!(
                "{flag} belonged to the retired per-deployment control model; \
                 select an instance with --instance instead"
            ),
            _ => break,
        }
    }
    Ok(GlobalOptions {
        instance,
        json,
        consumed,
    })
}
