//! Command-line model and parser façade.
//!
//! The public-in-crate surface stays here so controller and integration tests keep their stable
//! paths.  Definitions live in [`types`], help routing in [`help`], and token parsing in
//! [`parser`]; none of those modules owns command execution.

mod help;
mod parser;
mod types;

use std::path::PathBuf;

use anyhow::{Context, bail};

pub(crate) use help::help_topic;
#[cfg(test)]
pub(crate) use types::RelinquishOptions;
pub(crate) use types::{
    AcmeCertificateInput, AcmeCommand, BootstrapAdminOptions, CandidateTarget, Cli, Command,
    HelpTopic, InstallOptions, KeysCommand, StandardsProfileSecrets, TlsCertificateCheckInput,
    TlsCertificateInput, TlsCertificateSource, TlsCommand, UpdateOptions,
};

/// Consume the leading options which are shared by every command.
///
/// Keeping this boundary in the CLI façade means command parsing and help routing agree on
/// which token is the command.  Scalar global options are intentionally single-use: accepting
/// a second value would make a typo silently select a different configuration or deployment.
pub(crate) struct GlobalOptions {
    pub(crate) config: Option<PathBuf>,
    pub(crate) deployment: Option<String>,
    pub(crate) consumed: usize,
}

pub(crate) fn parse_global_options(values: &[String]) -> anyhow::Result<GlobalOptions> {
    let mut config = None;
    let mut deployment = None;
    let mut consumed = 0;
    while consumed < values.len() {
        let flag = values[consumed].as_str();
        if !matches!(flag, "--config" | "--deployment") {
            break;
        }
        let value = values
            .get(consumed + 1)
            .with_context(|| format!("{flag} requires a value"))?;
        match flag {
            "--config" => {
                if config.is_some() {
                    bail!("--config may be specified only once");
                }
                config = Some(PathBuf::from(value));
            }
            "--deployment" => {
                if deployment.is_some() {
                    bail!("--deployment may be specified only once");
                }
                deployment = Some(value.clone());
            }
            _ => unreachable!(),
        }
        consumed += 2;
    }
    Ok(GlobalOptions {
        config,
        deployment,
        consumed,
    })
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
