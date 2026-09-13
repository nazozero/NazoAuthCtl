//! Command-line model and parser façade.
//!
//! The public-in-crate surface stays here so controller and integration tests keep their stable
//! paths. Definitions live in [`types`], help routing in [`help`], and token parsing in
//! [`parser`]; none of those modules owns command execution.

pub(crate) mod envelope;
mod help;
pub(crate) mod language;
mod parser;
mod types;

use anyhow::Context as _;

pub(crate) use help::help_topic;
pub(crate) use types::{
    AcmeCertificateInput, AcmeCommand, AdminCommand, AdminCreateArgs, BackupArgs, BackupCommand,
    BindOptions, Cli, Command, ControllerCommand, HelpTopic, HostCommand, InstallArgs,
    InstanceCommand, InstanceSelector, PolicyArgs, RecoverArgs, TlsCertificateCheckInput,
    TlsCertificateInput, TlsCertificateSource, TlsCommand, UpdateArgs,
};

/// Consume the leading options which are shared by every command.
///
/// Keeping this boundary in the CLI façade means command parsing and help routing agree on
/// which token is the command. Scalar global options are intentionally single-use: accepting
/// a second value would make a typo silently select a different instance or output mode.
/// The final surface has exactly two global flags: `--instance SELECTOR` and `--json`.
pub struct GlobalOptions {
    pub instance: Option<String>,
    pub json: bool,
    pub consumed: usize,
}

pub fn parse_global_options(values: &[String]) -> anyhow::Result<GlobalOptions> {
    let mut instance = None;
    let mut json = false;
    let mut consumed = 0;
    while consumed < values.len() {
        let flag = values[consumed].as_str();
        match flag {
            "--instance" => {
                if instance.is_some() {
                    crate::ui::fail!(
                        "--instance may be specified only once",
                        "--instance 只能指定一次"
                    );
                }
                let value = values.get(consumed + 1).with_context(|| {
                    crate::ui::message!("{flag} requires a value", "{flag} 需要一个值")
                })?;
                if value.is_empty() {
                    crate::ui::fail!(
                        "--instance requires a non-empty selector",
                        "--instance 需要非空的实例名称"
                    );
                }
                instance = Some(value.clone());
                consumed += 2;
            }
            "--json" => {
                if json {
                    crate::ui::fail!("--json may be specified only once", "--json 只能指定一次");
                }
                json = true;
                consumed += 1;
            }
            _ => break,
        }
    }
    Ok(GlobalOptions {
        instance,
        json,
        consumed,
    })
}
