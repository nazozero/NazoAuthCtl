//! Command-line model and parser façade.
//!
//! The public-in-crate surface stays here so controller and integration tests keep their stable
//! paths.  Definitions live in [`types`], help routing in [`help`], and token parsing in
//! [`parser`]; none of those modules owns command execution.

mod help;
mod parser;
mod types;

pub(crate) use help::help_topic;
#[cfg(test)]
use std::path::PathBuf;
pub(crate) use types::{
    BootstrapAdminOptions, CandidateTarget, Cli, Command, ConformanceLeaseCommand, HelpTopic,
    InstallOptions, KeysCommand, StandardsProfileSecrets, UpdateOptions,
};
#[cfg(test)]
pub(crate) use types::{ConformanceCommand, RelinquishOptions};

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
