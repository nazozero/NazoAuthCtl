//! Controller surface orchestration and self-update.

#[cfg(unix)]
use crate::process::Process;
use anyhow::bail;

mod self_update;
mod surface_run;

pub(crate) use surface_run::run;

pub(crate) fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        bail!("this command requires root on a Unix host");
    }
    #[cfg(unix)]
    {
        if Process::new("id").arg("-u").stdout()?.trim() != "0" {
            bail!("this command requires root");
        }
        Ok(())
    }
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

pub(crate) fn require_confirmation(yes: bool, action: &str) -> anyhow::Result<()> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("{action} requires --yes in non-interactive mode");
    }
    eprint!("Confirm: {action} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("operation cancelled")
    }
}
