//! Controller surface orchestration and self-update.

#[cfg(unix)]
use crate::process::Process;
use anyhow::bail;

use crate::error_codes::PRIVILEGE_REQUIRED;

mod recovery_journal;
mod recovery_transport;
mod self_update;
mod surface_run;
mod transfer_journal;

pub(crate) use surface_run::run;

pub(crate) fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        bail!("{PRIVILEGE_REQUIRED}: this command requires root on a Unix host");
    }
    #[cfg(unix)]
    {
        if Process::new("id").arg("-u").stdout()?.trim() != "0" {
            bail!("{PRIVILEGE_REQUIRED}: this command requires root");
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn require_self_update_privilege() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn require_self_update_privilege() -> anyhow::Result<()> {
    require_root()
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn windows_self_update_uses_install_path_access_instead_of_unix_root() {
        super::require_self_update_privilege().expect("Windows has no Unix root identity");
    }
}
