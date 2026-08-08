use super::*;

use crate::filesystem::{open_secure_regular_file, sha256_file, validate_secure_directory};

mod activation;
mod execution;
mod persistence;
mod recovery;

pub(super) use activation::*;
pub(crate) use execution::{execute_coordinated_update, rollback_registered};
pub(super) use persistence::*;
pub(crate) use recovery::recover_registered;

impl RecoveryDriver {
    pub(super) fn validate(&self, runtimes: &[RuntimeLifecycle]) -> anyhow::Result<()> {
        validate_absolute_path(&self.program, "recovery driver program")?;
        for runtime in runtimes {
            for mount in &runtime.mounts {
                if paths_overlap(&self.program, &mount.source) {
                    bail!("recovery driver program is inside the application failure domain");
                }
            }
        }
        validate_lower_hex(&self.program_sha256)?;
        let mut program = open_secure_regular_file(&self.program, "recovery driver", false)?;
        if program.metadata()?.len() == 0
            || sha256_file(&mut program, &self.program.display().to_string())?
                != self.program_sha256
        {
            bail!("recovery driver digest does not match the lifecycle contract");
        }
        if self.arguments.len() > MAX_ARGUMENTS {
            bail!("recovery driver has too many arguments");
        }
        for argument in &self.arguments {
            if argument.is_empty()
                || argument.len() > MAX_ARGUMENT_BYTES
                || argument.contains(['\0', '\r', '\n'])
            {
                bail!("recovery driver argument is invalid");
            }
        }
        validate_absolute_path(&self.rehearsal_workspace, "recovery rehearsal workspace")?;
        validate_secure_directory(
            &self.rehearsal_workspace,
            "recovery rehearsal workspace",
            false,
        )?;
        for runtime in runtimes {
            for mount in &runtime.mounts {
                if paths_overlap(&self.rehearsal_workspace, &mount.source) {
                    bail!("recovery rehearsal workspace overlaps an application mount");
                }
            }
        }
        for (name, reference) in &self.credentials {
            validate_file_identifier(name, "recovery credential name")?;
            match reference {
                CredentialReference::File { path } => {
                    validate_absolute_path(path, "recovery credential file")?;
                    if runtimes.iter().any(|runtime| {
                        runtime
                            .mounts
                            .iter()
                            .any(|mount| paths_overlap(path, &mount.source))
                    }) {
                        bail!("recovery credential is inside the application failure domain");
                    }
                    let _credential = open_secure_regular_file(path, "recovery credential", false)?;
                }
                CredentialReference::Provider { provider, key } => {
                    validate_file_identifier(provider, "recovery credential provider")?;
                    validate_file_identifier(key, "recovery credential key")?;
                }
            }
        }
        Ok(())
    }
}
