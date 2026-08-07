use super::*;

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
        let metadata = fs::symlink_metadata(&self.program).with_context(|| {
            format!(
                "failed to inspect recovery driver {}",
                self.program.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            bail!("recovery driver must be a non-empty regular file");
        }
        validate_lower_hex(&self.program_sha256)?;
        if sha256(&self.program)? != self.program_sha256 {
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
                    let metadata = fs::symlink_metadata(path).with_context(|| {
                        format!("failed to inspect recovery credential {}", path.display())
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        bail!("recovery credential reference must name a regular file");
                    }
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
