use anyhow::bail;

use super::super::legacy_types::BootstrapAdminOptions;

pub(super) fn parse_bootstrap_admin(values: Vec<String>) -> anyhow::Result<BootstrapAdminOptions> {
    let mut credentials_stdin = false;
    let mut yes = false;
    for value in values {
        match value.as_str() {
            "--credentials-stdin" if !credentials_stdin => credentials_stdin = true,
            "--yes" if !yes => yes = true,
            "--credentials-stdin" => bail!("--credentials-stdin may be supplied only once"),
            "--yes" => bail!("--yes may be supplied only once"),
            other => bail!("unknown bootstrap-admin option {other}"),
        }
    }
    Ok(BootstrapAdminOptions {
        credentials_stdin,
        yes,
    })
}
