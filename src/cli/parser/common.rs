use anyhow::bail;

use crate::model::semantic_tag;

pub(super) fn parse_version_option(values: Vec<String>) -> anyhow::Result<Option<String>> {
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 2 || values[0] != "--to" {
        bail!("expected only --to VERSION");
    }
    validate_version(&values[1])?;
    Ok(Some(values[1].clone()))
}

pub(super) fn validate_version(version: &str) -> anyhow::Result<()> {
    if !semantic_tag(version) {
        bail!("release version is not an immutable semantic tag");
    }
    Ok(())
}

pub(super) fn no_arguments(values: &[String], command: &str) -> anyhow::Result<()> {
    if let Some(argument) = values.first() {
        bail!("{command} does not accept argument {argument}");
    }
    Ok(())
}
