use anyhow::bail;

use crate::model::semantic_tag;

pub(super) fn take_yes(mut values: Vec<String>) -> anyhow::Result<(Vec<String>, bool)> {
    let positions = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == "--yes").then_some(index))
        .collect::<Vec<_>>();
    if positions.len() > 1 {
        bail!("--yes may be supplied only once");
    }
    let yes = !positions.is_empty();
    if let Some(index) = positions.first().copied() {
        values.remove(index);
    }
    Ok((values, yes))
}

pub(super) fn parse_yes(values: Vec<String>, command: &str) -> anyhow::Result<bool> {
    if values.is_empty() {
        return Ok(false);
    }
    if values == ["--yes"] {
        return Ok(true);
    }
    bail!("{command} accepts only --yes")
}

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
