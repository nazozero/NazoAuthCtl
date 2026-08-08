use std::collections::BTreeMap;

use anyhow::{Context, bail};

use crate::model::semantic_tag;

use super::super::types::CandidateTarget;

pub(super) fn parse_candidate_target(
    values: Vec<String>,
) -> anyhow::Result<Option<CandidateTarget>> {
    if values.is_empty() {
        return Ok(None);
    }
    let values = parse_named_options_for(
        values,
        &[
            "--candidate-release",
            "--candidate-revision",
            "--candidate-build-id",
            "--candidate-oci-digest",
        ],
        "candidate target",
    )?;
    let release = values["--candidate-release"].clone();
    if !semantic_tag(&release) {
        bail!("--candidate-release must be a canonical v-prefixed semantic version");
    }
    let revision = values["--candidate-revision"].clone();
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        bail!("--candidate-revision must be a lowercase hexadecimal Git object ID");
    }
    let build_id = values["--candidate-build-id"].clone();
    if build_id.is_empty()
        || build_id.len() > 256
        || !build_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_@/+-".contains(character))
    {
        bail!("--candidate-build-id is unsafe");
    }
    let oci_digest = values["--candidate-oci-digest"].clone();
    if !oci_digest.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    }) {
        bail!("--candidate-oci-digest must be a lowercase sha256 digest");
    }
    Ok(Some(CandidateTarget {
        release,
        revision,
        build_id,
        oci_digest,
    }))
}

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

pub(super) fn parse_named_options(
    values: Vec<String>,
    expected: &[&str],
) -> anyhow::Result<BTreeMap<String, String>> {
    parse_named_options_for(values, expected, "keys operation")
}

pub(super) fn parse_named_options_for(
    values: Vec<String>,
    expected: &[&str],
    command: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    parse_named_options_for_with_optional(values, expected, &[], command)
}

pub(super) fn parse_named_options_for_with_optional(
    values: Vec<String>,
    required: &[&str],
    optional: &[&str],
    command: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    if !values.len().is_multiple_of(2)
        || values.len() < required.len() * 2
        || values.len() > (required.len() + optional.len()) * 2
    {
        bail!("{command} has missing or unexpected options");
    }
    let mut parsed = BTreeMap::new();
    let mut values = values.into_iter();
    while let Some(key) = values.next() {
        let value = values
            .next()
            .with_context(|| format!("{command} option has no value"))?;
        if (!required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
            || parsed.insert(key, value).is_some()
        {
            bail!("{command} has duplicate or unexpected options");
        }
    }
    if required.iter().any(|key| !parsed.contains_key(*key)) {
        bail!("{command} has missing or unexpected options");
    }
    Ok(parsed)
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
