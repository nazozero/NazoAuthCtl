use crate::model::semantic_tag;

pub(super) fn parse_version_option(
    values: impl IntoIterator<Item = String>,
) -> anyhow::Result<Option<String>> {
    let mut values = values.into_iter();
    let Some(flag) = values.next() else {
        return Ok(None);
    };
    let version = match (flag.as_str(), values.next(), values.next()) {
        ("--to", Some(version), None) => version,
        _ => crate::ui::fail!("expected only --to VERSION", "仅支持 --to VERSION"),
    };
    validate_version(&version)?;
    Ok(Some(version))
}

pub(super) fn validate_version(version: &str) -> anyhow::Result<()> {
    if !semantic_tag(version) {
        crate::ui::fail!(
            "release version is not an immutable semantic tag",
            "版本必须使用不可变的语义版本标签，例如 v0.2.29"
        );
    }
    Ok(())
}

pub(super) fn no_arguments(values: &[String], command: &str) -> anyhow::Result<()> {
    if let Some(argument) = values.first() {
        crate::ui::fail!(
            "{command} does not accept argument {argument}",
            "{command} 不接受参数 {argument}"
        );
    }
    Ok(())
}
