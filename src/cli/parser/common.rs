use crate::model::semantic_tag;

pub(super) fn parse_version_option(values: Vec<String>) -> anyhow::Result<Option<String>> {
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 2 || values[0] != "--to" {
        crate::ui::fail!("expected only --to VERSION", "仅支持 --to VERSION");
    }
    validate_version(&values[1])?;
    Ok(Some(values[1].clone()))
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
