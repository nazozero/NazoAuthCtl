use std::time::Duration;

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::BrowserError;
use super::schema::{
    BrowserCommand, BrowserEntry, BrowserSelector, BrowserTask, ReviewScreenshotMarker,
};
use super::validation::{
    MAX_MATCH_BYTES, MAX_SELECTOR_BYTES, MAX_STEP_TIMEOUT, MAX_STEPS, MAX_TEXT_BYTES,
    compile_pattern, validate_contains, validate_match_pattern,
};

impl BrowserTask {
    pub(super) fn parse(value: &Value) -> Result<Self, BrowserError> {
        let object = value.as_object().ok_or(BrowserError::InvalidSchema)?;
        reject_unknown_keys(object, &["task", "optional", "match", "commands"])?;
        let task = match object.get("task") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(BrowserError::InvalidSchema)?
                    .to_owned(),
            ),
        };
        let optional = object
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let match_pattern = match object.get("match") {
            None => None,
            Some(value) => {
                let value = value.as_str().ok_or(BrowserError::InvalidSchema)?;
                validate_match_pattern(value, MAX_MATCH_BYTES)?;
                Some(value.to_owned())
            }
        };
        let raw_commands = object
            .get("commands")
            .and_then(Value::as_array)
            .ok_or(BrowserError::InvalidSchema)?;
        if raw_commands.len() > MAX_STEPS {
            return Err(BrowserError::StepLimit);
        }
        let commands = raw_commands
            .iter()
            .map(BrowserCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            task,
            optional,
            match_pattern,
            commands,
        })
    }
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), BrowserError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(BrowserError::InvalidSchema);
    }
    Ok(())
}

impl BrowserEntry {
    pub fn parse(value: &Value) -> Result<Self, BrowserError> {
        let object = value.as_object().ok_or(BrowserError::InvalidSchema)?;
        reject_unknown_keys(object, &["comment", "match", "match-limit", "tasks"])?;
        if let Some(comment) = object.get("comment") {
            let comment = comment.as_str().ok_or(BrowserError::InvalidSchema)?;
            if comment.is_empty()
                || comment.len() > MAX_TEXT_BYTES
                || comment.chars().any(char::is_control)
            {
                return Err(BrowserError::InvalidSchema);
            }
        }
        let match_pattern = object
            .get("match")
            .and_then(Value::as_str)
            .ok_or(BrowserError::InvalidSchema)?;
        validate_match_pattern(match_pattern, MAX_MATCH_BYTES)?;
        let match_limit = match object.get("match-limit") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(BrowserError::InvalidSchema)?,
            ),
        };
        if match_limit == Some(0) {
            return Err(BrowserError::InvalidSchema);
        }
        let raw_tasks = object
            .get("tasks")
            .and_then(Value::as_array)
            .ok_or(BrowserError::InvalidSchema)?;
        if raw_tasks.len() > MAX_STEPS {
            return Err(BrowserError::StepLimit);
        }
        let tasks = raw_tasks
            .iter()
            .map(BrowserTask::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            match_pattern: match_pattern.to_owned(),
            match_limit,
            tasks,
        })
    }
}

impl BrowserSelector {
    pub(super) fn parse(kind: &str, value: &str) -> Result<Self, BrowserError> {
        if value.is_empty()
            || value.len() > MAX_SELECTOR_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(BrowserError::InvalidSchema);
        }
        match kind {
            "id" => Ok(Self::Id(value.to_owned())),
            "css" => Ok(Self::Css(value.to_owned())),
            "xpath" => Ok(Self::XPath(value.to_owned())),
            _ => Err(BrowserError::UnsupportedCommand),
        }
    }
}

impl TryFrom<&Value> for BrowserCommand {
    type Error = BrowserError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let values = value.as_array().ok_or(BrowserError::InvalidSchema)?;
        if values.is_empty() || values.len() > 6 {
            return Err(BrowserError::InvalidSchema);
        }
        let op = values[0].as_str().ok_or(BrowserError::InvalidSchema)?;
        match op {
            "wait" => {
                let kind = values
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or(BrowserError::InvalidSchema)?;
                if kind == "contains" {
                    let needle = values
                        .get(2)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?;
                    validate_contains(needle)?;
                    let timeout = parse_timeout(values.get(3))?;
                    if values.len() != 4 {
                        return Err(BrowserError::InvalidSchema);
                    }
                    Ok(Self::WaitContains {
                        needle: needle.to_owned(),
                        timeout,
                    })
                } else {
                    let selector_value = values
                        .get(2)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?;
                    let selector = BrowserSelector::parse(kind, selector_value)?;
                    let timeout = parse_timeout(values.get(3))?;
                    let text_pattern = match values.get(4) {
                        None => None,
                        Some(Value::String(pattern)) => {
                            compile_pattern(pattern)?;
                            Some(pattern.clone())
                        }
                        _ => return Err(BrowserError::InvalidSchema),
                    };
                    let review_screenshot = match values.get(5) {
                        None => None,
                        Some(Value::String(value)) => match value.as_str() {
                            "update-image-placeholder" => Some(ReviewScreenshotMarker::Required),
                            "update-image-placeholder-optional" => {
                                Some(ReviewScreenshotMarker::Optional)
                            }
                            _ => return Err(BrowserError::UnsupportedCommand),
                        },
                        Some(_) => return Err(BrowserError::InvalidSchema),
                    };
                    if values.len() > 6 {
                        return Err(BrowserError::InvalidSchema);
                    }
                    Ok(Self::WaitForElement {
                        selector,
                        timeout,
                        text_pattern,
                        review_screenshot,
                    })
                }
            }
            "wait-element-visible" => {
                if values.len() != 4 {
                    return Err(BrowserError::InvalidSchema);
                }
                let selector = BrowserSelector::parse(
                    values
                        .get(1)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?,
                    values
                        .get(2)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?,
                )?;
                Ok(Self::WaitElementVisible {
                    selector,
                    timeout: parse_timeout(values.get(3))?,
                })
            }
            "text" => {
                if values.len() != 4 {
                    return Err(BrowserError::InvalidSchema);
                }
                let selector = BrowserSelector::parse(
                    values
                        .get(1)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?,
                    values
                        .get(2)
                        .and_then(Value::as_str)
                        .ok_or(BrowserError::InvalidSchema)?,
                )?;
                let value = values
                    .get(3)
                    .and_then(Value::as_str)
                    .ok_or(BrowserError::InvalidSchema)?;
                if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
                    return Err(BrowserError::InvalidSchema);
                }
                Ok(Self::Text {
                    selector,
                    value: Zeroizing::new(value.to_owned()),
                })
            }
            "click" => {
                if values.len() != 3 && values.len() != 4 {
                    return Err(BrowserError::InvalidSchema);
                }
                let optional = match values.get(3) {
                    None => false,
                    Some(Value::String(marker)) if marker == "optional" => true,
                    Some(_) => return Err(BrowserError::UnsupportedCommand),
                };
                Ok(Self::Click {
                    selector: BrowserSelector::parse(
                        values
                            .get(1)
                            .and_then(Value::as_str)
                            .ok_or(BrowserError::InvalidSchema)?,
                        values
                            .get(2)
                            .and_then(Value::as_str)
                            .ok_or(BrowserError::InvalidSchema)?,
                    )?,
                    optional,
                })
            }
            _ => Err(BrowserError::UnsupportedCommand),
        }
    }
}

fn parse_timeout(value: Option<&Value>) -> Result<Duration, BrowserError> {
    let seconds = value
        .and_then(Value::as_u64)
        .ok_or(BrowserError::InvalidSchema)?;
    if seconds == 0 || seconds > MAX_STEP_TIMEOUT.as_secs() {
        return Err(BrowserError::InvalidTimeout);
    }
    Ok(Duration::from_secs(seconds))
}

pub(super) fn parse_browser_urls(
    value: Option<&Value>,
    policy: &super::validation::BrowserPolicy,
) -> Result<Vec<url::Url>, BrowserError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or(BrowserError::InvalidSchema)?;
    if values.len() > MAX_STEPS {
        return Err(BrowserError::StepLimit);
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let text = match value {
            Value::String(text) => text.as_str(),
            Value::Object(object) => {
                if object
                    .keys()
                    .any(|key| !["url", "method"].contains(&key.as_str()))
                    || object
                        .get("method")
                        .and_then(Value::as_str)
                        .is_some_and(|method| method != "GET")
                {
                    return Err(BrowserError::UnsupportedCommand);
                }
                object
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or(BrowserError::InvalidSchema)?
            }
            _ => return Err(BrowserError::InvalidSchema),
        };
        if text.len() > MAX_MATCH_BYTES {
            return Err(BrowserError::InvalidSchema);
        }
        let url = url::Url::parse(text).map_err(|_| BrowserError::InvalidSchema)?;
        policy.validate_url(&url)?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(BrowserError::InvalidSchema);
        }
        if !parsed.iter().any(|candidate| candidate == &url) {
            parsed.push(url);
        }
    }
    Ok(parsed)
}

pub fn parse_browser_entries(value: &Value) -> Result<Vec<BrowserEntry>, BrowserError> {
    let values = value.as_array().ok_or(BrowserError::InvalidSchema)?;
    if values.is_empty() || values.len() > MAX_STEPS {
        return Err(BrowserError::InvalidSchema);
    }
    values.iter().map(BrowserEntry::parse).collect()
}

/// Parse and consume a browser value while clearing input JSON strings.
pub fn parse_browser_entries_owned(mut value: Value) -> Result<Vec<BrowserEntry>, BrowserError> {
    let result = parse_browser_entries(&value);
    zeroize_value(&mut value);
    result
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_value),
        Value::Object(values) => values.values_mut().for_each(zeroize_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
