use std::fmt;

use serde_json::Value;
use url::Url;

use super::BrowserError;
use super::validation::{BrowserPolicy, MAX_MATCH_BYTES, MAX_STEPS};

/// Suite browser work is represented as bounded URLs rather than executable
/// command tuples. `visited` is bookkeeping only and is never trusted as
/// evidence that a Suite module passed. Verifier tests additionally expose a
/// same-origin URI-input endpoint where the verifier authorization request is
/// delivered before ordinary browser work can begin.
#[derive(Clone)]
pub struct BrowserRunnerState {
    urls: Vec<Url>,
    visited: Vec<Url>,
    uri_input_submit_urls: Vec<Url>,
}

impl fmt::Debug for BrowserRunnerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRunnerState")
            .field("url_count", &self.urls.len())
            .field("visited_count", &self.visited.len())
            .field("uri_input_count", &self.uri_input_submit_urls.len())
            .finish()
    }
}

impl BrowserRunnerState {
    pub fn parse(value: &Value, policy: &BrowserPolicy) -> Result<Self, BrowserError> {
        let object = value.as_object().ok_or(BrowserError::InvalidSchema)?;
        let urls = parse_browser_urls(
            Some(object.get("urls").ok_or(BrowserError::InvalidSchema)?),
            policy,
        )?;
        let visited = parse_browser_urls(object.get("visited"), policy)?;
        let uri_input_submit_urls =
            parse_uri_input_submit_urls(object.get("uriInputRequests"), policy)?;
        Ok(Self {
            urls,
            visited,
            uri_input_submit_urls,
        })
    }

    pub fn pending_url(&self) -> Option<&Url> {
        self.urls
            .iter()
            .find(|url| !self.visited.iter().any(|seen| seen == *url))
    }

    pub fn urls(&self) -> &[Url] {
        &self.urls
    }

    pub fn visited(&self) -> &[Url] {
        &self.visited
    }

    /// Reproduce the Suite UI's URI-input action: keep the verifier-generated
    /// authorization query and deliver it to the runner's authoritative
    /// same-origin submit endpoint.
    pub fn verifier_submission_url(&self, authorization_url: &Url) -> Result<Url, BrowserError> {
        let [submit_url] = self.uri_input_submit_urls.as_slice() else {
            return Err(BrowserError::InvalidSchema);
        };
        let query = authorization_url
            .query()
            .filter(|query| !query.is_empty())
            .ok_or(BrowserError::InvalidSchema)?;
        if submit_url.query().is_some() {
            return Err(BrowserError::InvalidSchema);
        }
        let mut delivery_url = submit_url.clone();
        delivery_url.set_query(Some(query));
        Ok(delivery_url)
    }
}

fn parse_uri_input_submit_urls(
    value: Option<&Value>,
    policy: &BrowserPolicy,
) -> Result<Vec<Url>, BrowserError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let requests = value.as_array().ok_or(BrowserError::InvalidSchema)?;
    if requests.len() > MAX_STEPS {
        return Err(BrowserError::StepLimit);
    }
    let mut submit_urls = Vec::with_capacity(requests.len());
    for request in requests {
        let submit_url = request
            .as_object()
            .and_then(|request| request.get("submitUrl"))
            .and_then(Value::as_str)
            .ok_or(BrowserError::InvalidSchema)?;
        if submit_url.len() > MAX_MATCH_BYTES {
            return Err(BrowserError::InvalidSchema);
        }
        let submit_url = Url::parse(submit_url).map_err(|_| BrowserError::InvalidSchema)?;
        if !policy.suite_origin.same_origin_url(&submit_url) {
            return Err(BrowserError::CrossOriginNavigation);
        }
        if submit_url.fragment().is_some() {
            return Err(BrowserError::InvalidSchema);
        }
        submit_urls.push(submit_url);
    }
    Ok(submit_urls)
}

fn parse_browser_urls(
    value: Option<&Value>,
    policy: &BrowserPolicy,
) -> Result<Vec<Url>, BrowserError> {
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
        let url = Url::parse(text).map_err(|_| BrowserError::InvalidSchema)?;
        policy.validate_url(&url)?;
        if url.fragment().is_some() {
            return Err(BrowserError::InvalidSchema);
        }
        if !parsed.iter().any(|candidate| candidate == &url) {
            parsed.push(url);
        }
    }
    Ok(parsed)
}
