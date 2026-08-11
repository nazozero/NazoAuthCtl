use std::fmt;

use serde_json::Value;
use url::Url;

use super::BrowserError;
use super::parser::parse_browser_urls;
use super::validation::BrowserPolicy;

/// Suite browser work is represented as a bounded plan of URLs rather than
/// executable command tuples. The upstream browser object also exposes other
/// interaction channels; this type deliberately projects only `urls` and
/// `visited`. `visited` is bookkeeping only and is never trusted as evidence
/// that a Suite module passed.
#[derive(Clone)]
pub struct OpenId4VcBrowserState {
    urls: Vec<Url>,
    visited: Vec<Url>,
}

impl fmt::Debug for OpenId4VcBrowserState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VcBrowserState")
            .field("url_count", &self.urls.len())
            .field("visited_count", &self.visited.len())
            .finish()
    }
}

impl OpenId4VcBrowserState {
    pub fn parse(value: &Value, policy: &BrowserPolicy) -> Result<Self, BrowserError> {
        let object = value.as_object().ok_or(BrowserError::InvalidSchema)?;
        let urls = parse_browser_urls(
            Some(object.get("urls").ok_or(BrowserError::InvalidSchema)?),
            policy,
        )?;
        let visited = parse_browser_urls(object.get("visited"), policy)?;
        if visited
            .iter()
            .any(|seen| !urls.iter().any(|url| url == seen))
        {
            return Err(BrowserError::InvalidSchema);
        }
        Ok(Self { urls, visited })
    }

    pub fn pending_url(&self) -> Option<&Url> {
        self.urls
            .iter()
            .find(|url| !self.visited.iter().any(|seen| seen == *url))
    }

    pub fn mark_visited(&mut self, url: &Url, policy: &BrowserPolicy) -> Result<(), BrowserError> {
        policy.validate_url(url)?;
        if !self.urls.iter().any(|candidate| candidate == url) {
            return Err(BrowserError::InvalidSchema);
        }
        if !self.visited.iter().any(|seen| seen == url) {
            self.visited.push(url.clone());
        }
        Ok(())
    }

    pub fn urls(&self) -> &[Url] {
        &self.urls
    }

    pub fn visited(&self) -> &[Url] {
        &self.visited
    }
}
