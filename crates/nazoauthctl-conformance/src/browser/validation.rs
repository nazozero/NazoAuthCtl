use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use regex::Regex;
use url::Url;

use crate::origin::Origin;

use super::BrowserError;

pub(super) const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const MAX_STEP_TIMEOUT: Duration = Duration::from_secs(300);
pub(super) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const MAX_STEPS: usize = 256;
pub(super) const MAX_MATCH_BYTES: usize = 4096;
pub(super) const MAX_SELECTOR_BYTES: usize = 4096;
pub(super) const MAX_TEXT_BYTES: usize = 64 * 1024;
pub(super) const MAX_REDIRECTS: usize = 3;

pub(super) fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']).to_ascii_lowercase();
    normalized == "localhost"
        || normalized == "localhost.localdomain"
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// A target origin accepted by the browser policy. Production targets must
/// be HTTPS; plaintext HTTP is only accepted for an explicitly loopback
/// development target.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserTargetOrigin {
    url: Url,
}

impl BrowserTargetOrigin {
    pub fn parse(value: &str) -> Result<Self, BrowserError> {
        let url = Url::parse(value.trim()).map_err(|_| BrowserError::InvalidOrigin)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(BrowserError::InvalidOrigin);
        }
        if url.scheme() == "http"
            && !is_loopback_host(url.host_str().ok_or(BrowserError::InvalidOrigin)?)
        {
            return Err(BrowserError::InsecureTarget);
        }
        let mut canonical = url;
        canonical.set_path("");
        Ok(Self { url: canonical })
    }

    pub fn from_origin(origin: &Origin) -> Result<Self, BrowserError> {
        Self::parse(origin.as_str())
    }

    pub fn as_url(&self) -> &Url {
        &self.url
    }

    pub(super) fn allows(&self, candidate: &Url) -> bool {
        same_origin(&self.url, candidate)
    }
}

impl fmt::Debug for BrowserTargetOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BrowserTargetOrigin")
            .field(&self.url.origin().ascii_serialization())
            .finish()
    }
}

/// The only URLs a browser session may visit. Navigation to a third-party
/// redirect is a hard error, including redirects hidden behind WebDriver.
#[derive(Clone, Debug)]
pub struct BrowserPolicy {
    pub target_origin: BrowserTargetOrigin,
    pub suite_origin: Origin,
    pub limits: BrowserLimits,
}

impl BrowserPolicy {
    pub fn new(
        target_origin: BrowserTargetOrigin,
        suite_origin: Origin,
    ) -> Result<Self, BrowserError> {
        let policy = Self {
            target_origin,
            suite_origin,
            limits: BrowserLimits::default(),
        };
        policy.limits.validate()?;
        Ok(policy)
    }

    pub fn with_limits(mut self, limits: BrowserLimits) -> Result<Self, BrowserError> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    pub fn allows_url(&self, url: &Url) -> bool {
        (self.target_origin.allows(url) || self.suite_origin.same_origin_url(url))
            && matches!(url.scheme(), "https" | "http")
    }

    pub(super) fn validate_url(&self, url: &Url) -> Result<(), BrowserError> {
        if self.allows_url(url) {
            Ok(())
        } else {
            Err(BrowserError::CrossOriginNavigation)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BrowserLimits {
    pub max_steps: usize,
    pub max_redirects: usize,
    pub max_step_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for BrowserLimits {
    fn default() -> Self {
        Self {
            max_steps: MAX_STEPS,
            max_redirects: MAX_REDIRECTS,
            max_step_timeout: MAX_STEP_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl BrowserLimits {
    fn validate(self) -> Result<(), BrowserError> {
        if self.max_steps == 0
            || self.max_steps > MAX_STEPS
            || self.max_redirects > MAX_REDIRECTS
            || self.max_step_timeout.is_zero()
            || self.max_step_timeout > MAX_STEP_TIMEOUT
            || self.poll_interval.is_zero()
        {
            return Err(BrowserError::InvalidLimits);
        }
        Ok(())
    }
}

pub(super) fn validate_contains(value: &str) -> Result<(), BrowserError> {
    if value.is_empty()
        || value.len() > MAX_MATCH_BYTES
        || value.chars().any(char::is_control)
        || value.contains("://")
        || value.contains("..")
    {
        return Err(BrowserError::InvalidSchema);
    }
    Ok(())
}

pub(super) fn compile_pattern(value: &str) -> Result<Regex, BrowserError> {
    if value.len() > MAX_MATCH_BYTES || value.chars().any(char::is_control) {
        return Err(BrowserError::InvalidSchema);
    }
    Regex::new(value).map_err(|_| BrowserError::InvalidPattern)
}

pub(super) fn validate_match_pattern(value: &str, max: usize) -> Result<(), BrowserError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(BrowserError::InvalidSchema);
    }
    Ok(())
}

pub(super) fn glob_matches(pattern: &str, value: &str) -> bool {
    let mut remainder = value;
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return false;
    };
    if !remainder.starts_with(first) {
        return false;
    }
    remainder = &remainder[first.len()..];
    let mut suffixes: Vec<&str> = parts.collect();
    let last = suffixes.pop().unwrap_or("");
    for part in suffixes {
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    remainder.ends_with(last)
}

pub(super) fn redacted_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

pub(super) fn same_origin(expected: &Url, actual: &Url) -> bool {
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
        && actual.username().is_empty()
        && actual.password().is_none()
}
