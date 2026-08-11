//! Rust-native browser automation for the OpenID Foundation Suite.
//!
//! The Suite's `browser` value is deliberately treated as data, not as a
//! script.  Only the small command vocabulary used by the official runner is
//! accepted.  Browser control is performed through the W3C WebDriver HTTP
//! protocol; no Python, Node, shell, or JavaScript runner is involved.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::origin::Origin;

mod webdriver;
pub use webdriver::{ManagedWebDriver, WebDriverClient, WebDriverEndpoint};

const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STEP_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_STEPS: usize = 256;
const MAX_MATCH_BYTES: usize = 4096;
const MAX_SELECTOR_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 3;

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']).to_ascii_lowercase();
    normalized == "localhost"
        || normalized == "localhost.localdomain"
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// A target origin accepted by the browser policy.  Production targets must
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

    fn allows(&self, candidate: &Url) -> bool {
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

/// The only URLs a browser session may visit.  Navigation to a third-party
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

    fn validate_url(&self, url: &Url) -> Result<(), BrowserError> {
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

/// A Suite `browser` entry.  Secret values are kept only in `BrowserCommand`;
/// this structure intentionally has no custom Debug implementation that could
/// expose them.
pub struct BrowserEntry {
    pub match_pattern: String,
    pub match_limit: Option<u32>,
    pub tasks: Vec<BrowserTask>,
}

impl fmt::Debug for BrowserEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserEntry")
            .field("match_pattern", &self.match_pattern)
            .field("match_limit", &self.match_limit)
            .field("tasks", &self.tasks.len())
            .finish()
    }
}

pub struct BrowserTask {
    pub task: Option<String>,
    pub optional: bool,
    pub match_pattern: Option<String>,
    pub commands: Vec<BrowserCommand>,
}

impl fmt::Debug for BrowserTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTask")
            .field("task", &self.task)
            .field("optional", &self.optional)
            .field("match_pattern", &self.match_pattern)
            .field("commands", &self.commands.len())
            .finish()
    }
}

impl BrowserTask {
    fn parse(value: &Value) -> Result<Self, BrowserError> {
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
        reject_unknown_keys(object, &["match", "match-limit", "tasks"])?;
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

/// OpenID4VC verifier modules expose browser work as a small state object,
/// rather than Suite command tuples.  Only target-origin `/authorize` URLs
/// with a query are accepted; `visited` is retained to make repeated modules
/// deterministic and is never trusted as proof of completion.
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
        reject_unknown_keys(object, &["urls", "visited"])?;
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
        let text = value.as_str().ok_or(BrowserError::InvalidSchema)?;
        if text.len() > MAX_MATCH_BYTES {
            return Err(BrowserError::InvalidSchema);
        }
        let url = Url::parse(text).map_err(|_| BrowserError::InvalidSchema)?;
        policy.validate_url(&url)?;
        if url.path() != "/authorize"
            || url.query().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
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

/// Parse and consume a browser value while clearing the input JSON strings.
/// Callers handling a materialized private plan should prefer this variant so
/// credentials do not remain in the source `Value` after command parsing.
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

/// A parsed selector accepted by WebDriver.  `contains` is not passed to the
/// driver as CSS; it is handled by page-source/URL matching, preventing XPath
/// or CSS injection from Suite configuration.
#[derive(Clone, Eq, PartialEq)]
pub enum BrowserSelector {
    Id(String),
    Css(String),
}

impl fmt::Debug for BrowserSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Id(_) => "Id(<redacted>)",
            Self::Css(_) => "Css(<redacted>)",
        })
    }
}

impl BrowserSelector {
    fn parse(kind: &str, value: &str) -> Result<Self, BrowserError> {
        if value.is_empty()
            || value.len() > MAX_SELECTOR_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(BrowserError::InvalidSchema);
        }
        match kind {
            "id" => Ok(Self::Id(value.to_owned())),
            "css" => Ok(Self::Css(value.to_owned())),
            _ => Err(BrowserError::UnsupportedCommand),
        }
    }
}

/// The supported subset of the official Suite browser command tuples.
pub enum BrowserCommand {
    WaitForElement {
        selector: BrowserSelector,
        timeout: Duration,
        text_pattern: Option<String>,
    },
    WaitElementVisible {
        selector: BrowserSelector,
        timeout: Duration,
    },
    WaitContains {
        needle: String,
        timeout: Duration,
    },
    Text {
        selector: BrowserSelector,
        value: Zeroizing<String>,
    },
    Click {
        selector: BrowserSelector,
    },
}

impl fmt::Debug for BrowserCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::WaitForElement { .. } => "wait",
            Self::WaitElementVisible { .. } => "wait-element-visible",
            Self::WaitContains { .. } => "wait-contains",
            Self::Text { .. } => "text",
            Self::Click { .. } => "click",
        };
        formatter.write_str(kind)
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
                    if values.len() == 6
                        && values[5].as_str() != Some("update-image-placeholder-optional")
                    {
                        return Err(BrowserError::UnsupportedCommand);
                    }
                    if values.len() > 6 {
                        return Err(BrowserError::InvalidSchema);
                    }
                    Ok(Self::WaitForElement {
                        selector,
                        timeout,
                        text_pattern,
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
                if values.len() != 3 {
                    return Err(BrowserError::InvalidSchema);
                }
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

fn validate_contains(value: &str) -> Result<(), BrowserError> {
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

fn compile_pattern(value: &str) -> Result<Regex, BrowserError> {
    if value.len() > MAX_MATCH_BYTES || value.chars().any(char::is_control) {
        return Err(BrowserError::InvalidSchema);
    }
    Regex::new(value).map_err(|_| BrowserError::InvalidPattern)
}

fn validate_match_pattern(value: &str, max: usize) -> Result<(), BrowserError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(BrowserError::InvalidSchema);
    }
    // A match is a simple glob.  Embedded URLs are checked against the
    // policy at execution time; arbitrary schemes are never navigated.
    Ok(())
}

/// Driver abstraction used both by the WebDriver implementation and by
/// deterministic tests.  A driver never receives a URL before policy checks.
pub trait BrowserDriver: Send {
    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError>;
    fn current_url(&mut self) -> Result<Url, BrowserError>;
    fn page_source(&mut self) -> Result<String, BrowserError>;
    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError>;
    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError>;
    fn element_text(&mut self, element: &str) -> Result<String, BrowserError>;
    fn element_send_keys(&mut self, element: &str, value: &str) -> Result<(), BrowserError>;
    fn element_click(&mut self, element: &str) -> Result<(), BrowserError>;
}

/// Contract consumed by the conformance orchestrator while a Suite module is
/// in `WAITING`.  Implementations must preserve official Suite results; this
/// trait only drives the browser and returns execution evidence.
pub trait BrowserAutomation: Send {
    fn execute(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
    ) -> Result<BrowserRunReport, BrowserError>;

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrowserRunReport {
    pub steps: usize,
    pub tasks: usize,
    pub entry_index: usize,
    pub final_origin: String,
}

pub struct BrowserExecutor<D> {
    driver: D,
    policy: BrowserPolicy,
    entry_uses: HashMap<usize, u32>,
    steps: usize,
}

impl<D: BrowserDriver> BrowserExecutor<D> {
    pub fn new(driver: D, policy: BrowserPolicy) -> Self {
        Self {
            driver,
            policy,
            entry_uses: HashMap::new(),
            steps: 0,
        }
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn policy(&self) -> &BrowserPolicy {
        &self.policy
    }

    pub fn run_commands(&mut self, commands: &[BrowserCommand]) -> Result<usize, BrowserError> {
        if commands.len() > self.policy.limits.max_steps.saturating_sub(self.steps) {
            return Err(BrowserError::StepLimit);
        }
        let mut executed = 0usize;
        for command in commands {
            self.execute_command(command)?;
            executed += 1;
            self.steps = self.steps.saturating_add(1);
            self.ensure_current_url()?;
        }
        Ok(executed)
    }

    pub fn run_command_values(&mut self, commands: &[Value]) -> Result<usize, BrowserError> {
        let parsed = commands
            .iter()
            .map(BrowserCommand::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        self.run_commands(&parsed)
    }

    fn execute_command(&mut self, command: &BrowserCommand) -> Result<(), BrowserError> {
        match command {
            BrowserCommand::WaitForElement {
                selector,
                timeout,
                text_pattern,
            } => {
                let deadline = self.deadline(*timeout);
                loop {
                    if let Ok(element) = self.driver.find_element(selector) {
                        if let Some(pattern) = text_pattern {
                            let text = self.driver.element_text(&element)?;
                            if compile_pattern(pattern)?.is_match(&text) {
                                return Ok(());
                            }
                        } else {
                            return Ok(());
                        }
                    }
                    self.sleep_until(deadline)?;
                }
            }
            BrowserCommand::WaitElementVisible { selector, timeout } => {
                let deadline = self.deadline(*timeout);
                loop {
                    if let Ok(element) = self.driver.find_element(selector)
                        && self.driver.element_displayed(&element)?
                    {
                        return Ok(());
                    }
                    self.sleep_until(deadline)?;
                }
            }
            BrowserCommand::WaitContains { needle, timeout } => {
                let deadline = self.deadline(*timeout);
                loop {
                    let current = self.driver.current_url()?;
                    self.policy.validate_url(&current)?;
                    if current.as_str().contains(needle) {
                        return Ok(());
                    }
                    // `contains` in the Suite runner is primarily a URL
                    // matcher.  Page source is also checked for OpenID4VC
                    // callback markers that are rendered without a URL change.
                    if self.driver.page_source()?.contains(needle) {
                        return Ok(());
                    }
                    self.sleep_until(deadline)?;
                }
            }
            BrowserCommand::Text { selector, value } => {
                let element = self.driver.find_element(selector)?;
                self.driver.element_send_keys(&element, value.as_str())
            }
            BrowserCommand::Click { selector } => {
                let element = self.driver.find_element(selector)?;
                self.driver.element_click(&element)
            }
        }
    }

    fn deadline(&self, timeout: Duration) -> Instant {
        Instant::now() + timeout.min(self.policy.limits.max_step_timeout)
    }

    fn sleep_until(&self, deadline: Instant) -> Result<(), BrowserError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(BrowserError::Timeout);
        }
        thread::sleep(remaining.min(self.policy.limits.poll_interval));
        Ok(())
    }

    fn ensure_current_url(&mut self) -> Result<Url, BrowserError> {
        let current = self.driver.current_url()?;
        self.policy.validate_url(&current)?;
        Ok(current)
    }

    fn matching_entry(
        &self,
        current: &Url,
        entries: &[BrowserEntry],
    ) -> Result<usize, BrowserError> {
        for (index, entry) in entries.iter().enumerate() {
            let Some(limit) = entry.match_limit else {
                if glob_matches(&entry.match_pattern, current.as_str()) {
                    return Ok(index);
                }
                continue;
            };
            if self.entry_uses.get(&index).copied().unwrap_or_default() >= limit {
                continue;
            }
            if glob_matches(&entry.match_pattern, current.as_str()) {
                return Ok(index);
            }
        }
        Err(BrowserError::NoMatchingEntry)
    }
}

impl<D: BrowserDriver> BrowserAutomation for BrowserExecutor<D> {
    fn execute(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
    ) -> Result<BrowserRunReport, BrowserError> {
        if entries.is_empty() {
            return Err(BrowserError::InvalidSchema);
        }
        self.policy.validate_url(authorization_url)?;
        self.navigate(authorization_url)?;
        let current = self.ensure_current_url()?;
        let entry_index = self.matching_entry(&current, entries)?;
        *self.entry_uses.entry(entry_index).or_default() += 1;
        let mut task_count = 0usize;
        let entry = &entries[entry_index];
        for task in &entry.tasks {
            if let Some(pattern) = task.match_pattern.as_deref() {
                validate_match_pattern(pattern, MAX_MATCH_BYTES)?;
                let deadline = self.deadline(DEFAULT_STEP_TIMEOUT);
                'wait_for_task: loop {
                    let current = self.ensure_current_url()?;
                    if glob_matches(pattern, current.as_str()) {
                        break;
                    }
                    if let Err(BrowserError::Timeout) = self.sleep_until(deadline) {
                        if task.optional {
                            break 'wait_for_task;
                        }
                        return Err(BrowserError::Timeout);
                    }
                }
            }
            self.run_commands(&task.commands)?;
            task_count += 1;
        }
        let final_url = self.ensure_current_url()?;
        Ok(BrowserRunReport {
            steps: self.steps,
            tasks: task_count,
            entry_index,
            final_origin: redacted_origin(&final_url),
        })
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
        self.policy.validate_url(url)?;
        self.driver.navigate(url)?;
        self.ensure_current_url().map(|_| ())
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    // Suite match strings use `*` as a whole-string wildcard.  Avoid regex
    // conversion so a Suite-provided pattern cannot become executable syntax.
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

fn redacted_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn same_origin(expected: &Url, actual: &Url) -> bool {
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
        && actual.username().is_empty()
        && actual.password().is_none()
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum BrowserError {
    #[error("browser endpoint is invalid")]
    InvalidEndpoint,
    #[error("plaintext browser endpoint must be loopback")]
    InsecureEndpoint,
    #[error("browser target origin is invalid")]
    InvalidOrigin,
    #[error("plaintext browser target must be loopback")]
    InsecureTarget,
    #[error("browser limits are invalid")]
    InvalidLimits,
    #[error("browser schema is invalid")]
    InvalidSchema,
    #[error("browser command is unsupported")]
    UnsupportedCommand,
    #[error("browser timeout expired")]
    Timeout,
    #[error("browser step limit exceeded")]
    StepLimit,
    #[error("browser redirect or navigation crossed the allowlist")]
    CrossOriginNavigation,
    #[error("browser entry did not match the current page")]
    NoMatchingEntry,
    #[error("browser command pattern is invalid")]
    InvalidPattern,
    #[error("browser command timeout is invalid")]
    InvalidTimeout,
    #[error("browser transport failed")]
    Transport,
    #[error("browser WebDriver protocol response is invalid")]
    Protocol,
    #[error("browser WebDriver rejected the request")]
    DriverRejected,
    #[error("browser response exceeds the size limit")]
    ResponseTooLarge,
    #[error("browser session is already started")]
    SessionAlreadyStarted,
    #[error("browser session is not started")]
    SessionNotStarted,
    #[error("browser element was not found")]
    ElementNotFound,
    #[error("chromedriver or chromium-driver was not found")]
    DriverUnavailable,
    #[error("managed browser driver failed to start")]
    DriverStartFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_remote_driver_is_rejected() {
        assert!(matches!(
            WebDriverEndpoint::parse("http://driver.example:9515"),
            Err(BrowserError::InsecureEndpoint)
        ));
        assert!(WebDriverEndpoint::parse("http://127.0.0.1:9515").is_ok());
    }

    #[test]
    fn target_http_is_only_loopback_and_suite_is_https() {
        assert!(BrowserTargetOrigin::parse("http://127.0.0.1:8080").is_ok());
        assert!(BrowserTargetOrigin::parse("http://issuer.example").is_err());
        assert!(Origin::parse("https://suite.example").is_ok());
    }

    #[test]
    fn command_parser_redacts_secret_debug_and_rejects_unknown_ops() {
        let command = BrowserCommand::try_from(&json!(["text", "id", "password", "super-secret"]))
            .expect("text");
        assert_eq!(format!("{command:?}"), "text");
        assert!(BrowserCommand::try_from(&json!(["execute-script", "alert(1)"])).is_err());
    }

    #[test]
    fn contains_is_not_a_selector_and_rejects_urls() {
        let command = BrowserCommand::try_from(&json!(["wait", "contains", "/ui/consent", 30]))
            .expect("contains");
        assert!(matches!(command, BrowserCommand::WaitContains { .. }));
        assert!(
            BrowserCommand::try_from(&json!(["wait", "contains", "https://evil.example", 30]))
                .is_err()
        );
    }

    #[test]
    fn browser_entry_parses_official_nazo_schema() {
        let value = json!({
            "match": "https://issuer.example/authorize*",
            "match-limit": 1,
            "tasks": [{
                "task": "Complete login page",
                "match": "https://issuer.example/ui/auth*",
                "commands": [
                    ["wait-element-visible", "id", "nazo-login-email", 30],
                    ["text", "id", "nazo-login-email", "user@example.test"],
                    ["wait", "contains", "/ui/consent", 30]
                ]
            }]
        });
        assert!(BrowserEntry::parse(&value).is_ok());
    }

    struct MockDriver {
        current: Url,
        source: String,
        found: bool,
        displayed: bool,
        clicked: bool,
    }

    impl BrowserDriver for MockDriver {
        fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
            self.current = url.clone();
            Ok(())
        }
        fn current_url(&mut self) -> Result<Url, BrowserError> {
            Ok(self.current.clone())
        }
        fn page_source(&mut self) -> Result<String, BrowserError> {
            Ok(self.source.clone())
        }
        fn find_element(&mut self, _selector: &BrowserSelector) -> Result<String, BrowserError> {
            if self.found {
                Ok("e".to_owned())
            } else {
                Err(BrowserError::ElementNotFound)
            }
        }
        fn element_displayed(&mut self, _element: &str) -> Result<bool, BrowserError> {
            Ok(self.displayed)
        }
        fn element_text(&mut self, _element: &str) -> Result<String, BrowserError> {
            Ok(self.source.clone())
        }
        fn element_send_keys(&mut self, _element: &str, _value: &str) -> Result<(), BrowserError> {
            Ok(())
        }
        fn element_click(&mut self, _element: &str) -> Result<(), BrowserError> {
            self.clicked = true;
            Ok(())
        }
    }

    #[test]
    fn executor_rejects_cross_origin_navigation_and_runs_mock_flow() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = MockDriver {
            current: Url::parse("https://issuer.example").expect("url"),
            source: "/ui/consent".to_owned(),
            found: true,
            displayed: true,
            clicked: false,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        assert!(matches!(
            executor.navigate(&Url::parse("https://evil.example/").expect("url")),
            Err(BrowserError::CrossOriginNavigation)
        ));
        let entries = vec![BrowserEntry::parse(&json!({
            "match": "https://issuer.example/authorize*",
            "tasks": [{
                "match": "https://issuer.example/authorize*",
                "commands": [["wait", "contains", "/ui/consent", 1], ["click", "id", "nazo-consent-approve"]]
            }]
        })).expect("entry")];
        let report = executor
            .execute(
                &Url::parse("https://issuer.example/authorize?x=1").expect("url"),
                &entries,
            )
            .expect("flow");
        assert_eq!(report.steps, 2);
    }
}
