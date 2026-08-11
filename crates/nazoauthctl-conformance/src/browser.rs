//! Rust-native browser automation for the OpenID Foundation Suite.
//!
//! Suite browser values are data, not scripts. The schema/parser and origin
//! validation live in private modules; this file owns the driver-facing
//! execution state machine and its public orchestration traits.

use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use thiserror::Error;
use url::Url;

#[cfg(test)]
use crate::origin::Origin;

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
    #[error("browser redirect limit exceeded")]
    RedirectLimit,
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

mod openid4vci;
mod openid4vp;
mod parser;
mod plan;
mod schema;
mod validation;
mod webdriver;

pub use openid4vci::{
    OpenId4VciError, OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver,
    OpenId4VciModule,
};
pub use openid4vp::{
    ConformanceBinding, OpenId4VpError, OpenId4VpPresentation, OpenId4VpStartRequest,
    OpenId4VpVerifier, OpenId4VpVerifierClient,
};
pub use parser::{parse_browser_entries, parse_browser_entries_owned};
pub use plan::OpenId4VcBrowserState;
pub use schema::{BrowserCommand, BrowserEntry, BrowserSelector, BrowserTask};
pub use validation::{BrowserLimits, BrowserPolicy, BrowserTargetOrigin};
pub use webdriver::{ManagedWebDriver, WebDriverClient, WebDriverEndpoint};

#[cfg(test)]
use validation::MAX_TEXT_BYTES;
use validation::{
    DEFAULT_STEP_TIMEOUT, MAX_MATCH_BYTES, compile_pattern, glob_matches, redacted_origin,
    validate_match_pattern,
};

/// Driver abstraction used both by WebDriver and deterministic tests. A
/// driver never receives a URL before policy checks.
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
/// in `WAITING`. This trait drives browser work only and returns no Suite
/// result, preserving the official PASS/FAIL decision.
pub trait BrowserAutomation: Send {
    fn execute(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
    ) -> Result<BrowserRunReport, BrowserError>;

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError>;

    /// Wait for an exact browser URL after an out-of-band flow, such as an
    /// OpenID4VP verifier start. Existing implementations fail closed unless
    /// they opt into URL polling.
    fn wait_for_url(&mut self, expected: &Url, timeout: Duration) -> Result<(), BrowserError> {
        let _ = (expected, timeout);
        Err(BrowserError::UnsupportedCommand)
    }
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
    redirects: usize,
    last_url: Option<Url>,
}

impl<D: BrowserDriver> BrowserExecutor<D> {
    pub fn new(driver: D, policy: BrowserPolicy) -> Self {
        Self {
            driver,
            policy,
            entry_uses: HashMap::new(),
            steps: 0,
            redirects: 0,
            last_url: None,
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
                    let current = self.ensure_current_url()?;
                    if current.as_str().contains(needle) {
                        return Ok(());
                    }
                    // `contains` is primarily a URL matcher. Page source is
                    // also checked for OpenID4VC callback markers rendered
                    // without a URL change.
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
            BrowserCommand::Click { selector, optional } => {
                let element = match self.driver.find_element(selector) {
                    Ok(element) => element,
                    Err(BrowserError::ElementNotFound) if *optional => return Ok(()),
                    Err(error) => return Err(error),
                };
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
        if let Some(previous) = &self.last_url
            && previous != &current
        {
            self.redirects = self.redirects.saturating_add(1);
            if self.redirects > self.policy.limits.max_redirects {
                return Err(BrowserError::RedirectLimit);
            }
        }
        self.last_url = Some(current.clone());
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
        self.redirects = 0;
        self.last_url = None;
        // Match the Suite entry against the URL that was requested.  The
        // first navigation commonly redirects `/authorize` to hosted login
        // or consent; selecting after navigation would lose the entry whose
        // tasks are explicitly responsible for those bounded redirects.
        let entry_index = self.matching_entry(authorization_url, entries)?;
        self.navigate(authorization_url)?;
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
        self.redirects = 0;
        self.last_url = Some(url.clone());
        self.driver.navigate(url)?;
        self.ensure_current_url().map(|_| ())
    }

    fn wait_for_url(&mut self, expected: &Url, timeout: Duration) -> Result<(), BrowserError> {
        self.policy.validate_url(expected)?;
        let deadline = self.deadline(timeout);
        loop {
            let current = self.ensure_current_url()?;
            if current == *expected {
                return Ok(());
            }
            self.sleep_until(deadline)?;
        }
    }
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

        assert!(matches!(
            BrowserCommand::try_from(&json!(["click", "id", "logout", "optional"])),
            Ok(BrowserCommand::Click { optional: true, .. })
        ));
        assert!(matches!(
            BrowserCommand::try_from(&json!(["click", "id", "logout", "ignored"])),
            Err(BrowserError::UnsupportedCommand)
        ));
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
            "comment": "NazoAuth conformance browser automation.",
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

        let invalid_comment = json!({
            "comment": "x".repeat(MAX_TEXT_BYTES + 1),
            "match": "https://issuer.example/authorize*",
            "tasks": []
        });
        assert!(matches!(
            BrowserEntry::parse(&invalid_comment),
            Err(BrowserError::InvalidSchema)
        ));
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

    struct RedirectingMockDriver {
        current: Url,
        cross_origin: bool,
    }

    impl BrowserDriver for RedirectingMockDriver {
        fn navigate(&mut self, _url: &Url) -> Result<(), BrowserError> {
            self.current = if self.cross_origin {
                Url::parse("https://evil.example/ui/auth").expect("url")
            } else {
                Url::parse("https://issuer.example/ui/auth").expect("url")
            };
            Ok(())
        }

        fn current_url(&mut self) -> Result<Url, BrowserError> {
            Ok(self.current.clone())
        }

        fn page_source(&mut self) -> Result<String, BrowserError> {
            Ok(String::new())
        }

        fn find_element(&mut self, _selector: &BrowserSelector) -> Result<String, BrowserError> {
            Ok("element".to_owned())
        }

        fn element_displayed(&mut self, _element: &str) -> Result<bool, BrowserError> {
            Ok(true)
        }

        fn element_text(&mut self, _element: &str) -> Result<String, BrowserError> {
            Ok(String::new())
        }

        fn element_send_keys(&mut self, _element: &str, _value: &str) -> Result<(), BrowserError> {
            Ok(())
        }

        fn element_click(&mut self, _element: &str) -> Result<(), BrowserError> {
            self.current = match self.current.path() {
                "/ui/auth" => Url::parse("https://issuer.example/ui/consent").expect("url"),
                "/ui/consent" => Url::parse("https://suite.example/test/callback").expect("url"),
                _ => self.current.clone(),
            };
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

    #[test]
    fn executor_matches_initial_authorize_entry_before_hosted_redirects() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = RedirectingMockDriver {
            current: Url::parse("https://issuer.example/authorize?x=1").expect("url"),
            cross_origin: false,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        let entries = vec![
            BrowserEntry::parse(&json!({
                "match": "https://issuer.example/authorize*",
                "tasks": [
                    {
                        "match": "https://issuer.example/ui/auth*",
                        "commands": [["click", "id", "login"]]
                    },
                    {
                        "match": "https://issuer.example/ui/consent*",
                        "commands": [["click", "id", "approve"]]
                    },
                    {
                        "match": "https://suite.example/test/callback*",
                        "commands": []
                    }
                ]
            }))
            .expect("entry"),
        ];
        executor
            .execute(
                &Url::parse("https://issuer.example/authorize?x=1").expect("url"),
                &entries,
            )
            .expect("redirect flow");
    }

    #[test]
    fn executor_rejects_cross_origin_redirect_after_initial_match() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = RedirectingMockDriver {
            current: Url::parse("https://issuer.example/authorize?x=1").expect("url"),
            cross_origin: true,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        let entries = vec![
            BrowserEntry::parse(&json!({
                "match": "https://issuer.example/authorize*",
                "tasks": []
            }))
            .expect("entry"),
        ];
        assert_eq!(
            executor
                .execute(
                    &Url::parse("https://issuer.example/authorize?x=1").expect("url"),
                    &entries,
                )
                .expect_err("cross-origin redirect"),
            BrowserError::CrossOriginNavigation
        );
    }
}
