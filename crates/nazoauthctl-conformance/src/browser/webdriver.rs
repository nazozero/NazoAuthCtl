//! W3C WebDriver transport and managed local driver lifecycle.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::validation::{MAX_TEXT_BYTES, is_loopback_host};
use super::{
    BrowserConsoleLogDiagnostic, BrowserConsoleLogMessageDiagnostic, BrowserDriver, BrowserError,
    BrowserPageRuntimeDiagnostic, BrowserSelector, WebDriverProtocolDiagnostic,
    decode_webdriver_png,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 256;
const W3C_ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";
const MAX_RUNTIME_ROOT_CHILDREN: usize = 4096;
const MAX_RUNTIME_MODULE_SCRIPTS: usize = 128;
const MAX_RUNTIME_RESOURCE_SCAN: usize = 512;
const MAX_RUNTIME_UI_ASSET_RESOURCES: usize = 128;
const MAX_RUNTIME_RESPONSE_STATUSES: usize = 16;
const MAX_RUNTIME_RECEIPT_RESOURCES: usize = 4;
const MAX_RUNTIME_RECEIPT_STATUSES: usize = 4;
const MAX_BROWSER_LOG_ENTRIES: usize = 128;
const MAX_BROWSER_LOG_MESSAGE_BYTES: usize = 16 * 1024;
const PAGE_RUNTIME_DIAGNOSTIC_SCRIPT: &str = r#"return (() => {
  const cap = (value, maximum) => Math.min(Math.max(0, Number(value) || 0), maximum);
  const root = document.getElementById('root');
  const rawChildCount = root ? root.childElementCount : 0;
  const rawModuleScriptCount = document.querySelectorAll('script[type="module"]').length;
  let resourceScanCount = 0;
  let resourceScanCapped = false;
  let assetCount = 0;
  let transferPositive = 0;
  let decodedPositive = 0;
  let statusCapped = false;
  const statuses = new Set();
  let assetCapped = false;
  let receiptCount = 0;
  let receiptCapped = false;
  let receiptTransferPositive = 0;
  let receiptDecodedPositive = 0;
  let receiptStatusCapped = false;
  const receiptStatuses = new Set();
  try {
    for (const entry of performance.getEntriesByType('resource')) {
      if (resourceScanCount >= 512) { resourceScanCapped = true; break; }
      resourceScanCount += 1;
      let resource;
      try { resource = new URL(entry.name, location.href); } catch (_) { continue; }
      if (resource.origin !== location.origin) { continue; }
      const status = Number(entry.responseStatus);
      if (resource.pathname === '/openid4vp/verification-receipts' && !resource.search && !resource.hash) {
        if (receiptCount >= 4) { receiptCapped = true; continue; }
        receiptCount += 1;
        if (entry.transferSize > 0) { receiptTransferPositive += 1; }
        if (entry.decodedBodySize > 0) { receiptDecodedPositive += 1; }
        if (Number.isInteger(status) && status >= 100 && status <= 599) {
          if (receiptStatuses.size < 4 || receiptStatuses.has(status)) { receiptStatuses.add(status); } else { receiptStatusCapped = true; }
        }
      }
      if (!resource.pathname.startsWith('/ui/assets/')) { continue; }
      if (assetCount >= 128) { assetCapped = true; continue; }
      assetCount += 1;
      if (entry.transferSize > 0) { transferPositive += 1; }
      if (entry.decodedBodySize > 0) { decodedPositive += 1; }
      if (Number.isInteger(status) && status >= 100 && status <= 599) {
        if (statuses.size < 16 || statuses.has(status)) { statuses.add(status); } else { statusCapped = true; }
      }
    }
  } catch (_) {}
  const readyState = ['loading', 'interactive', 'complete'].includes(document.readyState)
    ? document.readyState : 'other';
  return {
    ready_state: readyState,
    root_present: Boolean(root),
    root_child_element_count: cap(rawChildCount, 4096),
    root_child_element_count_capped: rawChildCount > 4096,
    has_vp_verification_result: Boolean(document.querySelector('[data-testid="vp-verification-result"]')),
    module_script_count: cap(rawModuleScriptCount, 128),
    module_script_count_capped: rawModuleScriptCount > 128,
    resource_scan_count: resourceScanCount,
    resource_scan_count_capped: resourceScanCapped,
    same_origin_ui_asset_resource_count: assetCount,
    same_origin_ui_asset_resource_count_capped: assetCapped,
    ui_asset_response_statuses: Array.from(statuses).sort((a, b) => a - b),
    ui_asset_response_statuses_capped: statusCapped,
    ui_asset_transfer_size_positive_count: transferPositive,
    ui_asset_decoded_size_positive_count: decodedPositive,
    verification_receipt_resource_count: receiptCount,
    verification_receipt_resource_count_capped: receiptCapped,
    verification_receipt_response_statuses: Array.from(receiptStatuses).sort((a, b) => a - b),
    verification_receipt_response_statuses_capped: receiptStatusCapped,
    verification_receipt_transfer_size_positive_count: receiptTransferPositive,
    verification_receipt_decoded_size_positive_count: receiptDecodedPositive,
    title_kind: document.title === 'NazoAuth' ? 'nazoauth' : 'other',
    navigator_online: Boolean(navigator.onLine)
  };
})();"#;

struct WebDriverResponse {
    value: Value,
    diagnostic: WebDriverProtocolDiagnostic,
}

impl WebDriverResponse {
    fn protocol(&self) -> BrowserError {
        BrowserError::ProtocolDiagnostic(self.diagnostic.clone())
    }
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SESSION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The browser endpoint may be a local, plaintext chromedriver endpoint.  A
/// plaintext endpoint on any non-loopback host is rejected to avoid leaking
/// credentials to an untrusted network peer.
#[derive(Clone)]
pub struct WebDriverEndpoint {
    url: Url,
}

impl WebDriverEndpoint {
    pub fn parse(value: &str) -> Result<Self, BrowserError> {
        let mut url = Url::parse(value.trim()).map_err(|_| BrowserError::InvalidEndpoint)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(BrowserError::InvalidEndpoint);
        }
        let host = url.host_str().ok_or(BrowserError::InvalidEndpoint)?;
        if url.scheme() == "http" && !is_loopback_host(host) {
            return Err(BrowserError::InsecureEndpoint);
        }
        if url.path().contains("..") || url.path().contains("//") {
            return Err(BrowserError::InvalidEndpoint);
        }
        let path = url.path().trim_end_matches('/').to_owned();
        url.set_path(if path.is_empty() { "/" } else { &path });
        Ok(Self { url })
    }

    pub fn as_url(&self) -> &Url {
        &self.url
    }

    fn endpoint_url(&self, suffix: &str) -> Result<Url, BrowserError> {
        if !suffix.starts_with('/') || suffix.contains("..") || suffix.contains("//") {
            return Err(BrowserError::InvalidEndpoint);
        }
        let mut value = self.url.clone();
        let base = self.url.path().trim_end_matches('/');
        let path = if base.is_empty() {
            suffix.to_owned()
        } else {
            format!("{base}{suffix}")
        };
        value.set_path(&path);
        Ok(value)
    }
}

impl fmt::Debug for WebDriverEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebDriverEndpoint(<redacted>)")
    }
}

/// A small W3C WebDriver client. Cookie values never leave the driver; the
/// only cookie operation is W3C delete-all, used to isolate Suite modules.
pub struct WebDriverClient {
    endpoint: WebDriverEndpoint,
    client: Client,
    session_id: Option<String>,
    max_response_bytes: usize,
}

impl fmt::Debug for WebDriverClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebDriverClient")
            .field("endpoint", &self.endpoint)
            .field("session_active", &self.session_id.is_some())
            .finish()
    }
}

impl WebDriverClient {
    pub fn connect(endpoint: WebDriverEndpoint, timeout: Duration) -> Result<Self, BrowserError> {
        if timeout.is_zero() {
            return Err(BrowserError::InvalidLimits);
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| BrowserError::Transport)?;
        Ok(Self {
            endpoint,
            client,
            session_id: None,
            max_response_bytes: MAX_RESPONSE_BYTES,
        })
    }

    pub fn start_chrome(&mut self) -> Result<(), BrowserError> {
        self.start_with_capabilities(json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:loggingPrefs": {
                        "browser": "ALL"
                    },
                    "goog:chromeOptions": {
                        "args": [
                            "--headless=new",
                            "--disable-gpu",
                            "--disable-dev-shm-usage",
                            "--no-first-run",
                            "--no-default-browser-check"
                        ]
                    }
                }
            }
        }))
    }

    pub fn start_with_capabilities(&mut self, capabilities: Value) -> Result<(), BrowserError> {
        if self.session_id.is_some() {
            return Err(BrowserError::SessionAlreadyStarted);
        }
        let response = self.post_value("/session", &capabilities, "new_session")?;
        let object = response
            .value
            .as_object()
            .ok_or_else(|| response.protocol())?;
        let session = object
            .get("sessionId")
            .and_then(Value::as_str)
            .or_else(|| {
                object
                    .get("value")
                    .and_then(|item| item.get("sessionId"))
                    .and_then(Value::as_str)
            })
            .ok_or_else(|| response.protocol())?;
        if !valid_session_id(session) {
            return Err(response.protocol());
        }
        self.session_id = Some(session.to_owned());
        Ok(())
    }

    pub fn quit(&mut self) -> Result<(), BrowserError> {
        let Some(session) = self.session_id.take() else {
            return Ok(());
        };
        if !valid_session_id(&session) {
            return Err(BrowserError::Protocol);
        }
        let path = format!("/session/{session}");
        let _ = self.delete_value(&path, "delete_session");
        Ok(())
    }

    fn session_path(&self, suffix: &str) -> Result<String, BrowserError> {
        let session = self
            .session_id
            .as_deref()
            .ok_or(BrowserError::SessionNotStarted)?;
        if !valid_session_id(session)
            || suffix.contains("..")
            || suffix.contains("//")
            || !suffix.starts_with('/')
        {
            return Err(BrowserError::Protocol);
        }
        Ok(format!("/session/{session}{suffix}"))
    }

    fn post_value(
        &self,
        path: &str,
        body: &Value,
        endpoint: &'static str,
    ) -> Result<WebDriverResponse, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(body).map_err(|_| BrowserError::Protocol)?)
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes, endpoint)
    }

    fn get_value(
        &self,
        path: &str,
        endpoint: &'static str,
    ) -> Result<WebDriverResponse, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes, endpoint)
    }

    fn delete_value(
        &self,
        path: &str,
        endpoint: &'static str,
    ) -> Result<WebDriverResponse, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .delete(url)
            .header("Accept", "application/json")
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes, endpoint)
    }
}

impl BrowserDriver for WebDriverClient {
    fn ensure_session(&mut self) -> Result<(), BrowserError> {
        let path = self.session_path("/url")?;
        match self.get_value(&path, "session_probe") {
            Ok(_) => Ok(()),
            Err(BrowserError::InvalidSession) => {
                self.session_id = None;
                self.start_chrome()
            }
            Err(error) => Err(error),
        }
    }

    fn clear_cookies(&mut self) -> Result<(), BrowserError> {
        self.delete_value(&self.session_path("/cookie")?, "delete_all_cookies")
            .map(|_| ())
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
        let path = self.session_path("/url")?;
        self.post_value(&path, &json!({ "url": url.as_str() }), "navigate")
            .map(|_| ())
    }

    fn refresh(&mut self) -> Result<(), BrowserError> {
        let path = self.session_path("/refresh")?;
        self.post_value(&path, &json!({}), "refresh").map(|_| ())
    }

    fn current_url(&mut self) -> Result<Url, BrowserError> {
        let response = self.get_value(&self.session_path("/url")?, "current_url")?;
        let text = response
            .value
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| response.protocol())?;
        Url::parse(text).map_err(|_| response.protocol())
    }

    fn page_source(&mut self) -> Result<String, BrowserError> {
        let response = self.get_value(&self.session_path("/source")?, "page_source")?;
        let text = response
            .value
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| response.protocol())?;
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(BrowserError::ResponseTooLarge);
        }
        Ok(text.to_owned())
    }

    fn page_runtime_diagnostic(&mut self) -> Result<BrowserPageRuntimeDiagnostic, BrowserError> {
        let response = self.post_value(
            &self.session_path("/execute/sync")?,
            &json!({ "script": PAGE_RUNTIME_DIAGNOSTIC_SCRIPT, "args": [] }),
            "page_runtime_diagnostic",
        )?;
        parse_page_runtime_diagnostic(&response.value).ok_or_else(|| response.protocol())
    }

    fn browser_console_log_diagnostic(
        &mut self,
        target_origin: &Url,
    ) -> Result<BrowserConsoleLogDiagnostic, BrowserError> {
        let response = self.post_value(
            &self.session_path("/log")?,
            &json!({ "type": "browser" }),
            "browser_console_log",
        )?;
        parse_browser_console_log_diagnostic(&response.value, target_origin)
            .ok_or_else(|| response.protocol())
    }

    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError> {
        let (using, value) = match selector {
            BrowserSelector::Id(value) => ("id", value.as_str()),
            BrowserSelector::Css(value) => ("css selector", value.as_str()),
            BrowserSelector::XPath(value) => ("xpath", value.as_str()),
        };
        let response = self.post_value(
            &self.session_path("/element")?,
            &json!({ "using": using, "value": value }),
            "find_element",
        )?;
        let object = response
            .value
            .get("value")
            .and_then(Value::as_object)
            .ok_or_else(|| response.protocol())?;
        let id = object
            .get(W3C_ELEMENT_KEY)
            .and_then(Value::as_str)
            .ok_or_else(|| response.protocol())?;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(response.protocol());
        }
        Ok(id.to_owned())
    }

    fn find_child_element(
        &mut self,
        parent: &str,
        selector: &BrowserSelector,
    ) -> Result<String, BrowserError> {
        if parent.is_empty() || parent.len() > 256 || parent.chars().any(char::is_control) {
            return Err(BrowserError::Protocol);
        }
        let (using, value) = match selector {
            BrowserSelector::Id(value) => ("id", value.as_str()),
            BrowserSelector::Css(value) => ("css selector", value.as_str()),
            BrowserSelector::XPath(value) => ("xpath", value.as_str()),
        };
        let response = self.post_value(
            &self.session_path(&format!("/element/{parent}/element"))?,
            &json!({ "using": using, "value": value }),
            "find_child_element",
        )?;
        let object = response
            .value
            .get("value")
            .and_then(Value::as_object)
            .ok_or_else(|| response.protocol())?;
        let id = object
            .get(W3C_ELEMENT_KEY)
            .and_then(Value::as_str)
            .ok_or_else(|| response.protocol())?;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(response.protocol());
        }
        Ok(id.to_owned())
    }

    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError> {
        let response = self.get_value(
            &self.session_path(&format!("/element/{element}/displayed"))?,
            "element_displayed",
        )?;
        response
            .value
            .get("value")
            .and_then(Value::as_bool)
            .ok_or_else(|| response.protocol())
    }

    fn element_text(&mut self, element: &str) -> Result<String, BrowserError> {
        let response = self.get_value(
            &self.session_path(&format!("/element/{element}/text"))?,
            "element_text",
        )?;
        let text = response
            .value
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| response.protocol())?;
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(BrowserError::ResponseTooLarge);
        }
        Ok(text.to_owned())
    }

    fn element_attribute(
        &mut self,
        element: &str,
        name: &str,
    ) -> Result<Option<String>, BrowserError> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(BrowserError::Protocol);
        }
        let response = self.get_value(
            &self.session_path(&format!("/element/{element}/attribute/{name}"))?,
            "element_attribute",
        )?;
        match response.value.get("value") {
            Some(Value::Null) | None => Ok(None),
            Some(Value::String(value)) if value.len() <= MAX_RESPONSE_BYTES => {
                Ok(Some(value.clone()))
            }
            _ => Err(response.protocol()),
        }
    }

    fn element_send_keys(&mut self, element: &str, value: &str) -> Result<(), BrowserError> {
        if value.len() > MAX_TEXT_BYTES {
            return Err(BrowserError::InvalidSchema);
        }
        // The value is never formatted into an error or log.  It is dropped
        // immediately after WebDriver accepts the request.
        let body = json!({ "text": value, "value": value.chars().collect::<Vec<_>>() });
        self.post_value(
            &self.session_path(&format!("/element/{element}/value"))?,
            &body,
            "element_send_keys",
        )
        .map(|_| ())
    }

    fn element_click(&mut self, element: &str) -> Result<(), BrowserError> {
        self.post_value(
            &self.session_path(&format!("/element/{element}/click"))?,
            &json!({}),
            "element_click",
        )
        .map(|_| ())
    }

    fn screenshot_png(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, BrowserError> {
        let response = self.get_value(&self.session_path("/screenshot")?, "screenshot")?;
        parse_screenshot_response(&response.value).map_err(|error| match error {
            BrowserError::Protocol => response.protocol(),
            error => error,
        })
    }
}

impl Drop for WebDriverClient {
    fn drop(&mut self) {
        let _ = self.quit();
    }
}

/// A managed local chromedriver session used by the ordinary CLI path.  It
/// owns both the driver process and the WebDriver session, so an interrupted
/// conformance run cannot leave a browser process behind.  CI may instead
/// supply an explicitly managed endpoint through [`WebDriverClient`].
pub struct ManagedWebDriver {
    client: WebDriverClient,
    child: Child,
}

impl fmt::Debug for ManagedWebDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedWebDriver(<local>)")
    }
}

impl ManagedWebDriver {
    pub fn start_default(timeout: Duration) -> Result<Self, BrowserError> {
        let binary = find_driver_binary().ok_or(BrowserError::DriverUnavailable)?;
        Self::start_with_binary(&binary, timeout)
    }

    pub fn start_with_binary(path: &Path, timeout: Duration) -> Result<Self, BrowserError> {
        validate_driver_binary(path)?;
        if timeout.is_zero() {
            return Err(BrowserError::InvalidLimits);
        }
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| BrowserError::DriverStartFailed)?;
        let port = listener
            .local_addr()
            .map_err(|_| BrowserError::DriverStartFailed)?
            .port();
        drop(listener);

        let mut command = Command::new(path);
        command
            .arg(format!("--port={port}"))
            .arg("--log-level=SEVERE")
            .env_clear()
            .env("PATH", safe_driver_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        if current_effective_uid() == Some(0) {
            // The CLI itself needs controller privileges, while a browser must
            // not inherit root. Chrome's own sandbox remains enabled because
            // the managed driver and its descendants run as the unprivileged
            // nobody identity instead of passing `--no-sandbox`.
            use std::os::unix::process::CommandExt as _;
            command.uid(65_534).gid(65_534).env("HOME", "/tmp");
        }
        configure_driver_process(&mut command);
        let child = command
            .spawn()
            .map_err(|_| BrowserError::DriverStartFailed)?;

        let endpoint = WebDriverEndpoint::parse(&format!("http://127.0.0.1:{port}"))?;
        let health_client = Client::builder()
            .timeout(Duration::from_secs(1))
            .redirect(Policy::none())
            .build()
            .map_err(|_| BrowserError::Transport)?;
        let deadline = Instant::now() + timeout.min(Duration::from_secs(60));
        let mut child = child;
        let ready = loop {
            if let Some(_status) = child
                .try_wait()
                .map_err(|_| BrowserError::DriverStartFailed)?
            {
                return Err(BrowserError::DriverStartFailed);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BrowserError::DriverStartFailed);
            }
            let health_url = endpoint.endpoint_url("/status")?;
            if let Ok(response) = health_client.get(health_url).send()
                && response.status().is_success()
            {
                let mut body = Vec::new();
                let _ = response.take(64 * 1024).read_to_end(&mut body);
                let ready = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("value")
                            .and_then(|item| item.get("ready"))
                            .and_then(Value::as_bool)
                    })
                    .unwrap_or(false);
                if ready {
                    break true;
                }
            }
            thread::sleep(Duration::from_millis(100));
        };
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BrowserError::DriverStartFailed);
        }

        let mut client = WebDriverClient::connect(endpoint, timeout)?;
        if let Err(error) = client.start_chrome() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(Self { client, child })
    }

    pub fn driver_mut(&mut self) -> &mut WebDriverClient {
        &mut self.client
    }
}

#[cfg(unix)]
fn current_effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let values = line
            .strip_prefix("Uid:")?
            .split_whitespace()
            .collect::<Vec<_>>();
        values.get(1)?.parse::<u32>().ok()
    })
}

impl BrowserDriver for ManagedWebDriver {
    fn ensure_session(&mut self) -> Result<(), BrowserError> {
        self.client.ensure_session()
    }

    fn clear_cookies(&mut self) -> Result<(), BrowserError> {
        self.client.clear_cookies()
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
        self.client.navigate(url)
    }
    fn refresh(&mut self) -> Result<(), BrowserError> {
        self.client.refresh()
    }
    fn current_url(&mut self) -> Result<Url, BrowserError> {
        self.client.current_url()
    }
    fn page_source(&mut self) -> Result<String, BrowserError> {
        self.client.page_source()
    }
    fn page_runtime_diagnostic(&mut self) -> Result<BrowserPageRuntimeDiagnostic, BrowserError> {
        self.client.page_runtime_diagnostic()
    }
    fn browser_console_log_diagnostic(
        &mut self,
        target_origin: &Url,
    ) -> Result<BrowserConsoleLogDiagnostic, BrowserError> {
        self.client.browser_console_log_diagnostic(target_origin)
    }
    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError> {
        self.client.find_element(selector)
    }
    fn find_child_element(
        &mut self,
        parent: &str,
        selector: &BrowserSelector,
    ) -> Result<String, BrowserError> {
        self.client.find_child_element(parent, selector)
    }
    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError> {
        self.client.element_displayed(element)
    }
    fn element_text(&mut self, element: &str) -> Result<String, BrowserError> {
        self.client.element_text(element)
    }
    fn element_attribute(
        &mut self,
        element: &str,
        name: &str,
    ) -> Result<Option<String>, BrowserError> {
        self.client.element_attribute(element, name)
    }
    fn element_send_keys(&mut self, element: &str, value: &str) -> Result<(), BrowserError> {
        self.client.element_send_keys(element, value)
    }
    fn element_click(&mut self, element: &str) -> Result<(), BrowserError> {
        self.client.element_click(element)
    }

    fn screenshot_png(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, BrowserError> {
        self.client.screenshot_png()
    }
}

impl Drop for ManagedWebDriver {
    fn drop(&mut self) {
        let _ = self.client.quit();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn validate_driver_binary(path: &Path) -> Result<(), BrowserError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(BrowserError::DriverUnavailable);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| BrowserError::DriverUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BrowserError::DriverUnavailable);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x0400 != 0 {
            return Err(BrowserError::DriverUnavailable);
        }
    }
    Ok(())
}

fn find_driver_binary() -> Option<PathBuf> {
    let mut directories = Vec::new();
    #[cfg(unix)]
    {
        directories.extend([
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/snap/bin"),
        ]);
    }
    #[cfg(windows)]
    {
        directories.extend([
            PathBuf::from(r"C:\Program Files\chromedriver"),
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application"),
            PathBuf::from(r"C:\Program Files (x86)\chromedriver"),
        ]);
    }
    let names = if cfg!(windows) {
        vec!["chromedriver.exe", "chromium-driver.exe"]
    } else {
        vec!["chromedriver", "chromium-driver"]
    };
    directories
        .into_iter()
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|path| validate_driver_binary(path).is_ok())
}

fn safe_driver_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32;C:\Windows"
    } else {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }
}

fn configure_driver_process(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

fn parse_webdriver_response(
    response: reqwest::blocking::Response,
    max: usize,
    endpoint: &'static str,
) -> Result<WebDriverResponse, BrowserError> {
    let status = response.status();
    let content_type =
        webdriver_content_type(response.headers().get(reqwest::header::CONTENT_TYPE));
    let length = response.content_length().unwrap_or(0);
    if length > max as u64 {
        return Err(BrowserError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BrowserError::Transport)?;
    if bytes.len() > max {
        return Err(BrowserError::ResponseTooLarge);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        BrowserError::ProtocolDiagnostic(webdriver_protocol_diagnostic(
            endpoint,
            status.as_u16(),
            content_type,
            &bytes,
            None,
        ))
    })?;
    let diagnostic = webdriver_protocol_diagnostic(
        endpoint,
        status.as_u16(),
        content_type,
        &bytes,
        Some(&value),
    );
    if !status.is_success() {
        // WebDriver error payloads often contain page text and selectors.  Do
        // not echo it. Preserve only the W3C error token needed by the bounded
        // browser state machine to distinguish normal DOM races from a driver
        // or protocol failure.
        return Err(classify_webdriver_error(&value));
    }
    Ok(WebDriverResponse { value, diagnostic })
}

fn webdriver_content_type(value: Option<&reqwest::header::HeaderValue>) -> &'static str {
    let value = match value {
        Some(value) => match value.to_str() {
            Ok(value) => value,
            Err(_) => return "invalid",
        },
        None => "",
    };
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match mime.as_str() {
        "application/json" => "application/json",
        "" => "missing",
        _ => "other",
    }
}

fn webdriver_protocol_diagnostic(
    endpoint: &'static str,
    status: u16,
    content_type: &'static str,
    body: &[u8],
    value: Option<&Value>,
) -> WebDriverProtocolDiagnostic {
    let (value_type, mut top_level_keys) = value.map_or(("invalid_json", Vec::new()), |value| {
        let value_type = match value.get("value") {
            Some(Value::Null) => "null",
            Some(Value::Bool(_)) => "bool",
            Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Array(_)) => "array",
            Some(Value::Object(_)) => "object",
            None => "missing",
        };
        let mut keys = value
            .as_object()
            .map(|object| {
                object
                    .keys()
                    .filter_map(|key| safe_top_level_key(key))
                    .take(16)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        keys.sort();
        (value_type, keys)
    });
    if top_level_keys.is_empty() {
        top_level_keys.push("none".to_owned());
    }
    let body_sha256 = Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    WebDriverProtocolDiagnostic {
        endpoint,
        status,
        content_type,
        body_len: body.len(),
        body_sha256,
        value_type,
        top_level_keys,
    }
}

fn safe_top_level_key(value: &str) -> Option<String> {
    ((1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
    .then_some(value.to_owned())
}

fn classify_webdriver_error(value: &Value) -> BrowserError {
    match value
        .get("value")
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
    {
        Some("no such element") => BrowserError::ElementNotFound,
        Some("stale element reference") => BrowserError::StaleElement,
        Some("invalid session id") => BrowserError::InvalidSession,
        _ => BrowserError::DriverRejected,
    }
}

fn parse_page_runtime_diagnostic(value: &Value) -> Option<BrowserPageRuntimeDiagnostic> {
    let value = value.get("value")?.as_object()?;
    if value.len() != 23
        || value.keys().any(|key| {
            !matches!(
                key.as_str(),
                "ready_state"
                    | "root_present"
                    | "root_child_element_count"
                    | "root_child_element_count_capped"
                    | "has_vp_verification_result"
                    | "module_script_count"
                    | "module_script_count_capped"
                    | "resource_scan_count"
                    | "resource_scan_count_capped"
                    | "same_origin_ui_asset_resource_count"
                    | "same_origin_ui_asset_resource_count_capped"
                    | "ui_asset_response_statuses"
                    | "ui_asset_response_statuses_capped"
                    | "ui_asset_transfer_size_positive_count"
                    | "ui_asset_decoded_size_positive_count"
                    | "verification_receipt_resource_count"
                    | "verification_receipt_resource_count_capped"
                    | "verification_receipt_response_statuses"
                    | "verification_receipt_response_statuses_capped"
                    | "verification_receipt_transfer_size_positive_count"
                    | "verification_receipt_decoded_size_positive_count"
                    | "title_kind"
                    | "navigator_online"
            )
        })
    {
        return None;
    }
    let ready_state = match value.get("ready_state")?.as_str()? {
        "loading" => "loading",
        "interactive" => "interactive",
        "complete" => "complete",
        "other" => "other",
        _ => return None,
    };
    let title_kind = match value.get("title_kind")?.as_str()? {
        "nazoauth" => "nazoauth",
        "other" => "other",
        _ => return None,
    };
    let bounded_count = |key: &str, maximum: usize| {
        let value = value.get(key)?.as_u64()?;
        usize::try_from(value)
            .ok()
            .filter(|value| *value <= maximum)
    };
    let bool_value = |key: &str| value.get(key)?.as_bool();
    let statuses = value
        .get("ui_asset_response_statuses")?
        .as_array()?
        .iter()
        .map(|status| u16::try_from(status.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    if statuses.len() > MAX_RUNTIME_RESPONSE_STATUSES
        || statuses.iter().any(|status| !(100..=599).contains(status))
        || statuses.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return None;
    }
    let receipt_statuses = value
        .get("verification_receipt_response_statuses")?
        .as_array()?
        .iter()
        .map(|status| u16::try_from(status.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    if receipt_statuses.len() > MAX_RUNTIME_RECEIPT_STATUSES
        || receipt_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
        || receipt_statuses.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return None;
    }
    let resource_scan_count = bounded_count("resource_scan_count", MAX_RUNTIME_RESOURCE_SCAN)?;
    let same_origin_ui_asset_resource_count = bounded_count(
        "same_origin_ui_asset_resource_count",
        MAX_RUNTIME_UI_ASSET_RESOURCES,
    )?;
    let ui_asset_transfer_size_positive_count = bounded_count(
        "ui_asset_transfer_size_positive_count",
        MAX_RUNTIME_UI_ASSET_RESOURCES,
    )?;
    let ui_asset_decoded_size_positive_count = bounded_count(
        "ui_asset_decoded_size_positive_count",
        MAX_RUNTIME_UI_ASSET_RESOURCES,
    )?;
    let verification_receipt_resource_count = bounded_count(
        "verification_receipt_resource_count",
        MAX_RUNTIME_RECEIPT_RESOURCES,
    )?;
    let verification_receipt_transfer_size_positive_count = bounded_count(
        "verification_receipt_transfer_size_positive_count",
        MAX_RUNTIME_RECEIPT_RESOURCES,
    )?;
    let verification_receipt_decoded_size_positive_count = bounded_count(
        "verification_receipt_decoded_size_positive_count",
        MAX_RUNTIME_RECEIPT_RESOURCES,
    )?;
    if same_origin_ui_asset_resource_count > resource_scan_count
        || ui_asset_transfer_size_positive_count > same_origin_ui_asset_resource_count
        || ui_asset_decoded_size_positive_count > same_origin_ui_asset_resource_count
        || verification_receipt_resource_count > resource_scan_count
        || verification_receipt_transfer_size_positive_count > verification_receipt_resource_count
        || verification_receipt_decoded_size_positive_count > verification_receipt_resource_count
    {
        return None;
    }
    Some(BrowserPageRuntimeDiagnostic {
        ready_state,
        root_present: bool_value("root_present")?,
        root_child_element_count: bounded_count(
            "root_child_element_count",
            MAX_RUNTIME_ROOT_CHILDREN,
        )?,
        root_child_element_count_capped: bool_value("root_child_element_count_capped")?,
        has_vp_verification_result: bool_value("has_vp_verification_result")?,
        module_script_count: bounded_count("module_script_count", MAX_RUNTIME_MODULE_SCRIPTS)?,
        module_script_count_capped: bool_value("module_script_count_capped")?,
        resource_scan_count,
        resource_scan_count_capped: bool_value("resource_scan_count_capped")?,
        same_origin_ui_asset_resource_count,
        same_origin_ui_asset_resource_count_capped: bool_value(
            "same_origin_ui_asset_resource_count_capped",
        )?,
        ui_asset_response_statuses: statuses,
        ui_asset_response_statuses_capped: bool_value("ui_asset_response_statuses_capped")?,
        ui_asset_transfer_size_positive_count,
        ui_asset_decoded_size_positive_count,
        verification_receipt_resource_count,
        verification_receipt_resource_count_capped: bool_value(
            "verification_receipt_resource_count_capped",
        )?,
        verification_receipt_response_statuses: receipt_statuses,
        verification_receipt_response_statuses_capped: bool_value(
            "verification_receipt_response_statuses_capped",
        )?,
        verification_receipt_transfer_size_positive_count,
        verification_receipt_decoded_size_positive_count,
        title_kind,
        navigator_online: bool_value("navigator_online")?,
        browser_log_collection: "selenium-vendor-browser-log",
    })
}

fn browser_log_level(value: &str) -> &'static str {
    match value {
        "SEVERE" => "severe",
        "WARNING" => "warning",
        "INFO" => "info",
        "DEBUG" => "debug",
        _ => "other",
    }
}

fn browser_log_source_kind(value: &str) -> &'static str {
    match value {
        "javascript" => "javascript",
        "network" => "network",
        "console-api" => "console-api",
        _ => "other",
    }
}

fn browser_log_category(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("uncaught") {
        "uncaught"
    } else if message.contains("content security policy") || message.contains("csp") {
        "csp"
    } else if message.contains("module") {
        "module"
    } else if message.contains("net::")
        || message.contains("failed to load resource")
        || message.contains("network")
    {
        "network"
    } else {
        "other"
    }
}

fn browser_log_http_status(message: &str) -> Option<u16> {
    for marker in ["HTTP/1.1 ", "HTTP/2 ", "HTTP/3 ", "status of ", "status="] {
        let Some(index) = message.find(marker) else {
            continue;
        };
        let bytes = &message.as_bytes()[index + marker.len()..];
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            continue;
        }
        let status = std::str::from_utf8(&bytes[..3]).ok()?.parse().ok()?;
        if (100..=599).contains(&status) {
            return Some(status);
        }
    }
    None
}

fn browser_log_network_error(message: &str, category: &'static str) -> Option<&'static str> {
    if category != "network" {
        return None;
    }
    for (needle, value) in [
        ("net::ERR_CONNECTION_REFUSED", "connection-refused"),
        ("net::ERR_NAME_NOT_RESOLVED", "name-not-resolved"),
        ("net::ERR_CONNECTION_TIMED_OUT", "connection-timed-out"),
        ("net::ERR_CONNECTION_RESET", "connection-reset"),
        ("net::ERR_ABORTED", "aborted"),
        ("net::ERR_FAILED", "failed"),
    ] {
        if message.contains(needle) {
            return Some(value);
        }
    }
    Some("other")
}

fn browser_log_resource_url(message: &str) -> Option<Url> {
    for prefix in ["https://", "http://"] {
        let mut remaining = message;
        while let Some(index) = remaining.find(prefix) {
            let candidate = &remaining[index..];
            let end = candidate
                .find(char::is_whitespace)
                .unwrap_or(candidate.len());
            let candidate = candidate[..end].trim_end_matches(|character: char| {
                matches!(character, ')' | ']' | '}' | ',' | ';' | '.' | '\'' | '"')
            });
            if let Ok(url) = Url::parse(candidate) {
                return Some(url);
            }
            remaining = &candidate[prefix.len()..];
        }
    }
    None
}

fn browser_log_resource_bucket(message: &str, target_origin: &Url) -> &'static str {
    let Some(resource) = browser_log_resource_url(message) else {
        return "unknown";
    };
    if resource.origin() != target_origin.origin() {
        return "cross-origin";
    }
    if resource.path() == "/openid4vp/verification-receipts"
        && resource.query().is_none()
        && resource.fragment().is_none()
    {
        "receipt-api"
    } else if resource.path().starts_with("/ui/assets/") {
        "ui-asset"
    } else if resource.path().starts_with("/ui/icons/") {
        "ui-icon"
    } else {
        "same-origin-other"
    }
}

fn browser_log_message_sha256(message: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nazoauthctl-browser-console-message-v1\0");
    digest.update(message.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_browser_console_log_diagnostic(
    value: &Value,
    target_origin: &Url,
) -> Option<BrowserConsoleLogDiagnostic> {
    let entries = value.get("value")?.as_array()?;
    if entries.len() > MAX_BROWSER_LOG_ENTRIES {
        return None;
    }
    let mut level_counts = BTreeMap::new();
    let mut source_kind_counts = BTreeMap::new();
    let mut category_counts = BTreeMap::new();
    let mut http_status_counts = BTreeMap::new();
    let mut resource_bucket_counts = BTreeMap::new();
    let mut network_error_counts = BTreeMap::new();
    let mut messages = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.as_object()?;
        if entry
            .keys()
            .any(|key| !matches!(key.as_str(), "level" | "message" | "source" | "timestamp"))
            || !entry.contains_key("level")
            || !entry.contains_key("message")
            || !entry.contains_key("source")
            || entry.get("timestamp").is_some_and(|value| !value.is_u64())
        {
            return None;
        }
        let raw_level = entry.get("level")?.as_str()?;
        let raw_source = entry.get("source")?.as_str()?;
        if raw_level.len() > 64 || raw_source.len() > 64 {
            return None;
        }
        let level = browser_log_level(raw_level);
        let source_kind = browser_log_source_kind(raw_source);
        let message = entry.get("message")?.as_str()?;
        let category = browser_log_category(message);
        let http_status = browser_log_http_status(message);
        let resource_bucket = browser_log_resource_bucket(message, target_origin);
        let network_error = browser_log_network_error(message, category);
        *level_counts.entry(level).or_insert(0) += 1;
        *source_kind_counts.entry(source_kind).or_insert(0) += 1;
        *category_counts.entry(category).or_insert(0) += 1;
        if let Some(status) = http_status {
            *http_status_counts.entry(status).or_insert(0) += 1;
        }
        *resource_bucket_counts.entry(resource_bucket).or_insert(0) += 1;
        if let Some(error) = network_error {
            *network_error_counts.entry(error).or_insert(0) += 1;
        }
        messages.push(BrowserConsoleLogMessageDiagnostic {
            level,
            source_kind,
            category,
            http_status,
            resource_bucket,
            network_error,
            message_sha256: browser_log_message_sha256(message),
            message_len: message.len().min(MAX_BROWSER_LOG_MESSAGE_BYTES),
            message_len_capped: message.len() > MAX_BROWSER_LOG_MESSAGE_BYTES,
        });
    }
    Some(BrowserConsoleLogDiagnostic {
        total: entries.len(),
        capped: false,
        level_counts: level_counts.into_iter().collect(),
        source_kind_counts: source_kind_counts.into_iter().collect(),
        category_counts: category_counts.into_iter().collect(),
        http_status_counts: http_status_counts.into_iter().collect(),
        resource_bucket_counts: resource_bucket_counts.into_iter().collect(),
        network_error_counts: network_error_counts.into_iter().collect(),
        messages,
    })
}

fn parse_screenshot_response(value: &Value) -> Result<zeroize::Zeroizing<Vec<u8>>, BrowserError> {
    let encoded = value
        .get("value")
        .and_then(Value::as_str)
        .ok_or(BrowserError::Protocol)?;
    decode_webdriver_png(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn webdriver_test_server(
        body: &'static str,
    ) -> (WebDriverEndpoint, std::thread::JoinHandle<String>) {
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("test read timeout");
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 512];
                let read = stream.read(&mut chunk).expect("test request read");
                assert_ne!(read, 0, "complete test request");
                bytes.extend_from_slice(&chunk[..read]);
                if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&bytes[..header_end]).expect("ASCII headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then_some(value.trim())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .expect("content length");
            while bytes.len() < header_end + content_length {
                let mut chunk = [0u8; 512];
                let read = stream.read(&mut chunk).expect("test request body");
                assert_ne!(read, 0, "complete test body");
                bytes.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            use std::io::Write as _;
            stream
                .write_all(response.as_bytes())
                .expect("test response");
            stream.flush().expect("flush test response");
            String::from_utf8(bytes).expect("request UTF-8")
        });
        (
            WebDriverEndpoint::parse(&format!("http://{address}")).expect("test endpoint"),
            handle,
        )
    }

    fn valid_png() -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("PNG header");
        writer
            .write_image_data(&[0x00, 0x00, 0x00, 0xff])
            .expect("one opaque pixel");
        drop(writer);
        bytes
    }

    #[test]
    fn webdriver_error_tokens_preserve_only_retryable_dom_states() {
        assert_eq!(
            classify_webdriver_error(&json!({
                "value": {"error": "no such element", "message": "sensitive page text"}
            })),
            BrowserError::ElementNotFound
        );
        assert_eq!(
            classify_webdriver_error(&json!({
                "value": {"error": "stale element reference", "message": "sensitive selector"}
            })),
            BrowserError::StaleElement
        );
        assert_eq!(
            classify_webdriver_error(&json!({
                "value": {"error": "invalid session id", "message": "sensitive session"}
            })),
            BrowserError::InvalidSession
        );
        assert_eq!(
            classify_webdriver_error(&json!({
                "value": {"error": "unknown error", "message": "sensitive driver detail"}
            })),
            BrowserError::DriverRejected
        );
    }

    #[test]
    fn protocol_diagnostic_is_metadata_only_and_bounded() {
        let body = br#"{\"value\":{\"secret\":\"do-not-persist\"},\"sessionId\":\"ignored\",\"bad key\":true}"#;
        let diagnostic = webdriver_protocol_diagnostic(
            "find_child_element",
            200,
            "application/json",
            body,
            Some(&json!({
                "value": {"secret": "do-not-persist"},
                "sessionId": "ignored",
                "bad key": true,
            })),
        );
        let rendered = diagnostic.to_string();
        assert_eq!(diagnostic.endpoint, "find_child_element");
        assert_eq!(diagnostic.status, 200);
        assert_eq!(diagnostic.content_type, "application/json");
        assert_eq!(diagnostic.value_type, "object");
        assert_eq!(diagnostic.top_level_keys, vec!["sessionId", "value"]);
        assert!(rendered.contains("body_len="));
        assert!(rendered.contains("body_sha256="));
        assert!(!rendered.contains("do-not-persist"));
        assert!(!rendered.contains("bad key"));
    }

    #[test]
    fn session_ids_are_path_safe_and_bounded() {
        assert!(valid_session_id("session-01._abc"));
        assert!(!valid_session_id("session/01"));
        assert!(!valid_session_id("session?01"));
        assert!(!valid_session_id("session 01"));
        assert!(!valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES + 1)));
    }

    #[test]
    fn w3c_refresh_posts_an_empty_object_to_the_session_refresh_endpoint() {
        let (endpoint, server) = webdriver_test_server(r#"{"value":null}"#);
        let mut client =
            WebDriverClient::connect(endpoint, Duration::from_secs(1)).expect("WebDriver client");
        client.session_id = Some("session-01".to_owned());

        client.refresh().expect("W3C refresh response");
        client.session_id = None;

        let request = server.join().expect("test server");
        assert!(request.starts_with("POST /session/session-01/refresh HTTP/1.1\r\n"));
        assert!(request.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn chrome_session_enables_consumed_browser_log_collection() {
        let (endpoint, server) = webdriver_test_server(r#"{"value":{"sessionId":"session-01"}}"#);
        let mut client =
            WebDriverClient::connect(endpoint, Duration::from_secs(1)).expect("WebDriver client");

        client.start_chrome().expect("start chrome");
        client.session_id = None;

        let request = server.join().expect("test server");
        let body = request.split_once("\r\n\r\n").expect("request body").1;
        let capabilities: Value = serde_json::from_str(body).expect("capabilities JSON");
        assert_eq!(
            capabilities
                .pointer("/capabilities/alwaysMatch/goog:loggingPrefs/browser")
                .and_then(Value::as_str),
            Some("ALL")
        );
    }

    #[test]
    fn w3c_page_runtime_diagnostic_uses_a_fixed_script_and_bounded_safe_shape() {
        let body = r#"{"value":{"ready_state":"complete","root_present":true,"root_child_element_count":2,"root_child_element_count_capped":false,"has_vp_verification_result":true,"module_script_count":1,"module_script_count_capped":false,"resource_scan_count":2,"resource_scan_count_capped":false,"same_origin_ui_asset_resource_count":2,"same_origin_ui_asset_resource_count_capped":false,"ui_asset_response_statuses":[200,304],"ui_asset_response_statuses_capped":false,"ui_asset_transfer_size_positive_count":2,"ui_asset_decoded_size_positive_count":1,"verification_receipt_resource_count":1,"verification_receipt_resource_count_capped":false,"verification_receipt_response_statuses":[404],"verification_receipt_response_statuses_capped":false,"verification_receipt_transfer_size_positive_count":1,"verification_receipt_decoded_size_positive_count":1,"title_kind":"nazoauth","navigator_online":true}}"#;
        let (endpoint, server) = webdriver_test_server(body);
        let mut client =
            WebDriverClient::connect(endpoint, Duration::from_secs(1)).expect("WebDriver client");
        client.session_id = Some("session-01".to_owned());

        let diagnostic = client
            .page_runtime_diagnostic()
            .expect("fixed runtime diagnostic");
        client.session_id = None;

        assert_eq!(diagnostic.ready_state, "complete");
        assert_eq!(diagnostic.ui_asset_response_statuses, vec![200, 304]);
        assert_eq!(diagnostic.verification_receipt_response_statuses, vec![404]);
        assert_eq!(
            diagnostic.browser_log_collection,
            "selenium-vendor-browser-log"
        );
        let mut receipt_200: Value = serde_json::from_str(body).expect("runtime fixture JSON");
        receipt_200["value"]["verification_receipt_response_statuses"] = json!([200]);
        assert_eq!(
            parse_page_runtime_diagnostic(&receipt_200)
                .expect("same-origin receipt 200 timing")
                .verification_receipt_response_statuses,
            vec![200]
        );
        let request = server.join().expect("test server");
        assert!(request.starts_with("POST /session/session-01/execute/sync HTTP/1.1\r\n"));
        let body = request.split_once("\r\n\r\n").expect("request body").1;
        let command: Value = serde_json::from_str(body).expect("execute JSON");
        assert_eq!(
            command.get("script").and_then(Value::as_str),
            Some(PAGE_RUNTIME_DIAGNOSTIC_SCRIPT)
        );
        assert_eq!(command.get("args"), Some(&json!([])));
        assert!(PAGE_RUNTIME_DIAGNOSTIC_SCRIPT.contains(
            "resource.pathname === '/openid4vp/verification-receipts' && !resource.search && !resource.hash"
        ));
        assert!(!request.contains("secret="));
    }

    #[test]
    fn selenium_browser_log_adapter_posts_only_the_fixed_type_and_hashes_messages() {
        let body = r#"{"value":[{"level":"SEVERE","source":"javascript","message":"Uncaught module error https://issuer.example/ui/assets/app.js?token=do-not-retain","timestamp":1},{"level":"WARNING","source":"network","message":"Failed to load resource https://issuer.example/openid4vp/verification-receipts status of 503 net::ERR_CONNECTION_REFUSED","timestamp":2}]}"#;
        let (endpoint, server) = webdriver_test_server(body);
        let mut client =
            WebDriverClient::connect(endpoint, Duration::from_secs(1)).expect("WebDriver client");
        client.session_id = Some("session-01".to_owned());

        let target_origin = Url::parse("https://issuer.example").expect("target origin");
        let diagnostic = client
            .browser_console_log_diagnostic(&target_origin)
            .expect("browser log summary");
        client.session_id = None;

        assert_eq!(diagnostic.total, 2);
        assert_eq!(diagnostic.level_counts, vec![("severe", 1), ("warning", 1)]);
        assert_eq!(
            diagnostic.category_counts,
            vec![("network", 1), ("uncaught", 1)]
        );
        assert_eq!(diagnostic.http_status_counts, vec![(503, 1)]);
        assert_eq!(
            diagnostic.resource_bucket_counts,
            vec![("receipt-api", 1), ("ui-asset", 1)]
        );
        assert_eq!(
            diagnostic.network_error_counts,
            vec![("connection-refused", 1)]
        );
        assert!(diagnostic.messages[0].message_len > 0);
        assert!(!diagnostic.messages[0].message_len_capped);
        let rendered = diagnostic.to_string();
        assert!(!rendered.contains("do-not-retain"));
        assert!(!rendered.contains("token="));
        assert!(!rendered.contains("openid4vp/verification-receipts"));
        let request = server.join().expect("test server");
        assert!(request.starts_with("POST /session/session-01/log HTTP/1.1\r\n"));
        assert!(request.ends_with("\r\n\r\n{\"type\":\"browser\"}"));
    }

    #[test]
    fn selenium_browser_log_adapter_rejects_unbounded_or_unknown_entries() {
        let entry = json!({
            "level": "SEVERE",
            "source": "javascript",
            "message": "uncaught",
        });
        let entries = Value::Array(
            (0..=MAX_BROWSER_LOG_ENTRIES)
                .map(|_| entry.clone())
                .collect(),
        );
        let target_origin = Url::parse("https://issuer.example").expect("target origin");
        assert!(
            parse_browser_console_log_diagnostic(&json!({ "value": entries }), &target_origin)
                .is_none()
        );
        assert!(
            parse_browser_console_log_diagnostic(
                &json!({
                    "value": [{
                        "level": "SEVERE",
                        "source": "javascript",
                        "message": "secret=do-not-retain",
                        "url": "https://issuer.example/?token=do-not-retain"
                    }]
                }),
                &target_origin
            )
            .is_none()
        );
        let long_message = "m".repeat(MAX_BROWSER_LOG_MESSAGE_BYTES + 1);
        let summary = parse_browser_console_log_diagnostic(
            &json!({
                "value": [{
                    "level": "INFO",
                    "source": "console-api",
                    "message": long_message,
                }]
            }),
            &target_origin,
        )
        .expect("bounded message summary");
        assert_eq!(
            summary.messages[0].message_len,
            MAX_BROWSER_LOG_MESSAGE_BYTES
        );
        assert!(summary.messages[0].message_len_capped);
    }

    #[test]
    fn selenium_browser_log_network_projection_is_bounded_and_never_retains_urls() {
        let target_origin = Url::parse("https://issuer.example").expect("target origin");
        let summary = parse_browser_console_log_diagnostic(
            &json!({
                "value": [
                    {
                        "level": "SEVERE",
                        "source": "network",
                        "message": "https://issuer.example/ui/icons/warning.svg HTTP/2 404 net::ERR_FAILED secret=do-not-retain"
                    },
                    {
                        "level": "WARNING",
                        "source": "network",
                        "message": "https://outside.example/trace?token=do-not-retain status=502 net::ERR_UNRECOGNIZED"
                    },
                    {
                        "level": "INFO",
                        "source": "network",
                        "message": "network request failed token=do-not-retain"
                    }
                ]
            }),
            &target_origin,
        )
        .expect("bounded browser log projection");

        assert_eq!(summary.http_status_counts, vec![(404, 1), (502, 1)]);
        assert_eq!(
            summary.resource_bucket_counts,
            vec![("cross-origin", 1), ("ui-icon", 1), ("unknown", 1)]
        );
        assert_eq!(
            summary.network_error_counts,
            vec![("failed", 1), ("other", 2)]
        );
        assert!(summary.messages.iter().all(|message| {
            matches!(
                message.resource_bucket,
                "receipt-api"
                    | "ui-asset"
                    | "ui-icon"
                    | "same-origin-other"
                    | "cross-origin"
                    | "unknown"
            )
        }));
        let rendered = summary.to_string();
        assert!(!rendered.contains("outside.example"));
        assert!(!rendered.contains("do-not-retain"));
        assert!(!rendered.contains("token="));
    }

    #[test]
    fn page_runtime_diagnostic_rejects_unbounded_or_sensitive_response_shape() {
        let mut valid = json!({
            "value": {
                "ready_state": "complete",
                "root_present": true,
                "root_child_element_count": 0,
                "root_child_element_count_capped": false,
                "has_vp_verification_result": false,
                "module_script_count": 0,
                "module_script_count_capped": false,
                "resource_scan_count": 0,
                "resource_scan_count_capped": false,
                "same_origin_ui_asset_resource_count": 0,
                "same_origin_ui_asset_resource_count_capped": false,
                "ui_asset_response_statuses": [],
                "ui_asset_response_statuses_capped": false,
                "ui_asset_transfer_size_positive_count": 0,
                "ui_asset_decoded_size_positive_count": 0,
                "verification_receipt_resource_count": 0,
                "verification_receipt_resource_count_capped": false,
                "verification_receipt_response_statuses": [],
                "verification_receipt_response_statuses_capped": false,
                "verification_receipt_transfer_size_positive_count": 0,
                "verification_receipt_decoded_size_positive_count": 0,
                "title_kind": "other",
                "navigator_online": false,
                "untrusted_page_text": "secret=do-not-retain"
            }
        });
        assert!(parse_page_runtime_diagnostic(&valid).is_none());
        valid["value"]
            .as_object_mut()
            .expect("object")
            .remove("untrusted_page_text");
        let diagnostic = parse_page_runtime_diagnostic(&valid).expect("safe fields only");
        assert_eq!(diagnostic.title_kind, "other");
        assert!(!diagnostic.to_string().contains("do-not-retain"));

        let mut oversized = valid;
        oversized["value"]["module_script_count"] = json!(MAX_RUNTIME_MODULE_SCRIPTS + 1);
        assert!(parse_page_runtime_diagnostic(&oversized).is_none());
        oversized["value"]["module_script_count"] = json!(0);
        oversized["value"]["ui_asset_response_statuses"] = Value::Array(
            (0..=MAX_RUNTIME_RESPONSE_STATUSES)
                .map(|_| json!(200))
                .collect(),
        );
        assert!(parse_page_runtime_diagnostic(&oversized).is_none());
    }

    #[test]
    fn w3c_screenshot_response_accepts_only_bounded_canonical_png() {
        let png = valid_png();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&png);
        assert_eq!(
            parse_screenshot_response(&json!({"value": encoded}))
                .expect("w3c screenshot")
                .as_slice(),
            png.as_slice()
        );
        assert_eq!(
            parse_screenshot_response(&json!({"value": "not-base64"}))
                .expect_err("strict encoding"),
            BrowserError::InvalidScreenshot
        );
        assert_eq!(
            parse_screenshot_response(
                &json!({"value": base64::engine::general_purpose::STANDARD.encode(b"not png")})
            )
            .expect_err("png signature"),
            BrowserError::InvalidScreenshot
        );
    }
}
