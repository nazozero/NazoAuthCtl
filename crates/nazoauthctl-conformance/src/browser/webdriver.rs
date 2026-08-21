//! W3C WebDriver transport and managed local driver lifecycle.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use url::Url;

use super::validation::{MAX_TEXT_BYTES, is_loopback_host};
use super::{BrowserDriver, BrowserError, BrowserSelector, decode_webdriver_png};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 256;
const W3C_ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";
const LEGACY_ELEMENT_KEY: &str = "ELEMENT";

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
        let value = self.post_value("/session", &capabilities)?;
        let object = value.as_object().ok_or(BrowserError::Protocol)?;
        let session = object
            .get("sessionId")
            .and_then(Value::as_str)
            .or_else(|| {
                object
                    .get("value")
                    .and_then(|item| item.get("sessionId"))
                    .and_then(Value::as_str)
            })
            .ok_or(BrowserError::Protocol)?;
        if !valid_session_id(session) {
            return Err(BrowserError::Protocol);
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
        let _ = self.delete_value(&path);
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

    fn post_value(&self, path: &str, body: &Value) -> Result<Value, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(body).map_err(|_| BrowserError::Protocol)?)
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes)
    }

    fn get_value(&self, path: &str) -> Result<Value, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes)
    }

    fn delete_value(&self, path: &str) -> Result<Value, BrowserError> {
        let url = self.endpoint.endpoint_url(path)?;
        let response = self
            .client
            .delete(url)
            .header("Accept", "application/json")
            .send()
            .map_err(|_| BrowserError::Transport)?;
        parse_webdriver_response(response, self.max_response_bytes)
    }
}

impl BrowserDriver for WebDriverClient {
    fn ensure_session(&mut self) -> Result<(), BrowserError> {
        let path = self.session_path("/url")?;
        match self.get_value(&path) {
            Ok(_) => Ok(()),
            Err(BrowserError::InvalidSession) => {
                self.session_id = None;
                self.start_chrome()
            }
            Err(error) => Err(error),
        }
    }

    fn clear_cookies(&mut self) -> Result<(), BrowserError> {
        self.delete_value(&self.session_path("/cookie")?)
            .map(|_| ())
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
        let path = self.session_path("/url")?;
        self.post_value(&path, &json!({ "url": url.as_str() }))
            .map(|_| ())
    }

    fn current_url(&mut self) -> Result<Url, BrowserError> {
        let value = self.get_value(&self.session_path("/url")?)?;
        let text = value
            .get("value")
            .and_then(Value::as_str)
            .ok_or(BrowserError::Protocol)?;
        Url::parse(text).map_err(|_| BrowserError::Protocol)
    }

    fn page_source(&mut self) -> Result<String, BrowserError> {
        let value = self.get_value(&self.session_path("/source")?)?;
        let text = value
            .get("value")
            .and_then(Value::as_str)
            .ok_or(BrowserError::Protocol)?;
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(BrowserError::ResponseTooLarge);
        }
        Ok(text.to_owned())
    }

    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError> {
        let (using, value) = match selector {
            BrowserSelector::Id(value) => ("id", value.as_str()),
            BrowserSelector::Css(value) => ("css selector", value.as_str()),
            BrowserSelector::XPath(value) => ("xpath", value.as_str()),
        };
        let result = self.post_value(
            &self.session_path("/element")?,
            &json!({ "using": using, "value": value }),
        )?;
        let object = result
            .get("value")
            .and_then(Value::as_object)
            .ok_or(BrowserError::ElementNotFound)?;
        let id = object
            .get(W3C_ELEMENT_KEY)
            .or_else(|| object.get(LEGACY_ELEMENT_KEY))
            .and_then(Value::as_str)
            .ok_or(BrowserError::ElementNotFound)?;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(BrowserError::Protocol);
        }
        Ok(id.to_owned())
    }

    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError> {
        let value =
            self.get_value(&self.session_path(&format!("/element/{element}/displayed"))?)?;
        value
            .get("value")
            .and_then(Value::as_bool)
            .ok_or(BrowserError::Protocol)
    }

    fn element_text(&mut self, element: &str) -> Result<String, BrowserError> {
        let value = self.get_value(&self.session_path(&format!("/element/{element}/text"))?)?;
        let text = value
            .get("value")
            .and_then(Value::as_str)
            .ok_or(BrowserError::Protocol)?;
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(BrowserError::ResponseTooLarge);
        }
        Ok(text.to_owned())
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
        )
        .map(|_| ())
    }

    fn element_click(&mut self, element: &str) -> Result<(), BrowserError> {
        self.post_value(
            &self.session_path(&format!("/element/{element}/click"))?,
            &json!({}),
        )
        .map(|_| ())
    }

    fn screenshot_png(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, BrowserError> {
        let value = self.get_value(&self.session_path("/screenshot")?)?;
        parse_screenshot_response(&value)
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
    fn current_url(&mut self) -> Result<Url, BrowserError> {
        self.client.current_url()
    }
    fn page_source(&mut self) -> Result<String, BrowserError> {
        self.client.page_source()
    }
    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError> {
        self.client.find_element(selector)
    }
    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError> {
        self.client.element_displayed(element)
    }
    fn element_text(&mut self, element: &str) -> Result<String, BrowserError> {
        self.client.element_text(element)
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
) -> Result<Value, BrowserError> {
    let status = response.status();
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
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| BrowserError::Protocol)?;
    if !status.is_success() {
        // WebDriver error payloads often contain page text and selectors.  Do
        // not echo it. Preserve only the W3C error token needed by the bounded
        // browser state machine to distinguish normal DOM races from a driver
        // or protocol failure.
        return Err(classify_webdriver_error(&value));
    }
    Ok(value)
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
    fn session_ids_are_path_safe_and_bounded() {
        assert!(valid_session_id("session-01._abc"));
        assert!(!valid_session_id("session/01"));
        assert!(!valid_session_id("session?01"));
        assert!(!valid_session_id("session 01"));
        assert!(!valid_session_id(&"a".repeat(MAX_SESSION_ID_BYTES + 1)));
    }

    #[test]
    fn w3c_screenshot_response_accepts_only_bounded_canonical_png() {
        let png = b"\x89PNG\r\n\x1a\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(png);
        assert_eq!(
            parse_screenshot_response(&json!({"value": encoded}))
                .expect("w3c screenshot")
                .as_slice(),
            png
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
