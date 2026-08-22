//! Rust-native browser automation for the OpenID Foundation Suite.
//!
//! Suite browser values are data, not scripts. The schema/parser and origin
//! validation live in private modules; this file owns the driver-facing
//! execution state machine and its public orchestration traits.

use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::origin::Origin;

/// A response-shape observation is deliberately metadata-only.  It is safe to
/// retain in root-private run evidence: it has no response body, selector,
/// URL, session id, or browser content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebDriverProtocolDiagnostic {
    pub endpoint: &'static str,
    pub status: u16,
    pub content_type: &'static str,
    pub body_len: usize,
    pub body_sha256: String,
    pub value_type: &'static str,
    pub top_level_keys: Vec<String>,
}

impl std::fmt::Display for WebDriverProtocolDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "endpoint={} status={} content_type={} body_len={} body_sha256={} value_type={} top_level_keys={}",
            self.endpoint,
            self.status,
            self.content_type,
            self.body_len,
            self.body_sha256,
            self.value_type,
            self.top_level_keys.join(","),
        )
    }
}

/// Canonical navigation observations exclude userinfo, query, and fragment.
/// The matcher is a digest prefix rather than a raw Suite value so this can
/// safely travel through the persisted local error report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserNavigationDiagnostic {
    pub from: String,
    pub to: String,
    pub selected_entry: Option<usize>,
    pub matcher_sha256_prefix: Option<String>,
}

impl std::fmt::Display for BrowserNavigationDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "from={} to={} selected_entry={} matcher_sha256_prefix={}",
            self.from,
            self.to,
            self.selected_entry
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("none"),
            self.matcher_sha256_prefix.as_deref().unwrap_or("none"),
        )
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
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
    #[error("browser review screenshot is required but capture is unavailable")]
    ReviewScreenshotRequired,
    #[error("browser screenshot is invalid")]
    InvalidScreenshot,
    #[error("browser review evidence path is unsafe")]
    UnsafeEvidencePath,
    #[error("browser review evidence write failed")]
    EvidenceWrite,
    #[error("browser review screenshot limit exceeded")]
    ReviewScreenshotLimit,
    #[error("browser timeout expired")]
    Timeout,
    #[error("browser step limit exceeded")]
    StepLimit,
    #[error("browser redirect or navigation crossed the allowlist")]
    CrossOriginNavigation,
    #[error("browser redirect or navigation crossed the allowlist [{0}]")]
    CrossOriginNavigationDiagnostic(BrowserNavigationDiagnostic),
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
    #[error("browser WebDriver protocol response is invalid [{0}]")]
    ProtocolDiagnostic(WebDriverProtocolDiagnostic),
    #[error("browser WebDriver rejected the request")]
    DriverRejected,
    #[error("browser response exceeds the size limit")]
    ResponseTooLarge,
    #[error("browser session is already started")]
    SessionAlreadyStarted,
    #[error("browser session is not started")]
    SessionNotStarted,
    #[error("browser session expired or was removed")]
    InvalidSession,
    #[error("browser element was not found")]
    ElementNotFound,
    #[error("browser element became stale")]
    StaleElement,
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
    ConformanceBinding, OpenId4VpError, OpenId4VpEvidenceBindingDiagnostic,
    OpenId4VpEvidenceContext, OpenId4VpEvidenceRunContext, OpenId4VpEvidenceVerifier,
    OpenId4VpPresentation, OpenId4VpStartRequest, OpenId4VpVerificationEvidence,
    OpenId4VpVerificationReceiptProvenance, OpenId4VpVerifier, OpenId4VpVerifierClient,
};
pub use parser::{parse_browser_entries, parse_browser_entries_owned};
pub use plan::{BrowserRunnerState, OpenId4VcBrowserState};
pub use schema::{
    BrowserCommand, BrowserEntry, BrowserSelector, BrowserTask, ReviewScreenshotMarker,
};
pub use validation::{BrowserLimits, BrowserPolicy, BrowserTargetOrigin};
pub use webdriver::{ManagedWebDriver, WebDriverClient, WebDriverEndpoint};

#[cfg(test)]
use validation::MAX_TEXT_BYTES;
use validation::{
    DEFAULT_STEP_TIMEOUT, MAX_MATCH_BYTES, compile_pattern, glob_matches, redacted_origin,
    validate_match_pattern,
};

/// Select the Suite's explicit module-specific browser override when present.
/// Overrides are materialized before plan creation so the Suite WebRunner and
/// the local driver consume the same authoritative configuration.
pub(crate) fn browser_config_for_module(
    plan_config: &Value,
    test_name: &str,
) -> Result<Value, BrowserError> {
    let overridden = match plan_config.get("override") {
        None => None,
        Some(Value::Object(overrides)) => match overrides.get(test_name) {
            None => None,
            Some(Value::Object(module)) => module.get("browser").cloned(),
            Some(_) => return Err(BrowserError::InvalidSchema),
        },
        Some(_) => return Err(BrowserError::InvalidSchema),
    };
    overridden
        .or_else(|| plan_config.get("browser").cloned())
        .ok_or(BrowserError::InvalidSchema)
}

/// Driver abstraction used both by WebDriver and deterministic tests. A
/// driver never receives a URL before policy checks.
pub trait BrowserDriver: Send {
    /// Confirm that the session is live before another Suite module claims
    /// this lane. Implementations may recreate only an explicitly expired
    /// session; other failures remain fail-closed.
    fn ensure_session(&mut self) -> Result<(), BrowserError> {
        Ok(())
    }

    /// Remove client-side authentication state before another independent
    /// Suite module uses this worker lane. Implementations must not export or
    /// inspect cookie values.
    fn clear_cookies(&mut self) -> Result<(), BrowserError> {
        Ok(())
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError>;
    fn current_url(&mut self) -> Result<Url, BrowserError>;
    fn page_source(&mut self) -> Result<String, BrowserError>;
    fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError>;
    /// Find an element relative to a previously verified root.  VP evidence
    /// projections must not be satisfied by lookalike elements elsewhere in
    /// the document.
    fn find_child_element(
        &mut self,
        _parent: &str,
        _selector: &BrowserSelector,
    ) -> Result<String, BrowserError> {
        Err(BrowserError::UnsupportedCommand)
    }
    fn element_displayed(&mut self, element: &str) -> Result<bool, BrowserError>;
    fn element_text(&mut self, element: &str) -> Result<String, BrowserError>;
    fn element_attribute(
        &mut self,
        _element: &str,
        _name: &str,
    ) -> Result<Option<String>, BrowserError> {
        Err(BrowserError::UnsupportedCommand)
    }
    fn element_send_keys(&mut self, element: &str, value: &str) -> Result<(), BrowserError>;
    fn element_click(&mut self, element: &str) -> Result<(), BrowserError>;

    /// Return a W3C screenshot that has already passed strict base64 and PNG
    /// validation. Test drivers must opt in explicitly; browser commands
    /// requesting required review evidence otherwise fail closed.
    fn screenshot_png(&mut self) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
        Err(BrowserError::ReviewScreenshotRequired)
    }
}

/// Contract consumed by the conformance orchestrator while a Suite module is
/// in `WAITING`. This trait drives browser work only and returns no Suite
/// result, preserving the official PASS/FAIL decision.
pub trait BrowserAutomation: Send {
    /// Establish a clean browser boundary for the next Suite module. The
    /// default keeps non-browser test doubles source-compatible; production
    /// WebDriver automation overrides this and deletes every browser cookie.
    fn reset_session(&mut self) -> Result<(), BrowserError> {
        Ok(())
    }

    fn execute(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
    ) -> Result<BrowserRunReport, BrowserError>;

    /// Execute a signed browser program with module-scoped local review
    /// capture. Existing test doubles remain source-compatible, but cannot
    /// silently satisfy a required screenshot instruction.
    fn execute_with_review_capture(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
        capture: Option<&BrowserReviewCaptureContext>,
    ) -> Result<BrowserRunReport, BrowserError> {
        let mut report = self.execute(authorization_url, entries)?;
        let selected = entries
            .get(report.entry_index)
            .ok_or(BrowserError::InvalidSchema)?;
        // A browser program may have mutually-exclusive entries. A test
        // double cannot claim required capture for an entry it did not
        // actually select.
        for marker in review_screenshot_markers(std::slice::from_ref(selected)) {
            if report.review_screenshot_attempts >= MAX_REVIEW_SCREENSHOTS_PER_MODULE {
                return Err(BrowserError::ReviewScreenshotLimit);
            }
            report.review_screenshot_attempts = report.review_screenshot_attempts.saturating_add(1);
            match marker {
                ReviewScreenshotMarker::Required => {
                    return Err(BrowserError::ReviewScreenshotRequired);
                }
                ReviewScreenshotMarker::Optional => {
                    let _ = capture;
                    report.review_screenshots_missing =
                        report.review_screenshots_missing.saturating_add(1);
                }
            }
        }
        Ok(report)
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError>;

    /// Wait for an exact browser URL after an out-of-band flow, such as an
    /// OpenID4VP verifier start. Existing implementations fail closed unless
    /// they opt into URL polling.
    fn wait_for_url(&mut self, expected: &Url, timeout: Duration) -> Result<(), BrowserError> {
        let _ = (expected, timeout);
        Err(BrowserError::UnsupportedCommand)
    }

    /// Ask the lane which entry it would select *now* for the target's
    /// authorization URL, before the verifier is completed. This preserves
    /// `match_limit` and prior-entry accounting; callers must not infer the
    /// result from a different Suite URL or an unselected alternative.
    fn selected_openid4vp_result_marker(
        &mut self,
        _authorization_url: &Url,
        _entries: &[BrowserEntry],
        _suite_evidence_url: &Url,
    ) -> Result<bool, BrowserError> {
        Err(BrowserError::ReviewScreenshotRequired)
    }

    /// Navigate only to a verified NazoAuthWeb VP receipt view, prove its
    /// non-secret DOM projection matches the runtime-signed receipt, then
    /// capture the current page. This never executes Suite stand-in commands.
    fn capture_openid4vp_verification_result(
        &mut self,
        _evidence: &crate::browser::OpenId4VpVerificationEvidence,
        _capture: &BrowserReviewCaptureContext,
        _obligation_index: usize,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        Err(BrowserError::ReviewScreenshotRequired)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrowserRunReport {
    pub steps: usize,
    pub tasks: usize,
    pub entry_index: usize,
    pub final_origin: String,
    #[serde(skip)]
    pub review_screenshots: Vec<BrowserReviewScreenshotReceipt>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshot_attempts: usize,
    /// Number of signed required capture obligations reached by this browser
    /// program. This is kept separate from optional misses so callers can
    /// prove that every required instruction produced exactly one image.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshots_required: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshots_required_captured: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub review_screenshots_missing: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// Explicit, module-scoped local evidence capture configuration. The path is
/// never inferred from a browser URL or a Suite response.
#[derive(Clone)]
pub struct BrowserReviewScreenshotCapture {
    evidence_directory: PathBuf,
    run_jti: String,
    budget: Arc<Mutex<ReviewCaptureBudget>>,
}

#[derive(Default)]
struct ReviewCaptureBudget {
    attempts: usize,
    decoded_bytes: usize,
}

impl BrowserReviewScreenshotCapture {
    pub fn new(evidence_directory: PathBuf, run_jti: &str) -> Result<Self, BrowserError> {
        crate::evidence::validate_private_evidence_directory(&evidence_directory)
            .map_err(|_| BrowserError::UnsafeEvidencePath)?;
        safe_capture_component(run_jti)?;
        Ok(Self {
            evidence_directory,
            run_jti: run_jti.to_owned(),
            budget: Arc::new(Mutex::new(ReviewCaptureBudget::default())),
        })
    }

    pub fn context(
        &self,
        identity: BrowserReviewModuleIdentity,
        capture_index: usize,
    ) -> Result<BrowserReviewCaptureContext, BrowserError> {
        BrowserReviewCaptureContext::new(
            self.evidence_directory.clone(),
            self.run_jti.clone(),
            identity,
            capture_index,
            self.budget.clone(),
        )
    }

    pub(crate) fn shares_run_budget_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.budget, &other.budget)
    }
}

/// The signed/module allocation facts that bind a review capture. Keeping
/// them together prevents serial, parallel, and test callers from deriving
/// overlapping identities through separate argument lists.
#[derive(Clone)]
pub struct BrowserReviewModuleIdentity {
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: BTreeMap<String, String>,
}

impl BrowserReviewModuleIdentity {
    pub fn new(
        matrix_plan_id: &str,
        suite_plan_id: &str,
        module_id: &str,
        test_name: &str,
        variant: &BTreeMap<String, String>,
    ) -> Result<Self, BrowserError> {
        Ok(Self {
            matrix_plan_id: safe_capture_component(matrix_plan_id)?.to_owned(),
            suite_plan_id: safe_capture_component(suite_plan_id)?.to_owned(),
            module_id: safe_capture_component(module_id)?.to_owned(),
            test_name: safe_capture_component(test_name)?.to_owned(),
            variant: variant.clone(),
        })
    }
}

/// Identifies one Suite module's bounded review screenshot sequence. It never
/// contains the browser URL, page source, Suite token, or browser command text.
#[derive(Clone)]
pub struct BrowserReviewCaptureContext {
    evidence_directory: PathBuf,
    run_jti: String,
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: String,
    test_name: String,
    variant: BTreeMap<String, String>,
    capture_index: usize,
    budget: Arc<Mutex<ReviewCaptureBudget>>,
}

impl BrowserReviewCaptureContext {
    fn new(
        evidence_directory: PathBuf,
        run_jti: String,
        identity: BrowserReviewModuleIdentity,
        capture_index: usize,
        budget: Arc<Mutex<ReviewCaptureBudget>>,
    ) -> Result<Self, BrowserError> {
        Ok(Self {
            evidence_directory,
            run_jti,
            matrix_plan_id: identity.matrix_plan_id,
            suite_plan_id: identity.suite_plan_id,
            module_id: identity.module_id,
            test_name: identity.test_name,
            variant: identity.variant,
            capture_index,
            budget,
        })
    }

    fn for_index(&self, relative_index: usize) -> Result<Self, BrowserError> {
        let capture_index = self
            .capture_index
            .checked_add(relative_index)
            .ok_or(BrowserError::UnsafeEvidencePath)?;
        Ok(Self {
            evidence_directory: self.evidence_directory.clone(),
            run_jti: self.run_jti.clone(),
            matrix_plan_id: self.matrix_plan_id.clone(),
            suite_plan_id: self.suite_plan_id.clone(),
            module_id: self.module_id.clone(),
            test_name: self.test_name.clone(),
            variant: self.variant.clone(),
            capture_index,
            budget: self.budget.clone(),
        })
    }

    fn reserve_attempt(&self) -> Result<(), BrowserError> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| BrowserError::EvidenceWrite)?;
        let next = budget
            .attempts
            .checked_add(1)
            .ok_or(BrowserError::ReviewScreenshotLimit)?;
        if next > MAX_REVIEW_SCREENSHOTS_PER_RUN {
            return Err(BrowserError::ReviewScreenshotLimit);
        }
        budget.attempts = next;
        Ok(())
    }

    fn reserve_bytes(&self, size: usize) -> Result<(), BrowserError> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| BrowserError::EvidenceWrite)?;
        let next = budget
            .decoded_bytes
            .checked_add(size)
            .ok_or(BrowserError::ReviewScreenshotLimit)?;
        if next > 32 * 1024 * 1024 {
            return Err(BrowserError::ReviewScreenshotLimit);
        }
        budget.decoded_bytes = next;
        Ok(())
    }

    fn relative_path(&self) -> Result<PathBuf, BrowserError> {
        let name = format!(
            "{}--{}--{:03}.png",
            self.matrix_plan_id, self.module_id, self.capture_index
        );
        if name.len() > 240 {
            return Err(BrowserError::UnsafeEvidencePath);
        }
        Ok(PathBuf::from("review-screenshots")
            .join(&self.run_jti)
            .join(name))
    }

    fn write_png(
        &self,
        bytes: &[u8],
        trigger_url: &Url,
        marker: ReviewScreenshotMarker,
        obligation_index: usize,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        self.write_png_with_audit(
            bytes,
            trigger_url,
            marker,
            obligation_index,
            BrowserReviewScreenshotSource::SuiteVerificationEvidence,
            None,
        )
    }

    fn write_vp_png(
        &self,
        bytes: &[u8],
        trigger_url: &Url,
        marker: ReviewScreenshotMarker,
        obligation_index: usize,
        verification_receipt: &OpenId4VpVerificationReceiptProvenance,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        self.write_png_with_audit(
            bytes,
            trigger_url,
            marker,
            obligation_index,
            BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver,
            Some(verification_receipt),
        )
    }

    fn write_png_with_audit(
        &self,
        bytes: &[u8],
        trigger_url: &Url,
        marker: ReviewScreenshotMarker,
        obligation_index: usize,
        source: BrowserReviewScreenshotSource,
        verification_receipt: Option<&OpenId4VpVerificationReceiptProvenance>,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        validate_png_screenshot(bytes)?;
        if verification_receipt.is_some_and(|receipt| {
            receipt.receipt_sha256.len() != 64
                || !receipt
                    .receipt_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }) {
            return Err(BrowserError::InvalidScreenshot);
        }
        self.reserve_bytes(bytes.len())?;
        let relative_path = self.relative_path()?;
        let path = self.evidence_directory.join(&relative_path);
        let trigger_url_sha256 = match source {
            BrowserReviewScreenshotSource::SuiteVerificationEvidence => {
                sha256_hex(trigger_url.as_str().as_bytes())
            }
            BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver => sha256_hex(
                format!("{}{}", redacted_origin(trigger_url), trigger_url.path()).as_bytes(),
            ),
        };
        let receipt = BrowserReviewScreenshotReceipt {
            path: relative_path,
            sha256: sha256_hex(bytes),
            size: bytes.len(),
            suite_plan_id: self.suite_plan_id.clone(),
            module_id: self.module_id.clone(),
            test_name: self.test_name.clone(),
            variant: self.variant.clone(),
            marker,
            obligation_index,
            trigger_origin: redacted_origin(trigger_url),
            trigger_path: trigger_url.path().to_owned(),
            // The one-time VP capability sits only in the fragment. It is
            // deliberately excluded from durable evidence; its signed hash
            // was checked before this write.
            trigger_url_sha256,
            source,
            verification_receipt: verification_receipt.cloned(),
        };
        let audit = serde_json::to_vec(&BrowserReviewScreenshotAudit::from(&receipt))
            .map_err(|_| BrowserError::EvidenceWrite)?;
        let audit_path = path.with_extension("png.receipt.json");
        let image_outcome = write_private_new_or_exact(&path, bytes)?;
        if let Err(error) = write_private_new_or_exact(&audit_path, &audit) {
            if matches!(
                image_outcome,
                crate::secure_file::NewOrExactOutcome::Created
            ) {
                let _ = crate::secure_file::remove_private_file_if_exact(&path, bytes);
            }
            return Err(error);
        }
        Ok(receipt)
    }
}

fn write_private_new_or_exact(
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<crate::secure_file::NewOrExactOutcome, BrowserError> {
    crate::secure_file::write_new_or_exact_with_outcome(path, bytes, true)
        .map_err(|_| BrowserError::EvidenceWrite)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn canonical_navigation_url(url: &Url) -> String {
    let mut canonical = url.clone();
    canonical
        .set_username("")
        .expect("URL username can be cleared");
    canonical
        .set_password(None)
        .expect("URL password can be cleared");
    canonical.set_query(None);
    canonical.set_fragment(None);
    canonical.to_string()
}

/// Private orchestration receipt. Public module reports project only
/// `path`, `sha256`, and `size` from this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserReviewScreenshotReceipt {
    pub path: PathBuf,
    pub sha256: String,
    pub size: usize,
    pub suite_plan_id: String,
    pub module_id: String,
    pub test_name: String,
    pub variant: BTreeMap<String, String>,
    pub marker: ReviewScreenshotMarker,
    pub obligation_index: usize,
    pub trigger_origin: String,
    pub trigger_path: String,
    pub trigger_url_sha256: String,
    pub source: BrowserReviewScreenshotSource,
    pub verification_receipt: Option<OpenId4VpVerificationReceiptProvenance>,
}

/// The only two review image origins. The NazoAuthWeb source is admitted only
/// after a same-module, runtime-signed OpenID4VP receipt was verified.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum BrowserReviewScreenshotSource {
    #[serde(rename = "suite-verification-evidence")]
    #[default]
    SuiteVerificationEvidence,
    #[serde(rename = "nazo-vp-verification-result/live-webdriver")]
    NazoVpVerificationResultLiveWebdriver,
}

#[derive(Serialize)]
struct BrowserReviewScreenshotAudit<'a> {
    suite_plan_id: &'a str,
    module_id: &'a str,
    test_name: &'a str,
    variant: &'a BTreeMap<String, String>,
    marker: ReviewScreenshotMarker,
    obligation_index: usize,
    path: &'a PathBuf,
    sha256: &'a str,
    size: usize,
    trigger_origin: &'a str,
    trigger_path: &'a str,
    trigger_url_sha256: &'a str,
    source: BrowserReviewScreenshotSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_receipt: Option<&'a OpenId4VpVerificationReceiptProvenance>,
}

impl<'a> From<&'a BrowserReviewScreenshotReceipt> for BrowserReviewScreenshotAudit<'a> {
    fn from(receipt: &'a BrowserReviewScreenshotReceipt) -> Self {
        Self {
            suite_plan_id: &receipt.suite_plan_id,
            module_id: &receipt.module_id,
            test_name: &receipt.test_name,
            variant: &receipt.variant,
            marker: receipt.marker,
            obligation_index: receipt.obligation_index,
            path: &receipt.path,
            sha256: &receipt.sha256,
            size: receipt.size,
            trigger_origin: &receipt.trigger_origin,
            trigger_path: &receipt.trigger_path,
            trigger_url_sha256: &receipt.trigger_url_sha256,
            source: receipt.source,
            verification_receipt: receipt.verification_receipt.as_ref(),
        }
    }
}

const MAX_REVIEW_SCREENSHOT_BYTES: usize = 500 * 1024;
pub(crate) const MAX_REVIEW_SCREENSHOTS_PER_MODULE: usize = 2;
pub(crate) const MAX_REVIEW_SCREENSHOTS_PER_RUN: usize = 64;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const OFFICIAL_SUITE_ORIGIN: &str = "https://www.certification.openid.net";

pub(crate) fn decode_webdriver_png(value: &str) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
    const MAX_BASE64_BYTES: usize = MAX_REVIEW_SCREENSHOT_BYTES.div_ceil(3) * 4;
    if value.is_empty() || value.len() > MAX_BASE64_BYTES {
        return Err(BrowserError::InvalidScreenshot);
    }
    let bytes = STANDARD
        .decode(value.as_bytes())
        .map_err(|_| BrowserError::InvalidScreenshot)?;
    if STANDARD.encode(&bytes) != value {
        return Err(BrowserError::InvalidScreenshot);
    }
    validate_png_screenshot(&bytes)?;
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn validate_png_screenshot(bytes: &[u8]) -> Result<(), BrowserError> {
    if bytes.len() > MAX_REVIEW_SCREENSHOT_BYTES || !bytes.starts_with(PNG_SIGNATURE) {
        return Err(BrowserError::InvalidScreenshot);
    }
    // PNG is deliberately parsed completely here instead of accepting a
    // magic prefix. WebDriver output is untrusted input at this boundary.
    // Bound width/height and verify every chunk CRC before evidence reaches
    // the root-owned directory. The browser is the only producer, so we do
    // not accept ancillary trailing bytes or a truncated IEND.
    let mut cursor = PNG_SIGNATURE.len();
    let mut saw_ihdr = false;
    let mut saw_idat = false;
    let mut saw_iend = false;
    while cursor < bytes.len() {
        let header_end = cursor
            .checked_add(8)
            .ok_or(BrowserError::InvalidScreenshot)?;
        if header_end > bytes.len() {
            return Err(BrowserError::InvalidScreenshot);
        }
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| BrowserError::InvalidScreenshot)?,
        ) as usize;
        let kind = &bytes[cursor + 4..header_end];
        let data_end = header_end
            .checked_add(length)
            .ok_or(BrowserError::InvalidScreenshot)?;
        let crc_end = data_end
            .checked_add(4)
            .ok_or(BrowserError::InvalidScreenshot)?;
        if crc_end > bytes.len() {
            return Err(BrowserError::InvalidScreenshot);
        }
        let expected_crc = u32::from_be_bytes(
            bytes[data_end..crc_end]
                .try_into()
                .map_err(|_| BrowserError::InvalidScreenshot)?,
        );
        if png_crc32(&bytes[cursor + 4..data_end]) != expected_crc {
            return Err(BrowserError::InvalidScreenshot);
        }
        match kind {
            b"IHDR" if !saw_ihdr && !saw_idat && !saw_iend && length == 13 => {
                let width = u32::from_be_bytes(
                    bytes[header_end..header_end + 4]
                        .try_into()
                        .map_err(|_| BrowserError::InvalidScreenshot)?,
                );
                let height = u32::from_be_bytes(
                    bytes[header_end + 4..header_end + 8]
                        .try_into()
                        .map_err(|_| BrowserError::InvalidScreenshot)?,
                );
                let bit_depth = bytes[header_end + 8];
                let color_type = bytes[header_end + 9];
                if width == 0
                    || height == 0
                    || width > 8_192
                    || height > 8_192
                    || u64::from(width) * u64::from(height) > 16 * 1024 * 1024
                    || !matches!(bit_depth, 1 | 2 | 4 | 8 | 16)
                    || !matches!(color_type, 0 | 2 | 3 | 4 | 6)
                    || bytes[header_end + 10] != 0
                    || bytes[header_end + 11] != 0
                    || bytes[header_end + 12] > 1
                {
                    return Err(BrowserError::InvalidScreenshot);
                }
                saw_ihdr = true;
            }
            b"IDAT" if saw_ihdr && !saw_iend && length > 0 => saw_idat = true,
            b"IEND" if saw_ihdr && saw_idat && !saw_iend && length == 0 => {
                saw_iend = true;
                if crc_end != bytes.len() {
                    return Err(BrowserError::InvalidScreenshot);
                }
            }
            _ if saw_iend || !saw_ihdr => return Err(BrowserError::InvalidScreenshot),
            _ => {}
        }
        cursor = crc_end;
    }
    if !saw_ihdr || !saw_idat || !saw_iend {
        return Err(BrowserError::InvalidScreenshot);
    }
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_limits(png::Limits {
        bytes: 64 * 1024 * 1024,
    });
    let mut reader = decoder
        .read_info()
        .map_err(|_| BrowserError::InvalidScreenshot)?;
    let info = reader.info();
    if info.is_animated()
        || info.width == 0
        || info.height == 0
        || info.width > 8_192
        || info.height > 8_192
        || u64::from(info.width) * u64::from(info.height) > 16 * 1024 * 1024
    {
        return Err(BrowserError::InvalidScreenshot);
    }
    let output_size = reader
        .output_buffer_size()
        .filter(|size| *size <= 64 * 1024 * 1024)
        .ok_or(BrowserError::InvalidScreenshot)?;
    let mut decoded = Zeroizing::new(vec![0_u8; output_size]);
    reader
        .next_frame(decoded.as_mut_slice())
        .map_err(|_| BrowserError::InvalidScreenshot)?;
    Ok(())
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn safe_capture_component(value: &str) -> Result<&str, BrowserError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(BrowserError::UnsafeEvidencePath);
    }
    Ok(value)
}

fn review_screenshot_markers(
    entries: &[BrowserEntry],
) -> impl Iterator<Item = ReviewScreenshotMarker> + '_ {
    entries.iter().flat_map(|entry| {
        entry.tasks.iter().flat_map(|task| {
            task.commands.iter().filter_map(|command| match command {
                BrowserCommand::WaitForElement {
                    review_screenshot: Some(marker),
                    ..
                } => Some(*marker),
                _ => None,
            })
        })
    })
}

pub(crate) fn required_review_screenshot_count(entries: &[BrowserEntry]) -> usize {
    review_screenshot_markers(entries)
        .filter(|marker| *marker == ReviewScreenshotMarker::Required)
        .count()
}

/// Returns true only when the browser program's already-*selected* entry
/// reaches exactly one current-module verification-evidence task with one
/// non-optional required screenshot command. Other entries (including
/// mutually exclusive alternatives) deliberately have no authority to ask
/// NazoAuth for a one-time VP result capability.
pub(crate) fn selected_required_review_screenshot_marker(
    entry: &BrowserEntry,
    suite_evidence_url: &Url,
) -> Result<bool, BrowserError> {
    let mut markers = 0usize;
    for task in &entry.tasks {
        // A marker with no URL gate would execute on whichever page the
        // browser happened to retain.  It has no authority to request a VP
        // result capability.  The selected entry must explicitly wait for
        // this module's signed Suite evidence URL.
        let Some(pattern) = task.match_pattern.as_deref() else {
            continue;
        };
        if task.optional || !glob_matches(pattern, suite_evidence_url.as_str()) {
            continue;
        }
        for command in &task.commands {
            if matches!(
                command,
                BrowserCommand::WaitForElement {
                    review_screenshot: Some(ReviewScreenshotMarker::Required),
                    ..
                }
            ) {
                markers = markers.saturating_add(1);
            }
        }
    }
    Ok(markers == 1)
}

pub struct BrowserExecutor<D> {
    driver: D,
    policy: BrowserPolicy,
    entry_uses: HashMap<usize, u32>,
    steps: usize,
    redirects: usize,
    last_url: Option<Url>,
    active_entry: Option<BrowserNavigationEntry>,
}

#[derive(Clone)]
struct BrowserNavigationEntry {
    index: usize,
    matcher_sha256_prefix: String,
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
            active_entry: None,
        }
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    pub fn policy(&self) -> &BrowserPolicy {
        &self.policy
    }

    pub fn run_commands(&mut self, commands: &[BrowserCommand]) -> Result<usize, BrowserError> {
        self.run_commands_with_review_capture(
            commands,
            None,
            &mut BrowserRunReport {
                steps: 0,
                tasks: 0,
                entry_index: 0,
                final_origin: String::new(),
                review_screenshots: Vec::new(),
                review_screenshot_attempts: 0,
                review_screenshots_required: 0,
                review_screenshots_required_captured: 0,
                review_screenshots_missing: 0,
            },
        )
    }

    fn run_commands_with_review_capture(
        &mut self,
        commands: &[BrowserCommand],
        capture: Option<&BrowserReviewCaptureContext>,
        report: &mut BrowserRunReport,
    ) -> Result<usize, BrowserError> {
        if commands.len() > self.policy.limits.max_steps.saturating_sub(self.steps) {
            return Err(BrowserError::StepLimit);
        }
        let mut executed = 0usize;
        'commands: for command in commands {
            let marker = match command {
                BrowserCommand::WaitForElement {
                    review_screenshot, ..
                } => *review_screenshot,
                _ => None,
            };
            if marker.is_some()
                && let Some(capture) = capture
            {
                capture.reserve_attempt()?;
            }
            if let Err(error) = self.execute_command(command) {
                // An optional marker is a signed best-effort capture point,
                // not permission to capture the previous page.  Skip this
                // action only. Do not execute later commands for this task on
                // the previous page; the outer task loop may continue.
                if marker == Some(ReviewScreenshotMarker::Optional)
                    && matches!(
                        error,
                        BrowserError::Timeout
                            | BrowserError::ElementNotFound
                            | BrowserError::StaleElement
                    )
                {
                    report.review_screenshot_attempts =
                        report.review_screenshot_attempts.saturating_add(1);
                    report.review_screenshots_missing =
                        report.review_screenshots_missing.saturating_add(1);
                    break 'commands;
                }
                return Err(error);
            }
            executed += 1;
            self.steps = self.steps.saturating_add(1);
            let trigger_url = self.ensure_current_url()?;
            if let Some(marker) = marker {
                let index = report.review_screenshot_attempts;
                if index >= MAX_REVIEW_SCREENSHOTS_PER_MODULE {
                    return Err(BrowserError::ReviewScreenshotLimit);
                }
                report.review_screenshot_attempts = index.saturating_add(1);
                if marker == ReviewScreenshotMarker::Required {
                    report.review_screenshots_required =
                        report.review_screenshots_required.saturating_add(1);
                }
                match capture {
                    Some(capture) => {
                        self.capture_review_screenshot(
                            capture,
                            index,
                            &trigger_url,
                            marker,
                            report,
                        )?;
                    }
                    None if marker == ReviewScreenshotMarker::Required => {
                        return Err(BrowserError::ReviewScreenshotRequired);
                    }
                    None => {
                        report.review_screenshots_missing =
                            report.review_screenshots_missing.saturating_add(1);
                    }
                }
            }
        }
        Ok(executed)
    }

    fn capture_review_screenshot(
        &mut self,
        capture: &BrowserReviewCaptureContext,
        index: usize,
        trigger_url: &Url,
        marker: ReviewScreenshotMarker,
        report: &mut BrowserRunReport,
    ) -> Result<(), BrowserError> {
        if self.policy.suite_origin.as_str() != OFFICIAL_SUITE_ORIGIN
            || !self.policy.suite_origin.same_origin_url(trigger_url)
            || !review_screenshot_path_binds_module(trigger_url, &capture.module_id)
        {
            return Err(self.navigation_violation(self.last_url.as_ref(), trigger_url));
        }
        let context = capture.for_index(index);
        let result = context.and_then(|context| {
            let screenshot = self.driver.screenshot_png()?;
            context.write_png(&screenshot, trigger_url, marker, index)
        });
        match result {
            Ok(receipt) => {
                if marker == ReviewScreenshotMarker::Required {
                    report.review_screenshots_required_captured = report
                        .review_screenshots_required_captured
                        .saturating_add(1);
                }
                report.review_screenshots.push(receipt);
                Ok(())
            }
            Err(error) if marker == ReviewScreenshotMarker::Optional => {
                let _ = error;
                report.review_screenshots_missing =
                    report.review_screenshots_missing.saturating_add(1);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn capture_openid4vp_verification_result(
        &mut self,
        evidence: &OpenId4VpVerificationEvidence,
        capture: &BrowserReviewCaptureContext,
        obligation_index: usize,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        if obligation_index >= MAX_REVIEW_SCREENSHOTS_PER_MODULE {
            return Err(BrowserError::ReviewScreenshotLimit);
        }
        // Reserve before navigating or asking WebDriver for bytes, so the
        // shared cross-lane budget cannot be exceeded by concurrent workers.
        capture.reserve_attempt()?;
        let ui_url = evidence
            .ui_url()
            .map_err(|_| BrowserError::CrossOriginNavigation)?;
        if !self.policy.target_origin.allows(&ui_url)
            || ui_url.path() != "/ui/verification-result"
            || ui_url.query().is_some()
            || !ui_url.fragment().is_some_and(|fragment| {
                fragment.len() == "receipt=".len() + 43
                    && fragment.starts_with("receipt=")
                    && fragment["receipt=".len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return Err(self.navigation_violation(self.last_url.as_ref(), &ui_url));
        }
        self.navigate(&ui_url)?;
        let current = self.ensure_current_url()?;
        if !self.policy.target_origin.allows(&current)
            || current.path() != "/ui/verification-result"
            || current.query().is_some()
            || current.fragment().is_some()
        {
            return Err(self.navigation_violation(self.last_url.as_ref(), &current));
        }
        let deadline = self.deadline(DEFAULT_STEP_TIMEOUT);
        loop {
            let root = self.driver.find_element(&BrowserSelector::Css(
                "[data-testid=\"vp-verification-result\"]".to_owned(),
            ));
            match root {
                Ok(root) => match self
                    .driver
                    .element_attribute(&root, "data-state")?
                    .as_deref()
                {
                    Some("verified") => {
                        if !self.driver.element_displayed(&root)? {
                            return Err(BrowserError::Protocol);
                        }
                        break;
                    }
                    Some("loading") => self.sleep_until(deadline)?,
                    _ => return Err(BrowserError::Protocol),
                },
                Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {
                    self.sleep_until(deadline)?;
                }
                Err(error) => return Err(error),
            }
        }
        self.verify_openid4vp_result_projection(evidence)?;
        // Re-observe after the DOM checks: a page that navigates during the
        // bounded wait must not donate a screenshot from another origin.
        let current = self.ensure_current_url()?;
        if !self.policy.target_origin.allows(&current)
            || current.path() != "/ui/verification-result"
            || current.query().is_some()
            || current.fragment().is_some()
        {
            return Err(self.navigation_violation(self.last_url.as_ref(), &current));
        }
        let context = capture.for_index(obligation_index)?;
        let screenshot = self.driver.screenshot_png()?;
        // The screenshot bytes are still only in memory. Recheck both the
        // URL and all visible DOM bindings before the durable PNG/receipt
        // pair is committed, so a late navigation cannot donate another page.
        let current = self.ensure_current_url()?;
        if !self.policy.target_origin.allows(&current)
            || current.path() != "/ui/verification-result"
            || current.query().is_some()
            || current.fragment().is_some()
        {
            return Err(self.navigation_violation(self.last_url.as_ref(), &current));
        }
        self.verify_openid4vp_result_projection(evidence)?;
        context.write_vp_png(
            &screenshot,
            &current,
            ReviewScreenshotMarker::Required,
            obligation_index,
            &evidence.receipt,
        )
    }

    fn expect_result_text(
        &mut self,
        root: &str,
        test_id: &str,
        expected: &str,
    ) -> Result<(), BrowserError> {
        let element = self.driver.find_child_element(
            root,
            &BrowserSelector::Css(format!("[data-testid=\"{test_id}\"]")),
        )?;
        if !self.driver.element_displayed(&element)?
            || self.driver.element_text(&element)? != expected
        {
            return Err(BrowserError::Protocol);
        }
        Ok(())
    }

    fn verify_openid4vp_result_projection(
        &mut self,
        evidence: &OpenId4VpVerificationEvidence,
    ) -> Result<(), BrowserError> {
        let root = self.driver.find_element(&BrowserSelector::Css(
            "[data-testid=\"vp-verification-result\"]".to_owned(),
        ))?;
        if !self.driver.element_displayed(&root)?
            || self
                .driver
                .element_attribute(&root, "data-state")?
                .as_deref()
                != Some("verified")
        {
            return Err(BrowserError::Protocol);
        }
        self.expect_result_text(&root, "vp-verification-status", "Verification successful")?;
        self.expect_result_text(&root, "vp-run-jti", &evidence.context.run_jti)?;
        self.expect_result_text(
            &root,
            "vp-artifact-sha256",
            &evidence.context.artifact_sha256,
        )?;
        self.expect_result_text(&root, "vp-matrix-sha256", &evidence.context.matrix_sha256)?;
        self.expect_result_text(&root, "vp-test-name", &evidence.context.test_name)?;
        self.expect_result_text(&root, "vp-suite-plan-id", &evidence.context.suite_plan_id)?;
        self.expect_result_text(
            &root,
            "vp-suite-module-id",
            &evidence.context.suite_module_id,
        )?;
        self.expect_result_text(&root, "vp-variant-sha256", &evidence.context.variant_sha256)?;
        self.expect_result_text(&root, "vp-receipt-sha256", &evidence.receipt.receipt_sha256)
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
                ..
            } => {
                let deadline = self.deadline(*timeout);
                loop {
                    match self.driver.find_element(selector) {
                        Ok(element) => {
                            if let Some(pattern) = text_pattern {
                                match self.driver.element_text(&element) {
                                    Ok(text) if compile_pattern(pattern)?.is_match(&text) => {
                                        return Ok(());
                                    }
                                    Ok(_)
                                    | Err(
                                        BrowserError::ElementNotFound | BrowserError::StaleElement,
                                    ) => {}
                                    Err(error) => return Err(error),
                                }
                            } else {
                                return Ok(());
                            }
                        }
                        Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                        Err(error) => return Err(error),
                    }
                    self.sleep_until(deadline)?;
                }
            }
            BrowserCommand::WaitElementVisible { selector, timeout } => {
                let deadline = self.deadline(*timeout);
                loop {
                    match self.driver.find_element(selector) {
                        Ok(element) => match self.driver.element_displayed(&element) {
                            Ok(true) => return Ok(()),
                            Ok(false)
                            | Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                            Err(error) => return Err(error),
                        },
                        Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                        Err(error) => return Err(error),
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
                let deadline = self.deadline(self.policy.limits.max_step_timeout);
                loop {
                    match self.driver.find_element(selector) {
                        Ok(element) => {
                            match self.driver.element_send_keys(&element, value.as_str()) {
                                Ok(()) => return Ok(()),
                                Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                        Err(error) => return Err(error),
                    }
                    self.sleep_until(deadline)?;
                }
            }
            BrowserCommand::Click { selector, optional } => {
                let deadline = self.deadline(self.policy.limits.max_step_timeout);
                loop {
                    match self.driver.find_element(selector) {
                        Ok(element) => match self.driver.element_click(&element) {
                            Ok(()) => return Ok(()),
                            Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                            Err(error) => return Err(error),
                        },
                        Err(BrowserError::ElementNotFound | BrowserError::StaleElement)
                            if *optional =>
                        {
                            return Ok(());
                        }
                        Err(BrowserError::ElementNotFound | BrowserError::StaleElement) => {}
                        Err(error) => return Err(error),
                    }
                    self.sleep_until(deadline)?;
                }
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
        self.policy
            .validate_url(&current)
            .map_err(|_| self.navigation_violation(self.last_url.as_ref(), &current))?;
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

    fn select_navigation_entry(&mut self, index: usize, entry: &BrowserEntry) {
        let matcher_sha256_prefix = sha256_hex(entry.match_pattern.as_bytes())
            .chars()
            .take(12)
            .collect();
        self.active_entry = Some(BrowserNavigationEntry {
            index,
            matcher_sha256_prefix,
        });
    }

    fn navigation_violation(&self, from: Option<&Url>, to: &Url) -> BrowserError {
        BrowserError::CrossOriginNavigationDiagnostic(BrowserNavigationDiagnostic {
            from: from
                .map(canonical_navigation_url)
                .unwrap_or_else(|| "none".to_owned()),
            to: canonical_navigation_url(to),
            selected_entry: self.active_entry.as_ref().map(|entry| entry.index),
            matcher_sha256_prefix: self
                .active_entry
                .as_ref()
                .map(|entry| entry.matcher_sha256_prefix.clone()),
        })
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

    fn selected_openid4vp_result_marker(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
        suite_evidence_url: &Url,
    ) -> Result<bool, BrowserError> {
        let entry_index = self.matching_entry(authorization_url, entries)?;
        let entry = entries
            .get(entry_index)
            .ok_or(BrowserError::InvalidSchema)?;
        self.select_navigation_entry(entry_index, entry);
        selected_required_review_screenshot_marker(entry, suite_evidence_url)
    }

    fn execute_inner(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
        capture: Option<&BrowserReviewCaptureContext>,
    ) -> Result<BrowserRunReport, BrowserError> {
        if entries.is_empty() {
            return Err(BrowserError::InvalidSchema);
        }
        self.policy.validate_url(authorization_url)?;
        self.redirects = 0;
        self.last_url = None;
        let entry_index = self.matching_entry(authorization_url, entries)?;
        let entry = entries
            .get(entry_index)
            .ok_or(BrowserError::InvalidSchema)?;
        self.select_navigation_entry(entry_index, entry);
        self.navigate(authorization_url)?;
        *self.entry_uses.entry(entry_index).or_default() += 1;
        let mut report = BrowserRunReport {
            steps: 0,
            tasks: 0,
            entry_index,
            final_origin: String::new(),
            review_screenshots: Vec::new(),
            review_screenshot_attempts: 0,
            review_screenshots_required: 0,
            review_screenshots_required_captured: 0,
            review_screenshots_missing: 0,
        };
        for task in &entry.tasks {
            let mut task_matched = true;
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
                            task_matched = false;
                            break 'wait_for_task;
                        }
                        return Err(BrowserError::Timeout);
                    }
                }
            }
            // A signed optional task whose selector never became true has
            // not authorized any of its commands (including screenshot
            // capture). Continue with the next task rather than executing on
            // the previous page.
            if !task_matched {
                continue;
            }
            self.run_commands_with_review_capture(&task.commands, capture, &mut report)?;
            report.tasks = report.tasks.saturating_add(1);
        }
        let final_url = self.ensure_current_url()?;
        report.steps = self.steps;
        report.final_origin = redacted_origin(&final_url);
        Ok(report)
    }
}

/// Review evidence is an explicit Suite-module artefact. Capturing an issuer
/// page, another Suite module, or a generic Suite landing page would create a
/// misleading local receipt even though the browser policy permits those
/// pages for normal protocol automation.
pub(crate) fn review_screenshot_path_binds_module(url: &Url, module_id: &str) -> bool {
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some(mut segments) = url.path_segments() else {
        return false;
    };
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next()
        ),
        (Some("test"), Some("a"), Some(module), Some("verification-evidence"), None)
            if module == module_id
    )
}

impl<D: BrowserDriver> BrowserAutomation for BrowserExecutor<D> {
    fn reset_session(&mut self) -> Result<(), BrowserError> {
        // W3C delete-all-cookies is scoped to the current browsing context's
        // cookie domain. Visit and clear each allowed origin independently;
        // validation rejects a redirect from target to Suite (or vice versa)
        // even though both origins are otherwise allowed for a test flow.
        self.driver.ensure_session()?;
        let target = self.policy.target_origin.as_url().clone();
        let suite = self
            .policy
            .suite_origin
            .url("/")
            .map_err(|_| BrowserError::InvalidOrigin)?;
        for expected in [&target, &suite] {
            self.policy.validate_url(expected)?;
            self.driver.navigate(expected)?;
            let actual = self.driver.current_url()?;
            self.policy.validate_cookie_redirect(expected, &actual)?;
            self.driver.clear_cookies()?;
        }
        self.entry_uses.clear();
        self.steps = 0;
        self.redirects = 0;
        self.last_url = None;
        self.active_entry = None;
        Ok(())
    }

    fn execute(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
    ) -> Result<BrowserRunReport, BrowserError> {
        self.execute_inner(authorization_url, entries, None)
    }

    fn execute_with_review_capture(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
        capture: Option<&BrowserReviewCaptureContext>,
    ) -> Result<BrowserRunReport, BrowserError> {
        self.execute_inner(authorization_url, entries, capture)
    }

    fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
        self.policy
            .validate_url(url)
            .map_err(|_| self.navigation_violation(self.last_url.as_ref(), url))?;
        self.redirects = 0;
        self.last_url = Some(url.clone());
        self.driver.navigate(url)?;
        self.ensure_current_url().map(|_| ())
    }

    fn wait_for_url(&mut self, expected: &Url, timeout: Duration) -> Result<(), BrowserError> {
        self.policy
            .validate_url(expected)
            .map_err(|_| self.navigation_violation(self.last_url.as_ref(), expected))?;
        let deadline = self.deadline(timeout);
        loop {
            let current = self.ensure_current_url()?;
            if current == *expected {
                return Ok(());
            }
            self.sleep_until(deadline)?;
        }
    }

    fn selected_openid4vp_result_marker(
        &mut self,
        authorization_url: &Url,
        entries: &[BrowserEntry],
        suite_evidence_url: &Url,
    ) -> Result<bool, BrowserError> {
        BrowserExecutor::selected_openid4vp_result_marker(
            self,
            authorization_url,
            entries,
            suite_evidence_url,
        )
    }

    fn capture_openid4vp_verification_result(
        &mut self,
        evidence: &OpenId4VpVerificationEvidence,
        capture: &BrowserReviewCaptureContext,
        obligation_index: usize,
    ) -> Result<BrowserReviewScreenshotReceipt, BrowserError> {
        BrowserExecutor::capture_openid4vp_verification_result(
            self,
            evidence,
            capture,
            obligation_index,
        )
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

        assert!(matches!(
            BrowserCommand::try_from(&json!([
                "wait",
                "xpath",
                "//*",
                1,
                ".*",
                "update-image-placeholder"
            ])),
            Ok(BrowserCommand::WaitForElement {
                selector: BrowserSelector::XPath(_),
                review_screenshot: Some(ReviewScreenshotMarker::Required),
                ..
            })
        ));
        assert!(matches!(
            BrowserCommand::try_from(&json!([
                "wait",
                "css",
                ".review",
                1,
                ".*",
                "update-image-placeholder-optional"
            ])),
            Ok(BrowserCommand::WaitForElement {
                review_screenshot: Some(ReviewScreenshotMarker::Optional),
                ..
            })
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

    #[test]
    fn suite_browser_state_projects_urls_from_the_full_runner_shape() {
        let policy = BrowserPolicy::new(
            BrowserTargetOrigin::parse("https://target.example").expect("target"),
            Origin::parse("https://suite.example").expect("suite"),
        )
        .expect("policy");
        let state = BrowserRunnerState::parse(
            &json!({
                "show_qr_code": false,
                "urls": [],
                "urlsWithMethod": [],
                "browserApiRequests": [],
                "uriInputRequests": [],
                "visited": [{
                    "url": "https://target.example/authorize?state=opaque",
                    "method": "GET"
                }],
                "visitedUrlsWithMethod": [],
                "runners": []
            }),
            &policy,
        )
        .expect("runner browser state");
        assert!(state.pending_url().is_none());
        assert_eq!(state.visited().first().map(Url::path), Some("/authorize"));

        let logout = BrowserRunnerState::parse(
            &json!({
                "urls": ["https://target.example/logout"],
                "visited": []
            }),
            &policy,
        )
        .expect("OIDC logout runner URL");
        assert_eq!(logout.pending_url().map(Url::path), Some("/logout"));

        assert!(matches!(
            BrowserRunnerState::parse(
                &json!({
                    "urls": [{
                        "url": "https://target.example/authorize?state=opaque",
                        "method": "POST"
                    }],
                    "visited": []
                }),
                &policy,
            ),
            Err(BrowserError::UnsupportedCommand)
        ));
    }

    struct MockDriver {
        current: Url,
        source: String,
        found: bool,
        displayed: bool,
        clicked: bool,
        cookies_cleared: bool,
        cookie_clear_count: usize,
        navigated: Vec<Url>,
        redirect_to: Option<Url>,
        session_checks: usize,
    }

    impl BrowserDriver for MockDriver {
        fn ensure_session(&mut self) -> Result<(), BrowserError> {
            self.session_checks += 1;
            Ok(())
        }

        fn clear_cookies(&mut self) -> Result<(), BrowserError> {
            self.cookies_cleared = true;
            self.cookie_clear_count += 1;
            Ok(())
        }

        fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
            self.navigated.push(url.clone());
            self.current = self.redirect_to.clone().unwrap_or_else(|| url.clone());
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

        fn screenshot_png(&mut self) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
            Ok(Zeroizing::new(test_png()))
        }
    }

    fn test_png() -> Vec<u8> {
        STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .expect("fixed PNG")
    }

    struct VpResultDriver {
        current: Url,
        run_jti: String,
        artifact_sha256: String,
        matrix_sha256: String,
        test_name: String,
        suite_plan_id: String,
        module_id: String,
        variant_sha256: String,
        receipt_sha256: String,
        allow_root_children: bool,
        navigated: Vec<Url>,
    }

    impl BrowserDriver for VpResultDriver {
        fn navigate(&mut self, url: &Url) -> Result<(), BrowserError> {
            self.navigated.push(url.clone());
            self.current = url.clone();
            self.current.set_fragment(None);
            Ok(())
        }

        fn current_url(&mut self) -> Result<Url, BrowserError> {
            Ok(self.current.clone())
        }

        fn page_source(&mut self) -> Result<String, BrowserError> {
            Ok(String::new())
        }

        fn find_element(&mut self, selector: &BrowserSelector) -> Result<String, BrowserError> {
            match selector {
                BrowserSelector::Css(value) if value.contains("data-testid") => Ok(value.clone()),
                _ => Err(BrowserError::ElementNotFound),
            }
        }

        fn find_child_element(
            &mut self,
            parent: &str,
            selector: &BrowserSelector,
        ) -> Result<String, BrowserError> {
            if !parent.contains("vp-verification-result") {
                return Err(BrowserError::ElementNotFound);
            }
            if !self.allow_root_children {
                return Err(BrowserError::ElementNotFound);
            }
            self.find_element(selector)
        }

        fn element_displayed(&mut self, _element: &str) -> Result<bool, BrowserError> {
            Ok(true)
        }

        fn element_text(&mut self, element: &str) -> Result<String, BrowserError> {
            if element.contains("vp-verification-status") {
                Ok("Verification successful".to_owned())
            } else if element.contains("vp-run-jti") {
                Ok(self.run_jti.clone())
            } else if element.contains("vp-artifact-sha256") {
                Ok(self.artifact_sha256.clone())
            } else if element.contains("vp-matrix-sha256") {
                Ok(self.matrix_sha256.clone())
            } else if element.contains("vp-test-name") {
                Ok(self.test_name.clone())
            } else if element.contains("vp-suite-plan-id") {
                Ok(self.suite_plan_id.clone())
            } else if element.contains("vp-suite-module-id") {
                Ok(self.module_id.clone())
            } else if element.contains("vp-variant-sha256") {
                Ok(self.variant_sha256.clone())
            } else if element.contains("vp-receipt-sha256") {
                Ok(self.receipt_sha256.clone())
            } else {
                Err(BrowserError::ElementNotFound)
            }
        }

        fn element_send_keys(&mut self, _element: &str, _value: &str) -> Result<(), BrowserError> {
            Ok(())
        }

        fn element_click(&mut self, _element: &str) -> Result<(), BrowserError> {
            Ok(())
        }

        fn element_attribute(
            &mut self,
            element: &str,
            name: &str,
        ) -> Result<Option<String>, BrowserError> {
            if element.contains("vp-verification-result") && name == "data-state" {
                Ok(Some("verified".to_owned()))
            } else {
                Ok(None)
            }
        }

        fn screenshot_png(&mut self) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
            Ok(Zeroizing::new(test_png()))
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
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: None,
            session_checks: 0,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        executor.reset_session().expect("reset browser session");
        assert_eq!(executor.driver_mut().session_checks, 1);
        assert!(executor.driver_mut().cookies_cleared);
        assert_eq!(executor.driver_mut().cookie_clear_count, 2);
        assert_eq!(executor.driver_mut().navigated.len(), 2);
        assert!(matches!(
            executor.navigate(&Url::parse("https://evil.example/").expect("url")),
            Err(BrowserError::CrossOriginNavigationDiagnostic(
                BrowserNavigationDiagnostic { ref to, .. }
            )) if to == "https://evil.example/"
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
    fn navigation_diagnostic_redacts_query_fragment_and_matcher_value() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let mut executor = BrowserExecutor::new(
            MockDriver {
                current: Url::parse("https://issuer.example/").expect("url"),
                source: String::new(),
                found: true,
                displayed: true,
                clicked: false,
                cookies_cleared: false,
                cookie_clear_count: 0,
                navigated: Vec::new(),
                redirect_to: None,
                session_checks: 0,
            },
            BrowserPolicy::new(target, suite).expect("policy"),
        );
        let entry = BrowserEntry::parse(&json!({
            "match": "https://suite.example/test/a/*/authorize?nonsecret-matcher",
            "tasks": []
        }))
        .expect("entry");
        executor.select_navigation_entry(3, &entry);
        let diagnostic = executor.navigation_violation(
            Some(&Url::parse("https://suite.example/a?token=secret#fragment").expect("from")),
            &Url::parse("https://elsewhere.example/b?code=secret#fragment").expect("to"),
        );
        let BrowserError::CrossOriginNavigationDiagnostic(diagnostic) = diagnostic else {
            panic!("navigation diagnostic")
        };
        let rendered = diagnostic.to_string();
        assert_eq!(diagnostic.from, "https://suite.example/a");
        assert_eq!(diagnostic.to, "https://elsewhere.example/b");
        assert_eq!(diagnostic.selected_entry, Some(3));
        assert_eq!(
            diagnostic.matcher_sha256_prefix.as_deref().map(str::len),
            Some(12)
        );
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("nonsecret-matcher"));
    }

    #[test]
    fn required_review_marker_fails_closed_without_explicit_capture() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = MockDriver {
            current: Url::parse("https://suite.example/test/a/module-a/verification-evidence")
                .expect("url"),
            source: "review evidence".to_owned(),
            found: true,
            displayed: true,
            clicked: false,
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: None,
            session_checks: 0,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        let entries = vec![BrowserEntry::parse(&json!({
            "match": "https://suite.example/test/a/module-a/verification-evidence*",
            "tasks": [{
                "commands": [["wait", "css", ".review", 1, "review evidence", "update-image-placeholder"]]
            }]
        }))
        .expect("entry")];
        assert_eq!(
            executor
                .execute(
                    &Url::parse("https://suite.example/test/a/module-a/verification-evidence")
                        .expect("url"),
                    &entries,
                )
                .expect_err("required capture"),
            BrowserError::ReviewScreenshotRequired
        );
    }

    #[cfg(unix)]
    #[test]
    fn signed_required_review_marker_writes_only_bounded_module_evidence() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse(OFFICIAL_SUITE_ORIGIN).expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = MockDriver {
            current: Url::parse(
                "https://www.certification.openid.net/test/a/module-a/verification-evidence",
            )
            .expect("url"),
            source: "review evidence".to_owned(),
            found: true,
            displayed: true,
            clicked: false,
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: None,
            session_checks: 0,
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temp")
            .join(format!("nazoauth-review-capture-{}", uuid::Uuid::now_v7()));
        crate::secure_file::ensure_directory(&root, true).expect("private root");
        let capture = BrowserReviewScreenshotCapture::new(root.clone(), "run-a")
            .expect("capture")
            .context(
                BrowserReviewModuleIdentity::new(
                    "matrix-plan-a",
                    "suite-plan-a",
                    "module-a",
                    "test-a",
                    &BTreeMap::new(),
                )
                .expect("identity"),
                0,
            )
            .expect("context");
        let mut executor = BrowserExecutor::new(driver, policy);
        let entries = vec![BrowserEntry::parse(&json!({
            "match": "https://www.certification.openid.net/test/a/module-a/verification-evidence",
            "tasks": [{
                "commands": [["wait", "xpath", "//*", 1, "review evidence", "update-image-placeholder"]]
            }]
        }))
        .expect("entry")];
        let report = executor
            .execute_with_review_capture(
                &Url::parse(
                    "https://www.certification.openid.net/test/a/module-a/verification-evidence",
                )
                .expect("url"),
                &entries,
                Some(&capture),
            )
            .expect("capture");
        assert_eq!(report.review_screenshots.len(), 1);
        let receipt = &report.review_screenshots[0];
        assert_eq!(
            receipt.path,
            PathBuf::from("review-screenshots/run-a/matrix-plan-a--module-a--000.png")
        );
        assert_eq!(
            std::fs::read(root.join(&receipt.path))
                .expect("png")
                .as_slice(),
            test_png().as_slice()
        );
        assert!(
            root.join(&receipt.path)
                .with_extension("png.receipt.json")
                .is_file()
        );
        std::fs::remove_dir_all(root).expect("remove root");
    }

    #[cfg(unix)]
    #[test]
    fn vp_result_capture_uses_only_the_same_module_nazoauthweb_projection() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse(OFFICIAL_SUITE_ORIGIN).expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let variant = BTreeMap::from([("transport".to_owned(), "direct_post".to_owned())]);
        let context = OpenId4VpEvidenceContext::new(
            "request-0123456789abcdef0123456789abcdef",
            "a".repeat(64),
            "b".repeat(64),
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
            "vp-happy",
            &variant,
        )
        .expect("context");
        let receipt_sha256 = "c".repeat(64);
        let evidence = OpenId4VpVerificationEvidence::test_verified(
            context.clone(),
            &receipt_sha256,
            "https://issuer.example/ui/verification-result#receipt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let driver = VpResultDriver {
            current: Url::parse("https://issuer.example/").expect("url"),
            run_jti: context.run_jti.clone(),
            artifact_sha256: context.artifact_sha256.clone(),
            matrix_sha256: context.matrix_sha256.clone(),
            test_name: context.test_name.clone(),
            suite_plan_id: context.suite_plan_id.clone(),
            module_id: context.suite_module_id.clone(),
            variant_sha256: context.variant_sha256.clone(),
            receipt_sha256: receipt_sha256.clone(),
            allow_root_children: true,
            navigated: Vec::new(),
        };
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temp")
            .join(format!("nazoauth-vp-result-{}", uuid::Uuid::now_v7()));
        crate::secure_file::ensure_directory(&root, true).expect("private root");
        let capture = BrowserReviewScreenshotCapture::new(
            root.clone(),
            "request-0123456789abcdef0123456789abcdef",
        )
        .expect("capture")
        .context(
            BrowserReviewModuleIdentity::new(
                "matrix-plan-a",
                &context.suite_plan_id,
                &context.suite_module_id,
                &context.test_name,
                &variant,
            )
            .expect("identity"),
            0,
        )
        .expect("context");
        let mut executor = BrowserExecutor::new(driver, policy);
        let receipt = executor
            .capture_openid4vp_verification_result(&evidence, &capture, 0)
            .expect("same-module result capture");
        assert_eq!(
            receipt.source,
            BrowserReviewScreenshotSource::NazoVpVerificationResultLiveWebdriver
        );
        assert_eq!(
            receipt
                .verification_receipt
                .as_ref()
                .map(|provenance| provenance.receipt_sha256.as_str()),
            Some(receipt_sha256.as_str())
        );
        assert_eq!(receipt.module_id, context.suite_module_id);
        let audit =
            std::fs::read_to_string(root.join(&receipt.path).with_extension("png.receipt.json"))
                .expect("audit");
        assert!(audit.contains("nazo-vp-verification-result/live-webdriver"));
        assert!(!audit.contains("receipt=AAAAAAAA"));
        assert_eq!(executor.driver_mut().navigated.len(), 1);
        assert_eq!(
            executor.driver_mut().navigated[0].fragment(),
            Some("receipt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        executor.driver_mut().allow_root_children = false;
        assert_eq!(
            executor
                .capture_openid4vp_verification_result(&evidence, &capture, 1)
                .expect_err("global lookalike outside the verified root"),
            BrowserError::ElementNotFound
        );
        std::fs::remove_dir_all(root).expect("remove root");
    }

    #[test]
    fn mutually_exclusive_unselected_required_marker_does_not_create_an_obligation() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let policy =
            BrowserPolicy::new(target, Origin::parse(OFFICIAL_SUITE_ORIGIN).expect("suite"))
                .expect("policy");
        let driver = MockDriver {
            current: Url::parse("https://issuer.example/selected").expect("URL"),
            source: String::new(),
            found: true,
            displayed: true,
            clicked: false,
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: None,
            session_checks: 0,
        };
        let entries = vec![
            BrowserEntry::parse(&json!({
                "match": "https://issuer.example/alternate",
                "tasks": [{"commands": [["wait", "xpath", "//*", 1, ".*", "update-image-placeholder"]]}]
            }))
            .expect("alternate entry"),
            BrowserEntry::parse(&json!({
                "match": "https://issuer.example/selected",
                "tasks": []
            }))
            .expect("selected entry"),
        ];
        let report = BrowserExecutor::new(driver, policy)
            .execute(
                &Url::parse("https://issuer.example/selected").expect("URL"),
                &entries,
            )
            .expect("unselected required marker is not an obligation");
        assert_eq!(report.entry_index, 1);
        assert_eq!(report.review_screenshots_required, 0);
    }

    #[test]
    fn vp_evidence_context_requires_the_actual_selected_required_marker() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let policy =
            BrowserPolicy::new(target, Origin::parse(OFFICIAL_SUITE_ORIGIN).expect("suite"))
                .expect("policy");
        let authorization =
            Url::parse("https://www.certification.openid.net/test/a/vp/authorize?request=one")
                .expect("authorization URL");
        let evidence = Url::parse(
            "https://www.certification.openid.net/test/a/module-a/verification-evidence",
        )
        .expect("evidence URL");
        let driver = MockDriver {
            current: authorization.clone(),
            source: String::new(),
            found: true,
            displayed: true,
            clicked: false,
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: None,
            session_checks: 0,
        };
        let entries = vec![
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "tasks": [{
                    "match": "https://www.certification.openid.net/test/a/module-a/verification-evidence",
                    "commands": [["wait", "xpath", "//*", 1, "review", "update-image-placeholder"]]
                }]
            }))
            .expect("first selected entry"),
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "tasks": [{
                    "match": "https://www.certification.openid.net/test/a/module-a/verification-evidence",
                    "commands": [["wait", "xpath", "//*", 1, "review", "update-image-placeholder"]]
                }]
            }))
            .expect("unselected alternative"),
        ];
        let mut executor = BrowserExecutor::new(driver, policy);
        assert!(
            executor
                .selected_openid4vp_result_marker(&authorization, &entries, &evidence)
                .expect("actual selected marker")
        );

        let no_marker_in_selected = vec![
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "tasks": [{"commands": []}]
            }))
            .expect("selected entry"),
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "tasks": [{
                    "match": "https://www.certification.openid.net/test/a/module-a/verification-evidence",
                    "commands": [["wait", "xpath", "//*", 1, "review", "update-image-placeholder"]]
                }]
            }))
            .expect("unselected alternative"),
        ];
        assert!(
            !executor
                .selected_openid4vp_result_marker(&authorization, &no_marker_in_selected, &evidence)
                .expect("unselected marker has no authority")
        );

        let ungated_marker = BrowserEntry::parse(&json!({
            "match": "https://issuer.example/authorize*",
            "tasks": [{
                "commands": [["wait", "xpath", "//*", 1, "review", "update-image-placeholder"]]
            }]
        }))
        .expect("ungated marker entry");
        assert!(
            !selected_required_review_screenshot_marker(&ungated_marker, &evidence)
                .expect("ungated marker cannot authorize issuance")
        );

        let mut exhausted_executor = executor;
        exhausted_executor.entry_uses.insert(0, 1);
        let limited_entries = vec![
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "match-limit": 1,
                "tasks": [{
                    "match": "https://www.certification.openid.net/test/a/module-a/verification-evidence",
                    "commands": [["wait", "xpath", "//*", 1, "review", "update-image-placeholder"]]
                }]
            }))
            .expect("exhausted entry"),
            BrowserEntry::parse(&json!({
                "match": "https://www.certification.openid.net/test/a/*/authorize*",
                "tasks": [{"commands": []}]
            }))
            .expect("next eligible entry"),
        ];
        assert!(
            !exhausted_executor
                .selected_openid4vp_result_marker(&authorization, &limited_entries, &evidence)
                .expect("match limit selects the next entry")
        );
    }

    #[cfg(unix)]
    #[test]
    fn review_capture_budget_is_shared_and_rejects_the_sixty_fifth_attempt_before_write() {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temp")
            .join(format!("nazoauth-review-budget-{}", uuid::Uuid::now_v7()));
        crate::secure_file::ensure_directory(&root, true).expect("private root");
        let capture = BrowserReviewScreenshotCapture::new(root.clone(), "run-a").expect("capture");
        for index in 0..MAX_REVIEW_SCREENSHOTS_PER_RUN {
            capture
                .context(
                    BrowserReviewModuleIdentity::new(
                        "matrix",
                        "suite",
                        "module",
                        "test",
                        &BTreeMap::new(),
                    )
                    .expect("identity"),
                    index,
                )
                .expect("context")
                .reserve_attempt()
                .expect("bounded attempt");
        }
        assert_eq!(
            capture
                .context(
                    BrowserReviewModuleIdentity::new(
                        "matrix",
                        "suite",
                        "module",
                        "test",
                        &BTreeMap::new(),
                    )
                    .expect("identity"),
                    64,
                )
                .expect("context")
                .reserve_attempt()
                .expect_err("sixty fifth attempt"),
            BrowserError::ReviewScreenshotLimit
        );
        assert!(!root.join("review-screenshots").exists());
        std::fs::remove_dir_all(root).expect("remove root");
    }

    #[test]
    fn webdriver_png_decoder_rejects_noncanonical_or_non_png_values() {
        let encoded = STANDARD.encode(test_png());
        assert_eq!(
            decode_webdriver_png(&encoded).expect("png").as_slice(),
            test_png().as_slice()
        );
        assert_eq!(
            decode_webdriver_png(&format!("{encoded}\n")).expect_err("noncanonical"),
            BrowserError::InvalidScreenshot
        );
        assert_eq!(
            decode_webdriver_png(&STANDARD.encode(b"not png")).expect_err("not png"),
            BrowserError::InvalidScreenshot
        );
        let mut corrupted = test_png();
        let last = corrupted.len().saturating_sub(1);
        corrupted[last] ^= 1;
        assert_eq!(
            validate_png_screenshot(&corrupted).expect_err("CRC mismatch"),
            BrowserError::InvalidScreenshot
        );
    }

    #[test]
    fn review_capture_path_is_bound_to_the_current_suite_module() {
        let url = Url::parse(
            "https://www.certification.openid.net/test/a/module-a/verification-evidence",
        )
        .expect("URL");
        assert!(review_screenshot_path_binds_module(&url, "module-a"));
        assert!(!review_screenshot_path_binds_module(&url, "module-b"));
        assert!(!review_screenshot_path_binds_module(
            &Url::parse("https://www.certification.openid.net/test/a/module-a").expect("URL"),
            "module-a"
        ));
        for invalid in [
            "https://www.certification.openid.net/test/a/module-a/verification-evidence/extra",
            "https://www.certification.openid.net/test/a/module-a/verification-evidence/",
            "https://www.certification.openid.net/test/a/module-a/verification-evidence?x=1",
            "https://www.certification.openid.net/test/a/module-a/verification-evidence#x",
            "https://user@www.certification.openid.net/test/a/module-a/verification-evidence",
            "https://www.certification.openid.net/test/a/module-b/verification-evidence",
        ] {
            assert!(
                !review_screenshot_path_binds_module(
                    &Url::parse(invalid).expect("URL"),
                    "module-a"
                ),
                "unexpected authorized evidence URL: {invalid}"
            );
        }
    }

    #[test]
    fn reset_session_rejects_redirect_between_allowed_cookie_origins() {
        let target = BrowserTargetOrigin::parse("https://issuer.example").expect("target");
        let suite = Origin::parse("https://suite.example").expect("suite");
        let policy = BrowserPolicy::new(target, suite).expect("policy");
        let driver = MockDriver {
            current: Url::parse("https://issuer.example/").expect("url"),
            source: String::new(),
            found: false,
            displayed: false,
            clicked: false,
            cookies_cleared: false,
            cookie_clear_count: 0,
            navigated: Vec::new(),
            redirect_to: Some(Url::parse("https://suite.example/").expect("redirect")),
            session_checks: 0,
        };
        let mut executor = BrowserExecutor::new(driver, policy);
        assert_eq!(
            executor
                .reset_session()
                .expect_err("cross-origin cleanup redirect"),
            BrowserError::CrossOriginNavigation
        );
        let driver = executor.driver_mut();
        assert_eq!(driver.cookie_clear_count, 0);
        assert_eq!(driver.navigated.len(), 1);
    }

    #[test]
    fn module_browser_selection_uses_the_explicit_suite_override() {
        let config = json!({
            "browser": [{
                "match": "https://issuer.example/authorize*",
                "tasks": [{
                    "match": "https://issuer.example/ui/consent*",
                    "commands": [["click", "id", "nazo-consent-approve"]]
                }]
            }],
            "override": {
                "negative-module": {"browser": [{
                    "match": "https://issuer.example/authorize*",
                    "tasks": [{
                        "match": "https://issuer.example/ui/consent*",
                        "commands": [["click", "id", "nazo-consent-deny"]]
                    }]
                }]}
            }
        });

        let selected = browser_config_for_module(&config, "negative-module")
            .expect("explicit module browser plan");
        let text = serde_json::to_string(&selected).expect("json");
        assert!(!text.contains("nazo-consent-approve"));
        assert_eq!(text.matches("nazo-consent-deny").count(), 1);
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
        let error = executor
            .execute(
                &Url::parse("https://issuer.example/authorize?x=1").expect("url"),
                &entries,
            )
            .expect_err("cross-origin redirect");
        let BrowserError::CrossOriginNavigationDiagnostic(diagnostic) = error else {
            panic!("expected cross-origin navigation diagnostic")
        };
        assert_eq!(diagnostic.from, "https://issuer.example/authorize");
        assert_eq!(diagnostic.to, "https://evil.example/ui/auth");
        assert_eq!(diagnostic.selected_entry, Some(0));
        assert_eq!(
            diagnostic.matcher_sha256_prefix,
            Some(sha256_hex("https://issuer.example/authorize*".as_bytes())[..12].to_owned())
        );
    }
}
