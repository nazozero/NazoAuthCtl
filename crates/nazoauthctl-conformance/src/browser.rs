//! Suite browser configuration and HTTP-based OpenID4VC drivers.
//! Browser interactions execute in the Suite. Historical PNG receipts remain
//! readable for already retained runs; this module never launches a browser.
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use thiserror::Error;
#[cfg(any(unix, test))]
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum BrowserError {
    #[error("browser target origin is invalid")]
    InvalidOrigin,
    #[error("plaintext browser target must be loopback")]
    InsecureTarget,
    #[error("browser schema is invalid")]
    InvalidSchema,
    #[error("browser command is unsupported")]
    UnsupportedCommand,
    #[error("historical screenshot is invalid")]
    InvalidScreenshot,
    #[error("browser step limit exceeded")]
    StepLimit,
    #[error("browser URL crossed the allowlist")]
    CrossOriginNavigation,
}

mod openid4vci;
mod openid4vp;
mod plan;
mod validation;
pub use openid4vci::{
    OpenId4VciError, OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver,
    OpenId4VciModule,
};
pub use openid4vp::{
    ConformanceBinding, OpenId4VpCompletionOutcome, OpenId4VpError,
    OpenId4VpEvidenceBindingDiagnostic, OpenId4VpEvidenceContext, OpenId4VpEvidenceRunContext,
    OpenId4VpEvidenceVerifier, OpenId4VpPresentation, OpenId4VpStartRequest,
    OpenId4VpVerificationEvidence, OpenId4VpVerificationReceiptProvenance, OpenId4VpVerifier,
    OpenId4VpVerifierClient,
};
pub use plan::BrowserRunnerState;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewScreenshotMarker {
    Required,
    Optional,
}

pub use validation::{BrowserPolicy, BrowserTargetOrigin};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BrowserReviewScreenshotSource {
    #[serde(rename = "suite-verification-evidence")]
    SuiteVerificationEvidence,
    #[serde(rename = "nazo-vp-verification-result/live-webdriver")]
    NazoVpVerificationResultLiveWebdriver,
    #[serde(rename = "nazo-vp-completion/live-webdriver")]
    NazoVpCompletionLiveWebdriver,
}

const MAX_REVIEW_SCREENSHOT_BYTES: usize = 500 * 1024;
pub(crate) const MAX_REVIEW_SCREENSHOTS_PER_MODULE: usize = 2;
pub(crate) const MAX_REVIEW_SCREENSHOTS_PER_RUN: usize = 64;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
pub(crate) fn validate_png_screenshot(bytes: &[u8]) -> Result<(), BrowserError> {
    if bytes.len() > MAX_REVIEW_SCREENSHOT_BYTES || !bytes.starts_with(PNG_SIGNATURE) {
        return Err(BrowserError::InvalidScreenshot);
    }
    // PNG is deliberately parsed completely here instead of accepting a
    // magic prefix. Retained evidence is untrusted at this boundary.
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

#[cfg(any(unix, test))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::Origin;
    use serde_json::json;
    #[test]
    fn target_http_is_only_loopback_and_suite_is_https() {
        for origin in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost",
        ] {
            assert!(BrowserTargetOrigin::parse(origin).is_ok());
        }
        assert!(BrowserTargetOrigin::parse("http://issuer.example").is_err());
        assert!(Origin::parse("https://suite.example").is_ok());
        let policy = BrowserPolicy::new(
            BrowserTargetOrigin::parse("https://target.example").unwrap(),
            Origin::parse("https://suite.example").unwrap(),
        );
        for rejected in [
            "https://user@target.example",
            "https://user@suite.example",
            "http://target.example",
            "https://attacker.example",
        ] {
            assert!(!policy.allows_url(&Url::parse(rejected).unwrap()));
        }
    }
    #[test]
    fn suite_browser_state_projects_urls_from_the_full_runner_shape() {
        let policy = BrowserPolicy::new(
            BrowserTargetOrigin::parse("https://target.example").expect("target"),
            Origin::parse("https://suite.example").expect("suite"),
        );
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
    #[test]
    fn suite_uri_input_retargets_the_verifier_authorization_query() {
        let policy = BrowserPolicy::new(
            BrowserTargetOrigin::parse("https://target.example").expect("target"),
            Origin::parse("https://suite.example").expect("suite"),
        );
        let state = BrowserRunnerState::parse(
            &json!({
                "urls": [],
                "visited": [],
                "uriInputRequests": [{
                    "description": "Paste the verifier authorization request",
                    "submitUrl": "https://suite.example/test/a/module/authorize"
                }]
            }),
            &policy,
        )
        .expect("URI-input runner state");
        let authorization_url = Url::parse(
            "https://suite.example/test/a/alias/authorize?client_id=redirect_uri%3Ahttps%3A%2F%2Ftarget.example&nonce=opaque",
        )
        .expect("authorization URL");
        let submission = state
            .verifier_submission_url(&authorization_url)
            .expect("submission URL");
        assert_eq!(submission.path(), "/test/a/module/authorize");
        assert_eq!(submission.query(), authorization_url.query());

        let cross_origin = BrowserRunnerState::parse(
            &json!({
                "urls": [],
                "visited": [],
                "uriInputRequests": [{
                    "submitUrl": "https://attacker.example/collect"
                }]
            }),
            &policy,
        );
        assert!(matches!(
            cross_origin,
            Err(BrowserError::CrossOriginNavigation)
        ));
        assert!(
            state
                .verifier_submission_url(
                    &Url::parse("https://suite.example/test/a/alias/authorize")
                        .expect("queryless authorization URL")
                )
                .is_err()
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
    fn historical_png_evidence_still_rejects_corruption_and_trailing_data() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let png = STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=").unwrap();
        assert!(validate_png_screenshot(&png).is_ok());
        let mut corrupt = png.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(validate_png_screenshot(&corrupt).is_err());
        let mut trailing = png;
        trailing.push(0);
        assert!(validate_png_screenshot(&trailing).is_err());
    }
}
