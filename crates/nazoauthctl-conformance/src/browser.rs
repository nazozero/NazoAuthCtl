//! Suite browser configuration and HTTP-based OpenID4VC drivers.
//! Browser interactions execute in the Suite. Historical PNG receipts remain
//! readable for already retained runs; this module never launches a browser.
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use thiserror::Error;
#[cfg(any(unix, test))]
use url::Url;

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
    ConformanceBinding, OpenId4VpCompletionOutcome, OpenId4VpError, OpenId4VpPresentation,
    OpenId4VpStartRequest, OpenId4VpVerificationReceiptProvenance, OpenId4VpVerifier,
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
pub(crate) fn validate_png_screenshot(bytes: &[u8]) -> Result<(), BrowserError> {
    if bytes.len() > MAX_REVIEW_SCREENSHOT_BYTES {
        return Err(BrowserError::InvalidScreenshot);
    }
    let mut input = Cursor::new(bytes);
    let mut options = png::DecodeOptions::default();
    // Retained evidence rejects corrupt ancillary chunks as well as image chunks.
    options.set_skip_ancillary_crc_failures(false);
    let mut decoder = png::Decoder::new_with_options(&mut input, options);
    decoder.set_limits(png::Limits {
        bytes: 64 * 1024 * 1024,
    });
    let mut reader = decoder
        .read_info()
        .map_err(|_| BrowserError::InvalidScreenshot)?;
    let info = reader.info();
    if info.is_animated()
        || info.width > 8_192
        || info.height > 8_192
        || u64::from(info.width) * u64::from(info.height) > 16 * 1024 * 1024
        || reader
            .output_buffer_size()
            .is_none_or(|size| size > 64 * 1024 * 1024)
    {
        return Err(BrowserError::InvalidScreenshot);
    }
    // Decode every row to validate compressed data without retaining a full image.
    while reader
        .next_row()
        .map_err(|_| BrowserError::InvalidScreenshot)?
        .is_some()
    {}
    reader
        .finish()
        .map_err(|_| BrowserError::InvalidScreenshot)?;
    drop(reader);
    if input.position() != bytes.len() as u64 {
        return Err(BrowserError::InvalidScreenshot);
    }
    Ok(())
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
    #[test]
    fn historical_png_evidence_checks_all_chunks_and_decodes_all_rows() {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, 16, 32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer
            .write_chunk(png::chunk::ChunkType(*b"tEXt"), b"key\0value")
            .unwrap();
        writer.write_image_data(&vec![42; 16 * 32 * 4]).unwrap();
        writer.finish().unwrap();
        assert!(validate_png_screenshot(&bytes).is_ok());
        for length in 0..bytes.len() {
            assert!(
                validate_png_screenshot(&bytes[..length]).is_err(),
                "truncation at {length}"
            );
        }
        let text = bytes.windows(4).position(|part| part == b"tEXt").unwrap();
        let mut corrupt = bytes.clone();
        corrupt[text + 4] ^= 1;
        assert!(validate_png_screenshot(&corrupt).is_err());
        let mut joined = bytes.clone();
        joined.extend_from_slice(&bytes);
        assert!(validate_png_screenshot(&joined).is_err());
    }
}
