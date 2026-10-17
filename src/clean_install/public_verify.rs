//! Public verification as an independent, explicit report.
//!
//! Install/update lifecycle commits depend on exactly one health domain: the
//! target-local runtime. Public DNS propagation, TLS termination, OIDC
//! discovery through the public boundary, and off-host backup state are
//! separate observations with separate owners. This module therefore takes no
//! ExecutionTarget, no RegistryStore, and no DeploymentState handle — it is
//! structurally incapable of rolling back or mutating a committed install.
//!
//! Rules pinned here:
//!
//! * a loopback issuer is always reported as a trial endpoint and can never
//!   produce a public pass;
//! * failures are reported with reasons and a `checked_at` timestamp; they
//!   never touch local lifecycle state;
//! * only an explicitly user-configured policy may block on this report — the
//!   default path never does.

use chrono::{DateTime, Utc};
use url::Url;

/// Probe seam so tests classify outcomes without a network.
pub(crate) trait PublicProber {
    /// Fetches discovery over verified TLS and returns its issuer.
    fn oidc_discovery(&self, issuer: &Url) -> Result<String, String>;
}

/// Outcome of one public verification run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicVerdict {
    /// Every public property held against a non-loopback origin.
    Passed,
    /// At least one check failed; reasons are bounded diagnostics.
    Failed { failures: Vec<String> },
}

/// One dated report. Pure data: rendering and any user-policy decision happen
/// above this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicVerificationReport {
    pub(crate) checked_at: DateTime<Utc>,
    pub(crate) issuer: String,
    /// True when the issuer resolves to a loopback/trial origin.
    pub(crate) loopback_trial: bool,
    pub(crate) verdict: PublicVerdict,
}

impl PublicVerificationReport {
    /// Human rendering for the `verify` CLI surface.
    pub(crate) fn render(&self) -> String {
        let mut lines = vec![crate::ui::message!(
            "public verification of {} at {}",
            "公网验证：{}\n检查时间：{}",
            self.issuer,
            self.checked_at.to_rfc3339()
        )];
        if self.loopback_trial {
            lines.push(
                crate::ui::text(
                    "note: loopback origins are local trial endpoints and are never a public pass",
                    "本机回环地址仅用于本地试运行，不能通过公网验证。",
                )
                .to_owned(),
            );
        }
        match &self.verdict {
            PublicVerdict::Passed => {
                lines.push(crate::ui::text("verdict: PASSED", "结果：通过").to_owned())
            }
            PublicVerdict::Failed { failures } => {
                lines.push(crate::ui::text("verdict: FAILED", "结果：失败").to_owned());
                for failure in failures {
                    lines.push(format!("  - {failure}"));
                }
                lines.push(
                    crate::ui::text(
                        "the deployed instance keeps running; fix the public boundary and re-run \
                     `verify`",
                        "实例继续运行。请修正公网访问配置后重新运行 verify。",
                    )
                    .to_owned(),
                );
            }
        }
        lines.join("\n")
    }
}

fn is_loopback(issuer: &Url) -> bool {
    match issuer.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Run the independent public checks. This function has no parameter through
/// which any local lifecycle state could be reached.
pub(crate) fn verify_public(prober: &dyn PublicProber, issuer: &str) -> PublicVerificationReport {
    let checked_at = Utc::now();
    let mut failures = Vec::new();
    let parsed = Url::parse(issuer).ok().filter(|url| {
        // P1-5: public verify requires HTTPS — HTTP is never acceptable for a
        // production issuer origin.
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
    });
    let Some(parsed) = parsed else {
        return PublicVerificationReport {
            checked_at,
            issuer: issuer.to_owned(),
            loopback_trial: false,
            verdict: PublicVerdict::Failed {
                failures: vec![
                    "issuer must be a valid HTTPS origin URL (HTTP is not accepted)".to_owned(),
                ],
            },
        };
    };
    let loopback_trial = is_loopback(&parsed);
    if loopback_trial {
        // Never a pass, by definition (G8 禁止事项).
        failures.push("issuer resolves to a loopback origin".to_owned());
    }
    match prober.oidc_discovery(&parsed) {
        Err(reason) => failures.push(format!("OIDC discovery failed: {reason}")),
        Ok(discovered_issuer) => {
            // P1-5: the discovery document's own issuer must equal the
            // target issuer exactly — a mismatch means a proxy or CDN is
            // serving someone else's identity.
            let normalized_target = parsed.as_str().trim_end_matches('/');
            let normalized_discovered = discovered_issuer.trim_end_matches('/');
            if normalized_discovered != normalized_target {
                failures.push(format!(
                    "discovery issuer mismatch: expected '{normalized_target}' but discovery reports '{normalized_discovered}'"
                ));
            }
        }
    }
    let verdict = if failures.is_empty() {
        PublicVerdict::Passed
    } else {
        PublicVerdict::Failed { failures }
    };
    PublicVerificationReport {
        checked_at,
        issuer: issuer.to_owned(),
        loopback_trial,
        verdict,
    }
}

/// One bounded HTTPS discovery request proves TLS reachability and the served
/// issuer together. curl verifies the certificate before reading the document.
pub(crate) struct CurlPublicProber;

impl PublicProber for CurlPublicProber {
    fn oidc_discovery(&self, issuer: &Url) -> Result<String, String> {
        let mut discovery = issuer.clone();
        discovery.set_path(".well-known/openid-configuration");
        let body = crate::process::Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--connect-timeout",
                "10",
                "--max-time",
                "20",
            ])
            .arg(discovery.as_str())
            .stdout()
            .map_err(|error| format!("{error:#}"))?;
        #[derive(serde::Deserialize)]
        struct DiscoveryDocument {
            issuer: String,
        }
        serde_json::from_str::<DiscoveryDocument>(&body)
            .map(|document| document.issuer)
            .map_err(|_| "discovery document must be valid JSON with a string issuer".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Prober {
        /// Some(discovered_issuer) on success.
        discovery: Result<String, String>,
    }

    impl PublicProber for Prober {
        fn oidc_discovery(&self, _issuer: &Url) -> Result<String, String> {
            self.discovery.clone()
        }
    }

    #[test]
    fn a_healthy_public_origin_passes() {
        let report = verify_public(
            &Prober {
                discovery: Ok("https://auth.example.com".to_owned()),
            },
            "https://auth.example.com",
        );
        assert_eq!(report.verdict, PublicVerdict::Passed);
        assert!(!report.loopback_trial);
        assert!(report.render().contains("PASSED"));
    }

    #[test]
    fn every_failure_is_reported_with_reasons_and_a_timestamp() {
        let report = verify_public(
            &Prober {
                discovery: Err("certificate expired".to_owned()),
            },
            "https://auth.example.com",
        );
        let PublicVerdict::Failed { failures } = &report.verdict else {
            panic!("expected failure");
        };
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures.iter().any(|f| f.contains("certificate expired")));
        let age = (Utc::now() - report.checked_at).num_milliseconds();
        assert!((0..60_000).contains(&age), "checked_at must be fresh");
        let rendered = report.render();
        assert!(rendered.contains("FAILED"), "{rendered}");
        assert!(rendered.contains("keeps running"), "{rendered}");
    }

    #[test]
    fn loopback_origins_can_never_be_a_public_pass_even_when_probes_succeed() {
        // 禁止事项 (G8): loopback is never reported as a formal public pass.
        let report = verify_public(
            &Prober {
                discovery: Ok("https://127.0.0.1:8000".to_owned()),
            },
            "https://127.0.0.1:8000",
        );
        assert!(report.loopback_trial);
        assert!(
            matches!(report.verdict, PublicVerdict::Failed { .. }),
            "loopback trial endpoints never pass: {:?}",
            report.verdict
        );
        assert!(report.render().contains("never a public pass"));

        let localhost = verify_public(
            &Prober {
                discovery: Ok("https://localhost:8000".to_owned()),
            },
            "https://localhost:8000",
        );
        assert!(localhost.loopback_trial);
        let ipv6 = verify_public(
            &Prober {
                discovery: Ok("https://[::1]:8000".to_owned()),
            },
            "https://[::1]:8000",
        );
        assert!(ipv6.loopback_trial);
        assert!(matches!(ipv6.verdict, PublicVerdict::Failed { .. }));

        // P1-5: plain-HTTP issuers are rejected before any probe runs, so an
        // HTTP loopback URL is not even classified as a loopback trial.
        let plaintext = verify_public(
            &Prober {
                discovery: Ok("http://127.0.0.1:8000".to_owned()),
            },
            "http://127.0.0.1:8000",
        );
        assert!(!plaintext.loopback_trial);
        assert!(matches!(plaintext.verdict, PublicVerdict::Failed { .. }));
    }

    #[test]
    fn malformed_issuers_fail_with_a_stable_reason_without_panicking() {
        for issuer in ["not-a-url", "ftp://x", "https://u:p@host"] {
            let report = verify_public(
                &Prober {
                    discovery: Ok("https://auth.example.com".to_owned()),
                },
                issuer,
            );
            let PublicVerdict::Failed { failures } = &report.verdict else {
                panic!("{issuer} must fail");
            };
            assert_eq!(failures.len(), 1, "{issuer}: {failures:?}");
        }
    }
}
