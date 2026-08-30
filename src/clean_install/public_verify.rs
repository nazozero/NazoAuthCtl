//! Public verification as an independent, explicit report (task G08).
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
//!   produce a public pass (goal plan 07 G8 禁止事项);
//! * failures are reported with reasons and a `checked_at` timestamp; they
//!   never touch local lifecycle state;
//! * only an explicitly user-configured policy may block on this report — the
//!   default path never does.

use chrono::{DateTime, Utc};
use url::Url;

/// Probe seam so tests classify outcomes without a network.
pub(crate) trait PublicProber {
    fn tls_handshake(&self, issuer: &Url) -> Result<(), String>;
    /// Returns the `issuer` value from the discovery document for
    /// exact-match comparison against the expected origin (P1-5).
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
    /// Human rendering for the future `verify` CLI surface.
    pub(crate) fn render(&self) -> String {
        let mut lines = vec![format!(
            "public verification of {} at {}",
            self.issuer,
            self.checked_at.to_rfc3339()
        )];
        if self.loopback_trial {
            lines.push(
                "note: loopback origins are local trial endpoints and are never a public pass"
                    .to_owned(),
            );
        }
        match &self.verdict {
            PublicVerdict::Passed => lines.push("verdict: PASSED".to_owned()),
            PublicVerdict::Failed { failures } => {
                lines.push("verdict: FAILED".to_owned());
                for failure in failures {
                    lines.push(format!("  - {failure}"));
                }
                lines.push(
                    "the deployed instance keeps running; fix the public boundary and re-run \
                     `verify`"
                        .to_owned(),
                );
            }
        }
        lines.join("\n")
    }
}

fn is_loopback(issuer: &Url) -> bool {
    issuer.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// Run the independent public checks. This function has no parameter through
/// which any local lifecycle state could be reached — that is the G08 design
/// guarantee, enforced by the type system rather than by discipline.
///
/// Delivery boundary: wired into the CLI by the I wave (`verify`).
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
    if let Err(reason) = prober.tls_handshake(&parsed) {
        failures.push(format!("TLS handshake failed: {reason}"));
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

/// Production prober: bounded curl for both checks, matching the transport
/// precedent of administrator provisioning. A TLS/transport failure surfaces as a
/// nonzero curl exit; any HTTP answer counts for the handshake half because
/// this check owns reachability, not application semantics.
pub(crate) struct CurlPublicProber;

impl PublicProber for CurlPublicProber {
    fn tls_handshake(&self, issuer: &Url) -> Result<(), String> {
        crate::process::Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--head",
                "--connect-timeout",
                "10",
                "--max-time",
                "20",
            ])
            .arg(issuer.as_str())
            .stdout()
            .map(|_| ())
            .map_err(|error| format!("{error:#}"))
    }

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
        // P1-5: extract the discovery issuer for exact-match comparison.
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(doc) => Ok(doc["issuer"].as_str().unwrap_or_default().to_owned()),
            Err(_) => Err("discovery document is not valid JSON".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Prober {
        tls: Result<(), String>,
        /// Some(discovered_issuer) on success.
        discovery: Result<String, String>,
    }

    impl PublicProber for Prober {
        fn tls_handshake(&self, _issuer: &Url) -> Result<(), String> {
            self.tls.clone()
        }
        fn oidc_discovery(&self, _issuer: &Url) -> Result<String, String> {
            self.discovery.clone()
        }
    }

    #[test]
    fn a_healthy_public_origin_passes() {
        let report = verify_public(
            &Prober {
                tls: Ok(()),
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
                tls: Err("certificate expired".to_owned()),
                discovery: Err("404 at /.well-known/openid-configuration".to_owned()),
            },
            "https://auth.example.com",
        );
        let PublicVerdict::Failed { failures } = &report.verdict else {
            panic!("expected failure");
        };
        assert_eq!(failures.len(), 2, "{failures:?}");
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
                tls: Ok(()),
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
                tls: Ok(()),
                discovery: Ok("https://localhost:8000".to_owned()),
            },
            "https://localhost:8000",
        );
        assert!(localhost.loopback_trial);

        // P1-5: plain-HTTP issuers are rejected before any probe runs, so an
        // HTTP loopback URL is not even classified as a loopback trial.
        let plaintext = verify_public(
            &Prober {
                tls: Ok(()),
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
                    tls: Ok(()),
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
