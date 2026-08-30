//! Closed controller-recovery ceremony transport.
//!
//! The recovered runtime is deliberately reachable only through its staged
//! loopback endpoint: directly for a local target, or through a short-lived SSH
//! forward for an SSH target. This transport is intentionally smaller than the
//! normal admin transport: it admits exactly the two Recovery Secret ceremony
//! requests, never receives admin credentials, and connects only to the
//! selected local port.

use anyhow::{Context as _, bail};
use url::{Host, Url};

use crate::controller_identity::admin_api::{
    AdminApiTransport, AdminHttpRequest, AdminHttpResponse,
};

const RECOVERY_PATHS: [&str; 2] = [
    "/controller-recovery/challenges",
    "/controller-recovery/recover",
];

/// Non-general HTTP transport for the recovery candidate's loopback endpoint.
pub(crate) struct RecoveryCeremonyTransport {
    issuer: Url,
    issuer_authority: String,
    local_port: u16,
}

impl RecoveryCeremonyTransport {
    pub(crate) fn new(issuer: &str, local_port: u16) -> anyhow::Result<Self> {
        let issuer = Url::parse(issuer).context("recovery ceremony issuer is not a URL")?;
        if issuer.scheme() != "https"
            || issuer.host().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || issuer.path() != "/"
            || local_port == 0
        {
            bail!("recovery ceremony requires a bare HTTPS issuer and a loopback port");
        }
        Ok(Self {
            issuer_authority: authority(&issuer)?,
            issuer,
            local_port,
        })
    }

    fn validate_request(&self, request: &AdminHttpRequest) -> anyhow::Result<&'static str> {
        let url = Url::parse(&request.url).context("recovery ceremony request URL is invalid")?;
        if url.scheme() != "https"
            || url.host() != self.issuer.host()
            || url.port() != self.issuer.port()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(request.method, "POST")
        {
            bail!("recovery ceremony transport rejected a non-ceremony request");
        }
        if request.headers.len() != usize::from(request.body.is_some())
            || request.headers.iter().any(|(name, value)| {
                !name.eq_ignore_ascii_case("content-type")
                    || !value.eq_ignore_ascii_case("application/json")
            })
        {
            bail!("recovery ceremony transport rejected credentials or non-JSON headers");
        }
        if url.path() == RECOVERY_PATHS[0] {
            Ok(RECOVERY_PATHS[0])
        } else if url.path() == RECOVERY_PATHS[1] {
            Ok(RECOVERY_PATHS[1])
        } else {
            bail!("recovery ceremony transport rejected a non-ceremony request")
        }
    }
}

impl AdminApiTransport for RecoveryCeremonyTransport {
    fn send(&self, request: AdminHttpRequest) -> anyhow::Result<AdminHttpResponse> {
        let path = self.validate_request(&request)?;
        // The HTTPS URL above is the authority contract.  The actual socket
        // has no DNS, no TLS downgrade decision, and no proxy route: it is
        // exactly the selected candidate or process-owned forward on
        // `127.0.0.1`.
        let local_url = format!("http://127.0.0.1:{}{path}", self.local_port);
        let mut command = crate::process::Process::new("curl").args([
            "--disable",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--request",
            request.method,
            "--header",
            &format!("Host: {}", self.issuer_authority),
            "--header",
            "Content-Type: application/json",
            "--write-out",
            "\n%{http_code}",
        ]);
        if request.body.is_some() {
            command = command.arg("--data-binary").arg("@-");
        }
        let output = command
            .arg(local_url)
            .stdin_output(request.body.as_deref().unwrap_or_default())
            .context("recovery ceremony loopback request failed")?;
        if !output.status.success() {
            bail!("recovery ceremony loopback transport failed");
        }
        let Some(marker) = output.stdout.iter().rposition(|byte| *byte == b'\n') else {
            bail!("recovery ceremony loopback response omitted its status marker");
        };
        let status = std::str::from_utf8(&output.stdout[marker + 1..])
            .context("recovery ceremony loopback response status is not UTF-8")?
            .parse::<u16>()
            .context("recovery ceremony loopback response status is invalid")?;
        Ok(AdminHttpResponse {
            status,
            body: output.stdout[..marker].to_vec(),
            set_cookie_headers: Vec::new(),
        })
    }
}

fn authority(url: &Url) -> anyhow::Result<String> {
    let host = match url.host() {
        Some(Host::Domain(value)) => value.to_owned(),
        Some(Host::Ipv4(value)) => value.to_string(),
        Some(Host::Ipv6(value)) => format!("[{value}]"),
        None => bail!("recovery ceremony issuer has no host"),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> AdminHttpRequest {
        AdminHttpRequest {
            method: "POST",
            url: url.to_owned(),
            headers: vec![("Content-Type", "application/json".to_owned())],
            body: Some(b"{}".to_vec()),
        }
    }

    #[test]
    fn admits_only_the_two_bound_https_ceremony_paths() -> anyhow::Result<()> {
        let transport = RecoveryCeremonyTransport::new("https://auth.example.test", 43123)?;
        assert!(
            transport
                .validate_request(&request(
                    "https://auth.example.test/controller-recovery/challenges"
                ))
                .is_ok()
        );
        assert!(
            transport
                .validate_request(&request(
                    "https://auth.example.test/controller-recovery/recover"
                ))
                .is_ok()
        );
        assert!(
            transport
                .validate_request(&request(
                    "https://other.example.test/controller-recovery/recover"
                ))
                .is_err()
        );
        assert!(
            transport
                .validate_request(&request(
                    "https://auth.example.test/admin/controller-registry/slots"
                ))
                .is_err()
        );
        assert!(
            transport
                .validate_request(&request(
                    "http://auth.example.test/controller-recovery/recover"
                ))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_admin_access_and_queries() -> anyhow::Result<()> {
        let transport = RecoveryCeremonyTransport::new("https://auth.example.test", 43123)?;
        let mut with_cookie = request("https://auth.example.test/controller-recovery/recover");
        with_cookie
            .headers
            .push(("Cookie", "session=forbidden".to_owned()));
        assert!(transport.validate_request(&with_cookie).is_err());
        assert!(
            transport
                .validate_request(&request(
                    "https://auth.example.test/controller-recovery/recover?unexpected=1"
                ))
                .is_err()
        );
        Ok(())
    }
}
