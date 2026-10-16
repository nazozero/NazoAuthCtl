use std::fmt;
use std::time::Duration;

use url::{Host, Url};

use crate::origin::Origin;

use super::BrowserError;

pub(super) const MAX_STEP_TIMEOUT: Duration = Duration::from_secs(300);
pub(super) const MAX_STEPS: usize = 256;
pub(super) const MAX_MATCH_BYTES: usize = 4096;

/// A target origin accepted by the browser policy. Production targets must
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
            && !match url.host() {
                Some(Host::Domain(host)) => matches!(host, "localhost" | "localhost.localdomain"),
                Some(Host::Ipv4(address)) => address.is_loopback(),
                Some(Host::Ipv6(address)) => address.is_loopback(),
                None => false,
            }
        {
            return Err(BrowserError::InsecureTarget);
        }
        let mut canonical = url;
        canonical.set_path("");
        Ok(Self { url: canonical })
    }

    pub fn as_url(&self) -> &Url {
        &self.url
    }

    pub(super) fn allows(&self, candidate: &Url) -> bool {
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

/// The only URLs a browser session may visit. Navigation to a third-party
/// redirect is a hard error in the HTTP-based protocol drivers.
#[derive(Clone, Debug)]
pub struct BrowserPolicy {
    pub target_origin: BrowserTargetOrigin,
    pub suite_origin: Origin,
}

impl BrowserPolicy {
    pub fn new(target_origin: BrowserTargetOrigin, suite_origin: Origin) -> Self {
        Self {
            target_origin,
            suite_origin,
        }
    }

    pub fn allows_url(&self, url: &Url) -> bool {
        self.target_origin.allows(url) || self.suite_origin.same_origin_url(url)
    }

    pub(super) fn validate_url(&self, url: &Url) -> Result<(), BrowserError> {
        if self.allows_url(url) {
            Ok(())
        } else {
            Err(BrowserError::CrossOriginNavigation)
        }
    }
}

pub(super) fn redacted_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

pub(super) fn same_origin(expected: &Url, actual: &Url) -> bool {
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
        && actual.username().is_empty()
        && actual.password().is_none()
}
