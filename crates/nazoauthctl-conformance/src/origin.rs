use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use url::Url;

/// A canonical HTTPS origin. Paths, query strings, fragments, and user-info
/// are intentionally not part of this type.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Origin(String);

impl Origin {
    /// Parse an HTTPS origin supplied by an operator. Network reachability is
    /// intentionally not inferred here: an explicit private/loopback Suite
    /// is valid, while callers that need public-only policy can use
    /// [`Self::parse_public_suite`].
    pub fn parse(value: &str) -> Result<Self, OriginError> {
        let value = value.trim();
        let parsed = Url::parse(value).map_err(|_| OriginError::InvalidSyntax)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(OriginError::NotHttpsOrigin);
        }

        let host = parsed.host_str().ok_or(OriginError::InvalidSyntax)?;
        let mut canonical = format!("https://{}", canonical_host(host));
        if let Some(port) = parsed.port()
            && port != 443
        {
            canonical.push(':');
            canonical.push_str(&port.to_string());
        }
        Ok(Self(canonical))
    }

    /// Parse a Suite origin supplied by the operator. Private/loopback hosts
    /// are allowed for an explicitly selected private Suite; callers that
    /// require a public endpoint can opt into [`Self::parse_public_suite`].
    pub fn parse_suite(value: &str) -> Result<Self, OriginError> {
        Self::parse(value)
    }

    pub fn parse_public_suite(value: &str) -> Result<Self, OriginError> {
        let origin = Self::parse(value)?;
        if is_private_or_local_host(&origin.host()) {
            return Err(OriginError::PrivateAddress);
        }
        Ok(origin)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn host(&self) -> String {
        Url::parse(&self.0)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .unwrap_or_default()
    }

    pub fn url(&self, path: &str) -> Result<Url, OriginError> {
        if !path.starts_with('/') || path.contains("//") || path.contains("..") {
            return Err(OriginError::InvalidPath);
        }
        let mut url = Url::parse(self.as_str()).map_err(|_| OriginError::InvalidSyntax)?;
        url.set_path(path);
        Ok(url)
    }

    pub fn same_origin_url(&self, url: &Url) -> bool {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_ascii_lowercase()
        };
        let authority = match url.port() {
            Some(port) if port != 443 => format!("{authority}:{port}"),
            _ => authority,
        };
        self.0 == format!("https://{authority}")
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Origin").field(&self.0).finish()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OriginError {
    InvalidSyntax,
    NotHttpsOrigin,
    PrivateAddress,
    InvalidPath,
}

impl fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSyntax => "invalid origin syntax",
            Self::NotHttpsOrigin => {
                "origin must be HTTPS without credentials, path, query, or fragment"
            }
            Self::PrivateAddress => "public Suite origin must not be a local or private address",
            Self::InvalidPath => "API path must be a normalized absolute path",
        })
    }
}

impl std::error::Error for OriginError {}

fn canonical_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    }
}

fn is_private_or_local_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if matches!(
        host.as_str(),
        "localhost" | "localhost.localdomain" | "metadata.google.internal"
    ) || host.ends_with(".local")
        || host.ends_with(".localhost")
    {
        return true;
    }
    let Ok(address) = host.parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(value) => {
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_unspecified()
                || value == Ipv4Addr::new(169, 254, 169, 254)
                || value.octets()[0] == 0
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unspecified()
                || value.is_unique_local()
                || is_ipv6_link_local(value)
        }
    }
}

fn is_ipv6_link_local(value: Ipv6Addr) -> bool {
    (value.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_https_origin_only() {
        let origin = Origin::parse("HTTPS://Example.test/").expect("origin");
        assert_eq!(origin.as_str(), "https://example.test");
        assert!(Origin::parse("https://example.test/path").is_err());
        assert!(Origin::parse("http://example.test").is_err());
    }

    #[test]
    fn explicit_suite_accepts_private_literal() {
        assert_eq!(
            Origin::parse_suite("https://127.0.0.1")
                .expect("origin")
                .as_str(),
            "https://127.0.0.1"
        );
        assert_eq!(
            Origin::parse_public_suite("https://localhost").unwrap_err(),
            OriginError::PrivateAddress
        );
    }
}
