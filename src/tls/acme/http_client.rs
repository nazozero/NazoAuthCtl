//! ACME network-authority enforcement.
//!
//! ACME resource URLs are server-provided and can legitimately use more than
//! one origin. The operator therefore declares the complete trusted origin
//! set, while this transport wrapper enforces it before every request leaves
//! the controller.

use std::{collections::BTreeSet, future::Future, io, pin::Pin};

use anyhow::{Context, bail};
use bytes::Bytes;
use http::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use instant_acme::{BodyWrapper, BytesResponse, Error as AcmeError, HttpClient};
use rustls::RootCertStore;
use url::Url;

const MAX_ALLOWED_ORIGINS: usize = 8;

#[derive(Clone, Debug)]
pub(super) struct AuthorityPolicy {
    origins: BTreeSet<String>,
}

impl AuthorityPolicy {
    pub(super) fn from_config(origins: &[String]) -> anyhow::Result<Self> {
        if origins.is_empty() || origins.len() > MAX_ALLOWED_ORIGINS {
            bail!("ACME allowed origins must contain between one and eight entries");
        }
        let mut canonical = BTreeSet::new();
        for origin in origins {
            let parsed = validate_https_url(origin, "ACME allowed origin")?;
            let expected = parsed.origin().ascii_serialization();
            if parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || origin != &expected
            {
                bail!("ACME allowed origins must be canonical HTTPS origins without a path");
            }
            if !canonical.insert(expected) {
                bail!("ACME allowed origins must not contain duplicates");
            }
        }
        Ok(Self { origins: canonical })
    }

    pub(super) fn require_url(&self, value: &str, label: &str) -> anyhow::Result<()> {
        let origin = validate_https_url(value, label)?
            .origin()
            .ascii_serialization();
        if !self.origins.contains(&origin) {
            bail!("{label} origin {origin} is outside the operator-declared ACME authority");
        }
        Ok(())
    }
}

pub(super) fn build_http_client(
    policy: AuthorityPolicy,
    roots: Option<RootCertStore>,
) -> anyhow::Result<Box<dyn HttpClient>> {
    let connector = match roots {
        Some(roots) => HttpsConnectorBuilder::new().with_tls_config(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ),
        None => HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .context("failed to load platform trust for the ACME client")?,
    }
    .https_only()
    .enable_http1()
    .enable_http2()
    .build();
    let inner: HyperClient<_, BodyWrapper<Bytes>> =
        HyperClient::builder(TokioExecutor::new()).build(connector);
    Ok(Box::new(AuthorityBoundHttpClient {
        policy,
        inner: Box::new(inner),
    }))
}

pub(super) fn validate_https_url(value: &str, label: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| format!("{label} is invalid"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("{label} must be HTTPS without credentials or fragment");
    }
    Ok(url)
}

struct AuthorityBoundHttpClient {
    policy: AuthorityPolicy,
    inner: Box<dyn HttpClient>,
}

impl HttpClient for AuthorityBoundHttpClient {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        if let Err(error) = self
            .policy
            .require_url(&request.uri().to_string(), "ACME request URL")
        {
            let error = io::Error::new(io::ErrorKind::PermissionDenied, error.to_string());
            return Box::pin(async move { Err(AcmeError::Other(Box::new(error))) });
        }
        self.inner.request(request)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct RecordingClient {
        calls: Arc<AtomicUsize>,
    }

    impl HttpClient for RecordingClient {
        fn request(
            &self,
            _request: Request<BodyWrapper<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AcmeError::Other(Box::new(io::Error::other(
                    "recording client stop",
                ))))
            })
        }
    }

    #[test]
    fn authority_policy_is_canonical_and_supports_explicit_multi_origin_acme() {
        let policy = AuthorityPolicy::from_config(&[
            "https://directory.example".to_owned(),
            "https://resources.example:8443".to_owned(),
        ])
        .unwrap();
        assert!(
            policy
                .require_url("https://directory.example/acme/directory", "directory")
                .is_ok()
        );
        assert!(
            policy
                .require_url("https://resources.example:8443/order/1?cursor=2", "order")
                .is_ok()
        );
        assert!(
            policy
                .require_url("https://resources.example/order/1", "order")
                .is_err()
        );
        assert!(
            AuthorityPolicy::from_config(&["https://DIRECTORY.example:443".to_owned()]).is_err()
        );
        assert!(
            AuthorityPolicy::from_config(&["https://directory.example/path".to_owned()]).is_err()
        );
        assert!(AuthorityPolicy::from_config(&[]).is_err());
        assert!(
            AuthorityPolicy::from_config(&[
                "https://directory.example".to_owned(),
                "https://directory.example".to_owned(),
            ])
            .is_err()
        );

        let private_test_authority =
            AuthorityPolicy::from_config(&["https://127.0.0.1:14000".to_owned()]).unwrap();
        assert!(
            private_test_authority
                .require_url("https://127.0.0.1:14000/dir", "private test directory")
                .is_ok()
        );
    }

    #[test]
    fn denied_request_never_reaches_the_http_transport() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = AuthorityBoundHttpClient {
            policy: AuthorityPolicy::from_config(&["https://acme.example".to_owned()]).unwrap(),
            inner: Box::new(RecordingClient {
                calls: calls.clone(),
            }),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let denied = Request::builder()
            .uri("https://127.0.0.1/internal")
            .body(BodyWrapper::default())
            .unwrap();
        assert!(runtime.block_on(client.request(denied)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let allowed = Request::builder()
            .uri("https://acme.example/order/1")
            .body(BodyWrapper::default())
            .unwrap();
        assert!(runtime.block_on(client.request(allowed)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
