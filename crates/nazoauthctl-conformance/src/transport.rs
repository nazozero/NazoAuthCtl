use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

impl HttpMethod {
    fn as_reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

/// Internal request representation. Its `Debug` implementation is omitted on
/// purpose: request headers and config bodies may contain credentials.
pub struct HttpRequest {
    pub(crate) method: HttpMethod,
    pub(crate) url: Url,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub trait Transport: Send + Sync {
    fn send(
        &self,
        request: HttpRequest,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, TransportError>;
}

#[derive(Clone)]
pub struct HttpTransport {
    client: Client,
}

impl HttpTransport {
    pub fn new(timeout: Duration) -> Result<Self, TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        Ok(Self { client })
    }
}

impl Transport for HttpTransport {
    fn send(
        &self,
        request: HttpRequest,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self
            .client
            .request(request.method.as_reqwest(), request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder.send().map_err(|_| TransportError::Network)?;
        if response
            .content_length()
            .is_some_and(|length| length > max_response_bytes as u64)
        {
            return Err(TransportError::Oversize);
        }
        let status = response.status().as_u16();
        let mut header_bytes = 0usize;
        let mut headers = Vec::new();
        for (name, value) in response.headers().iter() {
            let Some(value) = value.to_str().ok() else {
                continue;
            };
            header_bytes = header_bytes
                .saturating_add(name.as_str().len())
                .saturating_add(value.len());
            if header_bytes > max_response_bytes {
                return Err(TransportError::Oversize);
            }
            headers.push((name.as_str().to_owned(), value.to_owned()));
        }
        let mut body = Vec::new();
        response
            .take(max_response_bytes.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| TransportError::Network)?;
        if body.len() > max_response_bytes {
            return Err(TransportError::Oversize);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidConfiguration,
    Network,
    Oversize,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "HTTP transport configuration is invalid",
            Self::Network => "HTTP transport failed",
            Self::Oversize => "HTTP response exceeds the size limit",
        })
    }
}

impl std::error::Error for TransportError {}
