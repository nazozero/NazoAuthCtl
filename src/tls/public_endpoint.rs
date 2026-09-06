//! Bounded public-network proof of the certificate actually served after reload.

use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs as _},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use url::Url;

use super::{MAX_HTTP_RESPONSE_BYTES, ProviderConfig, sha256};

pub(super) fn verify_public(
    public_url: &Url,
    hostname: &str,
    expected_leaf_sha256: &str,
    roots: RootCertStore,
    provider: &ProviderConfig,
    expected_configuration_sha256: Option<&str>,
) -> anyhow::Result<()> {
    let port = public_url
        .port_or_known_default()
        .context("TLS public URL has no port")?;
    let mut addresses = resolve_public_addresses(
        hostname,
        port,
        Duration::from_secs(provider.connect_timeout_seconds),
    )?;
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        bail!("TLS public hostname resolved to no addresses");
    }
    if addresses.len() > 4 {
        bail!("TLS public hostname resolved beyond the certificate proof address bound");
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        bail!("TLS public hostname resolved to a non-public address");
    }
    for address in addresses {
        verify_public_address(
            public_url,
            hostname,
            address,
            expected_leaf_sha256,
            roots.clone(),
            provider,
            expected_configuration_sha256,
        )
        .with_context(|| format!("TLS public verification failed for address {address}"))?;
    }
    Ok(())
}

pub(super) fn verify_public_not_leaf(
    public_url: &Url,
    hostname: &str,
    forbidden_leaf_sha256: &str,
    roots: RootCertStore,
    provider: &ProviderConfig,
    require_closed: bool,
) -> anyhow::Result<()> {
    let port = public_url
        .port_or_known_default()
        .context("TLS public URL has no port")?;
    let mut addresses = resolve_public_addresses(
        hostname,
        port,
        Duration::from_secs(provider.connect_timeout_seconds),
    )?;
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        bail!("TLS public hostname resolved to no addresses");
    }
    if addresses.len() > 4 {
        bail!("TLS public hostname resolved beyond the rollback proof address bound");
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        bail!("TLS public hostname resolved to a non-public address");
    }
    for address in addresses {
        if require_closed {
            match TcpStream::connect_timeout(
                &address,
                Duration::from_secs(provider.connect_timeout_seconds),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(error) => {
                    return Err(error)
                        .context("could not prove the first native proxy generation was stopped");
                }
                Ok(_) => bail!(
                    "the first native proxy generation was rolled back but its public port remains open"
                ),
            }
        }
        verify_public_address_not_leaf(
            public_url,
            hostname,
            address,
            forbidden_leaf_sha256,
            roots.clone(),
            provider,
        )
        .with_context(|| format!("TLS rollback proof failed for public address {address}"))?;
    }
    Ok(())
}

fn resolve_public_addresses(
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<Vec<SocketAddr>> {
    let hostname = hostname.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (hostname.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>());
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(timeout)
        .context("TLS public hostname resolution timed out")?
        .context("failed to resolve TLS public hostname")
}

pub(super) fn verify_public_address(
    public_url: &Url,
    hostname: &str,
    address: SocketAddr,
    expected_leaf_sha256: &str,
    roots: RootCertStore,
    provider: &ProviderConfig,
    expected_configuration_sha256: Option<&str>,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(provider.request_timeout_seconds);
    loop {
        let observed = observe_public_address(
            public_url,
            hostname,
            address,
            roots.clone(),
            provider,
            deadline,
            expected_configuration_sha256.is_some(),
        )?;
        if observed.0 == expected_leaf_sha256
            && expected_configuration_sha256
                .is_none_or(|expected| observed.1.as_deref() == Some(expected))
        {
            return Ok(());
        }
        // NazoAuth polls its atomic material pointer; nginx/Angie also reload
        // asynchronously. Only a healthy, trusted old identity may settle.
        // TLS/HTTP failures still fail immediately and trigger rollback.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "TLS public endpoint certificate or configuration digest does not match the activated generation before the reload deadline"
            );
        }
        std::thread::sleep(Duration::from_millis(100).min(remaining));
    }
}

pub(super) fn verify_public_address_not_leaf(
    public_url: &Url,
    hostname: &str,
    address: SocketAddr,
    forbidden_leaf_sha256: &str,
    roots: RootCertStore,
    provider: &ProviderConfig,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(provider.request_timeout_seconds);
    let observed = observe_public_address(
        public_url, hostname, address, roots, provider, deadline, false,
    )?;
    if observed.0 == forbidden_leaf_sha256 {
        bail!("TLS public endpoint still presents the rolled-back candidate certificate");
    }
    Ok(())
}

fn observe_public_address(
    public_url: &Url,
    hostname: &str,
    address: SocketAddr,
    roots: RootCertStore,
    provider: &ProviderConfig,
    deadline: Instant,
    require_configuration: bool,
) -> anyhow::Result<(String, Option<String>)> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("TLS public request exceeded its absolute timeout");
    }
    let connect_timeout = Duration::from_secs(provider.connect_timeout_seconds).min(remaining);
    let mut tcp = TcpStream::connect_timeout(&address, connect_timeout)
        .with_context(|| format!("failed to connect to TLS public address {address}"))?;
    tcp.set_nonblocking(true)?;
    let crypto = rustls::crypto::aws_lc_rs::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(hostname.to_owned())
        .context("TLS hostname cannot be represented as SNI")?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name)?;
    let target = if public_url.path().is_empty() {
        "/"
    } else {
        public_url.path()
    };
    let authority = match public_url.port() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname.to_owned(),
    };
    write!(
        connection.writer(),
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: nazoauthctl-tls-verifier/1\r\n\r\n"
    )?;
    let response =
        drive_tls_until_status_line(&mut connection, &mut tcp, deadline, require_configuration)?;
    let peer = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("TLS public endpoint presented no certificate")?;
    let leaf_sha256 = sha256(peer.as_ref());
    let first_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .context("TLS public endpoint returned an empty response")?;
    let first_line = std::str::from_utf8(first_line)
        .context("TLS public endpoint returned a non-UTF-8 status line")?
        .trim_end_matches('\r');
    let mut fields = first_line.split_ascii_whitespace();
    let protocol = fields.next().unwrap_or_default();
    let status = fields
        .next()
        .context("TLS public endpoint status line has no status")?
        .parse::<u16>()
        .context("TLS public endpoint status is not numeric")?;
    if !matches!(protocol, "HTTP/1.0" | "HTTP/1.1") || !provider.accepted_statuses.contains(&status)
    {
        bail!("TLS public endpoint health status {status} is not accepted");
    }
    let configuration = if require_configuration {
        configuration_header(&response)?
    } else {
        None
    };
    Ok((leaf_sha256, configuration))
}

fn configuration_header(response: &[u8]) -> anyhow::Result<Option<String>> {
    let end = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .context("TLS public endpoint returned incomplete HTTP headers")?;
    let headers =
        std::str::from_utf8(&response[..end]).context("TLS public HTTP headers are not UTF-8")?;
    let mut values = headers.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("X-NazoAuth-TLS-Configuration")
            .then(|| value.trim().to_owned())
    });
    let first = values.next();
    if values.next().is_some() {
        bail!("TLS public endpoint returned duplicate configuration proof headers");
    }
    Ok(first)
}

#[cfg(test)]
#[test]
fn configuration_proof_rejects_duplicates_and_ignores_body_bytes() {
    assert_eq!(
        configuration_header(b"HTTP/1.1 200 OK\r\nx-nazoauth-tls-configuration: value\r\n\r\n\xff")
            .unwrap()
            .as_deref(),
        Some("value")
    );
    assert!(configuration_header(b"HTTP/1.1 200 OK\r\nX-NazoAuth-TLS-Configuration: a\r\nX-NazoAuth-TLS-Configuration: b\r\n\r\n").is_err());
    assert!(
        configuration_header(b"HTTP/1.1 200 OK\r\n\r\n")
            .unwrap()
            .is_none()
    );
}

fn drive_tls_until_status_line(
    connection: &mut ClientConnection,
    tcp: &mut TcpStream,
    deadline: Instant,
    require_headers: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut peer_closed = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            bail!("TLS public request exceeded its absolute timeout");
        }
        let mut progressed = false;
        while connection.wants_write() {
            match connection.write_tls(tcp) {
                Ok(0) => bail!("TLS public endpoint closed while ctl was writing"),
                Ok(_) => progressed = true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error).context("failed to write TLS public request"),
            }
        }
        loop {
            match connection.reader().read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    progressed = true;
                    response.extend_from_slice(&chunk[..read]);
                    if response.len() as u64 > MAX_HTTP_RESPONSE_BYTES {
                        bail!("TLS public endpoint status line exceeds the response limit");
                    }
                    if if require_headers {
                        response.windows(4).any(|part| part == b"\r\n\r\n")
                    } else {
                        response.contains(&b'\n')
                    } {
                        return Ok(response);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    return Err(error).context("failed to read TLS public response status");
                }
            }
        }
        if connection.wants_read() && !peer_closed {
            match connection.read_tls(tcp) {
                Ok(0) => peer_closed = true,
                Ok(_) => {
                    connection
                        .process_new_packets()
                        .context("TLS public endpoint handshake or record validation failed")?;
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error).context("failed to read TLS public endpoint"),
            }
        }
        if peer_closed {
            bail!("TLS public endpoint closed before returning an HTTP status line");
        }
        if !progressed {
            std::thread::sleep(
                Duration::from_millis(5).min(deadline.saturating_duration_since(now)),
            );
        }
    }
}

pub(super) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address.octets()),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ipv4(mapped.octets());
            }
            let segments = address.segments();
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && (segments[0] & 0xfe00) != 0xfc00
                && (segments[0] & 0xffc0) != 0xfe80
                && (segments[0] & 0xffc0) != 0xfec0
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
                && segments[0] != 0x2002
                && segments[0] != 0x3ffe
                && segments[0] != 0x5f00
                && !(segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
                && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        }
    }
}

fn is_public_ipv4(octets: [u8; 4]) -> bool {
    !matches!(
        octets,
        [0, ..]
            | [10, ..]
            | [100, 64..=127, ..]
            | [127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0, ..]
            | [192, 0, 2, ..]
            | [192, 88, 99, ..]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
            | [224..=255, ..]
    )
}
