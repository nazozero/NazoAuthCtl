use super::*;

pub(super) fn bootstrap_admin(
    config: &UpdateConfig,
    options: BootstrapAdminOptions,
) -> anyhow::Result<()> {
    let credentials = read_bootstrap_admin_credentials(options.credentials_stdin)?;
    let request_id = audited_bootstrap_admin(
        config,
        &credentials,
        std::ffi::OsStr::new("curl"),
        Some(crate::runtime::runtime_service_owner_uid(config)?),
    )?;
    println!(
        "Initial administrator created (request ID: {request_id}). Continue at {}/ui/auth",
        config.runtime.expected_issuer.trim_end_matches('/'),
    );
    Ok(())
}

pub(super) fn audited_bootstrap_admin(
    config: &UpdateConfig,
    credentials: &BootstrapAdminCredentials,
    curl_program: &std::ffi::OsStr,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<String> {
    let normalized_email = normalize_bootstrap_admin_email(&credentials.email)?;
    let mut pending = load_or_create_bootstrap_pending(config, &normalized_email)?;
    let request_id = pending.request_id.clone();
    if pending.status == BootstrapAdminPendingStatus::Succeeded {
        let token_path = bootstrap_token_path(config, expected_owner_uid)?;
        if token_path.exists() {
            let token = read_bootstrap_token(&token_path, expected_owner_uid)?;
            let expected_token_hmac = pending
                .token_hmac_sha256
                .as_deref()
                .context("bootstrap-admin success state has no token binding")?;
            if bootstrap_state_hmac(config, b"token-v1", token.as_bytes())? != expected_token_hmac {
                bail!(
                    "bootstrap token changed after the recorded success; a database recovery may have reopened initial administration"
                );
            }
            let receipt = claim_bootstrap_admin(
                config,
                credentials,
                &request_id,
                curl_program,
                expected_owner_uid,
            )?;
            let expected_user_id = pending
                .claimed_user_id
                .as_deref()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .context("bootstrap-admin success state has no valid application receipt")?;
            if receipt.claimed_user_id != expected_user_id
                || receipt.token_hmac_sha256 != expected_token_hmac
            {
                bail!("bootstrap application receipt changed after the recorded success");
            }
            remove_file_durable(&token_path)?;
        }
        return Ok(request_id);
    }
    match claim_bootstrap_admin(
        config,
        credentials,
        &request_id,
        curl_program,
        expected_owner_uid,
    ) {
        Ok(receipt) => {
            pending.status = BootstrapAdminPendingStatus::Succeeded;
            pending.claimed_user_id = Some(receipt.claimed_user_id.to_string());
            pending.token_hmac_sha256 = Some(receipt.token_hmac_sha256);
            atomic_write(
                &bootstrap_pending_path(config),
                &serde_json::to_vec_pretty(&pending)?,
                0o600,
            )?;
            let token_path = bootstrap_token_path(config, expected_owner_uid)?;
            remove_file_durable(&token_path)
                .context("initial administrator was created but token cleanup failed")?;
            Ok(request_id)
        }
        Err(error) => {
            Err(error).with_context(|| format!("bootstrap-admin request ID {request_id} failed"))
        }
    }
}

pub(super) fn claim_bootstrap_admin(
    config: &UpdateConfig,
    credentials: &BootstrapAdminCredentials,
    request_id: &str,
    curl_program: &std::ffi::OsStr,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<VerifiedBootstrapReceipt> {
    let normalized_email = normalize_bootstrap_admin_email(&credentials.email)?;
    if !(12..=1024).contains(&credentials.password.chars().count()) {
        bail!("administrator password must contain between 12 and 1024 characters");
    }

    let token_path = bootstrap_token_path(config, expected_owner_uid)?;
    let token = read_bootstrap_token(&token_path, expected_owner_uid)?;
    let token_hmac_sha256 = bootstrap_state_hmac(config, b"token-v1", token.as_bytes())?;
    let endpoint = bootstrap_admin_endpoint(&config.runtime.expected_issuer)?;
    let request = serde_json::to_vec(&BootstrapAdminRequest {
        request_id,
        token: &token,
        email: &normalized_email,
        password: &credentials.password,
    })?;
    let protocol = if endpoint.scheme() == "https" {
        "=https"
    } else {
        "=http"
    };
    let submission = (|| -> anyhow::Result<uuid::Uuid> {
        let output = Process::new(curl_program)
            .args([
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proto",
                protocol,
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(endpoint.as_str())
            .stdin_stdout(&request)
            .context("initial administrator request failed")?;
        let (body, status) = output
            .rsplit_once('\n')
            .context("initial administrator response omitted its HTTP status")?;
        if status.trim() != "201" {
            bail!("initial administrator endpoint returned an unexpected HTTP status");
        }
        let response: BootstrapAdminResponse = serde_json::from_str(body)
            .context("initial administrator endpoint returned an invalid response")?;
        let claimed_user_id = uuid::Uuid::parse_str(&response.id)
            .context("initial administrator response has an invalid user ID")?;
        if response.request_id != request_id
            || response.email != normalized_email
            || response.role != "admin"
            || response.next != "/ui/auth"
        {
            bail!("initial administrator endpoint returned an unexpected response contract");
        }
        Ok(claimed_user_id)
    })();
    let claimed_user_id = submission
        .map_err(|error| anyhow::Error::new(BootstrapOutcomeUnknown).context(error.to_string()))?;
    Ok(VerifiedBootstrapReceipt {
        claimed_user_id,
        token_hmac_sha256,
    })
}

pub(super) fn bootstrap_pending_path(config: &UpdateConfig) -> PathBuf {
    config
        .operator
        .state_directory
        .join("bootstrap-admin-pending.json")
}

pub(super) fn bootstrap_recovery_epoch_path(config: &UpdateConfig) -> PathBuf {
    config
        .operator
        .state_directory
        .join("bootstrap-recovery-epoch")
}

pub(super) fn load_or_create_bootstrap_pending(
    config: &UpdateConfig,
    normalized_email: &str,
) -> anyhow::Result<BootstrapAdminPending> {
    let path = bootstrap_pending_path(config);
    let email_hmac_sha256 = bootstrap_email_hmac(config, normalized_email)?;
    let recovery_epoch = current_bootstrap_recovery_epoch(config)?;
    if path.exists() {
        let pending_bytes = crate::filesystem::read_secure_regular_file(
            &path,
            "bootstrap-admin pending state",
            true,
            16 * 1024,
        )?;
        let pending: BootstrapAdminPending = serde_json::from_slice(&pending_bytes)
            .context("bootstrap-admin pending state is invalid")?;
        if pending.schema != 2 || !valid_bootstrap_request_id(&pending.request_id) {
            bail!("bootstrap-admin pending state does not match this request");
        }
        if pending.recovery_epoch == recovery_epoch {
            if pending.email_hmac_sha256 != email_hmac_sha256 {
                bail!("bootstrap-admin pending state does not match this request");
            }
            let receipt_is_valid = match pending.status {
                BootstrapAdminPendingStatus::Intent => {
                    pending.claimed_user_id.is_none() && pending.token_hmac_sha256.is_none()
                }
                BootstrapAdminPendingStatus::Succeeded => {
                    pending
                        .claimed_user_id
                        .as_deref()
                        .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
                        && pending
                            .token_hmac_sha256
                            .as_deref()
                            .is_some_and(valid_lower_hex_sha256)
                }
            };
            if !receipt_is_valid {
                bail!("bootstrap-admin pending state has an invalid application receipt");
            }
            return Ok(pending);
        }
    }
    crate::filesystem::ensure_directory_chain(&config.operator.state_directory)?;
    let pending = BootstrapAdminPending {
        schema: 2,
        request_id: format!("bootstrap-admin-{:032x}", rand::random::<u128>()),
        email_hmac_sha256,
        recovery_epoch,
        status: BootstrapAdminPendingStatus::Intent,
        claimed_user_id: None,
        token_hmac_sha256: None,
    };
    atomic_write(&path, &serde_json::to_vec_pretty(&pending)?, 0o600)?;
    Ok(pending)
}

pub(super) fn bootstrap_email_hmac(config: &UpdateConfig, email: &str) -> anyhow::Result<String> {
    bootstrap_state_hmac(config, b"email-v2", email.as_bytes())
}

pub(super) fn bootstrap_state_hmac(
    config: &UpdateConfig,
    domain: &[u8],
    value: &[u8],
) -> anyhow::Result<String> {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    let key = crate::filesystem::read_secure_secret_file(
        &config.operator.secret_revision_file,
        "deployment secret revision for bootstrap binding",
        4096,
    )?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key)
        .context("deployment secret revision cannot bind bootstrap state")?;
    hmac.update(b"nazoauthctl-bootstrap-admin-v2\0");
    hmac.update(domain);
    hmac.update(b"\0");
    hmac.update(value);
    let bytes = hmac.finalize().into_bytes();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

pub(super) fn valid_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(super) fn valid_bootstrap_recovery_epoch(value: &str) -> bool {
    value.len() == 41
        && value.strip_prefix("recovery-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

pub(super) fn current_bootstrap_recovery_epoch(config: &UpdateConfig) -> anyhow::Result<String> {
    let path = bootstrap_recovery_epoch_path(config);
    if path.exists() {
        let bytes = crate::filesystem::read_secure_regular_file(
            &path,
            "bootstrap recovery epoch",
            true,
            256,
        )?;
        let value = std::str::from_utf8(&bytes).context("bootstrap recovery epoch is not UTF-8")?;
        if !valid_bootstrap_recovery_epoch(value) {
            bail!("bootstrap recovery epoch is invalid");
        }
        return Ok(value.to_owned());
    }
    crate::filesystem::ensure_directory_chain(&config.operator.state_directory)?;
    let value = format!("recovery-{:032x}", rand::random::<u128>());
    atomic_write(&path, value.as_bytes(), 0o400)?;
    Ok(value)
}

pub(super) fn valid_bootstrap_request_id(request_id: &str) -> bool {
    request_id.len() == 48
        && request_id
            .strip_prefix("bootstrap-admin-")
            .is_some_and(|suffix| {
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

pub(super) fn read_bootstrap_admin_credentials(
    from_stdin: bool,
) -> anyhow::Result<BootstrapAdminCredentials> {
    if from_stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_BOOTSTRAP_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to read administrator credentials from stdin")?;
        return parse_bootstrap_admin_credentials(&bytes);
    }
    if !std::io::stdin().is_terminal() {
        bail!("interactive bootstrap requires a terminal or --credentials-stdin");
    }
    eprint!("Administrator email: ");
    std::io::stderr().flush()?;
    let mut email = String::new();
    std::io::stdin()
        .read_line(&mut email)
        .context("failed to read administrator email")?;
    let password = rpassword::prompt_password("Administrator password: ")
        .context("failed to read administrator password")?;
    validate_bootstrap_admin_credentials(BootstrapAdminCredentials { email, password })
}

pub(super) fn parse_bootstrap_admin_credentials(
    bytes: &[u8],
) -> anyhow::Result<BootstrapAdminCredentials> {
    if bytes.len() as u64 > MAX_BOOTSTRAP_CREDENTIAL_BYTES {
        bail!("administrator credential input exceeds the allowed size");
    }
    let credentials = serde_json::from_slice(bytes)
        .context("administrator credentials must be strict JSON with email and password")?;
    validate_bootstrap_admin_credentials(credentials)
}

pub(super) fn validate_bootstrap_admin_credentials(
    credentials: BootstrapAdminCredentials,
) -> anyhow::Result<BootstrapAdminCredentials> {
    normalize_bootstrap_admin_email(&credentials.email)?;
    if !(12..=1024).contains(&credentials.password.chars().count()) {
        bail!("administrator password must contain between 12 and 1024 characters");
    }
    Ok(credentials)
}

pub(super) fn normalize_bootstrap_admin_email(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    let Some((local, domain)) = value.split_once('@') else {
        bail!("administrator email is invalid");
    };
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || domain.split('.').any(|label| {
            label.is_empty() || label.starts_with('-') || label.ends_with('-') || label.len() > 63
        })
    {
        bail!("administrator email is invalid");
    }
    Ok(value)
}

pub(super) fn bootstrap_admin_endpoint(issuer: &str) -> anyhow::Result<url::Url> {
    let mut endpoint =
        url::Url::parse(issuer).context("configured issuer is not an HTTP origin")?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("configured issuer is not an HTTP origin");
    }
    if endpoint.scheme() == "http"
        && !endpoint.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        bail!("initial administrator bootstrap requires HTTPS outside loopback trial mode");
    }
    endpoint.set_path("/auth/bootstrap-admin");
    Ok(endpoint)
}

pub(super) fn bootstrap_token_path(
    config: &UpdateConfig,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<PathBuf> {
    let target = Path::new(BOOTSTRAP_MOUNT_TARGET);
    let mut sources = config
        .runtime
        .mounts
        .iter()
        .filter(|mount| mount.target == target)
        .map(|mount| mount.source.clone())
        .collect::<Vec<_>>();
    if config.runtime.backend == RuntimeBackendKind::Systemd && sources.is_empty() {
        sources.extend(
            config
                .runtime
                .snapshot_paths
                .iter()
                .filter(|path| path.file_name().is_some_and(|name| name == "bootstrap"))
                .cloned(),
        );
    }
    if sources.len() != 1 {
        bail!("managed runtime must expose exactly one bootstrap state source");
    }
    let source = &sources[0];
    validate_bootstrap_directory(source, expected_owner_uid)?;
    Ok(source.join(BOOTSTRAP_TOKEN_FILE))
}

#[cfg(unix)]
pub(super) fn read_bootstrap_token(
    path: &Path,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<String> {
    let mut file = match expected_owner_uid {
        Some(owner_uid) => crate::filesystem::open_secure_regular_file_for_uid(
            path,
            "initial administrator token",
            false,
            owner_uid,
        )?,
        None => {
            crate::filesystem::open_secure_regular_file(path, "initial administrator token", false)?
        }
    };
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata()?;
        if expected_owner_uid.is_some_and(|expected| metadata.uid() != expected) {
            bail!("initial administrator token has an unexpected runtime owner");
        }
        let mode = metadata.mode() & 0o7777;
        if mode & 0o077 != 0 || mode & 0o111 != 0 || mode & 0o400 == 0 {
            bail!("initial administrator token must be private and owner-readable");
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAX_BOOTSTRAP_TOKEN_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("failed to read initial administrator token")?;
    if bytes.len() as u64 > MAX_BOOTSTRAP_TOKEN_BYTES {
        bail!("initial administrator token exceeds the allowed size");
    }
    let token = std::str::from_utf8(&bytes)
        .context("initial administrator token is not valid UTF-8")?
        .trim_end_matches(['\r', '\n']);
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("initial administrator token has an invalid format");
    }
    Ok(token.to_owned())
}

#[cfg(not(unix))]
pub(super) fn read_bootstrap_token(
    path: &Path,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<String> {
    let _ = (path, expected_owner_uid);
    bail!("bootstrap-admin is supported only on Unix managed hosts")
}

#[cfg(unix)]
pub(super) fn validate_bootstrap_directory(
    path: &Path,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        fs::symlink_metadata(path).context("managed bootstrap state directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed bootstrap state source is not a directory");
    }
    if fs::canonicalize(path)? != path {
        bail!("managed bootstrap state source must not traverse symbolic links");
    }
    if expected_owner_uid.is_some_and(|expected| metadata.uid() != expected) {
        bail!("managed bootstrap state source has an unexpected runtime owner");
    }
    if metadata.mode() & 0o077 != 0 {
        bail!("managed bootstrap state source must not be accessible by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn validate_bootstrap_directory(
    _path: &Path,
    _expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    bail!("bootstrap-admin is supported only on Unix managed hosts")
}
