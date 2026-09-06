//! Native proxy configuration shares the certificate generation and rollback.

use super::*;

const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;
const CERTIFICATE: &str = "\"@NAZOAUTH_TLS_CERTIFICATE_FILE@\"";
const PRIVATE_KEY: &str = "\"@NAZOAUTH_TLS_PRIVATE_KEY_FILE@\"";
const CONFIGURATION: &str = "\"@NAZOAUTH_TLS_CONFIGURATION_SHA256@\"";

pub(super) fn load_template(
    input: &TlsCertificateInput,
    provider: &ProviderConfig,
) -> anyhow::Result<Option<Vec<u8>>> {
    match (&input.proxy_config, &provider.native_proxy_program) {
        (None, None) => Ok(None),
        (Some(path), Some(_)) => {
            let bytes = read_secure_regular_file(
                path,
                "native proxy configuration",
                true,
                MAX_CONFIGURATION_BYTES,
            )?;
            // Validate placeholder syntax during plan, before any journal write.
            render(&bytes, &provider.material_root.join("generations/plan"))?;
            Ok(Some(bytes.to_vec()))
        }
        _ => bail!("--proxy-config and provider native_proxy_program must be supplied together"),
    }
}

fn quoted_path(path: &Path) -> anyhow::Result<String> {
    let path = path
        .to_str()
        .context("native proxy TLS path must be UTF-8")?;
    if path.chars().any(char::is_control) {
        bail!("native proxy TLS path contains a control character");
    }
    let mut escaped = String::from("\"");
    for character in path.chars() {
        if matches!(character, '\\' | '"' | '$') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped.push('"');
    Ok(escaped)
}

fn render(template: &[u8], generation: &Path) -> anyhow::Result<Vec<u8>> {
    let template =
        std::str::from_utf8(template).context("native proxy configuration must be UTF-8")?;
    if template.contains('\0')
        || !template.contains(CERTIFICATE)
        || !template.contains(PRIVATE_KEY)
        || !template.contains(CONFIGURATION)
    {
        bail!(
            "native proxy configuration requires quoted certificate, private-key and configuration-SHA256 placeholders"
        );
    }
    let rendered = template
        .replace(
            CERTIFICATE,
            &quoted_path(&generation.join("fullchain.pem"))?,
        )
        .replace(
            PRIVATE_KEY,
            &quoted_path(&generation.join("private-key.pem"))?,
        )
        .replace(
            CONFIGURATION,
            &format!("\"{}\"", sha256(template.as_bytes())),
        );
    if rendered.contains("@NAZOAUTH_TLS_") {
        bail!("native proxy configuration contains an unresolved TLS placeholder");
    }
    Ok(rendered.into_bytes())
}

pub(super) fn stage(
    transaction: &CertificateTransaction,
    template: Option<&[u8]>,
) -> anyhow::Result<()> {
    match (template, transaction.proxy_configuration_sha256.as_deref()) {
        (None, None) => Ok(()),
        (Some(template), Some(digest)) if sha256(template) == digest => {
            let rendered = render(template, &transaction.generation)?;
            atomic_write(
                &transaction.generation.join("proxy.conf.template"),
                template,
                0o600,
            )?;
            atomic_write(&transaction.generation.join("proxy.conf"), &rendered, 0o600)
        }
        _ => bail!("native proxy configuration differs from the prepared transaction"),
    }
}

pub(super) fn validate_generation(generation: &Path, expected: Option<&str>) -> anyhow::Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let template = read_secure_regular_file(
        &generation.join("proxy.conf.template"),
        "installed proxy template",
        true,
        MAX_CONFIGURATION_BYTES,
    )?;
    if sha256(&template) != expected {
        bail!("installed proxy configuration differs from the committed receipt");
    }
    let rendered = read_secure_regular_file(
        &generation.join("proxy.conf"),
        "installed proxy configuration",
        true,
        MAX_CONFIGURATION_BYTES * 2,
    )?;
    if rendered.as_slice() != render(&template, generation)? {
        bail!("installed native proxy configuration drifted from its template");
    }
    Ok(())
}

pub(super) fn validate_candidate(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    validate_native(transaction, &transaction.generation)?;
    validate_generation(
        &transaction.generation,
        transaction.proxy_configuration_sha256.as_deref(),
    )
}

pub(super) fn validate_native(
    transaction: &CertificateTransaction,
    generation: &Path,
) -> anyhow::Result<()> {
    if let Some(program) = &transaction.provider.native_proxy_program {
        let command = ProviderCommand {
            program: program.clone(),
            args: vec![
                "-t".to_owned(),
                "-c".to_owned(),
                generation
                    .join("proxy.conf")
                    .to_str()
                    .context("native proxy configuration path must be UTF-8")?
                    .to_owned(),
            ],
        };
        execute_provider_command(transaction, &command, "native proxy configuration test")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_configuration_binds_both_tls_files_to_one_generation() -> anyhow::Result<()> {
        let template = b"ssl_certificate \"@NAZOAUTH_TLS_CERTIFICATE_FILE@\";\nssl_certificate_key \"@NAZOAUTH_TLS_PRIVATE_KEY_FILE@\"; add_header X-NazoAuth-TLS-Configuration \"@NAZOAUTH_TLS_CONFIGURATION_SHA256@\" always;";
        let rendered = String::from_utf8(render(template, Path::new("/etc/tls/generations/1"))?)?
            .replace("\\\\", "/");
        assert!(rendered.contains("ssl_certificate \"/etc/tls/generations/1/fullchain.pem\";"));
        assert!(
            rendered.contains("ssl_certificate_key \"/etc/tls/generations/1/private-key.pem\";")
        );
        assert!(!rendered.contains('@'));
        assert!(render(b"ssl_certificate /old/cert;", Path::new("/etc/tls/1")).is_err());
        assert!(
            render(
                b"@NAZOAUTH_TLS_CERTIFICATE_FILE@ @NAZOAUTH_TLS_PRIVATE_KEY_FILE@",
                Path::new("/etc/tls/1")
            )
            .is_err()
        );
        assert_eq!(quoted_path(Path::new("/etc/a\"$b"))?, "\"/etc/a\\\"\\$b\"");
        Ok(())
    }
}
