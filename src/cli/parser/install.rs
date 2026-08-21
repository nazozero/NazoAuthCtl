use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, bail};

use super::super::types::{CandidateTarget, InstallOptions, LocalOciCandidateInstall};
use super::common::validate_version;
use crate::install::{normalize_public_url_for_profile, normalize_single_host_cidr};

pub(super) fn parse_install(values: Vec<String>) -> anyhow::Result<InstallOptions> {
    let mut runtime = "auto".to_owned();
    let mut public_url = "http://127.0.0.1:8000".to_owned();
    let mut profile = "baseline".to_owned();
    let mut profile_material = None;
    let mut trusted_proxy_cidr = None;
    let mut data_root = PathBuf::from("/var/lib/nazoauth");
    let mut control_root = PathBuf::from("/var/lib/nazoauthctl");
    let mut recovery_root = PathBuf::from("/var/lib/nazoauth-recovery");
    let mut port = 8000;
    let mut network_subnet = None;
    let mut runtime_ip = None;
    let database_url = None;
    let migration_database_url = None;
    let database_backup_url = None;
    let valkey_url = None;
    let valkey_backup_url = None;
    let external_valkey_backup_scope = None;
    let database_runtime_endpoint_sha256 = None;
    let database_runtime_principal_sha256 = None;
    let migration_database_endpoint_sha256 = None;
    let migration_database_principal_sha256 = None;
    let database_backup_endpoint_sha256 = None;
    let database_backup_principal_sha256 = None;
    let valkey_runtime_principal_sha256 = None;
    let valkey_backup_endpoint_sha256 = None;
    let valkey_backup_principal_sha256 = None;
    let mut external_dependencies = false;
    let mut secrets_stdin = false;
    let mut secret_fd = None;
    let mut profile_secrets_stdin = false;
    let mut profile_secret_fd = None;
    let mut version = None;
    let mut candidate_image = None;
    let mut candidate_release = None;
    let mut candidate_revision = None;
    let mut candidate_build_id = None;
    let mut candidate_oci_digest = None;
    let mut seen_options = BTreeSet::new();
    let mut index = 0;
    while index < values.len() {
        let flag = values[index].as_str();
        if !seen_options.insert(flag) {
            bail!("{flag} may be supplied only once");
        }
        if flag == "--external-dependencies" {
            external_dependencies = true;
            index += 1;
            continue;
        }
        if flag == "--secrets-stdin" {
            secrets_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--profile-secrets-stdin" {
            profile_secrets_stdin = true;
            index += 1;
            continue;
        }
        let value = values
            .get(index + 1)
            .with_context(|| format!("{flag} requires a value"))?
            .clone();
        match flag {
            "--runtime" => runtime = value,
            "--public-url" => public_url = value,
            "--profile" => profile = value,
            "--profile-material" => profile_material = Some(PathBuf::from(value)),
            "--trusted-proxy-cidr" => {
                if trusted_proxy_cidr.is_some() {
                    bail!("--trusted-proxy-cidr may be supplied only once");
                }
                trusted_proxy_cidr = Some(normalize_single_host_cidr(&value)?);
            }
            "--data-root" => data_root = PathBuf::from(value),
            "--control-root" => control_root = PathBuf::from(value),
            "--recovery-root" => recovery_root = PathBuf::from(value),
            "--port" => {
                port = value
                    .parse()
                    .context("--port must be an integer from 1 through 65535")?;
                if port == 0 {
                    bail!("--port must be an integer from 1 through 65535");
                }
            }
            "--network-subnet" => {
                validate_network_subnet(&value)?;
                network_subnet = Some(value);
            }
            "--runtime-ip" => {
                value
                    .parse::<std::net::IpAddr>()
                    .context("--runtime-ip must be an IPv4 or IPv6 address")?;
                runtime_ip = Some(value);
            }
            "--secret-fd" => {
                if secret_fd.is_some() {
                    bail!("--secret-fd may be supplied only once");
                }
                secret_fd = Some(parse_secret_fd(&value, "--secret-fd")?);
            }
            "--profile-secret-fd" => {
                if profile_secret_fd.is_some() {
                    bail!("--profile-secret-fd may be supplied only once");
                }
                profile_secret_fd = Some(parse_secret_fd(&value, "--profile-secret-fd")?);
            }
            "--to" => {
                validate_version(&value)?;
                version = Some(value);
            }
            "--candidate-image" => candidate_image = Some(validate_local_oci_image(&value)?),
            "--candidate-release" => candidate_release = Some(value),
            "--candidate-revision" => candidate_revision = Some(value),
            "--candidate-build-id" => candidate_build_id = Some(value),
            "--candidate-oci-digest" => candidate_oci_digest = Some(value),
            other => bail!("unknown install option {other}"),
        }
        index += 2;
    }
    if !matches!(runtime.as_str(), "auto" | "podman" | "docker" | "host") {
        bail!("--runtime must be auto, podman, docker, or host");
    }
    if !matches!(profile.as_str(), "baseline" | "standards-full") {
        bail!("--profile must be baseline or standards-full");
    }
    if profile == "standards-full" && profile_material.is_none() {
        bail!("--profile standards-full requires --profile-material PATH");
    }
    if profile == "standards-full" && trusted_proxy_cidr.is_none() {
        bail!("--profile standards-full requires --trusted-proxy-cidr HOST/32 or HOST/128");
    }
    if profile == "baseline" && profile_material.is_some() {
        bail!("--profile-material is accepted only with --profile standards-full");
    }
    if profile == "baseline" && trusted_proxy_cidr.is_some() {
        bail!("--trusted-proxy-cidr is accepted only with --profile standards-full");
    }
    if profile != "standards-full" && (profile_secrets_stdin || profile_secret_fd.is_some()) {
        bail!("secure profile secret input requires --profile standards-full");
    }
    if network_subnet.is_some() != runtime_ip.is_some() {
        bail!("--network-subnet and --runtime-ip must be supplied together");
    }
    if let (Some(subnet), Some(address)) = (&network_subnet, &runtime_ip) {
        validate_network_assignment(subnet, address)?;
    }
    if runtime == "host" && network_subnet.is_some() {
        bail!("container network options are unavailable with --runtime host");
    }
    let local_oci_candidate = parse_local_oci_candidate(
        candidate_image,
        candidate_release,
        candidate_revision,
        candidate_build_id,
        candidate_oci_digest,
    )?;
    if local_oci_candidate.is_some() {
        if runtime == "host" {
            bail!("a local OCI candidate install requires --runtime auto, podman, or docker");
        }
        if version.is_some() {
            bail!("--to cannot be combined with a local OCI candidate install");
        }
        if external_dependencies {
            bail!(
                "a local OCI candidate install is managed-only and rejects --external-dependencies"
            );
        }
    }
    public_url = normalize_public_url_for_profile(&public_url, &profile)?;
    Ok(InstallOptions {
        runtime,
        public_url,
        profile,
        profile_material,
        trusted_proxy_cidr,
        data_root,
        control_root,
        recovery_root,
        port,
        network_subnet,
        runtime_ip,
        database_url,
        migration_database_url,
        database_backup_url,
        valkey_url,
        valkey_backup_url,
        external_valkey_backup_scope,
        database_runtime_endpoint_sha256,
        database_runtime_principal_sha256,
        migration_database_endpoint_sha256,
        migration_database_principal_sha256,
        database_backup_endpoint_sha256,
        database_backup_principal_sha256,
        valkey_runtime_principal_sha256,
        valkey_backup_endpoint_sha256,
        valkey_backup_principal_sha256,
        external_dependencies,
        secrets_stdin,
        secret_fd,
        profile_secrets_stdin,
        profile_secret_fd,
        profile_secrets: None,
        version,
        local_oci_candidate,
    })
}

fn parse_local_oci_candidate(
    image: Option<String>,
    release: Option<String>,
    revision: Option<String>,
    build_id: Option<String>,
    oci_digest: Option<String>,
) -> anyhow::Result<Option<LocalOciCandidateInstall>> {
    let values_present = [
        image.as_ref(),
        release.as_ref(),
        revision.as_ref(),
        build_id.as_ref(),
        oci_digest.as_ref(),
    ]
    .into_iter()
    .filter(Option::is_some)
    .count();
    if values_present == 0 {
        return Ok(None);
    }
    if values_present != 5 {
        bail!(
            "local OCI candidate install requires --candidate-image plus --candidate-release, --candidate-revision, --candidate-build-id, and --candidate-oci-digest"
        );
    }
    let release = release.expect("checked candidate release");
    if !crate::model::semantic_tag(&release) {
        bail!("--candidate-release must be a canonical v-prefixed semantic version");
    }
    let candidate_version = semver::Version::parse(release.trim_start_matches('v'))
        .context("--candidate-release must be a prerelease semantic version")?;
    if candidate_version.pre.is_empty() {
        bail!("--candidate-release must be a prerelease semantic version");
    }
    let revision = revision.expect("checked candidate revision");
    if revision.len() != 40
        || !revision
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        bail!("--candidate-revision must be a full lowercase Git commit SHA");
    }
    let build_id = build_id.expect("checked candidate build ID");
    if build_id != format!("source:{revision}") {
        bail!("local OCI candidate --candidate-build-id must be source:<full-revision>");
    }
    let oci_digest = oci_digest.expect("checked candidate OCI digest");
    if !oci_digest.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    }) {
        bail!("--candidate-oci-digest must be a lowercase sha256 digest");
    }
    Ok(Some(LocalOciCandidateInstall {
        image: image.expect("checked candidate image"),
        target: CandidateTarget {
            release,
            revision,
            build_id,
            oci_digest,
        },
    }))
}

fn validate_local_oci_image(value: &str) -> anyhow::Result<String> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:/@+-".contains(character))
    {
        bail!("--candidate-image must be a safe local OCI image reference");
    }
    Ok(value.to_owned())
}

fn validate_network_subnet(value: &str) -> anyhow::Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let address: std::net::IpAddr = address
        .parse()
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let prefix: u8 = prefix
        .parse()
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        bail!("--network-subnet must be an IPv4 or IPv6 CIDR");
    }
    Ok(())
}

fn validate_network_assignment(subnet: &str, address: &str) -> anyhow::Result<()> {
    let (network, prefix) = subnet
        .split_once('/')
        .context("--network-subnet must be an IPv4 or IPv6 CIDR")?;
    let network: std::net::IpAddr = network.parse()?;
    let address: std::net::IpAddr = address.parse()?;
    let prefix: u8 = prefix.parse()?;
    let contains = match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    };
    if !contains {
        bail!("--runtime-ip must belong to --network-subnet");
    }
    Ok(())
}

fn parse_secret_fd(value: &str, flag: &str) -> anyhow::Result<u32> {
    let fd: u32 = value
        .parse()
        .with_context(|| format!("{flag} must be an integer >= 3"))?;
    if fd < 3 {
        bail!("{flag} must be an integer >= 3");
    }
    Ok(fd)
}
