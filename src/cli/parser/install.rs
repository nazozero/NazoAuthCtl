use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, bail};

use super::super::types::InstallOptions;
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
    let valkey_url = None;
    let mut external_dependencies = false;
    let mut secrets_stdin = false;
    let mut secret_fd = None;
    let mut profile_secrets_stdin = false;
    let mut profile_secret_fd = None;
    let mut version = None;
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
        valkey_url,
        external_dependencies,
        secrets_stdin,
        secret_fd,
        profile_secrets_stdin,
        profile_secret_fd,
        profile_secrets: None,
        version,
    })
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
