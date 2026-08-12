use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_operator_protocol::{
    CONTROL_DISCOVERY_SCHEMA, DeploymentStatement, DiscoveryRequest, DiscoveryResponse,
    DiscoveryStatement, decode_instance_public_key, protected_header, verify_deployment_statement,
    verify_discovery_statement,
};
use serde::{Deserialize, Serialize};

use crate::{
    deployment::{ArtifactReference, RecoveryConclusion, RuntimeBackendKind},
    filesystem::read_secure_regular_file,
    process::Process,
    runtime_backend::{RuntimeObservation, installed_backends},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiscoveryReport {
    pub(crate) schema: u32,
    pub(crate) read_only: bool,
    pub(crate) ambiguous: bool,
    pub(crate) candidates: Vec<DiscoveredDeployment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiscoveredDeployment {
    pub(crate) target: String,
    pub(crate) deployment_id: Option<String>,
    pub(crate) runtime_instance_id: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) release: Option<String>,
    pub(crate) revision: Option<String>,
    pub(crate) build_id: Option<String>,
    pub(crate) instance_key_id: Option<String>,
    pub(crate) control_protocol_versions: Vec<u32>,
    pub(crate) operator_protocol_versions: Vec<u32>,
    pub(crate) runtime: RuntimeObservation,
    pub(crate) online_statement: Option<DiscoveryStatement>,
    pub(crate) offline_statement: Option<DeploymentStatement>,
    pub(crate) oidc_discovery_verified: bool,
    pub(crate) readiness_observed: bool,
    pub(crate) external_database: bool,
    pub(crate) external_valkey: bool,
    pub(crate) recovery_conclusion: RecoveryConclusion,
    pub(crate) evidence: Vec<String>,
    pub(crate) missing: Vec<String>,
    #[serde(skip)]
    pub(crate) sensitive_mount_sources: BTreeMap<PathBuf, PathBuf>,
}

/// The discovery report is public machine-readable output, while the full runtime observation is
/// an internal ownership/adoption record. Keep those contracts separate so arbitrary backend
/// labels and raw host mount paths cannot cross the output boundary; only the ownership label
/// allowlist and already-filtered safe environment metadata are displayed.
#[derive(Serialize)]
struct DisplayDiscoveredDeployment<'a> {
    target: &'a str,
    deployment_id: &'a Option<String>,
    runtime_instance_id: &'a Option<String>,
    issuer: &'a Option<String>,
    release: &'a Option<String>,
    revision: &'a Option<String>,
    build_id: &'a Option<String>,
    instance_key_id: &'a Option<String>,
    control_protocol_versions: &'a [u32],
    operator_protocol_versions: &'a [u32],
    runtime: DisplayRuntimeObservation<'a>,
    online_statement: &'a Option<DiscoveryStatement>,
    offline_statement: &'a Option<DeploymentStatement>,
    oidc_discovery_verified: bool,
    readiness_observed: bool,
    external_database: bool,
    external_valkey: bool,
    recovery_conclusion: &'a RecoveryConclusion,
    evidence: &'a [String],
    missing: &'a [String],
}

#[derive(Serialize)]
struct DisplayRuntimeObservation<'a> {
    backend: RuntimeBackendKind,
    object_reference: &'a str,
    display_name: &'a str,
    running: bool,
    server_command_verified: bool,
    artifact: &'a ArtifactReference,
    local_artifact_id: &'a Option<String>,
    ports: &'a [String],
    networks: &'a [String],
    mounts: Vec<DisplayMount>,
    safe_environment: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
    evidence: &'a [String],
    missing: &'a [String],
}

#[derive(Serialize)]
struct DisplayMount {
    source: &'static str,
    destination: String,
    read_only: bool,
    selinux_relabel: bool,
    ownership: crate::deployment::Responsibility,
    scope: crate::deployment::ResourceScope,
}

impl Serialize for DiscoveredDeployment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        DisplayDiscoveredDeployment {
            target: &self.target,
            deployment_id: &self.deployment_id,
            runtime_instance_id: &self.runtime_instance_id,
            issuer: &self.issuer,
            release: &self.release,
            revision: &self.revision,
            build_id: &self.build_id,
            instance_key_id: &self.instance_key_id,
            control_protocol_versions: &self.control_protocol_versions,
            operator_protocol_versions: &self.operator_protocol_versions,
            runtime: DisplayRuntimeObservation {
                backend: self.runtime.backend,
                object_reference: &self.runtime.object_reference,
                display_name: &self.runtime.display_name,
                running: self.runtime.running,
                server_command_verified: self.runtime.server_command_verified,
                artifact: &self.runtime.artifact,
                local_artifact_id: &self.runtime.local_artifact_id,
                ports: &self.runtime.ports,
                networks: &self.runtime.networks,
                mounts: self
                    .runtime
                    .mounts
                    .iter()
                    .map(|mount| DisplayMount {
                        source: "<redacted-mount-source>",
                        destination: mount.destination.display().to_string(),
                        read_only: mount.read_only,
                        selinux_relabel: mount.selinux_relabel,
                        ownership: mount.ownership,
                        scope: mount.scope,
                    })
                    .collect(),
                safe_environment: display_safe_environment(&self.runtime),
                labels: display_labels(&self.runtime),
                evidence: &self.runtime.evidence,
                missing: &self.runtime.missing,
            },
            online_statement: &self.online_statement,
            offline_statement: &self.offline_statement,
            oidc_discovery_verified: self.oidc_discovery_verified,
            readiness_observed: self.readiness_observed,
            external_database: self.external_database,
            external_valkey: self.external_valkey,
            recovery_conclusion: &self.recovery_conclusion,
            evidence: &self.evidence,
            missing: &self.missing,
        }
        .serialize(serializer)
    }
}

fn display_labels(runtime: &RuntimeObservation) -> BTreeMap<String, String> {
    const ALLOWED: [&str; 3] = [
        "io.nazoauth.deployment-id",
        "io.nazoauth.control-authority",
        "io.nazoauth.runtime-instance-id",
    ];
    runtime
        .labels
        .iter()
        .filter(|(name, _)| ALLOWED.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn display_safe_environment(runtime: &RuntimeObservation) -> BTreeMap<String, String> {
    const ALLOWED: [&str; 7] = [
        "ISSUER",
        "PUBLIC_BASE_URL",
        "DATA_DIR",
        "DEPLOYMENT_ID",
        "RUNTIME_INSTANCE_ID",
        "CONTROL_AUTHORITY",
        "INSTANCE_IDENTITY_DIR",
    ];
    runtime
        .safe_environment
        .iter()
        .filter(|(name, _)| ALLOWED.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub(crate) fn discover() -> anyhow::Result<DiscoveryReport> {
    let mut candidates = Vec::new();
    for backend in installed_backends() {
        for runtime in backend.discover()? {
            let mut candidate = enrich(runtime);
            candidate.sensitive_mount_sources = redact_secret_mount_sources(&mut candidate.runtime);
            candidates.push(candidate);
        }
    }
    Ok(finalize_report(candidates))
}

fn finalize_report(mut candidates: Vec<DiscoveredDeployment>) -> DiscoveryReport {
    candidates.sort_by(|left, right| left.target.cmp(&right.target));
    let ambiguous = candidates.len() > 1;
    DiscoveryReport {
        schema: 1,
        read_only: true,
        ambiguous,
        candidates,
    }
}

pub(crate) fn select(
    report: &DiscoveryReport,
    target: &str,
) -> anyhow::Result<DiscoveredDeployment> {
    let matches = report
        .candidates
        .iter()
        .filter(|candidate| candidate.target == target)
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [candidate] => Ok(candidate.clone()),
        [] => bail!("adoption target does not match a discovered runtime"),
        _ => bail!("adoption target is ambiguous"),
    }
}

fn enrich(runtime: RuntimeObservation) -> DiscoveredDeployment {
    let target = format!(
        "{}:{}",
        backend_name(runtime.backend),
        runtime.object_reference
    );
    let online = online_statement(&runtime).ok().flatten();
    let offline = offline_statement(&runtime).ok().flatten();
    let statements_consistent = match (online.as_ref(), offline.as_ref()) {
        (Some(online), Some(offline)) => statements_match(online, offline),
        _ => true,
    };
    let identity = statements_consistent
        .then(|| {
            online
                .as_ref()
                .map(IdentityStatement::Online)
                .or_else(|| offline.as_ref().map(IdentityStatement::Offline))
        })
        .flatten();
    let mut evidence = runtime.evidence.clone();
    let mut missing = runtime.missing.clone();
    if online.is_some() {
        evidence.push("nonce-bound NazoAuth control discovery signature verified".to_owned());
    } else {
        missing.push("online signed control discovery was not verified".to_owned());
    }
    if offline.is_some() {
        evidence.push(
            "offline deployment statement signature verified from a mounted data directory"
                .to_owned(),
        );
    } else {
        missing.push("offline signed deployment statement was not found".to_owned());
    }
    if !statements_consistent {
        missing.push("online and offline deployment identities conflict".to_owned());
    }
    let issuer = identity.as_ref().map(IdentityStatement::issuer);
    let (oidc_discovery_verified, readiness_observed) = issuer
        .and_then(|issuer| probe_public_service(issuer).ok())
        .unwrap_or((false, false));
    if oidc_discovery_verified {
        evidence.push("OIDC discovery issuer matches the signed deployment issuer".to_owned());
    } else {
        missing.push("OIDC Discovery issuer was not verified".to_owned());
    }
    if readiness_observed {
        evidence.push("readiness endpoint responded successfully".to_owned());
    } else {
        missing.push("readiness was not observed".to_owned());
    }
    let data_mounted = runtime.mounts.iter().any(|mount| {
        !mount.source.to_string_lossy().contains("redacted")
            && ["data", "runtime", "nazoauth"]
                .iter()
                .any(|name| mount.destination.to_string_lossy().contains(name))
    });
    let immutable_artifact = !matches!(runtime.artifact, ArtifactReference::Unknown);
    let recovery_conclusion = if offline.is_some() && data_mounted && immutable_artifact {
        // Release trust and a restorable backup are intentionally not inferred.
        RecoveryConclusion::RequiresUserEvidence
    } else {
        RecoveryConclusion::Unproven
    };
    let external_database = !runtime.mounts.iter().any(|mount| {
        mount
            .destination
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("postgres")
    });
    let external_valkey = !runtime.mounts.iter().any(|mount| {
        mount
            .destination
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("valkey")
            || mount
                .destination
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("redis")
    });
    DiscoveredDeployment {
        target,
        deployment_id: identity
            .as_ref()
            .map(IdentityStatement::deployment_id)
            .map(ToOwned::to_owned),
        runtime_instance_id: identity
            .as_ref()
            .map(IdentityStatement::runtime_instance_id)
            .map(ToOwned::to_owned),
        issuer: issuer.map(ToOwned::to_owned),
        release: identity
            .as_ref()
            .map(IdentityStatement::release)
            .map(ToOwned::to_owned),
        revision: identity
            .as_ref()
            .map(IdentityStatement::revision)
            .map(ToOwned::to_owned),
        build_id: identity
            .as_ref()
            .map(IdentityStatement::build_id)
            .map(ToOwned::to_owned),
        instance_key_id: identity
            .as_ref()
            .map(IdentityStatement::instance_key_id)
            .map(ToOwned::to_owned),
        control_protocol_versions: identity
            .as_ref()
            .map(IdentityStatement::control_versions)
            .unwrap_or_default(),
        operator_protocol_versions: identity
            .as_ref()
            .map(IdentityStatement::operator_versions)
            .unwrap_or_default(),
        runtime,
        online_statement: online,
        offline_statement: offline,
        oidc_discovery_verified,
        readiness_observed,
        external_database,
        external_valkey,
        recovery_conclusion,
        evidence,
        missing,
        sensitive_mount_sources: BTreeMap::new(),
    }
}

fn statements_match(online: &DiscoveryStatement, offline: &DeploymentStatement) -> bool {
    online.schema == offline.schema
        && online.product == offline.product
        && online.deployment_id == offline.deployment_id
        && online.runtime_instance_id == offline.runtime_instance_id
        && online.issuer == offline.issuer
        && online.release == offline.release
        && online.revision == offline.revision
        && online.build_id == offline.build_id
        && online.control_protocol_versions == offline.control_protocol_versions
        && online.operator_protocol_versions == offline.operator_protocol_versions
        && online.instance_key_id == offline.instance_key_id
}

enum IdentityStatement<'a> {
    Online(&'a DiscoveryStatement),
    Offline(&'a DeploymentStatement),
}

impl IdentityStatement<'_> {
    fn deployment_id(&self) -> &str {
        match self {
            Self::Online(value) => &value.deployment_id,
            Self::Offline(value) => &value.deployment_id,
        }
    }
    fn runtime_instance_id(&self) -> &str {
        match self {
            Self::Online(value) => &value.runtime_instance_id,
            Self::Offline(value) => &value.runtime_instance_id,
        }
    }
    fn issuer(&self) -> &str {
        match self {
            Self::Online(value) => &value.issuer,
            Self::Offline(value) => &value.issuer,
        }
    }
    fn release(&self) -> &str {
        match self {
            Self::Online(value) => &value.release,
            Self::Offline(value) => &value.release,
        }
    }
    fn revision(&self) -> &str {
        match self {
            Self::Online(value) => &value.revision,
            Self::Offline(value) => &value.revision,
        }
    }
    fn build_id(&self) -> &str {
        match self {
            Self::Online(value) => &value.build_id,
            Self::Offline(value) => &value.build_id,
        }
    }
    fn instance_key_id(&self) -> &str {
        match self {
            Self::Online(value) => &value.instance_key_id,
            Self::Offline(value) => &value.instance_key_id,
        }
    }
    fn control_versions(&self) -> Vec<u32> {
        match self {
            Self::Online(value) => value.control_protocol_versions.clone(),
            Self::Offline(value) => value.control_protocol_versions.clone(),
        }
    }
    fn operator_versions(&self) -> Vec<u32> {
        match self {
            Self::Online(value) => value.operator_protocol_versions.clone(),
            Self::Offline(value) => value.operator_protocol_versions.clone(),
        }
    }
}

fn online_statement(runtime: &RuntimeObservation) -> anyhow::Result<Option<DiscoveryStatement>> {
    if !runtime.running {
        return Ok(None);
    }
    let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let request = serde_json::to_string(&DiscoveryRequest {
        schema: CONTROL_DISCOVERY_SCHEMA,
        nonce: nonce.clone(),
    })?;
    for endpoint in direct_endpoints(runtime) {
        let output = Process::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "--connect-timeout",
                "2",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                &request,
                &format!("{endpoint}/.well-known/nazoauth-control"),
            ])
            .stdout();
        let Ok(output) = output else { continue };
        if output.len() > 64 * 1024 {
            continue;
        }
        let Ok(response) = serde_json::from_str::<DiscoveryResponse>(&output) else {
            continue;
        };
        let Ok(public_key) = decode_instance_public_key(&response.instance_public_key) else {
            continue;
        };
        let Ok(header) = protected_header(&response.statement) else {
            continue;
        };
        let Ok(statement) = verify_discovery_statement(
            &response.statement,
            &header.kid,
            &public_key,
            &nonce,
            Utc::now().timestamp(),
        ) else {
            continue;
        };
        return Ok(Some(statement));
    }
    Ok(None)
}

fn offline_statement(runtime: &RuntimeObservation) -> anyhow::Result<Option<DeploymentStatement>> {
    let data_dir = runtime.safe_environment.get("DATA_DIR").map(PathBuf::from);
    let identity_dir = runtime
        .safe_environment
        .get("INSTANCE_IDENTITY_DIR")
        .map(PathBuf::from)
        .or_else(|| data_dir.map(|path| path.join("instance")));
    let Some(identity_dir) = identity_dir else {
        return Ok(None);
    };
    let Some(host_identity_dir) = map_runtime_path(runtime, &identity_dir) else {
        return Ok(None);
    };
    let statement_path = host_identity_dir.join("deployment-statement.jws");
    let public_key_path = host_identity_dir.join("identity.pub");
    let statement = read_bounded(&statement_path, 64 * 1024)?;
    let public_key = read_bounded(&public_key_path, 1024)?;
    let public_key = decode_instance_public_key(public_key.trim())?;
    let header = protected_header(statement.trim())?;
    Ok(Some(verify_deployment_statement(
        statement.trim(),
        &header.kid,
        &public_key,
    )?))
}

fn map_runtime_path(runtime: &RuntimeObservation, runtime_path: &Path) -> Option<PathBuf> {
    if runtime.backend == RuntimeBackendKind::Systemd {
        return Some(runtime_path.to_owned());
    }
    runtime.mounts.iter().find_map(|mount| {
        let relative = runtime_path.strip_prefix(&mount.destination).ok()?;
        Some(mount.source.join(relative))
    })
}

pub(crate) fn deployment_statement_path(candidate: &DiscoveredDeployment) -> Option<PathBuf> {
    let data_dir = candidate
        .runtime
        .safe_environment
        .get("DATA_DIR")
        .map(PathBuf::from);
    let identity_dir = candidate
        .runtime
        .safe_environment
        .get("INSTANCE_IDENTITY_DIR")
        .map(PathBuf::from)
        .or_else(|| data_dir.map(|path| path.join("instance")))?;
    if candidate.runtime.backend == RuntimeBackendKind::Systemd {
        return Some(identity_dir.join("deployment-statement.jws"));
    }
    candidate
        .sensitive_mount_sources
        .iter()
        .find_map(|(destination, source)| {
            let relative = identity_dir.strip_prefix(destination).ok()?;
            Some(source.join(relative).join("deployment-statement.jws"))
        })
        .or_else(|| {
            map_runtime_path(&candidate.runtime, &identity_dir)
                .map(|path| path.join("deployment-statement.jws"))
        })
}

fn read_bounded(path: &Path, maximum: u64) -> anyhow::Result<String> {
    let bytes = read_secure_regular_file(path, "discovery evidence", false, maximum)?;
    String::from_utf8(bytes.to_vec()).context("discovery evidence is not valid UTF-8")
}

fn direct_endpoints(runtime: &RuntimeObservation) -> Vec<String> {
    runtime
        .ports
        .iter()
        .filter_map(|binding| binding.split_once("->").map(|(host, _)| host))
        .filter_map(|host| {
            let (address, port) = host.rsplit_once(':')?;
            let address = match address {
                "" | "0.0.0.0" | "::" => "127.0.0.1",
                value => value,
            };
            Some(format!("http://{address}:{port}"))
        })
        .collect()
}

fn probe_public_service(issuer: &str) -> anyhow::Result<(bool, bool)> {
    let issuer_url = crate::model::parse_public_origin(issuer, "discovered issuer")?;
    let issuer = issuer_url.as_str().trim_end_matches('/');
    let discovery = Process::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=http,https",
            "--max-time",
            "3",
            &format!("{issuer}/.well-known/openid-configuration"),
        ])
        .stdout()?;
    let document: serde_json::Value = serde_json::from_str(&discovery)?;
    let issuer_matches = document.get("issuer").and_then(serde_json::Value::as_str) == Some(issuer);
    let ready = Process::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=http,https",
            "--max-time",
            "3",
            &format!("{issuer}/ready"),
        ])
        .succeeds();
    Ok((issuer_matches, ready))
}

fn redact_secret_mount_sources(runtime: &mut RuntimeObservation) -> BTreeMap<PathBuf, PathBuf> {
    let mut sensitive = BTreeMap::new();
    for mount in &mut runtime.mounts {
        let destination = mount.destination.to_string_lossy().to_ascii_lowercase();
        if ["secret", "credential", "token", "private", "identity.key"]
            .iter()
            .any(|marker| destination.contains(marker))
        {
            sensitive.insert(mount.destination.clone(), mount.source.clone());
            mount.source = PathBuf::from("<redacted-secret-source>");
        }
    }
    sensitive
}

fn backend_name(backend: RuntimeBackendKind) -> &'static str {
    match backend {
        RuntimeBackendKind::Podman => "podman",
        RuntimeBackendKind::Docker => "docker",
        RuntimeBackendKind::Systemd => "systemd",
    }
}

#[cfg(test)]
#[path = "../tests/unit/discovery.rs"]
mod tests;
