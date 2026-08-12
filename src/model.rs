use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use crate::deployment::{Capability, CapabilityGrants, TrustState};
use anyhow::{Context, bail};
pub(crate) use nazoauthctl_runtime::runtime_backend::safe_systemd_path;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateConfig {
    pub(crate) schema: u32,
    pub(crate) trust: TrustState,
    pub(crate) capabilities: CapabilityGrants,
    #[serde(default = "baseline_install_profile")]
    pub(crate) install_profile: String,
    pub(crate) repository: String,
    pub(crate) backup_root: PathBuf,
    pub(crate) deployment_root: PathBuf,
    pub(crate) operator: Operator,
    #[serde(default)]
    pub(crate) dependencies: Dependencies,
    pub(crate) runtime: Runtime,
    pub(crate) postgres: Postgres,
    pub(crate) valkey: Valkey,
    pub(crate) ui: Ui,
}

fn baseline_install_profile() -> String {
    "baseline".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operator {
    pub(crate) deployment_id: String,
    pub(crate) controller_key_id: String,
    pub(crate) controller_private_key: PathBuf,
    pub(crate) controller_public_key: PathBuf,
    pub(crate) receipt_key_id: String,
    pub(crate) receipt_private_key: PathBuf,
    pub(crate) receipt_public_key: PathBuf,
    pub(crate) audit_key_id: String,
    pub(crate) audit_private_key: PathBuf,
    pub(crate) audit_public_key: PathBuf,
    pub(crate) break_glass_key_id: String,
    pub(crate) break_glass_private_key: PathBuf,
    pub(crate) break_glass_public_key: PathBuf,
    /// The single durable authority for the active controller/audit/recovery
    /// generation.  Older installations do not have it; ctl adopts their
    /// complete legacy keyset before doing any new rotation.
    #[serde(default)]
    pub(crate) active_identity_file: PathBuf,
    #[serde(default)]
    pub(crate) identity_generations_directory: PathBuf,
    #[serde(default)]
    pub(crate) recovery_generations_directory: PathBuf,
    pub(crate) secret_revision_file: PathBuf,
    pub(crate) state_directory: PathBuf,
    pub(crate) audit_directory: PathBuf,
    pub(crate) trust_state_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependencies {
    #[serde(default = "default_dependency_mode")]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) database_url_file: PathBuf,
    #[serde(default)]
    pub(crate) migration_database_url_file: PathBuf,
    #[serde(default)]
    pub(crate) valkey_url_file: PathBuf,
}

fn default_dependency_mode() -> String {
    "managed".to_owned()
}

impl Default for Dependencies {
    fn default() -> Self {
        Self {
            mode: default_dependency_mode(),
            database_url_file: PathBuf::new(),
            migration_database_url_file: PathBuf::new(),
            valkey_url_file: PathBuf::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    #[serde(alias = "engine")]
    pub(crate) backend: crate::deployment::RuntimeBackendKind,
    #[serde(
        default,
        alias = "dependency_engine",
        deserialize_with = "deserialize_optional_backend"
    )]
    pub(crate) dependency_backend: Option<crate::deployment::RuntimeBackendKind>,
    #[serde(skip)]
    pub(crate) backend_command_override: Option<PathBuf>,
    pub(crate) container_name: String,
    pub(crate) runtime_instance_id: String,
    pub(crate) network: String,
    #[serde(default)]
    pub(crate) network_subnet: Option<String>,
    #[serde(default)]
    pub(crate) ip_address: String,
    #[serde(default)]
    pub(crate) publish_address: String,
    pub(crate) health_url: String,
    pub(crate) readiness_attempts: u32,
    pub(crate) readiness_interval_seconds: u64,
    pub(crate) public_discovery_url: String,
    pub(crate) expected_issuer: String,
    #[serde(default)]
    pub(crate) mounts: Vec<Mount>,
    #[serde(default)]
    pub(crate) snapshot_paths: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) service_name: String,
    #[serde(default)]
    pub(crate) service_user: String,
    #[serde(default)]
    pub(crate) binary_path: PathBuf,
    #[serde(default)]
    pub(crate) binary_releases: PathBuf,
    #[serde(default)]
    pub(crate) working_directory: PathBuf,
}

fn deserialize_optional_backend<'de, D>(
    deserializer: D,
) -> Result<Option<crate::deployment::RuntimeBackendKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref() {
        None | Some("") => Ok(None),
        Some("podman") => Ok(Some(crate::deployment::RuntimeBackendKind::Podman)),
        Some("docker") => Ok(Some(crate::deployment::RuntimeBackendKind::Docker)),
        Some("systemd" | "host") => Ok(Some(crate::deployment::RuntimeBackendKind::Systemd)),
        Some(value) => Err(D::Error::custom(format!(
            "unsupported dependency runtime backend {value}"
        ))),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mount {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) read_only: bool,
    pub(crate) selinux_relabel: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Postgres {
    pub(crate) container_name: String,
    pub(crate) database: String,
    pub(crate) user: String,
    #[serde(default)]
    pub(crate) image: String,
    pub(crate) validation_image: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Valkey {
    pub(crate) container_name: String,
    pub(crate) data_volume: String,
    #[serde(default)]
    pub(crate) image: String,
    pub(crate) rdb_path: String,
    #[serde(default)]
    pub(crate) password_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ui {
    pub(crate) releases_root: PathBuf,
}

impl UpdateConfig {
    pub(crate) fn require_managed_lifecycle(&self) -> anyhow::Result<()> {
        use crate::deployment::Capability;

        if self.trust != TrustState::Adopted {
            bail!("deployment is not adopted");
        }
        let denied = [
            Capability::Runtime,
            Capability::Artifact,
            Capability::Backups,
        ]
        .into_iter()
        .filter(|capability| {
            !self
                .capabilities
                .grant(*capability)
                .responsibility
                .permits_mutation()
        })
        .map(Capability::name)
        .collect::<Vec<_>>();
        if !denied.is_empty() {
            bail!(
                "lifecycle operation exceeds granted capabilities: {}",
                denied.join(", ")
            );
        }
        Ok(())
    }

    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let config: Self =
            serde_json::from_slice(bytes).context("update configuration is not valid JSON")?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != 2 {
            bail!("unsupported update config schema");
        }
        self.capabilities.validate()?;
        if self.trust == TrustState::Observed
            && Capability::ALL.iter().any(|capability| {
                self.capabilities
                    .grant(*capability)
                    .responsibility
                    .permits_mutation()
            })
        {
            bail!("observed update configuration cannot grant mutation capability");
        }
        if !matches!(self.install_profile.as_str(), "baseline" | "standards-full") {
            bail!("unsupported install profile {}", self.install_profile);
        }
        validate_public_runtime_urls(&self.runtime)?;
        let repository_parts = self.repository.split('/').collect::<Vec<_>>();
        if repository_parts.len() != 2 || repository_parts.iter().any(|part| !safe_identifier(part))
        {
            bail!("repository must be a safe owner/name pair");
        }
        if !matches!(self.dependencies.mode.as_str(), "managed" | "external") {
            bail!("dependency mode must be managed or external");
        }
        let mut runtime_names = Vec::new();
        if self.runtime.backend != crate::deployment::RuntimeBackendKind::Systemd {
            runtime_names.extend([&self.runtime.container_name, &self.runtime.network]);
        }
        if self.dependencies.mode == "managed" {
            runtime_names.extend([
                &self.postgres.container_name,
                &self.valkey.container_name,
                &self.valkey.data_volume,
            ]);
        }
        for name in runtime_names {
            if !safe_identifier(name) {
                bail!("runtime object name is unsafe: {name}");
            }
        }
        for path in [
            &self.backup_root,
            &self.deployment_root,
            &self.ui.releases_root,
            &self.operator.controller_private_key,
            &self.operator.controller_public_key,
            &self.operator.receipt_private_key,
            &self.operator.receipt_public_key,
            &self.operator.audit_private_key,
            &self.operator.audit_public_key,
            &self.operator.break_glass_private_key,
            &self.operator.break_glass_public_key,
            &self.operator.secret_revision_file,
            &self.operator.state_directory,
            &self.operator.audit_directory,
            &self.operator.trust_state_file,
        ] {
            safe_absolute(path)?;
        }
        for path in [
            &self.operator.active_identity_file,
            &self.operator.identity_generations_directory,
            &self.operator.recovery_generations_directory,
        ] {
            if !path.as_os_str().is_empty() {
                safe_absolute(path)?;
            }
        }
        for identifier in [
            &self.operator.deployment_id,
            &self.runtime.runtime_instance_id,
            &self.operator.controller_key_id,
            &self.operator.receipt_key_id,
            &self.operator.audit_key_id,
            &self.operator.break_glass_key_id,
        ] {
            if !safe_identifier(identifier) {
                bail!("operator identity is unsafe");
            }
        }
        if self.runtime.backend == crate::deployment::RuntimeBackendKind::Systemd {
            for path in [
                &self.runtime.binary_path,
                &self.runtime.binary_releases,
                &self.runtime.working_directory,
            ] {
                safe_systemd_path(path)?;
            }
            if self.runtime.service_name.is_empty() || self.runtime.service_user.is_empty() {
                bail!("host runtime requires service_name and service_user");
            }
            if !safe_identifier(&self.runtime.service_name)
                || !safe_identifier(&self.runtime.service_user)
            {
                bail!("host service name or user is unsafe");
            }
        }
        if self.dependencies.mode == "external" {
            safe_absolute(&self.dependencies.database_url_file)?;
            safe_absolute(&self.dependencies.migration_database_url_file)?;
            safe_absolute(&self.dependencies.valkey_url_file)?;
        }
        if self.runtime.readiness_attempts == 0 {
            bail!("readiness_attempts must be positive");
        }
        for mount in &self.runtime.mounts {
            safe_absolute(&mount.source)?;
            safe_absolute(&mount.target)?;
        }
        for path in &self.runtime.snapshot_paths {
            safe_absolute(path)?;
        }
        for (key, value) in &self.runtime.environment {
            if !valid_environment_key(key) || !key.ends_with("_FILE") {
                bail!("runtime environment is limited to non-secret *_FILE locators");
            }
            safe_absolute(std::path::Path::new(value))?;
        }
        Ok(())
    }

    pub(crate) fn container_backend(&self) -> Option<crate::deployment::RuntimeBackendKind> {
        if self.runtime.backend == crate::deployment::RuntimeBackendKind::Systemd {
            self.runtime.dependency_backend
        } else {
            Some(self.runtime.backend)
        }
        .filter(|backend| *backend != crate::deployment::RuntimeBackendKind::Systemd)
    }
}

fn validate_public_runtime_urls(runtime: &Runtime) -> anyhow::Result<()> {
    let issuer = parse_public_origin(&runtime.expected_issuer, "expected issuer")?;
    let health =
        Url::parse(&runtime.health_url).context("health URL must be an absolute HTTP(S) URL")?;
    validate_health_url(&health, &issuer)?;
    let discovery = Url::parse(&runtime.public_discovery_url)
        .context("public Discovery URL must be an absolute URL")?;
    validate_public_transport(&discovery, "public Discovery URL")?;
    if !discovery.username().is_empty()
        || discovery.password().is_some()
        || discovery.query().is_some()
        || discovery.fragment().is_some()
    {
        bail!("public Discovery URL must not contain credentials, query, or fragment");
    }
    if discovery.origin() != issuer.origin()
        || discovery.path() != "/.well-known/openid-configuration"
    {
        bail!("public Discovery URL must be the expected issuer origin's OIDC Discovery endpoint");
    }
    Ok(())
}

fn validate_health_url(health: &Url, issuer: &Url) -> anyhow::Result<()> {
    validate_public_transport(health, "health URL")?;
    if !health.username().is_empty()
        || health.password().is_some()
        || health.query().is_some()
        || health.fragment().is_some()
    {
        bail!("health URL must not contain credentials, query, or fragment");
    }
    let loopback = health.host().is_some_and(|host| match host {
        Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    });
    if !loopback && health.origin() != issuer.origin() {
        bail!("health URL must be loopback or share the expected issuer origin");
    }
    Ok(())
}

pub(crate) fn parse_public_origin(value: &str, label: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| format!("{label} must be an absolute URL"))?;
    validate_public_transport(&url, label)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("{label} must be an HTTP(S) origin without credentials, path, query, or fragment");
    }
    Ok(url)
}

fn validate_public_transport(url: &Url, label: &str) -> anyhow::Result<()> {
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        bail!("{label} must use HTTP(S) and include a host");
    }
    if url.scheme() == "http"
        && !url.host().is_some_and(|host| match host {
            Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        })
    {
        bail!("{label} must use HTTPS outside localhost or loopback");
    }
    Ok(())
}

pub(crate) fn safe_absolute(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!(
            "path must be a normalized absolute non-root path: {}",
            path.display()
        );
    }
    Ok(())
}

fn valid_environment_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('A'..='Z' | '_'))
        && chars.all(|character| matches!(character, 'A'..='Z' | '0'..='9' | '_'))
}

fn safe_identifier(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn safe_protocol_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseManifest {
    pub(crate) schema: u32,
    pub(crate) version: String,
    pub(crate) target: String,
    pub(crate) backend_commit: String,
    pub(crate) release_identity: String,
    pub(crate) embedded: nazo_operator_protocol::EmbeddedIdentity,
    #[serde(default)]
    pub(crate) operator_protocol: Option<OperatorProtocolCompatibility>,
    pub(crate) artifacts: BTreeMap<String, Artifact>,
    pub(crate) frontend: FrontendRelease,
    pub(crate) oci: OciRelease,
    pub(crate) rollback: Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorProtocolCompatibility {
    pub(crate) version: u32,
    pub(crate) minimum_ctl_version: String,
    pub(crate) maximum_ctl_version_exclusive: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) repository: String,
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrontendRelease {
    pub(crate) repository: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) release_identity: String,
    pub(crate) artifact: Artifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OciRelease {
    pub(crate) repository: String,
    pub(crate) index_digest: String,
    pub(crate) platform_manifests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollback {
    pub(crate) artifact: bool,
    pub(crate) schema_compatible: bool,
    pub(crate) database_restore: DatabaseRestore,
    pub(crate) irreversible_migration: bool,
    pub(crate) minimum_supported_version: String,
    pub(crate) migration_floor: String,
    pub(crate) rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DatabaseRestore {
    Backup,
    Pitr,
    None,
}

impl ReleaseManifest {
    pub(crate) fn validate(&self, version: &str, expected_identity: &str) -> anyhow::Result<()> {
        let target = release_target().context("this platform has no official Release target")?;
        if !matches!(self.schema, 4 | 5)
            || self.version != version
            || self.target != target
            || self.release_identity != expected_identity
            || self.embedded.release != self.version
            || self.embedded.revision != self.backend_commit
            || self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION
            || !safe_protocol_identifier(&self.embedded.build_id)
            || !is_lower_hex(&self.backend_commit, 40)
        {
            bail!("signed release manifest failed policy validation");
        }
        match (self.schema, &self.operator_protocol) {
            (4, None) => {}
            (5, Some(protocol)) if protocol.version == self.embedded.protocol => {}
            _ => bail!("signed release manifest has an invalid operator protocol contract"),
        }
        if self.rollback.rationale.trim().is_empty()
            || !semantic_tag(&format!("v{}", self.rollback.minimum_supported_version))
            || !self
                .rollback
                .migration_floor
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            bail!("signed release manifest has invalid recovery policy");
        }
        if self.rollback.irreversible_migration && self.rollback.schema_compatible {
            bail!("irreversible migrations cannot claim schema-compatible rollback");
        }
        if self.rollback.schema_compatible && !self.rollback.artifact {
            bail!("schema-compatible rollback requires a retained artifact");
        }
        let expected = if self.schema == 4 {
            BTreeSet::from(["binary".to_owned(), "updater".to_owned()])
        } else {
            BTreeSet::from(["binary".to_owned()])
        };
        if self.artifacts.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("signed release manifest has an unexpected artifact set");
        }
        let executable_suffix = executable_suffix(&self.target);
        let expected_binary = format!("nazoauth-{}{executable_suffix}", self.target);
        if self.artifacts["binary"].name != expected_binary {
            bail!("signed release manifest artifact does not match its target");
        }
        if self.schema == 4 {
            let expected_updater = format!("nazoauthctl-{}{executable_suffix}", self.target);
            if self.artifacts["updater"].name != expected_updater {
                bail!("signed release manifest artifact does not match its target");
            }
        }
        for artifact in self.artifacts.values() {
            if artifact.size == 0
                || artifact.repository != "nazozero/NazoAuth"
                || !safe_artifact_name(&artifact.name)
                || !is_lower_hex(&artifact.sha256, 64)
            {
                bail!("signed release manifest contains an invalid artifact");
            }
        }
        self.validate_frontend()?;
        self.validate_oci()?;
        Ok(())
    }

    pub(crate) fn validate_controller_compatibility(&self) -> anyhow::Result<()> {
        if self.schema == 4 {
            if !matches!(self.version.as_str(), "v0.1.18" | "v0.1.19")
                || self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION
            {
                bail!("legacy server Release is outside the closed extraction baseline");
            }
            return Ok(());
        }
        let protocol = self
            .operator_protocol
            .as_ref()
            .context("server Release has no operator protocol compatibility contract")?;
        if protocol.version != nazo_operator_protocol::PROTOCOL_VERSION {
            bail!("server Release operator protocol version is unsupported");
        }
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        let minimum = semver::Version::parse(&protocol.minimum_ctl_version)
            .context("server Release minimum ctl version is invalid")?;
        let maximum = semver::Version::parse(&protocol.maximum_ctl_version_exclusive)
            .context("server Release maximum ctl version is invalid")?;
        if minimum >= maximum || current < minimum || current >= maximum {
            bail!("controller version is outside the server Release compatibility range");
        }
        Ok(())
    }

    pub(crate) fn image_ref(&self) -> anyhow::Result<String> {
        Ok(format!(
            "{}@{}",
            self.oci.repository,
            self.runtime_oci_digest()?
        ))
    }

    pub(crate) fn image_oci_digest(&self) -> &str {
        &self.oci.index_digest
    }

    pub(crate) fn runtime_oci_digest(&self) -> anyhow::Result<&str> {
        let platform = runtime_oci_platform(std::env::consts::OS, std::env::consts::ARCH)?;
        self.oci
            .platform_manifests
            .get(platform)
            .map(String::as_str)
            .context("signed Release has no manifest for this OCI platform")
    }

    pub(crate) fn frontend_commit(&self) -> &str {
        &self.frontend.commit
    }

    fn validate_frontend(&self) -> anyhow::Result<()> {
        let frontend = &self.frontend;
        let expected_identity = format!(
            "https://github.com/{}/.github/workflows/release.yml@refs/tags/{}",
            frontend.repository, frontend.version
        );
        if frontend.repository != "nazozero/NazoAuthWeb"
            || !semantic_tag(&frontend.version)
            || !is_lower_hex(&frontend.commit, 40)
            || frontend.release_identity != expected_identity
            || frontend.artifact.repository != frontend.repository
            || frontend.artifact.name != "nazoauth-web.tar.gz"
            || frontend.artifact.size == 0
            || frontend.artifact.size > 64 * 1024 * 1024
            || !is_lower_hex(&frontend.artifact.sha256, 64)
        {
            bail!("signed release manifest contains an invalid frontend release");
        }
        Ok(())
    }

    fn validate_oci(&self) -> anyhow::Result<()> {
        let expected_platforms =
            BTreeSet::from(["linux/amd64".to_owned(), "linux/arm64".to_owned()]);
        if self.oci.repository != "ghcr.io/nazozero/nazoauth"
            || !oci_digest(&self.oci.index_digest)
            || self
                .oci
                .platform_manifests
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != expected_platforms
            || self
                .oci
                .platform_manifests
                .values()
                .any(|digest| !oci_digest(digest))
        {
            bail!("signed release manifest contains an invalid OCI index");
        }
        Ok(())
    }
}

fn executable_suffix(target: &str) -> &'static str {
    if target.contains("windows") {
        ".exe"
    } else {
        ""
    }
}

fn runtime_oci_platform(os: &str, arch: &str) -> anyhow::Result<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("linux/amd64"),
        ("linux", "aarch64") => Ok("linux/arm64"),
        _ => bail!("managed OCI runtime is supported only on Linux x86-64 and Arm64"),
    }
}

pub(crate) fn release_target() -> Option<&'static str> {
    let target_env = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else {
        ""
    };
    release_target_for(std::env::consts::ARCH, std::env::consts::OS, target_env)
}

fn release_target_for(arch: &str, os: &str, target_env: &str) -> Option<&'static str> {
    match (arch, os, target_env) {
        ("x86_64", "linux", "musl") => Some("x86_64-unknown-linux-musl"),
        ("aarch64", "linux", "musl") => Some("aarch64-unknown-linux-musl"),
        ("x86_64", "linux", _) => Some("x86_64-unknown-linux-gnu"),
        ("aarch64", "linux", _) => Some("aarch64-unknown-linux-gnu"),
        ("x86_64", "windows", _) => Some("x86_64-pc-windows-msvc"),
        ("aarch64", "windows", _) => Some("aarch64-pc-windows-msvc"),
        ("x86_64", "macos", _) => Some("x86_64-apple-darwin"),
        ("aarch64", "macos", _) => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

fn oci_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

pub(crate) fn semantic_tag(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(rest).is_ok_and(|parsed| parsed.to_string() == rest)
}

fn safe_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
