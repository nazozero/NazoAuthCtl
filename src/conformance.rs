use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

use crate::{filesystem::ensure_private_directory, registry::RegistryStore};

const MAX_PROFILE_TOKEN_BYTES: u64 = 4 * 1024;
const DYNAMIC_REGISTRATION_TOKEN_NAME: &str = "dynamic-registration-token";
const CIBA_DECISION_TOKEN_NAME: &str = "ciba-decision-token";
const OPENID4VP_MANAGEMENT_TOKEN_NAME: &str = "openid4vp-management-token";
const OPENID4VCI_MANAGEMENT_TOKEN_NAME: &str = "openid4vci-management-token";

pub struct ConformanceDeploymentEvidence {
    pub deployment_id: String,
    pub target_issuer: String,
    pub release: String,
    pub revision: String,
    pub build_id: String,
    pub runtime: ConformanceRuntimeEvidence,
}

pub enum ConformanceRuntimeEvidence {
    OciImage { digest: String },
    HostBinary { sha256: String },
}

/// Holds the deployment/capability observation used by one ordinary provider run.
pub struct ConformanceSession {
    pub deployment_id: String,
    pub target_issuer: String,
    pub evidence: ConformanceDeploymentEvidence,
    pub recovery_dir: PathBuf,
    secrets_dir: PathBuf,
}

impl ConformanceSession {
    pub fn open(_config_path: &Path, selector: Option<&str>) -> anyhow::Result<Self> {
        let registry = RegistryStore::open_default()?;
        let record = crate::fleet::resolve_instance(&registry, selector, "conformance")?;
        let host = registry
            .host_by_id(record.host_id)?
            .context("instance references missing host")?;
        let target = crate::fleet::production_target(&host)?;
        crate::fleet::live_probe(target.as_ref())
            .context("conformance target helper verification failed")?;
        let inspection = target.inspect_instance(&record.deployment_id)?;
        if inspection.deployment_id != record.deployment_id || inspection.issuer != record.issuer {
            bail!(
                "conformance target identity drift: registry binds deployment '{}' to issuer '{}', target reported '{}' and '{}'",
                record.deployment_id,
                record.issuer,
                inspection.deployment_id,
                inspection.issuer
            );
        }

        let artifact = inspection.artifact.current.clone().context(
            "conformance requires a verified current artifact in target DeploymentState",
        )?;
        let runtime = match inspection.runtime.kind.as_str() {
            "podman" | "docker" => ConformanceRuntimeEvidence::OciImage { digest: artifact },
            "systemd" | "host" => ConformanceRuntimeEvidence::HostBinary { sha256: artifact },
            other => bail!("conformance target reports unsupported runtime kind '{other}'"),
        };
        let identity = inspection
            .current_build_identity
            .as_ref()
            .context("conformance requires verified build identity in target DeploymentState")?;
        let release = identity.version.clone();
        let revision = identity.commit.clone();
        let build_id = format!("{}:{}", identity.product, identity.version);

        let evidence = ConformanceDeploymentEvidence {
            deployment_id: record.deployment_id.clone(),
            target_issuer: inspection.issuer.clone(),
            release,
            revision,
            build_id,
            runtime,
        };

        let recovery_dir = registry
            .root()
            .join("conformance-recovery")
            .join(&record.deployment_id);
        ensure_private_directory(&recovery_dir, "conformance recovery directory")?;

        let secrets_dir = registry.root().join("secrets").join(&record.deployment_id);

        Ok(Self {
            deployment_id: record.deployment_id,
            target_issuer: inspection.issuer,
            evidence,
            recovery_dir,
            secrets_dir,
        })
    }

    pub fn target_issuer(&self) -> &str {
        &self.target_issuer
    }

    pub fn deployment_evidence(&self) -> ConformanceDeploymentEvidence {
        ConformanceDeploymentEvidence {
            deployment_id: self.evidence.deployment_id.clone(),
            target_issuer: self.evidence.target_issuer.clone(),
            release: self.evidence.release.clone(),
            revision: self.evidence.revision.clone(),
            build_id: self.evidence.build_id.clone(),
            runtime: match &self.evidence.runtime {
                ConformanceRuntimeEvidence::OciImage { digest } => {
                    ConformanceRuntimeEvidence::OciImage {
                        digest: digest.clone(),
                    }
                }
                ConformanceRuntimeEvidence::HostBinary { sha256 } => {
                    ConformanceRuntimeEvidence::HostBinary {
                        sha256: sha256.clone(),
                    }
                }
            },
        }
    }

    pub fn recovery_directory(&self) -> anyhow::Result<PathBuf> {
        Ok(self.recovery_dir.clone())
    }

    pub fn tenant_resource_client_config(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<crate::tenant_resources::TenantResourceClientConfig> {
        let key_store = crate::controller_identity::store::ControllerKeyStore::open_default()?;
        let active_key = key_store.load_active(&self.deployment_id)?;
        let (signing_key, controller_public_key, controller_key_id) = if let Some(key) = active_key
        {
            let sk = key.signing_key().clone();
            let pk = key.verifying_key();
            let kid = key.kid().to_owned();
            (Some(sk), pk, kid)
        } else {
            let private =
                crate::install::tenant_resource_controller_private_key_path(&self.secrets_dir);
            let sk = crate::install::read_tenant_resource_controller_signing_key(&private)?;
            let pk = sk.verifying_key();
            let kid = nazo_operator_protocol::instance_key_id(&pk);
            (Some(sk), pk, kid)
        };

        let runtime_public_key = controller_public_key;
        let runtime_key_id = nazo_operator_protocol::instance_key_id(&runtime_public_key);

        Ok(crate::tenant_resources::TenantResourceClientConfig {
            base_url: url::Url::parse(&self.target_issuer)
                .context("configured issuer is not a URL")?,
            deployment_id: self.deployment_id.clone(),
            tenant_id: tenant_id.to_owned(),
            runtime_instance_id: self.deployment_id.clone(),
            runtime_key_id,
            runtime_public_key,
            controller_key_id,
            controller_public_key,
            controller_signing_key: signing_key,
            actor_id: "nazoauthctl".to_owned(),
            embedded: nazo_operator_protocol::EmbeddedIdentity {
                release: self.evidence.release.clone(),
                revision: self.evidence.revision.clone(),
                protocol: nazo_operator_protocol::PROTOCOL_VERSION,
                build_id: self.evidence.build_id.clone(),
            },
        })
    }

    pub fn openid4vp_management_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            OPENID4VP_MANAGEMENT_TOKEN_NAME,
            "OpenID4VP management token",
        )
    }

    pub fn openid4vci_management_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            OPENID4VCI_MANAGEMENT_TOKEN_NAME,
            "OpenID4VCI management token",
        )
    }

    pub fn dynamic_registration_initial_access_token(
        &self,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            DYNAMIC_REGISTRATION_TOKEN_NAME,
            "dynamic-registration initial access token",
        )
    }

    pub fn ciba_automated_decision_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(CIBA_DECISION_TOKEN_NAME, "CIBA automated-decision token")
    }

    fn read_profile_secret(
        &self,
        name: &str,
        label: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let path = self.secrets_dir.join(name);
        let bytes =
            crate::filesystem::read_secure_secret_file(&path, label, MAX_PROFILE_TOKEN_BYTES)?;
        let value = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
        if value.len() < 32
            || value.len() > MAX_PROFILE_TOKEN_BYTES as usize
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            bail!("{label} is invalid");
        }
        Ok(zeroize::Zeroizing::new(value.to_owned()))
    }

    pub fn openid4vc_request_object_trust_anchor_pem(&self) -> anyhow::Result<String> {
        let bundle = self.secrets_dir.join("openid4vc-bundle.pem");
        let bytes = crate::filesystem::read_secure_secret_file(
            &bundle,
            "managed OpenID4VC certificate bundle",
            128 * 1024,
        )?;
        String::from_utf8(bytes.to_vec()).context("managed OpenID4VC trust anchor is not UTF-8 PEM")
    }
}
