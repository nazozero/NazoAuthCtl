use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use nazo_operator_protocol::decode_instance_public_key;

use crate::{
    controller::{ControlConfig, conformance_control_context},
    deployment::DeploymentStore,
    filesystem::ensure_private_directory,
    operator::ExpectedReleaseTarget,
};

const MAX_PROFILE_TOKEN_BYTES: u64 = 4 * 1024;
const DYNAMIC_REGISTRATION_TOKEN_NAME: &str = "dynamic-registration-token";
const DYNAMIC_REGISTRATION_TOKEN_TARGET: &str = "/run/nazoauth-secrets/dynamic-registration-token";
const CIBA_DECISION_TOKEN_NAME: &str = "ciba-decision-token";
const CIBA_DECISION_TOKEN_TARGET: &str = "/run/nazoauth-secrets/ciba-decision-token";
const OPENID4VP_MANAGEMENT_TOKEN_NAME: &str = "openid4vp-management-token";
const OPENID4VP_MANAGEMENT_TOKEN_TARGET: &str = "/run/nazoauth-secrets/openid4vp-management-token";
const OPENID4VCI_MANAGEMENT_TOKEN_NAME: &str = "openid4vci-management-token";
const OPENID4VCI_MANAGEMENT_TOKEN_TARGET: &str =
    "/run/nazoauth-secrets/openid4vci-management-token";

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
    context: ControlConfig,
    config_path: PathBuf,
    expected: ExpectedReleaseTarget,
    runtime_uid: u32,
}

impl ConformanceSession {
    pub fn open(config_path: &Path, selector: Option<&str>) -> anyhow::Result<Self> {
        let (context, _, expected) = conformance_control_context(config_path, selector)?;
        let resolved_config_path = context.path().to_owned();
        let runtime_uid = crate::runtime::runtime_service_owner_uid(&context.config)?;
        Ok(Self {
            context,
            config_path: resolved_config_path,
            expected,
            runtime_uid,
        })
    }

    pub fn target_issuer(&self) -> &str {
        &self.context.config.runtime.expected_issuer
    }

    pub fn deployment_evidence(&self) -> ConformanceDeploymentEvidence {
        let runtime = match self.context.config.runtime.backend {
            crate::deployment::RuntimeBackendKind::Podman
            | crate::deployment::RuntimeBackendKind::Docker => {
                ConformanceRuntimeEvidence::OciImage {
                    digest: self.expected.image_digest.clone(),
                }
            }
            crate::deployment::RuntimeBackendKind::Systemd => {
                ConformanceRuntimeEvidence::HostBinary {
                    sha256: self.expected.binary_digest.clone(),
                }
            }
        };
        ConformanceDeploymentEvidence {
            deployment_id: self.context.config.operator.deployment_id.clone(),
            target_issuer: self.context.config.runtime.expected_issuer.clone(),
            release: self.expected.embedded.release.clone(),
            revision: self.expected.embedded.revision.clone(),
            build_id: self.expected.embedded.build_id.clone(),
            runtime,
        }
    }

    pub fn tenant_resource_client_config(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<crate::tenant_resources::TenantResourceClientConfig> {
        let config_dir = self
            .config_path
            .parent()
            .context("controller configuration has no parent")?;
        let private = crate::install::tenant_resource_controller_private_key_path(config_dir);
        let public = crate::install::tenant_resource_controller_public_key_path(config_dir);
        let key_id_path = crate::install::tenant_resource_controller_key_id_path(config_dir);
        let signing_key = crate::install::read_tenant_resource_controller_signing_key(&private)?;
        let actual_public = crate::filesystem::read_secure_regular_file(
            &public,
            "tenant-resource controller public key",
            false,
            256,
        )?;
        let actual_public = std::str::from_utf8(&actual_public)
            .context("tenant-resource controller public key is not UTF-8")?;
        let controller_public_key = decode_instance_public_key(actual_public)?;
        if controller_public_key != signing_key.verifying_key() {
            bail!("tenant-resource controller public key does not match its private key");
        }
        let expected_key_id = nazo_operator_protocol::instance_key_id(&controller_public_key);
        let actual_key_id = crate::filesystem::read_secure_regular_file(
            &key_id_path,
            "tenant-resource controller key identity",
            false,
            256,
        )?;
        if actual_key_id.as_slice() != expected_key_id.as_bytes() {
            bail!("tenant-resource controller key identity is inconsistent");
        }
        let object_reference = if self.context.config.runtime.backend
            == crate::deployment::RuntimeBackendKind::Systemd
        {
            &self.context.config.runtime.service_name
        } else {
            &self.context.config.runtime.container_name
        };
        let observation = crate::runtime_backend::backend(self.context.config.runtime.backend)
            .inspect(object_reference)
            .context("failed to inspect the bound NazoAuth runtime")?;
        let runtime_identity =
            crate::discovery::verified_runtime_identity_for_uid(&observation, self.runtime_uid)?;
        let runtime_identity_is_explicit = self.context.config.runtime.backend
            == crate::deployment::RuntimeBackendKind::Systemd
            || self
                .context
                .config
                .runtime
                .environment
                .get("RUNTIME_INSTANCE_ID")
                == Some(&self.context.config.runtime.runtime_instance_id);
        if runtime_identity.statement.deployment_id != self.context.config.operator.deployment_id
            || (runtime_identity_is_explicit
                && runtime_identity.statement.runtime_instance_id
                    != self.context.config.runtime.runtime_instance_id)
            || runtime_identity.statement.issuer != self.context.config.runtime.expected_issuer
            || runtime_identity.statement.release != self.expected.embedded.release
            || runtime_identity.statement.revision != self.expected.embedded.revision
            || runtime_identity.statement.build_id != self.expected.embedded.build_id
        {
            bail!("bound runtime identity does not match the selected deployment");
        }
        Ok(crate::tenant_resources::TenantResourceClientConfig {
            base_url: url::Url::parse(&self.context.config.runtime.expected_issuer)
                .context("configured issuer is not a URL")?,
            deployment_id: self.context.config.operator.deployment_id.clone(),
            tenant_id: tenant_id.to_owned(),
            runtime_instance_id: runtime_identity.statement.runtime_instance_id,
            runtime_key_id: runtime_identity.statement.instance_key_id,
            runtime_public_key: runtime_identity.public_key,
            controller_key_id: expected_key_id,
            controller_public_key,
            controller_signing_key: Some(signing_key),
            actor_id: "nazoauthctl".to_owned(),
            embedded: self.expected.embedded.clone(),
        })
    }

    pub fn recovery_directory(&self) -> anyhow::Result<PathBuf> {
        let directory = DeploymentStore::system()
            .deployment_state_dir(&self.context.config.operator.deployment_id)
            .join("conformance-recovery");
        ensure_private_directory(&directory, "conformance recovery directory")?;
        Ok(directory)
    }

    /// Load the deployment-owned OpenID4VP verifier management token from the
    /// same secure file that is bound into the managed runtime.  The path is
    /// derived from the active deployment declaration, never from a CLI
    /// argument, and the token stays in zeroizing memory.
    pub fn openid4vp_management_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            OPENID4VP_MANAGEMENT_TOKEN_NAME,
            OPENID4VP_MANAGEMENT_TOKEN_TARGET,
            "OpenID4VP management token",
        )
    }

    /// Load the deployment-owned OpenID4VCI issuer management token from the
    /// active deployment's bound secret. The token is never accepted from a
    /// command-line argument and remains in zeroizing memory.
    pub fn openid4vci_management_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            OPENID4VCI_MANAGEMENT_TOKEN_NAME,
            OPENID4VCI_MANAGEMENT_TOKEN_TARGET,
            "OpenID4VCI management token",
        )
    }

    pub fn dynamic_registration_initial_access_token(
        &self,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            DYNAMIC_REGISTRATION_TOKEN_NAME,
            DYNAMIC_REGISTRATION_TOKEN_TARGET,
            "dynamic-registration initial access token",
        )
    }

    pub fn ciba_automated_decision_token(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        self.read_profile_secret(
            CIBA_DECISION_TOKEN_NAME,
            CIBA_DECISION_TOKEN_TARGET,
            "CIBA automated-decision token",
        )
    }

    fn read_profile_secret(
        &self,
        name: &str,
        container_target: &str,
        label: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        if self.context.config.install_profile != "standards-full" {
            bail!("OIDF conformance profile secrets require a standards-full deployment");
        }
        let path = if self.context.config.runtime.backend
            == crate::deployment::RuntimeBackendKind::Systemd
        {
            self.config_path
                .parent()
                .context("controller configuration has no parent")?
                .join("secrets")
                .join(name)
        } else {
            let target = Path::new(container_target);
            let mut matches = self
                .context
                .config
                .runtime
                .mounts
                .iter()
                .filter(|mount| mount.target == target);
            let mount = matches
                .next()
                .with_context(|| format!("managed runtime lacks the {label} mount"))?;
            if matches.next().is_some() || !mount.read_only {
                bail!("managed {label} mount is ambiguous or writable");
            }
            mount.source.clone()
        };
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

    /// Return the deployment-owned public CA that signs OpenID4VP request
    /// objects. The secure bundle stays on the managed host; only the public
    /// trust anchor is copied into the Suite configuration.
    pub fn openid4vc_request_object_trust_anchor_pem(&self) -> anyhow::Result<String> {
        if self.context.config.install_profile != "standards-full" {
            bail!("OpenID4VC conformance requires a standards-full deployment");
        }
        let bundle = crate::controller::managed_openid4vc_bundle_path(&self.context.config)?;
        let bytes =
            crate::controller::read_managed_openid4vc_bundle(&self.context.config, &bundle)?;
        let public = crate::controller::extract_openid4vc_trust_anchors(&bytes)?;
        String::from_utf8(public).context("managed OpenID4VC trust anchor is not UTF-8 PEM")
    }
}
