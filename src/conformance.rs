#[cfg(unix)]
use std::io::Read as _;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use nazo_operator_protocol::{
    ConformanceMatrixSummary, ConformanceOnboardingSummary, TaskOperation, TaskResult,
    validate_conformance_matrix_descriptor,
};
use sha2::{Digest as _, Sha256};

use crate::{
    controller::{ControlConfig, conformance_control_context},
    deployment::DeploymentStore,
    filesystem::{atomic_write, ensure_directory_chain, remove_file_durable, set_mode},
    operator::{self, ExpectedReleaseTarget},
    process::Process,
};

const MAX_MATRIX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ONBOARDING_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROFILE_TOKEN_BYTES: u64 = 4 * 1024;
const DYNAMIC_REGISTRATION_TOKEN_NAME: &str = "dynamic-registration-token";
const DYNAMIC_REGISTRATION_TOKEN_TARGET: &str = "/run/nazoauth-secrets/dynamic-registration-token";
const CIBA_DECISION_TOKEN_NAME: &str = "ciba-decision-token";
const CIBA_DECISION_TOKEN_TARGET: &str = "/run/nazoauth-secrets/ciba-decision-token";
const OPENID4VP_MANAGEMENT_TOKEN_NAME: &str = "openid4vp-management-token";
const OPENID4VP_MANAGEMENT_TOKEN_TARGET: &str = "/run/nazoauth-secrets/openid4vp-management-token";

pub struct ConformanceMatrix {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub source_release: String,
    pub group_count: u32,
    pub plan_count: u32,
}

pub struct ConformanceOnboarding {
    pub lease_id: String,
    pub request_jti: String,
    pub applicant_id: String,
    pub client_mappings: BTreeMap<String, String>,
    pub matrix_sha256: String,
    pub bundle_sha256: String,
    pub expires_at: i64,
    pub idempotent_replay: bool,
}

/// Holds shared deployment/capability locks for the complete Suite run.
///
/// Independent lease-scoped conformance sessions may overlap. Exclusive
/// update/rotation/recovery operations remain blocked until every session has
/// completed. Each controller-side operator transaction additionally takes a
/// short writer lock so intent and audit-chain appends cannot race. Secret
/// material lives only in a private `/run` directory and is removed
/// immediately after the operator task consumes it.
pub struct ConformanceSession {
    context: ControlConfig,
    config_path: PathBuf,
    target: String,
    expected: ExpectedReleaseTarget,
    run_directory: PathBuf,
    output_directory: PathBuf,
    runtime_uid: u32,
}

impl ConformanceSession {
    pub fn open(config_path: &Path, selector: Option<&str>) -> anyhow::Result<Self> {
        let (context, target, expected) = conformance_control_context(config_path, selector)?;
        let runtime_uid = crate::runtime::runtime_service_owner_uid(&context.config)?;
        let suffix = hex(rand::random::<[u8; 16]>());
        let run_directory = PathBuf::from(format!("/run/nazoauthctl-conformance-{suffix}"));
        ensure_directory_chain(&run_directory)?;
        set_mode(&run_directory, 0o750)?;
        Process::new("chown")
            .arg(format!("root:{runtime_uid}"))
            .arg(&run_directory)
            .run_quiet()
            .context("failed to bind conformance run directory ownership")?;

        let output_directory = run_directory.join("output");
        ensure_directory_chain(&output_directory)?;
        set_mode(&output_directory, 0o700)?;
        Process::new("chown")
            .arg(format!("{runtime_uid}:{runtime_uid}"))
            .arg(&output_directory)
            .run_quiet()
            .context("failed to bind conformance output ownership")?;

        Ok(Self {
            context,
            config_path: config_path.to_path_buf(),
            target,
            expected,
            run_directory,
            output_directory,
            runtime_uid,
        })
    }

    pub fn target_issuer(&self) -> &str {
        &self.context.config.runtime.expected_issuer
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

    pub fn describe_matrix(&self) -> anyhow::Result<ConformanceMatrix> {
        let result = self.with_operator_task_lock(|| {
            operator::execute_with_io(
                &self.context.config,
                &self.target,
                &self.expected,
                TaskOperation::ConformanceMatrixDescribe,
                None,
                None,
                Some(&self.output_directory),
                None,
            )
        })?;
        let TaskResult::ConformanceMatrix { summary } = result.result else {
            bail!("operator returned an unexpected MatrixDescribe result");
        };
        let path = self.output_directory.join("conformance-matrix.json");
        let bytes = read_runtime_output(
            &path,
            self.runtime_uid,
            "conformance matrix output",
            MAX_MATRIX_BYTES,
        )?;
        remove_file_durable(&path)?;
        verify_matrix_summary(&bytes, &summary)?;
        let descriptor: nazo_operator_protocol::ConformanceMatrixDescriptor =
            serde_json::from_slice(&bytes).context("operator Matrix is not strict JSON")?;
        validate_conformance_matrix_descriptor(&descriptor)
            .context("operator Matrix violates the protocol contract")?;
        Ok(ConformanceMatrix {
            bytes,
            sha256: summary.sha256,
            source_release: summary.source_release,
            group_count: summary.group_count,
            plan_count: summary.plan_count,
        })
    }

    pub fn apply_onboarding(
        &self,
        request_jti: &str,
        matrix_sha256: &str,
        bundle: &[u8],
        client_count: u32,
        ttl_seconds: u64,
    ) -> anyhow::Result<ConformanceOnboarding> {
        if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
            bail!("conformance onboarding bundle size is invalid");
        }
        let bundle_sha256 = digest(bundle);
        let bundle_path = self.run_directory.join("conformance-bundle.json");
        atomic_write(&bundle_path, bundle, 0o440)?;
        Process::new("chown")
            .arg(format!("root:{}", self.runtime_uid))
            .arg(&bundle_path)
            .run_quiet()
            .context("failed to bind conformance bundle ownership")?;

        let result = self.with_operator_task_lock(|| {
            operator::execute_with_io(
                &self.context.config,
                &self.target,
                &self.expected,
                TaskOperation::ConformanceOnboardingApply {
                    profile: "nazoauth-full".to_owned(),
                    bundle_schema: 2,
                    bundle_sha256: bundle_sha256.clone(),
                    matrix_sha256: matrix_sha256.to_owned(),
                    client_count,
                    ttl_seconds,
                },
                None,
                Some(&bundle_path),
                Some(&self.output_directory),
                Some(request_jti),
            )
        });
        let bundle_cleanup = remove_file_durable(&bundle_path);
        let result = match (result, bundle_cleanup) {
            (Ok(result), Ok(())) => result,
            (Ok(_), Err(error)) => {
                return Err(error).context("failed to remove consumed conformance bundle");
            }
            (Err(error), _) => return Err(error),
        };
        let TaskResult::ConformanceOnboardingApplied { onboarding } = result.result else {
            bail!("operator returned an unexpected onboarding result");
        };
        let lease_id = onboarding.lease_id.clone();
        let verified = (|| -> anyhow::Result<ConformanceOnboarding> {
            let output_path = self.output_directory.join("conformance-onboarding.json");
            let output_bytes = read_runtime_output(
                &output_path,
                self.runtime_uid,
                "conformance onboarding output",
                MAX_ONBOARDING_OUTPUT_BYTES,
            )?;
            remove_file_durable(&output_path)?;
            let output: ConformanceOnboardingSummary = serde_json::from_slice(&output_bytes)
                .context("operator onboarding output is not strict JSON")?;
            if output != onboarding
                || onboarding.request_jti != request_jti
                || onboarding.matrix_sha256 != matrix_sha256
                || onboarding.bundle_sha256 != bundle_sha256
                || onboarding.client_count != client_count
            {
                bail!("operator onboarding receipt and secure output do not match the request");
            }
            let client_mappings = onboarding
                .client_mappings
                .into_iter()
                .map(|mapping| (mapping.logical_client_id, mapping.client_id))
                .collect::<BTreeMap<_, _>>();
            if client_mappings.len() != usize::try_from(client_count)? {
                bail!("operator onboarding client mapping count is inconsistent");
            }
            Ok(ConformanceOnboarding {
                lease_id: onboarding.lease_id,
                request_jti: onboarding.request_jti,
                applicant_id: onboarding.applicant_id,
                client_mappings,
                matrix_sha256: onboarding.matrix_sha256,
                bundle_sha256: onboarding.bundle_sha256,
                expires_at: onboarding.expires_at,
                idempotent_replay: onboarding.idempotent_replay,
            })
        })();
        match verified {
            Ok(onboarding) => Ok(onboarding),
            Err(error) => match self.cleanup_lease(&lease_id) {
                Ok(()) => Err(error)
                    .context("onboarding was rolled back after output verification failed"),
                Err(cleanup) => bail!(
                    "onboarding output verification failed and lease rollback also failed: verification={error:#}; cleanup={cleanup:#}"
                ),
            },
        }
    }

    pub fn cleanup_lease(&self, lease_id: &str) -> anyhow::Result<()> {
        let (revoke, cleanup) = self.with_operator_task_lock(|| {
            let revoke = operator::execute(
                &self.context.config,
                &self.target,
                &self.expected,
                TaskOperation::ConformanceLeaseRevoke {
                    lease_id: lease_id.to_owned(),
                },
                None,
            );
            let cleanup = operator::execute(
                &self.context.config,
                &self.target,
                &self.expected,
                TaskOperation::ConformanceLeaseCleanup,
                None,
            );
            Ok((revoke, cleanup))
        })?;
        match (revoke, cleanup) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(revoke), Ok(_)) => Err(revoke).context("failed to revoke conformance lease"),
            (Ok(_), Err(cleanup)) => Err(cleanup).context("failed to cleanup conformance lease"),
            (Err(revoke), Err(cleanup)) => bail!(
                "failed to revoke and cleanup conformance lease: revoke={revoke:#}; cleanup={cleanup:#}"
            ),
        }
    }

    fn with_operator_task_lock<T>(
        &self,
        operation: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let store = DeploymentStore::system();
        let _writer = store.operator_task_lock(&self.context.config.operator.deployment_id)?;
        operation()
    }
}

impl Drop for ConformanceSession {
    fn drop(&mut self) {
        if self
            .run_directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("nazoauthctl-conformance-"))
            && self.run_directory.parent() == Some(Path::new("/run"))
            && fs::symlink_metadata(&self.run_directory)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            let _ = fs::remove_dir_all(&self.run_directory);
        }
    }
}

#[cfg(unix)]
fn read_runtime_output(
    path: &Path,
    owner_uid: u32,
    label: &str,
    maximum: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut file =
        crate::filesystem::open_secure_regular_file_for_uid(path, label, true, owner_uid)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() as u64 > maximum {
        bail!("{label} exceeds the allowed size");
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_runtime_output(
    path: &Path,
    owner_uid: u32,
    label: &str,
    maximum: u64,
) -> anyhow::Result<Vec<u8>> {
    let _ = (path, owner_uid, label, maximum);
    bail!("conformance operator output is supported only on Unix managed hosts")
}

fn verify_matrix_summary(bytes: &[u8], summary: &ConformanceMatrixSummary) -> anyhow::Result<()> {
    if summary.schema != 1
        || summary.sha256 != digest(bytes)
        || summary.size != bytes.len() as u64
        || summary.group_count == 0
        || summary.plan_count == 0
    {
        bail!("operator Matrix output does not match its signed summary");
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
