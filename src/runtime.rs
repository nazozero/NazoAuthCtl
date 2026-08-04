use std::{collections::BTreeMap, ffi::OsString, fs, path::Path};

use anyhow::{Context, bail};
use nazo_operator_protocol::{RuntimeTargetClaim, TaskOperation};

use crate::{
    deployment::{ArtifactReference, ResourceScope, Responsibility, RuntimeBackendKind},
    filesystem::{atomic_write, sha256},
    model::{Mount, UpdateConfig},
    runtime_backend::{
        self, ManagedPostgresCommand, ManagedPostgresRestore, ManagedValkeyRestore, NeutralMount,
        OneShotTask,
    },
};

#[derive(Debug)]
pub(crate) struct PreparedAppTask {
    backend: RuntimeBackendKind,
    command_override: Option<OsString>,
    task: OneShotTask,
    pub(crate) target: RuntimeTargetClaim,
}

impl PreparedAppTask {
    pub(crate) fn execute(&self, compact_envelope: &str) -> anyhow::Result<String> {
        let mut task = self.task.clone();
        task.stdin = compact_envelope.as_bytes().to_vec();
        selected_backend(self.backend, self.command_override.as_deref()).run_one_shot(&task)
    }

    /// Starts the already prepared task and accepts only the runtime's closed
    /// authorization-failure boundary.  Any setup failure, timeout, unrelated
    /// non-zero exit, or successful task is a failed retirement probe.
    pub(crate) fn expect_authorization_rejection(
        &self,
        compact_envelope: &str,
    ) -> anyhow::Result<()> {
        let mut task = self.task.clone();
        task.stdin = compact_envelope.as_bytes().to_vec();
        match selected_backend(self.backend, self.command_override.as_deref())
            .run_one_shot_authorization_probe(&task)?
        {
            true => Ok(()),
            false => bail!(
                "prepared runtime task did not reject retired controller at authorization boundary"
            ),
        }
    }
}

pub(crate) struct Runtime<'a> {
    config: &'a UpdateConfig,
}

impl<'a> Runtime<'a> {
    pub(crate) fn new(config: &'a UpdateConfig) -> Self {
        Self { config }
    }

    pub(crate) fn active_revision(&self) -> anyhow::Result<String> {
        let kind = self.backend_kind()?;
        if kind == RuntimeBackendKind::Systemd {
            let target = std::fs::canonicalize(&self.config.runtime.binary_path)
                .context("failed to resolve active host binary")?;
            return target
                .parent()
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
                .context("active host binary does not have a release directory");
        }
        self.backend()?
            .inspect(self.object_reference(kind))?
            .labels
            .remove("org.opencontainers.image.revision")
            .context("runtime image has no revision label")
    }

    pub(crate) fn active_image(&self) -> anyhow::Result<String> {
        let kind = self.backend_kind()?;
        if kind == RuntimeBackendKind::Systemd {
            bail!("host runtime does not have an active image");
        }
        match self
            .backend()?
            .inspect(self.object_reference(kind))?
            .artifact
        {
            ArtifactReference::Oci {
                image_reference, ..
            } => Ok(image_reference),
            _ => bail!("runtime object does not expose an OCI artifact"),
        }
    }

    pub(crate) fn prepare_app_task(
        &self,
        image_or_binary: &str,
        operation: &TaskOperation,
        public_jwk: Option<&Path>,
        config_manifest: &[u8],
    ) -> anyhow::Result<PreparedAppTask> {
        self.write_task_context(config_manifest)?;
        let backend = self.backend_kind()?;
        let artifact = match backend {
            RuntimeBackendKind::Systemd => {
                let path = fs::canonicalize(image_or_binary)
                    .context("failed to resolve host task binary")?;
                ArtifactReference::HostBinary {
                    sha256: sha256(&path)?,
                    path,
                }
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => ArtifactReference::Oci {
                image_reference: image_or_binary.to_owned(),
                digest: self.backend()?.resolve_image_digest(image_or_binary)?,
            },
        };
        let target = match &artifact {
            ArtifactReference::Oci {
                image_reference,
                digest,
            } => RuntimeTargetClaim::OciImage {
                image_ref: image_reference.clone(),
                image_digest: digest.clone(),
            },
            ArtifactReference::HostBinary { path, sha256 } => RuntimeTargetClaim::HostBinary {
                path: path.display().to_string(),
                sha256: sha256.clone(),
            },
            ArtifactReference::Unknown => bail!("operator task artifact is not verified"),
        };
        let task = self.one_shot_task(artifact, operation, public_jwk)?;
        Ok(PreparedAppTask {
            backend,
            command_override: self.command_override(),
            task,
            target,
        })
    }

    fn backend_kind(&self) -> anyhow::Result<RuntimeBackendKind> {
        Ok(self.config.runtime.backend)
    }

    fn command_override(&self) -> Option<OsString> {
        self.config
            .runtime
            .backend_command_override
            .as_ref()
            .map(|path| path.as_os_str().to_os_string())
    }

    fn backend(&self) -> anyhow::Result<Box<dyn runtime_backend::RuntimeBackend>> {
        Ok(selected_backend(
            self.backend_kind()?,
            self.command_override().as_deref(),
        ))
    }

    fn one_shot_task(
        &self,
        artifact: ArtifactReference,
        operation: &TaskOperation,
        public_jwk: Option<&Path>,
    ) -> anyhow::Result<OneShotTask> {
        if self.backend_kind()? == RuntimeBackendKind::Systemd {
            return self.systemd_one_shot_task(artifact, operation, public_jwk);
        }
        let mut mounts = Vec::new();
        let mut environment = BTreeMap::from([
            (
                "NAZOAUTH_OPERATOR_CONTEXT_FILE".to_owned(),
                "/run/nazoauth-operator/context.json".to_owned(),
            ),
            (
                "NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE".to_owned(),
                "/run/nazoauth-operator/controller.pub".to_owned(),
            ),
            (
                "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE".to_owned(),
                "/run/nazoauth-operator/receipt.key".to_owned(),
            ),
            (
                "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
                "/var/lib/nazoauth/operator-state".to_owned(),
            ),
            (
                "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE".to_owned(),
                "/run/nazoauth-operator/config-manifest.json".to_owned(),
            ),
            (
                "NAZOAUTH_SERVER_CONFIG_FILE".to_owned(),
                "/app/.env.yaml".to_owned(),
            ),
        ]);
        let config_mount = self.required_mount("/app/.env.yaml")?;
        mounts.push(neutral_mount(config_mount));

        if operation_uses_database(operation) {
            mounts.push(task_mount(
                operation_database_url_file(self.config, operation),
                Path::new("/run/nazoauth-secrets/database-url"),
                true,
            ));
            environment.insert(
                "DATABASE_URL_FILE".to_owned(),
                "/run/nazoauth-secrets/database-url".to_owned(),
            );
        } else {
            mounts.push(neutral_mount(
                self.required_mount("/var/lib/nazo_oauth/keys")?,
            ));
        }

        let operator_directory = self
            .config
            .operator
            .controller_public_key
            .parent()
            .context("operator directory is unavailable")?;
        let manifest_path = operator_directory.join("config-manifest.json");
        let context_path = operator_directory.join("context.json");
        for (source, target, read_only) in [
            (
                self.config.operator.controller_public_key.as_path(),
                Path::new("/run/nazoauth-operator/controller.pub"),
                true,
            ),
            (
                manifest_path.as_path(),
                Path::new("/run/nazoauth-operator/config-manifest.json"),
                true,
            ),
            (
                self.config.operator.receipt_private_key.as_path(),
                Path::new("/run/nazoauth-operator/receipt.key"),
                true,
            ),
            (
                context_path.as_path(),
                Path::new("/run/nazoauth-operator/context.json"),
                true,
            ),
            (
                self.config.operator.state_directory.as_path(),
                Path::new("/var/lib/nazoauth/operator-state"),
                false,
            ),
        ] {
            mounts.push(task_mount(source, target, read_only));
        }
        if let Some(path) = public_jwk {
            mounts.push(task_mount(
                path,
                Path::new("/run/nazoauth-operator/public.jwk"),
                true,
            ));
            environment.insert(
                "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE".to_owned(),
                "/run/nazoauth-operator/public.jwk".to_owned(),
            );
        }
        Ok(OneShotTask {
            artifact,
            command: match self.backend_kind()? {
                RuntimeBackendKind::Systemd => vec!["operator-task".to_owned()],
                RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                    vec!["nazoauth".to_owned(), "operator-task".to_owned()]
                }
            },
            network: operation_uses_database(operation)
                .then(|| self.config.runtime.network.clone()),
            mounts,
            environment,
            working_directory: (self.backend_kind()? == RuntimeBackendKind::Systemd)
                .then(|| self.config.runtime.working_directory.clone()),
            service_user: (self.backend_kind()? == RuntimeBackendKind::Systemd)
                .then(|| self.config.runtime.service_user.clone()),
            transient_credentials: BTreeMap::new(),
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            inaccessible_paths: Vec::new(),
            private_mounts: false,
            stdin: Vec::new(),
        })
    }

    fn systemd_one_shot_task(
        &self,
        artifact: ArtifactReference,
        operation: &TaskOperation,
        public_jwk: Option<&Path>,
    ) -> anyhow::Result<OneShotTask> {
        let key_directory = self
            .config
            .runtime
            .snapshot_paths
            .first()
            .context("application key state directory is unavailable")?;
        let app_root = key_directory
            .parent()
            .context("application data root is unavailable")?;
        let ui_releases = app_root
            .parent()
            .context("deployment data root is unavailable")?
            .join("ui-releases");
        let operator_directory = self
            .config
            .operator
            .controller_public_key
            .parent()
            .context("operator directory is unavailable")?;
        let mut environment = BTreeMap::from([
            (
                "NAZOAUTH_OPERATOR_CONTEXT_FILE".to_owned(),
                operator_directory
                    .join("context.json")
                    .display()
                    .to_string(),
            ),
            (
                "NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE".to_owned(),
                self.config
                    .operator
                    .controller_public_key
                    .display()
                    .to_string(),
            ),
            (
                "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE".to_owned(),
                "%d/operator-receipt-key".to_owned(),
            ),
            (
                "NAZOAUTH_OPERATOR_STATE_DIRECTORY".to_owned(),
                self.config.operator.state_directory.display().to_string(),
            ),
            (
                "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE".to_owned(),
                operator_directory
                    .join("config-manifest.json")
                    .display()
                    .to_string(),
            ),
            (
                "NAZOAUTH_SERVER_CONFIG_FILE".to_owned(),
                self.config
                    .runtime
                    .working_directory
                    .join(".env.yaml")
                    .display()
                    .to_string(),
            ),
        ]);
        let mut transient_credentials = BTreeMap::from([(
            "operator-receipt-key".to_owned(),
            self.config.operator.receipt_private_key.clone(),
        )]);
        let mut read_only_paths = Vec::new();
        let mut read_write_paths = vec![self.config.operator.state_directory.clone()];
        let mut inaccessible_paths = vec![
            app_root.join("avatars"),
            app_root.join("secrets"),
            app_root.join("bootstrap"),
            ui_releases,
        ];
        if operation_uses_database(operation) {
            transient_credentials.insert(
                "operator-database-url".to_owned(),
                operation_database_url_file(self.config, operation).to_path_buf(),
            );
            environment.insert(
                "DATABASE_URL_FILE".to_owned(),
                "%d/operator-database-url".to_owned(),
            );
            inaccessible_paths.push(key_directory.clone());
        } else {
            read_write_paths.push(key_directory.clone());
            inaccessible_paths.push(
                self.config
                    .dependencies
                    .migration_database_url_file
                    .parent()
                    .context("dependency secret directory is unavailable")?
                    .to_path_buf(),
            );
            if let Some(path) = public_jwk {
                read_only_paths.push(path.to_path_buf());
                environment.insert(
                    "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE".to_owned(),
                    path.display().to_string(),
                );
            }
        }
        Ok(OneShotTask {
            artifact,
            command: vec!["operator-task".to_owned()],
            network: operation_uses_database(operation).then(String::new),
            mounts: Vec::new(),
            environment,
            working_directory: Some(self.config.runtime.working_directory.clone()),
            service_user: Some(self.config.runtime.service_user.clone()),
            transient_credentials,
            read_only_paths,
            read_write_paths,
            inaccessible_paths,
            private_mounts: true,
            stdin: Vec::new(),
        })
    }

    pub(crate) fn start_container(&self, image: &str) -> anyhow::Result<()> {
        let backend_kind = self.backend_kind()?;
        if backend_kind == RuntimeBackendKind::Systemd {
            bail!("systemd runtime requires an explicit staged binary transaction");
        }
        let backend = self.backend()?;
        let replacement = runtime_backend::RuntimeReplacement {
            object_reference: self.config.runtime.container_name.clone(),
            artifact: ArtifactReference::Oci {
                image_reference: image.to_owned(),
                digest: backend.resolve_image_digest(image)?,
            },
            local_artifact_id: None,
            command: vec!["nazoauth".to_owned(), "server".to_owned()],
            mounts: self
                .config
                .runtime
                .mounts
                .iter()
                .map(neutral_mount)
                .collect(),
            environment: self.config.runtime.environment.clone(),
            networks: (!self.config.runtime.network.is_empty())
                .then(|| self.config.runtime.network.clone())
                .into_iter()
                .collect(),
            ip_address: (!self.config.runtime.ip_address.is_empty())
                .then(|| self.config.runtime.ip_address.clone()),
            ports: (!self.config.runtime.publish_address.is_empty())
                .then(|| self.config.runtime.publish_address.clone())
                .into_iter()
                .collect(),
            labels: BTreeMap::from([
                (
                    "io.nazoauth.deployment-id".to_owned(),
                    self.config.operator.deployment_id.clone(),
                ),
                (
                    "io.nazoauth.runtime-instance-id".to_owned(),
                    self.config.runtime.runtime_instance_id.clone(),
                ),
                (
                    "io.nazoauth.control-authority".to_owned(),
                    self.config.operator.controller_key_id.clone(),
                ),
            ]),
            container_policy: Some(runtime_backend::ContainerRuntimePolicy::managed_default()),
        };
        backend.replace(&replacement)
    }
    pub(crate) fn remove_container(&self) -> anyhow::Result<()> {
        if self.config.capabilities.runtime.responsibility
            == crate::deployment::Responsibility::Managed
            && !self.container_has_authorized_labels()
        {
            bail!("refusing to replace an unlabelled application container");
        }
        self.backend()?.remove(&self.config.runtime.container_name)
    }

    pub(crate) fn container_exists(&self) -> bool {
        self.backend_kind().is_ok_and(|kind| {
            kind != RuntimeBackendKind::Systemd
                && self.backend().is_ok_and(|backend| {
                    backend.inspect(&self.config.runtime.container_name).is_ok()
                })
        })
    }

    pub(crate) fn restart(&self) -> anyhow::Result<()> {
        let kind = self.backend_kind()?;
        self.backend()?.restart(self.object_reference(kind))
    }

    pub(crate) fn start_service(&self) -> anyhow::Result<()> {
        self.backend()?.start(&self.config.runtime.service_name)
    }

    pub(crate) fn stop_service(&self) -> anyhow::Result<()> {
        self.backend()?.stop(&self.config.runtime.service_name)
    }

    fn object_reference(&self, kind: RuntimeBackendKind) -> &str {
        match kind {
            RuntimeBackendKind::Systemd => &self.config.runtime.service_name,
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => {
                &self.config.runtime.container_name
            }
        }
    }

    pub(crate) fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        self.backend()?.pull_image(image)
    }

    pub(crate) fn export_image(&self, image: &str, archive: &Path) -> anyhow::Result<()> {
        let parent = archive
            .parent()
            .context("OCI recovery archive has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = archive.with_extension("oci-archive.tmp");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        self.backend()?.export_image(image, &temporary)?;
        let metadata = fs::symlink_metadata(&temporary)
            .context("container engine did not create the OCI recovery archive")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            bail!("container engine created an invalid OCI recovery archive");
        }
        fs::rename(&temporary, archive)?;
        Ok(())
    }

    pub(crate) fn import_image(&self, archive: &Path, expected_image: &str) -> anyhow::Result<()> {
        let metadata =
            fs::symlink_metadata(archive).context("trusted OCI recovery archive is unavailable")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            bail!("trusted OCI recovery archive is invalid");
        }
        self.backend()?.import_image(archive)?;
        self.image_digest(expected_image)?;
        Ok(())
    }

    pub(crate) fn restore_managed_dependencies(
        &self,
        backup_directory: &Path,
        postgres_service_file: &Path,
        postgres_password_file: &Path,
    ) -> anyhow::Result<()> {
        let backend = self.backend()?;
        backend.restore_managed_postgres(&ManagedPostgresRestore {
            network: self.config.runtime.network.clone(),
            backup_directory: backup_directory.to_path_buf(),
            service_file: postgres_service_file.to_path_buf(),
            password_file: postgres_password_file.to_path_buf(),
            image: self.config.postgres.validation_image.clone(),
        })?;
        backend.restore_managed_valkey(&ManagedValkeyRestore {
            object_reference: self.config.valkey.container_name.clone(),
            data_volume: self.config.valkey.data_volume.clone(),
            backup_directory: backup_directory.to_path_buf(),
            image: self.config.valkey.image.clone(),
        })
    }

    pub(crate) fn execute_managed_postgres(&self, sql: &[u8]) -> anyhow::Result<()> {
        self.backend()?
            .execute_managed_postgres(&ManagedPostgresCommand {
                object_reference: self.config.postgres.container_name.clone(),
                database: self.config.postgres.database.clone(),
                user: self.config.postgres.user.clone(),
                stdin: sql.to_vec(),
            })
    }

    pub(crate) fn image_revision(&self, image: &str) -> anyhow::Result<String> {
        Ok(self.embedded_identity(image)?.revision)
    }

    pub(crate) fn image_digest(&self, image: &str) -> anyhow::Result<String> {
        let (_, expected_digest) = image
            .rsplit_once('@')
            .context("managed OCI image reference is not pinned by digest")?;
        let normalized = expected_digest.strip_prefix("sha256:").unwrap_or("");
        if normalized.len() != 64
            || !normalized
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("managed OCI image reference has an invalid digest");
        }
        let actual = self.backend()?.resolve_image_digest(image)?;
        if actual != expected_digest.to_ascii_lowercase() {
            bail!("container engine retained a different OCI digest");
        }
        Ok(actual)
    }

    pub(crate) fn embedded_identity(
        &self,
        image_or_binary: &str,
    ) -> anyhow::Result<nazo_operator_protocol::EmbeddedIdentity> {
        let kind = self.backend_kind()?;
        let artifact = match kind {
            RuntimeBackendKind::Systemd => {
                let path = fs::canonicalize(image_or_binary)
                    .context("failed to resolve host binary for build identity")?;
                ArtifactReference::HostBinary {
                    sha256: sha256(&path)?,
                    path,
                }
            }
            RuntimeBackendKind::Podman | RuntimeBackendKind::Docker => ArtifactReference::Oci {
                image_reference: image_or_binary.to_owned(),
                digest: self.image_digest(image_or_binary)?,
            },
        };
        self.backend()?
            .read_build_identity(&artifact, None)
            .context("runtime embedded build identity is invalid")?
            .context("runtime backend returned no build identity")
    }
    pub(crate) fn verify_prepared_target(
        &self,
        expected: &RuntimeTargetClaim,
    ) -> anyhow::Result<()> {
        let actual = match expected {
            RuntimeTargetClaim::OciImage { image_ref, .. } => RuntimeTargetClaim::OciImage {
                image_ref: image_ref.clone(),
                image_digest: self.image_digest(image_ref)?,
            },
            RuntimeTargetClaim::HostBinary { path, .. } => RuntimeTargetClaim::HostBinary {
                path: path.clone(),
                sha256: sha256(Path::new(path))?,
            },
        };
        if &actual != expected {
            bail!("runtime target changed during privileged task execution");
        }
        Ok(())
    }

    fn write_task_context(&self, config_manifest: &[u8]) -> anyhow::Result<()> {
        let directory = self
            .config
            .operator
            .controller_public_key
            .parent()
            .context("operator directory is unavailable")?;
        atomic_write(
            &directory.join("context.json"),
            &serde_json::to_vec(&serde_json::json!({
                "controller_key_id": self.config.operator.controller_key_id,
                "receipt_key_id": self.config.operator.receipt_key_id,
            }))?,
            0o444,
        )?;
        atomic_write(
            &directory.join("config-manifest.json"),
            config_manifest,
            0o444,
        )
    }

    fn required_mount(&self, target: &str) -> anyhow::Result<&Mount> {
        self.config
            .runtime
            .mounts
            .iter()
            .find(|mount| mount.target == Path::new(target))
            .with_context(|| format!("runtime mount {target} is unavailable"))
    }

    fn container_has_authorized_labels(&self) -> bool {
        self.backend_kind().is_ok_and(|_| {
            self.backend().is_ok_and(|backend| {
                backend
                    .verify_ownership(
                        &self.config.runtime.container_name,
                        &self.config.operator.deployment_id,
                        &self.config.operator.controller_key_id,
                    )
                    .is_ok()
            })
        })
    }
}

fn selected_backend(
    kind: RuntimeBackendKind,
    command_override: Option<&std::ffi::OsStr>,
) -> Box<dyn runtime_backend::RuntimeBackend> {
    #[cfg(test)]
    if let Some(command) = command_override {
        return runtime_backend::backend_with_command(kind, command.to_os_string());
    }
    let _ = command_override;
    runtime_backend::backend(kind)
}

fn neutral_mount(mount: &Mount) -> NeutralMount {
    task_mount(&mount.source, &mount.target, mount.read_only)
}

fn task_mount(source: &Path, destination: &Path, read_only: bool) -> NeutralMount {
    NeutralMount {
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        read_only,
        selinux_relabel: true,
        ownership: Responsibility::Managed,
        scope: ResourceScope::Deployment,
    }
}

fn operation_uses_database(operation: &TaskOperation) -> bool {
    matches!(
        operation,
        TaskOperation::MigrateApply
            | TaskOperation::ConformanceLeaseCreate { .. }
            | TaskOperation::ConformanceLeaseList
            | TaskOperation::ConformanceLeaseRevoke { .. }
            | TaskOperation::ConformanceLeaseCleanup
    )
}

fn operation_database_url_file<'a>(
    config: &'a UpdateConfig,
    operation: &TaskOperation,
) -> &'a Path {
    if matches!(operation, TaskOperation::MigrateApply) {
        &config.dependencies.migration_database_url_file
    } else {
        &config.dependencies.database_url_file
    }
}

#[cfg(test)]
#[path = "../tests/unit/runtime.rs"]
mod tests;
