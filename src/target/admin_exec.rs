//! Target-side administrator provisioning through the deployment root.
//!
//! The target never exposes a second HTTP/admin-session path. It validates
//! the live DeploymentState in dispatch, then this executor invokes the one
//! fixed `nazoauth admin-provision` command in the current runtime artifact.
//! Credentials exist only in a short-lived owner-only file supplied through a
//! read-only container mount or a systemd transient credential.

use std::collections::BTreeMap;
use std::path::Path;

use zeroize::Zeroizing;

use super::control_exec::{
    FixedOneShotJob, FixedOneShotKind, FixedSecretFile, execute_fixed_one_shot,
};
use super::deployment_state::Failure;
use super::wire::{AdminProvisionReceipt, HOST_ERR_OPERATION_INVALID, sanitize};

pub(crate) const ADMIN_PROVISION_FILE_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_FILE";
pub(crate) const ADMIN_PROVISION_OPERATION_ID_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_OPERATION_ID";
pub(crate) const ADMIN_PROVISION_DEPLOYMENT_ID_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_DEPLOYMENT_ID";
const ADMIN_PROVISION_CREDENTIAL: &str = "admin-provision";
const CONTAINER_ADMIN_PROVISION_PATH: &str = "/run/nazoauth/admin-provision";
const ADMIN_PROVISION_RECEIPT_SCHEMA: u32 = 1;

/// Everything the administrator executor needs besides the password bytes.
/// The values are taken from the target's live DeploymentState; callers cannot
/// provide a runtime object, image, or filesystem path.
pub(crate) struct AdminProvisionJob<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) deployment_id: &'a str,
    pub(crate) artifact_reference: &'a str,
    pub(crate) runtime_kind: crate::runtime_backend::RuntimeBackendKind,
    pub(crate) runtime_object: &'a str,
    pub(crate) config_reference: &'a str,
    pub(crate) data_root: &'a str,
    pub(crate) scope_dir: &'a Path,
    pub(crate) email: &'a str,
    pub(crate) password: &'a [u8],
}

/// Injectable target-side seam. Tests can return a receipt without spawning a
/// container/systemd process; production uses [`HostAdminProvisioner`].
pub(crate) trait AdminProvisionExecutor: Send + Sync {
    fn execute(&self, job: &AdminProvisionJob<'_>) -> Result<AdminProvisionReceipt, Failure>;
}

/// Production administrator provisioner backed by the shared fixed one-shot
/// runtime executor.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostAdminProvisioner;

impl AdminProvisionExecutor for HostAdminProvisioner {
    fn execute(&self, job: &AdminProvisionJob<'_>) -> Result<AdminProvisionReceipt, Failure> {
        #[derive(serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct AdminProvisionInput<'a> {
            schema: u32,
            email: &'a str,
            password: &'a str,
        }

        let password = std::str::from_utf8(job.password).map_err(|_| {
            Failure::new(
                HOST_ERR_OPERATION_INVALID,
                "administrator password material is not valid UTF-8",
            )
        })?;
        let credentials = Zeroizing::new(
            serde_json::to_vec(&AdminProvisionInput {
                schema: 1,
                email: job.email,
                password,
            })
            .map_err(|_| {
                Failure::new(
                    HOST_ERR_OPERATION_INVALID,
                    "failed to prepare administrator credentials",
                )
            })?,
        );
        let fixed_job = FixedOneShotJob {
            deployment_id: job.deployment_id,
            artifact_reference: job.artifact_reference,
            runtime_kind: job.runtime_kind,
            runtime_object: job.runtime_object,
            config_reference: job.config_reference,
            data_root: job.data_root,
            scope_dir: job.scope_dir,
        };
        let secret_file = FixedSecretFile {
            credential_name: ADMIN_PROVISION_CREDENTIAL,
            container_path: CONTAINER_ADMIN_PROVISION_PATH,
            environment_name: ADMIN_PROVISION_FILE_ENV,
            bytes: credentials.as_slice(),
        };
        let mut environment = BTreeMap::new();
        environment.insert(
            ADMIN_PROVISION_OPERATION_ID_ENV.to_owned(),
            job.operation_id.to_owned(),
        );
        environment.insert(
            ADMIN_PROVISION_DEPLOYMENT_ID_ENV.to_owned(),
            job.deployment_id.to_owned(),
        );
        let stdout = execute_fixed_one_shot(
            &fixed_job,
            FixedOneShotKind::AdminProvision,
            environment,
            Some(&secret_file),
            Vec::new(),
        )?;
        decode_admin_provision_receipt(&stdout, job.operation_id, job.deployment_id)
    }
}

/// Decode exactly one server receipt and bind it to the operation currently
/// executing. The password is never parsed into this response type and is
/// therefore impossible to echo through a completion or an error.
pub(crate) fn decode_admin_provision_receipt(
    stdout: &str,
    operation_id: &str,
    deployment_id: &str,
) -> Result<AdminProvisionReceipt, Failure> {
    let mut frames = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(line) = frames.next() else {
        return Err(Failure::new(
            crate::target::CONTROL_OUTCOME_UNKNOWN,
            "the NazoAuth administrator provisioner produced no receipt; the outcome is unknown",
        ));
    };
    if frames.next().is_some() {
        return Err(Failure::new(
            crate::target::CONTROL_OUTCOME_UNKNOWN,
            "the NazoAuth administrator provisioner emitted more than one receipt; the outcome is unknown",
        ));
    }
    let receipt: AdminProvisionReceipt = serde_json::from_str(line).map_err(|error| {
        Failure::new(
            crate::target::CONTROL_OUTCOME_UNKNOWN,
            format!(
                "the administrator provisioner receipt did not parse ({})",
                sanitize(error.to_string())
            ),
        )
    })?;
    validate_admin_provision_receipt(&receipt, operation_id, deployment_id)?;
    Ok(receipt)
}

pub(crate) fn validate_admin_provision_receipt(
    receipt: &AdminProvisionReceipt,
    operation_id: &str,
    deployment_id: &str,
) -> Result<(), Failure> {
    if receipt.schema != ADMIN_PROVISION_RECEIPT_SCHEMA
        || receipt.operation_id != operation_id
        || receipt.deployment_id != deployment_id
        || !valid_receipt_field(&receipt.email, 254)
    {
        return Err(Failure::new(
            HOST_ERR_OPERATION_INVALID,
            "the administrator provisioner receipt is not bound to this operation and deployment",
        ));
    }
    Ok(())
}

fn valid_receipt_field(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: &str = "019d0000-0000-7000-8000-000000000001";
    const DEPLOYMENT_ID: &str = "deploy-alpha";

    #[test]
    fn receipt_requires_exact_operation_and_deployment_bindings() {
        let receipt = format!(
            r#"{{"schema":1,"operation_id":"{OPERATION_ID}","deployment_id":"{DEPLOYMENT_ID}","user_id":"019d0000-0000-7000-8000-000000000002","email":"admin@example.com"}}"#
        );
        let parsed =
            decode_admin_provision_receipt(&receipt, OPERATION_ID, DEPLOYMENT_ID).expect("receipt");
        assert_eq!(parsed.email, "admin@example.com");

        let error = decode_admin_provision_receipt(&receipt, OPERATION_ID, "deploy-other")
            .expect_err("deployment mismatch");
        assert_eq!(error.code, HOST_ERR_OPERATION_INVALID);
    }

    #[test]
    fn receipt_rejects_unknown_fields_and_multiple_frames() {
        let extra = format!(
            r#"{{"schema":1,"operation_id":"{OPERATION_ID}","deployment_id":"{DEPLOYMENT_ID}","user_id":"019d0000-0000-7000-8000-000000000002","email":"admin@example.com","password":"must-not-appear"}}"#
        );
        assert!(decode_admin_provision_receipt(&extra, OPERATION_ID, DEPLOYMENT_ID).is_err());

        let valid = format!(
            r#"{{"schema":1,"operation_id":"{OPERATION_ID}","deployment_id":"{DEPLOYMENT_ID}","user_id":"019d0000-0000-7000-8000-000000000002","email":"admin@example.com"}}"#
        );
        let error = decode_admin_provision_receipt(
            &format!("{valid}\n{valid}"),
            OPERATION_ID,
            DEPLOYMENT_ID,
        )
        .expect_err("multiple receipts");
        assert_eq!(error.code, crate::target::CONTROL_OUTCOME_UNKNOWN);
    }
}
