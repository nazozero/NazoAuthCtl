//! Credentials and validation for deployment-root administrator provisioning.
//!
//! The password stays zeroizing while it crosses the control-side call chain.
//! The target module is responsible for combining it with the public email at
//! the final fixed-command boundary.

use crate::admin_credentials::{AdminCredentials, validate_admin_credentials};

/// Prepare the password for the target's fixed `admin-provision` command.
/// The target combines it with the non-secret email into the strict JSON file
/// at the final execution boundary; the password is never a command-line or
/// environment value.
pub(crate) fn admin_provision_password_material(
    credentials: &AdminCredentials,
) -> anyhow::Result<crate::target::SecretMaterial> {
    validate_admin_credentials(credentials)?;
    crate::target::SecretMaterial::try_new(credentials.password.as_bytes().to_vec())
        .map_err(|error| anyhow::anyhow!("failed to prepare administrator credentials: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(email: &str, password: &str) -> AdminCredentials {
        AdminCredentials {
            email: email.to_owned(),
            password: zeroize::Zeroizing::new(password.to_owned()),
        }
    }

    #[test]
    fn validation_rejects_invalid_email_and_password() {
        assert!(validate_admin_credentials(&credentials("no-at", "long-enough-password")).is_err());
        assert!(validate_admin_credentials(&credentials("admin@example.com", "short")).is_err());
        assert!(
            validate_admin_credentials(&credentials("admin@example.com", "long-enough-password"))
                .is_ok()
        );
        assert!(
            validate_admin_credentials(&credentials("admin@example.com", &"密".repeat(342)))
                .is_err(),
            "the controller must enforce the server's UTF-8 byte limit"
        );
    }
}
