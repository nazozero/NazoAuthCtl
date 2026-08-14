use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use zeroize::Zeroizing;

use crate::{ConformanceReport, VerifiedOidfArtifact};

#[cfg(unix)]
const EVIDENCE_BUNDLE_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRuntimeIdentity {
    OciImage { digest: String },
    HostBinary { sha256: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeploymentIdentity {
    pub deployment_id: String,
    pub target_issuer: String,
    pub release: String,
    pub revision: String,
    pub build_id: String,
    pub runtime: EvidenceRuntimeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSourceIdentity {
    LegacyOperatorMatrix {
        source_release: String,
        matrix_sha256: String,
        suite_origin: String,
    },
    SignedOidfArtifact {
        suite_origin: String,
        artifact: Box<VerifiedOidfArtifact>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleIdentity {
    pub run_jti: String,
    pub deployment: EvidenceDeploymentIdentity,
    pub source: EvidenceSourceIdentity,
    pub outer_cleanup_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleReceipt {
    pub schema: u32,
    pub evidence_jti: String,
    pub directory: PathBuf,
    pub manifest_sha256: String,
    pub module_count: u32,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest<'a> {
    schema: u32,
    evidence_jti: &'a str,
    identity: &'a EvidenceBundleIdentity,
    public_report_file: &'static str,
    public_report_sha256: String,
    modules: Vec<EvidenceModuleManifest>,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceModuleManifest {
    index: u32,
    matrix_plan_id: String,
    suite_plan_id: String,
    module_id: Option<String>,
    test_name: String,
    file: String,
    sha256: String,
}

#[cfg(unix)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateModuleEvidence<'a> {
    schema: u32,
    evidence_jti: &'a str,
    index: u32,
    matrix_plan_id: &'a str,
    suite_plan_id: &'a str,
    module_id: &'a Option<String>,
    test_name: &'a str,
    info: &'a serde_json::Value,
    log: &'a serde_json::Value,
}

pub fn write_private_evidence_bundle(
    report: &ConformanceReport,
    root: &Path,
    identity: &EvidenceBundleIdentity,
) -> Result<EvidenceBundleReceipt, EvidenceError> {
    validate_identity(report, identity)?;
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(EvidenceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        let root =
            crate::secure_file::ensure_directory(root, true).map_err(map_secure_file_error)?;
        let evidence_jti = uuid::Uuid::now_v7().to_string();
        let directory =
            crate::secure_file::ensure_directory(&root.join(format!("run-{evidence_jti}")), true)
                .map_err(map_secure_file_error)?;
        match crate::secure_file::read_bounded(&directory.join("manifest.json"), 1, true) {
            Err(crate::secure_file::SecureFileError::NotFound) => {}
            Ok(_) | Err(crate::secure_file::SecureFileError::Oversize) => {
                return Err(EvidenceError::Conflict);
            }
            Err(error) => return Err(map_secure_file_error(error)),
        }

        let public_report = report
            .to_json_bytes()
            .map_err(|_| EvidenceError::Encoding)?;
        crate::secure_file::write_atomic(&directory.join("report.json"), &public_report, true)
            .map_err(map_secure_file_error)?;

        let mut modules = Vec::with_capacity(report.modules.len());
        for (index, module) in report.modules.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| EvidenceError::Encoding)?;
            let file = format!("module-{index:04}.json");
            let bytes = Zeroizing::new(
                serde_json::to_vec(&PrivateModuleEvidence {
                    schema: EVIDENCE_BUNDLE_SCHEMA,
                    evidence_jti: &evidence_jti,
                    index,
                    matrix_plan_id: &module.matrix_plan_id,
                    suite_plan_id: &module.suite_plan_id,
                    module_id: &module.module_id,
                    test_name: &module.test_name,
                    info: &module.raw_info,
                    log: &module.raw_log,
                })
                .map_err(|_| EvidenceError::Encoding)?,
            );
            crate::secure_file::write_atomic(&directory.join(&file), bytes.as_slice(), true)
                .map_err(map_secure_file_error)?;
            modules.push(EvidenceModuleManifest {
                index,
                matrix_plan_id: module.matrix_plan_id.clone(),
                suite_plan_id: module.suite_plan_id.clone(),
                module_id: module.module_id.clone(),
                test_name: module.test_name.clone(),
                file,
                sha256: sha256(bytes.as_slice()),
            });
        }

        let module_count = u32::try_from(modules.len()).map_err(|_| EvidenceError::Encoding)?;
        let manifest = serde_json::to_vec_pretty(&EvidenceManifest {
            schema: EVIDENCE_BUNDLE_SCHEMA,
            evidence_jti: &evidence_jti,
            identity,
            public_report_file: "report.json",
            public_report_sha256: sha256(&public_report),
            modules,
        })
        .map_err(|_| EvidenceError::Encoding)?;
        crate::secure_file::write_atomic(&directory.join("manifest.json"), &manifest, true)
            .map_err(map_secure_file_error)?;
        Ok(EvidenceBundleReceipt {
            schema: EVIDENCE_BUNDLE_SCHEMA,
            evidence_jti,
            directory,
            manifest_sha256: sha256(&manifest),
            module_count,
        })
    }
}

fn validate_identity(
    report: &ConformanceReport,
    identity: &EvidenceBundleIdentity,
) -> Result<(), EvidenceError> {
    if crate::artifact::validate_identifier(&identity.run_jti, 128).is_err()
        || crate::artifact::validate_identifier(&identity.deployment.deployment_id, 128).is_err()
        || !bounded(&identity.deployment.release, 128)
        || !lower_hex(&identity.deployment.revision, 40)
        || !bounded(&identity.deployment.build_id, 256)
        || identity.deployment.target_issuer.ends_with('/')
    {
        return Err(EvidenceError::Identity);
    }
    url::Url::parse(&identity.deployment.target_issuer)
        .ok()
        .filter(|url| url.scheme() == "https" && url.host_str().is_some())
        .ok_or(EvidenceError::Identity)?;
    match &identity.deployment.runtime {
        EvidenceRuntimeIdentity::OciImage { digest } => {
            let Some(digest) = digest.strip_prefix("sha256:") else {
                return Err(EvidenceError::Identity);
            };
            if !lower_hex(digest, 64) {
                return Err(EvidenceError::Identity);
            }
        }
        EvidenceRuntimeIdentity::HostBinary { sha256 } if !lower_hex(sha256, 64) => {
            return Err(EvidenceError::Identity);
        }
        EvidenceRuntimeIdentity::HostBinary { .. } => {}
    }
    let (matrix_sha256, suite_origin) = match &identity.source {
        EvidenceSourceIdentity::LegacyOperatorMatrix {
            source_release,
            matrix_sha256,
            suite_origin,
        } => {
            if !bounded(source_release, 128) || !lower_hex(matrix_sha256, 64) {
                return Err(EvidenceError::Identity);
            }
            (matrix_sha256, suite_origin)
        }
        EvidenceSourceIdentity::SignedOidfArtifact {
            suite_origin,
            artifact,
        } => {
            if !lower_hex(&artifact.matrix_sha256, 64)
                || !lower_hex(&artifact.driver_manifest_sha256, 64)
                || !lower_hex(&artifact.driver_sha256, 64)
            {
                return Err(EvidenceError::Identity);
            }
            (&artifact.matrix_sha256, suite_origin)
        }
    };
    if report.matrix_digest != *matrix_sha256 || report.suite_origin != *suite_origin {
        return Err(EvidenceError::Identity);
    }
    Ok(())
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn map_secure_file_error(error: crate::secure_file::SecureFileError) -> EvidenceError {
    match error {
        crate::secure_file::SecureFileError::UnsupportedPlatform => {
            EvidenceError::UnsupportedPlatform
        }
        crate::secure_file::SecureFileError::UnsafePath => EvidenceError::UnsafePath,
        crate::secure_file::SecureFileError::NotFound
        | crate::secure_file::SecureFileError::Oversize
        | crate::secure_file::SecureFileError::Io => EvidenceError::Io,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EvidenceError {
    UnsupportedPlatform,
    UnsafePath,
    Identity,
    Conflict,
    Encoding,
    Io,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => {
                "private evidence persistence is unavailable on this platform"
            }
            Self::UnsafePath => "private evidence path is not owner-only",
            Self::Identity => "private evidence identity is incomplete or inconsistent",
            Self::Conflict => "private evidence run directory is already committed",
            Self::Encoding => "private evidence could not be encoded",
            Self::Io => "private evidence persistence failed",
        })
    }
}

impl std::error::Error for EvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::OrchestrationIntegrity;
    use crate::{CleanupReport, ConformanceReport, ModuleOutcome, ModuleReport, ProgressSnapshot};

    fn report() -> ConformanceReport {
        ConformanceReport {
            schema: 3,
            matrix_digest: "c".repeat(64),
            suite_origin: "https://suite.example".to_owned(),
            auth_probe: None,
            errors: Vec::new(),
            local_success: true,
            suite_pass: true,
            human_review_required: false,
            human_review_modules: Vec::new(),
            skipped_modules: Vec::new(),
            failed_modules: Vec::new(),
            incomplete_modules: Vec::new(),
            orchestration_integrity: OrchestrationIntegrity {
                defined_modules: 1,
                created_instances: 1,
                terminal_modules: 1,
                all_modules_instantiated: true,
                all_modules_terminal: true,
                cleanup_complete: true,
            },
            progress: ProgressSnapshot {
                completed: 1,
                total: 1,
                groups: Vec::new(),
                passed_groups: 1,
                review_groups: 0,
                skipped_groups: 0,
                failed_groups: 0,
                running_groups: 0,
                remaining_groups: 0,
                passed: 1,
                reviewed: 0,
                skipped: 0,
                failed: 0,
                running: 0,
                remaining: 0,
                current_profile: None,
                current_variant: None,
                current_test: None,
            },
            plans: Vec::new(),
            modules: vec![ModuleReport {
                matrix_plan_id: "plan-a".to_owned(),
                suite_plan_id: "suite-plan-a".to_owned(),
                module_id: Some("module-a".to_owned()),
                test_name: "test-a".to_owned(),
                terminal: true,
                official_status: Some("FINISHED".to_owned()),
                official_result: Some("PASSED".to_owned()),
                expected_result: None,
                outcome: ModuleOutcome::Passed,
                human_review_required: false,
                blocking_log_results: Vec::new(),
                advisory_log_results: Vec::new(),
                info: serde_json::json!({"status":"FINISHED","result":"PASSED"}),
                log: serde_json::json!({"entries":1,"present":true}),
                raw_info: serde_json::json!({"status":"FINISHED","secret":"private"}),
                raw_log: serde_json::json!([{"message":"raw-private"}]),
            }],
            cleanup: CleanupReport::default(),
        }
    }

    fn identity() -> EvidenceBundleIdentity {
        EvidenceBundleIdentity {
            run_jti: "request-0123456789abcdef0123456789abcdef".to_owned(),
            deployment: EvidenceDeploymentIdentity {
                deployment_id: "deployment-a".to_owned(),
                target_issuer: "https://issuer.example".to_owned(),
                release: "v1.2.3".to_owned(),
                revision: "a".repeat(40),
                build_id: "build-a".to_owned(),
                runtime: EvidenceRuntimeIdentity::HostBinary {
                    sha256: "b".repeat(64),
                },
            },
            source: EvidenceSourceIdentity::LegacyOperatorMatrix {
                source_release: "v5.2.2".to_owned(),
                matrix_sha256: "c".repeat(64),
                suite_origin: "https://suite.example".to_owned(),
            },
            outer_cleanup_complete: true,
        }
    }

    #[test]
    fn identity_must_match_report_before_any_filesystem_access() {
        let mut identity = identity();
        if let EvidenceSourceIdentity::LegacyOperatorMatrix { matrix_sha256, .. } =
            &mut identity.source
        {
            *matrix_sha256 = "d".repeat(64);
        }
        assert_eq!(
            write_private_evidence_bundle(&report(), Path::new("relative"), &identity),
            Err(EvidenceError::Identity)
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn private_evidence_refuses_platforms_without_owner_only_file_proof() {
        assert_eq!(
            write_private_evidence_bundle(&report(), Path::new("relative"), &identity()),
            Err(EvidenceError::UnsupportedPlatform)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unique_run_bundle_commits_manifest_last_and_binds_raw_files() {
        let root = std::env::temp_dir().join(format!("nazoauth-evidence-{}", uuid::Uuid::now_v7()));
        let receipt =
            write_private_evidence_bundle(&report(), &root, &identity()).expect("evidence bundle");
        assert_eq!(receipt.module_count, 1);
        let manifest = std::fs::read(receipt.directory.join("manifest.json")).expect("manifest");
        assert_eq!(sha256(&manifest), receipt.manifest_sha256);
        let module = std::fs::read_to_string(receipt.directory.join("module-0000.json"))
            .expect("private module");
        assert!(module.contains("raw-private"));
        assert!(module.contains(&receipt.evidence_jti));
        std::fs::remove_dir_all(&root).expect("remove isolated test directory");
    }
}
