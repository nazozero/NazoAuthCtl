//! OpenID Foundation Conformance Suite orchestration boundary.
//!
//! This crate is deliberately an orchestration/client layer. The official
//! conformance suite remains the owner of test definitions and execution
//! semantics; this crate only creates plans, starts the suite's modules,
//! observes the API, and records an evidence-safe report. Official module
//! results are retained verbatim; orchestration only treats `FINISHED` with
//! the Suite's `PASSED` result as a successful module.

mod artifact;
mod artifact_discovery;
mod artifact_driver;
mod artifact_plan;
mod browser;
mod ciba_approval;
mod client;
mod credentials;
mod evidence;
mod materializer;
mod matrix;
mod orchestrator;
mod origin;
mod progress;
mod proxy_trust;
mod recovery;
mod report;
mod secure_file;
mod transport;

pub use artifact::{
    ArtifactError, ArtifactTrustPolicy, MAX_ARTIFACT_MATRIX_BYTES, MAX_SIGNED_DRIVER_BYTES,
    OIDF_ARTIFACT_SCHEMA_VERSION, OIDF_DRIVER_ENGINE_PROTOCOL, OIDF_MATRIX_SCHEMA_VERSION,
    OIDF_TRUST_POLICY_SCHEMA_VERSION, OidfArtifactMatrix, OidfArtifactMatrixGroup,
    OidfArtifactMatrixPlan, OidfArtifactMatrixVariant, OidfDriverIdentity, OidfDriverManifest,
    OidfMatrixIdentity, OidfPlanResourceBudget, OidfResourceBounds, OidfSuiteIdentity,
    VerifiedOidfArtifact, VerifiedOidfDriverManifest, read_artifact_driver, read_artifact_matrix,
    read_compact_manifest, verify_oidf_artifact, verify_oidf_driver_manifest, verify_oidf_matrix,
};
pub use artifact_discovery::{
    ArtifactDiscoveryError, CachedOidfArtifact, OIDF_ARTIFACT_CACHE_MAX_ENTRIES,
    OIDF_ARTIFACT_CACHE_MIN_FREE_BYTES, OIDF_ARTIFACT_CACHE_SCHEMA_VERSION, ResolvedOidfArtifact,
    open_cached_oidf_artifact, open_cached_oidf_driver_plan, resolve_oidf_artifact,
};
pub use artifact_driver::{
    MAX_ARTIFACT_DRIVER_BYTES, OIDF_DRIVER_SCHEMA_VERSION, OidfDriverAutomation, OidfDriverHandler,
    OidfDriverLane, OidfDriverProgram,
};
pub use artifact_plan::{
    OidfBoundedRunnerContract, OidfDriverInspectionPlan, OidfDriverPlanEntry, OidfPlanError,
    OidfPlanSelection,
};
pub use browser::{
    BrowserAutomation, BrowserCommand, BrowserDriver, BrowserEntry, BrowserError, BrowserExecutor,
    BrowserLimits, BrowserNavigationDiagnostic, BrowserPolicy, BrowserReviewCaptureContext,
    BrowserReviewModuleIdentity, BrowserReviewScreenshotCapture, BrowserReviewScreenshotReceipt,
    BrowserReviewScreenshotSource, BrowserRunReport, BrowserRunnerState, BrowserSelector,
    BrowserTargetOrigin, BrowserTask, ConformanceBinding, ManagedWebDriver, OpenId4VciError,
    OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver, OpenId4VciModule,
    OpenId4VpCompletionOutcome, OpenId4VpError, OpenId4VpEvidenceBindingDiagnostic,
    OpenId4VpEvidenceContext, OpenId4VpEvidenceRunContext, OpenId4VpEvidenceVerifier,
    OpenId4VpPresentation, OpenId4VpStartRequest, OpenId4VpVerificationEvidence,
    OpenId4VpVerificationReceiptProvenance, OpenId4VpVerifier, OpenId4VpVerifierClient,
    ReviewScreenshotMarker, WebDriverClient, WebDriverEndpoint, WebDriverProtocolDiagnostic,
    parse_browser_entries, parse_browser_entries_owned,
};
pub use ciba_approval::{
    CibaApprovalFailureStage, CibaUserApprovalBridge, CibaUserApprovalClient, CibaUserApprovalError,
};
pub use client::{
    AuthProbe, CancelOutcome, ClientConfig, DeleteOutcome, ModuleDefinition, ModuleInstance,
    PlanCreated, SuiteClient, SuiteClientError,
};
pub use credentials::{BearerToken, CredentialStore, CredentialStoreError};
pub use evidence::{
    EvidenceBundleIdentity, EvidenceBundleReceipt, EvidenceControlIdentity,
    EvidenceControlOperation, EvidenceDeploymentIdentity, EvidenceError, EvidenceRuntimeIdentity,
    EvidenceSourceIdentity, ReviewScreenshotManifestReceipt, validate_ordinary_control_identity,
    validate_private_evidence_directory, write_private_control_evidence_bundle,
    write_review_screenshot_manifest,
};
pub use materializer::{
    ArtifactMaterializationBinding, CryptoPolicy, DESCRIPTOR_SCHEMA_VERSION, DescriptorGroup,
    DescriptorMaterializer, DescriptorPlan, DescriptorSource, DescriptorVariant,
    MAX_DESCRIPTOR_BYTES, MaterializerError, MatrixDescriptor, PreparedMaterialization,
    RoleRequirement, SecureBytes, TenantResourceApplyOutput, TenantResourceManifest,
    TenantResourceManifestResource, TenantResourceMaterializedMatrix,
};
pub use matrix::{
    MATRIX_SCHEMA_VERSION, MAX_MATRIX_BYTES, MatrixArtifact, MatrixDocument, MatrixError,
    MatrixGroup, MatrixPlan, MatrixSelection, MatrixVariant, SelectedMatrix,
};
pub use orchestrator::{
    BOUNDED_PLAN_RUNNER_PROTOCOL, ConformanceAutomation, ConformanceRunConfig, ConformanceRunner,
    MAX_PARALLEL_JOBS, MAX_POLL_TIMEOUT, MAX_POLL_TIMEOUT_SECONDS, OrchestrationError, RunControl,
    RunSummary, SuiteResourceObserver, recover_suite_resources,
};
pub use origin::{Origin, OriginError};
pub use progress::{
    GroupProgress, GroupStatus, ProgressEvent, ProgressSink, ProgressSnapshot, StableRenderer,
    TtyRenderer, redacted_variant,
};
pub use proxy_trust::ProxyTrustGuard;
pub use recovery::{
    ConformanceProxyRecovery, ConformanceRecoveryGuard, ConformanceRecoveryStore,
    OpenId4VpEvidenceTrustAnchor, SuiteRecoveryState, SuiteRetentionCommitResolution,
    SuiteRetentionDeferredReview, SuiteRetentionManifest, SuiteRetentionManifestReceipt,
    SuiteRetentionPlan, SuiteRetentionScreenshotManifest, TenantResourceControlOperation,
    TenantResourceRecoveryBinding, TenantResourceRecoveryPhase,
};
pub use report::{
    CleanupFailure, CleanupReport, ConformanceReport, DeferredReviewPending, ModuleOutcome,
    ModuleReport, PlanReport, ReviewScreenshotReport,
};
pub use transport::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransport, Transport, TransportError,
    TransportFailureStage,
};
