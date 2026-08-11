//! OpenID Foundation Conformance Suite orchestration boundary.
//!
//! This crate is deliberately an orchestration/client layer. The official
//! conformance suite remains the owner of test definitions and execution
//! semantics; this crate only creates plans, starts the suite's modules,
//! observes the API, and records an evidence-safe report. Official module
//! results are retained verbatim; orchestration only treats `FINISHED` with
//! the Suite's `PASSED` result as a successful module.

mod browser;
mod client;
mod credentials;
mod materializer;
mod matrix;
mod orchestrator;
mod origin;
mod progress;
mod report;
mod secure_file;
mod transport;

pub use browser::{
    BrowserAutomation, BrowserCommand, BrowserDriver, BrowserEntry, BrowserError, BrowserExecutor,
    BrowserLimits, BrowserPolicy, BrowserRunReport, BrowserRunnerState, BrowserSelector,
    BrowserTargetOrigin, BrowserTask, ConformanceBinding, ManagedWebDriver, OpenId4VcBrowserState,
    OpenId4VciError, OpenId4VciIssuerClient, OpenId4VciIssuerConfig, OpenId4VciIssuerDriver,
    OpenId4VciModule, OpenId4VpError, OpenId4VpPresentation, OpenId4VpStartRequest,
    OpenId4VpVerifier, OpenId4VpVerifierClient, WebDriverClient, WebDriverEndpoint,
    parse_browser_entries, parse_browser_entries_owned,
};
pub use client::{
    AuthProbe, CancelOutcome, ClientConfig, DeleteOutcome, ModuleDefinition, ModuleInstance,
    PlanCreated, SuiteClient, SuiteClientError,
};
pub use credentials::{BearerToken, CredentialStore, CredentialStoreError};
pub use materializer::{
    CryptoPolicy, DESCRIPTOR_SCHEMA_VERSION, DescriptorGroup, DescriptorMaterializer,
    DescriptorPlan, DescriptorSource, DescriptorVariant, MAX_DESCRIPTOR_BYTES, MaterializedMatrix,
    MaterializerError, MatrixDescriptor, OnboardingOutput, PreparedMaterialization,
    RoleRequirement, SECURE_BUNDLE_SCHEMA_VERSION, SecureBytes, SecureOnboardingBundle,
};
pub use matrix::{
    MATRIX_SCHEMA_VERSION, MAX_MATRIX_BYTES, MatrixArtifact, MatrixDocument, MatrixError,
    MatrixGroup, MatrixPlan, MatrixSelection, MatrixVariant, SelectedMatrix,
};
pub use orchestrator::{
    ConformanceAutomation, ConformanceRunConfig, ConformanceRunner, MAX_PARALLEL_JOBS,
    OrchestrationError, RunControl, RunSummary,
};
pub use origin::{Origin, OriginError};
pub use progress::{
    GroupProgress, GroupStatus, ProgressEvent, ProgressSink, ProgressSnapshot, StableRenderer,
    TtyRenderer, redacted_variant,
};
pub use report::{
    CleanupFailure, CleanupReport, ConformanceReport, EvidenceError, ModuleReport, PlanReport,
};
pub use transport::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransport, Transport, TransportError,
};
