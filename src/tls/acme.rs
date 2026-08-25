//! Crash-safe ACME HTTP-01 certificate issuance.
//!
//! The ACME account and server-certificate private keys are controller-owned
//! deployment secrets. This module does not own NazoAuth protocol keys and it
//! does not install material into a TLS consumer; installation remains the
//! external-generation provider transaction in the parent module.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use chrono::Utc;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, Key, NewOrder,
    OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    AcmeInstallSource, LoadedProvider, canonical_hostname, canonical_tenant, load_provider, sha256,
};
use crate::{
    cli::{AcmeCertificateInput, AcmeCommand},
    deployment::{DeploymentRecord, DeploymentStore},
    filesystem::{
        atomic_write, ensure_private_directory, read_secure_regular_file, remove_file_durable,
        validate_secure_directory,
    },
};

const CONFIG_SCHEMA: u32 = 2;
pub(super) const CONFIG_PROTOCOL: &str = "nazoauthctl.acme.http01-webroot.v2";
const PLAN_SCHEMA: u32 = 2;
const ACCOUNT_SCHEMA: u32 = 2;
const TRANSACTION_SCHEMA: u32 = 2;
const RECEIPT_SCHEMA: u32 = 2;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_ACCOUNT_BYTES: u64 = 256 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 256 * 1024;
const MAX_RECEIPT_BYTES: u64 = 128 * 1024;
const MAX_CSR_BYTES: u64 = 64 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeConfig {
    schema: u32,
    protocol: String,
    tenant: String,
    hostname: String,
    directory_url: String,
    allowed_origins: Vec<String>,
    terms_of_service_url: String,
    contacts: Vec<String>,
    challenge_webroot: PathBuf,
    directory_trust_anchor: Option<PathBuf>,
    poll_timeout_seconds: u64,
    transaction_ttl_seconds: u64,
}

#[derive(Clone, Debug)]
struct LoadedAcmeConfig {
    config: AcmeConfig,
    sha256: String,
    source_bytes: Vec<u8>,
    directory_trust_anchor: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmePlan {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    acme_protocol: String,
    acme_config_sha256: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    directory_trust_anchor_sha256: Option<String>,
    directory_url: String,
    allowed_origins: Vec<String>,
    terms_of_service_url: String,
    challenge_webroot: PathBuf,
    account_path: PathBuf,
    workspace: PathBuf,
    current_revision: u64,
    target_revision: u64,
    transaction_expires_at: i64,
    steps: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    AccountReady,
    OrderCreated,
    ChallengePublished,
    ChallengeReady,
    CsrReady,
    Finalized,
    Issued,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeTransaction {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    expected_revision: u64,
    target_revision: u64,
    acme_config_sha256: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    directory_trust_anchor_sha256: Option<String>,
    directory_url: String,
    allowed_origins: Vec<String>,
    terms_of_service_url: String,
    account_path: PathBuf,
    workspace: PathBuf,
    order_url: Option<String>,
    challenge_path: Option<PathBuf>,
    challenge_sha256: Option<String>,
    account_key_sha256: Option<String>,
    private_key_sha256: Option<String>,
    csr_sha256: Option<String>,
    certificate_sha256: Option<String>,
    created_at: i64,
    expires_at: i64,
    phase: Phase,
    last_error: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    schema: u32,
    deployment_id: String,
    acme_config_sha256: String,
    directory_url: String,
    allowed_origins: Vec<String>,
    contacts_sha256: String,
    account_key_sha256: String,
    created_at: i64,
    credentials: AccountCredentials,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeReceipt {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    revision: u64,
    acme_protocol: String,
    acme_config_sha256: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    directory_trust_anchor_sha256: Option<String>,
    directory_url: String,
    allowed_origins: Vec<String>,
    terms_of_service_url: String,
    account_id: String,
    account_key_sha256: String,
    order_url: String,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_sha256: String,
    private_key_sha256: String,
    leaf_certificate_sha256: String,
    material_sha256: String,
    certificate_not_after: i64,
    transaction_created_at: i64,
    transaction_expires_at: i64,
    issued_at: i64,
}

struct LoadedAcmeReceipt {
    receipt: AcmeReceipt,
    receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AbortedTransaction {
    schema: u32,
    transaction: AcmeTransaction,
    reason: String,
    aborted_at: i64,
}

mod http_client;

use http_client::{AuthorityPolicy, build_http_client, validate_https_url};

pub(super) fn run(
    selector: Option<&str>,
    command: AcmeCommand,
    require_root: impl Fn() -> anyhow::Result<()>,
    confirm: impl Fn(bool, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    require_root()?;
    let store = DeploymentStore::system();
    match command {
        AcmeCommand::Plan(input) => plan(&store, selector, &input),
        AcmeCommand::Issue {
            input,
            agree_terms,
            yes,
        } => {
            if !agree_terms {
                bail!("tls acme issue requires explicit --agree-terms");
            }
            confirm(
                yes,
                "create or reuse an ACME account and issue a public TLS certificate",
            )?;
            issue(&store, selector, &input)
        }
        AcmeCommand::Recover {
            tenant,
            hostname,
            yes,
        } => {
            confirm(yes, "resume or safely retire the pending ACME issuance")?;
            recover(&store, selector, &tenant, &hostname)
        }
        AcmeCommand::Show { tenant, hostname } => show(&store, selector, &tenant, &hostname),
    }
}

pub(super) fn current_install_source(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    provider: &LoadedProvider,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<AcmeInstallSource> {
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    ensure_no_pending(store, record, &tenant, &hostname)?;
    let loaded = load_receipt_record(store, record, &tenant, &hostname)?
        .context("no current ACME issuance receipt exists for this binding")?;
    let receipt = loaded.receipt;
    validate_install_authority(
        &receipt,
        record.declaration_revision,
        &provider.config_sha256,
        &provider.trust_anchors_sha256,
    )?;
    Ok(AcmeInstallSource {
        receipt_sha256: loaded.receipt_sha256,
        issuance_jti: receipt.jti,
        issuance_declaration_revision: receipt.declaration_revision,
        issuance_revision: receipt.revision,
        acme_protocol: receipt.acme_protocol,
        acme_config_sha256: receipt.acme_config_sha256,
        certificate_path: receipt.certificate_path,
        private_key_path: receipt.private_key_path,
        certificate_sha256: receipt.certificate_sha256,
        private_key_sha256: receipt.private_key_sha256,
        leaf_certificate_sha256: receipt.leaf_certificate_sha256,
        material_sha256: receipt.material_sha256,
        certificate_not_after: receipt.certificate_not_after,
        issued_at: receipt.issued_at,
    })
}

fn validate_install_authority(
    receipt: &AcmeReceipt,
    declaration_revision: u64,
    provider_config_sha256: &str,
    trust_anchors_sha256: &str,
) -> anyhow::Result<()> {
    if receipt.declaration_revision != declaration_revision {
        bail!("current ACME receipt declaration revision differs from the deployment");
    }
    if receipt.provider_config_sha256 != provider_config_sha256
        || receipt.trust_anchors_sha256 != trust_anchors_sha256
    {
        bail!("current ACME receipt provider authority differs from the install provider");
    }
    Ok(())
}

fn plan(
    store: &DeploymentStore,
    selector: Option<&str>,
    input: &AcmeCertificateInput,
) -> anyhow::Result<()> {
    let record = store.resolve(selector, true)?;
    let provider = load_provider(
        store,
        &input.provider_config,
        &input.tenant,
        &input.hostname,
    )?;
    let acme = load_config(
        store,
        &input.acme_config,
        &provider,
        &input.tenant,
        &input.hostname,
    )?;
    ensure_no_pending(store, &record, &input.tenant, &input.hostname)?;
    let current = load_receipt(store, &record, &input.tenant, &input.hostname)?;
    let plan = build_plan(store, &record, &provider, &acme, current.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn issue(
    store: &DeploymentStore,
    selector: Option<&str>,
    input: &AcmeCertificateInput,
) -> anyhow::Result<()> {
    let record = store.resolve(selector, true)?;
    let provider = load_provider(
        store,
        &input.provider_config,
        &input.tenant,
        &input.hostname,
    )?;
    let acme = load_config(
        store,
        &input.acme_config,
        &provider,
        &input.tenant,
        &input.hostname,
    )?;
    let tenant = canonical_tenant(&input.tenant)?;
    let hostname = canonical_hostname(&input.hostname)?;
    let _deployment_lock = store.deployment_shared_lock(&record.deployment_id)?;
    let record = store.reload_locked(&record)?;
    let _challenge_lock = store.shared_resource_lock(&challenge_lock_id(&acme.config))?;
    ensure_no_pending(store, &record, &tenant, &hostname)?;
    let current = load_receipt(store, &record, &tenant, &hostname)?;
    let plan = build_plan(store, &record, &provider, &acme, current.as_ref())?;
    ensure_private_directory(&plan.workspace, "ACME issuance workspace")?;
    persist_config_snapshots(input, &provider, &acme, &plan.workspace)?;
    let mut transaction = AcmeTransaction {
        schema: TRANSACTION_SCHEMA,
        jti: plan.jti,
        deployment_id: plan.deployment_id,
        declaration_revision: plan.declaration_revision,
        tenant,
        hostname,
        expected_revision: plan.current_revision,
        target_revision: plan.target_revision,
        acme_config_sha256: plan.acme_config_sha256,
        provider_config_sha256: plan.provider_config_sha256,
        trust_anchors_sha256: plan.trust_anchors_sha256,
        directory_trust_anchor_sha256: plan.directory_trust_anchor_sha256,
        directory_url: plan.directory_url,
        allowed_origins: plan.allowed_origins,
        terms_of_service_url: plan.terms_of_service_url,
        account_path: plan.account_path,
        workspace: plan.workspace,
        order_url: None,
        challenge_path: None,
        challenge_sha256: None,
        account_key_sha256: None,
        private_key_sha256: None,
        csr_sha256: None,
        certificate_sha256: None,
        created_at: Utc::now().timestamp(),
        expires_at: plan.transaction_expires_at,
        phase: Phase::Prepared,
        last_error: None,
    };
    persist_pending(store, &transaction)?;
    drive_transaction(store, &record, &provider, &acme, &mut transaction)
}

fn recover(
    store: &DeploymentStore,
    selector: Option<&str>,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let record = store.resolve(selector, true)?;
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    let mut transaction = load_pending(store, &record, &tenant, &hostname)?
        .context("no pending ACME issuance exists for this binding")?;
    let _deployment_lock = store.deployment_shared_lock(&record.deployment_id)?;
    let record = store.reload_locked(&record)?;
    validate_transaction_binding(store, &transaction, &record, &tenant, &hostname)?;
    let config_path = transaction.workspace.join("acme-config.json");
    let provider_path = transaction.workspace.join("provider-config.json");
    let provider = load_provider_snapshot(store, &provider_path, &tenant, &hostname, &transaction)?;
    let acme = load_snapshot_config(
        store,
        &config_path,
        &provider,
        &tenant,
        &hostname,
        &transaction,
    )?;
    if acme.sha256 != transaction.acme_config_sha256
        || provider.config_sha256 != transaction.provider_config_sha256
        || provider.trust_anchors_sha256 != transaction.trust_anchors_sha256
        || acme.directory_trust_anchor.as_deref().map(sha256)
            != transaction.directory_trust_anchor_sha256
    {
        bail!("ACME recovery configuration differs from the journal binding");
    }
    validate_transaction_config(&transaction, &provider, &acme)?;
    let _challenge_lock = store.shared_resource_lock(&challenge_lock_id(&acme.config))?;
    let current = load_receipt(store, &record, &tenant, &hostname)?;
    if let Some(receipt) = current
        .as_ref()
        .filter(|receipt| receipt.jti == transaction.jti)
    {
        validate_receipt_transaction(receipt, &transaction)?;
        cleanup_challenge(&transaction)?;
        archive_transaction(store, &transaction)?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        return Ok(());
    }
    validate_previous_receipt(&transaction, current.as_ref())?;
    if Utc::now().timestamp() > transaction.expires_at {
        abort_transaction(store, &mut transaction, "transaction-expired")?;
        bail!("ACME issuance expired; challenge and pending journal were safely retired")
    }
    drive_transaction(store, &record, &provider, &acme, &mut transaction)
}

fn show(
    store: &DeploymentStore,
    selector: Option<&str>,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let record = store.resolve(selector, false)?;
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    let pending = load_pending(store, &record, &tenant, &hostname)?;
    if let Some(transaction) = &pending {
        validate_transaction_binding(store, transaction, &record, &tenant, &hostname)?;
    }
    let receipt = load_receipt(store, &record, &tenant, &hostname)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": 1,
            "deployment_id": record.deployment_id,
            "tenant": tenant,
            "hostname": hostname,
            "pending": pending,
            "receipt": receipt,
        }))?
    );
    Ok(())
}

fn load_config(
    store: &DeploymentStore,
    path: &Path,
    provider: &LoadedProvider,
    requested_tenant: &str,
    requested_hostname: &str,
) -> anyhow::Result<LoadedAcmeConfig> {
    let bytes = read_secure_regular_file(path, "ACME configuration", false, MAX_CONFIG_BYTES)?;
    let config: AcmeConfig =
        serde_json::from_slice(&bytes).context("ACME configuration is invalid")?;
    let directory_trust_anchor = load_directory_trust_anchor(&config)?;
    validate_config(
        store,
        &config,
        provider,
        requested_tenant,
        requested_hostname,
    )?;
    Ok(LoadedAcmeConfig {
        config,
        sha256: sha256(&bytes),
        source_bytes: bytes.to_vec(),
        directory_trust_anchor,
    })
}

fn load_snapshot_config(
    store: &DeploymentStore,
    path: &Path,
    provider: &LoadedProvider,
    requested_tenant: &str,
    requested_hostname: &str,
    transaction: &AcmeTransaction,
) -> anyhow::Result<LoadedAcmeConfig> {
    let bytes =
        read_secure_regular_file(path, "ACME configuration snapshot", true, MAX_CONFIG_BYTES)?;
    let config: AcmeConfig =
        serde_json::from_slice(&bytes).context("ACME configuration snapshot is invalid")?;
    let snapshot_path = transaction.workspace.join("directory-trust-anchor.pem");
    let directory_trust_anchor = match &transaction.directory_trust_anchor_sha256 {
        Some(expected) => {
            if config.directory_trust_anchor.is_none() {
                bail!("ACME journal binds a directory trust anchor absent from its configuration");
            }
            let root = read_secure_regular_file(
                &snapshot_path,
                "ACME directory trust anchor snapshot",
                true,
                MAX_CERTIFICATE_BYTES,
            )?;
            if sha256(&root) != *expected {
                bail!("ACME directory trust anchor snapshot differs from the journal binding");
            }
            super::material::root_store_from_pem(&root)?;
            Some(root.to_vec())
        }
        None => {
            if config.directory_trust_anchor.is_some() {
                bail!("ACME configuration requires an unbound directory trust anchor");
            }
            None
        }
    };
    validate_config(
        store,
        &config,
        provider,
        requested_tenant,
        requested_hostname,
    )?;
    Ok(LoadedAcmeConfig {
        config,
        sha256: sha256(&bytes),
        source_bytes: bytes.to_vec(),
        directory_trust_anchor,
    })
}

fn load_directory_trust_anchor(config: &AcmeConfig) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(path) = &config.directory_trust_anchor else {
        return Ok(None);
    };
    let root = read_secure_regular_file(
        path,
        "ACME directory trust anchor",
        false,
        MAX_CERTIFICATE_BYTES,
    )?;
    super::material::root_store_from_pem(&root)?;
    Ok(Some(root.to_vec()))
}

fn validate_config(
    store: &DeploymentStore,
    config: &AcmeConfig,
    provider: &LoadedProvider,
    requested_tenant: &str,
    requested_hostname: &str,
) -> anyhow::Result<()> {
    if config.schema != CONFIG_SCHEMA || config.protocol != CONFIG_PROTOCOL {
        bail!("unsupported ACME configuration schema or protocol");
    }
    let tenant = canonical_tenant(requested_tenant)?;
    let hostname = canonical_hostname(requested_hostname)?;
    if canonical_tenant(&config.tenant)? != tenant
        || canonical_hostname(&config.hostname)? != hostname
        || canonical_tenant(&provider.config.tenant)? != tenant
        || canonical_hostname(&provider.config.hostname)? != hostname
    {
        bail!("ACME, provider, and requested tenant/hostname bindings differ");
    }
    validate_https_url(&config.directory_url, "ACME directory URL")?;
    let authority = AuthorityPolicy::from_config(&config.allowed_origins)?;
    authority.require_url(&config.directory_url, "ACME directory URL")?;
    validate_https_url(&config.terms_of_service_url, "ACME terms-of-service URL")?;
    if config.contacts.is_empty() || config.contacts.len() > 8 {
        bail!("ACME contacts must contain between one and eight mailto URIs");
    }
    for contact in &config.contacts {
        let url = Url::parse(contact).context("ACME contact is not a valid URI")?;
        if url.scheme() != "mailto"
            || !url.cannot_be_a_base()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().is_empty()
            || contact.len() > 320
        {
            bail!("ACME contacts must be plain mailto URIs");
        }
    }
    validate_absolute_normalized(&config.challenge_webroot, "ACME challenge webroot")?;
    validate_secure_directory(&config.challenge_webroot, "ACME challenge webroot", false)?;
    let metadata = fs::symlink_metadata(&config.challenge_webroot)
        .context("ACME challenge webroot must already exist")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("ACME challenge webroot must be a real directory");
    }
    for root in [
        &store.config_root,
        &store.state_root,
        &provider.config.material_root,
    ] {
        if config.challenge_webroot.starts_with(root) || root.starts_with(&config.challenge_webroot)
        {
            bail!("ACME challenge webroot must not overlap controller or certificate state");
        }
    }
    if let Some(root) = &config.directory_trust_anchor {
        validate_absolute_normalized(root, "ACME directory trust anchor")?;
    }
    if !(10..=600).contains(&config.poll_timeout_seconds)
        || !(60..=3600).contains(&config.transaction_ttl_seconds)
        || config.poll_timeout_seconds >= config.transaction_ttl_seconds
    {
        bail!("ACME polling and transaction timeout bounds are invalid");
    }
    Ok(())
}

fn build_plan(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
    current: Option<&AcmeReceipt>,
) -> anyhow::Result<AcmePlan> {
    let tenant = canonical_tenant(&acme.config.tenant)?;
    let hostname = canonical_hostname(&acme.config.hostname)?;
    let jti = Uuid::now_v7().to_string();
    let now = Utc::now().timestamp();
    let expires_at = now
        .checked_add(i64::try_from(acme.config.transaction_ttl_seconds)?)
        .context("ACME transaction expiry overflow")?;
    let current_revision = current.map_or(0, |receipt| receipt.revision);
    let workspace = acme_binding_directory(store, &record.deployment_id, &tenant, &hostname)
        .join("transactions")
        .join(&jti);
    Ok(AcmePlan {
        schema: PLAN_SCHEMA,
        jti,
        deployment_id: record.deployment_id.clone(),
        declaration_revision: record.declaration_revision,
        tenant,
        hostname,
        acme_protocol: CONFIG_PROTOCOL.to_owned(),
        acme_config_sha256: acme.sha256.clone(),
        provider_config_sha256: provider.config_sha256.clone(),
        trust_anchors_sha256: provider.trust_anchors_sha256.clone(),
        directory_trust_anchor_sha256: acme.directory_trust_anchor.as_deref().map(sha256),
        directory_url: acme.config.directory_url.clone(),
        allowed_origins: acme.config.allowed_origins.clone(),
        terms_of_service_url: acme.config.terms_of_service_url.clone(),
        challenge_webroot: acme.config.challenge_webroot.clone(),
        account_path: account_path(store, record, acme),
        workspace,
        current_revision,
        target_revision: current_revision
            .checked_add(1)
            .context("ACME issuance revision overflow")?,
        transaction_expires_at: expires_at,
        steps: vec![
            "persist-config-and-transaction",
            "create-or-restore-bound-account",
            "create-or-resume-exact-identifier-order",
            "publish-http-01-challenge",
            "poll-authorization",
            "persist-key-and-csr",
            "finalize-order",
            "validate-chain-san-key-expiry-usage",
            "commit-receipt-and-retire-challenge",
        ],
    })
}

fn persist_config_snapshots(
    input: &AcmeCertificateInput,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
    workspace: &Path,
) -> anyhow::Result<()> {
    let provider_bytes = read_secure_regular_file(
        &input.provider_config,
        "TLS provider configuration snapshot",
        false,
        super::MAX_PROVIDER_BYTES,
    )?;
    if sha256(&provider_bytes) != provider.config_sha256 {
        bail!("TLS provider configuration changed while ACME issuance was prepared");
    }
    atomic_write(
        &workspace.join("acme-config.json"),
        &acme.source_bytes,
        0o600,
    )?;
    if let Some(root) = &acme.directory_trust_anchor {
        atomic_write(&workspace.join("directory-trust-anchor.pem"), root, 0o600)?;
    }
    atomic_write(
        &workspace.join("provider-trust-anchors.pem"),
        &provider.trust_anchors,
        0o600,
    )?;
    atomic_write(
        &workspace.join("provider-config.json"),
        &provider_bytes,
        0o600,
    )
}

fn drive_transaction(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
    transaction: &mut AcmeTransaction,
) -> anyhow::Result<()> {
    validate_transaction_binding(
        store,
        transaction,
        record,
        &transaction.tenant,
        &transaction.hostname,
    )?;
    validate_transaction_config(transaction, provider, acme)?;
    let current = load_receipt(store, record, &transaction.tenant, &transaction.hostname)?;
    validate_previous_receipt(transaction, current.as_ref())?;
    ensure_transaction_fresh(transaction)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create ACME runtime")?;
    let remaining = transaction
        .expires_at
        .checked_sub(Utc::now().timestamp())
        .filter(|seconds| *seconds > 0)
        .context("ACME transaction expired")?;
    let result = runtime
        .block_on(tokio::time::timeout(
            Duration::from_secs(u64::try_from(remaining)?),
            drive_async(store, record, provider, acme, transaction),
        ))
        .context("ACME transaction reached its durable expiry")
        .and_then(|result| result);
    if let Err(error) = result {
        transaction.last_error = Some(format!("{error:#}"));
        persist_pending(store, transaction)?;
        let cleanup = cleanup_challenge(transaction);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => {
                Err(error.context(format!("ACME challenge cleanup also failed: {cleanup:#}")))
            }
        };
    }
    Ok(())
}

async fn drive_async(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
    transaction: &mut AcmeTransaction,
) -> anyhow::Result<()> {
    let account = load_or_create_account(store, acme, transaction).await?;
    if transaction.phase == Phase::Prepared {
        transaction.phase = Phase::AccountReady;
        transaction.last_error = None;
        persist_pending(store, transaction)?;
    }
    ensure_transaction_fresh(transaction)?;

    let mut order = match &transaction.order_url {
        Some(url) => account
            .order(url.clone())
            .await
            .context("failed to resume ACME order")?,
        None => {
            let identifiers = [Identifier::Dns(transaction.hostname.clone())];
            let order = account
                .new_order(&NewOrder::new(&identifiers))
                .await
                .context("failed to create ACME order")?;
            AuthorityPolicy::from_config(&acme.config.allowed_origins)?
                .require_url(order.url(), "server-issued ACME order URL")?;
            transaction.order_url = Some(order.url().to_owned());
            transaction.phase = Phase::OrderCreated;
            persist_pending(store, transaction)?;
            order
        }
    };
    validate_order_identifiers(&mut order, &transaction.hostname).await?;
    ensure_transaction_fresh(transaction)?;

    let status = order.refresh().await?.status;
    match status {
        OrderStatus::Pending => {
            satisfy_authorization(store, acme, transaction, &mut order).await?;
            let status = order
                .poll_ready(&retry_policy(acme))
                .await
                .context("ACME order did not become ready")?;
            if status != OrderStatus::Ready {
                bail!("ACME order became invalid during authorization");
            }
        }
        OrderStatus::Ready | OrderStatus::Processing | OrderStatus::Valid => {}
        OrderStatus::Invalid => bail!("ACME order is invalid"),
    }
    cleanup_challenge(transaction)?;
    ensure_transaction_fresh(transaction)?;

    let csr = load_or_create_csr(store, transaction)?;
    if matches!(order.state().status, OrderStatus::Ready) {
        order
            .finalize_csr(&csr)
            .await
            .context("failed to finalize ACME order")?;
        transaction.phase = Phase::Finalized;
        persist_pending(store, transaction)?;
    }
    let certificate = match order.state().status {
        OrderStatus::Valid => order
            .certificate()
            .await
            .context("failed to fetch ACME certificate")?
            .context("ACME order is valid but returned no certificate")?,
        OrderStatus::Processing | OrderStatus::Ready => order
            .poll_certificate(&retry_policy(acme))
            .await
            .context("ACME certificate issuance did not complete")?,
        OrderStatus::Pending => bail!("ACME order regressed to pending after authorization"),
        OrderStatus::Invalid => bail!("ACME order became invalid during finalization"),
    };
    ensure_transaction_fresh(transaction)?;
    commit_issued_material(
        store,
        record,
        provider,
        acme,
        transaction,
        &account,
        order.url(),
        certificate.as_bytes(),
    )
}

async fn load_or_create_account(
    store: &DeploymentStore,
    acme: &LoadedAcmeConfig,
    transaction: &mut AcmeTransaction,
) -> anyhow::Result<Account> {
    let authority = AuthorityPolicy::from_config(&acme.config.allowed_origins)?;
    let roots = acme
        .directory_trust_anchor
        .as_deref()
        .map(super::material::root_store_from_pem)
        .transpose()?;
    let builder = Account::builder_with_http(build_http_client(authority.clone(), roots)?);
    match load_account(&transaction.account_path)? {
        Some(account_record) => {
            validate_account_record(&account_record, transaction, acme)?;
            bind_account_key_digest(store, transaction, &account_record.account_key_sha256)?;
            retire_account_key_draft(&transaction.account_path)?;
            let account = builder
                .from_credentials(account_record.credentials)
                .await
                .context("failed to restore ACME account")?;
            authority.require_url(account.id(), "restored ACME account URL")?;
            Ok(account)
        }
        None => {
            let contacts = acme
                .config
                .contacts
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let (key, key_der, key_digest) = load_or_create_account_key(transaction)?;
            bind_account_key_digest(store, transaction, &key_digest)?;
            let (account, credentials) = builder
                .create_from_key(
                    (key, PrivateKeyDer::Pkcs8(key_der)),
                    acme.config.directory_url.clone(),
                )
                .await
                .context("failed to create ACME account")?;
            authority.require_url(account.id(), "server-issued ACME account URL")?;
            account
                .update_contacts(&contacts)
                .await
                .context("failed to bind ACME account contacts")?;
            let account_record = AccountRecord {
                schema: ACCOUNT_SCHEMA,
                deployment_id: transaction.deployment_id.clone(),
                acme_config_sha256: acme.sha256.clone(),
                directory_url: acme.config.directory_url.clone(),
                allowed_origins: acme.config.allowed_origins.clone(),
                contacts_sha256: contacts_sha256(&acme.config.contacts),
                account_key_sha256: key_digest,
                created_at: Utc::now().timestamp(),
                credentials,
            };
            let serialized = Zeroizing::new(serde_json::to_vec_pretty(&account_record)?);
            atomic_write(&transaction.account_path, &serialized, 0o600)?;
            retire_account_key_draft(&transaction.account_path)?;
            Ok(account)
        }
    }
}

fn load_account(path: &Path) -> anyhow::Result<Option<AccountRecord>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let bytes = read_secure_regular_file(
                path,
                "ACME account credentials",
                true,
                MAX_ACCOUNT_BYTES,
            )?;
            let record =
                serde_json::from_slice(&bytes).context("ACME account credentials are invalid")?;
            Ok(Some(record))
        }
        Ok(_) => bail!("ACME account credentials must be a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to inspect ACME account credentials"),
    }
}

fn validate_account_record(
    account: &AccountRecord,
    transaction: &AcmeTransaction,
    acme: &LoadedAcmeConfig,
) -> anyhow::Result<()> {
    if account.schema != ACCOUNT_SCHEMA
        || account.deployment_id != transaction.deployment_id
        || account.acme_config_sha256 != acme.sha256
        || account.directory_url != acme.config.directory_url
        || account.allowed_origins != acme.config.allowed_origins
        || account.contacts_sha256 != contacts_sha256(&acme.config.contacts)
        || transaction
            .account_key_sha256
            .as_ref()
            .is_some_and(|digest| digest != &account.account_key_sha256)
    {
        bail!("ACME account credentials do not match the deployment and configuration binding");
    }
    Ok(())
}

fn account_key_draft_path(account_path: &Path) -> PathBuf {
    account_path.with_extension("key.pkcs8")
}

fn load_or_create_account_key(
    transaction: &AcmeTransaction,
) -> anyhow::Result<(Key, PrivatePkcs8KeyDer<'static>, String)> {
    let path = account_key_draft_path(&transaction.account_path);
    let bytes = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            read_secure_regular_file(
                &path,
                "ACME account private-key draft",
                true,
                super::MAX_PRIVATE_KEY_BYTES,
            )?
        }
        Ok(_) => bail!("ACME account private-key draft must be a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (_key, generated) =
                Key::generate_pkcs8().context("failed to generate ACME account private key")?;
            let bytes = Zeroizing::new(generated.secret_pkcs8_der().to_vec());
            atomic_write(&path, &bytes, 0o600)?;
            bytes
        }
        Err(error) => return Err(error).context("failed to inspect ACME account key draft"),
    };
    let digest = sha256(&bytes);
    if let Some(expected) = &transaction.account_key_sha256
        && *expected != digest
    {
        bail!("ACME account private-key draft differs from the journal binding");
    }
    let key = Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(bytes.as_slice().to_vec()))
        .context("ACME account private-key draft is invalid")?;
    Ok((
        key,
        PrivatePkcs8KeyDer::from(bytes.as_slice().to_vec()),
        digest,
    ))
}

fn bind_account_key_digest(
    store: &DeploymentStore,
    transaction: &mut AcmeTransaction,
    digest: &str,
) -> anyhow::Result<()> {
    validate_digest(digest, "ACME account private-key digest")?;
    match &transaction.account_key_sha256 {
        Some(expected) if expected != digest => {
            bail!("ACME account private key differs from the journal binding")
        }
        Some(_) => Ok(()),
        None => {
            transaction.account_key_sha256 = Some(digest.to_owned());
            persist_pending(store, transaction)
        }
    }
}

fn retire_account_key_draft(account_path: &Path) -> anyhow::Result<()> {
    let path = account_key_draft_path(account_path);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect ACME account key draft"),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            remove_file_durable(&path)
        }
        Ok(_) => bail!("ACME account key draft must be a regular non-symlink file"),
    }
}

async fn validate_order_identifiers(
    order: &mut instant_acme::Order,
    hostname: &str,
) -> anyhow::Result<()> {
    let mut count = 0_u8;
    let mut identifiers = order.identifiers();
    while let Some(identifier) = identifiers.next().await {
        let identifier = identifier.context("failed to load ACME order identifier")?;
        count = count
            .checked_add(1)
            .context("too many ACME order identifiers")?;
        match (identifier.wildcard, identifier.identifier) {
            (false, Identifier::Dns(name)) if canonical_hostname(name)? == hostname => {}
            _ => bail!("ACME order contains an unexpected or wildcard identifier"),
        }
    }
    if count != 1 {
        bail!("ACME order must contain exactly one DNS identifier");
    }
    Ok(())
}

async fn satisfy_authorization(
    store: &DeploymentStore,
    acme: &LoadedAcmeConfig,
    transaction: &mut AcmeTransaction,
    order: &mut instant_acme::Order,
) -> anyhow::Result<()> {
    let mut authorizations = order.authorizations();
    let mut authorization = authorizations
        .next()
        .await
        .context("ACME order has no authorization")?
        .context("failed to load ACME authorization")?;
    // `validate_order_identifiers` has already consumed this same order's
    // authorization list and required exactly one entry.
    let identifier = authorization.identifier();
    if identifier.wildcard
        || !matches!(identifier.identifier, Identifier::Dns(name) if canonical_hostname(name).ok().as_deref() == Some(transaction.hostname.as_str()))
    {
        bail!("ACME authorization identifier differs from the transaction binding");
    }
    match authorization.status {
        AuthorizationStatus::Valid => return Ok(()),
        AuthorizationStatus::Pending => {}
        status => bail!("ACME authorization cannot proceed from status {status:?}"),
    }
    let mut challenge = authorization
        .challenge(ChallengeType::Http01)
        .context("ACME authorization offers no HTTP-01 challenge")?;
    validate_challenge_token(&challenge.token)?;
    let response = challenge.key_authorization().as_str().as_bytes().to_vec();
    let path = acme.config.challenge_webroot.join(&challenge.token);
    transaction.challenge_path = Some(path.clone());
    transaction.challenge_sha256 = Some(sha256(&response));
    persist_pending(store, transaction)?;
    atomic_write(&path, &response, 0o644)?;
    transaction.phase = Phase::ChallengePublished;
    persist_pending(store, transaction)?;
    ensure_transaction_fresh(transaction)?;
    challenge
        .set_ready()
        .await
        .context("failed to notify ACME server that HTTP-01 is ready")?;
    transaction.phase = Phase::ChallengeReady;
    persist_pending(store, transaction)
}

fn load_or_create_csr(
    store: &DeploymentStore,
    transaction: &mut AcmeTransaction,
) -> anyhow::Result<Vec<u8>> {
    let key_path = transaction.workspace.join("private-key.pem");
    let csr_path = transaction.workspace.join("request.csr.der");
    match (&transaction.private_key_sha256, &transaction.csr_sha256) {
        (Some(key_digest), Some(csr_digest)) => {
            let key = read_secure_regular_file(
                &key_path,
                "ACME server private key",
                true,
                super::MAX_PRIVATE_KEY_BYTES,
            )?;
            let csr = read_secure_regular_file(
                &csr_path,
                "ACME certificate request",
                true,
                MAX_CSR_BYTES,
            )?;
            if sha256(&key) != *key_digest || sha256(&csr) != *csr_digest {
                bail!("ACME private key or CSR differs from the journal binding");
            }
            KeyPair::from_pem(std::str::from_utf8(&key)?)
                .context("ACME server private key is invalid")?;
            Ok(csr.to_vec())
        }
        (None, None) => {
            let key = KeyPair::generate().context("failed to generate ACME server private key")?;
            let mut params = CertificateParams::new(vec![transaction.hostname.clone()])
                .context("failed to create ACME certificate parameters")?;
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let csr = params
                .serialize_request(&key)
                .context("failed to generate ACME CSR")?;
            let key_pem = Zeroizing::new(key.serialize_pem());
            atomic_write(&key_path, key_pem.as_bytes(), 0o600)?;
            atomic_write(&csr_path, csr.der(), 0o600)?;
            transaction.private_key_sha256 = Some(sha256(key_pem.as_bytes()));
            transaction.csr_sha256 = Some(sha256(csr.der()));
            transaction.phase = Phase::CsrReady;
            persist_pending(store, transaction)?;
            Ok(csr.der().to_vec())
        }
        _ => bail!("ACME journal has a partial private-key/CSR binding"),
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_issued_material(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
    transaction: &mut AcmeTransaction,
    account: &Account,
    order_url: &str,
    certificate: &[u8],
) -> anyhow::Result<()> {
    if certificate.len() as u64 > MAX_CERTIFICATE_BYTES {
        bail!("ACME certificate chain exceeds the byte limit");
    }
    let certificate_path = transaction.workspace.join("fullchain.pem");
    let private_key_path = transaction.workspace.join("private-key.pem");
    atomic_write(&certificate_path, certificate, 0o644)?;
    transaction.certificate_sha256 = Some(sha256(certificate));
    persist_pending(store, transaction)?;
    let material = super::material::load_and_validate_material(
        &certificate_path,
        &private_key_path,
        &transaction.hostname,
        provider,
    )?;
    let authority = AuthorityPolicy::from_config(&acme.config.allowed_origins)?;
    authority.require_url(account.id(), "ACME account URL")?;
    authority.require_url(order_url, "ACME order URL")?;
    let receipt = AcmeReceipt {
        schema: RECEIPT_SCHEMA,
        jti: transaction.jti.clone(),
        deployment_id: transaction.deployment_id.clone(),
        declaration_revision: transaction.declaration_revision,
        tenant: transaction.tenant.clone(),
        hostname: transaction.hostname.clone(),
        revision: transaction.target_revision,
        acme_protocol: CONFIG_PROTOCOL.to_owned(),
        acme_config_sha256: acme.sha256.clone(),
        provider_config_sha256: provider.config_sha256.clone(),
        trust_anchors_sha256: provider.trust_anchors_sha256.clone(),
        directory_trust_anchor_sha256: transaction.directory_trust_anchor_sha256.clone(),
        directory_url: acme.config.directory_url.clone(),
        allowed_origins: acme.config.allowed_origins.clone(),
        terms_of_service_url: acme.config.terms_of_service_url.clone(),
        account_id: account.id().to_owned(),
        account_key_sha256: transaction
            .account_key_sha256
            .clone()
            .context("ACME journal has no account-key digest")?,
        order_url: order_url.to_owned(),
        certificate_path,
        private_key_path,
        certificate_sha256: sha256(certificate),
        private_key_sha256: transaction
            .private_key_sha256
            .clone()
            .context("ACME journal has no private-key digest")?,
        leaf_certificate_sha256: material.leaf_sha256,
        material_sha256: material.material_sha256,
        certificate_not_after: material.not_after,
        transaction_created_at: transaction.created_at,
        transaction_expires_at: transaction.expires_at,
        issued_at: Utc::now().timestamp(),
    };
    let current = load_receipt(store, record, &transaction.tenant, &transaction.hostname)?;
    validate_previous_receipt(transaction, current.as_ref())?;
    persist_receipt(store, transaction, &receipt)?;
    transaction.phase = Phase::Issued;
    transaction.last_error = None;
    persist_pending(store, transaction)?;
    cleanup_challenge(transaction)?;
    archive_transaction(store, transaction)?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn ensure_transaction_fresh(transaction: &AcmeTransaction) -> anyhow::Result<()> {
    if Utc::now().timestamp() > transaction.expires_at {
        bail!("ACME transaction expired");
    }
    Ok(())
}

fn validate_transaction_binding(
    store: &DeploymentStore,
    transaction: &AcmeTransaction,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    if transaction.schema != TRANSACTION_SCHEMA
        || transaction.deployment_id != record.deployment_id
        || transaction.declaration_revision != record.declaration_revision
        || transaction.tenant != canonical_tenant(tenant)?
        || transaction.hostname != canonical_hostname(hostname)?
        || transaction.target_revision
            != transaction
                .expected_revision
                .checked_add(1)
                .context("ACME issuance revision overflow")?
        || transaction.created_at > transaction.expires_at
        || transaction.workspace
            != acme_binding_directory(
                store,
                &record.deployment_id,
                &transaction.tenant,
                &transaction.hostname,
            )
            .join("transactions")
            .join(&transaction.jti)
        || transaction.account_path
            != account_path_for_binding(
                store,
                &record.deployment_id,
                &transaction.directory_url,
                &transaction.acme_config_sha256,
            )
    {
        bail!("ACME transaction does not match the selected deployment binding");
    }
    validate_absolute_normalized(&transaction.workspace, "ACME transaction workspace")?;
    validate_absolute_normalized(&transaction.account_path, "ACME account path")?;
    validate_uuid_v7(&transaction.jti, "ACME transaction JTI")?;
    for (digest, label) in [
        (&transaction.acme_config_sha256, "ACME configuration digest"),
        (
            &transaction.provider_config_sha256,
            "TLS provider configuration digest",
        ),
        (
            &transaction.trust_anchors_sha256,
            "TLS provider trust-anchor digest",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    for (digest, label) in [
        (
            transaction.directory_trust_anchor_sha256.as_deref(),
            "ACME directory trust-anchor digest",
        ),
        (
            transaction.challenge_sha256.as_deref(),
            "ACME challenge digest",
        ),
        (
            transaction.account_key_sha256.as_deref(),
            "ACME account private-key digest",
        ),
        (
            transaction.private_key_sha256.as_deref(),
            "ACME private-key digest",
        ),
        (transaction.csr_sha256.as_deref(), "ACME CSR digest"),
        (
            transaction.certificate_sha256.as_deref(),
            "ACME certificate digest",
        ),
    ] {
        if let Some(digest) = digest {
            validate_digest(digest, label)?;
        }
    }
    validate_https_url(&transaction.directory_url, "ACME journal directory URL")?;
    let authority = AuthorityPolicy::from_config(&transaction.allowed_origins)?;
    authority.require_url(&transaction.directory_url, "ACME journal directory URL")?;
    validate_https_url(
        &transaction.terms_of_service_url,
        "ACME journal terms-of-service URL",
    )?;
    if let Some(order_url) = &transaction.order_url {
        validate_https_url(order_url, "ACME journal order URL")?;
        authority.require_url(order_url, "ACME journal order URL")?;
    }
    if transaction.challenge_path.is_some() != transaction.challenge_sha256.is_some()
        || transaction.private_key_sha256.is_some() != transaction.csr_sha256.is_some()
    {
        bail!("ACME transaction journal contains a partial artifact binding");
    }
    Ok(())
}

fn validate_transaction_config(
    transaction: &AcmeTransaction,
    provider: &LoadedProvider,
    acme: &LoadedAcmeConfig,
) -> anyhow::Result<()> {
    if transaction.acme_config_sha256 != acme.sha256
        || transaction.provider_config_sha256 != provider.config_sha256
        || transaction.trust_anchors_sha256 != provider.trust_anchors_sha256
        || transaction.directory_trust_anchor_sha256
            != acme.directory_trust_anchor.as_deref().map(sha256)
        || transaction.directory_url != acme.config.directory_url
        || transaction.allowed_origins != acme.config.allowed_origins
        || transaction.terms_of_service_url != acme.config.terms_of_service_url
        || transaction.tenant != canonical_tenant(&acme.config.tenant)?
        || transaction.hostname != canonical_hostname(&acme.config.hostname)?
    {
        bail!("ACME transaction differs from its configuration and trust bindings");
    }
    let configured_ttl = i64::try_from(acme.config.transaction_ttl_seconds)?;
    let observed_ttl = transaction
        .expires_at
        .checked_sub(transaction.created_at)
        .context("ACME transaction time range underflow")?;
    if observed_ttl <= 0 || observed_ttl > configured_ttl {
        bail!("ACME transaction expiry exceeds its configured bound");
    }
    validate_secure_directory(&transaction.workspace, "ACME transaction workspace", true)?;
    if let Some(path) = &transaction.challenge_path {
        validate_absolute_normalized(path, "ACME HTTP-01 challenge path")?;
        if path.parent() != Some(acme.config.challenge_webroot.as_path()) {
            bail!("ACME HTTP-01 challenge escaped its configured webroot");
        }
        let token = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("ACME HTTP-01 challenge filename is not UTF-8")?;
        validate_challenge_token(token)?;
    }
    if transaction.phase != Phase::Prepared
        && transaction.phase != Phase::AccountReady
        && transaction.order_url.is_none()
    {
        bail!("ACME transaction phase requires a bound order URL");
    }
    if transaction.phase != Phase::Prepared && transaction.account_key_sha256.is_none() {
        bail!("ACME transaction phase requires a bound account private key");
    }
    if matches!(
        transaction.phase,
        Phase::ChallengePublished | Phase::ChallengeReady
    ) && transaction.challenge_path.is_none()
    {
        bail!("ACME challenge phase has no bound challenge artifact");
    }
    if matches!(
        transaction.phase,
        Phase::CsrReady | Phase::Finalized | Phase::Issued
    ) && transaction.private_key_sha256.is_none()
    {
        bail!("ACME finalization phase has no bound private key and CSR");
    }
    if transaction.phase == Phase::Issued && transaction.certificate_sha256.is_none() {
        bail!("issued ACME transaction has no bound certificate");
    }
    Ok(())
}

fn validate_receipt_shape(store: &DeploymentStore, receipt: &AcmeReceipt) -> anyhow::Result<()> {
    validate_uuid_v7(&receipt.jti, "ACME receipt JTI")?;
    for (digest, label) in [
        (
            &receipt.acme_config_sha256,
            "ACME receipt configuration digest",
        ),
        (
            &receipt.provider_config_sha256,
            "ACME receipt provider digest",
        ),
        (
            &receipt.trust_anchors_sha256,
            "ACME receipt trust-anchor digest",
        ),
        (
            &receipt.certificate_sha256,
            "ACME receipt certificate digest",
        ),
        (
            &receipt.account_key_sha256,
            "ACME receipt account private-key digest",
        ),
        (
            &receipt.private_key_sha256,
            "ACME receipt private-key digest",
        ),
        (
            &receipt.leaf_certificate_sha256,
            "ACME receipt leaf-certificate digest",
        ),
        (&receipt.material_sha256, "ACME receipt material digest"),
    ] {
        validate_digest(digest, label)?;
    }
    if let Some(digest) = &receipt.directory_trust_anchor_sha256 {
        validate_digest(digest, "ACME receipt directory trust-anchor digest")?;
    }
    validate_https_url(&receipt.directory_url, "ACME receipt directory URL")?;
    let authority = AuthorityPolicy::from_config(&receipt.allowed_origins)?;
    authority.require_url(&receipt.directory_url, "ACME receipt directory URL")?;
    validate_https_url(
        &receipt.terms_of_service_url,
        "ACME receipt terms-of-service URL",
    )?;
    validate_https_url(&receipt.account_id, "ACME receipt account URL")?;
    validate_https_url(&receipt.order_url, "ACME receipt order URL")?;
    authority.require_url(&receipt.account_id, "ACME receipt account URL")?;
    authority.require_url(&receipt.order_url, "ACME receipt order URL")?;
    let workspace = acme_binding_directory(
        store,
        &receipt.deployment_id,
        &receipt.tenant,
        &receipt.hostname,
    )
    .join("transactions")
    .join(&receipt.jti);
    if receipt.revision == 0
        || receipt.certificate_path != workspace.join("fullchain.pem")
        || receipt.private_key_path != workspace.join("private-key.pem")
        || receipt.transaction_created_at > receipt.issued_at
        || receipt.issued_at > receipt.transaction_expires_at
        || receipt.certificate_not_after <= receipt.issued_at
        || receipt.material_sha256
            != sha256(
                format!(
                    "{}:{}",
                    receipt.leaf_certificate_sha256, receipt.certificate_sha256
                )
                .as_bytes(),
            )
    {
        bail!("ACME issuance receipt has invalid paths or time ordering");
    }
    Ok(())
}

fn validate_uuid_v7(value: &str, label: &str) -> anyhow::Result<()> {
    let parsed = Uuid::parse_str(value).with_context(|| format!("{label} is invalid"))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        bail!("{label} must be a canonical UUIDv7");
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> anyhow::Result<()> {
    if !super::valid_sha256(value) {
        bail!("{label} must be lowercase SHA-256");
    }
    Ok(())
}

fn load_provider_snapshot(
    store: &DeploymentStore,
    path: &Path,
    tenant: &str,
    hostname: &str,
    transaction: &AcmeTransaction,
) -> anyhow::Result<LoadedProvider> {
    let bytes = read_secure_regular_file(
        path,
        "TLS provider configuration snapshot",
        true,
        super::MAX_PROVIDER_BYTES,
    )?;
    if sha256(&bytes) != transaction.provider_config_sha256 {
        bail!("TLS provider configuration snapshot differs from the ACME journal binding");
    }
    let config: super::ProviderConfig =
        serde_json::from_slice(&bytes).context("TLS provider configuration snapshot is invalid")?;
    super::validate_provider_config(store, &config, tenant, hostname)?;
    let trust_anchors = read_secure_regular_file(
        &transaction.workspace.join("provider-trust-anchors.pem"),
        "TLS provider trust anchor snapshot",
        true,
        super::MAX_TRUST_ANCHOR_BYTES,
    )?;
    if sha256(&trust_anchors) != transaction.trust_anchors_sha256 {
        bail!("TLS provider trust anchor snapshot differs from the ACME journal binding");
    }
    super::material::root_store_from_pem(&trust_anchors)?;
    let public_url =
        Url::parse(&config.public_url).context("TLS provider public URL is invalid")?;
    Ok(LoadedProvider {
        config,
        config_sha256: transaction.provider_config_sha256.clone(),
        trust_anchors: trust_anchors.to_vec(),
        trust_anchors_sha256: transaction.trust_anchors_sha256.clone(),
        public_url,
    })
}

fn validate_receipt_transaction(
    receipt: &AcmeReceipt,
    transaction: &AcmeTransaction,
) -> anyhow::Result<()> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.acme_protocol != CONFIG_PROTOCOL
        || receipt.jti != transaction.jti
        || receipt.deployment_id != transaction.deployment_id
        || receipt.declaration_revision != transaction.declaration_revision
        || receipt.tenant != transaction.tenant
        || receipt.hostname != transaction.hostname
        || receipt.revision != transaction.target_revision
        || receipt.acme_config_sha256 != transaction.acme_config_sha256
        || receipt.provider_config_sha256 != transaction.provider_config_sha256
        || receipt.trust_anchors_sha256 != transaction.trust_anchors_sha256
        || receipt.directory_trust_anchor_sha256 != transaction.directory_trust_anchor_sha256
        || receipt.directory_url != transaction.directory_url
        || receipt.allowed_origins != transaction.allowed_origins
        || receipt.terms_of_service_url != transaction.terms_of_service_url
        || receipt.account_key_sha256
            != transaction
                .account_key_sha256
                .as_deref()
                .unwrap_or_default()
        || receipt.order_url.as_str() != transaction.order_url.as_deref().unwrap_or_default()
        || receipt.certificate_sha256
            != transaction
                .certificate_sha256
                .as_deref()
                .unwrap_or_default()
        || receipt.private_key_sha256
            != transaction
                .private_key_sha256
                .as_deref()
                .unwrap_or_default()
        || receipt.transaction_created_at != transaction.created_at
        || receipt.transaction_expires_at != transaction.expires_at
        || receipt.certificate_path != transaction.workspace.join("fullchain.pem")
        || receipt.private_key_path != transaction.workspace.join("private-key.pem")
    {
        bail!("ACME issuance receipt differs from the pending transaction");
    }
    Ok(())
}

fn validate_previous_receipt(
    transaction: &AcmeTransaction,
    current: Option<&AcmeReceipt>,
) -> anyhow::Result<()> {
    match (transaction.expected_revision, current) {
        (0, None) => Ok(()),
        (expected, Some(receipt))
            if expected > 0
                && receipt.revision == expected
                && receipt.deployment_id == transaction.deployment_id
                && receipt.tenant == transaction.tenant
                && receipt.hostname == transaction.hostname =>
        {
            Ok(())
        }
        _ => bail!("previous ACME issuance receipt changed after transaction preparation"),
    }
}

fn persist_pending(store: &DeploymentStore, transaction: &AcmeTransaction) -> anyhow::Result<()> {
    atomic_write(
        &pending_path(store, transaction),
        &serde_json::to_vec_pretty(transaction)?,
        0o600,
    )
}

fn load_pending(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<Option<AcmeTransaction>> {
    let path =
        acme_binding_directory(store, &record.deployment_id, tenant, hostname).join("pending.json");
    let Some(bytes) =
        read_optional_private(&path, "ACME transaction journal", MAX_TRANSACTION_BYTES)?
    else {
        return Ok(None);
    };
    let transaction: AcmeTransaction =
        serde_json::from_slice(&bytes).context("ACME transaction journal is invalid")?;
    if transaction.schema != TRANSACTION_SCHEMA {
        bail!("unsupported ACME transaction journal schema");
    }
    Ok(Some(transaction))
}

fn ensure_no_pending(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    if load_pending(store, record, tenant, hostname)?.is_some() {
        bail!("an ACME issuance is pending for this binding; run tls acme recover");
    }
    Ok(())
}

fn persist_receipt(
    store: &DeploymentStore,
    transaction: &AcmeTransaction,
    receipt: &AcmeReceipt,
) -> anyhow::Result<()> {
    let directory = acme_binding_directory(
        store,
        &transaction.deployment_id,
        &transaction.tenant,
        &transaction.hostname,
    );
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let archive = directory
        .join("receipts")
        .join(format!("{}.json", receipt.revision));
    match read_optional_private(&archive, "ACME issuance receipt archive", MAX_RECEIPT_BYTES)? {
        Some(existing) if existing != bytes => {
            bail!("ACME issuance receipt revision archive contains conflicting evidence")
        }
        Some(_) => {}
        None => atomic_write(&archive, &bytes, 0o600)?,
    }
    atomic_write(&directory.join("current.json"), &bytes, 0o600)
}

fn load_receipt(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<Option<AcmeReceipt>> {
    Ok(load_receipt_record(store, record, tenant, hostname)?.map(|loaded| loaded.receipt))
}

fn load_receipt_record(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<Option<LoadedAcmeReceipt>> {
    let path =
        acme_binding_directory(store, &record.deployment_id, tenant, hostname).join("current.json");
    let Some(bytes) = read_optional_private(&path, "ACME issuance receipt", MAX_RECEIPT_BYTES)?
    else {
        return Ok(None);
    };
    let receipt: AcmeReceipt =
        serde_json::from_slice(&bytes).context("ACME issuance receipt is invalid")?;
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.acme_protocol != CONFIG_PROTOCOL
        || receipt.deployment_id != record.deployment_id
        || receipt.tenant != canonical_tenant(tenant)?
        || receipt.hostname != canonical_hostname(hostname)?
    {
        bail!("ACME issuance receipt differs from the selected binding");
    }
    validate_receipt_shape(store, &receipt)?;
    validate_receipt_artifacts(store, &receipt)?;
    Ok(Some(LoadedAcmeReceipt {
        receipt,
        receipt_sha256: sha256(&bytes),
    }))
}

fn validate_receipt_artifacts(
    store: &DeploymentStore,
    receipt: &AcmeReceipt,
) -> anyhow::Result<()> {
    let certificate = read_secure_regular_file(
        &receipt.certificate_path,
        "ACME receipt certificate chain",
        false,
        MAX_CERTIFICATE_BYTES,
    )?;
    let private_key = read_secure_regular_file(
        &receipt.private_key_path,
        "ACME receipt server private key",
        true,
        super::MAX_PRIVATE_KEY_BYTES,
    )?;
    if sha256(&certificate) != receipt.certificate_sha256
        || sha256(&private_key) != receipt.private_key_sha256
    {
        bail!("ACME receipt material differs from its bound digest");
    }
    let account = load_account(&account_path_for_binding(
        store,
        &receipt.deployment_id,
        &receipt.directory_url,
        &receipt.acme_config_sha256,
    ))?
    .context("ACME receipt account credentials are missing")?;
    if account.schema != ACCOUNT_SCHEMA
        || account.deployment_id != receipt.deployment_id
        || account.acme_config_sha256 != receipt.acme_config_sha256
        || account.directory_url != receipt.directory_url
        || account.allowed_origins != receipt.allowed_origins
        || account.account_key_sha256 != receipt.account_key_sha256
    {
        bail!("ACME receipt account credentials differ from its authority binding");
    }
    Ok(())
}

fn read_optional_private(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(Some(
            read_secure_regular_file(path, label, true, max_bytes)?.to_vec(),
        )),
        Ok(_) => bail!("{label} must be a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {label}")),
    }
}

fn archive_transaction(
    store: &DeploymentStore,
    transaction: &AcmeTransaction,
) -> anyhow::Result<()> {
    atomic_write(
        &transaction.workspace.join("transaction.json"),
        &serde_json::to_vec_pretty(transaction)?,
        0o600,
    )?;
    remove_file_durable(&pending_path(store, transaction))
}

fn abort_transaction(
    store: &DeploymentStore,
    transaction: &mut AcmeTransaction,
    reason: &str,
) -> anyhow::Result<()> {
    cleanup_challenge(transaction)?;
    transaction.last_error = Some(reason.to_owned());
    persist_pending(store, transaction)?;
    atomic_write(
        &transaction.workspace.join("aborted.json"),
        &serde_json::to_vec_pretty(&AbortedTransaction {
            schema: 1,
            transaction: transaction.clone(),
            reason: reason.to_owned(),
            aborted_at: Utc::now().timestamp(),
        })?,
        0o600,
    )?;
    archive_transaction(store, transaction)
}

fn cleanup_challenge(transaction: &AcmeTransaction) -> anyhow::Result<()> {
    let Some(path) = &transaction.challenge_path else {
        return Ok(());
    };
    let expected = transaction
        .challenge_sha256
        .as_deref()
        .context("ACME journal has a challenge path without a digest")?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect ACME HTTP-01 challenge"),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("ACME HTTP-01 challenge path is not a regular file");
            }
            let bytes = read_secure_regular_file(path, "ACME HTTP-01 challenge", false, 4096)?;
            if sha256(&bytes) != expected {
                bail!("ACME HTTP-01 challenge content differs from the journal binding");
            }
            remove_file_durable(path)
        }
    }
}

fn pending_path(store: &DeploymentStore, transaction: &AcmeTransaction) -> PathBuf {
    acme_binding_directory(
        store,
        &transaction.deployment_id,
        &transaction.tenant,
        &transaction.hostname,
    )
    .join("pending.json")
}

fn acme_binding_directory(
    store: &DeploymentStore,
    deployment_id: &str,
    tenant: &str,
    hostname: &str,
) -> PathBuf {
    let identity = sha256(format!("{tenant}\0{hostname}").as_bytes());
    store
        .deployment_state_dir(deployment_id)
        .join("tls-acme")
        .join("bindings")
        .join(identity)
}

fn account_path(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    acme: &LoadedAcmeConfig,
) -> PathBuf {
    account_path_for_binding(
        store,
        &record.deployment_id,
        &acme.config.directory_url,
        &acme.sha256,
    )
}

fn account_path_for_binding(
    store: &DeploymentStore,
    deployment_id: &str,
    directory_url: &str,
    acme_config_sha256: &str,
) -> PathBuf {
    let identity = sha256(format!("{directory_url}\0{acme_config_sha256}").as_bytes());
    store
        .deployment_state_dir(deployment_id)
        .join("tls-acme")
        .join("accounts")
        .join(format!("{identity}.json"))
}

fn contacts_sha256(contacts: &[String]) -> String {
    sha256(contacts.join("\0").as_bytes())
}

fn challenge_lock_id(config: &AcmeConfig) -> String {
    format!(
        "acme-http01-{}",
        sha256(config.challenge_webroot.to_string_lossy().as_bytes())
    )
}

fn retry_policy(acme: &LoadedAcmeConfig) -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .timeout(Duration::from_secs(acme.config.poll_timeout_seconds))
}

fn validate_challenge_token(token: &str) -> anyhow::Result<()> {
    if !(16..=256).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("ACME HTTP-01 challenge token is not bounded base64url data");
    }
    Ok(())
}

fn validate_absolute_normalized(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("{label} must be a normalized absolute path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::PrivateTempDir;

    #[test]
    fn strict_configuration_and_network_tokens_fail_closed() {
        let mut config = test_config(PathBuf::from("/srv/http/acme"));
        let mut value = serde_json::to_value(&config).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AcmeConfig>(value).is_err());

        assert!(validate_challenge_token("Abcdefghijklmnop_0123456789-").is_ok());
        assert!(validate_challenge_token("short").is_err());
        assert!(validate_challenge_token("abcdefghijklmnop/escape").is_err());
        assert!(validate_challenge_token("abcdefghijklmnop.dot").is_err());

        assert!(validate_https_url("https://acme.example/directory", "directory").is_ok());
        assert!(validate_https_url("https://acme.example/order?id=1", "order").is_ok());
        assert!(validate_https_url("http://acme.example/directory", "directory").is_err());
        assert!(validate_https_url("https://user@acme.example/directory", "directory").is_err());
        config.protocol.push_str(".unknown");
        assert_ne!(config.protocol, CONFIG_PROTOCOL);
    }

    #[test]
    fn challenge_cleanup_requires_the_exact_journal_digest() {
        let work = PrivateTempDir::new("nazoauthctl-acme-cleanup").unwrap();
        let challenge_root = work.path().join("challenge");
        ensure_private_directory(&challenge_root, "test challenge root").unwrap();
        let challenge = challenge_root.join("abcdefghijklmnop");
        atomic_write(&challenge, b"expected", 0o644).unwrap();
        let mut transaction = test_transaction(work.path());
        transaction.challenge_path = Some(challenge.clone());
        transaction.challenge_sha256 = Some(sha256(b"expected"));
        cleanup_challenge(&transaction).unwrap();
        assert!(!challenge.exists());

        atomic_write(&challenge, b"replaced", 0o644).unwrap();
        assert!(cleanup_challenge(&transaction).is_err());
        assert!(challenge.exists());
    }

    #[test]
    fn abort_preserves_evidence_and_releases_the_pending_binding() {
        let work = PrivateTempDir::new("nazoauthctl-acme-abort").unwrap();
        let store = DeploymentStore {
            config_root: work.path().join("config"),
            state_root: work.path().join("state"),
        };
        let mut transaction = test_transaction_for_store(&store);
        ensure_private_directory(&transaction.workspace, "test ACME workspace").unwrap();
        let challenge_root = work.path().join("challenge");
        ensure_private_directory(&challenge_root, "test challenge root").unwrap();
        let challenge = challenge_root.join("abcdefghijklmnop");
        atomic_write(&challenge, b"expected", 0o644).unwrap();
        transaction.challenge_path = Some(challenge.clone());
        transaction.challenge_sha256 = Some(sha256(b"expected"));
        persist_pending(&store, &transaction).unwrap();

        abort_transaction(&store, &mut transaction, "transaction-expired").unwrap();
        assert!(!pending_path(&store, &transaction).exists());
        assert!(!challenge.exists());
        assert!(transaction.workspace.join("aborted.json").is_file());
        assert!(transaction.workspace.join("transaction.json").is_file());
    }

    #[test]
    fn account_key_is_persisted_and_journal_bound_before_network_use() {
        let work = PrivateTempDir::new("nazoauthctl-acme-account-key").unwrap();
        let store = DeploymentStore {
            config_root: work.path().join("config"),
            state_root: work.path().join("state"),
        };
        let mut transaction = test_transaction_for_store(&store);
        transaction.phase = Phase::Prepared;
        transaction.account_key_sha256 = None;
        ensure_private_directory(&transaction.workspace, "test ACME workspace").unwrap();
        persist_pending(&store, &transaction).unwrap();

        let (_, _, digest) = load_or_create_account_key(&transaction).unwrap();
        bind_account_key_digest(&store, &mut transaction, &digest).unwrap();
        let (_, _, resumed_digest) = load_or_create_account_key(&transaction).unwrap();
        assert_eq!(digest, resumed_digest);
        let journal: AcmeTransaction = serde_json::from_slice(
            &read_secure_regular_file(
                &pending_path(&store, &transaction),
                "test ACME journal",
                true,
                MAX_TRANSACTION_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(journal.account_key_sha256.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn committed_receipt_must_match_every_transaction_authority() {
        let work = PrivateTempDir::new("nazoauthctl-acme-receipt").unwrap();
        let mut transaction = test_transaction(work.path());
        let mut receipt = test_receipt(&transaction);
        assert!(validate_receipt_transaction(&receipt, &transaction).is_ok());
        receipt.provider_config_sha256 = "f".repeat(64);
        assert!(validate_receipt_transaction(&receipt, &transaction).is_err());
        receipt.provider_config_sha256 = transaction.provider_config_sha256.clone();
        receipt.acme_protocol = "unknown.protocol".to_owned();
        assert!(validate_receipt_transaction(&receipt, &transaction).is_err());
        receipt = test_receipt(&transaction);
        receipt.allowed_origins = vec!["https://other-acme.example".to_owned()];
        assert!(validate_receipt_transaction(&receipt, &transaction).is_err());

        assert!(validate_previous_receipt(&transaction, None).is_ok());
        transaction.expected_revision = 1;
        transaction.target_revision = 2;
        let mut previous = test_receipt(&transaction);
        previous.revision = 1;
        previous.jti = "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8c".to_owned();
        assert!(validate_previous_receipt(&transaction, Some(&previous)).is_ok());
        previous.revision = 2;
        assert!(validate_previous_receipt(&transaction, Some(&previous)).is_err());
    }

    #[test]
    fn install_consumption_requires_exact_declaration_and_provider_authority() {
        let transaction = test_transaction(Path::new("/private/state"));
        let mut receipt = test_receipt(&transaction);
        assert!(
            validate_install_authority(
                &receipt,
                transaction.declaration_revision,
                &transaction.provider_config_sha256,
                &transaction.trust_anchors_sha256,
            )
            .is_ok()
        );

        receipt.declaration_revision += 1;
        assert!(
            validate_install_authority(
                &receipt,
                transaction.declaration_revision,
                &transaction.provider_config_sha256,
                &transaction.trust_anchors_sha256,
            )
            .is_err()
        );
        receipt.declaration_revision = transaction.declaration_revision;
        receipt.provider_config_sha256 = "f".repeat(64);
        assert!(
            validate_install_authority(
                &receipt,
                transaction.declaration_revision,
                &transaction.provider_config_sha256,
                &transaction.trust_anchors_sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_shape_binds_protocol_and_material_identity() {
        let work = PrivateTempDir::new("nazoauthctl-acme-receipt-shape").unwrap();
        let store = DeploymentStore {
            config_root: work.path().join("config"),
            state_root: work.path().join("state"),
        };
        let transaction = test_transaction_for_store(&store);
        let mut receipt = test_receipt(&transaction);
        assert!(validate_receipt_shape(&store, &receipt).is_ok());
        receipt.material_sha256 = "f".repeat(64);
        assert!(validate_receipt_shape(&store, &receipt).is_err());
        receipt = test_receipt(&transaction);
        receipt.acme_protocol = "unknown.protocol".to_owned();
        assert!(
            receipt.acme_protocol != CONFIG_PROTOCOL
                && validate_receipt_transaction(&receipt, &transaction).is_err()
        );
        receipt = test_receipt(&transaction);
        receipt.account_id = "https://127.0.0.1/internal-account".to_owned();
        assert!(validate_receipt_shape(&store, &receipt).is_err());
        receipt = test_receipt(&transaction);
        receipt.allowed_origins = Vec::new();
        assert!(validate_receipt_shape(&store, &receipt).is_err());
    }

    #[test]
    fn receipt_commit_archives_exact_revision_before_current_pointer() {
        let work = PrivateTempDir::new("nazoauthctl-acme-receipt-archive").unwrap();
        let store = DeploymentStore {
            config_root: work.path().join("config"),
            state_root: work.path().join("state"),
        };
        let transaction = test_transaction_for_store(&store);
        let receipt = test_receipt(&transaction);
        persist_receipt(&store, &transaction, &receipt).unwrap();
        let directory = acme_binding_directory(
            &store,
            &transaction.deployment_id,
            &transaction.tenant,
            &transaction.hostname,
        );
        let archive = fs::read(directory.join("receipts/1.json")).unwrap();
        let current = fs::read(directory.join("current.json")).unwrap();
        assert_eq!(archive, current);

        let mut conflicting = receipt;
        conflicting.order_url = "https://acme.example/order/conflict".to_owned();
        assert!(persist_receipt(&store, &transaction, &conflicting).is_err());
        assert_eq!(fs::read(directory.join("current.json")).unwrap(), current);
    }

    fn test_config(challenge_webroot: PathBuf) -> AcmeConfig {
        AcmeConfig {
            schema: CONFIG_SCHEMA,
            protocol: CONFIG_PROTOCOL.to_owned(),
            tenant: "tenant-a".to_owned(),
            hostname: "auth.example".to_owned(),
            directory_url: "https://acme.example/directory".to_owned(),
            allowed_origins: vec!["https://acme.example".to_owned()],
            terms_of_service_url: "https://acme.example/terms".to_owned(),
            contacts: vec!["mailto:security@example.com".to_owned()],
            challenge_webroot,
            directory_trust_anchor: None,
            poll_timeout_seconds: 120,
            transaction_ttl_seconds: 900,
        }
    }

    fn test_transaction(root: &Path) -> AcmeTransaction {
        let workspace = root.join("workspace");
        AcmeTransaction {
            schema: TRANSACTION_SCHEMA,
            jti: "0198f5df-4df8-7d9f-8f6a-5c2b2917cc8b".to_owned(),
            deployment_id: "deployment-a".to_owned(),
            declaration_revision: 7,
            tenant: "tenant-a".to_owned(),
            hostname: "auth.example".to_owned(),
            expected_revision: 0,
            target_revision: 1,
            acme_config_sha256: "a".repeat(64),
            provider_config_sha256: "b".repeat(64),
            trust_anchors_sha256: "c".repeat(64),
            directory_trust_anchor_sha256: None,
            directory_url: "https://acme.example/directory".to_owned(),
            allowed_origins: vec!["https://acme.example".to_owned()],
            terms_of_service_url: "https://acme.example/terms".to_owned(),
            account_path: root.join("account.json"),
            workspace: workspace.clone(),
            order_url: Some("https://acme.example/order/1".to_owned()),
            challenge_path: None,
            challenge_sha256: None,
            account_key_sha256: Some("3".repeat(64)),
            private_key_sha256: Some("d".repeat(64)),
            csr_sha256: Some("e".repeat(64)),
            certificate_sha256: Some("0".repeat(64)),
            created_at: 1_800_000_000,
            expires_at: 1_800_000_900,
            phase: Phase::Issued,
            last_error: None,
        }
    }

    fn test_transaction_for_store(store: &DeploymentStore) -> AcmeTransaction {
        let mut transaction = test_transaction(&store.state_root);
        transaction.workspace = acme_binding_directory(
            store,
            &transaction.deployment_id,
            &transaction.tenant,
            &transaction.hostname,
        )
        .join("transactions")
        .join(&transaction.jti);
        transaction.account_path = account_path_for_binding(
            store,
            &transaction.deployment_id,
            &transaction.directory_url,
            &transaction.acme_config_sha256,
        );
        transaction
    }

    fn test_receipt(transaction: &AcmeTransaction) -> AcmeReceipt {
        let certificate_sha256 = transaction.certificate_sha256.clone().unwrap();
        let leaf_certificate_sha256 = "1".repeat(64);
        AcmeReceipt {
            schema: RECEIPT_SCHEMA,
            jti: transaction.jti.clone(),
            deployment_id: transaction.deployment_id.clone(),
            declaration_revision: transaction.declaration_revision,
            tenant: transaction.tenant.clone(),
            hostname: transaction.hostname.clone(),
            revision: transaction.target_revision,
            acme_protocol: CONFIG_PROTOCOL.to_owned(),
            acme_config_sha256: transaction.acme_config_sha256.clone(),
            provider_config_sha256: transaction.provider_config_sha256.clone(),
            trust_anchors_sha256: transaction.trust_anchors_sha256.clone(),
            directory_trust_anchor_sha256: transaction.directory_trust_anchor_sha256.clone(),
            directory_url: transaction.directory_url.clone(),
            allowed_origins: transaction.allowed_origins.clone(),
            terms_of_service_url: transaction.terms_of_service_url.clone(),
            account_id: "https://acme.example/account/1".to_owned(),
            account_key_sha256: transaction.account_key_sha256.clone().unwrap(),
            order_url: transaction.order_url.clone().unwrap(),
            certificate_path: transaction.workspace.join("fullchain.pem"),
            private_key_path: transaction.workspace.join("private-key.pem"),
            certificate_sha256: certificate_sha256.clone(),
            private_key_sha256: transaction.private_key_sha256.clone().unwrap(),
            leaf_certificate_sha256: leaf_certificate_sha256.clone(),
            material_sha256: sha256(
                format!("{leaf_certificate_sha256}:{certificate_sha256}").as_bytes(),
            ),
            certificate_not_after: 1_900_000_000,
            transaction_created_at: transaction.created_at,
            transaction_expires_at: transaction.expires_at,
            issued_at: 1_800_000_100,
        }
    }
}
