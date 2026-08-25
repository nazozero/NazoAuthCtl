//! Deployment-owned public TLS certificate material transactions.
//!
//! This module deliberately does not configure NazoAuth's protocol keys or
//! select a runtime tenant. It owns only the file-provider lifecycle behind the
//! deployment's `proxy_tls` capability.

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use chrono::Utc;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    cli::{TlsCertificateCheckInput, TlsCertificateInput, TlsCertificateSource, TlsCommand},
    deployment::{Capability, DeploymentRecord, DeploymentStore},
    filesystem::{
        atomic_write, ensure_private_directory, read_secure_regular_file, remove_file_durable,
        symlink_atomic, sync_parent, validate_secure_directory,
    },
    process::Process,
};

const PROVIDER_PROTOCOL: &str = "nazoauthctl.tls.external-generation.v1";
const PROVIDER_SNAPSHOT_DIGEST_PROTOCOL: &str = "nazoauthctl.tls.provider-snapshot-digest.v1";
const PROVIDER_SCHEMA: u32 = 1;
const TRANSACTION_SCHEMA: u32 = 4;
const RECEIPT_SCHEMA: u32 = 2;
const PLAN_SCHEMA: u32 = 2;
const MAX_PROVIDER_BYTES: u64 = 64 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 128 * 1024;
const MAX_TRUST_ANCHOR_BYTES: u64 = 1024 * 1024;
const TRANSACTION_TTL_SECONDS: i64 = 15 * 60;
const MAX_WARNING_WINDOW_SECONDS: u64 = 90 * 24 * 3600;
const READINESS_EVIDENCE_TTL_SECONDS: i64 = 5 * 60;
const MAX_HTTP_RESPONSE_BYTES: u64 = 64 * 1024;

mod acme;
mod material;
mod public_endpoint;

use material::{ValidatedMaterial, load_and_validate_material, root_store_from_pem};
#[cfg(test)]
use public_endpoint::{is_public_ip, verify_public_address, verify_public_address_not_leaf};
use public_endpoint::{verify_public, verify_public_not_leaf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderCommand {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderConfig {
    schema: u32,
    protocol: String,
    tenant: String,
    hostname: String,
    material_root: PathBuf,
    activation_link: PathBuf,
    trust_anchors: PathBuf,
    public_url: String,
    accepted_statuses: BTreeSet<u16>,
    minimum_validity_seconds: u64,
    connect_timeout_seconds: u64,
    request_timeout_seconds: u64,
    validate: ProviderCommand,
    reload: ProviderCommand,
}

#[derive(Clone, Debug)]
struct LoadedProvider {
    config: ProviderConfig,
    config_sha256: String,
    trust_anchors: Vec<u8>,
    trust_anchors_sha256: String,
    public_url: Url,
}

#[derive(Clone, Debug)]
struct AcmeInstallSource {
    receipt_sha256: String,
    issuance_jti: String,
    issuance_declaration_revision: u64,
    issuance_revision: u64,
    acme_protocol: String,
    acme_config_sha256: String,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_sha256: String,
    private_key_sha256: String,
    leaf_certificate_sha256: String,
    material_sha256: String,
    certificate_not_after: i64,
    issued_at: i64,
}

#[derive(Clone, Debug)]
enum ResolvedCertificateSource {
    ExternalFiles {
        certificate: PathBuf,
        private_key: PathBuf,
    },
    AcmeReceipt(Box<AcmeInstallSource>),
}

impl ResolvedCertificateSource {
    fn paths(&self) -> (&Path, &Path) {
        match self {
            Self::ExternalFiles {
                certificate,
                private_key,
            } => (certificate, private_key),
            Self::AcmeReceipt(source) => (&source.certificate_path, &source.private_key_path),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CertificateSourceBinding {
    ExternalFiles {
        certificate_sha256: String,
        private_key_sha256: String,
    },
    AcmeReceipt {
        receipt_sha256: String,
        issuance_jti: String,
        issuance_declaration_revision: u64,
        issuance_revision: u64,
        acme_protocol: String,
        acme_config_sha256: String,
        certificate_sha256: String,
        private_key_sha256: String,
        issued_at: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificatePlan {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    capability: &'static str,
    capability_responsibility: String,
    capability_scope: String,
    provider_protocol: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    source: CertificateSourceBinding,
    material_sha256: String,
    leaf_certificate_sha256: String,
    certificate_not_after: i64,
    current_revision: u64,
    target_revision: u64,
    transaction_expires_at: i64,
    steps: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateReadiness {
    schema: u32,
    check_jti: String,
    checked_at: i64,
    evidence_expires_at: i64,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    capability: &'static str,
    capability_responsibility: String,
    capability_scope: String,
    provider_protocol: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    source: CertificateSourceBinding,
    receipt_jti: String,
    receipt_revision: u64,
    material_sha256: String,
    leaf_certificate_sha256: String,
    certificate_not_after: i64,
    renewal_required_at: i64,
    seconds_remaining: i64,
    warning_window_seconds: u64,
    active_generation: PathBuf,
    public_url: String,
    active_generation_verified: bool,
    source_authority_current: bool,
    public_endpoint_verified: bool,
    ready: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Prepared,
    Staged,
    Activating,
    Activated,
    Reloaded,
    Verified,
    RollbackFailed,
    RolledBack,
    Committed,
}

impl TransactionPhase {
    fn activation_may_have_happened(self) -> bool {
        matches!(
            self,
            Self::Activating
                | Self::Activated
                | Self::Reloaded
                | Self::Verified
                | Self::RollbackFailed
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateTransaction {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    capability: String,
    expected_revision: u64,
    target_revision: u64,
    source: CertificateSourceBinding,
    material_sha256: String,
    leaf_certificate_sha256: String,
    certificate_not_after: i64,
    provider_config_sha256: String,
    provider_snapshot_sha256: String,
    trust_anchors_sha256: String,
    trust_anchors_pem: String,
    provider: ProviderConfig,
    generation: PathBuf,
    previous_generation: Option<PathBuf>,
    previous_leaf_certificate_sha256: Option<String>,
    previous_receipt_sha256: Option<String>,
    created_at: i64,
    expires_at: i64,
    phase: TransactionPhase,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateReceipt {
    schema: u32,
    jti: String,
    deployment_id: String,
    declaration_revision: u64,
    tenant: String,
    hostname: String,
    capability: String,
    revision: u64,
    source: CertificateSourceBinding,
    material_sha256: String,
    leaf_certificate_sha256: String,
    certificate_not_after: i64,
    provider_protocol: String,
    provider_config_sha256: String,
    trust_anchors_sha256: String,
    generation: PathBuf,
    activation_link: PathBuf,
    public_url: String,
    transaction_created_at: i64,
    transaction_expires_at: i64,
    verified_at: i64,
}

pub(crate) fn run(
    selector: Option<&str>,
    command: TlsCommand,
    require_root: impl Fn() -> anyhow::Result<()>,
    confirm: impl Fn(bool, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let store = DeploymentStore::system();
    match command {
        TlsCommand::Acme(command) => acme::run(selector, command, require_root, confirm),
        TlsCommand::Check(input) => {
            require_root()?;
            check(&store, selector, &input)
        }
        TlsCommand::Plan(input) => {
            require_root()?;
            let record = store.resolve(selector, true)?;
            record.require_mutation(&[Capability::ProxyTls])?;
            let provider = load_provider(
                &store,
                &input.provider_config,
                &input.tenant,
                &input.hostname,
            )?;
            let _provider_lock =
                store.shared_resource_shared_lock(&provider_lock_id(&provider.config))?;
            let tenant = canonical_tenant(&input.tenant)?;
            let hostname = canonical_hostname(&input.hostname)?;
            ensure_no_pending(&store, &record, &tenant, &hostname)?;
            ensure_provider_not_pending(
                &store,
                &record.deployment_id,
                &provider.config,
                &tenant,
                &hostname,
            )?;
            let resolved_source = resolve_certificate_source(&store, &record, &input, &provider)?;
            let (certificate, private_key) = resolved_source.paths();
            let material =
                load_and_validate_material(certificate, private_key, &input.hostname, &provider)?;
            let source = bind_certificate_source(&resolved_source, &material)?;
            let receipt = load_receipt(&store, &record, &input.tenant, &input.hostname)?;
            let plan = build_plan(
                &record,
                &input,
                &provider,
                &source,
                &material,
                receipt.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        TlsCommand::Apply { input, yes } => {
            require_root()?;
            confirm(
                yes,
                "install and activate deployment-owned TLS certificate material",
            )?;
            apply(&store, selector, &input)
        }
        TlsCommand::Recover {
            tenant,
            hostname,
            yes,
        } => {
            require_root()?;
            confirm(yes, "roll back the pending TLS certificate transaction")?;
            recover(&store, selector, &tenant, &hostname)
        }
        TlsCommand::Show { tenant, hostname } => {
            require_root()?;
            let record = store.resolve(selector, false)?;
            let receipt = load_receipt(&store, &record, &tenant, &hostname)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": 1,
                    "deployment_id": record.deployment_id,
                    "tenant": canonical_tenant(&tenant)?,
                    "hostname": canonical_hostname(&hostname)?,
                    "receipt": receipt,
                }))?
            );
            Ok(())
        }
    }
}

fn check(
    store: &DeploymentStore,
    selector: Option<&str>,
    input: &TlsCertificateCheckInput,
) -> anyhow::Result<()> {
    let selected = store.resolve(selector, true)?;
    let _deployment_lock = store.deployment_shared_lock(&selected.deployment_id)?;
    let record = store.reload_locked(&selected)?;
    record.require_mutation(&[Capability::ProxyTls])?;
    let tenant = canonical_tenant(&input.tenant)?;
    let hostname = canonical_hostname(&input.hostname)?;
    let provider = load_provider(store, &input.provider_config, &tenant, &hostname)?;
    let _provider_lock = store.shared_resource_shared_lock(&provider_lock_id(&provider.config))?;
    ensure_no_pending(store, &record, &tenant, &hostname)?;
    ensure_provider_not_pending(
        store,
        &record.deployment_id,
        &provider.config,
        &tenant,
        &hostname,
    )?;
    let receipt = load_receipt(store, &record, &tenant, &hostname)?
        .context("no committed TLS certificate receipt exists for this binding")?;
    validate_active_receipt(&provider.config, Some(&receipt))?;
    validate_receipt_provider_authority(&receipt, &provider)?;

    let material = load_and_validate_material(
        &receipt.generation.join("fullchain.pem"),
        &receipt.generation.join("private-key.pem"),
        &hostname,
        &provider,
    )?;
    validate_installed_material(&receipt, &material)?;
    if matches!(
        &receipt.source,
        CertificateSourceBinding::AcmeReceipt { .. }
    ) {
        let source = acme::current_install_source(store, &record, &provider, &tenant, &hostname)?;
        let observed = bind_certificate_source(
            &ResolvedCertificateSource::AcmeReceipt(Box::new(source)),
            &material,
        )?;
        if observed != receipt.source {
            bail!("current ACME issuance receipt is not the installed certificate source");
        }
    }

    let warning_window_seconds = effective_warning_window(
        provider.config.minimum_validity_seconds,
        input.warning_window_seconds,
    )?;
    ensure_outside_warning_window(
        receipt.certificate_not_after,
        Utc::now().timestamp(),
        warning_window_seconds,
    )?;
    verify_public(
        &provider.public_url,
        &hostname,
        &receipt.leaf_certificate_sha256,
        material.root_store.clone(),
        &provider.config,
    )?;
    let checked_at = Utc::now().timestamp();
    let seconds_remaining = ensure_outside_warning_window(
        receipt.certificate_not_after,
        checked_at,
        warning_window_seconds,
    )?;
    let renewal_required_at = receipt
        .certificate_not_after
        .checked_sub(
            i64::try_from(warning_window_seconds)
                .context("TLS certificate warning window does not fit signed time")?,
        )
        .context("TLS certificate renewal boundary overflow")?;
    let evidence_expires_at = checked_at
        .checked_add(READINESS_EVIDENCE_TTL_SECONDS)
        .context("TLS readiness evidence expiry overflow")?
        .min(renewal_required_at);
    let grant = record.capabilities.grant(Capability::ProxyTls);
    let readiness = CertificateReadiness {
        schema: 1,
        check_jti: uuid::Uuid::now_v7().to_string(),
        checked_at,
        evidence_expires_at,
        deployment_id: record.deployment_id,
        declaration_revision: record.declaration_revision,
        tenant,
        hostname,
        capability: "proxy_tls",
        capability_responsibility: format!("{:?}", grant.responsibility).to_ascii_lowercase(),
        capability_scope: format!("{:?}", grant.scope).to_ascii_lowercase(),
        provider_protocol: PROVIDER_PROTOCOL.to_owned(),
        provider_config_sha256: provider.config_sha256,
        trust_anchors_sha256: provider.trust_anchors_sha256,
        source: receipt.source,
        receipt_jti: receipt.jti,
        receipt_revision: receipt.revision,
        material_sha256: receipt.material_sha256,
        leaf_certificate_sha256: receipt.leaf_certificate_sha256,
        certificate_not_after: receipt.certificate_not_after,
        renewal_required_at,
        seconds_remaining,
        warning_window_seconds,
        active_generation: receipt.generation,
        public_url: receipt.public_url,
        active_generation_verified: true,
        source_authority_current: true,
        public_endpoint_verified: true,
        ready: true,
    };
    println!("{}", serde_json::to_string_pretty(&readiness)?);
    Ok(())
}

fn effective_warning_window(
    provider_minimum_seconds: u64,
    requested_seconds: Option<u64>,
) -> anyhow::Result<u64> {
    let requested = requested_seconds.unwrap_or(provider_minimum_seconds);
    if !(3600..=MAX_WARNING_WINDOW_SECONDS).contains(&requested) {
        bail!("TLS certificate warning window must be between 3600 and 7776000 seconds");
    }
    Ok(requested.max(provider_minimum_seconds))
}

fn ensure_outside_warning_window(
    certificate_not_after: i64,
    checked_at: i64,
    warning_window_seconds: u64,
) -> anyhow::Result<i64> {
    let warning_window = i64::try_from(warning_window_seconds)
        .context("TLS certificate warning window does not fit signed time")?;
    let seconds_remaining = certificate_not_after
        .checked_sub(checked_at)
        .context("TLS certificate remaining lifetime overflow")?;
    if seconds_remaining <= warning_window {
        bail!(
            "TLS certificate has {seconds_remaining} seconds remaining, within the required {warning_window_seconds}-second renewal window"
        );
    }
    Ok(seconds_remaining)
}

fn apply(
    store: &DeploymentStore,
    selector: Option<&str>,
    input: &TlsCertificateInput,
) -> anyhow::Result<()> {
    let selected = store.resolve(selector, true)?;
    let _deployment_lock = store.deployment_lock(&selected.deployment_id)?;
    let record = store.reload_locked(&selected)?;
    let _shared_locks = store.shared_capability_locks(&record, &[Capability::ProxyTls])?;
    record.require_mutation(&[Capability::ProxyTls])?;

    let tenant = canonical_tenant(&input.tenant)?;
    let hostname = canonical_hostname(&input.hostname)?;
    ensure_no_pending(store, &record, &tenant, &hostname)?;
    let provider = load_provider(store, &input.provider_config, &tenant, &hostname)?;
    let _provider_lock = store.shared_resource_lock(&provider_lock_id(&provider.config))?;
    ensure_provider_not_pending(
        store,
        &record.deployment_id,
        &provider.config,
        &tenant,
        &hostname,
    )?;
    let resolved_source = resolve_certificate_source(store, &record, input, &provider)?;
    let (certificate, private_key) = resolved_source.paths();
    let material = load_and_validate_material(certificate, private_key, &hostname, &provider)?;
    let source = bind_certificate_source(&resolved_source, &material)?;
    let previous = load_receipt(store, &record, &tenant, &hostname)?;
    validate_active_receipt(&provider.config, previous.as_ref())?;
    if let Some(previous) = previous.as_ref() {
        validate_receipt_provider_authority(previous, &provider)?;
    }
    ensure_source_not_current(previous.as_ref(), &source)?;
    let expected_revision = previous.as_ref().map_or(0, |receipt| receipt.revision);
    let target_revision = expected_revision
        .checked_add(1)
        .context("TLS material revision overflow")?;
    let previous_receipt_sha256 = previous.as_ref().map(receipt_sha256).transpose()?;
    let provider_snapshot_sha256 = provider_snapshot_sha256(&provider.config)?;
    ensure_receipt_revision_available(store, &record, &tenant, &hostname, target_revision)?;
    let jti = uuid::Uuid::now_v7().to_string();
    let generation = provider
        .config
        .material_root
        .join("generations")
        .join(format!(
            "{target_revision}-{}-{}",
            &material.material_sha256[..16],
            &jti[..8]
        ));
    let now = Utc::now().timestamp();
    let mut transaction = CertificateTransaction {
        schema: TRANSACTION_SCHEMA,
        jti: jti.clone(),
        deployment_id: record.deployment_id.clone(),
        declaration_revision: record.declaration_revision,
        tenant: tenant.clone(),
        hostname: hostname.clone(),
        capability: "proxy_tls".to_owned(),
        expected_revision,
        target_revision,
        source: source.clone(),
        material_sha256: material.material_sha256.clone(),
        leaf_certificate_sha256: material.leaf_sha256.clone(),
        certificate_not_after: material.not_after,
        provider_config_sha256: provider.config_sha256.clone(),
        provider_snapshot_sha256,
        trust_anchors_sha256: provider.trust_anchors_sha256.clone(),
        trust_anchors_pem: std::str::from_utf8(&provider.trust_anchors)
            .context("TLS trust anchors are not UTF-8 PEM")?
            .to_owned(),
        provider: provider.config.clone(),
        generation: generation.clone(),
        previous_generation: previous.as_ref().map(|receipt| receipt.generation.clone()),
        previous_leaf_certificate_sha256: previous
            .as_ref()
            .map(|receipt| receipt.leaf_certificate_sha256.clone()),
        previous_receipt_sha256,
        created_at: now,
        expires_at: now + TRANSACTION_TTL_SECONDS,
        phase: TransactionPhase::Prepared,
        last_error: None,
    };
    persist_pending(store, &transaction)?;

    let result = (|| -> anyhow::Result<CertificateReceipt> {
        ensure_transaction_fresh(&transaction)?;
        stage_generation(&transaction, &material)?;
        transaction.phase = TransactionPhase::Staged;
        persist_pending(store, &transaction)?;
        ensure_transaction_fresh(&transaction)?;
        execute_provider_command(&transaction, &transaction.provider.validate, "validate")?;
        ensure_transaction_fresh(&transaction)?;
        transaction.phase = TransactionPhase::Activating;
        persist_pending(store, &transaction)?;
        activate(&transaction)?;
        transaction.phase = TransactionPhase::Activated;
        persist_pending(store, &transaction)?;
        ensure_transaction_fresh(&transaction)?;
        execute_provider_command(&transaction, &transaction.provider.reload, "reload")?;
        transaction.phase = TransactionPhase::Reloaded;
        persist_pending(store, &transaction)?;
        ensure_transaction_fresh(&transaction)?;
        verify_public(
            &provider.public_url,
            &hostname,
            &material.leaf_sha256,
            material.root_store.clone(),
            &provider.config,
        )?;
        transaction.phase = TransactionPhase::Verified;
        persist_pending(store, &transaction)?;
        Ok(CertificateReceipt {
            schema: RECEIPT_SCHEMA,
            jti: jti.clone(),
            deployment_id: record.deployment_id.clone(),
            declaration_revision: record.declaration_revision,
            tenant,
            hostname,
            capability: "proxy_tls".to_owned(),
            revision: target_revision,
            source: transaction.source.clone(),
            material_sha256: material.material_sha256.clone(),
            leaf_certificate_sha256: material.leaf_sha256.clone(),
            certificate_not_after: material.not_after,
            provider_protocol: PROVIDER_PROTOCOL.to_owned(),
            provider_config_sha256: provider.config_sha256.clone(),
            trust_anchors_sha256: provider.trust_anchors_sha256.clone(),
            generation,
            activation_link: provider.config.activation_link.clone(),
            public_url: provider.public_url.to_string(),
            transaction_created_at: transaction.created_at,
            transaction_expires_at: transaction.expires_at,
            verified_at: Utc::now().timestamp(),
        })
    })();

    match result {
        Ok(receipt) => {
            persist_receipt(store, &record, &receipt)?;
            transaction.phase = TransactionPhase::Committed;
            persist_pending(store, &transaction)?;
            finalize_transaction(store, &transaction)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        Err(error) => {
            transaction.last_error = Some(format!("{error:#}"));
            match rollback_transaction(&mut transaction, previous.as_ref(), &provider) {
                Ok(()) => {
                    finalize_transaction(store, &transaction)?;
                    bail!(
                        "TLS certificate apply failed and the previous generation was restored: {error:#}"
                    )
                }
                Err(rollback) => {
                    transaction.phase = TransactionPhase::RollbackFailed;
                    transaction.last_error =
                        Some(format!("apply={error:#}; rollback={rollback:#}"));
                    persist_pending(store, &transaction)?;
                    bail!(
                        "TLS certificate apply failed and rollback requires `tls certificate recover`: apply={error:#}; rollback={rollback:#}"
                    )
                }
            }
        }
    }
}

fn recover(
    store: &DeploymentStore,
    selector: Option<&str>,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let selected = store.resolve(selector, true)?;
    let _deployment_lock = store.deployment_lock(&selected.deployment_id)?;
    let record = store.reload_locked(&selected)?;
    let _shared_locks = store.shared_capability_locks(&record, &[Capability::ProxyTls])?;
    record.require_mutation(&[Capability::ProxyTls])?;
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    let mut transaction = load_pending(store, &record, &tenant, &hostname)?
        .context("no pending TLS certificate transaction exists for this binding")?;
    validate_transaction_binding(store, &transaction, &record, &tenant, &hostname)?;
    let _provider_lock = store.shared_resource_lock(&provider_lock_id(&transaction.provider))?;
    let previous = load_receipt(store, &record, &tenant, &hostname)?;
    let committed = if previous
        .as_ref()
        .is_some_and(|receipt| receipt.jti == transaction.jti)
    {
        previous.clone()
    } else {
        // Before accepting an archived target receipt, require the current
        // marker to still describe the exact pre-transaction state. The
        // activation pointer may already reference the target generation, so
        // this check deliberately validates identity rather than liveness.
        validate_previous_receipt_binding(&transaction, previous.as_ref())?;
        load_revision_receipt(
            store,
            &record,
            &tenant,
            &hostname,
            transaction.target_revision,
        )?
    };
    if let Some(receipt) = committed.as_ref() {
        validate_committed_receipt_binding(&transaction, receipt)?;
        if active_generation(&transaction.provider)?.as_ref() != Some(&transaction.generation) {
            bail!("committed TLS receipt exists but the active generation differs");
        }
        // Reassert both commit markers. This restores a missing current receipt
        // only from exact archived bytes and also detects a replaced archive
        // before the pending transaction is finalized.
        persist_receipt(store, &record, receipt)?;
        transaction.phase = TransactionPhase::Committed;
        persist_pending(store, &transaction)?;
        finalize_transaction(store, &transaction)?;
        println!("{}", serde_json::to_string_pretty(&transaction)?);
        return Ok(());
    }
    let observed = active_generation(&transaction.provider)?;
    validate_recovery_activation_state(&transaction, observed.as_deref())?;
    let provider = loaded_provider_from_transaction(store, &transaction)?;
    rollback_transaction(&mut transaction, previous.as_ref(), &provider)?;
    finalize_transaction(store, &transaction)?;
    println!("{}", serde_json::to_string_pretty(&transaction)?);
    Ok(())
}

fn resolve_certificate_source(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    input: &TlsCertificateInput,
    provider: &LoadedProvider,
) -> anyhow::Result<ResolvedCertificateSource> {
    match &input.source {
        TlsCertificateSource::ExternalFiles {
            certificate,
            private_key,
        } => Ok(ResolvedCertificateSource::ExternalFiles {
            certificate: certificate.clone(),
            private_key: private_key.clone(),
        }),
        TlsCertificateSource::CurrentAcmeReceipt => {
            acme::current_install_source(store, record, provider, &input.tenant, &input.hostname)
                .map(Box::new)
                .map(ResolvedCertificateSource::AcmeReceipt)
        }
    }
}

fn bind_certificate_source(
    source: &ResolvedCertificateSource,
    material: &ValidatedMaterial,
) -> anyhow::Result<CertificateSourceBinding> {
    match source {
        ResolvedCertificateSource::ExternalFiles { .. } => {
            Ok(CertificateSourceBinding::ExternalFiles {
                certificate_sha256: material.certificate_sha256.clone(),
                private_key_sha256: material.private_key_sha256.clone(),
            })
        }
        ResolvedCertificateSource::AcmeReceipt(source) => {
            if source.certificate_sha256 != material.certificate_sha256
                || source.private_key_sha256 != material.private_key_sha256
                || source.leaf_certificate_sha256 != material.leaf_sha256
                || source.material_sha256 != material.material_sha256
                || source.certificate_not_after != material.not_after
            {
                bail!("ACME issuance receipt differs from the offline-validated TLS material");
            }
            Ok(CertificateSourceBinding::AcmeReceipt {
                receipt_sha256: source.receipt_sha256.clone(),
                issuance_jti: source.issuance_jti.clone(),
                issuance_declaration_revision: source.issuance_declaration_revision,
                issuance_revision: source.issuance_revision,
                acme_protocol: source.acme_protocol.clone(),
                acme_config_sha256: source.acme_config_sha256.clone(),
                certificate_sha256: source.certificate_sha256.clone(),
                private_key_sha256: source.private_key_sha256.clone(),
                issued_at: source.issued_at,
            })
        }
    }
}

fn validate_installed_material(
    receipt: &CertificateReceipt,
    material: &ValidatedMaterial,
) -> anyhow::Result<()> {
    let (certificate_sha256, private_key_sha256) = source_file_sha256(&receipt.source);
    if receipt.material_sha256 != material.material_sha256
        || receipt.leaf_certificate_sha256 != material.leaf_sha256
        || receipt.certificate_not_after != material.not_after
        || certificate_sha256 != material.certificate_sha256
        || private_key_sha256 != material.private_key_sha256
    {
        bail!("active TLS generation differs from the committed certificate receipt");
    }
    Ok(())
}

fn validate_receipt_provider_authority(
    receipt: &CertificateReceipt,
    provider: &LoadedProvider,
) -> anyhow::Result<()> {
    if receipt.provider_config_sha256 != provider.config_sha256
        || receipt.trust_anchors_sha256 != provider.trust_anchors_sha256
        || receipt.activation_link != provider.config.activation_link
        || receipt.public_url != provider.public_url.as_str()
    {
        bail!("committed TLS receipt differs from the current provider authority");
    }
    Ok(())
}

fn source_file_sha256(source: &CertificateSourceBinding) -> (&str, &str) {
    match source {
        CertificateSourceBinding::ExternalFiles {
            certificate_sha256,
            private_key_sha256,
        }
        | CertificateSourceBinding::AcmeReceipt {
            certificate_sha256,
            private_key_sha256,
            ..
        } => (certificate_sha256, private_key_sha256),
    }
}

fn build_plan(
    record: &DeploymentRecord,
    input: &TlsCertificateInput,
    provider: &LoadedProvider,
    source: &CertificateSourceBinding,
    material: &ValidatedMaterial,
    current: Option<&CertificateReceipt>,
) -> anyhow::Result<CertificatePlan> {
    validate_active_receipt(&provider.config, current)?;
    if let Some(current) = current {
        validate_receipt_provider_authority(current, provider)?;
    }
    ensure_source_not_current(current, source)?;
    let current_revision = current.map_or(0, |receipt| receipt.revision);
    let grant = record.capabilities.grant(Capability::ProxyTls);
    Ok(CertificatePlan {
        schema: PLAN_SCHEMA,
        jti: uuid::Uuid::now_v7().to_string(),
        deployment_id: record.deployment_id.clone(),
        declaration_revision: record.declaration_revision,
        tenant: canonical_tenant(&input.tenant)?,
        hostname: canonical_hostname(&input.hostname)?,
        capability: "proxy_tls",
        capability_responsibility: format!("{:?}", grant.responsibility).to_ascii_lowercase(),
        capability_scope: format!("{:?}", grant.scope).to_ascii_lowercase(),
        provider_protocol: PROVIDER_PROTOCOL.to_owned(),
        provider_config_sha256: provider.config_sha256.clone(),
        trust_anchors_sha256: provider.trust_anchors_sha256.clone(),
        source: source.clone(),
        material_sha256: material.material_sha256.clone(),
        leaf_certificate_sha256: material.leaf_sha256.clone(),
        certificate_not_after: material.not_after,
        current_revision,
        target_revision: current_revision
            .checked_add(1)
            .context("TLS material revision overflow")?,
        transaction_expires_at: Utc::now().timestamp() + TRANSACTION_TTL_SECONDS,
        steps: vec![
            "offline-chain-san-key-expiry-usage-validation",
            "unique-generation-write-fsync",
            "candidate-provider-validation",
            "atomic-current-pointer-replace",
            "provider-reload",
            "public-tls-identity-and-health-verification",
            "receipt-commit-or-rollback",
        ],
    })
}

fn ensure_source_not_current(
    current: Option<&CertificateReceipt>,
    source: &CertificateSourceBinding,
) -> anyhow::Result<()> {
    if current.is_some_and(|receipt| &receipt.source == source) {
        bail!("the selected TLS certificate source is already the active committed revision");
    }
    Ok(())
}

fn load_provider(
    store: &DeploymentStore,
    path: &Path,
    requested_tenant: &str,
    requested_hostname: &str,
) -> anyhow::Result<LoadedProvider> {
    let bytes = read_secure_regular_file(
        path,
        "TLS provider configuration",
        false,
        MAX_PROVIDER_BYTES,
    )?;
    let config: ProviderConfig =
        serde_json::from_slice(&bytes).context("TLS provider configuration is invalid")?;
    validate_provider_config(store, &config, requested_tenant, requested_hostname)?;
    let trust_anchors = read_secure_regular_file(
        &config.trust_anchors,
        "TLS trust anchors",
        false,
        MAX_TRUST_ANCHOR_BYTES,
    )?;
    let public_url =
        Url::parse(&config.public_url).context("TLS provider public_url is invalid")?;
    Ok(LoadedProvider {
        config,
        config_sha256: sha256(&bytes),
        trust_anchors_sha256: sha256(&trust_anchors),
        trust_anchors: trust_anchors.to_vec(),
        public_url,
    })
}

fn loaded_provider_from_transaction(
    store: &DeploymentStore,
    transaction: &CertificateTransaction,
) -> anyhow::Result<LoadedProvider> {
    validate_provider_config(
        store,
        &transaction.provider,
        &transaction.tenant,
        &transaction.hostname,
    )?;
    let trust_anchors = transaction.trust_anchors_pem.as_bytes().to_vec();
    if trust_anchors.len() as u64 > MAX_TRUST_ANCHOR_BYTES
        || sha256(&trust_anchors) != transaction.trust_anchors_sha256
    {
        bail!("TLS transaction trust anchors do not match their bound digest");
    }
    root_store_from_pem(&trust_anchors)?;
    let public_url =
        Url::parse(&transaction.provider.public_url).context("TLS public URL is invalid")?;
    Ok(LoadedProvider {
        config: transaction.provider.clone(),
        config_sha256: transaction.provider_config_sha256.clone(),
        trust_anchors,
        trust_anchors_sha256: transaction.trust_anchors_sha256.clone(),
        public_url,
    })
}

fn validate_provider_config(
    store: &DeploymentStore,
    config: &ProviderConfig,
    requested_tenant: &str,
    requested_hostname: &str,
) -> anyhow::Result<()> {
    ensure_provider_platform_support()?;
    if config.schema != PROVIDER_SCHEMA || config.protocol != PROVIDER_PROTOCOL {
        bail!("unsupported TLS provider schema or protocol");
    }
    if canonical_tenant(&config.tenant)? != canonical_tenant(requested_tenant)?
        || canonical_hostname(&config.hostname)? != canonical_hostname(requested_hostname)?
    {
        bail!("TLS provider tenant/hostname binding differs from the requested binding");
    }
    validate_absolute_normalized(&config.material_root, "TLS material root")?;
    validate_absolute_normalized(&config.activation_link, "TLS activation link")?;
    validate_absolute_normalized(&config.trust_anchors, "TLS trust anchors")?;
    validate_secure_directory(&config.material_root, "TLS material root", true)?;
    if config.activation_link != config.material_root.join("current") {
        bail!("TLS activation_link must be material_root/current");
    }
    for root in [
        &store.config_root,
        &store.state_root,
        &store.break_glass_root,
    ] {
        if config.material_root.starts_with(root) || root.starts_with(&config.material_root) {
            bail!("TLS material root must not overlap controller state or recovery roots");
        }
    }
    let url = Url::parse(&config.public_url).context("TLS provider public_url is invalid")?;
    let public_hostname = url
        .host_str()
        .context("TLS provider public_url has no hostname")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || canonical_hostname(public_hostname)? != canonical_hostname(requested_hostname)?
    {
        bail!(
            "TLS provider public_url must be an HTTPS URL for the exact bound hostname without credentials, query, or fragment"
        );
    }
    if config.accepted_statuses.is_empty()
        || config
            .accepted_statuses
            .iter()
            .any(|status| !(200..=299).contains(status))
    {
        bail!("TLS provider accepted_statuses must contain only explicit 2xx statuses");
    }
    if !(3600..=90 * 24 * 3600).contains(&config.minimum_validity_seconds)
        || !(1..=60).contains(&config.connect_timeout_seconds)
        || !(1..=60).contains(&config.request_timeout_seconds)
    {
        bail!("TLS provider validity and timeout bounds are invalid");
    }
    validate_provider_command(&config.validate, "validate")?;
    validate_provider_command(&config.reload, "reload")?;
    Ok(())
}

#[cfg(unix)]
fn ensure_provider_platform_support() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_provider_platform_support() -> anyhow::Result<()> {
    bail!("TLS external-generation provider requires Unix atomic symlink semantics")
}

fn stage_generation(
    transaction: &CertificateTransaction,
    material: &ValidatedMaterial,
) -> anyhow::Result<()> {
    let generations = transaction.provider.material_root.join("generations");
    ensure_private_directory(&transaction.provider.material_root, "TLS material root")?;
    ensure_private_directory(&generations, "TLS generation root")?;
    match fs::symlink_metadata(&transaction.generation) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("TLS target generation already exists"),
        Err(error) => return Err(error).context("failed to inspect TLS target generation"),
    }
    fs::create_dir(&transaction.generation).context("failed to create unique TLS generation")?;
    sync_parent(&transaction.generation).context("failed to persist unique TLS generation")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&transaction.generation, fs::Permissions::from_mode(0o700))?;
    }
    atomic_write(
        &transaction.generation.join("fullchain.pem"),
        &material.certificate_pem,
        0o644,
    )?;
    atomic_write(
        &transaction.generation.join("private-key.pem"),
        &material.private_key_pem,
        0o600,
    )?;
    atomic_write(
        &transaction.generation.join("material.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1,
            "jti": transaction.jti,
            "deployment_id": transaction.deployment_id,
            "declaration_revision": transaction.declaration_revision,
            "tenant": transaction.tenant,
            "hostname": transaction.hostname,
            "capability": transaction.capability,
            "revision": transaction.target_revision,
            "material_sha256": transaction.material_sha256,
            "leaf_certificate_sha256": transaction.leaf_certificate_sha256,
            "certificate_not_after": transaction.certificate_not_after,
        }))?,
        0o600,
    )?;
    Ok(())
}

fn activate(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    let observed = active_generation(&transaction.provider)?;
    if observed != transaction.previous_generation {
        bail!("TLS activation pointer changed after transaction preparation");
    }
    symlink_atomic(
        &transaction.generation,
        &transaction.provider.activation_link,
    )
}

fn rollback_transaction(
    transaction: &mut CertificateTransaction,
    previous: Option<&CertificateReceipt>,
    provider: &LoadedProvider,
) -> anyhow::Result<()> {
    if transaction.phase.activation_may_have_happened() {
        let previous_roots = previous
            .map(|receipt| validate_rollback_material(receipt, provider))
            .transpose()?;
        restore_previous_activation(transaction)?;
        match (previous, previous_roots) {
            (Some(previous), Some(roots)) => verify_public(
                &provider.public_url,
                &transaction.hostname,
                &previous.leaf_certificate_sha256,
                roots,
                &transaction.provider,
            )?,
            (None, None) => verify_public_not_leaf(
                &provider.public_url,
                &transaction.hostname,
                &transaction.leaf_certificate_sha256,
                root_store_from_pem(&provider.trust_anchors)?,
                &transaction.provider,
            )?,
            _ => bail!("TLS rollback proof state is inconsistent"),
        }
    }
    remove_inactive_generation(transaction)?;
    transaction.phase = TransactionPhase::RolledBack;
    Ok(())
}

fn restore_previous_activation(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    match &transaction.previous_generation {
        Some(previous_generation) => {
            symlink_atomic(previous_generation, &transaction.provider.activation_link)?;
        }
        None => remove_file_durable(&transaction.provider.activation_link)?,
    }
    execute_provider_command(transaction, &transaction.provider.reload, "rollback reload")?;
    if active_generation(&transaction.provider)? != transaction.previous_generation {
        bail!("TLS rollback activation pointer does not match the previous generation");
    }
    Ok(())
}

fn validate_rollback_material(
    receipt: &CertificateReceipt,
    provider: &LoadedProvider,
) -> anyhow::Result<RootCertStore> {
    validate_receipt_provider_authority(receipt, provider)?;
    let material = load_and_validate_material(
        &receipt.generation.join("fullchain.pem"),
        &receipt.generation.join("private-key.pem"),
        &receipt.hostname,
        provider,
    )?;
    validate_installed_material(receipt, &material)?;
    Ok(material.root_store)
}

fn remove_inactive_generation(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    if active_generation(&transaction.provider)?.as_ref() == Some(&transaction.generation) {
        bail!("refusing to remove the active TLS generation");
    }
    let expected_parent = transaction.provider.material_root.join("generations");
    if transaction.generation.parent() != Some(expected_parent.as_path()) {
        bail!("TLS transaction generation escaped the provider generation root");
    }
    for name in ["material.json", "private-key.pem", "fullchain.pem"] {
        remove_file_durable(&transaction.generation.join(name))?;
    }
    match fs::remove_dir(&transaction.generation) {
        Ok(()) => sync_parent(&transaction.generation)
            .context("failed to persist removal of inactive TLS generation"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to remove inactive TLS generation"),
    }
}

fn execute_provider_command(
    transaction: &CertificateTransaction,
    command: &ProviderCommand,
    label: &str,
) -> anyhow::Result<()> {
    validate_provider_command(command, label)?;
    let output = Process::new(command.program.as_os_str())
        .args(command.args.iter())
        .env("NAZOAUTHCTL_TLS_PROVIDER_PROTOCOL", PROVIDER_PROTOCOL)
        .env("NAZOAUTHCTL_TLS_CAPABILITY", "proxy_tls")
        .env("NAZOAUTHCTL_TLS_DEPLOYMENT_ID", &transaction.deployment_id)
        .env(
            "NAZOAUTHCTL_TLS_DECLARATION_REVISION",
            transaction.declaration_revision.to_string(),
        )
        .env("NAZOAUTHCTL_TLS_TENANT", &transaction.tenant)
        .env("NAZOAUTHCTL_TLS_HOSTNAME", &transaction.hostname)
        .env("NAZOAUTHCTL_TLS_JTI", &transaction.jti)
        .env(
            "NAZOAUTHCTL_TLS_REVISION",
            transaction.target_revision.to_string(),
        )
        .env(
            "NAZOAUTHCTL_TLS_MATERIAL_SHA256",
            &transaction.material_sha256,
        )
        .env(
            "NAZOAUTHCTL_TLS_LEAF_CERTIFICATE_SHA256",
            &transaction.leaf_certificate_sha256,
        )
        .env(
            "NAZOAUTHCTL_TLS_PROVIDER_CONFIG_SHA256",
            &transaction.provider_config_sha256,
        )
        .env(
            "NAZOAUTHCTL_TLS_TRUST_ANCHORS_SHA256",
            &transaction.trust_anchors_sha256,
        )
        .env(
            "NAZOAUTHCTL_TLS_EXPIRES_AT",
            transaction.expires_at.to_string(),
        )
        .env(
            "NAZOAUTHCTL_TLS_CANDIDATE_DIR",
            transaction.generation.as_os_str(),
        )
        .env(
            "NAZOAUTHCTL_TLS_CURRENT_LINK",
            transaction.provider.activation_link.as_os_str(),
        )
        .timeout(Duration::from_secs(60))
        .output()
        .with_context(|| format!("TLS provider {label} command could not run"))?;
    if !output.status.success() {
        bail!(
            "TLS provider {label} command failed with status {}",
            output.status
        );
    }
    Ok(())
}

fn validate_provider_command(command: &ProviderCommand, label: &str) -> anyhow::Result<()> {
    validate_absolute_normalized(
        &command.program,
        &format!("TLS provider {label} executable"),
    )?;
    if command.args.len() > 32
        || command
            .args
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > 4096 || argument.contains('\0'))
    {
        bail!("TLS provider {label} arguments are invalid");
    }
    validate_secure_directory(
        command
            .program
            .parent()
            .context("TLS provider executable has no parent directory")?,
        &format!("TLS provider {label} executable"),
        false,
    )?;
    let metadata = fs::symlink_metadata(&command.program)
        .with_context(|| format!("failed to inspect TLS provider {label} executable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("TLS provider {label} executable must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode();
        if metadata.uid() != 0 || mode & 0o022 != 0 || mode & 0o111 == 0 {
            bail!(
                "TLS provider {label} executable must be root-owned, executable, and not group/world writable"
            );
        }
    }
    Ok(())
}

fn active_generation(provider: &ProviderConfig) -> anyhow::Result<Option<PathBuf>> {
    match fs::symlink_metadata(&provider.activation_link) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                bail!("TLS activation link is not a symlink");
            }
            let target = fs::read_link(&provider.activation_link)?;
            if !target.is_absolute()
                || target.parent() != Some(provider.material_root.join("generations").as_path())
            {
                bail!("TLS activation link points outside the provider generation root");
            }
            let target_metadata = fs::symlink_metadata(&target)?;
            if target_metadata.file_type().is_symlink() || !target_metadata.is_dir() {
                bail!("TLS activation target is not a real generation directory");
            }
            Ok(Some(target))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to inspect TLS activation link"),
    }
}

fn validate_active_receipt(
    provider: &ProviderConfig,
    receipt: Option<&CertificateReceipt>,
) -> anyhow::Result<()> {
    let active = active_generation(provider)?;
    match (active, receipt) {
        (None, None) => Ok(()),
        (Some(active), Some(receipt))
            if active == receipt.generation
                && receipt.activation_link == provider.activation_link
                && receipt.provider_protocol == PROVIDER_PROTOCOL =>
        {
            Ok(())
        }
        (Some(_), None) => bail!("TLS activation exists without an authoritative receipt"),
        (None, Some(_)) => bail!("TLS receipt exists but its activation link is missing"),
        (Some(_), Some(_)) => bail!("TLS activation link differs from the authoritative receipt"),
    }
}

fn validate_previous_receipt_binding(
    transaction: &CertificateTransaction,
    receipt: Option<&CertificateReceipt>,
) -> anyhow::Result<()> {
    match (transaction.expected_revision, receipt) {
        (0, None)
            if transaction.previous_generation.is_none()
                && transaction.previous_leaf_certificate_sha256.is_none()
                && transaction.previous_receipt_sha256.is_none() =>
        {
            Ok(())
        }
        (expected_revision, Some(receipt))
            if expected_revision > 0
                && receipt.revision == expected_revision
                && transaction.previous_generation.as_ref() == Some(&receipt.generation)
                && transaction.previous_leaf_certificate_sha256.as_ref()
                    == Some(&receipt.leaf_certificate_sha256) =>
        {
            let observed = receipt_sha256(receipt)?;
            if transaction.previous_receipt_sha256.as_deref() != Some(observed.as_str()) {
                bail!("TLS previous receipt digest no longer matches the pending transaction");
            }
            Ok(())
        }
        _ => bail!("TLS previous receipt no longer matches the pending transaction"),
    }
}

fn validate_recovery_activation_state(
    transaction: &CertificateTransaction,
    observed: Option<&Path>,
) -> anyhow::Result<()> {
    let previous = transaction.previous_generation.as_deref();
    let target = Some(transaction.generation.as_path());
    let valid = if transaction.phase.activation_may_have_happened() {
        observed == previous || observed == target
    } else {
        observed == previous
    };
    if !valid {
        bail!("TLS activation pointer changed outside the pending transaction");
    }
    Ok(())
}

fn validate_committed_receipt_binding(
    transaction: &CertificateTransaction,
    receipt: &CertificateReceipt,
) -> anyhow::Result<()> {
    if receipt.jti != transaction.jti
        || receipt.deployment_id != transaction.deployment_id
        || receipt.declaration_revision != transaction.declaration_revision
        || receipt.tenant != transaction.tenant
        || receipt.hostname != transaction.hostname
        || receipt.capability != transaction.capability
        || receipt.revision != transaction.target_revision
        || receipt.source != transaction.source
        || receipt.material_sha256 != transaction.material_sha256
        || receipt.leaf_certificate_sha256 != transaction.leaf_certificate_sha256
        || receipt.certificate_not_after != transaction.certificate_not_after
        || receipt.provider_config_sha256 != transaction.provider_config_sha256
        || receipt.trust_anchors_sha256 != transaction.trust_anchors_sha256
        || receipt.generation != transaction.generation
        || receipt.activation_link != transaction.provider.activation_link
        || receipt.public_url != transaction.provider.public_url
        || receipt.transaction_created_at != transaction.created_at
        || receipt.transaction_expires_at != transaction.expires_at
    {
        bail!("committed TLS receipt does not match the pending transaction");
    }
    Ok(())
}

fn binding_directory(
    store: &DeploymentStore,
    deployment_id: &str,
    tenant: &str,
    hostname: &str,
) -> PathBuf {
    let identity = sha256(format!("{tenant}\0{hostname}").as_bytes());
    store
        .deployment_state_dir(deployment_id)
        .join("tls")
        .join(identity)
}

fn provider_lock_id(provider: &ProviderConfig) -> String {
    format!(
        "tls-{}",
        sha256(provider.activation_link.to_string_lossy().as_bytes())
    )
}

fn pending_path(store: &DeploymentStore, transaction: &CertificateTransaction) -> PathBuf {
    binding_directory(
        store,
        &transaction.deployment_id,
        &transaction.tenant,
        &transaction.hostname,
    )
    .join("pending.json")
}

fn persist_pending(
    store: &DeploymentStore,
    transaction: &CertificateTransaction,
) -> anyhow::Result<()> {
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
) -> anyhow::Result<Option<CertificateTransaction>> {
    let path =
        binding_directory(store, &record.deployment_id, tenant, hostname).join("pending.json");
    let bytes = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            read_secure_regular_file(
                &path,
                "TLS transaction journal",
                true,
                MAX_TRANSACTION_BYTES,
            )?
        }
        Ok(_) => bail!("TLS transaction journal must be a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to inspect TLS transaction journal"),
    };
    let transaction: CertificateTransaction =
        serde_json::from_slice(&bytes).context("TLS transaction journal is invalid")?;
    if transaction.schema != TRANSACTION_SCHEMA {
        bail!("unsupported TLS transaction journal schema");
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
        bail!("a TLS transaction is pending for this binding; run tls certificate recover")
    }
    Ok(())
}

fn ensure_provider_not_pending(
    store: &DeploymentStore,
    current_deployment_id: &str,
    provider: &ProviderConfig,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let deployments_root = store.state_root.join("deployments");
    let deployments = match fs::read_dir(&deployments_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect deployment TLS state"),
    };
    let mut inspected_deployments = 0_u16;
    let mut inspected_bindings = 0_u32;
    for deployment in deployments {
        let deployment = deployment?;
        inspected_deployments = inspected_deployments
            .checked_add(1)
            .context("too many deployment state entries")?;
        if inspected_deployments > 1024 {
            bail!("too many deployment state entries while fencing TLS provider");
        }
        let metadata = fs::symlink_metadata(deployment.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("deployment state entry must be a real directory");
        }
        let deployment_id = deployment.file_name().to_string_lossy().into_owned();
        let tls_root = deployment.path().join("tls");
        let entries = match fs::read_dir(&tls_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("failed to inspect TLS transaction bindings"),
        };
        for entry in entries {
            let entry = entry?;
            inspected_bindings = inspected_bindings
                .checked_add(1)
                .context("too many TLS transaction bindings")?;
            if inspected_bindings > 4096 {
                bail!("too many TLS transaction bindings");
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("TLS binding state entry must be a real directory");
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !valid_sha256(&name) {
                bail!("TLS binding state directory has an invalid identity");
            }
            let path = entry.path().join("pending.json");
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
                Ok(_) => bail!("TLS transaction journal must be a regular non-symlink file"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).context("failed to inspect TLS transaction journal");
                }
            }
            let bytes = read_secure_regular_file(
                &path,
                "TLS transaction journal",
                true,
                MAX_TRANSACTION_BYTES,
            )?;
            let pending: CertificateTransaction =
                serde_json::from_slice(&bytes).context("TLS transaction journal is invalid")?;
            if pending.schema != TRANSACTION_SCHEMA || pending.deployment_id != deployment_id {
                bail!("TLS transaction journal crosses its deployment state boundary");
            }
            if pending.provider.activation_link == provider.activation_link
                && (pending.deployment_id != current_deployment_id
                    || pending.tenant != tenant
                    || pending.hostname != hostname)
            {
                bail!(
                    "the TLS provider activation resource is fenced by another pending deployment/tenant/hostname transaction"
                );
            }
        }
    }
    Ok(())
}

fn finalize_transaction(
    store: &DeploymentStore,
    transaction: &CertificateTransaction,
) -> anyhow::Result<()> {
    let directory = pending_path(store, transaction)
        .parent()
        .context("TLS transaction path has no parent")?
        .join("transactions");
    atomic_write(
        &directory.join(format!("{}.json", transaction.jti)),
        &serde_json::to_vec_pretty(transaction)?,
        0o600,
    )?;
    remove_file_durable(&pending_path(store, transaction))
}

fn persist_receipt(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    receipt: &CertificateReceipt,
) -> anyhow::Result<()> {
    let directory = binding_directory(
        store,
        &record.deployment_id,
        &receipt.tenant,
        &receipt.hostname,
    );
    persist_receipt_at(&directory, receipt)
}

fn persist_receipt_at(directory: &Path, receipt: &CertificateReceipt) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let archive = receipt_archive_path(directory, receipt.revision);
    match read_optional_receipt_bytes(&archive, "TLS certificate receipt archive")? {
        Some(existing) if existing.as_slice() != bytes.as_slice() => {
            bail!("TLS certificate receipt revision archive contains conflicting evidence")
        }
        Some(_) => {}
        None => atomic_write(&archive, &bytes, 0o600)?,
    }
    atomic_write(&directory.join("receipt.json"), &bytes, 0o600)
}

fn receipt_sha256(receipt: &CertificateReceipt) -> anyhow::Result<String> {
    Ok(sha256(&serde_json::to_vec_pretty(receipt)?))
}

fn provider_snapshot_sha256(provider: &ProviderConfig) -> anyhow::Result<String> {
    let material_root = canonical_digest_path(&provider.material_root, "TLS material root")?;
    let activation_link = canonical_digest_path(&provider.activation_link, "TLS activation link")?;
    let trust_anchors = canonical_digest_path(&provider.trust_anchors, "TLS trust anchors")?;
    let validate_program =
        canonical_digest_path(&provider.validate.program, "TLS validate command")?;
    let reload_program = canonical_digest_path(&provider.reload.program, "TLS reload command")?;
    let authority = (
        provider.schema,
        &provider.protocol,
        &provider.tenant,
        &provider.hostname,
        material_root,
        activation_link,
        trust_anchors,
        &provider.public_url,
        &provider.accepted_statuses,
        provider.minimum_validity_seconds,
        provider.connect_timeout_seconds,
        provider.request_timeout_seconds,
    );
    let commands = (
        (validate_program, &provider.validate.args),
        (reload_program, &provider.reload.args),
    );
    Ok(sha256(&serde_json::to_vec(&(
        PROVIDER_SNAPSHOT_DIGEST_PROTOCOL,
        authority,
        commands,
    ))?))
}

fn canonical_digest_path(path: &Path, label: &str) -> anyhow::Result<Vec<(u8, String)>> {
    path.components()
        .map(|component| {
            let (kind, value) = match component {
                Component::Prefix(prefix) => (0, Some(prefix.as_os_str())),
                Component::RootDir => (1, None),
                Component::CurDir => (2, None),
                Component::ParentDir => (3, None),
                Component::Normal(value) => (4, Some(value)),
            };
            let value = value
                .map(|value| {
                    value
                        .to_str()
                        .with_context(|| format!("{label} contains a non-UTF-8 path component"))
                        .map(str::to_owned)
                })
                .transpose()?
                .unwrap_or_default();
            Ok((kind, value))
        })
        .collect()
}

fn validate_provider_snapshot(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    if !valid_sha256(&transaction.provider_snapshot_sha256)
        || transaction.provider_snapshot_sha256 != provider_snapshot_sha256(&transaction.provider)?
    {
        bail!("TLS transaction provider snapshot does not match its bound digest");
    }
    Ok(())
}

fn ensure_receipt_revision_available(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
    revision: u64,
) -> anyhow::Result<()> {
    let directory = binding_directory(store, &record.deployment_id, tenant, hostname);
    ensure_receipt_archive_available(&directory, revision)
}

fn ensure_receipt_archive_available(directory: &Path, revision: u64) -> anyhow::Result<()> {
    if read_optional_receipt_bytes(
        &receipt_archive_path(directory, revision),
        "TLS certificate receipt archive",
    )?
    .is_some()
    {
        bail!(
            "TLS certificate target revision already has archived evidence; recover or review the interrupted transaction"
        );
    }
    Ok(())
}

fn receipt_archive_path(directory: &Path, revision: u64) -> PathBuf {
    directory.join("receipts").join(format!("{revision}.json"))
}

fn read_optional_receipt_bytes(
    path: &Path,
    label: &str,
) -> anyhow::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            read_secure_regular_file(path, label, true, MAX_PROVIDER_BYTES).map(Some)
        }
        Ok(_) => bail!("{label} must be a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {label}")),
    }
}

fn load_receipt(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<Option<CertificateReceipt>> {
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    let path =
        binding_directory(store, &record.deployment_id, &tenant, &hostname).join("receipt.json");
    load_receipt_at(&path, "TLS certificate receipt", record, &tenant, &hostname)
}

fn load_revision_receipt(
    store: &DeploymentStore,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
    revision: u64,
) -> anyhow::Result<Option<CertificateReceipt>> {
    let tenant = canonical_tenant(tenant)?;
    let hostname = canonical_hostname(hostname)?;
    let directory = binding_directory(store, &record.deployment_id, &tenant, &hostname);
    let receipt = load_receipt_at(
        &receipt_archive_path(&directory, revision),
        "TLS certificate receipt archive",
        record,
        &tenant,
        &hostname,
    )?;
    if receipt
        .as_ref()
        .is_some_and(|receipt| receipt.revision != revision)
    {
        bail!("TLS certificate receipt archive revision does not match its path");
    }
    Ok(receipt)
}

fn load_receipt_at(
    path: &Path,
    label: &str,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<Option<CertificateReceipt>> {
    let Some(bytes) = read_optional_receipt_bytes(path, label)? else {
        return Ok(None);
    };
    let receipt: CertificateReceipt =
        serde_json::from_slice(&bytes).context("TLS certificate receipt is invalid")?;
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.deployment_id != record.deployment_id
        || receipt.declaration_revision > record.declaration_revision
        || receipt.tenant != tenant
        || receipt.hostname != hostname
        || receipt.capability != "proxy_tls"
        || receipt.provider_protocol != PROVIDER_PROTOCOL
        || receipt.transaction_expires_at
            != receipt.transaction_created_at + TRANSACTION_TTL_SECONDS
        || receipt.revision == 0
        || receipt.certificate_not_after <= receipt.transaction_created_at
        || receipt.verified_at < receipt.transaction_created_at
        || receipt.verified_at > receipt.transaction_expires_at
        || receipt.verified_at >= receipt.certificate_not_after
        || uuid::Uuid::parse_str(&receipt.jti)
            .ok()
            .map(|jti| jti.get_version_num())
            != Some(7)
        || !valid_sha256(&receipt.material_sha256)
        || !valid_sha256(&receipt.leaf_certificate_sha256)
        || !valid_sha256(&receipt.provider_config_sha256)
        || !valid_sha256(&receipt.trust_anchors_sha256)
        || !valid_certificate_source_binding(
            &receipt.source,
            receipt.declaration_revision,
            receipt.transaction_created_at,
            receipt.certificate_not_after,
        )
        || receipt.material_sha256
            != source_material_sha256(&receipt.source, &receipt.leaf_certificate_sha256)
    {
        bail!("TLS certificate receipt binding is invalid");
    }
    Ok(Some(receipt))
}

fn validate_transaction_binding(
    store: &DeploymentStore,
    transaction: &CertificateTransaction,
    record: &DeploymentRecord,
    tenant: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    validate_provider_snapshot(transaction)?;
    let target_revision = transaction
        .expected_revision
        .checked_add(1)
        .context("TLS transaction revision overflow")?;
    let valid_previous_shape = if transaction.expected_revision == 0 {
        transaction.previous_generation.is_none()
            && transaction.previous_leaf_certificate_sha256.is_none()
            && transaction.previous_receipt_sha256.is_none()
    } else {
        transaction.previous_generation.is_some()
            && transaction
                .previous_leaf_certificate_sha256
                .as_deref()
                .is_some_and(valid_sha256)
            && transaction
                .previous_receipt_sha256
                .as_deref()
                .is_some_and(valid_sha256)
    };
    if transaction.schema != TRANSACTION_SCHEMA
        || transaction.deployment_id != record.deployment_id
        || transaction.declaration_revision != record.declaration_revision
        || transaction.tenant != tenant
        || transaction.hostname != hostname
        || transaction.capability != "proxy_tls"
        || transaction.provider.protocol != PROVIDER_PROTOCOL
        || transaction.provider.schema != PROVIDER_SCHEMA
        || transaction.target_revision != target_revision
        || !valid_previous_shape
        || transaction.expires_at != transaction.created_at + TRANSACTION_TTL_SECONDS
        || transaction.certificate_not_after <= transaction.created_at
        || !valid_sha256(&transaction.material_sha256)
        || !valid_sha256(&transaction.leaf_certificate_sha256)
        || !valid_sha256(&transaction.provider_config_sha256)
        || !valid_sha256(&transaction.trust_anchors_sha256)
        || !valid_certificate_source_binding(
            &transaction.source,
            transaction.declaration_revision,
            transaction.created_at,
            transaction.certificate_not_after,
        )
        || transaction.material_sha256
            != source_material_sha256(&transaction.source, &transaction.leaf_certificate_sha256)
        || uuid::Uuid::parse_str(&transaction.jti)
            .ok()
            .map(|jti| jti.get_version_num())
            != Some(7)
        || transaction.generation.parent()
            != Some(
                transaction
                    .provider
                    .material_root
                    .join("generations")
                    .as_path(),
            )
        || transaction
            .previous_generation
            .as_ref()
            .is_some_and(|generation| {
                generation.parent()
                    != Some(
                        transaction
                            .provider
                            .material_root
                            .join("generations")
                            .as_path(),
                    )
            })
    {
        bail!("TLS transaction journal binding is invalid");
    }
    validate_provider_config(store, &transaction.provider, tenant, hostname)?;
    Ok(())
}

fn valid_certificate_source_binding(
    source: &CertificateSourceBinding,
    declaration_revision: u64,
    consumed_at: i64,
    certificate_not_after: i64,
) -> bool {
    match source {
        CertificateSourceBinding::ExternalFiles {
            certificate_sha256,
            private_key_sha256,
        } => valid_sha256(certificate_sha256) && valid_sha256(private_key_sha256),
        CertificateSourceBinding::AcmeReceipt {
            receipt_sha256,
            issuance_jti,
            issuance_declaration_revision,
            issuance_revision,
            acme_protocol,
            acme_config_sha256,
            certificate_sha256,
            private_key_sha256,
            issued_at,
        } => {
            valid_sha256(receipt_sha256)
                && valid_sha256(acme_config_sha256)
                && valid_sha256(certificate_sha256)
                && valid_sha256(private_key_sha256)
                && acme_protocol == acme::CONFIG_PROTOCOL
                && *issuance_declaration_revision == declaration_revision
                && *issuance_revision > 0
                && *issued_at <= consumed_at
                && *issued_at < certificate_not_after
                && uuid::Uuid::parse_str(issuance_jti).ok().is_some_and(|jti| {
                    jti.get_version_num() == 7 && jti.to_string() == *issuance_jti
                })
        }
    }
}

fn source_material_sha256(source: &CertificateSourceBinding, leaf_sha256: &str) -> String {
    let certificate_sha256 = match source {
        CertificateSourceBinding::ExternalFiles {
            certificate_sha256, ..
        }
        | CertificateSourceBinding::AcmeReceipt {
            certificate_sha256, ..
        } => certificate_sha256,
    };
    sha256(format!("{leaf_sha256}:{certificate_sha256}").as_bytes())
}

fn ensure_transaction_fresh(transaction: &CertificateTransaction) -> anyhow::Result<()> {
    if Utc::now().timestamp() > transaction.expires_at {
        bail!("TLS transaction expired before commit");
    }
    Ok(())
}

fn canonical_tenant(value: &str) -> anyhow::Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("TLS tenant binding is invalid");
    }
    Ok(value.to_owned())
}

fn canonical_hostname(value: &str) -> anyhow::Result<String> {
    if value.is_empty() || value.len() > 253 || value.contains('*') || value.ends_with('.') {
        bail!("TLS hostname binding is invalid");
    }
    let parsed = url::Host::parse(value).context("TLS hostname binding is invalid")?;
    match parsed {
        url::Host::Domain(domain) => Ok(domain.to_ascii_lowercase()),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            bail!("TLS hostname binding must be a DNS name, not an IP literal")
        }
    }
}

fn validate_absolute_normalized(path: &Path, label: &str) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("{label} must be a normalized absolute non-root path");
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[path = "../tests/unit/tls.rs"]
mod tests;
