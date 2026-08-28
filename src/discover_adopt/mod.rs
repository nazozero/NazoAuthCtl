//! Discover and adopt: read-only target sweeps and controlled takeover of
//! existing NazoAuth deployments (goal plan 07 §6, task G05).
//!
//! `discover` enumerates every NazoAuth DeploymentState on one target through
//! the read-only host-level [`crate::target::HostOperation`] kind
//! `state-list`, handshake-gated like every inspection kind. It reports the
//! authoritative facts per deployment (deployment id, issuer, runtime surface,
//! artifact/config revisions, build identity, resource facts), cross-references
//! the Registry as display-only candidate status, and writes nothing — no
//! registry record, no observation cache, no target-side change, no privilege
//! or controller-key prerequisite. It works on unbound deployments by
//! construction because it only reads.
//!
//! `adopt` re-runs the discovery live (a stored discover report is never an
//! input), builds the B04 [`DiscoveryEvidence`] from the target's own
//! DeploymentState facts over the verified channel — closing the interim
//! boundary where operator input supplied the deployment binding — and
//! registers the InstanceRecord through the controlled evidence path. It
//! signs nothing, needs no controller key, performs zero target-side
//! mutations, and classifies resources conservatively per goal plan 07 §6:
//! only a declared managed+deployment-scoped fact is reported ctl-deletable;
//! everything not provably ctl's stays external/shared with zero-delete
//! protection. Nothing is ever guessed managed.
//!
//! Relocation discipline (task B07): a deployment id discovered under another
//! host than its registered one is a relocation candidate — reported by
//! discover, never silently rewritten, and refused by adopt with stable
//! guidance toward the explicit relocate path, which re-proves the live
//! target identity before moving the binding.
//!
//! The use cases are transport-agnostic by construction: they speak only to
//! an [`ExecutionTarget`], so local and SSH hosts share this exact code and
//! this exact test suite. CLI wiring lands with the I wave.

#[cfg(test)]
mod tests;

use anyhow::{Context as _, bail};
use uuid::Uuid;

use crate::fleet::{
    live_probe, production_target, resolve_host_selector, summarize_hello, summarize_inspection,
};
use crate::registry::{
    DiscoveryEvidence, HostRecord, InstanceRecord, ObservationCache, RegistryStore,
};
use crate::target::{
    ExecutionTarget, HostCompletionBody, HostOperation, HostOutcome, InstanceInspection, Resource,
    ResourceOwnership, ResourceScope,
};

/// Stable rejection: adopt named a deployment that live discovery does not
/// report on this target. Selection accepts exactly matching ids only;
/// substring, fuzzy, and stale-report matches never happen.
pub(crate) const ADOPT_TARGET_UNKNOWN: &str = "ADOPT_TARGET_UNKNOWN";
/// Stable rejection: the deployment is already registered under another host.
/// Adoption never rewrites bindings (B07); the explicit `instance relocate`
/// path owns relocations after live identity proof through the new host.
pub(crate) const ADOPT_RELOCATION_REQUIRED: &str = "ADOPT_RELOCATION_REQUIRED";
/// Stable rejection: the deployment is already registered on this very host.
pub(crate) const ADOPT_ALREADY_REGISTERED: &str = "ADOPT_ALREADY_REGISTERED";

/// Injectable context mirroring the clean-install context: the user-scoped
/// registry plus a way to reach hosts. Tests substitute scripted targets.
pub(crate) type TargetFactory =
    dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>>;

pub(crate) struct DiscoveryContext {
    pub(crate) registry: RegistryStore,
    pub(crate) factory: Box<TargetFactory>,
}

impl DiscoveryContext {
    pub(crate) fn production() -> anyhow::Result<Self> {
        Ok(Self {
            registry: RegistryStore::open_default()?,
            factory: Box::new(production_target),
        })
    }

    fn target_for(&self, record: &HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
        (self.factory)(record)
    }
}

/// One read-only discovery sweep (`discover --host <alias>`).
#[derive(Debug, Clone)]
pub(crate) struct DiscoverRequest {
    /// Optional exact host alias; absent resolves via the shared selector
    /// rules (local auto-ensure, single-host direct, multi-host ambiguity).
    pub(crate) host: Option<String>,
}

/// One controlled takeover
/// (`instance register --host <alias> --deployment-id ID`).
#[derive(Debug, Clone)]
pub(crate) struct AdoptRequest {
    pub(crate) host: Option<String>,
    /// Exact deployment id as displayed by discover. The live sweep must
    /// report this exact id; nothing else binds.
    pub(crate) deployment_id: String,
    /// Optional friendly instance alias; defaults to the deployment id.
    pub(crate) alias: Option<String>,
}

/// Run one read-only `state-list` sweep against an already-verified target
/// and return every discovered deployment inspection, sorted by deployment
/// id. This is the single enumeration seam both transports answer identically.
pub(crate) fn execute_state_list(
    target: &dyn ExecutionTarget,
) -> anyhow::Result<Vec<InstanceInspection>> {
    let operation = HostOperation::state_list(Uuid::now_v7().to_string());
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::StateListed { deployments },
        } => Ok(deployments),
        HostOutcome::Completed { .. } => {
            bail!("the target answered an unexpected completion instead of a discovery listing")
        }
        HostOutcome::Failed { code, detail } => Err(anyhow::anyhow!("{code}: {detail}")),
    }
}

/// Conservative goal-plan-07-§6 classification of one declared resource fact.
/// Nothing is ever upgraded to managed here: only the authoritative target
/// state's own managed+deployment declaration makes a resource ctl-deletable;
/// every other combination — including anything undeclared — stays external
/// or shared with zero-delete protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdoptionClass {
    /// Declared managed + deployment-scoped in the authoritative state; the
    /// only classification any destructive path may ever touch.
    ManagedDeletion,
    /// Not provably ctl-owned, or shared beyond this deployment.
    ExternalZeroDelete,
}

/// One resource fact paired with its conservative adoption classification.
#[derive(Clone, Debug)]
pub(crate) struct ClassifiedResource {
    pub(crate) resource: Resource,
    pub(crate) class: AdoptionClass,
}

/// Classify declared resources for display. Pure projection over the target's
/// own facts — the schema already forbids managed+shared, and the match below
/// still fails that combination closed as external rather than trusting it.
pub(crate) fn classify_resources(resources: &[Resource]) -> Vec<ClassifiedResource> {
    resources
        .iter()
        .map(|resource| {
            let class = match (resource.ownership, resource.scope) {
                (ResourceOwnership::Managed, ResourceScope::Deployment) => {
                    AdoptionClass::ManagedDeletion
                }
                _ => AdoptionClass::ExternalZeroDelete,
            };
            ClassifiedResource {
                resource: resource.clone(),
                class,
            }
        })
        .collect()
}

/// Registry cross-reference status of one discovered deployment (display only;
/// discover writes nothing in every branch).
enum CandidateStatus {
    Unregistered,
    RegisteredHere { alias: String },
    RegisteredElsewhere { alias: String, host_alias: String },
}

fn candidate_status(
    context: &DiscoveryContext,
    host_id: uuid::Uuid,
    deployment_id: &str,
) -> anyhow::Result<CandidateStatus> {
    match context.registry.instance_by_deployment(deployment_id)? {
        None => Ok(CandidateStatus::Unregistered),
        Some(record) if record.host_id == host_id => Ok(CandidateStatus::RegisteredHere {
            alias: record.alias,
        }),
        Some(record) => {
            let host_alias = context
                .registry
                .host_by_id(record.host_id)?
                .map(|host| host.alias)
                .unwrap_or_else(|| record.host_id.to_string());
            Ok(CandidateStatus::RegisteredElsewhere {
                alias: record.alias,
                host_alias,
            })
        }
    }
}

/// The G05 discover entry point: one handshake-gated read-only sweep with a
/// per-deployment fact report and Registry cross-reference. Multi-target
/// output lists every deployment and demands an exact id for any follow-up;
/// bare discover writes zero registry records.
///
/// Delivery boundary: the I wave wires this into the CLI parser; until then
/// the use case and its shared test suite are the contract.
pub(crate) fn run_discover(
    context: &DiscoveryContext,
    request: DiscoverRequest,
) -> anyhow::Result<String> {
    let host = resolve_host_selector(&context.registry, request.host.as_deref())?;
    let target = context.target_for(&host)?;
    // C08 gate upstream of the read-only kind, like every inspection.
    let hello = live_probe(target.as_ref(), &host).context(format!(
        "host '{}' failed its live verification; nothing was discovered and nothing changed",
        host.alias
    ))?;
    let inspections = execute_state_list(target.as_ref())
        .context("discovery sweep failed; nothing was changed")?;

    let mut report = format!(
        "discovered {} NazoAuth deployment(s) on host '{}'\nhelper identity: {}\n",
        inspections.len(),
        host.alias,
        summarize_hello(&hello)
    );
    if inspections.is_empty() {
        report.push_str("(no NazoAuth deployments found on this target; nothing to adopt)\n");
        return Ok(report);
    }

    for (index, inspection) in inspections.iter().enumerate() {
        report.push_str(&render_discovery_block(
            index + 1,
            inspection,
            &candidate_status(context, host.host_id, &inspection.deployment_id)?,
            &host.alias,
        ));
    }
    report.push_str(
        "discover is strictly read-only: no registry record, no cache entry, no target change\n",
    );
    Ok(report)
}

fn build_identity_line(inspection: &InstanceInspection) -> String {
    match &inspection.current_build_identity {
        Some(identity) => format!(
            "{} v{} (commit {})",
            identity.product, identity.version, identity.commit
        ),
        None => "not recorded".to_owned(),
    }
}

fn render_discovery_block(
    index: usize,
    inspection: &InstanceInspection,
    status: &CandidateStatus,
    host_alias: &str,
) -> String {
    let classified = classify_resources(&inspection.resources);
    let managed = classified
        .iter()
        .filter(|item| item.class == AdoptionClass::ManagedDeletion)
        .count();
    let artifacts = match (&inspection.artifact.current, &inspection.artifact.previous) {
        (None, None) => "-".to_owned(),
        (current, previous) => format!(
            "current={} previous={}",
            current.clone().unwrap_or_else(|| "-".to_owned()),
            previous.clone().unwrap_or_else(|| "-".to_owned())
        ),
    };
    let health = if inspection.healthy { "ok" } else { "down" };
    let mut block = format!(
        "[{index}] {}\n    issuer: {}\n    runtime: {}/{}\n    config: revision {} (schema {}, {})\n    artifacts: {artifacts}\n    build identity: {}\n    health: {health} — {}\n",
        inspection.deployment_id,
        inspection.issuer,
        inspection.runtime.kind,
        inspection.runtime.object,
        inspection.revision,
        inspection.config_schema,
        inspection.config_reference,
        build_identity_line(inspection),
        inspection.health_summary,
    );
    if classified.is_empty() {
        block.push_str("    resources: none declared — treated entirely as external\n");
    } else {
        block.push_str(&format!(
            "    resources: {} declared (managed+deletable: {managed}, external/shared zero-delete: {})\n",
            classified.len(),
            classified.len() - managed
        ));
        for item in &classified {
            let note = match item.class {
                AdoptionClass::ManagedDeletion => "managed+deployment",
                AdoptionClass::ExternalZeroDelete => "external/shared (zero-delete protection)",
            };
            block.push_str(&format!(
                "      - {} [{}] {} — {note}\n",
                item.resource.resource_id, item.resource.kind, item.resource.locator
            ));
        }
    }
    match status {
        CandidateStatus::Unregistered => block.push_str(&format!(
            "    status: registration candidate\n    next step: nazoauthctl instance register --host {host_alias} --deployment-id {}\n",
            inspection.deployment_id
        )),
        CandidateStatus::RegisteredHere { alias } => block.push_str(&format!(
            "    status: registered on this host as '{alias}'\n"
        )),
        CandidateStatus::RegisteredElsewhere { alias, host_alias: bound } => block.push_str(&format!(
            "    status: RELOCATION CANDIDATE — registered under host '{bound}' as '{alias}'; \
             this record is never rewritten by discovery\n    relocation requires explicit \
             proof through the new host: nazoauthctl instance relocate --instance {alias} --to-host {host_alias}\n"
        )),
    }
    block.push('\n');
    block
}

/// The G05 adopt entry point: live re-discovery, evidence derived from the
/// target's own DeploymentState, one controlled InstanceRecord write, and the
/// bind next-step guidance. Signs nothing, needs no controller key, changes
/// no target state.
///
/// Delivery boundary: the I wave wires this into the CLI parser; until then
/// the use case and its shared test suite are the contract.
pub(crate) fn run_adopt(
    context: &DiscoveryContext,
    request: AdoptRequest,
) -> anyhow::Result<String> {
    let requested = request.deployment_id.trim();
    if requested.is_empty() || requested != request.deployment_id {
        bail!("adopt requires an exact non-empty --deployment-id as displayed by discover");
    }

    // 1. Resolve the host via the shared selector rules.
    let host = resolve_host_selector(&context.registry, request.host.as_deref())?;
    let target = context.target_for(&host)?;

    // 2. Live verified contact before anything else (C08 gate upstream of
    //    the read-only enumeration too).
    let hello = live_probe(target.as_ref(), &host).context(format!(
        "host '{}' failed its live verification; nothing was adopted and nothing changed",
        host.alias
    ))?;

    // 3. Re-run discovery LIVE: adopt never consumes a stored discover
    //    report, so drift between a discover run and this adopt cannot poison
    //    the registration — vanished or renamed targets fail closed here.
    let inspections = execute_state_list(target.as_ref())
        .context("live discovery failed during adopt; nothing was registered")?;
    let inspection = inspections
        .iter()
        .find(|candidate| candidate.deployment_id == request.deployment_id)
        .cloned()
        .ok_or_else(|| {
            let known = if inspections.is_empty() {
                "-".to_owned()
            } else {
                inspections
                    .iter()
                    .map(|candidate| candidate.deployment_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            anyhow::anyhow!(
                "{ADOPT_TARGET_UNKNOWN}: no deployment '{}' was discovered on host '{}' \
                 (live discovery reports: {}). Re-run discover and adopt an exactly matching \
                 id; stored reports are never trusted",
                request.deployment_id,
                host.alias,
                known
            )
        })?;

    // 4. Duplicate discipline before any write, with stable outcomes: same
    //    host means already adopted; another host means relocation (B07),
    //    which only the explicit relocate path may perform after proving the
    //    deployment really runs there.
    match context
        .registry
        .instance_by_deployment(&inspection.deployment_id)?
    {
        Some(existing) if existing.host_id == host.host_id => bail!(
            "{ADOPT_ALREADY_REGISTERED}: deployment '{}' is already registered on this host as \
             instance '{}'; nothing was changed",
            inspection.deployment_id,
            existing.alias
        ),
        Some(existing) => {
            let bound_host = context
                .registry
                .host_by_id(existing.host_id)?
                .map(|bound| bound.alias)
                .unwrap_or_else(|| existing.host_id.to_string());
            bail!(
                "{ADOPT_RELOCATION_REQUIRED}: deployment '{}' is registered under host '{}' as \
                 instance '{}'. Adoption never rewrites bindings; prove the deployment really \
                 runs there with `nazoauthctl instance relocate --instance {} --to-host {}`, \
                 which verifies the target identity before moving the record",
                inspection.deployment_id,
                bound_host,
                existing.alias,
                existing.alias,
                host.alias
            )
        }
        None => {}
    }

    // 5. Build the evidence FROM THE TARGET'S OWN FACTS: deployment id and
    //    issuer come from the live DeploymentState read over the verified
    //    channel. Operator input has no field left to supply (closes the B04
    //    interim boundary); register_instance re-validates the envelope
    //    against the stored host record under the registry lock.
    let evidence =
        DiscoveryEvidence::new(&host, hello, &inspection.deployment_id, &inspection.issuer)?;
    let record = context.registry.register_instance(
        &evidence,
        request.alias.as_deref(),
        ObservationCache::now(true, summarize_inspection(&inspection)),
    )?;

    Ok(render_adopt_report(&record, &inspection))
}

fn render_adopt_report(record: &InstanceRecord, inspection: &InstanceInspection) -> String {
    let classified = classify_resources(&inspection.resources);
    let mut report = format!(
        "adopted deployment '{}' as instance '{}' on the registry\nissuer: {}\n\
         evidence derived from the target's own DeploymentState over a verified handshake\n\
         observation recorded: {}\n",
        record.deployment_id,
        record.alias,
        record.issuer,
        summarize_inspection(inspection),
    );
    if classified.is_empty() {
        report.push_str(
            "resources: none declared — everything is treated as external; uninstall could \
             delete nothing\n",
        );
    } else {
        let managed = classified
            .iter()
            .filter(|item| item.class == AdoptionClass::ManagedDeletion)
            .count();
        report.push_str(
            "resource classification (from the authoritative target state; nothing upgraded \
             to managed):\n",
        );
        for item in &classified {
            let note = match item.class {
                AdoptionClass::ManagedDeletion => {
                    "managed+deployment: the only class uninstall may replace/delete"
                }
                AdoptionClass::ExternalZeroDelete => "external/shared: zero-delete protection",
            };
            report.push_str(&format!(
                "  - {} [{}] {} — {note}\n",
                item.resource.resource_id, item.resource.kind, item.resource.locator
            ));
        }
        report.push_str(&format!(
            "managed+deletable: {managed}; external/shared zero-delete: {}\n",
            classified.len() - managed
        ));
    }
    report.push_str(
        "signed nothing; no controller key required; the target DeploymentState was not modified\n\
         \nnext steps:\n\
         1. create or confirm the instance administrator and enroll MFA at the instance itself\n\
         2. establish the controller binding after MFA enrollment:\n\
            nazoauthctl bind --instance <alias> --label <name>\n",
    );
    report
}
