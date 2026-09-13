//! Discover and adopt: read-only target sweeps and controlled takeover of
//! existing NazoAuth deployments (goal plan 07 §6, task G05).
//!
//! `discover` enumerates every NazoAuth DeploymentState on one target through
//! the read-only host-level [`crate::target::HostOperation`] kind
//! `state-list`, handshake-gated like every inspection kind. It reports the
//! authoritative facts per deployment (deployment id, issuer, runtime surface,
//! artifact/config revisions, release version, resource facts), cross-references
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

    let mut report = crate::ui::message!(
        "discovered {} NazoAuth deployment(s) on host '{}'\nhelper identity: {}\n",
        "在主机“{1}”发现 {0} 个 NazoAuth 部署\n执行器：{2}\n",
        inspections.len(),
        host.alias,
        summarize_hello(&hello)
    );
    if inspections.is_empty() {
        report.push_str(crate::ui::text(
            "(no NazoAuth deployments found on this target; nothing to adopt)\n",
            "此主机没有可注册的 NazoAuth 部署。\n",
        ));
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
    report.push_str(crate::ui::text(
        "discover is strictly read-only: no registry record, no cache entry, no target change\n",
        "发现操作已完成，尚未注册或修改这些部署。\n",
    ));
    Ok(report)
}

fn release_line(inspection: &InstanceInspection) -> String {
    match &inspection.current_release {
        Some(identity) => identity.version.clone(),
        None => crate::ui::text("not recorded", "未记录").to_owned(),
    }
}

fn render_discovery_block(
    index: usize,
    inspection: &InstanceInspection,
    status: &CandidateStatus,
    host_alias: &str,
) -> String {
    let title = format!("[{index}] {}", inspection.deployment_id);
    let mut block = crate::ui::fields(
        &title,
        &[
            (
                crate::ui::text("Service URL", "服务地址"),
                inspection.issuer.clone(),
            ),
            (crate::ui::text("Version", "版本"), release_line(inspection)),
            (
                crate::ui::text("Runtime", "运行环境"),
                inspection.runtime.kind.to_string(),
            ),
            (
                crate::ui::text("Health", "健康"),
                if inspection.healthy {
                    crate::ui::text("Healthy", "正常")
                } else {
                    crate::ui::text("Unhealthy", "异常")
                }
                .into(),
            ),
        ],
    );
    block.push_str("\n\n");
    block.push_str(&render_resources(inspection));
    block.push('\n');
    match status {
        CandidateStatus::Unregistered => block.push_str(&crate::ui::message!("    status: registration candidate\n    next step: nazoauthctl instance register --host {host_alias} --deployment-id {}\n", "状态：尚未注册\n下一步：nazoauthctl instance register --host {host_alias} --deployment-id {}\n",
            inspection.deployment_id
        )),
        CandidateStatus::RegisteredHere { alias } => block.push_str(&crate::ui::message!("    status: registered on this host as '{alias}'\n", "状态：已在此主机注册为“{alias}”\n"
        )),
        CandidateStatus::RegisteredElsewhere { alias, host_alias: bound } => block.push_str(&crate::ui::message!("    status: RELOCATION CANDIDATE — registered under host '{bound}' as '{alias}'; \
             this record is never rewritten by discovery\n    relocation requires explicit \
             proof through the new host: nazoauthctl instance relocate --instance {alias} --to-host {host_alias}\n", "状态：当前注册在主机“{bound}”，实例名为“{alias}”。本次发现未修改绑定。\n如需迁移绑定：nazoauthctl instance relocate --instance {alias} --to-host {host_alias}\n"
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
    let title = crate::ui::message!(
        "Registered deployment '{}' as instance '{}'",
        "部署“{}”已注册为实例“{}”",
        record.deployment_id,
        record.alias
    );
    let mut report = crate::ui::fields(
        &title,
        &[
            (
                crate::ui::text("Service URL", "服务地址"),
                record.issuer.clone(),
            ),
            (crate::ui::text("Version", "版本"), release_line(inspection)),
        ],
    );
    report.push_str("\n\n");
    report.push_str(&render_resources(inspection));
    report.push_str(&crate::ui::message!(
        "\n\nNext: set up administrator MFA, then run nazoauthctl bind --instance {} --label production\n",
        "\n\n下一步：设置管理员双重验证，然后运行 nazoauthctl bind --instance {} --label production\n", record.alias));
    report
}

fn render_resources(inspection: &InstanceInspection) -> String {
    if inspection.resources.is_empty() {
        return crate::ui::text("resources: none declared — everything is treated as external; uninstall could delete nothing", "未声明资源；所有资源按外部资源保留，卸载时不删除。 ").to_owned();
    }
    let rows = classify_resources(&inspection.resources)
        .iter()
        .map(|item| {
            vec![
                item.resource.kind.to_string(),
                item.resource.locator.clone(),
                match item.class {
                    AdoptionClass::ManagedDeletion => {
                        crate::ui::text("managed+deployment", "由 ctl 管理，卸载时删除")
                    }
                    AdoptionClass::ExternalZeroDelete => crate::ui::text(
                        "external/shared: zero-delete protection",
                        "外部或共享资源，保留",
                    ),
                }
                .into(),
            ]
        })
        .collect::<Vec<_>>();
    crate::ui::table(
        &[
            crate::ui::text("Resource type", "资源类型"),
            crate::ui::text("Location", "位置"),
            crate::ui::text("Ownership", "归属"),
        ],
        &rows,
    )
}
