//! Fleet commands over the user-scoped Registry (goal plan 02, tasks B03–B07).
//!
//! The Registry is inventory only: every command here treats the last cached
//! observation as display data, performs a live verified handshake before any
//! mutation or registration, and never issues a destructive remote operation.
//! `host forget`, `instance forget`, renames, and relocations touch local
//! records exclusively; the target-side authority stays with the host.
//!
//! Target construction goes through an injectable factory so unit tests drive
//! scripted [`ExecutionTarget`] doubles instead of OpenSSH or the network.

pub(crate) mod fleet_read;

use anyhow::{Context, bail};
use uuid::Uuid;

use crate::cli::{HostCommand, InstanceCommand, InstanceSelector};
use crate::discover_adopt::DiscoveryContext;
use crate::registry::{
    HostPrivilege, HostRecord, HostTransport, InstanceRecord, ObservationCache, RegistryStore,
};
use crate::target::{
    ExecutionTarget, HostCompletionBody, HostOperation, HostOutcome, InstanceInspection,
    LocalTarget, REMOTE_HELPER_MISMATCH, RemoteHello, ResourceOwnership, SshTarget,
    verify_remote_hello,
};

// Canonical names live in `crate::error_codes`; re-exported here so the
// historical call sites keep one stable path.
pub(crate) use crate::error_codes::{INSTANCE_AMBIGUOUS, INSTANCE_NOT_REGISTERED};

/// Cached observations older than this are displayed as stale.
const STALE_AFTER_HOURS: i64 = 24;

type TargetFactory = dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>>;

/// Everything the fleet commands need: the user-scoped store and a way to
/// reach hosts. Production wires the real transports; tests substitute
/// scripted doubles.
struct FleetContext {
    store: RegistryStore,
    factory: Box<TargetFactory>,
}

impl FleetContext {
    fn new(store: RegistryStore, factory: Box<TargetFactory>) -> Self {
        Self { store, factory }
    }

    fn production() -> anyhow::Result<Self> {
        Ok(Self::new(
            RegistryStore::open_default()?,
            Box::new(production_target),
        ))
    }

    fn target_for(&self, record: &HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
        (self.factory)(record)
    }
}

/// Production transport selection, shared with the lifecycle use-case waves
/// (G01+): local hosts answer natively, SSH hosts through system OpenSSH.
pub(crate) fn production_target(
    record: &HostRecord,
) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> {
    match record.transport {
        HostTransport::Local => Ok(Box::new(LocalTarget::new()?)),
        HostTransport::Ssh => Ok(Box::new(SshTarget::from_record(record)?)),
    }
}

// ---------------------------------------------------------------- entry points

pub(crate) fn run_host(command: HostCommand) -> anyhow::Result<()> {
    let context = FleetContext::production()?;
    let report = match command {
        HostCommand::Add {
            alias,
            ssh_profile,
            privilege,
        } => host_add(&context, &alias, &ssh_profile, privilege)?,
        HostCommand::List { refresh } => host_list(&context, refresh)?,
        HostCommand::Show { alias } => host_show(&context, &alias)?,
        HostCommand::Check { alias } => host_check(&context, &alias)?,
        HostCommand::Forget { alias, cascade } => host_forget(&context, &alias, cascade)?,
    };
    println!("{report}");
    Ok(())
}

pub(crate) fn run_instance(command: InstanceCommand) -> anyhow::Result<()> {
    let context = FleetContext::production()?;
    let report = match command {
        InstanceCommand::List { refresh } => instance_list(&context, refresh)?,
        InstanceCommand::Show(selector) => instance_show(&context, &selector)?,
        // Controlled takeover (G05): the deployment binding comes from the
        // target's own DeploymentState over a verified handshake.
        InstanceCommand::Register {
            host,
            deployment_id,
            alias,
        } => {
            let discovery = DiscoveryContext {
                registry: context.store.clone(),
                factory: Box::new(move |record| (context.factory)(record)),
            };
            crate::discover_adopt::run_adopt(
                &discovery,
                crate::discover_adopt::AdoptRequest {
                    host: Some(host),
                    deployment_id,
                    alias,
                },
            )?
        }
        InstanceCommand::Rename { source, new_alias } => {
            instance_rename(&context, &source, &new_alias)?
        }
        InstanceCommand::Forget(selector) => instance_forget(&context, &selector)?,
        InstanceCommand::Relocate { selector, to_host } => {
            instance_relocate(&context, &selector, &to_host)?
        }
    };
    println!("{report}");
    Ok(())
}

// ------------------------------------------------------------- live probes

/// One full live contact: verified hello identity plus a nonce-echoed ping.
/// Both transports answer through the identical [`ExecutionTarget`] contract.
pub(crate) fn live_probe(target: &dyn ExecutionTarget) -> anyhow::Result<RemoteHello> {
    let answered =
        target.execute_host_operation(&HostOperation::hello(Uuid::now_v7().to_string()))?;
    let hello = match answered.outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::Hello { hello },
        } => hello,
        HostOutcome::Completed { .. } => {
            bail!("the target answered an unexpected completion instead of a hello identity")
        }
        HostOutcome::Failed { code, detail } => {
            bail!("the target helper answered failure {code}: {detail}")
        }
    };
    verify_remote_hello(&hello).map_err(|reason| {
        anyhow::anyhow!(
            "{REMOTE_HELPER_MISMATCH}: {reason}. Upgrade the target helper first \
             (`nazoauthctl self update --yes` on the host), then retry; no fallback exists."
        )
    })?;

    let nonce = Uuid::now_v7().to_string();
    let echoed = target.execute_host_operation(&HostOperation::ping(
        Uuid::now_v7().to_string(),
        nonce.clone(),
    ))?;
    match echoed.outcome {
        HostOutcome::Completed {
            body: HostCompletionBody::Ping { nonce: returned },
        } if returned == nonce => Ok(hello),
        HostOutcome::Completed {
            body: HostCompletionBody::Ping { .. },
        } => bail!("the ping reply did not echo the probe nonce"),
        HostOutcome::Completed { .. } => {
            bail!("the target answered an unexpected completion instead of a ping reply")
        }
        HostOutcome::Failed { code, detail } => {
            bail!("the target helper answered failure {code}: {detail}")
        }
    }
}

/// Compact single-line identity string stored in the observation cache. Drift
/// reporting compares these summaries verbatim.
pub(crate) fn summarize_hello(hello: &RemoteHello) -> String {
    let commit = if hello.commit.is_empty() {
        "-"
    } else {
        hello.commit.as_str()
    };
    let runtimes = if hello.supported_runtimes.is_empty() {
        "-".to_owned()
    } else {
        hello.supported_runtimes.join(",")
    };
    format!(
        "helper={} commit={commit} os={} arch={} runtimes={runtimes}",
        hello.version, hello.os, hello.arch
    )
}

/// Compact single-line summary of one live DeploymentState inspection
/// (task F01). This is what `--refresh` writes into the instance observation
/// cache — real inspection data, never a placeholder sentence. The cache is
/// still display-only: it never authorizes or overwrites target state.
pub(crate) fn summarize_inspection(inspection: &InstanceInspection) -> String {
    let artifacts = match (&inspection.artifact.current, &inspection.artifact.previous) {
        (None, None) => "-".to_owned(),
        (current, previous) => {
            let current = current.clone().unwrap_or_else(|| "-".to_owned());
            let previous = previous.clone().unwrap_or_else(|| "-".to_owned());
            format!("{current}<-{previous}")
        }
    };
    let managed = inspection
        .resources
        .iter()
        .filter(|resource| resource.ownership == ResourceOwnership::Managed)
        .count();
    let health = if inspection.healthy { "ok" } else { "down" };
    // Backup/DR maturity (H05): informational display with its observation
    // timestamp; never a gate for any lifecycle use case.
    let backup = match inspection.backup_maturity.observed_at() {
        Some(observed_at) => format!(
            "{}@{}",
            inspection.backup_maturity.token(),
            observed_at.to_rfc3339()
        ),
        None => inspection.backup_maturity.token().to_owned(),
    };
    format!(
        "rev={} runtime={}/{} config={} artifacts={} resources={} managed={} health={health} backup={backup}",
        inspection.revision,
        inspection.runtime.kind,
        inspection.runtime.object,
        inspection.config_reference,
        artifacts,
        inspection.resources.len(),
        managed,
    )
}

/// Bound a failure diagnostic for storage in the free-text cache summary.
fn bounded_error_text(error: &anyhow::Error) -> String {
    format!("{error:#}")
        .chars()
        .take(200)
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect()
}

fn human_age(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        format!("{minutes}m")
    } else if seconds < 86_400 {
        let hours = seconds / 3_600;
        format!("{hours}h")
    } else {
        let days = seconds / 86_400;
        format!("{days}d")
    }
}

/// Display classifier for a cached observation (task B06): `never`, `fresh`,
/// `stale` (>24h), or `error` (last contact failed). Never consulted for
/// authorization — mutations always go live first.
fn observation_marker(observation: Option<&ObservationCache>) -> String {
    let Some(observation) = observation else {
        return "never observed".to_owned();
    };
    let age_seconds = (chrono::Utc::now() - observation.observed_at).num_seconds();
    let class = if !observation.reachable {
        "error"
    } else if age_seconds > STALE_AFTER_HOURS * 3_600 {
        "stale"
    } else {
        "fresh"
    };
    format!("{class} ({} ago)", human_age(age_seconds))
}

fn observation_summary_line(observation: Option<&ObservationCache>) -> String {
    match observation {
        None => String::new(),
        Some(observation) => format!("      last contact: {}", observation.summary),
    }
}

/// Shared host selector rules (goal plan 07 G01 step 1, reused by discover /
/// adopt in G05 and by the I-wave CLI): an explicit alias must match exactly;
/// without one the built-in local host is ensured and a single-host registry
/// selects itself while a multi-host registry demands disambiguation. This is
/// the single authority for that rule; clean-install consumes it too.
pub(crate) fn resolve_host_selector(
    registry: &RegistryStore,
    explicit: Option<&str>,
) -> anyhow::Result<HostRecord> {
    if let Some(alias) = explicit {
        return registry.host_by_alias(alias)?.with_context(|| {
            format!(
                "{}: unknown host alias '{alias}'; register it first with \
                     `nazoauthctl host add {alias} --ssh <profile>`",
                crate::error_codes::HOST_NOT_REGISTERED
            )
        });
    }
    registry.ensure_local_host()?;
    let hosts = registry.list_hosts()?;
    match hosts.as_slice() {
        [only] => Ok(only.clone()),
        [] => bail!("no hosts are available for installation"),
        many => {
            let aliases = many
                .iter()
                .map(|host| host.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{} hosts are registered ({aliases}); choose one explicitly with --host",
                many.len()
            )
        }
    }
}

// ------------------------------------------------------------- host commands

fn host_add(
    context: &FleetContext,
    alias: &str,
    ssh_profile: &str,
    privilege: HostPrivilege,
) -> anyhow::Result<String> {
    // Cheap guard first so an obvious duplicate never spends an SSH round trip.
    if context.store.host_by_alias(alias)?.is_some() {
        bail!("duplicate host alias '{alias}'");
    }
    let candidate = HostRecord::new_ssh(alias, ssh_profile, privilege)?;
    // Task B03 preflight: reach the helper and verify its identity BEFORE
    // anything is persisted. A host this control machine cannot talk to is
    // never registered half-done.
    let target = context.target_for(&candidate)?;
    let hello =
        live_probe(target.as_ref()).context("host add preflight failed; nothing was registered")?;
    let mut record = candidate;
    record.set_last_observation(ObservationCache::now(true, summarize_hello(&hello)));
    let stored = context.store.add_host(record)?;

    let profile = stored.ssh_profile.as_deref().unwrap_or("-");
    let mut report = format!(
        "registered host '{}' ({})\ntransport: ssh (profile '{profile}'), privilege: {:?}\nhelper identity: {}\nobservation recorded\n",
        stored.alias,
        stored.host_id,
        stored.privilege,
        summarize_hello(&hello)
    );
    if stored.privilege == HostPrivilege::Sudo {
        report.push_str(&format!(
            "note: formal operations use `sudo -n`; establish credentials once with \
             `ssh -t {profile} sudo -v` or configure NOPASSWD\n"
        ));
    }
    Ok(report)
}

fn host_list(context: &FleetContext, refresh: bool) -> anyhow::Result<String> {
    if refresh {
        for host in context.store.list_hosts()? {
            let target = context.target_for(&host)?;
            match live_probe(target.as_ref()) {
                Ok(hello) => context.store.set_host_observation(
                    host.host_id,
                    ObservationCache::now(true, summarize_hello(&hello)),
                )?,
                Err(error) => context.store.set_host_observation(
                    host.host_id,
                    ObservationCache::now(false, bounded_error_text(&error)),
                )?,
            }
        }
    }
    let hosts = context.store.list_hosts()?;
    let instances = context.store.list_instances()?;
    let mut report =
        String::from("ALIAS          TRANSPORT      PRIVILEGE  INSTANCES  OBSERVATION\n");
    for host in &hosts {
        let bound = instances
            .iter()
            .filter(|instance| instance.host_id == host.host_id)
            .count();
        let transport = match host.ssh_profile.as_deref() {
            Some(profile) => format!("ssh:{profile}"),
            None => "local".to_owned(),
        };
        let privilege = if host.privilege == HostPrivilege::Sudo {
            "sudo"
        } else {
            "direct"
        };
        let observation = observation_marker(host.last_observation.as_ref());
        let alias = host.alias.as_str();
        report.push_str(&format!(
            "{alias:<14} {transport:<14} {privilege:<10} {bound:<10} {observation}\n"
        ));
        let summary = observation_summary_line(host.last_observation.as_ref());
        if !summary.is_empty() {
            report.push_str(&summary);
            report.push('\n');
        }
    }
    Ok(report)
}

fn host_show(context: &FleetContext, alias: &str) -> anyhow::Result<String> {
    let host = context
        .store
        .host_by_alias(alias)?
        .with_context(|| format!("unknown host alias '{alias}'"))?;
    let all_instances = context.store.list_instances()?;
    let instances: Vec<&InstanceRecord> = all_instances
        .iter()
        .filter(|instance| instance.host_id == host.host_id)
        .collect();
    let mut report = format!(
        "host '{}' ({})\ntransport: {}\nprivilege: {:?}\nobservation: {}\n",
        host.alias,
        host.host_id,
        match host.transport {
            HostTransport::Local => "local".to_owned(),
            HostTransport::Ssh => format!("ssh ({})", host.ssh_profile.as_deref().unwrap_or("-")),
        },
        host.privilege,
        observation_marker(host.last_observation.as_ref()),
    );
    let summary = observation_summary_line(host.last_observation.as_ref());
    if !summary.is_empty() {
        report.push_str(&summary);
        report.push('\n');
    }
    if instances.is_empty() {
        report.push_str("instances: none\n");
    } else {
        report.push_str("instances:\n");
        for instance in instances {
            report.push_str(&format!(
                "  {} (deployment {}, issuer {})\n",
                instance.alias, instance.deployment_id, instance.issuer
            ));
        }
    }
    Ok(report)
}

fn host_check(context: &FleetContext, alias: &str) -> anyhow::Result<String> {
    let host = context
        .store
        .host_by_alias(alias)?
        .with_context(|| format!("unknown host alias '{alias}'"))?;
    let target = context.target_for(&host)?;
    let probe = live_probe(target.as_ref());
    match probe {
        Ok(hello) => {
            let summary = summarize_hello(&hello);
            let drifted = host
                .last_observation
                .as_ref()
                .filter(|cached| cached.reachable)
                .is_some_and(|cached| cached.summary != summary);
            context
                .store
                .set_host_observation(host.host_id, ObservationCache::now(true, summary.clone()))?;
            let mut report = format!(
                "checked host '{alias}' against the live target\nhelper identity: {summary}\nping echo verified\nobservation updated\n"
            );
            if drifted {
                report.push_str("drift detected against the cached observation:\n");
                if let Some(cached) = host.last_observation.as_ref() {
                    report.push_str(&format!(
                        "  cached: {}\n  live:   {summary}\n",
                        cached.summary
                    ));
                }
            }
            Ok(report)
        }
        Err(error) => {
            context.store.set_host_observation(
                host.host_id,
                ObservationCache::now(false, bounded_error_text(&error)),
            )?;
            Err(error).with_context(|| {
                format!("host '{alias}' is unreachable; the failure was recorded in its observation cache")
            })
        }
    }
}

fn host_forget(context: &FleetContext, alias: &str, cascade: bool) -> anyhow::Result<String> {
    // Registry-only by construction: no execution target is ever built here.
    let (_host, removed) = context.store.forget_host(alias, cascade)?;
    let mut report = format!("forgot host '{alias}' (registry-only operation)\n");
    if removed.is_empty() {
        report.push_str("no local instance records referenced this host\n");
    } else {
        report.push_str("removed local instance records:\n");
        for record in &removed {
            report.push_str(&format!(
                "  {} (deployment {})\n",
                record.alias, record.deployment_id
            ));
        }
    }
    report
        .push_str("no remote operation was attempted; remote deployments keep running untouched\n");
    Ok(report)
}

// ---------------------------------------------------------- instance commands

/// Task B05 selector rules: exact alias or exact deployment id only; a single
/// registered instance may omit the selector entirely; a multi-instance
/// Registry demands an explicit selector and lists the candidates.
pub(crate) fn resolve_instance(
    store: &RegistryStore,
    explicit: Option<&str>,
    action: &str,
) -> anyhow::Result<InstanceRecord> {
    let instances = store.list_instances()?;
    if let Some(selector) = explicit {
        return instances
            .iter()
            .find(|record| record.alias == selector || record.deployment_id == selector)
            .cloned()
            .with_context(|| {
                format!(
                    "{INSTANCE_NOT_REGISTERED}: no registered instance matches '{selector}' \
                     exactly. Selectors accept an exact alias or an exact deployment id only — \
                     substring, fuzzy, and discovery-order selection are never attempted"
                )
            });
    }
    match instances.as_slice() {
        [] => bail!("no instances are registered yet"),
        [single] => Ok(single.clone()),
        many => {
            let candidates = many
                .iter()
                .map(|record| format!("{} (deployment {})", record.alias, record.deployment_id))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{INSTANCE_AMBIGUOUS}: {action} requires an explicit --instance selector \
                 because {} instances are registered: {candidates}",
                many.len()
            )
        }
    }
}

fn merged_selector(selector: &InstanceSelector, action: &str) -> anyhow::Result<Option<String>> {
    selector
        .explicit()
        .with_context(|| format!("{action}: conflicting selectors"))
}

fn instance_list(context: &FleetContext, refresh: bool) -> anyhow::Result<String> {
    if refresh {
        // Go live once per distinct host, tolerating partial failure (fleet
        // batch reads may degrade; they never hide successful results).
        let instances = context.store.list_instances()?;
        let mut refreshed_hosts: Vec<uuid::Uuid> = Vec::new();
        for instance in &instances {
            if refreshed_hosts.contains(&instance.host_id) {
                continue;
            }
            refreshed_hosts.push(instance.host_id);
            let Some(host) = context.store.host_by_id(instance.host_id)? else {
                continue;
            };
            let target = context.target_for(&host)?;
            match live_probe(target.as_ref()) {
                Ok(hello) => {
                    let summary = summarize_hello(&hello);
                    context.store.set_host_observation(
                        host.host_id,
                        ObservationCache::now(true, summary.clone()),
                    )?;
                    for bound in instances
                        .iter()
                        .filter(|other| other.host_id == host.host_id)
                    {
                        // Real DeploymentState inspection per instance (F01):
                        // the cache now holds live facts, not a placeholder.
                        let observation = match target.inspect_instance(&bound.deployment_id) {
                            Ok(inspection) if inspection.deployment_id == bound.deployment_id => {
                                ObservationCache::now(true, summarize_inspection(&inspection))
                            }
                            Ok(inspection) => ObservationCache::now(
                                false,
                                bounded_error_text(&anyhow::anyhow!(
                                    "target reports deployment '{}' where '{}' is registered",
                                    inspection.deployment_id,
                                    bound.deployment_id
                                )),
                            ),
                            Err(error) => ObservationCache::now(false, bounded_error_text(&error)),
                        };
                        context
                            .store
                            .set_instance_observation(&bound.deployment_id, observation)?;
                    }
                }
                Err(error) => {
                    let text = bounded_error_text(&error);
                    context.store.set_host_observation(
                        host.host_id,
                        ObservationCache::now(false, text.clone()),
                    )?;
                    for bound in instances
                        .iter()
                        .filter(|other| other.host_id == host.host_id)
                    {
                        context.store.set_instance_observation(
                            &bound.deployment_id,
                            ObservationCache::now(false, text.clone()),
                        )?;
                    }
                }
            }
        }
    }
    let instances = context.store.list_instances()?;
    let mut report = String::from(
        "ALIAS       DEPLOYMENT-ID   HOST          ISSUER                       OBSERVATION\n",
    );
    for instance in &instances {
        let host_label = match context.store.host_by_id(instance.host_id)? {
            Some(host) => host.alias,
            None => "<unknown>".to_owned(),
        };
        let marker = observation_marker(instance.last_observation.as_ref());
        let alias = instance.alias.as_str();
        let deployment = instance.deployment_id.as_str();
        let issuer = instance.issuer.as_str();
        report.push_str(&format!(
            "{alias:<11} {deployment:<15} {host_label:<13} {issuer:<28} {marker}\n"
        ));
        let summary = observation_summary_line(instance.last_observation.as_ref());
        if !summary.is_empty() {
            report.push_str(&summary);
            report.push('\n');
        }
    }
    if instances.is_empty() {
        report.push_str("(no instances registered)\n");
    }
    Ok(report)
}

fn instance_show(context: &FleetContext, selector: &InstanceSelector) -> anyhow::Result<String> {
    let explicit = merged_selector(selector, "instance show")?;
    let record = resolve_instance(&context.store, explicit.as_deref(), "instance show")?;
    let host = context.store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "schema": 1,
        "alias": record.alias,
        "deployment_id": record.deployment_id,
        "host": {
            "id": record.host_id,
            "alias": host.alias,
            "transport": host.transport,
        },
        "issuer": record.issuer,
        "controller_id": record.controller_id,
        "controller_key_ref": record.controller_key_ref,
        "target_state_ref": record.target_state_ref,
        "observation": record.last_observation.map(|observation| serde_json::json!({
            "observed_at": observation.observed_at,
            "reachable": observation.reachable,
            "marker": observation_marker(Some(&observation)),
            "summary": observation.summary,
        })),
    }))?)
}

fn instance_rename(
    context: &FleetContext,
    source: &InstanceSelector,
    new_alias: &str,
) -> anyhow::Result<String> {
    let explicit = merged_selector(source, "instance rename")?;
    let record = resolve_instance(&context.store, explicit.as_deref(), "instance rename")?;
    let renamed = context.store.rename_instance(&record.alias, new_alias)?;
    Ok(format!(
        "renamed instance '{}' -> '{}' (deployment {}; key/issuer/host bindings unchanged)\n",
        record.alias, renamed.alias, renamed.deployment_id
    ))
}

fn instance_forget(context: &FleetContext, selector: &InstanceSelector) -> anyhow::Result<String> {
    let explicit = merged_selector(selector, "instance forget")?;
    let record = resolve_instance(&context.store, explicit.as_deref(), "instance forget")?;
    let mut report = String::new();
    if record.controller_id.is_some() || record.controller_key_ref.is_some() {
        report.push_str(&format!(
            "warning: instance '{}' carries controller binding references; forgetting removes \
             only the local Registry record — the Controller Slot at the server is NOT revoked\n",
            record.alias
        ));
    }
    // Registry-only: no target is ever contacted on this path.
    context
        .store
        .forget_instance_by_deployment(&record.deployment_id)?;
    report.push_str(&format!(
        "forgot instance '{}' (deployment {}) — registry-only operation\nthe remote instance keeps running and its controller slots are unchanged\n",
        record.alias, record.deployment_id
    ));
    Ok(report)
}

fn instance_relocate(
    context: &FleetContext,
    selector: &InstanceSelector,
    to_host: &str,
) -> anyhow::Result<String> {
    let explicit = merged_selector(selector, "instance relocate")?;
    let record = resolve_instance(&context.store, explicit.as_deref(), "instance relocate")?;
    let current = context.store.host_by_id(record.host_id)?.with_context(|| {
        format!(
            "instance '{}' references missing host {}",
            record.alias, record.host_id
        )
    })?;
    if current.alias == to_host {
        bail!(
            "instance '{}' is already bound to host '{}'",
            record.alias,
            current.alias
        );
    }
    let destination = context
        .store
        .host_by_alias(to_host)?
        .with_context(|| format!("unknown target host alias '{to_host}'"))?;

    // Task B07 + F01: relocation updates the binding ONLY after live
    // verification through the NEW host — verified helper identity first,
    // then a real DeploymentState inspection proving the same deployment
    // really runs there.
    let target = context.target_for(&destination)?;
    let hello = live_probe(target.as_ref()).with_context(|| {
        format!(
            "relocation target '{to_host}' failed its live verification; the binding of '{}' was not changed",
            record.alias
        )
    })?;
    let inspection = target.inspect_instance(&record.deployment_id).with_context(|| {
        format!(
            "the deployment '{}' could not be verified on '{to_host}'; the binding was not changed",
            record.deployment_id
        )
    })?;
    if inspection.deployment_id != record.deployment_id {
        bail!(
            "the deployment inspected through '{to_host}' reports identity '{}' instead of '{}'; \
             the binding was not changed",
            inspection.deployment_id,
            record.deployment_id
        );
    }

    let moved = context
        .store
        .relocate_instance(&record.deployment_id, destination.host_id)?;
    context.store.set_instance_observation(
        &moved.deployment_id,
        ObservationCache::now(
            true,
            format!(
                "relocated onto '{}'; {}; {}",
                destination.alias,
                summarize_hello(&hello),
                summarize_inspection(&inspection)
            ),
        ),
    )?;
    Ok(format!(
        "relocated instance '{}' (deployment {}) from host '{}' to host '{}'\n",
        moved.alias, moved.deployment_id, current.alias, destination.alias
    ))
}

#[cfg(test)]
use crate::filesystem;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{
        ControlOperationReceipt, ControlOperationRequest, HealthSnapshot, HostOverview, HostResult,
    };
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    // ---------- scripted target double ----------

    #[derive(Clone)]
    enum Scenario {
        /// Verified helper answering hello and ping correctly.
        Online,
        /// Verified helper whose target reports a different deployment id
        /// than the one asked about (relocation must refuse).
        ForeignDeployment,
        /// Answers hello with a drifted version (handshake must reject).
        HelperDrift,
        /// Transport-level failure with this diagnostic.
        Offline(&'static str),
    }

    struct FakeTarget {
        scenario: Scenario,
        calls: Arc<AtomicUsize>,
    }

    impl FakeTarget {
        fn hello(&self) -> RemoteHello {
            let mut hello = crate::target::wire::local_hello(vec!["podman".to_owned()]);
            if matches!(self.scenario, Scenario::HelperDrift) {
                hello.version = "0.0.9-drift".to_owned();
            }
            hello
        }

        fn inspection(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
            match self.scenario {
                Scenario::Offline(text) => bail!("{text}"),
                Scenario::ForeignDeployment => Ok(InstanceInspection {
                    current_build_identity: None,
                    deployment_id: format!("elsewhere-{deployment_id}"),
                    issuer: "https://auth.example.com".to_owned(),
                    observed_at: chrono::Utc::now(),
                    revision: 1,
                    runtime: crate::target::RuntimeSurface::new("podman", "other")?,
                    artifact: Default::default(),
                    config_reference: "/cfg".to_owned(),
                    config_schema: "v1".to_owned(),
                    resources: vec![],
                    healthy: true,
                    health_summary: "ok".to_owned(),
                    backup_maturity: crate::target::BackupMaturity::Unknown,
                    active_host_operation: None,
                    bootstrap_material: None,
                }),
                _ => Ok(InstanceInspection {
                    current_build_identity: None,
                    deployment_id: deployment_id.to_owned(),
                    issuer: "https://auth.example.com".to_owned(),
                    observed_at: chrono::Utc::now(),
                    revision: 7,
                    runtime: crate::target::RuntimeSurface::new("podman", "nazoauth-main")?,
                    artifact: Default::default(),
                    config_reference: "/etc/nazauth/config.toml".to_owned(),
                    config_schema: "nazauth-config-v1".to_owned(),
                    resources: vec![
                        crate::target::Resource::new(
                            "app-container",
                            "container",
                            "nazoauth-main",
                            crate::target::ResourceOwnership::Managed,
                            crate::target::ResourceScope::Deployment,
                        )?,
                        crate::target::Resource::new(
                            "shared-db",
                            "postgres",
                            "pg-main:5432",
                            crate::target::ResourceOwnership::External,
                            crate::target::ResourceScope::Shared,
                        )?,
                    ],
                    healthy: true,
                    health_summary: "runtime healthy".to_owned(),
                    backup_maturity: crate::target::BackupMaturity::Unknown,
                    active_host_operation: None,
                    bootstrap_material: None,
                }),
            }
        }
    }

    impl ExecutionTarget for FakeTarget {
        fn inspect_host(&self) -> anyhow::Result<HostOverview> {
            bail!("unused in fleet tests")
        }

        fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.inspection(deployment_id)
        }

        fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Scenario::Offline(text) = self.scenario {
                bail!("{text}");
            }
            match &operation.operation {
                crate::target::HostOperationBody::Hello {} => Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::Hello {
                        hello: self.hello(),
                    },
                )),
                crate::target::HostOperationBody::Ping { nonce } => Ok(HostResult::completed(
                    &operation.operation_id,
                    HostCompletionBody::Ping {
                        nonce: nonce.clone(),
                    },
                )),
                _ => bail!("fleet doubles only answer hello and ping"),
            }
        }

        fn execute_control_operation(
            &self,
            _request: &ControlOperationRequest,
        ) -> anyhow::Result<ControlOperationReceipt> {
            bail!("unused in fleet tests")
        }

        fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
            let inspection = self.inspection(deployment_id)?;
            Ok(HealthSnapshot {
                deployment_id: inspection.deployment_id,
                healthy: inspection.healthy,
                summary: inspection.health_summary,
                observed_at: inspection.observed_at,
            })
        }
    }

    // ---------- fixtures ----------

    type SharedCalls = Arc<AtomicUsize>;

    struct Fixture {
        _temp: filesystem::PrivateTempDir,
        context: FleetContext,
        calls: SharedCalls,
    }

    impl Fixture {
        fn with_scenario(scenario: Scenario) -> anyhow::Result<Self> {
            Self::with_host_scenarios(Box::new(move |_record| scenario.clone()))
        }

        /// Scenario chosen per host record (mixed-fleet tests).
        fn with_host_scenarios(pick: Box<dyn Fn(&HostRecord) -> Scenario>) -> anyhow::Result<Self> {
            let temp = filesystem::PrivateTempDir::new("nazauthctl-fleet-test")?;
            let store = RegistryStore::open(temp.path().join("registry"))?;
            let calls: SharedCalls = Arc::new(AtomicUsize::new(0));
            let calls_for_factory = calls.clone();
            let context = FleetContext::new(
                store,
                Box::new(move |record| {
                    Ok(Box::new(FakeTarget {
                        scenario: pick(record),
                        calls: calls_for_factory.clone(),
                    }))
                }),
            );
            Ok(Fixture {
                _temp: temp,
                context,
                calls,
            })
        }

        fn store(&self) -> &RegistryStore {
            &self.context.store
        }

        fn seed_ssh_host(&self, alias: &str, profile: &str) -> anyhow::Result<HostRecord> {
            let host = HostRecord::new_ssh(alias, profile, HostPrivilege::Direct)?;
            self.store().add_host(host)
        }

        fn seed_instance(
            &self,
            host_id: uuid::Uuid,
            deployment: &str,
            alias: &str,
        ) -> anyhow::Result<InstanceRecord> {
            let record = InstanceRecord::new(
                deployment,
                alias,
                host_id,
                "https://auth.example.com",
                "target-state/x",
            )?;
            self.store().add_instance(record)
        }
    }

    // ---------- B03 host commands ----------

    #[test]
    fn host_add_preflights_then_persists_with_a_fresh_observation() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let report = host_add(&fixture.context, "server-a", "prod-a", HostPrivilege::Sudo)?;
        assert!(report.contains("registered host 'server-a'"), "{report}");
        assert!(report.contains("sudo -v"), "{report}");
        let host = fixture.store().host_by_alias("server-a")?.expect("stored");
        assert_eq!(host.ssh_profile.as_deref(), Some("prod-a"));
        let observation = host.last_observation.expect("preflight observation");
        assert!(observation.reachable);
        assert!(
            observation.summary.starts_with("helper="),
            "{observation:?}"
        );
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            2,
            "one hello plus one ping"
        );
        Ok(())
    }

    #[test]
    fn host_add_preflight_failure_registers_nothing() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Offline("ssh to 'x' exited 255"))?;
        let error = host_add(
            &fixture.context,
            "server-a",
            "prod-a",
            HostPrivilege::Direct,
        )
        .expect_err("offline preflight");
        assert!(error.to_string().contains("nothing was registered"));
        assert!(fixture.store().host_by_alias("server-a")?.is_none());

        let drift = Fixture::with_scenario(Scenario::HelperDrift)?;
        let error = host_add(&drift.context, "server-b", "prod-b", HostPrivilege::Direct)
            .expect_err("mismatched helper");
        let rendered = format!("{error:#}");
        assert!(rendered.contains(REMOTE_HELPER_MISMATCH), "{rendered}");
        assert!(drift.store().host_by_alias("server-b")?.is_none());
        Ok(())
    }

    #[test]
    fn host_add_rejects_duplicate_aliases_before_any_probe() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        fixture.seed_ssh_host("server-a", "prod-a")?;
        let error = host_add(
            &fixture.context,
            "server-a",
            "prod-b",
            HostPrivilege::Direct,
        )
        .expect_err("duplicate");
        assert!(
            error.to_string().contains("duplicate host alias"),
            "{error}"
        );
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            0,
            "duplicate never reaches the wire"
        );
        Ok(())
    }

    #[test]
    fn host_list_reads_cache_only_until_refresh() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        fixture.seed_ssh_host("server-a", "prod-a")?;
        let report = host_list(&fixture.context, false)?;
        assert!(report.contains("never observed"), "{report}");
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            0,
            "default list never goes live"
        );

        let report = host_list(&fixture.context, true)?;
        assert!(report.contains("fresh ("), "{report}");
        assert!(
            fixture.calls.load(Ordering::Relaxed) > 0,
            "refresh went live"
        );
        Ok(())
    }

    #[test]
    fn host_list_refresh_keeps_offline_rows_flagged_as_errors() -> anyhow::Result<()> {
        let fixture = Fixture::with_host_scenarios(Box::new(|record| {
            if record.alias == "server-online" {
                Scenario::Online
            } else {
                Scenario::Offline("ssh to 'x' timed out")
            }
        }))?;
        fixture.seed_ssh_host("server-online", "prod-ok")?;
        fixture.seed_ssh_host("server-dead", "prod-dead")?;

        let report = host_list(&fixture.context, true)?;
        assert!(report.contains("server-dead"), "row must survive: {report}");
        assert!(report.contains("error ("), "{report}");
        assert!(report.contains("timed out"), "{report}");

        let dead = fixture.store().host_by_alias("server-dead")?.unwrap();
        let observation = dead.last_observation.expect("failure recorded");
        assert!(!observation.reachable, "{observation:?}");
        Ok(())
    }

    #[test]
    fn host_check_reports_drift_between_cache_and_live_helper() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.store().set_host_observation(
            host.host_id,
            ObservationCache::now(
                true,
                "helper=0.0.1-old commit=- os=linux arch=x86_64 runtimes=docker",
            ),
        )?;
        let report = host_check(&fixture.context, "server-a")?;
        assert!(report.contains("drift detected"), "{report}");
        assert!(report.contains("helper=0.0.1-old"), "{report}");
        Ok(())
    }

    #[test]
    fn host_check_records_failures_without_losing_the_host() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Offline("connection refused"))?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        let error = host_check(&fixture.context, "server-a").expect_err("offline");
        assert!(error.to_string().contains("unreachable"), "{error:#}");
        let stored = fixture.store().host_by_alias("server-a")?.unwrap();
        let observation = stored.last_observation.expect("kept last observation");
        assert!(!observation.reachable);
        assert!(observation.summary.contains("connection refused"));
        assert_eq!(stored.host_id, host.host_id);

        assert!(host_check(&fixture.context, "missing").is_err());
        Ok(())
    }

    #[test]
    fn host_check_on_the_local_transport_skips_the_network() -> anyhow::Result<()> {
        let temp = filesystem::PrivateTempDir::new("nazauthctl-fleet-local-test")?;
        let store = RegistryStore::open(temp.path().join("registry"))?;
        let local = store.ensure_local_host()?;
        let saw_ssh: Rc<RefCell<bool>> = Rc::new(RefCell::new(false));
        let saw = saw_ssh.clone();
        let context = FleetContext::new(
            store,
            Box::new(move |record| {
                assert_eq!(
                    record.transport,
                    HostTransport::Local,
                    "only the local host exists here"
                );
                *saw.borrow_mut() = true;
                Ok(Box::new(LocalTarget::new()?))
            }),
        );
        let report = host_check(&context, "local")?;
        assert!(report.contains("ping echo verified"), "{report}");
        assert!(*saw_ssh.borrow());
        let updated = context.store.host_by_id(local.host_id)?.unwrap();
        assert!(updated.last_observation.unwrap().reachable);
        Ok(())
    }

    #[test]
    fn host_forget_never_touches_a_target_even_with_cascade() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_instance(host.host_id, "deploy-alpha", "production")?;

        let error = host_forget(&fixture.context, "server-a", false).expect_err("blocked");
        let rendered = error.to_string();
        assert!(rendered.contains("--cascade"), "{rendered}");
        assert!(rendered.contains("never"), "{rendered}");

        let report = host_forget(&fixture.context, "server-a", true)?;
        assert!(
            report.contains("removed local instance records"),
            "{report}"
        );
        assert!(report.contains("no remote operation"), "{report}");
        assert!(fixture.store().host_by_alias("server-a")?.is_none());
        assert!(fixture.store().list_instances()?.is_empty());
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            0,
            "forget is registry-only"
        );
        Ok(())
    }

    // ---------- B04 instance commands ----------

    #[test]
    fn instance_forget_warns_on_controller_bindings_but_never_revokes() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        let mut bound = InstanceRecord::new(
            "deploy-bound",
            "bound",
            host.host_id,
            "https://auth.example.com",
            "target-state/x",
        )?;
        bound.controller_key_ref = Some("keys/deploy-bound/controller".to_owned());
        fixture.store().add_instance(bound)?;
        fixture.seed_instance(host.host_id, "deploy-plain", "plain")?;

        let report = instance_forget(
            &fixture.context,
            &InstanceSelector {
                positional: Some("bound".to_owned()),
                named: None,
            },
        )?;
        assert!(report.contains("warning:"), "{report}");
        assert!(report.contains("NOT revoked"), "{report}");
        assert!(
            fixture
                .store()
                .instance_by_deployment("deploy-bound")?
                .is_none()
        );

        let report = instance_forget(
            &fixture.context,
            &InstanceSelector {
                positional: None,
                named: Some("deploy-plain".to_owned()),
            },
        )?;
        assert!(!report.contains("warning:"), "{report}");
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            0,
            "forget never contacts targets"
        );
        Ok(())
    }

    // ---------- B05 selectors ----------

    #[test]
    fn a_single_instance_allows_omitting_the_selector_everywhere() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_instance(host.host_id, "deploy-alpha", "production")?;

        let empty = InstanceSelector::default();
        let shown = instance_show(&fixture.context, &empty)?;
        assert!(shown.contains("deploy-alpha"), "{shown}");
        let report = instance_rename(&fixture.context, &empty, "renamed")?;
        assert!(report.contains("'production' -> 'renamed'"), "{report}");
        Ok(())
    }

    #[test]
    fn multiple_instances_demand_explicit_selectors_and_list_candidates() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_instance(host.host_id, "deploy-alpha", "alpha")?;
        fixture.seed_instance(host.host_id, "deploy-beta", "beta")?;

        let error = instance_forget(&fixture.context, &InstanceSelector::default())
            .expect_err("ambiguous mutation");
        let rendered = error.to_string();
        assert!(rendered.contains(INSTANCE_AMBIGUOUS), "{rendered}");
        assert!(rendered.contains("alpha"), "{rendered}");
        assert!(rendered.contains("beta"), "{rendered}");

        let shown = instance_show(&fixture.context, &InstanceSelector::default());
        assert!(shown.is_err(), "ambiguous reads fail the same way");
        Ok(())
    }

    #[test]
    fn selectors_accept_only_exact_aliases_and_deployment_ids() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_instance(host.host_id, "deploy-alpha", "production")?;

        for selector in ["production", "deploy-alpha"] {
            let record = resolve_instance(fixture.store(), Some(selector), "test")?;
            assert_eq!(record.deployment_id, "deploy-alpha");
        }
        for selector in ["produc", "deploy-alph", "*"] {
            let error = resolve_instance(fixture.store(), Some(selector), "test")
                .expect_err("fuzzy selection");
            assert!(
                error.to_string().contains(INSTANCE_NOT_REGISTERED),
                "{selector}: {error}"
            );
        }
        Ok(())
    }

    // ---------- B06 observation cache ----------

    #[test]
    fn instance_lists_render_age_markers_from_cache() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let host = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_instance(host.host_id, "deploy-alpha", "production")?;
        let report = instance_list(&fixture.context, false)?;
        assert!(report.contains("never observed"), "{report}");

        fixture.store().set_instance_observation(
            "deploy-alpha",
            ObservationCache::now(true, "helper verified"),
        )?;
        let report = instance_list(&fixture.context, false)?;
        assert!(report.contains("fresh ("), "{report}");
        assert!(report.contains("helper verified"), "{report}");
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            0,
            "cache-only list stays offline"
        );
        Ok(())
    }

    // ---------- B07 relocation constraints ----------

    #[test]
    fn relocate_requires_matching_live_inspection_on_the_new_host() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::Online)?;
        let original = fixture.seed_ssh_host("server-a", "prod-a")?;
        let destination = fixture.seed_ssh_host("server-b", "prod-b")?;
        let mut record = InstanceRecord::new(
            "deploy-alpha",
            "production",
            original.host_id,
            "https://auth.example.com",
            "target-state/x",
        )?;
        record.last_observation = Some(ObservationCache::now(true, "old host view"));
        fixture.store().add_instance(record)?;

        // Cheap guards fire before any live contact.
        let calls_after_guards = fixture.calls.load(Ordering::Relaxed);
        let error = instance_relocate(
            &fixture.context,
            &InstanceSelector {
                positional: Some("production".to_owned()),
                named: None,
            },
            "server-a",
        )
        .expect_err("same host");
        assert!(error.to_string().contains("already bound"), "{error}");
        let error = instance_relocate(
            &fixture.context,
            &InstanceSelector {
                positional: Some("production".to_owned()),
                named: None,
            },
            "ghost",
        )
        .expect_err("unknown target");
        assert!(error.to_string().contains("unknown target host"), "{error}");
        assert_eq!(
            fixture.calls.load(Ordering::Relaxed),
            calls_after_guards,
            "guards precede the network"
        );

        // The live inspection through the new host proves the deployment
        // identity, and the binding moves with a real inspection summary.
        let report = instance_relocate(
            &fixture.context,
            &InstanceSelector {
                positional: Some("production".to_owned()),
                named: None,
            },
            "server-b",
        )?;
        assert!(report.contains("'server-b'"), "{report}");

        let moved = fixture
            .store()
            .instance_by_deployment("deploy-alpha")?
            .expect("still present");
        assert_eq!(moved.host_id, destination.host_id);
        let observation = moved.last_observation.expect("fresh observation");
        assert!(
            observation.summary.contains("rev=7"),
            "real inspection data recorded: {observation:?}"
        );
        Ok(())
    }

    #[test]
    fn relocate_refuses_when_the_target_reports_a_foreign_deployment() -> anyhow::Result<()> {
        let fixture = Fixture::with_scenario(Scenario::ForeignDeployment)?;
        let original = fixture.seed_ssh_host("server-a", "prod-a")?;
        let destination = fixture.seed_ssh_host("server-b", "prod-b")?;
        fixture.seed_instance(original.host_id, "deploy-alpha", "production")?;

        let error = instance_relocate(
            &fixture.context,
            &InstanceSelector {
                positional: Some("production".to_owned()),
                named: None,
            },
            "server-b",
        )
        .expect_err("foreign identity");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("elsewhere-deploy-alpha"), "{rendered}");
        assert!(rendered.contains("was not changed"), "{rendered}");

        let unchanged = fixture
            .store()
            .instance_by_deployment("deploy-alpha")?
            .expect("still present");
        assert_eq!(unchanged.host_id, original.host_id);
        assert_ne!(unchanged.host_id, destination.host_id);
        Ok(())
    }

    #[test]
    fn relocate_fails_closed_when_the_new_host_is_unreachable() -> anyhow::Result<()> {
        let fixture = Fixture::with_host_scenarios(Box::new(|record| {
            if record.alias == "server-b" {
                Scenario::Offline("ssh to 'server-b' timed out")
            } else {
                Scenario::Online
            }
        }))?;
        let original = fixture.seed_ssh_host("server-a", "prod-a")?;
        fixture.seed_ssh_host("server-b", "prod-b")?;
        fixture.seed_instance(original.host_id, "deploy-alpha", "production")?;

        let error = instance_relocate(
            &fixture.context,
            &InstanceSelector {
                positional: Some("production".to_owned()),
                named: None,
            },
            "server-b",
        )
        .expect_err("offline destination");
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        let unchanged = fixture
            .store()
            .instance_by_deployment("deploy-alpha")?
            .expect("still present");
        assert_eq!(unchanged.host_id, original.host_id);
        Ok(())
    }
}
