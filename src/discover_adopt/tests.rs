//! Shared discover/adopt scenarios (task G05).
//!
//! Every scenario runs against a real [`LocalTarget`] backed by a private
//! temp target-state root seeded through the production bootstrap path, so
//! assertions exercise real state documents, real enumeration, and the real
//! registry store. No container engine is ever spawned; Windows-safe.

use super::*;
use crate::filesystem::PrivateTempDir;
use crate::registry::{HostPrivilege, HostRecord};
use crate::target::{
    ArtifactRefs, BootstrapParams, BuildIdentity, RuntimeSurface, TargetStateStore,
};

const ARTIFACT: &str = "sha256:c0ffee0000000000000000000000000000000000000000000000000000000055";
const CONFIG_REFERENCE: &str = "/etc/nazauth/deployments/config.json";
const CONFIG_SCHEMA: &str = "nazauth-config-v1";

// ------------------------------------------------------------------ fixtures

struct Fixture {
    _temp: PrivateTempDir,
    context: DiscoveryContext,
    registry_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let temp = PrivateTempDir::new("nazauthctl-discover-adopt")?;
        let registry_root = temp.path().join("registry");
        let registry = RegistryStore::open(registry_root.clone())?;
        let state_root = temp.path().join("state");
        // The raw LocalTarget answers hello/ping/state-list natively; no
        // runtime override is needed because discovery never consumes
        // supported_runtimes.
        let local = crate::target::LocalTarget::with_state_root(&state_root);
        let context = DiscoveryContext {
            registry,
            factory: Box::new(move |_record| {
                Ok(Box::new(local.clone()) as Box<dyn ExecutionTarget + Send>)
            }),
        };
        Ok(Self {
            _temp: temp,
            context,
            registry_root,
            state_root,
        })
    }

    /// A fresh handle onto the same on-disk registry: proves writes by
    /// reloading instead of trusting in-memory caches.
    fn reloaded_registry(&self) -> anyhow::Result<RegistryStore> {
        RegistryStore::open(self.registry_root.clone())
    }

    fn target_store(&self) -> anyhow::Result<TargetStateStore> {
        TargetStateStore::open(&self.state_root)
    }

    fn seed_ssh_host(&self, alias: &str, profile: &str) -> anyhow::Result<HostRecord> {
        let host = HostRecord::new_ssh(alias, profile, HostPrivilege::Direct)?;
        self.context.registry.add_host(host)
    }

    /// Seed one deployment exactly the way a real install/bootstrap would
    /// commit it: a validated DeploymentState document under the target root.
    fn seed_deployment(
        &self,
        deployment_id: &str,
        issuer: &str,
        runtime_object: &str,
        resources: Vec<crate::target::Resource>,
        build_identity: Option<BuildIdentity>,
    ) -> anyhow::Result<()> {
        self.target_store()?.bootstrap(
            deployment_id,
            BootstrapParams {
                issuer: issuer.to_owned(),
                runtime: RuntimeSurface::new("podman", runtime_object)?,
                artifact: ArtifactRefs {
                    current: Some(ARTIFACT.to_owned()),
                    previous: None,
                },
                config_reference: CONFIG_REFERENCE.to_owned(),
                config_schema: CONFIG_SCHEMA.to_owned(),
                resources,
                current_build_identity: build_identity,
            },
            &uuid::Uuid::now_v7().to_string(),
        )?;
        Ok(())
    }
}

fn managed_runtime(runtime_object: &str) -> anyhow::Result<Vec<crate::target::Resource>> {
    Ok(vec![
        crate::target::Resource::new(
            "app-runtime",
            "container",
            runtime_object,
            crate::target::ResourceOwnership::Managed,
            crate::target::ResourceScope::Deployment,
        )?,
        // Shared dependency infrastructure: never ctl-owned.
        crate::target::Resource::new(
            "shared-postgres",
            "postgres",
            "pg-main.example.internal:5432/oauth",
            crate::target::ResourceOwnership::External,
            crate::target::ResourceScope::Shared,
        )?,
        // Dedicated-but-external volume: referenced, not owned.
        crate::target::Resource::new(
            "backup-volume",
            "volume",
            "/srv/backups/deploy-alpha",
            crate::target::ResourceOwnership::External,
            crate::target::ResourceScope::Deployment,
        )?,
    ])
}

// ------------------------------------------------------------ discover sweep

#[test]
fn discover_reports_every_declared_fact_per_deployment() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-alpha",
        "https://alpha.example.com",
        "nz-alpha",
        managed_runtime("nz-alpha")?,
        Some(BuildIdentity::new("nazoauth", "0.2.0", "abc1234")?),
    )?;
    fixture.seed_deployment(
        "deploy-beta",
        "https://beta.example.com",
        "nz-beta",
        vec![],
        None,
    )?;

    let report = run_discover(&fixture.context, DiscoverRequest { host: None })?;
    assert!(
        report.contains("discovered 2 NazoAuth deployment(s)"),
        "{report}"
    );

    // Per-deployment authoritative facts (G05 item 1), sorted deterministically.
    assert!(report.contains("[1] deploy-alpha"), "{report}");
    assert!(
        report.contains("issuer: https://alpha.example.com"),
        "{report}"
    );
    assert!(report.contains("runtime: podman/nz-alpha"), "{report}");
    assert!(report.contains("revision 1"), "{report}");
    assert!(report.contains(CONFIG_SCHEMA), "{report}");
    assert!(report.contains(ARTIFACT), "{report}");
    assert!(
        report.contains("build identity: nazoauth v0.2.0 (commit abc1234)"),
        "{report}"
    );
    assert!(
        report.contains("build identity: not recorded"),
        "deploy-beta has no build identity: {report}"
    );
    assert!(
        report.contains(
            "resources: 3 declared (managed+deletable: 1, external/shared zero-delete: 2)"
        ),
        "{report}"
    );
    assert!(
        report.contains("- shared-postgres [postgres] pg-main.example.internal:5432/oauth — external/shared (zero-delete protection)"),
        "{report}"
    );
    assert!(
        report.contains("- app-runtime [container] nz-alpha — managed+deployment"),
        "{report}"
    );

    // Multi-target display demands an exact id for follow-ups; adoption
    // candidates are named per deployment.
    assert_eq!(report.matches("adoption candidate").count(), 2, "{report}");
    assert!(
        report.contains("adopt --host local --deployment-id deploy-alpha"),
        "{report}"
    );
    assert!(report.contains("strictly read-only"), "{report}");
    Ok(())
}

#[test]
fn empty_target_discovers_zero_deployments() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;

    let report = run_discover(&fixture.context, DiscoverRequest { host: None })?;
    assert!(
        report.contains("discovered 0 NazoAuth deployment(s)"),
        "{report}"
    );
    assert!(report.contains("nothing to adopt"), "{report}");
    Ok(())
}

#[test]
fn bare_discover_writes_zero_registry_records_even_with_findings() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-alpha",
        "https://alpha.example.com",
        "nz-alpha",
        managed_runtime("nz-alpha")?,
        None,
    )?;
    let hosts_before = fixture.context.registry.list_hosts()?;

    let report = run_discover(&fixture.context, DiscoverRequest { host: None })?;
    assert!(report.contains("discovered 1"), "{report}");

    // Fresh reload proves the on-disk truth: zero instance records, and the
    // host record is byte-for-byte untouched (no observation cache write).
    let fresh = fixture.reloaded_registry()?;
    assert!(
        fresh.list_instances()?.is_empty(),
        "discover must not register"
    );
    let hosts_after = fresh.list_hosts()?;
    assert_eq!(hosts_after.len(), hosts_before.len());
    assert_eq!(hosts_after, hosts_before);
    assert!(hosts_after[0].last_observation.is_none());
    Ok(())
}

#[test]
fn multi_host_registries_demand_an_explicit_discovery_target() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_ssh_host("server-b", "prod-b")?;

    let error = run_discover(&fixture.context, DiscoverRequest { host: None })
        .expect_err("ambiguous hosts");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("--host"), "{rendered}");
    assert!(rendered.contains("server-b"), "{rendered}");
    assert!(rendered.contains("local"), "{rendered}");

    let unknown = run_discover(
        &fixture.context,
        DiscoverRequest {
            host: Some("ghost".to_owned()),
        },
    )
    .expect_err("unknown host");
    assert!(
        format!("{unknown:#}").contains("unknown host alias 'ghost'"),
        "{unknown:#}"
    );
    Ok(())
}

// ------------------------------------------------------------- adopt takeover

#[test]
fn adopt_registers_with_target_derived_evidence_and_classification() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-alpha",
        "https://alpha.example.com",
        "nz-alpha",
        managed_runtime("nz-alpha")?,
        Some(BuildIdentity::new("nazoauth", "0.2.0", "abc1234")?),
    )?;
    let state_path = fixture
        .state_root
        .join("deployments")
        .join("deploy-alpha")
        .join("state.json");
    let before = std::fs::read(&state_path)?;

    let report = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: None,
            deployment_id: "deploy-alpha".to_owned(),
            alias: Some("production".to_owned()),
        },
    )?;

    // Evidence matches the TARGET facts, not operator input.
    let record = fixture
        .context
        .registry
        .instance_by_alias("production")?
        .expect("adopted");
    assert_eq!(record.deployment_id, "deploy-alpha");
    assert_eq!(record.issuer, "https://alpha.example.com");
    let observation = record.last_observation.expect("first observation");
    assert!(observation.reachable, "{observation:?}");
    assert!(observation.summary.starts_with("rev=1 "), "{observation:?}");
    assert!(observation.summary.contains(ARTIFACT), "{observation:?}");

    // Conservative classification per §6: external/shared stays zero-delete;
    // only declared managed+deployment is reported deletable. Never guessed.
    assert!(
        report.contains("- app-runtime [container] nz-alpha — managed+deployment"),
        "{report}"
    );
    assert!(
        report.contains("- shared-postgres [postgres] pg-main.example.internal:5432/oauth — external/shared: zero-delete protection"),
        "{report}"
    );
    assert!(
        report.contains("- backup-volume [volume] /srv/backups/deploy-alpha — external/shared: zero-delete protection"),
        "{report}"
    );
    assert!(
        report.contains("managed+deletable: 1; external/shared zero-delete: 2"),
        "{report}"
    );
    assert!(
        report.contains("resource classification (from the authoritative target state; nothing upgraded to managed):"),
        "{report}"
    );
    assert!(
        report.contains("controller bind --instance <alias>"),
        "{report}"
    );
    assert!(report.contains("signed nothing"), "{report}");

    // Zero target-side mutation: the authoritative document is byte-stable.
    let after = std::fs::read(&state_path)?;
    assert_eq!(before, after, "adopt must not touch the target state");

    // Exactly one record exists.
    assert_eq!(fixture.context.registry.list_instances()?.len(), 1);

    // Re-adopting on the same host fails closed with the stable code.
    let error = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: None,
            deployment_id: "deploy-alpha".to_owned(),
            alias: None,
        },
    )
    .expect_err("duplicate adoption");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(ADOPT_ALREADY_REGISTERED), "{rendered}");
    Ok(())
}

#[test]
fn adopt_without_declared_resources_treats_everything_external() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-beta",
        "https://beta.example.com",
        "nz-beta",
        vec![],
        None,
    )?;

    let report = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: None,
            deployment_id: "deploy-beta".to_owned(),
            alias: None,
        },
    )?;
    assert!(
        report.contains("resources: none declared — everything is treated as external"),
        "{report}"
    );
    assert!(
        report.contains("uninstall could delete nothing"),
        "{report}"
    );
    // Alias defaults to the deployment id when not supplied.
    let record = fixture
        .context
        .registry
        .instance_by_alias("deploy-beta")?
        .expect("default alias");
    assert_eq!(record.deployment_id, "deploy-beta");
    Ok(())
}

// ------------------------------------------------------- discover/adopt drift

#[test]
fn adopt_fails_closed_when_live_drift_removed_the_discovered_target() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-vanishing",
        "https://vanish.example.com",
        "nz-vanish",
        vec![],
        None,
    )?;

    // Discover sees it…
    let report = run_discover(&fixture.context, DiscoverRequest { host: None })?;
    assert!(report.contains("deploy-vanishing"), "{report}");

    // …then the target drifts (deployment removed between the two calls).
    std::fs::remove_file(
        fixture
            .state_root
            .join("deployments")
            .join("deploy-vanishing")
            .join("state.json"),
    )?;

    // Adopt refuses on LIVE facts alone; stored reports are never input.
    let error = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: None,
            deployment_id: "deploy-vanishing".to_owned(),
            alias: None,
        },
    )
    .expect_err("vanished target");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(ADOPT_TARGET_UNKNOWN), "{rendered}");
    assert!(rendered.contains("live discovery reports: -"), "{rendered}");
    assert!(
        fixture.context.registry.list_instances()?.is_empty(),
        "drifted adoption registers nothing"
    );
    Ok(())
}

#[test]
fn adopt_requires_an_exact_live_deployment_id() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-alpha",
        "https://alpha.example.com",
        "nz-alpha",
        vec![],
        None,
    )?;

    // Malformed selectors (empty, untrimmed) fail the exact-id guard before
    // any discovery is consumed.
    for malformed in ["", "  deploy-alpha"] {
        let error = run_adopt(
            &fixture.context,
            AdoptRequest {
                host: None,
                deployment_id: malformed.to_owned(),
                alias: None,
            },
        )
        .expect_err(malformed);
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("exact non-empty --deployment-id"),
            "{malformed}: {rendered}"
        );
    }

    // A well-formed but non-matching id fails closed against LIVE discovery:
    // near-misses never fuzzy-match ("deploy-alph" ≠ "deploy-alpha").
    let error = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: None,
            deployment_id: "deploy-alph".to_owned(),
            alias: None,
        },
    )
    .expect_err("near-miss id");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(ADOPT_TARGET_UNKNOWN), "{rendered}");
    assert!(
        rendered.contains("live discovery reports: deploy-alpha"),
        "the refusal names the exact live candidates: {rendered}"
    );
    Ok(())
}

// ------------------------------------------------- relocation discipline (B07)

#[test]
fn relocation_is_reported_by_discover_and_refused_by_adoption() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let elsewhere = fixture.seed_ssh_host("server-b", "prod-b")?;
    fixture.context.registry.ensure_local_host()?;
    fixture.seed_deployment(
        "deploy-roaming",
        "https://roam.example.com",
        "nz-roam",
        vec![],
        None,
    )?;
    // The Registry believes this deployment lives on server-b (pre-existing
    // registration). The local target now reports the same id: a relocation.
    fixture.context.registry.add_instance(InstanceRecord::new(
        "deploy-roaming",
        "roaming",
        elsewhere.host_id,
        "https://roam.example.com",
        "target-state/ref",
    )?)?;

    // Discover reports the candidate and never rewrites the record.
    let report = run_discover(
        &fixture.context,
        DiscoverRequest {
            host: Some("local".to_owned()),
        },
    )?;
    assert!(report.contains("RELOCATION CANDIDATE"), "{report}");
    assert!(report.contains("host 'server-b' as 'roaming'"), "{report}");
    assert!(
        report.contains("instance relocate --instance roaming --to-host local"),
        "{report}"
    );
    let unchanged = fixture.reloaded_registry()?;
    let still_there = unchanged
        .instance_by_deployment("deploy-roaming")?
        .expect("record kept");
    assert_eq!(still_there.host_id, elsewhere.host_id);

    // Adopt against the new host requires explicit relocate semantics:
    // stable code plus guidance, record untouched.
    let error = run_adopt(
        &fixture.context,
        AdoptRequest {
            host: Some("local".to_owned()),
            deployment_id: "deploy-roaming".to_owned(),
            alias: None,
        },
    )
    .expect_err("relocation refused");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(ADOPT_RELOCATION_REQUIRED), "{rendered}");
    assert!(rendered.contains("instance relocate"), "{rendered}");
    let after = fixture.reloaded_registry()?;
    assert_eq!(
        after
            .instance_by_deployment("deploy-roaming")?
            .expect("still registered")
            .host_id,
        elsewhere.host_id,
        "adoption must never silently rewrite the binding"
    );
    Ok(())
}
