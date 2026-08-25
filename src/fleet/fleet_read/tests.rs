use super::*;
use crate::filesystem::PrivateTempDir;
use crate::registry::{HostPrivilege, InstanceRecord, RegistryStore};
use crate::target::{
    ControlOperationReceipt, ControlOperationRequest, HealthSnapshot, HostCompletionBody,
    HostOperation, HostOutcome, HostOverview, HostResult, RemoteHello, RuntimeSurface,
};
use std::sync::atomic::AtomicUsize;

#[derive(Clone)]
enum Scenario {
    Online,
    Offline(&'static str),
    /// Sleep longer than the runner timeout before answering.
    Slow(u64),
}

struct ScriptedTarget {
    scenario: Scenario,
}

impl ScriptedTarget {
    fn inspection(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
        if let Scenario::Offline(text) = self.scenario {
            anyhow::bail!("{text}");
        }
        Ok(InstanceInspection {
            current_build_identity: None,
            deployment_id: deployment_id.to_owned(),
            issuer: "https://auth.example.com".to_owned(),
            observed_at: chrono::Utc::now(),
            revision: 3,
            runtime: RuntimeSurface::new("podman", "nazoauth-main")?,
            artifact: Default::default(),
            config_reference: "/cfg".to_owned(),
            config_schema: "v1".to_owned(),
            resources: vec![],
            healthy: true,
            health_summary: "ok".to_owned(),
            backup_maturity: crate::target::BackupMaturity::Unknown,
            active_host_operation: None,
            bootstrap_material: None,
        })
    }
}

impl ExecutionTarget for ScriptedTarget {
    fn inspect_host(&self) -> anyhow::Result<HostOverview> {
        anyhow::bail!("unused in fleet_read tests")
    }

    fn inspect_instance(&self, deployment_id: &str) -> anyhow::Result<InstanceInspection> {
        if let Scenario::Slow(millis) = self.scenario {
            std::thread::sleep(std::time::Duration::from_millis(millis));
        }
        self.inspection(deployment_id)
    }

    fn execute_host_operation(&self, operation: &HostOperation) -> anyhow::Result<HostResult> {
        if let Scenario::Offline(text) = self.scenario {
            anyhow::bail!("{text}");
        }
        match &operation.operation {
            crate::target::HostOperationBody::Ping { nonce } => Ok(HostResult::completed(
                &operation.operation_id,
                HostCompletionBody::Ping {
                    nonce: nonce.clone(),
                },
            )),
            _ => anyhow::bail!("scripted target only answers pings here"),
        }
    }

    fn execute_control_operation(
        &self,
        _request: &ControlOperationRequest,
    ) -> anyhow::Result<ControlOperationReceipt> {
        anyhow::bail!("unused")
    }

    fn read_health(&self, deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
        let inspection = self.inspection(deployment_id)?;
        Ok(HealthSnapshot {
            deployment_id: inspection.deployment_id,
            healthy: true,
            summary: "ok".to_owned(),
            observed_at: chrono::Utc::now(),
        })
    }
}

struct Fixture {
    _temp: PrivateTempDir,
    store: RegistryStore,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let temp = PrivateTempDir::new("nazauthctl-fleet-read-test")?;
        let store = RegistryStore::open(temp.path().join("registry"))?;
        let host_a = store.add_host(crate::registry::HostRecord::new_ssh(
            "server-a",
            "prod-a",
            HostPrivilege::Direct,
        )?)?;
        let host_b = store.add_host(crate::registry::HostRecord::new_ssh(
            "server-b",
            "prod-b",
            HostPrivilege::Direct,
        )?)?;
        let host_c = store.add_host(crate::registry::HostRecord::new_ssh(
            "server-c",
            "prod-c",
            HostPrivilege::Direct,
        )?)?;
        for (host, alias) in [(host_a, "prod-a"), (host_b, "prod-b"), (host_c, "prod-c")] {
            store.add_instance(InstanceRecord::new(
                format!("deploy-{alias}"),
                alias,
                host.host_id,
                "https://auth.example.com",
                "ref",
            )?)?;
        }
        Ok(Self { _temp: temp, store })
    }

    fn items(&self) -> anyhow::Result<Vec<(InstanceRecord, HostRecord)>> {
        let mut items = Vec::new();
        for instance in self.store.list_instances()? {
            let host = self
                .store
                .host_by_id(instance.host_id)?
                .expect("fixture host");
            items.push((instance, host));
        }
        Ok(items)
    }
}

fn job() -> Arc<ReadJob> {
    Arc::new(|_instance, _host, target| {
        let hello = crate::fleet::live_probe(target)?;
        let inspection = target.inspect_instance("ignored-here")?;
        Ok(json!({
            "helper": crate::fleet::summarize_hello(&hello),
            "deployment_id": inspection.deployment_id,
        }))
    })
}

/// A/B online and C offline: every successful result survives, the offline
/// item carries a stable failure, and the order stays registry-stable.
#[test]
fn partial_failure_is_isolated_and_order_is_stable() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let items = fixture.items()?;
    assert_eq!(items.len(), 3);
    let aliases: Vec<String> = items.iter().map(|(i, _)| i.alias.clone()).collect();
    assert_eq!(aliases, ["prod-a", "prod-b", "prod-c"]);

    let factory: Arc<
        dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> + Send + Sync,
    > = Arc::new(|record: &HostRecord| {
        let scenario = if record.alias == "server-c" {
            Scenario::Offline("ssh to 'x' exited 255")
        } else {
            Scenario::Online
        };
        Ok(Box::new(ScriptedTarget { scenario }) as Box<dyn ExecutionTarget + Send>)
    });
    let runner = FleetReadRunner::new(factory, MAX_CONCURRENCY, Duration::from_secs(5));
    let outcomes = runner.run(items, job());
    assert_eq!(outcomes.len(), 3);
    assert_eq!(outcomes[0].instance.alias, "prod-a");
    assert_eq!(outcomes[1].instance.alias, "prod-b");
    assert_eq!(outcomes[2].instance.alias, "prod-c");
    assert!(outcomes[0].result.is_ok(), "{:?}", outcomes[0].result);
    assert!(outcomes[1].result.is_ok());
    let (code, detail) = outcomes[2].result.as_ref().expect_err("offline").clone();
    assert_eq!(code, error_codes::HOST_UNREACHABLE, "{detail}");
    assert!(detail.contains("exited 255"), "{detail}");
    Ok(())
}

#[test]
fn slow_targets_time_out_without_blocking_the_rest() -> anyhow::Result<()> {
    let factory: Arc<
        dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> + Send + Sync,
    > = Arc::new(|record: &HostRecord| {
        let scenario = if record.alias == "server-a" {
            Scenario::Slow(400)
        } else {
            Scenario::Online
        };
        Ok(Box::new(ScriptedTarget { scenario }) as Box<dyn ExecutionTarget + Send>)
    });
    let runner = FleetReadRunner::new(factory, 4, Duration::from_millis(80));
    let fixture = Fixture::new()?;
    let items = fixture.items()?;
    let start = std::time::Instant::now();
    let outcomes = runner.run(items, job());
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout must bound the run: {elapsed:?}"
    );
    let (code, detail) = outcomes[0].result.as_ref().expect_err("slow").clone();
    assert_eq!(code, error_codes::HOST_UNREACHABLE, "{detail}");
    assert!(detail.contains("did not answer within"), "{detail}");
    assert!(outcomes[1].result.is_ok());
    assert!(outcomes[2].result.is_ok());
    Ok(())
}

#[test]
fn concurrency_is_bounded_by_the_cap() -> anyhow::Result<()> {
    const PROBE_CONCURRENCY: usize = 8;
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let barrier_hit = Arc::new(std::sync::Barrier::new(1));
    let _ = barrier_hit;
    struct GateTarget {
        in_flight: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
    }
    impl ExecutionTarget for GateTarget {
        fn inspect_host(&self) -> anyhow::Result<HostOverview> {
            unreachable!()
        }
        fn inspect_instance(&self, _deployment_id: &str) -> anyhow::Result<InstanceInspection> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_seen.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("stop after measurement")
        }
        fn execute_host_operation(&self, _operation: &HostOperation) -> anyhow::Result<HostResult> {
            unreachable!()
        }
        fn execute_control_operation(
            &self,
            _request: &ControlOperationRequest,
        ) -> anyhow::Result<ControlOperationReceipt> {
            unreachable!()
        }
        fn read_health(&self, _deployment_id: &str) -> anyhow::Result<HealthSnapshot> {
            unreachable!()
        }
    }

    // Build a registry with more instances than the cap.
    let temp = PrivateTempDir::new("nazauthctl-fleet-cap-test")?;
    let store = RegistryStore::open(temp.path().join("registry"))?;
    let host = store.ensure_local_host()?;
    for index in 0..12 {
        store.add_instance(InstanceRecord::new(
            format!("deploy-{index:02}"),
            format!("inst-{index:02}"),
            host.host_id,
            "https://auth.example.com",
            "ref",
        )?)?;
    }
    let mut items = Vec::new();
    for instance in store.list_instances()? {
        items.push((instance, host.clone()));
    }
    let in_flight_clone = in_flight.clone();
    let max_clone = max_seen.clone();
    let factory: Arc<
        dyn Fn(&HostRecord) -> anyhow::Result<Box<dyn ExecutionTarget + Send>> + Send + Sync,
    > = Arc::new(move |_record: &HostRecord| {
        Ok(Box::new(GateTarget {
            in_flight: in_flight_clone.clone(),
            max_seen: max_clone.clone(),
        }) as Box<dyn ExecutionTarget + Send>)
    });
    let runner = FleetReadRunner::new(factory, PROBE_CONCURRENCY, Duration::from_secs(10));
    let outcomes = runner.run(items, Arc::new(|_, _, _| Ok(json!({}))));
    assert_eq!(outcomes.len(), 12);
    assert!(
        max_seen.load(Ordering::SeqCst) <= PROBE_CONCURRENCY,
        "cap violated: {}",
        max_seen.load(Ordering::SeqCst)
    );
    assert!(max_seen.load(Ordering::SeqCst) >= 2, "some concurrency expected");
    Ok(())
}

#[test]
fn stable_code_maps_transport_tokens() {
    assert_eq!(
        stable_code("REMOTE_HELPER_MISMATCH: drift"),
        error_codes::REMOTE_HELPER_MISMATCH
    );
    assert_eq!(
        stable_code("SSH_AUTH_FAILED: permission denied"),
        error_codes::SSH_AUTH_FAILED
    );
    assert_eq!(
        stable_code("SUDO_PASSWORD_REQUIRED: sudo refused"),
        error_codes::PRIVILEGE_REQUIRED
    );
}
