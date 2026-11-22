//! Runs the same RP driver used by the CLI against independent OS processes.
//! The fixture prepares NazoAuth through its normal CLI and public account APIs.
use std::{env, path::PathBuf, sync::Arc, time::Duration};

use nazoauthctl_conformance::{
    ClientConfig, HttpTransport, Origin, RpSettings, RunControl, SuiteClient, run_rp_blackbox,
};
use nazoauthctl_runtime::secure_file;

#[test]
#[ignore = "requires independent production NazoAuth and the original OIDF Suite"]
fn production_rp_blackbox() {
    let target = Origin::parse(&env::var("OIDF_RP_ORIGIN").expect("SUT origin")).unwrap();
    let suite_origin = Origin::parse_suite("https://localhost:8443").unwrap();
    let config =
        PathBuf::from(env::var_os("OIDF_RP_SETTINGS").expect("private account/provider settings"));
    let settings = RpSettings::load(&config, &target).unwrap();
    let evidence =
        PathBuf::from(env::var_os("OIDF_RP_EVIDENCE").expect("private evidence directory"));
    secure_file::ensure_directory(&evidence, true).unwrap();
    let suite = SuiteClient::with_transport(
        suite_origin,
        None,
        Arc::new(HttpTransport::new(Duration::from_secs(30)).unwrap()),
        ClientConfig::default(),
    )
    .unwrap();
    // The isolated original Suite dev profile has no authentication. Production
    // invocations still use the controller's authenticated Suite workflow.
    let report = run_rp_blackbox(
        &suite,
        target,
        &settings,
        &evidence,
        Duration::from_secs(60),
        true,
        &RunControl::default(),
    )
    .expect("black-box RP driver");
    assert_eq!(report.suite_runtime["version"], "5.3.4");
    assert_eq!(report.suite_runtime["revision"], "23353b3");
    assert!(
        report.cleanup_complete,
        "RP resource cleanup was incomplete"
    );
    assert!(
        report.success,
        "inspect rp-report.json for original Suite outcomes and application assertions"
    );
    assert_eq!(
        report
            .plans
            .iter()
            .map(|plan| plan.modules.len())
            .sum::<usize>(),
        28
    );
    let results = report
        .plans
        .iter()
        .flat_map(|plan| &plan.modules)
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|module| module.suite_result.as_deref() == Some("PASSED"))
            .count(),
        26
    );
    assert_eq!(
        results
            .iter()
            .filter(|module| module.suite_result.as_deref() == Some("SKIPPED"))
            .count(),
        2
    );
}
