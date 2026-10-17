use super::*;
use crate::process::Process;

fn task() -> OneShotTask {
    OneShotTask {
        artifact: ArtifactReference::Oci {
            image_reference: "example/nazoauth".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
        },
        command: vec!["nazoauth".into(), "operator-task".into()],
        network: None,
        mounts: Vec::new(),
        environment: BTreeMap::new(),
        working_directory: None,
        service_user: None,
        transient_credentials: BTreeMap::new(),
        read_only_paths: Vec::new(),
        read_write_paths: Vec::new(),
        inaccessible_paths: Vec::new(),
        private_mounts: false,
        stdin: b"request\n".to_vec(),
    }
}

#[test]
fn operator_capture_preserves_only_closed_rejection_markers() {
    for class in [
        "request",
        "authorization",
        "deployment",
        "revision",
        "conflict",
        "unavailable",
    ] {
        let marker = format!("nazoauth-operator-rejection={class}");
        let script =
            format!("cat >/dev/null; printf '%s\\n' '{marker}' 'database-password' >&2; exit 1");
        let error = task()
            .capture_result(Process::new("/bin/sh").args(["-c", &script]))
            .unwrap_err();
        assert_eq!(error.to_string(), marker);
    }
    for diagnostic in [
        "database-password",
        "nazoauth-operator-rejection=database-password",
        "database-password: nazoauth-operator-rejection=unavailable",
    ] {
        let script = format!("cat >/dev/null; printf '%s\\n' '{diagnostic}' >&2; exit 1");
        let error = task()
            .capture_result(Process::new("/bin/sh").args(["-c", &script]))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("operator task exited without a control receipt:")
        );
        assert!(!error.to_string().contains("database-password"));
    }
}

#[test]
fn operator_capture_keeps_stdout_receipts_on_nonzero_exit() {
    let output = task().capture_result(Process::new("/bin/sh").args([
        "-c",
        "cat >/dev/null; printf 'receipt'; printf 'nazoauth-operator-rejection=unavailable\\n' >&2; exit 1",
    ])).unwrap();
    assert_eq!(output, "receipt");
}
