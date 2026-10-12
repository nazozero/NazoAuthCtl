use super::*;

#[test]
fn timeout_kills_and_reaps_the_direct_child() {
    let started = std::time::Instant::now();
    let error = Process::new("sh")
        .args(["-c", "exec sleep 5"])
        .timeout(Duration::from_millis(25))
        .run_quiet()
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn security_cloud_does_not_render_child_stderr() {
    for stdin in [false, true] {
        let process = Process::new("/bin/sh").args(["-c", "printf lifecycle-secret >&2; exit 3"]);
        let error = if stdin {
            process.stdin_stdout(b"").unwrap_err()
        } else {
            process.run_quiet().unwrap_err()
        };
        assert!(!error.to_string().contains("lifecycle-secret"));
        assert!(error.to_string().contains("status"));
    }
}

#[test]
fn security_cloud_curl_disables_implicit_configuration_first() {
    for program in ["curl", "/usr/bin/curl", "curl.exe"] {
        let process = Process::new(program).arg("--version");
        let command = process.command();
        assert_eq!(
            command.get_args().next(),
            Some(std::ffi::OsStr::new("--disable"))
        );
    }
}
