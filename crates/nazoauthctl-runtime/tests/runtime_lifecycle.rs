#![cfg(unix)]

use std::{fs, process::Command};

use nazoauthctl_runtime::{
    RuntimeBackend,
    filesystem::PrivateTempDir,
    runtime_backend::{DockerBackend, PodmanBackend, SystemdBackend},
};

#[path = "../../../tests/unit/support.rs"]
mod support;

const UNIT: &str = "nazoauth-test.service";

#[test]
fn lifecycle_queries_only_the_state_each_operation_needs() {
    for backend in ["docker", "podman", "systemd"] {
        for case in [
            "absent",
            "stopped",
            "running",
            "stop-fails",
            "still-running",
            "missing-state",
            "inspect-fails",
            "post-stop-fails",
            "logs",
        ] {
            run_case(backend, case);
        }
    }
    for case in [
        "activating",
        "inspect",
        "inspect-absent",
        "process",
        "remove",
    ] {
        run_case("systemd", case);
    }
}

fn run_case(backend: &str, case: &str) {
    let work = PrivateTempDir::new("runtime-lifecycle").unwrap();
    fs::write(work.path().join("unit"), "# Managed by nazoauthctl\n").unwrap();
    for program in [
        "docker",
        "podman",
        "systemctl",
        "journalctl",
        "ps",
        "getent",
    ] {
        support::write_shell_executable(&work.path().join(program), FIXTURE);
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_child", "--ignored", "--nocapture"])
        .env("NAZOAUTHCTL_TESTING", "1")
        .env("LIFECYCLE_BACKEND", backend)
        .env("LIFECYCLE_CASE", case)
        .env("LIFECYCLE_DIR", work.path())
        .env("PATH", format!("{}:/usr/bin:/bin", work.path().display()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{backend}/{case}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(work.path().join("calls")).unwrap();
    let expected: &[&str] = match case {
        "running" | "activating" | "still-running" | "post-stop-fails" => {
            &["inspect", "stop", "inspect"]
        }
        "stop-fails" => &["inspect", "stop"],
        "logs" => &["logs"],
        "process" => &["process"],
        "remove" => &["inspect", "stop", "disable", "daemon-reload", "getent"],
        _ => &["inspect"],
    };
    assert_eq!(
        calls.lines().collect::<Vec<_>>(),
        expected,
        "{backend}/{case}"
    );
    if case == "remove" {
        assert!(!work.path().join("unit").exists());
    }
}

// Spawned with an isolated PATH by the parent, never changes process-global environment.
#[test]
#[ignore]
fn lifecycle_child() {
    let backend = std::env::var("LIFECYCLE_BACKEND").unwrap();
    let case = std::env::var("LIFECYCLE_CASE").unwrap();
    let runtime: Box<dyn RuntimeBackend> = match backend.as_str() {
        "docker" => Box::new(DockerBackend::default()),
        "podman" => Box::new(PodmanBackend::default()),
        "systemd" => Box::new(SystemdBackend),
        _ => unreachable!(),
    };
    match case.as_str() {
        "logs" => assert_eq!(runtime.read_logs(UNIT, 5).unwrap(), ["first", "second"]),
        "inspect" => assert!(runtime.inspect_optional(UNIT).unwrap().is_some()),
        "inspect-absent" => assert!(runtime.inspect_optional(UNIT).unwrap().is_none()),
        "process" => {
            let observed = runtime.inspect("process:123").unwrap();
            assert_eq!(observed.object_reference, "process:123");
            assert!(observed.server_command_verified);
        }
        "remove" => runtime.remove(UNIT).unwrap(),
        _ => {
            let result = runtime.quiesce_for_recovery(UNIT);
            match case.as_str() {
                "absent" | "stopped" => assert!(!result.unwrap()),
                "running" | "activating" => assert!(result.unwrap()),
                _ => assert!(result.is_err(), "{case}: {result:?}"),
            }
        }
    }
}

const FIXTURE: &str = r#"
program=${0##*/}
record() { printf '%s\n' "$1" >> "$LIFECYCLE_DIR/calls"; }
case "$program:$1" in
    docker:logs|podman:logs|journalctl:--unit)
        record logs
        printf 'first\nsecond\n'
        exit 0;;
    ps:-p)
        [ "$*" = '-p 123 -o args=' ] || exit 91
        record process
        printf '/missing/nazoauth server\n'
        exit 0;;
    getent:passwd) record getent; exit 2;;
    systemctl:stop|docker:stop|podman:stop)
        record stop
        [ "$LIFECYCLE_CASE" != stop-fails ] || exit 92
        touch "$LIFECYCLE_DIR/stopped"
        exit 0;;
    systemctl:disable|systemctl:daemon-reload) record "$1"; exit 0;;
    systemctl:show)
        case "$LIFECYCLE_CASE" in
            remove) [ "$4" = '--property=LoadState,FragmentPath' ] || exit 93;;
            inspect|inspect-absent) case "$4" in --property=Id,LoadState,ActiveState,*) ;; *) exit 94;; esac;;
            *) [ "$4" = '--property=LoadState,ActiveState' ] || exit 95;;
        esac;;
    docker:container|podman:container)
        [ "$*" = 'container inspect nazoauth-test.service --format {{json .}}' ] || exit 96;;
    *) exit 97;;
esac
record inspect
[ "$LIFECYCLE_CASE" != inspect-fails ] || { printf 'cannot connect\n' >&2; exit 1; }
if [ "$LIFECYCLE_CASE" = post-stop-fails ] && [ -f "$LIFECYCLE_DIR/stopped" ]; then exit 1; fi
if [ "$LIFECYCLE_CASE" = absent ] || [ "$LIFECYCLE_CASE" = inspect-absent ]; then
    if [ "$program" = systemctl ]; then printf 'LoadState=not-found\n'; exit 0; fi
    printf 'no such container\n' >&2
    exit 1
fi
if [ "$LIFECYCLE_CASE" = missing-state ]; then
    if [ "$program" = systemctl ]; then printf 'LoadState=loaded\n'; else printf '{}\n'; fi
    exit 0
fi
state=active
running=true
if [ "$LIFECYCLE_CASE" = stopped ] || { [ -f "$LIFECYCLE_DIR/stopped" ] && [ "$LIFECYCLE_CASE" != still-running ]; }; then
    state=inactive
    running=false
elif [ "$LIFECYCLE_CASE" = activating ]; then state=activating; fi
if [ "$program" = systemctl ]; then
    printf 'LoadState=loaded\nActiveState=%s\nFragmentPath=%s/unit\n' "$state" "$LIFECYCLE_DIR"
else
    printf '{"State":{"Running":%s}}\n' "$running"
fi
"#;
