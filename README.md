# NazoAuthCtl

`nazoauthctl` is the independently built host controller for NazoAuth. It owns
installation, signed update, rollback, recovery, runtime orchestration,
operator-task issuance and verification, controller audit state, diagnostics,
and the bootstrap-admin client.

The NazoAuth server remains the authority for application migrations, production
keys, consistency leases, and the `operator-task` executor. Protocol types are
not copied here: this repository consumes `nazo-operator-protocol` from an exact
NazoAuth commit and an exact package version.

## Trust and recovery boundary

- Normal application management (`migrate`, `keys`, and `conformance`) may run a
  signed one-shot `nazoauth operator-task` when the selected server artifact is
  still executable.
- `rollback`, `recover`, `recover-update`, `recover-identity`, backup restore,
  and activation of the previous trusted artifact must not require the running
  NazoAuth HTTP service, the current container, the current server binary, or an
  operator-task.
- Controller journals, audit state, trusted Release metadata, and cached recovery
  artifacts live outside the NazoAuth application mounts.
- A controller on the same machine cannot recover a lost machine. That boundary
  requires a separately stored, encrypted off-host recovery package.

See [architecture](docs/architecture.md), [recovery boundaries](docs/recovery.md),
and [compatibility](docs/compatibility.md).

## Development

The repository builds only `nazoauthctl`. The server compatibility workflow
downloads signed NazoAuth Release binaries and OCI images; it never rebuilds the
server.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

No independent controller Release is created by this extraction PR.
