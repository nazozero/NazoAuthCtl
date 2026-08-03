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
[discovery and adoption](docs/discovery-adoption.md), and
[compatibility](docs/compatibility.md).

## Existing deployments

Discovery is read-only and does not require a controller registry:

```sh
nazoauthctl discover
nazoauthctl adopt --target podman:actual-object-name --plan
nazoauthctl adopt --target podman:actual-object-name --yes
nazoauthctl deployments list
nazoauthctl --deployment DEPLOYMENT_ID status
```

Adoption records trust; it does not silently take ownership. Runtime, artifact,
configuration, database, Valkey, operator-task, backup, and proxy/TLS authority
are granted separately as `external`, `delegated`, or `managed`. Mixed updates
persist their plan and pause at external steps:

```sh
nazoauthctl --deployment DEPLOYMENT_ID update --yes
nazoauthctl --deployment DEPLOYMENT_ID transaction show
nazoauthctl --deployment DEPLOYMENT_ID transaction evidence --file evidence.json --yes
nazoauthctl --deployment DEPLOYMENT_ID transaction resume --yes
```

Accepted evidence is digest-bound coordination input. It does not by itself
claim that an external operation is semantically complete; final acceptance
must still observe the declared issuer, artifact, readiness, and replica state.

## Development

The repository builds only `nazoauthctl`. The server compatibility workflow
downloads signed NazoAuth Release binaries and OCI images; it never rebuilds the
server.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

No independent controller Release is created by this extraction PR.
