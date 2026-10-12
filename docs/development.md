# Development and verification

## Architecture and ownership

The workspace has three boundaries in addition to its root library:

| Owner | Responsibility |
| --- | --- |
| Root `nazoauthctl-core`, under `src/` | CLI contracts, host/instance registry, controller workflows, release verification, target protocol, journals, TLS and recovery decisions. |
| `crates/nazoauthctl` | Executable entry and OIDF command routing. |
| `crates/nazoauthctl-runtime` | Audited filesystem/process primitives and Docker, Podman and host runtime implementations. |
| `crates/nazoauthctl-conformance` | Official Suite clients, bounded orchestration, signed driver/Matrix handling and private evidence. It does not own official test results. |

The registry locates an instance; the target owns deployment state and execution
records. Resource discovery does not grant authority to mutate a resource.
Keep declared external/delegated/managed responsibilities when adding operations.
Shared protocol definitions come from the immutable `nazo-operator-protocol`
dependency in [Cargo.toml](../Cargo.toml). The existing local VP extension and
its upstream integration boundary are documented in [oidf-artifacts.md](oidf-artifacts.md).

Follow the existing command → controller → target operation → journal/receipt
chain. Retries retain the original operation identity and canonical content;
same identity with different content conflicts. An accepted signed request is
replayed with its original signature, including after key retirement. A request
never accepted still needs current authorization. Recovery must remain possible
without the active HTTP service or execution of its failed binary.

Current formats and migration-aware rollback are defined in
[compatibility.md](compatibility.md). TLS uses the existing lifecycle with its
own explicit provider authority; consult [tls-deployment.md](tls-deployment.md)
only for transport/certificate work. OIDF contracts are in
[oidf-artifacts.md](oidf-artifacts.md), with operational selection and failure
behavior in [conformance-run-options.md](conformance-run-options.md).

Published persistence fixtures are part of that contract. `self verify-state`
checks local readability without contacting services or rewriting stored bytes;
self-update and installer replacement must pass it before changing the installed
executable. Keep supported readers and frozen fixtures when a writer changes.

## Target capabilities

The target helper advertises usable runtimes. Clean install currently accepts
Linux and Windows target path models; `host` requires Linux systemd, while
Podman/Docker require the target engine. Direct TLS clean install is limited
to Linux containers. macOS is not accepted as a clean-install target. Native CI
success is not full lifecycle/recovery qualification for each combination.

The installer derives a deployment-specific loopback port. Read the current
`runtime.loopback_port` from `nazoauthctl --json status --instance INSTANCE`;
container port 8000 and source-tree Compose variables do not select this port.

## Verification

Dependency pins, compatibility constraints and useful upstream APIs are described
in [dependency maintenance](dependencies.md).

Use the pinned `rust-toolchain.toml`. Run commands from the repository root and
select the owning package/test first. These are available entry points, not a
mandatory sequence for every edit:

```sh
cargo fmt --all -- --check
cargo test --locked -p PACKAGE TEST_FILTER
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace --all-targets --all-features --release
```

Replace `PACKAGE` and `TEST_FILTER` with actual Cargo/test names. Tests use the
existing inline or mounted private-unit and crate test modules; do not create
another implementation of signing, journal transitions or release verification
inside fixtures. Assert resulting state and side effects. Lifecycle changes
need the relevant repeated-request, conflict, interruption, recovery, migration
fence and resource-isolation cases.

[CI](../.github/workflows/ci.yml) defines Linux, Windows and both macOS
architecture jobs, plus platform-specific installer checks. Evidence from one
platform does not establish another platform's filesystem, process or runtime
behavior. Use isolated fixtures and test credentials; a development task does
not authorize operations against registered real deployments.

The [signed-server gate](../.github/workflows/server-compatibility.yml) fixes a
controller commit and resolves the selected server release once. It verifies
host/OCI attestations and invokes production `VerifiedRelease::verify`; the
ignored external test requires the workflow's explicit artifact inputs.
Ordinary workspace tests do not prove this gate or real SSH/backup recovery.

For documentation-only changes, validate references, command names and changed
claims against their owners. Do not build the workspace or invoke deployment
commands merely to validate documentation. Once relevant checks pass, rerun or
expand only for a new change, failure or unresolved risk.

## Documentation maintenance

Every change includes maintenance of its corresponding guide, command examples
and affected indexes. Keep durable behavior here or in the owning contract;
update [README.md](../README.md) when a user-facing entry changes. Release notes
describe their named release, not the current command set. Put one-time logs,
test counts, selected artifact digests and acceptance reports in task/CI
evidence. Report local tests, platform execution, official Suite outcomes,
signed-release compatibility and deployment/recovery results separately.

## Simplification boundaries

Runtime backends and declared resource ownership are real extension boundaries.
PostgreSQL, Valkey and the current HTTP implementation do not define the future
set of backends. Add implementations at those boundaries when a command needs
them; do not maintain unused managed-service provisioning APIs as a substitute
for an executable workflow. `replace` creates an inactive candidate; its caller
owns `start` and readiness verification.

The runtime crate owns shared secure-file and child-process primitives.
Permission checks establish ownership and write/read authority, rather than a
particular ACL entry count. Private Unix controller files may belong to root or
the effective controller user. Windows private ACLs must exclude untrusted
principals; equivalent protected ACLs need not match the writer's exact layout.

Inspection isolates unrelated corrupt records. Exact instance/key lookup reads
the selected record. Recovery journals retain durable intent and recorded side
effects; a write failure is not converted into success by reading cached bytes.
Derived recovery staging can be rebuilt from the verified immutable snapshot.
