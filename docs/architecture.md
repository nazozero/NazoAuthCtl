# Repository and authority boundaries

## Ownership

| Authority | NazoAuth | NazoAuthCtl |
| --- | --- | --- |
| Server and HTTP endpoints | yes | client only |
| Database migrations and application key mutations | executes | authorizes and verifies |
| Operator protocol types and cryptography | unique source | exact dependency |
| Host/container lifecycle and backups | no | yes |
| Server Release/OCI verification | publishes | consumes |
| Controller Release and self rollback | no | publishes and consumes |
| Controller journals and audit chain | no | yes |

## Deployment state model

Discovery, trust, and authority are separate facts:

- `discovered` is ephemeral read-only evidence and creates no registry state;
- `observed` is a persisted, verified deployment which remains read-only;
- `adopted` binds the immutable deployment identity to a controller authority;
  it does not imply that any resource is managed.

Each capability has an independent responsibility (`external`, `delegated`, or
`managed`) and scope (`deployment` or `shared`). The deployment ID, not a
container name, port, path, unit name, alias, or discovery order, is the security
identity. Runtime instance IDs identify replicas inside that deployment.

Registry and declaration state live under `/etc/nazoauthctl`. Mutable state is
partitioned below `/var/lib/nazoauthctl/deployments/<deployment-id>`. Controller,
receipt, audit, and break-glass identities are generated per deployment; the
break-glass private identity uses a separate root. Registry, deployment, and
shared-resource locks have different scopes, so independent deployments do not
share one global mutation lock.

## Runtime adapters

Podman, Docker, and systemd implement the same typed runtime boundary for
discovery, inspection, lifecycle, replacement, one-shot execution, digest
resolution, build identity, mounts, and ownership checks. Deployment records
store neutral mount semantics such as `read_only` and `selinux_relabel`; backend
command syntax is not part of the declaration. Manually adopted objects keep
their real names. Controller-created names are derived from the deployment ID,
but labels and signed deployment identity remain authoritative.

## Mixed-ownership transactions

An update plan assigns every step to `ctl-owned`, `user-required`, or
`provider-owned`. The plan, target Release, declaration revision, and steps are
persisted below the selected deployment's `transactions` directory. External
steps pause the transaction. Evidence is closed JSON bound to the deployment,
transaction, step, opaque reference, and SHA-256; stored evidence is re-hashed
on resume. A different deployment, a changed declaration revision, a conflicting
plan, or modified evidence fails closed.

Evidence acceptance is deliberately not a completion assertion. A controller
step remains pending until the controller executes it, and final acceptance must
independently observe the expected result. This permits external operators and
providers to coordinate without granting ctl authority over their resources.

Proxy TLS remains an external capability. For `standards-full`, application
configuration (`MTLS_CERTIFICATE_SOURCE` and `TRUSTED_PROXY_CIDRS`) is necessary
but is not evidence that a proxy requested, validated, and safely forwarded a
client certificate. Acceptance therefore requires fresh provider evidence bound
to the deployment and update transaction: the observed proxy configuration
digest, the active client-CA bundle digest, an exact trusted upstream address,
RFC 9440 header-overwrite semantics, and TLS/mTLS probes. The provider owns
configuration validation, atomic reload, rollback, and recovery of its proxy;
ctl must not synthesize completion from application settings.

Conformance certificates and trust anchors are run-scoped. If a shared proxy is
used, the provider must atomically install the active lease's public CA bundle
before Suite modules are created and restore the previous bundle during the same
cleanup transaction. Such runs are serialized unless they have independent
listeners and bundles. Private keys never cross this boundary.

For a file-backed provider, `conformance run` accepts the paired
`--proxy-trust-bundle` and `--proxy-reload-executable` options. The materializer
supplies only generated public client CAs. ctl atomically installs that bundle,
invokes a root-owned reload executable, and restores a sibling recovery copy
after Suite and lease cleanup. Supplying only one option fails before proxy,
deployment, or Suite mutation.

`nazo-operator-protocol` remains in `nazozero/NazoAuth`. `Cargo.toml` pins both
the package version and a full Git revision. A protocol change therefore requires
an explicit dependency update and compatibility review; Cargo cannot silently
select a different protocol implementation.

## Two release domains

The server Release manifest is signed by the NazoAuth release workflow. It binds
the server binary, OCI index and platform digests, embedded build identity,
operator protocol version, supported controller range, frontend, and rollback
policy.

The controller Release manifest is signed by the NazoAuthCtl release workflow.
It binds only controller binaries and the controller's own rollback floor. A
server update cannot replace the running controller. Controller self-update is a
separate transaction with a global controller lock, journal, signed audit chain,
trust record, and rollback slot under the controller state root. It does not
select or borrow configuration, keys, or mutable state from any NazoAuth
deployment.

## Local development activation

Local development is a separate, explicit trust domain. Any operator may build
a NazoAuth OCI image or host binary locally and activate it with `development
activate`; the feature has no host-provider or GitHub dependency. It requires an
adopted, single-runtime deployment whose runtime and artifact capabilities are
managed, refuses to race an active update transaction, and uses the same locked
runtime replacement boundary as managed Release activation.

The unsigned artifact is accepted only when its embedded identity binds an exact
`local:<full-revision>` build ID to a full lowercase commit revision and a unique
semantic prerelease containing that revision's first eight characters. OCI
activation is pinned to the backend's immutable local image ID; host activation
is pinned to the binary SHA-256. The controller caches the previous runtime and
verifies the active local identity before updating the deployment declaration.

Development activation does not perform application migrations and does not
write the signed Release trust state. Consequently it cannot lower the normal
signed update floor or turn local material into a trusted Release. Returning to
a published build still uses the ordinary signed `update` transaction. The
conformance command may execute against a declared local runtime, but only after
re-reading its embedded identity and OCI manifest or host-binary digest; the
default signed task path and explicit signed candidate path are unchanged.

## Operator-task boundary

The operator-task is a one-shot application executor. The controller prepares a
closed config manifest, verifies the selected signed target, signs a short-lived
task, runs the target in a restricted process/container, verifies its signed
runtime receipt, and appends a controller audit receipt.

It is deliberately absent from host recovery. Recovery chooses already verified
local material and directly operates the runtime and backup providers.
