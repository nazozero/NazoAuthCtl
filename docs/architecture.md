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

## Operator-task boundary

The operator-task is a one-shot application executor. The controller prepares a
closed config manifest, verifies the selected signed target, signs a short-lived
task, runs the target in a restricted process/container, verifies its signed
runtime receipt, and appends a controller audit receipt.

It is deliberately absent from host recovery. Recovery chooses already verified
local material and directly operates the runtime and backup providers.
