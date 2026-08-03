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
separate transaction with a separate journal and rollback slot.

## Operator-task boundary

The operator-task is a one-shot application executor. The controller prepares a
closed config manifest, verifies the selected signed target, signs a short-lived
task, runs the target in a restricted process/container, verifies its signed
runtime receipt, and appends a controller audit receipt.

It is deliberately absent from host recovery. Recovery chooses already verified
local material and directly operates the runtime and backup providers.
