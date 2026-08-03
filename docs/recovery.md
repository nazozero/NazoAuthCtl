# Recovery invariants

## Failure-domain layout

The recommended production layout uses distinct ownership and storage boundaries:

- `/etc/nazoauth`: server configuration and runtime-readable secrets;
- `/var/lib/nazoauth`: application data mounted into the server;
- `/var/lib/nazoauthctl`: controller state, journals, audit chain, trusted
  manifests, and cached server/controller artifacts;
- a separately mounted recovery medium: break-glass private material and encrypted
  off-host recovery packages.

The break-glass private key must never be included in a NazoAuth mount or OCI
secret. It must not share the active controller key's storage failure domain.

Every deployment has an independent controller identity, receipt identity,
audit identity, break-glass identity, transaction directory, recovery metadata,
lock, and backup policy. Recovery resolves the immutable deployment ID before
opening any backup or key. An alias is only a selector. When multiple deployments
exist, a destructive command without `--deployment` fails and lists candidates.

Resources record both responsibility and scope. An `external` resource is never
mutated. A `shared` database, Valkey, network, volume, proxy, or Release cache is
never deleted as a side effect of recovering or relinquishing one deployment.
Until a provider-specific shared database lifecycle can be proven safe, it stays
`external/shared`.

## Command dependency contract

| Command | HTTP | current server | current OCI | operator-task | previous trusted cache |
| --- | --- | --- | --- | --- | --- |
| rollback | no | no | no | no | required |
| recover | no | no | no | no | required |
| recover-update | no | no | no | no | required |
| recover-identity | no | no | no | no | not required |
| migrate/keys/conformance | no | selected usable target | selected usable target for OCI mode | required | no |
| bootstrap-admin | required | required | runtime-specific | no | no |
| status/doctor | optional probes | inspected when available | inspected when available | no | no |

Recovery metadata is treated as closed, signed/digested input. Unknown schemas,
unsupported protocol versions, missing cache members, digest mismatches, and
ambiguous update phases fail closed.

## Offline recovery

Before activation, the controller retains the previous trusted server manifest,
verification bundles, host binary or OCI archive, frontend material, and backup
metadata. OCI recovery imports the retained archive when the engine no longer has
the previous image. No network lookup is part of the recovery path.

The signed offline deployment statement identifies a stopped replica from its
persistent mount. It is not sufficient artifact trust: ctl also verifies the
cached Release and the retained OCI digest or host-binary SHA-256. An unsupported
operator protocol blocks application tasks only. It does not block stopping the
failed runtime, importing the previous trusted artifact, restoring a declared
snapshot, unwinding an interrupted update, or starting the previous version.

## Machine loss

Local redundancy does not survive loss of the machine. Disaster recovery requires
an encrypted off-host package containing the database backup/PITR locator,
application snapshots, trusted Release records and public verification material.
Break-glass private material is transported separately. Restoring such a package
is an operator procedure and is not claimed as an automatic single-machine ctl
capability.
