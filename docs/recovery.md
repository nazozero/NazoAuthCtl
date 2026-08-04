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
the previous image. The cache binds the signed registry digest to the backend's
immutable local image ID and the archive SHA-256 before export. After import,
activation and acceptance use that same immutable local ID because Docker-format
archives do not reliably retain registry digest metadata. The deployment
declaration continues to record the signed Release digest as artifact identity;
the local ID is only the offline content link. No network lookup is part of the
recovery path.

For an adopted manual deployment, the lifecycle contract is the executable
offline boundary. It records every real object reference and an exact neutral
replacement specification. Its recovery driver is bound by absolute path and
SHA-256 and can only receive file/provider credential references. Adoption first
executes `rehearse`; an update executes `checkpoint`; full recovery executes
`restore`. Every receipt is bound to deployment, request, Release, lifecycle,
recovery manifest, operation, component set, and freshness window.

Full recovery first asks each selected backend to prove that every declared
runtime is stopped or absent. An unavailable backend or an indeterminate object
state fails before the recovery driver may restore application data or provider
state. The deployment-local recovery journal records that quiescence boundary
and binds the lifecycle, trusted runtime cache, and recovery-manifest digests so
an interrupted recovery cannot resume against substituted input.

The update journal is deployment-local and resumable. External or provider steps
pause until deployment- and transaction-bound evidence is supplied. ctl-owned
runtime replacements are recorded after each replica. The declaration changes
only after every target artifact and embedded build identity is observed. The
pre-update checkpoint and old trusted runtime become the rollback slot before
that atomic commit. Artifact-only rollback never restores provider data; full
recovery does.

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
