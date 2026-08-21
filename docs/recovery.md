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
replacement specification, including an explicit backend-neutral container
runtime policy. Recovery preserves that declared policy; adapters do not inject
managed-install hardening or infer policy from object names. Its recovery driver is bound by absolute path and
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

An external proxy provider keeps its own root-only recovery journal. Before a
reload it retains the previous configuration and CA bundle, records old/new
digests and the deployment transaction, validates the complete candidate, and
only then atomically selects it. After a crash, recovery reconciles the active
worker generation and file digests before deciding whether to finish or restore;
it never guesses from file names or application health alone. The old bundle is
retired only after the previous worker has exited. A conformance cleanup is not
complete until the pre-run proxy generation has been restored and probed.

The file-backed conformance provider records its intent as the private sibling
`.BUNDLE_NAME.nazoauthctl-restore`. Before onboarding, ctl also commits a
deployment-local, owner-only run journal bound to deployment/revision, target
issuer, request JTI, Matrix digest, random onboarding-bundle digest, expiry, and
the exact proxy paths. The active process holds that run's lock, so recovery
skips live parallel runs. After a crash, the next `conformance run` claims only
unlocked journals, lists leases through the authenticated operator protocol,
and identifies a pre-receipt lease by the random bundle digest. It independently
retries lease revoke/cleanup and proxy restoration; completion of one side is
persisted before retrying the other, and the journal is durably removed only
after both obligations finish. A five-minute settlement window prevents a
still-finishing operator apply from being mistaken for “no lease created”.

Proxy recovery invokes the same validated reload executable even when no new
run will install trust. Operators must not delete the journal or sibling
recovery file and must not start a second proxy writer; resolve any reported
operator/reload failure and rerun the command. Schema 1 journals cover the
legacy lease/proxy path for backward recovery. Schema 2 journals own ordinary
tenant-resource recovery: the exact signed Apply request and private manifest
are durable before mutation, the signed receipt is persisted before cleanup,
enumeration observes only the run identities, and Revoke is digest-fenced.
Resource and proxy cleanup markers are independent; the journal is removed only
after both complete and the private manifest has passed the durable
deletion-intent sequence.

An explicitly requested certification retention is a separate disposition, not
`cleanup_complete`. It is accepted only for the canonical official Suite and
only after all created modules are terminal and ordinary resource, listener,
and proxy cleanup have succeeded. The journal first records `RetentionPrepared`
while it still owns every Suite plan and, before creating files, binds
deterministic private provider-evidence paths. It then stages and verifies the
complete provider bundle, records its digest, writes a root-owned owner-only
pending Suite manifest, transfers ownership as `Retained`, promotes provider
evidence, and finally promotes the Suite manifest. A crash before transfer
defaults to normal plan deletion; a retained journal with a missing or
digest-mismatched provider bundle or Suite manifest fails closed and never
deletes the recorded plans. Operators review/publish retained plans in the
official UI and must use a later controlled deletion procedure; ctl does not
roll them back when unrelated cleanup subsequently fails.
Default ordinary runs continue to write schema-2 journals without retention
fields. New requested retentions upgrade the live journal to schema 4; schema
3 retained journals remain readable only for recovery/inspection compatibility
and are never silently upgraded. An older ctl binary rejects schema 4
fail-closed, so operators must not downgrade the binary until the retained
journal has finished and been removed.
The provider bundle itself is schema 5 and includes the exact signed artifact
digest in addition to its signed driver and Matrix identities; older bundle
shapes are not accepted for a new retained ownership transfer.

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
