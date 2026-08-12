# Discovery and adoption

## Read-only discovery

`nazoauthctl discover` enumerates local Podman, Docker, and systemd/process
backends. It does not require registry state, scan arbitrary networks, label or
rename objects, restart services, pull images, or write runtime state. Repeating
it has no external side effect.

For each candidate it records the actual object reference, command, artifact and
digest or host SHA-256, ports, networks, neutral mounts, safe non-secret identity
environment, and backend evidence. Environment values and mount sources that can
contain credentials are not emitted. Multiple candidates are reported as
ambiguous; selection is never based on enumeration order.

Online identification sends a random nonce to
`POST /.well-known/nazoauth-control` and verifies the domain-separated
`nazoauth-control-discovery+jwt` response with the returned instance public key.
Offline identification verifies the same replica's persistent signed deployment
statement. Both carry deployment and runtime instance IDs, issuer, Release,
revision, build ID, instance key ID, and supported protocol versions. Neither is
artifact trust: ctl separately verifies the local digest/SHA-256 and a trusted
signed Release.

## Explicit adoption

Adoption requires the exact reported `BACKEND:OBJECT` target. `--plan` performs
all checks and prints the proposed declaration without mutation. `--yes` is a
deployment-locked transaction which:

1. binds online and offline identity evidence to issuer and build identity;
2. verifies the Release and local artifact;
3. classifies database, Valkey, configuration, runtime, backups, and proxy/TLS;
4. rehearses the digest-bound recovery driver in its isolated workspace and
   proves a deployment-bound recovery point, or remains `observed`;
5. creates isolated controller, receipt, audit, and break-glass identities;
6. atomically writes the declaration, receipt, registry, and audit state.

It does not restart, replace, rename, delete, or relabel the manual runtime.
Adoption records only the capability grants explicitly supplied by the user.
The schema-2 recovery evidence manifest proves bounded files, hashes, Release
binding, provider attestation, and off-host placement. Mutation-capable adoption additionally requires
`--lifecycle PATH`. That strict JSON contract binds every discovered runtime by
immutable runtime instance ID and actual object reference, describes neutral
mount/network/port semantics, and names an absolute recovery-driver program plus
its SHA-256. The driver receives a closed request on standard input and returns a
request-bound receipt. It is executed directly, never through a shell. Inline
secrets, unknown environment keys, symlinks, mount overlap with the rehearsal
workspace, incomplete replica sets, and changed driver bytes fail closed.

The rehearsal result must cover every mutable data capability. Only then does ctl
persist controller-owned copies of the recovery package, exact trusted OCI
archives or host binaries, lifecycle contract, adoption receipt, and independent
deployment identities. Failure before this promotion leaves the runtime
unchanged and the deployment `observed`.

## Replicas and shared resources

`deployment_id` is the issuer/control domain. `runtime_instance_id` is one local
replica. Multiple replicas may share a deployment and image digest, while other
deployments on the same machine remain isolated even if names or images match.
Object names are locators only. Ownership checks use the deployment ID, runtime
instance ID, control authority, signed statement, and declared artifact.

Resources separately declare `scope: deployment|shared`. Shared resources are
observed or delegated only within their explicit capability. They are not
reference-counted and deleted speculatively.

## Evidence format for paused external steps

The `transaction evidence` input is strict JSON:

```json
{
  "schema": 1,
  "deployment_id": "deployment-id",
  "transaction_id": "019...",
  "step_id": "recovery-point",
  "kind": "provider-receipt",
  "reference_id": "snapshot-20260803-001",
  "artifact_sha256": "64-lowercase-hex-characters",
  "issued_at": 1785783900
}
```

The file must be a bounded regular non-symlink. Identifiers cannot contain
secret URLs or arbitrary path text. ctl copies a closed accepted-evidence record
into the selected deployment and re-hashes it on resume. The record states that
semantic completion is not claimed; observed acceptance remains mandatory.
