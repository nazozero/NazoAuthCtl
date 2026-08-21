# Local OCI candidate installation

`nazoauthctl install` can create a new, declaration-bound standards-full
deployment from an OCI image which is already present in Podman or Docker.
This path exists for an isolated conformance candidate; it is neither an
unsigned `update` nor an adoption of an arbitrary running container.

It is fresh-only. An existing controller config is never converted into this
mode. A retry requires incomplete local-candidate state and the exact original
arguments. It normally has no registered binding; the only exception is the
narrow crash window after this exact candidate declaration/registry binding
was durably written but before candidate completion. That retry proves the
same record first and only completes its recovery evidence—it does not replay
application tasks. A signed, adopted, development, or any other registered
deployment is rejected before candidate work begins.

Use all five candidate options together:

```text
--candidate-image IMAGE
--candidate-release vVERSION
--candidate-revision FULL_LOWERCASE_GIT_SHA
--candidate-build-id source:FULL_LOWERCASE_GIT_SHA
--candidate-oci-digest sha256:LOWERCASE_MANIFEST_DIGEST
```

The candidate path rejects `--to`, the host runtime,
`--external-dependencies`, `--secrets-stdin`, and `--secret-fd`. It requires
the `standards-full` profile and creates controller-managed PostgreSQL, Valkey,
roles, volumes, and root-owned secrets. This is intentional: interrupted
candidate work is restored only from a controller-owned managed backup, never
from an operator-provided endpoint.
Before a migration, key task, or runtime replacement,
the controller resolves the supplied image only from the selected local runtime,
then proves its immutable local image ID, OCI manifest digest, and embedded
release/revision/build ID against the supplied bindings. It never invokes an
image pull on this path.

The exact candidate binding is first persisted as a config sibling intent,
before the fresh controller config is published; the intent can restore that
config after an interruption only for the same five inputs. The immutable local
image ID is then persisted before privileged work. A retry must repeat all five
inputs and resolve the same local object.
Each attempt records a phase, immutable task JTIs, receipt digests, a rollback
backup, and (after initialization) a stopped-writer baseline backup. A task
that was merely started is treated as unknown: ctl quiesces the exact owned
runtime, restores PostgreSQL/Valkey/filesystem snapshots, audits the restore,
rotates the backup and JTI, and retries only as a new attempt. It does not
blindly replay an unknown migration or key task.

Before registration the exact local OCI is exported to a digest-bound package
under the independent recovery root. Registration is permitted only after the
package, baseline marker/checksum, active local image identity, OCI digest,
embedded quartet, readiness, discovery issuer, and the nonce-bound Ed25519
JWS from public `/.well-known/nazoauth-control` all agree with the
descriptor-bound instance public key and deployment statement. The record
therefore carries `RecoveryConclusion::Proven` plus the package and baseline
digest bindings; off-host recovery remains required.

Once completed, this deployment is permanently frozen as that exact candidate.
`update --yes`, development activation, migrations, and capability/provenance
transitions cannot replace its active release or runtime. Conformance,
read-only status/doctor diagnostics, and a safe explicit relinquish remain
available. Promotion to a signed Release is intentionally not implicit and
requires a future explicit promotion transaction.

The digest is the local OCI manifest digest reported by the chosen runtime, not
a mutable image tag and not the local image ID. Retagging `IMAGE` therefore
cannot change a resumed candidate: the stored local image ID, the reported
manifest digest, and the embedded identity must all still match.

This is an isolated candidate recovery boundary, not a signed Release rollback
contract; it never synthesizes an automatic signed-Release rollback. Pending
candidate state blocks conformance, update, development activation, and other
controller mutations. `status` and read-only diagnostics remain available for
evidence. If registration is already visible while the candidate state remains
incomplete, it stays fail-closed for operator recovery rather than silently
running or replacing that deployment. Do not use `development activate`,
`adopt`, or `update` to bypass that binding.
