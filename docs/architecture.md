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
used, the provider must atomically install the active run's public CA bundle
before Suite modules are created and restore the previous bundle during the same
cleanup transaction. Such runs are serialized unless they have independent
listeners and bundles. Private keys never cross this boundary.

For a file-backed provider, `conformance run` accepts the paired
`--proxy-trust-bundle` and `--proxy-reload-executable` options. The materializer
supplies only generated public client CAs. ctl atomically installs that bundle,
invokes a root-owned reload executable, and restores a sibling recovery copy
after Suite and ordinary-resource cleanup. Supplying only one option fails before proxy,
deployment, or Suite mutation.

## Conformance outcome evidence

The conformance report keeps local execution and official Suite outcomes as
separate facts. `local_success` means that ctl completed orchestration, evidence
collection, and cleanup without a local error. It is not a protocol result.
`suite_pass` is true only when at least one module was defined and every defined
module reached the Suite's exact `FINISHED` / `PASSED` result without warning or
failure conditions.

`REVIEW`, `WARNING`, `SKIPPED`, failed, and incomplete modules remain distinct
module outcomes and are listed separately in report schema 3. A signed Matrix
may explain an expected `SKIPPED` result, but the explanation never promotes it
to `PASSED`. Live progress uses the same outcome classification, so review and
skipped modules are not counted or rendered as passed. The CLI's final success
still requires local success, Suite pass, and deployment cleanup completion.

When `--evidence-dir` is supplied, ctl creates a new owner-only `run-<JTI>`
directory instead of reusing module filenames from an earlier run. Every raw
module file carries the run and module identity. `report.json` and all raw
module files are digest-bound by `manifest.json`, which is fsynced and written
last as the commit marker. A crash can therefore leave only an explicitly
uncommitted directory; it cannot make a partial set look complete or mix old
modules into a new run. The manifest also binds the immutable deployment
release/revision/build/runtime digest, Matrix source, Suite origin, and outer
resource/proxy cleanup result. This is ctl-generated integrity evidence, not a
Suite signature; signed Suite evidence remains an external release-stage
requirement.

`--capture-review-screenshots` is an explicit, local-only companion to
`--evidence-dir`. It recognizes only signed browser commands marked
`update-image-placeholder` or `update-image-placeholder-optional`; it never
calls a Suite image API. A required marker fails local orchestration if a
bounded W3C PNG screenshot cannot be captured, while an optional marker is
reported as missing and execution continues with the next signed task. A
normal capture is accepted only on the canonical Suite
`/test/a/{module-id}/…` page for its newly-created module. OpenID4VP required
captures first create with a caller-owned stable create JTI; a lost network
response retries the exact canonical request and validates the echoed JTI and
normalized-request digest before the same browser lane's actual signed-entry
selection attaches exact new plan/module context. They then complete the
protocol before issuing a
same-module, runtime-signed verification receipt and one-time NazoAuthWeb
result view at
`/ui/verification-result#receipt=…`; ctl verifies its non-secret DOM binding
before capture and never records the fragment capability. The capability is
issued only after protocol completion. Attachment is authenticated by the
runtime-discovery key: ctl checks the signed intent's issuer, audience, tenant,
transaction, exact evidence context, presentation request digest, and trust
policy binding before generating one stable issuance JTI. Retried issuance
requests reuse that JTI, so a lost response cannot silently rotate the browser
capability. The durable screenshot receipt retains only the signed JWS and its
non-secret tenant/runtime/key/context/binding/intent/capability hashes; recovery
reverifies it under the journal-owned runtime key. The capability is deliberately
not recoverable: a
process crash before the new module becomes terminal fails that module and
uses the ordinary exact cleanup path. PNG input is capped
at 500 KiB and fully decoded with bounded dimensions, pixels, and output before
it is written owner-only under `review-screenshots/`. The root-private capture
manifest is also the local, module-bound manual-upload list: it binds the run,
artifact/Matrix digests, Suite origin, exact plan/module IDs, test/variant,
capture source, and required/captured/missing obligations. It never POSTs an
image to the Suite. Retained plans bind its path and SHA-256 into the recovery
journal and reverify it before publication. Module reports contain only the
relative path, SHA-256, and size. Existing terminal Suite modules are never
targeted: a retained plan must be repeated to collect new local evidence, which
can then be attached manually in the official UI.

For the OpenID4VP deferred verification-evidence boundary documented by
[OIDF Suite MR !2100](https://gitlab.com/openid/conformance-suite/-/merge_requests/2100), a
capture-and-retain run may instead record a typed `deferred_review_pending`
module. This requires one actually selected signed required
`verification-evidence` marker, a verified NazoAuthWeb result capture, and a
fresh exact Suite `WAITING` state for that same module. It is neither a Suite
terminal result nor a pass/certification claim: reports keep
`acceptance_pass=false` and `review_pending=true`. The retention manifest
persists the exact plan/module/placeholder identity and capture-manifest hash
for controlled operator action later; ctl does not upload an image, mark a
browser URL visited, or modify an existing retained plan.

Final output schema 2 preserves a completed `RunOutput` even when resource,
proxy, or evidence cleanup fails. Such failures are listed in `errors`, keep
`success: false`, and leave `deployment.cleanup_complete: false`; they are no
longer converted into an unstructured error that discards the collected Suite
report.

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
