# TLS certificate provider contract

Human output follows the CLI locale and uses readable fields. Place `--json`
before the command to obtain the complete structured result. See
[language and presentation](cli-presentation.md).

This document defines the certificate transaction part of issue #31, including
optional native Nginx/Angie configuration in the same atomic generation.
It is a NazoAuthCtl provider protocol, not a NazoAuth server protocol and not a
claim that NazoAuth Direct TLS capability discovery already exists. The v1
provider is Unix-only because its security contract requires atomic symlink
replacement and owner/mode checks that are not equivalent to portable Windows
filesystem APIs.

## Ownership boundary

The transaction runs on the Unix host that owns a registered deployment. Ctl
verifies the target-helper protocol, deployment identity and current revision.
Selecting an SSH instance is rejected before accessing provider files: local
paths are never interpreted as remote paths. Run the TLS command on the owning
host with its local registry. The provider document is an explicit host-side
delegation; the current fleet model has no `proxy_tls=delegated` registry flag.

The provider owns only the public server certificate and its matching private
key under a deployment-owned secret path. NazoAuth protocol signing keys remain
inside NazoAuth or its configured KMS. Client and wallet private keys remain
with those clients. The reload command is a bounded, root-owned executable
invoked directly with a cleared environment; provider JSON must not contain
secret command arguments.

Each provider document is bound to exactly one deployment tenant/hostname pair.
Ctl does not use that value to select a runtime tenant. It prevents one SNI
material transaction from being replayed against another binding. A global
activation-resource lock serializes live operations, while pending journals are
scanned across deployments so a crashed transaction continues to fence its
`current` pointer until recovery completes.

## Provider JSON

Unknown fields and unknown protocols fail closed. Every path is an absolute,
normalized path. `activation_link` must equal `material_root/current`, and the
material root must not overlap ctl configuration, state, or
break-glass roots. Every existing ancestor of the material root and provider
executables must be root-owned and must not be replaceable by another user.

```json
{
  "schema": 1,
  "protocol": "nazoauthctl.tls.external-generation.v1",
  "tenant": "tenant-a",
  "hostname": "auth.example",
  "material_root": "/etc/nazoauth/tls/tenant-a/auth.example",
  "activation_link": "/etc/nazoauth/tls/tenant-a/auth.example/current",
  "trust_anchors": "/etc/ssl/certs/import-root.pem",
  "public_url": "https://auth.example/health",
  "accepted_statuses": [200],
  "minimum_validity_seconds": 604800,
  "connect_timeout_seconds": 10,
  "request_timeout_seconds": 20,
  "validate": {
    "program": "/usr/sbin/nginx",
    "args": ["-t"]
  },
  "reload": {
    "program": "/usr/bin/systemctl",
    "args": ["reload", "nginx"]
  }
}
```

For a non-root TLS consumer, optionally set `"reader_gid": 10001` to its actual
dedicated service group (the number is an example, not a default). Ctl retains
file ownership, grants group traversal/read on material directories (`0750`)
and read on the installed private key (`0640`). The service cannot write the
key or replace the generation. Without this field, material remains owner-only.
Root-only external imports are accepted in either case; a group-readable key
must use exactly the declared group and mode `0640`. Choose this authority
before the first receipt; changing it later is rejected as provider drift.

On an already configured and running NazoAuth Direct TLS consumer, `validate`
and `reload` may both use the root-owned `/usr/bin/true`: ctl validates material
offline and proves the public identity after the server's automatic reload.
This does not configure or start a service. See
[`tls-deployment.md`](tls-deployment.md) for the transport boundary.

For Angie, use its root-owned configuration-test executable and the matching
service reload command. A dedicated helper may be used, but it and its complete
directory chain must remain root-owned and non-group/world-writable, and the
regular file must have an execute bit. Shell strings are not accepted. The
helper receives only the following bounded contract variables:

- `NAZOAUTHCTL_TLS_PROVIDER_PROTOCOL`
- `NAZOAUTHCTL_TLS_CAPABILITY` (`proxy_tls`)
- `NAZOAUTHCTL_TLS_DEPLOYMENT_ID` and `NAZOAUTHCTL_TLS_DECLARATION_REVISION`
- `NAZOAUTHCTL_TLS_TENANT` and `NAZOAUTHCTL_TLS_HOSTNAME`
- `NAZOAUTHCTL_TLS_JTI`, `NAZOAUTHCTL_TLS_REVISION`, and
  `NAZOAUTHCTL_TLS_EXPIRES_AT`
- `NAZOAUTHCTL_TLS_MATERIAL_SHA256`,
  `NAZOAUTHCTL_TLS_LEAF_CERTIFICATE_SHA256`,
  `NAZOAUTHCTL_TLS_PROVIDER_CONFIG_SHA256`, and
  `NAZOAUTHCTL_TLS_TRUST_ANCHORS_SHA256`
- `NAZOAUTHCTL_TLS_CANDIDATE_DIR` and `NAZOAUTHCTL_TLS_CURRENT_LINK`

The validate command runs before activation. It must inspect the candidate when
the consumer has additional provider-specific rules. The reload command runs
only after ctl atomically replaces `current`.

## Plan, apply, receipt, and recovery

Use the same arguments for plan and apply:

```text
nazoauthctl tls certificate plan \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example \
  --certificate /run/cert-import/fullchain.pem \
  --private-key /run/cert-import/private-key.pem

nazoauthctl tls certificate apply \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example \
  --certificate /run/cert-import/fullchain.pem \
  --private-key /run/cert-import/private-key.pem
```

For the exact current ctl-managed ACME issuance receipt, replace the two material
paths with `--from-acme-current`. The receipt and its private artifacts are
revalidated and bound into the certificate plan, journal, and receipt; an
in-progress issuance, stale deployment declaration, or provider/trust digest
change fails closed. External paths and `--from-acme-current` are mutually
exclusive.

## Native proxy configuration

An optional `native_proxy_program` in the provider names the absolute,
root-owned Nginx or Angie executable. Choose this authority before the first
receipt, just like `reader_gid`. Supply `--proxy-config /secure/proxy.conf` to
every plan/apply for that provider, including ACME-backed renewals. Omitting
either half is rejected; renewal cannot silently drop a managed configuration.

The input is a complete, owner-only UTF-8 native configuration, at most 1 MiB.
Use these exact quoted placeholders in its TLS directives:

```nginx
ssl_certificate "@NAZOAUTH_TLS_CERTIFICATE_FILE@";
ssl_certificate_key "@NAZOAUTH_TLS_PRIVATE_KEY_FILE@";
add_header X-NazoAuth-TLS-Configuration "@NAZOAUTH_TLS_CONFIGURATION_SHA256@" always;
```

Ctl substitutes the generation's certificate paths with native string escaping,
writes `proxy.conf.template` and `proxy.conf` with fsync, and binds the template
digest into the plan, pending transaction and receipt. Its check and recovery
paths verify the template digest and exact rendered bytes. Configuration-only
changes can use the existing certificate; an unchanged certificate/configuration
pair is rejected as already current.

Ctl invokes `native_proxy_program -t -c GENERATION/proxy.conf` in addition to
the provider's validate hook, before switching `current`. The proxy service must
read `material_root/current/proxy.conf` as its main configuration so the existing
reload hook loads that exact generation. Configure a dedicated service/PID and
explicit absolute log, upstream and other runtime paths. Those referenced
resources and the service unit remain operator-owned; the receipt binds the
managed main configuration, not mutable include files or unrelated websites.
Use a self-contained configuration for reproducible configuration receipts.

The reload hook must start/reload this dedicated service when `current` exists
and stop it when the first installation is rolled back and `current` is absent.
The hook must wait for reload completion and retirement of previous workers
before returning; sending SIGHUP alone is asynchronous and can let a previous
worker satisfy a rollback proof before the failed candidate has stopped.
A systemd service with its main configuration set to that path is one option.
It must never reload or stop an unrelated proxy master. The existing hook
ownership, bounded execution and cleared-environment requirements still apply.

The diagnostic header must be returned by the configured public health URL;
locations that override `add_header` must include it too. Ctl requires the
exact template digest from the live HTTPS response before committing, including
configuration-only changes with an unchanged certificate. Duplicate proof
headers are rejected. Keep upstream responses from adding this header.

After activation, the public TLS/health/configuration proof gates the receipt. On
failure, ctl validates the previous native configuration, restores its pointer,
reloads it and verifies the previous public identity. A failed restoration keeps
the pending journal for `tls certificate recover`; a crash does not release the
binding. For a first native generation with no previous configuration, rollback
requires the dedicated public port to refuse connections after the stop hook;
a timeout does not prove successful removal. Keep the previous generation and its service dependencies until that
recovery completes. Switching an existing externally managed proxy to this
layout requires explicit service wiring; ctl does not rewrite a shared proxy
configuration or infer its ownership.

## Readiness and renewal warning

Run the read-only check from an external monitoring scheduler; ctl does not need
to remain running between checks:

```text
nazoauthctl tls certificate check \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example \
  --warning-window-seconds 1209600
```

The check reopens the current provider and receipt, proves the active generation
pointer, independently validates its certificate/private key, requires current
ACME authority when the installed source is ACME, and performs the same bounded
public TLS identity and HTTP health proof used after apply. It succeeds only
when remaining lifetime exceeds the larger of the provider's
`minimum_validity_seconds` and the explicit warning window. Success emits a
deployment/declaration/tenant/hostname/revision/source/digest-bound readiness
document with its own UUIDv7 and a five-minute expiry capped at the renewal
boundary; drift, pending work, public failure, or the renewal window returns a
nonzero process result for monitoring alerting.

Plan is read-only. Both commands re-open bounded regular files and independently
verify the chain against the explicit trust anchors, exact SAN, serverAuth use,
validity window, and certificate/private-key match. Apply then:

1. writes a deployment/tenant/hostname/JTI/revision/digest/expiry-bound journal;
2. writes a unique owner-only generation and fsyncs every file;
3. runs provider validation against that generation;
4. atomically replaces the `current` symlink;
5. requests reload;
6. performs a real public TLS handshake using the configured trust anchors,
   checks the exact leaf DER SHA-256 digest, and requires an explicitly accepted
   HTTP health status;
7. atomically commits the current receipt, or restores and reloads the previous
   generation.

Public verification checks every resolved address (at most four, deduplicated).
A healthy, trusted endpoint that still serves an old leaf is polled within
`request_timeout_seconds`. TLS/HTTP errors fail immediately; a permanently stale
leaf times out and rolls back. Rollback to a previous receipt uses the same
bounded identity proof. Set this timeout above the server's
`TLS_RELOAD_INTERVAL_SECONDS` (default five seconds), to allow asynchronous reload.

The current receipt is the commit marker. A crash before it is written is
recovered by rollback. A crash after it is written is recovered by idempotently
finishing audit/journal finalization:

```text
nazoauthctl tls certificate recover \
  --tenant tenant-a --hostname auth.example
```

Recovery accepts only the exact deployment declaration revision and the exact
previous or committed receipt recorded by the journal. If either changed while
ctl was interrupted, recovery fails closed without invoking an obsolete
provider task; the deployment declaration must first be reconciled by an
operator.

Each committed certificate receipt is written first to an immutable
`receipts/REVISION.json` archive and then to the binding's `receipt.json`
current pointer. If ctl stops between those two durable writes, recovery accepts
the archived receipt only when every journal, source, material, provider,
generation, revision, and expiry binding is exact and that generation is still
active; the current pointer must still be either the exact pre-transaction
receipt or the exact committed receipt. Recovery then restores the current
pointer and finishes the audit record. A rollback likewise refuses an activation
pointer outside the previous and target generations recorded by the journal.
The transaction journal also binds the complete pre-transaction receipt digest,
not only its revision and leaf certificate, so recovery cannot replace a changed
current marker with archived target evidence. Its schema also binds a versioned,
canonical digest of the embedded provider snapshot; changing a validate/reload command,
path, URL, status policy, timeout, or provider binding in a pending journal is
detected before recovery invokes it. Plan and apply require an existing receipt
to match the currently loaded provider configuration and trust-anchor authority.
Conflicting bytes at an occupied revision are never overwritten. A new apply
also refuses an already occupied target revision before staging or activating
material, leaving the interrupted evidence for explicit recovery or review.

The unique generation directory entry is synchronized before activation, in
addition to synchronizing each staged file and the activation symlink. A durable
activation pointer therefore cannot legitimately outlive the generation directory
entry it names after a power loss. Removal of an inactive generation synchronizes
the same parent directory so interrupted cleanup cannot resurrect an orphan entry.

Before rollback changes the activation symlink, ctl securely reopens the previous
generation and repeats the complete offline certificate-chain, SAN, serverAuth,
validity, private-key match, file-permission, source-digest, material-digest, and
provider-authority checks against its receipt. After reload, ctl requires the
activation pointer to name the recorded previous generation and publicly verifies
that exact previous leaf and health status. The failed candidate is deleted only
after those checks succeed.

An interrupted first installation has no previous receipt to prove. In that case,
rollback removes the activation link and reloads, but it is considered complete
only if every bounded public address successfully serves an accepted, trust-valid
TLS endpoint whose leaf is not the candidate. An unavailable endpoint is not proof
of absence: ctl retains the pending journal and inactive candidate for a later
`tls certificate recover` attempt or explicit operator review instead of claiming
that rollback succeeded.

`tls certificate show` prints the authoritative current receipt. Completed
transaction journals and revision receipts remain under the deployment state
directory. The active generation and TLS consumer do not depend on a running ctl
process, so stopping or uninstalling the ctl binary does not stop authentication.

## Lifecycle and compatibility boundary

This contract implements external import, file activation, reload, public
verification, receipt, and crash recovery without inventing a server API.
ACME HTTP-01 issuance is a separate transaction documented in
[`tls-acme-http01.md`](tls-acme-http01.md); its receipt can be supplied to this
provider's plan/apply commands. Current NazoAuth includes atomic server
certificate/key hot reload with last-good retention. It does not reload the
client CA through that same operation; client trust is a separate authority.
Existing `update --config-file --config-schema` owns server configuration
changes and rollback. Readiness follows `TRANSPORT_MODE` while connecting only
to loopback; HTTPS retains SNI and certificate verification.

Installation owns listener ports and material mounts; existing deployments keep
that topology during config updates. Native Nginx/Angie configuration is supplied
as a complete operator-owned template and validated by the selected native
binary. Ctl does not infer routes or runtime tenant/SNI selection.

Compatibility uses the existing target-helper handshake, deployment config schema,
explicit provider protocol, native validation and actual endpoint verification.
The helper handshake does not attest a server transport capability. There is no
additional TLS capability endpoint or NazoAuth version table. A server that cannot
load the selected configuration fails readiness and follows ordinary recovery.
No HTTP fallback is implemented or permitted here.
