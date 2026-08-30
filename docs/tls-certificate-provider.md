# TLS certificate provider contract

This document defines the first independently deployable part of issue #31: an
external certificate import transaction for an already configured TLS consumer.
It is a NazoAuthCtl provider protocol, not a NazoAuth server protocol and not a
claim that NazoAuth Direct TLS capability discovery already exists. The v1
provider is Unix-only because its security contract requires atomic symlink
replacement and owner/mode checks that are not equivalent to portable Windows
filesystem APIs.

## Ownership boundary

The transaction is available only for a registered current-protocol deployment whose `proxy_tls`
capability is explicitly `delegated` or `managed`. A fresh ctl installation
leaves that capability external, so TLS material cannot be changed accidentally.

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
owner-only material root must not overlap ctl configuration, state, or
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

## Current boundary and later phases

This contract closes external import, file activation, reload, public
verification, receipt, and crash recovery without inventing a server API.
ACME HTTP-01 issuance is a separate transaction documented in
[`tls-acme-http01.md`](tls-acme-http01.md); its receipt can be supplied to this
provider's plan/apply commands. NazoAuth PR #131 established the server's Direct
TLS transport baseline and #127 is closed, but that stage explicitly does not
provide atomic certificate/trust reload with last-known-good rollback or real
trusted-proxy parity. It also is not an authenticated machine-management
protocol for this controller. Direct TLS configuration/reload,
trusted-proxy/internal transport changes, multi-tenant authority, and
Nginx/Angie configuration generation therefore remain outside this provider
contract and depend on the ordinary capability/protocol work tracked by
NazoAuth #128/#129 and parent #130. Those later operations must negotiate
capabilities at runtime; they must not infer compatibility from an issue state
or a NazoAuth release number. No HTTP fallback is implemented or permitted
here.
