# TLS certificate provider contract

This document defines the first independently deployable part of issue #31: an
external certificate import transaction for an already configured TLS consumer.
It is a NazoAuthCtl provider protocol, not a NazoAuth server protocol and not a
claim that NazoAuth Direct TLS capability discovery already exists. The v1
provider is Unix-only because its security contract requires atomic symlink
replacement and owner/mode checks that are not equivalent to portable Windows
filesystem APIs.

## Ownership boundary

The transaction is available only for an adopted deployment whose `proxy_tls`
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
  "public_url": "https://auth.example/health/ready",
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
nazoauthctl --deployment DEPLOYMENT tls certificate plan \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example \
  --certificate /run/cert-import/fullchain.pem \
  --private-key /run/cert-import/private-key.pem

nazoauthctl --deployment DEPLOYMENT tls certificate apply \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example \
  --certificate /run/cert-import/fullchain.pem \
  --private-key /run/cert-import/private-key.pem --yes
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
nazoauthctl --deployment DEPLOYMENT tls certificate check \
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
nazoauthctl --deployment DEPLOYMENT tls certificate recover \
  --tenant tenant-a --hostname auth.example --yes
```

Recovery accepts only the exact deployment declaration revision and the exact
previous or committed receipt recorded by the journal. If either changed while
ctl was interrupted, recovery fails closed without invoking an obsolete
provider task; the deployment declaration must first be reconciled by an
operator.

`tls certificate show` prints the authoritative current receipt. Completed
transaction journals and revision receipts remain under the deployment state
directory. The active generation and TLS consumer do not depend on a running ctl
process, so stopping or uninstalling the ctl binary does not stop authentication.

## Current boundary and later phases

This contract closes external import, file activation, reload, public
verification, receipt, and crash recovery without inventing a server API.
ACME HTTP-01 issuance is a separate transaction documented in
[`tls-acme-http01.md`](tls-acme-http01.md); its receipt can be supplied to this
provider's plan/apply commands. Direct TLS configuration/reload,
trusted-proxy/internal transport changes, and Nginx/Angie configuration
generation remain blocked on the dynamic
NazoAuth capability/protocol work tracked by NazoAuth #127/#128/#129 and parent
#130. Those later operations must negotiate capabilities at runtime; they must
not infer compatibility from a NazoAuth release number. No HTTP fallback is
implemented or permitted here.
