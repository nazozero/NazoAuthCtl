# ACME HTTP-01 issuance contract

This contract is the certificate-issuance part of NazoAuthCtl issue #31. It
creates deployment-owned public-server certificate material without changing a
TLS consumer. Installation, reload, public verification, and rollback remain the
separate `tls certificate` transaction. A stopped controller is therefore not
on the authentication serving path.

## Ownership and prerequisites

The selected deployment must delegate or manage `proxy_tls`. NazoAuthCtl owns
the ACME account key and the issued server private key under its private
deployment state. NazoAuth protocol signing keys remain in NazoAuth or its KMS;
client and wallet private keys remain client-side.

Only an exact DNS hostname is accepted. Wildcards and IP identifiers fail
closed. HTTP-01 requires an existing, non-symlink webroot already served as
`http://HOST/.well-known/acme-challenge/TOKEN` by an independently configured
HTTP listener. NazoAuthCtl neither opens port 80 nor edits Nginx/Angie
configuration in this phase.

The TLS provider document supplies the certificate-chain trust anchors and
minimum-validity policy used for offline validation of the final material. Its
installation commands are not run during issuance.

## Strict configuration

Unknown fields, protocols, bindings, unsafe paths, non-HTTPS directory/TOS URLs,
non-mailto contacts, wildcard hostnames, and out-of-range timeouts fail closed.
Every ACME HTTP request is also restricted to an explicit operator-owned set of
canonical HTTPS origins. This is a transport boundary, so it covers directory,
nonce, account, order, authorization, challenge, finalize and certificate URLs
returned dynamically by the ACME server.

```json
{
  "schema": 2,
  "protocol": "nazoauthctl.acme.http01-webroot.v2",
  "tenant": "tenant-a",
  "hostname": "auth.example",
  "directory_url": "https://acme.example/directory",
  "allowed_origins": ["https://acme.example"],
  "terms_of_service_url": "https://acme.example/terms",
  "contacts": ["mailto:security@example.com"],
  "challenge_webroot": "/var/www/acme/.well-known/acme-challenge",
  "directory_trust_anchor": null,
  "poll_timeout_seconds": 120,
  "transaction_ttl_seconds": 900
}
```

`allowed_origins` contains one to eight exact origins such as
`https://acme.example` or `https://acme.example:8443`; paths, credentials,
queries, fragments, duplicates and non-canonical spellings are rejected. The
configured directory origin must be present. ACME permits server-provided
resources on different origins, so a CA that uses them must list each origin
explicitly instead of relying on an implicit same-origin exception. Literal
private or loopback origins can be listed for a private test CA, but doing so
expands that deployment's network authority. This is an application authority
boundary, not a replacement for an egress firewall: an allowed DNS hostname is
still resolved by the host's configured resolver.

`directory_trust_anchor` is optional and intended for a private/test ACME
directory. When present, the certificate is validated and copied into the
transaction workspace; recovery uses only the digest-bound snapshot. The TLS
provider configuration and its certificate trust anchors are snapshotted in the
same way.

## Plan, issue, and recovery

```text
nazoauthctl --deployment DEPLOYMENT tls acme plan \
  --acme-config /etc/nazoauth/acme.json \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example

nazoauthctl --deployment DEPLOYMENT tls acme issue \
  --acme-config /etc/nazoauth/acme.json \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example --agree-terms --yes

nazoauthctl --deployment DEPLOYMENT tls acme recover \
  --tenant tenant-a --hostname auth.example --yes
```

`--agree-terms` is mandatory and refers to the exact configured TOS URL. Issue:

1. binds deployment, declaration and issuance revisions, tenant, hostname,
   capability, JTI, configuration/trust digests, allowed ACME origins, and
   expiry in a durable journal;
2. persists and journal-binds the ACME account key before network use, then
   creates or restores the configuration-bound account with that same key;
3. creates or resumes one exact-identifier order by its server-issued URL;
4. journals the HTTP-01 path and digest before atomically publishing it;
5. persists the server key and CSR before finalizing the order;
6. writes the returned chain and verifies chain, exact SAN, serverAuth usage,
   validity window, and private-key match offline;
7. commits a receipt, retires only the exact digest-bound challenge file, appends
   the management audit record, and removes the pending journal.

Each receipt is committed to a conflict-checked revision archive before the
binding's `current.json` pointer is replaced. Later renewals therefore cannot
erase the exact receipt bytes referenced by an installation receipt.

A failure preserves the journal and evidence while retiring the challenge when
its content still matches the bound digest. `recover` resumes the same account
and order from private snapshots. An expired transaction is recorded as
aborted, its challenge is retired, and its pending lock is removed so a new
attempt can proceed. A crash after receipt commit is finalized idempotently.
Recovery reconstructs the HTTP client from the digest-bound configuration and
trust-anchor snapshots; a server-provided URL outside the recorded origin set
is rejected before DNS resolution, connection, or account-signed JWS delivery.

`tls acme show` reports the pending journal and current issuance receipt. Consume
that authority directly without copying private state paths:

```text
nazoauthctl --deployment DEPLOYMENT tls certificate plan \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example --from-acme-current

nazoauthctl --deployment DEPLOYMENT tls certificate apply \
  --provider-config /etc/nazoauth/tls-provider.json \
  --tenant tenant-a --hostname auth.example --from-acme-current --yes
```

The certificate transaction refuses a pending issuance, a stale declaration
revision, provider/trust digest drift, receipt or private-artifact tampering, or
any mismatch between the receipt and its independent offline PKI validation.
The issuance receipt identity is then carried through the installation plan,
journal, public-verification receipt, and recovery checks. Issuance itself does
not claim that any live endpoint changed certificates.

## Verification boundary

The ACME server performs the authoritative public HTTP-01 fetch. This phase does
not claim a local loopback request proves public reachability. It also does not
configure Direct TLS, Nginx/Angie, trusted proxy headers, or NazoAuth transport
capabilities. Those operations require the dynamically negotiated NazoAuth
capabilities tracked by NazoAuth #127/#128/#129 and #130.
