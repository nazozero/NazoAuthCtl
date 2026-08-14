# Signed OIDF driver and matrix artifacts

This contract separates OIDF conformance data from both the NazoAuth server
Release and the NazoAuthCtl Release. It is not a NazoAuth management API and it
does not execute the Suite.

## Ownership and trust

The artifact publisher owns a signed driver manifest and its matrix payload.
The controller operator owns a local trust policy. NazoAuth owns protocol keys,
tenant resolution, clients, users, and trust state. The Suite-side driver owns
test client and wallet private keys. Artifact verification never transfers any
of those private keys.

The trust policy is strict JSON:

```json
{
  "schema": 1,
  "source": "https://artifacts.example/oidf/",
  "signer_identity": "https://github.com/example/oidf-driver/.github/workflows/release.yml@refs/tags/v1.2.3",
  "key_id": "oidf-es256-0123456789abcdef0123456789abcdef",
  "public_key_sec1": "base64url-compressed-P-256-public-key"
}
```

Trust-policy schema 1 has an independent lifecycle from the signed artifact and
Matrix schemas. Upgrading publisher-owned artifact data therefore does not
silently require an unchanged operator trust policy to change versions.

`key_id` is derived from the first 32 lowercase hexadecimal characters of the
SHA-256 digest of the compressed SEC1 public key. The source is an exact,
normalized HTTPS directory. Credentials, query strings, fragments, encoded
path segments, cross-origin matrix URLs, unknown fields, and an inconsistent
key ID fail closed. On the Unix control host, the trust policy and its final
directory must be owner-only; the manifest and matrix may be public but must
still be stable, non-symlink, non-world-writable files owned by the caller or
root.

## Signed driver manifest

Manifest schema 2 is a compact JWS using ES256 with type
`nazoauth-oidf-driver-manifest+jws`. Its strict payload binds:

- artifact ID and immutable 40-character revision;
- trusted source and signer identity;
- issuance, not-before, and exclusive expiry, with a maximum 30-day lifetime;
- exact Suite release, source revision, and OCI image digest;
- driver engine protocol and required capability names;
- matrix URL, schema, byte size, and SHA-256 digest;
- maximum plans, cumulative module/client budgets, and wall-clock duration. The
  validity window must be long enough to contain the full wall-clock bound.

The JWS signs the original payload bytes. The verifier does not reserialize JSON
before checking the signature.

## Matrix schema

Schema 2 is declarative. It contains groups, Suite plan names, variants, config
templates, required capability names, and exact expected `SKIPPED` module
exceptions. Every plan declares module, client, and wall-clock budgets; the
verifier safely sums them and rejects a Matrix above any signed manifest bound.
Expected skip exceptions cannot outnumber the plan's module budget.
It cannot contain executable native plugins.

Sensitive fields such as passwords, tokens, client secrets, or private keys
must be exact placeholders in one of the `target`, `suite`, `resource`, or
`run` namespaces. Field matching normalizes ASCII case and separators, and the
same rule applies to group/plan variants. Serialized JSON secrets and private
key PEM blocks are also rejected; public structured JWK values remain possible
only when they contain no private or symmetric key members. `REVIEW` and
`WARNING` cannot be pre-approved by the matrix, and `SKIPPED` remains a distinct
classification rather than a pass.

## Local verification boundary

```text
nazoauthctl conformance artifact verify \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --manifest ./driver.jws \
  --matrix ./matrix.json \
  --capability nazoauth.client.create
```

The command reads bounded regular non-symlink files and emits a verified public
identity only after every check succeeds. `--capability` values are the
capability set supplied by the caller; this command does not discover or grant
NazoAuth capabilities. A future deployment-bound runner must obtain them from
authenticated capability negotiation and pass that observed set to the same
verifier. The public verifier revalidates the complete trust-policy schema,
source, signer identity, public key, and derived key ID even when a library
caller constructs the policy value directly instead of using the file parser.

The local verify command deliberately does not download artifacts, provision
server resources, run the Suite, or clean resources.

## Dynamic HTTPS discovery and immutable cache

```text
nazoauthctl conformance artifact resolve \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --manifest-url https://artifacts.example/oidf/stable/driver.jws \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --capability nazoauth.client.create
```

The stable channel URL must be below the trusted source. The client accepts
HTTPS only, sends no credentials, follows no redirect, applies connection and
whole-request timeouts, and bounds the response before parsing. It verifies the
driver signature, source, expiry, engine protocol, and capabilities before it
uses the signed matrix URL. The matrix download is then bounded by the signed
byte size and accepted only after exact digest and schema validation.

Verified bytes are stored under the driver manifest digest. The cache root,
`artifacts` directory, digest entry, lock, and files are all owner-only. A
stable cache-wide lock serializes writers for at most ten seconds. Cache record
schema 3 contains only deterministic commit identity: the trusted discovery URL
and complete verified artifact. It deliberately does not claim an unauthenticated
first-resolution timestamp. Schema 2 entries must be re-resolved.
An existing cache created with broader directory modes must be moved to a new
owner-only root or have the root and `artifacts` directory explicitly tightened
by the operator before this version will read or write it.

`driver.jws` and `matrix.json` are individually fsynced and atomically replaced;
`verified.json` is written and directory-fsynced last as the commit marker. A
cache hit requires the committed manifest, matrix, URL, and complete record to
match the newly fetched and verified artifact exactly. Conflicting committed
content fails closed; it is never overwritten as a recovery shortcut.

The cache accepts at most 64 digest entries and refuses a write unless the
filesystem will retain at least 512 MiB after the bounded manifest, Matrix, and
record are written. It never evicts committed evidence automatically, so every
entry is effectively recovery-pinned. An incomplete crash entry counts toward
the limit and requires explicit operator inspection/removal instead of being
silently treated as disposable evidence.

The cache is evidence and recovery input, not a new trust root. Resolution
still verifies the current signed channel and validity window. Offline cache
selection is therefore exact and has no moving alias:

```text
nazoauthctl conformance artifact open \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --capability nazoauth.client.create
```

`--digest` is the exact 64-character lowercase manifest SHA-256. The command
requires the final `verified.json` marker, reads only bounded owner-only regular
files, and performs no network request or cache write. It re-runs signature,
source, current validity, engine protocol, capability, matrix digest, size, and
schema verification, then requires the recomputed identity to equal both the
requested digest and committed record. Missing, incomplete, expired, tampered,
future-dated, untrusted, or capability-incompatible entries fail closed.

As with local verification and discovery, `--capability` is an explicit caller
input. Offline opening does not claim that NazoAuth granted or negotiated it.
A deployment-bound runner must pass the set observed from authenticated server
capability negotiation. Deployment-bound run journals, that negotiation,
provisioning, Suite execution, and cleanup remain separate later transactions.

## Offline inspection plan

An operator can compile an exact signed Matrix selection from one revalidated
cache entry without contacting NazoAuth or the Suite:

```text
nazoauthctl conformance artifact plan \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --capability nazoauth.client.create \
  --group oidc \
  --plan p001
```

Planning reuses the exact offline-open verification path; it does not trust the
cache record alone. Group and plan identifiers must be unique, must exist in
the verified Matrix, and their intersection must be non-empty. The emitted
entries bind the artifact identity, Suite plan name, variant, required
capabilities, the caller-declared capability set that allowed verification,
expected `SKIPPED` exceptions, and the verified JSON config template. The
artifact and matrix digests remain the sole byte-level identities; planning
does not create a competing template canonicalization rule. It also sums the
selected signed resource budgets and rejects a selection that cannot finish
strictly before the artifact's exclusive expiry.

Inspection-plan schema 3 is evidence, not an execution authorization. It carries
a plan JTI but deliberately records `deployment_bound: false`,
`capabilities_attested: false`, and `execution_permitted: false`, together with
the missing signed executable driver/runtime sandbox, authenticated
negotiation, ordinary resource provider, target/Suite origin policy, and
deployment-bound crash-safe journal blockers. The command creates no NazoAuth
resource, Suite plan, execution journal, or cleanup obligation. Signed budgets
are contract ceilings, not proof of runtime enforcement; a future runner must
enforce them against observed Suite modules, created clients, and elapsed time.
