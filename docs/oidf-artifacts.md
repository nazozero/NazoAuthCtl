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

`key_id` is derived from the first 32 lowercase hexadecimal characters of the
SHA-256 digest of the compressed SEC1 public key. The source is an exact,
normalized HTTPS directory. Credentials, query strings, fragments, encoded
path segments, cross-origin matrix URLs, unknown fields, and an inconsistent
key ID fail closed. On the Unix control host, the trust policy and its final
directory must be owner-only; the manifest and matrix may be public but must
still be stable, non-symlink, non-world-writable files owned by the caller or
root.

## Signed driver manifest

The manifest is a compact JWS using ES256 with type
`nazoauth-oidf-driver-manifest+jws`. Its strict payload binds:

- artifact ID and immutable 40-character revision;
- trusted source and signer identity;
- issuance, not-before, and expiry, with a maximum 30-day lifetime;
- exact Suite release, source revision, and OCI image digest;
- driver engine protocol and required capability names;
- matrix URL, schema, byte size, and SHA-256 digest;
- maximum plans, modules, clients, and wall-clock duration.

The JWS signs the original payload bytes. The verifier does not reserialize JSON
before checking the signature.

## Matrix schema

Schema 1 is declarative. It contains groups, Suite plan names, variants, config
templates, required capability names, and exact expected `SKIPPED` module
exceptions. It cannot contain executable native plugins.

Sensitive fields such as passwords, tokens, client secrets, or private keys
must be exact placeholders in one of the `target`, `suite`, `resource`, or
`run` namespaces. Literal sensitive material is rejected. `REVIEW` and
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
verifier.

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

Verified bytes are stored under the driver manifest digest in an owner-only
cache. `driver.jws` and `matrix.json` are individually fsynced and atomically
replaced. `verified.json` is written last and is the commit marker. A cache hit
requires the committed manifest, matrix, URL, and verified identity to match
the newly fetched and verified artifact exactly. Conflicting committed content
fails closed; it is never overwritten as a recovery shortcut.

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
does not create a competing template canonicalization rule.

This output is inspection evidence, not an execution authorization. It carries
a plan JTI but deliberately records `deployment_bound: false`,
`capabilities_attested: false`, and `execution_permitted: false`, together with
the missing authenticated negotiation, ordinary resource provider, and
deployment-bound crash-safe journal blockers. The command creates no NazoAuth
resource, Suite plan, execution journal, or cleanup obligation.
