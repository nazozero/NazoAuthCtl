# Signed OIDF driver and matrix artifacts

This contract separates OIDF conformance data from both the NazoAuth server
Release and the NazoAuthCtl Release. It is the trust boundary for future
dynamic discovery; it is not a NazoAuth management API and it does not execute
the Suite.

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

This phase deliberately does not download artifacts, provision server
resources, run the Suite, or clean resources. Dynamic HTTPS discovery and
crash-safe run journals are separate transactions layered on this verifier so
network retrieval cannot weaken the local trust decision.
