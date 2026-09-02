# OIDF driver and matrix artifacts

The normal user workflow has no artifact configuration:

```text
nazoauthctl oidf configure --tenant-domain oidf.example.com --suite https://suite.example
nazoauthctl oidf run
nazoauthctl oidf run ciba
nazoauthctl oidf run oidc-core-p001
```

The configuration command stores the operator-owned wildcard DNS suffix and
the selected Suite origin once for the selected instance. Neither has a
NazoAuth-owned default. The first run command runs the complete Matrix bundled
in the signed NazoAuthCtl release. The second uses a stable group
alias; the third selects one exact bundled plan. The other aliases are
`oidc`, `fapi`, `openid4vci`, `openid4vp`, and `openid4vc`. Unknown selectors
fail and print the valid aliases, groups, and plans.

NazoAuthCtl automatically creates a temporary tenant below the configured domain,
fresh test material, managed browser workers, and a private evidence directory.
For CIBA, ctl reads the authenticated Suite log and completes the requested
allow or deny action through the same login and CIBA decision endpoints used by
an ordinary tenant user. NazoAuth exposes no conformance-only route. On the
first interactive run ctl securely
prompts for the selected Suite API token and stores it in the platform
credential store. Non-interactive jobs may pipe the token with
`--token-stdin`.

Execution stops at the first Suite failure or ctl automation error. Started
Suite plans are retained and their exact IDs and Suite origin are printed so
the operator can inspect the same records in the Suite UI; plans that never
started are deleted. A CIBA test that explicitly requires uploaded visual
evidence is likewise retained as review pending instead of being reported as
an automated pass.

The remaining commands in this document are maintainer-facing artifact
inspection tools. They do not supply inputs to `oidf run`.

## Ownership and trust

The artifact publisher owns a signed driver manifest and its matrix payload.
For the inspection commands, the controller operator owns a local trust policy. NazoAuth owns protocol keys,
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

Manifest schema 3 is a compact JWS using ES256 with type
`nazoauth-oidf-driver-manifest+jws`. Its strict payload binds:

- artifact ID and immutable 40-character revision;
- trusted source and signer identity;
- issuance, not-before, and exclusive expiry, with a maximum 30-day lifetime;
- exact Suite release, source revision, and OCI image digest;
- driver engine protocol and required capability names;
- declarative driver URL, schema, byte size, and SHA-256 digest;
- matrix URL, schema, byte size, and SHA-256 digest;
- maximum plans, cumulative module/client budgets, and wall-clock duration. The
  validity window must be long enough to contain the full wall-clock bound.

The JWS signs the original payload bytes. The verifier does not reserialize JSON
before checking the signature.

## Declarative driver schema

Driver schema 1 is a signed-by-digest JSON payload consumed by engine protocol
2. It is not native code and has no URL, command, filesystem, credential, or
arbitrary network fields. A bounded handler table selects only controller-owned
operations already covered by the engine: `none`, `browser`, `openid4vci`, or
`openid4vp`, plus either the normal bounded-parallel lane or the serialized
`ciba` lane. A CIBA handler uses the temporary tenant's normal user session and
decision endpoints. Unknown
fields, handlers, operations, or engine protocols fail closed, so publishing a
new plan/handler mapping does not require a controller release while adding a
new host capability does.

## Matrix schema

Schema 2 is declarative. It contains groups, Suite plan names, explicit driver
handler references, variants, config
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
nazoauthctl oidf artifact verify \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --manifest ./manifest.jws \
  --driver ./driver.json \
  --matrix ./matrix.json \
  --require nazoauth.client.create
```

The command reads bounded regular non-symlink files and emits a verified public
identity only after every check succeeds. `--require` values are the
capability set supplied by the caller; this command does not discover or grant
NazoAuth capabilities. Ordinary `oidf run` instead consumes the Matrix bundled
with the ctl release and obtains deployment-bound provider actions and resource
kinds from authenticated capability negotiation. Runner capability strings and
provider authorization are never treated as the same authority. The public
verifier revalidates the complete trust-policy schema,
source, signer identity, public key, and derived key ID even when a library
caller constructs the policy value directly instead of using the file parser.

The local verify command deliberately does not download artifacts, provision
server resources, run the Suite, or clean resources.

## Dynamic HTTPS discovery and immutable cache

```text
nazoauthctl oidf artifact resolve \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --manifest-url https://artifacts.example/oidf/stable/driver.jws \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --require nazoauth.client.create
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
schema 4 contains only deterministic commit identity: the trusted discovery URL
and complete verified artifact. It deliberately does not claim an unauthenticated
first-resolution timestamp. Earlier cache schemas must be re-resolved.
An existing cache created with broader directory modes must be moved to a new
owner-only root or have the root and `artifacts` directory explicitly tightened
by the operator before this version will read or write it.

`manifest.jws`, `driver.json`, and `matrix.json` are individually fsynced and atomically replaced;
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
nazoauthctl oidf artifact open \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --require nazoauth.client.create
```

`--digest` is the exact 64-character lowercase manifest SHA-256. The command
requires the final `verified.json` marker, reads only bounded owner-only regular
files, and performs no network request or cache write. It re-runs signature,
source, current validity, engine protocol, capability, matrix digest, size, and
schema verification, then requires the recomputed identity to equal both the
requested digest and committed record. Missing, incomplete, expired, tampered,
future-dated, untrusted, or capability-incompatible entries fail closed.

As with local verification and discovery, `--require` is an explicit caller
input. Offline opening does not claim that NazoAuth granted or negotiated it.
A deployment-bound runner must pass the set observed from authenticated server
capability negotiation. Deployment-bound run journals, that negotiation,
provisioning, Suite execution, and cleanup remain separate later transactions.

## Offline inspection plan

An operator can compile an exact signed Matrix selection from one revalidated
cache entry without contacting NazoAuth or the Suite:

```text
nazoauthctl oidf artifact plan \
  --trust-policy /etc/nazoauthctl/oidf-trust.json \
  --cache-dir /var/lib/nazoauthctl/oidf-cache \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --require nazoauth.client.create \
  --group oidc \
  --plan p001
```

Planning reuses the exact offline-open verification path; it does not trust the
cache record alone. Group and plan identifiers must be unique, must exist in
the verified Matrix, and their intersection must be non-empty. The emitted
entries bind the artifact identity, Suite plan name, resolved declarative
driver handler/lane, variant, required
capabilities, the caller-declared capability set that allowed verification,
expected `SKIPPED` exceptions, and the verified JSON config template. The
artifact and matrix digests remain the sole byte-level identities; planning
does not create a competing template canonicalization rule. It also sums the
selected signed resource budgets and rejects a selection that cannot finish
strictly before the artifact's exclusive expiry.

Inspection-plan schema 5 is evidence, not an execution authorization. It carries
a plan JTI but deliberately records `deployment_bound: false`,
`capabilities_attested: false`, and `execution_permitted: false`, together with
the authenticated negotiation, ordinary resource provider, target/Suite origin
policy, and deployment-bound crash-safe journal blockers. The `plan` command
creates no NazoAuth resource, Suite plan, execution journal, or cleanup
obligation. It is not an input to ordinary `oidf run`, whose Matrix and driver
are part of the ctl release. Resource budgets remain contract ceilings enforced
against selected Suite modules, created clients, and elapsed time.

Schema 5 also binds the delivery contract to
`nazoauthctl-bounded-plan-runner-v1`, the existing runner whose behavior tests
cover a frozen plan denominator, worker-owned automation state, a maximum of
four jobs, a global serialized CIBA lane, stop-launching on fatal failure,
failure collection, and finally cleanup. Every selected plan receives a unique
task JTI for client/state/evidence ownership. A multi-plan selection
requires at least two jobs and permits at most the runner's existing bound;
there is no second scheduler and the release stage must not downgrade the full
matrix to serial execution. Only authenticated execution authorization can set
`execution_permitted: true`.

The run evidence sink commits each run into a unique owner-only directory with
a manifest-last digest envelope, and preserves structured output when outer
cleanup fails. Control evidence binds every operation to its operation ID,
canonical request hash, typed result, revision, and manifest transition, and
proves cleanup back to the enumerated baseline. Suite outcomes and controller
evidence remain distinct facts; neither is presented as a Suite signature.

Before ordinary Apply, `oidf run` durably stores the exact
`ControlOperation`, canonical request hash, and private manifest path. Response
loss replays that same operation. Cleanup first enumerates the run identities,
then issues a digest-bound Revoke, persists each typed terminal result, and
removes the private manifest only through the journal's deletion-intent state
machine. mTLS trust is an ordinary tenant resource; ingress forwards the RFC
9440 client-certificate header and no per-run proxy trust file is installed.
