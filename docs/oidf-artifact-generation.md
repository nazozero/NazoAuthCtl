# OIDF artifact generation

NazoAuthCtl consumes an externally published, signed driver and Matrix. The
artifact publisher owns this OIDF-specific material; NazoAuth remains the
black-box target and does not load it at runtime.

## Trust boundary

Only four identities are needed:

- the reviewed NazoAuthCtl generator commit;
- the source Matrix Git commit and path;
- the OIDF Suite image digest recorded in the signed manifest;
- the artifact signing key selected by its derived key ID.

The manifest signature binds the driver, Matrix, Suite identity and resource
bounds. Repeating their expected SHA-256 values in the generator or a second
provenance file adds no trust: it only makes a legitimate Matrix change require
manual checksum edits. The generator therefore computes content digests once
for the manifest and metadata.

## Generate

Run the generator from a clean checkout at the reviewed commit. The source
repository only has to contain the pinned source commit; its remote name or URL
is not a security boundary.

```sh
set -eu
ctl=/opt/nazoauth-e2e/ctl-source
source_repo=/opt/nazoauth-e2e/source
private=/opt/nazoauth-e2e/oidf-artifact-private
public=/opt/nazoauth-e2e/public/oidf/v5.2.2/current

: "${REVIEWED_CTL_COMMIT:?set the reviewed NazoAuthCtl commit}"
: "${EXPECTED_KEY_ID:?set the selected publisher key ID}"

git -C "$ctl" checkout --detach "$REVIEWED_CTL_COMMIT"
test "$(git -C "$ctl" rev-parse HEAD)" = "$REVIEWED_CTL_COMMIT"
git -C "$ctl" diff --quiet --
git -C "$ctl" diff --cached --quiet --

python3 -I "$ctl/scripts/oidf/generate_oidf_artifact.py" \
  --source-repo "$source_repo" \
  --output "$public" \
  --trust-policy-output "$private/trust-policy.json" \
  --signing-key "$private/signer.pem" \
  --expected-key-id "$EXPECTED_KEY_ID" \
  --reviewed-generator-commit "$REVIEWED_CTL_COMMIT" \
  --source 'https://suite.example/oidf/v5.2.2/current/' \
  --suite-origin 'https://suite.example'
```

The signing key must be an owner-only, non-symlink P-256 private key outside
the public output directory. The generator writes a public trust policy beside
the artifact and an owner-only copy at `--trust-policy-output`.

`--print-derived-metadata` performs the same source transformation without a
signing key or output mutation. It is useful for review, but its computed
digests are observations rather than additional allow-list inputs.

## Verify before use

Generation is not acceptance. Verify the result with the NazoAuthCtl binary
that will run the Suite:

```sh
nazoauthctl oidf artifact verify \
  --trust-policy "$private/trust-policy.json" \
  --manifest "$public/manifest.jws" \
  --driver "$public/driver.json" \
  --matrix "$public/matrix.json" \
  --require nazoauth.client.create
```

Keep the Suite API token and signing key out of Git, command output and public
artifact directories.
