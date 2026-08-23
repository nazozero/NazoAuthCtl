# Reproducible OIDF artifact generation

The OIDF release artifact is generated only on the isolated Hostinger validation host. The
generator is pinned to one NazoAuth Git commit, one matrix path and one Git blob. It also
checks the expected driver and matrix digests, byte sizes, artifact revision and resource
bounds before writing any output. A changed source or transform therefore fails closed.

## Git-only source preparation

Project files move between the workstation and Hostinger only through Git. Fetch the exact
NazoAuthCtl and NazoAuth commits into checkouts below the task prefix; do not use `scp`, copied
archives or files from an earlier candidate run.

```sh
set -eu
prefix=/opt/nazoauth-e2e/candidate-deps-oidf-20260820T1300Z
ctl="$prefix/source/v4/nazoauthctl"
nazo="$prefix/source/v6/nazoauth"

: "${REVIEWED_CTL_COMMIT:?set this from the independently reviewed task evidence}"
test "${#REVIEWED_CTL_COMMIT}" -eq 40
case "$REVIEWED_CTL_COMMIT" in *[!0-9a-f]*) exit 2;; esac

git -C "$ctl" fetch origin agent/oidf-vci-skip-amendment-20260821
git -C "$ctl" cat-file -e "$REVIEWED_CTL_COMMIT^{commit}"
git -C "$ctl" merge-base --is-ancestor "$REVIEWED_CTL_COMMIT" FETCH_HEAD
git -C "$ctl" checkout --detach "$REVIEWED_CTL_COMMIT"
test "$(git -C "$ctl" rev-parse HEAD)" = "$REVIEWED_CTL_COMMIT"

git -C "$nazo" fetch origin agent/spec-coverage-audit-20260820
git -C "$nazo" checkout --detach 45959681bf1a093793f5d23cd78f583862b8b167
test "$(git -C "$nazo" rev-parse HEAD)" = 45959681bf1a093793f5d23cd78f583862b8b167
git -C "$nazo" cat-file -e 77c362f9fc62e5114f3c61e2b4420f864d7112ab^{commit}
```

Record `REVIEWED_CTL_COMMIT` with the generated evidence. Its value comes from the independent
review/task evidence, never from the moving branch itself. The generator independently requires
the NazoAuth checkout's `origin` to be
`https://github.com/nazozero/NazoAuth.git` and reads the source matrix with native Git object
commands, not from the checked-out filesystem.

`--reviewed-generator-commit` is also mandatory at runtime. Before touching any output, the
generator locates its Ctl Git root from `__file__`, requires exact `HEAD`, clean tracked/index
state, and matches the current generator and provenance Git blobs to that reviewed commit.
Invoke it with Python isolated mode so the script directory, working directory, user site and
`PYTHONPATH` cannot shadow its standard-library imports.

## Reviewed matrix amendments and metadata derivation

At Suite revision `321bc5bc53601b9690b54c023c0cbfac0f0230f2`,
`VCIIssuerFailOnUnsupportedEncryptionAlgorithm.start()` calls `fireTestSkipped(...)` and returns
when `vci_credential_encryption` is not `encrypted`. The pinned NazoAuth source blob declares
`plain` for plans `openid4vc-vci-p028`, `openid4vc-vci-p031` and `openid4vc-vci-p032`. The
generator therefore adds exactly one `SKIPPED` expectation for that Suite module to each of
those plans. It fails closed if a plan is missing or duplicated, its variant is not `plain`, or
the module already has a different expected result.

Before changing the pinned output constants, derive the amended deterministic metadata only on
Hostinger from the exact independently reviewed commit. This mode still verifies the generator
HEAD, clean checkout and committed blobs, pinned provenance, NazoAuth origin/commit/blob and all
three amendment preconditions. It rejects signing/output arguments, does not read a signing key
and does not create an output directory or artifact file.

```sh
set -eu
prefix=/opt/nazoauth-e2e/candidate-deps-oidf-20260820T1300Z
ctl="$prefix/source/v4/nazoauthctl"
nazo="$prefix/source/v6/nazoauth"

: "${REVIEWED_CTL_COMMIT:?set this to the exact reviewed amendment commit}"
test "${#REVIEWED_CTL_COMMIT}" -eq 40
case "$REVIEWED_CTL_COMMIT" in *[!0-9a-f]*) exit 2;; esac

git -C "$ctl" fetch origin agent/oidf-vci-skip-amendment-20260821
git -C "$ctl" cat-file -e "$REVIEWED_CTL_COMMIT^{commit}"
git -C "$ctl" checkout --detach "$REVIEWED_CTL_COMMIT"
test "$(git -C "$ctl" rev-parse HEAD)" = "$REVIEWED_CTL_COMMIT"

python3 -I "$ctl/scripts/oidf/generate_oidf_artifact.py" \
  --nazoauth-repo "$nazo" \
  --reviewed-generator-commit "$REVIEWED_CTL_COMMIT" \
  --print-derived-metadata
```

The JSON result contains the computed driver and matrix SHA-256 digests and byte sizes, artifact
revision, resource bounds and `expected_match`. The reviewed final generator pins the Hostinger-
derived values in both the generator and provenance, so `expected_match` must be `true`. A false
value is output drift; normal signing mode enforces the same constants and fails closed before it
reads the signing key or mutates an output path.

## Private inputs and output layout

Provision the signing key out of band. The generator never creates or rotates it. The key must
already be a non-symlink regular file owned by the invoking Unix user with no group or other
permissions. The private trust-policy directory must likewise already exist, be owned by that
user and be owner-only.

Neither the signing key nor the Suite API token belongs in Git, command output, evidence logs or
the public artifact directory. Pass the expected public key ID explicitly so an accidental key
replacement cannot silently establish a new trust root. The trust policy contains public data;
the generator writes the same bytes to the public artifact and atomically to the operator's
owner-only path with mode `0600`.

```sh
set -eu
prefix=/opt/nazoauth-e2e/candidate-deps-oidf-20260820T1300Z
ctl="$prefix/source/v4/nazoauthctl"
nazo="$prefix/source/v6/nazoauth"
private="$prefix/state/oidf-artifact-private"
public="$prefix/evidence/oidf-artifact-public"

: "${REVIEWED_CTL_COMMIT:?set this from the independently reviewed task evidence}"
test "${#REVIEWED_CTL_COMMIT}" -eq 40
case "$REVIEWED_CTL_COMMIT" in *[!0-9a-f]*) exit 2;; esac

install -d -m 0700 "$private"
# Provision $private/signer.pem out of band, then enforce:
chmod 0600 "$private/signer.pem"

test "$(git -C "$ctl" rev-parse HEAD)" = "$REVIEWED_CTL_COMMIT"
git -C "$ctl" diff --quiet --
git -C "$ctl" diff --cached --quiet --
ctl_status=$(git -C "$ctl" status --porcelain=v1 --untracked-files=all)
test -z "$ctl_status"

python3 -I "$ctl/scripts/oidf/generate_oidf_artifact.py" \
  --nazoauth-repo "$nazo" \
  --output "$public" \
  --trust-policy-output "$private/trust-policy.json" \
  --signing-key "$private/signer.pem" \
  --expected-key-id 'oidf-es256-REPLACE_WITH_PREAPPROVED_KEY_ID' \
  --reviewed-generator-commit "$REVIEWED_CTL_COMMIT" \
  --source 'https://artifacts.example.invalid/oidf/v5.2.2/' \
  --suite-origin 'https://suite.example.invalid:30444'
```

Use the candidate's real canonical HTTPS artifact directory and isolated Suite origin in place
of the documentation-only `.invalid` names. The source must end in `/`; neither URL may contain
credentials, encoded components, query strings or fragments.

## Verification boundary

Generation is not acceptance. Use the NazoAuthCtl binary built and tested on Hostinger to inspect
the generated bytes with the current verifier before resolving, planning or running the Suite:

```sh
set -eu
prefix=/opt/nazoauth-e2e/candidate-deps-oidf-20260820T1300Z
private="$prefix/state/oidf-artifact-private"
public="$prefix/evidence/oidf-artifact-public"

"$prefix/bin/nazoauthctl" conformance artifact verify \
  --trust-policy "$private/trust-policy.json" \
  --manifest "$public/manifest.jws" \
  --driver "$public/driver.json" \
  --matrix "$public/matrix.json" \
  --capability nazoauth.client.create
```

Keep the Suite token in its pre-provisioned owner-only token file and pass it only through the
runner's file or descriptor input. Do not substitute a literal token into these commands or a
captured log.
