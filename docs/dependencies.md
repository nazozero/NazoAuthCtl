# Dependency maintenance

The four workspace manifests declare the current supported stable dependency
lines. `Cargo.lock` fixes the resolved graph and registry checksums;
`nazo-operator-protocol` remains an immutable Git revision whose published wire
and persistence contracts must be reviewed before advancing it. Raising a
manifest's version floor does not mean the locked executable previously used
that older version.

Use Rust 1.99.0 from `rust-toolchain.toml`, including rustfmt and Clippy. The Linux
release build uses the same version in the digest-pinned official
`rust:1.99.0-bookworm` image, retaining the Debian 12 compatibility baseline.
GitHub Actions remain pinned to the commits behind their current stable releases.
The Python maintenance scripts use the standard library; this repository has no
separate Cargo tool, pip environment, Node package manifest, or Dockerfile.

## Compatibility and useful changes

- [Keyring 4](https://docs.rs/keyring/4.2.0/keyring/v1/index.html) separates its
  backend ecosystem and retains the simple `v1` interface. The Windows-only
  dependency uses that interface with its native Credential Manager store.
  The controller keeps the same service/user digests, password representation,
  missing-entry handling and deletion behavior. It does not change Unix's
  private-file credential backend. The Windows namespace test constructs an
  entry and checks its frozen service/user identifiers. A separate Windows
  fixture writes the published native `user.service` target, Enterprise
  persistence and raw UTF-16LE dummy bytes through the current native store API;
  the product then verifies readback, origin isolation, deletion and `NoEntry`.
  This verifies a native legacy-format fixture, not execution of the old Keyring
  binary. The fixture has a unique private namespace and cleans up its own entry.
- [Rustls 0.23.45](https://github.com/rustls/rustls/releases/tag/v/0.23.45) fixes
  acceptance of TLS 1.3 handshake messages across encryption levels. The existing
  certificate roots, hostname verification and crypto provider remain in use.
- [Reqwest 0.13.5](https://github.com/seanmonstar/reqwest/releases/tag/v0.13.5)
  fixes proxy credential selection and reduces internal copies and timeout-timer
  work. Its new DNS-error classification and TLS-version diagnostics are useful
  future diagnostics, but do not require additional protocol exchanges or retries.
- [Cosign 3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3) fixes
  GHSA-fx35-mq7g-6g98, a public-key verification bypass in legacy bundles. The
  signed-server workflow specifies this version explicitly, verifies the actual
  Linux binary's SHA-256 and version, then uses the existing signer identity,
  issuer, source-ref and attestation checks. Installer version and installed
  Cosign version are distinct pins.
- [Rust 1.99](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/) adds owned lossy
  UTF-8 conversion and more collection/raw-layout APIs. Owned conversion can
  avoid a copy when a caller already owns bytes. Existing borrowed diagnostics
  should keep their ownership and error behavior; upgrading does not justify
  adding unsafe layout operations or replacing audited filesystem primitives.

## Upstream version constraints

Refreshing the graph preserves older major lines when the latest upstream
package still requires them. For example, instant-acme 0.8.5 requires base64
`^0.22`; reqwest 0.13.5 requires tower-http `^0.6.8`; pkcs1 0.7.5 requires der
and spki `^0.7`; and several derive crates require syn `^2`. Ring 0.17.14 also
requires getrandom `^0.2.10` and windows-sys `^0.52`. The current iana-time-zone
limits windows-core to `>=0.56, <=0.62`. These requirements prevent substitution
of the newest global major versions without an upstream release or an explicit
compatibility migration. Keep their newest compatible versions and report the
complete parent/range evidence with the dependency audit.

## Updating and verifying

Check non-yanked stable versions in the official crates.io index and distinguish
direct declarations from resolved versions. A cached registry or documentation
page can lag publication; cross-check conflicting results against the official
index. Refresh the complete graph with `cargo update` in the approved build
environment and commit the resulting lockfile. Preserve upstream semver and
feature requirements. Older transitive major versions required by an upstream
package must be recorded, rather than forced through incompatible patches.

Keep build/test dependencies and the Linux release image aligned with the
toolchain. Resolve each action tag to an immutable commit and each Docker tag to
its manifest digest. Verify downloaded tool bytes against the recorded release
checksum. Existing signature and persistence gates remain required.

The [four-platform CI](../.github/workflows/ci.yml) runs formatting, workspace
tests, Clippy, release builds and help smoke checks; Linux and macOS also check
published persistence fixtures. The
[signed-server workflow](../.github/workflows/server-compatibility.yml) separately
checks the production signed-release path. New dependency commits need their own
results: a previous commit's successful run is not evidence for an upgraded graph.
