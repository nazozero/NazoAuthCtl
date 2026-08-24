# Controller and server compatibility

Current NazoAuth Release manifests use a closed compatibility object:

```json
{
  "operator_protocol": {
    "version": 1,
    "minimum_ctl_version": "0.1.19",
    "maximum_ctl_version_exclusive": "0.3.0"
  }
}
```

The controller accepts a server only when the protocol constant (currently `1`)
equals its pinned `nazo-operator-protocol` constant. The protocol crate source is
pinned to an immutable Git revision, not to a NazoAuth product version. NazoAuth
and NazoAuthCtl releases are independent; the ctl SemVer only has to be inside
the server's declared range.
Unknown protocol versions and malformed or empty ranges fail closed.

The independent controller validates the current and previous immutable, signed
server Releases below without rebuilding them:

| Controller artifact | Server Release | Protocol | Status |
| --- | --- | --- | --- |
| current NazoAuthCtl v0.2.0 source, built once | v0.2.0 signed host + OCI | 1 | matrix and real-backend tested |
| current NazoAuthCtl v0.2.0 source, built once | v0.1.41 signed host + OCI | 1 | artifact/identity matrix sentinel |
| current NazoAuthCtl v0.2.0 source, built once | v0.1.34 signed host + OCI | 1 | artifact/identity matrix sentinel |
| current NazoAuthCtl v0.2.0 source, built once | v0.1.24 signed host + OCI | 1 | artifact/identity matrix-tested |
| current NazoAuthCtl v0.2.0 source, built once | v0.1.20 signed host + OCI | 1 | artifact/identity matrix-tested |
| current NazoAuthCtl v0.2.0 source, built once | v0.1.19 signed host + OCI | 1 | artifact/identity matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.24 signed host + OCI | 1 | artifact/identity matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.20 signed host + OCI | 1 | artifact/identity matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.19 signed host + OCI | 1 | artifact/identity matrix-tested |

The current NazoAuth v0.2.0 Release carries the explicit controller range and
the latest migration policy. Its migration floor is `20260822000200`; that
policy is schema-incompatible and irreversible, so database recovery requires
the controller's verified backup path rather than a server-artifact rollback.
v0.1.34 remains a signed compatibility sentinel. The v0.1.19 server predates
the explicit range; legacy acceptance is restricted to that version and
protocol 1. The v0.1.20 Release also carries the explicit range; there is no
open-ended legacy fallback.

The previous ctl cell is the signed independent NazoAuthCtl v0.1.23 Release.
The matrix verifies its provenance from the controller repository, downloads
already-built signed server binaries, verifies signed OCI images, and executes
build identity from both server forms. OCI tags are resolved to a manifest
digest before Sigstore verification and every subsequent pull, run, cache, and
recovery use that same digest reference. Destructive recovery scenarios run
with the current controller against NazoAuth v0.2.0 and verify Docker, Podman,
and systemd independently. No matrix job rebuilds the server.

The release workflow invokes this compatibility workflow as a reusable job and
passes the exact controller commit SHA from the tag. The release build and
publish jobs depend on that job; a compatibility result from another commit
cannot satisfy the release gate.
