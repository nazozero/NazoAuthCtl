# Controller and server compatibility

Current NazoAuth Release manifests use a closed compatibility object:

```json
{
  "operator_protocol": {
    "version": 1,
    "minimum_ctl_version": "0.1.19",
    "maximum_ctl_version_exclusive": "0.2.0"
  }
}
```

The controller accepts a server only when the protocol version equals its pinned
`nazo-operator-protocol` version and its own SemVer is inside the declared range.
Unknown protocol versions and malformed or empty ranges fail closed.

The independent controller validates the current and previous immutable, signed
server Releases below without rebuilding them:

| Controller artifact | Server Release | Protocol | Status |
| --- | --- | --- | --- |
| current NazoAuthCtl v0.1.25 source, built once | v0.1.24 signed host + OCI | 1 | artifact/identity matrix-tested |
| current NazoAuthCtl v0.1.25 source, built once | v0.1.20 signed host + OCI | 1 | matrix and real-backend tested |
| current NazoAuthCtl v0.1.25 source, built once | v0.1.19 signed host + OCI | 1 | matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.24 signed host + OCI | 1 | artifact/identity matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.20 signed host + OCI | 1 | artifact/identity matrix-tested |
| signed independent NazoAuthCtl v0.1.23 | v0.1.19 signed host + OCI | 1 | artifact/identity matrix-tested |

The v0.1.19 server predates the explicit controller range. Legacy acceptance is
restricted to that version and protocol 1. The v0.1.20 Release carries the
explicit range; there is no open-ended legacy fallback.

The previous ctl cell is the signed independent NazoAuthCtl v0.1.23 Release.
The matrix verifies its provenance from the controller repository, downloads
already-built signed server binaries, verifies signed OCI images, and executes
build identity from both server forms. Destructive recovery scenarios run only
with the current controller and verify Docker, Podman, and systemd independently.
No matrix job rebuilds the server.
