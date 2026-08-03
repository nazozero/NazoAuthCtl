# Controller and server compatibility

Future NazoAuth Release manifests use a closed compatibility object:

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

The extraction baseline validates the two immutable, already signed server
Releases below without rebuilding them:

| Controller artifact | Server Release | Protocol | Status |
| --- | --- | --- | --- |
| current NazoAuthCtl source, built once | v0.1.19 signed host + OCI | 1 | matrix-tested |
| current NazoAuthCtl source, built once | v0.1.18 signed host + OCI | 1 | matrix-tested |
| signed v0.1.19 ctl from NazoAuth | v0.1.19 signed host + OCI | 1 | matrix-tested |
| signed v0.1.19 ctl from NazoAuth | v0.1.18 signed host + OCI | 1 | matrix-tested |

Those immutable schema-4 Releases predate the explicit controller range. Legacy
acceptance is restricted to the two listed versions and protocol 1. New Releases
must carry the explicit range; there is no open-ended legacy fallback.

There is no independent NazoAuthCtl repository Release yet. The previous cell is
the already signed `nazoauthctl` artifact from the NazoAuth v0.1.19 Release. The
matrix verifies its provenance, downloads already-built signed server binaries,
verifies signed OCI images, and executes build identity from both forms. It does
not rebuild the server.
