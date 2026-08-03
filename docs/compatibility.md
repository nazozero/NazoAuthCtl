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

| Controller source | Server Release | Protocol | Status |
| --- | --- | --- | --- |
| extracted current | v0.1.19 | 1 | supported transition baseline |
| extracted current | v0.1.18 | 1 | previous supported baseline |

Those immutable schema-4 Releases predate the explicit controller range. Legacy
acceptance is restricted to the two listed versions and protocol 1. New Releases
must carry the explicit range; there is no open-ended legacy fallback.

There is no independent previous NazoAuthCtl Release yet. Until the first signed
controller Release exists, the previous-controller cell is represented by the
retained `v0.1.19` source history in NazoAuth and is not described as an
independently published artifact.
