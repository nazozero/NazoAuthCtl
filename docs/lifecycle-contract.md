# Manual deployment lifecycle contract

`adopt --lifecycle` accepts strict schema-1 JSON. The file is an explicit grant
to operate only the listed runtime objects and recovery capabilities; names are
locators, while `deployment_id`, `runtime_instance_id`, signed instance identity,
and verified artifact identity are the security binding.

```json
{
  "schema": 1,
  "deployment_id": "01JDEPLOYMENTID",
  "runtimes": [
    {
      "runtime_instance_id": "01JRUNTIMEINSTANCE",
      "backend": "podman",
      "object_reference": "actual-manual-name",
      "command": ["nazoauth", "server"],
      "mounts": [
        {
          "source": "/srv/auth-a/data",
          "destination": "/var/lib/nazo_oauth",
          "read_only": false,
          "selinux_relabel": true,
          "ownership": "external",
          "scope": "deployment"
        }
      ],
      "environment": {
        "DATA_DIR": "/var/lib/nazo_oauth",
        "DATABASE_URL_FILE": "/run/credentials/database-url"
      },
      "networks": ["actual-network"],
      "ip_address": null,
      "ports": ["127.0.0.1:19000:8000"]
    }
  ],
  "recovery_driver": {
    "program": "/usr/local/libexec/nazoauth-recovery-a",
    "program_sha256": "64-lowercase-hex-characters",
    "arguments": ["--closed-json"],
    "rehearsal_workspace": "/var/lib/nazoauthctl-rehearsal/auth-a",
    "credentials": {
      "database": {
        "kind": "file",
        "path": "/run/credentials/nazoauthctl-auth-a-database"
      }
    }
  }
}
```

Mounts are backend-neutral. `read_only`, `selinux_relabel`, ownership, and scope
are translated only by the selected runtime adapter; strings such as `rw,Z` are
not accepted as controller configuration. Systemd entries use an absolute binary
path as the first command argument. Container entries use the server entrypoint.

The driver reads one JSON request from standard input and writes one JSON receipt
to standard output. It must implement `rehearse`, `checkpoint`, and `restore`.
Checkpoint receipts additionally return an absolute recovery-manifest path and
its SHA-256. The manifest is then validated and copied into the selected
deployment's controller state. Driver output is bounded and unknown fields are
rejected.

Provider credential references identify an external credential resolver; file
references identify regular files. Neither form stores secret values in the
lifecycle contract, deployment declaration, transaction, audit event, or CLI
output.
