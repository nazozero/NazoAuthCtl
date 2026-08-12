# Manual deployment lifecycle contract

`adopt --lifecycle` accepts strict schema-2 JSON. The file is an explicit grant
to operate only the listed runtime objects and recovery capabilities; names are
locators, while `deployment_id`, `runtime_instance_id`, signed instance identity,
and verified artifact identity are the security binding.

```json
{
  "schema": 2,
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
      "ports": ["127.0.0.1:19000:8000"],
      "container_policy": {
        "restart": "no",
        "read_only_root": false,
        "no_new_privileges": false,
        "drop_all_capabilities": false,
        "pids_limit": null,
        "memory_limit_bytes": null,
        "cpu_limit_millis": null,
        "tmpfs": []
      }
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

Mounts and container policy are backend-neutral. `read_only`, `selinux_relabel`,
restart, root-filesystem mutability, privilege policy, limits, and tmpfs semantics
are translated only by the selected runtime adapter; strings such as `rw,Z` or
engine CLI arguments are not accepted as controller configuration. Container
entries must declare every policy field. Omitting policy fails closed instead of
silently adding managed-install hardening to a manually deployed runtime. Systemd
entries must set `container_policy` to `null` and use an absolute binary path as
the first command argument. Container entries use the server entrypoint.

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

## External proxy TLS provider

`proxy_tls` remains `external` unless a concrete provider adapter owns it. An
operator confirmation is authorization to proceed, not proof of semantic
completion. Provider evidence for an HTTPS or mTLS cutover must be closed,
fresh, and transaction-bound, and its retained observation must include:

- the public and dedicated mTLS listener origins;
- the proxy configuration and active public client-CA bundle SHA-256 digests;
- the exact address seen by NazoAuth and the matching single-host trusted CIDR;
- proof that inbound `Client-Cert`, `Client-Cert-Chain`, and legacy certificate
  headers are removed before the proxy writes its verified value;
- the allowed TLS 1.2 and TLS 1.3 cipher sets and rejection probes;
- the proxy worker/config generation and a tested previous-generation rollback.

For conformance, the CA bundle is derived only from public
`mtls_trust_anchor_pem` values owned by the active lease. Installing that bundle,
reloading, validating, restoring, and retiring the old worker are one journaled
lifecycle. A shared listener permits only one such lifecycle at a time. A
provider must fail closed on a stale lease, digest drift, failed validation, or
ambiguous worker generation. `ca-ignore-err all` and `crt-ignore-err all` are not
valid production evidence.
