# TLS through the existing lifecycle

Ctl is an offline control plane. Servers and proxies read installed material;
no authentication request calls ctl. Renewal checks run from an external
scheduler. TLS operations do not embed a NazoAuth release number.

## Direct TLS configuration

Merge these transport settings into the deployment's existing full config;
replace paths, addresses and origins with real deployment facts:

```yaml
TRANSPORT_MODE: "direct-tls"
TLS_CERTIFICATE_FILE: "/etc/nazoauth/tls/tenant-a/auth.example/current/fullchain.pem"
TLS_PRIVATE_KEY_FILE: "/etc/nazoauth/tls/tenant-a/auth.example/current/private-key.pem"
TLS_BIND: "0.0.0.0:8443"
MTLS_ENDPOINT_BASE_URL: "https://auth.example:8443"
TLS_CLIENT_CA_FILE: "/etc/nazoauth/tls/client-trust.pem"
TLS_RELOAD_INTERVAL_SECONDS: "5"
```

`PUBLIC_BASE_URL` remains the HTTPS issuer. `BIND` is its HTTPS listener;
`TLS_BIND` is a different listener for mTLS. The certificate must cover both
endpoint hostnames. Remove `TRUSTED_PROXY_CIDRS` and proxy certificate-source
settings. Preserve all database, signing, identity, data and secret settings.

For a new Linux Podman or Docker deployment, save the seven transport settings
above in a local `direct-tls.yaml` and add these options to the ordinary install
command (including its existing PostgreSQL and Valkey arguments):

```text
nazoauthctl install --public-url https://auth.example \
  --direct-tls-config /secure/direct-tls.yaml \
  --tls-material-root /etc/nazoauth/tls
```

The material root is an explicit, dedicated target-side directory containing
the certificate, private key, and client CA named in the config. It must already
exist, contain only this deployment's TLS material, and be separate from ctl's
managed config/data/secret directories. Install declares it external and never
changes or deletes it. The container mounts the whole root read-only at the
same path, so later atomic generation switches remain visible. Do not select a
symlink such as `current` as the root.

Ctl keeps `BIND: 0.0.0.0:8000`, publishes its generated loopback readiness port,
and publishes the HTTPS issuer and mTLS origin ports on IPv4. The two public
origins must use the same hostname and different ports; `TLS_BIND` supplies the
separate internal mTLS port. The transport file cannot override database,
signing, identity, or data configuration. Unknown transport settings fail
closed. Direct TLS installation uses the same prepared install journal,
artifact verification, rollback, and local-health receipt as proxy installation.
Public verification and controller binding remain explicit later steps.

Before database initialization, failed installation rolls back generated local
resources. Once initialization starts, database writes may already exist even
when the command fails. Ctl retains the prepared identity, configuration, keys,
and data and reports an incomplete install. Fix the reported external cause and
rerun the exact install command; do not delete those recovery files or generate
another deployment identity against that database.

Fresh installation does not invent a PID/mDL issuance profile or jurisdiction.
Enable optional digital-credential issuer/verifier features through a complete
`update --config-file` using the deployment's real credential catalog, issuing
country where required, and revocation policy. The required secret files are
already installed. An OIDF acceptance deployment must explicitly enable the
protocol profile that its matrix requires before the run.

Before activating OpenID4VC on a deployment that did not enable it at install,
initialize the system tenant's managed signing and certificate material with
the server's existing `tenant-bootstrap` command and the intended configuration.
Use that deployment's lifecycle database credentials, secret references and
service identity. Keep the active configuration unchanged until bootstrap
succeeds, then pass the complete configuration to ordinary update. Update's
`MigrateApply` operation applies schema/directory migrations; it does not replace
this explicit credential-profile initialization. A readiness failure after an
irreversible migration requires verified backup recovery, not manual journal
or migration-fence removal.

Use the service's actual dedicated group as the provider's `reader_gid`, and
allow traversal of its ancestors. A rootful official container uses UID/GID
10001; root-owned `0750` directories and a `0640` key for that dedicated group
allow reading without allowing the service to replace material. Rootless
containers require ownership matching their actual user mapping. The installed
server must support those permissions. If its permission check rejects them,
the install fails instead of weakening file permissions.

For an existing deployment, listener publications and mounts must already
cover the new configuration: config update preserves the installed runtime
topology. It does not add another TLS root or expose a different public port.

## Trusted proxy configuration

For a same-host loopback peer, the transport settings are:

```yaml
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32,::1/128"
MTLS_CERTIFICATE_SOURCE: "disabled"
```

A container sees its actual ingress peer; replace the CIDRs accordingly. This
example explicitly disables client certificate forwarding. If mTLS is required,
retain the existing RFC 9440 encoder and use `rfc9440`. Never forward an incoming
caller-controlled `Client-Cert`, or substitute escaped PEM for its DER encoding.

For an existing proxy whose configuration remains externally managed, point its
certificate directives at the provider's `current` files and retain its native
validate/reload hooks.

For a dedicated ctl-managed proxy configuration, set `native_proxy_program` in
the provider and supply `--proxy-config` to certificate plan/apply. The complete
native configuration and certificate share one generation and atomic `current`
pointer. Ctl runs the native `-t -c` check before switching and before restoring
the previous configuration. See [the provider contract](tls-certificate-provider.md#native-proxy-configuration)
for service wiring, ownership, and the configuration template.

## Applying and recovering

Apply the complete server configuration through the existing lifecycle:

```text
nazoauthctl update --instance INSTANCE --to CURRENT_OFFICIAL_TAG \
  --config-file /secure/candidate.yaml --config-schema DEPLOYMENT_CONFIG_SCHEMA
nazoauthctl verify --instance INSTANCE
```

The explicit tag pins this transaction to the selected artifact. Omitting
`--to` uses ordinary dynamic release resolution. Update still performs migration
admission. An applied migration requires verified database recovery rather than
artifact-only rollback. Before migration, rollback restores config before
starting the old artifact.

Readiness follows the configured transport. HTTPS connects to loopback while
preserving issuer SNI and host trust-store validation; install a private CA in
that store if required. There is no `--insecure` or HTTP fallback. Public
verification remains a separate check.

Snapshot signing-key verification, restore-test readiness/discovery/JWKS, and
the recovery-secret ceremony use the same configured transport. Recovery keeps
only the existing read-only mounts covering the restored TLS file settings;
the certificate directories remain external to the database/data snapshot.
Restore the declared TLS material on the target before staging a candidate.
The recovery journal preserves HTTPS through a controller restart and an SSH
loopback forward; it never retries a failed TLS connection as HTTP.

Use [certificate plan/apply/check/recover](tls-certificate-provider.md) for an
already configured TLS consumer. Use [ACME plan/issue/recover](tls-acme-http01.md)
for issuance and `--from-acme-current` for installation. The consumer must be
able to activate `current`; no-op hooks do not bootstrap a service or adopt an
arbitrary existing pointer. On interruption, recover the same binding before
another apply. A failed first install without a provable prior TLS identity
remains pending; an unreachable endpoint is not proof of rollback.

Run `tls certificate check` periodically with a warning window larger than
expected renewal/recovery time, and alert on nonzero exit. Local tests cover real
TLS, delayed leaf switching/rollback, deadlines and permissions. On 2026-09-06,
Candidate acceptance in a Linux environment also exercised public ACME issuance, renewal and
key replacement, both transport modes, native proxy config transactions,
interrupted recovery and protocol service with ctl absent. These results identify
the tested candidate binaries; distributed Release validation is separate evidence.
