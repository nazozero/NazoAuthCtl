<div align="center">
  <h1>NazoAuthCtl</h1>
  <p>Install, operate, and recover NazoAuth across local and SSH hosts.</p>
  <p>
    <a href="https://github.com/nazozero/NazoAuthCtl/actions/workflows/ci.yml"><img src="https://github.com/nazozero/NazoAuthCtl/actions/workflows/ci.yml/badge.svg?branch=main" alt="Controller CI"></a>
    <a href="https://github.com/nazozero/NazoAuthCtl/releases"><img src="https://img.shields.io/github/v/release/nazozero/NazoAuthCtl?label=release" alt="Latest release"></a>
    <a href="Cargo.toml"><img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-2563eb" alt="AGPL-3.0-or-later"></a>
  </p>
  <p>
    <a href="https://github.com/nazozero/NazoAuthCtl/releases">Download</a> ·
    <a href="https://github.com/nazozero/NazoAuth/blob/main/docs/operations/one-click-update.md">Deployment guide</a> ·
    <a href="docs/compatibility.md">Version policy</a> ·
    <a href="https://github.com/nazozero/NazoAuth">NazoAuth server</a>
  </p>
</div>

NazoAuthCtl is the host lifecycle controller for
[NazoAuth](https://github.com/nazozero/NazoAuth). Register hosts, install signed
releases, inspect instances, and verify backups from one CLI. It uses local
execution or existing OpenSSH aliases and supports Docker, Podman, and host
binaries.

The controller ships separately from the server. Its recovery path can run
when the active NazoAuth process is unavailable.

> [!WARNING]
> **Before 0.5.0, this project iterates rapidly. Version updates do not preserve
> compatibility with historical releases.** Only current local state, journal,
> configuration, and control-message formats are supported. Older formats are
> not converted. Retain verified backups and their matching recovery tools
> before changing a deployment.

## Operations

| Task | Commands |
| --- | --- |
| Set up hosts and instances | host add/check, discover, install, instance list/register |
| Inspect a deployment | status, logs, doctor, verify |
| Manage controller access | bind, controller add/rotate/revoke/recover |
| Change a running instance | update, rollback, operation |
| Prove recovery | backup snapshot, backup restore-test, backup copy, recover |
| Maintain the controller | self check, self update, self rollback |
| Manage deployment TLS | tls certificate, tls acme |

Read-only inspection works before controller binding. Mutations use signed
control operations, with the first administrator created through the target's
local deployment authority. Binding a Controller Key requires administrator
approval with fresh MFA.

## Start a deployment

Download a [release](https://github.com/nazozero/NazoAuthCtl/releases) for your
platform. For SSH targets, install the same controller build on both ends and
use an existing OpenSSH Host alias.

Prepare a public HTTPS issuer, PostgreSQL with distinct runtime and lifecycle
roles, and Valkey. NazoAuthCtl manages the application deployment; the external
data services remain under your administration.

<details>
<summary><strong>Install, create an administrator, then bind</strong></summary>

Replace the release-tag placeholder with the signed NazoAuth version you intend
to deploy. Password files are local controller inputs.

~~~sh
nazoauthctl host add production-host --ssh production --privilege sudo

nazoauthctl install \
  --host production-host --name production \
  --to '<nazoauth-release-tag>' \
  --runtime podman --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name nazoauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password

nazoauthctl admin create --instance production
~~~

Sign in at https://auth.example.com/ui/auth and enroll MFA before binding:

~~~sh
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl verify --instance production
~~~

Store the recovery secret offline. The install result covers target-local
health; public DNS, TLS, and OIDC are checked by the separate verify command.

</details>

Use the server's [deployment guide](https://github.com/nazozero/NazoAuth/blob/main/docs/operations/one-click-update.md)
for configuration, TLS, and the complete operating sequence.
Run <code>nazoauthctl &lt;command&gt; --help</code> for exact options.

## Recovery is part of the workflow

~~~sh
nazoauthctl backup snapshot --instance production
nazoauthctl backup restore-test --instance production
nazoauthctl policy backup-before-update require \
  --instance production --max-age-seconds 86400
nazoauthctl backup copy --instance production --to-host recovery-host
~~~

A snapshot records the database dump, data, secrets, configuration, and
artifact identity. A restore test executes against an isolated target.
Off-host copies provide a separate recovery location.

Interrupted operations retain their identity. The operation journal replays
the original signed request, including after controller-key retirement; it
does not sign the same operation with a replacement key. A request the server
has never accepted still needs current authorization.

Artifact rollback is available only when recorded schema and migration facts
allow it. Database recovery uses a verified snapshot; switching a binary alone
does not reverse a database migration. Recovery does not depend on the active
server process or its current executable.

## Ownership

~~~mermaid
flowchart LR
    Operator["Operator"] --> Ctl["NazoAuthCtl"]
    Ctl --> Registry["Local host / instance registry"]
    Ctl --> Host["Local execution or OpenSSH"]
    Host --> State["Target deployment state"]
    Host --> Runtime["NazoAuth runtime"]
    Host --> Backups["Verified backups"]
~~~

The local registry identifies hosts and instances. The target owns deployment
state and execution records. Signed release metadata identifies the artifact;
signed control operations identify each requested change. See the
[version and protocol policy](docs/compatibility.md) for the format boundaries.

## Build and test

Use the pinned Rust toolchain:

~~~sh
cargo build --release --locked -p nazoauthctl
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
~~~

[CI](.github/workflows/ci.yml) runs on Linux, Windows, and both macOS
architectures. The [signed-server gate](.github/workflows/server-compatibility.yml)
checks the selected release through the production artifact verifier.
The optional external server and signed-release tests require the binary and
attestation inputs supplied by that workflow.

<details>
<summary><strong>Conformance and TLS references</strong></summary>

- [OIDF artifact workflow](docs/oidf-artifacts.md)
- [Conformance run options](docs/conformance-run-options.md)
- [Shared signing keys](docs/shared-signing-keys.md)
- [TLS deployment](docs/tls-deployment.md)
- [Certificate providers](docs/tls-certificate-provider.md)
- [ACME HTTP-01](docs/tls-acme-http01.md)

</details>

Licensed under [AGPL-3.0-or-later](Cargo.toml).
