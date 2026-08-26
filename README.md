# nazoauthctl

`nazoauthctl` is the local and SSH-remote, multi-host, multi-instance operator
console for [NazoAuth](https://github.com/nazozero/NazoAuth). One console
remembers every host and instance you register; the target machine always stays
the authority for its own runtime state.

```text
                      |- local host
                      |- SSH server-a -- NazoAuth production
Operator -> nazoauthctl|- SSH server-b -- NazoAuth staging
                      |- SSH server-c -- NazoAuth test-1 / test-2
```

## The happy path

```bash
nazoauthctl host add server-a --ssh prod-a --privilege sudo
nazoauthctl install --host server-a --name production \
  --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name oauth --database-user nazauth \
  --valkey-host cache.internal --valkey-port 6379
nazoauthctl bind --instance production
nazoauthctl status
nazoauthctl update
nazoauthctl instance list
nazoauthctl status --all
```

That is the whole deployment story: register the host, install, bind a
Controller Key, operate. `install` commits as soon as the target reports local
health - public DNS/TLS verification (`verify`) and backup setup are separate
next steps, never hidden gates.

## Commands

| Command | Purpose |
|---|---|
| `host add/list/show/check/forget` | Register and inspect SSH targets or the local machine |
| `instance list/show/rename/forget/relocate` | Inventory of NazoAuth deployments per host |
| `controller list/add/rotate/revoke/recover` | Per-instance Controller Key lifecycle |
| `install` | Clean install onto a registered host |
| `discover` | Read-only sweep for existing NazoAuth deployments |
| `bind` | Attach this console's Controller Key to an instance |
| `status` / `doctor` | Live or cached fleet views (`--all`, `--json`) |
| `verify` | Public TLS + issuer discovery report |
| `update` / `rollback` | Crash-safe artifact/config lifecycle with one signed migration |
| `operation` | Recent operation journal entries per instance |
| `backup` | Backup maturity facts (informational) |
| `uninstall` | Remove exactly the resources this deployment owns |

## Concepts you actually need

**Hosts vs instances.** A *host* is a machine (local or an OpenSSH profile
alias). An *instance* is one NazoAuth deployment on that host, identified by
its immutable `deployment_id`; friendly aliases are selectors only.

**System OpenSSH only.** Remote execution shells out to your installed `ssh`
with your config, your agent, your `known_hosts`. ctl stores just the profile
alias - no keys, no host-key databases, no daemons on targets. Host-key
failures are OpenSSH failures, on purpose.

**Controller Key (30 days).** Every instance trusts up to three Ed25519
Controller Keys minted on the control machine; private keys never leave it.
Every key expires after exactly 30 days and any lifecycle change needs a fresh
administrator 2FA approval in NazoAuth. Expired keys fail admission;
`controller rotate` replaces them.

**Recovery Secret.** On first enrollment you receive a one-time offline secret
(shown once, stored nowhere). If every Controller Key slot is lost,
`controller recover` uses it to sign a challenge and reinstall exactly one new
slot - nothing else. It is not a data backup and not an admin password.

**forget / revoke / uninstall are three different things.**

- `instance forget` - remove the local inventory entry only; the target keeps
  running and its slots are untouched.
- `controller revoke` - revoke one slot in NazoAuth; the instance and files
  stay.
- `uninstall` - delete exactly the managed, deployment-scoped resources after
  showing you the plan. External/shared PostgreSQL, Valkey, and proxies are
  never deleted.

**Maturity, not gates.** Backup readiness and public reachability are reported
facts with timestamps. They never block install/update/status.

**Existing deployments.** `discover` sweeps a host read-only; adopting one
records the facts the target itself reports and classifies everything that ctl
did not provably create as external. `bind` then attaches your Controller Key.

## Errors

Failures carry stable codes (`HOST_UNREACHABLE`, `SSH_AUTH_FAILED`,
`CONFIG_REVISION_MISMATCH`, `EXTERNAL_RESOURCE_PROTECTED`, ...) plus the next
command to run. Use `--json` for machine-readable output with one result or
error per instance.

## Development

The published binary is `nazoauthctl`; CI formats, tests, lints, and builds the
complete Cargo workspace. Server compatibility jobs download signed NazoAuth
Release binaries and OCI images; they never rebuild the server.

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace
```

License: AGPL-3.0-or-later (see [LICENSES/AGPL-3.0-or-later.txt](LICENSES/AGPL-3.0-or-later.txt));
commercial licensing in [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
