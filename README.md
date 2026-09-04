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
  --database-name oauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host cache.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password
nazoauthctl admin create --instance production
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl status
nazoauthctl update
nazoauthctl instance list
nazoauthctl status --all
```

That is the whole deployment story: register the host, install, create an
administrator through the deployment root, bind a Controller Key, operate.
`install` commits as soon as the target reports local health - public DNS/TLS verification (`verify`) and backup setup are separate
next steps, never hidden gates.

For database-backed deployments, clean install does not import a legacy `keys/`
directory or current data. Follow [shared signing-key migration and recovery](docs/shared-signing-keys.md)
for the server's explicit offline key import, the same deployment wrapping key,
and the required backup and root-mount checks before a managed update.

## Commands

| Command | Purpose |
|---|---|
| `host add/list/show/check/forget` | Register and inspect SSH targets or the local machine |
| `instance register/list/show/rename/forget/relocate` | Register or inventory current-protocol NazoAuth deployments per host |
| `controller list/add/rotate/revoke/recover` | Per-instance Controller Key lifecycle |
| `install` | Clean install onto a registered host |
| `discover` | Read-only sweep for existing NazoAuth deployments |
| `bind` | Attach this console's Controller Key to an instance |
| `admin create` | Create an administrator through the instance's fixed target-local provisioner |
| `status` / `doctor` | Live or cached fleet views (`--all`, `--json`) |
| `verify` | Public TLS + issuer discovery report |
| `update` / `rollback` | Crash-safe artifact/config lifecycle with one signed migration |
| `operation` | Recent operation journal entries per instance |
| `policy backup-before-update` | Select `off`, `warn`, or a blocking maximum restore-test age |
| `backup` | Create, inspect, restore-test, and byte-verify snapshots |
| `recover` | Restore a verified snapshot and complete token invalidation |
| `uninstall` | Remove exactly the resources this deployment owns |
| `self check/update/rollback` | Maintain the current ctl release; unknown self-state schemas fail closed and must be reset from a backup, never migrated |
| `tls certificate/acme`, `remote exec` | Target TLS and the fixed remote protocol |

## Concepts you actually need

**Hosts vs instances.** A *host* is a machine (local or an OpenSSH profile
alias). An *instance* is one NazoAuth deployment on that host, identified by
its immutable `deployment_id`; friendly aliases are selectors only.

**Local and SSH targets.** Local targets execute directly. Remote execution
shells out to the installed system `ssh` with its config, agent, and
`known_hosts`. ctl stores only the profile alias; it does not store SSH keys or
run a target daemon. Backup copy uses the same target abstraction on both
sides, so either endpoint can be local or SSH as long as they are distinct
registered hosts.

**Controller Key (30 days).** Every instance trusts up to three Ed25519
Controller Keys minted on the control machine; private keys never leave it.
Every key expires after exactly 30 days and any lifecycle change needs a fresh
administrator 2FA approval in NazoAuth. Expired keys fail admission;
`controller rotate` replaces them. For an interactive change, ctl performs the
standard administrator password login and MFA flow itself, keeps the rotated
cookie/CSRF session only in memory, and requests approval for the exact
proposal. Use an owner-only `--credentials-file` to avoid retyping the email
and password; use `--approval-token` instead for non-interactive automation.

**Administrator creation.** `admin create` is the ctl deployment-root path for
administrator provisioning. It sends one journaled, instance-bound
HostOperation to the live target, which runs only the fixed
`nazoauth admin-provision` command from the DeploymentState artifact. The
credential JSON is supplied interactively or with `--credentials-stdin`; the
password is never an argv token, environment value, log, or persistent ctl
file; the target journal stores only the operation's canonical hash and public
receipt, never the credential JSON. The current target runtime and config are
checked before the one-shot run, and a retry reuses the target journal's
operation result.

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

**Backup policy is explicit.** Public reachability and backup timestamps remain
reported facts. `policy backup-before-update require --max-age-seconds N`
makes update refuse unless the target still has the exact restore-tested
snapshot manifest within that age. `warn` reports missing evidence and `off`
does not require it.

**Current protocol only.** `discover` sweeps a host read-only. `instance
register` accepts only a deployment whose target-owned state and verified
helper implement the current protocol. There is no old controller-state,
command, task-envelope, or deployment-state conversion path.

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
