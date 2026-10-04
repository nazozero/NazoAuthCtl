# Version policy and protocol contract

The controller and server are independently released. Interoperability is defined
by the operator protocol version and the signed release-manifest schema, not
by an independently maintained controller SemVer range. This controller accepts
operator protocol 3 and release-manifest schema 7. The protocol crate remains
an immutable Cargo dependency; updating a server release with the same protocol
does not require changing that dependency or rebuilding the controller.

The release gate builds the exact controller commit and resolves the latest
stable NazoAuth release once. Manual invocation may instead select an explicit
server release tag. Every download, attestation check, and execution uses that
resolved tag, so a newer release published during the job does not change its
subject. Host and OCI artifacts must report the same selected release and
protocol version. The gate also runs the production `VerifiedRelease::verify`
path; unknown manifest schemas and protocol versions are rejected.

Persisted formats are an upgrade contract, independently of controller SemVer.
Published readers and fixtures must be retained when adding another writer
schema. Current writers use deployment state 8, backup manifest 5 and recovery
plan 2. Readers also accept deployment state 7, backup manifest 4 and recovery
plan 1 from v0.2.27. Known deployment and recovery formats normalize in memory;
the next locked mutation saves the current format. Inspection does not rewrite
files. Backup schema 4 retains its original rollback-policy field and checksum,
so existing restore receipts remain bound to the original snapshot.

Historical rollback prohibitions survive normalization: when the old policy
forbids artifact rollback, its previous-artifact reference is not offered as a
rollback target. Pending migration fences are retained. An unknown or damaged
format is preserved for diagnosis, never automatically deleted or treated as a
fresh instance. Missing facts in an unfinished operation must not be invented.

`nazoauthctl self verify-state` checks the current user's registry, keys and
pending control/recovery journals, plus local deployment states, backup metadata
and target operation logs. It does not contact a running service or remote host.
The candidate executable must pass this check before `self update` replaces the
installed controller and again before committing the installation. It inherits
the same configured state roots. The Linux installer also runs the offline check
before replacing an existing executable. A rejected candidate leaves the old executable
in place; failed post-install verification restores it using the existing
self-update journal. Normal commands recover interrupted replacement journals.
The check proves local readability, not live server health or remote-helper
protocol compatibility; the host wire protocol remains 11.

CI runs the executable against frozen v0.2.27/v0.2.28 persistence fixtures and
asserts that reading does not alter their bytes. Those fixtures must accumulate,
not be replaced with the newest schema when a version changes.

Rollback after a migration is governed by recorded execution facts. A pending
applied migration fences artifact rollback, and a successful migrated update
clears the previous-artifact reference. Database recovery also clears that
reference. Updates without migration retain the previous-artifact rollback
path. Recovery still uses an independently verified snapshot, without trusting
the currently running server.

## Database backup sentinel compatibility

Snapshot and restore compute the database sentinel in one read-only,
read-committed PostgreSQL transaction. The controller locks the required
relations, then checks both the migration ledger and the token-storage shape.
The final SELECT reads every count and the migration head from one statement
snapshot taken after those locks; it does not reuse the presence probe's snapshot.
The legacy `oauth_tokens` layout retains its exact historical hash preimage.
The layout introduced by migration `20260926000100` counts refresh contracts,
families and spent proofs separately. Missing, mixed or ledger-inconsistent
relations fail closed; an absent table is never treated as an empty table.

This does not change backup manifest 4/5, restore receipt 2, or their checksum
rules. Published snapshot metadata is not rewritten or rehashed. Restoring an
old dump selects its legacy database facts before any server migration runs;
a new dump selects its matching refresh-state facts. Do not add compatibility
tables or views to the server to satisfy a controller backup query.

The sentinel is a bounded identity check alongside the immutable dump's byte
checksum, not a replacement for it. Its transaction does not extend across the
separate `pg_dump` process; this change does not promise a new cross-process
snapshot boundary or make a checksum-only check into a restore-test receipt.

The focused real-PostgreSQL regression is
`target::backup_exec::tests::database_sentinel_postgres_models_and_dump_restore`
in package `nazoauthctl-core`. It is explicitly ignored by the ordinary
cross-platform suite: run it with `--ignored --exact` and an isolated
`NAZOAUTHCTL_TEST_DATABASE_URL` whose role can create databases, plus matching
`psql`, `pg_dump` and `pg_restore` tools. It creates and removes only its
randomly named test databases and checks legacy/current dump-restore hashes,
changed facts, unknown layouts and missing tables. The regular suite retains
the published manifest checksum fixtures and output-pollution checks.

## Operation-specific compatibility

Host wire schema 11 and existing operation/result payloads are retained. An
inspection can now return independently readable facts with `diagnostics` when
unrelated backup or identity metadata is damaged; healthy results omit this
field. Admission, snapshot consumption and `self verify-state` still validate
the facts they actually use.

From controller/helper 0.2.31, backup chunks reuse one bounded SSH helper
session per target. The controller selects this only after the verified helper
hello advertises 0.2.31 or newer. Older helpers use the existing one-operation
transport. Chunk identities, digests, journal replay and interrupted-copy
semantics remain unchanged; no new command option is needed.
Imported files receive private permissions and the current user's ownership
before the first chunk is written, including on elevated Windows hosts.

ACME accounts are keyed by deployment and CA directory. Existing pending
transactions keep their recorded account path; new transactions automatically
reuse a matching legacy account. Historical account files remain available to
validate receipts bound to their original key.
