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
the same configured state roots. A rejected candidate leaves the old executable
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
