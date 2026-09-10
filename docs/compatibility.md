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

Before 0.5.0, the project iterates rapidly and does not preserve compatibility
with historical releases. Only current formats are supported. This controller
accepts only the exact current formats: host protocol 11, deployment state 8,
backup manifest 5, and recovery plan 2. It rejects a mismatch; it does not
convert historical state, backups, or operation records.

Rollback after a migration is governed by recorded execution facts. A pending
applied migration fences artifact rollback, and a successful migrated update
clears the previous-artifact reference. Database recovery also clears that
reference. Updates without migration retain the previous-artifact rollback
path. Recovery still uses an independently verified snapshot, without trusting
the currently running server.
