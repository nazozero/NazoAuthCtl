# Changelog

## 0.3.8 - 2026-10-24

### Fixed

- Prevent rollback from repeating a runtime switch when state was committed but
  journal completion was interrupted.
- Isolate restored rehearsal configuration from the source database and preserve
  temporary-resource ownership and snapshot selection across process loss.
- Preserve pending controller-add identity, bind off-host receipts to their
  immutable snapshots, and retain TLS authority across unrelated revisions.
- Decode Valkey credentials correctly and pass ACL usernames separately. Reject
  unsupported host backup and rehearsal operations before side effects.
- Correct Windows native structure and SID buffer alignment.

### Maintenance

- Borrow Base64 strings during backup and secret decoding and move selected
  journal receipts instead of cloning historical payloads.
- Update ctutils to address RUSTSEC-2026-0385.
- Refresh the dependency lockfile, use the NazoAuth 0.3.6 protocol packages,
  and update Tokio, UUID, Rust 1.99.1 and the pinned Cosign verifier.

### Documentation

- Describe OIDF results, dependency checks and platform verification directly
  through their tested versions, outcomes and scope.
- Clarify certificate issuance, activation and recovery conditions in the TLS
  guides using the actions and observations required at each stage.
- Remove repeated disclaimer-style wording from development guides and dated
  reports while preserving recorded results and outstanding verification work.

## Release history

Published versions and their changes are listed in
[GitHub Releases](https://github.com/nazozero/NazoAuthCtl/releases).
The [v0.3.0 release notes](docs/release-notes-0.3.0.md) describe the corresponding
CLI, security and compatibility changes.
