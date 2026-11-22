# Changelog

## Unreleased

- Add an external OIDC RP Suite execution lane owned by NazoAuthCtl.
  Existing 44 OP/AS plans stay unchanged; RP runs against production HTTPS
  endpoints and never seed private identity-link tables.

## 0.4.0 - Pending publication

- Correct `oidf run oidc` to select all nine bundled OP Core, Logout and
  Session Management plans rather than only the five Core plans. Exact plan
  selectors and the default full 44-plan Matrix are unchanged.
- Record the separate RP Basic, Configuration and Back-Channel Logout
  conformance workflow in NazoAuth. Do not import RP plan names into the
  controller's OP Matrix without a working RP provision-and-run path.
- Preserve operator protocol 4, immutable dependency revisions, and existing
  persisted state/backup formats. The release remains gated on successful CI
  and signed server compatibility.

## 0.3.11 - 2026-11-15

- Remove retired client-assertion audience exceptions from bundled OIDF client
  registrations so resource Apply follows NazoAuth's RFC 10070 policy.
- Include the durable server error code when OIDF setup or recovery fails.
- Temporarily exclude exact CIBA private-key modules whose Suite-generated
  endpoint audiences conflict with RFC 10070. Keep discovery and mTLS coverage,
  record each unexecuted module and upstream issue, and label subset acceptance
  separately from a full Suite pass.
- Drive the newer Suite VP wrong-type and revoked-credential negative tests
  through immediate rejection without requiring a successful target transaction;
  preserve the Suite's actual pass, failure and review outcomes.

## 0.3.10 - 2026-11-15

- Validate signed server compatibility through the controller's protocol policy
  and bind the verified manifest to the attested host/OCI protocol identity.
  This replaces a stale protocol-3-only release assertion.
- Includes the controller renewal changes below. The v0.3.9 release was blocked
  by that assertion before publication; its tag remains unchanged.

## 0.3.9 - Unpublished

- Automatically propose and activate controller-key renewal during signed
  management operations, including update with an expired key. No recurring MFA,
  background daemon or additional HTTP renewal request is required.
- Clarify that the key deadline triggers rotation; revocation terminates the
  controller's authorization. Host/SSH access remains independently required.
- Preserve pending keys and signed requests across lost responses, failed
  business operations and local receipt-persistence failures.
- Distinguish valid, expired and revoked keys; count occupied slots without
  revoked history and suppress approaching-expiry warnings for expired keys.
- Expiry warnings describe automatic renewal instead of instructing manual rotation.
- Use NazoAuth operator protocol 4. Upgrade the command host and SSH helper,
  then run update to NazoAuth 0.3.8 or later.

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
