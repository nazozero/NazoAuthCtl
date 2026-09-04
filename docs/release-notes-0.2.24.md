# NazoAuthCtl v0.2.24

This release provisions and recovers the shared signing-key encryption root
used by database-backed NazoAuth deployments. Clean install persists one
deployment-owned 32-byte root, passes it to the target as a secret file, and
requires the canonical current and previous-key paths during backup and
recovery. Every runtime instance must receive the same key ring.

Existing deployments require a manual migration. The controller refuses to
treat a legacy `keys/` directory or `--import-data-root` as an implicit
database signing-key migration. With the old file-backed service stopped, run
the server's explicit `nazoauth keys-import --tenant <tenant-uuid> --from
<legacy-jwk-keys-directory>` using the chosen deployment wrapping key, retain
the source directory and a verified database backup, then perform the managed
update. Do not rerun clean install after importing: it creates a different
deployment root and cannot decrypt the imported rows. During key rotation,
configure current and previous roots as a complete pair on every instance and
preserve both roots in recovery backups.
