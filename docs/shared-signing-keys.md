# Shared signing-key deployment root

Database-backed NazoAuth signing keys require one deployment-owned 32-byte
wrapping key, encoded as unpadded base64url. Clean install generates it once in
the controller registry's `secrets/<deployment-id>/signing-key-encryption-key`.
Retries reuse that exact value. It is independent of the client-secret pepper.

The target receives the key as a secret file. Its configuration references
`SIGNING_KEY_ENCRYPTION_KEY_FILE` and `SIGNING_KEY_ENCRYPTION_KEY_ID`; the key
itself is never embedded in the configuration. Every service instance in the
deployment must receive the same current and, during rotation, previous key
ring. Include that root in deployment backups: the database ciphertext alone
cannot recover private signing material.

The controller and target helper use host protocol schema 10 for the expanded
install secret contract. Upgrade both together; older helpers are rejected at
the handshake before receiving an install order.

## Existing deployments

`--import-data-root` and `--import-mfa-key-file` are refused for database-backed
installs. Copying a legacy `keys/` directory cannot seed the PostgreSQL signing
keyset, so the controller never treats this as an implicit key migration. For a
stopped file-backed deployment, first run the server's offline import with the
deployment wrapping-key configuration and an active tenant:

```
nazoauth keys-import --tenant <tenant-uuid> --from <legacy-jwk-keys-directory>
```

Run the command with the same deployment wrapping key used by the existing
deployment, while the old service is stopped. Keep the original key directory
and a verified database backup, then continue with a managed artifact update
for that deployment. Do not rerun clean install after importing: a fresh clean
install mints a different deployment root and cannot decrypt the imported row.

Artifact update does not generate a missing root or replace existing signing
keys. Before upgrading a file-backed deployment, use the server's explicit
key-import procedure with the chosen shared wrapping key and original key
directory. Preserve the source files and a verified backup until migration is
accepted. Configure the current key ID and key file on every runtime instance;
container deployments must mount the canonical target secret file at
`/run/secrets/signing-key-encryption-key`.

This controller refuses artifact updates with
`SIGNING_KEY_MIGRATION_REQUIRED` when the target root is absent, malformed, or
not mounted in a container. The check precedes configuration replacement,
database migration and runtime replacement. It does not infer a migration or
silently choose new signing keys. Use a server release supporting database
signing keys together with this controller's clean-install configuration.

Key rotation is a deployment operation: distribute the new current key plus
the previous key to all instances, rewrap the persisted generations through
the server lifecycle, then remove the previous key after every instance and
required backup recovery path can read the new generation.

During rotation, configure both previous-key settings as a complete pair. The
controller archives the configured previous root as
`app-secrets/signing-key-previous-encryption-key` and mounts it during restore
rehearsal. A missing pair or file makes backup fail, and recovery rejects a
snapshot that cannot provide the configured previous root before switching any
deployment paths. Formal OCI recovery also requires the stopped source runtime
to expose the canonical previous-key mount; otherwise it refuses before the
path switch rather than creating a candidate that cannot decrypt the ring.
