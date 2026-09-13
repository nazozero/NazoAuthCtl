# NazoAuthCtl v0.2.29

Fixes v0.2.28 refusing v0.2.27 deployment state and backup manifests after a
controller-only upgrade.

- Read deployment schema 7 and recovery plan 1 automatically. Reads preserve
  source bytes; the next locked mutation saves the current format. Historical
  migration fences and rollback prohibitions remain effective.
- Read backup manifest 4 with its original checksum and restore-receipt binding.
  No manual JSON edits, state deletion or backup recreation are required.
- Add `self verify-state`. Self-update runs the candidate's offline check before
  replacement and before committing installation. Incompatible candidates leave
  the old controller installed; failed post-install checks restore it. Normal
  commands recover interrupted self-update transactions using the same checks.
- Retain frozen persistence fixtures in CI to prevent future readers from
  dropping published formats. Unknown or corrupt data is preserved for diagnosis.

See [compatibility and self-repair](compatibility.md) for proof boundaries and
the supported persistent formats. This does not change the running NazoAuth
service or database during controller self-update.
