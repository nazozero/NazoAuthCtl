# NazoAuthCtl v0.2.25

This patch release preserves the target's stable
`SIGNING_KEY_MIGRATION_REQUIRED` refusal code when an existing deployment must
import legacy signing keys before a managed server update. Operators now see
the actionable migration boundary instead of the generic `INTERNAL_ERROR`
classification.

The immutable compatibility gate is updated for NazoAuth v0.2.12 and continues
to require operator protocol version 3.
