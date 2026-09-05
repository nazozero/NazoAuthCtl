# NazoAuthCtl v0.2.26

This patch release consumes the corrected tenant key-generation result contract
from NazoAuth v0.2.13. Database keyset revisions are canonical positive decimal
values, allowing an accepted idempotent key-generation operation to publish its
durable result and resume the interrupted conformance setup with the same
operation identity.

The immutable compatibility gate is updated for NazoAuth v0.2.13 and continues
to require operator protocol version 3.
