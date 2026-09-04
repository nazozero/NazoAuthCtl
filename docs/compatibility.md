# Controller and server compatibility

NazoAuthCtl v0.2.24 supports NazoAuth operator protocol version 3 only. The
controller consumes the protocol crate from the corresponding NazoAuth release
tag; the server Release manifest must also declare a controller range containing
v0.2.24. Unknown protocol versions, malformed ranges, and releases outside that
range fail closed.

The release gate builds the exact NazoAuthCtl tag commit once and validates it
against the explicitly selected supported NazoAuth Release. For the v0.2.24
controller release, that server release is v0.2.11. The gate downloads the signed
host binary and OCI image without rebuilding the server, verifies their GitHub
provenance and Sigstore identity, resolves the OCI tag to an immutable digest,
executes that immutable OCI artifact, and requires the same release version and
protocol-3 result from the host and OCI forms.

Only that protocol-3 pair is accepted. NazoAuthCtl v0.2.24 starts from clean
controller state and manages only target-owned current-protocol DeploymentState.
Old controller binaries, state directories, rollback slots, task envelopes,
commands, and deployment-state schemas are rejected rather than converted.
Database rollback across this cut is unsupported; recovery restores one
verified current-format snapshot through the current controller.

Both manual dispatch and reusable invocation require an exact controller commit
and an explicit server release tag. The controller release workflow pins the
server input to v0.2.11, and its publish jobs depend on this compatibility gate.
