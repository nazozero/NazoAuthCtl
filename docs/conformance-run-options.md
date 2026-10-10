# Conformance run options

`nazoauthctl oidf run` continues after ordinary Suite module failures by
default. Official failures remain recorded as `FAILED` and still make the run
fail; continuation only allows later selected modules and plans to produce
evidence.

Use `--fail-fast` when diagnosing the first error. This explicitly stops later
dispatch after the first ordinary failure. Interrupts, unresolved resource
ownership, and cleanup safety conditions still stop the run regardless of this
option.

Use `--exclude-plan ID` to omit a plan before Suite resources are created. The
argument accepts a full bundled plan ID or its exact final segment, such as
`p040`. Exclusions may be repeated, are recorded as canonical full IDs in the
inspection plan and public report, and never count as passed or skipped Suite
modules. Unknown, ambiguous, unselected, or all-plan exclusions are rejected.

For issuer-initiated VCI authorization-code tests with two clients, the native
driver sends a fresh Credential Offer after the first hosted flow has completed
and the Suite is waiting without a pending authorization URL. Offers remain
bounded to one per client phase: repeated polls never reuse the first single-use
`issuer_state` or create further offers. The pre-authorized-code flow keeps its
existing two-offer behavior. This does not relax client-attestation expiry or
change any official Suite outcome.
