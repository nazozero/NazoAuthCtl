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

Started Suite plans are retained by default for inspection. Use
`--delete-suite-plans` only when the run should delete its own Suite records
afterward. This option changes evidence retention, not module outcomes or the
obligation to clean temporary NazoAuth resources.


Selected plans determine resource allocation. A run creates at most one worker
per selected plan, up to `--jobs`. Browser, VCI and VP automation are initialized
only for plans that use them. Client keys and mTLS certificates are generated
only when referenced by registration or plan material. OIDC-only runs do not
create OpenID4VC attestation keys or trust-policy resources; the corresponding
optional deployment-report fields are omitted.

Interrupted-run cleanup uses recorded resource ownership and the actual tenant,
without recreating temporary resources first. Missing historical apply material
or screenshots do not prevent tenant cleanup. Evidence publication still
validates the files it publishes, and an ambiguous failed retention commit is
not reported as committed. Cleanup and evidence publication are separate facts.

The controller user's private state does not require root ownership. Shared
file primitives support Windows ACLs, but this does not qualify the complete
OIDF evidence/browser workflow on Windows; platform evidence remains distinct.
