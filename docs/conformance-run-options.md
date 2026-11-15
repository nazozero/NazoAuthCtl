# Conformance run options

`nazoauthctl oidf run` continues after ordinary Suite module failures by
default. Official failures remain recorded as `FAILED` and still make the run
fail; continuation only allows later selected modules and plans to produce
evidence.

An OpenID4VCI callback HTTP error or OpenID4VP completion-endpoint failure is an ordinary module failure when the Suite
already reports that module terminal with result `FAILED`. The runner records
that result and continues the plan. Without that authoritative failure, the
HTTP error remains an orchestration error; its status code is included in the
diagnostic. No failed result is converted to a pass.

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
per selected plan, up to `--jobs`. VCI and VP drivers are initialized
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
OIDF evidence workflow on Windows; platform evidence remains distinct.
For issuer-initiated VCI authorization-code tests with two clients, the native
driver sends a fresh Credential Offer after the first hosted flow has completed
and the Suite is waiting without a pending authorization URL. Offers remain
bounded to one per client phase: repeated polls never reuse the first single-use
`issuer_state` or create further offers. The pre-authorized-code flow keeps its
existing two-offer behavior. This does not relax client-attestation expiry or
change any official Suite outcome.

Backup validation probes the token schema before computing its sentinel. Legacy snapshots retain their exact token-count digest; deployments after token-table retirement count durable issuance evidence. Missing required current tables remain an error.

The bundled HAIP issuer clients explicitly require PAR, as required by HAIP 1.0 section 4 when using the authorization endpoint. Wallet attestation authentication remains unchanged. This changes the recorded matrix digest without excluding any module.

The FAPI-CIBA ID1 plans register clients with baseline assurance and explicit
CIBA requirements: signed authentication requests, PS256 ID Tokens and mTLS-bound
tokens. All bundled client registrations use the server's issuer-only assertion
audience policy from [RFC 10070 Section 4](https://www.rfc-editor.org/rfc/rfc10070.html#section-4);
they omit the retired endpoint and multiple-audience exceptions. FAPI 2 plans
retain their own assurance policy. The pinned Suite still uses endpoint audiences
in CIBA client-authentication sequences. The exact known conflicting modules are
temporarily excluded only for `private_key_jwt` / `plain_fapi` ping and poll,
while discovery and other mTLS tests continue. One exact mTLS client-identity mismatch module is also excluded for the open CIBA HTTP challenge conflict. See the [exclusion inventory and removal
condition](oidf.md#test-inputs-and-evidence). Excluded modules are recorded as not
executed, not as passes or official Suite skips. Successful setup or a successful
executed subset is not evidence that the excluded tests passed. No assertion,
official outcome or server security policy is rewritten.

The official VP wallet may return a result page instead of an HTTP redirect.
Positive VP flows require the target transaction's completion endpoint to
succeed before they can pass. A completion error with an authoritative Suite
terminal FAILED result is recorded as that failure and allows subsequent work
unless --fail-fast is set. For the Suite's named negative tests, including wrong `vct`, revoked
status-list credentials and revoked identifier-list credentials, an immediate
target rejection can instead leave a Suite result page. The controller then
collects the Suite's terminal result without requiring a successful target
transaction. This interaction is not a pass: a Suite failure remains a failure,
including failure to fetch a revocation list. An unrelated redirect or a Suite
HTTP error still fails. Historical signed-receipt checks remain for older records,
and official REVIEW outcomes remain unchanged.

For issuer-initiated multiple-client authorization, the Suite log's two explicit `VCIWaitForCredentialOffer` transitions determine when the second offer is due. A local completed-browser cache is not authoritative because another registered browser worker can complete the first flow. No offer is sent while browser URLs are pending, and repeated polling remains bounded to two offers.


## Browser execution and review evidence

New runs use the official Suite scripted browser and its per-module sessions.
The controller does not install or start a local browser or WebDriver. HTTP VCI,
VP and CIBA drivers remain; positive VP flows independently check the target
transaction's completion endpoint before accepting the interaction.

The Suite may fill review placeholders with HTML evidence. The controller keeps
that HTML and its metadata, rejects unfilled placeholders, and preserves
REVIEW as REVIEW. Historical PNG and signed-receipt validators remain for older
records. No HTML reconstruction is labeled a real screenshot.

The [removal validation](oidf-no-webdriver-20261011.md) covers 516 official
modules and corrects the earlier blanket PNG-only objection to 17 OIDC records.
That historical run contained three mdoc privacy warnings; its result is not
a statement about current server releases. Certification approval remains
separate from local execution success.

`acceptance_pass` requires a non-empty defined module set, all modules terminal,
successful local orchestration/resource settlement, the selected acceptance
policy and the matrix expectations. An empty or unfinished run cannot pass
acceptance. Official Suite pass and outstanding human review remain separate
report fields.
