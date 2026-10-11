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

Backup validation probes the token schema before computing its sentinel. Legacy snapshots retain their exact token-count digest; deployments after token-table retirement count durable issuance evidence. Missing required current tables remain an error.

The bundled HAIP issuer clients explicitly require PAR, as required by HAIP 1.0 section 4 when using the authorization endpoint. Wallet attestation authentication remains unchanged. This changes the recorded matrix digest without excluding any module.

The official VP wallet may return a result page instead of an HTTP redirect. The controller then visits only the completion URL returned by the target start operation. Target rejection or an unrelated redirect still fails. Historical signed-receipt checks remain for older records, and official REVIEW outcomes remain unchanged.

For issuer-initiated multiple-client authorization, the Suite log's two explicit `VCIWaitForCredentialOffer` transitions determine when the second offer is due. A local completed-browser cache is not authoritative because another registered browser worker can complete the first flow. No offer is sent while browser URLs are pending, and repeated polling remains bounded to two offers.


## Browser execution and review evidence

New runs use the official Suite scripted browser and its per-module sessions.
The controller does not install or start a local browser or WebDriver. HTTP VCI,
VP and CIBA drivers remain; VP independently checks the target transaction's
completion endpoint before accepting the interaction.

The Suite may fill review placeholders with HTML evidence. The controller keeps
that HTML and its metadata, rejects unfilled placeholders, and preserves
REVIEW as REVIEW. Historical PNG and signed-receipt validators remain for older
records. No HTML reconstruction is labeled a real screenshot.

The [removal validation](oidf-no-webdriver-20261011.md) covers 516 official
modules and corrects the earlier blanket PNG-only objection to 17 OIDC records.
The current run still contains three mdoc privacy warnings. Certification
approval remains separate from local execution success.
