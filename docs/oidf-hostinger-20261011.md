# Upgraded deployment and official OIDF validation, 2026-10-11

Validated controller source: `dbd8b0647731dcf4fa3d725cd8269fc745f9e5ee`.
Deployed NazoAuth source: `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
Official Suite reported version 5.3.2; the bundled matrix retains its historical
v5.2.2 source label and records the actual amended matrix digest in each report.

The upgraded database had retired `oauth_tokens`; released ctl backup verification
therefore failed. The repair preserves legacy snapshot digest semantics and uses
durable issuance counts on the current schema. Twenty backup tests, both schemas
on isolated PostgreSQL, and a complete live snapshot plus isolated restore-test
passed. No backup check was removed.

The issuer-initiated multiple-client module waits for a second single-use Offer.
A module-only deduplication key stalled that phase. An initial correction based
on the local HTTP driver's completed-URL cache also failed in the actual Suite:
a registered browser worker can complete that flow without updating the cache.
The final correction uses the Suite's explicit Offer-wait transitions, sends no
offer while browser URLs remain pending, and is bounded to two offers. Actual
second deliveries were observed after 314 ms and 415 ms; all ten multiple-client
variants passed without manual assistance.

The current Suite may display a VP result page instead of issuing a redirect.
The controller still requires the completion endpoint bound to the target
transaction to succeed. An unrelated redirect, unverified transaction or missing
completion response fails. Signed receipt and screenshot checks remain intact.
HAIP client registrations now explicitly enable the existing required-PAR policy;
all four non-PAR authorization negative tests pass. Attestation authentication
and all original safety lifetimes remain unchanged.

Validation commands on the deployment host:

```sh
cargo +1.97.1 fmt --all
cargo +1.97.1 test --release --locked -p nazoauthctl-conformance --lib
cargo +1.97.1 test --release --locked -p nazoauthctl-core --lib target::backup_exec::tests
cargo +1.97.1 clippy --locked -p nazoauthctl-conformance -p nazoauthctl-core --all-targets -- -D warnings
NAZO_SERVER_TEST_BINARY=<NazoAuth-host-library-test-executable> cargo +1.97.1 test --release --locked -p nazoauthctl-conformance --lib start_accepts_server_typed_dcql_digest -- --ignored --nocapture
nazoauthctl-selected --instance production oidf run openid4vc --json --jobs 4 --poll-timeout 1800
```

All positive commands exited 0. The regular suite has 269 passing tests and one
fixture-dependent ignored test; that test passed separately against the actual
host library executable. Pre-fix behavior failed the offer-phase, VP and HAIP
regressions. Earlier wrong-target/zero-test fixture attempts are INVALID and are
not counted as negative behavioral proof or positive acceptance.

The final official rerun settled all 397 modules across 17 plans in 671.742 s:
**364 PASS, 24 REVIEW, 6 WARNING, 3 expected SKIPPED, 0 FAIL, 0 incomplete**.
It used no manual offers or excluded plans. All 397 module files and 24 real
WebDriver screenshots match their recorded hashes. The ephemeral tenant and
private run material were cleaned, while official plans were retained for review.
`local_success=true` and `matrix_expectations_satisfied=true`; official
`suite_pass` and `acceptance_pass` remain false pending review. The six warnings
are two fresh-signer mdoc timestamp privacy heuristics and four discovery scope
warnings. None is relabeled PASS.

The combined original matrix ledger has 1,107 PASS, 41 REVIEW, 14 WARNING and
11 expected SKIPPED. It combines 776 unaffected original-run modules with the
397 corrected modules; it is not a second full-matrix run on one final SHA.

The validation controller remains separate from the globally installed signed
release. This preserves the release self-update trust state; use the retained
validated binary for current-schema backups until this repair is released.

[Full deployment report](https://github.com/nazozero/NazoAuth/blob/6177b290f87f88f515a78ea2abd41f0003a338c4/docs/operations/reports/main-upgrade-2026-10-10.md)
contains command exit records, prior failed/interrupted runs, source identities,
all module outcomes, retained plan IDs and private evidence manifest digests.
