# OIDF local WebDriver removal — 2026-10-11

**Removal and selected-flow validation: PASS. Certification approval: OPEN.**

Runtime-validated controller source: `e46dd90ddd3b8a70c162370b00ef1155323cd400`.
Unchanged deployed server source: `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
Official Suite: **5.3.2**, verified in all retained module records.

## Implementation

The controller no longer starts, discovers, downloads, or controls a local
browser or WebDriver. The official Suite owns its scripted browser and module
cookie sessions. The controller supplies that configuration and keeps the HTTP
VCI, VP and CIBA drivers. No browser replacement or download mechanism was added.

The VP browser matcher now targets the Suite's actual
`/test/a/*/verification-evidence` URL. Independently, the controller checks the
real target's transaction-specific completion endpoint. A Suite result page
alone is insufficient: target rejection, missing completion and unrelated
redirects still fail. Expected immediate negative cases retain their existing
Suite rejection path. No presentation validation or protocol check was removed.

Historical PNG and signed capture-receipt readers remain. New runs do not
produce local screenshots or screenshot manifests. The removed implementation
includes WebDriver transport, browser process management, local browser command
execution, capture/upload orchestration and its unreachable pending states.

## Official execution

| Selection | Modules | PASS | REVIEW | WARNING | SKIPPED | Seconds | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|
| VP p038 | 10 | 7 | 3 | 0 | 0 | 30.812 | 0 |
| Other 16 OpenID4VC plans | 387 | 356 | 21 | 7 | 3 | 587.700 | 0 |
| OIDC core p001–p003 | 108 | 91 | 9 | 0 | 8 | 210.544 | 0 |
| OIDC logout p006 | 11 | 3 | 8 | 0 | 0 | 61.901 | 0 |
| **Total** | **516** | **457** | **41** | **7** | **11** | | |

All 21 plans settled, with **0 failed and 0 incomplete modules**. All 516 raw
module files and four manifest/report hashes verify. All four run-owned tenants
were cleaned; official Suite plans remain retained for review. The intentional
plan selection is not a new run of the entire 44-plan matrix.

There are **41 filled HTML review entries, 35 image obligations explicitly
marked `image_no_longer_required`, 0 unfilled placeholders and 0 local PNGs**.
The four runs sampled only ctl and its descendants every 250 ms; no local browser
or WebDriver process was observed within that sampled process tree.

The [sanitized evidence ledger](oidf-no-webdriver-20261011.json) records commands,
exit codes, source identities, Suite outcomes, manifest hashes, HTML hashes,
withdrawn image obligations and process observations. Raw logs/configuration
remain private because they can contain test credentials and tokens.

Actual Suite commands used the separate source-built `$CTL` binary, with
`NAZOAUTHCTL_TARGET_STATE_ROOT` pointing to the existing controller state root:

```sh
$CTL --instance production oidf run openid4vc-vp-p038 --json --jobs 4 --poll-timeout 1800
$CTL --instance production oidf run openid4vc --exclude-plan p038 --json --jobs 4 --poll-timeout 1800
$CTL --instance production oidf run oidc --exclude-plan p004 --exclude-plan p005 --json --jobs 4 --poll-timeout 1800
$CTL --instance production oidf run oidc-logout-p006 --json --jobs 4 --poll-timeout 1800
```

Two initial selection commands were rejected before resources were created:
`p038` is not a complete run selector, and `oidc` selects core rather than all
OIDC families. Those exit-1 invocations are retained separately and are not
counted as executed Suite tests. No official module result was edited.

## Code verification

- 34 CLI unit tests and 5 CLI presentation tests pass.
- All **209 conformance tests pass with 0 ignored** after explicitly supplying
  the existing NazoAuth host library test executable. This includes the actual
  server typed-DCQL canonicalization fixture, not a copied controller hash.
- New regressions cover Suite HTML evidence and rejected empty/unfilled evidence,
  the VP evidence matcher, VP execution without local browser/capture, and
  continued historical PNG corruption checks. Existing target-completion,
  unrelated-redirect and expected-negative tests remain.
- `cargo +1.97.1 fmt --all -- --check`: exit 0.
- `cargo +1.97.1 clippy --locked --workspace --all-targets -- -D warnings`: exit 0.
- `LC_ALL=C cargo +1.97.1 test --release --locked -p nazoauthctl-conformance -p nazoauthctl`:
  exit 0; its one opt-in test was then run explicitly.
- `NAZO_SERVER_TEST_BINARY=$SERVER_TEST cargo +1.97.1 test --release --locked -p nazoauthctl-conformance --lib start_accepts_server_typed_dcql_digest -- --ignored --nocapture`:
  exit 0. The resulting conformance test executable was also run with
  `--include-ignored`: 209 passed, exit 0.
- `cargo +1.97.1 build --release --locked -p nazoauthctl --features pre-release-validation`:
  exit 0; the existing approved candidate metadata was supplied privately.
- `git diff --check`: exit 0.

The first CLI test invocation inherited a Chinese locale while eight existing
assertions expected English. The same executable passed all 34 CLI tests under
`LC_ALL=C`; no product-language behavior or assertion was weakened.

## Correction to the previous evidence review

The earlier blanket classification of 17 OIDC records as incomplete solely
because no PNG existed was too strict. The official
[BrowserControl implementation](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.2/src/main/java/net/openid/conformance/frontchannel/BrowserControl.java#L916-941)
can fill its placeholder with `page_source`, `content_type` and `matched_regexp`.
The official [VP deferred-evidence path](https://gitlab.com/openid/conformance-suite/-/merge_requests/2100)
also supports Suite-side evidence capture. The new run proves all 17 affected
OIDC modules and all 24 VP REVIEW modules produce filled HTML evidence without
local WebDriver. HTML is retained as HTML; no reconstructed image is labeled a
real screenshot. Earlier records and the 24 historical PNGs are preserved.

This completes the local-browser removal. Official REVIEW results remain REVIEW.

## Remaining issues and boundaries

Seven official WARNING modules remain: four discovery-scope warnings and three
mdoc batch-time privacy warnings (p029, p031, p033). Relative to the preceding
397-module OpenID4VC run, p033 batch issuance changed from PASSED to WARNING;
its condition is `VCIEnsureBatchTimeClaimsNotLinkable`, like the existing p029
and p031 warnings. Server timestamp issuance is unchanged, and the privacy
issue remains open in this revision. All other corresponding OpenID4VC official
outcomes are unchanged.

`local_success=true`, while `suite_pass=false` and `acceptance_pass=false` retain
their existing meaning. No performance claim is made. The installed signed ctl,
server image and running server binary remain unchanged; no PR was merged.

## Cross-platform CI follow-up

The first Windows job passed its tests but failed Clippy because removal left
one Unix-only fixture import and three historical-evidence helpers without
Windows callers. Their compilation is now scoped to their actual consumers:
the import and secure-publication helpers are Unix-only, while the URL predicate
also remains available to tests on every platform. No warning is suppressed,
assertion removed, or protocol/runtime behavior changed. The official Suite
results above retain their actual tested source SHA; this platform-scoping
follow-up does not require repeating the unchanged Linux protocol flows.
