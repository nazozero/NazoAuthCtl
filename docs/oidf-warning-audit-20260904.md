# OIDF run warning and interruption audit — 2026-09-04

Run: `run-01a06aae-3f30-7e92-b001-021414b73fac`.
The retained report and authenticated Suite records were inspected read-only.
No Suite result was edited and no replacement conformance run was performed.

## Corrected result accounting

The original report contained 1,142 of 1,146 created module instances, against
1,198 planned modules. Its 86 review results combined 25 actual `REVIEW` results
with 61 official `WARNING` results.

| Result | Original report | After reading four omitted Suite instances |
| --- | ---: | ---: |
| PASSED | 1,045 | 1,046 |
| REVIEW | 25 | 25 |
| WARNING | 61 | 61 |
| SKIPPED | 11 | 11 |
| FAILED | 0 | 1 |
| INTERRUPTED / incomplete | 0 | 2 |
| Not started | 52 | 52 |

The four omitted records are:

| Matrix plan | Suite instance | Observed status/result |
| --- | --- | --- |
| openid4vc-vci-haip-p036 | BEs9Gd0ztvmaxb4 | INTERRUPTED / no result |
| openid4vc-vci-haip-p037 | Z4hGe19eXeUlcdG | INTERRUPTED / no result |
| openid4vc-vp-p039 | QJuvqeTCzrszfKn | FINISHED / PASSED |
| openid4vc-vp-p040 | MsWChpvjsqb2Jzm | FINISHED / FAILED |

These are observations made after the run, not reconstructed original report
contents. The two interrupted instances were PAR expiry tests. The p040 failure
also contains a warning, so result categories and modules containing warning
conditions are different counts: 61 WARNING results, 62 modules with warnings.

## Warning causes

The 61 WARNING results belong to p029 (6), p031 (6), p033 (6), p035 (22), and
p037 (21). Their saved logs contain 336 WARNING condition entries:

| Suite condition | Entries | Observed defects |
| --- | ---: | --- |
| ValidateMdocDsCertificateProfile | 125 | Serial encoding can exceed 20 octets; validity exceeds 457 days; missing country, SKI, AKI, critical document-signing EKU, CRL distribution point, and issuer alternative name. |
| ValidateMdocDsCertificateMatchesIssuingCountry | 125 | mDL data says `UT`; the DS subject has no country. |
| ValidateMdocTrustAnchorIacaCertificateProfile | 86 | Missing country and issuer alternative name; incorrect SKI derivation; missing path-length constraint of zero. |

The omitted p040 record adds one `ValidateDirectPostResponse` warning, bringing
the observed condition count to 337. Its primary failure is separate from these
certificate-profile warnings: the Suite sample's MSO signed time precedes the
DS certificate's validity interval. See
[the timestamp diagnosis](oidf-mdoc-suite-time-20260904.md).

## Local repairs and remaining proof

The ctl patch gives WARNING a distinct outcome, count, progress status, and
module/condition list. It also collects created instances after execution stops,
preserves controlled review evidence, and reports missing terminal states,
unstarted modules, and the actual stop reason. It does not invent terminal
results when the Suite cannot supply them.

The server certificate-profile and CRL changes are in the separate
`NazoAuth-mdoc-cert-profile` worktree. They need deployment with regenerated
certificates before the official Suite can prove those warnings resolved.
The timestamp diagnosis proposes an upstream Suite fix; it has not been sent or
applied to the official service. Local tests do not establish a clean official
matrix result.

Local verification completed on 2026-09-04:

- ctl: 224 conformance tests and 30 CLI tests passed; Clippy for both packages
  with all targets and `-D warnings` passed.
- server: 9 keyctl tests, 20 credential-crypto tests, 62 settings tests, and the
  canonical configuration-key test passed; library Clippy with `-D warnings`
  passed. CRL checks cover signatures, explicit good/revoked state, expiry,
  absent state, HTTP status/content type, mismatched keys, and IACA rotation
  preserving both old and new CRL endpoints.
- Both worktrees passed formatting/diff checks. The server tests ran on Windows;
  Unix file-mode assertions were not executed. MSVC emitted its informational
  import-library linker message as `linker_messages`; this is separate from
  the OIDF WARNING results described above.

The new CRL address contains the IACA SHA-256 fingerprint, and the private IACA
record retains its own DS/CA certificates. Rotation therefore does not redirect
an old certificate to a CRL signed by a different IACA. CRL update bounds and
revision derive from the existing revocation snapshot.

## Hostinger verification and explicit run policy

The final source snapshots were built and tested on hostinger with Rust 1.97.1
under `/root/build/oidf-20260904`. Existing deployments were not changed.
The isolated PostgreSQL 18 and Valkey 8 test containers were removed after the
server tests. Build artifacts and logs remain in that directory.

- Server: `cargo test --locked -p nazo-oauth-server --lib` passed 1,382 tests,
  with 5 existing ignored tests, against the isolated PostgreSQL/Valkey setup.
  The persistence migration setup test also passed. This executes the Unix
  private-key file and directory permission assertions.
- Server: `cargo build --locked -p nazoauth` and workspace/all-target/all-feature
  Clippy with `-D warnings` passed. Formatting, static contracts, persistence
  dependency isolation, and binary `--help` also passed.
- ctl: `cargo test --locked --workspace --all-targets --all-features` passed
  747 tests, with 1 existing ignored test. Workspace/all-target/all-feature
  build and Clippy with `-D warnings`, formatting, and bilingual run help passed.
  The builds used the development profile with debug symbols disabled.
- New runner tests cover serial and parallel continuation versus explicit
  fail-fast, preservation of a failed group after later modules pass, exclusion
  selection validation, unsettled alias boundaries, and recovery of a created
  module when durable persistence fails.

Normal runs continue after terminal test failures. `--fail-fast` opts into
stopping at the first failure; resource ownership and unsettled alias boundaries
still constrain safe execution. `--exclude-plan p040` explicitly omits the whole
`openid4vc-vp-p040` plan before Suite allocation. It is never excluded by default.
The canonical excluded IDs and chosen failure policy are recorded in the report
and human summary. Excluded modules are not counted as passed or Suite-skipped.

This verification does not replace a deployment with newly generated certificates
and a fresh official Suite run. The 61 certificate warnings and the p040 sample
remain historical observations; no official Suite result has been rewritten.
